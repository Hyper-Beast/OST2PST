#include "ost2pst/ndb/amap.h"

#include <string>
#include <utility>

#include "ost2pst/ndb/crc.h"
#include "ost2pst/util/crc32.h"
#include "ost2pst/util/sig.h"

namespace ost2pst::ndb {

using util::ByteView;
using util::ErrorKind;
using util::make_error;
using util::Result;
using util::Status;

const char *amap_bit_order_name(AMapBitOrder order) {
    return order == AMapBitOrder::kMostSignificantFirst ? "msb-first" : "lsb-first";
}

bool amap_bit_set(const uint8_t *bits, uint64_t index, AMapBitOrder order) {
    const uint64_t byte = index / 8;
    const uint64_t bit = index % 8;
    // [MS-PST] 2.2.2.7.2 orders the bits but not the bits inside a byte; M0 measured this one.
    const uint8_t mask = (order == AMapBitOrder::kMostSignificantFirst)
                             ? static_cast<uint8_t>(1u << (7 - bit))
                             : static_cast<uint8_t>(1u << bit);
    return (bits[byte] & mask) != 0;
}

std::vector<uint64_t> amap_region_offsets(FileProfile profile, uint64_t ib_amap_last) {
    std::vector<uint64_t> offsets;
    const uint64_t interval = amap_interval(profile);
    for (uint64_t ib = amap_first_offset(profile); ib <= ib_amap_last; ib += interval) {
        offsets.push_back(ib);
    }
    return offsets;
}

uint64_t amap_first_unit(FileProfile profile, uint64_t region_ib) {
    // [MS-PST] 2.2.2.7.2: the region's first bit maps the first allocation unit of its own data section.
    return region_ib / block_granularity(profile);
}

uint64_t allocation_unit_offset(FileProfile profile, uint64_t unit) {
    // [MS-PST] 2.2.2.8: allocation units are granularity-sized and aligned, so unit N is at N * size.
    return unit * block_granularity(profile);
}

ByteView AMapRegion::page() const {
    return ByteView(bytes.data(), bytes.size(), ib);
}

ByteView AMapRegion::bits() const {
    return ByteView(bytes.data(), static_cast<size_t>(data_bytes), ib);
}

Result<AMapRegion> read_amap_region(const util::FileReader &file, FileProfile profile,
                                    uint64_t region_ib, FailureLog &failures) {
    const uint64_t size = page_size(profile);
    if (region_ib > file.size() || file.size() - region_ib < size) {
        return make_error(ErrorKind::kTruncated, "AMAPPAGE.ib", region_ib, region_ib,
                          "AMap region runs past the end of the file");
    }

    AMapRegion region;
    region.ib = region_ib;
    region.bytes.assign(static_cast<size_t>(size), 0);
    Status io = file.read_at(region_ib, region.bytes.data(), region.bytes.size());
    if (!io) {
        return io.error();
    }

    const ByteView view = region.page();
    Result<ByteView> window = view.sub(static_cast<size_t>(bt_trailer_offset(profile)),
                                       static_cast<size_t>(page_trailer_size(profile)));
    if (!window.ok()) {
        return window.error();
    }
    Result<PageTrailer> trailer = decode_page_trailer(window.value(), profile);
    if (!trailer.ok()) {
        failures.add(trailer.error());
        return trailer.error();
    }
    region.trailer = trailer.value();
    region.data_bytes = page_data_bytes(profile);

    const uint64_t trailer_at = region_ib + bt_trailer_offset(profile);
    // [MS-PST] 2.2.2.7.1: ptype says which structure the page holds.
    region.ptype_ok = region.trailer.ptype == kPageTypeAMap;
    if (!region.ptype_ok) {
        failures.add(trailer_at, "PAGETRAILER.ptype", region.trailer.ptype,
                     "expected an AMap page");
    }
    // [MS-PST] 2.2.2.7.1: an AMap page has wSig 0x0000 and a bid equal to its own ib.
    region.sig_ok = region.trailer.w_sig == 0 && region.trailer.bid == region_ib;
    if (!region.sig_ok) {
        failures.add(trailer_at, "PAGETRAILER.wSig", region.trailer.w_sig,
                     "an AMap page needs wSig 0 and bid equal to ib");
    }
    region.crc_ok = util::crc32(region.bits()) == region.trailer.dw_crc;
    if (!region.crc_ok) {
        failures.add(trailer_at, "PAGETRAILER.dwCRC", region.trailer.dw_crc,
                     "AMap page CRC does not match");
    }
    // [MS-PST] 2.2.2.7.2: an AMap maps itself, so its first bit byte is 0xFF.
    region.self_map_ok = region.bits().data()[0] == kAmapSelfMapByte;
    if (!region.self_map_ok) {
        failures.add(region_ib, "AMAPPAGE.rgbAMapBits[0]", region.bits().data()[0],
                     "expected 0xFF: an AMap maps itself");
    }
    return region;
}

Status for_each_allocated_unit(const util::FileReader &file, FileProfile profile,
                               uint64_t ib_amap_last, AMapBitOrder order, FailureLog &failures,
                               const AMapUnitCallback &callback, uint64_t *regions_visited,
                               uint64_t *regions_valid) {
    const uint64_t region_units = amap_units(profile);
    for (uint64_t region_ib : amap_region_offsets(profile, ib_amap_last)) {
        Result<AMapRegion> region = read_amap_region(file, profile, region_ib, failures);
        if (!region.ok()) {
            // A region that cannot even be read stops the chain: the offsets after it are guesses.
            if (region.error().kind == ErrorKind::kTruncated) {
                failures.add(region.error());
                return Status();
            }
            return region.error();
        }
        if (regions_visited != nullptr) {
            ++*regions_visited;
        }
        const AMapRegion &map = region.value();
        if (!map.ptype_ok || !map.sig_ok || !map.crc_ok) {
            continue;
        }
        if (regions_valid != nullptr) {
            ++*regions_valid;
        }
        const uint64_t first_unit = amap_first_unit(profile, map.ib);
        const uint8_t *bits = map.bits().data();
        for (uint64_t index = 0; index < region_units; ++index) {
            if (!amap_bit_set(bits, index, order)) {
                continue;
            }
            const uint64_t unit = first_unit + index;
            if (!callback(unit, allocation_unit_offset(profile, unit))) {
                return Status();
            }
        }
    }
    return Status();
}

} // namespace ost2pst::ndb
