#pragma once

#include <cstdint>
#include <functional>
#include <vector>

#include "ost2pst/ndb/layout.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/ndb/trailer.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ndb {

// [MS-PST] 2.2.2.7.2 states one bit per allocation unit but never states the bit order inside a byte.
// M0 measured MSB-first on the sample OST: with that order every unit the BBT allocates is marked,
// with the other order 36,113 of them are not.
enum class AMapBitOrder {
    kMostSignificantFirst,
    kLeastSignificantFirst,
};

const char *amap_bit_order_name(AMapBitOrder order);

// [MS-PST] 2.2.2.7.2: bit `index` counted from the start of one region's bit map.
bool amap_bit_set(const uint8_t *bits, uint64_t index, AMapBitOrder order);

// [MS-PST] 2.2.2.7.2: one AMap every amap_interval bytes from the profile's first AMap; ROOT.ibAMapLast
// ([MS-PST] 2.2.2.5) is the offset of the last region, so it terminates the chain.
std::vector<uint64_t> amap_region_offsets(FileProfile profile, uint64_t ib_amap_last);

// [MS-PST] 2.2.2.7.2: a region maps the data section that starts at its own offset, so bit N belongs
// to allocation unit (region ib / granularity) + N.
uint64_t amap_first_unit(FileProfile profile, uint64_t region_ib);
uint64_t allocation_unit_offset(FileProfile profile, uint64_t unit);

// One AMap region: the page bytes, the trailer that vouches for them, and which checks passed.
// [MS-PST] 2.2.2.7.2.1 AMAPPAGE is the page plus its PAGETRAILER.
struct AMapRegion {
    uint64_t ib = 0;
    PageTrailer trailer;
    bool ptype_ok = false;
    bool sig_ok = false;
    bool self_map_ok = false;
    bool crc_ok = false;

    std::vector<uint8_t> bytes; // the region page as read from the file
    uint64_t data_bytes = 0;    // [MS-PST] 2.2.2.7.1: page size minus trailer for this profile

    util::ByteView page() const; // the whole region page, based at its absolute offset
    util::ByteView bits() const; // [MS-PST] 2.2.2.7.2.1 rgbAMapBits: page data before the trailer
};

// Reads one region and runs every check [MS-PST] 2.2.2.7.1 / 2.2.2.7.2 gives an AMap page: ptype,
// ptypeRepeat, wSig 0 with bid equal to ib, the self-map byte, and dwCRC over the page data. Failed
// checks are logged and flagged on the region rather than returned, because a caller that is counting
// a whole chain still needs the other regions' stored CRCs to score its variants.
util::Result<AMapRegion> read_amap_region(const util::FileReader &file, FileProfile profile,
                                          uint64_t region_ib, FailureLog &failures);

// Walks the allocation units the whole chain claims, in file order. The callback gets the unit index
// and its absolute offset; returning false stops. Unverified regions are skipped (already logged).
using AMapUnitCallback = std::function<bool(uint64_t unit, uint64_t ib)>;
util::Status for_each_allocated_unit(const util::FileReader &file, FileProfile profile,
                                     uint64_t ib_amap_last, AMapBitOrder order, FailureLog &failures,
                                     const AMapUnitCallback &callback, uint64_t *regions_visited,
                                     uint64_t *regions_valid);

} // namespace ost2pst::ndb
