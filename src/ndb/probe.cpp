#include "ost2pst/ndb/probe.h"

#include <algorithm>
#include <cstdio>
#include <string>
#include <utility>

#include "ost2pst/ndb/trailer.h"
#include "ost2pst/util/crc32.h"
#include "ost2pst/util/sig.h"

namespace ost2pst::ndb {

using util::ByteView;
using util::DataError;
using util::ErrorKind;
using util::make_error;
using util::Result;
using util::Status;

namespace {

// [MS-PST] 2.2.2.8: allocation happens in granularity-sized units and [MS-PST] 2.2.2.7.2 marks one
// bit per unit, so one bit vector over units is what both the block walk and the AMap cross-check
// need. Keeping it as bits holds a 2.6 GB file to well under a megabyte.
class UnitMap {
  public:
    UnitMap(uint64_t units, uint64_t granularity)
        : granularity_(granularity), units_(units), bits_((units + 63) / 64, 0) {}

    uint64_t units() const { return units_; }

    void mark(uint64_t ib, uint64_t bytes) {
        const uint64_t first = ib / granularity_;
        const uint64_t last = (ib + bytes + granularity_ - 1) / granularity_;
        for (uint64_t unit = first; unit < last && unit < units_; ++unit) {
            bits_[unit >> 6] |= 1ULL << (unit & 63);
        }
    }

    bool marked(uint64_t unit) const {
        return unit < units_ && ((bits_[unit >> 6] >> (unit & 63)) & 1ULL) != 0;
    }

    uint64_t count() const {
        uint64_t total = 0;
        for (const uint64_t word : bits_) {
            uint64_t bits = word;
            while (bits != 0) {
                bits &= bits - 1;
                ++total;
            }
        }
        return total;
    }

  private:
    uint64_t granularity_ = 1;
    uint64_t units_ = 0;
    std::vector<uint64_t> bits_;
};

} // namespace

namespace {

// [MS-PST] 2.2.2.7.7.3: BBTENTRY.cb is the raw byte count, so the footprint is cb plus the trailer
// rounded to the granularity, and the trailer sits flush against the end of that footprint.
Status verify_blocks(const util::FileReader& file, FileProfile profile, const BTreeWalker& bbt,
                     const ProbeOptions& options, ProbeCounters& counters, FailureLog& failures,
                     UnitMap& units) {
    BlockCounters& blocks = counters.blocks;
    const uint64_t trailer_size = block_trailer_size(profile);
    const uint64_t granularity = block_granularity(profile);
    std::vector<uint8_t> buffer(static_cast<size_t>(block_max_size(profile)));

    for (const auto& item : bbt.bbt_index()) {
        const BbtEntry& entry = item.second;
        ++blocks.indexed;
        if (options.max_block_verify != 0 && blocks.verified >= options.max_block_verify) {
            break;
        }

        const uint64_t footprint = align_allocation(profile, entry.cb + trailer_size);
        if (footprint > block_max_size(profile) || entry.ib % granularity != 0 ||
            entry.ib > file.size() || file.size() - entry.ib < footprint) {
            ++blocks.out_of_range;
            failures.add(entry.ib, "BBTENTRY.ib", entry.ib,
                         "block footprint of " + std::to_string(footprint) +
                             " bytes is misaligned or runs past the file");
            continue;
        }

        Status read = file.read_at(entry.ib, buffer.data(), buffer.size());
        if (!read) {
            return read.error();
        }
        ++blocks.verified;
        units.mark(entry.ib, footprint);
        if (entry.cb > blocks.max_cb) {
            blocks.max_cb = entry.cb;
        }
        if (footprint > blocks.max_footprint) {
            blocks.max_footprint = footprint;
        }

        const uint64_t trailer_at = footprint - trailer_size;
        Result<BlockTrailer> decoded =
            decode_block_trailer(ByteView(buffer.data() + trailer_at,
                                          static_cast<size_t>(trailer_size), entry.ib + trailer_at),
                                 profile);
        if (!decoded.ok()) {
            failures.add(decoded.error());
            continue;
        }
        const BlockTrailer& trailer = decoded.value();

        // [MS-PST] 2.2.2.7.7.3 and [MS-PST] 2.2.2.8.1 describe the same block from two sides, so
        // the BBT entry and the trailer have to agree on the block's BID and raw size.
        if (trailer.cb == entry.cb) {
            ++blocks.cb_matches;
        } else {
            ++blocks.cb_mismatches;
            failures.add(entry.ib + trailer_at, "BLOCKTRAILER.cb", trailer.cb,
                         "BBTENTRY.cb is " + std::to_string(entry.cb));
        }
        if (trailer.bid == entry.bid) {
            ++blocks.bid_matches;
        } else {
            ++blocks.bid_mismatches;
            failures.add(entry.ib + trailer_at, "BLOCKTRAILER.bid", trailer.bid,
                         "BBTENTRY.bid is " + std::to_string(entry.bid));
        }

        const uint16_t expected_sig = util::compute_sig(entry.ib, trailer.bid);
        if (expected_sig == trailer.w_sig) {
            ++blocks.sig_ok;
        } else {
            ++blocks.sig_failed;
            failures.add(entry.ib + trailer_at, "BLOCKTRAILER.wSig", trailer.w_sig,
                         "expected " + std::to_string(expected_sig));
        }

        // [MS-PST] 2.2.2.8.1: dwCRC covers only the cb raw data bytes; padding is not part of it.
        tally_crc(blocks.crc_variants, trailer.dw_crc,
                  ByteView(buffer.data(), trailer.cb, entry.ib));
        if (util::crc32(ByteView(buffer.data(), trailer.cb, entry.ib)) == trailer.dw_crc) {
            ++blocks.crc_ok;
        } else {
            ++blocks.crc_failed;
            failures.add(entry.ib + trailer_at, "BLOCKTRAILER.dwCRC", trailer.dw_crc,
                         "block CRC over " + std::to_string(trailer.cb) + " bytes does not match");
        }

        if (profile == FileProfile::kOst) {
            // [MS-PST] 2.2.2.8.1 has no field here. OST writes a block type and the block's
            // uncompressed data length into the 8 bytes past the spec's 16-byte trailer.
            if (trailer.ost_b_typ == 2) {
                ++blocks.type_block;
            } else {
                ++blocks.type_other;
            }
            if (trailer.ost_uncompressed_cb == entry.c_ref) {
                ++blocks.uncompressed_cb_matches;
            } else {
                ++blocks.uncompressed_cb_mismatches;
                failures.add(entry.ib + trailer_at, "BLOCKTRAILER.ostUncompressedCb",
                             trailer.ost_uncompressed_cb,
                             "BBTENTRY +18 is " + std::to_string(entry.c_ref));
            }
            // [MS-PST] 2.2.2.7.7.3 names this slot dwPadding and says it MUST be zero; on the
            // measured OST it is non-zero on 197,742 of 198,111 entries and behaves like a
            // reference count on 197,178 of them. That reading is one sample's measurement and the
            // meaning is unresolved, so the value is counted here and never used as a count.
            if (entry.ost_c_ref < 1) {
                ++blocks.pad_below_one;
            }
        }
    }
    blocks.units_marked = units.count();
    return Status();
}

// [MS-PST] 2.2.2.7.2: one AMap per amap_interval bytes, from the profile's first AMap up to
// ROOT.ibAMapLast ([MS-PST] 2.2.2.5). Each region is read whole, so its bits and the units they
// claim are checked out of one buffer.
Status scan_amap(const util::FileReader& file, FileProfile profile, const Header& header,
                 const ProbeOptions& options, ProbeCounters& counters, FailureLog& failures,
                 const UnitMap& units) {
    AMapCounters& amap = counters.amap;
    const uint64_t region_units = amap_units(profile);
    uint64_t last_ib = 0;

    // [MS-PST] 2.2.2.7.2 / 2.2.2.5: one region per amap_interval bytes up to ROOT.ibAMapLast. The
    // shared iterator does the reading and the per-page checks so the probe and the reader cannot
    // drift apart on what a valid AMap page is.
    for (uint64_t ib : amap_region_offsets(profile, header.root.ib_amap_last)) {
        Result<AMapRegion> loaded = read_amap_region(file, profile, ib, failures);
        if (!loaded.ok()) {
            if (loaded.error().kind == ErrorKind::kTruncated) {
                failures.add(loaded.error());
                break;
            }
            return loaded.error();
        }
        ++amap.regions;
        last_ib = ib;
        const AMapRegion& region = loaded.value();
        if (!region.ptype_ok || !region.sig_ok) {
            continue;
        }

        tally_crc(amap.crc_variants, region.trailer.dw_crc, region.bits());
        if (!region.crc_ok) {
            continue;
        }
        ++amap.regions_valid;
        if (region.self_map_ok) {
            ++amap.self_byte_ok;
        }

        const uint64_t first_unit = amap_first_unit(profile, region.ib);
        const uint8_t* bits = region.bits().data();
        for (uint64_t unit = 0; unit < region_units; ++unit) {
            const uint64_t global = first_unit + unit;
            if (global >= units.units()) {
                break; // [MS-PST] 2.2.2.7.2: the last region may reach past the end of the file
            }
            ++amap.units_mapped;
            const bool mapped = amap_bit_set(bits, unit, options.amap_bit_order);
            if (mapped) {
                ++amap.bits_set;
            }
            if (mapped == units.marked(global)) {
                ++amap.units_agree;
            } else if (mapped) {
                ++amap.marks_unindexed;
            } else {
                ++amap.misses_indexed;
            }
        }
    }

    if (last_ib == header.root.ib_amap_last) {
        ++amap.last_region_matches_ib_amap_last;
    } else {
        failures.add(header.root.ib_amap_last, "ROOT.ibAMapLast", header.root.ib_amap_last,
                     "the AMap chain ends at 0x" + std::to_string(last_ib));
    }
    return Status();
}

// Every page-sized slot in the file judged by its trailer. Slots that pass both dwCRC and wSig are
// real pages; the rest are block data that happens to look like a trailer, so this is a tally and
// never a finding.
Status scan_page_grid(const util::FileReader& file, FileProfile profile, ProbeCounters& counters) {
    PageGridCounters& grid = counters.grid;
    const uint64_t size = page_size(profile);
    const uint64_t chunk = size * 256;
    std::vector<uint8_t> buffer(static_cast<size_t>(chunk));

    for (uint64_t base = 0; base < file.size(); base += chunk) {
        const uint64_t available = file.size() - base;
        const uint64_t whole = std::min<uint64_t>(chunk, (available / size) * size);
        if (whole == 0) {
            break;
        }
        Status io = file.read_at(base, buffer.data(), static_cast<size_t>(whole));
        if (!io) {
            return io.error();
        }
        for (uint64_t offset = 0; offset + size <= whole; offset += size) {
            const uint64_t ib = base + offset;
            ++grid.slots;
            const ByteView view(buffer.data() + offset, static_cast<size_t>(size), ib);
            Result<ByteView> window = view.sub(static_cast<size_t>(bt_trailer_offset(profile)),
                                               static_cast<size_t>(page_trailer_size(profile)));
            if (!window.ok()) {
                continue;
            }
            Result<PageTrailer> decoded = decode_page_trailer(window.value(), profile);
            if (!decoded.ok()) {
                continue;
            }
            const PageTrailer& trailer = decoded.value();
            ++grid.candidates;
            grid.by_ptype[trailer.ptype - kFirstPageType] += 1;

            Result<ByteView> data = view.sub(0, static_cast<size_t>(page_data_bytes(profile)));
            if (!data.ok()) {
                continue;
            }
            tally_crc(grid.crc_variants, trailer.dw_crc, data.value());
            const bool crc_ok = util::crc32(data.value()) == trailer.dw_crc;
            const bool sig_ok = page_type_uses_zero_sig(trailer.ptype)
                                    ? (trailer.w_sig == 0 && trailer.bid == ib)
                                    : (util::compute_sig(ib, trailer.bid) == trailer.w_sig);
            if (!crc_ok) {
                ++grid.crc_failed;
            }
            if (!sig_ok) {
                ++grid.sig_failed;
            }
            if (crc_ok && sig_ok) {
                ++grid.accepted;
                grid.accepted_by_ptype[trailer.ptype - kFirstPageType] += 1;
                if (trailer.ptype == kPageTypeDList) {
                    ++counters.dlist_pages;
                    if (ib == dlist_offset(profile)) {
                        ++counters.dlist_at_expected_offset;
                    }
                }
            }
        }
    }
    return Status();
}

} // namespace

namespace {

std::string hex64(uint64_t value) {
    char text[24];
    std::snprintf(text, sizeof(text), "0x%llX", static_cast<unsigned long long>(value));
    return text;
}

} // namespace

Result<ProbeReport> probe_file(const util::FileReader& file, const ProbeOptions& options) {
    std::vector<uint8_t> header_bytes(static_cast<size_t>(kHeaderSize));
    Status io = file.read_at(kHeaderOffset, header_bytes.data(), header_bytes.size());
    if (!io) {
        return io.error();
    }
    const ByteView header_view(header_bytes.data(), header_bytes.size(), kHeaderOffset);

    Result<Header> header = decode_header(header_view);
    if (!header.ok()) {
        return header.error();
    }

    ProbeReport report;
    report.header = header.value();

    Result<HeaderCrcReport> crcs = verify_header_crcs(header_view);
    if (!crcs.ok()) {
        return crcs.error();
    }
    report.header_crcs = crcs.value();

    // [MS-PST] 2.6.1.3.7: fAMapValid is checked before any AMap is trusted; the other refusals are
    // formats whose bytes this project cannot interpret without Outlook.
    Status refusal = validate_header_refusals(report.header);
    if (!refusal) {
        report.refusal = refusal.error();
        report.clean = false;
        return report;
    }

    Result<FileProfile> profile = detect_profile(file, report.header.root.bbt_bref.ib);
    if (!profile.ok()) {
        return profile.error();
    }
    report.profile = profile.value();
    report.profile_evidence = std::string(file_profile_name(report.profile)) +
                              ": the root BBT page at " + hex64(report.header.root.bbt_bref.ib) +
                              " has a valid trailer and dwCRC at " +
                              std::to_string(page_size(report.profile)) + "-byte pages";

    FailureLog failures(options.max_failures);
    ProbeCounters& counters = report.counters;

    // [MS-PST] 2.2.2.1 says wMagicClient is "SM"; OST writes "SO". The page layout decides the
    // profile, so a file whose two signals disagree is worth reporting.
    const bool magic_says_ost = report.header.w_magic_client[1] == kWMagicClientO;
    if (magic_says_ost != (report.profile == FileProfile::kOst)) {
        failures.add(kHeaderOffset + kWMagicClientOffset, "HEADER.wMagicClient",
                     report.header.w_magic_client[1],
                     "wMagicClient says " + magic_client_text(report.header) +
                         " but the page layout says " + file_profile_name(report.profile));
    }

    counters.file_eof_matches_size = report.header.root.ib_file_eof == file.size();
    if (!counters.file_eof_matches_size) {
        failures.add(kHeaderOffset + kRootIbFileEofOffset, "ROOT.ibFileEof",
                     report.header.root.ib_file_eof, "file size is " + std::to_string(file.size()));
    }

    const uint64_t granularity = block_granularity(report.profile);
    util::ByteBudget workspace(options.workspace_budget);
    auto* budget = options.workspace_budget ? &workspace : nullptr;
    if (budget) {
        auto reserved =
            budget->reserve(((file.size() / granularity + 1 + 63) / 64) * 8, "probe.workspace");
        if (!reserved.ok())
            return reserved.error();
    }
    UnitMap units(file.size() / granularity + 1, granularity);

    BTreeWalker bbt(kPageTypeBBT, report.profile, &failures, budget);
    Status walked = bbt.walk(file, report.header.root.bbt_bref.ib);
    if (!walked) {
        return walked.error();
    }
    counters.bbt = bbt.stats();
    counters.bbt_index_entries = bbt.bbt_index().size();

    Status status = verify_blocks(file, report.profile, bbt, options, counters, failures, units);
    if (!status) {
        return status.error();
    }

    BTreeWalker nbt(kPageTypeNBT, report.profile, &failures, budget);
    const std::unordered_map<uint64_t, BbtEntry>& index = bbt.bbt_index();
    nbt.set_nbt_handler([&](const NbtEntry& entry, uint64_t) {
        ++counters.nbt_entries;
        if (entry.bid_data != 0 && index.find(entry.bid_data) == index.end()) {
            ++counters.nbt_bid_data_missing;
        }
        if (entry.bid_sub != 0 && index.find(entry.bid_sub) == index.end()) {
            ++counters.nbt_bid_sub_missing;
        }
    });
    walked = nbt.walk(file, report.header.root.nbt_bref.ib);
    if (!walked) {
        return walked.error();
    }
    counters.nbt = nbt.stats();

    status = scan_amap(file, report.profile, report.header, options, counters, failures, units);
    if (!status) {
        return status.error();
    }
    status = scan_page_grid(file, report.profile, counters);
    if (!status) {
        return status.error();
    }

    report.failure_total = failures.total();
    report.failures = failures.failures();
    report.clean =
        report.failure_total == 0 && report.header_crcs.partial_ok && report.header_crcs.full_ok;
    return report;
}

} // namespace ost2pst::ndb
