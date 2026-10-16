#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "ost2pst/ndb/amap.h"
#include "ost2pst/ndb/btree.h"
#include "ost2pst/ndb/crc.h"
#include "ost2pst/ndb/header.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/ndb/profile.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ndb {

struct ProbeOptions {
    size_t max_failures = 10;
    uint64_t workspace_budget = 0; // Optional engineering ceiling, including the allocation bitmap.
    // How many BBT-indexed blocks get their trailer and CRC checked. 0 means every indexed block.
    uint64_t max_block_verify = 0;
    AMapBitOrder amap_bit_order = AMapBitOrder::kMostSignificantFirst;
};

// Every block the BBT indexes, opened through its own BBTENTRY: footprint, trailer, cb, the OST
// uncompressed-length slot, signature, and a CRC over exactly cb bytes ([MS-PST] 2.2.2.7.7.3
// / 2.2.2.8.1).
struct BlockCounters {
    uint64_t indexed = 0;
    uint64_t verified = 0;
    uint64_t cb_matches = 0;
    uint64_t cb_mismatches = 0;
    uint64_t bid_matches = 0;
    uint64_t bid_mismatches = 0;
    uint64_t uncompressed_cb_matches = 0;
    uint64_t uncompressed_cb_mismatches = 0;
    uint64_t pad_below_one = 0; // [MS-PST] 2.2.2.7.7.3 dwPadding entries below 1: counted, the
                                // slot's meaning is unresolved
    uint64_t type_block = 0;
    uint64_t type_other = 0;
    uint64_t sig_ok = 0;
    uint64_t sig_failed = 0;
    uint64_t crc_ok = 0;
    uint64_t crc_failed = 0;
    uint64_t out_of_range = 0;
    uint64_t units_marked = 0;
    uint64_t max_cb = 0;
    uint64_t max_footprint = 0;
    CrcVariantTally crc_variants;
};

// The AMap chain: one region per amap_interval bytes from the profile's first AMap to ibAMapLast
// ([MS-PST] 2.2.2.7.2). Cross-checked against the units the BBT actually allocated.
struct AMapCounters {
    uint64_t regions = 0;
    uint64_t regions_valid = 0;
    uint64_t self_byte_ok = 0;
    uint64_t bits_set = 0;
    uint64_t units_mapped = 0;
    uint64_t units_agree = 0;
    uint64_t marks_unindexed = 0;
    uint64_t misses_indexed = 0;
    uint64_t last_region_matches_ib_amap_last = 0;
    CrcVariantTally crc_variants;
};

// Every page-sized slot in the file, judged by its trailer alone. Slots that pass CRC and wSig are
// accepted; the rest are data that happens to look like a trailer.
struct PageGridCounters {
    uint64_t slots = 0;
    uint64_t candidates = 0;
    uint64_t accepted = 0;
    uint64_t crc_failed = 0;
    uint64_t sig_failed = 0;
    uint64_t by_ptype[7] = {};
    uint64_t accepted_by_ptype[7] = {};
    CrcVariantTally crc_variants;
};

// M0 reports measurements, never byte dumps: a 2.6 GB file is judged by counters.
struct ProbeCounters {
    BlockCounters blocks;
    AMapCounters amap;
    PageGridCounters grid;
    BTreeStats bbt;
    BTreeStats nbt;
    uint64_t bbt_index_entries = 0;
    uint64_t nbt_entries = 0;
    uint64_t nbt_bid_data_missing = 0;
    uint64_t nbt_bid_sub_missing = 0;
    uint64_t dlist_pages = 0;
    uint64_t dlist_at_expected_offset = 0;
    bool file_eof_matches_size = false;
};

struct ProbeReport {
    Header header;
    HeaderCrcReport header_crcs;
    FileProfile profile = FileProfile::kOst;
    std::string profile_evidence;
    std::optional<util::DataError> refusal;
    ProbeCounters counters;
    std::vector<ProbeFailure> failures;
    uint64_t failure_total = 0;
    bool clean = false;
};

// Full M0 read of one file: header, both header CRCs, the BBT and NBT walks, every indexed block,
// the AMap chain, and a page-trailer tally over the whole file. A refusal short-circuits the walk
// because the bytes below it cannot be interpreted.
util::Result<ProbeReport> probe_file(const util::FileReader& file, const ProbeOptions& options);

} // namespace ost2pst::ndb
