#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "ost2pst/ndb/amap.h"
#include "ost2pst/ndb/block_reader.h"
#include "ost2pst/ndb/btree.h"
#include "ost2pst/ndb/crc.h"
#include "ost2pst/ndb/header.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ndb {

struct NdbReadOptions {
    size_t max_failures = 10;
    bool verify_bid_data = true;  // open and CRC-check every block an NBTENTRY.bidData names
    bool scan_amap = true;        // walk the allocation map chain and count its units
    AMapBitOrder amap_bit_order = AMapBitOrder::kMostSignificantFirst;
};

// [MS-PST] 2.2.2.2: NID = (nidIndex << 5) | nidType, so the low 5 bits say what kind of object the
// entry is. Counting per type is how M3 tells a folder tree from an attachment table.
struct NidTypeCount {
    uint8_t nid_type = 0;
    uint64_t entries = 0;
    uint64_t with_bid_data = 0;
    uint64_t with_bid_sub = 0;
};

struct NdbReadCounters {
    uint64_t nbt_entries = 0;
    uint64_t nbt_bid_data_missing = 0;
    uint64_t nbt_bid_sub_missing = 0;
    uint64_t bbt_index_entries = 0;
    uint64_t bbt_index_bytes = 0;
    uint64_t bbt_index_duplicates = 0;
    uint64_t bbt_min_bid = 0;
    uint64_t bbt_max_bid = 0;
    uint64_t amap_regions = 0;
    uint64_t amap_regions_valid = 0;
    uint64_t amap_units_allocated = 0;
    uint64_t highest_block_bid = 0;
    uint64_t highest_page_bid = 0;
    bool bid_next_b_covers = false;
    bool bid_next_p_covers = false;
    bool file_eof_matches_size = false;
};

// What M1 promises: every NBT entry enumerated, every block a bidData names resolved and CRC-verified,
// and the header's own claims about the file checked against the file.
struct NdbReadReport {
    Header header;
    HeaderCrcReport header_crcs;
    FileProfile profile = FileProfile::kOst;
    std::string profile_evidence;
    std::optional<util::DataError> refusal;
    BTreeStats bbt;
    BTreeStats nbt;
    std::vector<NidTypeCount> nid_types;
    NdbReadCounters counters;
    BlockReadCounters blocks;
    std::vector<ProbeFailure> failures;
    uint64_t failure_total = 0;
    bool clean = false;
};

// Reads the NDB layer of one file. A refusal short-circuits: the bytes under an obfuscated or
// invalid header cannot be interpreted, so walking them would only invent findings.
util::Result<NdbReadReport> read_ndb(const util::FileReader &file, const NdbReadOptions &options);

} // namespace ost2pst::ndb
