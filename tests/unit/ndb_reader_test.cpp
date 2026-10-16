// M1's exit criteria, measured against a format-true synthetic OST instead of the 2.6 GB sample:
// every NBT entry enumerated, every block an NBTENTRY.bidData names resolved through the BBT and
// CRC-verified, the header's claims checked against the file, and a truncated file reported as a
// data error at an absolute offset instead of crashing.
#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "ost2pst/ndb/bbt_index.h"
#include "ost2pst/ndb/block_reader.h"
#include "ost2pst/ndb/btree.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/ndb/ndb_read.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/ndb/trailer.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/crc32.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/status.h"
#include "test_support.h"

namespace {

using ost2pst::ndb::AMapBitOrder;
using ost2pst::ndb::BbtIndex;
using ost2pst::ndb::BlockData;
using ost2pst::ndb::BlockReadCounters;
using ost2pst::ndb::BTreeWalker;
using ost2pst::ndb::FailureLog;
using ost2pst::ndb::FileProfile;
using ost2pst::ndb::for_each_allocated_unit;
using ost2pst::ndb::kPageTypeBBT;
using ost2pst::ndb::NdbReadOptions;
using ost2pst::ndb::NdbReadReport;
using ost2pst::ndb::NidTypeCount;
using ost2pst::ndb::ProbeFailure;
using ost2pst::ndb::read_block;
using ost2pst::ndb::read_ndb;
using ost2pst::test::fixture_path;
using ost2pst::test::golden_number;
using ost2pst::test::golden_path;
using ost2pst::test::golden_value;
using ost2pst::test::read_text;
using ost2pst::util::ByteView;
using ost2pst::util::ErrorKind;
using ost2pst::util::FileReader;
using ost2pst::util::Result;

constexpr FileProfile kProfile = FileProfile::kOst;
constexpr const char *kFixture = "synthetic-ost.bin";
constexpr const char *kTruncated = "synthetic-ost-truncated.bin";

std::string golden(const std::string &text, const std::string &key) {
    const std::optional<std::string> value = golden_value(text, key);
    if (!value) {
        ost2pst::test::report_failure(__FILE__, __LINE__, "golden key missing: " + key);
        return {};
    }
    return *value;
}

std::string hex(uint64_t value) {
    char text[24];
    std::snprintf(text, sizeof(text), "0x%llx", static_cast<unsigned long long>(value));
    return text;
}

FileReader open_fixture(const char *name) {
    Result<FileReader> opened = FileReader::open(std::filesystem::path(fixture_path(name)).wstring());
    TEST_OK(opened, name);
    if (!opened.ok()) {
        return FileReader();
    }
    return opened.take();
}

// The whole M1 promise in one call: the report has to be clean and every counter has to match the
// golden file the fixture generator wrote.
void check_full_read() {
    const std::string gold = read_text(golden_path("synthetic-ndb.json"));
    const FileReader file = open_fixture(kFixture);
    if (!file.is_open()) {
        return;
    }

    NdbReadOptions options;
    options.max_failures = 20;
    Result<NdbReadReport> report = read_ndb(file, options);
    TEST_OK(report, "read_ndb on the synthetic OST");
    if (!report.ok()) {
        return;
    }

    const NdbReadReport &value = report.value();
    TEST_EQ(value.clean, 1, "synthetic OST reads clean");
    TEST_EQ(value.failure_total, 0, "no findings");
    TEST_EQ(static_cast<uint64_t>(value.profile), static_cast<uint64_t>(FileProfile::kOst),
            "profile detected from the root BBT page");
    TEST_EQ(value.header_crcs.partial_ok, 1, "dwCRCPartial");
    TEST_EQ(value.header_crcs.full_ok, 1, "dwCRCFull");
    TEST_EQ(value.bbt.leaf_entries, golden_number(gold, "bbt_entries"), "BBT leaf entries");
    TEST_EQ(value.nbt.leaf_entries, golden_number(gold, "nbt_entries"), "NBT leaf entries");
    TEST_EQ(value.counters.nbt_entries, golden_number(gold, "nbt_entries"), "NBT entries enumerated");
    TEST_EQ(value.counters.nbt_bid_data_missing, golden_number(gold, "nbt_bid_data_missing"),
            "every bidData resolves through the BBT");
    TEST_EQ(value.counters.nbt_bid_sub_missing, 0, "every bidSub resolves through the BBT");
    TEST_EQ(value.counters.bbt_index_entries, golden_number(gold, "bbt_entries"), "BBT index size");
    TEST_EQ(value.counters.bbt_min_bid, golden_number(gold, "bbt_min_bid"), "lowest BID in the BBT");
    TEST_EQ(value.counters.bbt_max_bid, golden_number(gold, "bbt_max_bid"), "highest BID in the BBT");
    TEST_EQ(value.counters.amap_regions_valid, golden_number(gold, "amap_regions_valid"),
            "valid AMap regions");
    TEST_EQ(value.counters.amap_units_allocated, golden_number(gold, "amap_units_allocated"),
            "allocation units the AMap chain marks");
    TEST_EQ(value.counters.file_eof_matches_size, 1, "ROOT.ibFileEof equals the file size");
    TEST_EQ(value.counters.bid_next_b_covers, 1, "bidNextB is above every block BID seen");
    TEST_EQ(value.counters.bid_next_p_covers, 1, "bidNextP is above every page BID seen");
    TEST_EQ(value.blocks.requested, golden_number(gold, "blocks_requested"), "blocks requested");
    TEST_EQ(value.blocks.crc_ok, golden_number(gold, "blocks_crc_ok"), "block CRCs verified");
    TEST_EQ(value.blocks.cb_matches, golden_number(gold, "blocks_cb_matches"),
            "BLOCKTRAILER.cb agrees with BBTENTRY.cb");
    TEST_EQ(value.blocks.data_bytes, golden_number(gold, "blocks_data_bytes"), "raw block bytes read");
}

// [MS-PST] 2.2.2.2: NID = (nidIndex << 5) | nidType. The histogram is what M3 reads next, so the
// fixture deliberately carries four different types.
void check_nid_type_histogram() {
    const std::string gold = read_text(golden_path("synthetic-ndb.json"));
    const FileReader file = open_fixture(kFixture);
    if (!file.is_open()) {
        return;
    }
    NdbReadOptions options;
    options.scan_amap = false;
    Result<NdbReadReport> report = read_ndb(file, options);
    TEST_OK(report, "read_ndb for the histogram");
    if (!report.ok()) {
        return;
    }

    std::string actual;
    for (const NidTypeCount &count : report.value().nid_types) {
        if (!actual.empty()) {
            actual += ",";
        }
        actual += hex(count.nid_type) + "=" + std::to_string(count.entries);
    }
    TEST_STR(actual, golden(gold, "nid_type_counts"), "per-nidType entry counts");

    // nidType 0x02 is a folder and is the only fixture node with a subnode BTree; 0x1F is the LTP and
    // has neither a data block nor a subnode.
    for (const NidTypeCount &count : report.value().nid_types) {
        if (count.nid_type == 0x02) {
            TEST_EQ(count.with_bid_data, 1, "folder bidData count");
            TEST_EQ(count.with_bid_sub, 1, "folder bidSub count");
        }
        if (count.nid_type == 0x1F) {
            TEST_EQ(count.with_bid_data, 0, "LTP bidData count");
            TEST_EQ(count.with_bid_sub, 0, "LTP bidSub count");
        }
    }
}

// The BID-to-bytes step on its own: the index side and the block side have to agree on cb, bid, wSig
// and the CRC over exactly cb bytes ([MS-PST] 2.2.2.7.7.3 / 2.2.2.8.1 / 2.2.2.8.2).
void check_blocks_resolve() {
    const std::string gold = read_text(golden_path("synthetic-ndb.json"));
    const FileReader file = open_fixture(kFixture);
    if (!file.is_open()) {
        return;
    }

    FailureLog failures(20);
    BTreeWalker walker(kPageTypeBBT, kProfile, &failures);
    TEST_OK(walker.walk(file, golden_number(gold, "bbt_ib")), "walk the BBT");
    const BbtIndex index(walker.bbt_index());
    TEST_EQ(index.entries(), golden_number(gold, "bbt_entries"), "BBT index entries");

    BlockReadCounters counters;
    const uint64_t bids[] = {0x10, 0x14, 0x18};
    for (const uint64_t bid : bids) {
        const std::string name = hex(bid);
        Result<BlockData> block = read_block(file, kProfile, index, bid, counters, failures);
        TEST_OK(block, "read block " + name);
        if (!block.ok()) {
            continue;
        }
        const BlockData &value = block.value();
        TEST_EQ(value.bid, bid, "block BID echoes the BID asked for");
        TEST_EQ(value.ib, golden_number(gold, "block_ib_" + name), "block offset from BBTENTRY.ib");
        TEST_EQ(value.cb, golden_number(gold, "block_cb_" + name), "block cb from BBTENTRY.cb");
        TEST_EQ(value.data.size(), value.cb, "read_block hands back exactly cb bytes");
        const ByteView data(value.data.data(), value.data.size(), value.ib);
        TEST_EQ(ost2pst::util::crc32(data), golden_number(gold, "block_crc_" + name),
                "block bytes match the golden CRC");
    }

    TEST_EQ(counters.requested, 3, "requested");
    TEST_EQ(counters.decoded, 3, "trailers decoded");
    TEST_EQ(counters.cb_matches, 3, "cb agrees");
    TEST_EQ(counters.bid_matches, 3, "bid agrees");
    TEST_EQ(counters.sig_ok, 3, "wSig agrees");
    TEST_EQ(counters.crc_ok, 3, "CRC agrees");
    TEST_EQ(counters.crc_failed, 0, "no CRC failure");
    TEST_EQ(counters.not_indexed, 0, "no unindexed BID");
    TEST_EQ(counters.out_of_range, 0, "no footprint past the file");
    TEST_EQ(counters.data_bytes, golden_number(gold, "blocks_data_bytes"), "raw bytes counted");

    // A BID the BBT does not index is an error, not a silent zero-length block.
    BlockReadCounters missing_counters;
    FailureLog missing_failures(5);
    Result<BlockData> missing = read_block(file, kProfile, index, 0x999, missing_counters, missing_failures);
    TEST_ERROR(missing, ErrorKind::kBadField, "BBTENTRY.bid", "unindexed BID");
    TEST_EQ(missing_counters.requested, 1, "an unindexed BID is still counted as requested");
    TEST_EQ(missing_counters.not_indexed, 1, "not_indexed counted");
}

// A file cut inside a block footprint is corrupt, not fatal: the walk keeps going, counts the block
// it cannot read, and names the absolute offset of the entry that pointed at it.
void check_truncated_fixture() {
    const std::string gold = read_text(golden_path("synthetic-ndb.json"));
    const FileReader file = open_fixture(kTruncated);
    if (!file.is_open()) {
        return;
    }
    TEST_EQ(file.size(), golden_number(gold, "truncated_size"), "truncated fixture size");

    NdbReadOptions options;
    options.max_failures = 20;
    Result<NdbReadReport> report = read_ndb(file, options);
    TEST_OK(report, "read_ndb on the truncated fixture");
    if (!report.ok()) {
        return;
    }

    const NdbReadReport &value = report.value();
    TEST_EQ(value.clean, 0, "a truncated file is never clean");
    TEST_EQ(value.failure_total, golden_number(gold, "truncated_findings"), "finding count");
    TEST_EQ(value.counters.file_eof_matches_size, 0, "ROOT.ibFileEof stops matching the file");
    TEST_EQ(value.blocks.requested, golden_number(gold, "truncated_blocks_requested"),
            "every bidData is still requested");
    TEST_EQ(value.blocks.out_of_range, golden_number(gold, "truncated_blocks_out_of_range"),
            "the cut block is the only one that cannot fit");
    TEST_EQ(value.blocks.crc_ok, golden_number(gold, "truncated_blocks_crc_ok"),
            "the blocks that still fit keep verifying");
    TEST_EQ(value.blocks.data_bytes, golden_number(gold, "truncated_blocks_data_bytes"),
            "raw bytes counted from the readable blocks");
    TEST_EQ(value.counters.nbt_entries, golden_number(gold, "nbt_entries"),
            "the walk enumerates every entry it can reach");

    const uint64_t wanted_offset = golden_number(gold, "truncated_failure_offset");
    const std::string wanted_field = golden(gold, "truncated_failure_field");
    bool named_the_block = false;
    for (const ProbeFailure &failure : value.failures) {
        if (failure.offset == wanted_offset && failure.field == wanted_field) {
            named_the_block = true;
        }
    }
    TEST_CHECK(named_the_block);

    FailureLog failures(5);
    BTreeWalker walker(kPageTypeBBT, kProfile, &failures);
    TEST_OK(walker.walk(file, golden_number(gold, "bbt_ib")), "walk the truncated BBT");
    const BbtIndex index(walker.bbt_index());
    BlockReadCounters counters;
    Result<BlockData> block = read_block(file, kProfile, index, 0x18, counters, failures);
    TEST_ERROR(block, ErrorKind::kBadField, "BBTENTRY.ib", "block footprint past the end of the file");
    TEST_ERROR_OFFSET(block, wanted_offset, "block footprint past the end of the file");
}

// The two switches the CLI exposes both have to actually skip work.
void check_options() {
    const std::string gold = read_text(golden_path("synthetic-ndb.json"));
    const FileReader file = open_fixture(kFixture);
    if (!file.is_open()) {
        return;
    }
    NdbReadOptions options;
    options.verify_bid_data = false;
    options.scan_amap = false;
    Result<NdbReadReport> report = read_ndb(file, options);
    TEST_OK(report, "read_ndb with verification off");
    if (!report.ok()) {
        return;
    }
    TEST_EQ(report.value().blocks.requested, 0, "verify_bid_data off reads no block");
    TEST_EQ(report.value().counters.amap_regions, 0, "scan_amap off visits no region");
    TEST_EQ(report.value().counters.nbt_entries, 4, "the NBT walk still enumerates entries");
    TEST_EQ(report.value().counters.amap_units_allocated, 0, "no units counted without a scan");

    // [MS-PST] 2.2.2.7.2 states one bit per allocation unit but never the bit order inside a byte.
    // Flipping the order marks the same number of units at the wrong offsets, so the check that
    // matters is whether the units the BBT really allocates come out marked. That is how M0 measured
    // MSB-first on the sample OST.
    const uint64_t amap_ib = golden_number(gold, "amap_ib");
    FailureLog amap_failures(5);
    uint64_t regions = 0;
    uint64_t valid_regions = 0;

    std::vector<uint64_t> measured_order;
    TEST_OK(for_each_allocated_unit(file, kProfile, amap_ib, AMapBitOrder::kMostSignificantFirst,
                                    amap_failures,
                                    [&](uint64_t unit, uint64_t) {
                                        measured_order.push_back(unit);
                                        return true;
                                    },
                                    &regions, &valid_regions),
            "AMap walk in the measured bit order");
    TEST_EQ(regions, 1, "one region in the chain");
    TEST_EQ(valid_regions, 1, "the region passes every AMap page check");
    TEST_EQ(measured_order.size(), golden_number(gold, "amap_units_allocated"),
            "units marked in the measured order");

    std::vector<uint64_t> flipped_order;
    FailureLog flipped_failures(5);
    TEST_OK(for_each_allocated_unit(file, kProfile, amap_ib, AMapBitOrder::kLeastSignificantFirst,
                                    flipped_failures,
                                    [&](uint64_t unit, uint64_t) {
                                        flipped_order.push_back(unit);
                                        return true;
                                    },
                                    &regions, &valid_regions),
            "AMap walk in the other bit order");
    TEST_EQ(flipped_order.size(), measured_order.size(), "the bit order moves units, it does not add any");

    const uint64_t block_offsets[] = {golden_number(gold, "block_ib_0x10"),
                                      golden_number(gold, "block_ib_0x14"),
                                      golden_number(gold, "block_ib_0x18")};
    for (const uint64_t ib : block_offsets) {
        const uint64_t unit = ib / ost2pst::ndb::block_granularity(kProfile);
        TEST_CHECK(std::find(measured_order.begin(), measured_order.end(), unit) !=
                   measured_order.end());
        TEST_CHECK(std::find(flipped_order.begin(), flipped_order.end(), unit) == flipped_order.end());
    }
}

} // namespace

int main() {
    check_full_read();
    check_nid_type_histogram();
    check_blocks_resolve();
    check_truncated_fixture();
    check_options();
    return ost2pst::test::finish("ndb_reader_test");
}
