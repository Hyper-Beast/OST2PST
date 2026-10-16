// A node's data sits in one data block, or in the blocks a jump table names when it does not fit
// ([MS-PST] 2.2.2.8.3.2). Which of the two it is comes from the internal bit of the BID
// ([MS-PST] 2.2.2.2 bit B), never from trying a jump-table decode and falling back when it fails: a
// data block whose bytes happen to look like a table would be read as metadata, and a corrupt table
// would be read as data. This file checks that classification, the level and length checks, and the
// cycle and work caps.
#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "ost2pst/ltp/data_tree.h"
#include "ost2pst/ltp/hn_block.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

#include "test_support.h"

namespace {

using ost2pst::ltp::BlockSource;
using ost2pst::ltp::DataTreeCounters;
using ost2pst::ltp::HnFragment;
using ost2pst::ltp::read_data_tree;
using ost2pst::ndb::bid_index;
using ost2pst::ndb::bid_is_internal;
using ost2pst::ndb::bid_lookup_key;
using ost2pst::ndb::FailureLog;
using ost2pst::ndb::FileProfile;
using ost2pst::test::finish;
using ost2pst::util::ByteView;
using ost2pst::util::ErrorKind;
using ost2pst::util::make_error;
using ost2pst::util::Result;

// The 4k profile is the one an OST uses, and its hidBlockIndex width is what caps a node's data
// tree.
constexpr FileProfile kProfile = FileProfile::kOst;

// [MS-PST] 2.2.2.2: bidIndex steps by four and the BBT stores an internal block's BID with bit B
// set. So a BID with both flag bits clear names a data block and one with bit B set names an
// internal block, and the two share a bidIndex without being the same block.
constexpr uint64_t kDataBid = 0x4000;
constexpr uint64_t kDataBid2 = 0x4004;
constexpr uint64_t kDataBid3 = 0x4008;
constexpr uint64_t kXblockBid = 0x1002;  // bit B set: an XBLOCK
constexpr uint64_t kXblockBid2 = 0x1006; // bit B set: a second XBLOCK
constexpr uint64_t kXxblockBid = 0x100A; // bit B set: an XXBLOCK

void put8(std::vector<uint8_t>& out, uint8_t value) {
    out.push_back(value);
}

void put16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
}

void put32(std::vector<uint8_t>& out, uint32_t value) {
    for (uint64_t index = 0; index < 4; ++index) {
        out.push_back(static_cast<uint8_t>((value >> (8 * index)) & 0xFF));
    }
}

void put64(std::vector<uint8_t>& out, uint64_t value) {
    for (int shift = 0; shift < 8; ++shift) {
        out.push_back(static_cast<uint8_t>((value >> (8 * shift)) & 0xFF));
    }
}

// [MS-PST] 2.2.2.8.3.2.1 / 2.2.2.8.3.2.2: btype, cLevel, cEnt, lcbTotal, then cEnt BIDs.
std::vector<uint8_t> jump_table(uint8_t level, const std::vector<uint64_t>& bids,
                                uint32_t lcb_total) {
    std::vector<uint8_t> out;
    put8(out, 0x01);
    put8(out, level);
    put16(out, static_cast<uint16_t>(bids.size()));
    put32(out, lcb_total);
    for (uint64_t bid : bids) {
        put64(out, bid);
    }
    return out;
}

std::vector<uint8_t> payload(size_t size, uint8_t fill) {
    return std::vector<uint8_t>(size, fill);
}

// The BBT side of a BID: the block is Internal exactly when the BID it is indexed under carries bit
// B, and a lookup clears bit A first ([MS-PST] 2.2.2.2).
class FakeBlocks : public BlockSource {
  public:
    void add(uint64_t bid, std::vector<uint8_t> bytes) {
        blocks_[bid_lookup_key(bid)] = std::move(bytes);
    }
    void drop(uint64_t bid) { blocks_.erase(bid_lookup_key(bid)); }

    Result<ost2pst::ltp::BlockBytes> block(uint64_t bid) override {
        const auto found = blocks_.find(bid_lookup_key(bid));
        if (found == blocks_.end()) {
            return make_error(ErrorKind::kIo, "BlockSource.block", 0, bid,
                              "no such block in the fixture");
        }
        held_ = found->second;
        return ost2pst::ltp::BlockBytes{ByteView(held_.data(), held_.size(), bid_index(bid) * 4096),
                                        bid_is_internal(found->first)};
    }

  private:
    std::map<uint64_t, std::vector<uint8_t>> blocks_;
    std::vector<uint8_t> held_;
};

// A source that masks both flag bits off a reference can hand back the neighbouring block that
// shares its bidIndex. [MS-PST] 2.2.2.2 keeps bit B in the lookup key so that cannot happen
// silently; this source does it anyway, which is what the walk's own cross-check is for.
class LooseBlocks : public BlockSource {
  public:
    void add(uint64_t bid, std::vector<uint8_t> bytes) {
        blocks_[bid_index(bid)] = Stored{std::move(bytes), bid_is_internal(bid)};
    }

    Result<ost2pst::ltp::BlockBytes> block(uint64_t bid) override {
        const auto found = blocks_.find(bid_index(bid));
        if (found == blocks_.end()) {
            return make_error(ErrorKind::kIo, "BlockSource.block", 0, bid,
                              "no such block in the fixture");
        }
        held_ = found->second.bytes;
        return ost2pst::ltp::BlockBytes{ByteView(held_.data(), held_.size(), bid_index(bid) * 4096),
                                        found->second.internal};
    }

  private:
    struct Stored {
        std::vector<uint8_t> bytes;
        bool internal = false;
    };

    std::map<uint64_t, Stored> blocks_;
    std::vector<uint8_t> held_;
};
// An external block whose bytes happen to be a well-formed jump table is still the node's data: the
// tree ends there and the table's own bytes are what the node holds.
void check_external_block_that_looks_like_a_table() {
    FakeBlocks blocks;
    const std::vector<uint8_t> looks_like_table = jump_table(1, {kDataBid2, kDataBid3}, 8);
    blocks.add(kDataBid, looks_like_table);
    blocks.add(kDataBid2, payload(4, 0x11));
    blocks.add(kDataBid3, payload(4, 0x22));

    DataTreeCounters counters;
    FailureLog failures(5);
    const Result<std::vector<HnFragment>> tree =
        read_data_tree(blocks, kDataBid, kProfile, counters, failures);
    TEST_OK(tree, "an external block stays the data it holds");
    if (tree.ok()) {
        TEST_EQ(tree.value().size(), 1u, "one fragment: the block itself");
        TEST_EQ(tree.value()[0].block.bytes().size(), looks_like_table.size(),
                "its own bytes, not the blocks its header names");
        TEST_EQ(tree.value()[0].block.bytes().data()[1], 0x01,
                "the jump-table-looking bytes survived");
    }
    TEST_EQ(counters.trees, 1u, "a data tree of one block");
    TEST_EQ(counters.tables, 0u, "no jump table decoded");
    TEST_EQ(counters.data_blocks, 1u, "the one data block");
    TEST_EQ(counters.failed_trees, 0u, "nothing failed");
    TEST_EQ(failures.total(), 0u, "nothing logged");
}

// An internal block that is not a decodable jump table is a finding about the node, not a licence
// to read the block as data.
void check_internal_block_that_is_not_a_table() {
    FakeBlocks blocks;
    blocks.add(kXblockBid, payload(64, 0x5A)); // btype is 0x5A, not 0x01

    DataTreeCounters counters;
    FailureLog failures(5);
    const Result<std::vector<HnFragment>> tree =
        read_data_tree(blocks, kXblockBid, kProfile, counters, failures);
    TEST_ERROR(tree, ErrorKind::kBadField, "XBLOCK.btype",
               "an internal block that is not a jump table");
    TEST_EQ(counters.rejected_tables, 1u, "the rejected table counted");
    TEST_EQ(counters.failed_trees, 1u, "and the tree failed instead of falling back to data");
    TEST_EQ(counters.data_blocks, 0u, "no data invented out of its bytes");
    TEST_EQ(counters.errors.at("XBLOCK.btype"), 1u, "the finding tallied by field");
    TEST_EQ(failures.total(), 1u, "and logged once");
}

// A truncated jump table is a truncation, reported as one.
void check_truncated_internal_block() {
    std::vector<uint8_t> truncated = jump_table(1, {kDataBid}, 4);
    truncated.resize(12); // cEnt names one BID, the block is cut in the middle of it
    FakeBlocks blocks;
    blocks.add(kXblockBid, truncated);

    DataTreeCounters counters;
    FailureLog failures(5);
    const Result<std::vector<HnFragment>> tree =
        read_data_tree(blocks, kXblockBid, kProfile, counters, failures);
    TEST_ERROR(tree, ErrorKind::kTruncated, "XBLOCK.rgid", "a jump table cut short of cEnt");
    TEST_EQ(counters.rejected_tables, 1u, "counted as a rejected table");
    TEST_EQ(counters.failed_trees, 1u, "not downgraded to a data block");
}

// [MS-PST] 2.2.2.8.3.2.1: only a data block sits under an XBLOCK, so a child with the internal bit
// set is a contradiction the walk reports instead of descending into.
void check_xblock_naming_an_internal_child() {
    FakeBlocks blocks;
    blocks.add(kXblockBid, jump_table(1, {kDataBid, kXblockBid2}, 4));
    blocks.add(kDataBid, payload(4, 0x11));
    blocks.add(kXblockBid2, jump_table(1, {kDataBid2}, 4));
    blocks.add(kDataBid2, payload(4, 0x22));

    DataTreeCounters counters;
    FailureLog failures(5);
    const Result<std::vector<HnFragment>> tree =
        read_data_tree(blocks, kXblockBid, kProfile, counters, failures);
    TEST_ERROR(tree, ErrorKind::kBadField, "XBLOCK.rgid", "an XBLOCK that names an Internal block");
    TEST_EQ(counters.child_flag_mismatches, 1u, "the level contradiction counted");
    TEST_EQ(counters.failed_trees, 1u, "and the tree failed");
}

// [MS-PST] 2.2.2.8.3.2.2: an XXBLOCK names XBLOCKs, so an XXBLOCK below the top of the tree names a
// block that is not a data block.
void check_xxblock_below_the_top() {
    FakeBlocks blocks;
    blocks.add(kXxblockBid, jump_table(2, {kXblockBid}, 4));
    blocks.add(kXblockBid, jump_table(2, {kDataBid}, 4)); // cLevel 2 again, one level too deep
    blocks.add(kDataBid, payload(4, 0x11));

    DataTreeCounters counters;
    FailureLog failures(5);
    const Result<std::vector<HnFragment>> tree =
        read_data_tree(blocks, kXxblockBid, kProfile, counters, failures);
    TEST_ERROR(tree, ErrorKind::kBadField, "XBLOCK.cLevel",
               "an XXBLOCK below the top of a data tree");
    TEST_EQ(counters.child_flag_mismatches, 1u, "counted as a level contradiction");
    TEST_EQ(counters.failed_trees, 1u, "and the tree failed");
}

// Two BIDs with one bidIndex: bit B says which block the reference means, so the walk must answer
// with the internal one and not with the external neighbour's bytes.
void check_internal_bit_names_a_different_block() {
    FakeBlocks blocks;
    blocks.add(kDataBid, payload(4, 0x11));       // 0x4000: a data block
    blocks.add(kDataBid | 0x2, payload(4, 0x22)); // 0x4002: same bidIndex, Internal
    blocks.add(kXxblockBid, jump_table(2, {kDataBid | 0x2}, 4));

    DataTreeCounters counters;
    FailureLog failures(5);
    const Result<std::vector<HnFragment>> tree =
        read_data_tree(blocks, kXxblockBid, kProfile, counters, failures);
    TEST_ERROR(tree, ErrorKind::kBadField, "XBLOCK.btype",
               "the internal block the reference named");
    TEST_EQ(counters.rejected_tables, 1u, "it was read as the internal block it claims to be");
    TEST_EQ(counters.data_blocks, 0u, "and the external neighbour was not substituted for it");
}

// The cross-check for the case a source resolves a reference to a block whose index says otherwise.
void check_reference_and_index_disagree_about_internal() {
    LooseBlocks blocks;
    // An XXBLOCK may name an Internal block, so the level check passes and only the index
    // disagrees.
    blocks.add(kXxblockBid, jump_table(2, {kDataBid | 0x2}, 4)); // the table calls it Internal...
    blocks.add(kDataBid, payload(4, 0x11)); // ...the block it resolves to is not

    DataTreeCounters counters;
    FailureLog failures(5);
    const Result<std::vector<HnFragment>> tree =
        read_data_tree(blocks, kXxblockBid, kProfile, counters, failures);
    TEST_ERROR(tree, ErrorKind::kBadField, "XBLOCK.rgid",
               "a reference whose internal bit contradicts the BBTENTRY");
    TEST_EQ(counters.index_flag_mismatches, 1u, "the contradiction counted");
    TEST_EQ(counters.failed_trees, 1u, "and the tree failed");
}

// [MS-PST] 2.2.2.8.3.2.1: lcbTotal is the total bytes of the external data under the table, so the
// blocks the table names have to add up to it.
void check_lcb_total_mismatch() {
    FakeBlocks blocks;
    blocks.add(kXblockBid, jump_table(1, {kDataBid, kDataBid2}, 4 + 4 + 1));
    blocks.add(kDataBid, payload(4, 0x11));
    blocks.add(kDataBid2, payload(4, 0x22));

    DataTreeCounters counters;
    FailureLog failures(5);
    const Result<std::vector<HnFragment>> tree =
        read_data_tree(blocks, kXblockBid, kProfile, counters, failures);
    TEST_ERROR(tree, ErrorKind::kBadField, "XBLOCK.lcbTotal",
               "a table whose lcbTotal is not the data under it");
    TEST_EQ(counters.lcb_total_mismatches, 1u, "the length contradiction counted");
    TEST_EQ(counters.failed_trees, 1u, "and the tree failed");
}

// A block pointing to an ancestor is a cycle. Repeated sibling references are not.
void check_cycle() {
    FakeBlocks blocks;
    blocks.add(kXxblockBid, jump_table(2, {kXxblockBid}, 8));

    DataTreeCounters counters;
    FailureLog failures(5);
    const Result<std::vector<HnFragment>> tree =
        read_data_tree(blocks, kXxblockBid, kProfile, counters, failures);
    TEST_ERROR(tree, ErrorKind::kBadField, "XBLOCK.rgid",
               "a data tree that points back to its active ancestor");
    TEST_EQ(counters.cycles, 1u, "the cycle counted");
    TEST_EQ(counters.failed_trees, 1u, "and the tree failed");
}

// [MS-PST] 2.2.2.7.7.3.1 permits single-instancing; each rgbid slot references data.
// Each occurrence contributes bytes in order, even when several slots share one BID.
void check_shared_blocks() {
    for (const auto profile : {FileProfile::kPst, FileProfile::kOst}) {
        FakeBlocks blocks;
        blocks.add(kDataBid, payload(4, 0x11));
        blocks.add(kDataBid2, payload(2, 0x22));
        blocks.add(kXblockBid, jump_table(1, {kDataBid, kDataBid2, kDataBid}, 10));
        blocks.add(kXxblockBid, jump_table(2, {kXblockBid, kXblockBid}, 20));
        const std::vector<uint8_t> part{0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x11, 0x11, 0x11, 0x11};
        for (const uint64_t root : {kXblockBid, kXxblockBid}) {
            auto expected = part;
            if (root == kXxblockBid)
                expected.insert(expected.end(), part.begin(), part.end());
            DataTreeCounters counters;
            FailureLog failures;
            const auto tree = read_data_tree(blocks, root, profile, counters, failures);
            TEST_OK(tree, "materialize shared external blocks and shared sibling XBLOCKs");
            std::vector<uint8_t> actual;
            if (tree.ok()) {
                for (const auto& fragment : tree.value()) {
                    const auto bytes = fragment.block.bytes();
                    actual.insert(actual.end(), bytes.data(), bytes.data() + bytes.size());
                }
            }
            TEST_CHECK(actual == expected);
            TEST_EQ(counters.cycles, 0u, "sharing is not recursion");
            counters = {};
            actual.clear();
            const auto streamed = ost2pst::ltp::stream_data_tree(
                blocks, root, profile, counters, failures,
                [&](ByteView bytes) -> ost2pst::util::Status {
                    actual.insert(actual.end(), bytes.data(), bytes.data() + bytes.size());
                    return {};
                });
            TEST_OK(streamed, "stream each shared reference in logical order");
            TEST_CHECK(actual == expected);
            TEST_EQ(counters.cycles, 0u, "streaming sharing is not recursion");
        }
        blocks.add(kXblockBid, jump_table(1, {kDataBid, kDataBid}, 4));
        DataTreeCounters counters;
        FailureLog failures;
        TEST_ERROR(read_data_tree(blocks, kXblockBid, profile, counters, failures),
                   ErrorKind::kBadField, "XBLOCK.lcbTotal",
                   "lcbTotal must count each reference, not just unique data");
    }
}

// A BID the BBT does not index is a finding, not a shorter tree.
void check_missing_child() {
    FakeBlocks blocks;
    blocks.add(kXblockBid, jump_table(1, {kDataBid, kDataBid3}, 4));
    blocks.add(kDataBid, payload(4, 0x11));

    DataTreeCounters counters;
    FailureLog failures(5);
    const Result<std::vector<HnFragment>> tree =
        read_data_tree(blocks, kXblockBid, kProfile, counters, failures);
    TEST_ERROR(tree, ErrorKind::kIo, "BlockSource.block", "a child block the source does not hold");
    TEST_EQ(counters.blocks_failed, 1u, "the failed block read counted");
    TEST_EQ(counters.failed_trees, 1u, "and the tree failed rather than returning half the data");
}

// [MS-PST] 2.2.2.8.3.2.2 / 2.2.2.8.3.2.1: an XXBLOCK over two XBLOCKs over data blocks, with every
// lcbTotal matching the bytes under it.
void check_two_level_tree() {
    FakeBlocks blocks;
    blocks.add(kDataBid, payload(4, 0x11));
    blocks.add(kDataBid2, payload(6, 0x22));
    blocks.add(kDataBid3, payload(8, 0x33));
    blocks.add(kXblockBid, jump_table(1, {kDataBid, kDataBid2}, 10));
    blocks.add(kXblockBid2, jump_table(1, {kDataBid3}, 8));
    blocks.add(kXxblockBid, jump_table(2, {kXblockBid, kXblockBid2}, 18));

    DataTreeCounters counters;
    FailureLog failures(5);
    const Result<std::vector<HnFragment>> tree =
        read_data_tree(blocks, kXxblockBid, kProfile, counters, failures);
    TEST_OK(tree, "an XXBLOCK over two XBLOCKs");
    if (tree.ok()) {
        TEST_EQ(tree.value().size(), 3u,
                "the three data blocks, in the order the tables name them");
        TEST_EQ(tree.value()[0].block.bytes().data()[0], 0x11, "the first block's bytes");
        TEST_EQ(tree.value()[2].block.bytes().data()[0], 0x33, "the last block's bytes");
    }
    TEST_EQ(counters.tables, 3u, "three jump tables decoded");
    TEST_EQ(counters.xxblock_tables, 1u, "one of them an XXBLOCK");
    TEST_EQ(counters.data_blocks, 3u, "three data blocks");
    TEST_EQ(counters.max_entries, 2u, "the widest cEnt seen");
    TEST_EQ(counters.max_blocks, 3u, "the widest tree");
    TEST_EQ(counters.lcb_total_mismatches, 0u, "every lcbTotal matched");
    TEST_EQ(failures.total(), 0u, "nothing logged");
}

// A reference may set the reserved bit; [MS-PST] 2.2.2.2 says the reader clears it before the
// lookup.
void check_reference_with_the_reserved_bit() {
    FakeBlocks blocks;
    blocks.add(kXblockBid, jump_table(1, {kDataBid | 0x1}, 4));
    blocks.add(kDataBid, payload(4, 0x11));

    DataTreeCounters counters;
    FailureLog failures(5);
    const Result<std::vector<HnFragment>> tree =
        read_data_tree(blocks, kXblockBid, kProfile, counters, failures);
    TEST_OK(tree, "a reference that sets bit A still finds its block");
    TEST_EQ(counters.data_blocks, 1u, "the data block under it");
    TEST_EQ(counters.index_flag_mismatches, 0u, "bit A is not an internal-bit contradiction");
}

// [MS-PST] 2.3.1.1: a node's data tree cannot hold more data blocks than its HID can name, so the
// walk caps the work instead of trusting a runaway table.
void check_data_block_cap() {
    const uint64_t cap = ost2pst::ltp::data_tree_max_blocks(kProfile);
    FakeBlocks blocks;
    std::vector<uint64_t> first;
    std::vector<uint64_t> second;
    for (uint64_t index = 0; index < cap - 1; ++index) {
        const uint64_t bid = 0x8000 + index * 4;
        blocks.add(bid, payload(1, 0x5A));
        first.push_back(bid);
    }
    for (uint64_t index = 0; index < cap; ++index) {
        const uint64_t bid = 0x8000 + (cap - 1) * 4 + index * 4;
        blocks.add(bid, payload(1, 0x5A));
        second.push_back(bid);
    }
    blocks.add(kXblockBid, jump_table(1, first, static_cast<uint32_t>(first.size())));
    blocks.add(kXblockBid2, jump_table(1, second, static_cast<uint32_t>(second.size())));
    blocks.add(kXxblockBid, jump_table(2, {kXblockBid, kXblockBid2},
                                       static_cast<uint32_t>(first.size() + second.size())));

    DataTreeCounters counters;
    FailureLog failures(5);
    const Result<std::vector<HnFragment>> tree =
        read_data_tree(blocks, kXxblockBid, kProfile, counters, failures);
    TEST_ERROR(tree, ErrorKind::kBadField, "XBLOCK.rgid",
               "a tree wider than a node's hidBlockIndex can name");
    TEST_EQ(counters.capped, 1u, "the cap counted");
    TEST_EQ(counters.failed_trees, 1u, "and the tree failed");
}

// The counters from several seams add up to one report.
void check_merge_counters() {
    DataTreeCounters into;
    into.trees = 2;
    into.tables = 3;
    into.data_blocks = 7;
    into.max_entries = 4;
    into.max_blocks = 5;
    into.max_block_bytes = 100;
    into.max_heap_bytes = 90;
    into.errors["XBLOCK.lcbTotal"] = 2;

    DataTreeCounters from;
    from.trees = 1;
    from.xxblock_tables = 1;
    from.data_blocks = 3;
    from.cycles = 2;
    from.max_entries = 9;
    from.max_blocks = 1;
    from.max_block_bytes = 50;
    from.max_heap_bytes = 200;
    from.errors["XBLOCK.lcbTotal"] = 5;
    from.errors["XBLOCK.cLevel"] = 1;

    ost2pst::ltp::merge_data_tree_counters(into, from);
    TEST_EQ(into.trees, 3u, "trees added");
    TEST_EQ(into.tables, 3u, "tables added");
    TEST_EQ(into.xxblock_tables, 1u, "XXBLOCKs added");
    TEST_EQ(into.data_blocks, 10u, "data blocks added");
    TEST_EQ(into.cycles, 2u, "cycles added");
    TEST_EQ(into.max_entries, 9u, "the widest cEnt kept, not the last one seen");
    TEST_EQ(into.max_blocks, 5u, "the widest tree kept");
    TEST_EQ(into.max_block_bytes, 100u, "the largest block kept");
    TEST_EQ(into.max_heap_bytes, 200u, "the largest heap node kept");
    TEST_EQ(into.errors["XBLOCK.lcbTotal"], 7u, "error tallies merged");
    TEST_EQ(into.errors["XBLOCK.cLevel"], 1u, "a new field added");
}

} // namespace

int main() {
    {
        FakeBlocks blocks;
        blocks.add(kDataBid, payload(65536, 0x11));
        blocks.add(kDataBid2, payload(40000, 0x22));
        blocks.add(kDataBid3, payload(3, 0x33));
        blocks.add(kXblockBid, jump_table(1, {kDataBid, kDataBid2}, 105536));
        blocks.add(kXblockBid2, jump_table(1, {kDataBid3}, 3));
        blocks.add(kXxblockBid, jump_table(2, {kXblockBid, kXblockBid2}, 105539));
        DataTreeCounters streamed_counters;
        FailureLog failures;
        std::vector<uint8_t> streamed;
        size_t max_chunk = 0;
        auto read = ost2pst::ltp::stream_data_tree(
            blocks, kXxblockBid, kProfile, streamed_counters, failures,
            [&](ByteView part) -> ost2pst::util::Status {
                max_chunk = std::max(max_chunk, part.size());
                streamed.insert(streamed.end(), part.data(), part.data() + part.size());
                return {};
            });
        TEST_OK(read, "stream two tree levels through a reused source buffer");
        if (read.ok())
            TEST_EQ(read.value(), 105539u, "validated streamed byte length");
        TEST_CHECK(max_chunk <= 65536);
        DataTreeCounters legacy_counters;
        auto legacy = read_data_tree(blocks, kXxblockBid, kProfile, legacy_counters, failures);
        TEST_OK(legacy, "legacy fragment adapter");
        std::vector<uint8_t> expected;
        if (legacy.ok())
            for (const auto& fragment : legacy.value()) {
                const auto part = fragment.block.bytes();
                expected.insert(expected.end(), part.data(), part.data() + part.size());
            }
        TEST_CHECK(streamed == expected);
        TEST_EQ(streamed_counters.blocks_read, legacy_counters.blocks_read,
                "same verified source blocks");
        TEST_EQ(streamed_counters.data_blocks, legacy_counters.data_blocks,
                "same validated external population");
        ost2pst::util::ByteBudget small_budget(1);
        DataTreeCounters budget_counters;
        TEST_ERROR(
            read_data_tree(blocks, kXxblockBid, kProfile, budget_counters, failures, &small_budget),
            ErrorKind::kUnsupported, "data_tree.workspace",
            "materialization refuses insufficient workspace");
        TEST_EQ(small_budget.used(), 0u, "failed reservation does not allocate fragments");
        ost2pst::util::ByteBudget enough_budget(2 * 1024 * 1024);
        auto bounded = read_data_tree(blocks, kXxblockBid, kProfile, budget_counters, failures,
                                      &enough_budget);
        TEST_OK(bounded, "materialization with sufficient workspace");
        TEST_CHECK(enough_budget.used() <= 2 * 1024 * 1024);
        DataTreeCounters failed_counters;
        auto sink_failure = ost2pst::ltp::stream_data_tree(
            blocks, kXxblockBid, kProfile, failed_counters, failures,
            [](ByteView) -> ost2pst::util::Status {
                return make_error(ErrorKind::kIo, "test.spill_write", 0, 0, "disk full");
            });
        TEST_ERROR(sink_failure, ErrorKind::kIo, "test.spill_write", "consumer I/O propagates");
        TEST_EQ(failed_counters.failed_trees, 1u, "a failed consumer never commits a tree");
        blocks.add(kXxblockBid, jump_table(2, {kXblockBid, kXblockBid2}, 105538));
        failed_counters = {};
        auto length_failure =
            ost2pst::ltp::stream_data_tree(blocks, kXxblockBid, kProfile, failed_counters, failures,
                                           [](ByteView) -> ost2pst::util::Status { return {}; });
        TEST_ERROR(length_failure, ErrorKind::kBadField, "XBLOCK.lcbTotal",
                   "streaming retains parent length checks after a delivered prefix");
        blocks.drop(kDataBid2);
        failed_counters = {};
        auto source_failure =
            ost2pst::ltp::stream_data_tree(blocks, kXxblockBid, kProfile, failed_counters, failures,
                                           [](ByteView) -> ost2pst::util::Status { return {}; });
        TEST_ERROR(source_failure, ErrorKind::kIo, "BlockSource.block",
                   "later source I/O cannot turn a delivered prefix into success");
    }
    check_external_block_that_looks_like_a_table();
    check_internal_block_that_is_not_a_table();
    check_truncated_internal_block();
    check_xblock_naming_an_internal_child();
    check_xxblock_below_the_top();
    check_internal_bit_names_a_different_block();
    check_reference_and_index_disagree_about_internal();
    check_lcb_total_mismatch();
    check_cycle();
    check_shared_blocks();
    check_missing_child();
    check_two_level_tree();
    check_reference_with_the_reserved_bit();
    check_data_block_cap();
    check_merge_counters();
    return finish("ltp_data_tree_test");
}
