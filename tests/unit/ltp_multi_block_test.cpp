// A heap node spread over several data blocks: the node's own block is an XBLOCK jump table, every block
// it names carries its own header and its own HNPAGEMAP, and a HID's hidBlockIndex says which of those
// blocks an allocation lives in. This checks the jump table decoder, the per-block page maps, a HID
// resolved in a block other than the first, and the folder walk that depends on all three -- without it a
// big folder reads as empty.
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "ost2pst/ltp/block_heap.h"
#include "ost2pst/ltp/bth.h"
#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/hn_block.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/ltp_read.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/ltp/tc.h"
#include "ost2pst/ndb/btree.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"
#include "test_support.h"

namespace {

using namespace ost2pst;
using ltp::BlockJumpTable;
using ltp::BlockSource;
using ltp::FolderWalkOptions;
using ltp::FolderWalkStats;
using ltp::HnFragment;
using ltp::LtpFolder;
using ltp::NidMap;
using ltp::NodeFragmentHeapSource;
using ndb::FailureLog;
using ndb::NbtEntry;
using ndb::FileProfile;
using util::ByteView;
using util::ErrorKind;
using util::make_error;
using util::Result;

// A multi-block node is addressed by hidBlockIndex, whose width is profile-specific, so this fixture is
// read under the 4 KiB profile ([MS-PST] 2.3.1.1 as widened by libpff :1558-1559): block i is named by
// HID (i << 19) | 0x20.
constexpr FileProfile kProfile = FileProfile::kOst;

void put16(std::vector<uint8_t> &bytes, uint16_t value) {
    bytes.push_back(static_cast<uint8_t>(value & 0xFF));
    bytes.push_back(static_cast<uint8_t>(value >> 8));
}

void put32(std::vector<uint8_t> &bytes, uint32_t value) {
    for (int shift = 0; shift < 4; ++shift) {
        bytes.push_back(static_cast<uint8_t>((value >> (8 * shift)) & 0xFF));
    }
}

void put64(std::vector<uint8_t> &bytes, uint64_t value) {
    for (int shift = 0; shift < 8; ++shift) {
        bytes.push_back(static_cast<uint8_t>((value >> (8 * shift)) & 0xFF));
    }
}

// [MS-PST] 2.2.2.8.3.2.1 / 2.2.2.8.3.2.2: btype cLevel cEnt lcbTotal then cEnt BIDs.
std::vector<uint8_t> jump_table_bytes(uint8_t level, const std::vector<uint64_t> &bids,
                                      uint32_t lcb_total) {
    std::vector<uint8_t> bytes;
    bytes.push_back(ltp::kJumpTableType);
    bytes.push_back(level);
    put16(bytes, static_cast<uint16_t>(bids.size()));
    put32(bytes, lcb_total);
    for (uint64_t bid : bids) {
        put64(bytes, bid);
    }
    return bytes;
}

// One data block of a multi-block HN ([MS-PST] 2.3.1.2 / 2.3.1.3 / 2.3.1.4 / 2.3.1.5): the header that
// block index calls for, the HNPAGEMAP at its own ibHnpm, then one allocation per heap id.
HnFragment make_fragment(size_t index, uint8_t client_sig, uint32_t hid_user_root,
                         const std::vector<std::pair<uint32_t, std::vector<uint8_t>>> &allocations) {
    const uint16_t header_size = static_cast<uint16_t>(ltp::hn_block_header_size(index));
    std::vector<uint8_t> bytes;
    put16(bytes, header_size); // every HN block header starts with ibHnpm
    if (index == 0) {
        bytes.push_back(ltp::kHnSignature);
        bytes.push_back(client_sig);
        put32(bytes, hid_user_root);
        put32(bytes, 0); // rgbFillLevel
    } else if (ltp::hn_block_carries_fill_level(index)) {
        for (int slot = 0; slot < 64; ++slot) {
            bytes.push_back(0xEE); // [MS-PST] 2.3.1.4 rgbFillLevel: 128 4-bit fill levels
        }
    }
    put16(bytes, static_cast<uint16_t>(allocations.size()));
    put16(bytes, 0); // cFree
    uint16_t at = static_cast<uint16_t>(header_size + 4 + (allocations.size() + 1) * 2);
    for (const auto &item : allocations) {
        put16(bytes, at);
        at = static_cast<uint16_t>(at + item.second.size());
    }
    put16(bytes, at);
    for (const auto &item : allocations) {
        bytes.insert(bytes.end(), item.second.begin(), item.second.end());
    }

    HnFragment fragment;
    fragment.owned = std::move(bytes);
    fragment.block.form = ltp::BlockForm::kRaw;
    fragment.block.block_base = index * 0x1000000ull;
    fragment.block.raw_block =
        ByteView(fragment.owned.data(), fragment.owned.size(), fragment.block.block_base);
    return fragment;
}

void decode_page_map(HnFragment &fragment) {
    const ByteView view = fragment.block.heap_node();
    const Result<uint16_t> ib_hnpm = view.u16(ltp::kHnIbHnpmOffset);
    TEST_OK(ib_hnpm, "fragment ibHnpm");
    Result<ltp::HnPageMap> map =
        ltp::decode_hn_page_map(view, ib_hnpm.ok() ? ib_hnpm.value() : 0);
    TEST_OK(map, "fragment page map");
    if (map.ok()) {
        fragment.page_map = map.take();
        fragment.page_map_ok = true;
    }
}

void check_jump_table() {
    const std::vector<uint8_t> bytes = jump_table_bytes(1, {0x1001, 0x1002, 0x1003}, 0x1234);
    const ByteView view(bytes.data(), bytes.size(), 0x8000);
    Result<BlockJumpTable> jump = ltp::decode_block_jump_table(view);
    TEST_OK(jump, "XBLOCK");
    if (jump.ok()) {
        TEST_EQ(jump.value().c_level, 1u, "XBLOCK cLevel");
        TEST_EQ(jump.value().c_ent, 3u, "XBLOCK cEnt");
        TEST_EQ(jump.value().lcb_total, 0x1234u, "XBLOCK lcbTotal");
        TEST_EQ(jump.value().bids.size(), 3u, "XBLOCK bid count");
        TEST_EQ(jump.value().bids[2], 0x1003ull, "XBLOCK third bid");
    }
    // The same bytes are not a heap node: what open_node has to try before calling a block odd.
    TEST_ERROR(ltp::decode_hn_header(view), ErrorKind::kBadField, "HNHDR.bSig",
               "a jump table is not a heap node");

    // [MS-PST] 2.2.2.8.3.2.2: cLevel 2 is an XXBLOCK, and it decodes with the same shape.
    const std::vector<uint8_t> upper = jump_table_bytes(2, {0x2001, 0x2002}, 0x9000);
    Result<BlockJumpTable> xx =
        ltp::decode_block_jump_table(ByteView(upper.data(), upper.size(), 0x8000));
    TEST_OK(xx, "XXBLOCK");
    if (xx.ok()) {
        TEST_EQ(xx.value().c_level, 2u, "XXBLOCK cLevel");
        TEST_EQ(xx.value().bids.size(), 2u, "XXBLOCK bid count");
    }
}

void check_jump_table_rejects() {
    struct Case {
        uint8_t b_type;
        uint8_t c_level;
        uint16_t c_ent;
        ErrorKind kind;
        const char *field;
        const char *label;
    };
    const Case cases[] = {
        {0x02, 1, 1, ErrorKind::kBadField, "XBLOCK.btype", "btype other than 0x01"},
        {0x01, 0, 1, ErrorKind::kBadField, "XBLOCK.cLevel", "cLevel 0"},
        {0x01, 3, 1, ErrorKind::kBadField, "XBLOCK.cLevel", "cLevel other than 1 or 2"},
        {0x01, 1, 0, ErrorKind::kBadField, "XBLOCK.cEnt", "cEnt 0 names no block"},
    };
    for (const Case &item : cases) {
        std::vector<uint8_t> bytes;
        bytes.push_back(item.b_type);
        bytes.push_back(item.c_level);
        put16(bytes, item.c_ent);
        put32(bytes, 0);
        put64(bytes, 0x1001);
        TEST_ERROR(ltp::decode_block_jump_table(ByteView(bytes.data(), bytes.size(), 0x8000)),
                   item.kind, item.field, item.label);
    }

    std::vector<uint8_t> short_table = {ltp::kJumpTableType, 1, 4, 0, 0x00, 0x00, 0x00, 0x00, 0x01};
    TEST_ERROR(ltp::decode_block_jump_table(ByteView(short_table.data(), short_table.size(), 0x8000)),
               ErrorKind::kTruncated, "XBLOCK.rgid", "a BID array cut short of cEnt");

    std::vector<uint8_t> zero_bid = jump_table_bytes(1, {0x1001, 0}, 0);
    TEST_ERROR(ltp::decode_block_jump_table(ByteView(zero_bid.data(), zero_bid.size(), 0x8000)),
               ErrorKind::kBadField, "XBLOCK.rgid", "a BID of 0 names no block");

    std::vector<uint8_t> header_only = {ltp::kJumpTableType, 1, 0, 0, 0, 0, 0, 0};
    TEST_ERROR(ltp::decode_block_jump_table(ByteView(header_only.data(), header_only.size(), 0x8000)),
               ErrorKind::kBadField, "XBLOCK.cEnt", "cEnt 0 even with no room for a BID");
}

void check_block_headers() {
    TEST_EQ(ltp::hn_block_header_size(0), 12u, "block 0 carries the HNHDR");
    for (size_t index = 1; index < 8; ++index) {
        TEST_EQ(ltp::hn_block_header_size(index), 2u, "blocks 1-7 carry the HNPAGEHDR");
    }
    TEST_EQ(ltp::hn_block_header_size(8), 66u, "block 8 carries the HNBITMAPHDR");
    TEST_EQ(ltp::hn_block_header_size(135), 2u, "block 135 carries the HNPAGEHDR");
    TEST_EQ(ltp::hn_block_header_size(136), 66u, "block 136 carries the next HNBITMAPHDR");
    TEST_EQ(ltp::hn_block_header_size(264), 66u, "block 264 carries the one after that");
    TEST_CHECK(!ltp::hn_block_carries_fill_level(7));
    TEST_CHECK(ltp::hn_block_carries_fill_level(8));
    TEST_CHECK(!ltp::hn_block_carries_fill_level(135));
    TEST_CHECK(ltp::hn_block_carries_fill_level(136));
}

// The node's blocks are numbered in order, so the fragment a HID names is hid_block_index(hid, profile)
// and the vector has to hold every block up to the last one the node has. Nine blocks is also the
// shortest node that reaches the HNBITMAPHDR at block 8.
void check_fragment_heap() {
    std::vector<HnFragment> fragments;
    for (size_t index = 0; index <= 8; ++index) {
        const uint32_t hid = (static_cast<uint32_t>(index) << 19) | 0x20u;
        fragments.push_back(make_fragment(index, index == 0 ? ltp::kClientSigTc : 0, 0x20,
                                          {{hid, std::vector<uint8_t>(index + 2, static_cast<uint8_t>(0xA0 + index))}}));
    }
    for (HnFragment &fragment : fragments) {
        decode_page_map(fragment);
    }

    NodeFragmentHeapSource source(fragments, kProfile);
    Result<ByteView> first = source.heap(0x20); // allocation 1 of block 0
    TEST_OK(first, "a HID in block 0");
    if (first.ok()) {
        TEST_EQ(first.value().size(), 2u, "block 0 allocation size");
        TEST_EQ(first.value().data()[0], 0xA0u, "block 0 allocation bytes");
    }
    // [MS-PST] 2.3.1.1: hidBlockIndex is the block index itself, so block 1 is HID 1 << 19.
    Result<ByteView> second = source.heap(0x80020);
    TEST_OK(second, "a HID in block 1");
    if (second.ok()) {
        TEST_EQ(second.value().size(), 3u, "block 1 allocation size");
        TEST_EQ(second.value().data()[0], 0xA1u, "block 1 allocation bytes");
    }
    Result<ByteView> eighth = source.heap(0x00400020); // 8 << 19 = block 8
    TEST_OK(eighth, "a HID in block 8");
    if (eighth.ok()) {
        TEST_EQ(eighth.value().size(), 10u, "block 8 allocation size");
        TEST_EQ(eighth.value().data()[0], 0xA8u, "block 8 allocation bytes");
    }
    Result<ByteView> missing = source.heap(0x00480020); // 9 << 19 = block 9, which this node lacks
    TEST_ERROR(missing, ErrorKind::kUnsupported, "HID.hidBlockIndex", "a HID naming a block the node lacks");
    TEST_EQ(source.cross_block_misses, 1u, "cross-block misses counted");
}

std::vector<uint8_t> fragment_bytes(
    size_t index, uint8_t client_sig, uint32_t hid_user_root,
    const std::vector<std::pair<uint32_t, std::vector<uint8_t>>> &allocations) {
    return make_fragment(index, client_sig, hid_user_root, allocations).owned;
}

std::vector<uint8_t> bth_header(uint8_t cb_key, uint8_t cb_ent, uint32_t hid_root) {
    std::vector<uint8_t> bytes;
    bytes.push_back(ltp::kBthType);
    bytes.push_back(cb_key);
    bytes.push_back(cb_ent);
    bytes.push_back(0); // bIdxLevels: the array hidRoot names is the leaf array
    put32(bytes, hid_root);
    return bytes;
}

std::vector<uint8_t> tc_header_bytes(uint32_t hid_row_index) {
    std::vector<uint8_t> bytes;
    bytes.push_back(ltp::kClientSigTc);
    bytes.push_back(4);
    put16(bytes, 12);
    put16(bytes, 14);
    put16(bytes, 15);
    put16(bytes, 16);
    put32(bytes, hid_row_index);
    put32(bytes, 0); // hnidRows
    put32(bytes, 0);
    const auto column = [&](uint32_t tag, uint16_t ib_data, uint8_t cb_data, uint8_t i_bit) {
        put32(bytes, tag);
        put16(bytes, ib_data);
        bytes.push_back(cb_data);
        bytes.push_back(i_bit);
    };
    column(0x6619001F, 8, 4, 2);
    column(0x66740002, 12, 2, 3);
    column(0x67F20003, 0, 4, 0);
    column(0x67F30003, 4, 4, 1);
    return bytes;
}

std::vector<uint8_t> row_records(const std::vector<uint32_t> &row_ids) {
    std::vector<uint8_t> bytes;
    uint32_t index = 0;
    for (uint32_t row_id : row_ids) {
        put32(bytes, row_id);
        put32(bytes, index++);
    }
    return bytes;
}

std::vector<uint8_t> folder_pc_bytes(const std::u16string &name) {
    std::vector<std::tuple<uint16_t, uint16_t, uint32_t>> records;
    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> allocations;
    allocations.emplace_back(0x20, bth_header(2, 6, 0x40));
    std::vector<uint8_t> value;
    for (char16_t unit : name) {
        put16(value, static_cast<uint16_t>(unit));
    }
    put16(value, 0);
    if (name.empty()) {
        records.emplace_back(0x36DA, 0x000B, 1);
    } else {
        records.emplace_back(0x3001, 0x001F, 0x60);
        records.emplace_back(0x36DA, 0x000B, 1);
    }
    std::vector<uint8_t> record_bytes;
    for (const auto &record : records) {
        put16(record_bytes, std::get<0>(record));
        put16(record_bytes, std::get<1>(record));
        put32(record_bytes, std::get<2>(record));
    }
    allocations.emplace_back(0x40, record_bytes);
    if (!name.empty()) {
        allocations.emplace_back(0x60, value);
    }
    return fragment_bytes(0, ltp::kClientSigPc, 0x20, allocations);
}

class FakeBlocks : public BlockSource {
public:
    void add(uint64_t bid, const std::vector<uint8_t> &bytes, bool internal = false) {
        blocks_[bid] = bytes;
        if (internal) {
            internal_.insert(bid);
        }
    }

    Result<ltp::BlockBytes> block(uint64_t bid) override {
        const auto found = blocks_.find(bid);
        if (found == blocks_.end()) {
            return make_error(ErrorKind::kUnsupported, "BBTENTRY.bid", 0, bid,
                              "this test has no such block");
        }
        // [MS-PST] 2.2.2.2 bit B as the BBTENTRY stores it: the fixture says which blocks are Internal.
        return ltp::BlockBytes{ByteView(found->second.data(), found->second.size(), bid * 512),
                               internal_.count(bid) != 0};
    }

private:
    std::map<uint64_t, std::vector<uint8_t>> blocks_;
    std::set<uint64_t> internal_;
};

void add_node(NidMap &nodes, uint64_t index, uint32_t nid_type, uint64_t bid, uint64_t parent) {
    nodes.add(NbtEntry{ltp::make_nid(index, nid_type), bid, 0, static_cast<uint32_t>(parent)});
}

// Inbox with a contents table spread over two data blocks: TCINFO and the BTHHEADER in block 0, the
// RowIndex leaf array in block 1, reached through a HID whose hidBlockIndex is 1. The same folder with
// the leaf array in block 0 is what the single-block fixture already covers, so the number the walk
// reports here is the whole point: 3 rows read across a block boundary.
void check_folder_tree_over_two_blocks() {
    NidMap nodes;
    FakeBlocks blocks;
    add_node(nodes, 9, ltp::kNidTypeNormalFolder, 1, 0);
    add_node(nodes, 9, ltp::kNidTypeContentsTable, 2, 0x122);
    for (const uint64_t index : {0x100, 0x101, 0x102}) {
        add_node(nodes, index, ltp::kNidTypeNormalMessage, 0, 0x122);
    }

    blocks.add(1, folder_pc_bytes(std::u16string(u"Inbox")));
    const std::vector<uint8_t> table_block0 = fragment_bytes(
        0, ltp::kClientSigTc, 0x20, {{0x20, tc_header_bytes(0x40)}, {0x40, bth_header(4, 4, 0x80020)}});
    const std::vector<uint8_t> table_block1 =
        fragment_bytes(1, 0, 0, {{0x80020, row_records({0x2004, 0x2024, 0x2044})}});
    blocks.add(0x30, table_block0);
    blocks.add(0x34, table_block1);
    // [MS-PST] 2.2.2.2 bit B is what makes block 2 the jump table instead of a data block, and
    // [MS-PST] 2.2.2.8.3.2.1 says lcbTotal is the bytes of the external data under it.
    blocks.add(2, jump_table_bytes(1, {0x30, 0x34},
                                   static_cast<uint32_t>(table_block0.size() + table_block1.size())),
               true);

    FolderWalkOptions options;
    FolderWalkStats stats;
    std::vector<LtpFolder> folders;
    FailureLog failures(10);
    const util::Status walked = ltp::walk_folder_tree(nodes, blocks, ltp::kNidRootFolder, options,
                                                      kProfile, folders, stats, failures);
    TEST_CHECK(walked.ok());
    TEST_EQ(stats.folders, 1u, "folders visited");
    if (!folders.empty()) {
        TEST_STR(folders[0].name, "Inbox", "folder name");
        TEST_EQ(folders[0].messages, 3u, "messages read across a block boundary");
        TEST_EQ(folders[0].parent_messages, 3u, "messages the NID map holds");
        TEST_CHECK(folders[0].has_contents);
    }
    TEST_EQ(stats.tc_rows, 3u, "table rows counted");
    TEST_EQ(stats.missing, 0u, "rows with no NBT entry");
    TEST_EQ(stats.data_trees.trees, 1u, "the contents table's data tree flattened");
    TEST_EQ(stats.data_trees.tables, 1u, "one XBLOCK decoded");
    TEST_EQ(stats.data_trees.data_blocks, 2u, "the two data blocks it names");
    TEST_EQ(stats.data_trees.failed_trees, 0u, "no data tree failed");
    TEST_EQ(stats.data_trees.lcb_total_mismatches, 0u, "lcbTotal matched the data under it");
}

} // namespace

int main() {
    check_jump_table();
    check_jump_table_rejects();
    check_block_headers();
    check_fragment_heap();
    check_folder_tree_over_two_blocks();
    return ost2pst::test::finish("ltp_multi_block_test");
}
