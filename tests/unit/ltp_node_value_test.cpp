// A PC value HNID names either an allocation in the node's own data block or one of that node's subnodes
// ([MS-PST] 2.3.3.2), and a subnode value is the whole first data block of that subnode ([MS-PST]
// 2.2.2.8.3.3.1.1). NodeValueSource is the seam that answers both, so it is what every stream reader in
// this layer goes through.
#include <array>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "ost2pst/ltp/block_heap.h"
#include "ost2pst/ltp/data_tree.h"
#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/ltp/node_value.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"
#include "test_support.h"

namespace {

using ost2pst::ltp::BlockSource;
using ost2pst::ltp::BlockHeapSource;
using ost2pst::ltp::decode_hn_header;
using ost2pst::ltp::decode_hn_page_map;
using ost2pst::ltp::find_subnode;
using ost2pst::ltp::DataTreeCounters;
using ost2pst::ltp::kHnHeaderSize;
using ost2pst::ltp::NodeValueSource;
using ost2pst::ltp::SubnodeStats;
using ost2pst::ndb::FailureLog;
using ost2pst::ndb::FileProfile;
using ost2pst::test::finish;
using ost2pst::util::ByteView;
using ost2pst::util::ErrorKind;
using ost2pst::util::make_error;
using ost2pst::util::Result;

constexpr uint64_t kBlockBase = 0x20000;
constexpr uint64_t kSubnodeBid = 0x900;
// The fixture heap node holds allocations 1-2 of block 0, so either profile answers it; the 512 one is
// used because this test is about subnode lookup, not HID widths.
constexpr FileProfile kProfile = FileProfile::kPst;

void put16(std::vector<uint8_t> &out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
}

void put32(std::vector<uint8_t> &out, uint32_t value) {
    for (uint64_t index = 0; index < 4; ++index) {
        out.push_back(static_cast<uint8_t>((value >> (8 * index)) & 0xFF));
    }
}

void put8(std::vector<uint8_t> &out, uint8_t value) { out.push_back(value); }

void put64(std::vector<uint8_t> &out, uint64_t value) {
    for (uint64_t index = 0; index < 8; ++index) {
        out.push_back(static_cast<uint8_t>((value >> (8 * index)) & 0xFF));
    }
}

// A one-allocation heap node whose payload is the bytes handed in.
std::vector<uint8_t> heap_node(const std::vector<uint8_t> &payload) {
    std::vector<uint8_t> out;
    put16(out, 12); // ibHnpm
    out.push_back(0xEC);
    out.push_back(0xBC);
    put32(out, 0x20); // hidUserRoot
    put32(out, 0);    // rgbFillLevel
    put16(out, 1);    // cAlloc
    put16(out, 0);    // cFree
    put16(out, 20);   // rgibAlloc[0]: the allocation starts after the header and the page map
    put16(out, static_cast<uint16_t>(20 + payload.size())); // rgibAlloc[1]
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

// One SLBLOCK holding the subnodes this test needs ([MS-PST] 2.2.2.8.3.3.1.1).
std::vector<uint8_t> subnode_block(const std::vector<std::array<uint64_t, 3>> &entries) {
    std::vector<uint8_t> out;
    put8(out, 0x02);
    put8(out, 0);
    put16(out, static_cast<uint16_t>(entries.size()));
    put32(out, 0);
    for (const std::array<uint64_t, 3> &entry : entries) {
        put64(out, entry[0]);
        put64(out, entry[1]);
        put64(out, entry[2]);
    }
    return out;
}

// The subnode's own data block: raw bytes, no heap node in front of them. `internal` is what the
// BBTENTRY would have carried for the BID ([MS-PST] 2.2.2.2 bit B).
class Blocks : public BlockSource {
public:
    void set(uint64_t bid, std::vector<uint8_t> bytes, bool internal = false) {
        blocks_[bid] = std::move(bytes);
        if (internal) {
            internal_.insert(bid);
        }
    }

    Result<ost2pst::ltp::BlockBytes> block(uint64_t bid) override {
        const auto found = blocks_.find(bid);
        if (found == blocks_.end()) {
            return make_error(ErrorKind::kIo, "Blocks.block", bid, bid, "this BID is not in the fixture");
        }
        held_ = found->second;
        return ost2pst::ltp::BlockBytes{ByteView(held_.data(), held_.size(), bid), internal_.count(bid) != 0};
    }

private:
    std::map<uint64_t, std::vector<uint8_t>> blocks_;
    std::vector<uint8_t> held_;
    std::set<uint64_t> internal_;
};

// [MS-PST] 2.2.2.8.3.2.1: an XBLOCK jump table -- btype 0x01, cLevel 1, cEnt, lcbTotal, then cEnt BIDs.
std::vector<uint8_t> jump_table_bytes(const std::vector<uint64_t> &bids, uint32_t lcb_total) {
    std::vector<uint8_t> out;
    put8(out, 0x01);
    put8(out, 1);
    put16(out, static_cast<uint16_t>(bids.size()));
    put32(out, lcb_total);
    for (uint64_t bid : bids) {
        put64(out, bid);
    }
    return out;
}

} // namespace

int main() {
    const std::vector<uint8_t> payload(64, 0x5A);
    const std::vector<uint8_t> block = heap_node(payload);
    const ByteView view(block.data(), block.size(), kBlockBase);

    Result<ost2pst::ltp::HnHeader> header = decode_hn_header(view);
    TEST_OK(header, "the fixture heap node");
    Result<ost2pst::ltp::HnPageMap> map = decode_hn_page_map(view, header.value().ib_hnpm);
    TEST_OK(map, "the fixture page map");
    BlockHeapSource heap(view, map.value(), kProfile, 0);

    const std::vector<uint8_t> subnode_value(32, 0x11);
    Blocks blocks;
    blocks.set(kSubnodeBid, subnode_value);
    const std::vector<uint8_t> sl = subnode_block({{0x00008F5F, kSubnodeBid, 0}});
    blocks.set(0x800, sl, true); // [MS-PST] 2.2.2.8.3.3.1: an SLBLOCK is an Internal block

    SubnodeStats subnode_stats;
    DataTreeCounters data_trees;
    FailureLog failures(5);
    NodeValueSource values(heap, 0x800, kProfile, blocks, subnode_stats, data_trees, failures);

    // A HID is answered out of the node's own heap ([MS-PST] 2.3.1.1).
    Result<ByteView> heap_value = values.value(0x20);
    TEST_OK(heap_value, "a heap value");
    TEST_EQ(heap_value.value().size(), payload.size(), "the whole allocation");
    TEST_EQ(heap_value.value().data()[0], 0x5A, "the allocation bytes");
    TEST_EQ(values.heap_hits, 1, "the heap answered it");

    // A HNID whose type bits are not NID_TYPE_HID is a subnode, and its value is that subnode's data
    // block ([MS-PST] 2.3.3.2, 2.2.2.8.3.3.1.1).
    Result<ByteView> sub_value = values.value(0x00008F5F);
    TEST_OK(sub_value, "a subnode value");
    TEST_EQ(sub_value.value().size(), subnode_value.size(), "the whole subnode data block");
    TEST_EQ(sub_value.value().data()[0], 0x11, "the subnode bytes");
    TEST_EQ(values.subnode_hits, 1, "the subnode answered it");
    TEST_EQ(subnode_stats.found, 1, "the subnode lookup is counted");
    TEST_EQ(data_trees.trees, 1u, "the subnode value resolved as a one-block data tree");
    TEST_EQ(data_trees.data_blocks, 1u, "the one data block its SLENTRY.bidData names");
    TEST_EQ(subnode_stats.blocks_not_internal, 0u, "the SLBLOCK was flagged Internal as the spec requires");

    // A subnode the SLENTRY array does not hold is an error, not an empty value.
    Result<ByteView> missing = values.value(0x00009F5F);
    TEST_CHECK(!missing.ok());
    TEST_EQ(values.subnode_misses, 1, "the miss is counted");

    // A node with no bidSub cannot answer a subnode HNID at all.
    FailureLog quiet(5);
    SubnodeStats quiet_stats;
    DataTreeCounters quiet_trees;
    NodeValueSource no_subnode(heap, 0, kProfile, blocks, quiet_stats, quiet_trees, quiet);
    TEST_ERROR(no_subnode.value(0x00008F5F), ErrorKind::kBadField, "NBTENTRY.bidSub",
               "a subnode HNID on a node with no bidSub");

    // A subnode whose SLENTRY names a BID the source cannot read.
    blocks.set(0x810, subnode_block({{0x00007F5F, 0x1234, 0}}), true);
    NodeValueSource broken(heap, 0x810, kProfile, blocks, quiet_stats, quiet_trees, quiet);
    TEST_CHECK(!broken.value(0x00007F5F).ok());

    // [MS-PST] 2.2.2.8.3.2 / 3.6: a SLENTRY.bidData with the internal bit set roots a data tree, and the
    // value is every data block under it concatenated -- not the jump table's own bytes, which are
    // metadata about where the value sits.
    const std::vector<uint8_t> part0(16, 0x22);
    const std::vector<uint8_t> part1(24, 0x33);
    blocks.set(0x920, part0);
    blocks.set(0x924, part1);
    blocks.set(0x910, jump_table_bytes({0x920, 0x924}, static_cast<uint32_t>(part0.size() + part1.size())),
               true);
    blocks.set(0x820, subnode_block({{0x00006F5F, 0x910, 0}}), true);
    DataTreeCounters spread_trees;
    NodeValueSource spread(heap, 0x820, kProfile, blocks, quiet_stats, spread_trees, quiet);
    Result<ByteView> spread_value = spread.value(0x00006F5F);
    TEST_OK(spread_value, "a subnode value spread over a data tree");
    if (spread_value.ok()) {
        TEST_EQ(spread_value.value().size(), part0.size() + part1.size(), "both data blocks, in order");
        TEST_EQ(spread_value.value().data()[0], 0x22, "the first block's bytes");
        TEST_EQ(spread_value.value().data()[part0.size()], 0x33, "the second block's bytes");
    }
    TEST_EQ(spread_trees.tables, 1u, "the XBLOCK under the subnode decoded as a jump table");
    TEST_EQ(spread_trees.data_blocks, 2u, "the two data blocks it names");
    TEST_EQ(spread_trees.failed_trees, 0u, "the tree resolved");

    return finish("ltp_node_value_test");
}
