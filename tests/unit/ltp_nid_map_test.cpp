// A node's subnodes live in a BTree of its own: NBTENTRY.bidSub names an SLBLOCK of SLENTRYs, or a
// SIBLOCK of SIENTRYs that chains SLBLOCKs when there are too many for one block ([MS-PST] 2.2.2.8.3.3).
// This file checks those two block kinds and their entries, the descent that turns a HNID into the data
// block of the subnode it names, and the nidIndex grouping the Messaging layer builds a Folder object
// out of ([MS-PST] 2.4.4.3).
#include <array>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "ost2pst/ltp/hn_block.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/ndb/btree.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"
#include "test_support.h"

namespace {

using ost2pst::ltp::BlockForm;
using ost2pst::ltp::BlockSource;
using ost2pst::ltp::decode_si_entry;
using ost2pst::ltp::decode_sl_entry;
using ost2pst::ltp::decode_subnode_block_header;
using ost2pst::ltp::find_subnode;
using ost2pst::ltp::kMaxSubnodeDepth;
using ost2pst::ltp::kMaxSubnodeEntries;
using ost2pst::ltp::make_nid;
using ost2pst::ltp::nid_index;
using ost2pst::ltp::nid_type;
using ost2pst::ltp::nid_type_name;
using ost2pst::ltp::NidMap;
using ost2pst::ltp::NodeRef;
using ost2pst::ltp::SiEntry;
using ost2pst::ltp::SlEntry;
using ost2pst::ltp::SubnodeBlockHeader;
using ost2pst::ltp::SubnodeRef;
using ost2pst::ltp::SubnodeStats;
using ost2pst::ltp::subnode_nid_key;
using ost2pst::ltp::walk_subnode_entries;
using ost2pst::ndb::FailureLog;
using ost2pst::ndb::NbtEntry;
using ost2pst::util::ByteView;
using ost2pst::util::ErrorKind;
using ost2pst::util::make_error;
using ost2pst::util::Result;

constexpr uint64_t kBlockBase = 0x40000;

void put8(std::vector<uint8_t> &out, uint8_t value) { out.push_back(value); }
void put16(std::vector<uint8_t> &out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
}
void put32(std::vector<uint8_t> &out, uint32_t value) {
    for (uint64_t i = 0; i < 4; ++i) {
        out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
    }
}
void put64(std::vector<uint8_t> &out, uint64_t value) {
    for (uint64_t i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
    }
}

// [MS-PST] 2.2.2.8.3.3.1.2 / 2.2.2.8.3.3.2.2 header, then cEnt entries of 24 or 16 bytes.
std::vector<uint8_t> subnode_header(uint8_t c_level, uint16_t c_ent) {
    std::vector<uint8_t> out;
    put8(out, 0x02);
    put8(out, c_level);
    put16(out, c_ent);
    put32(out, 0);
    return out;
}

std::vector<uint8_t> sl_block(const std::vector<std::array<uint64_t, 3>> &entries) {
    std::vector<uint8_t> out = subnode_header(0, static_cast<uint16_t>(entries.size()));
    for (const std::array<uint64_t, 3> &entry : entries) {
        put64(out, entry[0]);
        put64(out, entry[1]);
        put64(out, entry[2]);
    }
    return out;
}

std::vector<uint8_t> si_block(const std::vector<std::array<uint64_t, 2>> &entries) {
    std::vector<uint8_t> out = subnode_header(1, static_cast<uint16_t>(entries.size()));
    for (const std::array<uint64_t, 2> &entry : entries) {
        put64(out, entry[0]);
        put64(out, entry[1]);
    }
    return out;
}

// A stored (level 0) deflate stream inside a zlib wrapper: what an OST block looks like when it is
// compressed, without needing a deflate encoder in the test.
std::vector<uint8_t> zlib_stored(const std::vector<uint8_t> &raw) {
    std::vector<uint8_t> out;
    put8(out, 0x78);
    put8(out, 0x01); // CMF/FLG: 0x7801 is a multiple of 31, no preset dictionary
    put8(out, 0x01); // BFINAL set, BTYPE 00 = stored
    put16(out, static_cast<uint16_t>(raw.size()));
    put16(out, static_cast<uint16_t>(~raw.size() & 0xFFFF));
    out.insert(out.end(), raw.begin(), raw.end());
    uint32_t a = 1;
    uint32_t b = 0;
    for (uint8_t byte : raw) {
        a = (a + byte) % 65521;
        b = (b + a) % 65521;
    }
    put8(out, static_cast<uint8_t>((b >> 8) & 0xFF)); // Adler-32 is big-endian in zlib
    put8(out, static_cast<uint8_t>(b & 0xFF));
    put8(out, static_cast<uint8_t>((a >> 8) & 0xFF));
    put8(out, static_cast<uint8_t>(a & 0xFF));
    return out;
}

class FakeBlocks : public BlockSource {
public:
    // Each fixture states which form its block is in, the same way the NDB does for a real file: the
    // walk must not have to guess compression from the bytes.
    void add(uint64_t bid, const std::vector<uint8_t> &bytes, bool internal = false,
             bool compressed = false) {
        Stored stored;
        stored.bytes = bytes;
        stored.base = kBlockBase + bid * 0x1000;
        blocks_[bid] = stored;
        if (internal) {
            internal_.insert(bid);
        }
        if (compressed) {
            compressed_.insert(bid);
        }
    }

    Result<ost2pst::ltp::BlockBytes> block(uint64_t bid) override {
        const auto found = blocks_.find(bid);
        if (found == blocks_.end()) {
            return make_error(ErrorKind::kIo, "BlockSource.block", 0, bid, "no such block in the fixture");
        }
        ++reads;
        // [MS-PST] 2.2.2.2 bit B as the BBTENTRY stores it: SLBLOCKs and SIBLOCKs are Internal blocks
        // ([MS-PST] 2.2.2.8.3), a data block is not. The compressed flag is the index-side answer about
        // the block's form, which is where the reader has to take it from.
        return ost2pst::ltp::BlockBytes{
            ByteView(found->second.bytes.data(), found->second.bytes.size(), found->second.base),
            internal_.count(bid) != 0, compressed_.count(bid) != 0};
    }

    uint64_t reads = 0;

private:
    struct Stored {
        std::vector<uint8_t> bytes;
        uint64_t base = 0;
    };

    std::map<uint64_t, Stored> blocks_;
    std::set<uint64_t> internal_;
    std::set<uint64_t> compressed_;
};

NbtEntry entry(uint64_t nid, uint64_t bid_data, uint64_t bid_sub, uint32_t nid_parent = 0) {
    NbtEntry value;
    value.nid = nid;
    value.bid_data = bid_data;
    value.bid_sub = bid_sub;
    value.nid_parent = nid_parent;
    return value;
}

} // namespace

namespace {

void check_nid_arithmetic() {
    // [MS-PST] 2.2.2.1: a NID is 5 bits of nidType under 27 bits of nidIndex.
    TEST_EQ(nid_type(0x249784), 0x04, "nidType of a message NID");
    TEST_EQ(nid_index(0x249784), 0x124BC, "nidIndex of a message NID");
    TEST_EQ(make_nid(nid_index(0x249784), nid_type(0x249784)), 0x249784, "NID round trip");
    TEST_EQ(make_nid(1, 0x0E), 0x2E, "nidIndex 1 under NID_TYPE_CONTENTS_TABLE");

    TEST_STR(nid_type_name(0x1F), "LTP", "NID_TYPE_LTP is what a subnode HNID names");
    TEST_STR(nid_type_name(0x02), "NORMAL_FOLDER", "NID_TYPE_NORMAL_FOLDER");
    TEST_STR(nid_type_name(0x14), "client", "the OST client-store types are named in M3");

    // The OST writes garbage above the low 32 bits of SLENTRY.nid, and the HNID that names the same
    // subnode is 32 bits, so the key is the low half.
    TEST_EQ(subnode_nid_key(0x7500007C00008F5Full), 0x8F5F, "SLENTRY.nid low 32 bits");
    TEST_EQ(subnode_nid_key(0x8F5F), 0x8F5F, "a HNID is already a key");
}

void check_block_header() {
    const std::vector<uint8_t> leaf = sl_block({{0x8F5F, 0x1380, 0}});
    Result<SubnodeBlockHeader> header =
        decode_subnode_block_header(ByteView(leaf.data(), leaf.size(), kBlockBase));
    TEST_OK(header, "SLBLOCK header");
    if (header.ok()) {
        TEST_EQ(header.value().b_type, 0x02, "btype");
        TEST_EQ(header.value().c_level, 0, "cLevel");
        TEST_EQ(header.value().c_ent, 1, "cEnt");
        TEST_EQ(header.value().entries_ib, 8, "rgentries starts after the 8-byte header");
        TEST_EQ(header.value().entry_size, 24, "a Unicode SLENTRY is 24 bytes");
    }

    const std::vector<uint8_t> intermediate = si_block({{0x100, 2}, {0x200, 3}});
    Result<SubnodeBlockHeader> si =
        decode_subnode_block_header(ByteView(intermediate.data(), intermediate.size(), kBlockBase));
    TEST_OK(si, "SIBLOCK header");
    if (si.ok()) {
        TEST_EQ(si.value().c_level, 1, "cLevel 1 is a SIBLOCK");
        TEST_EQ(si.value().c_ent, 2, "cEnt");
        TEST_EQ(si.value().entry_size, 16, "a Unicode SIENTRY is 16 bytes");
    }

    std::vector<uint8_t> bad = sl_block({{0x8F5F, 0x1380, 0}});
    ByteView view(bad.data(), bad.size(), kBlockBase);
    TEST_ERROR(decode_subnode_block_header(ByteView(bad.data(), 7, kBlockBase)), ErrorKind::kTruncated,
               "SUBNODE", "subnode header shorter than 8 bytes");

    bad[0] = 0x00; // a data block, not a subnode block
    TEST_ERROR(decode_subnode_block_header(view), ErrorKind::kBadSignature, "SUBNODE.btype",
               "btype other than 0x02");
    bad[0] = 0x02;
    bad[1] = 2;
    TEST_ERROR_OFFSET(decode_subnode_block_header(view), kBlockBase + 1, "cLevel other than 0 or 1");
    TEST_ERROR(decode_subnode_block_header(view), ErrorKind::kBadField, "SUBNODE.cLevel", "cLevel field");
    bad[1] = 0;
    bad[2] = 0;
    TEST_ERROR(decode_subnode_block_header(view), ErrorKind::kBadField, "SUBNODE.cEnt",
               "an SLBLOCK with no entries");
    bad[2] = 1;
    bad[4] = 1;
    TEST_ERROR_OFFSET(decode_subnode_block_header(view), kBlockBase + 4, "dwPadding that is not zero");
    TEST_ERROR(decode_subnode_block_header(view), ErrorKind::kBadField, "SUBNODE.dwPadding",
               "dwPadding field");
}

void check_entries() {
    const std::vector<uint8_t> leaf = sl_block({{0x7500007C00008F5Full, 0x1380, 0x1400}});
    Result<SlEntry> entry = decode_sl_entry(ByteView(leaf.data() + 8, 24, kBlockBase + 8));
    TEST_OK(entry, "SLENTRY");
    if (entry.ok()) {
        TEST_EQ(entry.value().nid, 0x7500007C00008F5Full, "nid as the file wrote it");
        TEST_EQ(subnode_nid_key(entry.value().nid), 0x8F5F, "the key is the low 32 bits");
        TEST_EQ(entry.value().bid_data, 0x1380, "bidData");
        TEST_EQ(entry.value().bid_sub, 0x1400, "bidSub");
        TEST_EQ(entry.value().offset, kBlockBase + 8, "entry offset");
    }
    TEST_ERROR(decode_sl_entry(ByteView(leaf.data() + 8, 23, kBlockBase + 8)), ErrorKind::kTruncated,
               "SLENTRY", "short SLENTRY");

    const std::vector<uint8_t> intermediate = si_block({{0x100, 2}});
    Result<SiEntry> si = decode_si_entry(ByteView(intermediate.data() + 8, 16, kBlockBase + 8));
    TEST_OK(si, "SIENTRY");
    if (si.ok()) {
        TEST_EQ(si.value().nid, 0x100, "key nid");
        TEST_EQ(si.value().bid, 2, "child bid");
        TEST_EQ(si.value().offset, kBlockBase + 8, "entry offset");
    }
    TEST_ERROR(decode_si_entry(ByteView(intermediate.data() + 8, 15, kBlockBase + 8)),
               ErrorKind::kTruncated, "SIENTRY", "short SIENTRY");
}

} // namespace

namespace {

void check_find_subnode() {
    FakeBlocks blocks;
    blocks.add(0x32, sl_block({{0x8F5F, 0x1380, 0}, {0x8C1F, 0x1500, 0x1600}}), true);
    SubnodeStats stats;
    FailureLog failures(3);
    Result<SubnodeRef> found = find_subnode(0x32, 0x8C1F, blocks, stats, failures);
    TEST_OK(found, "the second SLENTRY of an SLBLOCK");
    if (found.ok()) {
        TEST_EQ(found.value().nid, 0x8C1F, "nid");
        TEST_EQ(found.value().bid_data, 0x1500, "bidData of the subnode");
        TEST_EQ(found.value().bid_sub, 0x1600, "bidSub of that subnode");
        TEST_EQ(found.value().block_bid, 0x32, "the SLBLOCK that held it");
        TEST_EQ(found.value().entry_offset, kBlockBase + 0x32 * 0x1000 + 8 + 24, "entry offset");
        TEST_EQ(found.value().depth, 0, "no SIBLOCK hop");
    }
    TEST_EQ(stats.searches, 1, "searches");
    TEST_EQ(stats.found, 1, "found");
    TEST_EQ(stats.blocks_read, 1, "blocks read");
    TEST_EQ(stats.blocks_raw, 1, "a plain block stays plain");
    TEST_EQ(stats.entries_scanned, 2, "every entry scanned");
    TEST_EQ(stats.max_entries, 2, "widest subnode block seen");
    TEST_EQ(stats.si_hops, 0, "no hops");
    TEST_EQ(failures.total(), 0, "no findings");
    TEST_EQ(blocks.reads, 1, "one block read");

    // The high 32 bits of SLENTRY.nid are garbage in this OST; the match is on the low 32.
    FakeBlocks garbage;
    garbage.add(0x40, sl_block({{0x7500007C00008F5Full, 0x1380, 0}}));
    SubnodeStats gstats;
    FailureLog gfailures(3);
    Result<SubnodeRef> hit = find_subnode(0x40, 0x8F5F, garbage, gstats, gfailures);
    TEST_OK(hit, "a SLENTRY whose nid has garbage above the low 32 bits");
    if (hit.ok()) {
        TEST_EQ(hit.value().nid, 0x7500007C00008F5Full, "the walk reports what the file wrote");
    }

    // An OST compresses subnode blocks exactly like data blocks, so the walk inflates them -- when the
    // index says they are compressed.
    FakeBlocks compressed;
    compressed.add(0x50, zlib_stored(sl_block({{0x29985Full, 0x6000, 0}})), false, true);
    SubnodeStats cstats;
    FailureLog cfailures(3);
    Result<SubnodeRef> inflated = find_subnode(0x50, 0x29985F, compressed, cstats, cfailures);
    TEST_OK(inflated, "a compressed SLBLOCK");
    TEST_EQ(cstats.blocks_compressed, 1, "the walk saw a zlib stream");
    TEST_EQ(cstats.blocks_raw, 0, "and no plain block");
    TEST_EQ(cstats.found, 1, "found after inflating");

    // The sample's shape: 28 attachment blocks start with bytes that form a valid CMF/FLG pair while the
    // index calls them raw. Reading the bytes instead of the index lost those nodes.
    FakeBlocks sniffed;
    sniffed.add(0x51, zlib_stored(sl_block({{0x29985Full, 0x6000, 0}})), false, false);
    SubnodeStats sstats;
    FailureLog sfailures(3);
    Result<SubnodeRef> not_inflated = find_subnode(0x51, 0x29985F, sniffed, sstats, sfailures);
    TEST_ERROR(not_inflated, ErrorKind::kBadSignature, "SUBNODE.btype",
               "a raw block is not inflated just because its bytes look compressed");
    TEST_EQ(sstats.blocks_raw, 1, "the walk read the block's own bytes");
    TEST_EQ(sstats.blocks_compressed, 0, "and inflated nothing");
}

void check_subnode_chain() {
    // [MS-PST] 2.2.2.8.3.3.2: a SIBLOCK chains SLBLOCKs, and SIENTRY.nid is the key of the child.
    FakeBlocks blocks;
    blocks.add(1, si_block({{0x100, 2}, {0x200, 3}}), true);
    blocks.add(2, sl_block({{0x100, 0x2000, 0}, {0x140, 0x2100, 0}}), true);
    blocks.add(3, sl_block({{0x200, 0x3000, 0}, {0x250, 0x3100, 0x3200}}), true);
    SubnodeStats stats;
    FailureLog failures(3);

    Result<SubnodeRef> high = find_subnode(1, 0x250, blocks, stats, failures);
    TEST_OK(high, "the target sits in the second SLBLOCK");
    if (high.ok()) {
        TEST_EQ(high.value().block_bid, 3, "the SIBLOCK chose the child whose key is closest");
        TEST_EQ(high.value().depth, 1, "one hop");
    }
    Result<SubnodeRef> low = find_subnode(1, 0x140, blocks, stats, failures);
    TEST_OK(low, "the target sits in the first SLBLOCK");
    if (low.ok()) {
        TEST_EQ(low.value().block_bid, 2, "the child whose key does not exceed the target");
    }
    TEST_EQ(stats.si_hops, 2, "two descents");
    TEST_EQ(stats.max_depth, 1, "one hop deep");
    TEST_EQ(stats.found, 2, "both found");

    // Below every key: the first child is the only candidate.
    FakeBlocks below;
    below.add(1, si_block({{0x100, 2}}));
    below.add(2, sl_block({{0x050, 0x2000, 0}, {0x100, 0x2100, 0}}));
    SubnodeStats bstats;
    FailureLog bfailures(3);
    TEST_OK(find_subnode(1, 0x050, below, bstats, bfailures), "a target below every SIENTRY key");

    // A chain that visits the same block twice is corrupt, not a large node.
    FakeBlocks cycle;
    cycle.add(1, si_block({{0x100, 2}}));
    cycle.add(2, si_block({{0x100, 1}}));
    SubnodeStats cycstats;
    FailureLog cycfailures(3);
    TEST_ERROR(find_subnode(1, 0x100, cycle, cycstats, cycfailures), ErrorKind::kBadField, "SUBNODE.bid",
               "a subnode chain that loops");

    // Deeper than any real node's chain: the walk stops instead of following forever.
    FakeBlocks deep;
    for (uint64_t bid = 1; bid <= kMaxSubnodeDepth + 1; ++bid) {
        deep.add(bid, si_block({{0x100, bid + 1}}));
    }
    deep.add(kMaxSubnodeDepth + 2, sl_block({{0x100, 0x9000, 0}}));
    SubnodeStats dstats;
    FailureLog dfailures(3);
    Result<SubnodeRef> capped = find_subnode(1, 0x100, deep, dstats, dfailures);
    TEST_ERROR(capped, ErrorKind::kBadField, "SUBNODE.depth", "a chain deeper than the cap");
    TEST_CHECK(dstats.stopped_early);

    // The entry cap is per search: a node with a huge cEnt must not starve the searches after it.
    std::vector<std::array<uint64_t, 3>> many;
    for (uint64_t i = 0; i < kMaxSubnodeEntries + 904; ++i) {
        many.push_back({{0x1000 + i, 0x2000 + i, 0}});
    }
    FakeBlocks crowded;
    crowded.add(1, sl_block(many), true);
    crowded.add(2, sl_block({{0x8F5F, 0x3000, 0}}), true);
    SubnodeStats mstats;
    FailureLog mfailures(3);
    TEST_ERROR(find_subnode(1, 0x9999, crowded, mstats, mfailures), ErrorKind::kUnsupported,
               "SLENTRY.nid", "a search capped at the entry limit");
    TEST_CHECK(mstats.stopped_early);
    TEST_EQ(mstats.entries_scanned, kMaxSubnodeEntries, "one search scans at most the cap");
    TEST_OK(find_subnode(2, 0x8F5F, crowded, mstats, mfailures), "the next search still works");
}

} // namespace

namespace {

void check_subnode_errors() {
    FakeBlocks blocks;
    blocks.add(0x32, sl_block({{0x8F5F, 0x1380, 0}}), true);
    blocks.add(0x60, std::vector<uint8_t>{0xEC, 0x00, 0xEC, 0xBC, 0x20, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    std::vector<uint8_t> short_block = sl_block({{0x8F5F, 0x1380, 0}, {0x8C1F, 0x1500, 0}});
    short_block[2] = 4; // cEnt says four entries, the block holds two
    blocks.add(0x70, short_block, true);

    SubnodeStats stats;
    FailureLog failures(5);

    // [MS-PST] 2.2.2.7.7.4: bidSub zero means the node has no subnode block.
    TEST_ERROR(find_subnode(0, 0x8F5F, blocks, stats, failures), ErrorKind::kBadField,
               "NBTENTRY.bidSub", "no subnode block to search");

    // A BID the source cannot answer is the source's error, reported unchanged.
    TEST_ERROR(find_subnode(0x999, 0x8F5F, blocks, stats, failures), ErrorKind::kIo,
               "BlockSource.block", "a BID the source does not hold");

    // A data block is not a subnode block, and the walk says so instead of scanning garbage.
    TEST_ERROR(find_subnode(0x60, 0x8F5F, blocks, stats, failures), ErrorKind::kBadSignature,
               "SUBNODE.btype", "a data block where a subnode block was expected");
    TEST_EQ(stats.blocks_bad, 1, "the bad block counted");
    TEST_EQ(stats.blocks_not_internal, 1u, "and the BBT did not flag it Internal either");

    // A chain that never names the NID is an error, not an empty answer.
    TEST_ERROR(find_subnode(0x32, 0x8C1F, blocks, stats, failures), ErrorKind::kUnsupported,
               "SLENTRY.nid", "no SLENTRY names that NID");
    TEST_EQ(stats.not_found, 1, "not-found counted");

    // Entries that run past the end of the block are logged and skipped; the search still finishes.
    SubnodeStats sstats;
    FailureLog sfailures(5);
    TEST_ERROR(find_subnode(0x70, 0x9999, blocks, sstats, sfailures), ErrorKind::kUnsupported,
               "SLENTRY.nid", "the entries past the end of the block are gone");
    TEST_EQ(sstats.entries_scanned, 2, "the two entries that fit were scanned");
    TEST_EQ(sstats.entries_skipped, 2, "the two that did not fit were skipped");
    TEST_EQ(sstats.not_found, 1, "and the search still reported the answer");
    TEST_EQ(sfailures.total(), 2, "each skipped entry logged");
}

void check_walk_subnode_entries() {
    // One SLBLOCK: every entry comes back, ordered by the low-32-bit key a HNID uses.
    FakeBlocks blocks;
    blocks.add(1, sl_block({{0x8F5F, 0x1380, 0}, {0x671, 0x1400, 0x1500}, {0x692, 0x1600, 0}}), true);
    SubnodeStats stats;
    FailureLog failures(5);
    Result<std::vector<SubnodeRef>> entries = walk_subnode_entries(1, blocks, stats, failures);
    TEST_OK(entries, "every SLENTRY of one SLBLOCK");
    if (entries.ok() && entries.value().size() == 3) {
        TEST_EQ(entries.value()[0].nid, 0x671, "ordered by key");
        TEST_EQ(entries.value()[1].nid, 0x692, "the recipient table before the heap id");
        TEST_EQ(entries.value()[2].nid, 0x8F5F, "largest key last");
        TEST_EQ(entries.value()[2].bid_data, 0x1380, "bidData kept");
        TEST_EQ(entries.value()[0].bid_sub, 0x1500, "bidSub kept");
        TEST_EQ(entries.value()[2].block_bid, 1, "which block held the entry");
    } else {
        TEST_EQ(entries.value().size(), 3, "three subnodes");
    }
    TEST_EQ(stats.found, 3, "found counted");
    TEST_EQ(stats.entries_scanned, 3, "scanned counted");
    TEST_EQ(stats.max_entries, 3, "the widest block seen");
    TEST_CHECK(!stats.stopped_early);
    TEST_EQ(failures.total(), 0, "nothing logged");

    // Unlike the targeted descent, an enumeration follows EVERY SIBLOCK child.
    FakeBlocks chain;
    chain.add(1, si_block({{0x100, 2}, {0x200, 3}}), true);
    chain.add(2, sl_block({{0x150, 0x2000, 0}}), true);
    chain.add(3, sl_block({{0x250, 0x3000, 0x3100}}), true);
    SubnodeStats cstats;
    FailureLog cfailures(5);
    Result<std::vector<SubnodeRef>> chained = walk_subnode_entries(1, chain, cstats, cfailures);
    TEST_OK(chained, "both children of one SIBLOCK");
    if (chained.ok() && chained.value().size() == 2) {
        TEST_EQ(chained.value()[0].nid, 0x150, "the first child's entry");
        TEST_EQ(chained.value()[1].bid_sub, 0x3100, "the second child's entry");
        TEST_EQ(chained.value()[1].depth, 1, "reached through one SIBLOCK");
    } else {
        TEST_EQ(chained.value().size(), 2, "one entry from each SLBLOCK");
    }
    TEST_EQ(cstats.si_hops, 2, "both hops counted");
    TEST_EQ(cstats.max_depth, 1, "one SIBLOCK deep");
    TEST_CHECK(!cstats.stopped_early);

    // A block reached twice is a cycle: it stops that branch instead of spinning.
    FakeBlocks loop;
    loop.add(1, si_block({{0x100, 1}}), true);
    SubnodeStats lstats;
    FailureLog lfailures(5);
    Result<std::vector<SubnodeRef>> cyclic = walk_subnode_entries(1, loop, lstats, lfailures);
    TEST_OK(cyclic, "a cycle still answers with what it read");
    TEST_EQ(cyclic.value().size(), 0, "no entries behind the cycle");
    TEST_EQ(lstats.blocks_read, 1, "the block read once");
    TEST_CHECK(lstats.stopped_early);
    TEST_EQ(lfailures.total(), 1, "the cycle logged");

    // The depth cap drops the branch past it and says the list is short.
    FakeBlocks deep_chain;
    for (uint64_t bid = 1; bid <= kMaxSubnodeDepth + 1; ++bid) {
        deep_chain.add(bid, si_block({{0x100, bid + 1}}), true);
    }
    deep_chain.add(kMaxSubnodeDepth + 2, sl_block({{0x8F5F, 0x9000, 0}}), true);
    SubnodeStats dstats;
    FailureLog dfailures(5);
    Result<std::vector<SubnodeRef>> capped = walk_subnode_entries(1, deep_chain, dstats, dfailures);
    TEST_OK(capped, "a capped walk still answers");
    TEST_EQ(capped.value().size(), 0, "the entry sits past the depth cap");
    TEST_EQ(dstats.blocks_read, kMaxSubnodeDepth + 1, "the blocks within the cap read");
    TEST_CHECK(dstats.stopped_early);

    // The entry cap is per walk, and the answer says it is short.
    std::vector<std::array<uint64_t, 3>> many;
    for (uint64_t i = 0; i < kMaxSubnodeEntries + 904; ++i) {
        many.push_back({{0x1000 + i, 0x2000 + i, 0}});
    }
    FakeBlocks crowded;
    crowded.add(1, sl_block(many), true);
    SubnodeStats mstats;
    FailureLog mfailures(5);
    Result<std::vector<SubnodeRef>> crowded_entries = walk_subnode_entries(1, crowded, mstats, mfailures);
    TEST_OK(crowded_entries, "a capped enumeration");
    TEST_EQ(crowded_entries.value().size(), kMaxSubnodeEntries, "at most the cap returned");
    TEST_EQ(mstats.entries_scanned, kMaxSubnodeEntries, "scanning capped too");
    TEST_CHECK(mstats.stopped_early);

    // A block the source cannot answer is the source's error when it is the node's own subnode block.
    SubnodeStats estats;
    FailureLog efailures(5);
    TEST_ERROR(walk_subnode_entries(0, blocks, estats, efailures), ErrorKind::kBadField,
               "NBTENTRY.bidSub", "no subnode block to enumerate");
    TEST_ERROR(walk_subnode_entries(0x999, blocks, estats, efailures), ErrorKind::kIo,
               "BlockSource.block", "the node's own subnode block unreadable");

    // A data block where a subnode block was expected is reported, not enumerated as garbage.
    FakeBlocks not_subnode;
    not_subnode.add(0x60, std::vector<uint8_t>{0xEC, 0x00, 0xEC, 0xBC, 0x20, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    TEST_ERROR(walk_subnode_entries(0x60, not_subnode, estats, efailures), ErrorKind::kBadSignature,
               "SUBNODE.btype", "a data block where a subnode block was expected");

    // A child block that is missing only costs that branch; the rest of the list is still reported.
    FakeBlocks half;
    half.add(1, si_block({{0x100, 2}, {0x200, 4}}), true);
    half.add(2, sl_block({{0x150, 0x2000, 0}}), true);
    SubnodeStats hstats;
    FailureLog hfailures(5);
    Result<std::vector<SubnodeRef>> partial = walk_subnode_entries(1, half, hstats, hfailures);
    TEST_OK(partial, "the readable branch still reported");
    TEST_EQ(partial.value().size(), 1, "the entry from the block that exists");
    TEST_EQ(hstats.blocks_bad, 1, "the missing block counted");
    TEST_CHECK(hstats.stopped_early);
    TEST_EQ(hfailures.total(), 1, "and logged");

    // Entries running past the end of a block are logged and skipped; the walk still finishes.
    std::vector<uint8_t> short_block = sl_block({{0x8F5F, 0x1380, 0}, {0x8C1F, 0x1500, 0}});
    short_block[2] = 4; // cEnt says four entries, the block holds two
    FakeBlocks truncated;
    truncated.add(1, short_block, true);
    SubnodeStats tstats;
    FailureLog tfailures(5);
    Result<std::vector<SubnodeRef>> kept = walk_subnode_entries(1, truncated, tstats, tfailures);
    TEST_OK(kept, "a truncated block still yields what fits");
    TEST_EQ(kept.value().size(), 2, "the two entries that fit");
    TEST_EQ(tstats.entries_skipped, 2, "the two that did not");
    TEST_EQ(tfailures.total(), 2, "each skipped entry logged");
}

void check_nid_map() {
    // [MS-PST] 2.4.4.3: a Folder object is one PC and three TCs sharing a nidIndex.
    NidMap map;
    map.add(entry(0x22, 0x1000, 0x1100, 0x122));
    map.add(entry(0x2D, 0x1200, 0, 0x122));
    map.add(entry(0x2E, 0x1300, 0x1400, 0x122));
    map.add(entry(0x2F, 0x1500, 0, 0x122));
    map.add(entry(0x249784, 0x2000, 0x2100, 0x122));
    map.add(entry(0x22, 0x1000, 0x1100, 0x122));

    TEST_EQ(map.size(), 5, "entries kept");
    TEST_EQ(map.groups(), 2, "nidIndex groups");
    TEST_EQ(map.duplicates(), 1, "a repeated NID counted, not stored twice");
    TEST_EQ(map.with_subnode(), 3, "entries with a bidSub");
    TEST_EQ(map.missing_data(), 0, "every entry here has a bidData");
    // [MS-PST] 2.2.2.7.7.4 / 2.4.5.2: every entry here names NID 0x122 as its parent.
    TEST_EQ(map.parent_links(), 5, "the duplicate counted once, like every other tally");
    TEST_EQ(map.children(0x122, ost2pst::ltp::kNidTypeNormalMessage), 1, "the message under that parent");
    TEST_EQ(map.children(0x122, ost2pst::ltp::kNidTypeContentsTable), 1, "and its contents table");
    TEST_EQ(map.children(0x122, ost2pst::ltp::kNidTypeNormalFolder), 1, "the folder PC is itself a child");
    TEST_EQ(map.children(0x122, ost2pst::ltp::kNidTypeAttachmentTable), 0, "no attachment table under it");
    TEST_EQ(map.children(0x1234, ost2pst::ltp::kNidTypeNormalMessage), 0, "a parent the map does not have");

    Result<NodeRef> folder = map.node(0x22);
    TEST_OK(folder, "the folder PC");
    if (folder.ok()) {
        TEST_EQ(folder.value().bid_sub, 0x1100, "bidData and bidSub kept");
        TEST_EQ(folder.value().nid_parent, 0x122, "nidParent kept");
    }
    TEST_ERROR(map.node(0x1234), ErrorKind::kUnsupported, "NBTENTRY.nid", "a NID the map does not hold");

    // The sibling of a folder is the same nidIndex under another nidType.
    Result<NodeRef> contents = map.sibling(0x22, ost2pst::ltp::kNidTypeContentsTable);
    TEST_OK(contents, "the folder's contents table");
    if (contents.ok()) {
        TEST_EQ(contents.value().nid, 0x2E, "nidIndex 1 under NID_TYPE_CONTENTS_TABLE");
    }
    TEST_ERROR(map.sibling(0x22, ost2pst::ltp::kNidTypeAttachmentTable), ErrorKind::kUnsupported,
               "NBTENTRY.nid", "this folder has no attachment table");

    const std::vector<NodeRef> group = map.group(0x2E);
    TEST_EQ(group.size(), 4, "one PC and three TCs");
    if (group.size() == 4) {
        TEST_EQ(group[0].nid, 0x22, "sorted by nidType");
        TEST_EQ(group[1].nid, 0x2D, "HIERARCHY_TABLE");
        TEST_EQ(group[2].nid, 0x2E, "CONTENTS_TABLE");
        TEST_EQ(group[3].nid, 0x2F, "ASSOC_CONTENTS_TABLE");
    }
    TEST_EQ(map.group(0x249784).size(), 1, "a lone message");
    TEST_EQ(map.group(0x1234).size(), 0, "an index the map does not hold");

    NidMap empty;
    TEST_CHECK(empty.empty());
    TEST_EQ(empty.groups(), 0, "and no groups");
}

} // namespace

int main() {
    check_nid_arithmetic();
    check_block_header();
    check_entries();
    check_find_subnode();
    check_subnode_chain();
    check_subnode_errors();
    check_walk_subnode_entries();
    check_nid_map();
    return ost2pst::test::finish("ltp_nid_map_test");
}
