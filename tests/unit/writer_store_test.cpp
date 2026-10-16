// The generic store emitter on its own: a plan in, a whole PST out. The empty PST already checks
// the one-region shape the Outlook-accepted M4 candidate had, so this test goes after the parts
// only a content-bearing file reaches — a BTree deeper than one index level, AMap regions past the
// first, the SLBLOCK a node with subnodes needs, the XBLOCK a node whose data does not fit in one
// block needs, and the reference counts [MS-PST] 2.2.2.7.7.3.1 says those structures hold. Every
// claim is checked by reading the image back through ndb:: and ltp:: the way a reader would.
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include "ost2pst/ltp/block_heap.h"
#include "ost2pst/ltp/data_tree.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/ltp/node_open.h"
#include "ost2pst/ndb/bbt_index.h"
#include "ost2pst/ndb/btree.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/ndb/ndb_read.h"
#include "ost2pst/ndb/probe.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/writer/store.h"

#include "test_support.h"

namespace {

namespace ltp = ost2pst::ltp;
namespace ndb = ost2pst::ndb;

using ost2pst::ndb::FileProfile;
using ost2pst::util::ByteView;
using ost2pst::util::FileReader;
using ost2pst::util::Result;
using ost2pst::writer::kNoBlock;
using ost2pst::writer::StoreBlock;
using ost2pst::writer::StoreImage;
using ost2pst::writer::StoreNode;
using ost2pst::writer::StorePlan;
using ost2pst::writer::StoreSubnode;
using ost2pst::writer::write_store;
using ost2pst::writer::WrittenBlock;

constexpr FileProfile kProfile = FileProfile::kPst;
constexpr uint64_t kPageSize = ndb::kPstPageSize;
constexpr uint64_t kGranularity = ndb::block_granularity(kProfile);
constexpr uint64_t kAmapInterval = ndb::amap_interval(kProfile);

const char* kTempName = "ost2pst_writer_store_test.pst";

std::filesystem::path temp_path(const char* name) {
    std::filesystem::path path = std::filesystem::temp_directory_path();
    path /= name;
    return path;
}

// Deterministic block bytes, so a comparison that fails says which byte differs.
std::vector<uint8_t> payload(uint64_t seed, size_t cb) {
    std::vector<uint8_t> bytes(cb);
    uint64_t state = seed * 2654435761ull + 1;
    for (size_t index = 0; index < cb; ++index) {
        state = state * 6364136223846793005ull + 1442695040888963407ull;
        bytes[index] = static_cast<uint8_t>(state >> 33);
    }
    return bytes;
}

std::vector<uint32_t> default_rgnid() {
    return std::vector<uint32_t>(ndb::kRgnidCount, 1024u);
}

bool write_image(const StoreImage& image, const std::filesystem::path& path) {
    std::ofstream stream(path, std::ios::binary);
    if (!stream) {
        ost2pst::test::report_failure(__FILE__, __LINE__, "cannot create the store test PST");
        return false;
    }
    stream.write(reinterpret_cast<const char*>(image.bytes.data()),
                 static_cast<std::streamsize>(image.bytes.size()));
    return stream.good();
}

// One reusable page buffer. decode_bt_* copies what it returns, so the view only has to survive the
// decode call itself, not the walk below it.
struct PageReader {
    const FileReader& file;
    std::vector<uint8_t> buffer;

    ByteView read(uint64_t ib) {
        buffer.assign(kPageSize, 0);
        if (!file.read_at(ib, buffer.data(), buffer.size()).ok()) {
            ost2pst::test::report_failure(__FILE__, __LINE__,
                                          "cannot read page " + std::to_string(ib));
        }
        return ByteView(buffer.data(), buffer.size(), ib);
    }
};

// [MS-PST] 2.2.2.7.7.2: an index entry's btkey is the first key of the child page it names, and the
// keys inside one page ascend. ndb::BTreeWalker visits pages by level and never descends by key, so
// nothing else in the suite would notice a btkey that a key-seeking reader took to the wrong page.
uint64_t check_index_keys(PageReader& pages, uint8_t ptype, uint64_t ib, uint64_t bid_next_p,
                          uint64_t* first_key) {
    const ByteView view = pages.read(ib);
    Result<ndb::BtPageInfo> footer = ndb::decode_bt_page_footer(view, kProfile);
    TEST_OK(footer, "BTPAGE footer");
    if (!footer.ok()) {
        return 0;
    }
    if (footer.value().c_level == 0) {
        uint64_t count = 0;
        uint64_t previous = 0;
        if (ptype == ndb::kPageTypeBBT) {
            Result<std::vector<ndb::BbtEntry>> entries =
                ndb::decode_bbt_entries(view, footer.value());
            TEST_OK(entries, "BBT leaf entries");
            if (!entries.ok()) {
                return 0;
            }
            for (const ndb::BbtEntry& entry : entries.value()) {
                TEST_CHECK_MSG(entry.bid > previous, "leaf BIDs ascend inside a leaf page");
                previous = entry.bid;
                ++count;
            }
            if (!entries.value().empty()) {
                *first_key = entries.value().front().bid;
            }
        } else {
            Result<std::vector<ndb::NbtEntry>> entries =
                ndb::decode_nbt_entries(view, footer.value());
            TEST_OK(entries, "NBT leaf entries");
            if (!entries.ok()) {
                return 0;
            }
            for (const ndb::NbtEntry& entry : entries.value()) {
                TEST_CHECK_MSG(entry.nid > previous, "leaf NIDs ascend inside a leaf page");
                previous = entry.nid;
                ++count;
            }
            if (!entries.value().empty()) {
                *first_key = entries.value().front().nid;
            }
        }
        return count;
    }

    Result<std::vector<ndb::BtEntry>> index = ndb::decode_bt_entries(view, footer.value());
    TEST_OK(index, "index entries");
    if (!index.ok()) {
        return 0;
    }
    uint64_t total = 0;
    uint64_t previous = 0;
    for (const ndb::BtEntry& entry : index.value()) {
        uint64_t child_first = 0;
        total += check_index_keys(pages, ptype, entry.ib, bid_next_p, &child_first);
        TEST_EQ(entry.bt_key, child_first,
                "an index btkey names the smallest key of the page it points at");
        TEST_CHECK_MSG(entry.bt_key > previous, "index btkeys ascend");
        previous = entry.bt_key;
        TEST_CHECK_MSG(entry.bid != 0 && entry.bid < bid_next_p,
                       "an index entry names a page BID outside HEADER.bidNextP");
    }
    if (!index.value().empty()) {
        *first_key = index.value().front().bt_key;
    }
    return total;
}

// A file big enough to need several AMap regions and a BTree deeper than one index level: the shape
// a converted folder reaches, and the one the M4 candidate never exercised.
void check_deep_tree_and_regions() {
    StorePlan plan;
    const uint64_t block_count = 900;
    for (uint64_t index = 0; index < block_count; ++index) {
        plan.blocks.push_back(StoreBlock{payload(index, 4096)});
    }
    for (uint64_t index = 0; index < block_count; ++index) {
        StoreNode node;
        node.nid = static_cast<uint32_t>(ltp::make_nid(1024 + index, ltp::kNidTypeNormalMessage));
        node.nid_parent = 0x0122;
        node.data_blocks.push_back(index);
        plan.nodes.push_back(std::move(node));
    }
    plan.rgnid = default_rgnid();
    plan.rgnid[ltp::kNidTypeNormalMessage] = static_cast<uint32_t>(1023 + block_count);

    Result<StoreImage> built = write_store(plan);
    TEST_OK(built, "write_store over 900 blocks");
    if (!built.ok()) {
        return;
    }
    const StoreImage& image = built.value();

    TEST_EQ(image.blocks.size(), block_count, "a node of one data block needs no internal block");
    TEST_EQ(image.bid_next_b, (block_count + 1) * 4, "bidNextB is the BID the next block takes");
    TEST_CHECK_MSG(image.amap_regions >= 2, "this plan has to pass the first AMap region");
    TEST_EQ(image.bytes.size(), ndb::kPstAmapFirstOffset + image.amap_regions * kAmapInterval,
            "the file grows in whole AMap regions");
    TEST_EQ(image.cb_amap_free,
            (image.amap_regions * ndb::amap_units(kProfile) - image.amap_bits_set) * kGranularity,
            "cbAMapFree is the free bits of every AMap added up");

    // [MS-PST] 2.2.2.7.2 / 2.2.2.7.3: the AMap and PMap pages are allocated out of the data section
    // they map, so no data block may sit on one.
    for (uint64_t region = 0; region < image.amap_regions; ++region) {
        const uint64_t amap_ib = ndb::kPstAmapFirstOffset + region * kAmapInterval;
        std::vector<std::pair<uint64_t, uint64_t>> fixed = {{amap_ib, kPageSize}};
        if (region % 8 == 0) {
            fixed.push_back({amap_ib + kPageSize, kPageSize});
        }
        for (const WrittenBlock& block : image.blocks) {
            const uint64_t footprint =
                ndb::align_allocation(kProfile, block.cb + ndb::block_trailer_size(kProfile));
            for (const auto& range : fixed) {
                TEST_CHECK_MSG(block.ib >= range.first + range.second ||
                                   block.ib + footprint <= range.first,
                               "a data block overlaps an AMap or PMap page");
            }
        }
    }

    const std::filesystem::path path = temp_path(kTempName);
    if (!write_image(image, path)) {
        return;
    }
    Result<FileReader> opened = FileReader::open(path.native());
    TEST_OK(opened, "FileReader::open");
    if (opened.ok()) {
        const FileReader& file = opened.value();

        ndb::ProbeOptions probe_options;
        Result<ndb::ProbeReport> probed = ndb::probe_file(file, probe_options);
        TEST_OK(probed, "probe_file over a multi-region file");
        if (probed.ok()) {
            const ndb::ProbeReport& report = probed.value();
            TEST_CHECK_MSG(report.clean, "probe is not clean over a multi-region file");
            TEST_EQ(report.failure_total, 0u, "probe failures");
            TEST_EQ(report.counters.amap.regions, image.amap_regions, "AMap regions");
            TEST_EQ(report.counters.amap.regions_valid, image.amap_regions, "valid AMap regions");
            TEST_EQ(report.counters.amap.last_region_matches_ib_amap_last, 1u,
                    "ROOT.ibAMapLast names the last region");
            TEST_EQ(report.counters.amap.misses_indexed, 0u,
                    "the AMaps mark every allocated block");
            TEST_EQ(report.counters.blocks.indexed, block_count, "probe blocks indexed");
            TEST_EQ(report.counters.blocks.crc_failed, 0u, "block CRC failures");
            TEST_EQ(report.counters.blocks.cb_mismatches, 0u, "BBTENTRY.cb versus BLOCKTRAILER.cb");
            TEST_EQ(report.counters.blocks.bid_mismatches, 0u,
                    "BBTENTRY.bid versus BLOCKTRAILER.bid");
            TEST_EQ(report.counters.blocks.sig_failed, 0u, "block signature failures");
        }

        ndb::NdbReadOptions read_options;
        Result<ndb::NdbReadReport> read = ndb::read_ndb(file, read_options);
        TEST_OK(read, "read_ndb over a multi-region file");
        if (read.ok()) {
            const ndb::NdbReadReport& report = read.value();
            TEST_CHECK_MSG(report.clean, "read_ndb is not clean over a multi-region file");
            TEST_CHECK_MSG(report.counters.bid_next_b_covers, "bidNextB covers the blocks");
            TEST_CHECK_MSG(report.counters.bid_next_p_covers, "bidNextP covers the pages");
            TEST_EQ(report.bbt.max_level, 2u, "900 blocks need two BBT index levels");
            TEST_EQ(report.nbt.max_level, 2u, "900 nodes need two NBT index levels");
            TEST_EQ(report.counters.bbt_index_entries, block_count,
                    "every block is indexed exactly once");
            TEST_EQ(report.counters.nbt_entries, block_count, "every node is indexed exactly once");
            TEST_EQ(report.header.root.ib_amap_last,
                    ndb::kPstAmapFirstOffset + (image.amap_regions - 1) * kAmapInterval,
                    "ROOT.ibAMapLast");
            PageReader pages{file, {}};
            uint64_t first_key = 0;
            TEST_EQ(check_index_keys(pages, ndb::kPageTypeBBT, image.bbt_root_ib, image.bid_next_p,
                                     &first_key),
                    block_count, "the BBT indexes every written block");
            TEST_EQ(check_index_keys(pages, ndb::kPageTypeNBT, image.nbt_root_ib, image.bid_next_p,
                                     &first_key),
                    block_count, "the NBT indexes every node");
        }
    }
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

// A node with subnodes and a subnode whose data needs a data tree: the two internal block kinds the
// emitter has to build, and the reference counts the SLENTRYs and the XBLOCK rgbid slots owe them.
void check_subnodes_and_data_tree() {
    StorePlan plan;
    const uint64_t parent_data = 0;
    const uint64_t tree_first = 1; // five blocks under one XBLOCK
    const uint64_t subnode_data = 6;
    const uint64_t grandchild_data = 7;
    plan.blocks.push_back(StoreBlock{payload(parent_data, 64)});
    for (uint64_t index = tree_first; index <= 5; ++index) {
        plan.blocks.push_back(StoreBlock{payload(index, 3000)});
    }
    plan.blocks.push_back(StoreBlock{payload(subnode_data, 48)});
    plan.blocks.push_back(StoreBlock{payload(grandchild_data, 48)});

    StoreSubnode grandchild;
    grandchild.nid = 0x00000061;
    grandchild.data_blocks.push_back(grandchild_data);

    StoreSubnode deep;
    deep.nid = 0x00000060;
    deep.data_blocks.push_back(subnode_data);
    deep.subnodes.push_back(std::move(grandchild));

    StoreSubnode spread;
    spread.nid = 0x0000003F;
    spread.data_blocks = {1, 2, 3, 4, 5};

    StoreNode folder;
    folder.nid = 0x00000122;
    folder.nid_parent = 0x00000122;
    folder.data_blocks.push_back(parent_data);
    folder.subnodes.push_back(std::move(spread));
    folder.subnodes.push_back(std::move(deep));
    plan.nodes.push_back(std::move(folder));
    plan.rgnid = default_rgnid();

    Result<StoreImage> built = write_store(plan);
    TEST_OK(built, "write_store over a node with subnodes");
    if (!built.ok()) {
        return;
    }
    const StoreImage& image = built.value();

    // 8 data blocks, then the XBLOCK over the five, the SLBLOCK of the deep subnode, and the
    // SLBLOCK of the folder: 11 blocks, three of them internal ([MS-PST] 2.2.2.2 bit B).
    TEST_EQ(image.blocks.size(), 11u, "the emitter added one XBLOCK and two SLBLOCKs");
    uint64_t internal_blocks = 0;
    for (const WrittenBlock& block : image.blocks) {
        if (ndb::bid_is_internal(block.bid)) {
            ++internal_blocks;
        }
    }
    TEST_EQ(internal_blocks, 3u, "internal blocks carry bit B in their BID");
    TEST_EQ(image.bid_next_b, 12u * 4, "bidNextB covers the internal blocks too");

    // [MS-PST] 2.2.2.7.7.3.1: 1 leaf BBTENTRY + the NBTENTRY or SLENTRY that names the block + the
    // XBLOCK rgbid slot that names it. Nothing here is named twice, so every block sits at cRef 2.
    for (const WrittenBlock& block : image.blocks) {
        TEST_EQ(block.c_ref, 2u, "one reference names each block of this plan");
    }

    const std::filesystem::path path = temp_path(kTempName);
    if (!write_image(image, path)) {
        return;
    }
    Result<FileReader> opened = FileReader::open(path.native());
    TEST_OK(opened, "FileReader::open");
    if (!opened.ok()) {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        return;
    }
    const FileReader& file = opened.value();

    ndb::FailureLog failures(40);
    ndb::BTreeWalker bbt(ndb::kPageTypeBBT, kProfile, &failures);
    TEST_OK(bbt.walk(file, image.bbt_root_ib), "walk the BBT");
    const ndb::BbtIndex index(bbt.bbt_index());
    TEST_EQ(index.entries(), 11u, "the BBT indexes the internal blocks as well");

    ndb::BTreeWalker nbt(ndb::kPageTypeNBT, kProfile, &failures);
    ltp::NidMap nodes;
    nbt.set_nbt_handler([&nodes](const ndb::NbtEntry& entry, uint64_t) { nodes.add(entry); });
    TEST_OK(nbt.walk(file, image.nbt_root_ib), "walk the NBT");
    TEST_EQ(nodes.size(), 1u, "the plan has one NBT node");
    TEST_EQ(nodes.with_subnode(), 1u, "the node carries a bidSub");

    Result<ltp::NodeRef> node = nodes.node(0x00000122);
    TEST_OK(node, "the folder node");
    if (!node.ok()) {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        return;
    }
    TEST_CHECK_MSG(ndb::bid_is_internal(node.value().bid_sub), "bidSub names an internal block");

    ndb::BlockReadCounters counters;
    ltp::FileBlockSource blocks(file, kProfile, index, counters, failures);
    ltp::SubnodeStats stats;
    Result<std::vector<ltp::SubnodeRef>> subnodes =
        ltp::walk_subnode_entries(node.value().bid_sub, blocks, stats, failures);
    TEST_OK(subnodes, "walk the folder's subnode list");
    if (subnodes.ok()) {
        TEST_EQ(subnodes.value().size(), 2u, "the SLBLOCK holds both subnodes");
        TEST_EQ(stats.found, 2u, "subnode entries found");
        TEST_EQ(stats.blocks_not_internal, 0u, "a bidSub that is not an internal block");
        for (const ltp::SubnodeRef& subnode : subnodes.value()) {
            TEST_CHECK_MSG(subnode.nid == 0x3F || subnode.nid == 0x60,
                           "the SLENTRY names the local NID");
            TEST_CHECK_MSG(subnode.bid_data != 0, "every SLENTRY here names a data block");
        }
    }

    // The five-block subnode: bidData roots an XBLOCK, and read_data_tree flattens it back to the
    // bytes.
    Result<ltp::SubnodeRef> spread_ref =
        ltp::find_subnode(node.value().bid_sub, 0x3F, blocks, stats, failures);
    TEST_OK(spread_ref, "find the subnode whose data is a data tree");
    if (spread_ref.ok()) {
        ltp::DataTreeCounters trees;
        Result<std::vector<ltp::HnFragment>> fragments =
            ltp::read_data_tree(blocks, spread_ref.value().bid_data, kProfile, trees, failures);
        TEST_OK(fragments, "flatten the XBLOCK");
        if (fragments.ok()) {
            TEST_EQ(fragments.value().size(), 5u, "the XBLOCK names five data blocks");
            TEST_EQ(trees.tables, 1u, "one jump table decoded");
            TEST_EQ(trees.data_blocks, 5u, "the tree ended in five data blocks");
            TEST_EQ(trees.lcb_total_mismatches, 0u, "XBLOCK.lcbTotal equals the bytes under it");
            TEST_EQ(trees.child_flag_mismatches, 0u, "an XBLOCK names external blocks");
            std::vector<uint8_t> joined;
            for (const ltp::HnFragment& fragment : fragments.value()) {
                joined.insert(joined.end(), fragment.owned.begin(), fragment.owned.end());
            }
            std::vector<uint8_t> expected;
            for (uint64_t slot = 1; slot <= 5; ++slot) {
                const std::vector<uint8_t> bytes = payload(slot, 3000);
                expected.insert(expected.end(), bytes.begin(), bytes.end());
            }
            TEST_EQ(joined.size(), expected.size(),
                    "the data tree holds every byte of the subnode data");
            TEST_CHECK_MSG(joined == expected, "the data tree holds the bytes in the XBLOCK order");
        }
    }

    // The deep subnode's own subnode list: a second SLBLOCK reached through a SLENTRY bidSub.
    Result<ltp::SubnodeRef> deep_ref =
        ltp::find_subnode(node.value().bid_sub, 0x60, blocks, stats, failures);
    TEST_OK(deep_ref, "find the subnode with a subnode of its own");
    if (deep_ref.ok()) {
        TEST_CHECK_MSG(deep_ref.value().bid_sub != 0,
                       "the SLENTRY names the subnode list of that subnode");
        ltp::SubnodeStats deeper;
        Result<std::vector<ltp::SubnodeRef>> grand =
            ltp::walk_subnode_entries(deep_ref.value().bid_sub, blocks, deeper, failures);
        TEST_OK(grand, "walk the second SLBLOCK");
        if (grand.ok()) {
            TEST_EQ(grand.value().size(), 1u, "the second SLBLOCK holds one entry");
            TEST_EQ(grand.value().front().nid, 0x61u, "the grandchild local NID");
        }
    }

    TEST_EQ(failures.total(), 0u, "no reader finding about the emitter's internal blocks");
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

// A plan the emitter refuses, with the reason named: a caller that gets one of these has to know
// which part of its plan was wrong rather than guess from a half-written file.
void check_rejected_plans() {
    {
        StorePlan plan;
        plan.blocks.push_back(StoreBlock{payload(0, 64)});
        StoreNode node;
        node.nid = 0x00000122;
        node.data_blocks.push_back(0);
        plan.nodes.push_back(std::move(node));
        plan.rgnid.assign(ndb::kRgnidCount - 1, 1024u);
        TEST_ERROR(write_store(plan), ost2pst::util::ErrorKind::kBadField, "HEADER.rgnid",
                   "a plan has to name every nidType counter");
    }
    {
        StorePlan plan;
        plan.blocks.push_back(StoreBlock{payload(0, 64)});
        plan.rgnid = default_rgnid();
        StoreNode node;
        node.nid = 0x00000122;
        node.data_blocks.push_back(7);
        plan.nodes.push_back(std::move(node));
        TEST_ERROR(write_store(plan), ost2pst::util::ErrorKind::kBadField,
                   "writer.store.block_index", "a node cannot name a block the plan does not have");
    }
    {
        StorePlan plan;
        plan.blocks.push_back(StoreBlock{payload(0, static_cast<size_t>(ndb::kPstBlockMaxCb) + 1)});
        plan.rgnid = default_rgnid();
        StoreNode node;
        node.nid = 0x00000122;
        node.data_blocks.push_back(0);
        plan.nodes.push_back(std::move(node));
        TEST_ERROR(write_store(plan), ost2pst::util::ErrorKind::kBadField,
                   "writer.store.block_size", "one data block holds 8176 bytes and no more");
    }
    {
        StorePlan plan;
        const uint64_t too_many =
            1022; // one XBLOCK names at most 1021 ([MS-PST] 2.2.2.8.3.2.1 + 2.2.2.8)
        for (uint64_t index = 0; index < too_many; ++index) {
            plan.blocks.push_back(StoreBlock{payload(index, 8)});
        }
        plan.rgnid = default_rgnid();
        StoreNode node;
        node.nid = 0x00000122;
        for (uint64_t index = 0; index < too_many; ++index) {
            node.data_blocks.push_back(index);
        }
        plan.nodes.push_back(std::move(node));
        TEST_OK(write_store(plan), "XXBLOCK extends one XBLOCK capacity");
    }
    {
        StorePlan plan;
        plan.blocks.push_back(StoreBlock{payload(0, 8)});
        plan.rgnid = default_rgnid();
        StoreNode node;
        node.nid = 0x00000122;
        node.data_blocks.push_back(0);
        for (uint64_t index = 0; index < 341; ++index) { // one SLBLOCK names at most 340
            StoreSubnode subnode;
            subnode.nid = static_cast<uint32_t>(0x100 + index);
            node.subnodes.push_back(std::move(subnode));
        }
        plan.nodes.push_back(std::move(node));
        TEST_OK(write_store(plan), "SIBLOCK extends one SLBLOCK capacity");
    }
    {
        StorePlan plan;
        plan.rgnid = default_rgnid();
        TEST_ERROR(write_store(plan), ost2pst::util::ErrorKind::kBadField,
                   "writer.store.btree_empty", "a file with no blocks has no BBT root page");
    }
}

void check_expanded_trees() {
    for (const size_t extra : {size_t{0}, size_t{1}}) {
        StorePlan plan;
        plan.rgnid = default_rgnid();
        StoreNode root;
        root.nid = 0x122;
        const size_t data_count = 1021 + extra, sub_count = 340 + extra;
        for (size_t i = 0; i < data_count; ++i) {
            plan.blocks.push_back(StoreBlock{payload(i, 8)});
            root.data_blocks.push_back(i);
        }
        // Deliberately reverse local keys: the BTree writer must order them before splitting.
        for (size_t i = sub_count; i > 0; --i) {
            StoreSubnode child;
            child.nid = static_cast<uint32_t>(i * 32 + 31);
            root.subnodes.push_back(std::move(child));
        }
        plan.nodes.push_back(std::move(root));
        auto built = write_store(plan);
        TEST_OK(built, "write boundary data/subnode trees");
        if (!built.ok())
            return;
        const auto& image = built.value();
        TEST_EQ(image.blocks.size(), data_count + (extra ? 6u : 2u), "exact internal tree count");
        for (const auto& block : image.blocks)
            TEST_EQ(block.c_ref, 2u, "tree link plus leaf BBT reference");
        const auto path = temp_path("ost2pst_writer_expanded_trees.pst");
        if (!write_image(image, path))
            return;
        {
            auto opened = FileReader::open(path.wstring());
            TEST_OK(opened, "open expanded trees");
            if (!opened.ok())
                return;
            const auto& file = opened.value();
            ndb::FailureLog failures(40);
            ndb::BTreeWalker bbt(ndb::kPageTypeBBT, kProfile, &failures);
            TEST_OK(bbt.walk(file, image.bbt_root_ib), "expanded BBT");
            const ndb::BbtIndex index(bbt.bbt_index());
            ndb::BTreeWalker nbt(ndb::kPageTypeNBT, kProfile, &failures);
            ltp::NidMap nodes;
            nbt.set_nbt_handler([&](const ndb::NbtEntry& e, uint64_t) { nodes.add(e); });
            TEST_OK(nbt.walk(file, image.nbt_root_ib), "expanded NBT");
            auto node = nodes.node(0x122);
            TEST_OK(node, "expanded root");
            if (!node.ok())
                return;
            ndb::BlockReadCounters counters;
            ltp::FileBlockSource source(file, kProfile, index, counters, failures);
            ltp::DataTreeCounters trees;
            auto data =
                ltp::read_data_tree(source, node.value().bid_data, kProfile, trees, failures);
            TEST_OK(data, "reader follows XBLOCK/XXBLOCK");
            if (data.ok()) {
                TEST_EQ(data.value().size(), data_count, "all external blocks preserved");
                for (size_t i = 0; i < data.value().size(); ++i)
                    TEST_CHECK(data.value()[i].owned == payload(i, 8));
            }
            TEST_EQ(trees.tables, extra ? 3u : 1u, "XXBLOCK and its two children");
            TEST_EQ(trees.lcb_total_mismatches, 0u, "totals checked by reader");
            ltp::SubnodeStats stats;
            auto children =
                ltp::walk_subnode_entries(node.value().bid_sub, source, stats, failures);
            TEST_OK(children, "reader follows SLBLOCK/SIBLOCK");
            if (children.ok()) {
                TEST_EQ(children.value().size(), sub_count, "all subnodes preserved");
                for (size_t i = 0; i < children.value().size(); ++i)
                    TEST_EQ(children.value()[i].nid, (i + 1) * 32 + 31,
                            "strictly ordered local keys");
            }
            for (const size_t ordinal : {size_t{1}, size_t{340}, sub_count}) {
                auto child = ltp::find_subnode(node.value().bid_sub,
                                               static_cast<uint32_t>(ordinal * 32 + 31), source,
                                               stats, failures);
                TEST_OK(child, "lookup across split boundary");
            }
            TEST_EQ(failures.total(), 0u, "no decode/CRC/signature finding");
        }
        TEST_CHECK(std::filesystem::remove(path));
    }
}

} // namespace

int main() {
    check_deep_tree_and_regions();
    check_subnodes_and_data_tree();
    check_rejected_plans();
    check_expanded_trees();
    return ost2pst::test::finish("writer_store_test");
}
