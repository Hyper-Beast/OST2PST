#include "ost2pst/writer/store.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <tuple>
#include <utility>
#include <vector>

#include "ost2pst/ltp/layout.h"
#include "ost2pst/ndb/amap.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/crc32.h"
#include "ost2pst/util/sig.h"

#include "internal/block_index.h"
#include "internal/put.h"

namespace ost2pst::writer {

using util::ByteView;
using util::ErrorKind;
using util::make_error;
using util::Result;

namespace {

constexpr ndb::FileProfile kProfile = ndb::FileProfile::kPst;

// [MS-PST] 2.2.2.1: "BID values advance in increments of 4". [MS-PST] 2.2.2.2 reserves the two low
// bits of a BID and bit B marks a block that names other blocks, which is what a jump table and a
// subnode list are ([MS-PST] 2.2.2.8.3.2 / 2.2.2.8.3.3).
uint64_t block_bid(uint64_t index, bool internal) {
    const uint64_t bid = (index + 1) * 4;
    return internal ? bid | ndb::kBidInternalBit : bid;
}

// One BTPAGE: rgentries, then the BTPAGE footer, then the pageTrailer ([MS-PST] 2.2.2.7.7.1
// / 2.2.2.7.1). The dwPadding slot after the footer stays zero.
std::vector<uint8_t> bt_page(uint8_t ptype, uint64_t ib, uint64_t bid, uint8_t c_level,
                             uint8_t cb_ent, uint8_t c_ent_max,
                             const std::vector<uint8_t>& entries) {
    std::vector<uint8_t> page(ndb::kPstPageSize, 0);
    std::copy(entries.begin(), entries.end(), page.begin());
    page[ndb::bt_c_ent_offset(kProfile)] = static_cast<uint8_t>(entries.size() / cb_ent);
    page[ndb::bt_c_ent_max_offset(kProfile)] = c_ent_max;
    page[ndb::bt_cb_ent_offset(kProfile)] = cb_ent;
    page[ndb::bt_c_level_offset(kProfile)] = c_level;
    const uint64_t trailer_at = ndb::bt_trailer_offset(kProfile);
    page[trailer_at + ndb::kPageTrailerPtypeOffset] = ptype;
    page[trailer_at + ndb::kPageTrailerPtypeRepeatOffset] = ptype;
    put_u16(page, trailer_at + ndb::kPageTrailerWSigOffset, util::compute_sig(ib, bid));
    put_u32(page, trailer_at + ndb::kPageTrailerCrcOffset,
            util::crc32(
                ByteView(page.data(), static_cast<size_t>(ndb::page_data_bytes(kProfile)), ib)));
    put_u64(page, trailer_at + ndb::kPageTrailerBidOffset, bid);
    return page;
}

// An allocation-map page ([MS-PST] 2.2.2.7.2.1 / 3.1 / 5.1 / 6.1). 2.2.2.7.1 gives these page
// types wSig 0 and a bid equal to their own ib, so they take no BID from bidNextP.
std::vector<uint8_t> map_page(uint8_t ptype, uint64_t ib, const std::vector<uint8_t>& bits) {
    std::vector<uint8_t> page(ndb::kPstPageSize, 0);
    std::copy(bits.begin(), bits.end(), page.begin());
    const uint64_t trailer_at = ndb::bt_trailer_offset(kProfile);
    page[trailer_at + ndb::kPageTrailerPtypeOffset] = ptype;
    page[trailer_at + ndb::kPageTrailerPtypeRepeatOffset] = ptype;
    put_u16(page, trailer_at + ndb::kPageTrailerWSigOffset, 0);
    put_u32(page, trailer_at + ndb::kPageTrailerCrcOffset,
            util::crc32(
                ByteView(page.data(), static_cast<size_t>(ndb::page_data_bytes(kProfile)), ib)));
    put_u64(page, trailer_at + ndb::kPageTrailerBidOffset, ib);
    return page;
}

// [MS-PST] 2.2.2.7.4.2 DLISTPAGE. The page exists because the spec says implementations SHOULD
// create a Density List, but it carries no entries: [MS-PST] 2.2.2.7.4.1 gives DLISTPAGEENT two bit
// fields without saying how they pack into the DWORD, and the writer does not write a field it
// cannot cite.
std::vector<uint8_t> dlist_page(uint64_t ib, uint64_t bid) {
    std::vector<uint8_t> page(ndb::kPstPageSize, 0);
    page[0] = 0x01; // bFlags: DFL_BACKFILL_COMPLETE
    page[1] = 0;    // cEntDList
    const uint64_t trailer_at = ndb::bt_trailer_offset(kProfile);
    page[trailer_at + ndb::kPageTrailerPtypeOffset] = ndb::kPageTypeDList;
    page[trailer_at + ndb::kPageTrailerPtypeRepeatOffset] = ndb::kPageTypeDList;
    put_u16(page, trailer_at + ndb::kPageTrailerWSigOffset, util::compute_sig(ib, bid));
    put_u32(page, trailer_at + ndb::kPageTrailerCrcOffset,
            util::crc32(
                ByteView(page.data(), static_cast<size_t>(ndb::page_data_bytes(kProfile)), ib)));
    put_u64(page, trailer_at + ndb::kPageTrailerBidOffset, bid);
    return page;
}

// --- blocks -------------------------------------------------------------------------------

// One block the emitter will write: the caller's bytes for an external block, or the jump table /
// subnode list the emitter built for an internal one.
struct BlockRecord {
    uint64_t bid = 0;
    uint64_t ib = 0;
    uint64_t source_index = kNoBlock;
    uint64_t references = 0;
    uint16_t cb = 0;
    uint16_t c_ref = 0;
    bool internal() const { return ndb::bid_is_internal(bid); }
    uint64_t footprint() const {
        return ndb::align_allocation(kProfile, cb + ndb::block_trailer_size(kProfile));
    }
};
static_assert(sizeof(BlockRecord) <= 40);

// [MS-PST] 2.2.2.8.3.3.1.2 SLBLOCKHEADER: btype 0x02, cLevel 0, cEnt, dwPadding MUST be zero.
constexpr uint8_t kSubnodeBlockType = 0x02; // [MS-PST] 2.2.2.8.3.3.1.2: btype MUST be 0x02
constexpr uint8_t kSlBlockLevel = 0x00;     // [MS-PST] 2.2.2.8.3.3.1.2: cLevel 0 is an SLBLOCK
constexpr uint64_t kSubnodeHeaderSize = 8;  // [MS-PST] 2.2.2.8.3.3.1.2: btype cLevel cEnt dwPadding
constexpr uint64_t kSlEntrySize = 24; // [MS-PST] 2.2.2.8.3.3.1.1: SLENTRY is nid bidData bidSub

// [MS-PST] 2.2.2.8.3.2.1: an XBLOCK is btype 0x01, cLevel 0x01, cEnt, lcbTotal, then cEnt BIDs of
// data blocks. cEnt is a WORD and the block caps at 8176 bytes, so 1021 children is the widest one
// XBLOCK can hold ((8176 - 8) / 8); larger streams use an XXBLOCK (2.2.2.8.3.2.2).
constexpr uint64_t kXblockMaxChildren = (ndb::kPstBlockMaxCb - ltp::kJumpTableHeaderSize) /
                                        ltp::kJumpTableBidSize; // [MS-PST] 2.2.2.8.3.2.1 + 2.2.2.8

// [MS-PST] 2.2.2.8.3.3.1.1: one SLENTRY of a subnode list.
struct SlEntrySpec {
    uint32_t nid = 0;
    uint64_t bid_data = 0;
    uint64_t bid_sub = 0;
};

std::vector<uint8_t> xblock_bytes(const std::vector<uint64_t>& bids, uint64_t lcb_total,
                                  uint8_t level = ltp::kJumpTableLevelXblock) {
    std::vector<uint8_t> bytes(ltp::kJumpTableHeaderSize + ltp::kJumpTableBidSize * bids.size(), 0);
    bytes[ltp::kJumpTableTypeOffset] = ltp::kJumpTableType;
    bytes[ltp::kJumpTableLevelOffset] = level;
    put_u16(bytes, ltp::kJumpTableCountOffset, static_cast<uint16_t>(bids.size()));
    put_u32(bytes, ltp::kJumpTableTotalOffset, static_cast<uint32_t>(lcb_total));
    for (size_t index = 0; index < bids.size(); ++index) {
        put_u64(bytes, ltp::kJumpTableHeaderSize + index * ltp::kJumpTableBidSize, bids[index]);
    }
    return bytes;
}

std::vector<uint8_t> slblock_bytes(const std::vector<SlEntrySpec>& entries) {
    std::vector<uint8_t> bytes(kSubnodeHeaderSize + kSlEntrySize * entries.size(), 0);
    bytes[0] = kSubnodeBlockType;
    bytes[1] = kSlBlockLevel;
    put_u16(bytes, 2, static_cast<uint16_t>(entries.size()));
    put_u32(bytes, 4, 0); // dwPadding MUST be zero ([MS-PST] 2.2.2.8.3.3.1.2)
    for (size_t index = 0; index < entries.size(); ++index) {
        const uint64_t at = kSubnodeHeaderSize + index * kSlEntrySize;
        put_u64(bytes, at + 0, entries[index].nid);
        put_u64(bytes, at + 8, entries[index].bid_data);
        put_u64(bytes, at + 16, entries[index].bid_sub);
    }
    return bytes;
}

// The blocks built so far plus, for each, how many structures name it. [MS-PST] 2.2.2.7.7.3.1 lists
// the leaf BBTENTRY itself, an NBTENTRY bidData/bidSub, an SLENTRY bidData/bidSub, and an XBLOCK
// rgbid slot; cRef is 1 + those references.
struct BlockState {
    explicit BlockState(std::shared_ptr<util::Workspace> workspace = {})
        : blocks(std::move(workspace)) {}
    // External blocks carry no vector/allocation; only generated internal blocks own bytes.
    // Fixed chunks avoid doubling the index when internal blocks are appended.
    BlockIndex<BlockRecord> blocks;
    std::vector<std::vector<uint8_t>> internal_bytes;
    uint64_t external_count = 0;

    uint64_t append(std::vector<uint8_t> bytes, bool internal) {
        BlockRecord record;
        record.cb = static_cast<uint16_t>(bytes.size());
        if (internal) {
            record.source_index = internal_bytes.size();
            internal_bytes.push_back(std::move(bytes));
        }
        record.bid = block_bid(blocks.size(), internal);
        blocks.push_back(std::move(record));
        return blocks.size() - 1;
    }
    void external(uint64_t index, uint16_t size) {
        const auto slot = append({}, false);
        blocks[slot].source_index = index;
        blocks[slot].cb = size;
    }
};

// [MS-PST] 2.2.2.8.3.3.1.2: an SLBLOCK is 8 header bytes plus 24 bytes per entry, capped at the
// 8176-byte block, so 340 subnodes is the most one SLBLOCK can name.
constexpr uint64_t kSlblockMaxEntries = (ndb::kPstBlockMaxCb - kSubnodeHeaderSize) /
                                        kSlEntrySize; // [MS-PST] 2.2.2.8.3.3.1.1 / 2.2.2.8.3.3.1.2
constexpr uint64_t kSiEntrySize = 16;                 // [MS-PST] 2.2.2.8.3.3.2.1: nid(8), bid(8).
constexpr uint64_t kSiblockMaxEntries = (ndb::kPstBlockMaxCb - kSubnodeHeaderSize) / kSiEntrySize;

// Names the blocks under one node or subnode and returns the two block slots a parent references:
// the data block (or the XBLOCK over several) and the SLBLOCK naming its subnodes. Children come
// first so a parent's SLBLOCK can carry a child's bidSub ([MS-PST] 2.2.2.8.3.3.1.1).
Result<std::pair<uint64_t, uint64_t>> emit_tree(BlockState& state,
                                                const std::vector<uint64_t>& data_blocks,
                                                const std::vector<StoreSubnode>& subnodes,
                                                size_t depth = 0) {
    // Bound trusted-plan recursion too: corrupt item ancestry must never exhaust the stack.
    if (depth > 64)
        return make_error(ErrorKind::kUnsupported, "writer.store.depth", 0, depth);
    if (subnodes.size() > kSlblockMaxEntries * kSiblockMaxEntries)
        return make_error(ErrorKind::kUnsupported, "writer.store.siblock_capacity", 0,
                          subnodes.size());
    std::vector<std::pair<uint64_t, uint64_t>> children;
    children.reserve(subnodes.size());
    for (const StoreSubnode& subnode : subnodes) {
        Result<std::pair<uint64_t, uint64_t>> child =
            emit_tree(state, subnode.data_blocks, subnode.subnodes, depth + 1);
        if (!child.ok()) {
            return child.error();
        }
        children.push_back(child.value());
    }

    // Account for every generated X/XX/SL/SIBLOCK before adding this node's structures.
    const uint64_t data_count =
        data_blocks.size() <= 1
            ? 0
            : (data_blocks.size() + kXblockMaxChildren - 1) / kXblockMaxChildren +
                  (data_blocks.size() > kXblockMaxChildren ? 1 : 0);
    const uint64_t sub_count =
        subnodes.empty() ? 0
        : subnodes.size() <= kSlblockMaxEntries
            ? 1
            : (subnodes.size() + kSlblockMaxEntries - 1) / kSlblockMaxEntries + 1;
    if (data_count + sub_count > kStoreMaxBlocks - state.blocks.size())
        return make_error(ErrorKind::kUnsupported, "writer.store.metadata_budget", 0,
                          state.blocks.size() + data_count + sub_count,
                          "generated internal blocks exceed the writer capacity");

    uint64_t data_slot = kNoBlock;
    if (data_blocks.size() == 1) {
        if (data_blocks[0] >= state.external_count) {
            return make_error(ErrorKind::kBadField, "writer.store.block_index", data_blocks[0],
                              state.external_count, "a node names a block the plan does not have");
        }
        data_slot = data_blocks[0];
    } else if (data_blocks.size() > 1) {
        if (data_blocks.size() > kXblockMaxChildren * kXblockMaxChildren)
            return make_error(ErrorKind::kUnsupported, "writer.store.xxblock_capacity", 0,
                              data_blocks.size());
        uint64_t lcb_total = 0;
        for (uint64_t index : data_blocks) {
            if (index >= state.external_count) {
                return make_error(ErrorKind::kBadField, "writer.store.data_tree", index,
                                  state.blocks.size(),
                                  "a data tree names a block that is not a data block");
            }
            lcb_total += state.blocks[index].cb;
            if (lcb_total > UINT32_MAX)
                return make_error(ErrorKind::kUnsupported, "writer.store.lcb_total", 0, lcb_total);
        }
        std::vector<uint64_t> children_bids;
        for (size_t first = 0; first < data_blocks.size(); first += kXblockMaxChildren) {
            const size_t count = std::min<size_t>(kXblockMaxChildren, data_blocks.size() - first);
            std::vector<uint64_t> bids;
            uint64_t child_total = 0;
            for (size_t at = first; at < first + count; ++at) {
                const auto index = data_blocks[at];
                bids.push_back(state.blocks[index].bid);
                child_total += state.blocks[index].cb;
                ++state.blocks[index].references; // [MS-PST] 2.2.2.7.7.3.1: XBLOCK rgbid reference.
            }
            const auto child = state.append(xblock_bytes(bids, child_total), true);
            if (data_blocks.size() <= kXblockMaxChildren) {
                data_slot = child;
            } else {
                children_bids.push_back(state.blocks[child].bid);
                ++state.blocks[child]
                      .references; // [MS-PST] 2.2.2.8.3.2.2: XXBLOCK rgbid references XBLOCK.
            }
        }
        if (!children_bids.empty())
            data_slot = state.append(xblock_bytes(children_bids, lcb_total, 2), true);
    }

    uint64_t sub_slot = kNoBlock;
    if (!subnodes.empty()) {
        std::vector<SlEntrySpec> entries;
        entries.reserve(subnodes.size());
        for (size_t index = 0; index < subnodes.size(); ++index) {
            SlEntrySpec entry;
            entry.nid = subnodes[index].nid;
            entry.bid_data = children[index].first == kNoBlock
                                 ? 0
                                 : state.blocks[static_cast<size_t>(children[index].first)].bid;
            entry.bid_sub = children[index].second == kNoBlock
                                ? 0
                                : state.blocks[static_cast<size_t>(children[index].second)].bid;
            entries.push_back(entry);
        }
        std::sort(entries.begin(), entries.end(),
                  [](const SlEntrySpec& a, const SlEntrySpec& b) { return a.nid < b.nid; });
        for (size_t at = 1; at < entries.size(); ++at)
            if (entries[at - 1].nid == entries[at].nid)
                return make_error(ErrorKind::kBadField, "writer.store.duplicate_subnode", 0,
                                  entries[at].nid);
        if (entries.size() <= kSlblockMaxEntries) {
            sub_slot = state.append(slblock_bytes(entries), true);
        } else {
            const size_t count = (entries.size() + kSlblockMaxEntries - 1) / kSlblockMaxEntries;
            std::vector<uint8_t> bytes(kSubnodeHeaderSize + count * kSiEntrySize, 0);
            bytes[0] = kSubnodeBlockType;
            bytes[1] = 1; // [MS-PST] 2.2.2.8.3.3.2.2: SIBLOCK cLevel MUST be 1.
            put_u16(bytes, 2, static_cast<uint16_t>(count));
            for (size_t first = 0, slot = 0; first < entries.size();
                 first += kSlblockMaxEntries, ++slot) {
                const size_t end = std::min<size_t>(entries.size(), first + kSlblockMaxEntries);
                std::vector<SlEntrySpec> part(entries.begin() + first, entries.begin() + end);
                const auto child = state.append(slblock_bytes(part), true);
                put_u64(bytes, kSubnodeHeaderSize + slot * kSiEntrySize, part.front().nid);
                put_u64(bytes, kSubnodeHeaderSize + slot * kSiEntrySize + 8,
                        state.blocks[child].bid);
                // [MS-PST] 2.2.2.8.3.3.2.1 bid points to this SLBLOCK; retain its allocation
                // while the SIENTRY owns it (reference lifetime in 2.2.2.7.7.3.1).
                ++state.blocks[child].references;
            }
            sub_slot = state.append(std::move(bytes), true);
        }
        // The SLENTRY bidData and bidSub references [MS-PST] 2.2.2.7.7.3.1 counts are exactly the
        // ones each child added for the slots it returned; counting them again here would give
        // every subnode block a cRef one too high.
    }

    if (data_slot != kNoBlock) {
        ++state.blocks[data_slot].references;
    }
    if (sub_slot != kNoBlock) {
        ++state.blocks[sub_slot].references;
    }
    return std::make_pair(data_slot, sub_slot);
}

// --- BTree levels ---------------------------------------------------------------------------

// One BTree page before it has an offset or a BID: a leaf page names a run of the sorted entries,
// an index page names the pages of the level below it so their offsets can be filled in once known.
struct PageSpec {
    uint8_t ptype = 0;
    uint8_t c_level = 0;
    uint8_t cb_ent = 0;
    uint8_t c_ent_max = 0;
    uint64_t first_key =
        0; // [MS-PST] 2.2.2.7.7.2: an index entry's btkey is the first key of its child
    uint64_t entry_start = 0;
    uint64_t entry_count = 0;
    std::vector<uint64_t> children;
    uint64_t ib = 0;
    uint64_t bid = 0;
};

// Leaf pages first, then a level of index pages over them, repeating until one page is left
// ([MS-PST] 2.2.2.7.7.1 / 2.2.2.7.7.2). The keys have to arrive sorted.
template <class Key>
Result<std::vector<std::vector<PageSpec>>> build_levels(uint8_t ptype, uint8_t cb_ent,
                                                        uint64_t key_count, Key key) {
    if (key_count == 0) {
        return make_error(ErrorKind::kBadField, "writer.store.btree_empty", key_count, 0,
                          "a BTree with no entries has no root page");
    }
    const uint8_t leaf_max = static_cast<uint8_t>(ndb::bt_entries_bytes(kProfile) / cb_ent);
    const uint8_t index_max =
        static_cast<uint8_t>(ndb::bt_entries_bytes(kProfile) / ndb::kBtEntrySize);
    std::vector<PageSpec> leaves;
    for (uint64_t start = 0; start < key_count; start += leaf_max) {
        const uint64_t count = std::min<uint64_t>(leaf_max, key_count - start);
        PageSpec page;
        page.ptype = ptype;
        page.c_level = 0;
        page.cb_ent = cb_ent;
        page.c_ent_max = leaf_max;
        page.first_key = key(start);
        page.entry_start = start;
        page.entry_count = count;
        leaves.push_back(std::move(page));
    }
    std::vector<std::vector<PageSpec>> levels;
    levels.push_back(std::move(leaves));
    while (levels.back().size() > 1) {
        const std::vector<PageSpec>& below = levels.back();
        std::vector<PageSpec> above;
        for (uint64_t start = 0; start < below.size(); start += index_max) {
            const uint64_t count = std::min<uint64_t>(index_max, below.size() - start);
            PageSpec page;
            page.ptype = ptype;
            page.c_level = static_cast<uint8_t>(below.front().c_level + 1);
            page.cb_ent = ndb::kBtEntrySize;
            page.c_ent_max = index_max;
            page.first_key = below[start].first_key;
            for (uint64_t index = 0; index < count; ++index) {
                page.children.push_back(start + index);
            }
            above.push_back(std::move(page));
        }
        levels.push_back(std::move(above));
    }
    return levels;
}

// --- the fixed pages inside the data section -------------------------------------------------

// [MS-PST] 2.2.2.7.2: the first AMap sits at 0x4400 and every later one 253,952 bytes after it.
// [MS-PST] 2.2.2.7.3: the first PMap sits at 0x4600, one PMap covers 2,031,616 bytes, and one PMap
// appears for every eight AMaps (8 * 253,952 = 2,031,616), so the next PMap is 2,031,616 bytes
// after the first, which is immediately after the first AMap of the eight it maps. Both are
// "allocated out of the data section", so no data block or BTree page may land on them.
struct ReservedRange {
    uint64_t ib = 0;
    uint64_t cb = 0;
    uint8_t ptype = 0;
    uint64_t first_amap = 0;
};

// [MS-PST] 1.3.2.7/8 and 2.2.2.1/7.5.1/7.6.1: initial maps have 128 bytes,
// external maps have 496; FMap bytes index AMaps, FPMap bits index PMaps.
constexpr uint64_t kPmapAmapCount = 8; // [MS-PST] 2.2.2.7.3: 2,031,616 / 253,952.
constexpr uint64_t kInitialFmapAmaps = ndb::kDeprecatedMapBytes;
constexpr uint64_t kExternalFmapAmaps = ndb::page_data_bytes(kProfile);
constexpr uint64_t kInitialFpmapAmaps = ndb::kDeprecatedMapBytes * 8 * kPmapAmapCount;
constexpr uint64_t kExternalFpmapAmaps = ndb::page_data_bytes(kProfile) * 8 * kPmapAmapCount;

std::vector<ReservedRange> reserved_pages(uint64_t regions) {
    const uint64_t amap_interval = ndb::amap_interval(kProfile);
    const uint64_t page_size = ndb::kPstPageSize;
    std::vector<ReservedRange> ranges;
    for (uint64_t region = 0; region < regions; ++region) {
        const uint64_t amap_ib = ndb::kPstAmapFirstOffset + region * amap_interval;
        ranges.push_back(ReservedRange{amap_ib, page_size, ndb::kPageTypeAMap, region});
        uint64_t next = amap_ib + page_size;
        if (region % kPmapAmapCount == 0) {
            ranges.push_back(ReservedRange{next, page_size, ndb::kPageTypePMap, region});
            next += page_size;
        }
        // Placement after this region's AMap/PMap is inferred from one sample,
        // not in MS-PST or libpff notes: SCANPST 16.0.20430.20032 requires
        // FMap at 0x1F04800 + n*125960192, FPMap first at 0x7C004800.
        // See M6 research/outlook-root-open-failure.md. Map preservation itself
        // is mandatory in [MS-PST] 2.2.2.7.5/6 and 2.6.1.1.2.
        if (region >= kInitialFmapAmaps && (region - kInitialFmapAmaps) % kExternalFmapAmaps == 0) {
            ranges.push_back(ReservedRange{next, page_size, ndb::kPageTypeFMap, region});
            next += page_size;
        }
        if (region >= kInitialFpmapAmaps &&
            (region - kInitialFpmapAmaps) % kExternalFpmapAmaps == 0) {
            ranges.push_back(ReservedRange{next, page_size, ndb::kPageTypeFPMap, region});
        }
    }
    return ranges;
}

// The first offset at or after `cursor` where `span` bytes do not overlap a fixed page.
uint64_t take_range(const std::vector<ReservedRange>& reserved, uint64_t cursor, uint64_t span) {
    uint64_t offset = cursor;
    auto next = std::lower_bound(
        reserved.begin(), reserved.end(), offset,
        [](const ReservedRange& range, uint64_t at) { return range.ib + range.cb <= at; });
    while (next != reserved.end() && next->ib < offset + span) {
        offset = next->ib + next->cb;
        ++next;
    }
    return offset;
}

} // namespace

Result<StoreImage> write_store_to(const StoreBlockSource& source,
                                  const std::vector<StoreNode>& nodes,
                                  const std::vector<uint32_t>& rgnid,
                                  util::RandomAccessFile& output,
                                  std::shared_ptr<util::Workspace> workspace) {
    if (output.size() != 0)
        return make_error(ErrorKind::kBadField, "writer.store.output_not_empty", 0, output.size());
    if (rgnid.size() != ndb::kRgnidCount) {
        return make_error(ErrorKind::kBadField, "HEADER.rgnid", rgnid.size(), ndb::kRgnidCount,
                          "the plan has to supply every NID_TYPE counter");
    }

    // The caller's data blocks first, in the order it listed them, then the jump tables and subnode
    // lists the emitter has to add. [MS-PST] 2.2.2.1 gives each the next BID in steps of 4.
    BlockState state(workspace);
    // Explicit aggregate metadata capacities, independent of the per-record graph budget.
    if (source.count() > kStoreMaxBlocks || nodes.size() > kStoreMaxNodes)
        return make_error(ErrorKind::kUnsupported, "writer.store.metadata_budget", 0,
                          source.count());
    for (uint64_t index = 0; index < source.count(); ++index) {
        auto size = source.block_size(index);
        if (!size.ok())
            return size.error();
        if (size.value() > ndb::kPstBlockMaxCb)
            return make_error(ErrorKind::kBadField, "writer.store.block_size", index, size.value());
        state.external(index, size.value());
        if (!state.blocks.status().ok())
            return state.blocks.status().error();
    }
    state.external_count = state.blocks.size();
    std::vector<std::pair<uint64_t, uint64_t>> node_slots;
    node_slots.reserve(nodes.size());
    for (const StoreNode& node : nodes) {
        Result<std::pair<uint64_t, uint64_t>> slots =
            emit_tree(state, node.data_blocks, node.subnodes);
        if (!state.blocks.status().ok())
            return state.blocks.status().error();
        if (!slots.ok()) {
            return slots.error();
        }
        node_slots.push_back(slots.value());
    }
    for (size_t slot = 0; slot < state.blocks.size(); ++slot) {
        BlockRecord& block = state.blocks[slot];
        if (!state.blocks.status().ok())
            return state.blocks.status().error();
        if (block.references == 0 || block.references >= UINT16_MAX)
            return make_error(ErrorKind::kBadField, "writer.store.c_ref", slot, block.references);
        block.c_ref = static_cast<uint16_t>(1 + block.references);
    }

    // The BBT is keyed by BID and the NBT by NID ([MS-PST] 2.2.2.7.7.3 / 2.2.2.7.7.4), and a leaf
    // page holds its keys in ascending order, so both entry lists are sorted before they are cut
    // into pages.
    std::vector<uint64_t> nbt_order(nodes.size());
    for (uint64_t index = 0; index < nbt_order.size(); ++index) {
        nbt_order[static_cast<size_t>(index)] = index;
    }
    std::sort(nbt_order.begin(), nbt_order.end(), [&](uint64_t left, uint64_t right) {
        return nodes[static_cast<size_t>(left)].nid < nodes[static_cast<size_t>(right)].nid;
    });
    std::vector<uint64_t> nbt_keys;
    nbt_keys.reserve(nodes.size());
    for (uint64_t index : nbt_order) {
        if (!nbt_keys.empty() && nbt_keys.back() == nodes[index].nid)
            return make_error(ErrorKind::kBadField, "writer.store.duplicate_nid", 0,
                              nodes[index].nid);
        nbt_keys.push_back(nodes[static_cast<size_t>(index)].nid);
    }

    Result<std::vector<std::vector<PageSpec>>> bbt =
        build_levels(ndb::kPageTypeBBT, ndb::kBbtEntrySize, state.blocks.size(),
                     [&](uint64_t index) { return state.blocks[static_cast<size_t>(index)].bid; });
    if (!state.blocks.status().ok())
        return state.blocks.status().error();
    if (!bbt.ok()) {
        return bbt.error();
    }
    Result<std::vector<std::vector<PageSpec>>> nbt =
        build_levels(ndb::kPageTypeNBT, ndb::kNbtEntrySize, nbt_keys.size(),
                     [&](uint64_t index) { return nbt_keys[static_cast<size_t>(index)]; });
    if (!nbt.ok()) {
        return nbt.error();
    }

    // Page order: the BBT index pages top-down, then the NBT index pages, then the NBT leaves, then
    // the BBT leaves. BTree pages sit on 512-byte boundaries so the PMap, which counts 512-byte
    // pages
    // ([MS-PST] 2.2.2.7.3), can describe them.
    std::vector<std::vector<PageSpec>> bbt_levels = bbt.take();
    std::vector<std::vector<PageSpec>> nbt_levels = nbt.take();
    std::vector<PageSpec*> pages;
    for (size_t level = bbt_levels.size() - 1; level >= 1; --level) {
        for (PageSpec& page : bbt_levels[level]) {
            pages.push_back(&page);
        }
    }
    for (size_t level = nbt_levels.size() - 1; level >= 1; --level) {
        for (PageSpec& page : nbt_levels[level]) {
            pages.push_back(&page);
        }
    }
    for (PageSpec& page : nbt_levels[0]) {
        pages.push_back(&page);
    }
    for (PageSpec& page : bbt_levels[0]) {
        pages.push_back(&page);
    }

    // [MS-PST] 2.6.1.1.2: a PST grows in whole AMap regions, and [MS-PST] 2.2.2.7.2 puts an AMap
    // page at the start of each one. Those pages take space out of the data section they map, so
    // the layout has to be repeated until the regions it needs are the regions it reserved.
    const uint64_t data_start =
        ndb::kPstAmapFirstOffset +
        2 * ndb::kPstPageSize; // 0x4800: after the first AMap page and the first PMap page
    const uint64_t amap_interval = ndb::amap_interval(kProfile);
    uint64_t regions = 1;
    for (uint64_t attempt = 0; attempt < 64; ++attempt) {
        const std::vector<ReservedRange> reserved = reserved_pages(regions);
        uint64_t cursor = data_start;
        for (size_t slot = 0; slot < state.blocks.size(); ++slot) {
            auto& block = state.blocks[slot];
            if (!state.blocks.status().ok())
                return state.blocks.status().error();
            block.ib = take_range(reserved, cursor, block.footprint());
            cursor = block.ib + block.footprint();
        }
        const uint64_t page_alignment = ndb::kPstPageSize - 1;
        cursor = (cursor + page_alignment) & ~page_alignment;
        for (PageSpec* page : pages) {
            page->ib = take_range(reserved, cursor, ndb::kPstPageSize);
            cursor = page->ib + ndb::kPstPageSize;
        }
        const uint64_t needed =
            (cursor - ndb::kPstAmapFirstOffset + amap_interval - 1) / amap_interval;
        if (needed <= regions) {
            break;
        }
        regions = needed;
        if (attempt + 1 == 64) {
            return make_error(ErrorKind::kUnsupported, "writer.store.amap_capacity", cursor, needed,
                              "the file never settled into its own AMap regions");
        }
    }
    const uint64_t file_size = ndb::kPstAmapFirstOffset + regions * amap_interval;

    // Page BIDs come from HEADER.bidNextP ([MS-PST] 2.2.2.7.1); allocation maps keep their own
    // ib instead and take none ([MS-PST] 2.2.2.7.1).
    uint64_t next_page_bid = 1;
    const uint64_t dlist_bid = next_page_bid++;
    for (PageSpec* page : pages) {
        page->bid = next_page_bid++;
    }
    const uint64_t bid_next_p = next_page_bid;
    const uint64_t bbt_root_ib = bbt_levels.back()[0].ib;
    const uint64_t nbt_root_ib = nbt_levels.back()[0].ib;
    const uint64_t bbt_root_bid = bbt_levels.back()[0].bid;
    const uint64_t nbt_root_bid = nbt_levels.back()[0].bid;

    // [MS-PST] 2.2.2.1: bidNextB is the BID the next allocated block will take.
    const uint64_t bid_next_b = block_bid(state.blocks.size(), false);

    // The AMap marks one bit per 64-byte allocation unit of the data section that starts at its own
    // offset ([MS-PST] 2.2.2.7.2), including its own page. The bit order is the one the reader
    // measures on a real file (ndb::AMapBitOrder::kMostSignificantFirst); [MS-PST] never states it.
    std::vector<std::vector<uint8_t>> amap_bits(
        static_cast<size_t>(regions), std::vector<uint8_t>(ndb::page_data_bytes(kProfile), 0));
    const uint64_t granularity = ndb::block_granularity(kProfile);
    auto mark_units = [&](uint64_t ib, uint64_t span) {
        const uint64_t first_unit = ib / granularity;
        for (uint64_t unit = first_unit; unit < first_unit + span / granularity; ++unit) {
            const uint64_t region = (unit * granularity - ndb::kPstAmapFirstOffset) / amap_interval;
            const uint64_t bit = unit - ndb::amap_first_unit(kProfile, ndb::kPstAmapFirstOffset +
                                                                           region * amap_interval);
            std::vector<uint8_t>& bits = amap_bits[static_cast<size_t>(region)];
            bits[static_cast<size_t>(bit / 8)] |= static_cast<uint8_t>(0x80u >> (bit % 8));
        }
    };
    const auto fixed_pages = reserved_pages(regions);
    for (const auto& page : fixed_pages)
        mark_units(page.ib, page.cb);
    for (size_t slot = 0; slot < state.blocks.size(); ++slot) {
        const auto& block = state.blocks[slot];
        if (!state.blocks.status().ok())
            return state.blocks.status().error();
        mark_units(block.ib, block.footprint());
    }
    for (PageSpec* page : pages) {
        mark_units(page->ib, ndb::kPstPageSize);
    }
    uint64_t amap_bits_set = 0;
    for (const std::vector<uint8_t>& bits : amap_bits) {
        for (const uint8_t byte : bits) {
            for (uint64_t bit = 0; bit < 8; ++bit) {
                if ((byte & (1u << bit)) != 0) {
                    ++amap_bits_set;
                }
            }
        }
    }
    // [MS-PST] 2.2.2.5: cbAMapFree is the free space of all AMaps combined; cbPMapFree MUST be 0
    // for a new PST, which is what an all-ones PMap says ([MS-PST] 2.2.2.7.3: a 0 bit is an
    // available page).
    const uint64_t cb_amap_free =
        (regions * ndb::amap_units(kProfile) - amap_bits_set) * granularity;

    StoreImage image;
    // Explicit zero writes back the entire advertised EOF without relying on filesystem-specific
    // extension semantics. All subsequent writes use block/page-sized scratch buffers.
    std::vector<uint8_t> zeros(1024 * 1024, 0);
    for (uint64_t at = 0; at < file_size;) {
        const auto count = static_cast<size_t>(std::min<uint64_t>(zeros.size(), file_size - at));
        auto status = util::write_all(output, at, ByteView(zeros.data(), count));
        if (!status.ok())
            return status.error();
        at += count;
    }
    auto write = [&](uint64_t at, const std::vector<uint8_t>& bytes) {
        return util::write_all(output, at, ByteView(bytes.data(), bytes.size()));
    };

    const std::vector<uint8_t> dlist = dlist_page(ndb::kPstDlistOffset, dlist_bid);
    auto written = write(ndb::kPstDlistOffset, dlist);
    if (!written.ok())
        return written.error();
    for (const auto& page : fixed_pages) {
        std::vector<uint8_t> bits(ndb::page_data_bytes(kProfile), 0xFF);
        if (page.ptype == ndb::kPageTypeAMap) {
            bits = amap_bits[static_cast<size_t>(page.first_amap)];
        } else if (page.ptype == ndb::kPageTypeFMap) {
            // [MS-PST] 2.2.2.7.5.1: each byte is the longest contiguous free
            // AMap run, capped to one byte. Nonexistent regions offer no space.
            std::fill(bits.begin(), bits.end(), 0);
            for (size_t index = 0; index < bits.size() && page.first_amap + index < regions;
                 ++index) {
                uint64_t run = 0, longest = 0;
                for (const auto byte : amap_bits[static_cast<size_t>(page.first_amap + index)]) {
                    for (unsigned bit = 0; bit < 8; ++bit) {
                        run = (byte & (0x80u >> bit)) != 0 ? 0 : run + 1;
                        longest = std::max(longest, run);
                    }
                }
                bits[index] = static_cast<uint8_t>(std::min<uint64_t>(longest, UINT8_MAX));
            }
        }
        // PMaps advertise no free pages (cbPMapFree=0); FPMap bits agree.
        written = write(page.ib, map_page(page.ptype, page.ib, bits));
        if (!written.ok())
            return written.error();
    }

    if (!workspace)
        image.blocks.reserve(state.blocks.size());
    for (size_t slot = 0; slot < state.blocks.size(); ++slot) {
        const auto& block = state.blocks[slot];
        if (!state.blocks.status().ok())
            return state.blocks.status().error();
        std::vector<uint8_t> out(static_cast<size_t>(block.footprint()), 0);
        if (block.internal()) {
            const auto& bytes = state.internal_bytes[static_cast<size_t>(block.source_index)];
            std::copy(bytes.begin(), bytes.end(), out.begin());
        } else {
            auto read = source.read_block(block.source_index, out.data(), block.cb);
            if (!read.ok())
                return read.error();
        }
        const uint64_t trailer_at = block.footprint() - ndb::block_trailer_size(kProfile);
        put_u16(out, trailer_at + ndb::kBlockTrailerCbOffset, block.cb);
        put_u16(out, trailer_at + ndb::kBlockTrailerWSigOffset,
                util::compute_sig(block.ib, block.bid));
        put_u32(out, trailer_at + ndb::kBlockTrailerCrcOffset,
                util::crc32(ByteView(out.data(), block.cb, block.ib)));
        put_u64(out, trailer_at + ndb::kBlockTrailerBidOffset, block.bid);
        written = write(block.ib, out);
        if (!written.ok())
            return written.error();
        if (!workspace)
            image.blocks.push_back(WrittenBlock{block.bid, block.ib, block.cb, block.c_ref});
    }

    // Every page: rgentries, then the footer, then the pageTrailer. A leaf entry's key is the BID
    // of a block for the BBT and the NID of a node for the NBT; an index entry's btkey is the first
    // key of the child page it names ([MS-PST] 2.2.2.7.7.2 / 2.2.2.7.7.3 / 2.2.2.7.7.4).
    for (PageSpec* page : pages) {
        const std::vector<std::vector<PageSpec>>& levels =
            page->ptype == ndb::kPageTypeBBT ? bbt_levels : nbt_levels;
        std::vector<uint8_t> entries;
        if (page->c_level == 0) {
            for (uint64_t index = page->entry_start; index < page->entry_start + page->entry_count;
                 ++index) {
                const uint64_t at = entries.size();
                entries.resize(at + page->cb_ent);
                if (page->ptype == ndb::kPageTypeBBT) {
                    const BlockRecord& block = state.blocks[static_cast<size_t>(index)];
                    if (!state.blocks.status().ok())
                        return state.blocks.status().error();
                    put_u64(entries, at + ndb::kBbtEntryBidOffset, block.bid);
                    put_u64(entries, at + ndb::kBbtEntryIbOffset, block.ib);
                    put_u16(entries, at + ndb::kBbtEntryCbOffset, block.cb);
                    put_u16(entries, at + ndb::kBbtEntryCRefOffset, block.c_ref);
                    // [MS-PST] 2.2.2.7.7.3 dwPadding MUST be zero, and the page's own padding after
                    // the footer stays zero.
                } else {
                    const size_t node_index =
                        static_cast<size_t>(nbt_order[static_cast<size_t>(index)]);
                    const StoreNode& node = nodes[node_index];
                    const std::pair<uint64_t, uint64_t>& slots = node_slots[node_index];
                    put_u64(entries, at + ndb::kNbtEntryNidOffset, node.nid);
                    put_u64(entries, at + ndb::kNbtEntryBidDataOffset,
                            slots.first == kNoBlock
                                ? 0
                                : state.blocks[static_cast<size_t>(slots.first)].bid);
                    put_u64(entries, at + ndb::kNbtEntryBidSubOffset,
                            slots.second == kNoBlock
                                ? 0
                                : state.blocks[static_cast<size_t>(slots.second)].bid);
                    put_u32(entries, at + ndb::kNbtEntryNidParentOffset, node.nid_parent);
                }
            }
        } else {
            for (uint64_t child : page->children) {
                const PageSpec& below =
                    levels[static_cast<size_t>(page->c_level) - 1][static_cast<size_t>(child)];
                const uint64_t at = entries.size();
                entries.resize(at + ndb::kBtEntrySize);
                put_u64(entries, at + ndb::kBtEntryKeyOffset, below.first_key);
                put_u64(entries, at + ndb::kBtEntryBidOffset, below.bid);
                put_u64(entries, at + ndb::kBtEntryIbOffset, below.ib);
            }
        }
        const std::vector<uint8_t> bytes = bt_page(page->ptype, page->ib, page->bid, page->c_level,
                                                   page->cb_ent, page->c_ent_max, entries);
        written = write(page->ib, bytes);
        if (!written.ok())
            return written.error();
    }

    // The HEADER ([MS-PST] 2.2.2.1) and the ROOT inside it (2.2.2.5). The two CRCs come last so
    // each covers the bytes it is computed over.
    std::vector<uint8_t> header(ndb::kHeaderSize, 0);
    put_u32(header, ndb::kDwMagicOffset, ndb::kDwMagicValue);
    header[ndb::kWMagicClientOffset] = ndb::kWMagicClientS;
    header[ndb::kWMagicClientOffset + 1] = ndb::kWMagicClientM;
    put_u16(header, ndb::kWVerOffset, ndb::kMinUnicodeVer);
    put_u16(header, ndb::kWVerClientOffset,
            19); // [MS-PST] 2.2.2.1: a new PST SHOULD initialize wVerClient to 19
    header[ndb::kBPlatformCreateOffset] = ndb::kPlatformId;
    header[ndb::kBPlatformAccessOffset] = ndb::kPlatformId;
    put_u64(header, 0x018, 0); // bidUnused
    put_u64(header, ndb::kBidNextPOffset, bid_next_p);
    put_u32(header, 0x028,
            1); // dwUnique: a monotonically increasing value; this file has one header
    for (uint64_t index = 0; index < ndb::kRgnidCount; ++index) {
        put_u32(header, ndb::kRgnidOffset + index * 4, rgnid[static_cast<size_t>(index)]);
    }
    put_u64(header, 0x0AC, 0); // qwUnused MUST be zero
    const uint64_t root_at = ndb::kRootOffset;
    put_u64(header, root_at + ndb::kRootIbFileEofOffset, file_size);
    put_u64(header, root_at + ndb::kRootIbAMapLastOffset,
            ndb::kPstAmapFirstOffset + (regions - 1) * amap_interval);
    put_u64(header, root_at + ndb::kRootCbAMapFreeOffset, cb_amap_free);
    put_u64(header, root_at + ndb::kRootCbPMapFreeOffset, 0);
    put_u64(header, root_at + ndb::kRootNbtBrefOffset, nbt_root_bid);
    put_u64(header, root_at + ndb::kRootNbtBrefOffset + 8, nbt_root_ib);
    put_u64(header, root_at + ndb::kRootBbtBrefOffset, bbt_root_bid);
    put_u64(header, root_at + ndb::kRootBbtBrefOffset + 8, bbt_root_ib);
    header[root_at + ndb::kRootFAMapValidOffset] = ndb::kFAMapValid2;
    put_u32(header, ndb::kDwAlignOffset, 0);
    std::fill(header.begin() + static_cast<long>(ndb::kRgbFmOffset),
              header.begin() + static_cast<long>(ndb::kRgbFmOffset + ndb::kDeprecatedMapBytes),
              static_cast<uint8_t>(0xFF));
    std::fill(header.begin() + static_cast<long>(ndb::kRgbFpOffset),
              header.begin() + static_cast<long>(ndb::kRgbFpOffset + ndb::kDeprecatedMapBytes),
              static_cast<uint8_t>(0xFF));
    header[ndb::kBSentinelOffset] = ndb::kBSentinelValue;
    header[ndb::kBCryptMethodOffset] = ndb::kCryptMethodNone;
    put_u64(header, ndb::kBidNextBOffset, bid_next_b);
    put_u32(header, ndb::kDwCRCPartialOffset,
            util::crc32(ByteView(header.data() + ndb::kCrcPartialStart, ndb::kCrcPartialLength,
                                 ndb::kCrcPartialStart)));
    put_u32(header, ndb::kDwCRCFullOffset,
            util::crc32(ByteView(header.data() + ndb::kCrcFullStart, ndb::kCrcFullLength,
                                 ndb::kCrcFullStart)));
    if (!state.blocks.status().ok())
        return state.blocks.status().error();
    written = write(0, header);
    if (!written.ok())
        return written.error();
    written = output.flush();
    if (!written.ok())
        return written.error();

    image.bid_next_b = bid_next_b;
    image.bid_next_p = bid_next_p;
    image.bbt_root_ib = bbt_root_ib;
    image.nbt_root_ib = nbt_root_ib;
    image.amap_bits_set = amap_bits_set;
    image.cb_amap_free = cb_amap_free;
    image.amap_regions = regions;
    image.file_bytes = file_size;
    return image;
}

Result<StoreImage> write_store(const StorePlan& plan) {
    class Blocks final : public StoreBlockSource {
      public:
        explicit Blocks(const StorePlan& plan) : plan_(plan) {}
        uint64_t count() const override { return plan_.blocks.size(); }
        Result<uint16_t> block_size(uint64_t index) const override {
            const auto size = plan_.blocks[index].size();
            if (size > ndb::kPstBlockMaxCb)
                return make_error(ErrorKind::kBadField, "writer.store.block_size", index, size);
            return static_cast<uint16_t>(size);
        }
        util::Status read_block(uint64_t index, uint8_t* data, size_t size) const override {
            const auto& block = plan_.blocks[index];
            if (block.source) {
                if (!block.bytes.empty() || size != block.source_size)
                    return make_error(ErrorKind::kBadField, "writer.store.source", index, size);
                return block.source->read_at(block.source_offset, data, size);
            }
            const auto& bytes = plan_.blocks[index].bytes;
            if (size != bytes.size())
                return make_error(ErrorKind::kBadField, "writer.store.block_size", index, size);
            if (size)
                std::memcpy(data, bytes.data(), size);
            return {};
        }

      private:
        const StorePlan& plan_;
    } source(plan);
    class Buffer final : public util::RandomAccessFile {
      public:
        std::vector<uint8_t> bytes;
        uint64_t size() const override { return bytes.size(); }
        util::Status read_at(uint64_t at, uint8_t* data, size_t count) const override {
            if (at > bytes.size() || count > bytes.size() - at)
                return make_error(ErrorKind::kTruncated, "writer.buffer.read", at, count);
            if (count)
                std::memcpy(data, bytes.data() + at, count);
            return {};
        }
        Result<size_t> write_some(uint64_t at, ByteView input) override {
            if (at > SIZE_MAX || input.size() > SIZE_MAX - at)
                return make_error(ErrorKind::kBadField, "writer.buffer.size", at, input.size());
            bytes.resize(std::max(bytes.size(), static_cast<size_t>(at) + input.size()));
            if (!input.empty())
                std::memcpy(bytes.data() + at, input.data(), input.size());
            return input.size();
        }
        util::Status resize(uint64_t size) override {
            if (size > SIZE_MAX)
                return make_error(ErrorKind::kBadField, "writer.buffer.size", 0, size);
            bytes.resize(static_cast<size_t>(size));
            return {};
        }
        util::Status flush() override { return {}; }
    } output;
    auto result = write_store_to(source, plan.nodes, plan.rgnid, output);
    if (!result.ok())
        return result.error();
    auto image = result.take();
    image.bytes = std::move(output.bytes);
    return image;
}

} // namespace ost2pst::writer
