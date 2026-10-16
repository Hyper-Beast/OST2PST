#include "ost2pst/ltp/nid_map.h"

#include <algorithm>
#include <string>

#include "internal/take.h"
#include "ost2pst/ltp/hn_block.h"

namespace ost2pst::ltp {

using util::ByteView;
using util::DataError;
using util::ErrorKind;
using util::make_error;
using util::Result;

namespace {

// [MS-PST] 2.2.2.8.3.3.1.2 / 2.2.2.8.3.3.2.2: the header both subnode block kinds share.
constexpr uint64_t kSubnodeHeaderSize = 8;
constexpr uint64_t kSlEntrySize = 24; // [MS-PST] 2.2.2.8.3.3.1.1: nid bidData bidSub
constexpr uint64_t kSiEntrySize = 16; // [MS-PST] 2.2.2.8.3.3.2.1: nid bid

} // namespace

Result<SubnodeBlockHeader> decode_subnode_block_header(ByteView block) {
    if (!block.in_range(0, static_cast<size_t>(kSubnodeHeaderSize))) {
        return make_error(ErrorKind::kTruncated, "SUBNODE", block.base(), block.size(),
                          "a subnode block opens with bType cLevel cEnt dwPadding");
    }
    SubnodeBlockHeader parsed;
    DataError failure;
    if (!take(block.u8(0), parsed.b_type, "SUBNODE.btype", failure)) {
        return failure;
    }
    if (!take(block.u8(1), parsed.c_level, "SUBNODE.cLevel", failure)) {
        return failure;
    }
    if (!take(block.u16(2), parsed.c_ent, "SUBNODE.cEnt", failure)) {
        return failure;
    }
    uint32_t padding = 0;
    if (!take(block.u32(4), padding, "SUBNODE.dwPadding", failure)) {
        return failure;
    }

    // [MS-PST] 2.2.2.8.3.3.1.2 / 2.2.2.8.3.3.2.2: btype MUST be 0x02 for either kind, and cLevel is the
    // only thing that says which kind this is (0 SLBLOCK, 1 SIBLOCK).
    if (parsed.b_type != 0x02) {
        return make_error(ErrorKind::kBadSignature, "SUBNODE.btype", block.base(), parsed.b_type,
                          "a subnode block carries btype 0x02, this block carries a data block");
    }
    if (parsed.c_level > 1) {
        return make_error(ErrorKind::kBadField, "SUBNODE.cLevel", block.base() + 1, parsed.c_level,
                          "cLevel is 0 for an SLBLOCK and 1 for a SIBLOCK");
    }
    // [MS-PST] 2.2.2.8.3.3.1.2: an SLBLOCK with no entries MUST have been deleted.
    if (parsed.c_ent == 0) {
        return make_error(ErrorKind::kBadField, "SUBNODE.cEnt", block.base() + 2, 0,
                          "a subnode block with no entries should not exist");
    }
    if (padding != 0) {
        return make_error(ErrorKind::kBadField, "SUBNODE.dwPadding", block.base() + 4, padding,
                          "the spec says this padding MUST be zero");
    }
    parsed.entries_ib = kSubnodeHeaderSize;
    parsed.entry_size = parsed.c_level == 0 ? kSlEntrySize : kSiEntrySize;
    return parsed;
}

Result<SlEntry> decode_sl_entry(ByteView view) {
    if (!view.in_range(0, static_cast<size_t>(kSlEntrySize))) {
        return make_error(ErrorKind::kTruncated, "SLENTRY", view.base(), view.size(),
                          "SLENTRY is nid bidData bidSub, 8 bytes each");
    }
    SlEntry parsed;
    DataError failure;
    if (!take(view.u64(0), parsed.nid, "SLENTRY.nid", failure)) {
        return failure;
    }
    if (!take(view.u64(8), parsed.bid_data, "SLENTRY.bidData", failure)) {
        return failure;
    }
    if (!take(view.u64(16), parsed.bid_sub, "SLENTRY.bidSub", failure)) {
        return failure;
    }
    parsed.offset = view.base();
    return parsed;
}

Result<SiEntry> decode_si_entry(ByteView view) {
    if (!view.in_range(0, static_cast<size_t>(kSiEntrySize))) {
        return make_error(ErrorKind::kTruncated, "SIENTRY", view.base(), view.size(),
                          "SIENTRY is nid bid, 8 bytes each");
    }
    SiEntry parsed;
    DataError failure;
    if (!take(view.u64(0), parsed.nid, "SIENTRY.nid", failure)) {
        return failure;
    }
    if (!take(view.u64(8), parsed.bid, "SIENTRY.bid", failure)) {
        return failure;
    }
    parsed.offset = view.base();
    return parsed;
}

namespace {

// The descent. `scanned` counts entries for this search only, so one node with a corrupt cEnt cannot
// spend the work cap of every search that comes after it.
Result<SubnodeRef> descend_subnode(uint64_t bid_sub, uint64_t wanted, uint64_t local_nid,
                                   BlockSource &source, SubnodeStats &stats, ndb::FailureLog &failures,
                                   uint64_t &scanned) {
    uint64_t bid = bid_sub;
    std::vector<uint64_t> visited;

    for (uint64_t depth = 0; depth <= kMaxSubnodeDepth; ++depth) {
        if (std::find(visited.begin(), visited.end(), bid) != visited.end()) {
            return make_error(ErrorKind::kBadField, "SUBNODE.bid", 0, bid,
                              "the subnode chain visits the same block twice");
        }
        visited.push_back(bid);

        Result<BlockBytes> raw = source.block(bid);
        if (!raw.ok()) {
            return raw.error();
        }
        ++stats.blocks_read;
        // [MS-PST] 2.2.2.8.3: SLBLOCK and SIBLOCK are Internal blocks, so a block a bidSub or SIENTRY.bid
        // names has to carry the internal bit ([MS-PST] 2.2.2.2 bit B). The contradiction is counted
        // whatever the block turns out to be; it is reported as a finding only once the block has parsed as
        // a subnode block, because a block that is not one is already reported by the header check below.
        const bool flagged_internal = raw.value().internal;
        if (!flagged_internal) {
            ++stats.blocks_not_internal;
        }
        // An OST compresses subnode blocks the same way it compresses data blocks, so the answer comes
        // from the same place here as it does for a data block: what the index says about the block.
        Result<HnBlock> block = read_hn_block(raw.value().view, raw.value().compressed);
        if (!block.ok()) {
            ++stats.blocks_bad;
            failures.add(block.error());
            return block.error();
        }
        if (block.value().form == BlockForm::kCompressed) {
            ++stats.blocks_compressed;
        } else {
            ++stats.blocks_raw;
        }
        Result<SubnodeBlockHeader> header = decode_subnode_block_header(block.value().bytes());
        if (!header.ok()) {
            ++stats.blocks_bad;
            failures.add(header.error());
            return header.error();
        }
        if (!flagged_internal) {
            failures.add(raw.value().view.base(), "SUBNODE.internal", 0,
                         "the BBT does not flag this subnode block Internal");
        }
        const SubnodeBlockHeader &info = header.value();
        const ByteView bytes = block.value().bytes();
        if (info.c_ent > stats.max_entries) {
            stats.max_entries = info.c_ent;
        }
        if (depth > stats.max_depth) {
            stats.max_depth = depth;
        }

        uint64_t next_bid = 0; // the SIBLOCK child whose key is closest to the target
        uint64_t next_key = 0;
        uint64_t first_bid = 0; // the smallest key, used when the target is below every key
        uint64_t first_key = 0;
        for (uint64_t i = 0; i < info.c_ent; ++i) {
            if (scanned >= kMaxSubnodeEntries) {
                stats.stopped_early = true;
                break;
            }
            Result<ByteView> view = bytes.sub(info.entries_ib + i * info.entry_size,
                                             static_cast<size_t>(info.entry_size));
            if (!view.ok()) {
                ++stats.entries_skipped;
                failures.add(view.error());
                continue;
            }
            if (info.c_level == 0) {
                Result<SlEntry> entry = decode_sl_entry(view.value());
                if (!entry.ok()) {
                    ++stats.entries_skipped;
                    failures.add(entry.error());
                    continue;
                }
                ++scanned;
                if (subnode_nid_key(entry.value().nid) == wanted) {
                    SubnodeRef found;
                    found.nid = entry.value().nid;
                    found.bid_data = entry.value().bid_data;
                    found.bid_sub = entry.value().bid_sub;
                    found.block_bid = bid;
                    found.entry_offset = entry.value().offset;
                    found.depth = depth;
                    ++stats.found;
                    return found;
                }
                continue;
            }

            // [MS-PST] 2.2.2.8.3.3.2.1: SIENTRY.nid is the key NID of the next-level child block, and a
            // BTree array is in key order, so the child that can hold the target is the last entry whose
            // key does not exceed it.
            Result<SiEntry> entry = decode_si_entry(view.value());
            if (!entry.ok()) {
                ++stats.entries_skipped;
                failures.add(entry.error());
                continue;
            }
            ++scanned;
            const uint64_t key = subnode_nid_key(entry.value().nid);
            if (key <= wanted && (next_bid == 0 || key >= next_key)) {
                next_bid = entry.value().bid;
                next_key = key;
            }
            if (first_bid == 0 || key < first_key) {
                first_bid = entry.value().bid;
                first_key = key;
            }
        }

        if (info.c_level != 0) {
            if (next_bid == 0) {
                next_bid = first_bid;
            }
            if (next_bid == 0) {
                ++stats.not_found;
                return make_error(ErrorKind::kBadField, "SIENTRY.bid", bytes.base(), 0,
                                  "the SIBLOCK names no child block");
            }
            bid = next_bid;
            ++stats.si_hops;
            continue;
        }

        ++stats.not_found;
        return make_error(ErrorKind::kUnsupported, "SLENTRY.nid", bytes.base(), local_nid,
                          "no SLENTRY in this node's subnode BTree names that NID");
    }

    stats.stopped_early = true;
    return make_error(ErrorKind::kBadField, "SUBNODE.depth", 0, bid,
                      "the subnode chain is deeper than any real node's");
}

} // namespace

Result<SubnodeRef> find_subnode(uint64_t bid_sub, uint64_t local_nid, BlockSource &source,
                                SubnodeStats &stats, ndb::FailureLog &failures) {
    // [MS-PST] 2.2.2.7.7.4: bidSub zero means the node has no subnode block at all.
    if (bid_sub == 0) {
        return make_error(ErrorKind::kBadField, "NBTENTRY.bidSub", 0, 0,
                          "this node has no subnode block to search");
    }
    ++stats.searches;
    uint64_t scanned = 0;
    Result<SubnodeRef> outcome = descend_subnode(bid_sub, subnode_nid_key(local_nid), local_nid, source,
                                                 stats, failures, scanned);
    stats.entries_scanned += scanned;
    return outcome;
}

namespace {

// One block of one node's subnode BTree still to visit, with how many SIBLOCK hops deep it is.
struct SubnodeBranch {
    uint64_t bid = 0;
    uint64_t depth = 0;
};

} // namespace

Result<std::vector<SubnodeRef>> walk_subnode_entries(uint64_t bid_sub, BlockSource &source,
                                                    SubnodeStats &stats, ndb::FailureLog &failures) {
    // [MS-PST] 2.2.2.7.7.4: bidSub zero means the node has no subnode block at all.
    if (bid_sub == 0) {
        return make_error(ErrorKind::kBadField, "NBTENTRY.bidSub", 0, 0,
                          "this node has no subnode block to enumerate");
    }
    ++stats.searches;
    std::vector<SubnodeRef> found;
    std::vector<uint64_t> visited;
    std::vector<SubnodeBranch> pending{SubnodeBranch{bid_sub, 0}};
    uint64_t scanned = 0;

    while (!pending.empty()) {
        const SubnodeBranch branch = pending.back();
        pending.pop_back();
        if (std::find(visited.begin(), visited.end(), branch.bid) != visited.end()) {
            // A block reached twice is a cycle in this node's BTree, not a second copy of the list.
            failures.add(branch.bid, "SUBNODE.bid", branch.bid,
                         "the subnode BTree visits the same block twice");
            stats.stopped_early = true;
            continue;
        }
        visited.push_back(branch.bid);
        if (branch.depth > kMaxSubnodeDepth) {
            // [MS-PST] 2.2.2.8.3.3.2: SIBLOCKs chain SLBLOCKs, so a chain deeper than the cap is not a
            // real node's list. The entries under it are missing from the answer, which stopped_early says.
            failures.add(branch.bid, "SUBNODE.depth", branch.depth,
                         "the subnode BTree is deeper than any real node's");
            stats.stopped_early = true;
            continue;
        }

        Result<BlockBytes> raw = source.block(branch.bid);
        if (!raw.ok()) {
            ++stats.blocks_bad;
            if (branch.bid == bid_sub) {
                return raw.error(); // nothing about this node can be said without its first block
            }
            stats.stopped_early = true;
            failures.add(raw.error());
            continue;
        }
        ++stats.blocks_read;
        // Same rule as descend_subnode: [MS-PST] 2.2.2.8.3 says SLBLOCK and SIBLOCK are Internal blocks,
        // so the BBT MUST flag a block a bidSub or SIENTRY.bid names ([MS-PST] 2.2.2.2 bit B).
        const bool flagged_internal = raw.value().internal;
        if (!flagged_internal) {
            ++stats.blocks_not_internal;
        }
        Result<HnBlock> block = read_hn_block(raw.value().view, raw.value().compressed);
        if (!block.ok()) {
            ++stats.blocks_bad;
            if (branch.bid == bid_sub) {
                return block.error(); // the node's own subnode block is unreadable
            }
            stats.stopped_early = true;
            failures.add(block.error());
            continue;
        }
        if (block.value().form == BlockForm::kCompressed) {
            ++stats.blocks_compressed;
        } else {
            ++stats.blocks_raw;
        }
        Result<SubnodeBlockHeader> header = decode_subnode_block_header(block.value().bytes());
        if (!header.ok()) {
            ++stats.blocks_bad;
            if (branch.bid == bid_sub) {
                return header.error(); // the node's own subnode block is not a subnode block
            }
            stats.stopped_early = true;
            failures.add(header.error());
            continue;
        }
        if (!flagged_internal) {
            failures.add(raw.value().view.base(), "SUBNODE.internal", 0,
                         "the BBT does not flag this subnode block Internal");
        }
        const SubnodeBlockHeader &info = header.value();
        const ByteView bytes = block.value().bytes();
        if (info.c_ent > stats.max_entries) {
            stats.max_entries = info.c_ent;
        }
        if (branch.depth > stats.max_depth) {
            stats.max_depth = branch.depth;
        }

        for (uint64_t i = 0; i < info.c_ent; ++i) {
            if (scanned >= kMaxSubnodeEntries) {
                stats.stopped_early = true;
                break;
            }
            Result<ByteView> view = bytes.sub(info.entries_ib + i * info.entry_size,
                                             static_cast<size_t>(info.entry_size));
            if (!view.ok()) {
                ++stats.entries_skipped;
                failures.add(view.error());
                continue;
            }
            if (info.c_level == 0) {
                Result<SlEntry> entry = decode_sl_entry(view.value());
                if (!entry.ok()) {
                    ++stats.entries_skipped;
                    failures.add(entry.error());
                    continue;
                }
                ++scanned;
                SubnodeRef ref;
                ref.nid = entry.value().nid;
                ref.bid_data = entry.value().bid_data;
                ref.bid_sub = entry.value().bid_sub;
                ref.block_bid = branch.bid;
                ref.entry_offset = entry.value().offset;
                ref.depth = branch.depth;
                found.push_back(ref);
                ++stats.found;
                continue;
            }

            // [MS-PST] 2.2.2.8.3.3.2.1: an enumeration follows every child, unlike the targeted descent,
            // which follows only the one child that could hold the wanted key.
            Result<SiEntry> entry = decode_si_entry(view.value());
            if (!entry.ok()) {
                ++stats.entries_skipped;
                failures.add(entry.error());
                continue;
            }
            ++scanned;
            if (entry.value().bid == 0) {
                ++stats.entries_skipped;
                failures.add(entry.value().offset, "SIENTRY.bid", 0, "the SIENTRY names no child block");
                continue;
            }
            pending.push_back(SubnodeBranch{entry.value().bid, branch.depth + 1});
            ++stats.si_hops;
        }
    }

    stats.entries_scanned += scanned;
    std::sort(found.begin(), found.end(), [](const SubnodeRef &a, const SubnodeRef &b) {
        return subnode_nid_key(a.nid) < subnode_nid_key(b.nid);
    });
    return found;
}

void merge_subnode_stats(SubnodeStats &into, const SubnodeStats &from) {
    into.searches += from.searches;
    into.found += from.found;
    into.not_found += from.not_found;
    into.blocks_read += from.blocks_read;
    into.blocks_compressed += from.blocks_compressed;
    into.blocks_raw += from.blocks_raw;
    into.blocks_bad += from.blocks_bad;
    into.blocks_not_internal += from.blocks_not_internal;
    into.entries_scanned += from.entries_scanned;
    into.entries_skipped += from.entries_skipped;
    into.si_hops += from.si_hops;
    if (from.max_depth > into.max_depth) {
        into.max_depth = from.max_depth;
    }
    if (from.max_entries > into.max_entries) {
        into.max_entries = from.max_entries;
    }
    into.stopped_early = into.stopped_early || from.stopped_early;
}

void NidMap::add(const ndb::NbtEntry &entry) {
    if (by_nid_.find(entry.nid) != by_nid_.end()) {
        ++duplicates_;
        return;
    }
    by_nid_.emplace(entry.nid, NodeRef{entry.nid, entry.bid_data, entry.bid_sub, entry.nid_parent});
    by_index_[nid_index(entry.nid)].push_back(entry.nid);
    if (entry.nid_parent != 0) {
        ++by_parent_[(static_cast<uint64_t>(entry.nid_parent) << 8) | nid_type(entry.nid)];
        ++parent_links_;
    }
    if (entry.bid_sub != 0) {
        ++with_subnode_;
    }
    if (entry.bid_data == 0) {
        ++missing_data_;
    }
}

Result<NodeRef> NidMap::node(uint64_t nid) const {
    const auto found = by_nid_.find(nid);
    if (found == by_nid_.end()) {
        return make_error(ErrorKind::kUnsupported, "NBTENTRY.nid", 0, nid,
                          "no NBT entry carries this NID");
    }
    return found->second;
}

Result<NodeRef> NidMap::sibling(uint64_t nid, uint32_t nid_type) const {
    // [MS-PST] 2.4.4.3: the PC and the three TCs of one Folder object are the same nidIndex under
    // different nidTypes, so a sibling is built, not looked up.
    return node(make_nid(nid_index(nid), nid_type));
}

uint64_t NidMap::children(uint32_t parent_nid, uint32_t nid_type) const {
    const auto found = by_parent_.find((static_cast<uint64_t>(parent_nid) << 8) | nid_type);
    return found == by_parent_.end() ? 0 : found->second;
}

std::vector<NodeRef> NidMap::group(uint64_t nid) const {
    std::vector<NodeRef> members;
    const auto found = by_index_.find(nid_index(nid));
    if (found == by_index_.end()) {
        return members;
    }
    members.reserve(found->second.size());
    for (uint64_t member : found->second) {
        members.push_back(by_nid_.at(member));
    }
    std::sort(members.begin(), members.end(),
              [](const NodeRef &a, const NodeRef &b) { return a.nid < b.nid; });
    return members;
}

std::vector<NodeRef> NidMap::entries() const {
    std::vector<NodeRef> all;
    all.reserve(by_nid_.size());
    for (const auto &item : by_nid_) {
        all.push_back(item.second);
    }
    std::sort(all.begin(), all.end(), [](const NodeRef &a, const NodeRef &b) { return a.nid < b.nid; });
    return all;
}

} // namespace ost2pst::ltp
