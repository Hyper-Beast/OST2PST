#include "ost2pst/ltp/data_tree.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <utility>

#include "ost2pst/ltp/hn_block.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ltp {

using util::ByteView;
using util::DataError;
using util::ErrorKind;
using util::make_error;
using util::Result;

namespace {

void tally(DataTreeCounters& counters, const DataError& error) {
    ++counters.errors[error.field];
}

// [MS-PST] 2.2.2.7.7.3.1 allows multiple rgbid slots to share a block. Only a reference
// to an active ancestor is a cycle; finished siblings contribute their bytes on every visit.
struct TreeWalk {
    BlockSource& blocks;
    ndb::FileProfile profile;
    DataTreeCounters& counters;
    ndb::FailureLog& failures;
    std::vector<HnFragment> fragments;
    std::unordered_set<uint64_t> active_bids;
    DataError last_error;
    bool has_error = false;
    const DataVisitor* visitor = nullptr;
    uint64_t external_count = 0;
    util::ByteBudget* workspace = nullptr;

    bool fail(DataError error) {
        tally(counters, error);
        failures.add(error);
        last_error = std::move(error);
        has_error = true;
        return false;
    }

    // `named_by_table` says the BID came out of a jump table rather than being the tree's root, so
    // `table_says_internal` is what that table's rgid entry claimed about it.
    bool descend(uint64_t bid, uint32_t table_depth, uint64_t& data_bytes, bool named_by_table,
                 bool table_says_internal) {
        if (table_depth > kDataTreeMaxTableLevels) {
            return fail(make_error(ErrorKind::kBadField, "XBLOCK.cLevel", 0, bid,
                                   "a data tree reaches its data blocks in two table levels"));
        }
        Result<BlockBytes> raw = blocks.block(bid);
        if (!raw.ok()) {
            ++counters.blocks_failed;
            return fail(raw.error());
        }
        ++counters.blocks_read;
        const ByteView view = raw.value().view;
        if (view.size() > counters.max_block_bytes) {
            counters.max_block_bytes = view.size();
        }
        // [MS-PST] 2.2.2.2 bit B is carried on both sides -- the rgid entry that names the block
        // and the BBTENTRY the block is indexed under -- and they have to agree. Measured on the
        // sample: 203,136 references from the four holder structures, 0 disagreements on bit B
        // (DEVELOPMENT.md).
        if (named_by_table && table_says_internal != raw.value().internal) {
            ++counters.index_flag_mismatches;
            return fail(make_error(ErrorKind::kBadField, "XBLOCK.rgid", view.base(), bid,
                                   std::string("the jump table calls this block ") +
                                       (table_says_internal ? "Internal" : "a data block") +
                                       ", but the BBTENTRY for it says the opposite"));
        }

        Result<HnBlock> payload = read_hn_block(view, raw.value().compressed);
        if (!payload.ok()) {
            ++counters.blocks_failed;
            return fail(payload.error());
        }
        HnBlock block = payload.take();
        if (block.form == BlockForm::kCompressed) {
            ++counters.compressed;
        } else {
            ++counters.raw;
        }
        if (block.bytes().size() > counters.max_heap_bytes) {
            counters.max_heap_bytes = block.bytes().size();
        }

        // [MS-PST] 2.2.2.8.3.1: an external block holds the data itself, which is where a data tree
        // ends.
        if (!raw.value().internal) {
            ++external_count;
            if (external_count > data_tree_max_blocks(profile)) {
                ++counters.capped;
                return fail(make_error(ErrorKind::kBadField, "XBLOCK.rgid", view.base(),
                                       external_count,
                                       "the tree exceeds the node's hidBlockIndex range"));
            }
            data_bytes = block.bytes().size();
            if (visitor) {
                auto accepted = (*visitor)(block.bytes());
                if (!accepted.ok())
                    return fail(accepted.error());
                return true;
            }
            if (workspace) {
                // Reserve construction copies, page maps and vector growth as well as payload.
                auto reserved = workspace->reserve(8 * (data_bytes + sizeof(HnFragment)),
                                                   "data_tree.workspace", view.base());
                if (!reserved.ok())
                    return fail(reserved.error());
            }
            HnFragment fragment;
            if (block.form == BlockForm::kRaw) {
                // A BlockSource reuses its buffer, so the bytes a raw view points at do not outlive
                // the next read. A compressed block already owns what it inflated to.
                fragment.owned.assign(block.raw_block.data(),
                                      block.raw_block.data() + block.raw_block.size());
                block.raw_block =
                    ByteView(fragment.owned.data(), fragment.owned.size(), block.raw_block.base());
            }
            fragment.block = std::move(block);
            data_bytes = fragment.block.bytes().size();
            fragments.push_back(std::move(fragment));
            if (fragments.size() > data_tree_max_blocks(profile)) {
                ++counters.capped;
                return fail(make_error(
                    ErrorKind::kBadField, "XBLOCK.rgid", view.base(), fragments.size(),
                    "the tree holds more data blocks than a node's hidBlockIndex can name"));
            }
            return true;
        }

        // [MS-PST] 2.2.2.2 bit B / 2.2.2.8.3: an internal block names other blocks instead of
        // holding data, and for a data tree the only shape it may take is a jump table. A jump
        // table that does not decode is a finding about this node; the block is never downgraded to
        // data because decoding it as a table happened to fail.
        Result<BlockJumpTable> jump = decode_block_jump_table(block.bytes());
        if (!jump.ok()) {
            ++counters.rejected_tables;
            return fail(jump.error());
        }
        const BlockJumpTable table = jump.value();
        ++counters.tables;
        if (table.c_level == kJumpTableLevelXxblock) {
            ++counters.xxblock_tables;
        }
        if (table.c_ent > counters.max_entries) {
            counters.max_entries = table.c_ent;
        }
        // [MS-PST] 2.2.2.8.3.2.1 / 2.2.2.8.3.2.2: an XBLOCK names data blocks and an XXBLOCK names
        // XBLOCKs, so an XXBLOCK is only ever the top of a data tree.
        if (table.c_level == kJumpTableLevelXxblock && table_depth != 0) {
            ++counters.child_flag_mismatches;
            return fail(make_error(
                ErrorKind::kBadField, "XBLOCK.cLevel", block.block_base + kJumpTableLevelOffset,
                table.c_level,
                "an XXBLOCK below the top of a data tree names a block that is not a data block"));
        }

        uint64_t sum = 0;
        for (uint64_t child : table.bids) {
            const bool child_internal = ndb::bid_is_internal(child);
            if (table.c_level == kJumpTableLevelXblock && child_internal) {
                ++counters.child_flag_mismatches;
                return fail(make_error(ErrorKind::kBadField, "XBLOCK.rgid", block.block_base, child,
                                       "an XBLOCK names an Internal block, but only a data block "
                                       "sits under an XBLOCK"));
            }
            if (table.c_level == kJumpTableLevelXxblock && !child_internal) {
                ++counters.child_flag_mismatches;
                return fail(make_error(ErrorKind::kBadField, "XBLOCK.rgid", block.block_base, child,
                                       "an XXBLOCK names a block that is not Internal, but only an "
                                       "XBLOCK sits under an XXBLOCK"));
            }
            if (!active_bids.insert(ndb::bid_lookup_key(child)).second) {
                ++counters.cycles;
                return fail(make_error(ErrorKind::kBadField, "XBLOCK.rgid", block.block_base, child,
                                       "the data tree references an active ancestor"));
            }
            uint64_t child_bytes = 0;
            if (!descend(child, table_depth + 1, child_bytes, true, child_internal)) {
                return false;
            }
            active_bids.erase(ndb::bid_lookup_key(child));
            sum += child_bytes;
        }

        // [MS-PST] 2.2.2.8.3.2.1 / 2.2.2.8.3.2.2: lcbTotal is the total bytes of the external data
        // under this table, so the blocks the table names have to add up to it. Measured on the
        // sample: 7,281 of 7,283 tables match the uncompressed lengths, and the 2 that do not each
        // name a block the BBT does not index.
        if (sum != static_cast<uint64_t>(table.lcb_total)) {
            ++counters.lcb_total_mismatches;
            return fail(make_error(ErrorKind::kBadField, "XBLOCK.lcbTotal",
                                   block.block_base + kJumpTableTotalOffset, table.lcb_total,
                                   "the data blocks under this jump table hold " +
                                       std::to_string(sum) + " bytes"));
        }
        data_bytes = sum;
        return true;
    }
};

} // namespace

Result<std::vector<HnFragment>> read_data_tree(BlockSource& blocks, uint64_t root_bid,
                                               ndb::FileProfile profile, DataTreeCounters& counters,
                                               ndb::FailureLog& failures,
                                               util::ByteBudget* workspace) {
    TreeWalk walk{blocks, profile, counters, failures};
    walk.workspace = workspace;
    walk.active_bids.insert(ndb::bid_lookup_key(root_bid));
    uint64_t total = 0;
    if (!walk.descend(root_bid, 0, total, false, false)) {
        ++counters.failed_trees;
        if (!walk.has_error) {
            return make_error(ErrorKind::kBadField, "XBLOCK.rgid", 0, root_bid,
                              "this node's data tree does not resolve");
        }
        return walk.last_error;
    }
    ++counters.trees;
    counters.data_blocks += walk.fragments.size();
    if (walk.fragments.size() > counters.max_blocks) {
        counters.max_blocks = walk.fragments.size();
    }
    return std::move(walk.fragments);
}

Result<uint64_t> stream_data_tree(BlockSource& blocks, uint64_t root_bid, ndb::FileProfile profile,
                                  DataTreeCounters& counters, ndb::FailureLog& failures,
                                  const DataVisitor& visitor) {
    if (!visitor)
        return make_error(ErrorKind::kBadField, "data_tree.visitor", 0, root_bid,
                          "streaming requires a payload consumer");
    TreeWalk walk{blocks, profile, counters, failures};
    walk.visitor = &visitor;
    walk.active_bids.insert(ndb::bid_lookup_key(root_bid));
    uint64_t total = 0;
    if (!walk.descend(root_bid, 0, total, false, false)) {
        ++counters.failed_trees;
        return walk.last_error;
    }
    ++counters.trees;
    counters.data_blocks += walk.external_count;
    counters.max_blocks = std::max(counters.max_blocks, walk.external_count);
    return total;
}

void merge_data_tree_counters(DataTreeCounters& into, const DataTreeCounters& from) {
    into.trees += from.trees;
    into.tables += from.tables;
    into.xxblock_tables += from.xxblock_tables;
    into.data_blocks += from.data_blocks;
    into.blocks_read += from.blocks_read;
    into.blocks_failed += from.blocks_failed;
    into.compressed += from.compressed;
    into.raw += from.raw;
    into.rejected_tables += from.rejected_tables;
    into.child_flag_mismatches += from.child_flag_mismatches;
    into.index_flag_mismatches += from.index_flag_mismatches;
    into.lcb_total_mismatches += from.lcb_total_mismatches;
    into.cycles += from.cycles;
    into.capped += from.capped;
    into.failed_trees += from.failed_trees;
    if (from.max_entries > into.max_entries) {
        into.max_entries = from.max_entries;
    }
    if (from.max_blocks > into.max_blocks) {
        into.max_blocks = from.max_blocks;
    }
    if (from.max_block_bytes > into.max_block_bytes) {
        into.max_block_bytes = from.max_block_bytes;
    }
    if (from.max_heap_bytes > into.max_heap_bytes) {
        into.max_heap_bytes = from.max_heap_bytes;
    }
    for (const auto& item : from.errors) {
        into.errors[item.first] += item.second;
    }
}

} // namespace ost2pst::ltp
