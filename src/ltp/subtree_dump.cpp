// The subnode dump is a diagnostic, not a second reader: every structure it opens comes through the same
// seams the production walks use (ltp::open_node, ltp::read_pc, ltp::read_tc, ltp::walk_tc_row_index,
// ltp::walk_subnode_entries, ltp::read_data_tree), so what it prints is what the reader actually sees.
#include "ost2pst/ltp/subtree_dump.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "ost2pst/ltp/bth.h"
#include "ost2pst/ltp/data_tree.h"
#include "ost2pst/ltp/hn_block.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/ltp_read.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/ltp/node_open.h"
#include "ost2pst/ltp/node_value.h"
#include "ost2pst/ltp/pc.h"
#include "ost2pst/ltp/tc.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ltp {

using util::ByteView;
using util::Result;
using util::Status;

namespace {

constexpr uint64_t kMaxDumpNodes = 100000;

struct Ctx {
    BlockSource &blocks;
    ndb::FileProfile profile;
    ndb::FailureLog &failures;
    const SubtreeDumpOptions &options;
    LtpHeapCounters heap;
    DataTreeCounters trees;
    SubnodeStats subnodes;
    std::map<std::string, uint64_t> errors;
    bool capped = false;
    bool row_ids_capped = false;
};

void note(DumpNode &node, const std::string &text) {
    if (!node.note.empty()) {
        node.note += "; ";
    }
    node.note += text;
}

// Reads one node's Property Context and resolves every record's value through the seam that knows both the
// node's heap and its subnodes ([MS-PST] 2.3.3.2), which is the only way to see which local NIDs the node's
// own values name.
void read_property_context(DumpNode &node, NodeHeap &heap_node, Ctx &ctx) {
    std::vector<PcRecord> records;
    BthStats bth;
    const Status walked = read_pc(heap_node.header, ctx.profile, *heap_node.source,
                                  [&](const PcRecord &record) {
                                      ++node.pc_records;
                                      if (records.size() < ctx.options.max_pc_records) {
                                          records.push_back(record);
                                      } else {
                                          ctx.capped = true;
                                      }
                                      return true;
                                  },
                                  bth, ctx.failures);
    if (!walked.ok()) {
        note(node, "Property Context did not read: " + util::format_error(walked.error()));
        return;
    }

    NodeValueSource values(*heap_node.source, node.bid_sub, ctx.profile, ctx.blocks, ctx.subnodes,
                           ctx.trees, ctx.failures);
    for (const PcRecord &record : records) {
        DumpPcValue item;
        item.prop_id = record.prop_id;
        item.prop_type = record.prop_type;
        item.hnid = record.value_hnid;
        item.tag = (static_cast<uint32_t>(record.prop_id) << kTcTagPropIdShift) | record.prop_type;
        item.inline_value = record.value_inline;
        item.absent = record.value_absent;
        item.in_heap = record.value_in_heap;
        item.in_subnode = record.value_in_subnode;
        if (item.inline_value) {
            item.answered = true;
            item.bytes = record.value.size();
        } else if (item.absent) {
            item.answered = true;
        } else {
            const Result<ByteView> value = values.value(record.value_hnid);
            if (value.ok()) {
                item.answered = true;
                item.bytes = value.value().size();
            }
        }
        node.pc.push_back(item);
    }
    if (values.subnode_misses != 0) {
        note(node, "Property Context values naming a subnode this node does not hold: " +
                       std::to_string(values.subnode_misses));
    }
}

// Reads one node's Table Context and answers where its Row Matrix lives. [MS-PST] 2.3.4.1 puts the HNID in
// TCINFO.hnidRows, [MS-PST] 2.3.3.2 says a hidType other than NID_TYPE_HID names a subnode, and
// [MS-PST] 2.3.4.4 says a subnode's data is the rows spread over blocks.
void read_table_context(DumpNode &node, NodeHeap &heap_node, Ctx &ctx) {
    const Result<TcTable> table = read_tc(heap_node.header, *heap_node.source);
    if (!table.ok()) {
        note(node, "Table Context did not read: " + util::format_error(table.error()));
        return;
    }
    const TcTable &info = table.value();
    node.tc.read = true;
    node.tc.columns = info.info.c_cols;
    node.tc.hnid_rows = info.info.hnid_rows;
    node.tc.row_size = tc_row_size(info.info);
    node.tc.column_list = info.columns;
    if (node.tc.hnid_rows != 0) {
        // [MS-PST] 2.3.3.2: hidType decides heap or subnode; hnidRows 0 says there is no matrix at all.
        node.tc.matrix_in_heap = hid_type(node.tc.hnid_rows) == kHidTypeHid;
        node.tc.matrix_in_subnode = !node.tc.matrix_in_heap;
    }

    BthStats bth;
    const Status walked = walk_tc_row_index(info, ctx.profile, *heap_node.source,
                                            [&](const TcRowId &row) {
                                                ++node.tc.rows;
                                                if (node.tc.row_ids.size() < ctx.options.max_row_ids) {
                                                    node.tc.row_ids.push_back(row.row_id);
                                                } else {
                                                    ctx.row_ids_capped = true;
                                                }
                                                return true;
                                            },
                                            bth, ctx.failures);
    if (!walked.ok()) {
        note(node, "RowIndex BTH did not walk: " + util::format_error(walked.error()));
    }
    node.tc.matrix_bytes = node.tc.rows * node.tc.row_size;

    if (node.tc.matrix_in_heap) {
        const Result<ByteView> matrix = heap_node.source->heap(node.tc.hnid_rows);
        if (matrix.ok()) {
            node.tc.matrix_stored_bytes = matrix.value().size();
        } else {
            note(node, "the Row Matrix allocation did not answer: " + util::format_error(matrix.error()));
        }
        return;
    }
    if (!node.tc.matrix_in_subnode) {
        return;
    }
    const Result<SubnodeRef> sub =
        find_subnode(node.bid_sub, node.tc.hnid_rows, ctx.blocks, ctx.subnodes, ctx.failures);
    if (!sub.ok()) {
        note(node, "the Row Matrix subnode was not found: " + util::format_error(sub.error()));
        return;
    }
    const Result<std::vector<HnFragment>> tree =
        read_data_tree(ctx.blocks, sub.value().bid_data, ctx.profile, ctx.trees, ctx.failures);
    if (!tree.ok()) {
        note(node, "the Row Matrix data tree did not resolve: " + util::format_error(tree.error()));
        return;
    }
    node.tc.matrix_blocks = tree.value().size();
    for (const HnFragment &fragment : tree.value()) {
        node.tc.matrix_stored_bytes += fragment.block.heap_node().size();
    }
}

// Opens one node's data block and reads whatever its bClientSig says it is. A block that cannot be read or
// is not a heap node is described by its kind, because a dump that stops at the first odd block cannot say
// what the rest of the node holds.
void describe_node(DumpNode &node, Ctx &ctx) {
    node.data_internal = ndb::bid_is_internal(node.bid_data);
    node.sub_internal = ndb::bid_is_internal(node.bid_sub);
    if (node.bid_data == 0) {
        note(node, "NBTENTRY.bidData is zero: this node carries no data block");
        return;
    }

    NodeHeap heap_node;
    node.opened = open_node(ctx.blocks, ctx.profile, node.nid, node.bid_data, heap_node, ctx.heap,
                            ctx.trees, ctx.errors, nullptr, ctx.failures);
    node.cb_data = heap_node.cb;
    node.ib_data = heap_node.ib;
    if (node.opened == NodeOpen::kUnreadable) {
        note(node, "the data block could not be read");
        return;
    }
    if (node.opened == NodeOpen::kDataTreeFailed) {
        note(node, "the data tree this node's bidData roots does not resolve");
        return;
    }
    if (heap_node.multi_block) {
        node.data_blocks = heap_node.fragments.size();
        for (const HnFragment &fragment : heap_node.fragments) {
            node.data_heap_bytes += fragment.block.heap_node().size();
        }
    } else if (node.opened == NodeOpen::kOk) {
        node.data_blocks = 1;
        node.data_heap_bytes = heap_node.block.heap_node().size();
    }
    if (node.opened == NodeOpen::kNotHeapNode) {
        note(node, "the data block carries no HNHDR");
        return;
    }
    node.client_sig = heap_node.header.b_client_sig;
    node.heap_bytes = heap_node.block.heap_node().size();
    node.allocations = heap_node.page_map.c_alloc;
    if (!heap_node.page_map_ok || heap_node.source == nullptr) {
        note(node, "HNPAGEMAP did not decode, so no allocation of this node can be read");
        return;
    }
    if (heap_node.header.b_client_sig == kClientSigPc) {
        read_property_context(node, heap_node, ctx);
    } else if (heap_node.header.b_client_sig == kClientSigTc) {
        read_table_context(node, heap_node, ctx);
    } else {
        note(node, std::string("bClientSig ") + client_sig_name(heap_node.header.b_client_sig) +
                       ", which is neither a Property Context nor a Table Context");
    }
}

} // namespace

Result<SubtreeDump> dump_subtree(const NidMap &nodes, BlockSource &blocks, ndb::FileProfile profile,
                                uint64_t nid, const SubtreeDumpOptions &options) {
    const Result<NodeRef> ref = nodes.node(nid);
    if (!ref.ok()) {
        return ref.error();
    }

    ndb::FailureLog failures(20);
    SubtreeDumpOptions limits = options;
    if (limits.max_nodes > kMaxDumpNodes) {
        limits.max_nodes = kMaxDumpNodes;
    }
    Ctx ctx{blocks, profile, failures, limits};

    SubtreeDump dump;
    // The BFS below appends while a reference into the same vector is live, so the capacity is fixed first.
    dump.subnodes.reserve(static_cast<size_t>(limits.max_nodes));
    dump.root.nid = ref.value().nid;
    dump.root.local_nid = subnode_nid_key(ref.value().nid);
    dump.root.nid_type = nid_type(ref.value().nid);
    dump.root.bid_data = ref.value().bid_data;
    dump.root.bid_sub = ref.value().bid_sub;
    describe_node(dump.root, ctx);

    // [MS-PST] 2.2.2.8.3.3: a node's subnodes hang off its bidSub, and each SLENTRY carries that subnode's
    // own bidData and bidSub, so the same seam describes them all the way down.
    // The frontier is subnodes[index - 1], so the last entry of the list has to be reached at
    // index == size: with a strict `<` here the node appended last never has its own list walked.
    for (size_t index = 0; index <= dump.subnodes.size() || index == 0; ++index) {
        DumpNode &parent = index == 0 ? dump.root : dump.subnodes[index - 1];
        if (parent.bid_sub == 0) {
            continue;
        }
        if (parent.depth >= limits.max_depth) {
            ctx.capped = true;
            note(parent, "subnode list not enumerated: the depth cap is reached");
            continue;
        }
        const Result<std::vector<SubnodeRef>> entries =
            walk_subnode_entries(parent.bid_sub, ctx.blocks, ctx.subnodes, ctx.failures);
        if (!entries.ok()) {
            note(parent, "subnode BTree: " + util::format_error(entries.error()));
            continue;
        }
        for (const SubnodeRef &entry : entries.value()) {
            if (dump.subnodes.size() >= limits.max_nodes) {
                ctx.capped = true;
                note(parent, "subnode list cut at the node cap");
                break;
            }
            DumpNode child;
            child.nid = entry.nid;
            child.local_nid = subnode_nid_key(entry.nid);
            child.nid_type = nid_type(child.local_nid);
            child.bid_data = entry.bid_data;
            child.bid_sub = entry.bid_sub;
            child.depth = parent.depth + 1;
            child.parent_local_nid = parent.local_nid;
            child.has_parent = true;
            describe_node(child, ctx);
            dump.subnodes.push_back(std::move(child));
        }
    }

    std::sort(dump.subnodes.begin(), dump.subnodes.end(),
              [](const DumpNode &a, const DumpNode &b) {
                  if (a.depth != b.depth) {
                      return a.depth < b.depth;
                  }
                  return a.local_nid < b.local_nid;
              });
    dump.capped = ctx.capped;
    dump.row_ids_capped = ctx.row_ids_capped;
    dump.stats = ctx.subnodes;
    dump.trees = ctx.trees;
    dump.heap = ctx.heap;
    dump.failure_total = failures.total();
    dump.failures = failures.failures();
    return dump;
}

} // namespace ost2pst::ltp
