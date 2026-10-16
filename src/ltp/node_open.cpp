// Opening one node's data block, shared by every walk that needs a node's heap: the LTP census, the
// folder tree, the node dump, and the Messaging layer's inventory. Extracted from
// src/ltp/ltp_read.cpp so a second layer can open a node without re-implementing how a block is
// classified.
#include "ost2pst/ltp/node_open.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "ost2pst/ltp/block_heap.h"
#include "ost2pst/ltp/data_tree.h"
#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/hn_block.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/ltp_read.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/ndb/bbt_index.h"
#include "ost2pst/ndb/block_reader.h"
#include "ost2pst/ndb/profile.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ltp {

using util::ByteView;
using util::DataError;
using util::Result;

namespace {

void tally(std::map<std::string, uint64_t>& tallies, const DataError& error) {
    tallies[error.field] += 1;
}

void tally(std::map<std::string, uint64_t>& tallies, const std::string& key) {
    tallies[key] += 1;
}

} // namespace

Result<BlockBytes> FileBlockSource::block(uint64_t bid) {
    Result<ndb::BlockData> data =
        ndb::read_block(file_, profile_, index_, bid, counters_, failures_);
    if (!data.ok()) {
        return data.error();
    }
    held_ = data.take();
    return BlockBytes{ByteView(held_.data.data(), held_.data.size(), held_.ib), held_.internal,
                      held_.compressed};
}

NodeOpen open_node(BlockSource& blocks, ndb::FileProfile profile, uint64_t nid, uint64_t bid,
                   NodeHeap& node, LtpHeapCounters& counters, DataTreeCounters& data_trees,
                   std::map<std::string, uint64_t>& errors, LtpFindingTally* findings,
                   ndb::FailureLog& failures, util::ByteBudget* workspace) {
    node = NodeHeap{};
    node.bid = bid;
    // The error tally counts a field; the finding says which node it happened to and which of the
    // three classes it belongs to. A caller that re-opens a node the census already classified (the
    // folder walk, the node dump) passes nullptr so one node is never counted twice.
    auto record = [&](LtpFindingKind kind, const std::string& field, const std::string& detail) {
        if (findings != nullptr) {
            findings->record(kind, nid, bid, field, detail);
        }
    };
    node.profile = profile;
    Result<BlockBytes> raw = blocks.block(bid);
    if (!raw.ok()) {
        ++counters.blocks_failed;
        tally(errors, raw.error());
        record(LtpFindingKind::kDecodeFailure, raw.error().field, raw.error().detail);
        return NodeOpen::kUnreadable;
    }
    ++counters.blocks_read;
    node.ib = raw.value().view.base();
    node.cb = raw.value().view.size();
    if (workspace) {
        auto reserved =
            workspace->reserve(8 * (node.cb + sizeof(NodeHeap)), "node.workspace", node.ib);
        if (!reserved.ok()) {
            tally(errors, reserved.error());
            failures.add(reserved.error());
            return NodeOpen::kUnreadable;
        }
    }
    node.bytes.assign(raw.value().view.data(), raw.value().view.data() + raw.value().view.size());
    if (node.bytes.size() > counters.max_block_bytes) {
        counters.max_block_bytes = node.bytes.size();
    }

    const ByteView view(node.bytes.data(), node.bytes.size(), node.ib);
    Result<HnBlock> payload = read_hn_block(view, raw.value().compressed);
    if (!payload.ok()) {
        ++counters.blocks_failed;
        tally(errors, payload.error());
        record(LtpFindingKind::kDecodeFailure, payload.error().field, payload.error().detail);
        return NodeOpen::kUnreadable;
    }
    node.block = payload.take();
    if (node.block.form == BlockForm::kCompressed) {
        ++counters.compressed;
    } else {
        ++counters.raw;
    }

    const ByteView heap_node = node.block.heap_node();
    if (workspace && heap_node.size() > node.cb) {
        auto reserved =
            workspace->reserve(8 * (heap_node.size() - node.cb), "node.workspace", node.ib);
        if (!reserved.ok()) {
            tally(errors, reserved.error());
            failures.add(reserved.error());
            return NodeOpen::kUnreadable;
        }
    }
    if (heap_node.size() > counters.max_heap_bytes) {
        counters.max_heap_bytes = heap_node.size();
    }

    if (!raw.value().internal) {
        // [MS-PST] 2.2.2.8.3.1: an external block is the node's data, and a heap node is what it
        // normally holds. The two other things an NBTENTRY.bidData names are a basic queue node and
        // a plain array of NIDs ([MS-PST] 2.4.8.3); neither is a jump table whose decode happened
        // to fail.
        Result<HnHeader> header = decode_hn_header(heap_node);
        if (!header.ok()) {
            ++counters.heap_nodes_rejected;
            tally(errors, header.error());
            record(classify_missing_heap_node(nid), header.error().field, header.error().detail);
            return NodeOpen::kNotHeapNode;
        }
        ++counters.heap_nodes_ok;
        node.header = header.value();
        ++counters.client_sigs[node.header.b_client_sig];

        Result<HnPageMap> map = decode_hn_page_map(heap_node, node.header.ib_hnpm);
        if (!map.ok()) {
            tally(errors, map.error());
            record(LtpFindingKind::kDecodeFailure, map.error().field, map.error().detail);
            return NodeOpen::kOk; // the caller reports the context as failed; the heap node itself
                                  // decoded
        }
        node.page_map = map.take();
        node.page_map_ok = true;
        counters.allocations += node.page_map.c_alloc;
        if (node.page_map.c_alloc > counters.max_allocations) {
            counters.max_allocations = node.page_map.c_alloc;
        }
        node.source =
            std::make_unique<BlockHeapSource>(heap_node, node.page_map, profile, uint16_t{0});
        return NodeOpen::kOk;
    }

    // [MS-PST] 2.2.2.2 bit B / 2.2.2.8.3.2 / 3.6: the node's data is spread over the blocks this
    // internal block names. A data tree that does not add up is a finding about this node, so the
    // node is reported as failed instead of read out of whatever the root block's own bytes look
    // like.
    Result<std::vector<HnFragment>> tree =
        read_data_tree(blocks, bid, profile, data_trees, failures, workspace);
    if (!tree.ok()) {
        // The tree already tallied and logged its own finding; counting it here too would report
        // one broken data tree twice.
        return NodeOpen::kDataTreeFailed;
    }
    std::vector<HnFragment> fragments = tree.take();
    if (fragments.empty()) {
        ++counters.heap_nodes_rejected;
        tally(errors, "XBLOCK.cEnt");
        record(LtpFindingKind::kDecodeFailure, "XBLOCK.cEnt", "the jump table names no data block");
        return NodeOpen::kDataTreeFailed;
    }
    Result<HnHeader> first = decode_hn_header(fragments[0].block.heap_node());
    if (!first.ok()) {
        ++counters.heap_nodes_rejected;
        tally(errors, first.error());
        record(classify_missing_heap_node(nid), first.error().field, first.error().detail);
        return NodeOpen::kNotHeapNode;
    }

    ++counters.heap_nodes_ok;
    ++counters.multi_block_nodes;
    counters.multi_block_fragments += fragments.size();
    if (fragments.size() > counters.max_fragments) {
        counters.max_fragments = fragments.size();
    }
    node.header = first.value();
    ++counters.client_sigs[node.header.b_client_sig];
    node.multi_block = true;

    // [MS-PST] 2.3.1.6.2: every block of a multi-block HN carries its own header and its own
    // HNPAGEMAP at its own ibHnpm, so each one answers for its own allocations. A block whose map
    // does not decode is counted and left out; its heap items then report as unreachable rather
    // than ending the node.
    for (size_t index = 0; index < fragments.size(); ++index) {
        const ByteView part = fragments[index].block.heap_node();
        Result<uint16_t> ib_hnpm = part.u16(kHnIbHnpmOffset);
        if (!ib_hnpm.ok()) {
            ++counters.fragment_page_maps_rejected;
            tally(errors, ib_hnpm.error());
            record(LtpFindingKind::kDecodeFailure, ib_hnpm.error().field, ib_hnpm.error().detail);
            continue;
        }
        if (ib_hnpm.value() < hn_block_header_size(index)) {
            ++counters.fragment_page_maps_rejected;
            tally(errors, "HNHDR.ibHnpm");
            record(LtpFindingKind::kDecodeFailure, "HNHDR.ibHnpm",
                   "the page map starts inside the header this block carries");
            continue;
        }
        Result<HnPageMap> map = decode_hn_page_map(part, ib_hnpm.value());
        if (!map.ok()) {
            ++counters.fragment_page_maps_rejected;
            tally(errors, map.error());
            record(LtpFindingKind::kDecodeFailure, map.error().field, map.error().detail);
            continue;
        }
        fragments[index].page_map = map.take();
        fragments[index].page_map_ok = true;
        counters.allocations += fragments[index].page_map.c_alloc;
        if (fragments[index].page_map.c_alloc > counters.max_allocations) {
            counters.max_allocations = fragments[index].page_map.c_alloc;
        }
    }

    node.fragments = std::move(fragments);
    node.page_map = node.fragments[0].page_map;
    node.page_map_ok = node.fragments[0].page_map_ok;
    node.source = std::make_unique<NodeFragmentHeapSource>(node.fragments, profile);
    return NodeOpen::kOk;
}

} // namespace ost2pst::ltp
