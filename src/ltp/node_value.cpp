#include "ost2pst/ltp/node_value.h"

#include <utility>

#include "ost2pst/ltp/data_tree.h"
#include "ost2pst/ltp/hn_block.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ndb/layout.h"

namespace ost2pst::ltp {

using util::ByteView;
using util::ErrorKind;
using util::make_error;
using util::Result;

Result<uint64_t> ValueSource::stream(uint32_t hnid, const DataVisitor& visitor) {
    if (!visitor)
        return make_error(ErrorKind::kBadField, "value.visitor", 0, hnid);
    auto obtained = value(hnid);
    if (!obtained.ok())
        return obtained.error();
    const auto size = obtained.value().size();
    auto accepted = visitor(obtained.value());
    if (!accepted.ok())
        return accepted.error();
    return size;
}

NodeValueSource::NodeValueSource(HeapSource& heap, uint64_t bid_sub, ndb::FileProfile profile,
                                 BlockSource& blocks, SubnodeStats& subnode_stats,
                                 DataTreeCounters& data_trees, ndb::FailureLog& failures)
    : heap_(heap), bid_sub_(bid_sub), profile_(profile), blocks_(blocks),
      subnode_stats_(subnode_stats), data_trees_(data_trees), failures_(failures) {}

Result<ByteView> NodeValueSource::value(uint32_t hnid) {
    // [MS-PST] 2.3.3.2: hidType NID_TYPE_HID is a heap item, any other hidType is a subnode NID.
    if (hid_type(hnid) == kHidTypeHid) {
        Result<ByteView> item = heap_.heap(hnid);
        if (!item.ok()) {
            return item.error();
        }
        ++heap_hits;
        return item.value();
    }

    held_.clear();
    auto obtained = stream(hnid, [&](ByteView part) -> util::Status {
        held_.insert(held_.end(), part.data(), part.data() + part.size());
        return {};
    });
    if (!obtained.ok())
        return obtained.error();
    return ByteView(held_.data(), held_.size(), 0);
}

Result<uint64_t> NodeValueSource::stream(uint32_t hnid, const DataVisitor& visitor) {
    if (!visitor)
        return make_error(ErrorKind::kBadField, "value.visitor", 0, hnid);
    if (hid_type(hnid) == kHidTypeHid) {
        auto obtained = heap_.heap(hnid);
        if (!obtained.ok())
            return obtained.error();
        ++heap_hits;
        const auto size = obtained.value().size();
        auto accepted = visitor(obtained.value());
        if (!accepted.ok())
            return accepted.error();
        return size;
    }
    if (bid_sub_ == 0) {
        return make_error(ErrorKind::kBadField, "NBTENTRY.bidSub", 0, 0,
                          "the HNID names a subnode, but the node has no bidSub to search");
    }
    Result<SubnodeRef> subnode = find_subnode(bid_sub_, hnid, blocks_, subnode_stats_, failures_);
    if (!subnode.ok()) {
        ++subnode_misses;
        return subnode.error();
    }
    ++subnode_hits;

    const uint64_t bid_data = subnode.value().bid_data;
    if (bid_data == 0) {
        return make_error(ErrorKind::kBadField, "SLENTRY.bidData", subnode.value().entry_offset, 0,
                          "the SLENTRY that holds this subnode names no data block");
    }
    // [MS-PST] 2.2.2.8.3.2 / 3.6: the value is the data the subnode's data tree stores. When the
    // internal bit is set the tree is a jump table over several data blocks, and the jump table's
    // own bytes are metadata about where the value is -- reading them as the value is what a
    // 7,325-block-wide class of SLENTRY.bidData in the sample looks like. The concatenation is the
    // value, in the order the tables name the blocks.
    return stream_data_tree(blocks_, bid_data, profile_, data_trees_, failures_, visitor);
}

} // namespace ost2pst::ltp
