#include "ost2pst/ltp/block_heap.h"

#include <string>
#include <utility>

#include "ost2pst/ltp/layout.h"

namespace ost2pst::ltp {

using util::ByteView;
using util::ErrorKind;
using util::make_error;
using util::Result;

BlockHeapSource::BlockHeapSource(ByteView block, HnPageMap page_map, ndb::FileProfile profile,
                                 uint16_t block_index)
    : block_(block), page_map_(std::move(page_map)), block_index_(block_index), profile_(profile) {}

Result<ByteView> BlockHeapSource::heap(uint32_t hid) {
    // [MS-PST] 2.3.1.1: hidBlockIndex says which data block holds the allocation.
    if (hid_block_index(hid, profile_) != block_index_) {
        ++cross_block_misses;
        return make_error(ErrorKind::kUnsupported, "HID.hidBlockIndex", block_.base(), hid,
                          "the heap item lives in data block " +
                              std::to_string(hid_block_index(hid, profile_)) +
                              ", not in the block this source reads");
    }
    return hn_heap_item(page_map_, block_, hid, profile_);
}

NodeFragmentHeapSource::NodeFragmentHeapSource(const std::vector<HnFragment> &fragments,
                                               ndb::FileProfile profile)
    : fragments_(fragments), profile_(profile) {}

Result<ByteView> NodeFragmentHeapSource::heap(uint32_t hid) {
    // [MS-PST] 2.3.1.1: hidBlockIndex names the data block the allocation lives in, and the fragments are
    // that node's data blocks in the order its jump table lists them ([MS-PST] 2.2.2.8.3.2.1), so the
    // index is the fragment ordinal. No unit conversion: the 8x that used to be needed here was the 512
    // allocation/block widths applied to a 4 KiB file.
    const uint64_t fragment = hid_block_index(hid, profile_);
    if (fragment >= fragments_.size()) {
        ++cross_block_misses;
        return make_error(ErrorKind::kUnsupported, "HID.hidBlockIndex", 0, hid,
                          "the heap item names data block " +
                              std::to_string(hid_block_index(hid, profile_)) +
                              ", of which this node has " + std::to_string(fragments_.size()));
    }
    const HnFragment &part = fragments_[static_cast<size_t>(fragment)];
    if (!part.page_map_ok) {
        ++cross_block_misses;
        return make_error(ErrorKind::kUnsupported, "HNPAGEMAP", part.block.block_base, hid,
                          "data block " + std::to_string(fragment) + " has no usable page map");
    }
    return hn_heap_item(part.page_map, part.block.heap_node(), hid, profile_);
}

} // namespace ost2pst::ltp
