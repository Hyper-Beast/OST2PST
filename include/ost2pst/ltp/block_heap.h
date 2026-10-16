#pragma once

#include <cstdint>
#include <vector>

#include "ost2pst/ltp/bth.h"
#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/hn_block.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ltp {

// A HeapSource that answers a HID out of one data block's heap ([MS-PST] 2.3.1.1 / 2.3.1.5). A HID whose
// hidBlockIndex names a different data block cannot be answered from this block ([MS-PST] 2.3.1.4), and
// reaching it needs the subnode lookup that lands with the NID map, so it is reported rather than
// guessed at.
class BlockHeapSource : public HeapSource {
public:
    BlockHeapSource(util::ByteView block, HnPageMap page_map, ndb::FileProfile profile,
                    uint16_t block_index);

    util::Result<util::ByteView> heap(uint32_t hid) override;

    uint64_t cross_block_misses = 0; // HIDs that belong to another data block

private:
    util::ByteView block_;
    HnPageMap page_map_;
    uint16_t block_index_;
    ndb::FileProfile profile_;
};

// One data block of a multi-block HN: the block's own bytes and the HNPAGEMAP sitting at its own ibHnpm
// ([MS-PST] 2.3.1.6.2 / 2.3.1.5). Each block carries its own HNHDR-shaped, HNPAGEHDR-shaped or
// HNBITMAPHDR-shaped header, so each one answers for its own allocations.
struct HnFragment {
    // A BlockSource reuses one buffer, so a raw block's bytes are copied here and block.raw_block is
    // re-aimed at the copy. A compressed block already owns what it inflated to.
    std::vector<uint8_t> owned;
    HnBlock block;
    HnPageMap page_map;
    bool page_map_ok = false;
};

// A HeapSource over a multi-block HN: [MS-PST] 2.3.1.6.2 says the items are allocated out of the node's
// leaf data blocks and 2.3.1.1 says hidBlockIndex names the block an item lives in. The fragments are
// those blocks in the order the node's jump table names them ([MS-PST] 2.2.2.8.3.2.1), so hidBlockIndex
// selects a fragment directly once its width comes from the right profile.
class NodeFragmentHeapSource : public HeapSource {
public:
    NodeFragmentHeapSource(const std::vector<HnFragment> &fragments, ndb::FileProfile profile);

    util::Result<util::ByteView> heap(uint32_t hid) override;

    uint64_t cross_block_misses = 0; // HIDs naming a block this node does not have

private:
    const std::vector<HnFragment> &fragments_;
    ndb::FileProfile profile_;
};

} // namespace ost2pst::ltp
