#pragma once

#include <cstdint>
#include <vector>

#include "ost2pst/ltp/layout.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ltp {

// [MS-PST] 2.3.1.2 HNHDR: the first bytes of an HN's first data block. bSig is what says the block is a
// heap node at all, so nothing else in the block is trusted before it matches.
struct HnHeader {
    uint16_t ib_hnpm = 0;      // [MS-PST] 2.3.1.2 ibHnpm: HNPAGEMAP offset, relative to this header
    uint8_t b_sig = 0;         // [MS-PST] 2.3.1.2 bSig: 0xEC
    uint8_t b_client_sig = 0;  // [MS-PST] 2.3.1.2 bClientSig: which client structure the HN carries
    uint32_t hid_user_root = 0; // [MS-PST] 2.3.1.2 hidUserRoot
    uint32_t rgb_fill_level = 0; // [MS-PST] 2.3.1.2 rgbFillLevel
};

util::Result<HnHeader> decode_hn_header(util::ByteView block);

// [MS-PST] 2.3.1.5 HNPAGEMAP: cAlloc + 1 WORD offsets. Allocation n is [rgibAlloc[n], rgibAlloc[n+1])
// and the extra last entry marks the next available slot.
struct HnPageMap {
    uint16_t c_alloc = 0;
    uint16_t c_free = 0;
    std::vector<uint16_t> offsets; // c_alloc + 1 entries, monotonically increasing
    uint64_t base = 0;             // absolute file offset of the HNPAGEMAP itself
};

util::Result<HnPageMap> decode_hn_page_map(util::ByteView block, uint64_t ib_hnpm);

// One allocation's bytes, as a view based at its absolute file offset. Index is the 1-based hidIndex
// ([MS-PST] 2.3.1.1), and the window is [rgibAlloc[index-1], rgibAlloc[index]) ([MS-PST] 2.3.1.5).
util::Result<util::ByteView> hn_allocation(const HnPageMap &map, util::ByteView block,
                                           uint64_t index);

// [MS-PST] 2.3.1.1: a HID names allocation hid_index(hid, profile) of data block
// hid_block_index(hid, profile). The widths are profile-specific, so the profile has to come in; only the
// block handed in can be answered, and picking the block is the caller's job.
util::Result<util::ByteView> hn_heap_item(const HnPageMap &map, util::ByteView block, uint32_t hid,
                                          ndb::FileProfile profile);

} // namespace ost2pst::ltp
