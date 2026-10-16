#pragma once

#include <cstdint>

#include "ost2pst/ndb/layout.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ndb {

// [MS-PST] 2.2.2.7.1 PAGETRAILER (Unicode). ANSI swaps dwCRC and bid; this project reads Unicode
// only, so the Unicode order is the one encoded here. OST widens the trailer to 24 bytes and writes
// 1 in the slot past the spec's 16, but the five spec fields keep their offsets.
struct PageTrailer {
    uint8_t ptype = 0;
    uint8_t ptype_repeat = 0;
    uint16_t w_sig = 0;
    uint32_t dw_crc = 0;
    uint64_t bid = 0;
    uint32_t ost_flag = 0; // [MS-PST] 2.2.2.7.1: OST-only slot; 0 when the profile has no such slot
};

// [MS-PST] 2.2.2.8.1 BLOCKTRAILER (Unicode). cb counts raw data bytes only, never padding. OST
// widens the trailer to 24 bytes and writes a block type and the block's uncompressed data length past
// the spec's 16 (measured on every block of the sample; libpff's 4k block footer agrees).
struct BlockTrailer {
    uint16_t cb = 0;
    uint16_t w_sig = 0;
    uint32_t dw_crc = 0;
    uint64_t bid = 0;
    uint16_t ost_b_typ = 0; // [MS-PST] 2.2.2.8.1: OST-only slot; 2 on every block of the sample
    uint16_t ost_uncompressed_cb = 0; // [MS-PST] 2.2.2.8.1: OST-only slot; the uncompressed data length on the sample
};

// view is the trailer window itself, sized by the profile; every error it reports carries the
// window's absolute base offset, so callers never have to re-add it.
util::Result<PageTrailer> decode_page_trailer(util::ByteView view, FileProfile profile);
util::Result<BlockTrailer> decode_block_trailer(util::ByteView view, FileProfile profile);

// Structural pre-check only (ptype == ptypeRepeat in the defined range). Used while scanning a page
// grid, where a CRC is the expensive confirmation.
bool looks_like_page_trailer(const uint8_t *trailer);
bool is_page_type(uint8_t ptype);
bool page_type_uses_zero_sig(uint8_t ptype);
const char *page_type_name(uint8_t ptype);

} // namespace ost2pst::ndb
