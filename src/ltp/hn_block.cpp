#include "ost2pst/ltp/hn_block.h"

#include <string>
#include <utility>

#include "internal/take.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/util/inflate.h"

namespace ost2pst::ltp {

using util::ByteView;
using util::DataError;
using util::ErrorKind;
using util::make_error;
using util::Result;

const char *block_form_name(BlockForm form) {
    switch (form) {
    case BlockForm::kRaw:
        return "raw";
    case BlockForm::kCompressed:
        return "compressed";
    }
    return "unknown";
}

Result<HnBlock> read_hn_block(ByteView block, bool compressed, size_t max_output) {
    HnBlock out;
    out.block_base = block.base();
    if (!compressed) {
        out.form = BlockForm::kRaw;
        out.raw_block = block;
        return out;
    }
    // The NDB called this block compressed, so a missing CMF/FLG pair is a contradiction at the block,
    // not a hint to read the bytes as raw.
    if (!util::zlib_header_present(block)) {
        const uint32_t pair =
            block.size() >= 2 ? ((static_cast<uint32_t>(block.data()[0]) << 8) | block.data()[1]) : 0;
        return make_error(ErrorKind::kBadSignature, "zlib.CMF", block.base(), pair,
                          "the NDB says this block is compressed and its bytes carry no CMF/FLG pair");
    }
    Result<util::ZlibStream> stream = util::inflate_zlib(block, max_output);
    if (!stream.ok()) {
        return stream.error();
    }
    util::ZlibStream inflated = stream.take();
    out.form = BlockForm::kCompressed;
    out.stream_bytes = inflated.consumed;
    out.leftover = inflated.consumed <= block.size() ? block.size() - inflated.consumed : 0;
    out.inflated = std::move(inflated.data);
    return out;
}

bool hn_block_carries_fill_level(uint64_t block_index) {
    // [MS-PST] 2.3.1.6.2: the HNHDR's own fill level map covers blocks 0-7, so block 8 starts a new one
    // and its 128 slots carry through to the next HNBITMAPHDR.
    if (block_index < kHnBitmapFirstBlock) {
        return false;
    }
    return (block_index - kHnBitmapFirstBlock) % kHnBitmapSlots == 0;
}

size_t hn_block_header_size(uint64_t block_index) {
    if (block_index == 0) {
        return kHnHeaderSize; // [MS-PST] 2.3.1.2: the first block of an HN carries the HNHDR
    }
    if (hn_block_carries_fill_level(block_index)) {
        return kHnBitmapHeaderSize; // [MS-PST] 2.3.1.4: ibHnpm plus rgbFillLevel
    }
    return kHnPageHeaderSize; // [MS-PST] 2.3.1.3: ibHnpm alone
}

Result<BlockJumpTable> decode_block_jump_table(ByteView payload) {
    BlockJumpTable table;
    DataError failure;
    uint8_t b_type = 0;
    if (!take(payload.u8(kJumpTableTypeOffset), b_type, "XBLOCK.btype", failure)) {
        return failure;
    }
    // [MS-PST] 2.2.2.8.3.2.1: btype 0x01 is what an XBLOCK or XXBLOCK declares itself to be.
    if (b_type != kJumpTableType) {
        return make_error(ErrorKind::kBadField, "XBLOCK.btype", payload.base() + kJumpTableTypeOffset,
                          b_type, "must be 0x01 to indicate an XBLOCK or XXBLOCK");
    }
    if (!take(payload.u8(kJumpTableLevelOffset), table.c_level, "XBLOCK.cLevel", failure)) {
        return failure;
    }
    // [MS-PST] 2.2.2.8.3.2.1 / 2.2.2.8.3.2.2: 1 names data blocks, 2 names XBLOCKs, nothing else is
    // defined, and only level 1 is a heap node's own set of data blocks.
    if (table.c_level != kJumpTableLevelXblock && table.c_level != kJumpTableLevelXxblock) {
        return make_error(ErrorKind::kBadField, "XBLOCK.cLevel", payload.base() + kJumpTableLevelOffset,
                          table.c_level, "must be 0x01 for an XBLOCK or 0x02 for an XXBLOCK");
    }
    if (!take(payload.u16(kJumpTableCountOffset), table.c_ent, "XBLOCK.cEnt", failure)) {
        return failure;
    }
    if (table.c_ent < 1 || table.c_ent > kJumpTableMaxEntries) {
        return make_error(ErrorKind::kBadField, "XBLOCK.cEnt", payload.base() + kJumpTableCountOffset,
                          table.c_ent,
                          "must be between 1 and " + std::to_string(kJumpTableMaxEntries));
    }
    if (!take(payload.u32(kJumpTableTotalOffset), table.lcb_total, "XBLOCK.lcbTotal", failure)) {
        return failure;
    }
    // [MS-PST] 2.2.2.8.3.2.1: rgbid holds cEnt BIDs, 8 bytes each in a Unicode file.
    const uint64_t entries = static_cast<uint64_t>(table.c_ent) * kJumpTableBidSize;
    if (payload.size() < kJumpTableHeaderSize + entries) {
        return make_error(ErrorKind::kTruncated, "XBLOCK.rgid", payload.base() + kJumpTableHeaderSize,
                          entries, "the BID array runs past the end of the jump table");
    }
    table.bids.reserve(table.c_ent);
    for (uint16_t index = 0; index < table.c_ent; ++index) {
        const uint64_t at = kJumpTableHeaderSize + static_cast<uint64_t>(index) * kJumpTableBidSize;
        uint64_t bid = 0;
        if (!take(payload.u64(at), bid, "XBLOCK.rgid", failure)) {
            return failure;
        }
        if (bid == 0) {
            return make_error(ErrorKind::kBadField, "XBLOCK.rgid", payload.base() + at, bid,
                              "a jump table entry has to name a block");
        }
        table.bids.push_back(bid);
    }
    return table;
}

} // namespace ost2pst::ltp
