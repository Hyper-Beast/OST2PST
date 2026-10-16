#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ltp {

// [MS-PST] describes no block compression at all, but an OST stores most of its data blocks as one zlib
// stream (DEVELOPMENT.md). Which form a block is in comes from the NDB,
// never off nidType and never off a guess at the bytes: folders are compressed 49/65 while their own
// tables are 13/66.
enum class BlockForm {
    kRaw,        // the block's own bytes are the heap node
    kCompressed, // a zlib stream fills the block; the heap node is what it inflates to
};

const char *block_form_name(BlockForm form);

// One data block's heap-node bytes, and how they were obtained.
//
// A raw block is viewed at its file offset, so every offset inside it is absolute. An inflated block is
// viewed from 0: those bytes sit at no file offset, so every offset inside them is block-relative and
// block_base is where the block itself starts. Keeping the two apart is what stops a compressed block
// from being reported as "not a heap node".
struct HnBlock {
    BlockForm form = BlockForm::kRaw;
    uint64_t block_base = 0;
    size_t stream_bytes = 0; // block bytes the zlib stream used, CMF/FLG and Adler-32 included
    size_t leftover = 0;     // block bytes the stream did not use

    // The inflated bytes are held here, so heap_node() stays valid for as long as the HnBlock does.
    std::vector<uint8_t> inflated;
    util::ByteView raw_block;

    // The payload either way. heap_node() is the same view under the name the LTP layer uses; the
    // raw-or-compressed decision is about the block, not about what the payload is, so a subnode
    // block ([MS-PST] 2.2.2.8.3.3) reads its bytes through bytes().
    util::ByteView bytes() const { return heap_node(); }

    util::ByteView heap_node() const {
        if (form == BlockForm::kCompressed) {
            return util::ByteView(inflated.data(), inflated.size(), 0);
        }
        return raw_block;
    }
};

// `compressed` is what the NDB says about the block (ndb::BlockData::compressed, read off the OST
// trailer's uncompressed data length). A block the NDB calls compressed has to carry a CMF/FLG pair and
// inflate; one it calls raw is read as its own bytes even when those bytes look like a zlib header. On the
// sample 64 raw blocks start with a pair that passes the sniff and not one of them inflates, so guessing
// from the bytes loses 64 blocks the index describes correctly. max_output bounds how much a corrupt cb
// is allowed to ask for.
util::Result<HnBlock> read_hn_block(util::ByteView block, bool compressed, size_t max_output = 1u << 20);

// [MS-PST] 2.2.2.8.3.2.1 / 2.2.2.8.3.2.2: the jump table a node's data block carries when the node's
// data does not fit in one data block. cLevel says which kind: an XBLOCK names data blocks, an XXBLOCK
// names XBLOCKs, so only an XBLOCK's bids are the fragments a multi-block heap node is made of.
struct BlockJumpTable {
    uint8_t c_level = 0;
    uint16_t c_ent = 0;
    uint32_t lcb_total = 0;
    std::vector<uint64_t> bids;
};

util::Result<BlockJumpTable> decode_block_jump_table(util::ByteView payload);

// [MS-PST] 2.3.1.2 / 2.3.1.3 / 2.3.1.4 / 2.3.1.6.2: which header a block of a multi-block HN carries.
// Block 0 has the 12-byte HNHDR, block 8 and then every 128th block the 66-byte HNBITMAPHDR, and the
// blocks in between the 2-byte HNPAGEHDR. Every one of them starts with ibHnpm, so the offset of the
// block's own HNPAGEMAP is read off the block and this only says how much header precedes the heap.
size_t hn_block_header_size(uint64_t block_index);
bool hn_block_carries_fill_level(uint64_t block_index);

} // namespace ost2pst::ltp
