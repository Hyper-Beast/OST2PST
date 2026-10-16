#pragma once

#include <cstdint>
#include <vector>

#include "ost2pst/util/file_writer.h"
#include "ost2pst/util/status.h"
#include "ost2pst/util/value_spool.h"

namespace ost2pst::writer {

// One data block as the writer laid it out and as the BBT indexes it, kept so a caller can check
// the image against the writer's own bookkeeping instead of re-deriving the layout from the bytes.
struct WrittenBlock {
    uint64_t bid = 0;   // [MS-PST] 2.2.2.2: the BID, carrying bit B when the block is internal
    uint64_t ib = 0;    // [MS-PST] 2.2.2.8: the absolute offset of the block
    uint16_t cb = 0;    // [MS-PST] 2.2.2.7.7.3: raw data bytes, trailer and padding excluded
    uint16_t c_ref = 0; // [MS-PST] 2.2.2.7.7.3.1: 1 + the references that name this block
};

// A block slot that names nothing: a node with no data block, or a node with no subnode list. The
// emitter writes bidData 0 / bidSub 0 for it ([MS-PST] 2.2.2.7.7.4 NBTENTRY.bidData and bidSub).
constexpr uint64_t kNoBlock = ~0ull; // [MS-PST] 2.2.2.7.7.4: bidData 0 and bidSub 0 name no block

// Engineering ceilings for the complete output, including generated internal blocks.
// Per-record graph limits are separate. These are not PST format/file-size limits.
// 100 GiB / 8176 is about 13.2 million full external blocks. Allow partial blocks,
// table/heap overhead and generated trees as well; tiny-block stores can still hit this ceiling.
inline constexpr uint64_t kStoreMaxBlocks = 32000000;
inline constexpr uint64_t kStoreMaxNodes = 1000000;

// One external data block the caller supplies: raw bytes only, trailer and padding excluded
// ([MS-PST] 2.2.2.8.1 cb counts raw data bytes). The emitter gives it the next BID and its place in
// the file, and never reorders the list.
struct StoreBlock {
    std::vector<uint8_t> bytes;
    util::SharedBytes source;
    uint64_t source_offset = 0;
    uint16_t source_size = 0;
    uint64_t size() const { return source ? source_size : bytes.size(); }
};

// One subnode of a node ([MS-PST] 2.2.2.8.3.3.1.1 SLENTRY.nid): the NID is unique only within its
// parent node. More than one data block means the emitter writes an XBLOCK over them
// ([MS-PST] 2.2.2.8.3.2.1).
struct StoreSubnode {
    uint32_t nid = 0;
    std::vector<uint64_t> data_blocks;
    std::vector<StoreSubnode> subnodes;
};

// One NBT node ([MS-PST] 2.2.2.7.7.4 NBTENTRY). data_blocks names the block or blocks the bidData
// reaches; subnodes become the one SLBLOCK the bidSub names ([MS-PST] 2.2.2.8.3.3.1.2).
struct StoreNode {
    uint32_t nid = 0;
    uint32_t nid_parent = 0;
    std::vector<uint64_t> data_blocks;
    std::vector<StoreSubnode> subnodes;
};

// The whole file as a plan: the blocks in the order they are to be laid out, the nodes that
// reference them, and HEADER.rgnid. A block shared by several nodes is one entry named by several
// of them, which is how the writer keeps the reference counts of [MS-PST] 2.2.2.7.7.3.1 honest.
struct StorePlan {
    std::vector<StoreBlock> blocks;
    std::vector<StoreNode> nodes;
    std::vector<uint32_t> rgnid; // [MS-PST] 2.2.2.1 HEADER.rgnid[32]
};

// A whole PST file image plus the numbers the writer used to lay it out.
struct StoreImage {
    std::vector<uint8_t> bytes;
    std::vector<WrittenBlock> blocks;

    uint64_t bid_next_b = 0;
    uint64_t bid_next_p = 0;
    uint64_t bbt_root_ib = 0;
    uint64_t nbt_root_ib = 0;
    uint64_t amap_bits_set = 0;
    uint64_t cb_amap_free = 0;
    uint64_t amap_regions = 0;
    uint64_t file_bytes = 0;
};

// Writer-ready external blocks, read on demand. The source outlives write_store_to and keeps
// stable block numbering/sizes; neither interface exposes an OST handle or source-format BID.
class StoreBlockSource {
  public:
    virtual ~StoreBlockSource() = default;
    virtual uint64_t count() const = 0;
    virtual util::Result<uint16_t> block_size(uint64_t index) const = 0;
    virtual util::Status read_block(uint64_t index, uint8_t* data, size_t size) const = 0;
};

// Emits to an initially empty owned file with bounded I/O buffers. Returned bytes is empty;
// file_bytes and block/layout metadata describe the output. Flush succeeds before return.
util::Result<StoreImage> write_store_to(const StoreBlockSource& blocks,
                                        const std::vector<StoreNode>& nodes,
                                        const std::vector<uint32_t>& rgnid,
                                        util::RandomAccessFile& output);

// Lays a plan out as a complete Unicode 512-byte-page PST: data blocks with trailers, one SLBLOCK
// per node that has subnodes, one XBLOCK per node whose data needs more than one block, the BBT and
// NBT down to however many levels the entries need, the AMap/PMap regions the file needs, the DList
// page, the HEADER with both CRCs last.
util::Result<StoreImage> write_store(const StorePlan& plan);

} // namespace ost2pst::writer
