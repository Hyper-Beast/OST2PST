#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "ost2pst/util/status.h"
#include "ost2pst/util/workspace.h"

namespace ost2pst::writer {

// One heap node built in memory ([MS-PST] 2.3.1.6): its data blocks, each carrying the header that
// block needs ([MS-PST] 2.3.1.2 HNHDR / 2.3.1.3 HNPAGEHDR / 2.3.1.4 HNBITMAPHDR), the allocations
// packed after it, and the HNPAGEMAP at the end. A node whose allocations do not fit one data block
// fans out over several ([MS-PST] 2.3.1.6.2) and the caller names them with a data tree. The writer
// never reads a file, so this is where a Property Context or a Table Context becomes bytes; the NDB
// layer decides the block footprint and the trailer around it.
class HeapImage {
  public:
    explicit HeapImage(uint8_t client_sig); // [MS-PST] 2.3.1.2 bClientSig
    // Enable paged allocations before appending. Shared sources retain scratch lifetime.
    void enable_spill(std::shared_ptr<util::Workspace> workspace);
    util::Status stream_blocks(const util::ByteConsumer& consume) const;

    // Appends one allocation and returns its HID. The writer never frees a heap item, so the nth
    // allocation of its data block is numbered n and its HID is (hidBlockIndex << 16) | (n << 5)
    // ([MS-PST] 2.3.1.1 hidIndex is 1-based inside its block and hidBlockIndex is the block).
    util::Result<uint32_t> append(std::vector<uint8_t> bytes);

    // The HID of allocation index (1-based over the whole node); 0 when there is no such
    // allocation.
    uint32_t hid(uint64_t index) const;
    uint64_t allocation_count() const;
    uint64_t block_count() const;

    // [MS-PST] 2.3.1.2 hidUserRoot: the client root record is the first allocation, which is what
    // 2.3.3.6 and 2.3.4 show for a PC (its BTHHEADER) and for a TC (its TCINFO).
    uint32_t hid_user_root() const;

    // Every data block of the node in block order, each as its header + allocations + HNPAGEMAP.
    // The size of each is the cb its block trailer reports ([MS-PST] 2.2.2.8.1 cb counts raw data
    // bytes only, never the trailer and never the padding).
    const std::vector<std::vector<uint8_t>>& blocks() const;

    // The first data block, which is the whole node while it stays a single-block heap node
    // ([MS-PST] 2.3.1.6.1).
    const std::vector<uint8_t>& bytes() const;

    // ibHnpm of the first block ([MS-PST] 2.3.1.2). Every block of a multi-block node carries its
    // own at the same offset ([MS-PST] 2.3.1.3, 2.3.1.4).
    uint16_t ib_hnpm() const;

    // Rewrites the 4 bytes at offset inside allocation index (1-based) without changing its size,
    // so a header can name the HID of an allocation the writer has not built yet. No size changes,
    // so the packing, and every HID already handed out, stays put.
    util::Status patch(uint64_t index, uint64_t offset, uint32_t value);

    // Overwrites bytes inside an existing allocation, starting at offset, under the same rule: the
    // allocation keeps its size, so no HID moves.
    util::Status patch(uint64_t index, uint64_t offset, const std::vector<uint8_t>& bytes);

  private:
    struct DiskHeap;
    std::shared_ptr<DiskHeap> disk_;
    util::Status detach();
    util::Result<std::vector<uint8_t>> build_block(size_t block, uint64_t& allocation) const;
    // Whether an allocation of this many bytes still fits the data block at index.
    bool block_accepts(uint64_t block, uint64_t size) const;
    // ibHnpm of one block: the allocations are contiguous and the HNPAGEMAP starts on an even
    // offset.
    uint64_t block_ib_hnpm(uint64_t block) const;
    // Rebuilds every block image from the allocations and their placement.
    std::vector<std::vector<uint8_t>> build() const;

    uint8_t client_sig_ = 0;
    std::vector<std::vector<uint8_t>> allocations_;
    // Per data block: where its contiguous allocations end, and how many of them it holds.
    std::vector<uint64_t> block_alloc_end_;
    std::vector<uint64_t> block_slots_;
    // Which block, and which 1-based slot inside it, each allocation got, in append order.
    std::vector<std::pair<uint64_t, uint64_t>> placement_;
    mutable std::vector<std::vector<uint8_t>> blocks_;
    mutable bool dirty_ = true;
};

} // namespace ost2pst::writer
