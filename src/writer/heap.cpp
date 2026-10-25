#include "ost2pst/writer/heap.h"

#include <array>
#include <stdexcept>
#include <string>
#include <utility>

#include "ost2pst/ltp/hn_block.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/writer/layout.h"

#include "internal/put.h"

namespace ost2pst::writer {

using util::ErrorKind;
using util::make_error;
using util::Result;
using util::Status;

namespace {

// The writer emits the profile [MS-PST] 2.2.2.7 / 2.2.2.8 describes for a Unicode PST: 512-byte
// pages, 16-byte block trailers, 64-byte allocation units.
constexpr ndb::FileProfile kProfile = ndb::FileProfile::kPst;

// [MS-PST] 2.3.1.5: rgibAlloc holds cAlloc + 1 WORD offsets, the extra one marking the next free
// slot.
uint64_t page_map_bytes(uint64_t allocations) {
    return ltp::kHnPageMapHeaderSize + (allocations + 1) * ltp::kHnPageMapEntrySize;
}

// [MS-PST] 2.3.1.1: hidIndex is 11 bits in the 512-byte page profile, so a data block cannot hold
// more than 2047 allocations before its HIDs would run into the next block's.
constexpr uint64_t kMaxBlockAllocations =
    ltp::kHidIndexMask512; // [MS-PST] 2.3.1.1: hidIndex is 11 bits

uint32_t hid_of(uint64_t block, uint64_t slot) {
    // [MS-PST] 2.3.1.1: a HID is hidBlockIndex above hidIndex above hidType, and hidType is 0 for a
    // heap item. Block 0 slot 1 is therefore HID 0x20, the same value the single-block case had.
    return static_cast<uint32_t>((block << ltp::kHidBlockIndexShift512) |
                                 (slot << ltp::kHidIndexShift));
}

uint8_t fill_level(uint64_t used) {
    // [MS-PST] 2.3.1.2 and libpff "The table fill level": lower bounds on free bytes.
    constexpr uint64_t lower[] = {3584, 2560, 2048, 1792, 1536, 1280, 1024, 768,
                                  512,  256,  128,  64,   32,   16,   8};
    const uint64_t free = ndb::block_max_cb(kProfile) - used;
    for (uint8_t level = 0; level < 15; ++level) {
        if (free >= lower[level]) {
            return level;
        }
    }
    return 15;
}

} // namespace

struct HeapImage::DiskHeap {
    struct Record {
        uint64_t offset;
        uint32_t size;
        uint32_t hid;
    };
    explicit DiskHeap(std::shared_ptr<util::Workspace> workspace)
        : workspace(workspace), records(workspace),
          values(std::make_shared<util::SpillBuffer>(workspace)) {}
    std::shared_ptr<util::Workspace> workspace;
    util::SpillArray<Record> records;
    std::shared_ptr<util::SpillBuffer> values;
};

void HeapImage::enable_spill(std::shared_ptr<util::Workspace> workspace) {
    if (workspace && allocation_count() == 0)
        disk_ = std::make_shared<DiskHeap>(std::move(workspace));
}
Status HeapImage::detach() {
    if (!disk_ || disk_.use_count() == 1)
        return {};
    auto copy = std::make_shared<DiskHeap>(disk_->workspace);
    std::array<uint8_t, 8192> bytes{};
    for (uint64_t offset = 0; offset < disk_->values->size();) {
        const auto count =
            static_cast<size_t>(std::min<uint64_t>(bytes.size(), disk_->values->size() - offset));
        auto read = disk_->values->read_at(offset, bytes.data(), count);
        if (!read.ok())
            return read;
        auto appended = copy->values->append(util::ByteView(bytes.data(), count));
        if (!appended.ok())
            return appended;
        offset += count;
    }
    for (uint64_t index = 0; index < disk_->records.size(); ++index) {
        auto appended = copy->records.push_back(disk_->records.get(index));
        if (!disk_->records.status().ok())
            return disk_->records.status();
        if (!appended.ok())
            return appended;
    }
    disk_ = std::move(copy);
    return {};
}

HeapImage::HeapImage(uint8_t client_sig) : client_sig_(client_sig) {
    // [MS-PST] 2.3.1.6.1: a heap node always has its first data block, even before anything is
    // allocated from it, and the allocations start right after the 12-byte HNHDR.
    block_alloc_end_.push_back(kHnFirstAllocationOffset);
    block_slots_.push_back(0);
}

uint32_t HeapImage::hid(uint64_t index) const {
    if (disk_) {
        if (index < 1 || index > disk_->records.size())
            return 0;
        return disk_->records.get(index - 1).hid;
    }
    if (index < 1 || index > placement_.size()) {
        return 0;
    }
    const std::pair<uint64_t, uint64_t>& placed = placement_[static_cast<size_t>(index) - 1];
    return hid_of(placed.first, placed.second);
}

uint64_t HeapImage::allocation_count() const {
    return disk_ ? disk_->records.size() : allocations_.size();
}

uint64_t HeapImage::block_count() const {
    return block_alloc_end_.size();
}

// [MS-PST] 2.3.1.2 hidUserRoot names the client root record, and 2.3.3.6 / 2.3.4 show it as the
// first allocation of a PC (the BTHHEADER) or of a TC (the TCINFO).
uint32_t HeapImage::hid_user_root() const {
    return hid(1);
}

uint64_t HeapImage::block_ib_hnpm(uint64_t block) const {
    // Writer layout choice verified against the Outlook oracle: keep the WORD-based map aligned
    // without adding bytes to the last allocation. SCANPST rejects an odd ibHnpm. [MS-PST] 2.3.1.5
    // defines the item endpoints separately from where the map sits.
    const uint64_t end = block_alloc_end_[static_cast<size_t>(block)];
    return end + end % 2;
}

bool HeapImage::block_accepts(uint64_t block, uint64_t size) const {
    const uint64_t end = block_alloc_end_[static_cast<size_t>(block)] + size;
    const uint64_t slots = block_slots_[static_cast<size_t>(block)] + 1;
    const uint64_t ib_hnpm = end + end % 2;
    const uint64_t cb = ib_hnpm + page_map_bytes(slots);
    if (slots > kMaxBlockAllocations) {
        return false; // [MS-PST] 2.3.1.1: hidIndex is 11 bits
    }
    if (ib_hnpm > 0xFFFFu || cb > 0xFFFFu) {
        return false; // [MS-PST] 2.3.1.5: rgibAlloc entries are WORDs
    }
    if (cb > ndb::block_max_cb(kProfile)) {
        return false; // [MS-PST] 2.2.2.8: a data block holds at most 8176 raw bytes
    }
    // Preserve the conservative allocation packing policy independently of the stored block size.
    if (cb > kHeapPackingTargetBytes) {
        return false;
    }
    const uint64_t trailer = ndb::block_trailer_size(kProfile);
    const uint64_t footprint = ndb::align_allocation(kProfile, cb + trailer);
    if (footprint - cb - trailer > kMaxBlockPaddingBytes) {
        return false; // [MS-PST] 2.3.1.5: 0-63 bytes of padding before the block trailer
    }
    return true;
}

Result<uint32_t> HeapImage::append(std::vector<uint8_t> bytes) {
    auto unique = detach();
    if (!unique.ok())
        return unique.error();
    // [MS-PST] 2.3.1.5 sizes an allocation as rgibAlloc[n + 1] - rgibAlloc[n], and
    // ltp::hn_allocation refuses an allocation of zero bytes, so an empty item is a writer bug, not
    // a shape to emit.
    if (bytes.empty()) {
        return make_error(ErrorKind::kBadField, "writer.HeapImage.append", 0, 0,
                          "a heap allocation cannot be empty ([MS-PST] 2.3.1.5)");
    }
    // [MS-PST] 2.3.1.6.2: "individual heap items are allocated from the leaf data blocks in a
    // similar manner" to the single-block case, so the writer fills the block it is on and only
    // then opens the next one. It never splits an allocation across blocks, because
    // ltp::hn_allocation reads one item out of one block's rgibAlloc window and cannot reassemble a
    // split one.
    uint64_t block = block_alloc_end_.size() - 1;
    if (!block_accepts(block, bytes.size())) {
        if (block_slots_[static_cast<size_t>(block)] == 0) {
            return make_error(
                ErrorKind::kBadField, "writer.heap.allocation_capacity", bytes.size(), block,
                "one allocation larger than a data block can hold ([MS-PST] 2.3.1.1 / 2.3.1.2)");
        }
        block = block_alloc_end_.size();
        // Existing Unicode HID geometry: the block index must fit before it is
        // shifted into a 32-bit HID. Spilling must never turn this into wraparound.
        if (block >= ltp::kDataTreeMaxBlocks512)
            return make_error(ErrorKind::kUnsupported, "writer.heap.block_index", block,
                              ltp::kDataTreeMaxBlocks512,
                              "heap exceeds the Unicode HID block-index capacity");
        block_alloc_end_.push_back(ltp::hn_block_header_size(block));
        block_slots_.push_back(0);
        if (!block_accepts(block, bytes.size())) {
            block_alloc_end_.pop_back();
            block_slots_.pop_back();
            return make_error(
                ErrorKind::kBadField, "writer.heap.allocation_capacity", bytes.size(), block,
                "one allocation larger than a data block can hold ([MS-PST] 2.3.1.1 / 2.3.1.2)");
        }
    }
    const uint64_t slot = block_slots_[static_cast<size_t>(block)] + 1;
    block_alloc_end_[static_cast<size_t>(block)] += bytes.size();
    block_slots_[static_cast<size_t>(block)] = slot;
    if (disk_) {
        const auto offset = disk_->values->size();
        auto stored = disk_->values->append(util::ByteView(bytes.data(), bytes.size()));
        if (!stored.ok())
            return stored.error();
        stored = disk_->records.push_back(
            {offset, static_cast<uint32_t>(bytes.size()), hid_of(block, slot)});
        if (!stored.ok())
            return stored.error();
    } else {
        allocations_.push_back(std::move(bytes));
        placement_.emplace_back(block, slot);
    }
    dirty_ = true;
    return hid_of(block, slot);
}

Status HeapImage::patch(uint64_t index, uint64_t offset, uint32_t value) {
    if (disk_) {
        std::vector<uint8_t> bytes(4);
        put_u32(bytes, 0, value);
        return patch(index, offset, bytes);
    }
    if (index < 1 || index > allocations_.size()) {
        return make_error(ErrorKind::kBadField, "writer.HeapImage.patch", index,
                          allocations_.size(), "no allocation with that index to patch");
    }
    std::vector<uint8_t>& allocation = allocations_[static_cast<size_t>(index) - 1];
    if (offset + 4 > allocation.size()) {
        return make_error(ErrorKind::kBadField, "writer.HeapImage.patch", offset, allocation.size(),
                          "the 4 bytes to rewrite run past the end of the allocation");
    }
    put_u32(allocation, offset, value);
    dirty_ = true;
    return Status{};
}

Status HeapImage::patch(uint64_t index, uint64_t offset, const std::vector<uint8_t>& bytes) {
    if (disk_) {
        auto unique = detach();
        if (!unique.ok())
            return unique;
        if (index < 1 || index > disk_->records.size())
            return make_error(ErrorKind::kBadField, "writer.HeapImage.patch", index,
                              allocation_count());
        const auto record = disk_->records.get(index - 1);
        if (!disk_->records.status().ok())
            return disk_->records.status();
        if (offset > record.size || bytes.size() > record.size - offset)
            return make_error(ErrorKind::kBadField, "writer.HeapImage.patch", offset, record.size);
        dirty_ = true;
        return disk_->values->write_at(record.offset + offset,
                                       util::ByteView(bytes.data(), bytes.size()));
    }
    if (index < 1 || index > allocations_.size()) {
        return make_error(ErrorKind::kBadField, "writer.HeapImage.patch", index,
                          allocations_.size(), "no allocation with that index to patch");
    }
    std::vector<uint8_t>& allocation = allocations_[static_cast<size_t>(index) - 1];
    if (offset + bytes.size() > allocation.size()) {
        return make_error(ErrorKind::kBadField, "writer.HeapImage.patch", offset, allocation.size(),
                          "the bytes to rewrite run past the end of the allocation");
    }
    for (size_t byte = 0; byte < bytes.size(); ++byte) {
        allocation[static_cast<size_t>(offset) + byte] = bytes[byte];
    }
    dirty_ = true;
    return Status{};
}

uint16_t HeapImage::ib_hnpm() const {
    return static_cast<uint16_t>(block_ib_hnpm(0));
}

const std::vector<uint8_t>& HeapImage::bytes() const {
    return blocks()[0];
}

const std::vector<std::vector<uint8_t>>& HeapImage::blocks() const {
    if (dirty_) {
        blocks_ = build();
        dirty_ = false;
    }
    return blocks_;
}

Result<std::vector<uint8_t>> HeapImage::build_block(size_t block, uint64_t& allocation) const {
    const uint64_t header = ltp::hn_block_header_size(block);
    const uint64_t slots = block_slots_[block];
    const uint64_t ib_hnpm = block_ib_hnpm(block);
    const uint64_t cb = ib_hnpm + page_map_bytes(slots);
    // Outlook keeps every nonfinal HN leaf at full data capacity, including after freeing
    // almost all its items (research/m5-heap-compatibility.md). Shrinking these leaves made
    // Outlook grow the page map past their BBT cb on its first table update. The reserved tail
    // is free space inside cb, not a heap allocation or NDB alignment padding.
    const uint64_t stored_cb =
        block + 1 < block_alloc_end_.size() ? ndb::block_max_cb(kProfile) : cb;
    std::vector<uint8_t> image(stored_cb, 0);
    put_u16(image, ltp::kHnIbHnpmOffset, static_cast<uint16_t>(ib_hnpm));
    if (block == 0) {
        // [MS-PST] 2.3.1.2: only the first data block of an HN carries the bSig, bClientSig and
        // hidUserRoot of the HNHDR; the rest carry ibHnpm alone, or ibHnpm plus a Fill Level
        // Map.
        image[ltp::kHnSigOffset] = ltp::kHnSignature;
        image[ltp::kHnClientSigOffset] = client_sig_;
        put_u32(image, ltp::kHnUserRootOffset, hid(1));
    }
    // Fill maps are populated after all block headers exist; absent slots stay zero.

    uint64_t at = header;
    for (uint64_t slot = 1; slot <= slots; ++slot, ++allocation) {
        uint64_t item_size = 0;
        if (disk_) {
            const auto record = disk_->records.get(allocation);
            if (!disk_->records.status().ok())
                return disk_->records.status().error();
            item_size = record.size;
            auto read = disk_->values->read_at(record.offset, image.data() + at, record.size);
            if (!read.ok())
                return read.error();
        } else {
            const auto& item = allocations_[static_cast<size_t>(allocation)];
            item_size = item.size();
            std::copy(item.begin(), item.end(), image.begin() + static_cast<size_t>(at));
        }
        // [MS-PST] 2.3.1.5: rgibAlloc[n] is the start of the (n + 1)th allocation of this
        // block.
        put_u16(image, ib_hnpm + ltp::kHnPageMapTableOffset + (slot - 1) * ltp::kHnPageMapEntrySize,
                static_cast<uint16_t>(at));
        at += item_size;
    }
    put_u16(image, ib_hnpm + ltp::kHnPageMapCAllocOffset, static_cast<uint16_t>(slots));
    // cFree stays zero: the writer never frees a heap item.
    // [MS-PST] 2.3.1.5: the entry past the last allocation marks the next available slot, which
    // is before any alignment gap preceding the HNPAGEMAP.
    put_u16(image, ib_hnpm + ltp::kHnPageMapTableOffset + slots * ltp::kHnPageMapEntrySize,
            static_cast<uint16_t>(at));
    // Fill maps can be derived from placement without building every block image.
    const size_t first = block == 0 ? 0 : block;
    const size_t limit = block == 0 ? std::min<size_t>(8, block_count())
                                    : (block >= 8 && (block - 8) % 128 == 0
                                           ? std::min<size_t>(block + 128, block_count())
                                           : block);
    for (size_t child = first; child < limit; ++child) {
        // [MS-PST] 2.3.1.2 / 2.3.1.4: 8 slots in HNHDR, then 128 per HNBITMAPHDR.
        const size_t slot = child < 8 ? child : (child - 8) % 128;
        const size_t offset = (block == 0 ? 8 : 2) + slot / 2;
        const uint64_t used = block_ib_hnpm(child) + page_map_bytes(block_slots_[child]);
        image[offset] |= static_cast<uint8_t>(fill_level(used) << (4 * (slot % 2)));
    }
    return image;
}
Status HeapImage::stream_blocks(const util::ByteConsumer& consume) const {
    uint64_t allocation = 0;
    for (size_t block = 0; block < block_count(); ++block) {
        auto built = build_block(block, allocation);
        if (!built.ok())
            return built.error();
        const auto& bytes = built.value();
        auto accepted = consume(util::ByteView(bytes.data(), bytes.size()));
        if (!accepted.ok())
            return accepted;
    }
    return {};
}
std::vector<std::vector<uint8_t>> HeapImage::build() const {
    std::vector<std::vector<uint8_t>> blocks;
    auto result = stream_blocks([&](util::ByteView bytes) -> Status {
        blocks.emplace_back(bytes.data(), bytes.data() + bytes.size());
        return {};
    });
    // Legacy materialization is used only by in-memory callers. Production spill
    // consumers use stream_blocks and propagate its Status directly.
    if (!result.ok())
        throw std::runtime_error(util::format_error(result.error()));
    return blocks;
}

} // namespace ost2pst::writer
