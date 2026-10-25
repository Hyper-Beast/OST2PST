// Every PC and TC the writer emits is a heap node, so this file checks the builder against the one
// HN the spec spells out byte for byte ([MS-PST] 3.8, tests/fixtures/spec-example-hn.bin) and then
// reads the built image back through the reader's own HN decode ([MS-PST] 2.3.1.2 / 2.3.1.5
// / 2.3.1.1).
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <vector>

#include "ost2pst/ltp/block_heap.h"
#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/hn_block.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"
#include "ost2pst/writer/heap.h"
#include "ost2pst/writer/layout.h"

#include "test_support.h"

namespace {

using ost2pst::ltp::decode_hn_header;
using ost2pst::ltp::decode_hn_page_map;
using ost2pst::ltp::hn_heap_item;
using ost2pst::ltp::HnHeader;
using ost2pst::ltp::HnPageMap;
using ost2pst::ndb::FileProfile;
using ost2pst::test::fixture_path;
using ost2pst::test::read_bytes;
using ost2pst::util::ByteView;
using ost2pst::util::ErrorKind;
using ost2pst::util::Result;
using ost2pst::writer::HeapImage;

// The writer emits the 512-byte profile, and the spec's sample HN sits at 0x4800 ([MS-PST] 3.8).
constexpr FileProfile kProfile = FileProfile::kPst;
constexpr uint64_t kBlockBase = 0x4800;

ByteView view_of(const std::vector<uint8_t>& bytes) {
    return ByteView(bytes.data(), bytes.size(), kBlockBase);
}

void check_spec_sample() {
    const std::vector<uint8_t> sample = read_bytes(fixture_path("spec-example-hn.bin"));
    TEST_EQ(sample.size(), 258, "spec sample HN size");
    if (sample.size() != 258) {
        return;
    }

    Result<HnHeader> header = decode_hn_header(view_of(sample));
    TEST_OK(header, "spec sample HNHDR");
    if (!header.ok()) {
        return;
    }
    TEST_EQ(header.value().ib_hnpm, 0xEC, "spec sample ibHnpm");
    TEST_EQ(header.value().b_sig, 0xEC, "spec sample bSig");
    TEST_EQ(header.value().b_client_sig, 0xBC, "spec sample bClientSig");
    TEST_EQ(header.value().hid_user_root, 0x20, "spec sample hidUserRoot");
    TEST_EQ(header.value().rgb_fill_level, 0, "spec sample rgbFillLevel");

    Result<HnPageMap> map = decode_hn_page_map(view_of(sample), header.value().ib_hnpm);
    TEST_OK(map, "spec sample HNPAGEMAP");
    if (!map.ok()) {
        return;
    }
    TEST_EQ(map.value().c_alloc, 8, "spec sample cAlloc");
    TEST_EQ(map.value().c_free, 0, "spec sample cFree");
    const uint16_t expected[] = {0x000C, 0x0014, 0x006C, 0x007C, 0x008C,
                                 0x00A4, 0x00BC, 0x00D4, 0x00EC};
    for (int index = 0; index < 9; ++index) {
        TEST_EQ(map.value().offsets[static_cast<size_t>(index)], expected[index],
                "spec sample rgibAlloc");
    }

    // Rebuilt from its own allocations, the writer has to produce the same 258 bytes.
    HeapImage rebuilt(header.value().b_client_sig);
    for (uint16_t index = 1; index <= map.value().c_alloc; ++index) {
        Result<ByteView> item =
            hn_heap_item(map.value(), view_of(sample), static_cast<uint32_t>(index << 5), kProfile);
        TEST_OK(item, "spec sample allocation");
        if (!item.ok()) {
            return;
        }
        Result<uint32_t> hid = rebuilt.append(
            std::vector<uint8_t>(item.value().data(), item.value().data() + item.value().size()));
        TEST_OK(hid, "rebuild allocation");
        if (!hid.ok()) {
            return;
        }
        TEST_EQ(hid.value(), static_cast<uint64_t>(index) << 5,
                "the nth allocation is HID (n << 5)");
    }
    TEST_CHECK(rebuilt.bytes() == sample);
    TEST_EQ(rebuilt.ib_hnpm(), 0xEC, "rebuilt ibHnpm");
    TEST_EQ(rebuilt.hid_user_root(), 0x20, "rebuilt hidUserRoot");
}

void check_reader_round_trip() {
    const std::vector<uint8_t> first = {0xB5, 0x02, 0x06, 0x00, 0x40, 0x00, 0x00, 0x00};
    const std::vector<uint8_t> second(88, 0x5A);
    const std::vector<uint8_t> third(16, 0x33);

    HeapImage heap(0xBC);
    Result<uint32_t> first_hid = heap.append(first);
    Result<uint32_t> second_hid = heap.append(second);
    Result<uint32_t> third_hid = heap.append(third);
    TEST_OK(first_hid, "append allocation 1");
    TEST_OK(second_hid, "append allocation 2");
    TEST_OK(third_hid, "append allocation 3");
    TEST_EQ(first_hid.value(), 0x20, "HID 1");
    TEST_EQ(second_hid.value(), 0x40, "HID 2");
    TEST_EQ(third_hid.value(), 0x60, "HID 3");
    TEST_EQ(heap.allocation_count(), 3, "allocation count");
    // cb is HNHDR + allocations + HNPAGEMAP: no trailer, no padding ([MS-PST] 2.2.2.8.1).
    TEST_EQ(heap.bytes().size(), 12 + 88 + 8 + 16 + 4 + 2 * 4, "cb");
    TEST_EQ(heap.ib_hnpm(), 12 + 8 + 88 + 16, "ibHnpm");

    Result<HnHeader> header = decode_hn_header(view_of(heap.bytes()));
    TEST_OK(header, "built HNHDR");
    if (!header.ok()) {
        return;
    }
    TEST_EQ(header.value().ib_hnpm, heap.ib_hnpm(), "built ibHnpm read back");
    TEST_EQ(header.value().b_sig, 0xEC, "built bSig");
    TEST_EQ(header.value().b_client_sig, 0xBC, "built bClientSig");
    TEST_EQ(header.value().hid_user_root, 0x20, "built hidUserRoot");
    TEST_EQ(header.value().rgb_fill_level, 0, "built rgbFillLevel is FILL_LEVEL_EMPTY");

    Result<HnPageMap> map = decode_hn_page_map(view_of(heap.bytes()), header.value().ib_hnpm);
    TEST_OK(map, "built HNPAGEMAP");
    if (!map.ok()) {
        return;
    }
    TEST_EQ(map.value().c_alloc, 3, "built cAlloc");
    TEST_EQ(map.value().c_free, 0, "built cFree");
    const uint16_t expected[] = {0x000C, 0x0014, 0x006C, 0x007C};
    for (int index = 0; index < 4; ++index) {
        TEST_EQ(map.value().offsets[static_cast<size_t>(index)], expected[index],
                "built rgibAlloc");
    }

    const std::vector<uint8_t>* want[] = {&first, &second, &third};
    const uint32_t hids[] = {0x20, 0x40, 0x60};
    for (int index = 0; index < 3; ++index) {
        Result<ByteView> item =
            hn_heap_item(map.value(), view_of(heap.bytes()), hids[index], kProfile);
        TEST_OK(item, "heap item");
        if (!item.ok()) {
            continue;
        }
        const ByteView window = item.value();
        TEST_EQ(window.size(), want[index]->size(), "heap item size");
        TEST_CHECK(window.size() == want[index]->size() &&
                   std::equal(window.data(), window.data() + window.size(), want[index]->begin()));
        TEST_EQ(window.base(), kBlockBase + expected[index], "heap item absolute offset");
    }

    // A HID past the last allocation is a data error, not a read past the map ([MS-PST] 2.3.1.1).
    TEST_ERROR(hn_heap_item(map.value(), view_of(heap.bytes()), 0x80, kProfile),
               ErrorKind::kBadField, "HNPAGEMAP.cAlloc", "HID 0x80 names allocation 4");
    // A HID whose type bits are not NID_TYPE_HID is a node id, not a heap id.
    TEST_ERROR(hn_heap_item(map.value(), view_of(heap.bytes()), 0x21, kProfile),
               ErrorKind::kBadField, "HID", "a NID is not a heap id");
}

void check_writer_rejections() {
    HeapImage empty(0xBC);
    TEST_ERROR(empty.append(std::vector<uint8_t>{}), ErrorKind::kBadField,
               "writer.HeapImage.append", "an empty allocation");
    TEST_EQ(empty.allocation_count(), 0, "a rejected append leaves the heap unchanged");

    // This exceeds the writer's conservative packing target. It is not a format size limit.
    HeapImage too_big(0xBC);
    TEST_ERROR(too_big.append(std::vector<uint8_t>(4600, 0x11)), ErrorKind::kBadField,
               "writer.heap.allocation_capacity", "a block past the packing target");
    TEST_EQ(too_big.allocation_count(), 0, "a rejected append leaves the heap unchanged");

    // cb is HNHDR + allocation + HNPAGEMAP, so the largest single allocation is 4608 - 12 - 8
    // bytes.
    HeapImage fits(0xBC);
    TEST_OK(fits.append(std::vector<uint8_t>(4588, 0x11)), "a block at the packing target");
    TEST_EQ(fits.ib_hnpm(), 4600, "map position at the packing target");
    TEST_EQ(fits.bytes().size(), 4608, "cb at the limit");
}

void check_odd_payload_keeps_length_and_aligns_map() {
    // SCANPST rejected the old odd ibHnpm in both populated hierarchy tables.
    // The Outlook oracle places a gap before its map without extending the last item.
    HeapImage heap(0xBC);
    TEST_OK(heap.append({0x11, 0x22, 0x33}), "odd payload");
    TEST_EQ(heap.ib_hnpm(), 16u, "WORD-aligned map after a three-byte payload");
    auto map = decode_hn_page_map(view_of(heap.bytes()), heap.ib_hnpm());
    TEST_OK(map, "odd payload map");
    if (!map.ok())
        return;
    auto item = hn_heap_item(map.value(), view_of(heap.bytes()), heap.hid(1), kProfile);
    TEST_OK(item, "odd payload readback");
    if (item.ok()) {
        TEST_EQ(item.value().size(), 3u, "map alignment must not pad the value");
        TEST_EQ(item.value().data()[2], 0x33u, "last payload byte");
    }
    TEST_EQ(map.value().offsets.back(), 15u, "allocation endpoint excludes alignment gap");
    TEST_OK(heap.append({0x44}), "append after odd payload");
    TEST_EQ(heap.ib_hnpm(), 16u, "two payloads with an even total need no gap");
}

// A Message PC or a Contents Table heap is bigger than one data block: the sample's Message PC
// 0x002001C4 holds 114 allocations in 12,774 heap bytes and its ACSL Contents Table holds 750 in
// 103,192 (DEVELOPMENT.md, research/subtree-852E-acsl-contents.txt). Nine 4500-byte allocations is
// the shortest node that also reaches the HNBITMAPHDR at block 8 ([MS-PST] 2.3.1.4).
void check_multi_block_heap() {
    HeapImage heap(0xBC);
    std::vector<uint32_t> hids;
    for (int index = 0; index < 9; ++index) {
        Result<uint32_t> hid =
            heap.append(std::vector<uint8_t>(4500, static_cast<uint8_t>(0xA0 + index)));
        TEST_OK(hid, "an allocation that opens the next block");
        if (!hid.ok()) {
            return;
        }
        hids.push_back(hid.value());
    }
    TEST_EQ(heap.allocation_count(), 9u, "allocation count");
    TEST_EQ(heap.block_count(), 9u, "nine 4500-byte allocations need nine data blocks");

    // [MS-PST] 2.3.1.1: a HID names the data block its item lives in. Block 0 keeps the numbering
    // the single-block case had, so nothing about a small heap node changed.
    TEST_EQ(hids[0], 0x20u, "the first allocation is still HID 0x20");
    TEST_EQ(hids[1], 0x00010020u, "the second block's first allocation");
    TEST_EQ(hids[8], 0x00080020u, "the ninth block's first allocation");
    for (size_t index = 0; index < hids.size(); ++index) {
        TEST_EQ(ost2pst::ltp::hid_block_index(hids[index], kProfile), index,
                "hidBlockIndex names the block");
        TEST_EQ(ost2pst::ltp::hid_index(hids[index], kProfile), 1u,
                "one allocation per block, numbered 1");
    }

    const std::vector<std::vector<uint8_t>>& blocks = heap.blocks();
    TEST_EQ(blocks.size(), 9u, "one image per data block");
    std::vector<ost2pst::ltp::HnFragment> fragments;
    for (size_t index = 0; index < blocks.size(); ++index) {
        const uint64_t header = ost2pst::ltp::hn_block_header_size(index);
        // Outlook retains full nonfinal HN blocks even after freeing their contents:
        // research/m5-heap-compatibility.md. The tail is free capacity, not part of an item.
        const uint64_t used = header + 4500 + 4 + 2 * 2;
        TEST_EQ(blocks[index].size(), index + 1 < blocks.size() ? 8176u : used, "block cb");
        TEST_CHECK(std::all_of(blocks[index].begin() + used, blocks[index].end(),
                               [](uint8_t byte) { return byte == 0; }));

        const ByteView view(blocks[index].data(), blocks[index].size(),
                            kBlockBase + index * 0x10000);
        Result<HnPageMap> map = decode_hn_page_map(view, static_cast<uint16_t>(header + 4500));
        TEST_OK(map, "the block's own HNPAGEMAP");
        if (!map.ok()) {
            continue;
        }
        TEST_EQ(map.value().c_alloc, 1u, "one allocation in this block");
        TEST_EQ(map.value().offsets[0], header,
                "the allocation starts after the header this block carries");
        Result<ByteView> item = hn_heap_item(map.value(), view, hids[index], kProfile);
        TEST_OK(item, "the item the HID names");
        if (item.ok()) {
            TEST_EQ(item.value().size(), 4500u, "item size");
            TEST_EQ(item.value().data()[0], static_cast<uint8_t>(0xA0 + index), "item bytes");
        }

        ost2pst::ltp::HnFragment fragment;
        fragment.owned = blocks[index];
        fragment.block.form = ost2pst::ltp::BlockForm::kRaw;
        fragment.block.block_base = kBlockBase + index * 0x10000;
        fragment.block.raw_block =
            ByteView(fragment.owned.data(), fragment.owned.size(), fragment.block.block_base);
        fragment.page_map = map.take();
        fragment.page_map_ok = true;
        fragments.push_back(std::move(fragment));
    }

    // [MS-PST] 2.3.1.2 / 2.3.1.3 / 2.3.1.4: only block 0 carries bSig, bClientSig and hidUserRoot;
    // block 8 and every 128th block after it carries a Fill Level Map; the blocks in between carry
    // ibHnpm alone.
    TEST_EQ(blocks[0][ost2pst::ltp::kHnSigOffset], ost2pst::ltp::kHnSignature, "block 0 bSig");
    TEST_EQ(blocks[0][ost2pst::ltp::kHnClientSigOffset], 0xBC, "block 0 bClientSig");
    TEST_EQ(heap.hid_user_root(), 0x20u, "hidUserRoot is still the first allocation");
    for (size_t index = 1; index < blocks.size(); ++index) {
        TEST_CHECK(!ost2pst::ltp::hn_block_carries_fill_level(index) || index == 8);
        if (ost2pst::ltp::hn_block_carries_fill_level(index)) {
            for (uint64_t byte = 2; byte < 66; ++byte) {
                TEST_EQ(blocks[index][static_cast<size_t>(byte)], 0u,
                        "an unused Fill Level slot is zero ([MS-PST] 2.3.1.2)");
            }
        }
    }

    // The reader reaches a multi-block node's items through its data tree fragments, which is
    // exactly the source open_node builds for a node whose bidData is an XBLOCK
    // ([MS-PST] 2.2.2.8.3.2.1 / 2.3.1.6.2).
    ost2pst::ltp::NodeFragmentHeapSource source(fragments, kProfile);
    for (size_t index = 0; index < hids.size(); ++index) {
        Result<ByteView> item = source.heap(hids[index]);
        TEST_OK(item, "the reader reads every block of the node");
        if (item.ok()) {
            TEST_EQ(item.value().data()[0], static_cast<uint8_t>(0xA0 + index),
                    "item from the right block");
        }
    }
    TEST_EQ(source.cross_block_misses, 0u, "no HID named a block the node does not have");
}

void check_allocation_too_big_for_any_block() {
    // The packing target still limits individual allocations; this repair changes stored capacity,
    // not placement. [MS-PST] 2.3.1.1 addresses an allocation within one block.
    HeapImage too_big(0xBC);
    TEST_ERROR(too_big.append(std::vector<uint8_t>(4600, 0x11)), ErrorKind::kBadField,
               "writer.heap.allocation_capacity", "one allocation larger than a data block");
    TEST_EQ(too_big.allocation_count(), 0u, "a rejected append leaves the heap unchanged");
    TEST_EQ(too_big.block_count(), 1u, "and opens no block");

    // The same rule on a fresh block: a block after the first carries a 2-byte header instead of
    // the 12-byte HNHDR, so it has more room for one allocation -- but 4700 bytes is past the
    // packing target under either header, and the block the writer opened for it must not be left
    // behind.
    HeapImage partial(0xBC);
    TEST_OK(partial.append(std::vector<uint8_t>(4000, 0x22)), "an allocation that fills block 0");
    TEST_OK(partial.append(std::vector<uint8_t>(4590, 0x11)),
            "4590 bytes fits a block with no HNHDR");
    TEST_EQ(partial.block_count(), 2u, "and it opened the second block");
    TEST_ERROR(partial.append(std::vector<uint8_t>(4610, 0x11)), ErrorKind::kBadField,
               "writer.heap.allocation_capacity", "too large for a fresh block as well");
    TEST_EQ(partial.allocation_count(), 2u, "the rejected allocation is not kept");
    TEST_EQ(partial.block_count(), 2u, "and neither is the block it would have opened");
    TEST_EQ(partial.bytes().size(), 8176u, "nonfinal block retains its capacity");
}

void check_fill_level_uses_data_capacity() {
    // 4608 used bytes leave 3568 bytes of the 8176-byte data capacity free, level 1,
    // not level 0: the 16-byte NDB trailer is not available to the heap.
    HeapImage heap(0xBC);
    TEST_OK(heap.append(std::vector<uint8_t>(4588, 0x11)), "near the packing target");
    TEST_EQ(heap.bytes()[8] & 15, 1u, "fill level excludes trailer capacity");
    TEST_OK(heap.append(std::vector<uint8_t>(4500, 0x22)), "open another block");
    TEST_EQ(heap.bytes().size(), 8176u, "prior block becomes a full data block");
    TEST_EQ(heap.bytes()[8] & 15, 1u, "reserving the tail does not consume its free space");
    TEST_EQ(heap.bytes()[8] >> 4, 0u, "next block has at least 3584 bytes free");
    HeapImage bitmap(0xBC);
    for (size_t i = 0; i < 137; ++i) {
        TEST_OK(bitmap.append(std::vector<uint8_t>(4534, 0x33)), "bitmap-boundary allocation");
    }
    for (const size_t owner : {size_t{8}, size_t{136}}) {
        TEST_EQ(bitmap.blocks()[owner][2] & 15, 1u, "bitmap header reduces available capacity");
        TEST_EQ(bitmap.blocks()[owner][2] >> 4, 0u, "following or absent block is level zero");
    }
}

// A header has to name the HID of an allocation that does not exist yet, so the writer appends the
// header first and patches it in later. Patching rewrites bytes inside an allocation whose size
// does not change, so every HID already handed out still names the same bytes.
void check_patch_names_an_allocation_that_comes_later() {
    HeapImage heap(0xBC);
    TEST_OK(heap.append(std::vector<uint8_t>(16, 0)), "the header allocation");
    TEST_OK(heap.append(std::vector<uint8_t>(4590, 0x33)), "an allocation that opens block 1");
    const uint32_t target = heap.hid(2);
    TEST_EQ(target, 0x00010020u, "the HID of the allocation in block 1");
    const size_t before = heap.blocks()[0].size();

    TEST_OK(heap.patch(1, 4, target), "name it in the header");
    TEST_EQ(heap.blocks()[0].size(), before, "a patch does not change the block");
    TEST_EQ(heap.hid(1), 0x20u, "the patched allocation keeps its HID");
    TEST_EQ(heap.hid(2), target, "and so does the one it names");
    const ByteView view(heap.blocks()[0].data(), heap.blocks()[0].size(), kBlockBase);
    // Offset 4 of allocation 1, which starts after the 12-byte HNHDR ([MS-PST] 2.3.1.2).
    Result<uint32_t> named = view.u32(12 + 4);
    TEST_OK(named, "the patched field");
    if (named.ok()) {
        TEST_EQ(named.value(), target, "the header now names the later allocation");
    }

    TEST_ERROR(heap.patch(1, 14, 1u), ErrorKind::kBadField, "writer.HeapImage.patch",
               "4 bytes past the end of the allocation");
    TEST_ERROR(heap.patch(3, 0, 1u), ErrorKind::kBadField, "writer.HeapImage.patch",
               "no allocation with that index");
    TEST_EQ(heap.allocation_count(), 2u, "a rejected patch changes nothing");
    TEST_EQ(heap.blocks()[0].size(), before, "and does not resize the block");
}

void check_spill_copy_and_hid_capacity() {
    auto resources = std::make_shared<ost2pst::util::Workspace>(
        std::filesystem::temp_directory_path().wstring(), 128 * 1024);
    {
        HeapImage original(0xBC);
        original.enable_spill(resources);
        TEST_OK(original.append({1, 2, 3, 4}), "spooled heap allocation");
        HeapImage copy = original;
        TEST_OK(copy.patch(1, 0, 0x88776655u), "copy-on-write spooled heap patch");
        TEST_OK(copy.append({9, 10}), "append to copied spooled heap");
        TEST_EQ(original.allocation_count(), 1u, "original allocation count unchanged");
        TEST_EQ(copy.allocation_count(), 2u, "copy owns appended item");
        size_t blocks = 0;
        TEST_OK(original.stream_blocks([&](ByteView image) -> ost2pst::util::Status {
            TEST_EQ(image.u32(12).value(), 0x04030201u, "original bytes unchanged");
            ++blocks;
            return {};
        }),
                "stream original after modifying its copy");
        TEST_EQ(blocks, 1u, "one original block");
    }
    {
        HeapImage heap(0xBC);
        heap.enable_spill(resources);
        // 3580-byte allocations cannot share a block under the existing packing
        // policy. Reach the actual HID boundary without retaining their payloads.
        for (uint64_t block = 0; block < ost2pst::ltp::kDataTreeMaxBlocks512; ++block) {
            auto appended = heap.append(std::vector<uint8_t>(3580, 0x53));
            TEST_OK(appended, "HID addressable block");
            if (!appended.ok())
                return;
            TEST_EQ(ost2pst::ltp::hid_block_index(appended.value(), kProfile), block,
                    "HID block index never wraps");
        }
        TEST_ERROR(heap.append(std::vector<uint8_t>(3580, 0x54)), ErrorKind::kUnsupported,
                   "writer.heap.block_index", "format bound still enforced with disk scratch");
        TEST_EQ(heap.block_count(), ost2pst::ltp::kDataTreeMaxBlocks512, "refusal adds no block");
        TEST_CHECK(resources->memory->peak() <= resources->memory->limit());
    }
    TEST_EQ(resources->memory->used(), 0u, "heap scratch released");
}
} // namespace

int main() {
    check_spec_sample();
    check_reader_round_trip();
    check_writer_rejections();
    check_odd_payload_keeps_length_and_aligns_map();
    check_multi_block_heap();
    check_allocation_too_big_for_any_block();
    check_fill_level_uses_data_capacity();
    check_patch_names_an_allocation_that_comes_later();
    check_spill_copy_and_hid_capacity();
    return ost2pst::test::finish("writer_heap_test");
}
