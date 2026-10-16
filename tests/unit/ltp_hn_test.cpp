// The heap node is what an NBTENTRY.bidData actually points at, so the two things this file checks are
// the two questions every later LTP step asks: is this block a heap node at all ([MS-PST] 2.3.1.2), and
// which bytes does a heap id name ([MS-PST] 2.3.1.1 / 2.3.1.5).
#include <cstdint>
#include <vector>

#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"
#include "test_support.h"

namespace {

using ost2pst::ltp::decode_hn_header;
using ost2pst::ltp::decode_hn_page_map;
using ost2pst::ltp::HnHeader;
using ost2pst::ltp::HnPageMap;
using ost2pst::ltp::hn_allocation;
using ost2pst::ltp::hn_heap_item;
using ost2pst::ndb::FileProfile;
using ost2pst::util::ByteView;
using ost2pst::util::ErrorKind;
using ost2pst::util::Result;

constexpr uint64_t kBlockBase = 0x4000;
constexpr uint64_t kBlockSize = 512;
constexpr uint16_t kIbHnpm = 0x40;

// The fixture is a plain 512-byte-profile heap node.
constexpr FileProfile kProfile = FileProfile::kPst;

// A block that is a valid HN: HNHDR at 0, HNPAGEMAP at 0x40, three allocations at 0x0C, 0x14 and 0x92.
std::vector<uint8_t> make_block() {
    std::vector<uint8_t> block(kBlockSize, 0);
    // The allocation bytes go in first: the page map sits inside the allocation range, so writing it
    // last is what keeps cAlloc and rgibAlloc readable.
    for (uint64_t at = 0x0C; at < 0xAA; ++at) {
        block[at] = static_cast<uint8_t>(0xA0 + (at % 16));
    }
    block[0] = static_cast<uint8_t>(kIbHnpm & 0xFF);
    block[1] = static_cast<uint8_t>(kIbHnpm >> 8);
    block[2] = 0xEC;   // [MS-PST] 2.3.1.2 bSig
    block[3] = 0xBC;   // [MS-PST] 2.3.1.2 bClientSig: a property context
    block[4] = 0x20;   // [MS-PST] 2.3.1.2 hidUserRoot = HID 0x20, allocation 1
    block[kIbHnpm] = 3;
    block[kIbHnpm + 1] = 0;
    block[kIbHnpm + 2] = 0; // cFree
    block[kIbHnpm + 3] = 0;
    const uint16_t offsets[] = {0x000C, 0x0014, 0x0092, 0x00AA};
    for (int index = 0; index < 4; ++index) {
        block[kIbHnpm + 4 + index * 2] = static_cast<uint8_t>(offsets[index] & 0xFF);
        block[kIbHnpm + 5 + index * 2] = static_cast<uint8_t>(offsets[index] >> 8);
    }
    return block;
}

ByteView view_of(const std::vector<uint8_t> &block) {
    return ByteView(block.data(), block.size(), kBlockBase);
}

void check_hn_header() {
    const std::vector<uint8_t> block = make_block();
    Result<HnHeader> header = decode_hn_header(view_of(block));
    TEST_OK(header, "decode_hn_header");
    if (!header.ok()) {
        return;
    }
    TEST_EQ(header.value().ib_hnpm, kIbHnpm, "ibHnpm");
    TEST_EQ(header.value().b_sig, 0xEC, "bSig");
    TEST_EQ(header.value().b_client_sig, 0xBC, "bClientSig");
    TEST_EQ(header.value().hid_user_root, 0x20, "hidUserRoot");
    TEST_STR(ost2pst::ltp::client_sig_name(0xBC), "PC", "bClientSig name");
    TEST_STR(ost2pst::ltp::client_sig_name(0x7C), "TC", "bClientSig name for a table context");
    TEST_STR(ost2pst::ltp::client_sig_name(0xB5), "BTH", "bClientSig name for a bare tree");
    TEST_STR(ost2pst::ltp::client_sig_name(0x00), "unknown", "an undefined bClientSig is reported, not guessed");

    std::vector<uint8_t> not_an_hn = make_block();
    not_an_hn[2] = 0x00;
    TEST_ERROR(decode_hn_header(view_of(not_an_hn)), ErrorKind::kBadField, "HNHDR.bSig", "bSig is not 0xEC");
    TEST_ERROR_OFFSET(decode_hn_header(view_of(not_an_hn)), kBlockBase + 2, "bSig error offset");

    const std::vector<uint8_t> short_block(kBlockSize - 510);
    TEST_ERROR(decode_hn_header(view_of(short_block)), ErrorKind::kTruncated, "HNHDR", "block shorter than the HNHDR");
}

void check_page_map_and_heap_items() {
    const std::vector<uint8_t> block_bytes = make_block();
    const ByteView block = view_of(block_bytes);
    Result<HnPageMap> map = decode_hn_page_map(block, kIbHnpm);
    TEST_OK(map, "decode_hn_page_map");
    if (!map.ok()) {
        return;
    }
    TEST_EQ(map.value().c_alloc, 3, "cAlloc");
    TEST_EQ(map.value().c_free, 0, "cFree");
    TEST_EQ(map.value().offsets.size(), 4, "rgibAlloc holds cAlloc + 1 entries");
    TEST_EQ(map.value().base, kBlockBase + kIbHnpm, "the page map reports its absolute offset");

    // [MS-PST] 2.3.1.1: HID 0x20 is allocation 1, so it must name [rgibAlloc[0], rgibAlloc[1]).
    Result<ByteView> first = hn_heap_item(map.value(), block, 0x20, kProfile);
    TEST_OK(first, "heap item 0x20");
    if (first.ok()) {
        TEST_EQ(first.value().size(), 0x14 - 0x0C, "allocation 1 size");
        TEST_EQ(first.value().base(), kBlockBase + 0x0C, "allocation 1 absolute offset");
        TEST_EQ(first.value().data()[0], block_bytes[0x0C], "allocation 1 bytes");
    }
    Result<ByteView> second = hn_heap_item(map.value(), block, 0x40, kProfile);
    TEST_OK(second, "heap item 0x40");
    if (second.ok()) {
        TEST_EQ(second.value().size(), 0x92 - 0x14, "allocation 2 size");
        TEST_EQ(second.value().base(), kBlockBase + 0x14, "allocation 2 absolute offset");
    }
    TEST_OK(hn_allocation(map.value(), block, 3), "allocation 3");
    TEST_ERROR(hn_allocation(map.value(), block, 0), ErrorKind::kBadField, "HNPAGEMAP.cAlloc",
               "allocation 0 does not exist: hidIndex is 1-based");
    TEST_ERROR(hn_allocation(map.value(), block, 4), ErrorKind::kBadField, "HNPAGEMAP.cAlloc",
               "allocation past cAlloc");
    TEST_ERROR(hn_heap_item(map.value(), block, 0, kProfile), ErrorKind::kBadField, "HID",
               "HID 0 names nothing");
    TEST_ERROR(hn_heap_item(map.value(), block, 0x21, kProfile), ErrorKind::kBadField, "HID",
               "hidType 1 is a node id, not a heap id");
    // An allocation the 512 profile cannot name is readable under the 4 KiB one, which is the whole point
    // of passing the profile in rather than decoding with one layout and hoping.
    TEST_ERROR(hn_heap_item(map.value(), block, 2048u << 5, kProfile), ErrorKind::kBadField, "HID",
               "allocation 2048 is outside the 11-bit field of the 512 profile");
}

void check_page_map_rejects_nonsense() {
    {
        // [MS-PST] 2.3.1.5 sets no minimum for cAlloc. cAlloc 0 with rgibAlloc[0] == ibHnpm is the shape
        // the sample's empty heap blocks have: no items, and the next free slot right after the header.
        std::vector<uint8_t> block = make_block();
        block[kIbHnpm] = 0; // cAlloc 0
        block[kIbHnpm + 4] = static_cast<uint8_t>(kIbHnpm & 0xFF);
        block[kIbHnpm + 5] = static_cast<uint8_t>(kIbHnpm >> 8);
        Result<HnPageMap> empty = decode_hn_page_map(view_of(block), kIbHnpm);
        TEST_OK(empty, "cAlloc 0 decodes as an empty allocation table");
        if (empty.ok()) {
            TEST_EQ(empty.value().c_alloc, 0, "cAlloc 0");
            TEST_EQ(empty.value().offsets.size(), 1, "rgibAlloc holds cAlloc + 1 entries");
            TEST_EQ(empty.value().offsets[0], kIbHnpm, "the single entry is the next free slot");
            TEST_ERROR(hn_allocation(empty.value(), view_of(block), 1), ErrorKind::kBadField,
                       "HNPAGEMAP.cAlloc", "an empty table answers for no allocation");
        }
    }
    {
        std::vector<uint8_t> block = make_block();
        block[kIbHnpm + 4] = 0x80; // rgibAlloc[0] = 0x80, past the next entry: descending order
        TEST_ERROR(decode_hn_page_map(view_of(block), kIbHnpm), ErrorKind::kBadField,
                   "HNPAGEMAP.rgibAlloc", "allocations out of order");
    }
    {
        std::vector<uint8_t> block = make_block();
        block[kIbHnpm + 6] = 0xFF; // rgibAlloc[1] = 0xFF14, past the end of the block
        block[kIbHnpm + 7] = 0xFF;
        TEST_ERROR(decode_hn_page_map(view_of(block), kIbHnpm), ErrorKind::kBadField,
                   "HNPAGEMAP.rgibAlloc", "offset past the end of the block");
    }
    {
        std::vector<uint8_t> block = make_block();
        const uint16_t far = static_cast<uint16_t>(kBlockSize + 0x10);
        block[0] = static_cast<uint8_t>(far & 0xFF);
        block[1] = static_cast<uint8_t>(far >> 8);
        TEST_ERROR(decode_hn_page_map(view_of(block), far), ErrorKind::kBadField, "HNHDR.ibHnpm",
                   "ibHnpm past the end of the block");
    }
    {
        // cAlloc 3 but only two offset entries fit before the block ends.
        std::vector<uint8_t> block(kBlockSize, 0);
        block[0] = static_cast<uint8_t>(kBlockSize - 8);
        block[2] = 0xEC;
        block[kBlockSize - 8] = 3;
        TEST_ERROR(decode_hn_page_map(view_of(block), kBlockSize - 8), ErrorKind::kTruncated,
                   "HNPAGEMAP.rgibAlloc", "the offset table runs past the block");
    }
}

// The cap the reader used to put on cAlloc (8192) matched neither [MS-PST] 2.2.2.8 (a block is 64..8192
// bytes) nor the 4k profile's 65,536-byte block, and it refused a page map whose rgibAlloc plainly fits
// the block that carries it. This fixture is the sample OST's fullest data block, measured at
// DEVELOPMENT.md: 65,512 data bytes,
// HNPAGEMAP at 0xAD2C, cAlloc 8278, rgibAlloc ascending and every entry inside the block.
void check_page_map_in_the_fullest_measured_block() {
    constexpr uint64_t block_size = 65512;
    constexpr uint16_t ib_hnpm = 0xAD2C;
    constexpr uint16_t c_alloc = 8278;
    constexpr uint16_t c_free = 755;

    auto make_full_block = [&](uint16_t allocations) {
        std::vector<uint8_t> block(block_size, 0);
        block[0] = static_cast<uint8_t>(ib_hnpm & 0xFF);
        block[1] = static_cast<uint8_t>(ib_hnpm >> 8);
        block[2] = 0xEC; // [MS-PST] 2.3.1.2 bSig
        block[3] = 0xBC; // [MS-PST] 2.3.1.2 bClientSig: a property context
        block[ib_hnpm] = static_cast<uint8_t>(allocations & 0xFF);
        block[ib_hnpm + 1] = static_cast<uint8_t>(allocations >> 8);
        block[ib_hnpm + 2] = static_cast<uint8_t>(c_free & 0xFF);
        block[ib_hnpm + 3] = static_cast<uint8_t>(c_free >> 8);
        for (uint16_t index = 0; index <= allocations; ++index) {
            const uint64_t at = ib_hnpm + 4 + 2ull * index;
            if (at + 2 > block_size) {
                break; // the truncated case deliberately leaves the table unfinished
            }
            const uint16_t offset = static_cast<uint16_t>(ib_hnpm + 4 + 2 * index);
            block[at] = static_cast<uint8_t>(offset & 0xFF);
            block[at + 1] = static_cast<uint8_t>(offset >> 8);
        }
        for (uint64_t at = ib_hnpm + 4 + 2ull * (allocations + 1); at < block_size; ++at) {
            block[at] = static_cast<uint8_t>(at & 0xFF);
        }
        return block;
    };

    {
        const std::vector<uint8_t> block = make_full_block(c_alloc);
        const ByteView view(block.data(), block.size(), kBlockBase);
        Result<HnPageMap> map = decode_hn_page_map(view, ib_hnpm);
        TEST_OK(map, "cAlloc 8278 in a 65,512-byte block: the space the block leaves is the only bound");
        if (map.ok()) {
            TEST_EQ(map.value().c_alloc, c_alloc, "cAlloc");
            TEST_EQ(map.value().c_free, c_free, "cFree");
            TEST_EQ(map.value().offsets.size(), c_alloc + 1, "rgibAlloc holds cAlloc + 1 entries");
            // [MS-PST] 2.3.1.1 / 2.3.1.5: allocation 8278 is HID 8278 << 5 under the 4 KiB widths, and it
            // names [rgibAlloc[8277], rgibAlloc[8278]).
            Result<ByteView> last = hn_heap_item(map.value(), view, 8278u << 5, FileProfile::kOst);
            TEST_OK(last, "the last allocation of the fullest block");
            if (last.ok()) {
                TEST_EQ(last.value().base(), kBlockBase + ib_hnpm + 4 + 2ull * (c_alloc - 1),
                        "its absolute offset is rgibAlloc[8277]");
                TEST_EQ(last.value().size(), 2, "it runs to rgibAlloc[8279]");
            }
        }
    }
    {
        // cAlloc 10588 needs 4 + 10,589 * 2 = 21,182 bytes of table; from 0xAD2C the block leaves 21,180.
        const std::vector<uint8_t> block = make_full_block(10588);
        TEST_ERROR(decode_hn_page_map(ByteView(block.data(), block.size(), kBlockBase), ib_hnpm),
                   ErrorKind::kTruncated, "HNPAGEMAP.rgibAlloc",
                   "the offset table runs past the end of the block");
    }
    {
        std::vector<uint8_t> block = make_full_block(c_alloc);
        const uint64_t last_entry = ib_hnpm + 4 + 2ull * c_alloc;
        block[last_entry] = 0xFF; // rgibAlloc[8278] = 0xFFFF, past the 65,512-byte block
        block[last_entry + 1] = 0xFF;
        TEST_ERROR(decode_hn_page_map(ByteView(block.data(), block.size(), kBlockBase), ib_hnpm),
                   ErrorKind::kBadField, "HNPAGEMAP.rgibAlloc", "offset past the end of the block");
    }
    {
        std::vector<uint8_t> block = make_full_block(c_alloc);
        const uint64_t entry = ib_hnpm + 4 + 2ull * 4000;
        block[entry] = 0x00; // rgibAlloc[4000] back to 0: the table cannot go backwards
        block[entry + 1] = 0x00;
        TEST_ERROR(decode_hn_page_map(ByteView(block.data(), block.size(), kBlockBase), ib_hnpm),
                   ErrorKind::kBadField, "HNPAGEMAP.rgibAlloc", "allocations out of order");
    }
}

void check_hid_arithmetic() {
    // [MS-PST] 2.3.1.1 as written: hidType(5) | hidIndex(11) | hidBlockIndex(16).
    constexpr FileProfile k512 = FileProfile::kPst;
    TEST_EQ(ost2pst::ltp::hid_index(0x20, k512), 1, "HID 0x20 is allocation 1");
    TEST_EQ(ost2pst::ltp::hid_index(0x40, k512), 2, "HID 0x40 is allocation 2");
    TEST_EQ(ost2pst::ltp::hid_block_index(0x20, k512), 0, "HID 0x20 lives in data block 0");
    TEST_EQ(ost2pst::ltp::hid_block_index(0x00030020, k512), 3,
            "the top 16 bits are the data block index");
    TEST_EQ(ost2pst::ltp::hid_index(0x00030020, k512), 1, "the allocation index survives a block index");
    TEST_EQ(ost2pst::ltp::hid_type(0x20), 0, "hidType 0 is a heap id");
    TEST_EQ(ost2pst::ltp::hid_type(0x21), 1, "hidType 1 is a node id");
    TEST_CHECK(ost2pst::ltp::hid_is_valid(0x20, k512));
    TEST_CHECK(!ost2pst::ltp::hid_is_valid(0x00, k512));
    TEST_CHECK(!ost2pst::ltp::hid_is_valid(0x21, k512));
    TEST_CHECK(!ost2pst::ltp::hid_is_valid(0x1F, k512));

    // The 4 KiB profile widens the same two fields to 14 and 13 bits (libpff "64-bit 4k page table value
    // reference" :1558-1559). A HID is (allocation << 5) | hidType, so allocation 2048 is HID 0x10000:
    // under the 11-bit field that bit is not an allocation at all, it lands in the block index.
    constexpr FileProfile k4k = FileProfile::kOst;
    const uint32_t alloc_2047 = 2047u << 5;
    const uint32_t alloc_2048 = 2048u << 5;
    TEST_EQ(ost2pst::ltp::hid_index(alloc_2047, k512), 2047, "allocation 2047 fits the 11-bit field");
    TEST_EQ(ost2pst::ltp::hid_index(alloc_2048, k512), 0, "allocation 2048 wraps under the 11-bit field");
    TEST_EQ(ost2pst::ltp::hid_block_index(alloc_2048, k512), 1,
            "and the 512 profile reads the overflow as data block 1");
    TEST_CHECK(!ost2pst::ltp::hid_is_valid(alloc_2048, k512));
    TEST_EQ(ost2pst::ltp::hid_index(alloc_2048, k4k), 2048, "the 14-bit field reads allocation 2048");
    TEST_EQ(ost2pst::ltp::hid_block_index(alloc_2048, k4k), 0, "and it stays in block 0");
    TEST_CHECK(ost2pst::ltp::hid_is_valid(alloc_2048, k4k));
    TEST_EQ(ost2pst::ltp::hid_index(0x3FFFu << 5, k4k), 0x3FFF,
            "the 14-bit allocation field tops out at 16383");
    TEST_EQ(ost2pst::ltp::hid_index(0x4000u << 5, k4k), 0,
            "one bit past the 14-bit field is not an allocation");
    TEST_EQ(ost2pst::ltp::hid_block_index(0x4000u << 5, k4k), 1, "it becomes the first block bit");

    // The same bytes name different things under the two profiles. 0x00701A80 is the RowIndex BTH root of
    // the sample OST's Inbox: under the 4 KiB widths it is allocation 212 of data block 14, which is the
    // allocation the Inbox's leaf arrays are named from. Under the 512 widths the allocation is still 212
    // (it fits the narrower field) but the block index is 8 times too big -- the discrepancy the withdrawn
    // "hidBlockIndex counts 8,192-byte units" note was papering over.
    const uint32_t inbox_root = 0x00701A80;
    TEST_EQ(ost2pst::ltp::hid_block_index(inbox_root, k4k), 14, "4k: block = hid >> 19");
    TEST_EQ(ost2pst::ltp::hid_index(inbox_root, k4k), 212, "4k: allocation = (hid >> 5) & 0x3FFF");
    TEST_EQ(ost2pst::ltp::hid_block_index(inbox_root, k512), 112, "512 widths name block 112 instead");
    TEST_EQ(ost2pst::ltp::hid_index(inbox_root, k512), 212, "while the allocation stays 212");

    // 13 block bits: 8191 is the last data block a 4 KiB HID can name, and a non-zero block index has to
    // survive the split intact.
    TEST_EQ(ost2pst::ltp::hid_block_index(0x20 | (8191u << 19), k4k), 8191,
            "the 13-bit block field tops out at 8191");
    TEST_EQ(ost2pst::ltp::hid_block_index(0x20 | (5u << 19), k4k), 5, "a non-zero block index survives");
    TEST_EQ(ost2pst::ltp::hid_index(0x20 | (5u << 19), k4k), 1, "and does not eat the allocation index");
    TEST_CHECK(!ost2pst::ltp::hid_is_valid(0x21 | (5u << 19), k4k));
    TEST_CHECK(ost2pst::ltp::hid_is_valid(0x20 | (5u << 19), k4k));
}

} // namespace

int main() {
    check_hn_header();
    check_page_map_and_heap_items();
    check_page_map_rejects_nonsense();
    check_page_map_in_the_fullest_measured_block();
    check_hid_arithmetic();
    return ost2pst::test::finish("ltp_hn_test");
}
