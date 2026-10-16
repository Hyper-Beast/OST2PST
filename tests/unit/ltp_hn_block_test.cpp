// A data block is either the heap node itself or one zlib stream that inflates to it, and the caller says
// which, because the NDB says so: the OST trailer's uncompressed data length. This file checks that the
// two cases stay distinguishable after the inflate, including which offsets mean what inside each of them,
// and that a raw block whose bytes merely look like a zlib header stays raw.
#include <cstdint>
#include <vector>

#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/hn_block.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"
#include "test_support.h"

namespace {

using ost2pst::ltp::BlockForm;
using ost2pst::ltp::decode_hn_header;
using ost2pst::ltp::HnBlock;
using ost2pst::ltp::HnHeader;
using ost2pst::ltp::read_hn_block;
using ost2pst::util::ByteView;
using ost2pst::util::ErrorKind;
using ost2pst::util::Result;

constexpr uint64_t kBlockBase = 0x4000;
constexpr size_t kBlockSize = 512;

// The same valid heap node tests/unit/ltp_hn_test.cpp builds: HNHDR at 0, HNPAGEMAP at 0x40, three
// allocations at 0x0C, 0x14 and 0x92.
std::vector<uint8_t> make_heap_node() {
    std::vector<uint8_t> block(kBlockSize, 0);
    for (uint64_t at = 0x0C; at < 0xAA; ++at) {
        block[at] = static_cast<uint8_t>(0xA0 + (at % 16));
    }
    block[0] = 0x40;
    block[1] = 0x00;
    block[2] = 0xEC; // [MS-PST] 2.3.1.2 bSig
    block[3] = 0xBC; // [MS-PST] 2.3.1.2 bClientSig: a property context
    block[4] = 0x20; // [MS-PST] 2.3.1.2 hidUserRoot
    block[0x40] = 3; // [MS-PST] 2.3.1.5 cAlloc
    block[0x41] = 0;
    block[0x42] = 0; // cFree
    block[0x43] = 0;
    const uint16_t offsets[] = {0x000C, 0x0014, 0x0092, 0x00AA};
    for (int index = 0; index < 4; ++index) {
        block[0x44 + index * 2] = static_cast<uint8_t>(offsets[index] & 0xFF);
        block[0x45 + index * 2] = static_cast<uint8_t>(offsets[index] >> 8);
    }
    return block;
}

// zlib level 6 over that block: what the sample's 11,477 compressed blocks look like.
const uint8_t kCompressedHeapNode[] = {0x78, 0x9C, 0x73, 0x60, 0x78, 0xB3, 0x47, 0x81, 0x01, 0x02, 0xD6, 0xAC, 0x5D, 0xB7, 0x7E, 0xC1, 0xC2, 0x45, 0x8B, 0x97, 0x2C, 0x5D, 0xB6, 0x7C, 0xC5, 0xCA, 0x55, 0xAB, 0x89, 0xE1, 0x33, 0x03, 0xF5, 0xF1, 0x30, 0x88, 0x30, 0x4C, 0x62, 0x58, 0x45, 0x96, 0x7E, 0xE2, 0xF9, 0x0C, 0xA3, 0x80, 0x06, 0x00, 0x00, 0x39, 0x0C, 0x63, 0x01};

ByteView view_of(const std::vector<uint8_t> &bytes, uint64_t base = kBlockBase) {
    return ByteView(bytes.data(), bytes.size(), base);
}

ByteView view_of(const uint8_t *bytes, size_t size, uint64_t base = kBlockBase) {
    return ByteView(bytes, size, base);
}

bool same_bytes(ost2pst::util::ByteView view, const std::vector<uint8_t> &expected) {
    if (view.size() != expected.size()) {
        return false;
    }
    for (size_t index = 0; index < expected.size(); ++index) {
        if (view.data()[index] != expected[index]) {
            return false;
        }
    }
    return true;
}

void check_raw_block() {
    const std::vector<uint8_t> heap_node = make_heap_node();
    Result<HnBlock> block = read_hn_block(view_of(heap_node), false);
    TEST_OK(block, "raw block");
    if (!block.ok()) {
        return;
    }
    TEST_EQ(static_cast<int>(block.value().form), static_cast<int>(BlockForm::kRaw), "raw form");
    TEST_STR(ost2pst::ltp::block_form_name(block.value().form), "raw", "raw name");
    TEST_EQ(block.value().block_base, kBlockBase, "raw block_base");
    TEST_EQ(block.value().stream_bytes, 0u, "raw stream_bytes");
    TEST_EQ(block.value().leftover, 0u, "raw leftover");
    // A raw block is the block: its offsets stay absolute.
    TEST_EQ(block.value().heap_node().base(), kBlockBase, "raw heap_node base");
    TEST_CHECK(same_bytes(block.value().heap_node(), heap_node));

    Result<HnHeader> header = decode_hn_header(block.value().heap_node());
    TEST_OK(header, "raw block decodes as a heap node");
    if (header.ok()) {
        TEST_EQ(header.value().ib_hnpm, 0x40, "raw ibHnpm");
        TEST_EQ(header.value().b_sig, 0xEC, "raw bSig");
        TEST_EQ(header.value().b_client_sig, 0xBC, "raw bClientSig");
    }
}

void check_compressed_block() {
    Result<HnBlock> block = read_hn_block(view_of(kCompressedHeapNode, sizeof(kCompressedHeapNode)), true);
    TEST_OK(block, "compressed block");
    if (!block.ok()) {
        return;
    }
    TEST_EQ(static_cast<int>(block.value().form), static_cast<int>(BlockForm::kCompressed),
            "compressed form");
    TEST_STR(ost2pst::ltp::block_form_name(block.value().form), "compressed", "compressed name");
    TEST_EQ(block.value().block_base, kBlockBase, "compressed block_base");
    TEST_EQ(block.value().stream_bytes, sizeof(kCompressedHeapNode), "compressed stream_bytes");
    TEST_EQ(block.value().leftover, 0u, "compressed leftover");
    TEST_EQ(block.value().inflated.size(), kBlockSize, "inflated size");
    TEST_CHECK(same_bytes(block.value().heap_node(), make_heap_node()));

    // The inflated bytes sit at no file offset, so their view is based at 0 and every offset inside is
    // block-relative. Reporting kBlockBase + 12 here would name a file position that does not exist.
    TEST_EQ(block.value().heap_node().base(), 0u, "inflated offsets are block-relative");

    Result<HnHeader> header = decode_hn_header(block.value().heap_node());
    TEST_OK(header, "compressed block decodes as a heap node");
    if (header.ok()) {
        TEST_EQ(header.value().ib_hnpm, 0x40, "compressed ibHnpm");
        TEST_EQ(header.value().b_sig, 0xEC, "compressed bSig");
        TEST_EQ(header.value().b_client_sig, 0xBC, "compressed bClientSig");
        TEST_EQ(header.value().hid_user_root, 0x20, "compressed hidUserRoot");
    }
}

// A stream that stops short of cb is reported, not quietly accepted.
void check_leftover() {
    std::vector<uint8_t> bytes(kCompressedHeapNode,
                               kCompressedHeapNode + sizeof(kCompressedHeapNode));
    bytes.push_back(0xDE);
    bytes.push_back(0xAD);
    bytes.push_back(0xBE);
    bytes.push_back(0xEF);
    Result<HnBlock> block = read_hn_block(view_of(bytes), true);
    TEST_OK(block, "block with leftover bytes");
    if (block.ok()) {
        TEST_EQ(block.value().stream_bytes, sizeof(kCompressedHeapNode), "leftover stream_bytes");
        TEST_EQ(block.value().leftover, 4u, "leftover count");
        TEST_EQ(block.value().inflated.size(), kBlockSize, "leftover inflated size");
    }
}

// Bytes the NDB calls compressed and that then fail to deliver it are an error at the block, never a raw
// block and never a heap node.
void check_broken_compression() {
    static const uint8_t broken[] = {0x78, 0x9C, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    Result<HnBlock> block = read_hn_block(view_of(broken, sizeof(broken)), true);
    TEST_ERROR(block, ErrorKind::kBadField, "deflate.BTYPE", "broken compression");
    // The offset is the BTYPE field inside the block, not the block's start.
    TEST_ERROR_OFFSET(block, kBlockBase + 2, "broken compression offset stays inside the block");

    std::vector<uint8_t> truncated(kCompressedHeapNode,
                                   kCompressedHeapNode + sizeof(kCompressedHeapNode) - 2);
    TEST_ERROR(read_hn_block(view_of(truncated), true), ErrorKind::kTruncated, "zlib.adler32",
               "compressed block cut before the Adler-32");

    // The NDB calls the block compressed and the bytes carry no CMF/FLG pair: a contradiction, reported
    // as one instead of quietly read as raw.
    const std::vector<uint8_t> no_header = {0x40, 0x00, 0xEC, 0xBC, 0x20, 0x00, 0x00, 0x00};
    Result<HnBlock> contradicted = read_hn_block(view_of(no_header), true);
    TEST_ERROR(contradicted, ErrorKind::kBadSignature, "zlib.CMF", "compressed without a CMF/FLG pair");
    TEST_ERROR_OFFSET(contradicted, kBlockBase, "the contradiction is reported at the block");

    const std::vector<uint8_t> too_short = {0x78};
    Result<HnBlock> short_block = read_hn_block(view_of(too_short), false);
    TEST_OK(short_block, "one byte the NDB calls raw stays raw");
    if (short_block.ok()) {
        TEST_EQ(static_cast<int>(short_block.value().form), static_cast<int>(BlockForm::kRaw),
                "too short stays raw");
        TEST_ERROR(decode_hn_header(short_block.value().heap_node()), ErrorKind::kTruncated, "HNHDR",
                   "a block shorter than the HNHDR");
    }
}

// The cap is a reported error with the block's offset, so a corrupt cb cannot allocate without bound.
void check_output_cap() {
    Result<HnBlock> block = read_hn_block(view_of(kCompressedHeapNode, sizeof(kCompressedHeapNode)), true,
                                          256);
    TEST_ERROR(block, ErrorKind::kUnsupported, "deflate.output", "capped inflate");
    // The cap is reported where the inflate stopped, which has to be somewhere inside the block.
    TEST_CHECK(block.error().offset >= kBlockBase &&
               block.error().offset < kBlockBase + sizeof(kCompressedHeapNode));
}

// The 64 blocks the sample lost to the sniff: a raw PC heap node whose ibHnpm is 0x0178 starts with
// 78 01, a CMF/FLG pair that passes the check and divides by 31 exactly. The NDB calls the block raw, so
// the bytes are the heap node and the PC decodes.
void check_zlib_looking_raw_block() {
    std::vector<uint8_t> heap_node = make_heap_node();
    heap_node[0] = 0x78;
    heap_node[1] = 0x01; // ibHnpm 0x0178: what the sample's 28 attachment PCs carry
    Result<HnBlock> block = read_hn_block(view_of(heap_node), false);
    TEST_OK(block, "raw block that looks like a zlib stream");
    if (block.ok()) {
        TEST_EQ(static_cast<int>(block.value().form), static_cast<int>(BlockForm::kRaw),
                "zlib-looking raw stays raw");
        TEST_EQ(block.value().stream_bytes, 0u, "no stream was read");
        TEST_CHECK(same_bytes(block.value().heap_node(), heap_node));
        TEST_OK(decode_hn_header(block.value().heap_node()), "zlib-looking raw still decodes as a heap node");
    }
    // The same bytes asked to inflate do not deliver a stream, which is exactly why the bytes cannot
    // decide the form and the index can.
    TEST_CHECK(!read_hn_block(view_of(heap_node), true).ok());
}

} // namespace

int main() {
    check_raw_block();
    check_compressed_block();
    check_leftover();
    check_broken_compression();
    check_zlib_looking_raw_block();
    check_output_cap();
    return ost2pst::test::finish("ltp_hn_block_test");
}
