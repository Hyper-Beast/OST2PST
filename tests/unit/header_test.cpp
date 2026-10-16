// HEADER / ROOT decode against the [MS-PST] 3.2 example header, plus every M0 refusal policy.
//
// The fixture is the spec's own sample header, dumped byte-for-byte from [MS-PST] 3.2. Its
// bCryptMethod is 0x01, so it is also the case that proves validate_header_refusals refuses an
// obfuscated file instead of silently misreading it.
#include <cstdint>
#include <vector>

#include "ost2pst/ndb/header.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/util/byte_view.h"
#include "test_support.h"

namespace {

using ost2pst::ndb::decode_header;
using ost2pst::ndb::magic_client_text;
using ost2pst::ndb::validate_header_refusals;
using ost2pst::util::ByteView;
using ost2pst::util::ErrorKind;

std::vector<uint8_t> spec_header() {
    return ost2pst::test::read_bytes(ost2pst::test::fixture_path("spec-example-header.bin"));
}

void check_fixture_size() {
    const std::vector<uint8_t> bytes = spec_header();
    TEST_EQ(bytes.size(), ost2pst::ndb::kHeaderSize, "spec fixture size");
}

void check_decoded_fields() {
    const std::vector<uint8_t> bytes = spec_header();
    const auto decoded = decode_header(ByteView(bytes.data(), bytes.size()));
    TEST_OK(decoded, "decode_header(spec fixture)");
    if (!decoded.ok()) {
        return;
    }
    const ost2pst::ndb::Header &header = decoded.value();

    TEST_EQ(header.dw_magic, 0x4E444221u, "HEADER.dwMagic");
    TEST_EQ(header.dw_crc_partial, 0x379AA90Eu, "HEADER.dwCRCPartial");
    TEST_STR(magic_client_text(header), "SM", "HEADER.wMagicClient");
    TEST_EQ(header.w_ver, 23, "HEADER.wVer");
    TEST_EQ(header.w_ver_client, 19, "HEADER.wVerClient");
    TEST_EQ(header.b_platform_create, 0x01, "HEADER.bPlatformCreate");
    TEST_EQ(header.b_platform_access, 0x01, "HEADER.bPlatformAccess");
    TEST_EQ(header.dw_reserved1, 0x0000075Cu, "HEADER.dwReserved1");
    TEST_EQ(header.dw_reserved2, 0x0B997BD0u, "HEADER.dwReserved2");
    TEST_EQ(header.bid_unused, 0x0000000100000004ULL, "HEADER.bidUnused");
    TEST_EQ(header.bid_next_p, 0x254ULL, "HEADER.bidNextP");
    TEST_EQ(header.dw_unique, 0x45u, "HEADER.dwUnique");
    TEST_EQ(header.qw_unused, 0ULL, "HEADER.qwUnused");

    // rgnid: the spec's own table. Index 2/5/13/14/15 are the 0x404 entries, 3 is 0x4000, 4 is
    // 0x10002, 8 is 0x8000 and 31 is the 0x40F terminator.
    const uint32_t expected_rgnid[ost2pst::ndb::kRgnidCount] = {
        0x400,   0x400,   0x404,   0x4000,  0x10002, 0x404,   0x400,   0x400,
        0x8000,  0x400,   0x400,   0x400,   0x400,   0x404,   0x404,   0x404,
        0x400,   0x400,   0x400,   0x400,   0x400,   0x400,   0x400,   0x400,
        0x400,   0x400,   0x400,   0x400,   0x400,   0x400,   0x400,   0x40F};
    for (uint64_t index = 0; index < ost2pst::ndb::kRgnidCount; ++index) {
        TEST_EQ(header.rgnid[index], expected_rgnid[index], "HEADER.rgnid entry");
    }

    TEST_EQ(header.qw_unused, 0ULL, "HEADER.qwUnused");
    TEST_EQ(header.dw_align, 0u, "HEADER.dwAlign");
    TEST_EQ(header.b_sentinel, 0x80, "HEADER.bSentinel");
    TEST_EQ(header.b_crypt_method, 0x01, "HEADER.bCryptMethod");
    TEST_EQ(header.bid_next_b, 0x1434ULL, "HEADER.bidNextB");
    TEST_EQ(header.dw_crc_full, 0x1FD283D6u, "HEADER.dwCRCFull");
    TEST_EQ(header.b_reserved, 0, "HEADER.bReserved");
    for (uint8_t byte : header.rgb_reserved) {
        TEST_EQ(byte, 0, "HEADER.rgbReserved");
    }
    for (uint8_t byte : header.rgb_reserved2) {
        TEST_EQ(byte, 0, "HEADER.rgbReserved2");
    }
    for (uint8_t byte : header.rgb_reserved3) {
        TEST_EQ(byte, 0, "HEADER.rgbReserved3");
    }
    for (uint8_t byte : header.rgb_fm) {
        TEST_EQ(byte, 0xFF, "HEADER.rgbFM");
    }
    for (uint8_t byte : header.rgb_fp) {
        TEST_EQ(byte, 0xFF, "HEADER.rgbFP");
    }
}

void check_decoded_root() {
    const std::vector<uint8_t> bytes = spec_header();
    const auto decoded = decode_header(ByteView(bytes.data(), bytes.size()));
    TEST_OK(decoded, "decode_header for ROOT");
    if (!decoded.ok()) {
        return;
    }
    const ost2pst::ndb::Root &root = decoded.value().root;

    TEST_EQ(root.dw_reserved, 0u, "ROOT.dwReserved");
    TEST_EQ(root.ib_file_eof, 0x9F2400ULL, "ROOT.ibFileEof");
    TEST_EQ(root.ib_amap_last, 0x9B4400ULL, "ROOT.ibAMapLast");
    TEST_EQ(root.cb_amap_free, 0x12F240ULL, "ROOT.cbAMapFree");
    TEST_EQ(root.cb_pmap_free, 0ULL, "ROOT.cbPMapFree");
    TEST_EQ(root.nbt_bref.bid, 0x24BULL, "ROOT.BREFNBT.bid");
    TEST_EQ(root.nbt_bref.ib, 0x905200ULL, "ROOT.BREFNBT.ib");
    TEST_EQ(root.bbt_bref.bid, 0x253ULL, "ROOT.BREFBBT.bid");
    TEST_EQ(root.bbt_bref.ib, 0x900A00ULL, "ROOT.BREFBBT.ib");
    TEST_EQ(root.f_amap_valid, 0x02, "ROOT.fAMapValid");
    TEST_EQ(root.b_reserved, 0, "ROOT.bReserved");
    TEST_EQ(root.w_reserved, 0, "ROOT.wReserved");
}

void check_truncated_views() {
    const std::vector<uint8_t> bytes = spec_header();

    const auto empty = decode_header(ByteView(bytes.data(), 0));
    TEST_ERROR(empty, ErrorKind::kTruncated, "HEADER.dwMagic", "empty view");
    TEST_ERROR_OFFSET(empty, 0, "empty view");

    // One byte short: rgbReserved3 is the last field, so it is the one that reports the shortfall.
    const auto short_view = decode_header(ByteView(bytes.data(), ost2pst::ndb::kHeaderSize - 1));
    TEST_ERROR(short_view, ErrorKind::kTruncated, "HEADER.rgbReserved3", "563-byte view");
    TEST_ERROR_OFFSET(short_view, 0x214, "563-byte view");

    // ROOT read on its own: a view that stops one byte inside wReserved.
    const auto short_root =
        ost2pst::ndb::decode_root(ByteView(bytes.data(), 0x0FB), ost2pst::ndb::kRootOffset);
    TEST_ERROR(short_root, ErrorKind::kTruncated, "ROOT.wReserved", "ROOT one byte short");
    TEST_ERROR_OFFSET(short_root, 0x0FA, "ROOT one byte short");
}

// Mutates one field of a copy of the fixture and expects the documented refusal for it.
void expect_refusal(uint64_t offset, uint8_t value, const char *field, const char *label) {
    std::vector<uint8_t> bytes = spec_header();
    if (offset >= bytes.size()) {
        ost2pst::test::report_failure(__FILE__, __LINE__, "fixture too short for mutation");
        return;
    }
    // The fixture is obfuscated (bCryptMethod 0x01 at 0x201), which is itself a refusal. Neutralise
    // it so the mutation under test is the first refusal reported.
    if (offset != 0x201) {
        bytes[0x201] = 0x00;
    }
    bytes[offset] = value;
    const auto decoded = decode_header(ByteView(bytes.data(), bytes.size()));
    TEST_OK(decoded, label);
    if (!decoded.ok()) {
        return;
    }
    const auto status = validate_header_refusals(decoded.value());
    TEST_ERROR(status, ErrorKind::kUnsupported, field, label);
}

void check_refusals() {
    // The spec fixture itself is the bCryptMethod case: permute/cyclic obfuscation is out of scope
    // for M0 because the key is not in the file.
    const std::vector<uint8_t> bytes = spec_header();
    const auto decoded = decode_header(ByteView(bytes.data(), bytes.size()));
    TEST_OK(decoded, "fixture decode for refusal scan");
    if (decoded.ok()) {
        TEST_ERROR(validate_header_refusals(decoded.value()), ErrorKind::kUnsupported,
                   "HEADER.bCryptMethod", "spec fixture bCryptMethod");
    }

    expect_refusal(0x000, 0x00, "HEADER.dwMagic", "bad dwMagic");
    expect_refusal(0x00A, 22, "HEADER.wVer", "ANSI wVer 22");
    expect_refusal(0x00A, 37, "HEADER.wVer", "WIP wVer 37");
    expect_refusal(0x009, 'X', "HEADER.wMagicClient", "wMagicClient SX");
    expect_refusal(0x00E, 0x02, "HEADER.bPlatform", "bPlatformCreate 0x02");
    expect_refusal(0x00F, 0x02, "HEADER.bPlatform", "bPlatformAccess 0x02");
    expect_refusal(0x0FC, 0x01, "HEADER.dwAlign", "dwAlign 1");
    expect_refusal(0x200, 0x00, "HEADER.bSentinel", "bSentinel 0");
    expect_refusal(0x0F8, 0x00, "ROOT.fAMapValid", "fAMapValid INVALID_AMAP");
}

void check_accepted_configuration() {
    // Same fixture with the only unsupported field fixed: every other field already satisfies policy.
    std::vector<uint8_t> bytes = spec_header();
    bytes[0x201] = 0x00;
    const auto decoded = decode_header(ByteView(bytes.data(), bytes.size()));
    TEST_OK(decoded, "decode de-obfuscated fixture");
    if (decoded.ok()) {
        TEST_OK(validate_header_refusals(decoded.value()), "refusals accept bCryptMethod 0");
    }
}

} // namespace

int main() {
    check_fixture_size();
    check_decoded_fields();
    check_decoded_root();
    check_truncated_views();
    check_refusals();
    check_accepted_configuration();
    return ost2pst::test::finish("header_test");
}
