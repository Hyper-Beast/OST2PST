// PAGETRAILER and BLOCKTRAILER decode ([MS-PST] 2.2.2.7.1, 2.2.2.8.1) on both byte layouts, plus the
// structural helpers the page-grid scan depends on.
//
// Every error a trailer decoder reports must carry the absolute offset of the trailer window, not a
// buffer-relative one, because that offset is what makes a corrupt file diagnosable.
#include <cstdint>
#include <vector>

#include "ost2pst/ndb/layout.h"
#include "ost2pst/ndb/trailer.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/sig.h"
#include "test_support.h"

namespace {

using ost2pst::ndb::decode_block_trailer;
using ost2pst::ndb::decode_page_trailer;
using ost2pst::ndb::FileProfile;
using ost2pst::ndb::is_page_type;
using ost2pst::ndb::looks_like_page_trailer;
using ost2pst::ndb::page_type_name;
using ost2pst::ndb::page_type_uses_zero_sig;
using ost2pst::util::ByteView;
using ost2pst::util::ErrorKind;
using ost2pst::util::compute_sig;

constexpr uint64_t kTrailerBase = 0x22000 + 4072;

// A little-endian trailer window built from the spec's field order, sized for the profile.
std::vector<uint8_t> trailer_bytes(FileProfile profile, uint8_t ptype, uint8_t ptype_repeat,
                                   uint16_t w_sig, uint32_t dw_crc, uint64_t bid) {
    std::vector<uint8_t> bytes(ost2pst::ndb::page_trailer_size(profile), 0);
    bytes[0] = ptype;
    bytes[1] = ptype_repeat;
    bytes[2] = static_cast<uint8_t>(w_sig & 0xFF);
    bytes[3] = static_cast<uint8_t>(w_sig >> 8);
    for (size_t i = 0; i < 4; ++i) {
        bytes[4 + i] = static_cast<uint8_t>((dw_crc >> (8 * i)) & 0xFF);
    }
    // OST narrows bid to 4 bytes and zeroes the 4 bytes after it; a PST keeps the full 8.
    const size_t width = profile == FileProfile::kOst ? 4 : 8;
    for (size_t i = 0; i < width; ++i) {
        bytes[8 + i] = static_cast<uint8_t>((bid >> (8 * i)) & 0xFF);
    }
    return bytes;
}

ByteView trailer_view(const std::vector<uint8_t> &bytes, uint64_t base = kTrailerBase,
                      size_t size = 0) {
    return ByteView(bytes.data(), size == 0 ? bytes.size() : size, base);
}

void check_page_trailer_fields() {
    // [MS-PST] 2.2.2.7.1: an AMap page has wSig 0 and a bid equal to its own ib.
    const auto pst = decode_page_trailer(
        trailer_view(trailer_bytes(FileProfile::kPst, 0x84, 0x84, 0x0000, 0xDEADBEEF, 0x110)),
        FileProfile::kPst);
    TEST_OK(pst, "PST AMap page trailer");
    if (pst.ok()) {
        TEST_EQ(pst.value().ptype, 0x84, "PST PAGETRAILER.ptype");
        TEST_EQ(pst.value().ptype_repeat, 0x84, "PST PAGETRAILER.ptypeRepeat");
        TEST_EQ(pst.value().w_sig, 0x0000, "PST PAGETRAILER.wSig");
        TEST_EQ(pst.value().dw_crc, 0xDEADBEEFu, "PST PAGETRAILER.dwCRC");
        TEST_EQ(pst.value().bid, 0x110ULL, "PST PAGETRAILER.bid");
        TEST_EQ(pst.value().ost_flag, 0, "PST has no OST-only slot");
    }

    // The OST trailer is 24 bytes and writes 1 in the slot past the spec's 16.
    std::vector<uint8_t> ost_bytes = trailer_bytes(FileProfile::kOst, 0x84, 0x84, 0x0000, 0xDEADBEEF, 0x22000);
    TEST_EQ(ost_bytes.size(), 24, "OST PAGETRAILER size");
    ost_bytes[16] = 0x01;
    const auto ost = decode_page_trailer(trailer_view(ost_bytes), FileProfile::kOst);
    TEST_OK(ost, "OST AMap page trailer");
    if (ost.ok()) {
        TEST_EQ(ost.value().bid, 0x22000ULL, "OST PAGETRAILER.bid");
        TEST_EQ(ost.value().ost_flag, 1, "OST PAGETRAILER.ostFlag");
    }
}

void check_page_trailer_errors() {
    const auto bad_repeat = decode_page_trailer(
        trailer_view(trailer_bytes(FileProfile::kOst, 0x84, 0x85, 0, 0, 0x110)), FileProfile::kOst);
    TEST_ERROR(bad_repeat, ErrorKind::kBadField, "PAGETRAILER.ptypeRepeat", "ptypeRepeat mismatch");
    TEST_ERROR_OFFSET(bad_repeat, kTrailerBase, "ptypeRepeat mismatch offset");

    for (uint8_t ptype : {0x00, 0x7F, 0x87, 0xFF}) {
        const auto decoded = decode_page_trailer(
            trailer_view(trailer_bytes(FileProfile::kOst, ptype, ptype, 0, 0, 0x110)), FileProfile::kOst);
        TEST_ERROR(decoded, ErrorKind::kBadField, "PAGETRAILER.ptype", "undefined ptype");
        TEST_ERROR_OFFSET(decoded, kTrailerBase, "undefined ptype offset");
    }

    // A ptype that is in range but not repeated is reported as the repeat mismatch, not as an
    // undefined type: the first check is the one that identifies the corruption.
    const auto undefined_pair = decode_page_trailer(
        trailer_view(trailer_bytes(FileProfile::kOst, 0x7F, 0x80, 0, 0, 0)), FileProfile::kOst);
    TEST_ERROR(undefined_pair, ErrorKind::kBadField, "PAGETRAILER.ptypeRepeat",
               "mismatch wins over range check");

    // [MS-PST] 2.2.2.7.1: the window has to be the whole trailer of the profile being read.
    const std::vector<uint8_t> bytes = trailer_bytes(FileProfile::kOst, 0x84, 0x84, 0, 0, 0x110);
    const auto short_view = decode_page_trailer(trailer_view(bytes, kTrailerBase, 23), FileProfile::kOst);
    TEST_ERROR(short_view, ErrorKind::kTruncated, "PAGETRAILER", "23-byte OST page trailer");
    TEST_ERROR_OFFSET(short_view, kTrailerBase, "23-byte OST page trailer offset");

    const auto wrong_profile =
        decode_page_trailer(trailer_view(trailer_bytes(FileProfile::kPst, 0x84, 0x84, 0, 0, 0x110)),
                            FileProfile::kOst);
    TEST_ERROR(wrong_profile, ErrorKind::kTruncated, "PAGETRAILER", "16-byte window for a 24-byte profile");
}

std::vector<uint8_t> block_trailer_bytes(FileProfile profile, uint16_t cb, uint16_t w_sig,
                                         uint32_t dw_crc, uint64_t bid, uint16_t b_typ = 0,
                                         uint16_t uncompressed_cb = 0) {
    std::vector<uint8_t> bytes = trailer_bytes(profile, 0, 0, w_sig, dw_crc, bid);
    bytes[0] = static_cast<uint8_t>(cb & 0xFF);
    bytes[1] = static_cast<uint8_t>(cb >> 8);
    if (profile == FileProfile::kOst) {
        bytes[16] = static_cast<uint8_t>(b_typ & 0xFF);
        bytes[17] = static_cast<uint8_t>(b_typ >> 8);
        bytes[18] = static_cast<uint8_t>(uncompressed_cb & 0xFF);
        bytes[19] = static_cast<uint8_t>(uncompressed_cb >> 8);
    }
    return bytes;
}

void check_block_trailer() {
    const uint64_t base = 0x9B207400; // a real block offset from the sample's BBT

    // [MS-PST] 2.2.2.8: cb is bounded by the profile's capacity, which is 8176 for a PST and 65512
    // for an OST.
    for (uint16_t cb : {1, 64, 4096, static_cast<int>(ost2pst::ndb::kPstBlockMaxCb)}) {
        const auto decoded = decode_block_trailer(
            trailer_view(block_trailer_bytes(FileProfile::kPst, cb, 0xCFAE, 0x12345678, 0x4A20C4), base),
            FileProfile::kPst);
        TEST_OK(decoded, "PST block trailer cb in range");
        if (decoded.ok()) {
            TEST_EQ(decoded.value().cb, cb, "PST BLOCKTRAILER.cb");
            TEST_EQ(decoded.value().w_sig, 0xCFAE, "PST BLOCKTRAILER.wSig");
            TEST_EQ(decoded.value().dw_crc, 0x12345678u, "PST BLOCKTRAILER.dwCRC");
            TEST_EQ(decoded.value().bid, 0x4A20C4ULL, "PST BLOCKTRAILER.bid");
        }
    }
    for (uint16_t cb : {1, 8177, 40000, static_cast<int>(ost2pst::ndb::kOstBlockMaxCb)}) {
        const auto decoded = decode_block_trailer(
            trailer_view(block_trailer_bytes(FileProfile::kOst, cb, 0xCFAE, 0x12345678, 0x4A20C4, 2, 8910),
                         base),
            FileProfile::kOst);
        TEST_OK(decoded, "OST block trailer cb in range");
        if (decoded.ok()) {
            TEST_EQ(decoded.value().cb, cb, "OST BLOCKTRAILER.cb");
            TEST_EQ(decoded.value().ost_b_typ, 2, "OST BLOCKTRAILER.ostBTyp");
            TEST_EQ(decoded.value().ost_uncompressed_cb, 8910, "OST BLOCKTRAILER.ostUncompressedCb");
        }
    }

    for (uint16_t cb : {0, 8177, 0xFFFF}) {
        const auto decoded = decode_block_trailer(
            trailer_view(block_trailer_bytes(FileProfile::kPst, cb, 0, 0, 0x4A20C4), base), FileProfile::kPst);
        TEST_ERROR(decoded, ErrorKind::kBadField, "BLOCKTRAILER.cb", "cb out of PST range");
        TEST_ERROR_OFFSET(decoded, base, "cb out of PST range offset");
        TEST_EQ(decoded.error().value, cb, "cb reported value");
    }
    for (uint16_t cb : {0, 65513, 0xFFFF}) {
        const auto decoded = decode_block_trailer(
            trailer_view(block_trailer_bytes(FileProfile::kOst, cb, 0, 0, 0x4A20C4), base), FileProfile::kOst);
        TEST_ERROR(decoded, ErrorKind::kBadField, "BLOCKTRAILER.cb", "cb out of OST range");
        TEST_ERROR_OFFSET(decoded, base, "cb out of OST range offset");
    }

    const auto short_view = decode_block_trailer(
        trailer_view(block_trailer_bytes(FileProfile::kOst, 0x10, 0, 0, 0x4A20C4), base, 23), FileProfile::kOst);
    TEST_ERROR(short_view, ErrorKind::kTruncated, "BLOCKTRAILER", "23-byte OST block trailer");
    TEST_ERROR_OFFSET(short_view, base, "23-byte OST block trailer offset");
}

void check_structural_helpers() {
    for (uint8_t ptype = 0x80; ptype <= 0x86; ++ptype) {
        TEST_CHECK(is_page_type(ptype));
    }
    for (uint8_t ptype : {0x00, 0x01, 0x7F, 0x87, 0xFE, 0xFF}) {
        TEST_CHECK(!is_page_type(ptype));
    }

    const uint8_t good[24] = {0x84, 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const uint8_t bad_repeat[24] = {0x84, 0x85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const uint8_t out_of_range[24] = {0x12, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    TEST_CHECK(looks_like_page_trailer(good));
    TEST_CHECK(!looks_like_page_trailer(bad_repeat));
    TEST_CHECK(!looks_like_page_trailer(out_of_range));

    // [MS-PST] 2.2.2.7.1: allocation-map pages carry wSig 0; BTree and Density List pages do not.
    TEST_CHECK(page_type_uses_zero_sig(0x82));
    TEST_CHECK(page_type_uses_zero_sig(0x83));
    TEST_CHECK(page_type_uses_zero_sig(0x84));
    TEST_CHECK(page_type_uses_zero_sig(0x85));
    TEST_CHECK(!page_type_uses_zero_sig(0x80));
    TEST_CHECK(!page_type_uses_zero_sig(0x81));
    TEST_CHECK(!page_type_uses_zero_sig(0x86));
    TEST_CHECK(!page_type_uses_zero_sig(0x00));

    TEST_STR(page_type_name(0x80), "BBT", "page_type_name BBT");
    TEST_STR(page_type_name(0x81), "NBT", "page_type_name NBT");
    TEST_STR(page_type_name(0x82), "FMap", "page_type_name FMap");
    TEST_STR(page_type_name(0x83), "PMap", "page_type_name PMap");
    TEST_STR(page_type_name(0x84), "AMap", "page_type_name AMap");
    TEST_STR(page_type_name(0x85), "FPMap", "page_type_name FPMap");
    TEST_STR(page_type_name(0x86), "DList", "page_type_name DList");
    TEST_STR(page_type_name(0x00), "unknown", "page_type_name unknown");
    TEST_STR(page_type_name(0xFF), "unknown", "page_type_name unknown 0xFF");
}

void check_signature_matches_trailer() {
    // A page trailer's wSig is ComputeSig(ib, bid) for the page's own offset and BID.
    TEST_EQ(compute_sig(0x4400, 0x110), 0x4510, "PST AMap page wSig");
    TEST_EQ(compute_sig(0x4200, 0x108), 0x4308, "PST DList page wSig");
    // [MS-PST] 2.2.2.7.1: an allocation-map page has bid equal to its own ib, so its wSig is 0.
    TEST_EQ(compute_sig(0x22000, 0x22000), 0, "OST AMap page wSig is zero");
    // A BTree page's BID comes from the BREF that supplied it, not from its offset. These three are
    // the sample's own BBT root, NBT root, and DList page.
    TEST_EQ(compute_sig(0x9B1F6000, 0xFC163), 0x3A73, "sample BBT root page wSig");
    TEST_EQ(compute_sig(0x9B215000, 0xFC15F), 0x0A71, "sample NBT root page wSig");
    TEST_EQ(compute_sig(0x21000, 0xFC164), 0xD169, "sample DList page wSig");
}

} // namespace

int main() {
    check_page_trailer_fields();
    check_page_trailer_errors();
    check_block_trailer();
    check_structural_helpers();
    check_signature_matches_trailer();
    return ost2pst::test::finish("trailer_test");
}
