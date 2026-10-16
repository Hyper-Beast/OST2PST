// Generated synthetic 4K-profile layout anchors. No private mailbox bytes are included.
// Covers header/page/block fields, allocation, signatures and CRCs using independently generated data.
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "ost2pst/ndb/btree.h"
#include "ost2pst/ndb/crc.h"
#include "ost2pst/ndb/header.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/ndb/trailer.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/crc32.h"
#include "ost2pst/util/sig.h"
#include "test_support.h"

namespace {

using ost2pst::ndb::BbtEntry;
using ost2pst::ndb::BtPageInfo;
using ost2pst::ndb::decode_block_trailer;
using ost2pst::ndb::decode_bbt_entries;
using ost2pst::ndb::decode_bt_page_footer;
using ost2pst::ndb::decode_header;
using ost2pst::ndb::decode_page_trailer;
using ost2pst::ndb::FileProfile;
using ost2pst::ndb::Header;
using ost2pst::ndb::verify_header_crcs;
using ost2pst::test::fixture_path;
using ost2pst::test::golden_number;
using ost2pst::test::golden_path;
using ost2pst::test::golden_value;
using ost2pst::test::read_bytes;
using ost2pst::test::read_text;
using ost2pst::util::ByteView;

constexpr FileProfile kProfile = FileProfile::kOst;

std::string g(const std::string &golden, const char *key) {
    const std::optional<std::string> value = golden_value(golden, key);
    if (!value) {
        ost2pst::test::report_failure(__FILE__, __LINE__, std::string("golden key missing: ") + key);
        return {};
    }
    return *value;
}

void check_measured_layout_constants() {
    const std::string golden = read_text(golden_path("synthetic-layout.json"));
    TEST_EQ(ost2pst::ndb::page_size(kProfile), golden_number(golden, "page_size"), "OST page size");
    TEST_EQ(ost2pst::ndb::page_trailer_size(kProfile), golden_number(golden, "page_trailer_size"),
            "OST PAGETRAILER size");
    TEST_EQ(ost2pst::ndb::bt_trailer_offset(kProfile), golden_number(golden, "bt_trailer_offset"),
            "OST BTPAGE pageTrailer offset");
    TEST_EQ(ost2pst::ndb::bt_entries_bytes(kProfile), golden_number(golden, "bt_entries_bytes"),
            "OST rgentries size");
    TEST_EQ(ost2pst::ndb::block_granularity(kProfile), golden_number(golden, "block_granularity"),
            "OST block granularity");
    TEST_EQ(ost2pst::ndb::block_trailer_size(kProfile), golden_number(golden, "block_trailer_size"),
            "OST BLOCKTRAILER size");
    TEST_EQ(ost2pst::ndb::block_max_cb(kProfile), golden_number(golden, "block_max_cb"),
            "OST block max cb");
    TEST_EQ(ost2pst::ndb::amap_first_offset(kProfile), golden_number(golden, "amap_first_offset"),
            "OST first AMap");
    TEST_EQ(ost2pst::ndb::amap_interval(kProfile), golden_number(golden, "amap_interval"),
            "OST AMap interval");
    TEST_EQ(ost2pst::ndb::dlist_offset(kProfile), golden_number(golden, "dlist_offset"),
            "OST DList offset");

    // [MS-PST] 2.2.2.7.2: the AMap chain is contiguous, so the last region is the one ROOT.ibAMapLast
    // names. That is what makes ibAMapLast usable as the end of the scan.
    const uint64_t regions = golden_number(golden, "amap_regions");
    const uint64_t last = ost2pst::ndb::amap_first_offset(kProfile) +
                          (regions - 1) * ost2pst::ndb::amap_interval(kProfile);
    TEST_EQ(last, golden_number(golden, "ib_amap_last"), "last AMap region == ROOT.ibAMapLast");
}

void check_header_anchors() {
    const std::string golden = read_text(golden_path("synthetic-layout.json"));
    const std::vector<uint8_t> bytes = read_bytes(fixture_path("synthetic-header.bin"));
    TEST_EQ(bytes.size(), ost2pst::ndb::kHeaderSize, "header fixture size");
    if (bytes.size() != ost2pst::ndb::kHeaderSize) {
        return;
    }
    const ByteView view(bytes.data(), bytes.size(), ost2pst::ndb::kHeaderOffset);

    const auto decoded = decode_header(view);
    TEST_OK(decoded, "sample header decode");
    if (!decoded.ok()) {
        return;
    }
    const Header &header = decoded.value();
    TEST_EQ(header.dw_magic, golden_number(golden, "dw_magic"), "HEADER.dwMagic");
    TEST_STR(ost2pst::ndb::magic_client_text(header), g(golden, "w_magic_client"), "HEADER.wMagicClient");
    TEST_EQ(header.w_ver, golden_number(golden, "w_ver"), "HEADER.wVer");
    TEST_EQ(header.w_ver_client, golden_number(golden, "w_ver_client"), "HEADER.wVerClient");
    TEST_EQ(header.b_sentinel, golden_number(golden, "b_sentinel"), "HEADER.bSentinel");
    TEST_EQ(header.b_crypt_method, golden_number(golden, "b_crypt_method"), "HEADER.bCryptMethod");
    TEST_EQ(header.bid_next_p, golden_number(golden, "bid_next_p"), "HEADER.bidNextP");
    TEST_EQ(header.bid_next_b, golden_number(golden, "bid_next_b"), "HEADER.bidNextB");
    TEST_EQ(header.root.ib_file_eof, golden_number(golden, "ib_file_eof"), "ROOT.ibFileEof");
    TEST_EQ(header.root.ib_amap_last, golden_number(golden, "ib_amap_last"), "ROOT.ibAMapLast");
    TEST_EQ(header.root.f_amap_valid, golden_number(golden, "f_amap_valid"), "ROOT.fAMapValid");
    TEST_EQ(header.root.bbt_bref.bid, golden_number(golden, "bbt_bref_bid"), "ROOT.BREFBBT.bid");
    TEST_EQ(header.root.bbt_bref.ib, golden_number(golden, "bbt_bref_ib"), "ROOT.BREFBBT.ib");
    TEST_EQ(header.root.nbt_bref.bid, golden_number(golden, "nbt_bref_bid"), "ROOT.BREFNBT.bid");
    TEST_EQ(header.root.nbt_bref.ib, golden_number(golden, "nbt_bref_ib"), "ROOT.BREFNBT.ib");

    const auto crcs = verify_header_crcs(view);
    TEST_OK(crcs, "sample header CRCs");
    if (crcs.ok()) {
        TEST_CHECK(crcs.value().partial_ok);
        TEST_CHECK(crcs.value().full_ok);
        TEST_EQ(crcs.value().stored_partial, golden_number(golden, "dw_crc_partial"), "HEADER.dwCRCPartial");
        TEST_EQ(crcs.value().computed_partial, golden_number(golden, "dw_crc_partial"),
                "dwCRCPartial recomputes with the confirmed variant");
        TEST_EQ(crcs.value().stored_full, golden_number(golden, "dw_crc_full"), "HEADER.dwCRCFull");
        TEST_EQ(crcs.value().computed_full, golden_number(golden, "dw_crc_full"),
                "dwCRCFull recomputes with the confirmed variant");
    }
}

uint32_t util_crc32(const ByteView &view, FileProfile profile);

void check_amap_page_fixture() {
    const std::string golden = read_text(golden_path("synthetic-layout.json"));
    const std::vector<uint8_t> bytes = read_bytes(fixture_path("synthetic-amap-page.bin"));
    TEST_EQ(bytes.size(), ost2pst::ndb::page_size(kProfile), "AMap page fixture size");
    if (bytes.size() != ost2pst::ndb::page_size(kProfile)) {
        return;
    }
    const uint64_t ib = golden_number(golden, "amap_first_offset");
    const ByteView view(bytes.data(), bytes.size(), ib);

    const auto window = view.sub(ost2pst::ndb::bt_trailer_offset(kProfile),
                                 ost2pst::ndb::page_trailer_size(kProfile));
    TEST_OK(window, "AMap page trailer window");
    if (!window.ok()) {
        return;
    }
    const auto trailer = decode_page_trailer(window.value(), kProfile);
    TEST_OK(trailer, "AMap page trailer");
    if (!trailer.ok()) {
        return;
    }
    TEST_EQ(trailer.value().ptype, ost2pst::ndb::kPageTypeAMap, "PAGETRAILER.ptype is ptypeAMap");
    TEST_EQ(trailer.value().bid, ib, "[MS-PST] 2.2.2.7.1: an AMap page bid equals its own ib");
    TEST_EQ(trailer.value().w_sig, 0, "[MS-PST] 2.2.2.7.1: an AMap page wSig is 0");
    TEST_EQ(trailer.value().dw_crc, golden_number(golden, "amap_first_crc"), "PAGETRAILER.dwCRC");
    TEST_EQ(util_crc32(view, kProfile), golden_number(golden, "amap_first_crc_computed"),
            "AMap page CRC recomputes with the confirmed variant");
    TEST_EQ(bytes[0], ost2pst::ndb::kAmapSelfMapByte, "[MS-PST] 2.2.2.7.2: an AMap maps itself");
}

uint32_t util_crc32(const ByteView &view, FileProfile profile) {
    const ByteView data = view.sub(0, ost2pst::ndb::page_data_bytes(profile)).value();
    return ost2pst::util::crc32(data);
}

void check_bbt_leaf_fixture() {
    const std::string golden = read_text(golden_path("synthetic-layout.json"));
    const std::vector<uint8_t> bytes = read_bytes(fixture_path("synthetic-bbt-leaf.bin"));
    TEST_EQ(bytes.size(), ost2pst::ndb::page_size(kProfile), "BBT leaf fixture size");
    if (bytes.size() != ost2pst::ndb::page_size(kProfile)) {
        return;
    }
    const ByteView view(bytes.data(), bytes.size(), golden_number(golden, "bbt_leaf_ib"));

    const auto footer = decode_bt_page_footer(view, kProfile);
    TEST_OK(footer, "BBT leaf footer");
    if (!footer.ok()) {
        return;
    }
    const BtPageInfo &info = footer.value();
    TEST_EQ(info.c_ent_max, golden_number(golden, "bbt_leaf_c_ent_max"), "BTPAGE.cEntMax");
    TEST_EQ(info.cb_ent, golden_number(golden, "bbt_leaf_cb_ent"), "BTPAGE.cbEnt");
    TEST_EQ(info.c_level, 0, "BTPAGE.cLevel of a leaf");
    TEST_EQ(info.c_ent, golden_number(golden, "bbt_leaf_c_ent"), "BTPAGE.cEnt");

    const auto entries = decode_bbt_entries(view, info);
    TEST_OK(entries, "BBT leaf entries");
    if (!entries.ok() || entries.value().empty()) {
        return;
    }
    const BbtEntry &entry = entries.value().front();
    TEST_EQ(entry.bid, golden_number(golden, "bbt_entry_bid"), "BBTENTRY.bid");
    TEST_EQ(entry.ib, golden_number(golden, "bbt_entry_ib"), "BBTENTRY.ib");
    TEST_EQ(entry.cb, golden_number(golden, "bbt_entry_cb"), "BBTENTRY.cb");
    TEST_EQ(entry.c_ref, golden_number(golden, "bbt_entry_uncompressed_cb"),
            "BBTENTRY +18: uncompressed data length in the synthetic 4K fixture");
    TEST_EQ(entry.ost_c_ref, golden_number(golden, "bbt_entry_ost_cref"),
            "BBTENTRY +20: reference count in the synthetic 4K fixture");
}

void check_block_fixture() {
    const std::string golden = read_text(golden_path("synthetic-layout.json"));
    const std::vector<uint8_t> bytes = read_bytes(fixture_path("synthetic-block.bin"));
    const uint64_t ib = golden_number(golden, "block_ib");
    const uint64_t cb = golden_number(golden, "block_cb");
    // [MS-PST] 2.2.2.8: the footprint is cb plus the trailer, rounded up to the granularity.
    const uint64_t footprint = ost2pst::ndb::align_allocation(kProfile, cb + ost2pst::ndb::block_trailer_size(kProfile));
    TEST_EQ(bytes.size(), footprint, "block fixture is exactly the footprint");
    TEST_EQ(footprint, golden_number(golden, "block_footprint"), "block footprint");
    if (bytes.size() != footprint) {
        return;
    }

    const uint64_t trailer_at = footprint - ost2pst::ndb::block_trailer_size(kProfile);
    const auto trailer = decode_block_trailer(
        ByteView(bytes.data() + trailer_at, ost2pst::ndb::block_trailer_size(kProfile), ib + trailer_at),
        kProfile);
    TEST_OK(trailer, "block trailer");
    if (!trailer.ok()) {
        return;
    }
    TEST_EQ(trailer.value().cb, golden_number(golden, "block_cb"), "BLOCKTRAILER.cb");
    TEST_EQ(trailer.value().bid, golden_number(golden, "block_bid"), "BLOCKTRAILER.bid");
    TEST_EQ(trailer.value().w_sig, golden_number(golden, "block_wsig"), "BLOCKTRAILER.wSig");
    TEST_EQ(ost2pst::util::compute_sig(ib, trailer.value().bid),
            golden_number(golden, "block_wsig_expected"), "[MS-PST] 5.5: wSig is ComputeSig(ib, bid)");
    TEST_EQ(trailer.value().dw_crc, golden_number(golden, "block_crc"), "BLOCKTRAILER.dwCRC");
    // [MS-PST] 2.2.2.8.1: dwCRC covers only the cb raw bytes, never the padding.
    TEST_EQ(ost2pst::util::crc32(ByteView(bytes.data(), static_cast<size_t>(cb), ib)),
            golden_number(golden, "block_crc_computed"), "block CRC over cb only");
    TEST_EQ(trailer.value().ost_b_typ, golden_number(golden, "block_btyp"), "OST block type slot");
    TEST_EQ(trailer.value().ost_uncompressed_cb, golden_number(golden, "block_uncompressed_cb"),
            "OST uncompressed cb slot equals BBTENTRY +18");
}

void check_dlist_fixture() {
    const std::string golden = read_text(golden_path("synthetic-layout.json"));
    const std::vector<uint8_t> bytes = read_bytes(fixture_path("synthetic-dlist-page.bin"));
    TEST_EQ(bytes.size(), ost2pst::ndb::page_size(kProfile), "DList page fixture size");
    if (bytes.size() != ost2pst::ndb::page_size(kProfile)) {
        return;
    }
    const uint64_t ib = golden_number(golden, "dlist_offset");
    const ByteView view(bytes.data(), bytes.size(), ib);
    const auto window = view.sub(ost2pst::ndb::bt_trailer_offset(kProfile),
                                 ost2pst::ndb::page_trailer_size(kProfile));
    TEST_OK(window, "DList page trailer window");
    if (!window.ok()) {
        return;
    }
    const auto trailer = decode_page_trailer(window.value(), kProfile);
    TEST_OK(trailer, "DList page trailer");
    if (!trailer.ok()) {
        return;
    }
    TEST_EQ(trailer.value().ptype, ost2pst::ndb::kPageTypeDList, "PAGETRAILER.ptype is ptypeDL");
    TEST_EQ(trailer.value().bid, golden_number(golden, "dlist_bid"), "DList page bid");
    TEST_EQ(trailer.value().w_sig, golden_number(golden, "dlist_wsig"), "DList page wSig");
    TEST_EQ(ost2pst::util::compute_sig(ib, trailer.value().bid),
            golden_number(golden, "dlist_wsig_expected"), "[MS-PST] 5.5: DList wSig is computed");
    TEST_CHECK(ost2pst::util::crc32(
                   view.sub(0, ost2pst::ndb::page_data_bytes(kProfile)).value()) == trailer.value().dw_crc);
}

} // namespace

int main() {
    check_measured_layout_constants();
    check_header_anchors();
    check_amap_page_fixture();
    check_bbt_leaf_fixture();
    check_block_fixture();
    check_dlist_fixture();
    return ost2pst::test::finish("golden_test");
}
