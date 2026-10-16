// The whole empty PST in one place: the writer builds a file image without reading anything, and every
// reader layer has to accept the bytes. probe_file judges the NDB, read_ndb the BTrees and the blocks,
// and read_ltp the nodes, so a wrong page, block, or heap node shows up as a finding here rather than
// as a claim in a document.
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/ltp_read.h"
#include "ost2pst/ltp/pc.h"
#include "ost2pst/ltp/tc.h"
#include "ost2pst/ndb/amap.h"
#include "ost2pst/ndb/btree.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/ndb/ndb_read.h"
#include "ost2pst/ndb/probe.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/crc32.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/sig.h"
#include "ost2pst/writer/empty_pst.h"

#include "test_support.h"

namespace {

namespace ltp = ost2pst::ltp;
namespace ndb = ost2pst::ndb;

using ost2pst::ltp::LtpFolder;
using ost2pst::ltp::LtpReadOptions;
using ost2pst::ltp::LtpReadReport;
using ost2pst::ltp::read_ltp;
using ost2pst::ndb::FileProfile;
using ost2pst::ndb::NdbReadOptions;
using ost2pst::ndb::NdbReadReport;
using ost2pst::ndb::ProbeCounters;
using ost2pst::ndb::ProbeOptions;
using ost2pst::ndb::ProbeReport;
using ost2pst::ndb::probe_file;
using ost2pst::util::FileReader;
using ost2pst::util::Result;
using ost2pst::writer::build_empty_pst;
using ost2pst::writer::EmptyPstImage;
using ost2pst::writer::WrittenBlock;

const char *kTempName = "ost2pst_writer_empty_pst_test.pst";

std::filesystem::path temp_path(const char *name) {
    std::filesystem::path path = std::filesystem::temp_directory_path();
    path /= name;
    std::error_code ignored;
    if (std::getenv("OST2PST_KEEP_CANDIDATE") == nullptr) {
        std::filesystem::remove(path, ignored);
    }
    return path;
}

// [MS-PST] 2.4.3.2 ENTRYID: four zero flag bytes, the Provider UID, then the NID. The Provider UID is
// the writer's own fixed value, recorded in research/blank-pst-diff.md.
std::vector<uint8_t> entry_id(uint32_t nid) {
    static const uint8_t kUid[16] = {0x22, 0x9D, 0xB5, 0x0A, 0xDC, 0xD9, 0x94, 0x43,
                                     0x85, 0xDE, 0x90, 0xAE, 0xB0, 0x7D, 0x12, 0x70};
    std::vector<uint8_t> bytes(24, 0);
    for (size_t index = 0; index < 16; ++index) {
        bytes[4 + index] = kUid[index];
    }
    bytes[20] = static_cast<uint8_t>(nid & 0xFFu);
    bytes[21] = static_cast<uint8_t>((nid >> 8) & 0xFFu);
    bytes[22] = static_cast<uint8_t>((nid >> 16) & 0xFFu);
    bytes[23] = static_cast<uint8_t>((nid >> 24) & 0xFFu);
    return bytes;
}

bool contains(const std::vector<uint8_t> &haystack, const std::vector<uint8_t> &needle) {
    if (needle.size() > haystack.size()) {
        return false;
    }
    for (size_t at = 0; at + needle.size() <= haystack.size(); ++at) {
        bool match = true;
        for (size_t index = 0; index < needle.size(); ++index) {
            if (haystack[at + index] != needle[index]) {
                match = false;
                break;
            }
        }
        if (match) {
            return true;
        }
    }
    return false;
}

const LtpFolder *find_folder(const std::vector<LtpFolder> &folders, uint64_t nid) {
    for (const LtpFolder &folder : folders) {
        if (folder.nid == nid) {
            return &folder;
        }
    }
    return nullptr;
}

// A failure or a finding is only useful if the run says which one, so the report's own items get
// printed before the assertion that counts them.
void dump_failures(const char *tag, const std::vector<ndb::ProbeFailure> &failures) {
    for (const ndb::ProbeFailure &failure : failures) {
        std::fprintf(stderr, "%s failure: %s at 0x%llx (value 0x%llx): %s\n", tag,
                     failure.field.c_str(), static_cast<unsigned long long>(failure.offset),
                     static_cast<unsigned long long>(failure.value), failure.detail.c_str());
    }
}

void dump_finding(const ltp::LtpFinding &finding) {
    std::fprintf(stderr, "read_ltp finding: NID 0x%llx type 0x%llx bid 0x%llx %s: %s\n",
                 static_cast<unsigned long long>(finding.nid),
                 static_cast<unsigned long long>(finding.nid_type),
                 static_cast<unsigned long long>(finding.bid), finding.field.c_str(),
                 finding.detail.c_str());
}

const WrittenBlock *find_block(const std::vector<WrittenBlock> &blocks, uint64_t bid) {
    for (const WrittenBlock &block : blocks) {
        if (block.bid == bid) {
            return &block;
        }
    }
    return nullptr;
}

void check_internal_decoders() {
    class Heap : public ltp::HeapSource {
      public:
        std::map<uint32_t, std::vector<uint8_t>> items;
        Result<ost2pst::util::ByteView> heap(uint32_t hid) override {
            auto found = items.find(hid);
            if (found == items.end())
                return ost2pst::util::make_error(ost2pst::util::ErrorKind::kBadField, "test.HID", 0,
                                                 hid, "missing fixture allocation");
            return ost2pst::util::ByteView(found->second.data(), found->second.size(), hid);
        }
    } heap;
    ltp::HnHeader hn;
    hn.b_client_sig = 0x9C;
    hn.hid_user_root = 0x20;
    heap.items[0x20] = {0x40, 0, 0, 0};
    heap.items[0x40] = {0xB5, 16, 4, 0, 0, 0, 0, 0};
    auto check = [&](bool expected_ok, uint64_t records) {
        ltp::BthStats stats;
        ndb::FailureLog failures;
        auto status = ltp::validate_guid_map(hn, FileProfile::kPst, heap, stats, failures);
        TEST_EQ(status.ok(), expected_ok, "GUID map validation");
        if (status.ok())
            TEST_EQ(stats.leaf_records, records, "GUID records");
    };
    check(true, 0);
    heap.items[0x40][4] = 0x60;
    heap.items[0x60] = std::vector<uint8_t>(20, 0);
    heap.items[0x60][16] = 0x22;
    check(true, 1); // Nonempty maps use the same documented layout as the empty oracle.
    heap.items[0x60].push_back(0);
    check(false, 0); // A recovered BTH with trailing bytes must not become clean.
    heap.items[0x60].pop_back();
    heap.items[0x40][1] = 8;
    check(false, 0);
    heap.items[0x40][1] = 16;
    heap.items[0x20].push_back(0);
    check(false, 0);
    heap.items[0x20].pop_back();
    heap.items.erase(0x60);
    check(false, 0);

    const uint8_t sal[] = {0x23, 0x22, 0, 0};
    auto decoded = ltp::decode_search_activity_list({sal, sizeof(sal), 0x100});
    TEST_OK(decoded, "SAL array");
    if (decoded.ok()) {
        TEST_EQ(decoded.value().size(), 1u, "SAL length");
        TEST_EQ(decoded.value()[0], 0x2223u, "SAL NID");
    }
    TEST_CHECK(ltp::decode_search_activity_list({}).ok());
    TEST_CHECK(!ltp::decode_search_activity_list({sal, 3, 0x100}).ok());
}

void check_image_bookkeeping(const EmptyPstImage &image) {
    // These columns are present in the Outlook oracle and explicitly required by
    // SCANPST 16.0.20430.20032; the old schema missed or mistyped all six.
    const std::pair<uint64_t, uint32_t> required[] = {
        {40, 0x0E300102}, {40, 0x3613001F}, {44, 0x0E300102}, {44, 0x30130102}, {48, 0x682F001F},
        {52, 0x0058000B}, {64, 0x001A001F}, {64, 0x66050003}, {68, 0x00390040}, {68, 0x0E100003},
        {68, 0x0E140003}, {72, 0x0E330014}, {72, 0x0E370102}, {72, 0x0E380003}, {76, 0x001A001F},
        {76, 0x0E300102}, {76, 0x0E310102}, {76, 0x0E330014}, {76, 0x0E340102}, {76, 0x0E380003},
        {76, 0x0E3E0102}, {80, 0x0E330014}, {80, 0x30070040},
    };
    for (const auto& entry : required) {
        const auto* block = find_block(image.blocks, entry.first);
        TEST_CHECK(block != nullptr);
        if (!block)
            continue;
        const ost2pst::util::ByteView view(image.bytes.data() + block->ib, block->cb, block->ib);
        auto hn = ltp::decode_hn_header(view);
        TEST_OK(hn, "template HN");
        if (!hn.ok())
            continue;
        auto map = ltp::decode_hn_page_map(view, hn.value().ib_hnpm);
        TEST_OK(map, "template map");
        if (!map.ok())
            continue;
        ltp::BlockHeapSource source(view, map.value(), FileProfile::kPst, 0);
        auto tc = ltp::read_tc(hn.value(), source);
        TEST_OK(tc, "template TC");
        if (!tc.ok())
            continue;
        bool found = false;
        for (const auto& column : tc.value().columns)
            found |= column.tag == entry.second;
        TEST_CHECK_MSG(found, "Outlook-required template column missing or mistyped");
        if (entry.first == 64) {
            auto matrix = source.heap(tc.value().info.hnid_rows);
            TEST_OK(matrix, "receive row matrix");
            if (!matrix.ok())
                continue;
            for (const auto& column : tc.value().columns) {
                auto cell = ltp::tc_column_cell(tc.value(), column, matrix.value());
                TEST_OK(cell, "receive row cell");
                if (!cell.ok())
                    continue;
                TEST_CHECK(cell.value().exists);
                if (column.tag == 0x001A001F)
                    TEST_EQ(matrix.value().u32(column.ib_data).value(), 0u,
                            "default receive class");
                if (column.tag == 0x66050003)
                    TEST_EQ(matrix.value().u32(column.ib_data).value(), 0x122u, "receive target");
            }
        }
    }
    TEST_EQ(image.blocks.size(), 23u, "writer block count");
    TEST_EQ(image.bid_next_b, 96u, "writer bidNextB");
    TEST_EQ(image.bid_next_p, 9u, "writer bidNextP");
    TEST_CHECK_MSG(image.bytes.size() >= 0x4800, "the file has to reach past the first data block");

    // [MS-PST] 2.2.2.7.7.3.1: cRef is the block's own leaf BBTENTRY plus the NBTENTRY bidData/bidSub
    // and SLENTRY bidData slots that name it. The template blocks are shared, so they carry the
    // higher counts: 0x60D 4 references, 0x60E and 0x60F 6 each, 0x610 2, and every other block 1.
    struct Expectation {
        uint64_t bid;
        uint16_t c_ref;
    };
    const Expectation expectations[] = {
        {4, 2},  {8, 2},  {12, 2}, {16, 2}, {20, 2}, {24, 2}, {28, 2}, {32, 2},
        {36, 2}, {40, 5}, {44, 7}, {48, 7}, {52, 3}, {56, 2}, {60, 2}, {64, 2},
        {68, 2}, {72, 2}, {76, 2}, {80, 2}, {84, 2}, {88, 2}, {92, 2},
    };
    for (const Expectation &expectation : expectations) {
        const WrittenBlock *block = find_block(image.blocks, expectation.bid);
        if (block == nullptr) {
            ost2pst::test::report_failure(__FILE__, __LINE__, "no block with this BID");
            continue;
        }
        TEST_EQ(block->c_ref, expectation.c_ref, "cRef");
    }
}

void check_entry_ids(const EmptyPstImage &image) {
    const WrittenBlock* store = find_block(image.blocks, 4);
    TEST_CHECK(store != nullptr);
    if (store == nullptr)
        return;
    const ost2pst::util::ByteView view(image.bytes.data() + store->ib, store->cb, store->ib);
    auto hn = ltp::decode_hn_header(view);
    TEST_OK(hn, "store HN");
    if (!hn.ok())
        return;
    auto map = ltp::decode_hn_page_map(view, hn.value().ib_hnpm);
    TEST_OK(map, "store page map");
    if (!map.ok())
        return;
    ltp::BlockHeapSource source(view, map.value(), FileProfile::kPst, 0);
    ltp::BthStats stats;
    ndb::FailureLog failures;
    bool password_found = false;
    auto status = ltp::read_pc(
        hn.value(), FileProfile::kPst, source,
        [&](const ltp::PcRecord& record) {
            if (record.prop_id == 0x67FF) {
                password_found = true;
                TEST_EQ(record.prop_type, 0x0003u, "PST password is Integer32");
                TEST_EQ(record.value_hnid, 0u, "empty PST has no password");
            }
            return true;
        },
        stats, failures);
    TEST_CHECK(status.ok());
    TEST_CHECK_MSG(password_found, "Outlook store must carry explicit PR_PST_PASSWORD=0");
    // [MS-PST] 2.4.3.1 requires the three EntryIDs on the message store PC, and [MS-PST] 3.10's own
    // sample message store puts NIDs 0x8022, 0x8062 and 0x8042 in them.
    const uint32_t nids[] = {0x8022, 0x8062, 0x8042};
    for (const uint32_t nid : nids) {
        TEST_CHECK_MSG(contains(image.bytes, entry_id(nid)), "the message store carries this EntryID");
    }
}

// [MS-PST] 2.2.2.7.2 / 2.2.2.7.3: one AMap bit per 64-byte allocation unit of the region that starts at
// the AMap's own offset, and that region holds the AMap page, the PMap page, every data block and every
// BTree page. This walks the finished bytes and compares the bits against what the file really holds, so
// a page the writer forgot to mark is a bit that should have been set -- the mistake neither the CRC
// checks nor the self-round-trip read notices, because a free page still reads back correctly.
void check_allocation_map(const EmptyPstImage &image) {
    const std::vector<uint8_t> &bytes = image.bytes;
    const uint64_t granularity = ndb::block_granularity(FileProfile::kPst);
    const uint64_t page_size = ndb::page_size(FileProfile::kPst);
    const uint64_t units_per_page = page_size / granularity;
    const uint64_t first_unit = ndb::amap_first_unit(FileProfile::kPst, ndb::kPstAmapFirstOffset);
    const uint8_t *bits = bytes.data() + ndb::kPstAmapFirstOffset;

    // [MS-PST] 2.6.1.1.2: growth is in whole AMap regions; 2.2.2.7.2 maps
    // 496 * 8 allocations of 64 bytes, beginning at the AMap itself. A readable
    // last data block does not prove that the advertised free space exists.
    const uint64_t region_end = ndb::kPstAmapFirstOffset + 496u * 8u * 64u;
    TEST_EQ(bytes.size(), region_end, "the empty PST must back its complete AMap region");
    TEST_CHECK_MSG(image.cb_amap_free <= bytes.size() - ndb::kPstAmapFirstOffset,
                   "AMap free bytes cannot exceed the physical data region");

    auto u16 = [&](uint64_t at) {
        return static_cast<uint16_t>(bytes[at]) |
               static_cast<uint16_t>(static_cast<uint16_t>(bytes[at + 1]) << 8);
    };
    auto u32 = [&](uint64_t at) {
        return static_cast<uint32_t>(u16(at)) | (static_cast<uint32_t>(u16(at + 2)) << 16);
    };
    auto u64 = [&](uint64_t at) {
        return static_cast<uint64_t>(u32(at)) | (static_cast<uint64_t>(u32(at + 4)) << 32);
    };

    // Every unit a block footprint covers: cb plus the trailer, rounded to the allocation granularity.
    std::set<uint64_t> units;
    for (const WrittenBlock &block : image.blocks) {
        const uint64_t footprint =
            ndb::align_allocation(FileProfile::kPst, block.cb + ndb::block_trailer_size(FileProfile::kPst));
        for (uint64_t unit = block.ib / granularity; unit < (block.ib + footprint) / granularity; ++unit) {
            units.insert(unit);
        }
    }

    // A 512-byte slot counts as a page only when its trailer vouches for itself: ptype in range,
    // ptypeRepeat equal, wSig matching (ib, bid) and dwCRC matching the page bytes it covers.
    uint64_t pages = 0;
    for (uint64_t ib = ndb::kPstDlistOffset; ib + page_size <= bytes.size(); ib += page_size) {
        const uint64_t at = ib + ndb::bt_trailer_offset(FileProfile::kPst);
        const uint8_t ptype = bytes[at + ndb::kPageTrailerPtypeOffset];
        if (ptype < ndb::kFirstPageType || ptype > ndb::kLastPageType) {
            continue;
        }
        if (bytes[at + ndb::kPageTrailerPtypeRepeatOffset] != ptype) {
            continue;
        }
        const uint64_t bid = u64(at + ndb::kPageTrailerBidOffset);
        if (u16(at + ndb::kPageTrailerWSigOffset) != ost2pst::util::compute_sig(ib, bid)) {
            continue;
        }
        const uint64_t data_bytes = ndb::page_data_bytes(FileProfile::kPst);
        if (u32(at + ndb::kPageTrailerCrcOffset) !=
            ost2pst::util::crc32(
                ost2pst::util::ByteView(bytes.data() + ib, static_cast<size_t>(data_bytes), ib))) {
            continue;
        }
        ++pages;
        for (uint64_t unit = ib / granularity; unit < (ib + page_size) / granularity; ++unit) {
            units.insert(unit);
        }
    }
    // The DList, AMap and PMap pages, three BBT pages and four NBT pages.
    TEST_EQ(pages, 10u, "pages whose trailer vouches for itself");

    uint64_t in_region = 0;
    for (uint64_t unit : units) {
        if (unit >= first_unit) {
            ++in_region;
        }
    }

    uint64_t marked = 0;
    uint64_t marked_free = 0;
    uint64_t unmarked_allocated = 0;
    for (uint64_t index = 0; index < ndb::amap_units(FileProfile::kPst); ++index) {
        const uint64_t unit = first_unit + index;
        const bool bit = ndb::amap_bit_set(bits, index, ndb::AMapBitOrder::kMostSignificantFirst);
        const bool allocated = units.count(unit) != 0;
        marked += bit ? 1u : 0u;
        if (bit && !allocated) {
            ++marked_free;
        }
        if (!bit && allocated) {
            ++unmarked_allocated;
        }
    }
    TEST_EQ(marked_free, 0u, "the AMap marks a unit the file does not hold");
    TEST_EQ(unmarked_allocated, 0u, "the AMap leaves an allocated unit free");
    TEST_EQ(marked, in_region, "AMap bits versus the units the file holds");
    TEST_EQ(image.amap_bits_set, marked, "the writer's own AMap bit count");
    TEST_EQ(image.cb_amap_free, (ndb::amap_units(FileProfile::kPst) - marked) * granularity,
            "cbAMapFree versus the AMap bits");

    // [MS-PST] 2.2.2.7.3: the PMap page sits inside the region the AMap maps, so every one of its units
    // is marked. Marking the AMap page twice instead leaves the PMap looking free for the next allocator
    // to overwrite, and cbAMapFree 512 bytes too large.
    const uint64_t pmap_ib = ndb::kPstAmapFirstOffset + page_size;
    uint64_t pmap_marked = 0;
    for (uint64_t unit = pmap_ib / granularity; unit < (pmap_ib + page_size) / granularity; ++unit) {
        pmap_marked += ndb::amap_bit_set(bits, unit - first_unit,
                                         ndb::AMapBitOrder::kMostSignificantFirst)
                           ? 1u
                           : 0u;
    }
    TEST_EQ(pmap_marked, units_per_page, "the PMap page's allocation units");
}

void check_probe(const FileReader &file) {
    ProbeOptions options;
    Result<ProbeReport> probed = probe_file(file, options);
    TEST_OK(probed, "probe_file");
    if (!probed.ok()) {
        return;
    }
    const ProbeReport &report = probed.value();
    TEST_CHECK_MSG(report.clean, "probe is not clean");
    TEST_EQ(report.failure_total, 0u, "probe failures");
    dump_failures("probe", report.failures);
    TEST_CHECK_MSG(report.profile == FileProfile::kPst, "probe profile");
    TEST_CHECK_MSG(report.header_crcs.partial_ok, "HEADER.dwCRCPartial");
    TEST_CHECK_MSG(report.header_crcs.full_ok, "HEADER.dwCRCFull");
    TEST_CHECK_MSG(report.counters.file_eof_matches_size, "ROOT.ibFileEof");

    TEST_EQ(report.counters.bbt_index_entries, 23u, "probe BBT entries");
    TEST_EQ(report.counters.nbt_entries, 40u, "probe NBT entries");
    TEST_EQ(report.counters.nbt_bid_data_missing, 0u, "NBTENTRY.bidData the BBT does not index");
    TEST_EQ(report.counters.nbt_bid_sub_missing, 0u, "NBTENTRY.bidSub the BBT does not index");
    TEST_EQ(report.counters.blocks.indexed, 23u, "probe blocks indexed");
    TEST_EQ(report.counters.blocks.crc_failed, 0u, "block CRC failures");
    TEST_EQ(report.counters.blocks.cb_mismatches, 0u, "BBTENTRY.cb versus BLOCKTRAILER.cb");
    TEST_EQ(report.counters.blocks.bid_mismatches, 0u, "BBTENTRY.bid versus BLOCKTRAILER.bid");
    TEST_EQ(report.counters.blocks.sig_failed, 0u, "block signature failures");

    TEST_EQ(report.counters.amap.regions, 1u, "AMap regions");
    TEST_EQ(report.counters.amap.regions_valid, 1u, "valid AMap regions");
    TEST_EQ(report.counters.amap.self_byte_ok, 1u, "AMap self-map byte");
    TEST_EQ(report.counters.amap.last_region_matches_ib_amap_last, 1u, "ROOT.ibAMapLast");
    TEST_EQ(report.counters.amap.misses_indexed, 0u, "AMap leaves an allocated block unmarked");

    TEST_EQ(report.counters.dlist_pages, 1u, "DList pages");
    TEST_EQ(report.counters.dlist_at_expected_offset, 1u, "DList offset");

    // Every page the writer wrote has to pass its own trailer check ([MS-PST] 2.2.2.7.1).
    const ProbeCounters &counters = report.counters;
    TEST_EQ(counters.grid.accepted_by_ptype[ndb::kPageTypeBBT - ndb::kFirstPageType], 3u,
            "accepted BBT pages");
    TEST_EQ(counters.grid.accepted_by_ptype[ndb::kPageTypeNBT - ndb::kFirstPageType], 4u, "accepted NBT pages");
    TEST_EQ(counters.grid.accepted_by_ptype[ndb::kPageTypeAMap - ndb::kFirstPageType], 1u, "accepted AMap pages");
    TEST_EQ(counters.grid.accepted_by_ptype[ndb::kPageTypePMap - ndb::kFirstPageType], 1u, "accepted PMap pages");
    TEST_EQ(counters.grid.accepted_by_ptype[ndb::kPageTypeDList - ndb::kFirstPageType], 1u, "accepted DList pages");
    TEST_EQ(counters.grid.crc_failed, 0u, "page grid CRC failures");
}

void check_ndb(const FileReader &file, const EmptyPstImage &image) {
    NdbReadOptions options;
    Result<NdbReadReport> read = read_ndb(file, options);
    TEST_OK(read, "read_ndb");
    if (!read.ok()) {
        return;
    }
    const NdbReadReport &report = read.value();
    TEST_CHECK_MSG(report.clean, "read_ndb is not clean");
    TEST_EQ(report.failure_total, 0u, "read_ndb failures");
    TEST_CHECK_MSG(report.counters.bid_next_b_covers, "HEADER.bidNextB covers the blocks");
    TEST_CHECK_MSG(report.counters.bid_next_p_covers, "HEADER.bidNextP covers the pages");
    TEST_CHECK_MSG(report.counters.file_eof_matches_size, "ROOT.ibFileEof");
    TEST_EQ(report.counters.nbt_entries, 40u, "read_ndb NBT entries");
    TEST_EQ(report.counters.bbt_index_entries, 23u, "read_ndb BBT entries");
    TEST_EQ(report.counters.bbt_index_duplicates, 0u, "duplicate BBT entries");
    TEST_EQ(report.counters.amap_regions, 1u, "read_ndb AMap regions");
    TEST_EQ(report.counters.amap_regions_valid, 1u, "read_ndb valid AMap regions");
    TEST_EQ(report.blocks.crc_failed, 0u, "read_ndb block CRC failures");
    TEST_EQ(report.bbt.page_sig_failed, 0u, "BBT page signature failures");
    TEST_EQ(report.nbt.page_sig_failed, 0u, "NBT page signature failures");
    TEST_EQ(report.bbt.page_crc_failed, 0u, "BBT page CRC failures");
    TEST_EQ(report.nbt.page_crc_failed, 0u, "NBT page CRC failures");
    TEST_EQ(report.bbt.stride_mismatches, 0u, "BBT entry stride mismatches");
    TEST_EQ(report.nbt.stride_mismatches, 0u, "NBT entry stride mismatches");
    TEST_EQ(report.bbt.level_mismatches, 0u, "BBT level mismatches");
    TEST_EQ(report.nbt.level_mismatches, 0u, "NBT level mismatches");
    TEST_EQ(report.nbt.max_level, 1u, "the NBT is one level deep");
    TEST_EQ(report.bbt.max_level, 1u, "the BBT has an index root and two leaves");

    TEST_EQ(report.header.bid_next_b, image.bid_next_b, "HEADER.bidNextB");
    TEST_EQ(report.header.bid_next_p, image.bid_next_p, "HEADER.bidNextP");
    TEST_EQ(report.header.root.ib_amap_last, ndb::kPstAmapFirstOffset, "ROOT.ibAMapLast");
    TEST_EQ(report.header.root.cb_amap_free, image.cb_amap_free, "ROOT.cbAMapFree");
    TEST_EQ(report.header.root.cb_pmap_free, 0u, "ROOT.cbPMapFree");
    TEST_EQ(report.header.root.f_amap_valid, ndb::kFAMapValid2, "ROOT.fAMapValid");
    TEST_EQ(report.header.root.bbt_bref.ib, image.bbt_root_ib, "ROOT.BREFBBT.ib");
    TEST_EQ(report.header.root.nbt_bref.ib, image.nbt_root_ib, "ROOT.BREFNBT.ib");
    TEST_EQ(report.header.b_crypt_method, ndb::kCryptMethodNone, "HEADER.bCryptMethod");
    TEST_EQ(report.header.w_ver, ndb::kMinUnicodeVer, "HEADER.wVer");

    // [MS-PST] 2.2.2.1: rgnid[type] is the last nidIndex allocated for that type.
    TEST_EQ(report.header.rgnid[ltp::kNidTypeNormalFolder], 1027u, "rgnid[NORMAL_FOLDER]");
    TEST_EQ(report.header.rgnid[ltp::kNidTypeSearchFolder], 16384u, "rgnid[SEARCH_FOLDER]");
    TEST_EQ(report.header.rgnid[ltp::kNidTypeNormalMessage], 65536u, "rgnid[NORMAL_MESSAGE]");
    TEST_EQ(report.header.rgnid[ltp::kNidTypeAssocMessage], 32768u, "rgnid[ASSOC_MESSAGE]");
    TEST_EQ(report.header.rgnid[ltp::kNidTypeInternal], 1024u, "rgnid[INTERNAL]");
    TEST_EQ(report.header.rgnid[ltp::kNidTypeHierarchyTable], 1027u, "rgnid[HIERARCHY_TABLE]");

    // The node set [MS-PST] 2.7.1 requires, counted per nidType.
    uint64_t total = 0;
    for (const ndb::NidTypeCount &count : report.nid_types) {
        total += count.entries;
    }
    TEST_EQ(total, 40u, "NBT entries per nidType");
    for (const ndb::NidTypeCount &count : report.nid_types) {
        if (count.nid_type == ltp::kNidTypeInternal) {
            TEST_EQ(count.entries, 6u, "INTERNAL nodes");
            TEST_EQ(count.with_bid_data, 4u, "INTERNAL nodes with a data block");
            TEST_EQ(count.with_bid_sub, 0u, "INTERNAL nodes with a subnode BTree");
        }
        if (count.nid_type == ltp::kNidTypeNormalFolder) {
            TEST_EQ(count.entries, 4u, "NORMAL_FOLDER nodes");
        }
        if (count.nid_type == ltp::kNidTypeSearchFolder) {
            TEST_EQ(count.entries, 1u, "SEARCH_FOLDER nodes");
        }
        if (count.nid_type == ltp::kNidTypeHierarchyTable) {
            TEST_EQ(count.entries, 6u, "HIERARCHY_TABLE nodes");
        }
        if (count.nid_type == ltp::kNidTypeContentsTable) {
            TEST_EQ(count.entries, 6u, "CONTENTS_TABLE nodes");
        }
        if (count.nid_type == ltp::kNidTypeAssocContentsTable) {
            TEST_EQ(count.entries, 6u, "ASSOC_CONTENTS_TABLE nodes");
        }
        if (count.nid_type == ltp::kNidTypeSearchContentsTable) {
            TEST_EQ(count.entries, 2u, "SEARCH_CONTENTS_TABLE nodes");
        }
        if (count.nid_type == ltp::kNidTypeAttachmentTable) {
            TEST_EQ(count.entries, 1u, "ATTACHMENT_TABLE nodes");
        }
        if (count.nid_type == ltp::kNidTypeRecipientTable) {
            TEST_EQ(count.entries, 1u, "RECIPIENT_TABLE nodes");
        }
    }
}

void check_ltp(const FileReader &file) {
    LtpReadOptions options;
    Result<LtpReadReport> read = read_ltp(file, options);
    TEST_OK(read, "read_ltp");
    if (!read.ok()) {
        return;
    }
    const LtpReadReport &report = read.value();
    TEST_CHECK_MSG(report.clean, "read_ltp is not clean");
    TEST_EQ(report.failure_total, 0u, "read_ltp failures");
    TEST_EQ(report.findings.total, 0u, "read_ltp findings");
    TEST_EQ(report.findings.decode_failures, 0u, "read_ltp decode failures");
    dump_failures("read_ltp", report.failures);
    for (const ltp::LtpFinding &finding : report.findings.items) {
        dump_finding(finding);
    }
    TEST_EQ(report.nid_entries, 40u, "read_ltp NID entries");
    TEST_EQ(report.nid_duplicates, 0u, "duplicate NIDs");
    TEST_EQ(report.heap.heap_nodes_rejected, 0u, "heap nodes the reader rejected");
    TEST_EQ(report.heap.compressed, 0u, "compressed blocks in a PST");
    TEST_EQ(report.pcs.failed, 0u, "Property Contexts the reader failed to read");
    TEST_EQ(report.tcs.failed, 0u, "Table Contexts the reader failed to read");
    TEST_EQ(report.pcs.contexts, 8u, "Property Contexts");
    TEST_EQ(report.tcs.contexts, 27u, "Table Contexts");
    TEST_EQ(report.tcs.rows, 5u, "Table Context rows");
    TEST_EQ(report.tcs.columns_only, 24u, "Table Contexts with no rows");
    TEST_EQ(report.guid_maps_read, 1u, "GUID maps validated");
    TEST_EQ(report.guid_map_records, 0u, "empty GUID map records");
    TEST_CHECK(report.sal_read);
    TEST_EQ(report.search_activity_nids.size(), 1u, "SAL entries");
    if (!report.search_activity_nids.empty())
        TEST_EQ(report.search_activity_nids[0], 0x2223u, "SAL search folder");
    TEST_EQ(report.subnodes.found, 0u, "subnodes resolved");
    TEST_EQ(report.subnodes.not_found, 0u, "subnodes not found");
    const std::pair<uint64_t, uint64_t> internal_nodes[] = {
        {0x62B, 64}, {0x64C, 68}, {0x6B6, 72},  {0x6D7, 76}, {0x6F8, 80},
        {0xC01, 84}, {0x201, 88}, {0x2227, 92}, {0xEC1, 0},  {0x2226, 0},
    };
    for (const auto& expected : internal_nodes) {
        auto node = report.nodes.node(expected.first);
        TEST_OK(node, "required internal node");
        if (node.ok()) {
            TEST_EQ(node.value().bid_data, expected.second, "internal node payload");
            TEST_EQ(node.value().bid_sub, 0u, "internal node has no subnodes");
        }
    }

    // [MS-PST] 2.7.3.2 states the minimum map as a PC carrying only the bucket count, but the writer has
    // to emit streams both tools can read (src/writer/empty_pst.cpp), so the map carries one named
    // property with a legal identity plus the hash bucket that record hashes to. The oracle's map has 38
    // entries, which this writer does not reproduce (research/blank-pst-diff.md).
    TEST_CHECK_MSG(report.npm_read, "the Name-to-ID Map was read");
    TEST_EQ(report.npm.bucket_count, ltp::kNameidBucketCountRecommended, "Name-to-ID Map bucket count");
    TEST_EQ(report.npm.bucket_count_defaulted, 0u, "the bucket count is the recommended one");
    TEST_EQ(report.npm.entry_stream_bytes, 8u, "Entry Stream bytes");
    TEST_EQ(report.npm.string_stream_bytes, 4u, "String Stream bytes");
    TEST_EQ(report.npm.guid_stream_bytes, 32u, "GUID Stream bytes");
    TEST_EQ(report.npm.entry_records, 1u, "Entry Stream records");
    TEST_EQ(report.npm.entries_numeric, 1u, "Entry Stream records holding a numeric name");
    TEST_EQ(report.npm.entries_string, 0u, "Entry Stream records holding a String Stream offset");
    TEST_EQ(report.npm.string_names, 0u, "String Stream names");
    TEST_EQ(report.npm.ragged_streams, 0u, "ragged NAMEID streams");
    // [MS-PST] 2.4.7.5 read both ways: every Entry Stream record has to sit in the bucket its own two
    // DWORDs hash to, and every bucket record has to mirror an Entry Stream record. One record, one
    // bucket, one match on each side is what separates a named property from a record nothing points at.
    TEST_EQ(report.npm.buckets_present, 1u, "buckets the PC carries");
    TEST_EQ(report.npm.buckets_missing, ltp::kNameidBucketCountRecommended - 1u, "buckets with no property");
    TEST_EQ(report.npm.bucket_records, 1u, "bucket records");
    TEST_EQ(report.npm.max_bucket_records, 1u, "records in the one bucket");
    TEST_EQ(report.npm.bucket_mismatches, 0u, "a bucket record that hashes elsewhere");
    TEST_EQ(report.npm.crc_matches, 1u, "Entry Stream records a bucket record mirrors");
    TEST_EQ(report.npm.crc_mismatches, 0u, "Entry Stream records no bucket record mirrors");
    TEST_EQ(report.npm.guid_refs_out_of_range, 0u, "wGuid values past the end of the GUID Stream");
    TEST_EQ(report.npm.npid_min, 0x8001u, "the NPID the map declares");
    TEST_EQ(report.npm.npid_max, 0x8001u, "the NPID the map declares");
    TEST_EQ(report.named_properties, 1u, "named properties");
    TEST_CHECK_MSG(report.smq_present, "the Search Management Queue exists");
    TEST_EQ(report.smq.items_queued, 0u, "Search Management Queue items");
    TEST_EQ(report.smq.item_size, ltp::kSudSize, "Search Management Queue item size");

    // [MS-PST] 2.7.2 / 2.7.3.4: the minimum folder hierarchy, with the rows each folder's hierarchy
    // table carries.
    TEST_EQ(report.folders.size(), 5u, "folders");
    TEST_EQ(report.folder_stats.missing, 0u, "hierarchy rows with no NBT entry behind them");
    TEST_EQ(report.folder_stats.blocks_failed, 0u, "folder blocks the reader could not open");
    struct FolderExpectation {
        uint64_t nid;
        uint64_t parent;
        const char *name;
        uint64_t children;
    };
    const FolderExpectation expectations[] = {
        {0x0122, 0x0122, "", 3},
        {0x8022, 0x0122, "Top of Personal Folders", 1},
        {0x8042, 0x0122, "Search Root", 0},
        {0x8062, 0x8022, "Deleted Items", 0},
        {0x2223, 0x0122, "SPAM Search Folder 2", 0},
    };
    uint64_t messages = 0;
    for (const FolderExpectation &expectation : expectations) {
        const LtpFolder *folder = find_folder(report.folders, expectation.nid);
        if (folder == nullptr) {
            ost2pst::test::report_failure(__FILE__, __LINE__, "the folder tree is missing a folder");
            continue;
        }
        TEST_EQ(folder->parent, expectation.parent, "NBTENTRY.nidParent");
        TEST_STR(folder->name, expectation.name, "PidTagDisplayName");
        TEST_CHECK_MSG(folder->name_present, "the folder PC carries a display name");
        TEST_EQ(folder->children, expectation.children, "hierarchy table rows");
        TEST_EQ(folder->messages, 0u, "contents table rows");
        TEST_EQ(folder->associated, 0u, "FAI contents table rows");
        TEST_CHECK_MSG(folder->has_pc, "the folder has a Property Context");
        TEST_CHECK_MSG(folder->has_hierarchy, "the folder has a hierarchy table");
        TEST_CHECK_MSG(folder->has_contents, "the folder has a contents table");
        TEST_CHECK_MSG(folder->has_associated, "the folder has a FAI contents table");
        messages += folder->messages;
    }
    TEST_EQ(messages, 0u, "messages in an empty PST");
}

// Keep NDB valid while breaking an inner GUID-map field: the error must reach
// the whole-file verdict, rather than being hidden as an unsupported structure.
void check_internal_failure_propagates(const EmptyPstImage& image) {
    const auto* block = find_block(image.blocks, 84);
    TEST_CHECK(block != nullptr);
    if (!block)
        return;
    auto bytes = image.bytes;
    const ost2pst::util::ByteView view(bytes.data() + block->ib, block->cb, block->ib);
    auto hn = ltp::decode_hn_header(view);
    TEST_OK(hn, "GUID HN");
    if (!hn.ok())
        return;
    auto map = ltp::decode_hn_page_map(view, hn.value().ib_hnpm);
    TEST_OK(map, "GUID page map");
    if (!map.ok())
        return;
    ltp::BlockHeapSource source(view, map.value(), FileProfile::kPst, 0);
    auto root = source.heap(hn.value().hid_user_root);
    TEST_OK(root, "GUID root");
    if (!root.ok())
        return;
    const uint32_t bth_hid = root.value().u32(0).value();
    auto bth = source.heap(bth_hid);
    TEST_OK(bth, "GUID BTH");
    if (!bth.ok())
        return;
    bytes[bth.value().base() + 1] = 8; // legal generic BTH key width, wrong for GUID keys
    const uint64_t trailer =
        block->ib +
        ndb::align_allocation(FileProfile::kPst,
                              block->cb + ndb::block_trailer_size(FileProfile::kPst)) -
        ndb::block_trailer_size(FileProfile::kPst);
    const uint32_t crc = ost2pst::util::crc32(view);
    for (unsigned index = 0; index < 4; ++index)
        bytes[trailer + ndb::kBlockTrailerCrcOffset + index] =
            static_cast<uint8_t>(crc >> (index * 8));
    const auto path = temp_path("ost2pst_writer_bad_guid_test.pst");
    {
        std::ofstream stream(path, std::ios::binary);
        stream.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
    }
    {
        auto file = FileReader::open(path.native());
        TEST_OK(file, "open corrupt GUID fixture");
        if (file.ok()) {
            auto report = read_ltp(file.value(), {});
            TEST_OK(report, "read corrupt GUID fixture");
            if (report.ok()) {
                TEST_CHECK(!report.value().clean);
                TEST_EQ(report.value().findings.decode_failures, 1u, "one GUID decode failure");
                TEST_EQ(report.value().findings.unsupported, 0u,
                        "bad GUID map is not silently unsupported");
                TEST_EQ(report.value().guid_maps_read, 0u, "failed GUID map not counted as read");
                TEST_EQ(report.value().blocks.crc_failed, 0u, "fixture block CRC is valid");
            }
        }
    }
    std::error_code ignored;
    if (std::getenv("OST2PST_KEEP_CANDIDATE") == nullptr)
        std::filesystem::remove(path, ignored);
}

// [MS-PST] 2.2.2.7.7.2: an intermediate entry's btkey is the BID of a BBT page, and every key in the
// child page it names has to be greater than or equal to it. ndb::BTreeWalker visits pages by level and
// never descends by key, so nothing else in this suite would notice a btkey that a key-seeking reader,
// such as the libpff gate or Outlook, could take to the wrong page.
void check_bbt_index_keys(const EmptyPstImage &image) {
    const auto page = [&](uint64_t ib) {
        return ost2pst::util::ByteView(image.bytes.data() + ib, ndb::kPstPageSize, ib);
    };
    Result<ndb::BtPageInfo> root_footer = ndb::decode_bt_page_footer(page(image.bbt_root_ib), FileProfile::kPst);
    TEST_OK(root_footer, "BBT root footer");
    if (!root_footer.ok()) {
        return;
    }
    TEST_EQ(root_footer.value().c_level, 1u, "the BBT root is an index page");
    Result<std::vector<ndb::BtEntry>> index = ndb::decode_bt_entries(page(image.bbt_root_ib), root_footer.value());
    TEST_OK(index, "BBT index entries");
    if (!index.ok()) {
        return;
    }
    TEST_EQ(index.value().size(), 2u, "two BBT leaves under one index root");

    uint64_t leaf_entries = 0;
    uint64_t previous_key = 0;
    for (const ndb::BtEntry &entry : index.value()) {
        TEST_CHECK_MSG(entry.bt_key > previous_key, "index btkeys ascend");
        previous_key = entry.bt_key;
        TEST_CHECK_MSG(entry.bid != 0 && entry.bid < image.bid_next_p,
                       "index entry names a page BID outside HEADER.bidNextP");
        Result<ndb::BtPageInfo> leaf_footer = ndb::decode_bt_page_footer(page(entry.ib), FileProfile::kPst);
        TEST_OK(leaf_footer, "BBT leaf footer");
        if (!leaf_footer.ok()) {
            continue;
        }
        TEST_EQ(leaf_footer.value().c_level, 0u, "the page an index entry names is a leaf");
        Result<std::vector<ndb::BbtEntry>> leaves = ndb::decode_bbt_entries(page(entry.ib), leaf_footer.value());
        TEST_OK(leaves, "BBT leaf entries");
        if (!leaves.ok() || leaves.value().empty()) {
            continue;
        }
        TEST_EQ(entry.bt_key, leaves.value().front().bid,
                "btkey names the smallest key of the page it points at");
        uint64_t previous_bid = 0;
        for (const ndb::BbtEntry &leaf : leaves.value()) {
            TEST_CHECK_MSG(leaf.bid > previous_bid, "leaf BIDs ascend inside a BBT leaf");
            previous_bid = leaf.bid;
            ++leaf_entries;
        }
    }
    TEST_EQ(leaf_entries, image.blocks.size(), "every written block is indexed by exactly one leaf");
}

} // namespace

int main() {
    check_internal_decoders();
    Result<EmptyPstImage> built = build_empty_pst();
    TEST_OK(built, "build_empty_pst");
    if (!built.ok()) {
        return ost2pst::test::finish("writer_empty_pst_test");
    }
    const EmptyPstImage &image = built.value();

    check_image_bookkeeping(image);
    check_allocation_map(image);
    check_entry_ids(image);
    check_internal_failure_propagates(image);
    check_bbt_index_keys(image);

    const std::filesystem::path path = temp_path(kTempName);
    {
        std::ofstream stream(path, std::ios::binary);
        if (!stream) {
            ost2pst::test::report_failure(__FILE__, __LINE__, "cannot create the candidate PST");
            return ost2pst::test::finish("writer_empty_pst_test");
        }
        stream.write(reinterpret_cast<const char *>(image.bytes.data()),
                     static_cast<std::streamsize>(image.bytes.size()));
    }

    Result<FileReader> opened = FileReader::open(path.native());
    TEST_OK(opened, "FileReader::open");
    if (opened.ok()) {
        check_probe(opened.value());
        check_ndb(opened.value(), image);
        check_ltp(opened.value());
    }

    std::error_code ignored;
    if (std::getenv("OST2PST_KEEP_CANDIDATE") == nullptr) {
        std::filesystem::remove(path, ignored);
    }
    std::printf("  candidate %s: %llu bytes\n", kTempName,
                static_cast<unsigned long long>(image.bytes.size()));
    return ost2pst::test::finish("writer_empty_pst_test");
}
