// ostinfo: the read-only format tool. It never writes a file; it measures a real OST/PST against
// [MS-PST] and prints aggregated counters, never byte dumps. --probe is the M0 format probe,
// --ndb is the M1 NDB read (BBT index, NBT enumeration, block verification).
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>

#define NOMINMAX
// psapi.h requires the Windows types; preserve this dependency order.
// clang-format off
#include <windows.h>
#include <psapi.h>
// clang-format on

#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/ltp_read.h"
#include "ost2pst/ltp/name_id.h"
#include "ost2pst/ltp/node_open.h"
#include "ost2pst/ltp/subtree_dump.h"
#include "ost2pst/msg/inventory.h"
#include "ost2pst/msg/node_class.h"
#include "ost2pst/msg/subset.h"
#include "ost2pst/ndb/header.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/ndb/ndb_read.h"
#include "ost2pst/ndb/probe.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/crc32.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/status.h"

#include "read_only.h"

namespace {

using ost2pst::ltp::DataTreeCounters;
using ost2pst::ltp::FolderWalkStats;
using ost2pst::ltp::LtpFolder;
using ost2pst::ltp::LtpHeapCounters;
using ost2pst::ltp::LtpNodeDump;
using ost2pst::ltp::LtpPcCounters;
using ost2pst::ltp::LtpPropertyValue;
using ost2pst::ltp::LtpReadOptions;
using ost2pst::ltp::LtpReadReport;
using ost2pst::ltp::LtpTcCounters;
using ost2pst::ltp::SubnodeStats;
using ost2pst::ndb::AMapBitOrder;
using ost2pst::ndb::AMapCounters;
using ost2pst::ndb::BlockCounters;
using ost2pst::ndb::BlockReadCounters;
using ost2pst::ndb::BTreeStats;
using ost2pst::ndb::CrcVariantTally;
using ost2pst::ndb::Header;
using ost2pst::ndb::HeaderCrcReport;
using ost2pst::ndb::NdbReadCounters;
using ost2pst::ndb::NdbReadOptions;
using ost2pst::ndb::NdbReadReport;
using ost2pst::ndb::PageGridCounters;
using ost2pst::ndb::ProbeCounters;
using ost2pst::ndb::ProbeOptions;
using ost2pst::ndb::ProbeReport;
using ost2pst::ndb::Root;
using ost2pst::util::FileReader;

// Exit codes are part of the CLI contract: scripts/verify.sh reads them.
enum ExitCode {
    kExitOk = 0,
    kExitUsage = 1,
    kExitIo = 1,
    kExitRefusal = 2,
    kExitCorrupt = 3,
};

enum ParseResult {
    kParseOk,
    kParseHelp,
    kParseError,
};

enum Action {
    kActionProbe,
    kActionNdb,
    kActionLtp,
    kActionInventory,
    kActionSubtree,
    kActionSubset,
};

std::string to_utf8(const std::wstring& wide) {
    return ost2pst::cli::to_utf8(wide);
}

// An NID is written as hex in every [MS-PST] table, so --nid accepts either base.
bool parse_id(const std::wstring& text, uint64_t& destination) {
    if (text.empty() || text.front() < L'0' || text.front() > L'9')
        return false;
    errno = 0;
    wchar_t* end = nullptr;
    const unsigned long long value = wcstoull(text.c_str(), &end, 0);
    if (errno != 0 || end == text.c_str() || *end != L'\0') {
        return false;
    }
    destination = value;
    return true;
}

bool parse_count(const std::wstring& text, uint64_t& destination) {
    if (text.empty() || text.front() < L'0' || text.front() > L'9')
        return false;
    errno = 0;
    wchar_t* end = nullptr;
    const unsigned long long value = wcstoull(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str() || *end != L'\0') {
        return false;
    }
    destination = value;
    return true;
}

void print_usage() {
    printf("ostinfo - read-only [MS-PST] reader\n");
    printf("\n");
    printf("  ostinfo --probe <file> [options]   full format probe (M0)\n");
    printf(
        "  ostinfo --ndb   <file> [options]   NDB read: BBT index, NBT walk, block verify (M1)\n");
    printf("  ostinfo --ltp   <file> [options]   LTP read: NID map, heap nodes, PCs, TCs, folders "
           "(M2)\n");
    printf("  ostinfo --inventory <file> [options]  Messaging inventory: messages, attachments, "
           "FAI,\n");
    printf("                           folders, and what the source does not contain (M3)\n");
    printf("\n");
    printf("  Options may appear before or after the file.\n");
    printf("  --probe <path>           run the format probe\n");
    printf("  --ndb <path>             run the NDB read\n");
    printf("  --ltp <path>             run the LTP read\n");
    printf("  --inventory <path>       run the Messaging inventory (implies the LTP read)\n");
    printf("  --nid <N>                --ltp: also dump this NID's properties by tag\n");
    printf("  --subtree <N>            dump one NID's node and the subnodes its bidSub names "
           "(implies the\n");
    printf("                           LTP read without the census of every data block)\n");
    printf("  --subset <N>             read one folder's content the way a conversion would: its "
           "Message\n");
    printf("                           objects, their Recipient and Attachment Table rows, the "
           "Attachment\n");
    printf(
        "                           objects those rows name, and what the source does not carry\n");
    printf("                           (implies the LTP read without the census of every data "
           "block)\n");
    printf("  --no-payloads            --subset: report the 0x3701 records without reading their "
           "bytes\n");
    printf("  --max-failures <N>       findings kept for display (default 10; counting is "
           "unbounded)\n");
    printf("  --max-block-verify <N>   BBT-indexed blocks whose trailer and CRC get checked\n");
    printf("                           (default 0 = every indexed block, --probe only)\n");
    printf(
        "  --no-verify-blocks       --ndb: enumerate NBT entries without opening their blocks\n");
    printf("  --no-amap                --ndb: skip the allocation map chain\n");
    printf("  --no-scan-blocks         --ltp: skip opening every data block, read the folder tree "
           "only\n");
    printf("  --no-folders             --ltp: skip the folder hierarchy walk\n");
    printf("  --max-messages <N>       --inventory: cap the Message objects scanned (default "
           "1000000)\n");
    printf("  --max-embedded <N>       --inventory: cap the attached messages scanned (default "
           "1000000)\n");
    printf("  --max-embedded-depth <N> --inventory: how deep message -> attachment -> message may "
           "go\n");
    printf("                           (default 8)\n");
    printf("  --no-samples             --inventory: skip the named attachment samples\n");
    printf("  --amap-bit-order lsb|msb bit order inside an AMap byte (default msb: measured on the "
           "sample)\n");
    printf("  --help                   this text\n");
    printf("\n");
    printf("exit: 0 clean, 1 usage or IO, 2 refused format, 3 findings present\n");
}

ParseResult parse_options(int argc, wchar_t** argv, std::wstring& path, Action& action,
                          ProbeOptions& options, NdbReadOptions& ndb_options,
                          LtpReadOptions& ltp_options,
                          ost2pst::msg::InventoryOptions& inventory_options,
                          ost2pst::msg::SubsetOptions& subset_options, uint64_t& subtree_nid,
                          uint64_t& subset_nid) {
    bool action_chosen = false;
    for (int index = 1; index < argc; ++index) {
        const std::wstring argument = argv[index];
        if (argument == L"--help" || argument == L"-h") {
            return kParseHelp;
        }
        if (argument == L"--probe" || argument == L"--ndb" || argument == L"--ltp" ||
            argument == L"--inventory") {
            if (action_chosen) {
                return kParseError;
            }
            if (argument == L"--probe") {
                action = kActionProbe;
            } else if (argument == L"--ndb") {
                action = kActionNdb;
            } else if (argument == L"--ltp") {
                action = kActionLtp;
            } else {
                action = kActionInventory;
            }
            action_chosen = true;
            continue;
        }
        if (argument == L"--no-verify-blocks") {
            ndb_options.verify_bid_data = false;
            continue;
        }
        if (argument == L"--no-amap") {
            ndb_options.scan_amap = false;
            continue;
        }
        if (argument == L"--no-scan-blocks") {
            ltp_options.scan_blocks = false;
            continue;
        }
        if (argument == L"--no-folders") {
            ltp_options.build_folders = false;
            continue;
        }
        if (argument == L"--no-samples") {
            inventory_options.collect_samples = false;
            continue;
        }
        if (argument == L"--no-payloads") {
            subset_options.collect_payloads = false;
            continue;
        }
        if (!argument.empty() && argument[0] != L'-') {
            // The file may sit anywhere in the command line: `--ndb file --no-amap` and
            // `--ndb --no-amap file` mean the same thing. A second bare token is a mistake.
            if (!path.empty()) {
                return kParseError;
            }
            path = argument;
            continue;
        }
        if (index + 1 >= argc) {
            return kParseError;
        }
        const std::wstring value = argv[++index];
        if (argument == L"--max-failures") {
            uint64_t parsed = 0;
            if (!parse_count(value, parsed) || parsed > 1000000) {
                return kParseError;
            }
            options.max_failures = static_cast<size_t>(parsed);
            ndb_options.max_failures = static_cast<size_t>(parsed);
            ltp_options.max_failures = static_cast<size_t>(parsed);
        } else if (argument == L"--nid") {
            uint64_t parsed = 0;
            if (!parse_id(value, parsed) || parsed > 0xFFFFFFFFull) {
                return kParseError;
            }
            ltp_options.dump_nid = parsed;
            ltp_options.dump_requested = true;
        } else if (argument == L"--subtree") {
            uint64_t parsed = 0;
            // NID 0 names no node, so an unset --subtree stays distinguishable from a requested
            // one.
            if (!parse_id(value, parsed) || parsed == 0 || parsed > 0xFFFFFFFFull) {
                return kParseError;
            }
            subtree_nid = parsed;
        } else if (argument == L"--subset") {
            uint64_t parsed = 0;
            // NID 0 names no node, so an unset --subset stays distinguishable from a requested one.
            if (!parse_id(value, parsed) || parsed == 0 || parsed > 0xFFFFFFFFull) {
                return kParseError;
            }
            subset_nid = parsed;
        } else if (argument == L"--max-messages") {
            uint64_t parsed = 0;
            if (!parse_count(value, parsed) || parsed > 100000000) {
                return kParseError;
            }
            inventory_options.max_messages = parsed;
            inventory_options.max_associated = parsed;
            subset_options.max_messages = parsed;
        } else if (argument == L"--max-embedded") {
            uint64_t parsed = 0;
            if (!parse_count(value, parsed) || parsed > 100000000) {
                return kParseError;
            }
            inventory_options.max_embedded = parsed;
        } else if (argument == L"--max-embedded-depth") {
            uint64_t parsed = 0;
            if (!parse_count(value, parsed) || parsed > 64) {
                return kParseError;
            }
            inventory_options.max_embedded_depth = static_cast<uint32_t>(parsed);
        } else if (argument == L"--max-block-verify") {
            if (!parse_count(value, options.max_block_verify)) {
                return kParseError;
            }
        } else if (argument == L"--amap-bit-order") {
            if (value == L"msb" || value == L"msb-first") {
                options.amap_bit_order = AMapBitOrder::kMostSignificantFirst;
                ndb_options.amap_bit_order = AMapBitOrder::kMostSignificantFirst;
            } else if (value == L"lsb" || value == L"lsb-first") {
                options.amap_bit_order = AMapBitOrder::kLeastSignificantFirst;
                ndb_options.amap_bit_order = AMapBitOrder::kLeastSignificantFirst;
            } else {
                return kParseError;
            }
        } else {
            return kParseError;
        }
    }
    if (subtree_nid != 0) {
        // --subtree implies its own read: it needs the NID map and the BBT index, not the census.
        action = kActionSubtree;
        action_chosen = true;
    }
    if (subset_nid != 0) {
        // --subset needs the same two things --subtree needs, and for the same reason: the
        // extractor walks the nodes one folder names instead of opening every data block in the
        // file.
        action = kActionSubset;
        action_chosen = true;
    }
    return action_chosen && !path.empty() ? kParseOk : kParseError;
}

void print_header(const Header& header) {
    printf("HEADER\n");
    printf("  dwMagic           0x%08X\n", header.dw_magic);
    printf("  wMagicClient      %s\n", ost2pst::ndb::magic_client_text(header).c_str());
    printf("  wVer              %u\n", static_cast<unsigned>(header.w_ver));
    printf("  wVerClient        %u\n", static_cast<unsigned>(header.w_ver_client));
    printf("  bPlatform         create 0x%02X access 0x%02X\n",
           static_cast<unsigned>(header.b_platform_create),
           static_cast<unsigned>(header.b_platform_access));
    printf("  bSentinel         0x%02X\n", static_cast<unsigned>(header.b_sentinel));
    printf("  bCryptMethod      0x%02X\n", static_cast<unsigned>(header.b_crypt_method));
    printf("  bidNextP          %llu\n", static_cast<unsigned long long>(header.bid_next_p));
    printf("  bidNextB          %llu\n", static_cast<unsigned long long>(header.bid_next_b));
}

void print_root(const Root& root, uint64_t file_size) {
    printf("ROOT\n");
    printf("  ibFileEof         %llu (0x%llX)%s\n",
           static_cast<unsigned long long>(root.ib_file_eof),
           static_cast<unsigned long long>(root.ib_file_eof),
           root.ib_file_eof == file_size ? " == file size" : " != file size");
    printf("  ibAMapLast        %llu (0x%llX)\n",
           static_cast<unsigned long long>(root.ib_amap_last),
           static_cast<unsigned long long>(root.ib_amap_last));
    printf("  cbAMapFree        %llu\n", static_cast<unsigned long long>(root.cb_amap_free));
    printf("  cbPMapFree        %llu\n", static_cast<unsigned long long>(root.cb_pmap_free));
    printf("  NBT BREF          bid %llu ib 0x%llX\n",
           static_cast<unsigned long long>(root.nbt_bref.bid),
           static_cast<unsigned long long>(root.nbt_bref.ib));
    printf("  BBT BREF          bid %llu ib 0x%llX\n",
           static_cast<unsigned long long>(root.bbt_bref.bid),
           static_cast<unsigned long long>(root.bbt_bref.ib));
    printf("  fAMapValid        0x%02X\n", static_cast<unsigned>(root.f_amap_valid));
}

void print_header_crcs(const HeaderCrcReport& crcs) {
    printf("HEADER CRC\n");
    printf("  dwCRCPartial      stored 0x%08X computed 0x%08X %s\n", crcs.stored_partial,
           crcs.computed_partial, crcs.partial_ok ? "OK" : "MISMATCH");
    printf("  dwCRCFull         stored 0x%08X computed 0x%08X %s\n", crcs.stored_full,
           crcs.computed_full, crcs.full_ok ? "OK" : "MISMATCH");
}

void print_blocks(const BlockCounters& blocks, ost2pst::ndb::FileProfile profile,
                  const ProbeOptions& options) {
    printf("BLOCKS (granularity %llu, trailer %llu, max cb %u)\n",
           static_cast<unsigned long long>(ost2pst::ndb::block_granularity(profile)),
           static_cast<unsigned long long>(ost2pst::ndb::block_trailer_size(profile)),
           static_cast<unsigned>(ost2pst::ndb::block_max_cb(profile)));
    printf("  indexed           %llu, verified %llu%s\n",
           static_cast<unsigned long long>(blocks.indexed),
           static_cast<unsigned long long>(blocks.verified),
           options.max_block_verify == 0 ? " (all)" : " (capped)");
    printf("  cb agrees         %llu, mismatches %llu\n",
           static_cast<unsigned long long>(blocks.cb_matches),
           static_cast<unsigned long long>(blocks.cb_mismatches));
    printf("  bid agrees        %llu, mismatches %llu\n",
           static_cast<unsigned long long>(blocks.bid_matches),
           static_cast<unsigned long long>(blocks.bid_mismatches));
    printf("  wSig              %llu ok, %llu failed\n",
           static_cast<unsigned long long>(blocks.sig_ok),
           static_cast<unsigned long long>(blocks.sig_failed));
    printf("  CRC over cb     %llu ok, %llu failed\n",
           static_cast<unsigned long long>(blocks.crc_ok),
           static_cast<unsigned long long>(blocks.crc_failed));
    if (profile == ost2pst::ndb::FileProfile::kOst) {
        printf("  OST trailer     type=block %llu, other %llu; uncompressed cb agrees %llu, "
               "mismatches %llu\n",
               static_cast<unsigned long long>(blocks.type_block),
               static_cast<unsigned long long>(blocks.type_other),
               static_cast<unsigned long long>(blocks.uncompressed_cb_matches),
               static_cast<unsigned long long>(blocks.uncompressed_cb_mismatches));
        printf("  OST pad slot    BBTENTRY.dwPadding below 1 on %llu entries (counted; meaning "
               "unresolved)\n",
               static_cast<unsigned long long>(blocks.pad_below_one));
    }
    printf("  largest cb        %llu (footprint %llu)\n",
           static_cast<unsigned long long>(blocks.max_cb),
           static_cast<unsigned long long>(blocks.max_footprint));
    printf("  out of range      %llu\n", static_cast<unsigned long long>(blocks.out_of_range));
}

void print_amap(const AMapCounters& amap, ost2pst::ndb::FileProfile profile,
                const ProbeOptions& options) {
    printf("AMAP (bit order %s, interval %llu, units per region %llu)\n",
           ost2pst::ndb::amap_bit_order_name(options.amap_bit_order),
           static_cast<unsigned long long>(ost2pst::ndb::amap_interval(profile)),
           static_cast<unsigned long long>(ost2pst::ndb::amap_units(profile)));
    printf("  regions           %llu scanned, %llu fully valid, self-mapping byte OK on %llu\n",
           static_cast<unsigned long long>(amap.regions),
           static_cast<unsigned long long>(amap.regions_valid),
           static_cast<unsigned long long>(amap.self_byte_ok));
    printf("  last region       %s ROOT.ibAMapLast\n",
           amap.last_region_matches_ib_amap_last ? "reaches" : "does not reach");
    printf("  bits set          %llu over %llu units mapped\n",
           static_cast<unsigned long long>(amap.bits_set),
           static_cast<unsigned long long>(amap.units_mapped));
    printf("  vs BBT units      %llu agree, %llu marked but not indexed, %llu indexed but not "
           "marked\n",
           static_cast<unsigned long long>(amap.units_agree),
           static_cast<unsigned long long>(amap.marks_unindexed),
           static_cast<unsigned long long>(amap.misses_indexed));
}

void print_grid(const PageGridCounters& grid, ost2pst::ndb::FileProfile profile) {
    printf("PAGE GRID (page %llu, trailer at +%llu)\n",
           static_cast<unsigned long long>(ost2pst::ndb::page_size(profile)),
           static_cast<unsigned long long>(ost2pst::ndb::bt_trailer_offset(profile)));
    printf("  slots             %llu, trailer-shaped %llu, CRC and wSig both valid %llu\n",
           static_cast<unsigned long long>(grid.slots),
           static_cast<unsigned long long>(grid.candidates),
           static_cast<unsigned long long>(grid.accepted));
    printf("  failures          %llu CRC, %llu wSig\n",
           static_cast<unsigned long long>(grid.crc_failed),
           static_cast<unsigned long long>(grid.sig_failed));
    for (uint8_t ptype = ost2pst::ndb::kFirstPageType; ptype <= ost2pst::ndb::kLastPageType;
         ++ptype) {
        const size_t slot = ptype - ost2pst::ndb::kFirstPageType;
        printf("  %-6s pages     %6llu candidates, %6llu valid\n",
               ost2pst::ndb::page_type_name(ptype),
               static_cast<unsigned long long>(grid.by_ptype[slot]),
               static_cast<unsigned long long>(grid.accepted_by_ptype[slot]));
    }
}

void print_btree(const char* label, const BTreeStats& stats) {
    printf("%s\n", label);
    printf("  pages             %llu visited, %llu revisited, %llu truncated, %llu bad trailer\n",
           static_cast<unsigned long long>(stats.pages_visited),
           static_cast<unsigned long long>(stats.pages_revisited),
           static_cast<unsigned long long>(stats.pages_truncated),
           static_cast<unsigned long long>(stats.pages_bad_trailer));
    printf("  entries           %llu leaf, %llu intermediate, max level %u\n",
           static_cast<unsigned long long>(stats.leaf_entries),
           static_cast<unsigned long long>(stats.intermediate_entries),
           static_cast<unsigned>(stats.max_level));
    printf("  mismatches        %llu level, %llu stride\n",
           static_cast<unsigned long long>(stats.level_mismatches),
           static_cast<unsigned long long>(stats.stride_mismatches));
    printf("  page CRC          %llu ok / %llu failed, wSig %llu ok / %llu failed\n",
           static_cast<unsigned long long>(stats.page_crc_ok),
           static_cast<unsigned long long>(stats.page_crc_failed),
           static_cast<unsigned long long>(stats.page_sig_ok),
           static_cast<unsigned long long>(stats.page_sig_failed));
}

void print_tally(const char* label, const CrcVariantTally& tally) {
    printf("  %-18s total %8llu | seed0 %8llu | seed0~ %8llu | seedFF %8llu | seedFF~ %8llu\n",
           label, static_cast<unsigned long long>(tally.total),
           static_cast<unsigned long long>(tally.match_seed0_plain),
           static_cast<unsigned long long>(tally.match_seed0_complement),
           static_cast<unsigned long long>(tally.match_seed_ones_plain),
           static_cast<unsigned long long>(tally.match_seed_ones_complement));
}

void print_failures(uint64_t total, const std::vector<ost2pst::ndb::ProbeFailure>& failures) {
    printf("FINDINGS\n");
    printf("  total             %llu (%zu shown)\n", static_cast<unsigned long long>(total),
           failures.size());
    for (const ost2pst::ndb::ProbeFailure& failure : failures) {
        printf("  0x%08llX %-22s value 0x%llX %s\n",
               static_cast<unsigned long long>(failure.offset), failure.field.c_str(),
               static_cast<unsigned long long>(failure.value), failure.detail.c_str());
    }
}

// [MS-PST] 2.2.2.2 nidType table. Display only: the NDB layer treats a NID as an opaque number.
const char* nid_type_name(uint8_t type) {
    switch (type) {
    case 0x00:
        return "HID";
    case 0x01:
        return "INTERNAL";
    case 0x02:
        return "NORMAL_FOLDER";
    case 0x03:
        return "SEARCH_FOLDER";
    case 0x04:
        return "NORMAL_MESSAGE";
    case 0x05:
        return "ATTACHMENT";
    case 0x06:
        return "SEARCH_UPDATE_QUEUE";
    case 0x07:
        return "SEARCH_CRITERIA_OBJECT";
    case 0x08:
        return "ASSOC_MESSAGE";
    case 0x0A:
        return "CONTENTS_TABLE_INDEX";
    case 0x0B:
        return "RECEIVE_FOLDER_TABLE";
    case 0x0C:
        return "OUTGOING_QUEUE_TABLE";
    case 0x0D:
        return "HIERARCHY_TABLE";
    case 0x0E:
        return "CONTENTS_TABLE";
    case 0x0F:
        return "ASSOC_CONTENTS_TABLE";
    case 0x10:
        return "SEARCH_CONTENTS_TABLE";
    case 0x11:
        return "ATTACHMENT_TABLE";
    case 0x12:
        return "RECIPIENT_TABLE";
    case 0x13:
        return "SEARCH_TABLE_INDEX";
    case 0x1F:
        return "LTP";
    default:
        return "unknown";
    }
}

// Peak working set is what the memory budget in DEVELOPMENT.md 5.3 is measured against.
// The cast is to the API's own parameter type, not a struct laid over file bytes.
uint64_t peak_working_set_bytes() {
    PROCESS_MEMORY_COUNTERS_EX counters = {};
    counters.cb = sizeof(counters);
    if (!GetProcessMemoryInfo(GetCurrentProcess(),
                              reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&counters),
                              sizeof(counters))) {
        return 0;
    }
    return static_cast<uint64_t>(counters.PeakWorkingSetSize);
}

void print_ndb_index(const NdbReadReport& report) {
    const NdbReadCounters& counters = report.counters;
    printf("BBT INDEX\n");
    printf("  entries           %llu, duplicate BIDs %llu\n",
           static_cast<unsigned long long>(counters.bbt_index_entries),
           static_cast<unsigned long long>(counters.bbt_index_duplicates));
    printf("  resident bytes    %llu (%.1f MiB)\n",
           static_cast<unsigned long long>(counters.bbt_index_bytes),
           static_cast<double>(counters.bbt_index_bytes) / (1024.0 * 1024.0));
    printf("  BID range         0x%llX .. 0x%llX\n",
           static_cast<unsigned long long>(counters.bbt_min_bid),
           static_cast<unsigned long long>(counters.bbt_max_bid));
}

void print_ndb_nbt(const NdbReadReport& report) {
    const NdbReadCounters& counters = report.counters;
    printf("NBT ENTRIES\n");
    printf("  total             %llu, bidData missing %llu, bidSub missing %llu\n",
           static_cast<unsigned long long>(counters.nbt_entries),
           static_cast<unsigned long long>(counters.nbt_bid_data_missing),
           static_cast<unsigned long long>(counters.nbt_bid_sub_missing));
    printf("  per nidType       %-24s %8s %8s %8s\n", "type", "entries", "bidData", "bidSub");
    for (const ost2pst::ndb::NidTypeCount& count : report.nid_types) {
        printf("                    0x%02X %-21s %8llu %8llu %8llu\n", count.nid_type,
               nid_type_name(count.nid_type), static_cast<unsigned long long>(count.entries),
               static_cast<unsigned long long>(count.with_bid_data),
               static_cast<unsigned long long>(count.with_bid_sub));
    }
}

void print_ndb_blocks(const BlockReadCounters& blocks) {
    printf("BLOCK READS (every NBTENTRY.bidData)\n");
    printf("  requested         %llu, not indexed %llu, out of range %llu\n",
           static_cast<unsigned long long>(blocks.requested),
           static_cast<unsigned long long>(blocks.not_indexed),
           static_cast<unsigned long long>(blocks.out_of_range));
    printf("  cb agrees         %llu, mismatches %llu\n",
           static_cast<unsigned long long>(blocks.cb_matches),
           static_cast<unsigned long long>(blocks.cb_mismatches));
    printf("  bid agrees        %llu, mismatches %llu\n",
           static_cast<unsigned long long>(blocks.bid_matches),
           static_cast<unsigned long long>(blocks.bid_mismatches));
    printf("  wSig              %llu ok, %llu failed\n",
           static_cast<unsigned long long>(blocks.sig_ok),
           static_cast<unsigned long long>(blocks.sig_failed));
    printf("  CRC over cb     %llu ok, %llu failed\n",
           static_cast<unsigned long long>(blocks.crc_ok),
           static_cast<unsigned long long>(blocks.crc_failed));
    printf("  data bytes        %llu\n", static_cast<unsigned long long>(blocks.data_bytes));
}

void print_ndb_coverage(const NdbReadReport& report, uint64_t peak_bytes, double seconds) {
    const NdbReadCounters& counters = report.counters;
    printf("ALLOCATION MAP\n");
    printf("  regions           %llu scanned, %llu valid\n",
           static_cast<unsigned long long>(counters.amap_regions),
           static_cast<unsigned long long>(counters.amap_regions_valid));
    const uint64_t mapped = counters.amap_regions * ost2pst::ndb::amap_units(report.profile);
    printf("  allocated units   %llu of %llu mapped by the chain\n",
           static_cast<unsigned long long>(counters.amap_units_allocated),
           static_cast<unsigned long long>(mapped));
    printf("HEADER CLAIMS\n");
    printf("  ibFileEof         %s\n",
           counters.file_eof_matches_size ? "equals file size" : "MISMATCH");
    printf("  bidNextB          %s (highest block BID seen 0x%llX)\n",
           counters.bid_next_b_covers ? "covers" : "BELOW",
           static_cast<unsigned long long>(counters.highest_block_bid));
    printf("  bidNextP          %s (highest page BID seen 0x%llX)\n",
           counters.bid_next_p_covers ? "covers" : "BELOW",
           static_cast<unsigned long long>(counters.highest_page_bid));
    printf("RESOURCES\n");
    printf("  peak RSS          %llu bytes (%.1f MiB)\n",
           static_cast<unsigned long long>(peak_bytes),
           static_cast<double>(peak_bytes) / (1024.0 * 1024.0));
    printf("  wall time         %.2f s\n", seconds);
}

// A property value is arbitrary bytes, so a dump never lets a newline escape into the report.
std::string one_line(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (const char character : text) {
        if (character == '\r' || character == '\n' || character == '\t') {
            out.push_back(' ');
        } else {
            out.push_back(character);
        }
    }
    return out;
}

void print_ltp_nids(const LtpReadReport& report) {
    printf("NID MAP\n");
    printf("  entries           %llu, nidIndex groups %llu, duplicate NIDs %llu\n",
           static_cast<unsigned long long>(report.nid_entries),
           static_cast<unsigned long long>(report.nid_groups),
           static_cast<unsigned long long>(report.nid_duplicates));
    printf("  blocks            %llu name a data block, %llu name a subnode BTree\n",
           static_cast<unsigned long long>(report.nid_with_bid_data),
           static_cast<unsigned long long>(report.nid_with_bid_sub));
    printf("  per nidType       %-24s %8s\n", "type", "entries");
    for (const auto& item : report.nid_types) {
        printf("                    0x%02X %-21s %8llu\n", static_cast<unsigned>(item.first),
               nid_type_name(item.first), static_cast<unsigned long long>(item.second));
    }
}

void print_ltp_heap(const LtpHeapCounters& heap) {
    printf("HEAP NODES (every NBTENTRY.bidData opened once)\n");
    printf("  blocks            %llu read, %llu could not be read\n",
           static_cast<unsigned long long>(heap.blocks_read),
           static_cast<unsigned long long>(heap.blocks_failed));
    printf("  block form        %llu compressed, %llu raw\n",
           static_cast<unsigned long long>(heap.compressed),
           static_cast<unsigned long long>(heap.raw));
    printf("  heap nodes        %llu decoded, %llu carry no HNHDR\n",
           static_cast<unsigned long long>(heap.heap_nodes_ok),
           static_cast<unsigned long long>(heap.heap_nodes_rejected));
    printf("  multi-block       %llu nodes spread over %llu data blocks, %llu in the widest node\n",
           static_cast<unsigned long long>(heap.multi_block_nodes),
           static_cast<unsigned long long>(heap.multi_block_fragments),
           static_cast<unsigned long long>(heap.max_fragments));
    printf("                    %llu of those blocks carry no usable HNPAGEMAP\n",
           static_cast<unsigned long long>(heap.fragment_page_maps_rejected));
    printf("  allocations       %llu total, %llu in the fullest block\n",
           static_cast<unsigned long long>(heap.allocations),
           static_cast<unsigned long long>(heap.max_allocations));
    printf("  largest           %llu byte block, %llu byte heap node\n",
           static_cast<unsigned long long>(heap.max_block_bytes),
           static_cast<unsigned long long>(heap.max_heap_bytes));
    printf("  bClientSig        %-14s %8s\n", "value", "nodes");
    for (const auto& item : heap.client_sigs) {
        printf("                    0x%02X %-13s %8llu\n", static_cast<unsigned>(item.first),
               ost2pst::ltp::client_sig_name(static_cast<uint8_t>(item.first)),
               static_cast<unsigned long long>(item.second));
    }
}

// A node whose data does not fit in one data block ([MS-PST] 2.2.2.8.3.2), flattened through the
// jump tables its BID roots. The internal bit ([MS-PST] 2.2.2.2 bit B) is what decides the shape,
// so the counters say how often each shape was found and which check stopped a tree.
void print_ltp_data_trees(const DataTreeCounters& trees, const SubnodeStats& subnodes) {
    printf("DATA TREES (a node's data spread over the blocks its jump table names)\n");
    printf("  trees             %llu flattened, %llu ended in an error\n",
           static_cast<unsigned long long>(trees.trees),
           static_cast<unsigned long long>(trees.failed_trees));
    printf("  jump tables       %llu decoded, %llu of them XXBLOCK\n",
           static_cast<unsigned long long>(trees.tables),
           static_cast<unsigned long long>(trees.xxblock_tables));
    printf("  data blocks       %llu, %llu in the widest tree, %llu in the widest cEnt\n",
           static_cast<unsigned long long>(trees.data_blocks),
           static_cast<unsigned long long>(trees.max_blocks),
           static_cast<unsigned long long>(trees.max_entries));
    printf("  blocks            %llu read, %llu could not be read (%llu compressed, %llu raw)\n",
           static_cast<unsigned long long>(trees.blocks_read),
           static_cast<unsigned long long>(trees.blocks_failed),
           static_cast<unsigned long long>(trees.compressed),
           static_cast<unsigned long long>(trees.raw));
    printf("  largest           %llu byte block, %llu byte heap node\n",
           static_cast<unsigned long long>(trees.max_block_bytes),
           static_cast<unsigned long long>(trees.max_heap_bytes));
    printf(
        "  checks            %llu tables that are not jump tables, %llu child level mismatches\n",
        static_cast<unsigned long long>(trees.rejected_tables),
        static_cast<unsigned long long>(trees.child_flag_mismatches));
    printf("                    %llu internal-bit disagreements, %llu lcbTotal mismatches\n",
           static_cast<unsigned long long>(trees.index_flag_mismatches),
           static_cast<unsigned long long>(trees.lcb_total_mismatches));
    printf("                    %llu cycles, %llu trees over the block cap\n",
           static_cast<unsigned long long>(trees.cycles),
           static_cast<unsigned long long>(trees.capped));
    printf("  subnode blocks    %llu read, %llu the BBT does not flag Internal, %llu not a subnode "
           "block\n",
           static_cast<unsigned long long>(subnodes.blocks_read),
           static_cast<unsigned long long>(subnodes.blocks_not_internal),
           static_cast<unsigned long long>(subnodes.blocks_bad));
}
void print_ltp_pcs(const LtpPcCounters& pcs) {
    printf("PROPERTY CONTEXTS\n");
    printf("  read              %llu contexts, %llu failed, %llu records\n",
           static_cast<unsigned long long>(pcs.contexts),
           static_cast<unsigned long long>(pcs.failed),
           static_cast<unsigned long long>(pcs.records));
    printf("  values            %llu inline, %llu in the heap, %llu in a subnode, %llu with no "
           "value\n",
           static_cast<unsigned long long>(pcs.inline_values),
           static_cast<unsigned long long>(pcs.heap_values),
           static_cast<unsigned long long>(pcs.subnode_values),
           static_cast<unsigned long long>(pcs.no_values));
    printf("  widest            %llu records in one context\n",
           static_cast<unsigned long long>(pcs.max_records));
    printf("  per nidType       %-24s %8s\n", "type", "contexts");
    for (const auto& item : pcs.nid_types) {
        printf("                    0x%02X %-21s %8llu\n", static_cast<unsigned>(item.first),
               nid_type_name(item.first), static_cast<unsigned long long>(item.second));
    }
    printf("  property types    %-24s %8s\n", "type", "records");
    for (const auto& item : pcs.prop_types) {
        printf("                    0x%04X %-21s %8llu\n", static_cast<unsigned>(item.first),
               ost2pst::ltp::prop_type_info(item.first).name,
               static_cast<unsigned long long>(item.second));
    }
}

void print_ltp_tcs(const LtpTcCounters& tcs) {
    printf("TABLE CONTEXTS\n");
    printf("  read              %llu contexts, %llu failed, %llu rows\n",
           static_cast<unsigned long long>(tcs.contexts),
           static_cast<unsigned long long>(tcs.failed), static_cast<unsigned long long>(tcs.rows));
    printf("  widest            %llu columns, %llu rows in one RowIndex\n",
           static_cast<unsigned long long>(tcs.max_columns),
           static_cast<unsigned long long>(tcs.max_rows));
    printf("  Row Matrix        %llu in the heap, %llu in a subnode, %llu with no rows\n",
           static_cast<unsigned long long>(tcs.matrix_in_heap),
           static_cast<unsigned long long>(tcs.matrix_in_subnode),
           static_cast<unsigned long long>(tcs.columns_only));
    printf("  per nidType       %-24s %8s\n", "type", "contexts");
    for (const auto& item : tcs.nid_types) {
        printf("                    0x%02X %-21s %8llu\n", static_cast<unsigned>(item.first),
               nid_type_name(item.first), static_cast<unsigned long long>(item.second));
    }
}

void print_ltp_npm(const LtpReadReport& report) {
    printf("NAME-TO-ID MAP (NID 0x61)\n");
    if (!report.npm_read) {
        printf("  read              no Property Context behind that NID\n");
        return;
    }
    const ost2pst::ltp::NameIdStats& npm = report.npm;
    printf("  named properties  %llu (%llu string names, %llu numeric names)\n",
           static_cast<unsigned long long>(report.named_properties),
           static_cast<unsigned long long>(npm.entries_string),
           static_cast<unsigned long long>(npm.entries_numeric));
    printf("  buckets           %llu declared, %llu present, %llu empty, %llu records\n",
           static_cast<unsigned long long>(npm.bucket_count),
           static_cast<unsigned long long>(npm.buckets_present),
           static_cast<unsigned long long>(npm.buckets_missing),
           static_cast<unsigned long long>(npm.bucket_records));
    printf("  streams           GUID %llu B, Entry %llu B, String %llu B, Bucket %llu B\n",
           static_cast<unsigned long long>(npm.guid_stream_bytes),
           static_cast<unsigned long long>(npm.entry_stream_bytes),
           static_cast<unsigned long long>(npm.string_stream_bytes),
           static_cast<unsigned long long>(npm.bucket_stream_bytes));
    printf("  names             %llu resolved, %llu unresolved, longest %llu B\n",
           static_cast<unsigned long long>(npm.names_resolved),
           static_cast<unsigned long long>(npm.names_unresolved),
           static_cast<unsigned long long>(npm.max_name_bytes));
    printf("  String Stream     %llu names enumerated, %llu N == 1 offsets match none of them\n",
           static_cast<unsigned long long>(npm.string_names),
           static_cast<unsigned long long>(npm.string_offsets_unmatched));
    printf("  CRC pairing       %llu names hash to their bucket record, %llu do not\n",
           static_cast<unsigned long long>(npm.crc_matches),
           static_cast<unsigned long long>(npm.crc_mismatches));
    printf("  NPID range        0x%04X .. 0x%04X\n", npm.npid_min, npm.npid_max);
    // Printed even when zero: [MS-PST] 2.4.7.1 puts wGuid past the end of the GUID Stream on the
    // acceptance list, and a check that disappears from the report is not evidence that it passed.
    printf(
        "  GUID Stream       %llu B (%llu GUIDs, %llu distinct), %llu records point past its end\n",
        static_cast<unsigned long long>(npm.guid_stream_bytes),
        static_cast<unsigned long long>(npm.guid_stream_entries),
        static_cast<unsigned long long>(npm.guid_distinct),
        static_cast<unsigned long long>(npm.guid_refs_out_of_range));
    printf("                    %llu bytes past the last whole GUID, %llu records resolve through "
           "it\n",
           static_cast<unsigned long long>(npm.guid_stream_ragged_bytes),
           static_cast<unsigned long long>(npm.guid_custom_refs));
    // [MS-PST] 2.4.7.1: wGuid says which property set a named property belongs to, and the property
    // set is half of what the property is, so every kind the map uses is printed.
    printf("  property sets     %-24s %8s\n", "kind", "records");
    for (const auto& item : npm.guid_kinds) {
        printf("                    %-24s %8llu\n", item.first.c_str(),
               static_cast<unsigned long long>(item.second));
    }
}

void print_ltp_smq(const LtpReadReport& report) {
    printf("SEARCH MANAGEMENT QUEUE (NID 0x1E1)\n");
    if (!report.smq_present) {
        printf("  present           no NBT entry carries this NID\n");
        return;
    }
    const ost2pst::ltp::QueueStats& queue = report.smq;
    if (queue.bytes == 0) {
        printf("  queue             drained: the node names no data block\n");
    }
    printf("  queue             %llu bytes, item size %llu, head offset %llu\n",
           static_cast<unsigned long long>(queue.bytes),
           static_cast<unsigned long long>(queue.item_size),
           static_cast<unsigned long long>(queue.head_offset));
    printf("  items             %llu in the block, %llu queued, %llu consumed, %llu skipped\n",
           static_cast<unsigned long long>(queue.items_total),
           static_cast<unsigned long long>(queue.items_queued),
           static_cast<unsigned long long>(queue.items_consumed),
           static_cast<unsigned long long>(queue.items_skipped));
    if (queue.ragged) {
        printf("  cbData            not an integer multiple of the item size\n");
    }
    printf("  SUD types         ");
    if (report.sud_types.empty()) {
        printf("(none)");
    }
    for (const auto& item : report.sud_types) {
        printf("0x%04X %s=%llu ", item.first, ost2pst::ltp::sud_type_name(item.first),
               static_cast<unsigned long long>(item.second));
    }
    printf("\n");
}

void print_ltp_folders(const std::vector<LtpFolder>& folders, const FolderWalkStats& stats) {
    printf("FOLDER TREE (from NID 0x122)\n");
    printf("  folders           %llu visited, deepest at level %llu\n",
           static_cast<unsigned long long>(stats.folders),
           static_cast<unsigned long long>(stats.max_depth));
    printf(
        "  walk              %llu cycles, %llu rows with no NBT entry, %llu cut by the depth cap,"
        " %llu cut by the folder cap\n",
        static_cast<unsigned long long>(stats.cycles),
        static_cast<unsigned long long>(stats.missing),
        static_cast<unsigned long long>(stats.depth_capped),
        static_cast<unsigned long long>(stats.stopped_early));
    printf("  opened            %llu PCs, %llu table contexts, %llu blocks (%llu unreadable,"
           " %llu not heap nodes)\n",
           static_cast<unsigned long long>(stats.pcs_read),
           static_cast<unsigned long long>(stats.tcs_read),
           static_cast<unsigned long long>(stats.blocks_read),
           static_cast<unsigned long long>(stats.blocks_failed),
           static_cast<unsigned long long>(stats.not_heap_node));
    uint64_t messages = 0;
    uint64_t associated = 0;
    uint64_t held = 0;
    uint64_t held_associated = 0;
    for (const LtpFolder& folder : folders) {
        messages += folder.messages;
        associated += folder.associated;
        held += folder.parent_messages;
        held_associated += folder.parent_associated;
    }
    printf("  total             %llu messages, %llu associated messages across %llu folders\n",
           static_cast<unsigned long long>(messages), static_cast<unsigned long long>(associated),
           static_cast<unsigned long long>(folders.size()));
    printf("  held by nidParent %llu messages, %llu associated messages\n",
           static_cast<unsigned long long>(held), static_cast<unsigned long long>(held_associated));
    printf("  columns           msgs and assoc are rows of the contents and FAI tables; held and "
           "aheld\n"
           "                    are NBT entries whose nidParent is this folder\n");
    for (const LtpFolder& folder : folders) {
        const int indent = static_cast<int>(folder.depth > 30 ? 30 : folder.depth) * 2;
        std::string name = "(no PidTagDisplayName)";
        if (folder.name_present) {
            name = folder.name.empty() ? "(empty)" : one_line(folder.name);
        }
        printf("  %*s0x%08llX %6llu msgs %6llu held %5llu assoc %6llu aheld %5llu sub  %s\n",
               indent, "", static_cast<unsigned long long>(folder.nid),
               static_cast<unsigned long long>(folder.messages),
               static_cast<unsigned long long>(folder.parent_messages),
               static_cast<unsigned long long>(folder.associated),
               static_cast<unsigned long long>(folder.parent_associated),
               static_cast<unsigned long long>(folder.children), name.c_str());
    }
}

void print_ltp_dump(const LtpReadReport& report) {
    if (!report.dump && !report.dump_error) {
        return;
    }
    printf("NODE DUMP\n");
    if (report.dump_error) {
        printf("  %s\n", ost2pst::util::format_error(*report.dump_error).c_str());
        return;
    }
    const LtpNodeDump& dump = *report.dump;
    printf("  nid               0x%08llX nidType 0x%02X %s\n",
           static_cast<unsigned long long>(dump.nid),
           static_cast<unsigned>(ost2pst::ltp::nid_type(dump.nid)),
           nid_type_name(static_cast<uint8_t>(ost2pst::ltp::nid_type(dump.nid))));
    printf("  bidData           %llu, bidSub %llu, nidParent 0x%llX\n",
           static_cast<unsigned long long>(dump.bid_data),
           static_cast<unsigned long long>(dump.bid_sub),
           static_cast<unsigned long long>(dump.nid_parent));
    printf("  heap node         bClientSig 0x%02X %s, %llu bytes, %llu allocations\n",
           static_cast<unsigned>(dump.client_sig),
           ost2pst::ltp::client_sig_name(static_cast<uint8_t>(dump.client_sig)),
           static_cast<unsigned long long>(dump.heap_bytes),
           static_cast<unsigned long long>(dump.allocations));
    printf("  entries           %llu, %llu values answered, %llu unresolved\n", dump.values.size(),
           static_cast<unsigned long long>(dump.values_resolved),
           static_cast<unsigned long long>(dump.values_unresolved));
    uint64_t named_tags = 0;
    for (const LtpPropertyValue& item : dump.values) {
        if (item.named) {
            ++named_tags;
        }
    }
    printf("  named properties  %llu tags in the NPID range, %llu the Name-to-ID Map has no entry "
           "for\n",
           static_cast<unsigned long long>(named_tags),
           static_cast<unsigned long long>(dump.named_unresolved));
    for (const LtpPropertyValue& item : dump.values) {
        printf("    tag 0x%08X %-22s %s\n", item.tag,
               ost2pst::ltp::prop_type_info(ost2pst::ltp::tc_prop_type_of_tag(item.tag)).name,
               one_line(item.value).c_str());
        if (!item.named) {
            continue;
        }
        // [MS-PST] 2.4.7.1: the property set plus the string or numeric name is what a named
        // property IS; the tag alone cannot tell two same-named properties in different property
        // sets apart.
        printf("      identity        wGuid %u %s", static_cast<unsigned>(item.guid_index),
               ost2pst::ltp::name_id_guid_kind_name(item.guid_kind));
        if (item.guid_resolved) {
            const char* origin = item.guid_from_file ? "(from the file)" : "(reference value)";
            printf(" %s %s", ost2pst::ltp::name_id_guid_text(item.guid).c_str(), origin);
        }
        if (item.name_resolved) {
            printf(" N == 1 name \"%s\"", one_line(ost2pst::ltp::name_id_utf8(item.name)).c_str());
        } else if (item.name_is_string) {
            printf(" N == 1 name the String Stream does not hold");
        } else {
            printf(" N == 0 numeric name %u", static_cast<unsigned>(item.numeric_name));
        }
        printf("\n");
    }
}

// The subnode dump prints what ltp::dump_subtree measured. Every number here came through the
// production seams, so this section is evidence about the reader's own answer, not a second decode.
const char* node_open_name(ost2pst::ltp::NodeOpen opened) {
    switch (opened) {
    case ost2pst::ltp::NodeOpen::kOk:
        return "opened";
    case ost2pst::ltp::NodeOpen::kNotHeapNode:
        return "no HNHDR";
    case ost2pst::ltp::NodeOpen::kUnreadable:
        return "unreadable";
    case ost2pst::ltp::NodeOpen::kDataTreeFailed:
        return "data tree failed";
    }
    return "unknown";
}

const char* pc_value_kind(const ost2pst::ltp::DumpPcValue& value) {
    if (value.absent) {
        return "absent";
    }
    if (value.inline_value) {
        return "inline";
    }
    if (value.in_subnode) {
        return value.answered ? "subnode" : "subnode unanswered";
    }
    if (value.in_heap) {
        return value.answered ? "heap" : "heap unanswered";
    }
    return "unanswered";
}

void print_dump_node(const ost2pst::ltp::DumpNode& node, const char* label) {
    printf("%s 0x%08llX nidType 0x%02X %s\n", label,
           static_cast<unsigned long long>(node.local_nid), static_cast<unsigned>(node.nid_type),
           ost2pst::ltp::nid_type_name(static_cast<uint32_t>(node.nid_type)));
    if (node.has_parent) {
        printf("   depth %llu, named by subnode 0x%08llX's list\n",
               static_cast<unsigned long long>(node.depth),
               static_cast<unsigned long long>(node.parent_local_nid));
    }
    if (node.nid != node.local_nid) {
        printf("   SLENTRY.nid as written 0x%016llX\n", static_cast<unsigned long long>(node.nid));
    }
    printf("   bidData %llu%s cb %llu ib 0x%llX, bidSub %llu%s\n",
           static_cast<unsigned long long>(node.bid_data), node.data_internal ? " (internal)" : "",
           static_cast<unsigned long long>(node.cb_data),
           static_cast<unsigned long long>(node.ib_data),
           static_cast<unsigned long long>(node.bid_sub), node.sub_internal ? " (internal)" : "");
    printf("   block %s, bClientSig 0x%02X %s, heap %llu bytes, %llu allocations\n",
           node_open_name(node.opened), static_cast<unsigned>(node.client_sig),
           ost2pst::ltp::client_sig_name(static_cast<uint8_t>(node.client_sig)),
           static_cast<unsigned long long>(node.heap_bytes),
           static_cast<unsigned long long>(node.allocations));
    if (node.data_blocks != 0) {
        printf("   data blocks %llu, %llu bytes inflated\n",
               static_cast<unsigned long long>(node.data_blocks),
               static_cast<unsigned long long>(node.data_heap_bytes));
    }
    if (node.pc_records != 0) {
        printf("   Property Context %llu records, %llu listed\n",
               static_cast<unsigned long long>(node.pc_records),
               static_cast<unsigned long long>(node.pc.size()));
        for (const ost2pst::ltp::DumpPcValue& item : node.pc) {
            printf("     tag 0x%08X %-22s hnid 0x%08X %-18s %llu bytes\n", item.tag,
                   ost2pst::ltp::prop_type_info(ost2pst::ltp::tc_prop_type_of_tag(item.tag)).name,
                   item.hnid, pc_value_kind(item), static_cast<unsigned long long>(item.bytes));
        }
    }
    if (node.tc.read) {
        printf("   Table Context %u columns, hnidRows 0x%08X, %llu rows, row size %llu\n",
               static_cast<unsigned>(node.tc.columns), node.tc.hnid_rows,
               static_cast<unsigned long long>(node.tc.rows),
               static_cast<unsigned long long>(node.tc.row_size));
        const char* where =
            node.tc.matrix_in_heap
                ? "the heap"
                : (node.tc.matrix_in_subnode ? "a subnode" : "nowhere: hnidRows is 0");
        printf("     Row Matrix in %s, %llu bytes of rows, %llu bytes read over %llu blocks\n",
               where, static_cast<unsigned long long>(node.tc.matrix_bytes),
               static_cast<unsigned long long>(node.tc.matrix_stored_bytes),
               static_cast<unsigned long long>(node.tc.matrix_blocks));
        for (const ost2pst::ltp::TcColumn& column : node.tc.column_list) {
            printf("     column tag 0x%08X ibData %u cbData %u iBit %u\n", column.tag,
                   static_cast<unsigned>(column.ib_data), static_cast<unsigned>(column.cb_data),
                   static_cast<unsigned>(column.i_bit));
        }
        if (!node.tc.row_ids.empty()) {
            printf("     first dwRowIDs");
            for (uint32_t row_id : node.tc.row_ids) {
                printf(" 0x%08X", row_id);
            }
            printf("\n");
        }
    }
    if (!node.note.empty()) {
        printf("   note %s\n", one_line(node.note).c_str());
    }
}

void print_subtree(const ost2pst::ltp::SubtreeDump& dump,
                   const ost2pst::ndb::BlockReadCounters& blocks) {
    printf("SUBTREE DUMP\n");
    print_dump_node(dump.root, "node");
    printf("SUBNODES  %llu listed%s\n", static_cast<unsigned long long>(dump.subnodes.size()),
           dump.capped ? " (a work cap cut the dump short)" : "");
    for (const ost2pst::ltp::DumpNode& node : dump.subnodes) {
        print_dump_node(node, "  subnode");
    }
    const ost2pst::ltp::SubnodeStats& stats = dump.stats;
    printf("SUBNODE WALK\n");
    printf("  searches          %llu, entries found %llu, blocks read %llu\n",
           static_cast<unsigned long long>(stats.searches),
           static_cast<unsigned long long>(stats.found),
           static_cast<unsigned long long>(stats.blocks_read));
    printf("  blocks            %llu compressed, %llu raw, %llu bad, %llu not flagged Internal\n",
           static_cast<unsigned long long>(stats.blocks_compressed),
           static_cast<unsigned long long>(stats.blocks_raw),
           static_cast<unsigned long long>(stats.blocks_bad),
           static_cast<unsigned long long>(stats.blocks_not_internal));
    printf("  entries           %llu scanned, %llu skipped, SIBLOCK hops %llu\n",
           static_cast<unsigned long long>(stats.entries_scanned),
           static_cast<unsigned long long>(stats.entries_skipped),
           static_cast<unsigned long long>(stats.si_hops));
    printf("  widest            %llu entries in one block, %llu levels deep, stopped short %s\n",
           static_cast<unsigned long long>(stats.max_entries),
           static_cast<unsigned long long>(stats.max_depth), stats.stopped_early ? "yes" : "no");
    print_ltp_data_trees(dump.trees, ost2pst::ltp::SubnodeStats{});
    printf("BLOCKS THIS DUMP OPENED\n");
    printf("  requested         %llu, read %llu, not indexed %llu, out of range %llu, %llu bytes\n",
           static_cast<unsigned long long>(blocks.requested),
           static_cast<unsigned long long>(blocks.decoded),
           static_cast<unsigned long long>(blocks.not_indexed),
           static_cast<unsigned long long>(blocks.out_of_range),
           static_cast<unsigned long long>(blocks.data_bytes));
    print_failures(dump.failure_total, dump.failures);
}

// What the reader did not read, and which of the three reasons applies. A documented non-heap node
// is a node the spec says holds an array, a queue or a BLOB instead of a heap node; an unsupported
// structure is one the literature names but this reader does not decode; a decode failure is a node
// whose bytes contradict its own metadata. Only the last one makes the read not clean.
void print_ltp_findings(const ost2pst::ltp::LtpFindingTally& findings) {
    if (findings.total == 0) {
        return;
    }
    printf("LTP NODE FINDINGS (what the reader did not read, and why)\n");
    printf("  documented non-heap nodes %8llu\n",
           static_cast<unsigned long long>(findings.documented_non_heap));
    printf("  unsupported structures    %8llu\n",
           static_cast<unsigned long long>(findings.unsupported));
    printf("  decode failures           %8llu\n",
           static_cast<unsigned long long>(findings.decode_failures));
    for (const ost2pst::ltp::LtpFinding& finding : findings.items) {
        printf("  %-24s nid 0x%08llX nidType 0x%02X %-22s bid 0x%llX %s: %s\n",
               ost2pst::ltp::ltp_finding_kind_name(finding.kind),
               static_cast<unsigned long long>(finding.nid),
               static_cast<unsigned>(finding.nid_type),
               ost2pst::ltp::nid_type_name(finding.nid_type),
               static_cast<unsigned long long>(finding.bid), finding.field.c_str(),
               one_line(finding.detail).c_str());
    }
    if (findings.total > findings.items.size()) {
        printf("  %llu more findings not shown\n",
               static_cast<unsigned long long>(findings.total - findings.items.size()));
    }
}

void print_ltp_errors(const std::map<std::string, uint64_t>& errors) {
    if (errors.empty()) {
        return;
    }
    printf("LTP ERROR TALLY (counted, and not fatal to the walk)\n");
    for (const auto& item : errors) {
        printf("  %-24s %8llu\n", item.first.c_str(), static_cast<unsigned long long>(item.second));
    }
}

} // namespace

// The M3 inventory report. Every section names what the source contains and, in the completeness
// section, what it does not -- a count of absent things is never filled in with an invented value.
void print_inventory(const ost2pst::msg::InventoryReport& report) {
    auto u64 = [](uint64_t value) { return static_cast<unsigned long long>(value); };

    printf("INVENTORY: NODE TYPES (nidType, what the two opened sources say, what this run did)\n");
    printf("  NBT entries       %llu\n", u64(report.nid_entries));
    for (const auto& item : report.node_types) {
        const ost2pst::msg::NodeClassCount& count = item.second;
        printf("  0x%02X %-18s nodes %8llu subnodes %8llu opened %8llu read %8llu not-read %8llu\n",
               static_cast<unsigned>(item.first),
               ost2pst::msg::node_disposition_name(count.disposition), u64(count.nodes),
               u64(count.subnode_entries), u64(count.opened), u64(count.read), u64(count.not_read));
        printf("       [MS-PST] %s | libpff: %s\n",
               count.ms_pst_name.empty() ? "(no row)" : count.ms_pst_name.c_str(),
               count.libpff_label.empty() ? "(no row)" : count.libpff_label.c_str());
        printf("       why: %s\n", one_line(count.reason).c_str());
    }

    const auto print_messages = [&](const char* label, const ost2pst::msg::MessageStats& stats) {
        printf("INVENTORY: %s\n", label);
        printf("  scanned           %llu Message objects (%llu left out by a cap)\n",
               u64(stats.nodes), u64(stats.stopped_early));
        printf("  property contexts %llu read, %llu not read, %llu records\n", u64(stats.pcs_read),
               u64(stats.pcs_failed), u64(stats.pc_records));
        printf("  body forms        %llu with 0x1000, %llu with 0x1013, %llu with 0x1009, %llu "
               "with none"
               " (record presence only)\n",
               u64(stats.with_body), u64(stats.with_html), u64(stats.with_rtf),
               u64(stats.with_no_body_form));
        printf("  body content      %llu readable, %llu empty, %llu not in the source, %llu "
               "unreadable,"
               " %llu not decoded (%llu object, %llu compressed), %llu unknown, %llu bytes read\n",
               u64(stats.body.readable), u64(stats.body.empty), u64(stats.body.not_present),
               u64(stats.body.unreadable), u64(stats.body.unsupported),
               u64(stats.body.unsupported_object), u64(stats.body.unsupported_compressed),
               u64(stats.body.unknown), u64(stats.body.bytes_read));
        printf("  subnodes          %llu hold one, %llu have bidSub 0, %llu name an unreadable "
               "block\n",
               u64(stats.with_subnodes), u64(stats.without_subnode), u64(stats.with_bad_subnodes));
        printf("                    %llu SLENTRY entries, widest %llu, %llu SIBLOCK hops, %llu "
               "compressed"
               " blocks, %llu unreadable\n",
               u64(stats.subnode_entries), u64(stats.max_subnodes), u64(stats.si_hops),
               u64(stats.subnode_blocks_compressed), u64(stats.subnode_blocks_bad));
        std::string types;
        for (const auto& entry : stats.subnode_types) {
            char buffer[32];
            std::snprintf(buffer, sizeof(buffer), "0x%02X %llu, ",
                          static_cast<unsigned>(entry.first), u64(entry.second));
            types += buffer;
        }
        printf("  subnode types     %s\n", types.empty() ? "(none)" : one_line(types).c_str());
        printf(
            "  tables            %llu attachment tables (%llu read, %llu not read), %llu recipient"
            " tables (%llu read, %llu not read)\n",
            u64(stats.attachment_tables), u64(stats.attachment_tables_read),
            u64(stats.attachment_tables_not_read), u64(stats.recipient_tables),
            u64(stats.recipient_tables_read), u64(stats.recipient_tables_not_read));
        printf("  table rows        %llu recipient rows (%llu skipped), %llu messages with no "
               "Recipient"
               " Table\n",
               u64(stats.recipient_rows), u64(stats.recipient_rows_skipped),
               u64(stats.without_recipient_table));
        printf("  not read          %llu Property Contexts announced one and did not read, %llu "
               "subnode"
               " walks short, %llu RowIndex walks failed\n",
               u64(stats.pc_decode_failed), u64(stats.subnode_walks_incomplete),
               u64(stats.attachment_tables_row_index_failed +
                   stats.recipient_tables_row_index_failed));
    };

    const auto print_attachments = [&](const char* label,
                                       const ost2pst::msg::AttachmentStats& stats) {
        printf("INVENTORY: %s\n", label);
        printf(
            "  attachment objects %llu named by a subnode, %llu opened by a table row, %llu not a"
            " Property Context\n",
            u64(stats.subnode_entries), u64(stats.nodes_opened), u64(stats.nodes_no_pc));
        printf("  tables             %llu (%llu read, %llu not read), %llu rows, %llu resolved, "
               "%llu name"
               " no subnode, %llu skipped, %llu stopped early\n",
               u64(stats.tables), u64(stats.tables_read), u64(stats.tables_not_read),
               u64(stats.rows), u64(stats.rows_resolved), u64(stats.rows_unresolved),
               u64(stats.rows_skipped), u64(stats.tables_stopped_early));
        printf(
            "  0x0E20 size        %llu inline, %llu no record, %llu present with no value, %llu not"
            " inline, %llu bytes declared\n",
            u64(stats.with_size), u64(stats.without_size), u64(stats.size_value_absent),
            u64(stats.size_not_inline), u64(stats.declared_size_bytes));
        printf("  0x3701 payload     %llu readable, %llu empty, %llu not in the source, %llu "
               "unreadable,"
               " %llu not decoded (%llu object, %llu compressed), %llu unknown, %llu bytes read\n",
               u64(stats.payload.readable), u64(stats.payload.empty),
               u64(stats.payload.not_present), u64(stats.payload.unreadable),
               u64(stats.payload.unsupported), u64(stats.payload.unsupported_object),
               u64(stats.payload.unsupported_compressed), u64(stats.payload.unknown),
               u64(stats.payload.bytes_read));
        printf("  other columns      %llu with 0x3704, %llu with 0x3705, %llu without it, %llu with"
               " 0x370B, %llu without it\n",
               u64(stats.with_filename), u64(stats.with_method), u64(stats.without_method),
               u64(stats.with_rendering), u64(stats.without_rendering));
        std::string methods;
        for (const auto& entry : stats.methods) {
            char buffer[32];
            std::snprintf(buffer, sizeof(buffer), "0x%02X %llu, ",
                          static_cast<unsigned>(entry.first), u64(entry.second));
            methods += buffer;
        }
        printf("  0x3705 values      %s\n", methods.empty() ? "(none)" : one_line(methods).c_str());
        printf("  unnamed attachments %llu subnodes no Attachment Table row names, %llu whose "
               "naming could"
               " not be checked because a table did not walk\n",
               u64(stats.subnodes_not_named), u64(stats.subnodes_naming_unchecked));
        printf("  not read          %llu Attachment object Property Contexts that did not read, "
               "%llu tables"
               " whose RowIndex did not walk\n",
               u64(stats.pc_decode_failed), u64(stats.tables_row_index_failed));
    };

    print_messages("MESSAGES (NID_TYPE_NORMAL_MESSAGE 0x04)", report.messages);
    print_attachments("ATTACHMENTS (of those messages)", report.attachments);
    print_messages("FAI ENTRIES (NID_TYPE_ASSOC_MESSAGE 0x08)", report.associated);
    print_attachments("ATTACHMENTS (of those FAI entries)", report.associated_attachments);

    // [MS-PST] 2.4.6.2.2: an attached message is a Message object the NBT does not name and no
    // folder holds, so its counts are never added to the two populations above. The walk section
    // says how they were reached and what the recursion's own limits left uncounted.
    print_messages("EMBEDDED MESSAGES (attached messages: a 0x3701 PtypObject subnode)",
                   report.embedded);
    print_attachments("ATTACHMENTS (of those embedded messages)", report.embedded_attachments);
    printf("INVENTORY: ATTACHED MESSAGE WALK (how those messages were reached)\n");
    printf("  data objects      %llu reached, %llu scanned as messages, %llu not scanned as "
           "messages\n",
           u64(report.embedded_walks.objects), u64(report.embedded_walks.scanned),
           u64(report.embedded_walks.not_messages));
    printf("  stopped           %llu cycles, %llu depth-capped, %llu work-capped\n",
           u64(report.embedded_walks.cycles), u64(report.embedded_walks.depth_capped),
           u64(report.embedded_walks.capped));
    std::string depths;
    for (const auto& entry : report.embedded_walks.depths) {
        char buffer[32];
        std::snprintf(buffer, sizeof(buffer), "depth %u %llu, ", static_cast<unsigned>(entry.first),
                      u64(entry.second));
        depths += buffer;
    }
    printf("  nesting           %s\n", depths.empty() ? "(none)" : one_line(depths).c_str());
    std::string attached_types;
    for (const auto& entry : report.embedded_walks.nid_types) {
        char buffer[32];
        std::snprintf(buffer, sizeof(buffer), "0x%02X %llu, ", static_cast<unsigned>(entry.first),
                      u64(entry.second));
        attached_types += buffer;
    }
    printf("  nidTypes          %s\n",
           attached_types.empty() ? "(none)" : one_line(attached_types).c_str());

    printf("INVENTORY: FOLDERS (items attributed by nidParent, [MS-PST] 2.4.5.2)\n");
    printf("  folders           %llu\n", u64(report.folders.size()));
    // The bytes column is what those attachments declare (0x0E20), not what their payloads hold.
    for (const ost2pst::msg::FolderCounts& folder : report.folders) {
        const int indent = static_cast<int>(folder.depth > 30 ? 30 : folder.depth) * 2;
        std::string name = "(no PidTagDisplayName)";
        if (folder.name_present) {
            name = folder.name.empty() ? "(empty)" : one_line(folder.name);
        }
        printf("  %*s0x%08llX %6llu msgs %5llu assoc %6llu attach %12llu declared  %s\n", indent,
               "", u64(folder.nid), u64(folder.messages), u64(folder.associated),
               u64(folder.attachments), u64(folder.attachment_bytes), name.c_str());
    }

    const ost2pst::msg::CompletenessReport& c = report.completeness;
    printf("COMPLETENESS (what the source does not contain)\n");
    printf(
        "  %llu messages with no body form, %llu with no subnode, %llu with no Recipient Table\n",
        u64(c.messages_without_body_form), u64(c.messages_without_subnode),
        u64(c.messages_without_recipient_table));
    printf("  %llu attachments with no readable 0x0E20, %llu without 0x3705, %llu without 0x370B\n",
           u64(c.attachments_without_size), u64(c.attachments_without_method),
           u64(c.attachments_without_rendering));
    printf("  %llu attachment rows name no subnode, %llu attachment subnodes no row names\n",
           u64(c.attachment_rows_unresolved), u64(c.attachment_subnodes_unnamed));
    printf(
        "  %llu messages have an unreadable body, %llu attachments have an unreadable payload, %llu"
        " attachments declare a size and hold no payload\n",
        u64(c.messages_with_unreadable_body), u64(c.attachments_with_unreadable_payload),
        u64(c.attachments_with_declared_size_and_no_payload));
    printf(
        "  %llu NBT entries of a nidType the two opened sources do not define: no row in [MS-PST]"
        " 2.2.2.1, or named there with no structure defined\n",
        u64(c.nodes_of_unknown_type));
    printf("  %llu blocks unreadable, %llu decode failures\n", u64(c.blocks_unreadable),
           u64(c.decode_failures));
    printf("  %llu messages whose Property Context did not read\n",
           u64(c.messages_with_unreadable_property_context));
    printf("  %llu subnode walks came back short, %llu table RowIndex walks did not walk\n",
           u64(c.subnode_walks_incomplete), u64(c.row_index_walks_failed));
    printf("  %llu attachment data objects not decoded, %llu attached messages left by a cap\n",
           u64(c.attachment_data_objects_not_decoded), u64(c.attached_messages_left_by_cap));
    for (const std::string& note : c.notes) {
        printf("  - %s\n", one_line(note).c_str());
    }
    for (const std::string& note : c.unreadable_blocks) {
        printf("  ! %s\n", one_line(note).c_str());
    }
    for (const std::string& note : c.incomplete_walks) {
        printf("  ~ %s\n", one_line(note).c_str());
    }

    if (!report.attachments.samples.empty() || !report.associated_attachments.samples.empty() ||
        !report.embedded_attachments.samples.empty()) {
        printf("ATTACHMENT SAMPLES (named, so the enumeration can be checked item by item)\n");
        for (const std::string& sample : report.attachments.samples) {
            printf("  %s\n", one_line(sample).c_str());
        }
        for (const std::string& sample : report.associated_attachments.samples) {
            printf("  %s\n", one_line(sample).c_str());
        }
        // An attached message's attachments name the message and attachment they hang under, so a
        // line can be matched against an independent reader's path for the same item.
        for (const std::string& sample : report.embedded_attachments.samples) {
            printf("  %s\n", one_line(sample).c_str());
        }
    }

    const ost2pst::msg::InventoryStatus& s = report.status;
    printf("STATUS (whether this run read everything it counted)\n");
    printf("  decode failures      %8llu\n", u64(s.decode_failures));
    printf("  logged findings      %8llu\n", u64(s.logged_findings));
    printf("  unreadable blocks    %8llu\n", u64(s.blocks_unreadable));
    printf("  incomplete walks     %8llu\n", u64(s.walks_incomplete));
    printf("  scans capped         %8llu\n", u64(s.scans_capped));
    printf("  attached capped      %8llu\n", u64(s.embedded_capped));
    printf("  content unreadable   %8llu\n", u64(s.content_unreadable));
    printf("  structures not read  %8llu documented non-heap, %llu unsupported by this reader\n",
           u64(s.documented_non_heap), u64(s.unsupported_structures));
    for (const std::string& why : s.reasons) {
        printf("  - %s\n", one_line(why).c_str());
    }

    printf("HEAP (what the seams the inventory used counted)\n");
    print_ltp_heap(report.heap);
    print_ltp_data_trees(report.data_trees, ost2pst::ltp::SubnodeStats{});
    if (!report.errors.empty()) {
        print_ltp_errors(report.errors);
    }
}

// What one folder's conversion would carry. Every number here came through the same seams the
// production reader uses (open_node, read_pc, read_tc, walk_subnode_entries), so what the source
// does not hold shows up as a count with a reason instead of disappearing from the report.
void print_subset(const ost2pst::msg::SubsetReport& report,
                  const ost2pst::ndb::BlockReadCounters& blocks,
                  const ost2pst::msg::SubsetOptions& options) {
    auto u64 = [](uint64_t value) { return static_cast<unsigned long long>(value); };

    uint64_t subnodes_complete = 0;
    uint64_t subnodes_short = 0;
    for (const ost2pst::msg::SubsetMessage& message : report.messages) {
        if (message.subnodes_complete) {
            ++subnodes_complete;
        } else {
            ++subnodes_short;
        }
    }

    printf("SUBSET: FOLDER 0x%016llX\n", u64(report.folder.nid));
    printf("  name              %s\n", report.folder.name.empty()
                                           ? "(no readable 0x3001 PidTagDisplayName)"
                                           : one_line(report.folder.name).c_str());
    printf("  folder PC         %s, %llu values\n", report.folder.pc_read ? "read" : "not read",
           u64(report.folder.values.size()));
    if (!report.folder.note.empty()) {
        printf("                    %s\n", one_line(report.folder.note).c_str());
    }
    printf("  nidParent         %llu Message objects name this folder ([MS-PST] 2.4.5.2)\n",
           u64(report.folder_children));

    printf("SUBSET: MESSAGE OBJECTS\n");
    // An attached Message ([MS-PST] 2.4.6.2.2) is a Message object this reader read, but the NBT
    // does not name it, so the two counts stay apart and the table counters below cover both kinds.
    printf(
        "  read              %llu the folder names + %llu reached through an Attachment object,\n",
        u64(report.messages_read), u64(report.attachments_embedded));
    printf("                    skipped %llu, cap %llu per folder%s\n",
           u64(report.messages_skipped), u64(options.max_messages),
           report.capped ? " (the cap stopped this folder short)" : "");
    printf("  tables            of the %llu Message objects read, %llu carry a Recipient Table,\n",
           u64(report.messages_read + report.attachments_embedded),
           u64(report.messages_with_recipient_table));
    printf("                    %llu carry none ([MS-PST] 2.4.5 Required: Y)\n",
           u64(report.messages_without_recipient_table));
    printf(
        "                    %llu carry an Attachment Table ([MS-PST] 2.4.6.1 makes it optional)\n",
        u64(report.messages_with_attachment_table));
    printf("  values            %llu carried, %llu present with no value, %llu not readable\n",
           u64(report.values_read), u64(report.values_absent), u64(report.unreadable_values));
    printf("  required tags     %llu Message PCs miss a [MS-PST] 2.4.5.1.1 required tag\n",
           u64(report.required_missing));
    printf("  body forms        %llu readable 0x1000, %llu 0x1013, %llu 0x1009, %llu with none\n",
           u64(report.body_plain), u64(report.body_html), u64(report.body_rtf),
           u64(report.body_none));
    printf("  subnodes          %llu enumerated to the end, %llu short or absent\n",
           subnodes_complete, subnodes_short);
    printf("  rows              %llu RowIndex rows name a slot past their Row Matrix\n",
           u64(report.rows_without_cells));

    printf("SUBSET: RECIPIENT ROWS\n  read              %llu\n", u64(report.recipients_read));

    printf("SUBSET: ATTACHMENTS\n");
    printf(
        "  objects           %llu named by a row, %llu with no payload the converter can carry\n",
        u64(report.attachments_read), u64(report.attachments_without_payload));
    printf("  attached Message  %llu Attachment objects carry a Message as their 0x3701 object\n",
           u64(report.attachments_embedded + report.attachments_with_unread_object));
    printf(
        "                    ([MS-PST] 2.4.6.2.2): %llu of them this reader read as a Message,\n",
        u64(report.attachments_embedded));
    printf("                    %llu it could not carry\n",
           u64(report.attachments_with_unread_object));
    printf("  payload           %llu B read in total, largest single payload %llu B\n",
           u64(report.payload_bytes), u64(report.max_payload_bytes));
    // One data block holds 8,176 raw bytes ([MS-PST] 2.2.2.8.3.1), so the largest payload decides
    // whether a value needs a jump table under it at all.
    printf("                    (one data block holds 8,176 raw bytes: %s)\n",
           report.max_payload_bytes > 8176 ? "the largest one needs a data tree"
                                           : "every one fits in a single data block");

    // What the source has and this reader could not read. These are the counters the converter
    // turns into a shortfall and a nonzero exit (src/cli/ost2pst.cpp), so the diagnostic view
    // prints them too: a walk that stopped partway must not read as a folder that has fewer items.
    printf("SUBSET: EXTRACTION FAILURES\n");
    printf("  Property Context  %llu Message objects did not read their own\n",
           u64(report.messages_without_pc));
    printf("  tables            %llu Recipient Tables and %llu Attachment Tables the source has "
           "and this\n",
           u64(report.recipient_table_failures), u64(report.attachment_table_failures));
    printf("                    reader could not read\n");
    printf("  attachments       %llu objects that did not open as a Property Context\n",
           u64(report.attachment_pc_failures));
    printf(
        "  subnodes          %llu walks failed, %llu stopped before they enumerated every entry\n",
        u64(report.subnode_walk_failures), u64(report.subnode_walks_incomplete));
    printf("  row index         %llu table RowIndex walks stopped before the end\n",
           u64(report.row_index_walks_incomplete));
    printf("  row matrix        %llu blocks short of the full block [MS-PST] 2.3.4.4 requires\n",
           u64(report.matrix_short_blocks));
    printf("  values            %llu records the reader could not get the content of, %llu "
           "PtypObject\n",
           u64(report.unreadable_values), u64(report.object_values));
    printf("                    allocations it read ([MS-PST] 2.3.3.5)\n");

    std::map<uint16_t, const ost2pst::msg::SubsetValue*> named;
    for (const ost2pst::msg::SubsetMessage& message : report.messages) {
        for (const ost2pst::msg::SubsetValue& value : message.values) {
            if (value.named) {
                named.emplace(value.prop_id, &value);
            }
        }
    }
    printf("SUBSET: NAMED PROPERTIES\n");
    printf("  carried           %llu distinct NPID, %llu the Name-to-ID Map has no entry for\n",
           u64(named.size()), u64(report.named_unresolved));
    uint64_t shown = 0;
    for (const auto& item : named) {
        if (shown >= options.max_notes) {
            printf("  ...               %llu more not printed\n", u64(named.size() - shown));
            break;
        }
        const ost2pst::msg::SubsetValue& value = *item.second;
        std::string guid;
        for (const uint8_t byte : value.guid) {
            char buffer[4];
            std::snprintf(buffer, sizeof(buffer), "%02X", static_cast<unsigned>(byte));
            guid += buffer;
        }
        // [MS-PST] 2.4.7.1: the N bit decides what the name is, so a numeric name prints as the
        // name it is instead of being called unresolved.
        const bool name_known = value.name_is_string ? value.name_resolved : true;
        const std::string name = value.name_is_string
                                     ? ost2pst::ltp::name_id_utf8(value.name)
                                     : "numeric " + std::to_string(value.numeric_name);
        printf("  0x%04X            %-28s set %u %s guid %s\n",
               static_cast<unsigned>(value.prop_id),
               name_known ? one_line(name).c_str() : "(no String Stream name at that offset)",
               static_cast<unsigned>(value.guid_index),
               value.guid_resolved ? "resolved" : "unresolved",
               guid.empty() ? "(none)" : guid.c_str());
        ++shown;
    }

    printf("SUBSET: EVERY MESSAGE THIS RUN READ\n");
    for (const ost2pst::msg::SubsetMessage& message : report.messages) {
        uint64_t carried = 0;
        uint64_t none = 0;
        uint64_t unreadable = 0;
        std::string bodies;
        for (const ost2pst::msg::SubsetValue& value : message.values) {
            if (value.readable) {
                ++carried;
            } else if (value.absent) {
                ++none;
            } else {
                ++unreadable;
            }
            // 0x1000 and 0x1013 are body tags [MS-PST] names in its own example (3.13,
            // ms-pst.txt:8087, 8093); 0x1009 is a tag this sample carries and neither opened
            // reference names, so it is printed as what it is.
            if (value.readable &&
                (value.prop_id == 0x1000 || value.prop_id == 0x1013 || value.prop_id == 0x1009)) {
                char buffer[8];
                std::snprintf(buffer, sizeof(buffer), "%04X ",
                              static_cast<unsigned>(value.prop_id));
                bodies += buffer;
            }
        }
        printf(
            "  0x%016llX values %llu carried, %llu none, %llu unreadable | body %s| recipients %llu"
            " | attachments %llu | subnodes %llu\n",
            u64(message.nid), u64(carried), u64(none), u64(unreadable),
            bodies.empty() ? "none " : bodies.c_str(), u64(message.recipients.size()),
            u64(message.attachments.size()), u64(message.subnode_entries));
        if (!message.note.empty()) {
            printf("                    %s\n", one_line(message.note).c_str());
        }
        for (const ost2pst::msg::SubsetAttachment& attachment : message.attachments) {
            printf(
                "      row 0x%08X names subnode 0x%016llX: PC %s, declared %llu B, read %llu B\n",
                static_cast<unsigned>(attachment.row_id), u64(attachment.subnode_nid),
                attachment.pc_read ? "read" : "not read", u64(attachment.declared_bytes),
                u64(attachment.payload_bytes));
            if (!attachment.note.empty()) {
                printf("                    %s\n", one_line(attachment.note).c_str());
            }
        }
    }

    printf("SUBSET: NOTES\n");
    if (report.notes.empty()) {
        printf("  (none)\n");
    }
    for (const std::string& note : report.notes) {
        printf("  %s\n", one_line(note).c_str());
    }
    printf("SUBSET: SKIPPED\n");
    if (report.skipped.empty()) {
        printf("  (none)\n");
    }
    for (const std::string& item : report.skipped) {
        printf("  %s\n", one_line(item).c_str());
    }
    printf("BLOCKS THIS SUBSET OPENED\n");
    printf("  requested         %llu, read %llu, not indexed %llu, out of range %llu, %llu bytes\n",
           u64(blocks.requested), u64(blocks.decoded), u64(blocks.not_indexed),
           u64(blocks.out_of_range), u64(blocks.data_bytes));
}

int wmain(int argc, wchar_t** argv) {
    ProbeOptions probe_options;
    NdbReadOptions ndb_options;
    LtpReadOptions ltp_options;
    ost2pst::msg::InventoryOptions inventory_options;
    ost2pst::msg::SubsetOptions subset_options;
    uint64_t subtree_nid = 0;
    uint64_t subset_nid = 0;
    Action action = kActionProbe;
    std::wstring path;
    const ParseResult parsed =
        parse_options(argc, argv, path, action, probe_options, ndb_options, ltp_options,
                      inventory_options, subset_options, subtree_nid, subset_nid);
    if (parsed == kParseHelp) {
        print_usage();
        return kExitOk;
    }
    if (parsed == kParseError) {
        print_usage();
        return kExitUsage;
    }

    const std::string shown_path = to_utf8(path);
    ost2pst::util::Result<FileReader> opened = FileReader::open_stable(path);
    if (!opened.ok()) {
        std::fprintf(stderr, "cannot open %s: %s\n", shown_path.c_str(),
                     ost2pst::util::format_error(opened.error()).c_str());
        return ost2pst::cli::input_error_exit(opened.error());
    }
    const FileReader& file = opened.value();
    const auto valid = ost2pst::cli::validate_input(file);
    if (!valid.ok())
        return ost2pst::cli::report_input_error(valid.error());

    printf("%s %s\n", action == kActionProbe ? "probing" : "reading", shown_path.c_str());
    printf("  file size         %llu bytes\n", static_cast<unsigned long long>(file.size()));

    if (action == kActionProbe) {
        ost2pst::util::Result<ProbeReport> probed = ost2pst::ndb::probe_file(file, probe_options);
        if (!probed.ok()) {
            std::fprintf(stderr, "probe failed on %s: %s\n", shown_path.c_str(),
                         ost2pst::util::format_error(probed.error()).c_str());
            return ost2pst::cli::input_error_exit(probed.error());
        }
        const ProbeReport& report = probed.value();
        print_header(report.header);
        print_root(report.header.root, file.size());
        print_header_crcs(report.header_crcs);
        if (report.refusal) {
            printf("REFUSAL\n  %s\n", ost2pst::util::format_error(*report.refusal).c_str());
            printf("\nRESULT: refused\n");
            return kExitRefusal;
        }
        printf("PROFILE\n  detected          %s\n",
               ost2pst::ndb::file_profile_name(report.profile));
        printf("  evidence          %s\n", report.profile_evidence.c_str());
        print_blocks(report.counters.blocks, report.profile, probe_options);
        print_amap(report.counters.amap, report.profile, probe_options);
        print_grid(report.counters.grid, report.profile);
        print_btree("BBT", report.counters.bbt);
        printf("  BBT index         %llu blocks over %llu allocation units\n",
               static_cast<unsigned long long>(report.counters.bbt_index_entries),
               static_cast<unsigned long long>(report.counters.blocks.units_marked));
        print_btree("NBT", report.counters.nbt);
        printf("  NBT entries       %llu, bidData missing %llu, bidSub missing %llu\n",
               static_cast<unsigned long long>(report.counters.nbt_entries),
               static_cast<unsigned long long>(report.counters.nbt_bid_data_missing),
               static_cast<unsigned long long>(report.counters.nbt_bid_sub_missing));
        printf("DENSITY LIST\n  valid pages       %llu, at the profile offset %llu\n",
               static_cast<unsigned long long>(report.counters.dlist_pages),
               static_cast<unsigned long long>(report.counters.dlist_at_expected_offset));
        printf("CRC VARIANT TALLY (matches / total for each seed and complement reading)\n");
        print_tally("blocks", report.counters.blocks.crc_variants);
        print_tally("BBT pages", report.counters.bbt.crc_variants);
        print_tally("NBT pages", report.counters.nbt.crc_variants);
        print_tally("AMap pages", report.counters.amap.crc_variants);
        print_tally("grid candidates", report.counters.grid.crc_variants);
        print_failures(report.failure_total, report.failures);
        printf("\nRESULT: %s\n", report.clean ? "clean" : "findings present");
        return report.clean ? kExitOk : kExitCorrupt;
    }

    if (action == kActionInventory) {
        // The inventory is a layer above the census: it reads the file once through read_ltp, then
        // opens only the nodes a Message object's bidSub names, resolving them through the BBT
        // index the census already built.
        const auto started = std::chrono::steady_clock::now();
        ost2pst::util::Result<LtpReadReport> read = ost2pst::ltp::read_ltp(file, ltp_options);
        if (!read.ok()) {
            std::fprintf(stderr, "ltp read failed on %s: %s\n", shown_path.c_str(),
                         ost2pst::util::format_error(read.error()).c_str());
            return ost2pst::cli::input_error_exit(read.error());
        }
        const LtpReadReport& census = read.value();
        print_header(census.header);
        print_root(census.header.root, file.size());
        if (census.refusal) {
            printf("REFUSAL\n  %s\n", ost2pst::util::format_error(*census.refusal).c_str());
            printf("\nRESULT: refused\n");
            return kExitRefusal;
        }
        ost2pst::ndb::BlockReadCounters block_counters;
        ost2pst::ndb::FailureLog block_failures(1);
        ost2pst::ltp::FileBlockSource blocks(file, census.profile, census.bbt_index, block_counters,
                                             block_failures);
        // The block source and the failure log belong to this seam, and the inventory reads through
        // them. Handing over references is what lets the verdict below see a block the file itself
        // could not supply instead of only the ones the inventory noticed while opening nodes.
        const ost2pst::msg::InventoryUpstream upstream{&block_counters, &block_failures};
        ost2pst::util::Result<ost2pst::msg::InventoryReport> built =
            ost2pst::msg::build_inventory(census, blocks, inventory_options, upstream);
        const double seconds =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
        if (!built.ok()) {
            std::fprintf(stderr, "inventory failed on %s: %s\n", shown_path.c_str(),
                         ost2pst::util::format_error(built.error()).c_str());
            return ost2pst::cli::input_error_exit(built.error());
        }
        const ost2pst::msg::InventoryReport& report = built.value();
        printf("PROFILE\n  detected          %s\n",
               ost2pst::ndb::file_profile_name(census.profile));
        printf("  evidence          %s\n", census.profile_evidence.c_str());
        print_inventory(report);
        print_ltp_findings(census.findings);
        printf("RESOURCES\n");
        printf("  peak RSS          %llu bytes (%.1f MiB)\n",
               static_cast<unsigned long long>(peak_working_set_bytes()),
               static_cast<double>(peak_working_set_bytes()) / (1024.0 * 1024.0));
        printf("  wall time         %.2f s\n", seconds);
        // "clean" here is the inventory's own verdict, not a pair of counters picked at the print
        // site: every structure this run opened decoded, every list it counted was read to the end,
        // every block the index named was there, and no cap stopped a scan. A mailbox whose
        // messages have no body form, or whose attachments have no size, is incomplete rather than
        // corrupt -- the COMPLETENESS section says how much -- so those counts never turn this line
        // red. A decode failure, a walk that came back short, a block the file could not supply, a
        // cap that stopped a scan, or a value a record named that this reader could not get always
        // does.
        const ost2pst::msg::InventoryStatus& status = report.status;
        printf("\nRESULT: %s (%llu decode failures, %llu logged findings, %llu unreadable blocks,"
               " %llu incomplete walks, %llu scans capped, %llu unreadable content, %llu messages,"
               " %llu attached messages, %llu FAI entries, %llu attachments, %llu folders)\n",
               status.clean ? "clean" : "findings present",
               static_cast<unsigned long long>(status.decode_failures),
               static_cast<unsigned long long>(status.logged_findings),
               static_cast<unsigned long long>(status.blocks_unreadable),
               static_cast<unsigned long long>(status.walks_incomplete),
               static_cast<unsigned long long>(status.scans_capped),
               static_cast<unsigned long long>(status.content_unreadable),
               static_cast<unsigned long long>(report.messages.nodes),
               static_cast<unsigned long long>(report.embedded.nodes),
               static_cast<unsigned long long>(report.associated.nodes),
               static_cast<unsigned long long>(report.attachments.nodes_opened),
               static_cast<unsigned long long>(report.folders.size()));
        return status.clean ? kExitOk : kExitCorrupt;
    }

    if (action == kActionSubset) {
        // A folder conversion needs the NID map and the BBT index the LTP read builds, but not the
        // census of every data block or the folder walk: the extractor opens only the nodes this
        // folder names.
        LtpReadOptions options = ltp_options;
        options.scan_blocks = false;
        options.build_folders = false;
        options.dump_requested = false;
        const auto started = std::chrono::steady_clock::now();
        ost2pst::util::Result<LtpReadReport> read = ost2pst::ltp::read_ltp(file, options);
        if (!read.ok()) {
            std::fprintf(stderr, "ltp read failed on %s: %s\n", shown_path.c_str(),
                         ost2pst::util::format_error(read.error()).c_str());
            return ost2pst::cli::input_error_exit(read.error());
        }
        const LtpReadReport& census = read.value();
        print_header(census.header);
        print_root(census.header.root, file.size());
        if (census.refusal) {
            printf("REFUSAL\n  %s\n", ost2pst::util::format_error(*census.refusal).c_str());
            printf("\nRESULT: refused\n");
            return kExitRefusal;
        }
        printf("PROFILE\n  detected          %s\n",
               ost2pst::ndb::file_profile_name(census.profile));
        printf("  evidence          %s\n", census.profile_evidence.c_str());
        printf("NBT               %llu entries indexed\n",
               static_cast<unsigned long long>(census.nodes.size()));
        // The named identities the subset report resolves are the Name-to-ID Map's, so the map's
        // own state belongs next to them.
        print_ltp_npm(census);

        ost2pst::ndb::BlockReadCounters block_counters;
        ost2pst::ndb::FailureLog block_failures(20);
        ost2pst::ltp::FileBlockSource blocks(file, census.profile, census.bbt_index, block_counters,
                                             block_failures);
        const ost2pst::util::Result<ost2pst::msg::SubsetReport> built =
            ost2pst::msg::build_subset(census, blocks, subset_nid, subset_options);
        const double seconds =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
        if (!built.ok()) {
            std::fprintf(stderr, "subset read failed on %s folder 0x%llX: %s\n", shown_path.c_str(),
                         static_cast<unsigned long long>(subset_nid),
                         ost2pst::util::format_error(built.error()).c_str());
            return ost2pst::cli::input_error_exit(built.error());
        }
        const ost2pst::msg::SubsetReport& report = built.value();
        print_subset(report, block_counters, subset_options);
        printf("RESOURCES\n");
        printf("  peak RSS          %llu bytes (%.1f MiB)\n",
               static_cast<unsigned long long>(peak_working_set_bytes()),
               static_cast<double>(peak_working_set_bytes()) / (1024.0 * 1024.0));
        printf("  wall time         %.2f s\n", seconds);
        // A subset is clean when everything the extractor tried to read did read and every Message
        // object it read carries the Recipient Table [MS-PST] 2.4.5 marks Required: Y. A cap is not
        // corruption, but it means the folder was not read whole, so the verdict names it either
        // way.
        const uint64_t extraction_failures =
            report.messages_without_pc + report.recipient_table_failures +
            report.attachment_table_failures + report.attachment_pc_failures +
            report.subnode_walk_failures + report.subnode_walks_incomplete +
            report.row_index_walks_incomplete + report.matrix_short_blocks +
            report.attachments_with_unread_object +
            (report.object_values > report.object_values_carried
                 ? report.object_values - report.object_values_carried
                 : 0);
        const bool clean = report.folder.pc_read && report.messages_skipped == 0 &&
                           report.unreadable_values == 0 && report.rows_without_cells == 0 &&
                           report.messages_with_recipient_table ==
                               report.messages_read + report.attachments_embedded &&
                           extraction_failures == 0;
        printf("\nRESULT: %s (%llu messages read, %llu skipped%s, %llu values carried, %llu with "
               "no value,"
               " %llu not readable, %llu rows without cells,\n"
               "         %llu extraction failures: %llu tables, %llu subnode walks, %llu attached "
               "Messages)\n",
               clean ? "clean" : "findings present",
               static_cast<unsigned long long>(report.messages_read),
               static_cast<unsigned long long>(report.messages_skipped),
               report.capped ? ", capped" : "", static_cast<unsigned long long>(report.values_read),
               static_cast<unsigned long long>(report.values_absent),
               static_cast<unsigned long long>(report.unreadable_values),
               static_cast<unsigned long long>(report.rows_without_cells),
               static_cast<unsigned long long>(extraction_failures),
               static_cast<unsigned long long>(report.recipient_table_failures +
                                               report.attachment_table_failures),
               static_cast<unsigned long long>(report.subnode_walk_failures +
                                               report.subnode_walks_incomplete +
                                               report.row_index_walks_incomplete),
               static_cast<unsigned long long>(
                   report.attachments_with_unread_object +
                   (report.object_values > report.object_values_carried
                        ? report.object_values - report.object_values_carried
                        : 0)));
        return clean ? kExitOk : kExitCorrupt;
    }

    if (action == kActionSubtree) {
        // The dump needs the NID map and the BBT index the LTP read builds, but not the census of
        // every data block or the folder walk: it opens only the nodes it describes.
        LtpReadOptions options = ltp_options;
        options.scan_blocks = false;
        options.build_folders = false;
        options.dump_requested = false;
        const auto started = std::chrono::steady_clock::now();
        ost2pst::util::Result<LtpReadReport> read = ost2pst::ltp::read_ltp(file, options);
        if (!read.ok()) {
            std::fprintf(stderr, "ltp read failed on %s: %s\n", shown_path.c_str(),
                         ost2pst::util::format_error(read.error()).c_str());
            return ost2pst::cli::input_error_exit(read.error());
        }
        const LtpReadReport& census = read.value();
        print_header(census.header);
        print_root(census.header.root, file.size());
        if (census.refusal) {
            printf("REFUSAL\n  %s\n", ost2pst::util::format_error(*census.refusal).c_str());
            printf("\nRESULT: refused\n");
            return kExitRefusal;
        }
        printf("PROFILE\n  detected          %s\n",
               ost2pst::ndb::file_profile_name(census.profile));
        printf("  evidence          %s\n", census.profile_evidence.c_str());
        printf("NBT               %llu entries indexed\n",
               static_cast<unsigned long long>(census.nodes.size()));

        ost2pst::ndb::BlockReadCounters block_counters;
        ost2pst::ndb::FailureLog block_failures(20);
        ost2pst::ltp::FileBlockSource blocks(file, census.profile, census.bbt_index, block_counters,
                                             block_failures);
        ost2pst::ltp::SubtreeDumpOptions dump_options;
        const ost2pst::util::Result<ost2pst::ltp::SubtreeDump> dumped = ost2pst::ltp::dump_subtree(
            census.nodes, blocks, census.profile, subtree_nid, dump_options);
        const double seconds =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
        if (!dumped.ok()) {
            std::fprintf(stderr, "subtree dump failed on %s nid 0x%llX: %s\n", shown_path.c_str(),
                         static_cast<unsigned long long>(subtree_nid),
                         ost2pst::util::format_error(dumped.error()).c_str());
            return ost2pst::cli::input_error_exit(dumped.error());
        }
        const ost2pst::ltp::SubtreeDump& dump = dumped.value();
        print_subtree(dump, block_counters);
        printf("RESOURCES\n");
        printf("  peak RSS          %llu bytes (%.1f MiB)\n",
               static_cast<unsigned long long>(peak_working_set_bytes()),
               static_cast<double>(peak_working_set_bytes()) / (1024.0 * 1024.0));
        printf("  wall time         %.2f s\n", seconds);
        // A dump is clean when every block it opened decoded and every list it walked ran to the
        // end. A cap that cut a list short is not corruption, but it does mean the dump is not the
        // whole answer.
        const bool clean = dump.failure_total == 0 && dump.stats.blocks_bad == 0 &&
                           !dump.stats.stopped_early && !dump.capped;
        printf(
            "\nRESULT: %s (%llu logged findings, %llu bad subnode blocks, %llu blocks not flagged"
            " Internal, %llu blocks not indexed%s)\n",
            clean ? "clean" : "findings present",
            static_cast<unsigned long long>(dump.failure_total),
            static_cast<unsigned long long>(dump.stats.blocks_bad),
            static_cast<unsigned long long>(dump.stats.blocks_not_internal),
            static_cast<unsigned long long>(block_counters.not_indexed),
            dump.capped ? ", dump capped" : "");
        return clean ? kExitOk : kExitCorrupt;
    }

    if (action == kActionLtp) {
        const auto started = std::chrono::steady_clock::now();
        ost2pst::util::Result<LtpReadReport> read = ost2pst::ltp::read_ltp(file, ltp_options);
        const double seconds =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
        if (!read.ok()) {
            std::fprintf(stderr, "ltp read failed on %s: %s\n", shown_path.c_str(),
                         ost2pst::util::format_error(read.error()).c_str());
            return ost2pst::cli::input_error_exit(read.error());
        }
        const LtpReadReport& report = read.value();
        print_header(report.header);
        print_root(report.header.root, file.size());
        if (report.refusal) {
            printf("REFUSAL\n  %s\n", ost2pst::util::format_error(*report.refusal).c_str());
            printf("\nRESULT: refused\n");
            return kExitRefusal;
        }
        printf("PROFILE\n  detected          %s\n",
               ost2pst::ndb::file_profile_name(report.profile));
        printf("  evidence          %s\n", report.profile_evidence.c_str());
        print_btree("BBT", report.bbt);
        print_btree("NBT", report.nbt);
        print_ltp_nids(report);
        print_ltp_heap(report.heap);
        print_ltp_data_trees(report.data_trees, report.subnodes);
        print_ltp_pcs(report.pcs);
        print_ltp_tcs(report.tcs);
        printf("INTERNAL STRUCTURES\n");
        printf("  GUID maps         %llu read, %llu records\n",
               static_cast<unsigned long long>(report.guid_maps_read),
               static_cast<unsigned long long>(report.guid_map_records));
        printf("  Search Activity   %s, %llu NIDs\n", report.sal_read ? "read" : "not read",
               static_cast<unsigned long long>(report.search_activity_nids.size()));
        print_ltp_npm(report);
        print_ltp_smq(report);
        print_ltp_folders(report.folders, report.folder_stats);
        print_ltp_dump(report);
        print_ltp_errors(report.errors);
        print_ltp_findings(report.findings);
        printf("RESOURCES\n");
        printf("  peak RSS          %llu bytes (%.1f MiB)\n",
               static_cast<unsigned long long>(peak_working_set_bytes()),
               static_cast<double>(peak_working_set_bytes()) / (1024.0 * 1024.0));
        printf("  wall time         %.2f s\n", seconds);
        print_failures(report.failure_total, report.failures);
        uint64_t tallied_field_errors = 0;
        for (const auto& item : report.errors) {
            tallied_field_errors += item.second;
        }
        // "clean" says every structure the reader opened decoded; it never claims the file was read
        // completely, so the counts that say what was not read ride on the same line. Every number
        // names a section printed above it, so nothing counted anywhere can hide behind the word.
        printf(
            "\nRESULT: %s (%llu decode failures, %llu logged findings, %llu tallied field errors, "
            "%llu structures not read)\n",
            report.clean ? "clean" : "findings present",
            static_cast<unsigned long long>(report.findings.decode_failures),
            static_cast<unsigned long long>(report.failure_total),
            static_cast<unsigned long long>(tallied_field_errors),
            static_cast<unsigned long long>(report.findings.documented_non_heap +
                                            report.findings.unsupported));
        return report.clean ? kExitOk : kExitCorrupt;
    }

    // M1 exit criteria are a wall-clock budget and a peak-RSS budget, so both are measured around
    // the read itself rather than inferred afterwards.
    const auto started = std::chrono::steady_clock::now();
    ost2pst::util::Result<NdbReadReport> read = ost2pst::ndb::read_ndb(file, ndb_options);
    const double seconds =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    if (!read.ok()) {
        std::fprintf(stderr, "ndb read failed on %s: %s\n", shown_path.c_str(),
                     ost2pst::util::format_error(read.error()).c_str());
        return ost2pst::cli::input_error_exit(read.error());
    }
    const NdbReadReport& report = read.value();
    print_header(report.header);
    print_root(report.header.root, file.size());
    print_header_crcs(report.header_crcs);
    if (report.refusal) {
        printf("REFUSAL\n  %s\n", ost2pst::util::format_error(*report.refusal).c_str());
        printf("\nRESULT: refused\n");
        return kExitRefusal;
    }
    printf("PROFILE\n  detected          %s\n", ost2pst::ndb::file_profile_name(report.profile));
    printf("  evidence          %s\n", report.profile_evidence.c_str());
    print_btree("BBT", report.bbt);
    print_ndb_index(report);
    print_btree("NBT", report.nbt);
    print_ndb_nbt(report);
    print_ndb_blocks(report.blocks);
    print_ndb_coverage(report, peak_working_set_bytes(), seconds);
    print_failures(report.failure_total, report.failures);
    printf("\nRESULT: %s\n", report.clean ? "clean" : "findings present");
    return report.clean ? kExitOk : kExitCorrupt;
}
