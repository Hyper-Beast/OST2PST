// R4 is about what the reader SAYS about a node it could not read, not only about what it read. A data
// block with no HNHDR is three different facts: [MS-PST] 2.4.8.4 / 2.4.8.5 name predefined internal nodes
// that hold an array of NIDs, a queue, or an opaque BLOB instead of a heap node; [MS-PST] 2.3.1.2 reserves
// bClientSig values whose heap nothing defines; and a node whose own nidType does promise a Property
// Context or a Table Context, or a predefined internal NID the spec calls a PC ([MS-PST] 2.4.3, 2.4.4.1,
// 2.4.7, 2.7.3.3), contradicts its own metadata. This file builds a format-true OST-profile file per case
// and checks which class the report puts each node in, so "clean" can never mean "nothing was skipped".
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/ltp_read.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/crc32.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/sig.h"
#include "ost2pst/util/status.h"
#include "ost_fixture.h"
#include "test_support.h"

namespace {

using namespace ost2pst;
using ltp::classify_missing_heap_node;
using ltp::LtpFindingKind;
using ltp::LtpFindingTally;
using ltp::LtpReadOptions;
using ltp::LtpReadReport;
using ltp::read_ltp;
using util::ByteView;
using util::FileReader;
using util::Result;

// The format-true file builder is shared with the CLI test: see ost_fixture.h.
using namespace ost2pst::test::ost;


LtpReadOptions fixture_options() {
    LtpReadOptions options;
    options.build_folders = false; // these fixtures carry no folder tree; the census is what is under test
    options.max_failures = 10;
    return options;
}

LtpReadReport read_fixture(const std::vector<NodeSpec> &nodes, const char *name) {
    const std::vector<uint8_t> bytes = build_file(nodes);
    {
        std::ofstream out(name, std::ios::binary);
        out.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    std::wstring wide;
    for (const char character : std::string(name)) {
        wide.push_back(static_cast<wchar_t>(character));
    }
    Result<FileReader> opened = FileReader::open(wide);
    if (!opened.ok()) {
        ost2pst::test::report_failure(__FILE__, __LINE__,
                                      "cannot open the fixture: " + util::format_error(opened.error()));
        return {};
    }
    Result<LtpReadReport> read = read_ltp(opened.value(), fixture_options());
    std::remove(name);
    if (!read.ok()) {
        ost2pst::test::report_failure(__FILE__, __LINE__,
                                      "read_ltp failed: " + util::format_error(read.error()));
        return {};
    }
    return read.take();
}

uint64_t tallied(const LtpReadReport &report, const std::string &field) {
    const auto found = report.errors.find(field);
    return found == report.errors.end() ? 0 : found->second;
}

// A node the reader can read produces no finding at all: the classes stay empty and `clean` stays true.
void test_a_read_node_is_not_a_finding() {
    std::vector<std::vector<uint8_t>> allocations;
    allocations.push_back(bth_header(2, 6, 0x40));
    allocations.push_back(pc_records({{0x3001, 0x001F, 0x60}, {0x36DA, 0x000B, 1}}));
    allocations.push_back(utf16("Inbox"));
    const LtpReadReport report = read_fixture(
        {{9, ltp::kNidTypeNormalFolder, ltp::kNidRootFolder, false,
          heap_node(ltp::kClientSigPc, 0x20, allocations)}},
        "ltp_findings_clean.bin");

    TEST_EQ(report.findings.total, 0, "a read node records no finding");
    TEST_EQ(report.findings.decode_failures, 0, "no decode failures");
    TEST_EQ(report.findings.documented_non_heap, 0, "no documented non-heap nodes");
    TEST_EQ(report.findings.unsupported, 0, "no unsupported structures");
    TEST_EQ(report.failure_total, 0, "no logged findings");
    TEST_EQ(report.errors.size(), 0, "no tallied field errors");
    TEST_EQ(report.heap.heap_nodes_ok, 1, "one heap node decoded");
    TEST_EQ(report.pcs.contexts, 1, "read as the Property Context its nidType announces");
    TEST_CHECK(report.clean);
}

// [MS-PST] 2.3.1.5 bounds rgibAlloc by the space the block leaves, and nothing else. A cAlloc past that is
// a decode failure, and it is the only class that makes a read not clean.
void test_a_page_map_past_the_block_is_a_decode_failure() {
    {
        // cAlloc 4000 needs 8,002 bytes of table; this 64-byte block leaves 48.
        const LtpReadReport report = read_fixture(
            {{9, ltp::kNidTypeNormalFolder, ltp::kNidRootFolder, false, page_map_case(4000, 0, {16, 20, 24}, 64)}},
            "ltp_findings_truncated.bin");
        TEST_CHECK(!report.clean);
        TEST_EQ(report.findings.decode_failures, 1, "one decode failure");
        TEST_EQ(report.findings.documented_non_heap, 0, "and nothing excused as documented");
        TEST_EQ(report.findings.unsupported, 0, "or as unsupported");
        TEST_EQ(tallied(report, "HNPAGEMAP.rgibAlloc"), 1, "the tally names the field");
        TEST_EQ(report.heap.heap_nodes_ok, 1, "the heap node itself still decoded");
        if (!report.findings.items.empty()) {
            TEST_EQ(report.findings.items[0].nid, ltp::make_nid(9, ltp::kNidTypeNormalFolder),
                    "the finding names the node");
            TEST_STR(report.findings.items[0].field, "HNPAGEMAP.rgibAlloc", "the finding names the field");
            TEST_STR(ltp::ltp_finding_kind_name(report.findings.items[0].kind), "decode failure",
                     "class name");
        }
    }
    {
        // [MS-PST] 2.3.1.5: rgibAlloc lists the allocations in order, so a table that goes backwards is a
        // contradiction, not a shape the reader should accept.
        const LtpReadReport report = read_fixture(
            {{9, ltp::kNidTypeNormalFolder, ltp::kNidRootFolder, false,
              page_map_case(3, 0, {16, 40, 24, 48}, 64)}},
            "ltp_findings_order.bin");
        TEST_CHECK(!report.clean);
        TEST_EQ(report.findings.decode_failures, 1, "one decode failure");
        TEST_EQ(tallied(report, "HNPAGEMAP.rgibAlloc"), 1, "the tally names the field");
    }
}

// [MS-PST] 2.4.8.4.2 / 2.4.8.4.3 / 2.4.8.5.3 say these predefined internal nodes hold an array of NIDs, and
// 2.4.8.3 says a queue node holds an array of fixed-size items. A data block with no HNHDR under them is
// what the spec says to expect, so it is itemized as documented, never counted as a failure.
void test_documented_non_heap_nodes_are_itemized_not_failed() {
    const std::vector<uint8_t> nids = nid_array({0x223, 0x243, 0x263, 0x283});
    const LtpReadReport report = read_fixture(
        {
            {16, ltp::kNidTypeInternal, 0, false, nids}, // NID_SEARCH_ACTIVITY_LIST 0x201
            {19, ltp::kNidTypeInternal, 0, false, nids}, // NID_SEARCH_DOMAIN_OBJECT 0x261
            {25, ltp::kNidTypeInternal, 0, false, nids}, // NID_SEARCH_GATHERER_FOLDER_QUEUE 0x321
        },
        "ltp_findings_documented.bin");

    TEST_EQ(report.findings.documented_non_heap, 2, "two non-heap nodes still not decoded");
    TEST_EQ(report.findings.decode_failures, 0, "none of them is a decode failure");
    TEST_EQ(report.findings.unsupported, 0, "and none of them is unnamed");
    TEST_EQ(tallied(report, "HNHDR.bSig"), 2, "SAL is decoded without attempting HNHDR");
    TEST_EQ(report.heap.heap_nodes_rejected, 2, "the census counted the rejected blocks");
    TEST_CHECK(report.sal_read);
    TEST_EQ(report.search_activity_nids.size(), 4u, "all SAL NIDs were read");
    TEST_EQ(report.data_trees.data_blocks, 1u, "SAL data block counted outside the heap census");
    TEST_CHECK(report.clean);
    if (report.findings.items.size() == 2) {
        TEST_STR(report.findings.items[0].detail, "a heap node carries 0xEC",
                 "the finding quotes the rule");
        TEST_STR(ltp::ltp_finding_kind_name(report.findings.items[0].kind),
                 "documented non-heap node", "class name");
    }
    const auto broken = read_fixture({{16, ltp::kNidTypeInternal, 0, false, {0x23, 0x22, 0}}},
                                     "ltp_findings_bad_sal.bin");
    TEST_CHECK(!broken.clean);
    TEST_CHECK(!broken.sal_read);
    TEST_EQ(broken.findings.decode_failures, 1u, "incomplete SAL is a decode failure");
    TEST_EQ(tallied(broken, "SAL.rgnid"), 1u, "SAL error propagated to whole-file report");
}

// An internal nidIndex the [MS-PST] 2.4.1 table does not name, and a nidType the 2.2.2.1 table does
// not announce as a PC or a TC, are both structures this reader cannot say anything about. They are
// reported, not excused, and not called failures either.
void test_unknown_nodes_are_reported_as_unsupported() {
    const std::vector<uint8_t> nids = nid_array({0x223, 0x243});
    const LtpReadReport report = read_fixture(
        {
            {119, ltp::kNidTypeInternal, 0, false, nids}, // nid 0xEE1: no name in 2.4.1
            {120, ltp::kNidTypeInternal, 0, false, nids}, // nid 0xF01: no name in 2.4.1
            {1026, ltp::kNidTypeContentsTableIndex, 0, false, nids}, // nidType 0x0A: not announced as a TC
            {16391, ltp::kNidTypeSearchTableIndex, 0, false, nids},  // nidType 0x13: not announced as a TC
        },
        "ltp_findings_unknown.bin");

    TEST_EQ(report.findings.unsupported, 4, "four structures the reader cannot name");
    TEST_EQ(report.findings.documented_non_heap, 0, "none of them is documented as a non-heap node");
    TEST_EQ(report.findings.decode_failures, 0, "none of them contradicts its own metadata");
    TEST_CHECK(report.clean);
}

// A heap node whose bClientSig [MS-PST] 2.3.1.2 reserves is a structure with no defined contents. The node
// decoded, so it is not a decode failure; the reader still says it did not read it.
void test_a_reserved_client_sig_is_unsupported_not_failed() {
    const LtpReadReport report = read_fixture(
        {{9, ltp::kNidTypeNormalFolder, ltp::kNidRootFolder, false,
          heap_node(0x8C, 0x20, {bth_header(2, 6, 0)})}}, // 0x8C: reserved2 in 2.3.1.2
        "ltp_findings_reserved.bin");

    TEST_EQ(report.findings.unsupported, 1, "one heap node whose heap nothing defines");
    TEST_EQ(report.findings.decode_failures, 0, "the node itself decoded");
    TEST_EQ(report.heap.heap_nodes_ok, 1, "and is counted as a decoded heap node");
    TEST_EQ(report.pcs.contexts, 0, "it was not read as a PC");
    TEST_EQ(report.tcs.contexts, 0, "or as a TC");
    TEST_CHECK(report.clean);
    if (!report.findings.items.empty()) {
        TEST_STR(report.findings.items[0].field, "HNHDR.bClientSig", "the finding names the field");
        TEST_STR(ltp::ltp_finding_kind_name(report.findings.items[0].kind), "unsupported structure",
                 "class name");
    }
}

// The two classes that DO contradict the file: a nidType the [MS-PST] 2.2.2.1 table announces as a PC or a
// TC, and a predefined internal NID the spec itself calls a Property Context ([MS-PST] 2.4.3).
void test_a_promised_heap_node_that_is_not_one_is_a_failure() {
    const std::vector<uint8_t> nids = nid_array({0x223, 0x243});
    {
        const LtpReadReport report =
            read_fixture({{0x100, ltp::kNidTypeNormalMessage, ltp::kNidRootFolder, false, nids}},
                         "ltp_findings_message.bin");
        TEST_CHECK(!report.clean);
        TEST_EQ(report.findings.decode_failures, 1, "NID_TYPE_NORMAL_MESSAGE is announced as a PC");
        TEST_EQ(report.findings.unsupported, 0, "so it is not filed as unknown");
    }
    {
        const LtpReadReport report =
            read_fixture({{1, ltp::kNidTypeInternal, 0, false, nids}}, "ltp_findings_store.bin"); // 0x21
        TEST_CHECK(!report.clean);
        TEST_EQ(report.findings.decode_failures, 1, "[MS-PST] 2.4.3 says the message store is a PC");
        TEST_EQ(report.findings.documented_non_heap, 0, "and 2.4.8 does not name it as an array or queue");
    }
}

// C1: a Property Context whose own BTH contradicts what bClientSig announced is a statement about that
// node. Counting it only in pcs.failed is what let a file with an unreadable Property Context still read
// clean, because no caller looked at that counter -- the census has to record the finding too.
void test_a_property_context_that_contradicts_its_header_is_a_finding() {
    const LtpReadReport report = read_fixture(
        {{0x100, ltp::kNidTypeNormalMessage, ltp::kNidRootFolder, false,
          heap_node(ltp::kClientSigPc, 0x20, {bth_header(4, 4, 0)})}}, // a PC BTH is cbKey 2 / cbEnt 6
        "ltp_findings_bad_pc.bin");

    TEST_CHECK(!report.clean);
    TEST_EQ(report.pcs.contexts, 1, "the census opened it as the Property Context its nidType announces");
    TEST_EQ(report.pcs.failed, 1, "and the read failed");
    TEST_EQ(report.findings.decode_failures, 1, "the failure is itemized as a finding about that node");
    TEST_EQ(report.findings.unsupported, 0, "not filed as something unknown");
    TEST_EQ(report.findings.documented_non_heap, 0, "not excused as documented");
    if (!report.findings.items.empty()) {
        TEST_EQ(report.findings.items[0].nid, ltp::make_nid(0x100, ltp::kNidTypeNormalMessage),
                "the finding names the node");
        TEST_STR(report.findings.items[0].field, "BTHHEADER.cbKey", "the finding names the field");
        TEST_STR(ltp::ltp_finding_kind_name(report.findings.items[0].kind), "decode failure", "class name");
    }
}

// The itemized list is capped so a big mailbox stays printable, while the counts stay complete.
void test_the_itemized_list_is_capped_and_the_counts_are_not() {
    LtpFindingTally tally;
    tally.max_items = 3;
    for (uint64_t index = 0; index < 5; ++index) {
        tally.record(LtpFindingKind::kUnsupportedStructure, index, index, "HNHDR.bClientSig", "reserved");
    }
    tally.record(LtpFindingKind::kDecodeFailure, 9, 9, "HNPAGEMAP.rgibAlloc", "past the block");
    TEST_EQ(tally.total, 6, "every finding is counted");
    TEST_EQ(tally.unsupported, 5, "per class");
    TEST_EQ(tally.decode_failures, 1, "per class");
    TEST_EQ(tally.items.size(), 3, "only the cap is itemized");
}

// The classifier alone, without a file: the same three questions the report answers.
void test_classification() {
    using ltp::make_nid;
    TEST_EQ(classify_missing_heap_node(make_nid(16, ltp::kNidTypeInternal)),
            LtpFindingKind::kDocumentedNonHeapNode, "NID_SEARCH_ACTIVITY_LIST 0x201");
    TEST_EQ(classify_missing_heap_node(make_nid(19, ltp::kNidTypeInternal)),
            LtpFindingKind::kDocumentedNonHeapNode, "NID_SEARCH_DOMAIN_OBJECT 0x261");
    TEST_EQ(classify_missing_heap_node(make_nid(15, ltp::kNidTypeInternal)),
            LtpFindingKind::kDocumentedNonHeapNode, "NID_SEARCH_MANAGEMENT_QUEUE 0x1E1");
    TEST_EQ(classify_missing_heap_node(make_nid(20, ltp::kNidTypeInternal)),
            LtpFindingKind::kDocumentedNonHeapNode, "NID_SEARCH_GATHERER_QUEUE 0x281");
    TEST_EQ(classify_missing_heap_node(make_nid(21, ltp::kNidTypeInternal)),
            LtpFindingKind::kDocumentedNonHeapNode, "NID_SEARCH_GATHERER_DESCRIPTOR 0x2A1");
    TEST_EQ(classify_missing_heap_node(make_nid(25, ltp::kNidTypeInternal)),
            LtpFindingKind::kDocumentedNonHeapNode, "NID_SEARCH_GATHERER_FOLDER_QUEUE 0x321");
    TEST_EQ(classify_missing_heap_node(make_nid(18, ltp::kNidTypeInternal)),
            LtpFindingKind::kUnsupportedStructure, "NID_RESERVED1 0x241 has no defined structure");
    TEST_EQ(classify_missing_heap_node(make_nid(119, ltp::kNidTypeInternal)),
            LtpFindingKind::kUnsupportedStructure, "an internal nidIndex 2.4.1 does not name");
    TEST_EQ(classify_missing_heap_node(make_nid(1026, ltp::kNidTypeContentsTableIndex)),
            LtpFindingKind::kUnsupportedStructure, "nidType 0x0A is not announced as a TC");
    TEST_EQ(classify_missing_heap_node(make_nid(16391, ltp::kNidTypeSearchTableIndex)),
            LtpFindingKind::kUnsupportedStructure, "nidType 0x13 is not announced as a TC");
    TEST_EQ(classify_missing_heap_node(make_nid(9, ltp::kNidTypeReceiveFolderTable)),
            LtpFindingKind::kUnsupportedStructure, "nidType 0x0B is named but never marked a PC or a TC");
    TEST_EQ(classify_missing_heap_node(make_nid(9, ltp::kNidTypeOutgoingQueueTable)),
            LtpFindingKind::kUnsupportedStructure, "nidType 0x0C is named but never marked a PC or a TC");
    TEST_EQ(classify_missing_heap_node(make_nid(1, ltp::kNidTypeInternal)), LtpFindingKind::kDecodeFailure,
            "NID_MESSAGE_STORE 0x21: [MS-PST] 2.4.3 says it is a PC");
    TEST_EQ(classify_missing_heap_node(make_nid(3, ltp::kNidTypeInternal)), LtpFindingKind::kDecodeFailure,
            "NID_NAME_TO_ID_MAP 0x61: [MS-PST] 2.4.7 says it is a PC");
    TEST_EQ(classify_missing_heap_node(make_nid(9, ltp::kNidTypeNormalFolder)),
            LtpFindingKind::kDecodeFailure, "NID_TYPE_NORMAL_FOLDER is announced as a PC");
    TEST_EQ(classify_missing_heap_node(make_nid(9, ltp::kNidTypeHierarchyTable)),
            LtpFindingKind::kDecodeFailure, "NID_TYPE_HIERARCHY_TABLE is announced as a TC");
    TEST_EQ(classify_missing_heap_node(make_nid(9, ltp::kNidTypeContentsTable)),
            LtpFindingKind::kDecodeFailure, "NID_TYPE_CONTENTS_TABLE is announced as a TC");

    TEST_STR(ltp::predefined_internal_nid_name(0x201), "NID_SEARCH_ACTIVITY_LIST", "2.4.1 name");
    TEST_STR(ltp::predefined_internal_nid_name(0x241), "NID_RESERVED1", "2.4.1 name");
    TEST_STR(ltp::predefined_internal_nid_name(0xEE1), "", "2.4.1 names no such nidIndex");
    TEST_STR(ltp::documented_non_heap_internal_nid_name(0x2A1), "NID_SEARCH_GATHERER_DESCRIPTOR",
             "2.4.8.5.2 name");
    TEST_STR(ltp::documented_non_heap_internal_nid_name(0x21), "", "the message store is not an array node");
    TEST_STR(ltp::documented_heap_internal_nid_name(0x21), "NID_MESSAGE_STORE", "2.4.3 name");
    TEST_STR(ltp::documented_heap_internal_nid_name(0x201), "", "the SAL is not a PC");
}

} // namespace

int main() {
    test_classification();
    test_the_itemized_list_is_capped_and_the_counts_are_not();
    test_a_read_node_is_not_a_finding();
    test_a_page_map_past_the_block_is_a_decode_failure();
    test_documented_non_heap_nodes_are_itemized_not_failed();
    test_unknown_nodes_are_reported_as_unsupported();
    test_a_reserved_client_sig_is_unsupported_not_failed();
    test_a_promised_heap_node_that_is_not_one_is_a_failure();
    test_a_property_context_that_contradicts_its_header_is_a_finding();
    return ost2pst::test::finish("ltp_findings_test");
}
