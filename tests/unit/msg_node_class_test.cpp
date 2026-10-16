// M3 has to say, for every nidType the source contains, what the converter intends to do with it. This file
// pins that answer to the two documents this project has actually opened: [MS-PST] 2.2.2.1's nidType table
// (docs/reference/ms-pst.txt:876-907) and the libpff notes' node-identifier table
// (libpff format notes (see THIRD_PARTY_NOTICES.txt):845-893). A value neither table has a row for stays unknown, and a
// label the libpff notes mark Unknown is carried through as Unknown instead of being renamed. Nothing is
// called OST-only: a table being silent about a value is not evidence a PST lacks it.
#include <cstdint>
#include <string>

#include "ost2pst/ltp/layout.h"
#include "ost2pst/msg/node_class.h"
#include "test_support.h"

namespace {

using namespace ost2pst;
using msg::classify_nid_type;
using msg::NodeClass;
using msg::NodeDisposition;

constexpr int kCarried = static_cast<int>(NodeDisposition::kCarried);
constexpr int kUnknown = static_cast<int>(NodeDisposition::kUnknown);

// What each of the two opened tables says, transcribed row by row. `ms_pst` is false where [MS-PST] 2.2.2.1
// has no row at all; `libpff` is false where the libpff notes have no row.
struct Expected {
    uint32_t nid_type;
    int disposition;
    bool ms_pst;
    bool libpff;
};

const Expected kExpected[] = {
    {0x00, kCarried, true, true},
    {0x01, kCarried, true, true},
    {0x02, kCarried, true, true},
    {0x03, kCarried, true, true},
    {0x04, kCarried, true, true},
    {0x05, kCarried, true, true},
    {0x06, kCarried, true, true},
    {0x07, kCarried, true, true},
    {0x08, kCarried, true, true},
    {0x09, kUnknown, false, false}, // a gap in both tables
    {0x0A, kUnknown, true, true},   // named "Internal, persisted view-related", no structure defined
    {0x0B, kCarried, true, true},
    {0x0C, kCarried, true, true},
    {0x0D, kCarried, true, true},
    {0x0E, kCarried, true, true},
    {0x0F, kCarried, true, true},
    {0x10, kCarried, true, true},
    {0x11, kCarried, true, true},
    {0x12, kCarried, true, true},
    {0x13, kUnknown, true, true}, // as 0x0A
    {0x14, kUnknown, false, true}, // no [MS-PST] row, libpff says Unknown: unknown, not dropped
    {0x15, kUnknown, false, true},
    {0x16, kUnknown, false, true},
    {0x17, kUnknown, false, true},
    {0x18, kUnknown, false, true},
    {0x19, kUnknown, false, false},
    {0x1A, kUnknown, false, false},
    {0x1B, kUnknown, false, false},
    {0x1C, kUnknown, false, false},
    {0x1D, kUnknown, false, false},
    {0x1E, kUnknown, false, false},
    {0x1F, kCarried, true, true},
};

// Every value a NID's low 5 bits can hold gets an answer, and the answer matches the tables.
void test_every_nid_type_value() {
    for (uint32_t value = 0; value <= 0x1F; ++value) {
        const Expected &want = kExpected[value];
        const NodeClass got = classify_nid_type(value);
        const std::string label = "nidType " + std::to_string(value);
        TEST_EQ(got.nid_type, value, (label + " echoes the value").c_str());
        TEST_EQ(static_cast<int>(got.disposition), want.disposition, (label + " disposition").c_str());
        TEST_STR(msg::node_disposition_name(got.disposition),
                 want.disposition == kCarried ? "carried" : "unknown",
                 (label + " disposition name").c_str());
        TEST_EQ(got.ms_pst_name[0] != '\0', want.ms_pst, (label + " has an [MS-PST] row").c_str());
        TEST_EQ(got.libpff_label[0] != '\0', want.libpff, (label + " has a libpff row").c_str());
        TEST_CHECK(got.reason[0] != '\0');
    }
}

// "carried" is a claim about [MS-PST], so every carried type has to point at a section of it, and the name
// has to be the friendly name that table's row carries.
void test_carried_types_cite_an_opened_section() {
    for (uint32_t value = 0; value <= 0x1F; ++value) {
        const NodeClass got = classify_nid_type(value);
        if (got.disposition != NodeDisposition::kCarried) {
            continue;
        }
        const std::string label = "carried nidType " + std::to_string(value);
        TEST_CHECK(std::string(got.ms_pst_name).rfind("NID_TYPE_", 0) == 0);
        TEST_CHECK(std::string(got.reason).find("[MS-PST]") != std::string::npos);
        TEST_CHECK(std::string(got.reason).find("2.") != std::string::npos);
        TEST_CHECK(!std::string(got.libpff_label).empty());
    }
    // The two carried types the opened sources name but define no layout for are carried without a claim.
    const NodeClass inbox = classify_nid_type(0x0B);
    TEST_STR(inbox.ms_pst_name, "NID_TYPE_RECEIVE_FOLDER_TABLE", "0x0B friendly name");
    TEST_CHECK(std::string(inbox.reason).find("define no further structure") != std::string::npos);
    TEST_STR(inbox.libpff_label, "Inbox item (or received folder table)", "0x0B libpff label");
}

// 0x14 .. 0x18 are the values the sample carries (132 of them) that [MS-PST] 2.2.2.1 has no row for. Silence
// is not evidence a PST lacks them: the libpff notes label each one Unknown and describe real Outlook tables
// under the same identifiers, so they stay unknown, the label stays libpff's, and the reason has to say why
// nothing here discards them.
void test_types_with_no_ms_pst_row_stay_unknown() {
    const char *labels[] = {
        "Unknown (Related + 18 folder item) (Consists of a 8c table)",
        "Unknown (Related + 19 folder item) (Consists of a 8c table)",
        "Unknown (Unknown 1718 sub item) (Consists of a 7c table)",
        "Unknown (Unknown 1751 sub item)",
        "Unknown (Unknown 1784 sub item)",
    };
    for (uint32_t value = 0x14; value <= 0x18; ++value) {
        const NodeClass got = classify_nid_type(value);
        const std::string label = "nidType " + std::to_string(value);
        TEST_EQ(static_cast<int>(got.disposition), kUnknown, (label + " disposition").c_str());
        TEST_STR(msg::node_disposition_name(got.disposition), "unknown",
                 (label + " is not reported as dropped").c_str());
        TEST_STR(got.ms_pst_name, "", (label + " has no [MS-PST] name").c_str());
        TEST_STR(got.libpff_label, labels[value - 0x14], (label + " libpff label, verbatim").c_str());
        TEST_CHECK(std::string(got.reason).find("2.2.2.1") != std::string::npos);
        TEST_CHECK(std::string(got.reason).find("no row") != std::string::npos);
        TEST_CHECK(std::string(got.reason).find("pff-format.asciidoc") != std::string::npos);
        TEST_CHECK(std::string(got.reason).find("may be dropped") != std::string::npos);
    }
}

// 0x0A and 0x13 are named by [MS-PST] yet no opened section says what such a node holds, and the libpff
// notes call both Unknown. Naming a thing is not understanding it, so they are neither carried nor dropped.
void test_named_but_undefined_types_stay_unknown() {
    for (uint32_t value : {0x0A, 0x13}) {
        const NodeClass got = classify_nid_type(value);
        const std::string label = "nidType " + std::to_string(value);
        TEST_EQ(static_cast<int>(got.disposition), kUnknown, (label + " disposition").c_str());
        TEST_CHECK(std::string(got.ms_pst_name).rfind("NID_TYPE_", 0) == 0);
        TEST_STR(got.libpff_label, "Unknown (Internal, Persisted View- related)",
                 (label + " libpff keeps saying Unknown").c_str());
        TEST_CHECK(std::string(got.reason).find("Internal, persisted view-related") != std::string::npos);
        TEST_CHECK(std::string(got.reason).find("no section in the opened sources") != std::string::npos);
    }
}

// A value neither table has a row for cannot be claimed either way. The sample carries 0x19 and 0x1B, so
// the report has to be able to say "neither source names this" rather than pick a side.
void test_values_neither_source_names() {
    for (uint32_t value : {0x09, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E}) {
        const NodeClass got = classify_nid_type(value);
        const std::string label = "nidType " + std::to_string(value);
        TEST_EQ(static_cast<int>(got.disposition), kUnknown, (label + " disposition").c_str());
        TEST_STR(got.ms_pst_name, "", (label + " has no [MS-PST] name").c_str());
        TEST_STR(got.libpff_label, "", (label + " has no libpff label").c_str());
        TEST_CHECK(std::string(got.reason).find("neither") != std::string::npos);
    }
    // A value outside the 5 bits a nidType occupies is not a node type at all.
    const NodeClass out_of_range = classify_nid_type(0x20);
    TEST_EQ(static_cast<int>(out_of_range.disposition), kUnknown, "0x20 is not a nidType");
    TEST_STR(out_of_range.ms_pst_name, "", "0x20 names nothing");
}

// The LTP layer already names the types it decodes; msg must not disagree with the constants it reads them
// through, or the inventory would classify a node differently from the reader that opened it.
void test_layout_constants_and_the_classifier_agree() {
    const uint32_t carried[] = {
        ltp::kNidTypeHid,                 ltp::kNidTypeInternal,
        ltp::kNidTypeNormalFolder,        ltp::kNidTypeSearchFolder,
        ltp::kNidTypeNormalMessage,       ltp::kNidTypeAttachment,
        ltp::kNidTypeSearchUpdateQueue,   ltp::kNidTypeSearchCriteriaObject,
        ltp::kNidTypeAssocMessage,        ltp::kNidTypeReceiveFolderTable,
        ltp::kNidTypeOutgoingQueueTable,  ltp::kNidTypeHierarchyTable,
        ltp::kNidTypeContentsTable,       ltp::kNidTypeAssocContentsTable,
        ltp::kNidTypeSearchContentsTable, ltp::kNidTypeAttachmentTable,
        ltp::kNidTypeRecipientTable,      ltp::kNidTypeLtp,
    };
    for (uint32_t value : carried) {
        TEST_EQ(static_cast<int>(classify_nid_type(value).disposition), kCarried,
                ("ltp constant " + std::to_string(value) + " is carried").c_str());
    }
    const uint32_t unknown[] = {ltp::kNidTypeContentsTableIndex, ltp::kNidTypeSearchTableIndex};
    for (uint32_t value : unknown) {
        TEST_EQ(static_cast<int>(classify_nid_type(value).disposition), kUnknown,
                ("ltp constant " + std::to_string(value) + " is unknown").c_str());
    }
}

// The classification is a property of the type, not of the NID it appears under, and it is stable: the
// inventory counts the same value across 11,806 nodes.
void test_classification_is_stable() {
    const NodeClass first =
        classify_nid_type(static_cast<uint32_t>(ltp::nid_type(ltp::make_nid(1051, ltp::kNidTypeNormalFolder))));
    const NodeClass again = classify_nid_type(ltp::kNidTypeNormalFolder);
    TEST_EQ(static_cast<int>(first.disposition), static_cast<int>(again.disposition), "same disposition");
    TEST_STR(first.ms_pst_name, again.ms_pst_name, "same name");
    TEST_EQ(static_cast<int>(classify_nid_type(0x04).disposition), kCarried, "a message is carried");
    TEST_EQ(static_cast<int>(classify_nid_type(0x15).disposition), kUnknown,
            "an OST 8c table is neither claimed as carried nor discarded");
}

} // namespace

int main() {
    test_every_nid_type_value();
    test_carried_types_cite_an_opened_section();
    test_types_with_no_ms_pst_row_stay_unknown();
    test_named_but_undefined_types_stay_unknown();
    test_values_neither_source_names();
    test_layout_constants_and_the_classifier_agree();
    test_classification_is_stable();
    return ost2pst::test::finish("msg_node_class_test");
}
