// The inventory is what the converter will write from, so it is checked against a mailbox built here, where
// every number is known before the code runs. The fixture is one folder, five Message objects and one FAI
// entry, each shaped to exercise one thing the completeness report has to be able to say: a message with no
// body form, a message with no subnode at all, a message whose subnode block cannot be read, an attachment
// with no size record at all, an attachment subnode no Attachment Table row names, and an Attachment
// Table row that names a subnode that is not there.
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "ost2pst/ltp/block_heap.h"
#include "ost2pst/ltp/bth.h"
#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/ltp_read.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/ltp/pc.h"
#include "ost2pst/ltp/tc.h"
#include "ost2pst/msg/inventory.h"
#include "ost2pst/msg/node_class.h"
#include "ost2pst/ndb/btree.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"
#include "test_support.h"

namespace {

using namespace ost2pst;
using ltp::BlockSource;
using ltp::LtpFolder;
using ltp::LtpReadReport;
using ltp::NidMap;
using msg::AttachmentStats;
using msg::build_inventory;
using msg::InventoryOptions;
using msg::InventoryReport;
using msg::NodeDisposition;
using ndb::FileProfile;
using ndb::NbtEntry;
using util::ByteView;
using util::ErrorKind;
using util::make_error;
using util::Result;

constexpr FileProfile kProfile = FileProfile::kOst;

void put16(std::vector<uint8_t> &bytes, uint16_t value) {
    bytes.push_back(static_cast<uint8_t>(value & 0xFF));
    bytes.push_back(static_cast<uint8_t>(value >> 8));
}

void put32(std::vector<uint8_t> &bytes, uint32_t value) {
    for (int shift = 0; shift < 4; ++shift) {
        bytes.push_back(static_cast<uint8_t>((value >> (8 * shift)) & 0xFF));
    }
}

void put64(std::vector<uint8_t> &bytes, uint64_t value) {
    for (int shift = 0; shift < 8; ++shift) {
        bytes.push_back(static_cast<uint8_t>((value >> (8 * shift)) & 0xFF));
    }
}

std::vector<uint8_t> utf16(const std::u16string &text) {
    std::vector<uint8_t> bytes;
    for (const char16_t unit : text) {
        put16(bytes, static_cast<uint16_t>(unit));
    }
    put16(bytes, 0);
    return bytes;
}

std::vector<uint8_t> make_hn(uint8_t client_sig, uint32_t hid_user_root,
                             const std::vector<std::pair<uint32_t, std::vector<uint8_t>>> &allocations) {
    const uint16_t header_size = 12; // [MS-PST] 2.3.1.2 HNHDR
    const uint16_t map_size = static_cast<uint16_t>(4 + (allocations.size() + 1) * 2); // [MS-PST] 2.3.1.5
    std::vector<uint8_t> bytes;
    put16(bytes, header_size);
    bytes.push_back(ltp::kHnSignature);
    bytes.push_back(client_sig);
    put32(bytes, hid_user_root);
    put32(bytes, 0);
    put16(bytes, static_cast<uint16_t>(allocations.size()));
    put16(bytes, 0);
    uint16_t at = static_cast<uint16_t>(header_size + map_size);
    for (const auto &item : allocations) {
        put16(bytes, at);
        at = static_cast<uint16_t>(at + item.second.size());
    }
    put16(bytes, at);
    for (const auto &item : allocations) {
        bytes.insert(bytes.end(), item.second.begin(), item.second.end());
    }
    return bytes;
}

std::vector<uint8_t> bth_header(uint8_t cb_key, uint8_t cb_ent, uint32_t hid_root) {
    std::vector<uint8_t> bytes;
    bytes.push_back(ltp::kBthType);
    bytes.push_back(cb_key);
    bytes.push_back(cb_ent);
    bytes.push_back(0);
    put32(bytes, hid_root);
    return bytes;
}

std::vector<uint8_t> pc_records(const std::vector<std::tuple<int, int, uint32_t>> &records) {
    std::vector<uint8_t> bytes;
    for (const auto &record : records) {
        put16(bytes, static_cast<uint16_t>(std::get<0>(record)));
        put16(bytes, static_cast<uint16_t>(std::get<1>(record)));
        put32(bytes, std::get<2>(record));
    }
    return bytes;
}

std::vector<uint8_t> pc_block(const std::vector<std::tuple<int, int, uint32_t>> &records,
                              const std::u16string &heap_value) {
    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> allocations;
    allocations.emplace_back(0x20, bth_header(2, 6, 0x40));
    allocations.emplace_back(0x40, pc_records(records));
    if (!heap_value.empty()) {
        allocations.emplace_back(0x60, utf16(heap_value));
    }
    return make_hn(ltp::kClientSigPc, 0x20, allocations);
}

// A table context in the shape every real one has: rgib 12/14/15/16, PidTagLtpRowId at ibData 0 iBit 0 and
// PidTagLtpRowVer at ibData 4 iBit 1 ([MS-PST] 2.3.4.1 / 2.3.4.4.1), with the RowIndex BTH ([MS-PST]
// 2.3.4.3.1) holding one TCROWID per row.
std::vector<uint8_t> tc_block(const std::vector<uint32_t> &row_ids) {
    std::vector<uint8_t> header;
    header.push_back(ltp::kClientSigTc);
    header.push_back(4);
    put16(header, 12);
    put16(header, 14);
    put16(header, 15);
    put16(header, 16);
    put32(header, 0x40); // hidRowIndex
    put32(header, 0);    // hnidRows
    put32(header, 0);
    const auto column = [&](uint32_t tag, uint16_t ib_data, uint8_t cb_data, uint8_t i_bit) {
        put32(header, tag);
        put16(header, ib_data);
        header.push_back(cb_data);
        header.push_back(i_bit);
    };
    column(0x6619001F, 8, 4, 2);
    column(0x66740002, 12, 2, 3);
    column(0x67F20003, 0, 4, 0);
    column(0x67F30003, 4, 4, 1);

    std::vector<uint8_t> rows;
    uint32_t index = 0;
    for (uint32_t row_id : row_ids) {
        put32(rows, row_id);
        put32(rows, index++);
    }
    return make_hn(ltp::kClientSigTc, 0x20, {
        {0x20, header},
        {0x40, bth_header(4, 4, row_ids.empty() ? 0 : 0x60)},
        {0x60, rows},
    });
}

// An SLBLOCK ([MS-PST] 2.2.2.8.3.3.1.2): bType 0x02, cLevel 0, cEnt, dwPadding 0, then one SLENTRY each.
std::vector<uint8_t> sl_block(const std::vector<std::tuple<uint64_t, uint64_t, uint64_t>> &entries) {
    std::vector<uint8_t> bytes;
    bytes.push_back(0x02);
    bytes.push_back(0);
    put16(bytes, static_cast<uint16_t>(entries.size()));
    put32(bytes, 0);
    for (const auto &entry : entries) {
        put64(bytes, std::get<0>(entry));
        put64(bytes, std::get<1>(entry));
        put64(bytes, std::get<2>(entry));
    }
    return bytes;
}

class FakeBlocks : public BlockSource {
public:
    void add(uint64_t bid, const std::vector<uint8_t> &bytes) { blocks_[bid] = bytes; }

    // [MS-PST] 2.2.2.8.3 says SLBLOCK and SIBLOCK are Internal blocks, so a subnode BTree has to be indexed
    // with bit B set ([MS-PST] 2.2.2.2) or the reader reports the index contradicting the block.
    void add_internal(uint64_t bid, const std::vector<uint8_t> &bytes) {
        blocks_[bid] = bytes;
        internal_.insert(bid);
    }

    Result<ltp::BlockBytes> block(uint64_t bid) override {
        const auto found = blocks_.find(bid);
        if (found == blocks_.end()) {
            return make_error(ErrorKind::kUnsupported, "BBTENTRY.bid", 0, bid, "this test has no such block");
        }
        return ltp::BlockBytes{ByteView(found->second.data(), found->second.size(), bid * 512),
                               internal_.count(bid) != 0, false};
    }

private:
    std::map<uint64_t, std::vector<uint8_t>> blocks_;
    std::set<uint64_t> internal_;
};

// The fixture's NIDs. A Folder object is one PC and three tables under one nidIndex ([MS-PST] 2.4.4.3); a
// Message object's nidParent is that PC's NID ([MS-PST] 2.4.5.2); the tables inside a message hang under
// the internal NIDs [MS-PST] 2.4.6.1.1 and 2.4.5.3.1 name.
constexpr uint64_t kFolderNid = 0x122;      // nidIndex 9, NID_TYPE_NORMAL_FOLDER
constexpr uint64_t kMessageA = 0x2004;      // nidIndex 0x100
constexpr uint64_t kMessageB = 0x2024;
constexpr uint64_t kMessageC = 0x2044;
constexpr uint64_t kMessageD = 0x2064;
constexpr uint64_t kFaiE = 0x2088;          // nidIndex 0x104, NID_TYPE_ASSOC_MESSAGE
constexpr uint64_t kAttachmentA = 0x2005;   // nidIndex 0x100, NID_TYPE_ATTACHMENT
constexpr uint64_t kAttachmentB = 0x2025;   // ... the one whose 0x0E20 is present but empty
constexpr uint64_t kAttachmentC = 0x2065;   // ... the one no Attachment Table row names
constexpr uint64_t kRecipientRow = 0x2045;
constexpr uint64_t kMessageE = 0x20A4;      // subnodes, but no Recipient Table among them
constexpr uint64_t kAttachmentE = 0x20A5;
// C3: an attached message and the attachment it holds. Neither has an NBT entry -- [MS-PST] 2.4.6.2.2 says
// an attached message is the subnode a 0x3701 PtypObject names, "not located in the NBT", and its own
// attachment hangs under that message's Attachment Table.
constexpr uint64_t kAttachedMessage = 0x2085;    // the subnode of attachment A that holds the object
constexpr uint64_t kAttachedAttachment = 0x20C5; // ... and one of that message's own attachments

void add_node(NidMap &nodes, uint64_t index, uint32_t nid_type, uint64_t bid_data, uint64_t bid_sub,
              uint64_t parent) {
    nodes.add(NbtEntry{ltp::make_nid(index, nid_type), bid_data, bid_sub, static_cast<uint32_t>(parent)});
}

struct Fixture {
    ltp::LtpReadReport census;
    FakeBlocks blocks;
};

void build_fixture(Fixture &fixture) {
    NidMap &nodes = fixture.census.nodes;
    fixture.census.profile = kProfile;

    add_node(nodes, 9, ltp::kNidTypeNormalFolder, 1, 0, 0);
    add_node(nodes, 9, ltp::kNidTypeHierarchyTable, 2, 0, kFolderNid);
    add_node(nodes, 9, ltp::kNidTypeContentsTable, 3, 0, kFolderNid);
    add_node(nodes, 9, ltp::kNidTypeAssocContentsTable, 4, 0, kFolderNid);
    add_node(nodes, 0x100, ltp::kNidTypeNormalMessage, 10, 14, kFolderNid);
    add_node(nodes, 0x101, ltp::kNidTypeNormalMessage, 15, 16, kFolderNid);
    add_node(nodes, 0x102, ltp::kNidTypeNormalMessage, 0, 0, kFolderNid);   // no data block at all
    add_node(nodes, 0x103, ltp::kNidTypeNormalMessage, 20, 21, kFolderNid); // bidSub names a missing block
    add_node(nodes, 0x104, ltp::kNidTypeAssocMessage, 17, 0, kFolderNid);   // a FAI entry with no subnode
    add_node(nodes, 0x105, ltp::kNidTypeNormalMessage, 22, 23, kFolderNid); // subnodes, none of them a Recipient Table
    add_node(nodes, 1069, 0x14, 0, 0, kFolderNid); // a nidType [MS-PST] 2.2.2.1 has no row for
    add_node(nodes, 1026, ltp::kNidTypeContentsTableIndex, 0, 0, kFolderNid); // named, structure undefined

    // Message A: a body, an Attachment Table with three rows, a Recipient Table, and two Attachment objects.
    fixture.blocks.add(10, pc_block({{0x001A, 0x001F, 0x60}, {0x1000, 0x001F, 0x60}, {0x0E07, 0x0003, 1}},
                                    u"body"));
    fixture.blocks.add(14, sl_block({{0x671, 11, 0}, {0x692, 12, 0}, {kAttachmentA, 13, 0},
                                     {kAttachmentB, 18, 0}}));
    fixture.blocks.add(11, tc_block({kAttachmentA, kAttachmentB, 0x2085})); // 0x2085 names no subnode
    fixture.blocks.add(12, tc_block({kRecipientRow}));
    fixture.blocks.add(13, pc_block({{0x0E20, 0x0003, 707}, {0x3001, 0x001F, 0x60}, {0x3704, 0x001F, 0x60},
                                     {0x3705, 0x0003, 1}, {0x370B, 0x0003, 0}},
                                    u"note.pdf"));
    // The second attachment: no 0x0E20 record at all, which is [MS-PST] 2.4.6.2.1's MUST not being met.
    fixture.blocks.add(18, pc_block({{0x3001, 0x001F, 0x60}, {0x3704, 0x001F, 0x60}, {0x3705, 0x0003, 1},
                                     {0x370B, 0x0003, 0}},
                                    u"logo.png"));

    // Message B: no body form, a Recipient Table, and an Attachment object no Attachment Table row names.
    fixture.blocks.add(15, pc_block({{0x001A, 0x001F, 0x60}, {0x0037, 0x001F, 0x60}}, u"subject"));
    fixture.blocks.add(16, sl_block({{0x692, 12, 0}, {kAttachmentC, 13, 0}}));

    // Message D: a readable PC, and a bidSub that names a block the source does not have.
    fixture.blocks.add(20, pc_block({{0x1000, 0x001F, 0x60}}, u"body"));

    // Message E: an Attachment Table and an Attachment object, but no Recipient Table subnode at all.
    // [MS-PST] 2.4.5 marks the Recipient Table Required: Y, so this message is a completeness finding even
    // though its subnode BTree reads fine.
    fixture.blocks.add(22, pc_block({{0x001A, 0x001F, 0x60}, {0x1000, 0x001F, 0x60}}, u"E body"));
    fixture.blocks.add(23, sl_block({{0x671, 24, 0}, {kAttachmentE, 25, 0}}));
    fixture.blocks.add(24, tc_block({kAttachmentE}));
    fixture.blocks.add(25, pc_block({{0x0E20, 0x0003, 100}, {0x3001, 0x001F, 0x60}, {0x3704, 0x001F, 0x60},
                                     {0x3705, 0x0003, 1}, {0x370B, 0x0003, 0}},
                                    u"spread.xlsx"));

    // The FAI entry: a PC with no body form and no subnode.
    fixture.blocks.add(17, pc_block({{0x001A, 0x001F, 0x60}}, u"IPM.Note"));

    LtpFolder folder;
    folder.nid = kFolderNid;
    folder.parent = 0;
    folder.depth = 0;
    folder.name = "Inbox";
    folder.name_present = true;
    folder.children = 0;
    folder.messages = 5;
    folder.associated = 1;
    folder.parent_messages = 5;
    folder.parent_associated = 1;
    folder.has_pc = true;
    fixture.census.folders.push_back(folder);
}

InventoryReport run(const InventoryOptions &options = {}) {
    Fixture fixture;
    build_fixture(fixture);
    Result<InventoryReport> built = build_inventory(fixture.census, fixture.blocks, options);
    if (!built.ok()) {
        ost2pst::test::report_failure(__FILE__, __LINE__,
                                      "build_inventory failed: " + util::format_error(built.error()));
        return {};
    }
    return built.take();
}

// The same fixture with one thing broken, so a test can name which counter moved instead of guessing from a
// report that differs in a dozen places.
InventoryReport run_with(const std::function<void(Fixture &)> &change, const InventoryOptions &options = {}) {
    Fixture fixture;
    build_fixture(fixture);
    change(fixture);
    Result<InventoryReport> built = build_inventory(fixture.census, fixture.blocks, options);
    if (!built.ok()) {
        ost2pst::test::report_failure(__FILE__, __LINE__,
                                      "build_inventory failed: " + util::format_error(built.error()));
        return {};
    }
    return built.take();
}

// Every nidType the fixture carries gets a line, classified against the two opened sources. A type that
// only ever appears as a subnode (0x05, 0x11, 0x12) has no NBT entry, and the report says so instead of
// pretending the two populations are the same.
void test_census_classifies_every_type() {
    const InventoryReport report = run();
    TEST_EQ(report.nid_entries, 12, "every NBT entry is counted");

    // Eight nidTypes come out of the NBT and three more only out of a bidSub, so the census has eleven lines.
    TEST_EQ(report.node_types.size(), 11, "one line per nidType the fixture carries");
    const msg::NodeClassCount &message = report.node_types.at(ltp::kNidTypeNormalMessage);
    TEST_EQ(static_cast<int>(message.disposition), static_cast<int>(NodeDisposition::kCarried),
            "NID_TYPE_NORMAL_MESSAGE is carried");
    TEST_STR(message.ms_pst_name, "NID_TYPE_NORMAL_MESSAGE", "[MS-PST] 2.2.2.1's name");
    TEST_EQ(message.nodes, 5, "five Message objects");
    TEST_EQ(message.subnode_entries, 0, "and none of them is a subnode");

    const msg::NodeClassCount &attachment = report.node_types.at(ltp::kNidTypeAttachment);
    TEST_EQ(attachment.nodes, 0, "an Attachment object has no NBT entry in this fixture");
    TEST_EQ(attachment.subnode_entries, 4, "and four SLENTRYs name it");
    TEST_EQ(attachment.opened, 3, "three of them are named by an Attachment Table row");
    TEST_EQ(attachment.read, 3, "all three are Property Contexts");

    TEST_EQ(report.node_types.at(ltp::kNidTypeAttachmentTable).subnode_entries, 2, "two Attachment Tables");
    TEST_EQ(report.node_types.at(ltp::kNidTypeRecipientTable).subnode_entries, 2, "two Recipient Tables");

    const msg::NodeClassCount &no_row = report.node_types.at(0x14);
    TEST_EQ(static_cast<int>(no_row.disposition), static_cast<int>(NodeDisposition::kUnknown),
            "0x14 has no row in [MS-PST] 2.2.2.1, and a missing row is not a licence to drop the node");
    TEST_STR(no_row.ms_pst_name, "", "so it has no [MS-PST] name");
    TEST_CHECK(no_row.libpff_label.find("Unknown") != std::string::npos);
    TEST_EQ(no_row.nodes, 1, "and the fixture carries one");

    const msg::NodeClassCount &index = report.node_types.at(ltp::kNidTypeContentsTableIndex);
    TEST_EQ(static_cast<int>(index.disposition), static_cast<int>(NodeDisposition::kUnknown),
            "0x0A is named but undefined");
    TEST_EQ(index.opened, 0, "and the inventory does not open it");
}

void test_messages_and_attachments_are_counted() {
    const InventoryReport report = run();
    TEST_EQ(report.messages.nodes, 5, "five Message objects scanned");
    TEST_EQ(report.messages.pcs_read, 4, "three of them have a readable Property Context");
    TEST_EQ(report.messages.pcs_failed, 1, "one has no data block at all");
    TEST_EQ(report.messages.with_body, 3, "0x1000 present on A, D and E");
    TEST_EQ(report.messages.with_no_body_form, 1, "only B: C's Property Context did not read, so nothing is "
                                                  "known about what it carries");
    TEST_EQ(report.messages.pc_decode_failed, 0, "and C announced no Property Context at all, so it is not "
                                                 "a decode failure either");
    TEST_EQ(report.messages.subnode_entries, 8, "four SLENTRYs under A, two under B, two under E");
    TEST_EQ(report.messages.max_subnodes, 4, "the widest subnode BTree");
    TEST_EQ(report.messages.with_subnodes, 3, "A and B; D's bidSub names a block that is not there");
    TEST_EQ(report.messages.without_subnode, 1, "C does not");
    TEST_EQ(report.messages.recipient_tables, 2, "A and B have one");
    TEST_EQ(report.messages.recipient_tables_read, 2, "both read as Table Contexts");
    TEST_EQ(report.messages.recipient_rows, 2, "one row each");
    TEST_EQ(report.messages.without_recipient_table, 3, "C, D and E do not");

    const AttachmentStats &attachments = report.attachments;
    TEST_EQ(attachments.tables, 2, "two Attachment Tables");
    TEST_EQ(attachments.rows, 4, "with three rows");
    TEST_EQ(attachments.rows_resolved, 3, "two of which name a subnode that is there");
    TEST_EQ(attachments.rows_unresolved, 1, "and one names 0x2085, which is not");
    TEST_EQ(attachments.nodes_opened, 3, "three Attachment objects opened");
    TEST_EQ(attachments.nodes_no_pc, 0, "both Property Contexts");
    TEST_EQ(attachments.with_size, 2, "two inline 0x0E20");
    TEST_EQ(attachments.size_value_absent, 0, "an inline dwValueHnid is a value, not an empty property");
    TEST_EQ(attachments.without_size, 1, "and one attachment has no 0x0E20 record at all");
    TEST_EQ(attachments.declared_size_bytes, 807,
            "and only a readable 0x0E20 counts towards the declared total");
    TEST_EQ(attachments.with_filename, 3, "both carry 0x3704");
    TEST_EQ(attachments.with_method, 3, "both carry 0x3705");
    TEST_EQ(attachments.with_rendering, 3, "both carry 0x370B");
    TEST_EQ(attachments.subnode_entries, 4, "four Attachment objects exist as subnodes");
    TEST_EQ(attachments.subnodes_not_named, 1, "one of them no row names");

    // C2: a tag is not content. Every attachment here carries a 0x0E20 and none carries a 0x3701, so the
    // declared total is a claim about the source, never a number of bytes this reader obtained.
    TEST_EQ(report.messages.body.readable, 3, "A, D and E each have a 0x1000 whose heap value read");
    TEST_EQ(report.messages.body.not_present, 1, "B carries no body record");
    TEST_EQ(report.messages.body.unknown, 1, "C's Property Context did not read, so its body is unknown");
    TEST_EQ(report.messages.body.unreadable, 0, "nothing named a value this fixture cannot supply");
    TEST_EQ(report.messages.body.bytes_read, 34, "the utf-16 bodies of A, D and E, terminator included");
    TEST_EQ(attachments.payload.not_present, 3, "no attachment in this fixture carries a 0x3701 record");
    TEST_EQ(attachments.payload.bytes_read, 0, "so not one payload byte was read");
    TEST_EQ(attachments.declared_size_without_payload, 2, "two declare 707 and 100 bytes and hold nothing");

    TEST_EQ(report.associated.nodes, 1, "the FAI entry is scanned too");
    TEST_EQ(report.associated.without_subnode, 1, "and has no subnode");
}

// The completeness report is the part M4 has to write a PST against, so every line has to name something
// the source really does not have.
void test_completeness_reports_what_is_absent() {
    const InventoryReport report = run();
    const msg::CompletenessReport &c = report.completeness;
    TEST_EQ(c.messages_without_body_form, 2, "B and the FAI entry; C's Property Context did not read");
    TEST_EQ(c.messages_with_unreadable_property_context, 0,
            "no message announced a Property Context this fixture could not read");
    TEST_EQ(c.subnode_walks_incomplete, 0, "no subnode walk came back short");
    TEST_EQ(c.row_index_walks_failed, 0, "no RowIndex walk failed");
    TEST_EQ(c.messages_without_subnode, 2, "C and the FAI entry");
    TEST_EQ(c.messages_without_recipient_table, 4, "C, D, E and the FAI entry");
    TEST_EQ(c.attachments_without_size, 1, "the attachment with no 0x0E20 record");
    TEST_EQ(c.attachments_without_method, 0, "every attachment carries 0x3705");
    TEST_EQ(c.attachments_without_rendering, 0, "and 0x370B");
    TEST_EQ(c.attachment_rows_unresolved, 1, "one row names a subnode that is not there");
    TEST_EQ(c.attachment_subnodes_unnamed, 1, "one attachment no row names");
    TEST_EQ(c.messages_with_unreadable_body, 0, "no body record named a value this fixture cannot supply");
    TEST_EQ(c.attachments_with_unreadable_payload, 0, "and no 0x3701 record exists to fail");
    TEST_EQ(c.attachments_with_declared_size_and_no_payload, 2,
            "0x0E20 declares 707 and 100 bytes on attachments that carry no payload record at all");
    TEST_EQ(c.nodes_of_unknown_type, 2, "the 0x14 node, which [MS-PST] has no row for, and the 0x0A node,"
                                        " which it names without defining");
    TEST_EQ(c.decode_failures, 0, "nothing in the fixture contradicts its own metadata");
    TEST_CHECK(!c.notes.empty());
    TEST_CHECK(c.notes[0].find("body") != std::string::npos);
    TEST_CHECK(c.notes[2].find("2.4.5") != std::string::npos);
    TEST_CHECK(c.notes[3].find("2.4.6.2.1") != std::string::npos);
}

// A broken subnode block is a finding with a bid in it, not a reason to stop counting the message.
void test_a_broken_subnode_block_is_reported_not_fatal() {
    const InventoryReport report = run();
    TEST_EQ(report.messages.with_bad_subnodes, 1, "message D's bidSub names a missing block");
    TEST_EQ(report.messages.subnode_blocks_bad, 1, "counted as an unreadable block");
    TEST_EQ(report.completeness.blocks_unreadable, 1, "and it reaches the completeness report");
    bool named = false;
    for (const std::string &note : report.completeness.unreadable_blocks) {
        if (note.find("unreadable subnode block bid 0x") != std::string::npos) {
            named = true;
        }
    }
    TEST_CHECK(named);
    TEST_CHECK(!report.messages.subnode_failure_reasons.empty());
    TEST_EQ(report.status.blocks_unreadable, 1, "the verdict sees the block the source could not supply");
    TEST_CHECK(!report.status.clean);
    TEST_CHECK(!report.status.reasons.empty());
}

// C1: a read that failed has to reach the run's verdict, and it has to move the counter that names the
// failure rather than one that merely looks smaller. Each case breaks one thing in the fixture.
void test_a_failed_read_reaches_the_verdict() {
    {
        // A Property Context whose BTH contradicts what bClientSig announced.
        const InventoryReport report = run_with([](Fixture &fixture) {
            fixture.blocks.add(10, make_hn(ltp::kClientSigPc, 0x20, {{0x20, bth_header(4, 4, 0)}}));
        });
        TEST_EQ(report.messages.pcs_read, 3, "the other three Property Contexts still read");
        TEST_EQ(report.messages.pcs_failed, 2, "one has no data block, one contradicts its own header");
        TEST_EQ(report.messages.pc_decode_failed, 1, "only the one that announced a PC is a decode failure");
        TEST_EQ(report.completeness.messages_with_unreadable_property_context, 1,
                "and it is reported apart from messages with no body form");
        TEST_EQ(report.completeness.messages_without_body_form, 2,
                "still only B and the FAI entry: A had a body, it just could not be read");
        TEST_EQ(report.completeness.decode_failures, 1, "itemized as a decode failure");
        TEST_EQ(report.status.decode_failures, 1, "and the verdict counts it");
        TEST_CHECK(!report.status.clean);
    }
    {
        // A subnode block whose cEnt promises an entry array the block cannot hold.
        const InventoryReport report = run_with([](Fixture &fixture) {
            std::vector<uint8_t> truncated = sl_block({{0x692, 12, 0}});
            truncated.resize(8); // the 8-byte header only; the 24-byte SLENTRY is not there
            fixture.blocks.add(14, truncated);
        });
        TEST_EQ(report.messages.subnode_entries_past_block, 1, "the entry array runs past the block");
        TEST_EQ(report.messages.subnode_walks_incomplete, 1, "so that walk came back short");
        TEST_EQ(report.messages.subnode_entries, 4, "and enumerated nothing for message A");
        TEST_EQ(report.messages.with_subnodes, 2, "the other two messages still have their whole lists");
        TEST_EQ(report.completeness.subnode_walks_incomplete, 1, "and it reaches the completeness report");
        TEST_EQ(report.completeness.decode_failures, 1, "itemized as a decode failure");
        TEST_EQ(report.status.walks_incomplete, 1, "and the verdict");
        TEST_CHECK(!report.status.clean);
        bool named = false;
        for (const std::string &note : report.completeness.incomplete_walks) {
            if (note.find("incomplete subnode walk") != std::string::npos) {
                named = true;
            }
        }
        TEST_CHECK(named);
    }
    {
        // A Recipient Table whose RowIndex BTH names a heap id the node's page map does not hold.
        const InventoryReport report = run_with([](Fixture &fixture) {
            std::vector<uint8_t> table = tc_block({kRecipientRow});
            // TCINFO starts at 24: HNHDR 12 + HNPAGEMAP 4 + (3 allocations + 1) * 2.
            table[24 + ltp::kTcInfoRowIndexOffset] = 0xE0;
            table[25 + ltp::kTcInfoRowIndexOffset] = 0x7F; // hidRowIndex 0x7FE0: data block 1, this node has one
            fixture.blocks.add(12, table);
        });
        TEST_EQ(report.messages.recipient_tables_read, 2, "the tables themselves still decoded");
        TEST_EQ(report.messages.recipient_rows, 0, "and not one row was counted");
        TEST_EQ(report.messages.recipient_tables_row_index_failed, 2,
                "the two messages that share this table both report it");
        TEST_EQ(report.completeness.row_index_walks_failed, 2, "and it reaches the completeness report");
        TEST_EQ(report.status.walks_incomplete, 2, "and the verdict");
        TEST_CHECK(!report.status.clean);
    }
    {
        // A SIBLOCK chain that revisits the block it lives in.
        const InventoryReport report = run_with([](Fixture &fixture) {
            std::vector<uint8_t> cyclic;
            cyclic.push_back(0x02); // btype: a subnode block
            cyclic.push_back(1);    // cLevel 1: a SIBLOCK
            put16(cyclic, 1);       // cEnt
            put32(cyclic, 0);       // dwPadding
            put64(cyclic, 0x692);   // SIENTRY.nid
            put64(cyclic, 14);      // SIENTRY.bid: this very block
            fixture.blocks.add(14, cyclic);
        });
        TEST_EQ(report.messages.subnode_cycles, 1, "the cycle is counted, not walked to the cap");
        TEST_EQ(report.messages.subnode_walks_incomplete, 1, "and the walk is reported short");
        TEST_EQ(report.messages.subnode_entries, 4, "it enumerated nothing under message A");
        TEST_CHECK(!report.status.clean);
    }
    {
        // The same fixture with the one dangling bidSub supplied: nothing failed, so the run says clean.
        const InventoryReport report = run_with([](Fixture &fixture) {
            fixture.blocks.add(21, sl_block({{0x692, 12, 0}}));
        });
        TEST_EQ(report.status.decode_failures, 0, "no decode failure");
        TEST_EQ(report.status.logged_findings, 0, "no logged finding");
        TEST_EQ(report.status.blocks_unreadable, 0, "no unreadable block");
        TEST_EQ(report.status.walks_incomplete, 0, "no walk came back short");
        TEST_EQ(report.status.scans_capped, 0, "no cap stopped a scan");
        TEST_CHECK(report.status.clean);
        TEST_CHECK(report.status.reasons.empty());
    }
}

// Items land in the folder their nidParent chain names ([MS-PST] 2.4.5.2), which is the count that works
// when the folder's Contents Table is empty.
void test_items_are_attributed_to_their_folder() {
    const InventoryReport report = run();
    TEST_EQ(report.folders.size(), 1, "the census's folder list is the inventory's folder list");
    const msg::FolderCounts &folder = report.folders[0];
    TEST_EQ(folder.nid, kFolderNid, "Inbox");
    TEST_STR(folder.name, "Inbox", "named from the census, not re-read here");
    TEST_CHECK(folder.attributed);
    TEST_EQ(folder.messages, 5, "every message's nidParent chain reaches it");
    TEST_EQ(folder.associated, 1, "and the FAI entry's does");
    TEST_EQ(folder.attachments, 3, "the three attachments those messages resolved");
    TEST_EQ(folder.attachment_bytes, 807, "with only the readable sizes");
    TEST_EQ(folder.contents_rows, 5, "the Contents Table row count the census already measured");
}

// Named samples let the enumeration be checked item by item against an independent reader.
void test_attachment_samples_are_named() {
    const InventoryReport report = run();
    TEST_EQ(report.attachments.samples.size(), 3, "all three attachments carry a filename");
    bool found_name = false;
    bool found_size = false;
    for (const std::string &sample : report.attachments.samples) {
        if (sample.find("note.pdf") != std::string::npos) {
            found_name = true;
            found_size = sample.find("0x0E20=707") != std::string::npos;
        }
    }
    TEST_CHECK(found_name);
    TEST_CHECK(found_size);

    InventoryOptions no_samples;
    no_samples.collect_samples = false;
    TEST_EQ(run(no_samples).attachments.samples.size(), 0, "and they are optional");
}

// C2: "the source has no body" and "this reader could not get the body" are different findings, and a
// declared size is neither one. Each case changes one record of the fixture.
void test_content_status_separates_absent_from_unreadable() {
    {
        // A body record whose dwValueHnid is 0. [MS-PST] 2.3.3.2 says that is neither a HID nor a subnode
        // NID, so the source says this message's body is empty -- not that it has a body, and not that the
        // reader failed.
        const InventoryReport report = run_with([](Fixture &fixture) {
            fixture.blocks.add(10, pc_block({{0x001A, 0x001F, 0x60}, {0x1000, 0x001F, 0},
                                            {0x0E07, 0x0003, 1}},
                                            u"subject"));
        });
        TEST_EQ(report.messages.with_body, 3, "A, D and E all carry a 0x1000 record, whatever its value was");
        TEST_EQ(report.messages.with_no_body_form, 1, "so A is not one of the messages with no body record");
        TEST_EQ(report.messages.body.empty, 1, "and its content verdict is empty, not readable");
        TEST_EQ(report.messages.body.readable, 2, "D and E still have readable bodies");
        TEST_EQ(report.messages.body.bytes_read, 24, "the bytes of D and E only");
        TEST_EQ(report.completeness.messages_without_body_form, 2, "still B and the FAI entry");
        TEST_EQ(report.status.content_unreadable, 0, "an empty value is not a reader failure");
    }
    {
        // A 0x3701 whose HNID reads. The payload is content this reader obtained; the 0x0E20 beside it is
        // still only what the source declares, and the two numbers are not the same number.
        const InventoryReport report = run_with([](Fixture &fixture) {
            fixture.blocks.add(13, pc_block({{0x0E20, 0x0003, 707}, {0x3001, 0x001F, 0x60},
                                            {0x3701, 0x0102, 0x60}, {0x3704, 0x001F, 0x60},
                                            {0x3705, 0x0003, 1}, {0x370B, 0x0003, 0}},
                                            u"note.pdf"));
        });
        TEST_EQ(report.attachments.payload.readable, 1, "attachment A's data object read");
        TEST_EQ(report.attachments.payload.not_present, 2, "the other two still carry no 0x3701");
        TEST_EQ(report.attachments.payload.bytes_read, 18, "the nine utf-16 units the record named");
        TEST_EQ(report.attachments.declared_size_bytes, 807, "the declared total did not move");
        TEST_EQ(report.attachments.declared_size_without_payload, 1,
                "only E is left declaring a size it holds nothing for");
        TEST_EQ(report.status.content_unreadable, 0, "and nothing failed");
    }
    {
        // A 0x3701 that names a heap id the node's page map does not hold. The record is there, so this is
        // not a source that lacks a payload -- it is a payload this reader could not get, and it has to
        // reach the verdict instead of looking like an attachment with no data.
        const InventoryReport report = run_with([](Fixture &fixture) {
            fixture.blocks.add(13, pc_block({{0x0E20, 0x0003, 707}, {0x3001, 0x001F, 0x60},
                                            {0x3701, 0x0102, 0x80}, {0x3704, 0x001F, 0x60},
                                            {0x3705, 0x0003, 1}, {0x370B, 0x0003, 0}},
                                            u"note.pdf"));
        });
        TEST_EQ(report.attachments.payload.unreadable, 1, "the named value did not read");
        TEST_EQ(report.attachments.payload.bytes_read, 0, "and not one byte of it was obtained");
        TEST_EQ(report.attachments.declared_size_without_payload, 1,
                "the unreadable 707 is not counted as a size the attachment holds nothing for");
        TEST_EQ(report.completeness.attachments_with_unreadable_payload, 1, "reported as unreadable content");
        TEST_EQ(report.status.content_unreadable, 1, "and it reaches the verdict");
        TEST_EQ(report.status.decode_failures, 1, "itemized as a decode failure, not swallowed");
        TEST_CHECK(!report.status.clean);
        bool named = false;
        for (const auto &item : report.errors) {
            if (item.second != 0) {
                named = true;
            }
        }
        TEST_CHECK(named); // the field that refused the value is itemized, not dropped
    }
    {
        // A 0x3701 present with dwValueHnid 0 on an attachment that declares a size: the exact shape the
        // libpff notes record (libpff format notes (see THIRD_PARTY_NOTICES.txt):2511-2512). Incomplete, not corrupt.
        const InventoryReport report = run_with([](Fixture &fixture) {
            fixture.blocks.add(21, sl_block({{0x692, 12, 0}})); // the base fixture's one dangling bidSub
            fixture.blocks.add(13, pc_block({{0x0E20, 0x0003, 707}, {0x3001, 0x001F, 0x60},
                                            {0x3701, 0x0102, 0}, {0x3704, 0x001F, 0x60},
                                            {0x3705, 0x0003, 1}, {0x370B, 0x0003, 0}},
                                            u"note.pdf"));
        });
        TEST_EQ(report.attachments.payload.empty, 1, "the source says this data object is empty");
        TEST_EQ(report.attachments.payload.not_present, 2, "the other two carry no record at all");
        TEST_EQ(report.attachments.declared_size_without_payload, 2, "both sized attachments hold nothing");
        TEST_EQ(report.completeness.attachments_with_unreadable_payload, 0, "and nothing failed to read");
        TEST_EQ(report.status.content_unreadable, 0, "so the verdict does not call it unreadable content");
        // An empty payload is a completeness finding, not a corrupt file.
        TEST_CHECK(report.status.clean);
    }
    {
        // A 0x3701 of type Embedded Object. [MS-PST] 2.3.3.5 says its value is a heap allocation holding the
        // Nid of the subnode that carries the object data, and 2.4.6.2.2 says that subnode is a fully formed
        // message that is not in the NBT. This reader reaches it and stops, so the payload is content it does
        // not decode -- not content the source lacks, and not a reader failure either.
        const InventoryReport report = run_with([](Fixture &fixture) {
            fixture.blocks.add(21, sl_block({{0x692, 12, 0}})); // keep the run clean
            fixture.blocks.add_internal(26, sl_block({{0x2085, 27, 0}})); // the Attachment object's subnodes
            fixture.blocks.add(27, pc_block({{0x1000, 0x001F, 0x60}}, u"embedded body"));
            std::vector<uint8_t> object_value;
            put32(object_value, 0x2085); // Nid: the subnode that holds the object
            put32(object_value, 1234);   // ulSize
            fixture.blocks.add(14, sl_block({{0x671, 11, 0}, {0x692, 12, 0}, {kAttachmentA, 13, 26},
                                            {kAttachmentB, 18, 0}}));
            fixture.blocks.add(13, make_hn(ltp::kClientSigPc, 0x20, {
                {0x20, bth_header(2, 6, 0x40)},
                {0x40, pc_records({{0x0E20, 0x0003, 707}, {0x3001, 0x001F, 0x60}, {0x3701, 0x000D, 0x80},
                                   {0x3704, 0x001F, 0x60}, {0x3705, 0x0003, 5}, {0x370B, 0x0003, 0}})},
                {0x60, utf16(u"note.pdf")},
                {0x80, object_value},
            }));
        });
        TEST_EQ(report.attachments.payload.unsupported, 1, "the data object reached but not decoded");
        TEST_EQ(report.attachments.payload.unsupported_object, 1,
                "named as the form [MS-PST] 2.3.3.5 defines");
        TEST_EQ(report.attachments.payload.unsupported_compressed, 0, "and not as compressed RTF");
        TEST_EQ(report.attachments.payload.bytes_read, 0, "an undecoded payload contributes no bytes");
        TEST_EQ(report.attachments.declared_size_without_payload, 1,
                "the attachment that reaches an object is not one that holds nothing");
        TEST_EQ(report.completeness.attachments_with_unreadable_payload, 0, "reaching it is not a failure");
        TEST_EQ(report.status.content_unreadable, 0, "so the verdict does not call it unreadable");
        TEST_CHECK(report.status.clean);
    }
}

// A cap is a cap: the report says how many nodes it left out instead of looking like a smaller mailbox.
void test_caps_are_explicit() {
    InventoryOptions options;
    options.max_messages = 2;
    const InventoryReport report = run(options);
    TEST_EQ(report.messages.nodes, 2, "two scanned");
    TEST_EQ(report.messages.stopped_early, 3, "three left out");
    TEST_CHECK(report.capped);
    TEST_EQ(report.associated.nodes, 1, "the FAI cap is separate");
    TEST_EQ(report.status.scans_capped, 3, "the verdict says three Message objects went unscanned");
    TEST_CHECK(!report.status.clean);
}

// C3: an attached message is a Message object the NBT does not name, so the only way this inventory can
// count it is to follow the 0x3701 PtypObject out of the Attachment object that holds it ([MS-PST]
// 2.4.6.2.2). Every case starts from the same change: attachment A's data object becomes a PtypObject
// whose Nid names a subnode of the Attachment object, and that subnode is a Property Context with a body,
// its own Attachment Table, and an Attachment object of its own.
void attach_a_message(Fixture &fixture) {
    fixture.blocks.add(21, sl_block({{0x692, 12, 0}})); // keep the run clean
    fixture.blocks.add_internal(26, sl_block({{kAttachedMessage, 27, 28}})); // attachment A's subnodes
    fixture.blocks.add(27, pc_block({{0x1000, 0x001F, 0x60}}, u"embedded body"));
    fixture.blocks.add(28, sl_block({{0x671, 29, 0}, {kAttachedAttachment, 30, 0}}));
    fixture.blocks.add(29, tc_block({kAttachedAttachment}));
    fixture.blocks.add(30, pc_block({{0x0E20, 0x0003, 42}, {0x3001, 0x001F, 0x60}, {0x3704, 0x001F, 0x60},
                                     {0x3705, 0x0003, 5}, {0x370B, 0x0003, 0}},
                                    u"forwarded.msg"));
    std::vector<uint8_t> object_value;
    put32(object_value, kAttachedMessage); // Nid: the subnode that holds the object data
    put32(object_value, 1234);             // ulSize
    fixture.blocks.add(14, sl_block({{0x671, 11, 0}, {0x692, 12, 0}, {kAttachmentA, 13, 26},
                                     {kAttachmentB, 18, 0}}));
    fixture.blocks.add(13, make_hn(ltp::kClientSigPc, 0x20, {
        {0x20, bth_header(2, 6, 0x40)},
        {0x40, pc_records({{0x0E20, 0x0003, 707}, {0x3001, 0x001F, 0x60}, {0x3701, 0x000D, 0x80},
                           {0x3704, 0x001F, 0x60}, {0x3705, 0x0003, 5}, {0x370B, 0x0003, 0}})},
        {0x60, utf16(u"note.pdf")},
        {0x80, object_value},
    }));
}

void reset_attached_object(Fixture& fixture, uint32_t nid, uint32_t method,
                           uint16_t type = 0x000D) {
    std::vector<uint8_t> object;
    put32(object, nid);
    put32(object, 1234);
    fixture.blocks.add_internal(26, sl_block({{nid, 27, 28}}));
    fixture.blocks.add(13, make_hn(ltp::kClientSigPc, 0x20,
                                   {
                                       {0x20, bth_header(2, 6, 0x40)},
                                       {0x40, pc_records({{0x0E20, 0x0003, 707},
                                                          {0x3701, type, 0x80},
                                                          {0x3705, 0x0003, method}})},
                                       {0x60, utf16(u"note.msg")},
                                       {0x80, object},
                                   }));
}

void test_embedded_identity_and_method_contract() {
    const auto reused = run_with([](Fixture& fixture) {
        attach_a_message(fixture);
        reset_attached_object(fixture, kMessageA, 5);
    });
    TEST_EQ(reused.embedded.nodes, 1, "a different scope may reuse the ancestor's local NID");
    TEST_EQ(reused.embedded_attachments.rows_resolved, 1, "its descendants are retained");
    TEST_EQ(reused.embedded_walks.cycles, 0, "different structural targets are not a cycle");
    TEST_CHECK(reused.status.clean);

    const auto wrong_shape = run_with([](Fixture& fixture) {
        attach_a_message(fixture);
        reset_attached_object(fixture, 0x3004, 5);
        fixture.blocks.add(27, tc_block({}));
    });
    TEST_EQ(wrong_shape.embedded.nodes, 0, "a TC cannot represent a declared Message PC");
    TEST_CHECK(wrong_shape.status.decode_failures != 0);
    TEST_CHECK(!wrong_shape.status.clean);

    const auto ole = run_with([](Fixture& fixture) {
        attach_a_message(fixture);
        reset_attached_object(fixture, 0x3004, 6);
    });
    TEST_EQ(ole.embedded.nodes, 0, "OLE must not be guessed to be a message from its PC shape");
    TEST_EQ(ole.attachments.data_objects_not_messages, 1, "OLE remains explicitly undecoded");
    TEST_CHECK(ole.status.clean);

    const auto wrong_type = run_with([](Fixture& fixture) {
        attach_a_message(fixture);
        reset_attached_object(fixture, 0x3004, 5, 0x0102);
    });
    TEST_EQ(wrong_type.embedded.nodes, 0, "method 5 requires PtypObject");
    TEST_CHECK(wrong_type.status.decode_failures != 0);
    TEST_CHECK(!wrong_type.status.clean);
}

void test_attached_messages_are_walked_and_counted_apart() {
    {
        const InventoryReport report = run_with(attach_a_message);
        TEST_EQ(report.attachments.data_objects, 1, "one 0x3701 value names a subnode");
        TEST_EQ(report.attachments.data_objects_scanned, 1, "and its data block is a Property Context");
        TEST_EQ(report.attachments.data_objects_not_messages, 0, "so nothing was left undecoded");
        TEST_EQ(report.embedded.nodes, 1, "the attached message was scanned");
        TEST_EQ(report.messages.nodes, 5, "and it is not counted among the five the NBT names");
        TEST_EQ(report.embedded.pcs_read, 1, "its own Property Context read");
        TEST_EQ(report.embedded.body.readable, 1, "and its body was obtained");
        TEST_EQ(report.embedded.body.bytes_read, 28, "the utf-16 body of the attached message");
        TEST_EQ(report.embedded_attachments.tables, 1, "its own Attachment Table");
        TEST_EQ(report.embedded_attachments.rows_resolved, 1, "and the Attachment object its row names");
        TEST_EQ(report.embedded_attachments.declared_size_bytes, 42, "sized apart from the top-level total");
        TEST_EQ(report.attachments.declared_size_bytes, 807, "which did not move");
        TEST_EQ(report.embedded_walks.objects, 1, "one data object reached");
        TEST_EQ(report.embedded_walks.scanned, 1, "one Message object scanned");
        TEST_EQ(report.embedded_walks.cycles, 0, "no cycle");
        TEST_EQ(report.embedded_walks.depths.at(1), 1, "at nesting depth 1");
        TEST_EQ(report.embedded_walks.nid_types.at(ltp::kNidTypeAttachment), 1,
                "the subnode NID carries nidType 0x05; the Property Context is what says it is a message");
        TEST_EQ(report.node_types.at(ltp::kNidTypeAttachment).nodes, 0,
                "none of this adds an NBT entry to the 0x05 line");
        TEST_EQ(report.node_types.at(ltp::kNidTypeAttachment).opened, 5,
                "while what this run opened under that nidType counts all five: the three top-level "
                "Attachment objects, the attached message, and the Attachment object it holds");
        const msg::FolderCounts &folder = report.folders[0];
        TEST_EQ(folder.messages, 5, "an attached message has no parent folder ([MS-PST] 2.4.6.2.2)");
        TEST_EQ(folder.attachments, 3, "and neither does its attachment");
        bool path_named = false;
        for (const std::string &sample : report.embedded_attachments.samples) {
            if (sample.find("embedded 0x0000000000002085 attachment 0x00000000000020C5") !=
                std::string::npos) {
                path_named = true;
            }
        }
        TEST_CHECK(path_named);
        TEST_CHECK(report.attachments.samples[0].find("message 0x0000000000002004 attachment") == 0);
        TEST_EQ(report.completeness.attachment_data_objects_not_decoded, 0, "nothing left undecoded");
        TEST_EQ(report.completeness.attached_messages_left_by_cap, 0, "and no cap stopped the walk");
        TEST_CHECK(report.status.clean);

        // The row dump the cross-layer comparison reads. It is the inventory's own enumeration, so the
        // attached messages this run recursed into have to show up in it or the comparison would be
        // comparing a walk the production code never did.
        InventoryOptions with_rows;
        with_rows.collect_rows = true;
        const InventoryReport dumped = run_with(attach_a_message, with_rows);
        TEST_EQ(dumped.attachments.row_dump.size(), 3, "one row per Attachment object a table resolved");
        TEST_EQ(dumped.associated_attachments.row_dump.size(), 0,
                "and none where there is nothing to resolve");
        TEST_EQ(dumped.embedded_attachments.row_dump.size(), 1,
                "including the attached message's own attachment");
        bool embedded_row = false;
        for (const std::string &row : dumped.embedded_attachments.row_dump) {
            if (row.find("ATT\t0x00002085\t0x20C5\t42\t5\t1\tmessage "
                         "0x0000000000002004 attachment 0x0000000000002005 embedded "
                         "0x0000000000002085 attachment 0x00000000000020C5\n") !=
                std::string::npos) {
                embedded_row = true;
            }
        }
        TEST_CHECK(embedded_row);
        TEST_EQ(run_with(attach_a_message).attachments.row_dump.size(), 0,
                "and the dump is off unless asked for");
    }
    {
        // The attached message's own attachment names the message it hangs under. The recursion has to stop
        // there and say where, not walk the same item until a cap ends it.
        const InventoryReport report = run_with([](Fixture &fixture) {
            attach_a_message(fixture);
            fixture.blocks.add(28, sl_block({{0x671, 29, 0}, {kAttachedAttachment, 30, 31}}));
            fixture.blocks.add_internal(31, sl_block({{0x4004, 10, 14}}));
            std::vector<uint8_t> back;
            put32(back, 0x4004); // a new local name for the ancestor's actual data/subnode target
            put32(back, 10);
            fixture.blocks.add(30, make_hn(ltp::kClientSigPc, 0x20, {
                {0x20, bth_header(2, 6, 0x40)},
                {0x40, pc_records({{0x0E20, 0x0003, 42}, {0x3001, 0x001F, 0x60}, {0x3701, 0x000D, 0x80},
                                   {0x3704, 0x001F, 0x60}, {0x3705, 0x0003, 5}, {0x370B, 0x0003, 0}})},
                {0x60, utf16(u"forwarded.msg")},
                {0x80, back},
            }));
        });
        TEST_EQ(report.embedded.nodes, 1, "the attached message itself still got scanned");
        TEST_EQ(report.embedded_attachments.data_objects, 1, "its attachment names one more object");
        TEST_EQ(report.embedded_attachments.data_objects_scanned, 0, "and it was not scanned again");
        TEST_EQ(report.embedded_walks.objects, 2, "two data objects reached");
        TEST_EQ(report.embedded_walks.scanned, 1, "one Message object scanned");
        TEST_EQ(report.embedded_walks.cycles, 1, "the second was already on this path");
        TEST_EQ(report.status.decode_failures, 1, "a cycle is a finding, not a mailbox with one less item");
        TEST_CHECK(!report.status.clean);
        bool named = false;
        for (const std::string &note : report.completeness.incomplete_walks) {
            if (note.find("attached message walk stopped") != std::string::npos) {
                named = true;
            }
        }
        TEST_CHECK(named);
    }
    {
        // A cap on the recursion is reported as a cap. It never looks like a mailbox with no attached
        // messages, and the two caps say which one stopped the walk.
        InventoryOptions no_depth;
        no_depth.max_embedded_depth = 0;
        const InventoryReport capped = run_with(attach_a_message, no_depth);
        TEST_EQ(capped.embedded.nodes, 0, "nothing under the attachment was scanned");
        TEST_EQ(capped.embedded_walks.depth_capped, 1, "the depth cap stopped it");
        TEST_EQ(capped.attachments.data_objects, 1, "the data object is still counted");
        TEST_EQ(capped.attachments.data_objects_scanned, 0, "and says it was not scanned");
        TEST_EQ(capped.completeness.attached_messages_left_by_cap, 1, "reported as left unscanned");
        TEST_EQ(capped.status.embedded_capped, 1, "and it reaches the verdict");
        TEST_CHECK(capped.capped);
        TEST_CHECK(!capped.status.clean);

        InventoryOptions no_work;
        no_work.max_embedded = 0;
        const InventoryReport limited = run_with(attach_a_message, no_work);
        TEST_EQ(limited.embedded_walks.capped, 1, "the work cap stopped the same walk");
        TEST_EQ(limited.embedded_walks.depth_capped, 0, "and says which cap it was");
        TEST_EQ(limited.status.embedded_capped, 1, "reported the same way");
        TEST_CHECK(!limited.status.clean);
    }
}

// The recursion moves items into a population of their own, so a reader failure found there has to
// reach the verdict exactly as the same failure under a message the NBT names does.
void test_a_failure_under_an_attached_message_reaches_the_verdict() {
    {
        const InventoryReport report = run_with([](Fixture &fixture) {
            attach_a_message(fixture);
            fixture.blocks.add(27, pc_block({{0x1000, 0x001F, 0x90}}, u"embedded body"));
        });
        TEST_EQ(report.embedded.nodes, 1, "the attached message was still scanned");
        TEST_EQ(report.embedded.body.unreadable, 1, "the body record named an absent heap id");
        TEST_EQ(report.embedded.body.bytes_read, 0, "and not one byte of it was obtained");
        TEST_EQ(report.completeness.messages_with_unreadable_body, 1,
                "the unreadable body is not hidden in a population of its own");
        TEST_EQ(report.status.content_unreadable, 1, "and it reaches the verdict");
        TEST_CHECK(!report.status.clean);
    }
    {
        const InventoryReport report = run_with([](Fixture &fixture) {
            attach_a_message(fixture);
            fixture.blocks.add(30, pc_block({{0x0E20, 0x0003, 42},
                                             {0x3001, 0x001F, 0x60},
                                             {0x3701, 0x0102, 0x90},
                                             {0x3704, 0x001F, 0x60},
                                             {0x3705, 0x0003, 1},
                                             {0x370B, 0x0003, 0}},
                                            u"forwarded.msg"));
        });
        TEST_EQ(report.embedded_attachments.payload.unreadable, 1,
                "the attached message's own attachment named a payload this reader could not get");
        TEST_EQ(report.embedded_attachments.data_objects, 0,
                "0x0102 is the Binary Object form, so no further message was expected");
        TEST_EQ(report.completeness.attachments_with_unreadable_payload, 1,
                "reported together with the top-level attachments");
        TEST_EQ(report.status.content_unreadable, 1, "and it reaches the verdict");
        TEST_EQ(report.status.decode_failures, 1, "itemized, not swallowed");
        TEST_CHECK(!report.status.clean);
    }
}

} // namespace

int main() {
    test_census_classifies_every_type();
    test_messages_and_attachments_are_counted();
    test_completeness_reports_what_is_absent();
    test_a_broken_subnode_block_is_reported_not_fatal();
    test_a_failed_read_reaches_the_verdict();
    test_content_status_separates_absent_from_unreadable();
    test_items_are_attributed_to_their_folder();
    test_attachment_samples_are_named();
    test_caps_are_explicit();
    test_attached_messages_are_walked_and_counted_apart();
    test_embedded_identity_and_method_contract();
    test_a_failure_under_an_attached_message_reaches_the_verdict();
    return ost2pst::test::finish("msg_inventory_test");
}
