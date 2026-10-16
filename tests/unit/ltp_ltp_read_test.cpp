// The LTP read is the piece M3 builds a converter on, and it is the piece that can hide a wrong folder
// tree behind counters that look plausible. So this file builds a whole mailbox in memory -- a folder PC
// that names itself, a hierarchy table whose rows are NIDs, a contents table whose rows are messages --
// and checks the tree the reader reports against the tree that was written.
#include <cstdint>
#include <cstdio>
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
#include "ost2pst/ltp/name_id.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/ltp/node_value.h"
#include "ost2pst/ltp/pc.h"
#include "ost2pst/ltp/prop_type.h"
#include "ost2pst/ltp/tc.h"
#include "ost2pst/ndb/btree.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"
#include "test_support.h"

namespace {

using namespace ost2pst;
using ltp::BlockSource;
using ltp::FolderWalkOptions;
using ltp::FolderWalkStats;
using ltp::LtpFolder;
using ltp::NidMap;
using ltp::PcRecord;
using ltp::ValueSource;
using ndb::FailureLog;
using ndb::NbtEntry;
using ndb::FileProfile;
using util::ByteView;
using util::ErrorKind;
using util::make_error;
using util::Result;
using util::Status;

// The fixtures name allocations 1-3 of block 0 and are read the same way under either profile; the OST
// 4 KiB one is used because that is the profile walk_folder_tree runs under in this project.
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

std::vector<uint8_t> utf16(const std::u16string &text) {
    std::vector<uint8_t> bytes;
    for (const char16_t unit : text) {
        put16(bytes, static_cast<uint16_t>(unit));
    }
    put16(bytes, 0); // Outlook terminates a PC string value even though the spec does not require it
    return bytes;
}

// One whole data block: HNHDR, HNPAGEMAP, then one allocation per heap id, each exactly as long as the
// bytes handed in. A HID names allocation hidIndex(hid) ([MS-PST] 2.3.1.1), so the list has to run from
// HID 0x20 up in steps of 0x20 or the block would name allocations it does not have.
std::vector<uint8_t> make_hn(
    uint8_t client_sig, uint32_t hid_user_root,
    const std::vector<std::pair<uint32_t, std::vector<uint8_t>>> &allocations) {
    for (size_t index = 0; index < allocations.size(); ++index) {
        TEST_EQ(ltp::hid_index(allocations[index].first, kProfile), index + 1,
                "a fixture HID names its slot");
    }
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
    bytes.push_back(0); // bIdxLevels: the array hidRoot names is the leaf array
    put32(bytes, hid_root);
    return bytes;
}

std::vector<uint8_t> pc_records(const std::vector<std::tuple<uint16_t, uint16_t, uint32_t>> &records) {
    std::vector<uint8_t> bytes;
    for (const auto &record : records) {
        put16(bytes, std::get<0>(record));
        put16(bytes, std::get<1>(record));
        put32(bytes, std::get<2>(record));
    }
    return bytes;
}

// A table context with the column shape every real one has: rgib 12/14/15/16, PidTagLtpRowId at ibData 0
// iBit 0 and PidTagLtpRowVer at ibData 4 iBit 1 ([MS-PST] 2.3.4.4.1), plus two more columns so the group
// offsets are exercised.
std::vector<uint8_t> tc_header_bytes(uint32_t hid_row_index) {
    std::vector<uint8_t> bytes;
    bytes.push_back(ltp::kClientSigTc);
    bytes.push_back(4);
    put16(bytes, 12);
    put16(bytes, 14);
    put16(bytes, 15);
    put16(bytes, 16);
    put32(bytes, hid_row_index);
    put32(bytes, 0); // hnidRows: the Row Matrix is not what the folder tree reads
    put32(bytes, 0);
    const auto column = [&](uint32_t tag, uint16_t ib_data, uint8_t cb_data, uint8_t i_bit) {
        put32(bytes, tag);
        put16(bytes, ib_data);
        bytes.push_back(cb_data);
        bytes.push_back(i_bit);
    };
    column(0x6619001F, 8, 4, 2);
    column(0x66740002, 12, 2, 3);
    column(0x67F20003, 0, 4, 0);
    column(0x67F30003, 4, 4, 1);
    return bytes;
}

std::vector<uint8_t> row_records(const std::vector<uint32_t> &row_ids) {
    std::vector<uint8_t> bytes;
    uint32_t index = 0;
    for (uint32_t row_id : row_ids) {
        put32(bytes, row_id);
        put32(bytes, index++);
    }
    return bytes;
}

std::vector<uint8_t> table_block(const std::vector<uint32_t> &row_ids) {
    return make_hn(ltp::kClientSigTc, 0x20, {
        {0x20, tc_header_bytes(0x40)},
        {0x40, bth_header(4, 4, row_ids.empty() ? 0 : 0x60)},
        {0x60, row_records(row_ids)},
    });
}

// A Folder object's own Property Context: PidTagDisplayName as a heap string and PidTagSubFolders inline.
std::vector<uint8_t> folder_pc_block(const std::u16string &name) {
    std::vector<std::tuple<uint16_t, uint16_t, uint32_t>> records;
    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> allocations;
    allocations.emplace_back(0x20, bth_header(2, 6, 0x40));
    if (name.empty()) {
        records.emplace_back(0x36DA, 0x000B, 1);
    } else {
        records.emplace_back(0x3001, 0x001F, 0x60);
        records.emplace_back(0x36DA, 0x000B, 1);
    }
    allocations.emplace_back(0x40, pc_records(records));
    if (!name.empty()) {
        allocations.emplace_back(0x60, utf16(name));
    }
    return make_hn(ltp::kClientSigPc, 0x20, allocations);
}

// The same Folder object, but the display name is present with dwValueHnid 0: the property exists and its
// value is empty. This is what the root folder of a real OST looks like.
std::vector<uint8_t> folder_pc_block_empty_name() {
    std::vector<std::tuple<uint16_t, uint16_t, uint32_t>> records;
    records.emplace_back(0x3001, 0x001F, 0); // dwValueHnid 0: the property is there and the value is empty
    records.emplace_back(0x36DA, 0x000B, 1);
    return make_hn(ltp::kClientSigPc, 0x20, {
        {0x20, bth_header(2, 6, 0x40)},
        {0x40, pc_records(records)},
    });
}

class FakeBlocks : public BlockSource {
public:
    void add(uint64_t bid, const std::vector<uint8_t> &bytes) { blocks_[bid] = bytes; }
    void drop(uint64_t bid) { blocks_.erase(bid); }

    Result<ltp::BlockBytes> block(uint64_t bid) override {
        const auto found = blocks_.find(bid);
        if (found == blocks_.end()) {
            return make_error(ErrorKind::kUnsupported, "BBTENTRY.bid", 0, bid, "this test has no such block");
        }
        // [MS-PST] 2.2.2.2 bit B: every block this fixture holds is a data block unless add_internal says
        // otherwise, which is what the BBTENTRY would have carried.
        return ltp::BlockBytes{ByteView(found->second.data(), found->second.size(), bid * 512),
                               internal_.count(bid) != 0};
    }

private:
    std::map<uint64_t, std::vector<uint8_t>> blocks_;
    std::set<uint64_t> internal_;
};

void add_node(NidMap &nodes, uint64_t index, uint32_t nid_type, uint64_t bid, uint64_t parent) {
    const uint64_t nid = ltp::make_nid(index, nid_type);
    nodes.add(NbtEntry{nid, bid, 0, static_cast<uint32_t>(parent)});
}

struct Mailbox {
    NidMap nodes;
    FakeBlocks blocks;
};

// Inbox (NID 0x122) with three hierarchy rows -- two real subfolders and one NID the NBT does not carry --
// five messages and two associated messages. Work (0x2002) has three messages and a hierarchy row that
// points back at Inbox, which is the cycle the visited set has to survive. Personal (0x2042) has one
// message and no PidTagDisplayName at all.
void make_mailbox(Mailbox &box) {
    add_node(box.nodes, 9, ltp::kNidTypeNormalFolder, 1, 0);
    add_node(box.nodes, 9, ltp::kNidTypeHierarchyTable, 2, 0x122);
    add_node(box.nodes, 9, ltp::kNidTypeContentsTable, 3, 0x122);
    add_node(box.nodes, 9, ltp::kNidTypeAssocContentsTable, 4, 0x122);
    add_node(box.nodes, 256, ltp::kNidTypeNormalFolder, 5, 0x122);
    add_node(box.nodes, 256, ltp::kNidTypeHierarchyTable, 6, 0x122);
    add_node(box.nodes, 256, ltp::kNidTypeContentsTable, 7, 0x122);
    add_node(box.nodes, 258, ltp::kNidTypeNormalFolder, 8, 0x122);
    add_node(box.nodes, 258, ltp::kNidTypeContentsTable, 9, 0x122);

    box.blocks.add(1, folder_pc_block(u"Inbox"));
    box.blocks.add(2, table_block({0x2002, 0x2042, 0x9999}));
    box.blocks.add(3, table_block({0x2004, 0x2024, 0x2044, 0x2064, 0x2084}));
    box.blocks.add(4, table_block({0x20A8, 0x20C8}));
    box.blocks.add(5, folder_pc_block(u"Work"));
    box.blocks.add(6, table_block({0x122}));
    box.blocks.add(7, table_block({0x2104, 0x2124, 0x2144}));
    box.blocks.add(8, folder_pc_block(std::u16string()));
    box.blocks.add(9, table_block({0x2164}));

    // The items those tables name, as the NBT itself carries them. A Message object's nidParent is the NID
    // of its parent Folder object's PC ([MS-PST] 2.4.5.2), and none of these needs a data block: the walk
    // counts them out of the NID map alone.
    for (const uint64_t index : {0x100, 0x101, 0x102, 0x103, 0x104}) {
        add_node(box.nodes, index, ltp::kNidTypeNormalMessage, 0, 0x122);
    }
    for (const uint64_t index : {0x105, 0x106}) {
        add_node(box.nodes, index, ltp::kNidTypeAssocMessage, 0, 0x122);
    }
    for (const uint64_t index : {0x108, 0x109, 0x10A}) {
        add_node(box.nodes, index, ltp::kNidTypeNormalMessage, 0, 0x2002);
    }
    add_node(box.nodes, 0x10B, ltp::kNidTypeNormalMessage, 0, 0x2042);
}

void test_folder_tree() {
    Mailbox box;
    make_mailbox(box);
    FolderWalkOptions options;
    FolderWalkStats stats;
    std::vector<LtpFolder> folders;
    FailureLog failures(10);
    TEST_CHECK(ltp::walk_folder_tree(box.nodes, box.blocks, ltp::kNidRootFolder, options, kProfile, folders, stats,
                                     failures)
                   .ok());

    TEST_EQ(folders.size(), 3, "folders walked");
    TEST_EQ(stats.folders, 3, "folder counter");
    TEST_EQ(stats.max_depth, 1, "deepest folder");
    TEST_EQ(stats.cycles, 1, "the row that points back at Inbox");
    TEST_EQ(stats.missing, 1, "the row with no NBT entry behind it");
    TEST_EQ(stats.depth_capped, 0, "nothing capped");
    TEST_EQ(stats.stopped_early, 0, "nothing truncated");
    TEST_EQ(stats.tc_rows, 15, "rows counted");
    TEST_EQ(stats.pcs_read, 3, "one PC per folder");
    TEST_EQ(stats.tcs_read, 6, "every table the folders have");
    TEST_EQ(stats.blocks_read, 9, "one block per node");
    TEST_EQ(stats.blocks_failed, 0, "no unreadable block");
    TEST_EQ(stats.not_heap_node, 0, "no non-heap block");
    TEST_EQ(failures.total(), 0, "a clean synthetic mailbox reports no findings");
    if (folders.size() != 3) {
        return; // the counters already failed; indexing the tree would only add noise
    }

    TEST_EQ(folders[0].nid, 0x122, "root NID");
    TEST_EQ(folders[0].depth, 0, "root depth");
    TEST_EQ(folders[0].name_present, 1, "root has a name");
    TEST_STR(folders[0].name, "Inbox", "root name");
    TEST_EQ(folders[0].children, 3, "root hierarchy rows");
    TEST_EQ(folders[0].messages, 5, "root contents rows");
    TEST_EQ(folders[0].associated, 2, "root FAI contents rows");
    TEST_EQ(folders[0].parent_messages, 5, "the NBT agrees with the contents table");
    TEST_EQ(folders[0].parent_associated, 2, "and with the FAI table");
    TEST_EQ(folders[0].has_pc, 1, "root PC");
    TEST_EQ(folders[0].has_hierarchy, 1, "root hierarchy table");
    TEST_EQ(folders[0].has_contents, 1, "root contents table");
    TEST_EQ(folders[0].has_associated, 1, "root FAI contents table");

    TEST_EQ(folders[1].nid, 0x2002, "first subfolder NID");
    TEST_EQ(folders[1].depth, 1, "subfolder depth");
    TEST_STR(folders[1].name, "Work", "subfolder name");
    TEST_EQ(folders[1].children, 1, "its one hierarchy row");
    TEST_EQ(folders[1].messages, 3, "its messages");
    TEST_EQ(folders[1].associated, 0, "it has no FAI table");
    TEST_EQ(folders[1].has_associated, 0, "and the walk says so");

    TEST_EQ(folders[2].nid, 0x2042, "second subfolder NID");
    TEST_EQ(folders[2].name_present, 0, "no PidTagDisplayName");
    TEST_EQ(folders[2].messages, 1, "its one message");
    TEST_EQ(folders[2].parent_messages, 1, "the NBT names the same message");
    TEST_EQ(folders[2].children, 0, "it has no hierarchy table");
}

// A real OST leaves most of its contents tables empty while the NBT still names every message its parent
// folder. The walk reports both counts, so the divergence is a visible fact instead of a wrong number.
void test_parent_counts_without_rows() {
    Mailbox box;
    make_mailbox(box);
    add_node(box.nodes, 0x10C, ltp::kNidTypeNormalMessage, 0, 0x2042);
    add_node(box.nodes, 0x10D, ltp::kNidTypeAssocMessage, 0, 0x2042);
    FolderWalkOptions options;
    FolderWalkStats stats;
    std::vector<LtpFolder> folders;
    FailureLog failures(10);
    TEST_CHECK(ltp::walk_folder_tree(box.nodes, box.blocks, ltp::kNidRootFolder, options, kProfile, folders, stats,
                                     failures)
                   .ok());
    if (folders.size() != 3) {
        return;
    }
    TEST_EQ(folders[2].messages, 1, "the table still has its one row");
    TEST_EQ(folders[2].parent_messages, 2, "the NBT names two messages for the folder");
    TEST_EQ(folders[2].parent_associated, 1, "and one associated message");
    TEST_EQ(stats.blocks_read, 9, "counting them opened no extra block");
}

void test_walk_caps() {
    Mailbox box;
    make_mailbox(box);
    FolderWalkOptions shallow;
    shallow.max_depth = 0;
    FolderWalkStats stats;
    std::vector<LtpFolder> folders;
    FailureLog failures(10);
    TEST_CHECK(ltp::walk_folder_tree(box.nodes, box.blocks, ltp::kNidRootFolder, shallow, kProfile, folders, stats,
                                     failures)
                   .ok());
    TEST_EQ(folders.size(), 1, "a depth cap of zero walks the root only");
    TEST_EQ(stats.depth_capped, 2, "the two real subfolders were capped");
    TEST_EQ(stats.missing, 1, "the missing row is still reported as missing");

    Mailbox tight;
    make_mailbox(tight);
    FolderWalkOptions few;
    few.max_folders = 1;
    FolderWalkStats tight_stats;
    std::vector<LtpFolder> one;
    FailureLog more(10);
    TEST_CHECK(ltp::walk_folder_tree(tight.nodes, tight.blocks, ltp::kNidRootFolder, few, kProfile, one, tight_stats,
                                     more)
                   .ok());
    TEST_EQ(one.size(), 1, "the folder cap stops the walk");
    TEST_EQ(tight_stats.stopped_early, 1, "and says it stopped");
}

void test_missing_root() {
    NidMap nodes;
    FakeBlocks blocks;
    FolderWalkOptions options;
    FolderWalkStats stats;
    std::vector<LtpFolder> folders;
    FailureLog failures(10);
    const Status walked =
        ltp::walk_folder_tree(nodes, blocks, ltp::kNidRootFolder, options, kProfile, folders, stats, failures);
    TEST_ERROR(walked, ErrorKind::kUnsupported, "NBTENTRY.nid", "a file with no root folder");
    TEST_EQ(folders.size(), 0, "nothing walked");
}

// A folder whose data block cannot be read still gets counted, still gets its tables read, and still
// reports no name: one unreadable block must not lose the tree.
void test_unreadable_folder_block() {
    Mailbox box;
    make_mailbox(box);
    box.blocks.drop(1);
    FolderWalkOptions options;
    FolderWalkStats stats;
    std::vector<LtpFolder> folders;
    FailureLog failures(10);
    TEST_CHECK(ltp::walk_folder_tree(box.nodes, box.blocks, ltp::kNidRootFolder, options, kProfile, folders, stats,
                                     failures)
                   .ok());
    TEST_EQ(folders.size(), 3, "the tree survives an unreadable folder block");
    if (folders.empty()) {
        return;
    }
    TEST_EQ(folders[0].name_present, 0, "but the name is gone with it");
    TEST_EQ(folders[0].children, 3, "the tables were still read");
    TEST_EQ(stats.blocks_failed, 1, "and the failure is counted");
}

// A folder whose PidTagDisplayName is there but empty is a folder with an empty name: the walk reports it,
// reads its PC, and raises no finding for it.
void test_empty_display_name() {
    Mailbox box;
    make_mailbox(box);
    box.blocks.add(8, folder_pc_block_empty_name());
    FolderWalkOptions options;
    FolderWalkStats stats;
    std::vector<LtpFolder> folders;
    FailureLog failures(10);
    TEST_CHECK(ltp::walk_folder_tree(box.nodes, box.blocks, ltp::kNidRootFolder, options, kProfile, folders, stats,
                                     failures)
                   .ok());
    TEST_EQ(failures.total(), 0, "an empty display name is not a finding");
    TEST_EQ(stats.pcs_read, 3, "the PC was still read");
    if (folders.size() != 3) {
        return;
    }
    TEST_EQ(folders[2].nid, 0x2042, "the folder with the empty name");
    TEST_EQ(folders[2].name_present, 1, "the property is there");
    TEST_EQ(folders[2].name.empty(), 1, "and its value is empty");
}

class FakeValues : public ValueSource {
public:
    void add(uint32_t hnid, const std::vector<uint8_t> &bytes) { items_[hnid] = bytes; }

    Result<ByteView> value(uint32_t hnid) override {
        const auto found = items_.find(hnid);
        if (found == items_.end()) {
            return make_error(ErrorKind::kBadField, "HNID", 0, hnid, "this test has no such value");
        }
        return ByteView(found->second.data(), found->second.size(), 0);
    }

private:
    std::map<uint32_t, std::vector<uint8_t>> items_;
};

PcRecord record_of(uint16_t prop_id, uint16_t prop_type, uint32_t value_hnid) {
    PcRecord record;
    record.prop_id = prop_id;
    record.prop_type = prop_type;
    record.value_hnid = value_hnid;
    record.value_inline = ltp::prop_type_is_inline(prop_type);
    record.value_absent = !record.value_inline && value_hnid == 0;
    return record;
}

void test_render_value() {
    FakeValues values;
    values.add(0x60, utf16(u"Hello"));
    values.add(0x80, std::vector<uint8_t>(7, 0xAB));

    std::vector<uint8_t> four = {1, 0, 0, 0};
    PcRecord boolean = record_of(0x36DA, 0x000B, 1);
    boolean.value = ByteView(four.data(), four.size(), 0);
    TEST_STR(ltp::render_property_value(boolean, values), "1", "an inline PtypBoolean");

    std::vector<uint8_t> number = {0x34, 0x12, 0, 0};
    PcRecord integer = record_of(0x6673, 0x0003, 0x1234);
    integer.value = ByteView(number.data(), number.size(), 0);
    TEST_STR(ltp::render_property_value(integer, values), "4660", "an inline PtypInteger32");

    TEST_STR(ltp::render_property_value(record_of(0x3001, 0x001F, 0x60), values), "Hello",
             "a PtypString16 in the heap");

    PcRecord ansi = record_of(0x3001, 0x001E, 0x80);
    values.add(0xC0, std::vector<uint8_t>{'a', 'b', 0, 0});
    TEST_STR(ltp::render_property_value(record_of(0x3001, 0x001E, 0xC0), values), "ab",
             "a PtypString8 in the heap");

    TEST_STR(ltp::render_property_value(record_of(0x0418, 0x0102, 0x80), values), "7 bytes",
             "a PtypBinary is sized, not decoded");
    TEST_STR(ltp::render_property_value(record_of(0x8000, 0x101F, 0x60), values),
             "12 bytes (multi-valued)", "a multi-valued value is sized, not decoded");
    TEST_CHECK(ltp::render_property_value(record_of(0x3001, 0x001F, 0xA0), values)
                   .rfind("unresolved HNID", 0) == 0);
    TEST_STR(ltp::render_property_value(record_of(0x3001, 0x001F, 0), values), "(no value)",
             "dwValueHnid 0 is an empty value, not an unresolved HNID");
}

} // namespace

int main() {
    test_folder_tree();
    test_parent_counts_without_rows();
    test_walk_caps();
    test_missing_root();
    test_unreadable_folder_block();
    test_empty_display_name();
    test_render_value();
    return ost2pst::test::finish("ltp_ltp_read_test");
}
