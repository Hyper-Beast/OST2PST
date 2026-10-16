// The subset extractor is what the M5 writer will emit from, so it is checked against a mailbox
// built here, where every value is known before the code runs: a folder with three Message objects,
// a Recipient Table and an Attachment Table under the internal NIDs [MS-PST] 2.4.5.3.1
// and 2.4.6.1.1 name, Attachment objects with payloads in the heap and in a subnode, a body in a
// subnode, a Row Matrix in the heap and a Row Matrix in a subnode, a named property, and the two
// ways a value can be missing (dwValueHnid 0, and a record the PC does not carry at all).
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "ost2pst/ltp/bth.h"
#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/ltp_read.h"
#include "ost2pst/ltp/name_id.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/ltp/pc.h"
#include "ost2pst/ltp/tc.h"
#include "ost2pst/msg/emit.h"
#include "ost2pst/msg/item_conversion.h"
#include "ost2pst/msg/subset.h"
#include "ost2pst/ndb/btree.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

#include "test_support.h"

namespace {

using namespace ost2pst;
using ltp::BlockSource;
using ltp::LtpReadReport;
using ltp::NidMap;
using msg::build_subset;
using msg::SubsetAttachment;
using msg::SubsetMessage;
using msg::SubsetOptions;
using msg::SubsetRecipient;
using msg::SubsetReport;
using msg::SubsetValue;
using ndb::FileProfile;
using ndb::NbtEntry;
using util::ByteView;
using util::ErrorKind;
using util::make_error;
using util::Result;

constexpr FileProfile kProfile = FileProfile::kOst;

void put16(std::vector<uint8_t>& bytes, uint16_t value) {
    bytes.push_back(static_cast<uint8_t>(value & 0xFF));
    bytes.push_back(static_cast<uint8_t>(value >> 8));
}

void put32(std::vector<uint8_t>& bytes, uint32_t value) {
    for (int shift = 0; shift < 4; ++shift) {
        bytes.push_back(static_cast<uint8_t>((value >> (8 * shift)) & 0xFF));
    }
}

void put64(std::vector<uint8_t>& bytes, uint64_t value) {
    for (int shift = 0; shift < 8; ++shift) {
        bytes.push_back(static_cast<uint8_t>((value >> (8 * shift)) & 0xFF));
    }
}

// A Unicode PST stores strings as UTF-16 with a terminator ([MS-PST] 2.3.3.6), so the fixture's
// string values carry one and the test compares against the same bytes.
std::vector<uint8_t> utf16(const std::u16string& text) {
    std::vector<uint8_t> bytes;
    for (const char16_t unit : text) {
        put16(bytes, static_cast<uint16_t>(unit));
    }
    put16(bytes, 0);
    return bytes;
}

std::vector<uint8_t> utf16_text(const std::string& text) {
    std::u16string units;
    for (const char unit : text) {
        units.push_back(static_cast<char16_t>(static_cast<unsigned char>(unit)));
    }
    return utf16(units);
}

std::vector<uint8_t> bytes_of(const std::vector<int>& values) {
    std::vector<uint8_t> bytes;
    for (const int value : values) {
        bytes.push_back(static_cast<uint8_t>(value));
    }
    return bytes;
}

// The fixture's strings are ASCII in UTF-16 with a terminator, so the report's UTF-8 form is the
// low byte of each unit up to the terminator.
std::string utf8_of(const std::vector<uint8_t>& bytes) {
    std::string text;
    for (size_t offset = 0; offset + 1 < bytes.size(); offset += 2) {
        if (bytes[offset] == 0 && bytes[offset + 1] == 0) {
            break;
        }
        text += static_cast<char>(bytes[offset]);
    }
    return text;
}

std::vector<uint8_t>
make_hn(uint8_t client_sig, uint32_t hid_user_root,
        const std::vector<std::pair<uint32_t, std::vector<uint8_t>>>& allocations) {
    const uint16_t header_size = 12; // [MS-PST] 2.3.1.2 HNHDR
    const uint16_t map_size =
        static_cast<uint16_t>(4 + (allocations.size() + 1) * 2); // [MS-PST] 2.3.1.5
    std::vector<uint8_t> bytes;
    put16(bytes, header_size);
    bytes.push_back(ltp::kHnSignature);
    bytes.push_back(client_sig);
    put32(bytes, hid_user_root);
    put32(bytes, 0);
    put16(bytes, static_cast<uint16_t>(allocations.size()));
    put16(bytes, 0);
    uint16_t at = static_cast<uint16_t>(header_size + map_size);
    for (const auto& item : allocations) {
        put16(bytes, at);
        at = static_cast<uint16_t>(at + item.second.size());
    }
    put16(bytes, at);
    for (const auto& item : allocations) {
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

std::vector<uint8_t> pc_records(const std::vector<std::tuple<int, int, uint32_t>>& records) {
    std::vector<uint8_t> bytes;
    for (const auto& record : records) {
        put16(bytes, static_cast<uint16_t>(std::get<0>(record)));
        put16(bytes, static_cast<uint16_t>(std::get<1>(record)));
        put32(bytes, std::get<2>(record));
    }
    return bytes;
}

// A Property Context: the BTHHEADER ([MS-PST] 2.3.3.6) at HID 0x20, its record array at HID 0x40,
// then the value allocations the records name. HID 0x20 is the first allocation because hidIndex is
// 1-based
// ([MS-PST] 2.3.1.1), so the order of this list is the order the HNPAGEMAP describes.
std::vector<uint8_t>
pc_block(const std::vector<std::tuple<int, int, uint32_t>>& records,
         const std::vector<std::pair<uint32_t, std::vector<uint8_t>>>& values) {
    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> allocations;
    allocations.emplace_back(0x20, bth_header(2, 6, 0x40));
    allocations.emplace_back(0x40, pc_records(records));
    for (const auto& value : values) {
        allocations.push_back(value);
    }
    return make_hn(ltp::kClientSigPc, 0x20, allocations);
}

// A Table Context in the shape a real one has: PidTagLtpRowId at ibData 0 iBit 0 and
// PidTagLtpRowVer at ibData 4 iBit 1 ([MS-PST] 2.3.4.4.1), rgTCOLDESC sorted by tag
// ([MS-PST] 2.3.4.1), rgib derived from the columns so the row size always matches the row bytes
// the fixture writes, the RowIndex BTH
// ([MS-PST] 2.3.4.3.1), and the Row Matrix either as a heap allocation or absent because it lives
// in a subnode ([MS-PST] 2.3.4 / 2.3.4.4).
std::vector<uint8_t> tc_header(uint8_t columns, uint32_t hnid_rows,
                               const std::vector<std::tuple<uint32_t, int, int, int>>& cols) {
    // [MS-PST] 2.3.4.1: rgib holds the ending offset of the 4-byte group, then of the 2-byte group,
    // then of the 1-byte group, then of the Cell Existence Block, which is CEIL(cCols / 8) bytes
    // ([MS-PST] 2.3.4.4.1). The fixture only uses 4-byte columns, so the three group ends coincide.
    int end_4b = 0;
    int end_2b = 0;
    int end_1b = 0;
    for (const auto& column : cols) {
        const int ib_data = std::get<1>(column);
        const int cb_data = std::get<2>(column);
        const int end = ib_data + cb_data;
        if (cb_data == 4 || cb_data == 8) {
            end_4b = std::max(end_4b, end);
        } else if (cb_data == 2) {
            end_2b = std::max(end_2b, end);
        } else {
            end_1b = std::max(end_1b, end);
        }
    }
    end_2b = std::max(end_2b, end_4b);
    end_1b = std::max(end_1b, end_2b);
    const int ceb_bytes = (columns + 7) / 8;

    std::vector<uint8_t> header;
    header.push_back(ltp::kClientSigTc);
    header.push_back(columns);
    put16(header, static_cast<uint16_t>(end_4b));
    put16(header, static_cast<uint16_t>(end_2b));
    put16(header, static_cast<uint16_t>(end_1b));
    put16(header, static_cast<uint16_t>(end_1b + ceb_bytes));
    put32(header, 0x40);      // hidRowIndex
    put32(header, hnid_rows); // hnidRows
    put32(header, 0);
    for (const auto& column : cols) {
        put32(header, std::get<0>(column));
        put16(header, static_cast<uint16_t>(std::get<1>(column)));
        header.push_back(static_cast<uint8_t>(std::get<2>(column)));
        header.push_back(static_cast<uint8_t>(std::get<3>(column)));
    }
    return header;
}

std::vector<uint8_t> row_index_records(const std::vector<uint32_t>& row_ids) {
    std::vector<uint8_t> bytes;
    uint32_t index = 0;
    for (const uint32_t row_id : row_ids) {
        put32(bytes, row_id);
        put32(bytes, index++);
    }
    return bytes;
}

// One row of the fixture's Attachment Table: 0x67F2 at ibData 0, 0x67F3 at ibData 4, 0x0E20 at
// ibData 8, 0x3704 at ibData 12 (a HNID, because PtypString is variable-sized), 0x3705 at ibData
// 16, then the CEB with iBits 0..4 set.
std::vector<uint8_t> attachment_row(uint32_t row_id, uint32_t size, uint32_t name_hnid,
                                    uint32_t method) {
    std::vector<uint8_t> row;
    put32(row, row_id);
    put32(row, 0);
    put32(row, size);
    put32(row, name_hnid);
    put32(row, method);
    row.push_back(0xF8);
    return row;
}

// One row of the fixture's Recipient Table: 0x67F2, 0x67F3, 0x0FFF (EntryID, a HNID), 0x3001 (a
// HNID), CEB with iBits 0..3 set.
std::vector<uint8_t> recipient_row(uint32_t row_id, uint32_t entry_id_hnid, uint32_t name_hnid) {
    std::vector<uint8_t> row;
    put32(row, row_id);
    put32(row, 0);
    put32(row, entry_id_hnid);
    put32(row, name_hnid);
    row.push_back(0xF0);
    return row;
}

std::vector<uint8_t>
attachment_tc_block(const std::vector<uint32_t>& row_ids,
                    const std::vector<std::vector<uint8_t>>& rows, uint32_t hnid_rows,
                    uint32_t matrix_hid,
                    const std::vector<std::pair<uint32_t, std::vector<uint8_t>>>& values = {}) {
    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> allocations;
    allocations.emplace_back(0x20, tc_header(5, hnid_rows,
                                             {
                                                 {0x0E200003, 8, 4, 2},
                                                 {0x3704001F, 12, 4, 3},
                                                 {0x37050003, 16, 4, 4},
                                                 {0x67F20003, 0, 4, 0},
                                                 {0x67F30003, 4, 4, 1},
                                             }));
    allocations.emplace_back(0x40, bth_header(4, 4, row_ids.empty() ? 0 : 0x60));
    allocations.emplace_back(0x60, row_index_records(row_ids));
    if (matrix_hid != 0) {
        std::vector<uint8_t> matrix;
        for (const auto& row : rows) {
            matrix.insert(matrix.end(), row.begin(), row.end());
        }
        allocations.emplace_back(matrix_hid, matrix);
    }
    for (const auto& value : values) {
        allocations.push_back(value);
    }
    return make_hn(ltp::kClientSigTc, 0x20, allocations);
}

std::vector<uint8_t>
recipient_tc_block(const std::vector<uint32_t>& row_ids,
                   const std::vector<std::vector<uint8_t>>& rows,
                   const std::vector<std::pair<uint32_t, std::vector<uint8_t>>>& values) {
    std::vector<uint8_t> matrix;
    for (const auto& row : rows) {
        matrix.insert(matrix.end(), row.begin(), row.end());
    }
    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> allocations;
    allocations.emplace_back(0x20, tc_header(4, 0x80,
                                             {
                                                 {0x0FFF0102, 8, 4, 2},
                                                 {0x3001001F, 12, 4, 3},
                                                 {0x67F20003, 0, 4, 0},
                                                 {0x67F30003, 4, 4, 1},
                                             }));
    allocations.emplace_back(0x40, bth_header(4, 4, row_ids.empty() ? 0 : 0x60));
    allocations.emplace_back(0x60, row_index_records(row_ids));
    allocations.emplace_back(0x80, matrix);
    for (const auto& value : values) {
        allocations.push_back(value);
    }
    return make_hn(ltp::kClientSigTc, 0x20, allocations);
}

// An SLBLOCK ([MS-PST] 2.2.2.8.3.3.1.2): bType 0x02, cLevel 0, cEnt, dwPadding 0, then one SLENTRY
// each.
std::vector<uint8_t>
sl_block(const std::vector<std::tuple<uint64_t, uint64_t, uint64_t>>& entries) {
    std::vector<uint8_t> bytes;
    bytes.push_back(0x02);
    bytes.push_back(0);
    put16(bytes, static_cast<uint16_t>(entries.size()));
    put32(bytes, 0);
    for (const auto& entry : entries) {
        put64(bytes, std::get<0>(entry));
        put64(bytes, std::get<1>(entry));
        put64(bytes, std::get<2>(entry));
    }
    return bytes;
}

class FakeBlocks : public BlockSource {
  public:
    void add(uint64_t bid, const std::vector<uint8_t>& bytes) { blocks_[bid] = bytes; }

    // [MS-PST] 2.2.2.8.3 says an SLBLOCK is an Internal block, so a subnode BTree has to be indexed
    // with bit B set ([MS-PST] 2.2.2.2) or the reader reports the index contradicting the block.
    void add_internal(uint64_t bid, const std::vector<uint8_t>& bytes) {
        blocks_[bid] = bytes;
        internal_.insert(bid);
    }

    Result<ltp::BlockBytes> block(uint64_t bid) override {
        const auto found = blocks_.find(bid);
        if (found == blocks_.end()) {
            return make_error(ErrorKind::kUnsupported, "BBTENTRY.bid", 0, bid,
                              "this test has no such block");
        }
        return ltp::BlockBytes{ByteView(found->second.data(), found->second.size(), bid * 512),
                               internal_.count(bid) != 0, false};
    }

  private:
    std::map<uint64_t, std::vector<uint8_t>> blocks_;
    std::set<uint64_t> internal_;
};

// The fixture's NIDs. A Folder object is one PC and three tables under one nidIndex
// ([MS-PST] 2.4.4.3); a Message object's nidParent is that PC's NID ([MS-PST] 2.4.5.2); the tables
// inside a Message object hang under the internal NIDs [MS-PST] 2.4.5.3.1 and 2.4.6.1.1 name; a raw
// value subnode carries nidType NID_TYPE_LTP, which is what the sample's 60,141 such subnodes
// carry.
constexpr uint32_t kFolder = 0x122;    // nidIndex 9, NID_TYPE_NORMAL_FOLDER
constexpr uint32_t kMessageA = 0x2004; // nidIndex 0x100, NID_TYPE_NORMAL_MESSAGE
constexpr uint32_t kMessageB = 0x2024; // nidIndex 0x101
constexpr uint32_t kMessageC = 0x2044; // nidIndex 0x102
constexpr uint32_t kFaiD = 0x2068; // nidIndex 0x103, NID_TYPE_ASSOC_MESSAGE: not a normal message
constexpr uint32_t kAttachmentA =
    0x2005; // nidIndex 0x100, NID_TYPE_ATTACHMENT: a subnode, not an NBT entry
constexpr uint32_t kAttachmentB = 0x2025;
constexpr uint32_t kAttachmentC = 0x2045;
constexpr uint32_t kRecipientRow =
    0x4C7; // [MS-PST] 2.3.4.3 leaves the row key to the implementation
constexpr uint32_t kBodySubnode = 0x907F;    // nidIndex 0x483, NID_TYPE_LTP
constexpr uint32_t kPayloadSubnode = 0x909F; // nidIndex 0x484, NID_TYPE_LTP
constexpr uint32_t kMatrixSubnode = 0x3F;    // nidIndex 1, NID_TYPE_LTP: the Row Matrix subnode
constexpr uint32_t kEmbeddedMessage =
    0x20A4;                             // nidIndex 0x105, NID_TYPE_NORMAL_MESSAGE: the Message an
                                        // Attachment object's 0x3701 names ([MS-PST] 2.4.6.2.2)
constexpr uint32_t kEmbeddedPcBid = 32; // the attached Message object's Property Context
constexpr uint32_t kEmbeddedSubnodeBid = 31; // the Attachment object's subnode BTree that names it
constexpr uint32_t kNidAttachmentTable = 0x671;
constexpr uint32_t kNidRecipientTable = 0x692;

constexpr uint32_t kAttachmentAPayloadBytes = 14;
constexpr uint32_t kAttachmentBPayloadBytes = 20;

std::vector<uint8_t> attachment_payload() {
    return bytes_of(
        {0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34, 0x0a, 0x25, 0x44, 0x46, 0x45, 0x4f});
}

std::vector<uint8_t> subnode_payload() {
    std::vector<uint8_t> bytes;
    for (uint32_t index = 0; index < kAttachmentBPayloadBytes; ++index) {
        bytes.push_back(static_cast<uint8_t>(0xA0 + index));
    }
    return bytes;
}

// [MS-PST] 2.3.3.5: a PtypObject value is an 8-byte allocation holding Nid, then ulSize.
std::vector<uint8_t> object_allocation(uint32_t nid, uint32_t ul_size) {
    std::vector<uint8_t> bytes;
    put32(bytes, nid);
    put32(bytes, ul_size);
    return bytes;
}

void add_node(NidMap& nodes, uint64_t index, uint32_t nid_type, uint64_t bid_data, uint64_t bid_sub,
              uint64_t parent) {
    nodes.add(
        NbtEntry{ltp::make_nid(index, nid_type), bid_data, bid_sub, static_cast<uint32_t>(parent)});
}

struct Fixture {
    ltp::LtpReadReport census;
    FakeBlocks blocks;
};

void build_fixture(Fixture& fixture) {
    NidMap& nodes = fixture.census.nodes;
    fixture.census.profile = kProfile;

    add_node(nodes, 9, ltp::kNidTypeNormalFolder, 1, 0, 0);
    add_node(nodes, 0x100, ltp::kNidTypeNormalMessage, 10, 14, kFolder);
    add_node(nodes, 0x101, ltp::kNidTypeNormalMessage, 15, 16, kFolder);
    add_node(nodes, 0x102, ltp::kNidTypeNormalMessage, 22, 23, kFolder);
    add_node(nodes, 0x103, ltp::kNidTypeAssocMessage, 28, 0, kFolder);

    // The one named property the fixture carries, as the Name-to-ID Map reports it
    // ([MS-PST] 2.4.7.1).
    ltp::NamedProperty named;
    named.npid = 0x8000;
    named.guid_index = 1;
    named.guid_kind = ltp::NameIdGuidKind::kMapi;
    named.guid_resolved = true;
    named.guid = bytes_of({0x00, 0x06, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x46});
    named.n_bit_set = true;
    named.name_is_string = true;
    named.name = u"CustomFlag";
    named.name_resolved = true;
    fixture.census.name_id_map.entries.push_back(named);
    fixture.census.npm_read = true;
    fixture.census.named_properties = 1;

    // The Folder object: 0x3001 is a MUST ([MS-PST] 2.4.4.1.1) and the counts are the ones M5
    // emits.
    fixture.blocks.add(
        1,
        pc_block(
            {{0x3001, 0x001F, 0x60}, {0x3602, 0x0003, 3}, {0x3603, 0x0003, 0}, {0x360A, 0x0003, 0}},
            {{0x60, utf16_text("Inbox")}}));

    // Message A: every [MS-PST] 2.4.5.1.1 required tag, a body whose value is a subnode, a named
    // property, and an EntryID the writer regenerates rather than copies.
    fixture.blocks.add(
        10, pc_block({{0x001A, 0x001F, 0x60},
                      {0x0E07, 0x0003, 1},
                      {0x0E08, 0x0003, 0},
                      {0x0E17, 0x0003, 1},
                      {0x1000, 0x001F, kBodySubnode},
                      {0x3007, 0x001F, 0x80},
                      {0x3008, 0x001F, 0xA0},
                      {0x300B, 0x001F, 0xC0},
                      {0x8000, 0x001F, 0xE0},
                      {0x0FFF, 0x0102, 0x100}},
                     {{0x60, utf16_text("Subject A")},
                      {0x80, utf16_text("sender@example.com")},
                      {0xA0, utf16_text("Sender")},
                      {0xC0, utf16_text("SMTP:sender@example.com")},
                      {0xE0, utf16_text("flag value")},
                      {0x100, bytes_of({0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
                                        0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                                        0x0D, 0x0E, 0x0F, 0x10, 0x04, 0x20, 0x00, 0x00})}}));
    fixture.blocks.add_internal(14, sl_block({{kNidAttachmentTable, 11, 0},
                                              {kNidRecipientTable, 12, 0},
                                              {kAttachmentA, 13, 0},
                                              {kAttachmentB, 18, 29},
                                              {kBodySubnode, 19, 0}}));
    fixture.blocks.add(
        11, attachment_tc_block({kAttachmentA, kAttachmentB},
                                {attachment_row(kAttachmentA, 707, 0xA0, 1),
                                 attachment_row(kAttachmentB, 4096, 0xC0, 1)},
                                0x80, 0x80,
                                {{0xA0, utf16_text("note.pdf")}, {0xC0, utf16_text("logo.png")}}));
    fixture.blocks.add(
        12, recipient_tc_block({kRecipientRow}, {recipient_row(kRecipientRow, 0xA0, 0xC0)},
                               {{0xA0, bytes_of({0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
                                                 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                                                 0x0D, 0x0E, 0x0F, 0x10, 0x05, 0x20, 0x00, 0x00})},
                                {0xC0, utf16_text("Recipient")}}));
    fixture.blocks.add(13,
                       pc_block({{0x0E20, 0x0003, 707},
                                 {0x3704, 0x001F, 0x60},
                                 {0x3705, 0x0003, 1},
                                 {0x370B, 0x0003, 0},
                                 {0x3701, 0x0102, 0x80}},
                                {{0x60, utf16_text("note.pdf")}, {0x80, attachment_payload()}}));
    fixture.blocks.add(18, pc_block({{0x0E20, 0x0003, 4096},
                                     {0x3704, 0x001F, 0x60},
                                     {0x3705, 0x0003, 1},
                                     {0x370B, 0x0003, 0},
                                     {0x3701, 0x0102, kPayloadSubnode}},
                                    {{0x60, utf16_text("logo.png")}}));
    fixture.blocks.add(19, utf16_text("Body A"));
    fixture.blocks.add(20, subnode_payload());
    // The payload subnode hangs under the Attachment object's own bidSub, which is where the
    // sample's attachment data sits too
    // (DEVELOPMENT.md).
    fixture.blocks.add_internal(29, sl_block({{kPayloadSubnode, 20, 0}}));

    // Message B: a body and a subject, and none of the other [MS-PST] 2.4.5.1.1 required tags. It
    // shares the Recipient Table block with message A, which is what a real OST does when one table
    // serves one row.
    fixture.blocks.add(15,
                       pc_block({{0x001A, 0x001F, 0x60}, {0x1000, 0x001F, 0x80}},
                                {{0x60, utf16_text("Subject B")}, {0x80, utf16_text("Body B")}}));
    fixture.blocks.add_internal(16, sl_block({{kNidRecipientTable, 12, 0}}));

    // Message C: no Recipient Table subnode at all ([MS-PST] 2.4.5 marks it Required: Y), an
    // Attachment Table whose Row Matrix lives in a subnode of the table node ([MS-PST] 2.3.4.4),
    // and an Attachment object whose 0x3701 is present with dwValueHnid 0, which [MS-PST] 2.3.3.2
    // says means the property has no value.
    fixture.blocks.add(22,
                       pc_block({{0x001A, 0x001F, 0x60},
                                 {0x0E07, 0x0003, 1},
                                 {0x0E08, 0x0003, 0},
                                 {0x0E17, 0x0003, 1},
                                 {0x3007, 0x001F, 0x60},
                                 {0x3008, 0x001F, 0x60},
                                 {0x300B, 0x001F, 0x60},
                                 {0x1009, 0x0102, 0x80}},
                                {{0x60, utf16_text("Subject C")},
                                 {0x80, bytes_of({0x7B, 0x5C, 0x72, 0x74, 0x66, 0x31, 0x5C})}}));
    fixture.blocks.add_internal(23,
                                sl_block({{kNidAttachmentTable, 24, 27}, {kAttachmentC, 25, 0}}));
    fixture.blocks.add(
        24, attachment_tc_block({kAttachmentC}, {attachment_row(kAttachmentC, 100, 0x80, 1)},
                                kMatrixSubnode, 0, {{0x80, utf16_text("doc.xlsx")}}));
    fixture.blocks.add_internal(27, sl_block({{kMatrixSubnode, 26, 0}}));
    fixture.blocks.add(26, attachment_row(kAttachmentC, 100, 0x80, 1));
    fixture.blocks.add(25, pc_block({{0x0E20, 0x0003, 100},
                                     {0x3704, 0x001F, 0x60},
                                     {0x3705, 0x0003, 1},
                                     {0x370B, 0x0003, 0},
                                     {0x3701, 0x0102, 0}},
                                    {{0x60, utf16_text("doc.xlsx")}}));

    // The FAI entry: an NBT entry under the same nidParent, but nidType NID_TYPE_ASSOC_MESSAGE, so
    // it is not one of the folder's messages.
    fixture.blocks.add(28, pc_block({{0x001A, 0x001F, 0x60}}, {{0x60, utf16_text("IPM.Note")}}));
}

// Attachment A of message A becomes an attachment that is itself a Message: 0x3705 is 5, 0x3701 is
// a PtypObject naming a Message subnode of the Attachment object, and the Attachment object gets a
// subnode BTree that holds that subnode ([MS-PST] 2.4.6.2.2, 2.3.3.5).
void attachment_a_becomes_an_embedded_message(Fixture& fixture) {
    fixture.blocks.add(13, pc_block({{0x0E20, 0x0003, 14},
                                     {0x3704, 0x001F, 0x60},
                                     {0x3705, 0x0003, 5},
                                     {0x370B, 0x0003, 0},
                                     {0x3701, 0x000D, 0x80}},
                                    {{0x60, utf16_text("fwd: note.eml")},
                                     {0x80, object_allocation(kEmbeddedMessage, 14)}}));
    fixture.blocks.add_internal(14, sl_block({{kNidAttachmentTable, 11, 0},
                                              {kNidRecipientTable, 12, 0},
                                              {kAttachmentA, 13, kEmbeddedSubnodeBid},
                                              {kAttachmentB, 18, 29},
                                              {kBodySubnode, 19, 0}}));
    fixture.blocks.add_internal(kEmbeddedSubnodeBid,
                                sl_block({{kEmbeddedMessage, kEmbeddedPcBid, 0}}));
    fixture.blocks.add(kEmbeddedPcBid, pc_block({{0x001A, 0x001F, 0x60}, {0x1000, 0x001F, 0x80}},
                                                {{0x60, utf16_text("Embedded subject")},
                                                 {0x80, utf16_text("Embedded body")}}));
}

SubsetReport run(const SubsetOptions& options = {}) {
    Fixture fixture;
    build_fixture(fixture);
    Result<SubsetReport> built = build_subset(fixture.census, fixture.blocks, kFolder, options);
    if (!built.ok()) {
        ost2pst::test::report_failure(__FILE__, __LINE__,
                                      "build_subset failed: " + util::format_error(built.error()));
        return {};
    }
    return built.take();
}

// The same fixture with one thing broken, so a test can name which counter moved instead of
// guessing from a report that differs in a dozen places.
SubsetReport run_with(const std::function<void(Fixture&)>& change,
                      const SubsetOptions& options = {}) {
    Fixture fixture;
    build_fixture(fixture);
    change(fixture);
    Result<SubsetReport> built = build_subset(fixture.census, fixture.blocks, kFolder, options);
    if (!built.ok()) {
        ost2pst::test::report_failure(__FILE__, __LINE__,
                                      "build_subset failed: " + util::format_error(built.error()));
        return {};
    }
    return built.take();
}

const SubsetMessage* find_message(const SubsetReport& report, uint64_t nid) {
    for (const SubsetMessage& message : report.messages) {
        if (message.nid == nid) {
            return &message;
        }
    }
    ost2pst::test::report_failure(__FILE__, __LINE__,
                                  "the report carries no message 0x" + std::to_string(nid));
    return nullptr;
}

const SubsetValue* find_value(const std::vector<SubsetValue>& values, uint16_t prop_id) {
    for (const SubsetValue& value : values) {
        if (value.prop_id == prop_id) {
            return &value;
        }
    }
    return nullptr;
}

const SubsetAttachment* find_attachment(const SubsetMessage& message, uint64_t subnode_nid) {
    for (const SubsetAttachment& attachment : message.attachments) {
        if (attachment.subnode_nid == subnode_nid) {
            return &attachment;
        }
    }
    ost2pst::test::report_failure(
        __FILE__, __LINE__, "the message carries no attachment 0x" + std::to_string(subnode_nid));
    return nullptr;
}

// The two-block Row Matrix fixture ([MS-PST] 2.3.4.4). The reader is checked on the OST profile,
// where one data block carries 65,512 raw bytes, and 17-byte rows leave 11 bytes at the end of a
// full block that no row occupies -- the dead space the same section says a reader MUST ignore.
constexpr uint32_t kMatrixSubnode2 =
    0x90BF; // nidIndex 0x485, NID_TYPE_LTP: the second matrix subnode
constexpr uint64_t kTwoBlockFullBytes =
    65512; // ndb::block_max_cb(kOst) ([MS-PST] 2.2.2.8, OST profile)
constexpr uint64_t kTwoBlockRowBytes =
    17; // four 4-byte columns plus the 1-byte CEB ([MS-PST] 2.3.4.4.1)
constexpr uint32_t kTwoBlockRowsInFull = 3853; // Floor(65512 / 17) whole rows, 11 bytes left over
constexpr uint64_t kTwoBlockXBlockBid = 42; // bit B set: the jump table the subnode's bidData names
constexpr uint64_t kTwoBlockFirstBid = 40;
constexpr uint64_t kTwoBlockSecondBid = 44;
constexpr uint64_t kTwoBlockSubnodeBTreeBid = 30;

// One Row Matrix row of this fixture. 0x67F2 carries a marker naming which row of the matrix it is,
// so a test can tell which block the reader took the row out of instead of trusting a byte offset.
std::vector<uint8_t> matrix_row(uint32_t marker) {
    std::vector<uint8_t> row;
    put32(row, marker);
    put32(row, 0);
    put32(row, 0x80);
    put32(row, 0xA0);
    row.push_back(0xF0); // CEB with iBits 0..3 set, as recipient_row writes it
    return row;
}

// An XBLOCK ([MS-PST] 2.2.2.8.3.2.1): bType 1, cLevel 1, cEnt, lcbTotal, then the BID of each data
// block.
std::vector<uint8_t> jump_table(uint8_t level, const std::vector<uint64_t>& bids,
                                uint32_t lcb_total) {
    std::vector<uint8_t> bytes;
    bytes.push_back(0x01);
    bytes.push_back(level);
    put16(bytes, static_cast<uint16_t>(bids.size()));
    put32(bytes, lcb_total);
    for (const uint64_t bid : bids) {
        put64(bytes, bid);
    }
    return bytes;
}

// A Recipient Table whose Row Matrix is a subnode of the Table Context instead of a heap allocation
// ([MS-PST] 2.3.4.1 / 2.3.4.4). The RowIndex pairs are given so a test can name a row past the
// first block.
std::vector<uint8_t>
recipient_tc_matrix_subnode(const std::vector<std::pair<uint32_t, uint32_t>>& rows,
                            uint32_t matrix_nid,
                            const std::vector<std::pair<uint32_t, std::vector<uint8_t>>>& values) {
    std::vector<uint8_t> index;
    for (const auto& row : rows) {
        put32(index, row.first);
        put32(index, row.second);
    }
    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> allocations;
    allocations.emplace_back(0x20, tc_header(4, matrix_nid,
                                             {
                                                 {0x0FFF0102, 8, 4, 2},
                                                 {0x3001001F, 12, 4, 3},
                                                 {0x67F20003, 0, 4, 0},
                                                 {0x67F30003, 4, 4, 1},
                                             }));
    allocations.emplace_back(0x40, bth_header(4, 4, rows.empty() ? 0 : 0x60));
    allocations.emplace_back(0x60, index);
    for (const auto& value : values) {
        allocations.push_back(value);
    }
    return make_hn(ltp::kClientSigTc, 0x20, allocations);
}

std::vector<uint8_t> matrix_rows(uint32_t first_row, uint32_t count) {
    std::vector<uint8_t> bytes;
    for (uint32_t index = 0; index < count; ++index) {
        const std::vector<uint8_t> row = matrix_row(0x9000 + first_row + index);
        bytes.insert(bytes.end(), row.begin(), row.end());
    }
    return bytes;
}

void two_block_matrix_fixture(Fixture& fixture, uint64_t first_block_bytes) {
    // The Row Matrix lives in a subnode here, so the Table Context heap has no matrix allocation
    // and the two value allocations land at HID 0x80 and HID 0xA0 ([MS-PST] 2.3.1.5: the map
    // numbers allocations in order from hidUserRoot 0x20).
    fixture.blocks.add(12, recipient_tc_matrix_subnode(
                               {{kRecipientRow, 0}, {0x4C8, kTwoBlockRowsInFull}}, kMatrixSubnode2,
                               {{0x80, bytes_of({0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
                                                 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                                                 0x0D, 0x0E, 0x0F, 0x10, 0x05, 0x20, 0x00, 0x00})},
                                {0xA0, utf16_text("Recipient")}}));
    fixture.blocks.add_internal(14, sl_block({{kNidAttachmentTable, 11, 0},
                                              {kNidRecipientTable, 12, kTwoBlockSubnodeBTreeBid},
                                              {kAttachmentA, 13, 0},
                                              {kAttachmentB, 18, 29},
                                              {kBodySubnode, 19, 0}}));
    fixture.blocks.add_internal(kTwoBlockSubnodeBTreeBid,
                                sl_block({{kMatrixSubnode2, kTwoBlockXBlockBid, 0}}));
    fixture.blocks.add_internal(
        kTwoBlockXBlockBid,
        jump_table(1, {kTwoBlockFirstBid, kTwoBlockSecondBid},
                   static_cast<uint32_t>(first_block_bytes + 2 * kTwoBlockRowBytes)));
    std::vector<uint8_t> first = matrix_rows(0, kTwoBlockRowsInFull);
    first.resize(static_cast<size_t>(first_block_bytes), 0xEE);
    fixture.blocks.add(kTwoBlockFirstBid, first);
    fixture.blocks.add(kTwoBlockSecondBid, matrix_rows(kTwoBlockRowsInFull, 2));
}

// [MS-PST] 2.3.4.4: "each data block MUST store an integral number of rows, which means that rows
// cannot span across two blocks, and that each block MUST start with a fresh row", and every block
// but the last is a full block. A row past the first block therefore has to be found by which block
// holds it; multiplying dwRowIndex by the row width across a concatenation of the blocks lands in
// the dead space instead.
void test_a_row_in_the_second_matrix_block_reads_from_that_block() {
    const SubsetReport report =
        run_with([](Fixture& fixture) { two_block_matrix_fixture(fixture, kTwoBlockFullBytes); });
    TEST_EQ(report.rows_without_cells, 0, "no RowIndex row fell outside the rows its block holds");
    const SubsetMessage* message = find_message(report, kMessageA);
    if (message == nullptr) {
        return;
    }
    TEST_CHECK_MSG(message->recipient_table_read,
                   "the Recipient Table read through a Row Matrix spread over two data blocks");
    TEST_EQ(message->recipients.size(), 2, "both RowIndex rows came back");
    if (message->recipients.size() != 2) {
        return;
    }
    const SubsetValue* first = find_value(message->recipients[0].values, 0x67F2);
    TEST_CHECK_MSG(first != nullptr && first->readable,
                   "the first row read out of the first block");
    if (first != nullptr) {
        TEST_EQ(first->declared_bytes, 0x9000u,
                "dwRowIndex 0 is the row the first block starts with");
    }
    const SubsetValue* second = find_value(message->recipients[1].values, 0x67F2);
    TEST_CHECK_MSG(second != nullptr && second->readable, "the row past the first block read");
    if (second != nullptr) {
        TEST_EQ(second->declared_bytes, 0x9000u + kTwoBlockRowsInFull,
                "dwRowIndex names the row the second block starts with, not a byte offset past the "
                "first block");
    }
    const SubsetValue* name = find_value(message->recipients[1].values, 0x3001);
    TEST_CHECK_MSG(name != nullptr && name->readable,
                   "the variable-sized column of that row resolved");
    if (name != nullptr) {
        TEST_STR(utf8_of(name->bytes), "Recipient", "through the Table Context node's heap");
    }
    // Message B shares the same Table Context block but its own subnode list names no subnode BTree
    // for it, so its Recipient Table cannot be read: a failed read, counted as one.
    TEST_EQ(report.recipients_read, 2, "the two rows this reader could reach");
    TEST_EQ(report.recipient_table_failures, 1,
            "the table whose Row Matrix subnode its node does not hold is a failure, not an absent "
            "table");
}

// A nonfinal block that is not a full block is the corruption [MS-PST] 2.3.4.4 names. The reader
// counts it and says which rule the block breaks instead of smoothing the geometry over.
void test_a_short_nonfinal_matrix_block_is_counted() {
    const SubsetReport report = run_with([](Fixture& fixture) {
        two_block_matrix_fixture(fixture, kTwoBlockFullBytes - kTwoBlockRowBytes);
    });
    TEST_EQ(report.matrix_short_blocks, 1, "the first of the two blocks is short of a full block");
    TEST_CHECK_MSG(!report.notes.empty(), "the shortfall is named in the report");
    bool cited = false;
    for (const std::string& note : report.notes) {
        if (note.find("[MS-PST] 2.3.4.4") != std::string::npos &&
            note.find(std::to_string(kTwoBlockFullBytes)) != std::string::npos) {
            cited = true;
        }
    }
    TEST_CHECK_MSG(cited, "the note names the section and the block size the rule asks for");
}

// The folder and the Message objects under it, counted the way [MS-PST] 2.4.5.2 counts them: by
// nidParent.
void test_folder_and_its_messages_are_enumerated() {
    const SubsetReport report = run();
    TEST_EQ(report.folder.nid, kFolder, "the folder the caller named");
    TEST_CHECK_MSG(report.folder.pc_read, "the Folder object PC read");
    TEST_STR(report.folder.name, "Inbox", "0x3001 PidTagDisplayName read off the Folder object PC");
    TEST_EQ(report.folder_children, 3,
            "NBT entries naming this folder as their nidParent ([MS-PST] 2.4.5.2)");
    TEST_EQ(report.messages_read, 3, "the folder's Message objects");
    TEST_EQ(report.messages_skipped, 0, "none of them skipped");
    TEST_EQ(report.messages.size(), 3,
            "and the FAI entry under the same nidParent is not one of them");
    TEST_CHECK_MSG(!report.capped, "no cap was reached");
    TEST_CHECK_MSG(report.messages[0].nid == kMessageA && report.messages[1].nid == kMessageB &&
                       report.messages[2].nid == kMessageC,
                   "the folder's messages come out in NID order");
}

// Every value the fixture holds is carried as the bytes the source has, and the two kinds of "no
// value" stay apart: dwValueHnid 0 is absent, an unresolvable HNID is unreadable.
void test_message_properties_are_carried() {
    const SubsetReport report = run();
    const SubsetMessage* message = find_message(report, kMessageA);
    if (message == nullptr) {
        return;
    }
    const SubsetValue* subject = find_value(message->values, 0x001A);
    TEST_CHECK_MSG(subject != nullptr && subject->readable,
                   "a heap value resolves through the node's own heap");
    if (subject != nullptr) {
        TEST_STR(utf8_of(subject->bytes), "Subject A",
                 "the bytes are carried as the source holds them");
        TEST_EQ(subject->tag, 0x001A001F,
                "a property tag is the property ID over the property type ([MS-PST] 1.1)");
    }
    const SubsetValue* body = find_value(message->values, 0x1000);
    TEST_CHECK_MSG(body != nullptr && body->readable,
                   "a value whose HNID names a subnode resolves");
    if (body != nullptr) {
        TEST_EQ(body->bytes.size(), 14,
                "the body came out of the subnode the PC names ([MS-PST] 2.3.3.2)");
        TEST_STR(utf8_of(body->bytes), "Body A",
                 "and is the subnode's own bytes, not a copy of a heap value");
    }
    const SubsetValue* entry_id = find_value(message->values, 0x0FFF);
    TEST_CHECK_MSG(entry_id != nullptr && entry_id->readable, "the EntryID bytes were read");
    TEST_CHECK_MSG(entry_id != nullptr && entry_id->writer_assigned,
                   "an EntryID is regenerated against the new Provider UID, never copied "
                   "(docs/DEVELOPMENT.md D7)");
    const SubsetValue* sender = find_value(message->values, 0x3007);
    TEST_CHECK_MSG(sender != nullptr && sender->readable, "the sender is carried");
    if (sender != nullptr) {
        TEST_STR(utf8_of(sender->bytes), "sender@example.com", "as a string value");
    }
    const SubsetValue* named = find_value(message->values, 0x8000);
    TEST_CHECK_MSG(named != nullptr && named->named,
                   "an NPID in 0x8000..0x8FFF is a named property ([MS-PST] 2.4.7.1)");
    if (named != nullptr) {
        TEST_CHECK_MSG(named->name_resolved, "the Name-to-ID Map says which property it is");
        TEST_CHECK_MSG(named->name == u"CustomFlag", "by its string name");
        TEST_CHECK_MSG(named->name_is_string, "the N bit as the map wrote it");
        TEST_EQ(named->guid_index, 1, "and the property set it belongs to");
        TEST_EQ(named->guid.size(), 16, "carried as 16 GUID bytes for the writer to re-register");
    }
    TEST_EQ(report.named_tags, 1, "one named identity carried");
    TEST_EQ(report.named_unresolved, 0, "and every NPID the fixture carries is in the map");
    TEST_EQ(report.values_read, 61, "every value the fixture holds came out as bytes");
    TEST_EQ(report.values_absent, 1, "one record is present with no value");
    TEST_EQ(report.unreadable_values, 0, "and none of them failed to resolve");
}

// The Recipient Table and Attachment Table rows, read through the Row Matrix and the CEB
// ([MS-PST] 2.3.4.4.3), and the Attachment objects the rows name ([MS-PST] 2.4.6.1.3).
void test_recipient_and_attachment_rows_are_read() {
    const SubsetReport report = run();
    TEST_EQ(report.recipients_read, 2, "one Recipient Table row for each message that carries one");
    TEST_EQ(report.messages_with_recipient_table, 2,
            "[MS-PST] 2.4.5 marks the Recipient Table Required: Y");
    TEST_EQ(report.messages_with_attachment_table, 2,
            "and 2.4.6.1 makes the Attachment Table optional");
    TEST_EQ(report.attachments_read, 3, "the Attachment Table rows and the objects they name");
    TEST_EQ(report.payload_bytes, kAttachmentAPayloadBytes + kAttachmentBPayloadBytes,
            "the 0x3701 bytes the source actually holds");
    TEST_EQ(report.max_payload_bytes, kAttachmentBPayloadBytes, "the largest single payload");
    TEST_EQ(report.attachments_without_payload, 1, "the one attachment whose 0x3701 has no value");

    const SubsetMessage* message = find_message(report, kMessageA);
    if (message == nullptr) {
        return;
    }
    TEST_EQ(message->subnode_entries, 5, "every SLENTRY of the Message object's subnode BTree");
    TEST_CHECK_MSG(message->subnodes_complete, "the list was enumerated to the end");
    TEST_CHECK_MSG(message->recipient_table_read,
                   "the Recipient Table hung under 0x0692 ([MS-PST] 2.4.5.3.1)");
    TEST_CHECK_MSG(message->attachment_table_read,
                   "the Attachment Table under 0x0671 ([MS-PST] 2.4.6.1.1)");
    TEST_EQ(message->recipients.size(), 1, "one recipient row");
    if (!message->recipients.empty()) {
        const SubsetRecipient& recipient = message->recipients[0];
        TEST_EQ(recipient.row_id, kRecipientRow, "the row's dwRowID");
        const SubsetValue* row_id = find_value(recipient.values, 0x67F2);
        TEST_CHECK_MSG(row_id != nullptr && row_id->readable,
                       "PidTagLtpRowId is a cell the row holds inline");
        TEST_CHECK_MSG(row_id != nullptr && row_id->writer_assigned,
                       "but it is the new row's own id, so the writer assigns it");
        const SubsetValue* name = find_value(recipient.values, 0x3001);
        TEST_CHECK_MSG(name != nullptr && name->readable,
                       "a variable-sized column resolves through the TC node ([MS-PST] 2.3.4.4.2)");
        if (name != nullptr) {
            TEST_STR(utf8_of(name->bytes), "Recipient",
                     "and the value is the string the source holds");
        }
        const SubsetValue* entry_id = find_value(recipient.values, 0x0FFF);
        TEST_CHECK_MSG(entry_id != nullptr && entry_id->readable && !entry_id->writer_assigned,
                       "the recipient's address-book EntryID remains source content");
        if (entry_id != nullptr) {
            TEST_EQ(entry_id->bytes.size(), 24u,
                    "the fixture's provider-defined EntryID bytes were read whole");
            TEST_EQ(entry_id->bytes.back(), 0u,
                    "the source EntryID was not replaced with the new row id");
        }
    }
    const SubsetAttachment* attachment = find_attachment(*message, kAttachmentA);
    TEST_CHECK_MSG(attachment->pc_read,
                   "the Attachment object the row names has its own Property Context");
    TEST_EQ(attachment->declared_bytes, 707, "0x0E20 as the source states it");
    TEST_CHECK_MSG(attachment->payload_read, "0x3701 as the source holds it");
    TEST_EQ(attachment->payload_bytes, kAttachmentAPayloadBytes,
            "the payload is the bytes, not the declared size");
    const SubsetValue* filename = find_value(attachment->values, 0x3704);
    if (filename != nullptr) {
        TEST_STR(utf8_of(filename->bytes), "note.pdf", "the Attachment object's own name");
    }
    const SubsetValue* row_filename = find_value(attachment->row_values, 0x3704);
    TEST_CHECK_MSG(
        row_filename != nullptr && row_filename->readable,
        "the row's own cells are kept so they can be compared against the object they name");
    if (row_filename != nullptr) {
        TEST_STR(utf8_of(row_filename->bytes), "note.pdf", "and they agree with it here");
    }
    const SubsetValue* size_cell = find_value(attachment->row_values, 0x0E20);
    TEST_CHECK_MSG(size_cell != nullptr && size_cell->readable,
                   "a fixed 4-byte column is inline in the row");
    TEST_EQ(size_cell != nullptr ? size_cell->declared_bytes : 0, 707,
            "read out of the Row Matrix");
}

// A Row Matrix that lives in a subnode of the Table Context node rather than in its heap
// ([MS-PST] 2.3.4.4), which is what the sample's folder Contents Tables do.
void test_a_row_matrix_in_a_subnode_is_read() {
    const SubsetReport report = run();
    const SubsetMessage* message = find_message(report, kMessageC);
    if (message == nullptr) {
        return;
    }
    TEST_CHECK_MSG(
        message->attachment_table_read,
        "the Attachment Table read although its Row Matrix is a subnode ([MS-PST] 2.3.4.4)");
    TEST_EQ(message->subnode_entries, 2,
            "the Table Context's own subnode list is a separate BTree");
    const SubsetAttachment* attachment = find_attachment(*message, kAttachmentC);
    TEST_EQ(attachment->declared_bytes, 100,
            "the row's 0x0E20 came out of the subnode's row bytes");
    const SubsetValue* row_name = find_value(attachment->row_values, 0x3704);
    TEST_CHECK_MSG(row_name != nullptr && row_name->readable,
                   "the row's variable-sized column resolved");
    if (row_name != nullptr) {
        TEST_STR(utf8_of(row_name->bytes), "doc.xlsx", "through the Table Context node's heap");
    }
    TEST_CHECK_MSG(!attachment->payload_read, "0x3701 is present with dwValueHnid 0");
    TEST_CHECK_MSG(
        attachment->note.find("dwValueHnid 0") != std::string::npos,
        "and the report says [MS-PST] 2.3.3.2's meaning instead of calling it empty content");
}

// What the source does not have is reported per item, not folded into a total.
void test_required_tags_and_body_forms_are_reported() {
    const SubsetReport report = run();
    TEST_EQ(report.required_missing, 6,
            "message B carries none of the other [MS-PST] 2.4.5.1.1 required tags");
    TEST_EQ(report.body_plain, 2, "two messages have a readable 0x1000 value");
    TEST_EQ(report.body_rtf, 1,
            "one has a readable 0x1009 value, a tag neither opened reference names");
    TEST_EQ(report.body_html, 0, "none has 0x1013");
    TEST_EQ(report.body_none, 0, "and no message is left without a body the writer could write");
    TEST_EQ(
        report.messages_without_recipient_table, 1,
        "one message has subnodes but no Recipient Table, which [MS-PST] 2.4.5 marks Required: Y");
    const SubsetMessage* message = find_message(report, kMessageB);
    if (message != nullptr) {
        TEST_STR(
            message->note,
            "Message PC does not carry [MS-PST] 2.4.5.1.1 required tags: 0x0E07, 0x0E08, 0x0E17, "
            "0x3007, 0x3008, 0x300B",
            "the missing tags are named on the item that is missing them");
    }
    const SubsetMessage* without = find_message(report, kMessageC);
    if (without != nullptr) {
        TEST_CHECK_MSG(!without->recipient_table, "no 0x0692 subnode exists to read");
    }
}

// The cap is a decision the report has to state, because the folder's own count says how short it
// came.
void test_the_message_cap_is_reported_not_silent() {
    SubsetOptions options;
    options.max_messages = 2;
    const SubsetReport report = run(options);
    TEST_CHECK_MSG(report.capped, "the cap stopped the folder short");
    TEST_EQ(report.messages_read, 2, "the first two Message objects in NID order");
    TEST_EQ(report.messages_skipped, 1, "and one that the cap left out");
    TEST_EQ(report.messages.size(), 2, "the report carries only what it read");
    TEST_EQ(report.folder_children, 3, "while the folder still says how many messages it holds");
    TEST_CHECK_MSG(!report.notes.empty(), "the cap is named in the report");
    TEST_CHECK_MSG(report.notes[0].find("the cap kept the first 2") != std::string::npos,
                   "with the count it kept and the count it skipped");
}

// Turning payload collection off still enumerates every attachment; it only declines to pull the
// bytes.
void test_payload_collection_can_be_turned_off() {
    SubsetOptions options;
    options.collect_payloads = false;
    const SubsetReport report = run(options);
    TEST_EQ(report.attachments_read, 3, "the attachments are still enumerated");
    TEST_EQ(report.attachments_without_payload, 3, "and none of them carries payload bytes");
    TEST_EQ(report.payload_bytes, 0, "nothing was read through the blocks");
    TEST_EQ(report.max_payload_bytes, 0, "so there is no largest payload to report");
}

// A dwRowIndex that names a row past the Row Matrix is "a field value exceeds what its referent
// allows", so it is reported as a decode problem instead of quietly shortening the table.
void test_a_row_index_past_the_matrix_is_reported() {
    const SubsetReport report =
        run_with([](Fixture& fixture) { fixture.blocks.add(26, bytes_of({0x00})); });
    TEST_EQ(report.rows_without_cells, 1, "the row whose bytes the truncated matrix cannot hold");
    const SubsetMessage* message = find_message(report, kMessageC);
    if (message != nullptr && !message->attachments.empty()) {
        TEST_CHECK_MSG(message->attachments[0].note.find("dwRowIndex") != std::string::npos,
                       "the row says which index named which byte of which matrix");
    }
    TEST_EQ(report.attachments_read, 3, "the attachment is still reported, with its cells missing");
}

// A 0x3701 PtypObject is content the source has: the reader reads the object reference it holds,
// and an object it cannot carry is a shortfall, not "unreadable" and not "absent from the source".
void test_an_undecoded_object_value_is_named_not_silently_empty() {
    const SubsetReport report = run_with([](Fixture& fixture) {
        fixture.blocks.add(
            13, pc_block({{0x0E20, 0x0003, 707},
                          {0x3704, 0x001F, 0x60},
                          {0x3705, 0x0003, 1},
                          {0x370B, 0x0003, 0},
                          {0x3701, 0x000D, 0x80}},
                         {{0x60, utf16_text("note.pdf")},
                          {0x80, bytes_of({0x7F, 0x90, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00})}}));
    });
    TEST_EQ(report.attachments_without_payload, 2, "the object form joins the one with no value");
    TEST_EQ(report.object_values, 1,
            "the PtypObject allocation the reader read ([MS-PST] 2.3.3.5)");
    TEST_EQ(report.object_values_carried, 0,
            "and did not carry: 0x3705 is 1, not the 5 of 2.4.6.2.2");
    TEST_EQ(report.attachments_with_unread_object, 1,
            "counted as an object the converter could not carry");
    TEST_EQ(report.unreadable_values, 0,
            "so it is not counted as a value whose content the reader missed");
    TEST_EQ(report.values_absent, 1, "and the kinds stay apart in the totals");
    const SubsetMessage* message = find_message(report, kMessageA);
    if (message != nullptr) {
        const SubsetAttachment* attachment = find_attachment(*message, kAttachmentA);
        TEST_CHECK_MSG(attachment->note.find("PtypObject") != std::string::npos,
                       "the reason names the form and the subnode it points at ([MS-PST] 2.3.3.5)");
    }
}

// [MS-PST] 2.4.6.1.3 says a row's dwRowID IS the Attachment object's subnode NID. A row that names
// a subnode the Message object does not hold is a defect of the source, and the converter reports
// it instead of inventing an attachment.
void test_an_attachment_row_that_names_no_subnode_is_reported() {
    const SubsetReport report = run_with([](Fixture& fixture) {
        fixture.blocks.add(
            11,
            attachment_tc_block(
                {kAttachmentA, kAttachmentB, 0x2085},
                {attachment_row(kAttachmentA, 707, 0xA0, 1),
                 attachment_row(kAttachmentB, 4096, 0xC0, 1), attachment_row(0x2085, 1, 0xA0, 1)},
                0x80, 0x80, {{0xA0, utf16_text("note.pdf")}, {0xC0, utf16_text("logo.png")}}));
    });
    TEST_EQ(report.attachments_read, 3,
            "only rows that name an Attachment object count, message C's included");
    TEST_EQ(report.attachments_without_payload, 2,
            "the orphan row and the dwValueHnid 0 row are both reported");
    const SubsetMessage* message = find_message(report, kMessageA);
    if (message != nullptr) {
        uint64_t matched = 0;
        for (const SubsetAttachment& attachment : message->attachments) {
            if (attachment.subnode_nid != 0) {
                ++matched;
            }
        }
        TEST_EQ(matched, 2, "two of this Message object's rows name an Attachment object it holds");
        TEST_EQ(message->attachments.size(), 3, "and the orphan row is still in the report");
        if (message->attachments.size() == 3) {
            TEST_CHECK_MSG(message->attachments[2].subnode_nid == 0,
                           "it names no Attachment object");
            TEST_CHECK_MSG(message->attachments[2].note.find("names no subnode") !=
                               std::string::npos,
                           "with the reason");
        }
    }
}

// [MS-PST] 2.4.6.2.2: an Attachment object whose 0x3701 is a PtypObject naming a Message subnode
// carries that Message as its content. The reader walks to the subnode the object names and reads
// it as a Message.
void test_an_attachment_that_is_a_message_is_read_as_one() {
    const SubsetReport report = run_with(attachment_a_becomes_an_embedded_message);
    TEST_EQ(report.attachments_embedded, 1, "one Attachment object carried an attached Message");
    TEST_EQ(report.object_values, 1,
            "the PtypObject allocation the reader read ([MS-PST] 2.3.3.5)");
    TEST_EQ(report.object_values_carried, 1, "and carried as the Message it names");
    TEST_EQ(report.attachments_with_unread_object, 0, "nothing an object named went unread");
    TEST_EQ(report.attachments_without_payload, 1,
            "only the dwValueHnid 0 attachment is left without content");
    TEST_EQ(report.messages_read, 3,
            "the folder\"@s own messages: an attached Message is not one of them");
    TEST_EQ(report.messages_without_recipient_table, 2,
            "and the attached Message is reported as a message too");

    const SubsetMessage* message = find_message(report, kMessageA);
    if (message == nullptr) {
        return;
    }
    const SubsetAttachment* attachment = find_attachment(*message, kAttachmentA);
    if (attachment == nullptr) {
        return;
    }
    TEST_CHECK_MSG(attachment->object_form, "0x3701 read as a PtypObject, not as bytes");
    TEST_EQ(attachment->object_nid, kEmbeddedMessage, "naming the subnode the allocation holds");
    TEST_EQ(attachment->object_ul_size, 14, "with the ulSize the source states for it");
    TEST_CHECK_MSG(attachment->embedded_read, "which this reader opened as a Property Context");
    TEST_EQ(attachment->embedded_nid, kEmbeddedMessage, "at the NID the object names");
    TEST_EQ(attachment->embedded.embedded_depth, 1,
            "one level below the Message object the NBT names");
    TEST_CHECK_MSG(attachment->embedded.pc_read,
                   "the attached Message read its own Property Context");
    TEST_EQ(attachment->payload_read ? 1u : 0u, 0u,
            "the object form is the payload, not a byte value");
    const SubsetValue* subject = find_value(attachment->embedded.values, 0x001A);
    TEST_CHECK_MSG(subject != nullptr, "the attached Message\"@s properties are in the report");
    if (subject != nullptr) {
        TEST_STR(utf8_of(subject->bytes), "Embedded subject", "read out of the subnode it names");
    }
    const SubsetValue* body = find_value(attachment->embedded.values, 0x1000);
    TEST_CHECK_MSG(body != nullptr && utf8_of(body->bytes) == "Embedded body", "and its body");
    TEST_CHECK_MSG(attachment->note.empty(), "so the attachment carries no failure note");
}

// A walk that stops at SubsetOptions::max_embedded_depth is a shortfall the report has to name, not
// an attachment the source has no content for.
void test_an_attached_message_past_the_depth_cap_is_a_shortfall() {
    SubsetOptions options;
    options.max_embedded_depth = 0;
    const SubsetReport report = run_with(attachment_a_becomes_an_embedded_message, options);
    TEST_EQ(report.attachments_embedded, 0,
            "the cap stopped the walk before it read the attached Message");
    TEST_EQ(report.attachments_with_unread_object, 1,
            "so the object the source has counts as not carried");
    TEST_EQ(report.object_values, 1, "the PtypObject was still read");
    TEST_EQ(report.object_values_carried, 0, "and not carried");
    TEST_EQ(report.attachments_without_payload, 2,
            "it joins the dwValueHnid 0 attachment as content not written");
    const SubsetMessage* message = find_message(report, kMessageA);
    if (message == nullptr) {
        return;
    }
    const SubsetAttachment* attachment = find_attachment(*message, kAttachmentA);
    if (attachment == nullptr) {
        return;
    }
    TEST_CHECK_MSG(attachment->note.find("max_embedded_depth") != std::string::npos,
                   "the note names the option that stopped the walk");
    TEST_CHECK_MSG(!attachment->embedded_read, "and the attached Message was not read");
}

void test_method6_object_data_is_carried_without_message_interpretation() {
    const auto payload = pc_block({{0x1000, 0x001F, 0x60}}, {{0x60, utf16_text("opaque bytes")}});
    for (const bool spill : {false, true}) {
        util::ValueSpool spool(std::filesystem::temp_directory_path().wstring(), 0, 0);
        msg::SubsetOptions options;
        options.spool = spill ? &spool : nullptr;
        const auto report = run_with(
            [&](Fixture& fixture) {
                attachment_a_becomes_an_embedded_message(fixture);
                fixture.blocks.add(
                    13,
                    pc_block({{0x0E20, 0x0003, 707},
                              {0x3705, 0x0003, 6},
                              {0x370B, 0x0003, 0},
                              {0x3701, 0x000D, 0x60}},
                             {{0x60, object_allocation(kEmbeddedMessage,
                                                       static_cast<uint32_t>(payload.size()))}}));
                fixture.blocks.add(kEmbeddedPcBid, payload);
            },
            options);
        TEST_EQ(report.object_values_carried, 1, "method 6 carries available object bytes");
        TEST_EQ(report.attachments_with_unread_object, 0,
                "a supported opaque object is not dropped");
        TEST_EQ(report.attachments_embedded, 0,
                "PC-shaped method-6 bytes are not interpreted as a Message");
        const auto* message = find_message(report, kMessageA);
        if (!message)
            return;
        const auto* attachment = find_attachment(*message, kAttachmentA);
        if (!attachment)
            return;
        TEST_CHECK(attachment->payload_read);
        TEST_EQ(attachment->payload_bytes, payload.size(), "count actual object bytes");
        if (spill) {
            TEST_CHECK(attachment->object_source);
            std::vector<uint8_t> observed(payload.size());
            if (attachment->object_source)
                TEST_OK(attachment->object_source->read_at(0, observed.data(), observed.size()),
                        "read owned opaque bytes");
            TEST_CHECK(observed == payload);
        } else {
            TEST_CHECK(attachment->object_data == payload);
        }
        const auto emitted = msg::build_emit_request(report, msg::EmitOptions());
        TEST_OK(emitted, "emit opaque object bytes");
        if (emitted.ok()) {
            const auto& object =
                emitted.value().request.folders.front().messages.front().attachment_objects.front();
            TEST_CHECK(object.has_object_payload && !object.has_payload && !object.has_embedded);
            if (spill)
                TEST_CHECK(object.payload_source == attachment->object_source);
            else
                TEST_CHECK(object.payload == payload);
            TEST_EQ(emitted.value().report.attachments_opaque, 1,
                    "opaque object crosses the emitter seam");
        }
    }
}

void test_object_failures_are_not_absent_payloads() {
    for (int failure = 0; failure < 4; ++failure) {
        const auto report = run_with([&](Fixture& fixture) {
            attachment_a_becomes_an_embedded_message(fixture);
            auto reference = object_allocation(kEmbeddedMessage, failure == 1 ? 15 : 14);
            if (failure == 0)
                reference.resize(4); // missing ulSize
            fixture.blocks.add(
                13, pc_block({{0x3705, 0x0003, 6}, {0x3701, 0x000D, 0x60}}, {{0x60, reference}}));
            fixture.blocks.add(kEmbeddedPcBid, std::vector<uint8_t>(14, 0x5A));
            if (failure == 2)
                fixture.blocks.add_internal(kEmbeddedSubnodeBid,
                                            sl_block({{kEmbeddedMessage + 32, kEmbeddedPcBid, 0}}));
            if (failure == 3)
                fixture.blocks.add_internal(
                    kEmbeddedSubnodeBid,
                    sl_block({{kEmbeddedMessage, kEmbeddedPcBid, kEmbeddedSubnodeBid}}));
        });
        TEST_EQ(report.object_values_carried, 0, "failed object is not counted as carried");
        TEST_CHECK(report.unreadable_values != 0 || report.attachments_with_unread_object != 0);
        const auto* message = find_message(report, kMessageA);
        if (!message)
            continue;
        const auto* attachment = find_attachment(*message, kAttachmentA);
        if (!attachment)
            continue;
        TEST_CHECK(!attachment->object_data_read && !attachment->payload_read);
        TEST_CHECK(!attachment->note.empty());
    }
}

void test_single_item_extraction_and_fixed_registry() {
    Fixture fixture;
    build_fixture(fixture);
    fixture.blocks.add(15, std::vector<uint8_t>(8, 0));
    auto first = msg::extract_item(fixture.census, fixture.blocks, kMessageA, {});
    auto broken = msg::extract_item(fixture.census, fixture.blocks, kMessageB, {});
    auto next = msg::extract_item(fixture.census, fixture.blocks, kMessageC, {});
    TEST_OK(first, "independent first item");
    TEST_OK(broken, "item failure retained in diagnostics");
    TEST_OK(next, "independent item after failure");
    if (!first.ok() || !broken.ok() || !next.ok())
        return;
    TEST_EQ(first.value().messages.size(), 1u, "one item per extraction");
    TEST_EQ(first.value().attachments_read, 2u, "item attachments");
    TEST_EQ(broken.value().messages_without_pc, 1u, "unreadable item is a failure");
    TEST_CHECK(!broken.value().messages.front().pc_read);
    TEST_EQ(next.value().messages_without_pc, 0u,
            "failure does not poison independent source item");
    auto fai = msg::extract_item(fixture.census, fixture.blocks, kFaiD, {});
    TEST_OK(fai, "FAI is a supported top-level item kind");
    if (fai.ok()) {
        TEST_EQ(fai.value().messages.front().nid, kFaiD, "FAI source identity");
        TEST_CHECK_MSG(fai.value().messages.front().subnodes_complete,
                       "bidSub zero establishes an empty complete subnode population");
        auto empty_registry = msg::EmitRegistry::build({});
        TEST_OK(empty_registry, "registry for FAI without named properties");
        if (empty_registry.ok()) {
            msg::MailboxItem identity{kFaiD, kFolder, 0x100028, 0x8082, true};
            auto prepared =
                msg::prepare_item(fixture.census, fixture.blocks, identity, empty_registry.value());
            TEST_OK(prepared, "prepare readable FAI with no subnode tree");
            if (prepared.ok()) {
                TEST_EQ(prepared.value().outcome.status, msg::ItemStatus::kConverted,
                        "proven absence is not corruption");
                bool gap = false;
                for (const auto& finding : prepared.value().findings)
                    gap |= finding.code == "gap.recipient_table";
                TEST_CHECK(gap);
            }
        }
    }
    TEST_ERROR(msg::extract_item(fixture.census, fixture.blocks, kFolder, {}), ErrorKind::kBadField,
               "msg.extract.item_kind", "folder is not an item");

    const auto& source_named = fixture.census.name_id_map.entries.front();
    ost2pst::writer::NamedProperty reserved;
    reserved.name_is_string = false;
    reserved.numeric_name = 42;
    ost2pst::writer::NamedProperty used;
    used.name = source_named.name;
    used.guid = source_named.guid;
    auto registry = msg::EmitRegistry::build({reserved, used});
    TEST_OK(registry, "deterministic named registry");
    if (!registry.ok())
        return;
    auto item = first.value().messages.front();
    const auto* named_value = find_value(item.values, 0x8000);
    TEST_CHECK(named_value != nullptr);
    if (named_value == nullptr)
        return;
    msg::SubsetValue schema = *named_value;
    item.recipient_columns.push_back(schema);
    item.attachment_columns.push_back(schema);
    auto emitted = msg::build_emit_item(item, registry.value());
    TEST_OK(emitted, "one item with preassigned named identity");
    if (emitted.ok()) {
        const auto& output = emitted.value().message;
        bool found = false;
        for (const auto& p : output.properties) {
            if (!p.named)
                continue;
            found = true;
            TEST_EQ(p.named_index, 1u, "PC uses fixed index, not encounter order");
        }
        TEST_CHECK(found);
        for (const auto* table : {&output.recipients, &output.attachments}) {
            found = false;
            for (const auto& col : table->columns) {
                if (!col.named)
                    continue;
                found = true;
                TEST_EQ(col.named_index, 1u, "empty column uses same fixed identity");
            }
            TEST_CHECK(found);
        }
        TEST_EQ(emitted.value().report.named_unresolved, 0u, "all named identities resolved");
    }
    auto incomplete_registry = msg::EmitRegistry::build({reserved});
    TEST_OK(incomplete_registry, "registry with absent identity");
    if (incomplete_registry.ok()) {
        auto incomplete = msg::build_emit_item(item, incomplete_registry.value());
        TEST_OK(incomplete, "unmapped identity is explicitly reported");
        if (incomplete.ok())
            TEST_CHECK(incomplete.value().report.named_unresolved > 0);
    }
    TEST_ERROR(msg::EmitRegistry::build({used, used}), ErrorKind::kBadField,
               "msg.registry.duplicate", "duplicate fixed identity refused");
}

void test_unreadable_attachment_tables_cannot_succeed() {
    for (int failure = 0; failure < 6; ++failure) {
        Fixture fixture;
        build_fixture(fixture);
        std::vector<std::tuple<uint64_t, uint64_t, uint64_t>> entries;
        if (failure != 1)
            entries.emplace_back(kNidAttachmentTable, failure == 0 || failure == 5 ? 0 : 11, 0);
        entries.emplace_back(kNidRecipientTable, failure == 4 ? 0 : 12, 0);
        if (failure != 5) {
            entries.emplace_back(kAttachmentA, 13, 0);
            entries.emplace_back(kAttachmentB, 18, 29);
        }
        entries.emplace_back(kBodySubnode, 19, 0);
        fixture.blocks.add_internal(14, sl_block(entries));
        if (failure == 2)
            fixture.blocks.add(11, attachment_tc_block({}, {}, 0, 0, {}));
        if (failure == 3)
            fixture.blocks.add(11, attachment_tc_block(
                                       {kAttachmentA}, {attachment_row(kAttachmentA, 707, 0xA0, 1)},
                                       0x80, 0x80, {{0xA0, utf16_text("note.pdf")}}));
        const auto& source_named = fixture.census.name_id_map.entries.front();
        writer::NamedProperty named;
        named.name = source_named.name;
        named.guid = source_named.guid;
        auto registry = msg::EmitRegistry::build({named});
        TEST_OK(registry, "attachment failure registry");
        if (!registry.ok())
            continue;
        const msg::MailboxItem identity{kMessageA, kFolder, 0x200024, 0x8082, false};
        auto prepared =
            msg::prepare_item(fixture.census, fixture.blocks, identity, registry.value());
        TEST_OK(prepared, "attachment population failure is item-local");
        if (prepared.ok()) {
            TEST_CHECK(!prepared.value().outcome.source_complete);
            TEST_EQ(prepared.value().outcome.status, msg::ItemStatus::kSkippedCorrupt,
                    "zero-data/missing/empty/short table cannot silently discard objects");
            TEST_CHECK(prepared.value().content.plan.blocks.empty());
            TEST_CHECK(!prepared.value().diagnostics.empty());
        }
    }
}

void test_emitter_preserves_noncore_properties() {
    SubsetReport report = run();
    const auto emitted = ost2pst::msg::build_emit_request(report, ost2pst::msg::EmitOptions());
    TEST_CHECK(emitted.ok());
    if (!emitted.ok()) {
        return;
    }
    TEST_EQ(emitted.value().report.named_values, 1,
            "the named source property must reach the writer without a diagnostic filter");
    const auto& message = emitted.value().request.folders.front().messages.front();
    const auto named = std::find_if(message.properties.begin(), message.properties.end(),
                                    [](const auto& property) { return property.named; });
    TEST_CHECK_MSG(named != message.properties.end(), "the named property bytes reach the writer");
    if (named != message.properties.end()) {
        const auto* source = find_value(report.messages.front().values, 0x8000);
        TEST_CHECK(source != nullptr && source->bytes == named->value);
    }
}
} // namespace

int main() {
    test_folder_and_its_messages_are_enumerated();
    test_message_properties_are_carried();
    test_recipient_and_attachment_rows_are_read();
    test_a_row_matrix_in_a_subnode_is_read();
    test_required_tags_and_body_forms_are_reported();
    test_the_message_cap_is_reported_not_silent();
    test_payload_collection_can_be_turned_off();
    test_a_row_index_past_the_matrix_is_reported();
    test_an_undecoded_object_value_is_named_not_silently_empty();
    test_an_attachment_row_that_names_no_subnode_is_reported();
    test_a_row_in_the_second_matrix_block_reads_from_that_block();
    test_a_short_nonfinal_matrix_block_is_counted();
    test_an_attachment_that_is_a_message_is_read_as_one();
    test_an_attached_message_past_the_depth_cap_is_a_shortfall();
    test_method6_object_data_is_carried_without_message_interpretation();
    test_object_failures_are_not_absent_payloads();
    test_emitter_preserves_noncore_properties();
    test_single_item_extraction_and_fixed_registry();
    test_unreadable_attachment_tables_cannot_succeed();
    return ost2pst::test::finish("msg_subset_test");
}
