// A table context is a heap node whose header names a RowIndex BTH and a Row Matrix that normally lives
// in the subnode ([MS-PST] 2.3.4). This file checks TCINFO and its column descriptors, the group offsets
// that say where each column sits in a row, the Cell Existence Bitmap that says whether a cell is real,
// and the RowIndex walk that is the only ordered view of an unordered Row Matrix.
#include <cstdint>
#include <map>
#include <vector>

#include "ost2pst/ltp/bth.h"
#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/tc.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"
#include "test_support.h"

namespace {

using ost2pst::ltp::decode_tc_col_desc;
using ost2pst::ltp::decode_tc_info;
using ost2pst::ltp::decode_tc_row_id;
using ost2pst::ltp::HeapSource;
using ost2pst::ltp::BthStats;
using ost2pst::ltp::HnHeader;
using ost2pst::ltp::read_tc;
using ost2pst::ltp::tc_ceb_bit;
using ost2pst::ltp::tc_ceb_bytes;
using ost2pst::ltp::tc_column_cell;
using ost2pst::ltp::tc_row_size;
using ost2pst::ltp::tc_rows_per_block;
using ost2pst::ltp::TcCell;
using ost2pst::ltp::TcColumn;
using ost2pst::ltp::TcInfo;
using ost2pst::ltp::TcRowId;
using ost2pst::ltp::TcTable;
using ost2pst::ltp::walk_tc_row_index;
using ost2pst::ndb::FailureLog;
using ost2pst::ndb::FileProfile;
using ost2pst::util::ByteView;
using ost2pst::util::ErrorKind;
using ost2pst::util::make_error;
using ost2pst::util::Result;
using ost2pst::util::Status;

constexpr uint64_t kHeapBase = 0x20000;
constexpr uint32_t kHidTcHeader = 0x20;
constexpr uint32_t kHidRowIndexHeader = 0x60;
constexpr uint32_t kHidRowIdArray = 0x80;
// Every fixture HID here is allocation 1-4 of block 0, legal under both profiles; the 512 one is used
// because this test never resolves a HID against a block index.
constexpr FileProfile kProfile = FileProfile::kPst;

// The synthetic TC: 4 columns in a 16-byte row -- two 4-byte (rgib[0] 12), one 2-byte (rgib[1] 14), one
// 1-byte (rgib[2] 15), then a 1-byte CEB ending the row at rgib[3] 16.
constexpr uint8_t kCols = 4;
constexpr uint16_t kRgib[4] = {12, 14, 15, 16};

class FakeHeap : public HeapSource {
public:
    void add(uint32_t hid, const std::vector<uint8_t> &bytes) { items_[hid] = bytes; }

    Result<ByteView> heap(uint32_t hid) override {
        const auto found = items_.find(hid);
        if (found == items_.end()) {
            return make_error(ErrorKind::kBadField, "HID", kHeapBase + hid, hid, "no such heap item");
        }
        return ByteView(found->second.data(), found->second.size(), kHeapBase + hid);
    }

private:
    std::map<uint32_t, std::vector<uint8_t>> items_;
};

void put16(std::vector<uint8_t> &bytes, uint16_t value) {
    bytes.push_back(static_cast<uint8_t>(value & 0xFF));
    bytes.push_back(static_cast<uint8_t>(value >> 8));
}

void put32(std::vector<uint8_t> &bytes, uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        bytes.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
    }
}

std::vector<uint8_t> tc_info_bytes(uint8_t cols, const uint16_t rgib[4], uint32_t hid_row_index,
                                   uint32_t hnid_rows) {
    std::vector<uint8_t> bytes;
    bytes.push_back(ost2pst::ltp::kClientSigTc);
    bytes.push_back(cols);
    for (uint64_t i = 0; i < ost2pst::ltp::kTcRgibEntries; ++i) {
        put16(bytes, rgib[i]);
    }
    put32(bytes, hid_row_index);
    put32(bytes, hnid_rows);
    put32(bytes, 0); // hidIndex: deprecated, new PSTs write 0
    return bytes;
}

void append_col(std::vector<uint8_t> &bytes, uint32_t tag, uint16_t ib_data, uint8_t cb_data,
                uint8_t i_bit) {
    put32(bytes, tag);
    put16(bytes, ib_data);
    bytes.push_back(cb_data);
    bytes.push_back(i_bit);
}

// The four columns of the synthetic TC, in tag order, each inside the group its width puts it in.
std::vector<uint8_t> tc_header_bytes(uint8_t cols = kCols, const uint16_t rgib[4] = kRgib) {
    std::vector<uint8_t> bytes = tc_info_bytes(cols, rgib, kHidRowIndexHeader, 0x1234);
    append_col(bytes, 0x6619, 12, 2, 2);
    append_col(bytes, 0x6674, 14, 1, 3);
    append_col(bytes, 0x67F20003, 0, 4, 0);
    append_col(bytes, 0x67F30003, 4, 4, 1);
    return bytes;
}

std::vector<uint8_t> row_index_header_bytes(uint8_t cb_key = 4, uint8_t cb_ent = 4,
                                            uint32_t hid_root = kHidRowIdArray) {
    std::vector<uint8_t> bytes;
    bytes.push_back(ost2pst::ltp::kBthType);
    bytes.push_back(cb_key);
    bytes.push_back(cb_ent);
    bytes.push_back(0); // bIdxLevels: the array hidRoot names is already the leaf array
    put32(bytes, hid_root);
    return bytes;
}

std::vector<uint8_t> row_id_array_bytes() {
    std::vector<uint8_t> bytes;
    put32(bytes, 0x100);
    put32(bytes, 0);
    put32(bytes, 0x200);
    put32(bytes, 1);
    put32(bytes, 0x300);
    put32(bytes, 2);
    return bytes;
}

HnHeader tc_hn_header() {
    HnHeader header;
    header.b_sig = ost2pst::ltp::kHnSignature;
    header.b_client_sig = ost2pst::ltp::kClientSigTc;
    header.hid_user_root = kHidTcHeader;
    return header;
}

// HeapSource is non-copyable and non-movable, so a fake is filled in place rather than returned.
void fill_tc_heap(FakeHeap &heap) {
    heap.add(kHidTcHeader, tc_header_bytes());
    heap.add(kHidRowIndexHeader, row_index_header_bytes());
    heap.add(kHidRowIdArray, row_id_array_bytes());
}

void check_tc_info_decoder() {
    const std::vector<uint8_t> bytes = tc_info_bytes(kCols, kRgib, kHidRowIndexHeader, 0x1234);
    Result<TcInfo> info = decode_tc_info(ByteView(bytes.data(), bytes.size(), 0x4000));
    TEST_OK(info, "TCINFO");
    TEST_EQ(info.value().b_type, ost2pst::ltp::kClientSigTc, "bType");
    TEST_EQ(info.value().c_cols, kCols, "cCols");
    TEST_EQ(info.value().rgib[ost2pst::ltp::kTcRgib4b], 12, "rgib TCI_4b");
    TEST_EQ(info.value().rgib[ost2pst::ltp::kTcRgib2b], 14, "rgib TCI_2b");
    TEST_EQ(info.value().rgib[ost2pst::ltp::kTcRgib1b], 15, "rgib TCI_1b");
    TEST_EQ(info.value().rgib[ost2pst::ltp::kTcRgibBm], 16, "rgib TCI_bm");
    TEST_EQ(info.value().hid_row_index, kHidRowIndexHeader, "hidRowIndex");
    TEST_EQ(info.value().hnid_rows, 0x1234, "hnidRows");

    std::vector<uint8_t> wrong_type = tc_info_bytes(kCols, kRgib, kHidRowIndexHeader, 0);
    wrong_type[0] = ost2pst::ltp::kClientSigPc;
    TEST_ERROR(decode_tc_info(ByteView(wrong_type.data(), wrong_type.size(), 0x4000)),
               ErrorKind::kBadSignature, "TCINFO.bType", "bType is not bTypeTC");

    std::vector<uint8_t> no_columns = tc_info_bytes(0, kRgib, kHidRowIndexHeader, 0);
    TEST_ERROR(decode_tc_info(ByteView(no_columns.data(), no_columns.size(), 0x4000)),
               ErrorKind::kBadField, "TCINFO.cCols", "cCols zero");

    TEST_ERROR(decode_tc_info(ByteView(bytes.data(), 21, 0x4000)), ErrorKind::kTruncated, "TCINFO",
               "TCINFO shorter than 22 bytes");
}

void check_column_decoder() {
    std::vector<uint8_t> bytes;
    append_col(bytes, 0x6674, 14, 1, 3);
    Result<TcColumn> column = decode_tc_col_desc(ByteView(bytes.data(), bytes.size(), 0x900));
    TEST_OK(column, "TCOLDESC");
    TEST_EQ(column.value().tag, 0x6674, "tag");
    TEST_EQ(column.value().ib_data, 14, "ibData");
    TEST_EQ(column.value().cb_data, 1, "cbData");
    TEST_EQ(column.value().i_bit, 3, "iBit");
    TEST_ERROR(decode_tc_col_desc(ByteView(bytes.data(), 7, 0x900)), ErrorKind::kTruncated,
               "TCOLDESC", "TCOLDESC shorter than 8 bytes");
}

void check_read_tc() {
    FakeHeap heap;
    fill_tc_heap(heap);
    Result<TcTable> table = read_tc(tc_hn_header(), heap);
    TEST_OK(table, "read_tc");
    TEST_EQ(table.value().columns.size(), kCols, "column count");
    TEST_EQ(table.value().header_offset, kHeapBase + kHidTcHeader, "TCINFO offset");
    TEST_EQ(tc_row_size(table.value().info), 16, "row size is rgib[TCI_bm]");
    TEST_EQ(tc_ceb_bytes(table.value().info), 1, "CEB is CEIL(cCols / 8)");
    TEST_EQ(table.value().columns[0].tag, 0x6619, "first column tag");
    TEST_EQ(table.value().columns[2].tag, 0x67F20003, "PidTagLtpRowId is present");
    TEST_EQ(table.value().columns[3].tag, 0x67F30003, "PidTagLtpRowVer is present");
}

void check_read_tc_rejects() {
    HnHeader not_a_tc = tc_hn_header();
    not_a_tc.b_client_sig = ost2pst::ltp::kClientSigPc;
    FakeHeap plain;
    fill_tc_heap(plain);
    TEST_ERROR(read_tc(not_a_tc, plain), ErrorKind::kBadField, "HNHDR.bClientSig", "bClientSig is not TC");

    FakeHeap missing;
    TEST_ERROR(read_tc(tc_hn_header(), missing), ErrorKind::kBadField, "HID", "no TCINFO allocation");

    // rgTCOLDESC has to fit in the same allocation as TCINFO.
    FakeHeap short_heap;
    short_heap.add(kHidTcHeader, tc_info_bytes(kCols, kRgib, kHidRowIndexHeader, 0));
    TEST_ERROR(read_tc(tc_hn_header(), short_heap), ErrorKind::kTruncated, "TCINFO.rgTCOLDESC",
               "descriptors past the allocation");

    // rgib holds ending offsets, so they cannot go backwards.
    const uint16_t backwards[4] = {12, 15, 14, 16};
    FakeHeap backwards_heap;
    backwards_heap.add(kHidTcHeader, tc_header_bytes(kCols, backwards));
    TEST_ERROR(read_tc(tc_hn_header(), backwards_heap), ErrorKind::kBadField, "TCINFO.rgib",
               "rgib out of order");

    // The CEB is CEIL(cCols / 8) bytes and has to fit between rgib[TCI_1b] and rgib[TCI_bm].
    const uint16_t tight[4] = {12, 14, 15, 15};
    FakeHeap tight_heap;
    tight_heap.add(kHidTcHeader, tc_header_bytes(kCols, tight));
    TEST_ERROR(read_tc(tc_hn_header(), tight_heap), ErrorKind::kBadField, "TCINFO.rgib",
               "no room for the CEB");

    // rgTCOLDESC MUST be sorted by tag ([MS-PST] 2.3.4.1).
    std::vector<uint8_t> unsorted = tc_info_bytes(kCols, kRgib, kHidRowIndexHeader, 0);
    append_col(unsorted, 0x6619, 12, 2, 2);
    append_col(unsorted, 0x6674, 14, 1, 3);
    append_col(unsorted, 0x6619, 0, 4, 0);
    append_col(unsorted, 0x67F30003, 4, 4, 1);
    FakeHeap unsorted_heap;
    unsorted_heap.add(kHidTcHeader, unsorted);
    TEST_ERROR(read_tc(tc_hn_header(), unsorted_heap), ErrorKind::kBadField, "TCOLDESC.tag",
               "descriptors out of tag order");

    // A 2-byte column cannot sit in the 4-byte group.
    std::vector<uint8_t> misplaced = tc_info_bytes(kCols, kRgib, kHidRowIndexHeader, 0);
    append_col(misplaced, 0x6619, 4, 2, 2);
    append_col(misplaced, 0x6674, 14, 1, 3);
    append_col(misplaced, 0x67F20003, 0, 4, 0);
    append_col(misplaced, 0x67F30003, 4, 4, 1);
    FakeHeap misplaced_heap;
    misplaced_heap.add(kHidTcHeader, misplaced);
    TEST_ERROR(read_tc(tc_hn_header(), misplaced_heap), ErrorKind::kBadField, "TCOLDESC.ibData",
               "column in the wrong size group");

    // iBit indexes the CEB, and this TC's CEB has 8 bits.
    std::vector<uint8_t> far_bit = tc_info_bytes(kCols, kRgib, kHidRowIndexHeader, 0);
    append_col(far_bit, 0x6619, 12, 2, 2);
    append_col(far_bit, 0x6674, 14, 1, 9);
    append_col(far_bit, 0x67F20003, 0, 4, 0);
    append_col(far_bit, 0x67F30003, 4, 4, 1);
    FakeHeap far_bit_heap;
    far_bit_heap.add(kHidTcHeader, far_bit);
    TEST_ERROR(read_tc(tc_hn_header(), far_bit_heap), ErrorKind::kBadField, "TCOLDESC.iBit",
               "iBit past the CEB");

    // PidTagLtpRowId MUST have iBit 0 and ibData 0 ([MS-PST] 2.3.4.4.1).
    std::vector<uint8_t> wrong_row_id = tc_info_bytes(kCols, kRgib, kHidRowIndexHeader, 0);
    append_col(wrong_row_id, 0x6619, 12, 2, 2);
    append_col(wrong_row_id, 0x6674, 14, 1, 3);
    append_col(wrong_row_id, 0x67F20003, 8, 4, 4);
    append_col(wrong_row_id, 0x67F30003, 4, 4, 1);
    FakeHeap wrong_row_id_heap;
    wrong_row_id_heap.add(kHidTcHeader, wrong_row_id);
    TEST_ERROR(read_tc(tc_hn_header(), wrong_row_id_heap), ErrorKind::kBadField, "TCOLDESC.iBit",
               "PidTagLtpRowId in the wrong slot");
}

void check_row_index_walk() {
    FakeHeap heap;
    fill_tc_heap(heap);
    Result<TcTable> table = read_tc(tc_hn_header(), heap);
    TEST_OK(table, "read_tc");

    std::vector<TcRowId> rows;
    BthStats stats;
    FailureLog failures;
    Status walked = walk_tc_row_index(table.value(), kProfile, heap, [&](const TcRowId &row) {
        rows.push_back(row);
        return true;
    }, stats, failures);
    TEST_OK(walked, "walk_tc_row_index");
    TEST_EQ(rows.size(), 3, "row count");
    // The Row Matrix is unsorted; the RowIndex is what makes the rows ordered ([MS-PST] 2.3.4.4).
    TEST_EQ(rows.size() > 0 ? rows[0].row_id : 0, 0x100, "first dwRowID");
    TEST_EQ(rows.size() > 0 ? rows[0].row_index : 0xFFFF, 0, "first dwRowIndex");
    TEST_EQ(rows.size() > 1 ? rows[1].row_id : 0, 0x200, "second dwRowID");
    TEST_EQ(rows.size() > 1 ? rows[1].row_index : 0xFFFF, 1, "second dwRowIndex");
    TEST_EQ(rows.size() > 2 ? rows[2].row_id : 0, 0x300, "third dwRowID");
    TEST_EQ(stats.leaf_records, 3, "leaf records");
    TEST_EQ(failures.total(), 0, "no findings");

    // hidRowIndex 0 means the TC has no rows ([MS-PST] 2.3.4.1).
    TcTable empty = table.value();
    empty.info.hid_row_index = 0;
    std::vector<TcRowId> none;
    BthStats empty_stats;
    FailureLog empty_failures;
    TEST_OK(walk_tc_row_index(empty, kProfile, heap, [&](const TcRowId &row) {
        none.push_back(row);
        return true;
    }, empty_stats, empty_failures), "empty RowIndex");
    TEST_EQ(none.size(), 0, "no rows");
    TEST_EQ(empty_failures.total(), 0, "an empty TC is not a finding");

    // The RowIndex record shape is fixed by the spec ([MS-PST] 2.3.4.3.1).
    FakeHeap ansi;
    fill_tc_heap(ansi);
    ansi.add(kHidRowIndexHeader, row_index_header_bytes(4, 2));
    TcTable ansi_table = table.value();
    BthStats ansi_stats;
    FailureLog ansi_failures;
    TEST_ERROR(walk_tc_row_index(ansi_table, kProfile, ansi, [](const TcRowId &) { return true; },
                                ansi_stats, ansi_failures),
               ErrorKind::kBadField, "BTHHEADER.cbKey", "ANSI RowIndex record");
}

void check_cells() {
    FakeHeap heap;
    fill_tc_heap(heap);
    Result<TcTable> table = read_tc(tc_hn_header(), heap);
    TEST_OK(table, "read_tc");
    const TcTable &tc = table.value();

    // A 16-byte row: 4-byte group at 0 and 4, a 2-byte at 12, a 1-byte at 14, the CEB at 15.
    std::vector<uint8_t> row;
    put32(row, 0x11111111);
    put32(row, 0x22222222);
    put32(row, 0x33333333); // 12 bytes of 4-byte group
    put16(row, 0x4444);
    row.push_back(0x55);
    row.push_back(0xA0); // CEB: bits 0 and 2 set, bits 1 and 3 clear
    TEST_EQ(row.size(), 16, "row is rgib[TCI_bm] bytes");

    const ByteView view(row.data(), row.size(), 0x7000);
    Result<TcCell> row_id = tc_column_cell(tc, tc.columns[2], view);
    TEST_OK(row_id, "PidTagLtpRowId cell");
    TEST_EQ(row_id.value().exists, 1, "CEB bit 0 set");
    TEST_EQ(row_id.value().value.size(), 4, "4-byte slot");
    TEST_EQ(row_id.value().value.base(), 0x7000, "ibData 0");

    Result<TcCell> row_ver = tc_column_cell(tc, tc.columns[3], view);
    TEST_OK(row_ver, "PidTagLtpRowVer cell");
    TEST_EQ(row_ver.value().exists, 0, "CEB bit 1 clear");
    TEST_EQ(row_ver.value().value.size(), 0, "a cell that does not exist has no bytes");

    Result<TcCell> word = tc_column_cell(tc, tc.columns[0], view);
    TEST_OK(word, "2-byte column cell");
    TEST_EQ(word.value().exists, 1, "CEB bit 2 set");
    TEST_EQ(word.value().value.base(), 0x7000 + 12, "ibData 12");
    TEST_EQ(word.value().value.size(), 2, "2-byte slot");

    Result<TcCell> byte_cell = tc_column_cell(tc, tc.columns[1], view);
    TEST_OK(byte_cell, "1-byte column cell");
    TEST_EQ(byte_cell.value().exists, 0, "CEB bit 3 clear");

    // A row shorter than rgib[TCI_bm] is not a row.
    TEST_ERROR(tc_column_cell(tc, tc.columns[0], ByteView(row.data(), 15, 0x7000)),
               ErrorKind::kTruncated, "RowMatrix.row", "short row");
}

void check_geometry() {
    // [MS-PST] 2.3.4.4.1: iBit 0 is the MSB of rgCEB[0], then down to the LSB, then the next byte.
    uint8_t bits[2] = {0x80, 0x01};
    const ByteView ceb(bits, 2, 0);
    TEST_EQ(tc_ceb_bit(ceb, 0), 1, "iBit 0 is the MSB of byte 0");
    TEST_EQ(tc_ceb_bit(ceb, 7), 0, "iBit 7 is the LSB of byte 0");
    TEST_EQ(tc_ceb_bit(ceb, 8), 0, "iBit 8 is the MSB of byte 1");
    TEST_EQ(tc_ceb_bit(ceb, 15), 1, "iBit 15 is the LSB of byte 1");
    TEST_EQ(tc_ceb_bit(ceb, 16), 0, "iBit past the CEB");

    TcInfo info;
    info.c_cols = 4;
    info.rgib[ost2pst::ltp::kTcRgib1b] = 15;
    info.rgib[ost2pst::ltp::kTcRgibBm] = 16;
    TEST_EQ(tc_row_size(info), 16, "row size");
    TEST_EQ(tc_ceb_bytes(info), 1, "4 columns need one CEB byte");
    info.c_cols = 9;
    TEST_EQ(tc_ceb_bytes(info), 2, "9 columns need two CEB bytes");

    // [MS-PST] 2.3.4.4: rows never span a block, and every block but the last is 8192 bytes.
    const uint64_t trailer = ost2pst::ndb::kPstBlockTrailerSize;
    const uint64_t row = tc_row_size(info);
    TEST_EQ(tc_rows_per_block(ost2pst::ltp::kTcDataBlockSize, row, trailer), 511,
            "rows in a full 8192-byte block");
    TEST_EQ(tc_rows_per_block(100, row, trailer), 5, "rows in a short block");
    TEST_EQ(tc_rows_per_block(row, row, trailer), 0, "no room for a row once the trailer is counted");
    uint64_t zero_row = 0;
    TEST_EQ(tc_rows_per_block(ost2pst::ltp::kTcDataBlockSize, zero_row, trailer), 0, "zero row size");
}

void check_row_id_decoder() {
    std::vector<uint8_t> bytes;
    put32(bytes, 0x12345678);
    put32(bytes, 9);
    Result<TcRowId> record = decode_tc_row_id(ByteView(bytes.data(), bytes.size(), 0x800));
    TEST_OK(record, "TCROWID");
    TEST_EQ(record.value().row_id, 0x12345678, "dwRowID");
    TEST_EQ(record.value().row_index, 9, "dwRowIndex");
    TEST_EQ(record.value().offset, 0x800, "record offset");
    TEST_ERROR(decode_tc_row_id(ByteView(bytes.data(), 7, 0x800)), ErrorKind::kTruncated, "TCROWID",
               "short TCROWID");
}

} // namespace

int main() {
    check_tc_info_decoder();
    check_column_decoder();
    check_read_tc();
    check_read_tc_rejects();
    check_row_index_walk();
    check_cells();
    check_geometry();
    check_row_id_decoder();
    return ost2pst::test::finish("ltp_tc_test");
}
