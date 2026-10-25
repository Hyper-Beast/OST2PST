// A Table Context is the shape every folder table is built out of, so this file builds one with the
// writer and reads it back with the reader: ltp::read_tc, walk_tc_row_index and tc_column_cell over
// a BlockHeapSource of the built block ([MS-PST] 2.3.4 / 2.3.4.3.1 / 2.3.4.4).
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "ost2pst/ltp/block_heap.h"
#include "ost2pst/ltp/bth.h"
#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/tc.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/sha256.h"
#include "ost2pst/util/status.h"
#include "ost2pst/writer/heap.h"
#include "ost2pst/writer/tc.h"

#include "test_support.h"

namespace {

using ost2pst::ltp::BlockHeapSource;
using ost2pst::ltp::BthHeader;
using ost2pst::ltp::BthStats;
using ost2pst::ltp::decode_bth_header;
using ost2pst::ltp::decode_hn_header;
using ost2pst::ltp::decode_hn_page_map;
using ost2pst::ltp::hid_type;
using ost2pst::ltp::hn_heap_item;
using ost2pst::ltp::kNidTypeLtp;
using ost2pst::ltp::read_tc;
using ost2pst::ltp::tc_ceb_bit;
using ost2pst::ltp::tc_column_cell;
using ost2pst::ltp::tc_row_size;
using ost2pst::ltp::TcCell;
using ost2pst::ltp::TcColumn;
using ost2pst::ltp::TcRowId;
using ost2pst::ltp::TcTable;
using ost2pst::ndb::FailureLog;
using ost2pst::ndb::FileProfile;
using ost2pst::util::ByteView;
using ost2pst::util::ErrorKind;
using ost2pst::util::Result;
using ost2pst::util::Status;
using ost2pst::writer::build_table;
using ost2pst::writer::build_tc;
using ost2pst::writer::HeapImage;
using ost2pst::writer::LocalNids;
using ost2pst::writer::TcColumnSpec;
using ost2pst::writer::TcNode;
using ost2pst::writer::TcRow;

constexpr FileProfile kProfile = FileProfile::kPst;
constexpr uint64_t kBlockBase = 0x4800;

std::vector<uint8_t> utf16(const std::string& text) {
    std::vector<uint8_t> bytes;
    for (char character : text) {
        bytes.push_back(static_cast<uint8_t>(character));
        bytes.push_back(0);
    }
    return bytes;
}

std::vector<uint8_t> bytes_of(const ByteView& view) {
    return std::vector<uint8_t>(view.data(), view.data() + view.size());
}

std::vector<uint8_t> le32(uint32_t value) {
    return {static_cast<uint8_t>(value), static_cast<uint8_t>(value >> 8),
            static_cast<uint8_t>(value >> 16), static_cast<uint8_t>(value >> 24)};
}

// rgTCOLDESC comes back sorted by tag ([MS-PST] 2.3.4.1), which is not the order the columns were
// handed in, so a test that wants one column looks it up by tag.
size_t column_of(const std::vector<TcColumn>& columns, uint32_t tag) {
    for (size_t index = 0; index < columns.size(); ++index) {
        if (columns[index].tag == tag) {
            return index;
        }
    }
    TEST_CHECK_MSG(false, "read_tc did not return the column the test asked for");
    return 0;
}

ByteView view_of(const HeapImage& heap) {
    return ByteView(heap.bytes().data(), heap.bytes().size(), kBlockBase);
}

// The heap node header and page map of a built image, read the way the LTP layer reads a data
// block.
void open_heap(const HeapImage& heap, ost2pst::ltp::HnHeader& hn, ost2pst::ltp::HnPageMap& map,
               std::optional<BlockHeapSource>& source) {
    Result<ost2pst::ltp::HnHeader> header = decode_hn_header(view_of(heap));
    TEST_OK(header, "built TC HNHDR");
    if (!header.ok()) {
        return;
    }
    hn = header.value();
    Result<ost2pst::ltp::HnPageMap> page_map = decode_hn_page_map(view_of(heap), hn.ib_hnpm);
    TEST_OK(page_map, "built TC HNPAGEMAP");
    if (!page_map.ok()) {
        return;
    }
    map = page_map.value();
    source.emplace(view_of(heap), map, kProfile, uint16_t{0});
}

// The hierarchy Table Context of the [MS-PST] 3.12 sample: the same 13 columns, the same three
// rows, and the same rgib and RowIndex the spec lists for it.
std::vector<TcColumnSpec> sample_columns() {
    return {
        {0x0E300003}, {0x0E330014}, {0x0E340102}, {0x0E380003}, {0x3001001F},
        {0x36020003}, {0x36030003}, {0x360A000B}, {0x3613001F}, {0x66350003},
        {0x66360003}, {0x67F20003}, {0x67F30003},
    };
}

std::vector<std::vector<uint8_t>> sample_row_values(const std::vector<uint8_t>& name,
                                                    uint8_t subfolders, uint32_t row_id) {
    return {
        {},                         // 0x0E30 PidTagReplItemid: this row has no value for it
        std::vector<uint8_t>(8, 0), // 0x0E33 PidTagReplChangenum 0
        {},                         // 0x0E34 PidTagReplVersionhistory
        {},                         // 0x0E38 PidTagReplFlags
        name,                       // 0x3001 PidTagDisplayName
        le32(0),                    // 0x3602 PidTagContentCount 0
        le32(0),                    // 0x3603 PidTagContentUnreadCount 0
        {subfolders},               // 0x360A PidTagSubfolders
        {},                         // 0x3613 PidTagContainerClass
        {},                         // 0x6635
        {},                         // 0x6636
        le32(row_id),               // 0x67F2 PidTagLtpRowId
        le32(0),                    // 0x67F3 PidTagLtpRowVer
    };
}

void check_spec_sample_tc() {
    // Receive-folder default message class is present but empty. It must not be
    // encoded as absent, padded with a NUL string, or allocated as a zero-byte item.
    {
        TcRow row{1, {{}, le32(1), le32(0)}};
        row.present_empty = {true, false, false};
        auto result = build_tc({{0x001A001F}, {0x67F20003}, {0x67F30003}}, {row});
        TEST_OK(result, "present empty string");
        if (result.ok()) {
            ost2pst::ltp::HnHeader hn;
            ost2pst::ltp::HnPageMap map;
            std::optional<BlockHeapSource> source;
            open_heap(result.value(), hn, map, source);
            if (source) {
                auto table = read_tc(hn, *source);
                TEST_OK(table, "empty-string TC");
                if (table.ok()) {
                    auto matrix = hn_heap_item(map, view_of(result.value()),
                                               table.value().info.hnid_rows, kProfile);
                    TEST_OK(matrix, "empty-string matrix");
                    if (matrix.ok()) {
                        const auto& column = table.value().columns[0];
                        auto cell = tc_column_cell(table.value(), column, matrix.value());
                        TEST_OK(cell, "present empty cell");
                        if (cell.ok()) {
                            TEST_CHECK(cell.value().exists);
                            TEST_EQ(matrix.value().u32(column.ib_data).value(), 0u,
                                    "present empty value uses HNID zero");
                        }
                    }
                }
            }
        }
        row.present_empty = {true};
        TEST_CHECK(!build_tc({{0x001A001F}, {0x67F20003}, {0x67F30003}}, {row}).ok());
        row.present_empty = {false, true, false};
        row.values[1].clear();
        TEST_CHECK(!build_tc({{0x001A001F}, {0x67F20003}, {0x67F30003}}, {row}).ok());
    }
    const std::vector<uint8_t> top = utf16("Top of Personal Folders");
    const std::vector<uint8_t> search = utf16("Search Root");
    const std::vector<uint8_t> spam = utf16("SPAM Search Folder 2");
    // The Row Matrix is unsorted ([MS-PST] 2.3.4.4), and the spec sample lists its rows in this
    // order.
    const std::vector<TcRow> rows = {
        {0x8022, sample_row_values(top, 1, 0x8022)},
        {0x8042, sample_row_values(search, 0, 0x8042)},
        {0x2223, sample_row_values(spam, 0, 0x2223)},
    };

    Result<HeapImage> built = build_tc(sample_columns(), rows);
    TEST_OK(built, "build_tc");
    if (!built.ok()) {
        return;
    }
    const HeapImage& heap = built.value();
    // TCINFO + descriptors, RowIndex BTHHEADER, TCROWID array, Row Matrix, then the three names.
    TEST_EQ(heap.allocation_count(), 7, "TC allocations");
    TEST_EQ(heap.hid_user_root(), 0x20, "hidUserRoot names the TCINFO");

    ost2pst::ltp::HnHeader hn;
    ost2pst::ltp::HnPageMap map;
    std::optional<BlockHeapSource> source;
    open_heap(heap, hn, map, source);
    TEST_EQ(hn.b_client_sig, 0x7C, "a TC heap node carries bTypeTC");

    Result<TcTable> table = read_tc(hn, *source);
    TEST_OK(table, "read_tc on the built TC");
    if (!table.ok()) {
        return;
    }
    TEST_EQ(table.value().info.c_cols, 13, "cCols");
    // [MS-PST] 3.12 lists rgib 52, 52, 53, 55 for this TC.
    TEST_EQ(table.value().info.rgib[0], 52, "rgib[TCI_4b]");
    TEST_EQ(table.value().info.rgib[1], 52, "rgib[TCI_2b]: this TC has no 2-byte column");
    TEST_EQ(table.value().info.rgib[2], 53, "rgib[TCI_1b]");
    TEST_EQ(table.value().info.rgib[3], 55, "rgib[TCI_bm]: the row size");
    TEST_EQ(table.value().info.hid_row_index, 0x40, "hidRowIndex");
    TEST_EQ(table.value().info.hnid_rows, 0x80,
            "hnidRows: the spec sample puts the Row Matrix at 0x80");
    TEST_EQ(table.value().info.hid_index, 0, "hidIndex is zero for a creator of a new PST");

    const std::vector<TcColumn>& columns = table.value().columns;
    TEST_EQ(columns.size(), 13, "rgTCOLDESC entries");
    if (columns.size() != 13) {
        return;
    }
    const uint32_t expected_tags[] = {0x0E300003, 0x0E330014, 0x0E340102, 0x0E380003, 0x3001001F,
                                      0x36020003, 0x36030003, 0x360A000B, 0x3613001F, 0x66350003,
                                      0x66360003, 0x67F20003, 0x67F30003};
    const uint8_t expected_width[] = {4, 8, 4, 4, 4, 4, 4, 1, 4, 4, 4, 4, 4};
    for (size_t index = 0; index < columns.size() && index < 13; ++index) {
        TEST_EQ(columns[index].tag, expected_tags[index], "rgTCOLDESC is sorted by tag");
        TEST_EQ(columns[index].cb_data, expected_width[index],
                "cbData: the value width, or 4 for a value stored behind an HNID");
        TEST_CHECK(columns[index].ib_data + columns[index].cb_data <= table.value().info.rgib[3]);
    }
    // [MS-PST] 2.3.4.4.1 fixes the first two columns of every row.
    TEST_EQ(columns[11].ib_data, 0, "PidTagLtpRowId ibData");
    TEST_EQ(columns[11].i_bit, 0, "PidTagLtpRowId iBit");
    TEST_EQ(columns[12].ib_data, 4, "PidTagLtpRowVer ibData");
    TEST_EQ(columns[12].i_bit, 1, "PidTagLtpRowVer iBit");

    // The RowIndex walk has to land on the same (dwRowID, dwRowIndex) pairs the spec sample lists.
    const uint32_t expected_row_ids[] = {0x2223, 0x8022, 0x8042};
    const uint32_t expected_row_index[] = {2, 0, 1};
    std::vector<TcRowId> row_ids;
    BthStats stats;
    FailureLog failures;
    Status status = walk_tc_row_index(
        table.value(), kProfile, *source,
        [&](const TcRowId& row) {
            row_ids.push_back(row);
            return true;
        },
        stats, failures);
    TEST_CHECK(status.ok());
    TEST_EQ(failures.total(), 0, "no TC findings");
    TEST_EQ(row_ids.size(), 3, "RowIndex records");
    TEST_EQ(stats.leaf_records, 3, "BTH leaf records");
    TEST_EQ(stats.index_records, 0, "a RowIndex with bIdxLevels 0 has no index array");
    for (size_t index = 0; index < row_ids.size() && index < 3; ++index) {
        TEST_EQ(row_ids[index].row_id, expected_row_ids[index], "TCROWID.dwRowID order");
        TEST_EQ(row_ids[index].row_index, expected_row_index[index], "TCROWID.dwRowIndex");
    }

    // The Row Matrix itself, read back through the HNID TCINFO names for it.
    Result<ByteView> matrix =
        hn_heap_item(map, view_of(heap), table.value().info.hnid_rows, kProfile);
    TEST_OK(matrix, "Row Matrix heap item");
    if (!matrix.ok()) {
        return;
    }
    TEST_EQ(matrix.value().size(), 3 * tc_row_size(table.value().info), "Row Matrix bytes");

    const bool expected_exists[] = {false, true,  false, false, true, true, true,
                                    true,  false, false, false, true, true};
    const std::vector<uint8_t>* expected_names[] = {&top, &search, &spam};
    const uint32_t expected_row_id[] = {0x8022, 0x8042, 0x2223};
    // Which CEB bit each column owns, so the row's bits can be checked in bit order.
    bool expected_bit[16] = {};
    for (size_t column_index = 0; column_index < 13; ++column_index) {
        expected_bit[columns[column_index].i_bit] = expected_exists[column_index];
    }
    for (size_t row_index = 0; row_index < 3; ++row_index) {
        Result<ByteView> row = matrix.value().sub(row_index * tc_row_size(table.value().info),
                                                  tc_row_size(table.value().info));
        TEST_OK(row, "Row Matrix row");
        if (!row.ok()) {
            continue;
        }
        for (size_t column_index = 0; column_index < columns.size() && column_index < 13;
             ++column_index) {
            Result<TcCell> cell = tc_column_cell(table.value(), columns[column_index], row.value());
            TEST_OK(cell, "tc_column_cell");
            if (!cell.ok()) {
                continue;
            }
            TEST_EQ(cell.value().exists, expected_exists[column_index],
                    "the Cell Existence Bit says whether this row has a value for the column");
            if (!cell.value().exists) {
                continue;
            }
            if (columns[column_index].tag == 0x3001001F) {
                // A variable-sized column holds an HNID naming the value ([MS-PST] 2.3.4.4.2).
                const ByteView& slot = cell.value().value;
                const uint32_t hnid = static_cast<uint32_t>(slot.data()[0]) |
                                      static_cast<uint32_t>(slot.data()[1]) << 8 |
                                      static_cast<uint32_t>(slot.data()[2]) << 16 |
                                      static_cast<uint32_t>(slot.data()[3]) << 24;
                TEST_EQ(hnid, 0xA0u + row_index * 0x20u, "HNID of the PidTagDisplayName value");
                Result<ByteView> value = hn_heap_item(map, view_of(heap), hnid, kProfile);
                TEST_OK(value, "value heap item");
                if (value.ok()) {
                    TEST_CHECK(bytes_of(value.value()) == *expected_names[row_index]);
                }
            }
        }
        // dwRowID sits at ibData 0 of the row, which is the row's own PidTagLtpRowId.
        Result<TcCell> row_id_cell = tc_column_cell(table.value(), columns[11], row.value());
        TEST_CHECK(row_id_cell.ok() && row_id_cell.value().exists);
        if (row_id_cell.ok() && row_id_cell.value().exists) {
            TEST_CHECK(bytes_of(row_id_cell.value().value) == le32(expected_row_id[row_index]));
        }
        // PidTagSubfolders is the one 1-byte column, at rgib[TCI_1b].
        Result<TcCell> subfolders = tc_column_cell(table.value(), columns[7], row.value());
        TEST_CHECK(subfolders.ok() && subfolders.value().exists);
        if (subfolders.ok() && subfolders.value().exists) {
            TEST_CHECK(bytes_of(subfolders.value().value) ==
                       std::vector<uint8_t>{static_cast<uint8_t>(row_index == 0 ? 1 : 0)});
        }
        // [MS-PST] 2.3.4.4.1: iBit 0 is the MSB of rgCEB[0]. The bits of the columns with no value
        // stay clear, and the two bits past cCols stay zero.
        Result<ByteView> ceb = row.value().sub(table.value().info.rgib[2],
                                               ost2pst::ltp::tc_ceb_bytes(table.value().info));
        TEST_OK(ceb, "row Cell Existence Block");
        if (!ceb.ok()) {
            continue;
        }
        for (uint64_t bit = 0; bit < 16; ++bit) {
            TEST_EQ(tc_ceb_bit(ceb.value(), bit), expected_bit[bit], "CEB bit");
        }
    }
}

// A table with one column of every group: 8-byte, 4-byte, a variable-sized column that takes the
// 4-byte HNID slot, 2-byte and 1-byte. The columns are handed in out of tag order on purpose.
void check_mixed_width_tc() {
    const std::vector<TcColumnSpec> columns = {{0x3103001F}, {0x67F30003}, {0x00170003},
                                               {0x31010002}, {0x67F20003}, {0x0E330014},
                                               {0x3102000B}};
    const std::vector<uint8_t> name = utf16("A");
    const std::vector<uint8_t> wide = {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    // TcRow::values follows the order the columns were handed in: 0x3103, 0x67F3, 0x0017, 0x3101,
    // 0x67F2, 0x0E33, 0x3102. Row 1 leaves 0x3103, 0x3101 and 0x3102 out.
    const std::vector<TcRow> rows = {
        {0x1001,
         {name, le32(0), le32(0x0002), std::vector<uint8_t>{0x34, 0x12}, le32(0x1001), wide,
          std::vector<uint8_t>{1}}},
        {0x1000, {{}, le32(0), le32(0x0005), {}, le32(0x1000), wide, {}}},
    };

    Result<HeapImage> built = build_tc(columns, rows);
    TEST_OK(built, "build_tc with every column group");
    if (!built.ok()) {
        return;
    }
    TEST_EQ(built.value().allocation_count(), 5,
            "TCINFO, RowIndex BTHHEADER, TCROWID array, Row Matrix, one variable value");

    ost2pst::ltp::HnHeader hn;
    ost2pst::ltp::HnPageMap map;
    std::optional<BlockHeapSource> source;
    open_heap(built.value(), hn, map, source);
    Result<TcTable> table = read_tc(hn, *source);
    TEST_OK(table, "read_tc on the mixed TC");
    if (!table.ok()) {
        return;
    }
    TEST_EQ(table.value().info.c_cols, 7, "cCols");
    // 4-byte group: 0 and 4 for the two mandatory columns, then 8 (0x0017), 12 (0x0E33, 8 wide) and
    // 20 (0x3103, the HNID slot) -> 24. Then 24 (0x3101) -> 26, then 26 (0x3102) -> 27, then 1 CEB
    // byte.
    TEST_EQ(table.value().info.rgib[0], 24, "rgib[TCI_4b]");
    TEST_EQ(table.value().info.rgib[1], 26, "rgib[TCI_2b]");
    TEST_EQ(table.value().info.rgib[2], 27, "rgib[TCI_1b]");
    TEST_EQ(table.value().info.rgib[3], 28, "rgib[TCI_bm]");

    const uint32_t expected_tags[] = {0x00170003, 0x0E330014, 0x31010002, 0x3102000B,
                                      0x3103001F, 0x67F20003, 0x67F30003};
    const uint16_t expected_ib[] = {8, 12, 24, 26, 20, 0, 4};
    const uint8_t expected_cb[] = {4, 8, 2, 1, 4, 4, 4};
    const uint8_t expected_bit[] = {2, 3, 4, 5, 6, 0, 1};
    for (size_t index = 0; index < table.value().columns.size() && index < 7; ++index) {
        TEST_EQ(table.value().columns[index].tag, expected_tags[index], "sorted by tag");
        TEST_EQ(table.value().columns[index].ib_data, expected_ib[index], "ibData group order");
        TEST_EQ(table.value().columns[index].cb_data, expected_cb[index], "cbData");
        TEST_EQ(table.value().columns[index].i_bit, expected_bit[index], "iBit");
    }

    std::vector<TcRowId> row_ids;
    BthStats stats;
    FailureLog failures;
    Status status = walk_tc_row_index(
        table.value(), kProfile, *source,
        [&](const TcRowId& row) {
            row_ids.push_back(row);
            return true;
        },
        stats, failures);
    TEST_CHECK(status.ok());
    TEST_EQ(failures.total(), 0, "no findings for the mixed TC");
    TEST_EQ(row_ids.size(), 2, "RowIndex records");
    if (row_ids.size() != 2) {
        return;
    }
    TEST_EQ(row_ids[0].row_id, 0x1000, "the RowIndex is sorted by dwRowID");
    TEST_EQ(row_ids[0].row_index, 1, "dwRowIndex is the row position in the Row Matrix");
    TEST_EQ(row_ids[1].row_id, 0x1001, "second record");
    TEST_EQ(row_ids[1].row_index, 0, "second record row position");

    Result<ByteView> matrix =
        hn_heap_item(map, view_of(built.value()), table.value().info.hnid_rows, kProfile);
    TEST_OK(matrix, "Row Matrix heap item");
    if (!matrix.ok()) {
        return;
    }
    TEST_EQ(matrix.value().size(), 2 * 28, "two rows of 28 bytes");

    // Row 1 leaves three columns out; the space is still reserved ([MS-PST] 2.3.4.4.1).
    Result<ByteView> row = matrix.value().sub(28, 28);
    TEST_OK(row, "second row");
    if (row.ok()) {
        for (size_t index = 0; index < 7; ++index) {
            Result<TcCell> cell =
                tc_column_cell(table.value(), table.value().columns[index], row.value());
            TEST_OK(cell, "cell of the sparse row");
            if (!cell.ok()) {
                continue;
            }
            const bool expected = index == 0 || index == 1 || index == 5 || index == 6;
            TEST_EQ(cell.value().exists, expected, "sparse row cells");
        }
        Result<TcCell> wide_cell =
            tc_column_cell(table.value(), table.value().columns[1], row.value());
        TEST_CHECK(wide_cell.ok() && wide_cell.value().exists);
        if (wide_cell.ok() && wide_cell.value().exists) {
            TEST_CHECK(bytes_of(wide_cell.value().value) == wide);
        }
        Result<TcCell> importance =
            tc_column_cell(table.value(), table.value().columns[0], row.value());
        TEST_CHECK(importance.ok() && importance.value().exists);
        if (importance.ok() && importance.value().exists) {
            TEST_CHECK(bytes_of(importance.value().value) == le32(0x0005));
        }
    }

    // Row 0 stores its one variable-sized value behind the HNID of allocation 5.
    Result<ByteView> first = matrix.value().sub(0, 28);
    TEST_OK(first, "first row");
    if (first.ok()) {
        Result<TcCell> cell =
            tc_column_cell(table.value(), table.value().columns[4], first.value());
        TEST_CHECK(cell.ok() && cell.value().exists);
        if (cell.ok() && cell.value().exists) {
            TEST_CHECK(bytes_of(cell.value().value) == le32(0xA0));
            Result<ByteView> value = hn_heap_item(map, view_of(built.value()), 0xA0, kProfile);
            TEST_OK(value, "the value behind the HNID");
            if (value.ok()) {
                TEST_CHECK(bytes_of(value.value()) == name);
            }
        }
    }
}

void check_empty_tc() {
    Result<HeapImage> built = build_tc({{0x67F20003}, {0x67F30003}}, {});
    TEST_OK(built, "a TC with no rows");
    if (!built.ok()) {
        return;
    }
    TEST_EQ(built.value().allocation_count(), 2,
            "TCINFO with its descriptors plus the RowIndex BTHHEADER");

    ost2pst::ltp::HnHeader hn;
    ost2pst::ltp::HnPageMap map;
    std::optional<BlockHeapSource> source;
    open_heap(built.value(), hn, map, source);
    Result<TcTable> table = read_tc(hn, *source);
    TEST_OK(table, "read_tc on the empty TC");
    if (!table.ok()) {
        return;
    }
    // Outlook names a RowIndex even for a table with no rows: every table context of docs/1.pst and
    // of samples/reference.ost does, and the empty ones point at a BTHHEADER with hidRoot 0.
    TEST_EQ(table.value().info.hid_row_index, 0x40, "the RowIndex BTHHEADER is always named");
    TEST_EQ(table.value().info.hnid_rows, 0, "hnidRows is 0 when the TC has no rows");

    Result<ByteView> row_index = hn_heap_item(map, view_of(built.value()), 0x40, kProfile);
    TEST_OK(row_index, "the RowIndex allocation of an empty TC");
    if (row_index.ok()) {
        Result<BthHeader> bth = decode_bth_header(row_index.value(), kProfile);
        TEST_OK(bth, "the RowIndex of an empty TC is a BTHHEADER");
        if (bth.ok()) {
            TEST_EQ(bth.value().b_type, ost2pst::ltp::kBthType, "bType is the BTH signature");
            TEST_EQ(bth.value().cb_key, 4, "the Unicode RowIndex cbKey");
            TEST_EQ(bth.value().cb_ent, 4, "the Unicode RowIndex cbEnt");
            TEST_EQ(bth.value().hid_root, 0, "an empty RowIndex has hidRoot 0");
        }
    }
    TEST_EQ(table.value().info.rgib[0], 8, "the two mandatory columns");
    TEST_EQ(table.value().info.rgib[3], 9, "plus one CEB byte");

    BthStats stats;
    FailureLog failures;
    uint64_t rows = 0;
    Status status = walk_tc_row_index(
        table.value(), kProfile, *source,
        [&](const TcRowId&) {
            ++rows;
            return true;
        },
        stats, failures);
    TEST_CHECK(status.ok());
    TEST_EQ(rows, 0, "no rows");
    TEST_EQ(failures.total(), 0, "no findings for an empty TC");
}

// [MS-PST] 2.3.4.4: "In practice, the Row Matrix is stored in a subnode because of its typical
// size, but in rare cases, a TC can fit into a single data block if it is small enough." A table
// whose rows do not fit the heap the writer builds puts them in a subnode whose local NID is what
// TCINFO.hnidRows names, which is the shape both Contents Tables of the sample have (hnidRows 0x3F,
// hidType NID_TYPE_LTP).
void check_subnode_matrix_tc() {
    const std::vector<TcColumnSpec> columns = {{0x67F20003}, {0x67F30003}, {0x3001001F}};
    std::vector<TcRow> rows;
    std::vector<std::vector<uint8_t>> names;
    for (uint32_t index = 0; index < 150; ++index) {
        const std::vector<uint8_t> name = utf16("row " + std::to_string(index));
        names.push_back(name);
        rows.push_back(TcRow{0x1000 + index, {le32(0x1000 + index), le32(0), name}});
    }

    LocalNids local_nids;
    Result<TcNode> built = build_table(columns, rows, local_nids);
    TEST_OK(built, "build_table with 150 rows");
    if (!built.ok()) {
        return;
    }
    const TcNode& node = built.value();
    // TCINFO, the RowIndex BTHHEADER and the TCROWID array, then the 150 names: the rows left the
    // heap.
    TEST_EQ(node.heap.allocation_count(), 153, "the Row Matrix is not a heap allocation");
    TEST_EQ(node.subnodes.size(), 1, "one subnode: the Row Matrix");
    if (node.subnodes.size() != 1) {
        return;
    }
    TEST_EQ(node.subnodes[0].nid, 0x3F, "the Row Matrix subnode is nidIndex 1 under NID_TYPE_LTP");
    TEST_EQ(node.hnid_rows, 0x3F, "TCINFO.hnidRows names that subnode");
    TEST_EQ(hid_type(node.hnid_rows), kNidTypeLtp,
            "so hnidRows is an NID, not a HID ([MS-PST] 2.3.3.2)");
    TEST_EQ(node.subnodes[0].bytes.size(), 150 * 13, "150 rows of 13 bytes");
    TEST_EQ(local_nids.taken(), 1, "only the Row Matrix needed a local NID");

    ost2pst::ltp::HnHeader hn;
    ost2pst::ltp::HnPageMap map;
    std::optional<BlockHeapSource> source;
    open_heap(node.heap, hn, map, source);
    Result<TcTable> table = read_tc(hn, *source);
    TEST_OK(table, "read_tc on the subnode-matrix TC");
    if (!table.ok()) {
        return;
    }
    TEST_EQ(table.value().info.hnid_rows, 0x3F, "the reader reads hnidRows back");
    TEST_EQ(table.value().info.hid_row_index, 0x40, "the RowIndex is still a heap allocation");
    TEST_EQ(table.value().info.rgib[3], 13, "the row size is unchanged by where the rows live");

    std::vector<TcRowId> row_ids;
    BthStats stats;
    FailureLog failures;
    Status status = walk_tc_row_index(
        table.value(), kProfile, *source,
        [&](const TcRowId& row) {
            row_ids.push_back(row);
            return true;
        },
        stats, failures);
    TEST_CHECK(status.ok());
    TEST_EQ(failures.total(), 0, "no findings for the subnode-matrix TC");
    TEST_EQ(row_ids.size(), 150, "RowIndex records");
    if (row_ids.size() != 150) {
        return;
    }
    TEST_EQ(row_ids[0].row_id, 0x1000, "the RowIndex is sorted by dwRowID");
    TEST_EQ(row_ids[0].row_index, 0, "dwRowIndex is the position in the Row Matrix");
    TEST_EQ(row_ids[149].row_index, 149, "the last row");

    // The subnode bytes are the Row Matrix, and the reader reads rows out of them the same way it
    // reads them out of a heap allocation ([MS-PST] 2.3.4.4 / 2.3.4.4.1).
    const ByteView matrix(node.subnodes[0].bytes.data(), node.subnodes[0].bytes.size(), 0);
    const std::vector<TcColumn>& cols = table.value().columns;
    for (uint32_t index = 0; index < 150; ++index) {
        Result<ByteView> row = matrix.sub(index * 13, 13);
        TEST_OK(row, "Row Matrix row of the subnode");
        if (!row.ok()) {
            continue;
        }
        Result<TcCell> name_cell =
            tc_column_cell(table.value(), cols[column_of(cols, 0x3001001F)], row.value());
        TEST_CHECK(name_cell.ok() && name_cell.value().exists);
        if (!name_cell.ok() || !name_cell.value().exists) {
            continue;
        }
        // With no matrix allocation, the values start at allocation 4.
        const uint32_t expected_hid =
            static_cast<uint32_t>((4 + index) << ost2pst::ltp::kHidIndexShift);
        TEST_CHECK_MSG(bytes_of(name_cell.value().value) == le32(expected_hid),
                       "the cell names the value allocation");
        Result<ByteView> value = hn_heap_item(map, view_of(node.heap), expected_hid, kProfile);
        TEST_OK(value, "the value behind the HNID");
        if (value.ok()) {
            TEST_CHECK(bytes_of(value.value()) == names[index]);
        }
        Result<TcCell> row_id_cell =
            tc_column_cell(table.value(), cols[column_of(cols, 0x67F20003)], row.value());
        TEST_CHECK(row_id_cell.ok() && row_id_cell.value().exists);
        if (row_id_cell.ok() && row_id_cell.value().exists) {
            TEST_CHECK(bytes_of(row_id_cell.value().value) == le32(0x1000 + index));
        }
    }
}

// [MS-PST] 2.3.4.4.2 and 2.6.2.4.2: a cell value past 3580 bytes is a subnode of the TC node and
// the rgdwData slot holds its local NID. The Row Matrix stays in the heap here, so the matrix
// allocation and its HNID are unchanged and only the cell points outside the heap.
void check_tc_value_subnode() {
    const std::vector<TcColumnSpec> columns = {{0x67F20003}, {0x67F30003}, {0x3001001F}};
    const std::vector<uint8_t> wide(4000, 0x41);
    const std::vector<TcRow> rows = {{0x1000, {le32(0x1000), le32(0), wide}}};

    LocalNids local_nids;
    Result<TcNode> built = build_table(columns, rows, local_nids);
    TEST_OK(built, "build_table with a 4000-byte cell value");
    if (!built.ok()) {
        return;
    }
    const TcNode& node = built.value();
    TEST_EQ(node.heap.allocation_count(), 4,
            "TCINFO, RowIndex BTHHEADER, TCROWID array, Row Matrix");
    TEST_EQ(node.subnodes.size(), 1, "the long value is a subnode");
    TEST_EQ(node.hnid_rows, 0x80, "the Row Matrix is still the heap allocation at 0x80");
    if (node.subnodes.size() != 1) {
        return;
    }
    TEST_EQ(node.subnodes[0].nid, 0x3F, "the value subnode NID");
    TEST_CHECK(node.subnodes[0].bytes == wide);
    TEST_EQ(local_nids.taken(), 1, "one local NID for one subnode");

    ost2pst::ltp::HnHeader hn;
    ost2pst::ltp::HnPageMap map;
    std::optional<BlockHeapSource> source;
    open_heap(node.heap, hn, map, source);
    Result<TcTable> table = read_tc(hn, *source);
    TEST_OK(table, "read_tc on the TC with a subnode value");
    if (!table.ok()) {
        return;
    }
    Result<ByteView> matrix =
        hn_heap_item(map, view_of(node.heap), table.value().info.hnid_rows, kProfile);
    TEST_OK(matrix, "the Row Matrix heap item");
    if (!matrix.ok()) {
        return;
    }
    const std::vector<TcColumn>& cols = table.value().columns;
    Result<TcCell> cell =
        tc_column_cell(table.value(), cols[column_of(cols, 0x3001001F)], matrix.value());
    TEST_CHECK(cell.ok() && cell.value().exists);
    if (cell.ok() && cell.value().exists) {
        const uint32_t named = cell.value().value.u32(0).value();
        TEST_EQ(named, 0x3Fu, "the cell names the subnode NID");
        TEST_EQ(hid_type(named), kNidTypeLtp, "and that HNID is an NID, not a HID");
    }
}

// A folder Contents Table with a few dozen messages does not fit one data block: the cell values
// alone run past the 4,608 bytes that still leave FILL_LEVEL_EMPTY ([MS-PST] 2.3.1.2), so the heap
// node fans out over several data blocks ([MS-PST] 2.3.1.6.2) and every HID names the block its
// item lives in
// ([MS-PST] 2.3.1.1). This is the shape the sample's Contents Tables have.
void check_multi_block_tc() {
    const std::vector<TcColumnSpec> columns = {{0x67F20003}, {0x67F30003}, {0x3001001F}};
    std::vector<TcRow> rows;
    std::vector<std::vector<uint8_t>> names;
    for (uint32_t index = 0; index < 30; ++index) {
        std::vector<uint8_t> name(200, static_cast<uint8_t>('a')); // a fixed 200-byte UTF-16 value
        name[0] = static_cast<uint8_t>(index & 0xFF);
        name[2] = static_cast<uint8_t>((index >> 8) & 0xFF);
        names.push_back(name);
        rows.push_back(TcRow{0x1000 + index, {le32(0x1000 + index), le32(0), name}});
    }

    LocalNids local_nids;
    Result<TcNode> built = build_table(columns, rows, local_nids);
    TEST_OK(built, "build_table with 30 rows of 200-byte values");
    if (!built.ok()) {
        return;
    }
    const TcNode& node = built.value();
    TEST_EQ(node.heap.allocation_count(), 33u,
            "TCINFO, RowIndex BTHHEADER, TCROWID array, 30 values");
    TEST_EQ(node.heap.block_count(), 2u, "the heap node needs two data blocks");
    TEST_EQ(node.subnodes.size(), 1u, "the Row Matrix is the node's subnode");
    TEST_EQ(node.hnid_rows, 0x3Fu, "and TCINFO names it");
    if (node.subnodes.size() != 1) {
        return;
    }
    TEST_EQ(node.subnodes[0].bytes.size(), 30u * 13u, "30 rows of 13 bytes");

    // [MS-PST] 2.3.1.1: the allocations of block 0 keep the numbering a single-block node had, and
    // the ones that spilled name the second block.
    TEST_EQ(node.heap.hid(1), 0x20u, "hidUserRoot is TCINFO in block 0");
    TEST_EQ(node.heap.hid(2), 0x40u, "the RowIndex BTHHEADER is in block 0");
    TEST_EQ(node.heap.hid(3), 0x60u, "so is the TCROWID array");
    TEST_EQ(node.heap.hid(24), 0x00000300u, "the last value block 0 still holds");
    TEST_EQ(node.heap.hid(25), 0x00010020u, "the first value that had to move to block 1");
    for (uint64_t allocation = 1; allocation <= 24; ++allocation) {
        TEST_EQ(ost2pst::ltp::hid_block_index(node.heap.hid(allocation), kProfile), 0u,
                "the first 24 allocations are in block 0");
    }
    for (uint64_t allocation = 25; allocation <= 33; ++allocation) {
        TEST_EQ(ost2pst::ltp::hid_block_index(node.heap.hid(allocation), kProfile), 1u,
                "the rest are in block 1");
    }

    const std::vector<std::vector<uint8_t>>& blocks = node.heap.blocks();
    TEST_EQ(blocks.size(), 2u, "one image per data block");
    TEST_EQ(blocks[0].size(), 8176u, "nonfinal TC heap retains full data capacity");
    TEST_EQ(blocks[1].size(), 2 + 9 * 200 + 4 + 10 * 2,
            "block 1 cb: HNPAGEHDR, 9 allocations, map");
    TEST_CHECK(blocks[1].size() <= 4608 + 4 + 10 * 2);

    std::vector<ost2pst::ltp::HnFragment> fragments;
    for (size_t index = 0; index < blocks.size(); ++index) {
        ost2pst::ltp::HnFragment fragment;
        fragment.owned = blocks[index];
        fragment.block.form = ost2pst::ltp::BlockForm::kRaw;
        fragment.block.block_base = kBlockBase + index * 0x10000;
        fragment.block.raw_block =
            ByteView(fragment.owned.data(), fragment.owned.size(), fragment.block.block_base);
        const ByteView view = fragment.block.heap_node();
        if (index == 0) {
            Result<ost2pst::ltp::HnHeader> header = ost2pst::ltp::decode_hn_header(view);
            TEST_OK(header, "block 0 carries the HNHDR");
            if (header.ok()) {
                TEST_EQ(header.value().hid_user_root, 0x20u, "hidUserRoot is TCINFO");
            }
        }
        // [MS-PST] 2.3.1.3: the second block carries ibHnpm alone, and it is read off the block.
        Result<uint16_t> ib_hnpm = view.u16(ost2pst::ltp::kHnIbHnpmOffset);
        TEST_OK(ib_hnpm, "the block's own ibHnpm");
        Result<ost2pst::ltp::HnPageMap> map =
            decode_hn_page_map(view, ib_hnpm.ok() ? ib_hnpm.value() : 0);
        TEST_OK(map, "the block's own HNPAGEMAP");
        if (!map.ok()) {
            continue;
        }
        TEST_EQ(map.value().c_alloc, index == 0 ? 24u : 9u, "allocations per block");
        fragment.page_map = map.take();
        fragment.page_map_ok = true;
        fragments.push_back(std::move(fragment));
    }

    // The reader reaches such a node through the fragments its data tree names, exactly as
    // open_node builds them for a node whose bidData is an XBLOCK ([MS-PST] 2.2.2.8.3.2.1
    // / 2.3.1.6.2).
    std::optional<ost2pst::ltp::NodeFragmentHeapSource> source;
    source.emplace(fragments, kProfile);
    Result<ost2pst::ltp::HnHeader> hn =
        ost2pst::ltp::decode_hn_header(ByteView(blocks[0].data(), blocks[0].size(), kBlockBase));
    TEST_OK(hn, "the node's HNHDR");
    if (!hn.ok()) {
        return;
    }
    Result<TcTable> table = read_tc(hn.value(), *source);
    TEST_OK(table, "read_tc on a TC spread over two data blocks");
    if (!table.ok()) {
        return;
    }
    TEST_EQ(table.value().info.hid_row_index, 0x40u, "the RowIndex is still in block 0");
    TEST_EQ(table.value().info.hnid_rows, 0x3Fu, "and the rows are still a subnode");
    TEST_EQ(table.value().info.rgib[3], 13u, "the row size did not change");

    std::vector<TcRowId> row_ids;
    ost2pst::ltp::BthStats stats;
    FailureLog failures;
    Status status = ost2pst::ltp::walk_tc_row_index(
        table.value(), kProfile, *source,
        [&](const TcRowId& row) {
            row_ids.push_back(row);
            return true;
        },
        stats, failures);
    TEST_CHECK(status.ok());
    TEST_EQ(failures.total(), 0u, "no findings for a TC spread over two blocks");
    TEST_EQ(row_ids.size(), 30u, "the RowIndex read out of block 0");

    const ByteView matrix(node.subnodes[0].bytes.data(), node.subnodes[0].bytes.size(), 0);
    const std::vector<TcColumn>& cols = table.value().columns;
    for (uint32_t index = 0; index < row_ids.size(); ++index) {
        Result<ByteView> row = matrix.sub(row_ids[index].row_index * 13, 13);
        TEST_OK(row, "a row of the Row Matrix subnode");
        if (!row.ok()) {
            continue;
        }
        Result<TcCell> cell =
            tc_column_cell(table.value(), cols[column_of(cols, 0x3001001F)], row.value());
        TEST_CHECK(cell.ok() && cell.value().exists);
        if (!cell.ok() || !cell.value().exists) {
            continue;
        }
        // The 21 values block 0 still holds keep the HIDs a single-block node had; the rest name
        // block 1.
        const uint32_t expected_hid =
            index < 21
                ? static_cast<uint32_t>((4 + index) << ost2pst::ltp::kHidIndexShift)
                : static_cast<uint32_t>(0x10000u | ((index - 20) << ost2pst::ltp::kHidIndexShift));
        TEST_CHECK_MSG(bytes_of(cell.value().value) == le32(expected_hid),
                       "the cell names the value where the writer put it");
        Result<ByteView> value = source->heap(expected_hid);
        TEST_OK(value, "the reader resolves the value in its own block");
        if (value.ok()) {
            TEST_CHECK(bytes_of(value.value()) == names[index]);
        }
    }
    TEST_EQ(source->cross_block_misses, 0u, "no HID named a block this node does not have");
}

class ImageHeapSource final : public ost2pst::ltp::HeapSource {
  public:
    explicit ImageHeapSource(const HeapImage& image) : image_(image) {}
    Result<ByteView> heap(uint32_t hid) override {
        const auto block = ost2pst::ltp::hid_block_index(hid, kProfile);
        if (block >= image_.blocks().size()) {
            return ost2pst::util::make_error(ErrorKind::kBadField, "test.heap", hid, block,
                                             "missing heap block");
        }
        const auto& bytes = image_.blocks()[block];
        ByteView view(bytes.data(), bytes.size(), 0);
        auto map = decode_hn_page_map(view, view.u16(0).value());
        if (!map.ok())
            return map.error();
        return hn_heap_item(map.value(), view, hid, kProfile);
    }

  private:
    const HeapImage& image_;
};

class GeneratedRows final : public ost2pst::writer::TcRowSource {
  public:
    explicit GeneratedRows(uint32_t size) : size(size) {}
    uint64_t count() const override { return size; }
    Result<TcRow> read(uint64_t index) const override {
        ++calls;
        if (calls == fail_call) {
            return ost2pst::util::make_error(ErrorKind::kIo, "test.row.read", index, calls,
                                             "injected row read failure");
        }
        uint32_t id = 1000 + size - 1 - static_cast<uint32_t>(index);
        if (duplicate && index == size - 1)
            id = 1000 + size - 1;
        if (changed && calls > size && index == 0)
            ++id;
        return TcRow{id, {le32(id), le32(0)}};
    }
    uint32_t size;
    mutable uint64_t calls = 0;
    uint64_t fail_call = ~0ull;
    bool duplicate = false;
    bool changed = false;
};

void check_streamed_row_index() {
    // 447 eight-byte records per leaf; the last case needs two index levels.
    for (const uint32_t size : {447u, 448u, 199810u}) {
        GeneratedRows rows(size);
        LocalNids nids;
        auto built = ost2pst::writer::build_table_from({{0x67F20003}, {0x67F30003}}, rows, nids);
        TEST_OK(built, "table from repeatable bounded row source");
        if (!built.ok())
            continue;
        const auto& node = built.value();
        ImageHeapSource source(node.heap);
        auto header = decode_hn_header(view_of(node.heap));
        TEST_OK(header, "streamed TC header");
        if (!header.ok())
            continue;
        auto table = read_tc(header.value(), source);
        TEST_OK(table, "streamed TC");
        if (!table.ok())
            continue;
        auto bth_bytes = source.heap(table.value().info.hid_row_index);
        TEST_OK(bth_bytes, "streamed row index header");
        if (!bth_bytes.ok())
            continue;
        auto bth = decode_bth_header(bth_bytes.value(), kProfile);
        TEST_OK(bth, "streamed row index depth");
        if (!bth.ok())
            continue;
        TEST_EQ(bth.value().b_idx_levels, size == 447 ? 0u : (size == 448 ? 1u : 2u),
                "exact BTH split boundaries");
        BthStats stats;
        FailureLog failures;
        uint32_t seen = 0;
        auto status = ost2pst::ltp::walk_tc_row_index(
            table.value(), kProfile, source,
            [&](const TcRowId& row) {
                TEST_EQ(row.row_id, 1000 + seen, "streamed key order");
                TEST_EQ(row.row_index, size - 1 - seen, "streamed original matrix order");
                ++seen;
                return true;
            },
            stats, failures);
        TEST_OK(status, "walk streamed multi-level index");
        TEST_EQ(seen, size, "no rows lost at any level");
        TEST_EQ(failures.total(), 0u, "streamed index findings");
        TEST_CHECK(rows.calls <= 4ull * size);
    }
    for (uint64_t pass = 0; pass < 4; ++pass) {
        GeneratedRows rows(448);
        rows.fail_call = pass * 448 + 20;
        LocalNids nids;
        TEST_ERROR(ost2pst::writer::build_table_from({{0x67F20003}, {0x67F30003}}, rows, nids),
                   ErrorKind::kIo, "test.row.read", "propagate a read failure in every pass");
    }
    GeneratedRows duplicate(600);
    duplicate.duplicate = true;
    LocalNids duplicate_nids;
    TEST_ERROR(
        ost2pst::writer::build_table_from({{0x67F20003}, {0x67F30003}}, duplicate, duplicate_nids),
        ErrorKind::kBadField, "TCROWID.dwRowID", "duplicate across leaf boundary");
    GeneratedRows changed(600);
    changed.changed = true;
    LocalNids changed_nids;
    TEST_ERROR(
        ost2pst::writer::build_table_from({{0x67F20003}, {0x67F30003}}, changed, changed_nids),
        ErrorKind::kBadField, "writer.tc.changed_row", "changed source row refused");
}

void check_large_row_index() {
    // 600 TCROWID records do not fit one 3580-byte BTH leaf (MS-PST 2.6.2.2.2).
    std::vector<TcRow> rows;
    for (uint32_t i = 0; i < 600; ++i) {
        const uint32_t id = 1000 + 599 - i;
        rows.push_back(TcRow{id, {le32(id), le32(0)}});
    }
    LocalNids nids;
    auto built = build_table({{0x67F20003}, {0x67F30003}}, rows, nids);
    TEST_OK(built, "multi-leaf TC RowIndex");
    if (!built.ok())
        return;
    const auto& node = built.value();
    ImageHeapSource source(node.heap);
    auto header = decode_hn_header(view_of(node.heap));
    TEST_OK(header, "large TC header");
    if (!header.ok())
        return;
    auto table = read_tc(header.value(), source);
    TEST_OK(table, "large TC");
    if (!table.ok())
        return;
    BthStats stats;
    FailureLog failures;
    uint32_t seen = 0;
    auto status = ost2pst::ltp::walk_tc_row_index(
        table.value(), kProfile, source,
        [&](const TcRowId& row) {
            TEST_EQ(row.row_id, 1000 + seen, "sorted key across leaves");
            TEST_EQ(row.row_index, 599 - seen, "original matrix order preserved");
            ++seen;
            return true;
        },
        stats, failures);
    TEST_OK(status, "walk large TC RowIndex");
    TEST_EQ(seen, 600u, "all rows");
    TEST_EQ(failures.total(), 0u, "no BTH failures");
    TEST_CHECK(stats.index_records > 0);
}

void check_writer_rejections() {
    TEST_ERROR(build_tc({}, {}), ErrorKind::kBadField, "TCINFO.cCols", "a TC with no columns");
    TEST_ERROR(build_tc({{0x67F20003}, {0x67F20003}}, {}), ErrorKind::kBadField, "TCOLDESC.tag",
               "a duplicated column tag");
    const std::vector<TcColumnSpec> two = {{0x67F20003}, {0x67F30003}};
    TEST_ERROR(
        build_tc(two, {{0x1000, {le32(0x1000), le32(0)}}, {0x1000, {le32(0x1000), le32(0)}}}),
        ErrorKind::kBadField, "TCROWID.dwRowID", "two rows with one dwRowID");
    TEST_ERROR(build_tc(two, {{0x1000, {le32(0x1000)}}}), ErrorKind::kBadField, "RowMatrix.row",
               "a row with too few values");
    TEST_ERROR(build_tc({{0x67F20003}, {0x67F30003}, {0x00170003}},
                        {{0x1000, {le32(0x1000), le32(0), std::vector<uint8_t>{1, 2, 3}}}}),
               ErrorKind::kBadField, "TCCell.value", "a 3-byte value in a 4-byte column");
    // A value past 3580 bytes leaves the heap, so the plain build_tc that cannot emit a subnode
    // refuses it instead of dropping the subnode ([MS-PST] 2.3.4.4.2).
    TEST_ERROR(build_tc({{0x67F20003}, {0x67F30003}, {0x3001001F}},
                        {{0x1000, {le32(0x1000), le32(0), std::vector<uint8_t>(3581, 0x41)}}}),
               ErrorKind::kBadField, "writer.build_tc", "a table that needs a subnode");
    TEST_ERROR(build_tc({{0x67F20014}, {0x67F30003}}, {}), ErrorKind::kBadField, "TCOLDESC.cbData",
               "PidTagLtpRowId wider than the 4 bytes its ibData allows");
}

class DenseRows final : public ost2pst::writer::TcRowSource {
  public:
    uint32_t size = 69621;
    size_t payload_size = 84;
    mutable uint64_t calls = 0;
    uint64_t count() const override { return size; }
    static std::vector<uint8_t> payload(uint32_t row, uint32_t column, size_t size) {
        std::vector<uint8_t> bytes(size, static_cast<uint8_t>(column + 0x40));
        const auto identity = le32(row);
        std::copy(identity.begin(), identity.end(), bytes.begin());
        return bytes;
    }
    Result<TcRow> read(uint64_t index) const override {
        ++calls;
        const uint32_t id = 1000 + size - 1 - static_cast<uint32_t>(index);
        TcRow row{id, {le32(id), le32(0)}};
        for (uint32_t column = 0; column < 6; ++column)
            row.values.push_back(payload(static_cast<uint32_t>(index), column, payload_size));
        return row;
    }
};

void check_dense_table_workspace() {
    std::vector<TcColumnSpec> columns = {{0x67F20003}, {0x67F30003}};
    for (uint32_t column = 0; column < 6; ++column)
        columns.push_back({((0x5000 + column) << 16) | 0x0102});
    DenseRows rows;
    LocalNids nids;
    auto built = ost2pst::writer::build_table_from(columns, rows, nids);
    TEST_OK(built, "69,621 rows with dense values exceed the former 128 MiB accounting ceiling");
    if (built.ok()) {
        const auto& node = built.value();
        TEST_EQ(node.subnodes.size(), 1u, "only the row matrix leaves the heap");
        ImageHeapSource source(node.heap);
        auto header = decode_hn_header(view_of(node.heap));
        TEST_OK(header, "dense table heap header");
        if (!header.ok())
            return;
        auto table = read_tc(header.value(), source);
        TEST_OK(table, "reread dense table schema");
        if (!table.ok() || node.subnodes.empty())
            return;
        BthStats stats;
        FailureLog failures;
        uint32_t seen = 0;
        auto walked = ost2pst::ltp::walk_tc_row_index(
            table.value(), kProfile, source,
            [&](const TcRowId& row) {
                TEST_EQ(row.row_id, 1000 + seen, "dense table sorted row ID");
                TEST_EQ(row.row_index, rows.size - 1 - seen, "dense table original row position");
                ++seen;
                return true;
            },
            stats, failures);
        TEST_OK(walked, "reread every dense table index entry");
        TEST_EQ(seen, rows.size, "no rows omitted");
        const auto& matrix = node.subnodes.front().bytes;
        TEST_EQ(matrix.size(), static_cast<uint64_t>(rows.size) * node.row_size,
                "complete dense row matrix");
        for (uint32_t index = 0; index < rows.size; ++index) {
            ByteView row(matrix.data() + static_cast<size_t>(index) * node.row_size, node.row_size,
                         0);
            for (uint32_t column = 0; column < 6; ++column) {
                const auto tag = ((0x5000 + column) << 16) | 0x0102;
                auto cell = tc_column_cell(
                    table.value(), table.value().columns[column_of(table.value().columns, tag)],
                    row);
                TEST_OK(cell, "dense table cell survives");
                if (!cell.ok())
                    continue;
                TEST_CHECK(cell.value().exists);
                auto value = source.heap(cell.value().value.u32(0).value());
                TEST_OK(value, "dense table value HID resolves");
                if (value.ok())
                    TEST_CHECK(bytes_of(value.value()) ==
                               DenseRows::payload(index, column, rows.payload_size));
            }
        }
        TEST_EQ(failures.total(), 0u, "no dense index failures");
        TEST_EQ(rows.calls, 4ull * rows.size, "bounded repeatable passes");
    }
    DenseRows excessive;
    excessive.payload_size = 3580;
    LocalNids excessive_nids;
    auto refused = ost2pst::writer::build_table_from(columns, excessive, excessive_nids);
    TEST_ERROR(refused, ErrorKind::kUnsupported, "writer.tc.workspace",
               "value accounting still bounded");
    if (!refused.ok()) {
        TEST_CHECK(refused.error().detail.find("limit=536870912") != std::string::npos);
        TEST_CHECK(refused.error().detail.find("value_bytes=3580") != std::string::npos);
    }
    auto wide_columns = columns;
    wide_columns.resize(2);
    for (uint32_t column = 0; column < 253; ++column)
        wide_columns.push_back({((0x4000 + column) << 16) | 0x0102});
    GeneratedRows wide(1000000);
    LocalNids wide_nids;
    TEST_ERROR(ost2pst::writer::build_table_from(wide_columns, wide, wide_nids),
               ErrorKind::kUnsupported, "writer.tc.workspace", "metadata accounting still bounded");
    TEST_EQ(wide.calls, 0u, "metadata limit checked before reading row values");
    DenseRows too_many;
    too_many.size = 1000001;
    LocalNids too_many_nids;
    TEST_ERROR(ost2pst::writer::build_table_from(columns, too_many, too_many_nids),
               ErrorKind::kUnsupported, "writer.tc.row_budget", "row ceiling still bounded");
    TEST_EQ(too_many.calls, 0u, "reject row limit before reading values");
}

void check_spilled_table() {
    std::vector<TcColumnSpec> columns = {{0x67F20003}, {0x67F30003}};
    for (uint32_t column = 0; column < 6; ++column)
        columns.push_back({((0x5000 + column) << 16) | 0x0102});
    DenseRows rows;
    rows.size = 9000; // multiple external-sort runs, reverse row IDs
    LocalNids reference_nids;
    auto reference = ost2pst::writer::build_table_from(columns, rows, reference_nids);
    TEST_OK(reference, "resident reference table");
    if (!reference.ok())
        return;
    auto resources = std::make_shared<ost2pst::util::Workspace>(
        std::filesystem::temp_directory_path().wstring(), 1024 * 1024);
    {
        LocalNids paged_nids;
        auto paged = ost2pst::writer::build_table_from(columns, rows, paged_nids, resources);
        TEST_OK(paged, "same table fits a one MiB shared cache by spilling");
        if (!paged.ok())
            return;
        size_t block = 0;
        TEST_OK(paged.value().heap.stream_blocks([&](ByteView bytes) -> Status {
            TEST_CHECK(block < reference.value().heap.blocks().size());
            if (block < reference.value().heap.blocks().size())
                TEST_CHECK(bytes_of(bytes) == reference.value().heap.blocks()[block]);
            ++block;
            return {};
        }),
                "stream every heap block and compare exact bytes");
        TEST_EQ(block, reference.value().heap.block_count(), "same heap packing");
        TEST_EQ(paged.value().hnid_rows, reference.value().hnid_rows, "same matrix NID");
        TEST_EQ(paged.value().subnodes.size(), reference.value().subnodes.size(), "same subnodes");
        TEST_CHECK(paged.value().subnodes[0].bytes.empty());
        const auto source = paged.value().subnodes[0].source;
        TEST_CHECK(source);
        if (source) {
            std::vector<uint8_t> actual(static_cast<size_t>(source->size()));
            TEST_OK(source->read_at(0, actual.data(), actual.size()), "spooled matrix");
            TEST_CHECK(actual == reference.value().subnodes[0].bytes);
        }
        TEST_CHECK(resources->spilled_bytes > 0);
        TEST_CHECK(resources->memory->peak() <= resources->memory->limit());
    }
    TEST_EQ(resources->memory->used(), 0u, "returned table releases all spill leases");
    // Same valid table refused by the legacy 512 MiB cumulative-copy accounting.
    // Its actual payload is ~143 MiB and can be processed with a one MiB cache.
    DenseRows large;
    large.size = 7000;
    large.payload_size = 3580;
    LocalNids old_nids;
    TEST_ERROR(ost2pst::writer::build_table_from(columns, large, old_nids), ErrorKind::kUnsupported,
               "writer.tc.workspace", "reproduce fixed ceiling");
    LocalNids spill_nids;
    auto large_table = ost2pst::writer::build_table_from(columns, large, spill_nids, resources);
    TEST_OK(large_table, "table exceeding old accounting limit streams with small cache");
    if (large_table.ok()) {
        uint64_t count = 0;
        TEST_OK(large_table.value().heap.stream_blocks([&](ByteView) -> Status {
            ++count;
            return {};
        }),
                "all large table heap blocks readable");
        TEST_EQ(count, large_table.value().heap.block_count(), "no emitted blocks lost");
    }
}

} // namespace

int main() {
    check_spec_sample_tc();
    check_mixed_width_tc();
    check_empty_tc();
    check_subnode_matrix_tc();
    check_tc_value_subnode();
    check_multi_block_tc();
    check_large_row_index();
    check_streamed_row_index();
    check_writer_rejections();
    check_dense_table_workspace();
    check_spilled_table();
    return ost2pst::test::finish("writer_tc_test");
}
