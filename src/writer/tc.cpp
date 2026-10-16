#include "ost2pst/writer/tc.h"

#include <algorithm>
#include <string>
#include <utility>

#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/prop_type.h"
#include "ost2pst/writer/layout.h"

#include "internal/put.h"

namespace ost2pst::writer {

using util::ErrorKind;
using util::make_error;
using util::Result;
using util::Status;

namespace {
util::SharedBytes cell_source(const TcRow& row, size_t column) {
    return row.sources.empty() ? util::SharedBytes{} : row.sources[column];
}
uint64_t cell_size(const TcRow& row, size_t column) {
    const auto source = cell_source(row, column);
    return source ? source->size() : row.values[column].size();
}
Result<std::vector<uint8_t>> small_cell(const TcRow& row, size_t column, uint64_t limit) {
    const auto source = cell_source(row, column);
    if (!source)
        return row.values[column];
    if (source->size() > limit)
        return make_error(ErrorKind::kBadField, "TCCell.source_size", column, source->size());
    std::vector<uint8_t> bytes(static_cast<size_t>(source->size()));
    auto read = source->read_at(0, bytes.data(), bytes.size());
    if (!read.ok())
        return read.error();
    return bytes;
}

// One column after the writer has decided its geometry.
struct Column {
    uint32_t tag = 0;
    uint64_t width = 0; // bytes per row: the value width, or the 4-byte slot holding an HNID
    bool value_in_heap = false;
    uint64_t ib_data = 0;   // [MS-PST] 2.3.4.2 ibData: offset of this column inside a row
    uint64_t i_bit = 0;     // [MS-PST] 2.3.4.2 iBit: index of this column's Cell Existence Bit
    size_t input_index = 0; // which entry of TcRow::values holds this column's value
    bool placed = false;    // true for the two columns whose ibData [MS-PST] 2.3.4.4.1 fixes
};

// [MS-PST] 2.3.4.4.2: only single-valued fixed types up to 8 bytes live in the row.
// All other types, including every multi-valued type, use a 4-byte HNID slot.
bool value_lives_in_the_heap(uint32_t tag) {
    return !ltp::prop_type_is_tc_inline(ltp::tc_prop_type_of_tag(tag));
}

uint64_t column_width(uint32_t tag) {
    if (value_lives_in_the_heap(tag)) {
        return kTcHnidSlotBytes; // [MS-PST] 2.3.4.2: cbData is the size of an HNID for variable
                                 // data
    }
    return ltp::prop_type_info(ltp::tc_prop_type_of_tag(tag)).fixed_size;
}

} // namespace

Result<TcNode> build_table_from(const std::vector<TcColumnSpec>& column_specs,
                                const TcRowSource& rows, LocalNids& local_nids) {
    const uint64_t row_count = rows.count();
    // Engineering workspace limits, not PST format limits. Includes the output heap/matrix,
    // index arrays and their construction copies; callers do not retain input row payloads.
    constexpr uint64_t kWorkspaceBytes = 128ull * 1024 * 1024;
    constexpr uint64_t kMaxRows = 1000000;
    if (row_count > kMaxRows) {
        return make_error(ErrorKind::kUnsupported, "writer.tc.row_budget", row_count, kMaxRows,
                          "table exceeds the current metadata workspace budget");
    }
    // [MS-PST] 2.3.4.1: cCols is one byte and a table context has at least one column.
    if (column_specs.empty() || column_specs.size() > ltp::kTcMaxColumns) {
        return make_error(
            ErrorKind::kBadField, "TCINFO.cCols", 0, column_specs.size(),
            "cCols is a byte and a table context has at least one column ([MS-PST] 2.3.4.1)");
    }

    // [MS-PST] 2.3.4.1: rgTCOLDESC MUST be sorted by tag, so one tag cannot describe two columns.
    std::vector<size_t> order(column_specs.size());
    for (size_t index = 0; index < order.size(); ++index) {
        order[index] = index;
    }
    std::sort(order.begin(), order.end(), [&](size_t left, size_t right) {
        return column_specs[left].tag < column_specs[right].tag;
    });
    for (size_t index = 1; index < order.size(); ++index) {
        if (column_specs[order[index]].tag == column_specs[order[index - 1]].tag) {
            return make_error(ErrorKind::kBadField, "TCOLDESC.tag", column_specs[order[index]].tag,
                              index, "rgTCOLDESC is sorted by tag, so one tag cannot appear twice");
        }
    }

    std::vector<Column> columns;
    for (size_t index = 0; index < order.size(); ++index) {
        Column column;
        column.tag = column_specs[order[index]].tag;
        column.input_index = order[index];
        column.value_in_heap = value_lives_in_the_heap(column.tag);
        column.width = column_width(column.tag);
        columns.push_back(column);
    }

    // [MS-PST] 2.3.4.4.1 rules 1 to 4 fix PidTagLtpRowId at iBit 0 / ibData 0 and PidTagLtpRowVer
    // at iBit 1 / ibData 4, and rules 5 and 6 leave every other column free. The writer numbers the
    // other iBits in tag order from 2 and packs the other ibData values in tag order inside their
    // size group.
    uint64_t next_bit = 2;
    for (Column& column : columns) {
        const uint32_t prop_id = ltp::tc_prop_id_of_tag(column.tag);
        if (prop_id != ltp::kTcTagRowId && prop_id != ltp::kTcTagRowVer) {
            column.i_bit = next_bit++;
            continue;
        }
        // The two mandatory columns sit 4 bytes apart, so each one has to be a 4-byte column.
        if (column.width != 4) {
            return make_error(ErrorKind::kBadField, "TCOLDESC.cbData", column.tag, column.width,
                              "PidTagLtpRowId sits at ibData 0 and PidTagLtpRowVer at ibData 4, so "
                              "each is 4 bytes wide");
        }
        if (prop_id == ltp::kTcTagRowId) {
            column.i_bit = ltp::kTcRowIdIBit;
            column.ib_data = ltp::kTcRowIdIbData;
            column.placed = true;
        } else {
            column.i_bit = ltp::kTcRowVerIBit;
            column.ib_data = ltp::kTcRowVerIbData;
            column.placed = true;
        }
    }

    // [MS-PST] 2.3.4.4.1: rgCEB is CEIL(cCols / 8) bytes, so iBit has to stay inside it.
    const uint64_t ceb_bytes = (columns.size() + 7) / 8;
    for (const Column& column : columns) {
        if (column.i_bit >= ceb_bytes * 8) {
            return make_error(ErrorKind::kBadField, "TCOLDESC.iBit", column.tag, column.i_bit,
                              "the Cell Existence Block of this TC has " +
                                  std::to_string(ceb_bytes * 8) + " bits");
        }
    }

    // [MS-PST] 2.3.4.4.1: a row is the 8- and 4-byte group, then the 2-byte group, then the 1-byte
    // group, then the Cell Existence Block. ibData 0 and 4 belong to the two mandatory columns, so
    // the other 4-byte slots start at 8.
    uint64_t at = 8;
    for (Column& column : columns) {
        if (column.width != 8 && column.width != 4) {
            continue;
        }
        if (column.placed) {
            continue; // one of the two mandatory columns already has its ibData
        }
        column.ib_data = at;
        at += column.width;
    }
    const uint16_t end4 = static_cast<uint16_t>(at); // [MS-PST] 2.3.4.1 rgib[TCI_4b]
    for (Column& column : columns) {
        if (column.width != 2) {
            continue;
        }
        column.ib_data = at;
        at += 2;
    }
    const uint16_t end2 = static_cast<uint16_t>(at); // [MS-PST] 2.3.4.1 rgib[TCI_2b]
    for (Column& column : columns) {
        if (column.width != 1) {
            continue;
        }
        column.ib_data = at;
        at += 1;
    }
    const uint16_t end1 = static_cast<uint16_t>(at); // [MS-PST] 2.3.4.1 rgib[TCI_1b]
    const uint64_t row_size =
        static_cast<uint64_t>(end1) + ceb_bytes; // rgib[TCI_bm] is the row size
    if (row_size > 0xFFFFu) {
        return make_error(ErrorKind::kBadField, "TCINFO.rgib", row_size, columns.size(),
                          "a row is measured in the 16-bit rgib offsets ([MS-PST] 2.3.4.1)");
    }

    std::vector<uint32_t> keys;
    keys.reserve(static_cast<size_t>(row_count));
    auto read_row = [&](uint64_t index) -> Result<TcRow> {
        auto result = rows.read(index);
        if (!result.ok())
            return result.error();
        const TcRow& row = result.value();
        if (row.values.size() != columns.size()) {
            return make_error(ErrorKind::kBadField, "RowMatrix.row", row.row_id, row.values.size(),
                              "a row needs one value per column, this TC has " +
                                  std::to_string(columns.size()));
        }
        if (!row.sources.empty() && row.sources.size() != columns.size())
            return make_error(ErrorKind::kBadField, "TCCell.sources", row.row_id,
                              row.sources.size());
        for (size_t input = 0; input < row.values.size(); ++input)
            if (cell_source(row, input) && !row.values[input].empty())
                return make_error(ErrorKind::kBadField, "TCCell.source", row.row_id, input,
                                  "cell has both resident and streamed bytes");
        if (!row.present_empty.empty() && row.present_empty.size() != columns.size()) {
            return make_error(ErrorKind::kBadField, "RowMatrix.present_empty", row.row_id,
                              row.present_empty.size(),
                              "presence flags must match the input columns");
        }
        if (index < keys.size() && row.row_id != keys[static_cast<size_t>(index)]) {
            return make_error(ErrorKind::kBadField, "writer.tc.changed_row", index, row.row_id,
                              "row source changed while constructing its table");
        }
        return result;
    };

    // [MS-PST] 2.3.4.3.1: the RowIndex is a BTH keyed by dwRowID, so one row id cannot name two
    // rows. Duplicate detection follows the measurement pass, sorting only compact keys and
    // indices.

    // [MS-PST] 2.3.4.4.2: a value the row reaches through an HNID is 3580 bytes or less in the
    // heap; past that it is a subnode of the TC node and the rgdwData slot holds that subnode's
    // local NID
    // ([MS-PST] 2.6.2.4.2, docs/reference/ms-pst.txt:6164-6172). This pass only measures, because
    // the heap values are numbered after the Row Matrix is placed.
    const uint64_t cells = row_count * columns.size();
    uint64_t workspace = row_count * (row_size * 2 + columns.size() * 6 + 32);
    if (workspace > kWorkspaceBytes) {
        return make_error(ErrorKind::kUnsupported, "writer.tc.workspace", workspace,
                          kWorkspaceBytes, "table metadata exceeds the current workspace budget");
    }
    std::vector<uint32_t> value_hid(cells, 0);
    std::vector<char> value_in_subnode(cells, 0);
    uint64_t heap_value_bytes = 0;
    uint64_t heap_values = 0;
    uint64_t subnode_values = 0;
    for (size_t row_index = 0; row_index < row_count; ++row_index) {
        auto loaded = read_row(row_index);
        if (!loaded.ok())
            return loaded.error();
        const TcRow& row = loaded.value();
        keys.push_back(row.row_id);
        for (size_t column_index = 0; column_index < columns.size(); ++column_index) {
            if (!columns[column_index].value_in_heap) {
                continue;
            }
            const size_t input = columns[column_index].input_index;
            const auto size = cell_size(row, input);
            if (size == 0) {
                continue; // [MS-PST] 2.3.4.4.3: a cell that does not exist has no value
            }
            const auto source = cell_source(row, input);
            if (source && size > kTcHeapValueMaxBytes) {
                value_in_subnode[row_index * columns.size() + column_index] = 1;
                ++subnode_values;
                continue;
            }
            if (size > (kWorkspaceBytes - workspace) / 4) {
                return make_error(ErrorKind::kUnsupported, "writer.tc.workspace", row_index, size,
                                  "table values exceed the current workspace budget");
            }
            workspace += size * 4;
            const uint64_t cell = row_index * columns.size() + column_index;
            if (size > kTcHeapValueMaxBytes) {
                value_in_subnode[cell] = 1;
                ++subnode_values;
                continue;
            }
            heap_value_bytes += size;
            ++heap_values;
        }
    }

    std::vector<uint32_t> by_row_id(static_cast<size_t>(row_count));
    for (uint32_t index = 0; index < row_count; ++index)
        by_row_id[index] = index;
    std::sort(by_row_id.begin(), by_row_id.end(),
              [&](uint32_t left, uint32_t right) { return keys[left] < keys[right]; });
    for (size_t index = 1; index < by_row_id.size(); ++index) {
        if (keys[by_row_id[index - 1]] == keys[by_row_id[index]]) {
            return make_error(
                ErrorKind::kBadField, "TCROWID.dwRowID", keys[by_row_id[index]], index,
                "the RowIndex is keyed by dwRowID, so one row id cannot name two rows");
        }
    }

    // [MS-PST] 2.3.4.4: "In practice, the Row Matrix is stored in a subnode because of its typical
    // size, but in rare cases, a TC can fit into a single data block if it is small enough." The
    // writer keeps the matrix in the heap only while the whole heap node, rows included, stays
    // inside the one block it writes with room to spare ([MS-PST] 2.3.1.2 FILL_LEVEL_EMPTY), which
    // is also what the sample does: the 116-byte Attachment Table and 630-byte Recipient Table
    // matrices are heap allocations at HNID 0x80 and every Contents Table matrix is a subnode named
    // 0x3F
    // (DEVELOPMENT.md).
    const uint64_t header_bytes = ltp::kTcInfoSize + columns.size() * ltp::kTcColDescSize;
    const uint64_t matrix_bytes = row_count * row_size;
    const uint64_t heap_bytes = kHnFirstAllocationOffset + header_bytes + ltp::kBthHeaderSize +
                                row_count * ltp::kTcRowIdSize + matrix_bytes + heap_value_bytes;
    const bool matrix_in_subnode = row_count != 0 && (heap_bytes > kHeapPackingTargetBytes ||
                                                      matrix_bytes > kTcHeapValueMaxBytes);

    TcNode node;
    node.row_size =
        static_cast<uint16_t>(row_size); // [MS-PST] 2.3.4.1: rgib[TCI_bm] is the row size
    uint32_t matrix_nid = 0;
    if (matrix_in_subnode) {
        Result<uint32_t> nid = local_nids.take(ltp::kNidTypeLtp);
        if (!nid.ok()) {
            return nid.error();
        }
        matrix_nid = nid.value();
        node.subnodes.push_back(LocalSubnode{matrix_nid, std::vector<uint8_t>()});
    }

    // The subnode NIDs are taken before the Row Matrix is built so the matrix can carry them; the
    // sample gives the matrix the first local index and the raw value subnodes later ones
    // (DEVELOPMENT.md).
    for (size_t row_index = 0; row_index < row_count; ++row_index) {
        auto loaded = read_row(row_index);
        if (!loaded.ok())
            return loaded.error();
        const TcRow& row = loaded.value();
        for (size_t column_index = 0; column_index < columns.size(); ++column_index) {
            const uint64_t cell = row_index * columns.size() + column_index;
            if (!value_in_subnode[cell]) {
                continue;
            }
            Result<uint32_t> nid = local_nids.take(ltp::kNidTypeLtp);
            if (!nid.ok()) {
                return nid.error();
            }
            value_hid[cell] = nid.value();
            node.subnodes.push_back(
                LocalSubnode{nid.value(), row.values[columns[column_index].input_index],
                             cell_source(row, columns[column_index].input_index)});
        }
    }

    // Allocation 1: TCINFO followed by rgTCOLDESC ([MS-PST] 2.3.4.1), which hidUserRoot names. The
    // two HNIDs it names point at allocations that do not exist yet, so they are patched in at the
    // end.
    std::vector<uint8_t> header(header_bytes, 0);
    header[ltp::kTcInfoTypeOffset] = ltp::kClientSigTc;
    header[ltp::kTcInfoColsOffset] = static_cast<uint8_t>(columns.size());
    put_u16(header, ltp::kTcInfoRgibOffset + ltp::kTcRgib4b * 2, end4);
    put_u16(header, ltp::kTcInfoRgibOffset + ltp::kTcRgib2b * 2, end2);
    put_u16(header, ltp::kTcInfoRgibOffset + ltp::kTcRgib1b * 2, end1);
    put_u16(header, ltp::kTcInfoRgibOffset + ltp::kTcRgibBm * 2, static_cast<uint16_t>(row_size));
    for (size_t index = 0; index < columns.size(); ++index) {
        const uint64_t at_desc = ltp::kTcInfoSize + index * ltp::kTcColDescSize;
        put_u32(header, at_desc + ltp::kTcColTagOffset, columns[index].tag);
        put_u16(header, at_desc + ltp::kTcColIbDataOffset,
                static_cast<uint16_t>(columns[index].ib_data));
        header[at_desc + ltp::kTcColCbDataOffset] = static_cast<uint8_t>(columns[index].width);
        header[at_desc + ltp::kTcColIBitOffset] = static_cast<uint8_t>(columns[index].i_bit);
    }
    Result<uint32_t> appended = node.heap.append(std::move(header));
    if (!appended.ok()) {
        return appended.error();
    }

    // Allocation 2: the RowIndex BTHHEADER, emitted whether or not the table has rows.
    // [MS-PST] 2.3.4.3.1 gives the Unicode RowIndex cbKey 4 and cbEnt 4, and a table this small
    // needs no index level. [MS-PST] 2.3.2.1 says hidRoot is 0 when the BTH is empty, which is what
    // Outlook writes for a table with no rows (see the probe files named above).
    std::vector<uint8_t> bth_header(ltp::kBthHeaderSize, 0);
    bth_header[ltp::kBthTypeOffset] = ltp::kBthType;
    bth_header[ltp::kBthCbKeyOffset] = ltp::kTcRowIdCbKey;
    bth_header[ltp::kBthCbEntOffset] = ltp::kTcRowIdCbEnt;
    bth_header[ltp::kBthIdxLevelsOffset] = 0;
    appended = node.heap.append(std::move(bth_header));
    if (!appended.ok()) {
        return appended.error();
    }

    uint32_t row_ids_root = 0;
    uint8_t row_index_levels = 0;
    uint64_t matrix_allocation = 0;
    if (row_count != 0) {
        // Allocation 3: the TCROWID array, sorted by dwRowID because the RowIndex is a BTH.
        // dwRowIndex is the 0-based position of the row in the Row Matrix, which is the order the
        // rows were given in. [MS-PST] 2.6.2.2.2 limits each BTH index/leaf allocation to 3580
        // bytes. TC leaves and indices both have 4-byte keys and 4-byte values (2.3.4.3.1,
        // 2.3.2.2); an index key is the first key in its child. libpff "b5 table header"
        // independently documents these intermediate references.
        constexpr size_t kEntries = 3580 / ltp::kTcRowIdSize;
        std::vector<std::pair<uint32_t, uint32_t>> level;
        for (size_t begin = 0; begin < by_row_id.size(); begin += kEntries) {
            const size_t count = std::min(kEntries, by_row_id.size() - begin);
            std::vector<uint8_t> records(count * ltp::kTcRowIdSize, 0);
            for (size_t index = 0; index < count; ++index) {
                const uint32_t original = by_row_id[begin + index];
                put_u32(records, index * ltp::kTcRowIdSize, keys[original]);
                put_u32(records, index * ltp::kTcRowIdSize + ltp::kTcRowIdIndexOffset, original);
            }
            appended = node.heap.append(std::move(records));
            if (!appended.ok())
                return appended.error();
            level.emplace_back(keys[by_row_id[begin]], appended.value());
        }
        while (level.size() > 1) {
            std::vector<std::pair<uint32_t, uint32_t>> parent;
            for (size_t begin = 0; begin < level.size(); begin += kEntries) {
                const size_t count = std::min(kEntries, level.size() - begin);
                std::vector<uint8_t> records(count * ltp::kTcRowIdSize, 0);
                for (size_t index = 0; index < count; ++index) {
                    put_u32(records, index * ltp::kTcRowIdSize, level[begin + index].first);
                    put_u32(records, index * ltp::kTcRowIdSize + ltp::kTcRowIdCbKey,
                            level[begin + index].second);
                }
                appended = node.heap.append(std::move(records));
                if (!appended.ok())
                    return appended.error();
                parent.emplace_back(level[begin].first, appended.value());
            }
            level = std::move(parent);
            ++row_index_levels;
        }
        row_ids_root = level[0].second;

        // The Row Matrix is allocation 4 in the heap case and the first subnode in the subnode
        // case, and holds the same bytes either way. In the heap case it is appended as zeros first
        // because its cells carry the HNIDs of the values that follow it, and a HID only exists
        // once its allocation has been placed ([MS-PST] 2.3.1.1); the finished rows are then
        // written back over that same allocation, whose size does not change, so no HID moves.
        if (!matrix_in_subnode) {
            appended = node.heap.append(std::vector<uint8_t>(matrix_bytes, 0));
            if (!appended.ok()) {
                return appended.error();
            }
            matrix_allocation = node.heap.allocation_count();
        }
    }

    // The values that stayed in the heap follow the Row Matrix, in row order ([MS-PST] 2.3.4.4.2).
    std::vector<std::pair<uint64_t, uint64_t>>
        heap_cells; // cell -> the allocation holding its value
    for (size_t row_index = 0; row_index < row_count; ++row_index) {
        auto loaded = read_row(row_index);
        if (!loaded.ok())
            return loaded.error();
        const TcRow& row = loaded.value();
        for (size_t column_index = 0; column_index < columns.size(); ++column_index) {
            const uint64_t cell = row_index * columns.size() + column_index;
            if (!columns[column_index].value_in_heap || value_in_subnode[cell]) {
                continue;
            }
            auto obtained =
                small_cell(row, columns[column_index].input_index, kTcHeapValueMaxBytes);
            if (!obtained.ok())
                return obtained.error();
            const auto& value = obtained.value();
            if (value.empty()) {
                continue;
            }
            appended = node.heap.append(value);
            if (!appended.ok()) {
                return appended.error();
            }
            heap_cells.emplace_back(cell, node.heap.allocation_count());
        }
    }
    if (heap_cells.size() != heap_values) {
        return make_error(ErrorKind::kBadField, "writer.build_table", heap_cells.size(),
                          heap_values,
                          "the writer placed a different number of heap values than it measured");
    }
    for (const std::pair<uint64_t, uint64_t>& placed : heap_cells) {
        value_hid[placed.first] = node.heap.hid(placed.second);
    }

    if (row_count != 0) {
        // Every row is row_size bytes and space is reserved for a column whether or not its Cell
        // Existence Bit is set ([MS-PST] 2.3.4.4 / 2.3.4.4.1).
        std::vector<uint8_t> matrix(matrix_bytes, 0);
        for (size_t row_index = 0; row_index < row_count; ++row_index) {
            auto loaded = read_row(row_index);
            if (!loaded.ok())
                return loaded.error();
            const TcRow& row = loaded.value();
            const uint64_t row_at = row_index * row_size;
            for (size_t column_index = 0; column_index < columns.size(); ++column_index) {
                const Column& column = columns[column_index];
                const std::vector<uint8_t>& value = row.values[column.input_index];
                const auto source = cell_source(row, column.input_index);
                const bool present_empty =
                    !row.present_empty.empty() && row.present_empty[column.input_index];
                if (value.empty() && !source && !present_empty) {
                    continue; // the Cell Existence Bit stays clear
                }
                if (column.value_in_heap) {
                    put_u32(matrix, row_at + column.ib_data,
                            value_hid[row_index * columns.size() + column_index]);
                } else {
                    auto obtained = small_cell(row, column.input_index, column.width);
                    if (!obtained.ok())
                        return obtained.error();
                    const auto& fixed = obtained.value();
                    if (fixed.size() != column.width) {
                        return make_error(
                            ErrorKind::kBadField, "TCCell.value", column.tag, fixed.size(),
                            "an inline column value is exactly cbData = " +
                                std::to_string(column.width) + " bytes ([MS-PST] 2.3.4.2)");
                    }
                    for (size_t byte = 0; byte < fixed.size(); ++byte) {
                        matrix[static_cast<size_t>(row_at + column.ib_data) + byte] = fixed[byte];
                    }
                }
                // [MS-PST] 2.3.4.4.1: iBit 0 is the MSB of rgCEB[0], then down to the LSB of that
                // byte.
                const uint64_t ceb_at = row_at + end1 + column.i_bit / 8;
                matrix[static_cast<size_t>(ceb_at)] |=
                    static_cast<uint8_t>(1u << (7u - (column.i_bit % 8u)));
            }
        }
        if (matrix_in_subnode) {
            node.subnodes[0].bytes = std::move(matrix);
        } else {
            Status written = node.heap.patch(matrix_allocation, 0, matrix);
            if (!written.ok()) {
                return written.error();
            }
        }
    }

    // [MS-PST] 2.3.4.1 says hnidRows is 0 when the TC has no rows and hidIndex MUST be zero for a
    // creator of a new PST; it never says hidRowIndex may be 0. Outlook never writes 0 there: all
    // 22 table contexts of the Outlook blank PST and all 207 of the sample OST name a RowIndex
    // BTHHEADER, and every empty one points at a BTHHEADER whose hidRoot is 0
    // (research/m4-oracle-tc-probe.txt, research/m4-tc-probe-sample.txt). The writer therefore
    // always names a RowIndex and lets the BTH itself say that it is empty. A hnidRows that names a
    // subnode is an HNID whose hidType is that subnode's nidType ([MS-PST] 2.3.3.2 / 2.3.4.4).
    node.hnid_rows =
        row_count == 0 ? 0 : (matrix_in_subnode ? matrix_nid : node.heap.hid(matrix_allocation));
    Status patched = node.heap.patch(1, ltp::kTcInfoRowIndexOffset, node.heap.hid(2));
    if (!patched.ok()) {
        return patched.error();
    }
    patched = node.heap.patch(1, ltp::kTcInfoRowsOffset, node.hnid_rows);
    if (!patched.ok()) {
        return patched.error();
    }
    if (row_count != 0) {
        patched = node.heap.patch(2, ltp::kBthHidRootOffset, row_ids_root);
        if (!patched.ok()) {
            return patched.error();
        }
        patched =
            node.heap.patch(2, ltp::kBthIdxLevelsOffset, std::vector<uint8_t>{row_index_levels});
        if (!patched.ok())
            return patched.error();
    }
    return node;
}

Result<TcNode> build_table(const std::vector<TcColumnSpec>& columns, const std::vector<TcRow>& rows,
                           LocalNids& local_nids) {
    class VectorRows final : public TcRowSource {
      public:
        explicit VectorRows(const std::vector<TcRow>& rows) : rows_(rows) {}
        uint64_t count() const override { return rows_.size(); }
        Result<TcRow> read(uint64_t index) const override {
            return rows_.at(static_cast<size_t>(index));
        }

      private:
        const std::vector<TcRow>& rows_;
    } source(rows);
    return build_table_from(columns, source, local_nids);
}

// The table a caller expects to fit one heap node. A table that needed a subnode is refused here
// instead of having that subnode dropped on the floor.
Result<HeapImage> build_tc(const std::vector<TcColumnSpec>& columns,
                           const std::vector<TcRow>& rows) {
    LocalNids local_nids;
    Result<TcNode> node = build_table(columns, rows, local_nids);
    if (!node.ok()) {
        return node.error();
    }
    if (!node.value().subnodes.empty()) {
        return make_error(ErrorKind::kBadField, "writer.build_tc", node.value().subnodes.size(), 0,
                          "this table needs a subnode, which only build_table emits");
    }
    return std::move(node.value().heap);
}

} // namespace ost2pst::writer
