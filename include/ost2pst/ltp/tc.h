#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

#include "ost2pst/ltp/bth.h"
#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ltp {

// [MS-PST] 2.3.4.1 TCINFO: the TC header, reached through the containing HN's hidUserRoot and followed
// in the same allocation by cCols column descriptors. rgib holds the ending offset of each data group,
// so rgib[TCI_bm] is the size of one row of the Row Matrix.
struct TcInfo {
    uint8_t b_type = 0;
    uint8_t c_cols = 0;
    uint16_t rgib[kTcRgibEntries] = {}; // [MS-PST] 2.3.4.1 TCI_4b TCI_2b TCI_1b TCI_bm
    uint32_t hid_row_index = 0;
    uint32_t hnid_rows = 0; // 0 when the TC has no rows ([MS-PST] 2.3.4.1)
    uint32_t hid_index = 0; // deprecated ([MS-PST] 2.3.4.1)
};

util::Result<TcInfo> decode_tc_info(util::ByteView view);

// [MS-PST] 2.3.4.2 TCOLDESC: one column. cbData is the width of the column in bytes per row, except for
// variable-sized data, where it is the size of the HNID that stands in for the value ([MS-PST] 2.3.4.4.2).
struct TcColumn {
    uint32_t tag = 0;
    uint16_t ib_data = 0;
    uint8_t cb_data = 0;
    uint8_t i_bit = 0;
};

util::Result<TcColumn> decode_tc_col_desc(util::ByteView view);

// A TC header that has been checked against the spec: the descriptors are sorted by tag, each one fits
// inside a row, and the group offsets are in the order the Row Matrix lays its data out in.
struct TcTable {
    TcInfo info;
    std::vector<TcColumn> columns;
    uint64_t header_offset = 0; // where TCINFO itself was found
};

// Row geometry ([MS-PST] 2.3.4.4 / 2.3.4.4.1).
constexpr uint64_t tc_row_size(const TcInfo &info) { return info.rgib[kTcRgibBm]; }
constexpr uint64_t tc_ceb_bytes(const TcInfo &info) {
    return (static_cast<uint64_t>(info.c_cols) + 7) / 8; // [MS-PST] 2.3.4.4.1 rgCEB is CEIL(cCols / 8) bytes
}
// [MS-PST] 2.3.4.4.1: iBit 0 is the MSB of rgCEB[0], then down to the LSB, then the next byte.
inline bool tc_ceb_bit(util::ByteView ceb, uint64_t i_bit) {
    return ceb.in_range(i_bit / 8, 1) &&
           (ceb.data()[i_bit / 8] & (1u << (7u - (i_bit % 8u)))) != 0;
}
// [MS-PST] 2.3.4.4: rows never span a block, so a block holds Floor((cb - trailer) / row size) of them.
constexpr uint64_t tc_rows_per_block(uint64_t cb, uint64_t row_size, uint64_t trailer_size) {
    if (row_size == 0 || cb <= trailer_size) {
        return 0;
    }
    return (cb - trailer_size) / row_size;
}

// Reads a table context: bClientSig says it is one, hidUserRoot names the TCINFO allocation, and the
// cCols descriptors follow it. A descriptor that does not fit a row, a group offset out of order, or a
// descriptor array out of tag order is an error, because the Row Matrix cannot be read without them.
util::Result<TcTable> read_tc(const HnHeader &hn_header, HeapSource &source);

// [MS-PST] 2.3.4.3.1 TCROWID: the RowIndex BTH record, cbKey 4 and cbEnt 4 for a Unicode PST.
struct TcRowId {
    uint32_t row_id = 0;
    uint32_t row_index = 0;
    uint64_t offset = 0;
};

util::Result<TcRowId> decode_tc_row_id(util::ByteView record);

using TcRowCallback = std::function<bool(const TcRowId &row)>;

// Walks the RowIndex BTH and reports (dwRowID, dwRowIndex) pairs in row-id order. The Row Matrix itself
// is unsorted ([MS-PST] 2.3.4.4), so this is the only ordered view of a TC's rows.
// The profile decides the HID widths the RowIndex walk needs ([MS-PST] 2.3.1.1).
util::Status walk_tc_row_index(const TcTable &table, ndb::FileProfile profile, HeapSource &source,
                               const TcRowCallback &callback, BthStats &stats,
                               ndb::FailureLog &failures);

// One cell of one row. [MS-PST] 2.3.4.4.3 is explicit that the CEB is checked first and that a cell of
// a column that does not exist holds random bytes, so existence is part of the answer, not a hint.
struct TcCell {
    bool exists = false;
    util::ByteView value; // empty when the column does not exist in this row
};

util::Result<TcCell> tc_column_cell(const TcTable &table, const TcColumn &column, util::ByteView row);

} // namespace ost2pst::ltp
