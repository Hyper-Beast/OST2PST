#include "ost2pst/ltp/tc.h"

#include <string>

#include "internal/take.h"

namespace ost2pst::ltp {

using util::ByteView;
using util::DataError;
using util::ErrorKind;
using util::make_error;
using util::Result;
using util::Status;

Result<TcInfo> decode_tc_info(ByteView view) {
    if (!view.in_range(0, static_cast<size_t>(kTcInfoSize))) {
        return make_error(ErrorKind::kTruncated, "TCINFO", view.base(), view.size(),
                          "TCINFO is 22 bytes before rgTCOLDESC starts");
    }
    TcInfo parsed;
    DataError failure;
    if (!take(view.u8(kTcInfoTypeOffset), parsed.b_type, "TCINFO.bType", failure)) {
        return failure;
    }
    if (!take(view.u8(kTcInfoColsOffset), parsed.c_cols, "TCINFO.cCols", failure)) {
        return failure;
    }
    for (uint64_t i = 0; i < kTcRgibEntries; ++i) {
        if (!take(view.u16(kTcInfoRgibOffset + i * 2), parsed.rgib[i], "TCINFO.rgib", failure)) {
            return failure;
        }
    }
    if (!take(view.u32(kTcInfoRowIndexOffset), parsed.hid_row_index, "TCINFO.hidRowIndex", failure)) {
        return failure;
    }
    if (!take(view.u32(kTcInfoRowsOffset), parsed.hnid_rows, "TCINFO.hnidRows", failure)) {
        return failure;
    }
    if (!take(view.u32(kTcInfoIndexOffset), parsed.hid_index, "TCINFO.hidIndex", failure)) {
        return failure;
    }

    // [MS-PST] 2.3.4.1: bType MUST be bTypeTC, and 2.3.1.2 fixes that value at 0x7C.
    if (parsed.b_type != kClientSigTc) {
        return make_error(ErrorKind::kBadSignature, "TCINFO.bType", view.base(), parsed.b_type,
                          std::string("a TC header carries bTypeTC (") + client_sig_name(kClientSigTc) +
                              ")");
    }
    if (parsed.c_cols == 0) {
        return make_error(ErrorKind::kBadField, "TCINFO.cCols", view.base() + kTcInfoColsOffset, 0,
                          "a table context has at least one column");
    }
    return parsed;
}

Result<TcColumn> decode_tc_col_desc(ByteView view) {
    if (!view.in_range(0, static_cast<size_t>(kTcColDescSize))) {
        return make_error(ErrorKind::kTruncated, "TCOLDESC", view.base(), view.size(),
                          "TCOLDESC is tag ibData cbData iBit");
    }
    TcColumn parsed;
    DataError failure;
    if (!take(view.u32(kTcColTagOffset), parsed.tag, "TCOLDESC.tag", failure)) {
        return failure;
    }
    if (!take(view.u16(kTcColIbDataOffset), parsed.ib_data, "TCOLDESC.ibData", failure)) {
        return failure;
    }
    if (!take(view.u8(kTcColCbDataOffset), parsed.cb_data, "TCOLDESC.cbData", failure)) {
        return failure;
    }
    if (!take(view.u8(kTcColIBitOffset), parsed.i_bit, "TCOLDESC.iBit", failure)) {
        return failure;
    }
    return parsed;
}

// [MS-PST] 2.3.4.4.1: the Row Matrix groups columns by data size, so a column's width decides which
// group its ibData has to fall in. 8- and 4-byte values come first, then 2-byte, then 1-byte; a
// variable-sized column occupies a 4-byte slot holding an HNID ([MS-PST] 2.3.4.4.2).
static bool column_fits_group(const TcInfo &info, const TcColumn &column) {
    const uint64_t ib = column.ib_data;
    const uint64_t width = column.cb_data;
    switch (column.cb_data) {
    case 8:
    case 4:
        return ib + width <= info.rgib[kTcRgib4b]; // the 8- and 4-byte group starts at offset 0
    case 2:
        return ib >= info.rgib[kTcRgib4b] && ib + width <= info.rgib[kTcRgib2b];
    case 1:
        return ib >= info.rgib[kTcRgib2b] && ib + width <= info.rgib[kTcRgib1b];
    default:
        return false;
    }
}

Result<TcTable> read_tc(const HnHeader &hn_header, HeapSource &source) {
    // [MS-PST] 2.3.4: a TC is announced at the HN level by bClientSig == bTypeTC.
    if (hn_header.b_client_sig != kClientSigTc) {
        return make_error(ErrorKind::kBadField, "HNHDR.bClientSig", 0, hn_header.b_client_sig,
                          std::string("a table context carries bTypeTC, this heap node carries ") +
                              client_sig_name(hn_header.b_client_sig));
    }

    // [MS-PST] 2.3.4.1: TCINFO is reached through hidUserRoot.
    Result<ByteView> root = source.heap(hn_header.hid_user_root);
    if (!root.ok()) {
        return root.error();
    }
    Result<TcInfo> info = decode_tc_info(root.value());
    if (!info.ok()) {
        return info.error();
    }
    TcTable table;
    table.info = info.take();
    table.header_offset = root.value().base();

    // [MS-PST] 2.3.4.1: rgTCOLDESC follows TCINFO in the same allocation.
    const uint64_t columns_cb = static_cast<uint64_t>(table.info.c_cols) * kTcColDescSize;
    Result<ByteView> descriptors = root.value().sub(kTcInfoSize, static_cast<size_t>(columns_cb));
    if (!descriptors.ok()) {
        return make_error(ErrorKind::kTruncated, "TCINFO.rgTCOLDESC", root.value().base() + kTcInfoSize,
                          columns_cb,
                          std::to_string(table.info.c_cols) + " columns need " +
                              std::to_string(columns_cb) + " bytes and the allocation has less");
    }

    // [MS-PST] 2.3.4.1: the group offsets are ending offsets, so they only make sense in increasing
    // order, and rgib[TCI_bm] is the row size the whole Row Matrix is measured in.
    for (uint64_t i = 1; i < kTcRgibEntries; ++i) {
        if (table.info.rgib[i] < table.info.rgib[i - 1]) {
            return make_error(ErrorKind::kBadField, "TCINFO.rgib",
                              table.header_offset + kTcInfoRgibOffset + i * 2, table.info.rgib[i],
                              "rgib holds ending offsets, so rgib[" + std::to_string(i) +
                                  "] cannot be below rgib[" + std::to_string(i - 1) + "]");
        }
    }
    const uint64_t ceb = tc_ceb_bytes(table.info);
    if (table.info.rgib[kTcRgibBm] < table.info.rgib[kTcRgib1b] + ceb) {
        return make_error(ErrorKind::kBadField, "TCINFO.rgib",
                          table.header_offset + kTcInfoRgibOffset + kTcRgibBm * 2,
                          table.info.rgib[kTcRgibBm],
                          "the Cell Existence Block is CEIL(cCols / 8) = " + std::to_string(ceb) +
                              " bytes and does not fit between rgib[TCI_1b] and rgib[TCI_bm]");
    }

    uint32_t previous_tag = 0;
    for (uint64_t i = 0; i < table.info.c_cols; ++i) {
        Result<TcColumn> column =
            decode_tc_col_desc(descriptors.value().sub(i * kTcColDescSize, kTcColDescSize).value());
        if (!column.ok()) {
            return column.error();
        }
        TcColumn parsed = column.take();

        // [MS-PST] 2.3.4.1: the array MUST be sorted by tag.
        if (i != 0 && parsed.tag <= previous_tag) {
            return make_error(ErrorKind::kBadField, "TCOLDESC.tag",
                              descriptors.value().base() + i * kTcColDescSize, parsed.tag,
                              "rgTCOLDESC is sorted by tag and entry " + std::to_string(i) +
                                  " repeats or precedes " + std::to_string(previous_tag));
        }
        previous_tag = parsed.tag;

        if (!column_fits_group(table.info, parsed)) {
            return make_error(ErrorKind::kBadField, "TCOLDESC.ibData",
                              descriptors.value().base() + i * kTcColDescSize + kTcColIbDataOffset,
                              parsed.ib_data,
                              "a column " + std::to_string(parsed.cb_data) + " bytes wide has to sit in "
                              "the matching size group of a " + std::to_string(tc_row_size(table.info)) +
                                  "-byte row");
        }
        if (static_cast<uint64_t>(parsed.i_bit) >= ceb * 8) {
            return make_error(ErrorKind::kBadField, "TCOLDESC.iBit",
                              descriptors.value().base() + i * kTcColDescSize + kTcColIBitOffset,
                              parsed.i_bit, "the Cell Existence Block of this TC has " +
                                                std::to_string(ceb * 8) + " bits");
        }

        // [MS-PST] 2.3.4.4.1 fixes the first two columns of every row. A TCOLDESC tag is a property tag
// ([MS-PST] 1.1), so the comparison is against the property ID half: every one of this sample's 204
// TCs carries 0x67F20003 and 0x67F30003.
      
        if (tc_prop_id_of_tag(parsed.tag) == kTcTagRowId &&
            (parsed.i_bit != kTcRowIdIBit || parsed.ib_data != kTcRowIdIbData)) {
            return make_error(ErrorKind::kBadField, "TCOLDESC.iBit",
                              descriptors.value().base() + i * kTcColDescSize, parsed.tag,
                              "PidTagLtpRowId MUST have iBit 0 and ibData 0");
        }
        if (tc_prop_id_of_tag(parsed.tag) == kTcTagRowVer &&
            (parsed.i_bit != kTcRowVerIBit || parsed.ib_data != kTcRowVerIbData)) {
            return make_error(ErrorKind::kBadField, "TCOLDESC.iBit",
                              descriptors.value().base() + i * kTcColDescSize, parsed.tag,
                              "PidTagLtpRowVer MUST have iBit 1 and ibData 4");
        }
        table.columns.push_back(parsed);
    }
    return table;
}

Result<TcRowId> decode_tc_row_id(ByteView record) {
    if (!record.in_range(0, static_cast<size_t>(kTcRowIdSize))) {
        return make_error(ErrorKind::kTruncated, "TCROWID", record.base(), record.size(),
                          "a Unicode TCROWID is dwRowID then dwRowIndex, 4 bytes each");
    }
    TcRowId parsed;
    DataError failure;
    if (!take(record.u32(kTcRowIdValueOffset), parsed.row_id, "TCROWID.dwRowID", failure)) {
        return failure;
    }
    if (!take(record.u32(kTcRowIdIndexOffset), parsed.row_index, "TCROWID.dwRowIndex", failure)) {
        return failure;
    }
    parsed.offset = record.base();
    return parsed;
}

Status walk_tc_row_index(const TcTable &table, ndb::FileProfile profile, HeapSource &source,
                         const TcRowCallback &callback, BthStats &stats, ndb::FailureLog &failures) {
    if (table.info.hid_row_index == 0) {
        return Status(); // [MS-PST] 2.3.4.1: no RowIndex BTH means the TC has no rows
    }
    Result<ByteView> root = source.heap(table.info.hid_row_index);
    if (!root.ok()) {
        return root.error();
    }
    ++stats.heap_items_read;
    Result<BthHeader> header = decode_bth_header(root.value(), profile);
    if (!header.ok()) {
        return header.error();
    }
    // [MS-PST] 2.3.4.3.1: in a Unicode PST the RowIndex record is cbKey 4 and cbEnt 4.
    if (header.value().cb_key != kTcRowIdCbKey || header.value().cb_ent != kTcRowIdCbEnt) {
        return make_error(ErrorKind::kBadField, "BTHHEADER.cbKey", root.value().base(),
                          header.value().cb_key,
                          "the RowIndex BTH has cbKey 4 and cbEnt 4, this one has cbKey " +
                              std::to_string(header.value().cb_key) + " and cbEnt " +
                              std::to_string(header.value().cb_ent));
    }

    return walk_bth(header.value(), profile, source, [&](const BthLeafRecord &leaf) {
        const ByteView whole(leaf.key.data(), leaf.key.size() + leaf.data.size(), leaf.offset);
        Result<TcRowId> record = decode_tc_row_id(whole);
        if (!record.ok()) {
            failures.add(record.error());
            ++stats.skipped_records;
            return true;
        }
        TcRowId parsed = record.take();
        if (parsed.row_index >= kTcMaxRows) {
            failures.add(parsed.offset, "TCROWID.dwRowIndex", parsed.row_index,
                         "dwRowIndex names a row past the cap this reader will follow");
            ++stats.skipped_records;
            return true;
        }
        return callback(parsed);
    }, stats, failures);
}

Result<TcCell> tc_column_cell(const TcTable &table, const TcColumn &column, ByteView row) {
    const uint64_t row_size = tc_row_size(table.info);
    if (!row.in_range(0, static_cast<size_t>(row_size))) {
        return make_error(ErrorKind::kTruncated, "RowMatrix.row", row.base(), row.size(),
                          "a row of the Row Matrix is rgib[TCI_bm] = " + std::to_string(row_size) +
                              " bytes");
    }
    // [MS-PST] 2.3.4.4.1: the Cell Existence Block is the last thing in a row, from rgib[TCI_1b] to
    // rgib[TCI_bm].
    Result<ByteView> ceb =
        row.sub(table.info.rgib[kTcRgib1b], static_cast<size_t>(tc_ceb_bytes(table.info)));
    if (!ceb.ok()) {
        return ceb.error();
    }

    TcCell cell;
    // [MS-PST] 2.3.4.4.3: the bytes of a column whose CEB bit is clear are random and MUST NOT be read.
    cell.exists = tc_ceb_bit(ceb.value(), column.i_bit);
    if (!cell.exists) {
        return cell;
    }
    Result<ByteView> value = row.sub(column.ib_data, column.cb_data);
    if (!value.ok()) {
        return value.error();
    }
    cell.value = value.value();
    return cell;
}

} // namespace ost2pst::ltp
