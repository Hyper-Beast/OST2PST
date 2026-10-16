// The subset extractor (M5 step 3): one folder's content, reduced to values the writer can emit.
//
// Why this file and why it is here: ltp answers "what shape are these bytes" and must not know what
// a folder or an attachment means, and writer must not know how the source was laid out
// (DEVELOPMENT.md). This layer walks the nodes one folder
// conversion needs through the same seams the production reader uses (open_node, read_pc, read_tc,
// walk_tc_row_index, walk_subnode_entries, find_subnode, read_data_tree) and hands over property
// values, table rows and payload bytes. It is not a second inventory: src/msg/inventory.cpp counts
// a whole mailbox, this reads one folder deeply enough to convert it.
#include "ost2pst/msg/subset.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "ost2pst/ltp/bth.h"
#include "ost2pst/ltp/data_tree.h"
#include "ost2pst/ltp/hn_block.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/name_id.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/ltp/node_open.h"
#include "ost2pst/ltp/node_value.h"
#include "ost2pst/ltp/pc.h"
#include "ost2pst/ltp/prop_type.h"
#include "ost2pst/ltp/tc.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

namespace ost2pst::msg {

namespace {

using util::ByteView;
using util::Result;
using util::Status;

// [MS-PST] 2.4.5.3.1 and 2.4.6.1.1 name the internal NIDs a Message object's tables hang under.
constexpr uint64_t kNidAttachmentTable = 0x671;
constexpr uint64_t kNidRecipientTable = 0x692;
// [MS-PST] 2.4.4.1.1: a Folder object PC MUST carry 0x3001 PidTagDisplayName.
constexpr uint16_t kTagDisplayName = 0x3001;
// 0x1000 PidTagBody and 0x1013 PidTagHtml appear as property tags in [MS-PST]'s own example
// (docs/reference/ms-pst.txt:8087, 8093). 0x1009 is measured in this sample and named by neither
// opened reference, so it is carried as a body candidate, never as a spec-named property.
constexpr uint16_t kTagBody = 0x1000;
constexpr uint16_t kTagHtml = 0x1013;
constexpr uint16_t kTagBodyCandidate = 0x1009;
// [MS-PST] 2.4.6.2.1 (docs/reference/ms-pst.txt:3797-3817) says an Attachment object PC MUST carry
// 0x0E20, 0x3705 and 0x370B and that the content lives in PidTagAttachDataBinary, or in
// PidTagAttachDataObject when the attachment is itself a message, without giving either a tag
// number. 0x3701 is the data object the libpff notes name
// (libpff format notes (see THIRD_PARTY_NOTICES.txt):2491-2509).
constexpr uint16_t kTagAttachData = 0x3701;
constexpr uint16_t kTagAttachSize = 0x0E20;
// [MS-PST] 2.4.5.1.1 (docs/reference/ms-pst.txt:3672-3688): a Message object PC MUST carry each of
// these.
constexpr uint16_t kRequiredMessageTags[] = {0x001A, 0x0E07, 0x0E08, 0x0E17,
                                             0x3007, 0x3008, 0x300B};
// The property type the libpff notes call Embedded Object (0x000d). [MS-PST] 2.3.3.5 defines what
// such a PC value points at (docs/reference/ms-pst.txt:2771-2786) without naming a type id, and
// [MS-OXCDATA] is not in docs/reference/, so the id is cited from the libpff notes.
constexpr uint16_t kPropTypeObject = 0x000D;
// 0x3705 PidTagAttachMethod, and the value 5 that says the attachment is an embedded item: the tag
// is [MS-PST] 2.4.6.2.1's (docs/reference/ms-pst.txt:3797-3817) and the method table is
// libpff format notes (see THIRD_PARTY_NOTICES.txt):2491-2509.
constexpr uint16_t kTagAttachMethod = 0x3705;
constexpr uint32_t kAttachMethodMessage = 5;
constexpr uint64_t kTcHnidSlotBytes =
    4; // [MS-PST] 2.3.4.4.2: the HNID slot a variable-sized column leaves
// [MS-PST] 2.4.3.2 and DEVELOPMENT.md D7: EntryIDs are regenerated against the new Provider
// UID, and 0x67F2 / 0x67F3 are a row's own dwRowID and dwRowVer, which the writer assigns to the
// new row
// ([MS-PST] 2.4.4.4.1). None of the three is content to copy, so the extractor reads them and marks
// them.
constexpr uint16_t kTagEntryId = 0x0FFF;
constexpr uint16_t kTagLtpRowId = 0x67F2;
constexpr uint16_t kTagLtpRowVer = 0x67F3;

std::string hex_u32(uint32_t value) {
    char text[16];
    std::snprintf(text, sizeof(text), "%08X", value);
    return text;
}

std::string hex_u16(uint16_t value) {
    char text[8];
    std::snprintf(text, sizeof(text), "%04X", value);
    return text;
}

std::string hex_u64(uint64_t value) {
    char text[24];
    std::snprintf(text, sizeof(text), "%016llX", static_cast<unsigned long long>(value));
    return text;
}

// Every string value in a Unicode PST is UTF-16LE and terminated ([MS-PST] 2.3.3.6, 2.4.7.4); the
// report prints UTF-8 up to that terminator, because the terminator is not part of the string.
std::string utf16le_to_utf8(ByteView bytes) {
    std::string out;
    for (size_t offset = 0; offset + 1 < bytes.size(); offset += 2) {
        const uint32_t unit =
            bytes.data()[offset] | (static_cast<uint32_t>(bytes.data()[offset + 1]) << 8);
        if (unit == 0) {
            break;
        }
        if (unit < 0x80) {
            out += static_cast<char>(unit);
        } else if (unit < 0x800) {
            out += static_cast<char>(0xC0 | (unit >> 6));
            out += static_cast<char>(0x80 | (unit & 0x3F));
        } else {
            out += static_cast<char>(0xE0 | (unit >> 12));
            out += static_cast<char>(0x80 | ((unit >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (unit & 0x3F));
        }
    }
    return out;
}

uint64_t le_u32(const std::vector<uint8_t>& bytes) {
    return static_cast<uint64_t>(bytes[0]) | (static_cast<uint64_t>(bytes[1]) << 8) |
           (static_cast<uint64_t>(bytes[2]) << 16) | (static_cast<uint64_t>(bytes[3]) << 24);
}

// A per-item note is built from pieces, and the "; " separator only goes between them, never in
// front of the first one.
void append_note(std::string& note, const std::string& text) {
    if (!note.empty()) {
        note += "; ";
    }
    note += text;
}

struct Ctx {
    const ltp::LtpReadReport& census;
    ltp::BlockSource& blocks;
    const SubsetOptions& options;
    SubsetReport& report;
    // Counters for the targeted opens this extractor does, kept apart from the census that produced
    // the NID map so one block is never counted as read twice in the same run.
    ltp::LtpHeapCounters heap;
    ltp::DataTreeCounters trees;
    ltp::SubnodeStats subnodes;
    std::map<std::string, uint64_t> errors;
    ndb::FailureLog failures;
    std::set<uint16_t> named_resolved;
    std::set<uint16_t> named_unresolved;
    util::ByteBudget metadata;

    Ctx(const ltp::LtpReadReport& census, ltp::BlockSource& blocks, const SubsetOptions& options,
        SubsetReport& report)
        : census(census), blocks(blocks), options(options), report(report), failures(20),
          metadata(options.workspace_budget) {}

    util::ByteBudget* workspace() { return options.spool ? &metadata : nullptr; }
    bool reserve(uint64_t bytes, const char* field) {
        if (!workspace())
            return true;
        auto result = metadata.reserve(bytes, field);
        if (!result.ok()) {
            error(result.error());
            return false;
        }
        return true;
    }
    void finish_workspace() {
        if (metadata.error()) {
            report.workspace_error = metadata.error();
            report.capped = true;
            report.unsupported_values = true;
            note(util::format_error(*metadata.error()));
        }
    }

    void note(const std::string& text) {
        if (report.notes.size() < options.max_notes) {
            report.notes.push_back(text);
        }
    }

    void error(const util::DataError& value) {
        ++errors[value.field];
        if (value.kind == util::ErrorKind::kIo && !report.fatal_io)
            report.fatal_io = value;
        if (value.kind == util::ErrorKind::kUnsupported)
            report.unsupported_values = true;
    }

    void count_value(const SubsetValue& value) {
        if (value.readable) {
            ++report.values_read;
        } else if (value.absent) {
            ++report.values_absent;
        } else if (value.object_named) {
            // A PtypObject is content the source has and a value the reader cannot hold as bytes;
            // whether the converter carried the object it names is answered by
            // object_values_carried, not here.
            ++report.object_values;
        } else {
            ++report.unreadable_values;
        }
    }
};

void capture_value(Ctx& ctx, ltp::NodeValueSource& values, uint32_t hnid, SubsetValue& out) {
    auto captured = ctx.options.spool->capture([&](const util::ByteConsumer& consume) -> Status {
        auto read = values.stream(hnid, consume);
        return read.ok() ? Status{} : Status(read.error());
    });
    if (!captured.ok()) {
        ctx.error(captured.error());
        out.reason = "HNID 0x" + hex_u32(hnid) + ": " + util::format_error(captured.error());
        return;
    }
    auto value = captured.take();
    out.bytes = std::move(value.bytes);
    out.source = std::move(value.source);
    out.readable = true;
}

// [MS-PST] 2.4.7.1: an NPID is only an index into this file's Name-to-ID Map, so the identity
// behind it comes from that map and nowhere else. The writer re-registers it under a new NPID (D8).
void apply_named_identity(Ctx& ctx, SubsetValue& value) {
    if (value.prop_id < ltp::kNpidBase || value.prop_id > ltp::kNpidMax) {
        return;
    }
    value.named = true;
    const Result<ltp::NamedProperty> found =
        ltp::name_id_lookup_npid(ctx.census.name_id_map, value.prop_id);
    if (!found.ok()) {
        ctx.named_unresolved.insert(value.prop_id);
        return;
    }
    const ltp::NamedProperty& named = found.value();
    if (!ctx.reserve(8 * (2 * named.name.size() + named.guid.size()), "subset.identity_workspace"))
        return;
    value.name_resolved = named.name_resolved;
    value.name_is_string = named.name_is_string;
    value.name = named.name;
    value.numeric_name = named.numeric_name;
    value.guid_index = named.guid_index;
    value.guid_resolved = named.guid_resolved;
    value.guid = named.guid;
    // A numeric name is the property's name: [MS-PST] 2.4.7.1 says the N bit decides, and N == 0
    // means dwPropertyID IS the name. Only an N == 1 record whose offset no String Stream name
    // starts at leaves the identity without a name. The reader answers name_resolved for the String
    // Stream lookup, which an N == 0 record does not need. What the value carries is whether the
    // identity has a name at all, so the flag is set from the rule below rather than copied from
    // the map record.
    const bool name_known = named.name_is_string ? named.name_resolved : true;
    value.name_resolved = name_known;
    if (name_known) {
        ctx.named_resolved.insert(value.prop_id);
    } else {
        ctx.named_unresolved.insert(value.prop_id);
    }
}

// One Property Context record as the writer needs it. The record's own shape answers the first two
// questions: dwValueHnid 0 is [MS-PST] 2.3.3.2's "this property has no value", and an inline value
// IS the value ([MS-PST] 2.3.3.3). Everything else is a HNID answered through the node's heap and
// its subnodes together, which is the only thing that can tell a heap allocation from a subnode
// ([MS-PST] 2.3.3.2).
SubsetValue pc_record_value(Ctx& ctx, const ltp::PcRecord& record, ltp::NodeValueSource& values,
                            bool resolve_payload) {
    SubsetValue out;
    if (!ctx.reserve(8 * sizeof(SubsetValue), "subset.value_workspace")) {
        out.reason = "item metadata workspace exhausted";
        return out;
    }
    out.prop_id = record.prop_id;
    out.prop_type = record.prop_type;
    out.tag = (static_cast<uint32_t>(record.prop_id) << ltp::kTcTagPropIdShift) | record.prop_type;
    apply_named_identity(ctx, out);
    if (record.prop_id == kTagEntryId) {
        out.writer_assigned = true;
    }
    if (!resolve_payload && record.prop_id == kTagAttachData) {
        out.reason = "payload collection is off (SubsetOptions::collect_payloads)";
        return out;
    }
    if (record.value_absent) {
        out.absent = true;
        out.reason = "dwValueHnid 0: the property is present with no value ([MS-PST] 2.3.3.2)";
        return out;
    }
    if (record.value_inline) {
        out.bytes.assign(record.value.data(), record.value.data() + record.value.size());
        out.readable = true;
        if (out.bytes.size() == 4) {
            out.declared_bytes = le_u32(out.bytes);
        }
        return out;
    }
    if (ctx.options.spool && record.prop_type != kPropTypeObject) {
        capture_value(ctx, values, record.value_hnid, out);
        return out;
    }
    std::vector<uint8_t> object_reference;
    const Result<ByteView> obtained = [&]() -> Result<ByteView> {
        if (!ctx.options.spool || record.prop_type != kPropTypeObject)
            return values.value(record.value_hnid);
        auto read = values.stream(record.value_hnid, [&](ByteView part) -> Status {
            // MS-PST 2.3.3.5: validate the eight-byte reference without allocating a large subnode.
            if (part.size() > 8 - object_reference.size())
                return util::make_error(util::ErrorKind::kBadField, "PtypObject.reference_size",
                                        record.offset, part.size());
            if (!part.empty())
                object_reference.insert(object_reference.end(), part.data(),
                                        part.data() + part.size());
            return {};
        });
        if (!read.ok())
            return read.error();
        return ByteView(object_reference.data(), object_reference.size());
    }();
    if (!obtained.ok()) {
        ctx.error(obtained.error());
        out.reason = "the HNID 0x" + hex_u32(record.value_hnid) +
                     " did not resolve: " + obtained.error().detail;
        return out;
    }
    if (record.prop_type == kPropTypeObject) {
        if (obtained.value().size() != 8) {
            out.reason =
                "PtypObject allocation must contain exactly Nid and ulSize ([MS-PST] 2.3.3.5)";
            return out;
        }
        // [MS-PST] 2.3.3.5: the allocation holds Nid, the subnode that carries the object, then
        // ulSize, "the total size of the object". The object is not bytes, so `bytes` stays empty
        // and the reference is what gets recorded -- whether the converter can carry the object is
        // answered by the caller.
        const Result<uint32_t> object_nid = obtained.value().u32(0);
        const Result<uint32_t> object_size = obtained.value().u32(4);
        if (object_nid.ok()) {
            out.object_named = true;
            out.object_nid = object_nid.value();
            out.object_ul_size = object_size.ok() ? object_size.value() : 0;
        }
        out.reason =
            "PtypObject value naming subnode 0x" +
            (object_nid.ok() ? hex_u32(object_nid.value()) : std::string("<unreadable>")) +
            (object_size.ok()
                 ? ", the source states " + std::to_string(object_size.value()) +
                       " bytes for it ([MS-PST] 2.3.3.5)"
                 : ": the allocation is shorter than the 8 bytes [MS-PST] 2.3.3.5 defines");
        return out;
    }
    out.bytes.assign(obtained.value().data(), obtained.value().data() + obtained.value().size());
    out.readable = true;
    return out;
}

// Diagnostic BTH walks can tolerate damaged entries; conversion must not claim that
// the successfully visited subset establishes complete property/row populations.
Status complete_bth(const ltp::BthStats& stats, const char* field, uint64_t offset) {
    if (stats.skipped_records || stats.trailing_bytes || stats.stopped_early)
        return util::make_error(
            stats.stopped_early ? util::ErrorKind::kUnsupported : util::ErrorKind::kBadField, field,
            offset, stats.skipped_records,
            "incomplete BTH: skipped records=" + std::to_string(stats.skipped_records) +
                ", trailing bytes=" + std::to_string(stats.trailing_bytes) +
                ", stopped early=" + (stats.stopped_early ? "true" : "false"));
    return {};
}

// Reads every property. `resolve_payload` is off only when the caller wants the
// property list without pulling attachment data through the blocks.
bool read_property_values(Ctx& ctx, uint64_t nid, uint64_t bid_sub, ltp::NodeHeap& heap_node,
                          std::vector<SubsetValue>& values, bool resolve_payload,
                          std::string& note) {
    if (heap_node.source == nullptr) {
        return false;
    }
    std::vector<ltp::PcRecord> records;
    ltp::BthStats stats;
    Status walked = ltp::read_pc(
        heap_node.header, ctx.census.profile, *heap_node.source,
        [&](const ltp::PcRecord& record) {
            if (!ctx.reserve(4 * sizeof(ltp::PcRecord), "subset.pc_workspace"))
                return false;
            records.push_back(record);
            return true;
        },
        stats, ctx.failures);
    if (walked.ok())
        walked = complete_bth(stats, "PC.BTH.complete", heap_node.ib);
    if (!walked.ok()) {
        ctx.error(walked.error());
        const std::string detail =
            "Property Context did not read: " + util::format_error(walked.error());
        append_note(note, detail);
        ctx.note("0x" + hex_u64(nid) + ": " + detail);
        return false;
    }
    ltp::NodeValueSource source(*heap_node.source, bid_sub, ctx.census.profile, ctx.blocks,
                                ctx.subnodes, ctx.trees, ctx.failures);
    for (const ltp::PcRecord& record : records) {
        if (ctx.metadata.error())
            return false;
        SubsetValue value = pc_record_value(ctx, record, source, resolve_payload);
        ctx.count_value(value);
        values.push_back(std::move(value));
    }
    if (source.subnode_misses != 0) {
        ctx.note("0x" + hex_u64(nid) +
                 ": Property Context values naming a subnode this node does not hold: " +
                 std::to_string(source.subnode_misses));
    }
    return true;
}

// One row of a Table Context, as the extractor read it.
struct TableRow {
    uint32_t row_id = 0;    // TCROWID.dwRowID
    uint32_t row_index = 0; // TCROWID.dwRowIndex: which row of the Row Matrix this is
    std::vector<SubsetValue> values;
    bool cells_read = false;
    std::string note;
};

// One data block of a Row Matrix ([MS-PST] 2.3.4.4). Rows never span blocks and every block starts
// with a fresh row, so a block holds whole rows and, when it is a full block, the dead space at its
// end that the same section says readers MUST ignore. `first_row` is which row of the table this
// block's first row is.
struct MatrixBlock {
    std::vector<uint8_t> bytes;
    uint64_t rows = 0;
    uint64_t first_row = 0;
    uint64_t dead_bytes = 0;
};

struct TableStats {
    bool read = false;
    uint8_t columns = 0;
    std::vector<SubsetValue> column_values; // schema identities, including empty columns
    uint64_t rows = 0;
    uint64_t rows_without_cells = 0;
    bool matrix_in_heap = false;
    bool matrix_in_subnode = false;
    uint64_t matrix_bytes = 0;      // the bytes the blocks carry, dead space included
    uint64_t matrix_rows = 0;       // whole rows those bytes hold
    uint64_t matrix_dead_bytes = 0; // bytes no row occupies
    uint64_t matrix_blocks = 0;
    uint64_t matrix_short_blocks =
        0; // nonfinal blocks that are not a full block ([MS-PST] 2.3.4.4)
    std::string note;
};

// One cell of one row. [MS-PST] 2.3.4.4.2 decides whether the slot IS the value or names it: a
// single-valued fixed type of 8 bytes or less is inline. All other types, including
// multi-valued fixed-base arrays, leave a 4-byte HNID into the TC's heap or subnodes.
SubsetValue tc_cell_value(Ctx& ctx, const ltp::TcColumn& column, ByteView cell,
                          ltp::NodeValueSource& values) {
    SubsetValue out;
    if (!ctx.reserve(8 * sizeof(SubsetValue), "subset.cell_workspace")) {
        out.reason = "item metadata workspace exhausted";
        return out;
    }
    out.tag = column.tag;
    out.prop_id = static_cast<uint16_t>(ltp::tc_prop_id_of_tag(column.tag));
    out.prop_type = ltp::tc_prop_type_of_tag(column.tag);
    apply_named_identity(ctx, out);
    // A table row's 0x0FFF is not the PST object's 24-byte ENTRYID from [MS-PST] 2.4.3.2.
    // In a Recipient Table it is the address-book EntryID of that recipient ([MS-PST] 2.4.5.3.1),
    // so its provider-defined bytes are content and must survive conversion. Only the table's own
    // row key/version are assigned again by the destination writer.
    if (out.prop_id == kTagLtpRowId || out.prop_id == kTagLtpRowVer) {
        out.writer_assigned = true;
    }
    if (ltp::prop_type_is_tc_inline(out.prop_type)) {
        out.bytes.assign(cell.data(), cell.data() + cell.size());
        out.readable = true;
        if (out.bytes.size() == 4) {
            out.declared_bytes = le_u32(out.bytes);
        }
        return out;
    }
    if (!cell.in_range(0, static_cast<size_t>(kTcHnidSlotBytes))) {
        out.reason =
            "the row slot is " + std::to_string(cell.size()) +
            " bytes, less than the 4-byte HNID [MS-PST] 2.3.4.4.2 says a variable-sized column "
            "leaves";
        return out;
    }
    const Result<uint32_t> hnid = cell.u32(0);
    if (!hnid.ok()) {
        ctx.error(hnid.error());
        out.reason = "the row slot did not yield a HNID: " + hnid.error().detail;
        return out;
    }
    // [MS-PST] 2.3.4.4.2 processes non-inline values using 2.3.3, where HNID 0
    // means no value. CEB was already checked: this is a present empty cell, not
    // a missing column and not an invalid attempt to open heap allocation zero.
    if (hnid.value() == 0) {
        out.absent = true;
        return out;
    }
    if (ctx.options.spool) {
        capture_value(ctx, values, hnid.value(), out);
        return out;
    }
    const Result<ByteView> obtained = values.value(hnid.value());
    if (!obtained.ok()) {
        ctx.error(obtained.error());
        out.reason =
            "the HNID 0x" + hex_u32(hnid.value()) + " did not resolve: " + obtained.error().detail;
        return out;
    }
    out.bytes.assign(obtained.value().data(), obtained.value().data() + obtained.value().size());
    out.readable = true;
    return out;
}

// Opens one table subnode and reads its rows. The Row Matrix is copied out before any cell value is
// resolved because resolving a value re-aims the heap source that produced the matrix view.
bool read_table_rows(Ctx& ctx, uint64_t table_nid, uint64_t bid_data, uint64_t bid_sub,
                     std::vector<TableRow>& rows, TableStats& stats) {
    ltp::NodeHeap table;
    const ltp::NodeOpen opened =
        ltp::open_node(ctx.blocks, ctx.census.profile, table_nid, bid_data, table, ctx.heap,
                       ctx.trees, ctx.errors, nullptr, ctx.failures, ctx.workspace());
    if (opened != ltp::NodeOpen::kOk || table.source == nullptr ||
        table.header.b_client_sig != ltp::kClientSigTc) {
        stats.note = "the table node did not open as a Table Context";
        return false;
    }
    const Result<ltp::TcTable> table_info = ltp::read_tc(table.header, *table.source);
    if (!table_info.ok()) {
        ctx.error(table_info.error());
        stats.note = "Table Context did not read: " + util::format_error(table_info.error());
        return false;
    }
    const ltp::TcTable& info = table_info.value();
    const uint64_t row_size = ltp::tc_row_size(info.info);

    ltp::BthStats bth;
    std::vector<ltp::TcRowId> row_index;
    Status walked = ltp::walk_tc_row_index(
        info, ctx.census.profile, *table.source,
        [&](const ltp::TcRowId& row) {
            if (!ctx.reserve(
                    8 * (sizeof(TableRow) + sizeof(SubsetRecipient) + sizeof(SubsetAttachment)),
                    "subset.row_workspace"))
                return false;
            row_index.push_back(row);
            return true;
        },
        bth, ctx.failures);
    if (walked.ok())
        walked = complete_bth(bth, "TC.RowIndex.complete", info.header_offset);
    if (!walked.ok()) {
        ++ctx.report.row_index_walks_incomplete;
        ctx.error(walked.error());
        stats.note = "RowIndex BTH did not walk: " + util::format_error(walked.error());
        return false;
    }

    // Where the rows themselves live: [MS-PST] 2.3.4.1 puts the HNID in TCINFO.hnidRows,
    // [MS-PST] 2.3.3.2 says a hidType other than NID_TYPE_HID names one of the node's subnodes, and
    // [MS-PST] 2.3.4.4 says a subnode's data is the rows spread over blocks.
    std::vector<MatrixBlock> blocks;
    if (info.info.hnid_rows != 0) {
        if (ltp::hid_type(info.info.hnid_rows) == ltp::kHidTypeHid) {
            stats.matrix_in_heap = true;
            const Result<ByteView> bytes = table.source->heap(info.info.hnid_rows);
            if (!bytes.ok()) {
                ctx.error(bytes.error());
                stats.note = "the Row Matrix allocation 0x" + hex_u32(info.info.hnid_rows) +
                             " did not answer: " + util::format_error(bytes.error());
                return false;
            }
            blocks.push_back(
                MatrixBlock{std::vector<uint8_t>(bytes.value().data(),
                                                 bytes.value().data() + bytes.value().size()),
                            0, 0, 0});
        } else {
            stats.matrix_in_subnode = true;
            const Result<ltp::SubnodeRef> sub = ltp::find_subnode(
                bid_sub, info.info.hnid_rows, ctx.blocks, ctx.subnodes, ctx.failures);
            if (!sub.ok()) {
                ctx.error(sub.error());
                stats.note = "the Row Matrix subnode 0x" + hex_u32(info.info.hnid_rows) +
                             " was not found: " + util::format_error(sub.error());
                return false;
            }
            const Result<std::vector<ltp::HnFragment>> tree =
                ltp::read_data_tree(ctx.blocks, sub.value().bid_data, ctx.census.profile, ctx.trees,
                                    ctx.failures, ctx.workspace());
            if (!tree.ok()) {
                ctx.error(tree.error());
                stats.note =
                    "the Row Matrix data tree did not resolve: " + util::format_error(tree.error());
                return false;
            }
            stats.matrix_blocks = tree.value().size();
            for (const ltp::HnFragment& fragment : tree.value()) {
                const ByteView bytes = fragment.block.heap_node();
                blocks.push_back(MatrixBlock{
                    std::vector<uint8_t>(bytes.data(), bytes.data() + bytes.size()), 0, 0, 0});
            }
        }
    } else if (!row_index.empty()) {
        // TCINFO.hnidRows 0 says there is no Row Matrix at all ([MS-PST] 2.3.4.1), so a RowIndex
        // that names rows anyway is a contradiction and the rows cannot be read.
        stats.note = "TCINFO.hnidRows is 0 but the RowIndex names " +
                     std::to_string(row_index.size()) + " rows";
        return false;
    }

    // Row geometry per block ([MS-PST] 2.3.4.4): "Rows per block = Floor((sizeof(block) -
    // sizeof(BLOCKTRAILER)) / TCINFO.rgib[TCI_bm])". What a block hands a reader is its cb bytes,
    // which is sizeof(block) - sizeof(BLOCKTRAILER), so Floor(cb / row size) is the same count
    // taken from the bytes the block actually carries -- measured on the OST sample, whose 收件箱
    // matrix blocks each carry 65,512 bytes = 161 rows of 406. A nonfinal block shorter than the
    // profile's whole block is the corruption 2.3.4.4 names, so it is counted, not smoothed over.
    uint64_t matrix_rows = 0;
    uint64_t matrix_bytes = 0;
    for (size_t index = 0; index < blocks.size(); ++index) {
        MatrixBlock& block = blocks[index];
        block.rows = row_size == 0 ? 0 : block.bytes.size() / row_size;
        block.dead_bytes = block.bytes.size() - block.rows * row_size;
        block.first_row = matrix_rows;
        matrix_rows += block.rows;
        matrix_bytes += block.bytes.size();
        if (index + 1 < blocks.size() &&
            block.bytes.size() != ndb::block_max_cb(ctx.census.profile)) {
            ++stats.matrix_short_blocks;
            stats.note =
                "Row Matrix block " + std::to_string(index) + " carries " +
                std::to_string(block.bytes.size()) +
                " bytes, and [MS-PST] 2.3.4.4 requires every block but the last to be a full block "
                "(" +
                std::to_string(ndb::block_max_cb(ctx.census.profile)) + " raw bytes here)";
        }
    }
    stats.matrix_blocks = blocks.size();
    stats.matrix_rows = matrix_rows;
    if (stats.matrix_short_blocks != 0) {
        ctx.note("table 0x" + hex_u32(static_cast<uint32_t>(table_nid)) + ": " + stats.note);
    }
    if (stats.matrix_short_blocks != 0) {
        ctx.note("table 0x" + hex_u32(static_cast<uint32_t>(table_nid)) + ": " + stats.note);
    }
    stats.matrix_bytes = matrix_bytes;
    stats.matrix_dead_bytes = matrix_bytes - matrix_rows * row_size;
    ctx.report.matrix_short_blocks += stats.matrix_short_blocks;

    stats.read = true;
    stats.columns = info.info.c_cols;
    for (const ltp::TcColumn& column : info.columns) {
        if (!ctx.reserve(8 * sizeof(SubsetValue), "subset.column_workspace"))
            return false;
        SubsetValue definition;
        definition.tag = column.tag;
        definition.prop_id = static_cast<uint16_t>(ltp::tc_prop_id_of_tag(column.tag));
        definition.prop_type = ltp::tc_prop_type_of_tag(column.tag);
        apply_named_identity(ctx, definition);
        stats.column_values.push_back(std::move(definition));
    }
    stats.rows = row_index.size();

    ltp::NodeValueSource values(*table.source, bid_sub, ctx.census.profile, ctx.blocks,
                                ctx.subnodes, ctx.trees, ctx.failures);
    for (const ltp::TcRowId& row : row_index) {
        if (ctx.metadata.error())
            return false;
        TableRow out;
        out.row_id = row.row_id;
        out.row_index = row.row_index;
        const MatrixBlock* block = nullptr;
        uint64_t row_in_block = 0;
        for (const MatrixBlock& candidate : blocks) {
            if (static_cast<uint64_t>(row.row_index) < candidate.first_row + candidate.rows) {
                block = &candidate;
                row_in_block = static_cast<uint64_t>(row.row_index) - candidate.first_row;
                break;
            }
        }
        if (row_size == 0 || block == nullptr) {
            // A dwRowIndex naming a row past the matrix is "a field value exceeds what its referent
            // allows", so it is reported as a decode problem instead of being skipped silently.
            out.note = "dwRowIndex " + std::to_string(row.row_index) + " names a row past the " +
                       std::to_string(matrix_rows) + " rows the " + std::to_string(blocks.size()) +
                       " blocks of this Row Matrix hold (" + std::to_string(matrix_bytes) +
                       " bytes of " + std::to_string(row_size) + "-byte rows)";
            ++stats.rows_without_cells;
            ++ctx.report.rows_without_cells;
            rows.push_back(std::move(out));
            continue;
        }
        const ByteView row_bytes(block->bytes.data() + row_in_block * row_size,
                                 static_cast<size_t>(row_size), 0);
        out.cells_read = true;
        for (const ltp::TcColumn& column : info.columns) {
            if (ctx.metadata.error())
                return false;
            const Result<ltp::TcCell> cell = ltp::tc_column_cell(info, column, row_bytes);
            if (!cell.ok()) {
                ctx.error(cell.error());
                out.cells_read = false;
                ++stats.rows_without_cells;
                ++ctx.report.rows_without_cells;
                out.note = "column 0x" + hex_u32(column.tag) +
                           " did not read: " + util::format_error(cell.error());
                break;
            }
            // [MS-PST] 2.3.4.4.3: the CEB decides whether the column exists in this row, and the
            // bytes of a column that does not exist are random.
            if (!cell.value().exists) {
                continue;
            }
            SubsetValue value = tc_cell_value(ctx, column, cell.value().value, values);
            ctx.count_value(value);
            out.values.push_back(std::move(value));
        }
        rows.push_back(std::move(out));
    }
    return true;
}

// One Message object: its own Property Context, its subnode list, the Recipient Table and
// Attachment Table rows, and the Attachment objects those rows name ([MS-PST] 2.4.5, 2.4.6.1.3).
// [MS-PST] 2.4.6.2.2 (docs/reference/ms-pst.txt:3806-3817): an attachment that is itself a Message
// object carries its content as a PtypObject, and the same section says that Message is "not
// located in the NBT and [has] no parent folder" -- it is the subnode the object's Nid names under
// the Attachment object, which is what the OST sample does (research/review-repair-measurements.md:
// five Attachment objects of folder 0x8522 name a NID_TYPE_NORMAL_MESSAGE subnode and their ulSize
// equals the bytes under it). The libpff notes give 0x3705 method 5 for that form
// (libpff format notes (see THIRD_PARTY_NOTICES.txt):2491-2509).
void build_message(Ctx& ctx, const ltp::NodeRef& node, SubsetMessage& message, uint32_t depth,
                   const std::vector<uint64_t>& path);

// An object the converter cannot carry is a shortfall, not a folder with one fewer attachment:
// every branch below counts attachments_with_unread_object and says which part of the source it
// could not read.
void read_opaque_object(Ctx& ctx, const ltp::SubnodeRef& attachment_ref,
                        SubsetAttachment& attachment) {
    // MS-PST 2.3.3.5 names the object-data subnode. Method 6 in the libpff attachment notes
    // identifies OLE data, so heap-looking content is still opaque here.
    auto target = ltp::find_subnode(attachment_ref.bid_sub, attachment.object_nid, ctx.blocks,
                                    ctx.subnodes, ctx.failures);
    if (!target.ok()) {
        ctx.error(target.error());
        ++ctx.report.attachments_with_unread_object;
        append_note(attachment.note,
                    "object-data subnode did not resolve: " + target.error().detail);
        return;
    }
    if (target.value().bid_sub != 0) {
        ++ctx.report.attachments_with_unread_object;
        append_note(attachment.note, "opaque object with child subnodes is not supported");
        return;
    }
    if (ctx.options.spool) {
        auto captured =
            ctx.options.spool->capture([&](const util::ByteConsumer& consume) -> Status {
                auto streamed =
                    ltp::stream_data_tree(ctx.blocks, target.value().bid_data, ctx.census.profile,
                                          ctx.trees, ctx.failures, consume);
                return streamed.ok() ? Status{} : Status(streamed.error());
            });
        if (!captured.ok()) {
            ctx.error(captured.error());
            ++ctx.report.attachments_with_unread_object;
            append_note(attachment.note, "object-data tree failed: " + captured.error().detail);
            return;
        }
        auto value = captured.take();
        if (value.size() != attachment.object_ul_size) {
            ++ctx.report.attachments_with_unread_object;
            append_note(attachment.note, "PtypObject ulSize differs from its object-data length");
            return;
        }
        attachment.payload_bytes = value.size();
        attachment.object_data = std::move(value.bytes);
        attachment.object_source = std::move(value.source);
        attachment.object_data_read = true;
        attachment.payload_read = true;
        ++ctx.report.attachments_opaque;
        ++ctx.report.object_values_carried;
        return;
    }
    auto tree = ltp::read_data_tree(ctx.blocks, target.value().bid_data, ctx.census.profile,
                                    ctx.trees, ctx.failures);
    if (!tree.ok()) {
        ctx.error(tree.error());
        ++ctx.report.attachments_with_unread_object;
        append_note(attachment.note, "object-data tree failed: " + tree.error().detail);
        return;
    }
    uint64_t size = 0;
    for (const auto& fragment : tree.value())
        size += fragment.block.bytes().size();
    if (size != attachment.object_ul_size) {
        ++ctx.report.attachments_with_unread_object;
        append_note(attachment.note, "PtypObject ulSize differs from its object-data length");
        return;
    }
    for (const auto& fragment : tree.value()) {
        const auto part = fragment.block.bytes();
        attachment.object_data.insert(attachment.object_data.end(), part.data(),
                                      part.data() + part.size());
    }
    attachment.object_data_read = true;
    attachment.payload_read = true;
    attachment.payload_bytes = size;
    ++ctx.report.attachments_opaque;
    ++ctx.report.object_values_carried;
}

void read_attached_message(Ctx& ctx, const ltp::SubnodeRef& attachment_ref,
                           SubsetAttachment& attachment, uint32_t attach_method, uint32_t depth,
                           const std::vector<uint64_t>& path) {
    const uint32_t attachment_nid = static_cast<uint32_t>(ltp::subnode_nid_key(attachment_ref.nid));
    const std::string context = "attachment 0x" + hex_u32(attachment_nid);
    if (attach_method != kAttachMethodMessage) {
        ++ctx.report.attachments_with_unread_object;
        append_note(attachment.note,
                    context + ": 0x3701 is a PtypObject but 0x3705 is " +
                        std::to_string(attach_method) +
                        ", not the 5 that names an embedded Message ([MS-PST] 2.4.6.2.2)");
        return;
    }
    Result<ltp::SubnodeRef> named = ltp::find_subnode(attachment_ref.bid_sub, attachment.object_nid,
                                                      ctx.blocks, ctx.subnodes, ctx.failures);
    if (!named.ok()) {
        ctx.error(named.error());
        ++ctx.report.attachments_with_unread_object;
        append_note(attachment.note,
                    context + ": the subnode 0x3701 names, 0x" + hex_u32(attachment.object_nid) +
                        ", is not a subnode of this Attachment object: " + named.error().detail);
        return;
    }
    const ltp::SubnodeRef& target = named.value();
    const uint32_t target_type = static_cast<uint32_t>(ltp::nid_type(target.nid));
    if (target_type != ltp::kNidTypeNormalMessage) {
        ++ctx.report.attachments_with_unread_object;
        append_note(attachment.note, context + ": 0x3701 names subnode 0x" +
                                         hex_u32(attachment.object_nid) + " as nidType " +
                                         std::to_string(target_type) + " (" +
                                         ltp::nid_type_name(target_type) +
                                         "), not NID_TYPE_NORMAL_MESSAGE ([MS-PST] 2.4.6.2.2)");
        return;
    }
    if (std::find(path.begin(), path.end(), target.bid_data) != path.end()) {
        ++ctx.report.attachments_with_unread_object;
        append_note(attachment.note,
                    context + ": the attached Message 0x" +
                        hex_u32(static_cast<uint32_t>(ltp::subnode_nid_key(target.nid))) +
                        " is already on this path, so the source names a cycle");
        return;
    }
    if (depth + 1 > ctx.options.max_embedded_depth) {
        ++ctx.report.attachments_with_unread_object;
        append_note(
            attachment.note,
            context + ": the walk stopped at depth " + std::to_string(depth) +
                " (SubsetOptions::max_embedded_depth), so this attached Message was not read");
        return;
    }
    ltp::NodeHeap attached_heap;
    const ltp::NodeOpen attached_opened =
        ltp::open_node(ctx.blocks, ctx.census.profile, target.nid, target.bid_data, attached_heap,
                       ctx.heap, ctx.trees, ctx.errors, nullptr, ctx.failures, ctx.workspace());
    if (attached_opened != ltp::NodeOpen::kOk || attached_heap.source == nullptr ||
        attached_heap.header.b_client_sig != ltp::kClientSigPc) {
        ++ctx.report.attachments_with_unread_object;
        append_note(attachment.note,
                    context + ": the subnode 0x3701 names did not open as a Property Context");
        return;
    }
    ltp::NodeRef attached;
    attached.nid = ltp::subnode_nid_key(target.nid);
    attached.bid_data = target.bid_data;
    attached.bid_sub = target.bid_sub;
    attached.nid_parent = attachment_nid;
    std::vector<uint64_t> deeper = path;
    deeper.push_back(target.bid_data);
    attachment.embedded_nid = attached.nid;
    build_message(ctx, attached, attachment.embedded, depth + 1, deeper);
    attachment.embedded.embedded_depth = depth + 1;
    if (!attachment.embedded.pc_read) {
        ++ctx.report.attachments_with_unread_object;
        append_note(attachment.note, context + ": the attached Message 0x" +
                                         hex_u32(static_cast<uint32_t>(attached.nid)) +
                                         " has no readable Property Context");
        return;
    }
    attachment.embedded_read = true;
    ++ctx.report.attachments_embedded;
    ++ctx.report.object_values_carried;
}

void build_message(Ctx& ctx, const ltp::NodeRef& node, SubsetMessage& message, uint32_t depth,
                   const std::vector<uint64_t>& path) {
    ltp::NodeHeap heap_node;
    if (node.bid_data == 0) {
        message.note = "NBTENTRY.bidData is 0: the Message object carries no data block";
        return;
    }
    const ltp::NodeOpen opened =
        ltp::open_node(ctx.blocks, ctx.census.profile, node.nid, node.bid_data, heap_node, ctx.heap,
                       ctx.trees, ctx.errors, nullptr, ctx.failures, ctx.workspace());
    if (opened != ltp::NodeOpen::kOk || heap_node.source == nullptr ||
        heap_node.header.b_client_sig != ltp::kClientSigPc) {
        message.note = std::string("the node did not open as a Property Context (") +
                       ltp::nid_type_name(static_cast<uint32_t>(ltp::nid_type(node.nid))) + ", " +
                       ltp::client_sig_name(heap_node.header.b_client_sig) + ")";
        return;
    }
    message.pc_read = read_property_values(ctx, node.nid, node.bid_sub, heap_node, message.values,
                                           true, message.note);

    if (message.pc_read) {
        const auto has_tag = [&](uint16_t prop_id) {
            for (const SubsetValue& value : message.values) {
                if (value.prop_id == prop_id) {
                    return true;
                }
            }
            return false;
        };
        const auto has_readable = [&](uint16_t prop_id) {
            for (const SubsetValue& value : message.values) {
                if (value.prop_id == prop_id && value.readable) {
                    return true;
                }
            }
            return false;
        };
        // [MS-PST] 2.4.5.1.1 names the tags a Message object PC MUST carry. A missing one is a
        // statement about the source, so it is reported per message and not only in a total.
        std::string missing;
        for (const uint16_t tag : kRequiredMessageTags) {
            if (has_tag(tag)) {
                continue;
            }
            ++ctx.report.required_missing;
            if (!missing.empty()) {
                missing += ", ";
            }
            missing += "0x" + hex_u16(tag);
        }
        if (!missing.empty()) {
            append_note(message.note,
                        "Message PC does not carry [MS-PST] 2.4.5.1.1 required tags: " + missing);
        }
        // A body form counts when the extractor holds readable bytes for it. A record that is
        // present but unreadable is not a body the converter can write, so it lands in body_none
        // with its own reason.
        if (has_readable(kTagBody)) {
            ++ctx.report.body_plain;
        }
        if (has_readable(kTagHtml)) {
            ++ctx.report.body_html;
        }
        if (has_readable(kTagBodyCandidate)) {
            ++ctx.report.body_rtf;
        }
        if (!has_readable(kTagBody) && !has_readable(kTagHtml) &&
            !has_readable(kTagBodyCandidate)) {
            ++ctx.report.body_none;
        }
    }

    if (node.bid_sub == 0) {
        message.subnodes_complete = true;
        ++ctx.report.messages_without_recipient_table;
        append_note(message.note, "NBTENTRY.bidSub is 0: no subnode BTree");
        return;
    }
    ltp::SubnodeStats subnode_stats;
    Result<std::vector<ltp::SubnodeRef>> entries =
        ltp::walk_subnode_entries(node.bid_sub, ctx.blocks, subnode_stats, ctx.failures);
    ltp::merge_subnode_stats(ctx.subnodes, subnode_stats);
    if (!entries.ok()) {
        ctx.error(entries.error());
        ++ctx.report.subnode_walk_failures;
        append_note(message.note, "subnode BTree: " + util::format_error(entries.error()));
        return;
    }
    const std::vector<ltp::SubnodeRef> subnodes = entries.take();
    if (!ctx.reserve(8 * sizeof(ltp::SubnodeRef) * subnodes.size(), "subset.subnode_workspace"))
        return;
    message.subnode_entries = subnodes.size();
    message.subnodes_complete = !subnode_stats.stopped_early;
    if (subnode_stats.stopped_early) {
        ++ctx.report.subnode_walks_incomplete;
        append_note(message.note,
                    "subnode list is short: the walk stopped before it enumerated everything");
    }

    // The Attachment Table and the Attachment objects its rows name. [MS-PST] 2.4.6.1.3: each row's
    // dwRowID IS the subnode NID of the Attachment object for that row, so a row and a subnode have
    // to agree.
    std::set<uint32_t> attachment_rows;
    for (const ltp::SubnodeRef& subnode : subnodes) {
        if (ltp::subnode_nid_key(subnode.nid) != kNidAttachmentTable) {
            continue;
        }
        message.attachment_table = true;
        ++ctx.report.messages_with_attachment_table;
        if (subnode.bid_data == 0) {
            ++ctx.report.attachment_table_failures;
            append_note(message.note, "Attachment Table exists but bidData is 0");
            continue;
        }
        std::vector<TableRow> rows;
        TableStats stats;
        if (!read_table_rows(ctx, subnode.nid, subnode.bid_data, subnode.bid_sub, rows, stats)) {
            ++ctx.report.attachment_table_failures;
            append_note(message.note, "Attachment Table: " + stats.note);
            continue;
        }
        message.attachment_table_read = true;
        message.attachment_columns = stats.column_values;
        for (const TableRow& row : rows) {
            SubsetAttachment attachment;
            attachment.row_id = row.row_id;
            attachment.note = row.note;
            attachment.row_values = row.values;
            if (!attachment_rows.insert(row.row_id).second ||
                ltp::nid_type(row.row_id) != ltp::kNidTypeAttachment) {
                ++ctx.report.attachment_table_failures;
                append_note(attachment.note,
                            "duplicate or non-Attachment dwRowID in Attachment Table");
                message.attachments.push_back(std::move(attachment));
                continue;
            }
            const ltp::SubnodeRef* match = nullptr;
            for (const ltp::SubnodeRef& candidate : subnodes) {
                if (ltp::subnode_nid_key(candidate.nid) == row.row_id) {
                    match = &candidate;
                    break;
                }
            }
            if (match == nullptr) {
                // [MS-PST] 2.4.6.1.3 says the row names an Attachment object subnode. One that is
                // not in the subnode list is a defect of this source, and the attachment is
                // reported, not invented.
                append_note(attachment.note,
                            "the row's dwRowID 0x" + hex_u32(row.row_id) +
                                " names no subnode of this Message object ([MS-PST] 2.4.6.1.3)");
                ++ctx.report.attachments_without_payload;
                message.attachments.push_back(std::move(attachment));
                continue;
            }
            attachment.subnode_nid = ltp::subnode_nid_key(match->nid);
            ++ctx.report.attachments_read;
            ltp::NodeHeap attachment_node;
            const ltp::NodeOpen attachment_opened = ltp::open_node(
                ctx.blocks, ctx.census.profile, match->nid, match->bid_data, attachment_node,
                ctx.heap, ctx.trees, ctx.errors, nullptr, ctx.failures, ctx.workspace());
            if (attachment_opened != ltp::NodeOpen::kOk || attachment_node.source == nullptr ||
                attachment_node.header.b_client_sig != ltp::kClientSigPc) {
                append_note(attachment.note,
                            "the Attachment object did not open as a Property Context");
                ++ctx.report.attachment_pc_failures;
                message.attachments.push_back(std::move(attachment));
                continue;
            }
            attachment.pc_read = read_property_values(
                ctx, match->nid, match->bid_sub, attachment_node, attachment.values,
                ctx.options.collect_payloads, attachment.note);
            if (!attachment.pc_read) {
                append_note(attachment.note, "the Attachment object Property Context did not read");
                ++ctx.report.attachment_pc_failures;
                message.attachments.push_back(std::move(attachment));
                continue;
            }
            uint32_t attach_method = 0;
            const SubsetValue* data_value = nullptr;
            for (const SubsetValue& value : attachment.values) {
                if (value.prop_id == kTagAttachData) {
                    data_value = &value;
                    if (value.readable) {
                        attachment.payload_read = true;
                        attachment.payload_bytes = value.byte_count();
                    }
                }
                if (value.prop_id == kTagAttachSize) {
                    attachment.declared_bytes = value.declared_bytes;
                }
                if (value.prop_id == kTagAttachMethod && value.readable &&
                    value.bytes.size() >= 4) {
                    attach_method = static_cast<uint32_t>(le_u32(value.bytes));
                }
            }
            if (data_value != nullptr && data_value->object_named) {
                attachment.object_form = true;
                attachment.object_nid = data_value->object_nid;
                attachment.object_ul_size = data_value->object_ul_size;
                if (attach_method ==
                    6) { // libpff: attachment sub-item, method 6 is an OLE2 document
                    read_opaque_object(ctx, *match, attachment);
                } else {
                    read_attached_message(ctx, *match, attachment, attach_method, depth, path);
                }
            }
            // An embedded Message is the payload of this attachment ([MS-PST] 2.4.6.2.2), so a
            // carried one is not "an attachment with no payload"; one the walk could not carry is
            // counted apart from both.
            if (!attachment.payload_read && !attachment.embedded_read) {
                for (const SubsetValue& value : attachment.values) {
                    if (value.prop_id == kTagAttachData) {
                        append_note(attachment.note, "0x3701: " + value.reason);
                        break;
                    }
                }
                if (attachment.note.empty()) {
                    attachment.note = "the Attachment object PC carries no 0x3701 record";
                }
                ++ctx.report.attachments_without_payload;
                message.attachments.push_back(std::move(attachment));
                continue;
            }
            ctx.report.payload_bytes += attachment.payload_bytes;
            if (attachment.payload_bytes > ctx.report.max_payload_bytes) {
                ctx.report.max_payload_bytes = attachment.payload_bytes;
            }
            message.attachments.push_back(std::move(attachment));
        }
    }

    // The Recipient Table, which [MS-PST] 2.4.5 marks Required: Y for a Message object. A message
    // without one is reported; the converter does not invent a recipient for it.
    // Reconcile in both directions. Matching only the rows misses Attachment objects
    // left behind by a missing, unreadable or incomplete table ([MS-PST] 2.4.6.1.3).
    for (const auto& subnode : subnodes) {
        const auto nid = ltp::subnode_nid_key(subnode.nid);
        if (ltp::nid_type(nid) != ltp::kNidTypeAttachment || attachment_rows.contains(nid))
            continue;
        ++ctx.report.attachment_table_failures;
        ++ctx.report.attachments_read;
        SubsetAttachment attachment;
        attachment.row_id = nid;
        attachment.subnode_nid = nid;
        attachment.note = "Attachment object has no readable Attachment Table row";
        message.attachments.push_back(std::move(attachment));
    }

    uint64_t recipient_tables = 0;
    for (const ltp::SubnodeRef& subnode : subnodes) {
        if (ltp::subnode_nid_key(subnode.nid) != kNidRecipientTable) {
            continue;
        }
        message.recipient_table = true;
        ++recipient_tables;
        if (subnode.bid_data == 0) {
            ++ctx.report.recipient_table_failures;
            append_note(message.note, "Recipient Table exists but bidData is 0");
            continue;
        }
        std::vector<TableRow> rows;
        TableStats stats;
        if (!read_table_rows(ctx, subnode.nid, subnode.bid_data, subnode.bid_sub, rows, stats)) {
            ++ctx.report.recipient_table_failures;
            append_note(message.note, "Recipient Table: " + stats.note);
            continue;
        }
        message.recipient_table_read = true;
        message.recipient_columns = stats.column_values;
        for (const TableRow& row : rows) {
            SubsetRecipient recipient;
            recipient.row_id = row.row_id;
            recipient.values = row.values;
            recipient.note = row.note;
            ++ctx.report.recipients_read;
            message.recipients.push_back(std::move(recipient));
        }
    }
    if (recipient_tables == 0) {
        ++ctx.report.messages_without_recipient_table;
    } else {
        ++ctx.report.messages_with_recipient_table;
    }
}

// The Folder object itself: its Property Context, and the display name [MS-PST] 2.4.4.1.1 says it
// MUST carry.
void build_folder(Ctx& ctx, const ltp::NodeRef& node, SubsetFolder& folder) {
    folder.nid = node.nid;
    if (node.bid_data == 0) {
        folder.note = "NBTENTRY.bidData is 0: the Folder object carries no data block";
        return;
    }
    ltp::NodeHeap heap_node;
    const ltp::NodeOpen opened =
        ltp::open_node(ctx.blocks, ctx.census.profile, node.nid, node.bid_data, heap_node, ctx.heap,
                       ctx.trees, ctx.errors, nullptr, ctx.failures, ctx.workspace());
    if (opened != ltp::NodeOpen::kOk || heap_node.source == nullptr ||
        heap_node.header.b_client_sig != ltp::kClientSigPc) {
        folder.note = "the Folder object did not open as a Property Context";
        return;
    }
    folder.pc_read = read_property_values(ctx, node.nid, node.bid_sub, heap_node, folder.values,
                                          true, folder.note);
    for (const SubsetValue& value : folder.values) {
        if (value.prop_id == kTagDisplayName && value.readable) {
            if (value.source) {
                // Engineering limit for the name copies used by hierarchy/progress, not a layout
                // rule.
                if (value.source->size() > 1024 * 1024) {
                    ctx.error(util::make_error(util::ErrorKind::kUnsupported,
                                               "subset.folder_name_budget", node.nid,
                                               value.source->size()));
                    folder.pc_read = false;
                    return;
                }
                std::vector<uint8_t> bytes(static_cast<size_t>(value.source->size()));
                auto read = value.source->read_at(0, bytes.data(), bytes.size());
                if (!read.ok()) {
                    ctx.error(read.error());
                    folder.pc_read = false;
                    return;
                }
                folder.name = utf16le_to_utf8(ByteView(bytes.data(), bytes.size(), 0));
            } else {
                folder.name = utf16le_to_utf8(ByteView(value.bytes.data(), value.bytes.size(), 0));
            }
        }
    }
    if (folder.pc_read && folder.name.empty()) {
        folder.note = "the Folder object PC carries no readable 0x3001 PidTagDisplayName ([MS-PST] "
                      "2.4.4.1.1)";
    }
}

} // namespace

Result<SubsetReport> build_subset(const ltp::LtpReadReport& census, ltp::BlockSource& blocks,
                                  uint64_t folder_nid, const SubsetOptions& options) {
    const Result<ltp::NodeRef> folder_node = census.nodes.node(folder_nid);
    if (!folder_node.ok()) {
        return folder_node.error();
    }

    SubsetReport report;
    Ctx ctx(census, blocks, options, report);
    report.folder_children =
        census.nodes.children(static_cast<uint32_t>(folder_nid), ltp::kNidTypeNormalMessage);
    build_folder(ctx, folder_node.value(), report.folder);

    // [MS-PST] 2.4.5.2: a Message object's nidParent is the NID of its parent Folder object's PC,
    // so the NID map is the enumeration that works even when the folder's Contents Table holds no
    // rows -- which is what most folders of a real OST look like.
    std::vector<ltp::NodeRef> messages;
    for (const ltp::NodeRef& node : census.nodes.entries()) {
        if (ltp::nid_type(node.nid) == ltp::kNidTypeNormalMessage &&
            node.nid_parent == static_cast<uint32_t>(folder_nid)) {
            messages.push_back(node);
        }
    }
    if (messages.size() > static_cast<size_t>(options.max_messages)) {
        const uint64_t skipped = messages.size() - options.max_messages;
        report.capped = true;
        report.messages_skipped += skipped;
        ctx.note("the folder names " + std::to_string(messages.size()) +
                 " Message objects in the NBT; the cap kept the first " +
                 std::to_string(options.max_messages) + " in NID order and skipped " +
                 std::to_string(skipped));
        messages.resize(static_cast<size_t>(options.max_messages));
    }

    report.messages.reserve(messages.size());
    for (const ltp::NodeRef& node : messages) {
        SubsetMessage message;
        message.nid = node.nid;
        build_message(ctx, node, message, 0, {node.bid_data});
        if (message.pc_read) {
            ++report.messages_read;
        } else {
            ++report.messages_skipped;
            ++report.messages_without_pc;
            if (report.skipped.size() < options.max_notes) {
                report.skipped.push_back(
                    "0x" + hex_u64(node.nid) + ": " +
                    (message.note.empty() ? "no readable Property Context" : message.note));
            }
        }
        report.messages.push_back(std::move(message));
    }

    ctx.finish_workspace();
    report.named_tags = ctx.named_resolved.size();
    report.named_unresolved = ctx.named_unresolved.size();
    return report;
}

Result<SubsetReport> extract_item(const ltp::LtpReadReport& census, ltp::BlockSource& blocks,
                                  uint64_t item_nid, const SubsetOptions& options) {
    auto node = census.nodes.node(item_nid);
    if (!node.ok())
        return node.error();
    const auto type = ltp::nid_type(item_nid);
    if (type != ltp::kNidTypeNormalMessage && type != ltp::kNidTypeAssocMessage) {
        return util::make_error(util::ErrorKind::kBadField, "msg.extract.item_kind", item_nid, type,
                                "item must be an NBT normal or associated Message object");
    }
    auto parent = census.nodes.node(node.value().nid_parent);
    if (!parent.ok())
        return parent.error();
    if (ltp::nid_type(parent.value().nid) != ltp::kNidTypeNormalFolder) {
        return util::make_error(util::ErrorKind::kBadField, "msg.extract.item_parent", item_nid,
                                parent.value().nid, "item must belong to an actual folder");
    }
    SubsetReport report;
    report.folder.nid = parent.value().nid;
    Ctx ctx(census, blocks, options, report);
    SubsetMessage message;
    message.nid = item_nid;
    build_message(ctx, node.value(), message, 0, {node.value().bid_data});
    if (message.pc_read) {
        ++report.messages_read;
    } else {
        ++report.messages_skipped;
        ++report.messages_without_pc;
        report.skipped.push_back("0x" + hex_u64(item_nid) + ": " + message.note);
    }
    report.messages.push_back(std::move(message));
    ctx.finish_workspace();
    report.named_tags = ctx.named_resolved.size();
    report.named_unresolved = ctx.named_unresolved.size();
    return report;
}

Result<SubsetReport> extract_folder(const ltp::LtpReadReport& census, ltp::BlockSource& blocks,
                                    uint64_t folder_nid, const SubsetOptions& options) {
    auto node = census.nodes.node(folder_nid);
    if (!node.ok())
        return node.error();
    if (ltp::nid_type(folder_nid) != ltp::kNidTypeNormalFolder) {
        return util::make_error(util::ErrorKind::kBadField, "msg.extract.folder_kind", folder_nid,
                                0, "folder extraction requires an actual Folder object");
    }
    SubsetReport report;
    Ctx ctx(census, blocks, options, report);
    build_folder(ctx, node.value(), report.folder);
    ctx.finish_workspace();
    report.named_tags = ctx.named_resolved.size();
    report.named_unresolved = ctx.named_unresolved.size();
    return report;
}

} // namespace ost2pst::msg
