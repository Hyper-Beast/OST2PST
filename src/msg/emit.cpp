// msg -> writer: the conversion of one extracted folder into the request the writer emits. This
// file reads no file and owns no format arithmetic. It decides which source values may be handed
// over, which the writer has to assign itself, and which named identities have to be re-registered
// in the new store.
#include "ost2pst/msg/emit.h"

#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "ost2pst/ltp/name_id.h"
#include "ost2pst/ltp/prop_type.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

namespace ost2pst::msg {
namespace {

using util::ByteView;
using util::ErrorKind;
using util::make_error;
using util::Result;
using writer::ContentAttachment;
using writer::ContentCell;
using writer::ContentFolder;
using writer::ContentMessage;
using writer::ContentProperty;
using writer::ContentRow;
using writer::ContentTable;
using writer::NamedProperty;

constexpr uint16_t kTagDisplayName =
    0x3001; // [MS-PST] 2.4.4.1.1: PidTagDisplayName of a Folder object
constexpr uint16_t kTagAttachData =
    0x3701; // [MS-PST] 2.4.6.2.2: PidTagAttachData of an Attachment object
constexpr uint16_t kTagBody = 0x1000; // [MS-PST] ms-pst.txt:8087: 0x1000001F PidTagBody_W
constexpr uint16_t kTagHtml = 0x1013; // [MS-PST] ms-pst.txt:8093: 0x10130102 PidTagHtml
// 0x1009 is measured in this sample. Neither opened reference gives the numeric id: ms-pst.txt:4691
// and :5049 name PidTagRtfCompressed without one, and pff-format.asciidoc:2576 lists a compressed
// RTF message body for an e-mail item without a number.
constexpr uint16_t kTagRtfCompressed = 0x1009;

constexpr size_t kNoNamedSlot = ~static_cast<size_t>(0);

std::string hex4(uint16_t value) {
    static const char digits[] = "0123456789ABCDEF";
    std::string out = "0x";
    for (int shift = 12; shift >= 0; shift -= 4) {
        out.push_back(digits[(value >> shift) & 0xF]);
    }
    return out;
}

// The UTF-16LE bytes a PtypString16 value carries, read as code units. [MS-PST] 2.4.4.1.1 says a
// Folder object carries PidTagDisplayName; the writer names a folder with code units, not with
// UTF-8.
std::u16string utf16le(const std::vector<uint8_t>& bytes) {
    std::u16string out;
    for (size_t index = 0; index + 1 < bytes.size(); index += 2) {
        out.push_back(static_cast<char16_t>(bytes[index] | (bytes[index + 1] << 8)));
    }
    return out;
}
Result<std::u16string> folder_name(const SubsetValue& value) {
    if (!value.source)
        return utf16le(value.bytes);
    // Bound the hierarchy name copies separately from streamed property content.
    if (value.source->size() > 1024 * 1024)
        return make_error(ErrorKind::kUnsupported, "msg.emit.folder_name_budget", 0,
                          value.source->size());
    std::vector<uint8_t> bytes(static_cast<size_t>(value.source->size()));
    auto read = value.source->read_at(0, bytes.data(), bytes.size());
    if (!read.ok())
        return read.error();
    return utf16le(bytes);
}

uint32_t le32_at(const std::vector<uint8_t>& bytes, size_t offset) {
    return static_cast<uint32_t>(bytes[offset]) | (static_cast<uint32_t>(bytes[offset + 1]) << 8) |
           (static_cast<uint32_t>(bytes[offset + 2]) << 16) |
           (static_cast<uint32_t>(bytes[offset + 3]) << 24);
}

// libpff format notes (see THIRD_PARTY_NOTICES.txt):2632-2652: compressed RTF data starts with a
// 12-byte header whose first DWORD is the size of the compressed data including those 12 bytes, so
// the whole value is that DWORD plus 4; offset 8 is LZFu for compressed data and MELA for stored
// data. Checked here so a body the writer carries is at least self-consistent; it is not a claim
// that Outlook accepts the bytes.
Result<bool> rtf_header_adds_up(const SubsetValue& value) {
    if (value.byte_count() < 16) {
        return false;
    }
    std::vector<uint8_t> bytes(16);
    if (value.source) {
        auto read = value.source->read_at(0, bytes.data(), bytes.size());
        if (!read.ok())
            return read.error();
    } else {
        std::copy_n(value.bytes.begin(), bytes.size(), bytes.begin());
    }
    const uint32_t compressed = le32_at(bytes, 0);
    const uint32_t uncompressed = le32_at(bytes, 4);
    const bool signature = std::memcmp(bytes.data() + 8, "LZFu", 4) == 0 ||
                           std::memcmp(bytes.data() + 8, "MELA", 4) == 0;
    return signature && uncompressed != 0 &&
           static_cast<uint64_t>(compressed) + 4 == value.byte_count();
}

std::string identity_key(const std::vector<uint8_t>& guid, bool is_string,
                         const std::u16string& name, uint32_t numeric) {
    std::string key;
    // Explicit lengths distinguish the no-GUID set from every sixteen-byte GUID.
    key.push_back(static_cast<char>(guid.size()));
    for (const auto byte : guid)
        key.push_back(static_cast<char>(byte));
    key.push_back(is_string ? '\1' : '\0');
    if (is_string) {
        for (const char16_t unit : name) {
            key.push_back(static_cast<char>(unit & 0xFF));
            key.push_back(static_cast<char>(unit >> 8));
        }
    } else {
        for (int shift = 0; shift < 32; shift += 8)
            key.push_back(static_cast<char>(numeric >> shift));
    }
    return key;
}

// The shared state of one conversion: the named identities collected so far, and the report.
struct Emitter {
    explicit Emitter(const EmitOptions& options, const EmitRegistry* registry = nullptr)
        : registry(registry), options(options) {}
    const EmitRegistry* registry = nullptr;

    void note(const std::string& text) {
        if (report.notes.size() < options.max_notes) {
            report.notes.push_back(text);
        }
    }

    // [MS-PST] 2.4.7.1: a named property is a (property set, name) pair and a name is only unique
    // inside its property set, so the pair is what the new store re-registers. Two source NPIDs
    // that mean the same pair collapse into one entry, and the new NPID is a fresh index into the
    // new map.
    size_t slot_for(const SubsetValue& value, const std::string& context) {
        if (!value.name_resolved) {
            ++report.named_unresolved;
            ++report.values_dropped;
            note(context + ": " + hex4(value.prop_id) +
                 " is a named property whose name the source Name-to-ID Map never gave");
            return kNoNamedSlot;
        }
        // NAMEID_GUID_NONE has no GUID bytes and deliberately stays unresolved in
        // the reader. Match the manifest's distinction from a missing custom GUID.
        const bool no_guid = value.guid_index == 0 && value.guid.empty();
        if (!no_guid && (!value.guid_resolved || value.guid.size() != 16)) {
            ++report.named_unresolved;
            ++report.values_dropped;
            note(context + ": " + hex4(value.prop_id) +
                 " is a named property whose property set the source Name-to-ID Map never gave");
            return kNoNamedSlot;
        }
        std::string key =
            identity_key(value.guid, value.name_is_string, value.name, value.numeric_name);
        if (registry != nullptr) {
            auto fixed = registry->find(key);
            if (!fixed.ok()) {
                ++report.named_unresolved;
                ++report.values_dropped;
                note(context + ": named identity is absent from the fixed conversion registry");
                return kNoNamedSlot;
            }
            return static_cast<size_t>(fixed.value());
        }
        const auto found = named_slot.find(key);
        if (found != named_slot.end()) {
            return found->second;
        }
        NamedProperty entry;
        entry.name = value.name;
        entry.name_is_string = value.name_is_string;
        entry.numeric_name = value.numeric_name;
        entry.guid = value.guid;
        named.push_back(entry);
        const size_t index = named.size() - 1;
        named_slot.emplace(std::move(key), index);
        return index;
    }

    // One source value becomes one writer value, or is not handed over and the report says why.
    bool carry(const SubsetValue& value, const std::string& context, ContentProperty& out) {
        if (value.writer_assigned) {
            // [MS-PST] 2.4.3.2: a PST object EntryID names the store provider and object NID, and
            // 2.3.4.3 leaves table row keys to the implementation. Recipient-table 0x0FFF is
            // deliberately not marked writer_assigned: [MS-PST] 2.4.5.3.1 calls it the recipient's
            // address-book EntryID.
            ++report.writer_assigned_dropped;
            return false;
        }
        out.prop_id = value.prop_id;
        out.prop_type = value.prop_type;
        out.absent = value.absent;
        if (value.named) {
            const size_t index = slot_for(value, context);
            if (index == kNoNamedSlot) {
                return false;
            }
            out.named = true;
            out.named_index = index;
            ++report.named_values;
        }
        if (!value.readable && !value.absent) {
            ++report.values_dropped;
            note(context + ": " + hex4(value.prop_id) + " carries no readable content" +
                 (value.reason.empty() ? std::string() : std::string(": ") + value.reason));
            return false;
        }
        out.value = value.bytes;
        out.source = value.source;
        if (value.absent) {
            ++report.values_absent;
        } else {
            ++report.values_carried;
        }
        return true;
    }

    ContentTable table_for(const std::vector<SubsetValue>& columns, const std::string& context) {
        ContentTable table;
        for (const auto& definition : columns) {
            writer::ContentColumn column(definition.tag);
            if (definition.named) {
                const size_t index = slot_for(definition, context + " column");
                if (index == kNoNamedSlot)
                    continue; // slot_for records the shortfall, even with no rows
                column.named = true;
                column.named_index = index;
            }
            table.columns.push_back(column);
        }
        return table;
    }

    // The cells one table row carried, in the tags the source table had. A cell the writer assigns
    // itself or could not read is left out so the writer can fill the column or say it stayed
    // empty.
    ContentRow cells_for(uint32_t row_id, const std::vector<SubsetValue>& values,
                         const ContentTable& table, const std::string& context) {
        ContentRow row;
        row.row_id = row_id;
        for (const SubsetValue& value : values) {
            if (value.writer_assigned) {
                ++report.writer_assigned_dropped;
                continue;
            }
            const auto column =
                std::find_if(table.columns.begin(), table.columns.end(),
                             [&](const auto& candidate) { return candidate.tag == value.tag; });
            if (column == table.columns.end()) {
                ++report.values_dropped;
                note(context + ": cell has no registered column identity");
                continue;
            }
            if (!value.readable && !value.absent) {
                ++report.values_dropped;
                note(context + " row 0x" + hex4(static_cast<uint16_t>(value.tag >> 16)) + ": 0x" +
                     hex4(static_cast<uint16_t>(value.tag & 0xFFFF)) +
                     " carries no readable content" +
                     (value.reason.empty() ? std::string() : std::string(": ") + value.reason));
                continue;
            }
            ContentCell cell;
            cell.tag = value.tag;
            cell.value = value.bytes;
            cell.source = value.source;
            cell.absent = value.absent;
            if (column->named)
                ++report.named_values;
            row.cells.push_back(std::move(cell));
        }
        return row;
    }

    const EmitOptions& options;
    EmitReport report;
    std::optional<util::DataError> io_error;
    std::vector<NamedProperty> named;
    std::map<std::string, size_t> named_slot;
};

std::string hex8(uint32_t value) {
    static const char digits[] = "0123456789ABCDEF";
    std::string out = "0x";
    for (int shift = 28; shift >= 0; shift -= 4) {
        out.push_back(digits[(value >> shift) & 0xF]);
    }
    return out;
}

// The three body forms of a Message object. [MS-PST] 2.4.5.1.1 lists the seven MUST-carry tags and
// none of them is a body; ms-pst.txt:8087 and :8093 show 0x1000 and 0x1013 on a Message object of a
// real PST, and pff-format.asciidoc:2571-2578 names plain text, compressed RTF and HTML as the body
// forms of an e-mail item. The writer carries whichever the source had, unchanged, and only counts
// what it saw.
void count_body(const std::vector<SubsetValue>& values, Emitter& emitter,
                const std::string& context) {
    bool any = false;
    for (const SubsetValue& value : values) {
        if (value.prop_id == kTagBody) {
            ++emitter.report.body_plain;
            any = true;
        } else if (value.prop_id == kTagHtml) {
            ++emitter.report.body_html;
            any = true;
        } else if (value.prop_id == kTagRtfCompressed) {
            ++emitter.report.body_rtf;
            any = true;
            auto framed = value.readable ? rtf_header_adds_up(value) : Result<bool>(false);
            if (!framed.ok()) {
                emitter.io_error = framed.error();
                return;
            }
            if (framed.value()) {
                ++emitter.report.body_rtf_framed;
            } else {
                ++emitter.report.body_rtf_unframed;
                emitter.note(context + ": 0x1009 does not match the compressed-RTF header of "
                                       "docs/reference/pff-format.asciidoc:2632-2652");
            }
        }
    }
    if (!any) {
        ++emitter.report.messages_without_body;
    }
}

// One Message object as the writer needs it. An attachment whose 0x3701 object the extractor read
// as a Message ([MS-PST] 2.4.6.2.2) goes over as the embedded content of that Attachment object,
// and the writer puts it back as the PtypObject that names it.
ContentMessage emit_message(Emitter& emitter, const SubsetMessage& message) {
    ContentMessage out;
    const std::string context = "message " + hex8(static_cast<uint32_t>(message.nid));
    ++emitter.report.messages;
    count_body(message.values, emitter, context);
    for (const SubsetValue& value : message.values) {
        ContentProperty property;
        if (!emitter.carry(value, context, property)) {
            continue;
        }
        out.properties.push_back(std::move(property));
    }

    out.recipients = emitter.table_for(message.recipient_columns, context + " recipient table");
    for (const SubsetRecipient& recipient : message.recipients) {
        out.recipients.rows.push_back(emitter.cells_for(
            recipient.row_id, recipient.values, out.recipients, context + " recipient table"));
        ++emitter.report.recipients;
    }

    out.attachments = emitter.table_for(message.attachment_columns, context + " attachment table");
    for (const SubsetAttachment& attachment : message.attachments) {
        const std::string attach_context = context + " attachment " + hex8(attachment.row_id);
        out.attachments.rows.push_back(emitter.cells_for(attachment.row_id, attachment.row_values,
                                                         out.attachments, attach_context));
        ContentAttachment object;
        for (const SubsetValue& value : attachment.values) {
            if (value.prop_id == kTagAttachData && !value.absent) {
                // Payloads bypass carry(), but a failed value read must still reach the verdict.
                // Named objects use the separate embedded-object completeness checks.
                if (!value.readable && !value.absent && !value.object_named) {
                    ++emitter.report.values_dropped;
                    emitter.note(attach_context + ": 0x3701 content could not be read" +
                                 (value.reason.empty() ? std::string() : ": " + value.reason));
                }
                continue; // the payload goes over as 0x3701 ([MS-PST] 2.4.6.2.2), not as a PC
                          // record
            }
            // HNID 0 is a present-empty property. Preserve its original type in the PC,
            // even though there is no payload to send through the attachment byte path.
            ContentProperty property;
            if (!emitter.carry(value, attach_context, property)) {
                continue;
            }
            object.properties.push_back(std::move(property));
        }
        for (const SubsetValue& value : attachment.values) {
            if (value.prop_id == kTagAttachData && value.readable) {
                object.payload = value.bytes;
                object.payload_source = value.source;
                object.has_payload = true;
                break;
            }
        }
        if (attachment.embedded_read) {
            object.has_embedded = true;
            object.embedded_ul_size = attachment.object_ul_size;
            object.embedded = emit_message(emitter, attachment.embedded);
            ++emitter.report.attachments_embedded;
        }
        if (attachment.object_data_read) {
            object.has_object_payload = true;
            object.payload = attachment.object_data;
            object.payload_source = attachment.object_source;
            ++emitter.report.attachments_opaque;
        }
        if (object.has_payload || object.has_object_payload) {
            emitter.report.attachment_bytes +=
                object.payload_source ? object.payload_source->size() : object.payload.size();
        } else if (!object.has_embedded) {
            ++emitter.report.attachments_without_payload;
        }
        ++emitter.report.attachments;
        out.attachment_objects.push_back(std::move(object));
    }
    return out;
}

} // namespace

util::Result<EmitOutcome> build_emit_request(const SubsetReport& subset,
                                             const EmitOptions& options) {
    if (!subset.folder.pc_read) {
        return make_error(ErrorKind::kBadField, "msg.emit.folder_pc", subset.folder.nid, 0,
                          "the Folder object PC did not read, so there is no folder to convert");
    }
    Emitter emitter(options);
    EmitOutcome outcome;

    ContentFolder folder;
    folder.parent_nid = options.parent_nid;
    for (const SubsetValue& value : subset.folder.values) {
        ContentProperty property;
        if (!emitter.carry(value, "folder", property)) {
            continue;
        }
        if (value.prop_id == kTagDisplayName && value.readable) {
            auto name = folder_name(value);
            if (!name.ok())
                return name.error();
            folder.name = name.take();
        }
        folder.properties.push_back(std::move(property));
    }
    if (folder.name.empty()) {
        emitter.note(
            "folder: 0x3001 gave no display name, and [MS-PST] 2.4.4.1.1 says a Folder object "
            "MUST carry PidTagDisplayName");
    }
    ++emitter.report.folders;

    for (const SubsetMessage& message : subset.messages) {
        folder.messages.push_back(emit_message(emitter, message));
    }
    if (emitter.io_error)
        return *emitter.io_error;

    // The identities the new store has to register, counted before the vector moves into the
    // request.
    emitter.report.named_identities = emitter.named.size();
    outcome.request.named_properties = std::move(emitter.named);
    outcome.request.folders.push_back(std::move(folder));
    outcome.report = std::move(emitter.report);
    return outcome;
}

Result<EmitRegistry> EmitRegistry::build(std::vector<NamedProperty> entries) {
    if (entries.size() > ltp::kNpidMax - ltp::kNpidBase + 1u) {
        return make_error(ErrorKind::kUnsupported, "msg.registry.capacity", entries.size(), 0,
                          "identity count exceeds the output NPID range");
    }
    EmitRegistry result;
    for (size_t index = 0; index < entries.size(); ++index) {
        const auto& entry = entries[index];
        if (!entry.guid.empty() && entry.guid.size() != 16) {
            return make_error(ErrorKind::kBadField, "msg.registry.guid", index, entry.guid.size(),
                              "a property set is a sixteen-byte GUID or NAMEID_GUID_NONE");
        }
        if (!result.by_identity_
                 .emplace(
                     identity_key(entry.guid, entry.name_is_string, entry.name, entry.numeric_name),
                     index)
                 .second) {
            return make_error(ErrorKind::kBadField, "msg.registry.duplicate", index, 0,
                              "fixed identity registry must be deduplicated before numbering");
        }
    }
    result.entries_ = std::move(entries);
    return result;
}

Result<uint64_t> EmitRegistry::find(const std::string& key) const {
    const auto found = by_identity_.find(key);
    if (found == by_identity_.end()) {
        return make_error(ErrorKind::kBadField, "msg.registry.identity", 0, 0,
                          "identity is not in the immutable conversion registry");
    }
    return found->second;
}

Result<EmitItemOutcome> build_emit_item(const SubsetMessage& item, const EmitRegistry& registry,
                                        const EmitOptions& options) {
    if (!item.pc_read) {
        return make_error(ErrorKind::kBadField, "msg.emit.item_pc", item.nid, 0,
                          "an unreadable item PC cannot be emitted");
    }
    Emitter emitter(options, &registry);
    EmitItemOutcome result;
    result.message = emit_message(emitter, item);
    if (emitter.io_error)
        return *emitter.io_error;
    emitter.report.named_identities = registry.entries().size();
    result.report = std::move(emitter.report);
    return result;
}

Result<EmitFolderOutcome> build_emit_folder(const SubsetFolder& input, const EmitRegistry& registry,
                                            const EmitOptions& options) {
    if (!input.pc_read) {
        return make_error(ErrorKind::kBadField, "msg.emit.folder_pc", input.nid, 0,
                          "an unreadable folder PC cannot be emitted");
    }
    Emitter emitter(options, &registry);
    EmitFolderOutcome result;
    result.folder.parent_nid = options.parent_nid;
    for (const auto& value : input.values) {
        ContentProperty property;
        if (!emitter.carry(value, "folder", property))
            continue;
        if (value.prop_id == kTagDisplayName && value.readable) {
            auto name = folder_name(value);
            if (!name.ok())
                return name.error();
            result.folder.name = name.take();
        }
        result.folder.properties.push_back(std::move(property));
    }
    emitter.report.folders = 1;
    emitter.report.named_identities = registry.entries().size();
    result.report = std::move(emitter.report);
    return result;
}

} // namespace ost2pst::msg
