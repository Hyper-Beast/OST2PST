#include "ost2pst/msg/item_conversion.h"

#include <limits>

#include "ost2pst/ltp/data_tree.h"
#include "ost2pst/ltp/layout.h"

namespace ost2pst::msg {
namespace {

// Display logs intentionally cap findings. Capture typed I/O independently so a later
// disk-read failure cannot disappear behind earlier source findings or be relabelled corrupt.
class TrackedBlocks final : public ltp::BlockSource {
  public:
    explicit TrackedBlocks(ltp::BlockSource& source) : source_(source) {}
    util::Result<ltp::BlockBytes> block(uint64_t bid) override {
        auto result = source_.block(bid);
        if (!result.ok()) {
            if (result.error().kind == util::ErrorKind::kIo && !io_error)
                io_error = result.error();
            if (result.error().kind == util::ErrorKind::kUnsupported)
                unsupported = true;
        }
        return result;
    }
    std::optional<util::DataError> io_error;
    bool unsupported = false;

  private:
    ltp::BlockSource& source_;
};

bool object_population_complete(const SubsetMessage& message) {
    if (!message.pc_read || !message.subnodes_complete ||
        (message.recipient_table && !message.recipient_table_read) ||
        (message.attachment_table && !message.attachment_table_read))
        return false;
    for (const auto& attachment : message.attachments) {
        if (!attachment.pc_read ||
            (attachment.object_form && !attachment.embedded_read && !attachment.object_data_read))
            return false;
        if (attachment.embedded_read && !object_population_complete(attachment.embedded))
            return false;
    }
    return true;
}
bool population_complete(const SubsetReport& report) {
    return report.messages_read == 1 && report.messages.size() == 1 &&
           report.messages_without_pc == 0 && report.recipient_table_failures == 0 &&
           report.attachment_table_failures == 0 && report.attachment_pc_failures == 0 &&
           report.rows_without_cells == 0 && report.subnode_walk_failures == 0 &&
           report.subnode_walks_incomplete == 0 && report.row_index_walks_incomplete == 0 &&
           report.matrix_short_blocks == 0 && !report.capped &&
           report.attachments_with_unread_object == 0 &&
           report.object_values == report.object_values_carried &&
           object_population_complete(report.messages.front());
}

util::Status scopes(const SubsetMessage& message, std::vector<uint32_t> ancestry,
                    std::vector<ItemObjectScope>& objects) {
    if (message.nid > std::numeric_limits<uint32_t>::max())
        return util::make_error(util::ErrorKind::kBadField, "conversion.scope_identity", 0,
                                message.nid, "message NID exceeds its identifier range");
    ancestry.push_back(static_cast<uint32_t>(message.nid));
    objects.push_back({ItemObjectKind::kMessage, ancestry});
    for (const auto& recipient : message.recipients) {
        auto path = ancestry;
        path.push_back(recipient.row_id);
        objects.push_back({ItemObjectKind::kRecipient, std::move(path)});
    }
    for (const auto& attachment : message.attachments) {
        if (attachment.subnode_nid > std::numeric_limits<uint32_t>::max())
            return util::make_error(util::ErrorKind::kBadField, "conversion.scope_identity", 0,
                                    attachment.subnode_nid,
                                    "attachment NID exceeds its identifier range");
        auto path = ancestry;
        // The table row still identifies the affected object when opening it failed.
        path.push_back(attachment.row_id);
        objects.push_back({ItemObjectKind::kAttachment, path});
        if (attachment.embedded_read) {
            auto nested = scopes(attachment.embedded, std::move(path), objects);
            if (!nested.ok())
                return nested;
        }
    }
    return {};
}
void finding(PreparedItem& item, const char* code, uint64_t count) {
    if (count != 0)
        item.findings.push_back({code, count});
}

struct KnownGaps {
    uint64_t payload = 0;
    uint64_t recipient_table = 0;
    uint64_t body = 0;
};
bool has_property(const std::vector<SubsetValue>& values, uint16_t id) {
    for (const auto& value : values)
        if (value.prop_id == id)
            return true;
    return false;
}
void known_gaps(const SubsetMessage& message, KnownGaps& gaps) {
    if (message.pc_read) {
        // Same body property identifiers as the established subset contract. Presence,
        // not readability, decides source absence; an unreadable body is a failure.
        if (!has_property(message.values, 0x1000) && !has_property(message.values, 0x1013) &&
            !has_property(message.values, 0x1009))
            ++gaps.body;
    }
    if (message.subnodes_complete && !message.recipient_table)
        ++gaps.recipient_table;
    for (const auto& attachment : message.attachments) {
        if (attachment.pc_read && !has_property(attachment.values, 0x3701))
            ++gaps.payload;
        if (attachment.embedded_read)
            known_gaps(attachment.embedded, gaps);
    }
}
void source_findings(PreparedItem& item, const SubsetReport& report) {
    finding(item, "source.messages_without_pc", report.messages_without_pc);
    finding(item, "source.recipient_table_failure", report.recipient_table_failures);
    finding(item, "source.attachment_table_failure", report.attachment_table_failures);
    finding(item, "source.attachment_pc_failure", report.attachment_pc_failures);
    finding(item, "source.subnode_walk_failure", report.subnode_walk_failures);
    finding(item, "source.subnode_walk_incomplete", report.subnode_walks_incomplete);
    finding(item, "source.row_index_incomplete", report.row_index_walks_incomplete);
    finding(item, "source.matrix_short_block", report.matrix_short_blocks);
    finding(item, "source.rows_without_cells", report.rows_without_cells);
    finding(item, "source.unreadable_values", report.unreadable_values);
    finding(item, "source.named_unresolved", report.named_unresolved);
    finding(item, "source.unread_objects", report.attachments_with_unread_object);
    finding(item, "source.capped", report.capped ? 1 : 0);
    finding(item, "gap.required_property", report.required_missing);
    finding(item, "gap.empty_value", report.values_absent);
    finding(item, "source.attachment_payload_unavailable", report.attachments_without_payload);
    KnownGaps gaps;
    for (const auto& message : report.messages)
        known_gaps(message, gaps);
    finding(item, "gap.attachment_payload", gaps.payload);
    finding(item, "gap.recipient_table", gaps.recipient_table);
    finding(item, "gap.body", gaps.body);
}

void source_diagnostics(const SubsetMessage& message, std::vector<uint32_t> ancestry,
                        std::vector<ItemDiagnostic>& diagnostics) {
    ancestry.push_back(static_cast<uint32_t>(message.nid));
    if (!message.pc_read || !message.subnodes_complete ||
        (message.recipient_table && !message.recipient_table_read) ||
        (message.attachment_table && !message.attachment_table_read))
        diagnostics.push_back({ancestry, "message.read", message.note});
    const auto values = [&](const std::vector<SubsetValue>& properties,
                            const std::vector<uint32_t>& path, const char* stage) {
        for (const auto& property : properties) {
            if (!property.readable && !property.absent && !property.writer_assigned)
                diagnostics.push_back(
                    {path, stage, "tag=" + std::to_string(property.tag) + ": " + property.reason});
        }
    };
    values(message.values, ancestry, "message.property");
    for (const auto& recipient : message.recipients) {
        auto path = ancestry;
        path.push_back(recipient.row_id);
        values(recipient.values, path, "recipient.cell");
    }
    for (const auto& attachment : message.attachments) {
        auto path = ancestry;
        path.push_back(attachment.row_id);
        if (!attachment.pc_read ||
            (attachment.object_form && !attachment.embedded_read && !attachment.object_data_read))
            diagnostics.push_back({path, "attachment.read", attachment.note});
        values(attachment.values, path, "attachment.property");
        values(attachment.row_values, path, "attachment.cell");
        if (attachment.embedded_read)
            source_diagnostics(attachment.embedded, std::move(path), diagnostics);
    }
}

} // namespace

util::Result<PreparedItem> prepare_item(const ltp::LtpReadReport& census, ltp::BlockSource& blocks,
                                        const MailboxItem& item, const EmitRegistry& registry,
                                        const SubsetOptions& options) {
    // Manifest/index disagreements are shared-state errors, not item-local decode errors.
    auto source = census.nodes.node(item.source_nid);
    if (!source.ok())
        return source.error();
    if (source.value().nid_parent != item.source_parent ||
        item.associated != (ltp::nid_type(item.source_nid) == ltp::kNidTypeAssocMessage))
        return util::make_error(util::ErrorKind::kBadField, "conversion.item_manifest",
                                item.source_nid, item.source_parent,
                                "source identity disagrees with the manifest");
    TrackedBlocks tracked(blocks);
    SubsetOptions extraction_options = options;
    extraction_options.collect_payloads = true;
    auto extracted = extract_item(census, tracked, item.source_nid, extraction_options);
    if (tracked.io_error)
        return *tracked.io_error;
    if (!extracted.ok())
        return extracted.error();
    SubsetReport report = extracted.take();
    if (report.fatal_io)
        return *report.fatal_io;
    if (options.spool && options.spool->io_error())
        return *options.spool->io_error();
    PreparedItem result;
    result.outcome.item = item;
    result.outcome.source = {report.attachments_embedded, report.recipients_read,
                             report.attachments_read, report.attachments_opaque,
                             report.payload_bytes};
    result.outcome.source_complete = population_complete(report);
    source_findings(result, report);
    if (report.workspace_error)
        result.diagnostics.push_back({{item.source_nid},
                                      "extraction.workspace",
                                      util::format_error(*report.workspace_error)});
    for (const auto& entry : result.findings) {
        if (entry.code.starts_with("gap.")) {
            if (entry.count > std::numeric_limits<uint64_t>::max() - result.outcome.source_gaps)
                return util::make_error(util::ErrorKind::kBadField, "conversion.gap_overflow",
                                        item.source_nid);
            result.outcome.source_gaps += entry.count;
        }
    }
    for (const auto& message : report.messages) {
        auto scoped = scopes(message, {}, result.objects);
        if (!scoped.ok())
            return scoped.error();
        source_diagnostics(message, {}, result.diagnostics);
    }
    if (!result.outcome.source_complete || report.unreadable_values != 0) {
        result.outcome.status = (tracked.unsupported || report.unsupported_values)
                                    ? ItemStatus::kSkippedUnsupported
                                    : ItemStatus::kSkippedCorrupt;
        return result;
    }
    if (report.named_unresolved != 0) {
        result.outcome.status = ItemStatus::kSkippedUnsupported;
        return result;
    }
    auto emitted = build_emit_item(report.messages.front(), registry);
    if (!emitted.ok())
        return emitted.error();
    EmitItemOutcome emission = emitted.take();
    if (emission.report.values_dropped != 0 || emission.report.named_unresolved != 0) {
        finding(result, "emission.values_dropped", emission.report.values_dropped);
        finding(result, "emission.named_unresolved", emission.report.named_unresolved);
        result.outcome.status = ItemStatus::kSkippedUnsupported;
        return result;
    }
    auto built = writer::build_item_plan(emission.message, item.output_nid, item.output_parent,
                                         registry.entries().size());
    if (!built.ok())
        return built.error();
    auto plan = built.take();
    const auto& written = plan.content.report;
    const ItemPopulation committed{written.embedded_messages, written.recipients,
                                   written.attachments, written.opaque_objects,
                                   written.attachment_bytes};
    if (committed != result.outcome.source ||
        written.messages != 1 + result.outcome.source.embedded || written.values_dropped != 0 ||
        written.attachment_bytes != emission.report.attachment_bytes)
        return util::make_error(util::ErrorKind::kBadField, "conversion.writer_population",
                                item.source_nid, written.messages,
                                "writer lost available content; this is not a corrupt source item");
    result.outcome.status = ItemStatus::kConverted;
    result.outcome.committed = committed;
    result.outcome.read_state_known = plan.read_state_known;
    result.outcome.unread = plan.unread;
    result.content = std::move(plan.content);
    result.row = std::move(plan.row);
    return result;
}
} // namespace ost2pst::msg
