#include "ost2pst/msg/outcome.h"

#include <array>
#include <limits>

namespace ost2pst::msg {
namespace {
using util::ErrorKind;
using util::Result;
using util::Status;

Status invalid(const char* field, uint64_t value, const char* detail) {
    return util::make_error(ErrorKind::kBadField, field, 0, value, detail);
}

Status validate(const ItemOutcome& value) {
    const auto status = static_cast<uint64_t>(value.status);
    if (status < 1 || status > 4)
        return invalid("outcome.status", status, "unknown terminal status");
    if (value.source.opaque_objects > value.source.attachments ||
        value.committed.opaque_objects > value.committed.attachments ||
        (!value.read_state_known && value.unread))
        return invalid("outcome.population", value.item.source_nid,
                       "contradictory population or read-state metadata");
    if (value.status == ItemStatus::kConverted) {
        if (!value.source_complete || value.source != value.committed)
            return invalid("outcome.converted", value.item.source_nid,
                           "converted item must preserve its complete measured population");
    } else if (value.committed != ItemPopulation{} || value.read_state_known || value.unread) {
        return invalid("outcome.skipped", value.item.source_nid,
                       "failed/skipped item cannot contribute output content or unread counts");
    }
    return {};
}

bool add(uint64_t& target, uint64_t value) {
    if (value > std::numeric_limits<uint64_t>::max() - target)
        return false;
    target += value;
    return true;
}
bool add(ItemPopulation& target, const ItemPopulation& value) {
    return add(target.embedded, value.embedded) && add(target.recipients, value.recipients) &&
           add(target.attachments, value.attachments) &&
           add(target.opaque_objects, value.opaque_objects) &&
           add(target.attachment_bytes, value.attachment_bytes);
}

void encode_population(std::map<std::string, uint64_t>& fields, const std::string& prefix,
                       const ItemPopulation& value) {
    fields.emplace(prefix + ".embedded", value.embedded);
    fields.emplace(prefix + ".recipients", value.recipients);
    fields.emplace(prefix + ".attachments", value.attachments);
    fields.emplace(prefix + ".opaque_objects", value.opaque_objects);
    fields.emplace(prefix + ".attachment_bytes", value.attachment_bytes);
}
ItemPopulation decode_population(const std::map<std::string, uint64_t>& fields,
                                 const std::string& prefix) {
    return {fields.at(prefix + ".embedded"), fields.at(prefix + ".recipients"),
            fields.at(prefix + ".attachments"), fields.at(prefix + ".opaque_objects"),
            fields.at(prefix + ".attachment_bytes")};
}
} // namespace

const char* item_status_name(ItemStatus status) {
    switch (status) {
    case ItemStatus::kConverted:
        return "converted";
    case ItemStatus::kSkippedCorrupt:
        return "skipped-corrupt";
    case ItemStatus::kSkippedUnsupported:
        return "skipped-unsupported";
    case ItemStatus::kFailed:
        return "failed";
    }
    return "unknown";
}

util::Sha256Digest item_outcome_key(const MailboxItem& item) {
    util::Sha256 hash;
    const std::string domain = "ost2pst.m6.item.v1";
    hash.update(util::ByteView(reinterpret_cast<const uint8_t*>(domain.data()), domain.size(), 0));
    for (const uint32_t value :
         {item.source_nid, item.source_parent, item.output_nid, item.output_parent}) {
        const std::array<uint8_t, 4> bytes{
            static_cast<uint8_t>(value), static_cast<uint8_t>(value >> 8),
            static_cast<uint8_t>(value >> 16), static_cast<uint8_t>(value >> 24)};
        hash.update(util::ByteView(bytes.data(), bytes.size(), 0));
    }
    return hash.digest();
}

Result<writer::StagedDetails> encode_item_outcome(const ItemOutcome& value,
                                                  const writer::TcRow* row) {
    auto valid = validate(value);
    if (!valid.ok())
        return valid.error();
    if ((row != nullptr) != (value.status == ItemStatus::kConverted) ||
        (row != nullptr && row->row_id != value.item.output_nid))
        return invalid("outcome.row", value.item.output_nid,
                       "only a converted item has its reserved contents row")
            .error();
    writer::StagedDetails result;
    if (row != nullptr)
        result.row = *row;
    result.counters = {{"record_kind", 1},
                       {"item_schema", 1},
                       {"source_nid", value.item.source_nid},
                       {"source_parent", value.item.source_parent},
                       {"output_nid", value.item.output_nid},
                       {"output_parent", value.item.output_parent},
                       {"associated", value.item.associated ? 1 : 0},
                       {"status", static_cast<uint64_t>(value.status)},
                       {"source_complete", value.source_complete ? 1 : 0},
                       {"source_gaps", value.source_gaps},
                       {"read_state_known", value.read_state_known ? 1 : 0},
                       {"unread", value.unread ? 1 : 0}};
    encode_population(result.counters, "source", value.source);
    encode_population(result.counters, "committed", value.committed);
    return result;
}

Result<ItemOutcome> decode_item_outcome(const writer::StagedPlan& plan,
                                        writer::StagedOutcome framing) {
    const auto& fields = plan.details.counters;
    // Require the complete v1 field set and reject unexplained extension fields.
    ItemOutcome skeleton;
    skeleton.status = ItemStatus::kFailed;
    auto expected = encode_item_outcome(skeleton).take().counters;
    if (fields.size() != expected.size())
        return invalid("outcome.schema", fields.size(), "incorrect item field set").error();
    for (const auto& [name, unused] : expected) {
        (void)unused;
        if (!fields.contains(name))
            return invalid("outcome.schema", 0, "required item field is missing").error();
    }
    if (fields.at("record_kind") != 1 || fields.at("item_schema") != 1)
        return invalid("outcome.version", fields.at("item_schema"),
                       "unsupported item metadata version")
            .error();
    for (const auto* field : {"source_nid", "source_parent", "output_nid", "output_parent"}) {
        if (fields.at(field) > std::numeric_limits<uint32_t>::max())
            return invalid("outcome.identity", fields.at(field), "NID exceeds uint32").error();
    }
    for (const auto* field : {"associated", "source_complete", "read_state_known", "unread"}) {
        if (fields.at(field) > 1)
            return invalid("outcome.boolean", fields.at(field), "flag is not boolean").error();
    }
    ItemOutcome result;
    result.item = {static_cast<uint32_t>(fields.at("source_nid")),
                   static_cast<uint32_t>(fields.at("source_parent")),
                   static_cast<uint32_t>(fields.at("output_nid")),
                   static_cast<uint32_t>(fields.at("output_parent")), fields.at("associated") != 0};
    result.status = static_cast<ItemStatus>(fields.at("status"));
    result.source_complete = fields.at("source_complete") != 0;
    result.source_gaps = fields.at("source_gaps");
    result.read_state_known = fields.at("read_state_known") != 0;
    result.unread = fields.at("unread") != 0;
    result.source = decode_population(fields, "source");
    result.committed = decode_population(fields, "committed");
    auto valid = validate(result);
    if (!valid.ok())
        return valid.error();
    const bool converted = result.status == ItemStatus::kConverted;
    if (framing !=
            (converted ? writer::StagedOutcome::kConverted : writer::StagedOutcome::kFailed) ||
        plan.details.row.has_value() != converted || !plan.rgnid.empty() ||
        (converted && (plan.nodes.size() != 1 || plan.blocks.empty() ||
                       plan.nodes.front().nid != result.item.output_nid ||
                       plan.nodes.front().nid_parent != result.item.output_parent ||
                       plan.details.row->row_id != result.item.output_nid)) ||
        (!converted && (!plan.nodes.empty() || !plan.blocks.empty())))
        return invalid("outcome.content", result.item.source_nid,
                       "terminal status and staged content disagree")
            .error();
    return result;
}

OutcomeLedger::OutcomeLedger(const MailboxManifest& manifest) {
    for (const auto& item : manifest.items)
        expected_.emplace(item.source_nid, item);
}

Status OutcomeLedger::accept(size_t record, const util::Sha256Digest& key,
                             const ItemOutcome& value) {
    auto valid = validate(value);
    if (!valid.ok())
        return valid;
    const auto found = expected_.find(value.item.source_nid);
    if (found == expected_.end() || found->second.source_parent != value.item.source_parent ||
        found->second.output_nid != value.item.output_nid ||
        found->second.output_parent != value.item.output_parent ||
        found->second.associated != value.item.associated || key != item_outcome_key(value.item))
        return invalid("outcome.manifest", value.item.source_nid,
                       "outcome does not match its reserved manifest identity");
    if (items_.contains(value.item.source_nid))
        return invalid("outcome.duplicate", value.item.source_nid,
                       "item already has a durable terminal outcome");
    OutcomeTotals next = totals_;
    uint64_t* terminal = nullptr;
    switch (value.status) {
    case ItemStatus::kConverted:
        terminal = value.item.associated ? &next.converted_associated : &next.converted_normal;
        break;
    case ItemStatus::kSkippedCorrupt:
        terminal = &next.skipped_corrupt;
        break;
    case ItemStatus::kSkippedUnsupported:
        terminal = &next.skipped_unsupported;
        break;
    case ItemStatus::kFailed:
        terminal = &next.failed;
        break;
    }
    if (!add(*terminal, 1) || !add(next.terminal, 1) || !add(next.source, value.source) ||
        !add(next.committed, value.committed) || !add(next.source_gaps, value.source_gaps) ||
        !add(next.unknown_source, value.source_complete ? 0 : 1) ||
        !add(next.unknown_read_state,
             value.status == ItemStatus::kConverted && !value.read_state_known ? 1 : 0) ||
        !add(next.unread_normal,
             value.status == ItemStatus::kConverted && !value.item.associated && value.unread ? 1
                                                                                              : 0))
        return invalid("outcome.overflow", value.item.source_nid, "population total overflows");
    items_.emplace(value.item.source_nid, CommittedItem{record, value});
    totals_ = next;
    return {};
}

} // namespace ost2pst::msg
