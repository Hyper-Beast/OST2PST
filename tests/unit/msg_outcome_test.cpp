#include <chrono>
#include <filesystem>
#include <limits>

#include "ost2pst/msg/outcome.h"
#include "ost2pst/writer/content.h"

#include "test_support.h"

namespace {
namespace msg = ost2pst::msg;
namespace writer = ost2pst::writer;
using ost2pst::util::ErrorKind;

void check_durable_accounting() {
    const auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const auto directory = std::filesystem::temp_directory_path() / ("ost2pst-outcomes-" + suffix);
    std::filesystem::create_directory(directory);
    const auto data_path = directory / "data";
    const auto journal_path = directory / "journal";
    msg::MailboxManifest manifest;
    manifest.items = {{0x104, 0x122, 0x200024, 0x8082, false},
                      {0x128, 0x122, 0x100028, 0x8082, true},
                      {0x144, 0x122, 0x200044, 0x8082, false}};
    ost2pst::util::Sha256Digest binding{};
    binding[0] = 19;
    {
        auto data = ost2pst::util::FileWriter::create_new(data_path.native());
        auto file = ost2pst::util::FileWriter::create_new(journal_path.native());
        TEST_OK(data, "outcome data");
        TEST_OK(file, "outcome journal");
        if (!data.ok() || !file.ok())
            return;
        auto data_handle = data.take();
        auto file_handle = file.take();
        auto journal = writer::StagingJournal::create(data_handle, file_handle, binding);
        TEST_OK(journal, "new outcome journal");
        if (!journal.ok())
            return;
        // Result::value is const; take transfers ownership of the handles and journal.
    }
    {
        auto data_result = ost2pst::util::FileWriter::open_existing(data_path.native());
        auto file_result = ost2pst::util::FileWriter::open_existing(journal_path.native());
        TEST_OK(data_result, "reopen data");
        TEST_OK(file_result, "reopen journal");
        if (!data_result.ok() || !file_result.ok())
            return;
        auto data = data_result.take();
        auto file = file_result.take();
        auto recovered = writer::StagingJournal::recover(data, file, binding);
        TEST_OK(recovered, "recover empty journal");
        if (!recovered.ok())
            return;
        auto journal = recovered.take();
        msg::OutcomeLedger ledger(manifest);
        msg::InvocationAttempts attempts;
        for (size_t index = 0; index < manifest.items.size(); ++index) {
            const auto& identity = manifest.items[index];
            identity.associated ? ++attempts.associated : ++attempts.normal;
            msg::ItemOutcome outcome;
            outcome.item = identity;
            outcome.status =
                index == 1 ? msg::ItemStatus::kSkippedCorrupt : msg::ItemStatus::kConverted;
            outcome.source_complete = index != 1;
            outcome.source = {index, 2, 3, 1, 1000 + index};
            writer::StorePlan plan;
            writer::TcRow row;
            if (index != 1) {
                outcome.committed = outcome.source;
                outcome.read_state_known = true;
                outcome.unread = index == 0;
                // The ledger transports plans without claiming these synthetic bytes are a PST.
                plan.blocks.push_back({{1, 2, 3}});
                writer::StoreNode node;
                node.nid = identity.output_nid;
                node.nid_parent = identity.output_parent;
                node.data_blocks = {0};
                plan.nodes.push_back(std::move(node));
                row.row_id = identity.output_nid;
            }
            auto details = msg::encode_item_outcome(outcome, index == 1 ? nullptr : &row);
            TEST_OK(details, "encode terminal outcome");
            if (!details.ok())
                return;
            auto staging = details.take();
            staging.json =
                "{\"status\":\"" + std::string(msg::item_status_name(outcome.status)) + "\"}";
            TEST_OK(writer::stage_plan(journal, msg::item_outcome_key(identity),
                                       index == 1 ? writer::StagedOutcome::kFailed
                                                  : writer::StagedOutcome::kConverted,
                                       plan, staging),
                    "commit one terminal outcome");
            TEST_OK(ledger.accept(index, msg::item_outcome_key(identity), outcome),
                    "account after durability");
        }
        TEST_EQ(attempts.normal, 2u, "current invocation normal attempts");
        TEST_EQ(attempts.associated, 1u, "current invocation FAI attempts");
        TEST_EQ(ledger.totals().converted_normal, 2u, "valid neighbours survived corruption");
        TEST_EQ(ledger.totals().skipped_corrupt, 1u, "corrupt FAI terminal outcome");
        TEST_EQ(ledger.totals().committed.attachments, 6u,
                "only durable converted attachments count");
        TEST_EQ(ledger.totals().source.attachments, 9u,
                "partial source observations remain separate");
        TEST_EQ(ledger.totals().unknown_source, 1u, "partial descendant census is explicit");
    }
    {
        auto data_result = ost2pst::util::FileWriter::open_existing(data_path.native());
        auto file_result = ost2pst::util::FileWriter::open_existing(journal_path.native());
        if (!data_result.ok() || !file_result.ok()) {
            TEST_CHECK(false);
            return;
        }
        auto data = data_result.take();
        auto file = file_result.take();
        auto recovered = writer::StagingJournal::recover(data, file, binding);
        TEST_OK(recovered, "durable outcomes survive closing and reopening");
        if (!recovered.ok())
            return;
        auto journal = recovered.take();
        msg::OutcomeLedger ledger(manifest);
        msg::InvocationAttempts resumed_attempts;
        for (size_t index = 0; index < journal.records().size(); ++index) {
            auto plan = writer::read_staged_plan(journal, index);
            TEST_OK(plan, "read recovered outcome metadata");
            if (!plan.ok())
                return;
            auto outcome = msg::decode_item_outcome(plan.value(), journal.records()[index].outcome);
            TEST_OK(outcome, "validate recovered terminal outcome");
            if (!outcome.ok())
                return;
            TEST_OK(ledger.accept(index, journal.records()[index].key, outcome.value()),
                    "replay once");
            TEST_ERROR(ledger.accept(index, journal.records()[index].key, outcome.value()),
                       ErrorKind::kBadField, "outcome.duplicate",
                       "duplicate replay must not inflate totals");
            auto changed = outcome.value();
            changed.item.output_parent += 32;
            msg::OutcomeLedger empty(manifest);
            TEST_ERROR(empty.accept(index, msg::item_outcome_key(changed.item), changed),
                       ErrorKind::kBadField, "outcome.manifest", "refuse foreign identity");
            auto bad_plan = plan.value();
            bad_plan.details.counters["unread"] = 2;
            TEST_ERROR(msg::decode_item_outcome(bad_plan, journal.records()[index].outcome),
                       ErrorKind::kBadField, "outcome.boolean", "reject nonboolean flags");
            bad_plan = plan.value();
            bad_plan.details.counters.erase("source.embedded");
            TEST_ERROR(msg::decode_item_outcome(bad_plan, journal.records()[index].outcome),
                       ErrorKind::kBadField, "outcome.schema",
                       "missing population cannot default to zero");
            bad_plan = plan.value();
            if (index == 1) {
                bad_plan.details.counters["committed.attachments"] = 1;
                TEST_ERROR(msg::decode_item_outcome(bad_plan, journal.records()[index].outcome),
                           ErrorKind::kBadField, "outcome.skipped",
                           "skipped item cannot count emitted attempts");
            } else {
                bad_plan.nodes.front().nid_parent += 32;
                TEST_ERROR(msg::decode_item_outcome(bad_plan, journal.records()[index].outcome),
                           ErrorKind::kBadField, "outcome.content",
                           "check row/node ownership against outcome");
            }
        }
        TEST_EQ(resumed_attempts.normal + resumed_attempts.associated, 0u,
                "recovery performs no extraction attempts");
        TEST_EQ(ledger.totals().terminal, 3u, "exactly one outcome per original item");
        TEST_EQ(ledger.totals().committed.attachment_bytes, 2002u,
                "replay preserves committed bytes exactly");
        TEST_EQ(ledger.totals().unread_normal, 1u, "committed unread state survives recovery");
        TEST_EQ(ledger.totals().converted_associated, 0u, "skipped FAI never enters output totals");
    }
    std::error_code ignored;
    std::filesystem::remove(data_path, ignored);
    std::filesystem::remove(journal_path, ignored);
    std::filesystem::remove(directory, ignored);
}

void check_overflow_and_status() {
    msg::MailboxManifest manifest;
    manifest.items = {{0x104, 0x122, 0x200024, 0x8082, false},
                      {0x124, 0x122, 0x200044, 0x8082, false}};
    msg::OutcomeLedger ledger(manifest);
    msg::ItemOutcome first;
    first.item = manifest.items[0];
    first.source.attachment_bytes = std::numeric_limits<uint64_t>::max();
    TEST_OK(ledger.accept(0, msg::item_outcome_key(first.item), first),
            "represent partial source bytes");
    auto second = first;
    second.item = manifest.items[1];
    second.source.attachment_bytes = 1;
    TEST_ERROR(ledger.accept(1, msg::item_outcome_key(second.item), second), ErrorKind::kBadField,
               "outcome.overflow", "refuse counter overflow transactionally");
    TEST_EQ(ledger.totals().terminal, 1u, "overflow leaves ledger unchanged");
    TEST_EQ(ledger.items().size(), 1u, "overflow leaves item set unchanged");
    second.status = static_cast<msg::ItemStatus>(99);
    TEST_ERROR(msg::encode_item_outcome(second), ErrorKind::kBadField, "outcome.status",
               "unknown status refused");
}
} // namespace

int main() {
    check_durable_accounting();
    check_overflow_and_status();
    return ost2pst::test::finish("msg_outcome_test");
}
