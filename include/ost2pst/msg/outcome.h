#pragma once

#include <map>

#include "ost2pst/msg/mailbox.h"
#include "ost2pst/writer/staged_plan.h"

namespace ost2pst::msg {

// Private application metadata v1, independent of the PST format and journal framing.
enum class ItemStatus : uint64_t {
    kConverted = 1,
    kSkippedCorrupt = 2,
    kSkippedUnsupported = 3,
    kFailed = 4
};
const char* item_status_name(ItemStatus status);

struct ItemPopulation {
    uint64_t embedded = 0;
    uint64_t recipients = 0;
    uint64_t attachments = 0;
    uint64_t opaque_objects = 0;
    uint64_t attachment_bytes = 0;
    bool operator==(const ItemPopulation&) const = default;
};

struct ItemOutcome {
    MailboxItem item;
    ItemStatus status = ItemStatus::kFailed;
    // Partial extraction can establish some counts without enumerating every descendant.
    // Keep that uncertainty explicit; known counts are never promoted to a complete census.
    bool source_complete = false;
    ItemPopulation source;
    ItemPopulation committed;
    uint64_t source_gaps = 0;
    bool read_state_known = false;
    bool unread = false;
};

util::Sha256Digest item_outcome_key(const MailboxItem& item);
util::Result<writer::StagedDetails> encode_item_outcome(const ItemOutcome& outcome,
                                                        const writer::TcRow* row = nullptr);
util::Result<ItemOutcome> decode_item_outcome(const writer::StagedPlan& plan,
                                              writer::StagedOutcome framing);

struct OutcomeTotals {
    uint64_t terminal = 0;
    uint64_t converted_normal = 0;
    uint64_t converted_associated = 0;
    uint64_t skipped_corrupt = 0;
    uint64_t skipped_unsupported = 0;
    uint64_t failed = 0;
    uint64_t unknown_source = 0;
    uint64_t unknown_read_state = 0;
    uint64_t unread_normal = 0;
    uint64_t source_gaps = 0;
    ItemPopulation source;
    ItemPopulation committed;
};

struct CommittedItem {
    size_t record = 0;
    ItemOutcome outcome;
};

// Apply only after a successful durable commit or validated recovery. Duplicate terminal
// outcomes are refused rather than added twice. Invocation attempts do not enter this ledger.
class OutcomeLedger {
  public:
    explicit OutcomeLedger(const MailboxManifest& manifest);
    util::Status accept(size_t record, const util::Sha256Digest& key, const ItemOutcome& outcome);
    const std::map<uint32_t, CommittedItem>& items() const { return items_; }
    const OutcomeTotals& totals() const { return totals_; }

  private:
    std::map<uint32_t, MailboxItem> expected_;
    std::map<uint32_t, CommittedItem> items_;
    OutcomeTotals totals_;
};

// This structure is deliberately not serialized. Replaying a committed outcome cannot
// increase the amount of work performed during the current invocation.
struct InvocationAttempts {
    uint64_t normal = 0;
    uint64_t associated = 0;
};

} // namespace ost2pst::msg
