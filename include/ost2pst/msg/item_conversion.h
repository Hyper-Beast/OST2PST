#pragma once

#include <optional>
#include <string>
#include <vector>

#include "ost2pst/msg/outcome.h"

namespace ost2pst::msg {

enum class ItemObjectKind { kMessage, kAttachment, kRecipient };
struct ItemObjectScope {
    ItemObjectKind kind = ItemObjectKind::kMessage;
    std::vector<uint32_t> ancestry; // top-level source NID, then local ownership identifiers
};
struct ItemFinding {
    std::string code;
    uint64_t count = 0;
};
struct ItemDiagnostic {
    std::vector<uint32_t> ancestry;
    std::string stage;
    std::string detail;
};
struct PreparedItem {
    ItemOutcome outcome;
    writer::ContentPlan content;
    std::optional<writer::TcRow> row;
    std::vector<ItemObjectScope> objects;
    std::vector<ItemFinding> findings;
    std::vector<ItemDiagnostic> diagnostics;
};

// One transaction, without persistence. Source block I/O failure and writer/registry
// invariants return fatal typed errors. A partial item becomes an explicit terminal skip.
// With options.spool, large values retain owned scratch ranges through durable staging.
util::Result<PreparedItem> prepare_item(const ltp::LtpReadReport& census, ltp::BlockSource& blocks,
                                        const MailboxItem& item, const EmitRegistry& registry,
                                        const SubsetOptions& options = {});

} // namespace ost2pst::msg
