#pragma once

#include <string>

#include "ost2pst/writer/staging_workspace.h"

namespace ost2pst::cli {
// On-demand index accounting ceiling for 100 GiB-class stores, not an upfront allocation.
// Includes BBT hash/sorted-copy slack and NBT graph bookkeeping.
inline constexpr uint64_t kFullIndexWorkspaceBudget = 8ull * 1024 * 1024 * 1024;
enum class FullPoint {
    kItemPrepared,
    kItemCommitted,
    kFolderCommitted,
    kScaffoldCommitted,
    kAssemblyBegin,
    kAssembled,
    kVerificationOpen,
    kVerified,
    kReportsWritten,
    kReady,
    kPstPublished,
    kSummaryPublished,
    kItemsPublished,
    kComplete
};
// Explicit in-process seams for deterministic crash/I/O tests. No CLI flags or environment hooks.
struct FullConversionHooks {
    uint64_t index_workspace_budget = kFullIndexWorkspaceBudget;
    writer::InitializationObserver initialization;
    writer::CommitObserver commit;
    std::function<void(FullPoint)> phase;
    std::function<void(writer::CleanupPoint)> cleanup;
    std::function<util::Status(uint64_t, util::ByteView)> before_candidate_write;
};
int run_full(const std::wstring& input, const std::wstring& output, bool resume,
             const FullConversionHooks& hooks = {}, bool events_json = false);
} // namespace ost2pst::cli
