#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>

#include "ost2pst/writer/publication.h"
#include "ost2pst/writer/staging_journal.h"
#include "ost2pst/writer/staging_manifest.h"

namespace ost2pst::writer {

struct CompletedConversion {
    uint32_t exit_code = 0;
    uint64_t terminal_items = 0;
    bool operator==(const CompletedConversion&) const = default;
};
enum class CleanupPoint { kReceiptReady, kReceiptPublished, kDataReleased, kJournalReleased };
enum class InitializationPoint {
    kDirectoryCreated,
    kFilesCreated,
    kManifestFlushed,
    kJournalCreated,
    kPublicationReserved,
    kWorkspacePublished
};
using InitializationObserver = std::function<void(InitializationPoint)>;

// Owns every handle referenced by its journal; moving the wrapper preserves those addresses.
// Caller must hold a stable source handle and independently verify ConversionIdentity first.
class StagingWorkspace {
  public:
    StagingWorkspace(const StagingWorkspace&) = delete;
    StagingWorkspace& operator=(const StagingWorkspace&) = delete;
    StagingWorkspace(StagingWorkspace&&) noexcept;
    StagingWorkspace& operator=(StagingWorkspace&&) noexcept;
    ~StagingWorkspace();
    static util::Result<StagingWorkspace>
    create(const std::wstring& output, const ConversionIdentity& identity, const RunId& run_id);
    static util::Result<StagingWorkspace> resume(const std::wstring& output,
                                                 const ConversionIdentity& identity);
    // Full mode publishes a completely initialized sibling directory before staging items.
    // Abandoned initialization directories remain untouched. Resume restarts only if .work
    // is absent; an existing malformed workspace is always refused.
    static util::Result<StagingWorkspace> create_ready(const std::wstring& output,
                                                       const ConversionIdentity& identity,
                                                       const RunId& run_id,
                                                       const InitializationObserver& observer = {});
    static util::Result<StagingWorkspace> resume_ready(const std::wstring& output,
                                                       const ConversionIdentity& identity,
                                                       const RunId& fresh_id,
                                                       const InitializationObserver& observer = {});
    StagingJournal& journal();
    const StagingManifest& manifest() const;
    const std::wstring& directory() const;
    // Reserve artifacts before item work. Resume validates publication identity before
    // journal recovery can trim an uncommitted staging suffix.
    util::Status prepare_publication();
    Publication* publication();
    const std::optional<CompletedConversion>& completed() const;
    // Requires complete, validated publication. Receipt is durable before data/journal shrink.
    // Retains manifest, identities and sealed reports for idempotent --resume. No directory
    // deletion.
    util::Status cleanup_completed(const CompletedConversion& result,
                                   const std::function<void(CleanupPoint)>& observer = {});

  private:
    struct Impl;
    explicit StagingWorkspace(std::unique_ptr<Impl> impl);
    static util::Result<StagingWorkspace>
    open(const std::wstring& output, const ConversionIdentity& identity, const RunId* run_id,
         const std::wstring& initialization_directory = {},
         const InitializationObserver& observer = {},
         const StagingManifest* expected_manifest = nullptr, bool require_publication = false);
    std::unique_ptr<Impl> impl_;
};
} // namespace ost2pst::writer
