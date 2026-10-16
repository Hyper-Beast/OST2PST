#pragma once

#include <array>
#include <string>

#include "ost2pst/util/file_writer.h"
#include "ost2pst/util/sha256.h"
#include "ost2pst/writer/staging_manifest.h"

namespace ost2pst::writer {

enum class PublicationArtifact : size_t { kPst = 0, kSummary = 1, kItems = 2 };
enum class PublicationPhase { kBuilding, kReady, kComplete };

// Owns three reserved artifacts, including their original file identities after rename.
// Private publication v2: research/publication-state-format.md. The caller must hold
// StagingWorkspace ownership and the pinned output/work parents throughout its lifetime.
class Publication {
  public:
    Publication(const Publication&) = delete;
    Publication& operator=(const Publication&) = delete;
    Publication(Publication&&) noexcept = default;
    Publication& operator=(Publication&&) noexcept = default;
    static util::Result<Publication> create(const std::wstring& output,
                                            const util::Sha256Digest& manifest_binding,
                                            const std::wstring& initialization_directory = {});
    // Read-only validation; the workspace validates the journal before discarding any tail.
    static util::Result<Publication> recover(const std::wstring& output,
                                             const util::Sha256Digest& manifest_binding);
    util::RandomAccessFile& file(PublicationArtifact artifact);
    const std::wstring& path(PublicationArtifact artifact) const;
    PublicationPhase phase() const { return phase_; }
    const std::array<bool, 3>& published() const { return published_; }
    // Allows the independent reader to open the reserved candidate; reopen verifies its identity.
    util::Status close_candidate();
    util::Status reopen_candidate();
    // Caller completes internal verification and source-stability checks before sealing.
    util::Status mark_ready();
    util::Status publish_one(PublicationArtifact artifact);
    util::Status finish();
    util::Status discard_torn_tail();

  private:
    Publication() = default;
    util::Status validate_file(size_t index, bool check_hash);
    util::Status mutating(util::Status status);
    util::FileWriter marker_;
    std::array<util::FileWriter, 3> files_;
    std::array<std::wstring, 3> origins_, destinations_;
    std::array<OwnedFileIdentity, 4> identities_{}; // marker, PST, summary, item ledger
    std::array<uint64_t, 3> sizes_{};
    std::array<util::Sha256Digest, 3> hashes_{};
    util::Sha256Digest header_digest_{}, ready_digest_{};
    PublicationPhase phase_ = PublicationPhase::kBuilding;
    std::array<bool, 3> published_{};
    bool poisoned_ = false;
    uint64_t committed_marker_length_ = 144;
};

} // namespace ost2pst::writer
