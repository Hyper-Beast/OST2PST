#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

#include "ost2pst/writer/staging_journal.h"
#include "ost2pst/writer/store.h"
#include "ost2pst/writer/tc.h"

namespace ost2pst::writer {

// Application-owned counters and an already encoded JSON object accompany a durable outcome.
// They contain identities/diagnostics, not message bodies. Only committed records are replayed.
struct StagedDetails {
    std::optional<TcRow> row;
    std::map<std::string, uint64_t> counters;
    std::string json;
};

struct StagedBlockRef {
    size_t record = 0;
    uint64_t offset = 0; // relative to this committed journal record
    uint16_t size = 0;
};

struct StagedPlan {
    std::vector<StagedBlockRef> blocks;
    std::vector<StoreNode> nodes; // local block numbers; assembler relocates them
    std::vector<uint32_t> rgnid;
    StagedDetails details;
};

// Private encoded-plan v1, described in the M6 task's research/staged-plan-format.md.
// Validation precedes begin(); successful return means the complete outcome is durable.
util::Status stage_plan(StagingJournal& journal, const util::Sha256Digest& key,
                        StagedOutcome outcome, const StorePlan& plan, const StagedDetails& details,
                        const CommitObserver& observer = {});
util::Result<StagedPlan> read_staged_plan(const StagingJournal& journal, size_t record);

class StagedRows final : public TcRowSource {
  public:
    StagedRows(const StagingJournal& journal, std::vector<size_t> records)
        : journal_(journal), records_(std::move(records)) {}
    uint64_t count() const override { return records_.size(); }
    util::Result<TcRow> read(uint64_t index) const override;

  private:
    const StagingJournal& journal_;
    std::vector<size_t> records_;
};

struct StagedAssemblyOptions {
    // Fixed-size lookup budget, not a format limit. Zero preserves unshared assembly.
    // After filling the index, new contents remain unshared; existing entries stay usable.
    uint32_t sharing_entries = 524288;
};

struct StagedAssemblyStats {
    uint64_t block_references = 0;
    uint64_t stored_blocks = 0;
    uint64_t shared_references = 0;
    uint64_t avoided_payload_bytes = 0;
    uint64_t index_entries = 0;
    bool index_saturated = false;
};

// Reloads compact descriptors, never the complete staged payload. The journal owns and pins
// its files for the duration. Exactly one committed scaffold supplies HEADER.rgnid.
// Sharing checks bytes after a fingerprint match and caps each physical block's references.
// Stats are published only after successful assembly. M4/M5 write_store is unchanged.
util::Result<StoreImage> assemble_staged(const StagingJournal& journal,
                                         util::RandomAccessFile& output,
                                         const StagedAssemblyOptions& options = {},
                                         StagedAssemblyStats* stats = nullptr);

} // namespace ost2pst::writer
