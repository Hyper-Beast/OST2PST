#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <set>
#include <vector>

#include "ost2pst/util/file_writer.h"
#include "ost2pst/util/sha256.h"

namespace ost2pst::writer {

enum class StagedOutcome : uint32_t { kConverted = 1, kFailed = 2, kExcluded = 3 };
enum class CommitPoint { kBeforeDataFlush, kDataFlushed, kJournalWritten, kJournalFlushed };
using CommitObserver = std::function<void(CommitPoint)>;

struct StagedRecord {
    util::Sha256Digest key{};
    StagedOutcome outcome = StagedOutcome::kFailed;
    uint64_t offset = 0;
    uint64_t length = 0;
    util::Sha256Digest digest{};
};

// Private journal v1; contract/layout: M6 research/staging-journal-format.md.
// Files must outlive this session and remain exclusively owned by the caller.
// Any mutating I/O failure requires closing/reopening the files and recovery.
class StagingJournal {
  public:
    StagingJournal(const StagingJournal&) = delete;
    StagingJournal& operator=(const StagingJournal&) = delete;
    StagingJournal(StagingJournal&& other) noexcept;
    StagingJournal& operator=(StagingJournal&&) = delete;

    static util::Result<StagingJournal> create(util::RandomAccessFile& data,
                                               util::RandomAccessFile& journal,
                                               const util::Sha256Digest& manifest_binding,
                                               size_t record_budget = 100000);
    static util::Result<StagingJournal> recover(util::RandomAccessFile& data,
                                                util::RandomAccessFile& journal,
                                                const util::Sha256Digest& manifest_binding,
                                                size_t record_budget = 100000);

    util::Status begin(const util::Sha256Digest& key, StagedOutcome outcome);
    util::Status append(util::ByteView bytes);
    util::Status commit(const CommitObserver& observer = {});
    // Item-local failure only: discard its uncommitted bytes before recording a failure outcome.
    // A poisoned session cannot roll back; close/recover it instead.
    util::Status rollback();
    // Bounded assembly/report access; cannot read an unfinished transaction or a neighbouring item.
    util::Status read_committed(size_t record, uint64_t offset, uint8_t* data, size_t count) const;
    const std::vector<StagedRecord>& records() const { return records_; }
    bool poisoned() const { return poisoned_; }

  private:
    StagingJournal(util::RandomAccessFile& data, util::RandomAccessFile& journal, size_t budget)
        : data_(data), journal_(journal), budget_(budget) {}
    util::Status io_result(util::Status status);
    util::RandomAccessFile& data_;
    util::RandomAccessFile& journal_;
    size_t budget_;
    uint64_t committed_end_ = 0;
    bool active_ = false;
    bool poisoned_ = false;
    StagedRecord pending_;
    util::Sha256 pending_hash_;
    std::vector<StagedRecord> records_;
    std::set<util::Sha256Digest> keys_;
};

} // namespace ost2pst::writer
