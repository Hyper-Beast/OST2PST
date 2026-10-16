#include "ost2pst/writer/staging_journal.h"

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

namespace ost2pst::writer {
namespace {
using namespace util;
// Private format v1, defined in M6 research/staging-journal-format.md (not PST constants).
constexpr size_t kHeaderSize = 80;
constexpr size_t kRecordSize = 136;
constexpr std::array<uint8_t, 8> kHeaderMagic{'O', '2', 'P', 'J', 'N', 'L', '0', '1'};
constexpr std::array<uint8_t, 8> kRecordMagic{'O', '2', 'P', 'C', 'M', 'T', '0', '1'};

DataError invalid(const char* field, uint64_t offset = 0, uint64_t value = 0) {
    return make_error(ErrorKind::kBadField, field, offset, value, "invalid staging state");
}

void put(uint8_t* out, uint64_t value, size_t count) {
    for (size_t i = 0; i < count; ++i)
        out[i] = static_cast<uint8_t>(value >> (8 * i));
}

Sha256Digest hash(ByteView bytes) {
    Sha256 digest;
    // All callers pass bounded non-null private-format arrays.
    digest.update(bytes);
    return digest.digest();
}

bool matches(const Sha256Digest& digest, const uint8_t* bytes) {
    return std::equal(digest.begin(), digest.end(), bytes);
}

bool valid_outcome(uint32_t value) {
    return value >= 1 && value <= 3;
}

Result<Sha256Digest> hash_range(const RandomAccessFile& file, uint64_t offset, uint64_t length) {
    if (offset > file.size() || length > file.size() - offset)
        return invalid("staging.data_range", offset, length);
    std::array<uint8_t, 65536> buffer{};
    Sha256 digest;
    for (uint64_t done = 0; done < length;) {
        const auto count = static_cast<size_t>(std::min<uint64_t>(buffer.size(), length - done));
        auto read = file.read_at(offset + done, buffer.data(), count);
        if (!read.ok())
            return read.error();
        auto updated = digest.update(ByteView(buffer.data(), count));
        if (!updated.ok())
            return updated.error();
        done += count;
    }
    return digest.digest();
}
} // namespace

StagingJournal::StagingJournal(StagingJournal&& other) noexcept
    : data_(other.data_), journal_(other.journal_), budget_(other.budget_),
      committed_end_(other.committed_end_), active_(other.active_), poisoned_(other.poisoned_),
      pending_(other.pending_), pending_hash_(other.pending_hash_),
      records_(std::move(other.records_)), keys_(std::move(other.keys_)) {
    other.poisoned_ = true;
    other.active_ = false;
}

util::Result<StagingJournal> StagingJournal::create(RandomAccessFile& data,
                                                    RandomAccessFile& journal,
                                                    const Sha256Digest& binding, size_t budget) {
    if (&data == &journal || data.size() != 0 || journal.size() != 0 || budget == 0)
        return invalid("staging.create");
    std::array<uint8_t, kHeaderSize> header{};
    std::copy(kHeaderMagic.begin(), kHeaderMagic.end(), header.begin());
    put(header.data() + 8, 1, 4);
    std::copy(binding.begin(), binding.end(), header.begin() + 16);
    const auto digest = hash(ByteView(header.data(), 48));
    std::copy(digest.begin(), digest.end(), header.begin() + 48);
    auto flushed = data.flush();
    if (!flushed.ok())
        return flushed.error();
    auto written = write_all(journal, 0, ByteView(header.data(), header.size()));
    if (!written.ok())
        return written.error();
    flushed = journal.flush();
    if (!flushed.ok())
        return flushed.error();
    return StagingJournal(data, journal, budget);
}

util::Result<StagingJournal> StagingJournal::recover(RandomAccessFile& data,
                                                     RandomAccessFile& journal,
                                                     const Sha256Digest& binding, size_t budget) {
    if (&data == &journal || budget == 0)
        return invalid("staging.files");
    std::array<uint8_t, kHeaderSize> header{};
    auto read = journal.read_at(0, header.data(), header.size());
    if (!read.ok())
        return read.error();
    ByteView h(header.data(), header.size());
    if (!std::equal(kHeaderMagic.begin(), kHeaderMagic.end(), header.begin()) ||
        h.u32(8).value() != 1 || h.u32(12).value() != 0)
        return invalid("staging.header");
    if (!matches(hash(ByteView(header.data(), 48)), header.data() + 48))
        return make_error(ErrorKind::kBadCrc, "staging.header_hash", 0);
    if (!matches(binding, header.data() + 16))
        return invalid("staging.binding", 16);

    StagingJournal state(data, journal, budget);
    const uint64_t count = (journal.size() - kHeaderSize) / kRecordSize;
    if (count > budget)
        return invalid("staging.record_budget", kHeaderSize, count);
    for (uint64_t index = 0; index < count; ++index) {
        const uint64_t at = kHeaderSize + index * kRecordSize;
        std::array<uint8_t, kRecordSize> record{};
        read = journal.read_at(at, record.data(), record.size());
        if (!read.ok())
            return read.error();
        if (!matches(hash(ByteView(record.data(), 104)), record.data() + 104))
            return make_error(ErrorKind::kBadCrc, "staging.record_hash", at);
        ByteView r(record.data(), record.size(), at);
        if (!std::equal(kRecordMagic.begin(), kRecordMagic.end(), record.begin()) ||
            r.u64(8).value() != index + 1 || r.u32(52).value() != 0 ||
            !valid_outcome(r.u32(48).value()))
            return invalid("staging.record", at);
        StagedRecord decoded;
        std::copy_n(record.data() + 16, 32, decoded.key.begin());
        decoded.outcome = static_cast<StagedOutcome>(r.u32(48).value());
        decoded.offset = r.u64(56).value();
        decoded.length = r.u64(64).value();
        std::copy_n(record.data() + 72, 32, decoded.digest.begin());
        if (!state.keys_.insert(decoded.key).second)
            return invalid("staging.duplicate", at);
        if (decoded.offset != state.committed_end_)
            return invalid("staging.contiguity", at);
        auto payload = hash_range(data, decoded.offset, decoded.length);
        if (!payload.ok())
            return payload.error();
        if (payload.value() != decoded.digest)
            return make_error(ErrorKind::kBadCrc, "staging.data_hash", decoded.offset);
        state.committed_end_ += decoded.length;
        state.records_.push_back(decoded);
    }
    // No mutation above this point: mismatch/corruption cannot destroy recovery evidence.
    if (data.size() != state.committed_end_) {
        auto resized = data.resize(state.committed_end_);
        if (!resized.ok())
            return resized.error();
        auto flushed = data.flush();
        if (!flushed.ok())
            return flushed.error();
    }
    const uint64_t end = kHeaderSize + count * kRecordSize;
    if (journal.size() != end) {
        auto resized = journal.resize(end);
        if (!resized.ok())
            return resized.error();
    }
    // A complete record can be visible after the previous process's flush failed. Establish
    // durability now before exposing it as committed progress in the recovered session.
    auto flushed = journal.flush();
    if (!flushed.ok())
        return flushed.error();
    return state;
}

util::Status StagingJournal::io_result(Status status) {
    if (!status.ok())
        poisoned_ = true;
    return status;
}

util::Status StagingJournal::begin(const Sha256Digest& key, StagedOutcome outcome) {
    if (poisoned_ || active_)
        return invalid("staging.session");
    if (!valid_outcome(static_cast<uint32_t>(outcome)))
        return invalid("staging.outcome");
    if (keys_.contains(key))
        return invalid("staging.duplicate");
    if (records_.size() >= budget_)
        return invalid("staging.record_budget");
    pending_ = StagedRecord{key, outcome, committed_end_, 0, {}};
    pending_hash_ = Sha256{};
    active_ = true;
    return {};
}

util::Status StagingJournal::append(ByteView bytes) {
    if (poisoned_ || !active_)
        return invalid("staging.session");
    // Validate hash length and null buffers before touching the data stream.
    auto next = pending_hash_;
    auto updated = next.update(bytes);
    if (!updated.ok())
        return updated;
    if (bytes.size() > static_cast<uint64_t>(INT64_MAX) - committed_end_ - pending_.length)
        return invalid("staging.data_range", committed_end_, bytes.size());
    auto written = write_all(data_, committed_end_ + pending_.length, bytes);
    if (!written.ok())
        return io_result(written);
    pending_.length += bytes.size();
    pending_hash_ = next;
    return {};
}

util::Status StagingJournal::commit(const CommitObserver& observer) {
    if (poisoned_ || !active_)
        return invalid("staging.session");
    if (observer)
        observer(CommitPoint::kBeforeDataFlush);
    auto flushed = data_.flush();
    if (!flushed.ok())
        return io_result(flushed);
    if (observer)
        observer(CommitPoint::kDataFlushed);
    pending_.digest = pending_hash_.digest();
    std::array<uint8_t, kRecordSize> record{};
    std::copy(kRecordMagic.begin(), kRecordMagic.end(), record.begin());
    put(record.data() + 8, records_.size() + 1, 8);
    std::copy(pending_.key.begin(), pending_.key.end(), record.begin() + 16);
    put(record.data() + 48, static_cast<uint32_t>(pending_.outcome), 4);
    put(record.data() + 56, pending_.offset, 8);
    put(record.data() + 64, pending_.length, 8);
    std::copy(pending_.digest.begin(), pending_.digest.end(), record.begin() + 72);
    const auto digest = hash(ByteView(record.data(), 104));
    std::copy(digest.begin(), digest.end(), record.begin() + 104);
    const uint64_t at = kHeaderSize + static_cast<uint64_t>(records_.size()) * kRecordSize;
    auto written = write_all(journal_, at, ByteView(record.data(), record.size()));
    if (!written.ok())
        return io_result(written);
    if (observer)
        observer(CommitPoint::kJournalWritten);
    flushed = journal_.flush();
    if (!flushed.ok())
        return io_result(flushed);
    if (observer)
        observer(CommitPoint::kJournalFlushed);
    committed_end_ += pending_.length;
    keys_.insert(pending_.key);
    records_.push_back(pending_);
    active_ = false;
    return {};
}

util::Status StagingJournal::rollback() {
    if (poisoned_ || !active_)
        return invalid("staging.session");
    auto resized = data_.resize(committed_end_);
    if (!resized.ok())
        return io_result(resized);
    auto flushed = data_.flush();
    if (!flushed.ok())
        return io_result(flushed);
    // No journal record exists for this attempt. Its key remains available for the terminal
    // failure record (or a retry), and durable progress still refers only to committed items.
    pending_ = {};
    pending_hash_ = Sha256{};
    active_ = false;
    return {};
}

util::Status StagingJournal::read_committed(size_t record, uint64_t offset, uint8_t* data,
                                            size_t count) const {
    if (poisoned_)
        return invalid("staging.session");
    if (record >= records_.size())
        return invalid("staging.record_index", 0, record);
    const auto& range = records_[record];
    if (offset > range.length || count > range.length - offset)
        return invalid("staging.read_range", range.offset, offset);
    if (count != 0 && data == nullptr)
        return invalid("staging.read_buffer", range.offset + offset);
    return data_.read_at(range.offset + offset, data, count);
}

} // namespace ost2pst::writer
