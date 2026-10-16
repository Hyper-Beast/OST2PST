#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <vector>

#include "ost2pst/writer/staging_journal.h"

#include "test_support.h"

namespace {
using namespace ost2pst::util;
using namespace ost2pst::writer;

class MemoryFile final : public RandomAccessFile {
  public:
    std::vector<uint8_t> bytes, durable;
    std::vector<std::string>* events = nullptr;
    std::string name;
    bool fail_flush = false, fail_resize = false, fail_read = false;
    size_t writes = 0, mutations = 0, fail_write = 0, chunk = 17;
    uint64_t size() const override { return bytes.size(); }
    Status read_at(uint64_t offset, uint8_t* out, size_t count) const override {
        if (fail_read)
            return make_error(ErrorKind::kIo, "injected.read", offset);
        if (offset > size() || count > size() - offset)
            return make_error(ErrorKind::kTruncated, "memory.read", offset);
        if (count)
            std::memcpy(out, bytes.data() + offset, count);
        return {};
    }
    Result<size_t> write_some(uint64_t offset, ByteView input) override {
        ++writes;
        ++mutations;
        if (events)
            events->push_back(name + ".write");
        if (writes == fail_write)
            return make_error(ErrorKind::kIo, "injected.write", offset);
        const size_t count = std::min(chunk, input.size());
        bytes.resize(std::max(bytes.size(), static_cast<size_t>(offset) + count));
        std::copy_n(input.data(), count, bytes.data() + offset);
        return count;
    }
    Status resize(uint64_t length) override {
        ++mutations;
        if (fail_resize)
            return make_error(ErrorKind::kIo, "injected.resize", length);
        bytes.resize(static_cast<size_t>(length));
        return {};
    }
    Status flush() override {
        ++mutations;
        if (events)
            events->push_back(name + ".flush");
        if (fail_flush)
            return make_error(ErrorKind::kIo, "injected.flush", 0);
        durable = bytes;
        return {};
    }
    void crash() { bytes = durable; }
};

Sha256Digest key(uint8_t value) {
    Sha256Digest result{};
    result[0] = value;
    return result;
}

void add(StagingJournal& state, uint8_t id, StagedOutcome outcome,
         const std::vector<uint8_t>& bytes) {
    TEST_OK(state.begin(key(id), outcome), "begin item");
    TEST_OK(state.append(ByteView(bytes.data(), bytes.size())), "append item");
    TEST_OK(state.commit(), "commit item");
}

void check_roundtrip() {
    MemoryFile data, journal;
    auto created = StagingJournal::create(data, journal, key(99));
    TEST_OK(created, "create journal");
    if (!created.ok())
        return;
    auto state = created.take();
    std::vector<uint8_t> payload(150001);
    for (size_t i = 0; i < payload.size(); ++i)
        payload[i] = static_cast<uint8_t>(i * 13);
    add(state, 1, StagedOutcome::kConverted, payload);
    add(state, 2, StagedOutcome::kFailed, {9, 8});
    add(state, 3, StagedOutcome::kExcluded, {});
    TEST_EQ(state.records().size(), 3u, "one terminal record per item");
    const auto saved = journal.bytes;
    TEST_ERROR(state.begin(key(1), StagedOutcome::kConverted), ErrorKind::kBadField,
               "staging.duplicate", "do not count a retry twice");
    TEST_CHECK(journal.bytes == saved);
    data.crash();
    journal.crash();
    auto recovered = StagingJournal::recover(data, journal, key(99));
    TEST_OK(recovered, "recover committed records");
    if (!recovered.ok())
        return;
    auto replay = recovered.take();
    TEST_EQ(replay.records().size(), 3u, "recovery terminal count");
    TEST_EQ(replay.records()[1].offset, payload.size(), "contiguous ranges");
    TEST_EQ(replay.records()[2].length, 0u, "zero-length outcome supported");
    TEST_CHECK(replay.records()[1].outcome == StagedOutcome::kFailed);
    TEST_ERROR(replay.begin(key(2), StagedOutcome::kFailed), ErrorKind::kBadField,
               "staging.duplicate", "replay does not duplicate terminal outcome");
    add(replay, 4, StagedOutcome::kConverted, {42});
    auto next = StagingJournal::recover(data, journal, key(99));
    TEST_OK(next, "resume append survives second recovery");
    if (next.ok())
        TEST_EQ(next.value().records().size(), 4u, "appended record count");
}

void check_flush_order_and_failures() {
    for (int phase = 0; phase < 4; ++phase) {
        MemoryFile data, journal;
        auto created = StagingJournal::create(data, journal, key(9));
        TEST_OK(created, "create fault case");
        if (!created.ok())
            return;
        auto state = created.take();
        TEST_OK(state.begin(key(1), StagedOutcome::kConverted), "begin fault case");
        std::vector<std::string> events;
        data.events = &events;
        data.name = "data";
        journal.events = &events;
        journal.name = "journal";
        const std::array<uint8_t, 3> bytes{1, 2, 3};
        TEST_OK(state.append(ByteView(bytes.data(), bytes.size())), "append before failure");
        if (phase == 1)
            data.fail_flush = true;
        if (phase == 2)
            journal.fail_write = journal.writes + 2;
        if (phase == 3)
            journal.fail_flush = true;
        auto committed = state.commit();
        TEST_CHECK(committed.ok() == (phase == 0));
        TEST_EQ(state.records().size(), phase == 0 ? 1u : 0u, "counts only after successful flush");
        TEST_CHECK(state.poisoned() == (phase != 0));
        TEST_STR(events[0], "data.write", "append first");
        TEST_STR(events[1], "data.flush", "data flush before journal");
        if (phase == 1)
            TEST_EQ(events.size(), 2u, "data failure never writes commit");
        if (phase == 0 || phase == 3)
            TEST_STR(events.back(), "journal.flush", "journal flush last");
        if (phase != 0) {
            TEST_ERROR(state.commit(), ErrorKind::kBadField, "staging.session",
                       "refuse poisoned retry");
            TEST_ERROR(state.begin(key(2), StagedOutcome::kFailed), ErrorKind::kBadField,
                       "staging.session", "refuse poisoned new transaction");
        }
        data.events = nullptr;
        journal.events = nullptr;
        data.fail_flush = journal.fail_flush = false;
        journal.fail_write = 0;
        MemoryFile lost_data = data, lost_journal = journal;
        lost_data.crash();
        lost_journal.crash();
        auto lost = StagingJournal::recover(lost_data, lost_journal, key(9));
        TEST_OK(lost, "recover only flushed bytes");
        if (lost.ok())
            TEST_EQ(lost.value().records().size(), phase == 0 ? 1u : 0u,
                    "failed flush never assumed durable");
        // Even a failed journal flush can leave the full record visible. Recovery decides.
        auto visible = StagingJournal::recover(data, journal, key(9));
        TEST_OK(visible, "recover visible failed-flush state");
        if (visible.ok())
            TEST_EQ(visible.value().records().size(), (phase == 0 || phase == 3) ? 1u : 0u,
                    "visible complete record");
        data.crash();
        journal.crash();
        auto durable = StagingJournal::recover(data, journal, key(9));
        TEST_OK(durable, "recover simulated durable state");
        if (durable.ok())
            TEST_EQ(durable.value().records().size(), (phase == 0 || phase == 3) ? 1u : 0u,
                    "recovery flush makes validated progress durable");
    }
}

void check_torn_tail() {
    MemoryFile data, journal;
    auto created = StagingJournal::create(data, journal, key(9));
    if (!created.ok()) {
        TEST_OK(created, "create tail test");
        return;
    }
    auto state = created.take();
    add(state, 1, StagedOutcome::kConverted, {1, 2, 3});
    const size_t first_end = journal.bytes.size();
    add(state, 2, StagedOutcome::kConverted, {4, 5});
    const size_t record_size = journal.bytes.size() - first_end;
    for (size_t tail = 0; tail < record_size; ++tail) {
        MemoryFile cut_data = data, cut_journal = journal;
        cut_journal.bytes.resize(first_end + tail);
        auto recovered = StagingJournal::recover(cut_data, cut_journal, key(9));
        TEST_OK(recovered, "every short final record recovers prefix");
        if (recovered.ok())
            TEST_EQ(recovered.value().records().size(), 1u, "only complete prefix");
        TEST_EQ(cut_data.bytes.size(), 3u, "discard uncommitted data");
        TEST_EQ(cut_journal.bytes.size(), first_end, "discard torn record");
    }
}

void rehash_record(std::vector<uint8_t>& bytes, size_t offset) {
    Sha256 hash;
    TEST_OK(hash.update(ByteView(bytes.data() + offset, 104)), "hash synthetic record");
    const auto digest = hash.digest();
    std::copy(digest.begin(), digest.end(), bytes.begin() + offset + 104);
}

void check_refusals_preserve_evidence() {
    MemoryFile data, journal;
    auto created = StagingJournal::create(data, journal, key(9));
    if (!created.ok()) {
        TEST_OK(created, "create corrupt test");
        return;
    }
    auto state = created.take();
    add(state, 1, StagedOutcome::kConverted, {1, 2, 3});
    add(state, 2, StagedOutcome::kFailed, {});
    for (int fault = 0; fault < 10; ++fault) {
        MemoryFile bad_data = data, bad_journal = journal;
        Sha256Digest binding = key(9);
        size_t budget = 100;
        if (fault == 0)
            binding = key(8);
        if (fault == 1)
            bad_data.bytes[0] ^= 1;
        if (fault == 2)
            bad_journal.bytes[80] ^= 1;
        if (fault == 3)
            bad_journal.bytes[48] ^= 1;
        if (fault == 4)
            bad_data.bytes.resize(2);
        if (fault == 5)
            budget = 1;
        if (fault == 6)
            bad_data.fail_read = true;
        if (fault >= 7) {
            // Valid checksum cannot hide duplicated keys, discontinuous ranges or bad sequence.
            const size_t second = 80 + 136;
            if (fault == 7)
                bad_journal.bytes[second + 16] = 1;
            if (fault == 8)
                bad_journal.bytes[second + 56] = 1;
            if (fault == 9)
                bad_journal.bytes[second + 8] = 3;
            rehash_record(bad_journal.bytes, second);
        }
        bad_data.bytes.push_back(88);
        bad_journal.bytes.push_back(77);
        const auto before_data = bad_data.bytes, before_journal = bad_journal.bytes;
        bad_data.mutations = bad_journal.mutations = 0;
        auto refused = StagingJournal::recover(bad_data, bad_journal, binding, budget);
        TEST_CHECK(!refused.ok());
        TEST_CHECK(bad_data.bytes == before_data && bad_journal.bytes == before_journal);
        TEST_EQ(bad_data.mutations + bad_journal.mutations, 0u, "refuse before mutation");
    }
    TEST_CHECK(!StagingJournal::create(data, journal, key(9)).ok());
    TEST_CHECK(!StagingJournal::create(data, data, key(9)).ok());
}

void check_session_and_recovery_failures() {
    MemoryFile data, journal;
    auto created = StagingJournal::create(data, journal, key(9), 1);
    TEST_OK(created, "create bounded session");
    if (!created.ok())
        return;
    auto state = created.take();
    auto moved_from = created.take();
    TEST_ERROR(moved_from.begin(key(1), StagedOutcome::kConverted), ErrorKind::kBadField,
               "staging.session", "moved-from session cannot write");
    const uint8_t payload = 42;
    TEST_ERROR(state.append(ByteView(&payload, 1)), ErrorKind::kBadField, "staging.session",
               "append requires transaction");
    TEST_OK(state.begin(key(1), StagedOutcome::kConverted), "begin partial append");
    data.fail_write = 1;
    TEST_ERROR(state.append(ByteView(&payload, 1)), ErrorKind::kIo, "injected.write",
               "append failure propagates");
    TEST_CHECK(state.poisoned());
    TEST_ERROR(state.commit(), ErrorKind::kBadField, "staging.session",
               "cannot commit failed data");
    data.fail_write = 0;
    auto recovered = StagingJournal::recover(data, journal, key(9), 1);
    TEST_OK(recovered, "recover append failure");
    if (!recovered.ok())
        return;
    auto replay = recovered.take();
    add(replay, 1, StagedOutcome::kConverted, {payload});
    TEST_ERROR(replay.begin(key(2), StagedOutcome::kFailed), ErrorKind::kBadField,
               "staging.record_budget", "budget refuses before append");

    for (int fault = 0; fault < 3; ++fault) {
        MemoryFile bad_data = data, bad_journal = journal;
        if (fault == 0) {
            bad_data.bytes.push_back(8);
            bad_data.fail_resize = true;
        }
        if (fault == 1) {
            bad_journal.bytes.push_back(8);
            bad_journal.fail_resize = true;
        }
        if (fault == 2)
            bad_journal.fail_flush = true;
        auto refused = StagingJournal::recover(bad_data, bad_journal, key(9));
        TEST_ERROR(refused, ErrorKind::kIo, fault == 2 ? "injected.flush" : "injected.resize",
                   "recovery mutation failure cannot return usable session");
    }
    for (size_t length = 0; length < 80; ++length) {
        MemoryFile truncated = journal, untouched = data;
        truncated.bytes.resize(length);
        truncated.mutations = untouched.mutations = 0;
        TEST_CHECK(!StagingJournal::recover(untouched, truncated, key(9)).ok());
        TEST_EQ(truncated.mutations + untouched.mutations, 0u,
                "torn header refused without writes");
    }
}

void check_item_rollback_and_bounded_read() {
    MemoryFile data, journal;
    auto created = StagingJournal::create(data, journal, key(9));
    TEST_OK(created, "create isolated item test");
    if (!created.ok())
        return;
    auto state = created.take();
    TEST_ERROR(state.rollback(), ErrorKind::kBadField, "staging.session",
               "cannot roll back without active item");
    add(state, 1, StagedOutcome::kConverted, {11, 22, 33});
    const auto committed_journal = journal.bytes;
    TEST_OK(state.begin(key(2), StagedOutcome::kConverted), "begin corrupt source item");
    const std::array<uint8_t, 4> unfinished{91, 92, 93, 94};
    TEST_OK(state.append(ByteView(unfinished.data(), unfinished.size())), "partial item written");
    uint8_t value = 0;
    TEST_ERROR(state.read_committed(1, 0, &value, 1), ErrorKind::kBadField, "staging.record_index",
               "uncommitted bytes are not readable");
    TEST_OK(state.read_committed(0, 1, &value, 1), "read earlier item while staging");
    TEST_EQ(value, 22u, "record-relative read");
    TEST_OK(state.rollback(), "discard only unfinished item");
    TEST_CHECK((data.bytes == std::vector<uint8_t>{11, 22, 33}));
    TEST_CHECK(data.durable == data.bytes);
    TEST_CHECK(journal.bytes == committed_journal);
    TEST_EQ(state.records().size(), 1u, "rollback creates no terminal outcome");
    // Same source key now records its error; the neighbouring item is still converted.
    add(state, 2, StagedOutcome::kFailed, {7});
    add(state, 3, StagedOutcome::kConverted, {44, 55});
    data.crash();
    journal.crash();
    auto recovered = StagingJournal::recover(data, journal, key(9));
    TEST_OK(recovered, "replay good/failed/good sequence");
    if (!recovered.ok())
        return;
    auto replay = recovered.take();
    TEST_EQ(replay.records().size(), 3u, "one outcome per source item");
    TEST_CHECK(replay.records()[1].outcome == StagedOutcome::kFailed);
    TEST_OK(replay.read_committed(1, 0, &value, 1), "read failure diagnostic");
    TEST_EQ(value, 7u, "failed item contains no abandoned payload");
    TEST_OK(replay.read_committed(2, 1, &value, 1), "read later item");
    TEST_EQ(value, 55u, "later item intact");
    TEST_OK(replay.read_committed(0, 3, nullptr, 0), "zero-byte read at record end");
    TEST_ERROR(replay.read_committed(0, 3, &value, 1), ErrorKind::kBadField, "staging.read_range",
               "cannot cross into next record");
    TEST_ERROR(replay.read_committed(0, UINT64_MAX, &value, 1), ErrorKind::kBadField,
               "staging.read_range", "offset cannot wrap");
    TEST_ERROR(replay.read_committed(0, 0, &value, SIZE_MAX), ErrorKind::kBadField,
               "staging.read_range", "count cannot wrap");
    TEST_ERROR(replay.read_committed(0, 0, nullptr, 1), ErrorKind::kBadField, "staging.read_buffer",
               "nonempty read needs a buffer");
    data.fail_read = true;
    TEST_ERROR(replay.read_committed(0, 0, &value, 1), ErrorKind::kIo, "injected.read",
               "assembly read failure propagates");
}

void check_rollback_io_failures() {
    for (int fault = 0; fault < 3; ++fault) {
        MemoryFile data, journal;
        auto created = StagingJournal::create(data, journal, key(9));
        TEST_OK(created, "create rollback fault test");
        if (!created.ok())
            return;
        auto state = created.take();
        add(state, 1, StagedOutcome::kConverted, {1});
        TEST_OK(state.begin(key(2), StagedOutcome::kConverted), "begin rollback fault item");
        const uint8_t value = 2;
        TEST_OK(state.append(ByteView(&value, 1)), "append before rollback fault");
        if (fault == 0)
            data.fail_resize = true;
        if (fault == 1)
            data.fail_flush = true;
        if (fault == 2) {
            journal.fail_flush = true;
            TEST_ERROR(state.commit(), ErrorKind::kIo, "injected.flush", "commit may be visible");
        }
        const auto saved_journal = journal.bytes;
        const auto saved_data = data.bytes;
        auto rolled_back = state.rollback();
        TEST_ERROR(rolled_back, fault == 2 ? ErrorKind::kBadField : ErrorKind::kIo,
                   fault == 0   ? "injected.resize"
                   : fault == 1 ? "injected.flush"
                                : "staging.session",
                   "failed mutation cannot resume item isolation");
        TEST_CHECK(state.poisoned());
        TEST_EQ(state.records().size(), 1u, "failure never advances progress");
        TEST_CHECK(journal.bytes == saved_journal);
        if (fault == 2)
            TEST_CHECK(data.bytes == saved_data); // Do not erase a possibly committed range.
        TEST_ERROR(state.begin(key(3), StagedOutcome::kConverted), ErrorKind::kBadField,
                   "staging.session", "I/O failure is fatal, not item-local");
        data.fail_flush = data.fail_resize = journal.fail_flush = false;
        auto recovered = StagingJournal::recover(data, journal, key(9));
        TEST_OK(recovered, "recovery resolves failed rollback/commit");
        if (recovered.ok())
            TEST_EQ(recovered.value().records().size(), fault == 2 ? 2u : 1u,
                    "visible complete commit survives refused rollback");
    }
}
} // namespace

int main() {
    check_roundtrip();
    check_flush_order_and_failures();
    check_torn_tail();
    check_refusals_preserve_evidence();
    check_session_and_recovery_failures();
    check_item_rollback_and_bounded_read();
    check_rollback_io_failures();
    return ost2pst::test::finish("writer_staging_journal_test");
}
