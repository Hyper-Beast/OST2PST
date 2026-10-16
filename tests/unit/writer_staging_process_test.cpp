#include <array>
#include <chrono>
#include <filesystem>
#include <string>

#include "ost2pst/writer/staging_journal.h"

#include "test_support.h"
#include "windows_process.h"

#ifdef _WIN32
#include <windows.h>
#endif

namespace {
using namespace ost2pst::util;
using namespace ost2pst::writer;
#ifdef _WIN32
Sha256Digest key(uint8_t value) {
    Sha256Digest digest{};
    digest[0] = value;
    return digest;
}

[[noreturn]] void crash_now() {
    TerminateProcess(GetCurrentProcess(), 77);
    std::abort();
}

class CrashFile final : public RandomAccessFile {
  public:
    explicit CrashFile(FileWriter& file) : file_(file) {}
    int fault = -1;
    uint64_t size() const override { return file_.size(); }
    Status read_at(uint64_t at, uint8_t* data, size_t count) const override {
        return file_.read_at(at, data, count);
    }
    Result<size_t> write_some(uint64_t at, ByteView bytes) override {
        if (fault == 2) {
            auto wrote = file_.write_some(at, ByteView(bytes.data(), 19));
            if (wrote.ok())
                crash_now();
            return wrote;
        }
        auto wrote = file_.write_some(at, bytes);
        if (fault == 3 && wrote.ok())
            crash_now();
        return wrote;
    }
    Status resize(uint64_t size) override {
        auto resized = file_.resize(size);
        if (fault == 4 && resized.ok())
            crash_now();
        return resized;
    }
    Status flush() override {
        auto flushed = file_.flush();
        if (fault == 1 && flushed.ok())
            crash_now();
        return flushed;
    }

  private:
    FileWriter& file_;
};

int child(const std::filesystem::path& directory, int phase) {
    auto lock = FileWriter::acquire_lock((directory / "run.lock").wstring());
    auto data_result = FileWriter::create_new((directory / "data.bin").wstring());
    auto journal_result = FileWriter::create_new((directory / "journal.bin").wstring());
    if (!lock.ok() || !data_result.ok() || !journal_result.ok())
        return 20;
    auto data_file = data_result.take(), journal_file = journal_result.take();
    CrashFile data(data_file), journal(journal_file);
    auto created = StagingJournal::create(data, journal, key(99));
    if (!created.ok())
        return 21;
    auto state = created.take();
    const std::array<uint8_t, 3> payload{11, 22, 33};
    if (!state.begin(key(1), StagedOutcome::kConverted).ok() ||
        !state.append(ByteView(payload.data(), payload.size())).ok() || !state.commit().ok())
        return 22;
    if (!state.begin(key(2), StagedOutcome::kConverted).ok() ||
        !state.append(ByteView(payload.data(), payload.size())).ok())
        return 23;
    if (phase == 0)
        crash_now();
    if (phase >= 5) {
        if (phase == 5)
            data.fault = 4;
        if (phase == 6)
            data.fault = 1;
        if (!state.rollback().ok())
            return 25;
        if (phase == 7)
            crash_now();
        if (!state.begin(key(2), StagedOutcome::kFailed).ok() || !state.commit().ok())
            return 26;
        crash_now();
    }
    if (phase == 1)
        data.fault = 1;
    if (phase == 2 || phase == 3)
        journal.fault = phase;
    if (!state.commit().ok())
        return 24;
    crash_now();
}

DWORD launch(const std::filesystem::path& directory, int phase) {
    return ost2pst::test::run_self({L"--crash", directory.wstring(), std::to_wstring(phase)});
}

void check_process_crashes() {
    const auto stem = "ost2pst_crash_" +
                      std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    for (int phase = 0; phase < 9; ++phase) {
        const auto directory =
            std::filesystem::temp_directory_path() / (stem + "_" + std::to_string(phase));
        TEST_CHECK(std::filesystem::create_directory(directory));
        TEST_EQ(launch(directory, phase), 77u, "child terminates without destructors");
        {
            auto lock = FileWriter::acquire_lock((directory / "run.lock").wstring());
            TEST_OK(lock, "crashed process releases ownership");
            auto data_result = FileWriter::open_existing((directory / "data.bin").wstring());
            auto journal_result = FileWriter::open_existing((directory / "journal.bin").wstring());
            TEST_OK(data_result, "open surviving data");
            TEST_OK(journal_result, "open surviving journal");
            if (!lock.ok() || !data_result.ok() || !journal_result.ok())
                continue;
            auto data = data_result.take(), journal = journal_result.take();
            auto recovered = StagingJournal::recover(data, journal, key(99));
            TEST_OK(recovered, "recover after actual process termination");
            if (!recovered.ok())
                continue;
            auto state = recovered.take();
            const size_t expected = phase == 3 || phase == 4 || phase == 8 ? 2 : 1;
            TEST_EQ(state.records().size(), expected, "only complete validated commits survive");
            TEST_EQ(data.size(), phase == 3 || phase == 4 ? 6u : 3u,
                    "uncommitted payload discarded, failure outcome carries no payload");
            if (phase == 8)
                TEST_CHECK(state.records()[1].outcome == StagedOutcome::kFailed);
            TEST_OK(state.begin(key(3), StagedOutcome::kFailed), "resume another item");
            TEST_OK(state.commit(), "durable failure outcome after crash");
            auto replay = StagingJournal::recover(data, journal, key(99));
            TEST_OK(replay, "second recovery");
            if (replay.ok())
                TEST_EQ(replay.value().records().size(), expected + 1,
                        "no lost or duplicate outcome on replay");
        }
        // Delete only the three known files in this unique test-created directory.
        for (const auto* name : {"data.bin", "journal.bin", "run.lock"}) {
            std::error_code error;
            TEST_CHECK(std::filesystem::remove(directory / name, error));
            TEST_CHECK(!error);
        }
        TEST_CHECK(std::filesystem::remove(directory));
    }
}
#endif
} // namespace

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
    if (argc == 4 && std::wstring(argv[1]) == L"--crash")
        return child(argv[2], std::stoi(argv[3]));
    check_process_crashes();
#else
int main() {
#endif
    return ost2pst::test::finish("writer_staging_process_test");
}
