#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <vector>

#include "ost2pst/writer/staging_workspace.h"

#include "test_support.h"
#include "windows_process.h"

namespace {
using namespace ost2pst::util;
using namespace ost2pst::writer;

ConversionIdentity identity() {
    ConversionIdentity value;
    value.source_sha256[0] = 11;
    value.source_size = 123;
    value.source_profile = 36;
    value.converter_sha256[0] = 22;
    value.options = {{"search", "exclude"}};
    return value;
}
const std::array<std::vector<uint8_t>, 3> kPayloads{
    {{1, 2, 3, 4, 5}, {'{', '}', '\n'}, {'{', '}', '\n', '{', '}', '\n'}}};
void write_bytes(const std::filesystem::path& path, const std::vector<uint8_t>& bytes) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    TEST_CHECK(file.good());
}
std::vector<uint8_t> read_bytes(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    TEST_CHECK(file.good());
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}
struct Fixture {
    std::filesystem::path root, output, work;
    Fixture() {
        root = std::filesystem::temp_directory_path() /
               ("ost2pst-publication-" +
                std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        TEST_CHECK(std::filesystem::create_directory(root));
        output = root / L"mail \u90ae.pst";
        work = output.wstring() + L".work";
    }
    ~Fixture() {
        std::error_code ignored;
        // Only known fixture directories and files; never recursively remove unknown contents.
        if (std::filesystem::is_directory(root, ignored))
            for (const auto& entry : std::filesystem::directory_iterator(root)) {
                if (!entry.path().filename().wstring().starts_with(output.filename().wstring() +
                                                                   L".work.init-"))
                    continue;
                for (const auto* name :
                     {L"manifest.bin", L"run.lock", L"data.bin", L"journal.bin", L"publication.bin",
                      L"candidate.tmp", L"summary.tmp", L"items.tmp", L"foreign.txt"})
                    std::filesystem::remove(entry.path() / name, ignored);
                std::filesystem::remove(entry.path(), ignored);
            }
        for (const auto* name :
             {L"manifest.bin", L"run.lock", L"data.bin", L"journal.bin", L"publication.bin",
              L"completion.bin", L"candidate.tmp", L"summary.tmp", L"items.tmp", L"foreign.txt"})
            std::filesystem::remove(work / name, ignored);
        if (std::filesystem::is_directory(work, ignored))
            for (const auto& entry : std::filesystem::directory_iterator(work))
                if (entry.path().filename().wstring().starts_with(L"completion-"))
                    std::filesystem::remove(entry.path(), ignored);
        for (const auto* suffix : {L"", L".partial", L".report.json", L".items.jsonl"})
            std::filesystem::remove(output.wstring() + suffix, ignored);
        std::filesystem::remove(root / L"saved.bin", ignored);
        std::filesystem::remove(work, ignored);
        std::filesystem::remove(root, ignored);
    }
};
Status fill(Publication& state) {
    for (size_t index = 0; index < 3; ++index) {
        auto& file = state.file(static_cast<PublicationArtifact>(index));
        auto resized = file.resize(0);
        if (!resized.ok())
            return resized;
        const auto& bytes = kPayloads[index];
        auto written = write_all(file, 0, ByteView(bytes.data(), bytes.size()));
        if (!written.ok())
            return written;
        auto flushed = file.flush();
        if (!flushed.ok())
            return flushed;
    }
    return {};
}
Status publish_remaining(Publication& state) {
    for (size_t index = 0; index < 3; ++index) {
        auto published = state.publish_one(static_cast<PublicationArtifact>(index));
        if (!published.ok())
            return published;
    }
    return state.finish();
}
bool seed(const Fixture& fixture, bool ready = true, bool all_published = false) {
    auto created = StagingWorkspace::create(fixture.output.wstring(), identity(), RunId{1});
    TEST_OK(created, "create publication workspace");
    if (!created.ok())
        return false;
    auto workspace = created.take();
    auto reserved = workspace.prepare_publication();
    TEST_OK(reserved, "reserve artifact identities before conversion");
    if (!reserved.ok() || !workspace.publication())
        return false;
    TEST_OK(fill(*workspace.publication()), "fill synthetic publication artifacts");
    if (ready)
        TEST_OK(workspace.publication()->mark_ready(), "seal verified artifact generation");
    if (all_published)
        TEST_OK(publish_remaining(*workspace.publication()), "publish all artifacts");
    Sha256Digest key{};
    key[0] = 7;
    TEST_OK(workspace.journal().begin(key, StagedOutcome::kFailed), "uncommitted staging tail");
    const uint8_t bytes[] = {9, 8, 7};
    TEST_OK(workspace.journal().append(ByteView(bytes, sizeof(bytes))), "preserve tail on refusal");
    return true;
}

void check_refusals_preserve_evidence() {
    for (int fault = 0; fault < 5; ++fault) {
        Fixture fixture;
        if (!seed(fixture))
            return;
        const auto marker = fixture.work / L"publication.bin";
        if (fault == 0) {
            write_bytes(fixture.work / L"candidate.tmp", {1, 2, 3, 4, 6});
        } else if (fault == 1) {
            const auto path = std::filesystem::path(fixture.work / L"candidate.tmp");
            const auto bytes = read_bytes(path);
            std::filesystem::rename(path, fixture.root / L"saved.bin");
            write_bytes(path, bytes);
        } else if (fault == 2) {
            auto bytes = read_bytes(marker);
            bytes.back() ^= 1;
            write_bytes(marker, bytes);
        } else if (fault == 3) {
            write_bytes(fixture.output, {99});
        } else {
            std::error_code error;
            std::filesystem::create_hard_link(fixture.work / L"candidate.tmp",
                                              fixture.root / L"saved.bin", error);
            TEST_CHECK(!error);
        }
        const auto before_marker = read_bytes(marker);
        const auto before_data = read_bytes(fixture.work / L"data.bin");
        const auto before_journal = read_bytes(fixture.work / L"journal.bin");
        TEST_CHECK(!StagingWorkspace::resume(fixture.output.wstring(), identity()).ok());
        TEST_CHECK(read_bytes(marker) == before_marker);
        TEST_CHECK(read_bytes(fixture.work / L"data.bin") == before_data);
        TEST_CHECK(read_bytes(fixture.work / L"journal.bin") == before_journal);
    }
    Fixture fixture;
    if (!seed(fixture, true, true))
        return;
    write_bytes(fixture.output, {1, 2, 3, 4, 6});
    TEST_ERROR(StagingWorkspace::resume(fixture.output.wstring(), identity()), ErrorKind::kBadField,
               "publication.file_hash", "completed resume refuses an Outlook-modified file");
}

void check_torn_markers_and_journal_failure() {
    for (const uint64_t length : {uint64_t{155}, uint64_t{311}, uint64_t{313}, uint64_t{359}}) {
        Fixture fixture;
        const bool published = length >= 312;
        if (!seed(fixture, true, published))
            return;
        const auto marker = fixture.work / L"publication.bin";
        std::filesystem::resize_file(marker, length);
        auto resumed = StagingWorkspace::resume(fixture.output.wstring(), identity());
        TEST_OK(resumed, "recover a torn publication marker");
        if (!resumed.ok())
            continue;
        auto workspace = resumed.take();
        TEST_CHECK(workspace.publication() != nullptr);
        if (!workspace.publication())
            continue;
        auto& state = *workspace.publication();
        TEST_EQ(std::filesystem::file_size(marker), published ? 312u : 144u,
                "trim marker only after identity and journal validation");
        if (!published) {
            TEST_EQ(state.phase(), PublicationPhase::kBuilding, "torn ready retries assembly");
            TEST_OK(fill(state), "rebuild reserved artifacts");
            TEST_OK(state.mark_ready(), "seal rebuilt generation");
        }
        TEST_OK(publish_remaining(state), "complete interrupted publication");
        TEST_EQ(state.phase(), PublicationPhase::kComplete, "durable completion");
    }
    Fixture fixture;
    if (!seed(fixture))
        return;
    const auto marker = fixture.work / L"publication.bin";
    std::filesystem::resize_file(marker, 155);
    auto journal = read_bytes(fixture.work / L"journal.bin");
    journal[0] ^= 1;
    write_bytes(fixture.work / L"journal.bin", journal);
    TEST_CHECK(!StagingWorkspace::resume(fixture.output.wstring(), identity()).ok());
    TEST_EQ(std::filesystem::file_size(marker), 155u,
            "journal corruption cannot trim a separate publication marker");
    TEST_EQ(std::filesystem::file_size(fixture.work / L"data.bin"), 3u,
            "corruption retains uncommitted data evidence");
}

void check_no_replace_and_verification_window() {
    Fixture fixture;
    if (!seed(fixture, false))
        return;
    auto resumed = StagingWorkspace::resume(fixture.output.wstring(), identity());
    TEST_OK(resumed, "resume assembly");
    if (!resumed.ok())
        return;
    auto workspace = resumed.take();
    TEST_CHECK(workspace.publication() != nullptr);
    if (!workspace.publication())
        return;
    auto& state = *workspace.publication();
    TEST_OK(state.close_candidate(), "release candidate for independent reader");
    {
        auto reader = FileReader::open_stable(state.path(PublicationArtifact::kPst));
        TEST_OK(reader, "verification reader opens candidate");
        if (reader.ok()) {
            auto hash = sha256_file(reader.value());
            TEST_OK(hash, "reader hashes candidate");
        }
    }
    TEST_OK(state.reopen_candidate(), "reacquire original candidate identity");
    TEST_OK(state.mark_ready(), "seal after verification");
    TEST_ERROR(state.publish_one(PublicationArtifact::kSummary), ErrorKind::kBadField,
               "publication.order", "reports cannot precede PST publication");
    write_bytes(fixture.output, {99});
    TEST_CHECK(!state.publish_one(PublicationArtifact::kPst).ok());
    TEST_CHECK(read_bytes(fixture.output) == std::vector<uint8_t>{99});
    TEST_CHECK(!state.finish().ok());
    TEST_CHECK(read_bytes(fixture.work / L"candidate.tmp") == kPayloads[0]);
}

#ifdef _WIN32
[[noreturn]] void crash_now() {
    TerminateProcess(GetCurrentProcess(), 77);
    std::abort();
}
int initialize_child(const std::wstring& output, int phase) {
    auto result = StagingWorkspace::create_ready(output, identity(), RunId{1},
                                                 [&](InitializationPoint point) {
                                                     if (static_cast<int>(point) == phase)
                                                         crash_now();
                                                 });
    return result.ok() ? 0 : 29;
}

void check_initialization() {
    for (int phase = 0; phase != 6; ++phase) {
        Fixture fixture;
        TEST_EQ(ost2pst::test::run_self(
                    {L"--initialize", fixture.output.wstring(), std::to_wstring(phase)}),
                77u, "terminate a real initializer at each boundary");
        TEST_CHECK(std::filesystem::exists(fixture.work) == (phase == 5));
        std::filesystem::path abandoned;
        std::map<std::filesystem::path, std::vector<uint8_t>> before;
        for (const auto& entry : std::filesystem::directory_iterator(fixture.root)) {
            if (entry.path() == fixture.work)
                continue;
            abandoned = entry.path();
            write_bytes(abandoned / L"foreign.txt", {42});
            for (const auto& file : std::filesystem::directory_iterator(abandoned))
                before.emplace(file.path(), read_bytes(file.path()));
        }
        {
            auto restarted =
                StagingWorkspace::resume_ready(fixture.output.wstring(), identity(), RunId{2});
            TEST_OK(restarted, "restart unpublished initialization or resume the published run");
            if (!restarted.ok())
                continue;
            auto workspace = restarted.take();
            TEST_CHECK(workspace.manifest().run_id == (phase == 5 ? RunId{1} : RunId{2}));
            TEST_CHECK(workspace.publication() != nullptr);
            TEST_CHECK(workspace.journal().records().empty());
            TEST_CHECK(
                !StagingWorkspace::resume_ready(fixture.output.wstring(), identity(), RunId{3})
                     .ok());
            for (const auto& [path, bytes] : before)
                TEST_CHECK(read_bytes(path) == bytes);
            if (workspace.publication()) {
                TEST_OK(fill(*workspace.publication()), "assemble after startup recovery");
                TEST_OK(workspace.publication()->mark_ready(), "seal recovered run");
                TEST_OK(publish_remaining(*workspace.publication()), "publish recovered run");
            }
        }
        TEST_CHECK(read_bytes(fixture.output) == kPayloads[0]);
        auto repeated =
            StagingWorkspace::resume_ready(fixture.output.wstring(), identity(), RunId{3});
        TEST_OK(repeated, "ready startup remains resumable after publication");
    }
    // Never turn missing or malformed files in a published workspace into a new run.
    {
        Fixture fixture;
        {
            auto legacy = StagingWorkspace::create(fixture.output.wstring(), identity(), RunId{1});
            TEST_OK(legacy, "incomplete legacy workspace");
        }
        const auto before = read_bytes(fixture.work / L"journal.bin");
        TEST_ERROR(StagingWorkspace::resume_ready(fixture.output.wstring(), identity(), RunId{2}),
                   ErrorKind::kBadField, "workspace.publication_missing", "missing marker refused");
        TEST_CHECK(read_bytes(fixture.work / L"journal.bin") == before);
    }
    for (const auto* suffix : {L"", L".partial", L".report.json", L".items.jsonl"}) {
        Fixture fixture;
        auto foreign = std::filesystem::path(fixture.output.wstring() + suffix);
        write_bytes(foreign, {99});
        TEST_CHECK(
            !StagingWorkspace::resume_ready(fixture.output.wstring(), identity(), RunId{2}).ok());
        TEST_CHECK(read_bytes(foreign) == std::vector<uint8_t>{99});
        TEST_CHECK(!std::filesystem::exists(fixture.work));
    }
    {
        Fixture fixture;
        auto raced = StagingWorkspace::create_ready(
            fixture.output.wstring(), identity(), RunId{1}, [&](InitializationPoint point) {
                if (point == InitializationPoint::kPublicationReserved) {
                    TEST_CHECK(std::filesystem::create_directory(fixture.work));
                    write_bytes(fixture.work / L"foreign.txt", {99});
                }
            });
        TEST_CHECK(!raced.ok());
        TEST_CHECK(read_bytes(fixture.work / L"foreign.txt") == std::vector<uint8_t>{99});
        TEST_CHECK(!std::filesystem::exists(fixture.work / L"manifest.bin"));
    }
}
int child(const std::wstring& output, int phase) {
    auto created = StagingWorkspace::create(output, identity(), RunId{1});
    if (!created.ok())
        return 20;
    auto workspace = created.take();
    if (!workspace.prepare_publication().ok() || !workspace.publication())
        return 21;
    auto& state = *workspace.publication();
    if (phase >= 7) {
        Sha256Digest item_key{};
        item_key[0] = 1;
        const uint8_t staged[] = {1, 4, 7, 9};
        if (!workspace.journal().begin(item_key, StagedOutcome::kConverted).ok() ||
            !workspace.journal().append(ByteView(staged, sizeof(staged))).ok() ||
            !workspace.journal().commit().ok())
            return 27;
    }
    if (!fill(state).ok())
        return 22;
    if (phase == 0)
        crash_now();
    if (!state.close_candidate().ok())
        return 23;
    if (phase == 1)
        crash_now();
    if (!state.reopen_candidate().ok() || !state.mark_ready().ok())
        return 24;
    if (phase == 2)
        crash_now();
    for (size_t index = 0; index < 3; ++index) {
        if (!state.publish_one(static_cast<PublicationArtifact>(index)).ok())
            return 25;
        if (phase == static_cast<int>(index) + 3)
            crash_now();
    }
    if (!state.finish().ok())
        return 26;
    if (phase >= 7) {
        auto cleaned = workspace.cleanup_completed({3, 1}, [&](CleanupPoint point) {
            if (static_cast<int>(point) + 7 == phase)
                crash_now();
        });
        return cleaned.ok() ? 0 : 28;
    }
    crash_now();
}

void check_cleanup_termination_and_refusal() {
    for (int phase = 7; phase <= 10; ++phase) {
        Fixture fixture;
        TEST_EQ(
            ost2pst::test::run_self({L"--crash", fixture.output.wstring(), std::to_wstring(phase)}),
            77u, "real process killed at completion/cleanup boundary");
        write_bytes(fixture.work / L"foreign.txt", {7, 8, 9});
        {
            auto resumed = StagingWorkspace::resume(fixture.output.wstring(), identity());
            TEST_OK(resumed, "resume before or during staging cleanup");
            if (!resumed.ok())
                continue;
            auto workspace = resumed.take();
            TEST_CHECK(workspace.completed().has_value() == (phase != 7));
            if (workspace.completed()) {
                TEST_EQ(workspace.completed()->exit_code, 3u, "salvage result survives cleanup");
                TEST_EQ(workspace.completed()->terminal_items, 1u,
                        "terminal count survives cleanup");
            } else {
                TEST_EQ(workspace.journal().records().size(), 1u,
                        "unpublished receipt preserves journal");
            }
            TEST_OK(workspace.cleanup_completed({3, 1}), "finish or repeat interrupted cleanup");
            TEST_ERROR(workspace.cleanup_completed({0, 1}), ErrorKind::kBadField,
                       "workspace.cleanup_phase", "cleanup cannot change the durable result");
        }
        TEST_EQ(std::filesystem::file_size(fixture.work / L"data.bin"), 0u, "payload released");
        TEST_EQ(std::filesystem::file_size(fixture.work / L"journal.bin"), 0u, "journal released");
        TEST_CHECK(read_bytes(fixture.work / L"foreign.txt") == std::vector<uint8_t>({7, 8, 9}));
        TEST_CHECK(read_bytes(fixture.output) == kPayloads[0]);
        auto again = StagingWorkspace::resume(fixture.output.wstring(), identity());
        TEST_OK(again, "completed receipt supports repeat resume with zero staging bytes");
    }
    for (int fault = 0; fault != 3; ++fault) {
        Fixture fixture;
        TEST_EQ(ost2pst::test::run_self({L"--crash", fixture.output.wstring(), L"8"}), 77u,
                "stop after durable receipt before any cleanup");
        const auto staged = read_bytes(fixture.work / L"data.bin");
        const auto journal = read_bytes(fixture.work / L"journal.bin");
        const auto receipt_path = fixture.work / L"completion.bin";
        if (fault == 0) {
            auto receipt = read_bytes(receipt_path);
            receipt[32] ^= 1;
            write_bytes(receipt_path, receipt);
        } else if (fault == 1) {
            auto receipt = read_bytes(receipt_path);
            std::filesystem::rename(receipt_path, fixture.root / L"saved.bin");
            write_bytes(receipt_path, receipt);
        } else {
            write_bytes(fixture.output, {1, 2, 3, 9});
        }
        auto refused = StagingWorkspace::resume(fixture.output.wstring(), identity());
        TEST_CHECK(!refused.ok());
        TEST_CHECK(read_bytes(fixture.work / L"data.bin") == staged);
        TEST_CHECK(read_bytes(fixture.work / L"journal.bin") == journal);
    }
}
void check_process_termination() {
    for (int phase = 0; phase <= 6; ++phase) {
        Fixture fixture;
        TEST_EQ(
            ost2pst::test::run_self({L"--crash", fixture.output.wstring(), std::to_wstring(phase)}),
            77u, "real process killed at publication boundary");
        {
            auto resumed = StagingWorkspace::resume(fixture.output.wstring(), identity());
            TEST_OK(resumed, "recover terminated publisher");
            if (!resumed.ok())
                continue;
            auto workspace = resumed.take();
            TEST_CHECK(workspace.publication() != nullptr);
            if (!workspace.publication())
                continue;
            auto& state = *workspace.publication();
            if (state.phase() == PublicationPhase::kBuilding) {
                TEST_OK(fill(state), "restart uncommitted assembly");
                TEST_OK(state.mark_ready(), "seal recovered candidate");
            }
            TEST_OK(publish_remaining(state), "resume remaining artifact renames");
        }
        TEST_CHECK(read_bytes(fixture.output) == kPayloads[0]);
        TEST_CHECK(read_bytes(fixture.output.wstring() + L".report.json") == kPayloads[1]);
        TEST_CHECK(read_bytes(fixture.output.wstring() + L".items.jsonl") == kPayloads[2]);
        auto repeated = StagingWorkspace::resume(fixture.output.wstring(), identity());
        TEST_OK(repeated, "completed resume is idempotent");
        if (repeated.ok()) {
            auto workspace = repeated.take();
            TEST_CHECK(workspace.publication() != nullptr);
            if (!workspace.publication())
                continue;
            TEST_EQ(workspace.publication()->phase(), PublicationPhase::kComplete,
                    "durable completion remains available");
            TEST_OK(publish_remaining(*workspace.publication()), "no duplicate publication");
        }
    }
}
#endif
} // namespace

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
    if (argc == 4 && std::wstring(argv[1]) == L"--initialize")
        return initialize_child(argv[2], std::stoi(argv[3]));
    if (argc == 4 && std::wstring(argv[1]) == L"--crash")
        return child(argv[2], std::stoi(argv[3]));
#else
int main() {
#endif
    check_refusals_preserve_evidence();
    check_torn_markers_and_journal_failure();
    check_no_replace_and_verification_window();
#ifdef _WIN32
    check_initialization();
    check_process_termination();
    check_cleanup_termination_and_refusal();
#endif
    return ost2pst::test::finish("writer_publication_test");
}
