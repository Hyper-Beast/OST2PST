#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "ost2pst/writer/content.h"

#include "full_conversion.h"
#include "test_support.h"
#include "windows_process.h"

namespace {
using namespace ost2pst;
std::vector<uint8_t> read_bytes(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    TEST_CHECK(file.good());
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}
void write_bytes(const std::filesystem::path& path, const std::vector<uint8_t>& bytes) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    TEST_CHECK(file.good());
}
std::vector<uint8_t> text(const std::u16string& value) {
    std::vector<uint8_t> bytes;
    for (const auto unit : value) {
        bytes.push_back(static_cast<uint8_t>(unit));
        bytes.push_back(static_cast<uint8_t>(unit >> 8));
    }
    return bytes;
}
bool source_fixture(const std::filesystem::path& path) {
    writer::StoreRequest request;
    request.named_properties.push_back({u"resume", true, 0, std::vector<uint8_t>(16, 0x42)});
    writer::ContentFolder folder;
    folder.parent_nid = writer::kNidIpmsubtree;
    folder.name = u"Resume fixture";
    writer::ContentMessage message;
    // Required message properties: MS-PST 2.4.5.1.1; use synthetic values only.
    message.properties = {{0x001A, 0x001F, text(u"IPM.Note")},
                          {0x0E07, 0x0003, {1, 0, 0, 0}},
                          {0x0E08, 0x0003, {0, 0, 2, 0}},
                          {0x0E17, 0x0003, {0, 0, 0, 0}},
                          {0x3007, 0x0040, std::vector<uint8_t>(8, 0x30)},
                          {0x3008, 0x0040, std::vector<uint8_t>(8, 0x31)},
                          {0x300B, 0x0102, std::vector<uint8_t>(16, 0x40)},
                          {0x0037, 0x001F, text(u"Resume item")},
                          {0x1000, 0x001F, text(u"body")},
                          {0x8000, 0x001F, text(u"named"), false, true, 0}};
    message.recipients.columns = {0x0C150003, 0x3001001F};
    writer::ContentRow recipient;
    recipient.cells = {{0x0C150003, {1, 0, 0, 0}}, {0x3001001F, text(u"Recipient")}};
    message.recipients.rows.push_back(recipient);
    writer::ContentAttachment attachment;
    attachment.has_payload = true;
    attachment.payload.resize(65537);
    for (size_t i = 0; i < attachment.payload.size(); ++i)
        attachment.payload[i] = static_cast<uint8_t>(i * 17 + i / 251);
    attachment.properties = {{0x3705, 0x0003, {1, 0, 0, 0}},
                             {0x3707, 0x001F, text(u"payload.bin")}};
    message.attachment_objects.push_back(attachment);
    message.attachments.columns = {0x37050003};
    writer::ContentRow attachment_row;
    attachment_row.cells = {{0x37050003, {1, 0, 0, 0}}};
    message.attachments.rows.push_back(attachment_row);
    for (int i = 0; i != 3; ++i)
        folder.messages.push_back(message);
    request.folders.push_back(folder);
    auto built = writer::build_store(request);
    TEST_OK(built, "synthetic process recovery input");
    if (!built.ok())
        return false;
    write_bytes(path, built.value().image.bytes);
    return true;
}

[[noreturn]] void terminate() {
    TerminateProcess(GetCurrentProcess(), 77);
    std::abort();
}
int child(const std::filesystem::path& source, const std::filesystem::path& output, int point,
          bool resume) {
    cli::FullConversionHooks hooks;
    if (point == 92)
        hooks.index_workspace_budget = 1;
    hooks.initialization = [&](writer::InitializationPoint value) {
        if (point == static_cast<int>(value))
            terminate();
    };
    hooks.commit = [&](writer::CommitPoint value) {
        if (point == 10 + static_cast<int>(value))
            terminate();
    };
    hooks.phase = [&](cli::FullPoint value) {
        if (point == 20 + static_cast<int>(value))
            terminate();
        if (point == 91 && value == cli::FullPoint::kVerificationOpen)
            write_bytes(std::filesystem::path(output.wstring() + L".work") / L"candidate.tmp", {});
    };
    hooks.cleanup = [&](writer::CleanupPoint value) {
        if (point == 50 + static_cast<int>(value))
            terminate();
    };
    size_t starts = 0;
    hooks.before_candidate_write = [&](uint64_t offset, util::ByteView) -> util::Status {
        if (point == 90)
            return util::make_error(util::ErrorKind::kIo, "test.disk_full", offset, 112);
        if (point == 40)
            terminate();
        if (offset == 0 && ++starts == 2 && point == 41)
            terminate();
        return {};
    };
    return cli::run_full(source.wstring(), output.wstring(), resume, hooks);
}

void remove_fixture_output(const std::filesystem::path& output) {
    const auto work = output.wstring() + L".work";
    std::error_code error;
    for (const auto& entry : std::filesystem::directory_iterator(output.parent_path())) {
        const auto name = entry.path().filename().wstring();
        if (entry.path() != work && !name.starts_with(output.filename().wstring() + L".work.init-"))
            continue;
        for (const auto* leaf :
             {L"manifest.bin", L"run.lock", L"data.bin", L"journal.bin", L"publication.bin",
              L"completion.bin", L"candidate.tmp", L"summary.tmp", L"items.tmp", L"foreign.txt"})
            std::filesystem::remove(entry.path() / leaf, error);
        for (const auto& file : std::filesystem::directory_iterator(entry.path()))
            if (file.path().filename().wstring().starts_with(L"completion-"))
                std::filesystem::remove(file.path(), error);
        std::filesystem::remove(entry.path(), error);
    }
    for (const auto* suffix : {L"", L".report.json", L".items.jsonl"})
        std::filesystem::remove(output.wstring() + suffix, error);
}

void check_full_process_recovery() {
    const auto root =
        std::filesystem::temp_directory_path() /
        (L"ost2pst-full-process-" +
         std::to_wstring(std::chrono::steady_clock::now().time_since_epoch().count()));
    TEST_CHECK(std::filesystem::create_directory(root));
    const auto source = root / L"source.pst", baseline = root / L"baseline.pst";
    if (!source_fixture(source))
        return;
    const auto run = [&](const std::filesystem::path& output, int point, bool resume) {
        return test::run_self({L"--run", source.wstring(), output.wstring(), std::to_wstring(point),
                               resume ? L"1" : L"0"});
    };
    TEST_EQ(run(baseline, -1, false), 0u, "uninterrupted full conversion baseline");
    const auto expected = read_bytes(baseline);
    const auto expected_items = read_bytes(baseline.wstring() + L".items.jsonl");
    const std::vector<int> points{0,  1,  2,  3,  4,  5,  10, 11, 12, 13, 20,
                                  21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                                  32, 33, 40, 41, 50, 51, 52, 53, 90, 91, 92};
    for (int point : points) {
        const auto output = root / (L"case-" + std::to_wstring(point) + L".pst");
        const auto code = run(output, point, false);
        if (point >= 90) {
            TEST_CHECK(code != 0 && code != 77 && code != 99);
            TEST_CHECK(!std::filesystem::exists(output));
            TEST_CHECK(!std::filesystem::exists(output.wstring() + L".report.json"));
        } else {
            TEST_EQ(code, 77u, "real process terminated at requested full-pipeline boundary");
        }
        const auto work = std::filesystem::path(output.wstring() + L".work");
        if (std::filesystem::exists(work))
            write_bytes(work / L"foreign.txt", {42});
        TEST_EQ(run(output, -1, true), 0u, "resume the same binary and source to completion");
        TEST_CHECK(read_bytes(output) == expected);
        TEST_CHECK(read_bytes(output.wstring() + L".items.jsonl") == expected_items);
        const auto report = read_bytes(output.wstring() + L".report.json");
        const std::string report_text(report.begin(), report.end());
        TEST_CHECK(report_text.find("\"converted_normal\":3") != std::string::npos);
        TEST_CHECK(report_text.find("\"attachment_bytes\":196611") != std::string::npos);
        TEST_CHECK(report_text.find("\"performance\":{") != std::string::npos);
        if (point == 20 + static_cast<int>(cli::FullPoint::kAssemblyBegin)) {
            TEST_CHECK(report_text.find("\"resumed\":true") != std::string::npos);
            TEST_CHECK(report_text.find("\"throughput_bytes_per_second\":null") !=
                       std::string::npos);
        }
        TEST_EQ(std::filesystem::file_size(work / L"data.bin"), 0u,
                "staging released after resume");
        TEST_EQ(run(output, -1, true), 0u, "second resume remains idempotent");
        TEST_CHECK(read_bytes(output.wstring() + L".report.json") == report);
        if (std::filesystem::exists(work / L"foreign.txt"))
            TEST_CHECK(read_bytes(work / L"foreign.txt") == std::vector<uint8_t>{42});
        remove_fixture_output(output);
    }
    remove_fixture_output(baseline);
    std::filesystem::remove(source);
    TEST_CHECK(std::filesystem::remove(root));
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 6 && std::wstring(argv[1]) == L"--run")
        return child(argv[2], argv[3], std::stoi(argv[4]), std::wstring(argv[5]) == L"1");
    check_full_process_recovery();
    return test::finish("full_conversion_process_test");
}
