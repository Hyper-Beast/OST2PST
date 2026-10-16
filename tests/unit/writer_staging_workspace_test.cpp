#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "ost2pst/util/directory_pin.h"
#include "ost2pst/writer/staging_workspace.h"

#include "test_support.h"
#include "windows_process.h"

#ifdef _WIN32
#include <winioctl.h>
#endif

namespace {
using namespace ost2pst::util;
using namespace ost2pst::writer;

ConversionIdentity identity() {
    ConversionIdentity value;
    value.source_sha256[0] = 11;
    value.source_size = 123;
    value.source_profile = 36;
    value.converter_sha256[0] = 22;
    value.options = {{"hierarchy", "Imported OST"}, {"search", "exclude"}};
    return value;
}
Sha256Digest key(uint8_t id) {
    Sha256Digest result{};
    result[0] = id;
    return result;
}
void write_bytes(const std::filesystem::path& path, const std::vector<uint8_t>& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!bytes.empty())
        output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    TEST_CHECK(output.good());
}
std::vector<uint8_t> read_bytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    TEST_CHECK(input.good());
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(input),
                                std::istreambuf_iterator<char>());
}

struct Fixture {
    std::filesystem::path root, output, work;
    Fixture() {
        root = std::filesystem::temp_directory_path() /
               ("ost2pst_workspace_" +
                std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        TEST_CHECK(std::filesystem::create_directory(root));
        output = root / L"mail \u90ae\u4ef6.pst";
        work = output.wstring() + L".work";
    }
    ~Fixture() {
        // Remove only named files created by this fixture; do not recursively delete a directory.
        std::error_code ignored;
        for (const auto* name :
             {L"run.lock", L"manifest.bin", L"data.bin", L"journal.bin", L"foreign.txt"})
            std::filesystem::remove(work / name, ignored);
        std::filesystem::remove(work, ignored);
        for (const auto* name : {L"saved.bin", L"alias.bin", L"renamed", L"source.bin"})
            std::filesystem::remove(root / name, ignored);
        for (const auto* suffix : {L"", L".partial", L".report.json", L".items.jsonl"})
            std::filesystem::remove(output.wstring() + suffix, ignored);
        std::filesystem::remove(root, ignored);
    }
    bool initialize() {
        auto created = StagingWorkspace::create(output.wstring(), identity(), RunId{1});
        TEST_OK(created, "create owned workspace");
        if (!created.ok())
            return false;
        auto workspace = created.take();
        TEST_OK(workspace.journal().begin(key(1), StagedOutcome::kConverted),
                "begin committed item");
        const uint8_t bytes[] = {1, 2, 3};
        TEST_OK(workspace.journal().append(ByteView(bytes, sizeof(bytes))), "stage payload");
        TEST_OK(workspace.journal().commit(), "commit payload");
        TEST_OK(workspace.journal().begin(key(2), StagedOutcome::kConverted),
                "begin unfinished item");
        TEST_OK(workspace.journal().append(ByteView(bytes, sizeof(bytes))),
                "leave uncommitted suffix");
        return true;
    }
};

void check_resume_and_ownership() {
    Fixture fixture;
    if (!fixture.initialize())
        return;
    const auto data = fixture.work / "data.bin";
    TEST_EQ(std::filesystem::file_size(data), 6u, "uncommitted data remains after close");
    write_bytes(fixture.work / "foreign.txt", {99});
    {
        auto recovered = StagingWorkspace::resume(fixture.output.wstring(), identity());
        TEST_OK(recovered, "resume owned workspace");
        if (!recovered.ok())
            return;
        auto workspace = recovered.take();
        auto moved = std::move(workspace);
        TEST_EQ(moved.journal().records().size(), 1u, "one committed item recovered");
        TEST_EQ(std::filesystem::file_size(data), 3u, "uncommitted suffix trimmed");
        TEST_CHECK(!StagingWorkspace::resume(fixture.output.wstring(), identity()).ok());
#ifdef _WIN32
        TEST_EQ(ost2pst::test::run_self({L"--resume", fixture.output.wstring()}), 7u,
                "another process cannot own run");
#endif
        std::error_code error;
        std::filesystem::rename(fixture.work, fixture.root / "renamed", error);
        TEST_CHECK(bool(error));
        TEST_OK(moved.journal().begin(key(3), StagedOutcome::kFailed),
                "moved owner's journal stays valid");
        TEST_OK(moved.journal().commit(), "commit after wrapper move");
    }
#ifdef _WIN32
    TEST_EQ(ost2pst::test::run_self({L"--resume", fixture.output.wstring()}), 0u,
            "another process can resume after owner closes");
#endif
    auto preserved = read_bytes((fixture.work / "foreign.txt"));
    TEST_CHECK(preserved == std::vector<uint8_t>{99});
}

void check_mismatch_preserves_state() {
    Fixture fixture;
    if (!fixture.initialize())
        return;
    const auto data = fixture.work / "data.bin", journal = fixture.work / "journal.bin";
    const auto before_data = read_bytes(data);
    const auto before_journal = read_bytes(journal);
    for (int fault = 0; fault < 6; ++fault) {
        auto different = identity();
        if (fault == 0)
            different.source_sha256[0] ^= 1;
        if (fault == 1)
            ++different.source_size;
        if (fault == 2)
            ++different.source_profile;
        if (fault == 3)
            different.converter_sha256[0] ^= 1;
        if (fault == 4)
            different.options["search"] = "include";
        if (fault == 5)
            ++different.record_budget;
        TEST_ERROR(StagingWorkspace::resume(fixture.output.wstring(), different),
                   ErrorKind::kBadField, "workspace.identity",
                   "refuse mismatched conversion before recovery");
        TEST_CHECK(read_bytes(data) == before_data);
        TEST_CHECK(read_bytes(journal) == before_journal);
    }
    TEST_CHECK(!StagingWorkspace::create(fixture.output.wstring(), identity(), RunId{2}).ok());
    TEST_CHECK(read_bytes(data) == before_data);
}

void check_replaced_files() {
    for (const auto* name : {"run.lock", "manifest.bin", "data.bin", "journal.bin"}) {
        Fixture fixture;
        if (!fixture.initialize())
            return;
        const auto path = fixture.work / name;
        const auto contents = read_bytes(path);
        std::filesystem::rename(path, fixture.root / "saved.bin");
        TEST_CHECK(!StagingWorkspace::resume(fixture.output.wstring(), identity()).ok());
        TEST_CHECK(!std::filesystem::exists(path));
        write_bytes(path, contents);
        TEST_ERROR(StagingWorkspace::resume(fixture.output.wstring(), identity()),
                   ErrorKind::kBadField, "workspace.files",
                   "byte-identical replacement is not original file");
        TEST_EQ(std::filesystem::file_size(fixture.work / "data.bin"), 6u,
                "replacement refusal does not trim data");
    }
}

void check_corruption_preserves_state() {
    for (const auto* name : {"manifest.bin", "data.bin", "journal.bin"}) {
        Fixture fixture;
        if (!fixture.initialize())
            return;
        auto bytes = read_bytes(fixture.work / name);
        bytes[0] ^= 1;
        write_bytes(fixture.work / name, bytes);
        const auto before_manifest = read_bytes(fixture.work / "manifest.bin");
        const auto before_data = read_bytes(fixture.work / "data.bin");
        const auto before_journal = read_bytes(fixture.work / "journal.bin");
        TEST_CHECK(!StagingWorkspace::resume(fixture.output.wstring(), identity()).ok());
        TEST_CHECK(read_bytes(fixture.work / "manifest.bin") == before_manifest);
        TEST_CHECK(read_bytes(fixture.work / "data.bin") == before_data);
        TEST_CHECK(read_bytes(fixture.work / "journal.bin") == before_journal);
    }
}

#ifdef _WIN32
// Windows REPARSE_DATA_BUFFER.MountPointReparseBuffer; junctions need no symlink privilege.
bool create_junction(const std::filesystem::path& link, const std::filesystem::path& target) {
    struct MountPointHeader {
        DWORD tag;
        WORD data_length, reserved, substitute_offset, substitute_length, print_offset,
            print_length;
    };
    static_assert(sizeof(MountPointHeader) == 16);
    const auto print = target.wstring();
    const auto substitute = L"\\??\\" + print;
    const size_t path_bytes = (substitute.size() + print.size() + 2) * sizeof(wchar_t);
    if (path_bytes + sizeof(MountPointHeader) > MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
        return false;
    MountPointHeader header{IO_REPARSE_TAG_MOUNT_POINT,
                            static_cast<WORD>(8 + path_bytes),
                            0,
                            0,
                            static_cast<WORD>(substitute.size() * sizeof(wchar_t)),
                            static_cast<WORD>((substitute.size() + 1) * sizeof(wchar_t)),
                            static_cast<WORD>(print.size() * sizeof(wchar_t))};
    std::vector<uint8_t> buffer(sizeof(header) + path_bytes);
    std::memcpy(buffer.data(), &header, sizeof(header));
    std::memcpy(buffer.data() + sizeof(header), substitute.c_str(),
                (substitute.size() + 1) * sizeof(wchar_t));
    std::memcpy(buffer.data() + sizeof(header) + header.print_offset, print.c_str(),
                (print.size() + 1) * sizeof(wchar_t));
    if (!CreateDirectoryW(link.c_str(), nullptr))
        return false;
    HANDLE handle = CreateFileW(link.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (handle == INVALID_HANDLE_VALUE)
        return false;
    DWORD returned = 0;
    const bool ok =
        DeviceIoControl(handle, FSCTL_SET_REPARSE_POINT, buffer.data(),
                        static_cast<DWORD>(buffer.size()), nullptr, 0, &returned, nullptr) != 0;
    CloseHandle(handle);
    return ok;
}

void check_directory_aliases() {
    Fixture fixture;
    if (!fixture.initialize())
        return;
    const auto saved = fixture.root / "saved-work";
    std::filesystem::rename(fixture.work, saved);
    const bool linked = create_junction(fixture.work, saved);
    TEST_CHECK(linked);
    if (linked) {
        TEST_ERROR(StagingWorkspace::resume(fixture.output.wstring(), identity()),
                   ErrorKind::kBadField, "DirectoryPin.type", "work directory redirection refused");
        TEST_EQ(std::filesystem::file_size(saved / "data.bin"), 6u,
                "junction target not truncated");
    }
    std::filesystem::remove(fixture.work); // Removes the junction itself, never its target tree.
    std::filesystem::rename(saved, fixture.work);

    const auto parent_alias = fixture.root / "parent-alias";
    const bool parent_linked = create_junction(parent_alias, fixture.root);
    TEST_CHECK(parent_linked);
    if (parent_linked) {
        auto canonical = output_location(fixture.output.wstring());
        auto alias = output_location((parent_alias / fixture.output.filename()).wstring());
        TEST_OK(canonical, "resolve parent");
        TEST_OK(alias, "resolve parent junction");
        if (canonical.ok() && alias.ok())
            TEST_CHECK(canonical.value().binding == alias.value().binding);
        auto recovered = StagingWorkspace::resume(
            (parent_alias / fixture.output.filename()).wstring(), identity());
        TEST_OK(recovered, "equivalent parent alias resumes the same run");
        if (recovered.ok()) {
            auto workspace = recovered.take();
            TEST_EQ(workspace.journal().records().size(), 1u, "same committed progress");
            TEST_CHECK(!StagingWorkspace::resume(fixture.output.wstring(), identity()).ok());
        }
    }
    std::filesystem::remove(parent_alias);
}
#endif

void check_alias_and_output_refusals() {
    Fixture fixture;
    if (!fixture.initialize())
        return;
    std::error_code error;
    std::filesystem::create_hard_link(fixture.work / "data.bin", fixture.root / "alias.bin", error);
    TEST_CHECK(!error);
    TEST_ERROR(StagingWorkspace::resume(fixture.output.wstring(), identity()), ErrorKind::kBadField,
               "FileWriter.private_file", "private data cannot alias a foreign path");
    TEST_EQ(std::filesystem::file_size(fixture.root / "alias.bin"), 6u, "alias not truncated");
    std::filesystem::remove(fixture.root / "alias.bin");
    for (const auto* suffix : {L"", L".partial", L".report.json", L".items.jsonl"}) {
        const auto path = std::filesystem::path(fixture.output.wstring() + suffix);
        write_bytes(path, {42});
        TEST_ERROR(StagingWorkspace::resume(fixture.output.wstring(), identity()), ErrorKind::kIo,
                   "output.exists", "foreign output artifact refused");
        TEST_CHECK(read_bytes(path) == std::vector<uint8_t>{42});
        TEST_EQ(std::filesystem::file_size(fixture.work / "data.bin"), 6u,
                "refusal does not truncate");
        std::filesystem::remove(path);
    }
    const auto source_path = fixture.root / "source.bin";
    write_bytes(source_path, {31, 32});
    std::filesystem::create_hard_link(source_path, fixture.output, error);
    TEST_CHECK(!error);
    auto source = FileReader::open_stable(source_path.wstring());
    TEST_OK(source, "hold source stable");
    TEST_CHECK(!StagingWorkspace::resume(fixture.output.wstring(), identity()).ok());
    uint8_t byte = 0;
    if (source.ok()) {
        TEST_OK(source.value().read_at(0, &byte, 1), "source survives alias refusal");
        TEST_EQ(byte, 31u, "source unchanged");
    }
}

void check_bad_paths() {
    Fixture fixture;
    for (const auto* name : {L"NUL", L"con.txt", L"bad.", L"bad ", L"bad:stream", L".."}) {
        auto location = output_location((fixture.root / name).wstring());
        if (location.ok())
            std::fprintf(stderr, "accepted invalid leaf: %ls -> %s\n", name,
                         location.value().binding.c_str());
        TEST_ERROR(location, ErrorKind::kBadField, "output.filename",
                   "invalid leaf refused before normalization");
        TEST_CHECK(
            !StagingWorkspace::create((fixture.root / name).wstring(), identity(), RunId{1}).ok());
    }
    TEST_CHECK(!StagingWorkspace::create(fixture.output.wstring(), identity(), RunId{}).ok());
    TEST_CHECK(!std::filesystem::exists(fixture.work));
    TEST_CHECK(!StagingWorkspace::resume(fixture.output.wstring(), identity()).ok());
    TEST_CHECK(!std::filesystem::exists(fixture.work));
}
} // namespace

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
    if (argc == 3 && std::wstring(argv[1]) == L"--resume") {
        auto resumed = StagingWorkspace::resume(argv[2], identity());
        return resumed.ok() ? 0 : 7;
    }
#else
int main() {
#endif
    check_resume_and_ownership();
    check_mismatch_preserves_state();
    check_replaced_files();
    check_corruption_preserves_state();
#ifdef _WIN32
    check_directory_aliases();
#endif
    check_alias_and_output_refusals();
    check_bad_paths();
    return ost2pst::test::finish("writer_staging_workspace_test");
}
