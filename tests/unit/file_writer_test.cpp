#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <limits>
#include <string>
#include <vector>

#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/file_writer.h"

#include "test_support.h"
#include "windows_process.h"

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#endif

namespace {
using namespace ost2pst::util;

class PartialFile final : public RandomAccessFile {
  public:
    std::vector<uint8_t> bytes;
    size_t calls = 0;
    size_t fail_on = 0;
    size_t progress = 2;
    uint64_t size() const override { return bytes.size(); }
    Status read_at(uint64_t, uint8_t*, size_t) const override { return {}; }
    Result<size_t> write_some(uint64_t offset, ByteView input) override {
        ++calls;
        if (calls == fail_on)
            return make_error(ErrorKind::kIo, "injected.write", offset);
        if (progress == 0 || progress > 2)
            return progress;
        const size_t count = std::min(progress, input.size());
        bytes.resize(static_cast<size_t>(offset) + count);
        std::copy_n(input.data(), count, bytes.data() + offset);
        return count;
    }
    Status resize(uint64_t) override { return {}; }
    Status flush() override { return {}; }
};

void check_partial_writes() {
    const std::array<uint8_t, 5> bytes{1, 2, 3, 4, 5};
    const ByteView view(bytes.data(), bytes.size());
    PartialFile partial;
    TEST_OK(write_all(partial, 0, view), "retry partial writes");
    TEST_EQ(partial.calls, 3u, "three writes");
    TEST_CHECK(std::equal(bytes.begin(), bytes.end(), partial.bytes.begin()));
    for (size_t progress : {size_t{0}, size_t{6}}) {
        PartialFile invalid;
        invalid.progress = progress;
        TEST_ERROR(write_all(invalid, 0, view), ErrorKind::kIo, "FileWriter.write_progress",
                   "invalid progress fails");
        TEST_EQ(invalid.calls, 1u, "no infinite retry");
    }
    PartialFile failing;
    failing.fail_on = 2;
    TEST_ERROR(write_all(failing, 0, view), ErrorKind::kIo, "injected.write",
               "propagate failure after prefix");
    TEST_EQ(failing.bytes.size(), 2u, "only successful prefix exists");
    TEST_ERROR(write_all(failing, UINT64_MAX, view), ErrorKind::kBadField, "FileWriter.range",
               "offset overflow");
    TEST_ERROR(write_all(failing, 0, ByteView(nullptr, 1)), ErrorKind::kBadField, "FileWriter.data",
               "null input");
    TEST_EQ(failing.calls, 2u, "invalid arguments never reach sink");
}

#ifdef _WIN32
DWORD child_lock(const std::filesystem::path& path) {
    return ost2pst::test::run_self({L"--lock", path.wstring()});
}

void check_disk_files() {
    const auto stem = "ost2pst_writer_" +
                      std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const auto path = std::filesystem::temp_directory_path() / (stem + ".bin");
    const auto alias = std::filesystem::temp_directory_path() / (stem + "_alias.bin");
    const auto destination = std::filesystem::temp_directory_path() / (stem + "_published.bin");
    const std::array<uint8_t, 4> bytes{11, 22, 33, 44};
    auto created = FileWriter::create_new(path.wstring());
    TEST_OK(created, "create exclusive file");
    if (!created.ok())
        return;
    auto file = created.take();
    TEST_CHECK(!created.value().is_open());
    TEST_OK(write_all(file, 0, ByteView(bytes.data(), bytes.size())), "write bytes");
    TEST_OK(file.flush(), "flush bytes");
    TEST_EQ(child_lock(path), 7u, "second process cannot own file");
    TEST_CHECK(!FileWriter::create_new(path.wstring()).ok());
    TEST_CHECK(!FileWriter::open_existing(path.wstring()).ok());
    std::array<uint8_t, 4> read{};
    TEST_OK(file.read_at(0, read.data(), read.size()), "read own bytes");
    TEST_CHECK(read == bytes);
    TEST_ERROR(file.read_at(4, read.data(), 1), ErrorKind::kTruncated, "FileWriter.read",
               "read beyond EOF");
    TEST_ERROR(file.read_at(0, nullptr, 1), ErrorKind::kBadField, "FileWriter.data",
               "null read buffer");
    TEST_ERROR(file.write_some(UINT64_MAX, ByteView(bytes.data(), 1)), ErrorKind::kBadField,
               "FileWriter.range", "write offset overflow");
    TEST_ERROR(file.resize(UINT64_MAX), ErrorKind::kBadField, "FileWriter.range",
               "resize overflow");
    TEST_OK(file.close(), "close file");
    TEST_ERROR(file.flush(), ErrorKind::kIo, "FileWriter.flush", "closed flush fails");
    TEST_EQ(child_lock(path), 0u, "second process can acquire after release");
    TEST_CHECK(!FileWriter::create_new(path.wstring()).ok());
    auto reopened = FileWriter::open_existing(path.wstring());
    TEST_OK(reopened, "reopen existing");
    if (!reopened.ok())
        return;
    file = reopened.take();
    TEST_EQ(file.size(), bytes.size(), "reopen and lock did not truncate");
    TEST_OK(file.read_at(0, read.data(), read.size()), "read after reopen");
    TEST_CHECK(read == bytes);
    TEST_OK(file.close(), "close before sparse setup");

    // Synthetic sparse file tests real 64-bit seeks without reserving gigabytes of disk.
    HANDLE sparse = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    TEST_CHECK(sparse != INVALID_HANDLE_VALUE);
    if (sparse != INVALID_HANDLE_VALUE) {
        DWORD returned = 0;
        TEST_CHECK(
            DeviceIoControl(sparse, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &returned, nullptr));
        CloseHandle(sparse);
    }
    reopened = FileWriter::open_existing(path.wstring());
    TEST_OK(reopened, "reopen sparse");
    if (!reopened.ok())
        return;
    file = reopened.take();
    constexpr uint64_t large_offset = (uint64_t{1} << 31) + 123;
    TEST_OK(write_all(file, large_offset, ByteView(bytes.data(), bytes.size())),
            "write beyond 2 GiB");
    TEST_EQ(file.size(), large_offset + bytes.size(), "64-bit size");
    TEST_OK(file.flush(), "flush large_offset bytes");
    read.fill(0);
    TEST_OK(file.read_at(large_offset, read.data(), read.size()), "read beyond 2 GiB");
    TEST_CHECK(read == bytes);
    TEST_OK(file.read_at(0, read.data(), read.size()), "low bytes unaffected");
    TEST_CHECK(read == bytes);
    TEST_OK(file.resize(4), "truncate owned suffix");
    TEST_OK(file.flush(), "flush resize");
    TEST_OK(file.close(), "close before publication");

    std::error_code error;
    std::filesystem::create_hard_link(path, alias, error);
    TEST_CHECK(!error);
    {
        auto source = FileReader::open_stable(path.wstring());
        TEST_OK(source, "hold stable source");
        TEST_CHECK(!FileWriter::open_existing(alias.wstring()).ok());
    }
    TEST_CHECK(!publish_no_replace(path.wstring(), path.wstring()).ok());
    TEST_CHECK(!publish_no_replace(path.wstring(), alias.wstring()).ok());
    TEST_CHECK(std::filesystem::exists(path));
    TEST_OK(publish_no_replace(path.wstring(), destination.wstring()), "publish new destination");
    TEST_CHECK(!std::filesystem::exists(path));
    TEST_CHECK(!publish_no_replace(alias.wstring(), destination.wstring()).ok());
    auto actual = ost2pst::test::read_bytes(destination.string());
    TEST_CHECK(actual == std::vector<uint8_t>(bytes.begin(), bytes.end()));
    TEST_CHECK(std::filesystem::exists(alias));
    std::filesystem::remove(alias, error);
    TEST_CHECK(!error);
    std::filesystem::remove(destination, error);
    TEST_CHECK(!error);
}
#endif
} // namespace

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
    if (argc == 3 && std::wstring(argv[1]) == L"--lock") {
        auto lock = FileWriter::acquire_lock(argv[2]);
        return lock.ok() ? 0 : 7;
    }
#else
int main() {
#endif
    check_partial_writes();
#ifdef _WIN32
    check_disk_files();
#else
    TEST_ERROR(FileWriter::create_new(L"unused"), ErrorKind::kUnsupported, "FileWriter.platform",
               "platform limit");
#endif
    return ost2pst::test::finish("file_writer_test");
}
