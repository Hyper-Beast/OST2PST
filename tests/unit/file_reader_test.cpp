#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "ost2pst/util/file_reader.h"
#include "test_support.h"

namespace {

using ost2pst::util::ErrorKind;
using ost2pst::util::FileReader;

std::filesystem::path temp_path(const char *name) {
    std::filesystem::path path = std::filesystem::temp_directory_path();
    path /= name;
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    return path;
}

void check_size_and_reads() {
    const std::filesystem::path path = temp_path("ost2pst_file_reader_test.bin");
    std::vector<uint8_t> bytes(1100);
    for (size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<uint8_t>(index & 0xFFu);
    }
    {
        std::ofstream stream(path, std::ios::binary);
        if (!stream) {
            ost2pst::test::report_failure(__FILE__, __LINE__, "cannot create temp file");
            return;
        }
        std::string payload;
        payload.reserve(bytes.size());
        for (uint8_t byte : bytes) {
            payload.push_back(static_cast<char>(byte));
        }
        stream.write(payload.data(), static_cast<std::streamsize>(payload.size()));
        if (!stream) {
            ost2pst::test::report_failure(__FILE__, __LINE__, "cannot fill temp file");
            return;
        }
    }

    const auto opened = FileReader::open(path.wstring());
    TEST_OK(opened, "open 1100-byte file");
    if (!opened.ok()) {
        return;
    }
    const FileReader &reader = opened.value();
    TEST_CHECK(reader.is_open());
    // A fresh handle sits at offset 0, so sizing must seek to the end first.
    TEST_EQ(reader.size(), 1100u, "FileReader.size after open");

    std::vector<uint8_t> buffer(1100, 0);
    TEST_OK(reader.read_at(0, buffer.data(), buffer.size()), "read whole file");
    TEST_CHECK(buffer == bytes);

    uint8_t one = 0;
    TEST_OK(reader.read_at(1099, &one, 1), "read last byte");
    TEST_EQ(one, 1099 & 0xFF, "last byte value");
    TEST_OK(reader.read_at(0, &one, 0), "zero-length read");

    const auto past_end = reader.read_at(1100, &one, 1);
    TEST_ERROR(past_end, ErrorKind::kTruncated, "FileReader.read", "read at end of file");
    TEST_ERROR_OFFSET(past_end, 1100, "read at end of file offset");

    const auto straddles = reader.read_at(1090, buffer.data(), 20);
    TEST_ERROR(straddles, ErrorKind::kTruncated, "FileReader.read", "read past end");
    TEST_ERROR_OFFSET(straddles, 1090, "read past end offset");

    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

void check_large_file_size() {
    // Guards the 64-bit sizing path: a 32-bit tell() reports a negative or wrapped value past 2 GiB.
    const std::filesystem::path path = temp_path("ost2pst_file_reader_large.bin");
    std::error_code error;
    {
        std::ofstream stream(path, std::ios::binary);
        if (!stream) {
            ost2pst::test::report_failure(__FILE__, __LINE__, "cannot create large temp file");
            return;
        }
    }
    // resize_file extends by truncating/extending the end of file: no 2 GiB of zeros are written.
    const uint64_t expected_size = 0x80000000ULL + 1;
    std::filesystem::resize_file(path, expected_size, error);
    if (error) {
        std::printf("  SKIP large file sizing test: resize_file failed (%s)\n", error.message().c_str());
        std::filesystem::remove(path, error);
        return;
    }

    const auto opened = FileReader::open(path.wstring());
    TEST_OK(opened, "open 2 GiB + 1 file");
    if (opened.ok()) {
        TEST_EQ(opened.value().size(), expected_size, "FileReader.size past 2 GiB");
    }
    std::filesystem::remove(path, error);
}

void check_missing_file() {
    const std::filesystem::path path = temp_path("ost2pst_file_reader_absent.bin");
    const auto opened = FileReader::open(path.wstring());
    TEST_ERROR(opened, ErrorKind::kIo, "FileReader.open", "missing file");
}

} // namespace

int main() {
    check_size_and_reads();
    check_large_file_size();
    check_missing_file();
    return ost2pst::test::finish("file_reader_test");
}
