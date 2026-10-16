#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

#include "ost2pst/util/file_reader.h"

#include "test_support.h"

namespace {
using ost2pst::util::ErrorKind;
using ost2pst::util::FileReader;

void check_closed_handle() {
    FileReader closed;
    TEST_ERROR(closed.identity(), ErrorKind::kIo, "FileReader.identity", "closed handle");
}

void check_identity_and_lock() {
    const auto stem = "ost2pst_identity_" +
                      std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const auto path = std::filesystem::temp_directory_path() / (stem + ".bin");
    const auto alias = std::filesystem::temp_directory_path() / (stem + "_link.bin");
    const auto renamed = std::filesystem::temp_directory_path() / (stem + "_renamed.bin");
    {
        std::ofstream output(path, std::ios::binary);
        output << "original";
        TEST_CHECK(output.good());
    }
#ifdef _WIN32
    std::error_code error;
    std::filesystem::create_hard_link(path, alias, error);
    TEST_CHECK(!error);
    {
        auto opened = FileReader::open_stable(path.wstring());
        TEST_OK(opened, "stable source open");
        if (opened.ok()) {
            auto reader = opened.take();
            TEST_CHECK(!opened.value().is_open());
            auto original = reader.identity();
            TEST_OK(original, "stable handle identity");
            auto linked = FileReader::open(alias.wstring());
            TEST_OK(linked, "hard-link reader");
            if (original.ok() && linked.ok()) {
                auto second = linked.value().identity();
                TEST_OK(second, "alias handle identity");
                if (second.ok())
                    TEST_CHECK(original.value().same_file(second.value()));
                TEST_EQ(original.value().size, 8u, "identity includes handle size");
            }
            {
                std::ofstream writer(path, std::ios::binary | std::ios::trunc);
                TEST_CHECK(!writer.is_open());
            }
            {
                std::ofstream writer(alias, std::ios::binary | std::ios::trunc);
                TEST_CHECK(!writer.is_open());
            }
            std::filesystem::rename(path, renamed, error);
            TEST_CHECK(bool(error));
            error.clear();
            std::filesystem::remove(path, error);
            TEST_CHECK(bool(error));
            uint8_t first = 0;
            TEST_OK(reader.read_at(0, &first, 1), "source survives refused mutations");
            TEST_EQ(first, uint8_t{'o'}, "source byte unchanged");
            auto after = reader.identity();
            TEST_OK(after, "identity after refused mutations");
            if (original.ok() && after.ok()) {
                TEST_CHECK(original.value().same_file(after.value()));
                TEST_EQ(original.value().last_write, after.value().last_write,
                        "write time unchanged");
            }
        }
    }
    {
        std::fstream writer(path, std::ios::binary | std::ios::in | std::ios::out);
        TEST_CHECK(writer.is_open());
        auto rejected = FileReader::open_stable(path.wstring());
        TEST_ERROR(rejected, ErrorKind::kIo, "FileReader.open", "refuse active writer");
    }
    {
        std::ofstream writer(path, std::ios::binary | std::ios::trunc);
        TEST_CHECK(writer.is_open());
        writer << "replacement";
    }
    std::filesystem::remove(alias, error);
    TEST_CHECK(!error);
    std::filesystem::remove(path, error);
    TEST_CHECK(!error);
    // Only removes the unique test-owned alternate path if a failed assertion let rename succeed.
    std::filesystem::remove(renamed, error);
#else
    auto refused = FileReader::open_stable(path.wstring());
    TEST_ERROR(refused, ErrorKind::kUnsupported, "FileReader.open_stable",
               "explicit platform limit");
    std::error_code error;
    std::filesystem::remove(path, error);
#endif
}
} // namespace

int main() {
    check_closed_handle();
    check_identity_and_lock();
    return ost2pst::test::finish("file_identity_test");
}
