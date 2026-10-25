#include <array>
#include <filesystem>
#include <vector>

#include "ost2pst/util/workspace.h"

#include "test_support.h"

using namespace ost2pst::util;
namespace {
class FaultFile final : public RandomAccessFile {
  public:
    std::vector<uint8_t> bytes;
    bool read_failure = false, write_failure = false, resize_failure = false;
    uint64_t size() const override { return bytes.size(); }
    Status read_at(uint64_t offset, uint8_t* target, size_t count) const override {
        if (read_failure)
            return make_error(ErrorKind::kIo, "test.scratch_read", offset, count);
        if (offset > bytes.size() || count > bytes.size() - offset)
            return make_error(ErrorKind::kTruncated, "test.scratch_range", offset, count);
        std::copy_n(bytes.data() + offset, count, target);
        return {};
    }
    Result<size_t> write_some(uint64_t offset, ByteView input) override {
        if (write_failure)
            return make_error(ErrorKind::kIo, "test.scratch_write", offset);
        const auto count = std::min<size_t>(7, input.size());
        bytes.resize(std::max<uint64_t>(bytes.size(), offset + count));
        std::copy_n(input.data(), count, bytes.data() + offset);
        return count;
    }
    Status resize(uint64_t size) override {
        if (resize_failure)
            return make_error(ErrorKind::kIo, "test.scratch_resize", size);
        bytes.resize(size);
        return {};
    }
    Status flush() override { return {}; }
};
void check_failures_and_pressure() {
    auto resources = std::make_shared<Workspace>(std::filesystem::temp_directory_path().wstring(),
                                                 4 * SpillBuffer::kPage);
    {
        SpillBuffer buffer(resources);
        TEST_OK(buffer.resize(2 * SpillBuffer::kPage), "resident before pressure");
        resources->memory->set_target(0);
        const uint8_t byte = 23;
        TEST_OK(buffer.write_at(19, ByteView(&byte, 1)), "pressure spills existing contents");
        TEST_CHECK(buffer.spilled());
        TEST_EQ(resources->memory->used(), 0u, "zero target disables resident page cache");
        uint8_t actual = 0;
        TEST_OK(buffer.read_at(19, &actual, 1), "pressure preserves bytes");
        TEST_EQ(actual, byte, "value after cache shrink");
    }
    for (int mode = 0; mode < 3; ++mode) {
        auto file = std::make_shared<FaultFile>();
        SpillBuffer buffer(resources, file);
        const uint8_t value = 42;
        if (mode == 0)
            file->resize_failure = true;
        if (mode == 1)
            file->write_failure = true;
        auto wrote = buffer.append(ByteView(&value, 1));
        if (mode < 2) {
            TEST_CHECK(!wrote.ok() && wrote.error().kind == ErrorKind::kIo);
            TEST_CHECK(!buffer.append(ByteView(&value, 1)).ok());
        } else {
            TEST_OK(wrote, "partial scratch writes retried");
            file->read_failure = true;
            uint8_t actual = 0;
            TEST_ERROR(buffer.read_at(0, &actual, 1), ErrorKind::kIo, "test.scratch_read",
                       "late scratch read fatal");
            TEST_CHECK(!buffer.append(ByteView(&value, 1)).ok());
        }
    }
}
void check_pages(uint64_t limit) {
    auto resources =
        std::make_shared<Workspace>(std::filesystem::temp_directory_path().wstring(), limit);
    auto pool = resources->memory;
    {
        SpillBuffer first(resources), second(resources);
        std::vector<uint8_t> expected(5 * SpillBuffer::kPage + 713);
        for (size_t index = 0; index < expected.size(); ++index)
            expected[index] = static_cast<uint8_t>((index * 31 + index / 997) % 251);
        // Append across pages with partial final pages and repeated growth.
        for (size_t offset = 0; offset < expected.size(); offset += 137) {
            const auto count = std::min<size_t>(137, expected.size() - offset);
            TEST_OK(first.append(ByteView(expected.data() + offset, count)),
                    "append scratch bytes");
        }
        TEST_OK(second.resize(3 * SpillBuffer::kPage), "competing buffer");
        std::vector<uint8_t> actual(expected.size());
        TEST_OK(first.read_at(0, actual.data(), actual.size()), "reread spilled pages");
        TEST_CHECK(actual == expected);
        const std::array<uint8_t, 7> patch{2, 3, 5, 7, 11, 13, 17};
        const size_t start = SpillBuffer::kPage - 3;
        TEST_OK(first.write_at(start, ByteView(patch.data(), patch.size())), "patch crosses page");
        std::copy(patch.begin(), patch.end(), expected.begin() + start);
        TEST_OK(first.read_at(0, actual.data(), actual.size()), "reread patched pages");
        TEST_CHECK(actual == expected);
        TEST_CHECK(first.spilled());
        TEST_CHECK(pool->used() <= limit);
        TEST_CHECK(pool->peak() <= limit);
        TEST_CHECK(resources->spilled_bytes >= expected.size());
    }
    TEST_EQ(pool->used(), 0u, "all cache leases released with owners");
    {
        SpillArray<uint64_t> records(resources);
        TEST_OK(records.resize(20000), "zero initialized records");
        for (uint64_t index = 0; index < records.size(); ++index) {
            TEST_EQ(records.get(index), 0u, "new records initialized");
            TEST_OK(records.set(index, index * 71), "set record");
        }
        for (uint64_t index = records.size(); index-- > 0;)
            TEST_EQ(records.get(index), index * 71, "reverse page access");
        TEST_OK(records.status(), "array reads preserve status");
    }
    TEST_EQ(pool->used(), 0u, "array releases cache");
    SharedBytes retained;
    {
        ValueSpool spool(resources);
        const std::array<uint8_t, 5> bytes{9, 8, 7, 6, 5};
        auto captured = spool.capture([&](const ByteConsumer& consume) {
            return consume(ByteView(bytes.data(), bytes.size()));
        });
        TEST_OK(captured, "shared value spool");
        if (captured.ok())
            retained = captured.value().source;
    }
    TEST_CHECK(retained);
    if (retained) {
        std::array<uint8_t, 5> actual{};
        TEST_OK(retained->read_at(0, actual.data(), actual.size()), "range outlives spool");
        TEST_CHECK((actual == std::array<uint8_t, 5>{9, 8, 7, 6, 5}));
    }
    retained.reset();
    TEST_EQ(pool->used(), 0u, "range releases retained scratch");
}
} // namespace
int main() {
    TEST_EQ(automatic_memory_limit(0), 256ull << 20, "detection failure fallback");
    TEST_EQ(automatic_memory_limit(16ull << 30), (16ull << 30) / 10, "available memory fraction");
    TEST_EQ(automatic_memory_limit(128ull << 30), 2ull << 30, "automatic ceiling");
    check_pages(0);
    check_pages(SpillBuffer::kPage);
    check_pages(3 * SpillBuffer::kPage);
    check_failures_and_pressure();
    return ost2pst::test::finish("workspace_test");
}
