#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <limits>
#include <memory>
#include <vector>

#include "ost2pst/util/value_spool.h"

#include "test_support.h"

namespace {
using namespace ost2pst::util;
class Scratch final : public RandomAccessFile {
  public:
    std::vector<uint8_t> bytes;
    bool fail_write = false, fail_read = false;
    uint64_t size() const override { return bytes.size(); }
    Status read_at(uint64_t offset, uint8_t* data, size_t count) const override {
        if (fail_read)
            return make_error(ErrorKind::kIo, "test.scratch_read", offset, count);
        if (offset > bytes.size() || count > bytes.size() - offset)
            return make_error(ErrorKind::kTruncated, "test.scratch_range", offset, count);
        std::memcpy(data, bytes.data() + offset, count);
        return {};
    }
    Result<size_t> write_some(uint64_t offset, ByteView part) override {
        if (fail_write)
            return make_error(ErrorKind::kIo, "test.scratch_write", offset, part.size());
        const size_t count = std::min<size_t>(7, part.size());
        bytes.resize(static_cast<size_t>(offset) + count);
        std::memcpy(bytes.data() + offset, part.data(), count);
        return count;
    }
    Status resize(uint64_t size) override {
        bytes.resize(static_cast<size_t>(size));
        return {};
    }
    Status flush() override { return {}; }
};
ByteProducer producer(uint64_t count, uint8_t fill) {
    return [=](const ByteConsumer& consume) -> Status {
        const std::array<uint8_t, 17> pattern = [=] {
            std::array<uint8_t, 17> value{};
            value.fill(fill);
            return value;
        }();
        for (uint64_t offset = 0; offset < count;) {
            const auto chunk =
                static_cast<size_t>(std::min<uint64_t>(pattern.size(), count - offset));
            auto wrote = consume(ByteView(pattern.data(), chunk));
            if (!wrote.ok())
                return wrote;
            offset += chunk;
        }
        return {};
    };
}
void check_capture() {
    auto file = std::make_shared<Scratch>();
    SharedBytes retained;
    {
        ValueSpool spool(file, 80, 40);
        auto small = spool.capture(producer(30, 0x11));
        TEST_OK(small, "small value stays resident");
        if (small.ok()) {
            TEST_CHECK(!small.value().source);
            TEST_CHECK(small.value().bytes == std::vector<uint8_t>(30, 0x11));
        }
        auto large = spool.capture(producer(90, 0x22));
        TEST_OK(large, "large value spills through partial writes");
        if (large.ok()) {
            TEST_CHECK(large.value().bytes.empty());
            retained = large.value().source;
            TEST_CHECK(retained && retained->size() == 90);
        }
        auto next = spool.capture(producer(30, 0x33));
        TEST_OK(next, "second resident value");
        auto aggregate = spool.capture(producer(30, 0x44));
        TEST_OK(aggregate, "aggregate budget spills a small value");
        if (aggregate.ok())
            TEST_CHECK(aggregate.value().source && aggregate.value().bytes.empty());
        TEST_EQ(spool.resident_bytes(), 60u, "retained bytes stay within aggregate budget");
        TEST_EQ(spool.spilled_bytes(), 120u, "spilled values have disjoint ranges");
    }
    std::vector<uint8_t> observed(90);
    TEST_CHECK(retained);
    if (retained) {
        TEST_OK(retained->read_at(0, observed.data(), observed.size()),
                "owned value outlives spool");
        TEST_CHECK(observed == std::vector<uint8_t>(90, 0x22));
        TEST_ERROR(retained->read_at(89, observed.data(), 2), ErrorKind::kTruncated, "spool.range",
                   "a read cannot spill into the next value");
        file->fail_read = true;
        TEST_ERROR(retained->read_at(0, observed.data(), 1), ErrorKind::kIo, "test.scratch_read",
                   "late scratch I/O remains fatal");
    }
    auto full = std::make_shared<Scratch>();
    full->fail_write = true;
    ValueSpool failed(full, 0, 0);
    TEST_ERROR(failed.capture(producer(90, 0x55)), ErrorKind::kIo, "test.scratch_write",
               "disk full does not return partial content");
    TEST_CHECK(failed.io_error().has_value());
    TEST_ERROR(failed.capture(producer(1, 0x66)), ErrorKind::kIo, "test.scratch_write",
               "failed scratch sessions cannot resume writes");
    auto source_failure = std::make_shared<Scratch>();
    ValueSpool spool(source_failure, 0, 0);
    TEST_ERROR(spool.capture([](const ByteConsumer& consume) -> Status {
        const std::array<uint8_t, 3> value{1, 2, 3};
        auto accepted = consume(ByteView(value.data(), value.size()));
        if (!accepted.ok())
            return accepted;
        return make_error(ErrorKind::kBadCrc, "test.source_crc", 123, 0);
    }),
               ErrorKind::kBadCrc, "test.source_crc",
               "source failure never returns an owned range");
    TEST_CHECK(!spool.io_error());
    TEST_OK(spool.capture(producer(5, 0x77)), "a later value can follow a corrupt source value");
    TEST_OK(spool.capture([](const ByteConsumer& consume) { return consume(ByteView{}); }),
            "empty producer chunk is valid");
    auto ignored_failure = std::make_shared<Scratch>();
    ignored_failure->fail_write = true;
    ValueSpool guarded(ignored_failure, 0, 0);
    TEST_ERROR(guarded.capture([](const ByteConsumer& consume) -> Status {
        const uint8_t byte = 1;
        (void)consume(ByteView(&byte, 1));
        return {};
    }),
               ErrorKind::kIo, "test.scratch_write", "producer cannot hide a consumer failure");
}
void check_temporary_lifetime() {
    const auto path = std::filesystem::temp_directory_path() / "ost2pst_value_spool_lifetime.tmp";
    std::filesystem::remove(path);
    {
        auto opened = FileWriter::create_temporary(path.wstring());
        TEST_OK(opened, "exclusive delete-on-close file");
        if (!opened.ok())
            return;
        auto file = opened.take();
        const std::array<uint8_t, 4> bytes{0, 1, 0xFE, 0xFF};
        TEST_OK(write_all(file, 0, ByteView(bytes.data(), bytes.size())), "temporary bytes");
        std::array<uint8_t, 4> observed{};
        TEST_OK(file.read_at(0, observed.data(), observed.size()), "temporary bounded read");
        TEST_CHECK(observed == bytes);
        TEST_CHECK(!FileWriter::create_temporary(path.wstring()).ok());
    }
    TEST_CHECK(!std::filesystem::exists(path));
}
} // namespace
int main() {
    check_capture();
    check_temporary_lifetime();
    return ost2pst::test::finish("value_spool_test");
}
