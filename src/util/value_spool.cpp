#include "ost2pst/util/value_spool.h"

#include <algorithm>
#include <filesystem>
#include <limits>
#include <random>

#include "ost2pst/util/workspace.h"

namespace ost2pst::util {
ValueSpool::ValueSpool(std::shared_ptr<Workspace> workspace)
    : resident_budget_(0), value_limit_(0),
      shared_spool_(std::make_shared<SpillBuffer>(std::move(workspace))) {}
Status ValueSpool::spill_shared_cache() {
    return shared_spool_ ? shared_spool_->spill_to_disk() : Status{};
}
namespace {
class FileRange final : public ByteSource {
  public:
    FileRange(std::shared_ptr<RandomAccessFile> file, uint64_t offset, uint64_t size)
        : file_(std::move(file)), offset_(offset), size_(size) {}
    uint64_t size() const override { return size_; }
    Status read_at(uint64_t offset, uint8_t* data, size_t count) const override {
        if (offset > size_ || count > size_ - offset)
            return make_error(ErrorKind::kTruncated, "spool.range", offset, count,
                              "read exceeds the captured value");
        return file_->read_at(offset_ + offset, data, count);
    }

  private:
    std::shared_ptr<RandomAccessFile> file_;
    uint64_t offset_, size_;
};
} // namespace

ValueSpool::ValueSpool(std::wstring directory, uint64_t resident_budget, uint64_t value_limit)
    : directory_(std::move(directory)), resident_budget_(resident_budget),
      value_limit_(value_limit) {}
ValueSpool::ValueSpool(std::shared_ptr<RandomAccessFile> file, uint64_t resident_budget,
                       uint64_t value_limit)
    : file_(std::move(file)), resident_budget_(resident_budget), value_limit_(value_limit) {}

Status ValueSpool::ensure_file() {
    if (file_)
        return {};
    std::random_device random;
    const auto name =
        L"scratch-" + std::to_wstring(random()) + L"-" + std::to_wstring(random()) + L".tmp";
    auto opened =
        FileWriter::create_temporary((std::filesystem::path(directory_) / name).wstring());
    if (!opened.ok())
        return opened.error();
    file_ = std::make_shared<FileWriter>(opened.take());
    return {};
}

Result<StoredValue> ValueSpool::capture(const ByteProducer& producer) {
    if (io_error_)
        return *io_error_;
    if (!producer)
        return make_error(ErrorKind::kBadField, "spool.producer", 0, 0);
    if (shared_spool_) {
        const uint64_t start = shared_spool_->size();
        Status consumer_status;
        auto produced = producer([&](ByteView bytes) -> Status {
            if (!consumer_status.ok())
                return consumer_status;
            if (bytes.size() > UINT32_MAX - (shared_spool_->size() - start))
                consumer_status =
                    make_error(ErrorKind::kUnsupported, "spool.value_size", start, bytes.size());
            else
                consumer_status = shared_spool_->append(bytes);
            return consumer_status;
        });
        if (!consumer_status.ok())
            produced = consumer_status;
        if (!produced.ok()) {
            if (produced.error().kind == ErrorKind::kIo)
                io_error_ = produced.error();
            return produced.error();
        }
        StoredValue result;
        if (shared_spool_->size() != start)
            result.source =
                std::make_shared<SourceRange>(shared_spool_, start, shared_spool_->size() - start);
        return result;
    }
    StoredValue result;
    const uint64_t limit = std::min(value_limit_, resident_budget_ - resident_bytes_);
    uint64_t offset = 0, total = 0;
    bool spilled = false;
    std::optional<DataError> consumer_error;
    const ByteConsumer append = [&](ByteView part) -> Status {
        if (part.empty())
            return {};
        if (part.size() > std::numeric_limits<uint32_t>::max() - total)
            return make_error(ErrorKind::kUnsupported, "spool.value_size", total, part.size(),
                              "value exceeds the writer's DWORD stream length");
        if (!spilled && part.size() <= limit - total) {
            result.bytes.insert(result.bytes.end(), part.data(), part.data() + part.size());
            total += part.size();
            return {};
        }
        if (!spilled) {
            auto created = ensure_file();
            if (!created.ok())
                return created;
            offset = file_->size();
            auto initial =
                write_all(*file_, offset, ByteView(result.bytes.data(), result.bytes.size()));
            if (!initial.ok())
                return initial;
            std::vector<uint8_t>().swap(result.bytes);
            spilled = true;
        }
        auto wrote = write_all(*file_, offset + total, part);
        if (!wrote.ok())
            return wrote;
        total += part.size();
        return {};
    };
    const ByteConsumer consume = [&](ByteView part) -> Status {
        if (consumer_error)
            return *consumer_error;
        auto result = append(part);
        if (!result.ok())
            consumer_error = result.error();
        return result;
    };
    auto produced = producer(consume);
    if (consumer_error)
        produced = Status(*consumer_error);
    if (!produced.ok()) {
        if (produced.error().kind == ErrorKind::kIo)
            io_error_ = produced.error();
        return produced.error();
    }
    if (spilled) {
        result.source = std::make_shared<FileRange>(file_, offset, total);
    } else {
        resident_bytes_ += total;
    }
    return result;
}
} // namespace ost2pst::util
