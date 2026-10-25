#pragma once

#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

#include "ost2pst/util/value_spool.h"

namespace ost2pst::util {

// Single-threaded managed resident workspace accounting, not a process working-set limit.
// Leases follow storage lifetime, including sources retained by a returned plan.
class MemoryPool {
  public:
    explicit MemoryPool(uint64_t limit) : limit_(limit), target_(limit) {}
    bool acquire(uint64_t bytes) {
        if (bytes == 0)
            return true;
        if (used_ > target_ || bytes > target_ - used_)
            return false;
        used_ += bytes;
        peak_ = std::max(peak_, used_);
        return true;
    }
    void release(uint64_t bytes) { used_ -= bytes; }
    uint64_t limit() const { return limit_; }
    uint64_t used() const { return used_; }
    uint64_t peak() const { return peak_; }
    uint64_t target() const { return target_; }
    void set_target(uint64_t bytes) { target_ = std::min(bytes, limit_); }

  private:
    uint64_t limit_, target_, used_ = 0, peak_ = 0;
};

class MemoryReservation {
  public:
    explicit MemoryReservation(std::shared_ptr<MemoryPool> pool) : pool_(std::move(pool)) {}
    ~MemoryReservation() { pool_->release(charged_); }
    MemoryReservation(const MemoryReservation&) = delete;
    MemoryReservation& operator=(const MemoryReservation&) = delete;
    Status reserve(uint64_t bytes, const char* field) {
        if (!pool_->acquire(bytes))
            return make_error(ErrorKind::kUnsupported, field, 0, bytes,
                              "resident metadata exceeds the shared memory allowance (used=" +
                                  std::to_string(pool_->used()) +
                                  ", limit=" + std::to_string(pool_->target()) +
                                  ", requested=" + std::to_string(bytes) + " bytes)");
        charged_ += bytes;
        return {};
    }

  private:
    std::shared_ptr<MemoryPool> pool_;
    uint64_t charged_ = 0;
};

// Ten percent of available memory, clamped to 256 MiB..2 GiB; zero means
// detection failed and selects the conservative minimum. Never grows with input size.
uint64_t automatic_memory_limit(uint64_t available_bytes);
uint64_t available_physical_memory();

struct Workspace {
    explicit Workspace(std::wstring directory, uint64_t memory_bytes)
        : directory(std::move(directory)), memory(std::make_shared<MemoryPool>(memory_bytes)) {}
    std::wstring directory;
    std::shared_ptr<MemoryPool> memory;
    uint64_t spilled_bytes = 0;
    bool monitor_pressure = false; // full conversion enables cooperative cache shrink
    // In-process fault-injection seam; production uses exclusive temporary files.
    std::function<Result<std::shared_ptr<RandomAccessFile>>()> scratch_factory;
    void refresh();

  private:
    std::chrono::steady_clock::time_point last_check_{};
};

class SourceRange final : public ByteSource {
  public:
    SourceRange(SharedBytes source, uint64_t offset, uint64_t size)
        : source_(std::move(source)), offset_(offset), size_(size) {}
    uint64_t size() const override { return size_; }
    Status read_at(uint64_t offset, uint8_t* data, size_t count) const override {
        if (offset > size_ || count > size_ - offset)
            return make_error(ErrorKind::kTruncated, "scratch.range", offset, count);
        return source_->read_at(offset_ + offset, data, count);
    }

  private:
    SharedBytes source_;
    uint64_t offset_, size_;
};

// Growable private scratch bytes. Memory pages share one pool. On pressure the
// contents spill to an exclusive delete-on-close file; a single bounded page cache
// is used if the pool permits it. I/O errors are sticky and never become zero data.
class SpillBuffer final : public ByteSource {
  public:
    static constexpr size_t kPage = 64 * 1024;
    explicit SpillBuffer(std::shared_ptr<Workspace> workspace);
    SpillBuffer(std::shared_ptr<Workspace> workspace, std::shared_ptr<RandomAccessFile> file);
    ~SpillBuffer() override;
    SpillBuffer(const SpillBuffer&) = delete;
    SpillBuffer& operator=(const SpillBuffer&) = delete;
    uint64_t size() const override { return size_; }
    Status read_at(uint64_t offset, uint8_t* data, size_t count) const override;
    Status write_at(uint64_t offset, ByteView bytes);
    Status append(ByteView bytes) { return write_at(size_, bytes); }
    Status resize(uint64_t bytes);
    Status flush() const;
    Status spill_to_disk() { return spill(); }
    bool spilled() const { return bool(file_); }
    const Status& status() const { return status_; }

  private:
    Status spill();
    Status load(uint64_t page) const;
    Status fail(Status status) const;
    std::shared_ptr<Workspace> workspace_;
    std::vector<std::vector<uint8_t>> pages_;
    std::shared_ptr<RandomAccessFile> file_;
    uint64_t size_ = 0, charged_ = 0;
    mutable std::vector<uint8_t> cache_;
    mutable uint64_t cache_page_ = UINT64_MAX;
    mutable bool dirty_ = false;
    mutable Status status_;
};

// Fixed-width internal scratch records, never a PST or persistent journal layout.
// A sticky error is checked by the owner before exposing a constructed result.
template <class T> class SpillArray {
    static_assert(std::is_trivially_copyable_v<T>);

  public:
    explicit SpillArray(std::shared_ptr<Workspace> workspace)
        : bytes_(std::make_shared<SpillBuffer>(std::move(workspace))) {}
    uint64_t size() const { return bytes_->size() / sizeof(T); }
    Status resize(uint64_t count) {
        if (count > UINT64_MAX / sizeof(T))
            return make_error(ErrorKind::kUnsupported, "scratch.array_size", 0, count);
        return bytes_->resize(count * sizeof(T));
    }
    Status push_back(const T& value) {
        return bytes_->append(ByteView(reinterpret_cast<const uint8_t*>(&value), sizeof(T)));
    }
    T get(uint64_t index) const {
        T value{};
        const auto offset = index < size() ? index * sizeof(T) : bytes_->size();
        auto read = bytes_->read_at(offset, reinterpret_cast<uint8_t*>(&value), sizeof(T));
        (void)read; // read_at stores a sticky error, checked by the array owner
        return value;
    }
    Status set(uint64_t index, const T& value) {
        if (index >= size())
            return make_error(ErrorKind::kBadField, "scratch.array_index", index, size());
        return bytes_->write_at(index * sizeof(T),
                                ByteView(reinterpret_cast<const uint8_t*>(&value), sizeof(T)));
    }
    const Status& status() const { return bytes_->status(); }
    std::shared_ptr<SpillBuffer> bytes() const { return bytes_; }

  private:
    std::shared_ptr<SpillBuffer> bytes_;
};
} // namespace ost2pst::util
