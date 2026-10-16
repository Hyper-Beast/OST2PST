#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "ost2pst/util/file_writer.h"

namespace ost2pst::util {

// Immutable bytes with owned lifetime. Readers request bounded windows; this abstraction
// carries no source-format identifiers and is shared through extraction/emission/planning.
class ByteSource {
  public:
    virtual ~ByteSource() = default;
    virtual uint64_t size() const = 0;
    virtual Status read_at(uint64_t offset, uint8_t* data, size_t count) const = 0;
};
using SharedBytes = std::shared_ptr<const ByteSource>;
struct StoredValue {
    std::vector<uint8_t> bytes;
    SharedBytes source;
    uint64_t size() const { return source ? source->size() : bytes.size(); }
};
using ByteConsumer = std::function<Status(ByteView)>;
using ByteProducer = std::function<Status(const ByteConsumer&)>;

// One item's scratch storage. The backing file is created lazily, exclusively and with
// delete-on-close; captured ranges keep it alive. A failed producer never returns a value.
class ValueSpool {
  public:
    explicit ValueSpool(std::wstring directory, uint64_t resident_budget = 4 * 1024 * 1024,
                        uint64_t value_limit = 64 * 1024);
    // Injectable scratch I/O for short-write/disk-full/late-read tests.
    explicit ValueSpool(std::shared_ptr<RandomAccessFile> file,
                        uint64_t resident_budget = 4 * 1024 * 1024,
                        uint64_t value_limit = 64 * 1024);
    Result<StoredValue> capture(const ByteProducer& producer);
    uint64_t resident_bytes() const { return resident_bytes_; }
    uint64_t spilled_bytes() const { return file_ ? file_->size() : 0; }
    const std::optional<DataError>& io_error() const { return io_error_; }

  private:
    Status ensure_file();
    std::wstring directory_;
    std::shared_ptr<RandomAccessFile> file_;
    uint64_t resident_budget_, value_limit_, resident_bytes_ = 0;
    std::optional<DataError> io_error_;
};

} // namespace ost2pst::util
