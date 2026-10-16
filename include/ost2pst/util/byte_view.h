#pragma once

#include <cstddef>
#include <cstdint>

#include "ost2pst/util/status.h"

namespace ost2pst::util {

// A window of bytes plus the absolute file offset it came from, so every error can report an
// absolute offset instead of a buffer-relative one.
class ByteView {
public:
    ByteView() = default;
    ByteView(const uint8_t *data, size_t size, uint64_t base = 0)
        : data_(data), size_(size), base_(base) {}

    const uint8_t *data() const { return data_; }
    size_t size() const { return size_; }
    uint64_t base() const { return base_; }
    bool empty() const { return size_ == 0; }

    bool in_range(uint64_t offset, size_t length) const {
        return offset < size_ && length <= size_ - offset;
    }

    Result<uint8_t> u8(uint64_t offset) const { return read_le<uint8_t>(offset, 1); }
    Result<uint16_t> u16(uint64_t offset) const { return read_le<uint16_t>(offset, 2); }
    Result<uint32_t> u32(uint64_t offset) const { return read_le<uint32_t>(offset, 4); }
    Result<uint64_t> u64(uint64_t offset) const { return read_le<uint64_t>(offset, 8); }

    Result<ByteView> sub(uint64_t offset, size_t length) const {
        if (!in_range(offset, length)) {
            return truncated(offset, length);
        }
        return ByteView(data_ + offset, length, base_ + offset);
    }

private:
    template <class T>
    Result<T> read_le(uint64_t offset, size_t width) const {
        if (!in_range(offset, width)) {
            return truncated(offset, width);
        }
        T value = 0;
        for (size_t i = 0; i < width; ++i) {
            value = static_cast<T>(value | (static_cast<T>(data_[offset + i]) << (8u * i)));
        }
        return value;
    }

    DataError truncated(uint64_t offset, size_t length) const {
        return make_error(ErrorKind::kTruncated, "ByteView.read", base_ + offset, length,
                          "read runs past the end of the view");
    }

    const uint8_t *data_ = nullptr;
    size_t size_ = 0;
    uint64_t base_ = 0;
};

} // namespace ost2pst::util
