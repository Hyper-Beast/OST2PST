#pragma once

#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <utility>

namespace ost2pst::util {

// Every failure that comes out of parsed bytes is a data error, never an exception
// (DEVELOPMENT.md).
enum class ErrorKind {
    kIo,
    kTruncated,
    kBadField,
    kBadCrc,
    kBadSignature,
    kUnsupported,
};

inline const char *error_kind_name(ErrorKind kind) {
    switch (kind) {
    case ErrorKind::kIo:
        return "io";
    case ErrorKind::kTruncated:
        return "truncated";
    case ErrorKind::kBadField:
        return "bad-field";
    case ErrorKind::kBadCrc:
        return "bad-crc";
    case ErrorKind::kBadSignature:
        return "bad-signature";
    case ErrorKind::kUnsupported:
        return "unsupported";
    }
    return "unknown";
}

struct DataError {
    ErrorKind kind = ErrorKind::kIo;
    std::string field;   // record.field, e.g. "HEADER.bCryptMethod"
    uint64_t offset = 0; // absolute file offset the offending bytes live at
    uint64_t value = 0;  // offending value when it is numeric
    std::string detail;
};

inline DataError make_error(ErrorKind kind, std::string field, uint64_t offset, uint64_t value = 0,
                            std::string detail = {}) {
    return DataError{kind, std::move(field), offset, value, std::move(detail)};
}

inline std::string format_error(const DataError &error) {
    char number[64];
    std::snprintf(number, sizeof(number), "offset=0x%08llX value=0x%llX",
                  static_cast<unsigned long long>(error.offset),
                  static_cast<unsigned long long>(error.value));
    std::string text = std::string(error_kind_name(error.kind)) + " " + error.field + " " + number;
    if (!error.detail.empty()) {
        text += " [" + error.detail + "]";
    }
    return text;
}

class Status {
public:
    Status() = default;
    Status(DataError error) : error_(std::move(error)) {}

    bool ok() const { return !error_.has_value(); }
    explicit operator bool() const { return ok(); }
    const DataError &error() const { return *error_; }

private:
    std::optional<DataError> error_;
};

template <class T>
class Result {
public:
    Result(T value) : value_(std::move(value)) {}
    Result(DataError error) : error_(std::move(error)) {}

    bool ok() const { return !error_.has_value(); }
    explicit operator bool() const { return ok(); }
    const T &value() const { return *value_; }
    T take() { return std::move(*value_); }
    const DataError &error() const { return *error_; }

private:
    std::optional<T> value_;
    std::optional<DataError> error_;
};

} // namespace ost2pst::util
