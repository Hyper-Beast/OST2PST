#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "ost2pst/util/status.h"

namespace ost2pst::util {

// Cumulative allocation reservations for one bounded operation. Callers include construction
// copies and container growth in their charge; this is not a measurement of process RSS.
class ByteBudget {
  public:
    explicit ByteBudget(uint64_t limit) : limit_(limit) {}
    Status reserve(uint64_t count, const char* field, uint64_t offset = 0) {
        if (error_)
            return *error_;
        if (count > limit_ - used_) {
            error_ = make_error(ErrorKind::kUnsupported, field, offset, count,
                                "operation exceeds its engineering workspace budget (used=" +
                                    std::to_string(used_) + ", limit=" + std::to_string(limit_) +
                                    ", requested=" + std::to_string(count) + " bytes)");
            return *error_;
        }
        used_ += count;
        return {};
    }
    uint64_t used() const { return used_; }
    uint64_t remaining() const { return limit_ - used_; }
    const std::optional<DataError>& error() const { return error_; }

  private:
    uint64_t limit_, used_ = 0;
    std::optional<DataError> error_;
};
} // namespace ost2pst::util
