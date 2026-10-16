#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "ost2pst/util/status.h"

namespace ost2pst::ndb {

// One finding, always with the absolute file offset it was found at.
struct ProbeFailure {
    uint64_t offset = 0;
    std::string field;
    uint64_t value = 0;
    std::string detail;
};

// A corrupt file can produce millions of findings while still being walkable, so the walk keeps
// counting and only retains the first few for display.
class FailureLog {
public:
    explicit FailureLog(size_t max_kept = 10) : max_kept_(max_kept) {}

    void add(uint64_t offset, const char *field, uint64_t value, const std::string &detail) {
        ++total_;
        if (failures_.size() < max_kept_) {
            failures_.push_back(ProbeFailure{offset, field, value, detail});
        }
    }

    void add(const util::DataError &error) {
        add(error.offset, error.field.c_str(), error.value, error.detail);
    }

    uint64_t total() const { return total_; }
    size_t kept() const { return failures_.size(); }
    const std::vector<ProbeFailure> &failures() const { return failures_; }

private:
    size_t max_kept_ = 10;
    uint64_t total_ = 0;
    std::vector<ProbeFailure> failures_;
};

} // namespace ost2pst::ndb
