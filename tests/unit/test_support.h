#pragma once

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

#include "ost2pst/util/status.h"
#include "test_paths.h"

namespace ost2pst::test {

inline int &failure_count() {
    static int count = 0;
    return count;
}

inline void report_failure(const char *file, int line, const std::string &what) {
    ++failure_count();
    std::printf("  FAIL %s:%d %s\n", file, line, what.c_str());
}

inline void report_mismatch(const char *file, int line, const std::string &label,
                            unsigned long long actual, unsigned long long expected) {
    ++failure_count();
    std::printf("  FAIL %s:%d %s: actual=0x%llX expected=0x%llX\n", file, line, label.c_str(), actual,
                expected);
}

inline int finish(const char *name) {
    const int failed = failure_count();
    if (failed == 0) {
        std::printf("PASS %s\n", name);
        return 0;
    }
    std::printf("FAIL %s: %d failed check(s)\n", name, failed);
    return 1;
}

inline std::string fixture_path(const char *name) {
    return std::string(OST2PST_FIXTURE_DIR) + "/" + name;
}

inline std::string golden_path(const char *name) {
    return std::string(OST2PST_GOLDEN_DIR) + "/" + name;
}

inline std::vector<uint8_t> read_bytes(const std::string &path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        report_failure(__FILE__, __LINE__, "cannot open " + path);
        return {};
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(stream)),
                                std::istreambuf_iterator<char>());
}

inline std::string read_text(const std::string &path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        report_failure(__FILE__, __LINE__, "cannot open " + path);
        return {};
    }
    return std::string((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
}

// Golden files are flat one-level JSON with quoted-string values, so the tests need no JSON library.
inline std::optional<std::string> golden_value(const std::string &text, const std::string &key) {
    const std::string needle = "\"" + key + "\"";
    size_t at = text.find(needle);
    if (at == std::string::npos) {
        return {};
    }
    at = text.find(':', at + needle.size());
    if (at == std::string::npos) {
        return {};
    }
    ++at;
    while (at < text.size() && (text[at] == ' ' || text[at] == '\t' || text[at] == '\n' ||
                                text[at] == '\r')) {
        ++at;
    }
    if (at >= text.size()) {
        return {};
    }
    if (text[at] == '"') {
        const size_t end = text.find('"', at + 1);
        if (end == std::string::npos) {
            return {};
        }
        return text.substr(at + 1, end - at - 1);
    }
    size_t end = at;
    while (end < text.size() && (std::isalnum(static_cast<unsigned char>(text[end])) ||
                                 text[end] == 'x' || text[end] == 'X' || text[end] == '-' ||
                                 text[end] == '+' || text[end] == '.')) {
        ++end;
    }
    return text.substr(at, end - at);
}

inline uint64_t golden_number(const std::string &text, const std::string &key) {
    const std::optional<std::string> value = golden_value(text, key);
    if (!value) {
        report_failure(__FILE__, __LINE__, "golden key missing: " + key);
        return 0;
    }
    return static_cast<uint64_t>(std::strtoull(value->c_str(), nullptr, 0));
}

} // namespace ost2pst::test

#define TEST_CHECK(condition)                                                                            \
    do {                                                                                                 \
        if (!(condition)) {                                                                              \
            ::ost2pst::test::report_failure(__FILE__, __LINE__, "check failed: " #condition);           \
        }                                                                                                \
    } while (false)

// TEST_CHECK takes one argument; a check that wants to name itself needs this one.
#define TEST_CHECK_MSG(condition, label)                                                                 \
    do {                                                                                                 \
        if (!(condition)) {                                                                              \
            ::ost2pst::test::report_failure(__FILE__, __LINE__, label);                                  \
        }                                                                                                \
    } while (false)

#define TEST_EQ(actual, expected, label)                                                                 \
    do {                                                                                                 \
        const unsigned long long test_actual = static_cast<unsigned long long>(actual);                  \
        const unsigned long long test_expected = static_cast<unsigned long long>(expected);              \
        if (test_actual != test_expected) {                                                              \
            ::ost2pst::test::report_mismatch(__FILE__, __LINE__, label, test_actual, test_expected);     \
        }                                                                                                \
    } while (false)

#define TEST_STR(actual, expected, label)                                                                \
    do {                                                                                                 \
        const std::string test_actual = (actual);                                                        \
        const std::string test_expected = (expected);                                                    \
        if (test_actual != test_expected) {                                                              \
            ::ost2pst::test::report_failure(__FILE__, __LINE__,                                          \
                                            std::string(label) + " text mismatch: actual=\"" +           \
                                                test_actual + "\" expected=\"" + test_expected + "\"");   \
        }                                                                                                \
    } while (false)

#define TEST_OK(result, label)                                                                           \
    do {                                                                                                 \
        const auto &test_result = (result);                                                              \
        if (!test_result.ok()) {                                                                         \
            ::ost2pst::test::report_failure(__FILE__, __LINE__,                                          \
                                            std::string(label) + " unexpectedly failed: " +              \
                                                ::ost2pst::util::format_error(test_result.error()));     \
        }                                                                                                \
    } while (false)

// The macro parameters must not collide with the DataError member names they are compared against:
// a parameter called `field` would rewrite `test_result.error().field` into the argument.
#define TEST_ERROR(expression, expected_kind, expected_field, label)                                     \
    do {                                                                                                 \
        const auto &test_result = (expression);                                                          \
        if (test_result.ok()) {                                                                          \
            ::ost2pst::test::report_failure(__FILE__, __LINE__, std::string(label) + " unexpectedly ok"); \
        } else if (test_result.error().kind != (expected_kind)) {                                        \
            ::ost2pst::test::report_failure(__FILE__, __LINE__,                                          \
                                            std::string(label) + " wrong kind: " +                       \
                                                ::ost2pst::util::error_kind_name(test_result.error().kind)); \
        } else if (test_result.error().field != (expected_field)) {                                      \
            ::ost2pst::test::report_failure(__FILE__, __LINE__,                                          \
                                            std::string(label) + " wrong field: " +                      \
                                                test_result.error().field);                              \
        }                                                                                                \
    } while (false)

#define TEST_ERROR_OFFSET(expression, expected_offset, label)                                            \
    do {                                                                                                 \
        const auto &test_result = (expression);                                                          \
        if (test_result.ok()) {                                                                          \
            ::ost2pst::test::report_failure(__FILE__, __LINE__, std::string(label) + " unexpectedly ok"); \
        } else if (test_result.error().offset != static_cast<uint64_t>(expected_offset)) {               \
            ::ost2pst::test::report_mismatch(__FILE__, __LINE__, std::string(label) + " error offset",    \
                                             test_result.error().offset,                                 \
                                             static_cast<uint64_t>(expected_offset));                    \
        }                                                                                                \
    } while (false)
