#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ost2pst::gui {
inline constexpr size_t kMaxJsonBytes = 1024 * 1024;
inline constexpr size_t kMaxDiagnosticBytes = 256 * 1024;
inline constexpr size_t kMaxQueuedEvents = 64;
struct Json {
    enum class Kind { kNull, kBoolean, kNumber, kString, kObject, kArray } kind = Kind::kNull;
    std::string text;
    std::map<std::string, Json> object;
    std::vector<Json> array;
    const Json* at(std::string_view key) const;
    std::optional<uint64_t> uint_value() const;
    std::optional<uint64_t> uint_at(std::string_view key) const;
    std::string string_at(std::string_view key) const;
    bool operator==(const Json&) const = default;
};
std::optional<Json> parse_json(std::string_view text);
std::string json_quote(std::string_view text);
std::optional<Json> read_report(const std::wstring& path);
struct Counts {
    uint64_t terminal = 0, normal = 0, fai = 0, skipped = 0;
};
struct Summary {
    std::string status;
    uint64_t exit_code = 1, folders = 0, items = 0, bytes = 0;
    Counts counts;
    Json document;
};
std::optional<Summary> decode_summary(const Json& value);
enum class Verdict { kComplete, kIncomplete, kFailed, kStopped };
// One reducer owns wire validation and the final report/exit reconciliation.
struct Session {
    bool started = false, terminal = false, broken = false, error_seen = false;
    std::string phase = "identity", error_kind, error_scope, error_detail;
    Counts counts;
    std::optional<uint64_t> total;
    std::optional<Summary> result;
    uint64_t result_exit = 1;
    std::string result_status;
    bool consume(std::string_view line);
    Verdict finish(uint32_t exit_code, bool stop_observed, const std::optional<Json>& report) const;
};
std::wstring quote_argument(std::wstring_view value);
std::string resolve_locale(const std::vector<std::wstring>& preferred);
} // namespace ost2pst::gui
