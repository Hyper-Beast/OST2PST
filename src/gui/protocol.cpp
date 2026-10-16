#include "protocol.h"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <limits>

namespace ost2pst::gui {
namespace {
bool valid_utf8(std::string_view s) {
    for (size_t i = 0; i < s.size();) {
        uint32_t c = static_cast<unsigned char>(s[i++]);
        if (c < 128)
            continue;
        size_t n = 0;
        uint32_t minimum = 0;
        if (c >= 0xC2 && c <= 0xDF) {
            n = 1;
            c &= 31;
            minimum = 0x80;
        } else if (c >= 0xE0 && c <= 0xEF) {
            n = 2;
            c &= 15;
            minimum = 0x800;
        } else if (c >= 0xF0 && c <= 0xF4) {
            n = 3;
            c &= 7;
            minimum = 0x10000;
        } else
            return false;
        if (n > s.size() - i)
            return false;
        while (n--) {
            auto next = static_cast<unsigned char>(s[i++]);
            if ((next & 0xC0) != 0x80)
                return false;
            c = (c << 6) | (next & 63);
        }
        if (c < minimum || c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF))
            return false;
    }
    return true;
}
void append_utf8(std::string& s, uint32_t c) {
    if (c < 128)
        s += static_cast<char>(c);
    else if (c < 0x800) {
        s += static_cast<char>(0xC0 | (c >> 6));
        s += static_cast<char>(0x80 | (c & 63));
    } else if (c < 0x10000) {
        s += static_cast<char>(0xE0 | (c >> 12));
        s += static_cast<char>(0x80 | ((c >> 6) & 63));
        s += static_cast<char>(0x80 | (c & 63));
    } else {
        s += static_cast<char>(0xF0 | (c >> 18));
        s += static_cast<char>(0x80 | ((c >> 12) & 63));
        s += static_cast<char>(0x80 | ((c >> 6) & 63));
        s += static_cast<char>(0x80 | (c & 63));
    }
}
class Parser {
  public:
    explicit Parser(std::string_view s) : s_(s) {}
    std::optional<Json> parse() {
        auto v = value(0);
        space();
        return pos_ == s_.size() ? v : std::nullopt;
    }

  private:
    std::string_view s_;
    size_t pos_ = 0;
    void space() {
        while (pos_ < s_.size() &&
               (s_[pos_] == ' ' || s_[pos_] == '\n' || s_[pos_] == '\r' || s_[pos_] == '\t'))
            ++pos_;
    }
    bool take(char c) {
        space();
        if (pos_ == s_.size() || s_[pos_] != c)
            return false;
        ++pos_;
        return true;
    }
    std::optional<uint32_t> hex4() {
        if (s_.size() - pos_ < 4)
            return {};
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            const auto c = s_[pos_++];
            int h = c >= '0' && c <= '9'   ? c - '0'
                    : c >= 'a' && c <= 'f' ? c - 'a' + 10
                    : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                           : -1;
            if (h < 0)
                return {};
            v = v * 16 + static_cast<uint32_t>(h);
        }
        return v;
    }
    std::optional<std::string> string() {
        if (!take('"'))
            return {};
        std::string out;
        while (pos_ < s_.size()) {
            const auto c = s_[pos_++];
            if (c == '"')
                return out;
            if (static_cast<unsigned char>(c) < 32)
                return {};
            if (c != '\\') {
                out += c;
                continue;
            }
            if (pos_ == s_.size())
                return {};
            switch (s_[pos_++]) {
            case '"':
                out += '"';
                break;
            case '\\':
                out += '\\';
                break;
            case '/':
                out += '/';
                break;
            case 'b':
                out += '\b';
                break;
            case 'f':
                out += '\f';
                break;
            case 'n':
                out += '\n';
                break;
            case 'r':
                out += '\r';
                break;
            case 't':
                out += '\t';
                break;
            case 'u': {
                auto h = hex4();
                if (!h)
                    return {};
                uint32_t cp = *h;
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    if (s_.substr(pos_, 2) != "\\u")
                        return {};
                    pos_ += 2;
                    auto low = hex4();
                    if (!low || *low < 0xDC00 || *low > 0xDFFF)
                        return {};
                    cp = 0x10000 + ((cp - 0xD800) << 10) + *low - 0xDC00;
                } else if (cp >= 0xDC00 && cp <= 0xDFFF)
                    return {};
                append_utf8(out, cp);
                break;
            }
            default:
                return {};
            }
        }
        return {};
    }
    std::optional<Json> value(size_t depth) {
        space();
        if (depth > 32 || pos_ == s_.size())
            return {};
        Json v;
        const auto c = s_[pos_];
        if (c == '"') {
            auto t = string();
            if (!t)
                return {};
            v.kind = Json::Kind::kString;
            v.text = std::move(*t);
            return v;
        }
        if (c == '{' || c == '[') {
            ++pos_;
            const bool object = c == '{';
            const char end = object ? '}' : ']';
            v.kind = object ? Json::Kind::kObject : Json::Kind::kArray;
            if (take(end))
                return v;
            do {
                std::optional<std::string> key;
                if (object) {
                    key = string();
                    if (!key || !take(':'))
                        return {};
                }
                auto child = value(depth + 1);
                if (!child)
                    return {};
                if (object) {
                    if (!v.object.emplace(*key, std::move(*child)).second)
                        return {};
                } else
                    v.array.push_back(std::move(*child));
                if (take(end))
                    return v;
            } while (take(','));
            return {};
        }
        for (auto literal : {"null", "true", "false"}) {
            const std::string_view word(literal);
            if (s_.substr(pos_, word.size()) == word) {
                pos_ += word.size();
                if (word != "null") {
                    v.kind = Json::Kind::kBoolean;
                    v.text = word;
                }
                return v;
            }
        }
        const auto begin = pos_;
        if (s_[pos_] == '-')
            ++pos_;
        if (pos_ == s_.size())
            return {};
        if (s_[pos_] == '0')
            ++pos_;
        else {
            if (s_[pos_] < '1' || s_[pos_] > '9')
                return {};
            while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9')
                ++pos_;
        }
        if (pos_ < s_.size() && s_[pos_] == '.') {
            auto start = ++pos_;
            while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9')
                ++pos_;
            if (start == pos_)
                return {};
        }
        if (pos_ < s_.size() && (s_[pos_] == 'e' || s_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < s_.size() && (s_[pos_] == '+' || s_[pos_] == '-'))
                ++pos_;
            auto start = pos_;
            while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9')
                ++pos_;
            if (start == pos_)
                return {};
        }
        v.kind = Json::Kind::kNumber;
        v.text = s_.substr(begin, pos_ - begin);
        if (v.text.find_first_of(".eE") == std::string::npos) {
            const auto digits = std::string_view(v.text).substr(v.text.front() == '-' ? 1 : 0);
            uint64_t integer = 0;
            auto r = std::from_chars(digits.data(), digits.data() + digits.size(), integer);
            if (r.ec != std::errc{})
                return {};
        } else {
            double number = 0;
            auto r = std::from_chars(v.text.data(), v.text.data() + v.text.size(), number);
            if (r.ec != std::errc{} || !std::isfinite(number))
                return {};
        }
        return v;
    }
};
bool add(uint64_t& total, uint64_t n) {
    if (n > std::numeric_limits<uint64_t>::max() - total)
        return false;
    total += n;
    return true;
}
bool counts_valid(const Counts& c) {
    uint64_t sum = c.normal;
    return add(sum, c.fai) && add(sum, c.skipped) && sum == c.terminal;
}
} // namespace
const Json* Json::at(std::string_view key) const {
    if (kind != Kind::kObject)
        return nullptr;
    auto i = object.find(std::string(key));
    return i == object.end() ? nullptr : &i->second;
}
std::optional<uint64_t> Json::uint_value() const {
    if (kind != Kind::kNumber || text.empty() || text.front() == '-')
        return {};
    uint64_t n = 0;
    const auto r = std::from_chars(text.data(), text.data() + text.size(), n);
    if (r.ec != std::errc{} || r.ptr != text.data() + text.size())
        return {};
    return n;
}
std::optional<uint64_t> Json::uint_at(std::string_view key) const {
    auto p = at(key);
    return p ? p->uint_value() : std::nullopt;
}
std::string Json::string_at(std::string_view key) const {
    auto p = at(key);
    return p && p->kind == Kind::kString ? p->text : "";
}
std::optional<Json> parse_json(std::string_view text) {
    if (text.size() > kMaxJsonBytes || !valid_utf8(text))
        return {};
    return Parser(text).parse();
}
std::string json_quote(std::string_view text) {
    std::string out = "\"";
    for (auto c : text) {
        if (c == '"' || c == '\\') {
            out += '\\';
            out += c;
        } else if (static_cast<unsigned char>(c) < 32) {
            constexpr char hex[] = "0123456789abcdef";
            out += "\\u00";
            out += hex[(static_cast<unsigned char>(c) >> 4)];
            out += hex[c & 15];
        } else
            out += c;
    }
    return out + '"';
}
std::optional<Json> read_report(const std::wstring& path) {
    std::ifstream in(std::filesystem::path(path), std::ios::binary);
    if (!in)
        return {};
    std::string bytes(kMaxJsonBytes + 1, '\0');
    in.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    bytes.resize(static_cast<size_t>(in.gcount()));
    if (in.bad())
        return {};
    return parse_json(bytes);
}
std::optional<Summary> decode_summary(const Json& v) {
    if (v.uint_at("schema") != 1 || v.string_at("run_id").size() != 32 ||
        v.string_at("source_sha256").size() != 64 ||
        v.string_at("internal_verification") != "passed")
        return {};
    Summary s;
    s.document = v;
    s.status = v.string_at("status");
    auto code = v.uint_at("exit_code"), folders = v.uint_at("folders"), items = v.uint_at("items"),
         bytes = v.uint_at("pst_bytes"), terminal = v.uint_at("terminal"),
         normal = v.uint_at("converted_normal"), fai = v.uint_at("converted_fai"),
         corrupt = v.uint_at("skipped_corrupt"), unsupported = v.uint_at("skipped_unsupported"),
         failed = v.uint_at("failed"), recovered = v.uint_at("recovered_items");
    if (!code || !folders || !items || !bytes || !terminal || !normal || !fai || !corrupt ||
        !unsupported || !failed || !recovered)
        return {};
    s.exit_code = *code;
    s.folders = *folders;
    s.items = *items;
    s.bytes = *bytes;
    uint64_t skipped = *corrupt;
    if (!add(skipped, *unsupported) || !add(skipped, *failed))
        return {};
    s.counts = {*terminal, *normal, *fai, skipped};
    if (!counts_valid(s.counts) || *terminal != *items || *recovered > *terminal || *bytes == 0)
        return {};
    if (!((s.status == "complete" && *code == 0 && skipped == 0) ||
          (s.status == "incomplete" && *code == 3)))
        return {};
    return s;
}
bool Session::consume(std::string_view line) {
    const auto fail = [&]() {
        broken = true;
        return false;
    };
    if (broken || terminal)
        return fail();
    auto v = parse_json(line);
    if (!v || v->uint_at("schema") != 1)
        return fail();
    const auto event = v->string_at("event");
    if (event == "start") {
        if (started || v->uint_at("protocol") != 1)
            return fail();
        started = true;
        return true;
    }
    if (!started)
        return fail();
    if (event == "progress") {
        static const std::vector<std::string> phases = {"identity",    "index",    "items",
                                                        "folders",     "assembly", "verification",
                                                        "publication", "published"};
        auto p = v->string_at("phase");
        auto t = v->at("total");
        auto n = v->uint_at("terminal"), normal = v->uint_at("normal"), fai = v->uint_at("fai"),
             skipped = v->uint_at("skipped");
        if (std::find(phases.begin(), phases.end(), p) == phases.end() || !t || !n || !normal ||
            !fai || !skipped)
            return fail();
        auto denominator = t->uint_value();
        if (!denominator && t->kind != Json::Kind::kNull)
            return fail();
        Counts next{*n, *normal, *fai, *skipped};
        if (!counts_valid(next) || (denominator && *n > *denominator) || *n < counts.terminal ||
            *normal < counts.normal || *fai < counts.fai || *skipped < counts.skipped ||
            (total && denominator != total))
            return fail();
        if (std::find(phases.begin(), phases.end(), p) <
            std::find(phases.begin(), phases.end(), phase))
            return fail();
        phase = p;
        total = denominator;
        counts = next;
        return true;
    }
    if (event == "error") {
        auto kind = v->string_at("kind"), scope = v->string_at("scope");
        if (error_seen || (scope != "input" && scope != "operation") ||
            v->string_at("field").empty() || !v->uint_at("offset") || !v->uint_at("value") ||
            !v->at("detail") || v->at("detail")->kind != Json::Kind::kString)
            return fail();
        if (kind != "io" && kind != "truncated" && kind != "bad-field" && kind != "bad-crc" &&
            kind != "bad-signature" && kind != "unsupported")
            return fail();
        error_seen = true;
        error_kind = kind;
        error_scope = scope;
        error_detail = std::string(line);
        return true;
    }
    if (event == "result") {
        auto code = v->uint_at("exit_code");
        if (!code || *code > 3)
            return fail();
        result_status = v->string_at("status");
        result_exit = *code;
        if (result_status == "failed") {
            if (!error_seen || *code == 0)
                return fail();
        } else {
            auto report = v->at("report");
            if (!report || error_seen)
                return fail();
            result = decode_summary(*report);
            if (!result || result->status != result_status || result->exit_code != *code ||
                result->counts.terminal < counts.terminal ||
                result->counts.normal < counts.normal || result->counts.fai < counts.fai ||
                result->counts.skipped < counts.skipped || (total && result->items != *total))
                return fail();
            counts = result->counts;
        }
        terminal = true;
        return true;
    }
    return fail();
}
Verdict Session::finish(uint32_t code, bool stopped, const std::optional<Json>& report) const {
    if (broken)
        return Verdict::kFailed;
    if (started && terminal && result && result_exit == code && report &&
        *report == result->document)
        return result_status == "complete" ? Verdict::kComplete : Verdict::kIncomplete;
    if (stopped && !terminal)
        return Verdict::kStopped;
    return Verdict::kFailed;
}
std::wstring quote_argument(std::wstring_view value) {
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (auto c : value) {
        if (c == L'\\') {
            ++slashes;
            continue;
        }
        out.append(slashes * (c == L'"' ? 2 : 1), L'\\');
        slashes = 0;
        if (c == L'"')
            out += L'\\';
        out += c;
    }
    out.append(slashes * 2, L'\\');
    return out + L'"';
}
std::string resolve_locale(const std::vector<std::wstring>& preferred) {
    for (auto tag : preferred) {
        for (auto& c : tag) {
            if (c >= L'A' && c <= L'Z')
                c += L'a' - L'A';
            if (c == L'_')
                c = L'-';
        }
        auto primary = tag.substr(0, tag.find(L'-'));
        if (primary == L"zh") {
            const auto tokens = L"-" + tag + L"-";
            if (tokens.find(L"-hant-") != std::wstring::npos)
                return "zh-Hant";
            if (tokens.find(L"-hans-") != std::wstring::npos)
                return "zh-Hans";
            if (tokens.find(L"-tw-") != std::wstring::npos ||
                tokens.find(L"-hk-") != std::wstring::npos ||
                tokens.find(L"-mo-") != std::wstring::npos)
                return "zh-Hant";
            return "zh-Hans";
        }
        for (auto lang : {L"en", L"ja", L"fr", L"it", L"es", L"de", L"ko"})
            if (primary == lang) {
                std::string result;
                for (auto c : primary)
                    result += static_cast<char>(c);
                return result;
            }
    }
    return "en";
}
} // namespace ost2pst::gui
