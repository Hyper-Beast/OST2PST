#include <cstdio>
#include <stdexcept>

#include "../../src/gui/protocol.h"

using namespace ost2pst::gui;
static void check(bool value) {
    if (!value)
        throw std::runtime_error("GUI protocol assertion");
}
int main() {
    check(parse_json("{\"x\":1}").has_value());
    check(!parse_json("{\"x\":1,\"x\":2}"));
    check(!parse_json("{\"x\":18446744073709551616}"));
    check(!parse_json("1e99999"));
    check(!parse_json("01"));
    check(!parse_json("1."));
    check(!parse_json("{} trailing"));
    check(!parse_json("\"\\uDC00\""));
    check(!parse_json("{\"a\":1,\"\\u0061\":2}"));
    check(!parse_json("\"\\ud800\""));
    check(!parse_json(std::string("\"\xc0\xaf\"")));
    check(!parse_json(std::string(kMaxJsonBytes + 1, ' ')));
    check(!parse_json(std::string(33, '[') + "0" + std::string(33, ']')));
    check(parse_json("\"\\ud83d\\ude00\"").has_value());
    Session state;
    check(!state.consume("{\"schema\":1,\"event\":\"result\"}"));
    Session good;
    check(good.consume("{\"schema\":1,\"event\":\"start\",\"protocol\":1}"));
    check(good.consume("{\"schema\":1,\"event\":\"progress\",\"phase\":\"identity\",\"total\":null,"
                       "\"terminal\":0,\"normal\":0,\"fai\":0,\"skipped\":0}"));
    check(!good.consume("{\"schema\":2,\"event\":\"progress\"}"));
    const std::string report =
        R"({"schema":1,"run_id":"00000000000000000000000000000000","source_sha256":"0000000000000000000000000000000000000000000000000000000000000000","internal_verification":"passed","status":"complete","exit_code":0,"folders":1,"items":2,"terminal":2,"converted_normal":1,"converted_fai":1,"skipped_corrupt":0,"skipped_unsupported":0,"failed":0,"recovered_items":0,"pst_bytes":65536})";
    const std::string start = R"({"schema":1,"event":"start","protocol":1})";
    const std::string result =
        R"({"schema":1,"event":"result","exit_code":0,"status":"complete","report":)" + report +
        "}";
    Session complete;
    check(complete.consume(start));
    check(complete.consume(result));
    check(complete.finish(0, false, parse_json(report)) == Verdict::kComplete);
    check(complete.finish(3, false, parse_json(report)) == Verdict::kFailed);
    check(complete.finish(0, false, {}) == Verdict::kFailed);
    auto changed = parse_json(report);
    changed->object["folders"].text = "2";
    check(complete.finish(0, false, changed) == Verdict::kFailed);
    check(complete.finish(0, true, parse_json(report)) == Verdict::kComplete);
    check(!complete.consume(result));
    check(complete.finish(0, false, parse_json(report)) == Verdict::kFailed);
    Session interrupted;
    check(interrupted.consume(start));
    check(interrupted.finish(1223, true, parse_json(report)) == Verdict::kStopped);
    check(interrupted.finish(0, false, parse_json(report)) == Verdict::kFailed);
    Session invalid_counts;
    check(invalid_counts.consume(start));
    check(!invalid_counts.consume(
        R"({"schema":1,"event":"progress","phase":"items","total":1,"terminal":1,"normal":2,"fai":0,"skipped":0})"));
    Session duplicate_start;
    check(duplicate_start.consume(start));
    check(!duplicate_start.consume(start));
    Session typed;
    check(typed.consume(start));
    check(typed.consume(
        R"({"schema":1,"event":"error","scope":"input","kind":"bad-crc","field":"header.crc","offset":4,"value":3,"detail":"test"})"));
    check(typed.consume(R"({"schema":1,"event":"result","status":"failed","exit_code":3})"));
    check(typed.finish(3, false, parse_json(report)) == Verdict::kFailed);
    for (auto tag : {L"zh-CN", L"zh-SG", L"zh-Hans-TW", L"zh"})
        check(resolve_locale({tag}) == "zh-Hans");
    for (auto tag : {L"zh-TW", L"zh-HK", L"zh-MO", L"zh-Hant-CN"})
        check(resolve_locale({tag}) == "zh-Hant");
    check(resolve_locale({L"ru", L"ja-JP", L"en"}) == "ja");
    check(resolve_locale({L"fr-CA", L"ja"}) == "fr");
    for (const auto& [tag, expected] :
         std::vector<std::pair<std::wstring, std::string>>{{L"en-GB", "en"},
                                                           {L"it-CH", "it"},
                                                           {L"es-419", "es"},
                                                           {L"de-AT", "de"},
                                                           {L"ko-KR", "ko"},
                                                           {L"ZH_hAnT_hk", "zh-Hant"},
                                                           {L"ru-RU", "en"}})
        check(resolve_locale({tag}) == expected);
    check(resolve_locale({}) == "en");
    check(quote_argument(L"a b\\") == L"\"a b\\\\\"");
    check(quote_argument(L"a\"b") == L"\"a\\\"b\"");
    std::puts("GUI protocol boundaries passed");
}
