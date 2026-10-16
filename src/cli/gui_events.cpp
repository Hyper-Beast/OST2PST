#include "gui_events.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "../gui/protocol.h"

namespace ost2pst::cli {
void GuiEvents::emit(const std::string& fields) {
    if (!enabled_)
        return;
    std::fprintf(stdout, "{\"schema\":1,%s}\n", fields.c_str());
    std::fflush(stdout);
}
void GuiEvents::start() {
    emit("\"event\":\"start\",\"protocol\":1");
}
void GuiEvents::progress(const char* phase, bool known, uint64_t total, uint64_t terminal,
                         uint64_t normal, uint64_t fai, uint64_t skipped) {
    if (!enabled_)
        return;
    emit("\"event\":\"progress\",\"phase\":" + gui::json_quote(phase) +
         ",\"total\":" + (known ? std::to_string(total) : "null") +
         ",\"terminal\":" + std::to_string(terminal) + ",\"normal\":" + std::to_string(normal) +
         ",\"fai\":" + std::to_string(fai) + ",\"skipped\":" + std::to_string(skipped));
}
void GuiEvents::error(const util::DataError& e, bool input_phase) {
    emit("\"event\":\"error\",\"scope\":" + gui::json_quote(input_phase ? "input" : "operation") +
         ",\"kind\":" + gui::json_quote(util::error_kind_name(e.kind)) +
         ",\"field\":" + gui::json_quote(e.field) + ",\"offset\":" + std::to_string(e.offset) +
         ",\"value\":" + std::to_string(e.value) + ",\"detail\":" + gui::json_quote(e.detail));
}
bool GuiEvents::result(int code, const std::wstring& output) {
    if (!enabled_)
        return true;
    std::string report;
    if (code == 0 || code == 3) {
        auto decoded = gui::read_report(output + L".report.json");
        auto summary = decoded ? gui::decode_summary(*decoded) : std::nullopt;
        if (!summary || summary->exit_code != static_cast<uint64_t>(code))
            return false;
        std::ifstream in(std::filesystem::path(output + L".report.json"), std::ios::binary);
        report.assign(gui::kMaxJsonBytes + 1, '\0');
        in.read(report.data(), static_cast<std::streamsize>(report.size()));
        report.resize(static_cast<size_t>(in.gcount()));
        auto second = gui::parse_json(report);
        if (!second || *second != *decoded)
            return false;
        while (!report.empty() && (report.back() == '\n' || report.back() == '\r' ||
                                   report.back() == ' ' || report.back() == '\t'))
            report.pop_back();
    }
    emit("\"event\":\"result\",\"status\":" +
         gui::json_quote(code == 0   ? "complete"
                         : code == 3 ? "incomplete"
                                     : "failed") +
         ",\"exit_code\":" + std::to_string(code) +
         (report.empty() ? "" : ",\"report\":" + report));
    return true;
}
} // namespace ost2pst::cli
