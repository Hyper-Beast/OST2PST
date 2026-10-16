// Dedicated test executable: deterministic operational failures, never production CLI flags.
#include <filesystem>
#include <fstream>

#include "../src/cli/full_conversion.h"
int wmain(int argc, wchar_t** argv) {
    if (argc != 4 || std::wstring(argv[1]) != L"--events-json")
        return 1;
    const std::filesystem::path source = argv[2], output = argv[3];
    const auto mode = source.stem().wstring();
    ost2pst::cli::FullConversionHooks hooks;
    hooks.phase = [&](ost2pst::cli::FullPoint point) {
        using ost2pst::cli::FullPoint;
        if (point == FullPoint::kVerificationOpen && mode == L"verification")
            std::ofstream(std::filesystem::path(output.wstring() + L".work") / L"candidate.tmp",
                          std::ios::binary | std::ios::trunc);
        if (point == FullPoint::kReady && mode == L"late-pst")
            std::ofstream(output) << "foreign";
        if (point == FullPoint::kReady && mode == L"late-report")
            std::ofstream(std::filesystem::path(output.wstring() + L".report.json")) << "foreign";
    };
    return ost2pst::cli::run_full(source.wstring(), output.wstring(), false, hooks, true);
}
