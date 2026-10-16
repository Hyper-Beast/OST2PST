#include <cstdio>
#include <filesystem>
#include <stdexcept>

#include "../../src/gui/process_host.h"

using namespace ost2pst::gui;
namespace {
void check(bool b, const char* why) {
    if (!b)
        throw std::runtime_error(why);
}
int child(const std::wstring& mode) {
    if (mode == L"oversize") {
        auto s = std::string(kMaxJsonBytes + 1, ' ') + "\n";
        std::fwrite(s.data(), 1, s.size(), stdout);
        return 0;
    }
    if (mode == L"truncated") {
        std::printf("{\"schema\":1");
        return 0;
    }
    std::printf("{\"schema\":1,\"event\":\"start\",\"protocol\":1}\n");
    std::fflush(stdout);
    if (mode == L"hang") {
        Sleep(INFINITE);
        return 0;
    }
    std::string noise(kMaxDiagnosticBytes + 8192, 'x');
    std::fwrite(noise.data(), 1, noise.size(), stderr);
    std::fflush(stderr);
    for (int i = 0; i < 2000; ++i)
        std::printf("{\"schema\":1,\"event\":\"progress\",\"phase\":\"items\",\"total\":2000,"
                    "\"terminal\":%d,\"normal\":%d,\"fai\":0,\"skipped\":0}\n",
                    i, i);
    std::printf("{\"schema\":1,\"event\":\"error\",\"scope\":\"operation\",\"kind\":\"io\","
                "\"field\":\"test\",\"offset\":0,\"value\":1,\"detail\":\"test\"}\n");
    std::printf("{\"schema\":1,\"event\":\"result\",\"status\":\"failed\",\"exit_code\":1}\n");
    if (mode == L"duplicate")
        std::printf("{\"schema\":1,\"event\":\"result\",\"status\":\"failed\",\"exit_code\":1}\n");
    return 1;
}
} // namespace
int wmain(int argc, wchar_t** argv) {
    if (argc == 4 && std::wstring(argv[1]) == L"--events-json")
        return child(argv[2]);
    try {
        std::wstring module(32768, L'\0');
        module.resize(
            GetModuleFileNameW(nullptr, module.data(), static_cast<DWORD>(module.size())));
        ProcessHost host;
        HWND window = CreateWindowW(L"STATIC", L"host notifications", 0, 0, 0, 0, 0, HWND_MESSAGE,
                                    nullptr, GetModuleHandleW(nullptr), nullptr);
        uint64_t run = 0;
        for (auto mode : {L"noise", L"oversize", L"truncated", L"duplicate", L"hang"}) {
            host.start(window, ++run, module, mode, L"nonexistent-report", false);
            if (std::wstring(mode) == L"hang") {
                Sleep(30);
                host.stop();
            }
            auto start = GetTickCount64();
            while (!host.snapshot().finished && GetTickCount64() - start < 15000)
                Sleep(5);
            auto s = host.snapshot();
            check(s.finished, "bounded child finishes");
            if (std::wstring(mode) == L"noise") {
                check(!s.session.broken && s.session.terminal && s.session.error_seen,
                      "coalescing retains terminal and error");
                check(s.diagnostics.size() == kMaxDiagnosticBytes && s.diagnostics_truncated,
                      "bounded stderr tail");
            } else if (std::wstring(mode) == L"hang")
                check(s.verdict == Verdict::kStopped, "stop before initialization");
            else
                check(s.session.broken && s.verdict == Verdict::kFailed,
                      "bad stream cannot succeed");
            MSG m{};
            unsigned count = 0;
            while (PeekMessageW(&m, window, kWorkerChanged, kWorkerChanged, PM_REMOVE))
                ++count;
            // Polling snapshot resets the notification token, so at most one notification per poll.
            // A stalled view must be tested separately without snapshot acknowledgements.
            check(count <= 3000, "notifications bounded by acknowledgements");
        }
        // Stall the view: no acknowledgements until the worker has emitted all 2000 snapshots.
        host.start(window, ++run, module, L"noise", L"nonexistent-report", false);
        Sleep(500);
        MSG m{};
        unsigned count = 0;
        while (PeekMessageW(&m, window, kWorkerChanged, kWorkerChanged, PM_REMOVE))
            ++count;
        check(count <= 1, "stalled UI has one pending notification");
        auto start = GetTickCount64();
        while (!host.snapshot().finished && GetTickCount64() - start < 15000)
            Sleep(5);
        check(host.snapshot().finished, "stalled worker finishes");
        DestroyWindow(window);
        std::puts("Pipe, truncation, queue and stop boundaries passed");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s\n", e.what());
        return 1;
    }
}
