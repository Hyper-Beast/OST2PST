#define NOMINMAX
// clang-format off
#include <windows.h>
#include <commctrl.h>
#include <objbase.h>
// clang-format on
#include <atomic>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <stdexcept>
#include <thread>

#include "../../src/gui/wizard.h"

using namespace ost2pst::gui;
namespace {
void check(bool b, const char* why) {
    if (!b)
        throw std::runtime_error(why);
}
void pump() {
    MSG m{};
    while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) {
        if (m.message != WM_QUIT) {
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
    }
}
bool until(const std::function<bool()>& predicate, DWORD timeout = 30000) {
    const auto started = GetTickCount64();
    while (GetTickCount64() - started < timeout) {
        pump();
        if (predicate())
            return true;
        Sleep(10);
    }
    return false;
}
void screenshot(HWND w, const std::filesystem::path& path) {
    RECT r;
    GetClientRect(w, &r);
    HDC dc = GetDC(w), memory = CreateCompatibleDC(dc);
    HBITMAP bitmap = CreateCompatibleBitmap(dc, r.right, r.bottom);
    BITMAPINFO info{};
    info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = r.right;
    info.bmiHeader.biHeight = -r.bottom;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    std::vector<unsigned char> data(static_cast<size_t>(r.right) * r.bottom * 4);
    bool captured = false;
    for (int attempt = 0; attempt < 20 && !captured; ++attempt) {
        RedrawWindow(w, nullptr, nullptr, RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
        pump();
        Sleep(20); // Let the compositor commit newly shown/relayouted child controls.
        auto old = SelectObject(memory, bitmap);
        PatBlt(memory, 0, 0, r.right, r.bottom, BLACKNESS);
        bool printed = PrintWindow(w, memory, PW_CLIENTONLY | 2) != FALSE;
        SelectObject(memory, old);
        if (!printed || !GetDIBits(memory, bitmap, 0, r.bottom, data.data(), &info, DIB_RGB_COLORS))
            continue;
        for (size_t i = 0; i < data.size(); i += 4)
            if (data[i] || data[i + 1] || data[i + 2]) {
                captured = true;
                break;
            }
    }
    check(captured, "native capture contains rendered pixels");
    BITMAPFILEHEADER header{};
    header.bfType = 0x4D42;
    header.bfOffBits = sizeof(header) + sizeof(info.bmiHeader);
    header.bfSize = header.bfOffBits + static_cast<DWORD>(data.size());
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(&header), sizeof(header));
    out.write(reinterpret_cast<const char*>(&info.bmiHeader), sizeof(info.bmiHeader));
    out.write(reinterpret_cast<const char*>(data.data()), data.size());
    DeleteObject(bitmap);
    DeleteDC(memory);
    ReleaseDC(w, dc);
}
std::wstring caption(HWND w) {
    std::wstring s(2048, L'\0');
    s.resize(GetWindowTextW(w, s.data(), static_cast<int>(s.size())));
    return s;
}
void click(HWND w, int id) {
    SendMessageW(w, WM_COMMAND, MAKEWPARAM(id, BN_CLICKED),
                 reinterpret_cast<LPARAM>(GetDlgItem(w, id)));
    pump();
}
void switch_language(HWND w, int index) {
    HWND combo = GetDlgItem(w, kLanguage);
    SendMessageW(combo, CB_SETCURSEL, index, 0);
    SendMessageW(w, WM_COMMAND, MAKEWPARAM(kLanguage, CBN_SELCHANGE),
                 reinterpret_cast<LPARAM>(combo));
    pump();
    check(caption(combo) == kCatalogs[index].strings[static_cast<size_t>(Text::language_name)],
          "selector displays current language autonym");
    check(caption(GetDlgItem(w, kClose)) ==
              kCatalogs[index].strings[static_cast<size_t>(Text::close)],
          "current page immediately localized");
}
void footer_aligned(HWND w) {
    RECT reference;
    GetWindowRect(GetDlgItem(w, kPrimary), &reference);
    for (int id : {kDetails, kReport, kFolder, kResume, kClose}) {
        HWND button = GetDlgItem(w, id);
        if (!IsWindowVisible(button))
            continue;
        RECT r;
        GetWindowRect(button, &r);
        check(r.top == reference.top && r.bottom == reference.bottom, "result footer one baseline");
    }
}
struct ProgressMessages {
    unsigned marquee = 0, range = 0;
};
LRESULT CALLBACK progress_messages(HWND w, UINT m, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR data) {
    auto& seen = *reinterpret_cast<ProgressMessages*>(data);
    if (m == PBM_SETMARQUEE)
        ++seen.marquee;
    if (m == PBM_SETRANGE32)
        ++seen.range;
    return DefSubclassProc(w, m, wp, lp);
}
HWND progress_control(HWND w) {
    for (HWND child = GetWindow(w, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT)) {
        wchar_t name[64]{};
        GetClassNameW(child, name, 64);
        if (std::wstring(name) == PROGRESS_CLASSW)
            return child;
    }
    throw std::runtime_error("native progress control missing");
}
void modal_action(HWND owner, int answer, const std::function<void()>& action) {
    struct Match {
        HWND owner;
        HWND found = nullptr;
    } match{owner};
    const DWORD ui_thread = GetCurrentThreadId();
    std::atomic<bool> handled = false;
    std::thread helper([&] {
        const auto start = GetTickCount64();
        while (GetTickCount64() - start < 5000) {
            EnumThreadWindows(
                ui_thread,
                [](HWND w, LPARAM lp) -> BOOL {
                    auto* m = reinterpret_cast<Match*>(lp);
                    wchar_t cls[64];
                    GetClassNameW(w, cls, 64);
                    if (GetWindow(w, GW_OWNER) == m->owner && std::wstring(cls) == L"#32770" &&
                        IsWindowVisible(w)) {
                        m->found = w;
                        return FALSE;
                    }
                    return TRUE;
                },
                reinterpret_cast<LPARAM>(&match));
            if (match.found) {
                if (answer)
                    SendMessageW(match.found, WM_COMMAND, MAKEWPARAM(answer, BN_CLICKED),
                                 reinterpret_cast<LPARAM>(GetDlgItem(match.found, answer)));
                else
                    SendMessageW(match.found, WM_CLOSE, 0, 0);
                handled = true;
                return;
            }
            Sleep(10);
        }
    });
    action();
    helper.join();
    check(handled, "native modal dialog handled");
}
Snapshot run(ProcessHost& host, uint64_t id, const std::wstring& worker,
             const std::filesystem::path& source, const std::filesystem::path& output,
             bool resume = false, bool stop = false) {
    host.start(nullptr, id, worker, source.wstring(), output.wstring(), resume);
    if (stop) {
        check(until([&] {
                  auto s = host.snapshot();
                  return s.finished || s.session.phase == "items";
              }),
              "worker reaches items");
        host.stop();
    }
    check(until([&] { return host.snapshot().finished; }, 90000), "worker finishes");
    auto state = host.snapshot();
    check(state.run == id, "run identity");
    return state;
}
} // namespace
int wmain(int argc, wchar_t** argv) {
    if (argc != 7)
        return 1;
    try {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS};
        InitCommonControlsEx(&controls);
        const std::wstring worker = argv[1], failure_worker = argv[2];
        const std::filesystem::path source = argv[3], incomplete = argv[4], long_source = argv[5],
                                    root = argv[6];
        std::filesystem::create_directories(root);
        ProcessHost host;
        auto good = run(host, 1, worker, source, root / L"complete.pst");
        check(good.verdict == Verdict::kComplete, "real complete result");
        auto resumed = run(host, 2, worker, source, root / L"complete.pst", true);
        check(resumed.verdict == Verdict::kComplete, "completed resume");
        check(resumed.session.result->document == good.session.result->document,
              "same completed report");
        check(run(host, 3, worker, incomplete, root / L"incomplete.pst").verdict ==
                  Verdict::kIncomplete,
              "real incomplete result");
        check(run(host, 4, worker, source, root / L"complete.pst").verdict == Verdict::kFailed,
              "collision fails");
        auto missing = run(host, 5, worker + L".missing", source, root / L"missing.pst");
        check(missing.launch_error != 0 && missing.verdict == Verdict::kFailed, "missing worker");
        auto stopped = run(host, 6, worker, long_source, root / L"stopped.pst", false, true);
        check(stopped.verdict == Verdict::kStopped && stopped.stop_observed, "real stop observed");
        check(std::filesystem::exists(root / L"stopped.pst.work"), "stop retains work");
        std::ofstream(root / L"stopped.pst.work" / L"neighbor.txt") << "keep";
        auto recovered = run(host, 7, worker, long_source, root / L"stopped.pst", true);
        check(recovered.verdict == Verdict::kComplete, "interruption resume");
        check(std::filesystem::exists(root / L"stopped.pst.work" / L"neighbor.txt"),
              "resume retains neighbor");
        // A stop request after the terminal result cannot reverse successful completion.
        host.stop();
        check(host.snapshot().verdict == Verdict::kComplete, "completion wins late stop");
        uint64_t failure_id = 10;
        for (auto mode : {L"verification", L"late-pst", L"late-report"}) {
            const auto damaged_source = root / (std::wstring(mode) + L".ost");
            std::filesystem::copy_file(source, damaged_source);
            const auto output = root / (std::wstring(mode) + L".pst");
            const auto state = run(host, ++failure_id, failure_worker, damaged_source, output);
            check(state.verdict == Verdict::kFailed && state.session.terminal &&
                      state.session.error_seen && !state.session.broken,
                  "late operation failure is a typed failed result");
            if (std::wstring(mode) == L"late-report")
                check(std::filesystem::exists(output),
                      "published PST alone cannot establish success");
        }
        {
            Wizard ui(Strings({L"unsupported"}));
            check(ui.create(GetModuleHandleW(nullptr), SW_SHOWNOACTIVATE), "interactive controls");
            HWND w = ui.window();
            pump();
            check(SendMessageW(GetDlgItem(w, kLanguage), CB_GETCURSEL, 0, 0) == 0,
                  "unsupported UI language selects English");
            check(SendMessageW(GetDlgItem(w, kLanguage), CB_GETCOUNT, 0, 0) == 9,
                  "nine language choices");
            modal_action(w, 0, [&] { click(w, kBrowse); });
            SetWindowTextW(GetDlgItem(w, kPath), long_source.c_str());
            for (int lang = 0; lang < 9; ++lang) {
                switch_language(w, lang);
                check(caption(GetDlgItem(w, kPath)) == long_source.wstring(),
                      "source survives switch");
            }
            click(w, kPrimary);
            const auto destination = root / L"ui-stop.pst";
            SetWindowTextW(GetDlgItem(w, kPath), (root / L"CON.pst").c_str());
            click(w, kPrimary);
            check(IsWindowVisible(GetDlgItem(w, kBack)) != FALSE,
                  "reserved destination refused before worker");
            SetWindowTextW(GetDlgItem(w, kPath), source.c_str());
            click(w, kPrimary);
            check(IsWindowVisible(GetDlgItem(w, kBack)) != FALSE,
                  "existing source destination refused");
            SetWindowTextW(GetDlgItem(w, kPath), destination.c_str());
            for (int lang = 0; lang < 9; ++lang) {
                switch_language(w, lang);
                check(caption(GetDlgItem(w, kPath)) == destination.wstring(),
                      "destination survives switch");
            }
            click(w, kPrimary);
            ProgressMessages progress_seen;
            HWND progress = progress_control(w);
            SetWindowSubclass(progress, progress_messages, 1,
                              reinterpret_cast<DWORD_PTR>(&progress_seen));
            for (int lang = 0; lang < 9; ++lang)
                switch_language(w, lang);
            check(progress_seen.marquee <= 1 && progress_seen.range <= 1,
                  "language/snapshot refresh must not restart progress animation");
            RemoveWindowSubclass(progress, progress_messages, 1);
            check(until([&] { return std::filesystem::exists(destination.wstring() + L".work"); }),
                  "UI initialized work");
            modal_action(w, IDNO, [&] { SendMessageW(w, WM_CLOSE, 0, 0); });
            check(IsWindow(w), "declined close retains window");
            click(w, kPrimary);
            check(until([&] { return IsWindowVisible(GetDlgItem(w, kResume)) != FALSE; }),
                  "UI stop exposes resume after drain");
            check(!IsWindowVisible(GetDlgItem(w, kReport)), "stopped output is not successful");
            for (int lang = 0; lang < 9; ++lang) {
                switch_language(w, lang);
                check(IsWindowVisible(GetDlgItem(w, kResume)), "recovery survives language switch");
                check(ui.layout_valid(), "stopped localized footer layout");
                footer_aligned(w);
            }
            click(w, kResume);
            check(until([&] { return IsWindowVisible(GetDlgItem(w, kReport)) != FALSE; }, 90000),
                  "UI resumes to authoritative success");
            click(w, kPrimary);
            SetWindowTextW(GetDlgItem(w, kPath), long_source.c_str());
            click(w, kPrimary);
            SetWindowTextW(GetDlgItem(w, kPath), (root / L"ui-close.pst").c_str());
            click(w, kPrimary);
            modal_action(w, IDYES, [&] { SendMessageW(w, WM_CLOSE, 0, 0); });
            check(until([&] { return !IsWindow(w); }), "confirmed close waits for owned worker");
        }
        unsigned id = 0;
        for (const auto& lang :
             {L"en", L"zh-Hans", L"zh-Hant", L"ja", L"fr", L"it", L"es", L"de", L"ko"}) {
            for (UINT dpi : {96, 144, 192}) {
                Wizard ui(Strings({lang}), dpi);
                check(ui.create(GetModuleHandleW(nullptr), SW_SHOWNOACTIVATE),
                      "create native wizard");
                HWND w = ui.window();
                pump();
                check(caption(GetDlgItem(w, kLanguage)) == Strings({lang}).get(Text::language_name),
                      "startup language is selected");
                const auto stem = std::filesystem::path(lang).string() + "-" + std::to_string(dpi);
                check(ui.layout_valid(), "source layout");
                screenshot(w, root / (stem + "-source.bmp"));
                check(GetNextDlgTabItem(w, nullptr, FALSE) == GetDlgItem(w, kPath),
                      "first focus is path");
                SetWindowTextW(GetDlgItem(w, kPath), source.c_str());
                click(w, kPrimary);
                check(IsWindowVisible(GetDlgItem(w, kBack)), "source to destination");
                check(ui.layout_valid(), "destination layout");
                screenshot(w, root / (stem + "-destination.bmp"));
                auto output = root / (L"ui-" + std::to_wstring(++id) + L".pst");
                SetWindowTextW(GetDlgItem(w, kPath), output.c_str());
                click(w, kPrimary);
                check(ui.layout_valid(), "progress layout");
                screenshot(w, root / (stem + "-progress.bmp"));
                // The GUI resolves the sibling worker next to this test, staged by the test
                // launcher.
                check(until([&] { return IsWindowVisible(GetDlgItem(w, kDetails)) != FALSE; }),
                      "native UI result");
                check(IsWindowVisible(GetDlgItem(w, kReport)) != FALSE,
                      "UI success requires report");
                screenshot(w, root / (stem + "-result.bmp"));
                if (!ui.layout_valid())
                    std::fprintf(stderr, "Layout case %s\n", stem.c_str());
                check(ui.layout_valid(), "result layout");
                footer_aligned(w);
                SetWindowPos(w, nullptr, 0, 0, MulDiv(900, dpi, 96), MulDiv(540, dpi, 96),
                             SWP_NOMOVE | SWP_NOZORDER);
                for (int selected = 0; selected < 9; ++selected) {
                    switch_language(w, selected);
                    check(IsWindowVisible(GetDlgItem(w, kReport)),
                          "verified result survives switch");
                    check(ui.layout_valid(), "compact result with language switch");
                    footer_aligned(w);
                }
                click(w, kPrimary);
                check(IsWindowVisible(GetDlgItem(w, kPath)) != FALSE, "another run resets wizard");
                DestroyWindow(w);
                pump();
            }
        }
        {
            Wizard contrast(Strings({L"en"}), 96, true);
            check(contrast.create(GetModuleHandleW(nullptr), SW_SHOWNOACTIVATE),
                  "high contrast native branch");
            pump();
            check(contrast.layout_valid(), "high contrast layout");
            screenshot(contrast.window(), root / L"system-palette-source.bmp");
            DestroyWindow(contrast.window());
            pump();
        }
        std::puts("Native process, recovery and 109 localized/system-palette page captures passed");
        CoUninitialize();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s\n", e.what());
        return 1;
    }
}
