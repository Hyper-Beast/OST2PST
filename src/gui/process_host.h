#pragma once
#define NOMINMAX
#include <atomic>
#include <mutex>
#include <thread>
#include <windows.h>

#include "protocol.h"

namespace ost2pst::gui {
inline constexpr UINT kWorkerChanged = WM_APP + 14;
struct Snapshot {
    uint64_t run = 0;
    Session session;
    bool finished = false, stop_observed = false, diagnostics_truncated = false;
    DWORD exit_code = 1, launch_error = 0;
    std::string diagnostics;
    Verdict verdict = Verdict::kFailed;
};
class ProcessHost {
  public:
    ProcessHost() = default;
    ~ProcessHost();
    ProcessHost(const ProcessHost&) = delete;
    ProcessHost& operator=(const ProcessHost&) = delete;
    void start(HWND window, uint64_t run, const std::wstring& worker, const std::wstring& input,
               const std::wstring& output, bool resume);
    void stop();
    Snapshot snapshot();

  private:
    std::mutex mutex_;
    std::thread thread_;
    Snapshot state_;
    HANDLE process_ = nullptr;
    HWND window_ = nullptr;
    bool stop_requested_ = false;
    std::atomic<bool> notification_pending_{false};
    void notify();
    void run(std::wstring worker, std::wstring input, std::wstring output, bool resume);
};
std::wstring module_directory();
std::wstring worker_path();
} // namespace ost2pst::gui
