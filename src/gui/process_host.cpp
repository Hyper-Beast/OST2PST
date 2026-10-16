#include "process_host.h"

#include <array>
#include <filesystem>
#include <memory>
#include <vector>

namespace ost2pst::gui {
namespace {
class Handle {
  public:
    HANDLE value = nullptr;
    ~Handle() {
        if (value && value != INVALID_HANDLE_VALUE)
            CloseHandle(value);
    }
};
} // namespace
ProcessHost::~ProcessHost() {
    stop();
    if (thread_.joinable())
        thread_.join();
}
void ProcessHost::notify() {
    // A single pending notification coalesces snapshots; terminal/error state stays in the reducer.
    if (window_ && !notification_pending_.exchange(true))
        if (!PostMessageW(window_, kWorkerChanged, 0, 0))
            notification_pending_ = false;
}
Snapshot ProcessHost::snapshot() {
    std::lock_guard lock(mutex_);
    notification_pending_ = false;
    return state_;
}
void ProcessHost::start(HWND window, uint64_t id, const std::wstring& worker,
                        const std::wstring& input, const std::wstring& output, bool resume) {
    if (thread_.joinable())
        thread_.join();
    {
        std::lock_guard lock(mutex_);
        state_ = {};
        state_.run = id;
        stop_requested_ = false;
        window_ = window;
        notification_pending_ = false;
    }
    thread_ = std::thread(&ProcessHost::run, this, worker, input, output, resume);
}
void ProcessHost::stop() {
    std::lock_guard lock(mutex_);
    stop_requested_ = true;
    if (process_ && !state_.session.terminal && WaitForSingleObject(process_, 0) == WAIT_TIMEOUT) {
        if (TerminateProcess(process_, 1223))
            state_.stop_observed = true;
    }
}
void ProcessHost::run(std::wstring worker, std::wstring input, std::wstring output, bool resume) {
    Handle out_read, out_write, err_read, err_write, null_input, process, main_thread, job;
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    DWORD failure = 0;
    auto finish = [&] {
        {
            std::lock_guard lock(mutex_);
            process_ = nullptr;
            state_.launch_error = failure;
            state_.verdict = state_.session.finish(state_.exit_code, state_.stop_observed,
                                                   read_report(output + L".report.json"));
            state_.finished = true;
        }
        notify();
    };
    if (!CreatePipe(&out_read.value, &out_write.value, &sa, 0) ||
        !CreatePipe(&err_read.value, &err_write.value, &sa, 0) ||
        !SetHandleInformation(out_read.value, HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(err_read.value, HANDLE_FLAG_INHERIT, 0)) {
        failure = GetLastError();
        finish();
        return;
    }
    null_input.value = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                                   OPEN_EXISTING, 0, nullptr);
    if (null_input.value == INVALID_HANDLE_VALUE) {
        failure = GetLastError();
        finish();
        return;
    }
    SIZE_T attribute_bytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_bytes);
    std::vector<unsigned char> attributes(attribute_bytes);
    auto* list = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
    if (!InitializeProcThreadAttributeList(list, 1, 0, &attribute_bytes)) {
        failure = GetLastError();
        finish();
        return;
    }
    HANDLE inherited[] = {out_write.value, err_write.value, null_input.value};
    const bool updated =
        UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited,
                                  sizeof(inherited), nullptr, nullptr) != FALSE;
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdOutput = out_write.value;
    startup.StartupInfo.hStdError = err_write.value;
    startup.StartupInfo.hStdInput = null_input.value;
    startup.lpAttributeList = list;
    std::wstring command = quote_argument(worker) + L" --events-json " +
                           (resume ? L"--resume " : L"") + quote_argument(input) + L" " +
                           quote_argument(output);
    PROCESS_INFORMATION info{};
    const BOOL created =
        updated &&
        CreateProcessW(worker.c_str(), command.data(), nullptr, nullptr, TRUE,
                       CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, nullptr,
                       std::filesystem::path(worker).parent_path().c_str(), &startup.StartupInfo,
                       &info);
    if (!created)
        failure = GetLastError();
    DeleteProcThreadAttributeList(list);
    if (!created) {
        finish();
        return;
    }
    process.value = info.hProcess;
    main_thread.value = info.hThread;
    job.value = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job.value ||
        !SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits,
                                 sizeof(limits)) ||
        !AssignProcessToJobObject(job.value, process.value)) {
        failure = GetLastError();
        TerminateProcess(process.value, 1);
        WaitForSingleObject(process.value, INFINITE);
        finish();
        return;
    }
    CloseHandle(out_write.value);
    out_write.value = nullptr;
    CloseHandle(err_write.value);
    err_write.value = nullptr;
    {
        std::lock_guard lock(mutex_);
        process_ = process.value;
        if (stop_requested_) {
            state_.stop_observed = TerminateProcess(process.value, 1223) != FALSE;
        }
    }
    if (ResumeThread(main_thread.value) == static_cast<DWORD>(-1)) {
        failure = GetLastError();
        TerminateProcess(process.value, 1);
        WaitForSingleObject(process.value, INFINITE);
        finish();
        return;
    }
    std::thread errors([&] {
        std::array<char, 8192> buffer{};
        DWORD count;
        while (ReadFile(err_read.value, buffer.data(), static_cast<DWORD>(buffer.size()), &count,
                        nullptr) &&
               count) {
            std::lock_guard lock(mutex_);
            state_.diagnostics.append(buffer.data(), count);
            if (state_.diagnostics.size() > kMaxDiagnosticBytes) {
                state_.diagnostics.erase(0, state_.diagnostics.size() - kMaxDiagnosticBytes);
                state_.diagnostics_truncated = true;
            }
        }
    });
    std::array<char, 8192> buffer{};
    DWORD count;
    std::string line;
    bool discard = false;
    while (ReadFile(out_read.value, buffer.data(), static_cast<DWORD>(buffer.size()), &count,
                    nullptr) &&
           count) {
        for (DWORD i = 0; i < count; ++i) {
            if (buffer[i] == '\n') {
                if (!discard) {
                    if (!line.empty() && line.back() == '\r')
                        line.pop_back();
                    std::lock_guard lock(mutex_);
                    state_.session.consume(line);
                }
                line.clear();
                discard = false;
                notify();
            } else if (!discard) {
                line += buffer[i];
                if (line.size() > kMaxJsonBytes) {
                    std::lock_guard lock(mutex_);
                    state_.session.broken = true;
                    discard = true;
                    line.clear();
                }
            }
        }
    }
    {
        std::lock_guard lock(mutex_);
        if (!line.empty() || discard)
            state_.session.broken = true;
    }
    WaitForSingleObject(process.value, INFINITE);
    errors.join();
    {
        std::lock_guard lock(mutex_);
        GetExitCodeProcess(process.value, &state_.exit_code);
        process_ = nullptr;
    }
    finish();
}
std::wstring module_directory() {
    std::wstring path(32768, L'\0');
    const auto count = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (!count || count == path.size())
        return {};
    path.resize(count);
    return std::filesystem::path(path).parent_path().wstring();
}
std::wstring worker_path() {
    const auto dir = std::filesystem::path(module_directory());
    const auto packaged = dir / L"engine" / L"ost2pst.exe";
    std::error_code ec;
    if (std::filesystem::is_regular_file(packaged, ec))
        return packaged.wstring();
    return (dir / L"ost2pst.exe").wstring();
}
} // namespace ost2pst::gui
