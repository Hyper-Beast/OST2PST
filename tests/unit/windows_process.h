#pragma once

#ifdef _WIN32
#include <array>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace ost2pst::test {
// Windows argv quoting; CreateProcess receives no shell command language.
inline std::wstring quote_argument(const std::wstring& value) {
    std::wstring quoted = L"\"";
    size_t slashes = 0;
    for (wchar_t c : value) {
        if (c == L'\\') {
            ++slashes;
            continue;
        }
        quoted.append(c == L'\"' ? slashes * 2 + 1 : slashes, L'\\');
        quoted += c;
        slashes = 0;
    }
    quoted.append(slashes * 2, L'\\');
    return quoted + L'\"';
}

inline DWORD run_self(const std::vector<std::wstring>& arguments) {
    std::array<wchar_t, 32768> executable{};
    const DWORD length =
        GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (!length || length >= executable.size())
        return 99;
    std::wstring command = quote_argument(executable.data());
    for (const auto& argument : arguments)
        command += L" " + quote_argument(argument);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(executable.data(), command.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process))
        return 99;
    DWORD code = 99;
    if (WaitForSingleObject(process.hProcess, 10000) == WAIT_OBJECT_0)
        GetExitCodeProcess(process.hProcess, &code);
    else {
        TerminateProcess(process.hProcess, 99);
        WaitForSingleObject(process.hProcess, 10000);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return code;
}
} // namespace ost2pst::test
#endif
