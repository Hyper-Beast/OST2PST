#include "ost2pst/util/directory_pin.h"

#include <algorithm>
#include <filesystem>
#include <utility>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace ost2pst::util {
namespace {
DataError bad_path(const char* field) {
    return make_error(ErrorKind::kBadField, field, 0, 0, "invalid output or work path");
}
#ifdef _WIN32
DataError io(const char* field) {
    return make_error(ErrorKind::kIo, field, 0, GetLastError(), "Windows path operation failed");
}
#else
DataError unsupported() {
    return make_error(ErrorKind::kUnsupported, "DirectoryPin.platform", 0);
}
#endif
} // namespace

DirectoryPin::DirectoryPin(DirectoryPin&& other) noexcept
    : handle_(std::exchange(other.handle_, nullptr)), path_(std::move(other.path_)),
      identity_(other.identity_) {}
DirectoryPin& DirectoryPin::operator=(DirectoryPin&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = std::exchange(other.handle_, nullptr);
        path_ = std::move(other.path_);
        identity_ = other.identity_;
    }
    return *this;
}
DirectoryPin::~DirectoryPin() {
    close();
}
void DirectoryPin::close() {
#ifdef _WIN32
    if (handle_)
        CloseHandle(handle_);
#endif
    handle_ = nullptr;
}

Result<DirectoryPin> DirectoryPin::open(const std::wstring& path, bool resolve_link) {
#ifdef _WIN32
    const DWORD flags =
        FILE_FLAG_BACKUP_SEMANTICS | (resolve_link ? 0 : FILE_FLAG_OPEN_REPARSE_POINT);
    HANDLE handle =
        CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                    OPEN_EXISTING, flags, nullptr);
    if (handle == INVALID_HANDLE_VALUE)
        return io("DirectoryPin.open");
    DirectoryPin result;
    result.handle_ = handle;
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle, &info))
        return io("DirectoryPin.identity");
    if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return bad_path("DirectoryPin.type");
    result.identity_ =
        FileIdentity{info.dwVolumeSerialNumber,
                     (uint64_t{info.nFileIndexHigh} << 32) | info.nFileIndexLow, 0, 0};
    const DWORD needed = GetFinalPathNameByHandleW(handle, nullptr, 0, FILE_NAME_NORMALIZED);
    if (needed == 0)
        return io("DirectoryPin.path");
    std::vector<wchar_t> buffer(static_cast<size_t>(needed) + 1);
    const DWORD length = GetFinalPathNameByHandleW(
        handle, buffer.data(), static_cast<DWORD>(buffer.size()), FILE_NAME_NORMALIZED);
    if (length == 0 || length >= buffer.size())
        return io("DirectoryPin.path");
    result.path_.assign(buffer.data(), length);
    return result;
#else
    (void)path;
    (void)resolve_link;
    return unsupported();
#endif
}

Result<DirectoryPin> DirectoryPin::create_new(const std::wstring& path) {
#ifdef _WIN32
    if (!CreateDirectoryW(path.c_str(), nullptr))
        return io("DirectoryPin.create");
    // Leave failed initialization evidence in place; never delete an unverified directory.
    return open(path);
#else
    (void)path;
    return unsupported();
#endif
}

Status require_absent(const std::wstring& path) {
#ifdef _WIN32
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
        return make_error(ErrorKind::kIo, "output.exists", 0, ERROR_ALREADY_EXISTS,
                          "output artifact exists");
    const DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
        return {};
    return io("output.inspect");
#else
    (void)path;
    return unsupported();
#endif
}

Result<OutputLocation> output_location(const std::wstring& output) {
#ifdef _WIN32
    if (output.empty() || output.find(L'\0') != std::wstring::npos)
        return bad_path("output.path");
    // MSVC absolute() applies Win32 normalization, including stripping a terminal dot/space.
    // Validate the caller's leaf first so an invalid name cannot become a different output.
    const std::filesystem::path requested(output);
    const std::wstring leaf = requested.filename().wstring();
    if (leaf.empty() || leaf.back() == L'.' || leaf.back() == L' ' ||
        leaf.find_first_of(L":<>\"/\\|?*") != std::wstring::npos ||
        std::any_of(leaf.begin(), leaf.end(), [](wchar_t c) { return c < 32; }))
        return bad_path("output.filename");
    std::error_code error;
    auto absolute = std::filesystem::absolute(requested, error);
    if (error)
        return make_error(ErrorKind::kIo, "output.absolute", 0, error.value(), error.message());
    std::wstring stem = leaf.substr(0, leaf.find(L'.'));
    for (auto& c : stem)
        if (c >= L'a' && c <= L'z')
            c -= L'a' - L'A';
    if (stem == L"CON" || stem == L"PRN" || stem == L"AUX" || stem == L"NUL" ||
        (stem.size() == 4 && (stem.substr(0, 3) == L"COM" || stem.substr(0, 3) == L"LPT") &&
         stem[3] >= L'1' && stem[3] <= L'9'))
        return bad_path("output.filename");
    auto parent = DirectoryPin::open(absolute.parent_path().wstring(), true);
    if (!parent.ok())
        return parent.error();
    OutputLocation result;
    result.parent = parent.take();
    result.path = (std::filesystem::path(result.parent.path()) / leaf).wstring();
    const int count =
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, result.path.data(),
                            static_cast<int>(result.path.size()), nullptr, 0, nullptr, nullptr);
    if (count <= 0)
        return io("output.utf8");
    result.binding.resize(count);
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, result.path.data(),
                            static_cast<int>(result.path.size()), result.binding.data(), count,
                            nullptr, nullptr) != count)
        return io("output.utf8");
    return result;
#else
    (void)output;
    return unsupported();
#endif
}
} // namespace ost2pst::util
