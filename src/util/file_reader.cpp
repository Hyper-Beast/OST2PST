#include "ost2pst/util/file_reader.h"

#include <cstdio>
#include <utility>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <io.h>
#include <share.h>
#include <windows.h>
#endif

namespace ost2pst::util {

namespace {

#ifdef _WIN32
std::FILE* open_native(const std::wstring& path, bool stable) {
    return _wfsopen(path.c_str(), L"rb", stable ? _SH_DENYWR : _SH_DENYNO);
}

int seek(std::FILE* file, uint64_t offset) {
    return _fseeki64(file, static_cast<int64_t>(offset), SEEK_SET);
}

int seek_end(std::FILE* file) {
    return _fseeki64(file, 0, SEEK_END);
}

int64_t tell(std::FILE* file) {
    return _ftelli64(file);
}
#else
std::FILE* open_native(const std::wstring& path, bool) {
    // POSIX paths are byte strings; lossy conversion is acceptable because this build targets
    // Windows, and the fallback only keeps the tree compilable elsewhere.
    std::string narrow;
    for (wchar_t unit : path) {
        const uint32_t code = static_cast<uint32_t>(unit);
        if (code < 0x80) {
            narrow.push_back(static_cast<char>(code));
        } else if (code < 0x800) {
            narrow.push_back(static_cast<char>(0xC0u | (code >> 6)));
            narrow.push_back(static_cast<char>(0x80u | (code & 0x3Fu)));
        } else {
            narrow.push_back(static_cast<char>(0xE0u | (code >> 12)));
            narrow.push_back(static_cast<char>(0x80u | ((code >> 6) & 0x3Fu)));
            narrow.push_back(static_cast<char>(0x80u | (code & 0x3Fu)));
        }
    }
    return std::fopen(narrow.c_str(), "rb");
}

int seek(std::FILE* file, uint64_t offset) {
    return fseeko(file, static_cast<off_t>(offset), SEEK_SET);
}

int seek_end(std::FILE* file) {
    return fseeko(file, 0, SEEK_END);
}

int64_t tell(std::FILE* file) {
    return ftello(file);
}
#endif

} // namespace

FileReader::FileReader(FileReader&& other) noexcept
    : handle_(other.handle_), size_(other.size_), path_(std::move(other.path_)) {
    other.handle_ = nullptr;
    other.size_ = 0;
}

FileReader& FileReader::operator=(FileReader&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = other.handle_;
        size_ = other.size_;
        path_ = std::move(other.path_);
        other.handle_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

FileReader::~FileReader() {
    close();
}

void FileReader::close() {
    if (handle_ != nullptr) {
        std::fclose(static_cast<std::FILE*>(handle_));
        handle_ = nullptr;
        size_ = 0;
    }
}

Result<FileReader> FileReader::open(const std::wstring& path) {
    return open_impl(path, false);
}

Result<FileReader> FileReader::open_stable(const std::wstring& path) {
#ifdef _WIN32
    return open_impl(path, true);
#else
    (void)path;
    return make_error(ErrorKind::kUnsupported, "FileReader.open_stable", 0, 0,
                      "mandatory source write exclusion is not implemented on this platform");
#endif
}

Result<FileIdentity> FileReader::identity() const {
    if (!is_open())
        return make_error(ErrorKind::kIo, "FileReader.identity", 0, 0, "file is not open");
#ifdef _WIN32
    const intptr_t native = _get_osfhandle(_fileno(static_cast<std::FILE*>(handle_)));
    BY_HANDLE_FILE_INFORMATION info{};
    if (native == -1 || !GetFileInformationByHandle(reinterpret_cast<HANDLE>(native), &info))
        return make_error(ErrorKind::kIo, "FileReader.identity", 0, GetLastError(),
                          "cannot query handle identity");
    FileIdentity result;
    result.volume = info.dwVolumeSerialNumber;
    result.file = (uint64_t{info.nFileIndexHigh} << 32) | info.nFileIndexLow;
    result.size = (uint64_t{info.nFileSizeHigh} << 32) | info.nFileSizeLow;
    result.last_write =
        (uint64_t{info.ftLastWriteTime.dwHighDateTime} << 32) | info.ftLastWriteTime.dwLowDateTime;
    return result;
#else
    return make_error(ErrorKind::kUnsupported, "FileReader.identity", 0, 0,
                      "handle identity is not implemented on this platform");
#endif
}

Result<FileReader> FileReader::open_impl(const std::wstring& path, bool stable) {
    std::FILE* file = open_native(path, stable);
    if (file == nullptr) {
        return make_error(ErrorKind::kIo, "FileReader.open", 0, 0, "cannot open file");
    }
    // Size the file by seeking to the end; a fresh handle sits at 0, so tell() alone reports 0.
    if (seek_end(file) != 0) {
        std::fclose(file);
        return make_error(ErrorKind::kIo, "FileReader.size", 0, 0, "cannot size file");
    }
    const int64_t end = tell(file);
    if (end < 0) {
        std::fclose(file);
        return make_error(ErrorKind::kIo, "FileReader.size", 0, 0, "cannot size file");
    }
    if (seek(file, 0) != 0) {
        std::fclose(file);
        return make_error(ErrorKind::kIo, "FileReader.seek", 0, 0, "seek failed");
    }
    return FileReader(file, static_cast<uint64_t>(end), path);
}

Status FileReader::read_at(uint64_t offset, uint8_t* destination, size_t count) const {
    if (handle_ == nullptr) {
        return make_error(ErrorKind::kIo, "FileReader.read", offset, count, "file is not open");
    }
    if (offset > size_ || count > size_ - offset) {
        return make_error(ErrorKind::kTruncated, "FileReader.read", offset, count,
                          "read runs past end of file");
    }
    if (count == 0) {
        return Status();
    }
    if (seek(static_cast<std::FILE*>(handle_), offset) != 0) {
        return make_error(ErrorKind::kIo, "FileReader.seek", offset, count, "seek failed");
    }
    const size_t got = std::fread(destination, 1, count, static_cast<std::FILE*>(handle_));
    if (got != count) {
        return make_error(ErrorKind::kIo, "FileReader.read", offset, count,
                          "short read of " + std::to_string(got) + " bytes");
    }
    return Status();
}

} // namespace ost2pst::util
