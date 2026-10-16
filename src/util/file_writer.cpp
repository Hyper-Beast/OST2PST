#include "ost2pst/util/file_writer.h"

#include <algorithm>
#include <limits>
#include <utility>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace ost2pst::util {
namespace {
constexpr uint64_t kMaximumOffset = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());

Status range_check(uint64_t offset, uint64_t count) {
    if (offset > kMaximumOffset || count > kMaximumOffset - offset)
        return make_error(ErrorKind::kBadField, "FileWriter.range", offset, count,
                          "file range exceeds signed 64-bit offsets");
    return {};
}

#ifdef _WIN32
DataError io_error(const char* field, uint64_t offset = 0) {
    return make_error(ErrorKind::kIo, field, offset, GetLastError(),
                      "Windows file operation failed");
}
Status seek(void* handle, uint64_t offset) {
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(handle, position, nullptr, FILE_BEGIN))
        return io_error("FileWriter.seek", offset);
    return {};
}
#else
DataError unsupported() {
    return make_error(ErrorKind::kUnsupported, "FileWriter.platform", 0, 0,
                      "durable exclusive file operations are not implemented on this platform");
}
#endif
} // namespace

Status write_all(RandomAccessFile& file, uint64_t offset, ByteView bytes) {
    auto valid = range_check(offset, bytes.size());
    if (!valid.ok())
        return valid;
    if (!bytes.empty() && bytes.data() == nullptr)
        return make_error(ErrorKind::kBadField, "FileWriter.data", offset, bytes.size(),
                          "null data");
    size_t done = 0;
    while (done < bytes.size()) {
        auto wrote =
            file.write_some(offset + done, ByteView(bytes.data() + done, bytes.size() - done));
        if (!wrote.ok())
            return wrote.error();
        if (wrote.value() == 0 || wrote.value() > bytes.size() - done)
            return make_error(ErrorKind::kIo, "FileWriter.write_progress", offset + done,
                              wrote.value(), "write returned no progress or an invalid count");
        done += wrote.value();
    }
    return {};
}

FileWriter::FileWriter(FileWriter&& other) noexcept
    : handle_(std::exchange(other.handle_, nullptr)), size_(std::exchange(other.size_, 0)) {}

FileWriter& FileWriter::operator=(FileWriter&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = std::exchange(other.handle_, nullptr);
        size_ = std::exchange(other.size_, 0);
    }
    return *this;
}

FileWriter::~FileWriter() {
    close();
}

Result<FileWriter> FileWriter::create_new(const std::wstring& path) {
    return open(path, OpenMode::kCreate);
}
Result<FileWriter> FileWriter::create_temporary(const std::wstring& path) {
    return open(path, OpenMode::kTemporary);
}
Result<FileWriter> FileWriter::open_existing(const std::wstring& path) {
    return open(path, OpenMode::kExisting);
}
Result<FileWriter> FileWriter::open_private_existing(const std::wstring& path) {
    return open(path, OpenMode::kPrivateExisting);
}
Result<FileWriter> FileWriter::acquire_lock(const std::wstring& path) {
    return open(path, OpenMode::kLock);
}

Result<FileWriter> FileWriter::open(const std::wstring& path, OpenMode mode) {
#ifdef _WIN32
    const DWORD disposition = (mode == OpenMode::kCreate || mode == OpenMode::kTemporary)
                                  ? CREATE_NEW
                              : mode == OpenMode::kLock ? OPEN_ALWAYS
                                                        : OPEN_EXISTING;
    const DWORD attributes =
        FILE_FLAG_OPEN_REPARSE_POINT |
        (mode == OpenMode::kTemporary ? FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE
                                      : FILE_ATTRIBUTE_NORMAL);
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, disposition,
                                attributes, nullptr);
    if (handle == INVALID_HANDLE_VALUE)
        return io_error("FileWriter.open");
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle, &info)) {
        auto error = io_error("FileWriter.identity");
        CloseHandle(handle);
        return error;
    }
    if ((info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        (mode == OpenMode::kPrivateExisting && info.nNumberOfLinks != 1)) {
        CloseHandle(handle);
        return make_error(ErrorKind::kBadField, "FileWriter.private_file", 0, info.nNumberOfLinks,
                          "file is redirected or has multiple links");
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(handle, &size) || size.QuadPart < 0) {
        auto error = io_error("FileWriter.size");
        CloseHandle(handle);
        return error;
    }
    return FileWriter(handle, static_cast<uint64_t>(size.QuadPart));
#else
    (void)path;
    (void)mode;
    return unsupported();
#endif
}

Result<FileIdentity> FileWriter::identity() const {
    if (!is_open())
        return make_error(ErrorKind::kIo, "FileWriter.identity", 0, 0, "file is closed");
#ifdef _WIN32
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle_, &info))
        return io_error("FileWriter.identity");
    return FileIdentity{
        info.dwVolumeSerialNumber, (uint64_t{info.nFileIndexHigh} << 32) | info.nFileIndexLow,
        (uint64_t{info.nFileSizeHigh} << 32) | info.nFileSizeLow,
        (uint64_t{info.ftLastWriteTime.dwHighDateTime} << 32) | info.ftLastWriteTime.dwLowDateTime};
#else
    return unsupported();
#endif
}

Status FileWriter::close() {
    void* handle = std::exchange(handle_, nullptr);
    size_ = 0;
#ifdef _WIN32
    if (handle != nullptr && !CloseHandle(handle))
        return io_error("FileWriter.close");
#else
    (void)handle;
#endif
    return {};
}

Status FileWriter::read_at(uint64_t offset, uint8_t* data, size_t count) const {
    if (!is_open())
        return make_error(ErrorKind::kIo, "FileWriter.read", offset, count, "file is closed");
    if (offset > size_ || count > size_ - offset)
        return make_error(ErrorKind::kTruncated, "FileWriter.read", offset, count, "read past end");
    if (count != 0 && data == nullptr)
        return make_error(ErrorKind::kBadField, "FileWriter.data", offset, count,
                          "null destination");
#ifdef _WIN32
    auto positioned = seek(handle_, offset);
    if (!positioned.ok())
        return positioned;
    size_t done = 0;
    while (done < count) {
        const DWORD chunk = static_cast<DWORD>(std::min<size_t>(count - done, 1024 * 1024));
        DWORD got = 0;
        if (!ReadFile(handle_, data + done, chunk, &got, nullptr))
            return io_error("FileWriter.read", offset + done);
        if (got == 0)
            return make_error(ErrorKind::kIo, "FileWriter.read", offset + done, 0, "short read");
        done += got;
    }
    return {};
#else
    return unsupported();
#endif
}

Result<size_t> FileWriter::write_some(uint64_t offset, ByteView bytes) {
    if (!is_open())
        return make_error(ErrorKind::kIo, "FileWriter.write", offset, bytes.size(),
                          "file is closed");
    auto valid = range_check(offset, bytes.size());
    if (!valid.ok())
        return valid.error();
    if (bytes.empty())
        return size_t{0};
    if (bytes.data() == nullptr)
        return make_error(ErrorKind::kBadField, "FileWriter.data", offset, bytes.size(),
                          "null data");
#ifdef _WIN32
    auto positioned = seek(handle_, offset);
    if (!positioned.ok())
        return positioned.error();
    const DWORD chunk = static_cast<DWORD>(std::min<size_t>(bytes.size(), 1024 * 1024));
    DWORD wrote = 0;
    if (!WriteFile(handle_, bytes.data(), chunk, &wrote, nullptr))
        return io_error("FileWriter.write", offset);
    size_ = std::max(size_, offset + wrote);
    return static_cast<size_t>(wrote);
#else
    return unsupported();
#endif
}

Status FileWriter::resize(uint64_t size) {
    if (!is_open())
        return make_error(ErrorKind::kIo, "FileWriter.resize", size, 0, "file is closed");
    auto valid = range_check(size, 0);
    if (!valid.ok())
        return valid;
#ifdef _WIN32
    auto positioned = seek(handle_, size);
    if (!positioned.ok())
        return positioned;
    if (!SetEndOfFile(handle_))
        return io_error("FileWriter.resize", size);
    size_ = size;
    return {};
#else
    return unsupported();
#endif
}

Status FileWriter::flush() {
    if (!is_open())
        return make_error(ErrorKind::kIo, "FileWriter.flush", 0, 0, "file is closed");
#ifdef _WIN32
    if (!FlushFileBuffers(handle_))
        return io_error("FileWriter.flush");
    return {};
#else
    return unsupported();
#endif
}

Status publish_no_replace(const std::wstring& source, const std::wstring& destination) {
#ifdef _WIN32
    if (GetFileAttributesW(destination.c_str()) != INVALID_FILE_ATTRIBUTES)
        return make_error(ErrorKind::kIo, "FileWriter.publish", 0, ERROR_ALREADY_EXISTS,
                          "destination exists");
    // No REPLACE_EXISTING or COPY_ALLOWED: an intervening destination or other volume fails.
    if (!MoveFileExW(source.c_str(), destination.c_str(), MOVEFILE_WRITE_THROUGH))
        return io_error("FileWriter.publish");
    return {};
#else
    (void)source;
    (void)destination;
    return unsupported();
#endif
}

} // namespace ost2pst::util
