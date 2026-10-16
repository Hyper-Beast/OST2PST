#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "ost2pst/util/status.h"

namespace ost2pst::util {

// Handle identity detects filesystem aliases; size/time supplement, but never replace,
// the content digest when validating a persisted conversion run.
struct FileIdentity {
    uint64_t volume = 0;
    uint64_t file = 0;
    uint64_t size = 0;
    uint64_t last_write = 0;

    bool same_file(const FileIdentity& other) const {
        return volume == other.volume && file == other.file;
    }
};

// Owns one read-only file handle. No whole-file slurp: callers seek to an offset and read a
// bounded window, which keeps offsets auditable against the spec.
class FileReader {
  public:
    FileReader() = default;
    FileReader(const FileReader&) = delete;
    FileReader& operator=(const FileReader&) = delete;
    FileReader(FileReader&& other) noexcept;
    FileReader& operator=(FileReader&& other) noexcept;
    ~FileReader();

    static Result<FileReader> open(const std::wstring& path);
    // Windows denies writable opens while this handle lives and refuses a file already
    // open for writing. Unsupported platforms return an explicit refusal.
    static Result<FileReader> open_stable(const std::wstring& path);
    Result<FileIdentity> identity() const;

    bool is_open() const { return handle_ != nullptr; }
    uint64_t size() const { return size_; }
    const std::wstring& path() const { return path_; }

    Status read_at(uint64_t offset, uint8_t* destination, size_t count) const;

  private:
    static Result<FileReader> open_impl(const std::wstring& path, bool stable);
    FileReader(void* handle, uint64_t size, std::wstring path)
        : handle_(handle), size_(size), path_(std::move(path)) {}

    void close();

    void* handle_ = nullptr;
    uint64_t size_ = 0;
    std::wstring path_;
};

} // namespace ost2pst::util
