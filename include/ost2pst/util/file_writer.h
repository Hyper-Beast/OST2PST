#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/status.h"

namespace ost2pst::util {

// Staging uses this seam to exercise short writes and flush failures without a full disk.
class RandomAccessFile {
  public:
    virtual ~RandomAccessFile() = default;
    virtual uint64_t size() const = 0;
    virtual Status read_at(uint64_t offset, uint8_t* data, size_t count) const = 0;
    virtual Result<size_t> write_some(uint64_t offset, ByteView bytes) = 0;
    virtual Status resize(uint64_t size) = 0;
    virtual Status flush() = 0;
};

// Retries successful partial writes; a zero-progress write or invalid count is an error.
// Does not flush: transaction code must order data flush before journal commit/flush.
Status write_all(RandomAccessFile& file, uint64_t offset, ByteView bytes);

// Exclusive Windows handle with checked 64-bit offsets. No mode truncates on open.
class FileWriter final : public RandomAccessFile {
  public:
    FileWriter() = default;
    FileWriter(const FileWriter&) = delete;
    FileWriter& operator=(const FileWriter&) = delete;
    FileWriter(FileWriter&& other) noexcept;
    FileWriter& operator=(FileWriter&& other) noexcept;
    ~FileWriter() override;

    static Result<FileWriter> create_new(const std::wstring& path);
    static Result<FileWriter> create_temporary(const std::wstring& path);
    static Result<FileWriter> open_existing(const std::wstring& path);
    // Run-owned files must have one link and may not be reparse points or directories.
    static Result<FileWriter> open_private_existing(const std::wstring& path);
    Result<FileIdentity> identity() const;
    // A persistent lock file: opening does not change its contents; closing releases ownership.
    // Callers keep the handle for the entire run, including validation and publication.
    static Result<FileWriter> acquire_lock(const std::wstring& path);

    uint64_t size() const override { return size_; }
    bool is_open() const { return handle_ != nullptr; }
    Status read_at(uint64_t offset, uint8_t* data, size_t count) const override;
    Result<size_t> write_some(uint64_t offset, ByteView bytes) override;
    Status resize(uint64_t size) override;
    Status flush() override;
    Status close(); // Flush explicitly before close; destructor does not claim durability.

  private:
    enum class OpenMode { kCreate, kTemporary, kExisting, kPrivateExisting, kLock };
    static Result<FileWriter> open(const std::wstring& path, OpenMode mode);
    FileWriter(void* handle, uint64_t size) : handle_(handle), size_(size) {}
    void* handle_ = nullptr;
    uint64_t size_ = 0;
};

// Same-volume publication, never replaces an existing destination. Source must be closed
// and successfully flushed; ownership and content identity are the caller's responsibility.
Status publish_no_replace(const std::wstring& source, const std::wstring& destination);

} // namespace ost2pst::util
