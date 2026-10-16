#pragma once

#include <string>

#include "ost2pst/util/file_reader.h"

namespace ost2pst::util {

// Pins a Windows directory against rename/delete while files below it are in use.
// Exclusive run ownership is provided separately by its persistent lock file.
class DirectoryPin {
  public:
    DirectoryPin() = default;
    DirectoryPin(const DirectoryPin&) = delete;
    DirectoryPin& operator=(const DirectoryPin&) = delete;
    DirectoryPin(DirectoryPin&& other) noexcept;
    DirectoryPin& operator=(DirectoryPin&& other) noexcept;
    ~DirectoryPin();
    static Result<DirectoryPin> open(const std::wstring& path, bool resolve_link = false);
    static Result<DirectoryPin> create_new(const std::wstring& path);
    const std::wstring& path() const { return path_; }
    const FileIdentity& identity() const { return identity_; }

  private:
    void close();
    void* handle_ = nullptr;
    std::wstring path_;
    FileIdentity identity_;
};

struct OutputLocation {
    DirectoryPin parent;
    std::wstring path;
    std::string binding; // UTF-8 absolute path resolved through the pinned parent.
};

// Parent must exist. Rejects stream/device/ambiguous leaf names; does not create any files.
Result<OutputLocation> output_location(const std::wstring& output);
Status require_absent(const std::wstring& path);

} // namespace ost2pst::util
