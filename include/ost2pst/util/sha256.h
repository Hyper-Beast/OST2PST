#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/status.h"

namespace ost2pst::util {
class RandomAccessFile;

using Sha256Digest = std::array<uint8_t, 32>;

// Byte-oriented SHA-256 (RFC 6234 sections 4.1, 5.1, 6.1 and 6.2).
// digest() snapshots the state; callers can continue updating after taking a digest.
// This is a content fingerprint, not authentication of an untrusted manifest.
class Sha256 {
  public:
    Sha256();
    Status update(ByteView bytes);
    Sha256Digest digest() const;
    uint64_t size() const { return size_; }

  private:
    void compress(const uint8_t* block);

    std::array<uint32_t, 8> state_;
    std::array<uint8_t, 64> pending_{};
    size_t pending_size_ = 0;
    uint64_t size_ = 0;
};

std::string sha256_hex(const Sha256Digest& digest);
// Reads through the caller's handle with a fixed-size buffer. Source locking and stability
// verification belong to the handle owner; hashing alone does not prevent concurrent edits.
Result<Sha256Digest> sha256_file(const FileReader& file);
Result<Sha256Digest> sha256_file(const RandomAccessFile& file);

} // namespace ost2pst::util
