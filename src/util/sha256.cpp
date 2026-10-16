#include "ost2pst/util/sha256.h"

#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>
#include <vector>

#include "ost2pst/util/file_writer.h"

namespace ost2pst::util {
namespace {

// RFC 6234 section 5.1, preserved locally in RFC 6234 (see THIRD_PARTY_NOTICES.txt).
constexpr std::array<uint32_t, 64> kRoundConstants = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

} // namespace

Sha256::Sha256()
    // RFC 6234 section 6.1: SHA-256 initial hash words.
    : state_{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19} {}

void Sha256::compress(const uint8_t* block) {
    // RFC 6234 section 6.2; addition is modulo 2^32, words are big-endian.
    std::array<uint32_t, 64> words{};
    for (size_t i = 0; i < 16; ++i) {
        const size_t at = i * 4;
        words[i] = (uint32_t{block[at]} << 24) | (uint32_t{block[at + 1]} << 16) |
                   (uint32_t{block[at + 2]} << 8) | uint32_t{block[at + 3]};
    }
    for (size_t i = 16; i < words.size(); ++i) {
        const uint32_t x = words[i - 15], y = words[i - 2];
        const uint32_t s0 = std::rotr(x, 7) ^ std::rotr(x, 18) ^ (x >> 3);
        const uint32_t s1 = std::rotr(y, 17) ^ std::rotr(y, 19) ^ (y >> 10);
        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }
    uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    for (size_t i = 0; i < words.size(); ++i) {
        const uint32_t s1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
        const uint32_t choose = (e & f) ^ (~e & g);
        const uint32_t t1 = h + s1 + choose + kRoundConstants[i] + words[i];
        const uint32_t s0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
        const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = s0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

Status Sha256::update(ByteView bytes) {
    // RFC 6234 section 6.2 requires a bit length below 2^64. Reject before mutation.
    constexpr uint64_t kMaximumBytes = std::numeric_limits<uint64_t>::max() / 8;
    if (bytes.size() > kMaximumBytes - size_) {
        return make_error(ErrorKind::kBadField, "SHA256.length", size_, bytes.size(),
                          "input bit length must be less than 2^64");
    }
    if (bytes.size() != 0 && bytes.data() == nullptr) {
        return make_error(ErrorKind::kBadField, "SHA256.data", size_, bytes.size(),
                          "nonempty input has no data");
    }
    size_ += bytes.size();
    size_t offset = 0;
    if (pending_size_ != 0 && bytes.size() != 0) {
        const size_t count = std::min(pending_.size() - pending_size_, bytes.size());
        std::memcpy(pending_.data() + pending_size_, bytes.data(), count);
        pending_size_ += count;
        offset += count;
        if (pending_size_ == pending_.size()) {
            compress(pending_.data());
            pending_size_ = 0;
        }
    }
    while (bytes.size() - offset >= pending_.size()) {
        compress(bytes.data() + offset);
        offset += pending_.size();
    }
    if (offset != bytes.size()) {
        pending_size_ = bytes.size() - offset;
        std::memcpy(pending_.data(), bytes.data() + offset, pending_size_);
    }
    return {};
}

Sha256Digest Sha256::digest() const {
    Sha256 copy = *this;
    // RFC 6234 section 4.1: 1 bit, zero padding, then a big-endian 64-bit bit length.
    copy.pending_[copy.pending_size_++] = 0x80;
    if (copy.pending_size_ > 56) {
        std::fill(copy.pending_.begin() + copy.pending_size_, copy.pending_.end(), uint8_t{0});
        copy.compress(copy.pending_.data());
        copy.pending_size_ = 0;
    }
    std::fill(copy.pending_.begin() + copy.pending_size_, copy.pending_.begin() + 56, uint8_t{0});
    const uint64_t bits = size_ * 8;
    for (size_t i = 0; i < 8; ++i)
        copy.pending_[63 - i] = static_cast<uint8_t>(bits >> (8 * i));
    copy.compress(copy.pending_.data());
    Sha256Digest result{};
    for (size_t i = 0; i < copy.state_.size(); ++i)
        for (size_t j = 0; j < 4; ++j)
            result[i * 4 + j] = static_cast<uint8_t>(copy.state_[i] >> (24 - j * 8));
    return result;
}

std::string sha256_hex(const Sha256Digest& digest) {
    constexpr char kDigits[] = "0123456789abcdef";
    std::string text;
    text.reserve(digest.size() * 2);
    for (uint8_t byte : digest) {
        text.push_back(kDigits[byte >> 4]);
        text.push_back(kDigits[byte & 15]);
    }
    return text;
}

namespace {
template <class File> Result<Sha256Digest> bounded_file_hash(const File& file) {
    Sha256 hash;
    std::vector<uint8_t> buffer(1024 * 1024);
    for (uint64_t offset = 0; offset < file.size();) {
        const size_t count =
            static_cast<size_t>(std::min<uint64_t>(buffer.size(), file.size() - offset));
        auto read = file.read_at(offset, buffer.data(), count);
        if (!read.ok())
            return read.error();
        auto updated = hash.update(ByteView(buffer.data(), count, offset));
        if (!updated.ok())
            return updated.error();
        offset += count;
    }
    return hash.digest();
}
} // namespace

Result<Sha256Digest> sha256_file(const FileReader& file) {
    if (!file.is_open())
        return make_error(ErrorKind::kIo, "SHA256.file", 0, 0, "file is not open");
    return bounded_file_hash(file);
}

Result<Sha256Digest> sha256_file(const RandomAccessFile& file) {
    return bounded_file_hash(file);
}

} // namespace ost2pst::util
