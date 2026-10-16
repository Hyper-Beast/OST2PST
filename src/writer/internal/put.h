#pragma once

#include <cstdint>
#include <vector>

namespace ost2pst::writer {

// The write-side counterpart of util::ByteView's little-endian reads: every PST field is
// little-endian (DEVELOPMENT.md). Offsets are unchecked because every caller
// here writes into an image whose size it computed itself.
inline void put_u16(std::vector<uint8_t> &bytes, uint64_t offset, uint16_t value) {
    bytes[static_cast<size_t>(offset)] = static_cast<uint8_t>(value & 0xFFu);
    bytes[static_cast<size_t>(offset) + 1] = static_cast<uint8_t>(value >> 8);
}

inline void put_u32(std::vector<uint8_t> &bytes, uint64_t offset, uint32_t value) {
    for (uint64_t index = 0; index < 4; ++index) {
        bytes[static_cast<size_t>(offset) + index] = static_cast<uint8_t>(value >> (8u * index));
    }
}

inline void put_u64(std::vector<uint8_t> &bytes, uint64_t offset, uint64_t value) {
    for (uint64_t index = 0; index < 8; ++index) {
        bytes[static_cast<size_t>(offset) + index] = static_cast<uint8_t>(value >> (8u * index));
    }
}

} // namespace ost2pst::writer
