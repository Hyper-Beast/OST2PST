#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "ost2pst/util/byte_view.h"

namespace ost2pst::util {

// [MS-PST] 5.3 CRC: reflected CRC-32 table, polynomial 0xEDB88320 (bit-reversed 0x04C11DB7).
constexpr uint32_t kCrc32Polynomial = 0xEDB88320u;

constexpr std::array<uint32_t, 256> make_crc32_table() {
    std::array<uint32_t, 256> table{};
    for (uint32_t index = 0; index < 256; ++index) {
        uint32_t value = index;
        for (int bit = 0; bit < 8; ++bit) {
            value = (value & 1u) ? (kCrc32Polynomial ^ (value >> 1)) : (value >> 1);
        }
        table[index] = value;
    }
    return table;
}

inline constexpr std::array<uint32_t, 256> kCrc32Table = make_crc32_table();

// Seed variants exist so M0 can measure which one the real file uses instead of assuming the
// pseudocode is right ([MS-PST] 5.3 vs zlib crc32).
enum class CrcSeed {
    kZero,
    kAllOnes,
};

uint32_t crc32_update(uint32_t crc, ByteView data);

// [MS-PST] 5.3 ComputeCRC: seed 0, no final complement.
uint32_t crc32(ByteView data);

uint32_t crc32_variant(ByteView data, CrcSeed seed, bool final_complement);

} // namespace ost2pst::util
