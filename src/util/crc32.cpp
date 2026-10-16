#include "ost2pst/util/crc32.h"

namespace ost2pst::util {

uint32_t crc32_update(uint32_t crc, ByteView data) {
    const uint8_t *bytes = data.data();
    for (size_t i = 0; i < data.size(); ++i) {
        // [MS-PST] 5.3: dwCRC = CrcTableOffset32[(dwCRC ^ *pbBuffer++) & 0xFF] ^ (dwCRC >> 8).
        crc = kCrc32Table[(crc ^ bytes[i]) & 0xFFu] ^ (crc >> 8);
    }
    return crc;
}

uint32_t crc32(ByteView data) {
    return crc32_variant(data, CrcSeed::kZero, false);
}

uint32_t crc32_variant(ByteView data, CrcSeed seed, bool final_complement) {
    uint32_t crc = (seed == CrcSeed::kZero) ? 0u : 0xFFFFFFFFu;
    crc = crc32_update(crc, data);
    return final_complement ? ~crc : crc;
}

} // namespace ost2pst::util
