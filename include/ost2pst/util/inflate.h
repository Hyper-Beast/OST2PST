#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

namespace ost2pst::util {

// [RFC 1950] 2.2 zlib header: CMF/FLG. CM 8 (DEFLATE) is the only method defined, and the two bytes
// read as a 16-bit big-endian number have to divide by 31 exactly -- 31, not 32.
constexpr uint8_t kZlibCmfMethodMask = 0x0F;
constexpr uint8_t kZlibCmfMethodDeflate = 0x08;
constexpr uint8_t kZlibFlgCheckMask = 0x1F;
constexpr uint8_t kZlibFlgPresetDictionary = 0x20;
constexpr uint32_t kZlibCheckModulus = 31;
constexpr size_t kZlibHeaderBytes = 2;
constexpr size_t kZlibTrailerBytes = 4;

// [RFC 1950] 2.2 Adler-32 over the uncompressed bytes, stored big-endian.
uint32_t adler32(ByteView data);

// True when the first two bytes are a CMF/FLG pair that announces DEFLATE. OST decides compression by
// bytes, never by what NDB says about the block (DEVELOPMENT.md).
bool zlib_header_present(ByteView block);

// How far the zlib stream reached into the block handed in, header and Adler-32 included. A block whose
// stream stops short of cb is reported instead of quietly ignored.
struct ZlibStream {
    std::vector<uint8_t> data;
    size_t consumed = 0;
};

// [RFC 1951] DEFLATE on its own: stored, fixed-Huffman and dynamic-Huffman blocks.
// max_output is what keeps a corrupt stream from asking for an unreasonable allocation; going past it is
// a reported error, not a truncation.
Result<std::vector<uint8_t>> inflate_deflate(ByteView stream, size_t max_output = 1u << 20);

// [RFC 1950] CMF/FLG + DEFLATE + Adler-32. A preset dictionary is refused as unsupported: no OST block
// measured in this project carries one.
Result<ZlibStream> inflate_zlib(ByteView block, size_t max_output = 1u << 20);

} // namespace ost2pst::util
