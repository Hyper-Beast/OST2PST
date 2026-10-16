#include "ost2pst/util/inflate.h"

#include <algorithm>
#include <array>
#include <string>

namespace ost2pst::util {

namespace {

// [RFC 1951] 3.2.5: length codes 257..285 and distance codes 0..29 are base values plus extra bits.
// Code 257 + index. Each code covers base .. base + 2^extra - 1, and the groups tile 3..258 with no
// gaps and no overlaps: 3..10 (0 extra), 11..18 (1), 19..34 (2), 35..66 (3), 67..130 (4),
// 131..258 (5). Code 285 repeats 258 with no extra bits, which is what every deflate encoder emits
// for the maximum length; codes 286 and 287 are reserved and rejected before this table is read.
constexpr uint16_t kLengthBase[29] = {3,   4,   5,   6,   7,   8,   9,   10,  11,  13,
                                      15,  17,  19,  23,  27,  31,  35,  43,  51,  59,
                                      67,  83,  99,  115, 131, 163, 195, 227, 258};
constexpr uint8_t kLengthExtra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
                                      3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
constexpr uint16_t kDistanceBase[30] = {1,     2,     3,     4,     5,     7,     9,     13,
                                        17,    25,    33,    49,    65,    97,    129,   193,
                                        257,   385,   513,   769,   1025,  1537,  2049,  3073,
                                        4097,  6145,  8193,  12289, 16385, 24577};
constexpr uint8_t kDistanceExtra[30] = {0,  0,  0,  0,  1,  1,  2,  2,  3,  3,
                                        4,  4,  5,  5,  6,  6,  7,  7,  8,  8,
                                        9,  9,  10, 10, 11, 11, 12, 12, 13, 13};
// [RFC 1951] 3.2.7: the code-length code lengths arrive in this order, not in symbol order.
constexpr uint8_t kCodeLengthOrder[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5,
                                          11, 4,  12, 3, 13, 2, 14, 1, 15};
// [RFC 1951] 3.2.2: a code is at most 15 bits, and 256 ends a block.
constexpr uint16_t kMaxCodeBits = 15;
constexpr uint16_t kEndOfBlock = 256;
// [RFC 1951] 3.2.7: HLIT tops out at 286 symbols and HDIST at 30.
constexpr uint32_t kMaxLiteralSymbols = 286;
constexpr uint32_t kMaxDistanceSymbols = 30;

// DEFLATE packs bits from the low end of each byte, so the reader counts bits and hands back the
// absolute file offset whenever something goes wrong.
class BitReader {
public:
    explicit BitReader(ByteView stream) : stream_(stream) {}

    bool read_bit(uint8_t &out) {
        const uint64_t byte = bits_ >> 3;
        if (byte >= stream_.size()) {
            return false;
        }
        out = static_cast<uint8_t>((stream_.data()[byte] >> (bits_ & 7u)) & 1u);
        ++bits_;
        return true;
    }

    bool read_bits(uint8_t count, uint32_t &out) {
        uint32_t value = 0;
        for (uint8_t index = 0; index < count; ++index) {
            uint8_t bit = 0;
            if (!read_bit(bit)) {
                return false;
            }
            value |= static_cast<uint32_t>(bit) << index;
        }
        out = value;
        return true;
    }

    void align_to_byte() {
        if (bits_ & 7u) {
            bits_ += 8u - (bits_ & 7u);
        }
    }

    bool take_bytes(size_t count, ByteView &out) {
        Result<ByteView> window = stream_.sub(bits_ >> 3, count);
        if (!window.ok()) {
            return false;
        }
        out = window.value();
        bits_ += count * 8;
        return true;
    }

    uint64_t byte_offset() const { return bits_ >> 3; }
    uint64_t absolute(uint64_t bytes_in) const { return stream_.base() + bytes_in; }
    uint64_t here() const { return absolute(byte_offset()); }

private:
    ByteView stream_;
    uint64_t bits_ = 0;
};

DataError stream_error(BitReader &bits, ErrorKind kind, const char *field, uint64_t value,
                       const char *detail) {
    return make_error(kind, field, bits.here(), value, detail);
}

// A canonical Huffman code needs only the length of every symbol: the codes themselves follow from the
// lengths ([RFC 1951] 3.2.2), so nothing here builds a tree.
struct Huffman {
    std::array<uint16_t, kMaxCodeBits + 1> count{};
    std::vector<uint16_t> symbols;
};

Result<Huffman> build_huffman(const uint8_t *lengths, size_t count, bool allow_incomplete,
                              uint64_t error_offset, const char *field) {
    Huffman table;
    uint16_t longest = 0;
    for (size_t symbol = 0; symbol < count; ++symbol) {
        if (lengths[symbol] > kMaxCodeBits) {
            return make_error(ErrorKind::kBadField, field, error_offset, lengths[symbol],
                                "a Huffman code length is at most 15");
        }
        ++table.count[lengths[symbol]];
        if (lengths[symbol] > longest) {
            longest = lengths[symbol];
        }
    }
    table.count[0] = 0;

    int32_t left = 1;
    for (uint16_t length = 1; length <= longest; ++length) {
        left <<= 1;
        left -= table.count[length];
        if (left < 0) {
            return make_error(ErrorKind::kBadField, field, error_offset, length,
                                "the Huffman code is over-subscribed");
        }
    }
    if (left > 0 && !allow_incomplete) {
        return make_error(ErrorKind::kBadField, field, error_offset, static_cast<uint64_t>(left),
                            "the Huffman code is incomplete");
    }

    // next[length] is where the codes of that length start, so the symbol array has to hold
    // count[15] as well -- sizing it from next[15] alone writes a 15-bit code past the end.
    std::array<uint32_t, kMaxCodeBits + 2> next{};
    for (uint16_t length = 1; length <= kMaxCodeBits + 1; ++length) {
        next[length] = next[length - 1] + table.count[length - 1];
    }
    table.symbols.assign(next[kMaxCodeBits + 1], 0);
    for (uint16_t symbol = 0; symbol < count; ++symbol) {
        if (lengths[symbol] != 0) {
            table.symbols[next[lengths[symbol]]++] = symbol;
        }
    }
    return table;
}

// Walks the canonical code one bit at a time: at every length the codes already assigned are the
// window [first, first + count[length]) ([RFC 1951] 3.2.2).
Result<uint16_t> decode_symbol(const Huffman &table, BitReader &bits, const char *field) {
    uint32_t code = 0;
    uint32_t first = 0;
    uint32_t index = 0;
    for (uint16_t length = 1; length <= kMaxCodeBits; ++length) {
        uint8_t bit = 0;
        if (!bits.read_bit(bit)) {
            return stream_error(bits, ErrorKind::kTruncated, field, 0, "the stream ends inside a code");
        }
        code |= bit;
        if (code < first) {
            return stream_error(bits, ErrorKind::kBadField, field, code, "an invalid Huffman code");
        }
        const uint32_t offset = code - first;
        if (offset < table.count[length]) {
            return table.symbols[index + offset];
        }
        index += table.count[length];
        first = (first + table.count[length]) << 1;
        code <<= 1;
    }
    return stream_error(bits, ErrorKind::kBadField, field, code, "an invalid Huffman code");
}

// [RFC 1951] 3.2.6 fixed tables: 0..143 in 8 bits, 144..255 in 9, 256..279 in 7, 280..287 in 8, and
// every distance code in 5. Five bits hold 32 codes and the table only defines 30, so the distance
// table is incomplete on purpose: codes 30 and 31 are the ones inflate_encoded rejects.
const Huffman &fixed_literals() {
    static const Huffman table = [] {
        uint8_t lengths[kEndOfBlock + 32];
        for (size_t symbol = 0; symbol < 144; ++symbol) {
            lengths[symbol] = 8;
        }
        for (size_t symbol = 144; symbol < 256; ++symbol) {
            lengths[symbol] = 9;
        }
        for (size_t symbol = 256; symbol < 280; ++symbol) {
            lengths[symbol] = 7;
        }
        for (size_t symbol = 280; symbol < 288; ++symbol) {
            lengths[symbol] = 8;
        }
        Huffman built = build_huffman(lengths, 288, false, 0, "deflate.fixed").take();
        return built;
    }();
    return table;
}

const Huffman &fixed_distances() {
    static const Huffman table = [] {
        uint8_t lengths[30];
        for (size_t symbol = 0; symbol < 30; ++symbol) {
            lengths[symbol] = 5;
        }
        return build_huffman(lengths, 30, true, 0, "deflate.fixed").take();
    }();
    return table;
}

// [RFC 1951] 3.2.7 dynamic header: HLIT/HDIST/HCLEN, then the code-length code, then the literal and
// distance lengths with 16/17/18 as repeat codes.
Result<Huffman> read_dynamic_tables(BitReader &bits, Huffman &distance) {
    uint32_t hlit = 0;
    uint32_t hdist = 0;
    uint32_t hclen = 0;
    if (!bits.read_bits(5, hlit) || !bits.read_bits(5, hdist) || !bits.read_bits(4, hclen)) {
        return stream_error(bits, ErrorKind::kTruncated, "deflate.HLIT", 0,
                            "the stream ends inside the dynamic header");
    }
    hlit += 257;
    hdist += 1;
    hclen += 4;
    if (hlit > kMaxLiteralSymbols) {
        return stream_error(bits, ErrorKind::kBadField, "deflate.HLIT", hlit,
                            "a dynamic block declares at most 286 literal symbols");
    }
    if (hdist > kMaxDistanceSymbols) {
        return stream_error(bits, ErrorKind::kBadField, "deflate.HDIST", hdist,
                            "a dynamic block declares at most 30 distance symbols");
    }

    uint8_t code_lengths[19] = {};
    for (uint32_t index = 0; index < hclen; ++index) {
        uint32_t value = 0;
        if (!bits.read_bits(3, value)) {
            return stream_error(bits, ErrorKind::kTruncated, "deflate.HCLEN", 0,
                                "the stream ends inside the code-length code");
        }
        code_lengths[kCodeLengthOrder[index]] = static_cast<uint8_t>(value);
    }
    Result<Huffman> code_table = build_huffman(code_lengths, 19, false, bits.here(), "deflate.HCLEN");
    if (!code_table.ok()) {
        return code_table.error();
    }
    // [RFC 1951] 3.2.7: 16, 17 and 18 belong to the code-length alphabet itself -- a block that
    // repeats a length has to be able to name the repeat code, so their code lengths are normal.
    std::vector<uint8_t> lengths(hlit + hdist, 0);
    size_t filled = 0;
    while (filled < lengths.size()) {
        Result<uint16_t> symbol = decode_symbol(code_table.value(), bits, "deflate.CLEN");
        if (!symbol.ok()) {
            return symbol.error();
        }
        const uint16_t value = symbol.value();
        uint32_t repeat = 0;
        uint8_t copied = 0;
        if (value < 16) {
            lengths[filled++] = static_cast<uint8_t>(value);
            continue;
        }
        if (value == 16) {
            if (filled == 0) {
                return stream_error(bits, ErrorKind::kBadField, "deflate.CLEN", 16,
                                    "16 repeats a length before any length exists");
            }
            uint32_t extra = 0;
            if (!bits.read_bits(2, extra)) {
                return stream_error(bits, ErrorKind::kTruncated, "deflate.CLEN", 0,
                                    "the stream ends inside a 16 repeat");
            }
            repeat = 3 + extra;
            copied = lengths[filled - 1];
        } else if (value == 17) {
            uint32_t extra = 0;
            if (!bits.read_bits(3, extra)) {
                return stream_error(bits, ErrorKind::kTruncated, "deflate.CLEN", 0,
                                    "the stream ends inside a 17 repeat");
            }
            repeat = 3 + extra;
        } else if (value == 18) {
            uint32_t extra = 0;
            if (!bits.read_bits(7, extra)) {
                return stream_error(bits, ErrorKind::kTruncated, "deflate.CLEN", 0,
                                    "the stream ends inside a 18 repeat");
            }
            repeat = 11 + extra;
        } else {
            return stream_error(bits, ErrorKind::kBadField, "deflate.CLEN", value,
                                "the code-length code decoded an out-of-range symbol");
        }
        if (filled + repeat > lengths.size()) {
            return stream_error(bits, ErrorKind::kBadField, "deflate.CLEN", repeat,
                                "a repeat runs past the end of the length list");
        }
        for (uint32_t index = 0; index < repeat; ++index) {
            lengths[filled++] = copied;
        }
    }

    Result<Huffman> literals =
        build_huffman(lengths.data(), hlit, false, bits.here(), "deflate.LITERAL");
    if (!literals.ok()) {
        return literals.error();
    }
    // [RFC 1951] 3.2.7: a block with no matches may carry a distance code that decodes nothing.
    Result<Huffman> distance_table =
        build_huffman(lengths.data() + hlit, hdist, true, bits.here(), "deflate.DISTANCE");
    if (!distance_table.ok()) {
        return distance_table.error();
    }
    distance = distance_table.take();
    return literals.take();
}

DataError over_cap(BitReader &bits, size_t max_output) {
    return make_error(ErrorKind::kUnsupported, "deflate.output", bits.here(), max_output,
                      "the stream inflates past the cap asked for");
}

// One encoded block: literals, then length/distance pairs until the end-of-block symbol ([RFC 1951]
// 3.2.5). The copy is byte by byte so an overlap, where the distance is shorter than the length,
// repeats the bytes it just wrote the way DEFLATE says it should.
Status inflate_encoded(const Huffman &literals, const Huffman &distance, BitReader &bits,
                       std::vector<uint8_t> &out, size_t max_output, const char *field) {
    for (;;) {
        Result<uint16_t> symbol = decode_symbol(literals, bits, field);
        if (!symbol.ok()) {
            return symbol.error();
        }
        const uint16_t value = symbol.value();
        if (value < kEndOfBlock) {
            if (out.size() + 1 > max_output) {
                return over_cap(bits, max_output);
            }
            out.push_back(static_cast<uint8_t>(value));
            continue;
        }
        if (value == kEndOfBlock) {
            return Status();
        }
        // [RFC 1951] 3.2.5: 257..285 are the length codes; 286 and 287 are reserved.
        if (value > kEndOfBlock + 29) {
            return stream_error(bits, ErrorKind::kBadField, field, value,
                                "length codes 286 and 287 are unused");
        }
        const uint16_t length_code = static_cast<uint16_t>(value - kEndOfBlock - 1);
        uint32_t extra = 0;
        if (!bits.read_bits(kLengthExtra[length_code], extra)) {
            return stream_error(bits, ErrorKind::kTruncated, "deflate.LENGTH", 0,
                                "the stream ends inside a length code");
        }
        const uint32_t length = kLengthBase[length_code] + extra;

        Result<uint16_t> distance_symbol = decode_symbol(distance, bits, "deflate.DISTANCE");
        if (!distance_symbol.ok()) {
            return distance_symbol.error();
        }
        if (distance_symbol.value() >= 30) {
            return stream_error(bits, ErrorKind::kBadField, "deflate.DISTANCE", distance_symbol.value(),
                                "distance codes 30 and 31 are unused");
        }
        uint32_t distance_extra = 0;
        if (!bits.read_bits(kDistanceExtra[distance_symbol.value()], distance_extra)) {
            return stream_error(bits, ErrorKind::kTruncated, "deflate.DISTANCE", 0,
                                "the stream ends inside a distance code");
        }
        const uint32_t back = kDistanceBase[distance_symbol.value()] + distance_extra;
        if (back > out.size()) {
            return stream_error(bits, ErrorKind::kBadField, "deflate.DISTANCE", back,
                                "the match points before the start of the output");
        }
        if (out.size() + length > max_output) {
            return over_cap(bits, max_output);
        }
        const size_t start = out.size() - back;
        for (uint32_t index = 0; index < length; ++index) {
            out.push_back(out[start + index]);
        }
    }
}

Status inflate_body(BitReader &bits, std::vector<uint8_t> &out, size_t max_output) {
    for (;;) {
        uint8_t last = 0;
        uint32_t block_type = 0;
        if (!bits.read_bit(last) || !bits.read_bits(2, block_type)) {
            return stream_error(bits, ErrorKind::kTruncated, "deflate.BFINAL", 0,
                                "the stream ends before a block header");
        }
        if (block_type == 0) {
            // [RFC 1951] 3.2.4: LEN and its complement, then LEN raw bytes on a byte boundary.
            bits.align_to_byte();
            uint32_t length = 0;
            uint32_t complement = 0;
            if (!bits.read_bits(16, length) || !bits.read_bits(16, complement)) {
                return stream_error(bits, ErrorKind::kTruncated, "deflate.LEN", 0,
                                    "the stream ends inside a stored block header");
            }
            if ((length ^ 0xFFFFu) != complement) {
                return stream_error(bits, ErrorKind::kBadField, "deflate.NLEN", complement,
                                    "NLEN is not the complement of LEN");
            }
            ByteView payload;
            if (!bits.take_bytes(length, payload)) {
                return stream_error(bits, ErrorKind::kTruncated, "deflate.LEN", length,
                                    "the stream ends inside a stored block");
            }
            if (out.size() + length > max_output) {
                return over_cap(bits, max_output);
            }
            out.insert(out.end(), payload.data(), payload.data() + payload.size());
        } else if (block_type == 1) {
            Status status =
                inflate_encoded(fixed_literals(), fixed_distances(), bits, out, max_output, "deflate.FIXED");
            if (!status.ok()) {
                return status;
            }
        } else if (block_type == 2) {
            Huffman distance;
            Result<Huffman> literals = read_dynamic_tables(bits, distance);
            if (!literals.ok()) {
                return literals.error();
            }
            Status status = inflate_encoded(literals.value(), distance, bits, out, max_output,
                                            "deflate.DYNAMIC");
            if (!status.ok()) {
                return status;
            }
        } else {
            return stream_error(bits, ErrorKind::kBadField, "deflate.BTYPE", block_type,
                                "block type 3 is not defined");
        }
        if (last != 0) {
            return Status();
        }
    }
}

} // namespace

// [RFC 1950] 2.2 Adler-32: two running 16-bit sums modulo 65521, high half first.
uint32_t adler32(ByteView data) {
    uint32_t low = 1;
    uint32_t high = 0;
    for (size_t index = 0; index < data.size(); ++index) {
        low = (low + data.data()[index]) % 65521u;
        high = (high + low) % 65521u;
    }
    return (high << 16) | low;
}

bool zlib_header_present(ByteView block) {
    if (block.size() < kZlibHeaderBytes + kZlibTrailerBytes) {
        return false;
    }
    const uint8_t cmf = block.data()[0];
    const uint8_t flg = block.data()[1];
    if ((cmf & kZlibCmfMethodMask) != kZlibCmfMethodDeflate) {
        return false;
    }
    const uint32_t pair = (static_cast<uint32_t>(cmf) << 8) | flg;
    return pair % kZlibCheckModulus == 0;
}

Result<std::vector<uint8_t>> inflate_deflate(ByteView stream, size_t max_output) {
    BitReader bits(stream);
    std::vector<uint8_t> out;
    Status status = inflate_body(bits, out, max_output);
    if (!status.ok()) {
        return status.error();
    }
    return out;
}

Result<ZlibStream> inflate_zlib(ByteView block, size_t max_output) {
    if (!zlib_header_present(block)) {
        const uint32_t pair = block.size() >= 2 ? ((static_cast<uint32_t>(block.data()[0]) << 8) |
                                                   block.data()[1])
                                                : 0;
        return make_error(ErrorKind::kBadSignature, "zlib.CMF", block.base(), pair,
                          "the block does not start with a zlib CMF/FLG pair");
    }
    if ((block.data()[1] & kZlibFlgPresetDictionary) != 0) {
        return make_error(ErrorKind::kUnsupported, "zlib.FLG", block.base(), block.data()[1],
                          "FDICT is set: a preset dictionary appears in no OST block measured here");
    }

    BitReader bits(block);
    uint32_t header = 0;
    if (!bits.read_bits(kZlibHeaderBytes * 8, header)) {
        return make_error(ErrorKind::kTruncated, "zlib.CMF", block.base(), 0,
                          "the block is shorter than a zlib header");
    }

    std::vector<uint8_t> out;
    Status status = inflate_body(bits, out, max_output);
    if (!status.ok()) {
        return status.error();
    }

    // [RFC 1950] 2.2: the Adler-32 follows the deflate stream on a byte boundary, and a final
    // block is allowed to end mid-byte.
    bits.align_to_byte();
    ByteView trailer;
    if (!bits.take_bytes(kZlibTrailerBytes, trailer)) {
        return stream_error(bits, ErrorKind::kTruncated, "zlib.adler32", 0,
                            "the stream ends before the Adler-32");
    }
    uint32_t stored = 0;
    for (size_t index = 0; index < kZlibTrailerBytes; ++index) {
        stored = (stored << 8) | trailer.data()[index];
    }
    const uint32_t computed = adler32(ByteView(out.data(), out.size(), block.base()));
    if (stored != computed) {
        return make_error(ErrorKind::kBadCrc, "zlib.adler32", trailer.base(), stored,
                          "the checksum does not match the inflated bytes");
    }

    ZlibStream result;
    result.data = std::move(out);
    result.consumed = bits.byte_offset();
    return result;
}

} // namespace ost2pst::util
