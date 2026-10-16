#include "ost2pst/ndb/header.h"

namespace ost2pst::ndb {

using util::ByteView;
using util::DataError;
using util::ErrorKind;
using util::make_error;
using util::Result;
using util::Status;

namespace {

template <class T>
bool take(Result<T> read, T &destination, const char *field, DataError &failure) {
    if (read.ok()) {
        destination = read.value();
        return true;
    }
    failure = read.error();
    failure.field = field;
    return false;
}

bool take_bytes(ByteView view, uint64_t offset, uint8_t *destination, size_t count, const char *field,
                DataError &failure) {
    Result<ByteView> window = view.sub(offset, count);
    if (!window.ok()) {
        failure = window.error();
        failure.field = field;
        return false;
    }
    for (size_t i = 0; i < count; ++i) {
        destination[i] = window.value().data()[i];
    }
    return true;
}

bool refuse(const char *field, uint64_t offset, uint64_t value, const char *detail, DataError &failure) {
    failure = make_error(ErrorKind::kUnsupported, field, offset, value, detail);
    return false;
}

} // namespace

Result<Header> decode_header(ByteView view) {
    Header header;
    DataError failure;

    if (!take(view.u32(kDwMagicOffset), header.dw_magic, "HEADER.dwMagic", failure)) {
        return failure;
    }
    if (!take(view.u32(kDwCRCPartialOffset), header.dw_crc_partial, "HEADER.dwCRCPartial", failure)) {
        return failure;
    }
    if (!take_bytes(view, kWMagicClientOffset, header.w_magic_client.data(),
                    header.w_magic_client.size(), "HEADER.wMagicClient", failure)) {
        return failure;
    }
    if (!take(view.u16(kWVerOffset), header.w_ver, "HEADER.wVer", failure)) {
        return failure;
    }
    if (!take(view.u16(kWVerClientOffset), header.w_ver_client, "HEADER.wVerClient", failure)) {
        return failure;
    }
    if (!take(view.u8(kBPlatformCreateOffset), header.b_platform_create, "HEADER.bPlatformCreate",
              failure)) {
        return failure;
    }
    if (!take(view.u8(kBPlatformAccessOffset), header.b_platform_access, "HEADER.bPlatformAccess",
              failure)) {
        return failure;
    }
    if (!take(view.u32(0x010), header.dw_reserved1, "HEADER.dwReserved1", failure)) {
        return failure;
    }
    if (!take(view.u32(0x014), header.dw_reserved2, "HEADER.dwReserved2", failure)) {
        return failure;
    }
    if (!take(view.u64(0x018), header.bid_unused, "HEADER.bidUnused", failure)) {
        return failure;
    }
    if (!take(view.u64(kBidNextPOffset), header.bid_next_p, "HEADER.bidNextP", failure)) {
        return failure;
    }
    if (!take(view.u32(0x028), header.dw_unique, "HEADER.dwUnique", failure)) {
        return failure;
    }
    for (uint64_t index = 0; index < kRgnidCount; ++index) {
        if (!take(view.u32(kRgnidOffset + index * 4), header.rgnid[index], "HEADER.rgnid", failure)) {
            return failure;
        }
    }
    if (!take(view.u64(0x0AC), header.qw_unused, "HEADER.qwUnused", failure)) {
        return failure;
    }

    Result<Root> root = decode_root(view, kRootOffset);
    if (!root.ok()) {
        return root.error();
    }
    header.root = root.value();

    if (!take(view.u32(kDwAlignOffset), header.dw_align, "HEADER.dwAlign", failure)) {
        return failure;
    }
    if (!take_bytes(view, kRgbFmOffset, header.rgb_fm.data(), header.rgb_fm.size(), "HEADER.rgbFM",
                    failure)) {
        return failure;
    }
    if (!take_bytes(view, kRgbFpOffset, header.rgb_fp.data(), header.rgb_fp.size(), "HEADER.rgbFP",
                    failure)) {
        return failure;
    }
    if (!take(view.u8(kBSentinelOffset), header.b_sentinel, "HEADER.bSentinel", failure)) {
        return failure;
    }
    if (!take(view.u8(kBCryptMethodOffset), header.b_crypt_method, "HEADER.bCryptMethod", failure)) {
        return failure;
    }
    if (!take_bytes(view, 0x202, header.rgb_reserved.data(), header.rgb_reserved.size(),
                    "HEADER.rgbReserved", failure)) {
        return failure;
    }
    if (!take(view.u64(kBidNextBOffset), header.bid_next_b, "HEADER.bidNextB", failure)) {
        return failure;
    }
    if (!take(view.u32(kDwCRCFullOffset), header.dw_crc_full, "HEADER.dwCRCFull", failure)) {
        return failure;
    }
    if (!take_bytes(view, kRgbReserved2Offset, header.rgb_reserved2.data(),
                    header.rgb_reserved2.size(), "HEADER.rgbReserved2", failure)) {
        return failure;
    }
    if (!take(view.u8(kBReservedOffset), header.b_reserved, "HEADER.bReserved", failure)) {
        return failure;
    }
    if (!take_bytes(view, kRgbReserved3Offset, header.rgb_reserved3.data(),
                    header.rgb_reserved3.size(), "HEADER.rgbReserved3", failure)) {
        return failure;
    }
    return header;
}

Status validate_header_refusals(const Header &header) {
    DataError failure;

    if (header.dw_magic != kDwMagicValue) {
        // [MS-PST] 2.2.2.1: not an NDB file at all.
        if (refuse("HEADER.dwMagic", kDwMagicOffset, header.dw_magic, "not an NDB/LTP file", failure)) {
            return Status();
        }
        return failure;
    }
    if (header.w_ver < kMinUnicodeVer) {
        // [MS-PST] 2.2.2.1: wVer < 23 is the ANSI layout, which this converter does not read.
        if (refuse("HEADER.wVer", kWVerOffset, header.w_ver, "ANSI (wVer < 23) is not supported", failure)) {
            return Status();
        }
        return failure;
    }
    if (header.w_ver == kWipVer) {
        // [MS-PST] 2.2.2.1: wVer 37 is WIP-encrypted; the key lives outside the file.
        if (refuse("HEADER.wVer", kWVerOffset, header.w_ver, "WIP-protected PST is not supported", failure)) {
            return Status();
        }
        return failure;
    }
    if (header.w_magic_client[0] != kWMagicClientS ||
        (header.w_magic_client[1] != kWMagicClientM && header.w_magic_client[1] != kWMagicClientO)) {
        // [MS-PST] 2.2.2.1 requires "SM"; Outlook OST files write "SO" (DEVELOPMENT.md).
        const uint64_t value = (static_cast<uint64_t>(header.w_magic_client[1]) << 8) |
                               header.w_magic_client[0];
        if (refuse("HEADER.wMagicClient", kWMagicClientOffset, value, "wMagicClient is neither SM nor SO",
                   failure)) {
            return Status();
        }
        return failure;
    }
    if (header.b_platform_create != kPlatformId || header.b_platform_access != kPlatformId) {
        // [MS-PST] 2.2.2.1: both MUST be 0x01.
        const uint64_t value = (static_cast<uint64_t>(header.b_platform_access) << 8) |
                               header.b_platform_create;
        if (refuse("HEADER.bPlatform", kBPlatformCreateOffset, value, "platform ids must both be 0x01",
                   failure)) {
            return Status();
        }
        return failure;
    }
    if (header.dw_align != 0) {
        // [MS-PST] 2.2.2.1: dwAlign MUST be 0.
        if (refuse("HEADER.dwAlign", kDwAlignOffset, header.dw_align, "dwAlign must be 0", failure)) {
            return Status();
        }
        return failure;
    }
    if (header.b_sentinel != kBSentinelValue) {
        // [MS-PST] 2.2.2.1: bSentinel MUST be 0x80.
        if (refuse("HEADER.bSentinel", kBSentinelOffset, header.b_sentinel, "bSentinel must be 0x80",
                   failure)) {
            return Status();
        }
        return failure;
    }
    if (header.b_crypt_method != kCryptMethodNone) {
        // [MS-PST] 2.2.2.1 + 2.2.2.8.3.1.1: permute/cyclic obfuscation needs the bCryptMethod key.
        if (refuse("HEADER.bCryptMethod", kBCryptMethodOffset, header.b_crypt_method,
                   "obfuscated blocks are not supported in M0", failure)) {
            return Status();
        }
        return failure;
    }
    if (header.root.f_amap_valid == kFAMapInvalid) {
        // [MS-PST] 2.2.2.5 + 2.6.1.3.7: fAMapValid MUST be checked before using the AMaps.
        if (refuse("ROOT.fAMapValid", kHeaderOffset + kRootOffset + kRootFAMapValidOffset,
                   header.root.f_amap_valid, "AMap is INVALID_AMAP; allocation maps cannot be trusted",
                   failure)) {
            return Status();
        }
        return failure;
    }
    return Status();
}

std::string magic_client_text(const Header &header) {
    std::string text;
    for (uint8_t byte : header.w_magic_client) {
        text.push_back(static_cast<char>(byte));
    }
    return text;
}

} // namespace ost2pst::ndb
