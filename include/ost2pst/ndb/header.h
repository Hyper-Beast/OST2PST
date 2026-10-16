#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "ost2pst/ndb/layout.h"
#include "ost2pst/ndb/root.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ndb {

// [MS-PST] 2.2.2.1 HEADER (Unicode). Field names mirror the spec names so a decode failure can be
// reported with the spec's own field name.
struct Header {
    uint32_t dw_magic = 0;
    uint32_t dw_crc_partial = 0;
    std::array<uint8_t, 2> w_magic_client{};
    uint16_t w_ver = 0;
    uint16_t w_ver_client = 0;
    uint8_t b_platform_create = 0;
    uint8_t b_platform_access = 0;
    uint32_t dw_reserved1 = 0;
    uint32_t dw_reserved2 = 0;
    uint64_t bid_unused = 0;
    uint64_t bid_next_p = 0;
    uint32_t dw_unique = 0;
    std::array<uint32_t, kRgnidCount> rgnid{};
    uint64_t qw_unused = 0;
    Root root;
    uint32_t dw_align = 0;
    std::array<uint8_t, kDeprecatedMapBytes> rgb_fm{};
    std::array<uint8_t, kDeprecatedMapBytes> rgb_fp{};
    uint8_t b_sentinel = 0;
    uint8_t b_crypt_method = 0;
    std::array<uint8_t, 2> rgb_reserved{};
    uint64_t bid_next_b = 0;
    uint32_t dw_crc_full = 0;
    std::array<uint8_t, 3> rgb_reserved2{};
    uint8_t b_reserved = 0;
    std::array<uint8_t, kRgbReserved3Bytes> rgb_reserved3{};
};

// Decodes every field but performs no policy refusal: a WIP or permute-encoded file still decodes.
util::Result<Header> decode_header(util::ByteView view);

// Refusals this project honours in M0: anything whose bytes we cannot interpret without Outlook.
util::Status validate_header_refusals(const Header &header);

std::string magic_client_text(const Header &header);

} // namespace ost2pst::ndb
