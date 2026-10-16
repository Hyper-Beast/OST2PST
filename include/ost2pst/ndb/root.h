#pragma once

#include <cstdint>

#include "ost2pst/ndb/layout.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ndb {

// [MS-PST] 2.2.2.4 BREF (Unicode).
struct BRef {
    uint64_t bid = 0;
    uint64_t ib = 0;
};

// [MS-PST] 2.2.2.5 ROOT (Unicode, 72 bytes), embedded in the HEADER at kRootOffset.
struct Root {
    uint32_t dw_reserved = 0;
    uint64_t ib_file_eof = 0;
    uint64_t ib_amap_last = 0;
    uint64_t cb_amap_free = 0;
    uint64_t cb_pmap_free = 0;
    BRef nbt_bref;
    BRef bbt_bref;
    uint8_t f_amap_valid = 0;
    uint8_t b_reserved = 0;
    uint16_t w_reserved = 0;
};

// offset is the absolute offset of the ROOT record, i.e. kHeaderOffset + kRootOffset.
util::Result<Root> decode_root(util::ByteView view, uint64_t offset);

} // namespace ost2pst::ndb
