#pragma once

#include <cstdint>
#include <vector>

#include "ost2pst/ndb/bbt_index.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ndb {

// [MS-PST] 2.2.2.8.2: a block footprint is cb raw data bytes plus the trailer, rounded up to the
// granularity, and the trailer sits flush against the end of it.
uint64_t block_footprint(FileProfile profile, uint16_t cb);

// The bytes one BID holds, verified from both sides before anyone is allowed to read them.
struct BlockData {
    uint64_t bid = 0;
    uint64_t ib = 0;
    uint16_t cb = 0;
    uint64_t footprint = 0;
    // [MS-PST] 2.2.2.2 bit B as the BBTENTRY stores it: 1 means the block is Internal, i.e. it names
    // other blocks ([MS-PST] 2.2.2.8.3) instead of holding the data itself.
    bool internal = false;
    // The OST 4k-page trailer's uncompressed-data-length slot, read off the block's own trailer. MS-PST
    // 2.2.2.8.1 has no such field; libpff format notes (see THIRD_PARTY_NOTICES.txt) "The 64-bit 4k page block" names it,
    // and on the sample it equals cb on the 71,584 raw blocks and the inflated length on the 126,527
    // compressed ones, so it is what says whether a block is compressed.
    uint16_t uncompressed_cb = 0;
    bool compressed = false;
    std::vector<uint8_t> data; // exactly cb bytes: [MS-PST] 2.2.2.8.1 says padding is not part of a block
};

// Every check read_block can fail, counted so a walk reports rates instead of the first complaint.
struct BlockReadCounters {
    uint64_t requested = 0;
    uint64_t not_indexed = 0;
    uint64_t out_of_range = 0;
    uint64_t decoded = 0;
    uint64_t cb_matches = 0;
    uint64_t cb_mismatches = 0;
    uint64_t bid_matches = 0;
    uint64_t bid_mismatches = 0;
    uint64_t sig_ok = 0;
    uint64_t sig_failed = 0;
    uint64_t crc_ok = 0;
    uint64_t crc_failed = 0;
    uint64_t data_bytes = 0;
};

// Resolves a BID through the BBT index, reads its footprint, and checks that the block agrees with the
// entry that points at it: cb, bid, wSig, and the CRC over exactly cb bytes
// ([MS-PST] 2.2.2.7.7.3 / 2.2.2.8.1 / 2.2.2.8.2). A mismatch between the two sides is counted and
// logged and the bytes still come back, because a walk has to keep going; only a BID the index does
// not hold, a footprint that cannot fit in the file, or an undecodable trailer is returned as an error.
util::Result<BlockData> read_block(const util::FileReader &file, FileProfile profile,
                                   const BbtIndex &index, uint64_t bid, BlockReadCounters &counters,
                                   FailureLog &failures);

} // namespace ost2pst::ndb
