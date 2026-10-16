#include "ost2pst/ndb/block_reader.h"

#include <string>
#include <utility>

#include "ost2pst/ndb/trailer.h"
#include "ost2pst/util/crc32.h"
#include "ost2pst/util/sig.h"

namespace ost2pst::ndb {

using util::ByteView;
using util::ErrorKind;
using util::make_error;
using util::Result;
using util::Status;

uint64_t block_footprint(FileProfile profile, uint16_t cb) {
    // [MS-PST] 2.2.2.8: rounded up to the granularity, trailer included.
    return align_allocation(profile, static_cast<uint64_t>(cb) + block_trailer_size(profile));
}

Result<BlockData> read_block(const util::FileReader &file, FileProfile profile, const BbtIndex &index,
                             uint64_t bid, BlockReadCounters &counters, FailureLog &failures) {
    ++counters.requested;

    const BbtEntry *entry = index.lookup(bid);
    if (entry == nullptr) {
        // The caller knows which record asked for this BID, so it reports the finding with the offset
        // that actually points at it. Counting it here is enough for the walk to keep going.
        ++counters.not_indexed;
        return make_error(ErrorKind::kBadField, "BBTENTRY.bid", 0, bid,
                          "the BBT does not index this BID");
    }

    const uint64_t footprint = block_footprint(profile, entry->cb);
    if (footprint > block_max_size(profile) || entry->ib % block_granularity(profile) != 0 ||
        entry->ib > file.size() || file.size() - entry->ib < footprint) {
        ++counters.out_of_range;
        failures.add(entry->ib, "BBTENTRY.ib", entry->ib,
                     "block footprint of " + std::to_string(footprint) +
                         " bytes is misaligned or runs past the file");
        return make_error(ErrorKind::kBadField, "BBTENTRY.ib", entry->ib, footprint,
                          "block footprint is misaligned or past the end of the file");
    }

    std::vector<uint8_t> buffer(static_cast<size_t>(footprint));
    Status io = file.read_at(entry->ib, buffer.data(), buffer.size());
    if (!io) {
        return io.error();
    }

    const uint64_t trailer_at = entry->ib + footprint - block_trailer_size(profile);
    Result<ByteView> window =
        ByteView(buffer.data(), buffer.size(), entry->ib)
            .sub(footprint - block_trailer_size(profile), block_trailer_size(profile));
    if (!window.ok()) {
        return window.error();
    }
    Result<BlockTrailer> decoded = decode_block_trailer(window.value(), profile);
    if (!decoded.ok()) {
        failures.add(decoded.error());
        return decoded.error();
    }
    ++counters.decoded;
    const BlockTrailer &trailer = decoded.value();

    // [MS-PST] 2.2.2.7.7.3 and 2.2.2.8.1 describe the same block from the index side and the block
    // side, so the two must agree on the BID and the raw size.
    if (trailer.cb == entry->cb) {
        ++counters.cb_matches;
    } else {
        ++counters.cb_mismatches;
        failures.add(trailer_at, "BLOCKTRAILER.cb", trailer.cb,
                     "BBTENTRY.cb is " + std::to_string(entry->cb));
    }
    if (trailer.bid == entry->bid) {
        ++counters.bid_matches;
    } else {
        ++counters.bid_mismatches;
        failures.add(trailer_at, "BLOCKTRAILER.bid", trailer.bid,
                     "BBTENTRY.bid is " + std::to_string(entry->bid));
    }

    const uint16_t expected_sig = util::compute_sig(entry->ib, trailer.bid);
    if (expected_sig == trailer.w_sig) {
        ++counters.sig_ok;
    } else {
        ++counters.sig_failed;
        failures.add(trailer_at, "BLOCKTRAILER.wSig", trailer.w_sig,
                     "expected " + std::to_string(expected_sig));
    }

    // [MS-PST] 2.2.2.8.1: dwCRC covers only the cb raw data bytes.
    const ByteView data(buffer.data(), trailer.cb, entry->ib);
    if (util::crc32(data) == trailer.dw_crc) {
        ++counters.crc_ok;
    } else {
        ++counters.crc_failed;
        failures.add(trailer_at, "BLOCKTRAILER.dwCRC", trailer.dw_crc,
                     "block CRC over " + std::to_string(trailer.cb) + " bytes does not match");
    }

    BlockData block;
    block.bid = entry->bid;
    block.ib = entry->ib;
    block.cb = trailer.cb;
    block.footprint = footprint;
    // [MS-PST] 2.2.2.2 bit B, read off the BBTENTRY that names this block: the index side is what says
    // whether the block holds data or names other blocks ([MS-PST] 2.2.2.8.3).
    block.internal = bid_is_internal(entry->bid);
    // The OST trailer's uncompressed length is the compression answer, and it agrees with the BBTENTRY
    // slot -- probe.cpp compares the two on every block. MS-PST describes no block compression at all, so
    // a PST-profile block has no such slot and is read as its own bytes.
    block.uncompressed_cb = trailer.ost_uncompressed_cb;
    block.compressed =
        profile == FileProfile::kOst && trailer.ost_uncompressed_cb != trailer.cb;
    block.data.assign(buffer.begin(), buffer.begin() + trailer.cb);
    counters.data_bytes += block.data.size();
    return block;
}

} // namespace ost2pst::ndb
