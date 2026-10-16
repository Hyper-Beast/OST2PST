#include "ost2pst/ndb/trailer.h"

#include <string>

#include "internal/take.h"

namespace ost2pst::ndb {

using util::ByteView;
using util::DataError;
using util::ErrorKind;
using util::make_error;
using util::Result;

Result<PageTrailer> decode_page_trailer(ByteView view, FileProfile profile) {
    const uint64_t trailer_size = page_trailer_size(profile); // [MS-PST] 2.2.2.7.1 trailer size per profile
    if (!view.in_range(0, static_cast<size_t>(trailer_size))) {
        return make_error(ErrorKind::kTruncated, "PAGETRAILER", view.base(), view.size(),
                          "this profile needs a " + std::to_string(trailer_size) + "-byte trailer window");
    }

    PageTrailer trailer;
    DataError failure;

    if (!take(view.u8(kPageTrailerPtypeOffset), trailer.ptype, "PAGETRAILER.ptype", failure)) {
        return failure;
    }
    if (!take(view.u8(kPageTrailerPtypeRepeatOffset), trailer.ptype_repeat, "PAGETRAILER.ptypeRepeat",
              failure)) {
        return failure;
    }
    if (!take(view.u16(kPageTrailerWSigOffset), trailer.w_sig, "PAGETRAILER.wSig", failure)) {
        return failure;
    }
    if (!take(view.u32(kPageTrailerCrcOffset), trailer.dw_crc, "PAGETRAILER.dwCRC", failure)) {
        return failure;
    }
    if (!take(view.u64(kPageTrailerBidOffset), trailer.bid, "PAGETRAILER.bid", failure)) {
        return failure;
    }
    if (profile == FileProfile::kOst) {
        // [MS-PST] 2.2.2.7.1 has no field here; OST writes 1 in this slot on every page measured.
        if (!take(view.u32(kOstPageTrailerFlagOffset), trailer.ost_flag, "PAGETRAILER.ostFlag", failure)) {
            return failure;
        }
    }

    // [MS-PST] 2.2.2.7.1: ptypeRepeat MUST equal ptype, and ptype MUST be one of the seven values.
    if (trailer.ptype != trailer.ptype_repeat) {
        return make_error(ErrorKind::kBadField, "PAGETRAILER.ptypeRepeat", view.base(),
                          trailer.ptype_repeat, "does not match ptype");
    }
    if (!is_page_type(trailer.ptype)) {
        return make_error(ErrorKind::kBadField, "PAGETRAILER.ptype", view.base(), trailer.ptype,
                          "not a defined page type");
    }
    return trailer;
}

Result<BlockTrailer> decode_block_trailer(ByteView view, FileProfile profile) {
    const uint64_t trailer_size = block_trailer_size(profile); // [MS-PST] 2.2.2.8.1 trailer size per profile
    if (!view.in_range(0, static_cast<size_t>(trailer_size))) {
        return make_error(ErrorKind::kTruncated, "BLOCKTRAILER", view.base(), view.size(),
                          "this profile needs a " + std::to_string(trailer_size) + "-byte trailer window");
    }

    BlockTrailer trailer;
    DataError failure;

    if (!take(view.u16(kBlockTrailerCbOffset), trailer.cb, "BLOCKTRAILER.cb", failure)) {
        return failure;
    }
    if (!take(view.u16(kBlockTrailerWSigOffset), trailer.w_sig, "BLOCKTRAILER.wSig", failure)) {
        return failure;
    }
    if (!take(view.u32(kBlockTrailerCrcOffset), trailer.dw_crc, "BLOCKTRAILER.dwCRC", failure)) {
        return failure;
    }
    if (!take(view.u64(kBlockTrailerBidOffset), trailer.bid, "BLOCKTRAILER.bid", failure)) {
        return failure;
    }
    if (profile == FileProfile::kOst) {
        // [MS-PST] 2.2.2.8.1 has no field here; OST writes its block type and the block's uncompressed
        // data length into it.
        if (!take(view.u16(kOstBlockTrailerTypOffset), trailer.ost_b_typ, "BLOCKTRAILER.ostBTyp", failure)) {
            return failure;
        }
        if (!take(view.u16(kOstBlockTrailerUncompressedCbOffset), trailer.ost_uncompressed_cb,
                  "BLOCKTRAILER.ostUncompressedCb", failure)) {
            return failure;
        }
    }

    // [MS-PST] 2.2.2.8: cb is the raw byte count inside one block, so a cb of 0 or a cb larger than
    // this profile's capacity cannot describe a real allocation.
    if (trailer.cb < 1 || trailer.cb > block_max_cb(profile)) {
        return make_error(ErrorKind::kBadField, "BLOCKTRAILER.cb", view.base(), trailer.cb,
                          "must be between 1 and " + std::to_string(block_max_cb(profile)));
    }
    return trailer;
}

bool is_page_type(uint8_t ptype) {
    return ptype >= kFirstPageType && ptype <= kLastPageType;
}

bool looks_like_page_trailer(const uint8_t *trailer) {
    return trailer[0] == trailer[1] && is_page_type(trailer[0]);
}

bool page_type_uses_zero_sig(uint8_t ptype) {
    // [MS-PST] 2.2.2.7.1: wSig is 0x0000 for FMap, PMap, AMap and FPMap pages, and computed for
    // BBT, NBT and DList pages.
    return ptype == kPageTypeFMap || ptype == kPageTypePMap || ptype == kPageTypeAMap ||
           ptype == kPageTypeFPMap;
}

const char *page_type_name(uint8_t ptype) {
    switch (ptype) {
    case kPageTypeBBT:
        return "BBT";
    case kPageTypeNBT:
        return "NBT";
    case kPageTypeFMap:
        return "FMap";
    case kPageTypePMap:
        return "PMap";
    case kPageTypeAMap:
        return "AMap";
    case kPageTypeFPMap:
        return "FPMap";
    case kPageTypeDList:
        return "DList";
    default:
        return "unknown";
    }
}

} // namespace ost2pst::ndb
