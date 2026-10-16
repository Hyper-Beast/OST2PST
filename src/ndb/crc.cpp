#include "ost2pst/ndb/crc.h"

#include "internal/take.h"

namespace ost2pst::ndb {

using util::ByteView;
using util::CrcSeed;
using util::DataError;
using util::ErrorKind;
using util::make_error;
using util::Result;

const char *crc_variant_name(CrcVariant variant) {
    switch (variant) {
    case CrcVariant::kSeed0Plain:
        return "seed0-plain";
    case CrcVariant::kSeed0Complement:
        return "seed0-complement";
    case CrcVariant::kSeedOnesPlain:
        return "seed-ones-plain";
    case CrcVariant::kSeedOnesComplement:
        return "seed-ones-complement";
    }
    return "unknown";
}

Result<HeaderCrcReport> verify_header_crcs(ByteView view) {
    if (!view.in_range(0, kHeaderSize)) {
        return make_error(ErrorKind::kTruncated, "HEADER", view.base(), view.size(),
                          "header CRC needs the full 564-byte header");
    }

    HeaderCrcReport report;
    DataError failure;
    if (!take(view.u32(kDwCRCPartialOffset), report.stored_partial, "HEADER.dwCRCPartial", failure)) {
        return failure;
    }
    if (!take(view.u32(kDwCRCFullOffset), report.stored_full, "HEADER.dwCRCFull", failure)) {
        return failure;
    }

    // [MS-PST] 2.2.2.1: dwCRCPartial covers 471 bytes from wMagicClient, dwCRCFull covers 516 bytes
    // from wMagicClient through bidNextB inclusive. Both skip their own CRC field.
    Result<ByteView> partial = view.sub(kCrcPartialStart, kCrcPartialLength);
    if (!partial.ok()) {
        return partial.error();
    }
    Result<ByteView> full = view.sub(kCrcFullStart, kCrcFullLength);
    if (!full.ok()) {
        return full.error();
    }

    report.computed_partial = util::crc32(partial.value());
    report.computed_full = util::crc32(full.value());
    report.partial_ok = report.computed_partial == report.stored_partial;
    report.full_ok = report.computed_full == report.stored_full;
    return report;
}

void tally_crc(CrcVariantTally &tally, uint32_t stored, ByteView data) {
    ++tally.total;
    const uint32_t seed0 = util::crc32_update(0u, data);
    const uint32_t seed_ones = util::crc32_update(0xFFFFFFFFu, data);
    if (stored == seed0) {
        ++tally.match_seed0_plain;
    }
    if (stored == ~seed0) {
        ++tally.match_seed0_complement;
    }
    if (stored == seed_ones) {
        ++tally.match_seed_ones_plain;
    }
    if (stored == ~seed_ones) {
        ++tally.match_seed_ones_complement;
    }
}

} // namespace ost2pst::ndb
