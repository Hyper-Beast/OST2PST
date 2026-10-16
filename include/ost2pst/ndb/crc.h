#pragma once

#include <cstdint>

#include "ost2pst/ndb/layout.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/crc32.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ndb {

// The four ComputeCRC readings worth measuring. [MS-PST] 5.3 seeds 0 and returns without a final
// complement, but M0 must confirm that against real trailers instead of trusting the pseudocode.
enum class CrcVariant {
    kSeed0Plain,
    kSeed0Complement,
    kSeedOnesPlain,
    kSeedOnesComplement,
};

const char *crc_variant_name(CrcVariant variant);

// Both header CRCs measured against the byte ranges the spec assigns them ([MS-PST] 2.2.2.1).
struct HeaderCrcReport {
    uint32_t stored_partial = 0;
    uint32_t computed_partial = 0;
    uint32_t stored_full = 0;
    uint32_t computed_full = 0;
    bool partial_ok = false;
    bool full_ok = false;
};

// view must cover the whole HEADER (kHeaderSize bytes) from kHeaderOffset.
util::Result<HeaderCrcReport> verify_header_crcs(util::ByteView view);

// Per-variant match counts over every trailer the probe verified. The variant with a perfect score
// is the one the writer has to reproduce.
struct CrcVariantTally {
    uint64_t total = 0;
    uint64_t match_seed0_plain = 0;
    uint64_t match_seed0_complement = 0;
    uint64_t match_seed_ones_plain = 0;
    uint64_t match_seed_ones_complement = 0;
};

// One pass keeps two accumulators (seed 0 and seed all-ones); both complements are ~ of those, so a
// trailer costs one CRC pass and four comparisons.
void tally_crc(CrcVariantTally &tally, uint32_t stored, util::ByteView data);

} // namespace ost2pst::ndb
