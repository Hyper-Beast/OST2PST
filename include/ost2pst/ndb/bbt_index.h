#pragma once

#include <cstdint>
#include <unordered_map>
#include <vector>

#include "ost2pst/ndb/btree.h"

namespace ost2pst::ndb {

// [MS-PST] 2.2.2.7.7.3: the BBT is the only structure that turns a BID into an offset, so every later
// layer resolves BIDs through it. A sorted array binary-searches in O(log n) and costs 32 bytes an
// entry, which is what the memory budget in DEVELOPMENT.md 5.3 measures against.
class BbtIndex {
public:
    BbtIndex() = default;
    explicit BbtIndex(const std::unordered_map<uint64_t, BbtEntry> &walked);

    // [MS-PST] 2.2.2.2: a block BID carries two flag bits, and only the reserved one is cleared before a
    // lookup: "Readers MUST ignore this bit and treat it as zero before looking up the BID from the BBT".
    // The internal bit is kept, so a BID that claims to name an internal block does not silently resolve
    // to an external block with the same bidIndex. Measured on the sample: 4,062 of the 4,805 references
    // that failed a whole-BID lookup resolve once bit 0 is cleared
    // (DEVELOPMENT.md).
    const BbtEntry *lookup(uint64_t bid) const;

    uint64_t entries() const { return sorted_.size(); }
    uint64_t bytes() const;
    uint64_t duplicates() const { return duplicates_; }
    uint64_t min_bid() const;
    uint64_t max_bid() const;

    const std::vector<BbtEntry> &entries_sorted() const { return sorted_; }

private:
    std::vector<BbtEntry> sorted_;
    uint64_t duplicates_ = 0;
};

} // namespace ost2pst::ndb
