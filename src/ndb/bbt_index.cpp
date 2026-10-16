#include "ost2pst/ndb/bbt_index.h"

#include <algorithm>

namespace ost2pst::ndb {

BbtIndex::BbtIndex(const std::unordered_map<uint64_t, BbtEntry> &walked) {
    sorted_.reserve(walked.size());
    for (const auto &item : walked) {
        sorted_.push_back(item.second);
    }
    std::sort(sorted_.begin(), sorted_.end(),
              [](const BbtEntry &left, const BbtEntry &right) {
                  return bid_lookup_key(left.bid) < bid_lookup_key(right.bid);
              });
    // [MS-PST] 2.2.2.7.7.3 gives one BBTENTRY per block, so two entries with the same BID mean the
    // walk reached the same leaf twice or the file indexes one block twice.
    for (size_t index = 1; index < sorted_.size(); ++index) {
        if (bid_lookup_key(sorted_[index].bid) == bid_lookup_key(sorted_[index - 1].bid)) {
            ++duplicates_;
        }
    }
}

const BbtEntry *BbtIndex::lookup(uint64_t bid) const {
    // [MS-PST] 2.2.2.2: the reserved bit is cleared on both sides of the comparison, the internal bit is
    // not. A reference that sets bit 0 therefore still finds its block; a reference that sets bit 0 and
    // bit 1 does not find an external block sharing its bidIndex.
    const uint64_t key = bid_lookup_key(bid);
    const auto found = std::lower_bound(
        sorted_.begin(), sorted_.end(), key,
        [](const BbtEntry &entry, uint64_t wanted) { return bid_lookup_key(entry.bid) < wanted; });
    if (found == sorted_.end() || bid_lookup_key(found->bid) != key) {
        return nullptr;
    }
    return &*found;
}

uint64_t BbtIndex::bytes() const {
    return sorted_.capacity() * sizeof(BbtEntry);
}

uint64_t BbtIndex::min_bid() const {
    return sorted_.empty() ? 0 : sorted_.front().bid;
}

uint64_t BbtIndex::max_bid() const {
    return sorted_.empty() ? 0 : sorted_.back().bid;
}

} // namespace ost2pst::ndb
