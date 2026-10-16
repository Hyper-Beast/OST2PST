#include "ost2pst/writer/nid.h"

#include <algorithm>

#include "ost2pst/ltp/layout.h"

namespace ost2pst::writer {

using util::ErrorKind;
using util::make_error;
using util::Result;

LocalNids::LocalNids(uint32_t first_index) : next_index_(first_index) {}

uint64_t LocalNids::taken() const { return taken_; }

Result<uint32_t> LocalNids::take(uint32_t nid_type) {
    while (std::find(used_.begin(), used_.end(), next_index_) != used_.end()) {
        ++next_index_;
    }
    return take_at(next_index_, nid_type);
}

Result<uint32_t> LocalNids::take_at(uint32_t index, uint32_t nid_type) {
    // [MS-PST] 2.2.2.1 gives a NID a 27-bit nidIndex, and every field that names a subnode is 4 bytes
    // ([MS-PST] 2.3.3.3 dwValueHnid, 2.3.4.1 TCINFO.hnidRows, 2.3.4.4.2 the rgdwData slot), so an
    // index wider than that could not be referenced at all.
    if (index > ltp::kNidIndexMask) {
        return make_error(ErrorKind::kBadField, "SLENTRY.nid", index, nid_type,
                          "a nidIndex is 27 bits and a 4-byte HNID cannot name a wider subnode ([MS-PST] 2.2.2.1 / 2.3.3.3)");
    }
    if (nid_type > ltp::kNidTypeMask) {
        return make_error(ErrorKind::kBadField, "nidType", nid_type, index,
                          "nidType is 5 bits ([MS-PST] 2.2.2.1)");
    }
    if (std::find(used_.begin(), used_.end(), index) != used_.end()) {
        return make_error(ErrorKind::kBadField, "SLENTRY.nid", index, nid_type,
                          "a subnode NID is unique only within its parent node, so one index cannot name two subnodes ([MS-PST] 2.2.2.8.3.3.1.1)");
    }
    used_.push_back(index);
    ++taken_;
    return static_cast<uint32_t>(ltp::make_nid(index, nid_type));
}

} // namespace ost2pst::writer
