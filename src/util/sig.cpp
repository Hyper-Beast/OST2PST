#include "ost2pst/util/sig.h"

namespace ost2pst::util {

uint16_t compute_sig(uint64_t ib, uint64_t bid) {
    // [MS-PST] 5.5 folds only bits 16..31 with bits 0..15; bits 32..63 are discarded by the
    // uint16_t truncation of ib >> 16, so no extra folding is applied.
    ib ^= bid;
    return static_cast<uint16_t>(static_cast<uint16_t>(ib >> 16) ^ static_cast<uint16_t>(ib));
}

} // namespace ost2pst::util
