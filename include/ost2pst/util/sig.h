#pragma once

#include <cstdint>

namespace ost2pst::util {

// [MS-PST] 5.5 Block Signature: ib ^= bid, then XOR the two halves of the low 32 bits.
uint16_t compute_sig(uint64_t ib, uint64_t bid);

} // namespace ost2pst::util
