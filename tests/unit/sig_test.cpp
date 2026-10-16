// [MS-PST] 5.5 ComputeSig, the wSig carried by every PAGETRAILER and BLOCKTRAILER.
//
// Note the name collision the spec itself invites: the LTP dumps in [MS-PST] 3.x print a "Block
// Signature: 0xEC" which is the HEAP_SIGNATURE byte inside a BTH, not the trailer's wSig. Only
// ComputeSig(ib, bid) is tested here.
#include <vector>

#include "ost2pst/util/sig.h"
#include "test_support.h"

namespace {

using ost2pst::util::compute_sig;

// Independent restatement of [MS-PST] 5.5: fold the high and low 16 bits of the 32-bit XOR.
uint16_t reference_sig(uint64_t ib, uint64_t bid) {
    const uint32_t x = static_cast<uint32_t>((ib ^ bid) & 0xFFFFFFFFu);
    return static_cast<uint16_t>(static_cast<uint16_t>(x >> 16) ^ static_cast<uint16_t>(x));
}

void check_spec_cases() {
    TEST_EQ(compute_sig(0x4400, 0x4400), 0x0000, "ComputeSig(0x4400, 0x4400)");
    TEST_EQ(compute_sig(0x1234, 0x00FF), 0x12CB, "ComputeSig(0x1234, 0x00FF)");
    TEST_EQ(compute_sig(0x12345678, 0x00000001), 0x444D, "ComputeSig(0x12345678, 1)");
    TEST_EQ(compute_sig(0xFFFF0000, 0), 0xFFFF, "ComputeSig(0xFFFF0000, 0)");
    TEST_EQ(compute_sig(0xFFFFFFFF, 0xFFFFFFFF), 0x0000, "ComputeSig(0xFFFFFFFF, 0xFFFFFFFF)");

    // Unicode IB and BID are 64-bit while the spec's pseudocode folds a DWORD: bits 32 and above
    // must not leak into the result.
    TEST_EQ(compute_sig(0x100000000, 0), 0x0000, "ComputeSig(0x100000000, 0) discards bits 32+");
    TEST_EQ(compute_sig(0x100010000, 0), 0x0001, "ComputeSig(0x100010000, 0) discards bits 32+");
    TEST_EQ(compute_sig(0x10000000, 0x00000001), 0x1001, "ComputeSig(0x10000000, 1)");

    // Real offsets from the sample: a page BID is ib/64, a block BID is its own allocation id.
    TEST_EQ(compute_sig(0x4400, 0x110), 0x4510, "ComputeSig(AMap page 0x4400, bid 0x110)");
    TEST_EQ(compute_sig(0x4200, 0x108), 0x4308, "ComputeSig(DList page 0x4200, bid 0x108)");
    TEST_EQ(compute_sig(0x908A00, 0x1518), 0x9F88, "ComputeSig(block 0x908A00, bid 0x1518)");
}

void check_against_reference() {
    uint64_t ib = 0x4400;
    uint64_t bid = 0x110;
    for (int i = 0; i < 4096; ++i) {
        ib = ib * 6364136223846793005ULL + 1442695040888963407ULL;
        bid = bid * 2862933518186247529ULL + 3037000493ULL;
        TEST_EQ(compute_sig(ib, bid), reference_sig(ib, bid), "ComputeSig against reference");
    }
}

void check_properties() {
    // ib ^ bid == 0 whenever they are equal, so the signature is always zero there.
    for (uint64_t value : {0x0ULL, 0x4400ULL, 0x9D152000ULL, 0xFFFFFFFFFFFFFFFFULL}) {
        TEST_EQ(compute_sig(value, value), 0x0000, "ComputeSig(x, x) is zero");
    }
    // Only the low 32 bits of (ib ^ bid) matter, so XORing both sides with the same mask is neutral.
    const uint64_t mask = 0x0000FFFF0000FFFFULL;
    for (uint64_t ib : {0x4400ULL, 0x123456789ULL, 0xFEDCBA9876ULL}) {
        for (uint64_t bid : {0x1ULL, 0x110ULL, 0x1234567890ULL}) {
            TEST_EQ(compute_sig(ib, bid), compute_sig(ib ^ mask, bid ^ mask),
                    "ComputeSig depends only on the low 32 bits of ib ^ bid");
        }
    }
}

} // namespace

int main() {
    check_spec_cases();
    check_against_reference();
    check_properties();
    return ost2pst::test::finish("sig_test");
}
