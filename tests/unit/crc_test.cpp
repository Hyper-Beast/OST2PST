// CRC-32 as [MS-PST] 5.3 defines it, plus the four seed/complement readings M0 has to choose
// between. The reference implementation below recomputes the table value bit by bit so a mistake in
// the constexpr table cannot hide behind a matching test.
#include <string>
#include <vector>

#include "ost2pst/ndb/crc.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/util/crc32.h"
#include "test_support.h"

namespace {

using ost2pst::ndb::CrcVariantTally;
using ost2pst::ndb::verify_header_crcs;
using ost2pst::util::ByteView;
using ost2pst::util::CrcSeed;

ByteView text_view(const std::string &text) {
    return ByteView(reinterpret_cast<const uint8_t *>(text.data()), text.size());
}

ByteView bytes_view(const std::vector<uint8_t> &bytes) {
    return ByteView(bytes.data(), bytes.size());
}

// [MS-PST] 5.3: dwCRC = CrcTableOffset32[(dwCRC ^ byte) & 0xFF] ^ (dwCRC >> 8), with the table entry
// rebuilt from the polynomial 0xEDB88320 instead of read from the table under test.
uint32_t reference_crc(uint32_t crc, const uint8_t *bytes, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        uint32_t index = static_cast<uint32_t>((crc ^ bytes[i]) & 0xFFu);
        for (int bit = 0; bit < 8; ++bit) {
            index = (index & 1u) ? (0xEDB88320u ^ (index >> 1)) : (index >> 1);
        }
        crc = index ^ (crc >> 8);
    }
    return crc;
}

void check_spec_table() {
    // [MS-PST] 5.3 CrcTableOffset32, first row of the table as printed in the spec.
    TEST_EQ(ost2pst::util::kCrc32Table[0], 0x00000000u, "CrcTableOffset32[0]");
    TEST_EQ(ost2pst::util::kCrc32Table[1], 0x77073096u, "CrcTableOffset32[1]");
    TEST_EQ(ost2pst::util::kCrc32Table[2], 0xEE0E612Cu, "CrcTableOffset32[2]");
    TEST_EQ(ost2pst::util::kCrc32Table[3], 0x990951BAu, "CrcTableOffset32[3]");
    TEST_EQ(ost2pst::util::kCrc32Table[4], 0x076DC419u, "CrcTableOffset32[4]");
    TEST_EQ(ost2pst::util::kCrc32Table[7], 0x9E6495A3u, "CrcTableOffset32[7]");
    TEST_EQ(ost2pst::util::kCrc32Table[8], 0x0EDB8832u, "CrcTableOffset32[8]");
    TEST_EQ(ost2pst::util::kCrc32Table[255], 0x2D02EF8Du, "CrcTableOffset32[255]");
}

void check_known_vectors() {
    const std::string digits = "123456789";
    const ByteView view = text_view(digits);

    // The RFC-known CRC-32 vector is the seed-all-ones reading with a final complement.
    TEST_EQ(ost2pst::util::crc32_variant(view, CrcSeed::kAllOnes, true), 0xCBF43926u,
            "CRC-32(\"123456789\")");
    // [MS-PST] 5.3 ComputeCRC returns without complementing, so the project default is the seed-0
    // reading; both are pinned so a change in either is visible.
    TEST_EQ(ost2pst::util::crc32(view), 0x2DFD2D88u, "crc32(\"123456789\") seed0-plain");
    TEST_EQ(ost2pst::util::crc32_variant(view, CrcSeed::kZero, true), 0xD202D277u,
            "crc32(\"123456789\") seed0-complement");
    TEST_EQ(ost2pst::util::crc32_variant(view, CrcSeed::kAllOnes, false), 0x340BC6D9u,
            "crc32(\"123456789\") seed-ones-plain");

    TEST_EQ(ost2pst::util::crc32(ByteView()), 0u, "crc32(empty)");
    TEST_EQ(ost2pst::util::crc32_variant(ByteView(), CrcSeed::kAllOnes, true), 0u,
            "zlib-style crc32(empty)");
}

void check_against_reference() {
    std::vector<uint8_t> bytes;
    uint32_t state = 0x12345678u;
    for (size_t i = 0; i < 4096; ++i) {
        state = state * 1103515245u + 12345u;
        bytes.push_back(static_cast<uint8_t>((state >> 16) & 0xFFu));
    }
    const ByteView view = bytes_view(bytes);
    TEST_EQ(ost2pst::util::crc32(view), reference_crc(0u, bytes.data(), bytes.size()),
            "seed0-plain against reference");
    TEST_EQ(ost2pst::util::crc32_variant(view, CrcSeed::kAllOnes, false),
            reference_crc(0xFFFFFFFFu, bytes.data(), bytes.size()), "seed-ones-plain against reference");
    TEST_EQ(ost2pst::util::crc32_variant(view, CrcSeed::kAllOnes, true),
            ~reference_crc(0xFFFFFFFFu, bytes.data(), bytes.size()),
            "seed-ones-complement against reference");

    // Chunked updates must equal one pass: the walkers CRC a page in pieces and rely on this.
    const size_t half = bytes.size() / 2;
    uint32_t running = ost2pst::util::crc32_update(0u, ByteView(bytes.data(), half));
    running = ost2pst::util::crc32_update(running, ByteView(bytes.data() + half, bytes.size() - half));
    TEST_EQ(running, ost2pst::util::crc32(view), "chunked crc32_update composition");

    // Byte-at-a-time is the same function, which is what the spec's loop does.
    uint32_t one_byte_at_a_time = 0u;
    for (size_t i = 0; i < bytes.size(); ++i) {
        one_byte_at_a_time =
            ost2pst::util::crc32_update(one_byte_at_a_time, ByteView(bytes.data() + i, 1));
    }
    TEST_EQ(one_byte_at_a_time, ost2pst::util::crc32(view), "per-byte crc32_update composition");
}

// The spec's own 3.2 sample header carries both header CRCs, and the seed-0 reading is the one that
// reproduces them. This is the first hard evidence for the CRC variant decision.
void check_spec_header_crcs() {
    const std::vector<uint8_t> bytes =
        ost2pst::test::read_bytes(ost2pst::test::fixture_path("spec-example-header.bin"));
    TEST_EQ(bytes.size(), ost2pst::ndb::kHeaderSize, "spec-example-header.bin size");
    if (bytes.size() != ost2pst::ndb::kHeaderSize) {
        return;
    }

    const auto report = verify_header_crcs(bytes_view(bytes));
    TEST_OK(report, "verify_header_crcs(spec sample)");
    if (!report.ok()) {
        return;
    }
    TEST_CHECK(report.value().partial_ok);
    TEST_CHECK(report.value().full_ok);
    TEST_EQ(report.value().stored_partial, 0x379AA90Eu, "HEADER.dwCRCPartial stored");
    TEST_EQ(report.value().computed_partial, 0x379AA90Eu, "HEADER.dwCRCPartial computed seed0-plain");
    TEST_EQ(report.value().stored_full, 0x1FD283D6u, "HEADER.dwCRCFull stored");
    TEST_EQ(report.value().computed_full, 0x1FD283D6u, "HEADER.dwCRCFull computed seed0-plain");

    const auto truncated = verify_header_crcs(ByteView(bytes.data(), ost2pst::ndb::kHeaderSize - 1));
    TEST_ERROR(truncated, ost2pst::util::ErrorKind::kTruncated, "HEADER",
               "verify_header_crcs on a short view");
}

// The probe scores every trailer against all four readings. A score is only meaningful if the
// variants are distinguishable and only one counter moves per stored value.
void check_variant_tally() {
    const std::vector<uint8_t> bytes =
        ost2pst::test::read_bytes(ost2pst::test::fixture_path("spec-example-header.bin"));
    if (bytes.size() != ost2pst::ndb::kHeaderSize) {
        return;
    }
    const ByteView data = ByteView(bytes.data() + ost2pst::ndb::kCrcPartialStart,
                                   ost2pst::ndb::kCrcPartialLength);

    const uint32_t seed0 = ost2pst::util::crc32_variant(data, CrcSeed::kZero, false);
    const uint32_t seed0_complement = ~seed0;
    const uint32_t seed_ones = ost2pst::util::crc32_variant(data, CrcSeed::kAllOnes, false);
    const uint32_t seed_ones_complement = ~seed_ones;
    TEST_CHECK(seed0 != seed0_complement);
    TEST_CHECK(seed0 != seed_ones);
    TEST_CHECK(seed0 != seed_ones_complement);
    TEST_CHECK(seed0_complement != seed_ones);
    TEST_CHECK(seed0_complement != seed_ones_complement);
    TEST_CHECK(seed_ones != seed_ones_complement);

    CrcVariantTally tally;
    ost2pst::ndb::tally_crc(tally, seed0, data);
    TEST_EQ(tally.total, 1u, "tally total after seed0-plain");
    TEST_EQ(tally.match_seed0_plain, 1u, "tally match seed0-plain");
    TEST_EQ(tally.match_seed0_complement, 0u, "tally match seed0-complement");
    TEST_EQ(tally.match_seed_ones_plain, 0u, "tally match seed-ones-plain");
    TEST_EQ(tally.match_seed_ones_complement, 0u, "tally match seed-ones-complement");

    ost2pst::ndb::tally_crc(tally, seed0_complement, data);
    ost2pst::ndb::tally_crc(tally, seed_ones, data);
    ost2pst::ndb::tally_crc(tally, seed_ones_complement, data);
    TEST_EQ(tally.total, 4u, "tally total after all four variants");
    TEST_EQ(tally.match_seed0_plain, 1u, "tally match seed0-plain after four");
    TEST_EQ(tally.match_seed0_complement, 1u, "tally match seed0-complement after four");
    TEST_EQ(tally.match_seed_ones_plain, 1u, "tally match seed-ones-plain after four");
    TEST_EQ(tally.match_seed_ones_complement, 1u, "tally match seed-ones-complement after four");

    ost2pst::ndb::tally_crc(tally, 0xDEADBEEFu, data);
    TEST_EQ(tally.total, 5u, "tally total after a non-matching value");
    TEST_EQ(tally.match_seed0_plain, 1u, "tally unchanged by a non-matching value");
    TEST_EQ(tally.match_seed0_complement, 1u, "tally unchanged by a non-matching value");
    TEST_EQ(tally.match_seed_ones_plain, 1u, "tally unchanged by a non-matching value");
    TEST_EQ(tally.match_seed_ones_complement, 1u, "tally unchanged by a non-matching value");
}

} // namespace

int main() {
    check_spec_table();
    check_known_vectors();
    check_against_reference();
    check_spec_header_crcs();
    check_variant_tally();
    return ost2pst::test::finish("crc_test");
}
