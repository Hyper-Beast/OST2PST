// BbtIndex is the only structure that turns a BID into bytes ([MS-PST] 2.2.2.7.7.3), so every later
// layer depends on it. Tested without a file: sortedness, hit and miss lookups, the BID flag bits,
// duplicate detection, and the empty index.
#include <cstddef>
#include <cstdint>
#include <unordered_map>

#include "ost2pst/ndb/bbt_index.h"
#include "ost2pst/ndb/btree.h"
#include "ost2pst/ndb/layout.h"
#include "test_support.h"

namespace {

using ost2pst::ndb::BbtEntry;
using ost2pst::ndb::BbtIndex;

BbtEntry make_entry(uint64_t bid, uint64_t ib, uint16_t cb, uint16_t c_ref) {
    BbtEntry entry;
    entry.bid = bid;
    entry.ib = ib;
    entry.cb = cb;
    entry.c_ref = c_ref;
    return entry;
}

void check_sorted_lookup() {
    std::unordered_map<uint64_t, BbtEntry> walked;
    walked[0x30] = make_entry(0x30, 0x9000, 10, 1);
    walked[0x10] = make_entry(0x10, 0x4000, 100, 2);
    walked[0x20] = make_entry(0x20, 0x8000, 20, 3);

    const BbtIndex index(walked);
    TEST_EQ(index.entries(), 3, "index entries");
    TEST_EQ(index.duplicates(), 0, "no duplicate BIDs");
    TEST_EQ(index.min_bid(), 0x10, "lowest BID");
    TEST_EQ(index.max_bid(), 0x30, "highest BID");
    TEST_CHECK(index.bytes() >= 3 * sizeof(BbtEntry));

    const std::vector<BbtEntry> &sorted = index.entries_sorted();
    TEST_EQ(sorted.size(), 3, "entries_sorted exposes the whole index");
    for (size_t i = 1; i < sorted.size(); ++i) {
        TEST_CHECK(sorted[i - 1].bid < sorted[i].bid);
    }

    const BbtEntry *hit = index.lookup(0x20);
    TEST_CHECK(hit != nullptr);
    if (hit != nullptr) {
        TEST_EQ(hit->ib, 0x8000, "lookup resolves ib");
        TEST_EQ(hit->cb, 20, "lookup resolves cb");
        TEST_EQ(hit->c_ref, 3, "lookup resolves cRef");
    }
    TEST_CHECK(index.lookup(0x10) != nullptr);
    TEST_CHECK(index.lookup(0x30) != nullptr);
    TEST_CHECK(index.lookup(0x18) == nullptr);
    TEST_CHECK(index.lookup(0x0F) == nullptr);
    // [MS-PST] 2.2.2.2 bit A: 0x31 is 0x30 with the reserved bit set, so it resolves to the same block.
    TEST_CHECK(index.lookup(0x31) != nullptr);
    TEST_CHECK(index.lookup(0) == nullptr);
}

// [MS-PST] 2.2.2.2: a block BID carries two flag bits. Only the reserved one is cleared before the
// lookup -- "Readers MUST ignore this bit and treat it as zero before looking up the BID from the BBT" --
// and the internal one stays part of the value the BBT stores, so two BIDs that share a bidIndex but
// disagree about the internal bit name different blocks.
void check_bid_flag_bits() {
    std::unordered_map<uint64_t, BbtEntry> walked;
    walked[0x100] = make_entry(0x100, 0x4000, 64, 1); // external: bit B clear
    walked[0x102] = make_entry(0x102, 0x4100, 64, 1); // internal: bit B set, same bidIndex as 0x100
    const BbtIndex index(walked);
    TEST_EQ(ost2pst::ndb::bid_index(0x100), ost2pst::ndb::bid_index(0x102), "one bidIndex, two BIDs");
    TEST_CHECK(!ost2pst::ndb::bid_is_internal(0x100));
    TEST_CHECK(ost2pst::ndb::bid_is_internal(0x102));

    TEST_CHECK(index.lookup(0x100) != nullptr);
    const BbtEntry *external = index.lookup(0x101); // [MS-PST] 2.2.2.2 bit A: a reference may set the reserved bit
    TEST_CHECK(external != nullptr);
    if (external != nullptr) {
        TEST_EQ(external->ib, 0x4000, "clearing bit A still finds the external block");
    }
    const BbtEntry *internal = index.lookup(0x103); // bit A set and bit B set
    TEST_CHECK(internal != nullptr);
    if (internal != nullptr) {
        TEST_EQ(internal->ib, 0x4100, "bit B is kept, so it finds the internal block, not its external twin");
    }
    TEST_CHECK(index.lookup(0xFF) == nullptr);
    TEST_EQ(index.duplicates(), 0, "bit B keeps them two blocks, not one duplicate");

    // Two entries that differ only in the reserved bit are the same block indexed twice.
    std::unordered_map<uint64_t, BbtEntry> same_block;
    same_block[0x100] = make_entry(0x100, 0x4000, 64, 1);
    same_block[0x101] = make_entry(0x101, 0x4100, 64, 1);
    const BbtIndex twice(same_block);
    TEST_EQ(twice.duplicates(), 1, "one block reached through two BIDs that differ only in bit A");
}

// Two entries that share a BID mean one block is indexed twice, which is exactly what the M1 report
// calls out before anything trusts a BID.
void check_duplicate_bids() {
    std::unordered_map<uint64_t, BbtEntry> walked;
    walked[0x10] = make_entry(0x10, 0x4000, 100, 1);
    walked[0x11] = make_entry(0x10, 0x4200, 100, 1);
    walked[0x12] = make_entry(0x10, 0x4400, 100, 1);

    const BbtIndex index(walked);
    TEST_EQ(index.entries(), 3, "all three entries are kept");
    TEST_EQ(index.duplicates(), 2, "two neighbours share a BID");
    TEST_CHECK(index.lookup(0x10) != nullptr);
}

void check_empty_index() {
    const std::unordered_map<uint64_t, BbtEntry> walked;
    const BbtIndex index(walked);
    TEST_EQ(index.entries(), 0, "empty index");
    TEST_EQ(index.duplicates(), 0, "empty index has no duplicates");
    TEST_EQ(index.min_bid(), 0, "empty index has no lowest BID");
    TEST_EQ(index.max_bid(), 0, "empty index has no highest BID");
    TEST_CHECK(index.lookup(0x10) == nullptr);
    TEST_CHECK(index.entries_sorted().empty());
}

} // namespace

int main() {
    check_sorted_lookup();
    check_bid_flag_bits();
    check_duplicate_bids();
    check_empty_index();
    return ost2pst::test::finish("bbt_index_test");
}
