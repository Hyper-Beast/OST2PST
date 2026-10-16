// A BTH is only reachable through heap ids ([MS-PST] 2.3.2.1 / 2.3.2.2), so the walk is tested against a
// fake heap source rather than a file. That makes every shape the walk has to survive inline: one level,
// two levels, empty, a bad hidNextLevel, a trailing partial record, an unanswerable heap id.
#include <cstdint>
#include <map>
#include <utility>
#include <vector>

#include "ost2pst/ltp/bth.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"
#include "test_support.h"

namespace {

using ost2pst::ltp::BthHeader;
using ost2pst::ltp::BthLeafRecord;
using ost2pst::ltp::BthStats;
using ost2pst::ltp::decode_bth_header;
using ost2pst::ltp::HeapSource;
using ost2pst::ltp::walk_bth;
using ost2pst::ndb::FailureLog;
using ost2pst::ndb::FileProfile;
using ost2pst::util::ByteView;
using ost2pst::util::ErrorKind;
using ost2pst::util::make_error;
using ost2pst::util::Result;
using ost2pst::util::Status;

// Each heap item gets its own synthetic base so the test can prove every reported offset is absolute.
constexpr uint64_t kHeapBase = 0x10000;

// The synthetic heap is a 512-profile one; [MS-PST] 2.3.1.1 gives the HID widths this walk needs.
constexpr FileProfile kProfile = FileProfile::kPst;

class FakeHeap : public HeapSource {
public:
    void add(uint32_t hid, const std::vector<uint8_t> &bytes) { items_[hid] = bytes; }

    Result<ByteView> heap(uint32_t hid) override {
        ++calls;
        const auto found = items_.find(hid);
        if (found == items_.end()) {
            return make_error(ErrorKind::kBadField, "HID", kHeapBase + hid, hid, "no such heap item");
        }
        return ByteView(found->second.data(), found->second.size(), kHeapBase + hid);
    }

    int calls = 0;

private:
    std::map<uint32_t, std::vector<uint8_t>> items_;
};

void put16(std::vector<uint8_t> &bytes, uint16_t value) {
    bytes.push_back(static_cast<uint8_t>(value & 0xFF));
    bytes.push_back(static_cast<uint8_t>(value >> 8));
}

void put32(std::vector<uint8_t> &bytes, uint32_t value) {
    for (int shift = 0; shift < 4; ++shift) {
        bytes.push_back(static_cast<uint8_t>((value >> (8 * shift)) & 0xFF));
    }
}

// cbKey 2 / cbEnt 6 is the Property Context shape ([MS-PST] 2.3.3.3), so the fixtures use it: a 2-byte
// key then 6 data bytes, byte-aligned ([MS-PST] 2.3.2.3).
std::vector<uint8_t> leaf_array(const std::vector<uint16_t> &keys) {
    std::vector<uint8_t> bytes;
    for (size_t index = 0; index < keys.size(); ++index) {
        put16(bytes, keys[index]);
        put32(bytes, static_cast<uint32_t>(0x20 + index));
        bytes.push_back(static_cast<uint8_t>(index));
        bytes.push_back(static_cast<uint8_t>(0xF0 + index));
    }
    return bytes;
}

// [MS-PST] 2.3.2.2: an index record is the key then the 4-byte HID of the array one level down.
std::vector<uint8_t> index_array(const std::vector<std::pair<uint32_t, uint32_t>> &entries) {
    std::vector<uint8_t> bytes;
    for (const auto &entry : entries) {
        put16(bytes, static_cast<uint16_t>(entry.first));
        put32(bytes, entry.second);
    }
    return bytes;
}

BthHeader header(uint8_t idx_levels, uint32_t hid_root) {
    BthHeader value;
    value.b_type = 0xB5;
    value.cb_key = 2;
    value.cb_ent = 6;
    value.b_idx_levels = idx_levels;
    value.hid_root = hid_root;
    return value;
}

std::vector<uint8_t> header_bytes(uint8_t b_type, uint8_t cb_key, uint8_t cb_ent, uint8_t idx_levels,
                                  uint32_t hid_root) {
    std::vector<uint8_t> bytes;
    bytes.push_back(b_type);
    bytes.push_back(cb_key);
    bytes.push_back(cb_ent);
    bytes.push_back(idx_levels);
    put32(bytes, hid_root);
    return bytes;
}

// Collected leaf records, so a test can assert on key order rather than on a callback side effect.
struct Collected {
    std::vector<uint16_t> keys;
    std::vector<uint64_t> offsets;
    std::vector<uint64_t> positions;
    std::vector<uint32_t> hids;
};

void check_decode_accepts_and_rejects() {
    // [MS-PST] 2.3.2.1: bType cbKey cbEnt bIdxLevels hidRoot.
    const std::vector<uint8_t> good = header_bytes(0xB5, 2, 6, 0, 0x20);
    Result<BthHeader> decoded = decode_bth_header(ByteView(good.data(), good.size(), kHeapBase), kProfile);
    TEST_OK(decoded, "a well-formed BTHHEADER");
    if (decoded.ok()) {
        TEST_EQ(decoded.value().b_type, 0xB5, "bType");
        TEST_EQ(decoded.value().cb_key, 2, "cbKey");
        TEST_EQ(decoded.value().cb_ent, 6, "cbEnt");
        TEST_EQ(decoded.value().b_idx_levels, 0, "bIdxLevels");
        TEST_EQ(decoded.value().hid_root, 0x20, "hidRoot");
    }

    // Every cbKey the spec allows is accepted, and only those.
    const uint8_t allowed_keys[] = {2, 4, 8, 16};
    for (uint8_t cb_key : allowed_keys) {
        const std::vector<uint8_t> bytes = header_bytes(0xB5, cb_key, 6, 0, 0x20);
        TEST_OK(decode_bth_header(ByteView(bytes.data(), bytes.size(), kHeapBase), kProfile), "cbKey is allowed");
    }

    struct Case {
        uint8_t b_type;
        uint8_t cb_key;
        uint8_t cb_ent;
        uint8_t idx_levels;
        uint32_t hid_root;
        const char *field;
        const char *why;
    };
    const Case cases[] = {
        {0x00, 2, 6, 0, 0x20, "BTHHEADER.bType", "bType is not bTypeBTH"},
        {0xB5, 3, 6, 0, 0x20, "BTHHEADER.cbKey", "cbKey 3 is not 2, 4, 8 or 16"},
        {0xB5, 1, 6, 0, 0x20, "BTHHEADER.cbKey", "cbKey 1 is not 2, 4, 8 or 16"},
        {0xB5, 2, 0, 0, 0x20, "BTHHEADER.cbEnt", "cbEnt 0 means a record with no data"},
        {0xB5, 2, 33, 0, 0x20, "BTHHEADER.cbEnt", "cbEnt above 32"},
        {0xB5, 2, 6, 9, 0x20, "BTHHEADER.bIdxLevels", "9 index levels is treated as corrupt"},
        {0xB5, 2, 6, 0, 0x21, "BTHHEADER.hidRoot", "hidRoot with hidType 1 is a node id, not a heap id"},
        {0xB5, 2, 6, 0, 0x1F, "BTHHEADER.hidRoot", "hidRoot 0x1F has hidIndex 0"},
    };
    for (const Case &case_value : cases) {
        const std::vector<uint8_t> bytes =
            header_bytes(case_value.b_type, case_value.cb_key, case_value.cb_ent,
                         case_value.idx_levels, case_value.hid_root);
        TEST_ERROR(decode_bth_header(ByteView(bytes.data(), bytes.size(), kHeapBase), kProfile),
                   ErrorKind::kBadField, case_value.field, case_value.why);
    }

    // [MS-PST] 2.3.2.1: hidRoot 0 is a legal empty BTH.
    {
        const std::vector<uint8_t> bytes = header_bytes(0xB5, 2, 6, 0, 0);
        Result<BthHeader> empty = decode_bth_header(ByteView(bytes.data(), bytes.size(), kHeapBase), kProfile);
        TEST_OK(empty, "an empty BTH decodes");
        if (empty.ok()) {
            TEST_EQ(empty.value().hid_root, 0, "hidRoot 0");
        }
    }

    const std::vector<uint8_t> short_bytes = header_bytes(0xB5, 2, 6, 0, 0x20);
    TEST_ERROR(decode_bth_header(ByteView(short_bytes.data(), 7, kHeapBase), kProfile), ErrorKind::kTruncated,
               "BTHHEADER", "a 7-byte view cannot hold a BTHHEADER");
}

void check_single_level_bth() {
    // bIdxLevels 0 means hidRoot already names the leaf array ([MS-PST] 2.3.2.1).
    FakeHeap heap;
    heap.add(0x20, leaf_array({3, 1, 2}));
    Collected collected;
    BthStats stats;
    FailureLog failures;
    const BthHeader tree = header(0, 0x20);
    Status status = walk_bth(tree, kProfile, heap, [&](const BthLeafRecord &record) {
        collected.keys.push_back(static_cast<uint16_t>(record.key.u16(0).value()));
        collected.offsets.push_back(record.offset);
        collected.positions.push_back(record.position);
        collected.hids.push_back(record.hid);
        return true;
    }, stats, failures);

    TEST_OK(status, "walk of a one-level BTH");
    TEST_EQ(collected.keys.size(), 3, "leaf record count");
    // Records come out in the order they sit in the allocation, which is key order ([MS-PST] 2.3.2.3).
    TEST_EQ(collected.keys[0], 3, "first leaf key");
    TEST_EQ(collected.keys[1], 1, "second leaf key");
    TEST_EQ(collected.keys[2], 2, "third leaf key");
    TEST_EQ(collected.positions[0], 0, "position 0");
    TEST_EQ(collected.positions[2], 2, "position 2");
    TEST_EQ(collected.hids[0], 0x20, "the record reports the heap id it came from");
    TEST_EQ(collected.offsets[0], kHeapBase + 0x20, "first record absolute offset");
    TEST_EQ(collected.offsets[2], kHeapBase + 0x20 + 16, "third record absolute offset");
    TEST_EQ(stats.heap_items_read, 1, "one heap item read");
    TEST_EQ(stats.leaf_records, 3, "leaf records");
    TEST_EQ(stats.index_records, 0, "no index records");
    TEST_EQ(stats.max_depth, 0, "a one-level BTH has depth 0");
    TEST_EQ(stats.skipped_records, 0, "nothing skipped");
    TEST_EQ(stats.trailing_bytes, 0, "no trailing bytes");
    TEST_EQ(stats.stopped_early, 0, "the walk finished");
    TEST_EQ(failures.total(), 0, "no findings");

    // The data half of the record is the cbEnt bytes right after the key.
    Result<ByteView> data = ByteView(leaf_array({7}).data(), 8, kHeapBase).sub(2, 6);
    TEST_OK(data, "record data window");
    if (data.ok()) {
        TEST_EQ(data.value().base(), kHeapBase + 2, "record data absolute offset");
        TEST_EQ(data.value().size(), 6, "record data size");
    }
}

void check_two_level_bth() {
    // bIdxLevels 1: hidRoot names an index array, and each index record names a leaf array
    // ([MS-PST] 2.3.2.1 / 2.3.2.2).
    FakeHeap heap;
    heap.add(0x20, index_array({{0x0001, 0x40}, {0x0005, 0x60}}));
    heap.add(0x40, leaf_array({1, 2, 3}));
    heap.add(0x60, leaf_array({5, 6}));

    Collected collected;
    BthStats stats;
    FailureLog failures;
    const BthHeader tree = header(1, 0x20);
    Status status = walk_bth(tree, kProfile, heap, [&](const BthLeafRecord &record) {
        collected.keys.push_back(static_cast<uint16_t>(record.key.u16(0).value()));
        collected.offsets.push_back(record.offset);
        collected.hids.push_back(record.hid);
        return true;
    }, stats, failures);

    TEST_OK(status, "walk of a two-level BTH");
    TEST_EQ(collected.keys.size(), 5, "leaf record count");
    // Index arrays are in key order, so the leaves must come out sorted across levels.
    TEST_EQ(collected.keys[0], 1, "first leaf key");
    TEST_EQ(collected.keys[1], 2, "second leaf key");
    TEST_EQ(collected.keys[2], 3, "third leaf key");
    TEST_EQ(collected.keys[3], 5, "fourth leaf key");
    TEST_EQ(collected.keys[4], 6, "fifth leaf key");
    TEST_EQ(collected.hids[0], 0x40, "the first three leaves come from the first index record");
    TEST_EQ(collected.hids[3], 0x60, "the last two come from the second");
    TEST_EQ(collected.offsets[0], kHeapBase + 0x40, "absolute offset in the first leaf array");
    TEST_EQ(collected.offsets[4], kHeapBase + 0x60 + 8, "absolute offset in the second leaf array");
    TEST_EQ(stats.heap_items_read, 3, "one index array and two leaf arrays");
    TEST_EQ(stats.index_records, 2, "index records");
    TEST_EQ(stats.leaf_records, 5, "leaf records");
    TEST_EQ(stats.max_depth, 1, "depth 1 for one intermediate level");
    TEST_EQ(failures.total(), 0, "no findings");
}

void check_empty_bth() {
    FakeHeap heap;
    BthStats stats;
    FailureLog failures;
    const BthHeader tree = header(0, 0);
    Status status = walk_bth(tree, kProfile, heap, [](const BthLeafRecord &) { return true; }, stats, failures);
    TEST_OK(status, "an empty BTH walks");
    TEST_EQ(heap.calls, 0, "an empty BTH reads no heap item");
    TEST_EQ(stats.leaf_records, 0, "no leaf records");
    TEST_EQ(failures.total(), 0, "an empty BTH is not a finding");
}

void check_bad_index_record() {
    // One index record names a node id instead of a heap id: the level under it is unreachable, but the
    // rest of the tree is still walked and the bad record is reported with an absolute offset.
    FakeHeap heap;
    heap.add(0x20, index_array({{0x0001, 0x21}, {0x0005, 0x60}}));
    heap.add(0x60, leaf_array({5, 6}));

    Collected collected;
    BthStats stats;
    FailureLog failures;
    const BthHeader tree = header(1, 0x20);
    Status status = walk_bth(tree, kProfile, heap, [&](const BthLeafRecord &record) {
        collected.keys.push_back(static_cast<uint16_t>(record.key.u16(0).value()));
        return true;
    }, stats, failures);

    TEST_OK(status, "a bad index record does not end the walk");
    TEST_EQ(collected.keys.size(), 2, "the reachable leaves are still reported");
    TEST_EQ(stats.skipped_records, 1, "the bad index record is counted");
    TEST_EQ(stats.index_records, 2, "both index records were read; skipped_records is what flags the bad one");
    TEST_EQ(failures.total(), 1, "one finding");
    if (failures.kept() > 0) {
        TEST_EQ(failures.failures()[0].offset, kHeapBase + 0x20 + 2, "hidNextLevel absolute offset");
        TEST_STR(failures.failures()[0].field, "BTHENTRY.hidNextLevel", "finding field");
    }
}

void check_trailing_bytes_and_callback_stop() {
    {
        // A partial record at the end of an allocation is not a record ([MS-PST] 2.3.2.3).
        std::vector<uint8_t> bytes = leaf_array({1, 2});
        bytes.push_back(0xAA);
        bytes.push_back(0xBB);
        bytes.push_back(0xCC);
        FakeHeap heap;
        heap.add(0x20, bytes);
        BthStats stats;
        FailureLog failures;
        size_t seen = 0;
        Status status = walk_bth(header(0, 0x20), kProfile, heap, [&](const BthLeafRecord &) {
            ++seen;
            return true;
        }, stats, failures);
        TEST_OK(status, "trailing bytes do not fail the walk");
        TEST_EQ(seen, 2, "only whole records are reported");
        TEST_EQ(stats.trailing_bytes, 3, "the leftover bytes are reported instead of guessed at");
        TEST_EQ(failures.total(), 0, "trailing bytes alone are not a finding");
    }
    {
        // The callback says when to stop, and the record it refused is the only one not delivered.
        FakeHeap heap;
        heap.add(0x20, leaf_array({1, 2, 3}));
        BthStats stats;
        FailureLog failures;
        size_t seen = 0;
        Status status = walk_bth(header(0, 0x20), kProfile, heap, [&](const BthLeafRecord &) {
            ++seen;
            return seen < 2;
        }, stats, failures);
        TEST_OK(status, "a callback that returns false stops the walk cleanly");
        TEST_EQ(seen, 2, "the walk stops after the record the callback refused");
        TEST_EQ(stats.leaf_records, 2, "no records are counted after the stop");
        TEST_EQ(heap.calls, 1, "one heap item read");
    }
}

void check_unanswerable_heap_id_and_cap() {
    {
        // A heap id the source cannot answer at all is a failure, not a skipped record.
        FakeHeap heap;
        BthStats stats;
        FailureLog failures;
        Status status = walk_bth(header(0, 0x20), kProfile, heap, [](const BthLeafRecord &) { return true; },
                                 stats, failures);
        TEST_CHECK(!status.ok());
        if (!status.ok()) {
            TEST_EQ(status.error().kind, static_cast<uint64_t>(ErrorKind::kBadField), "error kind");
            TEST_STR(status.error().field, "HID", "the missing heap id is named");
        }
    }
    {
        // A corrupt BTH must not spin: the walk stops at its heap-item cap and says so.
        FakeHeap heap;
        std::vector<std::pair<uint32_t, uint32_t>> entries;
        for (uint32_t index = 0; index < 100000; ++index) {
            entries.push_back({index, 0x40});
        }
        heap.add(0x20, index_array(entries));
        heap.add(0x40, leaf_array({7}));

        BthStats stats;
        FailureLog failures;
        Status status = walk_bth(header(1, 0x20), kProfile, heap, [](const BthLeafRecord &) { return true; },
                                 stats, failures);
        TEST_OK(status, "the cap is a stop, not a failure");
        TEST_EQ(stats.stopped_early, 1, "the walk reports that it stopped early");
        TEST_EQ(stats.heap_items_read, 100000, "the heap-item cap");
        TEST_EQ(failures.total(), 1, "the stop is a finding");
        if (failures.kept() > 0) {
            TEST_STR(failures.failures()[0].field, "BTHHEADER.hidRoot", "the finding names the tree");
        }
    }
}

} // namespace

int main() {
    check_decode_accepts_and_rejects();
    check_single_level_bth();
    check_two_level_bth();
    check_empty_bth();
    check_bad_index_record();
    check_trailing_bytes_and_callback_stop();
    check_unanswerable_heap_id_and_cap();
    return ost2pst::test::finish("ltp_bth_test");
}
