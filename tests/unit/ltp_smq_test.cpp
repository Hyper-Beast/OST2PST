// The Search Management Queue is a queue node whose items are SUDs ([MS-PST] 2.4.8.4.1, 2.4.8.3): the
// node's data block is a flat array of 20-byte items and NBTENTRY.nidParent is re-purposed as the byte
// offset of the head, so the items before it have already been dequeued. This file checks the SUD record,
// the queue walk, and the census the SMQ reader reports.
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/smq.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"
#include "test_support.h"

namespace {

using ost2pst::ltp::decode_sud;
using ost2pst::ltp::kQueueMaxItems;
using ost2pst::ltp::kSudSize;
using ost2pst::ltp::read_smq;
using ost2pst::ltp::SmqReport;
using ost2pst::ltp::sud_data_fields;
using ost2pst::ltp::sud_flags_text;
using ost2pst::ltp::sud_type_name;
using ost2pst::ltp::Sud;
using ost2pst::ltp::walk_queue;
using ost2pst::ndb::FailureLog;
using ost2pst::test::finish;
using ost2pst::util::ByteView;
using ost2pst::util::ErrorKind;
using ost2pst::util::Result;
using ost2pst::util::Status;

void put16(std::vector<uint8_t> &out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
}

void put32(std::vector<uint8_t> &out, uint32_t value) {
    for (uint64_t index = 0; index < 4; ++index) {
        out.push_back(static_cast<uint8_t>((value >> (8 * index)) & 0xFF));
    }
}

// [MS-PST] 2.4.8.1.1: wFlags, wSUDType, then 16 bytes of SUDData.
std::vector<uint8_t> sud_bytes(uint16_t flags, uint16_t type, std::array<uint32_t, 4> data) {
    std::vector<uint8_t> out;
    put16(out, flags);
    put16(out, type);
    for (const uint32_t word : data) {
        put32(out, word);
    }
    return out;
}

std::vector<uint8_t> queue_of(const std::vector<std::vector<uint8_t>> &items) {
    std::vector<uint8_t> out;
    for (const std::vector<uint8_t> &item : items) {
        out.insert(out.end(), item.begin(), item.end());
    }
    return out;
}

void test_sud() {
    const std::vector<uint8_t> bytes = sud_bytes(0x8008, 0x0005, {0x00000122, 0x000002A2, 0, 0});
    Result<Sud> sud = decode_sud(ByteView(bytes.data(), bytes.size(), 0x9000));
    TEST_OK(sud, "a SUD");
    TEST_EQ(sud.value().w_flags, 0x8008, "wFlags");
    TEST_EQ(sud.value().w_type, 0x0005, "wSUDType");
    TEST_EQ(sud.value().data[0], 0x122, "SUDData[0]");
    TEST_EQ(sud.value().data[3], 0, "SUDData[3]");
    TEST_EQ(sud.value().offset, 0x9000, "the SUD offset");
    TEST_EQ(bytes.size(), kSudSize, "a SUD is 20 bytes");

    TEST_ERROR(decode_sud(ByteView(bytes.data(), kSudSize - 1, 0x100)), ErrorKind::kTruncated, "SUD",
               "a short SUD");

    TEST_STR(sud_type_name(0x0001), "SUDT_MSG_ADD", "SUDT_MSG_ADD");
    TEST_STR(sud_type_name(0x0005), "SUDT_FLD_ADD", "SUDT_FLD_ADD");
    TEST_STR(sud_type_name(0x000F), "SUDT_MSG_IDX", "SUDT_MSG_IDX");
    TEST_STR(sud_type_name(0x0000), "SUDT_NULL", "SUDT_NULL");
    TEST_CHECK(sud_type_name(0x0010) == nullptr);
}

void test_flags() {
    TEST_STR(sud_flags_text(0), "none", "no flags");
    TEST_STR(sud_flags_text(0x8008), "SUDF_NAME_CHANGED|SUDF_DOMAIN_CHECKED", "two flags");
    TEST_STR(sud_flags_text(0x0001), "SUDF_PRIORITY_LOW", "SUDF_PRIORITY_LOW");
    TEST_STR(sud_flags_text(0x0400), "SUDF_SRCH_DONE", "SUDF_SRCH_DONE");
    // [MS-PST] 2.4.8.1.1: a bit the spec does not define is not a name the reader may invent.
    TEST_STR(sud_flags_text(0x4000), "unknown", "a bit the spec does not name");
    TEST_STR(sud_flags_text(0x4008), "SUDF_NAME_CHANGED|unknown", "a named bit and an unnamed one");
}

void test_sud_data() {
    struct Case {
        uint16_t type;
        size_t fields;
        const char *first;
    };
    // [MS-PST] 2.4.8.2: every SUDData structure, and the DWORDs each one names.
    static constexpr Case kCases[] = {
        {0x0001, 2, "nidParent"}, // 2.4.8.2.1 SUD_MSG_ADD
        {0x0002, 2, "nidParent"}, // 2.4.8.2.1 SUD_MSG_MOD
        {0x0003, 2, "nidParent"}, // 2.4.8.2.1 SUD_MSG_DEL
        {0x0004, 3, "nidParentNew"}, // 2.4.8.2.2 SUD_MSG_MOV
        {0x0005, 4, "nidParent"}, // 2.4.8.2.3 SUD_FLD_ADD
        {0x0006, 2, "nidFld"}, // 2.4.8.2.4 SUD_FLD_MOD
        {0x0007, 2, "nidFld"}, // 2.4.8.2.4 SUD_FLD_DEL
        {0x0008, 4, "nidParent"}, // 2.4.8.2.3 SUD_FLD_MOV
        {0x0009, 1, "nidSrch"}, // 2.4.8.2.5 SUD_SRCH_ADD
        {0x000A, 2, "nidSrch"}, // 2.4.8.2.6 SUD_SRCH_MOD
        {0x000B, 1, "nidSrch"}, // 2.4.8.2.5 SUD_SRCH_DEL
        {0x000C, 2, "nidParent"}, // 2.4.8.2.1 SUD_MSG_ROW_MOD
        {0x000D, 2, "nidParent"}, // 2.4.8.2.7 SUD_MSG_SPAM
        {0x000E, 2, "nidParent"}, // 2.4.8.2.8 SUD_IDX_MSG_DEL
        {0x000F, 1, "nidMsg"}, // 2.4.8.2.9 SUD_MSG_IDX
    };
    for (const Case &entry : kCases) {
        const std::vector<uint8_t> bytes =
            sud_bytes(0, entry.type, {0x00000122, 0x000002A2, 0x000003A2, 0x000004A2});
        Result<Sud> sud = decode_sud(ByteView(bytes.data(), bytes.size(), 0));
        TEST_OK(sud, "SUD for the type census");
        const std::vector<std::pair<std::string, uint32_t>> fields = sud_data_fields(sud.value());
        TEST_EQ(fields.size(), entry.fields, "SUDData field count");
        if (!fields.empty()) {
            TEST_STR(fields[0].first, entry.first, "first SUDData field");
            TEST_EQ(fields[0].second, 0x122, "first SUDData value");
        }
    }
    // An undefined type has no defined SUDData ([MS-PST] 2.4.8.1).
    const std::vector<uint8_t> unknown = sud_bytes(0, 0x00FF, {1, 2, 3, 4});
    Result<Sud> sud = decode_sud(ByteView(unknown.data(), unknown.size(), 0));
    TEST_OK(sud, "a SUD of an unknown type");
    TEST_EQ(sud_data_fields(sud.value()).size(), 0, "an unknown type names no fields");
}

void test_queue() {
    const std::vector<uint8_t> block = queue_of({
        sud_bytes(0, 0x0001, {1, 2, 0, 0}),
        sud_bytes(0, 0x0002, {3, 4, 0, 0}),
        sud_bytes(0, 0x0003, {5, 6, 0, 0}),
        sud_bytes(0, 0x0005, {7, 8, 0, 0}),
    });
    {
        // [MS-PST] 2.4.8.3: nidParent is the byte offset of the head, so the first item is already gone.
        FailureLog failures(5);
        ost2pst::ltp::QueueStats stats;
        uint64_t seen = 0;
        Status status = walk_queue(kSudSize, kSudSize, ByteView(block.data(), block.size(), 0x5000),
                                   [&](ByteView item, uint64_t position) {
                                       ++seen;
                                       TEST_EQ(item.size(), kSudSize, "queue item size");
                                       TEST_EQ(position, seen - 1, "queue item position");
                                       return true;
                                   }, stats, failures);
        TEST_OK(status, "walk a queue");
        TEST_EQ(stats.bytes, 80, "queue bytes");
        TEST_EQ(stats.items_total, 4, "queue items");
        TEST_EQ(stats.items_consumed, 1, "items before the head");
        TEST_EQ(stats.items_queued, 3, "items at or past the head");
        TEST_EQ(seen, 4, "every item is still reported");
        TEST_EQ(stats.head_offset, kSudSize, "the head offset the caller passed");
        TEST_EQ(failures.total(), 0, "a well-formed queue reports nothing");
    }
    {
        // [MS-PST] 2.4.8.3: cbData that is not a multiple of k MUST NOT be processed past the whole items.
        std::vector<uint8_t> ragged = block;
        ragged.push_back(0xAA);
        ragged.push_back(0xBB);
        ragged.push_back(0xCC);
        FailureLog failures(5);
        ost2pst::ltp::QueueStats stats;
        Status status = walk_queue(0, kSudSize, ByteView(ragged.data(), ragged.size(), 0x6000),
                                   [&](ByteView, uint64_t) { return true; }, stats, failures);
        TEST_OK(status, "a ragged queue is walked up to the whole items");
        TEST_EQ(stats.ragged ? 1u : 0u, 1u, "the ragged cbData is recorded");
        TEST_EQ(stats.items_total, 4, "only whole items counted");
        TEST_EQ(failures.total(), 1, "the ragged cbData is reported");
    }
    {
        FailureLog failures(5);
        ost2pst::ltp::QueueStats stats;
        Status status = walk_queue(100, kSudSize, ByteView(block.data(), block.size(), 0x7000),
                                   [&](ByteView, uint64_t) { return true; }, stats, failures);
        TEST_OK(status, "a queue whose head is past the end");
        TEST_EQ(stats.head_past_end ? 1u : 0u, 1u, "the head offset is recorded as impossible");
        TEST_EQ(stats.items_consumed, 4, "every item is behind that head");
        TEST_EQ(stats.items_queued, 0, "nothing is queued");
        TEST_EQ(failures.total(), 1, "the head offset is reported");
    }
    {
        // [MS-PST] 2.4.8.3: when the last item is dequeued nidParent and cbData both go to zero.
        FailureLog failures(5);
        ost2pst::ltp::QueueStats stats;
        Status status = walk_queue(block.size(), kSudSize, ByteView(block.data(), block.size(), 0),
                                   [&](ByteView, uint64_t) { return true; }, stats, failures);
        TEST_OK(status, "an emptied queue");
        TEST_EQ(stats.head_past_end ? 1u : 0u, 0u, "a head at the end of the block is normal");
        TEST_EQ(stats.items_queued, 0, "nothing left to dequeue");
    }
    {
        FailureLog failures(5);
        ost2pst::ltp::QueueStats stats;
        Status status = walk_queue(0, kSudSize, ByteView(block.data(), block.size(), 0),
                                   [&](ByteView, uint64_t) { return false; }, stats, failures);
        TEST_OK(status, "a callback that stops the walk");
        TEST_EQ(stats.stopped_early ? 1u : 0u, 1u, "the stop is recorded");
        TEST_EQ(stats.items_skipped, 3, "the items past the stop are counted");
    }
    {
        FailureLog failures(5);
        ost2pst::ltp::QueueStats stats;
        TEST_ERROR(walk_queue(0, 0, ByteView(block.data(), block.size(), 0),
                              [&](ByteView, uint64_t) { return true; }, stats, failures),
                   ErrorKind::kBadField, "queue.itemSize", "a queue with zero-byte items");
    }
    {
        // An OST whose SMQ node has no data block at all is an empty queue, not a broken one.
        FailureLog failures(5);
        ost2pst::ltp::QueueStats stats;
        const std::vector<uint8_t> empty;
        Status status = walk_queue(0, kSudSize, ByteView(empty.data(), empty.size(), 0),
                                   [&](ByteView, uint64_t) { return true; }, stats, failures);
        TEST_OK(status, "an empty queue node");
        TEST_EQ(stats.items_total, 0, "no items");
        TEST_EQ(failures.total(), 0, "an empty queue reports nothing");
    }
}

void test_smq() {
    const std::vector<uint8_t> block = queue_of({
        sud_bytes(0, 0x0001, {0x122, 0x2A2, 0, 0}),
        sud_bytes(0x8000, 0x0005, {0x122, 0x322, 0, 0}),
        sud_bytes(0, 0x00FF, {9, 9, 9, 9}),
    });
    FailureLog failures(5);
    Result<SmqReport> report = read_smq(kSudSize, ByteView(block.data(), block.size(), 0x8000), failures);
    TEST_OK(report, "read the SMQ");
    TEST_EQ(report.value().queue.items_total, 3, "items in the block");
    TEST_EQ(report.value().queue.items_consumed, 1, "the item the head has already passed");
    TEST_EQ(report.value().queue.items_queued, 2, "items still queued");
    TEST_EQ(report.value().by_type.at(0x0001), 1, "one SUDT_MSG_ADD");
    TEST_EQ(report.value().by_type.at(0x0005), 1, "one SUDT_FLD_ADD");
    TEST_EQ(report.value().by_type.at(0x00FF), 1, "one undefined type");
    TEST_EQ(report.value().unknown_types, 1, "the undefined type counted");
    TEST_EQ(report.value().by_flags.at(0x8000), 1, "SUDF_DOMAIN_CHECKED counted");
    TEST_EQ(report.value().suds.size(), 3, "the SUDs are kept for the report");
    TEST_EQ(report.value().suds[1].position, 1, "the position of the second SUD");
    TEST_EQ(report.value().suds[1].offset, 0x8000 + kSudSize, "the absolute offset of the second SUD");
    TEST_EQ(failures.total(), 0, "a well-formed SMQ reports nothing");

    FailureLog quiet(5);
    const std::vector<uint8_t> empty;
    Result<SmqReport> none = read_smq(0, ByteView(empty.data(), empty.size(), 0), quiet);
    TEST_OK(none, "an empty SMQ");
    TEST_EQ(none.value().by_type.size(), 0, "no SUD types");
    TEST_EQ(none.value().queue.items_queued, 0, "nothing queued");
}

} // namespace

int main() {
    test_sud();
    test_flags();
    test_sud_data();
    test_queue();
    test_smq();
    return finish("ltp_smq_test");
}
