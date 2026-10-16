// A property context is a BTH with one fixed record shape ([MS-PST] 2.3.3.3), so this file checks the
// record decoder, the walk from the HN's hidUserRoot through the BTHHEADER to the record array, and the
// block-backed heap source a real PC is read through.
#include <cstdint>
#include <map>
#include <utility>
#include <vector>

#include "ost2pst/ltp/block_heap.h"
#include "ost2pst/ltp/bth.h"
#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/pc.h"
#include "ost2pst/ltp/prop_type.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"
#include "test_support.h"

namespace {

using ost2pst::ltp::BlockHeapSource;
using ost2pst::ltp::BthStats;
using ost2pst::ltp::decode_hn_header;
using ost2pst::ltp::decode_hn_page_map;
using ost2pst::ltp::decode_pc_record;
using ost2pst::ltp::HeapSource;
using ost2pst::ltp::HnHeader;
using ost2pst::ltp::HnPageMap;
using ost2pst::ltp::PcRecord;
using ost2pst::ltp::prop_type_info;
using ost2pst::ltp::prop_type_is_inline;
using ost2pst::ltp::read_pc;
using ost2pst::ndb::FailureLog;
using ost2pst::ndb::FileProfile;
using ost2pst::util::ByteView;
using ost2pst::util::ErrorKind;
using ost2pst::util::make_error;
using ost2pst::util::Result;
using ost2pst::util::Status;

constexpr uint64_t kHeapBase = 0x10000;
constexpr uint64_t kBlockBase = 0x4000;
constexpr uint64_t kBlockSize = 512;
constexpr uint16_t kIbHnpm = 0x40;
// The fixtures name allocations 1-3 of block 0, which is a legal HID under either profile; the 512 one
// is used here because nothing in this test depends on the block index.
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

struct Fixture {
    uint16_t prop_id;
    uint16_t prop_type;
    uint32_t value;
};

// [MS-PST] 2.3.3.3: wPropId is the key, then wPropType and dwValueHnid are the 6 data bytes.
std::vector<uint8_t> pc_record(uint16_t prop_id, uint16_t prop_type, uint32_t value) {
    std::vector<uint8_t> bytes;
    put16(bytes, prop_id);
    put16(bytes, prop_type);
    put32(bytes, value);
    return bytes;
}

std::vector<uint8_t> pc_records(const std::vector<Fixture> &fixtures) {
    std::vector<uint8_t> bytes;
    for (const Fixture &fixture : fixtures) {
        const std::vector<uint8_t> one = pc_record(fixture.prop_id, fixture.prop_type, fixture.value);
        bytes.insert(bytes.end(), one.begin(), one.end());
    }
    return bytes;
}

std::vector<uint8_t> bth_header_bytes(uint8_t cb_key, uint8_t cb_ent, uint32_t hid_root) {
    std::vector<uint8_t> bytes;
    bytes.push_back(0xB5);
    bytes.push_back(cb_key);
    bytes.push_back(cb_ent);
    bytes.push_back(0); // bIdxLevels
    put32(bytes, hid_root);
    return bytes;
}

HnHeader pc_hn_header(uint8_t client_sig = 0xBC) {
    HnHeader header;
    header.ib_hnpm = kIbHnpm;
    header.b_sig = 0xEC;
    header.b_client_sig = client_sig;
    header.hid_user_root = 0x20;
    return header;
}

// A real HN block whose allocation 1 (HID 0x20) holds the BTHHEADER, allocation 2 (HID 0x40) the record
// array and allocation 3 (HID 0x60) a value, each exactly the size of what it holds. That is the shape
// [MS-PST] 2.3.3.6 draws, and the record count a BTH reports comes from the allocation size.
std::vector<uint8_t> make_hn_block(const std::vector<uint8_t> &header_bytes,
                                   const std::vector<uint8_t> &records) {
    std::vector<uint8_t> block(kBlockSize, 0);
    const uint16_t first = 0x000C;
    const uint16_t after_header = static_cast<uint16_t>(first + header_bytes.size());
    const uint16_t after_records = static_cast<uint16_t>(after_header + records.size());
    const uint16_t after_value = static_cast<uint16_t>(after_records + 24);
    for (uint64_t at = first; at < after_value; ++at) {
        block[at] = static_cast<uint8_t>(0xA0 + (at % 16));
    }
    block[0] = static_cast<uint8_t>(kIbHnpm & 0xFF);
    block[1] = static_cast<uint8_t>(kIbHnpm >> 8);
    block[2] = 0xEC;
    block[3] = 0xBC;
    block[4] = 0x20;
    block[kIbHnpm] = 3;
    block[kIbHnpm + 1] = 0;
    block[kIbHnpm + 2] = 0;
    block[kIbHnpm + 3] = 0;
    const uint16_t offsets[] = {first, after_header, after_records, after_value};
    for (int index = 0; index < 4; ++index) {
        block[kIbHnpm + 4 + index * 2] = static_cast<uint8_t>(offsets[index] & 0xFF);
        block[kIbHnpm + 5 + index * 2] = static_cast<uint8_t>(offsets[index] >> 8);
    }
    for (size_t index = 0; index < header_bytes.size(); ++index) {
        block[first + index] = header_bytes[index];
    }
    for (size_t index = 0; index < records.size(); ++index) {
        block[after_header + index] = records[index];
    }
    return block;
}

void check_record_decoder() {
    // [MS-PST] 2.3.3.3: a fixed-size type of 4 bytes or less stores the value in dwValueHnid itself.
    {
        const std::vector<uint8_t> bytes = pc_record(0x67F1, 0x0003, 0x12345678); // PtypInteger32
        Result<PcRecord> record = decode_pc_record(ByteView(bytes.data(), bytes.size(), kHeapBase));
        TEST_OK(record, "an inline PtypInteger32");
        if (!record.ok()) {
            return;
        }
        TEST_EQ(record.value().prop_id, 0x67F1, "wPropId");
        TEST_EQ(record.value().prop_type, 0x0003, "wPropType");
        TEST_EQ(record.value().value_hnid, 0x12345678, "dwValueHnid holds the value");
        TEST_EQ(record.value().value_inline, 1, "value is inline");
        TEST_EQ(record.value().value_in_heap, 0, "an inline value is not a heap reference");
        TEST_EQ(record.value().value_in_subnode, 0, "an inline value is not a subnode reference");
        TEST_EQ(record.value().value.size(), 4, "the inline window is the four dwValueHnid bytes");
        TEST_EQ(record.value().value.base(), kHeapBase + 4, "inline value absolute offset");
        TEST_EQ(record.value().value.data()[0], 0x78, "inline value byte 0 (little-endian)");
        TEST_EQ(record.value().value.data()[3], 0x12, "inline value byte 3");
        TEST_EQ(record.value().offset, kHeapBase, "record absolute offset");
    }
    TEST_EQ(prop_type_is_inline(0x0002), 1, "PtypShort is 2 bytes");
    TEST_EQ(prop_type_is_inline(0x000B), 1, "PtypBoolean is 1 byte");
    TEST_EQ(prop_type_is_inline(0x0003), 1, "PtypInteger32 is 4 bytes");
    TEST_EQ(prop_type_is_inline(0x000A), 0, "PtypInteger64 is 8 bytes, too big for dwValueHnid");
    TEST_EQ(prop_type_is_inline(0x0048), 0, "PtypGuid is 16 bytes");
    TEST_EQ(prop_type_is_inline(0x001F), 0, "PtypString16 is variable-size");
    TEST_EQ(prop_type_is_inline(0x1003), 0, "a multi-valued type is stored through an HNID");
    TEST_EQ(prop_type_is_inline(0x0ABC), 0, "an unknown type is not guessed to be inline");
    TEST_STR(prop_type_info(0x0003).name, "PtypInteger32", "type name");
    TEST_EQ(prop_type_info(0x0003).fixed_size, 4, "fixed size");
    TEST_EQ(prop_type_info(0x0003).variable_size, 0, "fixed-size type");
    TEST_EQ(prop_type_info(0x1003).fixed_size, 4, "the multi-valued form keeps its base type size");
    TEST_EQ(prop_type_info(0x001F).variable_size, 1, "PtypString16 is variable-size");
    TEST_STR(prop_type_info(0x0ABC).name, "unknown", "an unrecognised type is named as unknown");

    // [MS-PST] 2.3.3.2: hidType NID_TYPE_HID means the data block, anything else is a subnode NID.
    {
        const std::vector<uint8_t> heap_value = pc_record(0x3001, 0x001F, 0x60);
        Result<PcRecord> record = decode_pc_record(ByteView(heap_value.data(), heap_value.size(), kHeapBase));
        TEST_OK(record, "a string value in the heap");
        if (record.ok()) {
            TEST_EQ(record.value().value_in_heap, 1, "HID 0x60 points into the data block");
            TEST_EQ(record.value().value_in_subnode, 0, "not a subnode");
            TEST_EQ(record.value().value_inline, 0, "a variable-size value is not inline");
            TEST_EQ(record.value().value.size(), 0, "no inline window for a referenced value");
        }
        const std::vector<uint8_t> subnode_value = pc_record(0x0FF9, 0x0102, 0x61);
        Result<PcRecord> big = decode_pc_record(ByteView(subnode_value.data(), subnode_value.size(), kHeapBase));
        TEST_OK(big, "a binary value in the subnode");
        if (big.ok()) {
            TEST_EQ(big.value().value_in_subnode, 1, "nidType 1 is a subnode NID");
            TEST_EQ(big.value().value_in_heap, 0, "not a heap item");
        }
        // [MS-PST] 2.3.3.2 / 2.3.3.3: dwValueHnid 0 answers neither way -- hidIndex 0 is not a HID and no
        // nidType is 0 -- so the record means the property has no value.
        {
            const std::vector<uint8_t> no_value = pc_record(0x3001, 0x001F, 0x00000000);
            Result<PcRecord> empty = decode_pc_record(ByteView(no_value.data(), no_value.size(), kHeapBase));
            TEST_OK(empty, "a string property with no value");
            if (empty.ok()) {
                TEST_EQ(empty.value().value_absent, 1, "dwValueHnid 0 means no value");
                TEST_EQ(empty.value().value_in_heap, 0, "so it names no heap item");
                TEST_EQ(empty.value().value_in_subnode, 0, "and no subnode");
                TEST_EQ(empty.value().value_inline, 0, "and is not the value itself");
            }
        }
    }

    const std::vector<uint8_t> bytes = pc_record(0x67F1, 0x0003, 0x1);
    TEST_ERROR(decode_pc_record(ByteView(bytes.data(), 7, kHeapBase)), ErrorKind::kTruncated,
               "PCBTHRECORD", "a 7-byte view cannot hold a PC record");
}

void check_read_pc_walk() {
    FakeHeap heap;
    heap.add(0x20, bth_header_bytes(2, 6, 0x40));
    heap.add(0x40, pc_records({{0x0FF9, 0x0102, 0x80}, {0x3001, 0x001F, 0x60}, {0x67F1, 0x0003, 0x2A}}));

    std::vector<PcRecord> records;
    BthStats stats;
    FailureLog failures;
    Status status = read_pc(pc_hn_header(), kProfile, heap, [&](const PcRecord &record) {
        records.push_back(record);
        return true;
    }, stats, failures);

    TEST_OK(status, "reading a PC");
    TEST_EQ(records.size(), 3, "record count");
    // A PC is a BTH, so records come out in property-id order ([MS-PST] 2.3.2.3 / 2.3.3).
    TEST_EQ(records.size() > 0 ? records[0].prop_id : 0, 0x0FF9, "first property id");
    TEST_EQ(records.size() > 1 ? records[1].prop_id : 0, 0x3001, "second property id");
    TEST_EQ(records.size() > 2 ? records[2].prop_id : 0, 0x67F1, "third property id");
    TEST_EQ(records.size() > 0 ? records[0].position : 0, 0, "position 0");
    TEST_EQ(records.size() > 2 ? records[2].position : 0, 2, "position 2");
    TEST_EQ(records.size() > 0 ? records[0].offset : 0, kHeapBase + 0x40, "first record absolute offset");
    TEST_EQ(records.size() > 2 ? records[2].offset : 0, kHeapBase + 0x40 + 16, "third record absolute offset");
    TEST_EQ(records.size() > 0 ? records[0].value_in_heap : 0, 1, "the binary value lives in the heap");
    TEST_EQ(records.size() > 2 ? records[2].value_inline : 0, 1, "the integer value is inline");
    TEST_EQ(stats.heap_items_read, 2, "the BTHHEADER allocation and the record array");
    TEST_EQ(stats.leaf_records, 3, "leaf records");
    TEST_EQ(stats.index_records, 0, "no index level");
    TEST_EQ(failures.total(), 0, "no findings");
    TEST_EQ(heap.calls, 2, "hidUserRoot then hidRoot");

    // [MS-PST] 2.3.2.1: a PC with no properties is a BTH with hidRoot 0.
    {
        FakeHeap empty;
        empty.add(0x20, bth_header_bytes(2, 6, 0));
        BthStats empty_stats;
        FailureLog empty_failures;
        size_t seen = 0;
        Status empty_status = read_pc(pc_hn_header(), kProfile, empty, [&](const PcRecord &) {
            ++seen;
            return true;
        }, empty_stats, empty_failures);
        TEST_OK(empty_status, "an empty PC reads");
        TEST_EQ(seen, 0, "no records");
        TEST_EQ(empty_stats.heap_items_read, 1, "only the BTHHEADER allocation");
        TEST_EQ(empty_failures.total(), 0, "an empty PC is not a finding");
    }
}

void check_read_pc_rejects() {
    {
        // [MS-PST] 2.3.3: a PC is announced by bClientSig == bTypePC, so a TC header is refused.
        FakeHeap heap;
        heap.add(0x20, bth_header_bytes(2, 6, 0x40));
        BthStats stats;
        FailureLog failures;
        Status status = read_pc(pc_hn_header(0x7C), kProfile, heap, [](const PcRecord &) { return true; }, stats,
                                failures);
        TEST_CHECK(!status.ok());
        if (!status.ok()) {
            TEST_EQ(status.error().kind, static_cast<uint64_t>(ErrorKind::kBadField), "error kind");
            TEST_STR(status.error().field, "HNHDR.bClientSig", "the header field that says this is not a PC");
        }
    }
    {
        // [MS-PST] 2.3.3: a PC BTH has cbKey 2 and cbEnt 6, and a header that says otherwise is refused.
        FakeHeap heap;
        heap.add(0x20, bth_header_bytes(4, 6, 0x40));
        BthStats stats;
        FailureLog failures;
        Status status = read_pc(pc_hn_header(), kProfile, heap, [](const PcRecord &) { return true; }, stats, failures);
        TEST_CHECK(!status.ok());
        if (!status.ok()) {
            TEST_STR(status.error().field, "BTHHEADER.cbKey", "the wrong record shape is named");
        }
    }
    {
        FakeHeap heap;
        heap.add(0x20, bth_header_bytes(2, 8, 0x40));
        BthStats stats;
        FailureLog failures;
        Status status = read_pc(pc_hn_header(), kProfile, heap, [](const PcRecord &) { return true; }, stats, failures);
        TEST_CHECK(!status.ok());
        if (!status.ok()) {
            TEST_STR(status.error().field, "BTHHEADER.cbKey", "cbEnt is reported with cbKey");
        }
    }
    {
        // hidUserRoot has to name a real allocation: nothing is invented when it does not.
        FakeHeap heap;
        BthStats stats;
        FailureLog failures;
        Status status = read_pc(pc_hn_header(), kProfile, heap, [](const PcRecord &) { return true; }, stats, failures);
        TEST_CHECK(!status.ok());
        if (!status.ok()) {
            TEST_STR(status.error().field, "HID", "the missing BTHHEADER allocation");
        }
    }
}

void check_block_heap_source() {
    const std::vector<uint8_t> block_bytes = make_hn_block(
        bth_header_bytes(2, 6, 0x40), pc_records({{0x3001, 0x001F, 0x60}, {0x67F1, 0x0003, 0x77}}));
    const ByteView block(block_bytes.data(), block_bytes.size(), kBlockBase);

    Result<HnHeader> header = decode_hn_header(block);
    TEST_OK(header, "the fixture block is a heap node");
    if (!header.ok()) {
        return;
    }
    Result<HnPageMap> map = decode_hn_page_map(block, header.value().ib_hnpm);
    TEST_OK(map, "and carries a page map");
    if (!map.ok()) {
        return;
    }

    BlockHeapSource source(block, map.value(), kProfile, 0);
    Result<ByteView> root = source.heap(0x20);
    TEST_OK(root, "HID 0x20 is the BTHHEADER allocation");
    if (root.ok()) {
        TEST_EQ(root.value().base(), kBlockBase + 0x0C, "allocation 1 absolute offset");
        TEST_EQ(root.value().size(), 8, "allocation 1 size");
    }
    Result<ByteView> records = source.heap(0x40);
    TEST_OK(records, "HID 0x40 is the record array");
    if (records.ok()) {
        TEST_EQ(records.value().base(), kBlockBase + 0x14, "allocation 2 absolute offset");
        TEST_EQ(records.value().size(), 16, "allocation 2 is exactly the two records");
    }

    // [MS-PST] 2.3.1.1 / 2.3.1.4: a HID naming another data block is not answerable from this block.
    TEST_ERROR(source.heap(0x00020020), ErrorKind::kUnsupported, "HID.hidBlockIndex",
               "a heap item in data block 2 is reported, not fetched from the wrong block");
    TEST_EQ(source.cross_block_misses, 1, "the miss is counted");
    TEST_ERROR(source.heap(0x21), ErrorKind::kBadField, "HID", "hidType 1 is a node id");
    TEST_ERROR(source.heap(0x80), ErrorKind::kBadField, "HNPAGEMAP.cAlloc", "allocation 4 does not exist");
}

void check_read_pc_over_a_real_block() {
    // The whole path over a real heap node: hidUserRoot -> BTHHEADER -> record array ([MS-PST] 2.3.3.1).
    const std::vector<uint8_t> block_bytes = make_hn_block(
        bth_header_bytes(2, 6, 0x40), pc_records({{0x3001, 0x001F, 0x60}, {0x67F1, 0x0003, 0x77}}));
    const ByteView block(block_bytes.data(), block_bytes.size(), kBlockBase);
    Result<HnHeader> header = decode_hn_header(block);
    TEST_OK(header, "the fixture block is a heap node");
    Result<HnPageMap> map = decode_hn_page_map(block, header.value().ib_hnpm);
    TEST_OK(map, "and carries a page map");
    if (!header.ok() || !map.ok()) {
        return;
    }

    BlockHeapSource source(block, map.value(), kProfile, 0);
    std::vector<PcRecord> parsed;
    BthStats stats;
    FailureLog failures;
    Status status = read_pc(header.value(), kProfile, source, [&](const PcRecord &record) {
        parsed.push_back(record);
        return true;
    }, stats, failures);
    TEST_OK(status, "reading a PC out of a real heap node");
    TEST_EQ(parsed.size(), 2, "record count");
    TEST_EQ(parsed.size() > 0 ? parsed[0].prop_id : 0, 0x3001, "first property id");
    TEST_EQ(parsed.size() > 0 ? parsed[0].offset : 0, kBlockBase + 0x14, "record offset inside the block");
    TEST_EQ(parsed.size() > 1 ? parsed[1].offset : 0, kBlockBase + 0x1C, "second record offset");
    TEST_EQ(parsed.size() > 1 ? parsed[1].value_hnid : 0, 0x77, "the inline value");
    TEST_EQ(parsed.size() > 1 ? parsed[1].value_inline : 0, 1, "PtypInteger32 is stored inline");
    TEST_EQ(stats.heap_items_read, 2, "two allocations read");
    TEST_EQ(failures.total(), 0, "no findings");
}

} // namespace

int main() {
    check_record_decoder();
    check_read_pc_walk();
    check_read_pc_rejects();
    check_block_heap_source();
    check_read_pc_over_a_real_block();
    return ost2pst::test::finish("ltp_pc_test");
}
