// A Property Context is the shape the message store and every Folder object PC is built out of, so this
// file builds one with the writer and reads it back with the reader: ltp::read_pc through a
// BlockHeapSource over the built block ([MS-PST] 2.3.3.3 / 2.3.3.6).
#include <cstdint>
#include <string>
#include <vector>

#include "ost2pst/ltp/block_heap.h"
#include "ost2pst/ltp/bth.h"
#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/pc.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"
#include "ost2pst/writer/heap.h"
#include "ost2pst/writer/nid.h"
#include "ost2pst/writer/pc.h"
#include "test_support.h"

namespace {

using ost2pst::ltp::BlockHeapSource;
using ost2pst::ltp::BthStats;
using ost2pst::ltp::decode_hn_header;
using ost2pst::ltp::decode_hn_page_map;
using ost2pst::ltp::hn_heap_item;
using ost2pst::ltp::HnHeader;
using ost2pst::ltp::HnPageMap;
using ost2pst::ltp::hid_type;
using ost2pst::ltp::kNidTypeAttachmentTable;
using ost2pst::ltp::kNidTypeLtp;
using ost2pst::ltp::kNidTypeRecipientTable;
using ost2pst::ltp::PcRecord;
using ost2pst::ltp::read_pc;
using ost2pst::ndb::FailureLog;
using ost2pst::ndb::FileProfile;
using ost2pst::util::ByteView;
using ost2pst::util::ErrorKind;
using ost2pst::util::Result;
using ost2pst::util::Status;
using ost2pst::writer::build_pc;
using ost2pst::writer::HeapImage;
using ost2pst::writer::LocalNids;
using ost2pst::writer::PcNode;
using ost2pst::writer::PcProperty;

constexpr FileProfile kProfile = FileProfile::kPst;
constexpr uint64_t kBlockBase = 0x4800;

std::vector<uint8_t> utf16(const std::string &text) {
    std::vector<uint8_t> bytes;
    for (char character : text) {
        bytes.push_back(static_cast<uint8_t>(character));
        bytes.push_back(0);
    }
    return bytes;
}

std::vector<uint8_t> bytes_of(const ByteView &view) {
    return std::vector<uint8_t>(view.data(), view.data() + view.size());
}

ByteView view_of(const HeapImage &heap) {
    return ByteView(heap.bytes().data(), heap.bytes().size(), kBlockBase);
}

// Reads the built image back the way the LTP layer reads a data block.
void check_pc_round_trip() {
    const std::vector<uint8_t> provider_uid = {0x22, 0x9D, 0xB5, 0x0A, 0xDC, 0xD9, 0x94, 0x43,
                                               0x85, 0xDE, 0x90, 0xAE, 0xB0, 0x7D, 0x12, 0x70};
    const std::vector<uint8_t> name = utf16("TOP OF PERSONAL FOLDERS");
    std::vector<uint8_t> entry_id = provider_uid;
    entry_id.insert(entry_id.begin(), 4, 0);
    entry_id.insert(entry_id.end(), 4, 0x22);

    // Deliberately out of order: a PC is a BTH, so the writer has to sort it by wPropId.
    const std::vector<PcProperty> properties = {
        {0x360A, 0x000B, {0x01}},
        {0x35E0, 0x0102, entry_id},
        {0x0FF9, 0x0102, provider_uid},
        {0x3602, 0x0003, {0x00, 0x00, 0x00, 0x00}},
        {0x3001, 0x001F, name},
        {0x66FA, 0x0003, {0x10, 0x00, 0x00, 0x00}},
    };

    LocalNids local_nids;
    Result<PcNode> built = build_pc(properties, local_nids);
    TEST_OK(built, "build_pc");
    if (!built.ok()) {
        return;
    }
    const PcNode &node = built.value();
    const HeapImage &heap = node.heap;
    TEST_EQ(heap.allocation_count(), 5, "BTHHEADER + record array + 3 values");
    TEST_EQ(heap.hid_user_root(), 0x20, "hidUserRoot names the BTHHEADER");
    TEST_EQ(node.subnodes.size(), 0, "no value here is past 3580 bytes");
    TEST_EQ(local_nids.taken(), 0, "so the node took no subnode NID");

    Result<HnHeader> hn = decode_hn_header(view_of(heap));
    TEST_OK(hn, "built PC HNHDR");
    if (!hn.ok()) {
        return;
    }
    TEST_EQ(hn.value().b_client_sig, 0xBC, "a PC heap node carries bTypePC");

    Result<HnPageMap> map = decode_hn_page_map(view_of(heap), hn.value().ib_hnpm);
    TEST_OK(map, "built PC HNPAGEMAP");
    if (!map.ok()) {
        return;
    }

    BlockHeapSource source(view_of(heap), map.value(), kProfile, 0);
    std::vector<PcRecord> records;
    BthStats stats;
    FailureLog failures;
    Status status = read_pc(hn.value(), kProfile, source,
                            [&](const PcRecord &record) {
                                records.push_back(record);
                                return true;
                            },
                            stats, failures);
    TEST_CHECK(status.ok());
    TEST_EQ(failures.total(), 0, "no PC findings");
    TEST_EQ(records.size(), 6, "record count");
    TEST_EQ(stats.leaf_records, 6, "BTH leaf records");
    TEST_EQ(stats.index_records, 0, "a PC with bIdxLevels 0 has no index array");

    const uint16_t expected_ids[] = {0x0FF9, 0x3001, 0x35E0, 0x3602, 0x360A, 0x66FA};
    const uint16_t expected_types[] = {0x0102, 0x001F, 0x0102, 0x0003, 0x000B, 0x0003};
    const bool expected_inline[] = {false, false, false, true, true, true};
    for (size_t index = 0; index < records.size() && index < 6; ++index) {
        TEST_EQ(records[index].prop_id, expected_ids[index], "records are sorted by wPropId");
        TEST_EQ(records[index].prop_type, expected_types[index], "wPropType");
        TEST_EQ(records[index].value_inline, expected_inline[index],
                "dwValueHnid is the value only for a fixed type of 4 bytes or less");
        TEST_EQ(records[index].position, index, "record position");
        if (index != 0) {
            TEST_CHECK(records[index].offset > records[index - 1].offset);
        }
    }

    // The three variable-size values are allocations 3, 4 and 5 in record order ([MS-PST] 2.3.3.3).
    const uint32_t expected_hids[] = {0x60, 0x80, 0xA0};
    const std::vector<uint8_t> *expected_values[] = {&provider_uid, &name, &entry_id};
    for (size_t index = 0; index < 3; ++index) {
        TEST_EQ(records[index].value_hnid, expected_hids[index], "HNID of the value");
        TEST_CHECK(records[index].value_in_heap);
        Result<ByteView> value = hn_heap_item(map.value(), view_of(heap), records[index].value_hnid,
                                              kProfile);
        TEST_OK(value, "value heap item");
        if (!value.ok()) {
            continue;
        }
        TEST_CHECK(bytes_of(value.value()) == *expected_values[index]);
    }

    // Inline values sit in dwValueHnid, little-endian ([MS-PST] 2.3.3.3).
    TEST_EQ(records[3].value_hnid, 0, "PidTagContentCount 0");
    TEST_EQ(records[4].value_hnid, 1, "PidTagSubfolders 1");
    TEST_EQ(records[5].value_hnid, 16, "an inline Integer32");
    TEST_EQ(records[3].value.size(), 4, "an inline value is the four dwValueHnid bytes");
}

void check_empty_pc() {
    LocalNids local_nids;
    Result<PcNode> built = build_pc({}, local_nids);
    TEST_OK(built, "an empty PC");
    if (!built.ok()) {
        return;
    }
    TEST_EQ(built.value().heap.allocation_count(), 1, "only the BTHHEADER");

    Result<HnHeader> hn = decode_hn_header(view_of(built.value().heap));
    TEST_OK(hn, "empty PC HNHDR");
    if (!hn.ok()) {
        return;
    }
    Result<HnPageMap> map = decode_hn_page_map(view_of(built.value().heap), hn.value().ib_hnpm);
    TEST_OK(map, "empty PC HNPAGEMAP");
    if (!map.ok()) {
        return;
    }
    BlockHeapSource source(view_of(built.value().heap), map.value(), kProfile, 0);
    BthStats stats;
    FailureLog failures;
    uint64_t records = 0;
    Status status = read_pc(hn.value(), kProfile, source,
                            [&](const PcRecord &) {
                                ++records;
                                return true;
                            },
                            stats, failures);
    TEST_CHECK(status.ok());
    TEST_EQ(records, 0, "hidRoot 0 means no records ([MS-PST] 2.3.2.1)");
    TEST_EQ(failures.total(), 0, "no findings for an empty PC");
}

// [MS-PST] 2.3.3.3 and 2.6.2.2.2: a variable-size value past 3580 bytes is not a heap allocation at all.
// It is a subnode of the node, and dwValueHnid holds that subnode's local NID, whose hidType is the
// nidType the reader matches against ([MS-PST] 2.3.3.2, and 2.4.5 names NID_TYPE_LTP for "raw LTP data
// for the Message PC").
void check_pc_value_subnode() {
    const std::vector<uint8_t> body(3581, 0x41); // one byte past the heap limit
    const std::vector<uint8_t> html(4000, 0x42);
    const std::vector<uint8_t> subject = utf16("Subject");

    LocalNids local_nids;
    Result<PcNode> built = build_pc({{0x1000, 0x001F, body},
                                     {0x1013, 0x001F, html},
                                     {0x0037, 0x001F, subject},
                                     {0x0E07, 0x0003, std::vector<uint8_t>(4, 0x01)}},
                                    local_nids);
    TEST_OK(built, "a PC with two values past 3580 bytes");
    if (!built.ok()) {
        return;
    }
    const PcNode &node = built.value();
    TEST_EQ(node.heap.allocation_count(), 3, "BTHHEADER, the record array, and the one value that stayed");
    TEST_EQ(node.subnodes.size(), 2, "the two long values became subnodes");
    if (node.subnodes.size() != 2) {
        return;
    }
    TEST_EQ(node.subnodes[0].nid, 0x3F, "the first subnode NID is nidIndex 1 under NID_TYPE_LTP");
    TEST_EQ(node.subnodes[1].nid, 0x5F, "the second takes the next nidIndex");
    TEST_CHECK(node.subnodes[0].bytes == body);
    TEST_CHECK(node.subnodes[1].bytes == html);
    TEST_EQ(local_nids.taken(), 2, "the node took one local NID per subnode");

    Result<HnHeader> hn = decode_hn_header(view_of(node.heap));
    TEST_OK(hn, "subnode PC HNHDR");
    if (!hn.ok()) {
        return;
    }
    Result<HnPageMap> map = decode_hn_page_map(view_of(node.heap), hn.value().ib_hnpm);
    TEST_OK(map, "subnode PC HNPAGEMAP");
    if (!map.ok()) {
        return;
    }
    BlockHeapSource source(view_of(node.heap), map.value(), kProfile, 0);
    std::vector<PcRecord> records;
    BthStats stats;
    FailureLog failures;
    Status status = read_pc(hn.value(), kProfile, source,
                            [&](const PcRecord &record) {
                                records.push_back(record);
                                return true;
                            },
                            stats, failures);
    TEST_CHECK(status.ok());
    TEST_EQ(failures.total(), 0, "no findings for the subnode PC");
    TEST_EQ(records.size(), 4, "record count");
    if (records.size() != 4) {
        return;
    }
    // Sorted by wPropId: 0x0037, 0x0E07, 0x1000, 0x1013.
    TEST_CHECK(records[0].value_in_heap);
    TEST_EQ(records[0].value_hnid, 0x60, "the value that stayed in the heap is still allocation 3");
    TEST_CHECK(records[1].value_inline);
    TEST_CHECK(records[2].value_in_subnode);
    TEST_EQ(records[2].value_hnid, 0x3F, "dwValueHnid holds the subnode NID ([MS-PST] 2.6.2.2.2)");
    TEST_EQ(hid_type(records[2].value_hnid), kNidTypeLtp,
            "an HNID that names a subnode carries that subnode's nidType ([MS-PST] 2.3.3.2)");
    TEST_CHECK(records[3].value_in_subnode);
    TEST_EQ(records[3].value_hnid, 0x5F, "the second subnode NID");
}

// A Message PC does not fit one data block either: the sample's Message PC 0x002001C4 holds 114
// allocations in 12,774 heap bytes (DEVELOPMENT.md).
// 25 strings of 200 bytes is the same shape in miniature, and the records have to name the block each
// value ended up in ([MS-PST] 2.3.1.1 / 2.3.1.6.2).
void check_multi_block_pc() {
    std::vector<PcProperty> properties;
    std::vector<std::vector<uint8_t>> values;
    for (uint16_t index = 0; index < 25; ++index) {
        std::vector<uint8_t> value(200, static_cast<uint8_t>('a'));
        value[0] = static_cast<uint8_t>(index & 0xFF);
        value[2] = static_cast<uint8_t>((index >> 8) & 0xFF);
        values.push_back(value);
        properties.push_back({static_cast<uint16_t>(0x8000 + index), 0x001F, value});
    }

    LocalNids local_nids;
    Result<PcNode> built = build_pc(properties, local_nids);
    TEST_OK(built, "build_pc with 25 values of 200 bytes");
    if (!built.ok()) {
        return;
    }
    const PcNode &node = built.value();
    TEST_EQ(node.heap.allocation_count(), 27u, "BTHHEADER, record array, 25 values");
    TEST_EQ(node.heap.block_count(), 2u, "the heap node needs two data blocks");
    TEST_EQ(node.subnodes.size(), 0u, "no value here is past 3580 bytes");
    TEST_EQ(node.heap.hid_user_root(), 0x20u, "hidUserRoot is the BTHHEADER in block 0");
    TEST_EQ(node.heap.hid(2), 0x40u, "so is the record array");
    TEST_EQ(node.heap.hid(23), 0x000002E0u, "the last value block 0 still holds");
    TEST_EQ(node.heap.hid(24), 0x00010020u, "the first value that had to move to block 1");

    const std::vector<std::vector<uint8_t>> &blocks = node.heap.blocks();
    TEST_EQ(blocks.size(), 2u, "one image per data block");
    TEST_EQ(blocks[0].size(), 8176u, "nonfinal PC heap retains full data capacity");
    TEST_EQ(blocks[1].size(), 2 + 4 * 200 + 4 + 5 * 2, "block 1 cb: HNPAGEHDR, 4 allocations, map");

    std::vector<ost2pst::ltp::HnFragment> fragments;
    for (size_t index = 0; index < blocks.size(); ++index) {
        ost2pst::ltp::HnFragment fragment;
        fragment.owned = blocks[index];
        fragment.block.form = ost2pst::ltp::BlockForm::kRaw;
        fragment.block.block_base = kBlockBase + index * 0x10000;
        fragment.block.raw_block =
            ByteView(fragment.owned.data(), fragment.owned.size(), fragment.block.block_base);
        const ByteView view = fragment.block.heap_node();
        Result<uint16_t> ib_hnpm = view.u16(ost2pst::ltp::kHnIbHnpmOffset);
        TEST_OK(ib_hnpm, "the block's own ibHnpm");
        Result<HnPageMap> map = decode_hn_page_map(view, ib_hnpm.ok() ? ib_hnpm.value() : 0);
        TEST_OK(map, "the block's own HNPAGEMAP");
        if (!map.ok()) {
            continue;
        }
        TEST_EQ(map.value().c_alloc, index == 0 ? 23u : 4u, "allocations per block");
        fragment.page_map = map.take();
        fragment.page_map_ok = true;
        fragments.push_back(std::move(fragment));
    }

    Result<HnHeader> hn = decode_hn_header(
        ByteView(blocks[0].data(), blocks[0].size(), kBlockBase));
    TEST_OK(hn, "the node's HNHDR");
    if (!hn.ok()) {
        return;
    }
    std::optional<ost2pst::ltp::NodeFragmentHeapSource> source;
    source.emplace(fragments, kProfile);
    std::vector<PcRecord> records;
    BthStats stats;
    FailureLog failures;
    Status status = read_pc(hn.value(), kProfile, *source,
                            [&](const PcRecord &record) {
                                records.push_back(record);
                                return true;
                            },
                            stats, failures);
    TEST_CHECK(status.ok());
    TEST_EQ(failures.total(), 0u, "no findings for a PC spread over two blocks");
    TEST_EQ(records.size(), 25u, "the record array read out of block 0");
    for (size_t index = 0; index < records.size() && index < values.size(); ++index) {
        // The 21 values block 0 still holds keep the HIDs a single-block PC had; the rest name block 1.
        const uint32_t expected_hid =
            index < 21 ? static_cast<uint32_t>((3 + index) << ost2pst::ltp::kHidIndexShift)
                       : static_cast<uint32_t>(0x10000u | ((index - 20) << ost2pst::ltp::kHidIndexShift));
        TEST_EQ(records[index].value_hnid, expected_hid, "the record names the value where it lives");
        Result<ByteView> value = source->heap(records[index].value_hnid);
        TEST_OK(value, "the reader resolves the value in its own block");
        if (value.ok()) {
            TEST_CHECK(bytes_of(value.value()) == values[index]);
        }
    }
    TEST_EQ(source->cross_block_misses, 0u, "no HID named a block this node does not have");
}

void check_writer_rejections() {
    LocalNids local_nids;
    TEST_ERROR(build_pc({{0x3001, 0x001F, {0x41, 0x00}}, {0x3001, 0x001F, {0x42, 0x00}}}, local_nids),
               ErrorKind::kBadField, "PC.wPropId", "a duplicated property id");
    TEST_ERROR(build_pc({{0x3602, 0x0003, std::vector<uint8_t>(5, 0x11)}}, local_nids), ErrorKind::kBadField,
               "PC.dwValueHnid", "an 8-byte value cannot be inline");
    TEST_ERROR(build_pc({{0x3001, 0x001F, {}}}, local_nids), ErrorKind::kBadField, "PC.dwValueHnid",
               "a variable-size value with no bytes");

    // [MS-PST] 2.2.2.8.3.3.1.1: a subnode NID is unique only within its parent node, so one nidIndex
    // cannot name two subnodes of the same node.
    LocalNids taken;
    TEST_OK(taken.take(kNidTypeLtp), "the first local NID");
    TEST_ERROR(taken.take_at(1, kNidTypeRecipientTable), ErrorKind::kBadField, "SLENTRY.nid",
               "one nidIndex cannot name two subnodes of one node");
    TEST_OK(taken.take_at(0x33, kNidTypeAttachmentTable), "a caller-chosen nidIndex");
    TEST_EQ(taken.taken(), 2, "the refused claim took nothing");
    TEST_OK(taken.take(kNidTypeLtp), "take() skips an index a caller already claimed");
}

} // namespace

int main() {
    check_pc_round_trip();
    check_empty_pc();
    check_pc_value_subnode();
    check_multi_block_pc();
    check_writer_rejections();
    return ost2pst::test::finish("writer_pc_test");
}
