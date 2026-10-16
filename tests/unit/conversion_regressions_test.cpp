#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <unordered_map>

#include "ost2pst/ltp/node_open.h"
#include "ost2pst/ltp/pc.h"
#include "ost2pst/ltp/tc.h"
#include "ost2pst/msg/item_conversion.h"
#include "ost2pst/writer/pc.h"
#include "ost2pst/writer/tc.h"

#include "test_support.h"

using namespace ost2pst;
namespace {
std::vector<uint8_t> value_bytes(const msg::SubsetValue& value) {
    if (!value.source)
        return value.bytes;
    std::vector<uint8_t> bytes(static_cast<size_t>(value.source->size()));
    TEST_OK(value.source->read_at(0, bytes.data(), bytes.size()), "read spooled value");
    return bytes;
}

void put(std::vector<uint8_t>& bytes, size_t at, uint32_t value, size_t size) {
    for (size_t i = 0; i < size; ++i)
        bytes.at(at + i) = static_cast<uint8_t>(value >> (8 * i));
}

// Synthetic external blocks and an XBLOCK, independent of the PC/TC writer.
struct Blocks : ltp::BlockSource {
    std::vector<std::vector<uint8_t>> leaves;
    std::vector<uint8_t> tree;
    explicit Blocks(const writer::HeapImage& heap) : leaves(heap.blocks()) {
        tree.resize(8 + leaves.size() * 8);
        tree[0] = tree[1] = 1;
        put(tree, 2, static_cast<uint32_t>(leaves.size()), 2);
        uint32_t total = 0;
        for (size_t i = 0; i < leaves.size(); ++i) {
            total += static_cast<uint32_t>(leaves[i].size());
            put(tree, 8 + i * 8, static_cast<uint32_t>(8 + i * 4), 4);
        }
        put(tree, 4, total, 4);
    }
    util::Result<ltp::BlockBytes> block(uint64_t bid) override {
        if (bid == 4 && leaves.size() > 1)
            return ltp::BlockBytes{util::ByteView(tree.data(), tree.size()), true, false};
        auto& bytes = leaves.at(bid == 4 ? 0 : (bid - 8) / 4);
        return ltp::BlockBytes{util::ByteView(bytes.data(), bytes.size()), false, false};
    }
};

writer::HeapImage partial_pc(bool trailing) {
    writer::HeapImage heap(ltp::kClientSigPc);
    std::vector<uint8_t> header(ltp::kBthHeaderSize);
    header[0] = ltp::kBthType;
    header[1] = ltp::kPcCbKey;
    header[2] = ltp::kPcCbEnt;
    header[3] = trailing ? 0 : 1;
    TEST_OK(heap.append(header), "BTH header");
    std::vector<uint8_t> records(trailing ? 9 : 8);
    put(records, 0, 0x4000, 2);
    put(records, 2, 3, 2);
    put(records, 4, 123, 4);
    auto leaf = heap.append(records);
    TEST_OK(leaf, "PC leaf");
    if (!leaf.ok())
        return heap;
    uint32_t root = leaf.value();
    if (!trailing) {
        std::vector<uint8_t> index(12);
        put(index, 0, 0x4000, 2);
        put(index, 2, root, 4);
        put(index, 6, 0x4001, 2);
        put(index, 8, 1, 4); // Invalid child HID after a valid leaf.
        auto added = heap.append(index);
        TEST_OK(added, "PC index");
        if (added.ok())
            root = added.value();
    }
    TEST_OK(heap.patch(1, ltp::kBthHidRootOffset, root), "PC root");
    return heap;
}

void check_partial_pc() {
    for (bool trailing : {false, true}) {
        Blocks blocks(partial_pc(trailing));
        ltp::LtpReadReport census;
        census.profile = ndb::FileProfile::kPst;
        census.nodes.add({0x8082, 8, 0, 0});
        census.nodes.add({0x200024, 4, 0, 0x8082});
        auto registry = msg::EmitRegistry::build({});
        TEST_OK(registry, "registry");
        if (!registry.ok())
            return;
        auto item = msg::prepare_item(census, blocks, {0x200024, 0x8082, 0x200024, 0x8082, false},
                                      registry.value());
        TEST_OK(item, "corrupt PC is an item skip, not a fatal writer error");
        if (item.ok()) {
            TEST_CHECK(item.value().outcome.status == msg::ItemStatus::kSkippedCorrupt);
            TEST_CHECK(!item.value().outcome.source_complete);
            TEST_CHECK(!item.value().diagnostics.empty());
        }
    }
}

void check_large_pc() {
    for (size_t count : {447u, 448u, 600u, 2000u}) {
        std::vector<writer::PcProperty> properties;
        for (size_t i = 0; i < count; ++i) {
            std::vector<uint8_t> value(i % 2 ? 20 : 4, static_cast<uint8_t>(i));
            properties.push_back({static_cast<uint16_t>(0x4000 + i),
                                  static_cast<uint16_t>(i % 2 ? 0x0102 : 0x0003), value});
        }
        writer::LocalNids ids;
        auto pc = writer::build_pc(properties, ids);
        TEST_OK(pc, "PC across the single-leaf boundary");
        if (!pc.ok())
            continue;
        Blocks blocks(pc.value().heap);
        ltp::NodeHeap node;
        ltp::LtpHeapCounters heaps;
        ltp::DataTreeCounters trees;
        std::map<std::string, uint64_t> errors;
        ndb::FailureLog failures;
        TEST_CHECK(ltp::open_node(blocks, ndb::FileProfile::kPst, 0x200024, 4, node, heaps, trees,
                                  errors, nullptr, failures) == ltp::NodeOpen::kOk);
        if (!node.source)
            continue;
        size_t index = 0;
        ltp::BthStats stats;
        auto read = ltp::read_pc(
            node.header, ndb::FileProfile::kPst, *node.source,
            [&](const ltp::PcRecord& record) {
                TEST_CHECK(index < properties.size());
                if (index >= properties.size())
                    return false;
                const auto& expected = properties[index++];
                TEST_EQ(record.prop_id, expected.prop_id, "ordered property identity");
                if (expected.prop_type == 0x0102) {
                    auto value = node.source->heap(record.value_hnid);
                    TEST_OK(value, "heap property across leaves");
                    if (value.ok())
                        TEST_CHECK(
                            std::vector<uint8_t>(value.value().data(),
                                                 value.value().data() + value.value().size()) ==
                            expected.value);
                } else {
                    TEST_EQ(record.value_hnid,
                            static_cast<uint32_t>(expected.value[0]) * 0x01010101u,
                            "inline property across leaves");
                }
                return true;
            },
            stats, failures);
        TEST_OK(read, "walk every leaf");
        TEST_EQ(index, count, "all properties preserved");
        TEST_EQ(failures.total(), 0u, "valid BTH");
    }
}

// Round-trip a complete item through real NDB blocks; no mailbox data is used.
void inspect(writer::StorePlan plan, const std::function<void(const msg::SubsetMessage&)>& check,
             bool corrupt = false) {
    auto scaffold = writer::build_scaffold_plan({}, {}, 1028, 65537, 32768);
    TEST_OK(scaffold, "store counters");
    if (!scaffold.ok())
        return;
    plan.rgnid = scaffold.value().plan.rgnid;
    plan.nodes.push_back({0x8082, 0, {}, {}});
    auto image = writer::write_store(plan);
    TEST_OK(image, "synthetic store");
    if (!image.ok())
        return;
    auto path = std::filesystem::temp_directory_path() / "ost2pst_conversion_regressions.pst";
    {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        file.write(reinterpret_cast<const char*>(image.value().bytes.data()),
                   static_cast<std::streamsize>(image.value().bytes.size()));
        TEST_CHECK(file.good());
    }
    {
        auto file = util::FileReader::open(path.wstring());
        TEST_OK(file, "open synthetic store");
        if (!file.ok())
            return;
        ltp::LtpReadOptions options;
        options.scan_blocks = options.build_folders = false;
        auto census = ltp::read_ltp(file.value(), options);
        TEST_OK(census, "synthetic census");
        if (!census.ok())
            return;
        ndb::BlockReadCounters counters;
        ndb::FailureLog failures;
        ltp::FileBlockSource blocks(file.value(), census.value().profile, census.value().bbt_index,
                                    counters, failures);
        if (corrupt) {
            auto registry = msg::EmitRegistry::build({});
            TEST_OK(registry, "registry");
            if (!registry.ok())
                return;
            auto prepared =
                msg::prepare_item(census.value(), blocks,
                                  {0x200024, 0x8082, 0x200024, 0x8082, false}, registry.value());
            TEST_OK(prepared, "partial table is an item skip");
            if (prepared.ok()) {
                TEST_CHECK(prepared.value().outcome.status == msg::ItemStatus::kSkippedCorrupt);
                TEST_CHECK(!prepared.value().outcome.source_complete);
                TEST_CHECK(!prepared.value().diagnostics.empty());
            }
        }
        for (bool streamed : {false, true}) {
            util::ValueSpool spool(std::filesystem::temp_directory_path().wstring(), 0, 0);
            msg::SubsetOptions extraction;
            if (streamed)
                extraction.spool = &spool;
            auto extracted = msg::extract_item(census.value(), blocks, 0x200024, extraction);
            TEST_OK(extracted, "extract synthetic item");
            if (extracted.ok() && !extracted.value().messages.empty())
                check(extracted.value().messages.front());
            else
                TEST_CHECK(false);
        }
    }
    std::filesystem::remove(path);
}

void check_independent_tc() {
    for (int variant = 0; variant < 3; ++variant) {
        writer::ContentMessage message;
        message.recipients.columns = {{0x40000102}};
        const std::vector<uint8_t> payload{1, 0, 0, 0, 2, 0, 0, 0};
        message.recipients.rows = {{1, {{0x40000102, payload}}}};
        auto item = writer::build_item_plan(message, 0x200024, 0x8082, 1);
        auto table = writer::build_tc({{0x40000102}}, {{1, {payload}}});
        TEST_OK(item, "item for independent TC fixture");
        TEST_OK(table, "binary TC fixture");
        if (!item.ok() || !table.ok())
            return;
        auto heap = table.take();
        if (variant == 0) {
            // 0x4000 sorts before the two required 0x67F2/0x67F3 columns. Change only
            // the descriptor type: the source representation must remain an HNID.
            TEST_OK(heap.patch(1, ltp::kTcInfoSize + ltp::kTcColTagOffset, 0x40001003),
                    "independent MV descriptor");
        } else {
            std::vector<uint8_t> records(variant == 1 ? 16 : 9);
            put(records, 0, 1, 4);
            if (variant == 1) {
                put(records, 4, heap.hid(3), 4);
                put(records, 8, 2, 4);
                put(records, 12, 1, 4); // Invalid second child after the valid row leaf.
                TEST_OK(heap.patch(2, ltp::kBthIdxLevelsOffset, std::vector<uint8_t>{1}),
                        "indexed RowIndex");
            }
            auto root = heap.append(records);
            TEST_OK(root, "partial RowIndex allocation");
            if (!root.ok())
                return;
            TEST_OK(heap.patch(2, ltp::kBthHidRootOffset, root.value()), "partial RowIndex root");
        }
        auto plan = item.take().content.plan;
        size_t replaced = 0;
        for (auto& sub : plan.nodes.front().subnodes)
            if (ltp::nid_type(sub.nid) == ltp::kNidTypeRecipientTable) {
                TEST_EQ(sub.data_blocks.size(), 1u, "small recipient heap");
                plan.blocks.at(sub.data_blocks.front()).bytes = heap.bytes();
                ++replaced;
            }
        TEST_EQ(replaced, 1u, "replace recipient table");
        inspect(
            std::move(plan),
            [&](const msg::SubsetMessage& read) {
                if (variant != 0)
                    return;
                size_t found = 0;
                for (const auto& row : read.recipients)
                    for (const auto& value : row.values)
                        if (value.tag == 0x40001003) {
                            ++found;
                            TEST_CHECK(value_bytes(value) == payload);
                        }
                TEST_EQ(found, 1u, "read independent MV bytes");
            },
            variant != 0);
    }
}

void check_mv() {
    for (uint16_t type :
         std::vector<uint16_t>{0x1002, 0x1003, 0x1004, 0x1005, 0x1006, 0x1007, 0x1014, 0x1040}) {
        for (size_t count : {2u, 2000u}) {
            const uint32_t tag = 0x40000000u | type;
            const size_t width = type == 0x1002 ? 2 : (type <= 0x1004 ? 4 : 8);
            std::vector<uint8_t> payload(width * count, 7);
            writer::LocalNids ids;
            auto tc = writer::build_table({{tag}}, {{1, {payload}}}, ids);
            TEST_OK(tc, "multi-valued fixed base type uses an HNID");
            writer::ContentMessage message;
            message.recipients.columns = {{tag}};
            message.recipients.rows = {{1, {{tag, payload}}}, {2, {{tag, {}, true}}}, {3, {}}};
            auto item = writer::build_item_plan(message, 0x200024, 0x8082, 1);
            TEST_OK(item, "MV content table including present-empty and missing cells");
            if (item.ok())
                inspect(item.take().content.plan, [&](const msg::SubsetMessage& read) {
                    TEST_EQ(read.recipients.size(), 3u, "three recipients");
                    size_t found = 0, empty = 0;
                    for (const auto& row : read.recipients)
                        for (const auto& value : row.values)
                            if (value.tag == tag) {
                                ++found;
                                if (value.absent)
                                    ++empty;
                                else
                                    TEST_CHECK(value_bytes(value) == payload);
                            }
                    TEST_EQ(found, 2u, "present differs from missing");
                    TEST_EQ(empty, 1u, "present-empty MV retained");
                });
        }
    }
}

void check_empty_attachment() {
    for (uint16_t type : std::vector<uint16_t>{0x0102, 0x000D}) {
        msg::SubsetMessage message;
        message.pc_read = true;
        msg::SubsetAttachment attachment;
        attachment.pc_read = true;
        msg::SubsetValue data;
        data.prop_id = 0x3701;
        data.prop_type = type;
        data.tag = 0x37010000u | type;
        data.absent = true;
        attachment.values.push_back(data);
        message.attachments.push_back(attachment);
        message.attachments.push_back({}); // Missing property remains missing.
        msg::SubsetAttachment nested;
        nested.pc_read = nested.embedded_read = true;
        msg::SubsetValue method;
        method.prop_id = 0x3705;
        method.prop_type = 0x0003;
        method.tag = 0x37050003;
        method.bytes = {5, 0, 0, 0};
        method.readable = true;
        nested.values.push_back(method);
        nested.embedded.pc_read = true;
        nested.embedded.attachments.push_back(attachment);
        message.attachments.push_back(nested);
        auto registry = msg::EmitRegistry::build({});
        TEST_OK(registry, "empty registry");
        if (!registry.ok())
            return;
        auto emitted = msg::build_emit_item(message, registry.value());
        TEST_OK(emitted, "emit empty attachment");
        if (!emitted.ok())
            continue;
        TEST_EQ(emitted.value().report.values_dropped, 0u, "empty is preserved");
        const auto& properties = emitted.value().message.attachment_objects.front().properties;
        TEST_CHECK(!properties.empty());
        auto item = writer::build_item_plan(emitted.value().message, 0x200024, 0x8082, 1);
        TEST_OK(item, "write empty attachment");
        if (item.ok())
            inspect(item.take().content.plan, [&](const msg::SubsetMessage& read) {
                TEST_EQ(read.attachments.size(), 3u, "empty, missing and embedded attachments");
                size_t found = 0;
                for (const auto& object : read.attachments) {
                    for (const auto& value : object.values)
                        if (value.prop_id == 0x3701) {
                            ++found;
                            if (!object.embedded_read) {
                                TEST_CHECK(value.absent);
                                TEST_EQ(value.prop_type, type, "empty payload retains its type");
                            }
                        }
                    if (object.embedded_read) {
                        size_t nested_empty = 0;
                        for (const auto& child : object.embedded.attachments)
                            for (const auto& value : child.values)
                                if (value.prop_id == 0x3701) {
                                    ++nested_empty;
                                    TEST_CHECK(value.absent);
                                    TEST_EQ(value.prop_type, type, "nested empty payload type");
                                }
                        TEST_EQ(nested_empty, 1u, "nested present-empty payload survives");
                    }
                }
                TEST_EQ(found, 2u, "empty and embedded properties exist; missing stays missing");
            });
    }
}

void check_index_budget() {
    ltp::LtpReadReport census;
    census.clean = census.npm_read = true;
    census.bbt.pages_visited = census.bbt.page_crc_ok = census.bbt.page_sig_ok = 1;
    census.nbt = census.bbt;
    census.nodes.add({0x122, 4, 0, 0x122});
    census.nbt.leaf_entries = census.nid_entries = 1;
    {
        std::unordered_map<uint64_t, ndb::BbtEntry> entries;
        const size_t count = 128ull * 1024 * 1024 / sizeof(ndb::BbtEntry) + 1;
        entries.reserve(count);
        for (size_t i = 0; i < count; ++i)
            entries.emplace((i + 1) * 4, ndb::BbtEntry{(i + 1) * 4, 0, 1, 2, 0});
        census.bbt_index = ndb::BbtIndex(entries);
    }
    census.bbt.leaf_entries = census.bbt_index.entries();
    TEST_CHECK(census.bbt_index.bytes() > 128ull * 1024 * 1024);
    TEST_OK(msg::build_mailbox_manifest(census), "manifest reuses the already budgeted BBT");
}
} // namespace

int main() {
    check_partial_pc();
    check_large_pc();
    check_independent_tc();
    check_mv();
    check_empty_attachment();
    check_index_budget();
    return test::finish("conversion_regressions_test");
}
