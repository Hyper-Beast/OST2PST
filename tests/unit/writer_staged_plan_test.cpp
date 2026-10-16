#include <algorithm>
#include <cstring>
#include <vector>

#include "ost2pst/util/crc32.h"
#include "ost2pst/writer/content.h"
#include "ost2pst/writer/staged_plan.h"

#include "test_support.h"

namespace {
using namespace ost2pst::util;
using namespace ost2pst::writer;

class MemoryFile final : public RandomAccessFile {
  public:
    std::vector<uint8_t> bytes;
    bool fail_read = false, fail_write = false, fail_flush = false;
    uint64_t fail_second_read_at = UINT64_MAX;
    mutable uint64_t matching_reads = 0;
    mutable size_t max_read = 0;
    size_t max_write = 0;
    uint64_t size() const override { return bytes.size(); }
    Status read_at(uint64_t offset, uint8_t* target, size_t count) const override {
        max_read = std::max(max_read, count);
        if (fail_read || (offset == fail_second_read_at && ++matching_reads == 2))
            return make_error(ErrorKind::kIo, "test.read", offset);
        if (offset > size() || count > size() - offset)
            return make_error(ErrorKind::kTruncated, "test.read", offset);
        if (count != 0)
            std::memcpy(target, bytes.data() + offset, count);
        return {};
    }
    Result<size_t> write_some(uint64_t offset, ByteView input) override {
        max_write = std::max(max_write, input.size());
        if (fail_write)
            return make_error(ErrorKind::kIo, "test.write", offset);
        const size_t count = std::min(size_t{1507}, input.size());
        bytes.resize(std::max(bytes.size(), static_cast<size_t>(offset) + count));
        if (count != 0)
            std::memcpy(bytes.data() + offset, input.data(), count);
        return count;
    }
    Status resize(uint64_t size) override {
        bytes.resize(static_cast<size_t>(size));
        return {};
    }
    Status flush() override {
        if (fail_flush)
            return make_error(ErrorKind::kIo, "test.flush", 0);
        return {};
    }
};

Sha256Digest key(uint8_t value) {
    Sha256Digest key{};
    key[0] = value;
    return key;
}

StorePlan item_plan() {
    StorePlan plan;
    plan.blocks.push_back({{1, 2, 3, 4}});
    plan.blocks.push_back({std::vector<uint8_t>(8176, 0x51)});
    plan.blocks.push_back({{9, 8, 7}});
    StoreNode node;
    node.nid = 0x200024;
    node.nid_parent = 0x8022;
    node.data_blocks = {0};
    node.subnodes = {{0x3F, {1, 2}, {}}};
    plan.nodes.push_back(std::move(node));
    return plan;
}

void check_roundtrip_and_assembly() {
    MemoryFile data, log;
    auto made = StagingJournal::create(data, log, key(99));
    TEST_OK(made, "journal for plans");
    if (!made.ok())
        return;
    auto journal = made.take();
    auto scaffold = build_scaffold_plan({}, {}, 1027, 65537, 32768);
    TEST_OK(scaffold, "scaffold plan");
    if (!scaffold.ok())
        return;
    const auto item = item_plan();
    StagedDetails details;
    details.row = TcRow{0x200024, {{1, 2}, {}}, {false, true}};
    details.counters = {{"committed.normal", 1}, {"source.attachment_bytes", 8179}};
    details.json = "{\"source\":123,\"status\":\"converted\"}";
    TEST_OK(stage_plan(journal, key(1), StagedOutcome::kConverted, scaffold.value().plan, {}),
            "commit scaffold");
    TEST_OK(stage_plan(journal, key(2), StagedOutcome::kConverted, item, details),
            "commit writer-ready item");
    StagedDetails failure;
    failure.counters = {{"failed", 1}};
    failure.json = "{\"source\":124,\"status\":\"failed\"}";
    TEST_OK(stage_plan(journal, key(3), StagedOutcome::kFailed, {}, failure),
            "durable terminal failure");
    auto read = read_staged_plan(journal, 1);
    TEST_OK(read, "decode item metadata without loading payload");
    if (!read.ok())
        return;
    TEST_EQ(read.value().blocks.size(), 3u, "external descriptors");
    TEST_EQ(read.value().nodes.front().subnodes.front().data_blocks.size(), 2u,
            "nested data tree slots");
    TEST_CHECK(read.value().details.json == details.json);
    TEST_CHECK(read.value().details.counters == details.counters);
    TEST_CHECK(read.value().details.row.has_value());
    if (read.value().details.row) {
        TEST_CHECK(read.value().details.row->values == details.row->values);
        TEST_CHECK(read.value().details.row->present_empty == details.row->present_empty);
    }
    const auto durable_bytes = data.bytes;
    const auto durable_log = log.bytes;
    TEST_CHECK(!stage_plan(journal, key(2), StagedOutcome::kConverted, item, details).ok());
    TEST_CHECK(data.bytes == durable_bytes && log.bytes == durable_log);
    auto recovered = StagingJournal::recover(data, log, key(99));
    TEST_OK(recovered, "validate committed ranges before resuming");
    if (!recovered.ok())
        return;
    auto replay = recovered.take();
    TEST_EQ(replay.records().size(), 3u, "one outcome per key after resume");
    auto reread = read_staged_plan(replay, 1);
    TEST_OK(reread, "read recovered plan");
    if (reread.ok())
        TEST_CHECK(reread.value().details.counters == details.counters);
    StagedRows rows(replay, {1});
    auto row = rows.read(0);
    TEST_OK(row, "spooled row source after recovery");
    if (row.ok())
        TEST_CHECK(row.value().values == details.row->values);
    StagedRows no_row(replay, {2});
    TEST_ERROR(no_row.read(0), ErrorKind::kBadField, "staged_plan.item_row",
               "failed record has no output row");
    MemoryFile output;
    auto assembled = assemble_staged(replay, output, {0});
    TEST_OK(assembled, "assemble from bounded committed reads");
    if (!assembled.ok())
        return;
    StorePlan expected = scaffold.value().plan;
    const uint64_t base = expected.blocks.size();
    expected.blocks.insert(expected.blocks.end(), item.blocks.begin(), item.blocks.end());
    auto node = item.nodes.front();
    node.data_blocks[0] += base;
    for (auto& slot : node.subnodes[0].data_blocks)
        slot += base;
    expected.nodes.push_back(std::move(node));
    auto image = write_store(expected);
    TEST_OK(image, "reference in-memory assembly");
    if (image.ok())
        TEST_CHECK(output.bytes == image.value().bytes);
    TEST_CHECK(assembled.value().bytes.empty());
    TEST_EQ(assembled.value().file_bytes, output.size(), "physical output size");
    TEST_CHECK(output.max_write <= 1024u * 1024u);
    data.fail_read = true;
    MemoryFile unread;
    TEST_ERROR(assemble_staged(replay, unread), ErrorKind::kIo, "test.read",
               "staging read failure");
    TEST_CHECK(unread.bytes.empty());
    data.fail_read = false;
    MemoryFile unwritten;
    unwritten.fail_write = true;
    TEST_ERROR(assemble_staged(replay, unwritten), ErrorKind::kIo, "test.write",
               "candidate write failure");
    MemoryFile unflushed;
    unflushed.fail_flush = true;
    TEST_ERROR(assemble_staged(replay, unflushed), ErrorKind::kIo, "test.flush",
               "candidate flush failure");
}

void check_validation_and_io() {
    MemoryFile data, log;
    auto made = StagingJournal::create(data, log, key(99));
    TEST_OK(made, "validation journal");
    if (!made.ok())
        return;
    auto journal = made.take();
    auto plan = item_plan();
    plan.nodes[0].data_blocks[0] = 3;
    TEST_ERROR(stage_plan(journal, key(1), StagedOutcome::kConverted, plan, {}),
               ErrorKind::kBadField, "staged_plan.block_slot",
               "bad relocation rejected before transaction");
    TEST_CHECK(data.bytes.empty());
    plan = item_plan();
    TEST_ERROR(stage_plan(journal, key(1), StagedOutcome::kFailed, plan, {}), ErrorKind::kBadField,
               "staged_plan.outcome", "failed item cannot publish bytes");
    TEST_CHECK(data.bytes.empty());
    data.fail_write = true;
    TEST_ERROR(stage_plan(journal, key(1), StagedOutcome::kConverted, plan, {}), ErrorKind::kIo,
               "test.write", "failed stage write is fatal");
    TEST_CHECK(journal.poisoned());
    TEST_CHECK(journal.records().empty());
}

void check_shared_assembly() {
    MemoryFile data, log;
    auto made = StagingJournal::create(data, log, key(99));
    TEST_OK(made, "sharing journal");
    if (!made.ok())
        return;
    auto journal = made.take();
    StorePlan first;
    first.blocks.push_back({{1, 2, 3, 4}});
    first.nodes.push_back({0x200004, 0, {0}, {}});
    first.rgnid.resize(32);
    auto second = first;
    second.rgnid.clear();
    second.nodes[0].nid = 0x200024;
    TEST_OK(stage_plan(journal, key(1), StagedOutcome::kConverted, first, {}), "first payload");
    TEST_OK(stage_plan(journal, key(2), StagedOutcome::kConverted, second, {}), "same payload");
    MemoryFile output;
    StagedAssemblyStats stats;
    auto result = assemble_staged(journal, output, {}, &stats);
    TEST_OK(result, "share equal bytes across committed records");
    if (result.ok()) {
        TEST_EQ(result.value().blocks.size(), 1u, "one physical external block");
        TEST_EQ(result.value().blocks[0].c_ref, 3u, "BBT plus two node references");
    }
    TEST_EQ(stats.shared_references, 1u, "one shared reference reported");
    TEST_EQ(stats.avoided_payload_bytes, 4u, "exact avoided bytes reported");
    auto recovered = StagingJournal::recover(data, log, key(99));
    TEST_OK(recovered, "sharing is rebuilt from committed ranges on resume");
    if (recovered.ok()) {
        MemoryFile replayed;
        TEST_OK(assemble_staged(recovered.value(), replayed), "recovered shared assembly");
        TEST_CHECK(replayed.bytes == output.bytes);
    }
    const auto loaded = read_staged_plan(journal, 0);
    TEST_OK(loaded, "locate canonical block for read-failure injection");
    if (loaded.ok()) {
        data.fail_second_read_at = journal.records()[0].offset + loaded.value().blocks[0].offset;
        MemoryFile failed;
        TEST_ERROR(assemble_staged(journal, failed, {}, &stats), ErrorKind::kIo, "test.read",
                   "canonical comparison I/O failure cannot become a cache miss");
        TEST_CHECK(failed.bytes.empty());
        TEST_EQ(stats.stored_blocks, 0u, "failed assembly publishes no success statistics");
    }
}

void check_sharing_collision_budget_and_ref_limit() {
    // Equal CRC32, equal length, different actual content. Sharing must compare bytes.
    const std::vector<uint8_t> a{0xD6, 0xAD, 0x77, 0xB8, 0xAD, 0x02, 0xBB, 0x31};
    const std::vector<uint8_t> b{0x46, 0xF3, 0x29, 0x8E, 0xF0, 0x05, 0x5B, 0x01};
    TEST_EQ(crc32(ByteView(a.data(), a.size())), crc32(ByteView(b.data(), b.size())),
            "fixture has a real fingerprint collision");
    MemoryFile data, log;
    auto made = StagingJournal::create(data, log, key(99));
    TEST_OK(made, "collision journal");
    if (!made.ok())
        return;
    auto journal = made.take();
    StorePlan plan;
    plan.blocks = {{a}, {b}};
    plan.nodes = {{0x200004, 0, {0, 1, 0}, {}}};
    plan.rgnid.resize(32);
    TEST_OK(stage_plan(journal, key(1), StagedOutcome::kConverted, plan, {}), "collision fixture");
    for (const uint32_t capacity : {1u, 8u}) {
        MemoryFile output;
        StagedAssemblyStats stats;
        auto result = assemble_staged(journal, output, {capacity}, &stats);
        TEST_OK(result, "bounded index preserves collision contents");
        TEST_EQ(stats.stored_blocks, 2u, "collision is not content equality");
        TEST_EQ(stats.shared_references, 1u, "cached original remains shareable after saturation");
        TEST_EQ(stats.index_entries, capacity == 1 ? 1u : 2u, "index obeys requested bound");
        TEST_CHECK(stats.index_saturated == (capacity == 1));
        if (result.ok()) {
            const auto& blocks = result.value().blocks;
            TEST_EQ(blocks[0].c_ref, 3u, "A occurs twice");
            TEST_EQ(blocks[1].c_ref, 2u, "B occurs once");
            TEST_CHECK(std::equal(a.begin(), a.end(), output.bytes.begin() + blocks[0].ib));
            TEST_CHECK(std::equal(b.begin(), b.end(), output.bytes.begin() + blocks[1].ib));
        }
    }
    MemoryFile over_budget;
    TEST_ERROR(assemble_staged(journal, over_budget, {1048577}), ErrorKind::kBadField,
               "staged_plan.sharing_budget", "excessive lookup allocation is refused before I/O");
    TEST_CHECK(over_budget.bytes.empty());

    MemoryFile unused_data, unused_log;
    auto unused_made = StagingJournal::create(unused_data, unused_log, key(99));
    TEST_OK(unused_made, "unused-descriptor journal");
    if (unused_made.ok()) {
        auto unused = unused_made.take();
        auto unreferenced = plan;
        unreferenced.blocks.push_back({{3, 2, 1}});
        TEST_OK(stage_plan(unused, key(1), StagedOutcome::kConverted, unreferenced, {}),
                "stage an unreferenced descriptor");
        MemoryFile refused;
        TEST_ERROR(assemble_staged(unused, refused), ErrorKind::kBadField, "writer.store.c_ref",
                   "sharing cannot silently drop an unreferenced staged block");
        TEST_CHECK(refused.bytes.empty());
    }

    MemoryFile many_data, many_log;
    auto many_made = StagingJournal::create(many_data, many_log, key(99));
    TEST_OK(many_made, "reference-limit journal");
    if (!many_made.ok())
        return;
    auto many = many_made.take();
    plan.blocks.resize(1);
    plan.nodes[0].data_blocks.assign(UINT16_MAX, 0);
    TEST_OK(stage_plan(many, key(1), StagedOutcome::kConverted, plan, {}),
            "reference-limit fixture");
    MemoryFile output;
    StagedAssemblyStats stats;
    auto result = assemble_staged(many, output, {1}, &stats);
    TEST_OK(result, "shared references spill to a new physical block before cRef overflow");
    TEST_EQ(stats.stored_blocks, 2u, "one extra copy handles the reference limit");
    if (result.ok()) {
        TEST_EQ(result.value().blocks[0].c_ref, UINT16_MAX, "first copy fills the valid count");
        TEST_EQ(result.value().blocks[1].c_ref, 2u, "remaining reference owns another copy");
    }
}

void check_bad_metadata() {
    MemoryFile data, log;
    auto made = StagingJournal::create(data, log, key(99));
    TEST_OK(made, "metadata journal");
    if (!made.ok())
        return;
    auto journal = made.take();
    TEST_OK(stage_plan(journal, key(1), StagedOutcome::kConverted, item_plan(), {}),
            "stage parser fixture");
    const auto saved = data.bytes;
    // Mutate the fake file only to reach parser validation. Real resume additionally refuses
    // any digest mismatch before these bytes can be used or an uncommitted suffix truncated.
    data.bytes[8] = 2;
    TEST_ERROR(read_staged_plan(journal, 0), ErrorKind::kBadField, "staged_plan.version",
               "future private format");
    data.bytes = saved;
    data.bytes[12] = 0xFF;
    data.bytes[13] = 0xFF;
    data.bytes[14] = 0xFF;
    data.bytes[15] = 0x7F;
    TEST_ERROR(read_staged_plan(journal, 0), ErrorKind::kBadField, "staged_plan.length",
               "oversized metadata");
    data.bytes = saved;
    data.bytes[28] = 0;
    data.bytes[29] = 0;
    TEST_ERROR(read_staged_plan(journal, 0), ErrorKind::kBadField, "staged_plan.external_size",
               "zero raw block length");
    data.bytes = saved;
    // Header + block count + three sizes + node count + parent + NID + slot count.
    const size_t slot = 24 + 4 + 6 + 4 + 4 + 4 + 4;
    data.bytes[slot] = 9;
    TEST_ERROR(read_staged_plan(journal, 0), ErrorKind::kBadField, "staged_plan.block_slot",
               "out-of-range relocation");
    auto recovered = StagingJournal::recover(data, log, key(99));
    TEST_CHECK(!recovered.ok());
    TEST_EQ(data.bytes[slot], 9u, "corrupt committed evidence preserved");
}

void check_streamed_payload_failure() {
    MemoryFile data, log;
    auto made = StagingJournal::create(data, log, key(99));
    TEST_OK(made, "streamed payload journal");
    if (!made.ok())
        return;
    auto journal = made.take();
    const auto resident = item_plan();
    TEST_OK(stage_plan(journal, key(1), StagedOutcome::kConverted, resident, {}),
            "baseline committed range");
    const auto committed_size = data.size();
    auto scratch = std::make_shared<MemoryFile>();
    ValueSpool spool(scratch, 0, 0);
    auto captured = spool.capture([&](const ByteConsumer& consume) {
        return consume(ByteView(resident.blocks[1].bytes.data(), resident.blocks[1].bytes.size()));
    });
    TEST_OK(captured, "owned external payload range");
    if (!captured.ok())
        return;
    auto streamed = resident;
    streamed.blocks[1].bytes.clear();
    streamed.blocks[1].source = captured.value().source;
    streamed.blocks[1].source_size = 8176;
    scratch->fail_read = true;
    TEST_ERROR(stage_plan(journal, key(2), StagedOutcome::kConverted, streamed, {}), ErrorKind::kIo,
               "test.read", "post-metadata source read is fatal");
    TEST_EQ(journal.records().size(), 1u, "prefix is not committed");
    TEST_CHECK(data.size() > committed_size);
    auto recovered = StagingJournal::recover(data, log, key(99));
    TEST_OK(recovered, "recover uncommitted source-read suffix");
    TEST_EQ(data.size(), committed_size, "only uncommitted prefix is removed");
    scratch->fail_read = false;
    if (recovered.ok()) {
        auto resumed = recovered.take();
        TEST_OK(stage_plan(resumed, key(2), StagedOutcome::kConverted, streamed, {}),
                "retry validated owned source");
        TEST_CHECK(resumed.records()[0].digest == resumed.records()[1].digest);
    }
    TEST_CHECK(scratch->max_read <= 8192);
}

void check_more_than_one_million_blocks() {
    MemoryFile data, log;
    auto made = StagingJournal::create(data, log, key(99));
    TEST_OK(made, "large descriptor journal");
    if (!made.ok())
        return;
    auto journal = made.take();
    constexpr uint64_t batch = 100001, batches = 11;
    for (uint64_t record = 0; record < batches; ++record) {
        StorePlan plan;
        plan.nodes.push_back({static_cast<uint32_t>(0x200004 + record * 32), 0, {}, {}});
        if (record == 0)
            plan.rgnid.resize(32);
        for (uint64_t slot = 0; slot < batch; ++slot) {
            const uint64_t identity = record * batch + slot;
            std::vector<uint8_t> bytes(8);
            for (size_t i = 0; i < bytes.size(); ++i)
                bytes[i] = static_cast<uint8_t>(identity >> (i * 8));
            plan.blocks.push_back({std::move(bytes)});
            plan.nodes[0].data_blocks.push_back(slot);
        }
        TEST_OK(stage_plan(journal, key(static_cast<uint8_t>(record)), StagedOutcome::kConverted,
                           plan, {}),
                "stage descriptor batch");
    }
    // Exercise both paths: sharing saturation must not restore the old aggregate ceiling.
    for (uint32_t sharing : {0u, 1u}) {
        MemoryFile output;
        StagedAssemblyStats stats;
        auto result = assemble_staged(journal, output, {sharing}, &stats);
        TEST_OK(result, "assemble over one million physical blocks");
        if (!result.ok())
            continue;
        TEST_EQ(stats.stored_blocks, batch * batches, "all distinct payloads retained");
        const auto& blocks = result.value().blocks;
        TEST_CHECK(blocks.size() > batch * batches); // X/XXBLOCKs also consume capacity.
        for (uint64_t slot : {uint64_t{0}, uint64_t{999999}, batch * batches - 1}) {
            const auto& block = blocks[static_cast<size_t>(slot)];
            TEST_EQ(ByteView(output.bytes.data(), output.bytes.size()).u64(block.ib).value(), slot,
                    "payload beyond old boundary is written without truncation");
            TEST_EQ(block.c_ref, 2u, "BBT plus exactly one tree reference");
        }
    }
}
} // namespace

int main() {
    check_more_than_one_million_blocks();
    check_shared_assembly();
    check_sharing_collision_budget_and_ref_limit();
    check_roundtrip_and_assembly();
    check_validation_and_io();
    check_bad_metadata();
    check_streamed_payload_failure();
    return ost2pst::test::finish("writer_staged_plan_test");
}
