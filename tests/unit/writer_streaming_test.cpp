#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "ost2pst/ndb/layout.h"
#include "ost2pst/util/crc32.h"
#include "ost2pst/util/sig.h"
#include "ost2pst/writer/store.h"

#include "test_support.h"

namespace {
using namespace ost2pst::util;
using namespace ost2pst::writer;
namespace ndb = ost2pst::ndb;

class GeneratedBlocks final : public StoreBlockSource {
  public:
    uint64_t total = 4;
    uint16_t length = 8176;
    bool fail_size = false, fail_read = false;
    mutable size_t largest_read = 0;
    uint64_t count() const override { return total; }
    Result<uint16_t> block_size(uint64_t index) const override {
        if (fail_size)
            return make_error(ErrorKind::kIo, "injected.size", index);
        return length;
    }
    Status read_block(uint64_t index, uint8_t* data, size_t size) const override {
        if (fail_read)
            return make_error(ErrorKind::kIo, "injected.source_read", index);
        TEST_CHECK(index < total);
        TEST_EQ(size, length, "one external block per read");
        largest_read = std::max(largest_read, size);
        std::fill_n(data, size, static_cast<uint8_t>(index % 251));
        return {};
    }
};

class Sink final : public RandomAccessFile {
  public:
    bool materialize = true, fail_flush = false, capture_maps = true;
    bool fail_free_map = false;
    size_t fail_write = 0, writes = 0, flushes = 0, largest_write = 0;
    uint64_t eof = 0, high_offset = 0;
    std::vector<uint8_t> bytes, high_block;
    std::map<uint64_t, std::vector<uint8_t>> fixed_maps;
    std::array<uint8_t, ndb::kHeaderSize> header{};
    uint64_t size() const override { return eof; }
    Status read_at(uint64_t at, uint8_t* data, size_t count) const override {
        if (!materialize || at > bytes.size() || count > bytes.size() - at)
            return make_error(ErrorKind::kTruncated, "test.read", at, count);
        if (count)
            std::memcpy(data, bytes.data() + at, count);
        return {};
    }
    Result<size_t> write_some(uint64_t at, ByteView input) override {
        if (++writes == fail_write)
            return make_error(ErrorKind::kIo, "injected.write", at);
        if (input.size() == ndb::kPstPageSize &&
            (input.data()[496] == ndb::kPageTypeAMap || input.data()[496] == ndb::kPageTypePMap ||
             input.data()[496] == ndb::kPageTypeFMap || input.data()[496] == ndb::kPageTypeFPMap)) {
            if (fail_free_map && (input.data()[496] == ndb::kPageTypeFMap ||
                                  input.data()[496] == ndb::kPageTypeFPMap))
                return make_error(ErrorKind::kIo, "injected.free_map_write", at);
            if (capture_maps)
                fixed_maps[at] = std::vector<uint8_t>(input.data(), input.data() + input.size());
        }
        largest_write = std::max(largest_write, input.size());
        eof = std::max(eof, at + input.size());
        if (materialize) {
            bytes.resize(static_cast<size_t>(eof));
            std::memcpy(bytes.data() + at, input.data(), input.size());
        }
        if (at == 0 && input.size() == header.size())
            std::copy_n(input.data(), input.size(), header.begin());
        // [MS-PST] 2.2.2.8.1: full Unicode blocks end in the 16-byte BLOCKTRAILER.
        if (at > 0x80000000ull && input.size() == 8192 &&
            !ndb::bid_is_internal(input.u64(8176 + ndb::kBlockTrailerBidOffset).value())) {
            high_offset = at;
            high_block.assign(input.data(), input.data() + input.size());
        }
        return input.size();
    }
    Status resize(uint64_t size) override {
        eof = size;
        if (materialize)
            bytes.resize(static_cast<size_t>(size));
        return {};
    }
    Status flush() override {
        ++flushes;
        if (fail_flush)
            return make_error(ErrorKind::kIo, "injected.flush", 0);
        return {};
    }
};

std::vector<StoreNode> nodes_for(uint64_t count) {
    StoreNode root;
    root.nid = 0x122;
    for (uint64_t i = 0; i < count; ++i)
        root.data_blocks.push_back(i);
    return {std::move(root)};
}
std::vector<uint32_t> seeds() {
    return std::vector<uint32_t>(32, 1024);
}

void check_equivalence_and_errors() {
    GeneratedBlocks source;
    const auto nodes = nodes_for(source.total);
    Sink output;
    auto emitted = write_store_to(source, nodes, seeds(), output);
    TEST_OK(emitted, "stream a small synthetic plan");
    if (!emitted.ok())
        return;
    TEST_CHECK(emitted.value().bytes.empty());
    TEST_EQ(emitted.value().file_bytes, output.size(), "summary names physical EOF");
    TEST_EQ(output.flushes, 1u, "flush before returning success");
    StorePlan plan;
    plan.nodes = nodes;
    plan.rgnid = seeds();
    for (uint64_t i = 0; i < source.total; ++i)
        plan.blocks.push_back(
            StoreBlock{std::vector<uint8_t>(source.length, static_cast<uint8_t>(i))});
    auto legacy = write_store(plan);
    TEST_OK(legacy, "legacy buffer adapter");
    if (legacy.ok())
        TEST_CHECK(legacy.value().bytes == output.bytes);
    for (int fault = 0; fault < 5; ++fault) {
        GeneratedBlocks bad_source;
        Sink bad_output;
        if (fault == 0)
            bad_source.fail_size = true;
        if (fault == 1)
            bad_source.fail_read = true;
        if (fault == 2)
            bad_output.fail_write = 1;
        if (fault == 3)
            bad_output.fail_flush = true;
        if (fault == 4)
            bad_output.bytes = {42}, bad_output.eof = 1;
        auto failed = write_store_to(bad_source, nodes, seeds(), bad_output);
        TEST_CHECK(!failed.ok());
        if (fault == 0 || fault == 4)
            TEST_EQ(bad_output.writes, 0u, "refuse before mutation");
        if (fault == 4)
            TEST_CHECK(bad_output.bytes == std::vector<uint8_t>{42});
        if (fault < 3)
            TEST_EQ(bad_output.flushes, 0u, "failed assembly cannot report flush success");
    }
}

void check_large_offsets() {
    GeneratedBlocks source;
    source.total = 263000;
    Sink output;
    output.materialize = false;
    auto result = write_store_to(source, nodes_for(source.total), seeds(), output);
    TEST_OK(result, "stream beyond signed 32-bit offsets without payload retention");
    if (!result.ok())
        return;
    TEST_CHECK(result.value().bytes.empty());
    TEST_CHECK(output.size() > 0x80000000ull);
    TEST_EQ(result.value().file_bytes, output.size(), "large physical EOF");
    TEST_CHECK(output.largest_write <= 1024 * 1024);
    TEST_EQ(source.largest_read, 8176u, "large plan still reads one block at a time");
    ByteView h(output.header.data(), output.header.size());
    TEST_EQ(h.u64(ndb::kRootOffset + ndb::kRootIbFileEofOffset).value(), output.size(),
            "64-bit header EOF");
    TEST_EQ(h.u32(ndb::kDwCRCFullOffset).value(),
            crc32(ByteView(output.header.data() + ndb::kCrcFullStart, ndb::kCrcFullLength)),
            "header CRC");
    TEST_EQ(output.high_block.size(), 8192u, "captured a full block above 2 GiB");
    if (output.high_block.size() != 8192)
        return;
    ByteView block(output.high_block.data(), output.high_block.size());
    const auto bid = block.u64(8184).value();
    TEST_EQ(block.u16(8176).value(), 8176u, "external trailer size above 2 GiB");
    TEST_EQ(block.u16(8178).value(), compute_sig(output.high_offset, bid),
            "64-bit block signature");
    TEST_EQ(block.u32(8180).value(), crc32(ByteView(output.high_block.data(), 8176)), "block CRC");
    TEST_EQ(output.high_block.front(), (bid / 4 - 1) % 251, "high-offset payload source identity");
    // The 3.3 GB diagnostic scan requires the first FPMap at this exact offset.
    constexpr uint64_t first_fpmap = 0x7C004800;
    const auto found = output.fixed_maps.find(first_fpmap);
    TEST_CHECK(found != output.fixed_maps.end());
    if (found != output.fixed_maps.end()) {
        ByteView page(found->second.data(), found->second.size());
        TEST_EQ(page.u8(496).value(), ndb::kPageTypeFPMap, "FPMap type above 2 GB");
        TEST_EQ(page.u8(497).value(), ndb::kPageTypeFPMap, "FPMap repeated type");
        TEST_EQ(page.u16(498).value(), 0u, "FPMap signature");
        TEST_EQ(page.u64(504).value(), first_fpmap, "FPMap back pointer");
        TEST_EQ(page.u32(500).value(), crc32(ByteView(found->second.data(), 496)), "FPMap CRC");
        TEST_CHECK(std::all_of(found->second.begin(), found->second.begin() + 496,
                               [](uint8_t byte) { return byte == 0xFF; }));
    }
}

void check_free_map_boundary() {
    // [MS-PST] 1.3.2.7: initial FMap covers 128 AMaps. SCANPST 16.0.20430.20032
    // reports its first external page at 0x1F04800 on the M6 candidate; test that
    // exact observed boundary without depending on private mailbox contents.
    constexpr uint64_t first_fmap = 0x1F04800;
    GeneratedBlocks source;
    source.total = 4200;
    Sink output;
    output.materialize = false;
    auto result = write_store_to(source, nodes_for(source.total), seeds(), output);
    TEST_OK(result, "stream through the first external FMap boundary");
    if (!result.ok())
        return;
    TEST_CHECK(output.size() > first_fmap + ndb::kPstPageSize);
    TEST_EQ(output.fixed_maps.count(first_fmap), 1u, "first FMap page exists");
    for (const auto& block : result.value().blocks) {
        const auto footprint = ndb::align_allocation(ndb::FileProfile::kPst, block.cb + 16);
        TEST_CHECK(block.ib + footprint <= first_fmap ||
                   block.ib >= first_fmap + ndb::kPstPageSize);
    }
    const auto found = output.fixed_maps.find(first_fmap);
    if (found != output.fixed_maps.end()) {
        ByteView page(found->second.data(), found->second.size());
        TEST_EQ(page.u8(496).value(), ndb::kPageTypeFMap, "FMap type");
        TEST_EQ(page.u8(497).value(), ndb::kPageTypeFMap, "FMap repeated type");
        TEST_EQ(page.u16(498).value(), 0u, "FMap signature");
        TEST_EQ(page.u64(504).value(), first_fmap, "FMap back pointer");
        TEST_EQ(page.u32(500).value(), crc32(ByteView(found->second.data(), 496)), "FMap CRC");
    }
    const auto amap = output.fixed_maps.find(first_fmap - 1024);
    TEST_CHECK(amap != output.fixed_maps.end());
    if (amap != output.fixed_maps.end())
        TEST_EQ(amap->second[2], 0xFFu, "FMap footprint allocated in its AMap");
    Sink failed;
    failed.materialize = false;
    failed.fail_free_map = true;
    auto refused = write_store_to(source, nodes_for(source.total), seeds(), failed);
    TEST_CHECK(!refused.ok());
    TEST_EQ(failed.flushes, 0u, "FMap write failure prevents final success");
}

void check_capacity_refusal() {
    GeneratedBlocks source;
    source.total = kStoreMaxBlocks + 1;
    Sink output;
    TEST_ERROR(write_store_to(source, nodes_for(1), seeds(), output), ErrorKind::kUnsupported,
               "writer.store.metadata_budget",
               "capacity refused without reading or allocating blocks");
    TEST_EQ(output.writes, 0u, "capacity failure leaves output untouched");
    TEST_EQ(source.largest_read, 0u, "capacity failure reads no payload");
}

void check_100_gib() {
    GeneratedBlocks source;
    constexpr uint64_t bytes = 100ull * 1024 * 1024 * 1024;
    source.total = (bytes + source.length - 1) / source.length;
    // Each node's stream remains below the existing 32-bit lcbTotal format boundary.
    std::vector<StoreNode> nodes;
    constexpr uint64_t batch = 500000;
    for (uint64_t first = 0; first < source.total; first += batch) {
        StoreNode node;
        node.nid = static_cast<uint32_t>(0x200004 + nodes.size() * 32);
        for (uint64_t slot = first; slot < std::min(source.total, first + batch); ++slot)
            node.data_blocks.push_back(slot);
        nodes.push_back(std::move(node));
    }
    Sink output;
    output.materialize = false;
    output.capture_maps = false;
    auto result = write_store_to(source, nodes, seeds(), output);
    TEST_OK(result, "write 100 GiB generated payload through real layout/CRC/trailer paths");
    if (!result.ok())
        return;
    TEST_CHECK(output.size() > bytes);
    TEST_CHECK(result.value().blocks.size() > source.total);
    const auto& last = result.value().blocks[static_cast<size_t>(source.total - 1)];
    TEST_EQ(output.high_offset, last.ib, "last external block is past 32-bit offset range");
    TEST_CHECK(last.ib > 0x100000000ull);
    ByteView trailer(output.high_block.data(), output.high_block.size());
    TEST_EQ(trailer.u64(8184).value(), last.bid, "last block trailer retains 64-bit BID");
    TEST_EQ(trailer.u16(8178).value(), compute_sig(last.ib, last.bid), "last block signature");
    TEST_EQ(trailer.u32(8180).value(), crc32(ByteView(output.high_block.data(), 8176)),
            "last block CRC");
    TEST_EQ(output.high_block.front(), (source.total - 1) % 251, "last generated payload retained");
    TEST_EQ(ByteView(output.header.data(), output.header.size())
                .u64(ndb::kRootOffset + ndb::kRootIbFileEofOffset)
                .value(),
            output.size(), "100 GiB EOF is preserved in header");
    TEST_EQ(output.flushes, 1u, "100 GiB write flushes before success");
    std::printf("100GiB generated sink: external=%llu total_blocks=%llu file_bytes=%llu\n",
                static_cast<unsigned long long>(source.total),
                static_cast<unsigned long long>(result.value().blocks.size()),
                static_cast<unsigned long long>(output.size()));
}
} // namespace

int main(int argc, char** argv) {
    check_equivalence_and_errors();
    check_free_map_boundary();
    check_capacity_refusal();
    if (argc == 2 && std::string(argv[1]) == "--large")
        check_large_offsets();
    if (argc == 2 && std::string(argv[1]) == "--100gib")
        check_100_gib();
    return ost2pst::test::finish("writer_streaming_test");
}
