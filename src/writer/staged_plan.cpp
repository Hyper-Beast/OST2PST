#include "ost2pst/writer/staged_plan.h"

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <utility>

#include "ost2pst/ndb/layout.h"
#include "ost2pst/util/crc32.h"

#include "internal/block_index.h"

namespace ost2pst::writer {
namespace {
using util::ByteView;
using util::ErrorKind;
using util::make_error;
using util::Result;
using util::Status;

// Converter-private framing and engineering budgets, unrelated to source-format layouts.
constexpr uint64_t kHeaderBytes = 24;
constexpr uint64_t kMetadataBytes = 32ull * 1024 * 1024;
constexpr uint64_t kAssemblyMetadataBytes = 1024ull * 1024 * 1024;
constexpr uint32_t kObjects = 1000000;
constexpr uint32_t kDepth = 64;
constexpr std::array<uint8_t, 8> kMagic{'O', 'S', 'T', 'P', 'L', 'A', 'N', '1'};

Status invalid(const char* field, uint64_t value, const char* detail) {
    return make_error(ErrorKind::kBadField, field, 0, value, detail);
}

class Encoder {
  public:
    std::vector<uint8_t> bytes;
    Status status;
    void number(uint64_t value, size_t width) {
        if (!space(width))
            return;
        for (size_t byte = 0; byte < width; ++byte)
            bytes.push_back(static_cast<uint8_t>(value >> (byte * 8)));
    }
    void blob(const uint8_t* data, size_t size) {
        if (size > std::numeric_limits<uint32_t>::max()) {
            status =
                invalid("staged_plan.blob", size, "byte string exceeds the private length field");
            return;
        }
        if (!space(size + 4))
            return;
        number(size, 4);
        if (size != 0)
            bytes.insert(bytes.end(), data, data + size);
    }
    void string(const std::string& text) {
        blob(reinterpret_cast<const uint8_t*>(text.data()), text.size());
    }
    void blob(const util::ByteSource& source) {
        const auto size = source.size();
        if (size > kMetadataBytes) {
            status = invalid("staged_plan.metadata_budget", size,
                             "streamed row exceeds the metadata budget");
            return;
        }
        if (!space(static_cast<size_t>(size) + 4))
            return;
        number(size, 4);
        const auto start = bytes.size();
        bytes.resize(start + static_cast<size_t>(size));
        // The metadata itself has a fixed engineering bound; the backing read still
        // uses bounded windows and never collects a second value-sized vector.
        for (uint64_t offset = 0; offset < size; offset += 8192) {
            const auto chunk = static_cast<size_t>(std::min<uint64_t>(8192, size - offset));
            auto read =
                source.read_at(offset, bytes.data() + start + static_cast<size_t>(offset), chunk);
            if (!read.ok()) {
                status = read;
                return;
            }
        }
    }

  private:
    bool space(size_t count) {
        if (!status.ok())
            return false;
        if (count > kMetadataBytes - bytes.size()) {
            status = invalid("staged_plan.metadata_budget", count,
                             "metadata exceeds its bounded record budget");
            return false;
        }
        return true;
    }
};

class Decoder {
  public:
    explicit Decoder(ByteView bytes) : bytes_(bytes) {}
    Status status;
    uint64_t number(size_t width) {
        if (!status.ok())
            return 0;
        if (!bytes_.in_range(at_, width)) {
            status = invalid("staged_plan.truncated", at_, "metadata field is truncated");
            return 0;
        }
        uint64_t result = 0;
        for (size_t byte = 0; byte < width; ++byte)
            result |= uint64_t{bytes_.data()[at_++]} << (byte * 8);
        return result;
    }
    uint32_t count(uint32_t limit = kObjects) {
        const auto result = static_cast<uint32_t>(number(4));
        if (result > limit) {
            status = invalid("staged_plan.count", result, "metadata collection exceeds its budget");
            return 0;
        }
        return result;
    }
    std::vector<uint8_t> blob() {
        const uint32_t size = count(static_cast<uint32_t>(kMetadataBytes));
        if (!status.ok())
            return {};
        if (size == 0)
            return {};
        if (!bytes_.in_range(at_, size)) {
            status = invalid("staged_plan.blob", size, "metadata byte string is truncated");
            return {};
        }
        std::vector<uint8_t> result(bytes_.data() + at_, bytes_.data() + at_ + size);
        at_ += size;
        return result;
    }
    std::string string() {
        auto bytes = blob();
        return std::string(bytes.begin(), bytes.end());
    }
    bool finished() const { return status.ok() && at_ == bytes_.size(); }

  private:
    ByteView bytes_;
    size_t at_ = 0;
};

template <class Node>
Status encode_node(Encoder& encoded, const Node& node, uint64_t block_count, uint32_t depth,
                   uint32_t& objects) {
    if (depth > kDepth || ++objects > kObjects || node.data_blocks.size() > kObjects ||
        node.subnodes.size() > kObjects) {
        return invalid("staged_plan.node_budget", depth, "node graph exceeds its record budget");
    }
    encoded.number(node.nid, 4);
    encoded.number(node.data_blocks.size(), 4);
    for (const auto slot : node.data_blocks) {
        if (slot >= block_count)
            return invalid("staged_plan.block_slot", slot, "local block slot is out of range");
        encoded.number(slot, 8);
    }
    encoded.number(node.subnodes.size(), 4);
    std::set<uint32_t> seen;
    for (const auto& child : node.subnodes) {
        if (!seen.insert(child.nid).second)
            return invalid("staged_plan.subnode", child.nid, "duplicate local NID");
        auto result = encode_node(encoded, child, block_count, depth + 1, objects);
        if (!result.ok())
            return result;
    }
    return encoded.status;
}

template <class Node>
void decode_node(Decoder& decoded, Node& node, uint64_t block_count, uint32_t depth,
                 uint32_t& objects) {
    if (!decoded.status.ok())
        return;
    if (depth > kDepth || ++objects > kObjects) {
        decoded.status =
            invalid("staged_plan.node_budget", depth, "node graph exceeds its record budget");
        return;
    }
    node.nid = static_cast<uint32_t>(decoded.number(4));
    const uint32_t blocks = decoded.count();
    for (uint32_t index = 0; index < blocks && decoded.status.ok(); ++index) {
        const auto slot = decoded.number(8);
        if (slot >= block_count) {
            decoded.status =
                invalid("staged_plan.block_slot", slot, "local block slot is out of range");
            return;
        }
        node.data_blocks.push_back(slot);
    }
    const uint32_t children = decoded.count();
    std::set<uint32_t> seen;
    for (uint32_t index = 0; index < children && decoded.status.ok(); ++index) {
        StoreSubnode child;
        decode_node(decoded, child, block_count, depth + 1, objects);
        if (!seen.insert(child.nid).second) {
            decoded.status = invalid("staged_plan.subnode", child.nid, "duplicate local NID");
            return;
        }
        node.subnodes.push_back(std::move(child));
    }
}

template <class Node> void relocate(Node& node, uint64_t base) {
    for (auto& block : node.data_blocks)
        block += base;
    for (auto& child : node.subnodes)
        relocate(child, base);
}

class JournalBlocks final : public StoreBlockSource {
  public:
    explicit JournalBlocks(const StagingJournal& journal) : journal_(journal) {}
    BlockIndex<StagedBlockRef> refs;
    uint64_t count() const override { return refs.size(); }
    Result<uint16_t> block_size(uint64_t index) const override {
        if (index >= refs.size())
            return invalid("staged_plan.block", index, "block index is out of range").error();
        return refs[static_cast<size_t>(index)].size;
    }
    Status read_block(uint64_t index, uint8_t* data, size_t size) const override {
        if (index >= refs.size())
            return invalid("staged_plan.block", index, "block index is out of range");
        const auto& ref = refs[static_cast<size_t>(index)];
        if (size != ref.size)
            return invalid("staged_plan.block_size", size,
                           "read must match the external block size");
        return journal_.read_committed(ref.record, ref.offset, data, size);
    }

  private:
    const StagingJournal& journal_;
};

// A bounded fingerprint index over staged bytes. CRC only selects candidates; byte equality
// is authoritative, including for equal-length CRC collisions. Payloads stay in the journal.
class SharingIndex {
  public:
    SharingIndex(const StagingJournal& journal, JournalBlocks& blocks, uint32_t capacity)
        : journal_(journal), blocks_(blocks), capacity_(capacity), heads_(capacity, kEnd) {
        entries_.reserve(capacity);
    }

    template <class Node>
    Status relocate_shared(Node& node, const std::vector<StagedBlockRef>& refs,
                           std::vector<bool>& used) {
        for (auto& slot : node.data_blocks) {
            if (slot >= refs.size())
                return invalid("staged_plan.block_slot", slot, "local block slot is out of range");
            used[static_cast<size_t>(slot)] = true;
            auto shared = select(refs[static_cast<size_t>(slot)]);
            if (!shared.ok())
                return shared.error();
            slot = shared.value();
        }
        for (auto& child : node.subnodes) {
            auto status = relocate_shared(child, refs, used);
            if (!status.ok())
                return status;
        }
        return {};
    }

    StagedAssemblyStats stats;

  private:
    static constexpr uint32_t kEnd = UINT32_MAX;
    struct Entry {
        uint64_t slot;
        uint32_t fingerprint;
        uint32_t next;
        uint16_t size;
        uint16_t references;
    };
    static_assert(sizeof(Entry) <= 32);

    Result<uint64_t> append(const StagedBlockRef& ref) {
        if (blocks_.refs.size() >= kStoreMaxBlocks)
            return make_error(ErrorKind::kUnsupported, "staged_plan.assembly_count", 0,
                              blocks_.refs.size(),
                              "physical block descriptors exceed the assembly capacity");
        const auto slot = blocks_.refs.size();
        blocks_.refs.push_back(ref);
        ++stats.stored_blocks;
        return slot;
    }

    Result<uint64_t> select(const StagedBlockRef& ref) {
        ++stats.block_references;
        auto read = journal_.read_committed(ref.record, ref.offset, bytes_.data(), ref.size);
        if (!read.ok())
            return read.error();
        const auto fingerprint = util::crc32(ByteView(bytes_.data(), ref.size));
        const auto bucket = fingerprint % heads_.size();
        for (uint32_t index = heads_[bucket]; index != kEnd; index = entries_[index].next) {
            auto& entry = entries_[index];
            if (entry.fingerprint != fingerprint || entry.size != ref.size)
                continue;
            read = blocks_.read_block(entry.slot, other_.data(), ref.size);
            if (!read.ok())
                return read.error();
            if (!std::equal(bytes_.begin(), bytes_.begin() + ref.size, other_.begin()))
                continue;
            // MS-PST 2.2.2.7.7.3.1: cRef includes the BBT entry as well as every
            // NBT/SLENTRY/XBLOCK reference. Start another physical copy before uint16_t fills.
            if (entry.references < UINT16_MAX - 1) {
                ++entry.references;
                ++stats.shared_references;
                stats.avoided_payload_bytes += ref.size;
                return entry.slot;
            }
            auto next = append(ref);
            if (!next.ok())
                return next.error();
            entry.slot = next.value();
            entry.references = 1;
            return entry.slot;
        }
        auto next = append(ref);
        if (!next.ok())
            return next.error();
        if (entries_.size() < capacity_) {
            const auto index = static_cast<uint32_t>(entries_.size());
            entries_.push_back({next.value(), fingerprint, heads_[bucket], ref.size, 1});
            heads_[bucket] = index;
            stats.index_entries = entries_.size();
        } else {
            stats.index_saturated = true;
        }
        return next.value();
    }

    const StagingJournal& journal_;
    JournalBlocks& blocks_;
    uint32_t capacity_;
    std::vector<uint32_t> heads_;
    std::vector<Entry> entries_;
    std::array<uint8_t, ndb::kPstBlockMaxCb> bytes_{}, other_{};
};
} // namespace

Status stage_plan(StagingJournal& journal, const util::Sha256Digest& key, StagedOutcome outcome,
                  const StorePlan& plan, const StagedDetails& details,
                  const CommitObserver& observer) {
    if (plan.blocks.size() > kObjects || plan.nodes.size() > kObjects ||
        (!plan.rgnid.empty() && plan.rgnid.size() != ndb::kRgnidCount) ||
        details.counters.size() > 1024) {
        return invalid("staged_plan.shape", plan.blocks.size(),
                       "plan exceeds its collection bounds");
    }
    if (outcome != StagedOutcome::kConverted && (!plan.blocks.empty() || !plan.nodes.empty() ||
                                                 !plan.rgnid.empty() || details.row.has_value())) {
        return invalid("staged_plan.outcome", static_cast<uint32_t>(outcome),
                       "failed/excluded outcome cannot carry content");
    }
    Encoder encoded;
    encoded.number(plan.blocks.size(), 4);
    uint64_t payload = 0;
    for (const auto& block : plan.blocks) {
        if (block.size() == 0 || block.size() > ndb::block_max_cb(ndb::FileProfile::kPst) ||
            (block.source && (!block.bytes.empty() || block.source_offset > block.source->size() ||
                              block.size() > block.source->size() - block.source_offset))) {
            return invalid("staged_plan.external_size", block.size(),
                           "external block has invalid raw length");
        }
        encoded.number(block.size(), 2);
        payload += block.size();
    }
    encoded.number(plan.nodes.size(), 4);
    uint32_t objects = 0;
    std::set<uint32_t> seen;
    for (const auto& node : plan.nodes) {
        if (!seen.insert(node.nid).second)
            return invalid("staged_plan.node", node.nid, "duplicate top-level NID");
        encoded.number(node.nid_parent, 4);
        auto result = encode_node(encoded, node, plan.blocks.size(), 0, objects);
        if (!result.ok())
            return result;
    }
    encoded.number(plan.rgnid.size(), 4);
    for (const auto index : plan.rgnid)
        encoded.number(index, 4);
    encoded.number(details.row.has_value() ? 1 : 0, 4);
    if (details.row.has_value()) {
        const auto& row = *details.row;
        if (row.values.size() > 255 ||
            (!row.sources.empty() && row.sources.size() != row.values.size()) ||
            (!row.present_empty.empty() && row.present_empty.size() != row.values.size())) {
            return invalid("staged_plan.row", row.values.size(),
                           "row columns/presence flags disagree");
        }
        encoded.number(row.row_id, 4);
        encoded.number(row.values.size(), 4);
        for (size_t index = 0; index < row.values.size(); ++index) {
            if (!row.sources.empty() && row.sources[index]) {
                if (!row.values[index].empty())
                    return invalid("staged_plan.row_source", index,
                                   "cell has both bytes and a source");
                encoded.blob(*row.sources[index]);
            } else {
                encoded.blob(row.values[index].data(), row.values[index].size());
            }
            encoded.number(!row.present_empty.empty() && row.present_empty[index] ? 1 : 0, 1);
        }
    }
    encoded.number(details.counters.size(), 4);
    for (const auto& [name, value] : details.counters) {
        if (name.empty() || name.size() > 128)
            return invalid("staged_plan.counter", name.size(), "invalid counter name length");
        encoded.string(name);
        encoded.number(value, 8);
    }
    encoded.string(details.json);
    if (!encoded.status.ok())
        return encoded.status;
    Encoder header;
    header.bytes.assign(kMagic.begin(), kMagic.end());
    header.number(1, 4);
    header.number(encoded.bytes.size(), 4);
    header.number(payload, 8);
    auto status = journal.begin(key, outcome);
    if (!status.ok())
        return status;
    status = journal.append(ByteView(header.bytes.data(), header.bytes.size(), 0));
    if (!status.ok())
        return status;
    status = journal.append(ByteView(encoded.bytes.data(), encoded.bytes.size(), 0));
    if (!status.ok())
        return status;
    std::array<uint8_t, ndb::kPstBlockMaxCb> buffer{};
    for (const auto& block : plan.blocks) {
        if (block.source) {
            status = block.source->read_at(block.source_offset, buffer.data(), block.source_size);
            if (!status.ok())
                return status;
            status = journal.append(ByteView(buffer.data(), block.source_size, 0));
        } else {
            status = journal.append(ByteView(block.bytes.data(), block.bytes.size(), 0));
        }
        if (!status.ok())
            return status;
    }
    return journal.commit(observer);
}

Result<StagedPlan> read_staged_plan(const StagingJournal& journal, size_t record) {
    if (record >= journal.records().size())
        return invalid("staged_plan.record", record, "record does not exist").error();
    std::array<uint8_t, kHeaderBytes> header{};
    auto status = journal.read_committed(record, 0, header.data(), header.size());
    if (!status.ok())
        return status.error();
    if (!std::equal(kMagic.begin(), kMagic.end(), header.begin())) {
        return invalid("staged_plan.magic", record, "unknown staged plan magic").error();
    }
    ByteView view(header.data(), header.size(), 0);
    if (view.u32(8).value() != 1)
        return invalid("staged_plan.version", record, "unsupported plan version").error();
    const uint64_t metadata_size = view.u32(12).value();
    const uint64_t payload = view.u64(16).value();
    const uint64_t length = journal.records()[record].length;
    if (metadata_size > kMetadataBytes || length < kHeaderBytes + metadata_size ||
        payload != length - kHeaderBytes - metadata_size) {
        return invalid("staged_plan.length", record, "record frame and committed length disagree")
            .error();
    }
    std::vector<uint8_t> bytes(static_cast<size_t>(metadata_size));
    status = journal.read_committed(record, kHeaderBytes, bytes.data(), bytes.size());
    if (!status.ok())
        return status.error();
    Decoder decoded(ByteView(bytes.data(), bytes.size(), 0));
    StagedPlan result;
    const uint32_t block_count = decoded.count();
    uint64_t offset = kHeaderBytes + metadata_size;
    for (uint32_t index = 0; index < block_count && decoded.status.ok(); ++index) {
        const auto size = static_cast<uint16_t>(decoded.number(2));
        if (size == 0 || size > ndb::block_max_cb(ndb::FileProfile::kPst) ||
            size > length - offset) {
            return invalid("staged_plan.external_size", size,
                           "block descriptor exceeds committed payload")
                .error();
        }
        result.blocks.push_back({record, offset, size});
        offset += size;
    }
    if (offset != length)
        return invalid("staged_plan.payload", record,
                       "block sizes do not cover the committed payload")
            .error();
    const uint32_t node_count = decoded.count();
    uint32_t objects = 0;
    std::set<uint32_t> seen;
    for (uint32_t index = 0; index < node_count && decoded.status.ok(); ++index) {
        StoreNode node;
        node.nid_parent = static_cast<uint32_t>(decoded.number(4));
        decode_node(decoded, node, block_count, 0, objects);
        if (!seen.insert(node.nid).second)
            return invalid("staged_plan.node", node.nid, "duplicate top-level NID").error();
        result.nodes.push_back(std::move(node));
    }
    const uint32_t rgnid_count = decoded.count(ndb::kRgnidCount);
    if (rgnid_count != 0 && rgnid_count != ndb::kRgnidCount) {
        return invalid("staged_plan.rgnid", rgnid_count,
                       "allocation counter list has the wrong length")
            .error();
    }
    for (uint32_t index = 0; index < rgnid_count; ++index)
        result.rgnid.push_back(static_cast<uint32_t>(decoded.number(4)));
    const uint32_t has_row = decoded.count(1);
    if (has_row != 0) {
        TcRow row;
        row.row_id = static_cast<uint32_t>(decoded.number(4));
        const uint32_t cells = decoded.count(255);
        for (uint32_t index = 0; index < cells && decoded.status.ok(); ++index) {
            row.values.push_back(decoded.blob());
            const auto empty = decoded.number(1);
            if (empty > 1)
                return invalid("staged_plan.present_empty", empty, "presence flag is not boolean")
                    .error();
            row.present_empty.push_back(empty != 0);
        }
        result.details.row = std::move(row);
    }
    const uint32_t counters = decoded.count(1024);
    for (uint32_t index = 0; index < counters && decoded.status.ok(); ++index) {
        auto name = decoded.string();
        const auto value = decoded.number(8);
        if (name.empty() || name.size() > 128 ||
            !result.details.counters.emplace(name, value).second) {
            return invalid("staged_plan.counter", index,
                           "counter is duplicated or has an invalid name")
                .error();
        }
    }
    result.details.json = decoded.string();
    if (!decoded.status.ok())
        return decoded.status.error();
    if (!decoded.finished())
        return invalid("staged_plan.trailing", record, "unexpected metadata suffix").error();
    if (journal.records()[record].outcome != StagedOutcome::kConverted &&
        (!result.blocks.empty() || !result.nodes.empty() || !result.rgnid.empty() ||
         result.details.row.has_value())) {
        return invalid("staged_plan.outcome", record, "failed/excluded outcome contains content")
            .error();
    }
    return result;
}

Result<TcRow> StagedRows::read(uint64_t index) const {
    if (index >= records_.size()) {
        return invalid("staged_plan.row_index", index, "no committed row at this index").error();
    }
    auto loaded = read_staged_plan(journal_, records_[static_cast<size_t>(index)]);
    if (!loaded.ok())
        return loaded.error();
    StagedPlan plan = loaded.take();
    if (!plan.details.row || plan.nodes.size() != 1 ||
        plan.nodes[0].nid != plan.details.row->row_id) {
        return invalid("staged_plan.item_row", index,
                       "committed contents row does not name its single top-level item")
            .error();
    }
    return std::move(*plan.details.row);
}

Result<StoreImage> assemble_staged(const StagingJournal& journal, util::RandomAccessFile& output,
                                   const StagedAssemblyOptions& options,
                                   StagedAssemblyStats* stats) {
    if (stats)
        *stats = {};
    // Engineering limit: at most 36 MiB for index entries/buckets, plus two block windows.
    if (options.sharing_entries > 1048576)
        return invalid("staged_plan.sharing_budget", options.sharing_entries,
                       "sharing index exceeds its fixed memory budget")
            .error();
    JournalBlocks blocks(journal);
    std::optional<SharingIndex> sharing;
    if (options.sharing_entries)
        sharing.emplace(journal, blocks, options.sharing_entries);
    std::vector<StoreNode> nodes;
    std::vector<uint32_t> rgnid;
    uint64_t metadata_total = 0;
    for (size_t index = 0; index < journal.records().size(); ++index) {
        // Check encoded metadata volume before decoding an additional graph. In-memory graph
        // expansion is separately bounded by the object/block capacities of write_store_to.
        std::array<uint8_t, kHeaderBytes> header{};
        auto read = journal.read_committed(index, 0, header.data(), header.size());
        if (!read.ok())
            return read.error();
        const uint64_t size = ByteView(header.data(), header.size(), 0).u32(12).value();
        if (size > kAssemblyMetadataBytes - metadata_total) {
            return make_error(ErrorKind::kUnsupported, "staged_plan.assembly_budget", 0, size,
                              "aggregate descriptors exceed the assembly budget");
        }
        metadata_total += size;
        auto loaded = read_staged_plan(journal, index);
        if (!loaded.ok())
            return loaded.error();
        StagedPlan plan = loaded.take();
        if ((!sharing && blocks.refs.size() + plan.blocks.size() > kStoreMaxBlocks) ||
            nodes.size() + plan.nodes.size() > kStoreMaxNodes) {
            return make_error(ErrorKind::kUnsupported, "staged_plan.assembly_count", 0, index,
                              "aggregate plan exceeds the writer metadata capacity");
        }
        const uint64_t base = blocks.refs.size();
        std::vector<bool> used(sharing ? plan.blocks.size() : 0, false);
        for (auto& node : plan.nodes) {
            if (sharing) {
                auto status = sharing->relocate_shared(node, plan.blocks, used);
                if (!status.ok())
                    return status.error();
            } else {
                relocate(node, base);
            }
            nodes.push_back(std::move(node));
        }
        if (sharing) {
            if (std::find(used.begin(), used.end(), false) != used.end())
                return invalid("writer.store.c_ref", index, "staged block has no references")
                    .error();
        } else {
            for (const auto& ref : plan.blocks)
                blocks.refs.push_back(ref);
        }
        if (!plan.rgnid.empty()) {
            if (!rgnid.empty())
                return invalid("staged_plan.scaffold", index, "more than one scaffold record")
                    .error();
            rgnid = std::move(plan.rgnid);
        }
    }
    if (rgnid.empty())
        return invalid("staged_plan.scaffold", 0,
                       "no committed scaffold supplies allocation counters")
            .error();
    StagedAssemblyStats completed;
    if (sharing)
        completed = sharing->stats;
    else
        completed.stored_blocks = blocks.count();
    sharing.reset(); // Do not retain the lookup index during writer layout and publication.
    auto result = write_store_to(blocks, nodes, rgnid, output);
    if (result.ok() && stats)
        *stats = completed;
    return result;
}

} // namespace ost2pst::writer
