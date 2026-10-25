#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>
#include <vector>

#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/ltp_read.h"
#include "ost2pst/ltp/node_open.h"
#include "ost2pst/ltp/pc.h"
#include "ost2pst/ltp/tc.h"
#include "ost2pst/msg/emit.h"
#include "ost2pst/msg/item_conversion.h"
#include "ost2pst/msg/mailbox.h"
#include "ost2pst/msg/subset.h"
#include "ost2pst/ndb/probe.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/writer/content.h"
#include "ost2pst/writer/empty_pst.h"
#include "ost2pst/writer/staged_plan.h"

#include "test_support.h"

namespace {
namespace writer = ost2pst::writer;
namespace ltp = ost2pst::ltp;
namespace msg = ost2pst::msg;
using ost2pst::util::ErrorKind;
using ost2pst::util::Result;

std::vector<uint8_t> u32(uint32_t value) {
    return {static_cast<uint8_t>(value), static_cast<uint8_t>(value >> 8),
            static_cast<uint8_t>(value >> 16), static_cast<uint8_t>(value >> 24)};
}
writer::ContentMessage message(uint32_t flags) {
    writer::ContentMessage result;
    result.properties = {{0x001A, 0x001F, {'I', 0, 'P', 0, 'M', 0}},
                         {0x0E07, 0x0003, u32(flags)},
                         {0x0E08, 0x0003, u32(50)},
                         {0x0E17, 0x0003, u32(0)},
                         {0x3007, 0x0040, std::vector<uint8_t>(8, 1)},
                         {0x3008, 0x0040, std::vector<uint8_t>(8, 2)},
                         {0x300B, 0x0102, {7, 8, 9}},
                         {0x1000, 0x001F, {'B', 0}},
                         {0x8000, 0x001F, {'V', 0}, false, true, 0}};
    result.recipients.columns = {{0x8000001F, true, 0}};
    result.properties.push_back(
        {0x1009, 0x0102, {12, 0, 0, 0, 1, 0, 0, 0, 'M', 'E', 'L', 'A', 0, 0, 0, 0}});
    result.recipients.rows = {{0, {{0x8000001F, {}, true}}}};
    return result;
}

class Rows final : public writer::TcRowSource {
  public:
    std::vector<writer::TcRow> values;
    bool fail = false;
    uint64_t count() const override { return values.size(); }
    Result<writer::TcRow> read(uint64_t index) const override {
        if (fail)
            return ost2pst::util::make_error(ErrorKind::kIo, "test.spool", index, 0, "read failed");
        return values.at(static_cast<size_t>(index));
    }
};

class FaultBlocks final : public ltp::BlockSource {
  public:
    explicit FaultBlocks(ltp::BlockSource& source) : source_(source) {}
    uint64_t failed_bid = 0;
    uint64_t replacement_bid = 0;
    std::vector<uint8_t> replacement;
    ErrorKind kind = ErrorKind::kBadCrc;
    Result<ltp::BlockBytes> block(uint64_t bid) override {
        if (bid == failed_bid)
            return ost2pst::util::make_error(kind, "test.source_block", bid, 0,
                                             "injected source read failure");
        auto result = source_.block(bid);
        if (result.ok() && bid == replacement_bid) {
            auto block = result.take();
            block.view =
                ost2pst::util::ByteView(replacement.data(), replacement.size(), block.view.base());
            return block;
        }
        return result;
    }

  private:
    ltp::BlockSource& source_;
};

class Scratch final : public ost2pst::util::RandomAccessFile {
  public:
    std::vector<uint8_t> bytes;
    bool fail_write = false, fail_read = false;
    mutable size_t max_read = 0;
    uint64_t size() const override { return bytes.size(); }
    ost2pst::util::Status read_at(uint64_t offset, uint8_t* data, size_t count) const override {
        max_read = std::max(max_read, count);
        if (fail_read)
            return ost2pst::util::make_error(ErrorKind::kIo, "test.scratch_read", offset);
        if (offset > size() || count > size() - offset)
            return ost2pst::util::make_error(ErrorKind::kTruncated, "test.scratch_range", offset);
        if (count)
            std::memcpy(data, bytes.data() + offset, count);
        return {};
    }
    Result<size_t> write_some(uint64_t offset, ost2pst::util::ByteView input) override {
        if (fail_write)
            return ost2pst::util::make_error(ErrorKind::kIo, "test.scratch_write", offset);
        bytes.resize(static_cast<size_t>(offset) + input.size());
        if (!input.empty())
            std::memcpy(bytes.data() + offset, input.data(), input.size());
        return input.size();
    }
    ost2pst::util::Status resize(uint64_t size) override {
        bytes.resize(size);
        return {};
    }
    ost2pst::util::Status flush() override { return {}; }
};

void check_streamed_preparation(const ltp::LtpReadReport& census, ltp::BlockSource& blocks,
                                const msg::MailboxManifest& manifest) {
    Scratch data, log;
    auto opened = writer::StagingJournal::create(data, log, {});
    TEST_OK(opened, "journal for streamed equivalence");
    if (!opened.ok())
        return;
    auto journal = opened.take();
    uint8_t key_index = 1;
    for (const auto& folder : manifest.folders) {
        ost2pst::util::ValueSpool spool(std::filesystem::temp_directory_path().wstring(), 0, 0);
        msg::SubsetOptions options;
        options.spool = &spool;
        auto streamed = msg::extract_folder(census, blocks, folder.source_nid, options);
        auto resident = msg::extract_folder(census, blocks, folder.source_nid, {});
        TEST_OK(streamed, "stream folder properties");
        TEST_OK(resident, "reference folder properties");
        if (streamed.ok() && resident.ok()) {
            TEST_CHECK(streamed.value().folder.name == resident.value().folder.name);
            auto a = msg::build_emit_folder(streamed.value().folder, manifest.registry);
            auto b = msg::build_emit_folder(resident.value().folder, manifest.registry);
            TEST_OK(a, "emit spilled folder name");
            TEST_OK(b, "emit resident folder name");
            if (a.ok() && b.ok())
                TEST_CHECK(a.value().folder.name == b.value().folder.name);
        }
    }
    for (const auto& item : manifest.items) {
        auto resident = msg::prepare_item(census, blocks, item, manifest.registry);
        TEST_OK(resident, "resident reference preparation");
        auto scratch = std::make_shared<Scratch>();
        ost2pst::util::ValueSpool spool(scratch, 0, 0);
        msg::SubsetOptions options;
        options.spool = &spool;
        auto streamed = msg::prepare_item(census, blocks, item, manifest.registry, options);
        TEST_OK(streamed, "force all non-inline values into owned ranges");
        TEST_EQ(spool.resident_bytes(), 0u, "resident budget enforced");
        auto tiny = options;
        tiny.workspace_budget = 1;
        auto capped = msg::prepare_item(census, blocks, item, manifest.registry, tiny);
        TEST_OK(capped, "metadata capacity has a terminal item outcome");
        if (capped.ok()) {
            TEST_EQ(capped.value().outcome.status, msg::ItemStatus::kSkippedUnsupported,
                    "workspace exhaustion is not source corruption or success");
            TEST_CHECK(capped.value().content.plan.blocks.empty());
            TEST_CHECK(std::any_of(capped.value().diagnostics.begin(),
                                   capped.value().diagnostics.end(), [](const auto& diagnostic) {
                                       return diagnostic.stage == "extraction.workspace" &&
                                              diagnostic.detail.find("node.workspace") !=
                                                  std::string::npos;
                                   }));
        }
        if (!resident.ok() || !streamed.ok())
            continue;
        TEST_EQ(streamed.value().outcome.status, msg::ItemStatus::kConverted,
                "spilled item remains convertible");
        TEST_CHECK(streamed.value().outcome.committed == resident.value().outcome.committed);
        TEST_CHECK(streamed.value().outcome.read_state_known ==
                   resident.value().outcome.read_state_known);
        auto extracted = msg::extract_item(census, blocks, item.source_nid, options);
        TEST_OK(extracted, "extract RTF under exhausted resident budget");
        if (extracted.ok()) {
            auto emitted =
                msg::build_emit_item(extracted.value().messages.front(), manifest.registry);
            TEST_OK(emitted, "read streamed RTF header");
            if (emitted.ok())
                TEST_EQ(emitted.value().report.body_rtf_framed,
                        1u + streamed.value().outcome.committed.embedded,
                        "RTF frame uses total range length");
            scratch->fail_read = true;
            TEST_ERROR(msg::build_emit_item(extracted.value().messages.front(), manifest.registry),
                       ErrorKind::kIo, "test.scratch_read", "RTF scratch read failure is fatal");
            scratch->fail_read = false;
        }
        writer::StagedDetails details;
        details.row = resident.value().row;
        ost2pst::util::Sha256Digest key{};
        key[0] = key_index++;
        const size_t reference_record = journal.records().size();
        TEST_OK(writer::stage_plan(journal, key, writer::StagedOutcome::kConverted,
                                   resident.value().content.plan, details),
                "stage resident reference");
        details.row = streamed.value().row;
        key[0] = key_index++;
        TEST_OK(writer::stage_plan(journal, key, writer::StagedOutcome::kConverted,
                                   streamed.value().content.plan, details),
                "stage scratch ranges");
        if (journal.records().size() == reference_record + 2) {
            TEST_CHECK(journal.records()[reference_record].digest ==
                       journal.records().back().digest);
            TEST_EQ(journal.records()[reference_record].length, journal.records().back().length,
                    "durable metadata and all payload bytes equal resident conversion");
        }
        TEST_CHECK(scratch->max_read <= 8192);
        scratch->fail_read = true;
        key[0] = key_index++;
        const size_t before = journal.records().size();
        const auto bytes_before = data.size();
        TEST_ERROR(writer::stage_plan(journal, key, writer::StagedOutcome::kConverted,
                                      streamed.value().content.plan, details),
                   ErrorKind::kIo, "test.scratch_read",
                   "scratch metadata read cannot become a committed prefix");
        TEST_EQ(journal.records().size(), before, "scratch error adds no terminal commit");
        TEST_EQ(data.size(), bytes_before, "metadata failure precedes transaction mutation");
        scratch->fail_read = false;
        scratch->fail_write = true;
        ost2pst::util::ValueSpool failed_spool(scratch, 0, 0);
        options.spool = &failed_spool;
        TEST_ERROR(msg::prepare_item(census, blocks, item, manifest.registry, options),
                   ErrorKind::kIo, "test.scratch_write", "scratch disk full is fatal at caller");
    }
}

void check_item_preparation(const ltp::LtpReadReport& census, ltp::BlockSource& blocks,
                            const msg::MailboxManifest& manifest, uint32_t normal_nid,
                            uint32_t associated_nid) {
    const auto normal =
        std::find_if(manifest.items.begin(), manifest.items.end(),
                     [&](const auto& item) { return item.source_nid == normal_nid; });
    const auto associated =
        std::find_if(manifest.items.begin(), manifest.items.end(),
                     [&](const auto& item) { return item.source_nid == associated_nid; });
    TEST_CHECK(normal != manifest.items.end() && associated != manifest.items.end());
    if (normal == manifest.items.end() || associated == manifest.items.end())
        return;
    auto prepared = msg::prepare_item(census, blocks, *normal, manifest.registry);
    TEST_OK(prepared, "full-mode item preparation");
    if (prepared.ok()) {
        TEST_EQ(prepared.value().outcome.status, msg::ItemStatus::kConverted,
                "readable item receives converted outcome");
        TEST_EQ(prepared.value().outcome.committed.attachments, 1u,
                "preparation preserves attachment population");
        TEST_CHECK(prepared.value().row.has_value());
        TEST_CHECK(!prepared.value().content.plan.blocks.empty());
        TEST_EQ(prepared.value().objects.size(), 3u,
                "message, recipient and attachment scopes survive payload release");
    }
    auto source = census.nodes.node(normal_nid);
    TEST_OK(source, "item source block identity");
    if (!source.ok())
        return;
    FaultBlocks fault(blocks);
    ltp::NodeHeap node;
    ltp::LtpHeapCounters heaps;
    ltp::DataTreeCounters trees;
    std::map<std::string, uint64_t> errors;
    ost2pst::ndb::FailureLog failures;
    const auto opened = ltp::open_node(blocks, census.profile, normal_nid, source.value().bid_data,
                                       node, heaps, trees, errors, nullptr, failures);
    TEST_EQ(opened, ltp::NodeOpen::kOk, "open source PC for an unavailable-body regression");
    if (opened == ltp::NodeOpen::kOk && node.source && !node.multi_block) {
        uint64_t body_record = 0, rtf_record = 0;
        ltp::BthStats stats;
        auto read = ltp::read_pc(
            node.header, census.profile, *node.source,
            [&](const ltp::PcRecord& property) {
                if (property.prop_id == 0x1000)
                    body_record = property.offset;
                if (property.prop_id == 0x1009)
                    rtf_record = property.offset;
                return true;
            },
            stats, failures);
        TEST_OK(read, "locate source body PC record without guessed offsets");
        auto raw = blocks.block(source.value().bid_data);
        TEST_OK(raw, "source PC bytes for the synthetic mutation");
        if (raw.ok() && body_record >= raw.value().view.base() &&
            body_record - raw.value().view.base() + 8 <= raw.value().view.size()) {
            fault.replacement.assign(raw.value().view.data(),
                                     raw.value().view.data() + raw.value().view.size());
            const auto original_pc = fault.replacement;
            const size_t offset = static_cast<size_t>(body_record - raw.value().view.base()) + 4;
            // MS-PST 2.3.3.3: dwValueHnid follows wPropId/wPropType. An intentionally
            // invalid PST HID (2.3.1.4) makes the present body unavailable, not absent.
            const auto invalid_hid = u32(0x0000FFE0);
            std::copy(invalid_hid.begin(), invalid_hid.end(), fault.replacement.begin() + offset);
            fault.replacement_bid = source.value().bid_data;
            auto unavailable = msg::prepare_item(census, fault, *normal, manifest.registry);
            TEST_OK(unavailable, "present but unreadable body produces an honest terminal skip");
            if (unavailable.ok()) {
                TEST_EQ(unavailable.value().outcome.status, msg::ItemStatus::kSkippedCorrupt,
                        "unreadable body cannot produce success");
                bool absence = false;
                for (const auto& finding : unavailable.value().findings)
                    absence |= finding.code == "gap.body";
                TEST_CHECK_MSG(!absence, "unreadable present body is not a legitimate source gap");
            }
            fault.replacement = original_pc;
            // Change only wPropId to an ordinary carried tag; the body property is now
            // absent while the same available value still exists (MS-PST 2.3.3.3).
            fault.replacement[offset - 4] = 1;
            TEST_CHECK(rtf_record >= raw.value().view.base() &&
                       rtf_record - raw.value().view.base() < fault.replacement.size());
            fault.replacement[static_cast<size_t>(rtf_record - raw.value().view.base())] = 10;
            auto absent = msg::prepare_item(census, fault, *normal, manifest.registry);
            TEST_OK(absent, "legitimate source body absence remains convertible");
            if (absent.ok()) {
                TEST_EQ(absent.value().outcome.status, msg::ItemStatus::kConverted,
                        "absence is separate from unreadable source data");
                bool absence = false;
                for (const auto& finding : absent.value().findings)
                    absence |= finding.code == "gap.body";
                TEST_CHECK_MSG(absence, "record a proven source body gap");
            }
            fault.replacement_bid = 0;
            fault.replacement.clear();
        } else {
            TEST_CHECK_MSG(false, "body record must lie within this single-block synthetic PC");
        }
    } else {
        TEST_CHECK_MSG(false, "the synthetic PC must be a single block");
    }
    fault.failed_bid = source.value().bid_data;
    auto corrupt = msg::prepare_item(census, fault, *normal, manifest.registry);
    TEST_OK(corrupt, "item-local CRC failure produces a terminal outcome");
    if (corrupt.ok()) {
        TEST_EQ(corrupt.value().outcome.status, msg::ItemStatus::kSkippedCorrupt,
                "source corruption is explicit");
        TEST_CHECK(!corrupt.value().outcome.source_complete);
        TEST_CHECK(corrupt.value().outcome.committed == msg::ItemPopulation{});
        TEST_CHECK(corrupt.value().content.plan.blocks.empty());
        TEST_CHECK(!corrupt.value().row);
        TEST_CHECK(!corrupt.value().findings.empty());
        TEST_EQ(corrupt.value().outcome.source_gaps, 0u,
                "an unreadable PC cannot establish legitimate property/body absence");
    }
    auto neighbour = msg::prepare_item(census, fault, *associated, manifest.registry);
    TEST_OK(neighbour, "valid FAI survives a corrupt neighbour");
    if (neighbour.ok()) {
        TEST_EQ(neighbour.value().outcome.status, msg::ItemStatus::kConverted,
                "FAI preparation is independent");
        TEST_EQ(neighbour.value().outcome.committed.embedded, 1u,
                "embedded ancestry preserved during preparation");
        bool scoped_embedded = false;
        for (const auto& object : neighbour.value().objects) {
            if (object.kind == msg::ItemObjectKind::kMessage && object.ancestry.size() == 3)
                scoped_embedded = object.ancestry.front() == associated_nid;
        }
        TEST_CHECK(scoped_embedded);
    }
    fault.kind = ErrorKind::kUnsupported;
    auto unsupported = msg::prepare_item(census, fault, *normal, manifest.registry);
    TEST_OK(unsupported, "unavailable item representation is a terminal unsupported outcome");
    if (unsupported.ok())
        TEST_EQ(unsupported.value().outcome.status, msg::ItemStatus::kSkippedUnsupported,
                "unsupported source is distinct from corruption");
    fault.kind = ErrorKind::kIo;
    msg::SubsetOptions no_notes;
    no_notes.max_notes = 0;
    TEST_ERROR(msg::prepare_item(census, fault, *normal, manifest.registry, no_notes),
               ErrorKind::kIo, "test.source_block",
               "source I/O is fatal, not a skipped-corrupt item");
    auto wrong = *normal;
    wrong.source_parent += 32;
    TEST_ERROR(msg::prepare_item(census, blocks, wrong, manifest.registry), ErrorKind::kBadField,
               "conversion.item_manifest", "shared-index mismatch is fatal");
    wrong = *normal;
    wrong.output_nid = wrong.output_parent;
    TEST_ERROR(msg::prepare_item(census, blocks, wrong, manifest.registry), ErrorKind::kBadField,
               "writer.item.identity", "writer invariant failure is fatal, not source corruption");
}

void relocate(writer::StoreSubnode& node, uint64_t base) {
    for (auto& block : node.data_blocks)
        block += base;
    for (auto& child : node.subnodes)
        relocate(child, base);
}
void append(writer::StorePlan& target, writer::ContentPlan part) {
    const uint64_t base = target.blocks.size();
    for (auto& node : part.plan.nodes) {
        for (auto& block : node.data_blocks)
            block += base;
        for (auto& child : node.subnodes)
            relocate(child, base);
        target.nodes.push_back(std::move(node));
    }
    for (auto& block : part.plan.blocks)
        target.blocks.push_back(std::move(block));
    if (!part.plan.rgnid.empty())
        target.rgnid = std::move(part.plan.rgnid);
}

void check_hidden_hierarchy(const ltp::LtpReadReport& census, ltp::BlockSource& blocks,
                            uint32_t imported_nid) {
    const uint32_t hierarchy_nid = static_cast<uint32_t>(
        ltp::make_nid(ltp::nid_index(writer::kNidIpmsubtree), ltp::kNidTypeHierarchyTable));
    auto ref = census.nodes.node(hierarchy_nid);
    TEST_OK(ref, "IPM subtree hierarchy reference");
    if (!ref.ok())
        return;
    ltp::NodeHeap node;
    ltp::LtpHeapCounters heaps;
    ltp::DataTreeCounters trees;
    std::map<std::string, uint64_t> errors;
    ost2pst::ndb::FailureLog failures;
    const auto opened = ltp::open_node(blocks, census.profile, hierarchy_nid, ref.value().bid_data,
                                       node, heaps, trees, errors, nullptr, failures);
    TEST_EQ(opened, ltp::NodeOpen::kOk, "hierarchy opens");
    if (opened != ltp::NodeOpen::kOk || !node.source)
        return;
    auto table = ltp::read_tc(node.header, *node.source);
    TEST_OK(table, "hierarchy TC");
    if (!table.ok())
        return;
    auto matrix = ltp::hn_heap_item(node.page_map, node.block.heap_node(),
                                    table.value().info.hnid_rows, census.profile);
    TEST_OK(matrix, "small hierarchy matrix");
    if (!matrix.ok())
        return;
    bool found = false;
    ltp::BthStats stats;
    auto walked = ltp::walk_tc_row_index(
        table.value(), census.profile, *node.source,
        [&](const ltp::TcRowId& id) {
            if (id.row_id != imported_nid)
                return true;
            found = true;
            const auto width = ltp::tc_row_size(table.value().info);
            auto row = matrix.value().sub(id.row_index * width, width);
            TEST_OK(row, "imported folder hierarchy row");
            if (!row.ok())
                return false;
            for (const auto& column : table.value().columns) {
                if (column.tag != 0x66350003 && column.tag != 0x66360003)
                    continue;
                auto cell = ltp::tc_column_cell(table.value(), column, row.value());
                TEST_OK(cell, "copied hidden-count hierarchy cell");
                if (cell.ok()) {
                    TEST_CHECK(cell.value().exists);
                    if (cell.value().exists) {
                        auto count = cell.value().value.u32(0);
                        TEST_OK(count, "hidden count Integer32");
                        if (count.ok())
                            TEST_EQ(count.value(), 0u, "hierarchy copies zero from child PC");
                    }
                }
            }
            return true;
        },
        stats, failures);
    TEST_OK(walked, "walk imported hierarchy row");
    TEST_CHECK(found);
}

void check_large_item_workspace(bool heap_heavy) {
    constexpr uint32_t nid = 0x200024, parent = writer::kNidIpmsubtree;
    const uint32_t row_count = heap_heavy ? 300 : 3000;
    auto large = message(0);
    large.properties.pop_back(); // no named-property registry needed
    large.recipients = {};
    for (uint32_t column = 0; column < 16; ++column)
        large.recipients.columns.push_back(
            {((0x5000 + column) << 16) | (heap_heavy ? 0x0102u : 0x0003u)});
    for (uint32_t row = 0; row < row_count; ++row) {
        writer::ContentRow value;
        value.row_id = row;
        for (const auto& column : large.recipients.columns)
            value.cells.push_back(
                {column.tag,
                 heap_heavy ? std::vector<uint8_t>(2048, static_cast<uint8_t>(row)) : u32(row)});
        large.recipients.rows.push_back(std::move(value));
    }
    auto outer = message(0);
    outer.properties.pop_back();
    outer.recipients = {};
    writer::ContentAttachment attachment;
    attachment.has_embedded = true;
    attachment.embedded = std::move(large);
    attachment.properties = {
        {0x0E20, 0x0003, u32(0)}, {0x3705, 0x0003, u32(5)}, {0x370B, 0x0003, u32(0)}};
    outer.attachment_objects.push_back(std::move(attachment));
    outer.attachments.rows.push_back({});
    auto plan = writer::build_item_plan(outer, nid, parent, 0);
    TEST_OK(plan, "generate nested recipient-heavy item");
    if (!plan.ok())
        return;
    auto scaffold = writer::build_scaffold_plan({}, {}, 1029, 65537, 32769);
    TEST_OK(scaffold, "workspace fixture scaffold");
    if (!scaffold.ok())
        return;
    writer::StorePlan store;
    append(store, scaffold.take());
    append(store, plan.take().content);
    auto image = writer::write_store(store);
    TEST_OK(image, "workspace fixture image");
    if (!image.ok())
        return;
    const auto path = std::filesystem::temp_directory_path() / "ost2pst_item_workspace_test.pst";
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output.write(reinterpret_cast<const char*>(image.value().bytes.data()),
                     static_cast<std::streamsize>(image.value().bytes.size()));
        TEST_CHECK(output.good());
    }
    {
        auto file = ost2pst::util::FileReader::open(path.native());
        TEST_OK(file, "open workspace fixture");
        if (!file.ok())
            return;
        ltp::LtpReadOptions read_options;
        read_options.build_folders = false;
        auto census = ltp::read_ltp(file.value(), read_options);
        TEST_OK(census, "workspace fixture census");
        if (!census.ok())
            return;
        ost2pst::ndb::BlockReadCounters counters;
        ost2pst::ndb::FailureLog failures;
        ltp::FileBlockSource blocks(file.value(), census.value().profile, census.value().bbt_index,
                                    counters, failures);
        auto registry = msg::EmitRegistry::build({});
        TEST_OK(registry, "empty workspace fixture registry");
        if (!registry.ok())
            return;
        msg::MailboxItem identity;
        identity.source_nid = nid;
        identity.source_parent = parent;
        identity.output_nid = nid;
        identity.output_parent = parent;
        for (bool legacy : {true, false}) {
            ost2pst::util::ValueSpool spool(std::filesystem::temp_directory_path().wstring());
            msg::SubsetOptions options;
            options.spool = &spool;
            if (legacy)
                options.workspace_budget = 64ull * 1024 * 1024;
            auto result =
                msg::prepare_item(census.value(), blocks, identity, registry.value(), options);
            TEST_OK(result, "bounded large-item preparation");
            if (!result.ok())
                continue;
            if (legacy) {
                TEST_EQ(result.value().outcome.status, msg::ItemStatus::kSkippedUnsupported,
                        "old 64 MiB ceiling reproduces recipient-heavy item refusal");
                TEST_CHECK(!result.value().outcome.source_complete);
                TEST_CHECK(result.value().content.plan.blocks.empty());
                TEST_CHECK(
                    std::any_of(result.value().diagnostics.begin(),
                                result.value().diagnostics.end(), [heap_heavy](const auto& d) {
                                    return d.stage == "extraction.workspace" &&
                                           d.detail.find(heap_heavy ? "data_tree.workspace"
                                                                    : "subset.cell_workspace") !=
                                               std::string::npos &&
                                           d.detail.find("limit=67108864") != std::string::npos &&
                                           d.detail.find("requested=") != std::string::npos;
                                }));
            } else {
                TEST_EQ(result.value().outcome.status, msg::ItemStatus::kConverted,
                        "default budget handles nested recipient-heavy item");
                TEST_CHECK(result.value().outcome.source_complete);
                TEST_EQ(result.value().outcome.committed.recipients, row_count,
                        "every recipient preserved");
                TEST_EQ(result.value().outcome.committed.embedded, 1u,
                        "embedded message preserved");
                TEST_EQ(result.value().outcome.committed.attachments, 1u, "attachment preserved");
                auto reference =
                    msg::prepare_item(census.value(), blocks, identity, registry.value());
                TEST_OK(reference, "unspooled content reference");
                if (reference.ok()) {
                    Scratch data, log;
                    auto opened = writer::StagingJournal::create(data, log, {});
                    TEST_OK(opened, "large-item comparison journal");
                    if (!opened.ok())
                        continue;
                    auto journal = opened.take();
                    ost2pst::util::Sha256Digest key{};
                    writer::StagedDetails details;
                    details.row = reference.value().row;
                    TEST_OK(writer::stage_plan(journal, key, writer::StagedOutcome::kConverted,
                                               reference.value().content.plan, details),
                            "stage reference content");
                    key[0] = 1;
                    details.row = result.value().row;
                    TEST_OK(writer::stage_plan(journal, key, writer::StagedOutcome::kConverted,
                                               result.value().content.plan, details),
                            "stage bounded content");
                    TEST_EQ(journal.records().size(), 2u, "both complete records staged");
                    if (journal.records().size() == 2)
                        TEST_CHECK(journal.records()[0].digest == journal.records()[1].digest);
                }
            }
        }
    }
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

void check_dense_folder_staging() {
    constexpr uint32_t nid = 0x200024, folder_nid = 0x8082, count = 69621;
    auto dense = message(0);
    for (const uint16_t property : {0x0037, 0x0042, 0x0070, 0x0E03, 0x0E04}) {
        std::vector<uint8_t> value(84, 0);
        for (size_t byte = 0; byte < value.size(); byte += 2)
            value[byte] = 'A';
        dense.properties.push_back({property, 0x001F, std::move(value)});
    }
    auto item = writer::build_item_plan(dense, nid, folder_nid, 1);
    TEST_OK(item, "prototype contents row for dense folder");
    if (!item.ok())
        return;
    class FolderRows final : public writer::TcRowSource {
      public:
        writer::TcRow prototype;
        uint64_t count() const override { return 69621; }
        Result<writer::TcRow> read(uint64_t index) const override {
            auto row = prototype;
            row.row_id =
                static_cast<uint32_t>(ltp::make_nid(65537 + index, ltp::kNidTypeNormalMessage));
            // The generated contents template ends with PidTagLtpRowId / RowVer.
            row.values[row.values.size() - 2] = u32(row.row_id);
            return row;
        }
    } rows;
    rows.prototype = item.take().row;
    writer::FolderPlanRequest request;
    request.folder = {folder_nid, writer::kNidIpmsubtree, u"Synthetic dense folder", count, count,
                      false};
    request.normal_rows = &rows;
    auto plan = writer::build_folder_plan(request, 1);
    TEST_OK(plan, "folder construction passes the former table workspace ceiling");
    if (!plan.ok())
        return;
    Scratch data, log;
    auto opened = writer::StagingJournal::create(data, log, {});
    TEST_OK(opened, "journal for dense folder fragment");
    if (!opened.ok())
        return;
    auto journal = opened.take();
    TEST_OK(
        writer::stage_plan(journal, {}, writer::StagedOutcome::kConverted, plan.value().plan, {}),
        "dense folder stages within record metadata limit");
    TEST_EQ(journal.records().size(), 1u, "one complete dense folder fragment committed");
}

void check_plans() {
    constexpr uint32_t folder_nid = 0x8082;
    constexpr uint32_t child_nid = 0x80A2;
    constexpr uint32_t normal_nid = 0x200024;
    constexpr uint32_t associated_nid = 0x100028;
    writer::NamedProperty named;
    named.name = u"shared-identity";
    named.guid.assign(16, 0x42);
    writer::NamedProperty numeric;
    numeric.name_is_string = false;
    numeric.numeric_name = 34168;
    // NAMEID_GUID_NONE is a valid property set, not an unresolved GUID.
    numeric.guid.clear();
    const std::vector<writer::NamedProperty> registry{named, numeric};
    auto normal_message = message(0);
    normal_message.properties.push_back({0x8001, 0x0003, u32(777), false, true, 1});
    writer::ContentAttachment binary;
    binary.has_payload = true;
    binary.payload = std::vector<uint8_t>(200000, 0xA7);
    binary.properties = {
        {0x0E20, 0x0003, u32(200000)}, {0x3705, 0x0003, u32(1)}, {0x370B, 0x0003, u32(0)}};
    normal_message.recipients.rows.front().cells.front().value = std::vector<uint8_t>(7000, 0x42);
    normal_message.recipients.rows.front().cells.front().absent = false;
    normal_message.attachments.columns = {{0x8000001F, true, 0}};
    normal_message.attachment_objects.push_back(binary);
    normal_message.attachments.rows.push_back(
        {0, {{0x8000001F, std::vector<uint8_t>(7000, 0x43)}}});
    auto normal = writer::build_item_plan(normal_message, normal_nid, folder_nid, registry.size());
    TEST_OK(normal, "one normal item plan");
    auto fai_message = message(0x41);
    writer::ContentAttachment attached;
    attached.has_embedded = true;
    attached.embedded = message(1);
    attached.embedded.attachments.columns = {{0x80000003, true, 1}};
    attached.properties = {
        {0x0E20, 0x0003, u32(0)}, {0x3705, 0x0003, u32(5)}, {0x370B, 0x0003, u32(0)}};
    fai_message.attachment_objects.push_back(std::move(attached));
    fai_message.attachments.rows.push_back({});
    auto fai = writer::build_item_plan(fai_message, associated_nid, folder_nid, registry.size());
    TEST_OK(fai, "one associated item with embedded descendant");
    if (!normal.ok() || !fai.ok())
        return;
    TEST_CHECK(normal.value().read_state_known && normal.value().unread);
    TEST_CHECK(fai.value().read_state_known && !fai.value().unread);
    TEST_EQ(fai.value().content.report.embedded_messages, 1u, "embedded object preserved in FAI");
    Rows normal_rows, fai_rows;
    normal_rows.values.push_back(normal.value().row);
    fai_rows.values.push_back(fai.value().row);
    writer::FolderPlanRequest request;
    request.folder = {folder_nid, writer::kNidIpmsubtree, u"Imported OST", 1, 1, true};
    request.folder.has_hidden_count = true;
    request.folder.has_hidden_unread = true;
    writer::FolderSummary child{child_nid, folder_nid, u"Empty", 0, 0, false};
    request.children = {child};
    request.normal_rows = &normal_rows;
    request.associated_rows = &fai_rows;
    request.properties = {
        {0x3617, 0x0003, u32(49)}, {0x6635, 0x0003, u32(0)}, {0x6636, 0x0003, u32(0)}};
    auto folder = writer::build_folder_plan(request, registry.size());
    TEST_OK(folder, "folder tables from separately committed rows");
    writer::FolderPlanRequest child_request;
    child_request.folder = child;
    auto empty_child = writer::build_folder_plan(child_request, registry.size());
    TEST_OK(empty_child, "empty nested folder plan");
    auto scaffold = writer::build_scaffold_plan(registry, {request.folder}, 1029, 65537, 32769);
    TEST_OK(scaffold, "scaffold with independent content identities");
    if (!folder.ok() || !empty_child.ok() || !scaffold.ok())
        return;
    writer::StorePlan store;
    append(store, scaffold.take());
    append(store, normal.take().content);
    append(store, fai.take().content);
    append(store, folder.take());
    append(store, empty_child.take());
    auto image = writer::write_store(store);
    TEST_OK(image, "assemble independently relocated content plans");
    if (!image.ok())
        return;
    const auto path = std::filesystem::temp_directory_path() / "ost2pst_writer_item_plan_test.pst";
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output.write(reinterpret_cast<const char*>(image.value().bytes.data()),
                     static_cast<std::streamsize>(image.value().bytes.size()));
        TEST_CHECK(output.good());
    }
    {
        auto file = ost2pst::util::FileReader::open(path.native());
        TEST_OK(file, "open assembled plan fixture");
        if (!file.ok())
            return;
        auto probe = ost2pst::ndb::probe_file(file.value(), {});
        TEST_OK(probe, "probe assembled plan fixture");
        if (probe.ok())
            TEST_CHECK(probe.value().clean);
        ltp::LtpReadOptions bounded;
        bounded.scan_blocks = false;
        bounded.build_folders = false;
        bounded.index_workspace_budget = 1;
        ost2pst::ndb::ProbeOptions probe_budget;
        probe_budget.workspace_budget = 1;
        TEST_ERROR(ost2pst::ndb::probe_file(file.value(), probe_budget), ErrorKind::kUnsupported,
                   "probe.workspace", "refuse before retaining the allocation bitmap");
        TEST_ERROR(ltp::read_ltp(file.value(), bounded), ErrorKind::kUnsupported, "BTree.workspace",
                   "refuse before retaining an index entry");
        bounded.index_workspace_budget = 256 * 1024 * 1024;
        auto bounded_read = ltp::read_ltp(file.value(), bounded);
        TEST_OK(bounded_read, "bounded global census");
        if (bounded_read.ok()) {
            TEST_CHECK(bounded_read.value().index_workspace_bytes > 0);
            TEST_CHECK(bounded_read.value().index_workspace_bytes <=
                       bounded.index_workspace_budget);
            bounded.index_workspace_budget = bounded_read.value().index_workspace_bytes - 1;
            auto refused = ltp::read_ltp(file.value(), bounded);
            TEST_CHECK(!refused.ok());
            if (!refused.ok())
                TEST_CHECK(refused.error().kind == ErrorKind::kUnsupported);
        }
        auto read = ltp::read_ltp(file.value(), {});
        TEST_OK(read, "read assembled content plans");
        if (!read.ok())
            return;
        TEST_CHECK(read.value().clean);
        bool found = false;
        for (const auto& f : read.value().folders) {
            if (f.nid != folder_nid)
                continue;
            found = true;
            TEST_EQ(f.messages, 1u, "normal TC population");
            TEST_EQ(f.associated, 1u, "FAI TC population");
            TEST_EQ(f.children, 1u, "nested empty folder");
        }
        TEST_CHECK(found);
        ost2pst::ndb::BlockReadCounters counters;
        ost2pst::ndb::FailureLog failures;
        ltp::FileBlockSource blocks(file.value(), read.value().profile, read.value().bbt_index,
                                    counters, failures);
        check_hidden_hierarchy(read.value(), blocks, folder_nid);
        auto extracted = msg::extract_item(read.value(), blocks, normal_nid, {});
        TEST_OK(extracted, "one-item extraction without folder-wide enumeration");
        if (extracted.ok()) {
            TEST_EQ(extracted.value().messages.size(), 1u, "only requested item extracted");
            TEST_EQ(extracted.value().attachments_read, 1u, "binary object extracted");
            TEST_EQ(extracted.value().payload_bytes, binary.payload.size(),
                    "available binary bytes");
            auto manifest = msg::build_mailbox_manifest(read.value());
            TEST_OK(manifest, "manifest accepts numeric names read from the actual NAMEID stream");
            if (manifest.ok()) {
                check_item_preparation(read.value(), blocks, manifest.value(), normal_nid,
                                       associated_nid);
                check_streamed_preparation(read.value(), blocks, manifest.value());
                TEST_EQ(manifest.value().named_mapping.at(0x8001), 0x8000,
                        "numeric identity receives deterministic destination NPID");
                TEST_EQ(manifest.value().named_mapping.at(0x8000), 0x8001,
                        "string identity is remapped separately");
                auto emitted = msg::build_emit_item(extracted.value().messages.front(),
                                                    manifest.value().registry);
                TEST_OK(emitted, "fixed registry accepts both parsed name forms");
                if (emitted.ok()) {
                    TEST_EQ(emitted.value().report.named_unresolved, 0u,
                            "no identity lost between census and item emitter");
                    TEST_EQ(emitted.value().report.values_dropped, 0u,
                            "readable values survive emission");
                    bool numeric_carried = false;
                    for (const auto& property : emitted.value().message.properties) {
                        if (property.prop_id == 0x8001) {
                            numeric_carried = property.named && property.named_index == 0 &&
                                              property.value == u32(777);
                        }
                    }
                    TEST_CHECK_MSG(numeric_carried, "numeric identity and value survive remapping");
                    auto rewritten = writer::build_item_plan(emitted.value().message, normal_nid,
                                                             folder_nid, registry.size());
                    TEST_OK(rewritten, "remapped item reaches writer through the full-mode seam");
                    if (rewritten.ok()) {
                        TEST_EQ(rewritten.value().content.report.values_dropped, 0u,
                                "writer accepts remapped properties and table identities");
                    }
                }
            }
        }
        auto associated = msg::extract_item(read.value(), blocks, associated_nid, {});
        TEST_OK(associated, "FAI extraction reuses the same object decoder");
        if (associated.ok()) {
            TEST_EQ(associated.value().attachments_embedded, 1u,
                    "FAI embedded descendant extracted");
            TEST_EQ(associated.value().object_values_carried, 1u, "FAI object bytes carried");
            TEST_EQ(associated.value().unreadable_values, 0u, "no FAI values lost");
            const auto& embedded = associated.value().messages.front().attachments.front().embedded;
            TEST_CHECK(embedded.attachment_table && embedded.attachment_table_read);
            TEST_CHECK(embedded.attachments.empty());
            bool named_empty_schema = false;
            for (const auto& column : embedded.attachment_columns)
                if (column.prop_id == 0x8001 && column.prop_type == 0x0003)
                    named_empty_schema = column.named && column.guid_index == 0 &&
                                         column.guid.empty() && column.numeric_name == 34168;
            TEST_CHECK_MSG(named_empty_schema,
                           "zero-row attachment schema and no-GUID identity survive reread");
            bool present_empty = false;
            for (const auto& recipient : associated.value().messages.front().recipients) {
                for (const auto& value : recipient.values) {
                    if (value.prop_id == 0x8000)
                        present_empty = value.absent && value.bytes.empty();
                }
            }
            TEST_CHECK_MSG(present_empty,
                           "CEB-set HNID zero survives extraction as an empty value");
        }
        auto extracted_folder = msg::extract_folder(read.value(), blocks, folder_nid, {});
        TEST_OK(extracted_folder, "folder-only extraction");
        if (extracted_folder.ok()) {
            TEST_CHECK(extracted_folder.value().messages.empty());
            for (const auto& value : extracted_folder.value().folder.values) {
                if (value.prop_id == 0x3603)
                    TEST_CHECK(value.bytes == u32(1));
                if (value.prop_id == 0x3617)
                    TEST_CHECK_MSG(value.bytes == u32(1),
                                   "associated count derives from committed FAI rows");
            }
        }
    }
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    normal_rows.fail = true;
    TEST_ERROR(writer::build_folder_plan(request, registry.size()), ErrorKind::kIo, "test.spool",
               "spool failure aborts folder assembly");
    normal_rows.fail = false;
    request.properties.back().value = u32(1);
    TEST_ERROR(writer::build_folder_plan(request, registry.size()), ErrorKind::kUnsupported,
               "writer.folder.hidden_counts", "nonzero hidden counts require a proven classifier");
    request.properties.back().value = u32(0);
    request.properties.front().prop_type = 0x0102;
    TEST_ERROR(writer::build_folder_plan(request, registry.size()), ErrorKind::kBadField,
               "writer.folder.count_property", "count must have its documented Integer32 type");
    request.properties.front().prop_type = 0x0003;
    request.folder.has_hidden_unread = false;
    TEST_ERROR(writer::build_folder_plan(request, registry.size()), ErrorKind::kBadField,
               "writer.folder.hidden_presence", "parent summary cannot omit an existing count");
    request.folder.has_hidden_unread = true;
    request.normal_rows = &fai_rows;
    TEST_ERROR(writer::build_folder_plan(request, registry.size()), ErrorKind::kBadField,
               "writer.folder.row_kind", "FAI rows cannot enter normal table");
    TEST_ERROR(writer::build_item_plan(message(0), folder_nid, folder_nid, 0), ErrorKind::kBadField,
               "writer.item.identity", "invalid top-level allocation");
}
} // namespace

int main() {
    for (const size_t count : {50u, 51u, 52u}) {
        auto item = message(0);
        writer::ContentAttachment attachment;
        attachment.has_payload = true;
        attachment.payload = {0x42};
        attachment.properties = {
            {0x0E20, 0x0003, u32(1)}, {0x3705, 0x0003, u32(1)}, {0x370B, 0x0003, u32(0)}};
        item.attachment_objects.assign(count, attachment);
        item.attachments.rows.resize(count);
        auto plan = writer::build_item_plan(item, 0x200024, 0x8082, 1);
        TEST_OK(plan, "attachment allocation must skip fixed local table identifiers");
        if (plan.ok()) {
            TEST_EQ(plan.value().content.report.attachments, count, "all attachments retained");
            const auto& subnodes = plan.value().content.plan.nodes.front().subnodes;
            std::set<uint32_t> nids;
            for (const auto& subnode : subnodes)
                TEST_CHECK(nids.insert(subnode.nid).second);
        }
    }
    check_plans();
    check_large_item_workspace(false);
    check_large_item_workspace(true);
    check_dense_folder_staging();
    auto scaffold = writer::build_scaffold_plan({}, {}, 1027, 65536, 32768);
    TEST_OK(scaffold, "empty standalone scaffold");
    auto empty = writer::build_empty_pst();
    TEST_OK(empty, "legacy M4 scaffold");
    if (scaffold.ok() && empty.ok()) {
        auto image = writer::write_store(scaffold.value().plan);
        TEST_OK(image, "assemble standalone empty scaffold");
        if (image.ok())
            TEST_CHECK(image.value().bytes == empty.value().bytes);
    }
    return ost2pst::test::finish("writer_item_plan_test");
}
