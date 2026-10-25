#include "full_conversion.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <locale>
#include <map>
#include <random>
#include <set>
#include <sstream>

#include "gui_events.h"
#include "read_only.h"

#define NOMINMAX
// psapi.h requires the Windows types; the project formatter otherwise sorts it first.
// clang-format off
#include <windows.h>
#include <psapi.h>
// clang-format on

#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/node_open.h"
#include "ost2pst/msg/item_conversion.h"
#include "ost2pst/ndb/probe.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/writer/staging_workspace.h"

namespace ost2pst::cli {
namespace {
using util::ErrorKind;
using util::Result;
using util::Status;
using Clock = std::chrono::steady_clock;

class ObservedCandidate final : public util::RandomAccessFile {
  public:
    ObservedCandidate(util::RandomAccessFile& file, const FullConversionHooks& hooks)
        : file_(file), hooks_(hooks) {}
    uint64_t size() const override { return file_.size(); }
    Status read_at(uint64_t offset, uint8_t* data, size_t count) const override {
        return file_.read_at(offset, data, count);
    }
    Result<size_t> write_some(uint64_t offset, util::ByteView bytes) override {
        if (hooks_.before_candidate_write) {
            auto observed = hooks_.before_candidate_write(offset, bytes);
            if (!observed.ok())
                return observed.error();
        }
        return file_.write_some(offset, bytes);
    }
    Status resize(uint64_t size) override { return file_.resize(size); }
    Status flush() override { return file_.flush(); }

  private:
    util::RandomAccessFile& file_;
    const FullConversionHooks& hooks_;
};

Status invalid(const char* field, uint64_t value, const char* detail) {
    return util::make_error(ErrorKind::kBadField, field, 0, value, detail);
}
util::ByteView bytes(const std::string& text) {
    return {reinterpret_cast<const uint8_t*>(text.data()), text.size(), 0};
}
std::string quoted(const std::string& text) {
    std::string out = "\"";
    for (const unsigned char c : text) {
        if (c == '"' || c == '\\') {
            out += '\\';
            out += static_cast<char>(c);
        } else if (c < 32) {
            char escape[7];
            std::snprintf(escape, sizeof escape, "\\u%04x", c);
            out += escape;
        } else {
            out += static_cast<char>(c);
        }
    }
    return out + '"';
}
std::string population(const msg::ItemPopulation& value) {
    std::ostringstream out;
    out << "{\"embedded\":" << value.embedded << ",\"recipients\":" << value.recipients
        << ",\"attachments\":" << value.attachments
        << ",\"opaque_objects\":" << value.opaque_objects
        << ",\"attachment_bytes\":" << value.attachment_bytes << '}';
    return out.str();
}
std::string item_json(const msg::PreparedItem& prepared) {
    const auto& value = prepared.outcome;
    const auto& item = value.item;
    std::ostringstream out;
    out << "{\"schema\":1,\"kind\":\"item\",\"source_nid\":" << item.source_nid
        << ",\"source_parent\":" << item.source_parent << ",\"output_nid\":" << item.output_nid
        << ",\"output_parent\":" << item.output_parent
        << ",\"associated\":" << (item.associated ? "true" : "false")
        << ",\"status\":" << quoted(msg::item_status_name(value.status))
        << ",\"source_complete\":" << (value.source_complete ? "true" : "false")
        << ",\"source\":" << population(value.source)
        << ",\"committed\":" << population(value.committed) << ",\"findings\":[";
    bool first = true;
    for (const auto& finding : prepared.findings) {
        if (!first)
            out << ',';
        first = false;
        out << "{\"code\":" << quoted(finding.code) << ",\"count\":" << finding.count << '}';
    }
    out << "],\"objects\":[";
    first = true;
    for (const auto& object : prepared.objects) {
        if (!first)
            out << ',';
        first = false;
        const auto kind = object.kind == msg::ItemObjectKind::kMessage      ? "message"
                          : object.kind == msg::ItemObjectKind::kAttachment ? "attachment"
                                                                            : "recipient";
        out << "{\"kind\":" << quoted(kind) << ",\"ancestry\":[";
        for (size_t i = 0; i < object.ancestry.size(); ++i) {
            if (i != 0)
                out << ',';
            out << object.ancestry[i];
        }
        out << "]}";
    }
    out << "],\"diagnostics\":[";
    first = true;
    for (const auto& diagnostic : prepared.diagnostics) {
        if (!first)
            out << ',';
        first = false;
        out << "{\"stage\":" << quoted(diagnostic.stage)
            << ",\"detail\":" << quoted(diagnostic.detail) << ",\"ancestry\":[";
        for (size_t i = 0; i < diagnostic.ancestry.size(); ++i) {
            if (i != 0)
                out << ',';
            out << diagnostic.ancestry[i];
        }
        out << "]}";
    }
    out << "]}";
    return out.str();
}

util::Sha256Digest auxiliary_key(uint64_t kind, uint32_t source, uint32_t output) {
    const auto text = "ost2pst.m6.aux.v1:" + std::to_string(kind) + ':' + std::to_string(source) +
                      ':' + std::to_string(output);
    util::Sha256 hash;
    hash.update(bytes(text));
    return hash.digest();
}
writer::StagedDetails auxiliary_details(uint64_t kind, uint32_t source, uint32_t output) {
    writer::StagedDetails details;
    details.counters = {{"record_kind", kind}, {"source_nid", source}, {"output_nid", output}};
    return details;
}
class Progress {
  public:
    explicit Progress(Clock::time_point start, GuiEvents& events)
        : start_(start), last_(start), events_(events) {}
    void show(const char* phase, const msg::OutcomeLedger* ledger = nullptr, uint64_t total = 0,
              uint32_t folder = 0, bool force = false) {
        const auto now = Clock::now();
        if (!force && now - last_ < std::chrono::seconds(1))
            return;
        last_ = now;
        const auto counts = ledger ? ledger->totals() : msg::OutcomeTotals{};
        events_.progress(phase, ledger != nullptr, total, counts.terminal, counts.converted_normal,
                         counts.converted_associated,
                         counts.skipped_corrupt + counts.skipped_unsupported + counts.failed);
        std::fprintf(
            stderr,
            "conversion phase=%s committed=%llu/%llu folder=0x%08X payload_bytes=%llu "
            "skipped=%llu elapsed=%.3fs\n",
            phase, static_cast<unsigned long long>(counts.terminal),
            static_cast<unsigned long long>(total), folder,
            static_cast<unsigned long long>(counts.committed.attachment_bytes),
            static_cast<unsigned long long>(counts.skipped_corrupt + counts.skipped_unsupported),
            std::chrono::duration<double>(now - start_).count());
    }

  private:
    Clock::time_point start_, last_;
    GuiEvents& events_;
};

struct FolderState {
    std::shared_ptr<util::MemoryReservation> reservation;
    writer::FolderSummary summary;
    std::vector<writer::ContentProperty> properties;
    std::vector<size_t> normal, associated;
};
Result<std::map<uint32_t, FolderState>> folders(const ltp::LtpReadReport& census,
                                                ltp::BlockSource& blocks,
                                                const msg::MailboxManifest& manifest,
                                                const msg::OutcomeLedger& ledger,
                                                std::shared_ptr<util::Workspace> resources) {
    std::map<uint32_t, FolderState> result;
    auto retained = std::make_shared<util::MemoryReservation>(resources->memory);
    util::ValueSpool spool(resources);
    const auto reserve = [&](uint64_t bytes, const char* field, uint64_t = 0) -> Status {
        auto result = retained->reserve(bytes, field);
        if (!result.ok()) {
            auto spilled = spool.spill_shared_cache();
            if (!spilled.ok())
                return spilled;
            result = retained->reserve(bytes, field);
        }
        return result;
    };
    msg::SubsetOptions options;
    options.spool = &spool;
    options.workspace = resources;
    options.workspace_budget = std::max<uint64_t>(512ull << 20, resources->memory->limit());
    for (const auto& folder : manifest.folders) {
        auto extracted = msg::extract_folder(census, blocks, folder.source_nid, options);
        if (!extracted.ok())
            return extracted.error();
        if (extracted.value().fatal_io)
            return *extracted.value().fatal_io;
        if (extracted.value().workspace_error)
            return *extracted.value().workspace_error;
        if (!extracted.value().folder.pc_read || extracted.value().unreadable_values != 0 ||
            extracted.value().named_unresolved != 0)
            return invalid("full.folder_read", folder.source_nid,
                           "folder content is unavailable; hierarchy cannot be published")
                .error();
        auto emitted = msg::build_emit_folder(extracted.value().folder, manifest.registry);
        if (!emitted.ok())
            return emitted.error();
        auto value = emitted.take();
        if (value.report.values_dropped != 0 || value.report.named_unresolved != 0)
            return invalid("full.folder_emission", folder.source_nid, "folder properties lost")
                .error();
        auto reserved =
            reserve(2 * sizeof(FolderState) + 128 + 4 * value.folder.name.capacity() +
                        2 * value.folder.properties.capacity() * sizeof(writer::ContentProperty),
                    "full.folder_workspace", folder.source_nid);
        if (!reserved.ok())
            return reserved.error();
        for (const auto& property : value.folder.properties) {
            reserved = reserve(2 * property.value.capacity() + 128, "full.folder_workspace",
                               folder.source_nid);
            if (!reserved.ok())
                return reserved.error();
        }
        FolderState state;
        state.reservation = retained;
        state.summary.nid = folder.output_nid;
        state.summary.parent_nid = folder.output_parent;
        state.summary.name =
            folder.output_parent == writer::kNidIpmsubtree ? u"Imported OST" : value.folder.name;
        state.properties = std::move(value.folder.properties);
        for (const auto& property : state.properties) {
            if (property.prop_id == 0x6635)
                state.summary.has_hidden_count = true;
            if (property.prop_id == 0x6636)
                state.summary.has_hidden_unread = true;
        }
        result.emplace(folder.output_nid, std::move(state));
    }
    for (const auto& [source, committed] : ledger.items()) {
        (void)source;
        if (committed.outcome.status != msg::ItemStatus::kConverted)
            continue;
        auto& state = result.at(committed.outcome.item.output_parent);
        auto& rows = committed.outcome.item.associated ? state.associated : state.normal;
        auto reserved = reserve(4 * sizeof(size_t), "full.folder_workspace");
        if (!reserved.ok())
            return reserved.error();
        rows.push_back(committed.record);
        if (!committed.outcome.item.associated) {
            if (state.summary.content_count == std::numeric_limits<uint32_t>::max())
                return invalid("full.folder_count", state.summary.nid, "count exceeds uint32")
                    .error();
            ++state.summary.content_count;
            if (committed.outcome.unread)
                ++state.summary.unread_count;
        }
    }
    for (auto& [nid, state] : result) {
        (void)nid;
        if (result.contains(state.summary.parent_nid))
            result.at(state.summary.parent_nid).summary.has_subfolders = true;
    }
    return result;
}

Status replay(const writer::StagingJournal& journal, const msg::MailboxManifest& manifest,
              msg::OutcomeLedger& ledger, std::set<uint32_t>& committed_folders, bool& scaffold,
              std::shared_ptr<util::Workspace> resources) {
    std::map<uint32_t, msg::MailboxFolder> expected;
    for (const auto& folder : manifest.folders)
        expected.emplace(folder.source_nid, folder);
    for (size_t record = 0; record < journal.records().size(); ++record) {
        auto loaded = writer::read_staged_plan(journal, record, resources);
        if (!loaded.ok())
            return loaded.error();
        const auto& plan = loaded.value();
        const auto& fields = plan.details.counters;
        if (!fields.contains("record_kind"))
            return invalid("full.record_kind", record, "record has no application type");
        const auto kind = fields.at("record_kind");
        if (kind == 1) {
            if (!committed_folders.empty() || scaffold)
                return invalid("full.record_order", record, "item follows folder finalization");
            auto decoded = msg::decode_item_outcome(plan, journal.records()[record].outcome);
            if (!decoded.ok())
                return decoded.error();
            auto accepted = ledger.accept(record, journal.records()[record].key, decoded.value());
            if (!accepted.ok())
                return accepted;
            if (plan.details.json.empty())
                return invalid("full.item_report", record, "durable item diagnostic is missing");
            continue;
        }
        if ((kind != 2 && kind != 3) || fields.size() != 3 || !fields.contains("source_nid") ||
            !fields.contains("output_nid") ||
            fields.at("source_nid") > std::numeric_limits<uint32_t>::max() ||
            fields.at("output_nid") > std::numeric_limits<uint32_t>::max() ||
            ledger.totals().terminal != manifest.items.size() || plan.details.row ||
            journal.records()[record].outcome != writer::StagedOutcome::kConverted)
            return invalid("full.auxiliary", record, "invalid finalization record");
        const auto source = static_cast<uint32_t>(fields.at("source_nid"));
        const auto output = static_cast<uint32_t>(fields.at("output_nid"));
        if (journal.records()[record].key != auxiliary_key(kind, source, output))
            return invalid("full.auxiliary_key", record, "record key disagrees with identity");
        if (kind == 2) {
            if (scaffold || !expected.contains(source) ||
                expected.at(source).output_nid != output || !plan.rgnid.empty() ||
                plan.nodes.size() != 4 || plan.blocks.empty() ||
                !committed_folders.insert(source).second)
                return invalid("full.folder_record", source, "invalid or duplicate folder record");
            const auto& folder = expected.at(source);
            for (const auto& node : plan.nodes) {
                const auto type = ltp::nid_type(node.nid);
                if (ltp::nid_index(node.nid) != ltp::nid_index(output) ||
                    (type != ltp::kNidTypeNormalFolder && type != ltp::kNidTypeHierarchyTable &&
                     type != ltp::kNidTypeContentsTable &&
                     type != ltp::kNidTypeAssocContentsTable) ||
                    node.nid_parent != (node.nid == output ? folder.output_parent : output))
                    return invalid("full.folder_node", node.nid, "folder record has foreign nodes");
            }
        } else {
            if (source != 0 || output != 0 || scaffold ||
                committed_folders.size() != manifest.folders.size() || plan.rgnid.empty() ||
                plan.nodes.empty() || plan.blocks.empty())
                return invalid("full.scaffold_record", record, "invalid or duplicate scaffold");
            scaffold = true;
        }
    }
    return {};
}

Status verify_candidate(const std::wstring& path, uint64_t size,
                        const msg::MailboxManifest& manifest, const msg::OutcomeLedger& ledger,
                        std::shared_ptr<util::Workspace> resources) {
    auto opened = util::FileReader::open(path);
    if (!opened.ok())
        return opened.error();
    const auto& file = opened.value();
    if (file.size() != size)
        return invalid("full.verify_size", file.size(), "candidate length changed");
    {
        ndb::ProbeOptions probe_options;
        probe_options.workspace_budget = kFullIndexWorkspaceBudget;
        auto probe = ndb::probe_file(file, probe_options);
        if (!probe.ok())
            return probe.error();
        if (probe.value().refusal || !probe.value().clean)
            return invalid("full.verify_ndb", probe.value().failure_total, "candidate NDB failed");
    }
    ltp::LtpReadOptions read_options;
    read_options.index_workspace_budget = kFullIndexWorkspaceBudget;
    read_options.scan_blocks =
        false; // Every committed item is extracted with a bounded spool below.
    auto read = ltp::read_ltp(file, read_options);
    if (!read.ok())
        return read.error();
    const auto& census = read.value();
    if (census.refusal || !census.clean ||
        census.named_properties != manifest.registry.entries().size())
        return invalid("full.verify_ltp", census.failure_total, "candidate LTP or registry failed");
    ndb::BlockReadCounters counters;
    ndb::FailureLog failures(20);
    ltp::FileBlockSource blocks(file, census.profile, census.bbt_index, counters, failures);
    for (const auto& folder : manifest.folders) {
        const auto found = std::find_if(census.folders.begin(), census.folders.end(),
                                        [&](const auto& f) { return f.nid == folder.output_nid; });
        if (found == census.folders.end() || found->parent != folder.output_parent)
            return invalid("full.verify_folder", folder.output_nid, "mapped folder is absent");
        uint64_t normal = 0, associated = 0;
        for (const auto& [source, committed] : ledger.items()) {
            (void)source;
            const auto& outcome = committed.outcome;
            if (outcome.item.output_parent == folder.output_nid &&
                outcome.status == msg::ItemStatus::kConverted)
                ++(outcome.item.associated ? associated : normal);
        }
        if (found->messages != normal || found->associated != associated ||
            found->parent_messages != normal || found->parent_associated != associated)
            return invalid("full.verify_folder_counts", folder.output_nid,
                           "table/ownership counts disagree");
    }
    for (const auto& [source, committed] : ledger.items()) {
        (void)source;
        const auto& outcome = committed.outcome;
        auto node = census.nodes.node(outcome.item.output_nid);
        if (outcome.status != msg::ItemStatus::kConverted) {
            if (node.ok())
                return invalid("full.verify_skip", outcome.item.output_nid, "skipped item exists");
            continue;
        }
        if (!node.ok() || node.value().nid_parent != outcome.item.output_parent)
            return invalid("full.verify_item", outcome.item.output_nid, "committed item is absent");
        util::ValueSpool spool(resources);
        msg::SubsetOptions extraction;
        extraction.spool = &spool;
        extraction.workspace = resources;
        extraction.workspace_budget = std::max<uint64_t>(512ull << 20, resources->memory->limit());
        auto extracted = msg::extract_item(census, blocks, outcome.item.output_nid, extraction);
        if (!extracted.ok())
            return extracted.error();
        const auto& value = extracted.value();
        if (value.fatal_io)
            return *value.fatal_io;
        const msg::ItemPopulation observed{value.attachments_embedded, value.recipients_read,
                                           value.attachments_read, value.attachments_opaque,
                                           value.payload_bytes};
        if (observed != outcome.committed || value.messages_read != 1 ||
            value.unreadable_values != 0 || value.named_unresolved != 0 ||
            value.messages_without_pc != 0 || value.recipient_table_failures != 0 ||
            value.attachment_table_failures != 0 || value.attachment_pc_failures != 0 ||
            value.rows_without_cells != 0 || value.subnode_walk_failures != 0 ||
            value.subnode_walks_incomplete != 0 || value.row_index_walks_incomplete != 0 ||
            value.matrix_short_blocks != 0 || value.capped ||
            value.attachments_with_unread_object != 0 ||
            value.object_values != value.object_values_carried)
            return invalid("full.verify_population", outcome.item.output_nid,
                           "committed item reread failed");
    }
    return {};
}

Status append_text(util::RandomAccessFile& file, const std::string& text) {
    return util::write_all(file, file.size(), bytes(text));
}
std::string run_id(const writer::RunId& id) {
    std::string result;
    for (uint8_t byte : id) {
        char hex[3];
        std::snprintf(hex, sizeof hex, "%02x", byte);
        result += hex;
    }
    return result;
}
Status reports(writer::Publication& publication, const writer::StagingWorkspace& workspace,
               const writer::StagingJournal& journal, const msg::MailboxManifest& manifest,
               const msg::OutcomeLedger& ledger, const msg::InvocationAttempts& attempts,
               uint64_t recovered, bool complete, const writer::StagedAssemblyStats& assembly,
               Clock::time_point start, bool resumed, std::shared_ptr<util::Workspace> resources) {
    auto& items = publication.file(writer::PublicationArtifact::kItems);
    auto reset = items.resize(0);
    if (!reset.ok())
        return reset;
    for (const auto& [source, committed] : ledger.items()) {
        (void)source;
        auto loaded = writer::read_staged_plan(journal, committed.record, resources);
        if (!loaded.ok())
            return loaded.error();
        auto written = append_text(items, loaded.value().details.json + '\n');
        if (!written.ok())
            return written;
    }
    for (const auto& folder : manifest.folders) {
        std::ostringstream out;
        out << "{\"schema\":1,\"kind\":\"folder\",\"source_nid\":" << folder.source_nid
            << ",\"source_parent\":" << folder.source_parent
            << ",\"output_nid\":" << folder.output_nid
            << ",\"output_parent\":" << folder.output_parent << "}\n";
        auto written = append_text(items, out.str());
        if (!written.ok())
            return written;
    }
    std::map<msg::CoverageKind, uint64_t> coverage;
    for (const auto& node : manifest.coverage) {
        ++coverage[node.kind];
        std::ostringstream out;
        out << "{\"schema\":1,\"kind\":\"coverage\",\"source_nid\":" << node.source_nid
            << ",\"source_parent\":" << node.source_parent << ",\"output_nid\":" << node.output_nid
            << ",\"status\":" << quoted(msg::coverage_kind_name(node.kind)) << "}\n";
        auto written = append_text(items, out.str());
        if (!written.ok())
            return written;
    }
    const auto& totals = ledger.totals();
    // Sample before sealing publication: sealed reports must remain immutable for recovery.
    const double seconds = std::chrono::duration<double>(Clock::now() - start).count();
    PROCESS_MEMORY_COUNTERS memory{};
    memory.cb = sizeof memory;
    const bool measured =
        GetProcessMemoryInfo(GetCurrentProcess(), &memory, sizeof memory) != FALSE;
    std::ostringstream out;
    out.imbue(std::locale::classic());
    out << std::setprecision(17);
    out << "{\"schema\":1,\"run_id\":" << quoted(run_id(workspace.manifest().run_id))
        << ",\"status\":" << quoted(complete ? "complete" : "incomplete")
        << ",\"exit_code\":" << (complete ? 0 : 3) << ",\"internal_verification\":\"passed\""
        << ",\"independent_review\":\"pending\",\"outlook_acceptance\":\"pending\""
        << ",\"source_sha256\":"
        << quoted(util::sha256_hex(workspace.manifest().conversion.source_sha256))
        << ",\"source_size\":" << workspace.manifest().conversion.source_size
        << ",\"folders\":" << manifest.folders.size() << ",\"items\":" << manifest.items.size()
        << ",\"terminal\":" << totals.terminal
        << ",\"converted_normal\":" << totals.converted_normal
        << ",\"converted_fai\":" << totals.converted_associated
        << ",\"skipped_corrupt\":" << totals.skipped_corrupt
        << ",\"skipped_unsupported\":" << totals.skipped_unsupported
        << ",\"failed\":" << totals.failed
        << ",\"unknown_source_populations\":" << totals.unknown_source
        << ",\"unknown_read_state\":" << totals.unknown_read_state
        << ",\"source_gaps\":" << totals.source_gaps << ",\"recovered_items\":" << recovered
        << ",\"invocation_attempts\":{\"normal\":" << attempts.normal
        << ",\"fai\":" << attempts.associated << "},\"source\":" << population(totals.source)
        << ",\"committed\":" << population(totals.committed)
        << ",\"output_verified\":" << population(totals.committed) << ",\"coverage\":{";
    bool first = true;
    for (const auto& [kind, count] : coverage) {
        if (!first)
            out << ',';
        first = false;
        out << quoted(msg::coverage_kind_name(kind)) << ':' << count;
    }
    out << "},\"block_sharing\":{\"references\":" << assembly.block_references
        << ",\"stored_blocks\":" << assembly.stored_blocks
        << ",\"shared_references\":" << assembly.shared_references
        << ",\"avoided_payload_bytes\":" << assembly.avoided_payload_bytes
        << ",\"index_entries\":" << assembly.index_entries
        << ",\"index_saturated\":" << (assembly.index_saturated ? "true" : "false")
        << "},\"pst_bytes\":" << publication.file(writer::PublicationArtifact::kPst).size()
        << ",\"performance\":{\"scope\":\"current_invocation_before_publication\""
        << ",\"resumed\":" << (resumed ? "true" : "false") << ",\"wall_seconds\":" << seconds
        << ",\"peak_working_set_bytes\":";
    if (measured)
        out << static_cast<uint64_t>(memory.PeakWorkingSetSize);
    else
        out << "null";
    out << ",\"throughput_bytes_per_second\":";
    // A resumed invocation reuses prior work; whole-source bytes / this duration would mislead.
    if (!resumed && seconds > 0)
        out << static_cast<double>(workspace.manifest().conversion.source_size) / seconds;
    else
        out << "null";
    out << "},\"resources\":{\"memory_limit_bytes\":" << resources->memory->limit()
        << ",\"peak_managed_bytes\":" << resources->memory->peak()
        << ",\"scratch_spilled_bytes\":" << resources->spilled_bytes
        << ",\"scope\":\"managed_workspace\"}}\n";
    auto& summary = publication.file(writer::PublicationArtifact::kSummary);
    reset = summary.resize(0);
    if (!reset.ok())
        return reset;
    auto written = append_text(summary, out.str());
    if (!written.ok())
        return written;
    auto flushed = items.flush();
    return flushed.ok() ? summary.flush() : flushed;
}

Result<int> convert(const std::wstring& input, const std::wstring& output, bool resume,
                    Clock::time_point start, const FullConversionHooks& hooks, bool& input_phase,
                    GuiEvents& events) {
    const auto observe = [&](FullPoint point) {
        if (hooks.phase)
            hooks.phase(point);
    };
    Progress progress(start, events);
    progress.show("identity", nullptr, 0, 0, true);
    auto opened = util::FileReader::open_stable(input);
    if (!opened.ok())
        return opened.error();
    auto file = opened.take();
    auto valid = validate_input(file);
    if (!valid.ok())
        return valid.error();
    auto original = file.identity();
    if (!original.ok())
        return original.error();
    auto digest = util::sha256_file(file);
    if (!digest.ok())
        return digest.error();
    input_phase = false;
    wchar_t module[32768];
    const auto length = GetModuleFileNameW(nullptr, module, static_cast<DWORD>(std::size(module)));
    if (length == 0 || length == std::size(module))
        return invalid("full.converter_path", length, "cannot identify converter binary").error();
    auto binary = util::FileReader::open(std::wstring(module, length));
    if (!binary.ok())
        return binary.error();
    auto binary_digest = util::sha256_file(binary.value());
    if (!binary_digest.ok())
        return binary_digest.error();
    progress.show("index", nullptr, 0, 0, true);
    input_phase = true;
    ltp::LtpReadOptions options;
    options.scan_blocks = false;
    options.build_folders = false;
    options.index_workspace_budget = hooks.index_workspace_budget;
    auto read = ltp::read_ltp(file, options);
    if (!read.ok())
        return read.error();
    auto census = read.take();
    if (census.refusal)
        return *census.refusal;
    auto built_manifest = msg::build_mailbox_manifest(census);
    if (!built_manifest.ok())
        return built_manifest.error();
    auto manifest = built_manifest.take();
    input_phase = false;
    writer::ConversionIdentity identity;
    identity.source_sha256 = digest.value();
    identity.source_size = file.size();
    identity.source_profile = writer::staging_profile_tag(census.profile);
    const uint64_t required_records = manifest.items.size() + manifest.folders.size() + 1;
    if (required_records > 1000000)
        return util::make_error(ErrorKind::kUnsupported, "full.record_budget", 0, required_records);
    identity.record_budget = static_cast<uint32_t>(std::max<uint64_t>(100000, required_records));
    identity.converter_sha256 = binary_digest.value();
    identity.options = {{"mode", "full-v1"}, {"hierarchy", "imported-ost"}, {"search", "excluded"}};
    writer::RunId id{};
    std::random_device random;
    for (auto& byte : id)
        byte = static_cast<uint8_t>(random());
    auto opened_workspace =
        resume ? writer::StagingWorkspace::resume_ready(output, identity, id, hooks.initialization)
               : writer::StagingWorkspace::create_ready(output, identity, id, hooks.initialization);
    if (!opened_workspace.ok())
        return opened_workspace.error();
    auto workspace = opened_workspace.take();
    auto& publication = *workspace.publication();
    if (workspace.completed()) {
        const auto completed = *workspace.completed();
        if (completed.terminal_items != manifest.items.size())
            return invalid("full.completed_population", completed.terminal_items,
                           "completion receipt differs from the source manifest")
                .error();
        auto cleaned = workspace.cleanup_completed(completed, hooks.cleanup);
        if (!cleaned.ok())
            std::fprintf(stderr, "conversion cleanup incomplete: %s\n",
                         util::format_error(cleaned.error()).c_str());
        std::fprintf(events.enabled() ? stderr : stdout,
                     "CONVERSION RESULT: %s\nrecovered=%llu attempted_normal=0 attempted_fai=0\n",
                     completed.exit_code == 0 ? "complete" : "incomplete",
                     static_cast<unsigned long long>(completed.terminal_items));
        return static_cast<int>(completed.exit_code);
    }
    auto& journal = workspace.journal();
    auto resources = std::make_shared<util::Workspace>(
        workspace.directory(), hooks.cache_limit_bytes.value_or(util::automatic_memory_limit(
                                   util::available_physical_memory())));
    resources->monitor_pressure = !hooks.cache_limit_bytes.has_value();
    std::fprintf(stderr,
                 "conversion resources cache_limit_bytes=%llu extraction_accounting_bytes=%llu\n",
                 static_cast<unsigned long long>(resources->memory->limit()),
                 static_cast<unsigned long long>(
                     std::max<uint64_t>(512ull << 20, resources->memory->limit())));
    msg::OutcomeLedger ledger(manifest);
    std::set<uint32_t> committed_folders;
    bool scaffold = false;
    auto replayed = replay(journal, manifest, ledger, committed_folders, scaffold, resources);
    if (!replayed.ok())
        return replayed.error();
    const uint64_t recovered = ledger.totals().terminal;
    progress.show("items", &ledger, manifest.items.size(), 0, true);
    msg::InvocationAttempts attempts;
    ndb::BlockReadCounters counters;
    ndb::FailureLog failures(20);
    ltp::FileBlockSource blocks(file, census.profile, census.bbt_index, counters, failures);
    for (const auto& item : manifest.items) {
        if (ledger.items().contains(item.source_nid))
            continue;
        if (publication.phase() != writer::PublicationPhase::kBuilding)
            return invalid("full.ready_ledger", item.source_nid, "sealed publication is incomplete")
                .error();
        ++(item.associated ? attempts.associated : attempts.normal);
        util::ValueSpool spool(resources);
        msg::SubsetOptions extraction;
        extraction.spool = &spool;
        extraction.workspace = resources;
        extraction.workspace_budget = std::max<uint64_t>(512ull << 20, resources->memory->limit());
        auto prepared = msg::prepare_item(census, blocks, item, manifest.registry, extraction);
        if (!prepared.ok())
            return prepared.error();
        auto value = prepared.take();
        observe(FullPoint::kItemPrepared);
        auto details = msg::encode_item_outcome(value.outcome, value.row ? &*value.row : nullptr);
        if (!details.ok())
            return details.error();
        auto metadata = details.take();
        metadata.json = item_json(value);
        const auto key = msg::item_outcome_key(item);
        const size_t record = journal.records().size();
        auto staged = writer::stage_plan(journal, key,
                                         value.outcome.status == msg::ItemStatus::kConverted
                                             ? writer::StagedOutcome::kConverted
                                             : writer::StagedOutcome::kFailed,
                                         value.content.plan, metadata, hooks.commit, resources);
        if (!staged.ok())
            return staged.error();
        auto accepted = ledger.accept(record, key, value.outcome);
        if (!accepted.ok())
            return accepted.error();
        observe(FullPoint::kItemCommitted);
        progress.show("items", &ledger, manifest.items.size(), item.source_parent);
    }
    bool unsupported_coverage = false;
    for (const auto& entry : manifest.coverage)
        unsupported_coverage |= entry.kind == msg::CoverageKind::kUnsupportedContent;
    const auto& totals = ledger.totals();
    const bool complete = totals.terminal == manifest.items.size() && totals.skipped_corrupt == 0 &&
                          totals.skipped_unsupported == 0 && totals.failed == 0 &&
                          !unsupported_coverage;
    if (publication.phase() == writer::PublicationPhase::kBuilding) {
        progress.show("folders", &ledger, manifest.items.size(), 0, true);
        auto states_result = folders(census, blocks, manifest, ledger, resources);
        if (!states_result.ok())
            return states_result.error();
        auto states = states_result.take();
        for (const auto& folder : manifest.folders) {
            if (committed_folders.contains(folder.source_nid))
                continue;
            auto& state = states.at(folder.output_nid);
            writer::StagedRows normal(journal, std::move(state.normal), resources),
                associated(journal, std::move(state.associated), resources);
            writer::FolderPlanRequest request;
            request.workspace = resources;
            request.folder = state.summary;
            request.properties = std::move(state.properties);
            request.normal_rows = &normal;
            request.associated_rows = &associated;
            for (const auto& [nid, child] : states) {
                (void)nid;
                if (child.summary.parent_nid == folder.output_nid)
                    request.children.push_back(child.summary);
            }
            auto plan = writer::build_folder_plan(request, manifest.registry.entries().size());
            if (!plan.ok())
                return plan.error();
            auto staged = writer::stage_plan(
                journal, auxiliary_key(2, folder.source_nid, folder.output_nid),
                writer::StagedOutcome::kConverted, plan.value().plan,
                auxiliary_details(2, folder.source_nid, folder.output_nid), {}, resources);
            if (!staged.ok())
                return staged.error();
            observe(FullPoint::kFolderCommitted);
        }
        if (!scaffold) {
            std::vector<writer::FolderSummary> children;
            for (const auto& [nid, state] : states) {
                (void)nid;
                if (state.summary.parent_nid == writer::kNidIpmsubtree)
                    children.push_back(state.summary);
            }
            auto plan = writer::build_scaffold_plan(
                manifest.registry.entries(), children, manifest.last_folder_index,
                manifest.last_normal_index, manifest.last_associated_index, resources);
            if (!plan.ok())
                return plan.error();
            auto staged = writer::stage_plan(journal, auxiliary_key(3, 0, 0),
                                             writer::StagedOutcome::kConverted, plan.value().plan,
                                             auxiliary_details(3, 0, 0), {}, resources);
            if (!staged.ok())
                return staged.error();
            observe(FullPoint::kScaffoldCommitted);
        }
        progress.show("assembly", &ledger, manifest.items.size(), 0, true);
        // Payload extraction is finished. Stable input identity uses the still-open file handle;
        // candidate reread must not overlap the source BBT/NBT and retained folder properties.
        states.clear();
        census.bbt_index = ndb::BbtIndex{};
        census.nodes = ltp::NidMap{};
        census.name_id_map = ltp::NameIdMap{};
        auto& candidate = publication.file(writer::PublicationArtifact::kPst);
        auto reset = candidate.resize(0);
        if (!reset.ok())
            return reset.error();
        writer::StagedAssemblyStats assembly;
        observe(FullPoint::kAssemblyBegin);
        ObservedCandidate observed_candidate(candidate, hooks);
        writer::StagedAssemblyOptions assembly_options;
        assembly_options.workspace = resources;
        auto assembled =
            writer::assemble_staged(journal, observed_candidate, assembly_options, &assembly);
        if (!assembled.ok())
            return assembled.error();
        observe(FullPoint::kAssembled);
        const uint64_t candidate_size = candidate.size();
        progress.show("verification", &ledger, manifest.items.size(), 0, true);
        auto closed = publication.close_candidate();
        if (!closed.ok())
            return closed.error();
        observe(FullPoint::kVerificationOpen);
        auto verified = verify_candidate(publication.path(writer::PublicationArtifact::kPst),
                                         candidate_size, manifest, ledger, resources);
        if (!verified.ok())
            return verified.error();
        observe(FullPoint::kVerified);
        auto reopened = publication.reopen_candidate();
        if (!reopened.ok())
            return reopened.error();
        auto stable = file.identity();
        if (!stable.ok())
            return stable.error();
        if (!original.value().same_file(stable.value()) ||
            original.value().size != stable.value().size ||
            original.value().last_write != stable.value().last_write)
            return invalid("full.source_changed", 0, "stable source changed before publication")
                .error();
        auto reported = reports(publication, workspace, journal, manifest, ledger, attempts,
                                recovered, complete, assembly, start, resume, resources);
        if (!reported.ok())
            return reported.error();
        observe(FullPoint::kReportsWritten);
        auto ready = publication.mark_ready();
        if (!ready.ok())
            return ready.error();
        observe(FullPoint::kReady);
    } else if (!scaffold || committed_folders.size() != manifest.folders.size()) {
        return invalid("full.ready_finalization", 0, "sealed output has incomplete finalization")
            .error();
    }
    progress.show("publication", &ledger, manifest.items.size(), 0, true);
    for (const auto artifact :
         {writer::PublicationArtifact::kPst, writer::PublicationArtifact::kSummary,
          writer::PublicationArtifact::kItems}) {
        auto published = publication.publish_one(artifact);
        if (!published.ok())
            return published.error();
        observe(artifact == writer::PublicationArtifact::kPst       ? FullPoint::kPstPublished
                : artifact == writer::PublicationArtifact::kSummary ? FullPoint::kSummaryPublished
                                                                    : FullPoint::kItemsPublished);
    }
    auto finished = publication.finish();
    if (!finished.ok())
        return finished.error();
    observe(FullPoint::kComplete);
    progress.show("published", &ledger, manifest.items.size(), 0, true);
    auto cleaned =
        workspace.cleanup_completed({complete ? 0u : 3u, ledger.totals().terminal}, hooks.cleanup);
    if (!cleaned.ok())
        std::fprintf(stderr, "conversion cleanup incomplete: %s\n",
                     util::format_error(cleaned.error()).c_str());
    std::fprintf(events.enabled() ? stderr : stdout,
                 "CONVERSION RESULT: %s\nrecovered=%llu attempted_normal=%llu attempted_fai=%llu\n",
                 complete ? "complete" : "incomplete", static_cast<unsigned long long>(recovered),
                 static_cast<unsigned long long>(attempts.normal),
                 static_cast<unsigned long long>(attempts.associated));
    return complete ? 0 : 3;
}
} // namespace

int run_full(const std::wstring& input, const std::wstring& output, bool resume,
             const FullConversionHooks& hooks, bool events_json) {
    const auto start = Clock::now();
    bool input_phase = true;
    GuiEvents events(events_json);
    events.start();
    auto result = convert(input, output, resume, start, hooks, input_phase, events);
    int code = 1;
    if (result.ok()) {
        code = result.value();
    } else {
        const auto& error = result.error();
        code = error.kind == ErrorKind::kUnsupported ? 2 : 1;
        if (input_phase)
            code = input_error_exit(error);
        if (error.field.starts_with("full.verify_"))
            code = 3;
        std::fprintf(stderr, "conversion failed: %s\n", util::format_error(error).c_str());
        events.error(error, input_phase);
        std::fprintf(stderr, "{\"schema\":1,\"status\":\"failed\",\"exit_code\":%d,\"field\":%s}\n",
                     code, quoted(error.field).c_str());
    }
    if (events_json) {
        if (result.ok()) {
            if (!events.result(code, output)) {
                events.error(util::make_error(ErrorKind::kIo, "gui.report", 0, 0,
                                              "published aggregate report could not be read"),
                             false);
                code = 1;
                events.result(code, output);
            }
        } else {
            // Exit 3 can be an input/verification failure, not a published incomplete conversion.
            std::fprintf(
                stdout,
                "{\"schema\":1,\"event\":\"result\",\"status\":\"failed\",\"exit_code\":%d}\n",
                code);
            std::fflush(stdout);
        }
    }
    PROCESS_MEMORY_COUNTERS memory{};
    const bool measured =
        GetProcessMemoryInfo(GetCurrentProcess(), &memory, sizeof memory) != FALSE;
    std::fprintf(
        stderr,
        "conversion invocation wall_seconds=%.3f peak_working_set=%llu measured=%s exit=%d\n",
        std::chrono::duration<double>(Clock::now() - start).count(),
        static_cast<unsigned long long>(measured ? memory.PeakWorkingSetSize : 0),
        measured ? "true" : "false", code);
    return code;
}
} // namespace ost2pst::cli
