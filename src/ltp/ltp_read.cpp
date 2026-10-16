// The LTP layer read over a real file: the BBT index, the NBT walk into a NID map, every data block
// opened and classified, every property context and table context walked, the Name-to-ID Map, the
// Search Management Queue, and the folder tree the Messaging layer is built out of.
#include "ost2pst/ltp/ltp_read.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "ost2pst/ltp/block_heap.h"
#include "ost2pst/ltp/bth.h"
#include "ost2pst/ltp/data_tree.h"
#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/hn_block.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/name_id.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/ltp/node_open.h"
#include "ost2pst/ltp/node_value.h"
#include "ost2pst/ltp/pc.h"
#include "ost2pst/ltp/prop_type.h"
#include "ost2pst/ltp/smq.h"
#include "ost2pst/ltp/tc.h"
#include "ost2pst/ndb/bbt_index.h"
#include "ost2pst/ndb/block_reader.h"
#include "ost2pst/ndb/btree.h"
#include "ost2pst/ndb/header.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/ndb/profile.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ltp {

using util::ByteView;
using util::DataError;
using util::ErrorKind;
using util::make_error;
using util::Result;
using util::Status;

const char* ltp_finding_kind_name(LtpFindingKind kind) {
    switch (kind) {
    case LtpFindingKind::kDocumentedNonHeapNode:
        return "documented non-heap node";
    case LtpFindingKind::kUnsupportedStructure:
        return "unsupported structure";
    case LtpFindingKind::kDecodeFailure:
        return "decode failure";
    }
    return "finding";
}

void LtpFindingTally::record(LtpFindingKind kind, uint64_t nid, uint64_t bid,
                             const std::string& field, const std::string& detail) {
    ++total;
    switch (kind) {
    case LtpFindingKind::kDocumentedNonHeapNode:
        ++documented_non_heap;
        break;
    case LtpFindingKind::kUnsupportedStructure:
        ++unsupported;
        break;
    case LtpFindingKind::kDecodeFailure:
        ++decode_failures;
        break;
    }
    if (items.size() >= max_items) {
        return;
    }
    LtpFinding finding;
    finding.kind = kind;
    finding.nid = nid;
    finding.nid_type = static_cast<uint32_t>(nid_type(nid));
    finding.bid = bid;
    finding.field = field;
    finding.detail = detail;
    items.push_back(std::move(finding));
}

// [MS-PST] 2.2.2.1 decides whether the nidType promised a heap node at all; [MS-PST] 2.4.8.3
// / 2.4.8.4 / 2.4.8.5 name the predefined internal nodes that hold an array of NIDs, a queue of
// fixed-size items, or an opaque BLOB instead. Anything else -- a nidType the table does not name,
// or an internal nidIndex it does not name -- is a structure this reader cannot say anything about,
// and that is reported as such instead of being counted as a successful read.
LtpFindingKind classify_missing_heap_node(uint64_t nid) {
    const uint32_t type = static_cast<uint32_t>(nid_type(nid));
    if (nid_type_announces_heap_node(type)) {
        return LtpFindingKind::kDecodeFailure;
    }
    if (*documented_non_heap_internal_nid_name(nid) != '\0') {
        return LtpFindingKind::kDocumentedNonHeapNode;
    }
    if (*documented_heap_internal_nid_name(nid) != '\0') {
        return LtpFindingKind::kDecodeFailure; // the spec says this node is a PC, so its block is
                                               // wrong
    }
    return LtpFindingKind::kUnsupportedStructure;
}

Status validate_guid_map(const HnHeader& header, ndb::FileProfile profile, HeapSource& source,
                         BthStats& stats, ndb::FailureLog& failures) {
    const auto root = source.heap(header.hid_user_root);
    if (!root.ok())
        return root.error();
    if (root.value().size() != 4) {
        return make_error(ErrorKind::kBadField, "GUIDMAP.root", root.value().base(),
                          root.value().size(), "libpff 9c table header is one DWORD HID");
    }
    const uint32_t bth_hid = root.value().u32(0).value();
    const auto bytes = source.heap(bth_hid);
    if (!bytes.ok())
        return bytes.error();
    const auto bth = decode_bth_header(bytes.value(), profile);
    if (!bth.ok())
        return bth.error();
    if (bth.value().cb_key != 16 || bth.value().cb_ent != 4) {
        return make_error(ErrorKind::kBadField, "GUIDMAP.BTHHEADER", bytes.value().base(),
                          bth.value().cb_key, "libpff 9c BTH needs GUID keys and DWORD values");
    }
    const uint64_t base = bytes.value().base();
    const auto walked = walk_bth(
        bth.value(), profile, source, [](const BthLeafRecord&) { return true; }, stats, failures);
    if (!walked.ok())
        return walked;
    if (stats.skipped_records || stats.trailing_bytes || stats.stopped_early) {
        return make_error(ErrorKind::kBadField, "GUIDMAP.BTH", base, stats.skipped_records,
                          "GUID map BTH was only partially read");
    }
    return Status{};
}

Result<std::vector<uint32_t>> decode_search_activity_list(ByteView bytes) {
    if (bytes.size() % 4 != 0) {
        return make_error(ErrorKind::kBadField, "SAL.rgnid", bytes.base(), bytes.size(),
                          "Search Activity List must contain whole DWORD NIDs");
    }
    std::vector<uint32_t> nids;
    for (size_t at = 0; at < bytes.size(); at += 4)
        nids.push_back(bytes.u32(at).value());
    return nids;
}

namespace {

// NameID parsing consumes owned stream copies. Reserve construction/copy allowance before
// capturing each window, so a large global stream cannot bypass the index ceiling.
class BudgetedValues final : public ValueSource {
  public:
    BudgetedValues(ValueSource& source, util::ByteBudget& budget)
        : source_(source), budget_(budget) {}
    Result<ByteView> value(uint32_t hnid) override {
        held_.clear();
        auto result = source_.stream(hnid, [&](ByteView part) -> Status {
            auto reserved = budget_.reserve(4 * part.size(), "NameID.workspace", part.base());
            if (!reserved.ok())
                return reserved;
            held_.insert(held_.end(), part.data(), part.data() + part.size());
            return {};
        });
        if (!result.ok())
            return result.error();
        return ByteView(held_.data(), held_.size());
    }

  private:
    ValueSource& source_;
    util::ByteBudget& budget_;
    std::vector<uint8_t> held_;
};

void tally(std::map<std::string, uint64_t>& tallies, const std::string& key) {
    tallies[key] += 1;
}

void tally(std::map<std::string, uint64_t>& tallies, const DataError& error) {
    tallies[error.field] += 1;
}

std::string hex_id(uint64_t value) {
    char text[24];
    std::snprintf(text, sizeof(text), "0x%llX", static_cast<unsigned long long>(value));
    return text;
}

// A PST string is Unicode and the spec never null terminates one ([MS-PST] 2.4.7.4 for the
// Name-to-ID Map, 2.3.3.3 for a PC value), but Outlook writes a terminator anyway. The decode stops
// at the first NUL and never reads past the bytes it was handed.
std::u16string decode_utf16(ByteView bytes) {
    std::u16string text;
    for (uint64_t offset = 0; offset + 1 < bytes.size(); offset += 2) {
        Result<uint16_t> unit = bytes.u16(offset);
        if (!unit.ok()) {
            break;
        }
        if (unit.value() == 0) {
            break;
        }
        text.push_back(static_cast<char16_t>(unit.value()));
    }
    return text;
}

// PtypString8 is a single-byte code page. Anything outside printable ASCII becomes a hex escape so
// a dump never drops a stray byte into the terminal.
std::string decode_ansi(ByteView bytes) {
    std::string text;
    for (size_t index = 0; index < bytes.size(); ++index) {
        const uint8_t byte = bytes.data()[index];
        if (byte == 0) {
            break;
        }
        if (byte >= 0x20 && byte < 0x7F) {
            text.push_back(static_cast<char>(byte));
        } else {
            char escape[8];
            std::snprintf(escape, sizeof(escape), "<%02X>", byte);
            text += escape;
        }
    }
    return text;
}

std::string truncate_text(std::string text, size_t limit) {
    if (text.size() <= limit) {
        return text;
    }
    // Cut on a UTF-8 boundary: a lead byte is the only byte that is not a continuation byte.
    size_t end = limit;
    while (end > 0 && (static_cast<uint8_t>(text[end]) & 0xC0u) == 0x80u) {
        --end;
    }
    return text.substr(0, end) + "...";
}

// One property context read out of an already-open node, tallied into the PC counters. The callback
// decides whether a record is kept as well as counted, which is what lets the folder walk pick out
// a display name and the census keep nothing but numbers.
//
// `findings` belongs to the pass that owns this node's classification. A context whose own bytes
// contradict what bClientSig announced is a statement about that node, and a counter alone cannot
// say which node it was -- counting `failed` without recording the finding is what let a file with
// an unreadable Property Context still read clean. A caller that re-reads a node the census already
// classified passes nullptr, so one node is never counted twice.
bool scan_property_context(const NodeHeap& node, uint64_t nid, uint8_t nid_type,
                           LtpPcCounters& counters, LtpFindingTally* findings,
                           ndb::FailureLog& failures, const PcCallback& callback) {
    ++counters.contexts;
    ++counters.nid_types[nid_type];
    if (!node.page_map_ok) {
        ++counters.failed; // open_node already recorded why the page map failed
        return false;
    }
    HeapSource& heap_source = *node.source;
    BthStats stats;
    // max_records is the widest single context, so it counts this context's own records, not the
    // running total the callback tallies across the whole file.
    uint64_t here = 0;
    const Status walked = read_pc(
        node.header, node.profile, heap_source,
        [&](const PcRecord& record) {
            ++here;
            return callback(record);
        },
        stats, failures);
    if (!walked.ok()) {
        ++counters.failed;
        if (findings != nullptr) {
            findings->record(LtpFindingKind::kDecodeFailure, nid, node.bid, walked.error().field,
                             walked.error().detail);
        }
        return false;
    }
    if (here > counters.max_records) {
        counters.max_records = here;
    }
    return true;
}

// One table context of one Folder object. `present` answers "does this Folder object have that
// table at all", which is a fact about the NBT, not a finding: a folder with no associated-messages
// table simply has none.
struct TableRead {
    bool present = false;
    bool read = false;
    uint64_t rows = 0;
    std::vector<uint32_t> row_ids;
};

constexpr size_t kMaxKeptRowIds =
    200000; // [MS-PST] 2.3.4.3.1 dwRowIndex is 32-bit, so a corrupt RowIndex needs a cap

// Opens the sibling of a Folder object that carries `nid_type` and walks its RowIndex.
void read_folder_table(const NidMap& nodes, BlockSource& blocks, uint64_t folder_nid,
                       uint32_t nid_type, ndb::FileProfile profile, LtpHeapCounters& heap,
                       DataTreeCounters& data_trees, std::map<std::string, uint64_t>& errors,
                       TableRead& out, bool keep_rows, ndb::FailureLog& failures) {
    Result<NodeRef> sibling = nodes.sibling(folder_nid, nid_type);
    if (!sibling.ok()) {
        return;
    }
    out.present = true;
    if (sibling.value().bid_data == 0) {
        return; // [MS-PST] 2.2.2.7.7.4: bidData zero means the entry names no data block
    }
    NodeHeap node;
    // The census pass already opened and classified this node, so the folder walk re-opens it
    // without recording a finding a second time.
    if (open_node(blocks, profile, sibling.value().nid, sibling.value().bid_data, node, heap,
                  data_trees, errors, nullptr, failures) != NodeOpen::kOk) {
        return;
    }
    if (node.header.b_client_sig != kClientSigTc) {
        tally(errors, "HNHDR.bClientSig");
        return;
    }
    if (!node.page_map_ok) {
        tally(errors, "HNPAGEMAP");
        return;
    }
    HeapSource& heap_source = *node.source;
    Result<TcTable> table = read_tc(node.header, heap_source);
    if (!table.ok()) {
        tally(errors, table.error());
        return;
    }
    out.read = true;
    BthStats stats;
    const Status walked = walk_tc_row_index(
        table.value(), node.profile, heap_source,
        [&](const TcRowId& row) {
            ++out.rows;
            if (keep_rows && out.row_ids.size() < kMaxKeptRowIds) {
                out.row_ids.push_back(row.row_id);
            }
            return true;
        },
        stats, failures);
    if (!walked.ok()) {
        tally(errors, walked.error());
    }
}

// The name of one folder: PidTagDisplayName out of the Folder object's own Property Context
// ([MS-PST] 2.4.4.4.1). The value is a string, so it is resolved through the node's heap and its
// subnodes exactly the way every other variable-size value is.
void read_folder_name(const NodeRef& ref, BlockSource& blocks, LtpHeapCounters& heap,
                      ndb::FileProfile profile, DataTreeCounters& data_trees,
                      SubnodeStats& subnodes, std::map<std::string, uint64_t>& errors,
                      LtpFolder& folder, uint64_t& pcs_read, ndb::FailureLog& failures) {
    if (ref.bid_data == 0) {
        return;
    }
    NodeHeap node;
    if (open_node(blocks, profile, ref.nid, ref.bid_data, node, heap, data_trees, errors, nullptr,
                  failures) != NodeOpen::kOk) {
        return;
    }
    if (node.header.b_client_sig != kClientSigPc) {
        return;
    }
    folder.has_pc = true;
    HeapSource& heap_source = *node.source;
    NodeValueSource values(heap_source, ref.bid_sub, profile, blocks, subnodes, data_trees,
                           failures);
    LtpPcCounters name_counters; // the folder's own PC is already counted by the census pass
    scan_property_context(node, ref.nid, static_cast<uint8_t>(nid_type(ref.nid)), name_counters,
                          nullptr, failures, [&](const PcRecord& record) {
                              if (record.prop_id != kPropDisplayName || folder.name_present) {
                                  return true;
                              }
                              if (record.value_absent) {
                                  // The Folder object says it has a display name and that name is
                                  // empty, which is a fact about the folder, not a broken
                                  // reference.
                                  folder.name.clear();
                                  folder.name_present = true;
                                  return true;
                              }
                              Result<ByteView> bytes = values.value(record.value_hnid);
                              if (!bytes.ok()) {
                                  failures.add(bytes.error());
                                  return true;
                              }
                              folder.name = name_id_utf8(decode_utf16(bytes.value()));
                              folder.name_present = true;
                              return true;
                          });
    ++pcs_read;
}

} // namespace

Status walk_folder_tree(const NidMap& nodes, BlockSource& blocks, uint64_t root_nid,
                        const FolderWalkOptions& options, ndb::FileProfile profile,
                        std::vector<LtpFolder>& folders, FolderWalkStats& stats,
                        ndb::FailureLog& failures) {
    Result<NodeRef> root = nodes.node(root_nid);
    if (!root.ok()) {
        return root.error();
    }

    // [MS-PST] 2.4.4.4.2: the hierarchy table's rows are the sub-Folder objects of this Folder
    // object, and a TCROWID's dwRowID IS their NID. Depth-first over those rows is the whole tree,
    // and the visited set is what stops a corrupt table from walking a cycle forever. Depth-first
    // is also what makes the folder list come out in tree order, which is what the CLI prints.
    LtpHeapCounters heap;
    std::map<std::string, uint64_t> errors;
    uint64_t pcs_read = 0;
    std::unordered_set<uint64_t> visited;
    std::vector<std::pair<uint64_t, uint32_t>> stack;
    stack.emplace_back(root_nid, 0);
    visited.insert(root_nid);

    while (!stack.empty()) {
        if (options.max_folders != 0 && folders.size() >= options.max_folders) {
            ++stats.stopped_early;
            break;
        }
        const uint64_t nid = stack.back().first;
        const uint32_t depth = stack.back().second;
        stack.pop_back();
        if (depth > stats.max_depth) {
            stats.max_depth = depth;
        }

        Result<NodeRef> ref = nodes.node(nid);
        if (!ref.ok()) {
            ++stats.missing;
            continue;
        }

        LtpFolder folder;
        folder.nid = nid;
        folder.parent = ref.value().nid_parent;
        folder.depth = depth;
        read_folder_name(ref.value(), blocks, heap, profile, stats.data_trees, stats.subnodes,
                         errors, folder, pcs_read, failures);

        TableRead hierarchy;
        read_folder_table(nodes, blocks, nid, kNidTypeHierarchyTable, profile, heap,
                          stats.data_trees, errors, hierarchy, true, failures);
        TableRead contents;
        read_folder_table(nodes, blocks, nid, kNidTypeContentsTable, profile, heap,
                          stats.data_trees, errors, contents, false, failures);
        TableRead associated;
        read_folder_table(nodes, blocks, nid, kNidTypeAssocContentsTable, profile, heap,
                          stats.data_trees, errors, associated, false, failures);

        folder.children = hierarchy.rows;
        folder.messages = contents.rows;
        folder.associated = associated.rows;
        folder.parent_messages = nodes.children(static_cast<uint32_t>(nid), kNidTypeNormalMessage);
        folder.parent_associated = nodes.children(static_cast<uint32_t>(nid), kNidTypeAssocMessage);
        folder.has_hierarchy = hierarchy.read;
        folder.has_contents = contents.read;
        folder.has_associated = associated.read;
        stats.tcs_read +=
            (hierarchy.read ? 1 : 0) + (contents.read ? 1 : 0) + (associated.read ? 1 : 0);
        stats.tc_rows += hierarchy.rows + contents.rows + associated.rows;

        std::vector<uint64_t> children;
        for (uint32_t row_id : hierarchy.row_ids) {
            const uint64_t child = row_id;
            if (!visited.insert(child).second) {
                ++stats.cycles; // the same NID reached twice: a hierarchy table that is not a tree
                continue;
            }
            if (!nodes.node(child).ok()) {
                ++stats.missing; // a row whose dwRowID names a NID the NBT does not carry
                continue;
            }
            if (depth >= options.max_depth) {
                ++stats
                      .depth_capped; // max_depth is the deepest level this walk is allowed to enter
                continue;
            }
            children.push_back(child);
        }
        // Pushed in reverse so the folders come out in the order the hierarchy table lists them.
        for (auto next = children.rbegin(); next != children.rend(); ++next) {
            stack.emplace_back(*next, depth + 1);
        }

        ++stats.folders;
        folders.push_back(folder);
    }

    stats.blocks_read = heap.blocks_read;
    stats.blocks_failed = heap.blocks_failed;
    stats.not_heap_node = heap.heap_nodes_rejected;
    stats.pcs_read = pcs_read;
    return {};
}

std::string render_property_value(const PcRecord& record, ValueSource& values) {
    const PropTypeInfo info = prop_type_info(record.prop_type);
    char text[96];

    if (record.value_inline) {
        // [MS-PST] 2.3.3.3: for a single-valued fixed-size type of 4 bytes or less, dwValueHnid is
        // the value itself, so the four bytes the record already carries are the answer.
        const ByteView raw = record.value;
        if (info.fixed_size == 1) {
            const Result<uint8_t> value = raw.u8(0);
            if (value.ok()) {
                return std::to_string(value.value());
            }
        } else if (info.fixed_size == 2) {
            const Result<uint16_t> value = raw.u16(0);
            if (value.ok()) {
                return std::to_string(value.value());
            }
        } else {
            const Result<uint32_t> value = raw.u32(0);
            if (value.ok()) {
                return std::to_string(value.value());
            }
        }
        return "unreadable";
    }

    if (record.value_absent) {
        return "(no value)";
    }
    const Result<ByteView> bytes = values.value(record.value_hnid);
    if (!bytes.ok()) {
        std::snprintf(text, sizeof(text), "unresolved HNID %s", hex_id(record.value_hnid).c_str());
        return text;
    }
    if ((record.prop_type & kPropTypeMultiValuedFlag) != 0) {
        // [MS-PST] 2.3.3.4: a multi-valued value is an MVLM array. This reader sizes it; decoding
        // the array is M3's job.
        std::snprintf(text, sizeof(text), "%zu bytes (multi-valued)", bytes.value().size());
        return text;
    }
    const uint16_t base = static_cast<uint16_t>(record.prop_type & ~kPropTypeMultiValuedFlag);
    if (base == 0x001F) {
        return truncate_text(name_id_utf8(decode_utf16(bytes.value())), 200);
    }
    if (base == 0x001E) {
        return truncate_text(decode_ansi(bytes.value()), 200);
    }
    std::snprintf(text, sizeof(text), "%zu bytes", bytes.value().size());
    return text;
}

Result<LtpReadReport> read_ltp(const util::FileReader& file, const LtpReadOptions& options) {
    std::vector<uint8_t> header_bytes(static_cast<size_t>(ndb::kHeaderSize));
    const Status io = file.read_at(ndb::kHeaderOffset, header_bytes.data(), header_bytes.size());
    if (!io.ok()) {
        return io.error();
    }
    const ByteView header_view(header_bytes.data(), header_bytes.size(), ndb::kHeaderOffset);
    const Result<ndb::Header> header = ndb::decode_header(header_view);
    if (!header.ok()) {
        return header.error();
    }

    LtpReadReport report;
    report.header = header.value();
    const Status refusal = ndb::validate_header_refusals(report.header);
    if (!refusal.ok()) {
        report.refusal = refusal.error();
        report.clean = false;
        return report;
    }

    const Result<ndb::FileProfile> profile =
        ndb::detect_profile(file, report.header.root.bbt_bref.ib);
    if (!profile.ok()) {
        return profile.error();
    }
    report.profile = profile.value();
    report.profile_evidence = std::string(ndb::file_profile_name(report.profile)) +
                              ": the root BBT page at " + hex_id(report.header.root.bbt_bref.ib) +
                              " has a valid trailer and dwCRC";

    ndb::FailureLog failures(options.max_failures);
    report.findings.max_items = options.max_failures;

    util::ByteBudget index_workspace(options.index_workspace_budget);
    auto* budget = options.index_workspace_budget ? &index_workspace : nullptr;
    Status walked;
    {
        ndb::BTreeWalker btree(ndb::kPageTypeBBT, report.profile, &failures, budget);
        walked = btree.walk(file, report.header.root.bbt_bref.ib);
        if (!walked.ok())
            return walked.error();
        report.bbt = btree.stats();
        report.bbt_index = ndb::BbtIndex(btree.bbt_index());
    }
    const ndb::BbtIndex& index = report.bbt_index;

    // Every data block an NBTENTRY names is opened and classified inside the walk itself: the BBT
    // index the block seam needs already exists by then, and a leaf callback keeps a big mailbox
    // from ever materialising its entries at once.
    FileBlockSource blocks(file, report.profile, index, report.blocks, failures);
    NidMap nodes;
    ndb::BTreeWalker nbt(ndb::kPageTypeNBT, report.profile, &failures, budget);
    nbt.set_nbt_handler([&](const ndb::NbtEntry& entry, uint64_t) {
        nodes.add(entry);
        ++report.nid_entries;
        const uint8_t type = static_cast<uint8_t>(nid_type(entry.nid));
        ++report.nid_types[type];
        if (entry.bid_data != 0) {
            ++report.nid_with_bid_data;
        }
        if (entry.bid_sub != 0) {
            ++report.nid_with_bid_sub;
        }
        if (!options.scan_blocks || entry.bid_data == 0) {
            return;
        }

        // [MS-PST] 2.4.8.4.2 identifies this exact internal NID as an array.
        // Do not feed it to HNHDR or reinterpret other unknown internal node types.
        if (entry.nid == 0x201) {
            const auto data =
                read_data_tree(blocks, entry.bid_data, report.profile, report.data_trees, failures);
            if (!data.ok()) {
                tally(report.errors, data.error());
                report.findings.record(LtpFindingKind::kDecodeFailure, entry.nid, entry.bid_data,
                                       data.error().field, data.error().detail);
                return;
            }
            std::vector<uint8_t> bytes;
            uint64_t base = 0;
            for (const auto& fragment : data.value()) {
                const auto view = fragment.block.heap_node();
                if (bytes.empty())
                    base = view.base();
                bytes.insert(bytes.end(), view.data(), view.data() + view.size());
            }
            auto sal = decode_search_activity_list(ByteView(bytes.data(), bytes.size(), base));
            if (!sal.ok()) {
                tally(report.errors, sal.error());
                report.findings.record(LtpFindingKind::kDecodeFailure, entry.nid, entry.bid_data,
                                       sal.error().field, sal.error().detail);
            } else {
                report.search_activity_nids = sal.take();
                report.sal_read = true;
            }
            return;
        }

        NodeHeap node;
        if (open_node(blocks, report.profile, entry.nid, entry.bid_data, node, report.heap,
                      report.data_trees, report.errors, &report.findings,
                      failures) != NodeOpen::kOk) {
            return;
        }
        if (node.header.b_client_sig == kClientSigPc) {
            scan_property_context(node, entry.nid, type, report.pcs, &report.findings, failures,
                                  [&](const PcRecord& record) {
                                      ++report.pcs.records;
                                      ++report.pcs.prop_types[record.prop_type];
                                      if (record.value_inline) {
                                          ++report.pcs.inline_values;
                                      } else if (record.value_absent) {
                                          ++report.pcs.no_values;
                                      } else if (record.value_in_heap) {
                                          ++report.pcs.heap_values;
                                      } else {
                                          ++report.pcs.subnode_values;
                                      }
                                      return true;
                                  });
            return;
        }
        // libpff "The 9c table" documents this client independently of nidType.
        if (node.header.b_client_sig == 0x9C) {
            if (!node.page_map_ok)
                return; // open_node already reported the failed map
            BthStats stats;
            const auto checked =
                validate_guid_map(node.header, node.profile, *node.source, stats, failures);
            if (!checked.ok()) {
                tally(report.errors, checked.error());
                report.findings.record(LtpFindingKind::kDecodeFailure, entry.nid, entry.bid_data,
                                       checked.error().field, checked.error().detail);
            } else {
                ++report.guid_maps_read;
                report.guid_map_records += stats.leaf_records;
            }
            return;
        }
        if (node.header.b_client_sig != kClientSigTc) {
            // [MS-PST] 2.3.1.2 predefines nine bClientSig values and says every other one is
            // reserved and MUST NOT be used. A heap node carrying one of the reserved values is a
            // structure this reader cannot interpret; the libpff notes name those values as table
            // variants the spec does not define (libpff format notes (see THIRD_PARTY_NOTICES.txt):1455-1470), so
            // the node is reported as a structure that was not read instead of counted as one that
            // was.
            report.findings.record(LtpFindingKind::kUnsupportedStructure, entry.nid, entry.bid_data,
                                   "HNHDR.bClientSig",
                                   std::string("bClientSig ") + hex_id(node.header.b_client_sig) +
                                       " " + client_sig_name(node.header.b_client_sig) +
                                       ": this reader does not implement this heap client");
            return;
        }
        ++report.tcs.contexts;
        ++report.tcs.nid_types[type];
        if (!node.page_map_ok) {
            ++report.tcs.failed; // open_node already recorded why the page map failed
            return;
        }
        HeapSource& heap_source = *node.source;
        const Result<TcTable> table = read_tc(node.header, heap_source);
        if (!table.ok()) {
            ++report.tcs.failed;
            tally(report.errors, table.error());
            report.findings.record(LtpFindingKind::kDecodeFailure, entry.nid, entry.bid_data,
                                   table.error().field, table.error().detail);
            return;
        }
        const TcInfo& info = table.value().info;
        report.tcs.columns += info.c_cols;
        if (info.c_cols > report.tcs.max_columns) {
            report.tcs.max_columns = info.c_cols;
        }
        if (info.hnid_rows == 0) {
            ++report.tcs.columns_only;
        } else if (hid_type(info.hnid_rows) == kHidTypeHid) {
            ++report.tcs.matrix_in_heap;
        } else {
            ++report.tcs.matrix_in_subnode;
        }
        BthStats stats;
        uint64_t here = 0;
        const Status rows = walk_tc_row_index(
            table.value(), node.profile, heap_source,
            [&](const TcRowId&) {
                ++report.tcs.rows;
                ++here;
                return true;
            },
            stats, failures);
        if (!rows.ok()) {
            ++report.tcs.failed;
            tally(report.errors, rows.error());
            report.findings.record(LtpFindingKind::kDecodeFailure, entry.nid, entry.bid_data,
                                   rows.error().field, rows.error().detail);
        }
        if (here > report.tcs.max_rows) {
            report.tcs.max_rows = here;
        }
    });
    walked = nbt.walk(file, report.header.root.nbt_bref.ib);
    if (!walked.ok()) {
        return walked.error();
    }
    report.nbt = nbt.stats();
    report.nid_groups = nodes.groups();
    report.nid_duplicates = nodes.duplicates();
    report.index_workspace_bytes = index_workspace.used();

    // The Name-to-ID Map ([MS-PST] 2.4.7) is a Property Context whose properties are the map's own
    // streams, and in an OST those streams sit in the node's subnodes. The Search Management Queue
    // ([MS-PST] 2.4.8.4.1) is a queue node, not a heap node at all. Both are opened through a
    // second block source with its own counters, so the census above stays exactly "every
    // NBTENTRY.bidData".
    ndb::BlockReadCounters targeted_blocks;
    FileBlockSource other(file, report.profile, index, targeted_blocks, failures);
    LtpHeapCounters targeted;

    const Result<NodeRef> npm = nodes.node(kNidNameToIdMap);
    if (npm.ok() && npm.value().bid_data != 0) {
        NodeHeap node;
        if (open_node(other, report.profile, npm.value().nid, npm.value().bid_data, node, targeted,
                      report.data_trees, report.errors, nullptr, failures,
                      budget) == NodeOpen::kOk &&
            node.header.b_client_sig == kClientSigPc && node.page_map_ok) {
            HeapSource& heap_source = *node.source;
            NodeValueSource values(heap_source, npm.value().bid_sub, report.profile, other,
                                   report.subnodes, report.data_trees, failures);
            std::vector<PcRecord> properties;
            LtpPcCounters npm_counters;
            scan_property_context(
                node, npm.value().nid, static_cast<uint8_t>(nid_type(npm.value().nid)),
                npm_counters, nullptr, failures, [&](const PcRecord& record) {
                    if (budget) {
                        auto reserved = budget->reserve(4 * sizeof(PcRecord), "NameID.workspace");
                        if (!reserved.ok())
                            return false;
                    }
                    properties.push_back(record);
                    return true;
                });
            BudgetedValues bounded(values, index_workspace);
            Result<NameIdMap> map =
                read_name_id_map(properties, budget ? static_cast<ValueSource&>(bounded) : values,
                                 report.npm, failures, budget);
            if (map.ok()) {
                report.npm_read = true;
                report.named_properties = map.value().entries.size();
                // Kept so a node dump can say what a named property is called and which property
                // set it belongs to ([MS-PST] 2.4.7.1).
                report.name_id_map = map.take();
            } else {
                tally(report.errors, map.error());
                report.findings.record(LtpFindingKind::kDecodeFailure, npm.value().nid,
                                       npm.value().bid_data, map.error().field, map.error().detail);
            }
        }
    }
    if (budget && budget->error())
        return *budget->error();
    report.index_workspace_bytes = index_workspace.used();

    const Result<NodeRef> smq = nodes.node(kNidSearchManagementQueue);
    if (smq.ok()) {
        report.smq_present = true;
        if (smq.value().bid_data != 0) {
            NodeHeap node;
            if (open_node(other, report.profile, smq.value().nid, smq.value().bid_data, node,
                          targeted, report.data_trees, report.errors, nullptr,
                          failures) == NodeOpen::kOk) {
                const Result<SmqReport> queue =
                    read_smq(smq.value().nid_parent, node.block.bytes(), failures);
                if (queue.ok()) {
                    report.smq = queue.value().queue;
                    for (const auto& item : queue.value().by_type) {
                        report.sud_types[item.first] += item.second;
                    }
                } else {
                    tally(report.errors, queue.error());
                    report.findings.record(LtpFindingKind::kDecodeFailure, smq.value().nid,
                                           smq.value().bid_data, queue.error().field,
                                           queue.error().detail);
                }
            }
        } else {
            // [MS-PST] 2.4.8.3: a queue node whose cbData is zero has been drained completely. This
            // OST goes one step further and gives the node no data block at all.
            report.smq.item_size = kSudSize;
            report.smq.head_offset = smq.value().nid_parent;
        }
    }

    if (options.build_folders) {
        const Status tree =
            walk_folder_tree(nodes, other, kNidRootFolder, options.folders, report.profile,
                             report.folders, report.folder_stats, failures);
        if (!tree.ok()) {
            tally(report.errors, tree.error());
            failures.add(tree.error());
            report.findings.record(LtpFindingKind::kDecodeFailure, kNidRootFolder, 0,
                                   tree.error().field, tree.error().detail);
        }
        merge_data_tree_counters(report.data_trees, report.folder_stats.data_trees);
        merge_subnode_stats(report.subnodes, report.folder_stats.subnodes);
    }

    if (options.dump_requested) {
        const Result<NodeRef> ref = nodes.node(options.dump_nid);
        if (!ref.ok()) {
            return ref.error(); // the CLI reports an NID the file does not carry as a failed read
        }
        LtpNodeDump dump;
        dump.nid = ref.value().nid;
        dump.bid_data = ref.value().bid_data;
        dump.bid_sub = ref.value().bid_sub;
        dump.nid_parent = ref.value().nid_parent;

        NodeHeap node;
        NodeOpen opened = NodeOpen::kUnreadable;
        if (ref.value().bid_data != 0) {
            opened = open_node(other, report.profile, ref.value().nid, ref.value().bid_data, node,
                               targeted, report.data_trees, report.errors, nullptr, failures);
        }
        if (ref.value().bid_data == 0) {
            report.dump_error = make_error(ErrorKind::kUnsupported, "NBTENTRY.bidData", 0, dump.nid,
                                           "this node carries no data block to dump");
        } else if (opened == NodeOpen::kUnreadable) {
            report.dump_error =
                make_error(ErrorKind::kUnsupported, "NBTENTRY.bidData", 0, ref.value().bid_data,
                           "this node's data block could not be read");
        } else if (opened == NodeOpen::kDataTreeFailed) {
            // [MS-PST] 2.2.2.8.3.2: the node's data lives in blocks this node's jump table names,
            // and that tree did not resolve, so there is nothing trustworthy to dump properties out
            // of.
            report.dump_error = make_error(
                ErrorKind::kUnsupported, "XBLOCK.rgid", node.ib, node.bid,
                "this node's data tree does not resolve, so its data blocks are unknown");
        } else if (opened == NodeOpen::kNotHeapNode) {
            // [MS-PST] 2.4.8.3: a queue node and a plain array of NIDs are data blocks the NBT
            // names, but they carry no HNHDR, so there is no heap node to read properties out of.
            report.dump_error =
                make_error(ErrorKind::kUnsupported, "HNHDR.bSig", node.ib, 0,
                           "this data block carries no HNHDR, so it has no properties to dump");
        } else if (node.header.b_client_sig == kClientSigPc && node.page_map_ok) {
            dump.client_sig = node.header.b_client_sig;
            dump.heap_bytes = node.block.heap_node().size();
            dump.allocations = node.page_map.c_alloc;
            HeapSource& heap_source = *node.source;
            NodeValueSource values(heap_source, ref.value().bid_sub, report.profile, other,
                                   report.subnodes, report.data_trees, failures);
            LtpPcCounters dump_counters;
            scan_property_context(node, dump.nid, static_cast<uint8_t>(nid_type(dump.nid)),
                                  dump_counters, nullptr, failures, [&](const PcRecord& record) {
                                      dump.properties.push_back(record);
                                      return true;
                                  });
            for (const PcRecord& record : dump.properties) {
                const bool answerable = record.value_inline || record.value_absent ||
                                        values.value(record.value_hnid).ok();
                const uint32_t tag =
                    (static_cast<uint32_t>(record.prop_id) << kTcTagPropIdShift) | record.prop_type;
                LtpPropertyValue item;
                item.tag = tag;
                item.value = render_property_value(record, values);
                // [MS-PST] 2.4.7.1: an NPID is 0x8000 plus wPropIdx, so a tag in that range is a
                // named property, and only the Name-to-ID Map says what it is called and which
                // property set it belongs to. The same string name under another property set is
                // another property.
                if (record.prop_id >= kNpidBase) {
                    item.named = true;
                    const Result<NamedProperty> named =
                        name_id_lookup_npid(report.name_id_map, record.prop_id);
                    if (named.ok()) {
                        item.name_resolved = named.value().name_resolved;
                        item.name_is_string = named.value().name_is_string;
                        item.name = named.value().name;
                        item.numeric_name = named.value().numeric_name;
                        item.guid_index = named.value().guid_index;
                        item.guid_kind = named.value().guid_kind;
                        item.guid_resolved = named.value().guid_resolved;
                        item.guid_from_file = named.value().guid_from_file;
                        item.guid = named.value().guid;
                    } else {
                        ++dump.named_unresolved;
                    }
                }
                dump.values.push_back(std::move(item));
                if (answerable) {
                    ++dump.values_resolved;
                } else {
                    ++dump.values_unresolved;
                }
            }
        } else if (node.header.b_client_sig == kClientSigTc && node.page_map_ok) {
            dump.client_sig = node.header.b_client_sig;
            dump.heap_bytes = node.block.heap_node().size();
            dump.allocations = node.page_map.c_alloc;
            HeapSource& heap_source = *node.source;
            const Result<TcTable> table = read_tc(node.header, heap_source);
            if (table.ok()) {
                for (const TcColumn& column : table.value().columns) {
                    char text[96];
                    std::snprintf(text, sizeof(text), "column ibData %u cbData %u iBit %u",
                                  static_cast<unsigned>(column.ib_data),
                                  static_cast<unsigned>(column.cb_data),
                                  static_cast<unsigned>(column.i_bit));
                    LtpPropertyValue item;
                    item.tag = column.tag;
                    item.value = text;
                    dump.values.push_back(std::move(item));
                    ++dump.values_resolved;
                }
            } else {
                report.dump_error = table.error();
            }
        } else {
            report.dump_error = make_error(
                ErrorKind::kUnsupported, "HNHDR.bClientSig", node.ib, node.header.b_client_sig,
                std::string("this heap node carries ") + client_sig_name(node.header.b_client_sig) +
                    ", which has no properties to dump");
        }
        for (PcRecord& record : dump.properties) {
            record.value = ByteView(); // the inline bytes it pointed at belong to this scope
        }
        report.dump = dump;
    }

    // Every use above is done, so the map the walk built moves into the report for the layer above.
    report.nodes = std::move(nodes);
    report.failure_total = failures.total();
    report.failures = failures.failures();
    // A data tree counts its findings in its own tally; the report's error table is where the
    // reader sees them, so the two are merged before anything is judged clean.
    for (const auto& item : report.data_trees.errors) {
        report.errors[item.first] += item.second;
    }
    // "clean" is a statement about what the reader attempted, not about the whole file: every
    // structure it opened decoded, and nothing it opened contradicted its own metadata. A logged
    // finding or a decode failure always makes this false. A documented non-heap node or a
    // structure the literature names but this reader does not decode is not a failure -- it is
    // itemized in `findings` and has to be justified in the milestone evidence, which is what the
    // old "HNPAGEMAP.cAlloc 1 next to RESULT: clean" hid.
    report.clean = report.failure_total == 0 && report.findings.decode_failures == 0;
    return report;
}

} // namespace ost2pst::ltp
