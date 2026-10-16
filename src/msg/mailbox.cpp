#include "ost2pst/msg/mailbox.h"

#include <limits>
#include <set>
#include <tuple>

#include "ost2pst/ltp/layout.h"

namespace ost2pst::msg {
namespace {
using util::ErrorKind;
using util::make_error;
using util::Result;

bool complete(const ndb::BTreeStats& tree) {
    return tree.pages_visited != 0 && tree.pages_truncated == 0 && tree.pages_bad_trailer == 0 &&
           tree.pages_revisited == 0 && tree.page_crc_failed == 0 && tree.page_sig_failed == 0 &&
           tree.level_mismatches == 0 && tree.stride_mismatches == 0 &&
           tree.page_crc_ok == tree.pages_visited && tree.page_sig_ok == tree.pages_visited;
}
using Identity = std::tuple<std::vector<uint8_t>, bool, std::u16string, uint32_t>;
Identity identity(const ltp::NamedProperty& entry) {
    return {entry.guid, entry.name_is_string, entry.name_is_string ? entry.name : std::u16string{},
            entry.name_is_string ? 0 : entry.numeric_name};
}

Result<EmitRegistry> registry(const ltp::LtpReadReport& source,
                              std::map<uint16_t, uint16_t>& mapping) {
    const auto& stats = source.npm;
    if (!source.npm_read || stats.records_skipped || stats.names_unresolved ||
        stats.ragged_streams || stats.bucket_mismatches || stats.crc_mismatches ||
        stats.string_names_past_end || stats.string_offsets_unmatched ||
        stats.guid_refs_out_of_range || stats.guid_stream_ragged_bytes || stats.stopped_early ||
        stats.entry_records != source.name_id_map.entries.size()) {
        return make_error(ErrorKind::kBadField, "mailbox.name_map", 0, 0,
                          "a complete, validated Name-to-ID map is required");
    }
    std::map<Identity, uint16_t> unique;
    std::set<uint16_t> source_ids;
    for (const auto& entry : source.name_id_map.entries) {
        // MS-PST 2.4.7.1 / libpff "The name-to-id map": NAMEID_GUID_NONE
        // explicitly has no GUID. The reader's guid_resolved remains false for it.
        const bool no_guid = entry.guid_index == 0 &&
                             entry.guid_kind == ltp::NameIdGuidKind::kNone && entry.guid.empty();
        // MS-PST 2.4.7.1 / libpff "The name-to-id map": only string names
        // require a String Stream lookup; numeric names are carried directly.
        if ((entry.name_is_string && !entry.name_resolved) ||
            (!no_guid && (!entry.guid_resolved || entry.guid.size() != 16)) ||
            entry.npid < ltp::kNpidBase || !source_ids.insert(entry.npid).second) {
            return make_error(ErrorKind::kBadField, "mailbox.named_identity", entry.entry_offset,
                              entry.npid, "unresolved or duplicate source property identity");
        }
        unique.emplace(identity(entry), uint16_t{0});
    }
    if (unique.size() > 4096)
        return make_error(ErrorKind::kUnsupported, "mailbox.named_capacity", 0, unique.size());
    std::vector<writer::NamedProperty> entries;
    for (auto& [key, index] : unique) {
        index = static_cast<uint16_t>(entries.size());
        entries.push_back({std::get<2>(key), std::get<1>(key), std::get<3>(key), std::get<0>(key)});
    }
    for (const auto& entry : source.name_id_map.entries)
        mapping.emplace(entry.npid,
                        static_cast<uint16_t>(ltp::kNpidBase + unique.at(identity(entry))));
    return EmitRegistry::build(std::move(entries));
}
} // namespace

const char* coverage_kind_name(CoverageKind kind) {
    switch (kind) {
    case CoverageKind::kContent:
        return "content";
    case CoverageKind::kRegenerated:
        return "regenerated";
    case CoverageKind::kExcludedSearch:
        return "excluded-search";
    case CoverageKind::kUnknown:
        return "unknown";
    case CoverageKind::kUnsupportedContent:
        return "unsupported-content";
    }
    return "unknown";
}

Result<MailboxManifest> build_mailbox_manifest(const ltp::LtpReadReport& census) {
    if (census.refusal || !census.clean || census.failure_total || !census.errors.empty() ||
        !complete(census.bbt) || !complete(census.nbt) || census.nid_duplicates ||
        census.nodes.duplicates() || census.bbt_index.duplicates() ||
        census.nbt.leaf_entries != census.nodes.size() ||
        census.nid_entries != census.nodes.size() ||
        census.bbt.leaf_entries != census.bbt_index.entries()) {
        return make_error(ErrorKind::kBadField, "mailbox.index", 0, census.nid_entries,
                          "BBT/NBT enumeration must be complete before allocating destination IDs");
    }
    // Engineering metadata budget, not a PST layout limit. Refuse before duplicating the index.
    if (census.nodes.size() > 1000000 || census.bbt_index.bytes() > 128 * 1024 * 1024)
        return make_error(ErrorKind::kUnsupported, "mailbox.index_budget", 0, census.nodes.size());
    MailboxManifest out;
    auto names = registry(census, out.named_mapping);
    if (!names.ok())
        return names.error();
    out.registry = names.take();
    const auto entries = census.nodes.entries();
    std::map<uint32_t, size_t> folders;
    std::set<uint64_t> search_indices;
    for (const auto& node : entries) {
        if (node.nid > std::numeric_limits<uint32_t>::max())
            return make_error(ErrorKind::kBadField, "mailbox.nid", 0, node.nid);
        if (ltp::nid_type(node.nid) == ltp::kNidTypeSearchFolder)
            search_indices.insert(ltp::nid_index(node.nid));
        if (ltp::nid_type(node.nid) != ltp::kNidTypeNormalFolder)
            continue;
        const auto source_nid = static_cast<uint32_t>(node.nid);
        const auto output_nid = static_cast<uint32_t>(
            ltp::make_nid(++out.last_folder_index, ltp::kNidTypeNormalFolder));
        folders.emplace(source_nid, out.folders.size());
        out.folders.push_back({source_nid, node.nid_parent, output_nid});
    }
    if (!folders.contains(static_cast<uint32_t>(ltp::kNidRootFolder)))
        return make_error(ErrorKind::kBadField, "mailbox.root", 0, ltp::kNidRootFolder);
    for (auto& folder : out.folders) {
        if (folder.source_nid == ltp::kNidRootFolder) {
            if (folder.source_parent != folder.source_nid && folder.source_parent != 0)
                return make_error(ErrorKind::kBadField, "mailbox.root_parent", 0,
                                  folder.source_parent);
            folder.output_parent = writer::kNidIpmsubtree;
        } else {
            const auto parent = folders.find(folder.source_parent);
            if (parent == folders.end())
                return make_error(ErrorKind::kBadField, "mailbox.folder_parent", 0,
                                  folder.source_nid, "actual folder has no retained actual parent");
            folder.output_parent = out.folders[parent->second].output_nid;
        }
        std::set<uint32_t> ancestry;
        auto current = folder.source_nid;
        while (current != ltp::kNidRootFolder) {
            if (!ancestry.insert(current).second)
                return make_error(ErrorKind::kBadField, "mailbox.folder_cycle", 0, current);
            if (ancestry.size() > 64)
                return make_error(ErrorKind::kUnsupported, "mailbox.folder_depth", 0, current);
            const auto found = folders.find(current);
            if (found == folders.end())
                return make_error(ErrorKind::kBadField, "mailbox.folder_parent", 0, current);
            current = out.folders[found->second].source_parent;
        }
    }
    for (const auto& node : entries) {
        const auto nid = static_cast<uint32_t>(node.nid);
        const auto type = ltp::nid_type(nid);
        NodeCoverage coverage{nid, node.nid_parent};
        if (type == ltp::kNidTypeNormalFolder) {
            coverage.kind = CoverageKind::kContent;
            coverage.output_nid = out.folders[folders.at(nid)].output_nid;
        } else if (type == ltp::kNidTypeNormalMessage || type == ltp::kNidTypeAssocMessage) {
            const auto parent = folders.find(node.nid_parent);
            if (parent == folders.end())
                return make_error(ErrorKind::kBadField, "mailbox.item_parent", 0, nid,
                                  "normal/FAI item has no retained actual owning folder");
            auto& folder = out.folders[parent->second];
            const bool associated = type == ltp::kNidTypeAssocMessage;
            auto& last = associated ? out.last_associated_index : out.last_normal_index;
            const auto output_nid = static_cast<uint32_t>(ltp::make_nid(++last, type));
            out.items.push_back({nid, node.nid_parent, output_nid, folder.output_nid, associated});
            ++(associated ? folder.associated_count : folder.normal_count);
            coverage.kind = CoverageKind::kContent;
            coverage.output_nid = output_nid;
        } else if (type == ltp::kNidTypeSearchFolder || type == ltp::kNidTypeSearchCriteriaObject ||
                   type == ltp::kNidTypeSearchContentsTable ||
                   search_indices.contains(ltp::nid_index(nid))) {
            coverage.kind = CoverageKind::kExcludedSearch;
        } else if (type == ltp::kNidTypeHierarchyTable || type == ltp::kNidTypeContentsTable ||
                   type == ltp::kNidTypeAssocContentsTable) {
            const auto owner = static_cast<uint32_t>(
                ltp::make_nid(ltp::nid_index(nid), ltp::kNidTypeNormalFolder));
            const auto found = folders.find(owner);
            if (found != folders.end()) {
                coverage.kind = CoverageKind::kRegenerated;
                coverage.output_nid = static_cast<uint32_t>(
                    ltp::make_nid(ltp::nid_index(out.folders[found->second].output_nid), type));
            }
        } else if (nid == ltp::kNidNameToIdMap) {
            coverage.kind = CoverageKind::kRegenerated;
            coverage.output_nid = nid;
        } else if (nid == 0x671 || nid == 0x692) {
            // Global NBT templates: MS-PST 2.4.6.1.1 / 2.4.5.3.1 / 2.7.3.3;
            // libpff "PST" descriptor notes list 1649/1682 as possible templates.
            // They are not per-message attachment/recipient content. Keep their
            // coverage unknown until source-schema/row equivalence is checked.
            coverage.kind = CoverageKind::kUnknown;
        } else if (type == ltp::kNidTypeAttachment || type == ltp::kNidTypeAttachmentTable ||
                   type == ltp::kNidTypeRecipientTable || type == ltp::kNidTypeLtp) {
            coverage.kind = CoverageKind::kUnsupportedContent;
        }
        // Unknown/internal nodes remain individually visible; a type label is no proof
        // that the generated scaffold reproduces this particular source node's content.
        out.coverage.push_back(coverage);
    }
    return out;
}
} // namespace ost2pst::msg
