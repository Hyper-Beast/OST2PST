// Read-only M6 source/output comparison. Uses extraction directly, never the emitter/writer.
// Logs contain structural paths, property identities and hashes, never property payloads.
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <string>

#include "ost2pst/ltp/node_open.h"
#include "ost2pst/msg/mailbox.h"
#include "ost2pst/msg/subset.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/sha256.h"

using namespace ost2pst;
namespace {
template <class T> T take(util::Result<T> value) {
    if (!value.ok()) {
        std::fprintf(stderr, "%s\n", util::format_error(value.error()).c_str());
        std::exit(2);
    }
    return value.take();
}
void require(bool good, const std::string& detail) {
    if (!good) {
        std::fprintf(stderr, "FAIL %s\n", detail.c_str());
        std::exit(3);
    }
}
std::string hex(uint64_t value) {
    char text[24];
    std::snprintf(text, sizeof text, "%llX", static_cast<unsigned long long>(value));
    return text;
}
std::string hex_bytes(const std::vector<uint8_t>& bytes) {
    std::string text;
    for (auto byte : bytes) {
        char pair[3];
        std::snprintf(pair, sizeof pair, "%02X", byte);
        text += pair;
    }
    return text;
}
std::string identity(const msg::SubsetValue& value) {
    std::string key = hex(value.prop_type) + ":";
    if (!value.named) return key + hex(value.prop_id);
    require(value.name_resolved && (value.guid_resolved || value.guid_index == 0),
            "unresolved named identity");
    key += "named:" + hex_bytes(value.guid) + ":";
    if (!value.name_is_string) return key + "number:" + hex(value.numeric_name);
    key += "string:";
    for (char16_t c : value.name) key += hex(c) + ".";
    return key;
}
std::string hash_bytes(const std::vector<uint8_t>& bytes, const util::SharedBytes& source) {
    util::Sha256 hash;
    if (source) {
        std::array<uint8_t, 65536> buffer;
        for (uint64_t offset = 0; offset < source->size();) {
            const size_t count = static_cast<size_t>(
                std::min<uint64_t>(buffer.size(), source->size() - offset));
            auto read = source->read_at(offset, buffer.data(), count);
            require(read.ok(), read.ok() ? "" : util::format_error(read.error()));
            require(hash.update({buffer.data(), count}).ok(), "SHA update");
            offset += count;
        }
    } else require(hash.update({bytes.data(), bytes.size()}).ok(), "SHA update");
    return util::sha256_hex(hash.digest());
}
uint64_t compared = 0, schemas = 0, bytes_compared = 0, object_refs = 0;
std::map<std::string, uint64_t> regenerated, added;
std::string class_of(const std::string& path) {
    return path.substr(path.find_last_of('/') + 1);
}
bool excluded(const msg::SubsetValue& value, const std::string& path, bool root) {
    // Explicit writer-owned values: MS-PST 2.4.3.2 and 2.3.4.4.1.
    if (value.writer_assigned) return true;
    if (class_of(path) != "folder") return false;
    // M6 folder plan regenerates counts/hierarchy and the approved imported root name.
    return value.prop_id == 0x3602 || value.prop_id == 0x3603 || value.prop_id == 0x360A ||
           value.prop_id == 0x3617 || (root && value.prop_id == 0x3001);
}
void values(const std::vector<msg::SubsetValue>& source,
            const std::vector<msg::SubsetValue>& target, const std::string& path,
            bool schema = false, bool root = false) {
    std::map<std::string, const msg::SubsetValue*> mapped;
    for (const auto& value : target)
        require(mapped.emplace(identity(value), &value).second, path + " duplicate output identity");
    for (const auto& value : source) {
        const auto key = identity(value);
        auto found = mapped.find(key);
        if (excluded(value, path, root)) {
            ++regenerated[class_of(path) + ":" + hex(value.prop_id)];
            if (found != mapped.end()) mapped.erase(found);
            continue;
        }
        require(found != mapped.end(), path + " missing " + key);
        const auto& output = *found->second;
        if (schema) ++schemas;
        else if (value.object_named) {
            require(output.object_named, path + " object reference " + key);
            // content.cpp rebuilds the referenced subtree and computes its new ulSize
            // (MS-PST 2.3.3.5). Compare the complete content below, not its old storage size.
            ++regenerated[class_of(path) + ":object_reference"];
            ++object_refs; // Content is compared recursively or as raw object bytes below.
        } else {
            require((value.readable || value.absent) && (output.readable || output.absent),
                    path + " unreadable " + key);
            const auto a = hash_bytes(value.bytes, value.source);
            const auto b = hash_bytes(output.bytes, output.source);
            require(value.absent == output.absent && value.byte_count() == output.byte_count() &&
                        a == b, path + " value mismatch " + key + " source=" + a + " target=" + b +
                        " sizes=" + std::to_string(value.byte_count()) + "/" +
                        std::to_string(output.byte_count()));
            ++compared;
            bytes_compared += value.byte_count();
        }
        mapped.erase(found);
    }
    for (const auto& [key, value] : mapped) {
        (void)value;
        ++added[class_of(path) + (schema ? ":schema:" : ":") + key];
    }
}
void message(const msg::SubsetMessage& a, const msg::SubsetMessage& b, const std::string& path) {
    require(a.pc_read && b.pc_read && a.subnodes_complete && b.subnodes_complete,
            path + " partial message");
    values(a.values, b.values, path + "/message");
    values(a.recipient_columns, b.recipient_columns, path + "/recipient", true);
    values(a.attachment_columns, b.attachment_columns, path + "/attachment-row", true);
    require(a.recipients.size() == b.recipients.size(), path + " recipient population");
    require(a.attachments.size() == b.attachments.size(), path + " attachment population");
    for (size_t i = 0; i < a.recipients.size(); ++i)
        values(a.recipients[i].values, b.recipients[i].values,
               path + "/r" + std::to_string(i) + "/recipient");
    for (size_t i = 0; i < a.attachments.size(); ++i) {
        const auto& x = a.attachments[i];
        const auto& y = b.attachments[i];
        const auto at = path + "/a" + std::to_string(i);
        require(x.pc_read && y.pc_read, at + " attachment PC");
        values(x.row_values, y.row_values, at + "/attachment-row");
        values(x.values, y.values, at + "/attachment");
        require(x.payload_read == y.payload_read && x.payload_bytes == y.payload_bytes &&
                    x.embedded_read == y.embedded_read && x.object_data_read == y.object_data_read,
                at + " payload kind or size");
        if (x.embedded_read) message(x.embedded, y.embedded, at + "/embedded");
        if (x.object_data_read) {
            require(hash_bytes(x.object_data, x.object_source) ==
                        hash_bytes(y.object_data, y.object_source), at + " opaque object hash");
            bytes_compared += x.payload_bytes;
            ++compared;
        }
    }
}
void valid(const msg::SubsetReport& report) {
    require(!report.fatal_io && !report.capped && report.unreadable_values == 0 &&
                report.named_unresolved == 0 && report.messages_without_pc == 0 &&
                report.recipient_table_failures == 0 && report.attachment_table_failures == 0 &&
                report.attachment_pc_failures == 0 && report.rows_without_cells == 0 &&
                report.subnode_walk_failures == 0 && report.subnode_walks_incomplete == 0 &&
                report.row_index_walks_incomplete == 0 && report.matrix_short_blocks == 0 &&
                report.attachments_with_unread_object == 0 &&
                report.object_values == report.object_values_carried, "partial extraction");
}
} // namespace
int wmain(int argc, wchar_t** argv) {
    if (argc != 4) return 1;
    auto source = take(util::FileReader::open_stable(argv[1]));
    auto target = take(util::FileReader::open_stable(argv[2]));
    ltp::LtpReadOptions options;
    options.scan_blocks = options.build_folders = false;
    auto a = take(ltp::read_ltp(source, options));
    auto b = take(ltp::read_ltp(target, options));
    auto manifest = take(msg::build_mailbox_manifest(a));
    (void)take(msg::build_mailbox_manifest(b)); // applies the complete-index validation to output
    ndb::BlockReadCounters ac, bc;
    ndb::FailureLog af(20), bf(20);
    ltp::FileBlockSource ab(source, a.profile, a.bbt_index, ac, af);
    ltp::FileBlockSource bb(target, b.profile, b.bbt_index, bc, bf);
    for (const auto& folder : manifest.folders) {
        require(take(b.nodes.node(folder.output_nid)).nid_parent == folder.output_parent,
                "mapped folder parent");
        util::ValueSpool as(argv[3]), bs(argv[3]);
        msg::SubsetOptions ao, bo;
        ao.spool = &as; bo.spool = &bs;
        auto ar = take(msg::extract_folder(a, ab, folder.source_nid, ao));
        auto br = take(msg::extract_folder(b, bb, folder.output_nid, bo));
        valid(ar); valid(br);
        require(ar.folder.pc_read && br.folder.pc_read, "folder PC");
        values(ar.folder.values, br.folder.values, hex(folder.source_nid) + "/folder", false,
               folder.output_parent == writer::kNidIpmsubtree);
    }
    for (const auto& item : manifest.items) {
        require(take(b.nodes.node(item.output_nid)).nid_parent == item.output_parent,
                "mapped item parent");
        util::ValueSpool as(argv[3]), bs(argv[3]);
        msg::SubsetOptions ao, bo;
        ao.spool = &as; bo.spool = &bs;
        auto ar = take(msg::extract_item(a, ab, item.source_nid, ao));
        auto br = take(msg::extract_item(b, bb, item.output_nid, bo));
        valid(ar); valid(br);
        require(ar.messages.size() == 1 && br.messages.size() == 1, "top-level population");
        message(ar.messages.front(), br.messages.front(), hex(item.source_nid));
        std::printf("ITEM %X %X %llu %llu\n", item.source_nid, item.output_nid,
                    static_cast<unsigned long long>(compared),
                    static_cast<unsigned long long>(bytes_compared));
    }
    for (const auto& [key,count] : regenerated)
        std::printf("REGENERATED %s %llu\n",key.c_str(),static_cast<unsigned long long>(count));
    for (const auto& [key,count] : added)
        std::printf("ADDED %s %llu\n",key.c_str(),static_cast<unsigned long long>(count));
    std::printf("COMPLETE folders=%zu items=%zu values=%llu schemas=%llu bytes=%llu object_refs=%llu\n",
                manifest.folders.size(), manifest.items.size(), static_cast<unsigned long long>(compared),
                static_cast<unsigned long long>(schemas), static_cast<unsigned long long>(bytes_compared),
                static_cast<unsigned long long>(object_refs));
    return 0;
}
