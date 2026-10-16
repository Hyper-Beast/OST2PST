#include <algorithm>
#include <vector>

#include "ost2pst/ltp/layout.h"
#include "ost2pst/msg/mailbox.h"

#include "test_support.h"

namespace {
namespace ltp = ost2pst::ltp;
namespace msg = ost2pst::msg;
using ost2pst::ndb::NbtEntry;
using ost2pst::util::ErrorKind;

ltp::LtpReadReport census(std::vector<NbtEntry> entries) {
    ltp::LtpReadReport result;
    result.clean = true;
    result.npm_read = true;
    result.bbt.pages_visited = result.bbt.page_crc_ok = result.bbt.page_sig_ok = 1;
    result.nbt = result.bbt;
    for (const auto& entry : entries)
        result.nodes.add(entry);
    result.nbt.leaf_entries = result.nid_entries = entries.size();
    return result;
}
std::vector<NbtEntry> nodes() {
    return {{0x122, 4, 0, 0x122},  {0x202, 8, 0, 0x122},  {0x222, 12, 0, 0x202},
            {0x244, 16, 0, 0x202}, {0x268, 20, 0, 0x222}, {0x283, 24, 0, 0x122},
            {0x287, 28, 0, 0},     {0x290, 32, 0, 0},     {0x20E, 36, 0, 0},
            {0x216, 40, 0, 0},     {0x61, 44, 0, 0},      {0x305, 48, 0, 0},
            {0x671, 52, 0, 0},     {0x692, 56, 0, 0}};
}
ltp::NamedProperty named(uint16_t npid, uint32_t value) {
    ltp::NamedProperty out;
    out.npid = npid;
    // read_name_id_map resolves strings; numeric names are available directly.
    out.name_resolved = false;
    out.numeric_name = value;
    out.guid_index = 3;
    out.guid_kind = ltp::NameIdGuidKind::kStream;
    out.guid_resolved = true;
    out.guid.assign(16, 0x42);
    return out;
}
void run() {
    auto source = census(nodes());
    source.name_id_map.entries = {named(0x8001, 222), named(0x8000, 111), named(0x8002, 222)};
    source.npm.entry_records = 3;
    auto built = msg::build_mailbox_manifest(source);
    TEST_CHECK(built.ok());
    if (!built.ok())
        return;
    const auto& manifest = built.value();
    TEST_CHECK(manifest.folders.size() == 3 && manifest.items.size() == 2);
    TEST_CHECK(manifest.folders[0].output_parent == ost2pst::writer::kNidIpmsubtree);
    TEST_CHECK(manifest.folders[1].output_parent == manifest.folders[0].output_nid);
    TEST_CHECK(manifest.folders[2].output_parent == manifest.folders[1].output_nid);
    TEST_CHECK(manifest.folders[1].normal_count == 1 && manifest.folders[2].associated_count == 1);
    TEST_CHECK(!manifest.items[0].associated && manifest.items[1].associated);
    TEST_CHECK(ltp::nid_type(manifest.items[1].output_nid) == ltp::kNidTypeAssocMessage);
    TEST_CHECK(manifest.registry.entries().size() == 2);
    TEST_CHECK(manifest.named_mapping.at(0x8000) == 0x8000);
    TEST_CHECK(manifest.named_mapping.at(0x8001) == 0x8001);
    TEST_CHECK(manifest.named_mapping.at(0x8002) == 0x8001);
    TEST_CHECK(manifest.coverage.size() == nodes().size());
    size_t excluded = 0, unknown = 0, unsupported = 0;
    for (const auto& entry : manifest.coverage) {
        excluded += entry.kind == msg::CoverageKind::kExcludedSearch;
        unknown += entry.kind == msg::CoverageKind::kUnknown;
        unsupported += entry.kind == msg::CoverageKind::kUnsupportedContent;
        if (entry.source_nid == 0x671 || entry.source_nid == 0x692) {
            TEST_CHECK(entry.kind == msg::CoverageKind::kUnknown);
            TEST_EQ(entry.output_nid, 0u, "template equivalence remains unverified");
        }
    }
    TEST_CHECK(excluded == 3 && unknown == 3 && unsupported == 1);
    auto reversed = nodes();
    std::reverse(reversed.begin(), reversed.end());
    auto reordered = census(reversed);
    reordered.npm = source.npm;
    reordered.name_id_map = source.name_id_map;
    std::reverse(reordered.name_id_map.entries.begin(), reordered.name_id_map.entries.end());
    auto again = msg::build_mailbox_manifest(reordered);
    TEST_CHECK(again.ok());
    if (again.ok()) {
        TEST_CHECK(again.value().named_mapping == manifest.named_mapping);
        TEST_CHECK(again.value().items[0].output_nid == manifest.items[0].output_nid);
        TEST_CHECK(again.value().items[1].output_parent == manifest.items[1].output_parent);
    }
    source.nbt.pages_revisited = 1;
    TEST_ERROR(msg::build_mailbox_manifest(source), ErrorKind::kBadField, "mailbox.index", 0);
    source.nbt.pages_revisited = 0;
    source.npm.stopped_early = true;
    TEST_ERROR(msg::build_mailbox_manifest(source), ErrorKind::kBadField, "mailbox.name_map", 0);
    source.npm.stopped_early = false;
    source.name_id_map.entries[0].name_is_string = true;
    TEST_ERROR(msg::build_mailbox_manifest(source), ErrorKind::kBadField, "mailbox.named_identity",
               0);
    source.name_id_map.entries[0].name_resolved = true;
    source.name_id_map.entries[0].name = u"resolved string";
    TEST_CHECK(msg::build_mailbox_manifest(source).ok());
    source.name_id_map.entries[0].guid_index = 0;
    source.name_id_map.entries[0].guid_kind = ltp::NameIdGuidKind::kNone;
    source.name_id_map.entries[0].guid_resolved = false;
    source.name_id_map.entries[0].guid.clear();
    TEST_CHECK(msg::build_mailbox_manifest(source).ok());
    source.name_id_map.entries[0] = named(0x8001, 222);
    source.name_id_map.entries[0].guid_resolved = false;
    TEST_ERROR(msg::build_mailbox_manifest(source), ErrorKind::kBadField, "mailbox.named_identity",
               0);
    source.name_id_map.entries[0].guid_resolved = true;
    source.name_id_map.entries[0].guid.pop_back();
    TEST_ERROR(msg::build_mailbox_manifest(source), ErrorKind::kBadField, "mailbox.named_identity",
               0);
    source.name_id_map.entries[0] = named(0x8000, 222);
    TEST_ERROR(msg::build_mailbox_manifest(source), ErrorKind::kBadField, "mailbox.named_identity",
               0);
    auto bad = nodes();
    bad[1].nid_parent = 0x222;
    TEST_ERROR(msg::build_mailbox_manifest(census(bad)), ErrorKind::kBadField,
               "mailbox.folder_cycle", 0);
    bad = nodes();
    bad[3].nid_parent = 0x283;
    TEST_ERROR(msg::build_mailbox_manifest(census(bad)), ErrorKind::kBadField,
               "mailbox.item_parent", 0);
    bad = nodes();
    bad[1].nid_parent = 0x283;
    TEST_ERROR(msg::build_mailbox_manifest(census(bad)), ErrorKind::kBadField,
               "mailbox.folder_parent", 0);
    bad = nodes();
    bad[0].nid_parent = 0x202;
    TEST_ERROR(msg::build_mailbox_manifest(census(bad)), ErrorKind::kBadField,
               "mailbox.root_parent", 0);
    bad = nodes();
    bad.push_back(bad[1]);
    TEST_ERROR(msg::build_mailbox_manifest(census(bad)), ErrorKind::kBadField, "mailbox.index", 0);
}
} // namespace
int main() {
    run();
    return ost2pst::test::finish("msg_mailbox_test");
}
