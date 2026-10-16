// The content writer checked against its own reader. A caller hands over one folder with five messages,
// their recipients, five attachments and three named identities; build_store emits a whole store around it;
// probe_file, read_ndb and read_ltp then have to accept the bytes and answer the same counts back.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "ost2pst/ltp/bth.h"
#include "ost2pst/ltp/data_tree.h"
#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/ltp_read.h"
#include "ost2pst/ltp/name_id.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/ltp/node_open.h"
#include "ost2pst/ltp/pc.h"
#include "ost2pst/ltp/subtree_dump.h"
#include "ost2pst/ltp/tc.h"
#include "ost2pst/ndb/bbt_index.h"
#include "ost2pst/ndb/btree.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/ndb/probe.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/writer/content.h"
#include "ost2pst/writer/empty_pst.h"

#include "test_support.h"

namespace {

namespace ltp = ost2pst::ltp;
namespace ndb = ost2pst::ndb;
namespace writer = ost2pst::writer;

using ost2pst::util::ByteView;
using ost2pst::util::FileReader;
using ost2pst::util::Result;

const char *kTempName = "ost2pst_writer_content_test.pst";
const char *kMatrixTempName = "ost2pst_writer_content_matrix.pst";
const char *kEmbeddedTempName = "ost2pst_writer_content_embedded.pst";

// The Provider UID this writer puts into every EntryID it regenerates (src/writer/content.cpp, recorded in
// research/blank-pst-diff.md of the M4 task).
const uint8_t kProviderUid[16] = {0x22, 0x9D, 0xB5, 0x0A, 0xDC, 0xD9, 0x94, 0x43,
                                  0x85, 0xDE, 0x90, 0xAE, 0xB0, 0x7D, 0x12, 0x70};

// A property set the source invented: neither of the two well-known sets, so it has to land in the GUID
// Stream of the new store ([MS-PST] 2.4.7.1 wGuid above 2, 2.4.7.2 GUID Stream).
const std::vector<uint8_t> kCustomGuid = {0x4D, 0x35, 0x43, 0x75, 0x73, 0x74, 0x6F, 0x6D,
                                          0x47, 0x75, 0x69, 0x64, 0x00, 0x01, 0x02, 0x03};
// PS_MAPI, the well-known set the writer must not put into the GUID Stream as a custom entry.
const std::vector<uint8_t> kMapiGuid = {0x28, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};

constexpr uint16_t kTypeInteger32 = 0x0003; // [MS-OXCDATA] 2.11.1 PtypInteger32
constexpr uint16_t kTypeBoolean = 0x000B;   // [MS-OXCDATA] 2.11.1 PtypBoolean
constexpr uint16_t kTypeUnicode = 0x001F;   // [MS-OXCDATA] 2.11.1 PtypString16
constexpr uint16_t kTypeTime = 0x0040;      // [MS-OXCDATA] 2.11.1 PtypTime
constexpr uint16_t kTypeBinary = 0x0102;    // [MS-OXCDATA] 2.11.1 PtypBinary
constexpr uint16_t kTypeObject = 0x000D;    // [MS-OXCDATA] 2.11.1 PtypObject: [MS-PST] 2.3.3.5

std::vector<uint8_t> le32_bytes(uint32_t value) {
    return {static_cast<uint8_t>(value & 0xFFu), static_cast<uint8_t>((value >> 8) & 0xFFu),
            static_cast<uint8_t>((value >> 16) & 0xFFu), static_cast<uint8_t>((value >> 24) & 0xFFu)};
}

std::vector<uint8_t> u16_bytes(const std::u16string &text) {
    std::vector<uint8_t> bytes;
    for (const char16_t unit : text) {
        bytes.push_back(static_cast<uint8_t>(unit & 0xFFu));
        bytes.push_back(static_cast<uint8_t>((unit >> 8) & 0xFFu));
    }
    return bytes;
}

std::u16string u16(const char *ascii) {
    std::u16string out;
    for (const char *p = ascii; *p != 0; ++p) {
        out.push_back(static_cast<char16_t>(static_cast<unsigned char>(*p)));
    }
    return out;
}

std::vector<uint8_t> blob(size_t count, uint8_t seed) {
    std::vector<uint8_t> bytes(count);
    for (size_t index = 0; index < count; ++index) {
        bytes[index] = static_cast<uint8_t>(seed + index % 251);
    }
    return bytes;
}

writer::ContentProperty value_of(uint16_t prop_id, uint16_t prop_type, std::vector<uint8_t> bytes) {
    writer::ContentProperty property;
    property.prop_id = prop_id;
    property.prop_type = prop_type;
    property.value = std::move(bytes);
    return property;
}

writer::ContentProperty named_value_of(uint16_t prop_id, uint16_t prop_type, std::vector<uint8_t> bytes,
                                       uint64_t index) {
    writer::ContentProperty property = value_of(prop_id, prop_type, std::move(bytes));
    property.named = true;
    property.named_index = index;
    return property;
}

writer::ContentCell cell_of(uint32_t tag, std::vector<uint8_t> bytes) {
    writer::ContentCell cell;
    cell.tag = tag;
    cell.value = std::move(bytes);
    return cell;
}

std::u16string u16_num(const char *prefix, size_t value) {
    std::u16string out = u16(prefix);
    out.push_back(static_cast<char16_t>(48 + (value % 10)));
    return out;
}

// A compact fixture value standing in for a provider-defined address-book EntryID. Recipient-table
// 0x0FFF is carried opaquely ([MS-PST] 2.4.5.3.1), so the writer must not turn these bytes into a PST NID.
std::vector<uint8_t> recipient_entry_id(size_t index) {
    std::vector<uint8_t> bytes = {
        0x00, 0x00, 0x00, 0x00, 0x81, 0x2B, 0x1F, 0xA4,
        0xBE, 0xA3, 0x10, 0x19, 0x9D, 0x6E, 0x00, 0xDD,
        0x01, 0x0F, 0x54, 0x02, 0x00, 0x00, 0x01, 0x80,
    };
    bytes.push_back(static_cast<uint8_t>(0xA0 + index));
    return bytes;
}

// Five messages, five recipients, five attachments and three named identities: the shape the M5 exit
// criterion asks for, held in memory because a unit test never opens the 2.6 GB sample
// (DEVELOPMENT.md).
writer::StoreRequest build_request() {
    writer::StoreRequest request;

    writer::NamedProperty custom;
    custom.name = u16("urn:schemas:mailheader:x-m5-test");
    custom.name_is_string = true;
    custom.guid = kCustomGuid;
    request.named_properties.push_back(custom);

    writer::NamedProperty numeric;
    numeric.name_is_string = false; // [MS-PST] 2.4.7.1: N == 0 means dwPropertyID IS the name
    numeric.numeric_name = 0x1234;
    numeric.guid = kMapiGuid;
    request.named_properties.push_back(numeric);

    writer::NamedProperty plain;
    plain.name = u16("x-m5-plain");
    plain.name_is_string = true;
    plain.guid = {}; // wGuid 0: NAMEID_GUID_NONE ([MS-PST] 2.4.7.1)
    request.named_properties.push_back(plain);

    writer::ContentFolder folder;
    folder.parent_nid = writer::kNidIpmsubtree;
    folder.name = u16("M5 Subset Folder");
    folder.properties.push_back(
        named_value_of(0x8000, kTypeUnicode, u16_bytes(u16("folder level named value")), 0));

    for (size_t index = 0; index < 5; ++index) {
        writer::ContentMessage message;
        // [MS-PST] 2.4.5.1.1: the seven tags a Message object PC MUST carry.
        message.properties.push_back(value_of(0x001A, kTypeUnicode, u16_bytes(u16("IPM.Note"))));
        message.properties.push_back(value_of(0x0E07, kTypeInteger32, le32_bytes(0x00000001)));
        message.properties.push_back(value_of(0x0E08, kTypeInteger32, le32_bytes(4096 + static_cast<uint32_t>(index))));
        message.properties.push_back(value_of(0x0E17, kTypeInteger32, le32_bytes(0)));
        message.properties.push_back(value_of(0x3007, kTypeTime, blob(8, static_cast<uint8_t>(index))));
        message.properties.push_back(value_of(0x3008, kTypeTime, blob(8, static_cast<uint8_t>(index))));
        message.properties.push_back(value_of(0x300B, kTypeBinary, blob(16, static_cast<uint8_t>(0x40 + index))));
        message.properties.push_back(
            value_of(0x0037, kTypeUnicode, u16_bytes(u16_num("M5 subject ", index))));
        // A PtypBoolean arrives as the 4 bytes a PC holds for it and has to land in the Contents Table as
        // the 1 byte that column declares.
        message.properties.push_back(value_of(0x0057, kTypeBoolean, le32_bytes(index == 0 ? 0u : 1u)));
        // The body triple: three of them plain, one HTML, one compressed RTF framed the way
        // libpff format notes (see THIRD_PARTY_NOTICES.txt):2632-2652 describes it.
        if (index < 3) {
            message.properties.push_back(
                value_of(0x1000, kTypeUnicode, u16_bytes(u16_num("body text ", index))));
        } else if (index == 3) {
            message.properties.push_back(
                value_of(0x1013, kTypeBinary, blob(900, static_cast<uint8_t>(index))));
        } else {
            std::vector<uint8_t> rtf = blob(60, static_cast<uint8_t>(index));
            std::vector<uint8_t> value = le32_bytes(static_cast<uint32_t>(rtf.size() + 12));
            const std::vector<uint8_t> uncompressed = le32_bytes(2048);
            value.insert(value.end(), uncompressed.begin(), uncompressed.end());
            value.insert(value.end(), {0x4C, 0x5A, 0x46, 0x75}); // the LZFu signature
            value.insert(value.end(), {0x11, 0x22, 0x33, 0x44});  // the CRC32 slot
            value.insert(value.end(), rtf.begin(), rtf.end());
            message.properties.push_back(value_of(0x1009, kTypeBinary, std::move(value)));
        }
        if (index == 0) {
            message.properties.push_back(named_value_of(0x8001, kTypeInteger32, le32_bytes(77), 1));
        }
        if (index == 1) {
            message.properties.push_back(
                named_value_of(0x8002, kTypeUnicode, u16_bytes(u16("a plain named value")), 2));
        }

        writer::ContentRow recipient;
        recipient.cells.push_back(cell_of(0x0C150003, le32_bytes(0))); // [MS-PST] 2.4.5.3.1 template column
        recipient.cells.push_back(cell_of(0x0FFF0102, recipient_entry_id(index)));
        recipient.cells.push_back(cell_of(0x3001001F, u16_bytes(u16_num("Recipient ", index))));
        message.recipients.columns = {0x0C150003, 0x0FFF0102, 0x3001001F};
        message.recipients.rows.push_back(std::move(recipient));

        const size_t attachments = index == 0 ? 2 : (index == 1 ? 3 : 0);
        for (size_t slot = 0; slot < attachments; ++slot) {
            // One payload past the 8176 bytes one data block can hold ([MS-PST] 2.2.2.8), so the writer has
            // to spread it over blocks and the reader has to flatten the tree back.
            const size_t size = (index == 1 && slot == 0) ? 9000 : 100 + slot;
            writer::ContentRow row;
            row.cells.push_back(cell_of(0x0E200003, le32_bytes(static_cast<uint32_t>(size))));
            row.cells.push_back(cell_of(0x0FFE0003, le32_bytes(1)));
            row.cells.push_back(cell_of(0x3703001F, u16_bytes(u16_num("attach-", index * 10 + slot))));
            message.attachments.columns = {0x0E200003, 0x0FFE0003, 0x3703001F};
            message.attachments.rows.push_back(std::move(row));

            writer::ContentAttachment object;
            // [MS-PST] 2.4.6.2.1: the three tags an Attachment object PC MUST carry.
            object.properties.push_back(
                value_of(0x0E20, kTypeInteger32, le32_bytes(static_cast<uint32_t>(size))));
            object.properties.push_back(value_of(0x3705, kTypeInteger32, le32_bytes(7)));
            object.properties.push_back(value_of(0x370B, kTypeInteger32, le32_bytes(0)));
            object.payload = blob(size, static_cast<uint8_t>(0x80 + index * 8 + slot));
            object.has_payload = true;
            message.attachment_objects.push_back(std::move(object));
        }

        folder.messages.push_back(std::move(message));
    }

    request.folders.push_back(std::move(folder));
    return request;
}

// A block with no bytes is a block the writer opened and then filled with nothing: [MS-PST] 2.2.2.7.7.3
// gives a BBTENTRY.cb that a reader must be able to trust, so the writer must not emit one.
void check_blocks(const writer::StoreImage &image) {
    for (size_t index = 0; index < image.blocks.size(); ++index) {
        const writer::WrittenBlock &block = image.blocks[index];
        if (block.cb == 0) {
            std::printf("  empty block at plan index %zu: bid 0x%llX ib 0x%llX cRef %u\n",
                        static_cast<unsigned long long>(index),
                        static_cast<unsigned long long>(block.bid),
                        static_cast<unsigned long long>(block.ib), static_cast<unsigned>(block.c_ref));
        }
        TEST_CHECK_MSG(block.cb != 0, "every written block carries bytes");
    }
}

void dump_failures(const char *tag, const std::vector<ndb::ProbeFailure> &failures) {
    for (const ndb::ProbeFailure &failure : failures) {
        std::fprintf(stderr, "%s failure: %s at 0x%llx (value 0x%llx): %s\n", tag,
                     failure.field.c_str(), static_cast<unsigned long long>(failure.offset),
                     static_cast<unsigned long long>(failure.value), failure.detail.c_str());
    }
}

void dump_finding(const ltp::LtpFinding &finding) {
    std::fprintf(stderr, "read_ltp finding: NID 0x%llx type 0x%llx bid 0x%llx %s: %s\n",
                 static_cast<unsigned long long>(finding.nid),
                 static_cast<unsigned long long>(finding.nid_type),
                 static_cast<unsigned long long>(finding.bid), finding.field.c_str(),
                 finding.detail.c_str());
}

// What the writer said it did.
void check_report(const writer::ContentReport &report) {
    TEST_EQ(report.folders, 1u, "folders emitted");
    TEST_EQ(report.messages, 5u, "messages emitted");
    TEST_EQ(report.recipients, 5u, "recipients emitted");
    TEST_EQ(report.attachments, 5u, "attachments emitted");
    TEST_EQ(report.attachment_bytes, 9000u + 100u + 101u + 101u + 102u, "attachment payload bytes");
    TEST_EQ(report.named_properties, 3u, "named identities re-registered");
    TEST_EQ(report.folder_nids.size(), 1u, "one folder NID");
    if (!report.folder_nids.empty()) {
        const uint32_t nid = report.folder_nids[0];
        TEST_EQ(ltp::nid_type(nid), ltp::kNidTypeNormalFolder, "folder NID type");
        TEST_CHECK_MSG(nid > 0x8022u, "the new folder sits above the minimum mailbox allocations");
    }
}

bool contains_bytes(const std::vector<uint8_t> &haystack, const std::vector<uint8_t> &needle) {
    if (needle.size() > haystack.size()) {
        return false;
    }
    for (size_t at = 0; at + needle.size() <= haystack.size(); ++at) {
        bool match = true;
        for (size_t index = 0; index < needle.size(); ++index) {
            if (haystack[at + index] != needle[index]) {
                match = false;
                break;
            }
        }
        if (match) {
            return true;
        }
    }
    return false;
}

// [MS-PST] 2.4.3.2: an ENTRYID is four zero flag bytes, the Provider UID of the store, then the NID. The
// writer regenerates every EntryID it writes against its own Provider UID, so the bytes have to say so.
std::vector<uint8_t> entry_id_bytes(uint32_t nid) {
    std::vector<uint8_t> bytes(20, 0); // rgbFlags + Provider UID, then the NID is appended
    for (size_t index = 0; index < 16; ++index) {
        bytes[4 + index] = kProviderUid[index];
    }
    const std::vector<uint8_t> nid_bytes = le32_bytes(nid);
    bytes.insert(bytes.end(), nid_bytes.begin(), nid_bytes.end());
    return bytes;
}

void check_structure(const FileReader &file, const writer::ContentReport &report) {
    Result<ndb::ProbeReport> probed = ndb::probe_file(file, ndb::ProbeOptions());
    TEST_OK(probed, "probe_file on the content store");
    if (probed.ok()) {
        dump_failures("probe", probed.value().failures);
        TEST_CHECK_MSG(probed.value().clean, "probe_file is not clean on the content store");
        TEST_CHECK_MSG(!probed.value().refusal.has_value(), "probe_file refused the content store");
        TEST_CHECK_MSG(probed.value().header_crcs.partial_ok, "partial HEADER CRC");
        TEST_CHECK_MSG(probed.value().header_crcs.full_ok, "full HEADER CRC");
        TEST_EQ(probed.value().profile, ndb::FileProfile::kPst, "profile of the written store");
    }

    Result<ltp::LtpReadReport> read = ltp::read_ltp(file, ltp::LtpReadOptions());
    TEST_OK(read, "read_ltp on the content store");
    if (!read.ok()) {
        return;
    }
    const ltp::LtpReadReport &census = read.value();
    dump_failures("read_ltp", census.failures);
    for (const ltp::LtpFinding &finding : census.findings.items) {
        dump_finding(finding);
    }
    TEST_CHECK_MSG(census.clean, "read_ltp is not clean on the content store");
    TEST_EQ(census.failure_total, 0u, "read_ltp failures");
    TEST_EQ(census.findings.total, 0u, "read_ltp findings");
    TEST_EQ(census.pcs.failed, 0u, "Property Contexts the reader failed to read");
    TEST_EQ(census.tcs.failed, 0u, "Table Contexts the reader failed to read");
    TEST_EQ(census.heap.heap_nodes_rejected, 0u, "heap nodes the reader rejected");
    TEST_EQ(census.nid_duplicates, 0u, "duplicate NIDs");
    TEST_CHECK_MSG(census.npm_read, "the Name-to-ID Map was read");

    const uint32_t folder_nid = report.folder_nids.empty() ? 0u : report.folder_nids[0];
    const ltp::LtpFolder *folder = nullptr;
    for (const ltp::LtpFolder &candidate : census.folders) {
        if (candidate.nid == folder_nid) {
            folder = &candidate;
        }
    }
    TEST_CHECK_MSG(folder != nullptr, "the new folder appears in the folder walk");
    if (folder != nullptr) {
        TEST_STR(folder->name, "M5 Subset Folder", "folder display name");
        TEST_CHECK_MSG(folder->has_pc, "the folder has a Property Context");
        TEST_CHECK_MSG(folder->has_hierarchy, "the folder has a Hierarchy Table");
        TEST_CHECK_MSG(folder->has_contents, "the folder has a Contents Table");
        TEST_CHECK_MSG(folder->has_associated, "the folder has a FAI Contents Table");
        TEST_EQ(folder->messages, 5u, "rows of the Contents Table");
        TEST_EQ(folder->parent_messages, 5u, "Message objects naming this folder as nidParent");
        TEST_EQ(folder->parent, writer::kNidIpmsubtree, "the new folder hangs under IPM_SUBTREE");
    }

    // [MS-PST] 2.4.4.3: a Folder object is one nidIndex wearing the PC type and the three table types, and
    // 2.2.2.7.7.4 / 2.4.5.2 make each table name the folder it belongs to as nidParent.
    if (folder_nid != 0) {
        const std::vector<ltp::NodeRef> group = census.nodes.group(folder_nid);
        TEST_EQ(group.size(), 4u, "one nidIndex carrying the folder PC and its three tables");
        bool type_seen[32] = {false};
        for (const ltp::NodeRef &node : group) {
            const uint64_t nid_type = ltp::nid_type(node.nid); // [MS-PST] 2.2.2.1: the low 5 bits
            if (nid_type < 32) {
                type_seen[nid_type] = true;
            }
            if (nid_type != ltp::kNidTypeNormalFolder) {
                TEST_EQ(node.nid_parent, folder_nid, "a folder table names the folder as nidParent");
            }
        }
        TEST_CHECK_MSG(type_seen[ltp::kNidTypeNormalFolder], "the folder PC NID");
        TEST_CHECK_MSG(type_seen[ltp::kNidTypeHierarchyTable], "the Hierarchy Table NID");
        TEST_CHECK_MSG(type_seen[ltp::kNidTypeContentsTable], "the Contents Table NID");
        TEST_CHECK_MSG(type_seen[ltp::kNidTypeAssocContentsTable], "the FAI Contents Table NID");
    }
}

// Each Message object node, its Recipient Table, its Attachment Table and the Attachment objects its rows
// name, described by the same dump ostinfo --subtree prints.
void check_content(const FileReader &file, const writer::StoreOutcome &outcome,
                   const std::vector<uint8_t> &image) {
    Result<ltp::LtpReadReport> read = ltp::read_ltp(file, ltp::LtpReadOptions());
    TEST_OK(read, "read_ltp for the subtree walk");
    if (!read.ok()) {
        return;
    }
    const ltp::LtpReadReport &census = read.value();
    const uint32_t folder_nid =
        outcome.report.folder_nids.empty() ? 0u : outcome.report.folder_nids[0];

    ndb::BlockReadCounters counters;
    ndb::FailureLog failures(20);
    ltp::FileBlockSource blocks(file, census.profile, census.bbt_index, counters, failures);

    ltp::SubtreeDumpOptions options;
    options.max_nodes = 200;
    options.max_depth = 3;
    options.max_pc_records = 400;
    options.max_row_ids = 16;

    uint64_t messages = 0, recipient_tables = 0, attachment_tables = 0, attachment_objects = 0;
    uint64_t payload_bytes = 0;
    bool saw_multi_block_payload = false;
    std::vector<uint64_t> message_nids;
    for (const ltp::NodeRef &entry : census.nodes.entries()) {
        if (ltp::nid_type(entry.nid) != ltp::kNidTypeNormalMessage) {
            continue;
        }
        ++messages;
        message_nids.push_back(entry.nid);
        TEST_EQ(entry.nid_parent, folder_nid, "every Message object names the new folder as nidParent");
        Result<ltp::SubtreeDump> dumped =
            ltp::dump_subtree(census.nodes, blocks, census.profile, entry.nid, options);
        TEST_OK(dumped, "dump_subtree on a Message object");
        if (!dumped.ok()) {
            continue;
        }
        const ltp::SubtreeDump &subtree = dumped.value();
        TEST_EQ(subtree.failure_total, 0u, "subtree dump failures");
        TEST_CHECK_MSG(!subtree.capped, "the Message subtree was described whole");

        bool required[7] = {false, false, false, false, false, false, false};
        const uint16_t required_ids[7] = {0x001A, 0x0E07, 0x0E08, 0x0E17, 0x3007, 0x3008, 0x300B};
        bool body = false;
        for (const ltp::DumpPcValue &value : subtree.root.pc) {
            for (size_t index = 0; index < 7; ++index) {
                if (value.prop_id == required_ids[index]) {
                    required[index] = true;
                }
            }
            if (value.prop_id == 0x1000 || value.prop_id == 0x1009 || value.prop_id == 0x1013) {
                body = true;
            }
            if (value.prop_id == 0x0FFF) {
                TEST_EQ(value.bytes, 24u, "the regenerated EntryID is rgbFlags + Provider UID + NID");
            }
        }
        for (size_t index = 0; index < 7; ++index) {
            TEST_CHECK_MSG(required[index], "the Message PC carries a tag [MS-PST] 2.4.5.1.1 requires");
        }
        TEST_CHECK_MSG(body, "the Message PC carries one of the three body forms");
        if (messages == 1) {
            const auto numeric =
                std::find_if(subtree.root.pc.begin(), subtree.root.pc.end(),
                             [](const auto& value) { return value.prop_id == 0x8001; });
            TEST_CHECK_MSG(numeric != subtree.root.pc.end(),
                           "named slot 1 is referenced as NPID 0x8001 in the Message PC");
            if (numeric != subtree.root.pc.end()) {
                TEST_EQ(numeric->prop_type, kTypeInteger32, "the mapped property retains its type");
                TEST_EQ(numeric->hnid, 77u, "the mapped property retains its inline value");
            }
        }

        std::vector<uint64_t> attachment_nids;
        bool saw_recipient_table = false;
        for (const ltp::DumpNode &subnode : subtree.subnodes) {
            if (subnode.nid_type == ltp::kNidTypeRecipientTable) {
                ++recipient_tables;
                saw_recipient_table = true;
                TEST_CHECK_MSG(subnode.tc.read, "the Recipient Table read");
                TEST_EQ(subnode.tc.rows, 1u, "Recipient Table rows");
                bool entry_id_column = false;
                for (const ltp::TcColumn &column : subnode.tc.column_list) {
                    if (column.tag == 0x0FFF0102) {
                        entry_id_column = true;
                    }
                }
                TEST_CHECK_MSG(entry_id_column, "the Recipient Table has the 0x0FFF EntryID column");
            }
            if (subnode.nid_type == ltp::kNidTypeAttachmentTable) {
                ++attachment_tables;
                bool row_id_column = false;
                bool row_ver_column = false;
                for (const ltp::TcColumn &column : subnode.tc.column_list) {
                    if (column.tag == 0x67F20003) {
                        row_id_column = true;
                    }
                    if (column.tag == 0x67F30003) {
                        row_ver_column = true;
                    }
                }
                TEST_CHECK_MSG(row_id_column, "the Attachment Table has the 0x67F2 row-id column");
                TEST_CHECK_MSG(row_ver_column, "the Attachment Table has the 0x67F3 row-version column");
                TEST_EQ(subnode.tc.row_ids.size(), attachment_nids.size(),
                        "Attachment Table rows against Attachment objects already seen");
            }
            if (subnode.nid_type == ltp::kNidTypeAttachment) {
                ++attachment_objects;
                attachment_nids.push_back(subnode.local_nid);
                bool data = false;
                for (const ltp::DumpPcValue &value : subnode.pc) {
                    if (value.prop_id != 0x3701) {
                        continue;
                    }
                    data = true;
                    TEST_EQ(value.prop_type, kTypeBinary, "0x3701 written as PtypBinary");
                    TEST_CHECK_MSG(value.answered, "the 0x3701 payload resolved");
                    payload_bytes += value.bytes;
                    if (value.bytes > 8176u) {
                        saw_multi_block_payload = true;
                        TEST_CHECK_MSG(value.in_subnode, "a value past one data block lives in a subnode");
                    }
                }
                TEST_CHECK_MSG(data, "the Attachment object carries 0x3701");
            }
        }
        TEST_CHECK_MSG(saw_recipient_table, "[MS-PST] 2.4.5.3: a Message object MUST have a Recipient Table");
        // [MS-PST] 2.4.6.1.3: the dwRowID of an Attachment Table row IS the subnode NID of the Attachment
        // object for that row.
        for (const ltp::DumpNode &subnode : subtree.subnodes) {
            if (subnode.nid_type != ltp::kNidTypeAttachmentTable) {
                continue;
            }
            for (uint64_t row_id : subnode.tc.row_ids) {
                bool found = false;
                for (uint64_t nid : attachment_nids) {
                    if (nid == row_id) {
                        found = true;
                    }
                }
                TEST_CHECK_MSG(found, "the row dwRowID names an Attachment object subnode");
            }
        }
    }
    TEST_EQ(messages, 5u, "Message objects in the new store");
    TEST_EQ(recipient_tables, 5u, "Recipient Tables");
    TEST_EQ(attachment_tables, 2u, "Attachment Tables");
    TEST_EQ(attachment_objects, 5u, "Attachment objects");
    TEST_EQ(payload_bytes, 9000u + 100u + 101u + 101u + 102u, "attachment payload bytes read back");
    TEST_CHECK_MSG(saw_multi_block_payload, "a payload past 8176 bytes round-tripped through a data tree");

    // Message object EntryIDs map the new store's NIDs ([MS-PST] 2.4.3.2). Recipient-table 0x0FFF
    // stays the source address-book provider's opaque value ([MS-PST] 2.4.5.3.1).
    for (const uint64_t nid : message_nids) {
        TEST_CHECK_MSG(contains_bytes(image, entry_id_bytes(static_cast<uint32_t>(nid))),
                   "a Message EntryID carries this store Provider UID and the Message NID");
    }
    for (size_t index = 0; index < 5; ++index) {
        TEST_CHECK_MSG(contains_bytes(image, recipient_entry_id(index)),
                   "a recipient address-book EntryID is preserved exactly");
    }
}

// The Name-to-ID Map of the new store: three identities, each findable the way the reader finds a named
// property, with the custom property set in the GUID Stream and the well-known ones not duplicated there.
void check_named_properties(const ltp::LtpReadReport& census) {
    TEST_EQ(census.named_properties, 3u, "Name-to-ID Map entries");
    // [MS-PST] 2.4.2.2 and 2.4.7.1: the first NPID is 0x8000; wPropIdx is
    // the zero-based Entry Stream ordinal, including in every hash-bucket copy.
    for (size_t index = 0; index < census.name_id_map.entries.size(); ++index) {
        TEST_EQ(census.name_id_map.entries[index].npid, 0x8000u + index,
                "NPID must match its Entry Stream position, with no missing ordinal zero");
    }
    for (const auto& bucket : census.name_id_map.bucket_records) {
        TEST_CHECK_MSG(bucket.prop_index < census.name_id_map.entries.size(),
                       "a bucket ordinal must index the Entry Stream");
        if (bucket.prop_index < census.name_id_map.entries.size()) {
            TEST_EQ(census.name_id_map.entries[bucket.prop_index].npid, ltp::name_id_npid(bucket),
                    "the bucket references the same named identity");
        }
    }
    TEST_EQ(census.npm.bucket_mismatches, 0u, "records that hash to the wrong bucket");
    TEST_EQ(census.npm.crc_mismatches, 0u,
            "names whose CRC is missing from the bucket holding them");
    TEST_CHECK_MSG(census.npm.crc_matches >= 2u, "both string names hash into their buckets");
    TEST_EQ(census.npm.entries_string, 2u, "Entry Stream records naming a String Stream offset");
    TEST_EQ(census.npm.entries_numeric, 1u, "Entry Stream records holding a numeric name");
    TEST_EQ(census.npm.guid_custom_refs, 1u, "records that resolve through the GUID Stream");
    // Only a property set that is neither well-known nor NAMEID_GUID_NONE needs a GUID Stream entry
    // ([MS-PST] 2.4.7.1 / 2.4.7.2), so this store has exactly the custom one.
    TEST_EQ(census.npm.guid_stream_entries, 1u, "the GUID Stream holds the custom property set");
    TEST_EQ(census.npm.names_unresolved, 0u, "names the String Stream could not give");

    Result<ltp::NamedProperty> numeric = ltp::name_id_lookup_npid(census.name_id_map, 0x8001);
    TEST_OK(numeric, "lookup of the numeric named property by NPID");
    if (numeric.ok()) {
        TEST_EQ(numeric.value().numeric_name, 0x1234u, "the numeric name survived the re-registration");
        TEST_CHECK_MSG(!numeric.value().name_is_string, "N == 0 stayed numeric");
        TEST_CHECK_MSG(numeric.value().guid == kMapiGuid, "PS_MAPI stayed the well-known property set");
        TEST_CHECK_MSG(!numeric.value().guid_from_file, "a well-known property set is not a GUID Stream entry");
    }
    Result<ltp::NamedProperty> custom =
        ltp::name_id_lookup(census.name_id_map, u"urn:schemas:mailheader:x-m5-test");
    TEST_OK(custom, "lookup of the custom named property by name");
    if (custom.ok()) {
        TEST_CHECK_MSG(custom.value().guid == kCustomGuid, "the custom property set round-tripped");
        TEST_CHECK_MSG(custom.value().guid_from_file, "the custom GUID came from the new GUID Stream");
        TEST_EQ(custom.value().guid_kind, ltp::NameIdGuidKind::kStream, "wGuid above 2");
    }
    Result<ltp::NamedProperty> plain = ltp::name_id_lookup(census.name_id_map, u"x-m5-plain");
    TEST_OK(plain, "lookup of the property with no property set");
    if (plain.ok()) {
        TEST_EQ(plain.value().guid_kind, ltp::NameIdGuidKind::kNone, "wGuid 0 is NAMEID_GUID_NONE");
    }
}

// The Contents Table cell copied out of a Message PC has to carry the width the column declares. A
// PtypBoolean is 4 bytes in a PC and 1 byte in a Row Matrix column, both measured on the sample:
// research/subtree-2001C4.txt:51 and research/subtree-852E-acsl-contents.txt:40.
void check_contents_cells(const FileReader &file, const writer::StoreOutcome &outcome) {
    Result<ltp::LtpReadReport> read = ltp::read_ltp(file, ltp::LtpReadOptions());
    TEST_OK(read, "read_ltp for the Contents Table cells");
    if (!read.ok()) {
        return;
    }
    const ltp::LtpReadReport &census = read.value();
    const uint32_t folder_nid = outcome.report.folder_nids.empty() ? 0u : outcome.report.folder_nids[0];
    uint32_t contents_nid = 0;
    for (const ltp::NodeRef &node : census.nodes.group(folder_nid)) {
        if (ltp::nid_type(node.nid) == ltp::kNidTypeContentsTable) {
            contents_nid = static_cast<uint32_t>(node.nid);
        }
    }
    TEST_CHECK_MSG(contents_nid != 0, "the Contents Table sits under the new folder nidIndex");
    if (contents_nid == 0) {
        return;
    }
    Result<ltp::NodeRef> ref = census.nodes.node(contents_nid);
    TEST_OK(ref, "the Contents Table NBT entry");
    if (!ref.ok()) {
        return;
    }

    ndb::BlockReadCounters counters;
    ndb::FailureLog failures(20);
    ltp::FileBlockSource blocks(file, census.profile, census.bbt_index, counters, failures);
    ltp::NodeHeap heap_node;
    ltp::LtpHeapCounters heap_counters;
    ltp::DataTreeCounters tree_counters;
    std::map<std::string, uint64_t> errors;
    const ltp::NodeOpen opened = ltp::open_node(blocks, census.profile, contents_nid, ref.value().bid_data,
                                                heap_node, heap_counters, tree_counters, errors, nullptr,
                                                failures);
    TEST_EQ(opened, ltp::NodeOpen::kOk, "the Contents Table node opens as a heap node");
    if (opened != ltp::NodeOpen::kOk || heap_node.source == nullptr) {
        return;
    }

    Result<ltp::TcTable> table = ltp::read_tc(heap_node.header, *heap_node.source);
    TEST_OK(table, "read_tc on the Contents Table");
    if (!table.ok()) {
        return;
    }
    const ltp::TcColumn *column = nullptr;
    for (const ltp::TcColumn &candidate : table.value().columns) {
        if (candidate.tag == 0x0057000B) {
            column = &candidate;
        }
    }
    TEST_CHECK_MSG(column != nullptr, "the Contents Table carries the 0x0057000B column");
    if (column == nullptr) {
        return;
    }
    TEST_EQ(column->cb_data, 1u, "a PtypBoolean column declares cbData 1");

    std::vector<ltp::TcRowId> rows;
    ltp::BthStats stats;
    const ost2pst::util::Status walked =
        ltp::walk_tc_row_index(table.value(), census.profile, *heap_node.source,
                               [&](const ltp::TcRowId &row) {
                                   rows.push_back(row);
                                   return rows.size() < 16;
                               },
                               stats, failures);
    TEST_OK(walked, "walk_tc_row_index on the Contents Table");
    TEST_EQ(rows.size(), 5u, "Contents Table rows");

    Result<ByteView> matrix = ltp::hn_heap_item(heap_node.page_map, heap_node.block.heap_node(),
                                                table.value().info.hnid_rows, census.profile);
    TEST_OK(matrix, "the Row Matrix of the Contents Table");
    if (!matrix.ok()) {
        return;
    }
    const uint64_t row_size = ltp::tc_row_size(table.value().info);
    for (size_t index = 0; index < rows.size(); ++index) {
        Result<ByteView> row = matrix.value().sub(rows[index].row_index * row_size, row_size);
        TEST_OK(row, "one Contents Table row");
        if (!row.ok()) {
            continue;
        }
        Result<ltp::TcCell> cell = ltp::tc_column_cell(table.value(), *column, row.value());
        TEST_OK(cell, "the 0x0057 cell of a Contents Table row");
        if (!cell.ok()) {
            continue;
        }
        TEST_CHECK_MSG(cell.value().exists, "the row carries a value for 0x0057");
        TEST_EQ(cell.value().value.size(), 1u,
                "the 4-byte PC boolean became the 1 byte the column declares");
        if (cell.value().value.size() == 1) {
            Result<uint8_t> stored = cell.value().value.u8(0);
            TEST_OK(stored, "the byte the narrowed boolean holds");
            if (stored.ok()) {
                TEST_EQ(stored.value(), index == 0 ? 0u : 1u,
                        "the boolean value survived the narrowing");
            }
        }
    }
}

// A folder big enough that the Contents Table's Row Matrix leaves the heap ([MS-PST] 2.6.2.2.2) and has to
// be spread over two data blocks ([MS-PST] 2.3.4.4). 70 rows of 126 bytes is 8,820 bytes, and 126 does not
// divide 8,176, so a full block holds 64 whole rows and 112 bytes the rows never occupy.
writer::StoreRequest build_many_request(size_t message_count) {
    writer::StoreRequest request;
    writer::ContentFolder folder;
    folder.parent_nid = writer::kNidIpmsubtree;
    folder.name = u16("M5 Matrix Folder");
    for (size_t index = 0; index < message_count; ++index) {
        writer::ContentMessage message;
        message.properties.push_back(value_of(0x001A, kTypeUnicode, u16_bytes(u16("IPM.Note"))));
        message.properties.push_back(value_of(0x0E07, kTypeInteger32, le32_bytes(1)));
        message.properties.push_back(
            value_of(0x0E08, kTypeInteger32, le32_bytes(4096u + static_cast<uint32_t>(index))));
        message.properties.push_back(value_of(0x0E17, kTypeInteger32, le32_bytes(0)));
        message.properties.push_back(value_of(0x3007, kTypeTime, blob(8, static_cast<uint8_t>(index))));
        message.properties.push_back(value_of(0x3008, kTypeTime, blob(8, static_cast<uint8_t>(index))));
        message.properties.push_back(value_of(0x300B, kTypeBinary, blob(16, static_cast<uint8_t>(index))));
        message.properties.push_back(value_of(0x1000, kTypeUnicode, u16_bytes(u16_num("body ", index))));
        folder.messages.push_back(std::move(message));
    }
    request.folders.push_back(std::move(folder));
    return request;
}

// [MS-PST] 2.3.4.4 gives the Row Matrix two rules at once: whole rows per block, and "Each block except the
// last one MUST have a size of 8192 bytes". A row therefore has to be found by which block holds it, not by
// multiplying the row index by the row width across a concatenation of blocks.
void check_two_block_matrix(const FileReader &file, const writer::StoreOutcome &outcome,
                            size_t message_count) {
    Result<ltp::LtpReadReport> read = ltp::read_ltp(file, ltp::LtpReadOptions());
    TEST_OK(read, "read_ltp for the two-block Row Matrix");
    if (!read.ok()) {
        return;
    }
    const ltp::LtpReadReport &census = read.value();
    const uint32_t folder_nid = outcome.report.folder_nids.empty() ? 0u : outcome.report.folder_nids[0];
    uint32_t contents_nid = 0;
    for (const ltp::NodeRef &node : census.nodes.group(folder_nid)) {
        if (ltp::nid_type(node.nid) == ltp::kNidTypeContentsTable) {
            contents_nid = static_cast<uint32_t>(node.nid);
        }
    }
    TEST_CHECK_MSG(contents_nid != 0, "the Contents Table of the folder with " + std::to_string(message_count) + " messages");
    if (contents_nid == 0) {
        return;
    }
    Result<ltp::NodeRef> ref = census.nodes.node(contents_nid);
    TEST_OK(ref, "the Contents Table NBT entry");
    if (!ref.ok()) {
        return;
    }
    ndb::BlockReadCounters counters;
    ndb::FailureLog failures(20);
    ltp::FileBlockSource blocks(file, census.profile, census.bbt_index, counters, failures);
    ltp::NodeHeap heap_node;
    ltp::LtpHeapCounters heap_counters;
    ltp::DataTreeCounters tree_counters;
    std::map<std::string, uint64_t> errors;
    const ltp::NodeOpen opened = ltp::open_node(blocks, census.profile, contents_nid, ref.value().bid_data,
                                                heap_node, heap_counters, tree_counters, errors, nullptr,
                                                failures);
    TEST_EQ(opened, ltp::NodeOpen::kOk, "the Contents Table node opens as a heap node");
    if (opened != ltp::NodeOpen::kOk || heap_node.source == nullptr) {
        return;
    }
    Result<ltp::TcTable> table = ltp::read_tc(heap_node.header, *heap_node.source);
    TEST_OK(table, "read_tc on the Contents Table");
    if (!table.ok()) {
        return;
    }
    const uint64_t row_size = ltp::tc_row_size(table.value().info);
    TEST_CHECK_MSG(row_size != 0 && ndb::kPstBlockMaxCb % row_size != 0,
                   "the row width does not divide one data block, which is the case the rule is about");
    TEST_CHECK_MSG(ltp::hid_type(table.value().info.hnid_rows) != ltp::kHidTypeHid,
                   "a Row Matrix too big for the heap is a subnode ([MS-PST] 2.3.4.1 / 2.6.2.2.2)");
    ltp::SubnodeStats subnode_stats;
    const Result<ltp::SubnodeRef> sub = ltp::find_subnode(ref.value().bid_sub, table.value().info.hnid_rows,
                                                          blocks, subnode_stats, failures);
    TEST_OK(sub, "the Row Matrix subnode");
    if (!sub.ok()) {
        return;
    }
    const Result<std::vector<ltp::HnFragment>> tree =
        ltp::read_data_tree(blocks, sub.value().bid_data, census.profile, tree_counters, failures);
    TEST_OK(tree, "the Row Matrix data tree");
    if (!tree.ok()) {
        return;
    }
    TEST_EQ(tree.value().size(), 2u, "the Row Matrix spans two data blocks");
    if (tree.value().size() != 2) {
        return;
    }
    const uint64_t full = ndb::block_max_cb(census.profile);
    const uint64_t rows_in_full = full / row_size;
    TEST_EQ(tree.value()[0].block.bytes().size(), full,
            "the first block carries a whole block of bytes, dead space inside cb ([MS-PST] 2.2.2.8)");
    TEST_EQ(ndb::align_allocation(census.profile, full + ndb::block_trailer_size(census.profile)), 8192u,
            "and its footprint is the 8192 bytes [MS-PST] 2.3.4.4 requires of every block but the last");
    const uint64_t rows_left = message_count - rows_in_full;
    TEST_EQ(tree.value()[1].block.bytes().size(), rows_left * row_size,
            "the last block carries exactly the rows left over, with no dead space");
    std::vector<ltp::TcRowId> rows;
    ltp::BthStats stats;
    const ost2pst::util::Status walked =
        ltp::walk_tc_row_index(table.value(), census.profile, *heap_node.source,
                               [&](const ltp::TcRowId &row) {
                                   rows.push_back(row);
                                   return rows.size() < 128;
                               },
                               stats, failures);
    TEST_OK(walked, "walk_tc_row_index on the two-block Contents Table");
    TEST_EQ(rows.size(), message_count, "every Contents Table row is in the RowIndex");
    const ltp::TcColumn *column = nullptr;
    for (const ltp::TcColumn &candidate : table.value().columns) {
        if (candidate.tag == 0x0E080003) {
            column = &candidate;
        }
    }
    TEST_CHECK_MSG(column != nullptr, "the Contents Table carries the 0x0E08 column");
    if (column == nullptr) {
        return;
    }
    uint64_t from_second_block = 0;
    for (const ltp::TcRowId &row : rows) {
        const size_t block_index = row.row_index < rows_in_full ? 0 : 1;
        const uint64_t first_row = block_index == 0 ? 0 : rows_in_full;
        const uint64_t offset = (static_cast<uint64_t>(row.row_index) - first_row) * row_size;
        TEST_CHECK_MSG(offset + row_size <= tree.value()[block_index].block.bytes().size(),
                       "the row sits inside the block that holds it, never across a block edge");
        const Result<ByteView> row_bytes =
            tree.value()[block_index].block.bytes().sub(static_cast<size_t>(offset), row_size);
        TEST_OK(row_bytes, "one Contents Table row out of the block that holds it");
        if (!row_bytes.ok()) {
            continue;
        }
        const Result<ltp::TcCell> cell = ltp::tc_column_cell(table.value(), *column, row_bytes.value());
        TEST_OK(cell, "the 0x0E08 cell of a Contents Table row");
        if (!cell.ok() || !cell.value().exists) {
            continue;
        }
        const Result<uint32_t> stored = cell.value().value.u32(0);
        TEST_OK(stored, "the 4 bytes the 0x0E08 column holds");
        if (stored.ok()) {
            TEST_EQ(stored.value(), 4096u + static_cast<uint32_t>(row.row_index),
                    "the row carries the message it stands for, read out of its own block");
        }
        if (block_index == 1) {
            ++from_second_block;
        }
    }
    TEST_EQ(from_second_block, rows_left,
            "the rows past the first block came out of the second block, not out of the first block dead space");
}
// One folder, one Message, one Attachment object whose content is itself a Message: 0x3705 is 5 and
// 0x3701 is the PtypObject that names the attached Message subnode ([MS-PST] 2.4.6.2.2).
writer::StoreRequest build_embedded_request() {
    writer::StoreRequest request;
    writer::ContentFolder folder;
    folder.parent_nid = writer::kNidIpmsubtree;
    folder.name = u16("M5 Attached Folder");

    const uint16_t kRequiredIds[7] = {0x001A, 0x0E07, 0x0E08, 0x0E17, 0x3007, 0x3008, 0x300B};
    const auto fill_required = [&](writer::ContentMessage &target, uint8_t seed) {
        target.properties.push_back(value_of(0x001A, kTypeUnicode, u16_bytes(u16("IPM.Note"))));
        target.properties.push_back(value_of(0x0E07, kTypeInteger32, le32_bytes(1)));
        target.properties.push_back(value_of(0x0E08, kTypeInteger32, le32_bytes(4096u + seed)));
        target.properties.push_back(value_of(0x0E17, kTypeInteger32, le32_bytes(0)));
        target.properties.push_back(value_of(0x3007, kTypeTime, blob(8, seed)));
        target.properties.push_back(value_of(0x3008, kTypeTime, blob(8, seed)));
        target.properties.push_back(value_of(0x300B, kTypeBinary, blob(16, seed)));
    };

    writer::ContentMessage message;
    fill_required(message, 1);
    message.properties.push_back(value_of(0x0037, kTypeUnicode, u16_bytes(u16("outer subject"))));
    message.properties.push_back(value_of(0x1000, kTypeUnicode, u16_bytes(u16("outer body"))));

    writer::ContentRow recipient;
    recipient.cells.push_back(cell_of(0x0C150003, le32_bytes(0)));
    recipient.cells.push_back(cell_of(0x3001001F, u16_bytes(u16("Outer Recipient"))));
    message.recipients.columns = {0x0C150003, 0x3001001F};
    message.recipients.rows.push_back(std::move(recipient));

    writer::ContentRow row;
    row.cells.push_back(cell_of(0x0E200003, le32_bytes(300)));
    row.cells.push_back(cell_of(0x3703001F, u16_bytes(u16("fwd: note.eml"))));
    message.attachments.columns = {0x0E200003, 0x3703001F};
    message.attachments.rows.push_back(std::move(row));

    writer::ContentAttachment object;
    // [MS-PST] 2.4.6.2.1: the three tags an Attachment object PC MUST carry.
    object.properties.push_back(value_of(0x0E20, kTypeInteger32, le32_bytes(300)));
    object.properties.push_back(value_of(0x3705, kTypeInteger32, le32_bytes(5))); // olEmbeddedmessage
    object.properties.push_back(value_of(0x370B, kTypeInteger32, le32_bytes(0)));
    object.has_embedded = true;
    object.embedded_ul_size = 0; // the source stated no ulSize, so the writer states the one it laid down

    writer::ContentMessage embedded;
    fill_required(embedded, 2);
    embedded.properties.push_back(value_of(0x0037, kTypeUnicode, u16_bytes(u16("attached subject"))));
    embedded.properties.push_back(value_of(0x1000, kTypeUnicode, u16_bytes(u16("attached body"))));
    writer::ContentRow embedded_recipient;
    embedded_recipient.cells.push_back(cell_of(0x0C150003, le32_bytes(0)));
    embedded_recipient.cells.push_back(cell_of(0x3001001F, u16_bytes(u16("Attached Recipient"))));
    embedded.recipients.columns = {0x0C150003, 0x3001001F};
    embedded.recipients.rows.push_back(std::move(embedded_recipient));
    object.embedded = std::move(embedded);

    message.attachment_objects.push_back(std::move(object));
    folder.messages.push_back(std::move(message));
    request.folders.push_back(std::move(folder));
    (void)kRequiredIds;
    return request;
}

// The attached Message has to come back out of the bytes the writer wrote: 0x3701 as a PtypObject naming a
// Message subnode of the Attachment object, that subnode carrying its own Property Context and Recipient
// Table, and none of it taking a slot from the NBT ([MS-PST] 2.4.6.2.2, 2.3.3.5, 2.6.1.2.2).
void check_embedded_message(const FileReader &file, const writer::StoreOutcome &outcome,
                            const std::vector<uint8_t> &image) {
    Result<ndb::ProbeReport> probed = ndb::probe_file(file, ndb::ProbeOptions());
    TEST_OK(probed, "probe_file on the store with an attached Message");
    if (probed.ok()) {
        dump_failures("probe", probed.value().failures);
        TEST_CHECK_MSG(probed.value().clean, "probe_file is not clean on the store with an attached Message");
    }

    Result<ltp::LtpReadReport> read = ltp::read_ltp(file, ltp::LtpReadOptions());
    TEST_OK(read, "read_ltp on the store with an attached Message");
    if (!read.ok()) {
        return;
    }
    const ltp::LtpReadReport &census = read.value();
    dump_failures("read_ltp", census.failures);
    for (const ltp::LtpFinding &finding : census.findings.items) {
        dump_finding(finding);
    }
    TEST_CHECK_MSG(census.clean, "read_ltp is not clean on the store with an attached Message");
    TEST_EQ(census.failure_total, 0u, "read_ltp failures");
    TEST_EQ(census.findings.total, 0u, "read_ltp findings");
    TEST_EQ(census.pcs.failed, 0u, "Property Contexts the reader failed to read");
    TEST_EQ(census.tcs.failed, 0u, "Table Contexts the reader failed to read");

    uint64_t nbt_messages = 0;
    uint64_t message_nid = 0;
    for (const ltp::NodeRef &entry : census.nodes.entries()) {
        if (ltp::nid_type(entry.nid) == ltp::kNidTypeNormalMessage) {
            ++nbt_messages;
            message_nid = entry.nid;
        }
    }
    TEST_EQ(nbt_messages, 1u, "the NBT names only the Message object the folder holds");
    TEST_EQ(outcome.report.messages, 2u, "while the writer built two: the folder one and the attached one");
    if (message_nid == 0) {
        return;
    }

    ltp::SubtreeDumpOptions options;
    options.max_nodes = 200;
    options.max_depth = 4;
    options.max_pc_records = 400;
    options.max_row_ids = 16;
    ndb::BlockReadCounters counters;
    ndb::FailureLog failures(20);
    ltp::FileBlockSource blocks(file, census.profile, census.bbt_index, counters, failures);

    Result<ltp::SubtreeDump> dumped =
        ltp::dump_subtree(census.nodes, blocks, census.profile, message_nid, options);
    TEST_OK(dumped, "dump_subtree on the Message object with the attached Message");
    if (!dumped.ok()) {
        return;
    }
    const ltp::SubtreeDump &subtree = dumped.value();
    TEST_EQ(subtree.failure_total, 0u, "subtree dump failures");
    const ltp::DumpNode *attachment = nullptr;
    for (const ltp::DumpNode &subnode : subtree.subnodes) {
        if (subnode.nid_type == ltp::kNidTypeAttachment) {
            attachment = &subnode;
        }
    }
    TEST_CHECK_MSG(attachment != nullptr, "the Attachment object subnode");
    if (attachment == nullptr) {
        return;
    }
    bool object_form = false;
    for (const ltp::DumpPcValue &value : attachment->pc) {
        if (value.prop_id != 0x3701) {
            continue;
        }
        object_form = true;
        TEST_EQ(value.prop_type, kTypeObject, "0x3701 written as PtypObject ([MS-PST] 2.4.6.2.2)");
        TEST_CHECK_MSG(value.in_heap, "a PtypObject value is a heap allocation of the node ([MS-PST] 2.3.3.2)");
        TEST_CHECK_MSG(value.answered, "the allocation resolved");
        TEST_EQ(value.bytes, 8u, "and it is the 8 bytes [MS-PST] 2.3.3.5 defines: Nid then ulSize");
    }
    TEST_CHECK_MSG(object_form, "the Attachment object carries 0x3701 as its content");

    // The attached Message is a subnode the Attachment object's own list names, so it shows up in the
    // same dump at the next depth ([MS-PST] 2.4.6.2.2, 2.2.2.8.3.3.1.1: a subnode NID is unique only within
    // its parent, so it is not an NBT entry).
    const ltp::DumpNode *attached = nullptr;
    for (const ltp::DumpNode &subnode : subtree.subnodes) {
        if (subnode.nid_type == ltp::kNidTypeNormalMessage &&
            subnode.parent_local_nid == attachment->local_nid) {
            attached = &subnode;
        }
    }
    TEST_CHECK_MSG(attached != nullptr, "the Attachment object has a Message subnode ([MS-PST] 2.4.6.2.2)");
    if (attached == nullptr) {
        return;
    }
    uint64_t recipient_tables = 0;
    for (const ltp::DumpNode &subnode : subtree.subnodes) {
        if (subnode.nid_type == ltp::kNidTypeRecipientTable &&
            subnode.parent_local_nid == attached->local_nid) {
            ++recipient_tables;
            TEST_CHECK_MSG(subnode.tc.read, "the attached Message's Recipient Table read");
            TEST_EQ(subnode.tc.rows, 1u, "with its one row");
        }
    }
    TEST_EQ(recipient_tables, 1u, "and the attached Message carries its own Recipient Table ([MS-PST] 2.4.5.3)");
    std::vector<uint8_t> allocation = le32_bytes(static_cast<uint32_t>(attached->local_nid));
    const std::vector<uint8_t> ul_size = le32_bytes(static_cast<uint32_t>(outcome.report.embedded_bytes));
    allocation.insert(allocation.end(), ul_size.begin(), ul_size.end());
    TEST_CHECK_MSG(contains_bytes(image, allocation),
                   "the 0x3701 allocation names that subnode with the ulSize of the blocks under it");

    bool subject = false;
    bool body = false;
    bool required[7] = {false, false, false, false, false, false, false};
    const uint16_t required_ids[7] = {0x001A, 0x0E07, 0x0E08, 0x0E17, 0x3007, 0x3008, 0x300B};
    for (const ltp::DumpPcValue &value : attached->pc) {
        for (size_t index = 0; index < 7; ++index) {
            if (value.prop_id == required_ids[index]) {
                required[index] = true;
            }
        }
        if (value.prop_id == 0x0037) {
            subject = true;
        }
        if (value.prop_id == 0x1000) {
            body = true;
        }
    }
    for (size_t index = 0; index < 7; ++index) {
        TEST_CHECK_MSG(required[index], "the attached Message PC carries a tag [MS-PST] 2.4.5.1.1 requires");
    }
    TEST_CHECK_MSG(subject, "the attached Message keeps its own subject");
    TEST_CHECK_MSG(body, "and its own body");
    TEST_CHECK_MSG(contains_bytes(image, u16_bytes(u16("attached subject"))),
                   "the attached subject is in the bytes of the new store");
    TEST_CHECK_MSG(contains_bytes(image, u16_bytes(u16("Attached Recipient"))),
                   "and its recipient row");
    TEST_CHECK_MSG(outcome.report.embedded_bytes > 0u, "the writer counted the blocks under the attached Message");
}

std::filesystem::path temp_path(const char *name) {
    std::filesystem::path path = std::filesystem::temp_directory_path();
    path /= name;
    std::error_code ignored;
    if (std::getenv("OST2PST_KEEP_CANDIDATE") == nullptr) {
        std::filesystem::remove(path, ignored);
    }
    return path;
}

void check_named_property_capacity() {
    // [MS-PST] 2.4.2.2: 0x8000 through 0x8FFF includes 4096 identities.
    writer::StoreRequest request;
    for (uint32_t index = 0; index < 4096; ++index) {
        writer::NamedProperty property;
        property.name_is_string = false;
        property.numeric_name = index;
        property.guid = kMapiGuid;
        request.named_properties.push_back(std::move(property));
    }
    const auto full = writer::build_store(request);
    TEST_OK(full, "all 4096 named property identifiers fit the reserved range");
    request.named_properties.push_back(request.named_properties.back());
    const auto overflow = writer::build_store(request);
    TEST_CHECK_MSG(!overflow.ok(), "a 4097th named identity exceeds the NPID range");
}

void check_named_table_column_contract() {
    auto request = build_request();
    auto& table = request.folders[0].messages[0].recipients;
    table.columns.emplace_back(0x81000003);
    auto missing = writer::build_store(request);
    TEST_CHECK_MSG(!missing.ok(), "a numeric source NPID alone is not a column identity");
    if (!missing.ok())
        TEST_STR(missing.error().field, "writer.table.named_column", "column contract");
    table.columns.back().named = true;
    table.columns.back().named_index = request.named_properties.size();
    auto invalid = writer::build_store(request);
    TEST_CHECK_MSG(!invalid.ok(), "a named column must index the registered identity array");
    if (!invalid.ok())
        TEST_STR(invalid.error().field, "writer.table.named_index", "index contract");
    table.columns.back().named_index = 1;
    table.columns.emplace_back(0x81010003, true, 1);
    table.rows[0].cells.push_back(cell_of(0x81000003, le32_bytes(111)));
    table.rows[0].cells.push_back(cell_of(0x81010003, le32_bytes(222)));
    const auto collision = writer::build_store(request);
    TEST_OK(collision, "source aliases share one destination column");
    if (collision.ok()) {
        TEST_EQ(collision.value().report.values_dropped, 1u,
                "conflicting cell aliases are reported instead of silently overwritten");
    }
}

} // namespace

int main() {
    check_named_property_capacity();
    check_named_table_column_contract();
    // The empty request has to be the M4 candidate byte for byte: the content build replaces the minimum
    // mailbox code, it does not change what that code produced.
    Result<writer::StoreOutcome> empty = writer::build_store(writer::StoreRequest());
    TEST_OK(empty, "build_store with an empty request");
    Result<writer::EmptyPstImage> baseline = writer::build_empty_pst();
    TEST_OK(baseline, "build_empty_pst");
    if (empty.ok() && baseline.ok()) {
        TEST_EQ(empty.value().image.bytes.size(), baseline.value().bytes.size(),
                "the empty content store has the M4 size");
        TEST_CHECK_MSG(empty.value().image.bytes == baseline.value().bytes,
                   "the empty content store is the M4 candidate byte for byte");
        TEST_EQ(empty.value().report.messages, 0u, "no messages in an empty store");
        // The report counts identities the caller handed over; the minimum map still carries its own
    // synthetic entry, which the reader reports instead (src/writer/content.cpp).
    TEST_EQ(empty.value().report.named_properties, 0u, "no identities handed over");
    }

    Result<writer::StoreOutcome> built = writer::build_store(build_request());
    TEST_OK(built, "build_store with one folder");
    if (!built.ok()) {
        std::fprintf(stderr, "build_store: %s\n",
                     ost2pst::util::format_error(built.error()).c_str());
        return ost2pst::test::finish("writer_content_test");
    }
    const writer::StoreOutcome &outcome = built.value();
    check_report(outcome.report);
    check_blocks(outcome.image);
    for (const std::string &note : outcome.report.notes) {
        std::printf("  note: %s\n", note.c_str());
    }

    const std::filesystem::path path = temp_path(kTempName);
    {
        std::ofstream stream(path, std::ios::binary);
        if (!stream) {
            ost2pst::test::report_failure(__FILE__, __LINE__, "cannot create the candidate PST");
            return ost2pst::test::finish("writer_content_test");
        }
        stream.write(reinterpret_cast<const char *>(outcome.image.bytes.data()),
                     static_cast<std::streamsize>(outcome.image.bytes.size()));
    }

    Result<FileReader> opened = FileReader::open(path.native());
    TEST_OK(opened, "FileReader::open");
    if (opened.ok()) {
        check_structure(opened.value(), outcome.report);
        check_content(opened.value(), outcome, outcome.image.bytes);
        check_contents_cells(opened.value(), outcome);
        Result<ltp::LtpReadReport> read = ltp::read_ltp(opened.value(), ltp::LtpReadOptions());
        if (read.ok()) {
            check_named_properties(read.value());
        }
    }

    std::error_code ignored;
    if (std::getenv("OST2PST_KEEP_CANDIDATE") == nullptr) {
        std::filesystem::remove(path, ignored);
    }
    // The two-block Row Matrix case: 70 messages, 126-byte rows, a row width that does not divide a block.
    constexpr size_t kMatrixMessages = 70;
    Result<writer::StoreOutcome> many = writer::build_store(build_many_request(kMatrixMessages));
    TEST_OK(many, "build_store with a folder of 70 messages");
    if (many.ok()) {
        const writer::StoreOutcome &big = many.value();
        TEST_EQ(big.report.messages, kMatrixMessages, "messages emitted");
        check_blocks(big.image);
        const std::filesystem::path big_path = temp_path(kMatrixTempName);
        {
            std::ofstream stream(big_path, std::ios::binary);
            if (!stream) {
                ost2pst::test::report_failure(__FILE__, __LINE__, "cannot create the two-block matrix PST");
            } else {
                stream.write(reinterpret_cast<const char *>(big.image.bytes.data()),
                             static_cast<std::streamsize>(big.image.bytes.size()));
            }
        }
        Result<FileReader> big_opened = FileReader::open(big_path.native());
        TEST_OK(big_opened, "FileReader::open on the store with the two-block Row Matrix");
        if (big_opened.ok()) {
            check_two_block_matrix(big_opened.value(), big, kMatrixMessages);
        }
        if (std::getenv("OST2PST_KEEP_CANDIDATE") == nullptr) {
            std::filesystem::remove(big_path, ignored);
        }
    }

    // The attached-Message case: an Attachment object whose content is itself a Message.
    Result<writer::StoreOutcome> attached = writer::build_store(build_embedded_request());
    TEST_OK(attached, "build_store with an Attachment object that is a Message");
    if (attached.ok()) {
        const writer::StoreOutcome &with_attached = attached.value();
        TEST_EQ(with_attached.report.attachments, 1u, "one Attachment object written");
        TEST_EQ(with_attached.report.embedded_messages, 1u, "one attached Message written under it");
        TEST_CHECK_MSG(with_attached.report.embedded_bytes > 0u, "the blocks under the attached Message counted");
        check_blocks(with_attached.image);
        for (const std::string &note : with_attached.report.notes) {
            std::printf("  attached-Message note: %s\n", note.c_str());
        }
        const std::filesystem::path attached_path = temp_path(kEmbeddedTempName);
        {
            std::ofstream stream(attached_path, std::ios::binary);
            if (!stream) {
                ost2pst::test::report_failure(__FILE__, __LINE__, "cannot create the attached-Message PST");
            } else {
                stream.write(reinterpret_cast<const char *>(with_attached.image.bytes.data()),
                             static_cast<std::streamsize>(with_attached.image.bytes.size()));
            }
        }
        Result<FileReader> attached_opened = FileReader::open(attached_path.native());
        TEST_OK(attached_opened, "FileReader::open on the store with an attached Message");
        if (attached_opened.ok()) {
            check_embedded_message(attached_opened.value(), with_attached, with_attached.image.bytes);
        }
        if (std::getenv("OST2PST_KEEP_CANDIDATE") == nullptr) {
            std::filesystem::remove(attached_path, ignored);
        }
    }

    std::printf("  candidate %s: %llu bytes, %llu blocks\n", kTempName,
                static_cast<unsigned long long>(outcome.image.bytes.size()),
                static_cast<unsigned long long>(outcome.report.blocks));
    return ost2pst::test::finish("writer_content_test");
}
