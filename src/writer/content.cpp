#include "ost2pst/writer/content.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/name_id.h"
#include "ost2pst/ltp/prop_type.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/writer/heap.h"
#include "ost2pst/writer/layout.h"
#include "ost2pst/writer/pc.h"
#include "ost2pst/writer/tc.h"

#include "internal/put.h"

namespace ost2pst::writer {

using util::ErrorKind;
using util::make_error;
using util::Result;

namespace {

// --- what the writer chooses, not what the spec fixes
// ---------------------------------------------

// [MS-PST] 2.4.3.1 requires PidTagRecordKey (0x0FF9, PtypBinary), the Provider UID of this PST, and
// 2.4.3.2 requires every EntryID to carry the same 16 bytes, but no document names a value a
// creator has to use. This is the writer's own fixed UID, not a spec constant;
// research/blank-pst-diff.md records it as a difference from the Outlook-generated blank PST.
const std::vector<uint8_t> kProviderUid = {
    0x22, 0x9D, 0xB5, 0x0A, 0xDC, 0xD9, 0x94, 0x43, //
    0x85, 0xDE, 0x90, 0xAE, 0xB0, 0x7D, 0x12, 0x70,
};

// [MS-PST] 2.4.3.1 requires a display name on the message store and names no value for it.
const char* kMessageStoreName = "OST2PST";

// Property types ([MS-OXCDATA] 2.11.1) the writer names, because ltp/prop_type.h carries the table
// as a function rather than as constants.
constexpr uint16_t kTypeInteger32 = 0x0003; // [MS-OXCDATA] 2.11.1 PtypInteger32
constexpr uint16_t kTypeBoolean = 0x000B;   // [MS-OXCDATA] 2.11.1 PtypBoolean
constexpr uint16_t kTypeUnicode = 0x001F;   // [MS-OXCDATA] 2.11.1 PtypUnicodeString
constexpr uint16_t kTypeBinary = 0x0102;    // [MS-OXCDATA] 2.11.1 PtypBinary
// The object type [MS-PST] 2.3.3.5 defines the shape of (docs/reference/ms-pst.txt:2771-2786) and
// the libpff notes name (libpff format notes (see THIRD_PARTY_NOTICES.txt):2491-2509).
constexpr uint16_t kTypeObject = 0x000D;

// [MS-PST] 2.7.3.2 states the minimum Name-to-ID Map as a PC carrying only the bucket count, and no
// document names the one named property a creator may carry. This is the writer's own: numeric name
// 1 under NAMEID_GUID_MAPI at ordinal 1, so its NPID is 0x8001.
constexpr uint32_t kNameidNumericName =
    0x0001; // [MS-PST] 2.4.7.1 dwPropertyID when N == 0 is the numeric name
constexpr uint16_t kNameidPropIndex = 0x0001; // [MS-PST] 2.4.7.1 NPID = 0x8000 + wPropIdx

// Message store property ids ([MS-PST] 2.4.3.1) and Folder object property ids ([MS-PST] 2.4.4.4).
constexpr uint16_t kPropRecordKey = 0x0FF9;         // [MS-PST] 2.4.3.1 PidTagRecordKey
constexpr uint16_t kPropIpmSubTreeEntryId = 0x35E0; // [MS-PST] 2.4.3.1 PidTagIpmSubTreeEntryId
constexpr uint16_t kPropIpmWastebasketEntryId =
    0x35E3;                                          // [MS-PST] 2.4.3.1 PidTagIpmWastebasketEntryId
constexpr uint16_t kPropFinderEntryId = 0x35E7;      // [MS-PST] 2.4.3.1 PidTagFinderEntryId
constexpr uint16_t kPropContentCount = 0x3602;       // [MS-PST] 2.7.3.4.1 PidTagContentCount
constexpr uint16_t kPropContentUnreadCount = 0x3603; // [MS-PST] 2.7.3.4.1 PidTagContentUnreadCount
constexpr uint16_t kPropSubfolders = 0x360A;         // [MS-PST] 2.7.3.4.1 PidTagSubfolders

// --- small builders
// -------------------------------------------------------------------------------

// [MS-PST] 2.4.3.2 ENTRYID: rgbFlags (4 bytes, each MUST be zero), the Provider UID (16 bytes),
// then the NID (4 bytes).
std::vector<uint8_t> entry_id(uint32_t nid) {
    std::vector<uint8_t> bytes(4 + kProviderUid.size() + 4, 0); // rgbFlags + Provider UID + nid
    std::copy(kProviderUid.begin(), kProviderUid.end(), bytes.begin() + 4);
    put_u32(bytes, 20, nid);
    return bytes;
}

// A PtypUnicodeString value in a PC heap allocation is the UTF-16LE bytes with no length prefix and
// no terminator -- the allocation size is the length ([MS-PST] 2.3.3.3, and ltp::walk_folder_tree
// decodes the allocation bytes exactly that way). Every name this writer emits is ASCII.
std::vector<uint8_t> utf16_bytes(const char* text) {
    std::vector<uint8_t> bytes;
    for (const char* p = text; *p != '\0'; ++p) {
        bytes.push_back(static_cast<uint8_t>(*p));
        bytes.push_back(0);
    }
    return bytes;
}

// The same for a name that came from a file rather than from the writer's own ASCII literals: the
// bytes are the UTF-16 code units, no length prefix, no terminator ([MS-PST] 2.3.3.6).
std::vector<uint8_t> utf16_bytes(const std::u16string& text) {
    std::vector<uint8_t> bytes;
    bytes.reserve(text.size() * 2);
    for (const char16_t unit : text) {
        bytes.push_back(static_cast<uint8_t>(unit & 0xFFu));
        bytes.push_back(static_cast<uint8_t>((unit >> 8) & 0xFFu));
    }
    return bytes;
}

// [MS-PST] 2.4.7.1 names PS_MAPI and PS_PUBLIC_STRINGS but defers their bytes to
// [MS-OXPROPS] 1.3.2, which this repository does not carry. libpff format notes (see
// THIRD_PARTY_NOTICES.txt):2264 and :2266 record both GUIDs and upstream
// libpff/libfmapi/libfmapi_class_identifier.c:29 and :32 hold the same 16 bytes, so the writer
// carries them as reference values, exactly as src/ltp/name_id.cpp does.
std::vector<uint8_t> guid_stream() {
    static const uint8_t kGuids[32] = {
        0x28, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x46, 0x29, 0x03, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    };
    return std::vector<uint8_t>(kGuids, kGuids + sizeof(kGuids));
}

std::vector<uint8_t> le32_bytes(uint32_t value) {
    std::vector<uint8_t> bytes(4, 0);
    put_u32(bytes, 0, value);
    return bytes;
}

// NAMEID record ([MS-PST] 2.4.7.1): dwPropertyID, then the WORD holding N (low bit) and wGuid (the
// 15 bits above it), then wPropIdx.
std::vector<uint8_t> name_id_record(uint32_t property_id, bool string_name, uint16_t guid_index,
                                    uint16_t prop_index) {
    std::vector<uint8_t> record(ltp::kNameIdRecordSize, 0);
    put_u32(record, ltp::kNameIdPropertyIdOffset, property_id);
    put_u16(record, ltp::kNameIdGuidOffset,
            static_cast<uint16_t>((guid_index << ltp::kNameIdGuidShift) |
                                  (string_name ? ltp::kNameIdNameBit : 0u)));
    put_u16(record, ltp::kNameIdPropIdxOffset, prop_index);
    return record;
}

PcProperty integer_property(uint16_t prop_id, uint32_t value) {
    PcProperty property;
    property.prop_id = prop_id;
    property.prop_type = kTypeInteger32;
    property.value = le32_bytes(value);
    return property;
}

PcProperty boolean_property(uint16_t prop_id, uint32_t value) {
    PcProperty property;
    property.prop_id = prop_id;
    property.prop_type = kTypeBoolean;
    property.value = {static_cast<uint8_t>(value != 0 ? 1 : 0)};
    return property;
}

PcProperty binary_property(uint16_t prop_id, std::vector<uint8_t> value) {
    PcProperty property;
    property.prop_id = prop_id;
    property.prop_type = kTypeBinary;
    property.value = std::move(value);
    return property;
}

// [MS-PST] 2.3.3.5: a PtypObject value is a heap allocation holding Nid, the subnode that carries
// the object, then ulSize, "the total size of the object".
PcProperty object_property(uint16_t prop_id, uint32_t nid, uint32_t ul_size) {
    std::vector<uint8_t> value = le32_bytes(nid);
    const std::vector<uint8_t> size = le32_bytes(ul_size);
    value.insert(value.end(), size.begin(), size.end());
    PcProperty property;
    property.prop_id = prop_id;
    property.prop_type = kTypeObject;
    property.value = std::move(value);
    return property;
}

// A property that has a value: a PtypUnicodeString value becomes a heap allocation of its own.
PcProperty string_property(uint16_t prop_id, const char* text) {
    PcProperty property;
    property.prop_id = prop_id;
    property.prop_type = kTypeUnicode;
    property.value = utf16_bytes(text);
    return property;
}

// [MS-PST] 2.3.3.3 read through ltp::decode_pc_record: dwValueHnid 0 says the property is present
// and has no value. The Root Folder of a new PST has an empty display name ([MS-PST] 2.7.3.4.1).
PcProperty empty_string_property(uint16_t prop_id) {
    PcProperty property;
    property.prop_id = prop_id;
    property.prop_type = kTypeUnicode;
    property.value_hnid = 0;
    return property;
}

std::vector<TcColumnSpec> columns(const std::vector<uint32_t>& tags) {
    std::vector<TcColumnSpec> specs;
    specs.reserve(tags.size());
    for (const uint32_t tag : tags) {
        specs.push_back(TcColumnSpec{tag});
    }
    return specs;
}

} // namespace

namespace {

// --- the blocks the file holds ------------------------------------------------------------------

// One block per node, laid out in this order, each taking the next block BID.
enum Slot : uint64_t {
    kSlotMessageStore = 0,
    kSlotNameIdMap = 1,
    kSlotRootFolder = 2,
    kSlotRootHierarchy = 3,
    kSlotIpmsubtree = 4,
    kSlotIpmsubtreeHierarchy = 5,
    kSlotSearchRoot = 6,
    kSlotDeletedItems = 7,
    kSlotSpamSearch = 8,
    kSlotHierarchyTemplate = 9,
    kSlotContentsTemplate = 10,
    kSlotFaiTemplate = 11,
    kSlotSearchContentsTemplate = 12,
    kSlotRecipientTemplate = 13,
    kSlotAttachmentTemplate = 14,
    kSlotReceiveTable = 15,
    kSlotOutgoingTable = 16,
    kSlotInternalTemplate16 = 17,
    kSlotInternalTemplate17 = 18,
    kSlotInternalTemplate18 = 19,
    kSlotGuidMap = 20,
    kSlotSearchActivity = 21,
    kSlotSearchCriteria = 22,
    kSlotCount = 23,
};

// [MS-PST] 2.7.3.4.1 .. 2.7.3.4.5: the five folders and their hierarchy rows.
// The oracle and SCANPST require zero message counts in an empty folder; the example
// counts 3/1 in 2.7.3.4.1/2 describe its children, not its empty contents table.
struct FolderSpec {
    uint32_t nid = 0;
    uint32_t nid_parent = 0;
    const char* name = "";
    uint32_t content_count = 0;     // 0x3602 PidTagContentCount
    uint32_t content_unread = 0;    // 0x3603 PidTagContentUnreadCount
    uint32_t subfolders = 0;        // 0x360A PidTagSubfolders
    std::vector<uint32_t> children; // dwRowID of each hierarchy row, in NID order
};

const std::vector<FolderSpec>& folders() {
    static const std::vector<FolderSpec> specs = {
        {0x0122, 0x0122, "", 0, 0, 1, {0x8022, 0x8042, 0x2223}},
        {0x8022, 0x0122, "Top of Personal Folders", 0, 0, 1, {0x8062}},
        {0x8042, 0x0122, "Search Root", 0, 0, 0, {}},
        {0x8062, 0x8022, "Deleted Items", 0, 0, 0, {}},
        {0x2223, 0x0122, "SPAM Search Folder 2", 0, 0, 0, {}},
    };
    return specs;
}

const FolderSpec* folder_spec(uint32_t nid) {
    for (const FolderSpec& spec : folders()) {
        if (spec.nid == nid) {
            return &spec;
        }
    }
    return nullptr;
}

// MS-PST 2.7.3.3 defines the template roles; 2.3.4.4.1 requires sorted tags.
// These schemas also incorporate columns/types required by SCANPST and measured in
// the Outlook blank oracle. In particular its 0E30 is binary and 3613 is Unicode,
// unlike the types in the normative table at 2.4.4.4.1. Evidence and exact versions:
// research/outlook-structure-repair.md. Do not infer modern Outlook schemas from OST.
const std::vector<uint32_t>& hierarchy_template_tags() {
    static const std::vector<uint32_t> tags = {
        0x0E300102, 0x0E330014, 0x0E340102, 0x0E380003, 0x3001001F, 0x36020003, 0x36030003,
        0x360A000B, 0x3613001F, 0x66350003, 0x66360003, 0x67F20003, 0x67F30003,
    };
    return tags;
}

const std::vector<uint32_t>& contents_template_tags() {
    static const std::vector<uint32_t> tags = {
        0x00170003, 0x001A001F, 0x00360003, 0x0037001F, 0x00390040, 0x0042001F, 0x0057000B,
        0x0058000B, 0x0070001F, 0x00710102, 0x0E03001F, 0x0E04001F, 0x0E060040, 0x0E070003,
        0x0E080003, 0x0E170003, 0x0E300102, 0x0E330014, 0x0E340102, 0x0E380003, 0x0E3C0102,
        0x0E3D0102, 0x10970003, 0x30080040, 0x30130102, 0x65C60003, 0x67F20003, 0x67F30003,
    };
    return tags;
}

const std::vector<uint32_t>& fai_template_tags() {
    static const std::vector<uint32_t> tags = {
        0x001A001F, 0x0E070003, 0x0E170003, 0x3001001F, 0x67F20003,
        0x67F30003, 0x6800001F, 0x6803000B, 0x68051003, 0x682F001F,
        0x70030003, 0x70040102, 0x70050102, 0x7006001F, 0x70070003,
    };
    return tags;
}

const std::vector<uint32_t>& search_contents_template_tags() {
    static const std::vector<uint32_t> tags = {
        0x00170003, 0x001A001F, 0x00360003, 0x0037001F, 0x0042001F, 0x0057000B, 0x0058000B,
        0x0E03001F, 0x0E04001F, 0x0E05001F, 0x0E060040, 0x0E070003, 0x0E080003, 0x0E170003,
        0x0E2A000B, 0x30080040, 0x67F10003, 0x67F20003, 0x67F30003,
    };
    return tags;
}

const std::vector<uint32_t>& recipient_template_tags() {
    static const std::vector<uint32_t> tags = {
        0x0C150003, 0x0E0F000B, 0x0FF90102, 0x0FFE0003, 0x0FFF0102, 0x3001001F, 0x3002001F,
        0x3003001F, 0x300B0102, 0x39000003, 0x39FF001F, 0x3A40000B, 0x67F20003, 0x67F30003,
    };
    return tags;
}

const std::vector<uint32_t>& attachment_template_tags() {
    static const std::vector<uint32_t> tags = {
        0x0E200003, 0x3704001F, 0x37050003, 0x370B0003, 0x67F20003, 0x67F30003,
    };
    return tags;
}

// One row of a hierarchy table: the Folder object the row stands for, plus the values its schema
// columns carry. [MS-PST] 2.4.4.4.1 makes dwRowID the NID of that Folder object.
struct HierarchyChild {
    uint32_t nid = 0;
    std::u16string name;
    uint32_t content_count = 0;  // 0x3602 PidTagContentCount
    uint32_t content_unread = 0; // 0x3603 PidTagContentUnreadCount
    uint32_t subfolders = 0;     // 0x360A PidTagSubfolders
    bool has_hidden_count = false;
    bool has_hidden_unread = false;
};

Result<std::vector<TcRow>> hierarchy_rows(const std::vector<HierarchyChild>& children) {
    const std::vector<uint32_t>& tags = hierarchy_template_tags();
    // The columns are addressed by tag, not by position, so a schema change cannot silently move a
    // value into the wrong column.
    const auto column_of = [&](uint32_t tag) {
        for (size_t index = 0; index < tags.size(); ++index) {
            if (tags[index] == tag) {
                return index;
            }
        }
        return tags.size();
    };
    const size_t name_column = column_of(0x3001001F);
    const size_t count_column = column_of(0x36020003);
    const size_t unread_column = column_of(0x36030003);
    const size_t subfolders_column = column_of(0x360A000B);
    const size_t row_id_column = column_of(0x67F20003);
    const size_t row_ver_column = column_of(0x67F30003);
    const size_t hidden_count_column = column_of(0x66350003);
    const size_t hidden_unread_column = column_of(0x66360003);
    if (name_column == tags.size() || count_column == tags.size() || unread_column == tags.size() ||
        subfolders_column == tags.size() || row_id_column == tags.size() ||
        row_ver_column == tags.size()) {
        return make_error(ErrorKind::kBadField, "hierarchy.template", 0, tags.size(),
                          "the hierarchy template lacks a column [MS-PST] 2.4.4.4.1 requires");
    }
    std::vector<TcRow> rows;
    for (const HierarchyChild& child : children) {
        TcRow row;
        row.row_id = child.nid;
        row.values = std::vector<std::vector<uint8_t>>(tags.size());
        row.values[name_column] = utf16_bytes(child.name);
        row.values[count_column] = le32_bytes(child.content_count);
        row.values[unread_column] = le32_bytes(child.content_unread);
        row.values[subfolders_column] = {static_cast<uint8_t>(child.subfolders != 0 ? 1 : 0)};
        row.values[row_id_column] = le32_bytes(child.nid);
        row.values[row_ver_column] = le32_bytes(0);
        // MS-PST 2.4.4.4.1: copy existing hidden counts from the child PC. The
        // full plan currently accepts only proven zero counts; M4 leaves them absent.
        if (child.has_hidden_count && hidden_count_column < tags.size())
            row.values[hidden_count_column] = le32_bytes(0);
        if (child.has_hidden_unread && hidden_unread_column < tags.size())
            row.values[hidden_unread_column] = le32_bytes(0);
        rows.push_back(std::move(row));
    }
    return rows;
}

Result<std::vector<uint8_t>> pc_image(const std::vector<PcProperty>& properties) {
    LocalNids local_nids;
    Result<PcNode> node = build_pc(properties, local_nids);
    if (!node.ok()) {
        return node.error();
    }
    if (!node.value().subnodes.empty()) {
        return make_error(ErrorKind::kBadField, "writer.build_pc", node.value().subnodes.size(), 0,
                          "the empty store has no value large enough to need a subnode");
    }
    if (node.value().heap.block_count() > 1) {
        return make_error(ErrorKind::kBadField, "writer.build_pc", node.value().heap.block_count(),
                          0,
                          "the empty store has no property set large enough to need a data tree");
    }
    return node.value().heap.bytes();
}

Result<std::vector<uint8_t>> tc_image(const std::vector<TcColumnSpec>& column_specs,
                                      const std::vector<TcRow>& rows) {
    Result<HeapImage> image = build_tc(column_specs, rows);
    if (!image.ok()) {
        return image.error();
    }
    if (image.value().block_count() > 1) {
        return make_error(ErrorKind::kBadField, "writer.build_tc", image.value().block_count(), 0,
                          "the empty store has no table large enough to need a data tree");
    }
    return image.value().bytes();
}

} // namespace
namespace {

// --- the content build -----------------------------------------------------------------------

// The report keeps a bounded number of per-item notes, then only counts what it dropped.
constexpr uint64_t kMaxReportNotes = 40;

// [MS-PST] 2.2.2.8: cb caps at 8176 raw bytes, so anything longer needs several blocks and the
// XBLOCK the emitter writes over them.
constexpr uint64_t kMaxBlockRawBytes =
    ndb::kPstBlockMaxCb; // [MS-PST] 2.2.2.8: 8176 raw bytes per data block

// [MS-PST] 2.4.5.3.1 and 2.4.6.1.1 name the internal NIDs a Message object's tables hang under, and
// the sample gives its table subnodes exactly those NIDs (research/subtree-2001C4.txt). A subnode
// NID is unique only within its parent ([MS-PST] 2.2.2.8.3.3.1.1), so the writer claims the same
// indices.
constexpr uint32_t kAttachmentTableLocalIndex =
    0x33; // [MS-PST] 2.4.6.1.1: NID_ATTACHMENT_TABLE 0x671 = (0x33 << 5) |
          // NID_TYPE_ATTACHMENT_TABLE
constexpr uint32_t kRecipientTableLocalIndex =
    0x34; // [MS-PST] 2.4.5.3.1: NID_RECIPIENT_TABLE 0x692 = (0x34 << 5) | NID_TYPE_RECIPIENT_TABLE

// [MS-PST] 2.4.5.1.1: the tags a Message object PC MUST carry.
constexpr uint16_t kMessageTagClass = 0x001A;
constexpr uint16_t kMessageTagFlags = 0x0E07;
constexpr uint16_t kMessageTagSize = 0x0E08;
constexpr uint16_t kMessageTagStatus = 0x0E17;
constexpr uint16_t kMessageTagCreationTime = 0x3007;
constexpr uint16_t kMessageTagModifiedTime = 0x3008;
constexpr uint16_t kMessageTagSearchKey = 0x300B;
constexpr uint16_t kRequiredMessageTags[] = {
    kMessageTagClass,        kMessageTagFlags,        kMessageTagSize,     kMessageTagStatus,
    kMessageTagCreationTime, kMessageTagModifiedTime, kMessageTagSearchKey};
// [MS-PST] 2.4.6.2.1: the tags an Attachment object PC MUST carry.
constexpr uint16_t kAttachmentTagSize = 0x0E20;
constexpr uint16_t kAttachmentTagMethod = 0x3705;
constexpr uint16_t kAttachmentTagRendering = 0x370B;
constexpr uint16_t kRequiredAttachmentTags[] = {kAttachmentTagSize, kAttachmentTagMethod,
                                                kAttachmentTagRendering};
// [MS-PST] 2.4.3.2 PidTagEntryId; 2.3.4.4.1 PidTagLtpRowId / PidTagLtpRowVer.
constexpr uint16_t kTagEntryId = 0x0FFF;
constexpr uint16_t kTagLtpRowId = 0x67F2;
constexpr uint16_t kTagLtpRowVer = 0x67F3;
// [MS-PST] 2.4.6.2.2 names PidTagAttachDataBinary without giving an id; 0x3701 is the one the
// libpff notes record (libpff format notes (see THIRD_PARTY_NOTICES.txt):2491-2509).
constexpr uint16_t kTagAttachData = 0x3701;
// [MS-OXCDATA] 2.11.1 PtypTime, the type of 0x3007 and 0x3008.
constexpr uint16_t kTypeTime = 0x0040;
// The same tags as the property tags a table column or a PC record names ([MS-PST] 1.1).
constexpr uint32_t kTagEntryIdBinary = 0x0FFF0102; // [MS-PST] 2.4.5.3.1 PidTagEntryId as PtypBinary
constexpr uint32_t kTagRowIdInt32 =
    0x67F20003; // [MS-PST] 2.3.4.4.1 PidTagLtpRowId as PtypInteger32
constexpr uint32_t kTagRowVerInt32 =
    0x67F30003; // [MS-PST] 2.3.4.4.1 PidTagLtpRowVer as PtypInteger32

std::string hex4(uint32_t value) {
    char text[16];
    std::snprintf(text, sizeof(text), "%04X", value);
    return text;
}

std::string hex8(uint32_t value) {
    char text[16];
    std::snprintf(text, sizeof(text), "%08X", value);
    return text;
}

// [MS-PST] 1.1: a property tag is the property id in the high 16 bits and the type in the low 16.
uint16_t tag_type(uint32_t tag) {
    return static_cast<uint16_t>(tag & 0xFFFFu);
}

// [MS-PST] 2.3.4.4 gives the Row Matrix two rules at once: "each data block MUST store an integral
// number of rows, which means that rows cannot span across two blocks, and that each block MUST
// start with a fresh row", and "Each block except the last one MUST have a size of 8192 bytes. If
// not, the file is considered corrupted." A full block therefore carries Floor((8192 - 16) / row
// size) whole rows and the leftover bytes at its end -- the "unused space at the end of the data
// block" the same section says readers MUST ignore. Those bytes are written inside cb, because cb
// is the only block size a reader is given and the footprint has to be the whole 8192. Measured on
// the OST sample: the 收件箱 Contents Table 0x218E (406-byte rows, 7,449 rows) puts 65,512 raw
// bytes, its profile's whole capacity, into each of its 46 nonfinal matrix blocks and 17,458 = 43
// whole rows into the last one
// (DEVELOPMENT.md).
// A raw value has no row geometry, so its chunks are cut at the block limit and a full one is 8176
// bytes.
Result<std::vector<std::vector<uint8_t>>> chunk_bytes(const std::vector<uint8_t>& bytes,
                                                      uint64_t row_size) {
    std::vector<std::vector<uint8_t>> chunks;
    if (bytes.empty()) {
        return chunks;
    }
    if (row_size == 0) {
        for (uint64_t at = 0; at < bytes.size(); at += kMaxBlockRawBytes) {
            const uint64_t take =
                std::min(kMaxBlockRawBytes, static_cast<uint64_t>(bytes.size()) - at);
            chunks.push_back(std::vector<uint8_t>(bytes.begin() + static_cast<size_t>(at),
                                                  bytes.begin() + static_cast<size_t>(at + take)));
        }
        return chunks;
    }
    const uint64_t rows_per_block = kMaxBlockRawBytes / row_size;
    if (rows_per_block == 0) {
        return make_error(ErrorKind::kUnsupported, "writer.content.row_size", row_size,
                          kMaxBlockRawBytes,
                          "a row wider than one data block cannot be written without spanning "
                          "blocks ([MS-PST] 2.3.4.4)");
    }
    if (bytes.size() % row_size != 0) {
        return make_error(ErrorKind::kBadField, "writer.content.row_geometry", bytes.size(),
                          row_size,
                          "a Row Matrix has to be a whole number of rows ([MS-PST] 2.3.4.4)");
    }
    const uint64_t total_rows = bytes.size() / row_size;
    for (uint64_t first_row = 0; first_row < total_rows; first_row += rows_per_block) {
        const uint64_t rows = std::min(rows_per_block, total_rows - first_row);
        const uint64_t at = first_row * row_size;
        std::vector<uint8_t> chunk(bytes.begin() + static_cast<size_t>(at),
                                   bytes.begin() + static_cast<size_t>(at + rows * row_size));
        if (first_row + rows < total_rows) {
            chunk.resize(static_cast<size_t>(kMaxBlockRawBytes), 0);
        }
        chunks.push_back(std::move(chunk));
    }
    return chunks;
}

// The blocks of the file. The 23 slots of the minimum mailbox keep their indices so the accepted M4
// bytes do not move; content blocks are appended after them.
struct Builder {
    explicit Builder(std::shared_ptr<util::Workspace> workspace = {})
        : blocks(kSlotCount), workspace(std::move(workspace)) {
        if (this->workspace)
            scratch = std::make_shared<util::SpillBuffer>(this->workspace);
    }

    std::vector<StoreBlock> blocks;
    std::vector<StoreNode> nodes;
    ContentReport report;
    std::shared_ptr<util::Workspace> workspace;
    std::shared_ptr<util::SpillBuffer> scratch;
    // HEADER.rgnid counters, seeded exactly as the minimum mailbox left them ([MS-PST] 2.2.2.1).
    uint32_t folder_index = 1027;
    uint32_t message_index = 65536;
    // [MS-PST] 2.3.4.3 leaves the RowIndex key to the implementation, and the recipient row ids of
    // the sample are not NBT entries, so the writer numbers them itself and never claims they name
    // a node.
    uint32_t recipient_row_id = 0;

    void set_slot(uint64_t slot, std::vector<uint8_t> bytes) {
        blocks[static_cast<size_t>(slot)] = stored_block(std::move(bytes));
    }
    StoreBlock stored_block(std::vector<uint8_t> bytes) {
        if (!scratch)
            return StoreBlock{std::move(bytes)};
        const auto offset = scratch->size();
        scratch->append(util::ByteView(bytes.data(), bytes.size()));
        return StoreBlock{{}, scratch, offset, static_cast<uint16_t>(bytes.size())};
    }
    uint64_t append_block(std::vector<uint8_t> bytes) {
        blocks.push_back(stored_block(std::move(bytes)));
        return blocks.size() - 1;
    }
    Result<std::vector<uint64_t>> append_source(const util::SharedBytes& source) {
        if (!source || source->size() == 0 || source->size() > UINT32_MAX)
            return make_error(ErrorKind::kBadField, "writer.content.source_size", 0,
                              source ? source->size() : 0);
        std::vector<uint64_t> slots;
        const uint64_t chunk = ndb::block_max_cb(ndb::FileProfile::kPst);
        for (uint64_t offset = 0; offset < source->size(); offset += chunk) {
            slots.push_back(blocks.size());
            blocks.push_back(
                StoreBlock{{},
                           source,
                           offset,
                           static_cast<uint16_t>(std::min(chunk, source->size() - offset))});
        }
        return slots;
    }
    void note(const std::string& text) {
        if (report.notes.size() < kMaxReportNotes) {
            report.notes.push_back(text);
        }
    }
};

bool has_property(const std::vector<PcProperty>& properties, uint16_t prop_id) {
    for (const PcProperty& property : properties) {
        if (property.prop_id == prop_id) {
            return true;
        }
    }
    return false;
}

// The cell of a table row that carries a property id, whatever its column type was.
const ContentCell* row_cell(const ContentRow* row, uint16_t prop_id) {
    if (row == nullptr) {
        return nullptr;
    }
    for (const ContentCell& cell : row->cells) {
        if (ltp::tc_prop_id_of_tag(cell.tag) == prop_id) {
            return &cell;
        }
    }
    return nullptr;
}

// A value the request hands over becomes a PC record. A named property gets the NPID this writer's
// own Name-to-ID Map gives that identity ([MS-PST] 2.4.7.1: an NPID is only an index into this
// file's map, so a source NPID never carries over), and a value the extractor could not read is
// dropped with a note instead of written as something guessed.
std::vector<PcProperty> content_properties(const std::vector<ContentProperty>& values,
                                           const std::vector<uint16_t>& npid_of_index,
                                           const std::string& context, Builder& builder) {
    std::vector<PcProperty> out;
    for (const ContentProperty& value : values) {
        uint16_t prop_id = value.prop_id;
        if (value.named) {
            if (value.named_index >= npid_of_index.size()) {
                ++builder.report.values_dropped;
                builder.note(context + ": named property 0x" + hex4(prop_id) +
                             " names no identity the writer was given");
                continue;
            }
            prop_id = npid_of_index[static_cast<size_t>(value.named_index)];
        }
        if (has_property(out, prop_id)) {
            ++builder.report.values_dropped;
            builder.note(context + ": 0x" + hex4(prop_id) +
                         " appears twice, and a PC is keyed by wPropId ([MS-PST] 2.3.3.3)");
            continue;
        }
        PcProperty property;
        property.prop_id = prop_id;
        property.prop_type = value.prop_type;
        property.source = value.source;
        if (value.absent) {
            if (ltp::prop_type_is_inline(value.prop_type)) {
                property.value.clear(); // an inline record with dwValueHnid 0 ([MS-PST] 2.3.3.3)
            } else {
                property.value_hnid = 0; // [MS-PST] 2.3.3.2: present with no value
            }
        } else if (value.value.empty() && !value.source) {
            // A variable-size value needs a heap allocation, which cannot be empty, so the writer
            // records it the only way a PC can say "present and empty" ([MS-PST] 2.3.3.2).
            if (ltp::prop_type_is_inline(value.prop_type)) {
                property.value.clear();
            } else {
                property.value_hnid = 0;
            }
            builder.note(
                context + ": 0x" + hex4(prop_id) +
                " carried no bytes, so it is recorded as present with no value ([MS-PST] 2.3.3.2)");
        } else {
            property.value = value.value;
        }
        ++builder.report.values_written;
        out.push_back(std::move(property));
    }
    return out;
}

// A tag the spec says a PC MUST carry, when the source had no value for it: the writer writes zero
// and says so, because it has no basis for inventing a value that would look like content.
void ensure_integer(std::vector<PcProperty>& properties, uint16_t prop_id, uint32_t value,
                    const std::string& why, Builder& builder, const std::string& context) {
    if (has_property(properties, prop_id)) {
        return;
    }
    properties.push_back(integer_property(prop_id, value));
    ++builder.report.values_written;
    builder.note(context + ": 0x" + hex4(prop_id) +
                 " has no value in the source, so the writer writes 0 (" + why + ")");
}

// The columns of a table the writer emits: the source table's own columns, plus any column the
// template of [MS-PST] 2.4.5.3.1 / 2.4.6.1.1 says every table of that kind has.
struct TableColumns {
    std::vector<uint32_t> tags;
    std::map<uint32_t, uint32_t> tag_of_source;
};

Result<TableColumns> table_columns(const std::vector<ContentColumn>& source_columns,
                                   const std::vector<uint32_t>& template_tags,
                                   const std::vector<uint16_t>& npid_of_index,
                                   const std::string& context, Builder& builder) {
    TableColumns result;
    auto& tags = result.tags;
    for (const auto& column : source_columns) {
        const uint16_t id = static_cast<uint16_t>(ltp::tc_prop_id_of_tag(column.tag));
        uint32_t tag = column.tag;
        if (column.named) {
            if (column.named_index >= npid_of_index.size()) {
                return make_error(ErrorKind::kBadField, "writer.table.named_index",
                                  column.named_index, npid_of_index.size(),
                                  context + ": named column has no registered identity");
            }
            tag = (static_cast<uint32_t>(npid_of_index[column.named_index])
                   << ltp::kTcTagPropIdShift) |
                  tag_type(column.tag);
        } else if (id >= ltp::kNpidBase && id <= ltp::kNpidMax) {
            return make_error(ErrorKind::kBadField, "writer.table.named_column", id, 0,
                              context + ": source NPID requires an explicit named identity");
        }
        const auto inserted = result.tag_of_source.emplace(column.tag, tag);
        if (!inserted.second && inserted.first->second != tag) {
            return make_error(ErrorKind::kBadField, "writer.table.column_identity", column.tag, tag,
                              context + ": source column names conflicting identities");
        }
        tags.push_back(tag);
    }
    for (const uint32_t tag : template_tags) {
        if (std::find(tags.begin(), tags.end(), tag) == tags.end()) {
            tags.push_back(tag);
            builder.note(context + ": the source table had no column 0x" + hex8(tag) +
                         ", which the table template defines ([MS-PST] 2.4.5.3.1 / 2.4.6.1.1)");
        }
    }
    std::sort(tags.begin(), tags.end());
    tags.erase(std::unique(tags.begin(), tags.end()), tags.end());
    return result;
}

// The cells a row carried, placed into the column list the writer ended up emitting. A cell whose
// tag has no column is dropped with a note rather than squeezed into a column of another type.
Result<std::vector<TcRow>> content_rows(const TableColumns& columns,
                                        const std::vector<ContentRow>& rows,
                                        const std::string& context, Builder& builder) {
    const auto& tags = columns.tags;
    std::vector<TcRow> out;
    for (const ContentRow& row : rows) {
        TcRow table_row;
        table_row.row_id = row.row_id;
        table_row.values = std::vector<std::vector<uint8_t>>(tags.size());
        table_row.present_empty = std::vector<bool>(tags.size(), false);
        table_row.sources.resize(tags.size());
        std::vector<bool> assigned(tags.size(), false);
        for (const ContentCell& cell : row.cells) {
            const auto mapped = columns.tag_of_source.find(cell.tag);
            const auto found = mapped == columns.tag_of_source.end()
                                   ? tags.end()
                                   : std::find(tags.begin(), tags.end(), mapped->second);
            if (found == tags.end()) {
                ++builder.report.values_dropped;
                builder.note(context + ": row 0x" + hex8(row.row_id) + " carries 0x" +
                             hex8(cell.tag) + " and this table has no column with that tag");
                continue;
            }
            const size_t column = static_cast<size_t>(found - tags.begin());
            if (assigned[column]) {
                ++builder.report.values_dropped;
                builder.note(context + ": two source cells map to the same output column");
                continue;
            }
            assigned[column] = true;
            table_row.values[column] = cell.value;
            table_row.sources[column] = cell.source;
            // Only a column the row reaches through an HNID can say "exists with no value" (HNID
            // 0); an inline column has no room for that distinction ([MS-PST] 2.3.4.4.2).
            table_row.present_empty[column] =
                cell.absent && !ltp::prop_type_is_tc_inline(tag_type(cell.tag));
            ++builder.report.values_written;
        }
        out.push_back(std::move(table_row));
    }
    return out;
}

// A PtypBoolean is 4 bytes in a PC and 1 byte in a Row Matrix column, measured in the same file:
// the Message PC 0x002001C4 holds 0x0057000B inline 4 bytes (research/subtree-2001C4.txt:51) while
// the ACSL Contents Table declares 0x0057000B with cbData 1
// (research/subtree-852E-acsl-contents.txt:40). A cell copied out of the PC has to fit the column
// it lands in, so the four bytes narrow to the one byte the column declares: the integer the four
// bytes hold is zero only when every one of them is zero. Any other size difference is left alone
// and the table writer reports it instead of guessing a width.
std::vector<uint8_t> row_cell_from_pc_value(uint16_t type, const std::vector<uint8_t>& value) {
    if (type == kTypeBoolean && value.size() > 1) {
        uint8_t set = 0;
        for (const uint8_t byte : value) {
            if (byte != 0) {
                set = 1;
            }
        }
        return std::vector<uint8_t>(1, set);
    }
    return value;
}

// A cell the writer assigns itself: its own row id, its version, or a regenerated EntryID.
void set_cell(TcRow& row, const std::vector<uint32_t>& tags, uint32_t tag,
              std::vector<uint8_t> value, Builder& builder, const std::string& context) {
    const auto found = std::find(tags.begin(), tags.end(), tag);
    if (found == tags.end()) {
        builder.note(context + ": this table has no column 0x" + hex8(tag) +
                     " for the value the writer assigns");
        return;
    }
    row.values[static_cast<size_t>(found - tags.begin())] = std::move(value);
    if (!row.sources.empty())
        row.sources[static_cast<size_t>(found - tags.begin())].reset();
    ++builder.report.values_written;
}

// Names the blocks under one node or subnode: its heap blocks, then each local subnode chunked into
// data blocks. `matrix_nid` / `matrix_row_size` say which subnode is a Row Matrix, because only a
// Row Matrix is cut on row boundaries ([MS-PST] 2.3.4.4). first_slot, when it is >= 0, puts the
// first heap block into an existing block slot instead of appending a new one. The Name-to-ID Map
// uses it so the minimum mailbox keeps the BIDs the accepted M4 candidate gave it and no slot ends
// up naming a block with no bytes ([MS-PST] 2.2.2.7.7.3 gives that block a cb a reader trusts).
Result<std::pair<std::vector<uint64_t>, std::vector<StoreSubnode>>>
place_node_data(const HeapImage& heap, const std::vector<LocalSubnode>& local_subnodes,
                uint32_t matrix_nid, uint64_t matrix_row_size, Builder& builder,
                int64_t first_slot = -1) {
    std::vector<uint64_t> data_blocks;
    data_blocks.reserve(static_cast<size_t>(heap.block_count()));
    auto streamed = heap.stream_blocks([&](util::ByteView bytes) -> util::Status {
        std::vector<uint8_t> block(bytes.data(), bytes.data() + bytes.size());
        if (first_slot >= 0 && data_blocks.empty()) {
            builder.set_slot(static_cast<uint64_t>(first_slot), std::move(block));
            data_blocks.push_back(static_cast<uint64_t>(first_slot));
        } else
            data_blocks.push_back(builder.append_block(std::move(block)));
        return builder.scratch ? builder.scratch->status() : util::Status{};
    });
    if (!streamed.ok())
        return streamed.error();
    std::vector<StoreSubnode> subnodes;
    for (const LocalSubnode& local : local_subnodes) {
        const uint64_t row_size = local.nid == matrix_nid ? matrix_row_size : 0;
        if (local.source) {
            if (!local.bytes.empty())
                return make_error(ErrorKind::kBadField, "writer.local_source", local.nid, row_size,
                                  "subnode has both resident and streamed values");
            if (row_size != 0) {
                if (row_size > kMaxBlockRawBytes || local.source->size() % row_size != 0)
                    return make_error(ErrorKind::kBadField, "writer.content.row_geometry",
                                      local.nid, row_size);
                StoreSubnode subnode;
                subnode.nid = local.nid;
                const uint64_t window = (kMaxBlockRawBytes / row_size) * row_size;
                for (uint64_t offset = 0; offset < local.source->size(); offset += window) {
                    const auto take =
                        static_cast<size_t>(std::min(window, local.source->size() - offset));
                    std::vector<uint8_t> bytes(
                        offset + take < local.source->size() ? kMaxBlockRawBytes : take, 0);
                    auto read = local.source->read_at(offset, bytes.data(), take);
                    if (!read.ok())
                        return read.error();
                    subnode.data_blocks.push_back(builder.append_block(std::move(bytes)));
                    if (builder.scratch && !builder.scratch->status().ok())
                        return builder.scratch->status().error();
                }
                subnodes.push_back(std::move(subnode));
                continue;
            }
            auto slots = builder.append_source(local.source);
            if (!slots.ok())
                return slots.error();
            subnodes.push_back(StoreSubnode{local.nid, slots.take(), {}});
            continue;
        }
        Result<std::vector<std::vector<uint8_t>>> chunks = chunk_bytes(local.bytes, row_size);
        if (!chunks.ok()) {
            return chunks.error();
        }
        StoreSubnode subnode;
        subnode.nid = local.nid;
        std::vector<std::vector<uint8_t>> chunked = chunks.take();
        for (std::vector<uint8_t>& chunk : chunked) {
            subnode.data_blocks.push_back(builder.append_block(std::move(chunk)));
        }
        subnodes.push_back(std::move(subnode));
    }
    // The sample's subnode list is in nid order (research/subtree-2001C4.txt: 0x0671, 0x0692,
    // 0x8045 .. 0x915F), which is what a BTree keyed by nid produces. [MS-PST] states no order for
    // SLENTRY, so sorting is the writer's choice, made to match the sample.
    std::sort(
        subnodes.begin(), subnodes.end(),
        [](const StoreSubnode& left, const StoreSubnode& right) { return left.nid < right.nid; });
    return std::make_pair(std::move(data_blocks), std::move(subnodes));
}

// One Table Context the content build emits: the columns, the rows, and the blocks that carry them.
struct TableBuild {
    uint32_t nid = 0;
    std::vector<uint64_t> data_blocks;
    std::vector<StoreSubnode> subnodes;
};

Result<TableBuild> build_content_table(uint32_t nid, const std::vector<uint32_t>& tags,
                                       const std::vector<TcRow>& rows, Builder& builder,
                                       const std::string& context,
                                       const TcRowSource* source = nullptr) {
    LocalNids local_nids; // the table node's own subnode supply ([MS-PST] 2.6.1.2.2)
    Result<TcNode> table =
        source != nullptr ? build_table_from(columns(tags), *source, local_nids, builder.workspace)
                          : build_table(columns(tags), rows, local_nids, builder.workspace);
    if (!table.ok()) {
        return table.error();
    }
    // TCINFO.hnidRows names the Row Matrix; when its hidType is not NID_TYPE_HID it is a subnode
    // ([MS-PST] 2.3.4.1 / 2.3.4.4, read through ltp::read_tc).
    const uint32_t matrix_nid =
        ltp::hid_type(table.value().hnid_rows) == ltp::kHidTypeHid ? 0 : table.value().hnid_rows;
    Result<std::pair<std::vector<uint64_t>, std::vector<StoreSubnode>>> placed = place_node_data(
        table.value().heap, table.value().subnodes, matrix_nid, table.value().row_size, builder);
    if (!placed.ok()) {
        return placed.error();
    }
    std::pair<std::vector<uint64_t>, std::vector<StoreSubnode>> slots = placed.take();
    TableBuild build;
    build.nid = nid;
    build.data_blocks = std::move(slots.first);
    build.subnodes = std::move(slots.second);
    (void)context;
    return build;
}

// One Message object: its Attachment objects, its Recipient Table, its Attachment Table, and its
// own Property Context.
struct MessageBuild {
    uint32_t nid = 0;
    StoreNode node;
    // The same content in the form a parent hangs it under: [MS-PST] 2.4.6.2.2 puts an attached
    // Message under the Attachment object that names it, not in the NBT.
    StoreSubnode subnode;
    // What the writer actually put in the PC, so the folder's Contents Table can copy from it.
    std::vector<PcProperty> properties;
};

// The bytes a subnode's own data blocks and every block under them carry, which is what
// [MS-PST] 2.3.3.5 calls the total size of the object. The internal blocks a multi-block data tree
// or a subnode list needs are not the object's content, so they are not counted; measured on the
// OST sample, where five ulSize values equal exactly this sum
// (research/review-repair-measurements.md).
uint64_t subtree_bytes(const StoreSubnode& subnode, const Builder& builder) {
    uint64_t total = 0;
    for (const uint64_t slot : subnode.data_blocks) {
        total += builder.blocks[static_cast<size_t>(slot)].size();
    }
    for (const StoreSubnode& child : subnode.subnodes) {
        total += subtree_bytes(child, builder);
    }
    return total;
}

StoreSubnode table_subnode(const TableBuild& table) {
    StoreSubnode subnode;
    subnode.nid = table.nid;
    subnode.data_blocks = table.data_blocks;
    subnode.subnodes = table.subnodes;
    return subnode;
}

// forced_nid is the NID a parent already allocated for this Message: an attached Message is a
// subnode of the Attachment object that names it ([MS-PST] 2.4.6.2.2), so it never takes a slot
// from HEADER.rgnid.
Result<MessageBuild> build_message(const ContentMessage& message, uint32_t parent_nid,
                                   const std::vector<uint16_t>& npid_of_index, Builder& builder,
                                   uint32_t forced_nid = 0) {
    MessageBuild build;
    build.nid = forced_nid != 0 ? forced_nid
                                : static_cast<uint32_t>(ltp::make_nid(++builder.message_index,
                                                                      ltp::kNidTypeNormalMessage));
    const std::string context = "message 0x" + hex8(build.nid);
    ++builder.report.messages;

    if (message.attachments.rows.size() != message.attachment_objects.size()) {
        return make_error(ErrorKind::kBadField, "writer.content.attachment_rows",
                          message.attachments.rows.size(), message.attachment_objects.size(),
                          "the Attachment Table rows and the Attachment object subnodes have to "
                          "match ([MS-PST] 2.4.6.2)");
    }

    LocalNids local_nids; // the Message node's own subnode supply ([MS-PST] 2.6.1.2.2)
    // Reserve the template table identifiers before dynamic attachment/property allocations.
    Result<uint32_t> recipient_nid =
        local_nids.take_at(kRecipientTableLocalIndex, ltp::kNidTypeRecipientTable);
    if (!recipient_nid.ok())
        return recipient_nid.error();
    uint32_t attachment_table_nid = 0;
    if (!message.attachment_objects.empty() || !message.attachments.columns.empty()) {
        auto table_nid =
            local_nids.take_at(kAttachmentTableLocalIndex, ltp::kNidTypeAttachmentTable);
        if (!table_nid.ok())
            return table_nid.error();
        attachment_table_nid = table_nid.value();
    }

    // Attachment objects first: [MS-PST] 2.4.6.1.3 makes each Attachment Table row's dwRowID the
    // subnode NID of the object it stands for, so those NIDs have to exist before the table is
    // built.
    std::vector<uint32_t> attachment_nids;
    std::vector<StoreSubnode> attachment_subnodes;
    for (size_t index = 0; index < message.attachment_objects.size(); ++index) {
        Result<uint32_t> taken = local_nids.take(ltp::kNidTypeAttachment);
        if (!taken.ok()) {
            return taken.error();
        }
        const uint32_t attachment_nid = taken.value();
        attachment_nids.push_back(attachment_nid);
        const ContentAttachment& attachment = message.attachment_objects[index];
        if ((attachment.has_payload && attachment.has_object_payload) ||
            (attachment.has_embedded &&
             (attachment.has_payload || attachment.has_object_payload))) {
            return make_error(ErrorKind::kBadField, "writer.attachment.payload_form", index, 0,
                              "an attachment cannot have conflicting payload representations");
        }
        const ContentRow* row =
            index < message.attachments.rows.size() ? &message.attachments.rows[index] : nullptr;
        const std::string attach_context = context + " attachment 0x" + hex8(attachment_nid);
        ++builder.report.attachments;

        std::vector<PcProperty> properties =
            content_properties(attachment.properties, npid_of_index, attach_context, builder);
        // [MS-PST] 2.4.6.2.1 requires 0x0E20, 0x3705 and 0x370B in the object. The Attachment Table
        // row carries the same metadata, so a missing one is copied from the row before it is
        // zeroed.
        for (const uint16_t tag : kRequiredAttachmentTags) {
            if (has_property(properties, tag)) {
                continue;
            }
            const ContentCell* cell = row_cell(row, tag);
            if (cell != nullptr && (!cell->value.empty() || cell->source)) {
                PcProperty property;
                property.prop_id = tag;
                property.prop_type = tag_type(cell->tag);
                property.value = cell->value;
                property.source = cell->source;
                properties.push_back(std::move(property));
                ++builder.report.values_written;
                builder.note(attach_context + ": 0x" + hex4(tag) +
                             " taken from the Attachment Table row ([MS-PST] 2.4.6.2.1)");
            } else {
                ensure_integer(properties, tag, 0, "[MS-PST] 2.4.6.2.1 requires it", builder,
                               attach_context);
            }
        }
        if (attachment.has_payload) {
            properties.push_back(binary_property(kTagAttachData, attachment.payload));
            properties.back().source = attachment.payload_source;
            ++builder.report.values_written;
            builder.report.attachment_bytes += attachment.payload_source
                                                   ? attachment.payload_source->size()
                                                   : attachment.payload.size();
        }
        LocalNids object_local_nids; // the object's own supply ([MS-PST] 2.6.1.2.2)
        StoreSubnode attached_subnode;
        bool carried_message = false;
        bool carried_object = false;
        if (attachment.has_object_payload) {
            // MS-PST 2.3.3.5: regenerate Nid and ulSize around the unchanged object bytes.
            // Raw data uses the existing NID_TYPE_LTP subnode allocation, not a source NID.
            const auto method =
                std::find_if(properties.begin(), properties.end(),
                             [](const PcProperty& p) { return p.prop_id == 0x3705; });
            if (method == properties.end() || method->prop_type != 0x0003 ||
                method->value.size() != 4 ||
                util::ByteView(method->value.data(), method->value.size(), 0).u32(0).value() != 6) {
                return make_error(
                    ErrorKind::kBadField, "writer.attachment.object_method", index, 0,
                    "opaque object data requires attachment method 6 (libpff attachment notes)");
            }
            const uint64_t payload_size = attachment.payload_source
                                              ? attachment.payload_source->size()
                                              : attachment.payload.size();
            if (payload_size > UINT32_MAX) {
                return make_error(ErrorKind::kUnsupported, "PtypObject.ulSize", index, payload_size,
                                  "object size exceeds the DWORD field");
            }
            auto nid = object_local_nids.take(ltp::kNidTypeLtp);
            if (!nid.ok())
                return nid.error();
            attached_subnode.nid = nid.value();
            if (attachment.payload_source) {
                if (!attachment.payload.empty())
                    return make_error(ErrorKind::kBadField, "writer.attachment.source", index);
                auto slots = builder.append_source(attachment.payload_source);
                if (!slots.ok())
                    return slots.error();
                attached_subnode.data_blocks = slots.take();
            } else {
                auto chunks = chunk_bytes(attachment.payload, 0);
                if (!chunks.ok())
                    return chunks.error();
                for (auto& chunk : chunks.value())
                    attached_subnode.data_blocks.push_back(builder.append_block(std::move(chunk)));
            }
            if (attached_subnode.data_blocks.empty())
                attached_subnode.data_blocks.push_back(builder.append_block({}));
            properties.push_back(
                object_property(kTagAttachData, nid.value(), static_cast<uint32_t>(payload_size)));
            ++builder.report.values_written;
            ++builder.report.opaque_objects;
            builder.report.attachment_bytes += payload_size;
            carried_object = true;
        }
        if (attachment.has_embedded) {
            // [MS-PST] 2.4.6.2.2: the attachment is itself a Message object and 0x3701 is the
            // PtypObject naming it as a subnode of this Attachment object. The NID comes from the
            // object's own supply because a subnode NID is unique only within its parent
            // ([MS-PST] 2.2.2.8.3.3.1.1).
            Result<uint32_t> taken_nid = object_local_nids.take(ltp::kNidTypeNormalMessage);
            if (!taken_nid.ok()) {
                return taken_nid.error();
            }
            Result<MessageBuild> embedded = build_message(
                attachment.embedded, attachment_nid, npid_of_index, builder, taken_nid.value());
            if (!embedded.ok()) {
                return embedded.error();
            }
            const uint64_t carried_bytes = subtree_bytes(embedded.value().subnode, builder);
            properties.push_back(object_property(kTagAttachData, embedded.value().nid,
                                                 static_cast<uint32_t>(carried_bytes)));
            ++builder.report.values_written;
            ++builder.report.embedded_messages;
            builder.report.embedded_bytes += carried_bytes;
            attached_subnode = std::move(embedded.value().subnode);
            carried_message = true;
            if (attachment.embedded_ul_size != 0 && attachment.embedded_ul_size != carried_bytes) {
                builder.note(
                    attach_context + ": the source states " +
                    std::to_string(attachment.embedded_ul_size) +
                    " bytes for the 0x3701 object and the blocks this writer laid down under it "
                    "carry " +
                    std::to_string(carried_bytes) + " ([MS-PST] 2.3.3.5 ulSize)");
            }
        }
        if (!attachment.has_payload && !carried_message && !carried_object) {
            builder.note(attach_context + ": no 0x3701 payload to write ([MS-PST] 2.4.6.2.2)");
        }
        Result<PcNode> pc = build_pc(properties, object_local_nids);
        if (!pc.ok()) {
            return pc.error();
        }
        Result<std::pair<std::vector<uint64_t>, std::vector<StoreSubnode>>> placed =
            place_node_data(pc.value().heap, pc.value().subnodes, 0, 0, builder);
        if (!placed.ok()) {
            return placed.error();
        }
        std::pair<std::vector<uint64_t>, std::vector<StoreSubnode>> slots = placed.take();
        StoreSubnode subnode;
        subnode.nid = attachment_nid;
        subnode.data_blocks = std::move(slots.first);
        subnode.subnodes = std::move(slots.second);
        if (carried_message || carried_object) {
            subnode.subnodes.push_back(std::move(attached_subnode));
            std::sort(subnode.subnodes.begin(), subnode.subnodes.end(),
                      [](const StoreSubnode& left, const StoreSubnode& right) {
                          return left.nid < right.nid;
                      });
        }
        attachment_subnodes.push_back(std::move(subnode));
    }

    // [MS-PST] 2.4.5.3: "A Recipient Table MUST exist for any Message object", in the subnode,
    // under the internal NID 2.4.5.3.1 names.
    const std::string recipient_context = context + " recipient table";
    const auto recipient_columns =
        table_columns(message.recipients.columns, recipient_template_tags(), npid_of_index,
                      recipient_context, builder);
    if (!recipient_columns.ok())
        return recipient_columns.error();
    const auto& recipient_tags = recipient_columns.value().tags;
    Result<std::vector<TcRow>> recipient_result = content_rows(
        recipient_columns.value(), message.recipients.rows, recipient_context, builder);
    if (!recipient_result.ok()) {
        return recipient_result.error();
    }
    std::vector<TcRow> recipient_rows = recipient_result.take();
    for (TcRow& row : recipient_rows) {
        row.row_id = ++builder.recipient_row_id;
        // Preserve 0x0FFF from the source row. [MS-PST] 2.4.5.3.1 identifies it as the recipient's
        // address-book EntryID, while 0x67F2 is the row ID. It is not [MS-PST] 2.4.3.2's 24-byte
        // PST object ENTRYID and therefore does not name this store's NBT node. The sample confirms
        // the distinction: its readable recipient EntryIDs are 102-157-byte Exchange/One-Off
        // provider values (research/body-probe-8522-full.txt:165-204). `content_rows` already
        // carried those bytes; only the row key and version below belong to the destination table.
        set_cell(row, recipient_tags, kTagRowIdInt32, le32_bytes(row.row_id), builder,
                 recipient_context);
        set_cell(row, recipient_tags, kTagRowVerInt32, le32_bytes(0), builder, recipient_context);
        ++builder.report.recipients;
    }
    Result<TableBuild> recipient_table = build_content_table(
        recipient_nid.value(), recipient_tags, recipient_rows, builder, recipient_context);
    if (!recipient_table.ok()) {
        return recipient_table.error();
    }
    std::vector<StoreSubnode> message_subnodes;
    message_subnodes.push_back(table_subnode(recipient_table.value()));

    // Preserve the supplied schema even with zero rows (DEVELOPMENT.md content contract).
    // A message without attachments or a source schema still needs no Attachment Table.
    if (!attachment_nids.empty() || !message.attachments.columns.empty()) {
        const std::string attachment_context = context + " attachment table";
        const auto attachment_columns =
            table_columns(message.attachments.columns, attachment_template_tags(), npid_of_index,
                          attachment_context, builder);
        if (!attachment_columns.ok())
            return attachment_columns.error();
        const auto& attachment_tags = attachment_columns.value().tags;
        Result<std::vector<TcRow>> attachment_result = content_rows(
            attachment_columns.value(), message.attachments.rows, attachment_context, builder);
        if (!attachment_result.ok()) {
            return attachment_result.error();
        }
        std::vector<TcRow> attachment_rows = attachment_result.take();
        for (size_t index = 0; index < attachment_rows.size(); ++index) {
            TcRow& row = attachment_rows[index];
            // [MS-PST] 2.4.6.1.3: the row's dwRowID IS the subnode NID of the Attachment object.
            row.row_id = attachment_nids[index];
            set_cell(row, attachment_tags, kTagRowIdInt32, le32_bytes(row.row_id), builder,
                     attachment_context);
            set_cell(row, attachment_tags, kTagRowVerInt32, le32_bytes(0), builder,
                     attachment_context);
        }
        Result<TableBuild> attachment_table = build_content_table(
            attachment_table_nid, attachment_tags, attachment_rows, builder, attachment_context);
        if (!attachment_table.ok()) {
            return attachment_table.error();
        }
        message_subnodes.push_back(table_subnode(attachment_table.value()));
    }

    // The Message object's own Property Context.
    std::vector<PcProperty> properties =
        content_properties(message.properties, npid_of_index, context, builder);
    // [MS-PST] 2.4.3.2 gives an ENTRYID as rgbFlags + the Provider UID + a NID, and
    // DEVELOPMENT.md D7 requires every EntryID of a converted store to carry this store's
    // Provider UID. The source's own 0x0FFF is never copied.
    properties.push_back(binary_property(kTagEntryId, entry_id(build.nid)));
    ++builder.report.values_written;
    for (const uint16_t tag : kRequiredMessageTags) {
        if (has_property(properties, tag)) {
            continue;
        }
        ++builder.report.required_missing;
        builder.note(context + ": the source PC carries no 0x" + hex4(tag) +
                     ", which [MS-PST] 2.4.5.1.1 requires");
    }
    // 0x0E17 PidTagMessageStatus and 0x3008 PidTagLastModificationTime are the two required tags
    // this sample has no value for (research/subset-measurements.md). The writer writes 0 for the
    // status and copies the message's own 0x3007 for the modification time; no opened reference
    // names a value for either, so both are writer choices, recorded here rather than presented as
    // the source's content.
    ensure_integer(properties, kMessageTagStatus, 0, "[MS-PST] 2.4.5.1.1 requires 0x0E17", builder,
                   context);
    if (!has_property(properties, kMessageTagModifiedTime)) {
        std::vector<uint8_t> timestamp(8, 0);
        for (const PcProperty& property : properties) {
            if (property.prop_id == kMessageTagCreationTime &&
                (property.source ? property.source->size() : property.value.size()) == 8) {
                if (property.source) {
                    auto read = property.source->read_at(0, timestamp.data(), timestamp.size());
                    if (!read.ok())
                        return read.error();
                } else {
                    timestamp = property.value;
                }
                break;
            }
        }
        PcProperty property;
        property.prop_id = kMessageTagModifiedTime;
        property.prop_type = kTypeTime;
        property.value = std::move(timestamp);
        properties.push_back(std::move(property));
        ++builder.report.values_written;
        builder.note(context +
                     ": 0x3008 written as a copy of the message's 0x3007 ([MS-PST] 2.4.5.1.1 "
                     "requires the tag; no opened reference names a value for it)");
    }
    Result<PcNode> pc = build_pc(properties, local_nids);
    if (!pc.ok()) {
        return pc.error();
    }
    Result<std::pair<std::vector<uint64_t>, std::vector<StoreSubnode>>> placed =
        place_node_data(pc.value().heap, pc.value().subnodes, 0, 0, builder);
    if (!placed.ok()) {
        return placed.error();
    }
    std::pair<std::vector<uint64_t>, std::vector<StoreSubnode>> slots = placed.take();
    build.properties = properties;
    build.node.nid = build.nid;
    build.node.nid_parent = parent_nid;
    build.node.data_blocks = std::move(slots.first);
    build.node.subnodes = std::move(slots.second);
    for (StoreSubnode& subnode : message_subnodes) {
        build.node.subnodes.push_back(std::move(subnode));
    }
    for (StoreSubnode& subnode : attachment_subnodes) {
        build.node.subnodes.push_back(std::move(subnode));
    }
    std::sort(
        build.node.subnodes.begin(), build.node.subnodes.end(),
        [](const StoreSubnode& left, const StoreSubnode& right) { return left.nid < right.nid; });
    build.subnode.nid = build.nid;
    build.subnode.data_blocks = build.node.data_blocks;
    build.subnode.subnodes = build.node.subnodes;
    return build;
}

TcRow message_row(const MessageBuild& message, const std::vector<uint32_t>& tags, Builder& builder,
                  const std::string& context) {
    TcRow row;
    row.row_id = message.nid;
    row.values = std::vector<std::vector<uint8_t>>(tags.size());
    row.present_empty = std::vector<bool>(tags.size(), false);
    row.sources.resize(tags.size());
    for (size_t column = 0; column < tags.size(); ++column) {
        const uint32_t tag = tags[column];
        const uint16_t prop_id = static_cast<uint16_t>(ltp::tc_prop_id_of_tag(tag));
        const uint16_t type = tag_type(tag);
        if (prop_id == kTagLtpRowId) {
            // [MS-PST] 2.4.4.5.2: the row's dwRowID is the NID of the Message object it stands for.
            row.values[column] = le32_bytes(message.nid);
            ++builder.report.values_written;
            continue;
        }
        if (prop_id == kTagLtpRowVer) {
            row.values[column] = le32_bytes(0);
            ++builder.report.values_written;
            continue;
        }
        for (const PcProperty& property : message.properties) {
            if (property.prop_id != prop_id) {
                continue;
            }
            if (property.prop_type != type) {
                builder.note(context + ": message 0x" + hex8(message.nid) + " has 0x" +
                             hex4(prop_id) + " as type 0x" + hex4(property.prop_type) + ", not 0x" +
                             hex4(type) + ", so the contents cell is left out");
                break;
            }
            if (property.source) {
                row.sources[column] = property.source;
            } else if (!property.value.empty()) {
                row.values[column] = row_cell_from_pc_value(type, property.value);
            } else {
                row.present_empty[column] = !ltp::prop_type_is_tc_inline(type);
            }
            ++builder.report.values_written;
            break;
        }
    }
    return row;
}

// The Folder object, its Contents Table, its Hierarchy Table and its FAI table. [MS-PST] 2.4.4.3:
// one nidIndex wearing the PC type and the table types, each table naming the folder as nidParent
// ([MS-PST] 2.2.2.7.7.4 / 2.4.5.2).
Result<std::pair<uint32_t, uint32_t>>
build_folder(const ContentFolder& folder, uint32_t nid, uint32_t hierarchy_nid,
             uint32_t contents_nid, uint32_t fai_nid, const std::vector<HierarchyChild>& children,
             const std::vector<uint16_t>& npid_of_index, Builder& builder,
             const TcRowSource* normal_source = nullptr, const TcRowSource* fai_source = nullptr,
             uint32_t unread_count = 0, bool shared_fai_template = true) {
    const std::string context = "folder 0x" + hex8(nid);
    ++builder.report.folders;
    builder.report.folder_nids.push_back(nid);

    std::vector<MessageBuild> messages;
    for (const ContentMessage& message : folder.messages) {
        Result<MessageBuild> built = build_message(message, nid, npid_of_index, builder);
        if (!built.ok()) {
            return built.error();
        }
        messages.push_back(built.take());
    }

    const std::vector<uint32_t>& contents_tags = contents_template_tags();
    std::vector<TcRow> contents_rows;
    for (const MessageBuild& message : messages) {
        contents_rows.push_back(message_row(message, contents_tags, builder, context));
    }
    Result<TableBuild> contents =
        build_content_table(contents_nid, contents_tags, contents_rows, builder,
                            context + " contents table", normal_source);
    if (!contents.ok()) {
        return contents.error();
    }

    Result<std::vector<TcRow>> hierarchy = hierarchy_rows(children);
    if (!hierarchy.ok()) {
        return hierarchy.error();
    }
    Result<TableBuild> hierarchy_table =
        build_content_table(hierarchy_nid, hierarchy_template_tags(), hierarchy.value(), builder,
                            context + " hierarchy table");
    if (!hierarchy_table.ok()) {
        return hierarchy_table.error();
    }

    // The Folder object's own PC. [MS-PST] 2.4.4.1.1 requires 0x3001, 0x3602, 0x3603 and 0x360A;
    // the writer takes the first from the request and counts from committed content. The full
    // pipeline supplies unread_count; the legacy subset adapter retains its accepted zero-count
    // behavior.
    std::vector<ContentProperty> carried;
    for (const ContentProperty& value : folder.properties) {
        if (value.prop_id == ltp::kPropDisplayName || value.prop_id == kPropContentCount ||
            value.prop_id == kPropContentUnreadCount || value.prop_id == kPropSubfolders) {
            continue; // the writer sets these from the folder it is emitting
        }
        carried.push_back(value);
    }
    std::vector<PcProperty> properties =
        content_properties(carried, npid_of_index, context, builder);
    PcProperty name;
    name.prop_id = ltp::kPropDisplayName;
    name.prop_type = kTypeUnicode;
    name.value = utf16_bytes(folder.name);
    if (name.value.empty()) {
        name.value_hnid = 0; // an empty name has no heap allocation ([MS-PST] 2.3.3.3)
    }
    properties.push_back(std::move(name));
    const uint64_t content_count =
        normal_source != nullptr ? normal_source->count() : folder.messages.size();
    if (content_count > 0x7FFFFFFFu || unread_count > content_count) {
        return make_error(ErrorKind::kBadField, "writer.folder.counts", content_count, unread_count,
                          "folder counts exceed signed Integer32 or unread count exceeds contents");
    }
    properties.push_back(integer_property(kPropContentCount, static_cast<uint32_t>(content_count)));
    properties.push_back(integer_property(kPropContentUnreadCount, unread_count));
    properties.push_back(boolean_property(kPropSubfolders, static_cast<uint32_t>(children.size())));
    LocalNids folder_local_nids;
    Result<PcNode> pc = build_pc(properties, folder_local_nids);
    if (!pc.ok()) {
        return pc.error();
    }
    Result<std::pair<std::vector<uint64_t>, std::vector<StoreSubnode>>> placed =
        place_node_data(pc.value().heap, pc.value().subnodes, 0, 0, builder);
    if (!placed.ok()) {
        return placed.error();
    }
    std::pair<std::vector<uint64_t>, std::vector<StoreSubnode>> slots = placed.take();

    StoreNode folder_node;
    folder_node.nid = nid;
    folder_node.nid_parent = folder.parent_nid;
    folder_node.data_blocks = std::move(slots.first);
    folder_node.subnodes = std::move(slots.second);
    builder.nodes.push_back(std::move(folder_node));

    StoreNode contents_node;
    contents_node.nid = contents_nid;
    contents_node.nid_parent = nid;
    contents_node.data_blocks = std::move(contents.value().data_blocks);
    contents_node.subnodes = std::move(contents.value().subnodes);
    builder.nodes.push_back(std::move(contents_node));

    StoreNode hierarchy_node;
    hierarchy_node.nid = hierarchy_nid;
    hierarchy_node.nid_parent = nid;
    hierarchy_node.data_blocks = std::move(hierarchy_table.value().data_blocks);
    hierarchy_node.subnodes = std::move(hierarchy_table.value().subnodes);
    builder.nodes.push_back(std::move(hierarchy_node));

    // The FAI table of a new folder is the shared template block: columns, no rows, exactly as the
    // minimum mailbox gives every folder that has no associated messages ([MS-PST] 2.7.3.3).
    StoreNode fai_node;
    fai_node.nid = fai_nid;
    fai_node.nid_parent = nid;
    if (shared_fai_template && (fai_source == nullptr || fai_source->count() == 0)) {
        fai_node.data_blocks.push_back(kSlotFaiTemplate);
    } else {
        auto fai = build_content_table(fai_nid, fai_template_tags(), {}, builder,
                                       context + " associated contents table", fai_source);
        if (!fai.ok())
            return fai.error();
        fai_node.data_blocks = std::move(fai.value().data_blocks);
        fai_node.subnodes = std::move(fai.value().subnodes);
    }
    builder.nodes.push_back(std::move(fai_node));

    for (MessageBuild& message : messages) {
        builder.nodes.push_back(std::move(message.node));
    }
    return std::make_pair(nid, contents_nid);
}

} // namespace

namespace {

// [MS-PST] 2.4.7.1 names PS_MAPI and PS_PUBLIC_STRINGS and defers their bytes to
// [MS-OXPROPS] 1.3.2, which this repository does not carry; libpff format notes (see
// THIRD_PARTY_NOTICES.txt):2264 and :2266 record both GUIDs and upstream
// libpff/libfmapi/libfmapi_class_identifier.c:29 and :32 hold the same 16 bytes, so the writer
// carries them as reference values, exactly as src/ltp/name_id.cpp does.
const std::vector<uint8_t>& mapi_guid() {
    static const std::vector<uint8_t> guid = {0x28, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                                              0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};
    return guid;
}

const std::vector<uint8_t>& public_strings_guid() {
    static const std::vector<uint8_t> guid = {0x29, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                                              0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};
    return guid;
}

std::u16string u16_from_ascii(const char* text) {
    std::u16string out;
    for (const char* p = text; *p != '\0'; ++p) {
        out.push_back(static_cast<char16_t>(static_cast<unsigned char>(*p)));
    }
    return out;
}

// The Name-to-ID Map PC ([MS-PST] 2.4.7). With nothing to register it is the minimum mailbox's
// single synthetic entry, byte for byte; otherwise every identity the request carried is registered
// in order, with zero-based wPropIdx so the first NPID is 0x8000 ([MS-PST] 2.4.2.2 / 2.4.7.1), the
// GUIDs deduplicated into the GUID Stream (2.4.7.2), the string names length-prefixed and 4-byte
// aligned in the String Stream (2.4.7.4), and every record placed in the bucket its own
// dwPropertyID hashes to (2.4.7.5).
Result<std::vector<PcProperty>> name_id_properties(const std::vector<NamedProperty>& named,
                                                   Builder& builder) {
    std::vector<PcProperty> properties;
    properties.push_back(
        integer_property(ltp::kPropNameidBucketCount, ltp::kNameidBucketCountRecommended));

    if (named.empty()) {
        const std::vector<uint8_t> entry =
            name_id_record(kNameidNumericName, false, ltp::kNameIdGuidMapi, kNameidPropIndex);
        const uint16_t guid_word =
            static_cast<uint16_t>(ltp::kNameIdGuidMapi << ltp::kNameIdGuidShift);
        const uint32_t bucket =
            ltp::name_id_bucket(kNameidNumericName, guid_word, ltp::kNameidBucketCountRecommended);
        properties.push_back(binary_property(ltp::kPropNameidStreamGuid, guid_stream()));
        properties.push_back(binary_property(ltp::kPropNameidStreamEntry, entry));
        properties.push_back(
            binary_property(ltp::kPropNameidStreamString, std::vector<uint8_t>(4, 0)));
        properties.push_back(
            binary_property(static_cast<uint16_t>(ltp::kPropNameidBucketBase + bucket), entry));
        return properties;
    }

    // wGuid 1 and 2 name the two well-known sets without a GUID Stream entry ([MS-PST] 2.4.7.1),
    // and libpff refuses a zero-length GUID Stream
    // (third_party/libpff/libpff/libpff_name_to_id_map.c:459), so a map that needs no custom GUID
    // still carries the two well-known ones, as the minimum mailbox does. That is a writer choice,
    // not a rule the opened references state.
    std::vector<std::vector<uint8_t>> guids;
    for (const NamedProperty& entry : named) {
        if (entry.guid.empty() || entry.guid == mapi_guid() ||
            entry.guid == public_strings_guid()) {
            continue;
        }
        if (std::find(guids.begin(), guids.end(), entry.guid) == guids.end()) {
            guids.push_back(entry.guid);
        }
    }
    if (guids.empty()) {
        const std::vector<uint8_t> well_known = guid_stream();
        guids.push_back(std::vector<uint8_t>(well_known.begin(), well_known.begin() + 16));
        guids.push_back(std::vector<uint8_t>(well_known.begin() + 16, well_known.end()));
    }
    const auto guid_index_of = [&](const std::vector<uint8_t>& guid) -> uint16_t {
        if (guid.empty()) {
            return ltp::kNameIdGuidNone;
        }
        if (guid == mapi_guid()) {
            return ltp::kNameIdGuidMapi;
        }
        if (guid == public_strings_guid()) {
            return ltp::kNameIdGuidPublicStrings;
        }
        for (size_t index = 0; index < guids.size(); ++index) {
            if (guids[index] == guid) {
                return static_cast<uint16_t>(ltp::kNameIdGuidStreamFirst + index);
            }
        }
        return ltp::kNameIdGuidNone;
    };

    // [MS-PST] 2.4.7.4: each name is a DWORD byte length followed by the Unicode bytes, and padding
    // ends each pair on a 4-byte boundary. dwPropertyID of an N == 1 record is the offset of that
    // pair.
    std::vector<uint8_t> string_stream;
    std::vector<uint32_t> name_offset(named.size(), 0);
    for (size_t index = 0; index < named.size(); ++index) {
        if (!named[index].name_is_string) {
            continue;
        }
        const std::vector<uint8_t> bytes = utf16_bytes(named[index].name);
        name_offset[index] = static_cast<uint32_t>(string_stream.size());
        const std::vector<uint8_t> length = le32_bytes(static_cast<uint32_t>(bytes.size()));
        string_stream.insert(string_stream.end(), length.begin(), length.end());
        string_stream.insert(string_stream.end(), bytes.begin(), bytes.end());
        while (string_stream.size() % ltp::kNameidStringAlignment != 0) {
            string_stream.push_back(0);
        }
    }
    if (string_stream.empty()) {
        string_stream =
            std::vector<uint8_t>(4, 0); // one length DWORD of 0: the smallest pair it can be
    }

    std::vector<uint8_t> entry_stream;
    std::map<uint32_t, std::vector<uint8_t>> buckets;
    for (size_t index = 0; index < named.size(); ++index) {
        const NamedProperty& entry = named[index];
        const uint16_t guid_index = guid_index_of(entry.guid);
        const bool string_name = entry.name_is_string;
        const uint16_t prop_index = static_cast<uint16_t>(index);
        const uint32_t entry_name = string_name ? name_offset[index] : entry.numeric_name;
        const std::vector<uint8_t> entry_record =
            name_id_record(entry_name, string_name, guid_index, prop_index);
        entry_stream.insert(entry_stream.end(), entry_record.begin(), entry_record.end());
        // [MS-PST] 2.4.7.5: a record inside a hash bucket holds the CRC32 ([MS-PST] 5.3) of the
        // name in dwPropertyID, not the String Stream offset the Entry Stream record holds. This is
        // exactly what src/ltp/name_id.cpp verifies, and ltp::name_id_crc is that reader's own
        // implementation.
        const uint32_t candidate = string_name ? ltp::name_id_crc(entry.name) : entry.numeric_name;
        const uint16_t guid_word = static_cast<uint16_t>((guid_index << ltp::kNameIdGuidShift) |
                                                         (string_name ? ltp::kNameIdNameBit : 0u));
        const uint32_t bucket =
            ltp::name_id_bucket(candidate, guid_word, ltp::kNameidBucketCountRecommended);
        if (bucket >= ltp::kNameidBucketCountRecommended) {
            return make_error(ErrorKind::kBadField, "NAMEID.bucket", bucket,
                              ltp::kNameidBucketCountRecommended,
                              "a bucket index must sit inside the bucket count ([MS-PST] 2.4.7.5)");
        }
        const std::vector<uint8_t> bucket_record =
            name_id_record(candidate, string_name, guid_index, prop_index);
        std::vector<uint8_t>& stream = buckets[bucket];
        stream.insert(stream.end(), bucket_record.begin(), bucket_record.end());
    }

    std::vector<uint8_t> guid_bytes;
    for (const std::vector<uint8_t>& guid : guids) {
        guid_bytes.insert(guid_bytes.end(), guid.begin(), guid.end());
    }
    properties.push_back(binary_property(ltp::kPropNameidStreamGuid, std::move(guid_bytes)));
    properties.push_back(binary_property(ltp::kPropNameidStreamEntry, std::move(entry_stream)));
    properties.push_back(binary_property(ltp::kPropNameidStreamString, std::move(string_stream)));
    // Only the buckets that hold a record become a property, as in the minimum mailbox:
    // [MS-PST] 2.4.7.5 numbers the buckets from PidTagNameidBucketBase but does not require an
    // empty one to be present, and this reader counts a missing bucket without treating it as a
    // failure (src/ltp/name_id.cpp).
    for (const auto& bucket : buckets) {
        properties.push_back(binary_property(
            static_cast<uint16_t>(ltp::kPropNameidBucketBase + bucket.first), bucket.second));
    }
    builder.note("Name-to-ID Map: " + std::to_string(named.size()) +
                 " named properties re-registered, " + std::to_string(guids.size()) +
                 " GUID Stream entries, " + std::to_string(buckets.size()) +
                 " non-empty buckets of " + std::to_string(ltp::kNameidBucketCountRecommended));
    return properties;
}

// The blocks and nodes of the minimum mailbox ([MS-PST] 2.7.3), which is what the accepted M4
// candidate is, with any folder the request added folded into the hierarchy tables. The Name-to-ID
// Map node is returned rather than slotted because a map with real entries has streams big enough
// to need subnodes.
struct NameIdNode {
    std::vector<uint64_t> data_blocks;
    std::vector<StoreSubnode> subnodes;
};

// The children of one minimum-mailbox folder: the ones [MS-PST] 2.7.3.4 names, plus any folder the
// request put under it.
Result<std::vector<HierarchyChild>>
mailbox_children(uint32_t nid,
                 const std::map<uint32_t, std::vector<HierarchyChild>>& extra_children) {
    const FolderSpec* spec = folder_spec(nid);
    if (spec == nullptr) {
        return make_error(ErrorKind::kBadField, "hierarchy.row", nid, nid,
                          "a hierarchy row names a folder this writer does not have");
    }
    std::vector<HierarchyChild> children;
    for (const uint32_t child_nid : spec->children) {
        const FolderSpec* child = folder_spec(child_nid);
        if (child == nullptr) {
            return make_error(ErrorKind::kBadField, "hierarchy.row", child_nid, child_nid,
                              "a hierarchy row names a folder this writer does not have");
        }
        HierarchyChild entry;
        entry.nid = child_nid;
        entry.name = u16_from_ascii(child->name);
        entry.content_count = child->content_count;
        entry.content_unread = child->content_unread;
        entry.subfolders = child->subfolders;
        children.push_back(entry);
    }
    const auto found = extra_children.find(nid);
    if (found != extra_children.end()) {
        children.insert(children.end(), found->second.begin(), found->second.end());
    }
    return children;
}

Result<NameIdNode>
build_minimum_mailbox(Builder& builder, const std::vector<NamedProperty>& named,
                      const std::map<uint32_t, std::vector<HierarchyChild>>& extra_children,
                      std::map<uint32_t, uint64_t>* hierarchy_slot) {
    // The message store ([MS-PST] 2.4.3.1): the Provider UID, a display name, and the three
    // EntryIDs. [MS-PST] 3.10's own sample message store PC carries this same Provider UID and puts
    // NIDs 0x8022, 0x8062 and 0x8042 in 0x35E0, 0x35E3 and 0x35E7, so the writer copies that
    // reading.
    Result<std::vector<uint8_t>> node = pc_image({
        binary_property(kPropRecordKey, kProviderUid),
        string_property(ltp::kPropDisplayName, kMessageStoreName),
        binary_property(kPropIpmSubTreeEntryId, entry_id(0x8022)),
        binary_property(kPropIpmWastebasketEntryId, entry_id(0x8062)),
        binary_property(kPropFinderEntryId, entry_id(0x8042)),
        // MS-PST 2.4.3.3 defines the password checksum; both the Outlook oracle and
        // SCANPST's repaired store explicitly carry zero for an unprotected store.
        integer_property(0x67FF, 0),
    });
    if (!node.ok()) {
        return node.error();
    }
    builder.set_slot(kSlotMessageStore, node.take());

    // The Name-to-ID Map ([MS-PST] 2.7.3.2). With nothing to register it is the minimum mailbox's
    // one synthetic entry, which is what the accepted M4 candidate carries; libpff refuses a
    // zero-length Entry Stream or GUID Stream
    // (third_party/libpff/libpff/libpff_name_to_id_map.c:379 and :459) and this reader reaches a
    // stream only through a non-empty heap allocation, so an empty map is not a map at all. The
    // oracle's map has 38 entries (research/blank-pst-diff.md).
    Result<std::vector<PcProperty>> name_id = name_id_properties(named, builder);
    if (!name_id.ok()) {
        return name_id.error();
    }
    NameIdNode name_id_node;
    if (named.empty()) {
        Result<std::vector<uint8_t>> image = pc_image(name_id.value());
        if (!image.ok()) {
            return image.error();
        }
        builder.set_slot(kSlotNameIdMap, image.take());
        name_id_node.data_blocks.push_back(kSlotNameIdMap);
    } else {
        LocalNids local_nids;
        Result<PcNode> pc = build_pc(name_id.value(), local_nids);
        if (!pc.ok()) {
            return pc.error();
        }
        Result<std::pair<std::vector<uint64_t>, std::vector<StoreSubnode>>> placed =
            place_node_data(pc.value().heap, pc.value().subnodes, 0, 0, builder, kSlotNameIdMap);
        if (!placed.ok()) {
            return placed.error();
        }
        std::pair<std::vector<uint64_t>, std::vector<StoreSubnode>> slots = placed.take();
        name_id_node.data_blocks = std::move(slots.first);
        name_id_node.subnodes = std::move(slots.second);
    }

    // The five folders ([MS-PST] 2.7.3.4). The Root Folder's display name is present and empty,
    // which a PC says by dwValueHnid 0; every other folder's name becomes a heap allocation.
    static const std::pair<uint32_t, uint64_t> kFolderSlots[] = {
        {0x0122, kSlotRootFolder},   {0x8022, kSlotIpmsubtree}, {0x8042, kSlotSearchRoot},
        {0x8062, kSlotDeletedItems}, {0x2223, kSlotSpamSearch},
    };
    for (const FolderSpec& spec : folders()) {
        std::vector<PcProperty> properties;
        if (spec.name[0] == '\0') {
            properties.push_back(empty_string_property(ltp::kPropDisplayName));
        } else {
            properties.push_back(string_property(ltp::kPropDisplayName, spec.name));
        }
        properties.push_back(integer_property(kPropContentCount, spec.content_count));
        properties.push_back(integer_property(kPropContentUnreadCount, spec.content_unread));
        properties.push_back(boolean_property(kPropSubfolders, spec.subfolders));
        node = pc_image(properties);
        if (!node.ok()) {
            return node.error();
        }
        uint64_t slot = 0;
        for (const auto& entry : kFolderSlots) {
            if (entry.first == spec.nid) {
                slot = entry.second;
            }
        }
        builder.set_slot(slot, node.take());
    }

    // The hierarchy tables. [MS-PST] 2.7.3.4.1 gives the Root Folder 3 rows and 2.7.3.4.2 gives IPM
    // Subtree 1; every other folder's hierarchy table is the template block, which has the columns
    // and no rows. A folder the request put under one of these folders adds a row, and a folder
    // whose table was the shared template gets a table of its own, because the template block is
    // shared and cannot be rewritten for one folder ([MS-PST] 2.2.2.7.7.3.1: one block, several
    // references).
    for (const FolderSpec& spec : folders()) {
        Result<std::vector<HierarchyChild>> children = mailbox_children(spec.nid, extra_children);
        if (!children.ok()) {
            return children.error();
        }
        if (children.value().empty()) {
            hierarchy_slot->insert(
                std::make_pair(spec.nid, static_cast<uint64_t>(kSlotHierarchyTemplate)));
            continue;
        }
        Result<std::vector<TcRow>> rows = hierarchy_rows(children.value());
        if (!rows.ok()) {
            return rows.error();
        }
        Result<std::vector<uint8_t>> image =
            tc_image(columns(hierarchy_template_tags()), rows.value());
        if (!image.ok()) {
            return image.error();
        }
        if (spec.nid == 0x0122) {
            builder.set_slot(kSlotRootHierarchy, image.take());
            hierarchy_slot->insert(
                std::make_pair(spec.nid, static_cast<uint64_t>(kSlotRootHierarchy)));
        } else if (spec.nid == 0x8022) {
            builder.set_slot(kSlotIpmsubtreeHierarchy, image.take());
            hierarchy_slot->insert(
                std::make_pair(spec.nid, static_cast<uint64_t>(kSlotIpmsubtreeHierarchy)));
        } else {
            const uint64_t block = builder.append_block(image.take());
            hierarchy_slot->insert(std::make_pair(spec.nid, block));
        }
    }

    // The six template objects ([MS-PST] 2.7.3.3): a TC with the columns and no rows.
    const uint64_t template_slots[] = {
        kSlotHierarchyTemplate,      kSlotContentsTemplate,  kSlotFaiTemplate,
        kSlotSearchContentsTemplate, kSlotRecipientTemplate, kSlotAttachmentTemplate,
    };
    const std::vector<uint32_t>* template_tags[] = {
        &hierarchy_template_tags(),       &contents_template_tags(),  &fai_template_tags(),
        &search_contents_template_tags(), &recipient_template_tags(), &attachment_template_tags(),
    };
    for (size_t index = 0; index < sizeof(template_slots) / sizeof(template_slots[0]); ++index) {
        Result<std::vector<uint8_t>> image = tc_image(columns(*template_tags[index]), {});
        if (!image.ok()) {
            return image.error();
        }
        builder.set_slot(template_slots[index], image.take());
    }

    // Version-specific schemas measured in the Outlook-created blank PST and required
    // by SCANPST. MS-PST names receive/outgoing node types, but not these full schemas.
    // Do not generalize the three extra template nidTypes to all source OST nodes.
    const std::pair<uint64_t, std::vector<uint32_t>> extra_templates[] = {
        {kSlotOutgoingTable, {0x00390040, 0x0E100003, 0x0E140003, 0x67F20003, 0x67F30003}},
        {kSlotInternalTemplate16, {0x0E330014, 0x0E370102, 0x0E380003, 0x67F20003, 0x67F30003}},
        {kSlotInternalTemplate17,
         {0x001A001F, 0x0E300102, 0x0E310102, 0x0E330014, 0x0E340102, 0x0E380003, 0x0E3E0102,
          0x67F20003, 0x67F30003}},
        {kSlotInternalTemplate18, {0x0E330014, 0x30070040, 0x67F20003, 0x67F30003}},
    };
    for (const auto& entry : extra_templates) {
        Result<std::vector<uint8_t>> image = tc_image(columns(entry.second), {});
        if (!image.ok()) {
            return image.error();
        }
        builder.set_slot(entry.first, image.take());
    }
    // The oracle's default receive class is present but empty, routing to the root.
    TcRow receive{1, {{}, le32_bytes(0x0122), le32_bytes(1), le32_bytes(0)}};
    receive.present_empty = {true, false, false, false};
    Result<std::vector<uint8_t>> image =
        tc_image(columns({0x001A001F, 0x66050003, 0x67F20003, 0x67F30003}), {receive});
    if (!image.ok()) {
        return image.error();
    }
    builder.set_slot(kSlotReceiveTable, image.take());

    // libpff "The 9c table": root references a BTH with GUID keys and DWORD values.
    // The Outlook oracle has the empty form (hidRoot=0), so no opaque data is copied.
    HeapImage guid_map(0x9C);
    auto allocated = guid_map.append(le32_bytes(2u << ltp::kHidIndexShift));
    if (!allocated.ok()) {
        return allocated.error();
    }
    allocated = guid_map.append({ltp::kBthType, 16, 4, 0, 0, 0, 0, 0});
    if (!allocated.ok()) {
        return allocated.error();
    }
    builder.set_slot(kSlotGuidMap, guid_map.bytes());
    // MS-PST 2.4.8.4.2: SAL is an array of NIDs. SCANPST and the
    // blank oracle include the already-existing spam search folder in that list.
    builder.set_slot(kSlotSearchActivity, le32_bytes(0x2223));
    // MS-PST 2.4.8.6.4 identifies the SCO as a PC; libpff's folder example and
    // both blank outputs carry 660B:0003=0. Its broader semantics remain unspecified.
    node = pc_image({integer_property(0x660B, 0)});
    if (!node.ok()) {
        return node.error();
    }
    builder.set_slot(kSlotSearchCriteria, node.take());
    return name_id_node;
}

} // namespace
namespace {
Result<ContentPlan> finish_plan(Builder& builder, const std::vector<NamedProperty>& named,
                                const std::map<uint32_t, std::vector<HierarchyChild>>& children_of,
                                uint32_t associated_index = 32768) {
    std::map<uint32_t, uint64_t> hierarchy_slot;
    Result<NameIdNode> name_id_node =
        build_minimum_mailbox(builder, named, children_of, &hierarchy_slot);
    if (!name_id_node.ok()) {
        return name_id_node.error();
    }

    // The nodes of the minimum mailbox ([MS-PST] 2.7.1 lists the mandatory ones). A folder object
    // is one nidIndex wearing its PC type and its table types ([MS-PST] 2.4.4.3), so each table NID
    // sits under the folder's own nidIndex and nidParent is the folder that owns it
    // ([MS-PST] 2.2.2.7.7.4 / 2.4.5.2).
    struct NbtSpec {
        uint32_t nid;
        std::vector<uint64_t> data_blocks;
        uint32_t nid_parent;
    };
    const std::vector<NbtSpec> specs = {
        {0x0021, {kSlotMessageStore}, 0},
        {0x0061, name_id_node.value().data_blocks, 0},
        {0x0122, {kSlotRootFolder}, 0x0122},
        {0x012D, {hierarchy_slot.at(0x0122)}, 0x0122},
        {0x012E, {kSlotContentsTemplate}, 0x0122},
        {0x012F, {kSlotFaiTemplate}, 0x0122},
        {0x01E1, {}, 0}, // Search Management Queue: an empty queue node (2.7.3.5)
        {0x0201, {kSlotSearchActivity}, 0},
        {0x060D, {kSlotHierarchyTemplate}, 0},
        {0x060E, {kSlotContentsTemplate}, 0},
        {0x060F, {kSlotFaiTemplate}, 0},
        {0x0610, {kSlotSearchContentsTemplate}, 0},
        {0x062B, {kSlotReceiveTable}, 0},
        {0x064C, {kSlotOutgoingTable}, 0},
        {0x0671, {kSlotAttachmentTemplate}, 0},
        {0x0692, {kSlotRecipientTemplate}, 0},
        {0x06B6, {kSlotInternalTemplate16}, 0},
        {0x06D7, {kSlotInternalTemplate17}, 0},
        {0x06F8, {kSlotInternalTemplate18}, 0},
        {0x0C01, {kSlotGuidMap}, 0},
        {0x0EC1, {}, 0}, // empty update queue, as in both independent blank outputs
        {0x2223, {kSlotSpamSearch}, 0x0122},
        {0x2226, {}, 0}, // MS-PST 2.4.8.6.3: empty search update queue
        {0x2227, {kSlotSearchCriteria}, 0},
        {0x222D, {hierarchy_slot.at(0x2223)}, 0x2223},
        {0x222E, {kSlotContentsTemplate}, 0x2223},
        {0x222F, {kSlotFaiTemplate}, 0x2223},
        {0x2230, {kSlotSearchContentsTemplate}, 0x2223},
        {0x8022, {kSlotIpmsubtree}, 0x0122},
        {0x802D, {hierarchy_slot.at(0x8022)}, 0x8022},
        {0x802E, {kSlotContentsTemplate}, 0x8022},
        {0x802F, {kSlotFaiTemplate}, 0x8022},
        {0x8042, {kSlotSearchRoot}, 0x0122},
        {0x804D, {hierarchy_slot.at(0x8042)}, 0x8042},
        {0x804E, {kSlotContentsTemplate}, 0x8042},
        {0x804F, {kSlotFaiTemplate}, 0x8042},
        {0x8062, {kSlotDeletedItems}, 0x8022},
        {0x806D, {hierarchy_slot.at(0x8062)}, 0x8062},
        {0x806E, {kSlotContentsTemplate}, 0x8062},
        {0x806F, {kSlotFaiTemplate}, 0x8062},
    };
    for (const NbtSpec& spec : specs) {
        StoreNode node;
        node.nid = spec.nid;
        node.nid_parent = spec.nid_parent;
        node.data_blocks = spec.data_blocks;
        if (spec.nid == 0x0061) {
            node.subnodes = std::move(name_id_node.value().subnodes);
        }
        builder.nodes.push_back(std::move(node));
    }

    // The plan the emitter lays out. The minimum-mailbox blocks keep the slot order, so the BIDs
    // they take are the ones the Outlook-accepted M4 candidate carried; content blocks follow them.
    // A template block named by several nodes stays one block with several references
    // ([MS-PST] 2.2.2.7.7.3.1), which is why the plan names blocks by index instead of giving every
    // node its own copy.
    StorePlan plan;
    plan.blocks = std::move(builder.blocks);
    plan.nodes = std::move(builder.nodes);

    // [MS-PST] 2.2.2.1: rgnid[type] is the last nidIndex allocated for that type. The folder NIDs
    // this writer uses are the ones [MS-PST] 2.7.1 names, and 0x8022, 0x8042 and 0x8062 are
    // nidIndex 1025, 1026 and 1027, so the folder and folder-table types end at 1027 in a store
    // with no content. Every NID this writer gives a type whose nodes all sit below that type's
    // seed (0x21, 0x61, 0x1E1, 0x201, 0x60D .. 0x692, 0x2223, 0x2230) leaves the seed alone.
    plan.rgnid.assign(ndb::kRgnidCount,
                      1024u); // [MS-PST] 2.2.2.1: "Any other NID_TYPE" starts at nidIndex 1024
    plan.rgnid[ltp::kNidTypeSearchFolder] = 16384;
    plan.rgnid[ltp::kNidTypeNormalMessage] = builder.message_index;
    plan.rgnid[ltp::kNidTypeAssocMessage] = associated_index;
    plan.rgnid[ltp::kNidTypeNormalFolder] = builder.folder_index;
    plan.rgnid[ltp::kNidTypeHierarchyTable] = builder.folder_index;
    plan.rgnid[ltp::kNidTypeContentsTable] = builder.folder_index;
    plan.rgnid[ltp::kNidTypeAssocContentsTable] = builder.folder_index;

    ContentPlan result;
    result.plan = std::move(plan);
    result.report = std::move(builder.report);
    return result;
}

} // namespace

Result<StoreOutcome> build_store(const StoreRequest& request) {
    Builder builder;

    // [MS-PST] 2.4.2.2 / 2.4.7.1: the inclusive NPID range 0x8000..0x8FFF
    // holds 4096 identities, whose Entry Stream ordinals start at zero.
    constexpr size_t kNamedCapacity = ltp::kNpidMax - ltp::kNpidBase + 1u;
    if (request.named_properties.size() > kNamedCapacity) {
        return make_error(ErrorKind::kBadField, "NAMEID.wPropIdx", request.named_properties.size(),
                          kNamedCapacity,
                          "an NPID is 0x8000 + wPropIdx and tops out at 0x8FFF ([MS-PST] 2.4.7.1)");
    }
    std::vector<uint16_t> npid_of_index;
    npid_of_index.reserve(request.named_properties.size());
    for (size_t index = 0; index < request.named_properties.size(); ++index) {
        npid_of_index.push_back(static_cast<uint16_t>(ltp::kNpidBase + index));
    }
    builder.report.named_properties = request.named_properties.size();

    // [MS-PST] 2.2.2.1: rgnid[nidType] is the last nidIndex allocated for that type, and 2.4.4.3
    // puts a folder's tables under the same nidIndex, so one allocation per folder gives its PC NID
    // and the three table NIDs that share its nidIndex.
    struct FolderNids {
        uint32_t nid = 0;
        uint32_t hierarchy = 0;
        uint32_t contents = 0;
        uint32_t fai = 0;
    };
    std::vector<FolderNids> folder_nids;
    folder_nids.reserve(request.folders.size());
    for (size_t index = 0; index < request.folders.size(); ++index) {
        const uint32_t folder_index = ++builder.folder_index;
        FolderNids nids;
        nids.nid = static_cast<uint32_t>(ltp::make_nid(folder_index, ltp::kNidTypeNormalFolder));
        nids.hierarchy =
            static_cast<uint32_t>(ltp::make_nid(folder_index, ltp::kNidTypeHierarchyTable));
        nids.contents =
            static_cast<uint32_t>(ltp::make_nid(folder_index, ltp::kNidTypeContentsTable));
        nids.fai =
            static_cast<uint32_t>(ltp::make_nid(folder_index, ltp::kNidTypeAssocContentsTable));
        folder_nids.push_back(nids);
    }

    // Which folder is whose child, and what each hierarchy row has to say about the folder it
    // names.
    std::map<uint32_t, std::vector<HierarchyChild>> children_of;
    for (size_t index = 0; index < request.folders.size(); ++index) {
        const ContentFolder& folder = request.folders[index];
        uint32_t subfolders = 0;
        for (const ContentFolder& candidate : request.folders) {
            if (candidate.parent_nid == folder_nids[index].nid) {
                ++subfolders;
            }
        }
        HierarchyChild child;
        child.nid = folder_nids[index].nid;
        child.name = folder.name;
        child.content_count = static_cast<uint32_t>(folder.messages.size());
        child.content_unread =
            0; // [MS-PST] 2.4.4.1.1 requires the property and names no rule for its value
        child.subfolders = subfolders;
        children_of[folder.parent_nid].push_back(child);
    }

    for (size_t index = 0; index < request.folders.size(); ++index) {
        const ContentFolder& folder = request.folders[index];
        const FolderNids& nids = folder_nids[index];
        std::vector<HierarchyChild> children;
        const auto found = children_of.find(nids.nid);
        if (found != children_of.end()) {
            children = found->second;
        }
        Result<std::pair<uint32_t, uint32_t>> built =
            build_folder(folder, nids.nid, nids.hierarchy, nids.contents, nids.fai, children,
                         npid_of_index, builder);
        if (!built.ok()) {
            return built.error();
        }
    }

    auto planned = finish_plan(builder, request.named_properties, children_of);
    if (!planned.ok())
        return planned.error();
    ContentPlan content = planned.take();
    Result<StoreImage> image = write_store(content.plan);
    if (!image.ok()) {
        return image.error();
    }
    StoreOutcome outcome;
    outcome.image = image.take();
    content.report.blocks = outcome.image.blocks.size();
    content.report.file_bytes = outcome.image.file_bytes;
    outcome.report = std::move(content.report);
    return outcome;
}

namespace {

Result<std::vector<uint16_t>> named_indices(uint64_t count) {
    if (count > ltp::kNpidMax - ltp::kNpidBase + 1u) {
        return make_error(ErrorKind::kUnsupported, "NAMEID.wPropIdx", count, 0,
                          "registry exceeds the NPID range in MS-PST 2.4.7.1");
    }
    std::vector<uint16_t> result;
    for (uint64_t index = 0; index < count; ++index) {
        result.push_back(static_cast<uint16_t>(ltp::kNpidBase + index));
    }
    return result;
}

ContentPlan take_content_plan(Builder& builder) {
    ContentPlan result;
    result.plan.blocks = std::move(builder.blocks);
    result.plan.nodes = std::move(builder.nodes);
    result.report = std::move(builder.report);
    return result;
}

util::Status check_folder_summary(const FolderSummary& folder) {
    if (ltp::nid_type(folder.nid) != ltp::kNidTypeNormalFolder ||
        ltp::nid_index(folder.nid) <= 1027 || folder.parent_nid == folder.nid ||
        ltp::nid_type(folder.parent_nid) != ltp::kNidTypeNormalFolder ||
        folder.content_count > 0x7FFFFFFFu || folder.unread_count > folder.content_count) {
        return make_error(ErrorKind::kBadField, "writer.folder.summary", folder.nid,
                          folder.parent_nid,
                          "invalid reserved folder identity, parent or committed counts");
    }
    return util::Status{};
}

HierarchyChild hierarchy_child(const FolderSummary& folder) {
    HierarchyChild child;
    child.nid = folder.nid;
    child.name = folder.name;
    child.content_count = folder.content_count;
    child.content_unread = folder.unread_count;
    child.subfolders = folder.has_subfolders ? 1u : 0u;
    child.has_hidden_count = folder.has_hidden_count;
    child.has_hidden_unread = folder.has_hidden_unread;
    return child;
}

class CheckedFolderRows final : public TcRowSource {
  public:
    CheckedFolderRows(const TcRowSource* source, uint32_t type) : source_(source), type_(type) {}
    uint64_t count() const override { return source_ != nullptr ? source_->count() : 0; }
    Result<TcRow> read(uint64_t index) const override {
        if (source_ == nullptr) {
            return make_error(ErrorKind::kBadField, "writer.folder.rows", index, 0,
                              "empty source has no rows");
        }
        auto row = source_->read(index);
        if (!row.ok())
            return row.error();
        if (ltp::nid_type(row.value().row_id) != type_) {
            return make_error(
                ErrorKind::kBadField, "writer.folder.row_kind", index, row.value().row_id,
                "normal and associated contents rows must use their own message NID type");
        }
        return row;
    }

  private:
    const TcRowSource* source_;
    uint32_t type_;
};

} // namespace

Result<ItemPlan> build_item_plan(const ContentMessage& message, uint32_t nid, uint32_t parent_nid,
                                 uint64_t named_count, std::shared_ptr<util::Workspace> workspace) {
    const auto type = ltp::nid_type(nid);
    if ((type != ltp::kNidTypeNormalMessage && type != ltp::kNidTypeAssocMessage) ||
        ltp::nid_type(parent_nid) != ltp::kNidTypeNormalFolder ||
        ltp::nid_index(nid) <= (type == ltp::kNidTypeAssocMessage ? 32768u : 65536u)) {
        return make_error(
            ErrorKind::kBadField, "writer.item.identity", nid, parent_nid,
            "top-level item needs a reserved normal/associated identity and folder parent");
    }
    auto indices = named_indices(named_count);
    if (!indices.ok())
        return indices.error();
    Builder builder(workspace);
    builder.blocks.clear();
    auto built = build_message(message, parent_nid, indices.value(), builder, nid);
    if (!built.ok())
        return built.error();
    ItemPlan result;
    result.row = message_row(built.value(),
                             type == ltp::kNidTypeAssocMessage ? fai_template_tags()
                                                               : contents_template_tags(),
                             builder, "item contents row");
    // MS-PST 2.4.4.1.1 defines unread count and 2.4.5.1.1 names PidTagMessageFlags.
    // The read bit value is from local libpff include/libpff/mapi.h LIBPFF_MESSAGE_FLAG_READ.
    for (const auto& property : built.value().properties) {
        if (property.prop_id == kMessageTagFlags && property.prop_type == kTypeInteger32 &&
            (property.source ? property.source->size() : property.value.size()) == 4) {
            std::array<uint8_t, 4> bytes{};
            if (property.source) {
                auto read = property.source->read_at(0, bytes.data(), bytes.size());
                if (!read.ok())
                    return read.error();
            } else {
                std::copy(property.value.begin(), property.value.end(), bytes.begin());
            }
            result.read_state_known = true;
            result.unread = (bytes[0] & 0x01u) == 0;
        }
    }
    builder.nodes.push_back(std::move(built.value().node));
    if (builder.scratch && !builder.scratch->status().ok())
        return builder.scratch->status().error();
    result.content = take_content_plan(builder);
    return result;
}

Result<ContentPlan> build_folder_plan(const FolderPlanRequest& request, uint64_t named_count) {
    auto valid = check_folder_summary(request.folder);
    if (!valid.ok())
        return valid.error();
    auto indices = named_indices(named_count);
    if (!indices.ok())
        return indices.error();
    CheckedFolderRows normal(request.normal_rows, ltp::kNidTypeNormalMessage);
    CheckedFolderRows associated(request.associated_rows, ltp::kNidTypeAssocMessage);
    if (associated.count() > 0x7FFFFFFFu) {
        return make_error(ErrorKind::kBadField, "writer.folder.associated_count",
                          request.folder.nid, associated.count(),
                          "associated count exceeds signed Integer32");
    }
    if (normal.count() != request.folder.content_count ||
        request.folder.has_subfolders != !request.children.empty()) {
        return make_error(ErrorKind::kBadField, "writer.folder.committed_counts",
                          request.folder.nid, normal.count(),
                          "folder summary differs from committed rows or child map");
    }
    std::set<uint32_t> seen;
    std::vector<HierarchyChild> children;
    for (const auto& child : request.children) {
        valid = check_folder_summary(child);
        if (!valid.ok())
            return valid.error();
        if (child.parent_nid != request.folder.nid || !seen.insert(child.nid).second) {
            return make_error(ErrorKind::kBadField, "writer.folder.children", child.nid,
                              child.parent_nid,
                              "child is duplicated or does not belong to this folder");
        }
        children.push_back(hierarchy_child(child));
    }
    ContentFolder folder;
    folder.parent_nid = request.folder.parent_nid;
    folder.name = request.folder.name;
    folder.properties = request.properties;
    std::set<uint16_t> count_properties;
    for (auto& property : folder.properties) {
        // libpff include/libpff/mapi.h: NUMBER_OF_ASSOCIATED_CONTENT. Regenerate
        // only an existing property; this is not a new mandatory PST property.
        if (property.prop_id == 0x3617 || property.prop_id == 0x6635 ||
            property.prop_id == 0x6636) {
            if (property.source && property.source->size() == 4 && property.value.empty()) {
                property.value.resize(4);
                auto read =
                    property.source->read_at(0, property.value.data(), property.value.size());
                if (!read.ok())
                    return read.error();
                property.source.reset();
            }
            if (!count_properties.insert(property.prop_id).second || property.named ||
                property.absent || property.prop_type != kTypeInteger32 ||
                property.value.size() != 4) {
                return make_error(ErrorKind::kBadField, "writer.folder.count_property",
                                  request.folder.nid, property.prop_id,
                                  "folder count must have a present Integer32 value");
            }
            if (property.prop_id == 0x3617) {
                property.value = le32_bytes(static_cast<uint32_t>(associated.count()));
            } else if (property.value != le32_bytes(0)) {
                // MS-PST 2.4.4.4.1 and 2.5.3.1 specify the counts and their use,
                // but do not establish the item classifier used by this pipeline.
                return make_error(ErrorKind::kUnsupported, "writer.folder.hidden_counts",
                                  request.folder.nid, property.prop_id,
                                  "nonzero hidden counts cannot be regenerated without a proven "
                                  "hidden-item classifier");
            }
        }
    }
    if (request.folder.has_hidden_count != count_properties.contains(0x6635) ||
        request.folder.has_hidden_unread != count_properties.contains(0x6636)) {
        return make_error(ErrorKind::kBadField, "writer.folder.hidden_presence", request.folder.nid,
                          0, "hierarchy summary and folder PC hidden-count presence disagree");
    }
    Builder builder(request.workspace);
    builder.blocks.clear();
    const uint64_t index = ltp::nid_index(request.folder.nid);
    auto built = build_folder(
        folder, request.folder.nid,
        static_cast<uint32_t>(ltp::make_nid(index, ltp::kNidTypeHierarchyTable)),
        static_cast<uint32_t>(ltp::make_nid(index, ltp::kNidTypeContentsTable)),
        static_cast<uint32_t>(ltp::make_nid(index, ltp::kNidTypeAssocContentsTable)), children,
        indices.value(), builder, &normal, &associated, request.folder.unread_count, false);
    if (!built.ok())
        return built.error();
    if (builder.scratch && !builder.scratch->status().ok())
        return builder.scratch->status().error();
    return take_content_plan(builder);
}

Result<ContentPlan> build_scaffold_plan(const std::vector<NamedProperty>& named,
                                        const std::vector<FolderSummary>& root_children,
                                        uint32_t last_folder_index, uint32_t last_message_index,
                                        uint32_t last_associated_index,
                                        std::shared_ptr<util::Workspace> workspace) {
    auto indices = named_indices(named.size());
    if (!indices.ok())
        return indices.error();
    if (last_folder_index < 1027 || last_message_index < 65536 || last_associated_index < 32768 ||
        last_folder_index > ltp::kNidIndexMask || last_message_index > ltp::kNidIndexMask ||
        last_associated_index > ltp::kNidIndexMask) {
        return make_error(ErrorKind::kBadField, "writer.scaffold.rgnid", last_folder_index,
                          last_message_index,
                          "reserved allocation counters are outside their NID range");
    }
    Builder builder(workspace);
    builder.folder_index = last_folder_index;
    builder.message_index = last_message_index;
    builder.report.named_properties = named.size();
    std::map<uint32_t, std::vector<HierarchyChild>> children;
    std::set<uint32_t> seen;
    for (const auto& child : root_children) {
        auto valid = check_folder_summary(child);
        if (!valid.ok())
            return valid.error();
        if (child.parent_nid != kNidIpmsubtree || ltp::nid_index(child.nid) > last_folder_index ||
            !seen.insert(child.nid).second) {
            return make_error(ErrorKind::kBadField, "writer.scaffold.children", child.nid,
                              child.parent_nid,
                              "import roots need distinct reserved identities below IPM_SUBTREE");
        }
        children[child.parent_nid].push_back(hierarchy_child(child));
    }
    return finish_plan(builder, named, children, last_associated_index);
}

} // namespace ost2pst::writer
