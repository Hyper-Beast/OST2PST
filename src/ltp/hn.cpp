#include "ost2pst/ltp/hn.h"

#include <string>

#include "internal/take.h"

namespace ost2pst::ltp {

using util::ByteView;
using util::DataError;
using util::ErrorKind;
using util::make_error;
using util::Result;

const char *client_sig_name(uint8_t client_sig) {
    // [MS-PST] 2.3.1.2: only these values are defined; anything else is reserved.
    switch (client_sig) {
    case kClientSigReserved1:
        return "reserved1";
    case kClientSigTc:
        return "TC";
    case kClientSigReserved2:
        return "reserved2";
    case kClientSigReserved3:
        return "reserved3";
    case kClientSigReserved4:
        return "reserved4";
    case kClientSigReserved5:
        return "reserved5";
    case kClientSigBth:
        return "BTH";
    case kClientSigPc:
        return "PC";
    case kClientSigReserved6:
        return "reserved6";
    default:
        return "unknown";
    }
}

const char *nid_type_name(uint32_t nid_type) {
    // [MS-PST] 2.2.2.1: the table has gaps (0x09, 0x14-0x1E); those are OST client-store types this
    // project names in M3, so they report as "client" rather than as an error.
    switch (nid_type) {
    case kNidTypeHid:
        return "HID";
    case kNidTypeInternal:
        return "INTERNAL";
    case kNidTypeNormalFolder:
        return "NORMAL_FOLDER";
    case kNidTypeSearchFolder:
        return "SEARCH_FOLDER";
    case kNidTypeNormalMessage:
        return "NORMAL_MESSAGE";
    case kNidTypeAttachment:
        return "ATTACHMENT";
    case kNidTypeSearchUpdateQueue:
        return "SEARCH_UPDATE_QUEUE";
    case kNidTypeSearchCriteriaObject:
        return "SEARCH_CRITERIA_OBJECT";
    case kNidTypeAssocMessage:
        return "ASSOC_MESSAGE";
    case kNidTypeContentsTableIndex:
        return "CONTENTS_TABLE_INDEX";
    case kNidTypeReceiveFolderTable:
        return "RECEIVE_FOLDER_TABLE";
    case kNidTypeOutgoingQueueTable:
        return "OUTGOING_QUEUE_TABLE";
    case kNidTypeHierarchyTable:
        return "HIERARCHY_TABLE";
    case kNidTypeContentsTable:
        return "CONTENTS_TABLE";
    case kNidTypeAssocContentsTable:
        return "ASSOC_CONTENTS_TABLE";
    case kNidTypeSearchContentsTable:
        return "SEARCH_CONTENTS_TABLE";
    case kNidTypeAttachmentTable:
        return "ATTACHMENT_TABLE";
    case kNidTypeRecipientTable:
        return "RECIPIENT_TABLE";
    case kNidTypeSearchTableIndex:
        return "SEARCH_TABLE_INDEX";
    case kNidTypeLtp:
        return "LTP";
    default:
        return "client";
    }
}

// [MS-PST] 2.2.2.1 (docs/reference/ms-pst.txt:873-903) marks in parentheses which nidType values are a
// Property Context (0x02 0x03 0x04 0x05 0x08) or a Table Context (0x0D 0x0E 0x0F 0x10 0x11 0x12). Only
// those are announced as heap nodes. 0x0B "Receive Folder object (Inbox)" and 0x0C "Outbound queue
// (Outbox)" are named but nowhere marked as a PC or a TC, so a block with no HNHDR under them is not a
// contradiction of the spec. 0x00 0x01 0x06 0x07 0x0A 0x13 0x1F are named as something else, and 0x09 and
// 0x14-0x1E are not in the table at all.
bool nid_type_announces_heap_node(uint32_t nid_type) {
    switch (nid_type) {
    case kNidTypeNormalFolder:
    case kNidTypeSearchFolder:
    case kNidTypeNormalMessage:
    case kNidTypeAttachment:
    case kNidTypeAssocMessage:
    case kNidTypeHierarchyTable:
    case kNidTypeContentsTable:
    case kNidTypeAssocContentsTable:
    case kNidTypeSearchContentsTable:
    case kNidTypeAttachmentTable:
    case kNidTypeRecipientTable:
        return true;
    default:
        return false;
    }
}

// [MS-PST] 2.4.1 (docs/reference/ms-pst.txt:3142-3166) lists every predefined internal NID. An nidIndex
// the table does not name has no meaning the spec gives it.
const char *predefined_internal_nid_name(uint64_t nid) {
    switch (nid) {
    case kNidMessageStore:
        return "NID_MESSAGE_STORE";
    case kNidNameToIdMap:
        return "NID_NAME_TO_ID_MAP";
    case kNidNormalFolderTemplate:
        return "NID_NORMAL_FOLDER_TEMPLATE";
    case kNidSearchFolderTemplate:
        return "NID_SEARCH_FOLDER_TEMPLATE";
    case kNidRootFolder:
        return "NID_ROOT_FOLDER";
    case kNidSearchManagementQueue:
        return "NID_SEARCH_MANAGEMENT_QUEUE";
    case kNidSearchActivityList:
        return "NID_SEARCH_ACTIVITY_LIST";
    case kNidReserved1:
        return "NID_RESERVED1";
    case kNidSearchDomainObject:
        return "NID_SEARCH_DOMAIN_OBJECT";
    case kNidSearchGathererQueue:
        return "NID_SEARCH_GATHERER_QUEUE";
    case kNidSearchGathererDescriptor:
        return "NID_SEARCH_GATHERER_DESCRIPTOR";
    case kNidReserved2:
        return "NID_RESERVED2";
    case kNidReserved3:
        return "NID_RESERVED3";
    case kNidSearchGathererFolderQueue:
        return "NID_SEARCH_GATHERER_FOLDER_QUEUE";
    default:
        return "";
    }
}

// [MS-PST] 2.4.8.3 says a queue node "contains an array of fixed-size items" (docs/reference/ms-pst.txt
// :4255-4256); 2.4.8.4.1 says the SMQ "uses a basic queue node" (:4292-4293); 2.4.8.4.2 and 2.4.8.4.3 say
// the SAL and the SDO "contain a simple array of NIDs (not a queue)" (:4302-4303, :4307); 2.4.8.5.1 says
// the SGQ "is implemented as a queue node" (:4315-4316), 2.4.8.5.2 that the SGD "contains an opaque,
// variable-size binary BLOB" (:4322-4323), and 2.4.8.5.3 that the SGFQ "contains a simple array of NIDs
// (not a queue)" (:4327-4328). None of those is a heap node, so a data block with no HNHDR under one of
// these NIDs is what the spec says to expect.
const char *documented_non_heap_internal_nid_name(uint64_t nid) {
    switch (nid) {
    case kNidSearchManagementQueue:
        return "NID_SEARCH_MANAGEMENT_QUEUE";
    case kNidSearchActivityList:
        return "NID_SEARCH_ACTIVITY_LIST";
    case kNidSearchDomainObject:
        return "NID_SEARCH_DOMAIN_OBJECT";
    case kNidSearchGathererQueue:
        return "NID_SEARCH_GATHERER_QUEUE";
    case kNidSearchGathererDescriptor:
        return "NID_SEARCH_GATHERER_DESCRIPTOR";
    case kNidSearchGathererFolderQueue:
        return "NID_SEARCH_GATHERER_FOLDER_QUEUE";
    default:
        return "";
    }
}

// [MS-PST] 2.4.3 says "the message store is implemented as a regular PC" (docs/reference/ms-pst.txt:3203);
// 2.4.4.1 is the Folder object PC, 2.4.7 the Name-to-ID Map, and 2.7.3.3 the template objects, each of
// which is a PC with its tables. A data block with no HNHDR under one of these NIDs contradicts the spec.
const char *documented_heap_internal_nid_name(uint64_t nid) {
    switch (nid) {
    case kNidMessageStore:
        return "NID_MESSAGE_STORE";
    case kNidNameToIdMap:
        return "NID_NAME_TO_ID_MAP";
    case kNidNormalFolderTemplate:
        return "NID_NORMAL_FOLDER_TEMPLATE";
    case kNidSearchFolderTemplate:
        return "NID_SEARCH_FOLDER_TEMPLATE";
    case kNidRootFolder:
        return "NID_ROOT_FOLDER";
    default:
        return "";
    }
}

Result<HnHeader> decode_hn_header(ByteView block) {
    if (!block.in_range(0, static_cast<size_t>(kHnHeaderSize))) {
        return make_error(ErrorKind::kTruncated, "HNHDR", block.base(), block.size(),
                          "a heap node starts with a 12-byte HNHDR");
    }
    HnHeader header;
    DataError failure;
    if (!take(block.u16(kHnIbHnpmOffset), header.ib_hnpm, "HNHDR.ibHnpm", failure)) {
        return failure;
    }
    if (!take(block.u8(kHnSigOffset), header.b_sig, "HNHDR.bSig", failure)) {
        return failure;
    }
    if (!take(block.u8(kHnClientSigOffset), header.b_client_sig, "HNHDR.bClientSig", failure)) {
        return failure;
    }
    if (!take(block.u32(kHnUserRootOffset), header.hid_user_root, "HNHDR.hidUserRoot", failure)) {
        return failure;
    }
    if (!take(block.u32(kHnFillLevelOffset), header.rgb_fill_level, "HNHDR.rgbFillLevel", failure)) {
        return failure;
    }
    // [MS-PST] 2.3.1.2: bSig MUST be 0xEC. This is the only thing that says the block is a heap node,
    // so a block that is not one is refused here rather than misread as one.
    if (header.b_sig != kHnSignature) {
        return make_error(ErrorKind::kBadField, "HNHDR.bSig", block.base() + kHnSigOffset,
                          header.b_sig, "a heap node carries 0xEC");
    }
    return header;
}

Result<HnPageMap> decode_hn_page_map(ByteView block, uint64_t ib_hnpm) {
    // [MS-PST] 2.3.1.2: ibHnpm is relative to the HNHDR, which 2.3.1.2 puts at the start of the block,
    // so the map sits at this block offset.
    if (ib_hnpm > block.size()) {
        return make_error(ErrorKind::kBadField, "HNHDR.ibHnpm", block.base() + kHnIbHnpmOffset,
                          ib_hnpm, "the page map is past the end of the HN block");
    }
    const uint64_t map_at = static_cast<size_t>(ib_hnpm);
    if (!block.in_range(map_at, static_cast<size_t>(kHnPageMapHeaderSize))) {
        return make_error(ErrorKind::kTruncated, "HNPAGEMAP", block.base() + map_at,
                          block.size() - map_at, "no room for cAlloc and cFree");
    }

    HnPageMap map;
    map.base = block.base() + map_at;
    DataError failure;
    uint16_t c_alloc = 0;
    if (!take(block.u16(map_at + kHnPageMapCAllocOffset), c_alloc, "HNPAGEMAP.cAlloc", failure)) {
        return failure;
    }
    if (!take(block.u16(map_at + kHnPageMapCFreeOffset), map.c_free, "HNPAGEMAP.cFree", failure)) {
        return failure;
    }
    map.c_alloc = c_alloc;

    // [MS-PST] 2.3.1.5: rgibAlloc holds cAlloc + 1 WORD offsets, each the start of an allocation inside
    // this block, so the only bound on cAlloc is the space the block leaves after the header and the two
    // counts, which is checked against block.size() below. [MS-PST] 2.2.2.8 (docs/reference/ms-pst.txt
    // :1877-1881, :1891-1892) caps a block at 8192 bytes; libpff format notes (see THIRD_PARTY_NOTICES.txt):1102-1106
    // calls 8 x 8192 = 65536 the "likely maximum" for the 64-bit 4k page profile, and this OST measures
    // 65,512 data bytes in its fullest block. The reader used to cap cAlloc at 8192, which is neither of
    // those, and refused page maps whose rgibAlloc fits the block that carries them
    // (DEVELOPMENT.md).
    // [MS-PST] 2.3.1.5 states no minimum for cAlloc: it is the allocation count, and rgibAlloc holds
    // cAlloc + 1 entries "to mark the offset of the next available slot". cAlloc 0 is an empty allocation
    // table whose single entry is that next free slot. The sample has 26 such blocks inside multi-block
    // heaps, each with rgibAlloc[0] == ibHnpm, the shape 2.3.1.5 gives a block that holds no items
    // (DEVELOPMENT.md).
    const uint64_t table_bytes =
        static_cast<uint64_t>(c_alloc + 1) * kHnPageMapEntrySize;
    if (block.size() - map_at < kHnPageMapHeaderSize + table_bytes) {
        return make_error(ErrorKind::kTruncated, "HNPAGEMAP.rgibAlloc",
                          map.base + kHnPageMapHeaderSize, table_bytes,
                          "the offset table runs past the end of the HN block");
    }

    map.offsets.reserve(c_alloc + 1);
    for (uint16_t index = 0; index <= c_alloc; ++index) {
        uint16_t offset = 0;
        const uint64_t at = map_at + kHnPageMapHeaderSize + index * kHnPageMapEntrySize;
        if (!take(block.u16(at), offset, "HNPAGEMAP.rgibAlloc", failure)) {
            return failure;
        }
        // [MS-PST] 2.3.1.5: each entry is the start of the next allocation, so the table cannot go
        // backwards and cannot point outside the block it belongs to.
        if (offset > block.size()) {
            return make_error(ErrorKind::kBadField, "HNPAGEMAP.rgibAlloc", block.base() + at, offset,
                              "offset is past the end of the HN block");
        }
        if (!map.offsets.empty() && offset < map.offsets.back()) {
            return make_error(ErrorKind::kBadField, "HNPAGEMAP.rgibAlloc", block.base() + at, offset,
                              "allocations are not in ascending order");
        }
        map.offsets.push_back(offset);
    }
    return map;
}

Result<ByteView> hn_allocation(const HnPageMap &map, ByteView block, uint64_t index) {
    if (index < 1 || index > map.c_alloc) {
        return make_error(ErrorKind::kBadField, "HNPAGEMAP.cAlloc", map.base, index,
                          "allocation index is outside 1 .. cAlloc");
    }
    // [MS-PST] 2.3.1.1: hidIndex is 1-based, and 2.3.1.5 makes allocation n the window
    // [rgibAlloc[n-1], rgibAlloc[n]).
    const uint64_t start = map.offsets[index - 1];
    const uint64_t end = map.offsets[index];
    if (end <= start || end > block.size()) {
        return make_error(ErrorKind::kBadField, "HNPAGEMAP.rgibAlloc", map.base, end,
                          "allocation " + std::to_string(index) + " is empty or runs past the block");
    }
    Result<ByteView> window = block.sub(start, static_cast<size_t>(end - start));
    if (!window.ok()) {
        return window.error();
    }
    return window.value();
}

Result<ByteView> hn_heap_item(const HnPageMap &map, ByteView block, uint32_t hid,
                              ndb::FileProfile profile) {
    if (!hid_is_valid(hid, profile)) {
        return make_error(ErrorKind::kBadField, "HID", map.base, hid,
                          "a heap id carries hidType 0 and a non-zero hidIndex");
    }
    return hn_allocation(map, block, hid_index(hid, profile));
}

} // namespace ost2pst::ltp
