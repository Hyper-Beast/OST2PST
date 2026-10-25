// The content-bearing store: the minimum mailbox of [MS-PST] 2.7.3 plus the folders, messages,
// recipient and attachment tables, attachment objects and named properties a caller hands over.
// The writer receives already-parsed values and never opens a source file
// (DEVELOPMENT.md).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "ost2pst/util/status.h"
#include "ost2pst/writer/store.h"
#include "ost2pst/writer/tc.h"

namespace ost2pst::writer {

// The NID of the IPM_SUBTREE folder the minimum mailbox emits ([MS-PST] 2.7.3.1 lists IPM_SUBTREE
// as a folder every PST has; the NID is the allocation this writer made for it, matching the M4
// candidate).
constexpr uint32_t kNidIpmsubtree =
    0x8022; // [MS-PST] 2.7.3.1: IPM_SUBTREE, allocated by this writer

// One named property identity to re-register ([MS-PST] 2.4.7.1: a named property is a (GUID, name)
// pair, and the NPID of a PST is only an index into that PST's own Name-to-ID Map, so a source NPID
// never carries over).
struct NamedProperty {
    std::u16string name;        // the string name when N == 1
    bool name_is_string = true; // [MS-PST] 2.4.7.1: the N bit decides whether the name is a string
    uint32_t numeric_name = 0;  // the name itself when N == 0
    // The 16 property-set GUID bytes. Empty means NAMEID_GUID_NONE ([MS-PST] 2.4.7.1 wGuid 0).
    std::vector<uint8_t> guid;
};

// One property value the writer puts into a Folder, Message or Attachment object PC.
struct ContentProperty {
    uint16_t prop_id = 0;   // a property id, or an NPID (0x8000 .. 0x8FFF) when `named` is set
    uint16_t prop_type = 0; // [MS-OXCDATA] 2.11.1 property type id
    std::vector<uint8_t> value;
    bool absent = false;      // present with no value: dwValueHnid 0 ([MS-PST] 2.3.3.2)
    bool named = false;       // re-registered under a new NPID taken from named_index
    uint64_t named_index = 0; // index into StoreRequest::named_properties
    util::SharedBytes source;
};

// One cell of a table row, named by its property tag so the writer can place it in whichever column
// list it ends up emitting ([MS-PST] 2.3.4.4.2).
struct ContentCell {
    uint32_t tag = 0;
    std::vector<uint8_t> value;
    bool absent = false; // CEB set, HNID 0: the cell exists and has no value ([MS-PST] 2.3.4.4)
    util::SharedBytes source;
};

// One row. row_id is informational only: the writer assigns the dwRowID of every row it emits
// ([MS-PST] 2.3.4.3.1 leaves the key to the implementation, 2.4.4.4.1 and 2.4.6.1.3 make it a NID).
struct ContentRow {
    uint32_t row_id = 0;
    std::vector<ContentCell> cells;
};

// The tag keys source cells; named_index selects the same identity registry used by PCs.
// The writer remaps the column and all its cells together ([MS-PST] 2.4.7.1).
struct ContentColumn {
    ContentColumn(uint32_t tag = 0, bool named = false, uint64_t named_index = 0)
        : tag(tag), named(named), named_index(named_index) {}
    uint32_t tag;
    bool named;
    uint64_t named_index;
};

// A table the writer has to emit: source columns with identities, and the rows to carry over.
struct ContentTable {
    std::vector<ContentColumn> columns;
    std::vector<ContentRow> rows;
};

struct ContentAttachment; // declared first so a Message can name the Attachment objects its table
                          // rows stand for

// One Message object: its PC, its Recipient Table rows, its Attachment Table rows, and the
// Attachment objects those rows name, in the same order as the rows ([MS-PST] 2.4.6.1.3, 2.4.6.2).
struct ContentMessage {
    std::vector<ContentProperty> properties;
    ContentTable recipients;
    ContentTable attachments;
    std::vector<ContentAttachment> attachment_objects;
};

// One Attachment object: its own PC values plus the 0x3701 bytes the writer re-emits as PtypBinary.
// An attachment that is itself a Message object instead carries that Message, and the writer writes
// 0x3701 as the PtypObject that names it ([MS-PST] 2.4.6.2.2, 2.3.3.5).
struct ContentAttachment {
    std::vector<ContentProperty> properties;
    std::vector<uint8_t> payload;
    bool has_payload = false;
    bool has_object_payload =
        false;               // payload bytes belong to a method-6 PtypObject (MS-PST 2.3.3.5)
    ContentMessage embedded; // the attached Message object, when has_embedded
    bool has_embedded = false;
    uint64_t embedded_ul_size = 0; // the ulSize the source stated for the object ([MS-PST] 2.3.3.5)
    util::SharedBytes payload_source;
};

// One Folder object: its parent, its name, its own PC values, and its messages.
struct ContentFolder {
    uint32_t parent_nid = 0;
    std::u16string name;
    std::vector<ContentProperty> properties;
    std::vector<ContentMessage> messages;
};

struct StoreRequest {
    std::vector<NamedProperty> named_properties; // the identities to re-register, in NPID order
    std::vector<ContentFolder> folders;
};

// What the content build did, so a caller can report it and a test can assert it.
struct ContentReport {
    uint64_t folders = 0;
    uint64_t messages = 0;
    uint64_t recipients = 0;
    uint64_t attachments = 0;
    uint64_t attachment_bytes = 0;
    uint64_t embedded_messages =
        0; // Attachment objects that carried a Message of their own ([MS-PST] 2.4.6.2.2)
    uint64_t opaque_objects = 0;
    uint64_t embedded_bytes = 0;   // the data blocks the writer laid down under those subnodes
    uint64_t named_properties = 0; // entries the Name-to-ID Map re-registered
    uint64_t values_written = 0;   // property values the writer put into the file
    uint64_t values_dropped = 0;   // values it could not carry, each with a note
    uint64_t required_missing = 0; // [MS-PST] 2.4.5.1.1 tags it had to synthesize or could not give
    uint64_t blocks = 0;
    uint64_t file_bytes = 0;
    std::vector<uint32_t> folder_nids;
    std::vector<std::string> notes;
};

// The file image plus the report of what went into it.
struct StoreOutcome {
    StoreImage image;
    ContentReport report;
};

// Local block numbers are relocated when the plan is appended to durable staging. No
// file image is allocated. Item, folder and scaffold plans can be released independently.
struct ContentPlan {
    StorePlan plan;
    ContentReport report;
};

struct ItemPlan {
    ContentPlan content;
    TcRow row; // normal Contents or FAI Contents schema, selected by the output NID type
    bool read_state_known = false;
    bool unread = false;
};

struct FolderSummary {
    uint32_t nid = 0;
    uint32_t parent_nid = 0;
    std::u16string name;
    uint32_t content_count = 0;
    uint32_t unread_count = 0;
    bool has_subfolders = false;
    bool has_hidden_count = false; // zero-valued source field, copied into hierarchy rows
    bool has_hidden_unread = false;
};

struct FolderPlanRequest {
    std::shared_ptr<util::Workspace> workspace;
    FolderSummary folder;
    std::vector<ContentProperty> properties;
    std::vector<FolderSummary> children;
    const TcRowSource* normal_rows = nullptr;
    const TcRowSource* associated_rows = nullptr;
};

// Output NIDs are reserved by the conversion manifest before extraction. Named indices
// use the same fixed registry for all plans; the scaffold carries the registry itself.
util::Result<ItemPlan> build_item_plan(const ContentMessage& message, uint32_t nid,
                                       uint32_t parent_nid, uint64_t named_count,
                                       std::shared_ptr<util::Workspace> workspace = {});
util::Result<ContentPlan> build_folder_plan(const FolderPlanRequest& request, uint64_t named_count);
util::Result<ContentPlan> build_scaffold_plan(const std::vector<NamedProperty>& named,
                                              const std::vector<FolderSummary>& root_children,
                                              uint32_t last_folder_index,
                                              uint32_t last_message_index,
                                              uint32_t last_associated_index,
                                              std::shared_ptr<util::Workspace> workspace = {});

// Builds the whole store: the minimum mailbox exactly as build_empty_pst emitted it, plus the
// content of the request. With an empty request the image is byte-for-byte the M4 candidate.
util::Result<StoreOutcome> build_store(const StoreRequest& request);

} // namespace ost2pst::writer
