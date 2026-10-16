// One folder's worth of source content, reduced to values the writer can emit: the folder's own
// Property Context, its Message objects with their Recipient Table and Attachment Table rows, and
// the Attachment objects those rows name. Everything here is what the source actually held; a value
// the reader could not get is reported as such instead of being left out silently.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "ost2pst/ltp/ltp_read.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/status.h"
#include "ost2pst/util/value_spool.h"

namespace ost2pst::msg {

// One property value as the source held it. `bytes` is what the reader obtained; `declared_bytes`
// is what the source's own metadata claims (PidTagMessageSize, PidTagAttachSize), kept apart
// because a declared size is not content.
struct SubsetValue {
    uint32_t tag = 0;
    uint16_t prop_id = 0;
    uint16_t prop_type = 0;
    bool readable = false;
    std::vector<uint8_t> bytes;
    uint64_t declared_bytes = 0;
    std::string reason; // why it is not readable, when it is not
    bool absent =
        false; // dwValueHnid 0: the property is present and has no value ([MS-PST] 2.3.3.2)
    bool writer_assigned = false; // the writer regenerates object EntryIDs and table row id/ver, so
                                  // they are not copied

    // [MS-PST] 2.3.3.5: a PtypObject value is an 8-byte allocation holding Nid, the subnode that
    // carries the object, then ulSize, "the total size of the object". The object is content the
    // source has; what this reader made of it is answered below, not by `bytes`.
    bool object_named = false;   // the value is a PtypObject that named a subnode
    uint32_t object_nid = 0;     // the Nid it names
    uint64_t object_ul_size = 0; // the ulSize the source states for it

    // [MS-PST] 2.4.7.1: an NPID names a property set plus a string or numeric name, and only the
    // source's Name-to-ID Map says which. The writer re-registers that identity under a new NPID.
    bool named = false;
    bool name_resolved =
        false; // the identity has a name: a numeric name is always known ([MS-PST] 2.4.7.1)
    bool name_is_string = false;
    std::u16string name;
    uint32_t numeric_name = 0;
    uint16_t guid_index = 0;
    bool guid_resolved = false;
    std::vector<uint8_t> guid;
    util::SharedBytes source;
    uint64_t byte_count() const { return source ? source->size() : bytes.size(); }
};

struct SubsetRecipient {
    uint32_t row_id = 0; // the Recipient Table row's dwRowID ([MS-PST] 2.3.4.3)
    std::vector<SubsetValue> values;
    std::string note;
};

struct SubsetAttachment; // declared first so a Message can hold the attachments its table names

struct SubsetMessage {
    uint64_t nid = 0;
    bool pc_read = false;
    std::vector<SubsetValue> values;
    bool recipient_table = false;
    bool recipient_table_read = false;
    std::vector<SubsetRecipient> recipients;
    // Schema entries carry tag/type and named identity only, independently of rows/CEB.
    // They are not values and do not contribute to the readable/unreadable value counters.
    std::vector<SubsetValue> recipient_columns;
    std::vector<SubsetValue> attachment_columns;
    bool attachment_table = false;
    bool attachment_table_read = false;
    std::vector<SubsetAttachment> attachments;
    uint64_t subnode_entries = 0;
    bool subnodes_complete = false; // the subnode list was enumerated to the end
    uint32_t embedded_depth =
        0; // 0 for a Message the NBT names, 1+ for one reached through an attachment
    std::string note;
};

struct SubsetAttachment {
    uint32_t row_id =
        0; // [MS-PST] 2.4.6.1.3: the row's dwRowID IS the Attachment object's subnode NID
    uint64_t subnode_nid = 0;
    bool pc_read = false;
    std::vector<SubsetValue> values;
    std::vector<SubsetValue>
        row_values; // the Attachment Table row's own cells, kept so they can be compared
                    // against the object they name instead of only believed
    bool payload_read = false;
    uint64_t payload_bytes = 0;  // the 0x3701 bytes actually read
    uint64_t declared_bytes = 0; // 0x0E20 as the source states it
    // [MS-PST] 2.4.6.2.2: an attachment that is itself a Message object carries its content as a
    // PtypObject ([MS-PST] 2.3.3.5) naming that Message subnode of the Attachment object.
    // `embedded` is what this reader read out of the subnode the object names; `object_ul_size` is
    // what the source states the object's total size to be.
    bool object_form = false;
    uint32_t object_nid = 0;
    uint64_t object_ul_size = 0;
    // Method-6 object data is carried without interpreting its bytes (MS-PST 2.3.3.5;
    // libpff attachment sub-item). It is distinct from an attached Message.
    bool object_data_read = false;
    std::vector<uint8_t> object_data;
    util::SharedBytes object_source;
    bool embedded_read = false;
    uint64_t embedded_nid = 0;
    SubsetMessage embedded;
    std::string note;
};

struct SubsetFolder {
    uint64_t nid = 0;
    bool pc_read = false;
    std::string name;
    std::vector<SubsetValue> values;
    std::string note;
};

struct SubsetOptions {
    // The Row Matrix of a Contents Table written with the M4 template is 126 bytes per row, and one
    // data block holds 8,176 raw bytes, so 64 messages is the count that keeps the matrix in a
    // single block
    // (DEVELOPMENT.md section 7).
    uint64_t max_messages = 64;
    bool collect_payloads = true;
    uint64_t max_notes = 20; // how many per-item notes the report keeps before it only counts them
    // [MS-PST] 2.4.6.2.2 puts an attached Message under the Attachment object that names it, so
    // reading one is a walk down. A walk that stops at this depth is reported as incomplete, not as
    // a folder with fewer attachments.
    uint32_t max_embedded_depth = 4;
    util::ValueSpool* spool = nullptr; // optional one-item owner; legacy adapters retain vectors
    // Cumulative metadata/HN/matrix reservations when spooling; payload budget is separate.
    // Charged on demand, including conservative construction/copy multipliers. A whole
    // embedded-message tree shares this ceiling; this is neither preallocation nor RSS.
    uint64_t workspace_budget = 512ull * 1024 * 1024;
};

struct SubsetReport {
    SubsetFolder folder;
    uint64_t folder_children = 0; // NBT entries naming this folder as their nidParent
    uint64_t messages_read = 0;
    uint64_t messages_skipped = 0; // past the cap, or with no readable PC
    uint64_t recipients_read = 0;
    uint64_t attachments_read = 0;
    uint64_t attachments_without_payload = 0;
    uint64_t attachments_embedded =
        0; // Attachment objects whose 0x3701 object was read as a Message
    uint64_t attachments_opaque = 0;
    uint64_t attachments_with_unread_object =
        0; // ... and ones whose object this reader could not carry
    uint64_t payload_bytes = 0;
    uint64_t max_payload_bytes =
        0;                   // the largest single payload: decides whether one XBLOCK suffices
    uint64_t body_plain = 0; // 0x1000 PidTagBody
    uint64_t body_html = 0;  // 0x1013 PidTagHtml
    uint64_t body_rtf = 0;   // 0x1009: measured in this sample, named by neither opened reference
    uint64_t body_none = 0;
    uint64_t named_tags = 0;       // distinct named property identities carried
    uint64_t named_unresolved = 0; // named tags whose name the map could not give: no entry at all,
                                   // or an N == 1 offset no String Stream name starts at
    uint64_t unreadable_values = 0; // values the reader could not obtain the content of
    uint64_t object_values = 0;     // PtypObject records whose 8-byte allocation the reader read
                                    // ([MS-PST] 2.3.3.5); they are not byte values
    uint64_t object_values_carried = 0; // ... carried as an attached Message or opaque object data
    uint64_t values_read = 0;           // values whose bytes the extractor holds
    uint64_t values_absent = 0;         // records present with no value ([MS-PST] 2.3.3.2)
    uint64_t required_missing = 0; // [MS-PST] 2.4.5.1.1 required tags a Message PC does not carry
    // [MS-PST] 2.4.5 marks the Recipient Table Required: Y for a Message object, and 2.4.6.1 makes
    // the Attachment Table optional, so a folder says which of the two its messages actually carry.
    uint64_t messages_with_recipient_table = 0;
    uint64_t messages_without_recipient_table = 0;
    uint64_t messages_with_attachment_table = 0;
    uint64_t rows_without_cells = 0; // a RowIndex row whose Row Matrix slot was out of range
    // Extraction state the source's own shape cannot explain: a Property Context, a table or a
    // subnode walk the source had and this reader could not finish. They are counted apart from the
    // totals above, which say what the source does not have, because a failed read must not turn
    // into a clean conversion.
    uint64_t messages_without_pc = 0; // a Message object whose own Property Context did not read
    uint64_t recipient_table_failures = 0;  // a Recipient Table subnode whose rows did not read
    uint64_t attachment_table_failures = 0; // ... or an Attachment Table
    uint64_t attachment_pc_failures =
        0; // an Attachment object that did not open as a Property Context
    uint64_t subnode_walk_failures = 0;      // a Message object's subnode BTree that did not walk
    uint64_t subnode_walks_incomplete = 0;   // ... or stopped before it enumerated every entry
    uint64_t row_index_walks_incomplete = 0; // a table RowIndex walk that stopped before the end
    uint64_t matrix_short_blocks = 0; // Row Matrix blocks short of a full block ([MS-PST] 2.3.4.4)
    std::vector<SubsetMessage> messages;
    std::vector<std::string> skipped; // "<NID>: <reason>"
    std::vector<std::string> notes;
    bool capped = false; // the message cap stopped the folder short
    std::optional<util::DataError> fatal_io;
    std::optional<util::DataError> workspace_error;
    bool unsupported_values = false;
};

// Reads one folder's content through the ltp seams. The NID map answers which Message objects name
// this folder as their nidParent ([MS-PST] 2.4.5.2), which is the enumeration that works even when
// the folder's contents table holds no rows -- what most folders of a real OST look like.
util::Result<SubsetReport> build_subset(const ltp::LtpReadReport& census, ltp::BlockSource& blocks,
                                        uint64_t folder_nid, const SubsetOptions& options);

// Reuses an already validated census. No folder enumeration or shared-index rebuild occurs
// during an item read; the returned report contains exactly one normal/FAI top-level item.
// A partial read stays in the report so the caller can commit an honest terminal failure.
util::Result<SubsetReport> extract_item(const ltp::LtpReadReport& census, ltp::BlockSource& blocks,
                                        uint64_t item_nid, const SubsetOptions& options);
util::Result<SubsetReport> extract_folder(const ltp::LtpReadReport& census,
                                          ltp::BlockSource& blocks, uint64_t folder_nid,
                                          const SubsetOptions& options);

} // namespace ost2pst::msg
