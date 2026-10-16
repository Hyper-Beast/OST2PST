#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "ost2pst/ltp/data_tree.h"
#include "ost2pst/ltp/ltp_read.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/msg/node_class.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/status.h"

namespace ost2pst::msg {

// M3: what the source actually holds, counted from the node set the LTP layer already indexed, so the
// converter writes from a measured inventory instead of from a guess about what a mailbox looks like.
//
// Everything here is built through ltp's public seams (NidMap, BlockSource, open_node, read_pc, read_tc,
// walk_tc_row_index) and the subnode BTree decoders in nid_map.h. The Messaging layer does not read the
// file itself and does not re-walk the NBT: one walk of report.nodes is the same node set the LTP census
// classified.
struct InventoryOptions {
    // How many Message objects the inventory may scan. A cap makes a partial run explicit; it never
    // silently truncates, because the report says which cap stopped it.
    uint64_t max_messages = 1000000;
    uint64_t max_associated = 1000000;
    // [MS-PST] 2.4.5.2: a Message object's nidParent is its parent Folder object. The hop cap only stops a
    // nidParent cycle from spinning; a real chain is a handful of hops.
    uint64_t max_parent_hops = 16;
    // [MS-PST] 2.4.6.2.2: an attachment that is itself a message is a subnode of the Attachment object, so
    // reaching it means recursing message -> attachment -> message. A mailbox can nest, and a malformed one
    // can point an attached message back at something already on the path, so the recursion has limits of
    // its own. They are work limits, not claims about the format.
    uint64_t max_embedded = 1000000;
    uint32_t max_embedded_depth = 8;
    // Named attachment samples so the enumeration can be checked item by item against an independent
    // reader, not only by totals.
    bool collect_samples = true;
    // ... and one row per Attachment object this run opened, in the columns the M3 cross-layer join
    // uses (message NID, attachment subnode NID, 0x0E20, 0x3705, whether 0x3704 is present, full
    // message/attachment ancestry). Off by default: it is the evidence a comparison needs, not
    // something the converter writes.
    bool collect_rows = false;
    size_t max_samples = 40;
    size_t max_notes = 20;
};

// One nidType as the source contains it, classified by node_class.h. `nodes` counts NBT entries;
// `subnode_entries` counts SLENTRY entries under a Message object's bidSub. The two are different
// populations and the report never adds them together: an Attachment object exists only as a subnode in
// the sample, so 0x05 has no NBT entry at all.
struct NodeClassCount {
    uint32_t nid_type = 0;
    NodeDisposition disposition = NodeDisposition::kUnknown;
    std::string ms_pst_name;
    std::string libpff_label;
    std::string reason;
    uint64_t nodes = 0;
    uint64_t subnode_entries = 0;
    // What the inventory did with them: opened the data block, got the shape the type announces (a Property
    // Context for a Message/Folder/Attachment object, a Table Context for a table type), or did not. Every
    // node of that nidType this run opened counts here, whether the NBT named it or an Attachment object's
    // PtypObject did ([MS-PST] 2.4.6.2.2); `nodes` stays the NBT population alone.
    uint64_t opened = 0;
    uint64_t read = 0;
    uint64_t not_read = 0;
};

// One folder, attributed the way [MS-PST] 2.4.5.2 attributes an item: by the nidParent chain, which is the
// count that still adds up when a folder's Contents Table carries no rows.
struct FolderCounts {
    uint64_t nid = 0;
    uint64_t parent = 0;
    uint32_t depth = 0;
    std::string name;      // PidTagDisplayName from the folder's own PC, when the LTP report resolved it
    bool name_present = false;
    uint64_t messages = 0;
    uint64_t associated = 0;
    uint64_t attachments = 0;
    uint64_t attachment_bytes = 0;
    uint64_t children = 0;   // rows of the folder's Hierarchy Table ([MS-PST] 2.4.4.4)
    uint64_t contents_rows = 0; // rows of its Contents Table ([MS-PST] 2.4.4.5)
    uint64_t associated_rows = 0; // rows of its FAI Contents Table ([MS-PST] 2.4.4.6)
    bool attributed = false; // at least one item reached this folder through its nidParent chain
};

// What one content question about one item actually yielded. [MS-PST] 2.3.3.2 / 2.3.3.3 give a PC value four
// shapes -- inline in dwValueHnid, a heap allocation of this node, one of its subnodes, or dwValueHnid 0,
// which is neither a HID nor a subnode NID and therefore no value at all -- and the record itself can be
// missing. The libpff notes show a real file answering these differently: an attachment whose data object
// value is empty while its 0x0E20 says 206, and an ATTACH_BY_VALUE attachment with a size and no data
// object at all (libpff format notes (see THIRD_PARTY_NOTICES.txt):2511-2519). Collapsing the classes is what let "the
// source has no body" stand in for "the reader got nothing".
enum class ContentStatus : uint8_t {
    kReadable,    // the value was found and its bytes read
    kEmpty,       // a record with dwValueHnid 0: the source says this content is empty
    kNotPresent,  // no record for the tag: the source does not carry this content
    kUnreadable,  // the record names a value this reader could not get (bad HNID, missing subnode)
    kUnsupported, // the value read but is in a form this reader does not decode (PtypObject, LZFu)
    kUnknown,     // the item's own Property Context did not read, so its content is unknown
};

// One count per status for one content question, plus the bytes that actually read. The 0x0E20 a source
// declares for an attachment ([MS-PST] 2.4.6.2.1, docs/reference/ms-pst.txt:3802) is not one of these
// numbers: it is what the source says the size is, and the libpff notes show it disagreeing with what the
// file holds.
struct ContentCounts {
    uint64_t readable = 0;
    uint64_t empty = 0;
    uint64_t not_present = 0;
    uint64_t unreadable = 0;
    uint64_t unsupported = 0;
    // ... split by the only two forms this reader can name without guessing: a PtypObject value naming a
    // subnode ([MS-PST] 2.3.3.5, docs/reference/ms-pst.txt:2771-2786) and a value carrying the "LZFu"
    // signature the libpff notes give for compressed RTF (libpff format notes (see THIRD_PARTY_NOTICES.txt):2638-2649).
    // These are sub-counts of `unsupported`, not extra items.
    uint64_t unsupported_object = 0;
    uint64_t unsupported_compressed = 0;
    uint64_t unknown = 0;
    uint64_t bytes_read = 0; // bytes obtained for the readable ones, never a declared size; for a body,
                             // the strongest of the three forms rather than the three summed
};

// Message objects and FAI entries share everything [MS-PST] 2.4.5 says about a Message object; 2.4.4.6 is
// only about which table they are listed in. They are counted separately because the sample's two
// populations differ in every one of these numbers.
struct MessageStats {
    uint64_t nodes = 0;             // NBT entries of this nidType
    uint64_t stopped_early = 0;     // nodes left unscanned because a cap was reached
    uint64_t pcs_read = 0;    // Property Contexts whose records actually read
    uint64_t pcs_failed = 0;  // bidData 0, or a node that is not a PC, or a PC whose records did not read
    uint64_t pc_decode_failed = 0; // ... the ones that announced a PC and contradicted it
    uint64_t pc_records = 0;
    // Tag presence only -- a record counts here whatever its value turned out to be. `body` below is the
    // content verdict, and the two are not the same number.
    uint64_t with_body = 0;         // 0x1000 PidTagBody ([MS-PST] 2.4.5.1.1, 3.x example ms-pst.txt:8087)
    uint64_t with_html = 0;         // 0x1013 PidTagHtml (ms-pst.txt:8093)
    uint64_t with_rtf = 0;          // 0x1009: measured in this sample, unnamed in both opened references
    uint64_t with_no_body_form = 0; // no record for any of the three tags
    // ... and what the body of each item actually yielded, one verdict per item, decided by the strongest
    // evidence among those tags. A record with dwValueHnid 0 is an empty body, not a body; a value this
    // reader could not get is not "the source has no body" either.
    ContentCounts body;
    uint64_t without_subnode = 0;   // bidSub 0
    uint64_t with_subnodes = 0;
    uint64_t with_bad_subnodes = 0; // bidSub named a block that could not be read
    uint64_t subnode_entries = 0;
    uint64_t max_subnodes = 0;
    uint64_t si_hops = 0;           // SIBLOCK hops taken to reach SLBLOCKs ([MS-PST] 2.2.2.8.3.3.2)
    uint64_t subnode_blocks_read = 0;
    uint64_t subnode_blocks_compressed = 0;
    uint64_t subnode_blocks_bad = 0;
    // What stopped a walk short of the whole tree. Each class names a different reason, and none of them
    // may be reported as "this message has no subnodes".
    uint64_t subnode_entries_past_block = 0; // rgentries the block cannot hold
    uint64_t subnode_entries_bad = 0;        // SLENTRY / SIENTRY records that did not decode
    uint64_t subnode_cycles = 0;             // a SIBLOCK chain that revisits the same block
    uint64_t subnode_walks_capped = 0;       // walks the depth or entry cap stopped
    uint64_t subnode_walks_incomplete = 0;   // messages whose subnode list is not the whole list
    uint64_t without_recipient_table = 0; // [MS-PST] 2.4.5 marks the Recipient Table Required: Y
    uint64_t attachment_tables = 0;
    uint64_t attachment_tables_read = 0;
    uint64_t attachment_tables_not_read = 0;
    uint64_t recipient_tables = 0;
    uint64_t recipient_tables_read = 0;
    uint64_t recipient_tables_not_read = 0;
    uint64_t recipient_rows = 0;
    uint64_t recipient_rows_skipped = 0;
    uint64_t recipient_tables_stopped_early = 0;
    // A table whose RowIndex BTH did not walk at all. Its rows are not counted, so a failed walk can never
    // look like a table with fewer rows.
    uint64_t attachment_tables_row_index_failed = 0;
    uint64_t recipient_tables_row_index_failed = 0;
    std::map<uint32_t, uint64_t> subnode_types; // nidType -> SLENTRY entries
    std::map<std::string, uint64_t> subnode_failure_reasons;
};

// The Attachment Table and the Attachment objects its rows name ([MS-PST] 2.4.6.1 / 2.4.6.1.3 / 2.4.6.2.1).
struct AttachmentStats {
    uint64_t tables = 0;
    uint64_t tables_read = 0;
    uint64_t tables_not_read = 0;
    uint64_t rows = 0;              // rows of the RowIndex walks that completed
    uint64_t rows_skipped = 0;      // RowIndex records the BTH walk had to skip
    uint64_t tables_stopped_early = 0;
    uint64_t tables_row_index_failed = 0; // tables whose RowIndex BTH did not walk, rows not counted
    uint64_t rows_resolved = 0;     // rows whose dwRowID named a subnode that is actually there
    uint64_t rows_unresolved = 0;   // ... and rows that did not
    uint64_t nodes_opened = 0;
    uint64_t nodes_no_pc = 0;
    uint64_t pc_decode_failed = 0; // Attachment object PCs whose records did not read: nothing is known
    uint64_t with_size = 0;         // 0x0E20 PidTagAttachSize, inline
    uint64_t without_size = 0;      // no 0x0E20 record at all
    uint64_t size_value_absent = 0; // 0x0E20 present with dwValueHnid 0
    uint64_t size_not_inline = 0;   // 0x0E20 present but not a 4-byte inline value
    uint64_t method_not_inline = 0;
    uint64_t with_filename = 0;     // 0x3704 PidTagAttachFilenameW
    uint64_t with_method = 0;       // 0x3705 PidTagAttachMethod
    uint64_t without_method = 0;
    uint64_t with_rendering = 0;    // 0x370B PidTagRenderingPosition
    uint64_t without_rendering = 0;
    uint64_t declared_size_bytes = 0; // sum of the 0x0E20 values: what the source declares, not what it holds
    // What each Attachment object's payload yielded: 0x3701, the attachment data object the libpff notes name
    // (libpff format notes (see THIRD_PARTY_NOTICES.txt):2491-2509); [MS-PST] 2.4.6.2.2 names the properties that hold an
    // attachment's content without giving their tag numbers (docs/reference/ms-pst.txt:3813-3817).
    ContentCounts payload;
    // The 0x3701 values whose PtypObject names a subnode ([MS-PST] 2.3.3.5), split by what that
    // subnode turned out to be. [MS-PST] 2.4.6.2.2 says an attachment that is itself a message
    // stores its data in such a subnode -- a fully formed Message object that is not in the NBT and
    // has no parent folder -- and the libpff notes tie attachment method 0x05 and 0x06 to the
    // Embedded Object type, one holding an embedded item and the other possibly an OLE2 document
    // (libpff format notes (see THIRD_PARTY_NOTICES.txt):2505-2508). Method 5 requires a Message PC. Other methods
    // remain undecoded; their PC shape cannot override the declared method. A contradictory
    // method-5 target also records a decode failure.
    uint64_t data_objects = 0;
    uint64_t data_objects_scanned = 0;    // ... opened as a Property Context and scanned as a message
    uint64_t data_objects_not_messages = 0; // ... did not: an object this reader does not decode
    // ... of which these declare a nonzero 0x0E20 and carry no payload or an empty one. [MS-PST] 2.4.6.2.1
    // requires the size while 2.4.6.2.2 says only that the content, if any, is in the data object
    // (docs/reference/ms-pst.txt:3797-3817).
    uint64_t declared_size_without_payload = 0;
    uint64_t subnode_entries = 0;   // 0x05 SLENTRY entries the subnode BTree holds
    uint64_t subnodes_not_named = 0; // ... that no Attachment Table row named
    // ... and the ones no verdict could be given on, because the Attachment Table that should have named
    // them did not walk. Calling those "not named" would blame the source for the reader's own failure.
    uint64_t subnodes_naming_unchecked = 0;
    std::map<uint32_t, uint64_t> methods; // 0x3705 value distribution
    std::vector<std::string> samples;
    // Filled only when InventoryOptions::collect_rows is set: one `ATT` row per Attachment object this run
    // resolved from an Attachment Table row, whatever depth its message was reached at. (`rows` above is
    // the row count, so this one is named for what it is: the dump.)
    std::vector<std::string> row_dump;
};

// What the source does not contain. Every line here is a count of items that are absent, never a value
// invented to fill the gap.
struct CompletenessReport {
    uint64_t messages_without_body_form = 0;
    uint64_t messages_without_subnode = 0;
    uint64_t messages_without_recipient_table = 0;
    uint64_t attachments_without_size = 0;
    uint64_t attachments_without_method = 0;
    uint64_t attachments_without_rendering = 0;
    uint64_t attachment_rows_unresolved = 0;
    uint64_t attachment_subnodes_unnamed = 0;
    // Content a record named and this reader could not get, kept apart from content the source lacks.
    uint64_t messages_with_unreadable_body = 0;
    uint64_t attachments_with_unreadable_payload = 0;
    // An attachment that declares a size and holds no payload. [MS-PST] 2.4.6.2.1 requires 0x0E20 while
    // 2.4.6.2.2 says only that the content "if any" is in the data object (ms-pst.txt:3797-3817), and the
    // libpff notes show both an empty data object with a nonzero size and a sized attachment with no data
    // object at all (pff-format.asciidoc:2511-2519).
    uint64_t attachments_with_declared_size_and_no_payload = 0;
    // NBT entries whose nidType the opened sources do not define: no row in [MS-PST] 2.2.2.1, or named there
    // with no structure defined in either source. One count, because "no row" and "named but undefined" are
    // both unknown -- the per-nidType lines say which is which, and neither one says the node may be dropped.
    uint64_t nodes_of_unknown_type = 0;
    uint64_t blocks_unreadable = 0;
    uint64_t decode_failures = 0;
    // A Property Context the source named but the reader could not read is neither "the source has no
    // body" nor a body this project invented, so it gets its own line.
    uint64_t messages_with_unreadable_property_context = 0;
    uint64_t subnode_walks_incomplete = 0;
    uint64_t row_index_walks_failed = 0;
    // What the walk into attached messages could not finish. [MS-PST] 2.4.6.2.2 says a 0x3701 PtypObject
    // names a fully formed Message object, so a data block that is not a Property Context, and an attached
    // message a cap stopped short of, are reported here instead of disappearing from the inventory. They
    // count apart from the two NBT populations, exactly as the attached messages themselves do.
    uint64_t attachment_data_objects_not_decoded = 0;
    uint64_t attached_messages_left_by_cap = 0;
    // What each count means, in the sources' own terms.
    std::vector<std::string> notes;
    // The individual blocks a walk could not read, capped so a corrupt file stays printable.
    std::vector<std::string> unreadable_blocks;
    // ... and the walks that read their blocks but still stopped short of the whole list.
    std::vector<std::string> incomplete_walks;
};

// What the recursion into attached messages saw. Attached messages are reached only by following the
// PtypObject value of 0x3701 out of an Attachment object ([MS-PST] 2.3.3.5, 2.4.6.2.2), so the walk that
// finds them is the inventory's own, and its limits have to be reported as its own too.
struct EmbeddedWalkCounters {
    uint64_t objects = 0;    // 0x3701 values whose PtypObject named a subnode this reader reached
    uint64_t scanned = 0;    // ... and scanned as a Message object
    uint64_t not_messages =
        0;                   // ... unsupported method, or a declared message that failed validation
    uint64_t cycles = 0;     // ... already on this item's path, so the recursion stopped there
    uint64_t depth_capped = 0; // ... stopped by max_embedded_depth
    uint64_t capped = 0;       // ... stopped by max_embedded
    std::map<uint32_t, uint64_t> depths; // nesting depth -> attached messages scanned at that depth
    std::map<uint32_t, uint64_t> nid_types; // the nidType each attached message's NID carries
};

// The one verdict a run of the inventory gets, so no caller has to re-derive it from a handful of counters
// and no failure can hide behind a section nobody added up. `clean` says every structure this run opened
// decoded and every list it counted was read to the end. The two classes the literature excuses -- a node
// the spec says holds an array, a queue or a BLOB, and a structure the literature names but this reader
// does not decode -- are counted here so the report can show them instead of folding them into "nothing
// was skipped".
struct InventoryStatus {
    bool clean = false;
    uint64_t decode_failures = 0;   // census findings plus this layer's: bytes that contradicted their metadata
    uint64_t logged_findings = 0;   // every FailureLog the run wrote into, the caller's block source included
    uint64_t blocks_unreadable = 0; // blocks the BBT named and the reader could not get
    uint64_t walks_incomplete = 0;  // subnode BTree and RowIndex walks that stopped short of the whole list
    uint64_t content_unreadable = 0; // item content a record named and this reader could not get
    uint64_t scans_capped = 0;      // nodes a max_messages / max_associated cap left unscanned
    uint64_t embedded_capped = 0;   // attached messages a depth or work cap left unscanned
    uint64_t unsupported_structures = 0;
    uint64_t documented_non_heap = 0;
    std::vector<std::string> reasons; // one line per class that made the run incomplete
};

// What the caller's own seams counted while the inventory ran: the block source it handed over and the
// FailureLog it passed down. Without them the verdict could not see a block the file itself could not
// read, which is exactly how a truncated file used to pass as complete. They are pointers to the caller's
// live objects because the numbers only mean something once the run is over -- a copy taken before the
// call would always be zero.
struct InventoryUpstream {
    const ndb::BlockReadCounters *blocks = nullptr;
    const ndb::FailureLog *failures = nullptr;
};

struct InventoryReport {
    ndb::FileProfile profile = ndb::FileProfile::kOst;
    uint64_t nid_entries = 0;

    std::map<uint32_t, NodeClassCount> node_types;
    MessageStats messages;   // nidType 0x04
    MessageStats associated; // nidType 0x08
    AttachmentStats attachments;          // the ones 0x04 messages hold
    AttachmentStats associated_attachments; // ... and the ones 0x08 FAI entries hold
    // Attached messages ([MS-PST] 2.4.6.2.2): fully formed Message objects that are subnodes of an
    // Attachment object, carry no NBT entry and have no parent folder, so they are counted apart from the
    // two NBT populations and never added to them.
    MessageStats embedded;
    AttachmentStats embedded_attachments;
    EmbeddedWalkCounters embedded_walks;
    std::vector<FolderCounts> folders;

    // The counters the ltp seams were handed. They stay ltp's own types: the inventory reports what the
    // seams said rather than re-deriving it.
    ltp::LtpHeapCounters heap;
    ltp::DataTreeCounters data_trees;
    std::map<std::string, uint64_t> errors;

    CompletenessReport completeness;
    InventoryStatus status;
    bool capped = false;
};

// Builds the inventory from an LTP report and a block source. `source` is the census: its NID map, its
// folder tree and its profile. `blocks` answers "what are this BID's bytes", which is all the inventory
// needs on top of the census. `upstream` is what the caller's own seams counted while the inventory ran;
// pass it, or the verdict below cannot see a block the file itself could not read.
// A node that cannot be opened is counted and reported, never fatal -- but `report.status` says whether
// the run as a whole read what it claimed to, and a caller that exits on a run must exit on that.
util::Result<InventoryReport> build_inventory(const ltp::LtpReadReport &source, ltp::BlockSource &blocks,
                                              const InventoryOptions &options,
                                              const InventoryUpstream &upstream = {});

} // namespace ost2pst::msg
