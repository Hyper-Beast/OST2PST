#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "ost2pst/ltp/data_tree.h"
#include "ost2pst/ltp/name_id.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/ltp/pc.h"
#include "ost2pst/ltp/smq.h"
#include "ost2pst/ndb/bbt_index.h"
#include "ost2pst/ndb/block_reader.h"
#include "ost2pst/ndb/btree.h"
#include "ost2pst/ndb/header.h"
#include "ost2pst/ndb/profile.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ltp {

// --- folder tree ([MS-PST] 2.4.4.4.2 / 2.4.4.5.2) ---
// A RowIndex record's dwRowID IS the NID of the node the row stands for: the hierarchy table's rows
// name the sub-Folder objects and the contents table's rows name the Message objects. So the tree
// and the per-folder item counts come out of the TCs alone, without opening a single message.
struct LtpFolder {
    uint64_t nid = 0;
    uint64_t parent = 0;
    uint32_t depth = 0;
    std::string name; // PidTagDisplayName, UTF-8
    bool name_present = false;
    uint64_t children = 0;   // rows of the hierarchy TC
    uint64_t messages = 0;   // rows of the contents TC
    uint64_t associated = 0; // rows of the FAI contents TC
    // The same items counted the other way round: NBT entries that name this folder as their
    // nidParent. A real OST leaves most of its contents tables empty, so these are the counts that
    // add up.
    uint64_t parent_messages = 0;   // nidType NID_TYPE_NORMAL_MESSAGE under this nidParent
    uint64_t parent_associated = 0; // nidType NID_TYPE_ASSOC_MESSAGE under this nidParent
    bool has_pc = false;
    bool has_hierarchy = false;
    bool has_contents = false;
    bool has_associated = false;
};

struct FolderWalkStats {
    uint64_t folders = 0;
    uint64_t blocks_read = 0;   // data blocks this walk opened for the folders it visited
    uint64_t blocks_failed = 0; // ... and could not read
    uint64_t not_heap_node = 0; // ... or found to carry no heap node
    uint64_t pcs_read = 0;
    uint64_t tcs_read = 0;
    uint64_t cycles = 0;        // a NID reached twice: the tree is walked with a visited set
    uint64_t missing = 0;       // a dwRowID with no NBTENTRY behind it
    uint64_t depth_capped = 0;  // a folder below the depth cap, not walked
    uint64_t stopped_early = 0; // the folder cap reached
    uint64_t max_depth = 0;
    uint64_t tc_rows = 0;        // rows counted across every table this walk opened
    DataTreeCounters data_trees; // data trees opened while reading this tree's nodes and values
    SubnodeStats subnodes;       // subnode BTrees walked while reading this tree's values
};

// Work caps. max_depth is the deepest level the walk may enter, so 0 walks the root folder alone.
struct FolderWalkOptions {
    uint64_t max_folders = 100000;
    uint64_t max_depth = 64;
};

// Walks the hierarchy from root_nid over the seams, so it is testable without a file: the NID map
// answers "what is this folder's hierarchy table", the block source answers "what are that node's
// bytes".
util::Status walk_folder_tree(const NidMap& nodes, BlockSource& blocks, uint64_t root_nid,
                              const FolderWalkOptions& options, ndb::FileProfile profile,
                              std::vector<LtpFolder>& folders, FolderWalkStats& stats,
                              ndb::FailureLog& failures);

// --- the whole LTP layer ---
struct LtpReadOptions {
    size_t max_failures = 10;
    // Construction allowances for global indices, including consumers' compact identity copies.
    // Zero preserves the legacy diagnostic reader; full conversion supplies an explicit ceiling.
    uint64_t index_workspace_budget = 0;
    bool scan_blocks = true;   // open every NBTENTRY.bidData and classify its heap node
    bool build_folders = true; // walk the folder hierarchy from NID_ROOT_FOLDER
    uint64_t dump_nid = 0;     // dump this NID's properties as well
    bool dump_requested = false;
    FolderWalkOptions folders;
};

// Why the reader stopped short of a readable structure. The three classes say different things and
// the report never merges them: [MS-PST] 2.2.2.1 says which nidType values are announced as a
// Property Context or a Table Context, so a data block with no HNHDR under any other nidType is not
// a decode failure; a heap node whose bClientSig the spec reserves is a structure this reader
// cannot read; and a node whose own type does promise a PC or a TC is a decode failure.
enum class LtpFindingKind {
    kDocumentedNonHeapNode, // [MS-PST] 2.4.8.3 / 2.4.8.4 / 2.4.8.5: a node the spec says holds an
                            // array, a queue or a BLOB
    kUnsupportedStructure,  // named by the literature, but not a shape this reader decodes
    kDecodeFailure,         // the bytes contradict what the node's own metadata says they are
};

const char* ltp_finding_kind_name(LtpFindingKind kind);

// One finding the reader can point at: which node, which field, and what was said about it.
struct LtpFinding {
    LtpFindingKind kind = LtpFindingKind::kDecodeFailure;
    uint64_t nid = 0;
    uint32_t nid_type = 0;
    uint64_t bid = 0;
    std::string field;
    std::string detail;
};

// Findings counted per class, with the itemized list capped so a big mailbox cannot make the report
// unprintable. `clean` is decided by the decode failures alone; the other two classes say what the
// reader did not read, and the report lists them instead of folding them into "no findings".
struct LtpFindingTally {
    uint64_t documented_non_heap = 0;
    uint64_t unsupported = 0;
    uint64_t decode_failures = 0;
    uint64_t total = 0;
    size_t max_items = 10;
    std::vector<LtpFinding> items;

    void record(LtpFindingKind kind, uint64_t nid, uint64_t bid, const std::string& field,
                const std::string& detail);
};

// Classifies a data block that carries no HNHDR by the node that names it: [MS-PST] 2.2.2.1 decides
// whether the nidType promised a heap node at all, and [MS-PST] 2.4.1 / 2.4.8 name the internal
// nodes that hold an array, a queue or a BLOB instead of one.
LtpFindingKind classify_missing_heap_node(uint64_t nid);

struct LtpHeapCounters {
    uint64_t blocks_read = 0;
    uint64_t blocks_failed = 0;
    uint64_t compressed = 0;
    uint64_t raw = 0;
    uint64_t heap_nodes_ok = 0;
    uint64_t heap_nodes_rejected = 0;
    uint64_t multi_block_nodes =
        0; // nodes whose data block is a jump table over several data blocks
    uint64_t multi_block_fragments = 0; // ... and the data blocks they spread the heap over
    uint64_t max_fragments = 0;
    uint64_t fragment_page_maps_rejected =
        0; // blocks of a multi-block node with no usable HNPAGEMAP
    uint64_t allocations = 0;
    uint64_t max_allocations = 0;
    uint64_t max_heap_bytes = 0;
    uint64_t max_block_bytes = 0;
    std::map<uint16_t, uint64_t> client_sigs; // bClientSig -> nodes carrying it
};

struct LtpPcCounters {
    uint64_t contexts = 0;
    uint64_t failed = 0;
    uint64_t records = 0;
    uint64_t inline_values = 0;
    uint64_t heap_values = 0;
    uint64_t subnode_values = 0;
    uint64_t no_values = 0; // dwValueHnid 0: the property is present and has no value
    uint64_t unresolved_values = 0;
    uint64_t skipped = 0;
    uint64_t max_records = 0;
    std::map<uint16_t, uint64_t> prop_types;
    std::map<uint8_t, uint64_t> nid_types;
};

struct LtpTcCounters {
    uint64_t contexts = 0;
    uint64_t failed = 0;
    uint64_t columns = 0;
    uint64_t rows = 0;
    uint64_t max_columns = 0;
    uint64_t max_rows = 0;
    uint64_t columns_only = 0; // hnidRows 0: a template, or a folder table with no rows
    uint64_t matrix_in_heap = 0;
    uint64_t matrix_in_subnode = 0;
    std::map<uint8_t, uint64_t> nid_types;
};

// libpff "The 9c table": root DWORD -> BTHHEADER, GUID keys / DWORD descriptors.
// A partial BTH walk is a failure, even when walk_bth recovered by skipping a record.
util::Status validate_guid_map(const HnHeader& header, ndb::FileProfile profile, HeapSource& source,
                               BthStats& stats, ndb::FailureLog& failures);

// [MS-PST] 2.4.8.4.2: SAL is an array of DWORD NIDs, not a heap or queue.
util::Result<std::vector<uint32_t>> decode_search_activity_list(util::ByteView bytes);

// One line of the node dump. A named property (NPID 0x8000 .. 0x8FFF) is identified by its property
// set and its name, not by its tag alone: [MS-PST] 2.4.7.1 says the same string name under two
// property sets is two different properties, so the dump carries the identity the Name-to-ID Map
// gives it.
struct LtpPropertyValue {
    uint32_t tag = 0;
    std::string value; // rendered value, or what the reader could say about it
    bool named = false;
    bool name_resolved = false;
    bool name_is_string = false; // [MS-PST] 2.4.7.1: the N bit decides whether the name is a string
    std::u16string name;         // the string name from the String Stream
    uint32_t numeric_name = 0;   // the name when the N bit is 0
    uint16_t guid_index = 0;     // the wGuid as written
    NameIdGuidKind guid_kind = NameIdGuidKind::kNone;
    bool guid_resolved = false;
    bool guid_from_file =
        false; // the GUID bytes came from this file's GUID Stream, not a reference table
    std::vector<uint8_t> guid; // the property-set GUID bytes
};

// One node's properties, decoded by tag: what `ostinfo --ltp --nid <NID>` prints. A node whose data
// block carries a Table Context instead of a Property Context has no properties, so its column
// descriptors are reported through the same list, rendered as the geometry of the column rather
// than as a value.
struct LtpNodeDump {
    uint64_t nid = 0;
    uint64_t bid_data = 0;
    uint64_t bid_sub = 0;
    uint32_t nid_parent = 0;
    uint16_t client_sig = 0;
    uint64_t heap_bytes = 0;
    uint64_t allocations = 0;
    std::vector<PcRecord> properties;
    std::vector<LtpPropertyValue>
        values; // property tag -> value and, for a named property, its identity
    uint64_t values_resolved = 0;
    uint64_t values_unresolved = 0;
    uint64_t named_unresolved = 0; // named property tags the Name-to-ID Map has no entry for
};

struct LtpReadReport {
    ndb::Header header;
    ndb::FileProfile profile = ndb::FileProfile::kOst;
    std::string profile_evidence;
    std::optional<util::DataError> refusal;
    uint64_t index_workspace_bytes = 0;

    ndb::BTreeStats bbt;
    ndb::BTreeStats nbt;
    ndb::BlockReadCounters blocks;

    // The NBT indexed by NID. Kept so a layer above this one can walk the same node set the census
    // walked instead of reading the NBT a second time; the counts below are the same walk's totals.
    NidMap nodes;

    // The BBT index the census resolved its BIDs through, kept for the same reason: a layer above
    // this one that opens a targeted handful of nodes needs the same BID -> offset map, and reading
    // the BBT twice would mean reading the same pages twice.
    ndb::BbtIndex bbt_index;

    uint64_t nid_entries = 0;
    uint64_t nid_groups = 0;
    uint64_t nid_duplicates = 0;
    uint64_t nid_with_bid_data = 0;
    uint64_t nid_with_bid_sub = 0;
    std::map<uint8_t, uint64_t> nid_types;

    LtpHeapCounters heap;
    LtpPcCounters pcs;
    LtpTcCounters tcs;
    uint64_t guid_maps_read = 0;
    uint64_t guid_map_records = 0;
    bool sal_read = false;
    std::vector<uint32_t> search_activity_nids;
    SubnodeStats subnodes;
    DataTreeCounters
        data_trees; // every data tree this read flattened, through a node or a subnode value

    NameIdStats npm;
    bool npm_read = false;
    uint64_t named_properties = 0; // entries of the Name-to-ID Map Entry Stream
    NameIdMap name_id_map; // the map itself, kept so a node dump can name its named properties
    QueueStats smq;
    std::map<uint16_t, uint64_t> sud_types;
    bool smq_present = false;

    std::vector<LtpFolder> folders;
    FolderWalkStats folder_stats;

    std::optional<LtpNodeDump> dump;
    std::optional<util::DataError> dump_error;

    std::map<std::string, uint64_t> errors; // error field -> how many times it appeared
    LtpFindingTally findings;               // what the reader did not read, and why, per class
    std::vector<ndb::ProbeFailure> failures;
    uint64_t failure_total = 0;
    // "clean" means every structure the reader attempted decoded. It does not claim the file was
    // read completely: documented non-heap nodes and unsupported structures are reported in
    // `findings` and justified item by item, while a decode failure or a logged finding always
    // makes this false.
    bool clean = false;
};

// Reads the LTP layer of one file on top of the NDB layer: the BBT index, the NBT walk into a NID
// map, every data block opened and classified, every property context and table context walked, the
// Name-to-ID Map, the Search Management Queue, and the folder tree. A refusal short-circuits the
// same way read_ndb does: bytes under an unreadable header cannot be interpreted.
util::Result<LtpReadReport> read_ltp(const util::FileReader& file, const LtpReadOptions& options);

// The value of one property record as text, for the node dump. A string type is decoded, a binary
// type is sized, a fixed-size type is shown as its integer, and anything that cannot be answered
// says so instead of guessing.
std::string render_property_value(const PcRecord& record, ValueSource& values);

} // namespace ost2pst::ltp
