// Describes one node and the subnodes its bidSub names, so a subnode layout can be measured instead of
// inferred: which local NIDs a node's own PC values name, where a Table Context keeps its Row Matrix, and
// how many bytes a subnode's data actually is ([MS-PST] 2.2.2.8.3.3, 2.3.3.2, 2.3.4.1).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "ost2pst/ltp/data_tree.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/ltp/node_open.h"
#include "ost2pst/ltp/tc.h"
#include "ost2pst/ndb/profile.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ltp {

// One Property Context record as the dump sees it: the tag, what dwValueHnid names, and how many bytes the
// value source actually answered. [MS-PST] 2.3.3.2 decides the "what" from hidType; the byte count is what
// was read, never what a property type claims.
struct DumpPcValue {
    uint32_t tag = 0;
    uint16_t prop_id = 0;
    uint16_t prop_type = 0;
    uint32_t hnid = 0;
    bool inline_value = false; // [MS-PST] 2.3.3.3: fixed-size type of 4 bytes or less
    bool absent = false;       // [MS-PST] 2.3.3.2: dwValueHnid 0 means the property has no value
    bool in_heap = false;      // [MS-PST] 2.3.3.2: hidType == NID_TYPE_HID
    bool in_subnode = false;   // [MS-PST] 2.3.3.2: any other hidType names a subnode
    bool answered = false;
    uint64_t bytes = 0;
};

// One Table Context, including where its Row Matrix lives. [MS-PST] 2.3.4.1 says TCINFO.hnidRows names it
// and 2.3.3.2 says a hidType other than NID_TYPE_HID names one of the node's subnodes; [MS-PST] 2.3.4.4
// says the subnode's data is the rows spread over blocks.
struct DumpTc {
    bool read = false;
    uint8_t columns = 0;
    uint32_t hnid_rows = 0; // 0 when the TC carries no rows ([MS-PST] 2.3.4.1)
    uint64_t rows = 0;      // rows the RowIndex BTH walked
    uint64_t row_size = 0;  // rgib[TCI_bm]
    bool matrix_in_heap = false;
    bool matrix_in_subnode = false;
    uint64_t matrix_bytes = 0;        // rows * row_size
    uint64_t matrix_blocks = 0;       // data blocks the subnode's data tree ends in
    uint64_t matrix_stored_bytes = 0; // ... as those blocks are stored
    std::vector<TcColumn> column_list;
    std::vector<uint32_t> row_ids; // the first rows in RowIndex order
};

// One node: the NBT node the dump started at, or one of its subnodes.
struct DumpNode {
    uint64_t nid = 0;       // the NBTENTRY.nid, or the SLENTRY.nid as written
    uint64_t local_nid = 0; // the low 32 bits a PC or TC HNID uses to name this node
    uint64_t nid_type = 0;  // [MS-PST] 2.2.2.1: the low 5 bits
    uint64_t bid_data = 0;
    uint64_t bid_sub = 0;
    bool data_internal = false; // [MS-PST] 2.2.2.2 bit B on bidData
    bool sub_internal = false;  // ... on bidSub
    uint64_t cb_data = 0;       // as the BBT stores it
    uint64_t ib_data = 0;
    uint64_t depth = 0;         // subnode levels below the dumped node
    uint64_t parent_local_nid = 0; // the subnode whose list names this one (unused at depth 0)
    bool has_parent = false;
    NodeOpen opened = NodeOpen::kUnreadable;
    uint16_t client_sig = 0;
    uint64_t heap_bytes = 0;    // this node's own heap, inflated
    uint64_t allocations = 0;
    uint64_t data_blocks = 0;   // data blocks its own data tree ends in (1 for a single-block node)
    uint64_t data_heap_bytes = 0; // ... and what they hold once inflated
    std::vector<DumpPcValue> pc;
    uint64_t pc_records = 0; // records seen, whether or not the dump kept them
    DumpTc tc;
    std::string note;
};

struct SubtreeDumpOptions {
    uint64_t max_nodes = 400; // nodes described, the dumped node included
    uint64_t max_depth = 2;   // subnode levels below the dumped node
    uint64_t max_pc_records = 400;
    uint64_t max_row_ids = 8;
};

struct SubtreeDump {
    DumpNode root;
    std::vector<DumpNode> subnodes; // every node below the root, in local-NID order
    SubnodeStats stats;
    DataTreeCounters trees;
    LtpHeapCounters heap;
    bool capped = false;   // a work cap cut the node list or a record list short
    bool row_ids_capped = false; // only the printed sample of dwRowIDs is short, not a list the dump read
    std::vector<ndb::ProbeFailure> failures;
    uint64_t failure_total = 0;
};

// Describes one NID's node and the subnodes its bidSub names. The NID map answers "what is this node", the
// block source answers "what are these bytes", so the dump is testable without a file. A node the map does
// not carry is an error; a node whose block cannot be read is described with its `opened` kind instead of
// ending the dump.
util::Result<SubtreeDump> dump_subtree(const NidMap &nodes, BlockSource &blocks,
                                       ndb::FileProfile profile, uint64_t nid,
                                       const SubtreeDumpOptions &options);

} // namespace ost2pst::ltp
