// The data tree a node's data is spread over when it does not fit in one data block
// ([MS-PST] 2.2.2.8.3.2), flattened into the data blocks it names.
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "ost2pst/ltp/block_heap.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_budget.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ltp {

// What flattening data trees cost and what it found. The block counters live here too so a caller
// can add them to its own pass instead of the tree keeping a second account of the same reads.
struct DataTreeCounters {
    uint64_t trees = 0;          // data trees flattened
    uint64_t tables = 0;         // jump tables decoded (XBLOCK and XXBLOCK)
    uint64_t xxblock_tables = 0; // ... of which cLevel 2
    uint64_t data_blocks = 0;    // external data blocks the trees ended in
    uint64_t blocks_read = 0;    // blocks a tree read, including the tree's own root
    uint64_t blocks_failed = 0;  // ... and could not read
    uint64_t compressed = 0;
    uint64_t raw = 0;
    uint64_t rejected_tables = 0; // internal blocks that are not a decodable jump table
    uint64_t child_flag_mismatches =
        0; // a jump table whose child's internal flag contradicts its cLevel
    uint64_t index_flag_mismatches = 0; // a reference flag that contradicts the BBTENTRY's own flag
    uint64_t lcb_total_mismatches = 0;  // a table whose lcbTotal is not the bytes under it
    uint64_t cycles = 0;
    uint64_t capped = 0;
    uint64_t failed_trees = 0;              // trees whose walk ended in an error
    uint16_t max_entries = 0;               // widest cEnt seen
    uint64_t max_blocks = 0;                // widest tree, in data blocks
    uint64_t max_block_bytes = 0;           // largest block a tree read, as stored
    uint64_t max_heap_bytes = 0;            // ... and what it held once inflated
    std::map<std::string, uint64_t> errors; // field -> count, merged into the caller's tally
};

// Flattens the data tree rooted at `root_bid` into its data blocks, in the order the jump tables
// name them. The root may be an external data block (a tree of one block, [MS-PST] 2.2.2.8.3.2) or
// an internal block, and the internal bit decides which ([MS-PST] 2.2.2.2 bit B, 3.6):
//
// - external: the block's own payload is the data, and the tree ends there;
// - internal: the block MUST decode as a jump table. A jump table that does not decode is a finding
// about
//   this node and is returned as an error -- never a licence to treat the block as data.
// - an XBLOCK (cLevel 1) names data blocks and an XXBLOCK (cLevel 2) names XBLOCKs
//   ([MS-PST] 2.2.2.8.3.2.1 / 2.2.2.8.3.2.2), so a child's internal flag has to match its parent's
//   cLevel;
// - each table's lcbTotal has to equal the bytes of the external data under it
//   ([MS-PST] 2.2.2.8.3.2.1 / 2.2.2.8.3.2.2);
// - a BID visited twice is a cycle, and the block count is capped at the number of data blocks a
//   multi-block heap node can address ([MS-PST] 2.3.1.1 hidBlockIndex).
//
// Every finding is counted in `counters` and logged in `failures`; the first failure also ends the
// tree and is returned, because a node whose data tree does not add up has no trustworthy data.
util::Result<std::vector<HnFragment>> read_data_tree(BlockSource& blocks, uint64_t root_bid,
                                                     ndb::FileProfile profile,
                                                     DataTreeCounters& counters,
                                                     ndb::FailureLog& failures,
                                                     util::ByteBudget* workspace = nullptr);

// Visits each validated external payload while its owner is alive. The visitor may have
// received a prefix before a later tree/length error: callers commit only after success.
// No payload fragments are retained; child flags, cycles, caps and lcbTotal use the same walk.
using DataVisitor = std::function<util::Status(util::ByteView)>;
util::Result<uint64_t> stream_data_tree(BlockSource& blocks, uint64_t root_bid,
                                        ndb::FileProfile profile, DataTreeCounters& counters,
                                        ndb::FailureLog& failures, const DataVisitor& visitor);

// Adds one pass's counters into another so a walk that flattens trees through several seams (a
// node's own data block, then a subnode value) still reports one total.
void merge_data_tree_counters(DataTreeCounters& into, const DataTreeCounters& from);

} // namespace ost2pst::ltp
