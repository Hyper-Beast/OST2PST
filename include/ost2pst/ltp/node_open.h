#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "ost2pst/ltp/data_tree.h"
#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/hn_block.h"
#include "ost2pst/ltp/ltp_read.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/ndb/block_reader.h"
#include "ost2pst/ndb/profile.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ltp {

// One node's data block, owned by this struct. A BlockSource reuses its own buffer, so a raw
// block's view would dangle the moment the next block is read -- and reading a subnode is exactly
// what a PC value lookup does. The bytes therefore live here, and every view this struct hands out
// points at them.
struct NodeHeap {
    std::vector<uint8_t> bytes;
    HnBlock block;
    HnHeader header;
    HnPageMap page_map;
    // The profile the block was read under. Every HID in this node is decoded with it, so a node
    // can never be read with one profile and answered with another ([MS-PST] 2.3.1.1).
    ndb::FileProfile profile = ndb::FileProfile::kPst;
    // A node whose data does not fit in one data block spreads its heap over the blocks its jump
    // table names ([MS-PST] 2.3.1.6.2). Empty for a single-block node, whose heap is `block` alone.
    std::vector<HnFragment> fragments;
    // The heap of this node, whichever of the two shapes it is in. Callers read properties through
    // this instead of picking a source themselves, so a multi-block node cannot be read as a
    // single-block one.
    std::unique_ptr<HeapSource> source;
    uint64_t bid = 0;
    uint64_t ib = 0;
    size_t cb = 0;
    bool page_map_ok = false;
    bool multi_block = false;
};

enum class NodeOpen {
    kOk,             // the block reads and its heap node decodes
    kNotHeapNode,    // the block reads but carries no HNHDR: a queue node or a plain array
                     // ([MS-PST] 2.4.8.3)
    kUnreadable,     // the block itself could not be read
    kDataTreeFailed, // the block is Internal and its data tree does not resolve
                     // ([MS-PST] 2.2.2.8.3.2)
};

// BlockSource over the real file: resolve the BID through the BBT, read it, and keep the bytes
// alive for the next call, which is exactly what the seam documents. Its own counters let a caller
// that opens a targeted handful of nodes keep them separate from a census of every
// NBTENTRY.bidData.
class FileBlockSource : public BlockSource {
  public:
    FileBlockSource(const util::FileReader& file, ndb::FileProfile profile,
                    const ndb::BbtIndex& index, ndb::BlockReadCounters& counters,
                    ndb::FailureLog& failures)
        : file_(file), profile_(profile), index_(index), counters_(counters), failures_(failures) {}

    util::Result<BlockBytes> block(uint64_t bid) override;

  private:
    const util::FileReader& file_;
    ndb::FileProfile profile_;
    const ndb::BbtIndex& index_;
    ndb::BlockReadCounters& counters_;
    ndb::FailureLog& failures_;
    ndb::BlockData held_;
};

// Opens one node's data block and classifies it. Nothing here aborts a walk: a block that cannot be
// read and a block that is not a heap node are both counted and reported, because a mailbox with
// one odd block still has a folder tree worth reading.
//
// Which kind of block it is comes from the BBTENTRY's internal bit ([MS-PST] 2.2.2.2 bit B), not
// from trying one decode and falling back to another. [MS-PST] 3.6 names the shape this produces: a
// node's bidData "that has the i bit set" roots a data tree, and [MS-PST] 2.2.2.8.3.1 is the other
// case -- an external block holds the data itself.
//
// `findings` may be nullptr for a caller that re-opens a node a census already classified, so one
// node is never counted twice; the error tally always counts the field.
NodeOpen open_node(BlockSource& blocks, ndb::FileProfile profile, uint64_t nid, uint64_t bid,
                   NodeHeap& node, LtpHeapCounters& counters, DataTreeCounters& data_trees,
                   std::map<std::string, uint64_t>& errors, LtpFindingTally* findings,
                   ndb::FailureLog& failures, util::ByteBudget* workspace = nullptr);

} // namespace ost2pst::ltp
