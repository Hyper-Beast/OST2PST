#pragma once

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

#include "ost2pst/ltp/layout.h"
#include "ost2pst/ndb/btree.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ltp {

// --- Subnode BTree ([MS-PST] 2.2.2.8.3.3) ---
// A node's subnodes hang off NBTENTRY.bidSub: an SLBLOCK array of SLENTRYs, chained by SIBLOCK arrays of
// SIENTRYs when one block cannot hold them all. Both block kinds MUST carry bType 0x02, so cLevel is
// what tells them apart: the block-type table's "SLBLOCK 0 / SIBLOCK 1" column is cLevel, not bType.
struct SubnodeBlockHeader {
    uint8_t b_type = 0;
    uint8_t c_level = 0;
    uint16_t c_ent = 0;
    uint64_t entries_ib = 0;  // where rgentries starts
    uint64_t entry_size = 0;  // 24 for a Unicode SLENTRY, 16 for a Unicode SIENTRY
};

// [MS-PST] 2.2.2.8.3.3.1.2 SLBLOCK / 2.2.2.8.3.3.2.2 SIBLOCK, Unicode: bType(1) cLevel(1) cEnt(2)
// dwPadding(4). bType MUST be 0x02, cLevel MUST be 0 for an SLBLOCK and 1 for a SIBLOCK, and an SLBLOCK's
// cEnt MUST NOT be zero.
util::Result<SubnodeBlockHeader> decode_subnode_block_header(util::ByteView block);

// [MS-PST] 2.2.2.8.3.3.1.1 SLENTRY, Unicode: nid(8) bidData(8) bidSub(8).
struct SlEntry {
    uint64_t nid = 0;
    uint64_t bid_data = 0;
    uint64_t bid_sub = 0;
    uint64_t offset = 0; // where the entry itself was read from
};

util::Result<SlEntry> decode_sl_entry(util::ByteView view);

// [MS-PST] 2.2.2.8.3.3.2.1 SIENTRY, Unicode: nid(8) bid(8).
struct SiEntry {
    uint64_t nid = 0;
    uint64_t bid = 0;
    uint64_t offset = 0;
};

util::Result<SiEntry> decode_si_entry(util::ByteView view);

// [MS-PST] 2.2.2.8.3.3.1.1 calls SLENTRY.nid the local NID of the subnode, and the HNID that names the
// same subnode ([MS-PST] 2.3.3.2) is 32 bits. The OST this project reads writes 8 bytes there and the
// high 4 are not part of the NID (measured: 0x7500007C00008F5F), so every subnode comparison is made on
// the low 32 bits.
constexpr uint64_t subnode_nid_key(uint64_t nid) { return nid & 0xFFFFFFFFu; }

// Work caps. A Unicode SLBLOCK holds at most Floor(65512 / 24) entries at the largest cb this project
// accepts, and a SIBLOCK chain is a way to chain SLBLOCKs, not a deep tree.
constexpr uint64_t kMaxSubnodeDepth = 8;   // [MS-PST] 2.2.2.8.3.3.2: SIBLOCKs chain SLBLOCKs
constexpr uint64_t kMaxSubnodeEntries = 4096;

// The bytes one BID holds, plus what the index says about the block. The internal bit is not a detail the
// caller can recover from the bytes: [MS-PST] 2.2.2.2 bit B is what separates an internal block (one that
// names other blocks, [MS-PST] 2.2.2.8.3) from a data block, and the two look alike once the block has
// been inflated. A source that cannot answer says so through the same field.
struct BlockBytes {
    util::ByteView view;
    bool internal = false; // [MS-PST] 2.2.2.2 bit B as the BBTENTRY stores it
    // Whether the block is compressed is what the NDB says about it -- the OST trailer's uncompressed
    // data length (ndb::BlockData::compressed) -- not what the bytes look like. A raw block whose first
    // two bytes happen to form a CMF/FLG pair is still raw.
    bool compressed = false;
};

// A subnode block is reached through a BID, and in an OST it is compressed exactly like a data block, so
// the seam hands over the block's own bytes together with what the index says about them. Virtual for the
// same reason HeapSource is: the walk has to be testable without a file.
class BlockSource {
public:
    BlockSource() = default;
    BlockSource(const BlockSource &) = delete;
    BlockSource &operator=(const BlockSource &) = delete;
    BlockSource(BlockSource &&) = delete;
    BlockSource &operator=(BlockSource &&) = delete;
    virtual ~BlockSource() = default;

    // Exactly the cb bytes one BID holds and the BBTENTRY's internal flag for it. The returned view has to
    // stay valid until the next call on the same object.
    virtual util::Result<BlockBytes> block(uint64_t bid) = 0;
};

// Where a subnode was found. bid_data and bid_sub come out of the SLENTRY, so the caller can read that
// subnode's own heap node and then descend into its own subnodes.
struct SubnodeRef {
    uint64_t nid = 0;
    uint64_t bid_data = 0;
    uint64_t bid_sub = 0;
    uint64_t block_bid = 0;    // the SLBLOCK that held the entry
    uint64_t entry_offset = 0; // offset of the entry, as that block's view reported it
    uint64_t depth = 0;        // SIBLOCK hops taken to reach the SLBLOCK
};

struct SubnodeStats {
    uint64_t searches = 0;
    uint64_t found = 0;
    uint64_t not_found = 0;
    uint64_t blocks_read = 0;
    uint64_t blocks_compressed = 0;
    uint64_t blocks_raw = 0;
    uint64_t blocks_bad = 0;
    uint64_t blocks_not_internal = 0; // blocks a bidSub/SIENTRY named that the BBT does not flag Internal
    uint64_t entries_scanned = 0;
    uint64_t entries_skipped = 0;
    uint64_t si_hops = 0;
    uint64_t max_depth = 0;
    uint64_t max_entries = 0;
    bool stopped_early = false;
};

// Adds one pass's subnode counters into another so a report that walks subnodes through several seams
// still shows one total.
void merge_subnode_stats(SubnodeStats &into, const SubnodeStats &from);

// Descend bidSub through SIBLOCKs to an SLBLOCK and return the SLENTRY whose nid is local_nid
// ([MS-PST] 2.2.2.8.3.3). Compressed blocks are inflated first. A bad entry is logged and skipped; a
// block the source cannot read, a block that is not a subnode block, and a chain that never holds the
// NID are returned as errors. Work is capped so a corrupt chain cannot spin.
util::Result<SubnodeRef> find_subnode(uint64_t bid_sub, uint64_t local_nid, BlockSource &source,
                                      SubnodeStats &stats, ndb::FailureLog &failures);

// Enumerates every SLENTRY a node's subnode BTree holds ([MS-PST] 2.2.2.8.3.3): every SIBLOCK child is
// followed, a block reached twice is a cycle and stops that branch, and the work caps are the same
// ltp::kMaxSubnodeDepth / kMaxSubnodeEntries find_subnode uses. `found` counts the entries returned;
// `stopped_early` says the list is short, which is a different statement from "this node has no subnodes".
util::Result<std::vector<SubnodeRef>> walk_subnode_entries(uint64_t bid_sub, BlockSource &source,
                                                            SubnodeStats &stats,
                                                            ndb::FailureLog &failures);

// --- NID map ---
// One NBTENTRY reduced to what the LTP layer needs ([MS-PST] 2.2.2.7.7.4).
struct NodeRef {
    uint64_t nid = 0;
    uint64_t bid_data = 0;
    uint64_t bid_sub = 0;
    uint32_t nid_parent = 0;
};

// The NBT indexed by NID, plus the nidIndex grouping the Messaging layer depends on: a Folder object is
// one PC and three TCs sharing one nidIndex under different nidTypes ([MS-PST] 2.4.4.3), so the sibling
// of a NID is the same nidIndex under another type.
class NidMap {
public:
    void add(const ndb::NbtEntry &entry);

    bool empty() const { return by_nid_.empty(); }
    size_t size() const { return by_nid_.size(); }
    size_t groups() const { return by_index_.size(); }

    util::Result<NodeRef> node(uint64_t nid) const;
    util::Result<NodeRef> sibling(uint64_t nid, uint32_t nid_type) const;

    // Every NID sharing this nidIndex's node, in nidType order.
    std::vector<NodeRef> group(uint64_t nid) const;

    // Every entry the map holds, ordered by NID. A caller that has to say something about each top-level
    // node needs the whole set, not one lookup at a time.
    std::vector<NodeRef> entries() const;

    // How many NBT entries name `parent_nid` as their nidParent under `nid_type` ([MS-PST] 2.2.2.7.7.4 /
    // 2.4.5.2). A Message object's nidParent is the NID of its parent Folder object's PC, so this is the
    // other way to know what a folder holds -- the one that still works when the folder's contents table
    // carries no rows, which is what most folders of a real OST look like.
    uint64_t children(uint32_t parent_nid, uint32_t nid_type) const;

    // NBT entries that carry a nonzero nidParent at all.
    uint64_t parent_links() const { return parent_links_; }

    uint64_t duplicates() const { return duplicates_; }
    uint64_t with_subnode() const { return with_subnode_; }
    uint64_t missing_data() const { return missing_data_; }

private:
    std::unordered_map<uint64_t, NodeRef> by_nid_;
    std::unordered_map<uint64_t, std::vector<uint64_t>> by_index_;
    std::unordered_map<uint64_t, uint64_t> by_parent_; // nidParent << 8 | nidType -> entries
    uint64_t duplicates_ = 0;
    uint64_t parent_links_ = 0;
    uint64_t with_subnode_ = 0;
    uint64_t missing_data_ = 0;
};

} // namespace ost2pst::ltp
