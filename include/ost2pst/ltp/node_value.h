#pragma once

#include <cstdint>
#include <vector>

#include "ost2pst/ltp/bth.h"
#include "ost2pst/ltp/data_tree.h"
#include "ost2pst/ltp/nid_map.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ltp {

// A PC value HNID names either an allocation in the node's own data block or one of that node's
// subnodes ([MS-PST] 2.3.3.2). Answering it therefore needs the node's heap and its bidSub
// together, which is what this seam holds.
class ValueSource {
  public:
    ValueSource() = default;
    ValueSource(const ValueSource&) = delete;
    ValueSource& operator=(const ValueSource&) = delete;
    ValueSource(ValueSource&&) = delete;
    ValueSource& operator=(ValueSource&&) = delete;
    virtual ~ValueSource() = default;

    // The bytes one HNID names. A subnode value is the data its SLENTRY.bidData names: one data
    // block, or every data block under the data tree that block roots when the internal bit is set
    // ([MS-PST] 2.2.2.8.3.3.1.1 / 2.2.2.8.3.2 / 3.6). The returned view stays valid until the next
    // call on the same object.
    virtual util::Result<util::ByteView> value(uint32_t hnid) = 0;
    virtual util::Result<uint64_t> stream(uint32_t hnid, const DataVisitor& visitor);
};

// The ValueSource over one node: its own heap node plus the subnode blocks reached through bidSub.
class NodeValueSource : public ValueSource {
  public:
    NodeValueSource(HeapSource& heap, uint64_t bid_sub, ndb::FileProfile profile,
                    BlockSource& blocks, SubnodeStats& subnode_stats, DataTreeCounters& data_trees,
                    ndb::FailureLog& failures);

    util::Result<util::ByteView> value(uint32_t hnid) override;
    util::Result<uint64_t> stream(uint32_t hnid, const DataVisitor& visitor) override;

    uint64_t heap_hits = 0;
    uint64_t subnode_hits = 0;
    uint64_t subnode_misses = 0;

  private:
    HeapSource& heap_;
    uint64_t bid_sub_;
    ndb::FileProfile profile_;
    BlockSource& blocks_;
    SubnodeStats& subnode_stats_;
    DataTreeCounters& data_trees_;
    ndb::FailureLog& failures_;
    std::vector<uint8_t> held_; // a subnode value has no home but this: the block came from a
                                // source that reuses its own buffer, so the bytes are kept here
};

} // namespace ost2pst::ltp
