#pragma once

#include <cstdint>
#include <vector>

#include "ost2pst/util/status.h"
#include "ost2pst/util/value_spool.h"

namespace ost2pst::writer {

// One subnode a built node needs beyond its own data block: the local NID the HNID that names it
// carries, and the raw bytes that become the subnode's data ([MS-PST] 2.3.3.2 / 2.3.4.1 / 2.3.4.4).
struct LocalSubnode {
    uint32_t nid = 0;
    std::vector<uint8_t> bytes;
    util::SharedBytes source;
};

// A node's own supply of subnode NIDs. [MS-PST] 2.6.1.2.2 says "NIDs for subnodes are internal and
// therefore NOT allocated from the rgnid[nidType] counter in the HEADER", and 2.2.2.8.3.3.1.1 says
// a subnode's NID is guaranteed unique only within its parent node, so every node gets its own
// counter and the NID keeps the [MS-PST] 2.2.2.1 shape (nidIndex << 5) | nidType. The sample's
// local NIDs are built the same way: 0x0671 is index 0x33 under NID_TYPE_ATTACHMENT_TABLE and 0x3F
// is index 1 under NID_TYPE_LTP
// (DEVELOPMENT.md).
class LocalNids {
  public:
    explicit LocalNids(uint32_t first_index = 1);

    // The next free local NID under nidType.
    util::Result<uint32_t> take(uint32_t nid_type);

    // A specific index the caller wants, such as the 0x33 / 0x34 the sample gives the Attachment
    // and Recipient tables. An index this node already handed out is refused.
    util::Result<uint32_t> take_at(uint32_t index, uint32_t nid_type);

    // How many NIDs this node has taken.
    uint64_t taken() const;

  private:
    uint32_t next_index_ = 1;
    uint64_t taken_ = 0;
    std::vector<uint32_t> used_;
};

} // namespace ost2pst::writer
