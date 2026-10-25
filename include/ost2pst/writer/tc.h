#pragma once

#include <cstdint>
#include <vector>

#include "ost2pst/ltp/layout.h"
#include "ost2pst/util/status.h"
#include "ost2pst/writer/heap.h"
#include "ost2pst/writer/nid.h"

namespace ost2pst::writer {

// One column of a Table Context. Its width comes from the property type in the tag: a fixed-size
// type of 8 bytes or less takes its own width, and anything [MS-PST] 2.3.4.4.2 calls variable-sized
// takes the 4-byte slot that holds an HNID.
struct TcColumnSpec {
    uint32_t tag =
        0; // [MS-PST] 1.1 property tag: property id in the high 16 bits, type in the low 16
};

// One row of the Row Matrix. values holds one entry per column, in the order the columns were
// given; an empty entry leaves the cell's Cell Existence Bit clear ([MS-PST] 2.3.4.4.3).
struct TcRow {
    uint32_t row_id =
        0; // [MS-PST] 2.3.4.3.1 dwRowID; a folder table row's is the NID of the object
    std::vector<std::vector<uint8_t>> values;
    // Optional presence flags for empty variable-sized values, in input-column order.
    // Such a cell has CEB=1 and HNID=0 (MS-PST 2.3.4.4); it differs from an absent cell.
    std::vector<bool> present_empty;
    // Optional immutable values, in input-column order; bytes and source are exclusive.
    std::vector<util::SharedBytes> sources;
};

// Repeatable rows backed by committed staging records or a spool. The source stays stable
// during construction; each read owns only that row's values, released before the next read.
class TcRowSource {
  public:
    virtual ~TcRowSource() = default;
    virtual uint64_t count() const = 0;
    virtual util::Result<TcRow> read(uint64_t index) const = 0;
};

// A Table Context as the writer emits it. The heap node holds TCINFO followed by rgTCOLDESC, the
// RowIndex BTHHEADER, the TCROWID array sorted by dwRowID, and the cell values that fit the heap
// ([MS-PST] 2.3.4.1 / 2.3.4.3.1 / 2.3.4.4). hnidRows is what TCINFO names for the rows: the HNID of
// the Row Matrix allocation while the matrix stays in the heap, or the local NID of the subnode
// that holds the rows otherwise ([MS-PST] 2.3.4.1 / 2.3.4.4). subnodes is that Row Matrix subnode
// first, then the cell values too large for the heap ([MS-PST] 2.3.4.4.2 / 2.6.2.4.2).
struct TcNode {
    HeapImage heap{ltp::kClientSigTc}; // [MS-PST] 2.3.1.2 bClientSig bTypeTC
    uint32_t hnid_rows = 0;
    // The row size the writer computed for this table ([MS-PST] 2.3.4.1 rgib[TCI_bm]). A caller
    // that puts the Row Matrix into blocks has to cut it on that boundary ([MS-PST] 2.3.4.4).
    uint16_t row_size = 0;
    std::vector<LocalSubnode> subnodes;
};

// Builds a Table Context. local_nids is this table node's own subnode NID supply
// ([MS-PST] 2.6.1.2.2: subnode NIDs are not allocated from HEADER.rgnid) and is only used when
// something leaves the heap.
util::Result<TcNode> build_table(const std::vector<TcColumnSpec>& columns,
                                 const std::vector<TcRow>& rows, LocalNids& local_nids,
                                 std::shared_ptr<util::Workspace> workspace = {});

// Input rows are read one at a time. With a workspace, table storage shares its
// memory pool and spills to disk. Legacy callers without one retain the 512 MiB
// cumulative copy-accounting ceiling. Both modes enforce one million rows and
// format limits, returning unsupported without a partial result on overflow.
util::Result<TcNode> build_table_from(const std::vector<TcColumnSpec>& columns,
                                      const TcRowSource& rows, LocalNids& local_nids,
                                      std::shared_ptr<util::Workspace> workspace = {});

// The common case for a table small enough for one heap node: build_table with a supply of its own,
// and the heap image alone. A table that needs a subnode is refused here rather than silently
// losing it.
util::Result<HeapImage> build_tc(const std::vector<TcColumnSpec>& columns,
                                 const std::vector<TcRow>& rows);

} // namespace ost2pst::writer
