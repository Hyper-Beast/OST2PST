#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "ost2pst/ltp/layout.h"
#include "ost2pst/util/status.h"
#include "ost2pst/writer/heap.h"
#include "ost2pst/writer/nid.h"

namespace ost2pst::writer {

// One property the writer puts into a Property Context. [MS-PST] 2.3.3.3 decides where the value
// goes: a single-valued fixed-size type of 4 bytes or less lives inline in dwValueHnid, a
// variable-size value of 3580 bytes or less becomes its own heap allocation, and a longer one
// becomes a subnode of the node whose local NID goes into dwValueHnid ([MS-PST] 2.6.2.2.2).
struct PcProperty {
    uint16_t prop_id = 0;       // [MS-PST] 2.3.3.3 wPropId: the key of the PC's BTH record
    uint16_t prop_type = 0;     // [MS-OXCDATA] 2.11.1 property type id
    std::vector<uint8_t> value; // the value bytes, little-endian for a fixed-size type
    // When set, dwValueHnid is written as this HNID and no heap allocation is made for the value.
    // 0 says the property is present and has no value ([MS-PST] 2.3.3.3, read through
    // ltp::decode_pc_record); a value whose hidType is not NID_TYPE_HID names one of the node's
    // subnodes ([MS-PST] 2.3.3.2).
    std::optional<uint32_t> value_hnid;
    util::SharedBytes source;
};

// A Property Context as the writer emits it: the heap node, plus the subnodes its records name.
// Allocation 1 is the BTHHEADER (cbKey 2, cbEnt 6, bIdxLevels 0), allocation 2 the record array
// sorted by wPropId, and every later allocation one variable-size value in record order
// ([MS-PST] 2.3.3.3 / 2.3.3.6, and the sample PC of 3.8). A value past 3580 bytes takes no
// allocation: it is a subnode, and subnodes come out in record order.
struct PcNode {
    HeapImage heap{ltp::kClientSigPc}; // [MS-PST] 2.3.1.2 bClientSig bTypePC
    std::vector<LocalSubnode> subnodes;
};

// local_nids is this node's own subnode NID supply ([MS-PST] 2.6.1.2.2: subnode NIDs do not come
// from HEADER.rgnid). It is only used when a value leaves the heap.
util::Result<PcNode> build_pc(const std::vector<PcProperty>& properties, LocalNids& local_nids);

} // namespace ost2pst::writer
