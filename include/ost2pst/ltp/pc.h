#pragma once

#include <cstdint>
#include <functional>

#include "ost2pst/ltp/bth.h"
#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/prop_type.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ltp {

// [MS-PST] 2.3.3.3 PC BTH record: wPropId is the key, then the data holds wPropType and dwValueHnid.
// Which of the two dwValueHnid holds -- the value itself or a reference to it -- is decided by the
// property type, so the record carries that decision instead of hiding it.
struct PcRecord {
    uint16_t prop_id = 0;
    uint16_t prop_type = 0;
    uint32_t value_hnid = 0;
    bool value_inline = false;     // [MS-PST] 2.3.3.3 fixed-size type of 4 bytes or less
    bool value_absent = false;     // [MS-PST] 2.3.3.2 / 2.3.3.3: dwValueHnid 0 is neither a HID nor a subnode NID, so the property has no value
    bool value_in_heap = false;    // [MS-PST] 2.3.3.2 hidType == NID_TYPE_HID: the data block
    bool value_in_subnode = false; // [MS-PST] 2.3.3.2 otherwise: the subnode block
    util::ByteView value;          // the four dwValueHnid bytes, only when the value is inline
    uint64_t offset = 0;           // absolute file offset of the record
    uint64_t position = 0;         // index within the leaf array, in key order
};

util::Result<PcRecord> decode_pc_record(util::ByteView record);

using PcCallback = std::function<bool(const PcRecord &record)>;

// Reads a property context: the containing HN's hidUserRoot names the allocation holding the BTHHEADER
// and that header's hidRoot names the record array ([MS-PST] 2.3.3.1 / 2.3.3.6). The header must carry
// the PC record shape, cbKey 2 and cbEnt 6 ([MS-PST] 2.3.3), which is what says this HN really is a PC.
// Records come out in property-id order because a PC is a BTH. The profile decides the HID widths the
// walk needs ([MS-PST] 2.3.1.1).
util::Status read_pc(const HnHeader &hn_header, ndb::FileProfile profile, HeapSource &source,
                     const PcCallback &callback, BthStats &stats, ndb::FailureLog &failures);

} // namespace ost2pst::ltp
