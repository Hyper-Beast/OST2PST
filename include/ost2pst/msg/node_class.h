#pragma once

#include <cstdint>

namespace ost2pst::msg {

// What the converter does with a node the source file contains. The three answers are different claims and
// the report never merges them: `carried` says [MS-PST] names the nidType as an object the Messaging layer
// reproduces; `unknown` says a source names the value but defines no structure for it, or neither source
// names it, and the converter says so instead of guessing; `dropped (OST-only)` says something positive says
// a PST does not carry the type.
//
// No nidType earns `dropped (OST-only)` today, and that is deliberate: [MS-PST] 2.2.2.1 having no row for a
// value is silence, not evidence a PST lacks it -- the libpff notes describe real Outlook tables under
// 0x14 .. 0x18 (libpff format notes (see THIRD_PARTY_NOTICES.txt):2402, 2405, 2410-2419). Claiming this disposition needs
// positive evidence about a PST, which is what the Outlook-generated blank PST (M4) is for, never what the
// OST happens to contain.
//
// Neither of the two sources this project has opened (docs/reference/ms-pst.txt,
// libpff format notes (see THIRD_PARTY_NOTICES.txt)) is treated as infallible: a label the libpff notes mark Unknown is
// carried through as Unknown, never rewritten into a table name this project invented.
enum class NodeDisposition {
    kCarried,
    kDroppedOstOnly,
    kUnknown,
};

const char *node_disposition_name(NodeDisposition disposition);

// One nidType as the two opened sources describe it.
struct NodeClass {
    uint32_t nid_type = 0;
    NodeDisposition disposition = NodeDisposition::kUnknown;
    const char *ms_pst_name = "";  // [MS-PST] 2.2.2.1's friendly name; empty when the table has no row
    const char *libpff_label = ""; // the libpff notes' description, verbatim, empty when they have no row
    const char *reason = "";       // why this disposition, naming the section it comes from
};

// Classifies one nidType value ([MS-PST] 2.2.2.1 nidType is the low 5 bits of a NID). Values outside 0x00
// .. 0x1F cannot come out of a NID at all.
NodeClass classify_nid_type(uint32_t nid_type);

} // namespace ost2pst::msg
