// The nidType table read out of the two sources this project has opened, with the gaps left as gaps.
// [MS-PST] 2.2.2.1 (docs/reference/ms-pst.txt:876-907) lists 0x00..0x08, 0x0A..0x13 and 0x1F and says
// nothing about any other value; the libpff notes (libpff format notes (see THIRD_PARTY_NOTICES.txt):845-892) add rows
// for 0x14..0x18 and label each of them Unknown. Neither list is rewritten into a name this project made up.
#include "ost2pst/msg/node_class.h"

#include <cstdint>

namespace ost2pst::msg {

namespace {

// [MS-PST] 2.2.2.1 says of 0x0A and 0x13 only "Internal, persisted view-related". No section in either
// opened source defines what such a node holds, and the libpff notes label both Unknown.
constexpr const char *kViewIndexReason =
    "[MS-PST] 2.2.2.1 names it 'Internal, persisted view-related' and no section in the opened sources "
    "defines what such a node holds; the libpff notes label it Unknown";

} // namespace

const char *node_disposition_name(NodeDisposition disposition) {
    switch (disposition) {
    case NodeDisposition::kCarried:
        return "carried";
    case NodeDisposition::kDroppedOstOnly:
        return "dropped (OST-only)";
    case NodeDisposition::kUnknown:
        return "unknown";
    }
    return "unknown";
}

NodeClass classify_nid_type(uint32_t nid_type) {
    NodeClass out;
    out.nid_type = nid_type;
    switch (nid_type) {
    case 0x00:
        out.disposition = NodeDisposition::kCarried;
        out.ms_pst_name = "NID_TYPE_HID";
        out.libpff_label = "Table value (or heap node)";
        out.reason = "[MS-PST] 2.2.2.1 names it as a heap node; [MS-PST] 2.3.3.2 is what a HNID uses it "
                     "for, so the output allocates its own";
        return out;
    case 0x01:
        out.disposition = NodeDisposition::kCarried;
        out.ms_pst_name = "NID_TYPE_INTERNAL";
        out.libpff_label = "Internal node";
        out.reason = "[MS-PST] 2.2.2.1 / 2.4.1 name the predefined internal nodes the writer emits";
        return out;
    case 0x02:
        out.disposition = NodeDisposition::kCarried;
        out.ms_pst_name = "NID_TYPE_NORMAL_FOLDER";
        out.libpff_label = "Folder item";
        out.reason = "[MS-PST] 2.4.4.1 Folder object PC with 2.4.4.4 hierarchy, 2.4.4.5 contents and "
                     "2.4.4.6 FAI contents tables";
        return out;
    case 0x03:
        out.disposition = NodeDisposition::kCarried;
        out.ms_pst_name = "NID_TYPE_SEARCH_FOLDER";
        out.libpff_label = "Search folder item";
        out.reason = "[MS-PST] 2.4.4.2 names the search Folder template the writer seeds";
        return out;
    case 0x04:
        out.disposition = NodeDisposition::kCarried;
        out.ms_pst_name = "NID_TYPE_NORMAL_MESSAGE";
        out.libpff_label = "Message item";
        out.reason = "[MS-PST] 2.4.5 Message Objects / 2.4.5.1 Message Object PC";
        return out;
    case 0x05:
        out.disposition = NodeDisposition::kCarried;
        out.ms_pst_name = "NID_TYPE_ATTACHMENT";
        out.libpff_label = "Attachment item";
        out.reason = "[MS-PST] 2.4.6 Attachment Objects / 2.4.6.2 Attachment Object PC; 2.4.5 names it as "
                     "an optional subnode of a Message object";
        return out;
    case 0x06:
        out.disposition = NodeDisposition::kCarried;
        out.ms_pst_name = "NID_TYPE_SEARCH_UPDATE_QUEUE";
        out.libpff_label = "Queue of changed search folder items";
        out.reason = "[MS-PST] 2.4.8.1 Search Update Descriptor / 2.4.8.3 Basic Queue Node";
        return out;
    case 0x07:
        out.disposition = NodeDisposition::kCarried;
        out.ms_pst_name = "NID_TYPE_SEARCH_CRITERIA_OBJECT";
        out.libpff_label = "Search folder criteria";
        out.reason = "[MS-PST] 2.2.2.1 names it as the node that defines a search Folder object's "
                     "criteria; the search machinery is [MS-PST] 2.4.8";
        return out;
    case 0x08:
        out.disposition = NodeDisposition::kCarried;
        out.ms_pst_name = "NID_TYPE_ASSOC_MESSAGE";
        out.libpff_label = "Associated contents item";
        out.reason = "[MS-PST] 2.4.4.6 FAI Contents Table holds them and 2.4.5.1 gives a Message object PC";
        return out;
    case 0x0A:
        out.disposition = NodeDisposition::kUnknown;
        out.ms_pst_name = "NID_TYPE_CONTENTS_TABLE_INDEX";
        out.libpff_label = "Unknown (Internal, Persisted View- related)";
        out.reason = kViewIndexReason;
        return out;
    case 0x0B:
        out.disposition = NodeDisposition::kCarried;
        out.ms_pst_name = "NID_TYPE_RECEIVE_FOLDER_TABLE";
        out.libpff_label = "Inbox item (or received folder table)";
        out.reason = "[MS-PST] 2.2.2.1 names it as the Receive Folder object (Inbox); the opened sources "
                     "define no further structure, so the node type is carried without a claimed layout";
        return out;
    case 0x0C:
        out.disposition = NodeDisposition::kCarried;
        out.ms_pst_name = "NID_TYPE_OUTGOING_QUEUE_TABLE";
        out.libpff_label = "Outbox item (or outgoing queue table)";
        out.reason = "[MS-PST] 2.2.2.1 names it as the Outbound queue (Outbox); the opened sources define "
                     "no further structure, so the node type is carried without a claimed layout";
        return out;
    case 0x0D:
        out.disposition = NodeDisposition::kCarried;
        out.ms_pst_name = "NID_TYPE_HIERARCHY_TABLE";
        out.libpff_label = "Sub folders item (or hierarchy table)";
        out.reason = "[MS-PST] 2.4.4.4 Hierarchy Table / 2.4.4.4.1 template";
        return out;
    case 0x0E:
        out.disposition = NodeDisposition::kCarried;
        out.ms_pst_name = "NID_TYPE_CONTENTS_TABLE";
        out.libpff_label = "Sub messages item (or contents table)";
        out.reason = "[MS-PST] 2.4.4.5 Contents Table / 2.4.4.5.1 template";
        return out;
    case 0x0F:
        out.disposition = NodeDisposition::kCarried;
        out.ms_pst_name = "NID_TYPE_ASSOC_CONTENTS_TABLE";
        out.libpff_label = "Sub associated contents item (or associated contents table)";
        out.reason = "[MS-PST] 2.4.4.6 FAI Contents Table / 2.4.4.6.1 template";
        return out;
    case 0x10:
        out.disposition = NodeDisposition::kCarried;
        out.ms_pst_name = "NID_TYPE_SEARCH_CONTENTS_TABLE";
        out.libpff_label = "Search contents table (Consists of an ac table)";
        out.reason = "[MS-PST] 2.2.2.1 names it as the contents table of a search Folder object, the shape "
                     "[MS-PST] 2.4.4.5 defines";
        return out;
    case 0x11:
        out.disposition = NodeDisposition::kCarried;
        out.ms_pst_name = "NID_TYPE_ATTACHMENT_TABLE";
        out.libpff_label = "Attachments item (Consists of a 7c table)";
        out.reason = "[MS-PST] 2.4.6.1 Attachment Table / 2.4.6.1.1 template";
        return out;
    case 0x12:
        out.disposition = NodeDisposition::kCarried;
        out.ms_pst_name = "NID_TYPE_RECIPIENT_TABLE";
        out.libpff_label = "Recipients item (Consists of a 7c table)";
        out.reason = "[MS-PST] 2.4.5.3 Recipient Table, which 2.4.5 says a Message object MUST have";
        return out;
    case 0x13:
        out.disposition = NodeDisposition::kUnknown;
        out.ms_pst_name = "NID_TYPE_SEARCH_TABLE_INDEX";
        out.libpff_label = "Unknown (Internal, Persisted View- related)";
        out.reason = kViewIndexReason;
        return out;
    // 0x14 .. 0x18: [MS-PST] 2.2.2.1 has no row, and the libpff notes label every one of them Unknown
    // (libpff format notes (see THIRD_PARTY_NOTICES.txt):877-889). That is not evidence a converter may drop them -- the
    // same notes describe real Outlook tables under those identifiers, quoted per case below. Unknown is the
    // honest answer, and the report keeps the NID, the type and the label instead of discarding the node.
    case 0x14:
        out.disposition = NodeDisposition::kUnknown;
        out.libpff_label = "Unknown (Related + 18 folder item) (Consists of a 8c table)";
        out.reason = "[MS-PST] 2.2.2.1's nidType table has no row for 0x14 and the libpff notes label it "
                     "Unknown (docs/reference/pff-format.asciidoc:877-879); the same notes describe a folder "
                     "descriptor index +18 as an 8c table over Inbox, Drafts, Sync Issues and Renamed By MAE "
                     "(pff-format.asciidoc:2402), so nothing in the opened sources says the node may be "
                     "dropped";
        return out;
    case 0x15:
        out.disposition = NodeDisposition::kUnknown;
        out.libpff_label = "Unknown (Related + 19 folder item) (Consists of a 8c table)";
        out.reason = "[MS-PST] 2.2.2.1's nidType table has no row for 0x15 and the libpff notes label it "
                     "Unknown (docs/reference/pff-format.asciidoc:880-882); the same notes describe a folder "
                     "descriptor index +19 as an 8c table over CommonViews, Inbox and Calendar "
                     "(pff-format.asciidoc:2405), so nothing in the opened sources says the node may be "
                     "dropped";
        return out;
    case 0x16:
        out.disposition = NodeDisposition::kUnknown;
        out.libpff_label = "Unknown (Unknown 1718 sub item) (Consists of a 7c table)";
        out.reason = "[MS-PST] 2.2.2.1's nidType table has no row for 0x16 and the libpff notes label it "
                     "Unknown (docs/reference/pff-format.asciidoc:883-885); the same notes describe the 1718 "
                     "sub item as a 7c table used by CommonViews, Inbox, Sent Items, Calendar and a long list "
                     "of other real folders, 'Perhaps a Folder View or sort sub item?' "
                     "(pff-format.asciidoc:2410-2419), so nothing in the opened sources says the node may be "
                     "dropped";
        return out;
    case 0x17:
        out.disposition = NodeDisposition::kUnknown;
        out.libpff_label = "Unknown (Unknown 1751 sub item)";
        out.reason = "[MS-PST] 2.2.2.1's nidType table has no row for 0x17 and the libpff notes label it "
                     "Unknown (docs/reference/pff-format.asciidoc:886-887); the same notes list 1751 as a "
                     "'Possible other sub item' of the same kind (pff-format.asciidoc:2425-2431), so nothing "
                     "in the opened sources says the node may be dropped";
        return out;
    case 0x18:
        out.disposition = NodeDisposition::kUnknown;
        out.libpff_label = "Unknown (Unknown 1784 sub item)";
        out.reason = "[MS-PST] 2.2.2.1's nidType table has no row for 0x18 and the libpff notes label it "
                     "Unknown (docs/reference/pff-format.asciidoc:888-889); the same notes list 1784 as a "
                     "'Possible other sub item' of the same kind (pff-format.asciidoc:2425-2431), so nothing "
                     "in the opened sources says the node may be dropped";
        return out;
    case 0x1F:
        out.disposition = NodeDisposition::kCarried;
        out.ms_pst_name = "NID_TYPE_LTP";
        out.libpff_label = "Local descriptor value";
        out.reason = "[MS-PST] 2.4.5 names it as the subnode holding raw LTP data for a Message object PC";
        return out;
    default:
        break;
    }
    out.disposition = NodeDisposition::kUnknown;
    out.reason = "neither [MS-PST] 2.2.2.1's nidType table nor the libpff notes have a row for this value";
    return out;
}

} // namespace ost2pst::msg
