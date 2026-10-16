// The seam between the reader and the writer: the extracted SubsetReport for one folder becomes the
// StoreRequest the writer emits. Named identities are deduplicated into the Name-to-ID Map
// belonging to the new store ([MS-PST] 2.4.7.1: an NPID is only an index into its own map, so a
// source NPID never carries over), and a value the source could not give is reported instead of
// invented.
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "ost2pst/msg/subset.h"
#include "ost2pst/util/status.h"
#include "ost2pst/writer/content.h"

namespace ost2pst::msg {

struct EmitOptions {
    // The new folder goes under the IPM_SUBTREE folder of the minimum mailbox so it shows up in the
    // folder tree a real Outlook opens ([MS-PST] 2.7.3.1 lists IPM_SUBTREE among the folders every
    // PST has; the NID itself is allocated by the writer, see writer::kNidIpmsubtree).
    uint32_t parent_nid = writer::kNidIpmsubtree;
    uint64_t max_notes = 40; // how many per-item notes the report keeps before it only counts them
};

// What the conversion handed over, and what it could not hand over.
struct EmitReport {
    uint64_t folders = 0;
    uint64_t messages = 0;
    uint64_t recipients = 0;
    uint64_t attachments = 0;
    uint64_t attachments_without_payload = 0;
    uint64_t attachments_embedded =
        0; // attachments handed over as an embedded Message ([MS-PST] 2.4.6.2.2)
    uint64_t attachments_opaque = 0;
    uint64_t attachment_bytes = 0;
    uint64_t named_identities = 0; // distinct (GUID, name) pairs registered in the new store
    uint64_t named_values = 0;     // property records that carry one of them
    uint64_t named_unresolved = 0; // named records whose name or GUID the source map never gave
    uint64_t values_carried = 0;   // property records handed to the writer with bytes
    uint64_t values_absent = 0;    // records handed over as present with no value
    uint64_t values_dropped = 0;   // records the writer cannot be given this value for
    uint64_t writer_assigned_dropped =
        0;                   // object EntryIDs and row ids/versions the writer regenerates itself
    uint64_t body_plain = 0; // 0x1000 PidTagBody
    uint64_t body_html = 0;  // 0x1013 PidTagHtml
    uint64_t body_rtf = 0;   // 0x1009 PidTagRtfCompressed
    uint64_t body_rtf_framed = 0;   // 0x1009 whose compressed-RTF header adds up
    uint64_t body_rtf_unframed = 0; // 0x1009 whose header does not
    uint64_t messages_without_body = 0;
    std::vector<std::string> notes;
};

struct EmitOutcome {
    writer::StoreRequest request;
    EmitReport report;
};

// Immutable conversion-wide identity numbering. Construct once before any item is emitted;
// full-mode emission never appends identities based on encounter order or renumbers them.
class EmitRegistry {
  public:
    static util::Result<EmitRegistry> build(std::vector<writer::NamedProperty> entries);
    const std::vector<writer::NamedProperty>& entries() const { return entries_; }
    util::Result<uint64_t> find(const std::string& identity_key) const;

  private:
    std::vector<writer::NamedProperty> entries_;
    std::map<std::string, uint64_t> by_identity_;
};

struct EmitItemOutcome {
    writer::ContentMessage message;
    EmitReport report;
};
struct EmitFolderOutcome {
    writer::ContentFolder folder;
    EmitReport report;
};
util::Result<EmitItemOutcome> build_emit_item(const SubsetMessage& item,
                                              const EmitRegistry& registry,
                                              const EmitOptions& options = {});
util::Result<EmitFolderOutcome> build_emit_folder(const SubsetFolder& folder,
                                                  const EmitRegistry& registry,
                                                  const EmitOptions& options = {});

// Turns the content of one folder into a writer request. It never reads a file and never invents a
// value: a value the extractor reported as unreadable is dropped with a note, and the report says
// so.
util::Result<EmitOutcome> build_emit_request(const SubsetReport& subset,
                                             const EmitOptions& options);

} // namespace ost2pst::msg
