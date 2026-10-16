// ost2pst: the writer CLI. --empty writes a blank Unicode 512-byte-page PST
// ([MS-PST] 2.2.2.7, 2.7.2) out of nothing; --folder converts one folder of a real OST into a new
// store. Both modes re-read the file they just wrote with the same readers this project uses on
// real mailboxes, because a writer that never opens its own bytes can only claim it wrote
// something, not that the bytes mean what they should.
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <fcntl.h> // _O_CREAT / _O_EXCL / _O_TRUNC
#include <io.h>    // _wopen / _write / _close
#include <string>
#include <vector>

#include "ost2pst/ltp/ltp_read.h"
#include "ost2pst/ltp/node_open.h"
#include "ost2pst/msg/emit.h"
#include "ost2pst/msg/subset.h"
#include "ost2pst/ndb/probe.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/status.h"
#include "ost2pst/writer/content.h"
#include "ost2pst/writer/empty_pst.h"

#include "full_conversion.h"
#include "read_only.h"

namespace {

enum ExitCode : int {
    kExitOk = 0,
    kExitUsage = 1,
    kExitIo = 1,
    kExitRefusal = 2,
    kExitFindings = 3,
};

void print_usage() {
    printf("ost2pst - [MS-PST] writer\n");
    printf("\n");
    printf("  ost2pst --empty <file>\n");
    printf("      write a blank Unicode PST, then re-read it\n");
    printf("  ost2pst [--resume] <in.ost> <out.pst>\n");
    printf("      convert the full mailbox with durable item outcomes and reports\n");
    printf("  ost2pst --dry-run <input> [output]\n");
    printf("      check physical structures and plan the mailbox without writing files\n");
    printf("  ost2pst --verify <file>\n");
    printf("      verify NDB/LTP structures without modifying the file\n");
    printf("  ost2pst --folder <NID> <in.ost> <out.pst>\n");
    printf("      convert one folder of an OST: its Message objects, their Recipient and\n");
    printf("      Attachment Tables, the Attachment objects those Tables name, and the named\n");
    printf("      properties those items use, into a new store built from the minimum mailbox\n");
    printf("  --max-messages <N>   with --folder, cap the Message objects taken from the folder\n");
    printf("                       (default 64)\n");
    printf("  --force              allow overwriting an existing output file\n");
    printf("  --help               this text\n");
    printf("\n");
    printf("exit: 0 success, 1 usage/IO/operational failure, 2 unsupported input format,\n");
    printf("      3 corrupt input, verification findings or incomplete conversion\n");
}

bool parse_positive(const std::wstring& text, int base, uint64_t& value) {
    if (text.empty() || text.front() < L'0' || text.front() > L'9')
        return false;
    errno = 0;
    wchar_t* end = nullptr;
    value = std::wcstoull(text.c_str(), &end, base);
    return errno == 0 && end != text.c_str() && *end == L'\0' && value != 0;
}

// The default must not destroy a file the user already has: a mistyped output path pointing at a
// real mailbox would otherwise be truncated before anything was checked. _O_CREAT | _O_EXCL makes
// the existence check and the open one operation, so a refusal leaves the original bytes alone and
// nothing can slip in between them. --force is the explicit way to say overwrite, and it truncates
// instead of writing over the front of a longer file. Measured here rather than read out of a
// document: _wfopen with the MSVC x mode never returns on this CRT (the process sits at the call
// and no file appears), so the exclusive create goes through _wopen.
struct WriteOutcome {
    bool ok = false;
    bool exists = false;
    int error = 0;
};

WriteOutcome write_file(const std::wstring& path, const std::vector<uint8_t>& bytes, bool force) {
    WriteOutcome outcome;
    const int flags = _O_WRONLY | _O_BINARY | _O_CREAT | (force ? _O_TRUNC : _O_EXCL);
    int descriptor = _wopen(path.c_str(), flags, _S_IREAD | _S_IWRITE);
    if (descriptor < 0) {
        outcome.exists = errno == EEXIST;
        outcome.error = errno;
        return outcome;
    }
    const char* data = reinterpret_cast<const char*>(bytes.data());
    size_t left = bytes.size();
    while (left != 0) {
        const unsigned chunk = static_cast<unsigned>(left < (1u << 30) ? left : (1u << 30));
        const int written = _write(descriptor, data, chunk);
        if (written <= 0) {
            outcome.error = errno;
            _close(descriptor);
            return outcome;
        }
        data += written;
        left -= static_cast<size_t>(written);
    }
    if (_close(descriptor) != 0) {
        outcome.error = errno;
        return outcome;
    }
    outcome.ok = true;
    return outcome;
}

void print_failures(uint64_t total, const std::vector<ost2pst::ndb::ProbeFailure>& failures) {
    if (total == 0) {
        return;
    }
    printf("FAILURES (%llu)\n", static_cast<unsigned long long>(total));
    for (const ost2pst::ndb::ProbeFailure& failure : failures) {
        printf("  %s at 0x%llx (value 0x%llx): %s\n", failure.field.c_str(),
               static_cast<unsigned long long>(failure.offset),
               static_cast<unsigned long long>(failure.value), failure.detail.c_str());
    }
}

// Opens the file the writer just produced and runs the two readers on it. The verdict in the exit
// code is theirs, not a guess made from the counts printed above.
int reread(const std::wstring& output, uint64_t expected_bytes) {
    ost2pst::util::Result<ost2pst::util::FileReader> opened =
        ost2pst::util::FileReader::open(output);
    if (!opened.ok()) {
        std::fprintf(stderr, "cannot re-open %ls: %s\n", output.c_str(),
                     ost2pst::util::format_error(opened.error()).c_str());
        return kExitIo;
    }
    const ost2pst::util::FileReader& file = opened.value();
    if (file.size() != expected_bytes) {
        std::fprintf(stderr, "%ls is %llu bytes, the writer wrote %llu\n", output.c_str(),
                     static_cast<unsigned long long>(file.size()),
                     static_cast<unsigned long long>(expected_bytes));
        return kExitIo;
    }

    ost2pst::util::Result<ost2pst::ndb::ProbeReport> probed =
        ost2pst::ndb::probe_file(file, ost2pst::ndb::ProbeOptions());
    if (!probed.ok()) {
        std::fprintf(stderr, "probe failed on %ls: %s\n", output.c_str(),
                     ost2pst::util::format_error(probed.error()).c_str());
        return kExitIo;
    }
    const ost2pst::ndb::ProbeReport& probe = probed.value();
    printf("re-read (ndb::probe_file)\n");
    printf("  profile           %s\n", ost2pst::ndb::file_profile_name(probe.profile));
    printf("  header CRCs       partial %s, full %s\n",
           probe.header_crcs.partial_ok ? "ok" : "FAILED",
           probe.header_crcs.full_ok ? "ok" : "FAILED");
    printf("  blocks            %llu, BBT entries %llu, NBT entries %llu\n",
           static_cast<unsigned long long>(probe.counters.blocks.verified),
           static_cast<unsigned long long>(probe.counters.bbt_index_entries),
           static_cast<unsigned long long>(probe.counters.nbt_entries));
    print_failures(probe.failure_total, probe.failures);

    ost2pst::util::Result<ost2pst::ltp::LtpReadReport> read =
        ost2pst::ltp::read_ltp(file, ost2pst::ltp::LtpReadOptions());
    if (!read.ok()) {
        std::fprintf(stderr, "ltp read failed on %ls: %s\n", output.c_str(),
                     ost2pst::util::format_error(read.error()).c_str());
        return kExitIo;
    }
    const ost2pst::ltp::LtpReadReport& ltp = read.value();
    printf("re-read (ltp::read_ltp)\n");
    printf("  PCs               %llu, TCs %llu (%llu with rows)\n",
           static_cast<unsigned long long>(ltp.pcs.contexts),
           static_cast<unsigned long long>(ltp.tcs.contexts),
           static_cast<unsigned long long>(ltp.tcs.rows));
    uint64_t messages = 0;
    for (const ost2pst::ltp::LtpFolder& folder : ltp.folders) {
        messages += folder.messages;
    }
    printf("  folders           %llu, messages %llu, named properties %llu\n",
           static_cast<unsigned long long>(ltp.folders.size()),
           static_cast<unsigned long long>(messages),
           static_cast<unsigned long long>(ltp.named_properties));
    print_failures(ltp.failure_total, ltp.failures);
    for (const ost2pst::ltp::LtpFinding& finding : ltp.findings.items) {
        printf("  finding: NID 0x%llx type 0x%llx bid 0x%llx %s: %s\n",
               static_cast<unsigned long long>(finding.nid),
               static_cast<unsigned long long>(finding.nid_type),
               static_cast<unsigned long long>(finding.bid), finding.field.c_str(),
               finding.detail.c_str());
    }

    const bool clean = probe.clean && !probe.refusal && ltp.clean && !ltp.refusal;
    // The verdict on the bytes of the store that was written, not on the conversion: a run that
    // could not read part of the source still writes a structurally clean store.
    printf("\nRE-READ RESULT: %s\n", clean ? "clean" : "findings present");
    return clean ? kExitOk : kExitFindings;
}

int run_empty(const std::wstring& output, bool force) {
    ost2pst::util::Result<ost2pst::writer::EmptyPstImage> built =
        ost2pst::writer::build_empty_pst();
    if (!built.ok()) {
        std::fprintf(stderr, "writing %ls failed: %s\n", output.c_str(),
                     ost2pst::util::format_error(built.error()).c_str());
        return kExitIo;
    }
    const ost2pst::writer::EmptyPstImage& image = built.value();
    const WriteOutcome written = write_file(output, image.bytes, force);
    if (!written.ok) {
        if (written.exists) {
            std::fprintf(stderr, "%ls already exists, refusing to overwrite it (pass --force)\n",
                         output.c_str());
        } else {
            std::fprintf(stderr, "cannot write %ls: %s\n", output.c_str(),
                         std::strerror(written.error));
        }
        return kExitIo;
    }

    printf("wrote %ls\n", output.c_str());
    printf("  image size        %llu bytes\n", static_cast<unsigned long long>(image.bytes.size()));
    printf("  blocks            %llu, bidNextB %llu, bidNextP %llu\n",
           static_cast<unsigned long long>(image.blocks.size()),
           static_cast<unsigned long long>(image.bid_next_b),
           static_cast<unsigned long long>(image.bid_next_p));
    printf("  BBT root          ib 0x%llx, NBT root ib 0x%llx\n",
           static_cast<unsigned long long>(image.bbt_root_ib),
           static_cast<unsigned long long>(image.nbt_root_ib));
    printf("  AMap              %llu bits set, cbAMapFree %llu\n",
           static_cast<unsigned long long>(image.amap_bits_set),
           static_cast<unsigned long long>(image.cb_amap_free));
    return reread(output, image.bytes.size());
}

// What went from the source folder into the new store, in the order the pipeline produced it: the
// extractor says what the source held, the emitter says what it handed the writer, the writer says
// what it put in the file. Reading only the last one would hide a value that stopped at an earlier
// step.
void print_conversion(const ost2pst::msg::SubsetReport& subset,
                      const ost2pst::msg::EmitReport& emitted,
                      const ost2pst::writer::ContentReport& written) {
    printf("CONVERSION\n");
    printf("  source folder     0x%08llX %s\n", static_cast<unsigned long long>(subset.folder.nid),
           subset.folder.name.empty() ? "(no name the reader could decode)"
                                      : subset.folder.name.c_str());
    if (!written.folder_nids.empty()) {
        printf("  new folder        0x%08llX (the NID this store allocated for the converted "
               "folder)\n",
               static_cast<unsigned long long>(written.folder_nids.front()));
    }
    printf("  messages          %llu read (%llu the folder names, %llu reached through an "
           "Attachment\n",
           static_cast<unsigned long long>(subset.messages_read + subset.attachments_embedded),
           static_cast<unsigned long long>(subset.messages_read),
           static_cast<unsigned long long>(subset.attachments_embedded));
    printf("                    object), %llu handed over, %llu written, %llu skipped\n",
           static_cast<unsigned long long>(emitted.messages),
           static_cast<unsigned long long>(written.messages),
           static_cast<unsigned long long>(subset.messages_skipped));
    printf("  recipients        %llu rows read, %llu written\n",
           static_cast<unsigned long long>(subset.recipients_read),
           static_cast<unsigned long long>(written.recipients));
    printf("  attachments       %llu objects read, %llu written, %llu with no carried 0x3701 "
           "content\n",
           static_cast<unsigned long long>(subset.attachments_read),
           static_cast<unsigned long long>(written.attachments),
           static_cast<unsigned long long>(emitted.attachments_without_payload));
    printf("  attached Messages %llu read out of Attachment objects, %llu written as their "
           "subnodes,\n",
           static_cast<unsigned long long>(subset.attachments_embedded),
           static_cast<unsigned long long>(written.embedded_messages));
    printf("                    %llu bytes of data blocks under them ([MS-PST] 2.4.6.2.2)\n",
           static_cast<unsigned long long>(written.embedded_bytes));
    printf("  opaque objects    %llu read, %llu written as object-data subnodes\n",
           static_cast<unsigned long long>(subset.attachments_opaque),
           static_cast<unsigned long long>(written.opaque_objects));
    printf("  object values     %llu PtypObject records read ([MS-PST] 2.3.3.5), %llu carried as\n",
           static_cast<unsigned long long>(subset.object_values),
           static_cast<unsigned long long>(subset.object_values_carried));
    printf("                    a Message or opaque object, %llu this reader could not carry\n",
           static_cast<unsigned long long>(subset.object_values > subset.object_values_carried
                                               ? subset.object_values - subset.object_values_carried
                                               : 0));
    printf("  payload           %llu bytes read from the source, %llu written, largest %llu\n",
           static_cast<unsigned long long>(subset.payload_bytes),
           static_cast<unsigned long long>(written.attachment_bytes),
           static_cast<unsigned long long>(subset.max_payload_bytes));
    printf("  bodies source     %llu plain 0x1000, %llu HTML 0x1013, %llu RTF 0x1009, %llu with "
           "none\n",
           static_cast<unsigned long long>(subset.body_plain),
           static_cast<unsigned long long>(subset.body_html),
           static_cast<unsigned long long>(subset.body_rtf),
           static_cast<unsigned long long>(subset.body_none));
    printf(
        "  bodies written    %llu plain, %llu HTML, %llu RTF (%llu with a compressed-RTF header\n",
        static_cast<unsigned long long>(emitted.body_plain),
        static_cast<unsigned long long>(emitted.body_html),
        static_cast<unsigned long long>(emitted.body_rtf),
        static_cast<unsigned long long>(emitted.body_rtf_framed));
    printf("                    that adds up, %llu without), %llu written with no body\n",
           static_cast<unsigned long long>(emitted.body_rtf_unframed),
           static_cast<unsigned long long>(emitted.messages_without_body));
    printf("  named source      %llu distinct identities, %llu values the map never named\n",
           static_cast<unsigned long long>(subset.named_tags),
           static_cast<unsigned long long>(subset.named_unresolved));
    printf("  named new store   %llu identities registered, %llu values carried under a new NPID\n",
           static_cast<unsigned long long>(written.named_properties),
           static_cast<unsigned long long>(emitted.named_values));
    printf("  named dropped     %llu values the emitter could not register because the source map "
           "left\n",
           static_cast<unsigned long long>(emitted.named_unresolved));
    printf("                    the identity without a name or a property set\n");
    printf("  values            %llu written with bytes, %llu present with no value, %llu the "
           "emitter\n",
           static_cast<unsigned long long>(written.values_written),
           static_cast<unsigned long long>(subset.values_absent),
           static_cast<unsigned long long>(emitted.values_dropped));
    printf("                    could not hand over, %llu the writer could not place, %llu "
           "regenerated\n",
           static_cast<unsigned long long>(written.values_dropped),
           static_cast<unsigned long long>(emitted.writer_assigned_dropped));
    printf("                    by the writer (EntryID, row id)\n");
    printf("  required tags     %llu [MS-PST] 2.4.5.1.1 tags the source did not carry\n",
           static_cast<unsigned long long>(written.required_missing));
    printf("  file              %llu bytes, %llu blocks\n",
           static_cast<unsigned long long>(written.file_bytes),
           static_cast<unsigned long long>(written.blocks));
    if (!subset.notes.empty() || !emitted.notes.empty() || !written.notes.empty()) {
        printf("NOTES\n");
        for (const std::string& note : subset.notes) {
            printf("  extractor: %s\n", note.c_str());
        }
        for (const std::string& note : emitted.notes) {
            printf("  emitter:   %s\n", note.c_str());
        }
        for (const std::string& note : written.notes) {
            printf("  writer:    %s\n", note.c_str());
        }
    }
    if (!subset.skipped.empty()) {
        printf("SKIPPED\n");
        for (const std::string& item : subset.skipped) {
            printf("  %s\n", item.c_str());
        }
    }
}

// The conversion only counts as done when the writer put into the file what the extractor read out
// of the source. Anything else is a shortfall the exit code has to name, not a line in a report
// that still exits zero.
void print_shortfall(const ost2pst::msg::SubsetReport& extracted,
                     const ost2pst::msg::EmitReport& emitted,
                     const ost2pst::writer::ContentReport& written, uint64_t max_messages) {
    printf("CONVERSION INCOMPLETE\n");
    if (extracted.unreadable_values != 0) {
        printf("  unreadable      %llu source values could not be read\n",
               static_cast<unsigned long long>(extracted.unreadable_values));
    }
    if (written.folders != 1) {
        printf("  folders         %llu written, 1 read\n",
               static_cast<unsigned long long>(written.folders));
    }
    if (written.messages != extracted.messages_read + extracted.attachments_embedded) {
        printf("  messages        %llu written, %llu read (%llu folder + %llu attached)\n",
               static_cast<unsigned long long>(written.messages),
               static_cast<unsigned long long>(extracted.messages_read +
                                               extracted.attachments_embedded),
               static_cast<unsigned long long>(extracted.messages_read),
               static_cast<unsigned long long>(extracted.attachments_embedded));
    }
    if (written.embedded_messages != extracted.attachments_embedded) {
        printf("  attached Message %llu written, %llu read out of Attachment objects\n",
               static_cast<unsigned long long>(written.embedded_messages),
               static_cast<unsigned long long>(extracted.attachments_embedded));
    }
    if (written.recipients != extracted.recipients_read) {
        printf("  recipients      %llu written, %llu read\n",
               static_cast<unsigned long long>(written.recipients),
               static_cast<unsigned long long>(extracted.recipients_read));
    }
    if (written.attachments != extracted.attachments_read) {
        printf("  attachments     %llu written, %llu read\n",
               static_cast<unsigned long long>(written.attachments),
               static_cast<unsigned long long>(extracted.attachments_read));
    }
    if (written.attachment_bytes != emitted.attachment_bytes) {
        printf("  payload         %llu written, %llu handed over\n",
               static_cast<unsigned long long>(written.attachment_bytes),
               static_cast<unsigned long long>(emitted.attachment_bytes));
    }
    if (written.named_properties != emitted.named_identities) {
        printf("  named           %llu registered, %llu handed over\n",
               static_cast<unsigned long long>(written.named_properties),
               static_cast<unsigned long long>(emitted.named_identities));
    }
    if (emitted.values_dropped != 0) {
        printf("  values          %llu the emitter could not hand over\n",
               static_cast<unsigned long long>(emitted.values_dropped));
    }
    if (written.values_dropped != 0) {
        printf("  values          %llu the writer could not place\n",
               static_cast<unsigned long long>(written.values_dropped));
    }
    if (extracted.rows_without_cells != 0) {
        printf("  rows            %llu named a slot past their Row Matrix\n",
               static_cast<unsigned long long>(extracted.rows_without_cells));
    }
    if (extracted.messages_without_pc != 0) {
        printf("  messages        %llu the extractor could not read the Property Context of\n",
               static_cast<unsigned long long>(extracted.messages_without_pc));
    }
    if (extracted.recipient_table_failures != 0) {
        printf("  recipient table %llu tables the source has and the reader could not read\n",
               static_cast<unsigned long long>(extracted.recipient_table_failures));
    }
    if (extracted.attachment_table_failures != 0) {
        printf("  attach table    %llu tables the source has and the reader could not read\n",
               static_cast<unsigned long long>(extracted.attachment_table_failures));
    }
    if (extracted.attachment_pc_failures != 0) {
        printf("  attachments     %llu objects whose Property Context did not read\n",
               static_cast<unsigned long long>(extracted.attachment_pc_failures));
    }
    if (extracted.subnode_walk_failures != 0 || extracted.subnode_walks_incomplete != 0) {
        printf("  subnodes        %llu walks failed, %llu stopped before they enumerated every "
               "entry\n",
               static_cast<unsigned long long>(extracted.subnode_walk_failures),
               static_cast<unsigned long long>(extracted.subnode_walks_incomplete));
    }
    if (extracted.row_index_walks_incomplete != 0) {
        printf("  row index       %llu table RowIndex walks stopped before the end\n",
               static_cast<unsigned long long>(extracted.row_index_walks_incomplete));
    }
    if (extracted.object_values != extracted.object_values_carried) {
        printf("  object values   %llu read, %llu carried as a Message or opaque object, %llu the "
               "reader could\n",
               static_cast<unsigned long long>(extracted.object_values),
               static_cast<unsigned long long>(extracted.object_values_carried),
               static_cast<unsigned long long>(extracted.object_values -
                                               extracted.object_values_carried));
        printf("                    not carry ([MS-PST] 2.3.3.5)\n");
    }
    if (extracted.attachments_with_unread_object != 0) {
        printf("  object content   %llu Attachment objects whose 0x3701 object the source has and "
               "this reader\n",
               static_cast<unsigned long long>(extracted.attachments_with_unread_object));
        printf("                    could not carry as a Message ([MS-PST] 2.4.6.2.2)\n");
    }
    if (extracted.matrix_short_blocks != 0) {
        printf("  row matrix      %llu blocks short of the full block [MS-PST] 2.3.4.4 requires\n",
               static_cast<unsigned long long>(extracted.matrix_short_blocks));
    }
    if (extracted.capped) {
        printf("  cap             the %llu-message cap stopped this folder short\n",
               static_cast<unsigned long long>(max_messages));
    }
}

// Report both missing payloads and failed reads, without treating them as equivalent.
// A source value that cannot be read also makes conversion_complete() false.
void print_source_gaps(const ost2pst::msg::SubsetReport& extracted) {
    if (extracted.attachments_without_payload == 0 && extracted.unreadable_values == 0) {
        return;
    }
    printf("NOT CARRIED FROM SOURCE\n");
    if (extracted.attachments_without_payload != 0) {
        printf("  attachments     %llu of %llu carry no 0x3701 bytes and no object this reader "
               "could carry,\n",
               static_cast<unsigned long long>(extracted.attachments_without_payload),
               static_cast<unsigned long long>(extracted.attachments_read));
        printf("                  so the new store writes the Attachment object with its other "
               "properties\n");
        printf("                  and no 0x3701 ([MS-PST] 2.4.6.2.2)\n");
    }
    if (extracted.unreadable_values != 0) {
        printf("  values          %llu records the source had and the reader could not get the "
               "content of\n",
               static_cast<unsigned long long>(extracted.unreadable_values));
    }
}

bool conversion_complete(const ost2pst::msg::SubsetReport& extracted,
                         const ost2pst::msg::EmitReport& emitted,
                         const ost2pst::writer::ContentReport& written) {
    return written.folders == 1 &&
           written.messages == extracted.messages_read + extracted.attachments_embedded &&
           written.embedded_messages == extracted.attachments_embedded &&
           written.opaque_objects == extracted.attachments_opaque &&
           emitted.attachments_opaque == extracted.attachments_opaque &&
           written.recipients == extracted.recipients_read &&
           written.attachments == extracted.attachments_read &&
           written.attachment_bytes == emitted.attachment_bytes &&
           written.named_properties == emitted.named_identities && written.values_dropped == 0 &&
           emitted.values_dropped == 0 && extracted.unreadable_values == 0 &&
           extracted.rows_without_cells == 0 && !extracted.capped &&
           // A read that failed partway is a shortfall even when the writer wrote every byte the
           // extractor managed to hand over: the counts agree because both stopped at the same
           // place.
           extracted.messages_without_pc == 0 && extracted.recipient_table_failures == 0 &&
           extracted.attachment_table_failures == 0 && extracted.attachment_pc_failures == 0 &&
           extracted.subnode_walk_failures == 0 && extracted.subnode_walks_incomplete == 0 &&
           extracted.row_index_walks_incomplete == 0 && extracted.matrix_short_blocks == 0 &&
           extracted.attachments_with_unread_object == 0 &&
           extracted.object_values == extracted.object_values_carried;
}

int run_folder(const std::wstring& input, const std::wstring& output, uint64_t folder_nid,
               uint64_t max_messages, bool force) {
    ost2pst::util::Result<ost2pst::util::FileReader> opened =
        ost2pst::util::FileReader::open_stable(input);
    if (!opened.ok()) {
        std::fprintf(stderr, "cannot open %ls: %s\n", input.c_str(),
                     ost2pst::util::format_error(opened.error()).c_str());
        return kExitIo;
    }
    const ost2pst::util::FileReader& file = opened.value();

    const auto valid = ost2pst::cli::validate_input(file);
    if (!valid.ok())
        return ost2pst::cli::report_input_error(valid.error());

    // A folder conversion needs the NID map and the BBT index the LTP read builds, but not the
    // census of every data block or the folder walk: the extractor opens only the nodes this folder
    // names.
    ost2pst::ltp::LtpReadOptions options;
    options.scan_blocks = false;
    options.build_folders = false;
    options.dump_requested = false;
    ost2pst::util::Result<ost2pst::ltp::LtpReadReport> read = ost2pst::ltp::read_ltp(file, options);
    if (!read.ok()) {
        std::fprintf(stderr, "ltp read failed on %ls: %s\n", input.c_str(),
                     ost2pst::util::format_error(read.error()).c_str());
        return ost2pst::cli::input_error_exit(read.error());
    }
    const ost2pst::ltp::LtpReadReport& census = read.value();
    if (census.refusal) {
        printf("REFUSAL\n  %s\n", ost2pst::util::format_error(*census.refusal).c_str());
        return kExitRefusal;
    }

    ost2pst::ndb::BlockReadCounters counters;
    ost2pst::ndb::FailureLog failures(20);
    ost2pst::ltp::FileBlockSource blocks(file, census.profile, census.bbt_index, counters,
                                         failures);
    ost2pst::msg::SubsetOptions subset_options;
    subset_options.max_messages = max_messages;
    ost2pst::util::Result<ost2pst::msg::SubsetReport> subset =
        ost2pst::msg::build_subset(census, blocks, folder_nid, subset_options);
    if (!subset.ok()) {
        std::fprintf(stderr, "folder 0x%llX could not be read out of %ls: %s\n",
                     static_cast<unsigned long long>(folder_nid), input.c_str(),
                     ost2pst::util::format_error(subset.error()).c_str());
        return kExitIo;
    }
    const ost2pst::msg::SubsetReport& extracted = subset.value();

    ost2pst::util::Result<ost2pst::msg::EmitOutcome> emitted =
        ost2pst::msg::build_emit_request(extracted, ost2pst::msg::EmitOptions());
    if (!emitted.ok()) {
        std::fprintf(stderr, "folder 0x%llX could not be turned into a writer request: %s\n",
                     static_cast<unsigned long long>(folder_nid),
                     ost2pst::util::format_error(emitted.error()).c_str());
        return kExitIo;
    }

    ost2pst::util::Result<ost2pst::writer::StoreOutcome> built =
        ost2pst::writer::build_store(emitted.value().request);
    if (!built.ok()) {
        std::fprintf(stderr, "writing %ls failed: %s\n", output.c_str(),
                     ost2pst::util::format_error(built.error()).c_str());
        return kExitIo;
    }
    const ost2pst::writer::StoreOutcome& store = built.value();

    const WriteOutcome written = write_file(output, store.image.bytes, force);
    if (!written.ok) {
        if (written.exists) {
            std::fprintf(stderr, "%ls already exists, refusing to overwrite it (pass --force)\n",
                         output.c_str());
        } else {
            std::fprintf(stderr, "cannot write %ls: %s\n", output.c_str(),
                         std::strerror(written.error));
        }
        return kExitIo;
    }

    printf("wrote %ls\n", output.c_str());
    print_conversion(extracted, emitted.value().report, store.report);
    const bool complete = conversion_complete(extracted, emitted.value().report, store.report);
    const int status = reread(output, store.image.bytes.size());
    if (!complete) {
        print_shortfall(extracted, emitted.value().report, store.report,
                        subset_options.max_messages);
    }
    print_source_gaps(extracted);
    printf("\nCONVERSION RESULT: %s\n", complete ? "complete" : "incomplete");
    if (status != kExitOk) {
        return status;
    }
    return complete ? kExitOk : kExitFindings;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    const wchar_t kDash = static_cast<wchar_t>(45); // the dash that starts an option
    std::wstring input;
    std::wstring output;
    uint64_t folder_nid = 0;
    uint64_t max_messages = 64;
    bool force = false;
    bool empty_mode = false;
    bool resume = false;
    bool cap_given = false;
    bool dry_run = false;
    bool verify = false;
    bool events_json = false;
    for (int index = 1; index < argc; ++index) {
        const std::wstring argument = argv[index];
        if (argument == L"--events-json") {
            events_json = true;
            continue;
        }
        if (argument == L"--help" || argument == L"-h") {
            print_usage();
            return kExitOk;
        }
        if (argument == L"--force") {
            force = true;
            continue;
        }
        if (argument == L"--dry-run") {
            dry_run = true;
            continue;
        }
        if (argument == L"--verify") {
            verify = true;
            continue;
        }
        if (argument == L"--resume") {
            resume = true;
            continue;
        }
        if (argument == L"--empty") {
            empty_mode = true;
            continue;
        }
        if (argument == L"--folder") {
            if (index + 1 >= argc) {
                std::fprintf(stderr, "--folder needs a NID\n");
                print_usage();
                return kExitUsage;
            }
            const std::wstring value = argv[++index];
            if (folder_nid != 0 || !parse_positive(value, 0, folder_nid) ||
                folder_nid > UINT32_MAX) {
                std::fprintf(stderr, "--folder needs a NID, got %ls\n", value.c_str());
                return kExitUsage;
            }
            continue;
        }
        if (argument == L"--max-messages") {
            cap_given = true;
            if (index + 1 >= argc) {
                std::fprintf(stderr, "--max-messages needs a count\n");
                print_usage();
                return kExitUsage;
            }
            const std::wstring value = argv[++index];
            if (!parse_positive(value, 10, max_messages)) {
                std::fprintf(stderr, "--max-messages needs a count above zero\n");
                return kExitUsage;
            }
            continue;
        }
        if (!argument.empty() && argument[0] == kDash) {
            std::fprintf(stderr, "unknown argument: %ls\n", argument.c_str());
            print_usage();
            return kExitUsage;
        }
        if (input.empty()) {
            input = argument;
        } else if (output.empty()) {
            output = argument;
        } else {
            std::fprintf(stderr, "too many file arguments: %ls\n", argument.c_str());
            return kExitUsage;
        }
    }

    if (events_json && (dry_run || verify || empty_mode || folder_nid != 0 || cap_given || force ||
                        input.empty() || output.empty())) {
        std::fprintf(stderr, "--events-json requires full conversion or full resume\n");
        return kExitUsage;
    }
    if (dry_run || verify) {
        if ((dry_run && verify) || empty_mode || folder_nid != 0 || cap_given || force || resume ||
            input.empty() || (verify && !output.empty())) {
            std::fprintf(stderr, "read-only modes require an input and reject conversion flags; "
                                 "--verify accepts one file\n");
            return kExitUsage;
        }
        return ost2pst::cli::run_read_only(input, output, dry_run);
    }
    if (folder_nid != 0) {
        if (resume || empty_mode) {
            std::fprintf(stderr, "--folder cannot be combined with --resume or --empty\n");
            return kExitUsage;
        }
        if (input.empty() || output.empty()) {
            std::fprintf(stderr, "--folder needs an input OST and an output PST\n");
            print_usage();
            return kExitUsage;
        }
        return run_folder(input, output, folder_nid, max_messages, force);
    }
    if (empty_mode || input.empty()) {
        if (resume || cap_given || !output.empty()) {
            std::fprintf(
                stderr,
                "--resume needs full-mode input and output; --max-messages needs --folder\n");
            return kExitUsage;
        }
        // --empty <file> arrives as the first positional, so the one file named is the output.
        output = input;
        if (output.empty()) {
            print_usage();
            return kExitUsage;
        }
        return run_empty(output, force);
    }
    if (output.empty() || force || cap_given) {
        std::fprintf(
            stderr,
            "full mode needs input and output and does not accept --force or --max-messages\n");
        return kExitUsage;
    }
    return ost2pst::cli::run_full(input, output, resume, {}, events_json);
}
