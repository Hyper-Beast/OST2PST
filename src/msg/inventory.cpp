// The Messaging layer's inventory (M3): every Message object and FAI entry the NBT names, opened through
// ltp::open_node, with its Property Context read, its subnode BTree enumerated, its Recipient Table and
// Attachment Table counted, and the Attachment objects its rows name opened and sized.
//
// Why this file and not one under ltp: ltp answers "what shape are these bytes" and must not know what a
// message or an attachment means (DEVELOPMENT.md). The counts below are
// statements about mailbox content, and they are what the converter and the completeness report consume.
//
// The subnode walk mirrors src/ltp/nid_map.cpp's production descent ([MS-PST] 2.2.2.8.3.3) but enumerates
// every SLENTRY instead of searching for one NID, because the inventory has to count what is there rather
// than answer a lookup. ltp::find_subnode is left untouched.
#include "ost2pst/msg/inventory.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "ost2pst/ltp/bth.h"
#include "ost2pst/ltp/hn.h"
#include "ost2pst/ltp/hn_block.h"
#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/node_open.h"
#include "ost2pst/ltp/node_value.h"
#include "ost2pst/ltp/pc.h"
#include "ost2pst/ltp/tc.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

namespace ost2pst::msg {

namespace {

// [MS-PST] 2.4.6.1.1 and 2.4.5.3.1 name the internal NIDs a Message object's tables hang under.
constexpr uint64_t kNidAttachmentTable = 0x671;
constexpr uint64_t kNidRecipientTable = 0x692;
// [MS-PST] 2.4.6.2.1 says an Attachment object PC MUST carry 0x0E20, 0x3705 and 0x370B; 2.4.6.1.1 names
// 0x3704 as the Attachment Table's filename column.
constexpr uint16_t kTagAttachSize = 0x0E20;
constexpr uint16_t kTagAttachFilename = 0x3704;
constexpr uint16_t kTagAttachMethod = 0x3705;
constexpr uint16_t kTagRenderingPosition = 0x370B;
// 0x3701 is the attachment data object the libpff notes name, of type Binary Data (0x0102) or Embedded
// Object (0x000d) (libpff format notes (see THIRD_PARTY_NOTICES.txt):2491-2509). [MS-PST] 2.4.6.2.2 says an attachment's
// content lives in PidTagAttachDataBinary, or in PidTagAttachDataObject when the attachment is itself a
// message, without giving either a tag number (docs/reference/ms-pst.txt:3813-3817).
constexpr uint16_t kTagAttachData = 0x3701;
// The property type the libpff notes call Embedded Object (0x000d). [MS-PST] 2.3.3.5 defines what a
// PtypObject value in a PC points at -- a heap allocation holding Nid (the subnode that contains the object
// data) and ulSize (docs/reference/ms-pst.txt:2771-2786) -- but names no type id, and [MS-OXCDATA] is not
// in docs/reference/, so the id is cited from the libpff notes.
constexpr uint16_t kPropTypeObject = 0x000D;
// libpff format notes, "Attachment", 0x3705/0x3701 table: method 5 is an embedded PFF item.
constexpr uint32_t kAttachMethodMessage = 5;

// [MS-PST] 2.2.2.1: NIDs are local to a namespace. A traversal target is the node's data
// and subnode tree, not its local name. Keep both: shared PC data alone is not a cycle.
using MessageTarget = std::pair<uint64_t, uint64_t>;
MessageTarget message_target(uint64_t data, uint64_t sub) {
    return {ndb::bid_lookup_key(data), ndb::bid_lookup_key(sub)};
}
// [MS-PST] 2.4.4.1.1 says a Folder object PC MUST carry 0x3001 PidTagDisplayName.
constexpr uint16_t kTagDisplayName = 0x3001;
// 0x1000 PidTagBody and 0x1013 PidTagHtml appear as property tags in [MS-PST]'s own example
// (docs/reference/ms-pst.txt:8087, 8093). 0x1009 is measured in this sample and named by neither opened
// reference, so it is reported as a body candidate, never as a spec-named property.
constexpr uint16_t kTagBody = 0x1000;
constexpr uint16_t kTagHtml = 0x1013;
constexpr uint16_t kTagBodyCandidate = 0x1009;

struct SubnodeEntry {
    uint64_t nid = 0;
    uint64_t bid_data = 0;
    uint64_t bid_sub = 0;
};

// What one subnode walk saw, so a bad block is reported instead of silently shortening the list. The
// `entries_*`, `cycles` and `capped` counters say the same thing about the list itself rather than about a
// block: the walk stopped before it enumerated everything the BTree holds, and which of those four reasons
// did it is a different question with a different fix.
struct WalkCounters {
    uint64_t blocks_read = 0;
    uint64_t blocks_compressed = 0;
    uint64_t blocks_bad = 0;
    uint64_t si_hops = 0;
    uint64_t entries_past_block = 0;
    uint64_t entries_bad = 0;
    uint64_t cycles = 0;
    uint64_t capped = 0;
    bool incomplete = false;
    std::set<uint64_t> *visited = nullptr; // a chain that revisits a block is a cycle, not a chain
    std::map<std::string, uint64_t> *reasons = nullptr;
    std::vector<std::string> *samples = nullptr;
    std::vector<std::string> *walk_samples = nullptr;
    size_t max_samples = 20;
};

std::string hex_u64(uint64_t value) {
    constexpr char kDigits[] = "0123456789ABCDEF";
    std::string text;
    for (int shift = 60; shift >= 0; shift -= 4) {
        text += kDigits[(value >> shift) & 0xF];
    }
    return text;
}

void note_failure(WalkCounters &counters, uint64_t bid, const std::string &reason) {
    ++counters.blocks_bad;
    counters.incomplete = true;
    if (counters.reasons != nullptr) {
        ++(*counters.reasons)[reason];
    }
    if (counters.samples != nullptr && counters.samples->size() < counters.max_samples) {
        counters.samples->push_back("unreadable subnode block bid 0x" + hex_u64(bid) + ": " + reason);
    }
}

// A walk problem that is not a block problem: the block read, and something inside it said the list is
// shorter than the block claims. Counting it only in a reason map nobody adds up is what let a truncated
// or cyclic subnode BTree report as a complete one.
void note_walk_problem(WalkCounters &counters, const std::string &reason) {
    counters.incomplete = true;
    if (counters.reasons != nullptr) {
        ++(*counters.reasons)[reason];
    }
    if (counters.walk_samples != nullptr && counters.walk_samples->size() < counters.max_samples) {
        counters.walk_samples->push_back("incomplete subnode walk: " + reason);
    }
}

std::string walk_problem_summary(const WalkCounters &counters) {
    std::string summary;
    const auto add = [&](uint64_t count, const char *label) {
        if (count == 0) {
            return;
        }
        if (!summary.empty()) {
            summary += ", ";
        }
        summary += std::to_string(count) + " " + label;
    };
    add(counters.entries_past_block, "entry arrays past the end of their block");
    add(counters.entries_bad, "entries that did not decode");
    add(counters.cycles, "SIBLOCK cycles");
    add(counters.capped, "walks stopped by a work cap");
    return summary;
}

// Enumerate every SLENTRY under bidSub. [MS-PST] 2.2.2.8.3.3.2: SIBLOCKs chain SLBLOCKs, so a SIBLOCK's
// entries are followed and an SLBLOCK's entries are the answer. An OST compresses a subnode block exactly
// like a data block, so the block's own form comes from the index before the header is read -- the same
// rule production descend_subnode follows. Capped by ltp's own work caps so a corrupt chain cannot spin.
bool walk_subnodes(ltp::BlockSource &blocks, uint64_t bid, uint64_t depth,
                   std::vector<SubnodeEntry> &out, WalkCounters &counters) {
    // [MS-PST] 2.2.2.8.3.3.2: SIBLOCKs chain SLBLOCKs, so a block reached twice is a cycle, not a longer
    // chain. Without this the walk spins to the cap and reports the cycle as nothing at all.
    if (counters.visited != nullptr && !counters.visited->insert(bid).second) {
        ++counters.cycles;
        note_walk_problem(counters, "the SIBLOCK chain revisits block 0x" + hex_u64(bid));
        return false;
    }
    if (depth > ltp::kMaxSubnodeDepth || out.size() > ltp::kMaxSubnodeEntries) {
        ++counters.capped;
        note_walk_problem(counters, depth > ltp::kMaxSubnodeDepth
                                         ? "the walk hit the depth cap " +
                                               std::to_string(ltp::kMaxSubnodeDepth)
                                         : "the walk hit the entry cap " +
                                               std::to_string(ltp::kMaxSubnodeEntries));
        return false;
    }
    util::Result<ltp::BlockBytes> raw = blocks.block(bid);
    if (!raw.ok()) {
        note_failure(counters, bid, "block read: " + util::format_error(raw.error()));
        return false;
    }
    ++counters.blocks_read;
    std::vector<uint8_t> bytes(raw.value().view.data(), raw.value().view.data() + raw.value().view.size());
    const util::ByteView view(bytes.data(), bytes.size(), raw.value().view.base());
    util::Result<ltp::HnBlock> payload = ltp::read_hn_block(view, raw.value().compressed);
    if (!payload.ok()) {
        note_failure(counters, bid, "block form: " + util::format_error(payload.error()));
        return false;
    }
    if (payload.value().form == ltp::BlockForm::kCompressed) {
        ++counters.blocks_compressed;
    }
    const util::ByteView content = payload.value().bytes();
    util::Result<ltp::SubnodeBlockHeader> header = ltp::decode_subnode_block_header(content);
    if (!header.ok()) {
        note_failure(counters, bid, "subnode header: " + util::format_error(header.error()));
        return false;
    }
    const ltp::SubnodeBlockHeader info = header.take();
    const uint64_t entry_size = info.c_level == 0 ? 24 : 16; // 2.2.2.8.3.3.1.1 SLENTRY / .2.1 SIENTRY
    for (uint16_t index = 0; index < info.c_ent; ++index) {
        const uint64_t offset = info.entries_ib + index * entry_size;
        if (!content.in_range(offset, entry_size)) {
            // cEnt promises entries the block does not hold. The list this walk returns is short by the
            // rest of them, and saying so is the whole point of counting it.
            ++counters.entries_past_block;
            note_walk_problem(counters, "cEnt " + std::to_string(info.c_ent) +
                                            " names an entry array past the end of block 0x" + hex_u64(bid));
            break;
        }
        util::Result<util::ByteView> slot = content.sub(offset, entry_size);
        if (!slot.ok()) {
            ++counters.entries_past_block;
            note_walk_problem(counters, util::format_error(slot.error()));
            break;
        }
        if (info.c_level == 0) {
            util::Result<ltp::SlEntry> entry = ltp::decode_sl_entry(slot.value());
            if (!entry.ok()) {
                ++counters.entries_bad;
                note_walk_problem(counters, "SLENTRY decode failed: " + util::format_error(entry.error()));
                continue;
            }
            out.push_back(SubnodeEntry{entry.value().nid, entry.value().bid_data, entry.value().bid_sub});
        } else {
            util::Result<ltp::SiEntry> entry = ltp::decode_si_entry(slot.value());
            if (!entry.ok()) {
                ++counters.entries_bad;
                note_walk_problem(counters, "SIENTRY decode failed: " + util::format_error(entry.error()));
                continue;
            }
            ++counters.si_hops;
            // One broken chain does not make the other chains' entries untrue, so the walk keeps going and
            // reports this one as incomplete.
            walk_subnodes(blocks, entry.value().bid, depth + 1, out, counters);
        }
    }
    return !counters.incomplete;
}

uint32_t inline_u32(const ltp::PcRecord &record) {
    util::Result<uint32_t> value = record.value.u32(0);
    return value.ok() ? value.value() : 0;
}

// One item answers one content question once, so when several tags ask the same question the answer is the
// strongest evidence among them. "Could not read" outranks "the source says it is empty" on purpose: while
// one alternative is unreadable, no one may conclude the item holds nothing.
int content_rank(ContentStatus status) {
    switch (status) {
    case ContentStatus::kReadable:
        return 4;
    case ContentStatus::kUnsupported:
        return 3;
    case ContentStatus::kUnreadable:
        return 2;
    case ContentStatus::kEmpty:
        return 1;
    case ContentStatus::kNotPresent:
        return 0;
    default:
        return -1;
    }
}

// One item's answer to one content question, and -- when the answer is "this reader does not decode it" --
// which form it was. The two forms are the only ones this reader can name without guessing: a PtypObject
// value, which [MS-PST] 2.3.3.5 defines as a heap allocation holding the Nid of a subnode plus a size
// (docs/reference/ms-pst.txt:2771-2786), and a value carrying the "LZFu" signature the libpff notes name for
// compressed RTF (libpff format notes (see THIRD_PARTY_NOTICES.txt):2638-2649).
struct ContentVerdict {
    ContentStatus status = ContentStatus::kNotPresent;
    uint64_t bytes = 0;
    bool object_form = false;
    bool compressed_form = false;
    uint64_t object_nid = 0;  // when object_form: the subnode [MS-PST] 2.3.3.5's Nid names
    uint64_t object_size = 0; // ... and the ulSize beside it
};

void count_content(ContentCounts &counts, const ContentVerdict &verdict) {
    const ContentStatus status = verdict.status;
    if (verdict.object_form) {
        ++counts.unsupported_object;
    }
    if (verdict.compressed_form) {
        ++counts.unsupported_compressed;
    }
    switch (status) {
    case ContentStatus::kReadable:
        ++counts.readable;
        break;
    case ContentStatus::kEmpty:
        ++counts.empty;
        break;
    case ContentStatus::kNotPresent:
        ++counts.not_present;
        break;
    case ContentStatus::kUnreadable:
        ++counts.unreadable;
        break;
    case ContentStatus::kUnsupported:
        ++counts.unsupported;
        break;
    case ContentStatus::kUnknown:
        ++counts.unknown;
        break;
    }
}

// The word a report uses for one verdict, so a sample line can be compared item by item with what an
// independent reader says about the same item.
const char *content_status_name(ContentStatus status) {
    switch (status) {
    case ContentStatus::kReadable:
        return "readable";
    case ContentStatus::kEmpty:
        return "empty";
    case ContentStatus::kNotPresent:
        return "not-present";
    case ContentStatus::kUnreadable:
        return "unreadable";
    case ContentStatus::kUnsupported:
        return "not-decoded";
    default:
        return "unknown";
    }
}

// The signature the libpff notes name for compressed RTF: a header whose third field is "LZFu"
// (libpff format notes (see THIRD_PARTY_NOTICES.txt):2638-2649). This reader inflates compressed blocks but has no LZFu
// inflater, so such a value is content it does not decode, not content the source lacks.
bool is_lzfu(util::ByteView bytes) {
    if (bytes.size() < 12) {
        return false;
    }
    return bytes.data()[8] == 'L' && bytes.data()[9] == 'Z' && bytes.data()[10] == 'F' &&
           bytes.data()[11] == 'u';
}

// UTF-16LE to UTF-8, only so a sample line can name an attachment the way a file system does.
std::string utf16le_to_utf8(util::ByteView bytes) {
    std::string text;
    for (uint64_t offset = 0; offset + 1 < bytes.size(); offset += 2) {
        util::Result<uint16_t> unit = bytes.u16(offset);
        if (!unit.ok()) {
            break;
        }
        const uint32_t code = unit.value();
        if (code == 0) {
            break;
        }
        if (code < 0x80) {
            text += static_cast<char>(code);
        } else if (code < 0x800) {
            text += static_cast<char>(0xC0u | (code >> 6));
            text += static_cast<char>(0x80u | (code & 0x3Fu));
        } else {
            text += static_cast<char>(0xE0u | (code >> 12));
            text += static_cast<char>(0x80u | ((code >> 6) & 0x3Fu));
            text += static_cast<char>(0x80u | (code & 0x3Fu));
        }
    }
    return text;
}

// One pass over the census. The scanner owns nothing but counters: the NID map, the block source and the
// folder list it reports into all belong to the caller.
class Scanner {
public:
    Scanner(const ltp::LtpReadReport &source, const std::vector<ltp::NodeRef> &entries,
            ltp::BlockSource &blocks, const InventoryOptions &options, InventoryReport &report)
        : source_(source), entries_(entries), blocks_(blocks), options_(options), report_(report),
          findings_(), failures_(options.max_notes) {
        findings_.max_items = options_.max_notes;
    }

    // The nidType census, classified once per value. A value the source contains but neither opened source
    // has a row for still gets a line, because "we do not know what this is" is a result.
    NodeClassCount &slot(uint32_t nid_type) {
        const auto found = report_.node_types.find(nid_type);
        if (found != report_.node_types.end()) {
            return found->second;
        }
        const NodeClass kind = classify_nid_type(nid_type);
        NodeClassCount &entry = report_.node_types[nid_type];
        entry.nid_type = nid_type;
        entry.disposition = kind.disposition;
        entry.ms_pst_name = kind.ms_pst_name;
        entry.libpff_label = kind.libpff_label;
        entry.reason = kind.reason;
        return entry;
    }

    void index_folders() {
        for (size_t index = 0; index < source_.folders.size(); ++index) {
            const ltp::LtpFolder &folder = source_.folders[index];
            FolderCounts counts;
            counts.nid = folder.nid;
            counts.parent = folder.parent;
            counts.depth = folder.depth;
            counts.name = folder.name;
            counts.name_present = folder.name_present;
            counts.children = folder.children;
            counts.contents_rows = folder.messages;
            counts.associated_rows = folder.associated;
            folder_index_[folder.nid] = report_.folders.size();
            report_.folders.push_back(counts);
        }
    }

    void index_parents() {
        for (const ltp::NodeRef &node : entries_) {
            parents_[node.nid] = node.nid_parent;
        }
    }

    // [MS-PST] 2.4.5.2: a Message object's nidParent is the NID of its parent Folder object's PC. The hop
    // cap only stops a cycle; a real chain is one hop.
    uint64_t folder_of(uint64_t nid) const {
        uint64_t current = nid;
        for (uint64_t hop = 0; hop < options_.max_parent_hops; ++hop) {
            const auto found = parents_.find(current);
            if (found == parents_.end() || found->second == 0) {
                break;
            }
            if (ltp::nid_type(found->second) == ltp::kNidTypeNormalFolder) {
                return found->second;
            }
            current = found->second;
        }
        return 0;
    }

    FolderCounts *folder_slot(uint64_t nid) const {
        const auto found = folder_index_.find(nid);
        return found == folder_index_.end() ? nullptr : &report_.folders[found->second];
    }

    void scan(const ltp::NodeRef &node, MessageStats &stats, AttachmentStats &attachments,
              uint32_t nid_type);

    // The same scan for an item reached through an Attachment object's PtypObject instead of the NBT.
    // [MS-PST] 2.4.6.2.2 says such an attached message is a fully formed Message object that is not in the
    // NBT and has no parent folder (docs/reference/ms-pst.txt:3813-3817), so `depth` is 0 only for the items
    // the NBT names, `path` records the parent message and attachment each one was reached through, and
    // `on_path` is what stops a cycle.
    void scan_message(uint64_t nid, uint64_t bid_data, uint64_t bid_sub, uint32_t nid_type,
                      MessageStats& stats, AttachmentStats& attachments, uint32_t depth,
                      const std::string& path, std::set<MessageTarget>& on_path);

    uint64_t decode_failures() const { return findings_.decode_failures; }
    const ltp::LtpFindingTally &findings() const { return findings_; }
    // Every FailureLog entry the seams this scanner handed out wrote into. A local FailureLog per call is
    // how a skipped BTH record used to disappear: nobody added the totals up.
    uint64_t failures_total() const { return failures_.total(); }

private:
    // One PC record, reduced to what a content verdict needs. The record's own flags say which of the
    // [MS-PST] 2.3.3.2 / 2.3.3.3 shapes it is, so a verdict never has to guess that from the bytes.
    struct PcValue {
        uint16_t prop_type = 0;
        uint32_t value_hnid = 0;
        bool value_inline = false; // [MS-PST] 2.3.3.3: a single-valued fixed-size type of 4 bytes or less
        bool value_absent = false; // [MS-PST] 2.3.3.2: dwValueHnid 0 is neither a HID nor a subnode NID
        uint32_t inline_u32 = 0;   // the four dwValueHnid bytes, when the value is inline
        bool has_inline_u32 = false; // ... and the record really carried all four
    };

    // Reads one node's Property Context and reports the tags it carries. Returns whether the records
    // really read, which is what the completeness report counts against [MS-PST] 2.4.5.1 / 2.4.6.2.1: a PC
    // whose BTH contradicts its header says nothing about what the source has, and everything about what
    // the reader could not get.
    bool read_properties(uint64_t nid, uint64_t bid, const ltp::NodeHeap &heap,
                         std::map<uint16_t, PcValue> &values, uint64_t &records);

    // What one record's value yielded, resolved through the node's own ValueSource -- the only seam that
    // knows both this node's heap and its subnodes ([MS-PST] 2.3.3.2). `bytes` receives only what actually
    // read and decoded; a value this reader could not get is reported as such instead of as absent content.
    ContentVerdict read_content(uint64_t nid, uint64_t bid, const PcValue &value,
                                ltp::NodeValueSource &values, uint16_t tag, const char *what);

    const ltp::LtpReadReport &source_;
    const std::vector<ltp::NodeRef> &entries_;
    ltp::BlockSource &blocks_;
    const InventoryOptions &options_;
    InventoryReport &report_;
    ltp::LtpFindingTally findings_;
    ndb::FailureLog failures_;
    std::unordered_map<uint64_t, uint64_t> parents_;
    std::unordered_map<uint64_t, size_t> folder_index_;
};

bool Scanner::read_properties(uint64_t nid, uint64_t bid, const ltp::NodeHeap &heap,
                              std::map<uint16_t, PcValue> &values, uint64_t &records) {
    if (heap.source == nullptr) {
        return false; // open_node already recorded why this node has no heap to read out of
    }
    ltp::BthStats stats;
    const util::Status status = ltp::read_pc(heap.header, source_.profile, *heap.source,
                                             [&](const ltp::PcRecord &record) {
                                                 ++records;
                                                 PcValue &value = values[record.prop_id];
                                                 value.prop_type = record.prop_type;
                                                 value.value_hnid = record.value_hnid;
                                                 value.value_inline = record.value_inline;
                                                 value.value_absent = record.value_absent;
                                                 if (record.value_inline && record.value.size() == 4) {
                                                     value.inline_u32 = inline_u32(record);
                                                     value.has_inline_u32 = true;
                                                 }
                                                 return true;
                                             }, stats, failures_);
    if (!status.ok()) {
        ++report_.errors[status.error().field];
        findings_.record(ltp::LtpFindingKind::kDecodeFailure, nid, bid, status.error().field,
                         status.error().detail);
        return false;
    }
    return true;
}

// What one record's value yielded. The record's own shape answers the first two questions: dwValueHnid 0 is
// [MS-PST] 2.3.3.2's "this property has no value", and an inline value IS the value ([MS-PST] 2.3.3.3).
// Everything else is a HNID, answered through the node's ValueSource -- the only seam that holds both this
// node's heap and its subnodes -- and a HNID that does not answer is a reader failure, never absent content.
ContentVerdict Scanner::read_content(uint64_t nid, uint64_t bid, const PcValue &value,
                                     ltp::NodeValueSource &values, uint16_t tag, const char *what) {
    ContentVerdict verdict;
    if (value.value_absent) {
        verdict.status = ContentStatus::kEmpty;
        return verdict;
    }
    if (value.value_inline) {
        verdict.status = ContentStatus::kReadable;
        verdict.bytes = 4;
        return verdict;
    }
    util::Result<util::ByteView> obtained = values.value(value.value_hnid);
    if (!obtained.ok()) {
        ++report_.errors[obtained.error().field];
        findings_.record(ltp::LtpFindingKind::kDecodeFailure, nid, bid, obtained.error().field,
                         std::string(what) + " 0x" + hex_u64(tag) + ": " + obtained.error().detail);
        verdict.status = ContentStatus::kUnreadable;
        return verdict;
    }
    if (value.prop_type == kPropTypeObject) {
        // [MS-PST] 2.3.3.5: the allocation holds Nid, the subnode that contains the object data, then
        // ulSize. Reading those 8 bytes and then the subnode they name is what says whether the payload is
        // reachable at all; decoding the object (an embedded message, an OLE2 document) is not this reader's
        // job yet, so a reachable one is content this reader does not decode rather than content absent.
        util::Result<uint32_t> object_nid = obtained.value().u32(0);
        util::Result<uint32_t> object_size = obtained.value().u32(4);
        if (!object_nid.ok() || !object_size.ok()) {
            findings_.record(ltp::LtpFindingKind::kDecodeFailure, nid, bid, "PtypObject value",
                             std::string(what) + " 0x" + hex_u64(tag) + ": the heap allocation a PtypObject "
                             "names is shorter than the 8 bytes [MS-PST] 2.3.3.5 defines");
            verdict.status = ContentStatus::kUnreadable;
            return verdict;
        }
        verdict.object_form = true;
        verdict.object_nid = object_nid.value();
        verdict.object_size = object_size.value();
        util::Result<util::ByteView> payload = values.value(static_cast<uint32_t>(verdict.object_nid));
        if (!payload.ok()) {
            ++report_.errors[payload.error().field];
            findings_.record(ltp::LtpFindingKind::kDecodeFailure, nid, bid, payload.error().field,
                             std::string(what) + " 0x" + hex_u64(tag) + ": the subnode a PtypObject names "
                             "did not read: " + payload.error().detail);
            verdict.status = ContentStatus::kUnreadable;
            return verdict;
        }
        verdict.status = ContentStatus::kUnsupported;
        return verdict;
    }
    if (is_lzfu(obtained.value())) {
        verdict.compressed_form = true;
        verdict.status = ContentStatus::kUnsupported;
        return verdict;
    }
    verdict.status = ContentStatus::kReadable;
    verdict.bytes = obtained.value().size();
    return verdict;
}

void Scanner::scan(const ltp::NodeRef &node, MessageStats &stats, AttachmentStats &attachments,
                   uint32_t nid_type) {
    // The NBT names this item, so it starts a path of its own. An attached message reached through one of
    // its attachments joins it, which is what lets the recursion see a cycle back into this item.
    std::set<MessageTarget> on_path{message_target(node.bid_data, node.bid_sub)};
    scan_message(node.nid, node.bid_data, node.bid_sub, nid_type, stats, attachments, 0,
                 "message 0x" + hex_u64(node.nid), on_path);
}

void Scanner::scan_message(uint64_t nid, uint64_t bid_data, uint64_t bid_sub, uint32_t nid_type,
                           MessageStats& stats, AttachmentStats& attachments, uint32_t depth,
                           const std::string& path, std::set<MessageTarget>& on_path) {
    ++stats.nodes;
    NodeClassCount &own = slot(nid_type);

    // Attribution happens whatever else this scan finds, so a message is never lost because its subnode
    // block could not be read.
    FolderCounts *folder = folder_slot(folder_of(nid));
    const uint64_t rows_before = attachments.rows_resolved;
    const uint64_t bytes_before = attachments.declared_size_bytes;
    const auto attribute = [&]() {
        // [MS-PST] 2.4.6.2.2: an attached message is "not located in the NBT and [has] no parent folder"
        // (docs/reference/ms-pst.txt:3816-3817), so it belongs to no folder and its attachments ride on its
        // own counts rather than a folder's.
        if (depth != 0 || folder == nullptr) {
            return;
        }
        folder->attributed = true;
        if (nid_type == ltp::kNidTypeNormalMessage) {
            ++folder->messages;
        } else {
            ++folder->associated;
        }
        folder->attachments += attachments.rows_resolved - rows_before;
        folder->attachment_bytes += attachments.declared_size_bytes - bytes_before;
    };

    // 1. the Message object's own Property Context ([MS-PST] 2.4.5.1).
    ltp::NodeHeap heap;
    std::map<uint16_t, PcValue> values;
    uint64_t records_here = 0;
    bool announced_pc = false;
    bool pc_read = false;
    if (bid_data != 0) {
        ++own.opened;
        const ltp::NodeOpen opened = ltp::open_node(blocks_, source_.profile, nid, bid_data, heap,
                                                    report_.heap, report_.data_trees, report_.errors,
                                                    &findings_, failures_);
        announced_pc = opened == ltp::NodeOpen::kOk && heap.header.b_client_sig == ltp::kClientSigPc;
        if (announced_pc) {
            // The read counts once the records read. Counting it before the call is what let a Property
            // Context whose BTH contradicted its header be reported as a read Property Context that
            // happens to carry no body property.
            pc_read = read_properties(nid, bid_data, heap, values, records_here);
        }
        if (pc_read) {
            ++own.read;
            ++stats.pcs_read;
            stats.pc_records += records_here;
        } else {
            ++own.not_read;
            ++stats.pcs_failed;
            if (announced_pc) {
                ++stats.pc_decode_failed;
            }
        }
    } else {
        ++own.not_read;
        ++stats.pcs_failed;
    }

    // Body forms. [MS-PST] gives the preference order (RtfCompressed, then Html, then Body) at
    // docs/reference/ms-pst.txt:5118-5130 without naming their tags; 0x1000 and 0x1013 appear as property
    // tags in the spec's own example, and 0x1009 is only measured in this sample. A message with none of
    // the three is reported, not given a body it does not have -- and a message whose Property Context did
    // not read is not in this count at all, because "the reader got nothing" is not "the source has none".
    if (pc_read) {
        if (values.count(kTagBody) != 0) {
            ++stats.with_body;
        }
        if (values.count(kTagHtml) != 0) {
            ++stats.with_html;
        }
        if (values.count(kTagBodyCandidate) != 0) {
            ++stats.with_rtf;
        }
        if (values.count(kTagBody) == 0 && values.count(kTagHtml) == 0 &&
            values.count(kTagBodyCandidate) == 0) {
            ++stats.with_no_body_form;
            count_content(stats.body, ContentVerdict{}); // no record for any of the three tags
        } else {
            // One verdict per message, from the strongest evidence among the body tags. Answering a HNID
            // needs this node's heap and its subnodes together ([MS-PST] 2.3.3.2), which is what a
            // NodeValueSource holds. The walk counters it would move are diagnostic and stay local; every
            // failure it logs goes into the same FailureLog the rest of this scan reports through.
            ltp::SubnodeStats body_subnodes;
            ltp::DataTreeCounters body_trees;
            ltp::NodeValueSource body_values(*heap.source, bid_sub, source_.profile, blocks_,
                                             body_subnodes, body_trees, failures_);
            ContentVerdict best;
            for (const uint16_t tag : {kTagBody, kTagHtml, kTagBodyCandidate}) {
                const auto found = values.find(tag);
                if (found == values.end()) {
                    continue;
                }
                const ContentVerdict verdict =
                    read_content(nid, bid_data, found->second, body_values, tag, "body");
                if (content_rank(verdict.status) > content_rank(best.status)) {
                    best = verdict; // bytes_read is the strongest body form, not the three summed
                }
            }
            count_content(stats.body, best);
            stats.body.bytes_read += best.bytes;
        }
    } else {
        // A Property Context that did not read says nothing about whether its message has a body.
        ContentVerdict unknown;
        unknown.status = ContentStatus::kUnknown;
        count_content(stats.body, unknown);
    }

    // 2. the subnode BTree ([MS-PST] 2.2.2.8.3.3). Everything a Message object holds besides its own PC is
    // here: 2.4.5 says the Recipient Table, the optional Attachment Table, the Attachment objects and the
    // raw LTP data are subnodes of the one top-level node.
    if (bid_sub == 0) {
        ++stats.without_subnode;
        ++stats.without_recipient_table;
        attribute();
        return;
    }
    std::vector<SubnodeEntry> subnodes;
    WalkCounters counters;
    std::set<uint64_t> visited;
    counters.visited = &visited;
    counters.reasons = &stats.subnode_failure_reasons;
    counters.samples = &report_.completeness.unreadable_blocks;
    counters.walk_samples = &report_.completeness.incomplete_walks;
    counters.max_samples = options_.max_notes;
    const uint64_t bad_before = stats.subnode_blocks_bad;
    walk_subnodes(blocks_, bid_sub, 0, subnodes, counters);
    stats.subnode_blocks_read += counters.blocks_read;
    stats.subnode_blocks_compressed += counters.blocks_compressed;
    stats.subnode_blocks_bad += counters.blocks_bad;
    stats.si_hops += counters.si_hops;
    stats.subnode_entries_past_block += counters.entries_past_block;
    stats.subnode_entries_bad += counters.entries_bad;
    stats.subnode_cycles += counters.cycles;
    stats.subnode_walks_capped += counters.capped;
    // A block nobody could read is already counted as an unreadable block; these are the ways the walk
    // comes back with a list that is not the whole list without one. Both make the run incomplete.
    const std::string short_by = walk_problem_summary(counters);
    if (!short_by.empty()) {
        ++stats.subnode_walks_incomplete;
        findings_.record(ltp::LtpFindingKind::kDecodeFailure, nid, bid_sub, "subnode BTree",
                         "the walk came back short: " + short_by);
    }
    if (subnodes.empty()) {
        if (stats.subnode_blocks_bad != bad_before || !short_by.empty()) {
            ++stats.with_bad_subnodes;
        }
        ++stats.without_recipient_table;
        attribute();
        return;
    }
    ++stats.with_subnodes;
    if (subnodes.size() > stats.max_subnodes) {
        stats.max_subnodes = subnodes.size();
    }
    stats.subnode_entries += subnodes.size();
    for (const SubnodeEntry &subnode : subnodes) {
        const uint32_t type = static_cast<uint32_t>(ltp::nid_type(subnode.nid));
        ++stats.subnode_types[type];
        ++slot(type).subnode_entries;
    }

    // 3. the Attachment Table and the Attachment objects its rows name. [MS-PST] 2.4.6.1.3: each row's
    // dwRowID IS the subnode NID of the Attachment object for that row, so the rows and the 0x05 subnodes
    // have to agree, and the inventory checks that in both directions instead of trusting either list.
    std::vector<uint32_t> attachment_keys;
    for (const SubnodeEntry &subnode : subnodes) {
        if (ltp::nid_type(subnode.nid) == ltp::kNidTypeAttachment) {
            ++attachments.subnode_entries;
            attachment_keys.push_back(static_cast<uint32_t>(ltp::subnode_nid_key(subnode.nid)));
        }
    }

    std::vector<uint32_t> named_keys;
    // [MS-PST] 2.4.6.1.3 only says something about the two lists when the row index actually walked. If it
    // did not, an Attachment object no row named is an open question, not a finding against the source.
    bool naming_checkable = true;
    for (const SubnodeEntry &subnode : subnodes) {
        if (ltp::subnode_nid_key(subnode.nid) != kNidAttachmentTable || subnode.bid_data == 0) {
            continue;
        }
        ++stats.attachment_tables;
        ++attachments.tables;
        NodeClassCount &table_slot = slot(ltp::kNidTypeAttachmentTable);
        ++table_slot.opened;
        ltp::NodeHeap table;
        const ltp::NodeOpen opened = ltp::open_node(blocks_, source_.profile, subnode.nid, subnode.bid_data,
                                                    table, report_.heap, report_.data_trees, report_.errors,
                                                    &findings_, failures_);
        if (opened != ltp::NodeOpen::kOk || table.source == nullptr ||
            table.header.b_client_sig != ltp::kClientSigTc) {
            ++table_slot.not_read;
            ++stats.attachment_tables_not_read;
            ++attachments.tables_not_read;
            continue;
        }
        util::Result<ltp::TcTable> info = ltp::read_tc(table.header, *table.source);
        if (!info.ok()) {
            ++report_.errors[info.error().field];
            ++table_slot.not_read;
            ++stats.attachment_tables_not_read;
            ++attachments.tables_not_read;
            findings_.record(ltp::LtpFindingKind::kDecodeFailure, subnode.nid, subnode.bid_data,
                             info.error().field, info.error().detail);
            naming_checkable = false;
            continue;
        }
        ++table_slot.read;
        ++stats.attachment_tables_read;
        ++attachments.tables_read;
        ltp::BthStats row_stats;
        std::vector<uint32_t> row_ids;
        const util::Status walked = ltp::walk_tc_row_index(
            info.value(), source_.profile, *table.source,
            [&](const ltp::TcRowId &row) {
                row_ids.push_back(row.row_id);
                return true;
            },
            row_stats, failures_);
        if (!walked.ok()) {
            // The rows this walk did not reach are not counted anywhere, so a table whose RowIndex did not
            // walk cannot look like a table with fewer rows.
            ++report_.errors[walked.error().field];
            ++attachments.tables_row_index_failed;
            ++stats.attachment_tables_row_index_failed;
            findings_.record(ltp::LtpFindingKind::kDecodeFailure, subnode.nid, subnode.bid_data,
                             walked.error().field, walked.error().detail);
            naming_checkable = false;
            continue;
        }
        attachments.rows += row_ids.size();
        attachments.rows_skipped += row_stats.skipped_records;
        if (row_stats.stopped_early) {
            ++attachments.tables_stopped_early;
        }
        for (uint32_t row_id : row_ids) {
            named_keys.push_back(row_id);
        }

        for (uint32_t row_id : row_ids) {
            const SubnodeEntry *match = nullptr;
            for (const SubnodeEntry &candidate : subnodes) {
                if (ltp::subnode_nid_key(candidate.nid) == row_id) {
                    match = &candidate;
                    break;
                }
            }
            if (match == nullptr) {
                ++attachments.rows_unresolved;
                continue;
            }
            ++attachments.rows_resolved;
            NodeClassCount &attach_slot = slot(ltp::kNidTypeAttachment);
            if (match->bid_data == 0) {
                ++attach_slot.not_read;
                ++attachments.nodes_no_pc;
                continue;
            }
            ++attach_slot.opened;
            ++attachments.nodes_opened;
            ltp::NodeHeap attachment;
            const ltp::NodeOpen attachment_opened =
                ltp::open_node(blocks_, source_.profile, match->nid, match->bid_data, attachment,
                               report_.heap, report_.data_trees, report_.errors, &findings_, failures_);
            if (attachment_opened != ltp::NodeOpen::kOk || attachment.source == nullptr ||
                attachment.header.b_client_sig != ltp::kClientSigPc) {
                ++attach_slot.not_read;
                ++attachments.nodes_no_pc;
                continue;
            }
            ++attach_slot.read;
            std::map<uint16_t, PcValue> attachment_values;
            uint64_t attachment_records = 0;
            const bool attachment_read =
                read_properties(match->nid, match->bid_data, attachment, attachment_values,
                                attachment_records);
            if (!attachment_read) {
                // Nothing is known about this Attachment object's properties, so none of the [MS-PST]
                // 2.4.6.2.1 MUSTs may be counted against it -- that would report the reader's own failure
                // as a property the source does not carry.
                ++attachments.pc_decode_failed;
                continue;
            }
            stats.pc_records += attachment_records;

            // [MS-PST] 2.4.6.2.1 names 0x0E20, 0x3705 and 0x370B as MUSTs of an Attachment object PC. Each
            // is answered three ways: the record is missing, it is present with no value (dwValueHnid 0,
            // [MS-PST] 2.3.3.2), or it is present but not the 4-byte inline form the type would use.
            const auto found_tag = [&](uint16_t tag) { return attachment_values.find(tag); };
            const auto present = [&](uint16_t tag) { return found_tag(tag) != attachment_values.end(); };
            const auto value_absent = [&](uint16_t tag) {
                const auto found = found_tag(tag);
                return found != attachment_values.end() && found->second.value_absent;
            };
            const auto has_inline = [&](uint16_t tag) {
                const auto found = found_tag(tag);
                return found != attachment_values.end() && found->second.has_inline_u32;
            };
            const auto inline_value = [&](uint16_t tag) {
                const auto found = found_tag(tag);
                return found == attachment_values.end() ? 0u : found->second.inline_u32;
            };
            uint32_t size_value = 0;
            if (!present(kTagAttachSize)) {
                ++attachments.without_size;
            } else if (value_absent(kTagAttachSize)) {
                ++attachments.size_value_absent;
            } else if (has_inline(kTagAttachSize)) {
                ++attachments.with_size;
                size_value = inline_value(kTagAttachSize);
                attachments.declared_size_bytes += size_value;
            } else {
                ++attachments.size_not_inline;
            }
            const bool has_filename = present(kTagAttachFilename) && !value_absent(kTagAttachFilename);
            if (has_filename) {
                ++attachments.with_filename;
            }
            uint32_t method_value = 0;
            if (!present(kTagAttachMethod)) {
                ++attachments.without_method;
            } else if (has_inline(kTagAttachMethod)) {
                ++attachments.with_method;
                method_value = inline_value(kTagAttachMethod);
                ++attachments.methods[method_value];
            } else {
                ++attachments.method_not_inline;
            }
            if (present(kTagRenderingPosition)) {
                ++attachments.with_rendering;
            } else {
                ++attachments.without_rendering;
            }
            if (options_.collect_rows) {
                // The same columns the M3 cross-layer join reads, so the comparison runs on this
                // inventory's own enumeration -- including the attached messages it recursed into --
                // instead of on a second walk that could differ from it.
                char row[160];
                std::snprintf(row, sizeof(row), "ATT\t0x%08X\t0x%04X\t%u\t%u\t%u\t",
                              static_cast<unsigned>(ltp::subnode_nid_key(nid)),
                              static_cast<unsigned>(ltp::subnode_nid_key(match->nid)), size_value,
                              method_value, has_filename ? 1u : 0u);
                attachments.row_dump.push_back(std::string(row) + path + " attachment 0x" +
                                               hex_u64(ltp::subnode_nid_key(match->nid)) + "\n");
            }

            // 0x3701 and 0x0E20 answer different questions, so they get separate answers. The size above is
            // what the source declares; this is whether the payload it names can actually be read. The
            // libpff notes show a real file with an empty 0x3701 value on an attachment that says 206, and
            // an ATTACH_BY_VALUE attachment with a size and no 0x3701 entry at all
            // (libpff format notes (see THIRD_PARTY_NOTICES.txt):2511-2519), so neither number implies the other.
            ltp::SubnodeStats payload_subnodes;
            ltp::DataTreeCounters payload_trees;
            ltp::NodeValueSource payload_values(*attachment.source, match->bid_sub, source_.profile, blocks_,
                                                payload_subnodes, payload_trees, failures_);
            ContentVerdict payload;
            const auto data_found = attachment_values.find(kTagAttachData);
            if (data_found != attachment_values.end()) {
                payload = read_content(match->nid, match->bid_data, data_found->second, payload_values,
                                       kTagAttachData, "attachment payload");
            }
            count_content(attachments.payload, payload);
            attachments.payload.bytes_read += payload.bytes;
            if (size_value != 0 && (payload.status == ContentStatus::kNotPresent ||
                                    payload.status == ContentStatus::kEmpty)) {
                ++attachments.declared_size_without_payload;
            }

            // libpff's Attachment method/type table and [MS-PST] 2.4.6.2.2 define the
            // interpretation before opening the target. A PC shape cannot turn OLE into a message.
            if (method_value == kAttachMethodMessage && data_found != attachment_values.end() &&
                data_found->second.prop_type != kPropTypeObject) {
                findings_.record(ltp::LtpFindingKind::kDecodeFailure, match->nid, match->bid_data,
                                 "attachment method/type", path + ": method 5 requires PtypObject");
            }
            if (payload.object_form && payload.status == ContentStatus::kUnsupported) {
                ++attachments.data_objects;
                ++report_.embedded_walks.objects;
                if (method_value != kAttachMethodMessage) {
                    ++attachments.data_objects_not_messages;
                    ++report_.embedded_walks.not_messages;
                    continue;
                }
                const uint64_t object_bid = match->bid_data;
                const util::Result<ltp::SubnodeRef> found_object = ltp::find_subnode(
                    match->bid_sub, payload.object_nid, blocks_, payload_subnodes, failures_);
                if (!found_object.ok()) {
                    // read_content resolved this same NID through this same bidSub a moment ago, so a
                    // subnode that is gone here is a contradiction, and it gets named instead of skipped.
                    ++attachments.data_objects_not_messages;
                    ++report_.embedded_walks.not_messages;
                    findings_.record(ltp::LtpFindingKind::kDecodeFailure, match->nid, object_bid,
                                     found_object.error().field,
                                     "the subnode a 0x3701 PtypObject names did not resolve: " +
                                         found_object.error().detail);
                    continue;
                }
                const uint64_t attached_nid = ltp::subnode_nid_key(found_object.value().nid);
                const uint32_t attached_type =
                    static_cast<uint32_t>(ltp::nid_type(found_object.value().nid));
                const MessageTarget target =
                    message_target(found_object.value().bid_data, found_object.value().bid_sub);
                if (on_path.count(target) != 0) {
                    ++report_.embedded_walks.cycles;
                    findings_.record(ltp::LtpFindingKind::kDecodeFailure, attached_nid, bid_data,
                                     "attached message",
                                     path + " names an attached message already on this path: 0x" +
                                         hex_u64(attached_nid));
                    if (report_.completeness.incomplete_walks.size() < options_.max_notes) {
                        report_.completeness.incomplete_walks.push_back(
                            "attached message walk stopped: " + path + " names 0x" +
                            hex_u64(attached_nid) + " already on this path");
                    }
                    continue;
                }
                if (depth + 1 > options_.max_embedded_depth) {
                    ++report_.embedded_walks.depth_capped;
                    report_.capped = true;
                    continue;
                }
                if (report_.embedded.nodes >= options_.max_embedded) {
                    ++report_.embedded_walks.capped;
                    report_.capped = true;
                    continue;
                }
                ltp::NodeHeap attached_heap;
                ltp::NodeOpen attached_open = ltp::NodeOpen::kUnreadable;
                if (found_object.value().bid_data != 0) {
                    attached_open = ltp::open_node(blocks_, source_.profile, found_object.value().nid,
                                                   found_object.value().bid_data, attached_heap,
                                                   report_.heap, report_.data_trees, report_.errors,
                                                   &findings_, failures_);
                }
                if (attached_open != ltp::NodeOpen::kOk ||
                    attached_heap.header.b_client_sig != ltp::kClientSigPc) {
                    ++attachments.data_objects_not_messages;
                    ++report_.embedded_walks.not_messages;
                    findings_.record(ltp::LtpFindingKind::kDecodeFailure, attached_nid,
                                     found_object.value().bid_data, "attached message PC",
                                     path + ": method 5 target is not a readable Message PC");
                    continue;
                }
                ++attachments.data_objects_scanned;
                ++report_.embedded_walks.scanned;
                ++report_.embedded_walks.depths[depth + 1];
                ++report_.embedded_walks.nid_types[attached_type];
                on_path.insert(target);
                scan_message(attached_nid, found_object.value().bid_data, found_object.value().bid_sub,
                             attached_type, report_.embedded, report_.embedded_attachments, depth + 1,
                             path + " attachment 0x" + hex_u64(ltp::subnode_nid_key(match->nid)) +
                                 " embedded 0x" + hex_u64(attached_nid),
                             on_path);
                on_path.erase(target);
            }

            // A named sample, so the enumeration can be checked attachment by attachment against an
            // independent reader rather than only by totals.
            if (options_.collect_samples && has_filename && attachments.samples.size() < options_.max_samples) {
                // The same ValueSource that answered the payload question answers the filename, so a name
                // that does not read lands in the run's FailureLog instead of a throwaway one nobody summed.
                // The inventory counts 0x3704 from the PC record; this only turns the record's HNID into
                // text so a sample line can name the attachment, and says what the payload verdict was.
                const util::Result<util::ByteView> name_bytes =
                    payload_values.value(attachment_values.find(kTagAttachFilename)->second.value_hnid);
                const std::string name = name_bytes.ok() ? utf16le_to_utf8(name_bytes.value()) : "<unreadable>";
                attachments.samples.push_back(path + " attachment 0x" +
                                             hex_u64(ltp::subnode_nid_key(match->nid)) + " 0x0E20=" +
                                             std::to_string(size_value) + " name " + name + " payload " +
                                             content_status_name(payload.status));
            }
        }
    }

    // The other direction of [MS-PST] 2.4.6.1.3: an Attachment object subnode no Attachment Table row names
    // is an attachment the converter would never be told about. rows_unresolved above is the same check the
    // other way round.
    if (naming_checkable) {
        std::sort(attachment_keys.begin(), attachment_keys.end());
        std::sort(named_keys.begin(), named_keys.end());
        for (uint32_t key : attachment_keys) {
            if (!std::binary_search(named_keys.begin(), named_keys.end(), key)) {
                ++attachments.subnodes_not_named;
            }
        }
    } else {
        attachments.subnodes_naming_unchecked += attachment_keys.size();
    }

    // 4. the Recipient Table, which [MS-PST] 2.4.5 marks Required: Y for a Message object. A message
    // without one is a completeness finding, not something the converter invents a recipient for.
    uint64_t own_recipient_tables = 0;
    for (const SubnodeEntry &subnode : subnodes) {
        if (ltp::subnode_nid_key(subnode.nid) != kNidRecipientTable || subnode.bid_data == 0) {
            continue;
        }
        ++stats.recipient_tables;
        ++own_recipient_tables;
        NodeClassCount &table_slot = slot(ltp::kNidTypeRecipientTable);
        ++table_slot.opened;
        ltp::NodeHeap table;
        const ltp::NodeOpen opened = ltp::open_node(blocks_, source_.profile, subnode.nid, subnode.bid_data,
                                                    table, report_.heap, report_.data_trees, report_.errors,
                                                    &findings_, failures_);
        if (opened != ltp::NodeOpen::kOk || table.source == nullptr ||
            table.header.b_client_sig != ltp::kClientSigTc) {
            ++table_slot.not_read;
            ++stats.recipient_tables_not_read;
            continue;
        }
        util::Result<ltp::TcTable> info = ltp::read_tc(table.header, *table.source);
        if (!info.ok()) {
            ++report_.errors[info.error().field];
            ++table_slot.not_read;
            ++stats.recipient_tables_not_read;
            findings_.record(ltp::LtpFindingKind::kDecodeFailure, subnode.nid, subnode.bid_data,
                             info.error().field, info.error().detail);
            continue;
        }
        ++table_slot.read;
        ++stats.recipient_tables_read;
        ltp::BthStats row_stats;
        uint64_t rows_here = 0;
        const util::Status walked = ltp::walk_tc_row_index(
            info.value(), source_.profile, *table.source,
            [&](const ltp::TcRowId &) {
                ++rows_here;
                return true;
            },
            row_stats, failures_);
        if (!walked.ok()) {
            ++report_.errors[walked.error().field];
            ++stats.recipient_tables_row_index_failed;
            findings_.record(ltp::LtpFindingKind::kDecodeFailure, subnode.nid, subnode.bid_data,
                             walked.error().field, walked.error().detail);
            continue;
        }
        stats.recipient_rows += rows_here;
        stats.recipient_rows_skipped += row_stats.skipped_records;
        if (row_stats.stopped_early) {
            ++stats.recipient_tables_stopped_early;
        }
    }
    if (own_recipient_tables == 0) {
        ++stats.without_recipient_table;
    }
    attribute();
}

} // namespace

util::Result<InventoryReport> build_inventory(const ltp::LtpReadReport &source, ltp::BlockSource &blocks,
                                              const InventoryOptions &options,
                                              const InventoryUpstream &upstream) {
    InventoryReport report;
    report.profile = source.profile;
    const std::vector<ltp::NodeRef> entries = source.nodes.entries();
    report.nid_entries = entries.size();

    Scanner scanner(source, entries, blocks, options, report);
    scanner.index_folders();
    scanner.index_parents();

    // Every NID the NBT names, classified by its nidType. A type the inventory never opens still gets a
    // line with nodes > 0 and opened == 0, which is the honest statement "this file has N of these and the
    // inventory did not look inside them".
    for (const ltp::NodeRef &node : entries) {
        ++scanner.slot(static_cast<uint32_t>(ltp::nid_type(node.nid))).nodes;
    }

    for (const ltp::NodeRef &node : entries) {
        const uint32_t type = static_cast<uint32_t>(ltp::nid_type(node.nid));
        if (type == ltp::kNidTypeNormalMessage) {
            if (report.messages.nodes >= options.max_messages) {
                ++report.messages.stopped_early;
                report.capped = true;
                continue;
            }
            scanner.scan(node, report.messages, report.attachments, type);
        } else if (type == ltp::kNidTypeAssocMessage) {
            if (report.associated.nodes >= options.max_associated) {
                ++report.associated.stopped_early;
                report.capped = true;
                continue;
            }
            scanner.scan(node, report.associated, report.associated_attachments, type);
        }
    }

    CompletenessReport &c = report.completeness;
    const AttachmentStats &normal = report.attachments;
    const AttachmentStats &assoc = report.associated_attachments;
    const auto missing_size = [](const AttachmentStats &stats) {
        return stats.without_size + stats.size_value_absent + stats.size_not_inline;
    };
    c.messages_without_body_form = report.messages.with_no_body_form + report.associated.with_no_body_form;
    c.messages_without_subnode = report.messages.without_subnode + report.associated.without_subnode;
    c.messages_without_recipient_table =
        report.messages.without_recipient_table + report.associated.without_recipient_table;
    c.attachments_without_size = missing_size(normal) + missing_size(assoc);
    c.attachments_without_method = normal.without_method + assoc.without_method;
    c.attachments_without_rendering = normal.without_rendering + assoc.without_rendering;
    c.attachment_rows_unresolved = normal.rows_unresolved + assoc.rows_unresolved;
    c.attachment_subnodes_unnamed = normal.subnodes_not_named + assoc.subnodes_not_named;
    // A reader failure under an attached message is the same failure as one under a message the NBT
    // names, so every class that says "this reader did not get it" folds the embedded scans in.
    // What the source lacks stays per population: an attached message's absences are reported in
    // their own section, never merged into the two NBT populations.
    c.messages_with_unreadable_body =
        report.messages.body.unreadable + report.associated.body.unreadable +
        report.embedded.body.unreadable;
    c.attachments_with_unreadable_payload = normal.payload.unreadable + assoc.payload.unreadable +
                                            report.embedded_attachments.payload.unreadable;
    c.attachments_with_declared_size_and_no_payload =
        normal.declared_size_without_payload + assoc.declared_size_without_payload;
    c.blocks_unreadable = report.heap.blocks_failed + report.messages.subnode_blocks_bad +
                          report.associated.subnode_blocks_bad + report.embedded.subnode_blocks_bad;
    c.decode_failures = scanner.decode_failures();
    c.messages_with_unreadable_property_context = report.messages.pc_decode_failed +
                                                  report.associated.pc_decode_failed +
                                                  report.embedded.pc_decode_failed;
    c.subnode_walks_incomplete = report.messages.subnode_walks_incomplete +
                                 report.associated.subnode_walks_incomplete +
                                 report.embedded.subnode_walks_incomplete;
    c.row_index_walks_failed = report.messages.attachment_tables_row_index_failed +
                               report.associated.attachment_tables_row_index_failed +
                               report.messages.recipient_tables_row_index_failed +
                               report.associated.recipient_tables_row_index_failed +
                               report.embedded.attachment_tables_row_index_failed +
                               report.embedded.recipient_tables_row_index_failed;
    c.attachment_data_objects_not_decoded =
        report.attachments.data_objects_not_messages +
        report.associated_attachments.data_objects_not_messages +
        report.embedded_attachments.data_objects_not_messages;
    c.attached_messages_left_by_cap =
        report.embedded_walks.depth_capped + report.embedded_walks.capped;
    for (const auto &entry : report.node_types) {
        if (entry.second.disposition == NodeDisposition::kUnknown) {
            c.nodes_of_unknown_type += entry.second.nodes;
        }
    }

    // What each of those counts means, in the sources' own terms. A count of zero says the source had
    // nothing missing in that respect; it never says the converter supplied a value the file did not have.
    c.notes.push_back("messages with no 0x1000, 0x1013 or 0x1009 record: the source carries no body form "
                      "for them. [MS-PST] states the best-body preference as PidTagRtfCompressed, then "
                      "PidTagHtml, then PidTagBody (docs/reference/ms-pst.txt:5118-5130) without naming "
                      "their tags; 0x1000 and 0x1013 appear as property tags in the spec's own example "
                      "(ms-pst.txt:8087, 8093) and 0x1009 is measured in this sample, named by neither "
                      "opened reference");
    c.notes.push_back("messages with bidSub 0: [MS-PST] 2.4.5 says a Message object's Recipient Table, "
                      "Attachment Table and Attachment objects are subnodes of its one top-level node, so "
                      "a message with no subnode has none of them");
    c.notes.push_back("messages with no Recipient Table subnode: [MS-PST] 2.4.5's subnode table marks the "
                      "Recipient Table Required: Y, so these messages are incomplete in the source, not "
                      "somewhere the converter invents a recipient");
    c.notes.push_back("attachments with no readable 0x0E20, 0x3705 or 0x370B: [MS-PST] 2.4.6.2.1 says an "
                      "Attachment object PC MUST carry all three");
    c.notes.push_back("attachment rows whose dwRowID names no subnode, and attachment subnodes no row "
                      "names: [MS-PST] 2.4.6.1.3 says each dwRowID IS the subnode NID of the Attachment "
                      "object for that row, so the two lists have to agree in both directions");
    c.notes.push_back("nidType values with no row in [MS-PST] 2.2.2.1, or named there with no structure "
                      "defined in either opened source: reported as they are, never renamed into something "
                      "this project invented, and never dropped because a table is silent about them -- "
                      "[MS-PST] 2.2.2.1 says nidType 'has no meaning to the structures defined in the NDB "
                      "Layer' (docs/reference/ms-pst.txt:872-873), which is not evidence a PST lacks the "
                      "value");
    c.notes.push_back("messages whose Property Context the source announced but this reader could not read: "
                      "kept apart from the count above, because [MS-PST] 2.4.5.1 puts a Message object's "
                      "properties in that one node -- a Property Context whose bytes contradicted its header "
                      "says nothing about which properties the source carries");
    c.notes.push_back("subnode BTree walks that came back short (an entry array past the end of its block, "
                      "entries that did not decode, a SIBLOCK chain that revisits a block, a walk stopped by "
                      "a work cap) and table RowIndex walks that did not walk: the entries and rows they did "
                      "not reach are not counted anywhere, so a failed walk can never look like a shorter "
                      "list the source really had");
    c.notes.push_back("body content, one verdict per Message object from the strongest of 0x1000, 0x1013 and "
                      "0x1009: readable means the bytes were obtained, empty means the record carried "
                      "dwValueHnid 0, which [MS-PST] 2.3.3.2 says is neither a HID nor a subnode NID, "
                      "not-present means no record for any of the three, unreadable means the record named a "
                      "heap allocation or subnode this reader could not get, and unknown means the Property "
                      "Context itself did not read. The 0x1000/0x1013/0x1009 counts above only say a record "
                      "exists");
    c.notes.push_back("attachment payload content (0x3701) kept apart from the 0x0E20 the source declares: "
                      "[MS-PST] 2.4.6.2.1 requires 0x0E20 while 2.4.6.2.2 says only that the binary content, "
                      "if any, is in PidTagAttachDataBinary or PidTagAttachDataObject "
                      "(docs/reference/ms-pst.txt:3797-3817), and the libpff notes show an empty 0x3701 "
                      "value on an attachment that declares 206 and a sized ATTACH_BY_VALUE attachment "
                      "with no 0x3701 entry at all (docs/reference/pff-format.asciidoc:2511-2519). "
                      "Declared bytes are never reported as bytes read");
    c.notes.push_back(
        "attached messages counted apart from the two NBT populations: [MS-PST] 2.4.6.2.2 "
        "says the Nid of a 0x3701 PtypObject is a subnode that is a fully formed Message "
        "object, not located in the NBT and with no parent folder "
        "(docs/reference/ms-pst.txt:3813-3817), so no NBT walk reaches them and no folder "
        "count includes them. Each one is reported with the message and attachment it was "
        "reached through. Attachment method 5 requires a readable Message PC; a "
        "contradiction is a decode failure. Other object methods remain explicitly "
        "undecoded, even when their data resembles a PC. A reader "
        "failure found under an attached message reaches the same verdict class as the "
        "same failure under a message the NBT names");

    // The verdict for the whole run. Every class below is a way this run claimed to have read something it
    // did not, so a caller that exits on a run exits on this instead of on whichever two counters it looked
    // at. The two classes the opened literature excuses -- a nidType [MS-PST] 2.4.1 / 2.4.8 documents as
    // holding an array, a queue or a BLOB instead of a heap node, and a structure the literature names but
    // this reader does not decode -- are reported here rather than folded into "nothing was skipped", and
    // they do not by themselves make the run incomplete, exactly as in ltp's own verdict.
    InventoryStatus &status = report.status;
    status.decode_failures = source.findings.decode_failures + scanner.decode_failures();
    const uint64_t upstream_failures = upstream.failures != nullptr ? upstream.failures->total() : 0;
    const ndb::BlockReadCounters upstream_blocks =
        upstream.blocks != nullptr ? *upstream.blocks : ndb::BlockReadCounters{};
    status.logged_findings = source.failure_total + scanner.failures_total() + upstream_failures;
    status.blocks_unreadable =
        c.blocks_unreadable + upstream_blocks.not_indexed + upstream_blocks.out_of_range;
    status.walks_incomplete = c.subnode_walks_incomplete + c.row_index_walks_failed;
    status.scans_capped = report.messages.stopped_early + report.associated.stopped_early;
    status.unsupported_structures = source.findings.unsupported;
    status.documented_non_heap = source.findings.documented_non_heap;
    status.content_unreadable = c.messages_with_unreadable_body + c.attachments_with_unreadable_payload;
    // An attached message no cap let the recursion reach is as uncounted as a Message object a scan cap
    // left out, and the two caps are different questions with different fixes.
    status.embedded_capped = report.embedded_walks.depth_capped + report.embedded_walks.capped;
    const auto reason = [&](uint64_t count, const char *text) {
        if (count != 0) {
            status.reasons.push_back(std::to_string(count) + " " + text);
        }
    };
    reason(status.decode_failures, "decode failures: bytes that contradicted their own metadata");
    reason(status.logged_findings, "logged findings from the block source and the seams under this layer");
    reason(status.blocks_unreadable, "blocks the index named and the reader could not get");
    reason(status.walks_incomplete, "subnode BTree or RowIndex walks that stopped short of the whole list");
    reason(status.scans_capped, "Message objects left unscanned by a work cap");
    reason(status.content_unreadable, "item content a record named and this reader could not get");
    reason(status.embedded_capped, "attached messages left unscanned by the depth or work cap");
    status.clean = status.decode_failures == 0 && status.logged_findings == 0 &&
                   status.blocks_unreadable == 0 && status.walks_incomplete == 0 &&
                   status.scans_capped == 0 && status.content_unreadable == 0 &&
                   status.embedded_capped == 0;

    return report;
}

} // namespace ost2pst::msg
