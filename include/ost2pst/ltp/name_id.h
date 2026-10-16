#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/node_value.h"
#include "ost2pst/ltp/pc.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_budget.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ltp {

// --- NAMEID record ([MS-PST] 2.4.7.1) ---
// dwPropertyID means three different things depending on where the record lives and on the N bit: a
// byte offset into the String Stream (an Entry Stream record naming a string), a numeric name (an
// Entry Stream record with N == 0), or the CRC32 of the name (any record inside a hash bucket).
struct NameIdRecord {
    uint32_t property_id = 0;
    uint16_t guid_word = 0; // the raw WORD holding N in its lowest bit and wGuid above it; the
                            // whole WORD is what [MS-PST] 2.4.7.5 puts into the bucket formula
    bool name_is_string = false; // the N bit as written
    uint16_t guid_index = 0;
    uint16_t prop_index = 0;
    uint64_t offset = 0; // offset of the record inside the stream it came from
};

util::Result<NameIdRecord> decode_name_id_record(util::ByteView record);

// [MS-PST] 2.4.7.1: the NPID of a named property is 0x8000 plus wPropIdx.
constexpr uint16_t name_id_npid(const NameIdRecord& record) {
    return static_cast<uint16_t>(kNpidBase +
                                 record.prop_index); // [MS-PST] 2.4.7.1 NPID = 0x8000 + wPropIdx
}

// [MS-PST] 2.4.7.5: the CRC32 ([MS-PST] 5.3) of the name bytes, which is what a hash-bucket record
// keeps in dwPropertyID when the name is a string. The String Stream holds Unicode even for an ANSI
// PST, so the bytes hashed are the UTF-16LE bytes of the name, without the length DWORD that
// precedes it and without a terminator: measured on a real OST, 842 of 842 String Stream names hash
// to the bucket record that mirrors them under exactly this reading, and none of the four other
// readings hashes to any of them.
uint32_t name_id_crc(const std::u16string& name);

// [MS-PST] 2.4.7.4: a name sits at dwPropertyID in the String Stream, behind a DWORD byte length,
// in Unicode, not null terminated.
util::Result<std::u16string> name_id_string_at(util::ByteView stream, uint32_t offset);

// [MS-PST] 2.4.7.1: wGuid says which property set a named property belongs to -- one of the two
// well-known sets, no GUID, or an entry of the GUID Stream. [MS-PST] names the two well-known sets
// and defers their bytes to [MS-OXPROPS] 1.3.2, which is not in docs/reference/; docs/reference/
// pff-format.asciidoc:2264 and :2266 record both GUIDs and the libfmapi tables under third_party/
// hold the same 16 bytes, so the reader carries them and marks them as reference values, not file
// bytes.
enum class NameIdGuidKind {
    kNone,          // wGuid 0: NAMEID_GUID_NONE ([MS-PST] 2.4.7.1)
    kMapi,          // wGuid 1: PS_MAPI
    kPublicStrings, // wGuid 2: PS_PUBLIC_STRINGS
    kStream,        // wGuid > 2: the (wGuid - 3)th 16-byte entry of the GUID Stream
    kOutOfRange,    // wGuid > 2 and the GUID Stream does not reach that entry
};

const char* name_id_guid_kind_name(NameIdGuidKind kind);

// Which kind a wGuid is, given how many GUIDs the GUID Stream actually holds.
NameIdGuidKind name_id_guid_kind(uint16_t guid_index, uint64_t guid_stream_bytes);

// [MS-PST] 2.4.7.3 / 2.4.7.5: a stream is a flat array of NAMEID records. A record that does not
// fit is logged and ends that stream; work is capped so a corrupt length cannot spin.
struct NameIdStats {
    uint64_t entry_records = 0;
    uint64_t bucket_records = 0;
    uint64_t buckets_present = 0;
    uint64_t buckets_missing = 0;
    uint64_t records_skipped = 0;
    uint64_t names_resolved = 0;
    uint64_t names_unresolved = 0;
    uint64_t ragged_streams = 0;
    uint64_t ragged_string_padding =
        0; // names whose byte length is not a multiple of 4, so the stream pads after them
    uint64_t bucket_mismatches = 0; // a bucket record that does not hash to the bucket holding it
    uint64_t crc_matches = 0;       // an Entry Stream name whose CRC is in the bucket it hashes to
    uint64_t crc_mismatches = 0;
    uint64_t string_names = 0;          // names the String Stream enumeration produced
    uint64_t string_names_past_end = 0; // a name whose bytes run past the end of the stream
    uint64_t entries_string = 0;        // Entry Stream records holding a String Stream offset
    uint64_t entries_numeric = 0;       // Entry Stream records holding a numeric name
    uint64_t string_offsets_unmatched =
        0; // an N == 1 record whose offset names no String Stream name
    uint64_t guid_refs_out_of_range = 0; // a wGuid pointing past the end of the GUID Stream
    uint64_t guid_stream_bytes = 0;
    uint64_t guid_stream_entries = 0; // 16-byte GUIDs the GUID Stream holds
    uint64_t guid_distinct = 0;       // distinct byte values among them
    uint64_t guid_custom_refs = 0;    // Entry Stream records that resolve through the GUID Stream
    uint64_t guid_stream_ragged_bytes = 0;      // bytes past the last whole GUID in the GUID Stream
    std::map<std::string, uint64_t> guid_kinds; // kind name -> Entry Stream records using it
    uint64_t entry_stream_bytes = 0;
    uint64_t string_stream_bytes = 0;
    uint64_t bucket_stream_bytes = 0;
    uint64_t max_bucket_records = 0;
    uint64_t max_name_bytes = 0;
    uint16_t npid_min = 0;
    uint16_t npid_max = 0;
    uint32_t bucket_count = 0;
    bool bucket_count_defaulted = false;
    bool stopped_early = false;
};

// [MS-PST] 2.4.7.4: the String Stream is a packed list, so its names are only findable by walking
// it from offset 0. The offsets that walk produces are exactly what an Entry Stream dwPropertyID
// points at when the N bit is set, so the walk is what those offsets get validated against.
struct StringName {
    uint32_t offset = 0;
    uint32_t length = 0; // the length DWORD, in bytes
    std::u16string name;
};

// The walk stops at the first pair that does not fit and reports that through stats. A stream whose
// pairs all end on a 4-byte boundary and whose last pair ends at the end of the stream enumerated
// cleanly.
util::Result<std::vector<StringName>>
enumerate_name_id_strings(util::ByteView stream, NameIdStats& stats,
                          util::ByteBudget* workspace = nullptr);

using NameIdRecordCallback = std::function<bool(const NameIdRecord& record)>;

util::Status walk_name_id_records(util::ByteView stream, const NameIdRecordCallback& callback,
                                  NameIdStats& stats, ndb::FailureLog& failures);

// One named property: what the Entry Stream says about it, plus the name the String Stream gives
// it.
struct NamedProperty {
    uint16_t npid = 0;
    uint16_t guid_index = 0;
    // Its property set. [MS-PST] 2.4.7.1: the same string name under two property sets is two
    // different named properties, so the GUID is part of the identity, not a detail of the record.
    NameIdGuidKind guid_kind = NameIdGuidKind::kNone;
    std::vector<uint8_t>
        guid; // the 16 property-set GUID bytes: the file's own GUID Stream entry for a
              // wGuid above 2, or the two well-known values the reference notes record
    bool guid_resolved = false;
    bool guid_from_file =
        false; // the bytes came from this file's GUID Stream, not from a reference table
    bool n_bit_set = false;      // the N bit as written
    bool name_is_string = false; // [MS-PST] 2.4.7.1: that bit decides, so it is carried through
    uint32_t string_offset = 0;  // the byte offset of the name in the String Stream
    uint32_t numeric_name = 0;   // the numeric name itself
    std::u16string name;         // empty when the name is numeric or the offset did not resolve
    bool name_resolved = false;
    uint64_t entry_offset = 0;
};

// The Name-to-ID Map read out of the property records of the node at NID_NAME_TO_ID_MAP
// ([MS-PST] 2.4.7).
struct NameIdMap {
    uint32_t bucket_count = 0;
    std::vector<NamedProperty> entries;       // the Entry Stream, in stream order
    std::vector<NameIdRecord> bucket_records; // every hash-bucket record, in bucket order
    std::vector<uint8_t> guid_stream; // the GUID Stream, kept so a caller can resolve a wGuid later
    NameIdStats stats;
};

// The properties come from read_pc over the node's PC; the streams behind them are resolved through
// the ValueSource, because in an OST the Entry and String Streams sit in subnodes.
//
// An Entry Stream record is read the way [MS-PST] 2.4.7.1 writes it: N == 1 resolves dwPropertyID
// through the String Stream, N == 0 keeps it as the 16-bit numeric name. The hash buckets are then
// walked to verify the bucket formula and the CRC32 of every name that resolved.
util::Result<NameIdMap> read_name_id_map(const std::vector<PcRecord>& properties,
                                         ValueSource& values, NameIdStats& stats,
                                         ndb::FailureLog& failures,
                                         util::ByteBudget* workspace = nullptr);

// [MS-PST] 2.4.7.5: a CRC match is only a candidate. The name itself decides, so a lookup hashes
// the name, walks the bucket it hashes to, and compares the names of the records that match the
// CRC.
util::Result<NamedProperty> name_id_lookup(const NameIdMap& map, const std::u16string& name);
util::Result<NamedProperty> name_id_lookup_npid(const NameIdMap& map, uint16_t npid);

// [MS-PST] 2.4.7.1: a name is only unique inside its property set, so a lookup that has both has to
// match both. This is what distinguishes two named properties that share a string name.
util::Result<NamedProperty>
name_id_lookup_name_guid(const NameIdMap& map, const std::u16string& name, uint16_t guid_index);

// The GUID a NAMEID record points at ([MS-PST] 2.4.7.1 / 2.4.7.2): one of the two well-known
// property sets, none, or the (wGuid - 3)th 16-byte entry of the GUID Stream.
util::Result<util::ByteView> name_id_guid(const NameIdRecord& record, util::ByteView guid_stream);

// The 16 bytes of a property-set GUID in the usual text form. [MS-PST] 2.4.7.2 says the GUID Stream
// holds the GUIDs; the text form is the mixed-endian one: the first three fields little-endian, the
// last eight bytes in order.
std::string name_id_guid_text(const std::vector<uint8_t>& guid);

const char* name_id_guid_name(uint16_t guid_index);
std::string name_id_utf8(const std::u16string& name);

} // namespace ost2pst::ltp
