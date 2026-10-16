#include "ost2pst/ltp/name_id.h"

#include <cstdio>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>

#include "ost2pst/util/crc32.h"

#include "internal/take.h"

namespace ost2pst::ltp {

using ndb::FailureLog;
using util::ByteView;
using util::DataError;
using util::ErrorKind;
using util::make_error;
using util::Result;
using util::Status;

namespace {

// A stream value has to be owned before the next value is fetched: a subnode block is read through
// a source that reuses its buffer, and the map needs the Entry Stream and the String Stream at
// once.
std::vector<uint8_t> own(ByteView view) {
    return std::vector<uint8_t>(view.data(), view.data() + view.size());
}

// [MS-PST] 2.4.7.1 names PS_MAPI and PS_PUBLIC_STRINGS but defers their bytes to
// [MS-OXPROPS] 1.3.2, which this repository does not carry. libpff format notes (see THIRD_PARTY_NOTICES.txt):2264
// and :2266 record both GUIDs (00020328-... and 00020329-...) and the libfmapi tables this
// repository builds against, upstream libpff/libfmapi/libfmapi_class_identifier.c:29 and :32,
// hold the same 16 bytes, so the reader carries them as reference values and never claims they came
// from the file.
constexpr uint8_t kGuidMapi[kNameIdGuidSize] = {0x28, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};
constexpr uint8_t kGuidPublicStrings[kNameIdGuidSize] = {
    0x29, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};

const PcRecord* find_property(const std::vector<PcRecord>& properties, uint16_t prop_id) {
    for (const PcRecord& record : properties) {
        if (record.prop_id == prop_id) {
            return &record;
        }
    }
    return nullptr;
}

// One NAMEID record folded into a single key, so a hash-bucket record can be matched against the
// Entry Stream record it mirrors.
uint64_t record_key(uint32_t property_id, uint16_t guid_index, uint16_t prop_index) {
    return (static_cast<uint64_t>(property_id) << 32) | (static_cast<uint64_t>(guid_index) << 16) |
           prop_index;
}

} // namespace

Result<NameIdRecord> decode_name_id_record(ByteView record) {
    if (!record.in_range(0, static_cast<size_t>(kNameIdRecordSize))) {
        return make_error(ErrorKind::kTruncated, "NAMEID", record.base(), record.size(),
                          "a NAMEID record is dwPropertyID, the N and wGuid WORD, then wPropIdx");
    }
    NameIdRecord parsed;
    DataError failure;
    if (!take(record.u32(kNameIdPropertyIdOffset), parsed.property_id, "NAMEID.dwPropertyID",
              failure)) {
        return failure;
    }
    if (!take(record.u16(kNameIdGuidOffset), parsed.guid_word, "NAMEID.wGuid", failure)) {
        return failure;
    }
    if (!take(record.u16(kNameIdPropIdxOffset), parsed.prop_index, "NAMEID.wPropIdx", failure)) {
        return failure;
    }
    parsed.name_is_string = (parsed.guid_word & kNameIdNameBit) != 0;
    parsed.guid_index = static_cast<uint16_t>(parsed.guid_word >> kNameIdGuidShift);
    parsed.offset = record.base();
    return parsed;
}

uint32_t name_id_crc(const std::u16string& name) {
    // [MS-PST] 2.4.7.4: the String Stream is Unicode even in an ANSI PST, so the bytes a name
    // hashes to are its UTF-16LE bytes. [MS-PST] 5.3 fixes the CRC variant: seed 0, no final
    // complement.
    const ByteView bytes(reinterpret_cast<const uint8_t*>(name.data()), name.size() * 2, 0);
    return util::crc32(bytes);
}

Result<std::u16string> name_id_string_at(ByteView stream, uint32_t offset) {
    Result<uint32_t> length = stream.u32(offset);
    if (!length.ok()) {
        return length.error();
    }
    const uint64_t bytes = length.value();
    if (bytes > kNameidMaxNameBytes) {
        return make_error(ErrorKind::kBadField, "NPMAP.StringStream.cbName", stream.base() + offset,
                          bytes,
                          "the name length DWORD is larger than any name this reader will copy");
    }
    if (bytes % 2 != 0) {
        return make_error(ErrorKind::kBadField, "NPMAP.StringStream.cbName", stream.base() + offset,
                          bytes, "a Unicode name has an even byte length");
    }
    const uint64_t start = offset + kNameidStringLengthSize;
    if (!stream.in_range(start, bytes)) {
        return make_error(ErrorKind::kTruncated, "NPMAP.StringStream.Name", stream.base() + start,
                          bytes, "the name runs past the end of the String Stream");
    }
    std::u16string name;
    name.resize(static_cast<size_t>(bytes / 2));
    for (uint64_t index = 0; index < name.size(); ++index) {
        name[static_cast<size_t>(index)] = static_cast<char16_t>(
            stream.data()[start + index * 2] |
            (static_cast<uint16_t>(stream.data()[start + index * 2 + 1]) << 8));
    }
    return name;
}

Result<std::vector<StringName>> enumerate_name_id_strings(ByteView stream, NameIdStats& stats,
                                                          util::ByteBudget* workspace) {
    std::vector<StringName> names;
    uint64_t offset = 0;
    while (offset < stream.size()) {
        if (workspace) {
            const auto length = stream.u32(offset);
            if (length.ok() && length.value() <= kNameidMaxNameBytes && length.value() % 2 == 0 &&
                stream.in_range(offset + kNameidStringLengthSize, length.value())) {
                // Engineering allowance for the name/vector and the offset lookup hash.
                auto reserved =
                    workspace->reserve(2ull * length.value() + 4 * sizeof(StringName) + 96,
                                       "NameID.workspace", stream.base() + offset);
                if (!reserved.ok())
                    return reserved.error();
            }
        }
        Result<std::u16string> name = name_id_string_at(stream, static_cast<uint32_t>(offset));
        if (!name.ok() || name.value().empty()) {
            // The packed list ends where a pair stops fitting; there is no count to consult.
            ++stats.string_names_past_end;
            break;
        }
        StringName item;
        item.offset = static_cast<uint32_t>(offset);
        item.length = static_cast<uint32_t>(name.value().size() * 2);
        item.name = name.take();
        if (item.length > stats.max_name_bytes) {
            stats.max_name_bytes = item.length;
        }
        // [MS-PST] 2.4.7.4: padding is added to the END of the name so the pair lands on a 4-byte
        // boundary, so the next name sits at offset + 4 + CEIL(cbName / 4) * 4. Measured on a real
        // OST: 26-byte, 20-byte, 34-byte and 74-byte names step 32, 24, 40 and 76 bytes, and the
        // walk of all 842 names ends exactly at the end of the stream.
        if (item.length % kNameidStringAlignment != 0) {
            ++stats.ragged_string_padding; // the name itself is not aligned, so the stream carries
                                           // padding
        }
        offset += kNameidStringLengthSize + ((item.length + 3) & ~3u);
        names.push_back(std::move(item));
        if (names.size() >= kNameidMaxRecords) {
            stats.stopped_early = true;
            break;
        }
    }
    stats.string_names += names.size();
    return names;
}

Status walk_name_id_records(ByteView stream, const NameIdRecordCallback& callback,
                            NameIdStats& stats, FailureLog& failures) {
    const uint64_t total = stream.size() / kNameIdRecordSize;
    if (stream.size() % kNameIdRecordSize != 0) {
        // [MS-PST] 2.4.7.3: the stream is a flat array of records, so a length that is not a
        // multiple of the record size means the stream is corrupt at its end.
        ++stats.ragged_streams;
        failures.add(make_error(ErrorKind::kBadField, "NPMAP.stream.cb", stream.base(),
                                stream.size(),
                                "a NAMEID stream is a flat array of 8-byte records"));
    }
    uint64_t limit = total;
    if (limit > kNameidMaxRecords) {
        limit = kNameidMaxRecords;
        stats.records_skipped += total - limit;
        stats.stopped_early = true;
    }
    for (uint64_t index = 0; index < limit; ++index) {
        Result<ByteView> view =
            stream.sub(index * kNameIdRecordSize, static_cast<size_t>(kNameIdRecordSize));
        if (!view.ok()) {
            failures.add(view.error());
            ++stats.records_skipped;
            continue;
        }
        Result<NameIdRecord> record = decode_name_id_record(view.value());
        if (!record.ok()) {
            failures.add(record.error());
            ++stats.records_skipped;
            continue;
        }
        if (!callback(record.value())) {
            stats.stopped_early = true;
            stats.records_skipped += total - index - 1;
            break;
        }
    }
    return Status();
}

Result<NameIdMap> read_name_id_map(const std::vector<PcRecord>& properties, ValueSource& values,
                                   NameIdStats& stats, FailureLog& failures,
                                   util::ByteBudget* workspace) {
    NameIdMap map;

    // [MS-PST] 2.4.7.5: a reader MUST consult PidTagNameidBucketCount for the bucket count.
    const PcRecord* counted = find_property(properties, kPropNameidBucketCount);
    if (counted == nullptr) {
        return make_error(ErrorKind::kBadField, "NPMAP.PidTagNameidBucketCount", 0, 0,
                          "the Name-to-ID Map PC carries no bucket count property");
    }
    if (!counted->value_inline) {
        return make_error(ErrorKind::kBadField, "NPMAP.PidTagNameidBucketCount", counted->offset,
                          counted->value_hnid,
                          "PidTagNameidBucketCount is PtypInteger32, so its value sits inline");
    }
    uint32_t bucket_count = 0;
    DataError failure;
    if (!take(counted->value.u32(0), bucket_count, "NPMAP.PidTagNameidBucketCount", failure)) {
        return failure;
    }
    if (bucket_count == 0 || bucket_count > kNameidMaxBucketCount) {
        return make_error(ErrorKind::kBadField, "NPMAP.PidTagNameidBucketCount", counted->offset,
                          bucket_count,
                          "the bucket count is zero or past the cap this reader will walk");
    }
    map.bucket_count = bucket_count;
    stats.bucket_count = bucket_count;
    stats.bucket_count_defaulted = bucket_count != kNameidBucketCountRecommended;

    auto fetch = [&](uint16_t prop_id, std::vector<uint8_t>& out) -> Status {
        const PcRecord* record = find_property(properties, prop_id);
        if (record == nullptr) {
            return make_error(ErrorKind::kBadField, "NPMAP.property", 0, prop_id,
                              "the Name-to-ID Map PC carries no property with this id");
        }
        Result<ByteView> view = values.value(record->value_hnid);
        if (!view.ok()) {
            return view.error();
        }
        if (workspace) {
            auto reserved = workspace->reserve(2ull * view.value().size(), "NameID.workspace");
            if (!reserved.ok())
                return reserved;
        }
        out = own(view.value());
        return Status();
    };

    std::vector<uint8_t> entry_stream;
    std::vector<uint8_t> string_stream;
    std::vector<uint8_t> guid_stream;
    Status status = fetch(kPropNameidStreamEntry, entry_stream);
    if (!status) {
        return status.error();
    }
    status = fetch(kPropNameidStreamString, string_stream);
    if (!status) {
        return status.error();
    }
    // [MS-PST] 2.4.7.2: the GUID Stream only matters for a wGuid above 2, so a map without one is
    // not a data error until a record actually asks for it.
    const PcRecord* guids = find_property(properties, kPropNameidStreamGuid);
    if (guids != nullptr) {
        Result<ByteView> view = values.value(guids->value_hnid);
        if (!view.ok()) {
            return view.error();
        }
        if (workspace) {
            auto reserved = workspace->reserve(2ull * view.value().size(), "NameID.workspace");
            if (!reserved.ok())
                return reserved.error();
        }
        guid_stream = own(view.value());
    }

    const ByteView entries(entry_stream.data(), entry_stream.size(), 0);
    const ByteView strings(string_stream.data(), string_stream.size(), 0);
    const ByteView guid_bytes(guid_stream.data(), guid_stream.size(), 0);
    stats.entry_stream_bytes = entry_stream.size();
    stats.string_stream_bytes = string_stream.size();
    stats.guid_stream_bytes = guid_stream.size();

    // [MS-PST] 2.4.7.4: the String Stream is packed, so its name offsets are only knowable by
    // walking it from the start. That index is what an N == 1 dwPropertyID gets checked against.
    Result<std::vector<StringName>> enumerated =
        enumerate_name_id_strings(strings, stats, workspace);
    if (!enumerated.ok()) {
        return enumerated.error();
    }
    const std::vector<StringName> names = enumerated.take();
    std::unordered_map<uint32_t, const StringName*> name_at;
    for (const StringName& item : names) {
        name_at[item.offset] = &item;
    }

    status = walk_name_id_records(
        entries,
        [&](const NameIdRecord& record) {
            if (workspace) {
                // Includes vector growth, GUID ownership and downstream identity/registry copies.
                auto reserved =
                    workspace->reserve(4 * (sizeof(NamedProperty) + kNameIdGuidSize) + 128,
                                       "NameID.workspace", record.offset);
                if (!reserved.ok())
                    return false;
            }
            NamedProperty property;
            property.guid_index = record.guid_index;
            // [MS-PST] 2.4.7.1 / 2.4.7.2: the property set is part of what the record names. A
            // wGuid above 2 is resolved through the GUID Stream; one that the stream does not reach
            // is a finding about this record, not something to count quietly.
            property.guid_kind = name_id_guid_kind(record.guid_index, guid_stream.size());
            ++stats.guid_kinds[name_id_guid_kind_name(property.guid_kind)];
            if (property.guid_kind == NameIdGuidKind::kStream) {
                Result<ByteView> bytes = name_id_guid(record, guid_bytes);
                if (bytes.ok()) {
                    property.guid.assign(bytes.value().data(),
                                         bytes.value().data() + bytes.value().size());
                    property.guid_resolved = true;
                    property.guid_from_file = true;
                    ++stats.guid_custom_refs;
                }
            } else if (property.guid_kind == NameIdGuidKind::kMapi ||
                       property.guid_kind == NameIdGuidKind::kPublicStrings) {
                const uint8_t* known =
                    property.guid_kind == NameIdGuidKind::kMapi ? kGuidMapi : kGuidPublicStrings;
                property.guid.assign(known, known + kNameIdGuidSize);
                property.guid_resolved = true;
            } else if (property.guid_kind == NameIdGuidKind::kOutOfRange) {
                ++stats.guid_refs_out_of_range;
                failures.add(make_error(
                    ErrorKind::kBadField, "NAMEID.wGuid", record.offset, record.guid_index,
                    "the GUID Stream holds " +
                        std::to_string(guid_stream.size() / kNameIdGuidSize) +
                        " GUIDs, this record asks for the " +
                        std::to_string(record.guid_index - kNameIdGuidStreamFirst) +
                        "th entry of it"));
            }
            property.n_bit_set = record.name_is_string;
            property.name_is_string = record.name_is_string;
            property.npid = name_id_npid(record);
            property.entry_offset = record.offset;
            // [MS-PST] 2.4.7.1: the N bit decides on its own. N == 1 means dwPropertyID is a String
            // Stream offset, N == 0 means it is the 16-bit numeric name.
            if (record.name_is_string) {
                property.string_offset = record.property_id;
                const auto found = name_at.find(record.property_id);
                if (found == name_at.end()) {
                    // The offset is not one the packed String Stream starts a name at, so the
                    // record points somewhere the stream does not hold.
                    ++stats.string_offsets_unmatched;
                    ++stats.names_unresolved;
                    failures.add(make_error(
                        ErrorKind::kBadField, "NAMEID.dwPropertyID", record.offset,
                        record.property_id,
                        "an N == 1 record names an offset no String Stream name starts at"));
                } else {
                    if (workspace) {
                        // A shared String Stream name can be copied into many distinct NAMEID
                        // entries.
                        auto reserved = workspace->reserve(8ull * found->second->name.size(),
                                                           "NameID.workspace", record.offset);
                        if (!reserved.ok())
                            return false;
                    }
                    property.name = found->second->name;
                    property.name_resolved = true;
                    ++stats.names_resolved;
                    if (property.name.size() * 2 > stats.max_name_bytes) {
                        stats.max_name_bytes = property.name.size() * 2;
                    }
                }
            } else {
                property.numeric_name = record.property_id;
            }
            if (stats.entry_records == 0 || property.npid < stats.npid_min) {
                stats.npid_min = property.npid;
            }
            if (property.npid > stats.npid_max) {
                stats.npid_max = property.npid;
            }
            ++stats.entry_records;
            map.entries.push_back(std::move(property));
            return true;
        },
        stats, failures);
    if (!status) {
        return status.error();
    }
    if (workspace && workspace->error())
        return *workspace->error();

    // [MS-PST] 2.4.7.5: the buckets are the properties 0x1000 .. 0x1000 + count - 1, each a flat
    // array of NAMEID records whose dwPropertyID is the CRC32 of the name instead of its String
    // Stream offset.
    for (uint32_t bucket = 0; bucket < bucket_count; ++bucket) {
        std::vector<uint8_t> bytes;
        status = fetch(static_cast<uint16_t>(kPropNameidBucketBase + bucket), bytes);
        if (!status) {
            if (workspace && workspace->error())
                return *workspace->error();
            ++stats.buckets_missing;
            continue;
        }
        ++stats.buckets_present;
        stats.bucket_stream_bytes += bytes.size();
        const ByteView stream(bytes.data(), bytes.size(), 0);
        uint64_t in_bucket = 0;
        walk_name_id_records(
            stream,
            [&](const NameIdRecord& record) {
                if (workspace) {
                    auto reserved = workspace->reserve(4 * sizeof(NameIdRecord) + 96,
                                                       "NameID.workspace", record.offset);
                    if (!reserved.ok())
                        return false;
                }
                ++in_bucket;
                ++stats.bucket_records;
                const uint32_t expected =
                    name_id_bucket(record.property_id, record.guid_word, bucket_count);
                if (expected != bucket) {
                    ++stats.bucket_mismatches;
                    failures.add(make_error(
                        ErrorKind::kBadField, "NAMEID.bucket", record.offset, expected,
                        "this record sits in bucket " + std::to_string(bucket) +
                            ", the bucket formula puts it in " + std::to_string(expected)));
                }
                map.bucket_records.push_back(record);
                return true;
            },
            stats, failures);
        if (workspace && workspace->error())
            return *workspace->error();
        if (in_bucket > stats.max_bucket_records) {
            stats.max_bucket_records = in_bucket;
        }
    }

    // [MS-PST] 2.4.7.5: a CRC match is only the candidate step. Pairing every Entry Stream name
    // with the bucket record that mirrors it is what proves the CRC and the bucket formula this
    // reader implements.
    std::unordered_map<uint64_t, uint64_t> candidates;
    for (const NameIdRecord& record : map.bucket_records) {
        ++candidates[record_key(record.property_id, record.guid_index, record.prop_index)];
    }
    // [MS-PST] 2.4.7.5: a bucket record mirrors the Entry Stream record it hashes to, holding the
    // CRC32 of the name where the entry holds the offset. Pairing the two is what proves the CRC
    // and the bucket formula this reader implements.
    for (const NamedProperty& property : map.entries) {
        // A string name hashes to its CRC; a numeric name is its own candidate ([MS-PST] 2.4.7.5).
        uint32_t candidate = 0;
        if (property.name_resolved) {
            candidate = name_id_crc(property.name);
        } else if (!property.name_is_string) {
            candidate = property.numeric_name;
        } else {
            continue; // the name never resolved, so there is nothing to compare against
        }
        const auto found = candidates.find(record_key(
            candidate, property.guid_index, static_cast<uint16_t>(property.npid - kNpidBase)));
        if (found != candidates.end()) {
            ++stats.crc_matches;
        } else {
            ++stats.crc_mismatches;
        }
    }
    for (const NamedProperty& property : map.entries) {
        if (property.name_is_string) {
            ++stats.entries_string;
        } else {
            ++stats.entries_numeric;
        }
    }
    // [MS-PST] 2.4.7.2: the GUID Stream is a flat array of 16-byte GUIDs. Keeping it is what lets a
    // caller turn a wGuid back into the property set after the map has been read.
    map.guid_stream = std::move(guid_stream);
    stats.guid_stream_entries = map.guid_stream.size() / kNameIdGuidSize;
    if (map.guid_stream.size() % kNameIdGuidSize != 0) {
        stats.guid_stream_ragged_bytes = map.guid_stream.size() % kNameIdGuidSize;
        failures.add(
            make_error(ErrorKind::kBadField, "NPMAP.guidStream", 0, map.guid_stream.size(),
                       "the GUID Stream is a flat array of 16-byte GUIDs, this one leaves " +
                           std::to_string(stats.guid_stream_ragged_bytes) +
                           " bytes past the last whole GUID"));
    }
    std::set<std::vector<uint8_t>> distinct;
    for (uint64_t offset = 0; offset + kNameIdGuidSize <= map.guid_stream.size();
         offset += kNameIdGuidSize) {
        distinct.insert(std::vector<uint8_t>(map.guid_stream.begin() + offset,
                                             map.guid_stream.begin() + offset + kNameIdGuidSize));
    }
    stats.guid_distinct = distinct.size();
    map.stats = stats;
    return map;
}

NameIdGuidKind name_id_guid_kind(uint16_t guid_index, uint64_t guid_stream_bytes) {
    if (guid_index < kNameIdGuidStreamFirst) {
        switch (guid_index) {
        case kNameIdGuidNone:
            return NameIdGuidKind::kNone;
        case kNameIdGuidMapi:
            return NameIdGuidKind::kMapi;
        default:
            return NameIdGuidKind::kPublicStrings;
        }
    }
    // [MS-PST] 2.4.7.1: wGuid 3 is the first entry of the GUID Stream, so the entry it asks for has
    // to fit.
    const uint64_t needed =
        (static_cast<uint64_t>(guid_index - kNameIdGuidStreamFirst) + 1) * kNameIdGuidSize;
    return needed > guid_stream_bytes ? NameIdGuidKind::kOutOfRange : NameIdGuidKind::kStream;
}

const char* name_id_guid_kind_name(NameIdGuidKind kind) {
    switch (kind) {
    case NameIdGuidKind::kNone:
        return "no GUID";
    case NameIdGuidKind::kMapi:
        return "PS_MAPI";
    case NameIdGuidKind::kPublicStrings:
        return "PS_PUBLIC_STRINGS";
    case NameIdGuidKind::kStream:
        return "GUID Stream";
    default:
        return "GUID Stream out of range";
    }
}

Result<NamedProperty> name_id_lookup(const NameIdMap& map, const std::u16string& name) {
    const uint32_t candidate_crc = name_id_crc(name);
    for (const NameIdRecord& record : map.bucket_records) {
        if (record.property_id != candidate_crc) {
            continue;
        }
        for (const NamedProperty& property : map.entries) {
            // [MS-PST] 2.4.7.5: the CRC only narrows the search, the name itself decides.
            if (property.name_resolved && property.guid_index == record.guid_index &&
                property.npid == name_id_npid(record) && property.name == name) {
                return property;
            }
        }
    }
    return make_error(ErrorKind::kUnsupported, "NPMAP.lookup", 0, candidate_crc,
                      "no named property in the map carries this name");
}

Result<NamedProperty> name_id_lookup_npid(const NameIdMap& map, uint16_t npid) {
    for (const NamedProperty& property : map.entries) {
        if (property.npid == npid) {
            return property;
        }
    }
    return make_error(ErrorKind::kUnsupported, "NPMAP.lookup", 0, npid,
                      "no named property in the map carries this NPID");
}

Result<NamedProperty> name_id_lookup_name_guid(const NameIdMap& map, const std::u16string& name,
                                               uint16_t guid_index) {
    for (const NamedProperty& property : map.entries) {
        if (property.name_resolved && property.name == name && property.guid_index == guid_index) {
            return property;
        }
    }
    return make_error(ErrorKind::kUnsupported, "NPMAP.lookup", 0, guid_index,
                      "no named property in the map carries this name under this property set");
}

Result<ByteView> name_id_guid(const NameIdRecord& record, ByteView guid_stream) {
    if (record.guid_index < kNameIdGuidStreamFirst) {
        return make_error(ErrorKind::kUnsupported, "NAMEID.wGuid", record.offset, record.guid_index,
                          std::string("this GUID is ") + name_id_guid_name(record.guid_index) +
                              ", not an entry of the GUID Stream");
    }
    // [MS-PST] 2.4.7.1: a wGuid above 2 is the index plus 3 into the GUID Stream.
    const uint64_t offset =
        static_cast<uint64_t>(record.guid_index - kNameIdGuidStreamFirst) * kNameIdGuidSize;
    return guid_stream.sub(offset, static_cast<size_t>(kNameIdGuidSize));
}

const char* name_id_guid_name(uint16_t guid_index) {
    switch (guid_index) {
    case kNameIdGuidNone:
        return "NAMEID_GUID_NONE";
    case kNameIdGuidMapi:
        return "PS_MAPI";
    case kNameIdGuidPublicStrings:
        return "PS_PUBLIC_STRINGS";
    default:
        return "GUID Stream";
    }
}

std::string name_id_guid_text(const std::vector<uint8_t>& guid) {
    if (guid.size() != kNameIdGuidSize) {
        return "";
    }
    auto word = [&](uint64_t offset) {
        return static_cast<uint32_t>(guid[offset]) |
               (static_cast<uint32_t>(guid[offset + 1]) << 8) |
               (static_cast<uint32_t>(guid[offset + 2]) << 16) |
               (static_cast<uint32_t>(guid[offset + 3]) << 24);
    };
    char text[64];
    std::snprintf(text, sizeof(text), "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", word(0),
                  static_cast<unsigned>(guid[4]) | (static_cast<unsigned>(guid[5]) << 8),
                  static_cast<unsigned>(guid[6]) | (static_cast<unsigned>(guid[7]) << 8),
                  static_cast<unsigned>(guid[8]), static_cast<unsigned>(guid[9]),
                  static_cast<unsigned>(guid[10]), static_cast<unsigned>(guid[11]),
                  static_cast<unsigned>(guid[12]), static_cast<unsigned>(guid[13]),
                  static_cast<unsigned>(guid[14]), static_cast<unsigned>(guid[15]));
    return text;
}

std::string name_id_utf8(const std::u16string& name) {
    std::string text;
    for (size_t index = 0; index < name.size(); ++index) {
        uint32_t code = static_cast<uint16_t>(name[index]);
        if (code >= 0xD800 && code <= 0xDBFF && index + 1 < name.size()) {
            const uint32_t low = static_cast<uint16_t>(name[index + 1]);
            if (low >= 0xDC00 && low <= 0xDFFF) {
                code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                ++index;
            }
        }
        if (code < 0x80) {
            text.push_back(static_cast<char>(code));
        } else if (code < 0x800) {
            text.push_back(static_cast<char>(0xC0 | (code >> 6)));
            text.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        } else if (code < 0x10000) {
            text.push_back(static_cast<char>(0xE0 | (code >> 12)));
            text.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
            text.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        } else {
            text.push_back(static_cast<char>(0xF0 | (code >> 18)));
            text.push_back(static_cast<char>(0x80 | ((code >> 12) & 0x3F)));
            text.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
            text.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        }
    }
    return text;
}

} // namespace ost2pst::ltp
