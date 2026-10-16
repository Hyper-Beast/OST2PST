// The Name-to-ID Map is a PC whose properties are streams and hash buckets ([MS-PST] 2.4.7): a
// NAMEID record array, a Unicode String Stream, a GUID Stream, and PidTagNameidBucketCount buckets
// that hold the CRC32 of each name instead of the name. This file checks the record, the streams,
// the bucket formula, and the rule that a CRC match is only a candidate until the name itself is
// compared.
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/name_id.h"
#include "ost2pst/ltp/node_value.h"
#include "ost2pst/ltp/pc.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/crc32.h"
#include "ost2pst/util/status.h"

#include "test_support.h"

namespace {

using ost2pst::ltp::decode_name_id_record;
using ost2pst::ltp::enumerate_name_id_strings;
using ost2pst::ltp::kNameIdRecordSize;
using ost2pst::ltp::kNpidBase;
using ost2pst::ltp::kPropNameidBucketBase;
using ost2pst::ltp::kPropNameidBucketCount;
using ost2pst::ltp::kPropNameidStreamEntry;
using ost2pst::ltp::kPropNameidStreamGuid;
using ost2pst::ltp::kPropNameidStreamString;
using ost2pst::ltp::name_id_bucket;
using ost2pst::ltp::name_id_crc;
using ost2pst::ltp::name_id_guid;
using ost2pst::ltp::name_id_guid_kind;
using ost2pst::ltp::name_id_guid_kind_name;
using ost2pst::ltp::name_id_guid_name;
using ost2pst::ltp::name_id_guid_text;
using ost2pst::ltp::name_id_lookup;
using ost2pst::ltp::name_id_lookup_name_guid;
using ost2pst::ltp::name_id_lookup_npid;
using ost2pst::ltp::name_id_npid;
using ost2pst::ltp::name_id_string_at;
using ost2pst::ltp::name_id_utf8;
using ost2pst::ltp::NamedProperty;
using ost2pst::ltp::NameIdGuidKind;
using ost2pst::ltp::NameIdMap;
using ost2pst::ltp::NameIdRecord;
using ost2pst::ltp::NameIdStats;
using ost2pst::ltp::PcRecord;
using ost2pst::ltp::read_name_id_map;
using ost2pst::ltp::StringName;
using ost2pst::ltp::ValueSource;
using ost2pst::ltp::walk_name_id_records;
using ost2pst::ndb::FailureLog;
using ost2pst::test::finish;
using ost2pst::util::ByteView;
using ost2pst::util::ErrorKind;
using ost2pst::util::make_error;
using ost2pst::util::Result;
using ost2pst::util::Status;

void put16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
}

void put32(std::vector<uint8_t>& out, uint32_t value) {
    for (uint64_t index = 0; index < 4; ++index) {
        out.push_back(static_cast<uint8_t>((value >> (8 * index)) & 0xFF));
    }
}

// [MS-PST] 2.4.7.1: dwPropertyID, then the WORD holding N in its lowest bit and wGuid above it,
// then wPropIdx. So N == 1 with wGuid 3 is the WORD 0x0007.
std::vector<uint8_t> name_id_bytes(uint32_t property_id, uint16_t guid_word, uint16_t prop_index) {
    std::vector<uint8_t> out;
    put32(out, property_id);
    put16(out, guid_word);
    put16(out, prop_index);
    return out;
}

// [MS-PST] 2.4.7.4: a DWORD byte length, the Unicode bytes, then padding to a 4-byte boundary.
std::vector<uint8_t> string_stream(const std::vector<std::u16string>& names,
                                   std::vector<uint32_t>& offsets) {
    std::vector<uint8_t> out;
    for (const std::u16string& name : names) {
        offsets.push_back(static_cast<uint32_t>(out.size()));
        const uint32_t bytes = static_cast<uint32_t>(name.size() * 2);
        put32(out, bytes);
        for (const char16_t unit : name) {
            put16(out, static_cast<uint16_t>(unit));
        }
        while (out.size() % 4 != 0) {
            out.push_back(0);
        }
    }
    return out;
}

std::u16string u16(const std::string& text) {
    std::u16string out;
    for (const char character : text) {
        out.push_back(static_cast<char16_t>(static_cast<unsigned char>(character)));
    }
    return out;
}

// The map reader only asks a HNID for bytes, so the fixture answers HNIDs out of a table.
class MapValues : public ValueSource {
  public:
    // ValueSource forbids copying, so the fixture moves its own streams instead.
    MapValues() = default;
    MapValues(MapValues&& other)
        : ValueSource(), streams_(std::move(other.streams_)), held_(std::move(other.held_)) {}

    void set(uint32_t hnid, std::vector<uint8_t> bytes) { streams_[hnid] = std::move(bytes); }

    Result<ByteView> value(uint32_t hnid) override {
        const auto found = streams_.find(hnid);
        if (found == streams_.end()) {
            return make_error(ErrorKind::kUnsupported, "MapValues.value", 0, hnid,
                              "this HNID has no stream");
        }
        held_ = found->second;
        return ByteView(held_.data(), held_.size(), 0);
    }

  private:
    std::map<uint32_t, std::vector<uint8_t>> streams_;
    std::vector<uint8_t> held_;
};

// An inline value is four bytes the record only points at, so the fixture keeps every one alive.
std::vector<std::vector<uint8_t>>& inline_values() {
    static std::vector<std::vector<uint8_t>> values;
    return values;
}

PcRecord inline_property(uint16_t prop_id, uint32_t value) {
    PcRecord record;
    record.prop_id = prop_id;
    record.prop_type = 0x0003; // PtypInteger32
    record.value_hnid = value;
    record.value_inline = true;
    std::vector<uint8_t> bytes;
    put32(bytes, value);
    inline_values().push_back(std::move(bytes));
    const std::vector<uint8_t>& held = inline_values().back();
    record.value = ByteView(held.data(), held.size(), 0);
    return record;
}

PcRecord stream_property(uint16_t prop_id, uint32_t hnid) {
    PcRecord record;
    record.prop_id = prop_id;
    record.prop_type = 0x0102; // PtypBinary
    record.value_hnid = hnid;
    record.value_in_heap = true;
    return record;
}

void test_record() {
    const std::vector<uint8_t> bytes = name_id_bytes(0x09575B3F, 0x0001, 0x0000);
    Result<NameIdRecord> record =
        decode_name_id_record(ByteView(bytes.data(), bytes.size(), 0x1000));
    TEST_OK(record, "NAMEID record");
    TEST_EQ(record.value().property_id, 0x09575B3F, "dwPropertyID");
    TEST_EQ(record.value().name_is_string ? 1u : 0u, 1u, "N bit");
    TEST_EQ(record.value().guid_index, 0, "wGuid");
    TEST_EQ(record.value().prop_index, 0, "wPropIdx");
    TEST_EQ(record.value().offset, 0x1000, "record offset");
    TEST_EQ(name_id_npid(record.value()), kNpidBase, "NPID of wPropIdx 0");

    // N == 0 with wGuid 1: a numeric name under PS_MAPI, and wPropIdx 5 -> NPID 0x8005.
    const std::vector<uint8_t> numeric = name_id_bytes(0x00000011, 0x0002, 0x0005);
    Result<NameIdRecord> number =
        decode_name_id_record(ByteView(numeric.data(), numeric.size(), 0));
    TEST_OK(number, "numeric NAMEID");
    TEST_EQ(number.value().name_is_string ? 1u : 0u, 0u, "N bit of a numeric name");
    TEST_EQ(number.value().guid_index, 1, "wGuid of a numeric name");
    TEST_EQ(name_id_npid(number.value()), 0x8005, "NPID of wPropIdx 5");

    // [MS-PST] 2.4.7.1: N is the lowest bit and wGuid the 15 above it, so N never leaks into the
    // index.
    const std::vector<uint8_t> big_guid = name_id_bytes(0, 0x0007, 0);
    Result<NameIdRecord> guid =
        decode_name_id_record(ByteView(big_guid.data(), big_guid.size(), 0));
    TEST_OK(guid, "NAMEID with the N bit set");
    TEST_EQ(guid.value().guid_index, 3, "wGuid above the N bit");

    TEST_ERROR(decode_name_id_record(ByteView(bytes.data(), kNameIdRecordSize - 1, 0x200)),
               ErrorKind::kTruncated, "NAMEID", "short NAMEID");
}

void test_crc() {
    // [MS-PST] 2.4.7.5: a hash bucket keeps the CRC32 of the name. [MS-PST] 2.4.7.4: the String
    // Stream is Unicode, so the hashed bytes are UTF-16LE. [MS-PST] 5.3: seed 0, no final
    // complement. Both values were measured with Python zlib over the same bytes.
    TEST_EQ(name_id_crc(u16("Author")), 0x09575B3F, "CRC32 of Author");
    TEST_EQ(name_id_crc(u16("x-ms-exchange-organization-authas")), 0x29A761E9,
            "CRC32 of the spec's own example name");
    TEST_EQ(name_id_crc(u16("Do Not Forward")), 0x6098B357, "CRC32 of Do Not Forward");
    TEST_EQ(name_id_crc(std::u16string()), 0, "CRC32 of an empty name");

    // [MS-PST] 2.4.7.5: ulBucket = (pul[0] ^ (pul[1] & 0xFFFF)) % BucketCount.
    const uint32_t count = 251;
    TEST_EQ(name_id_bucket(0x29A761E9, 0x0001, count),
            static_cast<uint32_t>((0x29A761E9u ^ 0x0001u) % count), "bucket of the spec example");
    TEST_EQ(name_id_bucket(0x00000011, 0x0002, count),
            static_cast<uint32_t>((0x11u ^ 0x02u) % count), "bucket of a numeric name");
    // pul[1] & 0xFFFF is the low WORD of the second DWORD, so wPropIdx never reaches the formula
    // while the N bit does: the same record with N cleared hashes to a different bucket.
    TEST_EQ(name_id_bucket(0x09575B3F, 0x0001 | (0x1234u << 16), count),
            name_id_bucket(0x09575B3F, 0x0001, count),
            "wPropIdx is not part of the bucket formula");
    TEST_CHECK(name_id_bucket(0x09575B3F, 0x0001, count) !=
               name_id_bucket(0x09575B3F, 0x0000, count));
}

void test_string_stream() {
    std::vector<uint32_t> offsets;
    const std::vector<uint8_t> stream =
        string_stream({u16("Author"), u16("Do Not Forward"), u"\u4e2d\u6587"}, offsets);
    TEST_EQ(offsets.size(), 3, "name count");
    TEST_EQ(offsets[0], 0, "first name offset");
    TEST_EQ(offsets[1], 16, "second name offset");
    TEST_EQ(offsets[2], 48, "third name offset");

    Result<std::u16string> first =
        name_id_string_at(ByteView(stream.data(), stream.size(), 0), offsets[0]);
    TEST_OK(first, "first name");
    TEST_STR(name_id_utf8(first.value()), "Author", "first name text");
    Result<std::u16string> second =
        name_id_string_at(ByteView(stream.data(), stream.size(), 0), offsets[1]);
    TEST_OK(second, "second name");
    TEST_STR(name_id_utf8(second.value()), "Do Not Forward", "second name text");
    Result<std::u16string> third =
        name_id_string_at(ByteView(stream.data(), stream.size(), 0), offsets[2]);
    TEST_OK(third, "third name");
    TEST_EQ(third.value().size(), 2, "non-ASCII name length in code units");

    // A name that runs past the end of the stream.
    std::vector<uint8_t> short_stream;
    put32(short_stream, 12);
    put16(short_stream, 'A');
    TEST_ERROR_OFFSET(
        name_id_string_at(ByteView(short_stream.data(), short_stream.size(), 0x800), 0), 0x804,
        "name past the end of the String Stream");

    // [MS-PST] 2.4.7.4: the name is Unicode, so an odd byte length cannot be one.
    std::vector<uint8_t> odd;
    put32(odd, 3);
    odd.push_back('A');
    odd.push_back('B');
    odd.push_back('C');
    TEST_ERROR(name_id_string_at(ByteView(odd.data(), odd.size(), 0), 0), ErrorKind::kBadField,
               "NPMAP.StringStream.cbName", "odd name length");

    // A corrupt length DWORD must not make the reader copy four gigabytes.
    std::vector<uint8_t> huge;
    put32(huge, 0xFFFFFFFFu);
    TEST_ERROR(name_id_string_at(ByteView(huge.data(), huge.size(), 0), 0), ErrorKind::kBadField,
               "NPMAP.StringStream.cbName", "name length past the cap");
}

void test_walk() {
    std::vector<uint8_t> stream;
    for (uint16_t index = 0; index < 3; ++index) {
        const std::vector<uint8_t> record = name_id_bytes(index, 0x0001, index);
        stream.insert(stream.end(), record.begin(), record.end());
    }
    stream.push_back(0xAA);
    stream.push_back(0xBB);
    stream.push_back(0xCC); // [MS-PST] 2.4.7.3: a stream is a flat array, so this tail is corrupt.

    NameIdStats stats;
    FailureLog failures(5);
    uint64_t walked = 0;
    Status status = walk_name_id_records(
        ByteView(stream.data(), stream.size(), 0x900),
        [&](const NameIdRecord&) {
            ++walked;
            return true;
        },
        stats, failures);
    TEST_OK(status, "walk a ragged stream");
    TEST_EQ(walked, 3, "whole records walked");
    TEST_EQ(stats.ragged_streams, 1, "ragged stream counted");
    TEST_EQ(failures.total(), 1, "ragged stream reported");

    NameIdStats stopped;
    FailureLog quiet(5);
    uint64_t seen = 0;
    status = walk_name_id_records(
        ByteView(stream.data(), 24, 0),
        [&](const NameIdRecord&) {
            ++seen;
            return seen < 2;
        },
        stopped, quiet);
    TEST_OK(status, "walk that a callback stops");
    TEST_EQ(seen, 2, "records the callback saw");
    TEST_EQ(stopped.stopped_early ? 1u : 0u, 1u, "the stop is recorded");
    TEST_EQ(stopped.records_skipped, 1, "the record past the stop is counted");
}

// One Name-to-ID Map: two string names and one numeric name, each mirrored in the bucket its own
// CRC hashes to.
struct Fixture {
    std::vector<PcRecord> properties;
    MapValues values;
    std::vector<uint32_t> name_offsets;
    uint32_t bucket_of[3] = {0, 0, 0};
};

Fixture build_fixture(uint32_t bucket_count = 251) {
    Fixture fixture;
    const std::vector<uint8_t> strings =
        string_stream({u16("Author"), u16("Do Not Forward")}, fixture.name_offsets);

    std::vector<uint8_t> entries;
    const std::vector<uint8_t> first =
        name_id_bytes(fixture.name_offsets[0], 0x0001, 0); // N == 1, wGuid 0
    const std::vector<uint8_t> second =
        name_id_bytes(fixture.name_offsets[1], 0x0003, 1); // N == 1, wGuid 1
    const std::vector<uint8_t> third =
        name_id_bytes(0x00000011, 0x0002, 2); // N == 0: a numeric name
    entries.insert(entries.end(), first.begin(), first.end());
    entries.insert(entries.end(), second.begin(), second.end());
    entries.insert(entries.end(), third.begin(), third.end());

    std::vector<uint8_t> guids;
    for (uint8_t byte = 0; byte < 32; ++byte) {
        guids.push_back(byte);
    }

    fixture.properties.push_back(inline_property(kPropNameidBucketCount, bucket_count));
    fixture.properties.push_back(stream_property(kPropNameidStreamEntry, 0x60));
    fixture.properties.push_back(stream_property(kPropNameidStreamString, 0x61));
    fixture.properties.push_back(stream_property(kPropNameidStreamGuid, 0x62));
    fixture.values.set(0x60, entries);
    fixture.values.set(0x61, strings);
    fixture.values.set(0x62, guids);

    if (bucket_count == 0) {
        return fixture; // [MS-PST] 2.4.7.5: with no buckets there is nothing to place
    }
    const uint32_t crcs[3] = {name_id_crc(u16("Author")), name_id_crc(u16("Do Not Forward")),
                              0x00000011};
    const uint16_t guid_words[3] = {0x0001, 0x0003, 0x0002};
    for (uint32_t index = 0; index < 3; ++index) {
        const std::vector<uint8_t> record =
            name_id_bytes(crcs[index], guid_words[index], static_cast<uint16_t>(index));
        fixture.bucket_of[index] = name_id_bucket(crcs[index], guid_words[index], bucket_count);
        const uint16_t prop_id =
            static_cast<uint16_t>(kPropNameidBucketBase + fixture.bucket_of[index]);
        fixture.properties.push_back(stream_property(prop_id, 0x100 + index));
        fixture.values.set(0x100 + index, record);
    }
    return fixture;
}

void test_map() {
    Fixture fixture = build_fixture();
    {
        NameIdStats limited_stats;
        FailureLog limited_failures;
        ost2pst::util::ByteBudget budget(1);
        TEST_ERROR(read_name_id_map(fixture.properties, fixture.values, limited_stats,
                                    limited_failures, &budget),
                   ErrorKind::kUnsupported, "NameID.workspace",
                   "decoded NameID allocations must reserve budget");
    }
    {
        MapValues shared;
        const std::u16string name(1024, u'x');
        std::vector<uint32_t> offsets;
        shared.set(0x61, string_stream({name}, offsets));
        std::vector<uint8_t> entries, buckets;
        for (uint16_t index = 0; index < 10; ++index) {
            const auto entry = name_id_bytes(0, 1, index);
            const auto bucket = name_id_bytes(name_id_crc(name), 1, index);
            entries.insert(entries.end(), entry.begin(), entry.end());
            buckets.insert(buckets.end(), bucket.begin(), bucket.end());
        }
        shared.set(0x60, entries);
        shared.set(0x100, buckets);
        const std::vector<PcRecord> properties{inline_property(kPropNameidBucketCount, 1),
                                               stream_property(kPropNameidStreamEntry, 0x60),
                                               stream_property(kPropNameidStreamString, 0x61),
                                               stream_property(kPropNameidBucketBase, 0x100)};
        NameIdStats enough_stats;
        FailureLog enough_failures;
        ost2pst::util::ByteBudget enough(1024 * 1024);
        auto carried = read_name_id_map(properties, shared, enough_stats, enough_failures, &enough);
        TEST_OK(carried, "shared name with sufficient construction budget");
        if (carried.ok()) {
            TEST_EQ(carried.value().entries.size(), 10, "all shared name copies retained");
            TEST_EQ(enough_failures.total(), 0, "shared-name fixture is complete");
        }
        NameIdStats small_stats;
        FailureLog small_failures;
        ost2pst::util::ByteBudget small(12000);
        TEST_ERROR(read_name_id_map(properties, shared, small_stats, small_failures, &small),
                   ErrorKind::kUnsupported, "NameID.workspace",
                   "refuse repeated name copies even though stream bytes fit");
        TEST_CHECK(small_stats.entry_records < 10);
    }
    NameIdStats stats;
    FailureLog failures(5);
    Result<NameIdMap> map = read_name_id_map(fixture.properties, fixture.values, stats, failures);
    TEST_OK(map, "read the Name-to-ID Map");
    TEST_EQ(map.value().bucket_count, 251, "bucket count");
    TEST_EQ(stats.bucket_count_defaulted ? 1u : 0u, 0u, "251 is the recommended count");
    TEST_EQ(map.value().entries.size(), 3, "Entry Stream records");
    TEST_EQ(stats.entry_records, 3, "entry records counted");
    TEST_EQ(stats.names_resolved, 2, "string names resolved");
    TEST_EQ(stats.names_unresolved, 0, "no name left unresolved");
    TEST_EQ(stats.npid_min, 0x8000, "lowest NPID");
    TEST_EQ(stats.npid_max, 0x8002, "highest NPID");
    TEST_EQ(stats.bucket_records, 3, "bucket records read");
    TEST_EQ(stats.buckets_present, 3, "buckets the PC carries");
    TEST_EQ(stats.buckets_missing, 248, "buckets the PC does not carry");
    TEST_EQ(stats.bucket_mismatches, 0, "every record is in the bucket it hashes to");
    TEST_EQ(stats.crc_matches, 3, "every entry is mirrored by its bucket record");
    TEST_EQ(stats.crc_mismatches, 0, "no entry lost its bucket record");
    TEST_EQ(failures.total(), 0, "a well-formed map reports nothing");

    const NamedProperty& author = map.value().entries[0];
    TEST_EQ(author.npid, 0x8000, "NPID of Author");
    TEST_EQ(author.guid_index, 0, "Author carries no GUID");
    TEST_STR(name_id_utf8(author.name), "Author", "Author name text");
    TEST_EQ(author.string_offset, fixture.name_offsets[0], "Author String Stream offset");
    TEST_EQ(map.value().entries[2].numeric_name, 0x0011, "numeric name");
    TEST_EQ(map.value().entries[2].name_resolved ? 1u : 0u, 0u,
            "a numeric name has no String Stream entry");

    Result<NamedProperty> found = name_id_lookup(map.value(), u16("Author"));
    TEST_OK(found, "lookup by name");
    TEST_EQ(found.value().npid, 0x8000, "lookup found the right NPID");
    TEST_ERROR(name_id_lookup(map.value(), u16("Authorship")), ErrorKind::kUnsupported,
               "NPMAP.lookup", "a name the map does not hold");
    TEST_OK(name_id_lookup_npid(map.value(), 0x8001), "lookup by NPID");
    TEST_ERROR(name_id_lookup_npid(map.value(), 0x8100), ErrorKind::kUnsupported, "NPMAP.lookup",
               "an NPID the map does not hold");
}

void test_map_rejects() {
    {
        Fixture fixture = build_fixture();
        fixture.properties.erase(fixture.properties.begin()); // no PidTagNameidBucketCount
        NameIdStats stats;
        FailureLog failures(5);
        TEST_ERROR(read_name_id_map(fixture.properties, fixture.values, stats, failures),
                   ErrorKind::kBadField, "NPMAP.PidTagNameidBucketCount",
                   "a map with no bucket count");
    }
    {
        Fixture fixture = build_fixture(0);
        NameIdStats stats;
        FailureLog failures(5);
        TEST_ERROR(read_name_id_map(fixture.properties, fixture.values, stats, failures),
                   ErrorKind::kBadField, "NPMAP.PidTagNameidBucketCount",
                   "a map with zero buckets");
    }
    {
        Fixture fixture = build_fixture();
        for (PcRecord& record : fixture.properties) {
            if (record.prop_id == kPropNameidStreamEntry) {
                record.prop_id = 0x0200; // the Entry Stream is gone
            }
        }
        NameIdStats stats;
        FailureLog failures(5);
        TEST_ERROR(read_name_id_map(fixture.properties, fixture.values, stats, failures),
                   ErrorKind::kBadField, "NPMAP.property", "a map with no Entry Stream");
    }
    {
        // [MS-PST] 2.4.7.5: a record in the wrong bucket is a data error, not a silent miss.
        Fixture fixture = build_fixture();
        for (PcRecord& record : fixture.properties) {
            if (record.value_hnid == 0x100) {
                record.prop_id =
                    static_cast<uint16_t>(kPropNameidBucketBase + fixture.bucket_of[0] + 1);
            }
        }
        NameIdStats stats;
        FailureLog failures(5);
        Result<NameIdMap> map =
            read_name_id_map(fixture.properties, fixture.values, stats, failures);
        TEST_OK(map, "a map with one misplaced bucket record");
        TEST_EQ(stats.bucket_mismatches, 1, "the misplaced record was counted");
        TEST_EQ(stats.bucket_records, 3, "the record was still read");
        TEST_EQ(failures.total(), 1, "the misplaced record was reported");
    }
    {
        // An N == 1 record whose dwPropertyID is no String Stream name keeps the map but resolves
        // nothing.
        Fixture fixture = build_fixture();
        for (PcRecord& record : fixture.properties) {
            if (record.prop_id == kPropNameidStreamEntry) {
                fixture.values.set(0x60, name_id_bytes(0xFFFF, 0x0001, 0));
                (void)record;
            }
        }
        NameIdStats stats;
        FailureLog failures(5);
        Result<NameIdMap> map =
            read_name_id_map(fixture.properties, fixture.values, stats, failures);
        TEST_OK(map, "a map whose name offset is out of range");
        TEST_EQ(map.value().entries.size(), 1, "the record is still reported");
        TEST_EQ(stats.names_unresolved, 1, "the name was not resolved");
        TEST_EQ(stats.string_offsets_unmatched, 1, "the offset matched no enumerated name");
        TEST_EQ(stats.crc_matches, 0, "an unresolved name cannot be cross-checked");
    }
    {
        Fixture fixture = build_fixture(100);
        NameIdStats stats;
        FailureLog failures(5);
        Result<NameIdMap> map =
            read_name_id_map(fixture.properties, fixture.values, stats, failures);
        TEST_OK(map, "a map with a non-recommended bucket count");
        TEST_EQ(map.value().bucket_count, 100, "the count the PC carries wins");
        TEST_EQ(stats.bucket_count_defaulted ? 1u : 0u, 1u, "a count other than 251 is noted");
        TEST_EQ(stats.crc_matches, 3, "the buckets still mirror the entries");
    }
}

void test_guid_stream() {
    std::vector<uint8_t> guids;
    for (uint8_t byte = 0; byte < 32; ++byte) {
        guids.push_back(byte);
    }
    const ByteView stream(guids.data(), guids.size(), 0);

    // [MS-PST] 2.4.7.1: wGuid 3 is the first entry of the GUID Stream, wGuid 4 the second.
    const std::vector<uint8_t> third = name_id_bytes(0, 0x0007, 0);
    Result<NameIdRecord> record = decode_name_id_record(ByteView(third.data(), third.size(), 0));
    TEST_OK(record, "a NAMEID with wGuid 3");
    Result<ByteView> guid = name_id_guid(record.value(), stream);
    TEST_OK(guid, "the GUID Stream entry behind wGuid 3");
    TEST_EQ(guid.value().size(), 16, "a GUID is 16 bytes");
    TEST_EQ(guid.value().data()[0], 0, "the first GUID");
    TEST_STR(name_id_guid_name(record.value().guid_index), "GUID Stream",
             "wGuid 3 names a stream entry");

    const std::vector<uint8_t> fifth = name_id_bytes(0, 0x8005, 0);
    Result<NameIdRecord> past = decode_name_id_record(ByteView(fifth.data(), fifth.size(), 0));
    TEST_OK(past, "a NAMEID with wGuid 5");
    TEST_ERROR(name_id_guid(past.value(), stream), ErrorKind::kTruncated, "ByteView.read",
               "a GUID past the end of the GUID Stream");

    // [MS-PST] 2.4.7.1: the two well-known GUIDs and "no GUID" are not stream entries.
    const std::vector<uint8_t> mapi = name_id_bytes(0, 0x0001, 0);
    Result<NameIdRecord> well_known =
        decode_name_id_record(ByteView(mapi.data(), mapi.size(), 0x40));
    TEST_OK(well_known, "a NAMEID with wGuid 1");
    TEST_ERROR(name_id_guid(well_known.value(), stream), ErrorKind::kUnsupported, "NAMEID.wGuid",
               "PS_MAPI is not a GUID Stream entry");
    TEST_STR(name_id_guid_name(0), "NAMEID_GUID_NONE", "wGuid 0");
    TEST_STR(name_id_guid_name(1), "PS_MAPI", "wGuid 1");
    TEST_STR(name_id_guid_name(2), "PS_PUBLIC_STRINGS", "wGuid 2");
}

// [MS-PST] 2.4.7.4: the String Stream is packed, so its names only come out of a walk from offset
// 0.
void test_enumerate_strings() {
    std::vector<uint32_t> offsets;
    const std::vector<uint8_t> stream =
        string_stream({u16("Author"), u16("Do Not Forward"), u"\u4e2d\u6587"}, offsets);
    NameIdStats stats;
    Result<std::vector<StringName>> names =
        enumerate_name_id_strings(ByteView(stream.data(), stream.size(), 0), stats);
    TEST_OK(names, "enumerate the String Stream");
    TEST_EQ(names.value().size(), 3, "names enumerated");
    TEST_EQ(stats.string_names, 3, "names counted");
    TEST_EQ(stats.string_names_past_end, 0, "the walk reached the end of the stream");
    TEST_EQ(stats.ragged_string_padding, 0, "every pair ends on a 4-byte boundary");
    for (size_t index = 0; index < names.value().size(); ++index) {
        TEST_EQ(names.value()[index].offset, offsets[index], "the walk finds the packed offsets");
        TEST_EQ(names.value()[index].length, names.value()[index].name.size() * 2,
                "the length DWORD");
    }
    TEST_STR(name_id_utf8(names.value()[1].name), "Do Not Forward", "the second name");

    // A pair whose bytes run past the end stops the walk and is reported instead of guessed at.
    std::vector<uint8_t> broken;
    put32(broken, 12);
    put16(broken, 'A');
    put16(broken, 'B');
    NameIdStats broken_stats;
    Result<std::vector<StringName>> none =
        enumerate_name_id_strings(ByteView(broken.data(), broken.size(), 0x900), broken_stats);
    TEST_OK(none, "a stream whose only name does not fit");
    TEST_EQ(none.value().size(), 0, "no name read");
    TEST_EQ(broken_stats.string_names_past_end, 1, "the walk stopped");

    // A zero-length name would spin the walk forever, so it ends it too.
    std::vector<uint8_t> zero;
    put32(zero, 0);
    NameIdStats zero_stats;
    Result<std::vector<StringName>> empty =
        enumerate_name_id_strings(ByteView(zero.data(), zero.size(), 0), zero_stats);
    TEST_OK(empty, "a stream that starts with a zero-length name");
    TEST_EQ(empty.value().size(), 0, "no name read");
    TEST_EQ(zero_stats.string_names_past_end, 1, "the walk stopped");

    // [MS-PST] 2.4.7.4: padding is added after the name, not after the length DWORD, so a 6-byte
    // name takes 4 + 8 bytes and the next name sits at 12, not at 10. Measured on a real OST the
    // same way: 26, 20, 34 and 74-byte names step 32, 24, 40 and 76 bytes.
    std::vector<uint8_t> padded;
    put32(padded, 6);
    put16(padded, 'A');
    put16(padded, 'B');
    put16(padded, 'C');
    put16(padded, 0); // the padding that ends the pair on a 4-byte boundary
    put32(padded, 4);
    put16(padded, 'D');
    put16(padded, 'E');
    NameIdStats padded_stats;
    Result<std::vector<StringName>> both =
        enumerate_name_id_strings(ByteView(padded.data(), padded.size(), 0), padded_stats);
    TEST_OK(both, "a padded pair does not end the stream");
    TEST_EQ(both.value().size(), 2, "both names read");
    TEST_EQ(both.value()[1].offset, 12, "the next name sits past the padding");
    TEST_EQ(padded_stats.ragged_string_padding, 1, "the name that needed padding counted");
    TEST_EQ(padded_stats.string_names_past_end, 0, "the walk reached the end of the stream");
}

// [MS-PST] 2.4.7.1: the N bit decides an Entry Stream record on its own. N == 1 means dwPropertyID
// is a String Stream offset, N == 0 means it is the 16-bit numeric name — even a number that looks
// exactly like an offset. The hash buckets then mirror every one of those records.
void test_n_bit_decides() {
    std::vector<uint32_t> offsets;
    const std::vector<uint8_t> strings =
        string_stream({u16("Author"), u16("Do Not Forward")}, offsets);
    TEST_EQ(offsets[1], 16, "the second name sits at offset 16");

    const std::vector<uint8_t> records[] = {
        name_id_bytes(offsets[0], 0x0007, 0), // N == 1, wGuid 3: the first GUID Stream entry
        name_id_bytes(offsets[1], 0x0009, 1), // N == 1, wGuid 4
        name_id_bytes(0x00000011, 0x000A, 2), // N == 0, wGuid 5: a numeric name
        name_id_bytes(offsets[1], 0x000C, 3), // N == 0: a number that looks exactly like an offset
        name_id_bytes(0x00000021, 0x000E, 4), // N == 0, wGuid 7: past the end of the GUID Stream
    };
    std::vector<uint8_t> entries;
    for (const std::vector<uint8_t>& record : records) {
        entries.insert(entries.end(), record.begin(), record.end());
    }

    std::vector<uint8_t> guids;
    for (uint8_t byte = 0; byte < 64; ++byte) {
        guids.push_back(byte); // four GUIDs: wGuid 3..6 are in range, wGuid 7 is not
    }

    Fixture fixture;
    fixture.properties.push_back(inline_property(kPropNameidBucketCount, 251));
    fixture.properties.push_back(stream_property(kPropNameidStreamEntry, 0x60));
    fixture.properties.push_back(stream_property(kPropNameidStreamString, 0x61));
    fixture.properties.push_back(stream_property(kPropNameidStreamGuid, 0x62));
    fixture.values.set(0x60, entries);
    fixture.values.set(0x61, strings);
    fixture.values.set(0x62, guids);

    const uint32_t bucket_values[5] = {name_id_crc(u16("Author")),
                                       name_id_crc(u16("Do Not Forward")), 0x11, 16, 0x21};
    const uint16_t guid_words[5] = {0x0007, 0x0009, 0x000A, 0x000C, 0x000E};
    std::map<uint32_t, std::vector<uint8_t>> buckets;
    for (uint32_t index = 0; index < 5; ++index) {
        const std::vector<uint8_t> record =
            name_id_bytes(bucket_values[index], guid_words[index], static_cast<uint16_t>(index));
        std::vector<uint8_t>& bucket =
            buckets[name_id_bucket(bucket_values[index], guid_words[index], 251)];
        bucket.insert(bucket.end(), record.begin(), record.end());
    }
    uint32_t hnid = 0x100;
    for (const auto& bucket : buckets) {
        fixture.properties.push_back(
            stream_property(static_cast<uint16_t>(kPropNameidBucketBase + bucket.first), hnid));
        fixture.values.set(hnid, bucket.second);
        ++hnid;
    }

    NameIdStats stats;
    FailureLog failures(5);
    Result<NameIdMap> map = read_name_id_map(fixture.properties, fixture.values, stats, failures);
    TEST_OK(map, "a map that sets the N bit where the spec says to");
    TEST_EQ(map.value().entries.size(), 5, "entry records");
    TEST_EQ(stats.string_names, 2, "the String Stream holds two names");
    TEST_EQ(stats.entries_string, 2, "the two records with N == 1 name a string");
    TEST_EQ(stats.entries_numeric, 3, "the three records with N == 0 hold a number");
    TEST_EQ(stats.names_resolved, 2, "two names resolved");
    TEST_EQ(stats.names_unresolved, 0, "no name left unresolved");
    TEST_EQ(stats.string_offsets_unmatched, 0, "both offsets are names the String Stream holds");
    TEST_EQ(stats.guid_refs_out_of_range, 1, "one wGuid points past the end of the GUID Stream");
    TEST_EQ(stats.crc_matches, 5, "every entry is mirrored by its bucket record");
    TEST_EQ(stats.crc_mismatches, 0, "no entry lost its bucket record");
    // [MS-PST] 2.4.7.1: the one wGuid past the end of the GUID Stream is a finding about that
    // record, so the read is not silent about it even though every other record in this map is
    // understood.
    TEST_EQ(failures.total(), 1, "only the out-of-range wGuid is reported");
    TEST_STR(failures.failures()[0].field, "NAMEID.wGuid", "the field the finding names");

    const NamedProperty& author = map.value().entries[0];
    TEST_EQ(author.n_bit_set ? 1u : 0u, 1u, "the record announces a string name");
    TEST_EQ(author.name_is_string ? 1u : 0u, 1u, "and it names a string");
    TEST_EQ(author.guid_index, 3, "wGuid 3 is the first GUID Stream entry");
    TEST_STR(name_id_utf8(author.name), "Author", "the name the offset points at");

    const NamedProperty& lookalike = map.value().entries[3];
    TEST_EQ(lookalike.name_is_string ? 1u : 0u, 0u, "N == 0 decides even for a lookalike");
    TEST_EQ(lookalike.numeric_name, 16u, "the number it holds");
    TEST_EQ(lookalike.name_resolved ? 1u : 0u, 0u, "no name was inferred for it");

    Result<NamedProperty> found = name_id_lookup(map.value(), u16("Do Not Forward"));
    TEST_OK(found, "a name found through its bucket record");
    TEST_EQ(found.value().npid, 0x8001, "the lookup found the right NPID");
    TEST_OK(name_id_lookup_npid(map.value(), 0x8003), "the numeric entry has an NPID too");

    const std::vector<uint8_t> past = name_id_bytes(0, 0x000E, 4);
    Result<NameIdRecord> record = decode_name_id_record(ByteView(past.data(), past.size(), 0));
    TEST_OK(record, "a NAMEID with wGuid 7");
    TEST_ERROR(name_id_guid(record.value(), ByteView(guids.data(), guids.size(), 0)),
               ErrorKind::kTruncated, "ByteView.read", "a wGuid past the end of the GUID Stream");
}

// [MS-PST] 2.4.7.1 / 2.4.7.2: a named property is a property set plus a name. Two records that
// share a string name under different property sets are two different properties, and a wGuid the
// GUID Stream does not reach is a finding about that record, not a count that quietly disappears.
void test_guid_identity() {
    std::vector<uint32_t> offsets;
    const std::vector<uint8_t> strings = string_stream({u16("Author")}, offsets);

    const std::vector<uint8_t> records[] = {
        name_id_bytes(offsets[0], 0x0003, 0), // N == 1, wGuid 1: "Author" under PS_MAPI
        name_id_bytes(offsets[0], 0x0005,
                      1), // N == 1, wGuid 2: the same name under PS_PUBLIC_STRINGS
        name_id_bytes(0x00000011, 0x0006,
                      2), // N == 0, wGuid 3: a numeric name under the first stream GUID
        name_id_bytes(offsets[0], 0x0009,
                      3), // N == 1, wGuid 4: "Author" under the second stream GUID
        name_id_bytes(offsets[0], 0x0015, 4), // N == 1, wGuid 10: past a 2-GUID stream
    };
    std::vector<uint8_t> entries;
    for (const std::vector<uint8_t>& record : records) {
        entries.insert(entries.end(), record.begin(), record.end());
    }
    std::vector<uint8_t> guids;
    for (uint8_t byte = 0; byte < 32; ++byte) {
        guids.push_back(byte); // two GUIDs, so wGuid 3 and 4 are in range and wGuid 10 is not
    }

    Fixture fixture;
    fixture.properties.push_back(inline_property(kPropNameidBucketCount, 251));
    fixture.properties.push_back(stream_property(kPropNameidStreamEntry, 0x60));
    fixture.properties.push_back(stream_property(kPropNameidStreamString, 0x61));
    fixture.properties.push_back(stream_property(kPropNameidStreamGuid, 0x62));
    fixture.values.set(0x60, entries);
    fixture.values.set(0x61, strings);
    fixture.values.set(0x62, guids);

    NameIdStats stats;
    FailureLog failures(5);
    Result<NameIdMap> map = read_name_id_map(fixture.properties, fixture.values, stats, failures);
    TEST_OK(map, "a map whose entries spread over four property sets");
    TEST_EQ(map.value().entries.size(), 5, "entry records");
    TEST_EQ(stats.entries_string, 4, "four records name a string");
    TEST_EQ(stats.entries_numeric, 1, "one record holds a numeric name");
    TEST_EQ(stats.names_resolved, 4, "one String Stream name shared by four records");
    TEST_EQ(stats.guid_stream_entries, 2, "the GUID Stream holds two GUIDs");
    TEST_EQ(stats.guid_distinct, 2, "they are different GUIDs");
    TEST_EQ(map.value().guid_stream.size(), 32, "the map keeps the GUID Stream it read");
    TEST_EQ(stats.guid_custom_refs, 2, "two records resolve through it");
    TEST_EQ(stats.guid_refs_out_of_range, 1, "one record asks for a GUID it does not hold");
    TEST_EQ(stats.guid_stream_ragged_bytes, 0, "the stream ends on a whole GUID");

    // The kind a wGuid is, given how many GUIDs the stream holds ([MS-PST] 2.4.7.1).
    TEST_EQ(name_id_guid_kind(0, 0), NameIdGuidKind::kNone, "wGuid 0 is NAMEID_GUID_NONE");
    TEST_EQ(name_id_guid_kind(1, 0), NameIdGuidKind::kMapi,
            "wGuid 1 is PS_MAPI with no stream at all");
    TEST_EQ(name_id_guid_kind(2, 0), NameIdGuidKind::kPublicStrings,
            "wGuid 2 is PS_PUBLIC_STRINGS");
    TEST_EQ(name_id_guid_kind(3, 32), NameIdGuidKind::kStream, "wGuid 3 is the first stream entry");
    TEST_EQ(name_id_guid_kind(4, 32), NameIdGuidKind::kStream, "wGuid 4 is the second");
    TEST_EQ(name_id_guid_kind(5, 32), NameIdGuidKind::kOutOfRange, "wGuid 5 needs a third GUID");
    TEST_EQ(name_id_guid_kind(3, 0), NameIdGuidKind::kOutOfRange,
            "a map with no GUID Stream at all");

    // [MS-PST] 2.4.7.1 names the two well-known sets and defers their bytes to [MS-OXPROPS] 1.3.2,
    // which this repository does not carry. libpff format notes (see THIRD_PARTY_NOTICES.txt):2264 and :2266
    // record both GUIDs, so the reader carries them and marks them as reference values rather than
    // file bytes.
    const NamedProperty& mapi = map.value().entries[0];
    TEST_EQ(mapi.guid_index, 1, "wGuid 1");
    TEST_EQ(mapi.guid_kind, NameIdGuidKind::kMapi, "PS_MAPI");
    TEST_STR(name_id_guid_kind_name(mapi.guid_kind), "PS_MAPI", "the set this reader reports");
    TEST_EQ(mapi.guid.size(), 16, "the PS_MAPI bytes the reader carries");
    TEST_STR(name_id_guid_text(mapi.guid), "00020328-0000-0000-C000-000000000046",
             "PS_MAPI as docs/reference/pff-format.asciidoc:2264 records it");
    TEST_EQ(mapi.guid_resolved ? 1u : 0u, 1u, "resolved from the reference, not the file");
    TEST_EQ(mapi.guid_from_file ? 1u : 0u, 0u, "and not from this file's GUID Stream");

    const NamedProperty& public_strings = map.value().entries[1];
    TEST_EQ(public_strings.guid_index, 2, "wGuid 2");
    TEST_EQ(public_strings.guid_kind, NameIdGuidKind::kPublicStrings, "PS_PUBLIC_STRINGS");
    TEST_STR(name_id_guid_kind_name(public_strings.guid_kind), "PS_PUBLIC_STRINGS", "the set name");
    TEST_STR(name_id_guid_text(public_strings.guid), "00020329-0000-0000-C000-000000000046",
             "PS_PUBLIC_STRINGS as docs/reference/pff-format.asciidoc:2266 records it");
    TEST_EQ(public_strings.guid_from_file ? 1u : 0u, 0u, "also a reference value");

    // [MS-PST] 2.4.7.2: a wGuid above 2 is the (wGuid - 3)th 16-byte entry of the GUID Stream, so
    // the bytes the identity rests on come out of the file itself.
    const NamedProperty& custom = map.value().entries[2];
    TEST_EQ(custom.guid_kind, NameIdGuidKind::kStream, "wGuid 3 is the first stream entry");
    TEST_EQ(custom.guid_resolved ? 1u : 0u, 1u, "its GUID resolved");
    TEST_EQ(custom.guid_from_file ? 1u : 0u, 1u, "and the bytes came from this file's GUID Stream");
    TEST_EQ(custom.guid.size(), 16, "the 16 bytes the file carries");
    TEST_STR(name_id_guid_text(custom.guid), "03020100-0504-0706-0809-0A0B0C0D0E0F",
             "the first GUID in text form");
    TEST_EQ(custom.name_is_string ? 1u : 0u, 0u, "N == 0");
    TEST_EQ(custom.numeric_name, 0x11, "the numeric name");

    const NamedProperty& second = map.value().entries[3];
    TEST_EQ(second.guid_kind, NameIdGuidKind::kStream, "wGuid 4 is the second stream entry");
    TEST_EQ(second.guid.size(), 16, "its GUID bytes");
    TEST_STR(name_id_guid_text(second.guid), "13121110-1514-1716-1819-1A1B1C1D1E1F",
             "the second GUID in text form");

    const NamedProperty& dangling = map.value().entries[4];
    TEST_EQ(dangling.guid_index, 10, "wGuid 10");
    TEST_EQ(dangling.guid_kind, NameIdGuidKind::kOutOfRange, "the stream does not reach it");
    TEST_STR(name_id_guid_kind_name(dangling.guid_kind), "GUID Stream out of range",
             "the kind reported");
    TEST_EQ(dangling.guid.size(), 0, "no bytes to report for it");

    // [MS-PST] 2.4.7.1: the name is only unique inside its property set, so a lookup that carries
    // both has to match both. This is what separates two named properties that share a string name.
    Result<NamedProperty> under_mapi = name_id_lookup_name_guid(map.value(), u16("Author"), 1);
    TEST_OK(under_mapi, "the name under PS_MAPI");
    TEST_EQ(under_mapi.value().npid, 0x8000, "the record that set it belongs to");
    Result<NamedProperty> under_public = name_id_lookup_name_guid(map.value(), u16("Author"), 2);
    TEST_OK(under_public, "the same name under PS_PUBLIC_STRINGS");
    TEST_EQ(under_public.value().npid, 0x8001, "a different named property");
    Result<NamedProperty> under_stream = name_id_lookup_name_guid(map.value(), u16("Author"), 4);
    TEST_OK(under_stream, "the same name under a custom GUID");
    TEST_EQ(under_stream.value().npid, 0x8003, "and a third NPID");
    TEST_EQ(under_stream.value().guid.size(), 16, "with that GUID carried along");
    Result<NamedProperty> under_broken = name_id_lookup_name_guid(map.value(), u16("Author"), 10);
    TEST_OK(under_broken,
            "the record whose own GUID is out of range is still a record of that name");
    TEST_EQ(under_broken.value().npid, 0x8004, "its NPID");
    TEST_EQ(under_broken.value().guid_kind, NameIdGuidKind::kOutOfRange, "with no GUID behind it");
    TEST_ERROR(name_id_lookup_name_guid(map.value(), u16("Author"), 3), ErrorKind::kUnsupported,
               "NPMAP.lookup", "no record uses that name under that property set");
    TEST_ERROR(name_id_lookup_name_guid(map.value(), u16("Authorship"), 1), ErrorKind::kUnsupported,
               "NPMAP.lookup", "a name the map does not hold");

    // The tally says which property sets the map actually uses, including the broken one.
    TEST_EQ(stats.guid_kinds["no GUID"], 0, "no record uses NAMEID_GUID_NONE here");
    TEST_EQ(stats.guid_kinds["PS_MAPI"], 1, "one record under PS_MAPI");
    TEST_EQ(stats.guid_kinds["PS_PUBLIC_STRINGS"], 1, "one under PS_PUBLIC_STRINGS");
    TEST_EQ(stats.guid_kinds["GUID Stream"], 2, "two under a custom GUID");
    TEST_EQ(stats.guid_kinds["GUID Stream out of range"], 1, "one that does not resolve");

    // [MS-PST] 2.4.7.1: a wGuid past the end of the GUID Stream is a finding, so the read is not
    // clean.
    TEST_EQ(failures.total(), 1, "the out-of-range wGuid entered the failure log");
    TEST_EQ(failures.kept(), 1, "and was kept for display");
    TEST_STR(failures.failures()[0].field, "NAMEID.wGuid", "the field the finding names");

    // [MS-PST] 2.4.7.2: the GUID Stream is a flat array of 16-byte GUIDs, so a stream that does not
    // end on one is a data error, not a shorter count.
    Fixture ragged = build_fixture();
    ragged.values.set(0x62,
                      std::vector<uint8_t>(24, 0x5A)); // one whole GUID and eight leftover bytes
    NameIdStats ragged_stats;
    FailureLog ragged_failures(5);
    Result<NameIdMap> ragged_map =
        read_name_id_map(ragged.properties, ragged.values, ragged_stats, ragged_failures);
    TEST_OK(ragged_map, "a map with a ragged GUID Stream");
    TEST_EQ(ragged_stats.guid_stream_entries, 1, "only the whole GUID counted");
    TEST_EQ(ragged_stats.guid_distinct, 1, "and it is one distinct GUID");
    TEST_EQ(ragged_stats.guid_stream_ragged_bytes, 8, "the leftover bytes reported");
    TEST_EQ(ragged_failures.total(), 1, "the ragged tail is a finding");
    TEST_STR(ragged_failures.failures()[0].field, "NPMAP.guidStream", "the field it names");
}

void test_utf8() {
    TEST_STR(name_id_utf8(u16("Author")), "Author", "an ASCII name");
    TEST_STR(name_id_utf8(std::u16string(u"\u4e2d\u6587")), "\xe4\xb8\xad\xe6\x96\x87",
             "a name outside ASCII");
    std::u16string astral;
    astral.push_back(static_cast<char16_t>(0xD83D));
    astral.push_back(static_cast<char16_t>(0xDE00));
    TEST_STR(name_id_utf8(astral), "\xf0\x9f\x98\x80", "a name with a surrogate pair");
    TEST_STR(name_id_utf8(std::u16string()), "", "an empty name");
}

} // namespace

int main() {
    test_record();
    test_crc();
    test_string_stream();
    test_walk();
    test_map();
    test_map_rejects();
    test_enumerate_strings();
    test_n_bit_decides();
    test_guid_stream();
    test_guid_identity();
    test_utf8();
    return finish("ltp_name_id_test");
}
