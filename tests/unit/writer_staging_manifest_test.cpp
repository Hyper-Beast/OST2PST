#include <algorithm>
#include <string>
#include <vector>

#include "ost2pst/writer/staging_manifest.h"

#include "test_support.h"

namespace {
using namespace ost2pst::writer;
using namespace ost2pst::util;

StagingManifest example() {
    StagingManifest manifest;
    manifest.conversion.source_size = (uint64_t{1} << 32) + 123;
    manifest.conversion.source_profile = 36;
    manifest.conversion.source_sha256[0] = 42;
    manifest.conversion.converter_sha256[31] = 99;
    manifest.conversion.options = {{"hierarchy", "Imported OST"}, {"search", "exclude"}};
    manifest.run_id[0] = 1;
    manifest.destination = "D:/example/\xE9\x82\xAE\xE4\xBB\xB6.pst";
    for (size_t i = 0; i < manifest.files.size(); ++i)
        manifest.files[i] = {12, 100 + i};
    return manifest;
}

void rehash(std::vector<uint8_t>& bytes) {
    Sha256 hash;
    TEST_OK(hash.update(ByteView(bytes.data(), bytes.size() - 32)), "rehash corrupt fixture");
    const auto digest = hash.digest();
    std::copy(digest.begin(), digest.end(), bytes.end() - 32);
}

void check_manifest() {
    for (const auto profile : {ost2pst::ndb::FileProfile::kOst, ost2pst::ndb::FileProfile::kPst}) {
        auto manifest = example();
        manifest.conversion.source_profile = staging_profile_tag(profile);
        auto encoded = encode_staging_manifest(manifest);
        TEST_OK(encoded, "both supported source profiles have persistable identities");
        if (encoded.ok()) {
            auto decoded =
                decode_staging_manifest(ByteView(encoded.value().data(), encoded.value().size()));
            TEST_OK(decoded, "replay source-profile identity");
            if (decoded.ok())
                TEST_CHECK(decoded.value() == manifest);
        }
    }
    const auto original = example();
    auto encoded = encode_staging_manifest(original);
    TEST_OK(encoded, "encode identity");
    if (!encoded.ok())
        return;
    const auto& bytes = encoded.value();
    ByteView view(bytes.data(), bytes.size());
    TEST_EQ(view.u64(48).value(), original.conversion.source_size, "64-bit source size survives");
    TEST_EQ(view.u32(12).value(), bytes.size(), "framed manifest length");
    auto decoded = decode_staging_manifest(view);
    TEST_OK(decoded, "decode identity");
    if (decoded.ok()) {
        TEST_CHECK(decoded.value() == original);
        auto again = encode_staging_manifest(decoded.value());
        TEST_OK(again, "encode decoded identity");
        if (again.ok())
            TEST_CHECK(again.value() == bytes);
    }
    for (size_t length = 0; length < bytes.size(); ++length)
        TEST_CHECK(!decode_staging_manifest(ByteView(bytes.data(), length)).ok());
    for (size_t changed = 0; changed < bytes.size(); ++changed) {
        auto corrupt = bytes;
        corrupt[changed] ^= 1;
        TEST_CHECK(!decode_staging_manifest(ByteView(corrupt.data(), corrupt.size())).ok());
    }
    for (int fault = 0; fault < 6; ++fault) {
        auto corrupt = bytes;
        if (fault == 0)
            corrupt[8] = 2;
        if (fault == 1)
            std::fill_n(corrupt.data() + 60, 4, uint8_t{0});
        if (fault == 2)
            std::fill_n(corrupt.data() + 96, 16, uint8_t{0});
        if (fault == 3)
            std::fill_n(corrupt.data() + 192, 4, uint8_t{255});
        const size_t option_count = 196 + original.destination.size();
        if (fault == 4)
            corrupt[option_count] = 65;
        if (fault == 5)
            corrupt[option_count + 8] = 0; // NUL inside first key.
        rehash(corrupt);
        TEST_CHECK(!decode_staging_manifest(ByteView(corrupt.data(), corrupt.size())).ok());
    }
    for (int fault = 0; fault < 6; ++fault) {
        auto invalid = original;
        if (fault == 0)
            invalid.conversion.source_size = UINT64_MAX;
        if (fault == 1)
            invalid.conversion.record_budget = 0;
        if (fault == 2)
            invalid.conversion.options["bad key"] = "value";
        if (fault == 3)
            invalid.conversion.options["key"] = std::string(4097, 'x');
        if (fault == 4)
            invalid.destination.clear();
        if (fault == 5)
            invalid.run_id.fill(0);
        TEST_CHECK(!encode_staging_manifest(invalid).ok());
    }
    auto reverse = original;
    reverse.conversion.options.clear();
    reverse.conversion.options.emplace("search", "exclude");
    reverse.conversion.options.emplace("hierarchy", "Imported OST");
    auto canonical = encode_staging_manifest(reverse);
    TEST_OK(canonical, "canonical map");
    if (canonical.ok())
        TEST_CHECK(canonical.value() == bytes);
}
} // namespace

int main() {
    check_manifest();
    return ost2pst::test::finish("writer_staging_manifest_test");
}
