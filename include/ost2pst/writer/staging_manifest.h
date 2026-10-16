#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "ost2pst/ndb/layout.h"
#include "ost2pst/util/sha256.h"

namespace ost2pst::writer {

// Private persistence tags must not depend on the enum's native ordinal.
constexpr uint32_t staging_profile_tag(ndb::FileProfile profile) {
    switch (profile) {
    case ndb::FileProfile::kPst:
        return 1; // Retain the already persisted Unicode 512 tag.
    case ndb::FileProfile::kOst:
        return 2; // Unicode 4K; application schema tag, not wVer or a format offset.
    }
    return 0;
}

struct ConversionIdentity {
    util::Sha256Digest source_sha256{};
    uint64_t source_size = 0;
    uint32_t source_profile = 0;
    uint32_t record_budget = 100000;
    util::Sha256Digest converter_sha256{};
    std::map<std::string, std::string> options;
    bool operator==(const ConversionIdentity&) const = default;
};

struct OwnedFileIdentity {
    uint64_t volume = 0;
    uint64_t file = 0;
    bool operator==(const OwnedFileIdentity&) const = default;
};

using RunId = std::array<uint8_t, 16>;
struct StagingManifest {
    ConversionIdentity conversion;
    RunId run_id{};
    // Directory, lock, manifest, data, journal (private format v1).
    std::array<OwnedFileIdentity, 5> files{};
    std::string destination;
    bool operator==(const StagingManifest&) const = default;
};

// Converter-owned layout: M6 research/staging-workspace-format.md. Bounded, canonical encoding.
util::Result<std::vector<uint8_t>> encode_staging_manifest(const StagingManifest& manifest);
util::Result<StagingManifest> decode_staging_manifest(util::ByteView bytes);

} // namespace ost2pst::writer
