#include "ost2pst/writer/staging_manifest.h"

#include <algorithm>
#include <limits>

namespace ost2pst::writer {
namespace {
using namespace util;
// Private manifest v1: M6 research/staging-workspace-format.md.
constexpr std::array<uint8_t, 8> kMagic{'O', '2', 'P', 'M', 'A', 'N', '0', '1'};
constexpr size_t kMaxManifest = 1024 * 1024;

DataError invalid(const char* field, uint64_t offset = 0) {
    return make_error(ErrorKind::kBadField, field, offset, 0, "invalid staging manifest");
}
void put(std::vector<uint8_t>& out, uint64_t value, size_t count) {
    for (size_t i = 0; i < count; ++i)
        out.push_back(static_cast<uint8_t>(value >> (8 * i)));
}
bool text_valid(const std::string& text, size_t max, bool allow_empty = false) {
    return (allow_empty || !text.empty()) && text.size() <= max &&
           text.find('\0') == std::string::npos;
}
bool key_valid(const std::string& text) {
    return text_valid(text, 128) && std::all_of(text.begin(), text.end(), [](unsigned char c) {
               return c >= 33 && c <= 126;
           });
}
void put_string(std::vector<uint8_t>& out, const std::string& text) {
    put(out, text.size(), 4);
    out.insert(out.end(), text.begin(), text.end());
}
Result<std::string> get_string(ByteView view, size_t& position, size_t limit) {
    auto length = view.u32(position);
    if (!length.ok())
        return length.error();
    position += 4;
    if (length.value() > limit || position > view.size() || length.value() > view.size() - position)
        return invalid("manifest.string", position);
    std::string value(reinterpret_cast<const char*>(view.data() + position), length.value());
    position += length.value();
    return value;
}
} // namespace

util::Result<std::vector<uint8_t>> encode_staging_manifest(const StagingManifest& manifest) {
    const auto& identity = manifest.conversion;
    if (identity.source_size > static_cast<uint64_t>(INT64_MAX) || identity.source_profile == 0 ||
        identity.record_budget == 0 || identity.record_budget > 1000000 ||
        identity.options.size() > 64 || !text_valid(manifest.destination, 131072) ||
        std::all_of(manifest.run_id.begin(), manifest.run_id.end(),
                    [](uint8_t c) { return c == 0; }))
        return invalid("manifest.identity");
    for (const auto& [key, value] : identity.options)
        if (!key_valid(key) || !text_valid(value, 4096, true))
            return invalid("manifest.option");
    std::vector<uint8_t> out(kMagic.begin(), kMagic.end());
    put(out, 1, 4);
    put(out, 0, 4);
    out.insert(out.end(), identity.source_sha256.begin(), identity.source_sha256.end());
    put(out, identity.source_size, 8);
    put(out, identity.source_profile, 4);
    put(out, identity.record_budget, 4);
    out.insert(out.end(), identity.converter_sha256.begin(), identity.converter_sha256.end());
    out.insert(out.end(), manifest.run_id.begin(), manifest.run_id.end());
    for (const auto& file : manifest.files) {
        put(out, file.volume, 8);
        put(out, file.file, 8);
    }
    put_string(out, manifest.destination);
    put(out, identity.options.size(), 4);
    for (const auto& [key, value] : identity.options) {
        put_string(out, key);
        put_string(out, value);
    }
    const size_t size = out.size() + 32;
    if (size > kMaxManifest)
        return invalid("manifest.size");
    for (size_t i = 0; i < 4; ++i)
        out[12 + i] = static_cast<uint8_t>(size >> (8 * i));
    Sha256 hasher;
    auto hashed = hasher.update(ByteView(out.data(), out.size()));
    if (!hashed.ok())
        return hashed.error();
    const auto digest = hasher.digest();
    out.insert(out.end(), digest.begin(), digest.end());
    return out;
}

util::Result<StagingManifest> decode_staging_manifest(ByteView bytes) {
    if (bytes.data() == nullptr || bytes.size() < 232 || bytes.size() > kMaxManifest)
        return invalid("manifest.size", bytes.base());
    if (!std::equal(kMagic.begin(), kMagic.end(), bytes.data()) || bytes.u32(8).value() != 1 ||
        bytes.u32(12).value() != bytes.size())
        return invalid("manifest.header", bytes.base());
    Sha256 hasher;
    auto hashed = hasher.update(ByteView(bytes.data(), bytes.size() - 32));
    if (!hashed.ok())
        return hashed.error();
    const auto digest = hasher.digest();
    if (!std::equal(digest.begin(), digest.end(), bytes.data() + bytes.size() - 32))
        return make_error(ErrorKind::kBadCrc, "manifest.hash", bytes.base());
    ByteView payload(bytes.data(), bytes.size() - 32, bytes.base());
    StagingManifest result;
    auto& identity = result.conversion;
    std::copy_n(payload.data() + 16, 32, identity.source_sha256.begin());
    identity.source_size = payload.u64(48).value();
    identity.source_profile = payload.u32(56).value();
    identity.record_budget = payload.u32(60).value();
    std::copy_n(payload.data() + 64, 32, identity.converter_sha256.begin());
    std::copy_n(payload.data() + 96, 16, result.run_id.begin());
    for (size_t i = 0; i < result.files.size(); ++i)
        result.files[i] = {payload.u64(112 + i * 16).value(), payload.u64(120 + i * 16).value()};
    size_t position = 192;
    auto destination = get_string(payload, position, 131072);
    if (!destination.ok())
        return destination.error();
    result.destination = destination.take();
    auto count = payload.u32(position);
    if (!count.ok())
        return count.error();
    if (count.value() > 64)
        return invalid("manifest.options", position);
    position += 4;
    std::string previous;
    for (uint32_t i = 0; i < count.value(); ++i) {
        auto key = get_string(payload, position, 128);
        if (!key.ok())
            return key.error();
        auto value = get_string(payload, position, 4096);
        if (!value.ok())
            return value.error();
        if (!key_valid(key.value()) || (i != 0 && key.value() <= previous))
            return invalid("manifest.option_order", position);
        previous = key.value();
        identity.options.emplace(key.take(), value.take());
    }
    if (position != payload.size())
        return invalid("manifest.trailing_bytes", position);
    auto canonical = encode_staging_manifest(result);
    if (!canonical.ok())
        return canonical.error();
    return result;
}
} // namespace ost2pst::writer
