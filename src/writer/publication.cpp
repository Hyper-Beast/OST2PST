#include "ost2pst/writer/publication.h"

#include <algorithm>
#include <filesystem>
#include <vector>

#include "ost2pst/util/directory_pin.h"

namespace ost2pst::writer {
namespace {
using util::ByteView;
using util::ErrorKind;
using util::Result;
using util::Sha256Digest;
using util::Status;
// Private application framing, not PST layout constants.
constexpr size_t kHeaderBytes = 144, kReadyBytes = 168, kCompleteBytes = 48;
constexpr std::array<uint8_t, 8> kHeaderMagic{'O', 'S', 'T', 'P', 'U', 'B', '0', '2'};
constexpr std::array<uint8_t, 8> kReadyMagic{'O', 'S', 'T', 'R', 'D', 'Y', '0', '2'};
constexpr std::array<uint8_t, 8> kCompleteMagic{'O', 'S', 'T', 'D', 'O', 'N', '0', '2'};

Status invalid(const char* field, uint64_t value, const char* detail) {
    return util::make_error(ErrorKind::kBadField, field, 0, value, detail);
}
void number(std::vector<uint8_t>& bytes, uint64_t value, size_t width) {
    for (size_t index = 0; index < width; ++index) {
        bytes.push_back(static_cast<uint8_t>(value));
        value >>= 8;
    }
}
Sha256Digest digest(const std::vector<uint8_t>& bytes, const Sha256Digest* binding = nullptr) {
    util::Sha256 hash;
    if (binding)
        hash.update(ByteView(binding->data(), binding->size(), 0));
    hash.update(ByteView(bytes.data(), bytes.size(), 0));
    return hash.digest();
}
void seal(std::vector<uint8_t>& bytes, const Sha256Digest* binding = nullptr) {
    const auto checksum = digest(bytes, binding);
    bytes.insert(bytes.end(), checksum.begin(), checksum.end());
}
bool valid_frame(const std::vector<uint8_t>& bytes, const std::array<uint8_t, 8>& magic,
                 const Sha256Digest* binding = nullptr) {
    if (!std::equal(magic.begin(), magic.end(), bytes.begin()))
        return false;
    const ByteView view(bytes.data(), bytes.size(), 0);
    if (view.u32(8).value() != 2 || view.u32(12).value() != bytes.size())
        return false;
    const std::vector<uint8_t> body(bytes.begin(), bytes.end() - 32);
    const auto expected = digest(body, binding);
    return std::equal(expected.begin(), expected.end(), bytes.end() - 32);
}
Result<bool> exists(const std::wstring& path) {
    std::error_code error;
    const bool present = std::filesystem::exists(path, error);
    if (error)
        return util::make_error(ErrorKind::kIo, "publication.path", 0, error.value(),
                                "could not inspect artifact location");
    return present;
}
} // namespace

Result<Publication> Publication::create(const std::wstring& output,
                                        const Sha256Digest& manifest_binding,
                                        const std::wstring& initialization_directory) {
    Publication state;
    const auto work = std::filesystem::path(
        initialization_directory.empty() ? output + L".work" : initialization_directory);
    state.origins_ = {(work / L"candidate.tmp").wstring(), (work / L"summary.tmp").wstring(),
                      (work / L"items.tmp").wstring()};
    state.destinations_ = {output, output + L".report.json", output + L".items.jsonl"};
    for (size_t index = 0; index < 3; ++index) {
        auto absent = util::require_absent(state.destinations_[index]);
        if (!absent.ok())
            return absent.error();
        absent = util::require_absent(state.origins_[index]);
        if (!absent.ok())
            return absent.error();
    }
    auto marker = util::FileWriter::create_new((work / L"publication.bin").wstring());
    if (!marker.ok())
        return marker.error();
    state.marker_ = marker.take();
    auto marker_id = state.marker_.identity();
    if (!marker_id.ok())
        return marker_id.error();
    state.identities_[0] = {marker_id.value().volume, marker_id.value().file};
    for (size_t index = 0; index < 3; ++index) {
        auto file = util::FileWriter::create_new(state.origins_[index]);
        if (!file.ok())
            return file.error();
        state.files_[index] = file.take();
        auto id = state.files_[index].identity();
        if (!id.ok())
            return id.error();
        state.identities_[index + 1] = {id.value().volume, id.value().file};
        auto flushed = state.files_[index].flush();
        if (!flushed.ok())
            return flushed.error();
    }
    std::vector<uint8_t> header(kHeaderMagic.begin(), kHeaderMagic.end());
    number(header, 2, 4);
    number(header, kHeaderBytes, 4);
    header.insert(header.end(), manifest_binding.begin(), manifest_binding.end());
    for (const auto& id : state.identities_) {
        number(header, id.volume, 8);
        number(header, id.file, 8);
    }
    seal(header);
    std::copy(header.end() - 32, header.end(), state.header_digest_.begin());
    auto written = util::write_all(state.marker_, 0, ByteView(header.data(), header.size(), 0));
    if (!written.ok())
        return written.error();
    auto flushed = state.marker_.flush();
    if (!flushed.ok())
        return flushed.error();
    return state;
}

Result<Publication> Publication::recover(const std::wstring& output,
                                         const Sha256Digest& manifest_binding) {
    Publication state;
    const auto work = std::filesystem::path(output + L".work");
    state.origins_ = {(work / L"candidate.tmp").wstring(), (work / L"summary.tmp").wstring(),
                      (work / L"items.tmp").wstring()};
    state.destinations_ = {output, output + L".report.json", output + L".items.jsonl"};
    auto marker = util::FileWriter::open_private_existing((work / L"publication.bin").wstring());
    if (!marker.ok())
        return marker.error();
    state.marker_ = marker.take();
    const uint64_t length = state.marker_.size();
    if (length < kHeaderBytes || length > kHeaderBytes + kReadyBytes + kCompleteBytes)
        return invalid("publication.length", length, "invalid publication marker length").error();
    std::vector<uint8_t> header(kHeaderBytes);
    auto read = state.marker_.read_at(0, header.data(), header.size());
    if (!read.ok())
        return read.error();
    if (!valid_frame(header, kHeaderMagic) ||
        !std::equal(manifest_binding.begin(), manifest_binding.end(), header.begin() + 16))
        return invalid("publication.binding", 0, "invalid or foreign publication header").error();
    std::copy(header.end() - 32, header.end(), state.header_digest_.begin());
    ByteView view(header.data(), header.size(), 0);
    for (size_t index = 0; index < 4; ++index)
        state.identities_[index] = {view.u64(48 + index * 16).value(),
                                    view.u64(56 + index * 16).value()};
    auto marker_id = state.marker_.identity();
    if (!marker_id.ok())
        return marker_id.error();
    if (state.identities_[0] != OwnedFileIdentity{marker_id.value().volume, marker_id.value().file})
        return invalid("publication.marker_identity", 0, "publication marker was replaced").error();
    uint64_t committed_length = kHeaderBytes;
    if (length >= kHeaderBytes + kReadyBytes) {
        std::vector<uint8_t> ready(kReadyBytes);
        read = state.marker_.read_at(kHeaderBytes, ready.data(), ready.size());
        if (!read.ok())
            return read.error();
        if (!valid_frame(ready, kReadyMagic, &state.header_digest_))
            return invalid("publication.ready", 0, "complete ready record is corrupt").error();
        ByteView values(ready.data(), ready.size(), 0);
        for (size_t index = 0; index < 3; ++index) {
            state.sizes_[index] = values.u64(16 + index * 40).value();
            std::copy_n(ready.begin() + 24 + index * 40, 32, state.hashes_[index].begin());
        }
        std::copy(ready.end() - 32, ready.end(), state.ready_digest_.begin());
        state.phase_ = PublicationPhase::kReady;
        committed_length += kReadyBytes;
        if (length == kHeaderBytes + kReadyBytes + kCompleteBytes) {
            std::vector<uint8_t> complete(kCompleteBytes);
            read = state.marker_.read_at(committed_length, complete.data(), complete.size());
            if (!read.ok())
                return read.error();
            if (!valid_frame(complete, kCompleteMagic, &state.ready_digest_))
                return invalid("publication.complete", 0, "complete record is corrupt").error();
            state.phase_ = PublicationPhase::kComplete;
            committed_length += kCompleteBytes;
        }
    }
    for (size_t index = 0; index < 3; ++index) {
        auto origin = exists(state.origins_[index]);
        auto destination = exists(state.destinations_[index]);
        if (!origin.ok())
            return origin.error();
        if (!destination.ok())
            return destination.error();
        if (origin.value() == destination.value() ||
            (state.phase_ == PublicationPhase::kBuilding && destination.value()) ||
            (state.phase_ == PublicationPhase::kComplete && origin.value()))
            return invalid("publication.locations", index,
                           "artifact is absent, duplicated or at an inconsistent location")
                .error();
        state.published_[index] = destination.value();
        auto file = util::FileWriter::open_private_existing(
            state.path(static_cast<PublicationArtifact>(index)));
        if (!file.ok())
            return file.error();
        state.files_[index] = file.take();
        auto valid = state.validate_file(index, state.phase_ != PublicationPhase::kBuilding);
        if (!valid.ok())
            return valid.error();
    }
    if ((state.published_[1] && !state.published_[0]) ||
        (state.published_[2] && !state.published_[1]))
        return invalid("publication.order", 0, "report published before its preceding artifact")
            .error();
    state.committed_marker_length_ = committed_length;
    return state;
}

Status Publication::discard_torn_tail() {
    if (poisoned_)
        return invalid("publication.poisoned", 0, "close and recover publication state");
    if (marker_.size() == committed_marker_length_)
        return {};
    auto resized = marker_.resize(committed_marker_length_);
    if (!resized.ok())
        return mutating(resized);
    return mutating(marker_.flush());
}

util::RandomAccessFile& Publication::file(PublicationArtifact artifact) {
    return files_.at(static_cast<size_t>(artifact));
}
const std::wstring& Publication::path(PublicationArtifact artifact) const {
    const size_t index = static_cast<size_t>(artifact);
    return published_.at(index) ? destinations_.at(index) : origins_.at(index);
}
Status Publication::mutating(Status status) {
    if (!status.ok())
        poisoned_ = true;
    return status;
}
Status Publication::validate_file(size_t index, bool check_hash) {
    auto id = files_[index].identity();
    if (!id.ok())
        return id.error();
    if (identities_[index + 1] != OwnedFileIdentity{id.value().volume, id.value().file})
        return invalid("publication.file_identity", index, "reserved artifact was replaced");
    if (check_hash) {
        if (files_[index].size() != sizes_[index])
            return invalid("publication.file_size", index, "sealed artifact size changed");
        auto hash = util::sha256_file(files_[index]);
        if (!hash.ok())
            return hash.error();
        if (hash.value() != hashes_[index])
            return invalid("publication.file_hash", index, "sealed artifact content changed");
    }
    return {};
}
Status Publication::close_candidate() {
    if (poisoned_)
        return invalid("publication.poisoned", 0, "close and recover publication state");
    auto valid = validate_file(0, phase_ != PublicationPhase::kBuilding);
    if (!valid.ok())
        return valid;
    auto flushed = files_[0].flush();
    if (!flushed.ok())
        return mutating(flushed);
    return mutating(files_[0].close());
}
Status Publication::reopen_candidate() {
    if (poisoned_)
        return invalid("publication.poisoned", 0, "close and recover publication state");
    auto file = util::FileWriter::open_private_existing(path(PublicationArtifact::kPst));
    if (!file.ok())
        return file.error();
    files_[0] = file.take();
    return validate_file(0, phase_ != PublicationPhase::kBuilding);
}
Status Publication::mark_ready() {
    if (poisoned_ || phase_ != PublicationPhase::kBuilding)
        return invalid("publication.phase", 0, "publication is not an active build");
    std::vector<uint8_t> ready(kReadyMagic.begin(), kReadyMagic.end());
    number(ready, 2, 4);
    number(ready, kReadyBytes, 4);
    for (size_t index = 0; index < 3; ++index) {
        auto valid = validate_file(index, false);
        if (!valid.ok())
            return valid;
        auto flushed = files_[index].flush();
        if (!flushed.ok())
            return mutating(flushed);
        auto hash = util::sha256_file(files_[index]);
        if (!hash.ok())
            return hash.error();
        sizes_[index] = files_[index].size();
        hashes_[index] = hash.value();
        number(ready, sizes_[index], 8);
        ready.insert(ready.end(), hashes_[index].begin(), hashes_[index].end());
    }
    seal(ready, &header_digest_);
    auto written = util::write_all(marker_, kHeaderBytes, ByteView(ready.data(), ready.size(), 0));
    if (!written.ok())
        return mutating(written);
    auto flushed = marker_.flush();
    if (!flushed.ok())
        return mutating(flushed);
    std::copy(ready.end() - 32, ready.end(), ready_digest_.begin());
    phase_ = PublicationPhase::kReady;
    committed_marker_length_ = kHeaderBytes + kReadyBytes;
    return {};
}
Status Publication::publish_one(PublicationArtifact artifact) {
    const size_t index = static_cast<size_t>(artifact);
    if (index >= 3 || poisoned_ || phase_ == PublicationPhase::kBuilding)
        return invalid("publication.phase", index, "publication is not sealed");
    auto valid = validate_file(index, true);
    if (!valid.ok())
        return valid;
    if (published_[index])
        return {};
    if (index > 0 && !published_[index - 1])
        return invalid("publication.order", index, "publish PST, summary, then item ledger");
    auto closed = files_[index].close();
    if (!closed.ok())
        return mutating(closed);
    auto published = util::publish_no_replace(origins_[index], destinations_[index]);
    if (!published.ok())
        return mutating(published);
    published_[index] = true;
    auto file = util::FileWriter::open_private_existing(destinations_[index]);
    if (!file.ok())
        return mutating(file.error());
    files_[index] = file.take();
    return mutating(validate_file(index, true));
}
Status Publication::finish() {
    if (poisoned_ || phase_ == PublicationPhase::kBuilding ||
        !std::all_of(published_.begin(), published_.end(), [](bool value) { return value; }))
        return invalid("publication.phase", 0, "all sealed artifacts must be published first");
    for (size_t index = 0; index < 3; ++index) {
        auto valid = validate_file(index, true);
        if (!valid.ok())
            return valid;
    }
    if (phase_ == PublicationPhase::kComplete)
        return {};
    std::vector<uint8_t> complete(kCompleteMagic.begin(), kCompleteMagic.end());
    number(complete, 2, 4);
    number(complete, kCompleteBytes, 4);
    seal(complete, &ready_digest_);
    auto written = util::write_all(marker_, kHeaderBytes + kReadyBytes,
                                   ByteView(complete.data(), complete.size(), 0));
    if (!written.ok())
        return mutating(written);
    auto flushed = marker_.flush();
    if (!flushed.ok())
        return mutating(flushed);
    phase_ = PublicationPhase::kComplete;
    committed_marker_length_ = kHeaderBytes + kReadyBytes + kCompleteBytes;
    return {};
}
} // namespace ost2pst::writer
