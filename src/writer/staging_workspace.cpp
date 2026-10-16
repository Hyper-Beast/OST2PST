#include "ost2pst/writer/staging_workspace.h"

#include <algorithm>
#include <array>
#include <filesystem>
#include <optional>
#include <random>
#include <utility>

#include "ost2pst/util/directory_pin.h"

namespace ost2pst::writer {
using namespace util;

namespace {
// Converter-private completion v1. Body binds the manifest and the receipt's own file identity.
constexpr size_t kCompletionBytes = 112, kCompletionBodyBytes = 80;
constexpr std::array<uint8_t, 8> kCompletionMagic{'O', 'S', 'T', 'F', 'I', 'N', '0', '1'};
void put_number(std::array<uint8_t, kCompletionBytes>& bytes, size_t at, uint64_t value,
                size_t width) {
    for (size_t i = 0; i < width; ++i)
        bytes[at + i] = static_cast<uint8_t>(value >> (i * 8));
}
Result<bool> path_exists(const std::filesystem::path& path) {
    std::error_code error;
    const bool exists = std::filesystem::exists(path, error);
    if (error)
        return make_error(ErrorKind::kIo, "workspace.completion_path", 0, error.value());
    return exists;
}
Result<CompletedConversion> read_completion(FileWriter& file, const Sha256Digest& binding) {
    if (file.size() != kCompletionBytes)
        return make_error(ErrorKind::kBadField, "workspace.completion_size", 0, file.size());
    std::array<uint8_t, kCompletionBytes> bytes{};
    auto read = file.read_at(0, bytes.data(), bytes.size());
    if (!read.ok())
        return read.error();
    const ByteView view(bytes.data(), bytes.size());
    Sha256 hash;
    auto hashed = hash.update(ByteView(bytes.data(), kCompletionBodyBytes));
    if (!hashed.ok())
        return hashed.error();
    const auto checksum = hash.digest();
    if (!std::equal(kCompletionMagic.begin(), kCompletionMagic.end(), bytes.begin()) ||
        view.u32(8).value() != 1 || view.u32(12).value() != kCompletionBytes ||
        view.u32(20).value() != 0 ||
        !std::equal(binding.begin(), binding.end(), bytes.begin() + 32) ||
        !std::equal(checksum.begin(), checksum.end(), bytes.begin() + kCompletionBodyBytes))
        return make_error(ErrorKind::kBadField, "workspace.completion_binding", 0);
    auto identity = file.identity();
    if (!identity.ok())
        return identity.error();
    if (view.u64(64).value() != identity.value().volume ||
        view.u64(72).value() != identity.value().file)
        return make_error(ErrorKind::kBadField, "workspace.completion_identity", 0);
    const uint32_t code = view.u32(16).value();
    if (code != 0 && code != 3)
        return make_error(ErrorKind::kBadField, "workspace.completion_result", 16, code);
    return CompletedConversion{code, view.u64(24).value()};
}
} // namespace

struct StagingWorkspace::Impl {
    OutputLocation output;
    DirectoryPin directory;
    FileWriter lock, manifest_file, data, journal_file;
    StagingManifest manifest;
    std::optional<StagingJournal> journal;
    util::Sha256Digest binding{};
    std::optional<Publication> publication;
    FileWriter completion_file;
    std::optional<CompletedConversion> completed;
};

StagingWorkspace::StagingWorkspace(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
StagingWorkspace::StagingWorkspace(StagingWorkspace&&) noexcept = default;
StagingWorkspace& StagingWorkspace::operator=(StagingWorkspace&&) noexcept = default;
StagingWorkspace::~StagingWorkspace() = default;
StagingJournal& StagingWorkspace::journal() {
    return *impl_->journal;
}
const std::wstring& StagingWorkspace::directory() const {
    return impl_->directory.path();
}
const StagingManifest& StagingWorkspace::manifest() const {
    return impl_->manifest;
}

util::Status StagingWorkspace::prepare_publication() {
    if (impl_->publication)
        return make_error(ErrorKind::kBadField, "workspace.publication", 0, 0,
                          "publication artifacts are already reserved");
    auto prepared = Publication::create(impl_->output.path, impl_->binding, directory());
    if (!prepared.ok())
        return prepared.error();
    impl_->publication.emplace(prepared.take());
    return {};
}
Publication* StagingWorkspace::publication() {
    return impl_->publication ? &*impl_->publication : nullptr;
}
const std::optional<CompletedConversion>& StagingWorkspace::completed() const {
    return impl_->completed;
}

Status StagingWorkspace::cleanup_completed(const CompletedConversion& result,
                                           const std::function<void(CleanupPoint)>& observer) {
    if (!impl_->publication || impl_->publication->phase() != PublicationPhase::kComplete ||
        (result.exit_code != 0 && result.exit_code != 3) ||
        (impl_->completed && *impl_->completed != result))
        return make_error(ErrorKind::kBadField, "workspace.cleanup_phase", 0);
    // Publication owns exclusive handles and validated all sealed hashes before becoming complete.
    if (!impl_->completed) {
        const auto target = std::filesystem::path(directory()) / L"completion.bin";
        auto absent = require_absent(target.wstring());
        if (!absent.ok())
            return absent;
        std::random_device random;
        std::wstring leaf = L"completion-";
        constexpr wchar_t hex[] = L"0123456789abcdef";
        for (size_t i = 0; i < 32; ++i)
            leaf += hex[random() & 15];
        const auto pending = std::filesystem::path(directory()) / (leaf + L".tmp");
        auto made = FileWriter::create_new(pending.wstring());
        if (!made.ok())
            return made.error();
        auto file = made.take();
        auto identity = file.identity();
        if (!identity.ok())
            return identity.error();
        std::array<uint8_t, kCompletionBytes> bytes{};
        std::copy(kCompletionMagic.begin(), kCompletionMagic.end(), bytes.begin());
        put_number(bytes, 8, 1, 4);
        put_number(bytes, 12, kCompletionBytes, 4);
        put_number(bytes, 16, result.exit_code, 4);
        put_number(bytes, 24, result.terminal_items, 8);
        std::copy(impl_->binding.begin(), impl_->binding.end(), bytes.begin() + 32);
        put_number(bytes, 64, identity.value().volume, 8);
        put_number(bytes, 72, identity.value().file, 8);
        Sha256 hash;
        auto status = hash.update(ByteView(bytes.data(), kCompletionBodyBytes));
        if (!status.ok())
            return status;
        const auto checksum = hash.digest();
        std::copy(checksum.begin(), checksum.end(), bytes.begin() + kCompletionBodyBytes);
        status = write_all(file, 0, ByteView(bytes.data(), bytes.size()));
        if (!status.ok())
            return status;
        status = file.flush();
        if (!status.ok())
            return status;
        if (observer)
            observer(CleanupPoint::kReceiptReady);
        status = file.close();
        if (!status.ok())
            return status;
        status = publish_no_replace(pending.wstring(), target.wstring());
        if (!status.ok())
            return status;
        auto reopened = FileWriter::open_private_existing(target.wstring());
        if (!reopened.ok())
            return reopened.error();
        impl_->completion_file = reopened.take();
        auto validated = read_completion(impl_->completion_file, impl_->binding);
        if (!validated.ok())
            return validated.error();
        impl_->completed = validated.take();
    }
    if (observer)
        observer(CleanupPoint::kReceiptPublished);
    impl_->journal.reset();
    auto status = impl_->data.resize(0);
    if (!status.ok())
        return status;
    status = impl_->data.flush();
    if (!status.ok())
        return status;
    if (observer)
        observer(CleanupPoint::kDataReleased);
    status = impl_->journal_file.resize(0);
    if (!status.ok())
        return status;
    status = impl_->journal_file.flush();
    if (!status.ok())
        return status;
    if (observer)
        observer(CleanupPoint::kJournalReleased);
    return {};
}

Result<StagingWorkspace> StagingWorkspace::create(const std::wstring& output,
                                                  const ConversionIdentity& identity,
                                                  const RunId& run_id) {
    return open(output, identity, &run_id);
}
Result<StagingWorkspace> StagingWorkspace::resume(const std::wstring& output,
                                                  const ConversionIdentity& identity) {
    return open(output, identity, nullptr);
}

Result<StagingWorkspace>
StagingWorkspace::open(const std::wstring& output, const ConversionIdentity& identity,
                       const RunId* run_id, const std::wstring& initialization_directory,
                       const InitializationObserver& observer,
                       const StagingManifest* expected_manifest, bool require_publication) {
    auto state = std::make_unique<Impl>();
    auto location = output_location(output);
    if (!location.ok())
        return location.error();
    state->output = location.take();
    if (run_id) {
        for (const auto* suffix : {L"", L".partial", L".report.json", L".items.jsonl"}) {
            auto absent = require_absent(state->output.path + suffix);
            if (!absent.ok())
                return absent.error();
        }
    }
    // Reject invalid caller fields before creating even an empty work directory.
    StagingManifest expected;
    expected.conversion = identity;
    expected.destination = state->output.binding;
    expected.run_id = run_id ? *run_id : RunId{1};
    auto validation = encode_staging_manifest(expected);
    if (!validation.ok())
        return validation.error();
    const auto directory_path =
        initialization_directory.empty() ? state->output.path + L".work" : initialization_directory;
    auto directory =
        run_id ? DirectoryPin::create_new(directory_path) : DirectoryPin::open(directory_path);
    if (!directory.ok())
        return directory.error();
    state->directory = directory.take();
    if (run_id && observer)
        observer(InitializationPoint::kDirectoryCreated);
    const std::array<const wchar_t*, 4> names{L"run.lock", L"manifest.bin", L"data.bin",
                                              L"journal.bin"};
    const std::array<FileWriter*, 4> files{&state->lock, &state->manifest_file, &state->data,
                                           &state->journal_file};
    std::array<OwnedFileIdentity, 5> file_ids{};
    const auto& directory_id = state->directory.identity();
    file_ids[0] = {directory_id.volume, directory_id.file};
    for (size_t i = 0; i < files.size(); ++i) {
        const auto path = (std::filesystem::path(state->directory.path()) / names[i]).wstring();
        auto opened =
            run_id ? FileWriter::create_new(path) : FileWriter::open_private_existing(path);
        if (!opened.ok())
            return opened.error();
        *files[i] = opened.take();
        auto file_id = files[i]->identity();
        if (!file_id.ok())
            return file_id.error();
        file_ids[i + 1] = {file_id.value().volume, file_id.value().file};
    }
    if (run_id && observer)
        observer(InitializationPoint::kFilesCreated);
    std::vector<uint8_t> encoded;
    if (run_id) {
        expected.files = file_ids;
        auto serialized = encode_staging_manifest(expected);
        if (!serialized.ok())
            return serialized.error();
        encoded = serialized.take();
        auto written = write_all(state->manifest_file, 0, ByteView(encoded.data(), encoded.size()));
        if (!written.ok())
            return written.error();
        auto flushed = state->manifest_file.flush();
        if (!flushed.ok())
            return flushed.error();
        state->manifest = std::move(expected);
        if (observer)
            observer(InitializationPoint::kManifestFlushed);
    } else {
        const uint64_t size = state->manifest_file.size();
        // Same private schema limit as encode/decode; bound allocation before reading untrusted
        // state.
        if (size > 1024 * 1024)
            return make_error(ErrorKind::kBadField, "manifest.size", 0, size);
        encoded.resize(static_cast<size_t>(size));
        auto read = state->manifest_file.read_at(0, encoded.data(), encoded.size());
        if (!read.ok())
            return read.error();
        auto decoded = decode_staging_manifest(ByteView(encoded.data(), encoded.size()));
        if (!decoded.ok())
            return decoded.error();
        state->manifest = decoded.take();
        if (state->manifest.conversion != identity ||
            state->manifest.destination != state->output.binding)
            return make_error(ErrorKind::kBadField, "workspace.identity", 0, 0,
                              "conversion identity differs");
        if (state->manifest.files != file_ids)
            return make_error(ErrorKind::kBadField, "workspace.files", 0, 0,
                              "run-owned file identity differs");
        if (expected_manifest && state->manifest != *expected_manifest)
            return make_error(ErrorKind::kBadField, "workspace.initialization_identity", 0);
    }
    Sha256 hasher;
    auto hashed = hasher.update(ByteView(encoded.data(), encoded.size()));
    if (!hashed.ok())
        return hashed.error();
    state->binding = hasher.digest();
    if (!run_id) {
        std::error_code error;
        const bool has_publication = std::filesystem::exists(
            std::filesystem::path(state->directory.path()) / L"publication.bin", error);
        if (error)
            return make_error(ErrorKind::kIo, "workspace.publication", 0, error.value());
        if (has_publication) {
            auto publication = Publication::recover(state->output.path, state->binding);
            if (!publication.ok())
                return publication.error();
            state->publication.emplace(publication.take());
        } else {
            if (require_publication)
                return make_error(ErrorKind::kBadField, "workspace.publication_missing", 0);
            for (const auto* suffix : {L"", L".partial", L".report.json", L".items.jsonl"}) {
                auto absent = require_absent(state->output.path + suffix);
                if (!absent.ok())
                    return absent.error();
            }
        }
    }
    const auto completion_path = std::filesystem::path(state->directory.path()) / L"completion.bin";
    auto has_completion = path_exists(completion_path);
    if (!has_completion.ok())
        return has_completion.error();
    if (has_completion.value()) {
        if (run_id || !state->publication ||
            state->publication->phase() != PublicationPhase::kComplete)
            return make_error(ErrorKind::kBadField, "workspace.completion_phase", 0);
        auto opened = FileWriter::open_private_existing(completion_path.wstring());
        if (!opened.ok())
            return opened.error();
        state->completion_file = opened.take();
        auto completed = read_completion(state->completion_file, state->binding);
        if (!completed.ok())
            return completed.error();
        state->completed = completed.take();
    }
    if (!state->completed) {
        auto journal = run_id ? StagingJournal::create(state->data, state->journal_file,
                                                       hasher.digest(), identity.record_budget)
                              : StagingJournal::recover(state->data, state->journal_file,
                                                        hasher.digest(), identity.record_budget);
        if (!journal.ok())
            return journal.error();
        state->journal.emplace(journal.take());
        if (run_id && observer)
            observer(InitializationPoint::kJournalCreated);
    }
    if (state->publication) {
        auto repaired = state->publication->discard_torn_tail();
        if (!repaired.ok())
            return repaired.error();
    }
    return StagingWorkspace(std::move(state));
}

Result<StagingWorkspace> StagingWorkspace::create_ready(const std::wstring& output,
                                                        const ConversionIdentity& identity,
                                                        const RunId& run_id,
                                                        const InitializationObserver& observer) {
    // Keep the canonical parent pinned while initialization handles close for the rename.
    auto location = output_location(output);
    if (!location.ok())
        return location.error();
    const auto final_directory = location.value().path + L".work";
    auto absent = require_absent(final_directory);
    if (!absent.ok())
        return absent.error();
    std::wstring pending = final_directory + L".init-";
    constexpr wchar_t hex[] = L"0123456789abcdef";
    for (uint8_t byte : run_id) {
        pending += hex[byte >> 4];
        pending += hex[byte & 15];
    }
    StagingManifest initialized_manifest;
    {
        auto initialized = open(location.value().path, identity, &run_id, pending, observer);
        if (!initialized.ok())
            return initialized.error();
        auto workspace = initialized.take();
        auto reserved = workspace.prepare_publication();
        if (!reserved.ok())
            return reserved.error();
        if (observer)
            observer(InitializationPoint::kPublicationReserved);
        initialized_manifest = workspace.manifest();
    }
    auto published = publish_no_replace(pending, final_directory);
    if (!published.ok())
        return published.error();
    if (observer)
        observer(InitializationPoint::kWorkspacePublished);
    // Check the precise initialized manifest before recovery can mutate any journal bytes.
    return open(location.value().path, identity, nullptr, {}, {}, &initialized_manifest, true);
}

Result<StagingWorkspace> StagingWorkspace::resume_ready(const std::wstring& output,
                                                        const ConversionIdentity& identity,
                                                        const RunId& fresh_id,
                                                        const InitializationObserver& observer) {
    auto location = output_location(output);
    if (!location.ok())
        return location.error();
    auto present = path_exists(location.value().path + L".work");
    if (!present.ok())
        return present.error();
    if (present.value())
        return open(location.value().path, identity, nullptr, {}, {}, nullptr, true);
    return create_ready(location.value().path, identity, fresh_id, observer);
}
} // namespace ost2pst::writer
