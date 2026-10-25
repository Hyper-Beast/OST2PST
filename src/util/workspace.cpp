#include "ost2pst/util/workspace.h"

#include <array>
#include <filesystem>
#include <random>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace ost2pst::util {
uint64_t automatic_memory_limit(uint64_t available) {
    return std::clamp<uint64_t>(available / 10, 256ull << 20, 2ull << 30);
}
uint64_t available_physical_memory() {
#ifdef _WIN32
    MEMORYSTATUSEX state{};
    state.dwLength = sizeof(state);
    if (GlobalMemoryStatusEx(&state))
        return state.ullAvailPhys;
#endif
    return 0;
}

void Workspace::refresh() {
    if (!monitor_pressure)
        return;
    const auto now = std::chrono::steady_clock::now();
    if (now - last_check_ < std::chrono::seconds(1))
        return;
    last_check_ = now;
    const auto available = available_physical_memory();
    if (available)
        memory->set_target(std::min(memory->limit(), available / 10));
}

SpillBuffer::SpillBuffer(std::shared_ptr<Workspace> workspace) : workspace_(std::move(workspace)) {}
SpillBuffer::SpillBuffer(std::shared_ptr<Workspace> workspace,
                         std::shared_ptr<RandomAccessFile> file)
    : workspace_(std::move(workspace)), file_(std::move(file)) {
    if (file_ && file_->size() != 0)
        status_ = make_error(ErrorKind::kBadField, "scratch.file_not_empty", 0, file_->size());
}
SpillBuffer::~SpillBuffer() {
    workspace_->memory->release(charged_);
}
Status SpillBuffer::fail(Status status) const {
    if (status_.ok() && !status.ok())
        status_ = std::move(status);
    return status_;
}
Status SpillBuffer::flush() const {
    if (!status_.ok())
        return status_;
    if (dirty_) {
        const uint64_t offset = cache_page_ * kPage;
        const auto count = static_cast<size_t>(std::min<uint64_t>(kPage, size_ - offset));
        auto written = write_all(*file_, offset, ByteView(cache_.data(), count));
        if (!written.ok())
            return fail(written);
        dirty_ = false;
    }
    return {};
}
Status SpillBuffer::spill() {
    if (file_)
        return status_;
    if (workspace_->scratch_factory) {
        auto opened = workspace_->scratch_factory();
        if (!opened.ok())
            return fail(opened.error());
        file_ = opened.take();
        if (!file_ || file_->size() != 0)
            return fail(
                make_error(ErrorKind::kBadField, "scratch.factory", 0, file_ ? file_->size() : 0));
    } else {
        std::random_device random;
        const auto path = std::filesystem::path(workspace_->directory) /
                          (L"scratch-pages-" + std::to_wstring(random()) + L"-" +
                           std::to_wstring(random()) + L".tmp");
        auto opened = FileWriter::create_temporary(path.wstring());
        if (!opened.ok())
            return fail(opened.error());
        file_ = std::make_shared<FileWriter>(opened.take());
    }
    for (size_t index = 0; index < pages_.size(); ++index) {
        const uint64_t offset = uint64_t{index} * kPage;
        if (offset >= size_)
            break;
        const auto count = static_cast<size_t>(std::min<uint64_t>(kPage, size_ - offset));
        auto written = write_all(*file_, offset, ByteView(pages_[index].data(), count));
        if (!written.ok())
            return fail(written);
    }
    workspace_->spilled_bytes += size_;
    pages_.clear();
    pages_.shrink_to_fit();
    workspace_->memory->release(charged_);
    charged_ = 0;
    if (workspace_->memory->acquire(kPage)) {
        charged_ = kPage;
        cache_.resize(kPage);
    }
    return {};
}
Status SpillBuffer::load(uint64_t page) const {
    if (page == cache_page_)
        return status_;
    auto flushed = flush();
    if (!flushed.ok())
        return flushed;
    std::fill(cache_.begin(), cache_.end(), uint8_t{0});
    const uint64_t offset = page * kPage;
    if (offset < file_->size()) {
        const auto count = static_cast<size_t>(std::min<uint64_t>(kPage, file_->size() - offset));
        auto read = file_->read_at(offset, cache_.data(), count);
        if (!read.ok())
            return fail(read);
    }
    cache_page_ = page;
    return {};
}
Status SpillBuffer::resize(uint64_t bytes) {
    if (!status_.ok())
        return status_;
    if (bytes < size_)
        return fail(make_error(ErrorKind::kBadField, "scratch.shrink", bytes, size_));
    const uint64_t count = bytes / kPage + (bytes % kPage != 0);
    while (!file_ && pages_.size() < count) {
        if (!workspace_->memory->acquire(kPage)) {
            auto result = spill();
            if (!result.ok())
                return result;
        } else {
            charged_ += kPage;
            pages_.emplace_back(kPage, 0);
        }
    }
    if (file_) {
        if (file_->size() < bytes) {
            const auto first = file_->size();
            const uint64_t capacity =
                bytes > UINT64_MAX - (kPage - 1) ? bytes : ((bytes + kPage - 1) / kPage) * kPage;
            auto result = file_->resize(capacity);
            if (!result.ok())
                return fail(result);
            // Do not depend on filesystem extension contents for zero-initialized
            // cell arrays, unused slots or partially filled cache pages.
            static constexpr std::array<uint8_t, kPage> zeros{};
            for (uint64_t offset = first; offset < capacity; offset += zeros.size()) {
                const auto zero_count =
                    static_cast<size_t>(std::min<uint64_t>(zeros.size(), capacity - offset));
                result = write_all(*file_, offset, ByteView(zeros.data(), zero_count));
                if (!result.ok())
                    return fail(result);
            }
        }
        workspace_->spilled_bytes += bytes - size_;
    }
    size_ = bytes;
    return {};
}
Status SpillBuffer::write_at(uint64_t offset, ByteView bytes) {
    if (!status_.ok())
        return status_;
    workspace_->refresh();
    if (!file_ && workspace_->memory->used() > workspace_->memory->target()) {
        auto result = spill();
        if (!result.ok())
            return result;
    }
    if (offset > size_ || bytes.size() > UINT64_MAX - offset)
        return fail(make_error(ErrorKind::kBadField, "scratch.write_range", offset, bytes.size()));
    if (offset + bytes.size() > size_) {
        auto grown = resize(offset + bytes.size());
        if (!grown.ok())
            return grown;
    }
    if (file_ && cache_.empty())
        return fail(write_all(*file_, offset, bytes));
    size_t done = 0;
    while (done < bytes.size()) {
        const auto page = offset / kPage;
        const auto within = static_cast<size_t>(offset % kPage);
        const auto count = std::min(kPage - within, bytes.size() - done);
        uint8_t* target = nullptr;
        if (file_) {
            auto loaded = load(page);
            if (!loaded.ok())
                return loaded;
            target = cache_.data();
            dirty_ = true;
        } else {
            target = pages_[static_cast<size_t>(page)].data();
        }
        std::memcpy(target + within, bytes.data() + done, count);
        done += count;
        offset += count;
    }
    return {};
}
Status SpillBuffer::read_at(uint64_t offset, uint8_t* data, size_t count) const {
    if (!status_.ok())
        return status_;
    if (offset > size_ || count > size_ - offset)
        return fail(make_error(ErrorKind::kBadField, "scratch.read_range", offset, count));
    if (file_ && cache_.empty())
        return fail(file_->read_at(offset, data, count));
    size_t done = 0;
    while (done < count) {
        const auto page = offset / kPage;
        const auto within = static_cast<size_t>(offset % kPage);
        const auto take = std::min(kPage - within, count - done);
        const uint8_t* source = nullptr;
        if (file_) {
            auto loaded = load(page);
            if (!loaded.ok())
                return loaded;
            source = cache_.data();
        } else {
            source = pages_[static_cast<size_t>(page)].data();
        }
        std::memcpy(data + done, source + within, take);
        done += take;
        offset += take;
    }
    return {};
}
} // namespace ost2pst::util
