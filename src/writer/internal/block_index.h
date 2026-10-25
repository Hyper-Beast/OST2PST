#pragma once

#include <cstddef>
#include <memory>
#include <type_traits>
#include <vector>

#include "ost2pst/util/workspace.h"

namespace ost2pst::writer {
// Append-only metadata in fixed chunks: no multi-million-entry vector reallocation, and
// no implementation-dependent deque allocation per element on the Windows STL.
// Callers enforce their aggregate capacity before appending. Payload bytes live elsewhere.
template <class T> class BlockIndex {
    static_assert(std::is_trivially_copyable_v<T>);
    static constexpr size_t kChunk = 4096;
    std::vector<std::unique_ptr<T[]>> chunks_;
    size_t size_ = 0;
    std::unique_ptr<util::SpillBuffer> paged_;
    mutable std::vector<T> cache_;
    mutable size_t cache_chunk_ = SIZE_MAX;
    mutable util::Status status_;

    void load(size_t chunk) const {
        if (!status_.ok() || cache_chunk_ == chunk)
            return;
        if (cache_chunk_ != SIZE_MAX) {
            const size_t first = cache_chunk_ * kChunk;
            const size_t count = std::min(kChunk, size_ - first);
            status_ = paged_->write_at(
                first * sizeof(T),
                util::ByteView(reinterpret_cast<const uint8_t*>(cache_.data()), count * sizeof(T)));
            if (!status_.ok())
                return;
        }
        std::fill(cache_.begin(), cache_.end(), T{});
        const size_t first = chunk * kChunk;
        if (first < size_) {
            const size_t count = std::min(kChunk, size_ - first);
            status_ = paged_->read_at(first * sizeof(T), reinterpret_cast<uint8_t*>(cache_.data()),
                                      count * sizeof(T));
        }
        cache_chunk_ = chunk;
    }

  public:
    explicit BlockIndex(std::shared_ptr<util::Workspace> workspace = {}) {
        if (workspace) {
            paged_ = std::make_unique<util::SpillBuffer>(std::move(workspace));
            cache_.resize(kChunk);
        }
    }
    util::Status status() const {
        return !status_.ok() ? status_ : (paged_ ? paged_->status() : util::Status{});
    }
    size_t size() const { return size_; }
    // References remain valid until another chunk is accessed, as in the writer's
    // immediate-use block lookups. The fixed 4096-record working window is not a growing cache.
    T& operator[](size_t index) {
        if (paged_) {
            load(index / kChunk);
            return cache_[index % kChunk];
        }
        return chunks_[index / kChunk][index % kChunk];
    }
    const T& operator[](size_t index) const {
        if (paged_) {
            load(index / kChunk);
            return cache_[index % kChunk];
        }
        return chunks_[index / kChunk][index % kChunk];
    }
    void push_back(const T& value) {
        if (paged_) {
            if (!status_.ok())
                return;
            status_ = paged_->resize((size_ + 1) * sizeof(T));
            if (!status_.ok())
                return;
            load(size_ / kChunk);
            if (!status_.ok())
                return;
            cache_[size_ % kChunk] = value;
            ++size_;
            return;
        }
        if (size_ % kChunk == 0)
            chunks_.push_back(std::make_unique<T[]>(kChunk));
        (*this)[size_++] = value;
    }
};
} // namespace ost2pst::writer
