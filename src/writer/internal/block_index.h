#pragma once

#include <cstddef>
#include <memory>
#include <type_traits>
#include <vector>

namespace ost2pst::writer {
// Append-only metadata in fixed chunks: no multi-million-entry vector reallocation, and
// no implementation-dependent deque allocation per element on the Windows STL.
// Callers enforce their aggregate capacity before appending. Payload bytes live elsewhere.
template <class T> class BlockIndex {
    static_assert(std::is_trivially_copyable_v<T>);
    static constexpr size_t kChunk = 4096;
    std::vector<std::unique_ptr<T[]>> chunks_;
    size_t size_ = 0;

  public:
    size_t size() const { return size_; }
    T& operator[](size_t index) { return chunks_[index / kChunk][index % kChunk]; }
    const T& operator[](size_t index) const { return chunks_[index / kChunk][index % kChunk]; }
    void push_back(const T& value) {
        if (size_ % kChunk == 0)
            chunks_.push_back(std::make_unique<T[]>(kChunk));
        (*this)[size_++] = value;
    }
};
} // namespace ost2pst::writer
