#include "ost2pst/ltp/bth.h"

#include <algorithm>
#include <string>
#include <vector>

#include "internal/take.h"

namespace ost2pst::ltp {

using util::ByteView;
using util::DataError;
using util::ErrorKind;
using util::make_error;
using util::Result;
using util::Status;

namespace {

// [MS-PST] 2.3.2.2: every index record points at one more heap item, so a tree that needs more heap
// items than this is not a mailbox tree, it is a corrupt one.
constexpr uint64_t kMaxHeapItems = 100000;

struct Frame {
    uint32_t hid = 0;
    uint8_t level = 0; // 0 means the array is the leaf array ([MS-PST] 2.3.2.1 bIdxLevels is zero-based)
};

} // namespace

Result<BthHeader> decode_bth_header(ByteView view, ndb::FileProfile profile) {
    if (!view.in_range(0, static_cast<size_t>(kBthHeaderSize))) {
        return make_error(ErrorKind::kTruncated, "BTHHEADER", view.base(), view.size(),
                          "a BTHHEADER is 8 bytes");
    }
    BthHeader header;
    DataError failure;
    if (!take(view.u8(kBthTypeOffset), header.b_type, "BTHHEADER.bType", failure)) {
        return failure;
    }
    if (!take(view.u8(kBthCbKeyOffset), header.cb_key, "BTHHEADER.cbKey", failure)) {
        return failure;
    }
    if (!take(view.u8(kBthCbEntOffset), header.cb_ent, "BTHHEADER.cbEnt", failure)) {
        return failure;
    }
    if (!take(view.u8(kBthIdxLevelsOffset), header.b_idx_levels, "BTHHEADER.bIdxLevels", failure)) {
        return failure;
    }
    if (!take(view.u32(kBthHidRootOffset), header.hid_root, "BTHHEADER.hidRoot", failure)) {
        return failure;
    }
    // [MS-PST] 2.3.2.1: bType MUST be bTypeBTH.
    if (header.b_type != kBthType) {
        return make_error(ErrorKind::kBadField, "BTHHEADER.bType", view.base() + kBthTypeOffset,
                          header.b_type, "a BTHHEADER carries bTypeBTH 0xB5");
    }
    // [MS-PST] 2.3.2.1: cbKey MUST be 2, 4, 8 or 16.
    if (header.cb_key != 2 && header.cb_key != 4 && header.cb_key != 8 && header.cb_key != 16) {
        return make_error(ErrorKind::kBadField, "BTHHEADER.cbKey", view.base() + kBthCbKeyOffset,
                          header.cb_key, "must be 2, 4, 8 or 16");
    }
    // [MS-PST] 2.3.2.1: cbEnt MUST be greater than zero and 32 or less.
    if (header.cb_ent < kBthCbEntMin || header.cb_ent > kBthCbEntMax) {
        return make_error(ErrorKind::kBadField, "BTHHEADER.cbEnt", view.base() + kBthCbEntOffset,
                          header.cb_ent, "must be between 1 and 32");
    }
    if (header.b_idx_levels > kBthMaxIdxLevels) {
        return make_error(ErrorKind::kBadField, "BTHHEADER.bIdxLevels",
                          view.base() + kBthIdxLevelsOffset, header.b_idx_levels,
                          "more than " + std::to_string(kBthMaxIdxLevels) + " index levels is corrupt");
    }
    // [MS-PST] 2.3.2.1: hidRoot is 0 for an empty BTH, otherwise a heap id.
    if (header.hid_root != 0 && !hid_is_valid(header.hid_root, profile)) {
        return make_error(ErrorKind::kBadField, "BTHHEADER.hidRoot", view.base() + kBthHidRootOffset,
                          header.hid_root, "an empty BTH has 0, any other root is a heap id");
    }
    return header;
}

Status walk_bth(const BthHeader &header, ndb::FileProfile profile, HeapSource &source,
                const BthLeafCallback &callback, BthStats &stats, ndb::FailureLog &failures) {
    // [MS-PST] 2.3.2.1: hidRoot 0 means the BTH has no entries at all.
    if (header.hid_root == 0) {
        return Status();
    }

    std::vector<Frame> stack;
    stack.push_back(Frame{header.hid_root, header.b_idx_levels});
    while (!stack.empty()) {
        const Frame frame = stack.back();
        stack.pop_back();
        if (stats.heap_items_read >= kMaxHeapItems) {
            stats.stopped_early = true;
            failures.add(0, "BTHHEADER.hidRoot", frame.hid,
                         "the walk stopped after " + std::to_string(kMaxHeapItems) + " heap items");
            return Status();
        }
        Result<ByteView> item = source.heap(frame.hid);
        if (!item.ok()) {
            return item.error();
        }
        ++stats.heap_items_read;
        const ByteView array = item.value();
        const uint64_t depth = header.b_idx_levels - frame.level;
        stats.max_depth = std::max(stats.max_depth, depth);

        // [MS-PST] 2.3.2.2 / 2.3.2.3: the record count comes from the allocation size, and a trailing
        // partial record is not a record.
        const bool leaf = frame.level == 0;
        const uint64_t record_size = leaf ? bth_leaf_record_size(header) : bth_index_record_size(header);
        const uint64_t records = array.size() / record_size;
        stats.trailing_bytes += array.size() - records * record_size;

        std::vector<Frame> children;
        for (uint64_t index = 0; index < records; ++index) {
            if (stats.leaf_records + stats.index_records >= kBthMaxRecords) {
                stats.stopped_early = true;
                failures.add(array.base(), "BTHENTRY", index,
                             "the walk stopped after " + std::to_string(kBthMaxRecords) + " records");
                return Status();
            }
            const uint64_t at = index * record_size;
            Result<ByteView> record = array.sub(at, static_cast<size_t>(record_size));
            if (!record.ok()) {
                failures.add(record.error());
                ++stats.skipped_records;
                continue;
            }

            if (leaf) {
                BthLeafRecord entry;
                entry.hid = frame.hid;
                entry.offset = array.base() + at;
                entry.position = index;
                entry.key = ByteView(record.value().data(), static_cast<size_t>(header.cb_key),
                                     array.base() + at);
                entry.data = ByteView(record.value().data() + header.cb_key,
                                      static_cast<size_t>(header.cb_ent), array.base() + at + header.cb_key);
                ++stats.leaf_records;
                if (!callback(entry)) {
                    return Status();
                }
                continue;
            }

            Result<uint32_t> next = record.value().u32(header.cb_key);
            if (!next.ok()) {
                failures.add(next.error());
                ++stats.skipped_records;
                continue;
            }
            ++stats.index_records;
            // [MS-PST] 2.3.2.2: hidNextLevel is the heap id of the next level's array.
            if (!hid_is_valid(next.value(), profile)) {
                failures.add(array.base() + at + header.cb_key, "BTHENTRY.hidNextLevel", next.value(),
                             "not a heap id, so the level below it is unreachable");
                ++stats.skipped_records;
                continue;
            }
            children.push_back(Frame{next.value(), static_cast<uint8_t>(frame.level - 1)});
        }

        // Index records are in key order ([MS-PST] 2.3.2.2), so pushing them in reverse makes the
        // leaf records come out in key order.
        for (auto reverse = children.rbegin(); reverse != children.rend(); ++reverse) {
            stack.push_back(*reverse);
        }
    }
    return Status();
}

} // namespace ost2pst::ltp
