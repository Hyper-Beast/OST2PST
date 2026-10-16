#pragma once

#include <cstdint>
#include <functional>

#include "ost2pst/ltp/layout.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ltp {

// [MS-PST] 2.3.2.1 BTHHEADER: bType cbKey cbEnt bIdxLevels hidRoot. bIdxLevels is zero-based, so 0 means
// the array hidRoot names is already the leaf array.
struct BthHeader {
    uint8_t b_type = 0;
    uint8_t cb_key = 0;
    uint8_t cb_ent = 0;
    uint8_t b_idx_levels = 0;
    uint32_t hid_root = 0; // 0 when the BTH is empty ([MS-PST] 2.3.2.1)
};

// hidRoot is a HID, and a HID's field widths are profile-specific ([MS-PST] 2.3.1.1), so validating the
// root needs the profile the file is read with.
util::Result<BthHeader> decode_bth_header(util::ByteView view, ndb::FileProfile profile);

// [MS-PST] 2.3.2.3: a leaf record is exactly cbKey key bytes then cbEnt data bytes, byte-aligned.
constexpr uint64_t bth_leaf_record_size(const BthHeader &header) {
    return static_cast<uint64_t>(header.cb_key) + header.cb_ent; // [MS-PST] 2.3.2.3 record = cbKey + cbEnt
}
// [MS-PST] 2.3.2.2: an index record is the key plus the 4-byte HID of the next level's array.
constexpr uint64_t bth_index_record_size(const BthHeader &header) {
    return static_cast<uint64_t>(header.cb_key) + kBthHidNextLevelSize; // [MS-PST] 2.3.2.2 key + hidNextLevel
}

// One leaf record, with the key and data as views into the heap allocation it came from.
struct BthLeafRecord {
    uint32_t hid = 0;      // heap id of the array holding this record
    uint64_t offset = 0;   // absolute file offset of the record itself
    uint64_t position = 0; // index within the leaf array, in key order
    util::ByteView key;
    util::ByteView data;
};

// A BTH only reaches its records through heap ids ([MS-PST] 2.3.2.1 / 2.3.2.2), so the walk is written
// against this seam. Keeping it virtual is what lets the traversal be tested without a file.
class HeapSource {
public:
    HeapSource() = default;
    HeapSource(const HeapSource &) = delete;
    HeapSource &operator=(const HeapSource &) = delete;
    HeapSource(HeapSource &&) = delete;
    HeapSource &operator=(HeapSource &&) = delete;
    virtual ~HeapSource() = default;

    // The returned view has to stay valid until the next call on the same object.
    virtual util::Result<util::ByteView> heap(uint32_t hid) = 0;
};

struct BthStats {
    uint64_t heap_items_read = 0;
    uint64_t index_records = 0;
    uint64_t leaf_records = 0;
    uint64_t levels_walked = 0;
    uint64_t skipped_records = 0;
    uint64_t trailing_bytes = 0;
    uint64_t max_depth = 0;
    bool stopped_early = false;
};

using BthLeafCallback = std::function<bool(const BthLeafRecord &record)>;

// Walks a BTH from hidRoot down to its leaf records and reports them in key order: index arrays are
// visited in key order and each leaf array is internally sorted ([MS-PST] 2.3.2.2 / 2.3.2.3). A bad
// record is counted and skipped so one bad heap item does not end the walk; only a heap id the source
// cannot answer at all is returned as an error. Work is capped so a corrupt BTH cannot spin.
// The profile decides which 32-bit ids count as heap ids ([MS-PST] 2.3.1.1).
util::Status walk_bth(const BthHeader &header, ndb::FileProfile profile, HeapSource &source,
                      const BthLeafCallback &callback, BthStats &stats, ndb::FailureLog &failures);

} // namespace ost2pst::ltp
