#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "ost2pst/ltp/layout.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ltp {

// --- Search Update Descriptor ([MS-PST] 2.4.8.1.1) ---
// wSUDType selects which SUDData structure the 16 bytes hold ([MS-PST] 2.4.8.2), and every one of them
// is a run of DWORDs, so the reader keeps the 16 bytes as they are and names the fields per type.
struct Sud {
    uint16_t w_flags = 0;
    uint16_t w_type = 0;
    std::array<uint32_t, 4> data{};
    uint64_t offset = 0;  // absolute offset of the SUD in the queue node's data block
    uint64_t position = 0; // index into the queue array
};

util::Result<Sud> decode_sud(util::ByteView view);

// [MS-PST] 2.4.8.2: the SUDData of the add / modify / delete / move types is a run of NIDs. These are the
// DWORDs each type names, in the order the spec lists them.
std::vector<std::pair<std::string, uint32_t>> sud_data_fields(const Sud &sud);

const char *sud_type_name(uint16_t sud_type);
std::string sud_flags_text(uint16_t flags);

// --- Basic queue node ([MS-PST] 2.4.8.3) ---
// The node's data block is a flat array of k-byte items and NBTENTRY.nidParent is re-purposed as the byte
// offset of the queue head, so the items before that offset have already been dequeued.
struct QueueStats {
    uint64_t bytes = 0;
    uint64_t item_size = 0;
    uint64_t head_offset = 0;
    uint64_t items_total = 0;
    uint64_t items_queued = 0;   // at or past the head
    uint64_t items_consumed = 0; // before the head, still in the block
    uint64_t items_skipped = 0;
    uint64_t max_offset_past_head = 0;
    bool ragged = false; // cbData is not an integer multiple of the item size
    bool head_past_end = false;
    bool stopped_early = false;
};

using QueueItemCallback = std::function<bool(util::ByteView item, uint64_t position)>;

// [MS-PST] 2.4.8.3: "Implementations MUST NOT process the contents of a queue if cbData is not an integer
// multiple of k", so a ragged block is reported and only the whole items are walked.
util::Status walk_queue(uint64_t head_offset, uint64_t item_size, util::ByteView block,
                        const QueueItemCallback &callback, QueueStats &stats, ndb::FailureLog &failures);

// The Search Management Queue ([MS-PST] 2.4.8.4.1): the queue node at NID_SEARCH_MANAGEMENT_QUEUE whose
// items are SUDs. There is exactly one per PST.
struct SmqReport {
    QueueStats queue;
    std::map<uint16_t, uint64_t> by_type;
    std::map<uint32_t, uint64_t> by_flags;
    std::vector<Sud> suds; // the queued items, capped so a corrupt queue cannot fill memory
    uint64_t unknown_types = 0;
    uint64_t held = 0; // items kept in suds
};

util::Result<SmqReport> read_smq(uint64_t head_offset, util::ByteView block, ndb::FailureLog &failures);

} // namespace ost2pst::ltp
