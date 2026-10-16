#pragma once

#include <cstdint>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "ost2pst/ndb/crc.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/ndb/report.h"
#include "ost2pst/ndb/trailer.h"
#include "ost2pst/util/byte_budget.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ndb {

// [MS-PST] 2.2.2.7.7.1 BTPAGE footer. cbEnt is the entry stride and the spec says implementations
// MUST use it rather than assuming a fixed entry size. OST widens the two counts to 2 bytes.
struct BtPageInfo {
    uint16_t c_ent = 0;
    uint16_t c_ent_max = 0;
    uint8_t cb_ent = 0;
    uint8_t c_level = 0;
};

// [MS-PST] 2.2.2.7.7.2 BTENTRY (Unicode): the intermediate entry shared by BBT and NBT.
struct BtEntry {
    uint64_t bt_key = 0;
    uint64_t bid = 0;
    uint64_t ib = 0;
};

// [MS-PST] 2.2.2.7.7.3 BBTENTRY (Unicode). cb is raw data bytes, excluding trailer and padding, so
// it must equal the BLOCKTRAILER.cb of the block it points at.
struct BbtEntry {
    uint64_t bid = 0;
    uint64_t ib = 0;
    uint16_t cb = 0;
    uint16_t c_ref = 0; // [MS-PST] 2.2.2.7.7.3 cRef slot: on the measured OST this is the block's
                        // uncompressed data length
    // [MS-PST] 2.2.2.7.7.3 dwPadding slot, which MUST be zero. On the measured OST it is non-zero
    // on 197,742 of 198,111 entries and behaves like a reference count on 197,178 of them; the
    // meaning is unresolved, so the raw value is carried and never read as a count.
    uint16_t ost_c_ref = 0;
};

// [MS-PST] 2.2.2.7.7.4 NBTENTRY (Unicode).
struct NbtEntry {
    uint64_t nid = 0;
    uint64_t bid_data = 0;
    uint64_t bid_sub = 0;
    uint32_t nid_parent = 0;
};

struct BTreeStats {
    uint64_t pages_visited = 0;
    uint64_t pages_truncated = 0;
    uint64_t pages_bad_trailer = 0;
    uint64_t pages_revisited = 0;
    uint64_t page_crc_ok = 0;
    uint64_t page_crc_failed = 0;
    uint64_t page_sig_ok = 0;
    uint64_t page_sig_failed = 0;
    uint64_t leaf_entries = 0;
    uint64_t intermediate_entries = 0;
    uint64_t max_level = 0;
    uint64_t max_page_bid = 0; // [MS-PST] 2.2.2.7.1: page BIDs come from HEADER.bidNextP
    uint64_t level_mismatches = 0;
    uint64_t stride_mismatches = 0;
    CrcVariantTally crc_variants;
};

// page is one page-sized view based at its absolute offset, so errors report absolute offsets.
util::Result<BtPageInfo> decode_bt_page_footer(util::ByteView page, FileProfile profile);
util::Result<std::vector<BtEntry>> decode_bt_entries(util::ByteView page, const BtPageInfo& info);
util::Result<std::vector<BbtEntry>> decode_bbt_entries(util::ByteView page, const BtPageInfo& info);
util::Result<std::vector<NbtEntry>> decode_nbt_entries(util::ByteView page, const BtPageInfo& info);

// Iterative walk: a real mailbox is deep enough that recursion is not worth the stack risk, and a
// leaf callback keeps millions of NBT entries from ever being materialised at once.
class BTreeWalker {
  public:
    BTreeWalker(uint8_t expected_ptype, FileProfile profile, FailureLog* failures,
                util::ByteBudget* workspace = nullptr);

    // IO failure is fatal; every format finding is counted, logged, and skipped.
    util::Status walk(const util::FileReader& file, uint64_t root_ib);

    const BTreeStats& stats() const { return stats_; }
    const std::unordered_map<uint64_t, BbtEntry>& bbt_index() const { return bbt_index_; }

    // entry_ib is the absolute file offset of the leaf page the entry was read from, so a finding
    // about an entry can be located in the file.
    void set_nbt_handler(std::function<void(const NbtEntry& entry, uint64_t entry_ib)> handler) {
        nbt_handler_ = std::move(handler);
    }

  private:
    struct Frame {
        uint64_t ib = 0;
        int64_t expected_level = -1; // -1 = the root page, whose level is whatever it says
    };

    util::Status visit(const util::FileReader& file, uint64_t ib, int64_t expected_level);
    void check_signature_and_crc(uint64_t ib, const PageTrailer& trailer, util::ByteView page);

    uint8_t expected_ptype_ = 0;
    FileProfile profile_ = FileProfile::kOst;
    FailureLog* failures_ = nullptr;
    BTreeStats stats_;
    std::unordered_map<uint64_t, BbtEntry> bbt_index_;
    std::unordered_set<uint64_t> visited_;
    std::vector<Frame> stack_;
    std::vector<uint8_t> buffer_;
    std::function<void(const NbtEntry& entry, uint64_t entry_ib)> nbt_handler_;
    util::ByteBudget* workspace_ = nullptr;
};

} // namespace ost2pst::ndb
