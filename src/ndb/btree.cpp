#include "ost2pst/ndb/btree.h"

#include <string>

#include "ost2pst/util/crc32.h"
#include "ost2pst/util/sig.h"

#include "internal/take.h"

namespace ost2pst::ndb {

using util::ByteView;
using util::DataError;
using util::ErrorKind;
using util::make_error;
using util::Result;
using util::Status;

Result<BtPageInfo> decode_bt_page_footer(ByteView page, FileProfile profile) {
    BtPageInfo info;
    DataError failure;

    // [MS-PST] 2.2.2.7.7.1 cEnt and cEntMax are 1 byte in a PST and 2 bytes in an OST.
    if (bt_count_width(profile) == 2) {
        if (!take(page.u16(bt_c_ent_offset(profile)), info.c_ent, "BTPAGE.cEnt", failure)) {
            return failure;
        }
        if (!take(page.u16(bt_c_ent_max_offset(profile)), info.c_ent_max, "BTPAGE.cEntMax",
                  failure)) {
            return failure;
        }
    } else {
        uint8_t c_ent = 0;
        uint8_t c_ent_max = 0;
        if (!take(page.u8(bt_c_ent_offset(profile)), c_ent, "BTPAGE.cEnt", failure)) {
            return failure;
        }
        if (!take(page.u8(bt_c_ent_max_offset(profile)), c_ent_max, "BTPAGE.cEntMax", failure)) {
            return failure;
        }
        info.c_ent = c_ent;
        info.c_ent_max = c_ent_max;
    }
    if (!take(page.u8(bt_cb_ent_offset(profile)), info.cb_ent, "BTPAGE.cbEnt", failure)) {
        return failure;
    }
    if (!take(page.u8(bt_c_level_offset(profile)), info.c_level, "BTPAGE.cLevel", failure)) {
        return failure;
    }

    if (info.c_ent > info.c_ent_max) {
        return make_error(ErrorKind::kBadField, "BTPAGE.cEnt",
                          page.base() + bt_c_ent_offset(profile), info.c_ent,
                          "larger than cEntMax");
    }
    if (info.cb_ent == 0) {
        return make_error(ErrorKind::kBadField, "BTPAGE.cbEnt",
                          page.base() + bt_cb_ent_offset(profile), 0,
                          "entry stride cannot be zero");
    }
    // [MS-PST] 2.2.2.7.7.1: rgentries ends at the footer, so cEnt * cbEnt has to fit inside it.
    if (static_cast<uint64_t>(info.c_ent) * info.cb_ent > bt_entries_bytes(profile)) {
        return make_error(ErrorKind::kBadField, "BTPAGE.cEnt",
                          page.base() + bt_c_ent_offset(profile), info.c_ent,
                          "entries run past the rgentries area");
    }
    return info;
}

Result<std::vector<BtEntry>> decode_bt_entries(ByteView page, const BtPageInfo& info) {
    std::vector<BtEntry> entries;
    entries.reserve(info.c_ent);
    for (uint16_t index = 0; index < info.c_ent; ++index) {
        Result<ByteView> view = page.sub(index * static_cast<uint64_t>(info.cb_ent), kBtEntrySize);
        if (!view.ok()) {
            return view.error();
        }
        BtEntry entry;
        DataError failure;
        if (!take(view.value().u64(kBtEntryKeyOffset), entry.bt_key, "BTENTRY.btkey", failure)) {
            return failure;
        }
        if (!take(view.value().u64(kBtEntryBidOffset), entry.bid, "BTENTRY.bid", failure)) {
            return failure;
        }
        if (!take(view.value().u64(kBtEntryIbOffset), entry.ib, "BTENTRY.ib", failure)) {
            return failure;
        }
        entries.push_back(entry);
    }
    return entries;
}

Result<std::vector<BbtEntry>> decode_bbt_entries(ByteView page, const BtPageInfo& info) {
    std::vector<BbtEntry> entries;
    entries.reserve(info.c_ent);
    for (uint16_t index = 0; index < info.c_ent; ++index) {
        Result<ByteView> view = page.sub(index * static_cast<uint64_t>(info.cb_ent), kBbtEntrySize);
        if (!view.ok()) {
            return view.error();
        }
        BbtEntry entry;
        DataError failure;
        if (!take(view.value().u64(kBbtEntryBidOffset), entry.bid, "BBTENTRY.bid", failure)) {
            return failure;
        }
        if (!take(view.value().u64(kBbtEntryIbOffset), entry.ib, "BBTENTRY.ib", failure)) {
            return failure;
        }
        if (!take(view.value().u16(kBbtEntryCbOffset), entry.cb, "BBTENTRY.cb", failure)) {
            return failure;
        }
        if (!take(view.value().u16(kBbtEntryCRefOffset), entry.c_ref, "BBTENTRY.cRef", failure)) {
            return failure;
        }
        if (!take(view.value().u16(kBbtEntryOstCRefOffset), entry.ost_c_ref, "BBTENTRY.ostCRef",
                  failure)) {
            return failure;
        }
        entries.push_back(entry);
    }
    return entries;
}

Result<std::vector<NbtEntry>> decode_nbt_entries(ByteView page, const BtPageInfo& info) {
    std::vector<NbtEntry> entries;
    entries.reserve(info.c_ent);
    for (uint16_t index = 0; index < info.c_ent; ++index) {
        Result<ByteView> view = page.sub(index * static_cast<uint64_t>(info.cb_ent), kNbtEntrySize);
        if (!view.ok()) {
            return view.error();
        }
        NbtEntry entry;
        DataError failure;
        if (!take(view.value().u64(kNbtEntryNidOffset), entry.nid, "NBTENTRY.nid", failure)) {
            return failure;
        }
        if (!take(view.value().u64(kNbtEntryBidDataOffset), entry.bid_data, "NBTENTRY.bidData",
                  failure)) {
            return failure;
        }
        if (!take(view.value().u64(kNbtEntryBidSubOffset), entry.bid_sub, "NBTENTRY.bidSub",
                  failure)) {
            return failure;
        }
        if (!take(view.value().u32(kNbtEntryNidParentOffset), entry.nid_parent,
                  "NBTENTRY.nidParent", failure)) {
            return failure;
        }
        entries.push_back(entry);
    }
    return entries;
}

BTreeWalker::BTreeWalker(uint8_t expected_ptype, FileProfile profile, FailureLog* failures,
                         util::ByteBudget* workspace)
    : expected_ptype_(expected_ptype), profile_(profile), failures_(failures),
      buffer_(static_cast<size_t>(page_size(profile))), workspace_(workspace) {}

void BTreeWalker::check_signature_and_crc(uint64_t ib, const PageTrailer& trailer, ByteView page) {
    // [MS-PST] 2.2.2.7.1: FMap/PMap/AMap/FPMap pages write wSig 0 and give the page a bid equal to
    // its own ib; BBT/NBT/DList pages take a bid from bidNextP and compute wSig from ib and bid.
    if (page_type_uses_zero_sig(trailer.ptype)) {
        if (trailer.w_sig == 0 && trailer.bid == ib) {
            ++stats_.page_sig_ok;
        } else {
            ++stats_.page_sig_failed;
            failures_->add(ib, "PAGETRAILER.wSig", trailer.w_sig,
                           "zero-signature page type must have wSig 0 and bid equal to ib");
        }
    } else {
        const uint16_t expected = util::compute_sig(ib, trailer.bid);
        if (expected == trailer.w_sig) {
            ++stats_.page_sig_ok;
        } else {
            ++stats_.page_sig_failed;
            failures_->add(ib, "PAGETRAILER.wSig", trailer.w_sig,
                           "expected " + std::to_string(expected));
        }
    }

    // [MS-PST] 2.2.2.7.1: dwCRC covers the page data excluding the trailer.
    Result<ByteView> data = page.sub(0, static_cast<size_t>(page_data_bytes(profile_)));
    if (!data.ok()) {
        failures_->add(data.error());
        return;
    }
    tally_crc(stats_.crc_variants, trailer.dw_crc, data.value());
    if (util::crc32(data.value()) == trailer.dw_crc) {
        ++stats_.page_crc_ok;
    } else {
        ++stats_.page_crc_failed;
        failures_->add(ib, "PAGETRAILER.dwCRC", trailer.dw_crc, "page CRC does not match");
    }
}

Status BTreeWalker::visit(const util::FileReader& file, uint64_t ib, int64_t expected_level) {
    ++stats_.pages_visited;

    if (ib > file.size() || file.size() - ib < page_size(profile_)) {
        ++stats_.pages_truncated;
        failures_->add(ib, "BTPAGE.ib", ib, "page runs past the end of the file");
        return Status();
    }
    if (visited_.contains(ib)) {
        ++stats_.pages_revisited;
        failures_->add(ib, "BTPAGE.ib", ib, "page reached twice (cycle in the BTree)");
        return Status();
    }
    // Engineering allowances cover hash nodes/buckets and traversal container growth.
    if (workspace_) {
        auto reserved = workspace_->reserve(96, "BTree.workspace", ib);
        if (!reserved.ok())
            return reserved;
    }
    visited_.insert(ib);

    Status io = file.read_at(ib, buffer_.data(), buffer_.size());
    if (!io) {
        return io.error();
    }
    const ByteView page(buffer_.data(), buffer_.size(), ib);

    Result<ByteView> window = page.sub(static_cast<size_t>(bt_trailer_offset(profile_)),
                                       static_cast<size_t>(page_trailer_size(profile_)));
    if (!window.ok()) {
        return window.error();
    }
    Result<PageTrailer> trailer = decode_page_trailer(window.value(), profile_);
    if (!trailer.ok()) {
        ++stats_.pages_bad_trailer;
        failures_->add(trailer.error());
        return Status();
    }
    const PageTrailer& trailer_record = trailer.value();
    if (trailer_record.ptype != expected_ptype_) {
        ++stats_.pages_bad_trailer;
        failures_->add(ib, "PAGETRAILER.ptype", trailer_record.ptype,
                       std::string("expected a ") + page_type_name(expected_ptype_) + " page");
        return Status();
    }

    if (trailer_record.bid > stats_.max_page_bid) {
        stats_.max_page_bid = trailer_record.bid;
    }
    check_signature_and_crc(ib, trailer_record, page);

    Result<BtPageInfo> footer = decode_bt_page_footer(page, profile_);
    if (!footer.ok()) {
        ++stats_.pages_bad_trailer;
        failures_->add(footer.error());
        return Status();
    }
    const BtPageInfo& info = footer.value();

    if (info.c_level > stats_.max_level) {
        stats_.max_level = info.c_level;
    }
    // cLevel counts down to 0 at the leaves ([MS-PST] 2.2.2.7.7.1), so a child of a level n page is
    // a level n-1 page. A mismatch means the walk is reading something that is not this BTree.
    if (expected_level >= 0 && static_cast<int64_t>(info.c_level) != expected_level) {
        ++stats_.level_mismatches;
        failures_->add(ib, "BTPAGE.cLevel", info.c_level,
                       "expected level " + std::to_string(expected_level));
    }

    const bool leaf = info.c_level == 0;
    const uint8_t expected_stride =
        leaf ? (expected_ptype_ == kPageTypeNBT ? kNbtEntrySize : kBbtEntrySize) : kBtEntrySize;
    if (info.cb_ent != expected_stride) {
        ++stats_.stride_mismatches;
        failures_->add(ib + bt_cb_ent_offset(profile_), "BTPAGE.cbEnt", info.cb_ent,
                       "expected " + std::to_string(expected_stride) +
                           " for this page type and level");
    }

    if (!leaf) {
        Result<std::vector<BtEntry>> entries = decode_bt_entries(page, info);
        if (!entries.ok()) {
            failures_->add(entries.error());
            return Status();
        }
        stats_.intermediate_entries += entries.value().size();
        for (const BtEntry& entry : entries.value()) {
            if (workspace_) {
                auto reserved = workspace_->reserve(64, "BTree.workspace", ib);
                if (!reserved.ok())
                    return reserved;
            }
            stack_.push_back(Frame{entry.ib, static_cast<int64_t>(info.c_level) - 1});
        }
        return Status();
    }

    stats_.leaf_entries += info.c_ent;
    if (expected_ptype_ == kPageTypeBBT) {
        Result<std::vector<BbtEntry>> entries = decode_bbt_entries(page, info);
        if (!entries.ok()) {
            failures_->add(entries.error());
            return Status();
        }
        for (const BbtEntry& entry : entries.value()) {
            if (workspace_) {
                // Hash construction plus the subsequent sorted BBT copy and allocator slack.
                auto reserved = workspace_->reserve(128, "BTree.workspace", ib);
                if (!reserved.ok())
                    return reserved;
            }
            bbt_index_.emplace(entry.bid, entry);
        }
        return Status();
    }

    Result<std::vector<NbtEntry>> entries = decode_nbt_entries(page, info);
    if (!entries.ok()) {
        failures_->add(entries.error());
        return Status();
    }
    if (nbt_handler_) {
        for (const NbtEntry& entry : entries.value()) {
            if (workspace_) {
                // NidMap's three indices, ordered enumeration, manifest, ledger and journal slots.
                auto reserved = workspace_->reserve(768, "BTree.workspace", ib);
                if (!reserved.ok())
                    return reserved;
            }
            nbt_handler_(entry, ib);
        }
    }
    return Status();
}

Status BTreeWalker::walk(const util::FileReader& file, uint64_t root_ib) {
    stack_.clear();
    stack_.push_back(Frame{root_ib, -1});
    while (!stack_.empty()) {
        const Frame frame = stack_.back();
        stack_.pop_back();
        Status status = visit(file, frame.ib, frame.expected_level);
        if (!status) {
            return status.error();
        }
    }
    return Status();
}

} // namespace ost2pst::ndb
