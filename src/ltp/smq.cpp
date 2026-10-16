#include "ost2pst/ltp/smq.h"

#include <utility>

#include "internal/take.h"

namespace ost2pst::ltp {

using ndb::FailureLog;
using util::ByteView;
using util::DataError;
using util::ErrorKind;
using util::make_error;
using util::Result;
using util::Status;

namespace {

// A queue is a work queue, not an index, so a corrupt cbData is capped instead of trusted.
constexpr uint64_t kMaxHeldSuds = 64;

} // namespace

Result<Sud> decode_sud(ByteView view) {
    if (!view.in_range(0, static_cast<size_t>(kSudSize))) {
        return make_error(ErrorKind::kTruncated, "SUD", view.base(), view.size(),
                          "a SUD is wFlags, wSUDType, then 16 bytes of SUDData");
    }
    Sud parsed;
    DataError failure;
    if (!take(view.u16(kSudFlagsOffset), parsed.w_flags, "SUD.wFlags", failure)) {
        return failure;
    }
    if (!take(view.u16(kSudTypeOffset), parsed.w_type, "SUD.wSUDType", failure)) {
        return failure;
    }
    for (size_t index = 0; index < parsed.data.size(); ++index) {
        if (!take(view.u32(kSudDataOffset + index * 4), parsed.data[index], "SUD.SUDData", failure)) {
            return failure;
        }
    }
    parsed.offset = view.base();
    return parsed;
}

std::vector<std::pair<std::string, uint32_t>> sud_data_fields(const Sud &sud) {
    switch (sud.w_type) {
    case kSudTypeMsgAdd:
    case kSudTypeMsgMod:
    case kSudTypeMsgDel:
    case kSudTypeMsgRowMod:
        // [MS-PST] 2.4.8.2.1: SUD_MSG_ADD / SUD_MSG_MOD / SUD_MSG_DEL.
        return {{"nidParent", sud.data[0]}, {"nidMsg", sud.data[1]}};
    case kSudTypeMsgMov:
        // [MS-PST] 2.4.8.2.2: SUD_MSG_MOV.
        return {{"nidParentNew", sud.data[0]}, {"nidMsg", sud.data[1]}, {"nidParentOld", sud.data[2]}};
    case kSudTypeFldAdd:
    case kSudTypeFldMov:
        // [MS-PST] 2.4.8.2.3: SUD_FLD_ADD / SUD_FLD_MOV.
        return {{"nidParent", sud.data[0]},
                {"nidMsg", sud.data[1]},
                {"dwReserved1", sud.data[2]},
                {"dwReserved2", sud.data[3]}};
    case kSudTypeFldMod:
    case kSudTypeFldDel:
        // [MS-PST] 2.4.8.2.4: SUD_FLD_MOD / SUD_FLD_DEL.
        return {{"nidFld", sud.data[0]}, {"dwReserved", sud.data[1]}};
    case kSudTypeSrchAdd:
    case kSudTypeSrchDel:
        // [MS-PST] 2.4.8.2.5: SUD_SRCH_ADD / SUD_SRCH_DEL.
        return {{"nidSrch", sud.data[0]}};
    case kSudTypeSrchMod:
        // [MS-PST] 2.4.8.2.6: SUD_SRCH_MOD.
        return {{"nidSrch", sud.data[0]}, {"dwReserved", sud.data[1]}};
    case kSudTypeMsgSpam:
        // [MS-PST] 2.4.8.2.7: SUD_MSG_SPAM.
        return {{"nidParent", sud.data[0]}, {"nidMsg", sud.data[1]}};
    case kSudTypeIdxMsgDel:
        // [MS-PST] 2.4.8.2.8: SUD_IDX_MSG_DEL.
        return {{"nidParent", sud.data[0]}, {"nidMsg", sud.data[1]}};
    case kSudTypeMsgIdx:
        // [MS-PST] 2.4.8.2.9: SUD_MSG_IDX.
        return {{"nidMsg", sud.data[0]}};
    default:
        return {}; // [MS-PST] 2.4.8.1: an undefined wSUDType has no defined SUDData
    }
}

const char *sud_type_name(uint16_t sud_type) {
    switch (sud_type) {
    case kSudTypeNull:
        return "SUDT_NULL";
    case kSudTypeMsgAdd:
        return "SUDT_MSG_ADD";
    case kSudTypeMsgMod:
        return "SUDT_MSG_MOD";
    case kSudTypeMsgDel:
        return "SUDT_MSG_DEL";
    case kSudTypeMsgMov:
        return "SUDT_MSG_MOV";
    case kSudTypeFldAdd:
        return "SUDT_FLD_ADD";
    case kSudTypeFldMod:
        return "SUDT_FLD_MOD";
    case kSudTypeFldDel:
        return "SUDT_FLD_DEL";
    case kSudTypeFldMov:
        return "SUDT_FLD_MOV";
    case kSudTypeSrchAdd:
        return "SUDT_SRCH_ADD";
    case kSudTypeSrchMod:
        return "SUDT_SRCH_MOD";
    case kSudTypeSrchDel:
        return "SUDT_SRCH_DEL";
    case kSudTypeMsgRowMod:
        return "SUDT_MSG_ROW_MOD";
    case kSudTypeMsgSpam:
        return "SUDT_MSG_SPAM";
    case kSudTypeIdxMsgDel:
        return "SUDT_IDX_MSG_DEL";
    case kSudTypeMsgIdx:
        return "SUDT_MSG_IDX";
    default:
        return nullptr;
    }
}

std::string sud_flags_text(uint16_t flags) {
    struct Flag {
        uint16_t bit;
        const char *name;
    };
    // [MS-PST] 2.4.8.1.1: the flags a SUD may carry, in the order the spec lists them.
    static constexpr Flag kFlags[] = {
        {kSudFlagPriorityLow, "SUDF_PRIORITY_LOW"},
        {kSudFlagPriorityHigh, "SUDF_PRIORITY_HIGH"},
        {kSudFlagSearchRestart, "SUDF_SEARCH_RESTART"},
        {kSudFlagNameChanged, "SUDF_NAME_CHANGED"},
        {kSudFlagMoveOutToIn, "SUDF_MOVE_OUT_TO_IN"},
        {kSudFlagMoveInToIn, "SUDF_MOVE_IN_TO_IN"},
        {kSudFlagMoveInToOut, "SUDF_MOVE_IN_TO_OUT"},
        {kSudFlagMoveOutToOut, "SUDF_MOVE_OUT_TO_OUT"},
        {kSudFlagSpamCheckServer, "SUDF_SPAM_CHECK_SERVER"},
        {kSudFlagSetDelName, "SUDF_SET_DEL_NAME"},
        {kSudFlagSrchDone, "SUDF_SRCH_DONE"},
        {kSudFlagDomainChecked, "SUDF_DOMAIN_CHECKED"},
    };
    std::string text;
    uint16_t known = 0;
    for (const Flag &flag : kFlags) {
        known |= flag.bit;
        if ((flags & flag.bit) != 0) {
            if (!text.empty()) {
                text += "|";
            }
            text += flag.name;
        }
    }
    if ((flags & ~known) != 0) {
        if (!text.empty()) {
            text += "|";
        }
        text += "unknown";
    }
    if (text.empty()) {
        text = "none";
    }
    return text;
}

Status walk_queue(uint64_t head_offset, uint64_t item_size, ByteView block,
                  const QueueItemCallback &callback, QueueStats &stats, FailureLog &failures) {
    if (item_size == 0) {
        return make_error(ErrorKind::kBadField, "queue.itemSize", block.base(), 0,
                          "a queue with zero-byte items has no head offset and no item count");
    }
    stats.bytes = block.size();
    stats.item_size = item_size;
    stats.head_offset = head_offset;

    // [MS-PST] 2.4.8.3: nidParent is a byte offset into the block, so a head past the end means the
    // queue is corrupt. When the last item is dequeued both nidParent and cbData go to zero, so a head
    // exactly at the end of an empty queue is normal.
    if (head_offset > block.size()) {
        stats.head_past_end = true;
        failures.add(make_error(ErrorKind::kBadField, "NBTENTRY.nidParent", block.base(), head_offset,
                                "the queue head is past the end of the queue node's data block"));
    }
    if (block.size() % item_size != 0) {
        // [MS-PST] 2.4.8.3: "Implementations MUST NOT process the contents of a queue if cbData is not
        // an integer multiple of k", so only the whole items are walked and the ragged tail is reported.
        stats.ragged = true;
        failures.add(make_error(ErrorKind::kBadField, "BBTENTRY.cbData", block.base(), block.size(),
                                "a queue node's cbData is not an integer multiple of the item size"));
    }

    const uint64_t total = block.size() / item_size;
    stats.items_total = total;
    uint64_t limit = total;
    if (limit > kQueueMaxItems) {
        limit = kQueueMaxItems;
        stats.stopped_early = true;
        stats.items_skipped += total - limit;
    }
    for (uint64_t index = 0; index < limit; ++index) {
        const uint64_t offset = index * item_size;
        // [MS-PST] 2.4.8.3: the items before the head have already been dequeued; they are still counted
        // so a reader can see how much of the block is dead space.
        if (offset < head_offset) {
            ++stats.items_consumed;
        } else {
            ++stats.items_queued;
        }
        Result<ByteView> item = block.sub(offset, static_cast<size_t>(item_size));
        if (!item.ok()) {
            failures.add(item.error());
            ++stats.items_skipped;
            continue;
        }
        if (!callback(item.value(), index)) {
            stats.stopped_early = true;
            stats.items_skipped += total - index - 1;
            break;
        }
    }
    return Status();
}

Result<SmqReport> read_smq(uint64_t head_offset, ByteView block, FailureLog &failures) {
    SmqReport report;
    // [MS-PST] 2.4.8.4.1: every item of the SMQ is a SUD, so k is the size of a SUD.
    Status status = walk_queue(head_offset, kSudSize, block, [&](ByteView item, uint64_t position) {
        Result<Sud> decoded = decode_sud(item);
        if (!decoded.ok()) {
            failures.add(decoded.error());
            ++report.queue.items_skipped;
            return true;
        }
        Sud sud = decoded.take();
        sud.position = position;
        ++report.by_type[sud.w_type];
        ++report.by_flags[sud.w_flags];
        if (sud_type_name(sud.w_type) == nullptr) {
            ++report.unknown_types;
        }
        if (report.suds.size() < kMaxHeldSuds) {
            report.suds.push_back(std::move(sud));
        }
        return true;
    }, report.queue, failures);
    if (!status) {
        return status.error();
    }
    report.held = report.suds.size();
    return report;
}

} // namespace ost2pst::ltp
