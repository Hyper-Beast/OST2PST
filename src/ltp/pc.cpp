#include "ost2pst/ltp/pc.h"

#include <string>

#include "internal/take.h"

namespace ost2pst::ltp {

using util::ByteView;
using util::DataError;
using util::ErrorKind;
using util::make_error;
using util::Result;
using util::Status;

Result<PcRecord> decode_pc_record(ByteView record) {
    if (!record.in_range(0, static_cast<size_t>(kPcRecordSize))) {
        return make_error(ErrorKind::kTruncated, "PCBTHRECORD", record.base(), record.size(),
                          "a PC BTH record is cbKey 2 plus cbEnt 6");
    }
    PcRecord parsed;
    DataError failure;
    if (!take(record.u16(kPcPropIdOffset), parsed.prop_id, "PCBTHRECORD.wPropId", failure)) {
        return failure;
    }
    if (!take(record.u16(kPcPropTypeOffset), parsed.prop_type, "PCBTHRECORD.wPropType", failure)) {
        return failure;
    }
    if (!take(record.u32(kPcValueHnidOffset), parsed.value_hnid, "PCBTHRECORD.dwValueHnid", failure)) {
        return failure;
    }
    parsed.offset = record.base();

    // [MS-PST] 2.3.3.3: the same four bytes are either the value or a reference to it, and wPropType is
    // what decides which.
    parsed.value_inline = prop_type_is_inline(parsed.prop_type);
    if (parsed.value_inline) {
        Result<ByteView> window = record.sub(kPcValueHnidOffset, 4);
        if (!window.ok()) {
            return window.error();
        }
        parsed.value = window.value();
        return parsed;
    }
    // [MS-PST] 2.3.3.2 / 2.3.3.3: dwValueHnid 0 answers neither way -- hidIndex 0 is not a HID and no
    // nidType is 0 -- and Outlook writes it for a variable-size property that has no value at all. The
    // record therefore says "this property is empty" instead of naming a heap item or a subnode.
    parsed.value_absent = parsed.value_hnid == 0;
    parsed.value_in_heap = !parsed.value_absent && hid_type(parsed.value_hnid) == kHidTypeHid;
    parsed.value_in_subnode = !parsed.value_absent && !parsed.value_in_heap;
    return parsed;
}

Status read_pc(const HnHeader &hn_header, ndb::FileProfile profile, HeapSource &source,
               const PcCallback &callback, BthStats &stats, ndb::FailureLog &failures) {
    // [MS-PST] 2.3.3: the existence of a PC is announced at the HN level by bClientSig == bTypePC.
    if (hn_header.b_client_sig != kClientSigPc) {
        return make_error(ErrorKind::kBadField, "HNHDR.bClientSig", 0, hn_header.b_client_sig,
                          std::string("a property context carries bTypePC, this heap node carries ") +
                              client_sig_name(hn_header.b_client_sig));
    }

    // [MS-PST] 2.3.3.1: the BTHHEADER of a PC is reached through hidUserRoot.
    Result<ByteView> root = source.heap(hn_header.hid_user_root);
    if (!root.ok()) {
        return root.error();
    }
    ++stats.heap_items_read;
    Result<BthHeader> header = decode_bth_header(root.value(), profile);
    if (!header.ok()) {
        return header.error();
    }
    // [MS-PST] 2.3.3: implementation-wise a PC is a BTH with cbKey 2 and cbEnt 6.
    if (header.value().cb_key != kPcCbKey || header.value().cb_ent != kPcCbEnt) {
        return make_error(ErrorKind::kBadField, "BTHHEADER.cbKey", root.value().base(),
                          header.value().cb_key,
                          "a PC BTH has cbKey 2 and cbEnt 6, this one has cbKey " +
                              std::to_string(header.value().cb_key) + " and cbEnt " +
                              std::to_string(header.value().cb_ent));
    }

    return walk_bth(header.value(), profile, source, [&](const BthLeafRecord &leaf) {
        // The key and the data of a BTH record are adjacent ([MS-PST] 2.3.2.3), so the whole record is
        // the two windows joined at the record's own absolute offset.
        const ByteView whole(leaf.key.data(), leaf.key.size() + leaf.data.size(), leaf.offset);
        Result<PcRecord> record = decode_pc_record(whole);
        if (!record.ok()) {
            failures.add(record.error());
            ++stats.skipped_records;
            return true;
        }
        PcRecord parsed = record.take();
        parsed.position = leaf.position;
        return callback(parsed);
    }, stats, failures);
}

} // namespace ost2pst::ltp
