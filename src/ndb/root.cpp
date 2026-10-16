#include "ost2pst/ndb/root.h"

namespace ost2pst::ndb {

using util::ByteView;
using util::DataError;
using util::Result;

namespace {

template <class T>
bool take(Result<T> read, T &destination, const char *field, DataError &failure) {
    if (read.ok()) {
        destination = read.value();
        return true;
    }
    failure = read.error();
    failure.field = field;
    return false;
}

Result<BRef> decode_bref(ByteView view, uint64_t offset) {
    BRef bref;
    DataError failure;
    if (!take(view.u64(offset + kBRefBidOffset), bref.bid, "BREF.bid", failure)) {
        return failure;
    }
    if (!take(view.u64(offset + kBRefIbOffset), bref.ib, "BREF.ib", failure)) {
        return failure;
    }
    return bref;
}

} // namespace

Result<Root> decode_root(ByteView view, uint64_t offset) {
    Root root;
    DataError failure;

    if (!take(view.u32(offset + kRootDwReservedOffset), root.dw_reserved, "ROOT.dwReserved", failure)) {
        return failure;
    }
    if (!take(view.u64(offset + kRootIbFileEofOffset), root.ib_file_eof, "ROOT.ibFileEof", failure)) {
        return failure;
    }
    if (!take(view.u64(offset + kRootIbAMapLastOffset), root.ib_amap_last, "ROOT.ibAMapLast", failure)) {
        return failure;
    }
    if (!take(view.u64(offset + kRootCbAMapFreeOffset), root.cb_amap_free, "ROOT.cbAMapFree", failure)) {
        return failure;
    }
    if (!take(view.u64(offset + kRootCbPMapFreeOffset), root.cb_pmap_free, "ROOT.cbPMapFree", failure)) {
        return failure;
    }

    Result<BRef> nbt = decode_bref(view, offset + kRootNbtBrefOffset);
    if (!nbt.ok()) {
        return nbt.error();
    }
    root.nbt_bref = nbt.value();

    Result<BRef> bbt = decode_bref(view, offset + kRootBbtBrefOffset);
    if (!bbt.ok()) {
        return bbt.error();
    }
    root.bbt_bref = bbt.value();

    if (!take(view.u8(offset + kRootFAMapValidOffset), root.f_amap_valid, "ROOT.fAMapValid", failure)) {
        return failure;
    }
    if (!take(view.u8(offset + kRootBReservedOffset), root.b_reserved, "ROOT.bReserved", failure)) {
        return failure;
    }
    if (!take(view.u16(offset + kRootWReservedOffset), root.w_reserved, "ROOT.wReserved", failure)) {
        return failure;
    }
    return root;
}

} // namespace ost2pst::ndb
