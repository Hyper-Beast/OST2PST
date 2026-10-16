#pragma once

#include "ost2pst/util/status.h"

namespace ost2pst::ltp {

// Same decoder helper the ndb layer uses, kept per layer so ltp never reaches into ndb's internals
// (DEVELOPMENT.md). On failure the error keeps its offset and takes the
// spec's own RECORD.Field name, so a report names the record the reader can trust.
template <class T>
bool take(util::Result<T> read, T &destination, const char *field, util::DataError &failure) {
    if (read.ok()) {
        destination = read.value();
        return true;
    }
    failure = read.error();
    failure.field = field;
    return false;
}

} // namespace ost2pst::ltp
