#pragma once

#include "ost2pst/util/status.h"

namespace ost2pst::ndb {

// One helper for every record decoder: read a little-endian field, and on failure rename the error
// field to the spec's own RECORD.Field so a report names the record the reader can trust
// (DEVELOPMENT.md).
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

} // namespace ost2pst::ndb
