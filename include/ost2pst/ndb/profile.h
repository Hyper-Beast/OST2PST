#pragma once

#include <string>

#include "ost2pst/ndb/layout.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/status.h"

namespace ost2pst::ndb {

const char *file_profile_name(FileProfile profile);

// The page and block sizes are the only structural difference between the two profiles, so the root
// BTree page decides which one a file uses: only the correct trailer offset yields a ptype of
// ptypeBBT together with a dwCRC that matches the page ([MS-PST] 2.2.2.7.7.1 / 2.2.2.7.1). The file
// extension is never consulted.
util::Result<FileProfile> detect_profile(const util::FileReader &file, uint64_t bbt_root_ib);

} // namespace ost2pst::ndb
