#include "ost2pst/ndb/profile.h"

#include <vector>

#include "ost2pst/ndb/trailer.h"
#include "ost2pst/util/crc32.h"

namespace ost2pst::ndb {

using util::ByteView;
using util::ErrorKind;
using util::make_error;
using util::Result;
using util::Status;

const char *file_profile_name(FileProfile profile) {
    return profile == FileProfile::kOst ? "OST" : "PST";
}

Result<FileProfile> detect_profile(const util::FileReader &file, uint64_t bbt_root_ib) {
    for (const FileProfile profile : {FileProfile::kOst, FileProfile::kPst}) {
        const uint64_t size = page_size(profile);
        if (bbt_root_ib > file.size() || file.size() - bbt_root_ib < size) {
            continue;
        }
        std::vector<uint8_t> page(static_cast<size_t>(size));
        Status io = file.read_at(bbt_root_ib, page.data(), page.size());
        if (!io) {
            return io.error();
        }
        const ByteView view(page.data(), page.size(), bbt_root_ib);
        Result<ByteView> window = view.sub(static_cast<size_t>(bt_trailer_offset(profile)),
                                           static_cast<size_t>(page_trailer_size(profile)));
        if (!window.ok()) {
            continue;
        }
        Result<PageTrailer> trailer = decode_page_trailer(window.value(), profile);
        if (!trailer.ok() || trailer.value().ptype != kPageTypeBBT) {
            continue;
        }
        // [MS-PST] 2.2.2.7.1: dwCRC covers the page minus the trailer, so only the profile with the
        // right page size can make the root page's stored CRC come out.
        Result<ByteView> data = view.sub(0, static_cast<size_t>(page_data_bytes(profile)));
        if (!data.ok() || util::crc32(data.value()) != trailer.value().dw_crc) {
            continue;
        }
        return profile;
    }
    return make_error(ErrorKind::kUnsupported, "BTPAGE.pageTrailer", bbt_root_ib, 0,
                      "no page layout makes the root BBT page dwCRC match");
}

} // namespace ost2pst::ndb
