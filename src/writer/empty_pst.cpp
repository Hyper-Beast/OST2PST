// The minimum mailbox is the content build with nothing to convert, so the accepted M4 candidate and a
// content-bearing store come out of the same emitter (src/writer/content.cpp).
#include "ost2pst/writer/empty_pst.h"

#include <utility>

#include "ost2pst/writer/content.h"

namespace ost2pst::writer {

util::Result<EmptyPstImage> build_empty_pst() {
    util::Result<StoreOutcome> outcome = build_store(StoreRequest());
    if (!outcome.ok()) {
        return outcome.error();
    }
    return std::move(outcome.value().image);
}

} // namespace ost2pst::writer
