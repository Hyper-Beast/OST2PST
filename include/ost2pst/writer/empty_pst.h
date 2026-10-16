#pragma once

#include "ost2pst/util/status.h"
#include "ost2pst/writer/store.h"

namespace ost2pst::writer {

// The minimum mailbox is one StorePlan, so its image is the emitter's image.
using EmptyPstImage = StoreImage;

// [MS-PST] 2.7.3.4: the minimum mailbox -- the Root Folder, IPM Subtree, Search Root, Spam Search
// Folder and Deleted Items, the six table templates of 2.7.3.3, an empty Name-to-ID Map, and an empty
// Search Management Queue and Search Activity List. Nothing is read from a file: every byte comes from
// the writer, and the CRCs come last so they cover the bytes they describe.
util::Result<EmptyPstImage> build_empty_pst();

} // namespace ost2pst::writer
