#pragma once

#include <cstdint>

namespace ost2pst::writer {

// Writer-only layout facts. Everything the reader already names lives in ndb/layout.h or ltp/layout.h
// and is used from there; this file holds only what the writer has to decide, and every constant
// carries the [MS-PST] section it comes from (scripts/check_layers.sh enforces that).

// [MS-PST] 2.3.1.2 puts a 12-byte HNHDR at the start of the first HN data block, and the spec's own
// sample HN (3.8) starts its first allocation at 0x0C, immediately after it (docs/reference/ms-pst.txt:
// 7412-7416). The writer packs its allocations the same way.
constexpr uint64_t kHnFirstAllocationOffset = 12; // [MS-PST] 2.3.1.2 + 3.8: allocations start right after the 12-byte HNHDR

// [MS-PST] 2.3.1.5: "There can be anywhere from 0 to 63 bytes of padding between the HNPAGEMAP and
// the block trailer", so a block whose data ends at the HNPAGEMAP is legal under 64-byte rounding.
constexpr uint64_t kMaxBlockPaddingBytes = 63; // [MS-PST] 2.3.1.5

// Conservative writer packing policy, not a format limit or a promise of FILL_LEVEL_EMPTY.
// Keep the existing allocation placement stable; heap.cpp computes fill levels separately
// against the 8176-byte data capacity, excluding the NDB trailer ([MS-PST] 2.2.2.8).
constexpr uint64_t kHeapPackingTargetBytes = 4608; // Policy below [MS-PST] 2.2.2.8 limit.

// [MS-PST] 2.3.4.4.2: a TC row holds a value inline when the type is fixed-size and 8 bytes or
// less; a variable-sized type, and any fixed type wider than 8 bytes, is stored behind an HNID
// instead.
constexpr uint64_t kTcInlineMaxFixedBytes = 8; // [MS-PST] 2.3.4.4.2: the TC stores 8-byte values inline, unlike a PC

// [MS-PST] 2.3.4.2: for variable-sized data cbData "is set to the size of an HNID", and 2.3.4.4.2 puts
// that HNID in the 4-byte rgdwData slot.
constexpr uint64_t kTcHnidSlotBytes = 4; // [MS-PST] 2.3.4.2 / 2.3.4.4.2: a variable-sized column is a 4-byte HNID slot

// [MS-PST] 2.3.4.4.2: a value reached through an HID is 3580 bytes or less; a longer one lives in the
// subnode, which a TC written into one data block does not have.
constexpr uint64_t kTcHeapValueMaxBytes = 3580; // [MS-PST] 2.3.4.4.2: HID (<= 3580 bytes)

// Where the writer's own allocation order lands when a TC fits one data block: heap.h numbers the nth
// allocation of a block as (n << 5), and 2.3.4.1 fixes only the first of them -- hidUserRoot points at
// the TC header "allocated from the heap with HID=0x20". The Row Matrix of the sample hierarchy TC sits
// at HID 0x80 (3.12), which is what the writer's order reaches once TCINFO, the RowIndex BTHHEADER and
// the TCROWID array come first. tc.cpp names the HIDs HeapImage actually gave, because a TC spread over
// several data blocks puts its later allocations behind a hidBlockIndex ([MS-PST] 2.3.1.1 / 2.3.1.6.2).
constexpr uint32_t kTcHidRowIndexBthHeader = 0x40; // [MS-PST] 2.3.4 + 2.3.4.3: the RowIndex BTHHEADER follows the TC header
constexpr uint32_t kTcHidRowIdArray = 0x60;        // [MS-PST] 2.3.4.3.1: the TCROWID array the RowIndex BTHHEADER points at
constexpr uint32_t kTcHidRowMatrix = 0x80;         // [MS-PST] 3.12: the sample Row Matrix is at HID 0x00000080

} // namespace ost2pst::writer

