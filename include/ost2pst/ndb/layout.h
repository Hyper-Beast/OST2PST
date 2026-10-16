#pragma once

#include <cstddef>
#include <cstdint>

namespace ost2pst::ndb {

// Every constant here is a byte-layout fact and carries its [MS-PST] section in the adjacent
// comment; scripts/check_layers.sh enforces that. A constant without a citation does not belong.
//
// Two profiles share this file on purpose. The project READS an OST and WRITES a PST, and the two
// differ in page size, trailer size, and allocation granularity even though [MS-PST] documents only
// the PST one. Every OST constant cites the [MS-PST] section it diverges from; the measurements
// behind them are in DEVELOPMENT.md

// Which byte layout a file is using. [MS-PST] 2.2.2.7 / 2.2.2.8 describe kPst; kOst is the same
// NDB with larger pages and blocks.
enum class FileProfile {
    kOst,
    kPst,
};

// --- HEADER ([MS-PST] 2.2.2.1) ---
constexpr uint64_t kHeaderOffset = 0x0000;          // [MS-PST] 2.2.2.1 HEADER lives at absolute offset 0
constexpr uint64_t kHeaderSize = 564;               // [MS-PST] 2.2.2.1 HEADER (Unicode) is 564 bytes
constexpr uint64_t kDwMagicOffset = 0x000;          // [MS-PST] 2.2.2.1 dwMagic
constexpr uint32_t kDwMagicValue = 0x4E444221;      // [MS-PST] 2.2.2.1 dwMagic MUST be 0x4E444221 "!BDN"
constexpr uint64_t kDwCRCPartialOffset = 0x004;     // [MS-PST] 2.2.2.1 dwCRCPartial
constexpr uint64_t kCrcPartialStart = 0x008;        // [MS-PST] 2.2.2.1 dwCRCPartial starts at wMagicClient
constexpr uint64_t kCrcPartialLength = 471;         // [MS-PST] 2.2.2.1 dwCRCPartial covers 471 bytes
constexpr uint64_t kWMagicClientOffset = 0x008;     // [MS-PST] 2.2.2.1 wMagicClient
constexpr uint8_t kWMagicClientS = 0x53;            // [MS-PST] 2.2.2.1 wMagicClient[0] is 0x53 'S'
constexpr uint8_t kWMagicClientM = 0x4D;            // [MS-PST] 2.2.2.1 wMagicClient MUST be "SM"
constexpr uint8_t kWMagicClientO = 0x4F;            // [MS-PST] 2.2.2.1 OST files write "SO" instead of "SM"
constexpr uint64_t kWVerOffset = 0x00A;             // [MS-PST] 2.2.2.1 wVer
constexpr uint16_t kMinUnicodeVer = 23;             // [MS-PST] 2.2.2.1 Unicode wVer MUST be >= 23
constexpr uint16_t kWipVer = 37;                    // [MS-PST] 2.2.2.1 wVer 37 means WIP-protected
constexpr uint64_t kWVerClientOffset = 0x00C;       // [MS-PST] 2.2.2.1 wVerClient (informational only)
constexpr uint64_t kBPlatformCreateOffset = 0x00E;  // [MS-PST] 2.2.2.1 bPlatformCreate
constexpr uint64_t kBPlatformAccessOffset = 0x00F;  // [MS-PST] 2.2.2.1 bPlatformAccess
constexpr uint8_t kPlatformId = 0x01;               // [MS-PST] 2.2.2.1 bPlatformCreate/Access MUST be 0x01
constexpr uint64_t kBidNextPOffset = 0x020;         // [MS-PST] 2.2.2.1 bidNextP
constexpr uint64_t kRgnidOffset = 0x02C;            // [MS-PST] 2.2.2.1 rgnid
constexpr uint64_t kRgnidCount = 32;                // [MS-PST] 2.2.2.1 rgnid[32]
constexpr uint64_t kRootOffset = 0x0B4;             // [MS-PST] 2.2.2.1 HEADER.ROOT is embedded in the header
constexpr uint64_t kRootSize = 72;                  // [MS-PST] 2.2.2.5 ROOT (Unicode) is 72 bytes
constexpr uint64_t kDwAlignOffset = 0x0FC;          // [MS-PST] 2.2.2.1 dwAlign MUST be 0
constexpr uint64_t kRgbFmOffset = 0x100;            // [MS-PST] 2.2.2.1 rgbFM (deprecated)
constexpr uint64_t kRgbFpOffset = 0x180;            // [MS-PST] 2.2.2.1 rgbFP (deprecated)
constexpr uint64_t kDeprecatedMapBytes = 128;       // [MS-PST] 2.2.2.1 rgbFM and rgbFP are 128 bytes each
constexpr uint64_t kBSentinelOffset = 0x200;        // [MS-PST] 2.2.2.1 bSentinel
constexpr uint8_t kBSentinelValue = 0x80;           // [MS-PST] 2.2.2.1 bSentinel MUST be 0x80
constexpr uint64_t kBCryptMethodOffset = 0x201;     // [MS-PST] 2.2.2.1 bCryptMethod
constexpr uint8_t kCryptMethodNone = 0x00;          // [MS-PST] 2.2.2.1 bCryptMethod 0x00 = no obfuscation
constexpr uint64_t kBidNextBOffset = 0x204;         // [MS-PST] 2.2.2.1 bidNextB
constexpr uint64_t kDwCRCFullOffset = 0x20C;        // [MS-PST] 2.2.2.1 dwCRCFull
constexpr uint64_t kCrcFullStart = 0x008;           // [MS-PST] 2.2.2.1 dwCRCFull starts at wMagicClient
constexpr uint64_t kCrcFullLength = 516;            // [MS-PST] 2.2.2.1 dwCRCFull covers through bidNextB inclusive
constexpr uint64_t kRgbReserved2Offset = 0x210;     // [MS-PST] 2.2.2.1 rgbReserved2 (3 bytes)
constexpr uint64_t kBReservedOffset = 0x213;        // [MS-PST] 2.2.2.1 bReserved
constexpr uint64_t kRgbReserved3Offset = 0x214;     // [MS-PST] 2.2.2.1 rgbReserved3 (32 bytes)
constexpr uint64_t kRgbReserved3Bytes = 32;         // [MS-PST] 2.2.2.1 rgbReserved3 is 32 bytes

// --- ROOT ([MS-PST] 2.2.2.5), offsets relative to the ROOT record ---
constexpr uint64_t kRootDwReservedOffset = 0;       // [MS-PST] 2.2.2.5 dwReserved
constexpr uint64_t kRootIbFileEofOffset = 4;        // [MS-PST] 2.2.2.5 ibFileEof is the file size in bytes
constexpr uint64_t kRootIbAMapLastOffset = 12;      // [MS-PST] 2.2.2.5 ibAMapLast is the last AMap page offset
constexpr uint64_t kRootCbAMapFreeOffset = 20;      // [MS-PST] 2.2.2.5 cbAMapFree
constexpr uint64_t kRootCbPMapFreeOffset = 28;      // [MS-PST] 2.2.2.5 cbPMapFree
constexpr uint64_t kRootNbtBrefOffset = 36;         // [MS-PST] 2.2.2.5 BREFNBT
constexpr uint64_t kRootBbtBrefOffset = 52;         // [MS-PST] 2.2.2.5 BREFBBT
constexpr uint64_t kRootFAMapValidOffset = 68;      // [MS-PST] 2.2.2.5 fAMapValid
constexpr uint64_t kRootBReservedOffset = 69;       // [MS-PST] 2.2.2.5 bReserved
constexpr uint64_t kRootWReservedOffset = 70;       // [MS-PST] 2.2.2.5 wReserved
constexpr uint8_t kFAMapInvalid = 0x00;             // [MS-PST] 2.2.2.5 INVALID_AMAP
constexpr uint8_t kFAMapValid1 = 0x01;              // [MS-PST] 2.2.2.5 VALID_AMAP1 (deprecated)
constexpr uint8_t kFAMapValid2 = 0x02;              // [MS-PST] 2.2.2.5 VALID_AMAP2

// --- NID arithmetic ([MS-PST] 2.2.2.2) ---
constexpr uint64_t kNidIndexShift = 5;              // [MS-PST] 2.2.2.2 NID = (nidIndex << 5) | nidType
constexpr uint64_t kNidTypeMask = 0x1F;             // [MS-PST] 2.2.2.2 nidType is the low 5 bits

// --- BID arithmetic ([MS-PST] 2.2.2.2) ---
// A block BID reserves its two least significant bits for flags, so bidIndex increments by one and the
// BID itself by four. Page BIDs ([MS-PST] 2.2.2.7) use all the bits instead.
constexpr uint64_t kBidReservedBit = 0x1;           // [MS-PST] 2.2.2.2 bit A: reserved; readers MUST treat it as zero before looking a BID up in the BBT
constexpr uint64_t kBidInternalBit = 0x2;           // [MS-PST] 2.2.2.2 bit B: MUST be 1 when the block is Internal, i.e. a block that names other blocks instead of holding data
constexpr uint64_t kBidFlagMask = 0x3;              // [MS-PST] 2.2.2.2 the two least significant bits of a block BID are flags

// [MS-PST] 2.2.2.2 bit A is the only bit a reader clears: "Readers MUST ignore this bit and treat it as
// zero before looking up the BID from the BBT". The internal bit stays part of the value the BBT stores,
// which is also what the libpff notes say ("clear the first LSB in the identifier",
// libpff format notes (see THIRD_PARTY_NOTICES.txt):647 and :758).
constexpr uint64_t bid_lookup_key(uint64_t bid) { return bid & ~kBidReservedBit; }     // [MS-PST] 2.2.2.2 bit A cleared, bit B kept: the key the BBT is searched with
constexpr uint64_t bid_index(uint64_t bid) { return bid & ~kBidFlagMask; }             // [MS-PST] 2.2.2.2 bidIndex is the BID with both flag bits removed
constexpr bool bid_is_internal(uint64_t bid) { return (bid & kBidInternalBit) != 0; }  // [MS-PST] 2.2.2.2 bit B: 1 means an internal block ([MS-PST] 2.2.2.8.3)

// --- BREF ([MS-PST] 2.2.2.4) ---
constexpr uint64_t kBRefSize = 16;                  // [MS-PST] 2.2.2.4 BREF (Unicode) is bid(8) + ib(8)
constexpr uint64_t kBRefBidOffset = 0;              // [MS-PST] 2.2.2.4 BREF.bid
constexpr uint64_t kBRefIbOffset = 8;               // [MS-PST] 2.2.2.4 BREF.ib

// --- Page types ([MS-PST] 2.2.2.7.1 ptype) ---
constexpr uint8_t kPageTypeBBT = 0x80;              // [MS-PST] 2.2.2.7.1 ptypeBBT Block BTree page
constexpr uint8_t kPageTypeNBT = 0x81;              // [MS-PST] 2.2.2.7.1 ptypeNBT Node BTree page
constexpr uint8_t kPageTypeFMap = 0x82;             // [MS-PST] 2.2.2.7.1 ptypeFMap Free Map page
constexpr uint8_t kPageTypePMap = 0x83;             // [MS-PST] 2.2.2.7.1 ptypePMap Allocation Page Map
constexpr uint8_t kPageTypeAMap = 0x84;             // [MS-PST] 2.2.2.7.1 ptypeAMap Allocation Map page
constexpr uint8_t kPageTypeFPMap = 0x85;            // [MS-PST] 2.2.2.7.1 ptypeFPMap Free Page Map page
constexpr uint8_t kPageTypeDList = 0x86;            // [MS-PST] 2.2.2.7.1 ptypeDL Density List page
constexpr uint8_t kFirstPageType = 0x80;            // [MS-PST] 2.2.2.7.1 lowest ptype a page may carry
constexpr uint8_t kLastPageType = 0x86;             // [MS-PST] 2.2.2.7.1 highest ptype a page may carry

// --- Trailer field offsets shared by both profiles ([MS-PST] 2.2.2.7.1 / 2.2.2.8.1) ---
// OST narrows bid to 4 bytes and zeroes the 4 bytes after it, so a 64-bit read at the spec's bid
// offset yields the same value for both profiles.
constexpr uint64_t kPageTrailerPtypeOffset = 0;       // [MS-PST] 2.2.2.7.1 ptype
constexpr uint64_t kPageTrailerPtypeRepeatOffset = 1; // [MS-PST] 2.2.2.7.1 ptypeRepeat
constexpr uint64_t kPageTrailerWSigOffset = 2;        // [MS-PST] 2.2.2.7.1 wSig
constexpr uint64_t kPageTrailerCrcOffset = 4;         // [MS-PST] 2.2.2.7.1 dwCRC
constexpr uint64_t kPageTrailerBidOffset = 8;         // [MS-PST] 2.2.2.7.1 bid (Unicode order)
constexpr uint64_t kBlockTrailerCbOffset = 0;         // [MS-PST] 2.2.2.8.1 cb
constexpr uint64_t kBlockTrailerWSigOffset = 2;       // [MS-PST] 2.2.2.8.1 wSig
constexpr uint64_t kBlockTrailerCrcOffset = 4;        // [MS-PST] 2.2.2.8.1 dwCRC
constexpr uint64_t kBlockTrailerBidOffset = 8;        // [MS-PST] 2.2.2.8.1 bid

// --- OST-only trailer fields ([MS-PST] 2.2.2.7.1 / 2.2.2.8.1 bytes past the 16-byte spec trailer) ---
// Measured on the sample across all 198,111 leaf BBT entries and the blocks they index
// (DEVELOPMENT.md): +16 is 2 on every
// block, +18 equals the block's uncompressed data length (== cb on the 71,584 raw blocks, == the zlib
// output length on the 126,527 compressed ones), +20..23 are zero. libpff's "The 64-bit 4k page block"
// footer (libpff format notes (see THIRD_PARTY_NOTICES.txt):1148-1167) names the same slots 2 / "Uncompressed block
// data size" / "Unknown (empty values)".
constexpr uint64_t kOstPageTrailerFlagOffset = 16;  // [MS-PST] 2.2.2.7.1: OST writes 1 here on every page
constexpr uint64_t kOstBlockTrailerTypOffset = 16;  // [MS-PST] 2.2.2.8.1: OST writes 2 (a block) here on every block
constexpr uint64_t kOstBlockTrailerUncompressedCbOffset = 18; // [MS-PST] 2.2.2.8.1: OST writes the uncompressed data length here

// --- BTree entry field offsets shared by both profiles ([MS-PST] 2.2.2.7.7.2 .. 2.2.2.7.7.4) ---
// OST narrows each key/id to 4 bytes and zeroes the pad after it, so the spec's Unicode offsets
// decode both profiles with the same 64-bit reads.
// On the measured OST the two slots past cb do not say what [MS-PST] names them.
//
// +18 holds the block's uncompressed data length (see the OST-only trailer block above): 198,111 of
// 198,111 leaf entries match the length their block's trailer announces, 71,584 of them as cb and
// 126,527 as the inflated length. That reading is settled by measurement.
//
// +20 is [MS-PST] 2.2.2.7.7.3 dwPadding, which MUST be zero, and it is non-zero on 197,742 entries. It
// behaves like a reference count -- 1 + the references 2.2.2.7.7.3.1 lists -- on 197,178 of 198,111
// entries (99.53%) once the reserved bit is cleared and only references from blocks reachable from an
// NBTENTRY are counted, but it is not explained: 369 entries sit 1 below, 564 sit 1..9 above, 743
// references name a BID the BBT does not index, and the libpff notes call this slot "File offset of the
// data allocation table" (libpff format notes (see THIRD_PARTY_NOTICES.txt):726-740). Its meaning is UNRESOLVED; the
// value is carried raw and never used as a reference count.
// (.../repair-2026-10-11/r1-r2-findings.md; the earlier 195,116 figure counted references from blocks
// nothing reaches.)
constexpr uint64_t kBtEntryKeyOffset = 0;             // [MS-PST] 2.2.2.7.7.2 BTENTRY.btkey
constexpr uint64_t kBtEntryBidOffset = 8;             // [MS-PST] 2.2.2.7.7.2 BTENTRY.bid
constexpr uint64_t kBtEntryIbOffset = 16;             // [MS-PST] 2.2.2.7.7.2 BTENTRY.ib
constexpr uint64_t kBbtEntryBidOffset = 0;            // [MS-PST] 2.2.2.7.7.3 BBTENTRY BREF.bid
constexpr uint64_t kBbtEntryIbOffset = 8;             // [MS-PST] 2.2.2.7.7.3 BBTENTRY BREF.ib
constexpr uint64_t kBbtEntryCbOffset = 16;            // [MS-PST] 2.2.2.7.7.3 BBTENTRY.cb
constexpr uint64_t kBbtEntryCRefOffset = 18;          // [MS-PST] 2.2.2.7.7.3 BBTENTRY.cRef: on the measured OST this is the block's uncompressed data length, 198,111/198,111
constexpr uint64_t kBbtEntryOstCRefOffset = 20;       // [MS-PST] 2.2.2.7.7.3 BBTENTRY.dwPadding (MUST be zero): on the measured OST it is non-zero on 197,742 entries and its meaning is unresolved
constexpr uint64_t kNbtEntryNidOffset = 0;            // [MS-PST] 2.2.2.7.7.4 NBTENTRY.nid
constexpr uint64_t kNbtEntryBidDataOffset = 8;        // [MS-PST] 2.2.2.7.7.4 NBTENTRY.bidData
constexpr uint64_t kNbtEntryBidSubOffset = 16;        // [MS-PST] 2.2.2.7.7.4 NBTENTRY.bidSub
constexpr uint64_t kNbtEntryNidParentOffset = 24;     // [MS-PST] 2.2.2.7.7.4 NBTENTRY.nidParent
constexpr uint64_t kNbtEntrySize = 32;                // [MS-PST] 2.2.2.7.7.4 NBTENTRY (Unicode) is 32 bytes
constexpr uint64_t kBbtEntrySize = 24;                // [MS-PST] 2.2.2.7.7.3 BBTENTRY (Unicode) is 24 bytes
constexpr uint64_t kBtEntrySize = 24;                 // [MS-PST] 2.2.2.7.7.2 BTENTRY (Unicode) is 24 bytes

// --- OST profile: measured on the sample, see DEVELOPMENT.md ---
constexpr uint64_t kOstPageSize = 4096;               // [MS-PST] 2.2.2.7: OST pages are 4096 bytes, not 512
constexpr uint64_t kOstPageTrailerSize = 24;          // [MS-PST] 2.2.2.7.1: OST PAGETRAILER is 24 bytes, not 16
constexpr uint64_t kOstBtFooterBytes = 16;            // [MS-PST] 2.2.2.7.7.1: OST footer is 16 bytes wide
constexpr uint64_t kOstBtCEntMaxDelta = 2;            // [MS-PST] 2.2.2.7.7.1: OST cEntMax is a 2-byte field
constexpr uint64_t kOstBtCbEntDelta = 4;              // [MS-PST] 2.2.2.7.7.1: OST cbEnt follows the two counts
constexpr uint64_t kOstBtCLevelDelta = 5;             // [MS-PST] 2.2.2.7.7.1: OST cLevel follows cbEnt
constexpr uint64_t kOstCountWidth = 2;                // [MS-PST] 2.2.2.7.7.1: OST cEnt/cEntMax are 2 bytes wide
constexpr uint64_t kOstBlockGranularity = 512;        // [MS-PST] 2.2.2.8: OST blocks are 512-byte aligned
constexpr uint64_t kOstBlockTrailerSize = 24;         // [MS-PST] 2.2.2.8.1: OST BLOCKTRAILER is 24 bytes, not 16
constexpr uint64_t kOstBlockMaxSize = 65536;          // [MS-PST] 2.2.2.8: OST block footprint caps at 128 units
constexpr uint64_t kOstBlockMaxUnits = 128;           // [MS-PST] 2.2.2.8: 65536 / 512 allocation units
constexpr uint16_t kOstBlockMaxCb = 65512;            // [MS-PST] 2.2.2.8: OST capacity is footprint minus trailer
constexpr uint64_t kOstAmapFirstOffset = 0x22000;     // [MS-PST] 2.2.2.7.2: OST's first AMap follows its DList page
constexpr uint64_t kOstAmapInterval = 16678912;       // [MS-PST] 2.2.2.7.2: 4072 bit bytes * 8 units * 512 bytes
constexpr uint64_t kOstDlistOffset = 0x21000;         // [MS-PST] 2.2.2.7.4: OST's single DList page

// --- PST profile: [MS-PST] as written, the shape the M1 writer emits ---
constexpr uint64_t kPstPageSize = 512;                // [MS-PST] 2.2.2.7 a page is 512 bytes
constexpr uint64_t kPstPageTrailerSize = 16;          // [MS-PST] 2.2.2.7.1 PAGETRAILER (Unicode) is 16 bytes
constexpr uint64_t kPstBtFooterBytes = 8;             // [MS-PST] 2.2.2.7.7.1 cEnt, cEntMax, cbEnt, cLevel, dwPadding
constexpr uint64_t kPstBtCEntMaxDelta = 1;            // [MS-PST] 2.2.2.7.7.1 cEntMax
constexpr uint64_t kPstBtCbEntDelta = 2;              // [MS-PST] 2.2.2.7.7.1 cbEnt
constexpr uint64_t kPstBtCLevelDelta = 3;             // [MS-PST] 2.2.2.7.7.1 cLevel
constexpr uint64_t kPstCountWidth = 1;                // [MS-PST] 2.2.2.7.7.1 cEnt and cEntMax are 1 byte wide
constexpr uint64_t kPstBlockGranularity = 64;         // [MS-PST] 2.2.2.8 blocks are 64-byte multiples and aligned
constexpr uint64_t kPstBlockTrailerSize = 16;         // [MS-PST] 2.2.2.8.1 BLOCKTRAILER (Unicode) is 16 bytes
constexpr uint64_t kPstBlockMaxSize = 8192;           // [MS-PST] 2.2.2.8 maximum block size is 8192 bytes
constexpr uint64_t kPstBlockMaxUnits = 128;           // [MS-PST] 2.2.2.8 8192 / 64 allocation units
constexpr uint16_t kPstBlockMaxCb = 8176;             // [MS-PST] 2.2.2.8 capacity is block size minus trailer
constexpr uint64_t kPstAmapFirstOffset = 0x4400;      // [MS-PST] 2.2.2.7.2 first AMap at absolute 0x4400
constexpr uint64_t kPstAmapInterval = 253952;         // [MS-PST] 2.2.2.7.2 an AMap maps 496 * 8 * 64 bytes
constexpr uint64_t kPstDlistOffset = 0x4200;          // [MS-PST] 2.2.2.7.4 at most one DList, at absolute 0x4200

// [MS-PST] 2.2.2.7.2: an AMap maps itself, so its first bit byte is 0xFF and it covers its own page.
constexpr uint8_t kAmapSelfMapByte = 0xFF;            // [MS-PST] 2.2.2.7.2 first bit byte is 0xFF: an AMap maps itself
constexpr uint64_t kAmapSelfUnits = 8;                // [MS-PST] 2.2.2.7.2 an AMap occupies the first page of its region

// --- Profile selectors. Each one is the only place a profile difference is allowed to appear. ---
constexpr uint64_t page_size(FileProfile profile) {                // [MS-PST] 2.2.2.7 page size
    return profile == FileProfile::kOst ? kOstPageSize : kPstPageSize;
}
constexpr uint64_t page_trailer_size(FileProfile profile) {        // [MS-PST] 2.2.2.7.1 PAGETRAILER size
    return profile == FileProfile::kOst ? kOstPageTrailerSize : kPstPageTrailerSize;
}
constexpr uint64_t page_data_bytes(FileProfile profile) {          // [MS-PST] 2.2.2.7.1 dwCRC covers page minus trailer
    return page_size(profile) - page_trailer_size(profile);
}
constexpr uint64_t bt_trailer_offset(FileProfile profile) {        // [MS-PST] 2.2.2.7.7.1 pageTrailer ends the page
    return page_data_bytes(profile);
}
constexpr uint64_t bt_footer_bytes(FileProfile profile) {          // [MS-PST] 2.2.2.7.7.1 BTPAGE footer width
    return profile == FileProfile::kOst ? kOstBtFooterBytes : kPstBtFooterBytes;
}
constexpr uint64_t bt_entries_bytes(FileProfile profile) {         // [MS-PST] 2.2.2.7.7.1 rgentries ends at the footer
    return bt_trailer_offset(profile) - bt_footer_bytes(profile);
}
constexpr uint64_t bt_count_width(FileProfile profile) {           // [MS-PST] 2.2.2.7.7.1 cEnt and cEntMax width
    return profile == FileProfile::kOst ? kOstCountWidth : kPstCountWidth;
}
constexpr uint64_t bt_c_ent_offset(FileProfile profile) {          // [MS-PST] 2.2.2.7.7.1 cEnt starts the footer
    return bt_entries_bytes(profile);
}
constexpr uint64_t bt_c_ent_max_offset(FileProfile profile) {      // [MS-PST] 2.2.2.7.7.1 cEntMax follows cEnt
    return bt_entries_bytes(profile) + (profile == FileProfile::kOst ? kOstBtCEntMaxDelta : kPstBtCEntMaxDelta);
}
constexpr uint64_t bt_cb_ent_offset(FileProfile profile) {         // [MS-PST] 2.2.2.7.7.1 cbEnt follows cEntMax
    return bt_entries_bytes(profile) + (profile == FileProfile::kOst ? kOstBtCbEntDelta : kPstBtCbEntDelta);
}
constexpr uint64_t bt_c_level_offset(FileProfile profile) {        // [MS-PST] 2.2.2.7.7.1 cLevel follows cbEnt
    return bt_entries_bytes(profile) + (profile == FileProfile::kOst ? kOstBtCLevelDelta : kPstBtCLevelDelta);
}
constexpr uint64_t block_granularity(FileProfile profile) {        // [MS-PST] 2.2.2.8 allocation granularity
    return profile == FileProfile::kOst ? kOstBlockGranularity : kPstBlockGranularity;
}
constexpr uint64_t block_trailer_size(FileProfile profile) {       // [MS-PST] 2.2.2.8.1 BLOCKTRAILER size
    return profile == FileProfile::kOst ? kOstBlockTrailerSize : kPstBlockTrailerSize;
}
constexpr uint64_t block_max_size(FileProfile profile) {           // [MS-PST] 2.2.2.8 maximum block footprint
    return profile == FileProfile::kOst ? kOstBlockMaxSize : kPstBlockMaxSize;
}
constexpr uint16_t block_max_cb(FileProfile profile) {             // [MS-PST] 2.2.2.8 maximum raw data bytes
    return profile == FileProfile::kOst ? kOstBlockMaxCb : kPstBlockMaxCb;
}
constexpr uint64_t page_units(FileProfile profile) {               // [MS-PST] 2.2.2.7 allocation units per page
    return page_size(profile) / block_granularity(profile);
}
constexpr uint64_t amap_first_offset(FileProfile profile) {        // [MS-PST] 2.2.2.7.2 absolute offset of the first AMap
    return profile == FileProfile::kOst ? kOstAmapFirstOffset : kPstAmapFirstOffset;
}
constexpr uint64_t amap_interval(FileProfile profile) {            // [MS-PST] 2.2.2.7.2 bytes mapped by one AMap
    return profile == FileProfile::kOst ? kOstAmapInterval : kPstAmapInterval;
}
constexpr uint64_t amap_units(FileProfile profile) {               // [MS-PST] 2.2.2.7.2 one bit byte maps 8 allocation units
    return amap_interval(profile) / block_granularity(profile);
}
constexpr uint64_t dlist_offset(FileProfile profile) {             // [MS-PST] 2.2.2.7.4 absolute offset of the DList
    return profile == FileProfile::kOst ? kOstDlistOffset : kPstDlistOffset;
}

// [MS-PST] 2.2.2.8: a footprint is the raw size plus the trailer, rounded up to the granularity.
constexpr uint64_t align_allocation(FileProfile profile, uint64_t value) { // [MS-PST] 2.2.2.8 64 or 512 byte rounding
    const uint64_t granularity = block_granularity(profile);
    return (value + (granularity - 1)) & ~(granularity - 1);
}

} // namespace ost2pst::ndb
