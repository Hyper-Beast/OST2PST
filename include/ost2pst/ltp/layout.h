#pragma once

#include <cstddef>
#include <cstdint>

#include "ost2pst/ndb/layout.h"

namespace ost2pst::ltp {

// LTP byte layout ([MS-PST] 2.3). Every constant here is a byte-layout fact and carries its [MS-PST]
// section in the adjacent comment; scripts/check_layers.sh enforces that.
//
// The LTP layer sits on top of the NDB layer: the block an NBTENTRY.bidData names is a heap node (HN),
// and a BTree-on-Heap (BTH) lives inside an HN. Nothing here knows what a folder or a message is --
// that vocabulary belongs to msg (M3).

// --- HID ([MS-PST] 2.3.1.1; libpff "64-bit 4k page table value reference" :1549) ---
// A HID is a 32-bit hybrid: 5 type bits, then a 1-based allocation index, then the index of the data
// block the item lives in. The widths of the last two depend on the page profile: [MS-PST] 2.3.1.1 gives
// them for the 512-byte profile, the libpff 4k notes for the 4 KiB one. HID 0x20 is allocation 1 of data
// block 0 under either, which is where a client's root record normally sits.
constexpr uint64_t kHidTypeMask = 0x1F;               // [MS-PST] 2.3.1.1 hidType is the low 5 bits of a HID
constexpr uint64_t kHidTypeHid = 0x00;                // [MS-PST] 2.3.1.1 hidType MUST be 0 (NID_TYPE_HID) for a valid HID
constexpr uint64_t kHidIndexShift = 5;                // [MS-PST] 2.3.1.1 hidIndex sits above hidType in both profiles

// 512-byte page profile ([MS-PST] 2.3.1.1 as written): 11 allocation bits, 16 block bits.
constexpr uint64_t kHidIndexMask512 = 0x7FF;          // [MS-PST] 2.3.1.1 hidIndex is 11 bits and MUST NOT be zero
constexpr uint64_t kHidBlockIndexShift512 = 16;       // [MS-PST] 2.3.1.1 hidBlockIndex is the top 16 bits
constexpr uint64_t kHidBlockIndexMask512 = 0xFFFF;    // [MS-PST] 2.3.1.1 hidBlockIndex is a zero-based data block index

// 4 KiB page profile (libpff "64-bit 4k page table value reference" :1558-1559, which widens the same
// [MS-PST] 2.3.1.1 fields): 14 allocation bits, 13 block bits. Reading a 4 KiB file with the 512 widths
// yields an allocation 8 times too small and a block index 8 times too big -- that is exactly the
// discrepancy the withdrawn "hidBlockIndex counts 8,192-byte units" note was papering over.
constexpr uint64_t kHidIndexMask4k = 0x3FFF;          // [MS-PST] 2.3.1.1 4k profile: hidIndex is 14 bits (libpff :1558)
constexpr uint64_t kHidBlockIndexShift4k = 19;        // [MS-PST] 2.3.1.1 4k profile: hidBlockIndex starts at bit 19 (libpff :1559)
constexpr uint64_t kHidBlockIndexMask4k = 0x1FFF;     // [MS-PST] 2.3.1.1 4k profile: hidBlockIndex is 13 bits (libpff :1559)

// --- data tree jump table: XBLOCK and XXBLOCK ([MS-PST] 2.2.2.8.3.2.1 / 2.2.2.8.3.2.2) ---
// Data too big for one data block fans out through a jump table: an XBLOCK names the data blocks, an
// XXBLOCK names XBLOCKs. Both are the same 8-byte header followed by cEnt BIDs.
constexpr uint64_t kJumpTableTypeOffset = 0;          // [MS-PST] 2.2.2.8.3.2.1 btype: Block type
constexpr uint8_t kJumpTableType = 0x01;              // [MS-PST] 2.2.2.8.3.2.1 btype MUST be 0x01 to indicate an XBLOCK or XXBLOCK
constexpr uint64_t kJumpTableLevelOffset = 1;         // [MS-PST] 2.2.2.8.3.2.1 cLevel: which of the two jump tables this is
constexpr uint8_t kJumpTableLevelXblock = 0x01;       // [MS-PST] 2.2.2.8.3.2.1 cLevel MUST be 0x01 for an XBLOCK, whose rgbid references data blocks
constexpr uint8_t kJumpTableLevelXxblock = 0x02;      // [MS-PST] 2.2.2.8.3.2.2 cLevel MUST be 0x02 for an XXBLOCK, whose rgbid references XBLOCKs
constexpr uint64_t kJumpTableCountOffset = 2;         // [MS-PST] 2.2.2.8.3.2.1 cEnt: the count of BID entries in the jump table
constexpr uint64_t kJumpTableTotalOffset = 4;         // [MS-PST] 2.2.2.8.3.2.1 lcbTotal: total bytes of the data the jump table covers
constexpr uint64_t kJumpTableHeaderSize = 8;          // [MS-PST] 2.2.2.8.3.2.1 btype cLevel cEnt lcbTotal come before rgbid
constexpr uint64_t kJumpTableBidSize = 8;             // [MS-PST] 2.2.2.8.3.2.1 a rgbid entry is 8 bytes in a Unicode PST
constexpr uint64_t kJumpTableMaxEntries = 8192;       // [MS-PST] 2.2.2.8.3.2.1 cEnt is 2 bytes and one XBLOCK has to fit in a data block

// --- data tree work caps ([MS-PST] 2.2.2.8.3.2 / 2.3.1.6.2) ---
// A multi-block heap node numbers its data blocks from zero and a HID reaches one of them through
// hidBlockIndex ([MS-PST] 2.3.1.6.2 / 2.3.1.1), so a node's data tree cannot hold more blocks than that
// field can name. Measured widest tree on the sample: 394 data blocks under one XBLOCK.
constexpr uint64_t kDataTreeMaxBlocks512 = kHidBlockIndexMask512 + 1; // [MS-PST] 2.3.1.1 512 profile: hidBlockIndex is 16 bits, so a node can address at most 65536 data blocks
constexpr uint64_t kDataTreeMaxBlocks4k = kHidBlockIndexMask4k + 1;   // [MS-PST] 2.3.1.1 4k profile: hidBlockIndex is 13 bits (libpff :1559), so at most 8192 data blocks
constexpr uint64_t kDataTreeMaxTableLevels = 2;                       // [MS-PST] 2.2.2.8.3.2.2 an XXBLOCK names XBLOCKs and an XBLOCK names data blocks, so two table levels reach the data
constexpr uint64_t data_tree_max_blocks(ndb::FileProfile profile) {   // [MS-PST] 2.3.1.1 the hidBlockIndex width is the page profile's
    return profile == ndb::FileProfile::kOst ? kDataTreeMaxBlocks4k : kDataTreeMaxBlocks512;
}

// --- HN block headers ([MS-PST] 2.3.1.3 / 2.3.1.4 / 2.3.1.6.2) ---
// In a multi-block HN the first block carries the HNHDR, blocks 1-7 the 2-byte HNPAGEHDR because the
// HNHDR's eight fill level slots cover them, and block 8 then every 128th block the 66-byte HNBITMAPHDR.
constexpr uint64_t kHnPageHeaderSize = 2;             // [MS-PST] 2.3.1.3 HNPAGEHDR is ibHnpm alone
constexpr uint64_t kHnBitmapFillLevelBytes = 64;      // [MS-PST] 2.3.1.4 HNBITMAPHDR.rgbFillLevel is 128 4-bit fill levels
constexpr uint64_t kHnBitmapHeaderSize = 66;          // [MS-PST] 2.3.1.4 HNBITMAPHDR is ibHnpm followed by rgbFillLevel
constexpr uint64_t kHnFillLevelSlots = 8;             // [MS-PST] 2.3.1.6.2 the HNHDR's eight Fill Level Map slots cover blocks 0 through 7
constexpr uint64_t kHnBitmapSlots = 128;              // [MS-PST] 2.3.1.6.2 an HNBITMAPHDR's 128 slots cover 128 blocks
constexpr uint64_t kHnBitmapFirstBlock = 8;           // [MS-PST] 2.3.1.6.2 the eighth block is the first one needing its own Fill Level Map

// --- HNHDR ([MS-PST] 2.3.1.2) ---
constexpr uint64_t kHnHeaderOffset = 0;               // [MS-PST] 2.3.1.2 HNHDR resides at the start of the first HN data block
constexpr uint64_t kHnHeaderSize = 12;                // [MS-PST] 2.3.1.2 HNHDR is ibHnpm bSig bClientSig hidUserRoot rgbFillLevel
constexpr uint64_t kHnIbHnpmOffset = 0;               // [MS-PST] 2.3.1.2 ibHnpm: HNPAGEMAP offset relative to the HNHDR
constexpr uint64_t kHnSigOffset = 2;                  // [MS-PST] 2.3.1.2 bSig
constexpr uint8_t kHnSignature = 0xEC;                // [MS-PST] 2.3.1.2 bSig MUST be 0xEC to indicate an HN
constexpr uint64_t kHnClientSigOffset = 3;            // [MS-PST] 2.3.1.2 bClientSig
constexpr uint64_t kHnUserRootOffset = 4;             // [MS-PST] 2.3.1.2 hidUserRoot: HID of the client root record
constexpr uint64_t kHnFillLevelOffset = 8;            // [MS-PST] 2.3.1.2 rgbFillLevel: eight 4-bit fill levels
constexpr uint64_t kHnFillLevelBytes = 4;             // [MS-PST] 2.3.1.2 rgbFillLevel is 4 bytes

// bClientSig values ([MS-PST] 2.3.1.2). Every other value is reserved and MUST NOT be used.
constexpr uint8_t kClientSigReserved1 = 0x6C;         // [MS-PST] 2.3.1.2 bTypeReserved1
constexpr uint8_t kClientSigTc = 0x7C;                // [MS-PST] 2.3.1.2 bTypeTC Table Context (TC/HN)
constexpr uint8_t kClientSigReserved2 = 0x8C;         // [MS-PST] 2.3.1.2 bTypeReserved2
constexpr uint8_t kClientSigReserved3 = 0x9C;         // [MS-PST] 2.3.1.2 bTypeReserved3
constexpr uint8_t kClientSigReserved4 = 0xA5;         // [MS-PST] 2.3.1.2 bTypeReserved4
constexpr uint8_t kClientSigReserved5 = 0xAC;         // [MS-PST] 2.3.1.2 bTypeReserved5
constexpr uint8_t kClientSigBth = 0xB5;               // [MS-PST] 2.3.1.2 bTypeBTH BTree-on-Heap
constexpr uint8_t kClientSigPc = 0xBC;                // [MS-PST] 2.3.1.2 bTypePC Property Context (PC/BTH)
constexpr uint8_t kClientSigReserved6 = 0xCC;         // [MS-PST] 2.3.1.2 bTypeReserved6

// --- HNPAGEMAP ([MS-PST] 2.3.1.5) ---
constexpr uint64_t kHnPageMapCAllocOffset = 0;        // [MS-PST] 2.3.1.5 cAlloc: allocation count
constexpr uint64_t kHnPageMapCFreeOffset = 2;         // [MS-PST] 2.3.1.5 cFree: freed-item count
constexpr uint64_t kHnPageMapTableOffset = 4;         // [MS-PST] 2.3.1.5 rgibAlloc follows the two counts
constexpr uint64_t kHnPageMapEntrySize = 2;           // [MS-PST] 2.3.1.5 each rgibAlloc entry is a WORD offset
constexpr uint64_t kHnPageMapHeaderSize = 4;          // [MS-PST] 2.3.1.5 the two counts precede rgibAlloc

// --- BTHHEADER ([MS-PST] 2.3.2.1) ---
constexpr uint64_t kBthHeaderSize = 8;                // [MS-PST] 2.3.2.1 BTHHEADER is bType cbKey cbEnt bIdxLevels hidRoot
constexpr uint64_t kBthTypeOffset = 0;                // [MS-PST] 2.3.2.1 bType
constexpr uint8_t kBthType = 0xB5;                    // [MS-PST] 2.3.2.1 bType MUST be bTypeBTH, which 2.3.1.2 fixes at 0xB5
constexpr uint64_t kBthCbKeyOffset = 1;               // [MS-PST] 2.3.2.1 cbKey: key size in bytes
constexpr uint64_t kBthCbEntOffset = 2;               // [MS-PST] 2.3.2.1 cbEnt: data size in bytes
constexpr uint64_t kBthIdxLevelsOffset = 3;           // [MS-PST] 2.3.2.1 bIdxLevels: intermediate index depth, zero-based
constexpr uint64_t kBthHidRootOffset = 4;             // [MS-PST] 2.3.2.1 hidRoot: HID of the entry array, 0 when the BTH is empty
constexpr uint8_t kBthCbKeyMin = 2;                   // [MS-PST] 2.3.2.1 cbKey MUST be 2, 4, 8 or 16
constexpr uint8_t kBthCbKeyMax = 16;                  // [MS-PST] 2.3.2.1 cbKey MUST be 2, 4, 8 or 16
constexpr uint8_t kBthCbEntMin = 1;                   // [MS-PST] 2.3.2.1 cbEnt MUST be greater than zero
constexpr uint8_t kBthCbEntMax = 32;                  // [MS-PST] 2.3.2.1 cbEnt MUST be 32 or less
constexpr uint8_t kBthMaxIdxLevels = 8;               // [MS-PST] 2.3.2.2: index levels are walked one heap item per record, so a deeper tree is treated as corrupt

// --- BTH records ([MS-PST] 2.3.2.2 / 2.3.2.3) ---
constexpr uint64_t kBthHidNextLevelSize = 4;          // [MS-PST] 2.3.2.2 hidNextLevel is 4 bytes at the end of an index record
constexpr uint64_t kBthMaxRecords = 1000000;          // [MS-PST] 2.3.2.3 the record count comes from the allocation size, so a corrupt size needs a hard cap

// --- Property Context ([MS-PST] 2.3.3.3) ---
constexpr uint8_t kPcCbKey = 2;                       // [MS-PST] 2.3.3.3 a PC BTH has cbKey 2: the key is wPropId
constexpr uint8_t kPcCbEnt = 6;                       // [MS-PST] 2.3.3.3 a PC BTH has cbEnt 6: wPropType then dwValueHnid
constexpr uint64_t kPcRecordSize = 8;                 // [MS-PST] 2.3.3.3 a PC record is cbKey + cbEnt = 8 bytes
constexpr uint64_t kPcPropIdOffset = 0;               // [MS-PST] 2.3.3.3 wPropId is the record key
constexpr uint64_t kPcPropTypeOffset = 2;             // [MS-PST] 2.3.3.3 wPropType starts the record data
constexpr uint64_t kPcValueHnidOffset = 4;            // [MS-PST] 2.3.3.3 dwValueHnid follows wPropType
constexpr uint64_t kPcValueInlineMax = 4;             // [MS-PST] 2.3.3.3 a fixed-size type of 4 bytes or less is stored inline in dwValueHnid
constexpr uint64_t kPcHeapValueMax = 3580;            // [MS-PST] 2.3.3.3 a variable-size value larger than this lives in the subnode, not the heap

// A PC's own two heap allocations ([MS-PST] 2.3.3.1 / 2.3.3.6). hidUserRoot names the BTHHEADER and the
// BTHHEADER's hidRoot names the record array; both are normally allocated at these HIDs.
constexpr uint32_t kPcHidBthHeader = 0x20;            // [MS-PST] 2.3.3.6 a PC's BTHHEADER is normally HID 0x20
constexpr uint32_t kPcHidRecordArray = 0x40;          // [MS-PST] 2.3.3.6 the PC record array is normally HID 0x40

// --- Table Context ([MS-PST] 2.3.4.1) ---
// A TC is an HN whose bClientSig is bTypeTC; hidUserRoot names the allocation holding TCINFO followed by
// rgTCOLDESC. The Row Matrix itself normally lives in the subnode, not in this block.
constexpr uint64_t kTcInfoSize = 22;                // [MS-PST] 2.3.4.1 TCINFO is bType cCols rgib hidRowIndex hnidRows hidIndex, 1+1+8+4+4+4 bytes
constexpr uint64_t kTcInfoTypeOffset = 0;           // [MS-PST] 2.3.4.1 bType: MUST be bTypeTC
constexpr uint64_t kTcInfoColsOffset = 1;           // [MS-PST] 2.3.4.1 cCols: column count
constexpr uint64_t kTcInfoRgibOffset = 2;           // [MS-PST] 2.3.4.1 rgib: four 16-bit group-ending offsets
constexpr uint64_t kTcInfoRgibBytes = 8;            // [MS-PST] 2.3.4.1 rgib is 4 WORDs
constexpr uint64_t kTcInfoRowIndexOffset = 10;      // [MS-PST] 2.3.4.1 hidRowIndex: HID of the RowIndex BTH
constexpr uint64_t kTcInfoRowsOffset = 14;          // [MS-PST] 2.3.4.1 hnidRows: HNID of the Row Matrix, 0 when the TC has no rows
constexpr uint64_t kTcInfoIndexOffset = 18;         // [MS-PST] 2.3.4.1 hidIndex: deprecated, new PSTs write 0
constexpr uint64_t kTcRgibEntries = 4;              // [MS-PST] 2.3.4.1 rgib holds TCI_4b TCI_2b TCI_1b TCI_bm
constexpr uint64_t kTcRgib4b = 0;                   // [MS-PST] 2.3.4.1 rgib[0]: ending offset of the 8- and 4-byte group
constexpr uint64_t kTcRgib2b = 1;                   // [MS-PST] 2.3.4.1 rgib[1]: ending offset of the 2-byte group
constexpr uint64_t kTcRgib1b = 2;                   // [MS-PST] 2.3.4.1 rgib[2]: ending offset of the 1-byte group
constexpr uint64_t kTcRgibBm = 3;                   // [MS-PST] 2.3.4.1 rgib[3]: ending offset of the Cell Existence Block, which is the row size
constexpr uint32_t kTcHidHeader = 0x20;             // [MS-PST] 2.3.4 the TC header is allocated from the heap with HID 0x20
constexpr uint8_t kTcMaxColumns = 255;              // [MS-PST] 2.3.4.1 cCols is one byte

// --- TCOLDESC ([MS-PST] 2.3.4.2) ---
constexpr uint64_t kTcColDescSize = 8;              // [MS-PST] 2.3.4.2 TCOLDESC is tag ibData cbData iBit
constexpr uint64_t kTcColTagOffset = 0;             // [MS-PST] 2.3.4.2 tag: the 32-bit tag of the column
constexpr uint64_t kTcColIbDataOffset = 4;          // [MS-PST] 2.3.4.2 ibData: offset from the start of a row
constexpr uint64_t kTcColCbDataOffset = 6;          // [MS-PST] 2.3.4.2 cbData: bytes per row, or the size of an HNID for variable-sized data
constexpr uint64_t kTcColIBitOffset = 7;            // [MS-PST] 2.3.4.2 iBit: 0-based index into the Cell Existence Bitmap

// --- RowIndex and TCROWID ([MS-PST] 2.3.4.3 / 2.3.4.3.1) ---
constexpr uint8_t kTcRowIdCbKey = 4;                // [MS-PST] 2.3.4.3.1 the Unicode RowIndex BTH has cbKey 4
constexpr uint8_t kTcRowIdCbEnt = 4;                // [MS-PST] 2.3.4.3.1 the Unicode RowIndex BTH has cbEnt 4
constexpr uint64_t kTcRowIdSize = 8;                // [MS-PST] 2.3.4.3.1 a Unicode TCROWID is dwRowID then dwRowIndex, 4 bytes each
constexpr uint64_t kTcRowIdValueOffset = 0;         // [MS-PST] 2.3.4.3.1 dwRowID: the 32-bit primary key
constexpr uint64_t kTcRowIdIndexOffset = 4;         // [MS-PST] 2.3.4.3.1 dwRowIndex: 0-based index of the row in the Row Matrix

// --- Row Matrix ([MS-PST] 2.3.4.4 / 2.3.4.4.1 / 2.3.4.4.3) ---
// Every row is laid out the same way: 4-byte group, 2-byte group, 1-byte group, then the CEB. Columns
// MUST be sorted by tag, and the first two are fixed by the spec.
constexpr uint64_t kTcTagPropIdShift = 16;            // [MS-PST] 1.1 property tag: the high 16 bits are the property ID, the low 16 the property type
constexpr uint32_t tc_prop_id_of_tag(uint32_t tag) { return tag >> kTcTagPropIdShift; }   // [MS-PST] 1.1 property tag high 16 bits
constexpr uint16_t tc_prop_type_of_tag(uint32_t tag) { return tag & 0xFFFF; }             // [MS-PST] 1.1 property tag low 16 bits
constexpr uint32_t kTcTagRowId = 0x67F2;            // [MS-PST] 2.4.4.4.1 PidTagLtpRowId, the row's own dwRowID
constexpr uint32_t kTcTagRowVer = 0x67F3;           // [MS-PST] 2.4.4.4.1 PidTagLtpRowVer, the row's version
constexpr uint64_t kTcRowIdIbData = 0;              // [MS-PST] 2.3.4.4.1 PidTagLtpRowId MUST have ibData 0
constexpr uint8_t kTcRowIdIBit = 0;                 // [MS-PST] 2.3.4.4.1 PidTagLtpRowId MUST have iBit 0
constexpr uint64_t kTcRowVerIbData = 4;             // [MS-PST] 2.3.4.4.1 PidTagLtpRowVer MUST have ibData 4
constexpr uint8_t kTcRowVerIBit = 1;                // [MS-PST] 2.3.4.4.1 PidTagLtpRowVer MUST have iBit 1
constexpr uint16_t kPropDisplayName = 0x3001;       // [MS-PST] 2.4.4.4.1 PidTagDisplayName: a folder's own name
constexpr uint64_t kTcDataBlockSize = 8192;         // [MS-PST] 2.3.4.4 every Row Matrix block but the last MUST be 8192 bytes
constexpr uint64_t kTcMaxRows = 1000000;            // [MS-PST] 2.3.4.3.1 dwRowIndex is 32-bit, so a corrupt RowIndex needs a hard cap

// --- Name-to-ID Map ([MS-PST] 2.4.7) ---
// The map at NID_NAME_TO_ID_MAP is a PC whose properties are not real properties but the streams and
// the hash buckets of the map ([MS-PST] 2.4.7, 2.1.2).
constexpr uint16_t kPropNameidBucketCount = 0x0001;      // [MS-PST] 2.1.2 PidTagNameidBucketCount: PtypInteger32 bucket count
constexpr uint16_t kPropNameidStreamGuid = 0x0002;       // [MS-PST] 2.1.2 PidTagNameidStreamGuid: PtypBinary GUID Stream
constexpr uint16_t kPropNameidStreamEntry = 0x0003;      // [MS-PST] 2.1.2 PidTagNameidStreamEntry: PtypBinary Entry Stream
constexpr uint16_t kPropNameidStreamString = 0x0004;     // [MS-PST] 2.1.2 PidTagNameidStreamString: PtypBinary String Stream
constexpr uint16_t kPropNameidBucketBase = 0x1000;       // [MS-PST] 2.4.7.5 PidTagNameidBucketBase: the buckets run sequentially from here to 0x1000 + count - 1
constexpr uint32_t kNameidBucketCountRecommended = 251;  // [MS-PST] 2.4.7.5 the bucket count SHOULD be 251, but a reader MUST consult the property
constexpr uint32_t kNameidMaxBucketCount = 4096;         // [MS-PST] 2.4.7.5 the count is a 32-bit property value, so a corrupt one needs a cap before anything is read

// NAMEID record ([MS-PST] 2.4.7.1): dwPropertyID, then the WORD holding N and wGuid, then wPropIdx.
constexpr uint64_t kNameIdRecordSize = 8;                // [MS-PST] 2.4.7.1 a NAMEID record is 4 + 2 + 2 bytes
constexpr uint64_t kNameIdPropertyIdOffset = 0;          // [MS-PST] 2.4.7.1 dwPropertyID: a String Stream offset, a numeric name, or a CRC
constexpr uint64_t kNameIdGuidOffset = 4;                // [MS-PST] 2.4.7.1 the WORD holding N and wGuid
constexpr uint16_t kNameIdNameBit = 0x0001;              // [MS-PST] 2.4.7.1 N is the lowest bit of that WORD (the layout diagram puts it left of wGuid): 1 means the name is a string
constexpr uint64_t kNameIdGuidShift = 1;                 // [MS-PST] 2.4.7.1 wGuid is the 15 bits above the N bit, so wGuid = word >> 1
constexpr uint64_t kNameIdPropIdxOffset = 6;             // [MS-PST] 2.4.7.1 wPropIdx: the ordinal that gives this record its NPID
constexpr uint16_t kNameIdGuidNone = 0x0000;             // [MS-PST] 2.4.7.1 NAMEID_GUID_NONE: no GUID is associated with the name
constexpr uint16_t kNameIdGuidMapi = 0x0001;             // [MS-PST] 2.4.7.1 NAMEID_GUID_MAPI: the GUID is PS_MAPI
constexpr uint16_t kNameIdGuidPublicStrings = 0x0002;    // [MS-PST] 2.4.7.1 NAMEID_GUID_PUBLIC_STRINGS: the GUID is PS_PUBLIC_STRINGS
constexpr uint16_t kNameIdGuidStreamFirst = 3;           // [MS-PST] 2.4.7.1 a wGuid above 2 is the index plus 3 into the GUID Stream
constexpr uint64_t kNameIdGuidSize = 16;                 // [MS-PST] 2.4.7.2 the GUID Stream is a flat array of 16-byte GUIDs
constexpr uint16_t kNpidBase = 0x8000;                   // [MS-PST] 2.4.7.1 the NPID of a named property is 0x8000 plus wPropIdx
constexpr uint16_t kNpidMax = 0x8FFF;                    // [MS-PST] 2.4.7.1 wPropIdx is the ordinal under 0x8000, so an NPID tops out at 0x8FFF

// String Stream ([MS-PST] 2.4.7.4): every name is a DWORD byte length followed by Unicode bytes, padded
// so the pair ends on a 4-byte boundary, and never null terminated.
constexpr uint64_t kNameidStringLengthSize = 4;          // [MS-PST] 2.4.7.4 each name is preceded by a DWORD giving its length in bytes
constexpr uint64_t kNameidStringAlignment = 4;           // [MS-PST] 2.4.7.4 padding ends each length/string pair on a 4-byte boundary
constexpr uint64_t kNameidMaxNameBytes = 65536;          // [MS-PST] 2.4.7.4 the length DWORD is 32-bit, so a corrupt one needs a cap before it is copied
constexpr uint64_t kNameidMaxRecords = 1000000;          // [MS-PST] 2.4.7.3 a stream length decides the record count, so a corrupt length needs a hard cap

// --- Search Update Descriptor ([MS-PST] 2.4.8.1.1) ---
constexpr uint64_t kSudSize = 20;                        // [MS-PST] 2.4.8.1.1 a SUD is wFlags wSUDType SUDData: 2 + 2 + 16 bytes
constexpr uint64_t kSudFlagsOffset = 0;                  // [MS-PST] 2.4.8.1.1 wFlags
constexpr uint64_t kSudTypeOffset = 2;                   // [MS-PST] 2.4.8.1.1 wSUDType selects which SUDData structure the 16 bytes hold
constexpr uint64_t kSudDataOffset = 4;                   // [MS-PST] 2.4.8.1.1 SUDData follows the two WORDs
constexpr uint64_t kSudDataSize = 16;                    // [MS-PST] 2.4.8.1.1 SUDData is 16 bytes whatever the type
constexpr uint16_t kSudTypeNull = 0x0000;                // [MS-PST] 2.4.8.1: SUDT_NULL, an invalid SUD type
constexpr uint16_t kSudTypeMsgAdd = 0x0001;              // [MS-PST] 2.4.8.1: SUDT_MSG_ADD
constexpr uint16_t kSudTypeMsgMod = 0x0002;              // [MS-PST] 2.4.8.1: SUDT_MSG_MOD
constexpr uint16_t kSudTypeMsgDel = 0x0003;              // [MS-PST] 2.4.8.1: SUDT_MSG_DEL
constexpr uint16_t kSudTypeMsgMov = 0x0004;              // [MS-PST] 2.4.8.1: SUDT_MSG_MOV
constexpr uint16_t kSudTypeFldAdd = 0x0005;              // [MS-PST] 2.4.8.1: SUDT_FLD_ADD
constexpr uint16_t kSudTypeFldMod = 0x0006;              // [MS-PST] 2.4.8.1: SUDT_FLD_MOD
constexpr uint16_t kSudTypeFldDel = 0x0007;              // [MS-PST] 2.4.8.1: SUDT_FLD_DEL
constexpr uint16_t kSudTypeFldMov = 0x0008;              // [MS-PST] 2.4.8.1: SUDT_FLD_MOV
constexpr uint16_t kSudTypeSrchAdd = 0x0009;             // [MS-PST] 2.4.8.1: SUDT_SRCH_ADD
constexpr uint16_t kSudTypeSrchMod = 0x000A;             // [MS-PST] 2.4.8.1: SUDT_SRCH_MOD
constexpr uint16_t kSudTypeSrchDel = 0x000B;             // [MS-PST] 2.4.8.1: SUDT_SRCH_DEL
constexpr uint16_t kSudTypeMsgRowMod = 0x000C;           // [MS-PST] 2.4.8.1: SUDT_MSG_ROW_MOD
constexpr uint16_t kSudTypeMsgSpam = 0x000D;             // [MS-PST] 2.4.8.1: SUDT_MSG_SPAM
constexpr uint16_t kSudTypeIdxMsgDel = 0x000E;           // [MS-PST] 2.4.8.1: SUDT_IDX_MSG_DEL
constexpr uint16_t kSudTypeMsgIdx = 0x000F;              // [MS-PST] 2.4.8.1: SUDT_MSG_IDX
constexpr uint16_t kSudFlagPriorityLow = 0x0001;         // [MS-PST] 2.4.8.1.1 SUDF_PRIORITY_LOW
constexpr uint16_t kSudFlagPriorityHigh = 0x0002;        // [MS-PST] 2.4.8.1.1 SUDF_PRIORITY_HIGH
constexpr uint16_t kSudFlagSearchRestart = 0x0004;       // [MS-PST] 2.4.8.1.1 SUDF_SEARCH_RESTART
constexpr uint16_t kSudFlagNameChanged = 0x0008;         // [MS-PST] 2.4.8.1.1 SUDF_NAME_CHANGED
constexpr uint16_t kSudFlagMoveOutToIn = 0x0010;         // [MS-PST] 2.4.8.1.1 SUDF_MOVE_OUT_TO_IN
constexpr uint16_t kSudFlagMoveInToIn = 0x0020;          // [MS-PST] 2.4.8.1.1 SUDF_MOVE_IN_TO_IN
constexpr uint16_t kSudFlagMoveInToOut = 0x0040;         // [MS-PST] 2.4.8.1.1 SUDF_MOVE_IN_TO_OUT
constexpr uint16_t kSudFlagMoveOutToOut = 0x0080;        // [MS-PST] 2.4.8.1.1 SUDF_MOVE_OUT_TO_OUT
constexpr uint16_t kSudFlagSpamCheckServer = 0x0100;     // [MS-PST] 2.4.8.1.1 SUDF_SPAM_CHECK_SERVER
constexpr uint16_t kSudFlagSetDelName = 0x0200;          // [MS-PST] 2.4.8.1.1 SUDF_SET_DEL_NAME
constexpr uint16_t kSudFlagSrchDone = 0x0400;            // [MS-PST] 2.4.8.1.1 SUDF_SRCH_DONE
constexpr uint16_t kSudFlagDomainChecked = 0x8000;       // [MS-PST] 2.4.8.1.1 SUDF_DOMAIN_CHECKED

// --- Basic queue node ([MS-PST] 2.4.8.3) ---
// A queue node is a node whose data block is a flat array of k-byte items. NBTENTRY.nidParent is
// re-purposed as the byte offset of the head, so the items before it have already been consumed.
constexpr uint64_t kQueueMaxItems = 1000000;             // [MS-PST] 2.4.8.3 the item count comes from cbData, so a corrupt cbData needs a hard cap

// Bucket selection ([MS-PST] 2.4.7.5): the bucket a NAMEID record belongs to comes from its own two
// DWORDs, where pul[1] is the WORD holding N and wGuid under the WORD holding wPropIdx.
constexpr uint32_t name_id_bucket(uint32_t property_id, uint32_t guid_word, uint32_t bucket_count) { // [MS-PST] 2.4.7.5
    return (property_id ^ (guid_word & 0xFFFFu)) % bucket_count;
}

// --- NID types ([MS-PST] 2.2.2.1) ---
// A NID is 32 bits: 5 low bits nidType, 27 bits nidIndex. Two subnodes of two different nodes may share
// an NID; two subnodes of the same node MUST NOT.
constexpr uint64_t kNidTypeMask = 0x1F;               // [MS-PST] 2.2.2.1 nidType is the low 5 bits of a NID
constexpr uint64_t kNidIndexShift = 5;                // [MS-PST] 2.2.2.1 nidIndex sits above nidType
constexpr uint64_t kNidIndexMask = 0x7FFFFFF;         // [MS-PST] 2.2.2.1 nidIndex is 27 bits
constexpr uint32_t kNidTypeHid = 0x00;                // [MS-PST] 2.2.2.1 NID_TYPE_HID: a heap node
constexpr uint32_t kNidTypeInternal = 0x01;           // [MS-PST] 2.2.2.1 NID_TYPE_INTERNAL
constexpr uint32_t kNidTypeNormalFolder = 0x02;       // [MS-PST] 2.2.2.1 NID_TYPE_NORMAL_FOLDER
constexpr uint32_t kNidTypeSearchFolder = 0x03;       // [MS-PST] 2.2.2.1 NID_TYPE_SEARCH_FOLDER
constexpr uint32_t kNidTypeNormalMessage = 0x04;      // [MS-PST] 2.2.2.1 NID_TYPE_NORMAL_MESSAGE
constexpr uint32_t kNidTypeAttachment = 0x05;         // [MS-PST] 2.2.2.1 NID_TYPE_ATTACHMENT
constexpr uint32_t kNidTypeSearchUpdateQueue = 0x06;  // [MS-PST] 2.2.2.1 NID_TYPE_SEARCH_UPDATE_QUEUE
constexpr uint32_t kNidTypeSearchCriteriaObject = 0x07; // [MS-PST] 2.2.2.1 NID_TYPE_SEARCH_CRITERIA_OBJECT
constexpr uint32_t kNidTypeAssocMessage = 0x08;       // [MS-PST] 2.2.2.1 NID_TYPE_ASSOC_MESSAGE
constexpr uint32_t kNidTypeContentsTableIndex = 0x0A; // [MS-PST] 2.2.2.1 NID_TYPE_CONTENTS_TABLE_INDEX
constexpr uint32_t kNidTypeReceiveFolderTable = 0x0B; // [MS-PST] 2.2.2.1 NID_TYPE_RECEIVE_FOLDER_TABLE
constexpr uint32_t kNidTypeOutgoingQueueTable = 0x0C; // [MS-PST] 2.2.2.1 NID_TYPE_OUTGOING_QUEUE_TABLE
constexpr uint32_t kNidTypeHierarchyTable = 0x0D;     // [MS-PST] 2.2.2.1 NID_TYPE_HIERARCHY_TABLE
constexpr uint32_t kNidTypeContentsTable = 0x0E;      // [MS-PST] 2.2.2.1 NID_TYPE_CONTENTS_TABLE
constexpr uint32_t kNidTypeAssocContentsTable = 0x0F; // [MS-PST] 2.2.2.1 NID_TYPE_ASSOC_CONTENTS_TABLE
constexpr uint32_t kNidTypeSearchContentsTable = 0x10; // [MS-PST] 2.2.2.1 NID_TYPE_SEARCH_CONTENTS_TABLE
constexpr uint32_t kNidTypeAttachmentTable = 0x11;    // [MS-PST] 2.2.2.1 NID_TYPE_ATTACHMENT_TABLE
constexpr uint32_t kNidTypeRecipientTable = 0x12;     // [MS-PST] 2.2.2.1 NID_TYPE_RECIPIENT_TABLE
constexpr uint32_t kNidTypeSearchTableIndex = 0x13;   // [MS-PST] 2.2.2.1 NID_TYPE_SEARCH_TABLE_INDEX
constexpr uint32_t kNidTypeLtp = 0x1F;                // [MS-PST] 2.2.2.1 NID_TYPE_LTP: what a subnode HNID names

// NID arithmetic ([MS-PST] 2.2.2.1). A Messaging-layer object is one nidIndex wearing several nidTypes,
// so the sibling of a NID is the same nidIndex under a different type.
constexpr uint64_t nid_type(uint64_t nid) { return nid & kNidTypeMask; }                       // [MS-PST] 2.2.2.1 nidType
constexpr uint64_t nid_index(uint64_t nid) { return (nid >> kNidIndexShift) & kNidIndexMask; } // [MS-PST] 2.2.2.1 nidIndex is 27 bits
constexpr uint64_t make_nid(uint64_t index, uint64_t type) { return (index << kNidIndexShift) | type; } // [MS-PST] 2.2.2.1 a NID is nidType under nidIndex

// --- Special internal NIDs ([MS-PST] 2.2.2.1) ---
constexpr uint64_t kNidMessageStore = 0x21;           // [MS-PST] 2.4.1 NID_MESSAGE_STORE: a PC (2.4.3, ms-pst.txt:3203)
constexpr uint64_t kNidNameToIdMap = 0x61;            // [MS-PST] 2.4.1 NID_NAME_TO_ID_MAP: a PC (2.4.7)
constexpr uint64_t kNidNormalFolderTemplate = 0xA1;   // [MS-PST] 2.4.1 NID_NORMAL_FOLDER_TEMPLATE: a PC and its tables (2.7.3.3)
constexpr uint64_t kNidSearchFolderTemplate = 0xC1;   // [MS-PST] 2.4.1 NID_SEARCH_FOLDER_TEMPLATE: a PC and its tables (2.7.3.3)
constexpr uint64_t kNidRootFolder = 0x122;            // [MS-PST] 2.4.1 NID_ROOT_FOLDER: a PC (2.4.4.1)
constexpr uint64_t kNidSearchManagementQueue = 0x1E1; // [MS-PST] 2.4.1 NID_SEARCH_MANAGEMENT_QUEUE: a queue node (2.4.8.4.1)
constexpr uint64_t kNidSearchActivityList = 0x201;    // [MS-PST] 2.4.1 NID_SEARCH_ACTIVITY_LIST: an array of NIDs (2.4.8.4.2)
constexpr uint64_t kNidReserved1 = 0x241;             // [MS-PST] 2.4.1 NID_RESERVED1: Reserved, no structure defined
constexpr uint64_t kNidSearchDomainObject = 0x261;    // [MS-PST] 2.4.1 NID_SEARCH_DOMAIN_OBJECT: an array of NIDs (2.4.8.4.3)
constexpr uint64_t kNidSearchGathererQueue = 0x281;   // [MS-PST] 2.4.1 NID_SEARCH_GATHERER_QUEUE: a queue node (2.4.8.5.1)
constexpr uint64_t kNidSearchGathererDescriptor = 0x2A1; // [MS-PST] 2.4.1 NID_SEARCH_GATHERER_DESCRIPTOR: an opaque BLOB (2.4.8.5.2)
constexpr uint64_t kNidReserved2 = 0x2E1;             // [MS-PST] 2.4.1 NID_RESERVED2: Reserved, no structure defined
constexpr uint64_t kNidReserved3 = 0x301;             // [MS-PST] 2.4.1 NID_RESERVED3: Reserved, no structure defined
constexpr uint64_t kNidSearchGathererFolderQueue = 0x321; // [MS-PST] 2.4.1 NID_SEARCH_GATHERER_FOLDER_QUEUE: an array of NIDs (2.4.8.5.3)
// HID arithmetic ([MS-PST] 2.3.1.1). The widths are profile-specific, so the profile is part of every
// split and no caller is allowed to guess it. The type bits decide whether a 32-bit id names a heap item
// or a node ([MS-PST] 2.3.3.2), so the split lives here and nowhere else.
constexpr uint32_t hid_type(uint32_t hid) { return static_cast<uint32_t>(hid & kHidTypeMask); }                                  // [MS-PST] 2.3.1.1 hidType is 5 bits in both profiles
constexpr uint64_t hid_index_mask(ndb::FileProfile profile) { return profile == ndb::FileProfile::kOst ? kHidIndexMask4k : kHidIndexMask512; }   // [MS-PST] 2.3.1.1 hidIndex width per profile (4k: libpff :1558)
constexpr uint64_t hid_block_index_shift(ndb::FileProfile profile) { return profile == ndb::FileProfile::kOst ? kHidBlockIndexShift4k : kHidBlockIndexShift512; } // [MS-PST] 2.3.1.1 hidBlockIndex position per profile (4k: libpff :1559)
constexpr uint64_t hid_block_index_mask(ndb::FileProfile profile) { return profile == ndb::FileProfile::kOst ? kHidBlockIndexMask4k : kHidBlockIndexMask512; }     // [MS-PST] 2.3.1.1 hidBlockIndex width per profile (4k: libpff :1559)
constexpr uint32_t hid_index(uint32_t hid, ndb::FileProfile profile) { return static_cast<uint32_t>((hid >> kHidIndexShift) & hid_index_mask(profile)); }           // [MS-PST] 2.3.1.1 hidIndex is 1-based
constexpr uint32_t hid_block_index(uint32_t hid, ndb::FileProfile profile) { return static_cast<uint32_t>((hid >> hid_block_index_shift(profile)) & hid_block_index_mask(profile)); } // [MS-PST] 2.3.1.1 hidBlockIndex
constexpr bool hid_is_valid(uint32_t hid, ndb::FileProfile profile) { return hid_type(hid) == kHidTypeHid && hid_index(hid, profile) != 0; }    // [MS-PST] 2.3.1.1 hidType MUST be 0, hidIndex MUST NOT be 0

const char *client_sig_name(uint8_t client_sig); // [MS-PST] 2.3.1.2 bClientSig friendly names
const char *nid_type_name(uint32_t nid_type); // [MS-PST] 2.2.2.1 nidType friendly names

// [MS-PST] 2.2.2.1 marks in parentheses which nidType values are a Property Context or a Table Context.
// Only those are announced as heap nodes, so a data block with no HNHDR under any other nidType is not a
// decode failure -- the node's own type never promised a heap node.
bool nid_type_announces_heap_node(uint32_t nid_type); // [MS-PST] 2.2.2.1 nidType table (ms-pst.txt:869-907)

// [MS-PST] 2.4.1 lists every predefined internal NID and names what each one holds. Returns "" for a
// nidIndex the table does not name, so an unnamed internal node is never called a known shape.
const char *predefined_internal_nid_name(uint64_t nid); // [MS-PST] 2.4.1 predefined internal NIDs (ms-pst.txt:3142-3166)

// [MS-PST] 2.4.8.3 / 2.4.8.4 / 2.4.8.5 name the predefined internal NIDs that hold an array of NIDs, a
// queue of fixed-size items, or an opaque BLOB instead of a heap node. Returns "" for the predefined
// internal NIDs that are PCs (2.4.3, 2.4.7, 2.7.3.3) and for Reserved entries.
const char *documented_non_heap_internal_nid_name(uint64_t nid); // [MS-PST] 2.4.8.4.2 (ms-pst.txt:4302), 2.4.8.4.3 (:4307)

// ... and the predefined internal NIDs the spec does say are Property Contexts: the message store
// ([MS-PST] 2.4.3, ms-pst.txt:3203), the Name-to-ID Map (2.4.7), the folder templates (2.7.3.3) and the
// root folder (2.4.4.1). A data block with no HNHDR under one of those contradicts the spec.
const char *documented_heap_internal_nid_name(uint64_t nid); // [MS-PST] 2.4.3 (ms-pst.txt:3203), 2.4.4.1, 2.4.7, 2.7.3.3

} // namespace ost2pst::ltp
