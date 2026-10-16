"""Build tests/fixtures/synthetic-ost.bin: a tiny but real OST-profile file.

Every CRC and signature uses the rules the reader enforces (seed 0, no complement, ComputeSig(ib,bid)),
so the fixture is a format-true file rather than a blob with plausible bytes. Layout (OST profile:
4096-byte pages, 24-byte trailers, 512-byte allocation units):

  0x00000 HEADER + ROOT
  0x01000 BBT leaf page (also the BBT root)   3 BBTENTRY
  0x02000 NBT leaf page (also the NBT root)   4 NBTENTRY
  0x22000 first AMap region (ROOT.ibAMapLast)
  0x23000 block bid 0x10 cb 100   footprint 512
  0x24000 block bid 0x14 cb 600   footprint 1024
  0x25000 block bid 0x18 cb 1024  footprint 1536
  0x26000 end of file
"""
import json
import os
import sys
from pathlib import Path
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT = Path(sys.argv[1]).resolve()
FIXTURES = str(OUTPUT / "fixtures")
GOLDEN = str(OUTPUT / "golden")

PAGE = 4096
PAGE_TRAILER = 24
GRANULARITY = 512
AMAP_FIRST = 0x22000
FILE_SIZE = 0x26000

BBT_IB, NBT_IB = 0x1000, 0x2000
BBT_BID, NBT_BID = 0x100, 0x101
BLOCKS = [(0x10, 0x23000, 100, 1), (0x14, 0x24000, 600, 2), (0x18, 0x25000, 1024, 1)]
NBT = [
    (0x21, 0x10, 0, 0x00000000),      # INTERNAL, no subnode
    (0x122, 0x14, 0x18, 0x00000021),  # NORMAL_FOLDER with a subnode BTree
    (0x124, 0x18, 0, 0x00000122),     # NORMAL_MESSAGE
    (0x1FF, 0, 0, 0x00000021),        # LTP with no data block at all
]


def crc(data):
    # [MS-PST] 5.3: seed 0 and NO final complement. zlib.crc32 complements before and after its own
    # loop, so the spec variant is zlib(data, 0xFFFFFFFF) ^ 0xFFFFFFFF. util::crc32 implements exactly
    # that; zlib.crc32(data, 0) would store a different number in every dwCRC.
    return (zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF


def sig(ib, bid):
    value = ib ^ bid
    return ((value >> 16) & 0xFFFF) ^ (value & 0xFFFF)


def footprint(cb):
    # [MS-PST] 2.2.2.8: raw bytes plus trailer, rounded up to the allocation granularity.
    return (cb + PAGE_TRAILER + GRANULARITY - 1) // GRANULARITY * GRANULARITY


def page_trailer(ptype, ib, bid, data):
    if ptype in (0x82, 0x83, 0x84, 0x85):
        w_sig, stored_bid = 0, ib
    else:
        w_sig, stored_bid = sig(ib, bid), bid
    return (struct.pack("<BBHI", ptype, ptype, w_sig, crc(data))
            + struct.pack("<Q", stored_bid) + struct.pack("<I", 1) + b"\x00" * 4)


def btree_page(ptype, ib, bid, entries, c_ent, c_ent_max, cb_ent, c_level):
    page = bytearray(entries)
    page += b"\x00" * (PAGE - PAGE_TRAILER - 16 - len(page))
    page += struct.pack("<HHBB", c_ent, c_ent_max, cb_ent, c_level) + b"\x00" * 10
    page += page_trailer(ptype, ib, bid, bytes(page[:PAGE - PAGE_TRAILER]))
    assert len(page) == PAGE, len(page)
    return bytes(page)


def block(bid, ib, cb, c_ref):
    data = bytes((ib + index) & 0xFF for index in range(cb))
    size = footprint(cb)
    out = bytearray(data)
    out += b"\x00" * (size - PAGE_TRAILER - cb)
    out += (struct.pack("<HHI", cb, sig(ib, bid), crc(data)) + struct.pack("<Q", bid)
            + struct.pack("<HH", 2, c_ref) + b"\x00" * 4)
    assert len(out) == size, len(out)
    return bytes(out)


def amap_page():
    bits = bytearray(PAGE - PAGE_TRAILER)
    bits[0] = 0xFF  # [MS-PST] 2.2.2.7.2: an AMap maps itself
    first_unit = AMAP_FIRST // GRANULARITY
    units = set()
    for _bid, ib, cb, _ref in BLOCKS:
        units.update(range(ib // GRANULARITY, (ib + footprint(cb)) // GRANULARITY))
    for unit in sorted(units):
        index = unit - first_unit
        bits[index // 8] |= 1 << (7 - index % 8)  # MSB-first: measured in M0
    page = bytearray(bits) + page_trailer(0x84, AMAP_FIRST, AMAP_FIRST, bytes(bits))
    assert len(page) == PAGE
    return bytes(page), len(units)


def header():
    head = bytearray(564)
    struct.pack_into("<I", head, 0x000, 0x4E444221)
    head[0x008:0x00A] = b"SO"
    struct.pack_into("<HH", head, 0x00A, 36, 12)
    head[0x00E] = 0x01
    head[0x00F] = 0x01
    struct.pack_into("<Q", head, 0x020, 0x102)  # bidNextP
    struct.pack_into("<I", head, 0x028, 0x0000C0FF)  # dwUnique
    struct.pack_into("<I", head, 0x0FC, 0)  # dwAlign MUST be 0
    head[0x100:0x200] = b"\xFF" * 256  # rgbFM / rgbFP (deprecated)
    head[0x200] = 0x80  # bSentinel
    head[0x201] = 0x00  # bCryptMethod: none
    struct.pack_into("<Q", head, 0x204, 0x400)  # bidNextB
    root = 0x0B4
    struct.pack_into("<Q", head, root + 4, FILE_SIZE)  # ibFileEof
    struct.pack_into("<Q", head, root + 12, AMAP_FIRST)  # ibAMapLast
    struct.pack_into("<Q", head, root + 20, 0)  # cbAMapFree
    struct.pack_into("<Q", head, root + 28, 0)  # cbPMapFree
    struct.pack_into("<QQ", head, root + 36, NBT_BID, NBT_IB)
    struct.pack_into("<QQ", head, root + 52, BBT_BID, BBT_IB)
    head[root + 68] = 0x02  # fAMapValid VALID_AMAP2
    struct.pack_into("<I", head, 0x004, crc(bytes(head[0x008:0x008 + 471])))
    struct.pack_into("<I", head, 0x20C, crc(bytes(head[0x008:0x008 + 516])))
    return bytes(head)


def build():
    file = bytearray(FILE_SIZE)
    file[0:564] = header()
    # [MS-PST] 2.2.2.7.7.3: BBTENTRY (Unicode) is bid ib cb cRef dwPadding = 24 bytes.
    bbt_entries = b"".join(struct.pack("<QQHHI", bid, ib, cb, ref, 0) for bid, ib, cb, ref in BLOCKS)
    assert len(bbt_entries) == 24 * len(BLOCKS), len(bbt_entries)   # [MS-PST] 2.2.2.7.7.3 stride 24
    file[BBT_IB:BBT_IB + PAGE] = btree_page(0x80, BBT_IB, BBT_BID, bbt_entries, len(BLOCKS), 169, 24, 0)
    nbt_entries = b"".join(
        # [MS-PST] 2.2.2.7.7.4: NBTENTRY (Unicode) is nid bidData bidSub nidParent dwPadding = 32 bytes.
        struct.pack("<QQQII", nid, bid_data, bid_sub, parent, 0)
        for nid, bid_data, bid_sub, parent in NBT)
    assert len(nbt_entries) == 32 * len(NBT), len(nbt_entries)  # [MS-PST] 2.2.2.7.7.4 stride 32
    file[NBT_IB:NBT_IB + PAGE] = btree_page(0x81, NBT_IB, NBT_BID, nbt_entries, len(NBT), 126, 32, 0)
    amap, mapped_units = amap_page()
    file[AMAP_FIRST:AMAP_FIRST + PAGE] = amap
    for bid, ib, cb, ref in BLOCKS:
        file[ib:ib + footprint(cb)] = block(bid, ib, cb, ref)
    return bytes(file), mapped_units


def main():
    data, mapped_units = build()
    os.makedirs(FIXTURES, exist_ok=True)
    os.makedirs(GOLDEN, exist_ok=True)
    with open(os.path.join(FIXTURES, "synthetic-ost.bin"), "wb") as handle:
        handle.write(data)
    # Cut inside the third block footprint: its trailer is gone, so the reader must report a data
    # error rather than read past the end.
    with open(os.path.join(FIXTURES, "synthetic-ost-truncated.bin"), "wb") as handle:
        handle.write(data[:0x25400])

    types = {}
    for nid, bid_data, bid_sub, _parent in NBT:
        entry = types.setdefault(nid & 0x1F, {"entries": 0, "with_bid_data": 0, "with_bid_sub": 0})
        entry["entries"] += 1
        entry["with_bid_data"] += 1 if bid_data else 0
        entry["with_bid_sub"] += 1 if bid_sub else 0

    golden = {
        "file_size": FILE_SIZE,
        "truncated_size": 0x25400,
        "bbt_ib": hex(BBT_IB),
        "nbt_ib": hex(NBT_IB),
        "amap_ib": hex(AMAP_FIRST),
        "bbt_entries": len(BLOCKS),
        "bbt_min_bid": hex(min(b for b, _i, _c, _r in BLOCKS)),
        "bbt_max_bid": hex(max(b for b, _i, _c, _r in BLOCKS)),
        "nbt_entries": len(NBT),
        "nbt_bid_data_missing": 0,
        # Flat text, not nested JSON: tests/unit/test_support.h reads golden files without a JSON
        # library, so every key has to hold one scalar.
        "nid_type_counts": ",".join("%s=%d" % (hex(t), v["entries"]) for t, v in sorted(types.items())),
        "blocks_requested": sum(1 for _n, d, _s, _p in NBT if d),
        "blocks_crc_ok": sum(1 for _n, d, _s, _p in NBT if d),
        "blocks_cb_matches": sum(1 for _n, d, _s, _p in NBT if d),
        "blocks_data_bytes": sum(cb for _b, _i, cb, _r in BLOCKS),
        "amap_regions_valid": 1,
        "amap_units_allocated": 8 + mapped_units,
    }
    # One flat key per block so a test can assert the index side and the block side agree.
    for bid, ib, cb, c_ref in BLOCKS:
        name = hex(bid)
        golden["block_ib_" + name] = ib
        golden["block_cb_" + name] = cb
        golden["block_cref_" + name] = c_ref
        golden["block_crc_" + name] = crc(bytes((ib + i) & 0xFF for i in range(cb)))

    # The cut lands inside the last block's footprint, so that one block stops being readable and
    # ROOT.ibFileEof stops matching the file. Everything else still reads.
    cut_bid, cut_ib, cut_cb, _cut_ref = BLOCKS[-1]
    golden["truncated_findings"] = 2
    golden["truncated_blocks_requested"] = golden["blocks_requested"]
    golden["truncated_blocks_out_of_range"] = 1
    golden["truncated_blocks_crc_ok"] = golden["blocks_crc_ok"] - 1
    golden["truncated_blocks_data_bytes"] = golden["blocks_data_bytes"] - cut_cb
    golden["truncated_failure_offset"] = cut_ib
    golden["truncated_failure_field"] = "BBTENTRY.ib"
    with open(os.path.join(GOLDEN, "synthetic-ndb.json"), "w", encoding="utf-8", newline="\n") as handle:
        json.dump(golden, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print("wrote synthetic-ost.bin (%d bytes) + truncated variant + golden/synthetic-ndb.json" % len(data))
    print("nid types:", golden["nid_type_counts"])
    print("allocated units:", golden["amap_units_allocated"])
    for bid, _ib, _cb, _r in BLOCKS:
        print("block %s: crc=%d" % (hex(bid), golden["block_crc_" + hex(bid)]))



# Public [MS-PST] examples, sections 3.2 and 3.8; no private file bytes.
Path(FIXTURES).mkdir(parents=True, exist_ok=True)
(Path(FIXTURES) / 'spec-example-header.bin').write_bytes(bytes.fromhex(
    '2142444e0ea99a37534d1700130001015c070000d07b990b0400000001000000540200000000000045000000000400000004'
    '0000040400000040000002000100040400000004000000040000008000000004000000040000000400000004000004040000'
    '0404000004040000000400000004000000040000000400000004000000040000000400000004000000040000000400000004'
    '0000000400000004000000040000000400000f04000000000000000000000000000000249f000000000000449b0000000000'
    '40f212000000000000000000000000004b0200000000000000529000000000005302000000000000000a9000000000000200'
    '000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    'ffffffffffffffffffffffff800100003414000000000000d683d21f00000000000000000000000000000000000000000000'
    '0000000000000000000000000000'
))
Path(FIXTURES).mkdir(parents=True, exist_ok=True)
(Path(FIXTURES) / 'spec-example-hn.bin').write_bytes(bytes.fromhex(
    'ec00ecbc2000000000000000b502060040000000340e0201a0000000380e030000000000f90f02016000000001301f008000'
    '0000df35030089000000e0350201c0000000e335020100010000e7350201e000000033660b0001000000fa6603000d000e00'
    'ff67030000000000229db50adcd9944385de90aeb07d127055004e00490043004f0044004500310001000000f55ef6669569'
    'cc4c83d1d873989902850100000000000000229db50adcd9944385de90aeb07d12702280000000000000229db50adcd99443'
    '85de90aeb07d12704280000000000000229db50adcd9944385de90aeb07d127062800000080000000c0014006c007c008c00'
    'a400bc00d400ec00'
))

main()

# Independent generated anchors for golden_test: tiny 4K-profile structures.
data, _ = build()
head = data[:564]
amap = data[AMAP_FIRST:AMAP_FIRST + PAGE]
leaf = data[BBT_IB:BBT_IB + PAGE]
bid, ib, cb, ref = BLOCKS[0]
payload = data[ib:ib + footprint(cb)]
dlist_ib, dlist_bid = 0x21000, 0x102
dlist_data = bytes(PAGE - PAGE_TRAILER)
dlist = dlist_data + page_trailer(0x86, dlist_ib, dlist_bid, dlist_data)
for kind, blob in [('header', head), ('amap-page', amap), ('bbt-leaf', leaf),
                   ('block', payload), ('dlist-page', dlist)]:
    (Path(FIXTURES) / f'synthetic-{kind}.bin').write_bytes(blob)
layout = dict(
    dw_magic='0x4E444221', w_magic_client='SO', w_ver=36, w_ver_client=12,
    b_sentinel=128, b_crypt_method=0, bid_next_p=0x102, bid_next_b=0x400,
    ib_file_eof=FILE_SIZE, ib_amap_last=AMAP_FIRST, f_amap_valid=2,
    bbt_bref_bid=BBT_BID, bbt_bref_ib=BBT_IB, nbt_bref_bid=NBT_BID, nbt_bref_ib=NBT_IB,
    dw_crc_partial=struct.unpack_from('<I', head, 4)[0],
    dw_crc_full=struct.unpack_from('<I', head, 0x20C)[0],
    profile='synthetic 4K', page_size=PAGE, page_trailer_size=PAGE_TRAILER,
    bt_trailer_offset=4072, bt_entries_bytes=4056, bbt_leaf_c_ent_max=169,
    bbt_leaf_cb_ent=24, block_granularity=GRANULARITY, block_trailer_size=PAGE_TRAILER,
    block_max_cb=65512, amap_first_offset=AMAP_FIRST, amap_interval=16678912,
    amap_regions=1, dlist_offset=dlist_ib, dlist_bid=dlist_bid,
    dlist_wsig=sig(dlist_ib, dlist_bid), dlist_wsig_expected=sig(dlist_ib, dlist_bid),
    amap_first_crc=crc(amap[:-PAGE_TRAILER]), amap_first_crc_computed=crc(amap[:-PAGE_TRAILER]),
    bbt_leaf_ib=BBT_IB, bbt_leaf_c_ent=len(BLOCKS), bbt_entry_bid=bid,
    bbt_entry_ib=ib, bbt_entry_cb=cb, bbt_entry_uncompressed_cb=ref, bbt_entry_ost_cref=0,
    block_ib=ib, block_footprint=footprint(cb), block_cb=cb, block_bid=bid,
    block_wsig=sig(ib, bid), block_wsig_expected=sig(ib, bid),
    block_crc=crc(payload[:cb]), block_crc_computed=crc(payload[:cb]),
    block_btyp=2, block_uncompressed_cb=ref)
(Path(GOLDEN) / 'synthetic-layout.json').write_text(json.dumps(layout, indent=2) + '\n', encoding='utf-8')
