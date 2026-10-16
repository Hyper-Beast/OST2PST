// The format-true synthetic OST the LTP-layer tests build: the M1 fixture layout
// (DEVELOPMENT.md) -- 4096-byte pages with
// 24-byte trailers, 512-byte allocation units, every CRC and signature computed with the rules the reader
// enforces. Shared so a test of the CLI's own verdict can build the same file the layer tests build.
#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "ost2pst/ltp/layout.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/crc32.h"
#include "ost2pst/util/sig.h"

namespace ost2pst::test::ost {

constexpr uint64_t kPage = 4096;
constexpr uint64_t kPageTrailer = 24;
constexpr uint64_t kGranularity = 512;
constexpr uint64_t kBbtIb = 0x1000;
constexpr uint64_t kNbtIb = 0x2000;
constexpr uint64_t kBbtBid = 0x100;
constexpr uint64_t kNbtBid = 0x101;
constexpr uint64_t kAmapIb = 0x22000;
constexpr uint64_t kFirstBlockIb = 0x23000;

void put16(std::vector<uint8_t> &out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>(value >> 8));
}

void put32(std::vector<uint8_t> &out, uint32_t value) {
    for (int shift = 0; shift < 4; ++shift) {
        out.push_back(static_cast<uint8_t>((value >> (8 * shift)) & 0xFF));
    }
}

void put64(std::vector<uint8_t> &out, uint64_t value) {
    for (int shift = 0; shift < 8; ++shift) {
        out.push_back(static_cast<uint8_t>((value >> (8 * shift)) & 0xFF));
    }
}

uint32_t crc_of(const std::vector<uint8_t> &bytes, uint64_t base) {
    return util::crc32(util::ByteView(bytes.data(), bytes.size(), base));
}

uint64_t footprint(uint16_t cb) {
    // [MS-PST] 2.2.2.8: raw bytes plus trailer, rounded up to the allocation granularity.
    return (static_cast<uint64_t>(cb) + kPageTrailer + kGranularity - 1) / kGranularity * kGranularity;
}

std::vector<uint8_t> page_with_footer(uint8_t ptype, uint64_t ib, uint64_t bid,
                                      const std::vector<uint8_t> &entries, uint16_t c_ent,
                                      uint16_t c_ent_max, uint8_t cb_ent, uint8_t c_level) {
    std::vector<uint8_t> page = entries;
    page.resize(static_cast<size_t>(kPage - kPageTrailer - 16), 0); // [MS-PST] 2.2.2.7.7.1 rgentries ends at the footer
    put16(page, c_ent);
    put16(page, c_ent_max);
    page.push_back(cb_ent);
    page.push_back(c_level);
    page.resize(page.size() + 10, 0);
    const std::vector<uint8_t> body(page);
    page.push_back(ptype);
    page.push_back(ptype);
    put16(page, util::compute_sig(ib, bid));
    put32(page, crc_of(body, ib)); // [MS-PST] 2.2.2.7.1 dwCRC covers the page minus the trailer
    put64(page, bid);
    put32(page, 1);
    page.resize(page.size() + 4, 0);
    return page;
}

std::vector<uint8_t> block_with_trailer(uint64_t ib, uint64_t bid, const std::vector<uint8_t> &payload) {
    const uint16_t cb = static_cast<uint16_t>(payload.size());
    const uint64_t size = footprint(cb);
    std::vector<uint8_t> out = payload;
    out.resize(static_cast<size_t>(size - kPageTrailer), 0);
    put16(out, cb);
    put16(out, util::compute_sig(ib, bid));
    put32(out, crc_of(payload, ib)); // [MS-PST] 2.2.2.8.1 dwCRC covers only the cb raw data bytes
    put64(out, bid);
    put16(out, 2);
    put16(out, cb); // the OST uncompressed-data-length slot: equal to cb, so the NDB calls this block raw
    put16(out, 1);  // the OST slot past it, whose meaning is unresolved and which the reader never uses
    out.resize(out.size() + 2, 0);
    return out;
}

// One NBTENTRY plus, unless `payload` is empty, the data block its bidData names. `internal` sets bit B on
// the BID ([MS-PST] 2.2.2.2), which is what says whether the block holds data or names other blocks.
struct NodeSpec {
    uint64_t index = 0;
    uint32_t type = 0;
    uint64_t parent = 0;
    bool internal = false;
    std::vector<uint8_t> payload;
};

std::vector<uint8_t> build_file(const std::vector<NodeSpec> &nodes) {
    std::vector<uint8_t> bbt_entries;
    std::vector<uint8_t> nbt_entries;
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> blocks;
    std::vector<uint64_t> allocated; // [unit index] for the AMap
    uint64_t bid = 0x10;
    uint64_t ib = kFirstBlockIb;
    for (const NodeSpec &node : nodes) {
        const uint64_t node_bid = node.internal ? (bid | ndb::kBidInternalBit) : bid;
        if (!node.payload.empty()) {
            const uint16_t cb = static_cast<uint16_t>(node.payload.size());
            // [MS-PST] 2.2.2.7.7.3 BBTENTRY: bid ib cb cRef dwPadding
            put64(bbt_entries, node_bid);
            put64(bbt_entries, ib);
            put16(bbt_entries, cb); // +16 cb
            put16(bbt_entries, cb); // +18 cRef: the block's uncompressed data length, as its trailer says
            put16(bbt_entries, 1);  // +20: the unresolved OST slot past cRef
            put16(bbt_entries, 0);  // +22
            blocks.emplace_back(ib, block_with_trailer(ib, node_bid, node.payload));
            for (uint64_t unit = ib / kGranularity; unit < (ib + footprint(cb)) / kGranularity; ++unit) {
                allocated.push_back(unit);
            }
            ib += footprint(cb);
        }
        // [MS-PST] 2.2.2.7.7.4 NBTENTRY: nid bidData bidSub nidParent dwPadding
        put64(nbt_entries, ltp::make_nid(node.index, node.type));
        put64(nbt_entries, node.payload.empty() ? 0 : node_bid);
        put64(nbt_entries, 0);
        put32(nbt_entries, static_cast<uint32_t>(node.parent));
        put32(nbt_entries, 0);
        bid += 4;
    }

    const uint64_t file_size = ib > kAmapIb + kPage ? ib : kAmapIb + kPage;

    std::vector<uint8_t> head(564, 0); // [MS-PST] 2.2.2.1 HEADER (Unicode) is 564 bytes
    const auto put_at = [&](size_t at, uint32_t value) {
        head[at] = static_cast<uint8_t>(value & 0xFF);
        head[at + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
        head[at + 2] = static_cast<uint8_t>((value >> 16) & 0xFF);
        head[at + 3] = static_cast<uint8_t>((value >> 24) & 0xFF);
    };
    const auto put64_at = [&](size_t at, uint64_t value) {
        for (int shift = 0; shift < 8; ++shift) {
            head[at + shift] = static_cast<uint8_t>((value >> (8 * shift)) & 0xFF);
        }
    };
    put_at(0x000, 0x4E444221); // dwMagic
    head[0x008] = 'S';
    head[0x009] = 'O'; // wMagicClient: an Outlook OST writes "SO"
    put_at(0x00A, 36); // wVer 36: the Unicode 4k page profile
    put_at(0x00C, 12); // wVerClient
    head[0x00E] = 0x01;
    head[0x00F] = 0x01; // bPlatform create/access
    put64_at(0x020, 0x102); // bidNextP
    put_at(0x028, 0x0000C0FF); // dwUnique
    put_at(0x0FC, 0); // dwAlign MUST be 0
    for (size_t at = 0x100; at < 0x200; ++at) {
        head[at] = 0xFF; // rgbFM / rgbFP, deprecated
    }
    head[0x200] = 0x80; // bSentinel
    head[0x201] = 0x00; // bCryptMethod none
    put64_at(0x204, 0x400); // bidNextB
    const size_t root = 0x0B4; // [MS-PST] 2.2.2.1 HEADER.ROOT is embedded in the header
    put64_at(root + 4, file_size); // ibFileEof
    put64_at(root + 12, kAmapIb); // ibAMapLast
    put64_at(root + 20, 0); // cbAMapFree
    put64_at(root + 28, 0); // cbPMapFree
    put64_at(root + 36, kNbtBid);
    put64_at(root + 44, kNbtIb); // NBT BREF
    put64_at(root + 52, kBbtBid);
    put64_at(root + 60, kBbtIb); // BBT BREF
    head[root + 68] = 0x02; // fAMapValid VALID_AMAP2
    put_at(0x004, crc_of(std::vector<uint8_t>(head.begin() + 0x008, head.begin() + 0x008 + 471), 0x008));
    put_at(0x20C, crc_of(std::vector<uint8_t>(head.begin() + 0x008, head.begin() + 0x008 + 516), 0x008));

    std::vector<uint8_t> amap(kPage - kPageTrailer, 0);
    amap[0] = 0xFF; // [MS-PST] 2.2.2.7.2: an AMap maps itself
    const uint64_t first_unit = kAmapIb / kGranularity;
    for (uint64_t unit : allocated) {
        const uint64_t index = unit - first_unit;
        amap[index / 8] |= static_cast<uint8_t>(1u << (7 - index % 8)); // MSB-first, measured in M0
    }
    const std::vector<uint8_t> amap_body(amap);
    amap.push_back(ndb::kPageTypeAMap);
    amap.push_back(ndb::kPageTypeAMap);
    put16(amap, 0); // AMap pages carry no wSig
    put32(amap, crc_of(amap_body, kAmapIb));
    put64(amap, kAmapIb);
    put32(amap, 1);
    amap.resize(amap.size() + 4, 0);

    std::vector<uint8_t> file(static_cast<size_t>(file_size), 0);
    const auto write_at = [&](uint64_t at, const std::vector<uint8_t> &bytes) {
        std::copy(bytes.begin(), bytes.end(), file.begin() + static_cast<ptrdiff_t>(at));
    };
    write_at(0, head);
    write_at(kBbtIb, page_with_footer(ndb::kPageTypeBBT, kBbtIb, kBbtBid, bbt_entries,
                                      static_cast<uint16_t>(bbt_entries.size() / 24), 169, 24, 0));
    write_at(kNbtIb, page_with_footer(ndb::kPageTypeNBT, kNbtIb, kNbtBid, nbt_entries,
                                      static_cast<uint16_t>(nbt_entries.size() / 32), 126, 32, 0));
    write_at(kAmapIb, amap);
    for (const auto &block : blocks) {
        write_at(block.first, block.second);
    }
    return file;
}

std::vector<uint8_t> heap_node(uint8_t client_sig, uint32_t hid_user_root,
                               const std::vector<std::vector<uint8_t>> &allocations,
                               uint16_t c_free = 0) {
    // [MS-PST] 2.3.1.2 HNHDR (12 bytes) then [MS-PST] 2.3.1.5 HNPAGEMAP at ibHnpm 12, then one allocation
    // per heap id, each exactly as long as the bytes handed in.
    const uint16_t header_size = 12;
    std::vector<uint8_t> out;
    put16(out, header_size);
    out.push_back(0xEC); // bSig
    out.push_back(client_sig);
    put32(out, hid_user_root);
    put32(out, 0); // rgbFillLevel
    put16(out, static_cast<uint16_t>(allocations.size()));
    put16(out, c_free);
    uint16_t at = static_cast<uint16_t>(header_size + 4 + (allocations.size() + 1) * 2);
    for (const std::vector<uint8_t> &item : allocations) {
        put16(out, at);
        at = static_cast<uint16_t>(at + item.size());
    }
    put16(out, at);
    for (const std::vector<uint8_t> &item : allocations) {
        out.insert(out.end(), item.begin(), item.end());
    }
    return out;
}

// A heap node whose HNPAGEMAP is written by hand, so a case can state a cAlloc the block cannot hold.
std::vector<uint8_t> page_map_case(uint16_t c_alloc, uint16_t c_free, const std::vector<uint16_t> &offsets,
                                   size_t block_bytes) {
    std::vector<uint8_t> out;
    put16(out, 12);
    out.push_back(0xEC);
    out.push_back(0xBC);
    put32(out, 0x20);
    put32(out, 0);
    put16(out, c_alloc);
    put16(out, c_free);
    for (uint16_t offset : offsets) {
        put16(out, offset);
    }
    out.resize(block_bytes, 0);
    return out;
}

// [MS-PST] 2.4.8.4.2: the Search Activity List "contains a simple array of NIDs (not a queue)".
std::vector<uint8_t> nid_array(const std::vector<uint32_t> &nids) {
    std::vector<uint8_t> out;
    for (uint32_t nid : nids) {
        put32(out, nid);
    }
    return out;
}

std::vector<uint8_t> bth_header(uint8_t cb_key, uint8_t cb_ent, uint32_t hid_root) {
    std::vector<uint8_t> out;
    out.push_back(ltp::kBthType); // [MS-PST] 2.3.1.2 / 2.3.2.1 bTypeBTH
    out.push_back(cb_key);
    out.push_back(cb_ent);
    out.push_back(0); // bIdxLevels
    put32(out, hid_root);
    return out;
}

// One PCRECORD ([MS-PST] 2.3.3.2): usPropID, wPropType, dwValueHnid.
struct PcSeed {
    uint16_t prop_id;
    uint16_t prop_type;
    uint32_t value_hnid;
};

std::vector<uint8_t> pc_records(const std::vector<PcSeed> &records) {
    std::vector<uint8_t> out;
    for (const PcSeed &record : records) {
        put16(out, record.prop_id);
        put16(out, record.prop_type);
        put32(out, record.value_hnid);
    }
    return out;
}

std::vector<uint8_t> utf16(const std::string &text) {
    std::vector<uint8_t> out;
    for (char character : text) {
        put16(out, static_cast<uint16_t>(static_cast<unsigned char>(character)));
    }
    put16(out, 0);
    return out;
}

} // namespace ost2pst::test::ost
