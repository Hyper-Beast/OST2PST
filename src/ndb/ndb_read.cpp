#include "ost2pst/ndb/ndb_read.h"

#include <cstdio>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "ost2pst/ndb/bbt_index.h"
#include "ost2pst/ndb/profile.h"
#include "ost2pst/ndb/trailer.h"
#include "ost2pst/util/crc32.h"

namespace ost2pst::ndb {

using util::ByteView;
using util::DataError;
using util::ErrorKind;
using util::make_error;
using util::Result;
using util::Status;

namespace {

std::string hex64(uint64_t value) {
    char text[24];
    std::snprintf(text, sizeof(text), "0x%llX", static_cast<unsigned long long>(value));
    return text;
}

} // namespace

Result<NdbReadReport> read_ndb(const util::FileReader &file, const NdbReadOptions &options) {
    std::vector<uint8_t> header_bytes(static_cast<size_t>(kHeaderSize));
    Status io = file.read_at(kHeaderOffset, header_bytes.data(), header_bytes.size());
    if (!io) {
        return io.error();
    }
    const ByteView header_view(header_bytes.data(), header_bytes.size(), kHeaderOffset);

    Result<Header> header = decode_header(header_view);
    if (!header.ok()) {
        return header.error();
    }

    NdbReadReport report;
    report.header = header.value();

    Result<HeaderCrcReport> crcs = verify_header_crcs(header_view);
    if (!crcs.ok()) {
        return crcs.error();
    }
    report.header_crcs = crcs.value();

    // [MS-PST] 2.6.1.3.7: fAMapValid is checked before any AMap is trusted. A refusal short-circuits
    // the walk: bytes under an obfuscated header cannot be interpreted, so counting them as findings
    // would only invent noise.
    Status refusal = validate_header_refusals(report.header);
    if (!refusal) {
        report.refusal = refusal.error();
        report.clean = false;
        return report;
    }

    Result<FileProfile> profile = detect_profile(file, report.header.root.bbt_bref.ib);
    if (!profile.ok()) {
        return profile.error();
    }
    report.profile = profile.value();
    report.profile_evidence = std::string(file_profile_name(report.profile)) + ": the root BBT page at " +
                              hex64(report.header.root.bbt_bref.ib) + " has a valid trailer and dwCRC at " +
                              std::to_string(page_size(report.profile)) + "-byte pages";

    FailureLog failures(options.max_failures);
    NdbReadCounters &counters = report.counters;

    counters.file_eof_matches_size = report.header.root.ib_file_eof == file.size();
    if (!counters.file_eof_matches_size) {
        failures.add(kHeaderOffset + kRootIbFileEofOffset, "ROOT.ibFileEof",
                     report.header.root.ib_file_eof, "file size is " + std::to_string(file.size()));
    }

    // [MS-PST] 2.2.2.7.7.3: a BID only means anything once the BBT has been walked, so the index is
    // built before a single NBT entry is looked at.
    BTreeWalker bbt(kPageTypeBBT, report.profile, &failures);
    Status walked = bbt.walk(file, report.header.root.bbt_bref.ib);
    if (!walked) {
        return walked.error();
    }
    report.bbt = bbt.stats();

    BbtIndex index(bbt.bbt_index());
    counters.bbt_index_entries = index.entries();
    counters.bbt_index_bytes = index.bytes();
    counters.bbt_index_duplicates = index.duplicates();
    if (index.duplicates() != 0) {
        failures.add(report.header.root.bbt_bref.ib, "BBTENTRY.bid", index.duplicates(),
                     "BBT entries share a BID, so a BID no longer names one block");
    }
    counters.bbt_min_bid = index.min_bid();
    counters.bbt_max_bid = index.max_bid();
    counters.highest_block_bid = index.max_bid();
    counters.highest_page_bid = report.bbt.max_page_bid;

    // [MS-PST] 2.2.2.7.7.4: every leaf entry names a data block and optionally a subnode BTree root.
    // Enumerating them is what M1 promises, and the per-nidType histogram is what M3 reads next.
    std::map<uint8_t, NidTypeCount> by_type;
    BTreeWalker nbt(kPageTypeNBT, report.profile, &failures);
    nbt.set_nbt_handler([&](const NbtEntry &entry, uint64_t entry_ib) {
        ++counters.nbt_entries;
        const uint8_t nid_type = static_cast<uint8_t>(entry.nid & kNidTypeMask);
        NidTypeCount &count = by_type[nid_type];
        count.nid_type = nid_type;
        ++count.entries;

        if (entry.bid_data > counters.highest_block_bid) {
            counters.highest_block_bid = entry.bid_data;
        }
        if (entry.bid_sub > counters.highest_block_bid) {
            counters.highest_block_bid = entry.bid_sub;
        }

        if (entry.bid_data != 0) {
            ++count.with_bid_data;
            if (index.lookup(entry.bid_data) == nullptr) {
                ++counters.nbt_bid_data_missing;
                failures.add(entry_ib, "NBTENTRY.bidData", entry.bid_data,
                             "nid " + hex64(entry.nid) + " names a BID the BBT does not index");
            } else if (options.verify_bid_data) {
                // Every check read_block performs is counted and logged there; a failure here is not a
                // reason to stop walking the rest of the mailbox.
                Result<BlockData> block =
                    read_block(file, report.profile, index, entry.bid_data, report.blocks, failures);
                if (!block.ok() && block.error().kind == ErrorKind::kIo) {
                    failures.add(block.error());
                }
            }
        }
        if (entry.bid_sub != 0) {
            ++count.with_bid_sub;
            if (index.lookup(entry.bid_sub) == nullptr) {
                ++counters.nbt_bid_sub_missing;
                failures.add(entry_ib, "NBTENTRY.bidSub", entry.bid_sub,
                             "nid " + hex64(entry.nid) + " names a subnode BID the BBT does not index");
            }
        }
    });
    walked = nbt.walk(file, report.header.root.nbt_bref.ib);
    if (!walked) {
        return walked.error();
    }
    report.nbt = nbt.stats();
    if (report.nbt.max_page_bid > counters.highest_page_bid) {
        counters.highest_page_bid = report.nbt.max_page_bid;
    }
    for (const auto &item : by_type) {
        report.nid_types.push_back(item.second);
    }

    if (options.scan_amap) {
        // [MS-PST] 2.6.1.3.7: fAMapValid says whether the AMaps may be trusted at all.
        if (report.header.root.f_amap_valid == kFAMapInvalid) {
            failures.add(kHeaderOffset + kRootFAMapValidOffset, "ROOT.fAMapValid",
                         report.header.root.f_amap_valid, "INVALID_AMAP: the allocation maps are not usable");
        } else {
            Status scanned = for_each_allocated_unit(
                file, report.profile, report.header.root.ib_amap_last, options.amap_bit_order, failures,
                [&](uint64_t, uint64_t) {
                    ++counters.amap_units_allocated;
                    return true;
                },
                &counters.amap_regions, &counters.amap_regions_valid);
            if (!scanned) {
                return scanned.error();
            }
        }
    }

    // [MS-PST] 2.2.2.1: bidNextB is the next block BID the file will hand out and bidNextP the next
    // page BID, so neither may sit at or below an ID already in use.
    counters.bid_next_b_covers = report.header.bid_next_b >= counters.highest_block_bid;
    if (!counters.bid_next_b_covers) {
        failures.add(kHeaderOffset + kBidNextBOffset, "HEADER.bidNextB", report.header.bid_next_b,
                     "highest block BID seen is " + hex64(counters.highest_block_bid));
    }
    counters.bid_next_p_covers = report.header.bid_next_p >= counters.highest_page_bid;
    if (!counters.bid_next_p_covers) {
        failures.add(kHeaderOffset + kBidNextPOffset, "HEADER.bidNextP", report.header.bid_next_p,
                     "highest page BID seen is " + hex64(counters.highest_page_bid));
    }

    report.failure_total = failures.total();
    report.failures = failures.failures();
    report.clean = report.failure_total == 0 && report.header_crcs.partial_ok &&
                   report.header_crcs.full_ok && counters.file_eof_matches_size &&
                   counters.bid_next_b_covers && counters.bid_next_p_covers &&
                   report.blocks.crc_failed == 0 && counters.nbt_bid_data_missing == 0;
    return report;
}

} // namespace ost2pst::ndb
