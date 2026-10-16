// Read-only PST reference-count audit, independent of writer plan/refcount generation.
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <map>

#include "ost2pst/ltp/hn_block.h"
#include "ost2pst/ltp/ltp_read.h"
#include "ost2pst/ndb/block_reader.h"
#include "ost2pst/util/file_reader.h"

using namespace ost2pst;
template <class T> T get(util::Result<T> value) {
    if (!value.ok()) {
        std::fprintf(stderr, "%s\n", util::format_error(value.error()).c_str());
        std::exit(2);
    }
    return value.take();
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 2)
        return 1;
    auto file = get(util::FileReader::open_stable(argv[1]));
    ltp::LtpReadOptions options;
    options.scan_blocks = options.build_folders = false;
    auto census = get(ltp::read_ltp(file, options));
    if (census.profile != ndb::FileProfile::kPst || !census.clean || census.failure_total)
        return 3;
    std::map<uint64_t, uint64_t> references;
    for (const auto& entry : census.bbt_index.entries_sorted())
        references.emplace(ndb::bid_lookup_key(entry.bid), 1); // BBT's own reference.
    auto add = [&](uint64_t bid) {
        if (!bid)
            return;
        auto found = references.find(ndb::bid_lookup_key(bid));
        if (found == references.end()) {
            std::fprintf(stderr, "missing BID %llX\n", bid);
            std::exit(4);
        }
        ++found->second;
    };
    for (const auto& node : census.nodes.entries()) {
        add(node.bid_data);
        add(node.bid_sub);
    }
    ndb::BlockReadCounters counters;
    ndb::FailureLog failures;
    // Each stored parent is counted once; each slot in that parent contributes a reference.
    // MS-PST 2.2.2.7.7.3.1, 2.2.2.8.3.2 and 2.2.2.8.3.3.
    for (const auto& entry : census.bbt_index.entries_sorted()) {
        if (!ndb::bid_is_internal(entry.bid))
            continue;
        auto raw = get(
            ndb::read_block(file, census.profile, census.bbt_index, entry.bid, counters, failures));
        auto block =
            get(ltp::read_hn_block({raw.data.data(), raw.data.size(), raw.ib}, raw.compressed));
        const auto bytes = block.bytes();
        const auto type = get(bytes.u8(0));
        if (type == 1) {
            const auto table = get(ltp::decode_block_jump_table(bytes));
            for (const auto bid : table.bids)
                add(bid);
        } else if (type == 2) {
            const auto header = get(ltp::decode_subnode_block_header(bytes));
            for (uint64_t index = 0; index < header.c_ent; ++index) {
                const auto view = get(bytes.sub(header.entries_ib + index * header.entry_size,
                                                static_cast<size_t>(header.entry_size)));
                if (header.c_level == 0) {
                    const auto row = get(ltp::decode_sl_entry(view));
                    add(row.bid_data);
                    add(row.bid_sub);
                } else {
                    add(get(ltp::decode_si_entry(view)).bid);
                }
            }
        } else {
            std::fprintf(stderr, "unexpected internal bType %u\n", type);
            return 5;
        }
    }
    uint64_t mismatches = 0, unreferenced = 0, shared = 0, max_ref = 0;
    for (const auto& entry : census.bbt_index.entries_sorted()) {
        const auto actual = references.at(ndb::bid_lookup_key(entry.bid));
        max_ref = std::max(max_ref, actual);
        shared += actual > 2;
        unreferenced += actual < 2;
        if (actual != entry.c_ref) {
            ++mismatches;
            std::printf("MISMATCH bid=%llX stored=%u counted=%llu\n", entry.bid, entry.c_ref,
                        actual);
        }
    }
    std::printf("blocks=%zu shared=%llu max_ref=%llu unreferenced=%llu mismatches=%llu "
                "read_failures=%llu\n",
                references.size(), shared, max_ref, unreferenced, mismatches, failures.total());
    return mismatches || unreferenced || failures.total() ? 6 : 0;
}
