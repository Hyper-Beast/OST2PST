#include "ost2pst/writer/pc.h"

#include <algorithm>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include "ost2pst/ltp/layout.h"
#include "ost2pst/ltp/prop_type.h"

#include "internal/put.h"

namespace ost2pst::writer {

using util::ErrorKind;
using util::make_error;
using util::Result;
using util::Status;

Result<PcNode> build_pc(const std::vector<PcProperty>& properties, LocalNids& local_nids) {
    // [MS-PST] 2.3.3.3: a PC is a BTH keyed by wPropId, so the records are sorted by it and one id
    // cannot appear twice.
    std::vector<PcProperty> sorted = properties;
    for (auto& property : sorted) {
        if (!property.source)
            continue;
        if (!property.value.empty() || property.value_hnid || property.source->size() == 0 ||
            (ltp::prop_type_is_inline(property.prop_type) &&
             property.source->size() > ltp::kPcValueInlineMax))
            return make_error(ErrorKind::kBadField, "PC.value_source", property.prop_id,
                              property.source->size(),
                              "streamed value contradicts its PC representation");
        if (property.source->size() <= ltp::kPcHeapValueMax) {
            property.value.resize(static_cast<size_t>(property.source->size()));
            auto read = property.source->read_at(0, property.value.data(), property.value.size());
            if (!read.ok())
                return read.error();
            property.source.reset();
        }
    }
    std::sort(sorted.begin(), sorted.end(), [](const PcProperty& left, const PcProperty& right) {
        return left.prop_id < right.prop_id;
    });
    for (size_t index = 1; index < sorted.size(); ++index) {
        if (sorted[index].prop_id == sorted[index - 1].prop_id) {
            return make_error(ErrorKind::kBadField, "PC.wPropId", sorted[index].prop_id, index,
                              "a PC is keyed by wPropId, so one property id cannot appear twice");
        }
    }

    // [MS-PST] 2.3.3.3: an inline value lives in dwValueHnid; a variable-size value of 3580 bytes
    // or less is a heap allocation; a longer one is a subnode and dwValueHnid holds its local NID
    // ([MS-PST] 2.6.2.2.2, docs/reference/ms-pst.txt:6078-6085). A heap value's HID only exists
    // once the writer has placed it, so those records are written with a zero slot and patched
    // afterwards.
    std::vector<uint32_t> value_hnid(sorted.size(), 0);
    std::vector<char> value_in_subnode(sorted.size(), 0);
    std::vector<char> value_in_heap(sorted.size(), 0);
    std::vector<LocalSubnode> subnodes;
    for (size_t index = 0; index < sorted.size(); ++index) {
        if (sorted[index].source) {
            auto nid = local_nids.take(ltp::kNidTypeLtp);
            if (!nid.ok())
                return nid.error();
            value_hnid[index] = nid.value();
            value_in_subnode[index] = 1;
            subnodes.push_back(LocalSubnode{nid.value(), {}, sorted[index].source});
            continue;
        }
        if (sorted[index].value_hnid.has_value()) {
            // The caller named the value instead of letting the writer allocate one for it.
            if (!sorted[index].value.empty()) {
                return make_error(
                    ErrorKind::kBadField, "PC.dwValueHnid", sorted[index].prop_id,
                    sorted[index].value.size(),
                    "dwValueHnid was given explicitly, so no value bytes are expected");
            }
            if (ltp::prop_type_is_inline(sorted[index].prop_type)) {
                return make_error(ErrorKind::kBadField, "PC.wPropType", sorted[index].prop_id,
                                  sorted[index].prop_type,
                                  "an inline value lives in dwValueHnid itself ([MS-PST] 2.3.3.3)");
            }
            value_hnid[index] = *sorted[index].value_hnid;
            continue;
        }
        if (ltp::prop_type_is_inline(sorted[index].prop_type)) {
            if (sorted[index].value.size() > ltp::kPcValueInlineMax) {
                return make_error(ErrorKind::kBadField, "PC.dwValueHnid", sorted[index].prop_id,
                                  sorted[index].value.size(),
                                  "an inline value is 4 bytes or less ([MS-PST] 2.3.3.3)");
            }
            uint32_t packed = 0;
            for (size_t byte = 0; byte < sorted[index].value.size(); ++byte) {
                packed |= static_cast<uint32_t>(sorted[index].value[byte]) << (8u * byte);
            }
            value_hnid[index] = packed;
            continue;
        }
        if (sorted[index].value.empty()) {
            return make_error(
                ErrorKind::kBadField, "PC.dwValueHnid", sorted[index].prop_id, 0,
                "a variable-size value needs a heap allocation, which cannot be empty");
        }
        if (sorted[index].value.size() > ltp::kPcHeapValueMax) {
            Result<uint32_t> nid = local_nids.take(ltp::kNidTypeLtp);
            if (!nid.ok()) {
                return nid.error();
            }
            value_hnid[index] = nid.value();
            value_in_subnode[index] = 1;
            subnodes.push_back(LocalSubnode{nid.value(), sorted[index].value});
            continue;
        }
        value_in_heap[index] = 1;
    }

    PcNode node;
    // Allocation 1: the BTHHEADER that hidUserRoot names ([MS-PST] 2.3.3.6). Its hidRoot is patched
    // in once the record array exists.
    std::vector<uint8_t> bth_header(ltp::kBthHeaderSize, 0);
    bth_header[ltp::kBthTypeOffset] = ltp::kBthType;
    bth_header[ltp::kBthCbKeyOffset] = ltp::kPcCbKey;
    bth_header[ltp::kBthCbEntOffset] = ltp::kPcCbEnt;
    bth_header[ltp::kBthIdxLevelsOffset] = 0; // Patched when index levels are needed.
    // hidRoot stays 0 for now: patched below, and left 0 for an empty PC ([MS-PST] 2.3.2.1).
    Result<uint32_t> appended = node.heap.append(std::move(bth_header));
    if (!appended.ok()) {
        return appended.error();
    }

    // [MS-PST] 2.6.2.1.2 limits each heap allocation to 3580 bytes. Split the PC
    // into BTH leaves, then index their first keys ([MS-PST] 2.3.2.2 / 2.3.2.3).
    constexpr size_t leaf_capacity = ltp::kPcHeapValueMax / ltp::kPcRecordSize;
    constexpr size_t index_record_size = ltp::kPcCbKey + ltp::kBthHidNextLevelSize;
    constexpr size_t index_capacity = ltp::kPcHeapValueMax / index_record_size;
    std::vector<uint64_t> record_allocations;
    std::vector<std::pair<uint16_t, uint32_t>> level;
    for (size_t first = 0; first < sorted.size(); first += leaf_capacity) {
        const size_t end = std::min(sorted.size(), first + leaf_capacity);
        std::vector<uint8_t> records((end - first) * ltp::kPcRecordSize, 0);
        for (size_t index = first; index < end; ++index) {
            const uint64_t at = (index - first) * ltp::kPcRecordSize;
            put_u16(records, at + ltp::kPcPropIdOffset, sorted[index].prop_id);
            put_u16(records, at + ltp::kPcPropTypeOffset, sorted[index].prop_type);
            put_u32(records, at + ltp::kPcValueHnidOffset, value_hnid[index]);
        }
        appended = node.heap.append(std::move(records));
        if (!appended.ok()) {
            return appended.error();
        }
        record_allocations.push_back(node.heap.allocation_count());
        level.emplace_back(sorted[first].prop_id, appended.value());
    }
    uint8_t index_levels = 0;
    while (level.size() > 1) {
        std::vector<std::pair<uint16_t, uint32_t>> next;
        for (size_t first = 0; first < level.size(); first += index_capacity) {
            const size_t end = std::min(level.size(), first + index_capacity);
            std::vector<uint8_t> records((end - first) * index_record_size, 0);
            for (size_t index = first; index < end; ++index) {
                const size_t at = (index - first) * index_record_size;
                put_u16(records, at, level[index].first);
                put_u32(records, at + ltp::kPcCbKey, level[index].second);
            }
            appended = node.heap.append(std::move(records));
            if (!appended.ok())
                return appended.error();
            next.emplace_back(level[first].first, appended.value());
        }
        level = std::move(next);
        ++index_levels;
    }

    // The variable-size values that stayed in the heap follow the record array ([MS-PST] 2.3.3.2).
    std::vector<std::pair<size_t, uint64_t>> heap_values;
    for (size_t index = 0; index < sorted.size(); ++index) {
        if (!value_in_heap[index]) {
            continue;
        }
        appended = node.heap.append(sorted[index].value);
        if (!appended.ok()) {
            return appended.error();
        }
        heap_values.emplace_back(index, node.heap.allocation_count());
    }

    // Every HID now exists; patch the root and each value's own leaf slot.
    if (!sorted.empty()) {
        Status root = node.heap.patch(1, ltp::kBthHidRootOffset, level.front().second);
        if (!root.ok()) {
            return root.error();
        }
        Status depth =
            node.heap.patch(1, ltp::kBthIdxLevelsOffset, std::vector<uint8_t>{index_levels});
        if (!depth.ok())
            return depth.error();
        for (const std::pair<size_t, uint64_t>& placed : heap_values) {
            Status patched = node.heap.patch(record_allocations[placed.first / leaf_capacity],
                                             (placed.first % leaf_capacity) * ltp::kPcRecordSize +
                                                 ltp::kPcValueHnidOffset,
                                             node.heap.hid(placed.second));
            if (!patched.ok()) {
                return patched.error();
            }
        }
    }

    node.subnodes = std::move(subnodes);
    return node;
}

} // namespace ost2pst::writer
