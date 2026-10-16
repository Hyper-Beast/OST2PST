#pragma once

#include <cstdint>

namespace ost2pst::ltp {

// Property type ids and their fixed data sizes ([MS-OXCDATA] 2.11.1). [MS-PST] 2.3.3.3 decides whether a
// PC value sits inline in dwValueHnid or behind an HNID by looking at that size, so the table lives in
// the same layer as the rule that needs it.
//
// [MS-OXCDATA] is not in docs/reference/ yet: the open-specifications download host is unreachable from this
// environment. The ids below were checked against the sample: its 26 property contexts name 0x0002,
// 0x0003, 0x000B, 0x0014, 0x001F, 0x0040, 0x0048, 0x0102 and the multi-valued forms 0x1014 and 0x101F,
// which is what corrected the first guess for PtypInteger64 (0x0014, not 0x000A). These are the types
// [MS-PST] 2.3.3.6 relies on, and M3 re-checks them against the text once it is available.
constexpr uint16_t kPropTypeMultiValuedFlag = 0x1000; // [MS-OXCDATA] 2.11.1 a property type carrying this flag is multi-valued

struct PropTypeInfo {
    uint16_t prop_type = 0;
    const char *name = "unknown";
    bool variable_size = true;
    uint16_t fixed_size = 0; // 0 unless the type is fixed-size
};

PropTypeInfo prop_type_info(uint16_t prop_type);

// [MS-PST] 2.3.3.3: only a single-valued fixed-size type of 4 bytes or less is stored inline. A
// multi-valued type is always stored through an HNID ([MS-PST] 2.3.3.4).
bool prop_type_is_inline(uint16_t prop_type);

} // namespace ost2pst::ltp
