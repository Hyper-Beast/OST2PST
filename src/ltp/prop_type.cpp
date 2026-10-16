#include "ost2pst/ltp/prop_type.h"

#include "ost2pst/ltp/layout.h"

namespace ost2pst::ltp {

PropTypeInfo prop_type_info(uint16_t prop_type) {
    // [MS-OXCDATA] 2.11.1: the multi-valued forms share the base type's id with the 0x1000 flag set.
    const uint16_t base = static_cast<uint16_t>(prop_type & ~kPropTypeMultiValuedFlag);
    switch (base) {
    case 0x0000:
        return {prop_type, "PtypUnspecified", true, 0}; // [MS-OXCDATA] 2.11.1
    case 0x0002:
        return {prop_type, "PtypShort", false, 2}; // [MS-OXCDATA] 2.11.1
    case 0x0003:
        return {prop_type, "PtypInteger32", false, 4}; // [MS-OXCDATA] 2.11.1
    case 0x0004:
        return {prop_type, "PtypFloating32", false, 4}; // [MS-OXCDATA] 2.11.1
    case 0x0005:
        return {prop_type, "PtypFloating64", false, 8}; // [MS-OXCDATA] 2.11.1
    case 0x0006:
        return {prop_type, "PtypCurrency", false, 8}; // [MS-OXCDATA] 2.11.1
    case 0x0007:
        return {prop_type, "PtypFloatingTime", false, 8}; // [MS-OXCDATA] 2.11.1
    case 0x0014:
        return {prop_type, "PtypInteger64", false, 8}; // [MS-OXCDATA] 2.11.1
    case 0x000B:
        return {prop_type, "PtypBoolean", false, 1}; // [MS-OXCDATA] 2.11.1
    case 0x000D:
        return {prop_type, "PtypObject", true, 0}; // [MS-OXCDATA] 2.11.1
    case 0x001E:
        return {prop_type, "PtypString8", true, 0}; // [MS-OXCDATA] 2.11.1
    case 0x001F:
        return {prop_type, "PtypString16", true, 0}; // [MS-OXCDATA] 2.11.1
    case 0x0040:
        return {prop_type, "PtypTime", false, 8}; // [MS-OXCDATA] 2.11.1
    case 0x0048:
        return {prop_type, "PtypGuid", false, 16}; // [MS-OXCDATA] 2.11.1
    case 0x0102:
        return {prop_type, "PtypBinary", true, 0}; // [MS-OXCDATA] 2.11.1
    default:
        break;
    }
    // An unrecognised type is treated as variable-size: the reader then looks for the value behind an
    // HNID instead of inventing four bytes out of the record.
    return {prop_type, "unknown", true, 0};
}

bool prop_type_is_inline(uint16_t prop_type) {
    if ((prop_type & kPropTypeMultiValuedFlag) != 0) {
        return false; // [MS-PST] 2.3.3.4: a multi-valued value is stored using an HNID
    }
    const PropTypeInfo info = prop_type_info(prop_type);
    // [MS-PST] 2.3.3.3: fixed data size <= 4 bytes means dwValueHnid is the value itself.
    return !info.variable_size && info.fixed_size >= 1 && info.fixed_size <= kPcValueInlineMax;
}

bool prop_type_is_tc_inline(uint16_t prop_type) {
    if ((prop_type & kPropTypeMultiValuedFlag) != 0)
        return false;
    const PropTypeInfo info = prop_type_info(prop_type);
    return !info.variable_size && info.fixed_size >= 1 && info.fixed_size <= 8;
}

} // namespace ost2pst::ltp
