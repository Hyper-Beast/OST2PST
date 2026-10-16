#pragma once

#include <cstdint>
#include <map>
#include <vector>

#include "ost2pst/ltp/ltp_read.h"
#include "ost2pst/msg/emit.h"

namespace ost2pst::msg {

enum class CoverageKind { kContent, kRegenerated, kExcludedSearch, kUnknown, kUnsupportedContent };
const char* coverage_kind_name(CoverageKind kind);

struct NodeCoverage {
    uint32_t source_nid = 0;
    uint32_t source_parent = 0;
    uint32_t output_nid = 0;
    CoverageKind kind = CoverageKind::kUnknown;
};
struct MailboxFolder {
    uint32_t source_nid = 0;
    uint32_t source_parent = 0;
    uint32_t output_nid = 0;
    uint32_t output_parent = 0;
    uint64_t normal_count = 0;
    uint64_t associated_count = 0;
};
struct MailboxItem {
    uint32_t source_nid = 0;
    uint32_t source_parent = 0;
    uint32_t output_nid = 0;
    uint32_t output_parent = 0;
    bool associated = false;
};
struct MailboxManifest {
    std::vector<MailboxFolder> folders;
    std::vector<MailboxItem> items;
    std::vector<NodeCoverage> coverage;
    EmitRegistry registry;
    std::map<uint16_t, uint16_t> named_mapping;
    uint32_t last_folder_index = 1027;
    uint32_t last_normal_index = 65536;
    uint32_t last_associated_index = 32768;
};

// Uses the completed index, never scans payloads. All vectors and destination identities
// have deterministic source-NID order; registry numbering uses sorted semantic identities.
util::Result<MailboxManifest> build_mailbox_manifest(const ltp::LtpReadReport& census);

} // namespace ost2pst::msg
