#include "read_only.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <vector>

#define NOMINMAX
// clang-format off
#include <windows.h>
#include <psapi.h>
// clang-format on

#include "ost2pst/ltp/ltp_read.h"
#include "ost2pst/msg/mailbox.h"
#include "ost2pst/ndb/crc.h"
#include "ost2pst/ndb/probe.h"

namespace ost2pst::cli {
namespace {

void print_failures(const std::vector<ndb::ProbeFailure>& failures) {
    for (const auto& failure : failures)
        std::printf("  %s offset=0x%llX value=0x%llX [%s]\n", failure.field.c_str(),
                    static_cast<unsigned long long>(failure.offset),
                    static_cast<unsigned long long>(failure.value), failure.detail.c_str());
}

int inspect(const std::wstring& input, const std::wstring& output, bool dry_run) {
    auto opened = util::FileReader::open_stable(input);
    if (!opened.ok())
        return report_input_error(opened.error());
    const auto& file = opened.value();
    auto valid = validate_input(file);
    if (!valid.ok())
        return report_input_error(valid.error());
    {
        ndb::ProbeOptions options;
        options.workspace_budget = 256 * 1024 * 1024;
        auto probed = ndb::probe_file(file, options);
        if (!probed.ok())
            return report_input_error(probed.error());
        const auto& probe = probed.value();
        if (probe.refusal)
            return report_input_error(*probe.refusal);
        std::printf("NDB profile=%s bytes=%llu blocks=%llu failures=%llu\n",
                    ndb::file_profile_name(probe.profile),
                    static_cast<unsigned long long>(file.size()),
                    static_cast<unsigned long long>(probe.counters.blocks.verified),
                    static_cast<unsigned long long>(probe.failure_total));
        print_failures(probe.failures);
        if (!probe.clean) {
            std::printf("%s RESULT: findings present\n", dry_run ? "DRY-RUN" : "VERIFY");
            return 3;
        }
    }
    ltp::LtpReadOptions options;
    options.index_workspace_budget = 256 * 1024 * 1024;
    options.scan_blocks = !dry_run;
    options.build_folders = !dry_run;
    auto read = ltp::read_ltp(file, options);
    if (!read.ok())
        return report_input_error(read.error());
    const auto& census = read.value();
    if (census.refusal)
        return report_input_error(*census.refusal);
    print_failures(census.failures);
    for (const auto& error : census.errors)
        std::printf("  %s count=%llu\n", error.first.c_str(),
                    static_cast<unsigned long long>(error.second));
    for (const auto& finding : census.findings.items)
        std::printf("  %s NID=0x%llX %s [%s]\n", ltp::ltp_finding_kind_name(finding.kind),
                    static_cast<unsigned long long>(finding.nid), finding.field.c_str(),
                    finding.detail.c_str());
    std::printf("LTP pcs=%llu tcs=%llu failures=%llu unsupported_structures=%llu\n",
                static_cast<unsigned long long>(census.pcs.contexts),
                static_cast<unsigned long long>(census.tcs.contexts),
                static_cast<unsigned long long>(census.failure_total),
                static_cast<unsigned long long>(census.findings.unsupported));
    if (!census.clean || census.failure_total || !census.errors.empty() ||
        census.findings.decode_failures) {
        std::printf("%s RESULT: findings present\n", dry_run ? "DRY-RUN" : "VERIFY");
        return 3;
    }
    if (dry_run) {
        auto planned = msg::build_mailbox_manifest(census);
        if (!planned.ok())
            return report_input_error(planned.error());
        const auto& manifest = planned.value();
        uint64_t normal = 0, associated = 0, unknown = 0, unsupported = 0, excluded = 0;
        for (const auto& item : manifest.items)
            ++(item.associated ? associated : normal);
        for (const auto& entry : manifest.coverage) {
            unknown += entry.kind == msg::CoverageKind::kUnknown;
            unsupported += entry.kind == msg::CoverageKind::kUnsupportedContent;
            excluded += entry.kind == msg::CoverageKind::kExcludedSearch;
        }
        std::printf(
            "PLAN folders=%llu normal=%llu fai=%llu excluded_search=%llu unknown=%llu "
            "unsupported_content=%llu\n",
            static_cast<unsigned long long>(manifest.folders.size()),
            static_cast<unsigned long long>(normal), static_cast<unsigned long long>(associated),
            static_cast<unsigned long long>(excluded), static_cast<unsigned long long>(unknown),
            static_cast<unsigned long long>(unsupported));
        if (!output.empty())
            std::printf("destination=%s (not checked or created)\n", to_utf8(output).c_str());
        std::printf("Per-item conversion and payload completeness are not evaluated.\n");
        std::printf("DRY-RUN RESULT: %s\n",
                    unsupported ? "unsupported content present" : "planned");
        return unsupported ? 3 : 0;
    }
    std::printf("Structural verification only; source equivalence and Outlook acceptance are not "
                "evaluated.\n");
    std::printf("VERIFY RESULT: %s\n",
                census.findings.unsupported ? "unsupported structures present" : "clean");
    return census.findings.unsupported ? 3 : 0;
}
} // namespace

std::string to_utf8(const std::wstring& wide) {
    if (wide.empty())
        return {};
    const int needed = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                                           nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
        return {};
    std::string text(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), text.data(), needed,
                        nullptr, nullptr);
    return text;
}

util::Status validate_input(const util::FileReader& file) {
    const auto size = static_cast<size_t>(std::min(file.size(), ndb::kHeaderSize));
    std::vector<uint8_t> bytes(size);
    auto io = file.read_at(0, bytes.data(), bytes.size());
    if (!io.ok())
        return io;
    const util::ByteView view(bytes.data(), bytes.size());
    // [MS-PST] 2.2.2.1: dwMagic and wVer precede the ANSI/Unicode layout split.
    const auto magic = view.u32(ndb::kDwMagicOffset);
    if (!magic.ok()) {
        auto error = magic.error();
        error.field = "HEADER.dwMagic";
        return error;
    }
    if (magic.value() != ndb::kDwMagicValue)
        return util::make_error(util::ErrorKind::kUnsupported, "HEADER.dwMagic",
                                ndb::kDwMagicOffset, magic.value(), "not an NDB/LTP file");
    const auto version = view.u16(ndb::kWVerOffset);
    if (!version.ok()) {
        auto error = version.error();
        error.field = "HEADER.wVer";
        return error;
    }
    if (version.value() < ndb::kMinUnicodeVer || version.value() == ndb::kWipVer)
        return util::make_error(
            util::ErrorKind::kUnsupported, "HEADER.wVer", ndb::kWVerOffset, version.value(),
            version.value() == ndb::kWipVer ? "WIP-protected files are not supported"
                                            : "ANSI layout is not supported");
    auto header = ndb::decode_header(view);
    if (!header.ok())
        return header.error();
    auto policy = ndb::validate_header_refusals(header.value());
    if (!policy.ok()) {
        auto error = policy.error();
        if (error.field == "HEADER.bCryptMethod")
            error.detail = "encoded or encrypted blocks are not supported";
        if (error.field == "HEADER.bPlatform") {
            const bool create = header.value().b_platform_create != ndb::kPlatformId;
            error.field = create ? "HEADER.bPlatformCreate" : "HEADER.bPlatformAccess";
            error.offset = create ? ndb::kBPlatformCreateOffset : ndb::kBPlatformAccessOffset;
            error.value =
                create ? header.value().b_platform_create : header.value().b_platform_access;
        }
        return error;
    }
    // [MS-PST] 2.2.2.5: ibFileEof is the file size in bytes, never an allocation-unit count.
    if (header.value().root.ib_file_eof != file.size())
        return util::make_error(header.value().root.ib_file_eof > file.size()
                                    ? util::ErrorKind::kTruncated
                                    : util::ErrorKind::kBadField,
                                "ROOT.ibFileEof", ndb::kRootOffset + ndb::kRootIbFileEofOffset,
                                header.value().root.ib_file_eof,
                                "physical file size is " + std::to_string(file.size()));
    auto crc = ndb::verify_header_crcs(view);
    if (!crc.ok())
        return crc.error();
    if (!crc.value().partial_ok)
        return util::make_error(util::ErrorKind::kBadCrc, "HEADER.dwCRCPartial",
                                ndb::kDwCRCPartialOffset, crc.value().stored_partial,
                                "header partial CRC mismatch");
    if (!crc.value().full_ok)
        return util::make_error(util::ErrorKind::kBadCrc, "HEADER.dwCRCFull", ndb::kDwCRCFullOffset,
                                crc.value().stored_full, "header full CRC mismatch");
    return {};
}

int input_error_exit(const util::DataError& error) {
    if (error.kind == util::ErrorKind::kIo)
        return 1;
    // A supported header with no valid root page is a structural failure, not an encoding policy.
    if (error.kind == util::ErrorKind::kUnsupported && error.field != "BTPAGE.pageTrailer")
        return 2;
    return 3;
}

int report_input_error(const util::DataError& error) {
    const int code = input_error_exit(error);
    std::fprintf(stderr, "%s: %s\n", code == 2 ? "REFUSAL" : "INPUT ERROR",
                 util::format_error(error).c_str());
    return code;
}

int run_read_only(const std::wstring& input, const std::wstring& output, bool dry_run) {
    const auto start = std::chrono::steady_clock::now();
    const int code = inspect(input, output, dry_run);
    PROCESS_MEMORY_COUNTERS memory{};
    const bool measured =
        GetProcessMemoryInfo(GetCurrentProcess(), &memory, sizeof memory) != FALSE;
    std::fprintf(stderr,
                 "%s invocation wall_seconds=%.3f peak_working_set=%llu measured=%s exit=%d\n",
                 dry_run ? "dry-run" : "verify",
                 std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count(),
                 static_cast<unsigned long long>(measured ? memory.PeakWorkingSetSize : 0),
                 measured ? "true" : "false", code);
    return code;
}
} // namespace ost2pst::cli
