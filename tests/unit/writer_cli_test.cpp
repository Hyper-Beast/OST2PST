// W3 is about what `ost2pst --empty` does to a path that already holds something. The writer builds
// the whole image in memory, so the only way it can destroy a file is the open it uses to write it,
// and a mistyped output path pointing at a real mailbox is the way that happens. This runs the
// built executable and checks the file left behind, not just its exit code.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "ost2pst/ltp/node_open.h"
#include "ost2pst/msg/mailbox.h"
#include "ost2pst/msg/subset.h"
#include "ost2pst/ndb/layout.h"
#include "ost2pst/util/byte_view.h"
#include "ost2pst/util/crc32.h"
#include "ost2pst/util/file_reader.h"
#include "ost2pst/util/status.h"
#include "ost2pst/writer/content.h"

#include "test_support.h"

namespace {

namespace ndb = ost2pst::ndb;
namespace writer = ost2pst::writer;

// src/cli/ost2pst.cpp: kExitOk 0, kExitUsage/kExitIo 1, kExitFindings 3.
constexpr int kExitOk = 0;
constexpr int kExitIo = 1;
constexpr int kExitFindings = 3; // a conversion shortfall or an unclean re-read

struct Run {
    int code = -1;
    std::string output;
};

Run run_cli(const std::string& arguments) {
    const std::string log = "writer_cli_run.out";
    // Unquoted on purpose: cmd /c merges quoted tokens when the line has more than two quote pairs.
    // Neither the executable path nor these fixture names contain a space.
    const std::string command =
        std::string(OST2PST_OST2PST_EXE) + " " + arguments + " > " + log + " 2>&1";
    Run run;
    run.code = std::system(command.c_str());
    run.output = ost2pst::test::read_text(log);
    std::remove(log.c_str());
    return run;
}

void write_bytes(const std::string& name, const std::vector<uint8_t>& bytes) {
    std::ofstream out(name, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
}

std::vector<uint8_t> read_bytes(const std::string& name) {
    std::ifstream in(name, std::ios::binary);
    if (!in) {
        return {};
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
}

bool exists(const std::string& name) {
    std::ifstream in(name);
    return static_cast<bool>(in);
}

// The size the CLI reports for the image it wrote, read back out of its own report so this test
// does not hard-code a layout that can still move.
unsigned long long reported_image_size(const Run& run) {
    const std::string needle = "image size        ";
    const size_t at = run.output.find(needle);
    if (at == std::string::npos) {
        return 0;
    }
    return std::strtoull(run.output.c_str() + at + needle.size(), nullptr, 10);
}

void expect_text(const Run& run, const char* needle) {
    if (run.output.find(needle) == std::string::npos) {
        ost2pst::test::report_failure(__FILE__, __LINE__,
                                      std::string("the CLI report has no: ") + needle);
    }
}

const std::vector<uint8_t> marker() {
    const std::string text = "EXISTING USER DATA";
    return std::vector<uint8_t>(text.begin(), text.end());
}

// The default: an existing file keeps its bytes and the run says no.
void test_an_existing_file_is_refused() {
    const std::string path = "writer_cli_existing.pst";
    write_bytes(path, marker());
    const Run run = run_cli("--empty " + path);
    TEST_EQ(static_cast<unsigned long long>(run.code), static_cast<unsigned long long>(kExitIo),
            "refusing to overwrite an existing file exits 1");
    TEST_CHECK(run.output.find("refusing to overwrite") != std::string::npos);
    TEST_EQ(static_cast<unsigned long long>(read_bytes(path).size()),
            static_cast<unsigned long long>(marker().size()),
            "the refusal left the original bytes alone");
    TEST_CHECK(read_bytes(path) == marker());
}

// --force is the explicit yes. It has to truncate a longer file down to the image, not append to
// it.
void test_force_overwrites_when_asked() {
    const std::string path = "writer_cli_force.pst";
    write_bytes(path, std::vector<uint8_t>(4096, 0x5A));
    const Run run = run_cli("--empty " + path + " --force");
    TEST_EQ(static_cast<unsigned long long>(run.code), static_cast<unsigned long long>(kExitOk),
            "--force over an existing file exits 0");
    expect_text(run, "RESULT: clean");
    const unsigned long long written = reported_image_size(run);
    TEST_CHECK(written > 0);
    TEST_EQ(static_cast<unsigned long long>(read_bytes(path).size()), written,
            "the file on disk is the image the writer reported");
}

// A refusal must not leave a half-written file, and a path whose directory is missing must not
// create one.
void test_a_missing_directory_leaves_no_file() {
    const std::string path = "writer_cli_missing_dir/writer_cli_missing.pst";
    const Run run = run_cli("--empty " + path);
    TEST_EQ(static_cast<unsigned long long>(run.code), static_cast<unsigned long long>(kExitIo),
            "an output path with no directory exits 1");
    TEST_CHECK(!exists(path));
    TEST_CHECK(!exists("writer_cli_missing_dir/writer_cli_missing.pst.out"));
}

// Usage errors are IO-level failures for this CLI, and none of them may touch the filesystem.
void test_usage_errors_write_nothing() {
    const Run no_output = run_cli("");
    TEST_EQ(static_cast<unsigned long long>(no_output.code),
            static_cast<unsigned long long>(kExitIo), "no --empty exits 1");
    expect_text(no_output, "ost2pst --empty <file>");
    TEST_CHECK(!exists("writer_cli_run.pst"));

    const Run unknown = run_cli("--empty writer_cli_run.pst --wat");
    TEST_EQ(static_cast<unsigned long long>(unknown.code), static_cast<unsigned long long>(kExitIo),
            "an unknown argument exits 1");
    TEST_CHECK(!exists("writer_cli_run.pst"));
}

// M5 Step 5: --folder on a store this writer wrote itself. The unit tests never open the 2.6 GB OST
// (DEVELOPMENT.md), so the input here is the store --empty just
// wrote, whose IPM_SUBTREE is a folder with no messages. What is under test is the flag plumbing:
// the NID is read, the report names the folder the new store allocated, the re-read verdict reaches
// the exit code, and a NID the input has no folder for is a nonzero exit that leaves no file
// behind.
void test_folder_conversion_of_a_written_store() {
    const std::string source = "writer_cli_folder_source.pst";
    const std::string out = "writer_cli_folder.pst";
    std::remove(source.c_str());
    std::remove(out.c_str());
    const Run made = run_cli("--empty " + source);
    TEST_EQ(static_cast<unsigned long long>(made.code), static_cast<unsigned long long>(kExitOk),
            "--empty wrote the store the folder conversion reads");

    const Run folder = run_cli("--folder 0x8022 --max-messages 8 " + source + " " + out);
    TEST_EQ(static_cast<unsigned long long>(folder.code), static_cast<unsigned long long>(kExitOk),
            "--folder on a folder the input has exits 0");
    expect_text(folder, "CONVERSION");
    expect_text(folder, "new folder        0x00008082");
    expect_text(folder, "RESULT: clean");
    expect_text(folder,
                "messages          0 read (0 the folder names, 0 reached through an Attachment");
    expect_text(folder, "object), 0 handed over, 0 written, 0 skipped");
    expect_text(folder,
                "attached Messages 0 read out of Attachment objects, 0 written as their subnodes");
    const std::vector<uint8_t> written = read_bytes(out);
    TEST_CHECK(written.size() > 0);

    const Run again = run_cli("--folder 0x8022 --max-messages 8 " + source + " " + out);
    TEST_EQ(static_cast<unsigned long long>(again.code), static_cast<unsigned long long>(kExitIo),
            "--folder refuses to overwrite the store it already wrote");
    TEST_EQ(static_cast<unsigned long long>(read_bytes(out).size()),
            static_cast<unsigned long long>(written.size()),
            "the refusal left the first store alone");

    const Run missing = run_cli("--folder 0x9999 " + source + " writer_cli_folder_missing.pst");
    TEST_EQ(static_cast<unsigned long long>(missing.code), static_cast<unsigned long long>(kExitIo),
            "a NID the input has no folder for exits nonzero");
    TEST_CHECK(!exists("writer_cli_folder_missing.pst"));

    const Run no_cap =
        run_cli("--folder 0x8022 --max-messages 0 " + source + " writer_cli_folder_cap.pst");
    TEST_EQ(static_cast<unsigned long long>(no_cap.code), static_cast<unsigned long long>(kExitIo),
            "--max-messages 0 is a usage error");
    TEST_CHECK(!exists("writer_cli_folder_cap.pst"));
}

// R2 from the 2026-10-13 review: a table the reader could not open has to reach the conversion
// verdict and the CLI exit code, not stay a note in a run that prints RESULT: clean. The store is
// built in memory, written to disk, then the Recipient Table block gets a wrong HNHDR.bClientSig
// with its dwCRC recomputed, the same corruption the review applied to the candidate
// ([MS-PST] 2.3.1.2, 2.2.2.8.1 dwCRC).
constexpr uint16_t kTypeInteger32 = 0x0003; // [MS-OXCDATA] 2.11.1 PtypInteger32
constexpr uint16_t kTypeUnicode = 0x001F;   // [MS-OXCDATA] 2.11.1 PtypString16
constexpr uint16_t kTypeTime = 0x0040;      // [MS-OXCDATA] 2.11.1 PtypTime
constexpr uint16_t kTypeBinary = 0x0102;    // [MS-OXCDATA] 2.11.1 PtypBinary

std::vector<uint8_t> le32_bytes(uint32_t value) {
    return {static_cast<uint8_t>(value & 0xFFu), static_cast<uint8_t>((value >> 8) & 0xFFu),
            static_cast<uint8_t>((value >> 16) & 0xFFu),
            static_cast<uint8_t>((value >> 24) & 0xFFu)};
}

std::vector<uint8_t> u16_bytes(const std::u16string& text) {
    std::vector<uint8_t> bytes;
    for (const char16_t unit : text) {
        bytes.push_back(static_cast<uint8_t>(unit & 0xFFu));
        bytes.push_back(static_cast<uint8_t>((unit >> 8) & 0xFFu));
    }
    return bytes;
}

std::u16string u16(const char* ascii) {
    std::u16string out;
    for (const char* p = ascii; *p != 0; ++p) {
        out.push_back(static_cast<char16_t>(static_cast<unsigned char>(*p)));
    }
    return out;
}

std::vector<uint8_t> blob(size_t size, uint8_t fill) {
    return std::vector<uint8_t>(size, fill);
}

writer::ContentProperty value_of(uint16_t prop_id, uint16_t prop_type, std::vector<uint8_t> bytes) {
    writer::ContentProperty property;
    property.prop_id = prop_id;
    property.prop_type = prop_type;
    property.value = std::move(bytes);
    return property;
}

writer::ContentCell cell_of(uint32_t tag, std::vector<uint8_t> bytes) {
    writer::ContentCell cell;
    cell.tag = tag;
    cell.value = std::move(bytes);
    return cell;
}

// One folder with one message and one recipient: the smallest store that has a Recipient Table to
// break.
writer::StoreRequest one_recipient_request() {
    writer::StoreRequest request;
    writer::ContentFolder folder;
    folder.parent_nid = writer::kNidIpmsubtree;
    folder.name = u16("CLI Recipient Folder");

    writer::ContentMessage message;
    // [MS-PST] 2.4.5.1.1: the tags a Message object PC MUST carry, plus a subject and a plain body.
    message.properties.push_back(value_of(0x001A, kTypeUnicode, u16_bytes(u16("IPM.Note"))));
    message.properties.push_back(value_of(0x0E07, kTypeInteger32, le32_bytes(1)));
    message.properties.push_back(value_of(0x0E08, kTypeInteger32, le32_bytes(4096)));
    message.properties.push_back(value_of(0x0E17, kTypeInteger32, le32_bytes(0)));
    message.properties.push_back(value_of(0x3007, kTypeTime, blob(8, 0x30)));
    message.properties.push_back(value_of(0x3008, kTypeTime, blob(8, 0x31)));
    message.properties.push_back(value_of(0x300B, kTypeBinary, blob(16, 0x40)));
    message.properties.push_back(
        value_of(0x0037, kTypeUnicode, u16_bytes(u16("CLI recipient subject"))));
    message.properties.push_back(value_of(0x1000, kTypeUnicode, u16_bytes(u16("cli body"))));

    writer::ContentRow recipient;
    recipient.cells.push_back(
        cell_of(0x0C150003, le32_bytes(0))); // [MS-PST] 2.4.5.3.1 template column
    recipient.cells.push_back(cell_of(0x3001001F, u16_bytes(u16("Zeta Recipient"))));
    message.recipients.columns = {0x0C150003, 0x3001001F};
    message.recipients.rows.push_back(std::move(recipient));

    folder.messages.push_back(std::move(message));
    request.folders.push_back(std::move(folder));
    return request;
}

void test_a_recipient_table_that_cannot_read_exits_nonzero() {
    const std::string clean = "writer_cli_recipient_clean.pst";
    const std::string broken = "writer_cli_recipient_broken.pst";
    const std::string clean_out = "writer_cli_recipient_clean_out.pst";
    const std::string broken_out = "writer_cli_recipient_broken_out.pst";
    std::remove(clean.c_str());
    std::remove(broken.c_str());
    std::remove(clean_out.c_str());
    std::remove(broken_out.c_str());

    ost2pst::util::Result<writer::StoreOutcome> built =
        writer::build_store(one_recipient_request());
    TEST_OK(built, "build_store wrote a folder with one recipient");
    writer::StoreOutcome outcome = built.take();
    const uint32_t folder_nid =
        outcome.report.folder_nids.empty() ? 0u : outcome.report.folder_nids[0];
    TEST_EQ(static_cast<unsigned long long>(outcome.report.recipients), 1ull,
            "the store carries the one recipient row the request asked for");
    write_bytes(clean, outcome.image.bytes);

    // The Recipient Table is the only block carrying the recipient's display name: a variable-sized
    // column value lives in the Table Context's own heap ([MS-PST] 2.3.4.4.2). The minimum mailbox
    // has other tables with the same 0x0C150003 column, so the column tag alone would not pick this
    // one out.
    const writer::WrittenBlock* table = nullptr;
    const std::vector<uint8_t> marker = u16_bytes(u16("Zeta Recipient"));
    for (const writer::WrittenBlock& block : outcome.image.blocks) {
        if (block.ib + marker.size() > outcome.image.bytes.size()) {
            continue;
        }
        const uint8_t* at = outcome.image.bytes.data() + block.ib;
        for (uint32_t offset = 0; offset + marker.size() <= block.cb; ++offset) {
            if (std::memcmp(at + offset, marker.data(), marker.size()) == 0) {
                table = &block;
                break;
            }
        }
        if (table != nullptr) {
            break;
        }
    }
    TEST_CHECK_MSG(table != nullptr, "the store wrote a Recipient Table data block");
    if (table == nullptr) {
        return;
    }

    // Break the client signature that says "this heap node is a Table Context" and re-sign the
    // block so the NDB layer still accepts it: the failure has to come from the table, not from a
    // corrupt block.
    outcome.image.bytes[table->ib + 3] = 0x8C;
    const uint64_t footprint = ndb::align_allocation(
        ndb::FileProfile::kPst, table->cb + ndb::block_trailer_size(ndb::FileProfile::kPst));
    const uint64_t trailer_at =
        table->ib + footprint - ndb::block_trailer_size(ndb::FileProfile::kPst);
    const uint32_t crc = ost2pst::util::crc32(
        ost2pst::util::ByteView(outcome.image.bytes.data() + table->ib, table->cb, table->ib));
    for (size_t index = 0; index < 4; ++index) {
        outcome.image.bytes[trailer_at + ndb::kBlockTrailerCrcOffset + index] =
            static_cast<uint8_t>((crc >> (8 * index)) & 0xFFu);
    }
    write_bytes(broken, outcome.image.bytes);

    char argument[64]; // the whole --folder/--max-messages line, snprintf truncates silently
    std::snprintf(argument, sizeof argument, "--folder 0x%08X --max-messages 8", folder_nid);

    const Run good = run_cli(std::string(argument) + " " + clean + " " + clean_out);
    TEST_EQ(static_cast<unsigned long long>(good.code), static_cast<unsigned long long>(kExitOk),
            "the same store converts clean while its Recipient Table reads");
    expect_text(good, "recipients        1 rows read, 1 written");
    expect_text(good, "RESULT: clean");
    expect_text(good, "CONVERSION RESULT: complete");

    const Run bad = run_cli(std::string(argument) + " " + broken + " " + broken_out);
    TEST_EQ(
        static_cast<unsigned long long>(bad.code), static_cast<unsigned long long>(kExitFindings),
        "a Recipient Table the reader could not open is a conversion shortfall, not a clean run");
    expect_text(bad, "CONVERSION INCOMPLETE");
    expect_text(bad, "recipient table 1 tables the source has and the reader could not read");
    expect_text(bad, "recipients        0 rows read, 0 written");
    // The store the writer produced is structurally clean; what is not clean is the conversion. The
    // two verdicts print on separate lines so a shortfall cannot hide behind a clean re-read.
    expect_text(bad, "RE-READ RESULT: clean");
    expect_text(bad, "CONVERSION RESULT: incomplete");
}

// A present but unreadable binary payload is a failed conversion, unlike a genuinely absent
// payload. Exercise both through the CLI so matching partial reader/writer counts cannot pass.
ost2pst::msg::SubsetReport read_subset(const std::string& path, uint32_t folder_nid = 0x8082);

void test_attachment_payload_failure_and_absence() {
    for (const int method : {0, 1, 6}) {
        const bool has_payload = method != 0;
        writer::StoreRequest request = one_recipient_request();
        writer::ContentMessage& message = request.folders[0].messages[0];
        writer::ContentAttachment attachment;
        attachment.has_payload = method == 1;
        attachment.has_object_payload = method == 6;
        if (has_payload) {
            attachment.payload = blob(57, 0x5A);
        }
        attachment.properties.push_back(
            value_of(0x3705, kTypeInteger32, le32_bytes(method == 6 ? 6 : 1)));
        message.attachment_objects.push_back(std::move(attachment));
        message.attachments.columns = {0x37050003};
        writer::ContentRow row;
        row.cells.push_back(cell_of(0x37050003, le32_bytes(method == 6 ? 6 : 1)));
        message.attachments.rows.push_back(std::move(row));
        auto built = writer::build_store(request);
        TEST_OK(built, "build attachment failure fixture");
        if (!built.ok()) {
            return;
        }
        writer::StoreOutcome outcome = built.take();
        const std::string stem = method == 6
                                     ? "writer_cli_object"
                                     : (has_payload ? "writer_cli_payload" : "writer_cli_absent");
        const std::string source = stem + ".pst";
        const std::string output = stem + "_out.pst";
        std::remove(output.c_str());
        write_bytes(source, outcome.image.bytes);
        char argument[64];
        std::snprintf(argument, sizeof argument, "--folder 0x%08X --max-messages 8",
                      outcome.report.folder_nids[0]);
        const Run good = run_cli(std::string(argument) + " " + source + " " + output);
        TEST_EQ(good.code, kExitOk, "readable or genuinely absent payload converts successfully");
        expect_text(good, "CONVERSION RESULT: complete");
        if (!has_payload) {
            expect_text(good, "1 objects read, 1 written, 1");
            continue;
        }
        expect_text(good, "57 bytes read from the source, 57 written");
        if (method == 6) {
            const auto reread = read_subset(output);
            TEST_EQ(reread.attachments_opaque, 1, "method 6 survives the complete CLI conversion");
            TEST_CHECK(!reread.messages.empty() && !reread.messages.front().attachments.empty());
            if (!reread.messages.empty() && !reread.messages.front().attachments.empty()) {
                const auto& object = reread.messages.front().attachments.front();
                TEST_CHECK(object.object_data_read && !object.embedded_read);
                TEST_CHECK(object.object_data == blob(57, 0x5A));
            }
        }

        // [MS-PST] 2.3.3: PC leaf records start with wPropId/wPropType followed by dwValueHnid.
        // This synthetic store has exactly one binary 0x3701. Replace its reference with an
        // invalid heap index, retaining a valid NDB CRC so the failure occurs during value read.
        size_t mutations = 0;
        for (const writer::WrittenBlock& block : outcome.image.blocks) {
            for (size_t offset = 0; offset + 8 <= block.cb; ++offset) {
                uint8_t* record = outcome.image.bytes.data() + block.ib + offset;
                if (record[0] != 0x01 || record[1] != 0x37 ||
                    record[2] != (method == 6 ? 0x0D : 0x02) ||
                    record[3] != (method == 6 ? 0 : 0x01)) {
                    continue;
                }
                const auto invalid_hid = le32_bytes(0xFFE0);
                std::memcpy(record + 4, invalid_hid.data(), invalid_hid.size());
                const uint64_t footprint = ndb::align_allocation(
                    ndb::FileProfile::kPst,
                    block.cb + ndb::block_trailer_size(ndb::FileProfile::kPst));
                const uint64_t trailer =
                    block.ib + footprint - ndb::block_trailer_size(ndb::FileProfile::kPst);
                const auto crc = le32_bytes(ost2pst::util::crc32(ost2pst::util::ByteView(
                    outcome.image.bytes.data() + block.ib, block.cb, block.ib)));
                std::memcpy(outcome.image.bytes.data() + trailer + ndb::kBlockTrailerCrcOffset,
                            crc.data(), crc.size());
                ++mutations;
            }
        }
        TEST_EQ(mutations, size_t{1}, "only the attachment payload reference was changed");
        const std::string broken = stem + "_broken.pst";
        const std::string broken_out = stem + "_broken_out.pst";
        std::remove(broken_out.c_str());
        write_bytes(broken, outcome.image.bytes);
        const Run bad = run_cli(std::string(argument) + " " + broken + " " + broken_out);
        TEST_EQ(bad.code, kExitFindings, "unreadable payload must return a conversion failure");
        expect_text(bad, "RE-READ RESULT: clean");
        expect_text(bad, "CONVERSION RESULT: incomplete");
        expect_text(bad, "1 records the source had and the reader could not get the content of");
        TEST_CHECK(bad.output.find("CONVERSION RESULT: complete") == std::string::npos);
        TEST_CHECK(bad.output.find("with no 0x3701 content in the source") == std::string::npos);
    }
}

ost2pst::msg::SubsetReport read_subset(const std::string& path, uint32_t folder_nid) {
    auto file = ost2pst::util::FileReader::open(std::wstring(path.begin(), path.end()));
    TEST_OK(file, "open named-table fixture");
    if (!file.ok())
        return {};
    ost2pst::ltp::LtpReadOptions options;
    options.scan_blocks = false;
    options.build_folders = false;
    auto census = ost2pst::ltp::read_ltp(file.value(), options);
    TEST_OK(census, "read fixture indices and named map");
    if (!census.ok())
        return {};
    ndb::BlockReadCounters counters;
    ndb::FailureLog failures(20);
    ost2pst::ltp::FileBlockSource blocks(file.value(), census.value().profile,
                                         census.value().bbt_index, counters, failures);
    if (folder_nid == 0) {
        for (const auto& node : census.value().nodes.entries())
            if (ost2pst::ltp::nid_type(node.nid) == ost2pst::ltp::kNidTypeNormalMessage) {
                folder_nid = node.nid_parent;
                break;
            }
    }
    auto subset = ost2pst::msg::build_subset(census.value(), blocks, folder_nid,
                                             ost2pst::msg::SubsetOptions());
    TEST_OK(subset, "read named table cells through the production extractor");
    return subset.ok() ? subset.take() : ost2pst::msg::SubsetReport{};
}

void check_named_cell(const std::vector<ost2pst::msg::SubsetValue>& values, uint32_t identity,
                      uint32_t expected_value) {
    size_t found = 0;
    for (const auto& value : values) {
        if (!value.named)
            continue;
        ++found;
        TEST_CHECK(value.name_resolved && value.guid_resolved);
        TEST_EQ(value.numeric_name, identity, "table identity must survive NPID reassignment");
        TEST_CHECK(value.bytes == le32_bytes(expected_value));
    }
    TEST_EQ(found, size_t{1}, "one named table value survives");
}

void test_named_table_identity_roundtrip() {
    // 0: shared PC/TC identity moves down; 1: identity exists only in tables;
    // 2: old NPID becomes another identity; 3: no rows; 4: rows exist but named cells do not.
    for (int scenario = 0; scenario != 5; ++scenario) {
        auto request = one_recipient_request();
        const std::vector<uint8_t> guid = {0x28, 0x03, 0x02, 0, 0, 0, 0, 0,
                                           0xC0, 0,    0,    0, 0, 0, 0, 0x46};
        for (uint32_t identity : {111u, 222u}) {
            writer::NamedProperty name;
            name.name_is_string = false;
            name.numeric_name = identity;
            name.guid = guid;
            request.named_properties.push_back(name);
        }
        auto& message = request.folders[0].messages[0];
        if (scenario == 0 || scenario == 2) {
            auto value = value_of(0x8001, kTypeInteger32, le32_bytes(77));
            value.named = true;
            value.named_index = 1;
            message.properties.push_back(value);
        }
        const uint32_t tag = scenario == 2 ? 0x80000003 : 0x80010003;
        const uint32_t identity = scenario == 2 ? 111u : 222u;
        const writer::ContentColumn named_column(tag, true, scenario == 2 ? 0 : 1);
        message.recipients.columns.push_back(named_column);
        message.recipients.rows[0].cells.push_back(cell_of(tag, le32_bytes(88)));
        message.attachments.columns = {0x37050003, named_column};
        writer::ContentRow row;
        row.cells = {cell_of(0x37050003, le32_bytes(1)), cell_of(tag, le32_bytes(99))};
        message.attachments.rows.push_back(row);
        writer::ContentAttachment attachment;
        attachment.has_payload = true;
        attachment.payload = {1, 2, 3};
        attachment.properties.push_back(value_of(0x3705, kTypeInteger32, le32_bytes(1)));
        message.attachment_objects.push_back(attachment);
        if (scenario == 3) {
            message.recipients.rows.clear();
            message.attachments.rows.clear();
            message.attachment_objects.clear();
        } else if (scenario == 4) {
            message.recipients.rows[0].cells.pop_back();
            message.attachments.rows[0].cells.pop_back();
        }
        auto built = writer::build_store(request);
        TEST_OK(built, "write valid named table source");
        if (!built.ok())
            return;
        const auto stem = "writer_cli_named_" + std::to_string(scenario);
        const auto source = stem + ".pst", output = stem + "_out.pst";
        write_bytes(source, built.value().image.bytes);
        const auto before = read_subset(source);
        TEST_EQ(before.named_unresolved, 0u, "the source has no unresolved identity");
        TEST_EQ(before.messages.size(), size_t{1}, "source message");
        if (before.messages.empty())
            continue;
        if (scenario < 3) {
            check_named_cell(before.messages[0].recipients[0].values, identity, 88);
            check_named_cell(before.messages[0].attachments[0].row_values, identity, 99);
        }
        std::remove(output.c_str());
        const auto result = run_cli("--folder 0x8082 --max-messages 8 " + source + " " + output);
        TEST_EQ(result.code, kExitOk, "valid named tables convert without shortfall");
        const auto after = read_subset(output);
        TEST_EQ(after.named_unresolved, 0u, "all output references must have identities");
        TEST_EQ(after.messages.size(), size_t{1}, "output message");
        if (after.messages.empty())
            continue;
        const size_t row_count = scenario == 3 ? 0 : 1;
        TEST_EQ(after.messages[0].recipients.size(), row_count, "output recipient");
        TEST_EQ(after.messages[0].attachments.size(), row_count, "output attachment");
        if (scenario < 3 && !after.messages[0].recipients.empty())
            check_named_cell(after.messages[0].recipients[0].values, identity, 88);
        if (scenario < 3 && !after.messages[0].attachments.empty())
            check_named_cell(after.messages[0].attachments[0].row_values, identity, 99);
        for (const auto* columns :
             {&after.messages[0].recipient_columns, &after.messages[0].attachment_columns}) {
            size_t named_columns = 0;
            for (const auto& column : *columns) {
                if (!column.named)
                    continue;
                ++named_columns;
                TEST_CHECK(column.name_resolved && column.guid_resolved);
                TEST_EQ(column.numeric_name, identity,
                        "schema identity survives without cell values");
            }
            const size_t expected = 1;
            TEST_EQ(named_columns, expected, "named schema columns survive in both tables");
        }

        if (scenario != 1 && scenario != 3)
            continue;
        // Controlled corruption: this tiny fixture has exactly one named column per TC.
        // Replace those TCOLDESC tags with an unmapped NPID, preserving the NDB CRC.
        auto image = built.value().image;
        const auto original_tag = le32_bytes(tag), missing_tag = le32_bytes(0x8FFF0003);
        size_t mutations = 0;
        for (const auto& block : image.blocks) {
            bool changed = false;
            for (size_t offset = 0; offset + 4 <= block.cb; ++offset) {
                auto* bytes = image.bytes.data() + block.ib + offset;
                if (std::memcmp(bytes, original_tag.data(), 4) != 0)
                    continue;
                std::memcpy(bytes, missing_tag.data(), 4);
                ++mutations;
                changed = true;
            }
            if (!changed)
                continue;
            const auto footprint = ndb::align_allocation(
                ndb::FileProfile::kPst, block.cb + ndb::block_trailer_size(ndb::FileProfile::kPst));
            const auto trailer =
                block.ib + footprint - ndb::block_trailer_size(ndb::FileProfile::kPst);
            const auto crc = le32_bytes(ost2pst::util::crc32(
                ost2pst::util::ByteView(image.bytes.data() + block.ib, block.cb, block.ib)));
            std::memcpy(image.bytes.data() + trailer + ndb::kBlockTrailerCrcOffset, crc.data(), 4);
        }
        TEST_EQ(mutations, size_t{2}, "only the intended TC tags changed");
        const auto broken = stem + "_broken.pst", broken_out = stem + "_broken_out.pst";
        write_bytes(broken, image.bytes);
        std::remove(broken_out.c_str());
        const auto bad = run_cli("--folder 0x8082 --max-messages 8 " + broken + " " + broken_out);
        TEST_EQ(bad.code, kExitFindings, "unmapped TC identity must reach the CLI failure verdict");
        expect_text(bad, "CONVERSION RESULT: incomplete");
        expect_text(bad, "RE-READ RESULT: clean");
    }
}

void test_missing_attachment_table_data_reaches_full_cli() {
    auto request = one_recipient_request();
    // Exercise no-GUID string/numeric names in PCs and empty table schemas.
    request.named_properties = {{u"no-guid-name", true, 0, {}}, {u"", false, 42, {}}};
    auto& message = request.folders.front().messages.front();
    message.properties.push_back({0x8000, kTypeUnicode, u16_bytes(u"value"), false, true, 0});
    message.properties.push_back({0x8001, kTypeInteger32, le32_bytes(73), false, true, 1});
    message.attachments.columns = {{0x80010003, true, 1}};
    request.folders.front().messages.push_back(message);
    auto& damaged = request.folders.front().messages.front();
    writer::ContentAttachment attachment;
    attachment.has_payload = true;
    attachment.payload = {0x31, 0x32, 0x33};
    attachment.properties = {value_of(0x3705, kTypeInteger32, le32_bytes(1))};
    damaged.attachment_objects.push_back(attachment);
    damaged.attachments.rows.push_back({0, {{0x80010003, le32_bytes(99)}}});
    auto built = writer::build_store(request);
    TEST_OK(built, "full CLI attachment/NameID/schema source");
    if (!built.ok())
        return;
    auto outcome = built.take();
    const std::string source = "writer_cli_attachment_table_data.pst";
    write_bytes(source, outcome.image.bytes);
    {
        auto file = ost2pst::util::FileReader::open(std::wstring(source.begin(), source.end()));
        TEST_OK(file, "open source for parsed subnode mutation");
        if (!file.ok())
            return;
        auto census = ost2pst::ltp::read_ltp(file.value(), {});
        TEST_OK(census, "source census for subnode mutation");
        if (!census.ok())
            return;
        auto manifest = ost2pst::msg::build_mailbox_manifest(census.value());
        TEST_OK(manifest, "no-GUID map accepted by planning");
        if (!manifest.ok() || manifest.value().items.empty())
            return;
        auto node = census.value().nodes.node(manifest.value().items.front().source_nid);
        TEST_OK(node, "message owning attachment table");
        if (!node.ok())
            return;
        ndb::BlockReadCounters counters;
        ndb::FailureLog failures;
        ost2pst::ltp::FileBlockSource blocks(file.value(), census.value().profile,
                                             census.value().bbt_index, counters, failures);
        ost2pst::ltp::SubnodeStats stats;
        auto entries =
            ost2pst::ltp::walk_subnode_entries(node.value().bid_sub, blocks, stats, failures);
        TEST_OK(entries, "locate Attachment Table SLENTRY through the parser");
        if (!entries.ok())
            return;
        size_t mutations = 0;
        for (const auto& entry : entries.value()) {
            if (ost2pst::ltp::subnode_nid_key(entry.nid) != 0x671)
                continue;
            const auto* block = census.value().bbt_index.lookup(entry.block_bid);
            TEST_CHECK(block != nullptr);
            if (!block)
                return;
            // SLENTRY.bidData follows its 8-byte NID (MS-PST 2.2.2.8.3.3).
            const auto at = entry.entry_offset + 8;
            TEST_CHECK(at >= block->ib && at + 8 <= block->ib + block->cb);
            if (at < block->ib || at + 8 > block->ib + block->cb)
                return;
            std::fill_n(outcome.image.bytes.begin() + at, 8, uint8_t{0});
            const auto footprint =
                ndb::align_allocation(ndb::FileProfile::kPst,
                                      block->cb + ndb::block_trailer_size(ndb::FileProfile::kPst));
            const auto trailer =
                block->ib + footprint - ndb::block_trailer_size(ndb::FileProfile::kPst);
            const auto crc = le32_bytes(ost2pst::util::crc32(ost2pst::util::ByteView(
                outcome.image.bytes.data() + block->ib, block->cb, block->ib)));
            std::memcpy(outcome.image.bytes.data() + trailer + ndb::kBlockTrailerCrcOffset,
                        crc.data(), crc.size());
            ++mutations;
        }
        TEST_EQ(mutations, size_t{1}, "only one table data reference was cleared");
    }
    write_bytes(source, outcome.image.bytes);
    for (const bool events : {false, true}) {
        const std::string output =
            events ? "writer_cli_attachment_events.pst" : "writer_cli_attachment_full.pst";
        const auto work = std::filesystem::absolute(output + ".work").lexically_normal();
        TEST_CHECK(work.parent_path() == std::filesystem::current_path());
        if (work.parent_path() != std::filesystem::current_path())
            return;
        std::filesystem::remove_all(work);
        for (const auto& suffix : {"", ".report.json", ".items.jsonl"})
            std::remove((output + suffix).c_str());
        const auto result = run_cli((events ? "--events-json " : "") + source + " " + output);
        TEST_EQ(result.code, kExitFindings,
                "unreadable attachment table makes full conversion incomplete");
        const auto report = ost2pst::test::read_text(output + ".report.json");
        TEST_CHECK(report.find("\"status\":\"incomplete\"") != std::string::npos);
        TEST_CHECK(report.find("\"converted_normal\":1") != std::string::npos);
        TEST_CHECK(report.find("\"skipped_corrupt\":1") != std::string::npos);
        const auto ledger = ost2pst::test::read_text(output + ".items.jsonl");
        TEST_CHECK(ledger.find("source.attachment_table_failure") != std::string::npos);
        const auto reread = read_subset(output, 0);
        TEST_EQ(reread.messages.size(), size_t{1}, "healthy neighbour survives");
        if (!reread.messages.empty()) {
            const auto& retained = reread.messages.front();
            TEST_CHECK(retained.attachment_table && retained.attachment_table_read);
            size_t named_columns = 0, named_values = 0;
            for (const auto& column : retained.attachment_columns)
                if (column.named) {
                    ++named_columns;
                    TEST_CHECK(column.guid_index == 0 && column.guid.empty() &&
                               column.numeric_name == 42);
                }
            for (const auto& property : retained.values)
                if (property.named) {
                    ++named_values;
                    TEST_CHECK(property.guid_index == 0 && property.guid.empty());
                    TEST_CHECK(property.name_is_string ? property.name == u"no-guid-name"
                                                       : property.numeric_name == 42);
                }
            TEST_EQ(named_columns, size_t{1}, "empty schema survives full CLI");
            TEST_EQ(named_values, size_t{2}, "both no-GUID name forms survive full CLI");
        }
    }
}

void test_full_conversion_and_resume() {
    const auto directory = std::filesystem::path("writer_cli_full_fixture");
    // This directory contains only the synthetic files owned by this test.
    std::filesystem::remove_all(directory);
    std::filesystem::create_directory(directory);
    const auto source = (directory / "source.pst").string();
    const auto output = (directory / "output.pst").string();
    auto request = one_recipient_request();
    request.folders[0].messages.push_back(request.folders[0].messages.front());
    request.named_properties.push_back({u"full-fixture", true, 0, std::vector<uint8_t>(16, 0x42)});
    for (auto& message : request.folders[0].messages)
        message.properties.push_back({0x8000, kTypeUnicode, u16_bytes(u"named"), false, true, 0});
    auto built = writer::build_store(request);
    TEST_OK(built, "full conversion source fixture");
    if (!built.ok())
        return;
    write_bytes(source, built.value().image.bytes);
    const auto unpublished = (directory / "unpublished.pst").string();
    const auto restarted = run_cli("--resume " + source + " " + unpublished);
    TEST_EQ(restarted.code, kExitOk,
            "resume can restart when initialization never published a workspace");
    const auto converted = run_cli(source + " " + output);
    if (converted.code != kExitOk)
        std::fprintf(stderr, "%s", converted.output.c_str());
    TEST_EQ(converted.code, kExitOk, "full mailbox CLI converts all items");
    expect_text(converted, "CONVERSION RESULT: complete");
    expect_text(converted, "phase=published");
    TEST_CHECK(exists(output) && exists(output + ".report.json") &&
               exists(output + ".items.jsonl"));
    const auto original = read_bytes(output);
    const auto report = ost2pst::test::read_text(output + ".report.json");
    const auto items = ost2pst::test::read_text(output + ".items.jsonl");
    TEST_CHECK(report.find("\"converted_normal\":2") != std::string::npos);
    TEST_CHECK(report.find("\"block_sharing\":{") != std::string::npos);
    TEST_CHECK(report.find("\"shared_references\":0") == std::string::npos);
    TEST_CHECK(report.find("\"index_saturated\":false") != std::string::npos);
    TEST_EQ(std::filesystem::file_size(output + ".work/data.bin"), 0u,
            "completed publication releases staged payload bytes");
    TEST_EQ(std::filesystem::file_size(output + ".work/journal.bin"), 0u,
            "completion receipt replaces the payload journal");
    TEST_CHECK(items.find("CLI recipient subject") == std::string::npos);
    const auto completed = run_cli("--resume " + source + " " + output);
    if (completed.code != kExitOk)
        std::fprintf(stderr, "%s", completed.output.c_str());
    TEST_EQ(completed.code, kExitOk, "completed full conversion resumes idempotently");
    expect_text(completed, "recovered=2 attempted_normal=0 attempted_fai=0");
    TEST_CHECK(read_bytes(output) == original);
    TEST_CHECK(ost2pst::test::read_text(output + ".report.json") == report);
    TEST_CHECK(ost2pst::test::read_text(output + ".items.jsonl") == items);
    const auto collision = run_cli(source + " " + output);
    TEST_EQ(collision.code, kExitIo, "new full conversion refuses owned existing output");
    TEST_CHECK(read_bytes(output) == original);
    const auto force = run_cli("--force " + source + " " + output);
    TEST_EQ(force.code, kExitIo, "full mode cannot replace state via --force");
    TEST_CHECK(read_bytes(output) == original);
    auto changed = built.value().image.bytes;
    changed.back() ^= 1;
    write_bytes(source, changed);
    const auto mismatch = run_cli("--resume " + source + " " + output);
    TEST_EQ(mismatch.code, kExitIo, "resume rejects changed full source digest");
    TEST_CHECK(read_bytes(output) == original);
    write_bytes(source, built.value().image.bytes);
    auto changed_output = original;
    if (!changed_output.empty())
        changed_output.back() ^= 1;
    write_bytes(output, changed_output);
    const auto tampered = run_cli("--resume " + source + " " + output);
    TEST_EQ(tampered.code, kExitIo, "resume refuses modified published file");
    TEST_CHECK(read_bytes(output) == changed_output);
    std::filesystem::remove_all(directory);
}

void test_full_corrupt_neighbour_isolation() {
    const auto directory = std::filesystem::path("writer_cli_full_corrupt_fixture");
    std::filesystem::remove_all(directory);
    std::filesystem::create_directory(directory);
    // The earlier regression already produced the smallest source with a valid NDB
    // CRC and an unreadable Recipient TC. Place valid items on either side of it.
    auto request = one_recipient_request();
    auto& messages = request.folders[0].messages;
    messages.push_back(messages.front());
    request.named_properties.push_back({u"full-fixture", true, 0, std::vector<uint8_t>(16, 0x42)});
    for (auto& message : messages)
        message.properties.push_back({0x8000, kTypeUnicode, u16_bytes(u"named"), false, true, 0});
    messages.push_back(messages.front());
    auto built = writer::build_store(request);
    TEST_OK(built, "three-item corrupt-neighbour fixture");
    if (!built.ok())
        return;
    auto image = built.take().image;
    const auto source = (directory / "source.pst").string();
    const auto output = (directory / "output.pst").string();
    write_bytes(source, image.bytes);
    uint64_t failed_bid = 0;
    {
        auto file = ost2pst::util::FileReader::open(std::wstring(source.begin(), source.end()));
        TEST_OK(file, "open corrupt-neighbour fixture");
        if (!file.ok())
            return;
        ost2pst::ltp::LtpReadOptions options;
        options.scan_blocks = false;
        options.build_folders = false;
        auto census = ost2pst::ltp::read_ltp(file.value(), options);
        TEST_OK(census, "read neighbour fixture index");
        if (!census.ok())
            return;
        auto manifest = ost2pst::msg::build_mailbox_manifest(census.value());
        TEST_OK(manifest, "reserve neighbour identities");
        if (!manifest.ok() || manifest.value().items.size() != 3)
            return;
        ndb::BlockReadCounters counters;
        ndb::FailureLog failures;
        ost2pst::ltp::FileBlockSource blocks(file.value(), census.value().profile,
                                             census.value().bbt_index, counters, failures);
        auto node = census.value().nodes.node(manifest.value().items[1].source_nid);
        TEST_OK(node, "middle item reference");
        if (node.ok())
            failed_bid = node.value().bid_data;
    }
    bool changed = false;
    for (const auto& block : image.blocks) {
        if (block.bid != failed_bid)
            continue;
        image.bytes[block.ib + 3] = 0x7C; // PC changed to TC, valid block CRC below
        const auto footprint = ndb::align_allocation(
            ndb::FileProfile::kPst, block.cb + ndb::block_trailer_size(ndb::FileProfile::kPst));
        const auto trailer = block.ib + footprint - ndb::block_trailer_size(ndb::FileProfile::kPst);
        const auto crc = le32_bytes(ost2pst::util::crc32(
            ost2pst::util::ByteView(image.bytes.data() + block.ib, block.cb, block.ib)));
        std::memcpy(image.bytes.data() + trailer + ndb::kBlockTrailerCrcOffset, crc.data(),
                    crc.size());
        changed = true;
    }
    TEST_CHECK(changed);
    write_bytes(source, image.bytes);
    const auto converted = run_cli(source + " " + output);
    if (converted.code != kExitFindings)
        std::fprintf(stderr, "%s", converted.output.c_str());
    TEST_EQ(converted.code, kExitFindings, "corrupt middle item yields verified salvage output");
    expect_text(converted, "CONVERSION RESULT: incomplete");
    const auto report = ost2pst::test::read_text(output + ".report.json");
    TEST_CHECK(report.find("\"converted_normal\":2") != std::string::npos);
    TEST_CHECK(report.find("\"skipped_corrupt\":1") != std::string::npos);
    const auto original = read_bytes(output);
    const auto resumed = run_cli("--resume " + source + " " + output);
    TEST_EQ(resumed.code, kExitFindings, "salvage resume must not become successful");
    expect_text(resumed, "recovered=3 attempted_normal=0 attempted_fai=0");
    TEST_CHECK(read_bytes(output) == original);
    std::filesystem::remove_all(directory);
}

} // namespace

int main() {
    test_an_existing_file_is_refused();
    test_force_overwrites_when_asked();
    test_a_missing_directory_leaves_no_file();
    test_usage_errors_write_nothing();
    test_folder_conversion_of_a_written_store();
    test_a_recipient_table_that_cannot_read_exits_nonzero();
    test_attachment_payload_failure_and_absence();
    test_named_table_identity_roundtrip();
    test_missing_attachment_table_data_reaches_full_cli();
    test_full_conversion_and_resume();
    test_full_corrupt_neighbour_isolation();
    return ost2pst::test::finish("writer_cli_test");
}
