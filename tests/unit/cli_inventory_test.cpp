// C1 is about the verdict a run of the inventory gets. This checks the seam that acts on it: `ostinfo
// --inventory` has to leave with the corrupt exit code when a structure it counted did not read, because a
// green CLI run is the first thing a reviewer (or a script) trusts. The file is the same format-true
// fixture the LTP tests build, so the only thing that changes between the two cases is one BTH header field.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#include "ost2pst/ltp/layout.h"
#include "ost_fixture.h"
#include "test_support.h"

namespace {

using namespace ost2pst;
using test::ost::bth_header;
using test::ost::build_file;
using test::ost::heap_node;
using test::ost::NodeSpec;
using test::ost::pc_records;
using test::ost::utf16;

// src/cli/ostinfo.cpp: kExitOk 0, kExitUsage/kExitIo 1, kExitRefusal 2, kExitCorrupt 3.
constexpr int kExitOk = 0;
constexpr int kExitCorrupt = 3;

void write_file(const std::string &name, const std::vector<uint8_t> &bytes) {
    std::ofstream out(name, std::ios::binary);
    out.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

struct Run {
    int code = -1;
    std::string output;
};

// The CLI is a separate process, so the fixture and its report stay in the test's own directory and the
// report is read back instead of being re-derived here.
Run run_inventory(const std::string &name) {
    const std::string log = name + ".out";
    // Unquoted on purpose: cmd /c strips the outer pair of quotes of a command line that has more than
    // two of them, which merges the executable and its arguments into one token. Neither path has a space.
    const std::string command =
        std::string(OST2PST_OSTINFO_EXE) + " --inventory --no-folders " + name + " > " + log + " 2>&1";
    Run run;
    run.code = std::system(command.c_str());
    run.output = ost2pst::test::read_text(log);
    std::remove(log.c_str());
    return run;
}

// One Message object whose Property Context reads, and the same object with a BTH that contradicts the
// bClientSig its nidType announces.
std::vector<uint8_t> fixture(bool broken_pc) {
    std::vector<std::vector<uint8_t>> allocations;
    allocations.push_back(bth_header(broken_pc ? 4 : 2, broken_pc ? 4 : 6, broken_pc ? 0 : 0x40));
    if (!broken_pc) {
        allocations.push_back(pc_records({{0x1000, 0x001F, 0x60}}));
        allocations.push_back(utf16("body"));
    }
    return build_file({{0x100, ltp::kNidTypeNormalMessage, ltp::kNidRootFolder, false,
                        heap_node(ltp::kClientSigPc, 0x20, allocations)}});
}

// TEST_CHECK takes one argument, so a missing line in the child's report names itself.
void expect_text(const Run &run, const char *needle) {
    if (run.output.find(needle) == std::string::npos) {
        ost2pst::test::report_failure(__FILE__, __LINE__, std::string("the CLI report has no: ") + needle);
    }
}

// The same Message object with a body record that names a heap id its page map does not hold. The record is
// there, so the source is not missing a body -- this reader could not get the one it named.
std::vector<uint8_t> unreadable_value_fixture() {
    std::vector<std::vector<uint8_t>> allocations;
    allocations.push_back(bth_header(2, 6, 0x40));
    allocations.push_back(pc_records({{0x1000, 0x001F, 0x80}}));
    allocations.push_back(utf16("body"));
    return build_file({{0x100, ltp::kNidTypeNormalMessage, ltp::kNidRootFolder, false,
                        heap_node(ltp::kClientSigPc, 0x20, allocations)}});
}

void test_a_clean_inventory_exits_zero() {
    write_file("cli_inventory_clean.ost", fixture(false));
    const Run run = run_inventory("cli_inventory_clean.ost");
    expect_text(run, "INVENTORY: NODE TYPES");
    expect_text(run, "STATUS (whether this run read everything it counted)");
    expect_text(run, "1 readable");
    expect_text(run, "RESULT: clean");
    TEST_EQ(run.code, kExitOk, "a file the inventory read whole exits 0");
}

void test_an_unreadable_property_context_exits_corrupt() {
    write_file("cli_inventory_bad.ost", fixture(true));
    const Run run = run_inventory("cli_inventory_bad.ost");
    expect_text(run, "INVENTORY: NODE TYPES");
    expect_text(run, "RESULT: findings present");
    expect_text(run, "decode failure");
    TEST_EQ(run.code, kExitCorrupt, "a Property Context that did not read exits 3");
}

// C2: content a record named and this reader could not get is a finding the CLI has to act on, not a body
// count that quietly drops by one.
void test_content_a_value_source_refused_exits_corrupt() {
    write_file("cli_inventory_content.ost", unreadable_value_fixture());
    const Run run = run_inventory("cli_inventory_content.ost");
    expect_text(run, "body content");
    expect_text(run, "1 unreadable");
    expect_text(run, "content unreadable");
    expect_text(run, "RESULT: findings present");
    TEST_EQ(run.code, kExitCorrupt, "a body value that did not read exits 3");
}

} // namespace

int main() {
    test_a_clean_inventory_exits_zero();
    test_an_unreadable_property_context_exits_corrupt();
    test_content_a_value_source_refused_exits_corrupt();
    return ost2pst::test::finish("cli_inventory_test");
}
