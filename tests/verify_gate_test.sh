#!/usr/bin/env bash
# W4 and W5: scripts/verify.sh must keep "the step ran and its result was bad" (FAIL, nonzero exit) apart
# from "a prerequisite was missing, so the step never ran" (NOT VERIFIED), and it must not delete or
# overwrite a read-only input or an output it does not own. One injected fault per case, against the real
# gate script, so the failure handling itself is tested and not just one happy run.
#
# The sample is the small generated PST rather than the 2.6 GB OST: the gates still run for real, they just
# run fast enough to belong in CTest. Each case generates into its own file named after the case under
# build/verify-gate-test, so the sample stays the read-only input the gate is supposed to protect and no
# case inherits another case's output.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

tmp=$(mktemp -d build/verify-gate-test-XXXXXX) || exit 1
echo "verification evidence: $tmp"

CONFIG="${OST2PST_GATE_CONFIG:-Debug}"
BUILD="${OST2PST_GATE_BUILD:-build}"
sample="$tmp/current-writer-sample.pst"
# Generate the read-only fixture from this build, not a possibly stale user candidate.
if ! "$BUILD/$CONFIG/ost2pst.exe" --empty "$sample" > "$tmp/sample-generation.txt" 2>&1; then
    echo "FAIL verify_gate_test: could not generate the current writer fixture"
    exit 1
fi
failures=0
# The outer CTest runs the full deterministic corpus once. Injected gate runs test fault
# propagation, not repeated fuzz coverage; the script must report their unit scope NOT VERIFIED.
export OST2PST_GATE_META=1

cat > "$tmp/broken-probe.cpp" <<'CPP'
int main() { this is not C++ }
CPP

# Runs, prints a folder tree, and stops before COMPLETE.
cat > "$tmp/probe-stops-early.sh" <<'SH'
#!/usr/bin/env bash
echo "folder type 0x00 name= sub_folders=0 sub_messages=0 sub_associated=0"
echo "the probe walked off the end here"
exit 0
SH

# Prints a COMPLETE tree whose Deleted Items folder claims one message the real file does not have.
cat > "$tmp/probe-wrong-count.sh" <<'SH'
#!/usr/bin/env bash
echo "folder type 0x00 name= sub_folders=3 sub_messages=0 sub_associated=0"
echo "  folder type 0x00 name=SPAM Search Folder 2 sub_folders=0 sub_messages=0 sub_associated=0"
echo "  folder type 0x00 name=Top of Personal Folders sub_folders=1 sub_messages=1 sub_associated=0"
echo "    folder type 0x00 name=Deleted Items sub_folders=0 sub_messages=0 sub_associated=0"
echo "  folder type 0x00 name=Search Root sub_folders=0 sub_messages=0 sub_associated=0"
echo "COMPLETE"
exit 0
SH
chmod +x "$tmp/probe-stops-early.sh" "$tmp/probe-wrong-count.sh"

run_case() { # name, expected exit (zero|nonzero), step, status, then the env overrides for this case
    local name="$1" expect_code="$2" step="$3" status="$4"
    shift 4
    local log="$tmp/$name.txt"
    local code=0
    if env OST2PST_SAMPLE="$sample" CONFIG="$CONFIG" BUILD="$BUILD" LOGDIR="$tmp" CANDIDATE="$tmp/$name.pst" "$@" \
           bash scripts/verify.sh > "$log" 2>&1; then
        code=0
    else
        code=$?
    fi
    local ok=1
    if [ "$expect_code" = nonzero ] && [ "$code" -eq 0 ]; then
        echo "  CASE $name: verify.sh exited 0 although the injected fault should have failed it"
        ok=0
    fi
    if [ "$expect_code" = zero ] && [ "$code" -ne 0 ]; then
        echo "  CASE $name: verify.sh exited $code although no step ran into a fault"
        ok=0
    fi
    if ! grep -qE "^  ${step} +${status}$" "$log"; then
        echo "  CASE $name: the summary says nothing about '$step' being '$status'"
        grep -E '^  [A-Za-z].*(PASS|FAIL|NOT VERIFIED)$' "$log" | sed 's/^/    /'
        ok=0
    fi
    if [ "$ok" = 1 ]; then
        echo "  ok $name ($step $status, exit $code)"
    else
        echo "  log: $log"
        failures=$((failures + 1))
    fi
}

assert_summary() { # a second line the same run's summary has to carry
    local name="$1" step="$2" status="$3"
    if ! grep -qE "^  $step +$status$" "$tmp/$name.txt"; then
        echo "  CASE $name: the summary says nothing about '$step' being '$status'"
        failures=$((failures + 1))
    fi
}

# 1. The writer ran and could not create its output: FAIL, and the gates that need the file did not run.
run_case generate-fails nonzero "empty pst" FAIL \
    CANDIDATE="$tmp/no-such-dir/m4-empty.pst"
assert_summary generate-fails "probe out.pst" "NOT VERIFIED"

# 2. The independent probe ran and did not compile: FAIL, not NOT VERIFIED.
run_case probe-compile-fails nonzero "libpff tree vs ltp" FAIL \
    PROBE_SRC="$tmp/broken-probe.cpp"

# 3. The independent probe ran, exited 0 and never reached COMPLETE: FAIL.
run_case probe-stops-early nonzero "libpff tree vs ltp" FAIL \
    PROBE="$tmp/probe-stops-early.sh"

# 4. The independent probe ran and the trees differ in a per-folder count: FAIL.
run_case tree-count-differs nonzero "libpff tree vs ltp" FAIL \
    PROBE="$tmp/probe-wrong-count.sh"

# 5. A prerequisite is missing: NOT VERIFIED, and only STRICT=1 turns that into a failed gate.
run_case prereq-missing zero "libpff tree vs ltp" "NOT VERIFIED" \
    LIBPFF="$tmp/no-libpff"
assert_summary prereq-missing "unit tests" "NOT VERIFIED"
run_case prereq-missing-strict nonzero "libpff tree vs ltp" "NOT VERIFIED" \
    LIBPFF="$tmp/no-libpff" STRICT=1

# W5: the gate must not delete or overwrite a read-only input, and it must not delete an output it does not
# own. Each case points CANDIDATE at a file it is not allowed to replace and then checks that the file
# still holds the same bytes: a gate that deleted and regenerated it would have changed them.
guard_case() { # name, expected exit (zero|nonzero), expected "empty pst" status, the file whose bytes must
    # survive, then the env overrides for this case
    local name="$1" expect_code="$2" status="$3" input="$4"
    shift 4
    local log="$tmp/$name.txt" before after code=0 ok=1
    before=$(sha256sum < "$input" | cut -d' ' -f1)
    if env OST2PST_SAMPLE="$sample" CONFIG="$CONFIG" BUILD="$BUILD" LOGDIR="$tmp" "$@" \
           bash scripts/verify.sh > "$log" 2>&1; then
        code=0
    else
        code=$?
    fi
    after=$(sha256sum < "$input" 2>/dev/null | cut -d' ' -f1)
    [ -n "$after" ] || after="the file is gone"
    if [ "$before" != "$after" ]; then
        echo "  CASE $name: $input changed from $before to $after"
        ok=0
    fi
    if [ "$expect_code" = nonzero ] && [ "$code" -eq 0 ]; then
        echo "  CASE $name: verify.sh exited 0 although CANDIDATE was not allowed to replace $input"
        ok=0
    fi
    if [ "$expect_code" = zero ] && [ "$code" -ne 0 ]; then
        echo "  CASE $name: verify.sh exited $code although the replace was authorized"
        ok=0
    fi
    if ! grep -qE "^  empty pst +$status$" "$log"; then
        echo "  CASE $name: the summary does not report 'empty pst' as '$status'"
        grep -E '^  [A-Za-z].*(PASS|FAIL|NOT VERIFIED)$' "$log" | sed 's/^/    /'
        ok=0
    fi
    if [ "$ok" = 1 ]; then
        echo "  ok $name (empty pst $status, exit $code, $input unchanged)"
    else
        echo "  log: $log"
        failures=$((failures + 1))
    fi
}

marker="$tmp/marker.pst"
printf 'USER DATA KEEP' > "$marker"

# 6. CANDIDATE names the read-only oracle: refused before anything was deleted, and the oracle survives.
guard_case candidate-is-oracle nonzero FAIL "$marker" \
    CANDIDATE="$marker" ORACLE="$marker"
assert_summary candidate-is-oracle "probe out.pst" "NOT VERIFIED"

# 7. CANDIDATE names the read-only OST sample.
guard_case candidate-is-sample nonzero FAIL "$marker" \
    CANDIDATE="$marker" OST2PST_SAMPLE="$marker"

# 8. CANDIDATE reaches the oracle through an alias rather than the same spelling: a ".." detour, and the
# same name in another case (Windows names are case-insensitive).
guard_case candidate-dotdot-alias-of-oracle nonzero FAIL "$marker" \
    CANDIDATE="$tmp/../verify-gate-test/marker.pst" ORACLE="$marker"
guard_case candidate-case-alias-of-oracle nonzero FAIL "$marker" \
    CANDIDATE="$tmp/MARKER.PST" ORACLE="$marker"

# 9. An existing output this script does not own survives the run. OVERWRITE=1 is what authorizes the
# replace, and then it goes through the CLI's --force instead of a delete.
guard_case existing-output-kept nonzero FAIL "$marker" \
    CANDIDATE="$marker"
printf 'USER DATA KEEP' > "$tmp/authorized.pst"
guard_case existing-output-authorized zero PASS "$sample" \
    CANDIDATE="$tmp/authorized.pst" OVERWRITE=1
if ! cmp -s "$tmp/authorized.pst" "$sample"; then
    echo "  CASE existing-output-authorized: OVERWRITE=1 did not write the candidate at the custom path"
    failures=$((failures + 1))
fi
# M5: the subset steps run for real whenever a folder is named, and a folder the input does not have is a
# FAIL rather than a step that never ran. The fixture here is the 271 KB store this build wrote, whose
# IPM_SUBTREE (0x8022) is a folder with no messages, so the 50-message / 5-attachment floor is lowered to
# 0 in the two cases that exercise the plumbing; the floor itself gets its own case.
assert_summary generate-fails "subset convert" "NOT VERIFIED"

run_case subset-folder-missing nonzero "subset convert" FAIL \
    SUBSET_FOLDER=0x9999 SUBSET_CANDIDATE="$tmp/subset-missing.pst"
assert_summary subset-folder-missing "subset vs pffexport" "NOT VERIFIED"

run_case subset-empty-folder zero "subset convert" PASS \
    SUBSET_FOLDER=0x8022 SUBSET_CANDIDATE="$tmp/subset-empty.pst" \
    SUBSET_MIN_MESSAGES=0 SUBSET_MIN_ATTACHMENTS=0
assert_summary subset-empty-folder "subset vs pffexport" PASS

run_case subset-below-floor nonzero "subset vs pffexport" FAIL \
    SUBSET_FOLDER=0x8022 SUBSET_CANDIDATE="$tmp/subset-floor.pst"

if [ "$failures" -ne 0 ]; then
    echo "FAIL verify_gate_test: $failures injected-fault case(s) handled wrongly"
    exit 1
fi
echo "PASS verify_gate_test"
