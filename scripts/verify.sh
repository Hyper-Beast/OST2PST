#!/usr/bin/env bash
# Gate 1 (DEVELOPMENT.md). Needs no Outlook.
#
# Two outcomes are kept apart on purpose:
#   NOT VERIFIED - required scope was not verified (missing prerequisite or partial meta-test scope).
#   FAIL         - the step ran and its own result was bad: a compile error, a nonzero exit, a report this
#                  script cannot parse, or a comparison that did not match.
# A FAIL always makes the script exit nonzero. NOT VERIFIED does so only under STRICT=1, the mode the M4
# acceptance run uses: a required gate without complete scope has not been passed.
#
# Every input a gate needs is overridable, which is what lets tests/verify_gate_test.sh inject a real
# fault into a real run: BUILD, CONFIG, OST2PST_SAMPLE, CANDIDATE, ORACLE, LIBPFF, PROBE_SRC (the tree
# probe source that gets compiled), PROBE (the command that enumerates the candidate tree),
#   SUBSET_FOLDER / SUBSET_MAX / SUBSET_CANDIDATE (the folder to convert, its message cap and the store it
#   writes), LOGDIR (where
# the gate logs go, so an injected-fault run cannot overwrite the accepted ones), OVERWRITE (authorize
# replacing a CANDIDATE this script does not own), STRICT.
# OST2PST_GATE_META=1 is only for injected fault tests: it excludes the repeated truncation label
# and records unit coverage NOT VERIFIED. Normal/strict acceptance retains the whole corpus.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
REPO="$PWD"

CONFIG="${CONFIG:-Release}"
BUILD="${BUILD:-build}"
CANDIDATE="${CANDIDATE:-$BUILD/m4-empty.pst}"
LIBPFF="${LIBPFF:-third_party/libpff/vs2022/Release/x64}"
ORACLE="${ORACLE:-docs/1.pst}"
PROBE_SRC="${PROBE_SRC:-tests/tools/blank_pst_libpff_probe.cpp}"
PROBE="${PROBE:-$BUILD/m4_libpff_probe.exe}"
SUBSET_FOLDER="${SUBSET_FOLDER:-}"
SUBSET_MAX="${SUBSET_MAX:-128}"
SUBSET_CANDIDATE="${SUBSET_CANDIDATE:-$BUILD/m5-subset.pst}"
# The M5 exit criteria (DEVELOPMENT.md + DEVELOPMENT.md) ask for one folder with at least 50 messages and
# 5 attachments; the floor is overridable so the meta-test can run the step against a small store.
SUBSET_MIN_MESSAGES="${SUBSET_MIN_MESSAGES:-50}"
SUBSET_MIN_ATTACHMENTS="${SUBSET_MIN_ATTACHMENTS:-5}"
STRICT="${STRICT:-0}"
LOGDIR="${LOGDIR:-$BUILD}"
mkdir -p "$LOGDIR"
report=()

record() { report+=("$1|$2"); }

# The toolchain only exists inside VsDevCmd, which means cmd.exe. Git Bash and WSL bash reach it
# differently, and MSYS rewrites a bare /c into a drive letter, so the slash count depends on the shell.
case "$(uname -s)" in
MINGW* | MSYS* | CYGWIN*)
    CMD_BIN=cmd
    CMD_SLASH='//c'
    ;;
*)
    CMD_BIN=/mnt/c/Windows/System32/cmd.exe
    CMD_SLASH='/c'
    ;;
esac
if ! command -v "$CMD_BIN" >/dev/null 2>&1 && [ ! -x "$CMD_BIN" ]; then
    CMD_BIN=''
fi

dev() { # run a command inside the VS dev environment
    # scripts/dev.cmd sets VsDevCmd plus CMAKE_GENERATOR/PLATFORM, so no nested quoting here.
    [ -n "$CMD_BIN" ] || return 127
    "$CMD_BIN" "$CMD_SLASH" "scripts\dev.cmd $1"
}

win_path() { # libpff tools refuse a \\?\-prefixed POSIX path, so hand them a Windows one.
    # Absolute first: pffexport runs with cwd = $BUILD, and cygpath leaves a relative path relative,
    # which would make it look for build/docs/1.pst. wslpath resolves one, cygpath does not.
    local absolute="$1"
    case "$absolute" in
    [A-Za-z]:*) ;;
    /*) ;;
    *) absolute="$PWD/$absolute" ;;
    esac
    if command -v wslpath >/dev/null 2>&1; then
        wslpath -w "$absolute"
    elif command -v cygpath >/dev/null 2>&1; then
        cygpath -w "$absolute"
    else
        return 1
    fi
}

strip_cr() { # a Windows binary writes CRLF into the log even when the shell is a POSIX one
    local file="$1"
    [ -f "$file" ] || return 0
    tr -d '\r' < "$file" > "$file.cr" && mv "$file.cr" "$file"
}

posix_path() { # accept D:\x or D:/x and answer with a path this shell can stat
    local path="${1//\\//}"
    if [ -f "$path" ]; then
        echo "$path"
        return 0
    fi
    case "$path" in
    [A-Za-z]:/*)
        local drive="$(printf '%s' "${path:0:1}" | tr 'A-Z' 'a-z')"
        local mapped="/mnt/$drive/${path:3}"
        if [ -f "$mapped" ]; then
            echo "$mapped"
            return 0
        fi
        ;;
    esac
    return 1
}

to_posix() { # any accepted path form (Windows drive form, D:/x, /d/x, ./x) -> a path this shell can cd into
    local path="$1"
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -u "$path"
        return 0
    fi
    if command -v wslpath >/dev/null 2>&1; then
        wslpath -u "$path"
        return 0
    fi
    printf '%s\n' "$path"
}

path_key() { # one key per path, for the read-only input checks below: the physical directory plus the file
    # name in lower case (Windows names are case-insensitive), plus device:inode when the file exists, so a
    # link or a path alias that reaches the same file produces the same key. Without a path helper the
    # drive-letter form cannot be resolved, and the caller treats that as "cannot prove", never as "safe".
    local path="$1" absolute base dir physical inode key
    [ -n "$path" ] || return 1
    absolute=$(to_posix "$path") || return 1
    case "$absolute" in
    /*) ;;
    *) absolute="$PWD/$absolute" ;;
    esac
    base="${absolute##*/}"
    dir="${absolute%/*}"
    [ -n "$dir" ] || dir="/"
    if [ -d "$dir" ]; then
        physical=$(cd "$dir" 2>/dev/null && pwd -P) || return 1
    else
        physical="$dir"
    fi
    key=$(printf '%s' "$physical/$base" | tr 'A-Z' 'a-z')
    if [ -e "$physical/$base" ]; then
        inode=$(stat -c '%d:%i' "$physical/$base" 2>/dev/null) || inode=''
        [ -n "$inode" ] && key="$key#$inode"
    fi
    printf '%s\n' "$key"
}

same_file() { # do two path_key keys name the same file? Same path, or the same device:inode when both exist.
    local left="$1" right="$2" left_path="${1%%#*}" right_path="${2%%#*}"
    if [ "$left_path" = "$right_path" ]; then
        return 0
    fi
    if [ "$left" != "$left_path" ] && [ "$right" != "$right_path" ] &&
        [ "${left#*#}" = "${right#*#}" ]; then
        return 0
    fi
    return 1
}

# Exporters run inside BUILD. Resolve the tool from the repository, regardless of BUILD depth.
pffexport_path=''
if [ -f "$LIBPFF/pffexport.exe" ]; then
    libpff_directory=$(to_posix "$LIBPFF") || exit 1
    libpff_directory=$(cd "$libpff_directory" && pwd -P) || exit 1
    pffexport_path="$libpff_directory/pffexport.exe"
fi

# The OST sample and the Outlook blank PST are read-only inputs: this gate reads them and must never delete
# or replace either one, whatever CANDIDATE says.
readonly_inputs=()
if [ -n "${OST2PST_SAMPLE:-}" ]; then
    if sample_key=$(path_key "$OST2PST_SAMPLE"); then
        readonly_inputs+=("OST2PST_SAMPLE|$sample_key")
    fi
fi
if oracle_key=$(path_key "$ORACLE"); then
    readonly_inputs+=("ORACLE|$oracle_key")
fi
default_candidate_key=$(path_key "$BUILD/m4-empty.pst") || default_candidate_key=''
default_subset_candidate_key=$(path_key "$SUBSET_CANDIDATE") || default_subset_candidate_key=''

# One canonical line per folder: "<display path>|<sub-folders>|<messages>|<associated>". The display path
# is built from the indentation, so a folder hanging off the wrong parent produces a different line, and
# the counts are the folder's own, not a total that could hide a shift. Both sides have to say the same
# thing about the same file before the tree is called identical.
ltp_tree_lines() { # ostinfo --ltp FOLDER TREE -> canonical lines
    awk '
        function canonical(depth, name) {
            if (name == "(empty)") { name = "" }
            if (depth == 0) { path[0] = name }
            else if (path[depth - 1] == "") { path[depth] = name }
            else { path[depth] = path[depth - 1] "/" name }
            return path[depth]
        }
        /^FOLDER TREE/ { in_tree = 1; next }
        !in_tree { next }
        /^[A-Za-z]/ { in_tree = 0; next }
        {
            if (!match($0, /^ +/)) { next }
            depth = (RLENGTH - 2) / 2
            if (depth < 0) { next }
            if ($0 !~ /msgs +[0-9]+ held +[0-9]+ assoc +[0-9]+ aheld +[0-9]+ sub/) { next }
            sub(/^ +/, "")
            name = $0
            sub(/.*sub  +/, "", name)
            print canonical(depth, name) "|" $10 "|" $2 "|" $6
        }
    ' "$1"
}

libpff_tree_lines() { # the libpff API probe's folder lines -> canonical lines
    awk '
        function canonical(depth, name) {
            if (depth == 0) { path[0] = name }
            else if (path[depth - 1] == "") { path[depth] = name }
            else { path[depth] = path[depth - 1] "/" name }
            return path[depth]
        }
        {
            if ($0 !~ /^ *folder type 0x[0-9A-Fa-f]+ name=/) { next }
            match($0, /^ */)
            if (split($0, parts, / sub_(folders|messages|associated)=/) != 4) { next }
            name = parts[1]
            sub(/^.*name=/, "", name)
            print canonical(RLENGTH / 2, name) "|" parts[2] "|" parts[3] "|" parts[4]
        }
    ' "$1"
}

tree_total() { # the messages column summed over the canonical lines
    awk -F'|' '{ sum += $3 + $4 } END { print sum + 0 }' "$1"
}

echo "== layer check"
if ./scripts/check_layers.sh; then record "layer check" PASS; else record "layer check" FAIL; fi

echo "== configure + build ($CONFIG)"
if [ -z "$CMD_BIN" ]; then
    echo "cmd.exe not reachable from this shell; set CMD_BIN"
    record "build" "NOT VERIFIED"
    record "unit tests" "NOT VERIFIED"
elif dev "cmake -S . -B $BUILD" && dev "cmake --build $BUILD --config $CONFIG"; then
    record "build" PASS
    echo "== unit tests"
    # verify_gate_test is this script's own meta-test: running it here would make verify.sh call itself
    # through CTest. The full CTest run (and the batch acceptance) is where it runs.
    test_scope=""
    if [ "${OST2PST_GATE_META:-0}" = 1 ]; then
        test_scope="-LE truncation"
        echo "Injected meta-test scope: truncation corpus belongs to outer CTest; unit coverage is partial"
    fi
    if dev "ctest --test-dir $BUILD -C $CONFIG --output-on-failure -E verify_gate_test $test_scope"; then
        if [ "${OST2PST_GATE_META:-0}" = 1 ]; then
            record "unit tests" "NOT VERIFIED"
        else
            record "unit tests" PASS
        fi
    else
        record "unit tests" FAIL
    fi
else
    echo "configure or build failed"
    record "build" FAIL
    record "unit tests" "NOT VERIFIED"
fi

echo "== ostinfo --probe \$OST2PST_SAMPLE"
sample_posix=''
sample_arg=''
if [ -z "${OST2PST_SAMPLE:-}" ]; then
    echo "OST2PST_SAMPLE unset"
    record "probe sample" "NOT VERIFIED"
elif ! sample_posix=$(posix_path "$OST2PST_SAMPLE"); then
    echo "OST2PST_SAMPLE does not name a readable file: $OST2PST_SAMPLE"
    record "probe sample" "NOT VERIFIED"
else
    # The reader opens the file through the Windows API, so it gets a Windows path when one is available.
    sample_arg="$sample_posix"
    if sample_win=$(win_path "$sample_posix"); then
        sample_arg="$sample_win"
    fi
    if "./$BUILD/$CONFIG/ostinfo.exe" --probe "$sample_arg" > "$LOGDIR/gate1-probe-sample.txt" 2>&1; then
        record "probe sample" PASS
    else
        record "probe sample" FAIL
    fi
    strip_cr "$LOGDIR/gate1-probe-sample.txt"
    tail -6 "$LOGDIR/gate1-probe-sample.txt"
fi

echo "== ost2pst --empty $CANDIDATE"
candidate_ready=0
if [ ! -x "./$BUILD/$CONFIG/ost2pst.exe" ]; then
    echo "no ost2pst binary for $BUILD/$CONFIG"
    record "empty pst" "NOT VERIFIED"
elif ! candidate_key=$(path_key "$CANDIDATE"); then
    echo "no path helper for CANDIDATE, so the gate cannot prove it is not a read-only input: $CANDIDATE"
    record "empty pst" "NOT VERIFIED"
else
    # W5: this gate used to rm -f whatever CANDIDATE named before it ever asked the CLI, so a mistyped
    # output path deleted the read-only input it was meant to compare against and the CLI's own refusal
    # never got the chance to run. Nothing is deleted here. The candidate is compared against every
    # read-only input first, and an existing file is replaced only when this script owns the path or the
    # caller authorized it with OVERWRITE=1 - and then through the CLI's --force, not a blind delete.
    collision=''
    for input in "${readonly_inputs[@]}"; do
        if same_file "$candidate_key" "${input#*|}"; then
            collision="${input%%|*}"
            break
        fi
    done
    owned=0
    if [ -n "$default_candidate_key" ] && [ "$candidate_key" = "$default_candidate_key" ]; then
        owned=1
    fi
    if [ -n "$collision" ]; then
        echo "CANDIDATE names the read-only input $collision: $CANDIDATE"
        echo "  the gate neither deletes nor overwrites a read-only input, so it stopped here"
        record "empty pst" FAIL
    elif [ -f "$CANDIDATE" ] && [ "$owned" = 0 ] && [ "${OVERWRITE:-0}" != 1 ]; then
        echo "CANDIDATE already exists and this script does not own it: $CANDIDATE"
        echo "  nothing was deleted; point CANDIDATE at a fresh path or set OVERWRITE=1 to authorize the replace"
        record "empty pst" FAIL
    else
        generate=("./$BUILD/$CONFIG/ost2pst.exe" --empty "$CANDIDATE")
        if [ -f "$CANDIDATE" ]; then
            generate+=(--force)
        fi
        if "${generate[@]}" > "$LOGDIR/gate1-generate.txt" 2>&1; then
            record "empty pst" PASS
            candidate_ready=1
        else
            record "empty pst" FAIL
        fi
        strip_cr "$LOGDIR/gate1-generate.txt"
        tail -12 "$LOGDIR/gate1-generate.txt"
    fi
fi

echo "== ostinfo --probe and --ltp on $CANDIDATE"
if [ ! -x "./$BUILD/$CONFIG/ostinfo.exe" ]; then
    echo "no ostinfo binary for $BUILD/$CONFIG"
    record "probe out.pst" "NOT VERIFIED"
    record "ltp out.pst" "NOT VERIFIED"
elif [ "$candidate_ready" = 0 ]; then
    echo "this run wrote no candidate, so these gates did not run"
    record "probe out.pst" "NOT VERIFIED"
    record "ltp out.pst" "NOT VERIFIED"
elif [ ! -f "$CANDIDATE" ]; then
    echo "no candidate file"
    record "probe out.pst" "NOT VERIFIED"
    record "ltp out.pst" "NOT VERIFIED"
else
    if "./$BUILD/$CONFIG/ostinfo.exe" --probe "$CANDIDATE" > "$LOGDIR/gate1-probe-candidate.txt" 2>&1; then
        record "probe out.pst" PASS
    else
        record "probe out.pst" FAIL
    fi
    strip_cr "$LOGDIR/gate1-probe-candidate.txt"
    tail -4 "$LOGDIR/gate1-probe-candidate.txt"
    if "./$BUILD/$CONFIG/ostinfo.exe" --ltp "$CANDIDATE" > "$LOGDIR/gate1-ltp-candidate.txt" 2>&1; then
        record "ltp out.pst" PASS
    else
        record "ltp out.pst" FAIL
    fi
    strip_cr "$LOGDIR/gate1-ltp-candidate.txt"
    tail -4 "$LOGDIR/gate1-ltp-candidate.txt"
fi

echo "== libpff pffexport on $CANDIDATE"
if [ ! -f "$LIBPFF/pffexport.exe" ]; then
    echo "libpff pffexport not built"
    record "pffexport out.pst" "NOT VERIFIED"
elif [ "$candidate_ready" = 0 ]; then
    echo "this run wrote no candidate, so this gate did not run"
    record "pffexport out.pst" "NOT VERIFIED"
elif [ ! -f "$CANDIDATE" ]; then
    echo "no candidate file"
    record "pffexport out.pst" "NOT VERIFIED"
elif ! candidate_win=$(win_path "$CANDIDATE"); then
    echo "no Windows path helper for the candidate"
    record "pffexport out.pst" "NOT VERIFIED"
else
    rm -rf "$BUILD/gate1-libpff.export"
    if (cd "$BUILD" && "$pffexport_path" -v -t gate1-libpff "$candidate_win" \
            > "$REPO/$LOGDIR/gate1-pffexport-candidate.txt" 2>&1) &&
       ! grep -q "unable to" "$LOGDIR/gate1-pffexport-candidate.txt"; then
        record "pffexport out.pst" PASS
    else
        record "pffexport out.pst" FAIL
    fi
    strip_cr "$LOGDIR/gate1-pffexport-candidate.txt"
    tail -6 "$LOGDIR/gate1-pffexport-candidate.txt"
fi

echo "== libpff folder tree vs ostinfo --ltp (parent, child and per-folder counts)"
probe_log="$LOGDIR/gate1-libpff-tree.txt"
if [ ! -f "$LIBPFF/libpff.lib" ]; then
    echo "libpff import libraries missing"
    record "libpff tree vs ltp" "NOT VERIFIED"
elif [ ! -f "$PROBE_SRC" ]; then
    echo "tree probe source missing: $PROBE_SRC"
    record "libpff tree vs ltp" "NOT VERIFIED"
elif [ "$candidate_ready" = 0 ]; then
    echo "this run wrote no candidate, so this gate did not run"
    record "libpff tree vs ltp" "NOT VERIFIED"
elif [ ! -f "$CANDIDATE" ]; then
    echo "no candidate file"
    record "libpff tree vs ltp" "NOT VERIFIED"
elif [ ! -f "$LOGDIR/gate1-ltp-candidate.txt" ]; then
    echo "no ostinfo --ltp report to compare against"
    record "libpff tree vs ltp" "NOT VERIFIED"
elif ! candidate_win=$(win_path "$CANDIDATE"); then
    echo "no Windows path helper for the candidate"
    record "libpff tree vs ltp" "NOT VERIFIED"
else
    libs=()
    for name in libpff libbfio libcdata libcerror libcfile libclocale libcnotify libcpath libcsplit \
                libcthreads libfcache libfdata libfdatetime libfguid libfmapi libfvalue libfwnt libuna zlib; do
        libs+=("$LIBPFF/$name.lib")
    done
    # Everything below ran, so every failure in it is a FAIL, never NOT VERIFIED.
    if ! dev "cl /nologo /EHsc /MD /O2 /I third_party\libpff\include /I third_party\libpff\libpff \
            $PROBE_SRC /Fe:$BUILD\m4_libpff_probe.exe /Fo:$BUILD\m4_libpff_probe_ /link ${libs[*]}"; then
        echo "the libpff tree probe did not compile"
        record "libpff tree vs ltp" FAIL
    elif ! cp "$LIBPFF/libpff.dll" "$BUILD/libpff.dll"; then
        echo "libpff.dll did not reach the probe"
        record "libpff tree vs ltp" FAIL
    elif ! "$PROBE" "$candidate_win" > "$probe_log" 2>&1; then
        strip_cr "$probe_log"
        echo "the libpff tree probe exited nonzero:"
        tail -8 "$probe_log"
        record "libpff tree vs ltp" FAIL
    else
        strip_cr "$probe_log"
        walk_state=$(awk '/^  walk /{
                print ($0 ~ /0 cycles/ && $0 ~ /0 rows with no NBT entry/ && $0 ~ /0 cut by the depth cap/ \
                       && $0 ~ /0 cut by the folder cap/) ? "clean" : "capped"
            }' "$LOGDIR/gate1-ltp-candidate.txt")
        ltp_tree="$LOGDIR/gate1-tree-ltp.txt"
        libpff_tree="$LOGDIR/gate1-tree-libpff.txt"
        ltp_tree_lines "$LOGDIR/gate1-ltp-candidate.txt" | sort > "$ltp_tree"
        libpff_tree_lines "$probe_log" | sort > "$libpff_tree"
        ltp_folders=$(wc -l < "$ltp_tree" | tr -d ' ')
        libpff_folders=$(wc -l < "$libpff_tree" | tr -d ' ')
        if ! grep -q "^COMPLETE$" "$probe_log"; then
            echo "the probe stopped before COMPLETE:"
            tail -8 "$probe_log"
            record "libpff tree vs ltp" FAIL
        elif grep -qE "sub_folder [0-9]+ unreadable|libpff call failed" "$probe_log"; then
            echo "libpff could not read every folder:"
            grep -E "sub_folder [0-9]+ unreadable|libpff call failed" "$probe_log"
            record "libpff tree vs ltp" FAIL
        elif [ "$walk_state" != clean ]; then
            echo "the folder walk was capped or cyclic, so its counts are not a tree: $walk_state"
            record "libpff tree vs ltp" FAIL
        elif [ "$ltp_folders" -eq 0 ] || [ "$libpff_folders" -eq 0 ]; then
            echo "no folder lines parsed: ostinfo --ltp $ltp_folders, libpff $libpff_folders"
            record "libpff tree vs ltp" FAIL
        elif diff -u "$ltp_tree" "$libpff_tree" > "$LOGDIR/gate1-tree-diff.txt"; then
            echo "  $ltp_folders folders on both sides, path + sub-folders + messages + associated equal"
            sed 's/^/  /' "$ltp_tree"
            echo "  messages + associated: ostinfo --ltp $(tree_total "$ltp_tree"), libpff $(tree_total "$libpff_tree")"
            record "libpff tree vs ltp" PASS
        else
            echo "folder trees differ (path|sub-folders|messages|associated):"
            cat "$LOGDIR/gate1-tree-diff.txt"
            record "libpff tree vs ltp" FAIL
        fi
    fi
fi

echo "== libpff on the Outlook blank PST oracle ($ORACLE, read-only)"
if [ ! -f "$LIBPFF/pffexport.exe" ]; then
    echo "libpff pffexport not built"
    record "pffexport oracle" "NOT VERIFIED"
elif [ ! -f "$ORACLE" ]; then
    echo "oracle file missing: $ORACLE"
    record "pffexport oracle" "NOT VERIFIED"
elif ! oracle_win=$(win_path "$ORACLE"); then
    echo "no Windows path helper for the oracle"
    record "pffexport oracle" "NOT VERIFIED"
else
    rm -rf "$BUILD/gate1-oracle.export"
    if (cd "$BUILD" && "$pffexport_path" -v -t gate1-oracle "$oracle_win" \
            > "$REPO/$LOGDIR/gate1-pffexport-oracle.txt" 2>&1) &&
       ! grep -q "unable to" "$LOGDIR/gate1-pffexport-oracle.txt"; then
        record "pffexport oracle" PASS
    else
        record "pffexport oracle" FAIL
    fi
    strip_cr "$LOGDIR/gate1-pffexport-oracle.txt"
    tail -6 "$LOGDIR/gate1-pffexport-oracle.txt"
fi

echo "== ost2pst --folder $SUBSET_FOLDER -> $SUBSET_CANDIDATE"
subset_ready=0
subset_new_nid=''
subset_log="$LOGDIR/gate1-subset-convert.txt"
if [ -z "$SUBSET_FOLDER" ]; then
    echo "SUBSET_FOLDER names no folder to convert"
    record "subset convert" "NOT VERIFIED"
elif [ ! -x "./$BUILD/$CONFIG/ost2pst.exe" ]; then
    echo "no ost2pst binary for $BUILD/$CONFIG"
    record "subset convert" "NOT VERIFIED"
elif [ -z "$sample_arg" ]; then
    echo "no readable OST2PST_SAMPLE to convert"
    record "subset convert" "NOT VERIFIED"
elif ! subset_key=$(path_key "$SUBSET_CANDIDATE"); then
    echo "no path helper for SUBSET_CANDIDATE, so the gate cannot prove it is not a read-only input: $SUBSET_CANDIDATE"
    record "subset convert" "NOT VERIFIED"
else
    collision=''
    for input in "${readonly_inputs[@]}"; do
        if same_file "$subset_key" "${input#*|}"; then
            collision="${input%%|*}"
            break
        fi
    done
    owned=0
    if [ -n "$default_subset_candidate_key" ] && [ "$subset_key" = "$default_subset_candidate_key" ]; then
        owned=1
    fi
    if [ -n "$collision" ]; then
        echo "SUBSET_CANDIDATE names the read-only input $collision: $SUBSET_CANDIDATE"
        echo "  the gate neither deletes nor overwrites a read-only input, so it stopped here"
        record "subset convert" FAIL
    elif [ -f "$SUBSET_CANDIDATE" ] && [ "$owned" = 0 ] && [ "${OVERWRITE:-0}" != 1 ]; then
        echo "SUBSET_CANDIDATE already exists and this script does not own it: $SUBSET_CANDIDATE"
        echo "  nothing was deleted; point SUBSET_CANDIDATE at a fresh path or set OVERWRITE=1 to authorize the replace"
        record "subset convert" FAIL
    else
        convert=("./$BUILD/$CONFIG/ost2pst.exe" --folder "$SUBSET_FOLDER" --max-messages "$SUBSET_MAX" \
                 "$sample_arg" "$SUBSET_CANDIDATE")
        if [ -f "$SUBSET_CANDIDATE" ]; then
            convert+=(--force)
        fi
        if "${convert[@]}" > "$subset_log" 2>&1; then
            record "subset convert" PASS
            subset_ready=1
            subset_new_nid=$(awk '/^  new folder +0x/{ print $3; exit }' "$subset_log")
        else
            record "subset convert" FAIL
        fi
        strip_cr "$subset_log"
        grep -E '^  (source folder|new folder|messages|recipients|attachments|payload|bodies|named|values|file) ' \
            "$subset_log" | sed 's/^/  /'
        if [ -z "$subset_new_nid" ]; then
            echo "the conversion report named no new folder NID, so its folder cannot be re-read"
            tail -12 "$subset_log"
        fi
    fi
fi

echo "== subset counts: own reader on the source folder, on the new store, and libpff pffexport"
subset_source_log="$LOGDIR/gate1-subset-source.txt"
subset_candidate_log="$LOGDIR/gate1-subset-candidate.txt"
subset_export_log="$LOGDIR/gate1-pffexport-subset.txt"
# One line per subset run: "<folder messages> <recipients> <attachment objects>
# <objects with no 0x3701 content> <payload bytes> <attached Messages read>
# <attached Messages this reader could not carry>". The counts come from the report the
# extractor prints for either file, so the two sides are read by the same code and a
# difference is a difference in the bytes, not in the reader.
subset_counts() {
    awk '
        /^SUBSET: MESSAGE OBJECTS/ { section = "messages"; next }
        /^SUBSET: RECIPIENT ROWS/ { section = "recipients"; next }
        /^SUBSET: ATTACHMENTS/ { section = "attachments"; next }
        /^SUBSET: / { section = ""; next }
        section == "messages" && /^ +read +[0-9]+ the folder names +\+ +[0-9]+ reached/ {
            messages = $2; attached = $7; next
        }
        section == "recipients" && /^ +read +[0-9]+$/ { recipients = $2; next }
        section == "attachments" && /^ +objects +[0-9]+ named by a row, +[0-9]+ with no payload/ {
            objects = $2; no_payload = $7; next
        }
        section == "attachments" && /^ +attached Message +[0-9]+ Attachment objects carry/ {
            object_form = $3; next
        }
        section == "attachments" && /^ +\([MS\-PST\] 2\.4\.6\.2\.2\): +[0-9]+ of them this reader read/ {
            embedded = $3; next
        }
        section == "attachments" && /^ +payload +[0-9]+ B read/ { payload = $2; next }
        END {
            print messages + 0, recipients + 0, objects + 0, no_payload + 0, payload + 0, embedded + 0,
                  object_form - embedded + 0
        }
    ' "$1"
}

# What pffexport wrote for the new store: Message directories and the attachment files under them.
# An attached Message exports as AttachmentNNNN/MessageNNNNN/ with its own Attachments under that, so a
# Message directory under Attachments is one level deeper than the folder's own and counts apart from it.
export_dir="$BUILD/gate1-subset.export"
exported_counts() {
    messages=$(find "$export_dir" -type d -name 'Message*' -not -path '*/Attachments/*' | wc -l | tr -d ' ')
    embedded=$(find "$export_dir" -type d -name 'Message*' -path '*/Attachments/*' | wc -l | tr -d ' ')
    # pffexport writes these next to the real attachments for the message itself, not as attachments.
    # Measured in this pffexport build (pffexport 20261010), not read out of a document.
    pseudo='^(ItemValues|RecipientsItemValues|Recipients|OutlookHeaders|ConversationIndex|InternetHeaders|Message)\.txt$|\.rtf$'
    # A file counts as an exported attachment only when the directory it sits in is an Attachments directory,
    # so the report files pffexport writes inside an attached Message directory are not attachment bytes.
    attachments=$(find "$export_dir" -path '*/Attachments/*' -type f -printf '%f|%s|%p\n' |
        awk -F'|' '{ n = split($3, parts, "/"); if (parts[n - 1] == "Attachments") print $1 "|" $2 }' |
        grep -Ev "$pseudo")
    files=$(printf '%s\n' "$attachments" | grep -c . | tr -d ' ')
    bytes=$(printf '%s\n' "$attachments" | awk -F'|' '{ sum += $2 } END { print sum + 0 }')
    printf '%s %s %s %s\n' "$messages" "$embedded" "$files" "$bytes"
}

if [ "$subset_ready" = 0 ]; then
    echo "this run converted no folder, so these counts did not run"
    record "subset vs pffexport" "NOT VERIFIED"
elif [ -z "$subset_new_nid" ]; then
    echo "no new folder NID in the conversion report"
    record "subset vs pffexport" FAIL
elif [ ! -x "./$BUILD/$CONFIG/ostinfo.exe" ]; then
    echo "no ostinfo binary for $BUILD/$CONFIG"
    record "subset vs pffexport" "NOT VERIFIED"
elif [ ! -f "$SUBSET_CANDIDATE" ]; then
    echo "no subset candidate file"
    record "subset vs pffexport" "NOT VERIFIED"
elif [ ! -f "$LIBPFF/pffexport.exe" ]; then
    echo "libpff pffexport not built"
    record "subset vs pffexport" "NOT VERIFIED"
elif ! subset_win=$(win_path "$SUBSET_CANDIDATE"); then
    echo "no Windows path helper for the subset candidate"
    record "subset vs pffexport" "NOT VERIFIED"
else
    # The source folder is read with the same cap the conversion used. Its own exit code is not the verdict
    # here: --subset exits 3 when the source has something this reader could not read, and whether it does
    # is one of the things the comparison is about. The store this writer just wrote has to read clean.
    "./$BUILD/$CONFIG/ostinfo.exe" --subset "$SUBSET_FOLDER" --max-messages "$SUBSET_MAX" "$sample_arg" \
        > "$subset_source_log" 2>&1
    source_status=$?
    if [ "$source_status" != 0 ] && [ "$source_status" != 3 ]; then
        echo "ostinfo --subset on the source folder exited $source_status:"
        tail -8 "$subset_source_log"
        record "subset vs pffexport" FAIL
    fi
    if [ ! -s "$subset_source_log" ]; then
        echo "no source subset report"
        record "subset vs pffexport" FAIL
    elif ! "./$BUILD/$CONFIG/ostinfo.exe" --subset "$subset_new_nid" --max-messages "$SUBSET_MAX" \
            "$SUBSET_CANDIDATE" > "$subset_candidate_log" 2>&1; then
        echo "ostinfo --subset found something wrong in the store this writer just wrote:"
        tail -8 "$subset_candidate_log"
        record "subset vs pffexport" FAIL
    else
        rm -rf "$export_dir"
        if ! (cd "$BUILD" && "$pffexport_path" -v -t gate1-subset "$subset_win" \
                > "$REPO/$subset_export_log" 2>&1) ||
           grep -q "unable to open file" "$subset_export_log" ||
           ! grep -q "^Export completed\.$" "$subset_export_log"; then
            echo "pffexport did not export the subset candidate:"
            tail -8 "$subset_export_log"
            record "subset vs pffexport" FAIL
        else
            strip_cr "$subset_source_log"
            strip_cr "$subset_candidate_log"
            strip_cr "$subset_export_log"
            source_counts=$(subset_counts "$subset_source_log")
            candidate_counts=$(subset_counts "$subset_candidate_log")
            export_counts=$(exported_counts)
            echo "  own reader, source folder $SUBSET_FOLDER:  $source_counts"
            echo "  own reader, new store folder $subset_new_nid: $candidate_counts"
            echo "  pffexport over the new store (messages, attachment files, bytes): $export_counts"
            set -- $source_counts
            src_messages=$1 src_recipients=$2 src_objects=$3 src_no_payload=$4 src_payload=$5
            src_embedded=$6 src_unread_object=$7
            set -- $candidate_counts
            new_messages=$1 new_recipients=$2 new_objects=$3 new_no_payload=$4 new_payload=$5
            new_embedded=$6 new_unread_object=$7
            set -- $export_counts
            exp_messages=$1 exp_embedded=$2 exp_files=$3 exp_bytes=$4
            differ=''
            [ "$src_messages" = "$new_messages" ] || differ="$differ messages"
            [ "$src_recipients" = "$new_recipients" ] || differ="$differ recipients"
            [ "$src_objects" = "$new_objects" ] || differ="$differ attachment-objects"
            [ "$src_no_payload" = "$new_no_payload" ] || differ="$differ attachments-without-payload"
            [ "$src_embedded" = "$new_embedded" ] || differ="$differ attached-messages"
            [ "$src_unread_object" = "$new_unread_object" ] || differ="$differ attached-messages-unread"
            [ "$src_payload" = "$new_payload" ] || differ="$differ payload-bytes"
            [ "$src_messages" = "$exp_messages" ] || differ="$differ pffexport-messages"
            [ "$new_embedded" = "$exp_embedded" ] || differ="$differ pffexport-embedded-messages"
            # An attached Message exports as a Message directory, not as an attachment file, so the
            # attachment-file target is the Attachment objects that are not object-form ones. An object this
            # reader could not carry exports as nothing at all, so it has to come off the target too.
            [ $(($new_objects - $new_embedded - $new_unread_object)) = "$exp_files" ] ||
                differ="$differ pffexport-attachment-files"
            [ "$new_payload" = "$exp_bytes" ] || differ="$differ pffexport-payload-bytes"
            if [ -n "$differ" ]; then
                echo "  the counts differ in:$differ"
                record "subset vs pffexport" FAIL
            elif [ "$new_messages" -lt "$SUBSET_MIN_MESSAGES" ] || [ "$exp_files" -lt "$SUBSET_MIN_ATTACHMENTS" ]; then
                echo "  the floor is $SUBSET_MIN_MESSAGES messages and $SUBSET_MIN_ATTACHMENTS attachments: $new_messages messages, $exp_files attachments"
                record "subset vs pffexport" FAIL
            else
                echo "  $new_messages folder messages + $new_embedded attached Messages, $new_recipients recipient rows,"
                echo "  $new_objects Attachment objects ($new_no_payload with no 0x3701 content, $new_embedded carrying a"
                echo "  Message of their own), $new_payload payload bytes, on all three sides"
                record "subset vs pffexport" PASS
            fi
        fi
    fi
fi

echo
if [ "$STRICT" = 1 ]; then
    echo "GATE 1 SUMMARY (STRICT: a required step that did not run fails the gate too)"
else
    echo "GATE 1 SUMMARY (NOT VERIFIED means required scope is unverified; STRICT=1 rejects it)"
fi
overall=0
for line in "${report[@]}"; do
    printf '  %-22s %s\n' "${line%%|*}" "${line##*|}"
    case "${line##*|}" in
    FAIL) overall=1 ;;
    "NOT VERIFIED")
        if [ "$STRICT" = 1 ]; then overall=1; fi
        ;;
    esac
done
exit "$overall"
