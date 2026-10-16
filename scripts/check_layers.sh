#!/usr/bin/env bash
# Enforces DEVELOPMENT.md: cli -> msg -> ltp -> ndb -> util.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

fail=0

forbid() { # <scope> <pattern> <why>
    local scope="$1" pattern="$2" why="$3"
    [ -d "$scope" ] || return 0
    if rg --no-messages -n "$pattern" "$scope" >/dev/null 2>&1; then
        echo "LAYER VIOLATION ($why) in $scope:"
        rg --no-messages -n "$pattern" "$scope"
        fail=1
    fi
}

forbid src/util 'ost2pst/(ndb|ltp|msg|writer|cli)/' 'util must not know any PST layer'
forbid include/ost2pst/util 'ost2pst/(ndb|ltp|msg|writer|cli)/' 'util public headers'
forbid src/ndb 'ost2pst/(ltp|msg|writer|cli)/' 'ndb must not know ltp/msg/writer/cli'
forbid include/ost2pst/ndb 'ost2pst/(ltp|msg|writer|cli)/' 'ndb public headers'
forbid src/ltp 'ost2pst/(msg|writer|cli)/' 'ltp must not know msg/writer/cli'
forbid include/ost2pst/ltp 'ost2pst/(msg|writer|cli)/' 'ltp public headers'
forbid src/ndb 'PR_[A-Z]' 'ndb stays format-only: no MAPI property ids'
forbid include/ost2pst/ndb 'PR_[A-Z]' 'ndb public headers stay format-only'

# Every layout constant carries a spec citation on its own line (cpp/coding-guidelines.md). [MS-OXCDATA]
# counts where the constant is a property type id, which [MS-PST] defers to [MS-OXCDATA] for.
for layout in include/ost2pst/ndb/layout.h include/ost2pst/ltp/layout.h include/ost2pst/ltp/prop_type.h include/ost2pst/writer/layout.h; do
    if [ -f "$layout" ]; then
        awk '/constexpr/ && !/MS-PST|MS-OXCDATA/ { print FILENAME ":" NR ": layout constant without a spec citation"; bad = 1 }
         END { exit bad }' "$layout" || fail=1
    fi
done

if [ "$fail" -eq 0 ]; then
    echo "layer check: OK"
fi
exit "$fail"

