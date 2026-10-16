"""Compare scoped production ATT rows against independent libpff metadata.

Oracle format: SCOPE<TAB>message ancestry<TAB>count; ROW<TAB>full attachment ancestry<TAB>size;
final COMPLETE. Scope counts make truncated, duplicated or one-to-many comparisons fail.
Ours may contain extra scopes, but must exactly cover every declared oracle scope.
"""
import argparse
from collections import Counter
from pathlib import Path


def compare(ours_text, oracle_text):
    ours, oracle, scopes = {}, {}, {}
    complete = False

    def insert(target, key, value):
        if key in target:
            raise ValueError(f"duplicate identity: {key}")
        target[key] = value

    for line in ours_text.splitlines():
        if not line.startswith("ATT\t"):
            continue
        fields = line.split("\t")
        if len(fields) != 7 or " attachment " not in fields[6]:
            raise ValueError("ATT row lacks a full scoped identity")
        insert(ours, fields[6], int(fields[3]))
    for line in oracle_text.splitlines():
        fields = line.split("\t")
        if complete:
            raise ValueError("data after oracle COMPLETE marker")
        if fields == ["COMPLETE"]:
            complete = True
        elif len(fields) == 3 and fields[0] == "SCOPE":
            insert(scopes, fields[1], int(fields[2]))
        elif len(fields) == 3 and fields[0] == "ROW":
            if " attachment " not in fields[1]:
                raise ValueError("oracle row lacks parent scope")
            insert(oracle, fields[1], int(fields[2]))
        else:
            raise ValueError("malformed oracle record")
    if not complete or not scopes:
        raise ValueError("incomplete or empty oracle")
    parent = lambda key: key.rsplit(" attachment ", 1)[0]
    counts = Counter(parent(key) for key in oracle)
    if any(scope not in scopes for scope in counts):
        raise ValueError("oracle row has undeclared scope")
    if any(count < 0 or counts[scope] != count for scope, count in scopes.items()):
        raise ValueError("oracle scope cardinality mismatch")
    comparable = {key: value for key, value in ours.items() if parent(key) in scopes}
    if comparable.keys() != oracle.keys():
        missing = len(oracle.keys() - comparable.keys())
        extra = len(comparable.keys() - oracle.keys())
        raise ValueError(f"scoped identity mismatch: missing={missing}, extra={extra}")
    differences = sum(comparable[key] != value for key, value in oracle.items())
    if differences:
        raise ValueError(f"declared size differences: {differences}")
    return (f"ours={len(ours)} oracle={len(oracle)} matched={len(comparable)} "
            f"scopes={len(scopes)} outside_oracle={len(ours)-len(comparable)} differences=0")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ours", type=Path)
    parser.add_argument("oracle", type=Path)
    args = parser.parse_args()
    try:
        print(compare(args.ours.read_text(encoding="utf-8"),
                      args.oracle.read_text(encoding="utf-8")))
    except (ValueError, OSError) as error:
        parser.exit(1, f"FAIL: {error}\n")


if __name__ == "__main__":
    main()
