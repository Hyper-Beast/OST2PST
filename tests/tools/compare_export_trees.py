"""Read-only byte comparison of two pffexport trees; report content paths only on failure."""
import hashlib
import json
import os
from pathlib import Path
import sys


def inventory(root):
    files = set()
    directories = set()
    for current, dirs, names in os.walk(root):
        relative = Path(current).relative_to(root)
        directories.update((relative / name).as_posix() for name in dirs)
        files.update((relative / name).as_posix() for name in names)
    return directories, files


def literal_path(value):
    absolute = str(Path(value).absolute())
    # pffexport can create trailing-dot attachment names through Win32 extended paths.
    return Path("\\\\?\\" + absolute) if os.name == "nt" else Path(absolute)


left, right, candidate = map(literal_path, sys.argv[1:4])
ld, lf = inventory(left)
rd, rf = inventory(right)
if not lf or ld != rd or lf != rf:
    raise SystemExit("Empty export or directory/file set mismatch")
total = 0
for name in sorted(lf):
    with (left / name).open("rb") as a, (right / name).open("rb") as b:
        while True:
            x, y = a.read(1024 * 1024), b.read(1024 * 1024)
            if x != y:
                raise SystemExit(f"Content mismatch: {name}")
            total += len(x)
            if not x:
                break
hash_value = hashlib.sha256()
with candidate.open("rb") as source:
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        hash_value.update(chunk)
print(json.dumps({"directories": len(ld), "files": len(lf), "compared_bytes": total,
                  "mismatches": 0, "candidate_bytes": candidate.stat().st_size,
                  "candidate_sha256": hash_value.hexdigest()}, indent=2))
