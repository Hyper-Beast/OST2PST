"""Deterministic synthetic truncation corpus with crash/hang detection."""
import argparse
import hashlib
import json
from pathlib import Path
import random
import re
import struct
import subprocess
import tempfile
import zlib

parser = argparse.ArgumentParser()
parser.add_argument('--ost2pst', required=True)
parser.add_argument('--ostinfo', required=True)
parser.add_argument('--fixture-builder', required=True)
args = parser.parse_args()
converter = str(Path(args.ost2pst).resolve())
reader = str(Path(args.ostinfo).resolve())
builder = str(Path(args.fixture_builder).resolve())


def crc(data):
    # [MS-PST] 5.3: seed zero, no final complement.
    return zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF


def command(exe, argv, root):
    return subprocess.run([exe, *map(str, argv)], cwd=root, capture_output=True,
                          text=True, errors='replace', timeout=5)


def assert_cut(exe, argv, root, label):
    run = command(exe, argv, root)
    text = run.stdout + run.stderr
    # Windows access violations and abort statuses must not count as ordinary data errors.
    precise = re.search(r'offset=0x[0-9A-Fa-f]+ value=0x[0-9A-Fa-f]+', text)
    tabular = re.search(r'0x[0-9A-Fa-f]+\s+\S+\s+value 0x[0-9A-Fa-f]+', text)
    if run.returncode not in (2, 3) or not (precise or tabular):
        raise AssertionError(f'{label}: exit={run.returncode}; {text[:1500]}\n{text[-2000:]}')


def tree_pages(original):
    # Only the known-valid generated Unicode 512-page fixtures: [MS-PST] 2.2.2.5
    # ROOT.BREFNBT/BREFBBT; 2.2.2.7.7.1 cEnt/cbEnt/cLevel; 2.2.2.7.7.2 BTENTRY.BREF.ib.
    pending = [struct.unpack_from('<Q', original, offset)[0] for offset in (0xE0, 0xF0)]
    seen = set()
    while pending:
        ib = pending.pop()
        assert ib not in seen and ib + 512 <= len(original)
        seen.add(ib)
        count, _, stride, level = original[ib + 488:ib + 492]
        assert stride > 0 and count * stride <= 488
        if level:
            assert stride >= 24
            pending.extend(struct.unpack_from('<Q', original, ib + i * stride + 16)[0]
                           for i in range(count))
    return seen


with tempfile.TemporaryDirectory(prefix='m7-truncation-', dir=Path.cwd()) as work:
    root = Path(work)
    empty = root/'empty.pst'
    made = command(converter, ['--empty', empty], root)
    assert made.returncode == 0, made.stdout + made.stderr
    content = root/'content.pst'
    made = command(builder, [content], root)
    assert made.returncode == 0, made.stdout + made.stderr
    metadata = json.loads(made.stdout)
    source = root/'cut.pst'
    output = root/'must-not-exist.pst'
    runs = 0
    summary = []
    for original in (empty.read_bytes(), content.read_bytes()):
        assert struct.unpack_from('<I', original, 4)[0] == crc(original[8:479])
        assert struct.unpack_from('<I', original, 0x20C)[0] == crc(original[8:524])
        pages = tree_pages(original)
        referenced_tree_end = max(pages) + 512
        cuts = set(range(565))
        rng = random.Random(0x4D37)
        cuts.update(rng.randrange(565, len(original)) for _ in range(96))
        boundaries = {len(original), 512, 8192, 16384, metadata['bbt'], metadata['nbt']}
        for ib in pages:
            boundaries.update((ib, ib + 488, ib + 496, ib + 512))
        if original == content.read_bytes():
            for block in metadata['blocks']:
                boundaries.update((block['ib'], block['ib'] + block['cb'],
                                   block['ib'] + ((block['cb'] + 16 + 63)//64)*64))
        for point in boundaries:
            cuts.update(point + delta for delta in (-1, 0, 1))
        cuts = sorted(cut for cut in cuts if 0 <= cut < len(original))
        tested = 0
        for cut in cuts:
            source.write_bytes(original[:cut])
            for exe, argv in ((converter, ['--verify', source]), (reader, ['--probe', source])):
                assert_cut(exe, argv, root, f'prefix={cut}')
                runs += 1
            # Recompute only explicit header fields to reach the internal parsers even after
            # truncation. [MS-PST] 2.2.2.5 EOF; 2.2.2.1 partial/full CRC ranges.
            # A repaired EOF after the last referenced page can remove only free tail space.
            # Such a different logical file is not an internal-parser truncation counterexample.
            if 564 <= cut < referenced_tree_end:
                forged = bytearray(original[:cut])
                struct.pack_into('<Q', forged, 0x0B8, cut)
                struct.pack_into('<I', forged, 4, crc(forged[8:479]))
                struct.pack_into('<I', forged, 0x20C, crc(forged[8:524]))
                source.write_bytes(forged)
                for exe, argv in ((converter, ['--verify', source]),
                                  (reader, ['--ltp', source]), (reader, ['--ndb', source])):
                    assert_cut(exe, argv, root, f'logical-eof={cut}')
                    runs += 1
                tested += 1
            if cut in (0, 4, 12, 512, 564, len(original)-1):
                for exe, argv in ((converter, ['--dry-run', source, output]),
                                  (converter, [source, output]),
                                  (converter, ['--folder', '0x8022', source, output]),
                                  (reader, ['--inventory', source]),
                                  (reader, ['--subset', '0x8022', source]),
                                  (reader, ['--subtree', '0x8022', source])):
                    assert_cut(exe, argv, root, f'action-prefix={cut}')
                    runs += 1
                assert not output.exists()
                assert not any(p.is_dir() for p in root.iterdir())
        summary.append({'bytes': len(original), 'sha256': hashlib.sha256(original).hexdigest(),
                        'prefixes': len(cuts), 'internal_parser_cuts': tested,
                        'referenced_tree_end': referenced_tree_end})
    print(json.dumps({'status': 'PASS', 'seed': '0x4D37', 'normal_diagnostic_exits': runs,
                      'corpus': summary}, indent=2))
