"""Real worker presentation contract; only synthetic inputs and temporary destinations."""
import argparse
import json
import math
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--worker', required=True)
p.add_argument('--fixture-builder', required=True)
a = p.parse_args()

def run(*args):
    return subprocess.run([a.worker, *map(str, args)], capture_output=True, timeout=30)

def events(r):
    rows = [json.loads(x) for x in r.stdout.decode('utf-8').splitlines()]
    assert rows and rows[0] == {'schema': 1, 'event': 'start', 'protocol': 1}, rows
    assert all(x['schema'] == 1 for x in rows)
    assert len([x for x in rows if x['event'] == 'result']) == 1
    assert rows[-1]['event'] == 'result'
    assert rows[-1]['exit_code'] == r.returncode
    return rows

def performance(report):
    p = report['performance']
    assert p['scope'] == 'current_invocation_before_publication'
    assert p['resumed'] is False
    assert math.isfinite(p['wall_seconds']) and p['wall_seconds'] > 0
    assert p['peak_working_set_bytes'] > 0
    assert math.isclose(p['throughput_bytes_per_second'],
                        report['source_size'] / p['wall_seconds'], rel_tol=1e-12)

with tempfile.TemporaryDirectory(prefix='ost2pst gui 日本語 ') as td:
    root = Path(td)
    source = root / '源 简繁 한국어 français.ost'
    subprocess.run([a.fixture_builder, str(source), '--incomplete', '3'], check=True, capture_output=True)
    out = root / '结果.pst'
    r = run('--events-json', source, out)
    rows = events(r)
    assert r.returncode == 3, r.stderr
    final = rows[-1]
    assert final['status'] in ('complete', 'incomplete'), final
    assert final['report'] == json.loads(Path(str(out)+'.report.json').read_text())
    performance(final['report'])
    assert all('subject' not in x and 'body' not in x for x in rows)
    assert [x['phase'] for x in rows if x['event'] == 'progress'][:2] == ['identity', 'index']
    resumed = run('--events-json', '--resume', source, out)
    assert events(resumed)[-1] == final, resumed.stderr
    collision = run('--events-json', source, out)
    assert events(collision)[-1]['status'] == 'failed'
    assert collision.returncode != 0
    normal = root / 'normal.pst'
    ordinary = run(source, normal)
    assert ordinary.returncode == r.returncode
    assert ordinary.stdout.startswith(b'CONVERSION RESULT:')
    assert normal.read_bytes() == out.read_bytes()
    performance(json.loads(Path(str(normal)+'.report.json').read_text()))
    for args in [('--empty', out), ('--dry-run', source), ('--verify', source), ('--folder', '34', source, out)]:
        bad = run('--events-json', *args)
        assert bad.returncode == 1 and bad.stdout == b''
    invalid = root / 'invalid.ost'
    invalid.write_bytes(b'bad')
    bad = run('--events-json', invalid, root / 'bad.pst')
    assert events(bad)[-1]['status'] == 'failed'
    assert not (root / 'bad.pst.work').exists()
    unsupported = bytearray(source.read_bytes())
    unsupported[10:12] = (37).to_bytes(2, 'little')
    invalid.write_bytes(unsupported)
    bad = run('--events-json', invalid, root / 'unsupported.pst')
    assert bad.returncode == 2 and events(bad)[-1]['status'] == 'failed'
print('Real GUI worker protocol passed')
