"""Optional private-sample gate: never part of the synthetic/default test suite."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for data in iter(lambda:f.read(1024*1024),b''): h.update(data)
    return h.hexdigest()

def main():
    p=argparse.ArgumentParser()
    for name in ('worker','source','authority','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--source-sha256',required=True)
    p.add_argument('--authority-sha256',required=True)
    a=p.parse_args()
    if a.output.exists(): raise SystemExit('Refusing to reuse an evidence directory')
    a.output.mkdir(parents=True)
    evidence={'worker_sha256':digest(a.worker),'source_bytes':a.source.stat().st_size,
              'authority_bytes':a.authority.stat().st_size,'runs':{}}
    assert digest(a.source) == a.source_sha256,'Frozen source hash mismatch'
    assert digest(a.authority) == a.authority_sha256,'Accepted authority hash mismatch'
    evidence['source_sha256']=a.source_sha256
    evidence['authority_sha256']=a.authority_sha256
    for mode in ('default','events'):
        destination=a.output/(mode+'.pst')
        args=[str(a.worker.resolve()),*(['--events-json'] if mode == 'events' else []),str(a.source.resolve()),str(destination.resolve())]
        started=time.perf_counter()
        with (a.output/(mode+'.stdout')).open('wb') as out,(a.output/(mode+'.stderr')).open('wb') as err:
            result=subprocess.run(args,stdout=out,stderr=err,timeout=1200)
        seconds=time.perf_counter()-started
        assert result.returncode == 0,(mode,result.returncode)
        report=json.loads(Path(str(destination)+'.report.json').read_text(encoding='utf-8'))
        actual=digest(destination)
        assert actual == a.authority_sha256,(mode,'PST differs from accepted writer authority',actual)
        if mode == 'events':
            rows=[json.loads(line) for line in (a.output/(mode+'.stdout')).read_text(encoding='utf-8').splitlines()]
            assert rows[0]['event'] == 'start' and rows[-1]['event'] == 'result'
            assert len([r for r in rows if r['event'] == 'result']) == 1
            assert rows[-1]['status'] == 'complete' and rows[-1]['exit_code'] == 0 and rows[-1]['report'] == report
        diagnostics=(a.output/(mode+'.stderr')).read_text(encoding='utf-8')
        peak=re.findall(r'peak_working_set=(\d+)',diagnostics)
        evidence['runs'][mode]={'args':args,'exit_code':result.returncode,'wall_seconds':seconds,'peak_working_set':int(peak[-1]) if peak else None,'pst_bytes':destination.stat().st_size,'pst_sha256':actual,'report':report}
        (a.output/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
        print(mode,'PASS',round(seconds,3),'seconds',flush=True)
    reports=[dict(evidence['runs'][m]['report']) for m in ('default','events')]
    for r in reports:
        r.pop('run_id')
        r.pop('performance', None)  # Per-invocation measurements are intentionally variable.
    assert reports[0] == reports[1],'Aggregate count/coverage mismatch'
    assert digest(Path(str(a.output/'default.pst')+'.items.jsonl')) == digest(Path(str(a.output/'events.pst')+'.items.jsonl')),'Item outcome mismatch'
    assert digest(a.source) == a.source_sha256 and digest(a.authority) == a.authority_sha256
    evidence['status']='PASS'
    (a.output/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('Frozen-source default/event/accepted-writer equivalence PASS')

if __name__ == '__main__': main()
