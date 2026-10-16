import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

p=argparse.ArgumentParser()
p.add_argument('--native-test',required=True)
p.add_argument('--worker',required=True)
p.add_argument('--failure-worker',required=True)
p.add_argument('--fixture-builder',required=True)
p.add_argument('--evidence',required=True)
a=p.parse_args()
with tempfile.TemporaryDirectory(prefix='ost2pst native 日本語 ') as td:
    root=Path(td)
    # Stage the test and worker in the portable layout to exercise fixed module-relative resolution.
    packaged=root/'原生 GUI package'
    (packaged/'engine').mkdir(parents=True)
    test=packaged/'native-test.exe'
    shutil.copy2(a.native_test,test)
    worker=packaged/'engine/ost2pst.exe'
    shutil.copy2(a.worker,worker)
    failure_worker=packaged/'engine/failure-worker.exe'
    shutil.copy2(a.failure_worker,failure_worker)
    sources=[]
    for name,args in [('完整 한국어 français.ost',['--complete','3']),('incomplete.ost',['--incomplete','3']),('long.ost',['--complete','700'])]:
        path=root/name
        subprocess.run([a.fixture_builder,str(path),*args],capture_output=True,check=True,timeout=60)
        sources.append(path)
    evidence=Path(a.evidence)/str(__import__('time').time_ns())
    subprocess.run([str(test),str(worker),str(failure_worker),*map(str,sources),str(evidence)],cwd=root,check=True,timeout=240)
    print('Native evidence:',evidence)
