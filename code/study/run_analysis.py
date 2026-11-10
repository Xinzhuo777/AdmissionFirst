"""Existing pure estimators; refuses to run before all new A018 stages end."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
RUN=ROOT/'results/raw/a018-unified'
OUT=ROOT/'results/analysis/a018-unified'


def sha(path):return 'sha256:'+hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    completed=json.loads((RUN/'completion.json').read_text())
    if (completed['status']!='completed' or len(completed['completed_stages'])!=11
        or any(s['actual_exit_code']!=0 for s in completed['completed_stages'])):
        raise ValueError('all eleven database/support stages must finish first')
    method=json.loads((HERE/'analysis-methods-freeze.json').read_text())
    for rel,digest in method['method_files'].items():
        if sha(ROOT/rel)!=digest:raise ValueError('analysis method changed: '+rel)
    if OUT.exists():raise ValueError('analysis outputs must be fresh')
    OUT.mkdir(parents=True)
    stages=[]
    for family in ['mixed','sf10','E10']:
        module='final_af_e10_analyze' if family=='E10' else 'final_af_e3_analyze'
        input_dir=RUN/family if family=='E10' else RUN/family/'primary'
        command=[sys.executable,'-B','-m','caprls_core.'+module,
                 '--input-dir',str(input_dir),'--output-dir',str(OUT/family)]
        if family!='E10':command+=['--draws','10000']
        env=dict(os.environ);env['PYTHONDONTWRITEBYTECODE']='1'
        # E10 loads its pinned external pure method from project/output; all
        # algorithm modules there are byte-identical to the frozen source.
        module_root=ROOT
        env['PYTHONPATH']=str(module_root)
        record={'command':command,'cwd':str(module_root),'started_at':datetime.now(timezone.utc).isoformat()}
        (OUT/(family+'.command.json')).write_text(json.dumps(record,indent=2)+'\n')
        started=time.perf_counter()
        with (OUT/(family+'.log')).open('x') as log:
            p=subprocess.run(command,cwd=module_root,env=env,stdout=log,stderr=subprocess.STDOUT)
        record.update(actual_exit_code=p.returncode,elapsed_seconds=time.perf_counter()-started)
        (OUT/(family+'.exit.json')).write_text(json.dumps(record,indent=2)+'\n')
        if p.returncode:raise RuntimeError('analysis exit '+str(p.returncode)+': '+family)
        result=json.loads((OUT/family/'analysis.json').read_text())
        if not result['analysis_ready']:raise ValueError('analysis not ready: '+family)
        stages.append({'family':family,'actual_exit_code':0,'analysis_ready':True,
                       'analysis_sha256':sha(OUT/family/'analysis.json')})
    for rel,digest in method['method_files'].items():
        if sha(ROOT/rel)!=digest:raise ValueError('analysis method changed during reduction: '+rel)
    (OUT/'completion.json').write_text(json.dumps({'status':'completed','at':datetime.now(timezone.utc).isoformat(),
        'stages':stages,'new_campaign':str(RUN),'methods_freeze_sha256':sha(HERE/'analysis-methods-freeze.json'),
        'historical_raw_imported':False,'database_access':False},indent=2)+'\n')


if __name__=='__main__':main()
