"""One frozen final-AF, one-profile, complete paper campaign.

All experiment outputs are fresh. This controller never imports previous raw
results, changes algorithms, or selects runs based on measured performance.
"""
import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import traceback

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SOURCE = ROOT
BASELINE = ROOT / 'baseline-source'
OUTPUT = ROOT / 'results/raw/a018-unified'
PROFILE = {'shared_buffers':'2GB','work_mem':'16MB',
           'effective_cache_size':'8GB','max_wal_size':'4GB'}
# Keep PostgreSQL's Unix socket path short; callers can select another parent.
TMP = Path(os.environ.get('CAPRLS_TMPDIR') or tempfile.gettempdir()).expanduser().resolve()
ORDER = ['E1','E7','admission21','mixed','sf10','E2','E4','E5','E10','CONTENT','STABILITY']


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    return 'sha256:' + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_once(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as handle:
        json.dump(value, handle, indent=2, default=str); handle.write('\n')


def replace_state(value):
    tmp = HERE / 'active-state.next.json'
    tmp.write_text(json.dumps(value, indent=2, default=str)+'\n')
    tmp.replace(HERE/'active-state.json')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec);sys.modules[name] = module
    spec.loader.exec_module(module); return module


def tools_and_controls():
    c = load('_a018_controls', HERE/'full-study/campaign_controller.py')
    return c.load_tools(), c


def common_env():
    env = dict(os.environ)
    env.update(PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=str(SOURCE),
               CAPRLS_TMPDIR=str(TMP),CAPRLS_PG_SHARED_BUFFERS='2GB',
               CAPRLS_PG_MAX_CONNECTIONS='10',CAPRLS_IDENTITY_PRIMITIVES='native',
               CAPRLS_PG_INITDB_SHARED_BUFFERS='400kB',CAPRLS_PG_INITDB_MAX_CONNECTIONS='20')
    opts = [p for key,value in PROFILE.items() if key!='shared_buffers'
            for p in ['-c',key+'='+value]]
    opts += ['-c','hash_mem_multiplier=2.0','-c','plan_cache_mode=force_custom_plan']
    env['CAPRLS_PG_EXTRA_OPTS'] = shlex.join(opts)
    return env


def guard(freeze, tools):
    for name, tree in (("source_identity", SOURCE), ("baseline_identity", BASELINE)):
        identity = tools.source_identity(tree)
        observed, expected = dict(identity["files"]), dict(freeze[name]["files"])
        if name == "source_identity":
            # A local native rebuild changes only its machine-specific build receipt.
            # The C source is independently pinned, and its ABI and binary are
            # verified by the native loader before experiments execute.
            observed.pop("configs/identity_primitives_build.yaml", None)
            expected.pop("configs/identity_primitives_build.yaml", None)
            if sha(SOURCE / "planner/_identity_primitives.c") != "sha256:45c98da081327e07b902a7fdc865b3cc3eb137f14c1867b8c2fb8a5b7d60f375":
                raise ValueError("native primitive source differs")
            sys.path.insert(0, str(SOURCE))
            from planner._identity_native_loader import load_native, backend_info
            if load_native() is None or backend_info().get("name") != "native-primitives":
                raise ValueError("build the native primitives for this machine first")
        if observed != expected:
            raise ValueError("frozen experiment source changed: " + name)


def call(command, log, env, cwd=SOURCE):
    command = list(map(str,command)); log = Path(log)
    started = time.perf_counter()
    write_once(log.with_suffix('.command.json'), {'at':now(),'command':command,'cwd':str(cwd),
        'environment':{k:env.get(k) for k in ['PYTHONPATH','CAPRLS_TMPDIR',
          'CAPRLS_PG_SHARED_BUFFERS','CAPRLS_PG_MAX_CONNECTIONS','CAPRLS_PG_EXTRA_OPTS',
          'CAPRLS_IDENTITY_PRIMITIVES']}})
    with log.open('x') as stream:
        proc = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT)
        code = proc.wait()
    receipt={'at':now(),'actual_exit_code':code,'elapsed_seconds':time.perf_counter()-started}
    write_once(log.with_suffix('.exit.json'),receipt)
    if code:raise RuntimeError('actual exit '+str(code)+': '+str(log))
    return receipt


def stage_command(stage):
    py = [sys.executable,'-B']
    if stage in {'E1','E7','E2','E4','E5','E10'}:
        return py+['-m','caprls_core.final_af_auxiliary_study','--root',str(ROOT),
            '--stage',stage,'--database-profile','shared_host_2gb','--output',str(OUTPUT/stage)]
    if stage == 'admission21':
        return py+[str(HERE/'run_admission.py'),'--output',str(OUTPUT/stage)]
    if stage in {'CONTENT','STABILITY'}:
        return py+[str(HERE/'support-study/run_profile_support.py'),
            '--root',str(ROOT),'--source-root',str(SOURCE),
            '--manifest',str(HERE/'inputs/mixed-input-manifest.yaml'),
            '--profiles',str(HERE/'database-profiles.json'),'--profile','shared_host_2gb',
            '--stage',stage,'--output-dir',str(OUTPUT/stage)]
    raise ValueError(stage)


def run_workload(workload, tools, controls, env):
    """Keep proven preparation and worker boundaries, omitting crossover only."""
    manifest_path = HERE/'inputs'/(workload+'-input-manifest.yaml')
    e3, preview, pg = tools.activate_source(SOURCE)
    manifest=e3._load_manifest(manifest_path);e3._validate_manifest(manifest_path,manifest)
    e3.require_e3_manifest_data(ROOT,manifest_path,manifest)
    queries=e3._queries_for_manifest(manifest_path,manifest)
    policies=e3._policies_for_manifest(manifest_path,manifest)
    scales={x['name']:x['scale'] for x in manifest['datasets']}
    base=OUTPUT/workload;base.mkdir()
    cluster_path=None
    controls.install_profile(PROFILE)
    with pg.temporary_cluster(database='caprls_a018_'+workload) as pg_env:
        cluster_path=Path(pg_env.host).parent
        actual=controls.settings(pg,pg_env);controls.verify_settings(actual,PROFILE)
        write_once(base/'settings-before.json',actual)
        shared=base/'shared-preparation';shared.mkdir()
        started=time.perf_counter()
        version=e3._prepare_database(ROOT,pg_env,tpch_scale=scales.get('tpch',''),job_scale=scales.get('job',''))
        artifacts=tools.prepare_artifacts(e3,pg,queries,policies,pg_env)
        pg.run_psql_command('CHECKPOINT',pg_env)
        statistics=tools.statistics_identity(pg,pg_env)
        write_once(shared/'artifacts.json',artifacts);write_once(shared/'statistics.json',statistics)
        write_once(shared/'protocol.json',{
            'schema':'a016_shared_database_preparation_v1','at':now(),'pg_env':asdict(pg_env),
            'postgres_version':version,'database_system_identifier':pg.run_psql_command(
                'SELECT system_identifier::text FROM pg_control_system()',pg_env),
            'manifest_sha256':sha(manifest_path),'queries':[q.query_id for q in queries],
            'policies':[p.config_id for p in policies],
            'artifacts_file_sha256':sha(shared/'artifacts.json'),
            'setup_wall_ms':(time.perf_counter()-started)*1000,
            'scope':'New data/artifact build for this sole profile and campaign; not reused old results.'})
        command=[sys.executable,'-B',str(HERE/'full-study/final_af_e3_study.py'),
            '--root',str(ROOT),'--source-root',str(SOURCE),'--baseline-source',str(BASELINE),
            '--manifest',str(manifest_path),'--output-dir',str(base/'primary'),
            '--host',pg_env.host,'--port',str(pg_env.port),'--user',pg_env.user,
            '--database',pg_env.database,'--shared-preparation',str(shared),
            '--measured','30','--normal-entry-check','--sampling-schedule','af_ip_adjacent_block_v1',
            '--worker-timeout','7200']
        receipt=call(command,base/'primary.log',env)
        if tools.statistics_identity(pg,pg_env)!=statistics:
            raise ValueError('stored statistics changed within primary study')
        final=controls.settings(pg,pg_env);controls.verify_settings(final,PROFILE)
        if final!=actual:raise ValueError('settings changed within primary study')
        write_once(base/'settings-after.json',final)
        summary=json.loads((base/'primary/summary.json').read_text())
        if summary.get('status')!='completed':raise ValueError('primary summary not complete')
    if cluster_path.exists():raise ValueError('temporary cluster cleanup incomplete')
    write_once(base/'completed.json',{'status':'completed','at':now(),
        'primary_actual_exit_code':receipt['actual_exit_code'],'cluster_removed':True,
        'statistics_digest':statistics['digest'],'new_database_build':True})
    return receipt


def protocol():
    freeze=json.loads((HERE/'source-freeze.json').read_text())
    return {'schema':'a018_one_final_af_complete_paper_campaign_v1','at':now(),
        'root':str(ROOT),'source':str(SOURCE),'baseline_source':str(BASELINE),
        'sources':freeze,'profile':PROFILE,'stage_order':ORDER,
        'commands':{s:(stage_command(s) if s not in {'mixed','sf10'} else
          {'operation':'run_workload','manifest':str(HERE/'inputs'/(s+'-input-manifest.yaml')),
           'driver':str(HERE/'full-study/final_af_e3_study.py'),
           'arguments':['--measured','30','--normal-entry-check','--sampling-schedule','af_ip_adjacent_block_v1'],
           'dynamic_arguments':'fresh private PG host/port and newly built same-stage shared preparation recorded before execution'}) for s in ORDER},
        'budgets':{'mixed':{'cases':33,'declared_modes':7,'natural_unavailable_preserved':True,
            'warmup':'8–12 by available mode count','measured':'30–36 rounded to complete original schedule'},
            'sf10':{'cases':15,'declared_modes':5,'warmup':8,'measured':32},
            'E2':{'cases':8,'warmup':5,'measured':10},'E4':{'manifest':'original complete paired cases','warmup':5,'measured':10},
            'E5':{'manifest':'five witnesses, two settings','warmup':5,'measured':10},
            'E10':{'cases':11,'warmup':5,'measured':30},
            'admission21':{'decisions':21,'expected_admitted':11,'expected_rejected':10,'includes':'13 E1 and 8 E6a fixtures'},
            'E1':{'scope':'original complete smoke stage; duplicated subset in admission21 is not independent evidence'},
            'E7':{'tests':5,'scope':'full audit/positive/error controls'},
            'CONTENT':{'logical_cases':52,'E2':8,'E3':33,'E10':11},
            'STABILITY':{'queries':11,'rebuilds':10,'observations':110}},
        'exclusions':['old R08 comparator','16MB profile','second block','internal four-choice R08/r02 comparisons','new optimization','old raw substitution'],
        'adoption':'Use this complete campaign in full after completion; no favorable run/case selection. Retain history separately.',
        'failure_policy':'Stop on actual failure; preserve output; do not assemble partial runs. A same-protocol full failed-stage restart requires a new stage directory and explicit event record; algorithm changes require escalation.',
        'temporary_data_directory':str(TMP),'resource_sampling_seconds':30,
        'analysis_policy':'Run pure estimators only after all database timing and support execution end.',
        'coordinator_sha256':sha(__file__),
        'adapter_sha256':{str(p.relative_to(HERE)):sha(p) for folder in ['full-study','support-study'] for p in sorted((HERE/folder).glob('*.py'))}}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--describe',action='store_true')
    args=parser.parse_args()
    if args.describe:
        print(json.dumps(protocol(),indent=2));return 0
    if OUTPUT.exists():raise ValueError('campaign output must be fresh')
    env=common_env();os.environ.update(env)
    tools,controls=tools_and_controls();freeze=json.loads((HERE/'source-freeze.json').read_text())
    guard(freeze,tools)
    OUTPUT.mkdir(parents=True);TMP.mkdir(parents=True, exist_ok=True)
    declaration=protocol();write_once(OUTPUT/'protocol.json',declaration)
    state={'schema':'a018_active_state_v1','status':'running','pid':os.getpid(),
           'started_at':now(),'active_stage':None,'completed_stages':[]}
    replace_state(state)
    resource_module=load('_a018_resources',HERE/'resource_sample.py')
    stop=threading.Event()
    def monitor():
        with (OUTPUT/'resource-samples.jsonl').open('x') as stream:
            while not stop.is_set():
                try:value=resource_module.resource_sample()
                except Exception as exc:value={'at':now(),'error':str(exc)}
                value['active_stage']=state['active_stage'];stream.write(json.dumps(value)+'\n');stream.flush()
                stop.wait(30)
    thread=threading.Thread(target=monitor,daemon=True);thread.start()
    try:
        for stage in ORDER:
            guard(freeze,tools)
            if sha(__file__)!=declaration['coordinator_sha256']:
                raise ValueError('coordinator changed during campaign')
            for rel,digest in declaration['adapter_sha256'].items():
                if sha(HERE/rel)!=digest:raise ValueError('execution adapter changed: '+rel)
            state['active_stage']=stage;state['stage_started_at']=now();replace_state(state)
            print('START '+stage+' '+now(),flush=True)
            if stage in {'mixed','sf10'}:receipt=run_workload(stage,tools,controls,env)
            else:receipt=call(stage_command(stage),OUTPUT/(stage+'.log'),env)
            guard(freeze,tools)
            state['completed_stages'].append({'stage':stage,**receipt});replace_state(state)
            print('COMPLETED '+stage+' '+now(),flush=True)
        state.update(status='completed',active_stage=None,finished_at=now());replace_state(state)
        write_once(OUTPUT/'completion.json',state)
        return 0
    except BaseException as exc:
        state.update(status='failed',error=str(exc),traceback=traceback.format_exc(),finished_at=now())
        replace_state(state);write_once(OUTPUT/'failure.json',state);raise
    finally:
        stop.set();thread.join(timeout=15)


if __name__=='__main__':raise SystemExit(main())
