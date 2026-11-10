"""Profile controls for the experiment runner."""

import argparse
from dataclasses import asdict
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import threading
import time
import traceback


def load_tools():
    p=Path(__file__).with_name('final_af_e3_study.py')
    sp=importlib.util.spec_from_file_location('_a016_campaign_tools',p)
    m=importlib.util.module_from_spec(sp);sys.modules[sp.name]=m;sp.loader.exec_module(m)
    return m


def install_profile(profile):
    os.environ['CAPRLS_PG_SHARED_BUFFERS']=profile['shared_buffers']
    os.environ['CAPRLS_PG_MAX_CONNECTIONS']='10'
    extra=[item for key,value in profile.items() if key!='shared_buffers'
           for item in ('-c',key+'='+value)]
    extra+=['-c','hash_mem_multiplier=2.0','-c','plan_cache_mode=force_custom_plan']
    os.environ['CAPRLS_PG_EXTRA_OPTS']=shlex.join(extra)


def run_command(command, log, tools, cwd=None):
    tools.write_once(log.with_suffix('.command.json'),{'command':list(map(str,command)),
        'started_at':tools.now(),'cwd':str(cwd) if cwd else str(Path.cwd()),'controlled_environment':{k:os.environ.get(k) for k in
            ('CAPRLS_TMPDIR','CAPRLS_PG_SHARED_BUFFERS','CAPRLS_PG_MAX_CONNECTIONS','CAPRLS_PG_EXTRA_OPTS')}})
    with log.open('x') as stream:
        process=subprocess.Popen(list(map(str,command)),stdout=stream,stderr=subprocess.STDOUT,cwd=cwd)
        result=process.wait()
    tools.write_once(log.with_suffix('.exit.json'),{'actual_exit_code':result,'at':tools.now()})
    if result:raise RuntimeError('stage failed with exit '+str(result)+': '+str(log))


def settings(pg,env):
    return json.loads(pg.run_psql_command("""
SELECT json_object_agg(name,json_build_object('setting',setting,'unit',unit,'source',source))::text
FROM pg_settings WHERE name IN ('shared_buffers','work_mem','effective_cache_size','max_wal_size',
 'hash_mem_multiplier','max_connections','autovacuum','jit','max_parallel_workers',
 'max_parallel_workers_per_gather','plan_cache_mode','shared_memory_type','max_worker_processes');
""",env))


def verify_settings(observed, expected):
    factors={'8kB':8192,'kB':1024,'MB':1024**2,'GB':1024**3}
    for key,value in expected.items():
        suffix=next((u for u in ('GB','MB','kB') if value.endswith(u)),None)
        if suffix is None:raise ValueError('unsupported memory profile unit')
        wanted=int(value[:-len(suffix)])*factors[suffix]
        actual=int(observed[key]['setting'])*factors[observed[key]['unit']]
        if wanted!=actual:raise ValueError('actual PostgreSQL parameter differs: '+key)
    for key,value in {'max_connections':'10','autovacuum':'off','jit':'off',
                      'max_parallel_workers':'0','max_parallel_workers_per_gather':'0',
                      'plan_cache_mode':'force_custom_plan'}.items():
        if observed[key]['setting']!=value:raise ValueError('common control differs: '+key)
