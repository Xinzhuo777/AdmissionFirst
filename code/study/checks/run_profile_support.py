"""Run selected 52/110 support with one explicit, audited PG memory profile.

The legacy CONTENT fixture sets 16MB immediately before opening its cluster.
This external common-configuration adapter reinstalls the declared profile
at that boundary. It changes no algorithm, specification or per-case check.
"""
import argparse
from contextlib import contextmanager
from dataclasses import asdict
import importlib.util
import json
from pathlib import Path
import sys


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True)
    parser.add_argument('--source-root', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--profiles', required=True)
    parser.add_argument('--profile', choices=('legacy_16mb','shared_host_2gb'), required=True)
    parser.add_argument('--stage', choices=('CONTENT','STABILITY'), required=True)
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()
    folder = Path(__file__).resolve().parent
    root, source, output = map(lambda x:Path(x).resolve(), (args.root,args.source_root,args.output_dir))
    if output.exists():raise ValueError('support output must be fresh')
    profiles_path = Path(args.profiles).resolve()
    profile_bytes = profiles_path.read_bytes()
    profile = json.loads(profile_bytes)['profiles'][args.profile]
    controller = load('_a016_support_profile_controls',folder.parent/'drivers/campaign_controller.py')
    tools = controller.load_tools()
    if args.stage == 'STABILITY':
        tools.activate_source(source)
    else:
        sys.path.insert(0,str(root))
    from caprls_core import postgres_runner as pg
    original = pg.temporary_cluster
    receipts = []

    @contextmanager
    def explicit_cluster(*positional, **keywords):
        controller.install_profile(profile)
        with original(*positional,**keywords) as env:
            actual = controller.settings(pg,env)
            controller.verify_settings(actual,profile)
            receipt = {'schema':'a016_support_actual_profile_v1','at':tools.now(),
                'stage':args.stage,'profile':args.profile,'pg_env':asdict(env),
                'profiles_sha256':tools.digest_bytes(profile_bytes),'actual_settings':actual}
            target = output/'profile-receipts'/('cluster-'+str(len(receipts)+1)+'.json')
            tools.write_once(target,receipt)
            receipts.append(receipt)
            yield env
            if controller.settings(pg,env) != actual:
                raise ValueError('support GUCs changed within the cluster')

    pg.temporary_cluster = explicit_cluster
    try:
        if args.stage == 'CONTENT':
            adapter = load('_a016_selected_content',folder/'content.py')
            result = adapter.run(root,source,Path(args.manifest).resolve(),
                root/'specs/content_compatibility_full_predicate.yaml',output)
        else:
            adapter = load('_a016_selected_stability',folder/'stability.py')
            namespace = argparse.Namespace(root=str(root),source_root=str(source),manifest=args.manifest,
                output_dir=str(output),worker_timeout=1800)
            result = adapter.run_study(namespace)
    finally:
        pg.temporary_cluster = original
    if profiles_path.read_bytes() != profile_bytes or len(receipts) != 1:
        raise ValueError('support profile declaration or cluster count changed')
    if result['status'] != 'pass':raise ValueError('support stage did not pass')
    tools.write_once(output/'a016-profile-support-completion.json',{
        'schema':'a016_profile_support_completion_v1','status':'pass','at':tools.now(),
        'stage':args.stage,'profile':args.profile,'actual_cluster_count':len(receipts),
        'source_identity':tools.source_identity(source),
        'query_latency_measured':False,'algorithm_or_specification_changes':False})
    print(json.dumps({'stage':args.stage,'profile':args.profile,'status':'pass'}),flush=True)


if __name__ == '__main__':
    main()
