"""Reduce the final AF application run with the existing application estimators."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys
from typing import Any
from . import selection_cost_observed_analyze as observed


def write_new(path: Path, value: Any) -> None:
    with path.open('x',encoding='utf-8') as handle:
        json.dump(value,handle,ensure_ascii=False,indent=2,allow_nan=False)
        handle.write('\n')

def analyze(run: Path, output: Path) -> dict[str,Any]:
    run,output=run.resolve(),output.resolve()
    if output.exists() or output.is_relative_to(run):
        raise ValueError('analysis requires a fresh output outside the raw run')
    completion=json.loads((run/'completion.json').read_text())
    protocol=json.loads((run/'protocol.json').read_text())
    if completion['status']!='completed' or completion['source_drift'] or completion['protected_drift']:
        raise ValueError('application run is not complete or immutable')
    config=protocol['configuration']
    if config['stage']!='E10' or config['manifest']['repetitions']!={'warmup':5,'measured':30}:
        raise ValueError('application protocol differs from the declared 5/30 study')
    # Reuse the established application estimator, not its historical data or
    # activity gates. Restore its old path insertion immediately after import.
    before=list(sys.path)
    try:
        pure=observed.load_pure_reducer()
    finally:
        sys.path[:]=before
    pure.ROOT=observed.ROOT
    pure.DRAWS=10000
    pure.boot.DEFAULT_REPLICATES=10000
    raw=pure.rep._load_raw_records(run/'raw','E10')
    rows=[]
    hashes={}
    for record in raw:
        row=pure.rep._flatten_record(record)
        sql=record.get('sql',{}).get('runner_sql')
        row['_runner_sql_plain_text_sha256']=hashlib.sha256(sql.encode()).hexdigest() if isinstance(sql,str) else None
        rows.append(row)
        path=Path(record['_raw_path'])
        hashes[str(path.relative_to(run))]=observed.sha(path)
    blockers=[]
    inventory=pure.validate_inventory(rows,'E10',blockers)
    cells=pure.cells_from_rows(rows,'E10',blockers)
    if len(cells)!=11:
        blockers.append(f'expected 11 complete application cases, got {len(cells)}')
    costs=observed.read_jsonl(run/'choice_costs.jsonl')
    expected_keys=sorted({('E10',pure.case_key(row,'E10')[0],'') for row in rows if row['run_kind']=='normal_mode'})
    components=observed.validate_and_summarize_components(costs,expected_keys)
    blockers.extend(components['blockers'])
    stats=[]
    for key,cell in cells:
        case=pure.case_statistics(cell,'E10')
        choice=pure.match_choice(key,'E10',rows,costs,blockers)
        case.update({'family':'E10','query_id':key[0],'policy_id':key[1],'context_id':key[2],**choice})
        eligible=case['classification']=='win' and choice['choice_stable'] and choice['choice_cost_ms'] is not None and case['native_minus_af_ms']>0
        case['eligible_for_recovery']=eligible
        case['recovery_executions']=math.ceil(choice['choice_cost_ms']/case['native_minus_af_ms']) if eligible else None
        stats.append(case)
    oracle=pure.rep._template_oracle_analysis(rows)[0]
    if len(oracle)!=330:
        blockers.append(f'expected 330 measured application choice observations, got {len(oracle)}')
    family=pure.family_report('E10',stats,cells,[],oracle) if not blockers else None
    report={'schema':'final_af_application_analysis_v1','created_at':datetime.now(timezone.utc).isoformat(),
        'analysis_ready':not blockers,'blockers':blockers,'source_run':str(run),'af':'one final AF',
        'comparators':'ordinary baseline implementations in the final application driver',
        'estimator':'existing application server-latency and native identical-SQL noise-control estimator; 10000 paired bootstrap replicates',
        'choice_cost_scope':'same-run SparseSelectionObserver; includes planning inputs',
        'choice_components':components,'family':family,'cases':stats,'inventory':inventory,
        'raw_files':hashes,'choice_sidecar_sha256':observed.sha(run/'choice_costs.jsonl'),
        'completion_sha256':observed.sha(run/'completion.json'),'protocol_sha256':observed.sha(run/'protocol.json'),
        'reducer_sha256':observed.sha(observed.PURE_REDUCER),'analyzer_sha256':observed.sha(Path(__file__)),
        'all_results_from_this_run':True,'manuscript_modified':False}
    output.mkdir(parents=True,exist_ok=False)
    write_new(output/'analysis.json',report)
    pure.write_csv_new(output/'case-statistics.csv',stats)
    pure.write_csv_new(output/'template-oracle.csv',oracle)
    pure.write_csv_new(output/'cell-statistics.csv',pure.rep._cell_stats(rows))
    return report

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-dir',type=Path,required=True)
    parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args(argv)
    report=analyze(args.input_dir,args.output_dir)
    print(json.dumps({'analysis_ready':report['analysis_ready'],'blockers':report['blockers'],'family':report['family']}))
    return 0 if report['analysis_ready'] else 1
if __name__=='__main__': raise SystemExit(main())
