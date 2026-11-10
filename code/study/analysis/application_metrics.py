"""External reducer of the unchanged original Table 3 drivers and cost sidecar.

No database access. Original estimators and core sources are imported read-only;
raw input is opened only after the sampling completion marker reports pass.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import csv
import hashlib
import json
import math
from pathlib import Path
import random
import statistics
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from caprls_core import reporting as rep
from caprls_core import bootstrap_geomean_ci as boot
from caprls_core.baselines import normalize_mode_id, ADMISSION_FIRST_MODE

NATIVE = 'native-pg-rls'
PD = 'native-pg-rls-physical-design'
AF = ADMISSION_FIRST_MODE
WARMUP = 5
MEASURED = 30
SEED = 62026
DRAWS = 2000


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def write_new(path, obj):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(obj, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write('\n')


def percentile(values, q):
    values = sorted(values)
    if not values:
        return None
    index = (len(values) - 1) * q
    low, high = math.floor(index), math.ceil(index)
    return values[low] + (values[high] - values[low]) * (index - low)


def ratios_summary(values):
    return {'cases': len(values), 'median': statistics.median(values) if values else None,
        'geometric_mean': math.exp(statistics.mean(map(math.log, values))) if values else None,
        'p90': percentile(values, .9), 'min': min(values) if values else None,
        'max': max(values) if values else None}


def hash_token(value):
    return str(value or '').removeprefix('sha256:')


def case_key(row, family):
    return (str(row['query_id']), str(row['param_policy_config_id'] if family == 'E3' else row['policy_id']),
            str(row.get('context_id') or ''))


def validate_inventory(rows, family, blockers):
    inventory = defaultdict(list)
    for row in rows:
        key = (case_key(row, family), row['run_kind'], normalize_mode_id(row.get('mode') or ''),
               str(row.get('template_id') or '') if row['run_kind'] == 'template_candidate' else '')
        inventory[key].append(row)
    for key, members in inventory.items():
        for phase, wanted in [('warmup', WARMUP), ('measured', MEASURED)]:
            ids = [int(r['measurement_iteration']) for r in members if r['measurement_phase'] == phase]
            if len(ids) != wanted or set(ids) != set(range(1, wanted + 1)):
                blockers.append(f'{family}/{key}: {phase} inventory {ids} differs from 1..{wanted}')
    normal = [r for r in rows if r['run_kind'] == 'normal_mode']
    cases = {case_key(r, family) for r in normal}
    wanted_cases = 33 if family == 'E3' else 11
    if len(cases) != wanted_cases:
        blockers.append(f'{family}: expected {wanted_cases} cases, observed {len(cases)}')
    for key in cases:
        chosen = [r for r in normal if case_key(r, family) == key and normalize_mode_id(r['mode']) == AF]
        if len(chosen) != WARMUP + MEASURED or any(r['status'] != 'pass' or r.get('oracle_status') not in ('match', 'pass') for r in chosen):
            blockers.append(f'{family}/{key}: selected-query count/reference correctness incomplete')
    return {'case_count': len(cases), 'all_record_count': len(rows), 'normal_record_count': len(normal),
            'logical_record_groups': len(inventory), 'required_warmup': WARMUP, 'required_measured': MEASURED}


def cells_from_rows(rows, family, blockers):
    grouped = defaultdict(lambda: defaultdict(list))
    for row in rows:
        if row['run_kind'] != 'normal_mode' or row['measurement_phase'] != 'measured' or row['status'] != 'pass':
            continue
        mode = normalize_mode_id(row['mode'])
        if family == 'E3' and mode not in boot.E3_POLICY_ENFORCEMENT_MODES:
            continue
        if family == 'E10' and mode not in (AF, NATIVE, PD):
            continue
        value = float(row['total_ms'])
        if value <= 0:
            blockers.append(f'{family}/{case_key(row, family)}/{mode}: nonpositive total')
            continue
        grouped[case_key(row, family)][mode].append(boot.Sample(int(row['measurement_iteration']), value,
                                                             str(row.get('runner_sql_hash') or '')))
    output = []
    for key, bymode in sorted(grouped.items()):
        if not {AF, NATIVE, PD}.issubset(bymode):
            blockers.append(f'{family}/{key}: missing AF/native/control mode')
            continue
        bad = False
        for mode, values in bymode.items():
            ids = [v.iteration for v in values]
            if len(ids) != MEASURED or set(ids) != set(range(1, MEASURED + 1)):
                blockers.append(f'{family}/{key}/{mode}: invalid measured inventory')
                bad = True
            if family == 'E3' and len({v.runner_sql_hash for v in values}) != 1:
                blockers.append(f'{family}/{key}/{mode}: original SQL pool requires stable hash')
                bad = True
        if not bad:
            output.append((key, boot.Cell(key[:2], {m: tuple(sorted(v, key=lambda x: x.iteration))
                                                   for m, v in bymode.items()})))
    return output


def case_statistics(cell, family):
    native = {x.iteration: x for x in cell.samples_by_mode[NATIVE]}
    control = {x.iteration: x for x in cell.samples_by_mode[PD]}
    if any(not native[i].runner_sql_hash or native[i].runner_sql_hash != control[i].runner_sql_hash for i in cell.iterations):
        raise ValueError('Native/PD do not have identical original timed SQL')
    aa = [abs(math.log(native[i].total_ms / control[i].total_ms)) for i in cell.iterations]
    envelope = percentile(aa, .9)
    ratio_fn = boot._e3_ratio if family == 'E3' else boot._e10_ratio
    point = ratio_fn(cell, cell.iterations)
    rng = random.Random(SEED)
    draws = []
    differences = []
    for _ in range(DRAWS):
        ids = [rng.choice(cell.iterations) for _ in cell.iterations]
        if family == 'E3':
            groups = defaultdict(list)
            mode_hash = {}
            for mode, samples in cell.samples_by_mode.items():
                byid = {sample.iteration: sample for sample in samples}
                mode_hash[mode] = samples[0].runner_sql_hash
                groups[mode_hash[mode]].extend(byid[i].total_ms for i in ids)
            n = statistics.median(groups[mode_hash[NATIVE]])
            a = statistics.median(groups[mode_hash[AF]])
        else:
            n = statistics.median(native[i].total_ms for i in ids)
            af = {x.iteration: x for x in cell.samples_by_mode[AF]}
            a = statistics.median(af[i].total_ms for i in ids)
        draws.append(n / a)
        differences.append(n - a)
    low, high = percentile(draws, .025), percentile(draws, .975)
    label = 'win' if low > math.exp(envelope) else ('loss' if high < math.exp(-envelope) else 'unresolved')
    if family == 'E3':
        groups = defaultdict(list)
        for mode, samples in cell.samples_by_mode.items():
            groups[samples[0].runner_sql_hash].extend(x.total_ms for x in samples)
        medians = {mode: statistics.median(groups[samples[0].runner_sql_hash])
                   for mode, samples in cell.samples_by_mode.items()}
    else:
        medians = {mode: statistics.median(x.total_ms for x in samples)
                   for mode, samples in cell.samples_by_mode.items()}
    delta = medians[NATIVE] - medians[AF]
    return {'native_over_af': point, 'classification': label,
        'classification_meaning': 'difference resolved beyond same-SQL fluctuation' if label != 'unresolved'
            else 'unresolved_difference_not_beyond_measurement_fluctuation',
        'paired_ratio_ci95': [low, high], 'native_minus_af_ms': delta, 'native_minus_af_us': delta * 1000,
        'paired_absolute_difference_ci95_ms': [percentile(differences, .025), percentile(differences, .975)],
        'aa_log_envelope_p90': envelope, 'aa_relative_envelope': math.expm1(envelope),
        'raw_unpooled_native_over_pd': [native[i].total_ms / control[i].total_ms for i in cell.iterations],
        'mode_medians_original_estimator_ms': medians, 'observed_positive_difference_diagnostic': delta > 0}


def match_choice(key, family, rows, costs, blockers):
    qid, pid, ctx = key
    candidates = [c for c in costs if c.get('record_kind') == 'choice' and c.get('family') == family and
                  c.get('query_id', c.get('case_id')) == qid and
                  (family != 'E3' or c.get('policy_id') == pid)]
    measured_rows = [r for r in rows if r['run_kind'] == 'normal_mode' and r['measurement_phase'] == 'measured' and
                     normalize_mode_id(r['mode']) == AF and case_key(r, family) == key]
    byrep = {int(r['measurement_iteration']): r for r in measured_rows}
    expected = 1 if family == 'E3' else WARMUP + MEASURED
    if len(candidates) != expected:
        blockers.append(f'{family}/{key}: expected {expected} choice records, found {len(candidates)}')
    active = candidates if family == 'E3' else [c for c in candidates if c.get('phase') == 'measured']
    if family == 'E10':
        for phase, wanted in [('warmup', WARMUP), ('measured', MEASURED)]:
            ids = [int(c['iteration']) for c in candidates if c.get('phase') == phase]
            if len(ids) != wanted or set(ids) != set(range(1, wanted + 1)):
                blockers.append(f'{family}/{key}: choice {phase} repetition inventory mismatch')
    identities = set()
    for c in active:
        targets = measured_rows if family == 'E3' else [byrep.get(int(c['iteration']))]
        for row in targets:
            if row is None or c['selected_template_id'] != row['template_id']:
                blockers.append(f'{family}/{key}: chosen template mismatch')
                continue
            sql_hash = c.get('original_timed_runner_sql_hash') if family == 'E3' else c.get('original_runner_sql_hash_if_available')
            # E10's original raw hash is SHA(JSON({'runner_sql': text})), while
            # the external observer hashes plain text. Preserve the raw hash
            # for original estimators and bind the sidecar to an added text SHA.
            actual_binding_hash = row.get('runner_sql_hash') if family == 'E3' else row.get('_runner_sql_plain_text_sha256')
            if sql_hash is not None and hash_token(sql_hash) != hash_token(actual_binding_hash):
                blockers.append(f'{family}/{key}: original timed SQL mismatch')
            identities.add((row['template_id'], row.get('runner_sql_hash'), ctx, c.get('state_context_hash')))
    values = [float(c['choice_cost_ms']) for c in active if c.get('choice_cost_ms') is not None]
    if any(v <= 0 for v in values) or len(values) != (1 if family == 'E3' else MEASURED):
        blockers.append(f'{family}/{key}: choice cost sample inventory/value invalid')
    return {'choice_cost_ms': statistics.median(values) if values else None,
        'choice_cost_observations': len(values), 'choice_stable': len(identities) == 1,
        'choice_cost_scope': 'E3 original planner core with planning inputs already collected' if family == 'E3'
            else 'E10 original START/STOP anchor including case planning inputs',
        'frequency': 'one observed choice per case' if family == 'E3' else 'original choice per repetition',
        'observed_choice_identities': sorted([list(i) for i in identities], key=repr),
        'input_sidecar_kept_separate_from_primary': True,
        'choice_observations': active}


def family_report(family, cases, cells, loss_rows, oracle_rows):
    result = {'cases': len(cases), 'native_over_af': ratios_summary([c['native_over_af'] for c in cases]),
        'classification': dict(Counter(c['classification'] for c in cases)),
        'choice_cost_ms_median': statistics.median(c['choice_cost_ms'] for c in cases) if cases else None,
        'choice_cost_scope': 'given planning inputs' if family == 'E3' else 'including planning inputs',
        'stable_choices': sum(c['choice_stable'] for c in cases),
        'resolved_positive_savings_cases': sum(c['eligible_for_recovery'] for c in cases),
        'conditional_recovery_median_executions': statistics.median([c['recovery_executions'] for c in cases
            if c['recovery_executions'] is not None]) if any(c['recovery_executions'] is not None for c in cases) else None,
        'observed_positive_count_diagnostic': sum(c['observed_positive_difference_diagnostic'] for c in cases)}
    if cells:
        estimator = 'e3_exact_runner_sql_pooling' if family == 'E3' else 'e10_mode_local'
        values = boot.bootstrap_distribution([cell for _, cell in cells], estimator=estimator,
            seed=boot.DEFAULT_SEED + (family == 'E10'), replicates=boot.DEFAULT_REPLICATES)
        result['native_over_af']['ci95'] = list(boot.percentile_interval(values))
        result['native_over_af']['bootstrap_replicates'] = boot.DEFAULT_REPLICATES
    if family == 'E3':
        values = [float(r['admission_first_slowdown_vs_fastest']) for r in loss_rows]
        result['af_over_fastest_mode'] = ratios_summary(values)
        result['af_over_fastest_mode']['exactly_fastest_cases'] = sum(math.isclose(v, 1, abs_tol=1e-12) for v in values)
        result['af_over_fastest_mode']['definition'] = 'original canonical total-ms mode medians; same applicable policy-enforcement modes'
    else:
        bycase = defaultdict(list)
        for row in oracle_rows:
            bycase[(row['query_id'], row['policy_id'], row['context_id'])].append(row)
        gaps = [statistics.median(float(r['oracle_gap']) for r in group) for group in bycase.values()]
        result['af_over_fastest_admitted'] = ratios_summary(gaps)
        result['af_over_fastest_admitted']['exact_case_matches'] = sum(math.isclose(v, 1, rel_tol=1e-12, abs_tol=1e-12) for v in gaps)
        result['af_over_fastest_admitted']['definition'] = 'original within-repetition execution-only chosen/eligible-oracle ratio, then case median'
        result['af_over_fastest_admitted']['measured_choice_observations'] = len(oracle_rows)
        result['af_over_fastest_admitted']['exact_observation_matches'] = sum(bool(r['chosen_is_measured_best']) for r in oracle_rows)
    return result


def write_csv_new(path, rows):
    fields = list(dict.fromkeys(k for row in rows for k in row))
    with path.open('x', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows({k: json.dumps(v) if isinstance(v, (dict, list, tuple)) else v for k, v in row.items()} for row in rows)


def analyze(run, out):
    completion = json.loads((run / 'completion.json').read_text())
    if completion.get('status') != 'pass':
        raise ValueError('Sampling did not complete with pass; refusing full raw analysis')
    out.mkdir(parents=True, exist_ok=False)
    snapshot = json.loads((run / 'original_source_snapshot.json').read_text())
    changed = [p for p, value in snapshot.items() if sha(ROOT / p) != value]
    if changed:
        raise ValueError(f'Frozen original sources changed: {changed}')
    protocol = json.loads((run / 'protocol.json').read_text())
    if protocol.get('warmup') != WARMUP or protocol.get('measured') != MEASURED:
        raise ValueError('Predeclared 5/30 protocol differs')
    costs = [json.loads(line) for line in (run / 'choice_costs.jsonl').read_text().splitlines() if line.strip()]
    blockers, warnings, cases, families, inventories, hashes = [], [], [], {}, {}, {}
    for family in ('E3', 'E10'):
        raw = rep._load_raw_records(run / family, family)
        rows = []
        for record in raw:
            row = rep._flatten_record(record)
            runner_text = record.get('sql', {}).get('runner_sql')
            row['_runner_sql_plain_text_sha256'] = hashlib.sha256(runner_text.encode()).hexdigest() if isinstance(runner_text, str) else None
            rows.append(row)
        hashes[family] = {str(Path(r['_raw_path']).relative_to(run)): sha(r['_raw_path']) for r in raw}
        del raw
        inventories[family] = validate_inventory(rows, family, blockers)
        cells = cells_from_rows(rows, family, blockers)
        cell_rows = rep._cell_stats(rows)
        if family == 'E3':
            rep._annotate_e3_runner_sql_canonical_latencies(rows, cell_rows)
        loss_rows = rep._e3_loss_table(cell_rows)[0] if family == 'E3' else []
        oracle_rows = rep._template_oracle_analysis(rows)[0] if family == 'E10' else []
        if family == 'E10' and len(oracle_rows) != 11 * MEASURED:
            blockers.append(f'E10: expected {11 * MEASURED} original oracle observations, got {len(oracle_rows)}')
        write_csv_new(out / (family + '_runs.csv'), rows)
        write_csv_new(out / (family + '_cell_stats.csv'), cell_rows)
        write_csv_new(out / (family + '_loss_table.csv' if family == 'E3' else family + '_template_oracle_analysis.csv'),
                      loss_rows if family == 'E3' else oracle_rows)
        chosen_cases = []
        for key, cell in cells:
            try:
                stats = case_statistics(cell, family)
            except ValueError as exc:
                blockers.append(f'{family}/{key}: {exc}')
                continue
            cost = match_choice(key, family, rows, costs, blockers)
            stats.update({'family': family, 'query_id': key[0], 'policy_id': key[1], 'context_id': key[2], **cost})
            eligible = stats['classification'] == 'win' and cost['choice_stable'] and cost['choice_cost_ms'] is not None
            stats['eligible_for_recovery'] = eligible
            stats['recovery_executions'] = math.ceil(cost['choice_cost_ms'] / stats['native_minus_af_ms']) if eligible else None
            if not cost['choice_stable']:
                warnings.append(f'{family}/{key}: changing chosen SQL/state; single-choice recovery not estimated')
            chosen_cases.append(stats)
        cases.extend(chosen_cases)
        families[family] = family_report(family, chosen_cases, cells, loss_rows, oracle_rows)
        del rows, cell_rows
    changed_after = [p for p, value in snapshot.items() if sha(ROOT / p) != value]
    if changed_after:
        blockers.append(f'Sources changed during reduction: {changed_after}')
    ready = not blockers and len(cases) == 44
    report = {'schema': 'caprls-original-protocol-independent-analysis-v2-text-binding', 'ready': ready,
        'completed_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'source_activity': str(run), 'blockers': blockers, 'warnings': warnings,
        'cases': cases, 'families': families, 'inventory': inventories,
        'source_snapshot_sha256': sha(run / 'original_source_snapshot.json'),
        'source_snapshot_changed': changed_after, 'raw_file_sha256': hashes,
        'choice_sidecar_sha256': sha(run / 'choice_costs.jsonl'), 'completion_sha256': sha(run / 'completion.json'),
        'analyzer_sha256': sha(Path(__file__)),
        'contract': {'performance': 'unchanged original four Table 3 row definitions',
            'E3': 'exact timed SQL pooling for point and each paired bootstrap draw',
            'E10': 'mode-local total medians; admitted-candidate row retains execution-only oracle ratios',
            'warmup': WARMUP, 'measured': MEASURED,
            'noise': 'same-case raw unpooled Native/Native+PD p90 absolute log ratio',
            'classification': 'paired 95% interval beyond noise envelope; otherwise unresolved',
            'classification_seed': SEED, 'classification_draws': DRAWS,
            'cost': 'E3 original core given inputs; E10 original anchor including inputs',
            'sql_binding': 'E10 sidecar text SHA checked against original raw SQL text; original JSON-encoded hash retained for performance',
            'recovery': 'same-activity C divided by original case-estimator saving; stable resolved wins only',
            'core_source_mutation': False, 'database_access': False, 'old_result_replacement': False}}
    write_new(out / 'analysis.json', report)
    lines = ['# 同批原协议 Table 3 双分面草案', '',
        'Panel A 保留原四行。倍率和候选范围均按原方法；U 表示差距未与实测波动分离。', '',
        '| Comparison | Cases | Median | GM | P90 | Outcome |', '| --- | ---: | ---: | ---: | ---: | --- |']
    for family, name in [('E3', 'Mixed'), ('E10', 'Application')]:
        f = families[family]; x = f['native_over_af']; count = f['classification']
        lines.append(f"| {name}: Native / AF | {f['cases']} | {x['median']:.6f} | {x['geometric_mean']:.6f} | {x['p90']:.6f} | {count.get('win',0)}/{count.get('unresolved',0)}/{count.get('loss',0)} W/U/L |")
        x = f['af_over_fastest_mode' if family == 'E3' else 'af_over_fastest_admitted']
        outcome = f"{x['exactly_fastest_cases']} exactly fastest" if family == 'E3' else f"{x['exact_case_matches']}/{f['cases']} exact case matches"
        lines.append(f"| {name}: AF / fastest {'mode' if family == 'E3' else 'admitted'} | {f['cases']} | {x['median']:.6f} | {x['geometric_mean']:.6f} | {x['p90']:.6f} | {outcome} |")
    lines += ['', 'Panel B 使用本次真实选择窗口及同批服务器时间分母。', '',
        '| Workload and choice scope | Cases | Choice median (s) | Stable resolved saving | Unresolved | Conditional recovery median |',
        '| --- | ---: | ---: | ---: | ---: | ---: |']
    for family, name in [('E3','Mixed: given inputs'), ('E10','Application: including inputs')]:
        f = families[family]
        lines.append(f"| {name} | {f['cases']} | {f['choice_cost_ms_median']/1000:.6f} | {f['resolved_positive_savings_cases']} | {f['classification'].get('unresolved',0)} | {f['conditional_recovery_median_executions']} |")
    lines += ['', '回本中位数仅针对选择一致且获益可分辨的子集，条件是选择继续适用、节省持续；原型尚无持久选择缓存。E3 只有每 case 一次真实选择观察，family 中位数跨 case 计算；E10 每 case 成本取30次正式原 anchor 中位数。',
        '', '此草案与新JSON供人工审查，尚未修改正文或采用新数字。']
    with (out / 'table3_draft.md').open('x', encoding='utf-8') as stream:
        stream.write('\n'.join(lines) + '\n')
    receipt = {'schema': 'caprls-original-protocol-independent-receipt-v1',
        'status': 'pass' if ready else 'needs_review', 'ready': ready, 'completed_at': report['completed_at'],
        'cases': len(cases), 'families': families, 'blockers': blockers, 'warnings': warnings,
        'core_hashes_match': not changed_after, 'source_snapshot_sha256': report['source_snapshot_sha256'],
        'choice_sidecar_sha256': report['choice_sidecar_sha256'], 'analysis_sha256': sha(out / 'analysis.json'),
        'analysis_path': str(out / 'analysis.json'), 'table3_draft_path': str(out / 'table3_draft.md'),
        'no_sampling_database_or_manuscript_write': True}
    write_new(out / 'receipt.json', receipt)
    print(json.dumps(receipt, ensure_ascii=False), flush=True)
    return 0 if ready else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    return analyze(args.run, args.output)


if __name__ == '__main__':
    raise SystemExit(main())
