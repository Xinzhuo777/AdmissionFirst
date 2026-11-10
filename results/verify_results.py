#!/usr/bin/env python3
"""Check case medians against the included repeated SQL execution samples."""
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for stage in ('mixed', 'sf10'):
    analysis = json.loads((ROOT / stage / 'analysis.json').read_text())
    observations = defaultdict(list)
    with (ROOT / stage / 'samples.jsonl').open() as stream:
        for line in stream:
            row = json.loads(line)
            value = row['measurement']['execution_ms']
            if row['phase'] == 'measured' and row['status'] == 'pass' and value is not None:
                observations[(row['case_id'], row['mode'])].append(value)
    checked = 0
    for row in analysis['summary_rows']:
        expected = row['median_postgres_query_execution_ms']
        if row['status'] != 'pass' or expected is None:
            continue
        key = row['case_id'], row['mode']
        if not observations[key]:
            raise AssertionError(f'{stage}: no measured observations for {key}')
        actual = statistics.median(observations[key])
        if not math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-10):
            raise AssertionError(f'{stage}: median mismatch for {key}: {actual} != {expected}')
        checked += 1
    print(f'{stage}: {checked} case/mode SQL medians verified')
    summaries = {(r['case_id'], r['mode']): r for r in analysis['summary_rows']}
    for comparator in ('native-pg-rls', 'local-greedy'):
        cases = analysis['comparisons']['sql_execution'][comparator]['cases']
        for case in cases:
            af = summaries[(case['case_id'], 'af')]['median_postgres_query_execution_ms']
            baseline = summaries[(case['case_id'], comparator)]['median_postgres_query_execution_ms']
            if not math.isclose(baseline / af, case['ratio'], rel_tol=1e-12):
                raise AssertionError(f"{stage}: ratio mismatch for {case['case_id']} / {comparator}")
        geometric_mean = math.exp(sum(math.log(case['ratio']) for case in cases) / len(cases))
        print(f'  {comparator}/AF geometric mean: {geometric_mean:.6f} ({len(cases)} cases)')
