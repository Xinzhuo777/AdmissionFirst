# Experimental results

These files contain selected observations from the unified 5–6 November 2026 experimental campaign, covering the `mixed` TPC-H/JOB workload, `sf10` TPC-H workload, auxiliary stages E2, E4, E5 and E10, and summaries for admission, content checks, and selection stability.

- `mixed/samples.jsonl` and `sf10/samples.jsonl` contain one record per scheduled observation, including warmups, measurement order, status, SQL hash, and timing fields. `analysis.json` contains selected published-workload case summaries, comparisons and confidence interval results.
- `E2`, `E4`, `E5` and `E10` contain one selected-field record per original auxiliary observation, including statuses, timings, case descriptors and oracle results. The E10 analysis contains case and family statistics.
- `admission21-summary.json`, `content-summary.json` and `stability-summary.json` report aggregate outcomes. They do not replace the underlying per-case evidence for those checks.

Records are field selections from the original outputs; no numerical values were modified. The extraction excludes query plans, SQL text, environment-specific paths, input inventories, operational logs and other fields. Consequently these files do not constitute a complete raw-data archive and do not by themselves rerun the experiments or reproduce every confidence interval or correctness check.

Run `python3 results/verify_results.py` from the repository root to compare the recorded SQL execution medians with the repeated measurements for every applicable mixed and SF10 case/mode. The command also prints the geometric means of the per-case ratios for Native PostgreSQL RLS and local-greedy. Timings depend on hardware and database configuration; a fresh run is not expected to reproduce identical values.
