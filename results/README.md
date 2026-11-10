# Results

These files contain selected measurements from the AdmissionFirst experiments.

- `mixed/` contains the TPC-H SF1 and JOB results.
- `sf10/` contains the TPC-H SF10 results.
- `E2/`, `E4/`, `E5/`, and `E10/` contain auxiliary experiment measurements;
  `E10/analysis.json` also contains case and family statistics.
- The summary files cover admission, content checks, and selection stability.

Each `samples.jsonl` file contains selected fields from the original records,
including timing and status. The mixed and SF10 files also include warmups,
measurement order, and SQL hashes. The corresponding `analysis.json` files
contain case summaries and comparisons.

From the repository root, check the mixed and SF10 execution-time medians and
case ratios with:

```sh
python3 results/verify_results.py
```

These files are an extract of the original results, not a complete raw-data
archive. They do not contain everything needed to recompute every confidence
interval or correctness check. Timing results will vary across machines.
