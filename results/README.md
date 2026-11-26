# Measurements and reported results

This directory holds the request latencies measured for the paper and the
scripts that turn them into every reported latency result.

```sh
python3 results/analyze.py --check   # recompute all tables and compare with the committed files
python3 results/figures.py           # redraw the three latency figures (needs matplotlib)
```

`analyze.py --check` needs only Python 3. It recomputes the files below from
`samples.csv.gz` and fails if any byte differs from the committed version.

## Files

| File | Content |
| --- | --- |
| `samples.csv.gz` | One row per scheduled request: 170 cases × 5 methods × 36 requests = 30,600 rows |
| `conditions.csv` | Median latency of each method in each case (milliseconds) |
| `comparisons.csv` | Per case and baseline: latency ratio to AF, paired 95% interval, outcome |
| `summary.csv` | The latency rows of the paper's performance table |
| `performance-table.md` | The same rows, laid out and rounded as in the paper |
| `paper-numbers.json` | The other latency figures quoted in the evaluation text |
| `analyze.py` | Computes the four files above |
| `figures.py` | Draws the latency CDF, the original-query bars and the path-search figure |

### `samples.csv.gz`

| Column | Meaning |
| --- | --- |
| `request` | Position in the measurement schedule |
| `case` | Case identifier (see `workload/cases.csv`) |
| `method` | `af`, `native` (PostgreSQL RLS), `index_priority`, `in_rewrite`, or `key_array` |
| `cycle` | Measurement cycle 0–3 |
| `kind` | `warmup` (one per cycle) or `measured` (eight per cycle) |
| `round` | Warmup: the cycle; measured: 0–31 |
| `latency_ms` | Time from submitting the SQL text to receiving the complete result |
| `status` | `ok` (completed and returned the correct answer) or `not_run` |

Every completed request returned the correct, complete answer. 72 positions
were not run: IndexPriority on the original JOB 14a query timed out in a
separate 600-second screening run, and the key-array policy on JOB 32a timed
out at the 120-second screening limit. No latency is imputed for them.

The `key_array` method (a policy that compares the key with an array of the
permitted keys) was measured alongside the other four but is not part of the
paper's comparison.

## How the numbers are computed

* **Latency of a method in a case**: the median of its 32 measured requests.
  Warmups are excluded.
* **Ratio**: baseline median / AF median. Values above 1 favor AF.
* **Paired 95% interval**: whole measurement cycles are resampled. Each of the
  4^4 = 256 ordered draws of four cycles, with replacement, gives a median per
  method; the same draw is used for all methods and cases. The interval spans
  the 2.5th and 97.5th percentiles (linear interpolation) of the 256 values.
* **Outcome**: AF wins a case if the interval of baseline/AF lies above 1,
  loses if it lies below 1, and otherwise there is no clear difference.
* **Geometric means** weight cases equally. The table rows use the cases in
  which all four reported methods completed: 119 benchmark cases (JOB 14a is
  excluded after the IndexPriority timeout) and all 50 application cases.
* **AF / fastest**: AF's median divided by the lowest median among the four
  methods. "AF fastest" counts cases where that ratio is exactly 1.

## Measurement setup

Requests were sent one at a time over an open connection, as unprepared SQL,
with libpq's simple query protocol. Each case and method had 4 warmups and 32
measured requests in four cycles; the order of the methods changed between
cycles, and one PostgreSQL instance ran at a time on a private copy of the
database. Every answer was compared with an independently computed reference
(column types, NULLs, duplicates, and the order and limit the query requires).

Hardware and software: MacBook Pro with a 10-core Apple M1 Pro and 32 GB of
memory; PostgreSQL 16.11 with 2 GB of shared buffers, default cost
parameters, autovacuum, JIT and parallel query disabled. The exact server and
session settings are in `workload/postgresql.conf` and `workload/session.json`.
The IN rewrite and the key-array policy ran on unmodified PostgreSQL 16.11.
NativePG-RLS and IndexPriority ran on PostgreSQL 16.11 with an earlier
version of the patch, in its `native` and `index_priority` modes.

AF's latencies were measured with the build that preceded the source in
`src/`. The current source adds the planning-time admission records described
in the paper. On all 170 cases it chooses the same executable plans and
returns the same answers as the measured build (`tools/replay.py` checks
this), but its latencies were not measured again.

Timings depend on hardware, data placement and caching, so a new run gives
different milliseconds. The plans and answers behind these measurements can
be checked with `tools/replay.py` (see `workload/README.md`).

## Not included

The paper's planning-time and prepared-statement measurements, the component
ablations, the sweep over all admitted search alternatives, and the
diagnostic build that admits unsafe orders were separate experiments. Their
data is not part of this directory.
