# A044 measurement snapshot

These measurements use the earlier A043 implementation, not the A047 r05
source currently in `code/`. The current source was separately checked against
A044 plans and answers; this snapshot is not an A047 performance run.

The snapshot records 170 conditions: 120 benchmark conditions and 50 synthetic
application conditions. Each completed condition/method cell contains four
warmups and 32 timed, unprepared requests across four cycles. Latency covers
submitting a request on an open connection and retrieving its complete result.

- `samples.csv.gz` contains timing and status fields for all 30,600 scheduled
  A044 positions: 30,528 completed requests and 72 positions not run after
  earlier timeout decisions. It omits raw query outputs, local paths, and
  timestamps.
- `conditions.csv` contains each condition's median and status for the five
  methods. The array value for JOB 32a is a historical A040 measurement,
  explicitly marked in its source column; it is not an A044 paired sample.
- `summary.csv` contains four-method paired summaries and their reported
  confidence intervals. The common denominator is 119 benchmark and 50
  application conditions. IndexPriority on JOB 14a timed out at 600 seconds;
  no latency was imputed.
- `verify_snapshot.py` verifies the included current-run medians and the
  geometric means on those common denominators. It does not independently
  recompute the confidence intervals or historical array measurement.

The five methods are AF, native RLS, IndexPriority, an IN-policy rewrite, and
an allowed-key array policy. The reported speedup ratios are baseline latency
divided by AF latency; larger than one favors AF. The tests ran on a MacBook
Pro with an Apple M1 Pro, 32 GB RAM, PostgreSQL 16.11, 2 GB shared buffers,
and serial queries. Timings depend on hardware, data, and workload.

This is an extract, not a raw-result archive. It allows the included summaries
to be checked; it does not supply the fixture data or rerun all 170 conditions.
