# Evaluation workload

The paper evaluates 170 cases: 120 benchmark cases on TPC-H and the Join
Order Benchmark (JOB), and 50 cases of a synthetic multi-tenant application.
This directory contains everything needed to run them again: the exact SQL,
the policies, the server and session settings, the recorded plans and
answers, and scripts that rebuild the six databases.

| Group (`workload`) | Cases | Database | Content |
| --- | ---: | --- | --- |
| `adapted` | 33 | `tpch_job` | TPC-H Q3, Q5, Q7, Q10, Q12 (SF1) and JOB 1a, 2a, 3c, 6d, 10a, 16b, each under an equality, a membership and a key-predicate policy |
| `adapted-sf10` | 15 | `tpch_sf10` | The five TPC-H queries at scale factor 10 under the same three policies |
| `original` | 72 | `original_queries` | Original SQL: eight TPC-H queries under three policies, 36 JOB queries under a membership policy, and six TPC-H queries with `orders` (and `lineitem`) also protected |
| `title-search` | 27 | `title_search` | Title searches over 524,288 documents that call a logging function `prefix_audit_secret`; 3 permission levels × 9 query forms |
| `path-search` | 12 | `path_search` | Document-path searches over one million documents with different prefix ranges and permission densities |
| `daily-requests` | 11 | `application` | Routine application requests: ticket lookup, dashboards, invoices, an audited document search, an ordered export, and requests after a revocation or a state change |

## Files

`cases.csv` lists the cases with their group, a description, the policy
type, the database, the login role, the protected tables, and whether the
case needs extra state or has an audit check.

Each case has a folder `cases/<group>/<name>/`:

| File | Content |
| --- | --- |
| `query.sql` | The SQL exactly as measured |
| `policy.sql` | Installs the row-level-security policy as written. Run as superuser before the query. AF, NativePG-RLS and IndexPriority all use this policy |
| `baseline-in_rewrite.sql` | The policy rewritten with an `IN` subquery (the IN-rewrite baseline) |
| `baseline-key_array.sql` | The policy rewritten to compare with an array of permitted keys |
| `expected-plan.json` | AF's executable plan in the measured run, from `EXPLAIN (VERBOSE, COSTS, SETTINGS, FORMAT JSON)`, without the two cost-estimate fields and with index OIDs replaced by index names |
| `expected.json` | SHA-256 digests of AF's complete typed answer (in returned order and as a multiset), its row count and columns, and the expected audit counts |
| `state-apply.sql`, `state-restore.sql` | Only for daily requests that need a revoked membership, a stale summary, another user context, or a partial index; the replay applies and then undoes them |
| `audit-reference.sql` | Only for the audited document search: the inputs the logging function may receive |

`postgresql.conf` holds the server settings of all measurements and
`session.json` the settings of each measured session.

Object names inside the SQL (for example `caprls_e3_rls_user`,
`public.a027_document` or `a031_policy`) are kept exactly as they were in
the measured databases. They appear in the stored data, in the recorded
plans and in the policies, so renaming them would change what is compared.

## Building the databases

`databases/` contains one build script per database. They create the
databases with the same content and the same physical row order as the
databases used for the measurements, and verify the result against
checksums of the originals. PostgreSQL's `ANALYZE` samples rows at random,
so each script then loads the planner statistics recorded from the
original database; without them, a few plans can differ.

`databases/build_all.sh` creates a new cluster with the experiment settings
and builds all six databases into it:

```sh
sh workload/databases/build_all.sh --install /path/to/build/install \
    --cluster /absolute/path/to/new/cluster --raw-data /path/to/raw-data
```

The TPC-H and IMDb files are not included. The scripts expect them in one
directory:

```
raw-data/tpch/sf1/   customer.tbl lineitem.tbl nation.tbl orders.tbl part.tbl partsupp.tbl region.tbl supplier.tbl
raw-data/tpch/sf10/  the same eight files at scale factor 10
raw-data/imdb/csv/   the 21 CSV files of the JOB IMDb snapshot (aka_name.csv ... title.csv)
```

* TPC-H: download TPC-H Tools v3.0.1 from the
  [TPC](https://www.tpc.org/tpc_documents_current_versions/current_specifications5.asp)
  (its license does not allow redistribution), build `dbgen` from
  `makefile.suite` (`DATABASE=DB2 MACHINE=LINUX WORKLOAD=TPCH`; recent
  compilers also need `-fcommon -Wno-implicit-function-declaration`), and run
  `./dbgen -s 1 -f` and `./dbgen -s 10 -f`.
* IMDb: download `imdb.tgz` of the Join Order Benchmark from CWI (linked from
  the [JOB repository](https://github.com/gregrahn/join-order-benchmark)) and
  unpack it into `raw-data/imdb/csv/`.

The scripts check the size and SHA-256 of every input file
(`databases/*/inputs.sha256`) before loading. The synthetic databases
(`title_search`, `path_search`, `application`) are generated and need no
input files.

## Replaying the cases

```sh
python3 tools/replay.py --install /path/to/build/install \
    --socket-dir /path/to/cluster/socket --port 54410 --admin postgres \
    --output /absolute/path/to/new/replay-output
```

For every case the replay installs `policy.sql` (and any state), connects as
the case's ordinary role with the settings of `session.json` and
`native_af.mode = 'af'`, runs the query once, records its plan, runs it
again, and compares:

* **plan**: the executable plan equals `expected-plan.json`;
* **answer**: the complete typed answer has the recorded digest;
* **audit**: the logging function received the recorded number of inputs,
  none of them unauthorized (27 title searches with 222,122 inputs in total,
  and the audited document search with 1,400).

The report is written to `replay.csv` and `summary.json` in the output
directory; plans that differ are saved in its `plans/` directory, and
`--save-plans` saves every plan. Use `--case`
to select cases (for example `--case 'path-search/*'`).

AF's cost model takes into account how much of a relation is already cached
in shared buffers and in the operating system's page cache
(`native_af.cache_aware_cost`, `native_af.os_cache_cost`). The measurements
ran on warm data: each query had already run many times, under five methods,
when its plan was recorded. The replay reproduces this state. Before the
cases of a database it reads all of the database's tables and indexes into
the operating system's page cache (`pg_prewarm` in `read` mode; the
extension is built by `src/build.sh` and created only for this step), and it
runs each query once before recording the plan. With a cold cache, AF
estimates more I/O; for one SF10 query this turns a hash aggregation into a
sort-based one, because the two then cost within PostgreSQL's 1% tolerance.
The machine therefore needs enough memory to hold the largest database
(about 12 GB). `--no-prewarm` skips this step; answers must match either way.
