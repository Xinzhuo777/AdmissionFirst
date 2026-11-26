# AdmissionFirst

AdmissionFirst (AF) is a modification of the PostgreSQL 16.11 query planner
for tables protected by row-level security (RLS). It is the implementation
and experiment artifact of the paper *Same Rows Are Not Enough*.

PostgreSQL normally evaluates an RLS policy exactly as written. AF adds other
ways to evaluate a supported policy, for example starting from the keys a
user may read, checking rows against a hash table of permitted keys, or
narrowing a `LIKE` search with a prefix range before the access check. Before
the planner compares the cost of such a candidate with the ordinary plans, AF
checks how the candidate enforces the policy (*plan admission*). A candidate
that could pass an unauthorized value to a function that might reveal it is
rejected and never costed. The admitted candidates then compete in
PostgreSQL's normal cost-based search.

## Contents

| Path | Content |
| --- | --- |
| `src/` | The AF sources, the patch to PostgreSQL 16.11, and `build.sh` |
| `tests/` | Safety tests on a small document table |
| `workload/` | The 170 evaluation cases: queries, policies, recorded plans and answers, and scripts that build the databases |
| `tools/` | `replay.py`, which replays the cases and compares them with the recorded run, and a small libpq client |
| `results/` | The 30,600 measured request latencies and the scripts that compute every reported latency result and figure |
| `reproduce.sh` | Runs everything above with one command |

## Reproducing the results

```sh
sh reproduce.sh /absolute/path/to/new/work-directory
```

This takes about ten minutes and needs a C compiler, `make`, `patch`,
`curl`, OpenSSL development files, and Python 3 (standard library only). It

1. downloads PostgreSQL 16.11, checks its SHA-256, applies the patch and
   builds it into `WORK/build` (an existing installation is never touched);
2. runs the safety tests in a temporary cluster;
3. recomputes every latency result of the paper from the measured requests
   and checks that the result files are byte-for-byte identical to the
   committed ones;
4. redraws the paper's three latency figures if matplotlib is installed.

With the raw TPC-H and IMDb data, the script also rebuilds the evaluation
databases, replays all 170 cases and compares each case's executable plan,
complete answer and audit log with the recorded run:

```sh
sh reproduce.sh /absolute/path/to/new/work-directory --replay /path/to/raw-data
```

See [workload/README.md](workload/README.md) for how to obtain the raw data
and what the replay checks. The databases take about 30 GB of disk space in
addition to the 15 GB of raw data; building them and replaying the cases took
about 20 minutes on the test machine (an Apple M1 Pro with 32 GB of memory).

### What is reproduced

| Paper result | How it is reproduced |
| --- | --- |
| Performance table (request latency rows) | `results/summary.csv`, recomputed from `results/samples.csv.gz` |
| Latency distribution, original queries, and path-search figures | `results/figures.py` |
| Latency figures quoted in the evaluation text | `results/paper-numbers.json` |
| Every AF request returns its reference answer | `tools/replay.py` compares all 170 answers |
| The audited searches pass only authorized values (222,122 audit inputs for AF) | `tools/replay.py` counts unauthorized audit inputs |
| AF's plan choices (for example, guard, keys-first, hash check) | `tools/replay.py` compares the executable plans |
| Admission rejects unsafe candidates and keeps order-sensitive ones | `tests/run_tests.sh` |

The repository does not re-measure latencies: timings depend on the
hardware, and a rerun gives different milliseconds. The planning-time and
prepared-statement measurements, the component ablations, the sweep over all
admitted search alternatives, and the diagnostic build that admits unsafe
orders were separate experiments and are not included.

## Building AF yourself

```sh
NATIVE_AF_BUILD_JOBS=8 sh src/build.sh /absolute/path/to/new/build
```

The installation ends up in `/absolute/path/to/new/build/install`. To build
from a local copy of the PostgreSQL source, set `NATIVE_AF_SOURCE_ARCHIVE` to
an unmodified `postgresql-16.11.tar.bz2`; its SHA-256 is checked as well.
AF is a source modification, not an extension, so it cannot be loaded into
an existing server.

## Using AF

AF is off by default (`native_af.mode = native`). Enable it per session:

```sql
SET native_af.mode = 'af';          -- 'native' (default), 'af', or 'index_priority'
```

| Setting | Meaning |
| --- | --- |
| `native_af.mode` | `native`: ordinary PostgreSQL; `af`: AdmissionFirst; `index_priority`: the fixed-rule baseline of the paper |
| `native_af.authorization_indexes` | Superuser setting. Lets AF and IndexPriority use partial indexes whose predicate is exactly a policy. On in all experiments |
| `native_af.max_authorized_keys` | Largest permitted-key array before AF falls back to the exact policy check (default 1,048,576) |
| `native_af.trace` | Reports admitted and rejected candidates as notices |

AF recognizes particular policy and query shapes, such as tenant equality,
group membership through an ACL table, and fixed-prefix `LIKE` searches.
Queries and policies it does not recognize are planned by PostgreSQL as
usual.

## Safety tests

```sh
sh tests/run_tests.sh /path/to/build/install /absolute/path/to/new/test-directory \
    --require-af-membership --require-sp
```

The tests create and stop their own cluster. For each mode they check the
returned rows, that a logging function only sees permitted rows, that
revocations, grants, membership changes, restrictive policies and `SET ROLE`
are honored by new and prepared statements, and that admission rejects or
keeps candidates as expected.

## Code overview

| File | Role |
| --- | --- |
| `native_af.c` | Configuration, policy recognition, the AF scan operators, costs, join planning with shared inputs, and the run-time join-input filter |
| `native_af_admission.c` | The admission check that runs before a candidate is costed |
| `native_af_sp.c` | Replacement of candidates for selections and projections |
| `native_af_guard.c` | The prefix guard for `LIKE` searches |
| `native_af_partial.c` | Partial indexes whose predicate is a policy |
| `native_af_keyed.c`, `native_af_binding.c` | Restricting and re-validating permitted-key sets at execution time |
| `native_af_os_cache.c` | Estimates which relation pages are in the operating-system cache |
| `postgres16.patch` | Hooks in the PostgreSQL planner, executor and `EXPLAIN` |

Each file starts with a description of what it does.

## License

The AdmissionFirst code is released under the MIT License (see
[LICENSE](LICENSE)). The patch contains PostgreSQL code, which remains under
the PostgreSQL License reproduced in [POSTGRESQL-COPYRIGHT](POSTGRESQL-COPYRIGHT).
TPC-H and the IMDb data used by the Join Order Benchmark are not included and
are subject to their own terms.
