# AdmissionFirst for PostgreSQL

AdmissionFirst (AF) adds checked row-level-security access alternatives to
PostgreSQL's planner and executor. It tests a candidate before comparing its
cost with ordinary PostgreSQL plans. The implementation includes policy-aware
access paths, join planning, and execution-time filtering for supported cases.

`code/` contains the PostgreSQL 16.11 patch and C implementation used in the
A044 experiments. This is a PostgreSQL source modification, not an extension
that can be loaded into an existing stock server. `results/` contains a compact
snapshot of those measurements.

## Build

Requirements are a C compiler, make, patch, curl, Python 3, OpenSSL development
files, and the usual PostgreSQL build tools. The script downloads PostgreSQL
16.11, checks its SHA-256, applies the patch, and installs into a new directory.
It does not change an existing PostgreSQL installation.

To build, run the focused correctness checks, and verify the saved A044
summary in one command, use `sh check.sh /absolute/path/to/new-work-directory`.
This command checks the recorded results; it does not rerun the full benchmark.
To build separately, use:

```sh
NATIVE_AF_BUILD_JOBS=2 sh code/build.sh /absolute/path/to/new-build
```

Alternatively, set `NATIVE_AF_SOURCE_ARCHIVE` to a local, unmodified
`postgresql-16.11.tar.bz2` instead of downloading it. Do not enable
`NATIVE_AF_GUARD_DIAGNOSTIC_UNSAFE` for a normal build.

The default `native_af.mode` is `native`. Set `native_af.mode` to `af` in the
query session to enable AF. The experimental configuration also enabled the
superuser-controlled `native_af.authorization_indexes` setting. The code
recognizes particular policy and query forms; unsupported forms retain ordinary
PostgreSQL behavior.

## Check the implementation

The following creates and stops an isolated local test cluster. The second
argument must be a new directory, outside any existing database cluster:

```sh
sh code/native_af/tests/run_doc.sh \
  /absolute/path/to/new-build/install /absolute/path/to/new-test-directory \
  --require-af-membership --require-sp
```

The test compares native, AF, and IndexPriority modes; checks full results and
non-leakproof observations; and exercises authorization changes and generic
prepared statements. This focused test is not the complete A044 benchmark.

## Check the experiment snapshot

```sh
python3 results/verify_snapshot.py
```

This recalculates the recorded request medians and four-method geometric means
from the included timing samples. See [results/README.md](results/README.md)
for the comparison scope, missing observations, and confidence intervals.

The complete A044 experiment also used separately prepared TPC-H, JOB/IMDb,
and synthetic application databases, two other PostgreSQL builds, and a
larger experiment harness. Those inputs and the full rerun harness are not yet
packaged here. The snapshot verification command does not rerun the benchmark.

## Source and notices

The AF source files and build script correspond to the measured A044 normal
build; `code/SOURCE.sha256` records their digests. PostgreSQL source is obtained
separately. The patch includes material from PostgreSQL, whose copyright and
license notice is reproduced in [POSTGRESQL-COPYRIGHT](POSTGRESQL-COPYRIGHT).
The license for the AF-specific code has not yet been selected.
