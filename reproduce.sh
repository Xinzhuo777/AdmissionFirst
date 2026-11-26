#!/bin/sh
# Reproduce the AdmissionFirst artifact with one command.
#
#   sh reproduce.sh WORK_DIRECTORY [--replay RAW_DATA_DIRECTORY]
#
# WORK_DIRECTORY must not exist yet; everything is created inside it:
#   build/       PostgreSQL 16.11 with AdmissionFirst            (src/build.sh)
#   tests/       safety tests in a temporary cluster             (tests/run_tests.sh)
#   figures/     the paper's latency figures, if matplotlib is installed
#   cluster/     with --replay: the six evaluation databases     (workload/databases/build_all.sh)
#   replay/      with --replay: plan, answer and audit check of all 170 cases
#   SUMMARY.txt  the outcome of every step
#
# Without --replay the script needs about ten minutes and no input data.
# --replay needs the raw TPC-H and IMDb files (see workload/README.md) and
# about 30 GB of free disk space; it adds about 20 minutes on the test machine.
#
# Environment:
#   AF_INSTALL                reuse this AdmissionFirst installation instead of building one
#   NATIVE_AF_SOURCE_ARCHIVE  local postgresql-16.11.tar.bz2 for src/build.sh
#   NATIVE_AF_BUILD_JOBS      parallel make jobs for src/build.sh (default 6)
#   AF_PORT                   port of the replay cluster (default 54410)
set -eu

usage() {
    echo "usage: sh reproduce.sh WORK_DIRECTORY [--replay RAW_DATA_DIRECTORY]" >&2
    exit 2
}
[ "$#" -eq 1 ] || [ "$#" -eq 3 ] || usage
raw_data=
if [ "$#" -eq 3 ]; then
    [ "$2" = --replay ] || usage
    raw_data=$(CDPATH='' cd -- "$3" && pwd)
fi
repository=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
mkdir "$1"
work=$(CDPATH='' cd -- "$1" && pwd)
summary="$work/SUMMARY.txt"
export PYTHONDONTWRITEBYTECODE=1

step() {
    printf '\n=== %s\n' "$*"
}
record() {
    printf '%s\n' "$*" | tee -a "$summary"
}

# 1. Build ---------------------------------------------------------------------
if [ -n "${AF_INSTALL:-}" ]; then
    install=$(CDPATH='' cd -- "$AF_INSTALL" && pwd)
    step "1/5 Using the existing installation $install"
else
    step "1/5 Building PostgreSQL 16.11 with AdmissionFirst (log files in $work/build)"
    sh "$repository/src/build.sh" "$work/build"
    install="$work/build/install"
fi
"$install/bin/postgres" --version > /dev/null
record "build: ok ($("$install/bin/postgres" --version))"

# 2. Safety tests ----------------------------------------------------------------
step "2/5 Running the safety tests"
sh "$repository/tests/run_tests.sh" "$install" "$work/tests" --require-af-membership --require-sp
record "safety tests: passed (native, af and index_priority modes)"

# 3. Results ---------------------------------------------------------------------
step "3/5 Recomputing all reported latency results from the 30,600 measured requests"
python3 "$repository/results/analyze.py" --check
record "latency results: recomputed files identical to results/ (conditions, comparisons, summary, paper numbers)"

# 4. Figures ---------------------------------------------------------------------
step "4/5 Drawing the latency figures"
if python3 -c "import matplotlib, numpy" 2>/dev/null; then
    python3 "$repository/results/figures.py" --output "$work/figures"
    record "figures: written to $work/figures"
else
    record "figures: skipped (matplotlib and numpy are not installed)"
fi

# 5. Replay ----------------------------------------------------------------------
if [ -z "$raw_data" ]; then
    step "5/5 Replay skipped (run with --replay RAW_DATA_DIRECTORY to rebuild the databases and replay all cases)"
    record "replay: skipped"
else
    step "5/5 Building the six evaluation databases and replaying the 170 cases"
    port=${AF_PORT:-54410}
    socket=$(mktemp -d /tmp/af-replay.XXXXXX)
    sh "$repository/workload/databases/build_all.sh" --install "$install" \
        --cluster "$work/cluster" --raw-data "$raw_data" --port "$port" --socket-dir "$socket"
    record "databases: built and verified against the original checksums"
    "$install/bin/pg_ctl" -D "$work/cluster" -l "$work/cluster.log" -w -t 600 start > /dev/null
    status=0
    python3 "$repository/tools/replay.py" --install "$install" --socket-dir "$socket" \
        --port "$port" --admin postgres --output "$work/replay" || status=$?
    "$install/bin/pg_ctl" -D "$work/cluster" -m fast -w stop > /dev/null
    rmdir "$socket" 2>/dev/null || true
    record "replay: $(python3 -c "import json,sys; s=json.load(open(sys.argv[1])); print(\
'{plans_matching}/{cases} plans, {answers_matching}/{cases} answers and {audits_ok}/{audited_cases} audits match; '\
'{audit_inputs} audit inputs, {unauthorized_audit_inputs} unauthorized'.format(**s))" "$work/replay/summary.json")"
    [ "$status" -eq 0 ] || { record "replay: FAILED (see $work/replay/replay.csv)"; exit 1; }
fi

step "Done. Summary ($summary):"
cat "$summary"
