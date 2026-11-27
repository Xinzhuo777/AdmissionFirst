#!/bin/sh
# Reproduce the AdmissionFirst artifact with one command.
#
#   sh reproduce.sh WORK_DIRECTORY [--replay RAW_DATA_DIRECTORY [--measure]]
#
# WORK_DIRECTORY must not exist yet; everything is created inside it:
#   build/        PostgreSQL 16.11 with AdmissionFirst            (src/build.sh)
#   tests/        safety tests in a temporary cluster             (tests/run_tests.sh)
#   tables/       the paper's latency table and all reported latency numbers
#   figures/      the paper's latency figures, if matplotlib is installed
#   cluster/      with --replay: the six evaluation databases     (workload/databases/build_all.sh)
#   replay/       with --replay: plan, answer and audit check of all 170 cases,
#                 and every AF plan (replay/plans/)
#   build-stock/  with --measure: unmodified PostgreSQL 16.11 for the SQL baselines
#   measurement/  with --measure: a new measurement of all five methods on the
#                 170 cases (samples.csv.gz), its tables/ and figures/, and
#                 comparison.md, which sets the new numbers beside the paper's
#   SUMMARY.txt   the outcome of every step
#
# Without --replay the script needs about ten minutes and no input data.
# --replay needs the raw TPC-H and IMDb files (see workload/README.md) and
# about 30 GB of free disk space; it adds about 20 minutes on the test machine.
# --measure adds a new latency measurement: 30,600 requests, about 9 hours.
#
# Environment:
#   AF_INSTALL                reuse this AdmissionFirst installation instead of building one
#   NATIVE_AF_SOURCE_ARCHIVE  local postgresql-16.11.tar.bz2 for src/build.sh
#   NATIVE_AF_BUILD_JOBS      parallel make jobs for src/build.sh (default 6)
#   AF_PORT                   port of the evaluation cluster (default 54410)
set -eu

usage() {
    echo "usage: sh reproduce.sh WORK_DIRECTORY [--replay RAW_DATA_DIRECTORY [--measure]]" >&2
    exit 2
}
[ "$#" -ge 1 ] || usage
work_arg=$1
shift
raw_data= measure=false
while [ "$#" -gt 0 ]; do
    case $1 in
        --replay) [ "$#" -ge 2 ] || usage; raw_data=$(CDPATH='' cd -- "$2" && pwd); shift 2 ;;
        --measure) measure=true; shift ;;
        *) usage ;;
    esac
done
if "$measure" && [ -z "$raw_data" ]; then
    echo "reproduce.sh: --measure needs the databases, so it requires --replay RAW_DATA_DIRECTORY" >&2
    exit 2
fi
repository=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
mkdir "$work_arg"
work=$(CDPATH='' cd -- "$work_arg" && pwd)
summary="$work/SUMMARY.txt"
steps=5
"$measure" && steps=6
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
    step "1/$steps Using the existing installation $install"
else
    step "1/$steps Building PostgreSQL 16.11 with AdmissionFirst (log files in $work/build)"
    sh "$repository/src/build.sh" "$work/build"
    install="$work/build/install"
fi
"$install/bin/postgres" --version > /dev/null
record "build: ok ($("$install/bin/postgres" --version))"
if "$measure"; then
    step "1/$steps Building unmodified PostgreSQL 16.11 for the SQL baselines (log files in $work/build-stock)"
    NATIVE_AF_STOCK=1 sh "$repository/src/build.sh" "$work/build-stock"
    record "baseline build: ok ($("$work/build-stock/install/bin/postgres" --version), unmodified)"
fi

# 2. Safety tests ----------------------------------------------------------------
step "2/$steps Running the safety tests"
sh "$repository/tests/run_tests.sh" "$install" "$work/tests" --require-af-membership --require-sp
record "safety tests: passed (native, af and index_priority modes)"

# 3. Results ---------------------------------------------------------------------
step "3/$steps Recomputing all reported latency results from the 30,600 measured requests"
python3 "$repository/results/analyze.py" --check
python3 "$repository/results/analyze.py" --output "$work/tables" > /dev/null
record "latency results: recomputed files identical to results/; table in $work/tables/performance-table.md"

# 4. Figures ---------------------------------------------------------------------
step "4/$steps Drawing the latency figures"
figures=false
if python3 -c "import matplotlib, numpy" 2>/dev/null; then
    figures=true
    python3 "$repository/results/figures.py" --output "$work/figures"
    record "figures: written to $work/figures"
else
    record "figures: skipped (matplotlib and numpy are not installed)"
fi

# 5. Replay ----------------------------------------------------------------------
if [ -z "$raw_data" ]; then
    step "5/$steps Replay skipped (run with --replay RAW_DATA_DIRECTORY to rebuild the databases and replay all cases)"
    record "replay: skipped"
else
    step "5/$steps Building the six evaluation databases and replaying the 170 cases"
    port=${AF_PORT:-54410}
    socket=$(mktemp -d /tmp/af-replay.XXXXXX)
    sh "$repository/workload/databases/build_all.sh" --install "$install" \
        --cluster "$work/cluster" --raw-data "$raw_data" --port "$port" --socket-dir "$socket"
    record "databases: built and verified against the original checksums"
    "$install/bin/pg_ctl" -D "$work/cluster" -l "$work/cluster.log" -w -t 600 start > /dev/null
    status=0
    python3 "$repository/tools/replay.py" --install "$install" --socket-dir "$socket" \
        --port "$port" --admin postgres --output "$work/replay" --save-plans || status=$?
    "$install/bin/pg_ctl" -D "$work/cluster" -m fast -w stop > /dev/null
    record "replay: $(python3 -c "import json,sys; s=json.load(open(sys.argv[1])); print(\
'{plans_matching}/{cases} plans, {answers_matching}/{cases} answers and {audits_ok}/{audited_cases} audits match; '\
'{audit_inputs} audit inputs, {unauthorized_audit_inputs} unauthorized'.format(**s))" "$work/replay/summary.json")"
    [ "$status" -eq 0 ] || { record "replay: FAILED (see $work/replay/replay.csv)"; exit 1; }

    # 6. New measurement -------------------------------------------------------------
    if "$measure"; then
        step "6/$steps Measuring all five methods on the 170 cases (30,600 requests; progress below)"
        out="$work/measurement"
        status=0
        python3 "$repository/tools/measure.py" --af-install "$install" \
            --stock-install "$work/build-stock/install" --cluster "$work/cluster" \
            --socket-dir "$socket" --port "$port" --output "$out" || status=$?
        python3 "$repository/results/analyze.py" --samples "$out/samples.csv.gz" --output "$out/tables"
        python3 "$repository/results/compare.py" "$out/tables" --output "$out/comparison.md" > /dev/null
        if "$figures"; then
            python3 "$repository/results/figures.py" --conditions "$out/tables/conditions.csv" --output "$out/figures"
        fi
        record "measurement: $(python3 -c "import json,sys; s=json.load(open(sys.argv[1])); print(\
'{requests} requests, statuses {statuses}; AF plans {af_plans_matching}/{af_plans_recorded} as recorded'.format(**s))" \
            "$out/summary.json")"
        record "measurement: table in $out/tables/performance-table.md, comparison with the paper in $out/comparison.md"
        [ "$status" -eq 0 ] || { record "measurement: FAILED (see $out/summary.json)"; exit 1; }
    fi
    rmdir "$socket" 2>/dev/null || true
fi

step "Done. Summary ($summary):"
cat "$summary"
