#!/bin/sh
# Build the benchmark databases from the raw TPC-H and IMDb files.
#
#   tpch_job   TPC-H SF1 subset + full JOB/IMDb subset + group ACL tables
#   tpch_sf10  TPC-H SF10 subset + small synthetic JOB tables + group ACL tables
#
# The result has the same table contents, the same physical row order
# (every row at the same ctid), the same indexes, roles, grants, policies and
# database settings as the databases the measurements ran on.  At the end the
# recorded planner statistics of those databases are loaded (pg_statistic and
# pg_class row counts), because PostgreSQL 16's ANALYZE samples at random and
# the benchmark compares query plans; --sampled-statistics keeps the build's
# own ANALYZE results instead.
#
# Usage:
#   sh build.sh --dataset tpch_job|tpch_sf10|all --raw-dir DIR \
#               [--bindir DIR] [--host SOCKETDIR] [--port N] [--user postgres] \
#               [--dbname NAME] [--copy-mode client|server] [--no-verify]
#               [--sampled-statistics]
#
# Every option can also be given as an environment variable:
#   PG_BINDIR, PGHOST, PGPORT, PGUSER, RAW_DIR, DATASET, DBNAME, COPY_MODE,
#   TPCH_SF1_DIR, TPCH_SF10_DIR, IMDB_DIR (override RAW_DIR/<default subdir>),
#   PYTHON (default python3), VERIFY (1/0), RECORDED_STATISTICS (1/0),
#   ALLOW_AUTOVACUUM (0/1), ALLOW_OTHER_SUPERUSER (0/1).
#
# Raw data layout under --raw-dir (see inputs.json for sizes and SHA-256):
#   tpch/sf1/{customer,orders,lineitem,nation}.tbl     TPC-H dbgen 3.0.1, -s 1
#   tpch/sf10/{customer,orders,lineitem,nation}.tbl    TPC-H dbgen 3.0.1, -s 10
#   imdb/csv/{title,movie_companies,cast_info,kind_type,company_type}.csv
#
# Server requirements: PostgreSQL 16 (the measurements used 16.11), a fresh
# database name, connection as the bootstrap superuser "postgres" (owner names
# appear in the ACLs), and autovacuum = off (the measured databases were never
# vacuumed; autovacuum would change visibility maps and statistics).  Keep
# autovacuum off while running the benchmark, too.  Nothing else in the
# server configuration affects the result: the build pins the session
# settings that do (statistics target, synchronized scans, and work_mem for
# the one statement whose row order depends on a sort).
# Disk: the finished databases take 3.7 GB (tpch_job) and 7.0 GB (tpch_sf10);
# the load needs roughly as much again for staging tables and WAL.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
PYTHON=${PYTHON:-python3}
PG_BINDIR=${PG_BINDIR:-}
PGHOST=${PGHOST:-/tmp}
PGPORT=${PGPORT:-5432}
PGUSER=${PGUSER:-postgres}
RAW_DIR=${RAW_DIR:-}
DATASET=${DATASET:-}
DBNAME=${DBNAME:-}
COPY_MODE=${COPY_MODE:-client}
VERIFY=${VERIFY:-1}
RECORDED_STATISTICS=${RECORDED_STATISTICS:-1}
ALLOW_AUTOVACUUM=${ALLOW_AUTOVACUUM:-0}
ALLOW_OTHER_SUPERUSER=${ALLOW_OTHER_SUPERUSER:-0}
TPCH_SF1_DIR=${TPCH_SF1_DIR:-}
TPCH_SF10_DIR=${TPCH_SF10_DIR:-}
IMDB_DIR=${IMDB_DIR:-}
WORK_DIR=${WORK_DIR:-}

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit "${1:-2}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dataset) DATASET=$2; shift 2 ;;
    --raw-dir) RAW_DIR=$2; shift 2 ;;
    --bindir) PG_BINDIR=$2; shift 2 ;;
    --host) PGHOST=$2; shift 2 ;;
    --port) PGPORT=$2; shift 2 ;;
    --user) PGUSER=$2; shift 2 ;;
    --dbname) DBNAME=$2; shift 2 ;;
    --copy-mode) COPY_MODE=$2; shift 2 ;;
    --work-dir) WORK_DIR=$2; shift 2 ;;
    --no-verify) VERIFY=0; shift ;;
    --sampled-statistics) RECORDED_STATISTICS=0; shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

die() { echo "build.sh: $*" >&2; exit 1; }
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

case "$DATASET" in
  tpch_job|tpch_sf10) ;;
  all)
    [ -z "$DBNAME" ] || die "--dbname cannot be combined with --dataset all"
    for d in tpch_job tpch_sf10; do
      DATASET=$d VERIFY=$VERIFY RECORDED_STATISTICS=$RECORDED_STATISTICS \
        sh "$0" --raw-dir "$RAW_DIR" --host "$PGHOST" --port "$PGPORT" \
        --user "$PGUSER" --copy-mode "$COPY_MODE" ${PG_BINDIR:+--bindir "$PG_BINDIR"} \
        ${WORK_DIR:+--work-dir "$WORK_DIR"} --dataset "$d" || exit 1
    done
    exit 0 ;;
  *) die "--dataset must be tpch_job, tpch_sf10 or all" ;;
esac
case "$COPY_MODE" in client|server) ;; *) die "--copy-mode must be client or server" ;; esac
DBNAME=${DBNAME:-$DATASET}
printf '%s' "$DBNAME" | grep -Eq '^[a-z_][a-z0-9_]{0,62}$' \
  || die "database name must match [a-z_][a-z0-9_]*"

if [ -n "$PG_BINDIR" ]; then PSQL=$PG_BINDIR/psql; else PSQL=$(command -v psql) || die "psql not found"; fi
[ -x "$PSQL" ] || die "psql not executable: $PSQL"
command -v "$PYTHON" >/dev/null 2>&1 || die "python3 not found (set PYTHON)"

# Raw input directories.
if [ "$DATASET" = tpch_job ]; then
  TPCH_DIR=${TPCH_SF1_DIR:-${RAW_DIR:+$RAW_DIR/tpch/sf1}}
  IMDB=${IMDB_DIR:-${RAW_DIR:+$RAW_DIR/imdb/csv}}
  [ -n "$IMDB" ] || die "give --raw-dir or IMDB_DIR"
  SCALE=mixed
  RECEIPT=33a9b238baa528c6ffbeb9e9ec2799021c4f43c5f36c772cb3e817a168384560
  JOB_SQL=$here/sql/job_imdb_load.sql
else
  TPCH_DIR=${TPCH_SF10_DIR:-${RAW_DIR:+$RAW_DIR/tpch/sf10}}
  IMDB=
  SCALE=sf10
  RECEIPT=e06b8cda2e1735667b4120b7bb204ebac204883a46d508d07f616c551a757785
  JOB_SQL=$here/sql/job_synthetic_load.sql
fi
[ -n "$TPCH_DIR" ] || die "give --raw-dir or TPCH_SF1_DIR / TPCH_SF10_DIR"
abspath() { (cd "$1" && pwd) || die "directory not found: $1"; }
TPCH_DIR=$(abspath "$TPCH_DIR")
[ -z "$IMDB" ] || IMDB=$(abspath "$IMDB")

if [ -z "$WORK_DIR" ]; then WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/benchmark-build.XXXXXX"); fi
mkdir -p "$WORK_DIR"
started=$(date +%s)

# 1. Raw inputs.
log "verifying raw input files for $DATASET"
"$PYTHON" -B "$here/tools/verify_inputs.py" --manifest "$here/inputs.json" \
  --database "$DATASET" --tpch-dir "$TPCH_DIR" ${IMDB:+--imdb-dir "$IMDB"}

# Session settings for every connection of the build.  Statistics target and
# synchronized scans affect the result; the others make the load independent
# of server defaults.
unset PGDATABASE PGOPTIONS PGSERVICE PGCLIENTENCODING 2>/dev/null || true
PGCLIENTENCODING=UTF8
PGOPTIONS="-c synchronize_seqscans=off -c default_statistics_target=100 \
-c default_table_access_method=heap -c default_tablespace= \
-c default_toast_compression=pglz -c standard_conforming_strings=on \
-c DateStyle=ISO,MDY -c row_security=on"
export PGHOST PGPORT PGUSER PGCLIENTENCODING PGOPTIONS
run_psql() { db=$1; shift; "$PSQL" -X --no-password -v ON_ERROR_STOP=1 -q -d "$db" "$@"; }
query() { run_psql postgres -At -c "$1"; }

# 2. Server checks.
version=$(query "SHOW server_version_num")
case "$version" in 16*) ;; *) die "PostgreSQL 16 required (server_version_num $version)" ;; esac
[ "$(query "SELECT rolsuper FROM pg_roles WHERE rolname = current_user")" = t ] \
  || die "connect as a superuser"
if [ "$(query "SELECT current_user")" != postgres ] && [ "$ALLOW_OTHER_SUPERUSER" != 1 ]; then
  die "connect as the superuser named postgres (owner names are part of the ACLs); set ALLOW_OTHER_SUPERUSER=1 to override"
fi
if [ "$(query "SHOW autovacuum")" != off ] && [ "$ALLOW_AUTOVACUUM" != 1 ]; then
  die "set autovacuum = off on the server (set ALLOW_AUTOVACUUM=1 to override)"
fi
[ -z "$(query "SELECT 1 FROM pg_database WHERE datname = '$DBNAME'")" ] \
  || die "database $DBNAME already exists"

# 3. Login role (cluster-wide) and database.
log "role and database $DBNAME"
run_psql postgres -f "$here/sql/role.sql"
run_psql postgres -c "CREATE DATABASE \"$DBNAME\" TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER libc LC_COLLATE 'C' LC_CTYPE 'C'"

# 4. Data load: one psql session, one statement per transaction.
"$PYTHON" -B "$here/tools/render_sql.py" --mode "$COPY_MODE" --tpch-dir "$TPCH_DIR" \
  ${IMDB:+--imdb-dir "$IMDB"} "$here/sql/tpch_load.sql" "$JOB_SQL" \
  "$here/sql/acl_load.sql" "$here/sql/grants_rls.sql" > "$WORK_DIR/$DBNAME.load.sql"
log "loading (copy mode $COPY_MODE): $WORK_DIR/$DBNAME.load.sql"
run_psql "$DBNAME" -f "$WORK_DIR/$DBNAME.load.sql"

# 5. Dataset marker, authorization indexes (with their ANALYZE), the
#    recorded permission-change cycle (tpch_job only) and the policies the
#    measured databases were archived with.
log "marker row, authorization indexes, archived state"
run_psql "$DBNAME" -v scale="$SCALE" -v receipt="$RECEIPT" -f "$here/sql/bench_marker.sql"
run_psql "$DBNAME" -v dbname="$DBNAME" -f "$here/sql/authorization_indexes.sql"
if [ "$DATASET" = tpch_job ]; then
  run_psql "$DBNAME" -f "$here/sql/membership_cycle.sql"
fi
run_psql "$DBNAME" -f "$here/sql/final_policies_$DATASET.sql"
# No VACUUM: the measured databases were only ANALYZEd (all-visible maps
# empty, dead rows from the permission-change cycle still present).
if [ "$RECORDED_STATISTICS" = 1 ]; then
  log "loading the recorded planner statistics"
  run_psql "$DBNAME" -f "$here/sql/recorded_statistics_$DATASET.sql"
  compare_opts=
else
  compare_opts=--sampled-statistics
fi
run_psql postgres -c "CHECKPOINT"
log "build finished in $(( $(date +%s) - started )) s"

# 6. Verification against the published fingerprint.
if [ "$VERIFY" = 1 ]; then
  log "fingerprinting $DBNAME"
  "$PYTHON" -B "$here/tools/fingerprint.py" --psql "$PSQL" --host "$PGHOST" --port "$PGPORT" \
    --user "$PGUSER" --dbname "$DBNAME" --output "$WORK_DIR/$DBNAME.fingerprint.json"
  "$PYTHON" -B "$here/tools/compare_fingerprint.py" $compare_opts \
    "$here/expected/$DATASET.json" "$WORK_DIR/$DBNAME.fingerprint.json"
  log "verified in $(( $(date +%s) - started )) s total"
fi
