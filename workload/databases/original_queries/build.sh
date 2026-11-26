#!/bin/sh
# Build the "original queries" benchmark database from the raw TPC-H SF1 and IMDb files:
# full TPC-H SF1 and the full IMDb / Join Order Benchmark schema, tenant columns, the
# ACL/group tables used by the row-level-security policies, secondary indexes, the
# ordinary reader role and its grants, a database-wide VACUUM (FREEZE, ANALYZE), and the
# policy / reference-view state of the recorded runs.  The result has the same content
# and the same physical row order (ctid of every row) as the database used for the
# paper's measurements.
#
# Usage: ./build.sh [options]
#   --pg-bin DIR        PostgreSQL 16 bin directory (psql; initdb and pg_ctl for
#                       --init-pgdata)                       [PG_BIN; default: PATH]
#   --socket-dir DIR    Unix-socket directory of the server  [PGHOST; default /tmp]
#   --port N            server port                          [PGPORT; default 5432]
#   --raw-dir DIR       directory containing tpch/sf1/ and imdb/csv/  [RAW_DIR]
#   --tpch-dir DIR      the eight dbgen SF1 .tbl files  [TPCH_DIR; default RAW_DIR/tpch/sf1]
#   --imdb-dir DIR      the 21 IMDb .csv files          [IMDB_DIR; default RAW_DIR/imdb/csv]
#   --dbname NAME       database to create              [DBNAME; default original_queries]
#   --init-pgdata DIR   create a new cluster in DIR (initdb -U postgres, UTF8, C locale),
#                       run a temporary server on --socket-dir/--port for the build and
#                       stop it afterwards                   [INIT_PGDATA]
#   --shared-buffers S  shared_buffers of that temporary server  [SHARED_BUFFERS; 1GB]
#   --skip-input-check  do not verify sizes and SHA-256 of the raw inputs
#   --recorded-statistics
#                       after the build, replace the randomly sampled planner statistics
#                       (pg_statistic, reltuples) with those recorded on the database used
#                       for the paper, so that query plans and estimates match exactly
#                       (sql/recorded_statistics.sql)          [RECORDED_STATISTICS=yes]
#
# Without --init-pgdata the server must already run, be PostgreSQL 16, accept the
# superuser "postgres" over the socket without a password prompt (or via ~/.pgpass), and
# have autovacuum = off for the duration of the build.  The target database must not
# exist.  About 25 GB of free disk space is needed (the database itself is about 12 GB).

set -eu

here=$(cd "$(dirname "$0")" && pwd)

PG_BIN=${PG_BIN:-}
SOCKET_DIR=${PGHOST:-/tmp}
PORT=${PGPORT:-5432}
RAW_DIR=${RAW_DIR:-}
TPCH_DIR=${TPCH_DIR:-}
IMDB_DIR=${IMDB_DIR:-}
DBNAME=${DBNAME:-original_queries}
INIT_PGDATA=${INIT_PGDATA:-}
SHARED_BUFFERS=${SHARED_BUFFERS:-1GB}
RECORDED_STATISTICS=${RECORDED_STATISTICS:-no}
CHECK_INPUTS=yes

die() { echo "build.sh: $*" >&2; exit 1; }
need_arg() { [ $# -ge 2 ] || die "option $1 needs a value"; }

while [ $# -gt 0 ]; do
  case $1 in
    --pg-bin) need_arg "$@"; PG_BIN=$2; shift 2 ;;
    --socket-dir|--host) need_arg "$@"; SOCKET_DIR=$2; shift 2 ;;
    --port) need_arg "$@"; PORT=$2; shift 2 ;;
    --raw-dir) need_arg "$@"; RAW_DIR=$2; shift 2 ;;
    --tpch-dir) need_arg "$@"; TPCH_DIR=$2; shift 2 ;;
    --imdb-dir) need_arg "$@"; IMDB_DIR=$2; shift 2 ;;
    --dbname) need_arg "$@"; DBNAME=$2; shift 2 ;;
    --init-pgdata) need_arg "$@"; INIT_PGDATA=$2; shift 2 ;;
    --shared-buffers) need_arg "$@"; SHARED_BUFFERS=$2; shift 2 ;;
    --skip-input-check) CHECK_INPUTS=no; shift ;;
    --recorded-statistics) RECORDED_STATISTICS=yes; shift ;;
    -h|--help) sed -n '2,35p' "$0"; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

if [ -z "$TPCH_DIR" ]; then
  [ -n "$RAW_DIR" ] || die "give --raw-dir or --tpch-dir/--imdb-dir"
  TPCH_DIR=$RAW_DIR/tpch/sf1
fi
if [ -z "$IMDB_DIR" ]; then
  [ -n "$RAW_DIR" ] || die "give --raw-dir or --tpch-dir/--imdb-dir"
  IMDB_DIR=$RAW_DIR/imdb/csv
fi
[ -d "$TPCH_DIR" ] || die "TPC-H directory not found: $TPCH_DIR"
[ -d "$IMDB_DIR" ] || die "IMDb directory not found: $IMDB_DIR"
# psql changes into these directories in turn, so they must be absolute.
TPCH_DIR=$(cd "$TPCH_DIR" && pwd)
IMDB_DIR=$(cd "$IMDB_DIR" && pwd)

if [ -n "$PG_BIN" ]; then
  PSQL=$PG_BIN/psql; INITDB=$PG_BIN/initdb; PG_CTL=$PG_BIN/pg_ctl
else
  PSQL=psql; INITDB=initdb; PG_CTL=pg_ctl
fi

# Keep the client environment from changing session behaviour.
unset PGOPTIONS PGSERVICE PGDATABASE PGUSER PGHOST PGPORT PGHOSTADDR
PGCLIENTENCODING=UTF8
export PGCLIENTENCODING

run_psql() {
  "$PSQL" -X --no-password -v ON_ERROR_STOP=1 -h "$SOCKET_DIR" -p "$PORT" -U postgres "$@"
}

elapsed() { echo $(( $(date +%s) - $1 )); }
t_start=$(date +%s)

# 1. Raw inputs.
if [ "$CHECK_INPUTS" = yes ]; then
  echo "== checking raw inputs (sizes and SHA-256)"
  python3 "$here/verify_inputs.py" "$here/inputs.sha256" "$TPCH_DIR" "$IMDB_DIR" \
    || die "raw inputs do not match inputs.sha256"
fi

# 2. Optional private cluster.
server_started=no
cleanup() {
  if [ "$server_started" = yes ]; then
    echo "== stopping the temporary server"
    "$PG_CTL" -D "$INIT_PGDATA" -m fast -w stop || true
    server_started=no
  fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

if [ -n "$INIT_PGDATA" ]; then
  [ ! -e "$INIT_PGDATA" ] || die "--init-pgdata directory already exists: $INIT_PGDATA"
  echo "== creating cluster $INIT_PGDATA"
  "$INITDB" -D "$INIT_PGDATA" -U postgres -E UTF8 --locale=C \
    --auth-local=trust --auth-host=scram-sha-256
  mkdir -p "$SOCKET_DIR"
  cat >> "$INIT_PGDATA/postgresql.conf" <<EOF

# Appended by build.sh.  Only the socket, memory and autovacuum settings matter for the
# build; the load script pins its planner settings per session.
listen_addresses = ''
port = $PORT
unix_socket_directories = '$SOCKET_DIR'
unix_socket_permissions = 0700
shared_buffers = '$SHARED_BUFFERS'
max_wal_size = '4GB'
autovacuum = off
jit = off
max_parallel_workers = 0
max_parallel_workers_per_gather = 0
EOF
  "$PG_CTL" -D "$INIT_PGDATA" -l "$INIT_PGDATA/build-server.log" -w start
  server_started=yes
fi

# 3. Server checks.
echo "== checking the server"
version=$(run_psql -d postgres -Atc "SHOW server_version_num")
case $version in
  16*) ;;
  *) die "PostgreSQL 16 is required (server_version_num $version)" ;;
esac
is_super=$(run_psql -d postgres -Atc "SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
[ "$is_super" = t ] || die "role postgres must be a superuser"
autovac=$(run_psql -d postgres -Atc "SHOW autovacuum")
[ "$autovac" = off ] || die "set autovacuum = off on the server for the build (it changes load plans)"
exists=$(run_psql -d postgres -v dbname="$DBNAME" -At <<'EOF'
SELECT count(*) FROM pg_database WHERE datname = :'dbname';
EOF
)
[ "$exists" = 0 ] || die "database $DBNAME already exists; drop it or choose --dbname"

# 4. Database.
echo "== creating database $DBNAME"
run_psql -d postgres -v dbname="$DBNAME" <<'EOF'
CREATE DATABASE :"dbname" TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER libc LC_COLLATE 'C' LC_CTYPE 'C';
EOF

# 5. Load, indexes, ACL data, grants, VACUUM (FREEZE, ANALYZE).
echo "== loading (this takes several minutes)"
t_load=$(date +%s)
run_psql -d "$DBNAME" -v tpch_dir="$TPCH_DIR" -v imdb_dir="$IMDB_DIR" -f "$here/sql/load.sql"
echo "== load finished in $(elapsed "$t_load") s"

# 6. Database setting, policies and reference views.
echo "== installing the policy and reference-view state"
run_psql -d "$DBNAME" -v dbname="$DBNAME" -f "$here/sql/finalize.sql"

# 7. Optional: planner statistics recorded on the reference database.  ANALYZE samples
#    rows at random in PostgreSQL 16, so without this step statistics of tables with more
#    than 30000 rows differ slightly from the reference and some plans can differ.
if [ "$RECORDED_STATISTICS" = yes ]; then
  echo "== replacing sampled statistics with the recorded ones"
  run_psql -d "$DBNAME" -q -f "$here/sql/recorded_statistics.sql"
fi

# 8. Sanity checks.
echo "== checking the result"
run_psql -d "$DBNAME" -At -f "$here/sql/check.sql"

cleanup
echo "== done in $(elapsed "$t_start") s: database $DBNAME"
