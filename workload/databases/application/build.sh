#!/bin/sh
# Build the "application" experiment database from scratch.
#
# The database holds the synthetic multi-tenant SaaS data set used by the
# daily application requests (support ticket lookup, dashboards, invoices,
# shared document search with an audit function, exports, ...).  The build
#   1. creates the login role and an empty database (UTF8, C collation),
#   2. installs the support objects and the application schema,
#   3. loads the deterministic data set in one transaction (with ANALYZE),
#   4. installs privileges and row-level security policies,
#   5. replays the recorded post-load history (audit rows, temporary state
#      changes and their restoration), which fixes the final physical row
#      placement,
#   6. restores the recorded planner statistics (ANALYZE samples rows at
#      random, so the statistics of large tables cannot be recomputed), and
#   7. verifies every table against the recorded fingerprints.
#
# Usage: build.sh --bindir DIR --host SOCKETDIR --port PORT [options]
# Run "build.sh --help" for all options.  Environment variables PGBIN,
# PGHOST, PGPORT, PGUSER and PYTHON provide defaults.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
PGBIN=${PGBIN:-}
HOST=${PGHOST:-}
PORT=${PGPORT:-5432}
SUPERUSER=${PGUSER:-postgres}
DBNAME=application
STATISTICS=recorded
NEW_CLUSTER=
SHARED_BUFFERS=256MB
PIN_OIDS=yes
AF_SETTING=auto
VERIFY=yes
ALLOW_AUTOVACUUM=no
PYTHON=${PYTHON:-python3}
ROLE=caprls_e10_rls_user

usage() {
	cat <<'EOF'
Usage: build.sh --bindir DIR --host SOCKETDIR --port PORT [options]

Connection (an existing server, superuser access over a Unix socket):
  --bindir DIR          PostgreSQL 16 bin directory (psql, and for
                        --new-cluster also initdb, pg_ctl, pg_resetwal)
  --host SOCKETDIR      Unix socket directory of the server
  --port PORT           server port (default 5432)
  --superuser NAME      superuser to connect as (default postgres)
  --dbname NAME         database to create (default application)

Private cluster:
  --new-cluster DATADIR run initdb in DATADIR (must not exist), start a
                        private server on --host/--port, build, and stop it
                        again; the cluster is left on disk, stopped
  --shared-buffers SIZE shared_buffers of the private cluster (default 256MB)
  --no-pin-oids         do not pin object and transaction identifiers of the
                        private cluster to those of the original cluster

Build choices:
  --statistics MODE     recorded (default): install the recorded planner
                        statistics; analyze: keep the statistics computed by
                        the ANALYZE of the load (random sample)
  --af-setting MODE     auto (default) | on | off: whether to store the
                        database default native_af.authorization_indexes=on
                        (auto: only if the server knows the parameter)
  --allow-autovacuum    build even though autovacuum is on (not recommended:
                        it changes the physical state and the statistics)
  --no-verify           skip the final fingerprint comparison
EOF
}

die() { echo "build.sh: $*" >&2; exit 1; }
say() { echo "build.sh: $*"; }

while [ $# -gt 0 ]; do
	case "$1" in
	--bindir) PGBIN=$2; shift 2 ;;
	--host) HOST=$2; shift 2 ;;
	--port) PORT=$2; shift 2 ;;
	--superuser) SUPERUSER=$2; shift 2 ;;
	--dbname) DBNAME=$2; shift 2 ;;
	--new-cluster) NEW_CLUSTER=$2; shift 2 ;;
	--shared-buffers) SHARED_BUFFERS=$2; shift 2 ;;
	--no-pin-oids) PIN_OIDS=no; shift ;;
	--statistics) STATISTICS=$2; shift 2 ;;
	--af-setting) AF_SETTING=$2; shift 2 ;;
	--allow-autovacuum) ALLOW_AUTOVACUUM=yes; shift ;;
	--no-verify) VERIFY=no; shift ;;
	-h|--help) usage; exit 0 ;;
	*) usage >&2; die "unknown argument: $1" ;;
	esac
done

[ -n "$PGBIN" ] || die "--bindir is required"
[ -x "$PGBIN/psql" ] || die "no psql in $PGBIN"
[ -n "$HOST" ] || die "--host (Unix socket directory) is required"
case "$STATISTICS" in recorded|analyze) ;; *) die "--statistics must be recorded or analyze" ;; esac
case "$AF_SETTING" in auto|on|off) ;; *) die "--af-setting must be auto, on or off" ;; esac
case "$DBNAME" in *[!a-z0-9_]*|'') die "--dbname must be a plain lower-case identifier" ;; esac
"$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 6))' || die "python3 >= 3.6 required"

PSQL="$PGBIN/psql"
started=$(date +%s)
admin() { "$PSQL" -X -q -v ON_ERROR_STOP=1 -h "$HOST" -p "$PORT" -U "$SUPERUSER" "$@"; }
scalar() { "$PSQL" -X -A -t -v ON_ERROR_STOP=1 -h "$HOST" -p "$PORT" -U "$SUPERUSER" "$@"; }

# Planner and session settings of the original load (they decide the join
# plans, and with them the physical order, of the INSERT ... SELECT steps).
PGOPTIONS="-c work_mem=16MB -c effective_cache_size=8GB -c random_page_cost=4 -c seq_page_cost=1"
PGOPTIONS="$PGOPTIONS -c cpu_tuple_cost=0.01 -c cpu_index_tuple_cost=0.005 -c cpu_operator_cost=0.0025"
PGOPTIONS="$PGOPTIONS -c jit=off -c max_parallel_workers_per_gather=0 -c TimeZone=UTC"
PGOPTIONS="$PGOPTIONS -c enable_hashjoin=on -c enable_mergejoin=on -c enable_nestloop=on -c enable_seqscan=on"
PGOPTIONS="$PGOPTIONS -c enable_indexscan=on -c enable_bitmapscan=on -c enable_sort=on -c enable_material=on"
# Storage-relevant defaults: inline compression method, statistics target,
# no synchronized sequential scans, plain heap tables in the default tablespace.
PGOPTIONS="$PGOPTIONS -c default_toast_compression=pglz -c default_statistics_target=100"
PGOPTIONS="$PGOPTIONS -c synchronize_seqscans=off -c default_table_access_method=heap -c default_tablespace="
export PGOPTIONS
unset PGDATABASE PGSERVICE PGSSLMODE 2>/dev/null || true

DATADIR=
server_start() {
	"$PGBIN/pg_ctl" -D "$DATADIR" -l "$DATADIR/build-server.log" -w -s start || die "server did not start (see $DATADIR/build-server.log)"
}
server_stop() {
	"$PGBIN/pg_ctl" -D "$DATADIR" -m fast -w -s stop || die "server did not stop"
}
# Set the cluster-wide counter for new object identifiers (stopped server).
next_oid() {
	server_stop
	"$PGBIN/pg_resetwal" -o "$1" "$DATADIR" >/dev/null || die "pg_resetwal failed"
	server_start
}
cleanup() {
	if [ -n "$DATADIR" ] && [ -f "$DATADIR/postmaster.pid" ]; then
		"$PGBIN/pg_ctl" -D "$DATADIR" -m fast -w -s stop || true
	fi
}

if [ -n "$NEW_CLUSTER" ]; then
	[ ! -e "$NEW_CLUSTER" ] || die "$NEW_CLUSTER already exists"
	for tool in initdb pg_ctl pg_resetwal pg_controldata; do
		[ -x "$PGBIN/$tool" ] || die "no $tool in $PGBIN"
	done
	mkdir -p "$HOST"
	say "initializing private cluster in $NEW_CLUSTER"
	"$PGBIN/initdb" -D "$NEW_CLUSTER" -U "$SUPERUSER" -E UTF8 --locale=C -A trust --no-instructions >/dev/null \
		|| die "initdb failed"
	DATADIR=$(cd "$NEW_CLUSTER" && pwd)
	trap cleanup EXIT INT TERM
	cat >>"$DATADIR/postgresql.conf" <<EOF

# Settings of the experiment profile (appended by build.sh).
listen_addresses = ''
port = $PORT
unix_socket_directories = '$HOST'
unix_socket_permissions = 0700
shared_buffers = $SHARED_BUFFERS
work_mem = 16MB
effective_cache_size = 8GB
max_wal_size = 4GB
random_page_cost = 4.0
seq_page_cost = 1.0
cpu_tuple_cost = 0.01
cpu_index_tuple_cost = 0.005
cpu_operator_cost = 0.0025
jit = off
max_parallel_workers = 0
max_parallel_workers_per_gather = 0
autovacuum = off
timezone = 'UTC'
log_timezone = 'UTC'
EOF
	printf 'local all all trust\n' >"$DATADIR/pg_hba.conf"
	server_start
fi

# ---------------------------------------------------------------- preflight
version=$(scalar -d postgres -c "SHOW server_version_num") || die "cannot connect to the server"
case "$version" in 16*) ;; *) die "PostgreSQL 16 required (server reports $version)" ;; esac
[ "$(scalar -d postgres -c "SELECT rolsuper FROM pg_roles WHERE rolname = current_user")" = t ] || die "$SUPERUSER is not a superuser"
if [ "$(scalar -d postgres -c "SHOW autovacuum")" != off ] && [ "$ALLOW_AUTOVACUUM" != yes ]; then
	die "autovacuum is on; set autovacuum = off (the experiments ran without it) or pass --allow-autovacuum"
fi
[ -z "$(scalar -d postgres -c "SELECT 1 FROM pg_database WHERE datname = '$DBNAME'")" ] || die "database $DBNAME already exists"
has_af=$(scalar -d postgres -c "SELECT count(*) FROM pg_settings WHERE name = 'native_af.authorization_indexes'")
if [ "$AF_SETTING" = on ] && [ "$has_af" != 1 ]; then
	die "the server does not know native_af.authorization_indexes (not the patched build?)"
fi
pin=no
if [ -n "$NEW_CLUSTER" ] && [ "$PIN_OIDS" = yes ]; then pin=yes; fi

# ------------------------------------------------- role and empty database
if [ "$pin" = yes ]; then next_oid 16699; fi
admin -d postgres <<EOF
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$ROLE') THEN
    CREATE ROLE $ROLE LOGIN NOSUPERUSER NOINHERIT NOBYPASSRLS;
  END IF;
END
\$\$;
EOF
if [ "$pin" = yes ]; then next_oid 17640; fi
say "creating database $DBNAME"
admin -d postgres -c "CREATE DATABASE $DBNAME TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER libc LC_COLLATE 'C' LC_CTYPE 'C'"

# ------------------------------------------------ schema, data, privileges
say "installing support objects and schema"
admin -d "$DBNAME" -f "$HERE/sql/01-support-objects.sql" >/dev/null
admin -d "$DBNAME" -f "$HERE/sql/02-application-schema.sql" >/dev/null
say "loading the data set (one transaction)"
"$PYTHON" -B "$HERE/lib/generate_data_sql.py" | admin -d "$DBNAME" >/dev/null
say "installing privileges and row-level security policies"
admin -d "$DBNAME" -f "$HERE/sql/04-access-policies.sql" >/dev/null
if [ "$AF_SETTING" = on ] || { [ "$AF_SETTING" = auto ] && [ "$has_af" = 1 ]; }; then
	admin -d postgres -c "ALTER DATABASE $DBNAME SET native_af.authorization_indexes TO on"
else
	say "note: database default native_af.authorization_indexes=on not stored"
fi
# The original runs created temporary tables from backend slot 6, which left
# the (empty) schemas pg_temp_6 and pg_toast_temp_6 behind.  They are owned
# by the bootstrap superuser, as PostgreSQL creates them.
if [ "$pin" = yes ]; then next_oid 17960; fi
owner=$(scalar -d "$DBNAME" -c "SELECT quote_ident(rolname) FROM pg_authid WHERE oid = 10")
admin -d "$DBNAME" -c "SET allow_system_table_mods = on" -c "CREATE SCHEMA pg_temp_6 AUTHORIZATION $owner" \
	-c "CREATE SCHEMA pg_toast_temp_6 AUTHORIZATION $owner"

# ------------------------------------------------------- recorded history
say "replaying the recorded post-load history"
"$PYTHON" -B "$HERE/lib/replay_history.py" --psql "$PSQL" --host "$HOST" --port "$PORT" \
	--user "$SUPERUSER" --dbname "$DBNAME"

if [ "$STATISTICS" = recorded ]; then
	say "installing the recorded planner statistics"
	admin -d "$DBNAME" -f "$HERE/data/planner-statistics.sql" >/dev/null
fi
admin -d "$DBNAME" -c "CHECKPOINT"

# -------------------------------------------------------------- verification
status=0
if [ "$VERIFY" = yes ]; then
	say "verifying table contents and physical row order"
	actual=$(scalar -d "$DBNAME" -f "$HERE/lib/table-checksums.sql" | grep -v '^SET$')
	expected=$(grep -v '^#' "$HERE/data/expected-checksums.tsv")
	if [ "$actual" = "$expected" ]; then
		say "verification passed: all tables match the recorded fingerprints"
	else
		echo "$actual" >"${TMPDIR:-/tmp}/application-build-checksums.$$"
		say "verification FAILED; differences (recorded vs. built):"
		echo "$expected" | diff - "${TMPDIR:-/tmp}/application-build-checksums.$$" || true
		rm -f "${TMPDIR:-/tmp}/application-build-checksums.$$"
		status=1
	fi
fi

if [ -n "$NEW_CLUSTER" ]; then
	if [ "$pin" = yes ]; then
		# Continue object and transaction identifiers where the original
		# cluster stopped, so later runs allocate the same identifiers.
		server_stop
		next_xid=$("$PGBIN/pg_controldata" "$DATADIR" | sed -n 's/^Latest checkpoint.s NextXID: *[0-9]*://p')
		xid_option=
		if [ -n "$next_xid" ] && [ "$next_xid" -le 1436 ]; then xid_option="-x 1436"; fi
		# shellcheck disable=SC2086
		"$PGBIN/pg_resetwal" -o 18077 $xid_option "$DATADIR" >/dev/null || die "pg_resetwal failed"
	else
		server_stop
	fi
	trap - EXIT INT TERM
	say "private cluster left stopped in $DATADIR"
fi
say "finished in $(( $(date +%s) - started )) s"
exit $status
