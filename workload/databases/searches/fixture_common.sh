# Shared helpers for build_title_search.sh and build_path_search.sh.
# POSIX sh; sourced, not executed.
#
# Connection settings (command-line options override the environment):
#   -b DIR   PostgreSQL bin directory      (env PG_BIN; default: psql on PATH)
#   -H DIR   server socket directory/host  (env PGHOST; default: libpq default)
#   -p PORT  server port                   (env PGPORT; default: 5432)
#   -d NAME  target database name          (env FIXTURE_DB; per-script default)
#   -U NAME  superuser to connect as       (env FIXTURE_ADMIN; default: postgres)
#   -R       keep the statistics of this build's own ANALYZE instead of
#            loading the reference statistics      (env FIXTURE_REFERENCE_STATS=0)

fixture_usage() {
    cat >&2 <<EOF
usage: $0 [-b PG_BIN_DIR] [-H SOCKET_DIR] [-p PORT] [-d DATABASE] [-U SUPERUSER] [-R]

Builds the $FIXTURE_LABEL fixture in a NEW database (default name
'$FIXTURE_DEFAULT_DB') on a running PostgreSQL 16 server.  The database must
not exist yet.  Connect as the bootstrap superuser named "postgres" so that
object ownership matches the reference database.

The generated data is deterministic.  ANALYZE samples rows at random, so by
default the build finally replaces the planner statistics of the new tables
with those of the reference database (stats/*.sql).  -R skips that step and
keeps the statistics of this build's own ANALYZE.
Environment equivalents: PG_BIN, PGHOST, PGPORT, FIXTURE_DB, FIXTURE_ADMIN,
FIXTURE_REFERENCE_STATS=0.
EOF
    exit 2
}

fixture_die() {
    echo "$0: error: $*" >&2
    exit 1
}

fixture_parse_args() {
    PG_BIN=${PG_BIN:-}
    FIXTURE_HOST=${PGHOST:-}
    FIXTURE_PORT=${PGPORT:-5432}
    FIXTURE_DB=${FIXTURE_DB:-$FIXTURE_DEFAULT_DB}
    FIXTURE_ADMIN=${FIXTURE_ADMIN:-postgres}
    FIXTURE_REFERENCE_STATS=${FIXTURE_REFERENCE_STATS:-1}
    while getopts "b:H:p:d:U:Rh" opt; do
        case $opt in
            b) PG_BIN=$OPTARG ;;
            H) FIXTURE_HOST=$OPTARG ;;
            p) FIXTURE_PORT=$OPTARG ;;
            d) FIXTURE_DB=$OPTARG ;;
            U) FIXTURE_ADMIN=$OPTARG ;;
            R) FIXTURE_REFERENCE_STATS=0 ;;
            *) fixture_usage ;;
        esac
    done
    shift $((OPTIND - 1))
    [ $# -eq 0 ] || fixture_usage
    if [ -n "$PG_BIN" ]; then
        PSQL=$PG_BIN/psql
    else
        PSQL=$(command -v psql) || fixture_die "psql not found; pass -b PG_BIN_DIR"
    fi
    [ -x "$PSQL" ] || fixture_die "not executable: $PSQL"
    case $FIXTURE_DB in
        ''|*[!a-z0-9_]*|[0-9]*) fixture_die "database name must match [a-z_][a-z0-9_]*: '$FIXTURE_DB'" ;;
    esac
    # Do not let a user's psqlrc or session defaults leak into the build.
    # Synchronized sequential scans could start a scan in the middle of a
    # table and so change the order in which INSERT ... SELECT writes rows;
    # parallel workers are disabled to keep every step serial.
    PGOPTIONS="-c synchronize_seqscans=off -c max_parallel_workers_per_gather=0 -c max_parallel_maintenance_workers=0"
    PGCLIENTENCODING=UTF8
    export PGOPTIONS PGCLIENTENCODING
    unset PGTZ PGDATESTYLE
}

# fixture_psql DB [psql args...]
fixture_psql() {
    _db=$1
    shift
    if [ -n "$FIXTURE_HOST" ]; then
        "$PSQL" -X -q -v ON_ERROR_STOP=1 -h "$FIXTURE_HOST" -p "$FIXTURE_PORT" \
            -U "$FIXTURE_ADMIN" -d "$_db" "$@"
    else
        "$PSQL" -X -q -v ON_ERROR_STOP=1 -p "$FIXTURE_PORT" \
            -U "$FIXTURE_ADMIN" -d "$_db" "$@"
    fi
}

fixture_query() {
    fixture_psql "$1" -A -t -c "$2"
}

# Checks the server and creates the empty target database.
fixture_create_database() {
    _ver=$(fixture_query postgres "SHOW server_version_num") ||
        fixture_die "cannot connect to the server"
    case $_ver in
        16*) ;;
        *) fixture_die "PostgreSQL 16 is required (server_version_num=$_ver)" ;;
    esac
    [ "$_ver" = 160011 ] ||
        echo "$0: warning: reference databases were built with PostgreSQL 16.11 (this server: $_ver)" >&2
    _super=$(fixture_query postgres "SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
    [ "$_super" = t ] || fixture_die "connect as a superuser"
    if [ "$FIXTURE_ADMIN" != postgres ] && [ "${FIXTURE_ALLOW_OTHER_ADMIN:-0}" != 1 ]; then
        fixture_die "connect as the superuser 'postgres' (objects are owned by it in the reference; set FIXTURE_ALLOW_OTHER_ADMIN=1 to override)"
    fi
    _exists=$(fixture_query postgres "SELECT count(*) FROM pg_database WHERE datname = '$FIXTURE_DB'")
    [ "$_exists" = 0 ] || fixture_die "database '$FIXTURE_DB' already exists; the fixture must be loaded into a new database"
    # The reference databases were built and used with autovacuum off.  An
    # autovacuum run would freeze and mark pages all-visible (the title
    # fixture was never vacuumed) and an autoanalyze would overwrite the
    # reference statistics.  Row content and placement would not change.
    _av=$(fixture_query postgres "SHOW autovacuum")
    if [ "$_av" != off ]; then
        [ "${FIXTURE_ALLOW_AUTOVACUUM:-0}" = 1 ] ||
            fixture_die "autovacuum is on; restart the server with autovacuum=off (or set FIXTURE_ALLOW_AUTOVACUUM=1 to accept visibility-map and statistics drift)"
        echo "$0: warning: autovacuum is on; visibility-map state and statistics may drift from the reference" >&2
    fi
    fixture_psql postgres -c "CREATE DATABASE \"$FIXTURE_DB\" TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER libc LC_COLLATE 'C' LC_CTYPE 'C'"
}

# fixture_load_statistics FILE: replace the planner statistics of the new
# tables with the reference ones (unless -R was given).
fixture_load_statistics() {
    if [ "$FIXTURE_REFERENCE_STATS" = 1 ]; then
        echo "loading reference planner statistics"
        fixture_psql "$FIXTURE_DB" -f "$1"
    else
        echo "keeping this build's own ANALYZE statistics (-R)"
    fi
}

fixture_now() {
    date +%s
}
