#!/bin/sh
# Create a new PostgreSQL cluster and build the six evaluation databases in it.
#
#   sh workload/databases/build_all.sh --install INSTALL --cluster NEW_CLUSTER_DIR \
#       --raw-data RAW_DATA_DIR [--port PORT] [--socket-dir DIR]
#
# INSTALL is a PostgreSQL 16.11 installation built with src/build.sh.
# RAW_DATA_DIR holds tpch/sf1, tpch/sf10 and imdb/csv (see workload/README.md).
# The cluster is initialized with the superuser "postgres", UTF8 and the C
# locale, and configured with workload/postgresql.conf. It listens only on a
# Unix socket (default: a new directory under /tmp; the path is printed) and
# is stopped when the script ends. Every database script checks its inputs
# and verifies the finished database against checksums of the original.
#
#   tpch_job, tpch_sf10   tpch_job/build.sh          (TPC-H SF1/SF10 and JOB subsets)
#   original_queries      original_queries/build.sh  (full TPC-H SF1 and JOB schemas)
#   title_search          searches/build_title_search.sh
#   path_search           searches/build_path_search.sh
#   application           application/build.sh
set -eu

usage() {
    sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
}
install= cluster= raw= port=54410 socket=
while [ "$#" -gt 0 ]; do
    case $1 in
        --install) install=$2; shift 2 ;;
        --cluster) cluster=$2; shift 2 ;;
        --raw-data) raw=$2; shift 2 ;;
        --port) port=$2; shift 2 ;;
        --socket-dir) socket=$2; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$install" ] && [ -n "$cluster" ] && [ -n "$raw" ] || usage
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
install=$(CDPATH='' cd -- "$install" && pwd)
raw=$(CDPATH='' cd -- "$raw" && pwd)
bin="$install/bin"
[ -n "$socket" ] || socket=$(mktemp -d /tmp/af-db.XXXXXX)
socket=$(CDPATH='' cd -- "$socket" && pwd)
[ ! -e "$cluster" ] || { echo "build_all.sh: $cluster already exists" >&2; exit 1; }

echo "Creating cluster $cluster (socket $socket, port $port)"
"$bin/initdb" -D "$cluster" -U postgres -E UTF8 --locale=C -A trust > "$cluster.initdb.log" 2>&1
{
    echo
    cat "$here/../postgresql.conf"
    echo "listen_addresses = ''"
    echo "port = $port"
    echo "unix_socket_directories = '$socket'"
    echo "unix_socket_permissions = 0700"
} >> "$cluster/postgresql.conf"
"$bin/pg_ctl" -D "$cluster" -l "$cluster.server.log" -w -t 600 start > /dev/null
trap '"$bin/pg_ctl" -D "$cluster" -m fast -w stop > /dev/null' EXIT

started=$(date +%s)
step() {
    printf '\n--- %s (%s s elapsed)\n' "$*" "$(( $(date +%s) - started ))"
}

step "tpch_job and tpch_sf10"
sh "$here/tpch_job/build.sh" --dataset all --raw-dir "$raw" --bindir "$bin" \
    --host "$socket" --port "$port" --user postgres

step "original_queries"
sh "$here/original_queries/build.sh" --pg-bin "$bin" --socket-dir "$socket" --port "$port" \
    --raw-dir "$raw" --recorded-statistics
python3 "$here/original_queries/fingerprint.py" --psql "$bin/psql" --host "$socket" --port "$port" \
    --user postgres --dbname original_queries --output "$cluster.original_queries.json" > /dev/null
python3 "$here/original_queries/fingerprint.py" \
    --compare "$here/original_queries/reference-fingerprint.json" "$cluster.original_queries.json"

for database in title_search path_search; do
    step "$database"
    sh "$here/searches/build_$database.sh" -b "$bin" -H "$socket" -p "$port" -U postgres
    python3 "$here/searches/fixture_digest.py" --psql "$bin/psql" --host "$socket" --port "$port" \
        --user postgres --dbname "$database" --output "$cluster.$database.json"
    python3 "$here/searches/fixture_digest.py" \
        --compare "$here/searches/expected/$database.digest.json" "$cluster.$database.json"
done

step "application"
sh "$here/application/build.sh" --bindir "$bin" --host "$socket" --port "$port" --superuser postgres

step "All six databases built and verified"
echo "Start the server with: $bin/pg_ctl -D $cluster -l $cluster.server.log start"
echo "(socket directory $socket, port $port)"
