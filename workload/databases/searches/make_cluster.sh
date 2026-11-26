#!/bin/sh
# Optional helper: create a new PostgreSQL 16 cluster that matches the
# reference clusters (bootstrap superuser "postgres", UTF8, C locale, no data
# checksums, 8 kB pages) and start it on a private Unix socket.
#
# Usage: make_cluster.sh -b PG_BIN_DIR -D DATA_DIR -H SOCKET_DIR -p PORT
#                        [-s SHARED_BUFFERS]
# The server is left running; stop it with: PG_BIN_DIR/pg_ctl -D DATA_DIR stop
set -eu
PG_BIN=${PG_BIN:-}
DATA=
SOCK=
PORT=${PGPORT:-5432}
SHBUF=256MB
while getopts "b:D:H:p:s:" opt; do
    case $opt in
        b) PG_BIN=$OPTARG ;;
        D) DATA=$OPTARG ;;
        H) SOCK=$OPTARG ;;
        p) PORT=$OPTARG ;;
        s) SHBUF=$OPTARG ;;
        *) echo "usage: $0 -b PG_BIN_DIR -D DATA_DIR -H SOCKET_DIR -p PORT [-s SHARED_BUFFERS]" >&2; exit 2 ;;
    esac
done
[ -n "$PG_BIN" ] && [ -n "$DATA" ] && [ -n "$SOCK" ] ||
    { echo "$0: -b, -D and -H are required" >&2; exit 2; }
[ ! -e "$DATA" ] || { echo "$0: $DATA already exists" >&2; exit 1; }
mkdir -p "$SOCK"
chmod 700 "$SOCK"
"$PG_BIN/initdb" -D "$DATA" -U postgres -E UTF8 --locale=C -A trust >/dev/null
# Settings used for the build.  autovacuum is off so that nothing touches the
# new tables between the build steps (the reference databases were built and
# used with autovacuum off).
cat >>"$DATA/postgresql.conf" <<EOF

# fixture build settings
listen_addresses = ''
port = $PORT
unix_socket_directories = '$SOCK'
unix_socket_permissions = 0700
shared_buffers = $SHBUF
maintenance_work_mem = 256MB
max_wal_size = 4GB
autovacuum = off
jit = off
EOF
"$PG_BIN/pg_ctl" -D "$DATA" -l "$DATA/server.log" -w start >/dev/null
echo "cluster running: socket $SOCK port $PORT"
