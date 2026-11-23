#!/bin/sh
# Run Doc safety cases in a fresh, local-only PostgreSQL cluster.
set -eu

if [ "$#" -lt 2 ]; then
    echo "usage: $0 POSTGRES_INSTALL NEW_RUN_DIRECTORY [DOC_SAFETY_OPTION ...]" >&2
    exit 2
fi
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
install=$(CDPATH='' cd -- "$1" && pwd)
mkdir "$2"
run=$(CDPATH='' cd -- "$2" && pwd)
shift 2

pg="$install/bin"
socket=$(mktemp -d /tmp/capr-af-doc.XXXXXX)
port=54409
started=false
finish() {
    result=$?
    trap - EXIT
    if "$started"; then
        "$pg/pg_ctl" -D "$run/data" -m fast -w stop > "$run/stop.log" 2>&1 ||
            result=1
    fi
    rmdir "$socket" || result=1
    printf '%s\n' "$result" > "$run/exit-code"
    exit "$result"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$pg/initdb" -D "$run/data" -A trust --no-locale > "$run/initdb.log" 2>&1
"$pg/pg_ctl" -D "$run/data" -l "$run/postgres.log" \
    -o "-c listen_addresses='' -c unix_socket_directories='$socket' -c max_parallel_workers_per_gather=0 -c jit=off -p $port" \
    -w start > "$run/start.log" 2>&1
started=true
libpq=$("$pg/pg_config" --libdir)/libpq
case $(uname -s) in
    Darwin) libpq="$libpq.dylib" ;;
    *) libpq="$libpq.so" ;;
esac
cd "$repo"
python3 -m native_af.tests.doc_safety \
    --socket-dir "$socket" --port "$port" --database postgres \
    --admin "$(id -un)" --libpq "$libpq" --output "$run/doc-safety.jsonl" "$@"
