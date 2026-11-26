#!/bin/sh
# Run the AdmissionFirst safety tests in a fresh, temporary PostgreSQL cluster.
#
#   sh tests/run_tests.sh POSTGRES_INSTALL NEW_RUN_DIRECTORY [DOC_SAFETY_OPTION ...]
#
# POSTGRES_INSTALL is an installation built by src/build.sh. The cluster is
# created inside NEW_RUN_DIRECTORY, listens only on a private Unix socket
# (port $AF_TEST_PORT, default 54409) and is stopped at the end. The results
# are written to NEW_RUN_DIRECTORY/doc-safety.jsonl and admission.jsonl.
# Useful options: --require-af-membership --require-sp
set -eu

if [ "$#" -lt 2 ]; then
    echo "usage: $0 POSTGRES_INSTALL NEW_RUN_DIRECTORY [DOC_SAFETY_OPTION ...]" >&2
    exit 2
fi
tests=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
install=$(CDPATH='' cd -- "$1" && pwd)
mkdir "$2"
run=$(CDPATH='' cd -- "$2" && pwd)
shift 2

pg="$install/bin"
socket=$(mktemp -d /tmp/af-test.XXXXXX)
port=${AF_TEST_PORT:-54409}
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
connection="--socket-dir $socket --port $port --database postgres --admin $(id -un) --libpq $libpq"
# shellcheck disable=SC2086
python3 "$tests/doc_safety.py" $connection --output "$run/doc-safety.jsonl" "$@"
# shellcheck disable=SC2086
python3 "$tests/admission.py" $connection --output "$run/admission.jsonl"
echo "All safety tests passed; results are in $run"
