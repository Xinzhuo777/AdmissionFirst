#!/bin/sh
# Build AF, run the focused RLS checks, and verify the saved A044 summary.
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: sh check.sh NEW_WORK_DIRECTORY" >&2
    exit 2
fi

repo=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
mkdir "$1"
work=$(CDPATH='' cd -- "$1" && pwd)
sh "$repo/code/build.sh" "$work/build"
sh "$repo/code/native_af/tests/run_doc.sh" "$work/build/install" "$work/test" \
    --require-af-membership --require-sp
python3 "$repo/results/verify_snapshot.py"
