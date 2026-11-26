#!/usr/bin/env python3
"""Concatenate loader SQL files and fill in the raw-data directories.

@TPCH_DIR@ and @IMDB_DIR@ are replaced by absolute directories.  In
"client" mode every server-side line of the form

    COPY <table> FROM '<file>' WITH (...);

becomes a psql meta-command

    \\copy <table> FROM '<file>' WITH (...)

so psql reads the file and streams it to the server (COPY ... FROM STDIN).
Both forms go through the same server-side COPY code and produce the same
table contents and row placement.  "server" mode keeps the COPY statements
(the server process must be able to read the files; needs superuser or
pg_read_server_files).
"""

import argparse
import re
import sys

COPY_LINE = re.compile(r"^COPY (\S+) FROM '([^']*)' (WITH \(.*\));\s*$")


def check_dir(path):
    if not path.startswith("/"):
        raise SystemExit(f"data directory must be absolute: {path}")
    if any(ch in path for ch in "'\\\n\r"):
        raise SystemExit(f"data directory may not contain quotes, backslashes or newlines: {path}")
    return path.rstrip("/")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=("client", "server"), required=True)
    parser.add_argument("--tpch-dir")
    parser.add_argument("--imdb-dir")
    parser.add_argument("files", nargs="+")
    args = parser.parse_args()
    replacements = {}
    if args.tpch_dir:
        replacements["@TPCH_DIR@"] = check_dir(args.tpch_dir)
    if args.imdb_dir:
        replacements["@IMDB_DIR@"] = check_dir(args.imdb_dir)
    out = []
    for name in args.files:
        with open(name, encoding="utf-8") as handle:
            text = handle.read()
        for key, value in replacements.items():
            text = text.replace(key, value)
        if "@TPCH_DIR@" in text or "@IMDB_DIR@" in text:
            raise SystemExit(f"{name}: a data directory placeholder was not provided")
        for line in text.splitlines():
            match = COPY_LINE.match(line)
            if match and args.mode == "client":
                line = f"\\copy {match.group(1)} FROM '{match.group(2)}' {match.group(3)}"
            out.append(line)
        out.append("")
    sys.stdout.write("\n".join(out))


if __name__ == "__main__":
    main()
