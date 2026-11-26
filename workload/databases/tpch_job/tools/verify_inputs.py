#!/usr/bin/env python3
"""Check size and SHA-256 of the raw input files needed for one database."""

import argparse
import hashlib
import json
import os
import sys


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 22), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--database", required=True, choices=("tpch_job", "tpch_sf10"))
    parser.add_argument("--tpch-dir", required=True)
    parser.add_argument("--imdb-dir")
    parser.add_argument("--size-only", action="store_true",
                        help="check sizes only (not recommended)")
    args = parser.parse_args()
    with open(args.manifest, encoding="utf-8") as handle:
        manifest = json.load(handle)
    recipe = manifest["databases"][args.database]
    checks = [(args.tpch_dir, manifest["datasets"][recipe["tpch"]])]
    if recipe["imdb"]:
        if not args.imdb_dir:
            raise SystemExit("--imdb-dir is required for " + args.database)
        checks.append((args.imdb_dir, manifest["datasets"][recipe["imdb"]]))
    failures = 0
    for directory, dataset in checks:
        for name, expected in sorted(dataset["files"].items()):
            path = os.path.join(directory, name)
            if not os.path.isfile(path):
                print(f"MISSING  {path}")
                failures += 1
                continue
            size = os.path.getsize(path)
            if size != expected["size"]:
                print(f"BAD SIZE {path}: {size} bytes, expected {expected['size']}")
                failures += 1
                continue
            if args.size_only:
                print(f"size ok  {path}")
                continue
            actual = sha256_file(path)
            if actual != expected["sha256"]:
                print(f"BAD HASH {path}: {actual}, expected {expected['sha256']}")
                failures += 1
            else:
                print(f"ok       {path} {actual}")
    if failures:
        print(f"{failures} input file(s) failed verification", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
