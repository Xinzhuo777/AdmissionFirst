#!/usr/bin/env python3
"""Check the raw TPC-H and IMDb input files against inputs.sha256.

Usage: python3 verify_inputs.py MANIFEST TPCH_DIR IMDB_DIR

Each manifest line is "<sha256> <bytes> tpch/<file>" or "<sha256> <bytes> imdb/<file>";
tpch/ entries are looked up in TPCH_DIR and imdb/ entries in IMDB_DIR.  Exits with
status 1 if any file is missing or differs.  Python 3 standard library only.
"""
import hashlib
import os
import sys


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while True:
            block = handle.read(8 << 20)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def main(argv):
    if len(argv) != 4:
        sys.stderr.write(__doc__)
        return 2
    manifest, tpch_dir, imdb_dir = argv[1:]
    roots = {'tpch': tpch_dir, 'imdb': imdb_dir}
    failures = 0
    checked = 0
    with open(manifest, encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            expected_sha, expected_size, name = line.split()
            group, base = name.split('/', 1)
            path = os.path.join(roots[group], base)
            checked += 1
            if not os.path.isfile(path):
                print('MISSING  %s' % path)
                failures += 1
                continue
            size = os.path.getsize(path)
            if size != int(expected_size):
                print('SIZE     %s: %d bytes, expected %s' % (path, size, expected_size))
                failures += 1
                continue
            actual_sha = sha256_of(path)
            if actual_sha != expected_sha:
                print('SHA-256  %s: %s, expected %s' % (path, actual_sha, expected_sha))
                failures += 1
                continue
            print('ok       %s' % path)
            sys.stdout.flush()
    if failures:
        print('%d of %d input files are missing or differ' % (failures, checked))
        return 1
    print('all %d input files match' % checked)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
