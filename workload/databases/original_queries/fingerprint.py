#!/usr/bin/env python3
"""Fingerprint the tables of a built "original queries" database.

For every table in schema public it records
  rows      exact row count
  content   order-independent hash: sum over rows of the first 128 bits of
            SHA-256(row in COPY text format), modulo 2**128
  physical  SHA-256 over "ctid<TAB>row" lines in physical (ctid) order, so it also
            fixes the page and line-pointer position of every row
and, from pg_class, relpages / relallvisible / main-fork size of the table and of each
index.  Two databases with equal fingerprints hold the same rows at the same ctids.

Usage:
  python3 fingerprint.py --psql /path/to/psql --host SOCKET_DIR --port PORT \
      --dbname original_queries [--jobs 4] [--output fingerprint.json]
  python3 fingerprint.py --compare a.json b.json

Python 3 standard library only; talks to the server through psql as user postgres.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
import subprocess
import sys

MASK = (1 << 128) - 1


def psql_base(args):
    return [args.psql, '-X', '--no-password', '-v', 'ON_ERROR_STOP=1', '-h', args.host,
            '-p', str(args.port), '-U', args.user, '-d', args.dbname]


def query(args, sql):
    out = subprocess.run(psql_base(args) + ['-At', '-F', '\t', '-c', sql], check=True,
                         stdout=subprocess.PIPE, env=clean_env()).stdout
    return [line.split('\t') for line in out.decode('utf-8').splitlines()]


def clean_env():
    env = {k: v for k, v in os.environ.items() if not k.startswith('PG')}
    env['PGCLIENTENCODING'] = 'UTF8'
    env['PGOPTIONS'] = ('-c synchronize_seqscans=off -c max_parallel_workers_per_gather=0 '
                        '-c row_security=off -c statement_timeout=0')
    return env


def table_hash(args, table):
    sql = 'COPY (SELECT ctid, * FROM public.%s) TO STDOUT' % quote_ident(table)
    proc = subprocess.Popen(psql_base(args) + ['-c', sql], stdout=subprocess.PIPE,
                            env=clean_env(), bufsize=1 << 20)
    physical = hashlib.sha256()
    content = 0
    rows = 0
    last = (-1, -1)
    ordered = True
    for line in proc.stdout:
        physical.update(line)
        tab = line.index(b'\t')
        block, offset = line[1:tab - 1].split(b',')
        position = (int(block), int(offset))
        if position <= last:
            ordered = False
        last = position
        content = (content + int.from_bytes(hashlib.sha256(line[tab + 1:]).digest()[:16], 'big')) & MASK
        rows += 1
    if proc.wait() != 0:
        raise RuntimeError('psql failed for table ' + table)
    return table, {'rows': rows, 'content': '%032x' % content,
                   'physical': physical.hexdigest(), 'ctid_ordered_scan': ordered}


def quote_ident(name):
    return '"' + name.replace('"', '""') + '"'


def fingerprint(args):
    tables = [r[0] for r in query(args, "SELECT relname FROM pg_class WHERE relkind = 'r' "
                                        "AND relnamespace = 'public'::regnamespace ORDER BY relname")]
    meta = {}
    for name, kind, pages, tuples, allvis, size, toast_pages in query(args, """
        SELECT c.relname, c.relkind, c.relpages, c.reltuples, c.relallvisible,
               pg_relation_size(c.oid), coalesce(t.relpages, 0)
        FROM pg_class c LEFT JOIN pg_class t ON t.oid = c.reltoastrelid
        WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'i')
        ORDER BY c.relname"""):
        meta[name] = {'kind': kind, 'relpages': int(pages), 'reltuples': float(tuples),
                      'relallvisible': int(allvis), 'main_bytes': int(size),
                      'toast_relpages': int(toast_pages)}
    result = {'tables': {}, 'indexes': {}}
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(table_hash, args, t) for t in tables]
        for future in concurrent.futures.as_completed(futures):
            table, data = future.result()
            data.update(meta[table])
            result['tables'][table] = data
            print('%-18s %10d rows  physical %s' % (table, data['rows'], data['physical'][:16]),
                  file=sys.stderr)
    for name, data in meta.items():
        if data['kind'] == 'i':
            result['indexes'][name] = data
    result['index_definitions'] = {r[0]: r[1] for r in query(args, """
        SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = 'public'""")}
    return result


def compare(a_path, b_path):
    with open(a_path) as handle:
        a = json.load(handle)
    with open(b_path) as handle:
        b = json.load(handle)
    exact = ('rows', 'content', 'physical', 'relpages', 'relallvisible', 'main_bytes',
             'toast_relpages')
    differences = 0
    for section, keys in (('tables', exact), ('indexes', ('relpages', 'main_bytes'))):
        for name in sorted(set(a[section]) | set(b[section])):
            if name not in a[section] or name not in b[section]:
                print('%s %s: present on one side only' % (section, name))
                differences += 1
                continue
            for key in keys:
                if a[section][name][key] != b[section][name][key]:
                    print('%s %s: %s %s != %s' % (section, name, key, a[section][name][key],
                                                  b[section][name][key]))
                    differences += 1
    if a['index_definitions'] != b['index_definitions']:
        print('index definitions differ')
        differences += 1
    print('%d differences' % differences)
    return 1 if differences else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--psql', default='psql')
    parser.add_argument('--host', default='/tmp')
    parser.add_argument('--port', default='5432')
    parser.add_argument('--user', default='postgres')
    parser.add_argument('--dbname', default='original_queries')
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--output')
    parser.add_argument('--compare', nargs=2, metavar='JSON')
    args = parser.parse_args()
    if args.compare:
        return compare(*args.compare)
    result = fingerprint(args)
    text = json.dumps(result, indent=1, sort_keys=True)
    if args.output:
        with open(args.output, 'w') as handle:
            handle.write(text + '\n')
    else:
        print(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
