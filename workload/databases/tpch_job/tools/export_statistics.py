#!/usr/bin/env python3
"""Export a database's planner statistics as a SQL script that loads them into
another build of the same database.

PostgreSQL 16's ANALYZE reads a random sample, so two builds with identical
data end up with slightly different pg_statistic rows and reltuples
estimates, and a few query plans can differ.  The files
sql/recorded_statistics_<database>.sql were produced with this tool from the
databases the measurements ran on; build.sh loads them at the end of a build
so the planner sees exactly the recorded statistics.

The script written here
  * replaces every pg_statistic row of the tables in the exported schemas,
  * sets pg_class.relpages / reltuples / relallvisible of every table and
    index in those schemas to the recorded values,
all in one transaction (superuser required).  Values are written as text and
read back with array_in() using the column's type, which reproduces the rows
byte for byte (check: tools/fingerprint.py records anyarray_send() digests).

Usage: python3 export_statistics.py --psql PSQL --host SOCKET_DIR --port PORT \
           --dbname DB --output FILE

Python 3 standard library only; talks to the server through psql.
"""

import argparse
import json
import os
import subprocess
import sys

SCHEMAS = ("public", "native_af_bench")
SCHEMA_LIST = ", ".join("'%s'" % s for s in SCHEMAS)

STATS_QUERY = r"""
SELECT json_build_object(
  'rel', format('%%I.%%I', n.nspname, c.relname), 'att', a.attname, 'attnum', s.staattnum,
  'inherit', s.stainherit, 'nullfrac', s.stanullfrac::text, 'width', s.stawidth,
  'distinct', s.stadistinct::text,
  'kinds', ARRAY[s.stakind1, s.stakind2, s.stakind3, s.stakind4, s.stakind5],
  'ops', ARRAY[s.staop1, s.staop2, s.staop3, s.staop4, s.staop5]::regoperator[]::text[],
  'opoids', ARRAY[s.staop1, s.staop2, s.staop3, s.staop4, s.staop5]::int8[],
  'colls', ARRAY[s.stacoll1, s.stacoll2, s.stacoll3, s.stacoll4, s.stacoll5]::regcollation[]::text[],
  'colloids', ARRAY[s.stacoll1, s.stacoll2, s.stacoll3, s.stacoll4, s.stacoll5]::int8[],
  'numbers', ARRAY[s.stanumbers1::text, s.stanumbers2::text, s.stanumbers3::text,
                   s.stanumbers4::text, s.stanumbers5::text],
  'values', ARRAY[s.stavalues1::text, s.stavalues2::text, s.stavalues3::text,
                  s.stavalues4::text, s.stavalues5::text])::text
FROM pg_catalog.pg_statistic s
JOIN pg_catalog.pg_class c ON c.oid = s.starelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_attribute a ON a.attrelid = s.starelid AND a.attnum = s.staattnum
WHERE n.nspname IN (%s)
ORDER BY 1
""" % SCHEMA_LIST

REL_QUERY = r"""
SELECT json_build_object('rel', format('%%I.%%I', n.nspname, c.relname), 'kind', c.relkind,
                         'relpages', c.relpages, 'reltuples', c.reltuples::text,
                         'relallvisible', c.relallvisible)::text
FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname IN (%s) AND c.relkind IN ('r', 'i')
ORDER BY 1
""" % SCHEMA_LIST

# MCV list, histogram, correlation: the value arrays have the column's type.
SUPPORTED_KINDS = {0, 1, 2, 3}


def run(args, sql):
    env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
    env["PGCLIENTENCODING"] = "UTF8"
    env["PGOPTIONS"] = "-c extra_float_digits=3 -c DateStyle=ISO,YMD -c IntervalStyle=postgres"
    out = subprocess.run([args.psql, "-X", "--no-password", "-v", "ON_ERROR_STOP=1",
                          "-h", args.host, "-p", str(args.port), "-U", args.user,
                          "-d", args.dbname, "-At", "-c", sql],
                         check=True, stdout=subprocess.PIPE, env=env).stdout
    return [json.loads(line) for line in out.decode("utf-8").splitlines() if line]


def lit(value):
    return "NULL" if value is None else "'" + value.replace("'", "''") + "'"


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--psql", default="psql")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=5432)
    parser.add_argument("--user", default="postgres")
    parser.add_argument("--dbname", required=True)
    parser.add_argument("--label", default="the recorded database",
                        help="description used in the file header")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    stats = run(args, STATS_QUERY)
    rels = run(args, REL_QUERY)
    for row in stats:
        if row["inherit"] or set(row["kinds"]) - SUPPORTED_KINDS:
            raise SystemExit(f"unsupported statistics row for {row['rel']}.{row['att']}")
    lines = [
        f"-- Planner statistics of {args.label}: every pg_statistic row of the",
        "-- tables in schemas " + ", ".join(SCHEMAS) + ", and relpages / reltuples /",
        "-- relallvisible of their tables and indexes.  Loaded by build.sh after the",
        "-- data load (superuser required); replaces the randomly sampled statistics of",
        "-- the new build.  Generated by tools/export_statistics.py; do not edit.",
        "-- Running ANALYZE afterwards would replace these statistics again.",
        "",
        "SET client_encoding = 'UTF8';",
        "SET DateStyle = 'ISO, YMD';",
        "BEGIN;",
        "DELETE FROM pg_catalog.pg_statistic WHERE starelid IN (SELECT c.oid FROM pg_catalog.pg_class c"
        " JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname IN (%s));" % SCHEMA_LIST,
    ]
    for row in stats:
        ops = ["0" if oid == 0 else "%s::regoperator" % lit(name)
               for name, oid in zip(row["ops"], row["opoids"])]
        colls = ["0" if oid == 0 else "%s::regcollation" % lit(name)
                 for name, oid in zip(row["colls"], row["colloids"])]
        numbers = ["NULL" if n is None else "%s::real[]" % lit(n) for n in row["numbers"]]
        values = ["NULL" if v is None else "array_in(%s, a.atttypid, -1)" % lit(v)
                  for v in row["values"]]
        lines.append(
            "INSERT INTO pg_catalog.pg_statistic SELECT a.attrelid, a.attnum, false, "
            "%s::real, %d, %s::real,\n %s,\n %s,\n %s,\n %s,\n %s\n"
            " FROM pg_catalog.pg_attribute a WHERE a.attrelid = %s::regclass AND a.attname = %s"
            " AND a.attnum = %d;"
            % (row["nullfrac"], row["width"], row["distinct"],
               ", ".join(str(k) for k in row["kinds"]), ", ".join(ops), ", ".join(colls),
               ", ".join(numbers), ",\n ".join(values),
               lit(row["rel"]), lit(row["att"]), row["attnum"]))
    for rel in rels:
        lines.append("UPDATE pg_catalog.pg_class SET relpages = %d, reltuples = %s, relallvisible = %d"
                     " WHERE oid = %s::regclass;"
                     % (rel["relpages"], rel["reltuples"], rel["relallvisible"], lit(rel["rel"])))
    lines.append(
        "DO $check$ BEGIN IF (SELECT count(*) FROM pg_catalog.pg_statistic s JOIN pg_catalog.pg_class c"
        " ON c.oid = s.starelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"
        " WHERE n.nspname IN (%s)) <> %d THEN RAISE EXCEPTION 'recorded statistics did not load completely';"
        " END IF; END $check$;" % (SCHEMA_LIST, len(stats)))
    lines.append("COMMIT;")
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    print(f"{len(stats)} pg_statistic rows and {len(rels)} relations written to {args.output}")


if __name__ == "__main__":
    main()
