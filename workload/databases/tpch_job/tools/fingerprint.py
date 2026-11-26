#!/usr/bin/env python3
"""Fingerprint a loaded benchmark database: catalog state plus per-table data hashes.

For every user table the tool streams the rows in physical order (a plain
sequential scan with synchronize_seqscans off, which returns tuples in ctid
order) and records:

  rows                row count
  content_md5_sum     order-independent hash: sum of md5(row text) mod 2**128
  physical_sha256     sha256 over "ctid<TAB>row text" lines in physical order,
                      so it changes if any row moves to another position
  first_ctid/last_ctid

The catalog part lists relations (relpages, reltuples, relallvisible, actual
size), columns, indexes, constraints, policies, grants, database settings and
the login role used by the benchmark, and an md5 digest of every pg_statistic
row (binary send format of all fields, including anyarray_send of the value
arrays).  Statistics gathered by ANALYZE are sampled at random by PostgreSQL;
they match the recorded ones only when the recorded statistics were loaded.

Only the Python standard library and the psql client are used.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys

CATALOG_SQL = r"""
SELECT json_build_object(
 'database', (SELECT json_build_object(
     'encoding', pg_encoding_to_char(encoding), 'collate', datcollate,
     'ctype', datctype, 'locale_provider', datlocprovider,
     'owner', pg_get_userbyid(datdba), 'acl', datacl::text)
   FROM pg_database WHERE datname = current_database()),
 'database_settings', (SELECT coalesce(json_agg(s ORDER BY s), '[]') FROM (
     SELECT coalesce((SELECT rolname FROM pg_roles WHERE oid = setrole), '') || ':' ||
            array_to_string(setconfig, ',') AS s
     FROM pg_db_role_setting WHERE setdatabase =
       (SELECT oid FROM pg_database WHERE datname = current_database())) x),
 'roles', (SELECT json_agg(json_build_object(
     'name', rolname, 'login', rolcanlogin, 'super', rolsuper, 'inherit', rolinherit,
     'createrole', rolcreaterole, 'createdb', rolcreatedb, 'replication', rolreplication,
     'bypassrls', rolbypassrls, 'config', rolconfig::text,
     'member_of', (SELECT coalesce(json_agg(g.rolname ORDER BY g.rolname), '[]')
                   FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
                   WHERE m.member = r.oid)) ORDER BY rolname)
   FROM pg_roles r WHERE rolname !~ '^pg_'),
 'schemas', (SELECT json_agg(json_build_object(
     'name', nspname, 'owner', pg_get_userbyid(nspowner), 'acl', nspacl::text) ORDER BY nspname)
   FROM pg_namespace WHERE nspname NOT LIKE 'pg\_%' AND nspname <> 'information_schema'),
 'extensions', (SELECT json_agg(extname || ' ' || extversion ORDER BY extname) FROM pg_extension),
 'relations', (SELECT json_agg(json_build_object(
     'name', n.nspname || '.' || c.relname, 'kind', c.relkind, 'persistence', c.relpersistence,
     'owner', pg_get_userbyid(c.relowner), 'acl', c.relacl::text, 'options', c.reloptions::text,
     'rls', c.relrowsecurity, 'force_rls', c.relforcerowsecurity,
     'relpages', c.relpages, 'reltuples', c.reltuples, 'relallvisible', c.relallvisible,
     'actual_pages', pg_relation_size(c.oid) / current_setting('block_size')::int,
     'fsm_bytes', pg_relation_size(c.oid, 'fsm'), 'vm_bytes', pg_relation_size(c.oid, 'vm'),
     'has_toast', c.reltoastrelid <> 0,
     'toast_pages', CASE WHEN c.reltoastrelid <> 0
                         THEN pg_relation_size(c.reltoastrelid) / current_setting('block_size')::int END)
     ORDER BY n.nspname, c.relname)
   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'),
 'columns', (SELECT json_agg(json_build_object(
     'table', a.attrelid::regclass::text, 'num', a.attnum, 'name', a.attname,
     'type', format_type(a.atttypid, a.atttypmod), 'notnull', a.attnotnull,
     'default', pg_get_expr(d.adbin, d.adrelid), 'stattarget', a.attstattarget,
     'collation', (SELECT collname FROM pg_collation WHERE oid = a.attcollation),
     'storage', a.attstorage, 'compression', a.attcompression)
     ORDER BY a.attrelid::regclass::text, a.attnum)
   FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
   JOIN pg_namespace n ON n.oid = c.relnamespace
   LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
   WHERE c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
     AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'),
 'indexes', (SELECT json_agg(json_build_object(
     'name', x.name, 'table', x.tab, 'definition', x.def, 'valid', x.valid,
     'ready', x.ready, 'creation_rank', x.rnk) ORDER BY x.name)
   FROM (SELECT i.indexrelid::regclass::text AS name, i.indrelid::regclass::text AS tab,
                pg_get_indexdef(i.indexrelid) AS def, i.indisvalid AS valid, i.indisready AS ready,
                rank() OVER (PARTITION BY i.indrelid ORDER BY i.indexrelid) AS rnk
         FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema') x),
 'constraints', (SELECT json_agg(json_build_object(
     'name', conname, 'table', conrelid::regclass::text, 'type', contype,
     'definition', pg_get_constraintdef(oid)) ORDER BY conrelid::regclass::text, conname)
   FROM pg_constraint WHERE connamespace IN
     (SELECT oid FROM pg_namespace WHERE nspname NOT LIKE 'pg\_%' AND nspname <> 'information_schema')),
 'policies', (SELECT coalesce(json_agg(json_build_object(
     'name', p.polname, 'table', p.polrelid::regclass::text, 'command', p.polcmd,
     'permissive', p.polpermissive,
     'roles', (SELECT json_agg(CASE WHEN r = 0 THEN 'public' ELSE pg_get_userbyid(r) END ORDER BY 1)
               FROM unnest(p.polroles) r),
     'using', pg_get_expr(p.polqual, p.polrelid),
     'with_check', pg_get_expr(p.polwithcheck, p.polrelid)) ORDER BY p.polrelid::regclass::text, p.polname), '[]')
   FROM pg_policy p),
 'functions', (SELECT coalesce(json_agg(p.oid::regprocedure::text ORDER BY 1), '[]')
   FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'),
 'triggers', (SELECT coalesce(json_agg(json_build_object(
     'table', tgrelid::regclass::text, 'internal', tgisinternal,
     'function', tgfoid::regproc::text, 'constraint', (SELECT conname FROM pg_constraint WHERE oid = tgconstraint))
     ORDER BY tgrelid::regclass::text, tgfoid::regproc::text, tgtype), '[]')
   FROM pg_trigger),
 'statistics_objects', (SELECT coalesce(json_agg(stxname ORDER BY stxname), '[]') FROM pg_statistic_ext),
 'default_acls', (SELECT coalesce(json_agg(defaclacl::text ORDER BY 1), '[]') FROM pg_default_acl),
 'comments', (SELECT coalesce(json_agg(description ORDER BY description), '[]') FROM pg_description d
   WHERE d.objoid >= 16384),
 'column_statistics_present', (SELECT coalesce(json_agg(x ORDER BY x), '[]') FROM (
     SELECT schemaname || '.' || tablename || '.' || attname AS x FROM pg_stats
     WHERE schemaname NOT LIKE 'pg\_%' AND schemaname <> 'information_schema') s),
 'statistics', (SELECT coalesce(json_object_agg(k, d ORDER BY k), '{}') FROM (
     SELECT format('%I.%I.%I', n.nspname, c.relname, a.attname) AS k,
            md5(concat_ws('|', s.stainherit, float4send(s.stanullfrac), s.stawidth,
                float4send(s.stadistinct),
                s.stakind1, s.stakind2, s.stakind3, s.stakind4, s.stakind5,
                s.staop1::regoperator, s.staop2::regoperator, s.staop3::regoperator,
                s.staop4::regoperator, s.staop5::regoperator,
                s.stacoll1::regcollation, s.stacoll2::regcollation, s.stacoll3::regcollation,
                s.stacoll4::regcollation, s.stacoll5::regcollation,
                coalesce(array_send(s.stanumbers1), '\x00'), coalesce(array_send(s.stanumbers2), '\x00'),
                coalesce(array_send(s.stanumbers3), '\x00'), coalesce(array_send(s.stanumbers4), '\x00'),
                coalesce(array_send(s.stanumbers5), '\x00'),
                coalesce(anyarray_send(s.stavalues1), '\x00'), coalesce(anyarray_send(s.stavalues2), '\x00'),
                coalesce(anyarray_send(s.stavalues3), '\x00'), coalesce(anyarray_send(s.stavalues4), '\x00'),
                coalesce(anyarray_send(s.stavalues5), '\x00'))) AS d
     FROM pg_statistic s JOIN pg_class c ON c.oid = s.starelid
     JOIN pg_namespace n ON n.oid = c.relnamespace
     JOIN pg_attribute a ON a.attrelid = s.starelid AND a.attnum = s.staattnum
     WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema') st)
)::text
"""

TABLES_SQL = r"""
SELECT format('%I.%I', n.nspname, c.relname)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'r' AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
ORDER BY 1
"""


class Psql:
    def __init__(self, args):
        self.base = [args.psql, "-X", "--no-password", "-v", "ON_ERROR_STOP=1",
                     "-h", args.host, "-p", str(args.port), "-U", args.user, "-d", args.dbname]
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
        self.env["PGCLIENTENCODING"] = "UTF8"
        self.env["PGOPTIONS"] = ("-c synchronize_seqscans=off -c DateStyle=ISO,YMD "
                                 "-c IntervalStyle=postgres -c extra_float_digits=1 "
                                 "-c TimeZone=UTC -c row_security=off -c jit=off "
                                 "-c max_parallel_workers_per_gather=0")

    def scalar(self, sql):
        out = subprocess.run(self.base + ["-At", "-c", sql], env=self.env,
                             stdout=subprocess.PIPE, check=True).stdout
        return out.decode("utf-8").rstrip("\n")

    def stream(self, sql):
        return subprocess.Popen(self.base + ["-At", "-c", sql], env=self.env,
                                stdout=subprocess.PIPE, bufsize=1 << 20)


def table_hashes(psql, table):
    # A query without WHERE/ORDER BY is a plain sequential scan, which returns
    # heap tuples in ctid order when synchronized scans are disabled.
    proc = psql.stream(f"COPY (SELECT ctid, * FROM ONLY {table}) TO STDOUT")
    physical = hashlib.sha256()
    total = 0
    rows = 0
    first = last = None
    mask = (1 << 128) - 1
    for line in proc.stdout:
        physical.update(line)
        tab = line.index(b"\t") if b"\t" in line else len(line) - 1
        ctid = line[:tab]
        body = line[tab + 1:]
        total = (total + int.from_bytes(hashlib.md5(body).digest(), "big")) & mask
        if first is None:
            first = ctid
        last = ctid
        rows += 1
    if proc.wait() != 0:
        raise RuntimeError(f"COPY failed for {table}")
    return {"rows": rows, "content_md5_sum": f"{total:032x}",
            "physical_sha256": physical.hexdigest(),
            "first_ctid": first.decode() if first else None,
            "last_ctid": last.decode() if last else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--psql", default="psql")
    parser.add_argument("--host", required=True, help="Unix socket directory or host")
    parser.add_argument("--port", type=int, default=5432)
    parser.add_argument("--user", default="postgres")
    parser.add_argument("--dbname", required=True)
    parser.add_argument("--catalog-only", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args()
    psql = Psql(args)
    result = {"catalog": json.loads(psql.scalar(CATALOG_SQL)), "tables": {}}
    if not args.catalog_only:
        for table in psql.scalar(TABLES_SQL).splitlines():
            result["tables"][table] = table_hashes(psql, table)
            print(f"{table}: {result['tables'][table]['rows']} rows", file=sys.stderr, flush=True)
    text = json.dumps(result, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
