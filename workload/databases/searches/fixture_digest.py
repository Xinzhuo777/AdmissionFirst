#!/usr/bin/env python3
"""Print a JSON digest of a fixture database, for comparing two builds.

The digest covers, for schema "public": every table's row count, an
order-independent content hash, a physical-order hash (row text together
with its ctid, in ctid order) and relpages/reltuples/relallvisible; index
definitions and sizes; column definitions and statistics targets;
constraints, policies, functions, sequences (with their current position);
privileges; and the attributes of every role that holds a privilege or a
policy.  Database names never enter the digest.

Planner statistics (pg_statistic) are reported as a hash per table only for
information: ANALYZE samples rows at random in PostgreSQL 16, so they are
reproducible only for tables small enough to be sampled completely.

usage: fixture_digest.py [--psql PATH] [--host DIR] [--port N] [--user NAME]
                         --dbname NAME [--output FILE]
       fixture_digest.py --compare A.json B.json

Standard library only (Python 3.9+); runs psql for all database access.
"""
import argparse
import json
import subprocess
import sys

TABLE_QUERY = """
SELECT json_build_object(
  'rows', count(*),
  'content_md5', md5(string_agg(h, ',' ORDER BY h)),
  'physical_md5', md5(string_agg(ctid::text || ':' || h, ',' ORDER BY ctid)))
FROM (SELECT ctid, md5(t::text) AS h FROM {table} t) s
"""

CATALOG_QUERIES = {
    "database": """
SELECT json_build_object('encoding', pg_encoding_to_char(encoding),
  'collate', datcollate, 'ctype', datctype, 'locale_provider', datlocprovider,
  'acl', datacl::text, 'connlimit', datconnlimit,
  'settings', (SELECT json_agg(setconfig) FROM pg_db_role_setting s WHERE s.setdatabase = d.oid))
FROM pg_database d WHERE datname = current_database()""",
    "relations": """
SELECT json_object_agg(c.relname, json_build_object(
  'kind', c.relkind, 'persistence', c.relpersistence, 'owner', c.relowner::regrole::text,
  'acl', c.relacl::text, 'options', c.reloptions, 'rowsecurity', c.relrowsecurity,
  'forcerowsecurity', c.relforcerowsecurity, 'relpages', c.relpages,
  'reltuples', c.reltuples, 'relallvisible', c.relallvisible,
  'indexdef', CASE WHEN c.relkind = 'i' THEN pg_get_indexdef(c.oid) END,
  'columns', (SELECT json_agg(json_build_object('name', a.attname,
        'type', format_type(a.atttypid, a.atttypmod), 'notnull', a.attnotnull,
        'collation', (SELECT collname FROM pg_collation WHERE oid = a.attcollation),
        'default', pg_get_expr(ad.adbin, ad.adrelid), 'identity', a.attidentity,
        'stattarget', a.attstattarget, 'acl', a.attacl::text) ORDER BY a.attnum)
      FROM pg_attribute a LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
      WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped)) ORDER BY c.relname)
FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace""",
    "constraints": """
SELECT json_object_agg(conrelid::regclass::text || '.' || conname, pg_get_constraintdef(oid) ORDER BY conrelid::regclass::text, conname)
FROM pg_constraint WHERE connamespace = 'public'::regnamespace""",
    "policies": """
SELECT json_agg(json_build_object('table', tablename, 'name', policyname,
  'permissive', permissive, 'roles', roles, 'cmd', cmd, 'qual', qual, 'with_check', with_check)
  ORDER BY tablename, policyname)
FROM pg_policies WHERE schemaname = 'public'""",
    "functions": """
SELECT json_object_agg(p.oid::regprocedure::text, json_build_object(
  'definition', pg_get_functiondef(p.oid), 'owner', p.proowner::regrole::text,
  'acl', p.proacl::text, 'leakproof', p.proleakproof, 'cost', p.procost,
  'volatile', p.provolatile, 'secdef', p.prosecdef, 'config', p.proconfig))
FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace""",
    "sequences": """
SELECT json_object_agg(schemaname || '.' || sequencename, json_build_object(
  'type', data_type::text, 'start', start_value, 'min', min_value, 'max', max_value,
  'increment', increment_by, 'cycle', cycle, 'cache', cache_size, 'last_value', last_value))
FROM pg_sequences WHERE schemaname = 'public'""",
    "schemas": """
SELECT json_object_agg(nspname, json_build_object('owner', nspowner::regrole::text, 'acl', nspacl::text) ORDER BY nspname)
FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'""",
    "default_acl": "SELECT json_agg(defaclacl::text) FROM pg_default_acl",
    "extensions": "SELECT json_agg(extname || ' ' || extversion ORDER BY extname) FROM pg_extension",
    "roles": """
SELECT json_object_agg(r.rolname, json_build_object('super', r.rolsuper, 'inherit', r.rolinherit,
  'createrole', r.rolcreaterole, 'createdb', r.rolcreatedb, 'login', r.rolcanlogin,
  'replication', r.rolreplication, 'bypassrls', r.rolbypassrls, 'connlimit', r.rolconnlimit,
  'validuntil', r.rolvaliduntil, 'config', r.rolconfig,
  'member_of', (SELECT json_agg(g.rolname ORDER BY g.rolname) FROM pg_auth_members m
                JOIN pg_roles g ON g.oid = m.roleid WHERE m.member = r.oid)) ORDER BY r.rolname)
FROM pg_roles r
WHERE r.oid IN (SELECT refobjid FROM pg_shdepend WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
                UNION SELECT relowner FROM pg_class WHERE relnamespace = 'public'::regnamespace
                UNION SELECT proowner FROM pg_proc WHERE pronamespace = 'public'::regnamespace)""",
    "statistics": """
SELECT json_object_agg(tablename, json_build_object('columns', n, 'md5', h) ORDER BY tablename)
FROM (SELECT tablename, count(*) AS n, md5(string_agg(s::text, E'\\n' ORDER BY attname, inherited)) AS h
      FROM pg_stats s WHERE schemaname = 'public' GROUP BY tablename) x""",
}


class Psql:
    def __init__(self, args):
        self.base = [args.psql, "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1", "-d", args.dbname]
        if args.host:
            self.base += ["-h", args.host]
        if args.port:
            self.base += ["-p", str(args.port)]
        if args.user:
            self.base += ["-U", args.user]

    def json(self, sql):
        out = subprocess.run(self.base + ["-c", sql], check=True, capture_output=True, text=True).stdout
        return json.loads(out.strip() or "null")


def digest(args):
    db = Psql(args)
    result = {name: db.json(sql) for name, sql in CATALOG_QUERIES.items()}
    tables = db.json("SELECT json_agg(quote_ident(relname) ORDER BY relname) FROM pg_class "
                     "WHERE relnamespace = 'public'::regnamespace AND relkind = 'r'")
    result["tables"] = {t: db.json(TABLE_QUERY.format(table="public." + t)) for t in tables or []}
    return result


def flatten(value, prefix=""):
    if isinstance(value, dict):
        for k in sorted(value):
            yield from flatten(value[k], prefix + "/" + str(k))
    else:
        yield prefix, value


def compare(a_path, b_path):
    a = dict(flatten(json.load(open(a_path))))
    b = dict(flatten(json.load(open(b_path))))
    diffs = [(k, a.get(k, "<missing>"), b.get(k, "<missing>")) for k in sorted(set(a) | set(b))
             if a.get(k, "<missing>") != b.get(k, "<missing>")]
    for k, x, y in diffs:
        print(k)
        print("   A:", json.dumps(x))
        print("   B:", json.dumps(y))
    print("%d differing fields (of %d)" % (len(diffs), len(set(a) | set(b))))
    return 1 if diffs else 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--psql", default="psql")
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--user", default="postgres")
    p.add_argument("--dbname")
    p.add_argument("--output")
    p.add_argument("--compare", nargs=2, metavar=("A", "B"))
    args = p.parse_args()
    if args.compare:
        sys.exit(compare(*args.compare))
    if not args.dbname:
        p.error("--dbname is required")
    text = json.dumps(digest(args), indent=1, sort_keys=True) + "\n"
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
