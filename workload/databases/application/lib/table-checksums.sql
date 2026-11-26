-- Per-table fingerprints of schema public, one tab-separated line per table:
--   table, row count, content hash (order independent), physical hash
--   (rows in ctid order, including each row's ctid), pg_class.relpages,
--   pg_class.reltuples, pages actually allocated in the main fork;
-- and one line per sequence: last_value, log_cnt, is_called.
-- Run with: psql -X -At -v ON_ERROR_STOP=1 -f table-checksums.sql
-- Hashes use the text form of each row, so the session settings are fixed.
SET TimeZone = 'UTC';
SET DateStyle = 'ISO, YMD';
SET IntervalStyle = 'postgres';
SET extra_float_digits = 1;
SET bytea_output = 'hex';
SET row_security = off;
SET work_mem = '256MB';
SET max_parallel_workers_per_gather = 0;
SELECT format($q$
SELECT concat_ws(E'\t', %1$L, count(*),
  md5(coalesce(string_agg(h, '' ORDER BY h), '')),
  md5(coalesce(string_agg(c::text || ':' || h, ',' ORDER BY c), '')),
  (SELECT relpages FROM pg_class WHERE oid = %2$L::regclass),
  (SELECT reltuples FROM pg_class WHERE oid = %2$L::regclass),
  pg_relation_size(%2$L::regclass) / current_setting('block_size')::int)
FROM (SELECT t.ctid AS c, md5(t::text) AS h FROM %2$s AS t) AS r
$q$, c.relname, 'public.' || quote_ident(c.relname))
FROM pg_class c
WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r'
ORDER BY c.relname
\gexec
SELECT format($q$SELECT concat_ws(E'\t', %1$L, last_value, log_cnt, is_called) FROM %2$s$q$,
              'sequence:' || c.relname, 'public.' || quote_ident(c.relname))
FROM pg_class c
WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'S'
ORDER BY c.relname
\gexec
