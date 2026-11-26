-- Export the planner statistics (pg_statistic rows) of every table in schema
-- "public" as a SQL script that loads them into another database with the
-- same tables.  This is how stats/*.sql were produced from the reference
-- databases; it is included for transparency.  Read-only on the source.
--
--   psql -X -A -t -q -v ON_ERROR_STOP=1 -d REFERENCE_DB -f export_statistics.sql > stats.sql
--
-- Values are written as text and read back with array_in() using the
-- column's type, so the loaded rows are byte-for-byte equal to the exported
-- ones.  Only statistic kinds 1-3 (MCV list, histogram, correlation) occur
-- in these fixtures; the export refuses anything else.
SET extra_float_digits = 3;
DO $check$
BEGIN
    IF EXISTS (SELECT FROM pg_catalog.pg_statistic s JOIN pg_catalog.pg_class c ON c.oid = s.starelid
               WHERE c.relnamespace = 'public'::regnamespace
                 AND (s.stakind1 > 3 OR s.stakind2 > 3 OR s.stakind3 > 3 OR s.stakind4 > 3 OR s.stakind5 > 3
                      OR s.stainherit)) THEN
        RAISE EXCEPTION 'unsupported statistic kind or inherited statistics';
    END IF;
END
$check$;
SELECT '-- Planner statistics (pg_statistic rows) of the reference database.';
SELECT '-- Loaded by the build script after the fixture build (superuser required).';
SELECT 'BEGIN;';
SELECT 'DELETE FROM pg_catalog.pg_statistic WHERE starelid IN (SELECT oid FROM pg_catalog.pg_class WHERE relnamespace = ''public''::regnamespace);';
WITH s AS (
    SELECT c.relname, a.attname, s.*
    FROM pg_catalog.pg_statistic s
    JOIN pg_catalog.pg_class c ON c.oid = s.starelid
    JOIN pg_catalog.pg_attribute a ON a.attrelid = s.starelid AND a.attnum = s.staattnum
    WHERE c.relnamespace = 'public'::regnamespace
), e AS (
    SELECT relname, staattnum, attname, stanullfrac, stawidth, stadistinct,
           ARRAY[stakind1, stakind2, stakind3, stakind4, stakind5] AS kinds,
           ARRAY[staop1, staop2, staop3, staop4, staop5] AS ops,
           ARRAY[stacoll1, stacoll2, stacoll3, stacoll4, stacoll5] AS colls,
           ARRAY[stanumbers1::text, stanumbers2::text, stanumbers3::text, stanumbers4::text, stanumbers5::text] AS nums,
           ARRAY[stavalues1::text, stavalues2::text, stavalues3::text, stavalues4::text, stavalues5::text] AS vals
    FROM s
)
SELECT format(
    E'INSERT INTO pg_catalog.pg_statistic SELECT a.attrelid, a.attnum, false, %s::real, %s, %s::real,\n %s,\n %s,\n %s,\n %s,\n %s\n'
    ' FROM pg_catalog.pg_attribute a WHERE a.attrelid = %L::regclass AND a.attname = %L;',
    stanullfrac::text, stawidth, stadistinct::text,
    (SELECT string_agg(k::text, ', ' ORDER BY i) FROM unnest(kinds) WITH ORDINALITY u(k, i)),
    (SELECT string_agg(CASE WHEN o = 0 THEN '0' ELSE quote_literal(o::regoperator::text) || '::regoperator' END, ', ' ORDER BY i)
       FROM unnest(ops) WITH ORDINALITY u(o, i)),
    (SELECT string_agg(CASE WHEN o = 0 THEN '0' ELSE quote_literal(o::regcollation::text) || '::regcollation' END, ', ' ORDER BY i)
       FROM unnest(colls) WITH ORDINALITY u(o, i)),
    (SELECT string_agg(CASE WHEN n IS NULL THEN 'NULL' ELSE quote_literal(n) || '::real[]' END, ', ' ORDER BY i)
       FROM unnest(nums) WITH ORDINALITY u(n, i)),
    (SELECT string_agg(CASE WHEN v IS NULL THEN 'NULL' ELSE 'array_in(' || quote_literal(v) || ', a.atttypid, -1)' END, E',\n ' ORDER BY i)
       FROM unnest(vals) WITH ORDINALITY u(v, i)),
    'public.' || quote_ident(relname), attname)
FROM e
ORDER BY relname, staattnum;
SELECT 'COMMIT;';
