-- Sanity checks after the build: exact row counts of every table, ACL row counts, tenant
-- columns without NULLs, the marker row and the reader role's attributes.  Fails (and
-- stops psql) on the first mismatch.

\set ON_ERROR_STOP on
SET search_path = public;
SET row_security = off;

DO $check$
DECLARE
  r record;
  n bigint;
BEGIN
  FOR r IN SELECT * FROM (VALUES
      ('nation', 25), ('region', 5), ('part', 200000), ('supplier', 10000),
      ('partsupp', 800000), ('customer', 150000), ('orders', 1500000),
      ('lineitem', 6001215),
      ('aka_name', 901343), ('aka_title', 361472), ('cast_info', 36244344),
      ('char_name', 3140339), ('comp_cast_type', 4), ('company_name', 234997),
      ('company_type', 4), ('complete_cast', 135086), ('info_type', 113),
      ('keyword', 134170), ('kind_type', 7), ('link_type', 18),
      ('movie_companies', 2609129), ('movie_info', 14835720),
      ('movie_info_idx', 1380035), ('movie_keyword', 4523930), ('movie_link', 29997),
      ('name', 4167491), ('person_info', 2963664), ('role_type', 12),
      ('title', 2528312),
      ('group_membership', 1), ('share_acl', 267831), ('a031_b_marker', 1)
    ) AS t(relname, expected)
  LOOP
    EXECUTE format('SELECT count(*) FROM public.%I', r.relname) INTO n;
    IF n <> r.expected THEN
      RAISE EXCEPTION 'table %: % rows, expected %', r.relname, n, r.expected;
    END IF;
  END LOOP;

  IF (SELECT count(*) FROM pg_tables WHERE schemaname = 'public') <> 32 THEN
    RAISE EXCEPTION 'unexpected number of tables in schema public';
  END IF;
  IF (SELECT count(*) FROM share_acl WHERE relname = 'public.customer') <> 15000
     OR (SELECT count(*) FROM share_acl WHERE relname = 'public.title') <> 252831 THEN
    RAISE EXCEPTION 'unexpected ACL row counts';
  END IF;
  IF EXISTS (SELECT 1 FROM customer WHERE tenant_id IS NULL)
     OR EXISTS (SELECT 1 FROM orders WHERE tenant_id IS NULL)
     OR EXISTS (SELECT 1 FROM lineitem WHERE tenant_id IS NULL)
     OR EXISTS (SELECT 1 FROM title WHERE tenant_id IS NULL) THEN
    RAISE EXCEPTION 'tenant_id contains NULL';
  END IF;
  IF (SELECT array_agg(identity) FROM a031_b_marker) <> ARRAY['a031-full-schema-b-r01'] THEN
    RAISE EXCEPTION 'marker row differs';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles ro
                 WHERE rolname = 'caprls_e3_rls_user' AND rolcanlogin AND NOT rolsuper
                   AND NOT rolinherit AND NOT rolbypassrls AND NOT rolcreaterole
                   AND NOT rolcreatedb AND NOT rolreplication
                   AND NOT EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = ro.oid)) THEN
    RAISE EXCEPTION 'reader role caprls_e3_rls_user has unexpected attributes or memberships';
  END IF;
END
$check$;

SELECT 'all checks passed' AS result;
