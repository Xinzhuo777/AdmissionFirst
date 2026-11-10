DROP SCHEMA IF EXISTS caprls_smoke CASCADE;
CREATE SCHEMA caprls_smoke;
SET search_path = caprls_smoke, public;
SET jit = off;
SET max_parallel_workers_per_gather = 0;

CREATE TEMP TABLE smoke_results (
  test_id text PRIMARY KEY,
  status text NOT NULL,
  details text NOT NULL
);

CREATE TABLE rls_doc (
  id bigint PRIMARY KEY,
  tenant_id integer NOT NULL,
  secret text NOT NULL
);
INSERT INTO rls_doc VALUES
  (1, 1, 'tenant1-visible-a'),
  (2, 1, 'tenant1-visible-b'),
  (3, 2, 'tenant2-hidden');
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'caprls_rls_user') THEN
    CREATE ROLE caprls_rls_user;
  END IF;
END;
$$;
ALTER TABLE rls_doc ENABLE ROW LEVEL SECURITY;
ALTER TABLE rls_doc FORCE ROW LEVEL SECURITY;
CREATE POLICY rls_doc_tenant ON rls_doc
  TO caprls_rls_user
  USING (tenant_id = current_setting('caprls.tenant_id')::integer);
GRANT USAGE ON SCHEMA caprls_smoke TO caprls_rls_user;
GRANT SELECT ON rls_doc TO caprls_rls_user;
GRANT INSERT ON public.caprls_audit_log TO caprls_rls_user;
GRANT USAGE ON SEQUENCE public.caprls_audit_log_audit_id_seq TO caprls_rls_user;
SET caprls.tenant_id = '1';
TRUNCATE public.caprls_audit_log;
SET ROLE caprls_rls_user;
SELECT count(*) FROM rls_doc WHERE public.caprls_audit_value('PG_RLS_nonleakproof_order', 'where', id, secret);
RESET ROLE;
INSERT INTO smoke_results
SELECT
  'PG_RLS_nonleakproof_order',
  CASE
    WHEN count(*) FILTER (WHERE observed_value = 'tenant2-hidden') = 0
      AND count(*) FILTER (WHERE observed_value LIKE 'tenant1-visible-%') = 2
    THEN 'pass' ELSE 'fail'
  END,
  'VOLATILE non-leakproof audit predicate only observed authorized RLS rows'
FROM public.caprls_audit_log
WHERE test_id = 'PG_RLS_nonleakproof_order';

INSERT INTO smoke_results
SELECT
  'PG_RLS_leakproof_exception',
  CASE WHEN EXISTS (
    SELECT 1
    FROM pg_proc
    WHERE proname = 'int4eq'
      AND proleakproof = true
  ) THEN 'pass' ELSE 'fail' END,
  'PostgreSQL marks builtin int4 equality as leakproof, so equality/range movement is a documented exception';

CREATE TABLE barrier_doc (
  id bigint PRIMARY KEY,
  tenant_id integer NOT NULL,
  secret text NOT NULL
);
INSERT INTO barrier_doc VALUES
  (1, 1, 'barrier-visible'),
  (2, 2, 'barrier-hidden');
CREATE VIEW barrier_v WITH (security_barrier = true) AS
  SELECT * FROM barrier_doc WHERE tenant_id = 1;
TRUNCATE public.caprls_audit_log;
SELECT count(*) FROM barrier_v WHERE public.caprls_audit_value('PG_security_barrier_nonleakproof', 'where', id, secret);
INSERT INTO smoke_results
SELECT
  'PG_security_barrier_nonleakproof',
  CASE
    WHEN count(*) FILTER (WHERE observed_value = 'barrier-hidden') = 0
      AND count(*) FILTER (WHERE observed_value = 'barrier-visible') = 1
    THEN 'pass' ELSE 'fail'
  END,
  'security_barrier view prevented non-leakproof predicate from observing filtered row'
FROM public.caprls_audit_log
WHERE test_id = 'PG_security_barrier_nonleakproof';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'caprls_view_owner') THEN
    CREATE ROLE caprls_view_owner;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'caprls_invoker_b') THEN
    CREATE ROLE caprls_invoker_b;
  END IF;
END;
$$;

CREATE TABLE owner_policy_doc (
  id integer PRIMARY KEY,
  tenant_id integer NOT NULL
);
INSERT INTO owner_policy_doc VALUES (1, 1), (2, 2);
ALTER TABLE owner_policy_doc ENABLE ROW LEVEL SECURITY;
ALTER TABLE owner_policy_doc FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_policy_for_view_owner ON owner_policy_doc
  TO caprls_view_owner
  USING (tenant_id = 1);
CREATE POLICY owner_policy_for_invoker_b ON owner_policy_doc
  TO caprls_invoker_b
  USING (tenant_id = 2);
GRANT USAGE ON SCHEMA caprls_smoke TO caprls_view_owner, caprls_invoker_b;
GRANT SELECT ON owner_policy_doc TO caprls_view_owner, caprls_invoker_b;

CREATE VIEW fixed_owner_v WITH (security_barrier = true) AS
  SELECT id, tenant_id FROM owner_policy_doc;
ALTER VIEW fixed_owner_v OWNER TO caprls_view_owner;
GRANT SELECT ON fixed_owner_v TO caprls_invoker_b;

CREATE VIEW invoker_v WITH (security_barrier = true, security_invoker = true) AS
  SELECT id, tenant_id FROM owner_policy_doc;
ALTER VIEW invoker_v OWNER TO caprls_view_owner;
GRANT SELECT ON invoker_v TO caprls_invoker_b;

CREATE TEMP TABLE role_check (
  test_id text PRIMARY KEY,
  ids integer[]
);
GRANT INSERT, SELECT ON role_check TO caprls_invoker_b;

SET ROLE caprls_invoker_b;
INSERT INTO role_check
SELECT 'PG_security_barrier_owner_policy', coalesce(array_agg(id ORDER BY id), ARRAY[]::integer[])
FROM caprls_smoke.fixed_owner_v;
INSERT INTO role_check
SELECT 'PG_security_invoker_rls_policy', coalesce(array_agg(id ORDER BY id), ARRAY[]::integer[])
FROM caprls_smoke.invoker_v;
RESET ROLE;

INSERT INTO smoke_results
SELECT
  'PG_security_barrier_owner_policy',
  CASE WHEN ids = ARRAY[1] THEN 'pass' ELSE 'fail' END,
  'fixed-owner security-barrier view used the owner-visible RLS policy result'
FROM role_check
WHERE test_id = 'PG_security_barrier_owner_policy';

INSERT INTO smoke_results
SELECT
  'PG_security_invoker_rls_policy',
  CASE WHEN ids = ARRAY[2] THEN 'pass' ELSE 'fail' END,
  'security_invoker=true view used the invoking role RLS policy result'
FROM role_check
WHERE test_id = 'PG_security_invoker_rls_policy';

CREATE TABLE mat_doc (id integer PRIMARY KEY, tenant_id integer NOT NULL);
INSERT INTO mat_doc VALUES (1, 1), (2, 2);
DO $$
DECLARE
  plan_json json;
BEGIN
  EXECUTE 'EXPLAIN (FORMAT JSON) WITH auth AS MATERIALIZED (SELECT * FROM caprls_smoke.mat_doc WHERE tenant_id = 1) SELECT * FROM auth WHERE id = 1'
    INTO plan_json;
  INSERT INTO smoke_results
  VALUES (
    'PG_materialized_cte_fence',
    CASE WHEN plan_json::text LIKE '%CTE Scan%' THEN 'pass' ELSE 'fail' END,
    'MATERIALIZED CTE creates a visible plan-shape fence; no security claim is derived from this alone'
  );
END;
$$;

TRUNCATE public.caprls_audit_log;
SELECT public.caprls_audit_value('PG_volatile_audit_call', 'direct', 1, 'audit-visible');
INSERT INTO smoke_results
SELECT
  'PG_volatile_audit_call',
  CASE WHEN count(*) = 1 THEN 'pass' ELSE 'fail' END,
  'VOLATILE PARALLEL UNSAFE audit function was called and persisted one audit row'
FROM public.caprls_audit_log
WHERE test_id = 'PG_volatile_audit_call';

SELECT jsonb_agg(
  jsonb_build_object(
    'test_id', test_id,
    'status', status,
    'details', details
  )
  ORDER BY test_id
)::text
FROM smoke_results;
