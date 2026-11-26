-- Post-load state of the "original queries" benchmark database.
--
-- Run with psql as "postgres", connected to the target database, after load.sql, with the
-- psql variable dbname set to the target database name (build.sh does this).
--
-- 1. Database-level default read by the AdmissionFirst planner patch.  On a stock
--    PostgreSQL server it is stored as a placeholder setting and has no effect.
-- 2. Row-level-security policies and trusted reference views.  Before each benchmark
--    condition the driver resets the four protected tables (customer, orders, lineitem,
--    title) and installs that condition's policies and reference views with exactly the
--    statements below, so any starting state works for replay.  The database is left in
--    the state of the last condition run on the reference copy (TPC-H Q18 with the
--    membership policy on customer and tenant policies on orders and lineitem).  Earlier
--    conditions protected title; the reset only disables row security, so title keeps
--    FORCE ROW LEVEL SECURITY with row security disabled.
-- No data, index or statistics change happens here.

\set ON_ERROR_STOP on
SET client_encoding = 'UTF8';
SET search_path = public;

ALTER DATABASE :"dbname" SET native_af.authorization_indexes = on;

-- Residue of the earlier title conditions (their own policy was dropped again by the reset).
ALTER TABLE public.title ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.title FORCE ROW LEVEL SECURITY;

-- Setup of the last condition, verbatim.
ALTER TABLE public.customer DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS a031_policy ON public.customer;
CREATE OR REPLACE VIEW a031_expected.customer AS SELECT * FROM public.customer WHERE EXISTS (SELECT 1 FROM public.share_acl a JOIN public.group_membership m ON m.group_id = a.group_id WHERE a.relname = 'public.customer' AND a.rid = customer.c_custkey AND a.permission = 'read' AND m.user_id = 'e3_user');
CREATE POLICY a031_policy ON public.customer FOR SELECT TO caprls_e3_rls_user USING (EXISTS (SELECT 1 FROM public.share_acl a JOIN public.group_membership m ON m.group_id = a.group_id WHERE a.relname = 'public.customer' AND a.rid = customer.c_custkey AND a.permission = 'read' AND m.user_id = 'e3_user'));
ALTER TABLE public.customer ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.customer FORCE ROW LEVEL SECURITY;
ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS a031_policy ON public.orders;
CREATE OR REPLACE VIEW a031_expected.orders AS SELECT * FROM public.orders WHERE tenant_id = 1;
CREATE POLICY a031_policy ON public.orders FOR SELECT TO caprls_e3_rls_user USING (tenant_id = 1);
ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.orders FORCE ROW LEVEL SECURITY;
ALTER TABLE public.lineitem DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS a031_policy ON public.lineitem;
CREATE OR REPLACE VIEW a031_expected.lineitem AS SELECT * FROM public.lineitem WHERE tenant_id = 1;
CREATE POLICY a031_policy ON public.lineitem FOR SELECT TO caprls_e3_rls_user USING (tenant_id = 1);
ALTER TABLE public.lineitem ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.lineitem FORCE ROW LEVEL SECURITY;
ALTER TABLE public.title DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS a031_policy ON public.title;
CREATE OR REPLACE VIEW a031_expected.title AS SELECT * FROM public.title WHERE true;
