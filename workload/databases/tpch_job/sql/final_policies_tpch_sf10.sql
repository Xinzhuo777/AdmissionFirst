-- Row policy present when the measured tpch_sf10 database was archived (the
-- selective-key policy on tpch_customer).  Benchmark cases replace it.
CREATE POLICY caprls_e3_policy_tpch_customer ON public.tpch_customer FOR SELECT TO caprls_e3_rls_user USING (tenant_id = 1 AND (c_custkey % 50::bigint) = 0);
