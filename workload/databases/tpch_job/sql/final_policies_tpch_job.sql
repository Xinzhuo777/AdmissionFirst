-- Row policies present when the measured tpch_job database was archived:
-- the selective-key policy on both protected tables (the last policy each
-- benchmark case left installed).  Every benchmark case drops and recreates
-- the policies it needs, so this only matters for ad-hoc queries.
CREATE POLICY caprls_e3_policy_tpch_customer ON public.tpch_customer FOR SELECT TO caprls_e3_rls_user USING (tenant_id = 1 AND (c_custkey % 50::bigint) = 0);
CREATE POLICY caprls_e3_policy_job_title ON public.job_title FOR SELECT TO caprls_e3_rls_user USING (region_id = 1 AND (t_id % 50::bigint) = 0);
