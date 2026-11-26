-- Read access for the benchmark's ordinary login role and row-level security
-- on the two protected tables.  FORCE makes the policies apply to the table
-- owner too.  Policies themselves are installed per benchmark case.
GRANT USAGE ON SCHEMA public TO caprls_e3_rls_user;
GRANT SELECT ON public.tpch_customer, public.tpch_orders, public.tpch_lineitem, public.job_title, public.job_movie_companies, public.job_cast_info, public.group_membership, public.share_acl TO caprls_e3_rls_user;
ALTER TABLE public.tpch_customer ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tpch_customer FORCE ROW LEVEL SECURITY;
ALTER TABLE public.job_title ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.job_title FORCE ROW LEVEL SECURITY;
