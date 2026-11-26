-- Partial B-tree "authorization indexes" for the selective-key policy
-- (tenant/region = 1 and key divisible by 50), then a fresh ANALYZE of the
-- two tables, and the database default that lets the patched planner use
-- them.  On a stock server the setting is stored as a placeholder and has
-- no effect.  Runs as one transaction, as when the measured database was
-- prepared.  psql variable: dbname.
BEGIN;
CREATE INDEX native_af_auth_tpch_customer_segment_key ON public.tpch_customer USING btree (c_mktsegment, c_custkey) WHERE (tenant_id = 1 AND (c_custkey % 50::bigint) = 0);
CREATE INDEX native_af_auth_job_title_kind_key ON public.job_title USING btree (kind, t_id) WHERE (region_id = 1 AND (t_id % 50::bigint) = 0);
ANALYZE public.tpch_customer;
ANALYZE public.job_title;
ALTER DATABASE :"dbname" SET native_af.authorization_indexes TO on;
COMMIT;
