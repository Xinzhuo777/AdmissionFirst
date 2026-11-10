CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS public;

CREATE TABLE IF NOT EXISTS public.artifact_dependencies (
  artifact_id text NOT NULL,
  dep_kind text NOT NULL,
  dep_name text NOT NULL,
  version_at_build bigint NOT NULL,
  PRIMARY KEY (artifact_id, dep_kind, dep_name)
);

CREATE TABLE IF NOT EXISTS public.auth_idx (
  artifact_id text NOT NULL,
  policy_id text NOT NULL,
  user_id text NOT NULL,
  ctx_hash text NOT NULL,
  rid bigint NOT NULL,
  rid_domain_id text NOT NULL,
  base_rel_oid oid,
  policy_version bigint NOT NULL DEFAULT 0,
  membership_version bigint NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS public.auth_idx_keyed (
  artifact_id text NOT NULL,
  policy_id text NOT NULL,
  user_id text NOT NULL,
  ctx_hash text NOT NULL,
  key_name text NOT NULL,
  key_value text,
  range_bucket text,
  rid bigint NOT NULL,
  rid_domain_id text NOT NULL,
  base_rel_oid oid,
  policy_version bigint NOT NULL DEFAULT 0,
  membership_version bigint NOT NULL DEFAULT 0
);

CREATE SEQUENCE IF NOT EXISTS public.udf_audit_call_seq;

CREATE TABLE IF NOT EXISTS public.udf_audit (
  run_id text NOT NULL,
  query_id text NOT NULL,
  plan_id text NOT NULL,
  occurrence_id text NOT NULL,
  rid bigint NOT NULL,
  value_hash text NOT NULL,
  call_counter bigint NOT NULL,
  observed_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION public.unsafe_log(
  run_id text,
  query_id text,
  plan_id text,
  occurrence_id text,
  rid bigint,
  secret text
) RETURNS boolean
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
AS $$
BEGIN
  INSERT INTO public.udf_audit(run_id, query_id, plan_id, occurrence_id, rid, value_hash, call_counter)
  VALUES (
    run_id,
    query_id,
    plan_id,
    occurrence_id,
    rid,
    encode(digest(coalesce(secret, ''), 'sha256'), 'hex'),
    nextval('public.udf_audit_call_seq')
  );
  RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION public.caprls_assert_artifact_valid(
  p_artifact_id text,
  p_expected_versions_json jsonb
) RETURNS boolean
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
AS $$
BEGIN
  RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION public.caprls_text_eq_bigint(left_value text, right_value bigint)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT left_value = right_value::text;
$$;

DROP OPERATOR IF EXISTS public.= (text, bigint);
CREATE OPERATOR public.= (
  LEFTARG = text,
  RIGHTARG = bigint,
  FUNCTION = public.caprls_text_eq_bigint
);

CREATE TABLE IF NOT EXISTS public.tenant (
  tenant_id bigint PRIMARY KEY,
  region text NOT NULL,
  plan text NOT NULL
);

CREATE TABLE IF NOT EXISTS public.user_account (
  user_id bigint PRIMARY KEY,
  tenant_id bigint NOT NULL,
  clearance integer NOT NULL,
  home_region text NOT NULL
);

CREATE TABLE IF NOT EXISTS public.group_membership (
  user_id text NOT NULL,
  group_id bigint NOT NULL,
  membership_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS public.share_acl (
  group_id bigint NOT NULL,
  rid bigint NOT NULL,
  relname text NOT NULL,
  permission text NOT NULL,
  valid_from timestamptz NOT NULL DEFAULT TIMESTAMPTZ '2020-01-01 00:00:00+00',
  valid_to timestamptz NOT NULL DEFAULT TIMESTAMPTZ '2030-01-01 00:00:00+00',
  acl_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (group_id, rid, relname, permission)
);

CREATE TABLE IF NOT EXISTS public.document (
  doc_id bigint PRIMARY KEY,
  tenant_id bigint NOT NULL,
  owner_id bigint NOT NULL,
  group_id bigint NOT NULL,
  region text NOT NULL,
  class integer NOT NULL,
  purpose text NOT NULL DEFAULT 'read',
  public boolean NOT NULL,
  secret text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS public.ticket (
  ticket_id bigint PRIMARY KEY,
  tenant_id bigint NOT NULL,
  owner_id bigint NOT NULL,
  status text NOT NULL,
  priority integer NOT NULL,
  secret text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS public.invoice (
  invoice_id bigint PRIMARY KEY,
  tenant_id bigint NOT NULL,
  account_id bigint NOT NULL,
  amount numeric(12,2) NOT NULL DEFAULT 0,
  region text NOT NULL,
  secret text NOT NULL
);

CREATE TABLE IF NOT EXISTS public.purpose_policy (
  rid bigint NOT NULL,
  relname text NOT NULL,
  purpose text NOT NULL,
  allowed boolean NOT NULL,
  PRIMARY KEY (rid, relname, purpose)
);

CREATE TABLE IF NOT EXISTS public.synthetic_context (
  ctx_hash text PRIMARY KEY,
  context_id text NOT NULL UNIQUE,
  user_id bigint NOT NULL,
  tenant_id bigint NOT NULL,
  sorted_roles text[] NOT NULL DEFAULT ARRAY[]::text[],
  sorted_group_ids text[] NOT NULL DEFAULT ARRAY[]::text[],
  purpose text,
  region text,
  clearance integer,
  time_bucket text,
  query_scope_id text,
  canonical_context jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS public.tpch_customer (
  c_custkey bigint PRIMARY KEY,
  c_mktsegment text NOT NULL,
  tenant_id bigint NOT NULL,
  region_id bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS public.tpch_orders (
  o_orderkey bigint PRIMARY KEY,
  o_custkey bigint NOT NULL,
  o_orderdate date NOT NULL,
  o_shippriority integer NOT NULL,
  tenant_id bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS public.tpch_lineitem (
  l_orderkey bigint NOT NULL,
  l_extendedprice numeric(12,2) NOT NULL,
  l_discount numeric(5,4) NOT NULL,
  l_shipdate date NOT NULL
);

CREATE TABLE IF NOT EXISTS public.job_title (
  t_id bigint PRIMARY KEY,
  kind text NOT NULL,
  production_year integer NOT NULL,
  region_id bigint NOT NULL,
  studio_id bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS public.job_movie_companies (
  movie_id bigint NOT NULL,
  company_id bigint NOT NULL,
  company_type text NOT NULL,
  region_id bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS public.job_cast_info (
  movie_id bigint NOT NULL,
  person_id bigint NOT NULL,
  role_id bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS public.e6b_mav_document_ctx_000001 (
  doc_id bigint PRIMARY KEY,
  tenant_id bigint NOT NULL,
  owner_id bigint NOT NULL,
  public boolean NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS public.e8b_mav_document_ctx_000001 (
  doc_id bigint PRIMARY KEY,
  tenant_id bigint NOT NULL,
  owner_id bigint NOT NULL,
  region text NOT NULL,
  public boolean NOT NULL
);

CREATE TABLE IF NOT EXISTS public.e10_mav_document_ctx_000001 (
  rid bigint PRIMARY KEY,
  tenant_id bigint NOT NULL,
  sort_key text NOT NULL
);

CREATE TABLE IF NOT EXISTS public.e10_mav_ticket_ctx_000001 (
  rid bigint PRIMARY KEY,
  tenant_id bigint NOT NULL,
  sort_key text NOT NULL
);

CREATE TABLE IF NOT EXISTS public.e10_mav_invoice_ctx_000001 (
  rid bigint PRIMARY KEY,
  tenant_id bigint NOT NULL,
  sort_key text NOT NULL
);

DROP MATERIALIZED VIEW IF EXISTS public.auth_view_document_scope;
CREATE MATERIALIZED VIEW public.auth_view_document_scope AS
SELECT d.doc_id, d.tenant_id, d.owner_id, d.purpose, d.public
FROM public.document d
WHERE false;

DROP MATERIALIZED VIEW IF EXISTS public.auth_mv_document_scope;
CREATE MATERIALIZED VIEW public.auth_mv_document_scope AS
SELECT d.doc_id, d.tenant_id, d.owner_id, d.purpose, d.public
FROM public.document d
WHERE false;

TRUNCATE public.auth_idx, public.auth_idx_keyed, public.artifact_dependencies, public.udf_audit;
TRUNCATE
  public.e6b_mav_document_ctx_000001,
  public.e8b_mav_document_ctx_000001,
  public.e10_mav_document_ctx_000001,
  public.e10_mav_ticket_ctx_000001,
  public.e10_mav_invoice_ctx_000001;
TRUNCATE
  public.purpose_policy,
  public.share_acl,
  public.group_membership,
  public.synthetic_context,
  public.invoice,
  public.ticket,
  public.document,
  public.user_account,
  public.tenant;
TRUNCATE
  public.tpch_lineitem,
  public.tpch_orders,
  public.tpch_customer,
  public.job_cast_info,
  public.job_movie_companies,
  public.job_title;

INSERT INTO public.tenant(tenant_id, region, plan)
VALUES (1, 'us', 'pro'), (10, 'us', 'enterprise'), (88, 'emea', 'enterprise')
ON CONFLICT DO NOTHING;

INSERT INTO public.user_account(user_id, tenant_id, clearance, home_region)
VALUES (1, 1, 3, 'us'), (7, 10, 5, 'us'), (85, 10, 4, 'us'), (88, 88, 5, 'emea'), (101, 88, 5, 'emea')
ON CONFLICT DO NOTHING;

INSERT INTO public.group_membership(user_id, group_id, membership_version)
VALUES ('1', 1, 0), ('7', 1, 0), ('85', 1, 0), ('88', 1, 0), ('e3_user', 1, 0)
ON CONFLICT DO NOTHING;

INSERT INTO public.document(doc_id, tenant_id, owner_id, group_id, region, class, purpose, public, secret, payload)
SELECT g, CASE WHEN g % 2 = 0 THEN 10 ELSE 88 END, 7, 1,
       CASE WHEN g % 2 = 0 THEN 'us' ELSE 'emea' END,
       1 + (g % 5), CASE WHEN g % 2 = 0 THEN 'analytics' ELSE 'read' END,
       (g % 3 = 0), 'doc-' || g::text, jsonb_build_object('doc', g)
FROM generate_series(1, 120) AS g;

INSERT INTO public.ticket(ticket_id, tenant_id, owner_id, status, priority, secret, payload)
SELECT g, 10, CASE WHEN g % 2 = 0 THEN 7 ELSE 85 END,
       CASE WHEN g % 2 = 0 THEN 'open' ELSE 'closed' END,
       1 + (g % 5), 'ticket-' || g::text, jsonb_build_object('ticket', g)
FROM generate_series(1, 60) AS g;

INSERT INTO public.invoice(invoice_id, tenant_id, account_id, amount, region, secret)
SELECT g, 88, 101, (g * 10)::numeric, CASE WHEN g % 2 = 0 THEN 'us' ELSE 'emea' END, 'invoice-' || g::text
FROM generate_series(1, 80) AS g;

INSERT INTO public.share_acl(group_id, rid, relname, permission, valid_from, valid_to, acl_version)
SELECT 1, doc_id, 'document', 'read', TIMESTAMPTZ '2020-01-01 00:00:00+00', TIMESTAMPTZ '2030-01-01 00:00:00+00', 0
FROM public.document
WHERE doc_id % 4 = 0
ON CONFLICT DO NOTHING;

INSERT INTO public.share_acl(group_id, rid, relname, permission, valid_from, valid_to, acl_version)
SELECT 1, c_custkey, 'public.tpch_customer', 'read', TIMESTAMPTZ '2020-01-01 00:00:00+00', TIMESTAMPTZ '2030-01-01 00:00:00+00', 0
FROM generate_series(1, 30) AS c_custkey
WHERE c_custkey % 3 = 0
ON CONFLICT DO NOTHING;

INSERT INTO public.share_acl(group_id, rid, relname, permission, valid_from, valid_to, acl_version)
SELECT 1, t_id, 'public.job_title', 'read', TIMESTAMPTZ '2020-01-01 00:00:00+00', TIMESTAMPTZ '2030-01-01 00:00:00+00', 0
FROM generate_series(1, 40) AS t_id
WHERE t_id % 4 = 0
ON CONFLICT DO NOTHING;

INSERT INTO public.purpose_policy(rid, relname, purpose, allowed)
SELECT invoice_id, 'invoice', 'audit', true
FROM public.invoice
ON CONFLICT DO NOTHING;

INSERT INTO public.synthetic_context(
  ctx_hash, context_id, user_id, tenant_id, sorted_roles, sorted_group_ids,
  purpose, region, clearance, time_bucket, query_scope_id, canonical_context
)
VALUES (
  'sha256:0a60c7a2405c83878811a5ec8aa57487a9b62fad8fb5d0bb42216ec758ee5f94',
  'ctx_000001',
  88,
  88,
  ARRAY['reader'],
  ARRAY['1'],
  'audit',
  'emea',
  5,
  '2026-06',
  'fixture',
  '{"fixture": true}'::jsonb
)
ON CONFLICT DO NOTHING;

INSERT INTO public.tpch_customer(c_custkey, c_mktsegment, tenant_id, region_id)
SELECT g, CASE WHEN g % 2 = 0 THEN 'BUILDING' ELSE 'AUTOMOBILE' END, 1 + (g % 10), 1 + (g % 5)
FROM generate_series(1, 30) AS g;

INSERT INTO public.tpch_orders(o_orderkey, o_custkey, o_orderdate, o_shippriority, tenant_id)
SELECT g, 1 + (g % 30), DATE '1995-01-01' + (g % 300), g % 5, 1 + (g % 10)
FROM generate_series(1, 80) AS g;

INSERT INTO public.tpch_lineitem(l_orderkey, l_extendedprice, l_discount, l_shipdate)
SELECT 1 + (g % 80), (100 + g)::numeric, 0.05, DATE '1995-03-01' + (g % 200)
FROM generate_series(1, 160) AS g;

INSERT INTO public.job_title(t_id, kind, production_year, region_id, studio_id)
SELECT g, CASE WHEN g % 2 = 0 THEN 'movie' ELSE 'episode' END, 1980 + (g % 40), 1 + (g % 5), 1 + (g % 20)
FROM generate_series(1, 40) AS g;

INSERT INTO public.job_movie_companies(movie_id, company_id, company_type, region_id)
SELECT 1 + (g % 40), 1 + (g % 20), CASE WHEN g % 2 = 0 THEN 'production' ELSE 'distributor' END, 1 + (g % 5)
FROM generate_series(1, 80) AS g;

INSERT INTO public.job_cast_info(movie_id, person_id, role_id)
SELECT 1 + (g % 40), 1 + (g % 100), 1 + (g % 8)
FROM generate_series(1, 120) AS g;

INSERT INTO public.auth_idx(artifact_id, policy_id, user_id, ctx_hash, rid, rid_domain_id, base_rel_oid)
SELECT artifact_id, policy_id, user_id, ctx_hash, rid, rid_domain_id, base_rel_oid
FROM (
  SELECT 'auth_idx_doc_ctx_000001', 'tenant_group', '88', 'sha256:0a60c7a2405c83878811a5ec8aa57487a9b62fad8fb5d0bb42216ec758ee5f94',
         doc_id, 'document.doc_id', 'public.document'::regclass::oid
  FROM public.document
  UNION ALL
  SELECT 'auth_idx_ticket_ctx_000001', 'tenant_only_ticket', '88', 'sha256:0a60c7a2405c83878811a5ec8aa57487a9b62fad8fb5d0bb42216ec758ee5f94',
         ticket_id, 'ticket.ticket_id', 'public.ticket'::regclass::oid
  FROM public.ticket
  UNION ALL
  SELECT 'auth_idx_invoice_ctx_000001', 'purpose_region_invoice', '88', 'sha256:0a60c7a2405c83878811a5ec8aa57487a9b62fad8fb5d0bb42216ec758ee5f94',
         invoice_id, 'invoice.invoice_id', 'public.invoice'::regclass::oid
  FROM public.invoice
) AS seeded(artifact_id, policy_id, user_id, ctx_hash, rid, rid_domain_id, base_rel_oid);

INSERT INTO public.auth_idx_keyed(artifact_id, policy_id, user_id, ctx_hash, key_name, key_value, range_bucket, rid, rid_domain_id, base_rel_oid)
SELECT 'auth_idx_keyed_doc_ctx_000001', 'tenant_group', '88',
       'sha256:0a60c7a2405c83878811a5ec8aa57487a9b62fad8fb5d0bb42216ec758ee5f94',
       'tenant_id', tenant_id::text, (doc_id / 1000)::text, doc_id, 'document.doc_id', 'public.document'::regclass::oid
FROM public.document;

INSERT INTO public.e6b_mav_document_ctx_000001(doc_id, tenant_id, owner_id, public, payload)
SELECT doc_id, tenant_id, owner_id, public, payload FROM public.document;

INSERT INTO public.e8b_mav_document_ctx_000001(doc_id, tenant_id, owner_id, region, public)
SELECT doc_id, tenant_id, owner_id, region, public FROM public.document;

INSERT INTO public.e10_mav_document_ctx_000001(rid, tenant_id, sort_key)
SELECT doc_id, tenant_id, doc_id::text FROM public.document;

INSERT INTO public.e10_mav_ticket_ctx_000001(rid, tenant_id, sort_key)
SELECT ticket_id, tenant_id, ticket_id::text FROM public.ticket;

INSERT INTO public.e10_mav_invoice_ctx_000001(rid, tenant_id, sort_key)
SELECT invoice_id, tenant_id, invoice_id::text FROM public.invoice;

REFRESH MATERIALIZED VIEW public.auth_view_document_scope;
REFRESH MATERIALIZED VIEW public.auth_mv_document_scope;

ANALYZE;
