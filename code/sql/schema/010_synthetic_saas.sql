CREATE TABLE IF NOT EXISTS public.tenant (
  tenant_id bigint PRIMARY KEY,
  region text NOT NULL,
  plan text NOT NULL
);

CREATE TABLE IF NOT EXISTS public.user_account (
  user_id bigint PRIMARY KEY,
  tenant_id bigint NOT NULL REFERENCES public.tenant(tenant_id),
  clearance integer NOT NULL,
  home_region text NOT NULL
);

CREATE TABLE IF NOT EXISTS public.role_assignment (
  user_id bigint NOT NULL REFERENCES public.user_account(user_id),
  tenant_id bigint NOT NULL REFERENCES public.tenant(tenant_id),
  role text NOT NULL,
  valid_from timestamptz NOT NULL,
  valid_to timestamptz NOT NULL,
  PRIMARY KEY (user_id, role)
);

CREATE TABLE IF NOT EXISTS public.group_membership (
  user_id bigint NOT NULL REFERENCES public.user_account(user_id),
  group_id bigint NOT NULL,
  membership_version bigint NOT NULL,
  PRIMARY KEY (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS public.document (
  doc_id bigint PRIMARY KEY,
  tenant_id bigint NOT NULL REFERENCES public.tenant(tenant_id),
  owner_id bigint NOT NULL REFERENCES public.user_account(user_id),
  group_id bigint NOT NULL,
  region text NOT NULL,
  class integer NOT NULL,
  public boolean NOT NULL,
  secret text NOT NULL,
  payload jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS public.ticket (
  ticket_id bigint PRIMARY KEY,
  tenant_id bigint NOT NULL REFERENCES public.tenant(tenant_id),
  owner_id bigint NOT NULL REFERENCES public.user_account(user_id),
  status text NOT NULL,
  priority integer NOT NULL,
  secret text NOT NULL,
  payload jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS public.invoice (
  invoice_id bigint PRIMARY KEY,
  tenant_id bigint NOT NULL REFERENCES public.tenant(tenant_id),
  account_id bigint NOT NULL REFERENCES public.user_account(user_id),
  amount numeric(12,2) NOT NULL,
  region text NOT NULL,
  secret text NOT NULL
);

CREATE TABLE IF NOT EXISTS public.event_log (
  event_id bigint PRIMARY KEY,
  tenant_id bigint NOT NULL REFERENCES public.tenant(tenant_id),
  actor_id bigint NOT NULL REFERENCES public.user_account(user_id),
  ts timestamptz NOT NULL,
  type text NOT NULL,
  payload jsonb NOT NULL,
  secret text NOT NULL
);

CREATE TABLE IF NOT EXISTS public.share_acl (
  group_id bigint NOT NULL,
  rid bigint NOT NULL,
  relname text NOT NULL,
  permission text NOT NULL,
  valid_from timestamptz NOT NULL,
  valid_to timestamptz NOT NULL,
  PRIMARY KEY (group_id, rid, relname, permission)
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
  sorted_roles text[] NOT NULL,
  sorted_group_ids text[] NOT NULL,
  purpose text,
  region text,
  clearance integer,
  time_bucket text,
  query_scope_id text,
  canonical_context jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS public.synthetic_dataset_summary (
  dataset_id text PRIMARY KEY,
  scale text NOT NULL,
  seed bigint NOT NULL,
  profile jsonb NOT NULL,
  table_counts jsonb NOT NULL,
  verification jsonb NOT NULL,
  generated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS document_tenant_doc_idx
ON public.document(tenant_id, doc_id);

CREATE INDEX IF NOT EXISTS document_owner_idx
ON public.document(owner_id);

CREATE INDEX IF NOT EXISTS document_group_idx
ON public.document(group_id);

CREATE INDEX IF NOT EXISTS ticket_tenant_ticket_idx
ON public.ticket(tenant_id, ticket_id);

CREATE INDEX IF NOT EXISTS invoice_region_idx
ON public.invoice(region, invoice_id);

CREATE INDEX IF NOT EXISTS event_log_tenant_ts_idx
ON public.event_log(tenant_id, ts);

CREATE INDEX IF NOT EXISTS group_membership_group_user_idx
ON public.group_membership(group_id, user_id);

CREATE INDEX IF NOT EXISTS share_acl_rel_rid_group_idx
ON public.share_acl(relname, rid, group_id);

CREATE INDEX IF NOT EXISTS purpose_policy_rel_rid_purpose_idx
ON public.purpose_policy(relname, rid, purpose)
WHERE allowed = true;
