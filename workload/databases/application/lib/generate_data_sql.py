#!/usr/bin/env python3
"""Render the deterministic data-load transaction for the application database.

The synthetic multi-tenant SaaS data set is fully determined by a scale
profile and an integer seed.  Every value is computed by SQL arithmetic over
generate_series(), except the 1000 user contexts, whose canonical JSON and
SHA-256 identifiers are computed here.  The output is one psql script that
runs in a single transaction: it empties the base tables, loads them in a
fixed order, refreshes planner statistics with ANALYZE, and records a summary
row.

Only the Python 3 standard library is used.  Usage:

    python3 generate_data_sql.py > load.sql

The only deviation from the original loader is that the summary row's
generated_at column is written with the timestamp recorded in the original
database instead of clock_timestamp(), so that the table contents match.
"""

import argparse
import hashlib
import json
import sys

# Scale profile "1e5" of the synthetic SaaS data set.
PROFILE_1E5 = {
    "tenants": 100,
    "users": 10000,
    "documents": 100000,
    "tickets": 100000,
    "invoices": 50000,
    "events": 500000,
    "acl_edges": 200000,
    "group_edges": 50000,
    "contexts": 1000,
}
SEED = 52
SCALE = "1e5"
RECORDED_GENERATED_AT = "2026-11-12 17:36:08.199564+00"

BASE_RELATIONS = [
    "tenant",
    "user_account",
    "role_assignment",
    "group_membership",
    "document",
    "ticket",
    "invoice",
    "event_log",
    "share_acl",
    "purpose_policy",
]
STATISTICS_RELATIONS = (*BASE_RELATIONS, "synthetic_context")


def _quote(value):
    return "'" + value.replace("'", "''") + "'"


def _canonical_context(payload):
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _context_rows(profile, seed):
    rows = []
    tenants = int(profile["tenants"])
    users = int(profile["users"])
    contexts = int(profile["contexts"])
    group_count = max(tenants * 10, 1)
    for idx in range(1, contexts + 1):
        user_id = 1 + ((idx * 37 + seed) % users)
        tenant_id = 1 + ((user_id - 1) % tenants)
        role_count = [1, 2, 5, 20][idx % 4]
        roles = sorted({f"role_{1 + ((idx + off) % 20)}" for off in range(role_count)})
        group_span = [1, 5, 20, 100][idx % 4]
        groups = sorted(
            {str(1 + ((user_id * 31 + off * 17 + seed) % group_count)) for off in range(group_span)}
        )
        payload = {
            "clearance": str(1 + ((user_id + seed) % 5)),
            "purpose": f"purpose_{1 + (idx % 8)}",
            "query_scope_id": f"scope_{1 + (idx % 16)}",
            "region": f"region_{1 + ((tenant_id + idx) % 10)}",
            "sorted_group_ids": groups,
            "sorted_roles": roles,
            "tenant_id": str(tenant_id),
            "time_bucket": "2026-01-01T00:00:00Z",
            "user_id": str(user_id),
        }
        canonical = _canonical_context(payload)
        ctx_hash = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        rows.append(
            "("
            f"'{ctx_hash}', "
            f"'ctx_{idx:06d}', "
            f"{user_id}, "
            f"{tenant_id}, "
            f"ARRAY[{','.join(_quote(role) for role in roles)}]::text[], "
            f"ARRAY[{','.join(_quote(group_id) for group_id in groups)}]::text[], "
            f"{_quote(payload['purpose'])}, "
            f"{_quote(payload['region'])}, "
            f"{int(payload['clearance'])}, "
            f"{_quote(payload['time_bucket'])}, "
            f"{_quote(payload['query_scope_id'])}, "
            f"{_quote(canonical)}::jsonb"
            ")"
        )
    return ",\n".join(rows)


def _analyze_relations_sql():
    return "\n".join(f"ANALYZE public.{relation};" for relation in STATISTICS_RELATIONS)


def generation_sql(dataset_id, scale, seed, profile, generated_at):
    profile_json = json.dumps(dict(profile), sort_keys=True)
    context_values = _context_rows(profile, seed)
    base_list = ','.join(_quote(rel) for rel in BASE_RELATIONS)
    stats_list = ','.join(_quote(rel) for rel in STATISTICS_RELATIONS)
    groups = max(int(profile['tenants']) * 10, 1)
    if generated_at is None:
        summary_columns = "dataset_id, scale, seed, profile, table_counts, verification"
        generated_value = ""
    else:
        summary_columns = "dataset_id, scale, seed, profile, table_counts, verification, generated_at"
        generated_value = f",\n  {_quote(generated_at)}::timestamptz"
    return f"""
\\set ON_ERROR_STOP on
BEGIN;
SELECT set_config('caprls.dataset_id', {_quote(dataset_id)}, false);
TRUNCATE TABLE
  public.synthetic_dataset_summary,
  public.synthetic_context,
  public.purpose_policy,
  public.share_acl,
  public.event_log,
  public.invoice,
  public.ticket,
  public.document,
  public.group_membership,
  public.role_assignment,
  public.user_account,
  public.tenant
RESTART IDENTITY CASCADE;

DELETE FROM public.base_versions WHERE relname = ANY (ARRAY[{base_list}]);
DELETE FROM public.context_versions;
DELETE FROM public.membership_versions;

INSERT INTO public.tenant(tenant_id, region, plan)
SELECT tenant_id,
       'region_' || (1 + ((tenant_id - 1) % 10))::text,
       (ARRAY['free','team','enterprise','regulated'])[1 + ((tenant_id - 1) % 4)]
FROM generate_series(1, {int(profile['tenants'])}) AS tenant_id;

INSERT INTO public.user_account(user_id, tenant_id, clearance, home_region)
SELECT user_id,
       1 + ((user_id - 1) % {int(profile['tenants'])}) AS tenant_id,
       1 + ((user_id + {seed}) % 5),
       'region_' || (1 + ((1 + ((user_id - 1) % {int(profile['tenants'])}) - 1) % 10))::text
FROM generate_series(1, {int(profile['users'])}) AS user_id;

INSERT INTO public.role_assignment(user_id, tenant_id, role, valid_from, valid_to)
SELECT u.user_id,
       u.tenant_id,
       'role_' || (1 + ((u.user_id + r.n + {seed}) % 20))::text,
       TIMESTAMPTZ '2026-01-01 00:00:00+00',
       TIMESTAMPTZ '2027-01-01 00:00:00+00'
FROM public.user_account u
JOIN LATERAL generate_series(1, CASE (u.user_id % 4) WHEN 0 THEN 1 WHEN 1 THEN 2 WHEN 2 THEN 5 ELSE 20 END) AS r(n) ON true;

INSERT INTO public.group_membership(user_id, group_id, membership_version)
SELECT
       1 + ((edge_id - 1) % {int(profile['users'])}) AS user_id,
       1 + ((((1 + ((edge_id - 1) % {int(profile['users'])})) * 31)
         + (floor((edge_id - 1) / greatest({int(profile['users'])}, 1))::bigint * 17)
         + {seed}) % {groups}) AS group_id,
       0 AS membership_version
FROM generate_series(1, {int(profile['group_edges'])}) AS edge_id
ON CONFLICT DO NOTHING;

INSERT INTO public.document(doc_id, tenant_id, owner_id, group_id, region, class, public, secret, payload)
SELECT doc_id,
       u.tenant_id,
       u.user_id,
       1 + ((doc_id * 17 + {seed}) % {groups}) AS group_id,
       'region_' || (1 + ((u.tenant_id + doc_id) % 10))::text,
       1 + ((doc_id + {seed}) % 5),
       (doc_id % 20 = 0),
       'secret_doc_' || doc_id::text || '_seed_{seed}',
       jsonb_build_object('doc_id', doc_id, 'bucket', doc_id % 100, 'seed', {seed})
FROM generate_series(1, {int(profile['documents'])}) AS doc_id
JOIN public.user_account u ON u.user_id = 1 + ((doc_id * 13 + {seed}) % {int(profile['users'])});

INSERT INTO public.ticket(ticket_id, tenant_id, owner_id, status, priority, secret, payload)
SELECT ticket_id,
       u.tenant_id,
       u.user_id,
       (ARRAY['open','pending','closed','escalated'])[1 + (ticket_id % 4)],
       1 + ((ticket_id + {seed}) % 5),
       'secret_ticket_' || ticket_id::text || '_seed_{seed}',
       jsonb_build_object('ticket_id', ticket_id, 'queue', ticket_id % 32, 'seed', {seed})
FROM generate_series(1, {int(profile['tickets'])}) AS ticket_id
JOIN public.user_account u ON u.user_id = 1 + ((ticket_id * 7 + {seed}) % {int(profile['users'])});

INSERT INTO public.invoice(invoice_id, tenant_id, account_id, amount, region, secret)
SELECT invoice_id,
       u.tenant_id,
       u.user_id,
       ((invoice_id * 193 + {seed}) % 100000)::numeric / 100.0,
       'region_' || (1 + ((u.tenant_id + invoice_id) % 10))::text,
       'secret_invoice_' || invoice_id::text || '_seed_{seed}'
FROM generate_series(1, {int(profile['invoices'])}) AS invoice_id
JOIN public.user_account u ON u.user_id = 1 + ((invoice_id * 19 + {seed}) % {int(profile['users'])});

INSERT INTO public.event_log(event_id, tenant_id, actor_id, ts, type, payload, secret)
SELECT event_id,
       u.tenant_id,
       u.user_id,
       TIMESTAMPTZ '2026-01-01 00:00:00+00' + ((event_id % 86400) || ' seconds')::interval,
       (ARRAY['read','write','share','revoke','login'])[1 + (event_id % 5)],
       jsonb_build_object('event_id', event_id, 'object_bucket', event_id % 1000, 'seed', {seed}),
       'secret_event_' || event_id::text || '_seed_{seed}'
FROM generate_series(1, {int(profile['events'])}) AS event_id
JOIN public.user_account u ON u.user_id = 1 + ((event_id * 23 + {seed}) % {int(profile['users'])});

INSERT INTO public.share_acl(group_id, rid, relname, permission, valid_from, valid_to)
SELECT
       1 + ((((1 + ((edge_id - 1) % {int(profile['documents'])})) * 17)
         + (floor((edge_id - 1) / greatest({int(profile['documents'])}, 1))::bigint * 31)
         + {seed}) % {groups}) AS group_id,
       1 + ((edge_id - 1) % {int(profile['documents'])}) AS rid,
       'document',
       CASE WHEN edge_id % 5 = 0 THEN 'owner' ELSE 'read' END,
       TIMESTAMPTZ '2026-01-01 00:00:00+00',
       TIMESTAMPTZ '2027-01-01 00:00:00+00'
FROM generate_series(1, {int(profile['acl_edges'])}) AS edge_id
ON CONFLICT DO NOTHING;

INSERT INTO public.purpose_policy(rid, relname, purpose, allowed)
SELECT doc_id, 'document', 'purpose_' || (1 + ((doc_id + {seed}) % 8))::text, true
FROM generate_series(1, {int(profile['documents'])}) AS doc_id
ON CONFLICT DO NOTHING;

INSERT INTO public.purpose_policy(rid, relname, purpose, allowed)
SELECT invoice_id, 'invoice', 'purpose_' || (1 + ((invoice_id + {seed}) % 8))::text, true
FROM generate_series(1, {int(profile['invoices'])}) AS invoice_id
ON CONFLICT DO NOTHING;

INSERT INTO public.synthetic_context(
  ctx_hash, context_id, user_id, tenant_id, sorted_roles, sorted_group_ids,
  purpose, region, clearance, time_bucket, query_scope_id, canonical_context
)
VALUES
{context_values};

INSERT INTO public.context_versions(ctx_hash, version, canonical_context)
SELECT ctx_hash, 0, canonical_context
FROM public.synthetic_context;

INSERT INTO public.membership_versions(scope_name, version)
VALUES ('group_membership', 0);

INSERT INTO public.base_versions(relname, version)
SELECT relname, 0
FROM unnest(ARRAY[{base_list}]) AS relname
ON CONFLICT (relname) DO UPDATE SET version = EXCLUDED.version;

-- Costing is prospective and must not depend on autovacuum timing. Refresh
-- all bulk-loaded planner inputs before recording the dataset as ready.
{_analyze_relations_sql()}

INSERT INTO public.synthetic_dataset_summary({summary_columns})
SELECT
  {_quote(dataset_id)},
  {_quote(scale)},
  {seed},
  {_quote(profile_json)}::jsonb,
  (
    SELECT jsonb_object_agg(relname, n ORDER BY relname)
    FROM (
      SELECT 'tenant' AS relname, count(*) AS n FROM public.tenant
      UNION ALL SELECT 'user_account', count(*) FROM public.user_account
      UNION ALL SELECT 'role_assignment', count(*) FROM public.role_assignment
      UNION ALL SELECT 'group_membership', count(*) FROM public.group_membership
      UNION ALL SELECT 'document', count(*) FROM public.document
      UNION ALL SELECT 'ticket', count(*) FROM public.ticket
      UNION ALL SELECT 'invoice', count(*) FROM public.invoice
      UNION ALL SELECT 'event_log', count(*) FROM public.event_log
      UNION ALL SELECT 'share_acl', count(*) FROM public.share_acl
      UNION ALL SELECT 'purpose_policy', count(*) FROM public.purpose_policy
      UNION ALL SELECT 'synthetic_context', count(*) FROM public.synthetic_context
    ) counts
  ),
  jsonb_build_object(
    'document_owner_same_tenant',
      NOT EXISTS (
        SELECT 1
        FROM public.document d
        JOIN public.user_account u ON u.user_id = d.owner_id
        WHERE u.tenant_id <> d.tenant_id
      ),
    'ticket_owner_same_tenant',
      NOT EXISTS (
        SELECT 1
        FROM public.ticket t
        JOIN public.user_account u ON u.user_id = t.owner_id
        WHERE u.tenant_id <> t.tenant_id
      ),
    'share_acl_group_based',
      NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'share_acl'
          AND column_name = 'user_id'
      ),
    'context_hashes_sha256',
      NOT EXISTS (
        SELECT 1 FROM public.synthetic_context
        WHERE ctx_hash !~ '^sha256:[0-9a-f]{{64}}$'
      ),
    'base_versions_present',
      (
        SELECT count(*) = {len(BASE_RELATIONS)}
        FROM public.base_versions
        WHERE relname = ANY (ARRAY[{base_list}])
          AND version = 0
      ),
    'membership_version_present',
      (
        SELECT count(*) = 1
        FROM public.membership_versions
        WHERE scope_name = 'group_membership'
          AND version = 0
      ),
    'planner_statistics_ready',
      (
        SELECT count(*) = {len(STATISTICS_RELATIONS)}
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relname = ANY (ARRAY[{stats_list}])
          AND c.reltuples >= 0
      )
  ){generated_value};
COMMIT;
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--live-timestamp", action="store_true",
                        help="use clock_timestamp() for the summary row instead of the recorded value")
    args = parser.parse_args()
    sql = generation_sql(f"synthetic_saas_{SCALE}_seed{SEED}", SCALE, SEED, PROFILE_1E5,
                         None if args.live_timestamp else RECORDED_GENERATED_AT)
    sys.stdout.write(sql)


if __name__ == "__main__":
    main()
