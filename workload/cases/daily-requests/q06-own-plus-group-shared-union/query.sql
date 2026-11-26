/* caprls_native_rls_policy_fingerprint: tenant_id,owner_id,public */

WITH auth AS MATERIALIZED (
  SELECT d.doc_id, d.owner_id, d.doc_id AS __rid
  FROM public.document d
  WHERE true
),
branch_tagged AS MATERIALIZED (
  SELECT d.doc_id AS branch_rid, 'own'::text AS branch_tag
  FROM auth d
  WHERE d.owner_id = '90'::bigint
  UNION ALL
  SELECT d.doc_id AS branch_rid, 'shared'::text AS branch_tag
  FROM auth d
  JOIN public.share_acl a
    ON a.rid = d.doc_id AND a.relname = 'document'
  WHERE a.permission IN ('read', 'owner')
)
SELECT count(DISTINCT branch_rid)
FROM branch_tagged
