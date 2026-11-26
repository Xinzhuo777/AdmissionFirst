BEGIN ISOLATION LEVEL REPEATABLE READ;
SET LOCAL search_path TO pg_catalog, public;
SET LOCAL row_security = on;
DO $$
BEGIN
  IF to_regclass('public.e10_state_mav_fa7631907e699336') IS NOT NULL THEN
    RAISE EXCEPTION 'E10 state relation already exists';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.artifact_dependencies
    WHERE artifact_id = 'e10-state:E10_Q8_stale_dashboard_mav:ctx_000001:fa7631907e699336'
  ) THEN
    RAISE EXCEPTION 'E10 state artifact identity already exists';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM public.synthetic_context context
    JOIN public.context_versions version
      ON version.ctx_hash = context.ctx_hash
     AND version.canonical_context = context.canonical_context
    WHERE context.context_id = 'ctx_000001'
      AND context.ctx_hash = 'sha256:f7dd134078a8f32da2a54ade0a7c9acc07f5a053877183ed253cc6907ee9cb26'
      AND context.user_id::text = '90'
      AND context.canonical_context = '{"clearance":"3","purpose":"purpose_2","query_scope_id":"scope_2","region":"region_2","sorted_group_ids":["843","860","877","894","911"],"sorted_roles":["role_2","role_3"],"tenant_id":"90","time_bucket":"2026-01-01T00:00:00Z","user_id":"90"}'::jsonb
      AND version.version = 0
  ) THEN
    RAISE EXCEPTION 'E10 target context changed before state materialization';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.synthetic_context context
    JOIN public.context_versions version
      ON version.ctx_hash = context.ctx_hash
     AND version.canonical_context = context.canonical_context
    WHERE context.context_id = 'ctx_000001'
      AND context.ctx_hash = 'sha256:f7dd134078a8f32da2a54ade0a7c9acc07f5a053877183ed253cc6907ee9cb26'
      AND context.user_id::text = '90'
      AND context.canonical_context = '{"clearance":"3","purpose":"purpose_2","query_scope_id":"scope_2","region":"region_2","sorted_group_ids":["843","860","877","894","911"],"sorted_roles":["role_2","role_3"],"tenant_id":"90","time_bucket":"2026-01-01T00:00:00Z","user_id":"90"}'::jsonb
      AND version.version = 0
  ) THEN
    RAISE EXCEPTION 'E10 build context changed before state materialization';
  END IF;

  IF (SELECT count(*) FROM public.base_versions WHERE relname = 'document') <> 1 THEN
    RAISE EXCEPTION 'E10 base epoch is missing or ambiguous';
  END IF;
  IF (
    SELECT count(*)
    FROM public.membership_versions
    WHERE scope_name = 'group_membership'
  ) <> 1 THEN
    RAISE EXCEPTION 'E10 membership epoch is missing or ambiguous';
  END IF;
END;
$$;
CREATE TEMP TABLE e10_state_base_backup ON COMMIT DROP AS
SELECT document.doc_id AS rid, document.payload
FROM public.document document
ORDER BY document.doc_id
LIMIT 1;
CREATE TEMP TABLE e10_state_membership_witness(user_id bigint, group_id bigint, membership_version bigint, witness_rid bigint, group_grant_count bigint) ON COMMIT DROP;
DO $$
BEGIN
  IF 'base_epoch_advanced' = 'base_epoch_advanced'
     AND (SELECT count(*) FROM e10_state_base_backup) <> 1 THEN
    RAISE EXCEPTION 'E10 base backup cardinality is not one';
  END IF;
  IF 'base_epoch_advanced' = 'membership_epoch_advanced'
     AND (
       (SELECT count(*) FROM e10_state_membership_witness) <> 1
       OR (SELECT group_grant_count FROM e10_state_membership_witness) <> 1
     ) THEN
    RAISE EXCEPTION 'E10 membership witness cardinality is not one';
  END IF;
END;
$$;
CREATE TABLE public.e10_state_mav_fa7631907e699336 (
  rid bigint PRIMARY KEY,
  doc_id bigint GENERATED ALWAYS AS (rid) STORED NOT NULL UNIQUE,
  tenant_id bigint NOT NULL,
  sort_key text NOT NULL
);
INSERT INTO public.artifact_dependencies(
  artifact_id, dep_kind, dep_name, version_at_build
)
VALUES
('e10-state:E10_Q8_stale_dashboard_mav:ctx_000001:fa7631907e699336', 'artifact_kind', 'mav', 0),
('e10-state:E10_Q8_stale_dashboard_mav:ctx_000001:fa7631907e699336', 'artifact_relation', 'public.e10_state_mav_fa7631907e699336', 'public.e10_state_mav_fa7631907e699336'::regclass::oid::bigint),
('e10-state:E10_Q8_stale_dashboard_mav:ctx_000001:fa7631907e699336', 'base', 'document', (SELECT version FROM public.base_versions WHERE relname = 'document')),
('e10-state:E10_Q8_stale_dashboard_mav:ctx_000001:fa7631907e699336', 'base_relation_oid', 'public.document', 'public.document'::regclass::oid::bigint),
('e10-state:E10_Q8_stale_dashboard_mav:ctx_000001:fa7631907e699336', 'context_scope', 'sha256:f7dd134078a8f32da2a54ade0a7c9acc07f5a053877183ed253cc6907ee9cb26', (SELECT version FROM public.context_versions WHERE ctx_hash = 'sha256:f7dd134078a8f32da2a54ade0a7c9acc07f5a053877183ed253cc6907ee9cb26')),
('e10-state:E10_Q8_stale_dashboard_mav:ctx_000001:fa7631907e699336', 'membership', 'group_membership', (SELECT version FROM public.membership_versions WHERE scope_name = 'group_membership')),
('e10-state:E10_Q8_stale_dashboard_mav:ctx_000001:fa7631907e699336', 'policy', 'tenant_group', 0),
('e10-state:E10_Q8_stale_dashboard_mav:ctx_000001:fa7631907e699336', 'principal', '90', 0),
('e10-state:E10_Q8_stale_dashboard_mav:ctx_000001:fa7631907e699336', 'rid_domain', 'document.doc_id', 0);
INSERT INTO public.e10_state_mav_fa7631907e699336(rid, tenant_id, sort_key)
SELECT d.doc_id,
       d.tenant_id,
       d.doc_id::text
FROM public.document d
WHERE (d.tenant_id = 90 OR d.owner_id = 90 OR d.public = true OR EXISTS (SELECT 1 FROM share_acl a JOIN group_membership gm ON gm.group_id = a.group_id WHERE a.rid = d.doc_id AND a.relname = 'document' AND gm.user_id = 90 AND a.permission IN ('read','owner') AND TIMESTAMPTZ '2026-06-01 00:00:00+00' BETWEEN a.valid_from AND a.valid_to));
SELECT jsonb_build_object(
  'case_query_id', 'E10_Q8_stale_dashboard_mav',
  'state_kind', 'base_epoch_advanced',
  'artifact_id', 'e10-state:E10_Q8_stale_dashboard_mav:ctx_000001:fa7631907e699336',
  'physical_relation', 'public.e10_state_mav_fa7631907e699336',
  'artifact_absent_before', true,
  'physical_relation_absent_before', true,
  'base_version', (
    SELECT version FROM public.base_versions WHERE relname = 'document'
  ),
  'membership_version', (
    SELECT version FROM public.membership_versions
    WHERE scope_name = 'group_membership'
  ),
  'target_context', jsonb_build_object(
    'context_id', 'ctx_000001',
    'ctx_hash', 'sha256:f7dd134078a8f32da2a54ade0a7c9acc07f5a053877183ed253cc6907ee9cb26',
    'principal_id', '90',
    'canonical_context', '{"clearance":"3","purpose":"purpose_2","query_scope_id":"scope_2","region":"region_2","sorted_group_ids":["843","860","877","894","911"],"sorted_roles":["role_2","role_3"],"tenant_id":"90","time_bucket":"2026-01-01T00:00:00Z","user_id":"90"}'::jsonb,
    'version', 0
  ),
  'build_context', jsonb_build_object(
    'context_id', 'ctx_000001',
    'ctx_hash', 'sha256:f7dd134078a8f32da2a54ade0a7c9acc07f5a053877183ed253cc6907ee9cb26',
    'principal_id', '90',
    'canonical_context', '{"clearance":"3","purpose":"purpose_2","query_scope_id":"scope_2","region":"region_2","sorted_group_ids":["843","860","877","894","911"],"sorted_roles":["role_2","role_3"],"tenant_id":"90","time_bucket":"2026-01-01T00:00:00Z","user_id":"90"}'::jsonb,
    'version', 0
  ),
  'base_row', (
    SELECT jsonb_build_object('rid', rid, 'payload', payload)
    FROM e10_state_base_backup
  ),
  'membership_witness', (
    SELECT jsonb_build_object(
      'user_id', user_id,
      'group_id', group_id,
      'membership_version', membership_version,
      'witness_rid', witness_rid,
      'group_grant_count', group_grant_count
    )
    FROM e10_state_membership_witness
  )
)::text;
COMMIT;

BEGIN ISOLATION LEVEL REPEATABLE READ;
SET LOCAL search_path TO pg_catalog, public;
DO $$
BEGIN
  IF (SELECT version FROM public.base_versions WHERE relname = 'document')
     IS DISTINCT FROM 0 THEN
    RAISE EXCEPTION 'E10 base epoch changed before mutation';
  END IF;
  IF (
    SELECT payload FROM public.document WHERE doc_id = 1
  ) IS DISTINCT FROM '{"bucket":1,"doc_id":1,"seed":52}'::jsonb THEN
    RAISE EXCEPTION 'E10 base recovery row changed before mutation';
  END IF;
END;
$$;
DO $$
DECLARE
  affected_rows integer;
BEGIN
  UPDATE public.document
  SET payload = jsonb_set(
    payload,
    '{caprls_state_epoch}',
    to_jsonb('sha256:5c139e11c2e42e62841086538a7eda82fccbf0878abc5cb5e04c364cf3b25a4d'::text),
    true
  )
  WHERE doc_id = 1;
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'E10 base mutation count is not one';
  END IF;
  UPDATE public.base_versions
  SET version = 1
  WHERE relname = 'document'
    AND version = 0;
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'E10 base epoch mutation count is not one';
  END IF;
END;
$$;
DO $$
BEGIN
  IF (SELECT version FROM public.base_versions WHERE relname = 'document')
     IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'E10 base epoch did not advance';
  END IF;
END;
$$;
COMMIT;
