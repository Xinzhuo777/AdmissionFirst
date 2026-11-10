\set ON_ERROR_STOP on

BEGIN;

SET LOCAL client_min_messages = notice;

INSERT INTO caprls_catalog.policy_catalog(
  policy_id,
  relname,
  policy_kind,
  exact_sql,
  required_attrs,
  required_ctx,
  policy_version
)
VALUES (
  'tenant_group',
  'document',
  'tenant_group',
  'SELECT 1',
  ARRAY['doc_id', 'tenant_id', 'group_id'],
  ARRAY['user_id', 'ctx_hash'],
  7
);

INSERT INTO caprls_catalog.rid_domain(
  domain_id,
  relname,
  surrogate_col,
  snapshot_id,
  snapshot_kind,
  multiplicity_kind
)
VALUES (
  'document.doc_id',
  'document',
  'doc_id',
  'base-document-v1',
  'base',
  'set'
);

INSERT INTO caprls_catalog.function_safety(
  function_schema,
  function_name,
  function_signature,
  safety_label,
  pg_volatility,
  leakproof,
  parallel_safety,
  trusted,
  notes
)
VALUES
  ('pg_catalog', 'int8eq', 'bigint,bigint', 'trusted_leakproof', 'i', true, 's', true, 'built-in equality/range path source'),
  ('public', 'unsafe_log', 'text,text,text,text,bigint,text', 'unsafe_log', 'v', false, 'u', false, 'direct-observation positive control');

INSERT INTO caprls_catalog.artifact_catalog(
  artifact_id,
  relname,
  artifact_type,
  target_kind,
  policy_id,
  user_scope,
  context_version,
  base_version,
  policy_version,
  membership_version,
  trusted_state_version,
  rid_domain_id,
  artifact_key_kind,
  valid
)
VALUES (
  'auth_idx_doc_ctx1',
  'document',
  'auth_idx',
  'exact_authorized_set',
  'tenant_group',
  'u1',
  3,
  11,
  7,
  5,
  2,
  'document.doc_id',
  'none',
  true
);

INSERT INTO caprls_catalog.artifact_dependencies(
  artifact_id,
  dep_kind,
  dep_name,
  version_at_build
)
VALUES
  ('auth_idx_doc_ctx1', 'policy', 'tenant_group', 7),
  ('auth_idx_doc_ctx1', 'membership', 'u1', 5),
  ('auth_idx_doc_ctx1', 'context', 'ctx1', 3),
  ('auth_idx_doc_ctx1', 'base', 'document', 11),
  ('auth_idx_doc_ctx1', 'rid_domain', 'document.doc_id', 0);

SELECT caprls_catalog.caprls_assert_artifact_valid(
  'auth_idx_doc_ctx1',
  '[
    {"dep_kind": "policy", "dep_name": "tenant_group", "version_at_build": 7},
    {"dep_kind": "membership", "dep_name": "u1", "version_at_build": 5},
    {"dep_kind": "context", "dep_name": "ctx1", "version_at_build": 3},
    {"dep_kind": "base", "dep_name": "document", "version_at_build": 11},
    {"dep_kind": "rid_domain", "dep_name": "document.doc_id", "version_at_build": 0}
  ]'::jsonb,
  'execute',
  'CaprlsAuthIndexPath',
  'pa_document_1',
  '{"Dom":"document.doc_id","AuthSet":"exact","Freshness":"valid","ContextScope":"ctx1"}'::jsonb
) AS validation_passed;

SELECT caprls_catalog.caprls_assert_artifact_valid(
  'auth_idx_doc_ctx1',
  '[
    {
      "dep_kind": "context",
      "dep_name": "ctx1",
      "version_at_build": 4,
      "failure_sqlstate": "P8A02",
      "failure_symbol": "CAPRLS_CONTEXT_MISMATCH"
    }
  ]'::jsonb,
  'fallback',
  'CaprlsAuthIndexPath',
  'pa_document_1',
  '{"Dom":"document.doc_id","AuthSet":"exact","Freshness":"stale","ContextScope":"ctx1"}'::jsonb
) AS validation_fallback;

SELECT caprls_catalog.caprls_assert_artifact_valid(
  'auth_idx_doc_ctx1',
  '[
    {
      "dep_kind": "rid_domain",
      "dep_name": "document.doc_id",
      "version_at_build": 1,
      "failure_sqlstate": "P8A03",
      "failure_symbol": "CAPRLS_RID_MISMATCH"
    }
  ]'::jsonb,
  'reject',
  'CaprlsAuthIndexPath',
  'pa_document_1',
  '{"Dom":"document.doc_id","RIDMatProps":"mismatch"}'::jsonb
) AS validation_reject;

DO $$
DECLARE
  observed_sqlstate text;
  observed_detail text;
BEGIN
  BEGIN
    PERFORM caprls_catalog.caprls_assert_artifact_valid(
      'auth_idx_doc_ctx1',
      '[
        {
          "dep_kind": "rid_domain",
          "dep_name": "document.doc_id",
          "version_at_build": 1,
          "failure_sqlstate": "P8A03",
          "failure_symbol": "CAPRLS_RID_MISMATCH"
        }
      ]'::jsonb,
      'execute',
      'CaprlsAuthIndexPath',
      'pa_document_1',
      '{"Dom":"document.doc_id","RIDMatProps":"mismatch"}'::jsonb
    );
  EXCEPTION WHEN SQLSTATE 'P8A03' THEN
    GET STACKED DIAGNOSTICS observed_sqlstate = RETURNED_SQLSTATE, observed_detail = PG_EXCEPTION_DETAIL;
  END;

  IF observed_sqlstate IS DISTINCT FROM 'P8A03' OR observed_detail IS DISTINCT FROM 'CAPRLS_RID_MISMATCH' THEN
    RAISE EXCEPTION 'expected CAPRLS_RID_MISMATCH, got sqlstate %, detail %', observed_sqlstate, observed_detail;
  END IF;
END;
$$;

SELECT jsonb_agg(
  jsonb_build_object(
    'template_id', template_id,
    'policy_access_occurrence_id', policy_access_occurrence_id,
    'policy_id', policy_id,
    'artifact_id', artifact_id,
    'rid_domain_id', rid_domain_id,
    'validation_action', validation_action,
    'delivered_contract_summary', delivered_contract_summary
  )
  ORDER BY observation_id
) AS caprls_catalog_smoke
FROM caprls_catalog.caprls_path_observations;

ROLLBACK;
