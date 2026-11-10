-- caprls_catalog--1.0.sql
-- SQL-level CAPRLS catalog and transaction-local artifact validation witness.

CREATE SCHEMA IF NOT EXISTS caprls_catalog;

CREATE TABLE IF NOT EXISTS caprls_catalog.policy_catalog (
  policy_id text PRIMARY KEY,
  relname text NOT NULL,
  policy_kind text NOT NULL,
  exact_sql text,
  guard_sql text,
  residual_sql text,
  required_attrs text[] NOT NULL DEFAULT ARRAY[]::text[],
  required_ctx text[] NOT NULL DEFAULT ARRAY[]::text[],
  policy_version bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (policy_kind IN ('exact', 'guard_residual', 'purpose_region', 'tenant_group', 'tenant_owner', 'custom'))
);

CREATE TABLE IF NOT EXISTS caprls_catalog.rid_domain (
  domain_id text PRIMARY KEY,
  relname text NOT NULL,
  base_rel_oid oid,
  surrogate_col text NOT NULL,
  snapshot_id text NOT NULL DEFAULT 'default',
  snapshot_kind text NOT NULL DEFAULT 'base',
  multiplicity_kind text NOT NULL DEFAULT 'set',
  materialized_rel_id text,
  lineage_tag_kind text NOT NULL DEFAULT 'none',
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (snapshot_kind IN ('base', 'materialized', 'snapshot', 'logical')),
  CHECK (multiplicity_kind IN ('set', 'bag', 'unknown')),
  CHECK (lineage_tag_kind IN ('none', 'union_branch', 'join_side', 'custom'))
);

CREATE TABLE IF NOT EXISTS caprls_catalog.function_safety (
  function_schema text NOT NULL DEFAULT 'public',
  function_name text NOT NULL,
  function_signature text NOT NULL,
  safety_label text NOT NULL,
  pg_volatility char(1) NOT NULL,
  leakproof boolean NOT NULL DEFAULT false,
  parallel_safety char(1) NOT NULL,
  trusted boolean NOT NULL DEFAULT false,
  notes text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (function_schema, function_name, function_signature),
  CHECK (safety_label IN ('trusted_leakproof', 'nonleakproof', 'unsafe_log', 'unsafe_throw', 'expensive_policy_udf', 'unknown')),
  CHECK (pg_volatility IN ('i', 's', 'v')),
  CHECK (parallel_safety IN ('s', 'r', 'u'))
);

CREATE TABLE IF NOT EXISTS caprls_catalog.policy_versions (
  policy_id text PRIMARY KEY,
  version bigint NOT NULL CHECK (version >= 0)
);

CREATE TABLE IF NOT EXISTS caprls_catalog.membership_versions (
  scope_key text PRIMARY KEY,
  version bigint NOT NULL CHECK (version >= 0)
);

CREATE TABLE IF NOT EXISTS caprls_catalog.base_versions (
  relname text PRIMARY KEY,
  version bigint NOT NULL CHECK (version >= 0)
);

CREATE TABLE IF NOT EXISTS caprls_catalog.context_versions (
  ctx_hash text PRIMARY KEY,
  version bigint NOT NULL CHECK (version >= 0),
  canonical_context jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS caprls_catalog.artifact_catalog (
  artifact_id text PRIMARY KEY,
  relname text NOT NULL,
  artifact_type text NOT NULL,
  target_kind text NOT NULL,
  policy_id text NOT NULL,
  user_scope text,
  tenant_scope text,
  role_scope text,
  group_scope_hash text,
  purpose_scope text,
  time_window tstzrange,
  context_version bigint,
  query_scope_hash text,
  base_version bigint,
  policy_version bigint,
  membership_version bigint,
  trusted_state_version bigint,
  rid_domain_id text NOT NULL,
  materialized_rel regclass,
  declared_cardinality bigint CHECK (declared_cardinality IS NULL OR declared_cardinality >= 0),
  artifact_key_kind text NOT NULL DEFAULT 'none',
  artifact_key_cols text[] NOT NULL DEFAULT ARRAY[]::text[],
  invalid_action text NOT NULL DEFAULT 'fallback',
  valid boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_validated_at timestamptz,
  CHECK (artifact_type IN ('auth_idx', 'auth_idx_keyed', 'mav', 'guard_candidate', 'hybrid_rid_source', 'custom')),
  CHECK (target_kind IN ('exact_authorized_set', 'complete_candidate_set', 'ordinary_rid_source', 'custom')),
  CHECK (artifact_key_kind IN ('none', 'equality', 'range_bucket')),
  CHECK (invalid_action IN ('reject', 'fallback')),
  FOREIGN KEY (policy_id) REFERENCES caprls_catalog.policy_catalog(policy_id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (rid_domain_id) REFERENCES caprls_catalog.rid_domain(domain_id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE IF NOT EXISTS caprls_catalog.artifact_dependencies (
  artifact_id text NOT NULL REFERENCES caprls_catalog.artifact_catalog(artifact_id) ON DELETE CASCADE,
  dep_kind text NOT NULL,
  dep_name text NOT NULL,
  version_at_build bigint NOT NULL CHECK (version_at_build >= 0),
  PRIMARY KEY (artifact_id, dep_kind, dep_name),
  CHECK (dep_kind IN (
    'policy',
    'membership',
    'context',
    'context_scope',
    'context_hash',
    'base',
    'base_relation',
    'rid_domain',
    'rid_domain_id',
    'base_rel_oid',
    'rid_props',
    'trusted_state',
    'toctou',
    'execution_snapshot',
    'custom'
  ))
);

CREATE TABLE IF NOT EXISTS caprls_catalog.path_observation_log (
  observation_id bigserial PRIMARY KEY,
  observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  txid bigint NOT NULL DEFAULT txid_current(),
  template_id text NOT NULL,
  policy_access_occurrence_id text NOT NULL,
  policy_id text NOT NULL,
  artifact_id text,
  rid_domain_id text,
  validation_action text NOT NULL,
  delivered_contract_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  CHECK (validation_action IN ('execute', 'reject', 'fallback', 'refresh', 'replan'))
);

CREATE INDEX IF NOT EXISTS artifact_catalog_policy_idx
ON caprls_catalog.artifact_catalog(policy_id, relname, artifact_type, valid);

CREATE INDEX IF NOT EXISTS artifact_catalog_rid_domain_idx
ON caprls_catalog.artifact_catalog(rid_domain_id, valid);

CREATE INDEX IF NOT EXISTS path_observation_policy_idx
ON caprls_catalog.path_observation_log(policy_id, policy_access_occurrence_id, observed_at);

CREATE OR REPLACE FUNCTION caprls_catalog.caprls_record_path_observation(
  p_template_id text,
  p_policy_access_occurrence_id text,
  p_policy_id text,
  p_artifact_id text,
  p_rid_domain_id text,
  p_validation_action text,
  p_delivered_contract_summary jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = caprls_catalog, pg_temp
AS $$
DECLARE
  v_observation_id bigint;
BEGIN
  IF p_validation_action NOT IN ('execute', 'reject', 'fallback', 'refresh', 'replan') THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P8A00',
      MESSAGE = 'CAPRLS invalid validation action',
      DETAIL = p_validation_action;
  END IF;

  INSERT INTO path_observation_log(
    template_id,
    policy_access_occurrence_id,
    policy_id,
    artifact_id,
    rid_domain_id,
    validation_action,
    delivered_contract_summary
  )
  VALUES (
    COALESCE(p_template_id, 'unknown-template'),
    COALESCE(p_policy_access_occurrence_id, 'unknown-occurrence'),
    COALESCE(p_policy_id, 'unknown-policy'),
    p_artifact_id,
    p_rid_domain_id,
    p_validation_action,
    COALESCE(p_delivered_contract_summary, '{}'::jsonb)
  )
  RETURNING observation_id INTO v_observation_id;

  RAISE NOTICE
    'CAPRLS template=% occurrence=% policy=% artifact=% rid_domain=% validation=% contract=%',
    COALESCE(p_template_id, 'unknown-template'),
    COALESCE(p_policy_access_occurrence_id, 'unknown-occurrence'),
    COALESCE(p_policy_id, 'unknown-policy'),
    COALESCE(p_artifact_id, 'none'),
    COALESCE(p_rid_domain_id, 'none'),
    p_validation_action,
    COALESCE(p_delivered_contract_summary, '{}'::jsonb)::text;

  RETURN v_observation_id;
END;
$$;

CREATE OR REPLACE FUNCTION caprls_catalog.caprls_assert_artifact_valid(
  p_artifact_id text,
  p_expected_versions_json jsonb,
  p_validation_action text DEFAULT 'reject',
  p_template_id text DEFAULT NULL,
  p_policy_access_occurrence_id text DEFAULT NULL,
  p_delivered_contract_summary jsonb DEFAULT '{}'::jsonb
) RETURNS boolean
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = caprls_catalog, pg_temp
AS $$
DECLARE
  expected record;
  actual_version bigint;
  v_policy_id text;
  v_rid_domain_id text;
  v_catalog_valid boolean;
  v_failure_sqlstate text;
  v_failure_symbol text;
  v_effective_action text;
  v_failure_summary jsonb;
BEGIN
  IF p_validation_action NOT IN ('execute', 'reject', 'fallback', 'refresh', 'replan') THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P8A00',
      MESSAGE = 'CAPRLS invalid validation action',
      DETAIL = p_validation_action;
  END IF;

  SELECT artifact_catalog.policy_id, artifact_catalog.rid_domain_id, artifact_catalog.valid
  INTO v_policy_id, v_rid_domain_id, v_catalog_valid
  FROM artifact_catalog
  WHERE artifact_catalog.artifact_id = p_artifact_id;

  IF NOT FOUND THEN
    v_failure_sqlstate := 'P8A05';
    v_failure_symbol := 'CAPRLS_ARTIFACT_UNKNOWN';
    v_failure_summary := jsonb_build_object(
      'artifact_id', p_artifact_id,
      'validation', 'fail',
      'failure_sqlstate', v_failure_sqlstate,
      'failure_symbol', v_failure_symbol
    );
    v_effective_action := CASE WHEN p_validation_action = 'execute' THEN 'reject' ELSE p_validation_action END;
    PERFORM caprls_record_path_observation(
      p_template_id,
      p_policy_access_occurrence_id,
      'unknown-policy',
      p_artifact_id,
      NULL,
      v_effective_action,
      COALESCE(p_delivered_contract_summary, '{}'::jsonb) || v_failure_summary
    );
    IF p_validation_action = 'execute' THEN
      RAISE EXCEPTION USING
        ERRCODE = v_failure_sqlstate,
        MESSAGE = 'CAPRLS artifact validation failed',
        DETAIL = v_failure_symbol;
    END IF;
    RETURN false;
  END IF;

  IF v_catalog_valid IS DISTINCT FROM true THEN
    v_failure_sqlstate := 'P8A01';
    v_failure_symbol := 'CAPRLS_ARTIFACT_INVALIDATED';
    v_failure_summary := jsonb_build_object(
      'artifact_id', p_artifact_id,
      'validation', 'fail',
      'failure_sqlstate', v_failure_sqlstate,
      'failure_symbol', v_failure_symbol
    );
    v_effective_action := CASE WHEN p_validation_action = 'execute' THEN 'reject' ELSE p_validation_action END;
    PERFORM caprls_record_path_observation(
      p_template_id,
      p_policy_access_occurrence_id,
      v_policy_id,
      p_artifact_id,
      v_rid_domain_id,
      v_effective_action,
      COALESCE(p_delivered_contract_summary, '{}'::jsonb) || v_failure_summary
    );
    IF p_validation_action = 'execute' THEN
      RAISE EXCEPTION USING
        ERRCODE = v_failure_sqlstate,
        MESSAGE = 'CAPRLS artifact validation failed',
        DETAIL = v_failure_symbol;
    END IF;
    RETURN false;
  END IF;

  FOR expected IN
    SELECT x.dep_kind, x.dep_name, x.version_at_build, x.failure_sqlstate, x.failure_symbol
    FROM jsonb_to_recordset(COALESCE(p_expected_versions_json, '[]'::jsonb))
      AS x(
        dep_kind text,
        dep_name text,
        version_at_build bigint,
        failure_sqlstate text,
        failure_symbol text
      )
  LOOP
    SELECT artifact_dependencies.version_at_build
    INTO actual_version
    FROM artifact_dependencies
    WHERE artifact_dependencies.artifact_id = p_artifact_id
      AND artifact_dependencies.dep_kind = expected.dep_kind
      AND artifact_dependencies.dep_name = expected.dep_name;

    IF actual_version IS DISTINCT FROM expected.version_at_build THEN
      v_failure_sqlstate := COALESCE(
        expected.failure_sqlstate,
        CASE
          WHEN expected.dep_kind IN ('context', 'context_scope', 'context_hash') THEN 'P8A02'
          WHEN expected.dep_kind IN ('rid_domain', 'rid_domain_id', 'base_rel_oid', 'base_relation', 'rid_props') THEN 'P8A03'
          WHEN expected.dep_kind IN ('toctou', 'execution_snapshot') THEN 'P8A04'
          ELSE 'P8A01'
        END
      );
      v_failure_symbol := COALESCE(
        expected.failure_symbol,
        CASE v_failure_sqlstate
          WHEN 'P8A02' THEN 'CAPRLS_CONTEXT_MISMATCH'
          WHEN 'P8A03' THEN 'CAPRLS_RID_MISMATCH'
          WHEN 'P8A04' THEN 'CAPRLS_TOCTOU_FAIL'
          ELSE 'CAPRLS_ARTIFACT_STALE'
        END
      );
      v_failure_summary := jsonb_build_object(
        'artifact_id', p_artifact_id,
        'validation', 'fail',
        'dep_kind', expected.dep_kind,
        'dep_name', expected.dep_name,
        'expected_version', expected.version_at_build,
        'actual_version', actual_version,
        'failure_sqlstate', v_failure_sqlstate,
        'failure_symbol', v_failure_symbol
      );
      v_effective_action := CASE WHEN p_validation_action = 'execute' THEN 'reject' ELSE p_validation_action END;
      PERFORM caprls_record_path_observation(
        p_template_id,
        p_policy_access_occurrence_id,
        v_policy_id,
        p_artifact_id,
        v_rid_domain_id,
        v_effective_action,
        COALESCE(p_delivered_contract_summary, '{}'::jsonb) || v_failure_summary
      );
      IF p_validation_action = 'execute' THEN
        RAISE EXCEPTION USING
          ERRCODE = v_failure_sqlstate,
          MESSAGE = 'CAPRLS artifact validation failed',
          DETAIL = v_failure_symbol;
      END IF;
      RETURN false;
    END IF;
  END LOOP;

  PERFORM caprls_record_path_observation(
    p_template_id,
    p_policy_access_occurrence_id,
    v_policy_id,
    p_artifact_id,
    v_rid_domain_id,
    'execute',
    COALESCE(p_delivered_contract_summary, '{}'::jsonb) || jsonb_build_object(
      'artifact_id', p_artifact_id,
      'validation', 'pass'
    )
  );

  UPDATE artifact_catalog
  SET last_validated_at = clock_timestamp()
  WHERE artifact_catalog.artifact_id = p_artifact_id;

  RETURN true;
END;
$$;

CREATE OR REPLACE VIEW caprls_catalog.caprls_path_observations AS
SELECT
  observation_id,
  observed_at,
  txid,
  template_id,
  policy_access_occurrence_id,
  policy_id,
  artifact_id,
  rid_domain_id,
  validation_action,
  delivered_contract_summary
FROM caprls_catalog.path_observation_log;

COMMENT ON SCHEMA caprls_catalog IS 'CAPRLS policy, artifact, RID-domain, function-safety, and validation witness metadata.';
COMMENT ON TABLE caprls_catalog.policy_catalog IS 'Declared policy metadata available before planning.';
COMMENT ON TABLE caprls_catalog.artifact_catalog IS 'Authorization artifact scope, version, key, materialization, and RID-domain metadata.';
COMMENT ON TABLE caprls_catalog.rid_domain IS 'RID-domain and materialization identity metadata used by contract checks.';
COMMENT ON TABLE caprls_catalog.function_safety IS 'Internal function-safety labels mapped to PostgreSQL volatility/leakproof/parallel properties.';
COMMENT ON TABLE caprls_catalog.path_observation_log IS 'Transaction-local path validation observations for EXPLAIN/log witness runs.';
COMMENT ON FUNCTION caprls_catalog.caprls_assert_artifact_valid(text, jsonb, text, text, text, jsonb) IS 'Validates artifact dependency versions in the current transaction and records execute/reject/fallback/refresh/replan observations.';
COMMENT ON FUNCTION caprls_catalog.caprls_record_path_observation(text, text, text, text, text, text, jsonb) IS 'Records and emits CAPRLS template, occurrence, policy, artifact, RID-domain, validation action, and delivered-contract summary.';
