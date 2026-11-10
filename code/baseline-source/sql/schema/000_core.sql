CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS public.base_versions (
  relname text PRIMARY KEY,
  version bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS public.context_versions (
  ctx_hash text PRIMARY KEY,
  version bigint NOT NULL,
  canonical_context jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS public.membership_versions (
  scope_name text PRIMARY KEY,
  version bigint NOT NULL
);

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
  policy_version bigint NOT NULL,
  membership_version bigint NOT NULL
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
  policy_version bigint NOT NULL,
  membership_version bigint NOT NULL
);

CREATE INDEX IF NOT EXISTS auth_idx_lookup
ON public.auth_idx(policy_id, user_id, ctx_hash, rid_domain_id, base_rel_oid, rid);

CREATE INDEX IF NOT EXISTS auth_idx_keyed_eq_lookup
ON public.auth_idx_keyed(policy_id, user_id, ctx_hash, key_name, key_value, rid_domain_id, base_rel_oid, rid);

CREATE INDEX IF NOT EXISTS auth_idx_keyed_bucket_lookup
ON public.auth_idx_keyed(policy_id, user_id, ctx_hash, key_name, range_bucket, rid_domain_id, base_rel_oid, rid);

CREATE TABLE IF NOT EXISTS public.caprls_audit_log (
  audit_id bigserial PRIMARY KEY,
  test_id text NOT NULL,
  phase text NOT NULL,
  rid bigint,
  observed_value text,
  role_name text NOT NULL DEFAULT current_user,
  called_at timestamptz NOT NULL DEFAULT clock_timestamp()
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

CREATE OR REPLACE FUNCTION public.caprls_audit_value(
  p_test_id text,
  p_phase text,
  p_rid bigint,
  p_observed_value text
) RETURNS boolean
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
AS $$
BEGIN
  INSERT INTO public.caprls_audit_log(test_id, phase, rid, observed_value, role_name)
  VALUES (p_test_id, p_phase, p_rid, p_observed_value, current_user);
  RETURN true;
END;
$$;

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

CREATE OR REPLACE FUNCTION public.unsafe_throw(
  run_id text,
  query_id text,
  plan_id text,
  occurrence_id text,
  rid bigint,
  secret text,
  sentinel text
) RETURNS boolean
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
AS $$
BEGIN
  IF secret = sentinel THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P8A10',
      MESSAGE = 'CAPRLS unsafe_throw observed sentinel',
      DETAIL = run_id || ':' || query_id || ':' || plan_id || ':' || occurrence_id || ':' || rid::text;
  END IF;
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
DECLARE
  expected record;
  actual_version bigint;
  v_failure_sqlstate text;
  v_failure_symbol text;
BEGIN
  FOR expected IN
    SELECT x.dep_kind, x.dep_name, x.version_at_build, x.failure_sqlstate, x.failure_symbol
    FROM jsonb_to_recordset(p_expected_versions_json)
      AS x(
        dep_kind text,
        dep_name text,
        version_at_build bigint,
        failure_sqlstate text,
        failure_symbol text
      )
  LOOP
    SELECT d.version_at_build
    INTO actual_version
    FROM public.artifact_dependencies d
    WHERE d.artifact_id = p_artifact_id
      AND d.dep_kind = expected.dep_kind
      AND d.dep_name = expected.dep_name;

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
      RAISE EXCEPTION USING
        ERRCODE = v_failure_sqlstate,
        MESSAGE = 'CAPRLS artifact validation failed',
        DETAIL = v_failure_symbol;
    END IF;
  END LOOP;
  RETURN true;
END;
$$;
