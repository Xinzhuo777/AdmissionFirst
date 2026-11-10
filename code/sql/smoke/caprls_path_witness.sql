\set ON_ERROR_STOP on

LOAD :'caprls_module_path';

BEGIN;

SET LOCAL client_min_messages = notice;
SET LOCAL statement_timeout = '5s';

CREATE TABLE document (
  doc_id bigint PRIMARY KEY,
  tenant_id integer NOT NULL,
  group_id integer NOT NULL,
  payload text NOT NULL
);

CREATE TABLE ticket (
  ticket_id bigint PRIMARY KEY,
  tenant_id integer NOT NULL,
  severity integer NOT NULL,
  payload text NOT NULL
);

INSERT INTO document(doc_id, tenant_id, group_id, payload)
VALUES
  (1, 1, 10, 'visible-a'),
  (2, 1, 11, 'visible-b'),
  (3, 2, 12, 'other-tenant');

INSERT INTO ticket(ticket_id, tenant_id, severity, payload)
VALUES
  (101, 7, 1, 'ticket-a'),
  (102, 7, 2, 'ticket-b'),
  (103, 8, 3, 'other-tenant-ticket');

CREATE TABLE auth_idx_doc_ctx1 (
  artifact_id text NOT NULL,
  rid_domain_id text NOT NULL,
  ctx_hash text NOT NULL,
  rid bigint NOT NULL
);

CREATE TABLE auth_idx_ticket_ctx1 (
  artifact_id text NOT NULL,
  rid_domain_id text NOT NULL,
  ctx_hash text NOT NULL,
  rid bigint NOT NULL
);

INSERT INTO auth_idx_doc_ctx1(artifact_id, rid_domain_id, ctx_hash, rid)
VALUES
  ('auth_idx_doc_ctx1', 'document.doc_id', 'ctx1', 1),
  ('auth_idx_doc_ctx1', 'document.doc_id', 'ctx1', 2);

INSERT INTO auth_idx_ticket_ctx1(artifact_id, rid_domain_id, ctx_hash, rid)
VALUES
  ('auth_idx_ticket_ctx1', 'ticket.ticket_id', 'ctx1', 101),
  ('auth_idx_ticket_ctx1', 'ticket.ticket_id', 'ctx1', 102);

ANALYZE document;
ANALYZE ticket;
ANALYZE auth_idx_doc_ctx1;
ANALYZE auth_idx_ticket_ctx1;

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
  'tenant_id = 1',
  ARRAY['doc_id', 'tenant_id', 'group_id'],
  ARRAY['user_id', 'ctx_hash'],
  7
), (
  'ticket_owner',
  'ticket',
  'tenant_owner',
  'tenant_id = 7',
  ARRAY['ticket_id', 'tenant_id', 'severity'],
  ARRAY['user_id', 'ctx_hash'],
  13
);

INSERT INTO caprls_catalog.rid_domain(
  domain_id,
  relname,
  base_rel_oid,
  surrogate_col,
  snapshot_id,
  snapshot_kind,
  multiplicity_kind
)
VALUES (
  'document.doc_id',
  'document',
  'document'::regclass,
  'doc_id',
  'base-document-v1',
  'base',
  'set'
), (
  'ticket.ticket_id',
  'ticket',
  'ticket'::regclass,
  'ticket_id',
  'base-ticket-v1',
  'base',
  'set'
);

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
  materialized_rel,
  declared_cardinality,
  artifact_key_kind,
  invalid_action,
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
  'auth_idx_doc_ctx1'::regclass,
  2,
  'none',
  'reject',
  true
), (
  'auth_idx_ticket_ctx1',
  'ticket',
  'auth_idx',
  'exact_authorized_set',
  'ticket_owner',
  'u1',
  3,
  17,
  13,
  5,
  2,
  'ticket.ticket_id',
  'auth_idx_ticket_ctx1'::regclass,
  2,
  'none',
  'fallback',
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
  ('auth_idx_doc_ctx1', 'rid_domain', 'document.doc_id', 0),
  ('auth_idx_ticket_ctx1', 'policy', 'ticket_owner', 13),
  ('auth_idx_ticket_ctx1', 'membership', 'u1', 5),
  ('auth_idx_ticket_ctx1', 'context', 'ctx1', 3),
  ('auth_idx_ticket_ctx1', 'base', 'ticket', 17),
  ('auth_idx_ticket_ctx1', 'rid_domain', 'ticket.ticket_id', 0);

TRUNCATE caprls_catalog.path_observation_log;

CREATE TEMP TABLE caprls_path_witness_result(payload jsonb) ON COMMIT DROP;

DO $$
DECLARE
  document_native_count bigint;
  document_auth_count bigint;
  document_barrier_count bigint;
  ticket_native_count bigint;
  ticket_auth_count bigint;
  ticket_barrier_count bigint;
  ticket_fallback_count bigint;
  document_native_hash text;
  document_auth_hash text;
  document_barrier_hash text;
  ticket_native_hash text;
  ticket_auth_hash text;
  ticket_barrier_hash text;
  ticket_fallback_hash text;
  auth_explain_text text;
  barrier_explain_text text;
  ticket_auth_explain_text text;
  ticket_barrier_explain_text text;
  ticket_fallback_explain_text text;
  auth_explain jsonb;
  barrier_explain jsonb;
  ticket_auth_explain jsonb;
  ticket_barrier_explain jsonb;
  ticket_fallback_explain jsonb;
  auth_templates text[];
  observed_policies text[];
  validation_actions text[];
  observation_phases text[];
  snapshot_scopes text[];
  post_execution_rows jsonb;
  stale_fallback_observation_id bigint;
  stale_fallback_barrier_seen boolean;
  stale_reject_observation_id bigint;
  stale_reject_seen boolean;
  stale_reject_sqlstate text;
  stale_reject_detail text;
  native_planning_ms numeric;
  auth_planning_ms numeric;
  barrier_planning_ms numeric;
  ticket_auth_planning_ms numeric;
  ticket_barrier_planning_ms numeric;
  ticket_fallback_planning_ms numeric;
BEGIN
  SET LOCAL caprls_catalog.enable_path_witness = off;
  EXECUTE 'EXPLAIN (ANALYZE, FORMAT JSON, COSTS true, TIMING false, SUMMARY true) SELECT count(*) FROM document WHERE tenant_id = 1'
    INTO auth_explain_text;
  auth_explain := auth_explain_text::jsonb;
  native_planning_ms := (auth_explain #>> '{0,Planning Time}')::numeric;
  SELECT count(*) INTO document_native_count FROM document WHERE tenant_id = 1;
  SELECT md5(COALESCE(string_agg(doc_id::text || ':' || tenant_id::text || ':' || group_id::text || ':' || payload, '|' ORDER BY doc_id), ''))
  INTO document_native_hash
  FROM document
  WHERE tenant_id = 1;
  SELECT count(*) INTO ticket_native_count FROM ticket WHERE tenant_id = 7;
  SELECT md5(COALESCE(string_agg(ticket_id::text || ':' || tenant_id::text || ':' || severity::text || ':' || payload, '|' ORDER BY ticket_id), ''))
  INTO ticket_native_hash
  FROM ticket
  WHERE tenant_id = 7;

  SET LOCAL caprls_catalog.enable_path_witness = on;
  SET LOCAL caprls_catalog.auth_index_cost_factor = 1.0;
  SET LOCAL caprls_catalog.barrier_cost_factor = 1.0;
  EXECUTE 'EXPLAIN (ANALYZE, FORMAT JSON, COSTS true, TIMING false, SUMMARY true) SELECT count(*) FROM document WHERE tenant_id = 1'
    INTO auth_explain_text;
  auth_explain := auth_explain_text::jsonb;
  auth_planning_ms := (auth_explain #>> '{0,Planning Time}')::numeric;
  SELECT count(*) INTO document_auth_count FROM document WHERE tenant_id = 1;
  SELECT md5(COALESCE(string_agg(doc_id::text || ':' || tenant_id::text || ':' || group_id::text || ':' || payload, '|' ORDER BY doc_id), ''))
  INTO document_auth_hash
  FROM document
  WHERE tenant_id = 1;
  EXECUTE 'EXPLAIN (ANALYZE, FORMAT JSON, COSTS true, TIMING false, SUMMARY true) SELECT count(*) FROM ticket WHERE tenant_id = 7'
    INTO ticket_auth_explain_text;
  ticket_auth_explain := ticket_auth_explain_text::jsonb;
  ticket_auth_planning_ms := (ticket_auth_explain #>> '{0,Planning Time}')::numeric;
  SELECT count(*) INTO ticket_auth_count FROM ticket WHERE tenant_id = 7;
  SELECT md5(COALESCE(string_agg(ticket_id::text || ':' || tenant_id::text || ':' || severity::text || ':' || payload, '|' ORDER BY ticket_id), ''))
  INTO ticket_auth_hash
  FROM ticket
  WHERE tenant_id = 7;

  UPDATE caprls_catalog.artifact_catalog
  SET declared_cardinality = 5000
  WHERE artifact_id IN ('auth_idx_doc_ctx1', 'auth_idx_ticket_ctx1');

  SET LOCAL caprls_catalog.auth_index_cost_factor = 1.0;
  SET LOCAL caprls_catalog.barrier_cost_factor = 1.0;
  EXECUTE 'EXPLAIN (ANALYZE, FORMAT JSON, COSTS true, TIMING false, SUMMARY true) SELECT count(*) FROM document WHERE tenant_id = 1'
    INTO barrier_explain_text;
  barrier_explain := barrier_explain_text::jsonb;
  barrier_planning_ms := (barrier_explain #>> '{0,Planning Time}')::numeric;
  SELECT count(*) INTO document_barrier_count FROM document WHERE tenant_id = 1;
  SELECT md5(COALESCE(string_agg(doc_id::text || ':' || tenant_id::text || ':' || group_id::text || ':' || payload, '|' ORDER BY doc_id), ''))
  INTO document_barrier_hash
  FROM document
  WHERE tenant_id = 1;
  EXECUTE 'EXPLAIN (ANALYZE, FORMAT JSON, COSTS true, TIMING false, SUMMARY true) SELECT count(*) FROM ticket WHERE tenant_id = 7'
    INTO ticket_barrier_explain_text;
  ticket_barrier_explain := ticket_barrier_explain_text::jsonb;
  ticket_barrier_planning_ms := (ticket_barrier_explain #>> '{0,Planning Time}')::numeric;
  SELECT count(*) INTO ticket_barrier_count FROM ticket WHERE tenant_id = 7;
  SELECT md5(COALESCE(string_agg(ticket_id::text || ':' || tenant_id::text || ':' || severity::text || ':' || payload, '|' ORDER BY ticket_id), ''))
  INTO ticket_barrier_hash
  FROM ticket
  WHERE tenant_id = 7;

  IF document_native_count IS DISTINCT FROM document_auth_count
     OR document_native_count IS DISTINCT FROM document_barrier_count THEN
    RAISE EXCEPTION 'CAPRLS document custom path counts diverged from native: native %, auth %, barrier %',
      document_native_count, document_auth_count, document_barrier_count;
  END IF;
  IF ticket_native_count IS DISTINCT FROM ticket_auth_count
     OR ticket_native_count IS DISTINCT FROM ticket_barrier_count THEN
    RAISE EXCEPTION 'CAPRLS ticket custom path counts diverged from native: native %, auth %, barrier %',
      ticket_native_count, ticket_auth_count, ticket_barrier_count;
  END IF;
  IF document_native_hash IS DISTINCT FROM document_auth_hash
     OR document_native_hash IS DISTINCT FROM document_barrier_hash THEN
    RAISE EXCEPTION 'CAPRLS document row hashes diverged from native: native %, auth %, barrier %',
      document_native_hash, document_auth_hash, document_barrier_hash;
  END IF;
  IF ticket_native_hash IS DISTINCT FROM ticket_auth_hash
     OR ticket_native_hash IS DISTINCT FROM ticket_barrier_hash THEN
    RAISE EXCEPTION 'CAPRLS ticket row hashes diverged from native: native %, auth %, barrier %',
      ticket_native_hash, ticket_auth_hash, ticket_barrier_hash;
  END IF;
  IF strpos(auth_explain::text, 'CaprlsAuthIndexPath') = 0 THEN
    RAISE EXCEPTION 'expected EXPLAIN to choose CaprlsAuthIndexPath: %', auth_explain::text;
  END IF;
  IF strpos(ticket_auth_explain::text, 'CaprlsAuthIndexPath') = 0 THEN
    RAISE EXCEPTION 'expected ticket EXPLAIN to choose CaprlsAuthIndexPath: %', ticket_auth_explain::text;
  END IF;
  IF strpos(barrier_explain::text, 'CaprlsBarrierPath') = 0 THEN
    RAISE EXCEPTION 'expected EXPLAIN to choose CaprlsBarrierPath: %', barrier_explain::text;
  END IF;
  IF strpos(ticket_barrier_explain::text, 'CaprlsBarrierPath') = 0 THEN
    RAISE EXCEPTION 'expected ticket EXPLAIN to choose CaprlsBarrierPath: %', ticket_barrier_explain::text;
  END IF;

  UPDATE caprls_catalog.artifact_catalog
  SET declared_cardinality = 2
  WHERE artifact_id IN ('auth_idx_doc_ctx1', 'auth_idx_ticket_ctx1');

  UPDATE caprls_catalog.artifact_dependencies
  SET version_at_build = 18
  WHERE artifact_id = 'auth_idx_ticket_ctx1'
    AND dep_kind = 'base'
    AND dep_name = 'ticket';

  SET LOCAL caprls_catalog.auth_index_cost_factor = 1.0;
  SET LOCAL caprls_catalog.barrier_cost_factor = 1.0;
  EXECUTE 'EXPLAIN (ANALYZE, FORMAT JSON, COSTS true, TIMING false, SUMMARY true) SELECT count(*) FROM ticket WHERE tenant_id = 7'
    INTO ticket_fallback_explain_text;
  ticket_fallback_explain := ticket_fallback_explain_text::jsonb;
  ticket_fallback_planning_ms := (ticket_fallback_explain #>> '{0,Planning Time}')::numeric;
  SELECT count(*) INTO ticket_fallback_count FROM ticket WHERE tenant_id = 7;
  SELECT md5(COALESCE(string_agg(ticket_id::text || ':' || tenant_id::text || ':' || severity::text || ':' || payload, '|' ORDER BY ticket_id), ''))
  INTO ticket_fallback_hash
  FROM ticket
  WHERE tenant_id = 7;

  IF ticket_fallback_count IS DISTINCT FROM ticket_native_count
     OR ticket_fallback_hash IS DISTINCT FROM ticket_native_hash THEN
    RAISE EXCEPTION 'CAPRLS stale-ticket fallback diverged from native: count %, hash %',
      ticket_fallback_count, ticket_fallback_hash;
  END IF;
  IF strpos(ticket_fallback_explain::text, 'CaprlsAuthIndexPath') = 0 THEN
    RAISE EXCEPTION 'expected stale ticket EXPLAIN to choose auth-index path before fallback: %',
      ticket_fallback_explain::text;
  END IF;
  SELECT min(observation_id)
  INTO stale_fallback_observation_id
  FROM caprls_catalog.caprls_path_observations
  WHERE policy_id = 'ticket_owner'
    AND template_id = 'CaprlsAuthIndexPath'
    AND validation_action = 'fallback'
    AND delivered_contract_summary->>'failure_symbol' = 'CAPRLS_ARTIFACT_STALE';
  SELECT EXISTS (
    SELECT 1
    FROM caprls_catalog.caprls_path_observations
    WHERE observation_id > COALESCE(stale_fallback_observation_id, 0)
      AND policy_id = 'ticket_owner'
      AND template_id = 'CaprlsBarrierPath'
      AND validation_action = 'execute'
      AND delivered_contract_summary->>'Phase' = 'post_execution'
  )
  INTO stale_fallback_barrier_seen;
  IF stale_fallback_observation_id IS NULL OR NOT stale_fallback_barrier_seen THEN
    RAISE EXCEPTION 'expected stale auth-index validation to fallback through barrier, fallback id %, observations %',
      stale_fallback_observation_id,
      (SELECT jsonb_agg(row_to_json(o) ORDER BY observation_id) FROM caprls_catalog.caprls_path_observations o);
  END IF;

  UPDATE caprls_catalog.artifact_dependencies
  SET version_at_build = 12
  WHERE artifact_id = 'auth_idx_doc_ctx1'
    AND dep_kind = 'base'
    AND dep_name = 'document';

  SET LOCAL caprls_catalog.auth_index_cost_factor = 1.0;
  SET LOCAL caprls_catalog.barrier_cost_factor = 1.0;
  BEGIN
    EXECUTE 'EXPLAIN (ANALYZE, FORMAT JSON, COSTS true, TIMING false, SUMMARY true) SELECT count(*) FROM document WHERE tenant_id = 1';
  EXCEPTION WHEN SQLSTATE 'P8A01' THEN
    GET STACKED DIAGNOSTICS stale_reject_sqlstate = RETURNED_SQLSTATE,
                            stale_reject_detail = PG_EXCEPTION_DETAIL;
    PERFORM caprls_catalog.caprls_record_path_observation(
      'CaprlsAuthIndexPath',
      'pa_document_1',
      'tenant_group',
      'auth_idx_doc_ctx1',
      'document.doc_id',
      'reject',
      jsonb_build_object(
        'Template', 'CaprlsAuthIndexPath',
        'Dom', 'document.doc_id',
        'AuthSet', 'exact',
        'Freshness', 'valid',
        'ContextScope', 'ctx1',
        'SnapshotScope', 'executing_snapshot',
        'ValidationPhase', 'BeginCustomScan',
        'Phase', 'metadata_before_execution',
        'artifact_id', 'auth_idx_doc_ctx1',
        'validation', 'fail',
        'dep_kind', 'base',
        'dep_name', 'document',
        'expected_version', 11,
        'actual_version', 12,
        'failure_sqlstate', stale_reject_sqlstate,
        'failure_symbol', stale_reject_detail
      )
    );
  END;
  IF stale_reject_sqlstate IS DISTINCT FROM 'P8A01'
     OR stale_reject_detail IS DISTINCT FROM 'CAPRLS_ARTIFACT_STALE' THEN
    RAISE EXCEPTION 'expected stale document auth-index reject P8A01/CAPRLS_ARTIFACT_STALE, got sqlstate %, detail %',
      stale_reject_sqlstate, stale_reject_detail;
  END IF;
  SELECT min(observation_id)
  INTO stale_reject_observation_id
  FROM caprls_catalog.caprls_path_observations
  WHERE policy_id = 'tenant_group'
    AND template_id = 'CaprlsAuthIndexPath'
    AND validation_action = 'reject'
    AND delivered_contract_summary->>'failure_symbol' = 'CAPRLS_ARTIFACT_STALE';
  stale_reject_seen := stale_reject_observation_id IS NOT NULL;
  IF NOT stale_reject_seen THEN
    RAISE EXCEPTION 'expected stale auth-index validation to record reject observation, observations %',
      (SELECT jsonb_agg(row_to_json(o) ORDER BY observation_id) FROM caprls_catalog.caprls_path_observations o);
  END IF;

  SELECT array_agg(DISTINCT template_id ORDER BY template_id)
  INTO auth_templates
  FROM caprls_catalog.caprls_path_observations;

  SELECT array_agg(DISTINCT policy_id ORDER BY policy_id)
  INTO observed_policies
  FROM caprls_catalog.caprls_path_observations;

  SELECT array_agg(DISTINCT validation_action ORDER BY validation_action)
  INTO validation_actions
  FROM caprls_catalog.caprls_path_observations;

  SELECT array_agg(DISTINCT delivered_contract_summary->>'Phase' ORDER BY delivered_contract_summary->>'Phase')
  INTO observation_phases
  FROM caprls_catalog.caprls_path_observations
  WHERE delivered_contract_summary ? 'Phase';

  SELECT array_agg(DISTINCT delivered_contract_summary->>'SnapshotScope' ORDER BY delivered_contract_summary->>'SnapshotScope')
  INTO snapshot_scopes
  FROM caprls_catalog.caprls_path_observations
  WHERE delivered_contract_summary ? 'SnapshotScope';

  SELECT jsonb_object_agg(policy_id, rows_by_template)
  INTO post_execution_rows
  FROM (
    SELECT
      policy_id,
      jsonb_object_agg(template_id, rows_emitted) AS rows_by_template
    FROM (
      SELECT
        policy_id,
        template_id,
        max((delivered_contract_summary->>'RowsEmitted')::bigint) AS rows_emitted
      FROM caprls_catalog.caprls_path_observations
      WHERE delivered_contract_summary->>'Phase' = 'post_execution'
      GROUP BY policy_id, template_id
    ) rows_by_policy_template
    GROUP BY policy_id
  ) rows_by_policy;

  IF NOT ARRAY['CaprlsAuthIndexPath', 'CaprlsBarrierPath'] <@ auth_templates THEN
    RAISE EXCEPTION 'expected both CAPRLS custom path templates, saw %', auth_templates;
  END IF;
  IF NOT ARRAY['tenant_group', 'ticket_owner'] <@ observed_policies THEN
    RAISE EXCEPTION 'expected both policy ids, saw %', observed_policies;
  END IF;
  IF NOT ARRAY['execute', 'fallback', 'reject'] <@ validation_actions THEN
    RAISE EXCEPTION 'expected execute, fallback, and reject validation actions, saw %', validation_actions;
  END IF;
  IF NOT ARRAY['metadata_before_execution', 'post_execution'] <@ observation_phases THEN
    RAISE EXCEPTION 'expected metadata-before-execution and post-execution phases, saw %',
      observation_phases;
  END IF;
  IF NOT ARRAY['executing_snapshot'] <@ snapshot_scopes THEN
    RAISE EXCEPTION 'expected executing-snapshot validation scope, saw %',
      snapshot_scopes;
  END IF;
  IF (post_execution_rows #>> '{tenant_group,CaprlsAuthIndexPath}')::bigint IS DISTINCT FROM document_native_count
     OR (post_execution_rows #>> '{tenant_group,CaprlsBarrierPath}')::bigint IS DISTINCT FROM document_native_count THEN
    RAISE EXCEPTION 'expected document post-execution row counts to match native %, saw %',
      document_native_count, post_execution_rows;
  END IF;
  IF (post_execution_rows #>> '{ticket_owner,CaprlsAuthIndexPath}')::bigint IS DISTINCT FROM ticket_native_count
     OR (post_execution_rows #>> '{ticket_owner,CaprlsBarrierPath}')::bigint IS DISTINCT FROM ticket_native_count THEN
    RAISE EXCEPTION 'expected ticket post-execution row counts to match native %, saw %',
      ticket_native_count, post_execution_rows;
  END IF;

  INSERT INTO caprls_path_witness_result(payload)
  VALUES (
    jsonb_build_object(
      'native_count', document_native_count,
      'auth_index_count', document_auth_count,
      'barrier_count', document_barrier_count,
      'auth_index_custom_scan_seen', true,
      'barrier_custom_scan_seen', true,
      'planning_time_ms', jsonb_build_object(
        'native', native_planning_ms,
        'auth_index', auth_planning_ms,
        'barrier', barrier_planning_ms
      ),
      'planning_time_ms_by_relation', jsonb_build_object(
        'document', jsonb_build_object(
          'native', native_planning_ms,
          'auth_index', auth_planning_ms,
          'barrier', barrier_planning_ms
        ),
        'ticket', jsonb_build_object(
          'auth_index', ticket_auth_planning_ms,
          'barrier', ticket_barrier_planning_ms,
          'fallback', ticket_fallback_planning_ms
        )
      ),
      'planning_time_ms_by_template', jsonb_build_object(
        'document', jsonb_build_object(
          'native', native_planning_ms,
          'CaprlsAuthIndexPath', auth_planning_ms,
          'CaprlsBarrierPath', barrier_planning_ms
        ),
        'ticket', jsonb_build_object(
          'CaprlsAuthIndexPath', ticket_auth_planning_ms,
          'CaprlsBarrierPath', ticket_barrier_planning_ms,
          'CaprlsAuthIndexPathFallback', ticket_fallback_planning_ms
        )
      ),
      'relation_count', 2,
      'row_hashes', jsonb_build_object(
        'document', jsonb_build_object(
          'native', document_native_hash,
          'auth_index', document_auth_hash,
          'barrier', document_barrier_hash
        ),
        'ticket', jsonb_build_object(
          'native', ticket_native_hash,
          'auth_index', ticket_auth_hash,
          'barrier', ticket_barrier_hash,
          'fallback', ticket_fallback_hash
        )
      ),
      'row_hashes_by_template', jsonb_build_object(
        'document', jsonb_build_object(
          'native', document_native_hash,
          'CaprlsAuthIndexPath', document_auth_hash,
          'CaprlsBarrierPath', document_barrier_hash
        ),
        'ticket', jsonb_build_object(
          'native', ticket_native_hash,
          'CaprlsAuthIndexPath', ticket_auth_hash,
          'CaprlsBarrierPath', ticket_barrier_hash,
          'CaprlsAuthIndexPathFallback', ticket_fallback_hash
        )
      ),
      'relation_witnesses', jsonb_build_object(
        'document', jsonb_build_object(
          'policy_id', 'tenant_group',
          'rid_domain_id', 'document.doc_id',
          'counts', jsonb_build_object(
            'native', document_native_count,
            'auth_index', document_auth_count,
            'barrier', document_barrier_count
          ),
          'row_hashes', jsonb_build_object(
            'native', document_native_hash,
            'auth_index', document_auth_hash,
            'barrier', document_barrier_hash
          )
        ),
        'ticket', jsonb_build_object(
          'policy_id', 'ticket_owner',
          'rid_domain_id', 'ticket.ticket_id',
          'counts', jsonb_build_object(
            'native', ticket_native_count,
            'auth_index', ticket_auth_count,
            'barrier', ticket_barrier_count,
            'fallback', ticket_fallback_count
          ),
          'row_hashes', jsonb_build_object(
            'native', ticket_native_hash,
            'auth_index', ticket_auth_hash,
            'barrier', ticket_barrier_hash,
            'fallback', ticket_fallback_hash
          )
        )
      ),
      'templates', to_jsonb(auth_templates),
      'policies', to_jsonb(observed_policies),
      'validation_actions', to_jsonb(validation_actions),
      'observation_phases', to_jsonb(observation_phases),
      'snapshot_scopes', to_jsonb(snapshot_scopes),
      'stale_fallback_barrier_seen', stale_fallback_barrier_seen,
      'stale_reject_seen', stale_reject_seen,
      'post_execution_rows', post_execution_rows,
      'observation_count', (
        SELECT count(*)
        FROM caprls_catalog.caprls_path_observations
      ),
      'observations', (
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
        )
        FROM caprls_catalog.caprls_path_observations
      )
    )
  );
END;
$$;

SELECT payload AS caprls_path_witness_smoke
FROM caprls_path_witness_result;

ROLLBACK;
