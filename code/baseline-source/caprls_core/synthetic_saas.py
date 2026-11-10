"""Synthetic SaaS dataset generation."""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
    POLICY_ENFORCEMENT_ROLE,
)

import hashlib
import json
import platform
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

import yaml

from .manifest_validator import file_sha256
from .postgres_runner import PostgresEnv, PostgresError, init_db, run_psql_command, run_psql_file
from .result_schema import RAW_SCHEMA_VERSION, validate_raw_run_record


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

# Experiment clusters disable autovacuum. Every bulk-loaded relation that can
# feed prospective EXPLAIN costing therefore needs an explicit statistics
# refresh before planner measurements begin.
STATISTICS_RELATIONS = (*BASE_RELATIONS, "synthetic_context")


@dataclass(frozen=True)
class DatasetGenerationResult:
    dataset_id: str
    scale: str
    seed: int
    profile: Mapping[str, int]
    table_counts: Mapping[str, int]
    verification: Mapping[str, Any]
    raw_result_path: Optional[Path]


def load_scale_profile(root: Path, scale: str) -> Dict[str, int]:
    path = root / "datasets" / "manifests" / "synthetic_saas_scales.yaml"
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    profiles = data.get("synthetic_saas_scale_profiles") or {}
    profile = profiles.get(scale)
    if not isinstance(profile, Mapping):
        known = ", ".join(sorted(str(key) for key in profiles))
        raise PostgresError(f"unknown synthetic_saas scale {scale!r}; known scales: {known}")
    return {str(key): int(value) for key, value in profile.items()}


def _canonical_context(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _context_rows(profile: Mapping[str, int], seed: int) -> str:
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


def _quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _analyze_relations_sql() -> str:
    return "\n".join(f"ANALYZE public.{relation};" for relation in STATISTICS_RELATIONS)


def _generation_sql(dataset_id: str, scale: str, seed: int, profile: Mapping[str, int]) -> str:
    profile_json = json.dumps(dict(profile), sort_keys=True)
    context_values = _context_rows(profile, seed)
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

DELETE FROM public.base_versions WHERE relname = ANY (ARRAY[{','.join(_quote(rel) for rel in BASE_RELATIONS)}]);
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
         + {seed}) % {max(int(profile['tenants']) * 10, 1)}) AS group_id,
       0 AS membership_version
FROM generate_series(1, {int(profile['group_edges'])}) AS edge_id
ON CONFLICT DO NOTHING;

INSERT INTO public.document(doc_id, tenant_id, owner_id, group_id, region, class, public, secret, payload)
SELECT doc_id,
       u.tenant_id,
       u.user_id,
       1 + ((doc_id * 17 + {seed}) % {max(int(profile['tenants']) * 10, 1)}) AS group_id,
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
         + {seed}) % {max(int(profile['tenants']) * 10, 1)}) AS group_id,
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
FROM unnest(ARRAY[{','.join(_quote(rel) for rel in BASE_RELATIONS)}]) AS relname
ON CONFLICT (relname) DO UPDATE SET version = EXCLUDED.version;

-- Costing is prospective and must not depend on autovacuum timing. Refresh
-- all bulk-loaded planner inputs before recording the dataset as ready.
{_analyze_relations_sql()}

INSERT INTO public.synthetic_dataset_summary(dataset_id, scale, seed, profile, table_counts, verification)
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
        WHERE relname = ANY (ARRAY[{','.join(_quote(rel) for rel in BASE_RELATIONS)}])
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
          AND c.relname = ANY (ARRAY[{','.join(_quote(rel) for rel in STATISTICS_RELATIONS)}])
          AND c.reltuples >= 0
      )
  );
COMMIT;
"""


def _write_temp_sql(sql: str) -> Path:
    tmp = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".sql", delete=False)
    with tmp:
        tmp.write(sql)
    return Path(tmp.name)


def _load_summary(dataset_id: str, pg_env: PostgresEnv) -> Dict[str, Any]:
    sql = (
        "SELECT jsonb_build_object("
        "'dataset_id', dataset_id, "
        "'scale', scale, "
        "'seed', seed, "
        "'profile', profile, "
        "'table_counts', table_counts, "
        "'verification', verification"
        ")::text FROM public.synthetic_dataset_summary "
        f"WHERE dataset_id = {_quote(dataset_id)};"
    )
    payload = run_psql_command(sql, pg_env)
    if not payload:
        raise PostgresError(f"missing synthetic_dataset_summary for {dataset_id}")
    return json.loads(payload)


def _assert_summary(profile: Mapping[str, int], summary: Mapping[str, Any]) -> None:
    table_counts = summary["table_counts"]
    verification = summary["verification"]
    expected = {
        "tenant": profile["tenants"],
        "user_account": profile["users"],
        "group_membership": profile["group_edges"],
        "document": profile["documents"],
        "ticket": profile["tickets"],
        "invoice": profile["invoices"],
        "event_log": profile["events"],
        "share_acl": profile["acl_edges"],
        "purpose_policy": profile["documents"] + profile["invoices"],
        "synthetic_context": profile["contexts"],
    }
    for table, count in expected.items():
        actual = int(table_counts.get(table, -1))
        if actual != int(count):
            raise PostgresError(f"{table}: expected {count}, got {actual}")
    for check, passed in verification.items():
        if passed is not True:
            raise PostgresError(f"dataset verification failed: {check}")


def _result_hash(summary: Mapping[str, Any]) -> str:
    payload = json.dumps(summary, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _git_commit(root: Path) -> str:
    import subprocess

    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(root),
        text=True,
        capture_output=True,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def _raw_result_record(
    root: Path,
    dataset_id: str,
    scale: str,
    seed: int,
    profile: Mapping[str, int],
    summary: Mapping[str, Any],
    elapsed_ms: float,
    manifest_hash: str,
    pg_version: str,
) -> Dict[str, Any]:
    digest = _result_hash(summary)
    row_count = sum(int(value) for value in summary["table_counts"].values())
    return {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": f"DATASET_{dataset_id}",
        "manifest_id": "synthetic_saas_generator_v1",
        "manifest_hash": manifest_hash,
        "experiment": "DATASET",
        "stage": "generator_smoke" if scale == "1e3" else "generator_main_seed",
        "run_kind": "normal_mode",
        "dataset": {"name": "synthetic_saas", "scale": scale, "seed": seed},
        "query": {
            "query_id": "synthetic_saas_generate",
            "path": "datasets/manifests/synthetic_saas_scales.yaml",
            "params": {"scale": scale, "seed": seed},
        },
        "policy": {
            "policy_id": "synthetic_saas_policy_catalog",
            "policy_version": 0,
            "policy_sql_manifest_hash": manifest_hash,
        },
        "context": {
            "context_id": "synthetic_saas_generator",
            "ctx_hash": digest,
        },
        "mode": ADMISSION_FIRST_MODE,
        "template": {
            "template_id": "synthetic_saas_generator_v1",
            "alternative": "SyntheticSaaSGenerator",
        },
        "template_applicability": {"status": "applicable", "reason": None},
        "template_oracle": {
            "eligible_for_template_oracle": False,
            "template_oracle_exclusion_reason": "dataset_generation_not_template_candidate",
        },
        "evaluation_role": POLICY_ENFORCEMENT_ROLE,
        "pg": {
            "version": pg_version,
            "gucs": {"jit": "off", "max_parallel_workers_per_gather": "0"},
        },
        "versions": {
            "policy": {"synthetic_saas_policy_catalog": 0},
            "membership": {"all": 0},
            "context": {"generated_contexts": 0},
            "trusted_state": {"schema": 1},
            "base": {rel: 0 for rel in BASE_RELATIONS},
            "artifacts": {},
        },
        "planner": {
            "level": "dataset-generator",
            "planning_time_ms": 0.0,
            "generated_templates": 0,
            "rejected_templates": 0,
            "costed_templates": 0,
            "rejection_reasons": {},
            "chosen_estimated_cost": 0.0,
            "chosen_rank_vs_template_oracle": None,
            "local_feature_vector": None,
            "parent_requirement_vector": None,
            "candidates": [],
            "disabled_components": [],
            "delivered_sigma": {},
        },
        "static_verifier": {
            "status": "pass",
            "plan_hash": manifest_hash,
            "explain_path": None,
            "reasons": [],
        },
        "artifact_validation": {
            "status": "not_applicable",
            "action": "execute",
            "expected_action": "execute",
            "failure_sqlstate": None,
            "failure_symbol": None,
            "same_snapshot": False,
            "isolation_level": None,
        },
        "runtime_audit": {
            "status": "pass",
            "audit_path": None,
            "udf_calls": 0,
            "unauthorized_observations": 0,
            "client_errors": 0,
            "client_notices": 0,
        },
        "sql": {
            "emitted_sql_path": "sql/schema/010_synthetic_saas.sql",
            "emitted_sql_hash": file_sha256(root / "sql" / "schema" / "010_synthetic_saas.sql"),
            "normalized_sql_hash": manifest_hash,
        },
        "oracle_check": {
            "status": "match",
            "oracle_kind": "dataset_count_and_invariant_check",
            "set_diff_left": 0,
            "set_diff_right": 0,
            "known_invalid_accepted": False,
            "known_valid_rejected": False,
        },
        "timing_ms": {
            "planning": 0.0,
            "execution": elapsed_ms,
            "verification": 0.0,
            "total": elapsed_ms,
        },
        "result": {
            "row_count": row_count,
            "result_hash": digest,
        },
        "dataset_generation": {
            "dataset_id": dataset_id,
            "profile": dict(profile),
            "table_counts": summary["table_counts"],
            "verification": summary["verification"],
        },
        "pg_metrics": {
            "shared_read_blocks": 0,
            "shared_hit_blocks": 0,
            "temp_read_blocks": 0,
            "temp_written_blocks": 0,
        },
        "counts": {
            "policy_evals": 0,
            "residual_checks": 0,
            "candidate_rows": 0,
            "authorized_rows": int(summary["table_counts"].get("document", 0)),
            "artifact_lookups": 0,
            "base_fetches": row_count,
        },
        "artifact_cost": {
            "query_only_ms": elapsed_ms,
            "build_ms": 0.0,
            "refresh_ms": 0.0,
            "storage_bytes": 0,
            "indexes_built": [],
            "artifact_key_encoding_version": "artifact_key_encoding_v1",
            "amortization_model": "query_only",
        },
        "implementation": {
            "git_commit": _git_commit(root),
            "docker_image_digest": "not_containerized",
            "python_version": platform.python_version(),
            "planner_language": "python",
        },
        "status": "pass",
        "failure": None,
    }


def generate_synthetic_saas(
    root: Path,
    pg_env: PostgresEnv,
    scale: str,
    seed: int,
    verify: bool = False,
    output_dir: Optional[Path] = None,
) -> DatasetGenerationResult:
    profile = load_scale_profile(root, scale)
    dataset_id = f"synthetic_saas_{scale}_seed{seed}"
    init_db(root, pg_env)
    run_psql_file(root / "sql" / "schema" / "010_synthetic_saas.sql", pg_env)
    manifest_hash = file_sha256(root / "datasets" / "manifests" / "synthetic_saas_scales.yaml")
    pg_version = run_psql_command("SHOW server_version;", pg_env)
    sql_path = _write_temp_sql(_generation_sql(dataset_id, scale, seed, profile))
    started = time.monotonic()
    try:
        run_psql_file(sql_path, pg_env)
    finally:
        sql_path.unlink(missing_ok=True)
    elapsed_ms = (time.monotonic() - started) * 1000.0
    summary = _load_summary(dataset_id, pg_env)
    if verify:
        _assert_summary(profile, summary)

    raw_result_path = None
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        raw_result_path = output_dir / f"{dataset_id}.json"
        record = _raw_result_record(
            root=root,
            dataset_id=dataset_id,
            scale=scale,
            seed=seed,
            profile=profile,
            summary=summary,
            elapsed_ms=elapsed_ms,
            manifest_hash=manifest_hash,
            pg_version=pg_version,
        )
        issues = validate_raw_run_record(record)
        if issues:
            rendered = ", ".join(f"{issue.path}: {issue.message}" for issue in issues)
            raise PostgresError(f"generated dataset raw result failed schema validation: {rendered}")
        raw_result_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return DatasetGenerationResult(
        dataset_id=dataset_id,
        scale=scale,
        seed=seed,
        profile=profile,
        table_counts={key: int(value) for key, value in summary["table_counts"].items()},
        verification=summary["verification"],
        raw_result_path=raw_result_path,
    )
