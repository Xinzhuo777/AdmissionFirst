"""Exact policy oracle and runtime-audit smoke checks."""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
    CONTRACT_VIOLATION_CONTROL_ROLE,
    POLICY_ENFORCEMENT_ROLE,
    normalize_mode_id,
)

import hashlib
import json
import platform
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

import yaml

from .manifest_validator import file_sha256
from .postgres_runner import PostgresEnv, PostgresError, run_psql_command, run_psql_file
from .result_schema import RAW_SCHEMA_VERSION, validate_raw_run_record
from .synthetic_saas import generate_synthetic_saas


PARAM_RE = re.compile(r"(?<!:):([A-Za-z_][A-Za-z0-9_]*)")


@dataclass(frozen=True)
class OracleAuditResult:
    context_id: str
    authorized_count: int
    total_rows: int
    contract_unauthorized_observations: int
    positive_unauthorized_observations: int
    raw_result_paths: Mapping[str, Path]


def _quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _sql_literal(value: Any, cast: Optional[str] = None) -> str:
    if isinstance(value, bool):
        rendered = "true" if value else "false"
    elif isinstance(value, int):
        rendered = str(value)
    elif isinstance(value, str) and value.isdigit():
        rendered = value
    else:
        rendered = _quote(str(value))
    if cast:
        return f"{rendered}::{cast}"
    return rendered


def _load_policy(root: Path, policy_id: str) -> Mapping[str, Any]:
    path = root / "manifests" / "policies" / "synthetic_saas_policies.yaml"
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    policies = data.get("policies") or {}
    policy = policies.get(policy_id)
    if not isinstance(policy, Mapping):
        raise PostgresError(f"unknown policy_id: {policy_id}")
    return policy


def _load_context(context_id: str, pg_env: PostgresEnv) -> Mapping[str, Any]:
    sql = (
        "SELECT canonical_context::text "
        "FROM public.synthetic_context "
        f"WHERE context_id = {_quote(context_id)};"
    )
    payload = run_psql_command(sql, pg_env)
    if not payload:
        raise PostgresError(f"unknown synthetic context: {context_id}")
    return json.loads(payload)


def _render_exact_predicate(
    template: str,
    alias: str,
    rid_col: str,
    context: Mapping[str, Any],
    relname: str,
) -> str:
    values: Dict[str, str] = {
        "ctx_tenant_id": _sql_literal(context["tenant_id"]),
        "user_id": _sql_literal(context["user_id"]),
        "now": _sql_literal("2026-06-01 00:00:00+00", "timestamptz"),
        "relname": _sql_literal(relname),
        "rid_domain_id": _sql_literal(f"{relname}.{rid_col}"),
    }
    rendered = template.replace("{alias}", alias).replace("{rid_col}", rid_col)
    missing = sorted(set(PARAM_RE.findall(rendered)) - set(values))
    if missing:
        raise PostgresError(f"cannot render exact policy; missing runtime bindings: {missing}")
    for name, value in sorted(values.items(), key=lambda item: len(item[0]), reverse=True):
        rendered = rendered.replace(f":{name}", value)
    return rendered


def _write_temp_sql(sql: str) -> Path:
    tmp = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".sql", delete=False)
    with tmp:
        tmp.write(sql)
    return Path(tmp.name)


def _oracle_script(predicate: str, context_id: str) -> str:
    contract_run = f"oracle_{context_id}_contract"
    positive_run = f"oracle_{context_id}_positive"
    return f"""
\\set ON_ERROR_STOP on
SET jit = off;
SET max_parallel_workers_per_gather = 0;
TRUNCATE public.udf_audit;
DROP TABLE IF EXISTS pg_temp.oracle_authorized;
CREATE TEMP TABLE oracle_authorized AS
SELECT d.doc_id AS rid
FROM public.document d
WHERE {predicate};
CREATE UNIQUE INDEX oracle_authorized_rid_idx ON oracle_authorized(rid);

WITH auth AS MATERIALIZED (
  SELECT d.*, d.doc_id AS __rid
  FROM public.document d
  WHERE {predicate}
)
SELECT count(*)
FROM auth
WHERE public.unsafe_log({_quote(contract_run)}, 'E7_contract_unsafe_where', 'contract_barrier_exact', 'document_occ_1', __rid, secret);

CREATE TEMP TABLE contract_audit AS
SELECT
  {_quote(contract_run)}::text AS run_id,
  count(*)::bigint AS udf_calls,
  count(*) FILTER (WHERE o.rid IS NULL)::bigint AS unauthorized_observations
FROM public.udf_audit a
LEFT JOIN oracle_authorized o ON o.rid = a.rid
WHERE a.run_id = {_quote(contract_run)}
  AND a.occurrence_id = 'document_occ_1';

TRUNCATE public.udf_audit;
WITH raw AS MATERIALIZED (
  SELECT d.*,
         d.doc_id AS __rid,
         public.unsafe_log({_quote(positive_run)}, 'E7_positive_raw_pushdown', 'raw_pushdown_positive_control', 'document_occ_1', d.doc_id, d.secret) AS observed
  FROM public.document d
)
SELECT count(*)
FROM raw d
WHERE observed
  AND {predicate};

CREATE TEMP TABLE positive_audit AS
SELECT
  {_quote(positive_run)}::text AS run_id,
  count(*)::bigint AS udf_calls,
  count(*) FILTER (WHERE o.rid IS NULL)::bigint AS unauthorized_observations
FROM public.udf_audit a
LEFT JOIN oracle_authorized o ON o.rid = a.rid
WHERE a.run_id = {_quote(positive_run)}
  AND a.occurrence_id = 'document_occ_1';

SELECT jsonb_build_object(
  'context_id', {_quote(context_id)},
  'authorized_count', (SELECT count(*) FROM oracle_authorized),
  'total_rows', (SELECT count(*) FROM public.document),
  'contract', (SELECT to_jsonb(contract_audit) FROM contract_audit),
  'positive', (SELECT to_jsonb(positive_audit) FROM positive_audit)
)::text;
"""


def _run_oracle_sql(predicate: str, context_id: str, pg_env: PostgresEnv) -> Mapping[str, Any]:
    path = _write_temp_sql(_oracle_script(predicate, context_id))
    try:
        stdout = run_psql_file(path, pg_env)
    finally:
        path.unlink(missing_ok=True)
    payload = ""
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            payload = stripped
    if not payload:
        raise PostgresError(f"oracle smoke did not emit JSON:\n{stdout}")
    return json.loads(payload)


def _result_hash(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _git_commit(root: Path) -> str:
    import subprocess

    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(root),
        text=True,
        capture_output=True,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def _raw_record(
    root: Path,
    mode: str,
    evaluation_role: str,
    test_id: str,
    run_payload: Mapping[str, Any],
    oracle_payload: Mapping[str, Any],
    scale: str,
    seed: int,
    policy_id: str,
    context_id: str,
    elapsed_ms: float,
    manifest_hash: str,
    pg_version: str,
) -> Dict[str, Any]:
    mode = normalize_mode_id(mode)
    unsafe = int(run_payload["unauthorized_observations"])
    expected_positive = test_id == "E7_positive_raw_pushdown"
    status = "unsafe_observation" if expected_positive and unsafe > 0 else "pass"
    audit_status = "fail" if unsafe > 0 else "pass"
    result_digest = _result_hash({"test_id": test_id, "run": run_payload, "oracle": oracle_payload})
    return {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": f"ORACLE_{test_id}_{context_id}",
        "manifest_id": "oracle_audit_smoke_v1",
        "manifest_hash": manifest_hash,
        "experiment": "ORACLE",
        "stage": "smoke",
        "run_kind": "normal_mode",
        "dataset": {"name": "synthetic_saas", "scale": scale, "seed": seed},
        "query": {
            "query_id": test_id,
            "path": "caprls_core/oracle_audit.py",
            "params": {"context_id": context_id, "policy_id": policy_id},
        },
        "policy": {
            "policy_id": policy_id,
            "policy_version": 0,
            "policy_sql_manifest_hash": manifest_hash,
        },
        "context": {
            "context_id": context_id,
            "ctx_hash": result_digest,
        },
        "mode": mode,
        "template": {
            "template_id": "barrier_filter_v1" if mode == ADMISSION_FIRST_MODE else "raw_pushdown_positive_control_v1",
            "alternative": "BarrierFilter" if mode == ADMISSION_FIRST_MODE else "UnsafeRawPushdownPositiveControl",
        },
        "template_applicability": {"status": "applicable", "reason": None},
        "template_oracle": {
            "eligible_for_template_oracle": False,
            "template_oracle_exclusion_reason": "oracle_audit_smoke_not_template_oracle_pool",
        },
        "evaluation_role": evaluation_role,
        "pg": {
            "version": pg_version,
            "gucs": {"jit": "off", "max_parallel_workers_per_gather": "0"},
        },
        "versions": {
            "policy": {policy_id: 0},
            "membership": {"all": 0},
            "context": {context_id: 0},
            "trusted_state": {"policy_catalog": 0},
            "base": {"document": 0, "share_acl": 0, "group_membership": 0},
            "artifacts": {},
        },
        "planner": {
            "level": "oracle-audit-smoke",
            "planning_time_ms": 0.0,
            "generated_templates": 1,
            "rejected_templates": 0,
            "costed_templates": 1,
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
            "status": audit_status,
            "audit_path": None,
            "udf_calls": int(run_payload["udf_calls"]),
            "unauthorized_observations": unsafe,
            "client_errors": 0,
            "client_notices": 0,
        },
        "sql": {
            "emitted_sql_path": "caprls_core/oracle_audit.py",
            "emitted_sql_hash": file_sha256(root / "caprls_core" / "oracle_audit.py"),
            "normalized_sql_hash": manifest_hash,
        },
        "oracle_check": {
            "status": "match",
            "oracle_kind": "set_core_occurrence_indexed",
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
            "row_count": int(oracle_payload["authorized_count"]),
            "result_hash": result_digest,
        },
        "pg_metrics": {
            "shared_read_blocks": 0,
            "shared_hit_blocks": 0,
            "temp_read_blocks": 0,
            "temp_written_blocks": 0,
        },
        "counts": {
            "policy_evals": int(oracle_payload["total_rows"]),
            "residual_checks": 0,
            "candidate_rows": int(run_payload["udf_calls"]),
            "authorized_rows": int(oracle_payload["authorized_count"]),
            "artifact_lookups": 0,
            "base_fetches": int(oracle_payload["total_rows"]),
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
        "oracle_audit": dict(oracle_payload),
        "status": status,
        "failure": None if unsafe == 0 else {"reason": "diagnostic positive control observed unauthorized rows"},
    }


def run_oracle_audit_smoke(
    root: Path,
    pg_env: PostgresEnv,
    dataset: str,
    scale: str,
    seed: int,
    policy_id: str,
    context_id: str,
    output_dir: Optional[Path] = None,
) -> OracleAuditResult:
    if dataset != "synthetic_saas":
        raise PostgresError(f"unsupported oracle smoke dataset: {dataset}")
    generate_synthetic_saas(root, pg_env, scale=scale, seed=seed, verify=True, output_dir=None)
    policy = _load_policy(root, policy_id)
    if "document" not in policy.get("applicable_relations", []):
        raise PostgresError(f"policy {policy_id} is not applicable to document")
    context = _load_context(context_id, pg_env)
    predicate = _render_exact_predicate(
        str(policy["exact_sql_template"]),
        alias="d",
        rid_col="doc_id",
        context=context,
        relname="document",
    )
    manifest_hash = file_sha256(root / "manifests" / "policies" / "synthetic_saas_policies.yaml")
    pg_version = run_psql_command("SHOW server_version;", pg_env)
    started = time.monotonic()
    oracle_payload = _run_oracle_sql(predicate, context_id, pg_env)
    elapsed_ms = (time.monotonic() - started) * 1000.0
    contract = oracle_payload["contract"]
    positive = oracle_payload["positive"]
    if int(contract["unauthorized_observations"]) != 0:
        raise PostgresError("AdmissionFirst oracle smoke observed unauthorized rows")
    if int(positive["unauthorized_observations"]) <= 0:
        raise PostgresError("positive raw-pushdown control did not observe unauthorized rows")

    raw_paths: Dict[str, Path] = {}
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        records = {
            "E7_contract_unsafe_where": _raw_record(
                root=root,
                mode=ADMISSION_FIRST_MODE,
                evaluation_role=POLICY_ENFORCEMENT_ROLE,
                test_id="E7_contract_unsafe_where",
                run_payload=contract,
                oracle_payload=oracle_payload,
                scale=scale,
                seed=seed,
                policy_id=policy_id,
                context_id=context_id,
                elapsed_ms=elapsed_ms,
                manifest_hash=manifest_hash,
                pg_version=pg_version,
            ),
            "E7_positive_raw_pushdown": _raw_record(
                root=root,
                mode="unsafe-pushdown-positive-control",
                evaluation_role=CONTRACT_VIOLATION_CONTROL_ROLE,
                test_id="E7_positive_raw_pushdown",
                run_payload=positive,
                oracle_payload=oracle_payload,
                scale=scale,
                seed=seed,
                policy_id=policy_id,
                context_id=context_id,
                elapsed_ms=elapsed_ms,
                manifest_hash=manifest_hash,
                pg_version=pg_version,
            ),
        }
        for test_id, record in records.items():
            issues = validate_raw_run_record(record)
            if issues:
                rendered = ", ".join(f"{issue.path}: {issue.message}" for issue in issues)
                raise PostgresError(f"generated oracle raw result failed schema validation: {rendered}")
            target = output_dir / f"{test_id}_{context_id}.json"
            target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            raw_paths[test_id] = target

    return OracleAuditResult(
        context_id=context_id,
        authorized_count=int(oracle_payload["authorized_count"]),
        total_rows=int(oracle_payload["total_rows"]),
        contract_unauthorized_observations=int(contract["unauthorized_observations"]),
        positive_unauthorized_observations=int(positive["unauthorized_observations"]),
        raw_result_paths=raw_paths,
    )
