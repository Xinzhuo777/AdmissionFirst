"""Executable smoke path for the first SQL enforcement template."""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
    POLICY_ENFORCEMENT_ROLE,
    normalize_mode_id,
)

import hashlib
import json
import platform
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

from planner.templates.barrier_filter import BarrierFilterPlan, emit_barrier_filter_sql
from planner.verifier.static import StaticVerification, verify_barrier_filter_static

from .manifest_validator import file_sha256
from .oracle_audit import _load_context, _load_policy, _render_exact_predicate
from .postgres_runner import PostgresEnv, PostgresError, run_psql_command
from .result_schema import RAW_SCHEMA_VERSION, validate_raw_run_record
from .synthetic_saas import generate_synthetic_saas


@dataclass(frozen=True)
class TemplateSmokeResult:
    template_id: str
    context_id: str
    row_count: int
    result_hash: str
    static_status: str
    oracle_status: str
    raw_result_path: Optional[Path]


def _git_commit(root: Path) -> str:
    import subprocess

    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(root),
        text=True,
        capture_output=True,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def _query_json(sql: str, pg_env: PostgresEnv) -> list[dict]:
    wrapped = (
        "SELECT coalesce(jsonb_agg(to_jsonb(q) ORDER BY q.doc_id), '[]'::jsonb)::text "
        f"FROM ({sql.rstrip().rstrip(';')}) q;"
    )
    payload = run_psql_command(wrapped, pg_env)
    return json.loads(payload or "[]")


def _hash_rows(rows: list[dict]) -> str:
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _explain(sql: str, pg_env: PostgresEnv) -> Any:
    payload = run_psql_command(f"EXPLAIN (FORMAT JSON, VERBOSE) {sql}", pg_env)
    return json.loads(payload)


def _oracle_sql(predicate: str) -> str:
    return f"""
SELECT d.doc_id, d.tenant_id, d.owner_id, d.public
FROM public.document d
WHERE {predicate}
ORDER BY d.doc_id;
"""


def _raw_record(
    root: Path,
    plan: BarrierFilterPlan,
    verification: StaticVerification,
    mode: str,
    dataset: str,
    scale: str,
    seed: int,
    policy_id: str,
    context_id: str,
    result_rows: list[dict],
    result_hash: str,
    oracle_hash: str,
    total_rows: int,
    elapsed_ms: float,
    manifest_hash: str,
    explain_path: Optional[Path],
    emitted_sql_path: Optional[Path],
    pg_version: str,
) -> dict:
    mode = normalize_mode_id(mode)
    oracle_match = result_hash == oracle_hash
    explain_ref = str(explain_path.relative_to(root)) if explain_path else None
    sql_ref = str(emitted_sql_path.relative_to(root)) if emitted_sql_path else None
    return {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": f"TEMPLATE_{plan.template_id}_{context_id}",
        "manifest_id": "barrier_filter_template_smoke_v1",
        "manifest_hash": manifest_hash,
        "experiment": "TEMPLATE",
        "stage": "smoke",
        "run_kind": "normal_mode",
        "dataset": {"name": dataset, "scale": scale, "seed": seed},
        "query": {
            "query_id": "barrier_filter_template_smoke",
            "path": "workloads/e1/projection_drop.sql",
            "params": {"context_id": context_id, "policy_id": policy_id},
        },
        "policy": {
            "policy_id": policy_id,
            "policy_version": 0,
            "policy_sql_manifest_hash": manifest_hash,
        },
        "context": {
            "context_id": context_id,
            "ctx_hash": result_hash,
        },
        "mode": mode,
        "template": {"template_id": plan.template_id, "alternative": plan.alternative},
        "template_applicability": {"status": "applicable", "reason": None},
        "template_oracle": {
            "eligible_for_template_oracle": True,
            "template_oracle_exclusion_reason": None,
        },
        "evaluation_role": POLICY_ENFORCEMENT_ROLE,
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
            "level": "A",
            "planning_time_ms": 0.0,
            "generated_templates": plan.generated_templates,
            "rejected_templates": plan.rejected_templates,
            "costed_templates": plan.costed_templates,
            "rejection_reasons": plan.rejection_reasons,
            "chosen_estimated_cost": plan.estimated_cost,
            "chosen_rank_vs_template_oracle": 1,
            "local_feature_vector": None,
            "parent_requirement_vector": None,
            "candidates": [],
            "disabled_components": [],
            "delivered_sigma": plan.delivered_sigma,
        },
        "static_verifier": {
            "status": verification.status,
            "plan_hash": verification.plan_hash,
            "explain_path": explain_ref,
            "reasons": verification.reasons,
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
            "emitted_sql_path": sql_ref,
            "emitted_sql_hash": "sha256:" + hashlib.sha256(plan.emitted_sql.encode("utf-8")).hexdigest(),
            "normalized_sql_hash": manifest_hash,
        },
        "oracle_check": {
            "status": "match" if oracle_match else "mismatch",
            "oracle_kind": "set_core_occurrence_indexed",
            "set_diff_left": 0 if oracle_match else 1,
            "set_diff_right": 0 if oracle_match else 1,
            "known_invalid_accepted": False,
            "known_valid_rejected": False,
        },
        "timing_ms": {
            "planning": 0.0,
            "execution": elapsed_ms,
            "verification": 0.0,
            "total": elapsed_ms,
        },
        "result": {"row_count": len(result_rows), "result_hash": result_hash},
        "pg_metrics": {
            "shared_read_blocks": 0,
            "shared_hit_blocks": 0,
            "temp_read_blocks": 0,
            "temp_written_blocks": 0,
        },
        "counts": {
            "policy_evals": total_rows,
            "residual_checks": 0,
            "candidate_rows": len(result_rows),
            "authorized_rows": len(result_rows),
            "artifact_lookups": 0,
            "base_fetches": len(result_rows),
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
        "status": "pass" if verification.status == "pass" and oracle_match else "wrong_result",
        "failure": None if verification.status == "pass" and oracle_match else {"reason": "template smoke failed"},
    }


def run_barrier_template_smoke(
    root: Path,
    pg_env: PostgresEnv,
    template_id: str,
    dataset: str,
    scale: str,
    seed: int,
    policy_id: str,
    context_id: str,
    output_dir: Optional[Path] = None,
) -> TemplateSmokeResult:
    if template_id != "barrier_filter_v1":
        raise PostgresError(f"unsupported template smoke template: {template_id}")
    if dataset != "synthetic_saas":
        raise PostgresError(f"unsupported template smoke dataset: {dataset}")

    generate_synthetic_saas(root, pg_env, scale=scale, seed=seed, verify=True, output_dir=None)
    policy = _load_policy(root, policy_id)
    context = _load_context(context_id, pg_env)
    predicate = _render_exact_predicate(
        str(policy["exact_sql_template"]),
        alias="d",
        rid_col="doc_id",
        context=context,
        relname="document",
    )
    plan = emit_barrier_filter_sql(
        relname="document",
        alias="d",
        rid_col="doc_id",
        predicate_sql=predicate,
        visible_columns=["doc_id", "tenant_id", "owner_id", "public"],
    )
    manifest_hash = file_sha256(root / "manifests" / "policies" / "synthetic_saas_policies.yaml")
    pg_version = run_psql_command("SHOW server_version;", pg_env)

    started = time.monotonic()
    explain_json = _explain(plan.emitted_sql, pg_env)
    plan_hash = "sha256:" + hashlib.sha256(
        json.dumps(explain_json, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    verification = verify_barrier_filter_static(plan.emitted_sql, explain_json, plan_hash)
    result_rows = _query_json(plan.emitted_sql, pg_env)
    oracle_rows = _query_json(_oracle_sql(predicate), pg_env)
    total_rows = int(run_psql_command("SELECT count(*) FROM public.document;", pg_env))
    elapsed_ms = (time.monotonic() - started) * 1000.0
    result_hash = _hash_rows(result_rows)
    oracle_hash = _hash_rows(oracle_rows)
    if verification.status != "pass":
        raise PostgresError(f"static verifier failed: {verification.reasons}")
    if result_hash != oracle_hash:
        raise PostgresError("BarrierFilter result did not match exact oracle")

    raw_result_path = None
    explain_path = None
    emitted_sql_path = None
    if output_dir is not None:
        raw_dir = output_dir
        explain_dir = root / "results" / "explain" / "TEMPLATE"
        sql_dir = root / "results" / "sql" / "TEMPLATE"
        raw_dir.mkdir(parents=True, exist_ok=True)
        explain_dir.mkdir(parents=True, exist_ok=True)
        sql_dir.mkdir(parents=True, exist_ok=True)
        explain_path = explain_dir / f"{template_id}_{context_id}.json"
        emitted_sql_path = sql_dir / f"{template_id}_{context_id}.sql"
        explain_path.write_text(json.dumps(explain_json, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        emitted_sql_path.write_text(plan.emitted_sql + "\n", encoding="utf-8")
        record = _raw_record(
            root=root,
            plan=plan,
            verification=verification,
            mode=ADMISSION_FIRST_MODE,
            dataset=dataset,
            scale=scale,
            seed=seed,
            policy_id=policy_id,
            context_id=context_id,
            result_rows=result_rows,
            result_hash=result_hash,
            oracle_hash=oracle_hash,
            total_rows=total_rows,
            elapsed_ms=elapsed_ms,
            manifest_hash=manifest_hash,
            explain_path=explain_path,
            emitted_sql_path=emitted_sql_path,
            pg_version=pg_version,
        )
        issues = validate_raw_run_record(record)
        if issues:
            rendered = ", ".join(f"{issue.path}: {issue.message}" for issue in issues)
            raise PostgresError(f"generated template raw result failed schema validation: {rendered}")
        raw_result_path = raw_dir / f"{template_id}_{context_id}.json"
        raw_result_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return TemplateSmokeResult(
        template_id=template_id,
        context_id=context_id,
        row_count=len(result_rows),
        result_hash=result_hash,
        static_status=verification.status,
        oracle_status="match",
        raw_result_path=raw_result_path,
    )
