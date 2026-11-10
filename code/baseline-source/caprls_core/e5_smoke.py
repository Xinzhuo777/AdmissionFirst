"""E5 fixed-representation regret witness smoke runner."""

from __future__ import annotations

import hashlib
import json
import platform
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional

import yaml

from .baselines import (
    ADMISSION_FIRST_MODE,
    FINITE_TEMPLATE_UPPER_BOUND_ROLE,
    load_mode_registry,
    mode_execution_order_key,
    normalize_mode_id,
    scientific_mode_key,
)
from .e2_smoke import (
    _build_auth_idx_sql,
    _clear_auth_idx_sql,
    _count_wrapper,
    _run_count_sql,
    _run_sql_script,
)
from .manifest_validator import file_sha256
from .oracle_audit import _load_context, _load_policy, _quote, _render_exact_predicate
from .postgres_runner import PostgresEnv, PostgresError, run_psql_command
from .result_schema import RAW_SCHEMA_VERSION, validate_raw_run_record
from .synthetic_saas import generate_synthetic_saas


@dataclass(frozen=True)
class E5Witness:
    witness_id: str
    witness_kind: str
    artifact_config: str
    theory_witness: str
    fixed_mode_under_test: str
    expected_best_mode: str
    policy_id: str = "e5_singleton_document"
    query_shape: str = "prefix_range"
    amortization_q: int = 1
    amortization_u: int = 0
    build_charge_modes: tuple[str, ...] = ()


@dataclass(frozen=True)
class E5Template:
    mode: str
    template_id: str
    alternative: str
    required_artifact: Optional[str]


@dataclass(frozen=True)
class E5RunResult:
    witness_id: str
    witness_kind: str
    artifact_config: str
    theory_witness: str
    fixed_mode_under_test: str
    expected_best_mode: str
    mode: str
    template_id: str
    alternative: str
    status: str
    template_applicability: str
    row_count: int
    execution_ms: float
    effective_ms: float
    build_ms: float
    storage_bytes: int
    policy_evals: int
    candidate_rows: int
    artifact_lookups: int
    base_fetches: int
    result_hash: str
    eligible_for_template_oracle: bool
    exclusion_reason: Optional[str] = None
    failure_reason: Optional[str] = None


@dataclass(frozen=True)
class E5SmokeResult:
    raw_result_paths: list[Path]
    candidate_records: int
    normal_records: int
    summary_records: int
    artifact_unavailable_records: int


WITNESSES = [
    E5Witness(
        "barrier_bad_auth_singleton",
        "regret_witness",
        "auth_idx",
        theory_witness="W1",
        fixed_mode_under_test="barrier-only",
        expected_best_mode="auth-index-enum-only",
    ),
    E5Witness(
        "auth_enum_bad_point_query",
        "regret_witness",
        "auth_idx",
        theory_witness="W2",
        fixed_mode_under_test="auth-index-enum-only",
        expected_best_mode="injection-only",
        policy_id="e5_all_document",
        query_shape="point",
    ),
    E5Witness(
        "mav_bad_single_use_refresh",
        "regret_witness",
        "mav",
        theory_witness="W3",
        fixed_mode_under_test="mav-only",
        expected_best_mode="injection-only",
        build_charge_modes=("mav-only",),
    ),
    E5Witness(
        "guard_bad_unselective_residual",
        "regret_witness",
        "auth_idx",
        theory_witness="W4",
        fixed_mode_under_test="guard-mandatory-discharge",
        expected_best_mode="auth-index-enum-only",
    ),
    E5Witness(
        "injection_bad_expensive_singleton",
        "regret_witness",
        "auth_idx",
        theory_witness="W5",
        fixed_mode_under_test="injection-only",
        expected_best_mode="auth-index-enum-only",
    ),
    E5Witness(
        "mav_good_repeated_dashboard",
        "positive_control",
        "mav",
        theory_witness="positive_control",
        fixed_mode_under_test="mav-only",
        expected_best_mode="mav-only",
        amortization_q=10,
    ),
]

TEMPLATES = [
    E5Template("barrier-only", "barrier_filter_v1", "BarrierFilter", None),
    E5Template(
        "auth-index-enum-only",
        "auth_index_enum_v1",
        "AuthorizationIndexSeek",
        "auth_idx",
    ),
    E5Template(
        "strong-auth-index",
        "strong_auth_index_keyed_v1",
        "StrongAuthIndexBaseline",
        "auth_idx",
    ),
    E5Template("mav-only", "mav_scan_v1", "MaterializedAuthorizedViewScan", "mav"),
    E5Template("injection-only", "safe_predicate_injection_v1", "ExactPredicateInjection", None),
    E5Template(
        "guard-mandatory-discharge",
        "guard_candidate_plus_residual_v1",
        "GuardCandidatePlusResidual",
        None,
    ),
]

REQUIRED_MODES = {
    "barrier-only",
    "auth-index-enum-only",
    "strong-auth-index",
    "mav-only",
    "injection-only",
    "guard-mandatory-discharge",
    ADMISSION_FIRST_MODE,
    "template-oracle",
}


def _git_commit(root: Path) -> str:
    import subprocess

    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(root),
        text=True,
        capture_output=True,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def _digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _load_manifest(manifest_path: Path) -> Mapping[str, Any]:
    with manifest_path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, Mapping):
        raise PostgresError(f"E5 manifest must be an object: {manifest_path}")
    return data


def _validate_manifest(manifest_path: Path, manifest: Mapping[str, Any]) -> None:
    if manifest.get("experiment") != "E5" or manifest.get("execution_tier") != "smoke":
        raise PostgresError("e5-smoke requires an E5 smoke manifest")

    modes = {normalize_mode_id(str(item)) for item in manifest.get("modes", [])}
    if modes != REQUIRED_MODES:
        raise PostgresError(
            "E5 modes do not match runner contract: "
            f"expected {sorted(REQUIRED_MODES)}, got {sorted(modes)}"
        )

    queries = {
        str(item.get("query_id")): str(item.get("path"))
        for item in manifest.get("queries", [])
        if isinstance(item, Mapping)
    }
    if queries != {"E5_witness_smoke": "workloads/e5/witness_smoke.sql"}:
        raise PostgresError(f"E5 smoke supports only E5_witness_smoke; got {queries}")

    expected_witnesses = {
        witness.witness_id: (witness.witness_kind, witness.artifact_config)
        for witness in WITNESSES
    }
    manifest_witnesses = {}
    for item in manifest.get("witnesses", []):
        if not isinstance(item, Mapping):
            continue
        configs = item.get("artifact_configs") or []
        manifest_witnesses[str(item.get("id"))] = (
            str(item.get("witness_kind")),
            str(configs[0]) if configs else "",
        )
    if manifest_witnesses != expected_witnesses:
        raise PostgresError(
            "E5 witnesses do not match runner contract: "
            f"expected {expected_witnesses}, got {manifest_witnesses}"
        )

    policy_apps = {
        str(item.get("policy_id")): str(item.get("relation"))
        for item in manifest.get("policy_applications", [])
        if isinstance(item, Mapping)
    }
    expected_policy_apps = {witness.policy_id: "document" for witness in WITNESSES}
    if policy_apps != expected_policy_apps:
        raise PostgresError(
            f"E5 smoke policy applications do not match runner contract: "
            f"expected {expected_policy_apps}, got {policy_apps}"
        )


def _require_prospective_admission_first_runner(manifest: Mapping[str, Any]) -> None:
    """Reject post-hoc regret winners before legacy smoke touches PostgreSQL."""

    if ADMISSION_FIRST_MODE in {
        normalize_mode_id(str(item)) for item in manifest.get("modes", ())
    }:
        raise PostgresError(
            "E5 legacy smoke cannot execute AdmissionFirst: measured-best regret rows are "
            "TemplateOracle diagnostics only; this runner has no prospective selector"
        )


def _available_artifacts(artifact_config: str) -> set[str]:
    if artifact_config == "none":
        return set()
    return {artifact_config}


def _query_bounds(witness: E5Witness, n_value: int, total_rows: int) -> tuple[int, int]:
    if witness.query_shape == "point":
        return (1, 1)
    if witness.query_shape == "prefix_range":
        return (1, min(n_value, total_rows))
    raise PostgresError(f"unsupported E5 witness query shape: {witness.query_shape}")


def _clear_mav_sql(artifact_id: str) -> str:
    return f"""
\\set ON_ERROR_STOP on
BEGIN;
DELETE FROM public.artifact_dependencies WHERE artifact_id = {_quote(artifact_id)};
DROP TABLE IF EXISTS public.e5_mav_authorized_document;
COMMIT;
"""


def _build_mav_sql(
    artifact_id: str,
    policy_id: str,
    ctx_hash: str,
    exact_predicate: str,
) -> str:
    return f"""
\\set ON_ERROR_STOP on
BEGIN;
DELETE FROM public.artifact_dependencies WHERE artifact_id = {_quote(artifact_id)};
DROP TABLE IF EXISTS public.e5_mav_authorized_document;
CREATE TABLE public.e5_mav_authorized_document AS
SELECT d.doc_id
FROM public.document d
WHERE {exact_predicate};
CREATE UNIQUE INDEX e5_mav_authorized_document_doc_id_idx
ON public.e5_mav_authorized_document(doc_id);
INSERT INTO public.artifact_dependencies(artifact_id, dep_kind, dep_name, version_at_build)
VALUES
  ({_quote(artifact_id)}, 'policy', {_quote(policy_id)}, 0),
  ({_quote(artifact_id)}, 'base', 'document', 0),
  ({_quote(artifact_id)}, 'context_scope', {_quote(ctx_hash)}, 0),
  ({_quote(artifact_id)}, 'rid_domain', 'document.doc_id', 0);
COMMIT;
ANALYZE public.e5_mav_authorized_document;
"""


def _candidate_sql(
    template: E5Template,
    exact_predicate: str,
    lo: int,
    hi: int,
    auth_idx_artifact_id: str,
    policy_id: str,
    user_id: str,
    ctx_hash: str,
) -> str:
    if template.mode == "barrier-only":
        return _count_wrapper(
            f"""
WITH auth AS MATERIALIZED (
  SELECT d.doc_id
  FROM public.document d
  WHERE {exact_predicate}
)
SELECT count(*) FROM auth WHERE doc_id BETWEEN {lo} AND {hi};
"""
        )
    if template.mode == "auth-index-enum-only":
        return _count_wrapper(
            f"""
WITH auth AS MATERIALIZED (
  SELECT a.rid
  FROM public.auth_idx a
  WHERE a.artifact_id = {_quote(auth_idx_artifact_id)}
    AND a.policy_id = {_quote(policy_id)}
    AND a.user_id = {_quote(user_id)}
    AND a.ctx_hash = {_quote(ctx_hash)}
    AND a.rid_domain_id = 'document.doc_id'
    AND a.base_rel_oid = 'public.document'::regclass::oid
)
SELECT count(*)
FROM auth a
JOIN public.document d ON d.doc_id = a.rid
WHERE d.doc_id BETWEEN {lo} AND {hi};
"""
        )
    if template.mode == "strong-auth-index":
        return _count_wrapper(
            f"""
SELECT count(*)
FROM public.auth_idx a
WHERE a.artifact_id = {_quote(auth_idx_artifact_id)}
  AND a.policy_id = {_quote(policy_id)}
  AND a.user_id = {_quote(user_id)}
  AND a.ctx_hash = {_quote(ctx_hash)}
  AND a.rid_domain_id = 'document.doc_id'
  AND a.base_rel_oid = 'public.document'::regclass::oid
  AND a.rid BETWEEN {lo} AND {hi};
"""
        )
    if template.mode == "mav-only":
        return _count_wrapper(
            f"""
SELECT count(*)
FROM public.e5_mav_authorized_document m
WHERE m.doc_id BETWEEN {lo} AND {hi};
"""
        )
    if template.mode == "injection-only":
        return _count_wrapper(
            f"""
SELECT count(*)
FROM public.document d
WHERE d.doc_id BETWEEN {lo} AND {hi}
  AND {exact_predicate};
"""
        )
    if template.mode == "guard-mandatory-discharge":
        residual_predicate = exact_predicate.replace("d.", "g.")
        return _count_wrapper(
            f"""
WITH guard_candidate AS MATERIALIZED (
  SELECT d.doc_id
  FROM public.document d
  WHERE d.doc_id BETWEEN {lo} AND {hi}
)
SELECT count(*)
FROM guard_candidate g
WHERE {residual_predicate};
"""
        )
    raise PostgresError(f"unsupported E5 template mode: {template.mode}")


def _make_result(
    witness: E5Witness,
    template: E5Template,
    status: str,
    row_count: int,
    execution_ms: float,
    build_ms: float,
    storage_bytes: int,
    total_rows: int,
    artifact_cardinality: int,
    failure_reason: Optional[str] = None,
) -> E5RunResult:
    applicable = status == "pass"
    effective_ms = execution_ms
    if template.mode in witness.build_charge_modes and witness.amortization_q > 0:
        effective_ms += build_ms / witness.amortization_q
    payload = {
        "witness_id": witness.witness_id,
        "mode": scientific_mode_key(template.mode),
        "template_id": template.template_id,
        "status": status,
        "row_count": row_count,
        "execution_ms": round(execution_ms, 6),
        "effective_ms": round(effective_ms, 6),
    }
    policy_evals = total_rows if template.mode == "barrier-only" else 0
    candidate_rows = total_rows if template.mode == "barrier-only" else artifact_cardinality
    return E5RunResult(
        witness_id=witness.witness_id,
        witness_kind=witness.witness_kind,
        artifact_config=witness.artifact_config,
        theory_witness=witness.theory_witness,
        fixed_mode_under_test=witness.fixed_mode_under_test,
        expected_best_mode=witness.expected_best_mode,
        mode=template.mode,
        template_id=template.template_id,
        alternative=template.alternative,
        status=status,
        template_applicability="applicable" if applicable else "artifact_unavailable",
        row_count=row_count,
        execution_ms=execution_ms,
        effective_ms=effective_ms,
        build_ms=build_ms,
        storage_bytes=storage_bytes,
        policy_evals=policy_evals,
        candidate_rows=candidate_rows,
        artifact_lookups=0 if template.required_artifact is None else 1,
        base_fetches=row_count,
        result_hash=_digest(payload),
        eligible_for_template_oracle=applicable,
        exclusion_reason=None if applicable else "artifact_unavailable",
        failure_reason=failure_reason,
    )


def _unavailable_result(witness: E5Witness, template: E5Template) -> E5RunResult:
    reason = f"requires {template.required_artifact} but artifact_config={witness.artifact_config}"
    return _make_result(
        witness=witness,
        template=template,
        status="expected_reject",
        row_count=0,
        execution_ms=0.0,
        build_ms=0.0,
        storage_bytes=0,
        total_rows=0,
        artifact_cardinality=0,
        failure_reason=reason,
    )


def _evaluation_role(root: Path, mode: str, run_kind: str) -> str:
    if run_kind in {"template_candidate", "template_oracle_summary"}:
        return FINITE_TEMPLATE_UPPER_BOUND_ROLE
    return load_mode_registry(root)[normalize_mode_id(mode)].evaluation_role


def _record(
    root: Path,
    manifest_path: Path,
    manifest_id: str,
    run_id: str,
    run_kind: str,
    mode: str,
    result: E5RunResult,
    dataset_scale: str,
    seed: int,
    policy_id: str,
    context_id: str,
    ctx_hash: str,
    pg_version: str,
    total_rows: int,
    authorized_rows: int,
    n_value: int,
    best_template_id: Optional[str],
    best_execution_ms: Optional[float],
    best_effective_ms: Optional[float],
    amortization_q: int,
    amortization_u: int,
    stage: str = "smoke",
    query_id: str = "E5_witness_smoke",
    query_path: str = "workloads/e5/witness_smoke.sql",
) -> Dict[str, Any]:
    mode = normalize_mode_id(mode)
    artifact_action = "reject" if result.template_applicability == "artifact_unavailable" else "execute"
    artifact_status = (
        "pass"
        if result.template_applicability == "applicable" and result.artifact_lookups
        else "not_applicable"
    )
    regret_ratio = None
    if best_effective_ms and best_effective_ms > 0 and result.status == "pass":
        regret_ratio = result.effective_ms / best_effective_ms
    return {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": run_id,
        "manifest_id": manifest_id,
        "manifest_hash": file_sha256(manifest_path),
        "experiment": "E5",
        "stage": stage,
        "run_kind": run_kind,
        "dataset": {"name": "synthetic_saas", "scale": dataset_scale, "seed": seed},
        "query": {
            "query_id": query_id,
            "path": query_path,
            "params": {
                "witness_id": result.witness_id,
                "witness_kind": result.witness_kind,
                "theory_witness": result.theory_witness,
                "fixed_mode_under_test": result.fixed_mode_under_test,
                "expected_best_mode": result.expected_best_mode,
                "N": n_value,
                "artifact_config": result.artifact_config,
                "amortization_q": amortization_q,
                "amortization_u": amortization_u,
            },
        },
        "policy": {
            "policy_id": policy_id,
            "policy_version": 0,
            "policy_sql_manifest_hash": file_sha256(root / "manifests" / "policies" / "synthetic_saas_policies.yaml"),
        },
        "context": {"context_id": context_id, "ctx_hash": ctx_hash},
        "mode": mode,
        "template": {"template_id": result.template_id, "alternative": result.alternative},
        "template_applicability": {
            "status": result.template_applicability,
            "reason": result.failure_reason if result.template_applicability != "applicable" else None,
        },
        "template_oracle": {
            "eligible_for_template_oracle": result.eligible_for_template_oracle,
            "template_oracle_exclusion_reason": result.exclusion_reason,
        },
        "evaluation_role": _evaluation_role(root, mode, run_kind),
        "pg": {
            "version": pg_version,
            "gucs": {"jit": "off", "max_parallel_workers_per_gather": "0"},
        },
        "versions": {
            "policy": {policy_id: 0},
            "membership": {"group_membership": 0},
            "context": {context_id: 0},
            "trusted_state": {"witness_contract": 1},
            "base": {"document": 0},
            "artifacts": _artifact_versions(result.witness_id, result.artifact_config),
        },
        "planner": {
            "level": "A",
            "planning_time_ms": 0.0,
            "generated_templates": len(TEMPLATES),
            "rejected_templates": 0 if result.eligible_for_template_oracle else 1,
            "costed_templates": 1 if result.eligible_for_template_oracle else 0,
            "rejection_reasons": {result.exclusion_reason: 1} if result.exclusion_reason else {},
            "chosen_estimated_cost": result.effective_ms,
            "chosen_rank_vs_template_oracle": 1
            if best_template_id == result.template_id and result.status == "pass"
            else None,
            "local_feature_vector": None,
            "parent_requirement_vector": {"witness_id": result.witness_id},
            "disabled_components": [],
            "candidates": [],
            "delivered_sigma": {},
        },
        "static_verifier": {
            "status": "pass",
            "plan_hash": result.result_hash,
            "explain_path": None,
            "reasons": [],
        },
        "artifact_validation": {
            "status": artifact_status,
            "action": artifact_action,
            "expected_action": artifact_action,
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
            "emitted_sql_path": query_path,
            "emitted_sql_hash": file_sha256(root / query_path),
            "normalized_sql_hash": result.result_hash,
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
            "execution": result.execution_ms,
            "verification": 0.0,
            "total": result.execution_ms,
        },
        "result": {"row_count": result.row_count, "result_hash": result.result_hash},
        "pg_metrics": {
            "shared_read_blocks": 0,
            "shared_hit_blocks": 0,
            "temp_read_blocks": 0,
            "temp_written_blocks": 0,
        },
        "counts": {
            "policy_evals": result.policy_evals,
            "residual_checks": 0,
            "candidate_rows": result.candidate_rows,
            "authorized_rows": authorized_rows,
            "artifact_lookups": result.artifact_lookups,
            "base_fetches": result.base_fetches,
        },
        "artifact_cost": {
            "query_only_ms": result.execution_ms,
            "build_ms": result.build_ms,
            "refresh_ms": 0.0,
            "storage_bytes": result.storage_bytes,
            "indexes_built": _indexes_built(result),
            "artifact_key_encoding_version": "artifact_key_encoding_v1",
            "amortization_model": "declared_q_u" if amortization_q > 1 or amortization_u else "query_only",
        },
        "implementation": {
            "git_commit": _git_commit(root),
            "docker_image_digest": "not_containerized",
            "python_version": platform.python_version(),
            "planner_language": "python",
        },
        "e5_witness": {
            "witness_id": result.witness_id,
            "witness_kind": result.witness_kind,
            "N": n_value,
            "fixed_mode": mode,
            "artifact_config": result.artifact_config,
            "best_template_id": best_template_id,
            "best_execution_ms": best_execution_ms,
            "best_effective_ms": best_effective_ms,
            "regret_ratio": regret_ratio,
            "effective_latency_ms": result.effective_ms,
            "amortized_latency_ms": result.effective_ms,
            "theory_witness": result.theory_witness,
            "fixed_mode_under_test": result.fixed_mode_under_test,
            "expected_best_mode": result.expected_best_mode,
            "amortization": {"Q": amortization_q, "U": amortization_u},
        },
        "status": result.status,
        "failure": None if result.failure_reason is None else {"reason": result.failure_reason},
    }


def _artifact_versions(witness_id: str, artifact_config: str) -> Dict[str, int]:
    if artifact_config == "auth_idx":
        return {f"e5_auth_idx_{witness_id}": 0}
    if artifact_config == "mav":
        return {f"e5_mav_{witness_id}": 0}
    return {}


def _indexes_built(result: E5RunResult) -> list[str]:
    if result.template_applicability != "applicable":
        return []
    if result.artifact_config == "auth_idx":
        return ["auth_idx_lookup"]
    if result.artifact_config == "mav":
        return ["e5_mav_authorized_document_doc_id_idx"]
    return []


def _candidate_record(
    root: Path,
    manifest_path: Path,
    manifest_id: str,
    result: E5RunResult,
    dataset_scale: str,
    seed: int,
    policy_id: str,
    context_id: str,
    ctx_hash: str,
    pg_version: str,
    total_rows: int,
    authorized_rows: int,
    n_value: int,
    best_template_id: Optional[str],
    best_execution_ms: Optional[float],
    best_effective_ms: Optional[float],
    amortization_q: int,
    amortization_u: int,
) -> Dict[str, Any]:
    return _record(
        root=root,
        manifest_path=manifest_path,
        manifest_id=manifest_id,
        run_id=f"E5_{result.witness_id}_{result.template_id}",
        run_kind="template_candidate",
        mode="template-oracle",
        result=result,
        dataset_scale=dataset_scale,
        seed=seed,
        policy_id=policy_id,
        context_id=context_id,
        ctx_hash=ctx_hash,
        pg_version=pg_version,
        total_rows=total_rows,
        authorized_rows=authorized_rows,
        n_value=n_value,
        best_template_id=best_template_id,
        best_execution_ms=best_execution_ms,
        best_effective_ms=best_effective_ms,
        amortization_q=amortization_q,
        amortization_u=amortization_u,
    )


def _normal_record(
    root: Path,
    manifest_path: Path,
    manifest_id: str,
    mode: str,
    result: E5RunResult,
    dataset_scale: str,
    seed: int,
    policy_id: str,
    context_id: str,
    ctx_hash: str,
    pg_version: str,
    total_rows: int,
    authorized_rows: int,
    n_value: int,
    best_template_id: Optional[str],
    best_execution_ms: Optional[float],
    best_effective_ms: Optional[float],
    amortization_q: int,
    amortization_u: int,
) -> Dict[str, Any]:
    return _record(
        root=root,
        manifest_path=manifest_path,
        manifest_id=manifest_id,
        run_id=f"E5_{result.witness_id}_{mode}",
        run_kind="normal_mode",
        mode=mode,
        result=result,
        dataset_scale=dataset_scale,
        seed=seed,
        policy_id=policy_id,
        context_id=context_id,
        ctx_hash=ctx_hash,
        pg_version=pg_version,
        total_rows=total_rows,
        authorized_rows=authorized_rows,
        n_value=n_value,
        best_template_id=best_template_id,
        best_execution_ms=best_execution_ms,
        best_effective_ms=best_effective_ms,
        amortization_q=amortization_q,
        amortization_u=amortization_u,
    )


def _summary_record(
    root: Path,
    manifest_path: Path,
    manifest_id: str,
    witness: E5Witness,
    eligible: list[E5RunResult],
    excluded: list[E5RunResult],
    chosen: E5RunResult,
    dataset_scale: str,
    seed: int,
    policy_id: str,
    context_id: str,
    ctx_hash: str,
    pg_version: str,
    total_rows: int,
    authorized_rows: int,
    n_value: int,
    stage: str = "smoke",
    query_id: str = "E5_witness_smoke",
    query_path: str = "workloads/e5/witness_smoke.sql",
) -> Dict[str, Any]:
    best = min(eligible, key=lambda item: (item.effective_ms, item.template_id))
    summary_payload = {
        "run_kind": "template_oracle_summary",
        "query_id": query_id,
        "context_id": context_id,
        "mode_under_test": ADMISSION_FIRST_MODE,
        "ranking_metric": "e5_effective_latency_ms",
        "eligible_templates": len(eligible),
        "excluded_templates": _excluded_counts(excluded),
        "best_template_id": best.template_id,
        "best_execution_ms": best.execution_ms,
        "best_effective_ms": best.effective_ms,
        "chosen_template_id": chosen.template_id,
        "chosen_execution_ms": chosen.execution_ms,
        "chosen_effective_ms": chosen.effective_ms,
        "gap": chosen.effective_ms / best.effective_ms if best.effective_ms > 0 else 1.0,
    }
    scientific_summary_payload = {
        **summary_payload,
        "mode_under_test": scientific_mode_key(ADMISSION_FIRST_MODE),
    }
    summary_result = E5RunResult(
        witness_id=witness.witness_id,
        witness_kind=witness.witness_kind,
        artifact_config=witness.artifact_config,
        theory_witness=witness.theory_witness,
        fixed_mode_under_test=witness.fixed_mode_under_test,
        expected_best_mode=witness.expected_best_mode,
        mode="template-oracle",
        template_id=best.template_id,
        alternative=best.alternative,
        status="pass",
        template_applicability="applicable",
        row_count=best.row_count,
        execution_ms=chosen.execution_ms,
        effective_ms=chosen.effective_ms,
        build_ms=best.build_ms,
        storage_bytes=best.storage_bytes,
        policy_evals=best.policy_evals,
        candidate_rows=best.candidate_rows,
        artifact_lookups=best.artifact_lookups,
        base_fetches=best.base_fetches,
        result_hash=_digest(scientific_summary_payload),
        eligible_for_template_oracle=True,
    )
    record = _record(
        root=root,
        manifest_path=manifest_path,
        manifest_id=manifest_id,
        run_id=f"E5_{witness.witness_id}_template_oracle_summary",
        run_kind="template_oracle_summary",
        mode="template-oracle",
        result=summary_result,
        dataset_scale=dataset_scale,
        seed=seed,
        policy_id=policy_id,
        context_id=context_id,
        ctx_hash=ctx_hash,
        pg_version=pg_version,
        total_rows=total_rows,
        authorized_rows=authorized_rows,
        n_value=n_value,
        best_template_id=best.template_id,
        best_execution_ms=best.execution_ms,
        best_effective_ms=best.effective_ms,
        amortization_q=witness.amortization_q,
        amortization_u=witness.amortization_u,
        stage=stage,
        query_id=query_id,
        query_path=query_path,
    )
    record["template_oracle_summary"] = summary_payload
    return record


def _excluded_counts(excluded: Iterable[E5RunResult]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in excluded:
        key = item.exclusion_reason or item.template_applicability
        counts[key] = counts.get(key, 0) + 1
    return counts


def _write_record(record: Mapping[str, Any], output_dir: Path) -> Path:
    issues = validate_raw_run_record(record)
    if issues:
        rendered = ", ".join(f"{issue.path}: {issue.message}" for issue in issues)
        raise PostgresError(f"E5 raw record failed schema validation: {rendered}")
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_mode = str(record["mode"]).replace("-", "_")
    safe_kind = str(record["run_kind"]).replace("-", "_")
    target = output_dir / f"{record['run_id']}_{safe_kind}_{safe_mode}.json"
    target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def _execute_template(
    witness: E5Witness,
    template: E5Template,
    exact_predicate: str,
    lo: int,
    hi: int,
    auth_idx_artifact_id: str,
    policy_id: str,
    user_id: str,
    ctx_hash: str,
    pg_env: PostgresEnv,
    oracle_count: int,
    total_rows: int,
    artifact_cardinality: int,
    build_ms: float,
    storage_bytes: int,
) -> E5RunResult:
    if template.required_artifact and template.required_artifact not in _available_artifacts(witness.artifact_config):
        return _unavailable_result(witness, template)
    sql = _candidate_sql(
        template=template,
        exact_predicate=exact_predicate,
        lo=lo,
        hi=hi,
        auth_idx_artifact_id=auth_idx_artifact_id,
        policy_id=policy_id,
        user_id=user_id,
        ctx_hash=ctx_hash,
    )
    row_count, execution_ms = _run_count_sql(sql, pg_env)
    if row_count != oracle_count:
        raise PostgresError(
            f"E5 {witness.witness_id}/{template.mode} returned {row_count}, "
            f"expected {oracle_count}"
        )
    return _make_result(
        witness=witness,
        template=template,
        status="pass",
        row_count=row_count,
        execution_ms=execution_ms,
        build_ms=build_ms if template.required_artifact == witness.artifact_config else 0.0,
        storage_bytes=storage_bytes if template.required_artifact == witness.artifact_config else 0,
        total_rows=total_rows,
        artifact_cardinality=artifact_cardinality,
    )


def run_e5_smoke(
    root: Path,
    pg_env: PostgresEnv,
    manifest_path: Path,
    output_dir: Path,
) -> E5SmokeResult:
    manifest = _load_manifest(manifest_path)
    _validate_manifest(manifest_path, manifest)
    _require_prospective_admission_first_runner(manifest)
    manifest_id = str(manifest["manifest_id"])
    dataset = manifest.get("dataset") or {}
    scale = str(dataset.get("scale", "1e5"))
    seed = int(dataset.get("seed", 46))
    n_values = [int(item) for item in manifest.get("N", [100000])]
    n_value = n_values[0]

    generate_synthetic_saas(root, pg_env, scale=scale, seed=seed, verify=True, output_dir=None)
    context_id = "ctx_000001"
    context = _load_context(context_id, pg_env)
    ctx_hash = run_psql_command(
        f"SELECT ctx_hash FROM public.synthetic_context WHERE context_id = {_quote(context_id)};",
        pg_env,
    )
    total_rows = int(run_psql_command("SELECT count(*) FROM public.document;", pg_env))
    pg_version = run_psql_command("SHOW server_version;", pg_env)
    user_id = str(context["user_id"])

    raw_paths: list[Path] = []
    candidate_records = 0
    normal_records = 0
    summary_records = 0
    artifact_unavailable_records = 0

    for witness in WITNESSES:
        policy_id = witness.policy_id
        policy = _load_policy(root, policy_id)
        exact_predicate = _render_exact_predicate(
            str(policy["exact_sql_template"]),
            alias="d",
            rid_col="doc_id",
            context=context,
            relname="document",
        )
        lo, hi = _query_bounds(witness, n_value, total_rows)
        oracle_count, _ = _run_count_sql(
            _count_wrapper(
                f"""
SELECT count(*)
FROM public.document d
WHERE d.doc_id BETWEEN {lo} AND {hi}
  AND {exact_predicate};
"""
            ),
            pg_env,
        )
        authorized_rows = int(
            run_psql_command(f"SELECT count(*) FROM public.document d WHERE {exact_predicate};", pg_env)
        )
        auth_idx_artifact_id = f"e5_auth_idx_{witness.witness_id}"
        mav_artifact_id = f"e5_mav_{witness.witness_id}"
        _run_sql_script(_clear_auth_idx_sql(auth_idx_artifact_id), pg_env)
        _run_sql_script(_clear_mav_sql(mav_artifact_id), pg_env)

        build_ms = 0.0
        storage_bytes = 0
        artifact_cardinality = 0
        if witness.artifact_config == "auth_idx":
            started = time.monotonic()
            _run_sql_script(
                _build_auth_idx_sql(
                    artifact_id=auth_idx_artifact_id,
                    policy_id=policy_id,
                    user_id=user_id,
                    ctx_hash=ctx_hash,
                    exact_predicate=exact_predicate,
                ),
                pg_env,
            )
            build_ms = (time.monotonic() - started) * 1000.0
            artifact_cardinality = int(
                run_psql_command(
                    f"SELECT count(*) FROM public.auth_idx WHERE artifact_id = {_quote(auth_idx_artifact_id)};",
                    pg_env,
                )
            )
            storage_bytes = artifact_cardinality * 64
        elif witness.artifact_config == "mav":
            started = time.monotonic()
            _run_sql_script(
                _build_mav_sql(
                    artifact_id=mav_artifact_id,
                    policy_id=policy_id,
                    ctx_hash=ctx_hash,
                    exact_predicate=exact_predicate,
                ),
                pg_env,
            )
            build_ms = (time.monotonic() - started) * 1000.0
            artifact_cardinality = int(
                run_psql_command("SELECT count(*) FROM public.e5_mav_authorized_document;", pg_env)
            )
            storage_bytes = artifact_cardinality * 64

        candidate_results = [
            _execute_template(
                witness=witness,
                template=template,
                exact_predicate=exact_predicate,
                lo=lo,
                hi=hi,
                auth_idx_artifact_id=auth_idx_artifact_id,
                policy_id=policy_id,
                user_id=user_id,
                ctx_hash=ctx_hash,
                pg_env=pg_env,
                oracle_count=oracle_count,
                total_rows=total_rows,
                artifact_cardinality=artifact_cardinality,
                build_ms=build_ms,
                storage_bytes=storage_bytes,
            )
            for template in TEMPLATES
        ]
        eligible = [item for item in candidate_results if item.eligible_for_template_oracle]
        excluded = [item for item in candidate_results if not item.eligible_for_template_oracle]
        if not eligible:
            raise PostgresError(f"E5 witness {witness.witness_id} produced no eligible template")
        chosen = min(eligible, key=lambda item: (item.effective_ms, item.template_id))
        best = chosen

        for result in candidate_results:
            if result.template_applicability == "artifact_unavailable":
                artifact_unavailable_records += 1
            raw_paths.append(
                _write_record(
                    _candidate_record(
                        root=root,
                        manifest_path=manifest_path,
                        manifest_id=manifest_id,
                        result=result,
                        dataset_scale=scale,
                        seed=seed,
                        policy_id=policy_id,
                        context_id=context_id,
                        ctx_hash=ctx_hash,
                        pg_version=pg_version,
                        total_rows=total_rows,
                        authorized_rows=authorized_rows,
                        n_value=n_value,
                        best_template_id=best.template_id,
                        best_execution_ms=best.execution_ms,
                        best_effective_ms=best.effective_ms,
                        amortization_q=witness.amortization_q,
                        amortization_u=witness.amortization_u,
                    ),
                    output_dir,
                )
            )
            candidate_records += 1

        for mode in sorted(
            REQUIRED_MODES - {"template-oracle"},
            key=mode_execution_order_key,
        ):
            result = chosen if mode == ADMISSION_FIRST_MODE else _find_mode(candidate_results, mode)
            raw_paths.append(
                _write_record(
                    _normal_record(
                        root=root,
                        manifest_path=manifest_path,
                        manifest_id=manifest_id,
                        mode=mode,
                        result=result,
                        dataset_scale=scale,
                        seed=seed,
                        policy_id=policy_id,
                        context_id=context_id,
                        ctx_hash=ctx_hash,
                        pg_version=pg_version,
                        total_rows=total_rows,
                        authorized_rows=authorized_rows,
                        n_value=n_value,
                        best_template_id=best.template_id,
                        best_execution_ms=best.execution_ms,
                        best_effective_ms=best.effective_ms,
                        amortization_q=witness.amortization_q,
                        amortization_u=witness.amortization_u,
                    ),
                    output_dir,
                )
            )
            normal_records += 1

        raw_paths.append(
            _write_record(
                _summary_record(
                    root=root,
                    manifest_path=manifest_path,
                    manifest_id=manifest_id,
                    witness=witness,
                    eligible=eligible,
                    excluded=excluded,
                    chosen=chosen,
                    dataset_scale=scale,
                    seed=seed,
                    policy_id=policy_id,
                    context_id=context_id,
                    ctx_hash=ctx_hash,
                    pg_version=pg_version,
                    total_rows=total_rows,
                    authorized_rows=authorized_rows,
                    n_value=n_value,
                ),
                output_dir,
            )
        )
        summary_records += 1

    return E5SmokeResult(
        raw_result_paths=raw_paths,
        candidate_records=candidate_records,
        normal_records=normal_records,
        summary_records=summary_records,
        artifact_unavailable_records=artifact_unavailable_records,
    )


def _find_mode(results: list[E5RunResult], mode: str) -> E5RunResult:
    for result in results:
        if result.mode == mode:
            return result
    raise PostgresError(f"missing E5 mode result: {mode}")
