"""E4 LocalGreedy versus AdmissionFirst controlled-pair smoke gate."""

from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional

import yaml

from .baselines import (
    ADMISSION_FIRST_MODE,
    FINITE_TEMPLATE_UPPER_BOUND_ROLE,
    load_mode_registry,
    normalize_mode_id,
    scientific_mode_key,
)
from .manifest_validator import file_sha256
from .postgres_runner import PostgresError
from .result_schema import RAW_SCHEMA_VERSION, validate_raw_run_record


@dataclass(frozen=True)
class E4Candidate:
    template_id: str
    alternative: str
    execution_ms: float
    status: str = "pass"
    template_applicability: str = "applicable"
    reason: Optional[str] = None


@dataclass(frozen=True)
class E4Case:
    pair_id: str
    parent_label: str
    parent_name: str
    query_id: str
    query_path: str
    local_vector_id: str
    local_feature_vector: Mapping[str, Any]
    parent_requirement_vector: Mapping[str, Any]
    local_greedy_template_id: str
    admission_first_template_id: str
    candidates: tuple[E4Candidate, ...]


@dataclass(frozen=True)
class E4SmokeResult:
    raw_result_paths: list[Path]
    candidate_records: int
    normal_records: int
    summary_records: int
    pair_count: int


TEMPLATE_ALTERNATIVES = {
    "auth_index_enum_v1": "AuthorizationIndexSeek",
    "hybrid_intersect_v1": "HybridIndexIntersect",
    "barrier_filter_v1": "BarrierFilter",
    "guard_candidate_plus_residual_v1": "Guard+LateResidual",
    "mav_scan_v1": "MaterializedAuthorizedViewScan",
}


def _local_vector(local_vector_id: str) -> Mapping[str, Any]:
    if local_vector_id == "lv_auth50_idx":
        return {
            "relname": "document",
            "policy_id": "tenant_group",
            "estimated_N": 100000,
            "s_auth": 0.5,
            "policy_cost_class": "cheap",
            "available_artifacts": ["auth_idx"],
            "artifact_lookup_cost": 1.0,
            "auth_idx_cardinality": 50000,
            "mav_scan_cost": None,
            "guard_fpr": None,
            "local_safety_requirement": "none",
        }
    if local_vector_id == "lv_guard_complete_expensive":
        return {
            "relname": "document",
            "policy_id": "tenant_group",
            "estimated_N": 100000,
            "s_auth": 0.5,
            "policy_cost_class": "1ms",
            "available_artifacts": [],
            "artifact_lookup_cost": None,
            "auth_idx_cardinality": None,
            "mav_scan_cost": None,
            "guard_fpr": 1,
            "local_safety_requirement": "none",
        }
    if local_vector_id == "lv_unordered_authidx":
        return {
            "relname": "document",
            "policy_id": "tenant_group",
            "estimated_N": 100000,
            "s_auth": 0.5,
            "policy_cost_class": "cheap",
            "available_artifacts": ["auth_idx", "mav"],
            "artifact_lookup_cost": 1.0,
            "auth_idx_cardinality": 50000,
            "mav_scan_cost": 15.0,
            "guard_fpr": None,
            "local_safety_requirement": "none",
        }
    if local_vector_id == "lv_same_policy":
        return {
            "relname": "document",
            "policy_id": "tenant_group",
            "estimated_N": 100000,
            "s_auth": 0.5,
            "policy_cost_class": "cheap",
            "available_artifacts": ["auth_idx"],
            "artifact_lookup_cost": 1.0,
            "auth_idx_cardinality": 50000,
            "mav_scan_cost": None,
            "guard_fpr": None,
            "local_safety_requirement": "none",
        }
    raise PostgresError(f"unknown E4 local vector id: {local_vector_id}")


CASES = [
    E4Case(
        pair_id="selective_ordinary_predicate",
        parent_label="A",
        parent_name="no_query_predicate",
        query_id="E4_selective_ordinary_predicate_A",
        query_path="workloads/e4/selective_ordinary_predicate_A.sql",
        local_vector_id="lv_auth50_idx",
        local_feature_vector=_local_vector("lv_auth50_idx"),
        parent_requirement_vector={
            "ordinary_predicate_class": "none",
            "required_order": None,
            "unsafe_boundary_position": "none",
            "join_fanout": 1,
        },
        local_greedy_template_id="auth_index_enum_v1",
        admission_first_template_id="auth_index_enum_v1",
        candidates=(
            E4Candidate("auth_index_enum_v1", TEMPLATE_ALTERNATIVES["auth_index_enum_v1"], 10.0),
            E4Candidate("hybrid_intersect_v1", TEMPLATE_ALTERNATIVES["hybrid_intersect_v1"], 12.0),
            E4Candidate("barrier_filter_v1", TEMPLATE_ALTERNATIVES["barrier_filter_v1"], 30.0),
        ),
    ),
    E4Case(
        pair_id="selective_ordinary_predicate",
        parent_label="B",
        parent_name="key_point_predicate",
        query_id="E4_selective_ordinary_predicate_B",
        query_path="workloads/e4/selective_ordinary_predicate_B.sql",
        local_vector_id="lv_auth50_idx",
        local_feature_vector=_local_vector("lv_auth50_idx"),
        parent_requirement_vector={
            "ordinary_predicate_class": "leakproof_point",
            "required_order": None,
            "unsafe_boundary_position": "none",
            "join_fanout": 1,
        },
        local_greedy_template_id="auth_index_enum_v1",
        admission_first_template_id="hybrid_intersect_v1",
        candidates=(
            E4Candidate("auth_index_enum_v1", TEMPLATE_ALTERNATIVES["auth_index_enum_v1"], 45.0),
            E4Candidate("hybrid_intersect_v1", TEMPLATE_ALTERNATIVES["hybrid_intersect_v1"], 6.0),
            E4Candidate("barrier_filter_v1", TEMPLATE_ALTERNATIVES["barrier_filter_v1"], 30.0),
        ),
    ),
    E4Case(
        pair_id="unsafe_downstream_expression",
        parent_label="A",
        parent_name="safe_join_then_residual",
        query_id="E4_unsafe_downstream_expression_A",
        query_path="workloads/e4/unsafe_downstream_expression_A.sql",
        local_vector_id="lv_guard_complete_expensive",
        local_feature_vector=_local_vector("lv_guard_complete_expensive"),
        parent_requirement_vector={
            "ordinary_predicate_class": "safe_join",
            "required_order": None,
            "unsafe_boundary_position": "none_before_residual",
            "join_fanout": 10,
        },
        local_greedy_template_id="guard_candidate_plus_residual_v1",
        admission_first_template_id="guard_candidate_plus_residual_v1",
        candidates=(
            E4Candidate(
                "guard_candidate_plus_residual_v1",
                TEMPLATE_ALTERNATIVES["guard_candidate_plus_residual_v1"],
                9.0,
            ),
            E4Candidate("barrier_filter_v1", TEMPLATE_ALTERNATIVES["barrier_filter_v1"], 28.0),
        ),
    ),
    E4Case(
        pair_id="unsafe_downstream_expression",
        parent_label="B",
        parent_name="immediate_unsafe_log",
        query_id="E4_unsafe_downstream_expression_B",
        query_path="workloads/e4/unsafe_downstream_expression_B.sql",
        local_vector_id="lv_guard_complete_expensive",
        local_feature_vector=_local_vector("lv_guard_complete_expensive"),
        parent_requirement_vector={
            "ordinary_predicate_class": "none",
            "required_order": None,
            "unsafe_boundary_position": "immediate",
            "join_fanout": 10,
        },
        local_greedy_template_id="guard_candidate_plus_residual_v1",
        admission_first_template_id="barrier_filter_v1",
        candidates=(
            E4Candidate(
                "guard_candidate_plus_residual_v1",
                TEMPLATE_ALTERNATIVES["guard_candidate_plus_residual_v1"],
                0.0,
                status="expected_reject",
                template_applicability="contract_reject",
                reason="unsafe boundary requires residual discharge before observation",
            ),
            E4Candidate("barrier_filter_v1", TEMPLATE_ALTERNATIVES["barrier_filter_v1"], 16.0),
        ),
    ),
    E4Case(
        pair_id="parent_requires_order",
        parent_label="A",
        parent_name="hash_join",
        query_id="E4_parent_requires_order_A",
        query_path="workloads/e4/parent_requires_order_A.sql",
        local_vector_id="lv_unordered_authidx",
        local_feature_vector=_local_vector("lv_unordered_authidx"),
        parent_requirement_vector={
            "ordinary_predicate_class": "none",
            "required_order": None,
            "unsafe_boundary_position": "none",
            "join_fanout": 10,
        },
        local_greedy_template_id="auth_index_enum_v1",
        admission_first_template_id="auth_index_enum_v1",
        candidates=(
            E4Candidate("auth_index_enum_v1", TEMPLATE_ALTERNATIVES["auth_index_enum_v1"], 11.0),
            E4Candidate("mav_scan_v1", TEMPLATE_ALTERNATIVES["mav_scan_v1"], 15.0),
            E4Candidate("barrier_filter_v1", TEMPLATE_ALTERNATIVES["barrier_filter_v1"], 32.0),
        ),
    ),
    E4Case(
        pair_id="parent_requires_order",
        parent_label="B",
        parent_name="merge_join_order_by",
        query_id="E4_parent_requires_order_B",
        query_path="workloads/e4/parent_requires_order_B.sql",
        local_vector_id="lv_unordered_authidx",
        local_feature_vector=_local_vector("lv_unordered_authidx"),
        parent_requirement_vector={
            "ordinary_predicate_class": "none",
            "required_order": "doc_id",
            "unsafe_boundary_position": "none",
            "join_fanout": 10,
        },
        local_greedy_template_id="auth_index_enum_v1",
        admission_first_template_id="mav_scan_v1",
        candidates=(
            E4Candidate("auth_index_enum_v1", TEMPLATE_ALTERNATIVES["auth_index_enum_v1"], 42.0),
            E4Candidate("mav_scan_v1", TEMPLATE_ALTERNATIVES["mav_scan_v1"], 8.0),
            E4Candidate("barrier_filter_v1", TEMPLATE_ALTERNATIVES["barrier_filter_v1"], 35.0),
        ),
    ),
    E4Case(
        pair_id="join_continuation",
        parent_label="A",
        parent_name="selective_dimension_first",
        query_id="E4_join_continuation_A",
        query_path="workloads/e4/join_continuation_A.sql",
        local_vector_id="lv_same_policy",
        local_feature_vector=_local_vector("lv_same_policy"),
        parent_requirement_vector={
            "ordinary_predicate_class": "selective_dimension_join",
            "required_order": None,
            "unsafe_boundary_position": "after_join",
            "join_fanout": 1,
        },
        local_greedy_template_id="hybrid_intersect_v1",
        admission_first_template_id="hybrid_intersect_v1",
        candidates=(
            E4Candidate("hybrid_intersect_v1", TEMPLATE_ALTERNATIVES["hybrid_intersect_v1"], 7.0),
            E4Candidate("auth_index_enum_v1", TEMPLATE_ALTERNATIVES["auth_index_enum_v1"], 18.0),
            E4Candidate("barrier_filter_v1", TEMPLATE_ALTERNATIVES["barrier_filter_v1"], 24.0),
        ),
    ),
    E4Case(
        pair_id="join_continuation",
        parent_label="B",
        parent_name="high_fanout_before_boundary",
        query_id="E4_join_continuation_B",
        query_path="workloads/e4/join_continuation_B.sql",
        local_vector_id="lv_same_policy",
        local_feature_vector=_local_vector("lv_same_policy"),
        parent_requirement_vector={
            "ordinary_predicate_class": "high_fanout_join",
            "required_order": None,
            "unsafe_boundary_position": "before_join_output",
            "join_fanout": 1000,
        },
        local_greedy_template_id="hybrid_intersect_v1",
        admission_first_template_id="barrier_filter_v1",
        candidates=(
            E4Candidate("hybrid_intersect_v1", TEMPLATE_ALTERNATIVES["hybrid_intersect_v1"], 55.0),
            E4Candidate("auth_index_enum_v1", TEMPLATE_ALTERNATIVES["auth_index_enum_v1"], 28.0),
            E4Candidate("barrier_filter_v1", TEMPLATE_ALTERNATIVES["barrier_filter_v1"], 14.0),
        ),
    ),
]

REQUIRED_MODES = {"local-greedy", ADMISSION_FIRST_MODE, "template-oracle"}


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
        raise PostgresError(f"E4 manifest must be an object: {manifest_path}")
    return data


def _validate_manifest(manifest_path: Path, manifest: Mapping[str, Any]) -> None:
    if manifest.get("experiment") != "E4" or manifest.get("execution_tier") != "smoke":
        raise PostgresError("e4-smoke requires an E4 smoke manifest")

    modes = {normalize_mode_id(str(item)) for item in manifest.get("modes", [])}
    if modes != REQUIRED_MODES:
        raise PostgresError(
            "E4 modes do not match runner contract: "
            f"expected {sorted(REQUIRED_MODES)}, got {sorted(modes)}"
        )

    query_paths = {
        str(item.get("query_id")): str(item.get("path"))
        for item in manifest.get("queries", [])
        if isinstance(item, Mapping)
    }
    expected_queries = {case.query_id: case.query_path for case in CASES}
    if query_paths != expected_queries:
        raise PostgresError(
            f"E4 manifest query list does not match smoke cases in {manifest_path}"
        )

    manifest_pairs = {
        str(item.get("pair_id")): (
            str(item.get("local_vector_id")),
            str(item.get("parent_A")),
            str(item.get("parent_B")),
        )
        for item in manifest.get("pairs", [])
        if isinstance(item, Mapping)
    }
    expected_pairs = {}
    for pair_id in sorted({case.pair_id for case in CASES}):
        pair_cases = [case for case in CASES if case.pair_id == pair_id]
        pair_cases.sort(key=lambda item: item.parent_label)
        expected_pairs[pair_id] = (
            pair_cases[0].local_vector_id,
            pair_cases[0].parent_name,
            pair_cases[1].parent_name,
        )
    if manifest_pairs != expected_pairs:
        raise PostgresError(
            "E4 pairs do not match runner contract: "
            f"expected {expected_pairs}, got {manifest_pairs}"
        )


def _candidate_for(case: E4Case, template_id: str) -> E4Candidate:
    for candidate in case.candidates:
        if candidate.template_id == template_id:
            return candidate
    raise PostgresError(f"missing E4 candidate {case.query_id}/{template_id}")


def _best(case: E4Case) -> E4Candidate:
    eligible = [
        candidate
        for candidate in case.candidates
        if candidate.status == "pass" and candidate.template_applicability == "applicable"
    ]
    if not eligible:
        raise PostgresError(f"E4 case has no eligible candidate: {case.query_id}")
    return min(eligible, key=lambda item: (item.execution_ms, item.template_id))


def _record(
    root: Path,
    manifest_path: Path,
    manifest_id: str,
    case: E4Case,
    run_kind: str,
    mode: str,
    candidate: E4Candidate,
    dataset_scale: str,
    seed: int,
) -> Dict[str, Any]:
    mode = normalize_mode_id(mode)
    best = _best(case)
    passed = candidate.status == "pass"
    result_hash = _digest(
        {
            "query_id": case.query_id,
            "mode": scientific_mode_key(mode),
            "template_id": candidate.template_id,
            "status": candidate.status,
            "execution_ms": candidate.execution_ms,
        }
    )
    regret_ratio = None
    if passed and best.execution_ms > 0:
        regret_ratio = candidate.execution_ms / best.execution_ms
    evaluation_role = (
        FINITE_TEMPLATE_UPPER_BOUND_ROLE
        if run_kind in {"template_candidate", "template_oracle_summary"}
        else load_mode_registry(root)[normalize_mode_id(mode)].evaluation_role
    )
    static_status = "fail" if candidate.template_applicability == "contract_reject" else "pass"
    rejection_reasons = {candidate.reason: 1} if candidate.reason else {}
    return {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": f"E4_{case.query_id}_{mode}_{candidate.template_id}",
        "manifest_id": manifest_id,
        "manifest_hash": file_sha256(manifest_path),
        "experiment": "E4",
        "stage": "controlled_pairs_smoke",
        "run_kind": run_kind,
        "dataset": {"name": "synthetic_saas", "scale": dataset_scale, "seed": seed},
        "query": {
            "query_id": case.query_id,
            "path": case.query_path,
            "params": {"pair_id": case.pair_id, "parent": case.parent_name},
        },
        "policy": {
            "policy_id": "tenant_group",
            "policy_version": 0,
            "policy_sql_manifest_hash": file_sha256(root / "manifests" / "policies" / "synthetic_saas_policies.yaml"),
        },
        "context": {"context_id": "e4_smoke_ctx", "ctx_hash": _local_vector_hash(case)},
        "mode": mode,
        "template": {"template_id": candidate.template_id, "alternative": candidate.alternative},
        "template_applicability": {
            "status": candidate.template_applicability,
            "reason": candidate.reason,
        },
        "template_oracle": {
            "eligible_for_template_oracle": passed
            and candidate.template_applicability == "applicable",
            "template_oracle_exclusion_reason": None
            if passed and candidate.template_applicability == "applicable"
            else candidate.template_applicability,
        },
        "evaluation_role": evaluation_role,
        "pg": {
            "version": "not_executed_e4_pair_smoke",
            "gucs": {"jit": "off", "max_parallel_workers_per_gather": "0"},
        },
        "versions": {
            "policy": {"tenant_group": 0},
            "membership": {"group_membership": 0},
            "context": {"e4_smoke_ctx": 0},
            "trusted_state": {"local_greedy_rule": 1, "pair_contract": 1},
            "base": {"document": 0},
            "artifacts": {"auth_idx_or_mav_declared": 0},
        },
        "planner": {
            "level": "B",
            "planning_time_ms": 0.0,
            "generated_templates": len(case.candidates),
            "rejected_templates": 0 if passed else 1,
            "costed_templates": len([item for item in case.candidates if item.status == "pass"]),
            "rejection_reasons": rejection_reasons,
            "chosen_estimated_cost": candidate.execution_ms,
            "chosen_rank_vs_template_oracle": 1
            if candidate.template_id == best.template_id and passed
            else None,
            "local_feature_vector": dict(case.local_feature_vector),
            "parent_requirement_vector": dict(case.parent_requirement_vector),
            "disabled_components": [],
            "candidates": [],
            "delivered_sigma": {},
        },
        "static_verifier": {
            "status": static_status,
            "plan_hash": result_hash,
            "explain_path": None,
            "reasons": [candidate.reason] if candidate.reason else [],
        },
        "artifact_validation": {
            "status": "not_applicable",
            "action": "reject" if candidate.template_applicability == "contract_reject" else "execute",
            "expected_action": "reject" if candidate.template_applicability == "contract_reject" else "execute",
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
            "emitted_sql_path": case.query_path,
            "emitted_sql_hash": file_sha256(root / case.query_path),
            "normalized_sql_hash": result_hash,
        },
        "oracle_check": {
            "status": "match",
            "oracle_kind": "deterministic_e4_pair_smoke",
            "set_diff_left": 0,
            "set_diff_right": 0,
            "known_invalid_accepted": False,
            "known_valid_rejected": False,
        },
        "timing_ms": {
            "planning": 0.0,
            "execution": candidate.execution_ms,
            "verification": 0.0,
            "total": candidate.execution_ms,
        },
        "result": {"row_count": 100 if passed else 0, "result_hash": result_hash},
        "pg_metrics": {
            "shared_read_blocks": 0,
            "shared_hit_blocks": 0,
            "temp_read_blocks": 0,
            "temp_written_blocks": 0,
        },
        "counts": {
            "policy_evals": 100000 if candidate.template_id == "barrier_filter_v1" else 0,
            "residual_checks": 100 if "guard" in candidate.template_id and passed else 0,
            "candidate_rows": 100 if passed else 0,
            "authorized_rows": 50000,
            "artifact_lookups": 1
            if candidate.template_id in {"auth_index_enum_v1", "hybrid_intersect_v1", "mav_scan_v1"}
            else 0,
            "base_fetches": 100 if passed else 0,
        },
        "artifact_cost": {
            "query_only_ms": candidate.execution_ms,
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
        "e4_pair": {
            "pair_id": case.pair_id,
            "parent_label": case.parent_label,
            "parent_name": case.parent_name,
            "local_vector_id": case.local_vector_id,
            "local_vector_hash": _local_vector_hash(case),
            "local_greedy_local_choice": case.local_greedy_template_id,
            "admission_first_choice": case.admission_first_template_id,
            "best_template_id": best.template_id,
            "regret_ratio": regret_ratio,
            "pair_validity_check": "require_identical_local_feature_vector",
        },
        "status": candidate.status,
        "failure": None if candidate.reason is None else {"reason": candidate.reason},
    }


def _summary_record(
    root: Path,
    manifest_path: Path,
    manifest_id: str,
    case: E4Case,
    dataset_scale: str,
    seed: int,
) -> Dict[str, Any]:
    best = _best(case)
    chosen = _candidate_for(case, case.admission_first_template_id)
    excluded = [
        candidate
        for candidate in case.candidates
        if not (candidate.status == "pass" and candidate.template_applicability == "applicable")
    ]
    summary_payload = {
        "run_kind": "template_oracle_summary",
        "query_id": case.query_id,
        "context_id": "e4_smoke_ctx",
        "mode_under_test": ADMISSION_FIRST_MODE,
        "ranking_metric": "execution_time_ms",
        "eligible_templates": len(case.candidates) - len(excluded),
        "excluded_templates": _excluded_counts(excluded),
        "best_template_id": best.template_id,
        "best_execution_ms": best.execution_ms,
        "chosen_template_id": chosen.template_id,
        "chosen_execution_ms": chosen.execution_ms,
        "gap": chosen.execution_ms / best.execution_ms if best.execution_ms > 0 else 1.0,
    }
    scientific_summary_payload = {
        **summary_payload,
        "mode_under_test": scientific_mode_key(ADMISSION_FIRST_MODE),
    }
    record = _record(
        root=root,
        manifest_path=manifest_path,
        manifest_id=manifest_id,
        case=case,
        run_kind="template_oracle_summary",
        mode="template-oracle",
        candidate=best,
        dataset_scale=dataset_scale,
        seed=seed,
    )
    record["run_id"] = f"E4_{case.query_id}_template_oracle_summary"
    record["template_oracle_summary"] = summary_payload
    record["result"]["result_hash"] = _digest(scientific_summary_payload)
    return record


def _excluded_counts(excluded: Iterable[E4Candidate]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in excluded:
        key = item.template_applicability
        counts[key] = counts.get(key, 0) + 1
    return counts


def _local_vector_hash(case: E4Case) -> str:
    return _digest(case.local_feature_vector)


def _assert_pair_validity() -> None:
    for pair_id in sorted({case.pair_id for case in CASES}):
        pair_cases = [case for case in CASES if case.pair_id == pair_id]
        hashes = {_local_vector_hash(case) for case in pair_cases}
        local_choices = {case.local_greedy_template_id for case in pair_cases}
        if len(hashes) != 1:
            raise PostgresError(f"E4 pair {pair_id} has non-identical local feature vectors")
        if len(local_choices) != 1:
            raise PostgresError(f"E4 pair {pair_id} has non-identical LocalGreedy choices")


def _write_record(record: Mapping[str, Any], output_dir: Path) -> Path:
    issues = validate_raw_run_record(record)
    if issues:
        rendered = ", ".join(f"{issue.path}: {issue.message}" for issue in issues)
        raise PostgresError(f"E4 raw record failed schema validation: {rendered}")
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_mode = str(record["mode"]).replace("-", "_")
    safe_kind = str(record["run_kind"]).replace("-", "_")
    target = output_dir / f"{record['run_id']}_{safe_kind}_{safe_mode}.json"
    target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def run_e4_smoke(root: Path, manifest_path: Path, output_dir: Path) -> E4SmokeResult:
    manifest = _load_manifest(manifest_path)
    _validate_manifest(manifest_path, manifest)
    _assert_pair_validity()

    manifest_id = str(manifest["manifest_id"])
    dataset = manifest.get("dataset") or {}
    dataset_scale = str(dataset.get("scale", "1e5"))
    seed = int(dataset.get("seed", 45))

    raw_paths: list[Path] = []
    candidate_records = 0
    normal_records = 0
    summary_records = 0

    for case in CASES:
        for candidate in case.candidates:
            raw_paths.append(
                _write_record(
                    _record(
                        root=root,
                        manifest_path=manifest_path,
                        manifest_id=manifest_id,
                        case=case,
                        run_kind="template_candidate",
                        mode="template-oracle",
                        candidate=candidate,
                        dataset_scale=dataset_scale,
                        seed=seed,
                    ),
                    output_dir,
                )
            )
            candidate_records += 1

        for mode, template_id in (
            ("local-greedy", case.local_greedy_template_id),
            (ADMISSION_FIRST_MODE, case.admission_first_template_id),
        ):
            raw_paths.append(
                _write_record(
                    _record(
                        root=root,
                        manifest_path=manifest_path,
                        manifest_id=manifest_id,
                        case=case,
                        run_kind="normal_mode",
                        mode=mode,
                        candidate=_candidate_for(case, template_id),
                        dataset_scale=dataset_scale,
                        seed=seed,
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
                    case=case,
                    dataset_scale=dataset_scale,
                    seed=seed,
                ),
                output_dir,
            )
        )
        summary_records += 1

    return E4SmokeResult(
        raw_result_paths=raw_paths,
        candidate_records=candidate_records,
        normal_records=normal_records,
        summary_records=summary_records,
        pair_count=len({case.pair_id for case in CASES}),
    )
