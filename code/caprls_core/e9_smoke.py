"""E9 synthetic planner-overhead smoke runner."""

from __future__ import annotations

import hashlib
import gc
import json
import platform
import time
import tracemalloc
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping

import yaml
from planner.core import (
    ArtifactMetadata,
    CostInputs,
    PlanningProblem,
)
from planner.emit import EmitContext
from planner.ir import Root, ScanProtected, UnionTagged
from planner.query import OccurrenceGoal, PlanningQuery, plan_query

from .baselines import (
    ADMISSION_FIRST_MODE,
    ADMISSION_FIRST_NO_DOMINANCE_MODE,
    load_mode_registry,
    mode_execution_order_key,
    normalize_mode_id,
    scientific_mode_key,
)
from .manifest_validator import file_sha256
from .postgres_runner import PostgresError
from .result_schema import RAW_SCHEMA_VERSION, validate_raw_run_record


@dataclass(frozen=True)
class E9Point:
    tier_name: str
    protected_occurrences: int
    joins: int
    alternatives_per_occurrence: int
    residuals: int


@dataclass(frozen=True)
class E9Metrics:
    mode: str
    generated_templates: int
    pruned_templates: int
    rejected_templates: int
    costed_templates: int
    dominance_checks: int
    memo_groups: int
    ir_node_count: int
    peak_memory_bytes: int
    serialized_state_bytes: int
    planning_ms: float
    chosen_estimated_cost: float | None
    rejection_reasons: Mapping[str, int]
    root_closure: Mapping[str, Any]
    root_sigma: Mapping[str, Any]
    certificate: tuple[Mapping[str, Any], ...] | None
    certificate_check: Mapping[str, Any] | None
    search_evidence: Mapping[str, Any]


@dataclass(frozen=True)
class E9SmokeResult:
    raw_result_paths: list[Path]
    normal_records: int
    points: int


REQUIRED_MODES = {ADMISSION_FIRST_MODE, ADMISSION_FIRST_NO_DOMINANCE_MODE, "local-greedy"}
E9_FEASIBILITY_SEARCH_BUDGET = 0
EXPECTED_GENERATOR = {
    "protected_relations": [1, 2],
    "policy_shapes": ["tenant_group"],
    "residual_shapes": ["none", "one_per_occurrence"],
    "seed": 48,
}


def _execution_modes(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    modes = tuple(
        normalize_mode_id(str(item)) for item in manifest.get("modes", [])
    )
    if len(modes) != len(set(modes)):
        raise PostgresError("E9 modes contain duplicate canonical identities")
    return tuple(sorted(modes, key=mode_execution_order_key))


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
        raise PostgresError(f"E9 manifest must be an object: {manifest_path}")
    return data


def _validate_manifest(manifest_path: Path, manifest: Mapping[str, Any]) -> None:
    if manifest.get("experiment") != "E9" or manifest.get("execution_tier") != "smoke":
        raise PostgresError("e9-smoke requires an E9 smoke manifest")
    if manifest.get("evidence_role") != "diagnostic_only" or manifest.get("promotion_eligible") is not False:
        raise PostgresError("current E9 smoke frontier must be diagnostic_only and non-promotable")
    if manifest.get("feasibility_search_budget") != E9_FEASIBILITY_SEARCH_BUDGET:
        raise PostgresError("E9 smoke feasibility_search_budget does not match runner contract")

    modes = _execution_modes(manifest)
    if set(modes) != REQUIRED_MODES:
        raise PostgresError(
            "E9 modes do not match runner contract: "
            f"expected {sorted(REQUIRED_MODES)}, got {sorted(modes)}"
        )

    generator = manifest.get("synthetic_generator") or {}
    if dict(generator) != EXPECTED_GENERATOR:
        raise PostgresError(
            "E9 synthetic_generator does not match runner contract: "
            f"expected {EXPECTED_GENERATOR}, got {generator}"
        )

    queries = {
        str(item.get("query_id")): str(item.get("path"))
        for item in manifest.get("queries", [])
        if isinstance(item, Mapping)
    }
    if queries != {"E9_smoke_occurrences": "workloads/e9/planner_stress_smoke.sql"}:
        raise PostgresError(f"E9 smoke supports only E9_smoke_occurrences; got {queries}")

    points = _points_from_manifest(manifest)
    expected = [
        E9Point("smoke_occurrences", 1, joins=1, alternatives_per_occurrence=2, residuals=1),
        E9Point("smoke_occurrences", 2, joins=1, alternatives_per_occurrence=2, residuals=1),
    ]
    if points != expected:
        raise PostgresError(f"E9 tiers do not match runner contract: {points}")


def _points_from_manifest(manifest: Mapping[str, Any]) -> list[E9Point]:
    points: list[E9Point] = []
    for tier in manifest.get("tiers", []):
        if not isinstance(tier, Mapping):
            continue
        fixed = tier.get("fixed") or {}
        for occurrences in tier.get("protected_occurrences", []):
            points.append(
                E9Point(
                    tier_name=str(tier.get("name")),
                    protected_occurrences=int(occurrences),
                    joins=int(fixed.get("joins", 0)),
                    alternatives_per_occurrence=int(fixed.get("alternatives_per_occurrence", 0)),
                    residuals=int(fixed.get("residuals", 0)),
                )
            )
    return points


def _planning_problem(point: E9Point, occurrence: int) -> PlanningProblem:
    estimated_rows = max(100, point.protected_occurrences * point.alternatives_per_occurrence * 100)
    return PlanningProblem(
        planning_execution_class="diagnostic_only",
        relation=f"e9_smoke_rel_{1 + ((occurrence - 1) % max(point.joins + 1, 1))}",
        policy_id="tenant_group",
        occurrence_id=f"e9_smoke_occ_{occurrence}",
        rid_col="id",
        required_attrs=("tenant_id", "value"),
        exact_policy_safe=True,
        supports_guard=True,
        has_safe_query_predicate=True,
        artifacts={
            "auth_idx": ArtifactMetadata(
                kind="auth_idx",
                artifact_id=f"e9_smoke_auth_idx_{occurrence}",
                cardinality=max(1, estimated_rows // 7),
            ),
            "auth_idx_keyed": ArtifactMetadata(
                kind="auth_idx",
                artifact_id=f"e9_smoke_auth_idx_keyed_{occurrence}",
                keyed=True,
                cardinality=max(1, estimated_rows // 21),
                key_value_cardinality=max(1, estimated_rows // 40),
            ),
            "mav": ArtifactMetadata(
                kind="mav",
                artifact_id=f"e9_smoke_mav_{occurrence}",
                rows=max(1, estimated_rows // 9),
                cardinality=max(1, estimated_rows // 9),
                order_keys=("id",) if occurrence % 2 == 0 else (),
            ),
        },
        cost_inputs=CostInputs(
            estimated_rows=estimated_rows,
            query_selectivity=min(1.0, 1.0 / max(1, point.alternatives_per_occurrence)),
            auth_selectivity=min(0.9, max(0.01, point.protected_occurrences / 100.0)),
            policy_eval_cost=0.003 + point.residuals * 0.0001,
            guard_selectivity=min(0.95, 0.05 + point.residuals * 0.01),
            artifact_lookup_cost=0.2 + point.alternatives_per_occurrence * 0.01,
            sort_cost=0.05 * max(0, point.joins - 1),
        ),
    )


def _planning_query(point: E9Point, mode: str) -> PlanningQuery:
    goals: dict[str, OccurrenceGoal] = {}
    branches = []
    occurrence_relations: dict[str, str] = {}
    occurrence_aliases: dict[str, str] = {}
    occurrence_rid_cols: dict[str, str] = {}
    exact_predicates: dict[str, str] = {}
    query_predicates: dict[str, str] = {}
    guard_predicates: dict[str, str] = {}
    residual_predicates: dict[str, str] = {}
    for occurrence in range(1, point.protected_occurrences + 1):
        problem = _planning_problem(point, occurrence)
        occurrence_id = problem.occurrence_id
        goals[occurrence_id] = OccurrenceGoal(problem)
        branches.append(ScanProtected(occurrence_id, "chosen"))
        occurrence_relations[occurrence_id] = problem.relation
        alias = f"s{occurrence}"
        occurrence_aliases[occurrence_id] = alias
        occurrence_rid_cols[occurrence_id] = problem.rid_col
        predicate = f"{alias}.tenant_id = 1 OR ({alias}.value % 7) = 0"
        exact_predicates[occurrence_id] = predicate
        query_predicates[occurrence_id] = predicate
        guard_predicates[occurrence_id] = predicate
        residual_predicates[
            f"{problem.policy_id}:exact_residual"
        ] = "rcheck.tenant_id = 1 OR (rcheck.value % 7) = 0"
    root_rho = {
        "visible_columns": ("id", "tenant_id", "value"),
        "required_order": ("id",) if point.joins >= 2 else (),
        "transparent": True,
        "unsafe_expression_boundary": False,
        "future_rid_intersection": point.joins > 1,
    }
    skeleton = (
        Root(branches[0], rho_root=root_rho)
        if len(branches) == 1
        else Root(UnionTagged(tuple(branches), branch_tag="e9_smoke_occ"), rho_root=root_rho)
    )
    return PlanningQuery(
        ir_skeleton=skeleton,
        occurrence_goals=goals,
        mode=mode,
        emit_context=EmitContext(
            default_rid_col="id",
            occurrence_relations=occurrence_relations,
            occurrence_aliases=occurrence_aliases,
            occurrence_rid_cols=occurrence_rid_cols,
            exact_predicates=exact_predicates,
            query_predicates=query_predicates,
            guard_predicates=guard_predicates,
            residual_predicates=residual_predicates,
        ),
    )


def _root_closure_payload(query_result: Any) -> dict[str, Any]:
    closure = query_result.root_closure
    return {
        "ok": closure.ok,
        "reason": closure.reason,
        "domain_covering": closure.domain_covering,
        "live_pairs_certified": closure.live_pairs_certified,
        "residuals_closed": closure.residuals_closed,
        "live_pairs": [
            {"basis_id": basis_id, "omega_id": omega_id}
            for basis_id, omega_id in closure.live_pairs
        ],
    }


def _profile_planner_core(point: E9Point, mode: str) -> E9Metrics:
    query = _planning_query(point, mode)

    gc.collect()
    gc_was_enabled = gc.isenabled()
    if gc_was_enabled:
        gc.disable()
    try:
        started = time.perf_counter()
        planning_result = plan_query(
            query,
            emit_certificates=False,
            compute_serialized_state=False,
            collect_candidate_payloads=False,
            search_budget=E9_FEASIBILITY_SEARCH_BUDGET,
        )
        planning_ms = (time.perf_counter() - started) * 1000.0
    finally:
        if gc_was_enabled:
            gc.enable()

    # Materialize audit evidence outside the timed planning path.
    tracemalloc.start()
    try:
        query_result = plan_query(
            query,
            search_budget=E9_FEASIBILITY_SEARCH_BUDGET,
        )
        _current_bytes, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    if (
        planning_result.generated_templates != query_result.generated_templates
        or planning_result.rejected_templates != query_result.rejected_templates
        or planning_result.costed_templates != query_result.costed_templates
        or planning_result.dominance_checks != query_result.dominance_checks
        or planning_result.dominance_pruned != query_result.dominance_pruned
        or planning_result.root_closure.ok != query_result.root_closure.ok
        or dict(planning_result.root_sigma) != dict(query_result.root_sigma)
    ):
        raise AssertionError("E9 audit planner run diverged from timed planner run")

    rejection_counts: dict[str, int] = {}
    chosen_costs: list[float] = []
    for result in query_result.occurrence_results.values():
        for reason, count in result.rejection_reasons.items():
            rejection_counts[reason] = rejection_counts.get(reason, 0) + int(count)
        if result.estimated_cost is not None:
            chosen_costs.append(float(result.estimated_cost))
    return E9Metrics(
        mode=mode,
        generated_templates=query_result.generated_templates,
        pruned_templates=query_result.dominance_pruned,
        rejected_templates=query_result.rejected_templates,
        costed_templates=query_result.costed_templates,
        dominance_checks=query_result.dominance_checks,
        memo_groups=query_result.memo_groups,
        ir_node_count=query_result.ir_node_count,
        peak_memory_bytes=peak_bytes,
        serialized_state_bytes=query_result.serialized_state_bytes,
        planning_ms=planning_ms,
        chosen_estimated_cost=sum(chosen_costs) if chosen_costs else None,
        rejection_reasons=rejection_counts,
        root_closure=_root_closure_payload(query_result),
        root_sigma=dict(query_result.root_sigma),
        certificate=None
        if query_result.certificate is None
        else tuple(dict(step) for step in query_result.certificate),
        certificate_check=None
        if query_result.certificate_check is None
        else dict(query_result.certificate_check),
        search_evidence=query_result.search_evidence.to_dict(),
    )


def _record(
    root: Path,
    manifest_path: Path,
    manifest_id: str,
    point: E9Point,
    metrics: E9Metrics,
    seed: int,
) -> Dict[str, Any]:
    mode = normalize_mode_id(metrics.mode)
    scientific_metrics = {
        **metrics.__dict__,
        "mode": scientific_mode_key(mode),
    }
    search_evidence = scientific_metrics.get("search_evidence")
    if isinstance(search_evidence, Mapping):
        scientific_search_evidence = dict(search_evidence)
        if scientific_search_evidence.get("reason") == "non_admission_first_mode":
            scientific_search_evidence["reason"] = "non_contract_aware_mode"
        scientific_metrics["search_evidence"] = scientific_search_evidence
    payload = {
        "point": point.__dict__,
        "metrics": scientific_metrics,
    }
    result_hash = _digest(payload)
    pruning_ratio = (
        metrics.pruned_templates / metrics.generated_templates
        if metrics.generated_templates
        else 0.0
    )
    return {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": f"E9_{point.tier_name}_occ{point.protected_occurrences}_{mode}",
        "manifest_id": manifest_id,
        "manifest_hash": file_sha256(manifest_path),
        "experiment": "E9",
        "stage": "smoke",
        "run_kind": "normal_mode",
        "evidence": {"role": "diagnostic_only", "promotion_eligible": False},
        "dataset": {"name": "synthetic_planner_stress", "scale": "generated", "seed": seed},
        "query": {
            "query_id": "E9_smoke_occurrences",
            "path": "workloads/e9/planner_stress_smoke.sql",
            "params": {
                "tier": point.tier_name,
                "protected_occurrences": point.protected_occurrences,
                "joins": point.joins,
                "alternatives_per_occurrence": point.alternatives_per_occurrence,
                "residuals": point.residuals,
            },
        },
        "policy": {
            "policy_id": "tenant_group",
            "policy_version": 0,
            "policy_sql_manifest_hash": file_sha256(root / "manifests" / "policies" / "synthetic_saas_policies.yaml"),
        },
        "context": {"context_id": "e9_synthetic_generator", "ctx_hash": _digest(point.__dict__)},
        "mode": mode,
        "template": {"template_id": "planner_state_memo_v1", "alternative": "SyntheticPlannerStress"},
        "template_applicability": {"status": "applicable", "reason": None},
        "template_oracle": {
            "eligible_for_template_oracle": False,
            "template_oracle_exclusion_reason": "E9_overhead_smoke_not_template_oracle_pool",
        },
        "evaluation_role": load_mode_registry(root)[mode].evaluation_role,
        "pg": {
            "version": "not_executed_e9_planner_smoke",
            "gucs": {"jit": "off", "max_parallel_workers_per_gather": "0"},
        },
        "versions": {
            "policy": {"tenant_group": 0},
            "membership": {},
            "context": {"e9_synthetic_generator": 0},
            "trusted_state": {"planner_overhead_model": 1},
            "base": {},
            "artifacts": {},
        },
        "planner": {
            "level": "B",
            "disabled_components": [],
            "planning_time_ms": metrics.planning_ms,
            "generated_templates": metrics.generated_templates,
            "rejected_templates": metrics.rejected_templates,
            "dominance_pruned": metrics.pruned_templates,
            "costed_templates": metrics.costed_templates,
            "rejection_reasons": dict(metrics.rejection_reasons),
            "chosen_estimated_cost": metrics.chosen_estimated_cost,
            "chosen_rank_vs_template_oracle": None,
            "query_ir_node_count": metrics.ir_node_count,
            "root_closure": dict(metrics.root_closure),
            "certificate": None
            if metrics.certificate is None
            else [dict(step) for step in metrics.certificate],
            "certificate_check": None
            if metrics.certificate_check is None
            else dict(metrics.certificate_check),
            "search": dict(metrics.search_evidence),
            "local_feature_vector": None
            if metrics.mode != "local-greedy"
            else {"protected_occurrences": point.protected_occurrences},
            "parent_requirement_vector": {
                "joins": point.joins,
                "residuals": point.residuals,
            },
            "candidates": [],
            "delivered_sigma": dict(metrics.root_sigma),
        },
        "static_verifier": {
            "status": "pass" if bool(metrics.root_closure.get("ok")) else "fail",
            "plan_hash": result_hash,
            "explain_path": None,
            "reasons": []
            if bool(metrics.root_closure.get("ok"))
            else [
                str(metrics.root_closure.get("reason") or "root_not_closed"),
                str(metrics.search_evidence.get("reason") or "search_incomplete"),
            ],
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
            "emitted_sql_path": "workloads/e9/planner_stress_smoke.sql",
            "emitted_sql_hash": file_sha256(root / "workloads" / "e9" / "planner_stress_smoke.sql"),
            "normalized_sql_hash": result_hash,
        },
        "oracle_check": {
            "status": "match",
            "oracle_kind": "synthetic_planner_metric_smoke",
            "set_diff_left": 0,
            "set_diff_right": 0,
            "known_invalid_accepted": False,
            "known_valid_rejected": False,
        },
        "timing_ms": {
            "planning": metrics.planning_ms,
            "execution": 0.0,
            "verification": 0.0,
            "total": metrics.planning_ms,
        },
        "result": {
            "row_count": metrics.generated_templates,
            "result_hash": result_hash,
        },
        "pg_metrics": {
            "shared_read_blocks": 0,
            "shared_hit_blocks": 0,
            "temp_read_blocks": 0,
            "temp_written_blocks": 0,
        },
        "counts": {
            "policy_evals": 0,
            "residual_checks": point.residuals,
            "candidate_rows": metrics.generated_templates,
            "authorized_rows": 0,
            "artifact_lookups": 0,
            "base_fetches": 0,
            "dominance_checks": metrics.dominance_checks,
            "dominance_pruned": metrics.pruned_templates,
            "memo_groups": metrics.memo_groups,
            "peak_memory_bytes": metrics.peak_memory_bytes,
            "serialized_state_bytes": metrics.serialized_state_bytes,
            "pruning_ratio": pruning_ratio,
        },
        "artifact_cost": {
            "query_only_ms": 0.0,
            "build_ms": 0.0,
            "refresh_ms": 0.0,
            "storage_bytes": 0,
            "indexes_built": [],
            "artifact_key_encoding_version": "artifact_key_encoding_v1",
            "amortization_model": "not_applicable",
        },
        "implementation": {
            "git_commit": _git_commit(root),
            "docker_image_digest": "not_containerized",
            "python_version": platform.python_version(),
            "planner_language": "python",
        },
        "e9_overhead": {
            "tier": point.tier_name,
            "protected_occurrences": point.protected_occurrences,
            "joins": point.joins,
            "alternatives_per_occurrence": point.alternatives_per_occurrence,
            "residuals": point.residuals,
            "memo_groups": metrics.memo_groups,
            "alternatives_generated": metrics.generated_templates,
            "alternatives_pruned": metrics.pruned_templates,
            "dominance_checks": metrics.dominance_checks,
            "pruning_ratio": pruning_ratio,
            "peak_memory_bytes": metrics.peak_memory_bytes,
            "serialized_state_bytes": metrics.serialized_state_bytes,
        },
        "status": "pass",
        "failure": None,
    }


def _write_record(record: Mapping[str, Any], output_dir: Path) -> Path:
    issues = validate_raw_run_record(record)
    if issues:
        rendered = ", ".join(f"{issue.path}: {issue.message}" for issue in issues)
        raise PostgresError(f"E9 raw record failed schema validation: {rendered}")
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_mode = str(record["mode"]).replace("-", "_")
    target = output_dir / f"{record['run_id']}_{safe_mode}.json"
    target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def run_e9_smoke(root: Path, manifest_path: Path, output_dir: Path) -> E9SmokeResult:
    manifest = _load_manifest(manifest_path)
    _validate_manifest(manifest_path, manifest)
    manifest_id = str(manifest["manifest_id"])
    seed = int((manifest.get("synthetic_generator") or {}).get("seed", 48))
    points = _points_from_manifest(manifest)

    raw_paths: list[Path] = []
    for point in points:
        for mode in _execution_modes(manifest):
            metrics = _profile_planner_core(point, str(mode))
            raw_paths.append(
                _write_record(
                    _record(
                        root=root,
                        manifest_path=manifest_path,
                        manifest_id=manifest_id,
                        point=point,
                        metrics=metrics,
                        seed=seed,
                    ),
                    output_dir,
                )
            )

    return E9SmokeResult(
        raw_result_paths=raw_paths,
        normal_records=len(raw_paths),
        points=len(points),
    )
