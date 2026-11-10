"""E9 tiered planner-overhead study runner."""

from __future__ import annotations

import hashlib
import gc
import json
import platform
import time
import tracemalloc
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

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
from .e2_smoke import _run_sql_script
from .manifest_validator import file_sha256, scientific_manifest_hash
from .postgres_runner import PostgresEnv, PostgresError, init_db, run_psql_command
from .repetitions import RepetitionRun, attach_repetition, iter_repetitions, protocol_from_manifest
from .result_schema import RAW_SCHEMA_VERSION, validate_raw_run_record


@dataclass(frozen=True)
class E9StudyPoint:
    tier_name: str
    protected_occurrences: int
    joins: int
    alternatives_per_occurrence: int
    residuals: int


@dataclass(frozen=True)
class E9StudyMetrics:
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
    template_oracle_rank: Optional[int]
    execution_ms: float = 0.0
    postgres_planning_ms: float = 0.0
    metrics_source: str = "modeled"
    chosen_estimated_cost: Optional[float] = None
    rejection_reasons: Optional[Mapping[str, int]] = None
    root_closure: Mapping[str, Any] | None = None
    root_sigma: Mapping[str, Any] | None = None
    certificate: tuple[Mapping[str, Any], ...] | None = None
    certificate_check: Mapping[str, Any] | None = None
    search_evidence: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class E9StudyResult:
    raw_result_paths: list[Path]
    normal_records: int
    points: int
    max_planning_ms: float
    max_generated_templates: int


REQUIRED_MODES = {ADMISSION_FIRST_MODE, ADMISSION_FIRST_NO_DOMINANCE_MODE, "local-greedy"}
E9_STUDY_ROWS_PER_RELATION = 10_000
# E9's current legacy stress fixture is not root-closed under the typed rho
# rules.  An unbounded feasibility repair would have 11**32 combinations at
# the largest point.  Keep this evidence path fail-closed and diagnostic until
# a root-closed typed E9 fixture is introduced; the zero budget is recorded as
# SearchIncomplete and cannot support a completeness/optimality claim.
E9_FEASIBILITY_SEARCH_BUDGET = 0
EXPECTED_GENERATOR = {
    "protected_relations": [1, 2, 4, 8, 16],
    "policy_shapes": ["tenant_group", "purpose_region", "guard_residual"],
    "residual_shapes": ["none", "one_per_occurrence", "branch_tagged"],
    "seed": 48,
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
        raise PostgresError(f"E9 overhead manifest must be an object: {manifest_path}")
    return data


def _points_from_manifest(manifest: Mapping[str, Any]) -> list[E9StudyPoint]:
    points: list[E9StudyPoint] = []
    for tier in manifest.get("tiers", []):
        if not isinstance(tier, Mapping):
            continue
        tier_name = str(tier.get("name"))
        fixed = tier.get("fixed") or {}
        if "points" in tier:
            for point in tier.get("points", []):
                if not isinstance(point, Mapping):
                    continue
                points.append(
                    E9StudyPoint(
                        tier_name=tier_name,
                        protected_occurrences=int(point["protected_occurrences"]),
                        joins=int(point["joins"]),
                        alternatives_per_occurrence=int(point["alternatives_per_occurrence"]),
                        residuals=int(point["residuals"]),
                    )
                )
        elif "protected_occurrences" in tier:
            for occurrences in tier.get("protected_occurrences", []):
                points.append(
                    E9StudyPoint(
                        tier_name=tier_name,
                        protected_occurrences=int(occurrences),
                        joins=int(fixed["joins"]),
                        alternatives_per_occurrence=int(fixed["alternatives_per_occurrence"]),
                        residuals=int(fixed["residuals"]),
                    )
                )
        elif "alternatives_per_occurrence" in tier:
            for alternatives in tier.get("alternatives_per_occurrence", []):
                points.append(
                    E9StudyPoint(
                        tier_name=tier_name,
                        protected_occurrences=int(fixed["protected_occurrences"]),
                        joins=int(fixed["joins"]),
                        alternatives_per_occurrence=int(alternatives),
                        residuals=int(fixed["residuals"]),
                    )
                )
    return points


def _validate_manifest(manifest_path: Path, manifest: Mapping[str, Any]) -> None:
    if manifest.get("experiment") != "E9" or manifest.get("execution_tier") != "main":
        raise PostgresError("e9-study requires an E9 main manifest")
    if manifest.get("stage") != "tiered":
        raise PostgresError("e9-study requires stage: tiered")
    if manifest.get("evidence_role") != "diagnostic_only" or manifest.get("promotion_eligible") is not False:
        raise PostgresError("current E9 study frontier must be diagnostic_only and non-promotable")
    if manifest.get("feasibility_search_budget") != E9_FEASIBILITY_SEARCH_BUDGET:
        raise PostgresError("E9 study feasibility_search_budget does not match runner contract")

    modes = {normalize_mode_id(str(item)) for item in manifest.get("modes", [])}
    if modes != REQUIRED_MODES:
        raise PostgresError(
            "E9 study modes do not match runner contract: "
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
    if queries != {"E9_tiered_overhead": "workloads/e9/planner_overhead.sql"}:
        raise PostgresError(f"E9 study supports only E9_tiered_overhead; got {queries}")

    points = _points_from_manifest(manifest)
    if len(points) != 15:
        raise PostgresError(f"E9 tiered manifest must produce 15 points; got {len(points)}")
    if max(point.protected_occurrences for point in points) != 32:
        raise PostgresError("E9 tiered manifest must include protected_occurrences=32")


def _planning_problem(point: E9StudyPoint, occurrence: int) -> PlanningProblem:
    estimated_rows = max(100, point.protected_occurrences * point.alternatives_per_occurrence * 100)
    return PlanningProblem(
        planning_execution_class="diagnostic_only",
        relation=f"e9_rel_{1 + ((occurrence - 1) % max(point.joins + 1, 1))}",
        policy_id="tenant_group",
        occurrence_id=f"e9_occ_{occurrence}",
        rid_col="id",
        required_attrs=("tenant_id", "value"),
        exact_policy_safe=True,
        supports_guard=True,
        has_safe_query_predicate=True,
        artifacts={
            "auth_idx": ArtifactMetadata(
                kind="auth_idx",
                artifact_id=f"e9_auth_idx_{occurrence}",
                cardinality=max(1, estimated_rows // 7),
            ),
            "auth_idx_keyed": ArtifactMetadata(
                kind="auth_idx",
                artifact_id=f"e9_auth_idx_keyed_{occurrence}",
                keyed=True,
                cardinality=max(1, estimated_rows // 21),
            ),
            "mav": ArtifactMetadata(
                kind="mav",
                artifact_id=f"e9_mav_{occurrence}",
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
            sort_cost=0.05 * max(0, point.joins - 4),
        ),
    )


def _planning_query(point: E9StudyPoint, mode: str) -> PlanningQuery:
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
        alias = f"r{occurrence}"
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
        "required_order": ("id",) if point.joins >= 8 else (),
        "transparent": True,
        "unsafe_expression_boundary": point.residuals > point.protected_occurrences,
        "future_rid_intersection": point.joins > 4,
    }
    skeleton = (
        Root(branches[0], rho_root=root_rho)
        if len(branches) == 1
        else Root(UnionTagged(tuple(branches), branch_tag="e9_occ"), rho_root=root_rho)
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


def _profile_planner_core(point: E9StudyPoint, mode: str) -> E9StudyMetrics:
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
            emit_sql_text=False,
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
    return E9StudyMetrics(
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
        template_oracle_rank=query_result.template_oracle_rank,
        chosen_estimated_cost=sum(chosen_costs) if chosen_costs else None,
        rejection_reasons=rejection_counts,
        metrics_source="planning_query_profiled",
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


def _prepare_pg_stress_schema(
    root: Path,
    pg_env: PostgresEnv,
    relations: int = 16,
    rows_per_relation: int = E9_STUDY_ROWS_PER_RELATION,
) -> str:
    init_db(root, pg_env)
    drops = "\n".join(
        f"DROP TABLE IF EXISTS public.e9_rel_{idx};" for idx in range(relations, 0, -1)
    )
    creates = []
    for idx in range(1, relations + 1):
        creates.append(
            f"""
CREATE TABLE public.e9_rel_{idx} (
  id integer PRIMARY KEY,
  tenant_id integer NOT NULL,
  value integer NOT NULL
	);
	INSERT INTO public.e9_rel_{idx}(id, tenant_id, value)
	SELECT g, 1 + ((g + {idx}) % 7), (g * {idx}) % 101
	FROM generate_series(1, {rows_per_relation}) AS g;
	CREATE INDEX e9_rel_{idx}_tenant_idx ON public.e9_rel_{idx}(tenant_id, id);
	ANALYZE public.e9_rel_{idx};
"""
        )
    _run_sql_script("\\set ON_ERROR_STOP on\n" + drops + "\n".join(creates), pg_env)
    return run_psql_command("SHOW server_version;", pg_env)


def _stress_sql(point: E9StudyPoint, mode: str) -> str:
    rel_count = max(1, min(point.joins + 1, 16))
    joins = [f"public.e9_rel_1 r1"]
    for idx in range(2, rel_count + 1):
        joins.append(f"JOIN public.e9_rel_{idx} r{idx} ON r{idx}.id = r1.id")

    if mode == "local-greedy":
        filters = []
        for occ in range(1, point.protected_occurrences + 1):
            rel_idx = 1 + ((occ - 1) % rel_count)
            filters.append(f"(r{rel_idx}.tenant_id = 1 OR (r{rel_idx}.value % 7) = 0)")
        where = " AND ".join(filters) if filters else "true"
        return f"""
SELECT count(*)
FROM {' '.join(joins)}
WHERE {where};
"""

    ctes = []
    auth_joins = []
    for occ in range(1, point.protected_occurrences + 1):
        rel_idx = 1 + ((occ - 1) % rel_count)
        ctes.append(
            f"""
p{occ} AS MATERIALIZED (
  SELECT id
  FROM public.e9_rel_{rel_idx}
  WHERE tenant_id = 1 OR (value % 7) = 0
)"""
        )
        auth_joins.append(f"JOIN p{occ} ON p{occ}.id = r{rel_idx}.id")

    return f"""
WITH {','.join(ctes)}
SELECT count(*)
FROM {' '.join(joins)}
{' '.join(auth_joins)};
"""


def _extract_explain_times(stdout: str) -> tuple[float, float]:
    start = stdout.find("[")
    end = stdout.rfind("]")
    if start < 0 or end < start:
        raise PostgresError(f"E9 EXPLAIN did not emit JSON:\n{stdout}")
    payload = json.loads(stdout[start : end + 1])
    if not payload:
        raise PostgresError(f"E9 EXPLAIN JSON payload is empty:\n{stdout}")
    item = payload[0]
    return float(item.get("Planning Time", 0.0)), float(item.get("Execution Time", 0.0))


def _postgres_metrics(point: E9StudyPoint, mode: str, pg_env: PostgresEnv) -> E9StudyMetrics:
    profiled = _profile_planner_core(point, mode)
    sql = "EXPLAIN (ANALYZE, FORMAT JSON, TIMING OFF, SUMMARY ON) " + _stress_sql(point, mode)
    postgres_planning_ms, execution_ms = _extract_explain_times(run_psql_command(sql, pg_env))
    return E9StudyMetrics(
        mode=profiled.mode,
        generated_templates=profiled.generated_templates,
        pruned_templates=profiled.pruned_templates,
        rejected_templates=profiled.rejected_templates,
        costed_templates=profiled.costed_templates,
        dominance_checks=profiled.dominance_checks,
        memo_groups=profiled.memo_groups,
        ir_node_count=profiled.ir_node_count,
        peak_memory_bytes=profiled.peak_memory_bytes,
        serialized_state_bytes=profiled.serialized_state_bytes,
        planning_ms=profiled.planning_ms,
        template_oracle_rank=profiled.template_oracle_rank,
        execution_ms=execution_ms,
        postgres_planning_ms=postgres_planning_ms,
        chosen_estimated_cost=profiled.chosen_estimated_cost,
        rejection_reasons=profiled.rejection_reasons,
        root_closure=profiled.root_closure,
        root_sigma=profiled.root_sigma,
        certificate=profiled.certificate,
        certificate_check=profiled.certificate_check,
        metrics_source="planning_query_profiled_plus_postgres_explain",
    )


def _record(
    root: Path,
    manifest_path: Path,
    manifest_id: str,
    point: E9StudyPoint,
    metrics: E9StudyMetrics,
    seed: int,
    rows_per_relation: int = E9_STUDY_ROWS_PER_RELATION,
    pg_version: str = "not_executed_e9_tiered_overhead",
    repetition: Optional[RepetitionRun] = None,
) -> Dict[str, Any]:
    mode = normalize_mode_id(metrics.mode)
    record_metrics = {**metrics.__dict__, "mode": mode}
    scientific_metrics = {
        **record_metrics,
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
        "metrics": record_metrics,
    }
    result_hash = _digest(
        {
            "point": point.__dict__,
            "metrics": scientific_metrics,
        }
    )
    local_feature_vector = None
    if metrics.mode == "local-greedy":
        local_feature_vector = {"protected_occurrences": point.protected_occurrences}
    parent_requirement_vector = {
        "joins": point.joins,
        "residuals": point.residuals,
    }
    static_plan_hash = _digest(
        {
            "point": point.__dict__,
            "mode": scientific_mode_key(mode),
            "generated_templates": metrics.generated_templates,
            "rejected_templates": metrics.rejected_templates,
            "dominance_pruned": metrics.pruned_templates,
            "costed_templates": metrics.costed_templates,
            "chosen_rank_vs_template_oracle": metrics.template_oracle_rank,
            "local_feature_vector": local_feature_vector,
            "parent_requirement_vector": parent_requirement_vector,
        }
    )
    pruning_ratio = (
        metrics.pruned_templates / metrics.generated_templates
        if metrics.generated_templates
        else 0.0
    )
    record = {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": f"E9_{point.tier_name}_occ{point.protected_occurrences}_alt{point.alternatives_per_occurrence}_{mode}",
        "manifest_id": manifest_id,
        "manifest_hash": file_sha256(manifest_path),
        "experiment": "E9",
        "stage": "tiered",
        "run_kind": "normal_mode",
        "evidence": {"role": "diagnostic_only", "promotion_eligible": False},
        "dataset": {"name": "synthetic_planner_stress", "scale": "generated", "seed": seed},
        "query": {
            "query_id": "E9_tiered_overhead",
            "path": "workloads/e9/planner_overhead.sql",
            "params": {
                "tier": point.tier_name,
                "protected_occurrences": point.protected_occurrences,
                "joins": point.joins,
                "alternatives_per_occurrence": point.alternatives_per_occurrence,
                "residuals": point.residuals,
                "rows_per_relation": rows_per_relation,
            },
        },
        "policy": {
            "policy_id": "tenant_group",
            "policy_version": 0,
            "policy_sql_manifest_hash": file_sha256(root / "manifests" / "policies" / "synthetic_saas_policies.yaml"),
        },
        "context": {"context_id": "e9_tiered_generator", "ctx_hash": _digest(point.__dict__)},
        "mode": mode,
        "template": {"template_id": "planner_state_memo_v1", "alternative": "SyntheticPlannerStress"},
        "template_applicability": {"status": "applicable", "reason": None},
        "template_oracle": {
            "eligible_for_template_oracle": bool(metrics.template_oracle_rank),
            "template_oracle_exclusion_reason": None
            if metrics.template_oracle_rank
            else "local_greedy_not_ranked_against_template_oracle_subset",
        },
        "evaluation_role": load_mode_registry(root)[mode].evaluation_role,
        "pg": {
            "version": pg_version,
            "gucs": {"jit": "off", "max_parallel_workers_per_gather": "0"},
        },
        "versions": {
            "policy": {"tenant_group": 0},
            "membership": {},
            "context": {"e9_tiered_generator": 0},
            "trusted_state": {"planner_core_profile": 1, "postgres_planning_probe": 1},
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
            "rejection_reasons": dict(metrics.rejection_reasons or {}),
            "chosen_estimated_cost": metrics.chosen_estimated_cost,
            "chosen_rank_vs_template_oracle": metrics.template_oracle_rank,
            "query_ir_node_count": metrics.ir_node_count,
            "root_closure": dict(metrics.root_closure or {}),
            "certificate": None
            if metrics.certificate is None
            else [dict(step) for step in metrics.certificate],
            "certificate_check": None
            if metrics.certificate_check is None
            else dict(metrics.certificate_check),
            "search": dict(metrics.search_evidence or {}),
            "local_feature_vector": local_feature_vector,
            "parent_requirement_vector": parent_requirement_vector,
            "candidates": [],
            "delivered_sigma": dict(metrics.root_sigma or {}),
        },
        "static_verifier": {
            "status": "pass" if bool((metrics.root_closure or {}).get("ok")) else "fail",
            "plan_hash": static_plan_hash,
            "explain_path": None,
            "reasons": []
            if bool((metrics.root_closure or {}).get("ok"))
            else [
                str((metrics.root_closure or {}).get("reason") or "root_not_closed"),
                str((metrics.search_evidence or {}).get("reason") or "search_incomplete"),
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
            "emitted_sql_path": "workloads/e9/planner_overhead.sql",
            "emitted_sql_hash": file_sha256(root / "workloads" / "e9" / "planner_overhead.sql"),
            "normalized_sql_hash": scientific_manifest_hash(manifest_path),
        },
        "oracle_check": {
            "status": "match",
            "oracle_kind": "synthetic_planner_overhead_tiered",
            "set_diff_left": 0,
            "set_diff_right": 0,
            "known_invalid_accepted": False,
            "known_valid_rejected": False,
        },
        "timing_ms": {
            "planning": metrics.planning_ms,
            "execution": metrics.execution_ms,
            "verification": 0.0,
            "total": metrics.planning_ms + metrics.execution_ms,
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
            "postgres_planning_ms": metrics.postgres_planning_ms,
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
            "query_only_ms": metrics.planning_ms + metrics.execution_ms,
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
        "e9_overhead_case": {
            **payload,
            "pruning_ratio": pruning_ratio,
            "metrics_source": metrics.metrics_source,
            "postgres_planning_ms": metrics.postgres_planning_ms,
            "static_plan_hash": static_plan_hash,
        },
        "status": "pass",
        "failure": None,
    }
    if repetition is not None:
        attach_repetition(record, repetition)
    return record


def _write_record(record: Mapping[str, Any], output_dir: Path) -> Path:
    issues = validate_raw_run_record(record)
    if issues:
        rendered = ", ".join(f"{issue.path}: {issue.message}" for issue in issues)
        raise PostgresError(f"E9 study raw record failed schema validation: {rendered}")
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_mode = str(record["mode"]).replace("-", "_")
    path = output_dir / f"{record['run_id'].replace('-', '_')}_{safe_mode}.json"
    with path.open("w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path


def run_e9_study(
    root: Path,
    manifest_path: Path,
    output_dir: Path,
    pg_env: Optional[PostgresEnv] = None,
) -> E9StudyResult:
    manifest = _load_manifest(manifest_path)
    _validate_manifest(manifest_path, manifest)
    manifest_id = str(manifest["manifest_id"])
    seed = int((manifest.get("dataset") or {}).get("seed", 48))
    points = _points_from_manifest(manifest)
    repetitions = protocol_from_manifest(manifest)
    pg_version = "not_executed_e9_tiered_overhead"
    if pg_env is not None:
        pg_version = _prepare_pg_stress_schema(root, pg_env)

    raw_paths: list[Path] = []
    max_planning_ms = 0.0
    max_generated_templates = 0
    for point in points:
        for mode in sorted(REQUIRED_MODES, key=mode_execution_order_key):
            for repetition in iter_repetitions(repetitions):
                metrics = (
                    _postgres_metrics(point, mode, pg_env)
                    if pg_env is not None
                    else _profile_planner_core(point, mode)
                )
                record = _record(
                    root,
                    manifest_path,
                    manifest_id,
                    point,
                    metrics,
                    seed,
                    E9_STUDY_ROWS_PER_RELATION,
                    pg_version,
                    repetition=repetition,
                )
                raw_paths.append(_write_record(record, output_dir))
                max_planning_ms = max(max_planning_ms, metrics.planning_ms)
                max_generated_templates = max(max_generated_templates, metrics.generated_templates)

    return E9StudyResult(
        raw_result_paths=raw_paths,
        normal_records=len(raw_paths),
        points=len(points),
        max_planning_ms=max_planning_ms,
        max_generated_templates=max_generated_templates,
    )
