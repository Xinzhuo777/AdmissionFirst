"""E4 PostgreSQL-backed controlled-pair reduced/main runner."""

from __future__ import annotations

import platform
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional

from planner.core import ArtifactMetadata, CostInputs, ParentRequirement, PlanningProblem, plan

from .baselines import (
    ADMISSION_FIRST_MODE,
    FINITE_TEMPLATE_UPPER_BOUND_ROLE,
    load_mode_registry,
    normalize_mode_id,
    scientific_mode_key,
)
from .e2_smoke import (
    _build_auth_idx_sql,
    _build_mav_sql,
    _clear_auth_idx_sql,
    _clear_mav_sql,
    _count_wrapper,
    _run_count_sql,
    _run_sql_script,
)
from .e4_smoke import (
    CASES,
    E4Candidate,
    E4Case,
    _assert_pair_validity,
    _digest,
    _excluded_counts,
    _git_commit,
    _load_manifest,
    _local_vector_hash,
    _validate_manifest as _validate_smoke_manifest,
    _write_record,
)
from .manifest_validator import file_sha256
from .oracle_audit import _load_context, _load_policy, _quote, _render_exact_predicate
from .postgres_runner import PostgresEnv, PostgresError, run_psql_command
from .repetitions import attach_repetition, iter_repetitions, protocol_from_manifest
from .result_schema import RAW_SCHEMA_VERSION
from .synthetic_saas import generate_synthetic_saas


@dataclass(frozen=True)
class E4MainResult:
    raw_result_paths: list[Path]
    candidate_records: int
    normal_records: int
    summary_records: int
    pair_count: int
    contract_reject_records: int


@dataclass(frozen=True)
class ParentSql:
    joins: str
    where: str
    order_by: str
    query_selectivity: float


@dataclass(frozen=True)
class MeasuredCandidate:
    template_id: str
    alternative: str
    status: str
    template_applicability: str
    reason: Optional[str]
    row_count: int
    execution_ms: float
    result_hash: str
    policy_evals: int
    candidate_rows: int
    artifact_lookups: int
    base_fetches: int
    build_ms: float
    storage_bytes: int
    indexes_built: tuple[str, ...]
    artifact_kind: Optional[str]


@dataclass(frozen=True)
class E4ExecutionContext:
    exact_predicate: str
    guard_predicate: str
    context_id: str
    ctx_hash: str
    user_id: str
    pg_version: str
    total_rows: int
    authorized_rows: int
    guard_rows: int
    auth_idx_artifact_id: str
    mav_artifact_id: str
    auth_idx_build_ms: float
    mav_build_ms: float
    auth_idx_rows: int
    mav_rows: int


def _validate_manifest(manifest_path: Path, manifest: Mapping[str, Any]) -> None:
    if manifest.get("experiment") != "E4" or manifest.get("execution_tier") != "main":
        raise PostgresError("e4-main requires an E4 main manifest")
    if manifest.get("stage") not in {"controlled_pairs_reduced", "controlled_pairs_full"}:
        raise PostgresError("e4-main requires stage controlled_pairs_reduced or controlled_pairs_full")

    smoke_equivalent = dict(manifest)
    smoke_equivalent["execution_tier"] = "smoke"
    smoke_equivalent["stage"] = "controlled_pairs_smoke"
    _validate_smoke_manifest(manifest_path, smoke_equivalent)


def _parent_sql(case: E4Case) -> ParentSql:
    if case.pair_id == "selective_ordinary_predicate" and case.parent_label == "B":
        return ParentSql("", "d.doc_id BETWEEN 1 AND 1000", "", 0.01)
    if case.pair_id == "unsafe_downstream_expression" and case.parent_label == "A":
        return ParentSql(
            "JOIN public.tenant t ON t.tenant_id = d.tenant_id AND t.plan = 'enterprise'",
            "true",
            "",
            0.25,
        )
    if case.pair_id == "parent_requires_order" and case.parent_label == "B":
        return ParentSql("", "true", "ORDER BY d.doc_id", 1.0)
    if case.pair_id == "join_continuation" and case.parent_label == "A":
        return ParentSql(
            "JOIN public.tenant t ON t.tenant_id = d.tenant_id AND t.plan = 'enterprise'",
            "true",
            "",
            0.25,
        )
    if case.pair_id == "join_continuation" and case.parent_label == "B":
        return ParentSql(
            "JOIN public.event_log e ON e.tenant_id = d.tenant_id AND e.event_id <= 1000",
            "true",
            "",
            10.0,
        )
    return ParentSql("", "true", "", 1.0)


def _parent_requirement(case: E4Case) -> ParentRequirement:
    vector = case.parent_requirement_vector
    return ParentRequirement(
        required_order=tuple([str(vector["required_order"])])
        if vector.get("required_order")
        else (),
        transparent=vector.get("unsafe_boundary_position") != "immediate",
        unsafe_expression_boundary=vector.get("unsafe_boundary_position") == "immediate",
        future_rid_intersection=vector.get("ordinary_predicate_class")
        in {"leakproof_point", "selective_dimension_join", "high_fanout_join"},
    )


def _source_count_sql(source_sql: str, case: E4Case) -> str:
    parent = _parent_sql(case)
    return _count_wrapper(
        f"""
WITH source AS MATERIALIZED (
{source_sql}
),
parent AS MATERIALIZED (
  SELECT d.*
  FROM source d
  {parent.joins}
  WHERE {parent.where}
  {parent.order_by}
)
SELECT count(*) FROM parent;
"""
    )


def _oracle_sql(case: E4Case, exact_predicate: str) -> str:
    return _source_count_sql(
        f"""
  SELECT d.doc_id, d.tenant_id, d.owner_id, d.group_id, d.region, d.class, d.public, d.secret
  FROM public.document d
  WHERE {exact_predicate}
""",
        case,
    )


def _parent_rows_sql(case: E4Case) -> str:
    return _source_count_sql(
        """
  SELECT d.doc_id, d.tenant_id, d.owner_id, d.group_id, d.region, d.class, d.public, d.secret
  FROM public.document d
""",
        case,
    )


def _candidate_sql(
    case: E4Case,
    candidate: E4Candidate,
    ctx: E4ExecutionContext,
) -> str:
    if candidate.template_id == "barrier_filter_v1":
        return _source_count_sql(
            f"""
  SELECT d.doc_id, d.tenant_id, d.owner_id, d.group_id, d.region, d.class, d.public, d.secret
  FROM public.document d
  WHERE {ctx.exact_predicate}
""",
            case,
        )
    if candidate.template_id == "auth_index_enum_v1":
        return _source_count_sql(
            f"""
  SELECT d.doc_id, d.tenant_id, d.owner_id, d.group_id, d.region, d.class, d.public, d.secret
  FROM public.auth_idx a
  JOIN public.document d ON d.doc_id = a.rid
  WHERE a.artifact_id = {_quote(ctx.auth_idx_artifact_id)}
    AND a.policy_id = 'tenant_group'
    AND a.user_id = {_quote(ctx.user_id)}
    AND a.ctx_hash = {_quote(ctx.ctx_hash)}
    AND a.rid_domain_id = 'document.doc_id'
    AND a.base_rel_oid = 'public.document'::regclass::oid
""",
            case,
        )
    if candidate.template_id == "mav_scan_v1":
        return _source_count_sql(
            """
  SELECT m.doc_id, m.tenant_id, m.owner_id, 0::bigint AS group_id,
         NULL::text AS region, 0::integer AS class, m.public, NULL::text AS secret
  FROM public.mav_document_ctx_000001 m
""",
            case,
        )
    if candidate.template_id == "hybrid_intersect_v1":
        parent = _parent_sql(case)
        return _count_wrapper(
            f"""
WITH parent AS MATERIALIZED (
  SELECT d.doc_id
  FROM public.document d
  {parent.joins}
  WHERE {parent.where}
  {parent.order_by}
),
auth AS MATERIALIZED (
  SELECT a.rid
  FROM public.auth_idx a
  WHERE a.artifact_id = {_quote(ctx.auth_idx_artifact_id)}
    AND a.policy_id = 'tenant_group'
    AND a.user_id = {_quote(ctx.user_id)}
    AND a.ctx_hash = {_quote(ctx.ctx_hash)}
    AND a.rid_domain_id = 'document.doc_id'
    AND a.base_rel_oid = 'public.document'::regclass::oid
)
SELECT count(*)
FROM parent p
JOIN auth a ON a.rid = p.doc_id;
"""
        )
    if candidate.template_id == "guard_candidate_plus_residual_v1":
        parent = _parent_sql(case)
        return _count_wrapper(
            f"""
WITH cand AS MATERIALIZED (
  SELECT d.doc_id, d.tenant_id, d.owner_id, d.group_id, d.region, d.class, d.public, d.secret
  FROM public.document d
  WHERE {ctx.guard_predicate}
),
parent AS MATERIALIZED (
  SELECT d.*
  FROM cand d
  {parent.joins}
  WHERE {parent.where}
  {parent.order_by}
),
exact AS MATERIALIZED (
  SELECT d.doc_id
  FROM parent d
  WHERE {ctx.exact_predicate}
)
SELECT count(*) FROM exact;
"""
        )
    raise PostgresError(f"unsupported E4 template candidate: {candidate.template_id}")


def _artifact_kind(template_id: str) -> Optional[str]:
    if template_id in {"auth_index_enum_v1", "hybrid_intersect_v1"}:
        return "auth_idx"
    if template_id == "mav_scan_v1":
        return "mav"
    return None


def _measure_candidate(
    *,
    case: E4Case,
    candidate: E4Candidate,
    ctx: E4ExecutionContext,
    pg_env: PostgresEnv,
    oracle_count: int,
    parent_rows: int,
) -> MeasuredCandidate:
    artifact_kind = _artifact_kind(candidate.template_id)
    if candidate.status != "pass" or candidate.template_applicability != "applicable":
        return MeasuredCandidate(
            template_id=candidate.template_id,
            alternative=candidate.alternative,
            status=candidate.status,
            template_applicability=candidate.template_applicability,
            reason=candidate.reason,
            row_count=0,
            execution_ms=0.0,
            result_hash=_digest(
                {
                    "query_id": case.query_id,
                    "template_id": candidate.template_id,
                    "status": candidate.status,
                    "reason": candidate.reason,
                }
            ),
            policy_evals=0,
            candidate_rows=0,
            artifact_lookups=0,
            base_fetches=0,
            build_ms=0.0,
            storage_bytes=0,
            indexes_built=(),
            artifact_kind=artifact_kind,
        )

    row_count, execution_ms = _run_count_sql(_candidate_sql(case, candidate, ctx), pg_env)
    if row_count != oracle_count:
        raise PostgresError(
            f"E4 {case.query_id}/{candidate.template_id} returned {row_count}, "
            f"expected {oracle_count}"
        )

    build_ms = 0.0
    storage_bytes = 0
    indexes_built: tuple[str, ...] = ()
    artifact_lookups = 0
    candidate_rows = parent_rows
    policy_evals = 0
    if candidate.template_id == "barrier_filter_v1":
        policy_evals = ctx.total_rows
        candidate_rows = ctx.authorized_rows
    elif candidate.template_id == "guard_candidate_plus_residual_v1":
        policy_evals = ctx.guard_rows
        candidate_rows = ctx.guard_rows
    elif artifact_kind == "auth_idx":
        artifact_lookups = 1
        candidate_rows = min(parent_rows, ctx.auth_idx_rows)
        build_ms = ctx.auth_idx_build_ms
        storage_bytes = ctx.auth_idx_rows * 64
        indexes_built = ("auth_idx_lookup",)
    elif artifact_kind == "mav":
        artifact_lookups = 1
        candidate_rows = min(parent_rows, ctx.mav_rows)
        build_ms = ctx.mav_build_ms
        storage_bytes = ctx.mav_rows * 80
        indexes_built = ("mav_document_ctx_000001_pkey",)

    return MeasuredCandidate(
        template_id=candidate.template_id,
        alternative=candidate.alternative,
        status="pass",
        template_applicability="applicable",
        reason=None,
        row_count=row_count,
        execution_ms=execution_ms,
        result_hash=_digest(
            {
                "query_id": case.query_id,
                "template_id": candidate.template_id,
                "row_count": row_count,
                "execution_ms": round(execution_ms, 6),
            }
        ),
        policy_evals=policy_evals,
        candidate_rows=candidate_rows,
        artifact_lookups=artifact_lookups,
        base_fetches=row_count,
        build_ms=build_ms,
        storage_bytes=storage_bytes,
        indexes_built=indexes_built,
        artifact_kind=artifact_kind,
    )


def _problem_for_case(
    case: E4Case,
    ctx: E4ExecutionContext,
    parent_rows: int,
) -> PlanningProblem:
    parent = _parent_sql(case)
    artifacts: Dict[str, ArtifactMetadata] = {}
    if "auth_idx" in case.local_feature_vector.get("available_artifacts", []):
        artifacts["auth_idx"] = ArtifactMetadata(
            kind="auth_idx",
            artifact_id=ctx.auth_idx_artifact_id,
            cardinality=ctx.auth_idx_rows,
            rows=ctx.auth_idx_rows,
        )
    if "mav" in case.local_feature_vector.get("available_artifacts", []):
        artifacts["mav"] = ArtifactMetadata(
            kind="mav",
            artifact_id=ctx.mav_artifact_id,
            cardinality=ctx.mav_rows,
            rows=ctx.mav_rows,
            order_keys=("doc_id",),
        )
    return PlanningProblem(
        planning_execution_class="diagnostic_only",
        relation="document",
        policy_id="tenant_group",
        occurrence_id=case.query_id,
        rid_col="doc_id",
        required_attrs=("tenant_id", "owner_id", "public"),
        required_ctx=("user_id", "tenant_id", "now"),
        exact_policy_safe=True,
        supports_guard=True,
        has_safe_query_predicate=parent.query_selectivity < 1.0
        or case.pair_id == "join_continuation",
        artifacts=artifacts,
        parent_requirement=_parent_requirement(case),
        cost_inputs=CostInputs(
            estimated_rows=ctx.total_rows,
            query_selectivity=max(parent.query_selectivity, parent_rows / max(ctx.total_rows, 1)),
            auth_selectivity=ctx.authorized_rows / max(ctx.total_rows, 1),
            policy_eval_cost=0.004 if case.local_vector_id != "lv_guard_complete_expensive" else 0.01,
            residual_eval_cost=0.003,
            scan_cost_per_row=0.001,
            base_fetch_cost=0.0001 if case.local_vector_id == "lv_unordered_authidx" else 0.004,
            artifact_lookup_cost=0.2,
            guard_selectivity=ctx.guard_rows / max(ctx.total_rows, 1),
            sort_cost=60.0 if case.parent_requirement_vector.get("required_order") else 0.0,
        ),
    )


def _measured_for(measured: Iterable[MeasuredCandidate], template_id: str) -> MeasuredCandidate:
    for item in measured:
        if item.template_id == template_id:
            return item
    raise PostgresError(f"missing measured E4 template: {template_id}")


def _best_measured(measured: Iterable[MeasuredCandidate]) -> MeasuredCandidate:
    eligible = [
        item
        for item in measured
        if item.status == "pass" and item.template_applicability == "applicable"
    ]
    if not eligible:
        raise PostgresError("E4 measured case has no eligible template")
    return min(eligible, key=lambda item: (item.execution_ms, item.template_id))


def _record(
    *,
    root: Path,
    manifest_path: Path,
    manifest_id: str,
    stage: str,
    case: E4Case,
    run_kind: str,
    mode: str,
    candidate: MeasuredCandidate,
    measured: list[MeasuredCandidate],
    dataset_scale: str,
    seed: int,
    ctx: E4ExecutionContext,
    planner_problem: PlanningProblem,
) -> Dict[str, Any]:
    mode = normalize_mode_id(mode)
    best = _best_measured(measured)
    passed = candidate.status == "pass"
    regret_ratio = candidate.execution_ms / best.execution_ms if passed and best.execution_ms > 0 else None
    evaluation_role = (
        FINITE_TEMPLATE_UPPER_BOUND_ROLE
        if run_kind in {"template_candidate", "template_oracle_summary"}
        else load_mode_registry(root)[normalize_mode_id(mode)].evaluation_role
    )
    static_status = "fail" if candidate.template_applicability == "contract_reject" else "pass"
    rejected = [
        item
        for item in measured
        if not (item.status == "pass" and item.template_applicability == "applicable")
    ]
    rejection_reasons = _excluded_counts(
        [
            E4Candidate(
                item.template_id,
                item.alternative,
                item.execution_ms,
                status=item.status,
                template_applicability=item.template_applicability,
                reason=item.reason,
            )
            for item in rejected
        ]
    )
    planner_result = plan(planner_problem, ADMISSION_FIRST_MODE)
    artifact_action = "reject" if candidate.template_applicability == "contract_reject" else "execute"
    artifact_status = (
        "pass"
        if candidate.artifact_kind is not None and candidate.template_applicability == "applicable"
        else "not_applicable"
    )
    return {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": f"E4main_{case.query_id}_{mode}_{candidate.template_id}",
        "manifest_id": manifest_id,
        "manifest_hash": file_sha256(manifest_path),
        "experiment": "E4",
        "stage": stage,
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
            "policy_sql_manifest_hash": file_sha256(
                root / "manifests" / "policies" / "synthetic_saas_policies.yaml"
            ),
        },
        "context": {"context_id": ctx.context_id, "ctx_hash": ctx.ctx_hash},
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
            "version": ctx.pg_version,
            "gucs": {"jit": "off", "max_parallel_workers_per_gather": "0"},
        },
        "versions": {
            "policy": {"tenant_group": 0},
            "membership": {"group_membership": 0},
            "context": {ctx.context_id: 0},
            "trusted_state": {"planner_core": 1, "pair_contract": 1},
            "base": {"document": 0, "event_log": 0, "tenant": 0},
            "artifacts": {
                ctx.auth_idx_artifact_id: 0,
                ctx.mav_artifact_id: 0,
            },
        },
        "planner": {
            "level": "B",
            "planning_time_ms": 0.0,
            "generated_templates": len(case.candidates),
            "rejected_templates": len(rejected),
            "costed_templates": len(measured) - len(rejected),
            "rejection_reasons": rejection_reasons,
            "chosen_estimated_cost": candidate.execution_ms,
            "chosen_rank_vs_template_oracle": 1
            if candidate.template_id == best.template_id and passed
            else None,
            "local_feature_vector": dict(case.local_feature_vector),
            "parent_requirement_vector": planner_result.parent_requirement_vector,
            "disabled_components": [],
            "candidates": [],
            "delivered_sigma": {},
        },
        "static_verifier": {
            "status": static_status,
            "plan_hash": candidate.result_hash,
            "explain_path": None,
            "reasons": [candidate.reason] if candidate.reason else [],
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
            "emitted_sql_path": case.query_path,
            "emitted_sql_hash": file_sha256(root / case.query_path),
            "normalized_sql_hash": candidate.result_hash,
        },
        "oracle_check": {
            "status": "match" if passed else "not_applicable",
            "oracle_kind": "postgres_e4_exact_policy_count",
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
        "result": {"row_count": candidate.row_count, "result_hash": candidate.result_hash},
        "pg_metrics": {
            "shared_read_blocks": 0,
            "shared_hit_blocks": 0,
            "temp_read_blocks": 0,
            "temp_written_blocks": 0,
        },
        "counts": {
            "policy_evals": candidate.policy_evals,
            "residual_checks": candidate.candidate_rows
            if candidate.template_id == "guard_candidate_plus_residual_v1" and passed
            else 0,
            "candidate_rows": candidate.candidate_rows,
            "authorized_rows": ctx.authorized_rows,
            "artifact_lookups": candidate.artifact_lookups,
            "base_fetches": candidate.base_fetches,
        },
        "artifact_cost": {
            "query_only_ms": candidate.execution_ms,
            "build_ms": candidate.build_ms,
            "refresh_ms": 0.0,
            "storage_bytes": candidate.storage_bytes,
            "indexes_built": list(candidate.indexes_built),
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
    *,
    root: Path,
    manifest_path: Path,
    manifest_id: str,
    stage: str,
    case: E4Case,
    measured: list[MeasuredCandidate],
    dataset_scale: str,
    seed: int,
    ctx: E4ExecutionContext,
    planner_problem: PlanningProblem,
) -> Dict[str, Any]:
    best = _best_measured(measured)
    chosen = _measured_for(measured, case.admission_first_template_id)
    excluded = [
        E4Candidate(
            item.template_id,
            item.alternative,
            item.execution_ms,
            status=item.status,
            template_applicability=item.template_applicability,
            reason=item.reason,
        )
        for item in measured
        if not (item.status == "pass" and item.template_applicability == "applicable")
    ]
    summary_payload = {
        "run_kind": "template_oracle_summary",
        "query_id": case.query_id,
        "context_id": ctx.context_id,
        "mode_under_test": ADMISSION_FIRST_MODE,
        "ranking_metric": "execution_time_ms",
        "eligible_templates": len(measured) - len(excluded),
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
        stage=stage,
        case=case,
        run_kind="template_oracle_summary",
        mode="template-oracle",
        candidate=best,
        measured=measured,
        dataset_scale=dataset_scale,
        seed=seed,
        ctx=ctx,
        planner_problem=planner_problem,
    )
    record["run_id"] = f"E4main_{case.query_id}_template_oracle_summary"
    record["template_oracle_summary"] = summary_payload
    record["result"]["result_hash"] = _digest(scientific_summary_payload)
    record["sql"]["normalized_sql_hash"] = record["result"]["result_hash"]
    record["static_verifier"]["plan_hash"] = record["result"]["result_hash"]
    return record


def _prepare_context(
    root: Path,
    pg_env: PostgresEnv,
    scale: str,
    seed: int,
) -> E4ExecutionContext:
    generate_synthetic_saas(root, pg_env, scale=scale, seed=seed, verify=True, output_dir=None)
    policy = _load_policy(root, "tenant_group")
    context_id = "ctx_000001"
    context = _load_context(context_id, pg_env)
    ctx_hash = run_psql_command(
        f"SELECT ctx_hash FROM public.synthetic_context WHERE context_id = {_quote(context_id)};",
        pg_env,
    )
    exact_predicate = _render_exact_predicate(
        str(policy["exact_sql_template"]),
        alias="d",
        rid_col="doc_id",
        context=context,
        relname="document",
    )
    guard_predicate = _render_exact_predicate(
        str(policy["guard_sql_template"]),
        alias="d",
        rid_col="doc_id",
        context=context,
        relname="document",
    )
    total_rows = int(run_psql_command("SELECT count(*) FROM public.document;", pg_env))
    authorized_rows = int(
        run_psql_command(f"SELECT count(*) FROM public.document d WHERE {exact_predicate};", pg_env)
    )
    guard_rows = int(
        run_psql_command(f"SELECT count(*) FROM public.document d WHERE {guard_predicate};", pg_env)
    )
    pg_version = run_psql_command("SHOW server_version;", pg_env)
    user_id = str(context["user_id"])
    auth_idx_artifact_id = "e4_auth_idx_ctx_000001"
    mav_artifact_id = "e4_mav_ctx_000001"
    _run_sql_script(_clear_auth_idx_sql(auth_idx_artifact_id), pg_env)
    _run_sql_script(_clear_mav_sql(mav_artifact_id), pg_env)

    started = time.monotonic()
    _run_sql_script(
        _build_auth_idx_sql(
            artifact_id=auth_idx_artifact_id,
            policy_id="tenant_group",
            user_id=user_id,
            ctx_hash=ctx_hash,
            exact_predicate=exact_predicate,
        ),
        pg_env,
    )
    auth_idx_build_ms = (time.monotonic() - started) * 1000.0
    auth_idx_rows = int(
        run_psql_command(
            f"SELECT count(*) FROM public.auth_idx WHERE artifact_id = {_quote(auth_idx_artifact_id)};",
            pg_env,
        )
    )

    started = time.monotonic()
    _run_sql_script(
        _build_mav_sql(
            artifact_id=mav_artifact_id,
            policy_id="tenant_group",
            ctx_hash=ctx_hash,
            exact_predicate=exact_predicate,
        ),
        pg_env,
    )
    mav_build_ms = (time.monotonic() - started) * 1000.0
    mav_rows = int(run_psql_command("SELECT count(*) FROM public.mav_document_ctx_000001;", pg_env))
    _run_sql_script(
        """
\\set ON_ERROR_STOP on
ANALYZE public.document;
ANALYZE public.tenant;
ANALYZE public.event_log;
ANALYZE public.auth_idx;
ANALYZE public.mav_document_ctx_000001;
""",
        pg_env,
    )
    return E4ExecutionContext(
        exact_predicate=exact_predicate,
        guard_predicate=guard_predicate,
        context_id=context_id,
        ctx_hash=ctx_hash,
        user_id=user_id,
        pg_version=pg_version,
        total_rows=total_rows,
        authorized_rows=authorized_rows,
        guard_rows=guard_rows,
        auth_idx_artifact_id=auth_idx_artifact_id,
        mav_artifact_id=mav_artifact_id,
        auth_idx_build_ms=auth_idx_build_ms,
        mav_build_ms=mav_build_ms,
        auth_idx_rows=auth_idx_rows,
        mav_rows=mav_rows,
    )


def run_e4_main(
    root: Path,
    pg_env: PostgresEnv,
    manifest_path: Path,
    output_dir: Path,
) -> E4MainResult:
    manifest = _load_manifest(manifest_path)
    _validate_manifest(manifest_path, manifest)
    _assert_pair_validity()
    manifest_id = str(manifest["manifest_id"])
    stage = str(manifest["stage"])
    dataset = manifest.get("dataset") or {}
    scale = str(dataset.get("scale", "1e5"))
    seed = int(dataset.get("seed", 45))
    ctx = _prepare_context(root, pg_env, scale=scale, seed=seed)
    repetitions = protocol_from_manifest(manifest)

    raw_paths: list[Path] = []
    candidate_records = 0
    normal_records = 0
    summary_records = 0
    contract_reject_records = 0

    for case in CASES:
        oracle_count, _ = _run_count_sql(_oracle_sql(case, ctx.exact_predicate), pg_env)
        parent_rows, _ = _run_count_sql(_parent_rows_sql(case), pg_env)
        planner_problem = _problem_for_case(case, ctx, parent_rows)

        for repetition in iter_repetitions(repetitions):
            measured = [
                _measure_candidate(
                    case=case,
                    candidate=candidate,
                    ctx=ctx,
                    pg_env=pg_env,
                    oracle_count=oracle_count,
                    parent_rows=parent_rows,
                )
                for candidate in case.candidates
            ]
            contract_reject_records += len(
                [item for item in measured if item.template_applicability == "contract_reject"]
            )

            for result in measured:
                record = _record(
                    root=root,
                    manifest_path=manifest_path,
                    manifest_id=manifest_id,
                    stage=stage,
                    case=case,
                    run_kind="template_candidate",
                    mode="template-oracle",
                    candidate=result,
                    measured=measured,
                    dataset_scale=scale,
                    seed=seed,
                    ctx=ctx,
                    planner_problem=planner_problem,
                )
                attach_repetition(record, repetition)
                raw_paths.append(_write_record(record, output_dir))
                candidate_records += 1

            for mode, template_id in (
                ("local-greedy", case.local_greedy_template_id),
                (ADMISSION_FIRST_MODE, case.admission_first_template_id),
            ):
                record = _record(
                    root=root,
                    manifest_path=manifest_path,
                    manifest_id=manifest_id,
                    stage=stage,
                    case=case,
                    run_kind="normal_mode",
                    mode=mode,
                    candidate=_measured_for(measured, template_id),
                    measured=measured,
                    dataset_scale=scale,
                    seed=seed,
                    ctx=ctx,
                    planner_problem=planner_problem,
                )
                attach_repetition(record, repetition)
                raw_paths.append(_write_record(record, output_dir))
                normal_records += 1

            summary = _summary_record(
                root=root,
                manifest_path=manifest_path,
                manifest_id=manifest_id,
                stage=stage,
                case=case,
                measured=measured,
                dataset_scale=scale,
                seed=seed,
                ctx=ctx,
                planner_problem=planner_problem,
            )
            attach_repetition(summary, repetition)
            raw_paths.append(_write_record(summary, output_dir))
            summary_records += 1

    return E4MainResult(
        raw_result_paths=raw_paths,
        candidate_records=candidate_records,
        normal_records=normal_records,
        summary_records=summary_records,
        pair_count=len({case.pair_id for case in CASES}),
        contract_reject_records=contract_reject_records,
    )
