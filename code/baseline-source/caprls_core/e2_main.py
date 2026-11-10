"""Run the reduced PostgreSQL-backed E2 artifact-availability grid."""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
    FINITE_TEMPLATE_UPPER_BOUND_ROLE,
    POLICY_ENFORCEMENT_ROLE,
    normalize_mode_id,
)

import math
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping, Optional

from planner.core import (
    PlanResult,
    plan as plan_occurrence,
)
from planner.query import derive_occurrence_goals, plan_query
from planner.verifier.static import StaticVerification

from .e2_smoke import (
    E2_PLANNER_REGISTRY,
    E2_TEMPLATE_ORDER,
    TEMPLATE_CANDIDATES,
    CandidateResult,
    _available_artifacts,
    _base_record,
    _build_auth_idx_keyed_sql,
    _build_auth_idx_sql,
    _build_auth_view_sql,
    _build_mav_sql,
    _candidate_result,
    _candidate_sql,
    _clear_auth_idx_keyed_sql,
    _clear_auth_idx_sql,
    _clear_mav_sql,
    _count_wrapper,
    _e2_planning_problem,
    _e2_planning_query,
    _explain_plan_hash,
    _extract_explain_json,
    _find_candidate,
    _load_manifest,
    _planner_payload_from_query_result,
    _run_count_sql,
    _run_sql_script,
    _summary_record,
    _text_digest,
    _unavailable_candidate,
    _write_record,
)
from .e8b_study import ValidationTiming, _run_validated_query
from .oracle_audit import _load_context, _load_policy, _quote, _render_exact_predicate
from .postgres_runner import PostgresEnv, PostgresError, run_psql_command
from .repetitions import RepetitionRun, attach_repetition, iter_repetitions, protocol_from_manifest
from .synthetic_saas import generate_synthetic_saas


@dataclass(frozen=True)
class E2MainResult:
    raw_result_paths: list[Path]
    grid_points: int
    candidate_records: int
    normal_records: int
    summary_records: int
    artifact_unavailable_records: int


@dataclass(frozen=True)
class E2GridPoint:
    s_auth: float
    s_q: float
    policy_cost: str
    artifact_availability: str

    @property
    def point_id(self) -> str:
        return (
            f"sq{_slug_float(self.s_q)}_sa{_slug_float(self.s_auth)}_"
            f"{self.policy_cost}_{self.artifact_availability}"
        )


E2_RAWPG_RANKER_NAME = "pg-explain-raw"
E2_RAWPG_COST_MODEL_VERSION = "pg_explain_raw_v1"
E2_RAWPG_MANIFEST = {
    "name": E2_RAWPG_RANKER_NAME,
    "version": E2_RAWPG_COST_MODEL_VERSION,
    "calibration": "zero",
    "analyze": False,
    "incomplete_pool": "error",
    "tie_break": "rawpg_then_heuristic_then_template_id",
}
E2_TIMING_CONTRACT = {
    "ranking_metric": "postgres_server_execution_ms",
    "query_only": "postgres_server_planning_plus_execution_ms",
    "total": "query_only_plus_artifact_validation_ms",
    "prospective_selection": "cell_level_full_selection_client_wall_ms_not_amortized",
}


MODE_TO_TEMPLATE = {
    "barrier-only": "barrier_filter_v1",
    "injection-only": "safe_predicate_injection_v1",
    "auth-view-only": "auth_view_scan_v1",
    "auth-index-enum-only": "auth_index_enum_v1",
    "strong-auth-index": "strong_auth_index_keyed_v1",
    "mav-only": "mav_scan_v1",
    "guard-mandatory-discharge": "guard_candidate_plus_residual_v1",
}


def _slug_float(value: float) -> str:
    return str(value).replace(".", "p").replace("-", "m")


def _validate_manifest(manifest_path: Path, manifest: Mapping[str, Any]) -> None:
    if manifest.get("experiment") != "E2" or manifest.get("execution_tier") != "main":
        raise PostgresError("e2-main requires an E2 main manifest")
    if manifest.get("stage") not in {"alternative_matrix", "alternative_matrix_reduced"}:
        raise PostgresError("e2-main requires an alternative_matrix stage")

    candidate_ids = [candidate.template_id for candidate in TEMPLATE_CANDIDATES]
    manifest_candidates = [str(item) for item in manifest.get("template_candidates", [])]
    if manifest_candidates != candidate_ids:
        raise PostgresError(
            "E2 main template_candidates do not match planner registry: "
            f"expected {candidate_ids}, got {manifest_candidates}"
        )

    modes = {normalize_mode_id(str(item)) for item in manifest.get("modes", [])}
    required = {ADMISSION_FIRST_MODE, "template-oracle"}
    supported = required | set(MODE_TO_TEMPLATE)
    missing = required - modes
    unsupported = modes - supported
    if missing or unsupported:
        raise PostgresError(
            "E2 main modes do not match runner contract: "
            f"missing={sorted(missing)}, unsupported={sorted(unsupported)}"
        )

    queries = {
        str(item.get("query_id")): str(item.get("path"))
        for item in manifest.get("queries", [])
        if isinstance(item, Mapping)
    }
    if queries != {"E2_range_count": "workloads/e2/range_count.sql"}:
        raise PostgresError(f"E2 reduced main currently supports only E2_range_count; got {queries}")

    ranker = manifest.get("ranker")
    if ranker != E2_RAWPG_MANIFEST:
        raise PostgresError(
            "E2 main requires the zero-calibration pg-explain-raw ranker: "
            f"expected {E2_RAWPG_MANIFEST}, got {ranker}"
        )
    if manifest.get("timing_contract") != E2_TIMING_CONTRACT:
        raise PostgresError(
            "E2 main timing_contract does not match the recorded query/selection scopes: "
            f"expected {E2_TIMING_CONTRACT}, got {manifest.get('timing_contract')}"
        )


def _grid_points(manifest: Mapping[str, Any]) -> list[E2GridPoint]:
    variables = manifest.get("variables") or {}
    points: list[E2GridPoint] = []
    for s_auth in [float(item) for item in variables.get("s_auth", [0.01])]:
        for s_q in [float(item) for item in variables.get("s_q", [0.01])]:
            for policy_cost in [str(item) for item in variables.get("policy_cost", ["cheap"])]:
                for artifact_availability in [
                    str(item) for item in variables.get("artifact_availability", ["none"])
                ]:
                    points.append(
                        E2GridPoint(
                            s_auth=s_auth,
                            s_q=s_q,
                            policy_cost=policy_cost,
                            artifact_availability=artifact_availability,
                        )
                    )
    return points


def _write_main_record(
    *,
    root: Path,
    manifest_path: Path,
    manifest_id: str,
    stage: str,
    run_id: str,
    run_kind: str,
    mode: str,
    candidate: CandidateResult,
    scale: str,
    seed: int,
    policy_id: str,
    context_id: str,
    ctx_hash: str,
    pg_version: str,
    total_rows: int,
    authorized_rows: int,
    artifact_cardinality: int,
    point: E2GridPoint,
    evaluation_role: str,
    output_dir: Path,
    repetition: Optional[RepetitionRun] = None,
    exact_predicate: str = "d.tenant_id = 1",
    guard_predicate: str | None = None,
    lo: int = 1,
    hi: int = 100,
    artifact_id: str = "auth_idx_doc_ctx_000001",
    keyed_artifact_id: str = "auth_idx_keyed_doc_ctx_000001",
    mav_relation: str = "mav_document_ctx_000001",
    user_id: str | None = None,
    planner_payload_override: Mapping[str, Any] | None = None,
) -> Path:
    record = _base_record(
        root=root,
        manifest_path=manifest_path,
        manifest_id=manifest_id,
        run_id=run_id,
        run_kind=run_kind,
        mode=mode,
        template_id=candidate.template_id,
        alternative=candidate.alternative,
        evaluation_role=evaluation_role,
        status=candidate.status,
        candidate=candidate,
        dataset_scale=scale,
        seed=seed,
        policy_id=policy_id,
        context_id=context_id,
        ctx_hash=ctx_hash,
        pg_version=pg_version,
        total_rows=total_rows,
        authorized_rows=authorized_rows,
        auth_idx_cardinality=artifact_cardinality,
        s_auth=point.s_auth,
        s_q=point.s_q,
        policy_cost=point.policy_cost,
        failure_reason=candidate.failure_reason,
        stage=stage,
        run_id_prefix="E2main",
        extra_query_params={"grid_point": point.point_id},
        exact_predicate=exact_predicate,
        guard_predicate=guard_predicate,
        lo=lo,
        hi=hi,
        artifact_id=artifact_id,
        keyed_artifact_id=keyed_artifact_id,
        mav_relation=mav_relation,
        user_id=user_id,
    )
    if planner_payload_override is not None:
        _apply_planner_payload_override(
            record,
            planner_payload_override,
            expected_template_id=(candidate.template_id if mode == ADMISSION_FIRST_MODE else None),
        )
    if repetition is not None:
        attach_repetition(record, repetition)
    return _write_record(
        record,
        output_dir,
        candidate.static_verifier_explain_json,
    )


def _apply_planner_payload_override(
    record: dict[str, Any],
    planner_payload: Mapping[str, Any],
    *,
    expected_template_id: str | None = None,
) -> None:
    selected = planner_payload.get("selected_template_id")
    if expected_template_id is not None and selected != expected_template_id:
        raise PostgresError(
            "E2 record template differs from its prospective planner choice: "
            f"record={expected_template_id}, planner={selected}"
        )
    record["planner"] = dict(planner_payload)
    query_plan = planner_payload.get("query_plan")
    if not isinstance(query_plan, Mapping):
        return
    emitted_sql = query_plan.get("emitted_sql")
    if isinstance(emitted_sql, str) and emitted_sql.strip():
        record["sql"]["ir_equivalence_runner_sql"] = emitted_sql
        record["sql"]["ir_equivalence_runner_sql_hash"] = _text_digest(emitted_sql)


def _artifact_cardinalities(
    pg_env: PostgresEnv,
    artifact_id: str,
    keyed_artifact_id: str,
    artifact_availability: str,
) -> tuple[int, int, int, int]:
    auth_idx_cardinality = int(
        run_psql_command(
            f"SELECT count(*) FROM public.auth_idx WHERE artifact_id = {_quote(artifact_id)};",
            pg_env,
        )
    )
    keyed_cardinality = int(
        run_psql_command(
            f"SELECT count(*) FROM public.auth_idx_keyed WHERE artifact_id = {_quote(keyed_artifact_id)};",
            pg_env,
        )
    )
    mav_cardinality = 0
    if "mav" in _available_artifacts(artifact_availability):
        mav_cardinality = int(
            run_psql_command("SELECT count(*) FROM public.mav_document_ctx_000001;", pg_env)
        )
    return (
        auth_idx_cardinality,
        keyed_cardinality,
        mav_cardinality,
        max(auth_idx_cardinality, keyed_cardinality, mav_cardinality),
    )


def _build_artifacts(
    pg_env: PostgresEnv,
    artifact_availability: str,
    artifact_id: str,
    keyed_artifact_id: str,
    mav_artifact_id: str,
    policy_id: str,
    user_id: str,
    ctx_hash: str,
    exact_predicate: str,
) -> None:
    _run_sql_script(_build_auth_view_sql(exact_predicate), pg_env)
    _run_sql_script(_clear_auth_idx_sql(artifact_id), pg_env)
    _run_sql_script(_clear_auth_idx_keyed_sql(keyed_artifact_id), pg_env)
    _run_sql_script(_clear_mav_sql(mav_artifact_id), pg_env)
    available = _available_artifacts(artifact_availability)
    if "auth_idx" in available:
        _run_sql_script(
            _build_auth_idx_sql(
                artifact_id=artifact_id,
                policy_id=policy_id,
                user_id=user_id,
                ctx_hash=ctx_hash,
                exact_predicate=exact_predicate,
            ),
            pg_env,
        )
    if "auth_idx_keyed" in available:
        _run_sql_script(
            _build_auth_idx_keyed_sql(
                artifact_id=keyed_artifact_id,
                policy_id=policy_id,
                user_id=user_id,
                ctx_hash=ctx_hash,
                exact_predicate=exact_predicate,
            ),
            pg_env,
        )
    if "mav" in available:
        _run_sql_script(
            _build_mav_sql(
                artifact_id=mav_artifact_id,
                policy_id=policy_id,
                ctx_hash=ctx_hash,
                exact_predicate=exact_predicate,
            ),
            pg_env,
        )


def _expected_artifact_json(policy_id: str, ctx_hash: str) -> str:
    import json

    return json.dumps(
        [
            {"dep_kind": "policy", "dep_name": policy_id, "version_at_build": 0},
            {"dep_kind": "membership", "dep_name": "group_membership", "version_at_build": 0},
            {"dep_kind": "base", "dep_name": "document", "version_at_build": 0},
            {"dep_kind": "context_scope", "dep_name": ctx_hash, "version_at_build": 0},
            {"dep_kind": "rid_domain", "dep_name": "document.doc_id", "version_at_build": 0},
        ],
        sort_keys=True,
        separators=(",", ":"),
    )


def _artifact_ids_for_template(
    template_id: str,
    artifact_id: str,
    keyed_artifact_id: str,
    mav_artifact_id: str,
) -> tuple[str, ...]:
    if template_id == "auth_index_enum_v1":
        return (artifact_id,)
    if template_id == "strong_auth_index_keyed_v1":
        return (keyed_artifact_id,)
    if template_id == "mav_scan_v1":
        return (mav_artifact_id,)
    if template_id == "hybrid_intersect_v1":
        return (artifact_id,)
    return ()


def _validated_sql_body(sql: str) -> str:
    skipped_prefixes = ("\\", "SET jit", "SET max_parallel_workers_per_gather")
    return "\n".join(
        line
        for line in sql.splitlines()
        if not line.strip().startswith(skipped_prefixes)
    ).strip()


def _run_validated_e2_template(
    template_id: str,
    sql: str,
    artifact_ids: tuple[str, ...],
    expected_json: str,
    pg_env: PostgresEnv,
):
    measurement = _run_validated_query(
        template_id,
        _validated_sql_body(sql),
        artifact_ids,
        expected_json,
        pg_env,
    )
    if not measurement.validation.validation_passed:
        return measurement
    if not artifact_ids:
        measurement = replace(
            measurement,
            validation=ValidationTiming(
                validation_passed=True,
                failure_sqlstate=None,
                failure_symbol=None,
                elapsed_ms=0.0,
                same_snapshot=False,
                isolation_level=None,
            ),
        )
    row_count, _ = _run_count_sql(sql, pg_env)
    return replace(measurement, row_count=row_count)


def _static_verification_from_timing(timing: Any, fallback_sql: str) -> StaticVerification:
    return StaticVerification(
        status=str(getattr(timing, "static_verifier_status", "pass")),
        reasons=list(getattr(timing, "static_verifier_reasons", ()) or ()),
        plan_hash=str(getattr(timing, "static_verifier_plan_hash", "") or _candidate_digest(fallback_sql)),
    )


def _candidate_digest(sql: str) -> str:
    import hashlib
    import json

    payload = json.dumps({"sql": sql}, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _e2_prospective_pg_cost(
    sql: str,
    pg_env: PostgresEnv,
) -> tuple[float, dict[str, Any]]:
    """Cost an E2 measurement runner prospectively with plain EXPLAIN."""

    body = _validated_sql_body(sql).rstrip().rstrip(";")
    if not body:
        raise PostgresError("E2 prospective runner SQL is empty")
    explain_sql = (
        "SET jit = off; "
        "SET max_parallel_workers_per_gather = 0; "
        "SET plan_cache_mode = force_custom_plan; "
        "EXPLAIN (FORMAT JSON) "
        + body
        + ";"
    )
    started_ns = time.perf_counter_ns()
    explain_json = _extract_explain_json(run_psql_command(explain_sql, pg_env))
    explain_wall_ms = (time.perf_counter_ns() - started_ns) / 1_000_000.0
    plan = explain_json[0].get("Plan")
    if not isinstance(plan, Mapping):
        raise PostgresError("E2 prospective EXPLAIN lacks a root Plan object")
    try:
        pg_total_cost = float(plan["Total Cost"])
    except (KeyError, TypeError, ValueError) as exc:
        raise PostgresError("E2 prospective EXPLAIN lacks a numeric Total Cost") from exc
    if not math.isfinite(pg_total_cost) or pg_total_cost < 0.0:
        raise PostgresError(f"E2 prospective EXPLAIN cost is invalid: {pg_total_cost}")
    return pg_total_cost, {
        "pg_plan_rows": plan.get("Plan Rows"),
        "plan_hash": _explain_plan_hash(explain_json),
        "explain_prospective": True,
        "explain_analyze": False,
        "explain_wall_ms": explain_wall_ms,
        "runner_sql_hash": _text_digest(sql),
    }


def _rerank_e2_plan_with_pg_explain(
    plan_result: PlanResult,
    *,
    runner_sql_by_template: Mapping[str, str],
    pg_env: PostgresEnv,
) -> PlanResult:
    """Replace every admitted E2 heuristic cost with complete RawPG evidence."""

    accepted_ids = {
        candidate.template_id for candidate in plan_result.candidates if candidate.accepted
    }
    if not accepted_ids:
        raise PostgresError("E2 admission produced no accepted candidate")
    if not accepted_ids.issubset(runner_sql_by_template):
        raise PostgresError(
            "E2 actual runner SQL must cover the complete accepted pool: "
            f"missing={sorted(accepted_ids - set(runner_sql_by_template))}"
        )

    reranked = []
    for candidate in plan_result.candidates:
        unpruned = replace(candidate, pruned_by_dominance=None)
        if not candidate.accepted:
            reranked.append(unpruned)
            continue
        pg_total_cost, prospective = _e2_prospective_pg_cost(
            runner_sql_by_template[candidate.template_id],
            pg_env,
        )
        diagnostics = dict(candidate.diagnostics)
        diagnostics.update(
            {
                "ranker": E2_RAWPG_RANKER_NAME,
                "cost_model_version": E2_RAWPG_COST_MODEL_VERSION,
                "heuristic_cost": candidate.estimated_cost,
                "pg_total_cost": float(pg_total_cost),
                **dict(prospective),
            }
        )
        reranked.append(
            replace(
                unpruned,
                estimated_cost=float(pg_total_cost),
                diagnostics=diagnostics,
            )
        )

    candidates = tuple(reranked)
    eligible = [candidate for candidate in candidates if candidate.accepted]

    def rank_key(candidate: Any) -> tuple[float, float, str]:
        heuristic = candidate.diagnostics.get("heuristic_cost")
        heuristic_tie_break = float(heuristic) if heuristic is not None else float("inf")
        return (float(candidate.estimated_cost), heuristic_tie_break, candidate.template_id)

    chosen = min(eligible, key=rank_key) if eligible else None
    if chosen is None:
        raise PostgresError("E2 RawPG rerank left no eligible candidate")
    return replace(
        plan_result,
        costed_templates=len(accepted_ids),
        chosen_template=chosen,
        emitted_sql=chosen.emitted_sql,
        delivered_sigma=chosen.delivered_sigma,
        estimated_cost=chosen.estimated_cost,
        candidates=candidates,
    )


def _prospective_admission_first_plan(
    *,
    policy_id: str,
    total_rows: int,
    authorized_rows: int,
    artifact_availability: str,
    artifact_cardinality: int,
    point: E2GridPoint,
    exact_predicate: str,
    guard_predicate: str,
    lo: int,
    hi: int,
    artifact_id: str,
    keyed_artifact_id: str,
    mav_relation: str,
    user_id: str,
    ctx_hash: str,
    runner_sql_by_template: Mapping[str, str],
    pg_env: PostgresEnv,
) -> tuple[str, Mapping[str, Any]]:
    """Admit, prospectively cost, and close the exact E2 query before execution."""

    selection_started_ns = time.perf_counter_ns()
    problem = _e2_planning_problem(
        policy_id=policy_id,
        total_rows=total_rows,
        authorized_rows=authorized_rows,
        artifact_availability=artifact_availability,
        artifact_cardinality=artifact_cardinality,
        s_q=point.s_q,
        policy_cost=point.policy_cost,
    )
    query = _e2_planning_query(
        problem,
        ADMISSION_FIRST_MODE,
        exact_predicate=exact_predicate,
        guard_predicate=guard_predicate,
        lo=lo,
        hi=hi,
        artifact_id=artifact_id,
        keyed_artifact_id=keyed_artifact_id,
        mav_relation=mav_relation,
        policy_id=policy_id,
        user_id=user_id,
        ctx_hash=ctx_hash,
    )
    effective_goal = derive_occurrence_goals(query)[problem.occurrence_id]
    effective_problem = effective_goal.problem
    admitted = plan_occurrence(
        effective_problem,
        effective_goal.mode or ADMISSION_FIRST_MODE,
        registry=E2_PLANNER_REGISTRY,
    )
    reranked = _rerank_e2_plan_with_pg_explain(
        admitted,
        runner_sql_by_template=runner_sql_by_template,
        pg_env=pg_env,
    )
    query_result = plan_query(
        query,
        registry=E2_PLANNER_REGISTRY,
        preplanned_occurrence_results={problem.occurrence_id: reranked},
    )
    occurrence = query_result.occurrence_results.get(problem.occurrence_id)
    chosen = None if occurrence is None else occurrence.chosen_template
    if not query_result.ok or chosen is None:
        reason = query_result.root_closure.reason or "no admitted template"
        raise PostgresError(f"E2 prospective AdmissionFirst selection failed: {reason}")
    if chosen.template_id not in E2_TEMPLATE_ORDER:
        raise PostgresError(
            "E2 prospective AdmissionFirst selected an unknown template: "
            f"{chosen.template_id}"
        )
    planner_payload = _planner_payload_from_query_result(
        query_result,
        template_id=chosen.template_id,
        occurrence_id=problem.occurrence_id,
    )
    accepted_ids = sorted(candidate.template_id for candidate in reranked.candidates if candidate.accepted)
    selection_wall_values = [
        float(candidate.diagnostics["explain_wall_ms"])
        for candidate in reranked.candidates
        if candidate.accepted
    ]
    selection_wall_ms = (time.perf_counter_ns() - selection_started_ns) / 1_000_000.0
    planner_payload.update(
        {
            "planning_time_ms": selection_wall_ms,
            "selected_template_id": chosen.template_id,
            "ranker": E2_RAWPG_RANKER_NAME,
            "cost_model_version": E2_RAWPG_COST_MODEL_VERSION,
            "zero_calibration": True,
            "choice_reason": "argmin_complete_prospective_pg_total_cost",
            "selection_phase": "before_reference_and_candidate_execution",
            "prospective_explain_analyze": False,
            "prospective_cost_pool_complete": True,
            "prospective_costed_template_ids": accepted_ids,
            "chosen_pg_total_cost": chosen.diagnostics.get("pg_total_cost"),
            "prospective_selection_explain_count": len(selection_wall_values),
            "prospective_selection_wall_ms": selection_wall_ms,
            "prospective_explain_wall_ms": sum(selection_wall_values),
            "prospective_selection_timing_scope": (
                "cell_level_full_selection_client_wall_ms_not_amortized"
            ),
            "query_timing_scope": "postgres_server_planning_plus_execution_ms",
        }
    )
    return chosen.template_id, planner_payload


def _prospective_admission_first_candidate(
    candidate_results: list[CandidateResult],
    prospective_template_id: str,
) -> CandidateResult:
    candidate = _find_candidate(candidate_results, prospective_template_id)
    if not candidate.eligible_for_template_oracle:
        raise PostgresError(
            "E2 prospective AdmissionFirst template is not executable: "
            f"{prospective_template_id}"
        )
    return candidate


def run_e2_main(
    root: Path,
    pg_env: PostgresEnv,
    manifest_path: Path,
    output_dir: Path,
) -> E2MainResult:
    manifest = _load_manifest(manifest_path)
    _validate_manifest(manifest_path, manifest)
    manifest_id = str(manifest["manifest_id"])
    stage = str(manifest["stage"])
    dataset = manifest.get("dataset") or {}
    scale = str(dataset.get("scale", "1e5"))
    seed = int(dataset.get("seed", 42))
    modes = [normalize_mode_id(str(item)) for item in manifest.get("modes", [])]
    points = _grid_points(manifest)
    repetitions = protocol_from_manifest(manifest)

    generate_synthetic_saas(
        root,
        pg_env,
        scale=scale,
        seed=seed,
        verify=True,
        output_dir=None,
    )
    policy_app = (manifest.get("policy_applications") or [{}])[0]
    policy_id = str(policy_app.get("policy_id", "tenant_group"))
    policy = _load_policy(root, policy_id)
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
    guard_template = policy.get("guard_sql_template")
    if not guard_template:
        raise PostgresError(f"policy {policy_id} has no guard template for E2 main")
    guard_predicate = _render_exact_predicate(
        str(guard_template),
        alias="d",
        rid_col="doc_id",
        context=context,
        relname="document",
    )
    total_rows = int(run_psql_command("SELECT count(*) FROM public.document;", pg_env))
    authorized_rows = int(
        run_psql_command(f"SELECT count(*) FROM public.document d WHERE {exact_predicate};", pg_env)
    )
    pg_version = run_psql_command("SHOW server_version;", pg_env)
    user_id = str(context["user_id"])
    artifact_id = "auth_idx_doc_ctx_000001"
    keyed_artifact_id = "auth_idx_keyed_doc_ctx_000001"
    mav_artifact_id = "mav_document_ctx_000001"

    raw_paths: list[Path] = []
    candidate_records = 0
    normal_records = 0
    summary_records = 0
    artifact_unavailable_records = 0
    for point in points:
        hi = max(1, int(total_rows * point.s_q))
        lo = 1
        _build_artifacts(
            pg_env=pg_env,
            artifact_availability=point.artifact_availability,
            artifact_id=artifact_id,
            keyed_artifact_id=keyed_artifact_id,
            mav_artifact_id=mav_artifact_id,
            policy_id=policy_id,
            user_id=user_id,
            ctx_hash=ctx_hash,
            exact_predicate=exact_predicate,
        )
        _, _, _, artifact_cardinality = _artifact_cardinalities(
            pg_env,
            artifact_id,
            keyed_artifact_id,
            point.artifact_availability,
        )
        available = _available_artifacts(point.artifact_availability)
        runner_sql_by_template: dict[str, str] = {}
        for template in TEMPLATE_CANDIDATES:
            sql_artifact_id = (
                keyed_artifact_id
                if template.template_id == "strong_auth_index_keyed_v1"
                else artifact_id
            )
            runner_sql_by_template[template.template_id] = _candidate_sql(
                template.template_id,
                exact_predicate,
                guard_predicate,
                lo,
                hi,
                sql_artifact_id,
                policy_id,
                user_id,
                ctx_hash,
            )
        prospective_template_id, prospective_planner_payload = _prospective_admission_first_plan(
            policy_id=policy_id,
            total_rows=total_rows,
            authorized_rows=authorized_rows,
            artifact_availability=point.artifact_availability,
            artifact_cardinality=artifact_cardinality,
            point=point,
            exact_predicate=exact_predicate,
            guard_predicate=guard_predicate,
            lo=lo,
            hi=hi,
            artifact_id=artifact_id,
            keyed_artifact_id=keyed_artifact_id,
            mav_relation=mav_artifact_id,
            user_id=user_id,
            ctx_hash=ctx_hash,
            runner_sql_by_template=runner_sql_by_template,
            pg_env=pg_env,
        )
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
        for repetition in iter_repetitions(repetitions):
            candidate_results: list[CandidateResult] = []
            for template in TEMPLATE_CANDIDATES:
                if not template.required_artifacts.issubset(available):
                    result = _unavailable_candidate(template, point.artifact_availability)
                    artifact_unavailable_records += 1
                else:
                    sql = runner_sql_by_template[template.template_id]
                    artifact_ids = _artifact_ids_for_template(
                        template.template_id,
                        artifact_id,
                        keyed_artifact_id,
                        mav_artifact_id,
                    )
                    measurement = _run_validated_e2_template(
                        template.template_id,
                        sql,
                        artifact_ids,
                        _expected_artifact_json(policy_id, ctx_hash),
                        pg_env,
                    )
                    if not measurement.validation.validation_passed:
                        raise PostgresError(
                            f"{template.template_id} validation or execution failed: "
                            f"{measurement.validation.failure_sqlstate}/"
                            f"{measurement.validation.failure_symbol}"
                        )
                    row_count = measurement.row_count
                    static_verification = _static_verification_from_timing(
                        measurement.timing,
                        sql,
                    )
                    static_verifier_explain_json = getattr(
                        measurement.timing,
                        "static_verifier_explain_json",
                        None,
                    )
                    if row_count != oracle_count:
                        raise PostgresError(
                            f"{template.template_id} returned {row_count}, expected {oracle_count}"
                        )
                    result = _candidate_result(
                        candidate=template,
                        artifact_availability=point.artifact_availability,
                        row_count=row_count,
                        planning_ms=measurement.timing.planning_ms,
                        execution_ms=measurement.timing.execution_ms,
                        oracle_count=oracle_count,
                        total_rows=total_rows,
                        auth_idx_cardinality=artifact_cardinality,
                        validation_ms=measurement.validation.elapsed_ms,
                        validation_same_snapshot=measurement.validation.same_snapshot,
                        validation_isolation_level=measurement.validation.isolation_level,
                        static_verification=static_verification,
                        static_verifier_explain_json=static_verifier_explain_json,
                        runner_sql=sql,
                    )
                candidate_results.append(result)
                raw_paths.append(
                    _write_main_record(
                        root=root,
                        manifest_path=manifest_path,
                        manifest_id=manifest_id,
                        stage=stage,
                        run_id=f"{point.point_id}_{template.template_id}",
                        run_kind="template_candidate",
                        mode="template-oracle",
                        candidate=result,
                        scale=scale,
                        seed=seed,
                        policy_id=policy_id,
                        context_id=context_id,
                        ctx_hash=ctx_hash,
                        pg_version=pg_version,
                        total_rows=total_rows,
                        authorized_rows=authorized_rows,
                        artifact_cardinality=artifact_cardinality,
                        point=point,
                        evaluation_role=FINITE_TEMPLATE_UPPER_BOUND_ROLE,
                        output_dir=output_dir,
                        repetition=repetition,
                        exact_predicate=exact_predicate,
                        guard_predicate=guard_predicate,
                        lo=lo,
                        hi=hi,
                        artifact_id=artifact_id,
                        keyed_artifact_id=keyed_artifact_id,
                        mav_relation=mav_artifact_id,
                        user_id=user_id,
                    )
                )
                candidate_records += 1

            eligible = [item for item in candidate_results if item.eligible_for_template_oracle]
            excluded = [item for item in candidate_results if not item.eligible_for_template_oracle]
            if not eligible:
                raise PostgresError(f"no eligible E2 templates for point={point.point_id}")
            admission_first = _prospective_admission_first_candidate(
                candidate_results,
                prospective_template_id,
            )
            if ADMISSION_FIRST_MODE in modes:
                raw_paths.append(
                    _write_main_record(
                        root=root,
                        manifest_path=manifest_path,
                        manifest_id=manifest_id,
                        stage=stage,
                        run_id=f"{point.point_id}_{ADMISSION_FIRST_MODE}",
                        run_kind="normal_mode",
                        mode=ADMISSION_FIRST_MODE,
                        candidate=admission_first,
                        scale=scale,
                        seed=seed,
                        policy_id=policy_id,
                        context_id=context_id,
                        ctx_hash=ctx_hash,
                        pg_version=pg_version,
                        total_rows=total_rows,
                        authorized_rows=authorized_rows,
                        artifact_cardinality=artifact_cardinality,
                        point=point,
                        evaluation_role=POLICY_ENFORCEMENT_ROLE,
                        output_dir=output_dir,
                        repetition=repetition,
                        exact_predicate=exact_predicate,
                        guard_predicate=guard_predicate,
                        lo=lo,
                        hi=hi,
                        artifact_id=artifact_id,
                        keyed_artifact_id=keyed_artifact_id,
                        mav_relation=mav_artifact_id,
                        user_id=user_id,
                        planner_payload_override=prospective_planner_payload,
                    )
                )
                normal_records += 1
            for mode in modes:
                if mode in {ADMISSION_FIRST_MODE, "template-oracle"}:
                    continue
                template_id = MODE_TO_TEMPLATE.get(mode)
                if template_id is None:
                    continue
                mode_candidate = _find_candidate(candidate_results, template_id)
                raw_paths.append(
                    _write_main_record(
                        root=root,
                        manifest_path=manifest_path,
                        manifest_id=manifest_id,
                        stage=stage,
                        run_id=f"{point.point_id}_{mode}",
                        run_kind="normal_mode",
                        mode=mode,
                        candidate=mode_candidate,
                        scale=scale,
                        seed=seed,
                        policy_id=policy_id,
                        context_id=context_id,
                        ctx_hash=ctx_hash,
                        pg_version=pg_version,
                        total_rows=total_rows,
                        authorized_rows=authorized_rows,
                        artifact_cardinality=artifact_cardinality,
                        point=point,
                        evaluation_role=POLICY_ENFORCEMENT_ROLE,
                        output_dir=output_dir,
                        repetition=repetition,
                        exact_predicate=exact_predicate,
                        guard_predicate=guard_predicate,
                        lo=lo,
                        hi=hi,
                        artifact_id=artifact_id,
                        keyed_artifact_id=keyed_artifact_id,
                        mav_relation=mav_artifact_id,
                        user_id=user_id,
                    )
                )
                normal_records += 1
            if "template-oracle" in modes:
                summary = _summary_record(
                    root=root,
                    manifest_path=manifest_path,
                    manifest_id=manifest_id,
                    artifact_availability=point.artifact_availability,
                    eligible=eligible,
                    excluded=excluded,
                    chosen=admission_first,
                    dataset_scale=scale,
                    seed=seed,
                    policy_id=policy_id,
                    context_id=context_id,
                    ctx_hash=ctx_hash,
                    pg_version=pg_version,
                    total_rows=total_rows,
                    authorized_rows=authorized_rows,
                    auth_idx_cardinality=artifact_cardinality,
                    s_auth=point.s_auth,
                    s_q=point.s_q,
                    policy_cost=point.policy_cost,
                    exact_predicate=exact_predicate,
                    guard_predicate=guard_predicate,
                    lo=lo,
                    hi=hi,
                    artifact_id=artifact_id,
                    keyed_artifact_id=keyed_artifact_id,
                    mav_relation=mav_artifact_id,
                    user_id=user_id,
                )
                summary["run_id"] = f"E2main_{point.point_id}_template_oracle_summary"
                summary["stage"] = stage
                summary["query"]["params"]["grid_point"] = point.point_id
                summary["template_oracle_summary"]["admission_first_planner"] = dict(
                    prospective_planner_payload
                )
                attach_repetition(summary, repetition)
                raw_paths.append(
                    _write_record(
                        summary,
                        output_dir,
                    )
                )
                summary_records += 1

    return E2MainResult(
        raw_result_paths=raw_paths,
        grid_points=len(points),
        candidate_records=candidate_records,
        normal_records=normal_records,
        summary_records=summary_records,
        artifact_unavailable_records=artifact_unavailable_records,
    )
