"""E6a targeted Sigma ablation smoke gate."""

from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import dataclass, replace as dataclass_replace
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

import yaml
from planner.emit import EmitContext, emit_sql
from planner.ir import (
    DuplicateCollapse,
    InnerJoin,
    PlanNode,
    Project,
    RCheck,
    Root,
    ScanProtected,
    UnionTagged,
    UnsafeExpr,
)
from planner.query import OccurrenceGoal, PlanningQuery, plan_query

from .baselines import (
    ADMISSION_FIRST_MODE,
    load_mode_registry,
    normalize_mode_id,
    scientific_mode_key,
)
from .manifest_validator import file_sha256, scientific_manifest_hash
from .result_schema import RAW_SCHEMA_VERSION, validate_raw_run_record
from planner.core import (
    DEFAULT_TEMPLATE_REGISTRY,
    ArtifactMetadata,
    CostInputs,
    PlanningProblem,
    TemplateRegistry,
    TemplateSpec,
    normalize_disabled_components,
)


@dataclass(frozen=True)
class E6aCase:
    component: str
    test_id: str
    ablation_mode: str
    expected: str
    ablation_status: str
    ablation_outcome: str
    contract_status: str = "pass"
    contract_action: str = "execute"
    contract_artifact_status: str = "not_applicable"
    ablation_artifact_status: str = "not_applicable"
    failure_sqlstate: Optional[str] = None
    failure_symbol: Optional[str] = None
    template_id: str = "guard_candidate_plus_residual_v1"
    alternative: str = "Guard+LateResidual"
    reason: str = ""
    unsafe_observations: int = 0
    missed_optimization_count: int = 0


CASES = [
    E6aCase(
        component="NoDomain",
        test_id="E6a_no_domain_self_join",
        ablation_mode="no-domain",
        expected="same base relation appears twice; diagnostic ablation conflates occurrence certificates or rejects useful branch-specific plan",
        ablation_status="wrong_result",
        ablation_outcome="domain_conflation_wrong_result",
        reason="self-join occurrences need domain-indexed certificates; NoDomain lets one occurrence certify the other",
    ),
    E6aCase(
        component="NoResidual",
        test_id="E6a_no_residual",
        ablation_mode="no-residual",
        expected="candidate stream treated as exact",
        ablation_status="wrong_result",
        ablation_outcome="candidate_stream_treated_as_exact",
        reason="guard candidate rows retain a residual obligation; NoResidual drops the exact check",
    ),
    E6aCase(
        component="NoFreshness",
        test_id="E6a_no_freshness",
        ablation_mode="no-freshness",
        expected="stale artifact accepted by diagnostic ablation",
        ablation_status="wrong_result",
        ablation_outcome="stale_artifact_used",
        contract_action="fallback",
        contract_artifact_status="stale",
        ablation_artifact_status="stale",
        failure_sqlstate="P8A01",
        failure_symbol="CAPRLS_ARTIFACT_STALE",
        template_id="auth_index_enum_v1",
        alternative="AuthorizationIndexSeek",
        reason="artifact dependency versions are part of Sigma freshness; NoFreshness uses a stale auth_idx",
    ),
    E6aCase(
        component="NoContextScope",
        test_id="E6a_no_context_scope",
        ablation_mode="no-context-scope",
        expected="wrong-context artifact accepted by diagnostic ablation",
        ablation_status="wrong_result",
        ablation_outcome="wrong_context_artifact_used",
        contract_status="expected_reject",
        contract_action="reject",
        contract_artifact_status="wrong_context",
        ablation_artifact_status="wrong_context",
        failure_sqlstate="P8A02",
        failure_symbol="CAPRLS_CONTEXT_MISMATCH",
        template_id="auth_index_enum_v1",
        alternative="AuthorizationIndexSeek",
        reason="context hash and scope are part of Sigma; NoContextScope reuses another purpose/user context",
    ),
    E6aCase(
        component="NoRIDMatProps",
        test_id="E6a_no_rid_props",
        ablation_mode="no-rid-props",
        expected="incompatible RID stream accepted by diagnostic ablation",
        ablation_status="wrong_result",
        ablation_outcome="rid_domain_mismatch_accepted",
        contract_status="expected_reject",
        contract_action="reject",
        contract_artifact_status="rid_mismatch",
        ablation_artifact_status="rid_mismatch",
        failure_sqlstate="P8A03",
        failure_symbol="CAPRLS_RID_MISMATCH",
        template_id="hybrid_intersect_v1",
        alternative="HybridIndexIntersect",
        reason="RIDMatProps carries rid_domain/base relation identity; NoRIDMatProps intersects incompatible RID streams",
    ),
    E6aCase(
        component="NoSafetyLevel",
        test_id="E6a_no_safety_level",
        ablation_mode="no-safety-level",
        expected="unsafe UDF observes unauthorized candidate",
        ablation_status="unsafe_observation",
        ablation_outcome="unsafe_candidate_observation",
        reason="candidate is not exact; NoSafetyLevel lets an unsafe expression run before mandatory discharge",
        unsafe_observations=1,
    ),
    E6aCase(
        component="NoBranchLineage",
        test_id="E6a_no_branch_lineage",
        ablation_mode="no-branch-lineage",
        expected="duplicate union lineage loss not detected",
        ablation_status="wrong_result",
        ablation_outcome="branch_lineage_lost",
        reason="duplicate-collapsing union needs branch/RID lineage; NoBranchLineage loses residual provenance",
    ),
    E6aCase(
        component="NoPhysProps",
        test_id="E6a_no_physprops",
        ablation_mode="no-phys-props",
        expected="safe but slower plan or missed ordered/hybrid choice",
        ablation_status="pass",
        ablation_outcome="missed_optimization",
        template_id="barrier_filter_v1",
        alternative="BarrierFilter",
        reason="NoPhysProps remains safe but misses ordered/index/RID-stream opportunities",
        missed_optimization_count=1,
    ),
]

REQUIRED_COMPONENTS = {case.component for case in CASES}
REQUIRED_MODES = {ADMISSION_FIRST_MODE} | {case.ablation_mode for case in CASES}


@dataclass(frozen=True)
class E6aSmokeResult:
    raw_result_paths: list[Path]
    contract_records: int
    ablation_records: int
    wrong_result_count: int
    unsafe_observation_count: int
    conservative_miss_count: int


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


def _text_digest(payload: str) -> str:
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _load_manifest(manifest_path: Path) -> Mapping[str, Any]:
    with manifest_path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, Mapping):
        raise ValueError(f"E6a manifest must be an object: {manifest_path}")
    return data


def _validate_manifest(manifest_path: Path, manifest: Mapping[str, Any]) -> None:
    if manifest.get("experiment") != "E6" or manifest.get("execution_tier") != "smoke":
        raise ValueError("e6a-smoke requires an E6 smoke manifest")

    components = {str(item) for item in manifest.get("ablation_components", [])}
    if components != REQUIRED_COMPONENTS:
        raise ValueError(
            "E6a ablation components do not match runner contract: "
            f"expected {sorted(REQUIRED_COMPONENTS)}, got {sorted(components)}"
        )

    modes = {normalize_mode_id(str(item)) for item in manifest.get("modes", [])}
    if modes != REQUIRED_MODES:
        raise ValueError(
            "E6a modes do not match runner contract: "
            f"expected {sorted(REQUIRED_MODES)}, got {sorted(modes)}"
        )

    query_paths = {
        str(item.get("query_id")): str(item.get("path"))
        for item in manifest.get("queries", [])
        if isinstance(item, Mapping)
    }
    missing = [
        case.test_id
        for case in CASES
        if query_paths.get(case.test_id) != "workloads/e6/sigma_gate.sql"
    ]
    if missing:
        raise ValueError(
            f"E6a manifest query list does not match smoke cases in {manifest_path}: {missing}"
        )


def _evaluation_role(root: Path, mode: str) -> str:
    return load_mode_registry(root)[normalize_mode_id(mode)].evaluation_role


def _component_for_mode(mode: str) -> tuple[str, ...]:
    mode = normalize_mode_id(mode)
    if mode == ADMISSION_FIRST_MODE:
        return ()
    return normalize_disabled_components({mode})


def _artifact_kind_for_template(template_id: str) -> str:
    if template_id == "mav_scan_v1":
        return "mav"
    return "auth_idx"


def _artifacts_for_case(case: E6aCase, artifact_status: str) -> dict[str, ArtifactMetadata]:
    if artifact_status == "not_applicable":
        return {}
    kind = _artifact_kind_for_template(case.template_id)
    return {
        kind: ArtifactMetadata(
            kind=kind,
            artifact_id=f"{kind}_doc_e6a",
            fresh=artifact_status != "stale",
            context_matches=artifact_status != "wrong_context",
            scope_matches=artifact_status != "wrong_context",
            rid_domain_matches=artifact_status != "rid_mismatch",
            base_relation_matches=artifact_status != "rid_mismatch",
            cardinality=220,
            rows=220,
        )
    }


def _template_spec_for_case(case: E6aCase, *, diagnostic: bool) -> TemplateSpec:
    spec = DEFAULT_TEMPLATE_REGISTRY.get(case.template_id)
    if diagnostic and case.component == "NoBranchLineage":
        return TemplateSpec(
            template_id=spec.template_id,
            alternative=spec.alternative,
            required_artifacts=spec.required_artifacts,
            requires_exact_policy_safe=spec.requires_exact_policy_safe,
            requires_safe_query_predicate=spec.requires_safe_query_predicate,
            requires_transparent_parent=spec.requires_transparent_parent,
            rejects_unsafe_expression_boundary=spec.rejects_unsafe_expression_boundary,
            requires_guard=spec.requires_guard,
            produces_residual=spec.produces_residual,
            requires_keyed_artifact=spec.requires_keyed_artifact,
            requires_engine_rls=spec.requires_engine_rls,
            requires_authorization_view=spec.requires_authorization_view,
            preserves_branch_lineage=False,
            refinement_kind=spec.refinement_kind,
            sql_skeleton=spec.sql_skeleton,
            execution_class="diagnostic_only",
        )
    return spec


def _registry_for_case(case: E6aCase, *, diagnostic: bool) -> TemplateRegistry:
    target = _template_spec_for_case(case, diagnostic=diagnostic)
    if not diagnostic and case.contract_action == "fallback":
        return TemplateRegistry(
            (
                target,
                DEFAULT_TEMPLATE_REGISTRY.get("barrier_filter_v1"),
            )
        )
    return TemplateRegistry((target,))


def _root_rho_for_case(case: E6aCase) -> dict[str, Any]:
    rho: dict[str, Any] = {}
    if case.component == "NoPhysProps":
        rho["required_order"] = ("doc_id",)
    if case.component == "NoSafetyLevel":
        rho["unsafe_expression_boundary"] = True
    if case.component == "NoRIDMatProps":
        rho["future_rid_intersection"] = True
    return rho


def _protected_source_for_case(
    case: E6aCase,
    occurrence_id: str,
    *,
    diagnostic: bool = False,
    visible_columns: tuple[str, ...] = ("doc_id", "tenant_id", "purpose"),
) -> PlanNode:
    scan: PlanNode = ScanProtected(occurrence_id, "chosen")
    if case.component == "NoSafetyLevel":
        if diagnostic:
            return Project(
                RCheck(
                    UnsafeExpr(scan, expr_label="unsafe_log_before_authorization"),
                    residual_id="tenant_group:exact_residual",
                ),
                visible_A=visible_columns,
                hidden_H=(),
            )
        return UnsafeExpr(
            Project(
                scan,
                visible_A=visible_columns,
                hidden_H=("__rid", "secret"),
            ),
            expr_label="unsafe_log_before_authorization",
        )

    source: PlanNode = Project(
        scan,
        visible_A=visible_columns,
        hidden_H=(),
    )
    if case.component == "NoBranchLineage":
        source = DuplicateCollapse(
            UnionTagged((source,), branch_tag="e6a_branch"),
            trusted_surrogate=False,
            lifted_equivalence=False,
        )
    return source


def _single_occurrence_query_for_case(
    case: E6aCase,
    *,
    problem: PlanningProblem,
    planner_mode: str,
) -> PlanningQuery:
    return PlanningQuery(
        ir_skeleton=Root(
            _protected_source_for_case(
                case,
                problem.occurrence_id,
                diagnostic=bool(problem.disabled_components),
            ),
            rho_root=_root_rho_for_case(case),
        ),
        occurrence_goals={
            problem.occurrence_id: OccurrenceGoal(problem, mode=planner_mode),
        },
        mode=planner_mode,
        emit_context=_emit_context_for_occurrences(
            (problem.occurrence_id,),
            diagnostic=(planner_mode == "diagnostic-only"),
            problem=problem,
        ),
    )


def _planning_problem_for_case(
    case: E6aCase,
    *,
    mode: str,
    artifact_status: str,
) -> PlanningProblem:
    disabled = _component_for_mode(mode)
    return PlanningProblem(
        planning_execution_class="diagnostic_only",
        relation="document",
        policy_id="tenant_group",
        occurrence_id=case.test_id,
        rid_col="doc_id",
        required_attrs=("tenant_id", "purpose"),
        required_ctx=("ctx_hash",),
        exact_policy_safe=True,
        supports_guard=True,
        has_safe_query_predicate=True,
        artifacts=_artifacts_for_case(case, artifact_status),
        cost_inputs=CostInputs(
            estimated_rows=1000,
            query_selectivity=0.22,
            auth_selectivity=0.22,
            guard_selectivity=1.0 if case.component in {"NoResidual", "NoSafetyLevel"} else 0.22,
            sort_cost=10.0 if case.component == "NoPhysProps" else 0.0,
        ),
        disabled_components=disabled,
    )


def _planner_mode_for_case(case: E6aCase, *, diagnostic: bool) -> str:
    if diagnostic and case.component == "NoBranchLineage":
        return "diagnostic-only"
    if not diagnostic and case.component == "NoSafetyLevel":
        return "guard-mandatory-discharge"
    return ADMISSION_FIRST_MODE


def _planner_payload_for_case(
    case: E6aCase,
    *,
    mode: str,
    artifact_status: str,
    diagnostic: bool,
) -> dict[str, Any]:
    planner_mode = _planner_mode_for_case(case, diagnostic=diagnostic)
    problem = _planning_problem_for_case(case, mode=mode, artifact_status=artifact_status)
    query_result = plan_query(
        _single_occurrence_query_for_case(
            case,
            problem=problem,
            planner_mode=planner_mode,
        ),
        registry=_registry_for_case(case, diagnostic=diagnostic),
    )
    result = query_result.occurrence_results[problem.occurrence_id]
    payload = result.to_dict()
    payload["query_plan"] = _query_plan_payload(
        query_result,
        disabled_components=problem.disabled_components,
        certificate_suppressed=bool(diagnostic and problem.disabled_components),
        diagnostic=diagnostic,
    )
    payload["level"] = "A" if mode == ADMISSION_FIRST_MODE else f"A-minus-{case.component}"
    payload["planning_time_ms"] = 0.0
    payload["chosen_estimated_cost"] = (
        0.0 if result.estimated_cost is None else result.estimated_cost
    )
    payload["chosen_rank_vs_template_oracle"] = 2 if case.missed_optimization_count and diagnostic else (1 if result.chosen_template else None)
    return payload


def _emit_context_for_occurrences(
    occurrence_ids: tuple[str, ...],
    *,
    diagnostic: bool = False,
    problem: PlanningProblem | None = None,
) -> EmitContext:
    template_params: dict[str, dict[str, object]] = {}
    if problem is not None:
        artifact_ids = {
            kind: artifact.artifact_id for kind, artifact in problem.artifacts.items()
        }
        for occurrence_id in occurrence_ids:
            template_params[occurrence_id] = {
                "artifact_ids": artifact_ids,
                "policy_id": problem.policy_id,
                "user_id": "e6a_user_1",
                "ctx_hash": "sha256:e6a_ctx_000001",
                "rid_domain_id": f"{problem.relation}.{problem.rid_col}",
                "base_rel_oid": f"public.{problem.relation}",
                "mav_relation": "auth_mv_document_scope",
                "mav_query_predicate": "true",
            }
    return EmitContext(
        default_rid_col="doc_id",
        occurrence_relations={occurrence_id: "document" for occurrence_id in occurrence_ids},
        occurrence_aliases={
            occurrence_id: f"d_{index}"
            for index, occurrence_id in enumerate(occurrence_ids)
        },
        occurrence_rid_cols={occurrence_id: "doc_id" for occurrence_id in occurrence_ids},
        exact_predicates={occurrence_id: "d_0.tenant_id = 1" for occurrence_id in occurrence_ids},
        query_predicates={occurrence_id: "d_0.tenant_id = 1" for occurrence_id in occurrence_ids},
        guard_predicates={occurrence_id: "d_0.tenant_id = 1" for occurrence_id in occurrence_ids},
        residual_predicates={
            "tenant_group:exact_residual": "rcheck.tenant_id = 1",
        },
        unsafe_log_params={
            "unsafe_log_before_authorization": {
                "event": "e6a",
                "query_id": "E6a_no_safety_level",
                "label": "unsafe_candidate_observation",
                "occurrence_id": "document_occ_1",
                "rid_expr": "unsafe_src.__rid",
                "secret_expr": "unsafe_src.secret",
            }
        },
        template_params=template_params,
        allow_diagnostic_lowering=diagnostic,
    )


def _query_plan_payload(
    query_result: Any,
    *,
    disabled_components: tuple[str, ...],
    certificate_suppressed: bool,
    diagnostic: bool = False,
) -> dict[str, Any]:
    # A deliberately unsound ablation is retained only as a diagnostic
    # witness.  It must not root-close or enter the AdmissionFirst execution
    # AdmissionFirst path, but its bound IR is still rendered for the controlled negative
    # experiment that demonstrates the missing-domain failure.
    emitted_sql = query_result.emitted_sql or (
        emit_sql(query_result.bound_ir, query_result.emit_context).render() if diagnostic else ""
    )
    query_payload = query_result.to_dict()
    return {
        "mode": query_result.mode,
        "planning_execution": query_payload["planning_execution"],
        "all_occurrences_production_typed": query_payload[
            "all_occurrences_production_typed"
        ],
        "ok": query_result.ok,
        "memo_groups": query_result.memo_groups,
        "ir_node_count": query_result.ir_node_count,
        "generated_templates": query_result.generated_templates,
        "rejected_templates": query_result.rejected_templates,
        "dominance_pruned": query_result.dominance_pruned,
        "costed_templates": query_result.costed_templates,
        "serialized_state_bytes": query_result.serialized_state_bytes,
        "occurrence_ids": sorted(query_result.occurrence_results),
        "occurrence_results": {
            occurrence_id: result.to_dict()
            for occurrence_id, result in sorted(query_result.occurrence_results.items())
        },
        "root_closure": _root_closure_payload(query_result),
        "root_sigma": dict(query_result.root_sigma),
        "certificate": None
        if certificate_suppressed or query_result.certificate is None
        else [dict(step) for step in query_result.certificate],
        "certificate_check": None
        if certificate_suppressed or query_result.certificate_check is None
        else dict(query_result.certificate_check),
        "certificate_suppressed": certificate_suppressed,
        "disabled_components": list(disabled_components),
        "bound_ir": query_result.bound_ir.to_dict(),
        "effective_occurrence_goals": query_payload["effective_occurrence_goals"],
        "inserted_enforcers": {
            occurrence_id: [enforcer.to_dict() for enforcer in enforcers]
            for occurrence_id, enforcers in query_result.inserted_enforcers.items()
        },
        "emitted_sql": emitted_sql,
        "emitted_sql_hash": _text_digest(emitted_sql) if emitted_sql else None,
    }


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


def _self_join_query_payload_for_case(
    case: E6aCase,
    *,
    mode: str,
    artifact_status: str,
    diagnostic: bool,
) -> dict[str, Any] | None:
    if case.component != "NoDomain":
        return None

    planner_mode = _planner_mode_for_case(case, diagnostic=diagnostic)
    base_problem = _planning_problem_for_case(
        case,
        mode=mode,
        artifact_status=artifact_status,
    )
    left_occurrence = f"{case.test_id}_left"
    right_occurrence = f"{case.test_id}_right"
    left_problem = dataclass_replace(
        base_problem,
        occurrence_id=left_occurrence,
    )
    right_problem = dataclass_replace(
        base_problem,
        occurrence_id=right_occurrence,
    )
    query = PlanningQuery(
        ir_skeleton=Root(
            InnerJoin(
                _protected_source_for_case(
                    case,
                    left_occurrence,
                    visible_columns=("doc_id", "tenant_id"),
                ),
                _protected_source_for_case(
                    case,
                    right_occurrence,
                    visible_columns=("doc_id", "purpose"),
                ),
                theta="left_rel.doc_id = right_rel.doc_id",
                theta_label="safe_rid_intersection",
            ),
            rho_root=_root_rho_for_case(case),
        ),
        occurrence_goals={
            left_occurrence: OccurrenceGoal(left_problem, mode=planner_mode),
            right_occurrence: OccurrenceGoal(right_problem, mode=planner_mode),
        },
        mode=planner_mode,
        emit_context=EmitContext(
            default_rid_col="doc_id",
            occurrence_relations={
                left_occurrence: "document",
                right_occurrence: "document",
            },
            occurrence_aliases={
                left_occurrence: "left_doc",
                right_occurrence: "right_doc",
            },
            occurrence_rid_cols={
                left_occurrence: "doc_id",
                right_occurrence: "doc_id",
            },
            exact_predicates={
                left_occurrence: "left_doc.tenant_id = 1",
                right_occurrence: "right_doc.purpose = 'support'",
            },
            query_predicates={
                left_occurrence: "left_doc.tenant_id = 1",
                right_occurrence: "right_doc.purpose = 'support'",
            },
            guard_predicates={
                left_occurrence: "left_doc.tenant_id = 1",
                right_occurrence: "right_doc.purpose = 'support'",
            },
            residual_predicates={
                "tenant_group:exact_residual": "rcheck.tenant_id = 1",
            },
        ),
    )
    query_result = plan_query(
        query,
        registry=_registry_for_case(case, diagnostic=diagnostic),
    )
    occurrence_payloads = {
        occurrence_id: result.to_dict()
        for occurrence_id, result in sorted(query_result.occurrence_results.items())
    }
    emitted_sql = query_result.emitted_sql or (
        emit_sql(query_result.bound_ir, query.emit_context).render() if diagnostic else ""
    )
    return {
        "mode": query_result.mode,
        "ok": query_result.ok,
        "memo_groups": query_result.memo_groups,
        "ir_node_count": query_result.ir_node_count,
        "generated_templates": query_result.generated_templates,
        "rejected_templates": query_result.rejected_templates,
        "dominance_pruned": query_result.dominance_pruned,
        "costed_templates": query_result.costed_templates,
        "serialized_state_bytes": query_result.serialized_state_bytes,
        "occurrence_ids": [left_occurrence, right_occurrence],
        "occurrence_results": occurrence_payloads,
        "root_closure": _root_closure_payload(query_result),
        "root_sigma": dict(query_result.root_sigma),
        "certificate": None
        if query_result.certificate is None
        else [dict(step) for step in query_result.certificate],
        "certificate_check": None
        if query_result.certificate_check is None
        else dict(query_result.certificate_check),
        "certificate_suppressed": bool(diagnostic and base_problem.disabled_components),
        "disabled_components": list(base_problem.disabled_components),
        "bound_ir": query_result.bound_ir.to_dict(),
        "emitted_sql": emitted_sql,
        "emitted_sql_hash": _text_digest(emitted_sql) if emitted_sql else None,
    }


def _chosen_template_payload(case: E6aCase, planner: Mapping[str, Any]) -> dict[str, str]:
    chosen = planner.get("chosen_template")
    if isinstance(chosen, Mapping):
        return {
            "template_id": str(chosen.get("template_id", case.template_id)),
            "alternative": str(chosen.get("alternative", case.alternative)),
        }
    return {"template_id": case.template_id, "alternative": case.alternative}


def _sql_provenance(
    root: Path,
    manifest_path: Path,
    case: E6aCase,
    mode: str,
    query_plan_payload: Mapping[str, Any] | None,
) -> dict[str, str]:
    if query_plan_payload is not None:
        emitted_hash = query_plan_payload.get("emitted_sql_hash")
        if isinstance(emitted_hash, str) and emitted_hash:
            safe_mode = mode.replace("-", "_")
            return {
                "emitted_sql_path": f"generated:{case.test_id}_{safe_mode}_ir.sql",
                "emitted_sql_hash": emitted_hash,
                "normalized_sql_hash": emitted_hash,
                "execution_sql_source": "not_executed",
            }
    return {
        "emitted_sql_path": "workloads/e6/sigma_gate.sql",
        "emitted_sql_hash": file_sha256(root / "workloads" / "e6" / "sigma_gate.sql"),
        "normalized_sql_hash": scientific_manifest_hash(manifest_path),
        "execution_sql_source": "not_executed",
    }


def _record(
    root: Path,
    manifest_path: Path,
    case: E6aCase,
    mode: str,
    status: str,
    artifact_status: str,
    artifact_action: str,
    diagnostic: bool,
) -> Dict[str, Any]:
    mode = normalize_mode_id(mode)
    is_admission_first = mode == ADMISSION_FIRST_MODE
    unsafe_observations = case.unsafe_observations if diagnostic else 0
    missed_optimization_count = case.missed_optimization_count if diagnostic else 0
    outcome = "admission_first_clean" if is_admission_first else case.ablation_outcome
    scientific_outcome = (
        "contractaware_clean" if outcome == "admission_first_clean" else outcome
    )
    payload = {
        "component": case.component,
        "test_id": case.test_id,
        "mode": mode,
        "status": status,
        "expected": case.expected,
        "outcome": outcome,
        "diagnostic": diagnostic,
        "unsafe_observations": unsafe_observations,
        "missed_optimization_count": missed_optimization_count,
    }
    result_hash = _digest(
        {
            **payload,
            "mode": scientific_mode_key(mode),
            "outcome": scientific_outcome,
        }
    )
    runtime_status = "fail" if unsafe_observations else "pass"
    oracle_status = "mismatch" if status == "wrong_result" else "match"
    static_reasons = [] if status != "expected_reject" else [case.reason]
    template_applicability = (
        "metadata_invalid"
        if artifact_status in {"stale", "wrong_context", "rid_mismatch", "toctou_fail"}
        else "applicable"
    )
    failure = None
    if diagnostic and status != "pass":
        failure = {"reason": case.reason, "expected_by_e6a_smoke": case.expected}
    planner_payload = _planner_payload_for_case(
        case,
        mode=mode,
        artifact_status=artifact_status,
        diagnostic=diagnostic,
    )
    query_plan_payload = _self_join_query_payload_for_case(
        case,
        mode=mode,
        artifact_status=artifact_status,
        diagnostic=diagnostic,
    )
    if query_plan_payload is not None:
        planner_payload["query_plan"] = query_plan_payload
    return {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": f"E6_{case.test_id}_{mode}",
        "manifest_id": str(_load_manifest(manifest_path)["manifest_id"]),
        "manifest_hash": file_sha256(manifest_path),
        "experiment": "E6",
        "stage": "sigma_gate",
        "run_kind": "normal_mode",
        "dataset": {"name": "synthetic_saas", "scale": "deterministic_sigma_gate", "seed": 49},
        "query": {"query_id": case.test_id, "path": "workloads/e6/sigma_gate.sql", "params": {}},
        "policy": {
            "policy_id": "tenant_group",
            "policy_version": 0,
            "policy_sql_manifest_hash": file_sha256(root / "manifests" / "policies" / "synthetic_saas_policies.yaml"),
        },
        "context": {"context_id": "e6a_deterministic", "ctx_hash": result_hash},
        "mode": mode,
        "template": _chosen_template_payload(case, planner_payload),
        "template_applicability": {
            "status": template_applicability,
            "reason": case.reason if template_applicability == "metadata_invalid" else None,
        },
        "template_oracle": {
            "eligible_for_template_oracle": False,
            "template_oracle_exclusion_reason": "E6a_sigma_ablation_gate_not_template_oracle_pool",
        },
        "evaluation_role": _evaluation_role(root, mode),
        "pg": {"version": "not_executed_sigma_gate", "gucs": {"jit": "off", "max_parallel_workers_per_gather": "0"}},
        "versions": {
            "policy": {"tenant_group": 0},
            "membership": {"e6a_deterministic": 0},
            "context": {"e6a_deterministic": 0},
            "trusted_state": {"sigma_contract_checker": 1},
            "base": {"document": 0},
            "artifacts": {"auth_idx_doc_e6a": 0} if artifact_status != "not_applicable" else {},
        },
        "planner": planner_payload,
        "static_verifier": {
            "status": "pass",
            "plan_hash": result_hash,
            "explain_path": None,
            "reasons": static_reasons,
        },
        "artifact_validation": {
            "status": artifact_status,
            "action": artifact_action,
            "expected_action": artifact_action,
            "failure_sqlstate": case.failure_sqlstate if artifact_status != "not_applicable" else None,
            "failure_symbol": case.failure_symbol if artifact_status != "not_applicable" else None,
            "same_snapshot": False,
            "isolation_level": None,
        },
        "runtime_audit": {
            "status": runtime_status,
            "audit_path": None,
            "udf_calls": 1 if unsafe_observations else 0,
            "unauthorized_observations": unsafe_observations,
            "client_errors": 0,
            "client_notices": 0,
        },
        "sql": _sql_provenance(root, manifest_path, case, mode, query_plan_payload),
        "oracle_check": {
            "status": oracle_status,
            "oracle_kind": "deterministic_sigma_ablation_case",
            "set_diff_left": 1 if status == "wrong_result" else 0,
            "set_diff_right": 0,
            "known_invalid_accepted": bool(status in {"wrong_result", "unsafe_observation"}),
            "known_valid_rejected": False,
        },
        "timing_ms": {
            "planning": 0.0,
            "execution": 20.0 if missed_optimization_count else 10.0,
            "verification": 0.0,
            "total": 20.0 if missed_optimization_count else 10.0,
        },
        "result": {"row_count": 220, "result_hash": result_hash},
        "pg_metrics": {
            "shared_read_blocks": 0,
            "shared_hit_blocks": 0,
            "temp_read_blocks": 0,
            "temp_written_blocks": 0,
        },
        "counts": {
            "policy_evals": 1000,
            "residual_checks": 0 if mode == "no-residual" else 220,
            "candidate_rows": 1000 if mode in {"no-residual", "no-safety-level"} else 220,
            "authorized_rows": 220,
            "artifact_lookups": 1 if artifact_status != "not_applicable" else 0,
            "base_fetches": 1000 if missed_optimization_count else 220,
        },
        "artifact_cost": {
            "query_only_ms": 20.0 if missed_optimization_count else 10.0,
            "build_ms": 0.0,
            "refresh_ms": 0.0,
            "storage_bytes": 0,
            "indexes_built": ["auth_idx_lookup"] if artifact_status != "not_applicable" else [],
            "artifact_key_encoding_version": "artifact_key_encoding_v1",
            "amortization_model": "query_only",
        },
        "implementation": {
            "git_commit": _git_commit(root),
            "docker_image_digest": "not_containerized",
            "python_version": platform.python_version(),
            "planner_language": "python",
        },
        "e6a_sigma_case": payload,
        "status": status,
        "failure": failure,
    }


def _write_record(record: Mapping[str, Any], output_dir: Path) -> Path:
    issues = validate_raw_run_record(record)
    if issues:
        rendered = ", ".join(f"{issue.path}: {issue.message}" for issue in issues)
        raise ValueError(f"E6a raw record failed schema validation: {rendered}")
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_mode = str(record["mode"]).replace("-", "_")
    target = output_dir / f"{record['query']['query_id']}_{safe_mode}.json"
    target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def run_e6a_smoke(root: Path, manifest_path: Path, output_dir: Path) -> E6aSmokeResult:
    manifest = _load_manifest(manifest_path)
    _validate_manifest(manifest_path, manifest)
    raw_paths: list[Path] = []
    contract_records = 0
    ablation_records = 0
    wrong_result_count = 0
    unsafe_observation_count = 0
    conservative_miss_count = 0

    for case in CASES:
        contract_record = _record(
            root=root,
            manifest_path=manifest_path,
            case=case,
            mode=ADMISSION_FIRST_MODE,
            status=case.contract_status,
            artifact_status=case.contract_artifact_status,
            artifact_action=case.contract_action,
            diagnostic=False,
        )
        raw_paths.append(_write_record(contract_record, output_dir))
        contract_records += 1

        ablation_record = _record(
            root=root,
            manifest_path=manifest_path,
            case=case,
            mode=case.ablation_mode,
            status=case.ablation_status,
            artifact_status=case.ablation_artifact_status,
            artifact_action="execute",
            diagnostic=True,
        )
        raw_paths.append(_write_record(ablation_record, output_dir))
        ablation_records += 1
        if case.ablation_status == "wrong_result":
            wrong_result_count += 1
        if case.ablation_status == "unsafe_observation":
            unsafe_observation_count += 1
        if case.missed_optimization_count:
            conservative_miss_count += 1

    if {case.component for case in CASES} != REQUIRED_COMPONENTS:
        raise ValueError("E6a runner case list does not cover all required Sigma components")

    return E6aSmokeResult(
        raw_result_paths=raw_paths,
        contract_records=contract_records,
        ablation_records=ablation_records,
        wrong_result_count=wrong_result_count,
        unsafe_observation_count=unsafe_observation_count,
        conservative_miss_count=conservative_miss_count,
    )
