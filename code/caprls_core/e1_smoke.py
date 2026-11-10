"""Deterministic E1 contract-correctness and admissibility smoke gate."""

from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional

import yaml

from .baselines import (
    ADMISSION_FIRST_MODE,
    load_mode_registry,
    normalize_mode_id,
    scientific_mode_key,
)
from .manifest_validator import file_sha256
from .result_schema import RAW_SCHEMA_VERSION, validate_raw_run_record
from planner.contracts import (
    GammaFact,
    GammaSnapshot,
    PolicyAccessTarget,
    canonical_predicate_digest,
    implementation_target_binding,
    target_refinement_subject_digest,
)
from planner.core import (
    DEFAULT_TEMPLATE_REGISTRY,
    ArtifactMetadata,
    CostInputs,
    PlanningProblem,
    TemplateRegistry,
    TemplateSpec,
    normalize_disabled_components,
)
from planner.emit import EmitContext
from planner.ir import DuplicateCollapse, PlanNode, Project, Root, ScanProtected, UnionTagged, UnsafeExpr
from planner.query import OccurrenceGoal, PlanningQuery, plan_query


@dataclass(frozen=True)
class E1Case:
    test_id: str
    query_path: str
    template_id: str
    alternative: str
    expected_admission_first: str
    contract_reason: str
    diagnostic_mode: Optional[str] = None
    diagnostic_status: Optional[str] = None
    artifact_status: str = "not_applicable"
    artifact_action: str = "execute"
    template_applicability: str = "applicable"


E1_PRINCIPAL_ID = "1"
E1_CONTEXT_DIGEST = "sha256:" + hashlib.sha256(
    b"e1-deterministic-context"
).hexdigest()
E1_EXACT_POLICY_PREDICATE = "d.tenant_id = 1"
E1_QUERY_PREDICATE = "d.doc_id BETWEEN 1 AND 100"
E1_MAV_QUERY_PREDICATE = "doc_id BETWEEN 1 AND 100"
E1_SMOKE_EVIDENCE_SCOPE = "e1_smoke_only_non_promotable"
E1_QUERY_FILTERED_CASES = frozenset(
    {
        "E1_query_filtered_as_bare_policyaccess",
        "E1_valid_query_filtered_target",
    }
)

KNOWN_INVALID_CASES = [
    E1Case(
        test_id="E1_incomplete_guard",
        query_path="workloads/e1/incomplete_guard.sql",
        template_id="guard_candidate_plus_residual_v1",
        alternative="Guard+LateResidual",
        expected_admission_first="expected_reject",
        contract_reason="guard candidate is incomplete for tenant_group; shared rows outside tenant may be lost",
        diagnostic_mode="incomplete-guard-candidate",
        diagnostic_status="wrong_result",
        template_applicability="contract_reject",
    ),
    E1Case(
        test_id="E1_stale_auth_idx",
        query_path="workloads/e1/stale_auth_idx.sql",
        template_id="auth_index_enum_v1",
        alternative="AuthorizationIndexSeek",
        expected_admission_first="expected_reject",
        contract_reason="artifact dependency version is stale after ACL revocation",
        diagnostic_mode="stale-artifact-user",
        diagnostic_status="wrong_result",
        artifact_status="stale",
        artifact_action="fallback",
        template_applicability="metadata_invalid",
    ),
    E1Case(
        test_id="E1_context_scope_mismatch",
        query_path="workloads/e1/context_scope_mismatch.sql",
        template_id="auth_index_enum_v1",
        alternative="AuthorizationIndexSeek",
        expected_admission_first="expected_reject",
        contract_reason="artifact context hash does not match the current principal/context",
        diagnostic_mode="wrong-context-artifact-user",
        diagnostic_status="wrong_result",
        artifact_status="wrong_context",
        artifact_action="reject",
        template_applicability="metadata_invalid",
    ),
    E1Case(
        test_id="E1_rid_domain_mismatch",
        query_path="workloads/e1/rid_domain_mismatch.sql",
        template_id="hybrid_intersect_v1",
        alternative="HybridIndexIntersect",
        expected_admission_first="expected_reject",
        contract_reason="ordinary and authorization RID streams use incompatible domains",
        diagnostic_mode="rid-domain-blind-intersection",
        diagnostic_status="wrong_result",
        artifact_status="rid_mismatch",
        artifact_action="reject",
        template_applicability="metadata_invalid",
    ),
    E1Case(
        test_id="E1_unsafe_udf_before_auth",
        query_path="workloads/e1/unsafe_udf_before_auth.sql",
        template_id="raw_pushdown_positive_control_v1",
        alternative="UnsafeRawPushdownPositiveControl",
        expected_admission_first="expected_reject",
        contract_reason="unsafe UDF would observe raw protected tuples before exact authorization",
        diagnostic_mode="unsafe-pushdown-positive-control",
        diagnostic_status="unsafe_observation",
        template_applicability="contract_reject",
    ),
    E1Case(
        test_id="E1_projection_drops_carrier",
        query_path="workloads/e1/projection_drop.sql",
        template_id="guard_candidate_plus_residual_v1",
        alternative="Guard+LateResidual",
        expected_admission_first="expected_reject",
        contract_reason="projection drops hidden RID/residual attributes before residual discharge",
        diagnostic_mode="ordinary-no-contract",
        diagnostic_status="wrong_result",
        template_applicability="contract_reject",
    ),
    E1Case(
        test_id="E1_duplicate_union_lineage_loss",
        query_path="workloads/e1/duplicate_union_lineage_loss.sql",
        template_id="guard_candidate_plus_residual_v1",
        alternative="Guard+LateResidual",
        expected_admission_first="expected_reject",
        contract_reason="duplicate-collapsing UNION loses branch/RID lineage before residual discharge",
        diagnostic_mode="ordinary-no-contract",
        diagnostic_status="wrong_result",
        template_applicability="contract_reject",
    ),
    E1Case(
        test_id="E1_query_filtered_as_bare_policyaccess",
        query_path="workloads/e1/query_filtered_as_bare_policyaccess.sql",
        template_id="mav_scan_v1",
        alternative="MaterializedAuthorizedViewScan",
        expected_admission_first="expected_reject",
        contract_reason="query-filtered artifact target is used as bare PolicyAccess(document)",
        diagnostic_mode="ordinary-no-contract",
        diagnostic_status="wrong_result",
        template_applicability="contract_reject",
    ),
]

KNOWN_VALID_CASES = [
    E1Case(
        test_id="E1_valid_barrier_exact",
        query_path="workloads/e1/valid_barrier_exact.sql",
        template_id="barrier_filter_v1",
        alternative="BarrierFilter",
        expected_admission_first="pass",
        contract_reason="exact authorization at protected access",
    ),
    E1Case(
        test_id="E1_valid_guard_late",
        query_path="workloads/e1/valid_guard_late.sql",
        template_id="guard_candidate_plus_residual_v1",
        alternative="Guard+LateResidual",
        expected_admission_first="pass",
        contract_reason="complete guard retains RID/residual attrs through transparent operators and discharges before deadline",
    ),
    E1Case(
        test_id="E1_valid_visible_projection_hidden_rid",
        query_path="workloads/e1/valid_visible_projection_hidden_rid.sql",
        template_id="guard_candidate_plus_residual_v1",
        alternative="Guard+LateResidual",
        expected_admission_first="pass",
        contract_reason="visible projection hides RID but hidden carrier survives until residual discharge",
    ),
    E1Case(
        test_id="E1_valid_unionall_branch_tags",
        query_path="workloads/e1/valid_unionall_branch_tags.sql",
        template_id="guard_candidate_plus_residual_v1",
        alternative="Guard+LateResidual",
        expected_admission_first="pass",
        contract_reason="UNION ALL branch tags are retained and branch-local residuals discharge before root",
    ),
    E1Case(
        test_id="E1_valid_query_filtered_target",
        query_path="workloads/e1/valid_query_filtered_target.sql",
        template_id="mav_scan_v1",
        alternative="MaterializedAuthorizedViewScan",
        expected_admission_first="pass",
        contract_reason="query-filtered target is used only under matching parent key requirement",
    ),
]

ALL_CASES = KNOWN_INVALID_CASES + KNOWN_VALID_CASES


@dataclass(frozen=True)
class E1SmokeResult:
    raw_result_paths: list[Path]
    admission_first_records: int
    diagnostic_records: int
    known_invalid_rejected: int
    known_valid_accepted: int


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
        manifest = yaml.safe_load(fh) or {}
    if not isinstance(manifest, Mapping):
        raise ValueError(f"E1 manifest must be an object: {manifest_path}")
    return manifest


def _manifest_query_paths(manifest_path: Path) -> dict[str, str]:
    manifest = _load_manifest(manifest_path)
    return {str(item["query_id"]): str(item["path"]) for item in manifest.get("queries", [])}


def _evaluation_role(root: Path, mode: str) -> str:
    return load_mode_registry(root)[normalize_mode_id(mode)].evaluation_role


def _component_for_case(case: E1Case, mode: str) -> tuple[str, ...]:
    if mode == ADMISSION_FIRST_MODE:
        return ()
    if mode == "ordinary-no-contract":
        if case.test_id == "E1_duplicate_union_lineage_loss":
            return normalize_disabled_components({"branch_lineage"})
        if case.test_id == "E1_query_filtered_as_bare_policyaccess":
            return normalize_disabled_components({"domain"})
        return normalize_disabled_components({"residual"})
    component_by_mode = {
        "incomplete-guard-candidate": "residual",
        "stale-artifact-user": "freshness",
        "wrong-context-artifact-user": "context_scope",
        "rid-domain-blind-intersection": "rid_props",
        "unsafe-pushdown-positive-control": "safety_level",
    }
    return normalize_disabled_components({component_by_mode[mode]})


def _planner_template_id_for_case(case: E1Case) -> str:
    return case.template_id


def _clone_template_spec(
    spec: TemplateSpec,
    *,
    alternative: str,
    preserves_branch_lineage: Optional[bool] = None,
    refinement_kind: Optional[str] = None,
) -> TemplateSpec:
    semantic_override = (
        preserves_branch_lineage is not None
        and preserves_branch_lineage != spec.preserves_branch_lineage
    ) or (refinement_kind is not None and refinement_kind != spec.refinement_kind)
    return TemplateSpec(
        template_id=spec.template_id,
        alternative=alternative,
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
        preserves_branch_lineage=(
            spec.preserves_branch_lineage
            if preserves_branch_lineage is None
            else preserves_branch_lineage
        ),
        refinement_kind=spec.refinement_kind if refinement_kind is None else refinement_kind,
        sql_skeleton=spec.sql_skeleton,
        execution_class=("diagnostic_only" if semantic_override else spec.execution_class),
    )


def _template_spec_for_case(case: E1Case, *, diagnostic: bool = False) -> TemplateSpec:
    if case.template_id == "raw_pushdown_positive_control_v1":
        spec = TemplateSpec(
            template_id=case.template_id,
            alternative=case.alternative,
            requires_exact_policy_safe=True,
            requires_transparent_parent=True,
            rejects_unsafe_expression_boundary=True,
            execution_class="diagnostic_only",
            sql_skeleton=(
                "SELECT unsafe_log({R}.{rid_col}) FROM {R} "
                "WHERE <ordinary_query_predicate_before_exact_policy>"
            ),
        )
    else:
        spec = DEFAULT_TEMPLATE_REGISTRY.get(_planner_template_id_for_case(case))
    preserves_branch_lineage = False if case.test_id == "E1_duplicate_union_lineage_loss" else None
    refinement_kind = (
        "query_filtered"
        if diagnostic and case.test_id in E1_QUERY_FILTERED_CASES
        else None
    )
    return _clone_template_spec(
        spec,
        alternative=case.alternative,
        preserves_branch_lineage=preserves_branch_lineage,
        refinement_kind=refinement_kind,
    )


def _registry_for_case(case: E1Case, *, diagnostic: bool = False) -> TemplateRegistry:
    return TemplateRegistry((_template_spec_for_case(case, diagnostic=diagnostic),))


def _artifact_kind_for_template(template_id: str) -> Optional[str]:
    if template_id == "mav_scan_v1":
        return "mav"
    if template_id in {
        "auth_index_enum_v1",
        "auth_index_semijoin_v1",
        "hybrid_intersect_v1",
    }:
        return "auth_idx"
    if template_id in {
        "strong_auth_index_keyed_v1",
        "auth_index_keyed_semijoin_v1",
    }:
        return "auth_idx_keyed"
    return None


def _artifacts_for_case(case: E1Case) -> dict[str, ArtifactMetadata]:
    kind = _artifact_kind_for_template(_planner_template_id_for_case(case))
    if kind is None:
        return {}
    artifact_status = case.artifact_status
    return {
        kind: ArtifactMetadata(
            kind=kind,
            artifact_id=f"{kind}_doc_e1",
            fresh=artifact_status != "stale",
            context_matches=artifact_status != "wrong_context",
            scope_matches=artifact_status != "wrong_context",
            rid_domain_matches=artifact_status != "rid_mismatch",
            base_relation_matches=artifact_status != "rid_mismatch",
            exact=True,
            keyed=kind == "auth_idx_keyed",
            cardinality=128,
            rows=128,
            key_domain_matches=artifact_status != "rid_mismatch",
        )
    }


def _root_rho_for_case(case: E1Case) -> dict[str, Any]:
    rho: dict[str, Any] = {}
    if case.test_id == "E1_query_filtered_as_bare_policyaccess":
        rho["licensed_refinements"] = ()
    elif case.test_id == "E1_valid_query_filtered_target":
        rho["licensed_refinements"] = ("query_filtered",)
    if case.test_id == "E1_projection_drops_carrier":
        rho["transparent"] = False
    if case.test_id == "E1_unsafe_udf_before_auth":
        rho["unsafe_expression_boundary"] = True
    return rho


def _ir_skeleton_for_case(case: E1Case) -> Root:
    occurrence = ScanProtected(case.test_id, "chosen")
    if case.test_id == "E1_projection_drops_carrier":
        source: PlanNode = Project(occurrence, visible_A=("tenant_id",), hidden_H=())
    else:
        source = Project(
            occurrence,
            visible_A=("doc_id", "tenant_id", "purpose"),
            hidden_H=(),
        )
    if case.test_id == "E1_unsafe_udf_before_auth":
        source = UnsafeExpr(source, expr_label="unsafe_log_before_authorization")
    elif case.test_id == "E1_duplicate_union_lineage_loss":
        source = DuplicateCollapse(
            UnionTagged((source,), branch_tag="e1_duplicate_branch"),
            trusted_surrogate=False,
            lifted_equivalence=False,
        )
    elif case.test_id == "E1_valid_unionall_branch_tags":
        source = UnionTagged((source,), branch_tag="e1_branch")
    return Root(source, rho_root=_root_rho_for_case(case))


def _planning_problem_for_case(case: E1Case, mode: str) -> PlanningProblem:
    artifacts = _artifacts_for_case(case)
    target: Optional[PolicyAccessTarget] = None
    target_bindings = ()
    query_predicate: Optional[str] = None
    require_typed_admission = False
    if mode == ADMISSION_FIRST_MODE and case.test_id in E1_QUERY_FILTERED_CASES:
        target = PolicyAccessTarget(
            relation="document",
            policy_id="tenant_group",
            occurrence_id=case.test_id,
            principal_id=E1_PRINCIPAL_ID,
            context_digest=E1_CONTEXT_DIGEST,
            policy_predicate_digest=canonical_predicate_digest(
                E1_EXACT_POLICY_PREDICATE
            ),
        )
        query_predicate = E1_MAV_QUERY_PREDICATE
        target_bindings = (
            implementation_target_binding(
                template_id="mav_scan_v1",
                target=target,
                rid_col="doc_id",
                refinement_kind="query_filtered",
                refinement_predicate=query_predicate,
            ),
        )
        require_typed_admission = True

    draft = PlanningProblem(
        relation="document",
        policy_id="tenant_group",
        occurrence_id=case.test_id,
        rid_col="doc_id",
        required_attrs=("tenant_id", "purpose"),
        required_ctx=("ctx_hash",),
        exact_policy_safe=True,
        supports_guard=case.test_id != "E1_incomplete_guard",
        has_safe_query_predicate=True,
        logical_target=target,
        implementation_target_bindings=target_bindings,
        query_predicate=query_predicate,
        planning_execution_class=(
            "production_normal"
            if require_typed_admission
            else "diagnostic_only"
        ),
        require_typed_admission=require_typed_admission,
        artifacts=artifacts,
        cost_inputs=CostInputs(
            estimated_rows=1000,
            query_selectivity=0.16,
            auth_selectivity=0.16,
            guard_selectivity=0.16 if case.test_id != "E1_incomplete_guard" else 1.0,
        ),
        disabled_components=_component_for_case(case, mode),
    )

    if not require_typed_admission:
        return draft
    assert target is not None
    binding = target_bindings[0]
    artifact = artifacts["mav"]
    snapshot_id = _digest(
        {
            "kind": "e1_typed_target_snapshot_v1",
            "evidence_scope": E1_SMOKE_EVIDENCE_SCOPE,
            "logical_target_digest": target.digest,
            "binding_digest": binding.digest,
        }
    )

    def fact(fact_id: str, kind: str, subject_digest: str) -> GammaFact:
        return GammaFact(
            fact_id=fact_id,
            kind=kind,
            subject_digest=subject_digest,
            verdict="pass",
            validator_version=f"{E1_SMOKE_EVIDENCE_SCOPE}:validator-v1",
            snapshot_id=snapshot_id,
            evidence_digest=_digest(
                {
                    "fact_id": fact_id,
                    "kind": kind,
                    "subject_digest": subject_digest,
                    "snapshot_id": snapshot_id,
                    "evidence_scope": E1_SMOKE_EVIDENCE_SCOPE,
                }
            ),
            dynamic=False,
        )

    gamma = GammaSnapshot(
        snapshot_id=snapshot_id,
        facts=(
            fact(
                f"e1:{case.test_id}:artifact-validation",
                "artifact_validation",
                artifact.artifact_id,
            ),
            fact(
                f"e1:{case.test_id}:target-refinement",
                "target_refinement",
                target_refinement_subject_digest(
                    binding,
                    target,
                    snapshot_id=snapshot_id,
                ),
            ),
        ),
    )
    return replace(draft, gamma_snapshot=gamma)


def _emit_context_for_case(case: E1Case, *, diagnostic: bool = False) -> EmitContext:
    occurrence_id = case.test_id
    return EmitContext(
        default_rid_col="doc_id",
        occurrence_relations={occurrence_id: "document"},
        occurrence_aliases={occurrence_id: "d"},
        occurrence_rid_cols={occurrence_id: "doc_id"},
        exact_predicates={occurrence_id: E1_EXACT_POLICY_PREDICATE},
        guard_predicates={occurrence_id: E1_EXACT_POLICY_PREDICATE},
        query_predicates={occurrence_id: E1_QUERY_PREDICATE},
        residual_predicates={
            "tenant_group:exact_residual": "rcheck.tenant_id = 1",
        },
        template_params={
            occurrence_id: {
                "artifact_ids": {
                    "auth_idx": "auth_idx_doc_e1",
                    "auth_idx_keyed": "auth_idx_keyed_doc_e1",
                    "mav": "mav_doc_e1",
                },
                "mav_relation": "auth_mv_document_scope",
                "mav_query_predicate": E1_MAV_QUERY_PREDICATE,
                "policy_id": "tenant_group",
                "user_id": E1_PRINCIPAL_ID,
                "ctx_hash": E1_CONTEXT_DIGEST,
                "rid_domain_id": "document.doc_id",
                "base_rel_oid": "public.document",
                "key_name": "doc_id",
                "key_predicate": "a.key_value::bigint BETWEEN 1 AND 100",
                "carrier_columns": ("doc_id", "tenant_id", "purpose"),
            }
        },
        allow_diagnostic_lowering=(
            _template_spec_for_case(
                case,
                diagnostic=diagnostic,
            ).execution_class
            == "diagnostic_only"
        ),
    )


def _planner_payload_for_case(case: E1Case, mode: str, status: str) -> dict[str, Any]:
    diagnostic = mode != ADMISSION_FIRST_MODE
    case_spec = _template_spec_for_case(case, diagnostic=diagnostic)
    planner_mode = (
        "diagnostic-only"
        if case_spec.execution_class == "diagnostic_only"
        else ADMISSION_FIRST_MODE
    )
    query_result = plan_query(
        PlanningQuery(
            ir_skeleton=_ir_skeleton_for_case(case),
            occurrence_goals={
                case.test_id: OccurrenceGoal(
                    _planning_problem_for_case(case, mode),
                    mode=planner_mode,
                )
            },
            mode=ADMISSION_FIRST_MODE,
            emit_context=_emit_context_for_case(case, diagnostic=diagnostic),
        ),
        registry=_registry_for_case(case, diagnostic=diagnostic),
    )
    result = query_result.occurrence_results[case.test_id]
    payload = result.to_dict()
    payload["query_plan"] = _query_plan_payload(query_result)
    payload["level"] = "A" if mode == ADMISSION_FIRST_MODE else "A-minus-E1"
    payload["planning_time_ms"] = 0.0
    payload["chosen_estimated_cost"] = 0.0 if result.estimated_cost is None else result.estimated_cost
    payload["chosen_rank_vs_template_oracle"] = (
        1 if result.chosen_template is not None and query_result.ok else None
    )
    return payload


def _admission_first_status_from_planner(planner: Mapping[str, Any]) -> str:
    query_plan = planner.get("query_plan")
    if isinstance(query_plan, Mapping) and bool(query_plan.get("ok")):
        return "pass"
    return "expected_reject"


def _query_plan_payload(query_result: Any) -> dict[str, Any]:
    emitted_sql = query_result.emitted_sql or ""
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
        "root_closure": {
            "ok": query_result.root_closure.ok,
            "reason": query_result.root_closure.reason,
            "domain_covering": query_result.root_closure.domain_covering,
            "live_pairs_certified": query_result.root_closure.live_pairs_certified,
            "residuals_closed": query_result.root_closure.residuals_closed,
        },
        "root_sigma": dict(query_result.root_sigma),
        "certificate": None
        if query_result.certificate is None
        else [dict(step) for step in query_result.certificate],
        "certificate_check": None
        if query_result.certificate_check is None
        else dict(query_result.certificate_check),
        "bound_ir": query_result.bound_ir.to_dict(),
        "effective_occurrence_goals": query_payload["effective_occurrence_goals"],
        "inserted_enforcers": {
            occurrence_id: [enforcer.to_dict() for enforcer in enforcers]
            for occurrence_id, enforcers in query_result.inserted_enforcers.items()
        },
        "emitted_sql": emitted_sql,
        "emitted_sql_hash": _text_digest(emitted_sql) if emitted_sql else None,
    }


def _chosen_template_payload(case: E1Case, planner: Mapping[str, Any]) -> dict[str, str]:
    chosen = planner.get("chosen_template")
    if isinstance(chosen, Mapping):
        return {
            "template_id": str(chosen.get("template_id", case.template_id)),
            "alternative": str(chosen.get("alternative", case.alternative)),
        }
    return {"template_id": case.template_id, "alternative": case.alternative}


def _target_candidate_payload(planner: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    candidates = planner.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return None
    candidate = candidates[0]
    return candidate if isinstance(candidate, Mapping) else None


def _sql_provenance(planner: Mapping[str, Any], fallback_hash: str) -> dict[str, Any]:
    query_plan = planner.get("query_plan")
    if isinstance(query_plan, Mapping):
        emitted_hash = query_plan.get("emitted_sql_hash")
        emitted_sql = query_plan.get("emitted_sql")
        if (
            isinstance(emitted_hash, str)
            and emitted_hash.startswith("sha256:")
            and isinstance(emitted_sql, str)
            and emitted_sql.strip()
        ):
            return {
                "emitted_sql_path": "generated:e1_contract_smoke_ir.sql",
                "emitted_sql_hash": emitted_hash,
                "normalized_sql_hash": emitted_hash,
                "execution_sql_source": "not_executed",
                "runner_sql": emitted_sql,
                "runner_sql_hash": _text_digest(emitted_sql),
            }
    return {
        "emitted_sql_path": None,
        "emitted_sql_hash": fallback_hash,
        "normalized_sql_hash": fallback_hash,
        "execution_sql_source": "not_executed",
    }


def _template_applicability_payload(
    case: E1Case,
    *,
    is_admission_first: bool,
    status: str,
    planner: Mapping[str, Any],
) -> dict[str, Optional[str]]:
    target = _target_candidate_payload(planner)
    if target is not None:
        applicability_status = str(target.get("template_applicability", "applicable"))
        reasons = target.get("rejection_reasons")
        if isinstance(reasons, list) and reasons:
            reason = "; ".join(str(reason) for reason in reasons)
        else:
            reason = None
    else:
        applicability_status = case.template_applicability if is_admission_first else "applicable"
        reason = None
    return {
        "status": applicability_status,
        "reason": reason if is_admission_first and status == "expected_reject" else None,
    }


def _record(
    root: Path,
    manifest_path: Path,
    case: E1Case,
    mode: str,
    status: str,
    evaluation_role: str,
    diagnostic: bool,
) -> dict[str, Any]:
    mode = normalize_mode_id(mode)
    is_admission_first = mode == ADMISSION_FIRST_MODE
    known_invalid = case in KNOWN_INVALID_CASES
    planner_payload = _planner_payload_for_case(case, mode, status)
    if is_admission_first:
        planner_status = _admission_first_status_from_planner(planner_payload)
        if status != planner_status:
            raise ValueError(
                f"E1 {case.test_id} AdmissionFirst status expectation {status!r} "
                f"does not match planner-derived status {planner_status!r}"
            )
        status = planner_status
    checker_payload = {
        "test_id": case.test_id,
        "mode": mode,
        "status": status,
        "status_source": "planner_query" if is_admission_first else "diagnostic_control",
        "reason": case.contract_reason,
        "diagnostic": diagnostic,
    }
    checker_digest_payload = {
        **checker_payload,
        "mode": scientific_mode_key(mode),
    }
    result_hash = _digest(checker_digest_payload)
    artifact_status = case.artifact_status if is_admission_first else (
        case.artifact_status if case.artifact_status != "not_applicable" else "not_applicable"
    )
    artifact_action = case.artifact_action if is_admission_first else "execute"
    expected_action = case.artifact_action if is_admission_first else "execute"
    known_invalid_accepted = bool(is_admission_first and known_invalid and status == "pass")
    known_valid_rejected = bool(is_admission_first and not known_invalid and status != "pass")
    runtime_status = "fail" if status == "unsafe_observation" else "pass"
    oracle_status = "match" if status in {"pass", "expected_reject"} else "mismatch"
    target_candidate = _target_candidate_payload(planner_payload)
    planner_reasons = []
    if target_candidate is not None:
        reasons = target_candidate.get("rejection_reasons")
        if isinstance(reasons, list):
            planner_reasons = [str(reason) for reason in reasons]
    return {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": f"E1_{case.test_id}_{mode}",
        "manifest_id": str(_load_manifest(manifest_path)["manifest_id"]),
        "manifest_hash": file_sha256(manifest_path),
        "experiment": "E1",
        "stage": "smoke",
        "run_kind": "normal_mode",
        "dataset": {"name": "synthetic_saas", "scale": "deterministic_contract", "seed": 42},
        "query": {"query_id": case.test_id, "path": case.query_path, "params": {}},
        "policy": {
            "policy_id": "tenant_group",
            "policy_version": 0,
            "policy_sql_manifest_hash": file_sha256(root / "manifests" / "policies" / "synthetic_saas_policies.yaml"),
        },
        "context": {"context_id": "e1_deterministic", "ctx_hash": result_hash},
        "mode": mode,
        "template": _chosen_template_payload(case, planner_payload),
        "template_applicability": _template_applicability_payload(
            case,
            is_admission_first=is_admission_first,
            status=status,
            planner=planner_payload,
        ),
        "template_oracle": {
            "eligible_for_template_oracle": bool(is_admission_first and status == "pass"),
            "template_oracle_exclusion_reason": None if is_admission_first and status == "pass" else "not_admissible_or_diagnostic",
        },
        "evaluation_role": evaluation_role,
        "pg": {"version": "not_executed_contract_smoke", "gucs": {"jit": "off", "max_parallel_workers_per_gather": "0"}},
        "versions": {
            "policy": {"tenant_group": 0},
            "membership": {"e1_deterministic": 0},
            "context": {"e1_deterministic": 0},
            "trusted_state": {"contract_checker": 1},
            "base": {"document": 0},
            "artifacts": {},
        },
        "planner": planner_payload,
        "static_verifier": {
            "status": "pass",
            "plan_hash": result_hash,
            "explain_path": None,
            "reasons": planner_reasons if is_admission_first and status == "expected_reject" else [],
        },
        "artifact_validation": {
            "status": artifact_status,
            "action": artifact_action,
            "expected_action": expected_action,
            "failure_sqlstate": _artifact_sqlstate(artifact_status),
            "failure_symbol": _artifact_symbol(artifact_status),
            "same_snapshot": False,
            "isolation_level": None,
        },
        "runtime_audit": {
            "status": runtime_status,
            "audit_path": None,
            "udf_calls": 1 if status == "unsafe_observation" else 0,
            "unauthorized_observations": 1 if status == "unsafe_observation" else 0,
            "client_errors": 0,
            "client_notices": 0,
        },
        "sql": _sql_provenance(planner_payload, result_hash),
        "oracle_check": {
            "status": oracle_status,
            "oracle_kind": "deterministic_contract_case",
            "set_diff_left": 0 if oracle_status == "match" else 1,
            "set_diff_right": 0 if oracle_status == "match" else 1,
            "known_invalid_accepted": known_invalid_accepted,
            "known_valid_rejected": known_valid_rejected,
        },
        "timing_ms": {"planning": 0.0, "execution": 0.0, "verification": 0.0, "total": 0.0},
        "result": {"row_count": 0, "result_hash": result_hash},
        "pg_metrics": {"shared_read_blocks": 0, "shared_hit_blocks": 0, "temp_read_blocks": 0, "temp_written_blocks": 0},
        "counts": {
            "policy_evals": 0,
            "residual_checks": 0,
            "candidate_rows": 0,
            "authorized_rows": 0,
            "artifact_lookups": 0,
            "base_fetches": 0,
        },
        "artifact_cost": {
            "query_only_ms": 0.0,
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
        "e1_contract_case": checker_payload,
        "status": status,
        "failure": None if not diagnostic else {"reason": "diagnostic baseline failure expected by E1 smoke"},
    }


def _artifact_sqlstate(status: str) -> Optional[str]:
    return {
        "stale": "P8A01",
        "wrong_context": "P8A02",
        "rid_mismatch": "P8A03",
        "toctou_fail": "P8A04",
    }.get(status)


def _artifact_symbol(status: str) -> Optional[str]:
    return {
        "stale": "CAPRLS_ARTIFACT_STALE",
        "wrong_context": "CAPRLS_CONTEXT_MISMATCH",
        "rid_mismatch": "CAPRLS_RID_MISMATCH",
        "toctou_fail": "CAPRLS_TOCTOU_FAIL",
    }.get(status)


def _write_record(record: Mapping[str, Any], output_dir: Path) -> Path:
    issues = validate_raw_run_record(record)
    if issues:
        rendered = ", ".join(f"{issue.path}: {issue.message}" for issue in issues)
        raise ValueError(f"E1 raw record failed schema validation: {rendered}")
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_mode = str(record["mode"]).replace("-", "_")
    target = output_dir / f"{record['query']['query_id']}_{safe_mode}.json"
    target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def run_e1_smoke(root: Path, manifest_path: Path, output_dir: Path) -> E1SmokeResult:
    query_paths = _manifest_query_paths(manifest_path)
    missing = [case.test_id for case in ALL_CASES if query_paths.get(case.test_id) != case.query_path]
    if missing:
        raise ValueError(f"E1 manifest query list does not match smoke cases: {missing}")

    raw_paths: list[Path] = []
    admission_first_records = 0
    diagnostic_records = 0
    known_invalid_rejected = 0
    known_valid_accepted = 0
    for case in ALL_CASES:
        contract_record = _record(
            root=root,
            manifest_path=manifest_path,
            case=case,
            mode=ADMISSION_FIRST_MODE,
            status=case.expected_admission_first,
            evaluation_role=_evaluation_role(root, ADMISSION_FIRST_MODE),
            diagnostic=False,
        )
        raw_paths.append(_write_record(contract_record, output_dir))
        admission_first_records += 1
        if case in KNOWN_INVALID_CASES and case.expected_admission_first == "expected_reject":
            known_invalid_rejected += 1
        if case in KNOWN_VALID_CASES and case.expected_admission_first == "pass":
            known_valid_accepted += 1

        if case.diagnostic_mode and case.diagnostic_status:
            diagnostic_record = _record(
                root=root,
                manifest_path=manifest_path,
                case=case,
                mode=case.diagnostic_mode,
                status=case.diagnostic_status,
                evaluation_role=_evaluation_role(root, case.diagnostic_mode),
                diagnostic=True,
            )
            raw_paths.append(_write_record(diagnostic_record, output_dir))
            diagnostic_records += 1

    if known_invalid_rejected != len(KNOWN_INVALID_CASES):
        raise ValueError("AdmissionFirst did not reject all E1 known-invalid cases")
    if known_valid_accepted != len(KNOWN_VALID_CASES):
        raise ValueError("AdmissionFirst did not accept all E1 known-valid cases")

    return E1SmokeResult(
        raw_result_paths=raw_paths,
        admission_first_records=admission_first_records,
        diagnostic_records=diagnostic_records,
        known_invalid_rejected=known_invalid_rejected,
        known_valid_accepted=known_valid_accepted,
    )
