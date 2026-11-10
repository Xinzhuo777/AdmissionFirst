"""Shared finite-template planner core.

This module is deliberately a prototype decision layer: it enumerates known
enforcement templates, checks contract preconditions, and ranks accepted
candidates by a deterministic cost model. PostgreSQL-backed runners still own
SQL execution, EXPLAIN verification, runtime audit, and oracle checks.
"""

from __future__ import annotations

import json
import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Optional

from caprls_core.baselines import (
    ADMISSION_FIRST_MODE,
    ADMISSION_FIRST_NO_DOMINANCE_MODE,
    normalize_mode_id,
)
from caprls_core.artifact_economics import (
    declared_q_u_amortized_ms,
    estimated_invalidation_count,
)

from .certificates import certificate_to_dicts, emit_flat_certificate
from .capabilities import certificate_builder, cost_extractor
from .contracts import (
    AdmissionDecision,
    AuthorizationViewBinding,
    GammaFact,
    GammaSnapshot,
    ImplementationTargetBinding,
    MemoGoal,
    NativeRLSSessionContract,
    PolicyAccessTarget,
    TARGET_REFINEMENT_KINDS,
    TemplateDefinition,
    canonical_predicate_digest,
    default_template_definitions,
    implementation_target_match_subject_digest,
    required_gamma_fact_kinds,
    target_refinement_subject_digest,
    template_definition,
)
from .kappa import kappa_sem_for_template
from .state import structured_sigma
from .verifier.cert_checker import check_certificate


DISABLED_COMPONENTS = frozenset(
    {
        "domain",
        "residual",
        "freshness",
        "context_scope",
        "rid_props",
        "safety_level",
        "branch_lineage",
        "phys_props",
    }
)

_INTERNAL_DIAGNOSTIC_MODE = "diagnostic-only"


def normalize_planner_mode(mode: str) -> str:
    """Normalize public mode ids while retaining the internal diagnostic path."""

    value = str(mode)
    if value == _INTERNAL_DIAGNOSTIC_MODE:
        return value
    return normalize_mode_id(value)


def normalize_disabled_components(components: Iterable[str] | None) -> tuple[str, ...]:
    if components is None:
        return ()
    normalized: set[str] = set()
    for component in components:
        key = str(component).strip().replace("-", "_")
        if key.startswith("no_"):
            key = key[3:]
        if not key:
            continue
        if key not in DISABLED_COMPONENTS:
            raise ValueError(f"unknown disabled planner component: {component}")
        normalized.add(key)
    return tuple(sorted(normalized))


@dataclass(frozen=True)
class TemplateSpec:
    template_id: str
    alternative: str
    required_artifacts: frozenset[str] = frozenset()
    requires_exact_policy_safe: bool = False
    requires_safe_query_predicate: bool = False
    requires_transparent_parent: bool = False
    rejects_unsafe_expression_boundary: bool = False
    requires_guard: bool = False
    produces_residual: bool = False
    requires_keyed_artifact: bool = False
    requires_engine_rls: bool = False
    requires_authorization_view: bool = False
    preserves_branch_lineage: bool = True
    refinement_kind: Optional[str] = None
    sql_skeleton: str = ""
    # Production registry entries are compiled from TemplateDefinition.  The
    # field is retained here because diagnostic studies deliberately construct
    # controlled variants of canonical semantics.
    execution_class: str = "production_normal"


@dataclass(frozen=True)
class ArtifactMetadata:
    kind: str
    artifact_id: str
    fresh: bool = True
    context_matches: bool = True
    rid_domain_matches: bool = True
    base_relation_matches: bool = True
    exact: bool = True
    keyed: bool = False
    scope_matches: bool = True
    cardinality: Optional[int] = None
    rows: Optional[int] = None
    key_name: Optional[str] = None
    key_value: Optional[str] = None
    key_value_cardinality: Optional[int] = None
    key_domain_matches: bool = True
    supports_equality_key: bool = False
    order_keys: tuple[str, ...] = ()
    build_ms: float = 0.0
    refresh_ms: float = 0.0
    storage_bytes: int = 0


@dataclass(frozen=True)
class ParentRequirement:
    logical_group_id: Optional[str] = None
    visible_columns: tuple[str, ...] = ()
    required_order: tuple[str, ...] = ()
    licensed_refinements: tuple[str, ...] = ("query_filtered",)
    residual_allowed: bool = True
    residual_deadline: str = "parent_transparent_boundary"
    min_safety_level: str = "exact_authorized"
    freshness_predicate: Optional[str] = None
    context_predicate: Optional[str] = None
    allowed_enforcers: tuple[str, ...] = ("residual_check", "validation_gate", "sort")
    observable_coverage: tuple[str, ...] = ()
    transparent: bool = True
    unsafe_expression_boundary: bool = False
    needs_branch_lineage: bool = False
    future_rid_intersection: bool = False


@dataclass(frozen=True)
class CostInputs:
    estimated_rows: int = 100_000
    query_selectivity: float = 1.0
    auth_selectivity: float = 0.1
    policy_eval_cost: float = 0.003
    residual_eval_cost: float = 0.002
    scan_cost_per_row: float = 0.001
    base_fetch_cost: float = 0.004
    artifact_lookup_cost: float = 0.2
    guard_selectivity: float = 0.25
    sort_cost: float = 0.0
    # Per-row write+rescan surcharge for MATERIALIZED CTE stages. Zero keeps
    # legacy heuristic behavior; runners that emit materialized barrier/guard/
    # hybrid SQL should charge it so the heuristic sees the same plan shape
    # PostgreSQL executes.
    materialize_cost_per_row: float = 0.0
    residual_check_cost: float = 0.0
    validation_gate_cost: float = 0.0
    materialize_cost: float = 0.0
    declared_reuse: Optional[int] = None
    declared_update_rate_per_hour: float = 0.0
    declared_ttl_s: float = 3600.0
    declared_contexts: int = 1000


PLANNING_EXECUTION_CLASSES = frozenset(
    {"unclassified", "production_normal", "diagnostic_only"}
)


@dataclass(frozen=True)
class PlanningProblem:
    relation: str
    policy_id: str
    occurrence_id: str
    rid_col: str
    required_attrs: tuple[str, ...] = ()
    required_ctx: tuple[str, ...] = ()
    exact_policy_safe: bool = False
    supports_guard: bool = False
    has_safe_query_predicate: bool = False
    engine_rls_available: bool = False
    engine_rls_policy_hash: Optional[str] = None
    authorization_view_binding: Optional[AuthorizationViewBinding] = None
    native_rls_session_contract: Optional[NativeRLSSessionContract] = None
    gamma_snapshot: Optional[GammaSnapshot] = None
    logical_target: Optional[PolicyAccessTarget] = None
    implementation_target_bindings: tuple[ImplementationTargetBinding, ...] = ()
    query_predicate: Optional[str] = None
    # New adapters are unclassified until their evidence role is explicit.
    # Only diagnostic-only untyped problems may use the legacy Gamma adapter.
    planning_execution_class: str = "unclassified"
    require_typed_admission: bool = False
    artifacts: Mapping[str, ArtifactMetadata] = field(default_factory=dict)
    parent_requirement: ParentRequirement = field(default_factory=ParentRequirement)
    cost_inputs: CostInputs = field(default_factory=CostInputs)
    disabled_components: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.planning_execution_class not in PLANNING_EXECUTION_CLASSES:
            raise ValueError("PlanningProblem planning_execution_class is invalid")

    @property
    def production_typed_admission(self) -> bool:
        return (
            self.planning_execution_class == "production_normal"
            and self.require_typed_admission
        )


def planning_execution_metadata(
    problem: PlanningProblem,
    *,
    execution_admitted: Optional[bool] = None,
) -> dict[str, Any]:
    admitted = (
        _planning_execution_rejection_code(problem) is None
        if execution_admitted is None
        else bool(execution_admitted)
    )
    production_typed = problem.production_typed_admission and admitted
    execution_class = problem.planning_execution_class
    return {
        "planning_execution_class": execution_class,
        "require_typed_admission": problem.require_typed_admission,
        "planning_execution_admitted": admitted,
        "production_typed_admission": production_typed,
        "non_promotable": not production_typed,
        "planning_evidence_role": (
            "production_normal_typed"
            if production_typed
            else (
                "diagnostic_only_non_promotable"
                if execution_class == "diagnostic_only"
                else "planning_execution_rejected"
            )
        ),
    }


def _planning_execution_rejection_code(
    problem: PlanningProblem,
    *,
    mode: Optional[str] = None,
    template: Optional[TemplateSpec] = None,
) -> Optional[str]:
    if problem.planning_execution_class == "unclassified":
        return "contract_reject:planning_execution_class_unclassified"
    if (
        problem.planning_execution_class == "production_normal"
        and not problem.require_typed_admission
    ):
        return "contract_reject:production_normal_requires_typed_admission"
    if problem.planning_execution_class == "production_normal" and (
        mode == "diagnostic-only"
        or (
            template is not None
            and template.execution_class == "diagnostic_only"
        )
    ):
        return "contract_reject:production_normal_diagnostic_path_forbidden"
    return None


@dataclass(frozen=True)
class ContractCheck:
    accepted: bool
    reasons: tuple[str, ...]
    delivered_sigma: Mapping[str, Any]
    template_applicability: str
    admission_decision: Optional[AdmissionDecision] = None


@dataclass(frozen=True)
class _LegacyDiagnosticCheckContext:
    """Problem-level facts shared by every template in one diagnostic plan.

    The legacy adapter, policy subject, and memo goal depend on the planning
    problem, not on a candidate template.  Preparing them once prevents a
    finite-template enumeration from replaying identical evidence work for
    every candidate while preserving the exact per-template checks below.
    """

    gamma: GammaSnapshot
    policy_subject: str
    memo_goal: MemoGoal


@dataclass(frozen=True)
class CandidatePlan:
    template_id: str
    alternative: str
    accepted: bool
    template_applicability: str
    rejection_reasons: tuple[str, ...]
    estimated_cost: Optional[float]
    delivered_sigma: Mapping[str, Any]
    emitted_sql: str
    kappa_sem: Mapping[str, Any] = field(default_factory=dict)
    certificate: Optional[tuple[Mapping[str, Any], ...]] = None
    certificate_check: Optional[Mapping[str, Any]] = None
    diagnostics: Mapping[str, Any] = field(default_factory=dict)
    pruned_by_dominance: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "template_id": self.template_id,
            "alternative": self.alternative,
            "accepted": self.accepted,
            "template_applicability": self.template_applicability,
            "rejection_reasons": list(self.rejection_reasons),
            "estimated_cost": self.estimated_cost,
            "kappa_sem": dict(self.kappa_sem),
            "delivered_sigma": dict(self.delivered_sigma),
            "emitted_sql": self.emitted_sql,
            "diagnostics": dict(self.diagnostics),
            "pruned_by_dominance": self.pruned_by_dominance,
            "certificate": None,
            "certificate_check": None,
        }
        if self.certificate is not None:
            payload["certificate"] = [dict(step) for step in self.certificate]
        if self.certificate_check is not None:
            payload["certificate_check"] = dict(self.certificate_check)
        return payload


@dataclass(frozen=True)
class PlanResult:
    mode: str
    generated_templates: int
    rejected_templates: int
    costed_templates: int
    chosen_template: Optional[CandidatePlan]
    emitted_sql: Optional[str]
    delivered_sigma: Mapping[str, Any]
    estimated_cost: Optional[float]
    rejection_reasons: Mapping[str, int]
    local_feature_vector: Optional[Mapping[str, Any]]
    parent_requirement_vector: Mapping[str, Any]
    candidates: tuple[CandidatePlan, ...]
    dominance_checks: int = 0
    dominance_pruned: int = 0
    disabled_components: tuple[str, ...] = ()
    planning_execution_class: str = "unclassified"
    require_typed_admission: bool = False
    planning_execution_admitted: bool = False

    def __post_init__(self) -> None:
        if self.planning_execution_class not in PLANNING_EXECUTION_CLASSES:
            raise ValueError("PlanResult planning_execution_class is invalid")

    @property
    def production_typed_admission(self) -> bool:
        return (
            self.planning_execution_class == "production_normal"
            and self.require_typed_admission
            and self.planning_execution_admitted
        )

    def to_dict(self) -> dict[str, Any]:
        production_typed = self.production_typed_admission
        return {
            "mode": self.mode,
            "planning_execution": {
                "planning_execution_class": self.planning_execution_class,
                "require_typed_admission": self.require_typed_admission,
                "planning_execution_admitted": self.planning_execution_admitted,
                "production_typed_admission": production_typed,
                "non_promotable": not production_typed,
                "planning_evidence_role": (
                    "production_normal_typed"
                    if production_typed
                    else (
                        "diagnostic_only_non_promotable"
                        if self.planning_execution_class == "diagnostic_only"
                        else "planning_execution_rejected"
                    )
                ),
            },
            "disabled_components": list(self.disabled_components),
            "generated_templates": self.generated_templates,
            "rejected_templates": self.rejected_templates,
            "costed_templates": self.costed_templates,
            "dominance_checks": self.dominance_checks,
            "dominance_pruned": self.dominance_pruned,
            "chosen_template": None
            if self.chosen_template is None
            else self.chosen_template.to_dict(),
            "emitted_sql": self.emitted_sql,
            "delivered_sigma": dict(self.delivered_sigma),
            "estimated_cost": self.estimated_cost,
            "rejection_reasons": dict(self.rejection_reasons),
            "local_feature_vector": None
            if self.local_feature_vector is None
            else dict(self.local_feature_vector),
            "parent_requirement_vector": dict(self.parent_requirement_vector),
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        }


class TemplateRegistry:
    def __init__(self, templates: Iterable[TemplateSpec]):
        ordered = tuple(templates)
        seen: set[str] = set()
        for template in ordered:
            if template.template_id in seen:
                raise ValueError(f"duplicate template_id: {template.template_id}")
            if template.execution_class != "diagnostic_only":
                try:
                    canonical = template_definition(template.template_id)
                except KeyError as exc:
                    raise ValueError(
                        "non-diagnostic template registry entries must use a canonical "
                        f"template ID: {template.template_id}"
                    ) from exc
                if canonical.execution_class == "diagnostic_only":
                    raise ValueError(
                        "diagnostic canonical template must be declared diagnostic_only: "
                        f"{template.template_id}"
                    )
                expected = template_spec_from_definition(canonical)
                # ``alternative`` is presentation metadata used by reports;
                # every semantic/admission/execution field must remain the
                # canonical one. Controlled ablations must use the explicit
                # diagnostic execution class rather than mutate a production
                # template under a familiar ID.
                if replace(template, alternative=expected.alternative) != expected:
                    raise ValueError(
                        "production template registry entry drifts from its canonical "
                        f"definition: {template.template_id}"
                    )
            seen.add(template.template_id)
        self._templates = ordered
        self._by_id = {template.template_id: template for template in ordered}

    def template_specs(self) -> tuple[TemplateSpec, ...]:
        return self._templates

    def get(self, template_id: str) -> TemplateSpec:
        return self._by_id[template_id]

    def validate_complete(self) -> None:
        """Verify that a canonical registry has no semantic/capability drift.

        Diagnostic study registries may intentionally use a modified
        ``TemplateSpec`` and are not validated here implicitly.  The default
        production registry calls this method at module initialization and CI
        exercises it explicitly.
        """

        from .contracts import validate_implementation_capabilities

        violations = list(validate_implementation_capabilities(raise_on_error=False))
        for spec in self._templates:
            try:
                definition = template_definition(spec.template_id)
            except KeyError:
                violations.append(f"unknown_template_spec:{spec.template_id}")
                continue
            expected = template_spec_from_definition(definition)
            if spec != expected:
                violations.append(f"registry_semantic_drift:{spec.template_id}")
        if violations:
            raise RuntimeError(
                "template registry is incomplete or drifted: "
                + ", ".join(sorted(set(violations)))
            )

    def select_for_mode(self, mode: str) -> tuple[TemplateSpec, ...]:
        mode = normalize_planner_mode(mode)
        if mode in {
            ADMISSION_FIRST_MODE,
            ADMISSION_FIRST_NO_DOMINANCE_MODE,
            "template-oracle",
        }:
            # Positive controls must never enter a normal selector merely
            # because a caller supplied a custom registry.  Diagnostic
            # execution requires the explicit mode below and is therefore
            # visible in experiment records as a separate class.
            return tuple(
                template
                for template in self._templates
                if template.execution_class != "diagnostic_only"
            )
        if mode == _INTERNAL_DIAGNOSTIC_MODE:
            diagnostic_templates = tuple(
                template
                for template in self._templates
                if template.execution_class == "diagnostic_only"
            )
            if not diagnostic_templates:
                raise ValueError("diagnostic-only mode requires a diagnostic template registry")
            return diagnostic_templates
        if mode == "local-greedy":
            return tuple(
                template
                for template in self._templates
                if template.execution_class != "diagnostic_only"
                and template.template_id
                not in {"hybrid_intersect_v1", "guard_candidate_plus_residual_v1"}
            )
        fixed = {
            "barrier-only": "barrier_filter_v1",
            "injection-only": "safe_predicate_injection_v1",
            "auth-view-only": "auth_view_scan_v1",
            "auth-index-enum-only": "auth_index_enum_v1",
            "strong-auth-index": "strong_auth_index_keyed_v1",
            "mav-only": "mav_scan_v1",
            "guard-late-only": "guard_candidate_plus_residual_v1",
            "guard-mandatory-discharge": "guard_candidate_plus_residual_v1",
        }
        if mode not in fixed:
            raise ValueError(f"mode is not supported by planner core: {mode}")
        return (self.get(fixed[mode]),)


def _artifact_for_requirement(
    artifacts: Mapping[str, ArtifactMetadata], required_kind: str
) -> Optional[ArtifactMetadata]:
    if required_kind in artifacts:
        return artifacts[required_kind]
    if required_kind == "auth_idx_keyed":
        artifact = artifacts.get("auth_idx")
        if artifact is not None and artifact.keyed:
            return artifact
    return None


def _artifact_ids_for_template(
    artifacts: Mapping[str, ArtifactMetadata], template: TemplateSpec
) -> dict[str, str]:
    artifact_ids: dict[str, str] = {}
    for required in sorted(template.required_artifacts):
        artifact = _artifact_for_requirement(artifacts, required)
        if artifact is not None:
            artifact_ids[required] = artifact.artifact_id
    return artifact_ids


def _stable_digest(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def policy_subject_digest(problem: PlanningProblem) -> str:
    if isinstance(problem.logical_target, PolicyAccessTarget):
        return problem.logical_target.digest
    return _stable_digest(
        {
            "relation": problem.relation,
            "policy_id": problem.policy_id,
            "occurrence_id": problem.occurrence_id,
            "rid_col": problem.rid_col,
        }
    )


def _finite_requirement_atoms(predicate: str | None) -> tuple[str, ...]:
    if not predicate:
        return ()
    return tuple(
        dict.fromkeys(
            atom.strip()
            for atom in str(predicate).split(" && ")
            if atom.strip()
        )
    )


# Retained for compatibility with focused unit tests and older adapters.  New
# typed analysis imports the public spelling above so the target subject is
# not reimplemented in each layer.
def _policy_subject_digest(problem: PlanningProblem) -> str:
    return policy_subject_digest(problem)


def legacy_gamma_snapshot_for_diagnostic(problem: PlanningProblem) -> GammaSnapshot:
    """Adapt legacy PlanningProblem flags into one versioned Gamma snapshot.

    This adapter is deliberately local to legacy tests/diagnostics. Production
    callers set ``require_typed_admission=True`` and are rejected when they do
    not provide validator-originated facts.
    """

    if (
        problem.planning_execution_class != "diagnostic_only"
        or problem.require_typed_admission
    ):
        raise ValueError(
            "legacy Gamma adapter requires an untyped diagnostic-only problem"
        )
    subject = _policy_subject_digest(problem)
    snapshot_id = _stable_digest(
        {
            "subject": subject,
            "engine_rls_policy_hash": problem.engine_rls_policy_hash,
            "view_binding": None
            if problem.authorization_view_binding is None
            else problem.authorization_view_binding.binding_id,
            "rls_contract": None
            if problem.native_rls_session_contract is None
            else problem.native_rls_session_contract.contract_id,
        }
    )

    def fact(kind: str, verdict: bool, subject_digest: str = subject) -> GammaFact:
        return GammaFact(
            fact_id=f"legacy:{kind}:{subject_digest}",
            kind=kind,
            subject_digest=subject_digest,
            verdict="pass" if verdict else "fail",
            validator_version="legacy-planning-problem-v1",
            snapshot_id=snapshot_id,
            evidence_digest=_stable_digest(
                {
                    "legacy_evidence": kind,
                    "subject": subject_digest,
                    "snapshot": snapshot_id,
                }
            ),
        )

    facts = [
        fact("exact_policy_safe", problem.exact_policy_safe),
        fact("safe_query_predicate", problem.has_safe_query_predicate),
    ]
    view = problem.authorization_view_binding
    if view is not None:
        facts.append(
            fact(
                "authorization_view_binding",
                view.matches(
                    relation=problem.relation,
                    rid_col=problem.rid_col,
                    policy_id=problem.policy_id,
                ),
                view.binding_id,
            )
        )
    rls = problem.native_rls_session_contract
    if rls is not None:
        facts.append(
            fact(
                "native_rls_session_contract",
                rls.matches(relation=problem.relation, policy_id=problem.policy_id),
                rls.contract_id,
            )
        )
    return GammaSnapshot(snapshot_id=snapshot_id, facts=tuple(facts))


def _memo_goal_for(problem: PlanningProblem, gamma: GammaSnapshot) -> MemoGoal:
    rho_digest = _stable_digest({"rho": problem.parent_requirement})
    return MemoGoal(
        relation=problem.relation,
        policy_id=problem.policy_id,
        occurrence_id=problem.occurrence_id,
        rid_col=problem.rid_col,
        rho_digest=rho_digest,
        gamma=gamma,
        logical_target=(
            problem.logical_target
            if isinstance(problem.logical_target, PolicyAccessTarget)
            else None
        ),
    )


def _prepare_legacy_diagnostic_check_context(
    problem: PlanningProblem,
) -> _LegacyDiagnosticCheckContext:
    gamma = legacy_gamma_snapshot_for_diagnostic(problem)
    return _LegacyDiagnosticCheckContext(
        gamma=gamma,
        policy_subject=_policy_subject_digest(problem),
        memo_goal=_memo_goal_for(problem, gamma),
    )


def _typed_target_admission(
    *,
    template: TemplateSpec,
    definition: TemplateDefinition | None,
    problem: PlanningProblem,
    gamma: GammaSnapshot,
) -> tuple[tuple[str, ...], Optional[ImplementationTargetBinding], tuple[str, ...]]:
    """Check logical-target and implementation binding identity before cost."""

    reasons: list[str] = []
    evidence_refs: list[str] = []
    target = problem.logical_target
    if target is None:
        reasons.append("contract_reject:logical_target_missing")
    elif not isinstance(target, PolicyAccessTarget):
        reasons.append("contract_reject:logical_target_invalid")
        target = None
    else:
        if target.relation != problem.relation:
            reasons.append("contract_reject:logical_target_relation_mismatch")
        if target.policy_id != problem.policy_id:
            reasons.append("contract_reject:logical_target_policy_mismatch")
        if target.occurrence_id != problem.occurrence_id:
            reasons.append("contract_reject:logical_target_occurrence_mismatch")

    if definition is None:
        reasons.append("contract_reject:implementation_target_kind_unknown")

    try:
        declared_bindings = tuple(problem.implementation_target_bindings)
    except TypeError:
        declared_bindings = ()
        reasons.append("contract_reject:implementation_target_binding_invalid")
    if any(not isinstance(item, ImplementationTargetBinding) for item in declared_bindings):
        reasons.append("contract_reject:implementation_target_binding_invalid")
    matching_bindings = tuple(
        item
        for item in declared_bindings
        if isinstance(item, ImplementationTargetBinding)
        and item.template_id == template.template_id
    )
    binding: Optional[ImplementationTargetBinding]
    if not matching_bindings:
        reasons.append("contract_reject:implementation_target_binding_missing")
        binding = None
    elif len(matching_bindings) != 1:
        reasons.append("contract_reject:implementation_target_binding_ambiguous")
        binding = None
    else:
        binding = matching_bindings[0]

    if binding is None:
        return tuple(reasons), None, ()

    if binding.occurrence_id != problem.occurrence_id:
        reasons.append("contract_reject:implementation_target_occurrence_mismatch")
    if target is not None and binding.logical_target_digest != target.digest:
        reasons.append("contract_reject:implementation_logical_target_mismatch")
    if definition is not None and (
        binding.implementation_target_kind != definition.target_kind
    ):
        reasons.append("contract_reject:implementation_target_kind_mismatch")
    if binding.rid_col != problem.rid_col:
        reasons.append("contract_reject:implementation_target_rid_mismatch")
    if target is not None and binding.context_digest != target.context_digest:
        reasons.append("contract_reject:implementation_target_context_mismatch")

    refinement_kind = binding.refinement_kind
    if (
        definition is not None
        and definition.target_kind == "query_filtered"
        and refinement_kind is None
    ):
        reasons.append("contract_reject:target_refinement_declaration_missing")
    if refinement_kind is not None:
        if (
            definition is None
            or refinement_kind not in definition.allowed_refinement_kinds
        ):
            reasons.append(
                f"contract_reject:target_refinement_not_supported:{refinement_kind}"
            )
        if refinement_kind not in TARGET_REFINEMENT_KINDS:
            reasons.append(
                f"contract_reject:target_refinement_kind_unknown:{refinement_kind}"
            )
        predicate = str(problem.query_predicate or "").strip()
        if not predicate:
            reasons.append("contract_reject:target_refinement_predicate_missing")
        elif binding.refinement_predicate_digest != canonical_predicate_digest(predicate):
            reasons.append("contract_reject:target_refinement_predicate_mismatch")
        if refinement_kind not in set(problem.parent_requirement.licensed_refinements):
            reasons.append(f"contract_reject:refinement_not_licensed:{refinement_kind}")
        if target is not None:
            subject = target_refinement_subject_digest(
                binding,
                target,
                snapshot_id=gamma.snapshot_id,
            )
            matching_facts = tuple(
                fact
                for fact in gamma.matching(
                    "target_refinement",
                    subject_digest=subject,
                    require_static=True,
                )
                if fact.accepted
            )
            if not matching_facts:
                reasons.append("contract_reject:target_refinement_fact_missing")
            else:
                evidence_refs.extend(fact.fact_id for fact in matching_facts)
    elif target is not None and binding.implementation_target_kind != "bare_occurrence":
        subject = implementation_target_match_subject_digest(
            binding,
            target,
            snapshot_id=gamma.snapshot_id,
        )
        matching_facts = tuple(
            fact
            for fact in gamma.matching(
                "implementation_target_match",
                subject_digest=subject,
                require_static=True,
            )
            if fact.accepted
        )
        if not matching_facts:
            reasons.append("contract_reject:implementation_target_match_fact_missing")
        else:
            evidence_refs.extend(fact.fact_id for fact in matching_facts)

    return tuple(reasons), binding, tuple(sorted(set(evidence_refs)))


class ContractChecker:
    def check(
        self,
        template: TemplateSpec,
        problem: PlanningProblem,
        mode: str = ADMISSION_FIRST_MODE,
        normalized_disabled_components: Iterable[str] | None = None,
        *,
        _include_rejected_sigma: bool = True,
        _legacy_diagnostic_context: _LegacyDiagnosticCheckContext | None = None,
    ) -> ContractCheck:
        mode = normalize_planner_mode(mode)
        disabled = (
            set(normalized_disabled_components)
            if normalized_disabled_components is not None
            else set(normalize_disabled_components(problem.disabled_components))
        )
        reasons: list[str] = []
        applicability = "applicable"
        compatibility_mode = "typed"
        execution_rejection = _planning_execution_rejection_code(
            problem,
            mode=mode,
            template=template,
        )
        if execution_rejection is not None:
            reasons.append(execution_rejection)
        gamma = problem.gamma_snapshot
        if (
            problem.planning_execution_class == "diagnostic_only"
            and not problem.require_typed_admission
        ):
            if _legacy_diagnostic_context is None:
                _legacy_diagnostic_context = _prepare_legacy_diagnostic_check_context(
                    problem
                )
            gamma = _legacy_diagnostic_context.gamma
            compatibility_mode = "legacy_diagnostic"
        elif gamma is None:
            if problem.require_typed_admission:
                # Still construct a typed memo key so rejection evidence is
                # deterministic, but never turn the old booleans into facts.
                gamma = GammaSnapshot(
                    snapshot_id=_stable_digest(
                        {
                            "missing_gamma": _policy_subject_digest(problem),
                            "occurrence_id": problem.occurrence_id,
                        }
                    )
                )
                reasons.append("contract_reject:gamma_snapshot_missing")
            else:
                gamma = GammaSnapshot(
                    snapshot_id=_stable_digest(
                        {
                            "classified_admission_rejection": (
                                execution_rejection or "typed_admission_required"
                            ),
                            "occurrence_id": problem.occurrence_id,
                        }
                    )
                )
        memo_goal = (
            _legacy_diagnostic_context.memo_goal
            if _legacy_diagnostic_context is not None
            else _memo_goal_for(problem, gamma)
        )
        evidence_refs: list[str] = []
        required_dynamic_fact_kinds: set[str] = set()
        try:
            definition = template_definition(template.template_id)
        except KeyError:
            definition = None
        implementation_target_binding: Optional[ImplementationTargetBinding] = None
        if problem.require_typed_admission:
            (
                target_reasons,
                implementation_target_binding,
                target_evidence_refs,
            ) = _typed_target_admission(
                template=template,
                definition=definition,
                problem=problem,
                gamma=gamma,
            )
            reasons.extend(target_reasons)
            evidence_refs.extend(target_evidence_refs)

        for required in sorted(template.required_artifacts):
            artifact = _artifact_for_requirement(problem.artifacts, required)
            if artifact is None:
                reasons.append(f"artifact_unavailable:{required}")
                applicability = "artifact_unavailable"
                continue
            artifact_reasons = _artifact_validation_reasons(
                template,
                required,
                artifact,
                disabled_components=disabled,
            )
            if artifact_reasons:
                reasons.extend(artifact_reasons)
                applicability = "metadata_invalid"
            if problem.require_typed_admission:
                if not gamma.has_pass(
                    "artifact_validation", subject_digest=artifact.artifact_id
                ):
                    reasons.append(f"contract_reject:artifact_fact_missing:{required}")
                else:
                    evidence_refs.extend(
                        fact.fact_id
                        for fact in gamma.matching(
                            "artifact_validation", subject_digest=artifact.artifact_id
                        )
                        if fact.accepted
                    )
                required_dynamic_fact_kinds.update(
                    {"artifact_freshness", "artifact_context", "artifact_toctou"}
                )

        policy_subject = (
            _legacy_diagnostic_context.policy_subject
            if _legacy_diagnostic_context is not None
            else _policy_subject_digest(problem)
        )
        if problem.require_typed_admission and definition is not None:
            for fact_kind in required_gamma_fact_kinds(definition):
                subjects = _required_gamma_subjects(
                    fact_kind,
                    problem=problem,
                    template=template,
                    policy_subject=policy_subject,
                )
                if not subjects:
                    reasons.append(f"contract_reject:gamma_fact_subject_missing:{fact_kind}")
                    continue
                for subject in subjects:
                    if not gamma.has_pass(fact_kind, subject_digest=subject):
                        reasons.append(
                            f"contract_reject:gamma_fact_missing:{fact_kind}"
                        )
                        continue
                    evidence_refs.extend(
                        fact.fact_id
                        for fact in gamma.matching(fact_kind, subject_digest=subject)
                        if fact.accepted
                    )
        if problem.require_typed_admission and problem.parent_requirement.context_predicate:
            context_atoms = _finite_requirement_atoms(
                problem.parent_requirement.context_predicate
            )
            context_facts = tuple(
                fact
                for fact in gamma.matching(
                    "root_context_evidence",
                    subject_digest=policy_subject,
                    require_static=True,
                )
                if fact.accepted
            )
            context_fact_ids = {fact.fact_id for fact in context_facts}
            if not context_atoms:
                reasons.append("contract_reject:root_context_predicate_invalid")
            for atom in context_atoms:
                if atom not in context_fact_ids:
                    reasons.append(
                        "contract_reject:root_context_evidence_missing:" + atom
                    )
            evidence_refs.extend(fact.fact_id for fact in context_facts)
        if (
            template.requires_exact_policy_safe
            and not gamma.has_pass("exact_policy_safe", subject_digest=policy_subject)
            and "safety_level" not in disabled
        ):
            reasons.append("contract_reject:exact_policy_not_safe_for_injection")
        elif template.requires_exact_policy_safe:
            evidence_refs.extend(
                fact.fact_id
                for fact in gamma.matching(
                    "exact_policy_safe", subject_digest=policy_subject
                )
                if fact.accepted
            )
        if (
            template.requires_safe_query_predicate
            and not gamma.has_pass("safe_query_predicate", subject_digest=policy_subject)
            and "safety_level" not in disabled
        ):
            reasons.append("contract_reject:missing_safe_query_predicate")
        elif template.requires_safe_query_predicate:
            evidence_refs.extend(
                fact.fact_id
                for fact in gamma.matching(
                    "safe_query_predicate", subject_digest=policy_subject
                )
                if fact.accepted
            )
        if template.requires_transparent_parent and not problem.parent_requirement.transparent:
            reasons.append("contract_reject:requires_transparent_parent")
        if (
            template.rejects_unsafe_expression_boundary
            and problem.parent_requirement.unsafe_expression_boundary
            and "safety_level" not in disabled
        ):
            reasons.append("contract_reject:inline_barrier_crosses_unsafe_boundary")
        try:
            canonical_target_kind = template_definition(template.template_id).target_kind
        except KeyError:
            canonical_target_kind = None
        refinement_kind = template.refinement_kind
        if refinement_kind is None and canonical_target_kind == "query_filtered":
            # A query-filtered target is itself a refinement obligation.  It
            # must not depend on an optional display-only predicate field;
            # otherwise SafePredicateInjection and the semi-join variants
            # bypass rho licensing while OrdinaryFirstExactCheck does not.
            refinement_kind = "query_filtered"
        if (
            not problem.require_typed_admission
            and
            refinement_kind
            and refinement_kind not in set(problem.parent_requirement.licensed_refinements)
            and "domain" not in disabled
        ):
            reasons.append(f"contract_reject:refinement_not_licensed:{refinement_kind}")
        if template.requires_guard and not problem.supports_guard and "residual" not in disabled:
            reasons.append("contract_reject:policy_has_no_complete_guard")
        if template.requires_authorization_view:
            view = problem.authorization_view_binding
            if view is None:
                reasons.append("contract_reject:authorization_view_binding_missing")
            elif not view.matches(
                relation=problem.relation,
                rid_col=problem.rid_col,
                policy_id=problem.policy_id,
            ):
                reasons.append("contract_reject:authorization_view_binding_invalid")
            elif not gamma.has_pass(
                "authorization_view_binding", subject_digest=view.binding_id
            ):
                reasons.append("contract_reject:authorization_view_fact_missing")
            else:
                evidence_refs.extend(
                    fact.fact_id
                    for fact in gamma.matching(
                        "authorization_view_binding", subject_digest=view.binding_id
                    )
                    if fact.accepted
                )
                required_dynamic_fact_kinds.add("authorization_view_binding")
        if template.requires_engine_rls:
            rls = problem.native_rls_session_contract
            if not problem.engine_rls_available:
                reasons.append("engine_rls_unavailable")
            elif rls is None:
                reasons.append("contract_reject:native_rls_session_contract_missing")
            elif not problem.engine_rls_policy_hash:
                reasons.append("contract_reject:native_rls_policy_fingerprint_missing")
            elif problem.engine_rls_policy_hash != rls.policy_fingerprint:
                reasons.append("contract_reject:native_rls_policy_fingerprint_mismatch")
            elif not rls.matches(relation=problem.relation, policy_id=problem.policy_id):
                reasons.append("contract_reject:native_rls_session_contract_invalid")
            elif not gamma.has_pass(
                "native_rls_session_contract", subject_digest=rls.contract_id
            ):
                reasons.append("contract_reject:native_rls_session_fact_missing")
            else:
                evidence_refs.extend(
                    fact.fact_id
                    for fact in gamma.matching(
                        "native_rls_session_contract", subject_digest=rls.contract_id
                    )
                    if fact.accepted
                )
                required_dynamic_fact_kinds.add("native_rls_session_contract")
        if (
            template.produces_residual
            and problem.parent_requirement.unsafe_expression_boundary
            and mode != "guard-mandatory-discharge"
            and "residual" not in disabled
            and "safety_level" not in disabled
        ):
            reasons.append("contract_reject:residual_crosses_unsafe_boundary")
        if (
            template.produces_residual
            and not problem.parent_requirement.transparent
            and mode != "guard-mandatory-discharge"
            and "residual" not in disabled
        ):
            reasons.append("contract_reject:residual_crosses_nontransparent_parent")
        if (
            problem.parent_requirement.needs_branch_lineage
            and not template.preserves_branch_lineage
            and "branch_lineage" not in disabled
        ):
            reasons.append("contract_reject:branch_lineage_not_preserved")

        if reasons and applicability == "applicable":
            applicability = "contract_reject"
        accepted = not reasons
        decision = AdmissionDecision(
            accepted=accepted,
            rejection_codes=tuple(reasons),
            evidence_refs=tuple(sorted(set(evidence_refs))),
            memo_goal=memo_goal,
            required_dynamic_fact_kinds=tuple(required_dynamic_fact_kinds),
            compatibility_mode=compatibility_mode,
            implementation_target_binding=implementation_target_binding,
        )
        return ContractCheck(
            accepted=accepted,
            reasons=tuple(reasons),
            # A rejected candidate's Sigma is useful only when callers retain
            # candidate diagnostics.  The low-overhead planner path discards
            # rejected candidates, so constructing and serializing that state
            # is pure repeated work and cannot affect admission or ranking.
            delivered_sigma=(
                _sigma_for_template(
                    template,
                    problem,
                    mode,
                    accepted,
                    disabled_components=disabled,
                    gamma_snapshot=gamma,
                    evidence_refs=tuple(evidence_refs),
                    policy_subject=policy_subject,
                )
                if accepted or _include_rejected_sigma
                else {}
            ),
            template_applicability=applicability,
            admission_decision=decision,
        )


def _required_gamma_subjects(
    fact_kind: str,
    *,
    problem: PlanningProblem,
    template: TemplateSpec,
    policy_subject: str,
) -> tuple[str, ...]:
    """Resolve every concrete subject a canonical Gamma requirement covers."""

    if fact_kind == "artifact_validation":
        subjects: list[str] = []
        for required in sorted(template.required_artifacts):
            artifact = _artifact_for_requirement(problem.artifacts, required)
            if artifact is not None:
                subjects.append(artifact.artifact_id)
        return tuple(subjects)
    if fact_kind == "authorization_view_binding":
        view = problem.authorization_view_binding
        return () if view is None else (view.binding_id,)
    if fact_kind == "native_rls_session_contract":
        contract = problem.native_rls_session_contract
        return () if contract is None else (contract.contract_id,)
    return (policy_subject,)


def _artifact_validation_reasons(
    template: TemplateSpec,
    required_kind: str,
    artifact: ArtifactMetadata,
    *,
    disabled_components: Iterable[str] = (),
) -> list[str]:
    disabled = set(disabled_components) if disabled_components else set()
    reasons: list[str] = []
    if not artifact.fresh and "freshness" not in disabled:
        reasons.append(f"metadata_invalid:{required_kind}:stale")
    if (
        not artifact.context_matches or not artifact.scope_matches
    ) and "context_scope" not in disabled:
        reasons.append(f"metadata_invalid:{required_kind}:wrong_context")
    if not artifact.rid_domain_matches and "rid_props" not in disabled:
        reasons.append(f"metadata_invalid:{required_kind}:rid_mismatch")
    if not artifact.base_relation_matches and "rid_props" not in disabled:
        reasons.append(f"metadata_invalid:{required_kind}:base_relation_mismatch")
    if not artifact.exact:
        reasons.append(f"metadata_invalid:{required_kind}:not_exact")
    if template.requires_keyed_artifact and not artifact.keyed:
        reasons.append(f"metadata_invalid:{required_kind}:not_keyed")
    if (
        template.requires_keyed_artifact
        and not artifact.key_domain_matches
        and "rid_props" not in disabled
    ):
        reasons.append(f"metadata_invalid:{required_kind}:key_domain_mismatch")
    return reasons


def _sigma_for_template(
    template: TemplateSpec,
    problem: PlanningProblem,
    mode: str,
    accepted: bool,
    *,
    disabled_components: Iterable[str] = (),
    gamma_snapshot: GammaSnapshot | None = None,
    evidence_refs: Iterable[str] = (),
    policy_subject: str | None = None,
) -> dict[str, Any]:
    disabled = set(disabled_components) if disabled_components else set()
    refs = tuple(sorted(set(str(ref) for ref in evidence_refs)))
    residual_deadline = None
    if accepted and template.produces_residual and "residual" not in disabled:
        residual_deadline = (
            "before_unsafe"
            if mode == "guard-mandatory-discharge"
            else problem.parent_requirement.residual_deadline
        )
    if template.required_artifacts:
        freshness = "valid_artifact" if accepted else "requires_validation"
        auth_set = "artifact_exact" if accepted else "unknown"
    elif template.requires_engine_rls:
        freshness = "engine_rls_policy" if accepted else "requires_engine_rls"
        auth_set = "engine_exact" if accepted else "unknown"
    elif template.produces_residual and "residual" not in disabled:
        freshness = "non_artifact_candidate"
        auth_set = "candidate"
    else:
        freshness = "non_artifact_exact"
        auth_set = "exact" if accepted else "unknown"
    safety_level = (
        "exact_authorized"
        if accepted and (not template.produces_residual or "residual" in disabled)
        else "candidate"
    )
    if accepted and "safety_level" in disabled:
        safety_level = "disabled_safety_level"
    occurrence_id = (
        "disabled_domain"
        if "domain" in disabled
        else problem.occurrence_id
    )
    branch_lineage = (
        "disabled_branch_lineage"
        if "branch_lineage" in disabled
        else ("preserved" if template.preserves_branch_lineage else "not_preserved")
    )
    required_order = () if "phys_props" in disabled else problem.parent_requirement.required_order
    delivered_order = () if "phys_props" in disabled else _delivered_order_keys_for_template(template, problem)
    if problem.production_typed_admission and accepted:
        recoverability_evidence_mode = "production_typed"
    elif (
        problem.planning_execution_class == "diagnostic_only"
        and not problem.require_typed_admission
    ):
        recoverability_evidence_mode = "legacy_diagnostic"
    else:
        recoverability_evidence_mode = "planning_rejected"
    gamma_snapshot_id = (
        gamma_snapshot.snapshot_id
        if gamma_snapshot is not None
        else "planning-rejected:missing-gamma"
    )
    context_evidence_refs: tuple[str, ...] = ()
    if gamma_snapshot is not None and accepted:
        admitted_refs = set(refs)
        context_evidence_refs = tuple(
            sorted(
                fact.fact_id
                for fact in gamma_snapshot.matching(
                    "root_context_evidence",
                    subject_digest=(
                        policy_subject
                        if policy_subject is not None
                        else policy_subject_digest(problem)
                    ),
                    require_static=True,
                )
                if fact.accepted and fact.fact_id in admitted_refs
            )
        )
    non_context_refs = tuple(
        ref for ref in refs if ref not in set(context_evidence_refs)
    )
    sigma = structured_sigma(
        relation=problem.relation,
        occurrence_id=occurrence_id,
        rid_col=problem.rid_col,
        policy_id=problem.policy_id,
        template_id=template.template_id,
        auth_summary=auth_set,
        freshness=freshness,
        context_scope="bound_context" if accepted else "unchecked",
        safety_level=safety_level,
        required_attrs=problem.required_attrs,
        required_ctx=problem.required_ctx,
        # A leaf has no physical branch tag.  If a live residual is actually
        # transported through UnionTagged, that transfer rule adds the
        # lineage Need together with the real emitted tag-column binding.
        required_lineage=(),
        residual_deadline=residual_deadline,
        branch_lineage=branch_lineage,
        required_order=required_order,
        delivered_order=delivered_order,
        trusted_reads=non_context_refs,
        freshness_evidence=non_context_refs,
        gamma_snapshot_id=gamma_snapshot_id,
        recoverability_evidence_mode=recoverability_evidence_mode,
    ).to_dict()
    sigma["PhysProps"]["amortization"] = (
        "declared_Q_U"
        if template.required_artifacts and problem.cost_inputs.declared_reuse is not None
        else "undeclared"
    )
    # Recoverability must consume validator-originated identities, not a
    # convenient hidden column.  Legacy compatibility facts remain visibly
    # marked and strict paths reject them before this state is emitted.
    if gamma_snapshot is not None:
        sigma["PhysProps"]["gamma_snapshot_id"] = gamma_snapshot.snapshot_id
        sigma["PhysProps"]["gamma_snapshot_digest"] = gamma_snapshot.digest
    if refs:
        sigma["PhysProps"]["trusted_reads"] = list(non_context_refs)
        sigma["PhysProps"]["gamma_evidence_refs"] = list(refs)
        sigma["PhysProps"]["freshness_evidence"] = list(non_context_refs)
    sigma["PhysProps"]["context_evidence"] = list(context_evidence_refs)
    if disabled:
        sigma["DisabledComponents"] = sorted(disabled)
    return sigma


def _delivered_order_keys_for_template(
    template: TemplateSpec, problem: PlanningProblem
) -> tuple[str, ...]:
    if template.template_id != "mav_scan_v1":
        return ()
    artifact = _artifact_for_requirement(problem.artifacts, "mav")
    if artifact is None:
        return ()
    return artifact.order_keys


class CostEstimator:
    def estimate(self, template: TemplateSpec, problem: PlanningProblem) -> float:
        c = problem.cost_inputs
        n = max(1, c.estimated_rows)
        q_rows = max(1.0, n * max(c.query_selectivity, 0.0))
        auth_rows = max(1.0, n * max(c.auth_selectivity, 0.0))
        artifact_rows = self._artifact_rows(template, problem, auth_rows)
        artifact_maintenance_ms = self._artifact_maintenance_ms(template, problem)

        if template.template_id == "barrier_filter_v1":
            return (
                n * (c.scan_cost_per_row + c.policy_eval_cost)
                + auth_rows * c.materialize_cost_per_row
                + c.sort_cost
            )
        if template.template_id == "barrier_filter_inline_v1":
            return q_rows * (c.scan_cost_per_row + c.policy_eval_cost) * 1.05 + c.sort_cost
        if template.template_id == "safe_predicate_injection_v1":
            return q_rows * (c.scan_cost_per_row + c.policy_eval_cost)
        if template.template_id == "ordinary_first_exact_check_v1":
            return q_rows * (c.scan_cost_per_row + c.policy_eval_cost) * 0.98
        if template.template_id == "native_pg_rls_v1":
            return q_rows * (c.scan_cost_per_row + c.policy_eval_cost)
        if template.template_id == "raw_pushdown_positive_control_v1":
            return q_rows * c.scan_cost_per_row
        if template.template_id == "auth_view_scan_v1":
            return auth_rows * c.scan_cost_per_row * 0.9 + c.sort_cost
        if template.template_id == "auth_index_enum_v1":
            return c.artifact_lookup_cost + artifact_rows * c.base_fetch_cost + artifact_maintenance_ms
        if template.template_id == "auth_index_semijoin_v1":
            semijoin_rows = min(q_rows, artifact_rows)
            return (
                c.artifact_lookup_cost
                + q_rows * c.scan_cost_per_row
                + semijoin_rows * c.base_fetch_cost * 0.5
                + artifact_maintenance_ms
            )
        if template.template_id == "strong_auth_index_keyed_v1":
            keyed_artifact = _artifact_for_requirement(problem.artifacts, "auth_idx_keyed")
            if keyed_artifact is not None and keyed_artifact.key_value_cardinality is not None:
                artifact_rows = float(max(1, keyed_artifact.key_value_cardinality))
            keyed_rows = min(artifact_rows, max(1.0, q_rows * max(c.auth_selectivity, 0.01)))
            return (
                c.artifact_lookup_cost
                + keyed_rows * c.base_fetch_cost * 0.75
                + artifact_maintenance_ms
            )
        if template.template_id == "auth_index_keyed_semijoin_v1":
            keyed_artifact = _artifact_for_requirement(problem.artifacts, "auth_idx_keyed")
            if keyed_artifact is not None and keyed_artifact.key_value_cardinality is not None:
                artifact_rows = float(max(1, keyed_artifact.key_value_cardinality))
            semijoin_rows = min(q_rows, artifact_rows)
            return (
                c.artifact_lookup_cost
                + q_rows * c.scan_cost_per_row
                + semijoin_rows * c.base_fetch_cost * 0.4
                + artifact_maintenance_ms
            )
        if template.template_id == "mav_scan_v1":
            order_bonus = 0.6 if problem.parent_requirement.required_order else 1.0
            return (
                c.artifact_lookup_cost
                + artifact_rows * c.scan_cost_per_row * order_bonus
                + artifact_maintenance_ms
            )
        if template.template_id == "guard_candidate_plus_residual_v1":
            candidate_rows = max(1.0, n * max(c.guard_selectivity, 0.0))
            return (
                n * c.scan_cost_per_row
                + candidate_rows * c.materialize_cost_per_row
                + candidate_rows * (c.residual_eval_cost + c.base_fetch_cost * 0.25)
            )
        if template.template_id == "hybrid_intersect_v1":
            intersect_rows = max(1.0, min(q_rows, artifact_rows))
            return (
                c.artifact_lookup_cost
                + q_rows * c.scan_cost_per_row
                + artifact_rows * c.scan_cost_per_row * 0.35
                + (q_rows + artifact_rows) * c.materialize_cost_per_row
                + intersect_rows * c.base_fetch_cost
                + artifact_maintenance_ms
            )
        raise ValueError(f"no cost model for template: {template.template_id}")

    def _artifact_rows(
        self, template: TemplateSpec, problem: PlanningProblem, default_rows: float
    ) -> float:
        for required in template.required_artifacts:
            artifact = _artifact_for_requirement(problem.artifacts, required)
            if artifact is None:
                continue
            if template.template_id == "mav_scan_v1" and artifact.rows is not None:
                return float(max(1, artifact.rows))
            if artifact.cardinality is not None:
                return float(max(1, artifact.cardinality))
        return default_rows

    def _artifact_maintenance_ms(self, template: TemplateSpec, problem: PlanningProblem) -> float:
        c = problem.cost_inputs
        if not template.required_artifacts or c.declared_reuse is None:
            return 0.0
        artifact: Optional[ArtifactMetadata] = None
        for required in template.required_artifacts:
            artifact = _artifact_for_requirement(problem.artifacts, required)
            if artifact is not None:
                break
        if artifact is None or (artifact.build_ms == 0.0 and artifact.refresh_ms == 0.0):
            return 0.0
        invalidations = estimated_invalidation_count(
            update_rate_per_hour=c.declared_update_rate_per_hour,
            ttl_s=c.declared_ttl_s,
            contexts=c.declared_contexts,
        )
        return declared_q_u_amortized_ms(
            query_ms=0.0,
            build_ms=artifact.build_ms,
            maintenance_unit_ms=artifact.refresh_ms,
            invalidation_count=invalidations,
            fallback_ms=0.0,
            reuse=c.declared_reuse,
        )


@dataclass(frozen=True)
class DominanceStats:
    candidates: tuple[CandidatePlan, ...]
    checks: int
    pruned: int


def _candidate_rank_key(candidate: CandidatePlan) -> tuple[float, str]:
    return (float(candidate.estimated_cost or 0.0), candidate.template_id)


def _candidate_rank_key_after_enforcers(
    candidate: CandidatePlan,
    rho: ParentRequirement,
    cost_inputs: CostInputs,
) -> tuple[float, str]:
    return (cost_after_enforcers(candidate, rho, cost_inputs), candidate.template_id)


def _residual_key_set(candidate: CandidatePlan) -> frozenset[str]:
    residuals = candidate.delivered_sigma.get("Residual") or []
    return frozenset(
        _residual_key(residual)
        for residual in residuals
        if isinstance(residual, Mapping)
    )


def _residual_key(residual: Mapping[str, Any]) -> str:
    return json.dumps(dict(residual), sort_keys=True, separators=(",", ":"))


def _residuals_covered_by(candidate: CandidatePlan, other: CandidatePlan) -> bool:
    return _residual_key_set(candidate).issubset(_residual_key_set(other))


def _auth_level(auth_set: Any) -> int:
    if isinstance(auth_set, Mapping):
        auth_set = auth_set.get("summary")
    if auth_set in {"exact", "artifact_exact", "engine_exact"}:
        return 2
    if auth_set == "candidate":
        return 1
    return 0


def _has_rid_carrier(candidate: CandidatePlan) -> bool:
    rid_props = candidate.delivered_sigma.get("RIDMatProps")
    return isinstance(rid_props, Mapping) and bool(rid_props.get("carrier"))


def _preserves_branch_lineage(candidate: CandidatePlan) -> bool:
    return candidate.delivered_sigma.get("BranchLineage") == "preserved"


def _delivered_order(candidate: CandidatePlan) -> tuple[str, ...]:
    phys = candidate.delivered_sigma.get("PhysProps")
    if not isinstance(phys, Mapping):
        return ()
    value = phys.get("delivered_order") or ()
    return tuple(str(item) for item in value)


def _satisfies_required_order(candidate: CandidatePlan, rho: ParentRequirement) -> bool:
    if not rho.required_order:
        return True
    delivered = _delivered_order(candidate)
    return tuple(rho.required_order) == delivered[: len(rho.required_order)]


def _candidate_residuals(candidate: CandidatePlan) -> tuple[Mapping[str, Any], ...]:
    residuals = candidate.delivered_sigma.get("Residual") or ()
    if not isinstance(residuals, Iterable) or isinstance(residuals, (str, bytes)):
        return ()
    return tuple(residual for residual in residuals if isinstance(residual, Mapping))


def _needs_validation_gate(candidate: CandidatePlan) -> bool:
    for step in candidate.certificate or ():
        if step.get("constructor") == "ArtifactValid":
            return True
    auth_set = candidate.delivered_sigma.get("AuthSet")
    if isinstance(auth_set, Mapping) and auth_set.get("summary") == "artifact_exact":
        return True
    return candidate.delivered_sigma.get("Freshness") == "valid_artifact"


def _satisfies_materialized_requirement(
    candidate: CandidatePlan,
    rho: ParentRequirement,
) -> bool:
    if "materialized" not in set(rho.observable_coverage):
        return True
    phys = candidate.delivered_sigma.get("PhysProps")
    return isinstance(phys, Mapping) and bool(phys.get("materialized"))


def required_enforcer_cost(
    candidate: CandidatePlan,
    rho: ParentRequirement,
    *,
    cost_inputs: CostInputs | None = None,
    sort_enforcer_cost: float | None = None,
) -> float:
    inputs = cost_inputs or CostInputs()
    if sort_enforcer_cost is not None and inputs.sort_cost != sort_enforcer_cost:
        inputs = replace(inputs, sort_cost=sort_enforcer_cost)
    allowed = set(rho.allowed_enforcers)
    total = 0.0

    if _candidate_residuals(candidate):
        if "residual_check" not in allowed:
            return float("inf")
        total += inputs.residual_check_cost

    if _needs_validation_gate(candidate):
        if "validation_gate" not in allowed:
            return float("inf")
        total += inputs.validation_gate_cost

    if rho.required_order and not _satisfies_required_order(candidate, rho):
        if "sort" not in allowed:
            return float("inf")
        total += inputs.sort_cost

    if not _satisfies_materialized_requirement(candidate, rho):
        if "materialize" not in allowed:
            return float("inf")
        total += inputs.materialize_cost

    return total


def cost_after_enforcers(
    candidate: CandidatePlan,
    rho: ParentRequirement,
    cost_inputs: CostInputs | None = None,
    *,
    sort_enforcer_cost: float | None = None,
) -> float:
    """Return the ranking cost after rho-required enforcers are accounted for."""

    if candidate.estimated_cost is None:
        return float("inf")
    enforcer_cost = required_enforcer_cost(
        candidate,
        rho,
        cost_inputs=cost_inputs,
        sort_enforcer_cost=sort_enforcer_cost,
    )
    return float(candidate.estimated_cost) + enforcer_cost


@dataclass(frozen=True)
class _DominanceProfile:
    cost_after_enforcers: float
    auth_level: int
    residual_keys: frozenset[str]
    preserves_branch_lineage: bool
    has_rid_carrier: bool


def _dominance_cost_inputs(
    cost_inputs: CostInputs | None,
    sort_enforcer_cost: float | None,
) -> CostInputs:
    inputs = cost_inputs or CostInputs()
    if sort_enforcer_cost is not None and inputs.sort_cost != sort_enforcer_cost:
        return replace(inputs, sort_cost=sort_enforcer_cost)
    return inputs


def _dominance_profile(
    candidate: CandidatePlan,
    rho: ParentRequirement,
    cost_inputs: CostInputs,
) -> _DominanceProfile:
    return _DominanceProfile(
        cost_after_enforcers=cost_after_enforcers(candidate, rho, cost_inputs),
        auth_level=_auth_level(candidate.delivered_sigma.get("AuthSet")),
        residual_keys=_residual_key_set(candidate),
        preserves_branch_lineage=_preserves_branch_lineage(candidate),
        has_rid_carrier=_has_rid_carrier(candidate),
    )


def _dominates_with_profiles(
    p1: CandidatePlan,
    p2: CandidatePlan,
    rho: ParentRequirement,
    p1_profile: _DominanceProfile,
    p2_profile: _DominanceProfile,
) -> bool:
    if not (p1.accepted and p2.accepted):
        return False
    if p1 is p2 or p1.template_id == p2.template_id:
        return False
    if p1.estimated_cost is None or p2.estimated_cost is None:
        return False
    if p1.delivered_sigma.get("Dom") != p2.delivered_sigma.get("Dom"):
        return False
    if p1_profile.auth_level < p2_profile.auth_level:
        return False
    if not p1_profile.residual_keys.issubset(p2_profile.residual_keys):
        return False
    if (
        rho.needs_branch_lineage
        and p2_profile.preserves_branch_lineage
        and not p1_profile.preserves_branch_lineage
    ):
        return False
    if rho.future_rid_intersection and p2_profile.has_rid_carrier and not p1_profile.has_rid_carrier:
        return False

    p1_cost = p1_profile.cost_after_enforcers
    p2_cost = p2_profile.cost_after_enforcers
    if p1_cost == float("inf"):
        return False
    if p1_cost > p2_cost:
        return False
    if p1_cost == p2_cost and p1.template_id > p2.template_id:
        return False
    return True


def dominates(
    p1: CandidatePlan,
    p2: CandidatePlan,
    rho: ParentRequirement,
    *,
    cost_inputs: CostInputs | None = None,
    sort_enforcer_cost: float | None = None,
) -> bool:
    """Return whether p1 is a rho-relative safe replacement for p2."""

    inputs = _dominance_cost_inputs(cost_inputs, sort_enforcer_cost)
    return _dominates_with_profiles(
        p1,
        p2,
        rho,
        _dominance_profile(p1, rho, inputs),
        _dominance_profile(p2, rho, inputs),
    )


def _apply_dominance_pruning(
    candidates: Iterable[CandidatePlan],
    rho: ParentRequirement,
    *,
    cost_inputs: CostInputs | None = None,
    sort_enforcer_cost: float,
    retain_pruned: bool = True,
) -> DominanceStats:
    inputs = _dominance_cost_inputs(cost_inputs, sort_enforcer_cost)
    candidate_tuple = tuple(candidates)
    accepted_candidates = tuple(candidate for candidate in candidate_tuple if candidate.accepted)
    profiles = {
        id(candidate): _dominance_profile(candidate, rho, inputs)
        for candidate in accepted_candidates
    }
    ordered = sorted(
        accepted_candidates,
        key=lambda candidate: (
            profiles[id(candidate)].cost_after_enforcers,
            candidate.template_id,
        ),
    )
    kept: list[CandidatePlan] = []
    pruned_by_id: dict[str, str] = {}
    checks = 0
    for candidate in ordered:
        dominator: CandidatePlan | None = None
        for kept_candidate in kept:
            checks += 1
            if _dominates_with_profiles(
                kept_candidate,
                candidate,
                rho,
                profiles[id(kept_candidate)],
                profiles[id(candidate)],
            ):
                dominator = kept_candidate
                break
        if dominator is None:
            kept.append(candidate)
        else:
            pruned_by_id[candidate.template_id] = dominator.template_id

    if retain_pruned:
        rewritten = tuple(
            replace(candidate, pruned_by_dominance=pruned_by_id.get(candidate.template_id))
            if candidate.template_id in pruned_by_id
            else candidate
            for candidate in candidate_tuple
        )
    else:
        rewritten = tuple(kept)
    return DominanceStats(candidates=rewritten, checks=checks, pruned=len(pruned_by_id))


def apply_dominance_pruning(
    candidates: Iterable[CandidatePlan],
    rho: ParentRequirement,
    *,
    cost_inputs: CostInputs | None = None,
    sort_enforcer_cost: float,
    retain_pruned: bool = True,
) -> DominanceStats:
    """Apply the public rho-relative dominance pass to an accepted candidate set."""

    return _apply_dominance_pruning(
        candidates,
        rho,
        cost_inputs=cost_inputs,
        sort_enforcer_cost=sort_enforcer_cost,
        retain_pruned=retain_pruned,
    )


def plan(
    problem: PlanningProblem,
    mode: str,
    registry: TemplateRegistry | None = None,
    checker: ContractChecker | None = None,
    estimator: CostEstimator | None = None,
    disabled_components: Iterable[str] | None = None,
    emit_certificates: bool = True,
    collect_candidate_payloads: bool = True,
) -> PlanResult:
    mode = normalize_planner_mode(mode)
    registry = registry or DEFAULT_TEMPLATE_REGISTRY
    checker = checker or ContractChecker()
    estimator = estimator or CostEstimator()
    requested_disabled = list(problem.disabled_components)
    if disabled_components is not None:
        requested_disabled.extend(disabled_components)
    normalized_disabled = normalize_disabled_components(requested_disabled)
    if normalized_disabled != tuple(problem.disabled_components):
        problem = replace(problem, disabled_components=normalized_disabled)
    specs = registry.select_for_mode(mode)
    local_problem = _local_problem(problem) if mode == "local-greedy" else problem
    planning_execution_admitted = (
        _planning_execution_rejection_code(local_problem, mode=mode) is None
        and all(
            _planning_execution_rejection_code(
                local_problem,
                mode=mode,
                template=spec,
            )
            is None
            for spec in specs
        )
    )
    diagnostic_ablation = bool(local_problem.disabled_components)
    legacy_diagnostic_context = (
        _prepare_legacy_diagnostic_check_context(local_problem)
        if type(checker) is ContractChecker
        and local_problem.planning_execution_class == "diagnostic_only"
        and not local_problem.require_typed_admission
        else None
    )

    candidates: list[CandidatePlan] = []
    rejection_counts: dict[str, int] = {}
    for spec in specs:
        execution_rejection = _planning_execution_rejection_code(
            local_problem,
            mode=mode,
            template=spec,
        )
        if type(checker) is ContractChecker:
            check = checker.check(
                spec,
                local_problem,
                mode=mode,
                normalized_disabled_components=normalized_disabled,
                _include_rejected_sigma=collect_candidate_payloads,
                _legacy_diagnostic_context=legacy_diagnostic_context,
            )
        else:
            # Preserve the long-standing provider interface for controlled
            # checker subclasses.  They remain responsible for their own
            # diagnostic work and receive no private optimization keyword.
            check = checker.check(
                spec,
                local_problem,
                mode=mode,
                normalized_disabled_components=normalized_disabled,
            )
        if execution_rejection is not None:
            rejection_codes = (
                execution_rejection,
                *(
                    reason
                    for reason in check.reasons
                    if reason != execution_rejection
                ),
            )
            admission_decision = check.admission_decision
            if admission_decision is not None:
                admission_decision = replace(
                    admission_decision,
                    accepted=False,
                    rejection_codes=rejection_codes,
                )
            check = ContractCheck(
                accepted=False,
                reasons=rejection_codes,
                delivered_sigma={},
                template_applicability="contract_reject",
                admission_decision=admission_decision,
            )
        kappa_sem: Mapping[str, Any] = {}
        if emit_certificates or collect_candidate_payloads:
            kappa_sem = kappa_sem_for_template(
                spec.template_id,
                relation=local_problem.relation,
                policy_id=local_problem.policy_id,
                occurrence_id=local_problem.occurrence_id,
                required_attrs=local_problem.required_attrs,
                required_ctx=local_problem.required_ctx,
                residual_deadline="before_unsafe"
                if mode == "guard-mandatory-discharge"
                else local_problem.parent_requirement.residual_deadline,
            ).to_dict()
        certificate: Optional[tuple[Mapping[str, Any], ...]] = None
        certificate_check: Optional[Mapping[str, Any]] = None
        if check.accepted:
            try:
                definition = template_definition(spec.template_id)
            except KeyError:
                definition = None
            if definition is None or definition.execution_class == "diagnostic_only":
                # Diagnostic-only studies deliberately keep their execution
                # outside the production capability matrix.
                estimated_cost = estimator.estimate(spec, local_problem)
            else:
                estimated_cost = cost_extractor(
                    str(definition.cost_extractor_id)
                )(spec, local_problem, estimator=estimator)
            if emit_certificates and not diagnostic_ablation:
                if definition is None or definition.execution_class == "diagnostic_only":
                    build_certificate = emit_flat_certificate
                else:
                    build_certificate = certificate_builder(
                        str(definition.certificate_builder_id)
                    )
                emitted_certificate = build_certificate(
                    template_id=spec.template_id,
                    kappa_sem=kappa_sem,
                    delivered_sigma=check.delivered_sigma,
                    artifact_ids=_artifact_ids_for_template(local_problem.artifacts, spec),
                )
                certificate = tuple(certificate_to_dicts(emitted_certificate))
                checked_certificate = check_certificate(
                    certificate,
                    expected_sigma=check.delivered_sigma,
                    template_id=spec.template_id,
                )
                certificate_check = checked_certificate.to_dict()
                if not checked_certificate.ok:
                    rendered = ", ".join(reject.reason for reject in checked_certificate.rejects)
                    raise ValueError(f"certificate check failed for {spec.template_id}: {rendered}")
        else:
            estimated_cost = None
            for reason in check.reasons:
                rejection_counts[reason] = rejection_counts.get(reason, 0) + 1
        diagnostics: Mapping[str, Any] = {}
        if collect_candidate_payloads:
            admission = check.admission_decision
            admission_payload: Mapping[str, Any] = {}
            if admission is not None:
                admission_payload = {
                    "memo_goal": {
                        "relation": admission.memo_goal.relation,
                        "policy_id": admission.memo_goal.policy_id,
                        "occurrence_id": admission.memo_goal.occurrence_id,
                        "rid_col": admission.memo_goal.rid_col,
                        "target_kind": admission.memo_goal.target_kind,
                        "logical_target_digest": admission.memo_goal.target_digest,
                        "logical_target": (
                            None
                            if admission.memo_goal.logical_target is None
                            else admission.memo_goal.logical_target.to_dict()
                        ),
                        "rho_digest": admission.memo_goal.rho_digest,
                        "gamma_snapshot_id": admission.memo_goal.gamma.snapshot_id,
                        "gamma_snapshot_digest": admission.memo_goal.gamma.digest,
                    },
                    "evidence_refs": list(admission.evidence_refs),
                    "rejection_codes": list(admission.rejection_codes),
                    "required_dynamic_fact_kinds": list(
                        admission.required_dynamic_fact_kinds
                    ),
                    "compatibility_mode": admission.compatibility_mode,
                    "planning_execution": planning_execution_metadata(
                        local_problem,
                        execution_admitted=execution_rejection is None,
                    ),
                    "implementation_target_binding": (
                        None
                        if admission.implementation_target_binding is None
                        else {
                            **admission.implementation_target_binding.to_dict(),
                            "binding_digest": admission.implementation_target_binding.digest,
                        }
                    ),
                }
            diagnostics = {
                "admission": admission_payload,
                "planning_execution": planning_execution_metadata(
                    local_problem,
                    execution_admitted=execution_rejection is None,
                ),
                **(
                    {
                        "disabled_components": list(local_problem.disabled_components),
                        "certificate_suppressed": bool(check.accepted),
                        "diagnostic_ablation": True,
                    }
                    if diagnostic_ablation
                    else {}
                ),
            }
        if collect_candidate_payloads or check.accepted:
            candidates.append(
                CandidatePlan(
                    template_id=spec.template_id,
                    alternative=spec.alternative,
                    accepted=check.accepted,
                    template_applicability=check.template_applicability,
                    rejection_reasons=check.reasons,
                    estimated_cost=estimated_cost,
                    kappa_sem=kappa_sem,
                    certificate=certificate,
                    certificate_check=certificate_check,
                    delivered_sigma=check.delivered_sigma,
                    emitted_sql=_render_sql_skeleton(spec, local_problem)
                    if collect_candidate_payloads
                    else "",
                    diagnostics=diagnostics,
                )
            )

    contract_accepted_count = sum(1 for candidate in candidates if candidate.accepted)
    dominance_checks = 0
    dominance_pruned = 0
    # G4 is root-only: before transfer, root closure, strict certificate
    # replay, and plain-EXPLAIN cost evidence, a leaf candidate is not a
    # complete rho-observable plan. Keep every admitted physical alternative
    # here; reference dominance is applied only to completed roots.

    accepted = [
        candidate
        for candidate in candidates
        if candidate.accepted and candidate.pruned_by_dominance is None
    ]
    chosen = min(
        accepted,
        key=lambda candidate: _candidate_rank_key_after_enforcers(
            candidate,
            problem.parent_requirement,
            problem.cost_inputs,
        ),
    ) if accepted else None
    return PlanResult(
        mode=mode,
        generated_templates=len(specs),
        rejected_templates=len(specs) - contract_accepted_count,
        costed_templates=len(accepted),
        chosen_template=chosen,
        emitted_sql=None if chosen is None else chosen.emitted_sql,
        delivered_sigma={} if chosen is None else chosen.delivered_sigma,
        estimated_cost=None if chosen is None else chosen.estimated_cost,
        rejection_reasons=rejection_counts,
        local_feature_vector=_local_feature_vector(local_problem) if mode == "local-greedy" else None,
        parent_requirement_vector=_parent_requirement_vector(problem.parent_requirement),
        candidates=tuple(candidates),
        dominance_checks=dominance_checks,
        dominance_pruned=dominance_pruned,
        disabled_components=normalized_disabled,
        planning_execution_class=problem.planning_execution_class,
        require_typed_admission=problem.require_typed_admission,
        planning_execution_admitted=planning_execution_admitted,
    )


def _local_problem(problem: PlanningProblem) -> PlanningProblem:
    return PlanningProblem(
        relation=problem.relation,
        policy_id=problem.policy_id,
        occurrence_id=problem.occurrence_id,
        rid_col=problem.rid_col,
        required_attrs=problem.required_attrs,
        required_ctx=problem.required_ctx,
        exact_policy_safe=problem.exact_policy_safe,
        supports_guard=problem.supports_guard,
        has_safe_query_predicate=False,
        engine_rls_available=problem.engine_rls_available,
        engine_rls_policy_hash=problem.engine_rls_policy_hash,
        authorization_view_binding=problem.authorization_view_binding,
        native_rls_session_contract=problem.native_rls_session_contract,
        gamma_snapshot=problem.gamma_snapshot,
        logical_target=problem.logical_target,
        implementation_target_bindings=problem.implementation_target_bindings,
        query_predicate=problem.query_predicate,
        planning_execution_class=problem.planning_execution_class,
        require_typed_admission=problem.require_typed_admission,
        artifacts=problem.artifacts,
        parent_requirement=ParentRequirement(),
        cost_inputs=problem.cost_inputs,
        disabled_components=problem.disabled_components,
    )


def _local_feature_vector(problem: PlanningProblem) -> dict[str, Any]:
    c = problem.cost_inputs
    return {
        "relname": problem.relation,
        "policy_id": problem.policy_id,
        "estimated_N": c.estimated_rows,
        "s_auth": c.auth_selectivity,
        "s_q": c.query_selectivity,
        "policy_eval_cost": c.policy_eval_cost,
        "available_artifacts": sorted(problem.artifacts),
        "artifact_lookup_cost": c.artifact_lookup_cost,
        "guard_fpr": c.guard_selectivity / max(c.auth_selectivity, 0.000001),
        "declared_reuse": c.declared_reuse,
        "declared_update_rate_per_hour": c.declared_update_rate_per_hour,
        "local_safety_requirement": "none",
    }


def _parent_requirement_vector(parent: ParentRequirement) -> dict[str, Any]:
    return {
        "logical_group_id": parent.logical_group_id,
        "visible_columns": list(parent.visible_columns),
        "required_order": list(parent.required_order),
        "licensed_refinements": list(parent.licensed_refinements),
        "residual_allowed": parent.residual_allowed,
        "residual_deadline": parent.residual_deadline,
        "min_safety_level": parent.min_safety_level,
        "freshness_predicate": parent.freshness_predicate,
        "context_predicate": parent.context_predicate,
        "allowed_enforcers": list(parent.allowed_enforcers),
        "observable_coverage": list(parent.observable_coverage),
        "transparent": parent.transparent,
        "unsafe_expression_boundary": parent.unsafe_expression_boundary,
        "needs_branch_lineage": parent.needs_branch_lineage,
        "future_rid_intersection": parent.future_rid_intersection,
    }


def _render_sql_skeleton(template: TemplateSpec, problem: PlanningProblem) -> str:
    if template.sql_skeleton:
        return template.sql_skeleton.format(
            R=problem.relation,
            rid_col=problem.rid_col,
            policy_id=problem.policy_id,
            occurrence_id=problem.occurrence_id,
        )
    return f"-- {template.template_id} for PolicyAccess({problem.relation}, {problem.policy_id})"


def plan_to_json(result: PlanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True)


def template_spec_from_definition(definition: TemplateDefinition) -> TemplateSpec:
    """Compile canonical template facts into the legacy planner surface."""

    return TemplateSpec(
        template_id=definition.template_id,
        alternative=definition.alternative,
        required_artifacts=definition.required_artifacts,
        requires_exact_policy_safe=definition.requires_exact_policy_safe,
        requires_safe_query_predicate=definition.requires_safe_query_predicate,
        requires_transparent_parent=definition.requires_transparent_parent,
        rejects_unsafe_expression_boundary=definition.rejects_unsafe_expression_boundary,
        requires_guard=definition.requires_guard,
        produces_residual=definition.produces_residual,
        requires_keyed_artifact=definition.requires_keyed_artifact,
        requires_engine_rls=definition.requires_engine_rls,
        requires_authorization_view=definition.requires_authorization_view,
        preserves_branch_lineage=definition.preserves_branch_lineage,
        refinement_kind=(
            "query_filtered" if definition.target_kind == "query_filtered" else None
        ),
        sql_skeleton=definition.sql_skeleton,
        execution_class=definition.execution_class,
    )


DEFAULT_TEMPLATE_REGISTRY = TemplateRegistry(
    template_spec_from_definition(definition)
    for definition in default_template_definitions()
)
DEFAULT_TEMPLATE_REGISTRY.validate_complete()
