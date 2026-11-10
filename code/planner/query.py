"""Query-level planner wrapper over the finite-template planner."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields, replace
from typing import Any, Mapping, Sequence

from caprls_core.baselines import ADMISSION_FIRST_MODE, scientific_mode_key

from .core import (
    ContractChecker,
    CostEstimator,
    DEFAULT_TEMPLATE_REGISTRY,
    ParentRequirement,
    PlanResult,
    PlanningProblem,
    TemplateRegistry,
    normalize_planner_mode,
    plan,
    planning_execution_metadata,
    policy_subject_digest,
)
from .certificates import emit_query_certificate
from .emit import EmitContext, emit_sql
from .features import DEFAULT_PLANNER_FEATURE_FLAGS, PlannerFeatureFlags
from .frontier import exhaustive_first_feasible
from .ir import (
    BarrierEnforce,
    Boundary,
    DuplicateCollapse,
    InnerJoin,
    Materialize,
    PlanNode,
    Project,
    RCheck,
    Root,
    ScanOrdinary,
    ScanProtected,
    Select,
    SortEnforce,
    UnionTagged,
    UnsafeExpr,
    ValidationGate,
    walk,
)
from .state import Sigma, sigma_from_dict
from .obligations import ObligationGraph, build_obligation_graph
from .transfer import (
    EnforcerInsertion,
    RootClosure,
    enforce_materialize,
    enforce_residual_check,
    enforce_sort,
    enforce_validation_gate,
    root_close,
    transfer_boundary,
    transfer_duplicate_collapse,
    transfer_inner_join,
    transfer_project,
    transfer_select_leakproof_only,
    transfer_select_logical_target,
    transfer_select_necessary_safe_reducer,
    transfer_select_unsafe,
    transfer_union_tagged,
)
from .verifier.cert_checker import check_certificate


@dataclass(frozen=True)
class OccurrenceGoal:
    problem: PlanningProblem
    mode: str | None = None
    gamma_facts: tuple[str, ...] = ()
    required_gamma_facts: tuple[str, ...] = ()


@dataclass(frozen=True)
class PlanningQuery:
    ir_skeleton: PlanNode
    occurrence_goals: Mapping[str, OccurrenceGoal]
    mode: str
    emit_context: EmitContext = field(default_factory=EmitContext)


@dataclass(frozen=True)
class SearchEvidence:
    """Visible completeness evidence for the finite G5b feasibility search."""

    status: str
    explored_combinations: int
    total_combinations: int
    search_budget: int | None
    incumbent_legal: bool
    reason: str = ""
    prechecked_combinations: int = 0
    combination_trace: tuple[tuple[str, ...], ...] = ()
    trace_complete: bool = True

    def __post_init__(self) -> None:
        if self.status not in {"not_needed", "complete", "incomplete", "disabled"}:
            raise ValueError("invalid search evidence status")
        if self.explored_combinations < 0 or self.total_combinations < 0:
            raise ValueError("search evidence counts cannot be negative")
        if self.search_budget is not None and self.search_budget < 0:
            raise ValueError("search budget cannot be negative")
        if self.prechecked_combinations < 0:
            raise ValueError("prechecked combination count cannot be negative")
        trace = tuple(tuple(str(value) for value in item) for item in self.combination_trace)
        if any(not value for item in trace for value in item):
            raise ValueError("search trace template identities must be nonempty")
        object.__setattr__(self, "combination_trace", trace)
        if not isinstance(self.trace_complete, bool):
            raise TypeError("search trace completeness must be boolean")
        if self.explored_combinations + self.prechecked_combinations > self.total_combinations:
            raise ValueError("search evidence cannot inspect more than its declared frontier")
        inspected = self.explored_combinations + self.prechecked_combinations
        if len(trace) > inspected:
            raise ValueError("search trace cannot exceed inspected combinations")
        if self.trace_complete and len(trace) != inspected:
            raise ValueError("complete search trace must cover every inspected combination")
        if self.status == "complete" and (
            self.explored_combinations + self.prechecked_combinations
            != self.total_combinations
        ):
            raise ValueError("complete search evidence must account for the full frontier")

    @property
    def complete(self) -> bool:
        # A legal local incumbent is sufficient for G5b, but it is not an
        # exhaustive frontier/global-optimality claim.
        return self.status == "complete"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "search_complete": self.complete,
            "explored_combinations": self.explored_combinations,
            "total_combinations": self.total_combinations,
            "search_budget": self.search_budget,
            "incumbent_legal": self.incumbent_legal,
            "reason": self.reason,
            "prechecked_combinations": self.prechecked_combinations,
            "combination_trace": [list(item) for item in self.combination_trace],
            "trace_complete": self.trace_complete,
        }


@dataclass(frozen=True)
class QueryPlanResult:
    mode: str
    occurrence_results: Mapping[str, PlanResult]
    effective_occurrence_goals: Mapping[str, OccurrenceGoal]
    root_closure: RootClosure
    root_sigma: Mapping[str, Any]
    certificate: tuple[Mapping[str, Any], ...] | None
    certificate_check: Mapping[str, Any] | None
    emitted_sql: str | None
    bound_ir: PlanNode
    emit_context: EmitContext
    inserted_enforcers: Mapping[str, tuple[EnforcerInsertion, ...]]
    memo_groups: int
    ir_node_count: int
    generated_templates: int
    rejected_templates: int
    costed_templates: int
    dominance_checks: int
    dominance_pruned: int
    serialized_state_bytes: int
    template_oracle_rank: int | None
    obligation_graph: ObligationGraph
    search_evidence: SearchEvidence = field(
        default_factory=lambda: SearchEvidence(
            status="not_needed",
            explored_combinations=0,
            total_combinations=0,
            search_budget=None,
            incumbent_legal=False,
        )
    )
    feature_flags: PlannerFeatureFlags = DEFAULT_PLANNER_FEATURE_FLAGS

    @property
    def ok(self) -> bool:
        return self.root_closure.ok

    def to_dict(self) -> dict[str, Any]:
        planning_execution = {
            occurrence_id: result.to_dict()["planning_execution"]
            for occurrence_id, result in sorted(self.occurrence_results.items())
        }
        return {
            "mode": self.mode,
            "planning_execution": planning_execution,
            "all_occurrences_production_typed": bool(planning_execution)
            and all(
                item["production_typed_admission"]
                for item in planning_execution.values()
            ),
            "memo_groups": self.memo_groups,
            "ir_node_count": self.ir_node_count,
            "generated_templates": self.generated_templates,
            "rejected_templates": self.rejected_templates,
            "costed_templates": self.costed_templates,
            "dominance_checks": self.dominance_checks,
            "dominance_pruned": self.dominance_pruned,
            "serialized_state_bytes": self.serialized_state_bytes,
            "template_oracle_rank": self.template_oracle_rank,
            "root_closure": _root_closure_to_dict(self.root_closure),
            "root_sigma": dict(self.root_sigma),
            "certificate": None
            if self.certificate is None
            else [dict(step) for step in self.certificate],
            "certificate_check": None
            if self.certificate_check is None
            else dict(self.certificate_check),
            "effective_occurrence_goals": {
                occurrence_id: _occurrence_goal_to_dict(
                    goal,
                    execution_metadata=planning_execution[occurrence_id],
                )
                for occurrence_id, goal in self.effective_occurrence_goals.items()
            },
            "inserted_enforcers": {
                occurrence_id: [enforcer.to_dict() for enforcer in enforcers]
                for occurrence_id, enforcers in self.inserted_enforcers.items()
            },
            "bound_ir": self.bound_ir.to_dict(),
            "obligation_graph": self.obligation_graph.to_dict(),
            "obligation_graph_digest": self.obligation_graph.digest,
            "search": self.search_evidence.to_dict(),
            "feature_flags": self.feature_flags.to_dict(),
            "emitted_sql": self.emitted_sql,
            "occurrence_results": {
                occurrence_id: result.to_dict()
                for occurrence_id, result in self.occurrence_results.items()
            },
        }


def _selected_plan_has_diagnostic_intent(
    *,
    effective_goals: Mapping[str, OccurrenceGoal],
    occurrence_results: Mapping[str, PlanResult],
    registry: TemplateRegistry | None,
) -> bool:
    """Detect selected diagnostic intent without trusting the context flag."""

    if any(goal.mode == "diagnostic-only" for goal in effective_goals.values()):
        return True
    if any(result.mode == "diagnostic-only" for result in occurrence_results.values()):
        return True
    if not isinstance(registry, TemplateRegistry):
        return False
    specs_by_id = {spec.template_id: spec for spec in registry.template_specs()}
    for result in occurrence_results.values():
        chosen = result.chosen_template
        if chosen is None:
            continue
        spec = specs_by_id.get(chosen.template_id)
        if spec is not None and spec.execution_class == "diagnostic_only":
            return True
    return False


def _diagnostic_emission_authorized(
    *,
    query: PlanningQuery,
    effective_goals: Mapping[str, OccurrenceGoal],
    occurrence_results: Mapping[str, PlanResult],
    bound_ir: PlanNode,
    registry: TemplateRegistry | None,
    emit_sql_text: bool,
) -> bool:
    """Authorize SQL only for a fully cross-checked diagnostic plan.

    No single caller-controlled flag or serialized result is sufficient.  The
    goal mode, planner result mode, actual registry execution class, chosen
    template binding, and certificate suppression must agree for every
    protected occurrence.  Production SQL emission remains governed solely
    by root closure.
    """

    if (
        not emit_sql_text
        or not query.emit_context.allow_diagnostic_lowering
        or not isinstance(registry, TemplateRegistry)
        or not effective_goals
        or set(occurrence_results) != set(effective_goals)
    ):
        return False
    registry_specs = registry.template_specs()
    if not registry_specs or any(
        spec.execution_class != "diagnostic_only" for spec in registry_specs
    ):
        return False
    specs_by_id = {spec.template_id: spec for spec in registry_specs}
    for occurrence_id, goal in effective_goals.items():
        result = occurrence_results[occurrence_id]
        chosen = result.chosen_template
        if (
            goal.mode != "diagnostic-only"
            or result.mode != "diagnostic-only"
            or chosen is None
            or not chosen.accepted
            or chosen.certificate is not None
            or chosen.certificate_check is not None
        ):
            return False
        spec = specs_by_id.get(chosen.template_id)
        if spec is None or spec.execution_class != "diagnostic_only":
            return False

    scans = tuple(node for node in walk(bound_ir) if isinstance(node, ScanProtected))
    if not scans or {scan.occurrence_id for scan in scans} != set(effective_goals):
        return False
    for scan in scans:
        chosen = occurrence_results[scan.occurrence_id].chosen_template
        if chosen is None or scan.template_slot != chosen.template_id:
            return False
    return True


def plan_query(
    query: PlanningQuery,
    *,
    registry: TemplateRegistry | None = None,
    checker: ContractChecker | None = None,
    estimator: CostEstimator | None = None,
    preplanned_occurrence_results: Mapping[str, PlanResult] | None = None,
    emit_certificates: bool = True,
    emit_sql_text: bool = True,
    compute_serialized_state: bool = True,
    collect_candidate_payloads: bool = True,
    feasibility_backtracking: bool | None = None,
    search_budget: int | None = None,
    feature_flags: PlannerFeatureFlags = DEFAULT_PLANNER_FEATURE_FLAGS,
) -> QueryPlanResult:
    try:
        normalized_query_mode = normalize_planner_mode(query.mode)
        normalized_goals = {
            occurrence_id: (
                goal
                if goal.mode is None or normalize_planner_mode(goal.mode) == goal.mode
                else replace(goal, mode=normalize_planner_mode(goal.mode))
            )
            for occurrence_id, goal in query.occurrence_goals.items()
        }
    except ValueError as exc:
        # Preserve the query-planner boundary's long-standing public error
        # contract while keeping the central normalizer strict.
        raise ValueError(f"mode is not supported: {exc}") from exc
    if normalized_query_mode != query.mode or normalized_goals != query.occurrence_goals:
        query = replace(
            query,
            mode=normalized_query_mode,
            occurrence_goals=normalized_goals,
        )
    if not isinstance(feature_flags, PlannerFeatureFlags):
        raise TypeError("feature_flags must be PlannerFeatureFlags")
    effective_backtracking = (
        feature_flags.feasibility_backtracking
        if feasibility_backtracking is None
        else bool(feasibility_backtracking)
    )
    occurrence_results: dict[str, PlanResult] = {}
    occurrence_leaf_sigmas: dict[str, Sigma] = {}
    occurrence_sigmas: dict[str, Sigma] = {}
    inserted_enforcers: dict[str, tuple[EnforcerInsertion, ...]] = {}
    enforcer_rejections: list[tuple[str, str]] = []
    effective_goals = derive_occurrence_goals(query)
    obligation_graph = build_obligation_graph(
        query.ir_skeleton,
        effective_goals,
        root_observables=(
            query.ir_skeleton.rho_root
            if isinstance(query.ir_skeleton, Root)
            else {}
        ),
    )
    explicit_enforcers = _collect_explicit_enforcers(query.ir_skeleton)
    preplanned = dict(preplanned_occurrence_results or {})
    shared_checker = checker or ContractChecker()
    shared_estimator = estimator or CostEstimator()

    for occurrence_id, goal in sorted(effective_goals.items()):
        problem = goal.problem
        if problem.occurrence_id != occurrence_id:
            problem = replace(problem, occurrence_id=occurrence_id)
        result = preplanned.get(occurrence_id)
        if result is None:
            result = plan(
                problem,
                goal.mode or query.mode,
                registry=registry,
                checker=shared_checker,
                estimator=shared_estimator,
                emit_certificates=emit_certificates,
                collect_candidate_payloads=collect_candidate_payloads,
            )
        else:
            effective_mode = goal.mode or query.mode
            selected_specs = (
                registry or DEFAULT_TEMPLATE_REGISTRY
            ).select_for_mode(effective_mode)
            execution_admitted = not (
                problem.planning_execution_class == "unclassified"
                or (
                    problem.planning_execution_class == "production_normal"
                    and (
                        not problem.require_typed_admission
                        or effective_mode == "diagnostic-only"
                        or any(
                            spec.execution_class == "diagnostic_only"
                            for spec in selected_specs
                        )
                    )
                )
            )
            expected_execution = planning_execution_metadata(
                problem,
                execution_admitted=execution_admitted,
            )
            actual_execution = result.to_dict()["planning_execution"]
            if actual_execution != expected_execution:
                raise ValueError(
                    "preplanned result planning execution identity mismatch"
                )
            if not result.planning_execution_admitted:
                raise ValueError(
                    "preplanned result cannot bypass planning execution admission"
                )
        occurrence_results[occurrence_id] = result
        if result.chosen_template is None:
            continue
        sigma = sigma_from_dict(result.delivered_sigma)
        occurrence_leaf_sigmas[occurrence_id] = sigma
        applied = _apply_query_enforcers(
            sigma=sigma,
            result=result,
            problem=problem,
            explicit_enforcers=explicit_enforcers.get(occurrence_id, ()),
        )
        if not applied.ok:
            enforcer_rejections.append((occurrence_id, applied.reason))
            continue
        if applied.sigma is not None:
            sigma = applied.sigma
        if applied.inserted_enforcers:
            inserted_enforcers[occurrence_id] = applied.inserted_enforcers
        occurrence_sigmas[occurrence_id] = sigma

    bound_ir = _bind_chosen_templates(
        query.ir_skeleton,
        occurrence_results,
        inserted_enforcers,
    )
    transfer_eval: _IRTransferEvaluation | None = None
    root_sigma: Mapping[str, Any] = {}
    operator_transfer_rules: tuple[str, ...] = ()
    operator_transfers: tuple[Mapping[str, Any], ...] = ()

    if enforcer_rejections:
        closure = RootClosure(
            ok=False,
            reason=enforcer_rejections[0][1],
            domain_covering=False,
            live_pairs_certified=False,
            residuals_closed=False,
        )
    elif len(occurrence_sigmas) != len(effective_goals):
        closure = RootClosure(
            ok=False,
            reason="occurrence_not_admitted",
            domain_covering=False,
            live_pairs_certified=False,
            residuals_closed=False,
        )
    else:
        transfer_eval = _evaluate_bound_ir(
            bound_ir,
            occurrence_leaf_sigmas,
            effective_goals,
        )
        if not transfer_eval.ok or transfer_eval.sigma is None:
            closure = RootClosure(
                ok=False,
                reason=transfer_eval.reason,
                domain_covering=False,
                live_pairs_certified=False,
                residuals_closed=False,
            )
        else:
            root_sigma = transfer_eval.sigma.to_dict()
            operator_transfer_rules = transfer_eval.transfer_rules
            if emit_certificates:
                operator_transfers = _operator_transfer_evidence(bound_ir, operator_transfer_rules)
            closure = root_close(
                (transfer_eval.sigma,),
                obligation_graph=obligation_graph,
                rho=(
                    query.ir_skeleton.rho_root
                    if isinstance(query.ir_skeleton, Root)
                    else {}
                ),
            )

    diagnostic_intent = _selected_plan_has_diagnostic_intent(
        effective_goals=effective_goals,
        occurrence_results=occurrence_results,
        registry=registry,
    )
    if diagnostic_intent:
        emission_authorized = _diagnostic_emission_authorized(
            query=query,
            effective_goals=effective_goals,
            occurrence_results=occurrence_results,
            bound_ir=bound_ir,
            registry=registry,
            emit_sql_text=emit_sql_text,
        )
    else:
        emission_authorized = closure.ok and emit_sql_text
    emitted_sql = (
        emit_sql(bound_ir, query.emit_context).render()
        if emission_authorized
        else None
    )
    certificate: tuple[Mapping[str, Any], ...] | None = None
    certificate_check: Mapping[str, Any] | None = None
    if emit_certificates:
        certificate, certificate_check = _query_certificate_and_check(
            occurrence_results=occurrence_results,
            root_sigma=root_sigma,
            root_closure=closure,
            operator_transfers=operator_transfers,
        )
    serialized_state_bytes = 0
    if compute_serialized_state:
        payload = _serialized_state_payload(
            query=query,
            effective_goals=effective_goals,
            occurrence_results=occurrence_results,
            bound_ir=bound_ir,
            root_sigma=root_sigma,
            root_closure=closure,
            certificate=certificate,
            certificate_check=certificate_check,
            inserted_enforcers=inserted_enforcers,
            obligation_graph=obligation_graph,
        )
        serialized_state_bytes = len(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
    result = QueryPlanResult(
        mode=query.mode,
        occurrence_results=occurrence_results,
        effective_occurrence_goals=effective_goals,
        root_closure=closure,
        root_sigma=root_sigma,
        certificate=certificate,
        certificate_check=certificate_check,
        emitted_sql=emitted_sql,
        bound_ir=bound_ir,
        emit_context=query.emit_context,
        inserted_enforcers=inserted_enforcers,
        memo_groups=len(effective_goals),
        ir_node_count=len(walk(bound_ir)),
        generated_templates=sum(result.generated_templates for result in occurrence_results.values()),
        rejected_templates=sum(result.rejected_templates for result in occurrence_results.values()),
        costed_templates=sum(result.costed_templates for result in occurrence_results.values()),
        dominance_checks=sum(result.dominance_checks for result in occurrence_results.values()),
        dominance_pruned=sum(result.dominance_pruned for result in occurrence_results.values()),
        serialized_state_bytes=serialized_state_bytes,
        template_oracle_rank=_template_oracle_rank(occurrence_results.values(), query.mode),
        obligation_graph=obligation_graph,
        feature_flags=feature_flags,
    )
    if not effective_backtracking:
        return replace(
            result,
            search_evidence=SearchEvidence(
                status="disabled",
                explored_combinations=0,
                total_combinations=0,
                search_budget=search_budget,
                incumbent_legal=result.ok,
                reason="recursive_or_explicitly_disabled",
            ),
        )
    return _apply_feasibility_backtracking(
        result,
        query=query,
        registry=registry,
        checker=checker,
        estimator=estimator,
        emit_certificates=emit_certificates,
        emit_sql_text=emit_sql_text,
        compute_serialized_state=compute_serialized_state,
        collect_candidate_payloads=collect_candidate_payloads,
        search_budget=search_budget,
        feature_flags=feature_flags,
    )


def _apply_feasibility_backtracking(
    incumbent: QueryPlanResult,
    *,
    query: PlanningQuery,
    registry: TemplateRegistry | None,
    checker: ContractChecker | None,
    estimator: CostEstimator | None,
    emit_certificates: bool,
    emit_sql_text: bool,
    compute_serialized_state: bool,
    collect_candidate_payloads: bool,
    search_budget: int | None,
    feature_flags: PlannerFeatureFlags,
) -> QueryPlanResult:
    """G5b: preserve a legal incumbent; otherwise search admitted alternatives.

    This is deliberately a feasibility search, not G5c global reranking.  It
    never changes an already root-legal selection merely because another leaf
    candidate has a lower model cost.  The enumeration is finite,
    deterministic, and records incomplete budget exits explicitly.
    """

    if normalize_planner_mode(query.mode) != ADMISSION_FIRST_MODE:
        return replace(
            incumbent,
            search_evidence=SearchEvidence(
                status="disabled",
                explored_combinations=0,
                total_combinations=0,
                search_budget=search_budget,
                incumbent_legal=incumbent.ok,
                reason="non_admission_first_mode",
            ),
        )
    if incumbent.ok:
        return replace(
            incumbent,
            search_evidence=SearchEvidence(
                status="not_needed",
                explored_combinations=0,
                total_combinations=0,
                search_budget=search_budget,
                incumbent_legal=True,
                reason="local_incumbent_root_closed",
            ),
        )

    occurrence_ids = tuple(sorted(incumbent.occurrence_results))
    alternatives_by_occurrence: dict[str, tuple[PlanResult, ...]] = {}
    for occurrence_id in occurrence_ids:
        result = incumbent.occurrence_results[occurrence_id]
        chosen = result.chosen_template
        if chosen is None:
            return replace(
                incumbent,
                search_evidence=SearchEvidence(
                    status="complete",
                    explored_combinations=0,
                    total_combinations=0,
                    search_budget=search_budget,
                    incumbent_legal=False,
                    reason="no_admitted_incumbent_for_occurrence",
                ),
            )
        candidates = [
            candidate
            for candidate in result.candidates
            if candidate.accepted and candidate.estimated_cost is not None
        ]
        # Registry/candidate ordering is frozen before any execution.  The
        # incumbent is first so a future caller cannot use this helper as an
        # unrecorded tie-break/reranking mechanism.
        alternatives = [chosen] + sorted(
            (candidate for candidate in candidates if candidate.template_id != chosen.template_id),
            key=lambda candidate: (candidate.template_id, candidate.alternative),
        )
        alternatives_by_occurrence[occurrence_id] = tuple(
            replace(
                result,
                chosen_template=candidate,
                emitted_sql=candidate.emitted_sql,
                delivered_sigma=candidate.delivered_sigma,
                estimated_cost=candidate.estimated_cost,
            )
            for candidate in alternatives
        )

    first_legal_result: QueryPlanResult | None = None
    first_legal_key: tuple[str, ...] | None = None

    def combination_key(combination: tuple[PlanResult, ...]) -> tuple[str, ...]:
        template_ids: list[str] = []
        for result in combination:
            chosen = result.chosen_template
            if chosen is None:
                raise AssertionError("frontier combination is missing a chosen template")
            template_ids.append(chosen.template_id)
        return tuple(template_ids)

    def is_legal(combination: tuple[PlanResult, ...]) -> bool:
        nonlocal first_legal_key, first_legal_result
        selected = {
            occurrence_id: combination[index]
            for index, occurrence_id in enumerate(occurrence_ids)
        }
        candidate_result = plan_query(
            query,
            registry=registry,
            checker=checker,
            estimator=estimator,
            preplanned_occurrence_results=selected,
            emit_certificates=emit_certificates,
            emit_sql_text=emit_sql_text,
            compute_serialized_state=compute_serialized_state,
            collect_candidate_payloads=collect_candidate_payloads,
            feasibility_backtracking=False,
            search_budget=search_budget,
            feature_flags=feature_flags,
        )
        if candidate_result.ok and first_legal_result is None:
            first_legal_key = combination_key(combination)
            first_legal_result = candidate_result
        return candidate_result.ok

    # The first product point is the already-checked, invalid local
    # incumbent.  ``exhaustive_first_feasible`` records it as prechecked and
    # scans all remaining admitted combinations unless the explicit budget
    # fires.  It retains the first legal fallback without performing G5c cost
    # reranking.
    frontier = exhaustive_first_feasible(
        alternatives_by_occurrence,
        is_legal=is_legal,
        search_budget=search_budget,
        skip_first=True,
    )
    evidence = frontier.evidence
    combination_trace = tuple(
        combination_key(combination) for combination in frontier.combinations
    )

    def search_evidence(status: str, reason: str) -> SearchEvidence:
        return SearchEvidence(
            status=status,
            explored_combinations=evidence.explored_combinations,
            total_combinations=evidence.total_combinations,
            search_budget=search_budget,
            incumbent_legal=False,
            reason=reason,
            prechecked_combinations=evidence.prechecked_combinations,
            combination_trace=combination_trace,
            trace_complete=frontier.combinations_complete,
        )

    if frontier.first_legal is not None:
        legal_key = combination_key(frontier.first_legal)
        fallback = first_legal_result
        if fallback is None or first_legal_key != legal_key:
            raise AssertionError("frontier reported a legal combination without validation result")
        if evidence.search_complete:
            return replace(
                fallback,
                search_evidence=search_evidence("complete", "legal_feasibility_fallback_found"),
            )
        return replace(
            fallback,
            search_evidence=search_evidence(
                "incomplete",
                "search_budget_exhausted_with_legal_fallback",
            ),
        )

    if not evidence.search_complete:
        return replace(
            incumbent,
            search_evidence=search_evidence(
                "incomplete",
                "search_budget_exhausted_without_legal_incumbent",
            ),
        )
    return replace(
        incumbent,
        search_evidence=search_evidence("complete", "no_legal_root_in_finite_admitted_frontier"),
    )


@dataclass(frozen=True)
class _DerivedRequirement:
    visible_columns: tuple[str, ...] = ()
    required_order: tuple[str, ...] = ()
    observable_coverage: tuple[str, ...] = ()
    required_ctx: tuple[str, ...] = ()
    required_gamma_facts: tuple[str, ...] = ()
    residual_deadline: str | None = None
    min_safety_level: str | None = None
    freshness_predicate: str | None = None
    context_predicate: str | None = None
    needs_branch_lineage: bool = False
    future_rid_intersection: bool = False


@dataclass(frozen=True)
class _EnforcerApplication:
    ok: bool
    sigma: Sigma | None = None
    reason: str = ""
    inserted_enforcers: tuple[EnforcerInsertion, ...] = ()

    @classmethod
    def accept(
        cls,
        sigma: Sigma,
        *,
        inserted_enforcers: tuple[EnforcerInsertion, ...] = (),
    ) -> "_EnforcerApplication":
        return cls(ok=True, sigma=sigma, inserted_enforcers=inserted_enforcers)

    @classmethod
    def reject(cls, reason: str) -> "_EnforcerApplication":
        return cls(ok=False, reason=reason)


@dataclass(frozen=True)
class _IRTransferEvaluation:
    ok: bool
    sigma: Sigma | None = None
    reason: str = ""
    transfer_rules: tuple[str, ...] = ()

    @classmethod
    def accept(
        cls,
        sigma: Sigma | None,
        *,
        transfer_rules: tuple[str, ...] = (),
    ) -> "_IRTransferEvaluation":
        return cls(ok=True, sigma=sigma, transfer_rules=transfer_rules)

    @classmethod
    def reject(cls, reason: str) -> "_IRTransferEvaluation":
        return cls(ok=False, reason=reason)


def derive_occurrence_goals(query: PlanningQuery) -> dict[str, OccurrenceGoal]:
    """Return occurrence goals after conservative Root-to-leaf rho derivation.

    The finite-template planner still owns template enumeration and contract
    checks. This layer only tightens local requirements that are explicit in the
    query IR, such as projection columns, sort order, branch lineage, and
    residual discharge deadlines before unsafe or opaque operators.
    """

    root_rho = query.ir_skeleton.rho_root if isinstance(query.ir_skeleton, Root) else {}
    derived = _collect_requirement_derivations(query.ir_skeleton)
    effective: dict[str, OccurrenceGoal] = {}
    parent_cache: dict[tuple[ParentRequirement, _DerivedRequirement], ParentRequirement] = {}
    for occurrence_id, goal in sorted(query.occurrence_goals.items()):
        occurrence_derived = derived.get(occurrence_id, _DerivedRequirement())
        problem = goal.problem
        if problem.occurrence_id != occurrence_id:
            problem = replace(problem, occurrence_id=occurrence_id)
        parent_key = (problem.parent_requirement, occurrence_derived)
        parent = parent_cache.get(parent_key)
        if parent is None:
            parent = _derive_parent_requirement(
                problem.parent_requirement,
                root_rho=root_rho,
                derived=occurrence_derived,
            )
            parent_cache[parent_key] = parent
        required_attrs = _merge_tuple(problem.required_attrs, parent.visible_columns)
        required_ctx = _merge_tuple(
            _merge_tuple(problem.required_ctx, root_rho.get("required_ctx")),
            occurrence_derived.required_ctx,
        )
        effective[occurrence_id] = replace(
            goal,
            required_gamma_facts=_merge_tuple(
                goal.required_gamma_facts,
                occurrence_derived.required_gamma_facts,
            ),
            problem=replace(
                problem,
                required_attrs=required_attrs,
                required_ctx=required_ctx,
                parent_requirement=parent,
            ),
        )
    return effective


def _derive_parent_requirement(
    parent: ParentRequirement,
    *,
    root_rho: Mapping[str, Any],
    derived: _DerivedRequirement,
) -> ParentRequirement:
    effective = _apply_root_rho(parent, root_rho)
    updates: dict[str, Any] = {}
    if derived.visible_columns:
        updates["visible_columns"] = _merge_tuple(effective.visible_columns, derived.visible_columns)
    if derived.required_order:
        updates["required_order"] = (
            effective.required_order
            if effective.required_order
            else tuple(derived.required_order)
        )
    if derived.observable_coverage:
        updates["observable_coverage"] = _merge_tuple(
            effective.observable_coverage,
            derived.observable_coverage,
        )
    if derived.residual_deadline:
        updates["residual_deadline"] = _stricter_deadline(
            effective.residual_deadline,
            derived.residual_deadline,
        )
    if derived.min_safety_level:
        updates["min_safety_level"] = _stricter_safety_level(
            effective.min_safety_level,
            derived.min_safety_level,
        )
    if derived.freshness_predicate:
        updates["freshness_predicate"] = _combine_predicate(
            effective.freshness_predicate,
            derived.freshness_predicate,
        )
    if derived.context_predicate:
        updates["context_predicate"] = _combine_predicate(
            effective.context_predicate,
            derived.context_predicate,
        )
    if derived.needs_branch_lineage:
        updates["needs_branch_lineage"] = True
    if derived.future_rid_intersection:
        updates["future_rid_intersection"] = True
    return replace(effective, **updates) if updates else effective


_PARENT_FIELD_NAMES = {item.name for item in fields(ParentRequirement)}
_PARENT_TUPLE_FIELDS = {
    "visible_columns",
    "required_order",
    "licensed_refinements",
    "allowed_enforcers",
    "observable_coverage",
}
_PARENT_BOOL_FIELDS = {
    "residual_allowed",
    "transparent",
    "unsafe_expression_boundary",
    "needs_branch_lineage",
    "future_rid_intersection",
}


def _apply_root_rho(parent: ParentRequirement, root_rho: Mapping[str, Any]) -> ParentRequirement:
    updates: dict[str, Any] = {}
    for key, value in root_rho.items():
        if key not in _PARENT_FIELD_NAMES:
            continue
        if key in _PARENT_TUPLE_FIELDS:
            coerced = _tuple_of_str(value)
            if key in {"visible_columns", "observable_coverage"}:
                updates[key] = _merge_tuple(getattr(parent, key), coerced)
            elif key == "required_order":
                updates[key] = getattr(parent, key) or coerced
            else:
                updates[key] = coerced
            continue
        if key in _PARENT_BOOL_FIELDS:
            current = bool(getattr(parent, key))
            incoming = bool(value)
            if key in {"residual_allowed", "transparent"}:
                updates[key] = current and incoming
            else:
                updates[key] = current or incoming
            continue
        if key == "min_safety_level":
            updates[key] = _stricter_safety_level(getattr(parent, key), str(value))
            continue
        if key in {"freshness_predicate", "context_predicate"}:
            updates[key] = _combine_predicate(getattr(parent, key), str(value))
            continue
        updates[key] = value
    return replace(parent, **updates) if updates else parent


def _collect_requirement_derivations(node: PlanNode) -> dict[str, _DerivedRequirement]:
    collected: dict[str, _DerivedRequirement] = {}

    def visit(current: PlanNode, state: _DerivedRequirement) -> None:
        if isinstance(current, ScanProtected):
            collected[current.occurrence_id] = _merge_derivation(
                collected.get(current.occurrence_id, _DerivedRequirement()),
                state,
            )
            return
        if isinstance(current, ScanOrdinary):
            return
        if isinstance(current, Root):
            visit(current.source, state)
            return
        if isinstance(current, Select):
            visit(current.source, _state_for_select(current, state))
            return
        if isinstance(current, Project):
            visit(
                current.source,
                replace(
                    state,
                    visible_columns=_merge_tuple(state.visible_columns, current.visible_A),
                    observable_coverage=_merge_tuple(
                        state.observable_coverage,
                        tuple(f"hidden_carrier:{column}" for column in current.hidden_H),
                    ),
                ),
            )
            return
        if isinstance(current, InnerJoin):
            next_state = state
            if "rid" in current.theta_label or "intersection" in current.theta_label:
                next_state = replace(next_state, future_rid_intersection=True)
            visit(current.left, next_state)
            visit(current.right, next_state)
            return
        if isinstance(current, UnionTagged):
            next_state = replace(
                state,
                needs_branch_lineage=True,
                observable_coverage=_merge_tuple(
                    state.observable_coverage,
                    (f"branch_tag:{current.branch_tag}",),
                ),
            )
            for branch in current.branches:
                visit(branch, next_state)
            return
        if isinstance(current, DuplicateCollapse):
            if current.trusted_surrogate or current.lifted_equivalence:
                gamma_fact = _duplicate_collapse_gamma_fact(current)
                visit(
                    current.source,
                    replace(
                        state,
                        required_gamma_facts=_merge_tuple(
                            state.required_gamma_facts,
                            (gamma_fact,) if gamma_fact else (),
                        ),
                    ),
                )
            else:
                visit(
                    current.source,
                    replace(
                        state,
                        needs_branch_lineage=True,
                        residual_deadline=_stricter_deadline(
                            state.residual_deadline,
                            "before_duplicate_collapse",
                        ),
                    ),
                )
            return
        if isinstance(current, UnsafeExpr):
            visit(
                current.source,
                replace(
                    state,
                    residual_deadline=_stricter_deadline(state.residual_deadline, "before_unsafe"),
                    min_safety_level=_stricter_safety_level(
                        state.min_safety_level,
                        "exact_authorized",
                    ),
                    observable_coverage=_merge_tuple(
                        state.observable_coverage,
                        (f"unsafe_expr:{current.expr_label}",),
                    ),
                ),
            )
            return
        if isinstance(current, Boundary):
            visit(
                current.source,
                replace(
                    state,
                    residual_deadline=_stricter_deadline(
                        state.residual_deadline,
                        f"before_{current.kind}",
                    ),
                ),
            )
            return
        if isinstance(current, RCheck):
            visit(
                current.source,
                replace(
                    state,
                    observable_coverage=_merge_tuple(
                        state.observable_coverage,
                        (f"residual_check:{current.residual_id}",),
                    ),
                ),
            )
            return
        if isinstance(current, BarrierEnforce):
            visit(
                current.source,
                replace(
                    state,
                    observable_coverage=_merge_tuple(state.observable_coverage, ("barrier",)),
                ),
            )
            return
        if isinstance(current, ValidationGate):
            visit(
                current.source,
                replace(
                    state,
                    required_ctx=_merge_tuple(
                        state.required_ctx,
                        (f"artifact_context:{current.artifact_id}",),
                    ),
                    freshness_predicate=_combine_predicate(
                        state.freshness_predicate,
                        f"artifact_snapshot_valid:{current.artifact_id}",
                    ),
                    context_predicate=_combine_predicate(
                        state.context_predicate,
                        f"artifact_context_matches:{current.artifact_id}",
                    ),
                    observable_coverage=_merge_tuple(
                        state.observable_coverage,
                        (f"artifact_valid:{current.artifact_id}",),
                    ),
                ),
            )
            return
        if isinstance(current, SortEnforce):
            visit(
                current.source,
                replace(
                    state,
                    required_order=state.required_order or tuple(current.keys),
                    observable_coverage=_merge_tuple(
                        state.observable_coverage,
                        tuple(f"order:{key}" for key in current.keys),
                    ),
                ),
            )
            return
        if isinstance(current, Materialize):
            visit(
                current.source,
                replace(
                    state,
                    observable_coverage=_merge_tuple(state.observable_coverage, ("materialized",)),
                ),
            )
            return
        raise TypeError(f"unsupported IR node: {current!r}")

    visit(node, _DerivedRequirement())
    return collected


def _state_for_select(node: Select, state: _DerivedRequirement) -> _DerivedRequirement:
    if node.pred_kind == "necessary_safe_reducer":
        return replace(
            state,
            required_gamma_facts=_merge_tuple(
                state.required_gamma_facts,
                (_necessity_fact_for_select(node),),
            ),
        )
    if node.pred_kind != "unsafe":
        return state
    return replace(
        state,
        residual_deadline=_stricter_deadline(state.residual_deadline, "before_unsafe"),
        min_safety_level=_stricter_safety_level(
            state.min_safety_level,
            "exact_authorized",
        ),
        observable_coverage=_merge_tuple(
            state.observable_coverage,
            (f"unsafe_predicate:{node.expr_label or node.pred}",),
        ),
    )


def _merge_derivation(
    left: _DerivedRequirement,
    right: _DerivedRequirement,
) -> _DerivedRequirement:
    return _DerivedRequirement(
        visible_columns=_merge_tuple(left.visible_columns, right.visible_columns),
        required_order=left.required_order or right.required_order,
        observable_coverage=_merge_tuple(left.observable_coverage, right.observable_coverage),
        required_ctx=_merge_tuple(left.required_ctx, right.required_ctx),
        required_gamma_facts=_merge_tuple(
            left.required_gamma_facts,
            right.required_gamma_facts,
        ),
        residual_deadline=_stricter_deadline(left.residual_deadline, right.residual_deadline),
        min_safety_level=_stricter_safety_level(left.min_safety_level, right.min_safety_level),
        freshness_predicate=_combine_predicate(
            left.freshness_predicate,
            right.freshness_predicate,
        ),
        context_predicate=_combine_predicate(
            left.context_predicate,
            right.context_predicate,
        ),
        needs_branch_lineage=left.needs_branch_lineage or right.needs_branch_lineage,
        future_rid_intersection=left.future_rid_intersection or right.future_rid_intersection,
    )


def _tuple_of_str(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)):
        return (str(value),)
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(str(item) for item in value)
    return (str(value),)


def _merge_tuple(left: Any, right: Any) -> tuple[str, ...]:
    merged: list[str] = []
    for item in (*_tuple_of_str(left), *_tuple_of_str(right)):
        if item not in merged:
            merged.append(item)
    return tuple(merged)


def _append_transfer_rule(prior_rules: tuple[str, ...], rule: str) -> tuple[str, ...]:
    return (*prior_rules, rule)


def _concat_transfer_rules(*parts: tuple[str, ...]) -> tuple[str, ...]:
    merged: list[str] = []
    for part in parts:
        merged.extend(part)
    return tuple(merged)


def _deadline_rank(deadline: str | None) -> tuple[int, str]:
    if not deadline:
        return (100, "")
    if deadline == "before_unsafe":
        return (0, deadline)
    if deadline.startswith("before_"):
        return (1, deadline)
    if deadline == "parent_transparent_boundary":
        return (2, deadline)
    return (3, deadline)


def _stricter_deadline(left: str | None, right: str | None) -> str | None:
    if not left:
        return right
    if not right:
        return left
    return left if _deadline_rank(left) <= _deadline_rank(right) else right


_SAFETY_RANK = {
    "unsafe_before_authorization": 0,
    "candidate_until_residual_discharge": 1,
    "engine_authorized": 2,
    "exact_authorized": 3,
}


def _safety_rank(level: str | None) -> tuple[int, str]:
    if not level:
        return (-1, "")
    return (_SAFETY_RANK.get(level, 3), level)


def _stricter_safety_level(left: str | None, right: str | None) -> str | None:
    if not left:
        return right
    if not right:
        return left
    return left if _safety_rank(left) >= _safety_rank(right) else right


def _combine_predicate(left: str | None, right: str | None) -> str | None:
    if not left:
        return right
    if not right or right == left:
        return left
    parts: list[str] = []
    for item in (*left.split(" && "), *right.split(" && ")):
        item = item.strip()
        if item and item not in parts:
            parts.append(item)
    return " && ".join(parts)


def _evaluate_bound_ir(
    node: PlanNode,
    occurrence_sigmas: Mapping[str, Sigma],
    effective_goals: Mapping[str, OccurrenceGoal],
) -> _IRTransferEvaluation:
    if isinstance(node, ScanProtected):
        sigma = occurrence_sigmas.get(node.occurrence_id)
        if sigma is None:
            return _IRTransferEvaluation.reject(f"missing_sigma:{node.occurrence_id}")
        return _IRTransferEvaluation.accept(sigma)
    if isinstance(node, ScanOrdinary):
        return _IRTransferEvaluation.accept(None)
    if isinstance(node, Root):
        child = _evaluate_bound_ir(node.source, occurrence_sigmas, effective_goals)
        if not child.ok:
            return child
        if child.sigma is None:
            return _IRTransferEvaluation.reject("root_has_no_protected_sigma")
        return _IRTransferEvaluation.accept(
            child.sigma,
            transfer_rules=_append_transfer_rule(child.transfer_rules, "Root"),
        )
    if isinstance(node, Select):
        child = _evaluate_bound_ir(node.source, occurrence_sigmas, effective_goals)
        if not child.ok or child.sigma is None:
            return child
        if node.pred_kind == "logical_target":
            transferred = transfer_select_logical_target(child.sigma)
        elif node.pred_kind == "necessary_safe_reducer":
            transferred = transfer_select_necessary_safe_reducer(
                child.sigma,
                gamma_necessity_fact=_has_necessity_fact(node, effective_goals),
            )
        elif node.pred_kind == "leakproof_only":
            transferred = transfer_select_leakproof_only(child.sigma)
        elif node.pred_kind == "unsafe":
            transferred = transfer_select_unsafe(
                child.sigma,
                observed_basis_ids=tuple(basis.basis_id for basis in child.sigma.dom),
            )
        else:
            return _IRTransferEvaluation.reject(f"unknown_select_kind:{node.pred_kind}")
        if node.pred_kind == "unsafe":
            label = node.expr_label.strip() or node.pred.strip() or "unsafe_predicate"
            normalized = "".join(
                char if char.isalnum() or char in ":-_" else "_"
                for char in label
            )
            rule = f"Select:unsafe:{normalized}"
        else:
            rule = f"Select:{node.pred_kind}"
        return _from_transfer_result(transferred, child.transfer_rules, rule)
    if isinstance(node, Project):
        child = _evaluate_bound_ir(node.source, occurrence_sigmas, effective_goals)
        if not child.ok or child.sigma is None:
            return child
        transferred = transfer_project(
            child.sigma,
            visible_attrs=node.visible_A,
            hidden_attrs=node.hidden_H,
        )
        return _from_transfer_result(transferred, child.transfer_rules, "Project")
    if isinstance(node, InnerJoin):
        left = _evaluate_bound_ir(node.left, occurrence_sigmas, effective_goals)
        if not left.ok:
            return left
        right = _evaluate_bound_ir(node.right, occurrence_sigmas, effective_goals)
        if not right.ok:
            return right
        rules = _concat_transfer_rules(left.transfer_rules, right.transfer_rules)
        if left.sigma is None:
            return _IRTransferEvaluation.accept(
                right.sigma,
                transfer_rules=_append_transfer_rule(rules, "InnerJoin:ordinary_left"),
            )
        if right.sigma is None:
            return _IRTransferEvaluation.accept(
                left.sigma,
                transfer_rules=_append_transfer_rule(rules, "InnerJoin:ordinary_right"),
            )
        transferred = transfer_inner_join(
            left.sigma,
            right.sigma,
            theta_safe=not node.theta_label.startswith("unsafe"),
        )
        return _from_transfer_result(transferred, rules, "InnerJoin")
    if isinstance(node, UnionTagged):
        branch_sigmas: list[Sigma] = []
        rules: tuple[str, ...] = ()
        for branch in node.branches:
            evaluated = _evaluate_bound_ir(branch, occurrence_sigmas, effective_goals)
            if not evaluated.ok:
                return evaluated
            rules = _concat_transfer_rules(rules, evaluated.transfer_rules)
            if evaluated.sigma is not None:
                branch_sigmas.append(evaluated.sigma)
        transferred = transfer_union_tagged(tuple(branch_sigmas), branch_tag=node.branch_tag)
        return _from_transfer_result(transferred, rules, "UnionTagged")
    if isinstance(node, DuplicateCollapse):
        child = _evaluate_bound_ir(node.source, occurrence_sigmas, effective_goals)
        if not child.ok or child.sigma is None:
            return child
        transferred = transfer_duplicate_collapse(
            child.sigma,
            trusted_surrogate=node.trusted_surrogate,
            lifted_equivalence=node.lifted_equivalence,
            gamma_fact=_duplicate_collapse_gamma_fact(node),
        )
        if not transferred.ok:
            return _IRTransferEvaluation.reject(transferred.reason)
        if (node.trusted_surrogate or node.lifted_equivalence) and not _has_duplicate_collapse_fact(
            node,
            effective_goals,
        ):
            return _IRTransferEvaluation.reject("missing_gamma_fact_for_duplicate_collapse")
        if node.lifted_equivalence:
            rule = "DuplicateCollapse:lifted_equivalence"
            gamma_fact = _duplicate_collapse_gamma_fact(node)
            if gamma_fact:
                rule = f"{rule}:{gamma_fact}"
        elif node.trusted_surrogate:
            rule = "DuplicateCollapse:trusted_surrogate"
            gamma_fact = _duplicate_collapse_gamma_fact(node)
            if gamma_fact:
                rule = f"{rule}:{gamma_fact}"
        else:
            rule = "DuplicateCollapse"
        return _from_transfer_result(transferred, child.transfer_rules, rule)
    if isinstance(node, UnsafeExpr):
        child = _evaluate_bound_ir(node.source, occurrence_sigmas, effective_goals)
        if not child.ok or child.sigma is None:
            return child
        transferred = transfer_select_unsafe(
            child.sigma,
            observed_basis_ids=tuple(basis.basis_id for basis in child.sigma.dom),
        )
        return _from_transfer_result(transferred, child.transfer_rules, f"UnsafeExpr:{node.expr_label}")
    if isinstance(node, Boundary):
        child = _evaluate_bound_ir(node.source, occurrence_sigmas, effective_goals)
        if not child.ok or child.sigma is None:
            return child
        transferred = transfer_boundary(
            child.sigma,
            kind=node.kind,
            allowed_enforcers=_allowed_enforcers_for_node(node, effective_goals),
        )
        if transferred.inserted_enforcers:
            return _IRTransferEvaluation.reject("transfer_enforcer_not_bound_in_ir")
        return _from_transfer_result(transferred, child.transfer_rules, f"Boundary:{node.kind}")
    if isinstance(node, RCheck):
        child = _evaluate_bound_ir(node.source, occurrence_sigmas, effective_goals)
        if not child.ok or child.sigma is None:
            return child
        if "residual_check" not in set(_allowed_enforcers_for_node(node, effective_goals)):
            return _IRTransferEvaluation.reject("residual_check_not_allowed_by_rho")
        transferred = enforce_residual_check(child.sigma, residual_ids=(node.residual_id,))
        return _from_transfer_result(transferred, child.transfer_rules, f"RCheck:{node.residual_id}")
    if isinstance(node, BarrierEnforce):
        child = _evaluate_bound_ir(node.source, occurrence_sigmas, effective_goals)
        if not child.ok or child.sigma is None:
            return child
        return _IRTransferEvaluation.accept(
            child.sigma,
            transfer_rules=_append_transfer_rule(child.transfer_rules, "BarrierEnforce"),
        )
    if isinstance(node, ValidationGate):
        child = _evaluate_bound_ir(node.source, occurrence_sigmas, effective_goals)
        if not child.ok or child.sigma is None:
            return child
        transferred = enforce_validation_gate(
            child.sigma,
            artifact_id=node.artifact_id,
            allowed_enforcers=_allowed_enforcers_for_node(node, effective_goals),
        )
        return _from_transfer_result(
            transferred,
            child.transfer_rules,
            f"ValidationGate:{node.artifact_id}",
        )
    if isinstance(node, SortEnforce):
        child = _evaluate_bound_ir(node.source, occurrence_sigmas, effective_goals)
        if not child.ok or child.sigma is None:
            return child
        transferred = enforce_sort(
            child.sigma,
            keys=node.keys,
            allowed_enforcers=_allowed_enforcers_for_node(node, effective_goals),
        )
        return _from_transfer_result(
            transferred,
            child.transfer_rules,
            f"SortEnforce:{','.join(node.keys)}",
        )
    if isinstance(node, Materialize):
        child = _evaluate_bound_ir(node.source, occurrence_sigmas, effective_goals)
        if not child.ok or child.sigma is None:
            return child
        transferred = enforce_materialize(
            child.sigma,
            allowed_enforcers=_allowed_enforcers_for_node(node, effective_goals),
        )
        return _from_transfer_result(transferred, child.transfer_rules, "Materialize")
    raise TypeError(f"unsupported IR node: {node!r}")


def _from_transfer_result(
    transferred: Any,
    prior_rules: tuple[str, ...],
    rule: str,
) -> _IRTransferEvaluation:
    if not transferred.ok or transferred.sigma is None:
        return _IRTransferEvaluation.reject(transferred.reason)
    return _IRTransferEvaluation.accept(
        transferred.sigma,
        transfer_rules=_append_transfer_rule(prior_rules, rule),
    )


def _necessity_fact_for_select(node: Select) -> str:
    label = node.expr_label.strip() or node.pred.strip() or "select"
    if label.startswith("gamma:necessary:"):
        return label
    normalized = "".join(char if char.isalnum() or char in ":-_" else "_" for char in label)
    return f"gamma:necessary:{normalized}"


def _has_necessity_fact(
    node: Select,
    effective_goals: Mapping[str, OccurrenceGoal],
) -> bool:
    fact = _necessity_fact_for_select(node)
    occurrence_ids = _scan_occurrence_ids(node)
    if not occurrence_ids:
        return False
    for occurrence_id in occurrence_ids:
        goal = effective_goals.get(occurrence_id)
        if goal is None:
            return False
        if goal.problem.require_typed_admission:
            gamma = goal.problem.gamma_snapshot
            if gamma is None or not gamma.has_pass(
                fact,
                subject_digest=policy_subject_digest(goal.problem),
            ):
                return False
        elif fact not in goal.gamma_facts:
            return False
    return True


def _duplicate_collapse_gamma_fact(node: DuplicateCollapse) -> str:
    label = node.gamma_fact.strip()
    if not label:
        return ""
    if label.startswith("gamma:duplicate-collapse:"):
        return label
    normalized = "".join(char if char.isalnum() or char in ":-_" else "_" for char in label)
    return f"gamma:duplicate-collapse:{normalized}"


def _has_duplicate_collapse_fact(
    node: DuplicateCollapse,
    effective_goals: Mapping[str, OccurrenceGoal],
) -> bool:
    fact = _duplicate_collapse_gamma_fact(node)
    if not fact:
        return False
    occurrence_ids = _scan_occurrence_ids(node)
    if not occurrence_ids:
        return False
    for occurrence_id in occurrence_ids:
        goal = effective_goals.get(occurrence_id)
        if goal is None:
            return False
        if goal.problem.require_typed_admission:
            gamma = goal.problem.gamma_snapshot
            if gamma is None or not gamma.has_pass(
                fact,
                subject_digest=policy_subject_digest(goal.problem),
            ):
                return False
        elif fact not in goal.gamma_facts:
            return False
    return True


def _allowed_enforcers_for_node(
    node: PlanNode,
    effective_goals: Mapping[str, OccurrenceGoal],
) -> tuple[str, ...]:
    occurrence_ids = _scan_occurrence_ids(node)
    if not occurrence_ids:
        return ("residual_check", "validation_gate", "sort", "materialize")
    allowed: set[str] | None = None
    for occurrence_id in occurrence_ids:
        goal = effective_goals.get(occurrence_id)
        current = set(goal.problem.parent_requirement.allowed_enforcers) if goal else set()
        allowed = current if allowed is None else allowed & current
    return tuple(sorted(allowed or ()))


def _scan_occurrence_ids(node: PlanNode) -> tuple[str, ...]:
    ids: list[str] = []
    for current in walk(node):
        if isinstance(current, ScanProtected) and current.occurrence_id not in ids:
            ids.append(current.occurrence_id)
    return tuple(ids)


def _ir_operator_name(node: PlanNode) -> str | None:
    if isinstance(node, (ScanProtected, ScanOrdinary)):
        return None
    return str(node.to_dict().get("node", ""))


def _rule_operator(rule: str) -> str:
    return rule.split(":", 1)[0]


def _walk_transfer_nodes_postorder(
    node: PlanNode,
    path: tuple[str, ...] = ("root",),
) -> tuple[tuple[PlanNode, tuple[str, ...]], ...]:
    if isinstance(node, Root):
        children = ((node.source, "source"),)
    elif isinstance(node, (Select, Project, DuplicateCollapse, UnsafeExpr, Boundary, RCheck)):
        children = ((node.source, "source"),)
    elif isinstance(node, InnerJoin):
        children = ((node.left, "left"), (node.right, "right"))
    elif isinstance(node, UnionTagged):
        children = tuple(
            (branch, f"branches[{index}]")
            for index, branch in enumerate(node.branches)
        )
    elif isinstance(node, (BarrierEnforce, ValidationGate, SortEnforce, Materialize)):
        children = ((node.source, "source"),)
    else:
        children = ()

    nodes: list[tuple[PlanNode, tuple[str, ...]]] = []
    for child, label in children:
        nodes.extend(_walk_transfer_nodes_postorder(child, (*path, label)))
    if _ir_operator_name(node) is not None:
        nodes.append((node, path))
    return tuple(nodes)


def _operator_transfer_evidence(
    bound_ir: PlanNode,
    transfer_rules: tuple[str, ...],
) -> tuple[Mapping[str, Any], ...]:
    transfer_nodes = _walk_transfer_nodes_postorder(bound_ir)
    cursor = 0
    evidence: list[Mapping[str, Any]] = []
    for index, rule in enumerate(transfer_rules):
        operator = _rule_operator(rule)
        matched_node: PlanNode | None = None
        matched_path: tuple[str, ...] = ("unmatched", str(index))
        for candidate_index in range(cursor, len(transfer_nodes)):
            node, path = transfer_nodes[candidate_index]
            if _ir_operator_name(node) == operator:
                matched_node = node
                matched_path = path
                cursor = candidate_index + 1
                break
        evidence.append(
            {
                "rule": rule,
                "operator": operator,
                "node_path": list(matched_path),
                "occurrence_ids": list(_scan_occurrence_ids(matched_node)) if matched_node else [],
                "traversal_index": index,
                "ir_traversal_version": "ir_transfer_path_v1",
            }
        )
    return tuple(evidence)


def _query_certificate_and_check(
    *,
    occurrence_results: Mapping[str, PlanResult],
    root_sigma: Mapping[str, Any],
    root_closure: RootClosure,
    operator_transfers: Sequence[str | Mapping[str, Any]] = (),
) -> tuple[tuple[Mapping[str, Any], ...] | None, Mapping[str, Any] | None]:
    if not root_closure.ok:
        return None, None
    occurrence_certificates: dict[str, tuple[Mapping[str, Any], ...]] = {}
    for occurrence_id, result in sorted(occurrence_results.items()):
        chosen = result.chosen_template
        if chosen is None or chosen.certificate is None:
            return None, None
        occurrence_certificates[occurrence_id] = tuple(
            dict(step) for step in chosen.certificate
        )
    certificate = emit_query_certificate(
        occurrence_certificates=occurrence_certificates,
        operator_transfers=operator_transfers,
        delivered_sigma=root_sigma,
        domain_covering=root_closure.domain_covering,
        live_pairs_certified=root_closure.live_pairs_certified,
        residuals_closed=root_closure.residuals_closed,
    )
    checked = check_certificate(
        certificate,
        expected_sigma=root_sigma,
        template_id="query_plan",
    )
    check_payload = checked.to_dict()
    if not checked.ok:
        rendered = ", ".join(reject.reason for reject in checked.rejects)
        raise ValueError(f"query certificate check failed: {rendered}")
    return certificate, check_payload


def _apply_query_enforcers(
    *,
    sigma: Sigma,
    result: PlanResult,
    problem: PlanningProblem,
    explicit_enforcers: tuple[str, ...],
) -> _EnforcerApplication:
    current = sigma
    inserted: list[EnforcerInsertion] = []
    explicit = set(explicit_enforcers)
    allowed = tuple(problem.parent_requirement.allowed_enforcers)
    disabled_components = set(problem.disabled_components)
    validation_disabled = bool(disabled_components & {"freshness", "context_scope", "rid_props"})

    for artifact_id in _chosen_artifact_ids(result, problem):
        if validation_disabled:
            continue
        gate = enforce_validation_gate(
            current,
            artifact_id=artifact_id,
            allowed_enforcers=allowed,
        )
        if not gate.ok or gate.sigma is None:
            return _EnforcerApplication.reject(gate.reason)
        current = gate.sigma
        if "validation_gate" not in explicit:
            inserted.extend(gate.inserted_enforcers)

    if current.residuals and "residual_check" not in explicit:
        if "residual_check" not in set(allowed):
            return _EnforcerApplication.accept(current, inserted_enforcers=tuple(inserted))
        checked = enforce_residual_check(current)
        if not checked.ok or checked.sigma is None:
            return _EnforcerApplication.reject(checked.reason)
        current = checked.sigma
        inserted.extend(checked.inserted_enforcers)

    required_order = tuple(problem.parent_requirement.required_order)
    if required_order and not _delivered_order_satisfies(current, required_order):
        sorted_result = enforce_sort(
            current,
            keys=required_order,
            allowed_enforcers=allowed,
        )
        if not sorted_result.ok or sorted_result.sigma is None:
            return _EnforcerApplication.reject(sorted_result.reason)
        current = sorted_result.sigma
        if "sort" not in explicit:
            inserted.extend(sorted_result.inserted_enforcers)

    if (
        "materialized" in set(problem.parent_requirement.observable_coverage)
        and not current.phys_props.get("materialized")
    ):
        materialized = enforce_materialize(current, allowed_enforcers=allowed)
        if not materialized.ok or materialized.sigma is None:
            return _EnforcerApplication.reject(materialized.reason)
        current = materialized.sigma
        if "materialize" not in explicit:
            inserted.extend(materialized.inserted_enforcers)

    return _EnforcerApplication.accept(current, inserted_enforcers=tuple(inserted))


def _chosen_artifact_ids(result: PlanResult, problem: PlanningProblem) -> tuple[str, ...]:
    chosen = result.chosen_template
    if chosen is None:
        return ()
    for step in chosen.certificate or ():
        if step.get("constructor") != "ArtifactValid":
            continue
        artifact_ids = step.get("artifact_ids")
        if isinstance(artifact_ids, Mapping):
            return tuple(str(value) for _key, value in sorted(artifact_ids.items()))
    kinds = _artifact_kinds_for_template(chosen.template_id)
    artifact_ids: list[str] = []
    for kind in kinds:
        artifact = problem.artifacts.get(kind)
        if artifact is not None:
            artifact_ids.append(artifact.artifact_id)
    return tuple(artifact_ids)


def _artifact_kinds_for_template(template_id: str) -> tuple[str, ...]:
    if template_id in {"mav_scan_v1"}:
        return ("mav",)
    if template_id in {"strong_auth_index_keyed_v1", "auth_index_keyed_semijoin_v1"}:
        return ("auth_idx_keyed",)
    if template_id in {
        "auth_index_enum_v1",
        "auth_index_semijoin_v1",
        "hybrid_intersect_v1",
    }:
        return ("auth_idx",)
    return ()


def _delivered_order_satisfies(sigma: Sigma, required_order: tuple[str, ...]) -> bool:
    delivered = _tuple_of_str(sigma.phys_props.get("delivered_order"))
    return required_order == delivered[: len(required_order)]


def _collect_explicit_enforcers(node: PlanNode) -> dict[str, tuple[str, ...]]:
    collected: dict[str, tuple[str, ...]] = {}

    def visit(current: PlanNode, active: tuple[str, ...]) -> None:
        if isinstance(current, ScanProtected):
            collected[current.occurrence_id] = _merge_tuple(
                collected.get(current.occurrence_id, ()),
                active,
            )
            return
        if isinstance(current, ScanOrdinary):
            return
        next_active = active
        if isinstance(current, RCheck):
            next_active = _merge_tuple(active, ("residual_check",))
        elif isinstance(current, ValidationGate):
            next_active = _merge_tuple(active, ("validation_gate",))
        elif isinstance(current, SortEnforce):
            next_active = _merge_tuple(active, ("sort",))
        elif isinstance(current, Materialize):
            next_active = _merge_tuple(active, ("materialize",))
        for child in current.children():
            visit(child, next_active)

    visit(node, ())
    return collected


def _root_closure_to_dict(closure: RootClosure) -> dict[str, Any]:
    return {
        "ok": closure.ok,
        "reason": closure.reason,
        "domain_covering": closure.domain_covering,
        "live_pairs_certified": closure.live_pairs_certified,
        "residuals_closed": closure.residuals_closed,
        "obligation_graph_digest": closure.obligation_graph_digest,
        "live_pairs": [
            {"basis_id": basis_id, "omega_id": omega_id}
            for basis_id, omega_id in closure.live_pairs
        ],
    }


def _template_oracle_rank(results: Any, mode: str) -> int | None:
    if mode == "local-greedy":
        return None
    ranks: list[int] = []
    for result in results:
        chosen = result.chosen_template
        if chosen is None or chosen.estimated_cost is None:
            continue
        accepted = sorted(
            (
                candidate
                for candidate in result.candidates
                if candidate.accepted and candidate.estimated_cost is not None
            ),
            key=lambda item: (float(item.estimated_cost or 0.0), item.template_id),
        )
        if chosen in accepted:
            ranks.append(1 + accepted.index(chosen))
    return max(ranks) if ranks else None


def _chosen_template_id(
    occurrence_id: str,
    occurrence_results: Mapping[str, PlanResult],
    fallback: str,
) -> str:
    result = occurrence_results.get(occurrence_id)
    if result is not None and result.chosen_template is not None:
        return result.chosen_template.template_id
    return fallback


def _wrap_occurrence_enforcers(
    node: PlanNode,
    occurrence_id: str,
    inserted_enforcers: Mapping[str, tuple[EnforcerInsertion, ...]],
) -> PlanNode:
    wrapped = node
    for enforcer in inserted_enforcers.get(occurrence_id, ()):
        if enforcer.enforcer == "ValidationGate":
            for artifact_id in enforcer.target_ids:
                wrapped = ValidationGate(wrapped, artifact_id=artifact_id)
        elif enforcer.enforcer == "RCheck":
            for residual_id in enforcer.target_ids:
                wrapped = RCheck(wrapped, residual_id=residual_id)
        elif enforcer.enforcer == "SortEnforce":
            wrapped = SortEnforce(wrapped, keys=enforcer.target_ids)
        elif enforcer.enforcer == "Materialize":
            wrapped = Materialize(wrapped)
    return wrapped


def _bind_chosen_templates(
    node: PlanNode,
    occurrence_results: Mapping[str, PlanResult],
    inserted_enforcers: Mapping[str, tuple[EnforcerInsertion, ...]],
) -> PlanNode:
    if isinstance(node, ScanProtected):
        bound = replace(
            node,
            template_slot=_chosen_template_id(
                node.occurrence_id,
                occurrence_results,
                node.template_slot,
            ),
        )
        return _wrap_occurrence_enforcers(bound, node.occurrence_id, inserted_enforcers)
    if isinstance(node, ScanOrdinary):
        return node
    if isinstance(node, Select):
        return replace(
            node,
            source=_bind_chosen_templates(node.source, occurrence_results, inserted_enforcers),
        )
    if isinstance(node, Project):
        return replace(
            node,
            source=_bind_chosen_templates(node.source, occurrence_results, inserted_enforcers),
        )
    if isinstance(node, InnerJoin):
        return replace(
            node,
            left=_bind_chosen_templates(node.left, occurrence_results, inserted_enforcers),
            right=_bind_chosen_templates(node.right, occurrence_results, inserted_enforcers),
        )
    if isinstance(node, UnionTagged):
        return replace(
            node,
            branches=tuple(
                _bind_chosen_templates(branch, occurrence_results, inserted_enforcers)
                for branch in node.branches
            ),
        )
    if isinstance(node, DuplicateCollapse):
        return replace(
            node,
            source=_bind_chosen_templates(node.source, occurrence_results, inserted_enforcers),
        )
    if isinstance(node, UnsafeExpr):
        return replace(
            node,
            source=_bind_chosen_templates(node.source, occurrence_results, inserted_enforcers),
        )
    if isinstance(node, Boundary):
        return replace(
            node,
            source=_bind_chosen_templates(node.source, occurrence_results, inserted_enforcers),
        )
    if isinstance(node, RCheck):
        return replace(
            node,
            source=_bind_chosen_templates(node.source, occurrence_results, inserted_enforcers),
        )
    if isinstance(node, BarrierEnforce):
        return replace(
            node,
            source=_bind_chosen_templates(node.source, occurrence_results, inserted_enforcers),
        )
    if isinstance(node, ValidationGate):
        return replace(
            node,
            source=_bind_chosen_templates(node.source, occurrence_results, inserted_enforcers),
        )
    if isinstance(node, SortEnforce):
        return replace(
            node,
            source=_bind_chosen_templates(node.source, occurrence_results, inserted_enforcers),
        )
    if isinstance(node, Materialize):
        return replace(
            node,
            source=_bind_chosen_templates(node.source, occurrence_results, inserted_enforcers),
        )
    if isinstance(node, Root):
        return replace(
            node,
            source=_bind_chosen_templates(node.source, occurrence_results, inserted_enforcers),
        )
    raise TypeError(f"unsupported IR node: {node!r}")


def _serialized_state_payload(
    *,
    query: PlanningQuery,
    effective_goals: Mapping[str, OccurrenceGoal],
    occurrence_results: Mapping[str, PlanResult],
    bound_ir: PlanNode,
    root_sigma: Mapping[str, Any],
    root_closure: RootClosure,
    certificate: tuple[Mapping[str, Any], ...] | None,
    certificate_check: Mapping[str, Any] | None,
    inserted_enforcers: Mapping[str, tuple[EnforcerInsertion, ...]],
    obligation_graph: ObligationGraph,
) -> dict[str, Any]:
    def serialized_result(result: PlanResult) -> dict[str, Any]:
        payload = result.to_dict()
        payload["mode"] = _scientific_mode_or_passthrough(result.mode)
        return payload

    return {
        "mode": _scientific_mode_or_passthrough(query.mode),
        "ir_skeleton": query.ir_skeleton.to_dict(),
        "bound_ir": bound_ir.to_dict(),
        "obligation_graph": obligation_graph.to_dict(),
        "obligation_graph_digest": obligation_graph.digest,
        "occurrence_goals": {
            occurrence_id: _occurrence_goal_to_dict(
                goal,
                execution_metadata=occurrence_results[
                    occurrence_id
                ].to_dict()["planning_execution"],
                scientific_mode=True,
            )
            for occurrence_id, goal in sorted(query.occurrence_goals.items())
        },
        "effective_occurrence_goals": {
            occurrence_id: _occurrence_goal_to_dict(
                goal,
                execution_metadata=occurrence_results[
                    occurrence_id
                ].to_dict()["planning_execution"],
                scientific_mode=True,
            )
            for occurrence_id, goal in sorted(effective_goals.items())
        },
        "occurrence_results": {
            occurrence_id: serialized_result(result)
            for occurrence_id, result in sorted(occurrence_results.items())
        },
        "root_closure": _root_closure_to_dict(root_closure),
        "root_sigma": dict(root_sigma),
        "certificate": None
        if certificate is None
        else [dict(step) for step in certificate],
        "certificate_check": None if certificate_check is None else dict(certificate_check),
        "inserted_enforcers": {
            occurrence_id: [enforcer.to_dict() for enforcer in enforcers]
            for occurrence_id, enforcers in sorted(inserted_enforcers.items())
        },
    }


def _scientific_mode_or_passthrough(mode: str) -> str:
    try:
        return scientific_mode_key(mode)
    except ValueError:
        # Diagnostic-only planner modes are intentionally outside the public
        # evaluation taxonomy and therefore have no rename mapping.
        return mode


def _occurrence_goal_to_dict(
    goal: OccurrenceGoal,
    *,
    execution_metadata: Mapping[str, Any] | None = None,
    scientific_mode: bool = False,
) -> dict[str, Any]:
    input_execution = planning_execution_metadata(goal.problem)
    execution = (
        input_execution
        if execution_metadata is None
        else dict(execution_metadata)
    )
    return {
        "mode": (
            _scientific_mode_or_passthrough(goal.mode)
            if scientific_mode and goal.mode is not None
            else goal.mode
        ),
        "gamma_facts": list(goal.gamma_facts),
        "required_gamma_facts": list(goal.required_gamma_facts),
        "planning_execution_input": input_execution,
        "planning_execution": execution,
        "problem": asdict(goal.problem),
    }
