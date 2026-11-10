"""Fail-closed reference dominance for completed CAPRLS root plans.

This module intentionally does *not* import :mod:`planner.core`: the legacy
planner currently applies a small, leaf-local heuristic dominance pass, while
the reference relation here is only meaningful after a complete root plan has
been closed, lowered, certified, and given prospective cost evidence.  Keeping
the model separate prevents an accidental early-DP use of a root-only rule.

The relation is deliberately conservative.  A profile whose field is absent,
unknown, malformed, or not represented by this finite model is incomparable
and therefore cannot prune another plan.  That can retain extra candidates,
but it cannot turn missing evidence into a fail-open dominance claim.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Protocol, TYPE_CHECKING

from .state import Need

if TYPE_CHECKING:  # Avoid a runtime core <-> dominance import cycle.
    from .core import ParentRequirement


_PROFILE_FIELDS = (
    "target_and_refinement",
    "visible_schema",
    "hidden_attrs_and_carriers",
    "auth_pairs",
    "residual_obligations_and_need",
    "coverage_and_live",
    "branch_and_lineage",
    "safety",
    "freshness",
    "context",
    "rid_and_materialization",
    "phys_props",
    "required_enforcers",
)

_SAFETY_RANK = {
    "unsafe_before_authorization": 0,
    "candidate": 1,
    "candidate_authorized": 1,
    "candidate_until_residual_discharge": 1,
    "engine_authorized": 2,
    "exact_authorized": 3,
}

_LINEAGE_RANK = {
    "lost": 0,
    "not_preserved": 0,
    "collapsed": 1,
    "preserved": 2,
}

_VALID_EVIDENCE_STATES = frozenset(
    {
        "valid_artifact",
        "non_artifact_exact",
        "engine_rls_policy",
        "bound_context",
        "validated",
    }
)
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class RhoLike(Protocol):
    """The read-only portion of ``ParentRequirement`` used by dominance."""

    licensed_refinements: tuple[str, ...]
    visible_columns: tuple[str, ...]
    required_order: tuple[str, ...]
    min_safety_level: str
    freshness_predicate: str | None
    context_predicate: str | None
    observable_coverage: tuple[str, ...]
    needs_branch_lineage: bool
    future_rid_intersection: bool


def _digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _freeze_strings(values: Any) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        return frozenset((str(values),))
    try:
        return frozenset(str(value) for value in values)
    except TypeError as exc:
        raise TypeError("expected an iterable of strings") from exc


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType({str(key): value[key] for key in sorted(value, key=str)})


def _predicate_atoms(predicate: str | None) -> frozenset[str]:
    """Return the finite predicate tokens used by the current rho contract.

    ``derive_occurrence_goals`` joins independently declared predicates with
    ``" && "``.  Reference dominance does not pretend to prove arbitrary SQL
    predicate implication; a token outside this finite contract is therefore
    only satisfied by an exact evidence token.
    """

    if not predicate:
        return frozenset()
    return frozenset(
        token.strip()
        for token in str(predicate).split(" && ")
        if token.strip()
    )


def _rho_hidden_superset_license(rho: RhoLike) -> frozenset[str]:
    """Read explicit finite-profile licenses for extra internal carriers.

    The existing ``ParentRequirement`` has no dedicated field for this yet.
    Until one is introduced, only the deliberately explicit
    ``allow_hidden_superset:<carrier>`` convention is accepted.  Absence of
    the marker means exact hidden-carrier equality is required.
    """

    prefix = "allow_hidden_superset:"
    licensed: set[str] = set()
    for item in getattr(rho, "observable_coverage", ()):
        text = str(item)
        if text.startswith(prefix) and text[len(prefix) :]:
            licensed.add(text[len(prefix) :])
    return frozenset(licensed)


@dataclass(frozen=True)
class VisibleColumn:
    """A root-observable output column, including PostgreSQL-relevant shape."""

    name: str
    type_name: str
    nullable: bool
    collation: str | None = None

    def __post_init__(self) -> None:
        if not self.name or not self.type_name:
            raise ValueError("VisibleColumn requires a name and type_name")
        if not isinstance(self.nullable, bool):
            raise TypeError("VisibleColumn.nullable must be bool")
        if self.collation is not None and not str(self.collation):
            raise ValueError("VisibleColumn.collation cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type_name": self.type_name,
            "nullable": self.nullable,
            "collation": self.collation,
        }


@dataclass(frozen=True)
class TargetAndRefinement:
    """Canonical target identity plus an explicit rho-licensed refinement."""

    target_id: str
    target_kind: str
    relation: str
    policy_id: str
    occurrence_ids: tuple[str, ...]
    refinement_kind: str | None = None
    refines_target_id: str | None = None
    refinement_predicate_digest: str | None = None
    refinement_evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not all(
            str(value)
            for value in (
                self.target_id,
                self.target_kind,
                self.relation,
                self.policy_id,
            )
        ):
            raise ValueError("TargetAndRefinement requires complete target identity")
        occurrences = tuple(str(value) for value in self.occurrence_ids)
        if not occurrences or any(not value for value in occurrences):
            raise ValueError("TargetAndRefinement requires occurrence_ids")
        if len(occurrences) != len(set(occurrences)):
            raise ValueError("TargetAndRefinement occurrence_ids must be unique")
        object.__setattr__(self, "occurrence_ids", occurrences)
        evidence = tuple(sorted(set(str(value) for value in self.refinement_evidence)))
        object.__setattr__(self, "refinement_evidence", evidence)
        if self.refinement_kind is None:
            if (
                self.refines_target_id is not None
                or self.refinement_predicate_digest is not None
                or evidence
            ):
                raise ValueError("unrefined target cannot carry refinement evidence")
        elif (
            not self.refines_target_id
            or self.refinement_predicate_digest is None
            or _SHA256_RE.fullmatch(self.refinement_predicate_digest) is None
            or not evidence
        ):
            raise ValueError(
                "refinement requires parent target, predicate digest, and evidence"
            )

    def same_target_as(self, other: "TargetAndRefinement") -> bool:
        return (
            self.target_id == other.target_id
            and self.target_kind == other.target_kind
            and self.relation == other.relation
            and self.policy_id == other.policy_id
            and self.occurrence_ids == other.occurrence_ids
        )

    def valid_replacement_for(self, other: "TargetAndRefinement", rho: RhoLike) -> bool:
        if self.same_target_as(other):
            return True
        return bool(
            self.refinement_kind
            and self.refines_target_id == other.target_id
            and self.refinement_kind in set(getattr(rho, "licensed_refinements", ()))
            and self.refinement_evidence
            and self.relation == other.relation
            and self.policy_id == other.policy_id
            and self.occurrence_ids == other.occurrence_ids
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "target_kind": self.target_kind,
            "relation": self.relation,
            "policy_id": self.policy_id,
            "occurrence_ids": list(self.occurrence_ids),
            "refinement_kind": self.refinement_kind,
            "refines_target_id": self.refines_target_id,
            "refinement_predicate_digest": self.refinement_predicate_digest,
            "refinement_evidence": list(self.refinement_evidence),
        }


def canonical_refined_target_id(
    logical_target_id: str,
    refinement_kind: str,
    refinement_predicate_digest: str,
) -> str:
    """Return a template-independent logical refinement identity."""

    if (
        not logical_target_id
        or not refinement_kind
        or _SHA256_RE.fullmatch(refinement_predicate_digest) is None
    ):
        raise ValueError("canonical refinement identity requires complete typed inputs")
    return _digest(
        {
            "contract": "logical_refined_target_v1",
            "logical_target_id": logical_target_id,
            "refinement_kind": refinement_kind,
            "refinement_predicate_digest": refinement_predicate_digest,
        }
    )


@dataclass(frozen=True, order=True)
class AuthPair:
    basis_id: str
    omega_id: str

    def __post_init__(self) -> None:
        if not self.basis_id or not self.omega_id:
            raise ValueError("AuthPair requires basis_id and omega_id")

    def to_dict(self) -> dict[str, str]:
        return {"basis_id": self.basis_id, "omega_id": self.omega_id}


@dataclass(frozen=True)
class ResidualObligation:
    """The complete residual identity, including Need and deadline.

    At the root this is proof/history metadata for a discharged residual, not
    permission for an open residual to cross root closure.
    """

    basis_id: str
    omega_id: str
    check_id: str
    need: Need
    deadline: str

    def __post_init__(self) -> None:
        if not self.basis_id or not self.omega_id or not self.check_id or not self.deadline:
            raise ValueError("ResidualObligation requires identity, Need, and deadline")
        if not isinstance(self.need, Need):
            raise TypeError("ResidualObligation.need must be Need")

    def to_dict(self) -> dict[str, Any]:
        return {
            "basis_id": self.basis_id,
            "omega_id": self.omega_id,
            "check_id": self.check_id,
            "need": self.need.to_dict(),
            "deadline": self.deadline,
        }


@dataclass(frozen=True)
class CoverageAndLive:
    coverage: frozenset[str]
    live_pairs: frozenset[AuthPair]

    def __post_init__(self) -> None:
        object.__setattr__(self, "coverage", _freeze_strings(self.coverage))
        object.__setattr__(self, "live_pairs", frozenset(self.live_pairs))
        if any(not isinstance(pair, AuthPair) for pair in self.live_pairs):
            raise TypeError("CoverageAndLive.live_pairs must contain AuthPair values")

    def to_dict(self) -> dict[str, Any]:
        return {
            "coverage": sorted(self.coverage),
            "live_pairs": [pair.to_dict() for pair in sorted(self.live_pairs)],
        }


@dataclass(frozen=True)
class BranchAndLineage:
    branch_lineage: str
    branch_tags: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.branch_lineage not in _LINEAGE_RANK:
            raise ValueError(f"unknown branch lineage: {self.branch_lineage}")
        object.__setattr__(self, "branch_tags", _freeze_strings(self.branch_tags))

    def to_dict(self) -> dict[str, Any]:
        return {
            "branch_lineage": self.branch_lineage,
            "branch_tags": sorted(self.branch_tags),
        }


@dataclass(frozen=True)
class SafetyProfile:
    """Safety levels keyed by canonical root basis identity."""

    by_basis: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        normalized = tuple(sorted((str(key), str(value)) for key, value in self.by_basis))
        if not normalized or len({key for key, _value in normalized}) != len(normalized):
            raise ValueError("SafetyProfile requires one known level for each basis")
        for basis_id, level in normalized:
            if not basis_id or level not in _SAFETY_RANK:
                raise ValueError(f"unknown safety level for basis {basis_id}: {level}")
        object.__setattr__(self, "by_basis", normalized)

    @classmethod
    def from_mapping(cls, by_basis: Mapping[str, str]) -> "SafetyProfile":
        return cls(tuple((str(key), str(value)) for key, value in by_basis.items()))

    def as_mapping(self) -> Mapping[str, str]:
        return MappingProxyType(dict(self.by_basis))

    def to_dict(self) -> dict[str, str]:
        return dict(self.by_basis)


@dataclass(frozen=True)
class RequirementEvidence:
    """Validator-originated freshness or context evidence for a root plan."""

    state: str
    satisfied_predicates: frozenset[str] = frozenset()
    evidence_refs: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.state not in _VALID_EVIDENCE_STATES:
            raise ValueError(f"unknown or failing evidence state: {self.state}")
        object.__setattr__(self, "satisfied_predicates", _freeze_strings(self.satisfied_predicates))
        object.__setattr__(self, "evidence_refs", _freeze_strings(self.evidence_refs))

    def satisfies(self, predicate: str | None) -> bool:
        return _predicate_atoms(predicate).issubset(self.satisfied_predicates)

    def covers(self, other: "RequirementEvidence") -> bool:
        # Different evidence states can encode materially different validation
        # paths.  Do not assume a lattice relation without a theorem.
        return (
            self.state == other.state
            and self.satisfied_predicates.issuperset(other.satisfied_predicates)
            and self.evidence_refs.issuperset(other.evidence_refs)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "satisfied_predicates": sorted(self.satisfied_predicates),
            "evidence_refs": sorted(self.evidence_refs),
        }


@dataclass(frozen=True)
class RIDMaterialization:
    rid_domain: str
    surrogate_col: str
    carrier: str
    materialized: bool

    def __post_init__(self) -> None:
        if not self.rid_domain or not self.surrogate_col or not self.carrier:
            raise ValueError("RIDMaterialization requires domain, surrogate, and carrier")
        if not isinstance(self.materialized, bool):
            raise TypeError("RIDMaterialization.materialized must be bool")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rid_domain": self.rid_domain,
            "surrogate_col": self.surrogate_col,
            "carrier": self.carrier,
            "materialized": self.materialized,
        }


@dataclass(frozen=True)
class PhysicalProperties:
    """Explicitly modeled root-observable and cost-relevant physical facts."""

    delivered_order: tuple[str, ...]
    observable_properties: tuple[tuple[str, str], ...] = ()
    cost_relevant_properties: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        order = tuple(str(value) for value in self.delivered_order)
        if any(not value for value in order):
            raise ValueError("PhysicalProperties.delivered_order cannot contain empty keys")
        object.__setattr__(self, "delivered_order", order)
        for field_name in ("observable_properties", "cost_relevant_properties"):
            normalized = tuple(
                sorted((str(key), str(value)) for key, value in getattr(self, field_name))
            )
            if len({key for key, _value in normalized}) != len(normalized):
                raise ValueError(f"{field_name} contains duplicate keys")
            if any(not key or not value for key, value in normalized):
                raise ValueError(f"{field_name} cannot contain empty entries")
            object.__setattr__(self, field_name, normalized)

    def to_dict(self) -> dict[str, Any]:
        return {
            "delivered_order": list(self.delivered_order),
            "observable_properties": dict(self.observable_properties),
            "cost_relevant_properties": dict(self.cost_relevant_properties),
        }


@dataclass(frozen=True, order=True)
class EnforcerRequirement:
    kind: str
    target_ids: tuple[str, ...] = ()
    placement: str = "root"

    def __post_init__(self) -> None:
        if not self.kind or not self.placement:
            raise ValueError("EnforcerRequirement requires kind and placement")
        targets = tuple(str(value) for value in self.target_ids)
        if any(not value for value in targets):
            raise ValueError("EnforcerRequirement target_ids cannot contain empty values")
        object.__setattr__(self, "target_ids", targets)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "target_ids": list(self.target_ids),
            "placement": self.placement,
        }


@dataclass(frozen=True)
class RhoObservableProfile:
    """All finite, rho-observable semantics required by reference dominance.

    ``None`` is intentionally distinct from an empty tuple/set: empty can be
    a valid known fact, whereas ``None`` marks a dimension unknown.  Unknown
    profiles remain serializable for an audit ledger but are never dominant.
    """

    target_and_refinement: TargetAndRefinement | None = None
    visible_schema: tuple[VisibleColumn, ...] | None = None
    hidden_attrs_and_carriers: frozenset[str] | None = None
    auth_pairs: frozenset[AuthPair] | None = None
    residual_obligations_and_need: frozenset[ResidualObligation] | None = None
    coverage_and_live: CoverageAndLive | None = None
    branch_and_lineage: BranchAndLineage | None = None
    safety: SafetyProfile | None = None
    freshness: RequirementEvidence | None = None
    context: RequirementEvidence | None = None
    rid_and_materialization: RIDMaterialization | None = None
    phys_props: PhysicalProperties | None = None
    required_enforcers: tuple[EnforcerRequirement, ...] | None = None
    unknown_dimensions: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        unknown = set(str(value) for value in self.unknown_dimensions)
        for field_name in _PROFILE_FIELDS:
            value = getattr(self, field_name)
            if value is None:
                unknown.add(field_name)

        expected_types = {
            "target_and_refinement": TargetAndRefinement,
            "coverage_and_live": CoverageAndLive,
            "branch_and_lineage": BranchAndLineage,
            "safety": SafetyProfile,
            "freshness": RequirementEvidence,
            "context": RequirementEvidence,
            "rid_and_materialization": RIDMaterialization,
            "phys_props": PhysicalProperties,
        }
        for field_name, expected_type in expected_types.items():
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, expected_type):
                raise TypeError(f"{field_name} must be {expected_type.__name__}")

        if self.visible_schema is not None:
            schema = tuple(self.visible_schema)
            if any(not isinstance(column, VisibleColumn) for column in schema):
                raise TypeError("visible_schema must contain VisibleColumn values")
            object.__setattr__(self, "visible_schema", schema)
        if self.hidden_attrs_and_carriers is not None:
            object.__setattr__(
                self,
                "hidden_attrs_and_carriers",
                _freeze_strings(self.hidden_attrs_and_carriers),
            )
        if self.auth_pairs is not None:
            pairs = frozenset(self.auth_pairs)
            if any(not isinstance(pair, AuthPair) for pair in pairs):
                raise TypeError("auth_pairs must contain AuthPair values")
            object.__setattr__(self, "auth_pairs", pairs)
        if self.residual_obligations_and_need is not None:
            residuals = frozenset(self.residual_obligations_and_need)
            if any(not isinstance(item, ResidualObligation) for item in residuals):
                raise TypeError("residual obligations must contain ResidualObligation values")
            object.__setattr__(self, "residual_obligations_and_need", residuals)
        if self.required_enforcers is not None:
            enforcers = tuple(sorted(self.required_enforcers))
            if any(not isinstance(item, EnforcerRequirement) for item in enforcers):
                raise TypeError("required_enforcers must contain EnforcerRequirement values")
            object.__setattr__(self, "required_enforcers", enforcers)
        object.__setattr__(self, "unknown_dimensions", frozenset(sorted(unknown)))

    @property
    def is_complete(self) -> bool:
        return not self.unknown_dimensions

    @property
    def digest(self) -> str:
        return _digest(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_and_refinement": None
            if self.target_and_refinement is None
            else self.target_and_refinement.to_dict(),
            "visible_schema": None
            if self.visible_schema is None
            else [column.to_dict() for column in self.visible_schema],
            "hidden_attrs_and_carriers": None
            if self.hidden_attrs_and_carriers is None
            else sorted(self.hidden_attrs_and_carriers),
            "auth_pairs": None
            if self.auth_pairs is None
            else [pair.to_dict() for pair in sorted(self.auth_pairs)],
            "residual_obligations_and_need": None
            if self.residual_obligations_and_need is None
            else [
                item.to_dict()
                for item in sorted(
                    self.residual_obligations_and_need,
                    key=lambda item: (item.basis_id, item.omega_id, item.check_id, item.deadline),
                )
            ],
            "coverage_and_live": None
            if self.coverage_and_live is None
            else self.coverage_and_live.to_dict(),
            "branch_and_lineage": None
            if self.branch_and_lineage is None
            else self.branch_and_lineage.to_dict(),
            "safety": None if self.safety is None else self.safety.to_dict(),
            "freshness": None if self.freshness is None else self.freshness.to_dict(),
            "context": None if self.context is None else self.context.to_dict(),
            "rid_and_materialization": None
            if self.rid_and_materialization is None
            else self.rid_and_materialization.to_dict(),
            "phys_props": None if self.phys_props is None else self.phys_props.to_dict(),
            "required_enforcers": None
            if self.required_enforcers is None
            else [item.to_dict() for item in self.required_enforcers],
            "unknown_dimensions": sorted(self.unknown_dimensions),
        }


@dataclass(frozen=True)
class FinalProspectiveCost:
    """Prospective cost only for a fully bound, statically checked root plan."""

    complete_root_plan_digest: str
    explain_plan_digest: str
    cost_after_all_enforcers: float
    sql_ast_digest: str
    certificate_digest: str
    static_verification_digest: str
    cost_model_version: str
    planning_environment_digest: str
    root_closed: bool
    certificate_replayed: bool
    plain_explain_completed: bool
    static_verification_passed: bool

    def __post_init__(self) -> None:
        required = (
            self.complete_root_plan_digest,
            self.explain_plan_digest,
            self.sql_ast_digest,
            self.certificate_digest,
            self.static_verification_digest,
            self.cost_model_version,
            self.planning_environment_digest,
        )
        if any(not str(value) for value in required):
            raise ValueError("FinalProspectiveCost requires complete bound-plan evidence")
        for label, value in (
            ("complete_root_plan_digest", self.complete_root_plan_digest),
            ("explain_plan_digest", self.explain_plan_digest),
            ("sql_ast_digest", self.sql_ast_digest),
            ("certificate_digest", self.certificate_digest),
            ("static_verification_digest", self.static_verification_digest),
            ("planning_environment_digest", self.planning_environment_digest),
        ):
            if not _SHA256_RE.fullmatch(value):
                raise ValueError(f"{label} must be a sha256 digest")
        if not isinstance(self.cost_after_all_enforcers, (int, float)) or not math.isfinite(
            float(self.cost_after_all_enforcers)
        ):
            raise ValueError("FinalProspectiveCost must contain a finite prospective cost")
        if float(self.cost_after_all_enforcers) < 0:
            raise ValueError("FinalProspectiveCost cannot be negative")
        checks = (
            self.root_closed,
            self.certificate_replayed,
            self.plain_explain_completed,
            self.static_verification_passed,
        )
        if any(not isinstance(value, bool) for value in checks):
            raise TypeError("FinalProspectiveCost verification states must be bool")
        if not (
            all(checks)
        ):
            raise ValueError(
                "FinalProspectiveCost requires passed root closure, certificate replay, "
                "plain EXPLAIN, and static verification"
            )
        object.__setattr__(self, "cost_after_all_enforcers", float(self.cost_after_all_enforcers))

    def to_dict(self) -> dict[str, Any]:
        return {
            "complete_root_plan_digest": self.complete_root_plan_digest,
            "explain_plan_digest": self.explain_plan_digest,
            "cost_after_all_enforcers": self.cost_after_all_enforcers,
            "sql_ast_digest": self.sql_ast_digest,
            "certificate_digest": self.certificate_digest,
            "static_verification_digest": self.static_verification_digest,
            "cost_model_version": self.cost_model_version,
            "planning_environment_digest": self.planning_environment_digest,
            "root_closed": self.root_closed,
            "certificate_replayed": self.certificate_replayed,
            "plain_explain_completed": self.plain_explain_completed,
            "static_verification_passed": self.static_verification_passed,
        }


@dataclass(frozen=True)
class ReferencePlan:
    """A completed candidate eligible for root-level reference comparison.

    ``measured_outcomes`` exists solely so callers can carry telemetry beside
    a plan record.  It is intentionally excluded from both equality and every
    dominance decision; no measured wall-clock value can influence selection.
    """

    plan_id: str
    profile: RhoObservableProfile
    prospective_cost: FinalProspectiveCost | None
    measured_outcomes: Mapping[str, Any] = field(
        default_factory=dict,
        compare=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if not self.plan_id:
            raise ValueError("ReferencePlan requires plan_id")
        if not isinstance(self.profile, RhoObservableProfile):
            raise TypeError("ReferencePlan.profile must be RhoObservableProfile")
        if self.prospective_cost is not None and not isinstance(
            self.prospective_cost, FinalProspectiveCost
        ):
            raise TypeError("ReferencePlan.prospective_cost must be FinalProspectiveCost")
        object.__setattr__(self, "measured_outcomes", _freeze_mapping(self.measured_outcomes))


@dataclass(frozen=True)
class ReferenceDominanceDecision:
    dominates: bool
    reason: str


@dataclass(frozen=True)
class CostEvidencePoolDecision:
    """All-or-nothing prospective-cost eligibility for one root frontier."""

    ok: bool
    reason: str
    cost_model_version: str | None = None
    planning_environment_digest: str | None = None


def validate_final_prospective_cost_pool(
    plans: Iterable[ReferencePlan],
) -> CostEvidencePoolDecision:
    """Reject mixed or partial cost evidence rather than selectively pruning.

    Callers pass the entire admitted root frontier.  A missing plain EXPLAIN
    cost for any member must cause a declared common fallback estimator or a
    cell-level planner/cost-evidence failure; this helper deliberately does
    not silently omit that member from the pool.
    """

    materialized = tuple(plans)
    if not materialized:
        return CostEvidencePoolDecision(False, "empty_root_frontier")
    if len({plan.plan_id for plan in materialized}) != len(materialized):
        return CostEvidencePoolDecision(False, "duplicate_root_plan_id")
    if any(plan.prospective_cost is None for plan in materialized):
        return CostEvidencePoolDecision(False, "missing_final_prospective_cost")
    costs = tuple(plan.prospective_cost for plan in materialized)
    assert all(cost is not None for cost in costs)
    first = costs[0]
    assert first is not None
    if any(
        cost is None
        or cost.cost_model_version != first.cost_model_version
        or cost.planning_environment_digest != first.planning_environment_digest
        for cost in costs
    ):
        return CostEvidencePoolDecision(False, "mixed_cost_evidence")
    return CostEvidencePoolDecision(
        True,
        "complete_common_prospective_cost_evidence",
        cost_model_version=first.cost_model_version,
        planning_environment_digest=first.planning_environment_digest,
    )


def _safety_at_least(left: SafetyProfile, right: SafetyProfile, rho: RhoLike) -> bool:
    left_levels = dict(left.by_basis)
    right_levels = dict(right.by_basis)
    required_level = str(getattr(rho, "min_safety_level", ""))
    if required_level not in _SAFETY_RANK:
        return False
    for basis_id, right_level in right_levels.items():
        left_level = left_levels.get(basis_id)
        if left_level is None or _SAFETY_RANK[left_level] < _SAFETY_RANK[right_level]:
            return False
    return all(_SAFETY_RANK[level] >= _SAFETY_RANK[required_level] for level in left_levels.values())


def _physical_rho_rejection_reason(
    props: PhysicalProperties | None,
    rid: RIDMaterialization | None,
    rho: RhoLike,
) -> str | None:
    required_order = tuple(str(value) for value in getattr(rho, "required_order", ()))
    if (
        props is not None
        and required_order
        and props.delivered_order[: len(required_order)] != required_order
    ):
        return "required_order_not_delivered"
    coverage = set(str(value) for value in getattr(rho, "observable_coverage", ()))
    if "materialized" in coverage and rid is not None and not rid.materialized:
        return "materialization_does_not_satisfy_rho"
    return None


@dataclass(frozen=True)
class ProfileRhoValidationDecision:
    ok: bool
    reason: str


def validate_profile_against_rho(
    profile: RhoObservableProfile,
    rho: RhoLike,
    *,
    expected_logical_target_id: str | None = None,
) -> ProfileRhoValidationDecision:
    """Reject known rho conflicts; require completeness before ranking."""

    target = profile.target_and_refinement
    if target is not None and target.refinement_kind is not None:
        if target.refinement_kind not in set(
            str(value) for value in getattr(rho, "licensed_refinements", ())
        ):
            return ProfileRhoValidationDecision(
                False,
                "target_refinement_not_licensed_by_rho",
            )
        assert target.refines_target_id is not None
        assert target.refinement_predicate_digest is not None
        if target.target_id != canonical_refined_target_id(
            target.refines_target_id,
            target.refinement_kind,
            target.refinement_predicate_digest,
        ):
            return ProfileRhoValidationDecision(
                False,
                "logical_refinement_identity_mismatch",
            )
    if target is not None and expected_logical_target_id is not None:
        if target.refinement_kind is None:
            if target.target_id != expected_logical_target_id:
                return ProfileRhoValidationDecision(
                    False,
                    "logical_target_identity_mismatch",
                )
        else:
            if (
                target.refines_target_id != expected_logical_target_id
                or target.refinement_predicate_digest is None
                or target.target_id
                != canonical_refined_target_id(
                    expected_logical_target_id,
                    target.refinement_kind,
                    target.refinement_predicate_digest,
                )
            ):
                return ProfileRhoValidationDecision(
                    False,
                    "logical_refinement_identity_mismatch",
                )

    required_visible = tuple(str(value) for value in getattr(rho, "visible_columns", ()))
    if (
        profile.visible_schema is not None
        and required_visible
        and tuple(column.name for column in profile.visible_schema) != required_visible
    ):
        return ProfileRhoValidationDecision(False, "visible_schema_does_not_satisfy_rho")
    required_coverage = {
        str(value)
        for value in getattr(rho, "observable_coverage", ())
        if not str(value).startswith("allow_hidden_superset:")
    }
    if (
        profile.coverage_and_live is not None
        and not required_coverage.issubset(profile.coverage_and_live.coverage)
    ):
        return ProfileRhoValidationDecision(False, "coverage_does_not_satisfy_rho")
    if (
        profile.branch_and_lineage is not None
        and getattr(rho, "needs_branch_lineage", False)
        and profile.branch_and_lineage.branch_lineage != "preserved"
    ):
        return ProfileRhoValidationDecision(False, "branch_lineage_does_not_satisfy_rho")
    if (
        profile.rid_and_materialization is not None
        and getattr(rho, "future_rid_intersection", False)
        and not profile.rid_and_materialization.carrier
    ):
        return ProfileRhoValidationDecision(False, "rid_carrier_does_not_satisfy_rho")
    if profile.safety is not None and not _safety_at_least(
        profile.safety,
        profile.safety,
        rho,
    ):
        return ProfileRhoValidationDecision(False, "safety_does_not_satisfy_rho")
    if profile.freshness is not None and not profile.freshness.satisfies(
        getattr(rho, "freshness_predicate", None)
    ):
        return ProfileRhoValidationDecision(False, "freshness_does_not_satisfy_rho")
    if profile.context is not None and not profile.context.satisfies(
        getattr(rho, "context_predicate", None)
    ):
        return ProfileRhoValidationDecision(False, "context_does_not_satisfy_rho")
    physical_reason = _physical_rho_rejection_reason(
        profile.phys_props,
        profile.rid_and_materialization,
        rho,
    )
    if physical_reason is not None:
        return ProfileRhoValidationDecision(False, physical_reason)
    if not profile.is_complete:
        return ProfileRhoValidationDecision(False, "unknown_or_incomplete_profile")
    return ProfileRhoValidationDecision(True, "profile_satisfies_rho")


def _profile_satisfies_rho(profile: RhoObservableProfile, rho: RhoLike) -> bool:
    return validate_profile_against_rho(profile, rho).ok


def _semantic_replacement_reason(
    left: RhoObservableProfile,
    right: RhoObservableProfile,
    rho: RhoLike,
) -> str | None:
    """Return ``None`` iff the left profile safely replaces the right one."""

    if not left.is_complete or not right.is_complete:
        return "unknown_or_incomplete_profile"
    if not _profile_satisfies_rho(left, rho) or not _profile_satisfies_rho(right, rho):
        return "profile_does_not_satisfy_rho"

    # Narrow the type checker after the completeness guard; all values are
    # non-None by construction of an is_complete profile.
    assert left.target_and_refinement is not None and right.target_and_refinement is not None
    assert left.visible_schema is not None and right.visible_schema is not None
    assert left.hidden_attrs_and_carriers is not None and right.hidden_attrs_and_carriers is not None
    assert left.auth_pairs is not None and right.auth_pairs is not None
    assert left.residual_obligations_and_need is not None and right.residual_obligations_and_need is not None
    assert left.coverage_and_live is not None and right.coverage_and_live is not None
    assert left.branch_and_lineage is not None and right.branch_and_lineage is not None
    assert left.safety is not None and right.safety is not None
    assert left.freshness is not None and right.freshness is not None
    assert left.context is not None and right.context is not None
    assert left.rid_and_materialization is not None and right.rid_and_materialization is not None
    assert left.phys_props is not None and right.phys_props is not None
    assert left.required_enforcers is not None and right.required_enforcers is not None

    if not left.target_and_refinement.valid_replacement_for(right.target_and_refinement, rho):
        return "target_or_refinement_not_rho_valid"
    if left.visible_schema != right.visible_schema:
        return "visible_schema_mismatch"
    if not right.hidden_attrs_and_carriers.issubset(left.hidden_attrs_and_carriers):
        return "hidden_carrier_loss"
    extra_hidden = left.hidden_attrs_and_carriers - right.hidden_attrs_and_carriers
    if extra_hidden and not extra_hidden.issubset(_rho_hidden_superset_license(rho)):
        return "hidden_carrier_superset_not_licensed"
    if not right.auth_pairs.issubset(left.auth_pairs):
        return "auth_pair_coverage_loss"
    if not left.residual_obligations_and_need.issubset(right.residual_obligations_and_need):
        return "residual_obligation_not_discharged"
    if not right.coverage_and_live.coverage.issubset(left.coverage_and_live.coverage):
        return "observable_coverage_loss"
    if not right.coverage_and_live.live_pairs.issubset(left.coverage_and_live.live_pairs):
        return "live_pair_coverage_loss"
    if left.branch_and_lineage.branch_tags != right.branch_and_lineage.branch_tags:
        return "branch_tag_mismatch"
    if _LINEAGE_RANK[left.branch_and_lineage.branch_lineage] < _LINEAGE_RANK[
        right.branch_and_lineage.branch_lineage
    ]:
        return "branch_lineage_loss"
    if not _safety_at_least(left.safety, right.safety, rho):
        return "safety_level_loss"
    if not left.freshness.covers(right.freshness):
        return "freshness_not_comparable"
    if not left.context.covers(right.context):
        return "context_not_comparable"
    if (
        left.rid_and_materialization.rid_domain != right.rid_and_materialization.rid_domain
        or left.rid_and_materialization.surrogate_col != right.rid_and_materialization.surrogate_col
        or left.rid_and_materialization.carrier != right.rid_and_materialization.carrier
        or (
            right.rid_and_materialization.materialized
            and not left.rid_and_materialization.materialized
        )
    ):
        return "rid_or_materialization_mismatch"
    if left.phys_props.observable_properties != right.phys_props.observable_properties:
        return "observable_phys_props_mismatch"
    if left.phys_props.cost_relevant_properties != right.phys_props.cost_relevant_properties:
        return "cost_relevant_phys_props_mismatch"
    if left.required_enforcers != right.required_enforcers:
        return "required_enforcer_mismatch"
    return None


def compare_reference_dominance(
    left: ReferencePlan,
    right: ReferencePlan,
    rho: RhoLike,
) -> ReferenceDominanceDecision:
    """Evaluate the conservative root-level reference relation.

    Only ``FinalProspectiveCost`` is used for cost comparison.  The
    ``ReferencePlan.measured_outcomes`` field is deliberately never read.
    """

    if left.plan_id == right.plan_id:
        return ReferenceDominanceDecision(False, "same_plan")
    if left.prospective_cost is None or right.prospective_cost is None:
        return ReferenceDominanceDecision(False, "missing_final_prospective_cost")
    if (
        left.prospective_cost.cost_model_version != right.prospective_cost.cost_model_version
        or left.prospective_cost.planning_environment_digest
        != right.prospective_cost.planning_environment_digest
    ):
        return ReferenceDominanceDecision(False, "mixed_cost_evidence")

    semantic_reason = _semantic_replacement_reason(left.profile, right.profile, rho)
    if semantic_reason is not None:
        return ReferenceDominanceDecision(False, semantic_reason)

    left_cost = left.prospective_cost.cost_after_all_enforcers
    right_cost = right.prospective_cost.cost_after_all_enforcers
    if left_cost < right_cost:
        return ReferenceDominanceDecision(True, "strictly_lower_final_prospective_cost")
    if left_cost == right_cost and left.plan_id < right.plan_id:
        return ReferenceDominanceDecision(True, "deterministic_equal_cost_tie_break")
    return ReferenceDominanceDecision(False, "final_prospective_cost_not_lower")


def dominates_reference(
    left: ReferencePlan,
    right: ReferencePlan,
    rho: RhoLike,
) -> bool:
    """Return whether ``left`` is a fail-closed rho-relative replacement."""

    return compare_reference_dominance(left, right, rho).dominates


__all__ = [
    "AuthPair",
    "BranchAndLineage",
    "CostEvidencePoolDecision",
    "CoverageAndLive",
    "EnforcerRequirement",
    "FinalProspectiveCost",
    "PhysicalProperties",
    "ProfileRhoValidationDecision",
    "RIDMaterialization",
    "ReferenceDominanceDecision",
    "ReferencePlan",
    "RequirementEvidence",
    "ResidualObligation",
    "RhoObservableProfile",
    "SafetyProfile",
    "TargetAndRefinement",
    "VisibleColumn",
    "canonical_refined_target_id",
    "compare_reference_dominance",
    "dominates_reference",
    "validate_final_prospective_cost_pool",
    "validate_profile_against_rho",
]
