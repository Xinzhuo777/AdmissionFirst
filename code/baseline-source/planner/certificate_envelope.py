"""Strict certificate envelopes bound to real planning and execution objects.

The historical flat checker remains useful for auditing old run records, but
it deliberately accepts constructor fields as supplied.  This module is the
new fail-closed path: it records immutable identity digests and replays the
certificate against the *actual* plan, target, rho, Gamma, registry, SQL draft
and independently constructed :class:`ObligationGraph`.

The finite project fragment has no version-locked PostgreSQL parser.  Its
``sql_ast_digest`` therefore means the controlled continuation normal form in
``ExecutableDraft``; ``exact_sql_digest`` is carried alongside it and is the
authoritative mutation detector.
"""

from __future__ import annotations

import hashlib
import json
import weakref
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

from caprls_core.baselines import ADMISSION_FIRST_MODE

from .contracts import (
    GammaSnapshot,
    ImplementationTargetBinding,
    PolicyAccessTarget,
    TEMPLATE_DEFINITIONS,
    TemplateDefinition,
    canonical_predicate_digest,
)
from .execution import (
    ConditionallyCheckedPlan,
    DynamicObligation,
    ExecutableDraft,
    _make_conditionally_checked_plan_from_verified_replay,
)
from .obligations import ObligationGraph, build_obligation_graph
from .state import Sigma, sigma_from_dict
from .transfer import root_close
from .verifier.cert_checker import check_certificate


_SHA256_PREFIX = "sha256:"
_REPLAY_RESULT_CAPABILITY = object()
# This is a request-local provenance registry, not a cache of facts or
# certificates.  It lets the next type-state transition distinguish the exact
# object minted by replay from a public dataclass lookalike or ``replace``d
# copy. Weak references ensure this is not a cross-request certificate cache;
# no dynamic H2 verdict is stored here.
_VERIFIED_REPLAY_RESULTS: dict[
    int, weakref.ReferenceType["CertificateReplayResult"]
] = {}


class CertificateReplayError(ValueError):
    """Raised when a strict certificate cannot be replayed safely."""


def _canonical_value(value: Any) -> Any:
    """Convert finite planner values to an immutable JSON-safe structure."""

    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _canonical_value(value.to_dict())
    if is_dataclass(value):
        return {
            field.name: _canonical_value(getattr(value, field.name))
            for field in fields(value)
            if not field.name.startswith("_")
        }
    if isinstance(value, Mapping):
        return {str(key): _canonical_value(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, (tuple, list, frozenset, set)):
        items = [_canonical_value(item) for item in value]
        if isinstance(value, (frozenset, set)):
            return sorted(items, key=lambda item: json.dumps(item, sort_keys=True, default=str))
        return items
    return value


def _deep_freeze(value: Any) -> Any:
    """Take an immutable snapshot of certificate payloads at the envelope edge."""

    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _deep_freeze(value[key]) for key in sorted(value, key=str)}
        )
    if isinstance(value, (tuple, list)):
        return tuple(_deep_freeze(item) for item in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise CertificateReplayError(
        f"certificate payload contains unsupported mutable value: {type(value).__name__}"
    )


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw(child) for child in value]
    return value


def _digest(value: Any) -> str:
    encoded = json.dumps(
        _canonical_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return _SHA256_PREFIX + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _require_digest(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.startswith(_SHA256_PREFIX) or len(value) != 71:
        raise CertificateReplayError(f"{label} must be a sha256 digest")


def canonical_registry_digest(
    definitions: Sequence[TemplateDefinition] = TEMPLATE_DEFINITIONS,
) -> str:
    """Digest the complete canonical catalog, not a free-form version label."""

    return _digest(tuple(definitions))


def gamma_snapshots_digest(
    snapshots: Mapping[str, GammaSnapshot] | Sequence[GammaSnapshot],
) -> str:
    """Bind the complete planning Gamma input in a deterministic order."""

    normalized = _normalize_snapshots(snapshots)
    return _digest(
        tuple(
            (
                key,
                snapshot.snapshot_id,
                snapshot.digest,
            )
            for key, snapshot in normalized
        )
    )


def policy_predicate_binding_subject(problem: Any, predicate: str) -> str:
    """Return the validator subject for an exact-policy SQL predicate.

    ``trusted_exact_policy_executable`` establishes that a policy target is
    executable.  It does not, on its own, authenticate an arbitrary SQL
    spelling supplied later by an emitter.  Strict lowering therefore also
    requires a validator-issued fact over the typed policy target *and* the
    controlled predicate digest.  This is a finite-fragment identity binding,
    not a theorem of equivalence for arbitrary PostgreSQL expressions.
    """

    from .core import policy_subject_digest

    text = str(predicate).strip()
    if not text or text == "<exact_policy>":
        raise CertificateReplayError("strict lowering requires a concrete exact policy predicate")
    return _digest(
        {
            "policy_subject": policy_subject_digest(problem),
            "predicate_digest": canonical_predicate_digest(text),
            "relation": str(problem.relation),
            "policy_id": str(problem.policy_id),
            "rid_col": str(problem.rid_col),
        }
    )


def canonical_rho_binding(plan: Any, semantic_context: "SemanticReplayContext") -> Mapping[str, Any]:
    """Derive the only rho binding eligible for strict replay.

    ``rho`` is not a caller-authored certificate attachment.  The root
    component comes from the actual bound ``Root`` IR and every occurrence
    component comes from the typed effective goal that transfer consumed.
    Keeping this derivation next to replay prevents a matching pair of
    forged ``envelope.rho`` and function argument from bypassing root
    obligations.
    """

    if not isinstance(semantic_context, SemanticReplayContext):
        raise CertificateReplayError("canonical rho derivation requires SemanticReplayContext")
    root_rho = getattr(plan, "rho_root", {})
    if not isinstance(root_rho, Mapping):
        raise CertificateReplayError("bound IR root rho must be a mapping")
    occurrences: dict[str, Any] = {}
    for occurrence_id, goal in sorted(semantic_context.effective_occurrence_goals.items()):
        problem = getattr(goal, "problem", None)
        parent = None if problem is None else getattr(problem, "parent_requirement", None)
        if parent is None:
            raise CertificateReplayError(
                f"canonical rho derivation missing parent requirement: {occurrence_id}"
            )
        occurrences[occurrence_id] = asdict(parent)
    return {
        "root": _canonical_value(root_rho),
        "occurrences": _canonical_value(occurrences),
    }


def canonical_target_binding(
    plan: Any,
    semantic_context: "SemanticReplayContext",
    *,
    registry_definitions: Sequence[TemplateDefinition] = TEMPLATE_DEFINITIONS,
) -> Mapping[str, Mapping[str, Any]]:
    """Derive the complete strict target mapping from bound IR and typed goals.

    ``T`` is a semantic input, not an extensible caller-owned bag of fields.
    The finite implementation currently exposes exactly the subject and
    template fields below.  Requiring exact structural equality means a fresh
    envelope cannot authenticate either an omitted target component or an
    additional self-asserted refinement claim.
    """

    if not isinstance(semantic_context, SemanticReplayContext):
        raise CertificateReplayError("canonical target derivation requires SemanticReplayContext")
    scans = _finite_protected_scans(plan)
    if scans is None or set(scans) != set(semantic_context.effective_occurrence_goals):
        raise CertificateReplayError("canonical target derivation cannot bind protected occurrences")
    frozen_definitions = tuple(registry_definitions)
    definitions = {definition.template_id: definition for definition in frozen_definitions}
    if len(definitions) != len(frozen_definitions):
        raise CertificateReplayError("canonical target derivation has duplicate registry template IDs")
    target: dict[str, Mapping[str, Any]] = {}
    for occurrence_id, template_id in sorted(scans.items()):
        goal = semantic_context.effective_occurrence_goals[occurrence_id]
        problem = getattr(goal, "problem", None)
        definition = definitions.get(template_id)
        if problem is None or definition is None:
            raise CertificateReplayError(
                "canonical target derivation has unknown selected template or goal: "
                + occurrence_id
            )
        logical_target = getattr(problem, "logical_target", None)
        if not isinstance(logical_target, PolicyAccessTarget):
            raise CertificateReplayError(
                "canonical target derivation requires typed PolicyAccessTarget: "
                + occurrence_id
            )
        raw_bindings = getattr(problem, "implementation_target_bindings", ())
        if not isinstance(raw_bindings, (list, tuple)) or any(
            not isinstance(binding, ImplementationTargetBinding)
            for binding in raw_bindings
        ):
            raise CertificateReplayError(
                "canonical target derivation has invalid implementation bindings: "
                + occurrence_id
            )
        selected_bindings = tuple(
            binding
            for binding in raw_bindings
            if binding.template_id == template_id
        )
        if len(selected_bindings) != 1:
            raise CertificateReplayError(
                "canonical target derivation requires one selected implementation binding: "
                + occurrence_id
            )
        selected_binding = selected_bindings[0]
        target[occurrence_id] = {
            "relation": str(problem.relation),
            "policy_id": str(problem.policy_id),
            "rid_col": str(problem.rid_col),
            "target_kind": str(definition.target_kind),
            "template_id": str(template_id),
            "logical_target": {
                "value": logical_target.to_dict(),
                "digest": logical_target.digest,
            },
            "selected_implementation": {
                "binding": selected_binding.to_dict(),
                "digest": selected_binding.digest,
            },
        }
    return target


def _strict_gamma_binding(
    semantic_context: "SemanticReplayContext",
    snapshots: Mapping[str, GammaSnapshot] | Sequence[GammaSnapshot],
) -> tuple[tuple[str, GammaSnapshot], ...]:
    """Bind strict Gamma exactly to the typed effective-goal domain."""

    if not isinstance(semantic_context, SemanticReplayContext):
        raise CertificateReplayError(
            "strict Gamma binding requires SemanticReplayContext"
        )
    if not isinstance(snapshots, Mapping):
        raise CertificateReplayError(
            "strict Gamma binding requires an occurrence-keyed mapping"
        )
    supplied_keys = tuple(snapshots.keys())
    if any(not isinstance(key, str) or not key for key in supplied_keys):
        raise CertificateReplayError(
            "strict Gamma occurrence keys must be nonempty strings"
        )
    expected_keys = tuple(sorted(semantic_context.effective_occurrence_goals))
    if set(supplied_keys) != set(expected_keys) or len(supplied_keys) != len(
        expected_keys
    ):
        raise CertificateReplayError(
            "strict Gamma occurrence domain does not match effective goals"
        )

    normalized: list[tuple[str, GammaSnapshot]] = []
    facts_by_id: dict[str, Any] = {}
    for occurrence_id in expected_keys:
        goal = semantic_context.effective_occurrence_goals[occurrence_id]
        problem = getattr(goal, "problem", None)
        expected = None if problem is None else getattr(
            problem, "gamma_snapshot", None
        )
        supplied = snapshots[occurrence_id]
        if not isinstance(expected, GammaSnapshot) or not isinstance(
            supplied, GammaSnapshot
        ):
            raise CertificateReplayError(
                "strict Gamma requires one typed snapshot per effective goal: "
                + occurrence_id
            )
        if _canonical_value(supplied) != _canonical_value(expected):
            raise CertificateReplayError(
                "strict Gamma snapshot value differs from effective goal: "
                + occurrence_id
            )
        local_fact_ids: set[str] = set()
        for fact in supplied.facts:
            if fact.fact_id in local_fact_ids:
                raise CertificateReplayError(
                    "strict Gamma snapshot contains duplicate fact_id: "
                    + occurrence_id
                    + ":"
                    + fact.fact_id
                )
            local_fact_ids.add(fact.fact_id)
            if fact.snapshot_id != supplied.snapshot_id:
                raise CertificateReplayError(
                    "strict Gamma fact snapshot identity mismatch: "
                    + occurrence_id
                    + ":"
                    + fact.fact_id
                )
            fact_value = _canonical_value(fact)
            prior = facts_by_id.get(fact.fact_id)
            if prior is not None and prior != fact_value:
                raise CertificateReplayError(
                    "strict Gamma fact_id conflicts across occurrences: "
                    + fact.fact_id
                )
            facts_by_id[fact.fact_id] = fact_value
        normalized.append((occurrence_id, supplied))
    return tuple(normalized)


@dataclass(frozen=True)
class SemanticReplayContext:
    """Inputs needed to re-run finite IR transfer instead of trusting Sigma.

    The context is assembled from the selected leaf plans before certificate
    replay.  It carries the *leaf* Sigma values and inherited occurrence goals
    that the finite transfer evaluator consumes; the final/root Sigma is
    intentionally absent because it must be derived during replay.
    """

    occurrence_leaf_sigmas: Mapping[str, Sigma | Mapping[str, Any]]
    effective_occurrence_goals: Mapping[str, Any]
    root_rho: Mapping[str, Any] = field(default_factory=dict)
    emit_context: Any | None = None
    emit_context_digest: str = field(init=False)

    def __post_init__(self) -> None:
        normalized_sigmas: dict[str, Sigma] = {}
        for occurrence_id, sigma in self.occurrence_leaf_sigmas.items():
            key = str(occurrence_id)
            if not key:
                raise CertificateReplayError("semantic replay leaf occurrence ID is empty")
            if isinstance(sigma, Sigma):
                normalized_sigmas[key] = sigma
            elif isinstance(sigma, Mapping):
                normalized_sigmas[key] = sigma_from_dict(sigma)
            else:
                raise CertificateReplayError("semantic replay leaves must be Sigma values")
        if not normalized_sigmas:
            raise CertificateReplayError("semantic replay requires at least one leaf Sigma")
        normalized_goals = {str(key): value for key, value in self.effective_occurrence_goals.items()}
        if set(normalized_sigmas) != set(normalized_goals):
            raise CertificateReplayError(
                "semantic replay leaf Sigma and occurrence-goal domains must match"
            )
        if any(not key or not hasattr(goal, "problem") for key, goal in normalized_goals.items()):
            raise CertificateReplayError("semantic replay requires typed occurrence goals")
        # Only the finite, typed emitter context is eligible for strict
        # replay.  The digest is captured here and recomputed at replay time,
        # so a mutable mapping nested in an otherwise frozen dataclass cannot
        # change the SQL lowering after the envelope was built.
        from .emit import EmitContext

        if not isinstance(self.emit_context, EmitContext):
            raise CertificateReplayError("semantic replay requires a typed EmitContext")
        object.__setattr__(self, "occurrence_leaf_sigmas", MappingProxyType(normalized_sigmas))
        object.__setattr__(self, "effective_occurrence_goals", MappingProxyType(normalized_goals))
        object.__setattr__(self, "root_rho", _deep_freeze(self.root_rho))
        object.__setattr__(self, "emit_context_digest", _digest(self.emit_context))


@dataclass(frozen=True)
class CertificateEnvelope:
    """The immutable identity boundary for a conditionally checked plan."""

    plan_digest: str
    target_digest: str
    rho_digest: str
    gamma_snapshot_digest: str
    registry_digest: str
    emit_context_digest: str
    sql_ast_digest: str
    exact_sql_digest: str
    obligation_graph_digest: str
    steps: tuple[Mapping[str, Any], ...]

    def __post_init__(self) -> None:
        for label, value in (
            ("plan_digest", self.plan_digest),
            ("target_digest", self.target_digest),
            ("rho_digest", self.rho_digest),
            ("gamma_snapshot_digest", self.gamma_snapshot_digest),
            ("registry_digest", self.registry_digest),
            ("emit_context_digest", self.emit_context_digest),
            ("sql_ast_digest", self.sql_ast_digest),
            ("exact_sql_digest", self.exact_sql_digest),
            ("obligation_graph_digest", self.obligation_graph_digest),
        ):
            _require_digest(value, label)
        normalized_steps = tuple(
            _deep_freeze(step) if isinstance(step, Mapping) else _invalid_step(step)
            for step in self.steps
        )
        if not normalized_steps:
            raise CertificateReplayError("certificate envelope cannot be empty")
        object.__setattr__(self, "steps", normalized_steps)

    @property
    def digest(self) -> str:
        return _digest(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_digest": self.plan_digest,
            "target_digest": self.target_digest,
            "rho_digest": self.rho_digest,
            "gamma_snapshot_digest": self.gamma_snapshot_digest,
            "registry_digest": self.registry_digest,
            "emit_context_digest": self.emit_context_digest,
            "sql_ast_digest": self.sql_ast_digest,
            "exact_sql_digest": self.exact_sql_digest,
            "obligation_graph_digest": self.obligation_graph_digest,
            "steps": [_thaw(step) for step in self.steps],
        }


def _invalid_step(value: Any) -> Mapping[str, Any]:
    raise CertificateReplayError(f"certificate step must be a mapping, got {type(value).__name__}")


@dataclass(frozen=True)
class CertificateReplayResult:
    """Result of strict static replay; successful output is still non-executable."""

    ok: bool
    reasons: tuple[str, ...]
    static_certificate_digest: str
    conditional_sigma_digest: str
    draft_identity_digest: str = ""
    pending_dynamic_obligations: tuple[DynamicObligation, ...] = ()
    h_obligations: tuple[str, ...] = ()
    _replay_capability: object | None = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        object.__setattr__(self, "reasons", tuple(str(reason) for reason in self.reasons))
        object.__setattr__(
            self,
            "pending_dynamic_obligations",
            tuple(self.pending_dynamic_obligations),
        )
        object.__setattr__(self, "h_obligations", tuple(sorted(set(self.h_obligations))) )
        if self.ok:
            _require_digest(self.static_certificate_digest, "static_certificate_digest")
            _require_digest(self.conditional_sigma_digest, "conditional_sigma_digest")
            _require_digest(self.draft_identity_digest, "draft_identity_digest")

    @property
    def pending_dynamic_obligation_ids(self) -> tuple[str, ...]:
        return tuple(item.obligation_id for item in self.pending_dynamic_obligations)


def _mint_verified_replay_result(
    *,
    static_certificate_digest: str,
    conditional_sigma_digest: str,
    draft_identity_digest: str,
    pending_dynamic_obligations: tuple[DynamicObligation, ...],
    h_obligations: tuple[str, ...],
) -> CertificateReplayResult:
    result = CertificateReplayResult(
        ok=True,
        reasons=(),
        static_certificate_digest=static_certificate_digest,
        conditional_sigma_digest=conditional_sigma_digest,
        draft_identity_digest=draft_identity_digest,
        pending_dynamic_obligations=pending_dynamic_obligations,
        h_obligations=h_obligations,
        _replay_capability=_REPLAY_RESULT_CAPABILITY,
    )
    key = id(result)

    def _drop(reference: weakref.ReferenceType[CertificateReplayResult]) -> None:
        if _VERIFIED_REPLAY_RESULTS.get(key) is reference:
            _VERIFIED_REPLAY_RESULTS.pop(key, None)

    _VERIFIED_REPLAY_RESULTS[key] = weakref.ref(result, _drop)
    return result


def _is_minted_replay_result(result: CertificateReplayResult) -> bool:
    return (
        result._replay_capability is _REPLAY_RESULT_CAPABILITY
        and _VERIFIED_REPLAY_RESULTS.get(id(result)) is not None
        and _VERIFIED_REPLAY_RESULTS[id(result)]() is result
    )


def build_certificate_envelope(
    *,
    plan: Any,
    target: Any,
    rho: Any,
    gamma_snapshots: Mapping[str, GammaSnapshot] | Sequence[GammaSnapshot],
    draft: ExecutableDraft,
    obligation_graph: ObligationGraph,
    semantic_context: SemanticReplayContext,
    steps: Sequence[Mapping[str, Any]],
    registry_definitions: Sequence[TemplateDefinition] = TEMPLATE_DEFINITIONS,
) -> CertificateEnvelope:
    """Build an envelope only from concrete planner/execution inputs."""

    if not isinstance(draft, ExecutableDraft):
        raise CertificateReplayError("strict envelope requires an ExecutableDraft")
    if not isinstance(semantic_context, SemanticReplayContext):
        raise CertificateReplayError("strict envelope requires a SemanticReplayContext")
    if _digest(semantic_context.emit_context) != semantic_context.emit_context_digest:
        raise CertificateReplayError("strict envelope emit context mutated before construction")
    if _canonical_value(rho) != _canonical_value(canonical_rho_binding(plan, semantic_context)):
        raise CertificateReplayError("strict envelope rho does not match bound IR and typed goals")
    if _canonical_value(target) != _canonical_value(
        canonical_target_binding(
            plan,
            semantic_context,
            registry_definitions=registry_definitions,
        )
    ):
        raise CertificateReplayError("strict envelope target does not match bound IR and typed goals")
    _strict_gamma_binding(semantic_context, gamma_snapshots)
    registry_digest = canonical_registry_digest(registry_definitions)
    if draft.registry_digest != registry_digest:
        raise CertificateReplayError("draft registry digest does not match the canonical registry")
    return CertificateEnvelope(
        plan_digest=_digest(plan),
        target_digest=_digest(target),
        rho_digest=_digest(rho),
        gamma_snapshot_digest=gamma_snapshots_digest(gamma_snapshots),
        registry_digest=registry_digest,
        emit_context_digest=semantic_context.emit_context_digest,
        sql_ast_digest=draft.full_ast_digest,
        exact_sql_digest=draft.exact_sql_digest,
        obligation_graph_digest=obligation_graph.digest,
        steps=tuple(dict(step) for step in steps),
    )


def replay_certificate_envelope(
    envelope: CertificateEnvelope,
    *,
    plan: Any,
    target: Any,
    rho: Mapping[str, Any],
    root_rho: Mapping[str, Any] | None = None,
    gamma_snapshots: Mapping[str, GammaSnapshot] | Sequence[GammaSnapshot],
    draft: ExecutableDraft,
    obligation_graph: ObligationGraph,
    root_sigma: Sigma | Mapping[str, Any],
    semantic_context: SemanticReplayContext | None = None,
    expected_occurrence_ids: Iterable[str] = (),
    required_evidence_refs: Iterable[str] = (),
    pending_dynamic_obligations: Iterable[DynamicObligation] = (),
    registry_definitions: Sequence[TemplateDefinition] = TEMPLATE_DEFINITIONS,
) -> CertificateReplayResult:
    """Replay a certificate against the actual objects that produced it.

    This function does not execute SQL or treat a planning-time H2 verdict as
    long-lived authority.  It returns unresolved dynamic obligations for the
    separate per-transaction authorization transition.
    """

    if not isinstance(envelope, CertificateEnvelope):
        raise CertificateReplayError("strict replay requires a CertificateEnvelope")
    reasons: list[str] = []
    context_digest = ""
    canonical_rho: Mapping[str, Any] | None = None
    canonical_target: Mapping[str, Mapping[str, Any]] | None = None
    if isinstance(semantic_context, SemanticReplayContext):
        context_digest = _digest(semantic_context.emit_context)
        if context_digest != semantic_context.emit_context_digest:
            reasons.append("semantic_replay_emit_context_mutated")
        try:
            canonical_rho = canonical_rho_binding(plan, semantic_context)
        except CertificateReplayError as exc:
            reasons.append("semantic_replay_rho_derivation_error:" + str(exc))
        else:
            if _canonical_value(rho) != _canonical_value(canonical_rho):
                reasons.append("semantic_replay_rho_binding_mismatch")
        try:
            canonical_target = canonical_target_binding(
                plan,
                semantic_context,
                registry_definitions=registry_definitions,
            )
        except CertificateReplayError as exc:
            reasons.append("semantic_replay_target_derivation_error:" + str(exc))
        else:
            if _canonical_value(target) != _canonical_value(canonical_target):
                reasons.append("semantic_replay_target_binding_mismatch")
        try:
            _strict_gamma_binding(semantic_context, gamma_snapshots)
        except CertificateReplayError as exc:
            reasons.append("semantic_replay_gamma_binding_error:" + str(exc))
    # Checker implementations consume ordinary JSON-shaped lists/maps.  The
    # envelope keeps a deep immutable snapshot; thaw a fresh value solely for
    # deterministic replay so checker normalization cannot mutate evidence.
    replay_steps = tuple(_thaw(step) for step in envelope.steps)
    if not isinstance(draft, ExecutableDraft):
        reasons.append("binding_mismatch:draft_missing")
    else:
        expected_registry_digest = canonical_registry_digest(registry_definitions)
        try:
            supplied_gamma_digest = gamma_snapshots_digest(gamma_snapshots)
        except CertificateReplayError:
            supplied_gamma_digest = ""
            reasons.append("binding_mismatch:gamma_invalid")
        checks = (
            ("plan", envelope.plan_digest, _digest(plan)),
            ("target", envelope.target_digest, _digest(target)),
            ("rho", envelope.rho_digest, _digest(rho)),
            ("gamma", envelope.gamma_snapshot_digest, supplied_gamma_digest),
            ("registry", envelope.registry_digest, expected_registry_digest),
            ("emit_context", envelope.emit_context_digest, context_digest),
            ("draft_registry", draft.registry_digest, expected_registry_digest),
            ("bound_ir", draft.bound_ir_digest, _digest(plan.to_dict()) if hasattr(plan, "to_dict") else ""),
            ("sql_ast", envelope.sql_ast_digest, draft.full_ast_digest),
            ("exact_sql", envelope.exact_sql_digest, draft.exact_sql_digest),
            ("obligation_graph", envelope.obligation_graph_digest, obligation_graph.digest),
        )
        reasons.extend(
            f"binding_mismatch:{label}" for label, expected, actual in checks if expected != actual
        )

    try:
        snapshots = _normalize_snapshots(gamma_snapshots)
    except CertificateReplayError as exc:
        reasons.append("gamma_inventory_invalid:" + str(exc))
        snapshots = ()
    all_facts: dict[str, Any] = {}
    for _key, snapshot in snapshots:
        for fact in snapshot.facts:
            all_facts.setdefault(fact.fact_id, fact)
            if fact.snapshot_id != snapshot.snapshot_id:
                reasons.append("gamma_snapshot_fact_mismatch")
            if fact.validator_version.startswith("legacy-"):
                reasons.append("legacy_gamma_not_eligible_for_strict_replay")
    for evidence_ref in sorted(set(str(item) for item in required_evidence_refs)):
        fact = all_facts.get(evidence_ref)
        if fact is None or not fact.accepted:
            reasons.append(f"admission_evidence_missing:{evidence_ref}")

    pending = tuple(pending_dynamic_obligations)
    if any(not isinstance(item, DynamicObligation) for item in pending):
        reasons.append("dynamic_obligation_invalid")
        pending = ()
    elif len({item.obligation_id for item in pending}) != len(pending):
        reasons.append("dynamic_obligation_duplicate")

    supplied_sigma = root_sigma if isinstance(root_sigma, Sigma) else sigma_from_dict(root_sigma)
    canonical_root_rho: Mapping[str, Any] = (
        {} if canonical_rho is None else canonical_rho["root"]
    )
    supplied_root_rho = root_rho if root_rho is not None else canonical_root_rho
    if _canonical_value(supplied_root_rho) != _canonical_value(canonical_root_rho):
        reasons.append("semantic_replay_root_rho_binding_mismatch")
    semantic_sigma, semantic_reasons = _replay_actual_finite_ir(
        plan=plan,
        target=target,
        steps=replay_steps,
        semantic_context=semantic_context,
        expected_occurrence_ids=expected_occurrence_ids,
        supplied_sigma=supplied_sigma,
        root_rho=supplied_root_rho,
        required_evidence_refs=required_evidence_refs,
        pending_dynamic_obligations=pending,
        registry_definitions=registry_definitions,
        obligation_graph=obligation_graph,
        draft=draft if isinstance(draft, ExecutableDraft) else None,
    )
    reasons.extend(semantic_reasons)
    actual_scans = _finite_protected_scans(plan)
    actual_occurrence_ids = () if actual_scans is None else tuple(sorted(actual_scans))
    supplied_occurrence_ids = tuple(sorted(set(str(item) for item in expected_occurrence_ids)))
    if actual_scans is None or supplied_occurrence_ids != actual_occurrence_ids:
        reasons.append("semantic_replay_expected_occurrences_mismatch")
    if semantic_sigma is None:
        sigma = supplied_sigma
    else:
        sigma = semantic_sigma
    flat = check_certificate(
        replay_steps,
        expected_sigma=sigma.to_dict(),
        template_id="query_plan",
    )
    if not flat.ok:
        reasons.extend(f"flat_certificate:{reject.reason}" for reject in flat.rejects)
    reasons.extend(
        _strict_constructor_shape_reasons(
            replay_steps,
            actual_occurrence_ids,
            plan=plan,
            target=target,
        )
    )
    reasons.extend(
        _artifact_step_evidence_reasons(
            replay_steps,
            all_facts=all_facts,
            pending_dynamic_obligations=pending,
        )
    )

    # RootClosed booleans are non-authoritative; recompute using immutable
    # pre-candidate obligations and the actual rho supplied to replay.
    closure = root_close(
        (sigma,),
        obligation_graph=obligation_graph,
        rho=supplied_root_rho,
    )
    if not closure.ok:
        reasons.append(f"independent_root_closure:{closure.reason}")
    root_steps = [step for step in replay_steps if step.get("constructor") == "RootClosed"]
    if len(root_steps) != 1:
        reasons.append("root_closed_cardinality_invalid")
    elif any(
        root_steps[0].get(field) is not expected
        for field, expected in (
            ("domain_covering", closure.domain_covering),
            ("live_pairs_certified", closure.live_pairs_certified),
            ("residuals_recorded_or_discharged", closure.residuals_closed),
        )
    ):
        reasons.append("root_closed_self_assertion_mismatch")

    if reasons:
        return CertificateReplayResult(
            ok=False,
            reasons=tuple(sorted(set(reasons))),
            static_certificate_digest="",
            conditional_sigma_digest="",
            draft_identity_digest="",
            pending_dynamic_obligations=pending,
            h_obligations=flat.h_obligations,
        )
    return _mint_verified_replay_result(
        static_certificate_digest=envelope.digest,
        conditional_sigma_digest=_digest(sigma.to_dict()),
        draft_identity_digest=draft.identity_digest,
        pending_dynamic_obligations=pending,
        h_obligations=flat.h_obligations,
    )


def conditionally_checked_from_replay(
    *,
    draft: ExecutableDraft,
    replay: CertificateReplayResult,
) -> ConditionallyCheckedPlan:
    """Turn a successful strict replay into the next non-executable state."""

    if not replay.ok or not _is_minted_replay_result(replay):
        raise CertificateReplayError("cannot construct a conditional plan from failed certificate replay")
    if draft.identity_digest != replay.draft_identity_digest:
        raise CertificateReplayError(
            "certificate replay was minted for a different ExecutableDraft"
        )
    return _make_conditionally_checked_plan_from_verified_replay(
        draft=draft,
        replay_draft_identity_digest=replay.draft_identity_digest,
        static_certificate_digest=replay.static_certificate_digest,
        conditional_sigma_digest=replay.conditional_sigma_digest,
        pending_dynamic_obligations=replay.pending_dynamic_obligations,
    )


def _replay_actual_finite_ir(
    *,
    plan: Any,
    target: Any,
    steps: Sequence[Mapping[str, Any]],
    semantic_context: SemanticReplayContext | None,
    expected_occurrence_ids: Iterable[str],
    supplied_sigma: Sigma,
    root_rho: Mapping[str, Any],
    required_evidence_refs: Iterable[str],
    pending_dynamic_obligations: Sequence[DynamicObligation],
    registry_definitions: Sequence[TemplateDefinition],
    obligation_graph: ObligationGraph,
    draft: ExecutableDraft | None,
) -> tuple[Sigma | None, tuple[str, ...]]:
    """Re-derive transfer state from finite IR and selected leaf Sigma values.

    Flat constructors remain evidence carriers, but cannot dictate their own
    final state.  The independent evaluator is the same pure finite transfer
    implementation used during planning; replay compares its actual transfer
    trace, leaf bindings, and final Sigma against the envelope payload.
    """

    if not isinstance(semantic_context, SemanticReplayContext):
        return None, ("semantic_replay_context_missing",)
    reasons: list[str] = []
    scans = _finite_protected_scans(plan)
    expected_ids = tuple(sorted(set(str(item) for item in expected_occurrence_ids)))
    actual_ids = () if scans is None else tuple(sorted(scans))
    if scans is None or expected_ids != actual_ids or set(actual_ids) != set(semantic_context.effective_occurrence_goals):
        reasons.append("semantic_replay_occurrence_context_mismatch")
    if _canonical_value(semantic_context.root_rho) != _canonical_value(root_rho):
        reasons.append("semantic_replay_root_rho_mismatch")
    try:
        rebuilt_graph = build_obligation_graph(
            plan,
            semantic_context.effective_occurrence_goals,
            root_observables=semantic_context.root_rho,
        )
    except Exception as exc:
        return None, tuple(
            sorted(set([*reasons, f"semantic_replay_obligation_graph_error:{type(exc).__name__}"]))
        )
    if rebuilt_graph.digest != obligation_graph.digest:
        reasons.append("semantic_replay_obligation_graph_mismatch")
    frozen_template_ids = {definition.template_id for definition in registry_definitions}
    if scans is None or any(template_id not in frozen_template_ids for template_id in scans.values()):
        reasons.append("semantic_replay_template_not_in_frozen_registry")
    reasons.extend(
        _native_rls_session_binding_reasons(
            scans=scans,
            semantic_context=semantic_context,
            draft=draft,
        )
    )
    try:
        from .emit import emit_sql

        expected_sql = emit_sql(plan, semantic_context.emit_context).render_core()
    except Exception as exc:
        return None, tuple(
            sorted(set([*reasons, f"semantic_replay_lowering_error:{type(exc).__name__}"]))
        )
    # Exact SQL (not merely the normalized AST digest) must be generated
    # from the replayed bound IR under the same controlled emit context.
    if draft is None or draft.core_sql != expected_sql:
        reasons.append("semantic_replay_canonical_lowering_mismatch")
    try:
        derived_evidence_refs, derived_pending = derive_typed_admission_bindings(
            plan=plan,
            semantic_context=semantic_context,
            registry_definitions=registry_definitions,
        )
    except CertificateReplayError as exc:
        return None, tuple(
            sorted(set([*reasons, "semantic_replay_typed_admission_rejected:" + str(exc)]))
        )
    if tuple(sorted(set(str(item) for item in required_evidence_refs))) != derived_evidence_refs:
        reasons.append("semantic_replay_admission_evidence_mismatch")
    if tuple(pending_dynamic_obligations) != derived_pending:
        reasons.append("semantic_replay_dynamic_obligation_mismatch")
    try:
        # Local import avoids making query's historical planner import this
        # strict envelope at module initialization time.
        from .query import _evaluate_bound_ir, _operator_transfer_evidence

        transfer = _evaluate_bound_ir(
            plan,
            semantic_context.occurrence_leaf_sigmas,
            semantic_context.effective_occurrence_goals,
        )
    except Exception as exc:
        return None, tuple(sorted(set([*reasons, f"semantic_replay_transfer_error:{type(exc).__name__}"])))
    if not transfer.ok or transfer.sigma is None:
        return None, tuple(
            sorted(
                set(
                    [
                        *reasons,
                        "semantic_replay_transfer_rejected:" + (transfer.reason or "unknown"),
                    ]
                )
            )
        )
    derived_sigma = transfer.sigma
    if _digest(derived_sigma.to_dict()) != _digest(supplied_sigma.to_dict()):
        reasons.append("semantic_replay_final_sigma_mismatch")

    expected_ir_transfers = tuple(
        {
            "constructor": "Transfer",
            "rule": "ir:" + str(item["rule"]),
            "preserves_live": True,
            "preserves_coverage": True,
            "operator": str(item["operator"]),
            "node_path": list(item["node_path"]),
            "occurrence_ids": list(item["occurrence_ids"]),
            "traversal_index": int(item["traversal_index"]),
            "ir_traversal_version": str(item["ir_traversal_version"]),
        }
        for item in _operator_transfer_evidence(plan, transfer.transfer_rules)
    )
    observed_ir_transfers = tuple(
        dict(step)
        for step in steps
        if str(step.get("constructor") or "") == "Transfer"
        and str(step.get("rule") or "").startswith("ir:")
    )
    if _canonical_value(observed_ir_transfers) != _canonical_value(expected_ir_transfers):
        reasons.append("semantic_replay_transfer_trace_mismatch")
    reasons.extend(
        _leaf_binding_reasons(
            plan=plan,
            target=target,
            steps=steps,
            leaves=semantic_context.occurrence_leaf_sigmas,
            goals=semantic_context.effective_occurrence_goals,
        )
    )
    # The historical flat checker validates fields that are present, but it
    # cannot prove that every constructor which the actual IR/admission path
    # requires is present.  Rebuild the entire finite proof in its canonical
    # topological order and compare every payload.  This makes one-step
    # erasure, duplication, reordering and self-certified evidence fail
    # closed instead of relying on a permissive query-level flat sequence.
    try:
        expected_steps = derive_strict_certificate_steps(
            plan=plan,
            semantic_context=semantic_context,
            obligation_graph=obligation_graph,
            root_rho=root_rho,
            registry_definitions=registry_definitions,
        )
    except CertificateReplayError as exc:
        reasons.append("semantic_replay_constructor_derivation_error:" + str(exc))
    else:
        if _canonical_value(steps) != _canonical_value(expected_steps):
            reasons.append("semantic_replay_constructor_trace_mismatch")
    return derived_sigma, tuple(sorted(set(reasons)))


def derive_strict_certificate_steps(
    *,
    plan: Any,
    semantic_context: SemanticReplayContext,
    obligation_graph: ObligationGraph,
    root_rho: Mapping[str, Any],
    registry_definitions: Sequence[TemplateDefinition] = TEMPLATE_DEFINITIONS,
) -> tuple[Mapping[str, Any], ...]:
    """Reconstruct the finite strict proof from trusted planner inputs.

    The legacy query certificate is retained for historical evidence readers,
    but it is not an authority in the strict path.  This function repeats the
    finite certificate construction from (1) the chosen slots in bound IR,
    (2) typed occurrence goals/leaf Sigma, (3) the frozen registry, and (4)
    the independently replayed transfer/root closure.  The returned sequence
    is a canonical postorder serialization of the proof DAG.
    """

    scans = _finite_protected_scans(plan)
    if scans is None or set(scans) != set(semantic_context.effective_occurrence_goals):
        raise CertificateReplayError("strict proof cannot bind protected occurrences")
    frozen_definitions = tuple(registry_definitions)
    definitions = {definition.template_id: definition for definition in frozen_definitions}
    if len(definitions) != len(frozen_definitions):
        raise CertificateReplayError("strict proof registry has duplicate template IDs")

    try:
        from .certificates import (
            certificate_to_dicts,
            emit_flat_certificate,
            emit_query_certificate,
        )
        from .core import _artifact_ids_for_template, template_spec_from_definition
        from .kappa import kappa_sem_for_template
        from .query import _evaluate_bound_ir, _operator_transfer_evidence
    except Exception as exc:  # pragma: no cover - import graph protection
        raise CertificateReplayError(
            "strict proof dependencies are unavailable: " + type(exc).__name__
        ) from exc

    leaf_paths = _finite_ir_leaf_paths(plan)
    if leaf_paths is None:
        raise CertificateReplayError("strict proof cannot derive finite IR leaf paths")
    protected_leaf_paths, _ordinary_leaf_paths = leaf_paths
    occurrence_certificates: dict[str, tuple[Mapping[str, Any], ...]] = {}
    for occurrence_id, template_id in sorted(scans.items()):
        goal = semantic_context.effective_occurrence_goals[occurrence_id]
        problem = getattr(goal, "problem", None)
        definition = definitions.get(template_id)
        leaf_sigma = semantic_context.occurrence_leaf_sigmas.get(occurrence_id)
        if problem is None or definition is None or leaf_sigma is None:
            raise CertificateReplayError(
                "strict proof has an unbound occurrence/template/leaf Sigma: " + occurrence_id
            )
        if definition.execution_class == "diagnostic_only":
            raise CertificateReplayError("strict proof cannot contain a diagnostic template")
        kappa_sem = kappa_sem_for_template(
            template_id,
            relation=problem.relation,
            policy_id=problem.policy_id,
            occurrence_id=occurrence_id,
            required_attrs=problem.required_attrs,
            required_ctx=problem.required_ctx,
            residual_deadline=problem.parent_requirement.residual_deadline,
        ).to_dict()
        flat_steps = tuple(
            step
            for step in certificate_to_dicts(
                emit_flat_certificate(
                    template_id=template_id,
                    kappa_sem=kappa_sem,
                    delivered_sigma=leaf_sigma.to_dict(),
                    artifact_ids=_artifact_ids_for_template(
                        problem.artifacts,
                        template_spec_from_definition(definition),
                    ),
                )
            )
            if step.get("constructor") != "OrdinaryOp"
        )
        leaf_identity = protected_leaf_paths.get(occurrence_id)
        if leaf_identity is None or leaf_identity[1] != template_id:
            raise CertificateReplayError(
                "strict proof protected leaf path/template mismatch: "
                + occurrence_id
            )
        occurrence_certificates[occurrence_id] = (
            *flat_steps,
            _strict_h6_leaf_step(
                operator=template_id,
                node_path=leaf_identity[0],
                occurrence_id=occurrence_id,
                logical_operator="ScanProtected",
            ),
        )

    transfer = _evaluate_bound_ir(
        plan,
        semantic_context.occurrence_leaf_sigmas,
        semantic_context.effective_occurrence_goals,
    )
    if not transfer.ok or transfer.sigma is None:
        raise CertificateReplayError(
            "strict proof transfer rejected: " + (transfer.reason or "unknown")
        )
    closure = root_close(
        (transfer.sigma,),
        obligation_graph=obligation_graph,
        rho=root_rho,
    )
    if not closure.ok:
        raise CertificateReplayError("strict proof root closure rejected: " + closure.reason)
    operator_transfers = _operator_transfer_evidence(plan, transfer.transfer_rules)
    base_steps = tuple(
        emit_query_certificate(
            occurrence_certificates=occurrence_certificates,
            operator_transfers=operator_transfers,
            delivered_sigma=transfer.sigma.to_dict(),
            domain_covering=closure.domain_covering,
            live_pairs_certified=closure.live_pairs_certified,
            residuals_closed=closure.residuals_closed,
        )
    )
    return _with_strict_h6_operator_steps(base_steps, plan=plan)


def _native_rls_session_binding_reasons(
    *,
    scans: Mapping[str, str] | None,
    semantic_context: SemanticReplayContext,
    draft: ExecutableDraft | None,
) -> tuple[str, ...]:
    """Bind external native-RLS evidence to the actual execution session."""

    if scans is None:
        return ("native_rls_protected_scan_shape_invalid",)
    reasons: list[str] = []
    for occurrence_id, template_id in scans.items():
        if template_id != "native_pg_rls_v1":
            continue
        goal = semantic_context.effective_occurrence_goals.get(occurrence_id)
        problem = None if goal is None else getattr(goal, "problem", None)
        contract = None if problem is None else getattr(problem, "native_rls_session_contract", None)
        if contract is None or not contract.matches(
            relation=str(getattr(problem, "relation", "")),
            policy_id=str(getattr(problem, "policy_id", "")),
        ):
            reasons.append("native_rls_contract_invalid")
            continue
        emitted_contract = semantic_context.emit_context.native_rls_contract_for(occurrence_id)
        if emitted_contract is None:
            reasons.append("native_rls_emit_contract_missing")
        elif _canonical_value(emitted_contract) != _canonical_value(contract):
            reasons.append("native_rls_emit_contract_mismatch")
        gamma = getattr(problem, "gamma_snapshot", None)
        if gamma is None or contract.snapshot_id != gamma.snapshot_id:
            reasons.append("native_rls_contract_snapshot_mismatch")
        if str(getattr(problem, "engine_rls_policy_hash", "")) != contract.policy_fingerprint:
            reasons.append("native_rls_policy_fingerprint_mismatch")
        if draft is None:
            reasons.append("native_rls_draft_missing")
            continue
        session = draft.session_contract
        if session.role != contract.role:
            reasons.append("native_rls_session_role_mismatch")
        if str(session.gucs.get("row_security", "")).lower() != "on":
            reasons.append("native_rls_session_row_security_disabled")
    return tuple(reasons)


def _leaf_binding_reasons(
    *,
    plan: Any,
    target: Any,
    steps: Sequence[Mapping[str, Any]],
    leaves: Mapping[str, Sigma],
    goals: Mapping[str, Any],
) -> tuple[str, ...]:
    """Bind every Exact/Candidate leaf to its real occurrence and Sigma."""

    scans = _finite_protected_scans(plan)
    if scans is None:
        return ("semantic_replay_protected_scan_shape_invalid",)
    reasons: list[str] = []
    if set(scans) != set(leaves) or set(leaves) != set(goals):
        reasons.append("semantic_replay_leaf_occurrence_mismatch")
        return tuple(reasons)
    target_map = target if isinstance(target, Mapping) else {}
    if set(str(key) for key in target_map) != set(scans):
        reasons.append("semantic_replay_target_occurrence_domain_mismatch")
    leaf_steps = [
        step
        for step in steps
        if str(step.get("constructor") or "") in {"ExactLeaf", "CandidateLeaf"}
    ]
    matched_indices: set[int] = set()
    for occurrence_id, template_id in scans.items():
        sigma = leaves[occurrence_id]
        goal = goals[occurrence_id]
        binding = target_map.get(occurrence_id)
        if not isinstance(binding, Mapping):
            reasons.append("semantic_replay_target_occurrence_missing")
            continue
        expected_kind = str(binding.get("target_kind") or "")
        if not expected_kind:
            reasons.append("semantic_replay_target_kind_missing")
        try:
            from .contracts import template_definition

            canonical_target_kind = template_definition(template_id).target_kind
        except KeyError:
            reasons.append("semantic_replay_target_template_unknown")
            canonical_target_kind = ""
        if expected_kind != canonical_target_kind:
            reasons.append("semantic_replay_target_kind_canonical_mismatch")
        if str(binding.get("template_id") or "") != template_id:
            reasons.append("semantic_replay_target_template_mismatch")
        problem = getattr(goal, "problem", None)
        if problem is None or (
            str(binding.get("relation") or "") != str(problem.relation)
            or str(binding.get("policy_id") or "") != str(problem.policy_id)
            or str(binding.get("rid_col") or "") != str(problem.rid_col)
        ):
            reasons.append("semantic_replay_target_subject_mismatch")
        basis_ids = {basis.basis_id for basis in sigma.dom}
        omega_ids = {omega for _basis, omega in sigma.auth_set}
        expected_constructor = "CandidateLeaf" if sigma.residuals else "ExactLeaf"
        matching = [
            index
            for index, step in enumerate(leaf_steps)
            if str(step.get("constructor") or "") == expected_constructor
            and str(step.get("target_kind") or "") == expected_kind
            and str(step.get("basis_id") or "") in basis_ids
            and str(step.get("omega_id") or "") in omega_ids
        ]
        if len(matching) != 1:
            reasons.append("semantic_replay_leaf_binding_mismatch")
            continue
        matched_indices.add(matching[0])
    if len(matched_indices) != len(leaf_steps):
        reasons.append("semantic_replay_leaf_consumption_mismatch")
    return tuple(reasons)


def _finite_protected_scans(plan: Any) -> Mapping[str, str] | None:
    if not hasattr(plan, "to_dict") or not callable(plan.to_dict):
        return None
    try:
        root = plan.to_dict()
    except Exception:
        return None
    if not isinstance(root, Mapping):
        return None
    scans: dict[str, str] = {}

    def visit(node: Mapping[str, Any]) -> bool:
        name = str(node.get("node") or "")
        if name == "ScanProtected":
            occurrence = str(node.get("occurrence_id") or "")
            template = str(node.get("template_slot") or "")
            if not occurrence or not template or occurrence in scans:
                return False
            scans[occurrence] = template
            return True
        if name == "ScanOrdinary":
            return True
        if name in {
            "Select", "Project", "DuplicateCollapse", "UnsafeExpr", "Boundary", "RCheck",
            "BarrierEnforce", "ValidationGate", "SortEnforce", "Materialize", "Root",
        }:
            child = node.get("source")
            return isinstance(child, Mapping) and visit(child)
        if name == "InnerJoin":
            left, right = node.get("left"), node.get("right")
            return isinstance(left, Mapping) and isinstance(right, Mapping) and visit(left) and visit(right)
        if name == "UnionTagged":
            branches = node.get("branches")
            return (
                isinstance(branches, (list, tuple))
                and bool(branches)
                and all(isinstance(branch, Mapping) and visit(branch) for branch in branches)
            )
        return False

    return scans if visit(root) else None


def derive_typed_admission_bindings(
    *,
    plan: Any,
    semantic_context: SemanticReplayContext,
    registry_definitions: Sequence[TemplateDefinition] = TEMPLATE_DEFINITIONS,
) -> tuple[tuple[str, ...], tuple[DynamicObligation, ...]]:
    """Re-evaluate canonical typed admission and derive its exact evidence set.

    This is intentionally independent of candidate diagnostics supplied by a
    caller.  It consumes the selected bound template, typed occurrence goal,
    and its Gamma snapshot, then returns the only static evidence references
    and per-subject H2 recipes that strict replay may accept.
    """

    scans = _finite_protected_scans(plan)
    if scans is None or set(scans) != set(semantic_context.effective_occurrence_goals):
        raise CertificateReplayError("typed admission replay cannot bind protected occurrences")
    # Import locally because planner.query imports the historical flat
    # certificate emitter.  The strict module is intentionally layered above
    # that historical path rather than forming an import cycle at startup.
    from .core import ContractChecker, template_spec_from_definition
    from .emit import ArtifactValidationRecipe, emit_sql

    checker = ContractChecker()
    evidence_refs: set[str] = set()
    obligations: list[DynamicObligation] = []
    frozen_definitions = tuple(registry_definitions)
    definitions_by_id = {
        definition.template_id: definition for definition in frozen_definitions
    }
    if len(definitions_by_id) != len(frozen_definitions):
        raise CertificateReplayError("strict replay registry contains duplicate template IDs")
    try:
        validation_recipes = tuple(emit_sql(plan, semantic_context.emit_context).validation_recipes)
    except Exception as exc:
        raise CertificateReplayError(
            "typed admission replay could not derive ValidationGate recipes: "
            + type(exc).__name__
        ) from exc
    if any(not recipe.complete for recipe in validation_recipes):
        incomplete = ", ".join(
            sorted(recipe.artifact_id for recipe in validation_recipes if not recipe.complete)
        )
        raise CertificateReplayError(
            "typed admission replay has incomplete ValidationGate recipe: " + incomplete
        )
    consumed_recipe_indices: set[int] = set()
    for occurrence_id, template_id in sorted(scans.items()):
        goal = semantic_context.effective_occurrence_goals[occurrence_id]
        problem = goal.problem
        if not bool(getattr(problem, "require_typed_admission", False)):
            raise CertificateReplayError(
                f"typed admission replay requires typed goal: {occurrence_id}"
            )
        if getattr(problem, "gamma_snapshot", None) is None:
            raise CertificateReplayError(
                f"typed admission replay requires Gamma snapshot: {occurrence_id}"
            )
        try:
            definition = definitions_by_id[template_id]
        except KeyError as exc:
            raise CertificateReplayError(
                f"typed admission replay selected template is absent from frozen registry: {template_id}"
            ) from exc
        check = checker.check(
            template_spec_from_definition(definition),
            problem,
            mode=getattr(goal, "mode", None) or ADMISSION_FIRST_MODE,
        )
        decision = check.admission_decision
        if decision is None or not decision.accepted:
            reasons = () if decision is None else decision.rejection_codes
            raise CertificateReplayError(
                "typed admission replay rejected " + occurrence_id + ": " + ", ".join(reasons)
            )
        leaf_sigma = sigma_from_dict(check.delivered_sigma)
        actual_leaf = semantic_context.occurrence_leaf_sigmas[occurrence_id]
        if _digest(leaf_sigma.to_dict()) != _digest(actual_leaf.to_dict()):
            raise CertificateReplayError(
                f"typed admission replay leaf Sigma mismatch: {occurrence_id}"
            )
        evidence_refs.update(decision.evidence_refs)
        if "trusted_exact_policy_executable" in definition.pre:
            predicate = semantic_context.emit_context.exact_predicate_for(occurrence_id)
            binding_subject = policy_predicate_binding_subject(problem, predicate)
            matching_binding_facts = tuple(
                fact
                for fact in problem.gamma_snapshot.matching(
                    "exact_policy_predicate_binding",
                    subject_digest=binding_subject,
                    require_static=True,
                )
                if fact.accepted
            )
            if not matching_binding_facts:
                raise CertificateReplayError(
                    "typed admission replay exact policy predicate binding missing: "
                    + occurrence_id
                )
            evidence_refs.update(fact.fact_id for fact in matching_binding_facts)
        artifact_recipes: tuple[ArtifactValidationRecipe, ...] = ()
        required_artifact_ids = _artifact_subjects_for_definition(problem, definition)
        if required_artifact_ids:
            indexed_matches = tuple(
                (index, recipe)
                for index, recipe in enumerate(validation_recipes)
                if recipe.occurrence_id == occurrence_id
                and recipe.template_id == template_id
                and recipe.artifact_id in set(required_artifact_ids)
            )
            if (
                len(indexed_matches) != len(required_artifact_ids)
                or tuple(sorted(recipe.artifact_id for _index, recipe in indexed_matches))
                != tuple(sorted(required_artifact_ids))
            ):
                raise CertificateReplayError(
                    "typed admission replay ValidationGate does not bind every selected artifact: "
                    + occurrence_id
                )
            if any(index in consumed_recipe_indices for index, _recipe in indexed_matches):
                raise CertificateReplayError("typed admission replay reuses a ValidationGate recipe")
            consumed_recipe_indices.update(index for index, _recipe in indexed_matches)
            artifact_recipes = tuple(recipe for _index, recipe in indexed_matches)
        obligations.extend(
            _dynamic_obligations_for_admission(
                occurrence_id=occurrence_id,
                template_id=template_id,
                problem=problem,
                decision=decision,
                definition=definition,
                artifact_recipes=artifact_recipes,
            )
        )
    if len(consumed_recipe_indices) != len(validation_recipes):
        raise CertificateReplayError("typed admission replay has an unconsumed ValidationGate recipe")
    unique_obligations = {item.obligation_id: item for item in obligations}
    if len(unique_obligations) != len(obligations):
        raise CertificateReplayError("typed admission replay produced duplicate dynamic obligations")
    return tuple(sorted(evidence_refs)), tuple(
        unique_obligations[key] for key in sorted(unique_obligations)
    )


def _dynamic_obligations_for_admission(
    *,
    occurrence_id: str,
    template_id: str,
    problem: Any,
    decision: Any,
    definition: TemplateDefinition,
    artifact_recipes: Sequence[Any] = (),
) -> tuple[DynamicObligation, ...]:
    from .execution import canonical_dynamic_recipe_digest

    gamma = problem.gamma_snapshot
    assert gamma is not None
    fact_by_id = {fact.fact_id: fact for fact in gamma.facts}
    definitions: dict[str, DynamicObligation] = {}

    def add(
        kind: str,
        subject: str,
        validator_version: str,
        *,
        fact_id: str = "",
        recipe_payload: Mapping[str, Any] | None = None,
    ) -> None:
        payload = {
            "occurrence_id": occurrence_id,
            "template_id": template_id,
            "kind": kind,
            "subject_digest": subject,
            "validator_version": validator_version,
            "gamma_snapshot_id": gamma.snapshot_id,
            "gamma_snapshot_digest": gamma.digest,
            "fact_id": fact_id,
        }
        if recipe_payload is not None:
            # The live validator must receive the complete gate recipe, not
            # merely an opaque digest.  Bind it to the exact Gamma snapshot
            # and dynamic H2 kind before carrying it across the type-state
            # boundary.
            payload = {**dict(recipe_payload), **payload}
        recipe = canonical_dynamic_recipe_digest(payload)
        obligation_id = f"{occurrence_id}:{kind}:{recipe.split(':', 1)[1][:20]}"
        obligation = DynamicObligation(
            obligation_id=obligation_id,
            kind=kind,
            subject_digest=subject,
            validator_version=validator_version,
            recipe_digest=recipe,
            recipe_payload=payload,
        )
        definitions[obligation_id] = obligation

    # A dynamic fact consumed for planning must always be revalidated with the
    # same fact identity/subject in the trial snapshot.
    for evidence_ref in decision.evidence_refs:
        fact = fact_by_id.get(evidence_ref)
        if fact is not None and fact.dynamic:
            add(fact.kind, fact.subject_digest, fact.validator_version, fact_id=fact.fact_id)

    required_kinds = set(decision.required_dynamic_fact_kinds)
    if required_kinds & {"artifact_freshness", "artifact_context", "artifact_toctou"}:
        if not artifact_recipes:
            raise CertificateReplayError(
                "dynamic artifact obligations require a bound ValidationGate recipe"
            )
        for kind in sorted(required_kinds & {"artifact_freshness", "artifact_context", "artifact_toctou"}):
            for recipe in artifact_recipes:
                if kind not in set(recipe.required_checks):
                    raise CertificateReplayError(
                        "ValidationGate recipe does not cover required dynamic check: " + kind
                    )
                add(
                    kind,
                    recipe.artifact_id,
                    "caprls-dynamic-h2-v1",
                    recipe_payload=recipe.to_dynamic_recipe_payload(),
                )
    if "authorization_view_binding" in required_kinds:
        view = getattr(problem, "authorization_view_binding", None)
        if view is None or not view.binding_id:
            raise CertificateReplayError("dynamic view obligation has no binding subject")
        add("authorization_view_binding", view.binding_id, "caprls-dynamic-h2-v1")
    if "native_rls_session_contract" in required_kinds:
        contract = getattr(problem, "native_rls_session_contract", None)
        if contract is None or not contract.contract_id:
            raise CertificateReplayError("dynamic native-RLS obligation has no contract subject")
        contract_payload = _canonical_value(contract)
        if not isinstance(contract_payload, Mapping):
            raise CertificateReplayError("dynamic native-RLS contract payload is invalid")
        add(
            "native_rls_session_contract",
            contract.contract_id,
            "caprls-dynamic-h2-v1",
            recipe_payload={
                "native_rls_contract": contract_payload,
                "native_rls_contract_digest": canonical_dynamic_recipe_digest(contract_payload),
                "engine_rls_policy_hash": str(getattr(problem, "engine_rls_policy_hash", "")),
                "relation": str(problem.relation),
                "policy_id": str(problem.policy_id),
            },
        )
    for kind in sorted(required_kinds - {
        "artifact_freshness", "artifact_context", "artifact_toctou",
        "authorization_view_binding", "native_rls_session_contract",
    }):
        # Other declared dynamic obligations are policy-scope bound.
        from .core import policy_subject_digest

        add(kind, policy_subject_digest(problem), "caprls-dynamic-h2-v1")
    return tuple(definitions[key] for key in sorted(definitions))


def _artifact_subjects_for_definition(
    problem: Any,
    definition: TemplateDefinition,
) -> tuple[str, ...]:
    artifacts = getattr(problem, "artifacts", {})
    subjects: list[str] = []
    for required in sorted(definition.required_artifacts):
        artifact = artifacts.get(required)
        if artifact is None and required == "auth_idx_keyed":
            candidate = artifacts.get("auth_idx")
            if candidate is not None and bool(getattr(candidate, "keyed", False)):
                artifact = candidate
        artifact_id = "" if artifact is None else str(getattr(artifact, "artifact_id", ""))
        if not artifact_id:
            raise CertificateReplayError(
                f"dynamic artifact obligation has no selected artifact: {required}"
            )
        subjects.append(artifact_id)
    return tuple(subjects)


def _normalize_snapshots(
    snapshots: Mapping[str, GammaSnapshot] | Sequence[GammaSnapshot],
) -> tuple[tuple[str, GammaSnapshot], ...]:
    if isinstance(snapshots, Mapping):
        normalized = tuple((str(key), snapshots[key]) for key in sorted(snapshots, key=str))
    else:
        normalized = tuple((str(index), item) for index, item in enumerate(tuple(snapshots)))
    if any(not isinstance(snapshot, GammaSnapshot) for _key, snapshot in normalized):
        raise CertificateReplayError("Gamma replay input must contain GammaSnapshot values")
    facts_by_id: dict[str, Any] = {}
    for key, snapshot in normalized:
        local_ids: set[str] = set()
        for fact in snapshot.facts:
            if fact.fact_id in local_ids:
                raise CertificateReplayError(
                    "Gamma snapshot contains duplicate fact_id: "
                    + key
                    + ":"
                    + fact.fact_id
                )
            local_ids.add(fact.fact_id)
            if fact.snapshot_id != snapshot.snapshot_id:
                raise CertificateReplayError(
                    "Gamma fact snapshot identity mismatch: "
                    + key
                    + ":"
                    + fact.fact_id
                )
            fact_value = _canonical_value(fact)
            prior = facts_by_id.get(fact.fact_id)
            if prior is not None and prior != fact_value:
                raise CertificateReplayError(
                    "Gamma fact_id conflicts across occurrences: "
                    + fact.fact_id
                )
            facts_by_id[fact.fact_id] = fact_value
    return normalized


def _finite_ir_leaf_paths(
    plan: Any,
) -> tuple[
    Mapping[str, tuple[tuple[str, ...], str]],
    tuple[tuple[tuple[str, ...], str], ...],
] | None:
    """Return protected and ordinary leaf identities in finite postorder."""

    if not hasattr(plan, "to_dict") or not callable(plan.to_dict):
        return None
    try:
        root = plan.to_dict()
    except Exception:
        return None
    if not isinstance(root, Mapping):
        return None
    protected: dict[str, tuple[tuple[str, ...], str]] = {}
    ordinary: list[tuple[tuple[str, ...], str]] = []

    def visit(node: Mapping[str, Any], path: tuple[str, ...]) -> bool:
        name = str(node.get("node") or "")
        if name == "ScanProtected":
            occurrence_id = str(node.get("occurrence_id") or "")
            template_id = str(node.get("template_slot") or "")
            if not occurrence_id or not template_id or occurrence_id in protected:
                return False
            protected[occurrence_id] = (path, template_id)
            return True
        if name == "ScanOrdinary":
            relation = str(node.get("rel") or "")
            if not relation:
                return False
            ordinary.append((path, relation))
            return True
        if name in {
            "Select",
            "Project",
            "DuplicateCollapse",
            "UnsafeExpr",
            "Boundary",
            "RCheck",
            "BarrierEnforce",
            "ValidationGate",
            "SortEnforce",
            "Materialize",
            "Root",
        }:
            child = node.get("source")
            return isinstance(child, Mapping) and visit(
                child, (*path, "source")
            )
        if name == "InnerJoin":
            left, right = node.get("left"), node.get("right")
            return (
                isinstance(left, Mapping)
                and isinstance(right, Mapping)
                and visit(left, (*path, "left"))
                and visit(right, (*path, "right"))
            )
        if name == "UnionTagged":
            branches = node.get("branches")
            return (
                isinstance(branches, (list, tuple))
                and bool(branches)
                and all(
                    isinstance(branch, Mapping)
                    and visit(branch, (*path, f"branches[{index}]"))
                    for index, branch in enumerate(branches)
                )
            )
        return False

    if not visit(root, ("root",)):
        return None
    return MappingProxyType(protected), tuple(ordinary)


def _strict_h6_leaf_step(
    *,
    operator: str,
    node_path: tuple[str, ...],
    occurrence_id: str = "",
    logical_operator: str,
    relation: str = "",
) -> Mapping[str, Any]:
    payload: dict[str, Any] = {
        "constructor": "OrdinaryOp",
        "operator": operator,
        "preserves_sigma": True,
        "strict_h6": True,
        "h6_scope": "selected_implementation"
        if occurrence_id
        else "ordinary_scan",
        "logical_operator": logical_operator,
        "node_path": list(node_path),
        "occurrence_ids": [occurrence_id] if occurrence_id else [],
    }
    if occurrence_id:
        payload["template_id"] = operator
    if relation:
        payload["relation"] = relation
    return payload


def _strict_h6_transfer_step(transfer_step: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        "constructor": "OrdinaryOp",
        "operator": str(transfer_step.get("operator") or ""),
        "preserves_sigma": True,
        "strict_h6": True,
        "h6_scope": "finite_ir_operator",
        "logical_operator": str(transfer_step.get("operator") or ""),
        "paired_transfer_rule": str(transfer_step.get("rule") or ""),
        "node_path": list(transfer_step.get("node_path") or ()),
        "occurrence_ids": list(transfer_step.get("occurrence_ids") or ()),
        "traversal_index": transfer_step.get("traversal_index"),
        "ir_traversal_version": str(
            transfer_step.get("ir_traversal_version") or ""
        ),
    }


def _with_strict_h6_operator_steps(
    steps: Sequence[Mapping[str, Any]],
    *,
    plan: Any,
) -> tuple[Mapping[str, Any], ...]:
    leaf_paths = _finite_ir_leaf_paths(plan)
    if leaf_paths is None:
        raise CertificateReplayError("strict H6 cannot derive finite IR leaves")
    _protected, ordinary = leaf_paths
    ordinary_steps = tuple(
        _strict_h6_leaf_step(
            operator="ScanOrdinary",
            node_path=path,
            logical_operator="ScanOrdinary",
            relation=relation,
        )
        for path, relation in ordinary
    )
    staged = list(steps)
    insertion_index = next(
        (
            index
            for index, step in enumerate(staged)
            if (
                step.get("constructor") == "Transfer"
                and (
                    str(step.get("rule") or "").startswith("ir:")
                    or str(step.get("rule") or "") == "query_root_closure"
                )
            )
        ),
        len(staged),
    )
    staged[insertion_index:insertion_index] = ordinary_steps

    bound: list[Mapping[str, Any]] = []
    for step in staged:
        bound.append(step)
        if step.get("constructor") == "Transfer" and str(
            step.get("rule") or ""
        ).startswith("ir:"):
            bound.append(_strict_h6_transfer_step(step))
    return tuple(bound)


def _strict_h6_trace_reasons(
    steps: Sequence[Mapping[str, Any]],
    *,
    plan: Any,
) -> tuple[str, ...]:
    leaf_paths = _finite_ir_leaf_paths(plan)
    if leaf_paths is None:
        return ("strict_h6_finite_ir_invalid",)
    protected, ordinary = leaf_paths
    expected_selected = tuple(
        _strict_h6_leaf_step(
            operator=template_id,
            node_path=path,
            occurrence_id=occurrence_id,
            logical_operator="ScanProtected",
        )
        for occurrence_id, (path, template_id) in sorted(protected.items())
    )
    expected_ordinary = tuple(
        _strict_h6_leaf_step(
            operator="ScanOrdinary",
            node_path=path,
            logical_operator="ScanOrdinary",
            relation=relation,
        )
        for path, relation in ordinary
    )
    strict_steps = tuple(
        step
        for step in steps
        if step.get("constructor") == "OrdinaryOp"
        and step.get("strict_h6") is True
    )
    observed_selected = tuple(
        step
        for step in strict_steps
        if step.get("h6_scope") == "selected_implementation"
    )
    observed_ordinary = tuple(
        step for step in strict_steps if step.get("h6_scope") == "ordinary_scan"
    )
    expected_paired: list[Mapping[str, Any]] = []
    adjacency_valid = True
    for index, step in enumerate(steps):
        if step.get("constructor") != "Transfer" or not str(
            step.get("rule") or ""
        ).startswith("ir:"):
            continue
        expected = _strict_h6_transfer_step(step)
        expected_paired.append(expected)
        if index + 1 >= len(steps) or _canonical_value(
            steps[index + 1]
        ) != _canonical_value(expected):
            adjacency_valid = False
    observed_paired = tuple(
        step
        for step in strict_steps
        if step.get("h6_scope") == "finite_ir_operator"
    )
    reasons: list[str] = []
    if _canonical_value(observed_selected) != _canonical_value(expected_selected):
        reasons.append("strict_h6_selected_implementation_mismatch")
    if _canonical_value(observed_ordinary) != _canonical_value(expected_ordinary):
        reasons.append("strict_h6_ordinary_scan_mismatch")
    if _canonical_value(observed_paired) != _canonical_value(
        tuple(expected_paired)
    ):
        reasons.append("strict_h6_operator_trace_mismatch")
    if not adjacency_valid:
        reasons.append("strict_h6_transfer_adjacency_mismatch")
    if len(strict_steps) != (
        len(expected_selected) + len(expected_ordinary) + len(expected_paired)
    ):
        reasons.append("strict_h6_cardinality_mismatch")
    if any(step.get("preserves_sigma") is not True for step in strict_steps):
        reasons.append("strict_h6_preservation_derivation_mismatch")
    return tuple(reasons)


def _strict_constructor_shape_reasons(
    steps: Sequence[Mapping[str, Any]],
    expected_occurrence_ids: Iterable[str],
    *,
    plan: Any,
    target: Any,
) -> tuple[str, ...]:
    """Reject missing/duplicate/extra occurrence consumption and malformed paths."""

    reasons: list[str] = []
    expected = tuple(sorted(set(str(item) for item in expected_occurrence_ids)))
    occurrence_rules: list[str] = []
    traversal_indices: set[int] = set()
    observed_ir_paths: dict[tuple[str, ...], str] = {}
    target_kinds: set[str] = set()
    if isinstance(target, Mapping):
        for item in target.values():
            if isinstance(item, Mapping) and item.get("target_kind"):
                target_kinds.add(str(item["target_kind"]))
            elif isinstance(item, str) and item:
                target_kinds.add(item)
    for step in steps:
        constructor = str(step.get("constructor") or "")
        if constructor in {"ExactLeaf", "CandidateLeaf"}:
            if str(step.get("target_kind") or "") not in target_kinds:
                reasons.append("leaf_target_binding_mismatch")
        if constructor != "Transfer":
            continue
        rule = str(step.get("rule") or "")
        if rule.startswith("occurrence_admitted:"):
            occurrence_rules.append(rule.split(":", 1)[1])
        if rule.startswith("ir:"):
            path = step.get("node_path")
            index = step.get("traversal_index")
            if not isinstance(path, (list, tuple)) or not path or not all(
                isinstance(item, str) and item for item in path
            ):
                reasons.append("ir_transfer_path_invalid")
            if not isinstance(index, int) or index in traversal_indices:
                reasons.append("ir_transfer_index_invalid")
            elif isinstance(index, int):
                traversal_indices.add(index)
            if isinstance(path, (list, tuple)) and all(isinstance(item, str) and item for item in path):
                observed_ir_paths[tuple(path)] = str(step.get("operator") or "")
    if expected:
        if tuple(sorted(occurrence_rules)) != expected or len(occurrence_rules) != len(expected):
            reasons.append("occurrence_consumption_mismatch")
    elif occurrence_rules:
        reasons.append("unexpected_occurrence_consumption")
    actual_ir_paths = _finite_ir_operator_paths(plan)
    if actual_ir_paths is None:
        reasons.append("actual_plan_not_finite_ir")
    else:
        if set(observed_ir_paths) != set(actual_ir_paths):
            reasons.append("ir_transfer_consumption_mismatch")
        for path, expected_operator in actual_ir_paths.items():
            if observed_ir_paths.get(path) != expected_operator:
                reasons.append("ir_transfer_actual_operator_mismatch")
    reasons.extend(_strict_h6_trace_reasons(steps, plan=plan))
    return tuple(reasons)


def _artifact_step_evidence_reasons(
    steps: Sequence[Mapping[str, Any]],
    *,
    all_facts: Mapping[str, Any],
    pending_dynamic_obligations: Sequence[DynamicObligation],
) -> tuple[str, ...]:
    """Bind ArtifactValid to validator facts and unresolved H2 recipes."""

    reasons: list[str] = []
    pending_kinds = {item.kind for item in pending_dynamic_obligations}
    artifact_seen = False
    for step in steps:
        if step.get("constructor") != "ArtifactValid":
            continue
        artifact_seen = True
        artifact_ids = step.get("artifact_ids")
        if not isinstance(artifact_ids, Mapping):
            reasons.append("artifact_step_missing_ids")
            continue
        for artifact_id in artifact_ids.values():
            subject = str(artifact_id)
            if not any(
                fact.accepted
                and fact.kind == "artifact_validation"
                and fact.subject_digest == subject
                for fact in all_facts.values()
            ):
                reasons.append("artifact_step_gamma_evidence_missing")
    if artifact_seen and not {
        "artifact_freshness",
        "artifact_context",
        "artifact_toctou",
    }.issubset(pending_kinds):
        reasons.append("artifact_step_dynamic_h2_recipe_missing")
    return tuple(reasons)


def _finite_ir_operator_paths(plan: Any) -> Mapping[tuple[str, ...], str] | None:
    """Return the exact postorder operator/path set for the finite IR."""

    if not hasattr(plan, "to_dict") or not callable(plan.to_dict):
        return None
    try:
        root = plan.to_dict()
    except Exception:
        return None
    if not isinstance(root, Mapping):
        return None
    unary = {
        "Select",
        "Project",
        "DuplicateCollapse",
        "UnsafeExpr",
        "Boundary",
        "RCheck",
        "BarrierEnforce",
        "ValidationGate",
        "SortEnforce",
        "Materialize",
        "Root",
    }
    leaves = {"ScanProtected", "ScanOrdinary"}
    paths: dict[tuple[str, ...], str] = {}

    def visit(node: Mapping[str, Any], path: tuple[str, ...]) -> bool:
        name = str(node.get("node") or "")
        if name in leaves:
            return True
        if name in unary:
            child = node.get("source")
            if not isinstance(child, Mapping) or not visit(child, (*path, "source")):
                return False
        elif name == "InnerJoin":
            left, right = node.get("left"), node.get("right")
            if not isinstance(left, Mapping) or not isinstance(right, Mapping):
                return False
            if not visit(left, (*path, "left")) or not visit(right, (*path, "right")):
                return False
        elif name == "UnionTagged":
            branches = node.get("branches")
            if not isinstance(branches, (list, tuple)) or not branches:
                return False
            for index, branch in enumerate(branches):
                if not isinstance(branch, Mapping) or not visit(branch, (*path, f"branches[{index}]")):
                    return False
        else:
            return False
        paths[path] = name
        return True

    return paths if visit(root, ("root",)) else None
