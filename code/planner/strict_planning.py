"""Strict planning entry point for the new certificate/execution boundary.

Legacy ``plan_query`` remains readable for historical record audits and old
diagnostic studies.  New AdmissionFirst callers use this module: it requires
typed Gamma for every occurrence, emits one immutable draft, constructs a
strict certificate envelope, and returns only a conditionally checked (still
non-executable) plan.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields, is_dataclass, replace
from functools import lru_cache
import copyreg
import hashlib
import json
from typing import Any, Callable, Mapping
import re
import weakref
from types import CodeType, FunctionType, MappingProxyType, ModuleType

from caprls_core.baselines import ADMISSION_FIRST_MODE

from .certificate_envelope import (
    CertificateEnvelope,
    CertificateReplayError,
    CertificateReplayResult,
    DynamicObligation,
    SemanticReplayContext,
    build_certificate_envelope,
    canonical_registry_digest,
    canonical_rho_binding,
    canonical_target_binding,
    conditionally_checked_from_replay,
    derive_strict_certificate_steps,
    derive_typed_admission_bindings,
    replay_certificate_envelope,
    semantic_continuation_scope_for_plan,
    _digest as _certificate_digest,
    _is_minted_replay_result,
)
from .contracts import (
    GammaFact,
    GammaSnapshot,
    TemplateDefinition,
    default_template_definitions,
    template_definition,
)
from .core import (
    ArtifactMetadata,
    ContractChecker,
    CostEstimator,
    TemplateRegistry,
    normalize_planner_mode,
)
from .emit import StrictArtifactExpectation, TemplateLoweringError, emit_sql
from .execution import (
    BoundParameter,
    ConditionallyCheckedPlan,
    ContinuationTemplate,
    ExecutableDraft,
    ExecutionIdentityError,
    SessionContract,
    _has_verified_static_replay,
)
from .ir import Root
from .query import (
    PlanningQuery,
    QueryPlanResult,
    derive_occurrence_goals,
    plan_query,
)
from .state import sigma_from_dict
from .identity_observation import Observation, capture_observation

# These source-controlled schemas, rather than the mere presence of a
# dataclass/to_dict method, delimit the observation fast path.
from . import contracts as _identity_contracts
from . import core as _identity_core
from . import emit as _identity_emit
from . import execution as _identity_execution
from . import features as _identity_features
from . import ir as _identity_ir
from . import obligations as _identity_obligations
from . import query as _identity_query
from . import state as _identity_state
from . import transfer as _identity_transfer
from . import certificate_envelope as _identity_envelope


# Strict execution currently supports only the identity continuation.  The
# finite IR emitter owns the entire statement; allowing a caller-supplied
# wrapper to add a scan/join/union would make full-SQL identity a tautology.
# A future typed ContinuationAST registry may add reviewed shapes explicitly.
_STRICT_IDENTITY_CONTINUATION_TEMPLATE = "{{CORE_SQL}}"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROMOTABLE_REGISTRY_EVIDENCE_ROLES = frozenset(
    {"source_controlled_canonical", "production_manifest"}
)


@dataclass(frozen=True)
class StrictPlanningRequest:
    query: PlanningQuery
    session_contract: SessionContract
    continuation: ContinuationTemplate
    registry_version: str
    typed_params: tuple[BoundParameter, ...] = ()


@dataclass(frozen=True)
class ForcedRootProvenance:
    """Strictly sealed identity of one freshly admitted root-frontier member."""

    occurrence_id: str
    template_id: str
    admitted_candidate_inventory: tuple[tuple[str, str], ...]
    admitted_candidate_inventory_digest: str
    registry_digest: str
    registry_scope_identity: str
    registry_manifest_digest: str
    registry_evidence_role: str
    identity_digest: str
    _construction_token: object | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "occurrence_id": self.occurrence_id,
            "template_id": self.template_id,
            "admitted_candidate_inventory": [
                {"template_id": template_id, "candidate_digest": candidate_digest}
                for template_id, candidate_digest in self.admitted_candidate_inventory
            ],
            "admitted_candidate_inventory_digest": self.admitted_candidate_inventory_digest,
            "registry_digest": self.registry_digest,
            "registry_scope_identity": self.registry_scope_identity,
            "registry_manifest_digest": self.registry_manifest_digest,
            "registry_evidence_role": self.registry_evidence_role,
            "identity_digest": self.identity_digest,
        }


@dataclass(frozen=True)
class ForcedRootAttemptProvenance:
    """Sealed outcome of one exact forced-frontier completion attempt.

    Unlike :class:`ForcedRootProvenance`, this receipt may describe a root
    which was freshly admitted but then failed deterministic root closure,
    lowering, or certificate replay.  It is deliberately separate so the
    success-only strict-result bridge remains unchanged.
    """

    occurrence_id: str
    template_id: str
    admitted_candidate_inventory: tuple[tuple[str, str], ...]
    admitted_candidate_inventory_digest: str
    registry_digest: str
    registry_scope_identity: str
    registry_manifest_digest: str
    registry_evidence_role: str
    outcome_status: str
    rejection_reasons_digest: str
    identity_digest: str
    _construction_token: object | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "occurrence_id": self.occurrence_id,
            "template_id": self.template_id,
            "admitted_candidate_inventory": [
                {"template_id": template_id, "candidate_digest": candidate_digest}
                for template_id, candidate_digest in self.admitted_candidate_inventory
            ],
            "admitted_candidate_inventory_digest": self.admitted_candidate_inventory_digest,
            "registry_digest": self.registry_digest,
            "registry_scope_identity": self.registry_scope_identity,
            "registry_manifest_digest": self.registry_manifest_digest,
            "registry_evidence_role": self.registry_evidence_role,
            "outcome_status": self.outcome_status,
            "rejection_reasons_digest": self.rejection_reasons_digest,
            "identity_digest": self.identity_digest,
        }


@dataclass(frozen=True)
class StrictPlanningResult:
    query_result: QueryPlanResult | None
    draft: ExecutableDraft | None
    envelope: CertificateEnvelope | None
    replay: CertificateReplayResult | None
    conditional_plan: ConditionallyCheckedPlan | None
    rejection_reasons: tuple[str, ...] = ()
    forced_root_provenance: ForcedRootProvenance | None = None
    forced_root_attempt_provenance: ForcedRootAttemptProvenance | None = None
    _strict_result_capability: object | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )
    _strict_result_identity_seal: str = field(
        default="", init=False, repr=False, compare=False
    )
    _forced_root_attempt_capability: object | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    @property
    def ok(self) -> bool:
        return self.conditional_plan is not None and not self.rejection_reasons


@dataclass(frozen=True)
class StrictRegistryScope:
    """Adapter-minted identity for one complete non-default registry portfolio.

    The public forced-root API never treats a caller-selected registry subset as
    complete merely because it has more than one member.  Default ``None``
    registry uses the source-controlled canonical catalog.  Any custom
    portfolio must instead arrive with this owner-bound scope, minted by the
    trusted manifest/receipt adapter after checking its expected inventory and
    digest.
    """

    registry: TemplateRegistry = field(repr=False, compare=False)
    scope_id: str
    manifest_digest: str
    registry_digest: str
    template_ids: tuple[str, ...]
    evidence_role: str
    owner_identity_digest: str | None
    identity_digest: str
    artifact_evidence_bindings: tuple[tuple[str, str, str], ...] = ()
    _construction_token: object | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )


_STRICT_RESULT_CAPABILITY = object()
_STRICT_REGISTRY_SCOPE_CAPABILITY = object()
_FORCED_ROOT_PROVENANCE_CAPABILITY = object()
_FORCED_ROOT_ATTEMPT_PROVENANCE_CAPABILITY = object()
_FORCED_ROOT_ATTEMPT_RESULT_CAPABILITY = object()
_VERIFIED_STRICT_RESULTS: dict[
    int,
    tuple[
        weakref.ReferenceType[StrictPlanningResult],
        QueryPlanResult,
        ExecutableDraft,
        CertificateEnvelope,
        CertificateReplayResult,
        ConditionallyCheckedPlan,
        str,
    ],
] = {}
_VERIFIED_STRICT_REGISTRY_SCOPES: dict[
    int,
    tuple[
        weakref.ReferenceType[StrictRegistryScope],
        TemplateRegistry,
        str,
        weakref.ReferenceType[Any] | None,
        Callable[[Any], str] | None,
    ],
] = {}
_VERIFIED_FORCED_ROOT_ATTEMPTS: dict[
    int,
    tuple[
        weakref.ReferenceType[StrictPlanningResult],
        QueryPlanResult | None,
        ExecutableDraft | None,
        CertificateEnvelope | None,
        CertificateReplayResult | None,
        ConditionallyCheckedPlan | None,
        ForcedRootAttemptProvenance,
        str,
    ],
] = {}


@dataclass(frozen=True)
class _StrictResultObservation:
    graph: Observation
    root_edges: tuple[object, ...]
    global_bindings: tuple[tuple[dict[str, Any], str, object], ...]
    function_states: tuple[tuple[FunctionType, tuple[object, ...]], ...]
    continuation_registry: object
    continuation_id: str
    continuation_definition: object
    # The reusable forced seal belongs to this exact issuance record.  A
    # registry replacement, even with the same children, must use the full
    # payload checker rather than compare a newly supplied seal to itself.
    forced_attempt_registration: object


# The owning result is represented only by this weak reference. Observations
# may retain its children, but must not retain the result itself or a callback
# bound to it; otherwise the registration's weak cleanup would never run.
_STRICT_RESULT_OBSERVATIONS: dict[
    int, tuple[weakref.ReferenceType[StrictPlanningResult], _StrictResultObservation]
] = {}


_STRICT_OBSERVATION_ROOT_FIELDS = (
    "query_result", "draft", "envelope", "replay", "conditional_plan",
    "rejection_reasons", "forced_root_provenance", "forced_root_attempt_provenance",
)
_OBSERVATION_ABSENT_GLOBAL = object()


class _UnclosedObservationSource:
    """Unsupported standalone closure; deliberately outside the type schema."""


def _strict_observation_code_names(code: CodeType) -> frozenset[str]:
    names = set(code.co_names)
    for constant in code.co_consts:
        if type(constant) is CodeType:
            names.update(_strict_observation_code_names(constant))
    return frozenset(names)


def _strict_observation_types() -> tuple[type, ...]:
    return (
        ForcedRootProvenance, ForcedRootAttemptProvenance,
        _identity_contracts.PolicyAccessTarget,
        _identity_contracts.ImplementationTargetBinding,
        _identity_contracts.AuthorizationViewBinding,
        _identity_contracts.NativeRLSSessionContract,
        _identity_contracts.GammaFact, _identity_contracts.GammaSnapshot,
        _identity_contracts.MemoGoal, _identity_contracts.AdmissionDecision,
        _identity_contracts.TemplateDefinition,
        _identity_core.TemplateSpec, _identity_core.ArtifactMetadata,
        _identity_core.ParentRequirement, _identity_core.CostInputs,
        _identity_core.PlanningProblem, _identity_core.ContractCheck,
        _identity_core.CandidatePlan, _identity_core.PlanResult,
        _identity_emit.EmitContext, _identity_emit.ArtifactDependencyIdentity,
        _identity_emit.ArtifactDependencyExpectation,
        _identity_emit.ArtifactComponentBinding,
        _identity_emit.StrictArtifactExpectation,
        _identity_emit.ArtifactValidationRecipe,
        _identity_execution.DynamicObligation, _identity_execution.BoundParameter,
        _identity_execution.SessionContract, _identity_execution.ContinuationTemplate,
        _identity_execution.ContinuationDefinition,
        _identity_execution.ExecutableDraft,
        _identity_execution.ConditionallyCheckedPlan,
        _identity_execution._StaticReplayCapability,
        _identity_features.PlannerFeatureFlags,
        _identity_ir.ScanProtected, _identity_ir.ScanOrdinary,
        _identity_ir.Select, _identity_ir.Project, _identity_ir.InnerJoin,
        _identity_ir.UnionTagged, _identity_ir.DuplicateCollapse,
        _identity_ir.UnsafeExpr, _identity_ir.Boundary, _identity_ir.RCheck,
        _identity_ir.BarrierEnforce, _identity_ir.ValidationGate,
        _identity_ir.SortEnforce, _identity_ir.Materialize, _identity_ir.Root,
        _identity_obligations.LogicalBasis, _identity_obligations.LogicalObligation,
        _identity_obligations.ResidualDeadline, _identity_obligations.LineageTransform,
        _identity_obligations.ObligationGraph,
        _identity_query.OccurrenceGoal, _identity_query.QueryPlanResult,
        _identity_query.SearchEvidence,
        _identity_state.BasisElement, _identity_state.Need,
        _identity_state.RIDCarrierBinding, _identity_state.LineageCarrierBinding,
        _identity_state.RecoverabilityContext, _identity_state.RecoverabilityWitness,
        _identity_state.ResidualRecord, _identity_state.Sigma,
        _identity_transfer.EnforcerInsertion, _identity_transfer.RootClosure,
        _identity_envelope.CertificateEnvelope,
        _identity_envelope.CertificateReplayResult,
    )


def _strict_observation_roots(result: StrictPlanningResult) -> tuple[object, ...]:
    return tuple(object.__getattribute__(result, name) for name in _STRICT_OBSERVATION_ROOT_FIELDS)


def _strict_observation_function_state(function: FunctionType) -> tuple[object, ...]:
    return (
        function.__code__, function.__defaults__, function.__kwdefaults__,
        function.__closure__, function.__dict__, function.__annotations__,
    )


def _strict_observation_class_source(cls: type) -> tuple[object, ...]:
    result: list[object] = [cls.__mro__, *vars(cls).keys(), *vars(cls).values()]
    catalog = vars(cls).get("__dataclass_fields__", {})
    for name, item in catalog.items():
        result.extend((name, item, item.name, item._field_type))
    return tuple(result)


def _strict_observation_pins_intact(
    bindings: tuple[tuple[dict[str, Any], str, object], ...],
    functions: tuple[tuple[FunctionType, tuple[object, ...]], ...],
) -> bool:
    for namespace, name, value in bindings:
        if value is _OBSERVATION_ABSENT_GLOBAL:
            if name in namespace:
                return False
        elif name not in namespace or namespace[name] is not value:
            return False
    return all(
        all(actual is old for actual, old in zip(_strict_observation_function_state(function), expected))
        for function, expected in functions
    )


def _strict_observation_class_pins_intact() -> bool:
    for cls, expected in _STRICT_OBSERVATION_CLASS_BASELINE:
        current = _strict_observation_class_source(cls)
        if len(current) != len(expected) or any(a is not b for a, b in zip(current, expected)):
            return False
    return True


def _strict_observation_source_dependencies(
    trusted_types: tuple[type, ...],
) -> tuple[
    tuple[tuple[dict[str, Any], str, object], ...],
    tuple[tuple[FunctionType, tuple[object, ...]], ...],
    tuple[object, ...],
]:
    """Pin finite serializers' source helpers without walking module globals.

    Class descriptors/function state are also checked by the graph. Here we
    bind the helper names and constants those controlled methods read. The
    interpreter/standard library are trusted implementation, as in the full
    checker. A name resolved through trusted builtins must remain absent from
    its function globals; adding a module shadow changes that resolution.
    Ordinary replacement of used module entry points is also detected.
    Request-local provenance registries are checked separately on every hit.
    """

    queue: list[FunctionType] = []
    behavior_methods: set[int] = set()
    for cls in (*trusted_types, StrictPlanningResult):
        for name, value in vars(cls).items():
            if name.startswith("__") and name != "__post_init__":
                continue
            if type(value) is FunctionType:
                queue.append(value)
                behavior_methods.add(id(value))
            elif type(value) in (staticmethod, classmethod):
                queue.append(value.__func__)
                behavior_methods.add(id(value.__func__))
            elif type(value) is property:
                functions = tuple(item for item in (value.fget, value.fset, value.fdel) if item is not None)
                queue.extend(functions)
                behavior_methods.update(id(item) for item in functions)
            elif type(value).__module__ == "functools" and hasattr(value, "func"):
                queue.append(value.func)
                behavior_methods.add(id(value.func))
    # These ordinary helpers are not necessarily methods of a graph node.
    entry_points = (
        _strict_identity_value, _strict_result_identity_payload,
        _forced_attempt_result_identity_payload,
        _identity_envelope._canonical_value,
    )
    queue.extend(entry_points)
    seen: set[int] = set()
    bindings: dict[tuple[int, str], tuple[dict[str, Any], str, object]] = {}
    for function in entry_points:
        namespace = function.__globals__
        bindings[(id(namespace), function.__name__)] = (
            namespace, function.__name__, function,
        )
    states: list[tuple[FunctionType, tuple[object, ...]]] = []
    data_roots: list[object] = []
    while queue:
        function = queue.pop()
        if type(function) is not FunctionType or id(function) in seen:
            continue
        seen.add(id(function))
        state = _strict_observation_function_state(function)
        states.append((function, state))
        # Actual typed nodes already observe their class methods, including
        # defaults/closures. Only standalone helper data needs another root.
        if id(function) not in behavior_methods:
            data_roots.extend((function.__defaults__, function.__kwdefaults__, function.__dict__, function.__annotations__))
            if function.__closure__:
                # Class behavior closures are observed by the DAG. A new
                # standalone closure would need its own environment proof;
                # preserve the full checker instead of trusting cell identity.
                data_roots.append(_UnclosedObservationSource())
        if function.__closure__:
            for cell in function.__closure__:
                try:
                    content = cell.cell_contents
                except ValueError:
                    continue
                if type(content) is FunctionType:
                    queue.append(content)
        namespace = function.__globals__
        bindings[(id(namespace), "__builtins__")] = (
            namespace, "__builtins__",
            namespace.get("__builtins__", _OBSERVATION_ABSENT_GLOBAL),
        )
        code_names = _strict_observation_code_names(function.__code__)
        for name in code_names:
            if name not in namespace:
                # Absence is a dependency too: LOAD_GLOBAL can currently
                # resolve bool/tuple/etc. from builtins, then be shadowed.
                bindings[(id(namespace), name)] = (
                    namespace, name, _OBSERVATION_ABSENT_GLOBAL,
                )
                continue
            value = namespace[name]
            bindings[(id(namespace), name)] = (namespace, name, value)
            if type(value) is FunctionType and value.__module__.startswith("planner."):
                queue.append(value)
            elif type(value).__module__ == "functools" and hasattr(value, "__wrapped__"):
                wrapped = value.__wrapped__
                if type(wrapped) is FunctionType and wrapped.__module__.startswith("planner."):
                    metadata = vars(value)
                    bindings[(id(metadata), "__wrapped__")] = (metadata, "__wrapped__", wrapped)
                    queue.append(wrapped)
            elif type(value) is ModuleType:
                # Attribute loads on an imported helper module are finite in
                # these source-controlled methods; avoid traversing the module.
                for attribute in code_names:
                    module_namespace = vars(value)
                    item = module_namespace.get(attribute, _OBSERVATION_ABSENT_GLOBAL)
                    bindings[(id(module_namespace), attribute)] = (
                        module_namespace, attribute, item,
                    )
                    if type(item) is FunctionType and item.__module__.startswith("planner."):
                        queue.append(item)
    externally_checked = {
        (id(vars(_identity_envelope)), "_VERIFIED_REPLAY_RESULTS"),
        (id(vars(_identity_execution)), "_VERIFIED_CONDITIONAL_PLANS"),
        # Only the selected ID is read by this draft; its exact immutable
        # definition, table binding and class behavior are checked per hit.
        (id(vars(_identity_execution)), "APPROVED_CONTINUATION_DEFINITIONS"),
    }
    for namespace, name, value in bindings.values():
        if (
            type(value) in (dict, list, tuple, set, frozenset, MappingProxyType)
            and (id(namespace), name) not in externally_checked
            # The interpreter's builtin table is trusted, not an application
            # data graph. Its binding and module-global shadow absences above
            # remain pinned, without traversing the interpreter namespace.
            and name != "__builtins__"
        ):
            # The pointer alone does not observe an in-place policy/schema
            # table change. Keep the actual finite contents in the same DAG.
            data_roots.append(value)
    return tuple(bindings.values()), tuple(states), tuple(data_roots)


def _capture_strict_result_observation(result: StrictPlanningResult) -> _StrictResultObservation | None:
    """Observe only after full sealing, at the synchronous internal mint edge.

    Like the existing checker, this does not provide a concurrent-mutation
    transaction. No callback/await is introduced between seal and capture.
    A graph miss keeps using the full checker; it does not re-trust changed
    behavior or normalize a changed object into a new fast-path authority.
    """

    try:
        roots = _strict_observation_roots(result)
        trusted = _STRICT_OBSERVATION_TRUSTED_TYPES
        bindings, functions, source_data = _STRICT_OBSERVATION_SOURCE_BASELINE
        if not _strict_observation_pins_intact(bindings, functions):
            return None
        if not _strict_observation_class_pins_intact():
            return None
        graph = capture_observation(roots + source_data, trusted_types=trusted, forbidden_ids=(id(result),))
        if graph is None:
            return None
        draft = result.draft
        assert draft is not None
        registry = _identity_execution.APPROVED_CONTINUATION_DEFINITIONS
        definition = registry.get(draft.continuation_id)
        if type(definition) is not _identity_execution.ContinuationDefinition:
            return None
        forced_registration = None
        if result.forced_root_attempt_provenance is not None:
            forced_registration = _VERIFIED_FORCED_ROOT_ATTEMPTS.get(id(result))
            if (
                forced_registration is None
                or forced_registration[0]() is not result
                or any(
                    forced_registration[index] is not child
                    for index, child in enumerate(roots[:5], 1)
                )
                or forced_registration[6] is not result.forced_root_attempt_provenance
            ):
                # Successful forced results are observed only after their
                # first complete forced-payload validation and registration.
                return None
        return _StrictResultObservation(
            graph, roots, bindings, functions, registry,
            draft.continuation_id, definition, forced_registration,
        )
    except Exception:
        # An unsupported observation must not change successful full sealing.
        return None


def _strict_result_observation_matches(result: StrictPlanningResult, cached: _StrictResultObservation) -> bool:
    try:
        roots = _strict_observation_roots(result)
        if any(current is not old for current, old in zip(roots, cached.root_edges)):
            return False
        if not _is_minted_replay_result(result.replay):
            return False
        if not _identity_execution._is_registered_verified_conditional_plan(result.conditional_plan):
            return False
        registry = _identity_execution.APPROVED_CONTINUATION_DEFINITIONS
        if registry is not cached.continuation_registry or registry.get(cached.continuation_id) is not cached.continuation_definition:
            return False
        if not _strict_observation_pins_intact(cached.global_bindings, cached.function_states):
            return False
        if not _strict_observation_class_pins_intact():
            return False
        return cached.graph.unchanged()
    except Exception:
        return False


def _strict_identity_value(value: Any) -> Any:
    if value is None or value.__class__ in {str, int, float, bool}:
        return value
    if isinstance(value, Mapping):
        pairs = [
            (_strict_identity_value(key), _strict_identity_value(item))
            for key, item in value.items()
        ]
        return {
            "__mapping__": sorted(
                pairs,
                key=lambda item: _stable_digest(item[0]),
            )
        }
    if isinstance(value, (tuple, list)):
        return {
            "__sequence_type__": value.__class__.__name__,
            "items": [_strict_identity_value(item) for item in value],
        }
    if isinstance(value, (set, frozenset)):
        items = [_strict_identity_value(item) for item in value]
        return {
            "__set_type__": value.__class__.__name__,
            "items": sorted(items, key=_stable_digest),
        }
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return {
            "__type__": value.__class__.__qualname__,
            "value": _strict_identity_value(to_dict()),
        }
    if is_dataclass(value):
        return {
            "__type__": value.__class__.__qualname__,
            "fields": {
                item.name: _strict_identity_value(getattr(value, item.name))
                for item in fields(value)
                if not item.name.startswith("_")
            },
        }
    raise ExecutionIdentityError(
        "strict planning identity contains an unsupported value: "
        + value.__class__.__name__
    )


def _strict_result_identity_payload(
    result: StrictPlanningResult,
) -> dict[str, Any]:
    if result.__class__ is not StrictPlanningResult:
        raise ExecutionIdentityError(
            "strict result identity requires an exact StrictPlanningResult"
        )
    query_result = result.query_result
    draft = result.draft
    envelope = result.envelope
    replay = result.replay
    conditional = result.conditional_plan
    if (
        query_result.__class__ is not QueryPlanResult
        or draft.__class__ is not ExecutableDraft
        or envelope.__class__ is not CertificateEnvelope
        or replay.__class__ is not CertificateReplayResult
        or conditional.__class__ is not ConditionallyCheckedPlan
        or result.rejection_reasons
    ):
        raise ExecutionIdentityError(
            "strict result does not contain the exact successful planning chain"
        )
    try:
        draft.assert_identity_intact()
        envelope.__post_init__()
        replay.__post_init__()
        conditional.__post_init__()
        query_payload = query_result.to_dict()
    except Exception as exc:
        raise ExecutionIdentityError(
            "strict result nested identity is invalid"
        ) from exc
    if (
        not query_result.ok
        or query_result.certificate is None
        or not query_result.emitted_sql
        or not replay.ok
        or replay.reasons
        or not _is_minted_replay_result(replay)
        or not _has_verified_static_replay(conditional)
        or conditional.draft is not draft
        or replay.draft_identity_digest != draft.identity_digest
        or envelope.exact_sql_digest != draft.exact_sql_digest
        or envelope.sql_ast_digest != draft.full_ast_digest
        or envelope.registry_digest != draft.registry_digest
        or envelope.plan_digest != _certificate_digest(query_result.bound_ir)
        or envelope.emit_context_digest
        != _certificate_digest(query_result.emit_context)
        or draft.bound_ir_digest
        != _stable_digest(query_result.bound_ir.to_dict())
        or replay.static_certificate_digest != envelope.digest
        or conditional.static_certificate_digest
        != replay.static_certificate_digest
        or conditional.conditional_sigma_digest
        != replay.conditional_sigma_digest
        or len(replay.pending_dynamic_obligations)
        != len(conditional.pending_dynamic_obligations)
        or any(
            left is not right
            for left, right in zip(
                replay.pending_dynamic_obligations,
                conditional.pending_dynamic_obligations,
            )
        )
    ):
        raise ExecutionIdentityError(
            "strict result planning chain bindings do not replay"
        )
    return {
        "query_result": _strict_identity_value(query_payload),
        "query_emit_context": _strict_identity_value(query_result.emit_context),
        "draft": {
            "identity_digest": draft.identity_digest,
            "core_sql": draft.core_sql,
            "sql_text": draft.sql_text,
            "parameter_digest": draft.parameter_digest,
            "session_digest": draft.session_contract.digest,
        },
        "envelope": _strict_identity_value(envelope.to_dict()),
        "replay": {
            "ok": replay.ok,
            "reasons": replay.reasons,
            "static_certificate_digest": replay.static_certificate_digest,
            "conditional_sigma_digest": replay.conditional_sigma_digest,
            "draft_identity_digest": replay.draft_identity_digest,
            "pending_dynamic_obligations": [
                item.to_dict()
                for item in replay.pending_dynamic_obligations
            ],
            "h_obligations": replay.h_obligations,
        },
        "conditional_plan": {
            "identity_digest": conditional.identity_digest,
            "draft_identity_digest": conditional.draft.identity_digest,
            "pending_dynamic_obligations": [
                item.to_dict()
                for item in conditional.pending_dynamic_obligations
            ],
        },
        "forced_root_provenance": (
            None
            if result.forced_root_provenance is None
            else result.forced_root_provenance.to_dict()
        ),
        "forced_root_attempt_provenance": (
            None
            if result.forced_root_attempt_provenance is None
            else result.forced_root_attempt_provenance.to_dict()
        ),
        "rejection_reasons": result.rejection_reasons,
    }


def _strict_result_identity_seal(result: StrictPlanningResult) -> str:
    return _stable_digest(
        {"strict_planning_result": _strict_result_identity_payload(result)}
    )


def _mint_strict_planning_result(
    *,
    query_result: QueryPlanResult,
    draft: ExecutableDraft,
    envelope: CertificateEnvelope,
    replay: CertificateReplayResult,
    conditional_plan: ConditionallyCheckedPlan,
    forced_root_provenance: ForcedRootProvenance | None = None,
    forced_root_attempt_provenance: ForcedRootAttemptProvenance | None = None,
) -> StrictPlanningResult:
    result = StrictPlanningResult(
        query_result=query_result,
        draft=draft,
        envelope=envelope,
        replay=replay,
        conditional_plan=conditional_plan,
        forced_root_provenance=forced_root_provenance,
        forced_root_attempt_provenance=forced_root_attempt_provenance,
    )
    seal = _strict_result_identity_seal(result)
    object.__setattr__(
        result,
        "_strict_result_capability",
        _STRICT_RESULT_CAPABILITY,
    )
    object.__setattr__(result, "_strict_result_identity_seal", seal)
    key = id(result)

    def _drop(reference: weakref.ReferenceType[StrictPlanningResult]) -> None:
        registered = _VERIFIED_STRICT_RESULTS.get(key)
        if registered is not None and registered[0] is reference:
            _VERIFIED_STRICT_RESULTS.pop(key, None)
        observed = _STRICT_RESULT_OBSERVATIONS.get(key)
        if observed is not None and observed[0] is reference:
            _STRICT_RESULT_OBSERVATIONS.pop(key, None)

    reference = weakref.ref(result, _drop)
    _VERIFIED_STRICT_RESULTS[key] = (
        reference,
        query_result,
        draft,
        envelope,
        replay,
        conditional_plan,
        seal,
    )
    if forced_root_attempt_provenance is None:
        observation = _capture_strict_result_observation(result)
        if observation is not None:
            _STRICT_RESULT_OBSERVATIONS[key] = (reference, observation)
    return result


def _require_registered_strict_planning_result(
    result: StrictPlanningResult,
) -> str:
    if result.__class__ is not StrictPlanningResult:
        raise ExecutionIdentityError(
            "strict bridge requires an exact StrictPlanningResult"
        )
    registered = _VERIFIED_STRICT_RESULTS.get(id(result))
    if (
        registered is None
        or registered[0]() is not result
        or registered[1] is not result.query_result
        or registered[2] is not result.draft
        or registered[3] is not result.envelope
        or registered[4] is not result.replay
        or registered[5] is not result.conditional_plan
        or registered[6] != result._strict_result_identity_seal
        or result._strict_result_capability is not _STRICT_RESULT_CAPABILITY
        or not result._strict_result_identity_seal
    ):
        raise ExecutionIdentityError(
            "strict result was not minted by strict_plan_query"
        )
    _require_continuation_refinement_provenance(result)
    observed = _STRICT_RESULT_OBSERVATIONS.get(id(result))
    if (
        observed is not None
        and observed[0]() is result
        and _strict_result_observation_matches(result, observed[1])
    ):
        return result._strict_result_identity_seal
    current = _strict_result_identity_seal(result)
    if current != result._strict_result_identity_seal:
        raise ExecutionIdentityError(
            "strict result identity changed after planning"
        )
    return current


def _require_continuation_refinement_provenance(result: StrictPlanningResult) -> None:
    """New scoped roots retain their proof capabilities at each consumption.

    Unscoped roots use the existing identity observer unchanged. The first
    refinement implementation fully rechecks its local proof provenance;
    no cached schema observation or authorization verdict is inferred here.
    """
    query_result = result.query_result
    if query_result is None:
        return
    for occurrence_id,occurrence in query_result.occurrence_results.items():
        chosen = occurrence.chosen_template
        if chosen is None or chosen.template_id != "barrier_filter_continuation_v1":
            continue
        from .continuation_refinement import require_continuation_refinement
        problem = query_result.effective_occurrence_goals[occurrence_id].problem
        try:
            require_continuation_refinement(problem.continuation_refinement,
                target=problem.logical_target,rid_column=problem.rid_col,
                query_predicate=problem.query_predicate,gamma=problem.gamma_snapshot)
        except (ValueError,TypeError,KeyError) as exc:
            raise ExecutionIdentityError("strict continuation refinement provenance changed") from exc


def _forced_inventory_digest(
    occurrence_id: str,
    inventory: tuple[tuple[str, str], ...],
) -> str:
    return _stable_digest(
        {
            "occurrence_id": occurrence_id,
            "admitted_candidates": [
                {"template_id": template_id, "candidate_digest": candidate_digest}
                for template_id, candidate_digest in inventory
            ],
        }
    )


def _forced_provenance_identity(
    *,
    occurrence_id: str,
    template_id: str,
    admitted_candidate_inventory_digest: str,
    registry_digest: str,
    registry_scope_identity: str,
    registry_manifest_digest: str,
    registry_evidence_role: str,
) -> str:
    return _stable_digest(
        {
            "occurrence_id": occurrence_id,
            "template_id": template_id,
            "admitted_candidate_inventory_digest": admitted_candidate_inventory_digest,
            "registry_digest": registry_digest,
            "registry_scope_identity": registry_scope_identity,
            "registry_manifest_digest": registry_manifest_digest,
            "registry_evidence_role": registry_evidence_role,
        }
    )


def _mint_forced_root_provenance(
    *,
    occurrence_id: str,
    template_id: str,
    admitted_candidates: tuple[Any, ...],
    registry_digest: str,
    registry_scope_identity: str,
    registry_manifest_digest: str,
    registry_evidence_role: str,
) -> ForcedRootProvenance:
    inventory = tuple(
        sorted(
            (
                str(candidate.template_id),
                _stable_digest(candidate.to_dict()),
            )
            for candidate in admitted_candidates
        )
    )
    if (
        not inventory
        or len({item[0] for item in inventory}) != len(inventory)
        or sum(1 for item in inventory if item[0] == template_id) != 1
    ):
        raise ExecutionIdentityError("forced-root admitted inventory is invalid")
    for label, value in (
        ("registry_digest", registry_digest),
        ("registry_scope_identity", registry_scope_identity),
        ("registry_manifest_digest", registry_manifest_digest),
    ):
        if _SHA256_RE.fullmatch(value) is None:
            raise ExecutionIdentityError(f"forced-root {label} must be a sha256 digest")
    if registry_evidence_role not in {
        "source_controlled_canonical",
        "production_manifest",
        "isolated_test_non_promotable",
    }:
        raise ExecutionIdentityError("forced-root registry evidence role is invalid")
    inventory_digest = _forced_inventory_digest(occurrence_id, inventory)
    identity = _forced_provenance_identity(
        occurrence_id=occurrence_id,
        template_id=template_id,
        admitted_candidate_inventory_digest=inventory_digest,
        registry_digest=registry_digest,
        registry_scope_identity=registry_scope_identity,
        registry_manifest_digest=registry_manifest_digest,
        registry_evidence_role=registry_evidence_role,
    )
    provenance = ForcedRootProvenance(
        occurrence_id=occurrence_id,
        template_id=template_id,
        admitted_candidate_inventory=inventory,
        admitted_candidate_inventory_digest=inventory_digest,
        registry_digest=registry_digest,
        registry_scope_identity=registry_scope_identity,
        registry_manifest_digest=registry_manifest_digest,
        registry_evidence_role=registry_evidence_role,
        identity_digest=identity,
    )
    object.__setattr__(
        provenance,
        "_construction_token",
        _FORCED_ROOT_PROVENANCE_CAPABILITY,
    )
    return provenance


def _require_forced_root_provenance(
    result: StrictPlanningResult,
) -> ForcedRootProvenance:
    """Require a successful strict result minted from a fresh forced frontier."""

    _require_registered_strict_planning_result(result)
    provenance = result.forced_root_provenance
    if (
        provenance is None
        or provenance.__class__ is not ForcedRootProvenance
        or provenance._construction_token is not _FORCED_ROOT_PROVENANCE_CAPABILITY
        or result.query_result is None
        or result.draft is None
    ):
        raise ExecutionIdentityError("strict result is not a forced frontier member")
    occurrence = result.query_result.occurrence_results.get(provenance.occurrence_id)
    chosen = None if occurrence is None else occurrence.chosen_template
    current_inventory = ()
    if occurrence is not None:
        current_inventory = tuple(
            sorted(
                (candidate.template_id, _stable_digest(candidate.to_dict()))
                for candidate in occurrence.candidates
                if candidate.accepted
            )
        )
    current_inventory_digest = _forced_inventory_digest(
        provenance.occurrence_id,
        current_inventory,
    )
    current_identity = _forced_provenance_identity(
        occurrence_id=provenance.occurrence_id,
        template_id=provenance.template_id,
        admitted_candidate_inventory_digest=current_inventory_digest,
        registry_digest=result.draft.registry_digest,
        registry_scope_identity=provenance.registry_scope_identity,
        registry_manifest_digest=provenance.registry_manifest_digest,
        registry_evidence_role=provenance.registry_evidence_role,
    )
    if (
        chosen is None
        or chosen.template_id != provenance.template_id
        or tuple(sorted(result.query_result.effective_occurrence_goals))
        != (provenance.occurrence_id,)
        or provenance.admitted_candidate_inventory != current_inventory
        or provenance.admitted_candidate_inventory_digest != current_inventory_digest
        or provenance.registry_digest != result.draft.registry_digest
        or provenance.identity_digest != current_identity
    ):
        raise ExecutionIdentityError("forced-root provenance no longer binds its result")
    return provenance


def _forced_attempt_provenance_identity(
    *,
    forced: ForcedRootProvenance,
    outcome_status: str,
    rejection_reasons_digest: str,
) -> str:
    return _stable_digest(
        {
            "forced_root_identity": forced.identity_digest,
            "outcome_status": outcome_status,
            "rejection_reasons_digest": rejection_reasons_digest,
        }
    )


def _mint_forced_root_attempt_provenance(
    forced: ForcedRootProvenance,
    *,
    outcome_status: str,
    rejection_reasons: tuple[str, ...],
) -> ForcedRootAttemptProvenance:
    if outcome_status not in {
        "completed",
        "structural_rejection",
        "evidence_failure",
    }:
        raise ExecutionIdentityError("forced-root attempt outcome is invalid")
    if (outcome_status == "completed") != (not rejection_reasons):
        raise ExecutionIdentityError(
            "forced-root attempt outcome and rejection reasons disagree"
        )
    reasons_digest = _stable_digest(
        {"rejection_reasons": list(rejection_reasons)}
    )
    identity = _forced_attempt_provenance_identity(
        forced=forced,
        outcome_status=outcome_status,
        rejection_reasons_digest=reasons_digest,
    )
    attempt = ForcedRootAttemptProvenance(
        occurrence_id=forced.occurrence_id,
        template_id=forced.template_id,
        admitted_candidate_inventory=forced.admitted_candidate_inventory,
        admitted_candidate_inventory_digest=(
            forced.admitted_candidate_inventory_digest
        ),
        registry_digest=forced.registry_digest,
        registry_scope_identity=forced.registry_scope_identity,
        registry_manifest_digest=forced.registry_manifest_digest,
        registry_evidence_role=forced.registry_evidence_role,
        outcome_status=outcome_status,
        rejection_reasons_digest=reasons_digest,
        identity_digest=identity,
    )
    object.__setattr__(
        attempt,
        "_construction_token",
        _FORCED_ROOT_ATTEMPT_PROVENANCE_CAPABILITY,
    )
    return attempt


def _forced_attempt_result_identity_payload(
    result: StrictPlanningResult,
) -> dict[str, Any]:
    query_result = result.query_result
    draft = result.draft
    envelope = result.envelope
    replay = result.replay
    conditional = result.conditional_plan
    if query_result is not None and query_result.__class__ is not QueryPlanResult:
        raise ExecutionIdentityError("forced-root attempt query result is invalid")
    if draft is not None:
        if draft.__class__ is not ExecutableDraft:
            raise ExecutionIdentityError("forced-root attempt draft is invalid")
        draft.assert_identity_intact()
    if envelope is not None:
        if envelope.__class__ is not CertificateEnvelope:
            raise ExecutionIdentityError("forced-root attempt envelope is invalid")
        envelope.__post_init__()
    if replay is not None:
        if replay.__class__ is not CertificateReplayResult:
            raise ExecutionIdentityError("forced-root attempt replay is invalid")
        replay.__post_init__()
    if conditional is not None and conditional.__class__ is not ConditionallyCheckedPlan:
        raise ExecutionIdentityError("forced-root attempt conditional plan is invalid")
    return {
        "query_result": None if query_result is None else query_result.to_dict(),
        "draft": (
            None
            if draft is None
            else {
                "identity_digest": draft.identity_digest,
                "exact_sql_digest": draft.exact_sql_digest,
                "bound_ir_digest": draft.bound_ir_digest,
                "registry_digest": draft.registry_digest,
            }
        ),
        "envelope": None if envelope is None else envelope.to_dict(),
        "replay": (
            None
            if replay is None
            else {
                "ok": replay.ok,
                "reasons": list(replay.reasons),
                "static_certificate_digest": replay.static_certificate_digest,
                "conditional_sigma_digest": replay.conditional_sigma_digest,
                "draft_identity_digest": replay.draft_identity_digest,
                "pending_dynamic_obligations": [
                    item.to_dict() for item in replay.pending_dynamic_obligations
                ],
                "h_obligations": list(replay.h_obligations),
            }
        ),
        "conditional_plan_identity": (
            None if conditional is None else conditional.identity_digest
        ),
        "rejection_reasons": list(result.rejection_reasons),
        "forced_root_provenance": (
            None
            if result.forced_root_provenance is None
            else result.forced_root_provenance.to_dict()
        ),
        "forced_root_attempt_provenance": (
            None
            if result.forced_root_attempt_provenance is None
            else result.forced_root_attempt_provenance.to_dict()
        ),
    }


def _register_forced_root_attempt_result(
    result: StrictPlanningResult,
) -> StrictPlanningResult:
    attempt = result.forced_root_attempt_provenance
    if attempt is None:
        raise ExecutionIdentityError("forced-root attempt provenance is missing")
    seal = _stable_digest(
        {"forced_root_attempt_result": _forced_attempt_result_identity_payload(result)}
    )
    object.__setattr__(
        result,
        "_forced_root_attempt_capability",
        _FORCED_ROOT_ATTEMPT_RESULT_CAPABILITY,
    )
    key = id(result)

    def _drop(reference: weakref.ReferenceType[StrictPlanningResult]) -> None:
        registered = _VERIFIED_FORCED_ROOT_ATTEMPTS.get(key)
        if registered is not None and registered[0] is reference:
            _VERIFIED_FORCED_ROOT_ATTEMPTS.pop(key, None)

    _VERIFIED_FORCED_ROOT_ATTEMPTS[key] = (
        weakref.ref(result, _drop),
        result.query_result,
        result.draft,
        result.envelope,
        result.replay,
        result.conditional_plan,
        attempt,
        seal,
    )
    return result


def _mint_forced_root_failure(
    *,
    query_result: QueryPlanResult | None,
    draft: ExecutableDraft | None,
    envelope: CertificateEnvelope | None,
    replay: CertificateReplayResult | None,
    rejection_reasons: tuple[str, ...],
    forced_root_provenance: ForcedRootProvenance | None,
    structural_rejection: bool,
) -> StrictPlanningResult:
    if forced_root_provenance is None:
        return StrictPlanningResult(
            query_result=query_result,
            draft=draft,
            envelope=envelope,
            replay=replay,
            conditional_plan=None,
            rejection_reasons=rejection_reasons,
        )
    attempt = _mint_forced_root_attempt_provenance(
        forced_root_provenance,
        outcome_status=(
            "structural_rejection" if structural_rejection else "evidence_failure"
        ),
        rejection_reasons=rejection_reasons,
    )
    return _register_forced_root_attempt_result(
        StrictPlanningResult(
            query_result=query_result,
            draft=draft,
            envelope=envelope,
            replay=replay,
            conditional_plan=None,
            rejection_reasons=rejection_reasons,
            forced_root_attempt_provenance=attempt,
        )
    )


def _require_forced_root_attempt_provenance(
    result: StrictPlanningResult,
) -> ForcedRootAttemptProvenance:
    """Require one exact, freshly admitted forced-completion attempt."""

    if result.__class__ is not StrictPlanningResult:
        raise ExecutionIdentityError(
            "forced-root attempt requires an exact StrictPlanningResult"
        )
    registered = _VERIFIED_FORCED_ROOT_ATTEMPTS.get(id(result))
    attempt = result.forced_root_attempt_provenance
    if (
        registered is None
        or registered[0]() is not result
        or registered[1] is not result.query_result
        or registered[2] is not result.draft
        or registered[3] is not result.envelope
        or registered[4] is not result.replay
        or registered[5] is not result.conditional_plan
        or registered[6] is not attempt
        or attempt is None
        or attempt.__class__ is not ForcedRootAttemptProvenance
        or attempt._construction_token
        is not _FORCED_ROOT_ATTEMPT_PROVENANCE_CAPABILITY
        or result._forced_root_attempt_capability
        is not _FORCED_ROOT_ATTEMPT_RESULT_CAPABILITY
    ):
        raise ExecutionIdentityError(
            "forced-root attempt was not minted by strict planning"
        )
    observed = _STRICT_RESULT_OBSERVATIONS.get(id(result))
    if (
        observed is not None
        and observed[0]() is result
        and observed[1].forced_attempt_registration is registered
        and _strict_result_observation_matches(result, observed[1])
    ):
        # This graph was captured after the original full forced payload and
        # observes its values, validators and serializer source.  Reusing the
        # seal avoids repeating value-preserving normalization that would
        # otherwise invalidate the same strict-result graph.  All provenance
        # and structural checks below still run on every call.
        current_seal = registered[7]
    else:
        current_seal = _stable_digest(
            {"forced_root_attempt_result": _forced_attempt_result_identity_payload(result)}
        )
    if current_seal != registered[7]:
        raise ExecutionIdentityError("forced-root attempt identity changed")
    query_result = result.query_result
    occurrence = (
        None
        if query_result is None
        else query_result.occurrence_results.get(attempt.occurrence_id)
    )
    inventory = ()
    if occurrence is not None:
        inventory = tuple(
            sorted(
                (candidate.template_id, _stable_digest(candidate.to_dict()))
                for candidate in occurrence.candidates
                if candidate.accepted
            )
        )
    reasons_digest = _stable_digest(
        {"rejection_reasons": list(result.rejection_reasons)}
    )
    forced_value = ForcedRootProvenance(
        occurrence_id=attempt.occurrence_id,
        template_id=attempt.template_id,
        admitted_candidate_inventory=attempt.admitted_candidate_inventory,
        admitted_candidate_inventory_digest=(
            attempt.admitted_candidate_inventory_digest
        ),
        registry_digest=attempt.registry_digest,
        registry_scope_identity=attempt.registry_scope_identity,
        registry_manifest_digest=attempt.registry_manifest_digest,
        registry_evidence_role=attempt.registry_evidence_role,
        identity_digest=_forced_provenance_identity(
            occurrence_id=attempt.occurrence_id,
            template_id=attempt.template_id,
            admitted_candidate_inventory_digest=(
                attempt.admitted_candidate_inventory_digest
            ),
            registry_digest=attempt.registry_digest,
            registry_scope_identity=attempt.registry_scope_identity,
            registry_manifest_digest=attempt.registry_manifest_digest,
            registry_evidence_role=attempt.registry_evidence_role,
        ),
    )
    current_identity = _forced_attempt_provenance_identity(
        forced=forced_value,
        outcome_status=attempt.outcome_status,
        rejection_reasons_digest=reasons_digest,
    )
    chosen = None if occurrence is None else occurrence.chosen_template
    if (
        query_result is None
        or occurrence is None
        or chosen is None
        or chosen.template_id != attempt.template_id
        or tuple(sorted(query_result.effective_occurrence_goals))
        != (attempt.occurrence_id,)
        or inventory != attempt.admitted_candidate_inventory
        or _forced_inventory_digest(attempt.occurrence_id, inventory)
        != attempt.admitted_candidate_inventory_digest
        or reasons_digest != attempt.rejection_reasons_digest
        or current_identity != attempt.identity_digest
        or (attempt.outcome_status == "completed") != result.ok
        or (attempt.outcome_status == "completed") != (not result.rejection_reasons)
    ):
        raise ExecutionIdentityError(
            "forced-root attempt provenance no longer binds its result"
        )
    if attempt.outcome_status == "completed":
        _require_forced_root_provenance(result)
    return attempt


@dataclass(frozen=True, order=True)
class _StrictArtifactPreflightEntry:
    occurrence_id: str
    required_kind: str
    artifact_id: str
    artifact_metadata_digest: str
    expectation_digest: str
    gamma_snapshot_id: str
    gamma_snapshot_digest: str
    fact_id: str
    fact_validator_version: str


def strict_plan_query(
    request: StrictPlanningRequest,
    *,
    registry: TemplateRegistry | None = None,
    checker: ContractChecker | None = None,
    estimator: CostEstimator | None = None,
) -> StrictPlanningResult:
    """Produce a non-executable conditionally checked plan or fail closed."""

    return _strict_plan_query_impl(
        request,
        registry=registry,
        checker=checker,
        estimator=estimator,
        forced_alternative=None,
        registry_scope=None,
    )


def strict_plan_forced_alternative(
    request: StrictPlanningRequest,
    *,
    occurrence_id: str,
    template_id: str,
    registry: TemplateRegistry | None = None,
    registry_scope: StrictRegistryScope | None = None,
    checker: ContractChecker | None = None,
    estimator: CostEstimator | None = None,
) -> StrictPlanningResult:
    """Strictly complete one freshly admitted single-occurrence alternative.

    The caller supplies only canonical identities.  A promotable path always
    runs admission with internally owned exact checker/estimator providers
    against the complete active selector portfolio, resolves the requested
    template from that new accepted-candidate inventory, binds it internally,
    and then performs ordinary root closure, lowering, and independent replay.
    Caller-provided candidate/result values are never accepted; caller-owned
    providers are allowed only by explicitly non-promotable test scopes.

    This finite adapter deliberately rejects multi-occurrence queries: choosing
    combinations of already legal occurrence alternatives is G5c, not the F1
    single-occurrence production-root migration.
    """

    if type(occurrence_id) is not str or not occurrence_id:
        raise TypeError("forced root occurrence_id must be a nonempty exact string")
    if type(template_id) is not str or not template_id:
        raise TypeError("forced root template_id must be a nonempty exact string")
    return _strict_plan_query_impl(
        request,
        registry=registry,
        checker=checker,
        estimator=estimator,
        forced_alternative=(occurrence_id, template_id),
        registry_scope=registry_scope,
    )


def _strict_plan_query_impl(
    request: StrictPlanningRequest,
    *,
    registry: TemplateRegistry | None,
    checker: ContractChecker | None,
    estimator: CostEstimator | None,
    forced_alternative: tuple[str, str] | None,
    registry_scope: StrictRegistryScope | None,
) -> StrictPlanningResult:
    """Shared strict path; ``forced_alternative`` is identity-only and trusted internally."""

    query = request.query
    try:
        registry_definitions = _registry_definitions(registry)
    except ValueError as exc:
        return StrictPlanningResult(
            query_result=None,
            draft=None,
            envelope=None,
            replay=None,
            conditional_plan=None,
            rejection_reasons=("strict_registry_rejected:" + str(exc),),
        )
    production_artifact_evidence_bindings: tuple[
        tuple[str, str, str], ...
    ] = ()
    forced_required_artifact_kinds: tuple[str, ...] | None = None
    if forced_alternative is not None:
        _occurrence_id, forced_template_id = forced_alternative
        matching_definitions = tuple(
            definition
            for definition in registry_definitions
            if definition.template_id == forced_template_id
        )
        if len(matching_definitions) == 1:
            forced_required_artifact_kinds = tuple(
                sorted(matching_definitions[0].required_artifacts)
            )
    if forced_alternative is not None and registry is not None:
        try:
            preflight_scope = _require_registered_strict_registry_scope(
                registry_scope,
                registry,
            )
        except (ExecutionIdentityError, TypeError, ValueError) as exc:
            return StrictPlanningResult(
                query_result=None,
                draft=None,
                envelope=None,
                replay=None,
                conditional_plan=None,
                rejection_reasons=(
                    "forced_root_registry_scope_rejected:" + str(exc),
                ),
            )
        if preflight_scope.evidence_role == "production_manifest":
            production_artifact_evidence_bindings = (
                preflight_scope.artifact_evidence_bindings
            )
    strict_preflight, artifact_preflight_seal = _strict_input_reasons(
        query,
        continuation=request.continuation,
        registry_definitions=registry_definitions,
        production_artifact_evidence_bindings=(
            production_artifact_evidence_bindings
        ),
        required_artifact_kinds=forced_required_artifact_kinds,
    )
    if strict_preflight:
        # Fail before candidate costing/ranking.  A legacy boolean-only input
        # is not permitted to enter the strict prospective pool at all.
        return StrictPlanningResult(
            query_result=None,
            draft=None,
            envelope=None,
            replay=None,
            conditional_plan=None,
            rejection_reasons=strict_preflight,
        )
    forced_root_provenance: ForcedRootProvenance | None = None
    query_result: QueryPlanResult | None = None
    try:
        if forced_alternative is None:
            query_result = plan_query(
                query,
                registry=registry,
                checker=checker,
                estimator=estimator,
            )
        else:
            occurrence_id, template_id = forced_alternative
            if registry is None:
                if registry_scope is not None:
                    return StrictPlanningResult(
                        query_result=None,
                        draft=None,
                        envelope=None,
                        replay=None,
                        conditional_plan=None,
                        rejection_reasons=(
                            "forced_root_default_registry_rejects_custom_scope",
                        ),
                    )
                (
                    registry_scope_identity,
                    registry_manifest_digest,
                    forced_registry_digest,
                ) = _source_controlled_registry_scope(registry_definitions)
                registry_evidence_role = "source_controlled_canonical"
            else:
                try:
                    verified_scope = _require_registered_strict_registry_scope(
                        registry_scope,
                        registry,
                    )
                except (ExecutionIdentityError, TypeError, ValueError) as exc:
                    return StrictPlanningResult(
                        query_result=None,
                        draft=None,
                        envelope=None,
                        replay=None,
                        conditional_plan=None,
                        rejection_reasons=(
                            "forced_root_registry_scope_rejected:" + str(exc),
                        ),
                    )
                registry_scope_identity = verified_scope.identity_digest
                registry_manifest_digest = verified_scope.manifest_digest
                forced_registry_digest = verified_scope.registry_digest
                registry_evidence_role = verified_scope.evidence_role
            if registry_evidence_role in _PROMOTABLE_REGISTRY_EVIDENCE_ROLES and (
                checker is not None or estimator is not None
            ):
                return StrictPlanningResult(
                    query_result=None,
                    draft=None,
                    envelope=None,
                    replay=None,
                    conditional_plan=None,
                    rejection_reasons=(
                        "forced_root_promotable_provider_override_rejected",
                    ),
                )
            effective_goals = derive_occurrence_goals(query)
            if tuple(sorted(effective_goals)) != (occurrence_id,):
                return StrictPlanningResult(
                    query_result=None,
                    draft=None,
                    envelope=None,
                    replay=None,
                    conditional_plan=None,
                    rejection_reasons=(
                        "forced_root_requires_exact_single_occurrence:" + occurrence_id,
                    ),
                )
            if registry_evidence_role in _PROMOTABLE_REGISTRY_EVIDENCE_ROLES:
                shared_checker = ContractChecker()
                shared_estimator = CostEstimator()
            else:
                shared_checker = checker or ContractChecker()
                shared_estimator = estimator or CostEstimator()
            freshly_enumerated = plan_query(
                query,
                registry=registry,
                checker=shared_checker,
                estimator=shared_estimator,
                feasibility_backtracking=False,
            )
            query_result = freshly_enumerated
            occurrence_result = freshly_enumerated.occurrence_results.get(occurrence_id)
            if occurrence_result is None:
                return StrictPlanningResult(
                    query_result=freshly_enumerated,
                    draft=None,
                    envelope=None,
                    replay=None,
                    conditional_plan=None,
                    rejection_reasons=(
                        "forced_root_occurrence_not_enumerated:" + occurrence_id,
                    ),
                )
            matching = tuple(
                candidate
                for candidate in occurrence_result.candidates
                if candidate.template_id == template_id
                and candidate.accepted
                and candidate.estimated_cost is not None
            )
            if len(matching) != 1:
                return StrictPlanningResult(
                    query_result=freshly_enumerated,
                    draft=None,
                    envelope=None,
                    replay=None,
                    conditional_plan=None,
                    rejection_reasons=(
                        "forced_root_template_not_uniquely_admitted:" + template_id,
                    ),
                )
            candidate = matching[0]
            admitted_candidates = tuple(
                candidate
                for candidate in occurrence_result.candidates
                if candidate.accepted
            )
            forced_root_provenance = _mint_forced_root_provenance(
                occurrence_id=occurrence_id,
                template_id=template_id,
                admitted_candidates=admitted_candidates,
                registry_digest=forced_registry_digest,
                registry_scope_identity=registry_scope_identity,
                registry_manifest_digest=registry_manifest_digest,
                registry_evidence_role=registry_evidence_role,
            )
            forced_occurrence = replace(
                occurrence_result,
                chosen_template=candidate,
                emitted_sql=candidate.emitted_sql,
                delivered_sigma=candidate.delivered_sigma,
                estimated_cost=candidate.estimated_cost,
            )
            query_result = plan_query(
                query,
                registry=registry,
                checker=shared_checker,
                estimator=shared_estimator,
                preplanned_occurrence_results={occurrence_id: forced_occurrence},
                feasibility_backtracking=False,
            )
    except TemplateLoweringError as exc:
        post_plan_artifact_reasons, post_plan_artifact_seal = (
            _artifact_preflight_inventory(
                query,
                registry_definitions=registry_definitions,
                production_artifact_evidence_bindings=(
                    production_artifact_evidence_bindings
                ),
                required_artifact_kinds=forced_required_artifact_kinds,
            )
        )
        rejection = (
            "strict_artifact_preflight_seal_mismatch"
            if post_plan_artifact_reasons
            or post_plan_artifact_seal != artifact_preflight_seal
            else "strict_planning_lowering_rejected:" + str(exc)
        )
        return _mint_forced_root_failure(
            query_result=query_result,
            draft=None,
            envelope=None,
            replay=None,
            rejection_reasons=(rejection,),
            forced_root_provenance=forced_root_provenance,
            structural_rejection=False,
        )
    assert query_result is not None
    post_plan_artifact_reasons, post_plan_artifact_seal = _artifact_preflight_inventory(
        query,
        registry_definitions=registry_definitions,
        production_artifact_evidence_bindings=(
            production_artifact_evidence_bindings
        ),
        required_artifact_kinds=forced_required_artifact_kinds,
    )
    if (
        post_plan_artifact_reasons
        or post_plan_artifact_seal != artifact_preflight_seal
    ):
        return _mint_forced_root_failure(
            query_result=query_result,
            draft=None,
            envelope=None,
            replay=None,
            rejection_reasons=("strict_artifact_preflight_seal_mismatch",),
            forced_root_provenance=forced_root_provenance,
            structural_rejection=False,
        )
    if not query_result.ok or not query_result.emitted_sql or query_result.certificate is None:
        return _mint_forced_root_failure(
            query_result=query_result,
            draft=None,
            envelope=None,
            replay=None,
            rejection_reasons=(f"semantic_plan_not_closed:{query_result.root_closure.reason}",),
            forced_root_provenance=forced_root_provenance,
            structural_rejection=True,
        )

    registry_digest = canonical_registry_digest(registry_definitions)
    try:
        # QueryPlanResult.emitted_sql intentionally remains the historical
        # diagnostic script (including ValidationGate statements).  A strict
        # ExecutableDraft is instead rebuilt from the bound IR's single query
        # body; H2 recipes travel through the certificate/runtime type-state
        # chain and are executed only after plain EXPLAIN in the live trial.
        strict_fragment = emit_sql(query_result.bound_ir, query.emit_context)
        incomplete_recipes = tuple(
            recipe.artifact_id
            for recipe in strict_fragment.validation_recipes
            if not recipe.complete
        )
        if incomplete_recipes:
            raise TemplateLoweringError(
                "strict artifact validation recipe is incomplete: "
                + ", ".join(sorted(incomplete_recipes))
            )
        draft = ExecutableDraft.from_core_sql(
            plan_id=_plan_id(query_result),
            bound_ir_digest=_stable_digest(query_result.bound_ir.to_dict()),
            core_sql=strict_fragment.render_core(),
            continuation=request.continuation,
            typed_params=tuple(request.typed_params),
            session_contract=request.session_contract,
            registry_version=request.registry_version,
            registry_digest=registry_digest,
            continuation_scope=semantic_continuation_scope_for_plan(query_result.bound_ir,
                effective_occurrence_goals=query_result.effective_occurrence_goals,
                emit_context=query.emit_context),
        )
    except (TemplateLoweringError, ExecutionIdentityError, ValueError) as exc:
        return _mint_forced_root_failure(
            query_result=query_result,
            draft=None,
            envelope=None,
            replay=None,
            rejection_reasons=("strict_lowering_rejected:" + str(exc),),
            forced_root_provenance=forced_root_provenance,
            structural_rejection=False,
        )
    gamma_snapshots = {
        occurrence_id: goal.problem.gamma_snapshot
        for occurrence_id, goal in query_result.effective_occurrence_goals.items()
        if goal.problem.gamma_snapshot is not None
    }
    semantic_context = SemanticReplayContext(
        occurrence_leaf_sigmas={
            occurrence_id: sigma_from_dict(result.delivered_sigma)
            for occurrence_id, result in query_result.occurrence_results.items()
            if result.chosen_template is not None
        },
        effective_occurrence_goals=query_result.effective_occurrence_goals,
        root_rho=(query.ir_skeleton.rho_root if isinstance(query.ir_skeleton, Root) else {}),
        emit_context=query.emit_context,
    )
    try:
        evidence_refs, pending = derive_typed_admission_bindings(
            plan=query_result.bound_ir,
            semantic_context=semantic_context,
            registry_definitions=registry_definitions,
        )
    except CertificateReplayError as exc:
        return _mint_forced_root_failure(
            query_result=query_result,
            draft=draft,
            envelope=None,
            replay=None,
            rejection_reasons=("typed_admission_replay_failed:" + str(exc),),
            forced_root_provenance=forced_root_provenance,
            structural_rejection=False,
        )
    root_rho = (
        query.ir_skeleton.rho_root
        if isinstance(query.ir_skeleton, Root)
        else {}
    )
    try:
        target = canonical_target_binding(
            query_result.bound_ir,
            semantic_context,
            registry_definitions=registry_definitions,
        )
        rho = canonical_rho_binding(query_result.bound_ir, semantic_context)
        strict_steps = derive_strict_certificate_steps(
            plan=query_result.bound_ir,
            semantic_context=semantic_context,
            obligation_graph=query_result.obligation_graph,
            root_rho=root_rho,
            registry_definitions=registry_definitions,
        )
        envelope = build_certificate_envelope(
            plan=query_result.bound_ir,
            target=target,
            rho=rho,
            gamma_snapshots=gamma_snapshots,
            draft=draft,
            obligation_graph=query_result.obligation_graph,
            semantic_context=semantic_context,
            steps=strict_steps,
            registry_definitions=registry_definitions,
        )
    except CertificateReplayError as exc:
        return _mint_forced_root_failure(
            query_result=query_result,
            draft=draft,
            envelope=None,
            replay=None,
            rejection_reasons=(
                "strict_certificate_construction_failed:" + str(exc),
            ),
            forced_root_provenance=forced_root_provenance,
            structural_rejection=False,
        )
    replay = replay_certificate_envelope(
        envelope,
        plan=query_result.bound_ir,
        target=target,
        rho=rho,
        root_rho=root_rho,
        gamma_snapshots=gamma_snapshots,
        draft=draft,
        obligation_graph=query_result.obligation_graph,
        root_sigma=query_result.root_sigma,
        semantic_context=semantic_context,
        expected_occurrence_ids=tuple(sorted(query_result.effective_occurrence_goals)),
        required_evidence_refs=evidence_refs,
        pending_dynamic_obligations=pending,
        registry_definitions=registry_definitions,
    )
    if not replay.ok:
        return _mint_forced_root_failure(
            query_result=query_result,
            draft=draft,
            envelope=envelope,
            replay=replay,
            rejection_reasons=replay.reasons,
            forced_root_provenance=forced_root_provenance,
            structural_rejection=False,
        )
    conditional_plan = conditionally_checked_from_replay(
        draft=draft,
        replay=replay,
    )
    forced_attempt = (
        None
        if forced_root_provenance is None
        else _mint_forced_root_attempt_provenance(
            forced_root_provenance,
            outcome_status="completed",
            rejection_reasons=(),
        )
    )
    result = _mint_strict_planning_result(
        query_result=query_result,
        draft=draft,
        envelope=envelope,
        replay=replay,
        conditional_plan=conditional_plan,
        forced_root_provenance=forced_root_provenance,
        forced_root_attempt_provenance=forced_attempt,
    )
    if forced_attempt is not None:
        result = _register_forced_root_attempt_result(result)
        # The internal attempt registration performs another validating
        # normalization of envelope.steps. Capture after that final step,
        # before the successful result is exposed to its caller.
        observation = _capture_strict_result_observation(result)
        if observation is not None:
            reference = _VERIFIED_STRICT_RESULTS[id(result)][0]
            _STRICT_RESULT_OBSERVATIONS[id(result)] = (reference, observation)
    return result


def _strict_input_reasons(
    query: PlanningQuery,
    *,
    continuation: ContinuationTemplate | None = None,
    registry_definitions: tuple[TemplateDefinition, ...],
    production_artifact_evidence_bindings: tuple[
        tuple[str, str, str], ...
    ] = (),
    required_artifact_kinds: tuple[str, ...] | None = None,
) -> tuple[tuple[str, ...], tuple[_StrictArtifactPreflightEntry, ...]]:
    reasons: list[str] = []
    if normalize_planner_mode(query.mode) != ADMISSION_FIRST_MODE:
        reasons.append("strict_mode_requires_admission_first_selector")
    if query.emit_context.allow_diagnostic_lowering:
        reasons.append("strict_mode_forbids_diagnostic_lowering")
    approved_identity_continuation = False
    if type(continuation) is ContinuationTemplate:
        try:
            definition = continuation.approved_definition
        except ExecutionIdentityError:
            definition = None
        approved_identity_continuation = bool(
            definition is not None
            and definition.wrapper_kind == "identity"
            and definition.template == _STRICT_IDENTITY_CONTINUATION_TEMPLATE
            and continuation.template == _STRICT_IDENTITY_CONTINUATION_TEMPLATE
        )
    if not approved_identity_continuation:
        reasons.append("strict_mode_requires_approved_identity_continuation")
    for occurrence_id, goal in sorted(query.occurrence_goals.items()):
        if (
            goal.mode is not None
            and normalize_planner_mode(goal.mode) != ADMISSION_FIRST_MODE
        ):
            reasons.append(f"diagnostic_or_baseline_occurrence_mode:{occurrence_id}")
        if goal.problem.disabled_components:
            reasons.append(f"strict_mode_forbids_disabled_components:{occurrence_id}")
        if not goal.problem.require_typed_admission:
            reasons.append(f"typed_admission_not_required:{occurrence_id}")
        if goal.problem.gamma_snapshot is None:
            reasons.append(f"gamma_snapshot_missing:{occurrence_id}")
    artifact_reasons, artifact_seal = _artifact_preflight_inventory(
        query,
        registry_definitions=registry_definitions,
        production_artifact_evidence_bindings=(
            production_artifact_evidence_bindings
        ),
        required_artifact_kinds=required_artifact_kinds,
    )
    reasons.extend(artifact_reasons)
    return tuple(reasons), artifact_seal


def _artifact_preflight_inventory(
    query: PlanningQuery,
    *,
    registry_definitions: tuple[TemplateDefinition, ...],
    production_artifact_evidence_bindings: tuple[
        tuple[str, str, str], ...
    ] = (),
    required_artifact_kinds: tuple[str, ...] | None = None,
) -> tuple[tuple[str, ...], tuple[_StrictArtifactPreflightEntry, ...]]:
    reasons: list[str] = []
    entries: list[_StrictArtifactPreflightEntry] = []
    artifact_requirements = (
        frozenset(required_artifact_kinds)
        if required_artifact_kinds is not None
        else frozenset(
            required
            for definition in registry_definitions
            for required in definition.required_artifacts
        )
    )
    expectations = query.emit_context.artifact_expectations
    production_evidence = frozenset(production_artifact_evidence_bindings)
    for occurrence_id, goal in sorted(query.occurrence_goals.items()):
        artifacts = goal.problem.artifacts
        if not isinstance(artifacts, Mapping):
            reasons.append(f"strict_artifact_registry_invalid:{occurrence_id}")
            continue
        gamma = goal.problem.gamma_snapshot
        for required in sorted(artifact_requirements):
            artifact = artifacts.get(required)
            if artifact is None and required == "auth_idx_keyed":
                candidate = artifacts.get("auth_idx")
                if candidate is not None and bool(getattr(candidate, "keyed", False)):
                    artifact = candidate
            if artifact is None:
                continue
            if artifact.__class__ is not ArtifactMetadata:
                reasons.append(
                    f"strict_artifact_metadata_untyped:{occurrence_id}:{required}"
                )
                continue
            artifact_id = artifact.artifact_id
            if artifact_id.__class__ is not str or not artifact_id:
                reasons.append(
                    f"strict_artifact_identity_invalid:{occurrence_id}:{required}"
                )
                continue
            expectation = (
                expectations.get(artifact_id)
                if isinstance(expectations, Mapping)
                else None
            )
            if expectation.__class__ is not StrictArtifactExpectation:
                reasons.append(
                    "strict_artifact_expectation_missing_or_untyped:"
                    f"{occurrence_id}:{artifact_id}"
                )
                continue
            try:
                expectation.assert_valid()
                expectation_digest = expectation.digest
            except TemplateLoweringError:
                reasons.append(
                    f"strict_artifact_expectation_invalid:{occurrence_id}:{artifact_id}"
                )
                continue
            if gamma is None:
                continue
            if gamma.__class__ is not GammaSnapshot:
                reasons.append(
                    f"strict_artifact_gamma_untyped:{occurrence_id}:{artifact_id}"
                )
                continue
            subject_facts = tuple(
                fact
                for fact in gamma.facts
                if getattr(fact, "kind", None) == "artifact_validation"
                and getattr(fact, "subject_digest", None) == artifact_id
            )
            if not subject_facts:
                reasons.append(
                    f"strict_artifact_validation_fact_missing:{occurrence_id}:{artifact_id}"
                )
                continue
            if len(subject_facts) != 1:
                reasons.append(
                    f"strict_artifact_validation_fact_ambiguous:{occurrence_id}:{artifact_id}"
                )
                continue
            fact = subject_facts[0]
            if (
                fact.__class__ is not GammaFact
                or fact.verdict != "pass"
                or fact.snapshot_id != gamma.snapshot_id
                or fact.dynamic is not False
            ):
                reasons.append(
                    f"strict_artifact_validation_fact_invalid:{occurrence_id}:{artifact_id}"
                )
                continue
            if fact.evidence_digest != expectation_digest and (
                artifact_id,
                expectation_digest,
                fact.evidence_digest,
            ) not in production_evidence:
                reasons.append(
                    "strict_artifact_validation_fact_digest_mismatch:"
                    f"{occurrence_id}:{artifact_id}"
                )
                continue
            try:
                gamma_digest = gamma.digest
            except (AttributeError, TypeError, ValueError):
                reasons.append(
                    f"strict_artifact_gamma_invalid:{occurrence_id}:{artifact_id}"
                )
                continue
            entries.append(
                _StrictArtifactPreflightEntry(
                    occurrence_id=occurrence_id,
                    required_kind=required,
                    artifact_id=artifact_id,
                    artifact_metadata_digest=_stable_digest(asdict(artifact)),
                    expectation_digest=expectation_digest,
                    gamma_snapshot_id=gamma.snapshot_id,
                    gamma_snapshot_digest=gamma_digest,
                    fact_id=fact.fact_id,
                    fact_validator_version=fact.validator_version,
                )
            )
    return tuple(reasons), tuple(sorted(entries))


def _registry_definitions(registry: TemplateRegistry | None) -> tuple[TemplateDefinition, ...]:
    """Bind strict identity to the actual frozen selector registry, not global defaults."""

    if registry is None:
        return default_template_definitions()
    definitions: list[TemplateDefinition] = []
    for spec in registry.template_specs():
        try:
            definition = template_definition(spec.template_id)
        except KeyError as exc:
            raise ValueError(f"strict registry contains unknown template: {spec.template_id}") from exc
        definitions.append(definition)
    if not definitions:
        raise ValueError("strict registry cannot be empty")
    return tuple(definitions)


def _strict_registry_scope_identity(
    *,
    scope_id: str,
    manifest_digest: str,
    registry_digest: str,
    template_ids: tuple[str, ...],
    evidence_role: str,
    owner_identity_digest: str | None,
    artifact_evidence_bindings: tuple[tuple[str, str, str], ...] = (),
) -> str:
    return _stable_digest(
        {
            "scope_id": scope_id,
            "manifest_digest": manifest_digest,
            "registry_digest": registry_digest,
            "template_ids": list(template_ids),
            "evidence_role": evidence_role,
            "owner_identity_digest": owner_identity_digest,
            "artifact_evidence_bindings": [
                {
                    "artifact_id": artifact_id,
                    "expectation_digest": expectation_digest,
                    "gamma_evidence_digest": gamma_evidence_digest,
                }
                for (
                    artifact_id,
                    expectation_digest,
                    gamma_evidence_digest,
                ) in artifact_evidence_bindings
            ],
        }
    )


def _canonical_artifact_evidence_bindings(
    bindings: tuple[tuple[str, str, str], ...],
) -> tuple[tuple[str, str, str], ...]:
    try:
        materialized = tuple(bindings)
    except TypeError as exc:
        raise TypeError(
            "production artifact evidence bindings must be a typed tuple"
        ) from exc
    if any(
        item.__class__ is not tuple
        or len(item) != 3
        or item[0].__class__ is not str
        or not item[0]
        or item[1].__class__ is not str
        or _SHA256_RE.fullmatch(item[1]) is None
        or item[2].__class__ is not str
        or _SHA256_RE.fullmatch(item[2]) is None
        for item in materialized
    ):
        raise ValueError("production artifact evidence binding is invalid")
    canonical = tuple(sorted(materialized))
    if materialized != canonical or len({item[0] for item in canonical}) != len(
        canonical
    ):
        raise ValueError(
            "production artifact evidence bindings must be canonical and unique"
        )
    return canonical


def _source_controlled_registry_scope(
    definitions: tuple[TemplateDefinition, ...],
) -> tuple[str, str, str]:
    registry_digest = canonical_registry_digest(definitions)
    template_ids = tuple(item.template_id for item in definitions)
    manifest_digest = _stable_digest(
        {
            "source_controlled_active_selector_portfolio": (
                "planner.core.DEFAULT_TEMPLATE_REGISTRY"
            ),
            "definition_provider": "planner.contracts.default_template_definitions",
            "registry_digest": registry_digest,
            "template_ids": list(template_ids),
        }
    )
    scope_identity = _strict_registry_scope_identity(
        scope_id="source-controlled-default-selector-portfolio",
        manifest_digest=manifest_digest,
        registry_digest=registry_digest,
        template_ids=template_ids,
        evidence_role="source_controlled_canonical",
        owner_identity_digest=None,
        artifact_evidence_bindings=(),
    )
    return scope_identity, manifest_digest, registry_digest


def _mint_test_strict_registry_scope(
    registry: TemplateRegistry,
    *,
    scope_id: str,
) -> StrictRegistryScope:
    """Mint a custom-registry scope that is permanently non-promotable.

    There is intentionally no raw-assertion production minter.  A future
    manifest/receipt owner may add a separate sealed bridge; until then custom
    registries can only exercise isolated contract tests.
    """

    if registry.__class__ is not TemplateRegistry:
        raise TypeError("strict registry scope requires an exact TemplateRegistry")
    if not scope_id:
        raise ValueError("strict registry scope requires scope identity")
    registry.validate_complete()
    definitions = _registry_definitions(registry)
    actual_ids = tuple(item.template_id for item in definitions)
    actual_digest = canonical_registry_digest(definitions)
    evidence_role = "isolated_test_non_promotable"
    manifest_digest = _stable_digest(
        {
            "isolated_test_registry_scope": scope_id,
            "registry_digest": actual_digest,
            "template_ids": list(actual_ids),
        }
    )
    identity = _strict_registry_scope_identity(
        scope_id=scope_id,
        manifest_digest=manifest_digest,
        registry_digest=actual_digest,
        template_ids=actual_ids,
        evidence_role=evidence_role,
        owner_identity_digest=None,
        artifact_evidence_bindings=(),
    )
    scope = StrictRegistryScope(
        registry=registry,
        scope_id=scope_id,
        manifest_digest=manifest_digest,
        registry_digest=actual_digest,
        template_ids=actual_ids,
        evidence_role=evidence_role,
        owner_identity_digest=None,
        identity_digest=identity,
        artifact_evidence_bindings=(),
    )
    object.__setattr__(
        scope,
        "_construction_token",
        _STRICT_REGISTRY_SCOPE_CAPABILITY,
    )
    key = id(scope)

    def _drop(reference: weakref.ReferenceType[StrictRegistryScope]) -> None:
        registered = _VERIFIED_STRICT_REGISTRY_SCOPES.get(key)
        if registered is not None and registered[0] is reference:
            _VERIFIED_STRICT_REGISTRY_SCOPES.pop(key, None)

    _VERIFIED_STRICT_REGISTRY_SCOPES[key] = (
        weakref.ref(scope, _drop),
        registry,
        identity,
        None,
        None,
    )
    return scope


def _mint_production_strict_registry_scope(
    registry: TemplateRegistry,
    *,
    scope_id: str,
    manifest_digest: str,
    expected_registry_digest: str,
    expected_template_ids: tuple[str, ...],
    owner: Any,
    owner_identity_digest: str,
    owner_validator: Callable[[Any], str],
    artifact_evidence_bindings: tuple[tuple[str, str, str], ...] = (),
) -> StrictRegistryScope:
    """Private bridge for a trusted production manifest/receipt owner.

    The owner is revalidated on every forced-root entry.  This is not a raw
    assertion API: the trusted adapter must supply a live identity-capability
    validator, and copied/equal-value scopes are never registered.
    """

    if registry.__class__ is not TemplateRegistry:
        raise TypeError("production registry scope requires an exact registry")
    if not scope_id or _SHA256_RE.fullmatch(manifest_digest) is None:
        raise ValueError("production registry manifest identity is invalid")
    if _SHA256_RE.fullmatch(owner_identity_digest) is None:
        raise ValueError("production registry owner identity is invalid")
    if not callable(owner_validator):
        raise TypeError("production registry owner validator is required")
    if owner_validator(owner) != owner_identity_digest:
        raise ExecutionIdentityError("production registry owner did not replay")
    canonical_evidence_bindings = _canonical_artifact_evidence_bindings(
        artifact_evidence_bindings
    )
    registry.validate_complete()
    definitions = _registry_definitions(registry)
    actual_ids = tuple(item.template_id for item in definitions)
    actual_digest = canonical_registry_digest(definitions)
    if (
        actual_ids != tuple(expected_template_ids)
        or actual_digest != expected_registry_digest
    ):
        raise ExecutionIdentityError(
            "production registry differs from its owner manifest"
        )
    evidence_role = "production_manifest"
    identity = _strict_registry_scope_identity(
        scope_id=scope_id,
        manifest_digest=manifest_digest,
        registry_digest=actual_digest,
        template_ids=actual_ids,
        evidence_role=evidence_role,
        owner_identity_digest=owner_identity_digest,
        artifact_evidence_bindings=canonical_evidence_bindings,
    )
    scope = StrictRegistryScope(
        registry=registry,
        scope_id=scope_id,
        manifest_digest=manifest_digest,
        registry_digest=actual_digest,
        template_ids=actual_ids,
        evidence_role=evidence_role,
        owner_identity_digest=owner_identity_digest,
        identity_digest=identity,
        artifact_evidence_bindings=canonical_evidence_bindings,
    )
    object.__setattr__(
        scope,
        "_construction_token",
        _STRICT_REGISTRY_SCOPE_CAPABILITY,
    )
    key = id(scope)

    def _drop(reference: weakref.ReferenceType[StrictRegistryScope]) -> None:
        registered = _VERIFIED_STRICT_REGISTRY_SCOPES.get(key)
        if registered is not None and registered[0] is reference:
            _VERIFIED_STRICT_REGISTRY_SCOPES.pop(key, None)

    try:
        owner_reference: weakref.ReferenceType[Any] = weakref.ref(owner)
    except TypeError as exc:
        raise TypeError("production registry owner must support weak identity") from exc
    _VERIFIED_STRICT_REGISTRY_SCOPES[key] = (
        weakref.ref(scope, _drop),
        registry,
        identity,
        owner_reference,
        owner_validator,
    )
    return scope


def _require_registered_strict_registry_scope(
    scope: StrictRegistryScope | None,
    registry: TemplateRegistry,
) -> StrictRegistryScope:
    if scope is None or scope.__class__ is not StrictRegistryScope:
        raise ExecutionIdentityError(
            "custom forced-root registry requires a registered complete scope"
        )
    registered = _VERIFIED_STRICT_REGISTRY_SCOPES.get(id(scope))
    if (
        registered is None
        or registered[0]() is not scope
        or registered[1] is not registry
        or scope.registry is not registry
        or scope._construction_token is not _STRICT_REGISTRY_SCOPE_CAPABILITY
        or not scope.scope_id
        or _SHA256_RE.fullmatch(scope.manifest_digest) is None
        or scope.evidence_role not in {
            "production_manifest",
            "isolated_test_non_promotable",
        }
    ):
        raise ExecutionIdentityError("strict registry scope is not adapter-registered")
    registry.validate_complete()
    if scope.evidence_role == "production_manifest":
        owner_reference = registered[3]
        owner_validator = registered[4]
        owner = None if owner_reference is None else owner_reference()
        if (
            owner is None
            or owner_validator is None
            or scope.owner_identity_digest is None
            or owner_validator(owner) != scope.owner_identity_digest
        ):
            raise ExecutionIdentityError(
                "production registry owner identity changed"
            )
    elif scope.owner_identity_digest is not None:
        raise ExecutionIdentityError("test registry scope cannot carry an owner")
    definitions = _registry_definitions(registry)
    actual_ids = tuple(item.template_id for item in definitions)
    actual_digest = canonical_registry_digest(definitions)
    current_identity = _strict_registry_scope_identity(
        scope_id=scope.scope_id,
        manifest_digest=scope.manifest_digest,
        registry_digest=actual_digest,
        template_ids=actual_ids,
        evidence_role=scope.evidence_role,
        owner_identity_digest=scope.owner_identity_digest,
        artifact_evidence_bindings=_canonical_artifact_evidence_bindings(
            scope.artifact_evidence_bindings
        ),
    )
    if (
        scope.registry_digest != actual_digest
        or scope.template_ids != actual_ids
        or scope.identity_digest != current_identity
        or registered[2] != current_identity
    ):
        raise ExecutionIdentityError("strict registry scope identity changed")
    return scope


def _admission_bindings(
    query_result: QueryPlanResult,
) -> tuple[tuple[str, ...], tuple[DynamicObligation, ...]]:
    refs: list[str] = []
    pending: list[DynamicObligation] = []
    for occurrence_id, result in sorted(query_result.occurrence_results.items()):
        chosen = result.chosen_template
        if chosen is None:
            continue
        admission = chosen.diagnostics.get("admission") if isinstance(chosen.diagnostics, Mapping) else None
        if not isinstance(admission, Mapping):
            continue
        refs.extend(str(item) for item in admission.get("evidence_refs", ()) if str(item))
        memo_goal = admission.get("memo_goal")
        subject = _stable_digest(memo_goal if isinstance(memo_goal, Mapping) else {"occurrence": occurrence_id})
        for kind in admission.get("required_dynamic_fact_kinds", ()):
            kind_value = str(kind)
            pending.append(
                DynamicObligation(
                    obligation_id=f"{occurrence_id}:{kind_value}",
                    kind=kind_value,
                    subject_digest=subject,
                    validator_version="caprls-dynamic-h2-v1",
                    recipe_digest=_stable_digest(
                        {"occurrence": occurrence_id, "kind": kind_value, "subject": subject}
                    ),
                )
            )
    return tuple(sorted(set(refs))), tuple(pending)


def _plan_id(query_result: QueryPlanResult) -> str:
    return "strict:" + _stable_digest(query_result.bound_ir.to_dict()).split(":", 1)[1]


@lru_cache(maxsize=512)
def _cached_string_digest(value: str) -> str:
    """Cache only immutable text, never a planner object or a verdict."""

    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@lru_cache(maxsize=256)
def _cached_string_mapping_digest(items: tuple[tuple[str, str], ...]) -> str:
    """Digest a fresh immutable snapshot of an exact string/string dict."""

    encoded = json.dumps(dict(items), sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _immutable_text_digest(value: Any) -> str | None:
    # Re-read every dict on every invocation.  In particular this is not an
    # identity cache: mutating a SQL/identity mapping changes its cache key,
    # and no admission, certificate replay or tampering check is bypassed.
    if type(value) is str:
        return _cached_string_digest(value)
    if type(value) is dict and all(
        type(key) is str and type(item) is str
        for key, item in value.items()
    ):
        return _cached_string_mapping_digest(tuple(sorted(value.items())))
    return None


def _stable_digest(value: Any) -> str:
    # Avoid depending on a private helper: the envelope will independently
    # recompute/bind this value, so this is only an identity carrier.
    cached = _immutable_text_digest(value)
    if cached is not None:
        return cached
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


# Fix eligibility to the loaded source-controlled schemas and serializers.
# Replacing a method/helper may still succeed via the original full checker,
# but cannot silently establish a fresh fast-path trust assumption.
_STRICT_OBSERVATION_TRUSTED_TYPES = _strict_observation_types()
for _copy_metadata_class in (*_STRICT_OBSERVATION_TRUSTED_TYPES, StrictPlanningResult):
    # copy/copy.deepcopy lazily add this standard-library cache to a class.
    # Establish it before pinning namespaces, rather than treating a later
    # harmless first copy as a permanent source/schema change. The cache is
    # still ordinary observed class data; replacing or mutating it is not
    # ignored by the observation graph.
    copyreg._slotnames(_copy_metadata_class)
del _copy_metadata_class
_STRICT_OBSERVATION_SOURCE_BASELINE = _strict_observation_source_dependencies(
    _STRICT_OBSERVATION_TRUSTED_TYPES
)
_STRICT_OBSERVATION_CLASS_BASELINE = tuple(
    (cls, _strict_observation_class_source(cls))
    for cls in (*_STRICT_OBSERVATION_TRUSTED_TYPES, StrictPlanningResult)
)
