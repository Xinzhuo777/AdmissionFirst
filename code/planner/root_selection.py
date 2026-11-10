"""Sealed completed-root reference selection for the finite F1 planning path.

This module is intentionally planning-only.  Its receipts cannot be passed to
runtime authorization and it never executes a statement or reads a measured
outcome.  A production adapter must first mint one common read-only planning
batch, bind every member to a registered :class:`StrictPlanningResult`, and
observe the complete root schema and prospective PostgreSQL evidence.  The
selector accepts only the resulting sealed ``PlanningEvidenceBatch`` so a
caller cannot pass a favorable subset of completed roots.

The concrete PostgreSQL batch adapter is kept outside this module.  The private
``_mint_test_planning_evidence_batch`` seam exists only for isolated contract
tests; production callers must not import it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
import re
from typing import Any, Mapping, Sequence
import weakref

from .dominance import (
    AuthPair,
    BranchAndLineage,
    CostEvidencePoolDecision,
    CoverageAndLive,
    EnforcerRequirement,
    FinalProspectiveCost,
    PhysicalProperties,
    RIDMaterialization,
    ReferencePlan,
    RequirementEvidence,
    ResidualObligation,
    RhoObservableProfile,
    SafetyProfile,
    TargetAndRefinement,
    VisibleColumn,
    canonical_refined_target_id,
    compare_reference_dominance,
    validate_final_prospective_cost_pool,
    validate_profile_against_rho,
)
from .contracts import target_refinement_subject_digest
from .core import policy_subject_digest
from .emit import emit_sql
from .features import PlannerFeatureFlags
from .ir import Project, Root, ScanProtected, Select, UnionTagged, walk
from .pc_scope import (
    closed_pc_cte_name, continuation_avoids_name,
    decode_access_root_materialized, safe_pc_predicate,
)
from .query import QueryPlanResult
from .state import Sigma, sigma_from_dict
from .strict_planning import (
    StrictPlanningResult,
    _forced_inventory_digest,
    _immutable_text_digest,
    _require_forced_root_attempt_provenance,
    _require_forced_root_provenance,
    _require_registered_strict_planning_result,
)


_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PLANNING_EVIDENCE_TOKEN = object()
_BOUND_RUNNER_TOKEN = object()
_COMPLETED_ROOT_TOKEN = object()
_ISOLATED_SELECTION_TOKEN = object()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: Any) -> str:
    cached = _immutable_text_digest(value)
    if cached is not None:
        return cached
    return "sha256:" + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _require_digest(value: str, label: str) -> None:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a sha256 digest")


def _string_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)):
        return (str(value),)
    try:
        result = tuple(str(item) for item in value)
    except TypeError:
        return ()
    return result if all(result) else ()


def _string_mapping(value: Any) -> tuple[tuple[str, str], ...] | None:
    # Missing is not known-empty.  Only an observed mapping, including an
    # explicitly observed empty mapping, can close a profile dimension.
    if value is None:
        return None
    if not isinstance(value, Mapping):
        return None
    normalized = tuple(sorted((str(key), str(item)) for key, item in value.items()))
    if any(not key or not item for key, item in normalized):
        return None
    return normalized


@dataclass(frozen=True, order=True)
class TypedRootSchemaColumn:
    """One validator-observed root output column."""

    ordinal: int
    name: str
    type_name: str
    nullable: bool
    collation: str | None = None
    visibility: str = "visible"

    def __post_init__(self) -> None:
        if not isinstance(self.ordinal, int) or isinstance(self.ordinal, bool) or self.ordinal < 0:
            raise ValueError("root schema ordinal must be a nonnegative integer")
        if not self.name or not self.type_name:
            raise ValueError("root schema column requires name and type")
        if not isinstance(self.nullable, bool):
            raise TypeError("root schema nullable must be boolean")
        if self.collation is not None and not self.collation:
            raise ValueError("root schema collation cannot be empty")
        if self.visibility not in {"visible", "hidden"}:
            raise ValueError("root schema visibility must be visible or hidden")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ordinal": self.ordinal,
            "name": self.name,
            "type_name": self.type_name,
            "nullable": self.nullable,
            "collation": self.collation,
            "visibility": self.visibility,
        }


@dataclass(frozen=True)
class ContinuationSpec:
    """Finite, source-controlled semantic continuation contract.

    Adapters select one finite renderer and freeze its exact SQL suffix.  The
    shared seam composes that suffix with the registered strict core; callers
    cannot supply a different complete runner at identity-mint time.
    """

    spec_id: str
    query_id: str
    policy_id: str
    renderer_id: str
    renderer_version: str
    result_mode: str
    required_hidden_carriers: tuple[str, ...]
    result_columns: tuple[TypedRootSchemaColumn, ...]
    ordered_keys: tuple[str, ...]
    row_limit: int | None
    continuation_sql: str = field(repr=False)
    _construction_token: object | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._construction_token is not _BOUND_RUNNER_TOKEN:
            raise ValueError("continuation spec must be source-controlled")
        if (
            not self.spec_id
            or not self.query_id
            or not self.policy_id
            or not self.renderer_id
            or not self.renderer_version
        ):
            raise ValueError("continuation spec requires finite identities")
        if self.result_mode not in {
            "ordered_sequence",
            "typed_rid_set",
            "singleton_typed_scalar_set",
        }:
            raise ValueError("continuation spec result mode is invalid")
        carriers = tuple(self.required_hidden_carriers)
        if (
            any(type(item) is not str or not item for item in carriers)  # noqa: E721
            or len(set(carriers)) != len(carriers)
        ):
            raise ValueError("continuation spec hidden carriers are malformed")
        object.__setattr__(self, "required_hidden_carriers", carriers)
        columns = tuple(self.result_columns)
        if not columns or any(
            item.__class__ is not TypedRootSchemaColumn for item in columns
        ):
            raise TypeError("continuation spec requires a typed result contract")
        if tuple(item.ordinal for item in columns) != tuple(range(len(columns))):
            raise ValueError("continuation result ordinals must be contiguous")
        if len({item.name for item in columns}) != len(columns):
            raise ValueError("continuation result names must be unique")
        if any(item.visibility != "visible" for item in columns):
            raise ValueError("continuation result contract may expose visible columns only")
        object.__setattr__(self, "result_columns", columns)
        ordered_keys = tuple(self.ordered_keys)
        if (
            any(type(item) is not str or not item for item in ordered_keys)  # noqa: E721
            or len(set(ordered_keys)) != len(ordered_keys)
        ):
            raise ValueError("continuation ordered keys are malformed")
        if self.result_mode == "ordered_sequence":
            if not ordered_keys:
                raise ValueError("ordered continuation requires finite ordered keys")
        elif ordered_keys:
            raise ValueError("unordered or scalar continuation cannot declare order")
        object.__setattr__(self, "ordered_keys", ordered_keys)
        if self.row_limit is not None and (
            type(self.row_limit) is not int or self.row_limit <= 0  # noqa: E721
        ):
            raise ValueError("continuation row limit must be a positive exact integer")
        if (
            type(self.continuation_sql) is not str  # noqa: E721
            or not self.continuation_sql
            or self.continuation_sql != self.continuation_sql.rstrip()
        ):
            raise ValueError("continuation SQL must be exact, nonempty, and right-trimmed")

    @property
    def result_contract_digest(self) -> str:
        return _digest(
            {
                "result_mode": self.result_mode,
                "columns": [item.to_dict() for item in self.result_columns],
                "ordered_keys": list(self.ordered_keys),
                "row_limit": self.row_limit,
            }
        )

    @property
    def continuation_sql_digest(self) -> str:
        return _digest({"exact_continuation_sql": self.continuation_sql})

    @property
    def digest(self) -> str:
        return _digest(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec_id": self.spec_id,
            "query_id": self.query_id,
            "policy_id": self.policy_id,
            "renderer_id": self.renderer_id,
            "renderer_version": self.renderer_version,
            "result_mode": self.result_mode,
            "required_hidden_carriers": list(self.required_hidden_carriers),
            "result_columns": [item.to_dict() for item in self.result_columns],
            "ordered_keys": list(self.ordered_keys),
            "row_limit": self.row_limit,
            "continuation_sql_digest": self.continuation_sql_digest,
            "result_contract_digest": self.result_contract_digest,
        }


_REGISTERED_CONTINUATION_SPECS: dict[
    int,
    tuple[weakref.ReferenceType[ContinuationSpec], str],
] = {}


def _register_continuation_spec(spec: ContinuationSpec) -> ContinuationSpec:
    key = id(spec)

    def _drop(reference: weakref.ReferenceType[ContinuationSpec]) -> None:
        registered = _REGISTERED_CONTINUATION_SPECS.get(key)
        if registered is not None and registered[0] is reference:
            _REGISTERED_CONTINUATION_SPECS.pop(key, None)

    _REGISTERED_CONTINUATION_SPECS[key] = (weakref.ref(spec, _drop), spec.digest)
    return spec


def _require_registered_continuation_spec(spec: ContinuationSpec) -> str:
    if spec.__class__ is not ContinuationSpec:
        raise TypeError("bound runner requires an exact ContinuationSpec")
    registered = _REGISTERED_CONTINUATION_SPECS.get(id(spec))
    if registered is None or registered[0]() is not spec:
        raise ValueError("continuation spec is not adapter-registered")
    spec.__post_init__()
    if registered[1] != spec.digest:
        raise ValueError("continuation spec changed after source issuance")
    return registered[1]


def _mint_source_controlled_continuation_spec(
    *,
    spec_id: str,
    query_id: str,
    policy_id: str,
    renderer_id: str,
    renderer_version: str,
    result_mode: str,
    required_hidden_carriers: Sequence[str],
    result_columns: Sequence[TypedRootSchemaColumn],
    ordered_keys: Sequence[str],
    row_limit: int | None,
    continuation_sql: str,
) -> ContinuationSpec:
    """Private adapter seam for selecting one finite continuation contract."""

    return _register_continuation_spec(ContinuationSpec(
        spec_id=spec_id,
        query_id=query_id,
        policy_id=policy_id,
        renderer_id=renderer_id,
        renderer_version=renderer_version,
        result_mode=result_mode,
        required_hidden_carriers=tuple(required_hidden_carriers),
        result_columns=tuple(result_columns),
        ordered_keys=tuple(ordered_keys),
        row_limit=row_limit,
        continuation_sql=continuation_sql,
        _construction_token=_BOUND_RUNNER_TOKEN,
    ))


def _strict_core_sql(strict_result: StrictPlanningResult) -> str:
    _require_registered_strict_planning_result(strict_result)
    if strict_result.draft is None:
        raise ValueError("complete runner requires a strict core")
    core_sql = strict_result.draft.sql_text.strip().rstrip(";")
    if not core_sql:
        raise ValueError("complete runner strict core is empty")
    return core_sql


def _require_draft_semantic_continuation_scope(
    draft: Any,
    continuation_spec: ContinuationSpec,
    *,
    occurrence_id: str,
) -> str | None:
    """Consume a conditional core only with its exact registered context.

    The scope is data, not the proof issuer. Front-end certificate replay must
    separately establish the necessity/descriptor identities it names.
    """
    scope = draft.continuation_scope
    if scope is None:
        return None
    draft.assert_identity_intact()
    _require_registered_continuation_spec(continuation_spec)
    if (
        scope.occurrence_id != occurrence_id
        or scope.continuation_digest != continuation_spec.digest
        or scope.continuation_sql_digest != continuation_spec.continuation_sql_digest
        or scope.result_contract_digest != continuation_spec.result_contract_digest
    ):
        raise ValueError("strict core semantic continuation scope does not match its consumer")
    return scope.digest


def _closed_pc_scope_fragment(strict_result: StrictPlanningResult,
                              core_sql: str, continuation_sql: str):
    """Use the original owned IR/fragment, with an explicit catalog premise.

    The optional fact is issued by the trusted adapter from its canonical
    finite source and observed builtin catalog. It grants no admission or
    runtime capability. All original schema/EXPLAIN/binding guards still run.
    """
    query = strict_result.query_result
    if query is None or len(query.effective_occurrence_goals) != 1:
        return None
    nodes = walk(query.bound_ir)
    if any(type(node) not in {Root, Project, Select, ScanProtected} for node in nodes):
        return None
    scans = tuple(node for node in nodes if type(node) is ScanProtected)
    if len(scans) != 1 or scans[0].template_slot != "barrier_filter_query_v1":
        return None
    goal = query.effective_occurrence_goals.get(scans[0].occurrence_id)
    if goal is None or goal.problem.gamma_snapshot is None:
        return None
    gamma = goal.problem.gamma_snapshot
    subject = policy_subject_digest(goal.problem)
    if not all(gamma.has_pass(kind, subject_digest=subject) for kind in (
            "pc_scope_lift_builtin_safe", "exact_policy_safe", "safe_query_predicate")):
        return None
    if any(node.pred_kind != "logical_target" or not safe_pc_predicate(node.pred, "sel")
           for node in nodes if type(node) is Select):
        return None
    fragment = emit_sql(query.bound_ir, query.emit_context)
    if (fragment.render_core().strip().rstrip(";") != core_sql
            or len(fragment.ctes) != 1 or fragment.validation_statements
            or fragment.validation_recipes):
        return None
    name = closed_pc_cte_name(fragment.ctes[0])
    if name is None or not continuation_avoids_name(continuation_sql, name):
        return None
    return fragment


def _compose_exact_bound_runner_sql(
    strict_result: StrictPlanningResult,
    continuation_sql: str,
    *,
    materialized: bool = True,
) -> str:
    """Compose the only exact F1 runner form accepted by the shared seam."""

    if (
        type(continuation_sql) is not str  # noqa: E721
        or not continuation_sql
        or continuation_sql != continuation_sql.rstrip()
    ):
        raise ValueError("complete runner continuation SQL is malformed")
    if type(materialized) is not bool:  # noqa: E721
        raise TypeError("bound runner materialized flag must be bool")
    if (
        strict_result.draft is not None
        and strict_result.draft.continuation_scope is not None
        and strict_result.draft.continuation_scope.continuation_sql_digest
        != _digest({"exact_continuation_sql": continuation_sql})
    ):
        raise ValueError("composition changed a required semantic continuation SQL")
    if (
        not materialized
        and len(
            re.findall(
                r"\bcaprls_access_root\b",
                continuation_sql,
                flags=re.IGNORECASE,
            )
        )
        != 1
    ):
        raise ValueError(
            "NOT MATERIALIZED access root requires one continuation reference"
        )
    wrapper = "MATERIALIZED" if materialized else "NOT MATERIALIZED"
    core_sql = _strict_core_sql(strict_result)
    fragment = _closed_pc_scope_fragment(strict_result, core_sql, continuation_sql)
    prefix = ""
    if fragment is not None:
        prefix = fragment.ctes[0] + ",\n"
        core_sql = fragment.body
    return (
        "WITH " + prefix + "caprls_access_root AS "
        + wrapper
        + " (\n"
        + core_sql
        + "\n)"
        + continuation_sql
    )


def _bound_runner_access_root_is_materialized(runner_sql: str) -> bool:
    value = decode_access_root_materialized(runner_sql)
    if value is None:
        raise ValueError("bound runner is not a canonical complete access-root composition")
    return value


@dataclass(frozen=True)
class TypedRootPhysicalObservation:
    """Validator-observed physical facts for one completed root.

    ``None`` means that the adapter did not observe the dimension.  It is
    never normalized to ``()``: an explicit empty tuple is the distinct,
    known-empty value.
    """

    delivered_order: tuple[str, ...] | None
    observable_properties: tuple[tuple[str, str], ...] | None
    cost_relevant_properties: tuple[tuple[str, str], ...] | None
    hidden_attrs_and_carriers: tuple[str, ...] | None
    observable_coverage: tuple[str, ...] | None
    rid_domain: str | None
    rid_surrogate_col: str | None
    rid_carrier: str | None
    rid_materialized: bool | None

    def __post_init__(self) -> None:
        if self.delivered_order is not None:
            order = tuple(str(value) for value in self.delivered_order)
            if any(not value for value in order):
                raise ValueError("observed delivered order contains an empty key")
            object.__setattr__(self, "delivered_order", order)
        for field_name in ("observable_properties", "cost_relevant_properties"):
            value = getattr(self, field_name)
            if value is None:
                continue
            entries = tuple(value)
            try:
                mapped = dict(entries)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{field_name} must be a typed mapping") from exc
            normalized = _string_mapping(mapped)
            if normalized is None or len(normalized) != len(entries):
                raise ValueError(f"{field_name} must be a unique typed mapping")
            object.__setattr__(self, field_name, normalized)
        for field_name in ("hidden_attrs_and_carriers", "observable_coverage"):
            value = getattr(self, field_name)
            if value is None:
                continue
            normalized_values = tuple(sorted(set(str(item) for item in value)))
            if any(not item for item in normalized_values):
                raise ValueError(f"{field_name} contains an empty identity")
            object.__setattr__(self, field_name, normalized_values)
        for field_name in ("rid_domain", "rid_surrogate_col", "rid_carrier"):
            value = getattr(self, field_name)
            if value is not None and (type(value) is not str or not value):  # noqa: E721
                raise ValueError(f"{field_name} must be a nonempty exact string")
        if self.rid_materialized is not None and type(self.rid_materialized) is not bool:  # noqa: E721
            raise TypeError("rid_materialized must be an observed bool or None")

    @property
    def complete(self) -> bool:
        return (
            self.delivered_order is not None
            and self.observable_properties is not None
            and self.cost_relevant_properties is not None
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "delivered_order": (
                None if self.delivered_order is None else list(self.delivered_order)
            ),
            "observable_properties": (
                None
                if self.observable_properties is None
                else dict(self.observable_properties)
            ),
            "cost_relevant_properties": (
                None
                if self.cost_relevant_properties is None
                else dict(self.cost_relevant_properties)
            ),
            "hidden_attrs_and_carriers": (
                None
                if self.hidden_attrs_and_carriers is None
                else list(self.hidden_attrs_and_carriers)
            ),
            "observable_coverage": (
                None
                if self.observable_coverage is None
                else list(self.observable_coverage)
            ),
            "rid": {
                "domain": self.rid_domain,
                "surrogate_col": self.rid_surrogate_col,
                "carrier": self.rid_carrier,
                "materialized": self.rid_materialized,
            },
        }


@dataclass(frozen=True)
class PlanningBatchIdentity:
    """Common environment identity for one read-only prospective batch."""

    batch_id: str
    snapshot_digest: str
    database_identity_digest: str
    session_contract_digest: str
    guc_digest: str
    cost_model_version: str
    catalog_digest: str
    gamma_digest: str
    registry_digest: str
    registry_scope_identity: str
    registry_manifest_digest: str
    admitted_candidate_inventory_digest: str
    target_digest: str
    logical_target_id: str
    rho_digest: str
    emit_context_digest: str
    obligation_graph_digest: str
    evidence_role: str

    def __post_init__(self) -> None:
        if not self.batch_id or not self.cost_model_version:
            raise ValueError("planning batch requires batch and cost-model identities")
        if self.evidence_role not in {
            "production_validator",
            "isolated_test_non_promotable",
        }:
            raise ValueError("planning batch evidence role is invalid")
        for label, value in (
            ("snapshot_digest", self.snapshot_digest),
            ("database_identity_digest", self.database_identity_digest),
            ("session_contract_digest", self.session_contract_digest),
            ("guc_digest", self.guc_digest),
            ("catalog_digest", self.catalog_digest),
            ("gamma_digest", self.gamma_digest),
            ("registry_digest", self.registry_digest),
            ("registry_scope_identity", self.registry_scope_identity),
            ("registry_manifest_digest", self.registry_manifest_digest),
            (
                "admitted_candidate_inventory_digest",
                self.admitted_candidate_inventory_digest,
            ),
            ("target_digest", self.target_digest),
            ("logical_target_id", self.logical_target_id),
            ("rho_digest", self.rho_digest),
            ("emit_context_digest", self.emit_context_digest),
            ("obligation_graph_digest", self.obligation_graph_digest),
        ):
            _require_digest(value, label)

    @property
    def environment_digest(self) -> str:
        return _digest(self.to_dict())

    def to_dict(self) -> dict[str, str]:
        return {
            "batch_id": self.batch_id,
            "snapshot_digest": self.snapshot_digest,
            "database_identity_digest": self.database_identity_digest,
            "session_contract_digest": self.session_contract_digest,
            "guc_digest": self.guc_digest,
            "cost_model_version": self.cost_model_version,
            "catalog_digest": self.catalog_digest,
            "gamma_digest": self.gamma_digest,
            "registry_digest": self.registry_digest,
            "registry_scope_identity": self.registry_scope_identity,
            "registry_manifest_digest": self.registry_manifest_digest,
            "admitted_candidate_inventory_digest": self.admitted_candidate_inventory_digest,
            "target_digest": self.target_digest,
            "logical_target_id": self.logical_target_id,
            "rho_digest": self.rho_digest,
            "emit_context_digest": self.emit_context_digest,
            "obligation_graph_digest": self.obligation_graph_digest,
            "evidence_role": self.evidence_role,
        }


@dataclass(frozen=True)
class BoundRunnerIdentity:
    """Adapter-owned identity of the exact semantic SQL costed by F1."""

    strict_result: StrictPlanningResult = field(repr=False, compare=False)
    strict_result_identity_seal: str
    plan_id: str
    template_id: str
    query_id: str
    policy_id: str
    case_owner_identity_digest: str
    strict_complete_root_plan_digest: str
    strict_exact_sql_digest: str
    strict_sql_ast_digest: str
    continuation_spec: ContinuationSpec
    renderer_id: str
    renderer_version: str
    ordered_keys: tuple[str, ...]
    row_limit: int | None
    strict_core_sql_digest: str
    continuation_sql_digest: str
    continuation_digest: str
    result_contract_digest: str
    runner_sql: str = field(repr=False)
    runner_sql_digest: str
    session_contract_digest: str
    registry_digest: str
    snapshot_digest: str
    database_identity_digest: str
    catalog_digest: str
    identity_digest: str
    _construction_token: object | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._construction_token is not _BOUND_RUNNER_TOKEN:
            raise ValueError("bound runner identity must be adapter-owned")
        strict_seal = _require_registered_strict_planning_result(self.strict_result)
        provenance = _require_forced_root_provenance(self.strict_result)
        strict = self.strict_result
        if strict.draft is None:
            raise ValueError("bound runner requires a complete strict draft")
        if self.continuation_spec.__class__ is not ContinuationSpec:
            raise TypeError("bound runner requires a source-controlled continuation")
        _require_registered_continuation_spec(self.continuation_spec)
        _require_draft_semantic_continuation_scope(
            strict.draft, self.continuation_spec, occurrence_id=provenance.occurrence_id,
        )
        if type(self.runner_sql) is not str or not self.runner_sql.strip():  # noqa: E721
            raise ValueError("bound runner requires exact nonempty SQL")
        canonical_runner_sql = _compose_exact_bound_runner_sql(
            strict,
            self.continuation_spec.continuation_sql,
            materialized=_bound_runner_access_root_is_materialized(
                self.runner_sql
            ),
        )
        if self.runner_sql != canonical_runner_sql:
            raise ValueError("bound runner differs from canonical strict-core composition")
        for label, value in (
            ("strict_result_identity_seal", self.strict_result_identity_seal),
            ("case_owner_identity_digest", self.case_owner_identity_digest),
            (
                "strict_complete_root_plan_digest",
                self.strict_complete_root_plan_digest,
            ),
            ("strict_exact_sql_digest", self.strict_exact_sql_digest),
            ("strict_sql_ast_digest", self.strict_sql_ast_digest),
            ("strict_core_sql_digest", self.strict_core_sql_digest),
            ("continuation_sql_digest", self.continuation_sql_digest),
            ("continuation_digest", self.continuation_digest),
            ("result_contract_digest", self.result_contract_digest),
            ("runner_sql_digest", self.runner_sql_digest),
            ("session_contract_digest", self.session_contract_digest),
            ("registry_digest", self.registry_digest),
            ("snapshot_digest", self.snapshot_digest),
            ("database_identity_digest", self.database_identity_digest),
            ("catalog_digest", self.catalog_digest),
            ("identity_digest", self.identity_digest),
        ):
            _require_digest(value, label)
        expected_without_identity = {
            "strict_result_identity_seal": strict_seal,
            "plan_id": strict.draft.plan_id,
            "template_id": provenance.template_id,
            "query_id": self.continuation_spec.query_id,
            "policy_id": self.continuation_spec.policy_id,
            "case_owner_identity_digest": self.case_owner_identity_digest,
            "strict_complete_root_plan_digest": strict.draft.bound_ir_digest,
            "strict_exact_sql_digest": strict.draft.exact_sql_digest,
            "strict_sql_ast_digest": strict.draft.full_ast_digest,
            "renderer_id": self.continuation_spec.renderer_id,
            "renderer_version": self.continuation_spec.renderer_version,
            "ordered_keys": self.continuation_spec.ordered_keys,
            "row_limit": self.continuation_spec.row_limit,
            "strict_core_sql_digest": _digest(
                {"strict_core_sql": _strict_core_sql(strict)}
            ),
            "continuation_sql_digest": (
                self.continuation_spec.continuation_sql_digest
            ),
            "continuation_digest": self.continuation_spec.digest,
            "result_contract_digest": self.continuation_spec.result_contract_digest,
            "runner_sql_digest": _digest({"exact_runner_sql": self.runner_sql}),
            "session_contract_digest": strict.draft.session_contract.digest,
            "registry_digest": strict.draft.registry_digest,
            "snapshot_digest": self.snapshot_digest,
            "database_identity_digest": self.database_identity_digest,
            "catalog_digest": self.catalog_digest,
        }
        actual_without_identity = {
            key: getattr(self, key) for key in expected_without_identity
        }
        if actual_without_identity != expected_without_identity:
            raise ValueError("bound runner is detached from strict or continuation identity")
        if self.identity_digest != _digest(expected_without_identity):
            raise ValueError("bound runner identity digest mismatch")

    @property
    def planning_environment_digest(self) -> str:
        return _digest(
            {
                "session_contract_digest": self.session_contract_digest,
                "registry_digest": self.registry_digest,
                "snapshot_digest": self.snapshot_digest,
                "database_identity_digest": self.database_identity_digest,
                "catalog_digest": self.catalog_digest,
                "case_owner_identity_digest": self.case_owner_identity_digest,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "strict_result_identity_seal": self.strict_result_identity_seal,
            "plan_id": self.plan_id,
            "template_id": self.template_id,
            "query_id": self.query_id,
            "policy_id": self.policy_id,
            "case_owner_identity_digest": self.case_owner_identity_digest,
            "strict_complete_root_plan_digest": self.strict_complete_root_plan_digest,
            "strict_exact_sql_digest": self.strict_exact_sql_digest,
            "strict_sql_ast_digest": self.strict_sql_ast_digest,
            "renderer_id": self.renderer_id,
            "renderer_version": self.renderer_version,
            "ordered_keys": list(self.ordered_keys),
            "row_limit": self.row_limit,
            "strict_core_sql_digest": self.strict_core_sql_digest,
            "continuation_sql_digest": self.continuation_sql_digest,
            "continuation": self.continuation_spec.to_dict(),
            "continuation_digest": self.continuation_digest,
            "result_contract_digest": self.result_contract_digest,
            "runner_sql": self.runner_sql,
            "runner_sql_digest": self.runner_sql_digest,
            "session_contract_digest": self.session_contract_digest,
            "registry_digest": self.registry_digest,
            "snapshot_digest": self.snapshot_digest,
            "database_identity_digest": self.database_identity_digest,
            "catalog_digest": self.catalog_digest,
            "planning_environment_digest": self.planning_environment_digest,
            "identity_digest": self.identity_digest,
        }


def _mint_bound_runner_identity(
    strict_result: StrictPlanningResult,
    *,
    continuation_spec: ContinuationSpec,
    runner_sql: str,
    case_owner_identity_digest: str,
    snapshot_digest: str,
    database_identity_digest: str,
    catalog_digest: str,
    access_root_materialized: bool = True,
) -> BoundRunnerIdentity:
    """Mint the exact semantic runner after observing its planning environment."""

    strict_seal = _require_registered_strict_planning_result(strict_result)
    provenance = _require_forced_root_provenance(strict_result)
    if strict_result.draft is None:
        raise ValueError("bound runner requires a complete strict draft")
    draft = strict_result.draft
    _require_registered_continuation_spec(continuation_spec)
    _require_draft_semantic_continuation_scope(
        draft, continuation_spec, occurrence_id=provenance.occurrence_id,
    )
    canonical_runner_sql = _compose_exact_bound_runner_sql(
        strict_result,
        continuation_spec.continuation_sql,
        materialized=access_root_materialized,
    )
    if runner_sql != canonical_runner_sql:
        raise ValueError("runner SQL is not the canonical complete composition")
    runner_digest = _digest({"exact_runner_sql": canonical_runner_sql})
    payload = {
        "strict_result_identity_seal": strict_seal,
        "plan_id": draft.plan_id,
        "template_id": provenance.template_id,
        "query_id": continuation_spec.query_id,
        "policy_id": continuation_spec.policy_id,
        "case_owner_identity_digest": case_owner_identity_digest,
        "strict_complete_root_plan_digest": draft.bound_ir_digest,
        "strict_exact_sql_digest": draft.exact_sql_digest,
        "strict_sql_ast_digest": draft.full_ast_digest,
        "renderer_id": continuation_spec.renderer_id,
        "renderer_version": continuation_spec.renderer_version,
        "ordered_keys": continuation_spec.ordered_keys,
        "row_limit": continuation_spec.row_limit,
        "strict_core_sql_digest": _digest(
            {"strict_core_sql": _strict_core_sql(strict_result)}
        ),
        "continuation_sql_digest": continuation_spec.continuation_sql_digest,
        "continuation_digest": continuation_spec.digest,
        "result_contract_digest": continuation_spec.result_contract_digest,
        "runner_sql_digest": runner_digest,
        "session_contract_digest": draft.session_contract.digest,
        "registry_digest": draft.registry_digest,
        "snapshot_digest": snapshot_digest,
        "database_identity_digest": database_identity_digest,
        "catalog_digest": catalog_digest,
    }
    return BoundRunnerIdentity(
        strict_result=strict_result,
        continuation_spec=continuation_spec,
        runner_sql=canonical_runner_sql,
        identity_digest=_digest(payload),
        _construction_token=_BOUND_RUNNER_TOKEN,
        **payload,
    )


@dataclass(frozen=True)
class TypedRootSchemaReceipt:
    """Owner-minted actual root schema, bound to one strict root and snapshot."""

    strict_result: StrictPlanningResult = field(repr=False, compare=False)
    strict_result_identity_seal: str
    plan_id: str
    complete_root_plan_digest: str
    exact_sql_digest: str
    snapshot_digest: str
    columns: tuple[TypedRootSchemaColumn, ...]
    receipt_digest: str
    _construction_token: object | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._construction_token is not _PLANNING_EVIDENCE_TOKEN:
            raise ValueError("typed root schema receipt must be validator-owned")
        strict_seal = _require_registered_strict_planning_result(self.strict_result)
        strict = self.strict_result
        if strict.draft is None:
            raise ValueError("typed root schema receipt requires a strict draft")
        columns = tuple(self.columns)
        if any(item.__class__ is not TypedRootSchemaColumn for item in columns):
            raise TypeError("typed root schema receipt has an invalid column")
        if tuple(item.ordinal for item in columns) != tuple(range(len(columns))):
            raise ValueError("typed root schema receipt ordinals must be contiguous")
        if len({item.name for item in columns}) != len(columns):
            raise ValueError("typed root schema receipt column names must be unique")
        object.__setattr__(self, "columns", columns)
        for label, value in (
            ("strict_result_identity_seal", self.strict_result_identity_seal),
            ("complete_root_plan_digest", self.complete_root_plan_digest),
            ("exact_sql_digest", self.exact_sql_digest),
            ("snapshot_digest", self.snapshot_digest),
            ("receipt_digest", self.receipt_digest),
        ):
            _require_digest(value, label)
        expected = _schema_receipt_digest(
            strict_result_identity_seal=strict_seal,
            plan_id=strict.draft.plan_id,
            complete_root_plan_digest=strict.draft.bound_ir_digest,
            exact_sql_digest=strict.draft.exact_sql_digest,
            snapshot_digest=self.snapshot_digest,
            columns=columns,
        )
        if (
            self.strict_result_identity_seal != strict_seal
            or self.plan_id != strict.draft.plan_id
            or self.complete_root_plan_digest != strict.draft.bound_ir_digest
            or self.exact_sql_digest != strict.draft.exact_sql_digest
            or self.receipt_digest != expected
        ):
            raise ValueError("typed root schema receipt is detached from its strict root")

    def to_dict(self) -> dict[str, Any]:
        return {
            "strict_result_identity_seal": self.strict_result_identity_seal,
            "plan_id": self.plan_id,
            "complete_root_plan_digest": self.complete_root_plan_digest,
            "exact_sql_digest": self.exact_sql_digest,
            "snapshot_digest": self.snapshot_digest,
            "columns": [item.to_dict() for item in self.columns],
            "receipt_digest": self.receipt_digest,
        }


@dataclass(frozen=True)
class TypedRunnerResultSchemaReceipt:
    """Nonexecuting describe receipt for the exact semantic runner result."""

    bound_runner: BoundRunnerIdentity = field(repr=False, compare=False)
    bound_runner_identity_digest: str
    plan_id: str
    snapshot_digest: str
    result_contract_digest: str
    columns: tuple[TypedRootSchemaColumn, ...]
    receipt_digest: str
    _construction_token: object | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._construction_token is not _PLANNING_EVIDENCE_TOKEN:
            raise ValueError("runner result schema receipt must be validator-owned")
        if self.bound_runner.__class__ is not BoundRunnerIdentity:
            raise TypeError("runner result schema requires a bound runner")
        self.bound_runner.__post_init__()
        columns = tuple(self.columns)
        if any(item.__class__ is not TypedRootSchemaColumn for item in columns):
            raise TypeError("runner result schema receipt has an invalid column")
        object.__setattr__(self, "columns", columns)
        for label, value in (
            ("bound_runner_identity_digest", self.bound_runner_identity_digest),
            ("snapshot_digest", self.snapshot_digest),
            ("result_contract_digest", self.result_contract_digest),
            ("receipt_digest", self.receipt_digest),
        ):
            _require_digest(value, label)
        expected_columns = self.bound_runner.continuation_spec.result_columns
        expected = _runner_schema_receipt_digest(
            bound_runner_identity_digest=self.bound_runner.identity_digest,
            plan_id=self.bound_runner.plan_id,
            snapshot_digest=self.bound_runner.snapshot_digest,
            result_contract_digest=(
                self.bound_runner.continuation_spec.result_contract_digest
            ),
            columns=expected_columns,
        )
        if (
            self.bound_runner_identity_digest != self.bound_runner.identity_digest
            or self.plan_id != self.bound_runner.plan_id
            or self.snapshot_digest != self.bound_runner.snapshot_digest
            or self.result_contract_digest
            != self.bound_runner.continuation_spec.result_contract_digest
            or columns != expected_columns
            or self.receipt_digest != expected
        ):
            raise ValueError("runner result schema conflicts with frozen contract")

    def to_dict(self) -> dict[str, Any]:
        return {
            "bound_runner_identity_digest": self.bound_runner_identity_digest,
            "plan_id": self.plan_id,
            "snapshot_digest": self.snapshot_digest,
            "result_contract_digest": self.result_contract_digest,
            "columns": [item.to_dict() for item in self.columns],
            "receipt_digest": self.receipt_digest,
        }


def _runner_schema_receipt_digest(
    *,
    bound_runner_identity_digest: str,
    plan_id: str,
    snapshot_digest: str,
    result_contract_digest: str,
    columns: Sequence[TypedRootSchemaColumn],
) -> str:
    return _digest(
        {
            "bound_runner_identity_digest": bound_runner_identity_digest,
            "plan_id": plan_id,
            "snapshot_digest": snapshot_digest,
            "result_contract_digest": result_contract_digest,
            "columns": [item.to_dict() for item in columns],
        }
    )


def _schema_receipt_digest(
    *,
    strict_result_identity_seal: str,
    plan_id: str,
    complete_root_plan_digest: str,
    exact_sql_digest: str,
    snapshot_digest: str,
    columns: Sequence[TypedRootSchemaColumn],
) -> str:
    return _digest(
        {
            "strict_result_identity_seal": strict_result_identity_seal,
            "plan_id": plan_id,
            "complete_root_plan_digest": complete_root_plan_digest,
            "exact_sql_digest": exact_sql_digest,
            "snapshot_digest": snapshot_digest,
            "columns": [item.to_dict() for item in columns],
        }
    )


@dataclass(frozen=True)
class _PlanningRootEvidence:
    strict_result: StrictPlanningResult = field(repr=False, compare=False)
    bound_runner: BoundRunnerIdentity = field(repr=False, compare=False)
    strict_result_identity_seal: str
    plan_id: str
    complete_root_plan_digest: str
    explain_plan_digest: str
    prospective_total_cost: float
    sql_ast_digest: str
    certificate_digest: str
    static_verification_digest: str
    exact_sql_digest: str
    schema_receipt: TypedRootSchemaReceipt
    runner_schema_receipt: TypedRunnerResultSchemaReceipt
    physical_observation: TypedRootPhysicalObservation
    _construction_token: object | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._construction_token is not _PLANNING_EVIDENCE_TOKEN:
            raise ValueError("planning root evidence must be adapter-owned")
        strict_seal = _require_registered_strict_planning_result(self.strict_result)
        strict = self.strict_result
        _require_forced_root_provenance(strict)
        if strict.draft is None or strict.envelope is None:
            raise ValueError("planning root evidence requires the complete strict chain")
        if self.schema_receipt.strict_result is not strict:
            raise ValueError("planning root evidence has a detached schema receipt")
        if (
            self.bound_runner.__class__ is not BoundRunnerIdentity
            or self.bound_runner.strict_result is not strict
            or self.runner_schema_receipt.__class__
            is not TypedRunnerResultSchemaReceipt
            or self.runner_schema_receipt.bound_runner is not self.bound_runner
        ):
            raise ValueError("planning evidence has a detached semantic runner")
        self.bound_runner.__post_init__()
        self.runner_schema_receipt.__post_init__()
        if self.physical_observation.__class__ is not TypedRootPhysicalObservation:
            raise TypeError("planning root evidence requires typed physical observations")
        for label, value in (
            ("strict_result_identity_seal", self.strict_result_identity_seal),
            ("complete_root_plan_digest", self.complete_root_plan_digest),
            ("explain_plan_digest", self.explain_plan_digest),
            ("sql_ast_digest", self.sql_ast_digest),
            ("certificate_digest", self.certificate_digest),
            ("static_verification_digest", self.static_verification_digest),
            ("exact_sql_digest", self.exact_sql_digest),
        ):
            _require_digest(value, label)
        if (
            not isinstance(self.prospective_total_cost, (int, float))
            or isinstance(self.prospective_total_cost, bool)
            or not math.isfinite(float(self.prospective_total_cost))
            or float(self.prospective_total_cost) < 0
        ):
            raise ValueError("planning root evidence requires finite nonnegative cost")
        if (
            self.strict_result_identity_seal != strict_seal
            or self.plan_id != strict.draft.plan_id
            or self.complete_root_plan_digest != self.bound_runner.identity_digest
            or self.sql_ast_digest != self.bound_runner.runner_sql_digest
            or self.certificate_digest != strict.envelope.digest
            or self.exact_sql_digest != self.bound_runner.runner_sql_digest
        ):
            raise ValueError("planning root evidence is detached from its bound runner")
        identity_reasons = _strict_root_observation_rejection_reasons(
            strict,
            self.schema_receipt.columns,
            self.physical_observation,
        )
        if identity_reasons:
            raise ValueError(
                "planning root evidence conflicts with strict root identity:"
                + ",".join(identity_reasons)
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "strict_result_identity_seal": self.strict_result_identity_seal,
            "plan_id": self.plan_id,
            "complete_root_plan_digest": self.complete_root_plan_digest,
            "explain_plan_digest": self.explain_plan_digest,
            "prospective_total_cost": float(self.prospective_total_cost),
            "sql_ast_digest": self.sql_ast_digest,
            "certificate_digest": self.certificate_digest,
            "static_verification_digest": self.static_verification_digest,
            "exact_sql_digest": self.exact_sql_digest,
            "schema_receipt_digest": self.schema_receipt.receipt_digest,
            "bound_runner": self.bound_runner.to_dict(),
            "runner_schema_receipt": self.runner_schema_receipt.to_dict(),
            "physical_observation": self.physical_observation.to_dict(),
        }


@dataclass(frozen=True)
class PlanningFrontierEntry:
    """Owner-sealed classification of one freshly admitted leaf alternative."""

    occurrence_id: str
    template_id: str
    candidate_digest: str
    status: str
    plan_id: str | None
    forced_provenance_identity: str | None
    reasons: tuple[str, ...]
    _construction_token: object | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._construction_token is not _PLANNING_EVIDENCE_TOKEN:
            raise ValueError("planning frontier classification must be adapter-owned")
        if not self.occurrence_id or not self.template_id:
            raise ValueError("planning frontier entry requires occurrence and template")
        _require_digest(self.candidate_digest, "candidate_digest")
        if self.status not in {
            "completed_cost_eligible",
            "structural_rejection",
            "evidence_failure",
        }:
            raise ValueError("planning frontier status is invalid")
        reasons = tuple(sorted(set(str(item) for item in self.reasons)))
        if any(not item for item in reasons):
            raise ValueError("planning frontier reasons cannot be empty")
        object.__setattr__(self, "reasons", reasons)
        if self.status == "completed_cost_eligible":
            if not self.plan_id or not self.forced_provenance_identity or reasons:
                raise ValueError("completed frontier entry has invalid evidence bindings")
        else:
            if self.status == "structural_rejection" and self.plan_id is not None:
                raise ValueError("structural rejection cannot have a completed plan ID")
            if not reasons:
                raise ValueError("failed frontier entry requires structured reasons")
        if self.forced_provenance_identity is not None:
            _require_digest(
                self.forced_provenance_identity,
                "forced_provenance_identity",
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "occurrence_id": self.occurrence_id,
            "template_id": self.template_id,
            "candidate_digest": self.candidate_digest,
            "status": self.status,
            "plan_id": self.plan_id,
            "forced_provenance_identity": self.forced_provenance_identity,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class PlanningEvidenceBatch:
    """One adapter-owned, common-snapshot prospective root evidence pool."""

    identity: PlanningBatchIdentity
    roots: tuple[_PlanningRootEvidence, ...]
    frontier_entries: tuple[PlanningFrontierEntry, ...]
    frontier_complete: bool
    batch_digest: str
    _construction_token: object | None = field(default=None, repr=False, compare=False)

    @property
    def cost_evidence_complete(self) -> bool:
        return self.frontier_complete and not any(
            item.status == "evidence_failure" for item in self.frontier_entries
        )

    @property
    def completed_plan_ids(self) -> tuple[str, ...]:
        return tuple(item.plan_id for item in self.roots)

    def __post_init__(self) -> None:
        if self._construction_token is not _PLANNING_EVIDENCE_TOKEN:
            raise ValueError("planning evidence batch must be adapter-owned")
        if self.identity.__class__ is not PlanningBatchIdentity:
            raise TypeError("planning evidence batch requires a typed identity")
        roots = tuple(sorted(self.roots, key=lambda item: item.plan_id))
        if any(item.__class__ is not _PlanningRootEvidence for item in roots):
            raise ValueError("planning evidence batch requires typed root evidence")
        if len({item.plan_id for item in roots}) != len(roots):
            raise ValueError("planning evidence batch contains duplicate roots")
        object.__setattr__(self, "roots", roots)
        entries = tuple(
            sorted(
                self.frontier_entries,
                key=lambda item: (
                    item.occurrence_id,
                    item.template_id,
                    item.candidate_digest,
                ),
            )
        )
        if not entries or any(item.__class__ is not PlanningFrontierEntry for item in entries):
            raise ValueError("planning evidence batch requires a typed frontier trace")
        if type(self.frontier_complete) is not bool:  # noqa: E721
            raise TypeError("planning frontier completeness must be boolean")
        entry_keys = tuple(
            (item.occurrence_id, item.template_id, item.candidate_digest)
            for item in entries
        )
        if len(set(entry_keys)) != len(entry_keys):
            raise ValueError("planning frontier classifies a candidate more than once")
        occurrence_ids = {item.occurrence_id for item in entries}
        if len(occurrence_ids) != 1:
            raise ValueError("finite forced-root batch requires one occurrence inventory")
        occurrence_id = next(iter(occurrence_ids))
        inventory = tuple((item.template_id, item.candidate_digest) for item in entries)
        if (
            _forced_inventory_digest(occurrence_id, inventory)
            != self.identity.admitted_candidate_inventory_digest
        ):
            raise ValueError("planning frontier does not match admitted inventory digest")
        object.__setattr__(self, "frontier_entries", entries)
        completed_items = tuple(
            item for item in entries if item.status == "completed_cost_eligible"
        )
        completed_entries = {
            item.plan_id: item
            for item in completed_items
        }
        if len(completed_entries) != len(completed_items):
            raise ValueError("planning frontier contains duplicate completed plan IDs")
        if set(completed_entries) != {item.plan_id for item in roots}:
            raise ValueError("completed root evidence does not exactly match frontier trace")
        for item in roots:
            strict = item.strict_result
            assert strict.draft is not None
            provenance = _require_forced_root_provenance(strict)
            completed_entry = completed_entries[item.plan_id]
            if (
                strict.draft.session_contract.digest != self.identity.session_contract_digest
                or _digest(dict(strict.draft.session_contract.gucs))
                != self.identity.guc_digest
                or strict.draft.registry_digest != self.identity.registry_digest
                or provenance.registry_digest != self.identity.registry_digest
                or provenance.registry_scope_identity
                != self.identity.registry_scope_identity
                or provenance.registry_manifest_digest
                != self.identity.registry_manifest_digest
                or provenance.admitted_candidate_inventory_digest
                != self.identity.admitted_candidate_inventory_digest
                or provenance.admitted_candidate_inventory != inventory
                or item.schema_receipt.snapshot_digest != self.identity.snapshot_digest
                or item.bound_runner.snapshot_digest != self.identity.snapshot_digest
                or item.bound_runner.database_identity_digest
                != self.identity.database_identity_digest
                or item.bound_runner.catalog_digest != self.identity.catalog_digest
                or item.bound_runner.session_contract_digest
                != self.identity.session_contract_digest
                or item.bound_runner.registry_digest != self.identity.registry_digest
                or item.runner_schema_receipt.snapshot_digest
                != self.identity.snapshot_digest
                or strict.envelope is None
                or _strict_gamma_digest(strict) != self.identity.gamma_digest
                or _strict_logical_target_digest(strict) != self.identity.target_digest
                or _strict_single_logical_target_id(strict)
                != self.identity.logical_target_id
                or strict.envelope.rho_digest != self.identity.rho_digest
                or strict.envelope.emit_context_digest != self.identity.emit_context_digest
                or strict.envelope.obligation_graph_digest
                != self.identity.obligation_graph_digest
                or completed_entry.forced_provenance_identity
                != provenance.identity_digest
                or completed_entry.template_id != provenance.template_id
            ):
                raise ValueError("planning root does not share the batch environment")
            if self.identity.evidence_role == "production_validator":
                if provenance.registry_evidence_role not in {
                    "source_controlled_canonical",
                    "production_manifest",
                }:
                    raise ValueError("production batch rejects non-promotable registry scope")
                for occurrence_goal in strict.query_result.effective_occurrence_goals.values():
                    problem = occurrence_goal.problem
                    if (
                        problem.planning_execution_class != "production_normal"
                        or not problem.require_typed_admission
                    ):
                        raise ValueError(
                            "production batch requires production-normal typed admission"
                        )
        _require_digest(self.batch_digest, "batch_digest")
        expected = _planning_batch_digest(
            self.identity,
            roots,
            entries,
            self.frontier_complete,
        )
        if self.batch_digest != expected:
            raise ValueError("planning evidence batch digest mismatch")

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_dict(),
            "environment_digest": self.identity.environment_digest,
            "roots": [item.to_dict() for item in self.roots],
            "frontier_entries": [item.to_dict() for item in self.frontier_entries],
            "frontier_complete": self.frontier_complete,
            "cost_evidence_complete": self.cost_evidence_complete,
            "batch_digest": self.batch_digest,
        }


def _planning_batch_digest(
    identity: PlanningBatchIdentity,
    roots: Sequence[_PlanningRootEvidence],
    frontier_entries: Sequence[PlanningFrontierEntry],
    frontier_complete: bool,
) -> str:
    ordered_roots = tuple(sorted(roots, key=lambda item: item.plan_id))
    ordered_entries = tuple(
        sorted(
            frontier_entries,
            key=lambda item: (
                item.occurrence_id,
                item.template_id,
                item.candidate_digest,
            ),
        )
    )
    return _digest(
        {
            "identity": identity.to_dict(),
            "roots": [item.to_dict() for item in ordered_roots],
            "frontier_entries": [item.to_dict() for item in ordered_entries],
            "frontier_complete": frontier_complete,
        }
    )


_REGISTERED_BATCHES: dict[int, tuple[weakref.ReferenceType[PlanningEvidenceBatch], str]] = {}


def _register_batch(batch: PlanningEvidenceBatch) -> PlanningEvidenceBatch:
    key = id(batch)

    def _drop(reference: weakref.ReferenceType[PlanningEvidenceBatch]) -> None:
        registered = _REGISTERED_BATCHES.get(key)
        if registered is not None and registered[0] is reference:
            _REGISTERED_BATCHES.pop(key, None)

    _REGISTERED_BATCHES[key] = (weakref.ref(batch, _drop), batch.batch_digest)
    return batch


def _require_registered_batch(batch: PlanningEvidenceBatch) -> str:
    if batch.__class__ is not PlanningEvidenceBatch:
        raise TypeError("completed roots require an exact PlanningEvidenceBatch")
    registered = _REGISTERED_BATCHES.get(id(batch))
    if registered is None or registered[0]() is not batch:
        raise ValueError("planning evidence batch is not adapter-registered")
    batch.__post_init__()
    if registered[1] != batch.batch_digest:
        raise ValueError("planning evidence batch identity changed after registration")
    return batch.batch_digest


@dataclass(frozen=True)
class CompletedRootPlan:
    """A strict, schema-complete, prospectively costed root comparison input."""

    plan_id: str
    strict_result: StrictPlanningResult = field(repr=False, compare=False)
    batch: PlanningEvidenceBatch = field(repr=False, compare=False)
    schema_receipt: TypedRootSchemaReceipt = field(repr=False, compare=False)
    bound_runner: BoundRunnerIdentity = field(repr=False, compare=False)
    runner_schema_receipt: TypedRunnerResultSchemaReceipt = field(
        repr=False,
        compare=False,
    )
    profile: RhoObservableProfile
    prospective_cost: FinalProspectiveCost
    reference_plan: ReferencePlan
    identity_digest: str
    _construction_token: object | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._construction_token is not _COMPLETED_ROOT_TOKEN:
            raise ValueError("CompletedRootPlan must be derived from a planning evidence batch")
        batch_digest = _require_registered_batch(self.batch)
        strict_seal = _require_registered_strict_planning_result(self.strict_result)
        if (
            self.profile.__class__ is not RhoObservableProfile
            or self.prospective_cost.__class__ is not FinalProspectiveCost
            or self.reference_plan.__class__ is not ReferencePlan
            or self.schema_receipt.__class__ is not TypedRootSchemaReceipt
            or self.bound_runner.__class__ is not BoundRunnerIdentity
            or self.runner_schema_receipt.__class__
            is not TypedRunnerResultSchemaReceipt
        ):
            raise TypeError("completed root has an invalid typed component")
        if (
            self.reference_plan.plan_id != self.plan_id
            or self.reference_plan.profile is not self.profile
            or self.reference_plan.prospective_cost is not self.prospective_cost
            or self.schema_receipt.strict_result is not self.strict_result
            or self.bound_runner.strict_result is not self.strict_result
            or self.runner_schema_receipt.bound_runner is not self.bound_runner
        ):
            raise ValueError("completed root components are not identity-bound")
        _require_digest(self.identity_digest, "completed root identity_digest")
        expected = _digest(
            {
                "plan_id": self.plan_id,
                "strict_result_identity_seal": strict_seal,
                "planning_batch_digest": batch_digest,
                "schema_receipt_digest": self.schema_receipt.receipt_digest,
                "bound_runner_identity_digest": self.bound_runner.identity_digest,
                "runner_schema_receipt_digest": self.runner_schema_receipt.receipt_digest,
                "profile_digest": self.profile.digest,
                "prospective_cost": self.prospective_cost.to_dict(),
            }
        )
        if self.identity_digest != expected:
            raise ValueError("completed root identity digest mismatch")


_REGISTERED_COMPLETED_ROOTS: dict[
    int, tuple[weakref.ReferenceType[CompletedRootPlan], str]
] = {}


def _register_completed_root(plan: CompletedRootPlan) -> CompletedRootPlan:
    key = id(plan)

    def _drop(reference: weakref.ReferenceType[CompletedRootPlan]) -> None:
        registered = _REGISTERED_COMPLETED_ROOTS.get(key)
        if registered is not None and registered[0] is reference:
            _REGISTERED_COMPLETED_ROOTS.pop(key, None)

    _REGISTERED_COMPLETED_ROOTS[key] = (weakref.ref(plan, _drop), plan.identity_digest)
    return plan


def _require_registered_completed_root(plan: CompletedRootPlan) -> str:
    if plan.__class__ is not CompletedRootPlan:
        raise TypeError("root selector accepts only exact CompletedRootPlan values")
    registered = _REGISTERED_COMPLETED_ROOTS.get(id(plan))
    if registered is None or registered[0]() is not plan:
        raise ValueError("completed root was not minted by the planning adapter")
    plan.__post_init__()
    if registered[1] != plan.identity_digest:
        raise ValueError("completed root identity changed after minting")
    return plan.identity_digest


def _admission_evidence_refs(query_result: QueryPlanResult, occurrence_id: str) -> tuple[str, ...]:
    occurrence = query_result.occurrence_results.get(occurrence_id)
    if occurrence is None or occurrence.chosen_template is None:
        return ()
    admission = occurrence.chosen_template.diagnostics.get("admission")
    if not isinstance(admission, Mapping):
        return ()
    return tuple(sorted(set(_string_tuple(admission.get("evidence_refs")))))


def _target_profile(strict_result: StrictPlanningResult) -> TargetAndRefinement | None:
    query_result = strict_result.query_result
    if query_result is None:
        return None
    occurrence_ids = tuple(sorted(query_result.effective_occurrence_goals))
    if len(occurrence_ids) != 1:
        return None
    occurrence_id = occurrence_ids[0]
    goal = query_result.effective_occurrence_goals[occurrence_id]
    problem = goal.problem
    result = query_result.occurrence_results.get(occurrence_id)
    chosen = None if result is None else result.chosen_template
    target = problem.logical_target
    if (
        problem.planning_execution_class != "production_normal"
        or not problem.require_typed_admission
        or target is None
        or chosen is None
    ):
        return None
    bindings = tuple(
        item
        for item in problem.implementation_target_bindings
        if item.template_id == chosen.template_id
        and item.occurrence_id == occurrence_id
        and item.logical_target_digest == target.digest
    )
    if len(bindings) != 1:
        return None
    binding = bindings[0]
    refinement_evidence: tuple[str, ...] = ()
    refined_target_id: str | None = None
    if binding.refinement_kind is not None:
        gamma = problem.gamma_snapshot
        predicate_digest = binding.refinement_predicate_digest
        if gamma is None or predicate_digest is None:
            return None
        subject = target_refinement_subject_digest(
            binding,
            target,
            snapshot_id=gamma.snapshot_id,
        )
        refinement_facts = tuple(
            fact
            for fact in gamma.matching(
                "target_refinement",
                subject_digest=subject,
                require_static=True,
            )
            if fact.accepted
        )
        admission_refs = set(_admission_evidence_refs(query_result, occurrence_id))
        if not refinement_facts or not {
            fact.fact_id for fact in refinement_facts
        }.issubset(admission_refs):
            return None
        refinement_evidence = tuple(
            sorted(
                f"{fact.fact_id}@{fact.evidence_digest}"
                for fact in refinement_facts
            )
        )
        refined_target_id = canonical_refined_target_id(
            target.digest,
            binding.refinement_kind,
            predicate_digest,
        )
    return TargetAndRefinement(
        target_id=(refined_target_id or target.digest),
        target_kind=(
            binding.refinement_kind
            if binding.refinement_kind is not None
            else "policy_access"
        ),
        relation=target.relation,
        policy_id=target.policy_id,
        occurrence_ids=(occurrence_id,),
        refinement_kind=binding.refinement_kind,
        refines_target_id=(target.digest if binding.refinement_kind is not None else None),
        refinement_predicate_digest=binding.refinement_predicate_digest,
        refinement_evidence=refinement_evidence,
    )


def _requirement_evidence(
    *,
    state: str,
    required_predicate: str | None,
    evidence_refs: tuple[str, ...],
) -> RequirementEvidence | None:
    required_atoms = frozenset(
        atom.strip()
        for atom in str(required_predicate or "").split(" && ")
        if atom.strip()
    )
    if required_predicate and (
        not required_atoms or not required_atoms.issubset(evidence_refs)
    ):
        return None
    try:
        return RequirementEvidence(
            state=state,
            satisfied_predicates=required_atoms,
            evidence_refs=frozenset(evidence_refs),
        )
    except (TypeError, ValueError):
        return None


def _strict_root_observation_rejection_reasons(
    strict_result: StrictPlanningResult,
    columns: Sequence[TypedRootSchemaColumn],
    physical_observation: TypedRootPhysicalObservation,
) -> tuple[str, ...]:
    """Cross-bind known adapter observations to sealed static root identity."""

    query_result = strict_result.query_result
    if query_result is None:
        return ("strict_root_identity_missing",)
    try:
        sigma = sigma_from_dict(query_result.root_sigma)
    except Exception:
        return ("strict_root_sigma_unparseable",)

    reasons: list[str] = []
    goals = tuple(query_result.effective_occurrence_goals.values())
    if len(goals) == 1:
        problem = goals[0].problem
        target = problem.logical_target
        if target is not None:
            expected_from_target = {
                "rid_domain": f"{target.relation}.{problem.rid_col}",
                "rid_surrogate_col": problem.rid_col,
            }
            for observed_field, expected_value in expected_from_target.items():
                observed_value = getattr(physical_observation, observed_field)
                if observed_value is not None and observed_value != expected_value:
                    reasons.append(
                        "known_target_identity_mismatch:" + observed_field
                    )
                static_key = (
                    "surrogate_col"
                    if observed_field == "rid_surrogate_col"
                    else observed_field
                )
                static_value = sigma.rid_mat_props.get(static_key)
                if static_value and str(static_value) != expected_value:
                    reasons.append(
                        "strict_root_identity_mismatch:" + observed_field
                    )

    static_rid_fields = {
        "rid_domain": sigma.rid_mat_props.get("rid_domain"),
        "rid_surrogate_col": sigma.rid_mat_props.get("surrogate_col"),
        "rid_carrier": sigma.rid_mat_props.get("carrier"),
    }
    for observed_field, static_value in static_rid_fields.items():
        observed_value = getattr(physical_observation, observed_field)
        if observed_value is None:
            continue
        if type(static_value) is not str or not static_value:  # noqa: E721
            reasons.append("strict_root_identity_missing:" + observed_field)
        elif observed_value != static_value:
            reasons.append("known_root_identity_mismatch:" + observed_field)

    static_visible = sigma.phys_props.get("visible_attrs")
    static_hidden = sigma.phys_props.get("hidden_attrs")
    observed_visible = tuple(
        item.name for item in columns if item.visibility == "visible"
    )
    observed_hidden = tuple(
        item.name for item in columns if item.visibility == "hidden"
    )
    visible_names: tuple[str, ...] | None = None
    hidden_names: tuple[str, ...] | None = None
    for field_name, static_value in (
        ("visible_schema_names", static_visible),
        ("hidden_schema_names", static_hidden),
    ):
        if type(static_value) not in {list, tuple}:  # noqa: E721
            reasons.append("strict_root_identity_missing:" + field_name)
            continue
        names = tuple(static_value)
        if (
            any(type(item) is not str or not item for item in names)  # noqa: E721
            or len(set(names)) != len(names)
        ):
            reasons.append("strict_root_identity_malformed:" + field_name)
            continue
        if field_name == "visible_schema_names":
            visible_names = names
        else:
            hidden_names = names
    if visible_names is not None:
        if observed_visible != visible_names:
            reasons.append("known_root_identity_mismatch:visible_schema_names")
    if hidden_names is not None:
        if observed_hidden != hidden_names:
            reasons.append("known_root_identity_mismatch:hidden_schema_names")
    if (
        visible_names is not None
        and hidden_names is not None
        and set(visible_names).intersection(hidden_names)
    ):
        reasons.append("strict_root_identity_malformed:schema_visibility_overlap")
    if visible_names is not None and hidden_names is not None:
        expected_partition_order = tuple(
            (name, "visible") for name in visible_names
        ) + tuple((name, "hidden") for name in hidden_names)
        observed_partition_order = tuple(
            (item.name, item.visibility) for item in columns
        )
        if observed_partition_order != expected_partition_order:
            reasons.append(
                "known_root_identity_mismatch:schema_partition_order"
            )
        if physical_observation.hidden_attrs_and_carriers is not None:
            expected_physical_hidden = set(hidden_names)
            static_carrier = static_rid_fields["rid_carrier"]
            if type(static_carrier) is str and static_carrier:  # noqa: E721
                expected_physical_hidden.add(static_carrier)
            if set(physical_observation.hidden_attrs_and_carriers) != (
                expected_physical_hidden
            ):
                reasons.append(
                    "known_root_identity_mismatch:hidden_physical_inventory"
                )

    if (
        physical_observation.rid_carrier is not None
        and physical_observation.hidden_attrs_and_carriers is not None
        and physical_observation.rid_carrier
        not in set(physical_observation.hidden_attrs_and_carriers)
    ):
        reasons.append("known_root_identity_mismatch:rid_carrier_visibility")
    return tuple(sorted(set(reasons)))


def _profile_from_actual_root(
    strict_result: StrictPlanningResult,
    schema_receipt: TypedRootSchemaReceipt,
    physical_observation: TypedRootPhysicalObservation,
) -> RhoObservableProfile:
    query_result = strict_result.query_result
    if query_result is None:
        raise ValueError("root profile requires a successful strict query result")
    sigma: Sigma
    try:
        sigma = sigma_from_dict(query_result.root_sigma)
    except Exception as exc:
        raise ValueError("root profile cannot parse the actual root Sigma") from exc

    occurrence_ids = tuple(sorted(query_result.effective_occurrence_goals))
    rho = (
        query_result.effective_occurrence_goals[occurrence_ids[0]].problem.parent_requirement
        if len(occurrence_ids) == 1
        else None
    )
    phys = sigma.phys_props
    hidden = (
        None
        if physical_observation.hidden_attrs_and_carriers is None
        else frozenset(physical_observation.hidden_attrs_and_carriers)
    )

    auth_pairs = frozenset(AuthPair(left, right) for left, right in sigma.auth_set)
    residuals = frozenset(
        ResidualObligation(
            item.basis_id,
            item.omega_id,
            item.check_id,
            item.need,
            item.deadline,
        )
        for item in sigma.residuals
    )
    live_pairs = frozenset(
        AuthPair(basis_id, omega_id)
        for basis_id, omega_ids in sigma.live.items()
        for omega_id in omega_ids
    )

    coverage = (
        None
        if physical_observation.observable_coverage is None
        else frozenset(physical_observation.observable_coverage)
    )

    branch_tags = frozenset(
        node.branch_tag for node in walk(query_result.bound_ir) if isinstance(node, UnionTagged)
    )
    freshness_refs = _string_tuple(phys.get("freshness_evidence"))
    context_refs = _string_tuple(phys.get("context_evidence"))
    freshness_state = sigma.freshness
    if freshness_state == "non_artifact_candidate" and (
        query_result.root_closure.ok
        and query_result.root_closure.residuals_closed
        and not residuals
        and auth_pairs == live_pairs
        and auth_pairs
        and all(
            sigma.safety.get(pair.basis_id) == "exact_authorized"
            for pair in auth_pairs
        )
    ):
        # The leaf state names the pre-residual candidate stream.  F1 profiles
        # the completed root, so a sealed closure with no residuals, exact
        # live/auth equality, and exact-authorized safety is the finite witness
        # for the root's non-artifact-exact freshness state.
        freshness_state = "non_artifact_exact"
    freshness = _requirement_evidence(
        state=freshness_state,
        required_predicate=(None if rho is None else rho.freshness_predicate),
        evidence_refs=freshness_refs,
    )
    context = _requirement_evidence(
        state=sigma.context_scope,
        required_predicate=(None if rho is None else rho.context_predicate),
        evidence_refs=context_refs,
    )

    rid = None
    if (
        physical_observation.rid_domain is not None
        and physical_observation.rid_surrogate_col is not None
        and physical_observation.rid_carrier is not None
        and physical_observation.rid_materialized is not None
    ):
        rid = RIDMaterialization(
            rid_domain=physical_observation.rid_domain,
            surrogate_col=physical_observation.rid_surrogate_col,
            carrier=physical_observation.rid_carrier,
            materialized=physical_observation.rid_materialized,
        )

    physical = None
    if physical_observation.complete:
        assert physical_observation.delivered_order is not None
        assert physical_observation.observable_properties is not None
        assert physical_observation.cost_relevant_properties is not None
        physical = PhysicalProperties(
            delivered_order=physical_observation.delivered_order,
            observable_properties=physical_observation.observable_properties,
            cost_relevant_properties=physical_observation.cost_relevant_properties,
        )

    enforcers = tuple(
        sorted(
            EnforcerRequirement(
                kind=item.enforcer,
                target_ids=tuple(item.target_ids),
                placement=f"occurrence:{occurrence_id}",
            )
            for occurrence_id, items in query_result.inserted_enforcers.items()
            for item in items
        )
    )
    return RhoObservableProfile(
        target_and_refinement=_target_profile(strict_result),
        visible_schema=tuple(
            VisibleColumn(item.name, item.type_name, item.nullable, item.collation)
            for item in schema_receipt.columns
            if item.visibility == "visible"
        ),
        hidden_attrs_and_carriers=hidden,
        auth_pairs=auth_pairs,
        residual_obligations_and_need=residuals,
        coverage_and_live=(
            None if coverage is None else CoverageAndLive(coverage, live_pairs)
        ),
        branch_and_lineage=BranchAndLineage(sigma.branch_lineage, branch_tags),
        safety=(
            SafetyProfile.from_mapping(sigma.safety) if sigma.safety else None
        ),
        freshness=freshness,
        context=context,
        rid_and_materialization=rid,
        phys_props=physical,
        required_enforcers=enforcers,
    )


def completed_root_plans_from_batch(
    batch: PlanningEvidenceBatch,
) -> tuple[CompletedRootPlan, ...]:
    """Derive sealed selector inputs; callers cannot supply profiles or costs."""

    batch_digest = _require_registered_batch(batch)
    completed: list[CompletedRootPlan] = []
    for evidence in batch.roots:
        strict = evidence.strict_result
        strict_seal = _require_registered_strict_planning_result(strict)
        profile = _profile_from_actual_root(
            strict,
            evidence.schema_receipt,
            evidence.physical_observation,
        )
        cost = FinalProspectiveCost(
            complete_root_plan_digest=evidence.bound_runner.identity_digest,
            explain_plan_digest=evidence.explain_plan_digest,
            cost_after_all_enforcers=float(evidence.prospective_total_cost),
            sql_ast_digest=evidence.bound_runner.runner_sql_digest,
            certificate_digest=evidence.certificate_digest,
            static_verification_digest=evidence.static_verification_digest,
            cost_model_version=batch.identity.cost_model_version,
            planning_environment_digest=batch.identity.environment_digest,
            root_closed=True,
            certificate_replayed=True,
            plain_explain_completed=True,
            static_verification_passed=True,
        )
        reference = ReferencePlan(evidence.plan_id, profile, cost)
        identity_digest = _digest(
            {
                "plan_id": evidence.plan_id,
                "strict_result_identity_seal": strict_seal,
                "planning_batch_digest": batch_digest,
                "schema_receipt_digest": evidence.schema_receipt.receipt_digest,
                "bound_runner_identity_digest": evidence.bound_runner.identity_digest,
                "runner_schema_receipt_digest": (
                    evidence.runner_schema_receipt.receipt_digest
                ),
                "profile_digest": profile.digest,
                "prospective_cost": cost.to_dict(),
            }
        )
        completed.append(
            _register_completed_root(
                CompletedRootPlan(
                    plan_id=evidence.plan_id,
                    strict_result=strict,
                    batch=batch,
                    schema_receipt=evidence.schema_receipt,
                    bound_runner=evidence.bound_runner,
                    runner_schema_receipt=evidence.runner_schema_receipt,
                    profile=profile,
                    prospective_cost=cost,
                    reference_plan=reference,
                    identity_digest=identity_digest,
                    _construction_token=_COMPLETED_ROOT_TOKEN,
                )
            )
        )
    return tuple(completed)


@dataclass(frozen=True)
class RootPairDecision:
    left_plan_id: str
    right_plan_id: str
    dominates: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "left_plan_id": self.left_plan_id,
            "right_plan_id": self.right_plan_id,
            "dominates": self.dominates,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class RootDominator:
    pruned_plan_id: str
    dominator_plan_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "pruned_plan_id": self.pruned_plan_id,
            "dominator_plan_ids": list(self.dominator_plan_ids),
        }


@dataclass(frozen=True)
class RootProfileValidation:
    plan_id: str
    ok: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"plan_id": self.plan_id, "ok": self.ok, "reason": self.reason}


@dataclass(frozen=True)
class RootSelectionAudit:
    status: str
    feature_mode: str
    frontier_size: int
    completed_root_count: int
    frontier_complete: bool
    cost_evidence_complete: bool
    profile_comparison_complete: bool
    cost_evidence: CostEvidencePoolDecision
    profile_complete_plan_ids: tuple[str, ...]
    incomplete_profile_plan_ids: tuple[str, ...]
    profile_rho_validations: tuple[RootProfileValidation, ...] = ()
    structural_rejections: tuple[PlanningFrontierEntry, ...] = ()
    evidence_failures: tuple[PlanningFrontierEntry, ...] = ()
    pair_decisions: tuple[RootPairDecision, ...] = ()
    dominators: tuple[RootDominator, ...] = ()
    survivor_plan_ids: tuple[str, ...] = ()
    chosen_plan_id: str | None = None
    tied_minimum_plan_ids: tuple[str, ...] = ()
    tie_break: str = "final_prospective_cost_then_plan_id"
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "feature_mode": self.feature_mode,
            "frontier_size": self.frontier_size,
            "completed_root_count": self.completed_root_count,
            "frontier_complete": self.frontier_complete,
            "cost_evidence_complete": self.cost_evidence_complete,
            "profile_comparison_complete": self.profile_comparison_complete,
            "cost_evidence": {
                "ok": self.cost_evidence.ok,
                "reason": self.cost_evidence.reason,
                "cost_model_version": self.cost_evidence.cost_model_version,
                "planning_environment_digest": self.cost_evidence.planning_environment_digest,
            },
            "profile_complete_plan_ids": list(self.profile_complete_plan_ids),
            "incomplete_profile_plan_ids": list(self.incomplete_profile_plan_ids),
            "profile_rho_validations": [
                item.to_dict() for item in self.profile_rho_validations
            ],
            "structural_rejections": [
                item.to_dict() for item in self.structural_rejections
            ],
            "evidence_failures": [item.to_dict() for item in self.evidence_failures],
            "pair_decisions": [item.to_dict() for item in self.pair_decisions],
            "dominators": [item.to_dict() for item in self.dominators],
            "survivor_plan_ids": list(self.survivor_plan_ids),
            "chosen_plan_id": self.chosen_plan_id,
            "tied_minimum_plan_ids": list(self.tied_minimum_plan_ids),
            "tie_break": self.tie_break,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class RootSelectionResult:
    ok: bool
    chosen: CompletedRootPlan | None
    audit: RootSelectionAudit


def _selection_failure(
    *,
    batch: PlanningEvidenceBatch,
    mode: str,
    plans: Sequence[CompletedRootPlan],
    cost_evidence: CostEvidencePoolDecision,
    complete_ids: tuple[str, ...],
    incomplete_ids: tuple[str, ...],
    reason: str,
    status: str = "rejected",
    profile_rho_validations: tuple[RootProfileValidation, ...] = (),
) -> RootSelectionResult:
    return RootSelectionResult(
        ok=False,
        chosen=None,
        audit=RootSelectionAudit(
            status=status,
            feature_mode=mode,
            frontier_size=len(batch.frontier_entries),
            completed_root_count=len(plans),
            frontier_complete=batch.frontier_complete,
            cost_evidence_complete=batch.cost_evidence_complete and cost_evidence.ok,
            profile_comparison_complete=False,
            cost_evidence=cost_evidence,
            profile_complete_plan_ids=complete_ids,
            incomplete_profile_plan_ids=incomplete_ids,
            profile_rho_validations=profile_rho_validations,
            structural_rejections=tuple(
                item
                for item in batch.frontier_entries
                if item.status == "structural_rejection"
            ),
            evidence_failures=tuple(
                item
                for item in batch.frontier_entries
                if item.status == "evidence_failure"
            ),
            reasons=(reason,),
        ),
    )


def select_completed_roots(
    batch: PlanningEvidenceBatch,
    *,
    feature_flags: PlannerFeatureFlags,
) -> RootSelectionResult:
    """Run all-or-nothing selection over production-validator evidence only."""

    return _select_completed_roots(
        batch,
        feature_flags=feature_flags,
        isolated_test_token=None,
    )


def _select_completed_roots_for_isolated_test(
    batch: PlanningEvidenceBatch,
    *,
    feature_flags: PlannerFeatureFlags,
) -> RootSelectionResult:
    """Private comparison harness for explicitly non-promotable test batches."""

    return _select_completed_roots(
        batch,
        feature_flags=feature_flags,
        isolated_test_token=_ISOLATED_SELECTION_TOKEN,
    )


def _select_completed_roots(
    batch: PlanningEvidenceBatch,
    *,
    feature_flags: PlannerFeatureFlags,
    isolated_test_token: object | None,
) -> RootSelectionResult:
    """Shared selector; the token cannot mint or promote planning evidence."""

    if feature_flags.__class__ is not PlannerFeatureFlags:
        raise TypeError("root selector requires exact PlannerFeatureFlags")
    _require_registered_batch(batch)
    materialized = tuple(
        sorted(
            completed_root_plans_from_batch(batch),
            key=lambda item: (item.plan_id, item.identity_digest),
        )
    )
    for plan in materialized:
        _require_registered_completed_root(plan)
    mode = feature_flags.reference_dominance
    empty_cost = validate_final_prospective_cost_pool(())
    complete_ids = tuple(
        plan.plan_id for plan in materialized if plan.profile.is_complete
    )
    incomplete_ids = tuple(
        plan.plan_id for plan in materialized if not plan.profile.is_complete
    )
    if not batch.frontier_complete:
        return _selection_failure(
            batch=batch,
            mode=mode,
            plans=materialized,
            cost_evidence=CostEvidencePoolDecision(False, "incomplete_root_frontier"),
            complete_ids=complete_ids,
            incomplete_ids=incomplete_ids,
            reason="root_frontier_not_complete",
        )
    if not batch.cost_evidence_complete:
        return _selection_failure(
            batch=batch,
            mode=mode,
            plans=materialized,
            cost_evidence=CostEvidencePoolDecision(False, "frontier_evidence_failure"),
            complete_ids=complete_ids,
            incomplete_ids=incomplete_ids,
            reason="root_frontier_cost_evidence_failure",
        )
    if not materialized:
        return _selection_failure(
            batch=batch,
            mode=mode,
            plans=materialized,
            cost_evidence=empty_cost,
            complete_ids=(),
            incomplete_ids=(),
            reason="empty_completed_root_pool",
        )
    cost_evidence = validate_final_prospective_cost_pool(
        plan.reference_plan for plan in materialized
    )
    if not cost_evidence.ok:
        return _selection_failure(
            batch=batch,
            mode=mode,
            plans=materialized,
            cost_evidence=cost_evidence,
            complete_ids=complete_ids,
            incomplete_ids=incomplete_ids,
            reason="incomplete_or_mixed_prospective_cost_pool:" + cost_evidence.reason,
        )
    evidence_role = batch.identity.evidence_role
    if evidence_role != "production_validator" and (
        evidence_role != "isolated_test_non_promotable"
        or isolated_test_token is not _ISOLATED_SELECTION_TOKEN
    ):
        return _selection_failure(
            batch=batch,
            mode=mode,
            plans=materialized,
            cost_evidence=cost_evidence,
            complete_ids=complete_ids,
            incomplete_ids=incomplete_ids,
            reason="non_promotable_planning_evidence",
            status="non_promotable",
        )
    if mode != "enabled":
        return _selection_failure(
            batch=batch,
            mode=mode,
            plans=materialized,
            cost_evidence=cost_evidence,
            complete_ids=complete_ids,
            incomplete_ids=incomplete_ids,
            reason="reference_dominance_not_enabled",
            status=("shadow_only" if mode == "shadow" else "disabled"),
        )
    query_result = materialized[0].strict_result.query_result
    assert query_result is not None
    rho = next(iter(query_result.effective_occurrence_goals.values())).problem.parent_requirement
    profile_validations = tuple(
        RootProfileValidation(
            plan.plan_id,
            decision.ok,
            decision.reason,
        )
        for plan in materialized
        for decision in (
            validate_profile_against_rho(
                plan.profile,
                rho,
                expected_logical_target_id=batch.identity.logical_target_id,
            ),
        )
    )
    invalid_known = tuple(
        item
        for item in profile_validations
        if not item.ok and item.reason != "unknown_or_incomplete_profile"
    )
    if invalid_known:
        first = invalid_known[0]
        return _selection_failure(
            batch=batch,
            mode=mode,
            plans=materialized,
            cost_evidence=cost_evidence,
            complete_ids=complete_ids,
            incomplete_ids=incomplete_ids,
            reason=(
                "root_profile_does_not_satisfy_rho:"
                + first.plan_id
                + ":"
                + first.reason
            ),
            profile_rho_validations=profile_validations,
        )
    if len(materialized) > 1 and incomplete_ids:
        return _selection_failure(
            batch=batch,
            mode=mode,
            plans=materialized,
            cost_evidence=cost_evidence,
            complete_ids=complete_ids,
            incomplete_ids=incomplete_ids,
            reason="multiple_root_pool_requires_complete_rho_profiles",
            profile_rho_validations=profile_validations,
        )
    if len(materialized) == 1 and incomplete_ids and len(batch.frontier_entries) != 1:
        return _selection_failure(
            batch=batch,
            mode=mode,
            plans=materialized,
            cost_evidence=cost_evidence,
            complete_ids=complete_ids,
            incomplete_ids=incomplete_ids,
            reason="incomplete_profile_requires_exact_singleton_inventory",
            profile_rho_validations=profile_validations,
        )
    if len(materialized) == 1:
        only = materialized[0]
        return RootSelectionResult(
            ok=True,
            chosen=only,
            audit=RootSelectionAudit(
                status=("selected" if only.profile.is_complete else "singleton_no_comparison"),
                feature_mode=mode,
                frontier_size=len(batch.frontier_entries),
                completed_root_count=1,
                frontier_complete=batch.frontier_complete,
                cost_evidence_complete=True,
                profile_comparison_complete=only.profile.is_complete,
                cost_evidence=cost_evidence,
                profile_complete_plan_ids=complete_ids,
                incomplete_profile_plan_ids=incomplete_ids,
                profile_rho_validations=profile_validations,
                structural_rejections=tuple(
                    item
                    for item in batch.frontier_entries
                    if item.status == "structural_rejection"
                ),
                survivor_plan_ids=(only.plan_id,),
                chosen_plan_id=only.plan_id,
                tied_minimum_plan_ids=(only.plan_id,),
                reasons=(
                    ()
                    if only.profile.is_complete
                    else ("singleton_profile_incomplete_no_pairwise_claim",)
                ),
            ),
        )

    pair_decisions: list[RootPairDecision] = []
    dominators_by_plan: dict[str, set[str]] = {plan.plan_id: set() for plan in materialized}
    for left in materialized:
        for right in materialized:
            if left is right:
                continue
            decision = compare_reference_dominance(
                left.reference_plan,
                right.reference_plan,
                rho,
            )
            pair_decisions.append(
                RootPairDecision(
                    left.plan_id,
                    right.plan_id,
                    decision.dominates,
                    decision.reason,
                )
            )
            if decision.dominates:
                dominators_by_plan[right.plan_id].add(left.plan_id)
    survivors = tuple(
        sorted(plan.plan_id for plan in materialized if not dominators_by_plan[plan.plan_id])
    )
    by_id = {plan.plan_id: plan for plan in materialized}
    chosen = min(
        (by_id[plan_id] for plan_id in survivors),
        key=lambda item: (item.prospective_cost.cost_after_all_enforcers, item.plan_id),
    )
    minimum = chosen.prospective_cost.cost_after_all_enforcers
    tied = tuple(
        sorted(
            plan_id
            for plan_id in survivors
            if by_id[plan_id].prospective_cost.cost_after_all_enforcers == minimum
        )
    )
    dominators = tuple(
        RootDominator(plan_id, tuple(sorted(values)))
        for plan_id, values in sorted(dominators_by_plan.items())
        if values
    )
    return RootSelectionResult(
        ok=True,
        chosen=chosen,
        audit=RootSelectionAudit(
            status="selected",
            feature_mode=mode,
            frontier_size=len(batch.frontier_entries),
            completed_root_count=len(materialized),
            frontier_complete=True,
            cost_evidence_complete=True,
            profile_comparison_complete=True,
            cost_evidence=cost_evidence,
            profile_complete_plan_ids=complete_ids,
            incomplete_profile_plan_ids=incomplete_ids,
            profile_rho_validations=profile_validations,
            structural_rejections=tuple(
                item
                for item in batch.frontier_entries
                if item.status == "structural_rejection"
            ),
            pair_decisions=tuple(pair_decisions),
            dominators=dominators,
            survivor_plan_ids=survivors,
            chosen_plan_id=chosen.plan_id,
            tied_minimum_plan_ids=tied,
        ),
    )


def _strict_gamma_digest(strict: StrictPlanningResult) -> str:
    assert strict.query_result is not None
    return _digest(
        {
            occurrence_id: (
                None
                if goal.problem.gamma_snapshot is None
                else {
                    "snapshot_id": goal.problem.gamma_snapshot.snapshot_id,
                    "digest": goal.problem.gamma_snapshot.digest,
                }
            )
            for occurrence_id, goal in sorted(
                strict.query_result.effective_occurrence_goals.items()
            )
        }
    )


def _strict_logical_target_digest(strict: StrictPlanningResult) -> str:
    assert strict.query_result is not None
    return _digest(
        {
            occurrence_id: (
                None
                if goal.problem.logical_target is None
                else goal.problem.logical_target.to_dict()
            )
            for occurrence_id, goal in sorted(
                strict.query_result.effective_occurrence_goals.items()
            )
        }
    )


def _strict_single_logical_target_id(strict: StrictPlanningResult) -> str:
    if strict.query_result is None:
        raise ValueError("strict root is missing its query result")
    goals = tuple(strict.query_result.effective_occurrence_goals.values())
    if len(goals) != 1 or goals[0].problem.logical_target is None:
        raise ValueError("forced root requires one typed logical target")
    return goals[0].problem.logical_target.digest


def _mint_production_planning_evidence_batch(
    strict_attempts: Sequence[StrictPlanningResult],
    *,
    bound_runners: Mapping[str, BoundRunnerIdentity],
    prospective_costs: Mapping[str, float],
    explain_plan_digests: Mapping[str, str],
    schemas: Mapping[str, Sequence[TypedRootSchemaColumn]],
    runner_schemas: Mapping[str, Sequence[TypedRootSchemaColumn]],
    physical_observations: Mapping[str, TypedRootPhysicalObservation],
    static_verification_digests: Mapping[str, str],
    batch_id: str,
    snapshot_digest: str,
    database_identity_digest: str,
    catalog_digest: str,
    cost_model_version: str,
) -> PlanningEvidenceBatch:
    """Mint one all-or-nothing production batch from sealed strict attempts.

    Structural classification is derived exclusively from the strict
    attempt receipts.  No caller-supplied rejection map or favorable subset is
    accepted.  Missing or malformed PostgreSQL evidence remains serialized as
    an evidence failure so the public selector rejects the whole cell.
    """

    attempts = tuple(strict_attempts)
    if not attempts or not batch_id or not cost_model_version:
        raise ValueError("production planning batch requires attempts and identity")
    attempt_provenances = tuple(
        _require_forced_root_attempt_provenance(item) for item in attempts
    )
    ordered = tuple(
        strict
        for _attempt, strict in sorted(
            zip(attempt_provenances, attempts),
            key=lambda item: (item[0].template_id, item[0].identity_digest),
        )
    )
    attempt_provenances = tuple(
        _require_forced_root_attempt_provenance(item) for item in ordered
    )
    first_attempt = attempt_provenances[0]
    inventory = first_attempt.admitted_candidate_inventory
    if any(
        item.occurrence_id != first_attempt.occurrence_id
        or item.admitted_candidate_inventory != inventory
        or item.admitted_candidate_inventory_digest
        != first_attempt.admitted_candidate_inventory_digest
        or item.registry_digest != first_attempt.registry_digest
        or item.registry_scope_identity != first_attempt.registry_scope_identity
        or item.registry_manifest_digest != first_attempt.registry_manifest_digest
        or item.registry_evidence_role != "production_manifest"
        for item in attempt_provenances
    ):
        raise ValueError(
            "production forced attempts do not share one owner-bound inventory"
        )
    attempts_by_template = {
        provenance.template_id: (strict, provenance)
        for strict, provenance in zip(ordered, attempt_provenances)
    }
    inventory_ids = {template_id for template_id, _candidate_digest in inventory}
    if (
        len(attempts_by_template) != len(ordered)
        or set(attempts_by_template) != inventory_ids
        or len(ordered) != len(inventory)
    ):
        raise ValueError(
            "production batch must contain exactly one forced attempt per admitted root"
        )
    completed = tuple(
        strict
        for strict, provenance in zip(ordered, attempt_provenances)
        if provenance.outcome_status == "completed"
    )
    if not completed:
        raise ValueError("production batch has no completed strict root")
    completed_provenances = tuple(
        _require_forced_root_provenance(item) for item in completed
    )
    strict_seals = tuple(
        _require_registered_strict_planning_result(item) for item in completed
    )
    drafts = tuple(item.draft for item in completed)
    if any(item is None for item in drafts):
        raise ValueError("production batch completed root lacks a strict draft")
    plan_ids = tuple(item.plan_id for item in drafts if item is not None)
    if len(set(plan_ids)) != len(plan_ids):
        raise ValueError("production planning batch contains duplicate strict roots")
    allowed_plan_ids = set(plan_ids)
    for label, evidence in (
        ("bound runners", bound_runners),
        ("prospective costs", prospective_costs),
        ("EXPLAIN digests", explain_plan_digests),
        ("schemas", schemas),
        ("runner schemas", runner_schemas),
        ("physical observations", physical_observations),
        ("static verification digests", static_verification_digests),
    ):
        if set(evidence) - allowed_plan_ids:
            raise ValueError(f"production planning batch has detached {label}")
    strict_by_template = {
        provenance.template_id: (strict, seal, provenance)
        for strict, seal, provenance in zip(
            completed,
            strict_seals,
            completed_provenances,
        )
    }
    session_digests = {
        item.session_contract.digest for item in drafts if item is not None
    }
    registry_digests = {
        item.registry_digest for item in drafts if item is not None
    }
    gamma_digests = {_strict_gamma_digest(item) for item in completed}
    target_digests = {_strict_logical_target_digest(item) for item in completed}
    logical_target_ids = {
        _strict_single_logical_target_id(item) for item in completed
    }
    rho_digests = {
        item.envelope.rho_digest for item in completed if item.envelope is not None
    }
    emit_context_digests = {
        item.envelope.emit_context_digest
        for item in completed
        if item.envelope is not None
    }
    obligation_graph_digests = {
        item.envelope.obligation_graph_digest
        for item in completed
        if item.envelope is not None
    }
    shared_sets = (
        session_digests,
        registry_digests,
        gamma_digests,
        target_digests,
        logical_target_ids,
        rho_digests,
        emit_context_digests,
        obligation_graph_digests,
    )
    if any(len(values) != 1 for values in shared_sets):
        raise ValueError(
            "production roots do not share session, registry, Gamma, and query contract"
        )
    first_draft = drafts[0]
    assert first_draft is not None
    identity = PlanningBatchIdentity(
        batch_id=batch_id,
        snapshot_digest=snapshot_digest,
        database_identity_digest=database_identity_digest,
        session_contract_digest=next(iter(session_digests)),
        guc_digest=_digest(dict(first_draft.session_contract.gucs)),
        cost_model_version=cost_model_version,
        catalog_digest=catalog_digest,
        gamma_digest=next(iter(gamma_digests)),
        registry_digest=next(iter(registry_digests)),
        registry_scope_identity=first_attempt.registry_scope_identity,
        registry_manifest_digest=first_attempt.registry_manifest_digest,
        admitted_candidate_inventory_digest=(
            first_attempt.admitted_candidate_inventory_digest
        ),
        target_digest=next(iter(target_digests)),
        logical_target_id=next(iter(logical_target_ids)),
        rho_digest=next(iter(rho_digests)),
        emit_context_digest=next(iter(emit_context_digests)),
        obligation_graph_digest=next(iter(obligation_graph_digests)),
        evidence_role="production_validator",
    )
    roots: list[_PlanningRootEvidence] = []
    frontier_entries: list[PlanningFrontierEntry] = []
    for template_id, candidate_digest in inventory:
        attempt_result, attempt = attempts_by_template[template_id]
        if attempt.outcome_status == "structural_rejection":
            frontier_entries.append(
                PlanningFrontierEntry(
                    occurrence_id=attempt.occurrence_id,
                    template_id=template_id,
                    candidate_digest=candidate_digest,
                    status="structural_rejection",
                    plan_id=None,
                    forced_provenance_identity=attempt.identity_digest,
                    reasons=attempt_result.rejection_reasons,
                    _construction_token=_PLANNING_EVIDENCE_TOKEN,
                )
            )
            continue
        if attempt.outcome_status == "evidence_failure":
            frontier_entries.append(
                PlanningFrontierEntry(
                    occurrence_id=attempt.occurrence_id,
                    template_id=template_id,
                    candidate_digest=candidate_digest,
                    status="evidence_failure",
                    plan_id=(
                        None
                        if attempt_result.draft is None
                        else attempt_result.draft.plan_id
                    ),
                    forced_provenance_identity=attempt.identity_digest,
                    reasons=attempt_result.rejection_reasons,
                    _construction_token=_PLANNING_EVIDENCE_TOKEN,
                )
            )
            continue
        strict_tuple = strict_by_template.get(template_id)
        if strict_tuple is None:
            raise ValueError("completed forced attempt lost its strict result")
        strict, strict_seal, provenance = strict_tuple
        assert strict.draft is not None and strict.envelope is not None
        plan_id = strict.draft.plan_id
        missing: list[str] = []
        if plan_id not in prospective_costs:
            missing.append("plain_explain_cost_missing")
        if plan_id not in bound_runners:
            missing.append("bound_runner_identity_missing")
        if plan_id not in explain_plan_digests:
            missing.append("plain_explain_plan_digest_missing")
        if plan_id not in schemas:
            missing.append("typed_access_root_schema_missing")
        if plan_id not in runner_schemas:
            missing.append("typed_runner_result_schema_missing")
        if plan_id not in physical_observations:
            missing.append("typed_root_physical_observation_missing")
        if plan_id not in static_verification_digests:
            missing.append("static_verification_digest_missing")
        columns = tuple(schemas.get(plan_id, ()))
        result_columns = tuple(runner_schemas.get(plan_id, ()))
        bound_runner = bound_runners.get(plan_id)
        physical_observation = physical_observations.get(plan_id)
        if columns and any(
            item.__class__ is not TypedRootSchemaColumn for item in columns
        ):
            missing.append("typed_root_schema_invalid")
        if result_columns and any(
            item.__class__ is not TypedRootSchemaColumn for item in result_columns
        ):
            missing.append("typed_runner_result_schema_invalid")
        if (
            bound_runner is not None
            and bound_runner.__class__ is not BoundRunnerIdentity
        ):
            missing.append("bound_runner_identity_invalid")
        if bound_runner is not None and bound_runner.__class__ is BoundRunnerIdentity:
            try:
                bound_runner.__post_init__()
            except (TypeError, ValueError):
                missing.append("bound_runner_identity_invalid")
            if (
                bound_runner.strict_result is not strict
                or bound_runner.snapshot_digest != snapshot_digest
                or bound_runner.database_identity_digest != database_identity_digest
                or bound_runner.catalog_digest != catalog_digest
            ):
                missing.append("bound_runner_environment_mismatch")
            if result_columns != bound_runner.continuation_spec.result_columns:
                missing.append("typed_runner_result_schema_contract_mismatch")
        if (
            physical_observation is not None
            and physical_observation.__class__ is not TypedRootPhysicalObservation
        ):
            missing.append("typed_root_physical_observation_invalid")
        for label, evidence_map in (
            ("plain_explain_plan_digest_invalid", explain_plan_digests),
            ("static_verification_digest_invalid", static_verification_digests),
        ):
            value = evidence_map.get(plan_id)
            if value is not None and _SHA256_RE.fullmatch(value) is None:
                missing.append(label)
        cost = prospective_costs.get(plan_id)
        if cost is not None and (
            not isinstance(cost, (int, float))
            or isinstance(cost, bool)
            or not math.isfinite(float(cost))
            or float(cost) < 0
        ):
            missing.append("plain_explain_cost_invalid")
        if missing:
            frontier_entries.append(
                PlanningFrontierEntry(
                    occurrence_id=provenance.occurrence_id,
                    template_id=template_id,
                    candidate_digest=candidate_digest,
                    status="evidence_failure",
                    plan_id=plan_id,
                    forced_provenance_identity=provenance.identity_digest,
                    reasons=tuple(missing),
                    _construction_token=_PLANNING_EVIDENCE_TOKEN,
                )
            )
            continue
        assert (
            physical_observation is not None
            and cost is not None
            and bound_runner is not None
        )
        identity_reasons = _strict_root_observation_rejection_reasons(
            strict,
            columns,
            physical_observation,
        )
        if identity_reasons:
            frontier_entries.append(
                PlanningFrontierEntry(
                    occurrence_id=provenance.occurrence_id,
                    template_id=template_id,
                    candidate_digest=candidate_digest,
                    status="evidence_failure",
                    plan_id=plan_id,
                    forced_provenance_identity=provenance.identity_digest,
                    reasons=identity_reasons,
                    _construction_token=_PLANNING_EVIDENCE_TOKEN,
                )
            )
            continue
        schema_digest = _schema_receipt_digest(
            strict_result_identity_seal=strict_seal,
            plan_id=plan_id,
            complete_root_plan_digest=strict.draft.bound_ir_digest,
            exact_sql_digest=strict.draft.exact_sql_digest,
            snapshot_digest=snapshot_digest,
            columns=columns,
        )
        schema = TypedRootSchemaReceipt(
            strict_result=strict,
            strict_result_identity_seal=strict_seal,
            plan_id=plan_id,
            complete_root_plan_digest=strict.draft.bound_ir_digest,
            exact_sql_digest=strict.draft.exact_sql_digest,
            snapshot_digest=snapshot_digest,
            columns=columns,
            receipt_digest=schema_digest,
            _construction_token=_PLANNING_EVIDENCE_TOKEN,
        )
        runner_schema_digest = _runner_schema_receipt_digest(
            bound_runner_identity_digest=bound_runner.identity_digest,
            plan_id=plan_id,
            snapshot_digest=snapshot_digest,
            result_contract_digest=bound_runner.result_contract_digest,
            columns=result_columns,
        )
        runner_schema = TypedRunnerResultSchemaReceipt(
            bound_runner=bound_runner,
            bound_runner_identity_digest=bound_runner.identity_digest,
            plan_id=plan_id,
            snapshot_digest=snapshot_digest,
            result_contract_digest=bound_runner.result_contract_digest,
            columns=result_columns,
            receipt_digest=runner_schema_digest,
            _construction_token=_PLANNING_EVIDENCE_TOKEN,
        )
        roots.append(
            _PlanningRootEvidence(
                strict_result=strict,
                bound_runner=bound_runner,
                strict_result_identity_seal=strict_seal,
                plan_id=plan_id,
                complete_root_plan_digest=bound_runner.identity_digest,
                explain_plan_digest=explain_plan_digests[plan_id],
                prospective_total_cost=float(cost),
                sql_ast_digest=bound_runner.runner_sql_digest,
                certificate_digest=strict.envelope.digest,
                static_verification_digest=(
                    static_verification_digests[plan_id]
                ),
                exact_sql_digest=bound_runner.runner_sql_digest,
                schema_receipt=schema,
                runner_schema_receipt=runner_schema,
                physical_observation=physical_observation,
                _construction_token=_PLANNING_EVIDENCE_TOKEN,
            )
        )
        frontier_entries.append(
            PlanningFrontierEntry(
                occurrence_id=provenance.occurrence_id,
                template_id=template_id,
                candidate_digest=candidate_digest,
                status="completed_cost_eligible",
                plan_id=plan_id,
                forced_provenance_identity=provenance.identity_digest,
                reasons=(),
                _construction_token=_PLANNING_EVIDENCE_TOKEN,
            )
        )
    batch = PlanningEvidenceBatch(
        identity=identity,
        roots=tuple(roots),
        frontier_entries=tuple(frontier_entries),
        frontier_complete=True,
        batch_digest=_planning_batch_digest(
            identity,
            roots,
            frontier_entries,
            True,
        ),
        _construction_token=_PLANNING_EVIDENCE_TOKEN,
    )
    return _register_batch(batch)


def _mint_test_planning_evidence_batch(
    strict_results: Sequence[StrictPlanningResult],
    *,
    prospective_costs: Mapping[str, float],
    schemas: Mapping[str, Sequence[TypedRootSchemaColumn]],
    physical_observations: Mapping[str, TypedRootPhysicalObservation],
    structural_rejections: Mapping[str, Sequence[str]] | None = None,
    batch_label: str = "isolated-root-selection-test",
    cost_model_version: str = "isolated-plain-explain-v1",
) -> PlanningEvidenceBatch:
    """Private isolated-test adapter; never a production evidence source."""

    stricts = tuple(strict_results)
    if not stricts or not batch_label:
        raise ValueError("test planning batch requires strict roots and a label")
    provenances = tuple(_require_forced_root_provenance(item) for item in stricts)
    stricts = tuple(
        strict
        for _provenance, strict in sorted(
            zip(provenances, stricts),
            key=lambda item: (item[0].template_id, item[0].identity_digest),
        )
    )
    provenances = tuple(_require_forced_root_provenance(item) for item in stricts)
    strict_seals = tuple(
        _require_registered_strict_planning_result(item) for item in stricts
    )
    drafts = tuple(item.draft for item in stricts)
    if any(item is None for item in drafts):
        raise ValueError("test planning batch requires successful strict roots")
    plan_ids = tuple(item.plan_id for item in drafts if item is not None)
    if len(set(plan_ids)) != len(plan_ids):
        raise ValueError("test planning batch contains duplicate strict roots")
    allowed_plan_ids = set(plan_ids)
    for label, evidence in (
        ("prospective costs", prospective_costs),
        ("schemas", schemas),
        ("physical observations", physical_observations),
    ):
        extra = set(evidence) - allowed_plan_ids
        if extra:
            raise ValueError(f"test planning batch has detached {label}")
    inventory = provenances[0].admitted_candidate_inventory
    if any(
        item.admitted_candidate_inventory != inventory
        or item.admitted_candidate_inventory_digest
        != provenances[0].admitted_candidate_inventory_digest
        or item.registry_scope_identity != provenances[0].registry_scope_identity
        or item.registry_manifest_digest != provenances[0].registry_manifest_digest
        for item in provenances
    ):
        raise ValueError("forced roots do not share one fresh admitted inventory")
    strict_by_template = {
        provenance.template_id: (strict, seal, provenance)
        for strict, seal, provenance in zip(stricts, strict_seals, provenances)
    }
    if len(strict_by_template) != len(stricts):
        raise ValueError("test planning batch contains duplicate forced templates")
    inventory_ids = {template_id for template_id, _digest_value in inventory}
    if not set(strict_by_template).issubset(inventory_ids):
        raise ValueError("forced strict root is detached from admitted inventory")
    rejected = {
        str(template_id): tuple(str(reason) for reason in reasons)
        for template_id, reasons in (structural_rejections or {}).items()
    }
    if not set(rejected).issubset(inventory_ids) or set(rejected) & set(strict_by_template):
        raise ValueError("structural rejection classification is detached or conflicting")
    session_digests = {item.session_contract.digest for item in drafts if item is not None}
    registry_digests = {item.registry_digest for item in drafts if item is not None}
    gamma_digests = {_strict_gamma_digest(item) for item in stricts}
    target_digests = {_strict_logical_target_digest(item) for item in stricts}
    logical_target_ids = {_strict_single_logical_target_id(item) for item in stricts}
    rho_digests = {
        item.envelope.rho_digest for item in stricts if item.envelope is not None
    }
    emit_context_digests = {
        item.envelope.emit_context_digest for item in stricts if item.envelope is not None
    }
    obligation_graph_digests = {
        item.envelope.obligation_graph_digest
        for item in stricts
        if item.envelope is not None
    }
    shared_sets = (
        session_digests,
        registry_digests,
        gamma_digests,
        target_digests,
        logical_target_ids,
        rho_digests,
        emit_context_digests,
        obligation_graph_digests,
    )
    if any(len(values) != 1 for values in shared_sets):
        raise ValueError(
            "test planning roots do not share session, registry, Gamma, and query contract"
        )
    session_digest = next(iter(session_digests))
    registry_digest = next(iter(registry_digests))
    gamma_digest = next(iter(gamma_digests))
    snapshot_digest = _digest(
        {
            "test_batch": batch_label,
            "gamma_digest": gamma_digest,
            "strict_result_seals": sorted(strict_seals),
        }
    )
    database_identity_digest = _digest({"test_database": batch_label})
    catalog_digest = _digest(
        {
            "test_catalog": batch_label,
            "admitted_template_ids": sorted(inventory_ids),
        }
    )
    first_draft = drafts[0]
    assert first_draft is not None
    identity = PlanningBatchIdentity(
        batch_id="test:" + batch_label,
        snapshot_digest=snapshot_digest,
        database_identity_digest=database_identity_digest,
        session_contract_digest=session_digest,
        guc_digest=_digest(dict(first_draft.session_contract.gucs)),
        cost_model_version=cost_model_version,
        catalog_digest=catalog_digest,
        gamma_digest=gamma_digest,
        registry_digest=registry_digest,
        registry_scope_identity=provenances[0].registry_scope_identity,
        registry_manifest_digest=provenances[0].registry_manifest_digest,
        admitted_candidate_inventory_digest=(
            provenances[0].admitted_candidate_inventory_digest
        ),
        target_digest=next(iter(target_digests)),
        logical_target_id=next(iter(logical_target_ids)),
        rho_digest=next(iter(rho_digests)),
        emit_context_digest=next(iter(emit_context_digests)),
        obligation_graph_digest=next(iter(obligation_graph_digests)),
        evidence_role="isolated_test_non_promotable",
    )
    roots: list[_PlanningRootEvidence] = []
    frontier_entries: list[PlanningFrontierEntry] = []
    for template_id, candidate_digest in inventory:
        if template_id in rejected:
            frontier_entries.append(
                PlanningFrontierEntry(
                    occurrence_id=provenances[0].occurrence_id,
                    template_id=template_id,
                    candidate_digest=candidate_digest,
                    status="structural_rejection",
                    plan_id=None,
                    forced_provenance_identity=None,
                    reasons=rejected[template_id],
                    _construction_token=_PLANNING_EVIDENCE_TOKEN,
                )
            )
            continue
        strict_tuple = strict_by_template.get(template_id)
        if strict_tuple is None:
            frontier_entries.append(
                PlanningFrontierEntry(
                    occurrence_id=provenances[0].occurrence_id,
                    template_id=template_id,
                    candidate_digest=candidate_digest,
                    status="evidence_failure",
                    plan_id=None,
                    forced_provenance_identity=None,
                    reasons=("forced_attempt_or_validator_receipt_missing",),
                    _construction_token=_PLANNING_EVIDENCE_TOKEN,
                )
            )
            continue
        strict, strict_seal, provenance = strict_tuple
        assert strict.draft is not None and strict.envelope is not None
        plan_id = strict.draft.plan_id
        missing: list[str] = []
        if plan_id not in prospective_costs:
            missing.append("plain_explain_cost_missing")
        if plan_id not in schemas:
            missing.append("typed_root_schema_missing")
        if plan_id not in physical_observations:
            missing.append("typed_root_physical_observation_missing")
        if missing:
            frontier_entries.append(
                PlanningFrontierEntry(
                    occurrence_id=provenance.occurrence_id,
                    template_id=template_id,
                    candidate_digest=candidate_digest,
                    status="evidence_failure",
                    plan_id=plan_id,
                    forced_provenance_identity=provenance.identity_digest,
                    reasons=tuple(missing),
                    _construction_token=_PLANNING_EVIDENCE_TOKEN,
                )
            )
            continue
        columns = tuple(schemas[plan_id])
        physical_observation = physical_observations[plan_id]
        if (
            all(item.__class__ is TypedRootSchemaColumn for item in columns)
            and physical_observation.__class__ is TypedRootPhysicalObservation
        ):
            identity_reasons = _strict_root_observation_rejection_reasons(
                strict,
                columns,
                physical_observation,
            )
            if identity_reasons:
                frontier_entries.append(
                    PlanningFrontierEntry(
                        occurrence_id=provenance.occurrence_id,
                        template_id=template_id,
                        candidate_digest=candidate_digest,
                        status="evidence_failure",
                        plan_id=plan_id,
                        forced_provenance_identity=provenance.identity_digest,
                        reasons=identity_reasons,
                        _construction_token=_PLANNING_EVIDENCE_TOKEN,
                    )
                )
                continue
        schema_digest = _schema_receipt_digest(
            strict_result_identity_seal=strict_seal,
            plan_id=plan_id,
            complete_root_plan_digest=strict.draft.bound_ir_digest,
            exact_sql_digest=strict.draft.exact_sql_digest,
            snapshot_digest=snapshot_digest,
            columns=columns,
        )
        schema = TypedRootSchemaReceipt(
            strict_result=strict,
            strict_result_identity_seal=strict_seal,
            plan_id=plan_id,
            complete_root_plan_digest=strict.draft.bound_ir_digest,
            exact_sql_digest=strict.draft.exact_sql_digest,
            snapshot_digest=snapshot_digest,
            columns=columns,
            receipt_digest=schema_digest,
            _construction_token=_PLANNING_EVIDENCE_TOKEN,
        )
        result_columns = tuple(
            item for item in columns if item.visibility == "visible"
        )
        continuation = _mint_source_controlled_continuation_spec(
            spec_id="isolated-test-identity-v1",
            query_id=provenance.occurrence_id,
            policy_id=next(
                iter(strict.query_result.effective_occurrence_goals.values())
            ).problem.policy_id,
            renderer_id="isolated-test-visible-root-renderer",
            renderer_version="v1",
            result_mode="typed_rid_set",
            required_hidden_carriers=("__rid",),
            result_columns=result_columns,
            ordered_keys=(),
            row_limit=None,
            continuation_sql=(
                "\nSELECT "
                + ", ".join(item.name for item in result_columns)
                + " FROM caprls_access_root"
            ),
        )
        runner_sql = _compose_exact_bound_runner_sql(
            strict,
            continuation.continuation_sql,
        )
        bound_runner = _mint_bound_runner_identity(
            strict,
            continuation_spec=continuation,
            runner_sql=runner_sql,
            case_owner_identity_digest=_digest(
                {"isolated_test_owner": batch_label}
            ),
            snapshot_digest=snapshot_digest,
            database_identity_digest=database_identity_digest,
            catalog_digest=catalog_digest,
        )
        runner_schema_digest = _runner_schema_receipt_digest(
            bound_runner_identity_digest=bound_runner.identity_digest,
            plan_id=plan_id,
            snapshot_digest=snapshot_digest,
            result_contract_digest=bound_runner.result_contract_digest,
            columns=result_columns,
        )
        runner_schema = TypedRunnerResultSchemaReceipt(
            bound_runner=bound_runner,
            bound_runner_identity_digest=bound_runner.identity_digest,
            plan_id=plan_id,
            snapshot_digest=snapshot_digest,
            result_contract_digest=bound_runner.result_contract_digest,
            columns=result_columns,
            receipt_digest=runner_schema_digest,
            _construction_token=_PLANNING_EVIDENCE_TOKEN,
        )
        root_evidence = _PlanningRootEvidence(
                strict_result=strict,
                bound_runner=bound_runner,
                strict_result_identity_seal=strict_seal,
                plan_id=plan_id,
                complete_root_plan_digest=bound_runner.identity_digest,
                explain_plan_digest=_digest(
                    {"test_plain_explain": batch_label, "plan_id": plan_id}
                ),
                prospective_total_cost=float(prospective_costs[plan_id]),
                sql_ast_digest=bound_runner.runner_sql_digest,
                certificate_digest=strict.envelope.digest,
                static_verification_digest=_digest(
                    {"test_static_verification": batch_label, "plan_id": plan_id}
                ),
                exact_sql_digest=bound_runner.runner_sql_digest,
                schema_receipt=schema,
                runner_schema_receipt=runner_schema,
                physical_observation=physical_observation,
                _construction_token=_PLANNING_EVIDENCE_TOKEN,
            )
        roots.append(root_evidence)
        frontier_entries.append(
            PlanningFrontierEntry(
                occurrence_id=provenance.occurrence_id,
                template_id=template_id,
                candidate_digest=candidate_digest,
                status="completed_cost_eligible",
                plan_id=plan_id,
                forced_provenance_identity=provenance.identity_digest,
                reasons=(),
                _construction_token=_PLANNING_EVIDENCE_TOKEN,
            )
        )
    batch = PlanningEvidenceBatch(
        identity=identity,
        roots=tuple(roots),
        frontier_entries=tuple(frontier_entries),
        frontier_complete=True,
        batch_digest=_planning_batch_digest(
            identity,
            roots,
            frontier_entries,
            True,
        ),
        _construction_token=_PLANNING_EVIDENCE_TOKEN,
    )
    return _register_batch(batch)


__all__ = [
    "BoundRunnerIdentity",
    "CompletedRootPlan",
    "ContinuationSpec",
    "PlanningBatchIdentity",
    "PlanningEvidenceBatch",
    "PlanningFrontierEntry",
    "RootDominator",
    "RootPairDecision",
    "RootProfileValidation",
    "RootSelectionAudit",
    "RootSelectionResult",
    "TypedRootPhysicalObservation",
    "TypedRootSchemaColumn",
    "TypedRootSchemaReceipt",
    "TypedRunnerResultSchemaReceipt",
    "completed_root_plans_from_batch",
    "select_completed_roots",
]
