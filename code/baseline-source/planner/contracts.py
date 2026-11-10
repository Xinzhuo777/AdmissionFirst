"""Canonical semantic and executable contracts for CAPRLS templates.

This module is the single source of truth for the finite template portfolio.
Historically, :mod:`planner.core`, :mod:`planner.kappa`, the SQL emitter, and
the static verifier each carried overlapping lists of template IDs.  That made
it possible for a template to be admitted by the planner while silently
falling through to an unrelated SQL scan.  Definitions below deliberately
separate semantic facts from executable capabilities and give every template
an explicit execution class.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Mapping, Optional


EXECUTION_CLASSES = frozenset(
    {"production_normal", "baseline", "external_enforcement", "diagnostic_only"}
)
TARGET_REFINEMENT_KINDS = frozenset({"query_filtered"})
_SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Canonical preconditions that require validator-issued Gamma facts.  The
# remaining preconditions (for example transparent_parent and licensed
# refinement) are rho/target obligations and are checked by the contract
# evaluator separately.  Keeping this table next to TemplateDefinition avoids
# silently accepting a newly declared semantic precondition because no caller
# happened to add an ad-hoc boolean check.
PRECONDITION_GAMMA_FACT_KINDS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "trusted_exact_policy_executable": ("trusted_exact_policy_executable",),
        "safe_query_predicate": ("safe_query_predicate",),
        "engine_rls_policy_installed": ("native_rls_session_contract",),
        "declared_authorization_view": ("authorization_view_binding",),
        "fresh_scoped_snapshot_valid_rid_compatible_artifact": ("artifact_validation",),
        "key_domain_compatible_artifact": ("artifact_validation",),
        "complete_candidate_basis": ("complete_candidate_basis",),
        "trusted_exact_residual_executable": ("trusted_exact_residual_executable",),
    }
)


def _freeze_value(value: Any) -> Any:
    """Take an immutable recursive snapshot at the canonical catalog edge."""

    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze_value(child) for key, child in value.items()})
    if isinstance(value, (tuple, list)):
        return tuple(_freeze_value(child) for child in value)
    if isinstance(value, set):
        return frozenset(_freeze_value(child) for child in value)
    return value


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return _freeze_value(dict(value))


def canonical_predicate_digest(predicate: str) -> str:
    """Digest the controlled finite-fragment predicate spelling.

    This is intentionally a narrow identity check, not a claim of general SQL
    AST equivalence.  G7a subsequently binds the full canonical AST/SQL.  At
    this boundary it prevents a native-RLS contract issued for one predicate
    from being used to emit a different predicate's policy fingerprint.
    """

    normalized = re.sub(r"\s+", " ", str(predicate).strip()).lower()
    return "sha256:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _identity_digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PolicyAccessTarget:
    """Occurrence-specific logical ``PolicyAccess(R, Pi, u, c)`` identity.

    RID/carrier identity is deliberately absent. It belongs to the parent
    requirement and the implementation binding, whereas this value names the
    logical denotation that remains stable when physical templates change.
    ``policy_predicate_digest`` names the validated ``Pi_R`` definition; it
    is distinct from any concrete lowering/executable predicate spelling.
    """

    relation: str
    policy_id: str
    occurrence_id: str
    principal_id: str
    context_digest: str
    policy_predicate_digest: str

    def __post_init__(self) -> None:
        required = {
            "relation": self.relation,
            "policy_id": self.policy_id,
            "occurrence_id": self.occurrence_id,
            "principal_id": self.principal_id,
            "context_digest": self.context_digest,
            "policy_predicate_digest": self.policy_predicate_digest,
        }
        missing = sorted(label for label, value in required.items() if not str(value))
        if missing:
            raise ValueError(
                "PolicyAccessTarget requires complete logical identity: "
                + ", ".join(missing)
            )
        if not _SHA256_DIGEST_RE.fullmatch(self.context_digest):
            raise ValueError("PolicyAccessTarget context_digest must be a sha256 digest")
        if not _SHA256_DIGEST_RE.fullmatch(self.policy_predicate_digest):
            raise ValueError(
                "PolicyAccessTarget policy_predicate_digest must be a sha256 digest"
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": "policy_access",
            "relation": self.relation,
            "policy_id": self.policy_id,
            "occurrence_id": self.occurrence_id,
            "principal_id": self.principal_id,
            "context_digest": self.context_digest,
            "policy_predicate_digest": self.policy_predicate_digest,
        }

    @property
    def digest(self) -> str:
        return _identity_digest(self.to_dict())


@dataclass(frozen=True)
class ImplementationTargetBinding:
    """Bind one canonical template declaration to one logical occurrence.

    A binding is structural input, not evidence that a refinement is valid.
    When ``refinement_kind`` is present, admission additionally requires a
    current validator fact whose subject covers this binding and snapshot.
    """

    template_id: str
    occurrence_id: str
    logical_target_digest: str
    implementation_target_kind: str
    rid_col: str
    context_digest: str
    refinement_kind: Optional[str] = None
    refinement_predicate_digest: Optional[str] = None

    def __post_init__(self) -> None:
        required = {
            "template_id": self.template_id,
            "occurrence_id": self.occurrence_id,
            "implementation_target_kind": self.implementation_target_kind,
            "rid_col": self.rid_col,
        }
        missing = sorted(label for label, value in required.items() if not str(value))
        if missing:
            raise ValueError(
                "ImplementationTargetBinding requires complete implementation identity: "
                + ", ".join(missing)
            )
        if not _SHA256_DIGEST_RE.fullmatch(self.logical_target_digest):
            raise ValueError(
                "ImplementationTargetBinding logical_target_digest must be a sha256 digest"
            )
        if not _SHA256_DIGEST_RE.fullmatch(self.context_digest):
            raise ValueError(
                "ImplementationTargetBinding context_digest must be a sha256 digest"
            )
        has_refinement = bool(self.refinement_kind)
        has_predicate = bool(self.refinement_predicate_digest)
        if has_refinement != has_predicate:
            raise ValueError(
                "ImplementationTargetBinding refinement kind and predicate digest must be paired"
            )
        if has_predicate and not _SHA256_DIGEST_RE.fullmatch(
            str(self.refinement_predicate_digest)
        ):
            raise ValueError(
                "ImplementationTargetBinding refinement predicate must be a sha256 digest"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "occurrence_id": self.occurrence_id,
            "logical_target_digest": self.logical_target_digest,
            "implementation_target_kind": self.implementation_target_kind,
            "rid_col": self.rid_col,
            "context_digest": self.context_digest,
            "refinement_kind": self.refinement_kind,
            "refinement_predicate_digest": self.refinement_predicate_digest,
        }

    @property
    def digest(self) -> str:
        return _identity_digest(self.to_dict())


def target_refinement_subject_digest(
    binding: ImplementationTargetBinding,
    target: PolicyAccessTarget,
    *,
    snapshot_id: str,
) -> str:
    """Return the current-snapshot subject for a refinement validator fact."""

    return _identity_digest(
        {
            "contract": "target_refinement_v1",
            "logical_target": target.to_dict(),
            "logical_target_digest": target.digest,
            "implementation_binding": binding.to_dict(),
            "implementation_binding_digest": binding.digest,
            "snapshot_id": str(snapshot_id),
        }
    )


def implementation_target_match_subject_digest(
    binding: ImplementationTargetBinding,
    target: PolicyAccessTarget,
    *,
    snapshot_id: str,
) -> str:
    """Return the current-snapshot subject for a non-bare target match fact."""

    return _identity_digest(
        {
            "contract": "implementation_target_match_v1",
            "logical_target": target.to_dict(),
            "logical_target_digest": target.digest,
            "implementation_binding": binding.to_dict(),
            "implementation_binding_digest": binding.digest,
            "snapshot_id": str(snapshot_id),
        }
    )


@dataclass(frozen=True)
class AuthorizationViewBinding:
    """A declared, scope-bound authorization view usable by one occurrence.

    ``binding_id`` is immutable evidence used to bind planning, certification,
    and execution.  The view name is never inferred from a base-table name.
    """

    binding_id: str
    view_relation: str
    base_relation: str
    rid_col: str
    policy_id: str
    scope_fingerprint: str
    relation_oid: str = ""
    view_definition_digest: str = ""
    policy_fingerprint: str = ""
    rid_domain_id: str = ""
    validator_evidence_digest: str = ""
    snapshot_id: str = ""

    def matches(self, *, relation: str, rid_col: str, policy_id: str) -> bool:
        return (
            bool(self.binding_id)
            and bool(self.view_relation)
            and bool(self.scope_fingerprint)
            and bool(self.relation_oid)
            and bool(self.view_definition_digest)
            and bool(self.policy_fingerprint)
            and bool(self.rid_domain_id)
            and bool(self.validator_evidence_digest)
            and bool(self.snapshot_id)
            and self.base_relation == relation
            and self.rid_col == rid_col
            and self.policy_id == policy_id
        )


@dataclass(frozen=True)
class NativeRLSSessionContract:
    """Typed evidence required before delegating authorization to PostgreSQL.

    This is intentionally stronger than an ``engine_rls_available`` boolean:
    a role that bypasses RLS, an owner without FORCE ROW LEVEL SECURITY, or a
    missing snapshot/fingerprint cannot be treated as native authorization.
    """

    contract_id: str
    relation: str
    policy_id: str
    policy_fingerprint: str
    role: str
    snapshot_id: str
    emitted_policy_digest: str = ""
    validator_evidence_digest: str = ""
    row_security_enabled: bool = True
    role_bypasses_rls: bool = False
    role_owns_relation: bool = False
    force_row_security: bool = False

    def matches(self, *, relation: str, policy_id: str) -> bool:
        return (
            bool(self.contract_id)
            and bool(self.policy_fingerprint)
            and bool(self.role)
            and bool(self.snapshot_id)
            and bool(self.emitted_policy_digest)
            and bool(self.validator_evidence_digest)
            and self.relation == relation
            and self.policy_id == policy_id
            and self.row_security_enabled
            and not self.role_bypasses_rls
            and (not self.role_owns_relation or self.force_row_security)
        )


@dataclass(frozen=True)
class GammaFact:
    """Versioned evidence consumed by contract admission.

    ``kind`` is deliberately an extensible string because the experiment
    portfolio contains policy, artifact, view, and session validators.  The
    tuple of identity/version/snapshot fields prevents an unscoped boolean
    from being reused as evidence for another occurrence or snapshot.
    """

    fact_id: str
    kind: str
    subject_digest: str
    verdict: str
    validator_version: str
    snapshot_id: str
    evidence_digest: str = ""
    dynamic: bool = False

    def __post_init__(self) -> None:
        required = {
            "fact_id": self.fact_id,
            "kind": self.kind,
            "subject_digest": self.subject_digest,
            "validator_version": self.validator_version,
            "snapshot_id": self.snapshot_id,
            "evidence_digest": self.evidence_digest,
        }
        missing = sorted(label for label, value in required.items() if not str(value))
        if missing:
            raise ValueError("GammaFact requires validator-bound fields: " + ", ".join(missing))
        if not _SHA256_DIGEST_RE.fullmatch(self.evidence_digest):
            raise ValueError("GammaFact evidence_digest must be a sha256 digest")
        if self.verdict not in {"pass", "fail"}:
            raise ValueError("GammaFact verdict must be pass or fail")

    @property
    def accepted(self) -> bool:
        return self.verdict == "pass"


@dataclass(frozen=True)
class GammaSnapshot:
    """Immutable evidence snapshot used by one planner admission pass."""

    snapshot_id: str
    facts: tuple[GammaFact, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "facts", tuple(self.facts))
        if not self.snapshot_id:
            raise ValueError("GammaSnapshot requires a snapshot_id")
        if any(not isinstance(fact, GammaFact) for fact in self.facts):
            raise TypeError("GammaSnapshot facts must be GammaFact values")

    def matching(
        self,
        kind: str,
        *,
        subject_digest: str | None = None,
        require_static: bool = False,
    ) -> tuple[GammaFact, ...]:
        return tuple(
            fact
            for fact in self.facts
            if fact.kind == kind
            and fact.snapshot_id == self.snapshot_id
            and (subject_digest is None or fact.subject_digest == subject_digest)
            and (not require_static or not fact.dynamic)
        )

    def has_pass(
        self,
        kind: str,
        *,
        subject_digest: str | None = None,
        require_static: bool = False,
    ) -> bool:
        return any(
            fact.accepted
            for fact in self.matching(
                kind,
                subject_digest=subject_digest,
                require_static=require_static,
            )
        )

    @cached_property
    def digest(self) -> str:
        payload = "|".join(
            "\x1f".join(
                (
                    fact.fact_id,
                    fact.kind,
                    fact.subject_digest,
                    fact.verdict,
                    fact.validator_version,
                    fact.snapshot_id,
                    fact.evidence_digest,
                    "dynamic" if fact.dynamic else "static",
                )
            )
            for fact in sorted(self.facts, key=lambda item: item.fact_id)
        )
        return "sha256:" + hashlib.sha256(
            (self.snapshot_id + "\n" + payload).encode("utf-8")
        ).hexdigest()


@dataclass(frozen=True)
class MemoGoal:
    """Typed memo key for one target/rho/Gamma admission request."""

    relation: str
    policy_id: str
    occurrence_id: str
    rid_col: str
    rho_digest: str
    gamma: GammaSnapshot
    logical_target: Optional[PolicyAccessTarget] = None

    def __post_init__(self) -> None:
        required = {
            "relation": self.relation,
            "policy_id": self.policy_id,
            "occurrence_id": self.occurrence_id,
            "rid_col": self.rid_col,
            "rho_digest": self.rho_digest,
        }
        missing = sorted(label for label, value in required.items() if not str(value))
        if missing:
            raise ValueError("MemoGoal requires complete target/rho identity: " + ", ".join(missing))
        if not isinstance(self.gamma, GammaSnapshot):
            raise TypeError("MemoGoal gamma must be a GammaSnapshot")
        if self.logical_target is not None and not isinstance(
            self.logical_target, PolicyAccessTarget
        ):
            raise TypeError("MemoGoal logical_target must be a PolicyAccessTarget")

    @property
    def target_kind(self) -> str:
        return "policy_access" if self.logical_target is not None else "legacy_untyped"

    @property
    def target_digest(self) -> Optional[str]:
        return None if self.logical_target is None else self.logical_target.digest


@dataclass(frozen=True)
class AdmissionDecision:
    """Structured result of evaluating a canonical template contract."""

    accepted: bool
    rejection_codes: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    memo_goal: MemoGoal
    required_dynamic_fact_kinds: tuple[str, ...] = ()
    compatibility_mode: str = "typed"
    implementation_target_binding: Optional[ImplementationTargetBinding] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "rejection_codes", tuple(str(code) for code in self.rejection_codes))
        object.__setattr__(
            self,
            "evidence_refs",
            tuple(sorted(set(str(ref) for ref in self.evidence_refs))),
        )
        object.__setattr__(
            self,
            "required_dynamic_fact_kinds",
            tuple(sorted(set(str(kind) for kind in self.required_dynamic_fact_kinds))),
        )
        if self.compatibility_mode not in {"typed", "legacy_diagnostic"}:
            raise ValueError("AdmissionDecision compatibility_mode is invalid")
        if self.implementation_target_binding is not None and not isinstance(
            self.implementation_target_binding, ImplementationTargetBinding
        ):
            raise TypeError(
                "AdmissionDecision implementation_target_binding has invalid type"
            )


@dataclass(frozen=True)
class TemplateDefinition:
    """Complete semantic/admission/execution contract for one template."""

    template_id: str
    alternative: str
    target_kind: str
    pre: tuple[str, ...]
    guarantee: str
    safety: str
    freshness: str
    physprops: Mapping[str, Any] = field(default_factory=dict)
    residual_kind: Optional[str] = None
    refinement_predicate: Optional[str] = None
    allowed_refinement_kinds: frozenset[str] = frozenset()

    # Planner admission requirements.  These compile to the compatibility
    # ``TemplateSpec`` surface in planner.core.
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

    # Executable capability contract.  An ID is used rather than an imported
    # callable to keep this module acyclic and make the matrix auditable.
    execution_class: str = "production_normal"
    lowering_id: Optional[str] = None
    static_verifier_id: Optional[str] = None
    certificate_builder_id: Optional[str] = "transfer_certificate_v1"
    cost_extractor_id: Optional[str] = "finite_cost_model_v1"
    sql_skeleton: str = ""
    include_in_default_registry: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "pre", tuple(str(value) for value in self.pre))
        object.__setattr__(self, "physprops", _freeze_mapping(self.physprops))
        object.__setattr__(
            self,
            "required_artifacts",
            frozenset(str(value) for value in self.required_artifacts),
        )
        object.__setattr__(
            self,
            "allowed_refinement_kinds",
            frozenset(str(value) for value in self.allowed_refinement_kinds),
        )
        unknown_refinements = self.allowed_refinement_kinds - TARGET_REFINEMENT_KINDS
        if unknown_refinements:
            raise ValueError(
                "template definition declares unknown target refinements: "
                + ", ".join(sorted(unknown_refinements))
            )
        if not self.template_id or not self.alternative or not self.target_kind:
            raise ValueError("template definition requires template_id, alternative, and target_kind")
        if self.execution_class not in EXECUTION_CLASSES:
            raise ValueError(
                f"unknown template execution class for {self.template_id}: "
                f"{self.execution_class}"
            )
        if self.execution_class == "diagnostic_only" and self.include_in_default_registry:
            raise ValueError(
                f"diagnostic template must not be in default registry: {self.template_id}"
            )
        executable = self.execution_class != "diagnostic_only"
        required_capabilities = (
            self.lowering_id,
            self.static_verifier_id,
            self.certificate_builder_id,
            self.cost_extractor_id,
        )
        if executable and any(not capability for capability in required_capabilities):
            raise ValueError(
                f"executable template requires every implementation capability: {self.template_id}"
            )
        if not executable and any(capability is not None for capability in required_capabilities):
            raise ValueError(
                f"diagnostic template must not claim production execution capabilities: {self.template_id}"
            )


def _definition(
    template_id: str,
    alternative: str,
    target_kind: str,
    pre: tuple[str, ...],
    guarantee: str,
    safety: str,
    freshness: str,
    *,
    physprops: Mapping[str, Any] | None = None,
    residual_kind: Optional[str] = None,
    refinement_predicate: Optional[str] = None,
    allowed_refinement_kinds: frozenset[str] = frozenset(),
    required_artifacts: frozenset[str] = frozenset(),
    requires_exact_policy_safe: bool = False,
    requires_safe_query_predicate: bool = False,
    requires_transparent_parent: bool = False,
    rejects_unsafe_expression_boundary: bool = False,
    requires_guard: bool = False,
    produces_residual: bool = False,
    requires_keyed_artifact: bool = False,
    requires_engine_rls: bool = False,
    requires_authorization_view: bool = False,
    execution_class: str = "production_normal",
    sql_skeleton: str = "",
    include_in_default_registry: bool = True,
) -> TemplateDefinition:
    return TemplateDefinition(
        template_id=template_id,
        alternative=alternative,
        target_kind=target_kind,
        pre=pre,
        guarantee=guarantee,
        safety=safety,
        freshness=freshness,
        physprops=dict(physprops or {}),
        residual_kind=residual_kind,
        refinement_predicate=refinement_predicate,
        allowed_refinement_kinds=allowed_refinement_kinds,
        required_artifacts=required_artifacts,
        requires_exact_policy_safe=requires_exact_policy_safe,
        requires_safe_query_predicate=requires_safe_query_predicate,
        requires_transparent_parent=requires_transparent_parent,
        rejects_unsafe_expression_boundary=rejects_unsafe_expression_boundary,
        requires_guard=requires_guard,
        produces_residual=produces_residual,
        requires_keyed_artifact=requires_keyed_artifact,
        requires_engine_rls=requires_engine_rls,
        requires_authorization_view=requires_authorization_view,
        execution_class=execution_class,
        lowering_id=(None if execution_class == "diagnostic_only" else template_id),
        static_verifier_id=(None if execution_class == "diagnostic_only" else template_id),
        certificate_builder_id=(
            None if execution_class == "diagnostic_only" else "transfer_certificate_v1"
        ),
        cost_extractor_id=(
            None if execution_class == "diagnostic_only" else "finite_cost_model_v1"
        ),
        sql_skeleton=sql_skeleton,
        include_in_default_registry=include_in_default_registry,
    )


# Keep this tuple intentionally ordered: the registry tie-break and experiment
# manifests depend on deterministic order.  All semantic fields that formerly
# lived in planner.kappa are declared here, exactly once.
TEMPLATE_DEFINITIONS: tuple[TemplateDefinition, ...] = (
    _definition(
        "barrier_filter_v1",
        "BarrierFilter",
        "bare_occurrence",
        ("trusted_exact_policy_executable",),
        "exact_stream",
        "exact_authorized",
        "non_artifact",
        physprops={"barrier": "materialized"},
        sql_skeleton=(
            "WITH auth AS MATERIALIZED (SELECT {R}.*, {R}.{rid_col} AS __rid "
            "FROM {R} WHERE <exact_policy>) SELECT * FROM auth"
        ),
    ),
    _definition(
        "barrier_filter_inline_v1",
        "InlineBarrierFilter",
        "bare_occurrence",
        ("trusted_exact_policy_executable", "transparent_parent"),
        "exact_stream",
        "exact_authorized",
        "non_artifact",
        physprops={"barrier": "inline"},
        requires_exact_policy_safe=True,
        requires_transparent_parent=True,
        rejects_unsafe_expression_boundary=True,
        sql_skeleton=(
            "WITH auth AS NOT MATERIALIZED (SELECT {R}.*, {R}.{rid_col} AS __rid "
            "FROM {R} WHERE <exact_policy>) SELECT * FROM auth"
        ),
    ),
    _definition(
        "safe_predicate_injection_v1",
        "SafePredicateInjection",
        "query_filtered",
        ("trusted_exact_policy_executable", "safe_query_predicate"),
        "exact_stream",
        "exact_authorized",
        "non_artifact",
        physprops={"predicate_placement": "injected"},
        allowed_refinement_kinds=frozenset({"query_filtered"}),
        requires_exact_policy_safe=True,
        requires_safe_query_predicate=True,
        sql_skeleton="SELECT * FROM {R} WHERE <safe_query> AND <exact_policy>",
    ),
    _definition(
        "native_pg_rls_v1",
        "NativePostgreSQLRLS",
        "bare_occurrence",
        ("engine_rls_policy_installed",),
        "exact_stream",
        "engine_authorized",
        "engine_policy_snapshot",
        physprops={"engine": "postgres_rls"},
        requires_engine_rls=True,
        execution_class="external_enforcement",
        sql_skeleton="SELECT * FROM {R} WHERE <ordinary_query_predicate> -- engine RLS policy enforced",
    ),
    _definition(
        "raw_pushdown_positive_control_v1",
        "UnsafeRawPushdownPositiveControl",
        "bare_occurrence",
        ("unsafe_positive_control",),
        "raw_stream",
        "unsafe_before_authorization",
        "non_artifact",
        physprops={"predicate_placement": "raw_pushdown_positive_control"},
        requires_exact_policy_safe=True,
        requires_transparent_parent=True,
        rejects_unsafe_expression_boundary=True,
        execution_class="diagnostic_only",
        include_in_default_registry=False,
        sql_skeleton=(
            "SELECT unsafe_log({R}.{rid_col}) FROM {R} "
            "WHERE <ordinary_query_predicate_before_exact_policy>"
        ),
    ),
    _definition(
        "ordinary_first_exact_check_v1",
        "OrdinaryFirstExactCheck",
        "query_filtered",
        (
            "trusted_exact_policy_executable",
            "safe_query_predicate",
            "licensed_query_filtered_refinement",
        ),
        "exact_stream",
        "exact_authorized",
        "non_artifact",
        physprops={"predicate_placement": "ordinary_first"},
        refinement_predicate="ordinary_query_predicate",
        allowed_refinement_kinds=frozenset({"query_filtered"}),
        requires_exact_policy_safe=True,
        requires_safe_query_predicate=True,
        sql_skeleton="SELECT * FROM {R} WHERE <ordinary_query_predicate> AND <exact_policy>",
    ),
    _definition(
        "auth_view_scan_v1",
        "AuthorizationViewScan",
        "declared_view",
        ("declared_authorization_view",),
        "exact_stream",
        "exact_authorized",
        "view_policy_snapshot",
        physprops={"source": "authorization_view"},
        requires_authorization_view=True,
        sql_skeleton="SELECT * FROM auth_view_{R}_scope",
    ),
    _definition(
        "auth_index_enum_v1",
        "AuthorizationIndexSeek",
        "rid_domain",
        ("fresh_scoped_snapshot_valid_rid_compatible_artifact",),
        "exact_rids",
        "exact_authorized",
        "artifact_snapshot_valid",
        physprops={"artifact_type": "auth_idx"},
        required_artifacts=frozenset({"auth_idx"}),
        sql_skeleton="SELECT {R}.* FROM auth_idx JOIN {R} ON {R}.{rid_col} = auth_idx.rid",
    ),
    _definition(
        "auth_index_semijoin_v1",
        "AuthorizationIndexSemiJoin",
        "query_filtered",
        (
            "fresh_scoped_snapshot_valid_rid_compatible_artifact",
            "safe_query_predicate",
        ),
        "exact_rids",
        "exact_authorized",
        "artifact_snapshot_valid",
        physprops={"artifact_type": "auth_idx", "join_shape": "semijoin"},
        allowed_refinement_kinds=frozenset({"query_filtered"}),
        required_artifacts=frozenset({"auth_idx"}),
        requires_safe_query_predicate=True,
        sql_skeleton=(
            "SELECT * FROM {R} WHERE <ordinary_query_predicate> "
            "AND EXISTS (SELECT 1 FROM auth_idx WHERE auth_idx.rid = {R}.{rid_col})"
        ),
    ),
    _definition(
        "strong_auth_index_keyed_v1",
        "AuthorizationIndexSeek",
        "rid_domain",
        (
            "fresh_scoped_snapshot_valid_rid_compatible_artifact",
            "key_domain_compatible_artifact",
        ),
        "exact_rids",
        "exact_authorized",
        "artifact_snapshot_valid",
        physprops={"artifact_type": "auth_idx_keyed"},
        required_artifacts=frozenset({"auth_idx_keyed"}),
        requires_keyed_artifact=True,
        sql_skeleton=(
            "SELECT {R}.* FROM auth_idx_keyed JOIN {R} "
            "ON {R}.{rid_col} = auth_idx_keyed.rid"
        ),
    ),
    _definition(
        "auth_index_keyed_semijoin_v1",
        "AuthorizationIndexKeyedSemiJoin",
        "query_filtered",
        (
            "fresh_scoped_snapshot_valid_rid_compatible_artifact",
            "key_domain_compatible_artifact",
            "safe_query_predicate",
        ),
        "exact_rids",
        "exact_authorized",
        "artifact_snapshot_valid",
        physprops={"artifact_type": "auth_idx_keyed", "join_shape": "semijoin"},
        allowed_refinement_kinds=frozenset({"query_filtered"}),
        required_artifacts=frozenset({"auth_idx_keyed"}),
        requires_keyed_artifact=True,
        requires_safe_query_predicate=True,
        sql_skeleton=(
            "SELECT * FROM {R} WHERE <ordinary_query_predicate> "
            "AND EXISTS (SELECT 1 FROM auth_idx_keyed WHERE auth_idx_keyed.rid = {R}.{rid_col} "
            "AND auth_idx_keyed.key_name = <key_name> AND auth_idx_keyed.key_value = <key_value>)"
        ),
    ),
    _definition(
        "mav_scan_v1",
        "MaterializedAuthorizedViewScan",
        "declared_view",
        ("fresh_scoped_snapshot_valid_rid_compatible_artifact",),
        "exact_stream",
        "exact_authorized",
        "artifact_snapshot_valid",
        physprops={"artifact_type": "mav"},
        allowed_refinement_kinds=frozenset({"query_filtered"}),
        required_artifacts=frozenset({"mav"}),
        sql_skeleton="SELECT * FROM auth_mv_{R}_scope WHERE <safe_query_if_any>",
    ),
    _definition(
        "guard_candidate_plus_residual_v1",
        "Guard+LateResidual",
        "bare_occurrence",
        ("complete_candidate_basis", "trusted_exact_residual_executable"),
        "complete_candidate",
        "candidate_until_residual_discharge",
        "non_artifact_candidate",
        physprops={"guard": "complete_candidate"},
        residual_kind="exact_policy_residual",
        requires_guard=True,
        produces_residual=True,
        sql_skeleton=(
            "WITH cand AS MATERIALIZED (SELECT {R}.*, {R}.{rid_col} AS __rid "
            "FROM {R} WHERE <complete_guard>) SELECT * FROM cand"
        ),
    ),
    _definition(
        "hybrid_intersect_v1",
        "HybridIndexIntersect",
        "query_filtered",
        (
            "fresh_scoped_snapshot_valid_rid_compatible_artifact",
            "safe_query_predicate",
        ),
        "exact_rids",
        "exact_authorized",
        "artifact_snapshot_valid",
        physprops={"artifact_type": "auth_idx", "join_shape": "hybrid_intersect"},
        allowed_refinement_kinds=frozenset({"query_filtered"}),
        required_artifacts=frozenset({"auth_idx"}),
        requires_safe_query_predicate=True,
        sql_skeleton=(
            "WITH q AS MATERIALIZED (SELECT {R}.{rid_col} AS rid FROM {R} "
            "WHERE <safe_query>), a AS MATERIALIZED "
            "(SELECT rid FROM auth_idx WHERE <valid_artifact_scope>) "
            "SELECT {R}.* FROM q JOIN a USING (rid) JOIN {R} ON {R}.{rid_col} = q.rid"
        ),
    ),
)


_BY_TEMPLATE_ID = {definition.template_id: definition for definition in TEMPLATE_DEFINITIONS}
if len(_BY_TEMPLATE_ID) != len(TEMPLATE_DEFINITIONS):  # pragma: no cover - import invariant
    raise RuntimeError("duplicate template IDs in canonical definition catalog")


def template_definition(template_id: str) -> TemplateDefinition:
    try:
        return _BY_TEMPLATE_ID[template_id]
    except KeyError as exc:
        raise KeyError(f"unknown canonical template definition: {template_id}") from exc


def implementation_target_binding(
    *,
    template_id: str,
    target: PolicyAccessTarget,
    rid_col: str,
    refinement_kind: Optional[str] = None,
    refinement_predicate: Optional[str] = None,
) -> ImplementationTargetBinding:
    """Construct a binding from the canonical template declaration."""

    definition = template_definition(template_id)
    return ImplementationTargetBinding(
        template_id=template_id,
        occurrence_id=target.occurrence_id,
        logical_target_digest=target.digest,
        implementation_target_kind=definition.target_kind,
        rid_col=str(rid_col),
        context_digest=target.context_digest,
        refinement_kind=refinement_kind,
        refinement_predicate_digest=(
            None
            if refinement_predicate is None
            else canonical_predicate_digest(refinement_predicate)
        ),
    )


def default_template_definitions() -> tuple[TemplateDefinition, ...]:
    return tuple(
        definition
        for definition in TEMPLATE_DEFINITIONS
        if definition.include_in_default_registry
    )


def required_gamma_fact_kinds(definition: TemplateDefinition) -> tuple[str, ...]:
    """Return every typed validator fact implied by canonical preconditions."""

    return tuple(
        sorted(
            {
                kind
                for precondition in definition.pre
                for kind in PRECONDITION_GAMMA_FACT_KINDS.get(precondition, ())
            }
        )
    )


def template_kappa_contracts() -> Mapping[str, Mapping[str, Any]]:
    """Return the legacy κ table shape, derived from canonical definitions."""

    return {
        definition.template_id: {
            "target_kind": definition.target_kind,
            "pre": definition.pre,
            "guarantee": definition.guarantee,
            "safety": definition.safety,
            "freshness": definition.freshness,
            "physprops": dict(definition.physprops),
            **(
                {"residual_kind": definition.residual_kind}
                if definition.residual_kind is not None
                else {}
            ),
            **(
                {"refinement_predicate": definition.refinement_predicate}
                if definition.refinement_predicate is not None
                else {}
            ),
            "allowed_refinement_kinds": tuple(
                sorted(definition.allowed_refinement_kinds)
            ),
        }
        for definition in TEMPLATE_DEFINITIONS
    }


def validate_implementation_capabilities(
    *,
    definitions: tuple[TemplateDefinition, ...] | None = None,
    lowerers: Mapping[str, object] | None = None,
    static_verifiers: Mapping[str, object] | None = None,
    certificate_builders: Mapping[str, object] | None = None,
    cost_extractors: Mapping[str, object] | None = None,
    raise_on_error: bool = True,
) -> tuple[str, ...]:
    """Validate the runtime matrix without creating import-time cycles.

    Production and externally enforced templates require lowering, static
    verification, certificate construction, and costing.  Diagnostic-only
    templates remain in the semantic catalog but cannot accidentally become a
    default planner candidate.
    """

    from .capabilities import CERTIFICATE_BUILDERS, COST_EXTRACTORS
    from .emit import PROTECTED_SCAN_LOWERERS
    from .kappa import template_kappa_table
    from .verifier.static import TEMPLATE_STATIC_VERIFIERS

    violations: list[str] = []
    kappa_ids = set(template_kappa_table())
    active_definitions = TEMPLATE_DEFINITIONS if definitions is None else tuple(definitions)
    active_lowerers = PROTECTED_SCAN_LOWERERS if lowerers is None else lowerers
    active_static_verifiers = (
        TEMPLATE_STATIC_VERIFIERS if static_verifiers is None else static_verifiers
    )
    active_certificate_builders = (
        CERTIFICATE_BUILDERS if certificate_builders is None else certificate_builders
    )
    active_cost_extractors = COST_EXTRACTORS if cost_extractors is None else cost_extractors
    for definition in active_definitions:
        if definition.template_id not in kappa_ids:
            violations.append(f"missing_kappa:{definition.template_id}")
        if definition.execution_class == "diagnostic_only":
            if definition.include_in_default_registry:
                violations.append(f"diagnostic_in_default_registry:{definition.template_id}")
            continue
        if (
            not definition.lowering_id
            or not callable(active_lowerers.get(definition.lowering_id))
        ):
            violations.append(f"missing_lowering:{definition.template_id}")
        if (
            not definition.static_verifier_id
            or not callable(active_static_verifiers.get(definition.static_verifier_id))
        ):
            violations.append(f"missing_static_verifier:{definition.template_id}")
        if (
            not definition.certificate_builder_id
            or not callable(active_certificate_builders.get(definition.certificate_builder_id))
        ):
            violations.append(f"missing_certificate_builder:{definition.template_id}")
        if (
            not definition.cost_extractor_id
            or not callable(active_cost_extractors.get(definition.cost_extractor_id))
        ):
            violations.append(f"missing_cost_extractor:{definition.template_id}")

    executable_ids = {
        definition.lowering_id
        for definition in active_definitions
        if definition.execution_class != "diagnostic_only" and definition.lowering_id
    }
    for lowering_id in active_lowerers:
        if lowering_id not in executable_ids:
            violations.append(f"orphan_lowering:{lowering_id}")
    static_ids = {
        definition.static_verifier_id
        for definition in active_definitions
        if definition.execution_class != "diagnostic_only" and definition.static_verifier_id
    }
    for verifier_id in active_static_verifiers:
        if verifier_id not in static_ids:
            violations.append(f"orphan_static_verifier:{verifier_id}")

    result = tuple(sorted(set(violations)))
    if result and raise_on_error:
        raise RuntimeError("template capability matrix is incomplete: " + ", ".join(result))
    return result
