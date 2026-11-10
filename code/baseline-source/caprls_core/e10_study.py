"""E10 bounded multi-tenant SaaS case-study runner."""

from __future__ import annotations

import hashlib
import json
import math
import platform
import re
import time
import weakref
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Mapping, Optional

import yaml

from .baselines import (
    ADMISSION_FIRST_MODE,
    FINITE_TEMPLATE_UPPER_BOUND_ROLE,
    load_mode_registry,
    mode_execution_order_key,
    normalize_mode_id,
    scientific_mode_key,
)
from .e8b_study import (
    QueryTiming,
    _relation_size_bytes,
    _timed_sql_script,
    _validation_ms_from_psql_output,
)
from .explain_artifacts import attach_static_verifier_explain
from .manifest_validator import file_sha256, scientific_manifest_hash
from .native_rls import configure_native_rls
from .oracle_audit import _load_context, _load_policy, _quote
from .postgres_runner import (
    PostgresEnv,
    PostgresError,
    PostgresTransactionSession,
    run_psql_command,
)
from .repetitions import attach_repetition, iter_repetitions, protocol_from_manifest
from .result_schema import RAW_SCHEMA_VERSION, validate_raw_run_record
from .synthetic_saas import generate_synthetic_saas
from planner.contracts import (
    GammaFact,
    GammaSnapshot,
    ImplementationTargetBinding,
    PolicyAccessTarget,
    canonical_predicate_digest,
    implementation_target_binding,
    implementation_target_match_subject_digest,
    target_refinement_subject_digest,
    template_definition,
)
from planner.emit import (
    ArtifactComponentBinding,
    ArtifactDependencyExpectation,
    ArtifactDependencyIdentity,
    EmitContext,
    StrictArtifactExpectation,
)
from planner.certificate_envelope import (
    canonical_registry_digest,
    policy_predicate_binding_subject,
)
from planner.core import (
    ArtifactMetadata,
    CandidatePlan,
    CostInputs,
    DEFAULT_TEMPLATE_REGISTRY,
    ParentRequirement,
    PlanningProblem,
    PlanResult,
    TemplateRegistry,
    apply_dominance_pruning,
    cost_after_enforcers,
    plan as plan_occurrence,
)
from planner.ir import (
    Materialize,
    Project,
    Root,
    ScanProtected,
    Select,
    UnsafeExpr,
    ValidationGate,
    walk,
)
from planner.query import (
    OccurrenceGoal,
    PlanningQuery,
    QueryPlanResult,
    derive_occurrence_goals,
    plan_query,
)
from planner.execution import ContinuationTemplate, SessionContract
from planner.features import PlannerFeatureFlags
from planner.root_selection import (
    BoundRunnerIdentity,
    ContinuationSpec,
    PlanningEvidenceBatch,
    TypedRootPhysicalObservation,
    TypedRootSchemaColumn,
    _compose_exact_bound_runner_sql,
    _mint_bound_runner_identity,
    _mint_production_planning_evidence_batch,
    _mint_source_controlled_continuation_spec,
    _require_registered_batch,
    select_completed_roots,
)
from planner.state import sigma_from_dict
from planner.strict_planning import (
    StrictPlanningRequest,
    StrictPlanningResult,
    _mint_production_strict_registry_scope,
    _require_forced_root_attempt_provenance,
    _stable_digest as _strict_planning_digest,
    strict_plan_forced_alternative,
)
from planner.verifier.static import (
    StaticVerification,
    native_rls_policy_fingerprint_comment,
    verify_template_static,
)


@dataclass(frozen=True)
class E10Case:
    query_id: str
    label: str
    policy_mix: str
    query_shape: str
    contract_template_id: str
    contract_alternative: str
    contract_reason: str
    local_template_id: str
    local_alternative: str
    policy_evals: int
    residual_checks: int
    artifact_lookups: int
    row_count: int
    mav_validity: str = "fresh"
    available_artifacts: tuple[str, ...] = ("auth_idx", "auth_idx_keyed", "mav")
    exact_policy_safe: bool = False
    auth_cardinality_hint: Optional[int] = None
    complete_guard_sql_template: Optional[str] = None


CASES = [
    E10Case(
        query_id="E10_Q1_support_ticket_lookup",
        label="Support ticket lookup by key",
        policy_mix="tenant_isolation_break_glass",
        query_shape="key_lookup",
        contract_template_id="hybrid_intersect_v1",
        contract_alternative="HybridIndexIntersect",
        contract_reason="safe ordinary key predicate and compatible authorization RIDs make hybrid intersection cheapest",
        local_template_id="strong_auth_index_keyed_v1",
        local_alternative="StrongAuthIndexBaseline",
        policy_evals=0,
        residual_checks=0,
        artifact_lookups=1,
        row_count=1,
        available_artifacts=("auth_idx",),
        auth_cardinality_hint=5000,
    ),
    E10Case(
        query_id="E10_Q2_tenant_dashboard",
        label="Tenant dashboard aggregation",
        policy_mix="tenant_group_dashboard",
        query_shape="dashboard_aggregation",
        contract_template_id="mav_scan_v1",
        contract_alternative="MaterializedAuthorizedViewScan",
        contract_reason="fresh context-scoped MAV discharges residuals before aggregation and amortizes repeated dashboard reads",
        local_template_id="barrier_filter_v1",
        local_alternative="BarrierFilter",
        policy_evals=0,
        residual_checks=0,
        artifact_lookups=1,
        row_count=20,
    ),
    E10Case(
        query_id="E10_Q3_cross_tenant_admin_audit",
        label="Cross-tenant admin audit",
        policy_mix="admin_audit_group_acl",
        query_shape="wide_audit_scan",
        contract_template_id="auth_index_enum_v1",
        contract_alternative="AuthorizationIndexSeek",
        contract_reason="authorization RID artifact is selective enough for admin audit while preserving exact result checks",
        local_template_id="auth_index_enum_v1",
        local_alternative="AuthorizationIndexSeek",
        policy_evals=0,
        residual_checks=0,
        artifact_lookups=1,
        row_count=500,
        available_artifacts=("auth_idx",),
    ),
    E10Case(
        query_id="E10_Q4_shared_document_search_audit",
        label="Shared document search with audit logging",
        policy_mix="owner_shared_audit_logging",
        query_shape="search_with_unsafe_audit_udf",
        contract_template_id="barrier_filter_v1",
        contract_alternative="BarrierFilter",
        contract_reason="unsafe audit logging requires exact authorization before audited values are observed",
        local_template_id="guard_candidate_plus_residual_v1",
        local_alternative="Guard+LateResidual",
        policy_evals=1000,
        residual_checks=0,
        artifact_lookups=0,
        row_count=75,
        available_artifacts=(),
    ),
    E10Case(
        query_id="E10_Q5_invoice_region_purpose_join",
        label="Invoice join with region and purpose policy",
        policy_mix="purpose_region_join",
        query_shape="transparent_join_with_late_residual",
        contract_template_id="guard_candidate_plus_residual_v1",
        contract_alternative="Guard+LateResidual",
        contract_reason="complete guard is useful through transparent joins and residual is discharged before non-transparent boundaries",
        local_template_id="auth_index_enum_v1",
        local_alternative="AuthorizationIndexSeek",
        policy_evals=350,
        residual_checks=160,
        artifact_lookups=0,
        row_count=160,
        available_artifacts=(),
        complete_guard_sql_template="{alias}.region = :ctx_region",
    ),
    E10Case(
        query_id="E10_Q6_own_plus_group_shared_union",
        label="Union of own and group-shared documents",
        policy_mix="branch_lineage_union",
        query_shape="branch_tagged_union_all",
        contract_template_id="barrier_filter_v1",
        contract_alternative="BarrierFilter",
        contract_reason="branch-lineage union is cheapest when exact authorization is materialized before union output",
        local_template_id="barrier_filter_v1",
        local_alternative="BarrierFilter",
        policy_evals=500,
        residual_checks=0,
        artifact_lookups=0,
        row_count=180,
        available_artifacts=(),
    ),
    E10Case(
        query_id="E10_Q7_ordered_export",
        label="Ordered export",
        policy_mix="ordered_tenant_export",
        query_shape="ordered_export",
        contract_template_id="mav_scan_v1",
        contract_alternative="MaterializedAuthorizedViewScan",
        contract_reason="ordered materialized authorized path avoids a large post-authorization sort",
        local_template_id="auth_index_enum_v1",
        local_alternative="AuthorizationIndexSeek",
        policy_evals=0,
        residual_checks=0,
        artifact_lookups=1,
        row_count=1000,
    ),
    E10Case(
        query_id="E10_Q11_ticket_exact_injection",
        label="Support ticket range with cheap tenant-owner policy",
        policy_mix="tenant_owner_ticket_sargable",
        query_shape="ticket_exact_injection",
        contract_template_id="safe_predicate_injection_v1",
        contract_alternative="SafePredicateInjection",
        contract_reason="cheap exact tenant/owner policy is safe to inject and no artifact is declared",
        local_template_id="barrier_filter_v1",
        local_alternative="BarrierFilter",
        policy_evals=20,
        residual_checks=0,
        artifact_lookups=0,
        row_count=20,
        available_artifacts=(),
        exact_policy_safe=True,
    ),
    E10Case(
        query_id="E10_Q8_stale_dashboard_mav",
        label="Tenant dashboard with stale MAV metadata",
        policy_mix="tenant_group_dashboard_stale_mav",
        query_shape="dashboard_aggregation_stale_mav",
        contract_template_id="mav_scan_v1",
        contract_alternative="MaterializedAuthorizedViewScan",
        contract_reason="freshness metadata must reject a stale MAV and fall back to the cheapest admissible exact template",
        local_template_id="barrier_filter_v1",
        local_alternative="BarrierFilter",
        policy_evals=0,
        residual_checks=0,
        artifact_lookups=1,
        row_count=20,
        mav_validity="stale",
    ),
    E10Case(
        query_id="E10_Q9_wrong_context_mav",
        label="Admin audit with wrong-context MAV metadata",
        policy_mix="admin_audit_wrong_context_mav",
        query_shape="wide_audit_scan_wrong_context_mav",
        contract_template_id="mav_scan_v1",
        contract_alternative="MaterializedAuthorizedViewScan",
        contract_reason="context-scope metadata must reject a MAV built for a different context before cost ranking",
        local_template_id="auth_index_enum_v1",
        local_alternative="AuthorizationIndexSeek",
        policy_evals=0,
        residual_checks=0,
        artifact_lookups=1,
        row_count=500,
        mav_validity="wrong_context",
    ),
    E10Case(
        query_id="E10_Q10_revoked_membership_mav",
        label="Ordered export after membership revocation",
        policy_mix="ordered_tenant_export_revoked_mav",
        query_shape="ordered_export_revoked_mav",
        contract_template_id="mav_scan_v1",
        contract_alternative="MaterializedAuthorizedViewScan",
        contract_reason="revocation/freshness metadata must reject a MAV whose membership dependency is stale",
        local_template_id="auth_index_enum_v1",
        local_alternative="AuthorizationIndexSeek",
        policy_evals=0,
        residual_checks=0,
        artifact_lookups=1,
        row_count=1000,
        mav_validity="revoked",
    ),
]

REQUIRED_MODES = {
    "native-pg-rls",
    "native-pg-rls-physical-design",
    "barrier-only",
    "auth-index-enum-only",
    "strong-auth-index",
    "mav-only",
    "guard-mandatory-discharge",
    "local-greedy",
    ADMISSION_FIRST_MODE,
}

DIAGNOSTIC_UNSAFE_PUSHDOWN_MODE = "unsafe-pushdown-positive-control"
E10_BARRIER_QUERY_ID = "E10_Q4_shared_document_search_audit"
E10_GUARD_UNSAFE_STATIC_WITNESS_QUERY_ID = "E10_GUARD_UNSAFE_STATIC_WITNESS"
E10_GUARD_UNSAFE_STATIC_WITNESS_MODE = "guard-mandatory-discharge"
E10_GUARD_UNSAFE_STATIC_WITNESS_RUN_ID = "e10_guard_unsafe_static_witness"
E10_NATIVE_RLS_ROLE = "caprls_e10_rls_user"
E10_NATIVE_RLS_TEMPLATE_IDS = {"native_pg_rls_v1", "native_pg_rls_physical_design_v1"}
E10_EXTRA_HIDDEN_CARRIERS = {
    "E10_Q4_shared_document_search_audit": ("secret",),
    "E10_Q5_invoice_region_purpose_join": ("account_id",),
    "E10_Q6_own_plus_group_shared_union": ("owner_id",),
    "E10_Q11_ticket_exact_injection": ("priority", "status"),
    E10_GUARD_UNSAFE_STATIC_WITNESS_QUERY_ID: ("secret",),
}
E10_ACCESS_COLUMN_CONTRACTS = {
    "document": {
        "doc_id": ("bigint", False),
        "tenant_id": ("bigint", False),
        "owner_id": ("bigint", False),
        "public": ("boolean", False),
        "secret": ("text", False),
    },
    "ticket": {
        "ticket_id": ("bigint", False),
        "tenant_id": ("bigint", False),
        "owner_id": ("bigint", False),
        "status": ("text", False),
        "priority": ("integer", False),
        "secret": ("text", False),
    },
    "invoice": {
        "invoice_id": ("bigint", False),
        "tenant_id": ("bigint", False),
        "account_id": ("bigint", False),
        "region": ("text", False),
        "secret": ("text", False),
    },
}
E10_STATE_OBSERVATION_SCHEMA = "e10_artifact_state_observation_v1"
E10_STATE_COLLECTOR_VERSION = "e10_catalog_state_collector_v1"
E10_STATE_SEARCH_PATH = "pg_catalog, public"
E10_STATE_ROW_SECURITY = "on"
E10_STATE_DEPENDENCY_KINDS = frozenset(
    {
        "artifact_kind",
        "artifact_relation",
        "base",
        "base_relation_oid",
        "context_scope",
        "membership",
        "policy",
        "principal",
        "rid_domain",
    }
)
E10_NEGATIVE_STATE_KIND_BY_QUERY = {
    "E10_Q8_stale_dashboard_mav": "base_epoch_advanced",
    "E10_Q9_wrong_context_mav": "alternate_context",
    "E10_Q10_revoked_membership_mav": "membership_epoch_advanced",
}


def _expected_contract_choice_for_state(case: E10Case) -> str:
    """Return the expected choice after the case's declared state transition."""

    state_kind = E10_NEGATIVE_STATE_KIND_BY_QUERY.get(case.query_id)
    if state_kind in {"base_epoch_advanced", "membership_epoch_advanced"}:
        # Both the MAV and authorization index depend on the advanced epoch.
        return "BarrierFilter"
    if state_kind == "alternate_context":
        # Only the alternate-context MAV is unusable; the scoped auth index remains.
        return "AuthorizationIndexSeek"
    return case.contract_alternative


E10_PLANNING_OBSERVATION_SCHEMA = "e10_planning_catalog_observation_v1"
E10_PLANNING_RECEIPT_SCHEMA = "e10_planning_receipt_v1"
E10_PLANNING_REPLAY_SCHEMA = "e10_planning_replay_v1"
E10_PLANNING_VALIDATOR_VERSION = "e10_planning_validator_v1"
E10_PLANNING_COLLECTOR_VERSION = "e10_planning_collector_v1"
E10_SELECTED_ARTIFACT_OBSERVATION_SCHEMA = (
    "e10_selected_artifact_catalog_observation_v1"
)
E10_SELECTED_ARTIFACT_COLLECTOR_VERSION = (
    "e10_selected_artifact_catalog_collector_v1"
)
E10_PLANNING_TARGET_DOMAIN = "bare_full_policy_target"
E10_PLANNING_ARTIFACT_KINDS = (
    "auth_idx",
    "auth_idx_keyed",
    "mav",
)
E10_ADMISSION_BUNDLE_SCHEMA = "e10_typed_admission_bundle_v1"
E10_ADMISSION_REPLAY_SCHEMA = "e10_typed_admission_replay_v1"
E10_ADMISSION_ISSUER_VERSION = "e10_typed_admission_issuer_v1"
E10_ADMISSION_EVIDENCE_SCHEMA = "e10_gamma_evidence_v1"
E10_ADMISSION_VALIDATOR_VERSION = "e10_typed_admission_validator_v1"
E10_ADMISSION_DYNAMIC_OBLIGATION_KINDS = (
    "artifact_context",
    "artifact_freshness",
    "artifact_toctou",
)
E10_ADMISSION_EVIDENCE_SOURCE_KINDS = frozenset(
    {
        "artifact_assessment",
        "exact_policy_expression",
        "guard_basis",
        "implementation_target_binding",
        "query_predicate_expression",
        "trusted_policy_executable",
    }
)
E10_ADMISSION_SOURCE_KIND_BY_FACT_KIND = {
    "artifact_validation": "artifact_assessment",
    "complete_candidate_basis": "guard_basis",
    "exact_policy_safe": "exact_policy_expression",
    "exact_policy_predicate_binding": "exact_policy_expression",
    "implementation_target_match": "implementation_target_binding",
    "safe_query_predicate": "query_predicate_expression",
    "target_refinement": "implementation_target_binding",
    "trusted_exact_policy_executable": "trusted_policy_executable",
    "trusted_exact_residual_executable": "guard_basis",
}


@dataclass(frozen=True)
class E10StudyResult:
    raw_result_paths: list[Path]
    correctness_result_paths: list[Path]
    correctness_records: int
    normal_records: int
    diagnostic_records: int
    candidate_records: int
    summary_records: int
    query_count: int
    contract_records: int
    chosen_alternatives: int


@dataclass(frozen=True)
class E10StaticWitnessResult:
    raw_result_paths: list[Path]
    witness_records: int


@dataclass(frozen=True)
class E10ModeMeasurement:
    timing: QueryTiming
    row_count: int
    policy_evals: Optional[int]
    residual_checks: Optional[int]
    candidate_rows: Optional[int]
    authorized_rows: Optional[int]
    artifact_lookups: Optional[int]
    base_fetches: Optional[int]
    build_ms: float
    storage_bytes: int
    artifact_versions: Mapping[str, int]
    udf_calls: int = 0
    unauthorized_observations: int = 0
    validation_ms: float = 0.0
    same_snapshot: bool = False
    validation_isolation_level: Optional[str] = None
    static_verifier_status: str = "pass"
    static_verifier_plan_hash: Optional[str] = None
    static_verifier_reasons: tuple[str, ...] = ()
    static_verifier_explain_json: Optional[tuple[Mapping[str, Any], ...]] = None
    runner_sql: Optional[str] = None
    execution_sql_source: str = "case_study_runner_sql"


@dataclass(frozen=True)
class E10PostgresMeasurements:
    pg_version: str
    context_id: str
    ctx_hash: str
    measurements: Mapping[tuple[str, str], E10ModeMeasurement]
    plan_results: Mapping[tuple[str, str], PlanResult]
    candidate_measurements: Mapping[tuple[str, str], E10ModeMeasurement]
    diagnostic_measurements: Mapping[tuple[str, str], E10ModeMeasurement]
    query_plans: Mapping[tuple[str, str], Mapping[str, Any]] = field(
        default_factory=dict
    )
    candidate_query_plans: Mapping[tuple[str, str], Mapping[str, Any]] = field(
        default_factory=dict
    )
    planning_receipts: Mapping[str, E10PlanningReceipt] = field(default_factory=dict)
    planning_expectations: Mapping[str, E10PlanningExpectation] = field(
        default_factory=dict
    )
    planning_admission_bundles: Mapping[str, E10AdmissionBundle] = field(
        default_factory=dict
    )

@dataclass(frozen=True)
class E10PlannerInvocation:
    occurrence_result: PlanResult
    query_result: QueryPlanResult
    query_plan: Mapping[str, Any]
    problem: PlanningProblem
    planning_receipt: Optional[E10PlanningReceipt] = None
    planning_admission_bundle: Optional[E10AdmissionBundle] = None
    production_completed_roots: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class E10ArtifactStateExpectation:
    artifact_id: str
    artifact_kind: str
    physical_relation: str
    base_relation: str
    rid_domain_id: str
    policy_id: str
    principal_id: str
    target_context_hash: str

    def __post_init__(self) -> None:
        values = {
            "artifact_id": self.artifact_id,
            "artifact_kind": self.artifact_kind,
            "physical_relation": self.physical_relation,
            "base_relation": self.base_relation,
            "rid_domain_id": self.rid_domain_id,
            "policy_id": self.policy_id,
            "principal_id": self.principal_id,
            "target_context_hash": self.target_context_hash,
        }
        missing = sorted(key for key, value in values.items() if not str(value))
        if missing:
            raise ValueError(
                "E10 artifact state expectation is incomplete: " + ", ".join(missing)
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_kind": self.artifact_kind,
            "physical_relation": self.physical_relation,
            "base_relation": self.base_relation,
            "rid_domain_id": self.rid_domain_id,
            "policy_id": self.policy_id,
            "principal_id": self.principal_id,
            "target_context_hash": self.target_context_hash,
        }


@dataclass(frozen=True)
class E10ArtifactDependencyState:
    dep_kind: str
    dep_name: str
    version_at_build: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "dep_kind": self.dep_kind,
            "dep_name": self.dep_name,
            "version_at_build": self.version_at_build,
        }


@dataclass(frozen=True)
class E10ArtifactStateObservation:
    schema_version: str
    collector_version: str
    session_user: str
    current_user: str
    search_path: str
    row_security: str
    isolation_level: str
    snapshot_text: str
    artifact_id: str
    physical_relation_oid: Optional[int]
    base_relation_oid: Optional[int]
    target_context_principal_id: Optional[str]
    target_context_payload_json: Optional[str]
    target_context_version: Optional[int]
    artifact_context_principal_id: Optional[str]
    artifact_context_payload_json: Optional[str]
    artifact_context_version: Optional[int]
    current_base_version: Optional[int]
    current_membership_version: Optional[int]
    dependencies: tuple[E10ArtifactDependencyState, ...]
    catalog_state_digest: str
    observation_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "dependencies", tuple(self.dependencies))
        if any(
            not isinstance(item, E10ArtifactDependencyState)
            for item in self.dependencies
        ):
            raise TypeError("E10 artifact dependencies must be typed values")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "collector_version": self.collector_version,
            "session_user": self.session_user,
            "current_user": self.current_user,
            "search_path": self.search_path,
            "row_security": self.row_security,
            "isolation_level": self.isolation_level,
            "snapshot_text": self.snapshot_text,
            "artifact_id": self.artifact_id,
            "physical_relation_oid": self.physical_relation_oid,
            "base_relation_oid": self.base_relation_oid,
            "target_context_principal_id": self.target_context_principal_id,
            "target_context_payload": (
                None
                if self.target_context_payload_json is None
                else json.loads(self.target_context_payload_json)
            ),
            "target_context_version": self.target_context_version,
            "artifact_context_principal_id": self.artifact_context_principal_id,
            "artifact_context_payload": (
                None
                if self.artifact_context_payload_json is None
                else json.loads(self.artifact_context_payload_json)
            ),
            "artifact_context_version": self.artifact_context_version,
            "current_base_version": self.current_base_version,
            "current_membership_version": self.current_membership_version,
            "dependencies": [item.to_dict() for item in self.dependencies],
            "catalog_state_digest": self.catalog_state_digest,
            "observation_digest": self.observation_digest,
        }


@dataclass(frozen=True)
class E10ArtifactStateAssessment:
    valid: bool
    dependency_set_complete: bool
    artifact_identity_matches: bool
    relation_identity_matches: bool
    rid_identity_matches: bool
    policy_identity_matches: bool
    principal_matches: bool
    context_matches: bool
    base_fresh: bool
    context_fresh: bool
    membership_fresh: bool
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "reasons", tuple(self.reasons))

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "dependency_set_complete": self.dependency_set_complete,
            "artifact_identity_matches": self.artifact_identity_matches,
            "relation_identity_matches": self.relation_identity_matches,
            "rid_identity_matches": self.rid_identity_matches,
            "policy_identity_matches": self.policy_identity_matches,
            "principal_matches": self.principal_matches,
            "context_matches": self.context_matches,
            "base_fresh": self.base_fresh,
            "context_fresh": self.context_fresh,
            "membership_fresh": self.membership_fresh,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class E10NegativeStateSpec:
    case_query_id: str
    state_kind: str
    relation: str
    rid_col: str
    policy_id: str
    alias: str
    artifact_id: str
    physical_relation: str
    target_context_id: str
    target_context_hash: str
    target_principal_id: str
    target_context_payload_json: str
    target_context_version: int
    build_context_id: str
    build_context_hash: str
    build_principal_id: str
    build_context_payload_json: str
    build_context_version: int
    exact_predicate: str

    @property
    def expectation(self) -> E10ArtifactStateExpectation:
        return E10ArtifactStateExpectation(
            artifact_id=self.artifact_id,
            artifact_kind="mav",
            physical_relation=self.physical_relation,
            base_relation=f"public.{self.relation}",
            rid_domain_id=f"{self.relation}.{self.rid_col}",
            policy_id=self.policy_id,
            principal_id=self.target_principal_id,
            target_context_hash=self.target_context_hash,
        )


@dataclass(frozen=True)
class E10NegativeStateHandle:
    spec: E10NegativeStateSpec
    baseline_payload_json: str
    baseline_digest: str
    pre_observation: E10ArtifactStateObservation
    negative_observation: E10ArtifactStateObservation
    negative_assessment: E10ArtifactStateAssessment


@dataclass(frozen=True)
class E10StateRestoration:
    baseline_digest: str
    restored_baseline_digest: str
    pre_catalog_state_digest: str
    restored_catalog_state_digest: str
    catalog_exact: bool
    data_exact: bool
    assessment_exact: bool
    restored_assessment: E10ArtifactStateAssessment


@dataclass(frozen=True)
class E10PlanningRegistryEntry:
    template_id: str
    spec_digest: str

    def __post_init__(self) -> None:
        if not self.template_id:
            raise ValueError("E10 planning registry template identifier is missing")
        if re.fullmatch(r"sha256:[0-9a-f]{64}", self.spec_digest) is None:
            raise ValueError("E10 planning registry spec digest is invalid")

    def to_dict(self) -> dict[str, str]:
        return {
            "template_id": self.template_id,
            "spec_digest": self.spec_digest,
        }


@dataclass(frozen=True)
class E10PlanningContextIdentity:
    context_hash: str
    principal_id: str
    canonical_context_json: str
    version: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "context_hash": self.context_hash,
            "principal_id": self.principal_id,
            "canonical_context": json.loads(self.canonical_context_json),
            "version": self.version,
        }


@dataclass(frozen=True)
class E10PlanningScopeIdentity:
    policy_id: str
    principal_id: str
    context_hash: str
    rid_domain_id: str
    base_relation_oid: int
    policy_version: int
    membership_version: int
    key_name: Optional[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "principal_id": self.principal_id,
            "context_hash": self.context_hash,
            "rid_domain_id": self.rid_domain_id,
            "base_relation_oid": self.base_relation_oid,
            "policy_version": self.policy_version,
            "membership_version": self.membership_version,
            "key_name": self.key_name,
        }


@dataclass(frozen=True)
class E10PlanningArtifactExpectation:
    kind: str
    artifact_id: str
    physical_relation: str
    declared: bool
    dependency_profile: str
    key_name: Optional[str] = None

    def __post_init__(self) -> None:
        if self.kind not in E10_PLANNING_ARTIFACT_KINDS:
            raise ValueError(
                "E10 planning artifact kind is outside the finite inventory"
            )
        if not self.artifact_id:
            raise ValueError("E10 planning artifact identifier is missing")
        if (
            not self.physical_relation.startswith("public.")
            or re.fullmatch(
                r"[a-z_][a-z0-9_]*",
                self.physical_relation.removeprefix("public."),
            )
            is None
        ):
            raise ValueError("E10 planning artifact relation is invalid")
        allowed_profiles = {"legacy5"} if self.kind != "mav" else {"legacy5", "state9"}
        if self.dependency_profile not in allowed_profiles:
            raise ValueError("E10 planning artifact dependency profile is unknown")
        if self.kind == "auth_idx_keyed":
            if not self.key_name:
                raise ValueError("E10 keyed artifact key identity is missing")
        elif self.key_name is not None:
            raise ValueError("E10 non-keyed artifact has an unexpected key identity")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "artifact_id": self.artifact_id,
            "physical_relation": self.physical_relation,
            "declared": self.declared,
            "dependency_profile": self.dependency_profile,
            "key_name": self.key_name,
            "target_domain": E10_PLANNING_TARGET_DOMAIN,
        }


@dataclass(frozen=True)
class E10PlanningExpectation:
    scope: str
    case_query_id: str
    occurrence_id: str
    relation_name: str
    rid_col: str
    rid_domain_id: str
    policy_id: str
    policy_manifest_digest: str
    policy_config_digest: str
    policy_definition_digest: str
    exact_predicate: str
    exact_predicate_digest: str
    guard_predicate_digest: str
    query_predicate_digest: str
    principal_id: str
    context_id: str
    context_hash: str
    canonical_context_json: str
    context_version: int
    registry_inventory: tuple[E10PlanningRegistryEntry, ...]
    artifacts: tuple[E10PlanningArtifactExpectation, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "registry_inventory", tuple(self.registry_inventory))
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        if self.scope not in {"production", "fixture"}:
            raise ValueError("E10 planning expectation scope is invalid")
        if not self.exact_predicate.strip():
            raise ValueError("E10 planning exact predicate is missing")
        if self.exact_predicate_digest != _e10_sql_fragment_digest(
            self.exact_predicate
        ):
            raise ValueError("E10 planning exact predicate digest is inconsistent")
        context = json.loads(self.canonical_context_json)
        if not isinstance(context, Mapping):
            raise ValueError("E10 planning canonical context is invalid")
        if _canonical_digest(context) != self.context_hash:
            raise ValueError("E10 planning canonical context digest is inconsistent")
        if str(context.get("user_id")) != self.principal_id:
            raise ValueError("E10 planning canonical context principal is inconsistent")
        if (
            not isinstance(self.context_version, int)
            or isinstance(self.context_version, bool)
            or self.context_version < 0
        ):
            raise ValueError("E10 planning context version is invalid")
        if self.rid_domain_id != f"{self.relation_name}.{self.rid_col}":
            raise ValueError("E10 planning RID domain is inconsistent")
        if self.registry_inventory != tuple(
            sorted(self.registry_inventory, key=lambda item: item.template_id)
        ) or len({item.template_id for item in self.registry_inventory}) != len(
            self.registry_inventory
        ):
            raise ValueError("E10 planning registry inventory is not canonical")
        if tuple(item.kind for item in self.artifacts) != E10_PLANNING_ARTIFACT_KINDS:
            raise ValueError("E10 planning artifact expectation order is not canonical")
        if len({item.artifact_id for item in self.artifacts}) != len(self.artifacts):
            raise ValueError("E10 planning artifact identifiers conflict")
        if len({item.physical_relation for item in self.artifacts}) != len(
            self.artifacts
        ):
            raise ValueError("E10 planning artifact relations conflict")

    @property
    def digest(self) -> str:
        return _canonical_digest(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "case_query_id": self.case_query_id,
            "occurrence_id": self.occurrence_id,
            "relation_name": self.relation_name,
            "rid_col": self.rid_col,
            "rid_domain_id": self.rid_domain_id,
            "policy_id": self.policy_id,
            "policy_manifest_digest": self.policy_manifest_digest,
            "policy_config_digest": self.policy_config_digest,
            "policy_definition_digest": self.policy_definition_digest,
            "exact_predicate_digest": self.exact_predicate_digest,
            "guard_predicate_digest": self.guard_predicate_digest,
            "query_predicate_digest": self.query_predicate_digest,
            "principal_id": self.principal_id,
            "context_id": self.context_id,
            "context_hash": self.context_hash,
            "canonical_context": json.loads(self.canonical_context_json),
            "context_version": self.context_version,
            "registry_inventory": [item.to_dict() for item in self.registry_inventory],
            "artifacts": [item.to_dict() for item in self.artifacts],
        }


@dataclass(frozen=True)
class E10PlanningArtifactObservation:
    kind: str
    artifact_id: str
    physical_relation: str
    physical_relation_oid: Optional[int]
    scope_identities: tuple[E10PlanningScopeIdentity, ...]
    dependencies: tuple[E10ArtifactDependencyState, ...]
    artifact_contexts: tuple[E10PlanningContextIdentity, ...]
    duplicate_identity: bool
    key_identity_matches: bool
    content_exact: bool
    cross_kind_conflict: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope_identities", tuple(self.scope_identities))
        object.__setattr__(self, "dependencies", tuple(self.dependencies))
        object.__setattr__(self, "artifact_contexts", tuple(self.artifact_contexts))

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "artifact_id": self.artifact_id,
            "physical_relation": self.physical_relation,
            "physical_relation_oid": self.physical_relation_oid,
            "scope_identities": [item.to_dict() for item in self.scope_identities],
            "dependencies": [item.to_dict() for item in self.dependencies],
            "artifact_contexts": [item.to_dict() for item in self.artifact_contexts],
            "duplicate_identity": self.duplicate_identity,
            "key_identity_matches": self.key_identity_matches,
            "content_exact": self.content_exact,
            "cross_kind_conflict": self.cross_kind_conflict,
        }


@dataclass(frozen=True)
class E10PlanningCatalogObservation:
    schema_version: str
    collector_version: str
    collector_sql_digest: str
    scope: str
    session_user: str
    current_user: str
    search_path: str
    row_security: str
    isolation_level: str
    snapshot_text: str
    case_query_id: str
    occurrence_id: str
    relation_name: str
    relation_oid: Optional[int]
    rid_domain_id: str
    policy_id: str
    principal_id: str
    context_id: str
    context_hash: str
    canonical_context_json: str
    context_version: Optional[int]
    current_base_version: Optional[int]
    current_membership_version: Optional[int]
    artifacts: tuple[E10PlanningArtifactObservation, ...]
    observation_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifacts", tuple(self.artifacts))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "collector_version": self.collector_version,
            "collector_sql_digest": self.collector_sql_digest,
            "scope": self.scope,
            "session_user": self.session_user,
            "current_user": self.current_user,
            "search_path": self.search_path,
            "row_security": self.row_security,
            "isolation_level": self.isolation_level,
            "snapshot_text": self.snapshot_text,
            "case_query_id": self.case_query_id,
            "occurrence_id": self.occurrence_id,
            "relation_name": self.relation_name,
            "relation_oid": self.relation_oid,
            "rid_domain_id": self.rid_domain_id,
            "policy_id": self.policy_id,
            "principal_id": self.principal_id,
            "context_id": self.context_id,
            "context_hash": self.context_hash,
            "canonical_context": json.loads(self.canonical_context_json),
            "context_version": self.context_version,
            "current_base_version": self.current_base_version,
            "current_membership_version": self.current_membership_version,
            "artifacts": [item.to_dict() for item in self.artifacts],
            "observation_digest": self.observation_digest,
        }


@dataclass(frozen=True)
class E10SelectedArtifactCatalogObservation:
    """Current-H2 catalog evidence for exactly the selected artifact."""

    schema_version: str
    collector_version: str
    collector_sql_digest: str
    scope: str
    session_user: str
    current_user: str
    search_path: str
    row_security: str
    isolation_level: str
    snapshot_text: str
    case_query_id: str
    occurrence_id: str
    relation_name: str
    relation_oid: Optional[int]
    rid_domain_id: str
    policy_id: str
    principal_id: str
    context_id: str
    context_hash: str
    canonical_context_json: str
    context_version: Optional[int]
    current_base_version: Optional[int]
    current_membership_version: Optional[int]
    artifact: E10PlanningArtifactObservation
    observation_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "collector_version": self.collector_version,
            "collector_sql_digest": self.collector_sql_digest,
            "scope": self.scope,
            "session_user": self.session_user,
            "current_user": self.current_user,
            "search_path": self.search_path,
            "row_security": self.row_security,
            "isolation_level": self.isolation_level,
            "snapshot_text": self.snapshot_text,
            "case_query_id": self.case_query_id,
            "occurrence_id": self.occurrence_id,
            "relation_name": self.relation_name,
            "relation_oid": self.relation_oid,
            "rid_domain_id": self.rid_domain_id,
            "policy_id": self.policy_id,
            "principal_id": self.principal_id,
            "context_id": self.context_id,
            "context_hash": self.context_hash,
            "canonical_context": json.loads(self.canonical_context_json),
            "context_version": self.context_version,
            "current_base_version": self.current_base_version,
            "current_membership_version": self.current_membership_version,
            "artifact": self.artifact.to_dict(),
            "observation_digest": self.observation_digest,
        }


@dataclass(frozen=True)
class E10PlanningArtifactAssessment:
    kind: str
    artifact_id: str
    declared: bool
    target_domain: str
    observed: bool
    artifact_identity_matches: bool
    dependency_set_complete: bool
    fresh: bool
    context_matches: bool
    scope_matches: bool
    rid_domain_matches: bool
    base_relation_matches: bool
    policy_matches: bool
    principal_matches: bool
    exact: bool
    keyed: bool
    key_domain_matches: bool
    usable: bool
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "reasons", tuple(self.reasons))

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "artifact_id": self.artifact_id,
            "declared": self.declared,
            "target_domain": self.target_domain,
            "observed": self.observed,
            "artifact_identity_matches": self.artifact_identity_matches,
            "dependency_set_complete": self.dependency_set_complete,
            "fresh": self.fresh,
            "context_matches": self.context_matches,
            "scope_matches": self.scope_matches,
            "rid_domain_matches": self.rid_domain_matches,
            "base_relation_matches": self.base_relation_matches,
            "policy_matches": self.policy_matches,
            "principal_matches": self.principal_matches,
            "exact": self.exact,
            "keyed": self.keyed,
            "key_domain_matches": self.key_domain_matches,
            "usable": self.usable,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class E10PlanningReceipt:
    schema_version: str
    validator_version: str
    scope: str
    expectation_digest: str
    policy_manifest_digest: str
    policy_config_digest: str
    policy_definition_digest: str
    exact_predicate_digest: str
    guard_predicate_digest: str
    query_predicate_digest: str
    registry_inventory: tuple[E10PlanningRegistryEntry, ...]
    declared_artifacts: tuple[E10PlanningArtifactExpectation, ...]
    observation: E10PlanningCatalogObservation
    artifact_assessments: tuple[E10PlanningArtifactAssessment, ...]
    validated_usable_kinds: tuple[str, ...]
    reasons: tuple[str, ...]
    receipt_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "registry_inventory", tuple(self.registry_inventory))
        object.__setattr__(self, "declared_artifacts", tuple(self.declared_artifacts))
        object.__setattr__(
            self, "artifact_assessments", tuple(self.artifact_assessments)
        )
        object.__setattr__(
            self, "validated_usable_kinds", tuple(self.validated_usable_kinds)
        )
        object.__setattr__(self, "reasons", tuple(self.reasons))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "validator_version": self.validator_version,
            "scope": self.scope,
            "expectation_digest": self.expectation_digest,
            "policy_manifest_digest": self.policy_manifest_digest,
            "policy_config_digest": self.policy_config_digest,
            "policy_definition_digest": self.policy_definition_digest,
            "exact_predicate_digest": self.exact_predicate_digest,
            "guard_predicate_digest": self.guard_predicate_digest,
            "query_predicate_digest": self.query_predicate_digest,
            "registry_inventory": [item.to_dict() for item in self.registry_inventory],
            "declared_artifacts": [item.to_dict() for item in self.declared_artifacts],
            "observation": self.observation.to_dict(),
            "artifact_assessments": [
                item.to_dict() for item in self.artifact_assessments
            ],
            "validated_usable_kinds": list(self.validated_usable_kinds),
            "reasons": list(self.reasons),
            "receipt_digest": self.receipt_digest,
        }


@dataclass(frozen=True)
class E10PlanningReplay:
    schema_version: str
    valid: bool
    scope: str
    receipt_digest: str
    validated_usable_kinds: tuple[str, ...]
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "validated_usable_kinds", tuple(self.validated_usable_kinds)
        )
        object.__setattr__(self, "reasons", tuple(self.reasons))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "valid": self.valid,
            "scope": self.scope,
            "receipt_digest": self.receipt_digest,
            "validated_usable_kinds": list(self.validated_usable_kinds),
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class E10AdmissionEvidence:
    schema_version: str
    fact_id: str
    kind: str
    subject_digest: str
    validator_version: str
    snapshot_id: str
    source_kind: str
    payload_json: str
    evidence_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "fact_id": self.fact_id,
            "kind": self.kind,
            "subject_digest": self.subject_digest,
            "validator_version": self.validator_version,
            "snapshot_id": self.snapshot_id,
            "source_kind": self.source_kind,
            "payload": json.loads(self.payload_json),
            "evidence_digest": self.evidence_digest,
        }


@dataclass(frozen=True)
class E10AdmissionDynamicObligation:
    kind: str
    artifact_id: str
    snapshot_id: str
    source_fact_id: str

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "artifact_id": self.artifact_id,
            "snapshot_id": self.snapshot_id,
            "source_fact_id": self.source_fact_id,
        }


@dataclass(frozen=True)
class E10AdmissionBundle:
    schema_version: str
    issuer_version: str
    scope: str
    case_query_id: str
    receipt_digest: str
    expectation_digest: str
    observation_digest: str
    collector_sql_digest: str
    observation_snapshot_text: str
    snapshot_id: str
    registry_inventory: tuple[E10PlanningRegistryEntry, ...]
    exact_predicate_digest: str
    query_predicate_digest: str
    guard_predicate_digest: str
    residual_predicate_digest: Optional[str]
    guard_lowering_digest: Optional[str]
    logical_target: PolicyAccessTarget
    implementation_target_bindings: tuple[ImplementationTargetBinding, ...]
    parent_requirement: ParentRequirement
    gamma_snapshot: GammaSnapshot
    evidence: tuple[E10AdmissionEvidence, ...]
    unresolved_dynamic_obligations: tuple[E10AdmissionDynamicObligation, ...]
    bundle_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "registry_inventory", tuple(self.registry_inventory))
        object.__setattr__(
            self,
            "implementation_target_bindings",
            tuple(self.implementation_target_bindings),
        )
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(
            self,
            "unresolved_dynamic_obligations",
            tuple(self.unresolved_dynamic_obligations),
        )
        if not isinstance(self.logical_target, PolicyAccessTarget):
            raise TypeError("E10 admission logical target must be typed")
        if any(
            not isinstance(item, ImplementationTargetBinding)
            for item in self.implementation_target_bindings
        ):
            raise TypeError("E10 admission implementation bindings must be typed")
        if not isinstance(self.parent_requirement, ParentRequirement):
            raise TypeError("E10 admission rho must be a ParentRequirement")
        if not isinstance(self.gamma_snapshot, GammaSnapshot):
            raise TypeError("E10 admission Gamma must be a GammaSnapshot")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "issuer_version": self.issuer_version,
            "scope": self.scope,
            "case_query_id": self.case_query_id,
            "receipt_digest": self.receipt_digest,
            "expectation_digest": self.expectation_digest,
            "observation_digest": self.observation_digest,
            "collector_sql_digest": self.collector_sql_digest,
            "observation_snapshot_text": self.observation_snapshot_text,
            "snapshot_id": self.snapshot_id,
            "registry_inventory": [item.to_dict() for item in self.registry_inventory],
            "exact_predicate_digest": self.exact_predicate_digest,
            "query_predicate_digest": self.query_predicate_digest,
            "guard_predicate_digest": self.guard_predicate_digest,
            "residual_predicate_digest": self.residual_predicate_digest,
            "guard_lowering_digest": self.guard_lowering_digest,
            "logical_target": self.logical_target.to_dict(),
            "implementation_target_bindings": [
                item.to_dict() for item in self.implementation_target_bindings
            ],
            "parent_requirement": _e10_parent_requirement_to_dict(
                self.parent_requirement
            ),
            "gamma_snapshot": _e10_gamma_snapshot_to_dict(self.gamma_snapshot),
            "gamma_snapshot_digest": self.gamma_snapshot.digest,
            "evidence": [item.to_dict() for item in self.evidence],
            "unresolved_dynamic_obligations": [
                item.to_dict() for item in self.unresolved_dynamic_obligations
            ],
            "bundle_digest": self.bundle_digest,
        }


@dataclass(frozen=True)
class E10AdmissionReplay:
    schema_version: str
    valid: bool
    scope: str
    bundle_digest: str
    receipt_digest: str
    snapshot_id: str
    gamma_snapshot_digest: str
    unresolved_dynamic_obligations: tuple[E10AdmissionDynamicObligation, ...]
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "unresolved_dynamic_obligations",
            tuple(self.unresolved_dynamic_obligations),
        )
        object.__setattr__(self, "reasons", tuple(self.reasons))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "valid": self.valid,
            "scope": self.scope,
            "bundle_digest": self.bundle_digest,
            "receipt_digest": self.receipt_digest,
            "snapshot_id": self.snapshot_id,
            "gamma_snapshot_digest": self.gamma_snapshot_digest,
            "unresolved_dynamic_obligations": [
                item.to_dict() for item in self.unresolved_dynamic_obligations
            ],
            "reasons": list(self.reasons),
        }


E10_PLANNER_TEMPLATE_IDS = (
    "safe_predicate_injection_v1",
    "barrier_filter_v1",
    "auth_index_enum_v1",
    "strong_auth_index_keyed_v1",
    "mav_scan_v1",
    "guard_candidate_plus_residual_v1",
    "hybrid_intersect_v1",
)


def _e10_registry() -> TemplateRegistry:
    return TemplateRegistry(
        DEFAULT_TEMPLATE_REGISTRY.get(template_id)
        for template_id in E10_PLANNER_TEMPLATE_IDS
    )


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


def _canonical_json(payload: Any) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _canonical_digest(payload: Any) -> str:
    return (
        "sha256:" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
    )


def _e10_template_spec_payload(template: Any) -> dict[str, Any]:
    return {
        "template_id": template.template_id,
        "alternative": template.alternative,
        "required_artifacts": sorted(template.required_artifacts),
        "requires_exact_policy_safe": template.requires_exact_policy_safe,
        "requires_safe_query_predicate": template.requires_safe_query_predicate,
        "requires_transparent_parent": template.requires_transparent_parent,
        "rejects_unsafe_expression_boundary": template.rejects_unsafe_expression_boundary,
        "requires_guard": template.requires_guard,
        "produces_residual": template.produces_residual,
        "requires_keyed_artifact": template.requires_keyed_artifact,
        "requires_engine_rls": template.requires_engine_rls,
        "requires_authorization_view": template.requires_authorization_view,
        "preserves_branch_lineage": template.preserves_branch_lineage,
        "refinement_kind": template.refinement_kind,
        "sql_skeleton": template.sql_skeleton,
        "execution_class": template.execution_class,
    }


def _e10_registry_inventory() -> tuple[E10PlanningRegistryEntry, ...]:
    return tuple(
        E10PlanningRegistryEntry(
            template_id=template.template_id,
            spec_digest=_canonical_digest(_e10_template_spec_payload(template)),
        )
        for template in sorted(
            _e10_registry().template_specs(),
            key=lambda item: item.template_id,
        )
    )


_E10_PRODUCTION_SOURCE_CAPABILITY = object()
_E10_PRODUCTION_OWNER_CAPABILITY = object()
_REGISTERED_E10_PRODUCTION_SOURCES: dict[
    int, tuple[weakref.ReferenceType[Any], str, str]
] = {}
_REGISTERED_E10_PRODUCTION_OWNERS: dict[
    int,
    tuple[
        weakref.ReferenceType[Any],
        str,
        E10Case,
        Path,
        E10PlanningExpectation,
        E10PlanningReceipt,
        E10AdmissionBundle,
    ],
] = {}
_REGISTERED_E10_PRODUCTION_QUERY_PLANS: dict[
    int,
    tuple[
        dict[str, Any],
        str,
        _E10ProductionPlanningOwner,
        PlanningEvidenceBatch,
        str,
        str,
        BoundRunnerIdentity,
    ],
] = {}
_REGISTERED_E10_PRODUCTION_PLAN_LINEAGE: dict[
    int,
    tuple[PlanResult, Mapping[str, Any], str, str],
] = {}


def _register_e10_production_source(
    value: Any,
    *,
    kind: str,
    identity_digest: str,
) -> Any:
    object.__setattr__(
        value,
        "_e10_production_source_capability",
        _E10_PRODUCTION_SOURCE_CAPABILITY,
    )
    key = id(value)

    def _drop(reference: weakref.ReferenceType[Any]) -> None:
        registered = _REGISTERED_E10_PRODUCTION_SOURCES.get(key)
        if registered is not None and registered[0] is reference:
            _REGISTERED_E10_PRODUCTION_SOURCES.pop(key, None)

    _REGISTERED_E10_PRODUCTION_SOURCES[key] = (
        weakref.ref(value, _drop),
        kind,
        identity_digest,
    )
    return value


def _require_e10_production_source(
    value: Any,
    *,
    kind: str,
    identity_digest: str,
) -> None:
    registered = _REGISTERED_E10_PRODUCTION_SOURCES.get(id(value))
    if (
        registered is None
        or registered[0]() is not value
        or registered[1] != kind
        or registered[2] != identity_digest
        or getattr(value, "_e10_production_source_capability", None)
        is not _E10_PRODUCTION_SOURCE_CAPABILITY
    ):
        raise PostgresError(
            f"E10 production {kind} is not an exact issued source capability"
        )


def _e10_production_case_digest(case: E10Case) -> str:
    if case.__class__ is not E10Case:
        raise PostgresError("E10 production case identity is untyped")
    return _canonical_digest(
        {
            "schema": "e10_production_case_identity_v1",
            "case": asdict(case),
        }
    )


def _e10_production_root_identity_digest(root: Path) -> str:
    if not isinstance(root, Path):
        raise PostgresError("E10 production root identity is untyped")
    try:
        normalized = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PostgresError("E10 production root identity cannot be resolved") from exc
    return _canonical_digest(
        {
            "schema": "e10_production_root_identity_v1",
            "normalized_root": str(normalized),
        }
    )


@dataclass(frozen=True)
class _E10ProductionPlanningOwner:
    case: E10Case = field(repr=False, compare=False)
    root: Path = field(repr=False, compare=False)
    expectation: E10PlanningExpectation = field(repr=False, compare=False)
    receipt: E10PlanningReceipt = field(repr=False, compare=False)
    bundle: E10AdmissionBundle = field(repr=False, compare=False)
    registry_inventory: tuple[E10PlanningRegistryEntry, ...]
    artifact_evidence_bindings: tuple[tuple[str, str, str], ...]
    case_digest: str
    root_identity_digest: str
    registry_manifest_digest: str
    identity_digest: str


def _require_e10_production_planning_owner(
    owner: _E10ProductionPlanningOwner,
) -> str:
    if owner.__class__ is not _E10ProductionPlanningOwner:
        raise PostgresError("E10 production planning owner type is invalid")
    registered = _REGISTERED_E10_PRODUCTION_OWNERS.get(id(owner))
    if (
        registered is None
        or registered[0]() is not owner
        or registered[1] != owner.identity_digest
        or registered[2] is not owner.case
        or registered[3] is not owner.root
        or registered[4] is not owner.expectation
        or registered[5] is not owner.receipt
        or registered[6] is not owner.bundle
        or getattr(owner, "_e10_production_owner_capability", None)
        is not _E10_PRODUCTION_OWNER_CAPABILITY
    ):
        raise PostgresError("E10 production planning owner is not registered")
    _require_e10_production_source(
        owner.expectation,
        kind="expectation",
        identity_digest=owner.expectation.digest,
    )
    _require_e10_production_source(
        owner.receipt,
        kind="receipt",
        identity_digest=owner.receipt.receipt_digest,
    )
    _require_e10_production_source(
        owner.bundle,
        kind="admission_bundle",
        identity_digest=owner.bundle.bundle_digest,
    )
    current_inventory = _e10_registry_inventory()
    current_case_digest = _e10_production_case_digest(owner.case)
    current_root_identity_digest = _e10_production_root_identity_digest(owner.root)
    _, current_artifact_bindings = _e10_strict_artifact_contract(
        owner.receipt,
        owner.bundle,
    )
    if (
        owner.expectation.scope != "production"
        or owner.receipt.scope != "production"
        or owner.bundle.scope != "production"
        or owner.registry_inventory != current_inventory
        or owner.expectation.registry_inventory != current_inventory
        or owner.receipt.registry_inventory != current_inventory
        or owner.bundle.registry_inventory != current_inventory
        or owner.artifact_evidence_bindings != current_artifact_bindings
        or owner.case_digest != current_case_digest
        or owner.root_identity_digest != current_root_identity_digest
    ):
        raise PostgresError("E10 production planning owner inventory changed")
    receipt_replay = _replay_e10_planning_receipt(
        owner.receipt,
        owner.expectation,
        require_production=True,
    )
    bundle_replay = _replay_e10_admission_bundle(
        owner.bundle,
        root=owner.root,
        case=owner.case,
        receipt=owner.receipt,
        expectation=owner.expectation,
        require_production=True,
    )
    if not receipt_replay.valid or not bundle_replay.valid:
        raise PostgresError("E10 production planning owner no longer replays")
    expected_manifest = _canonical_digest(
        {
            "schema": "e10_production_registry_manifest_v1",
            "expectation_digest": owner.expectation.digest,
            "receipt_digest": owner.receipt.receipt_digest,
            "bundle_digest": owner.bundle.bundle_digest,
            "registry_inventory": [item.to_dict() for item in current_inventory],
            "artifact_evidence_bindings": [
                list(item) for item in current_artifact_bindings
            ],
            "case_digest": current_case_digest,
            "root_identity_digest": current_root_identity_digest,
        }
    )
    expected_identity = _canonical_digest(
        {
            "schema": "e10_production_planning_owner_v1",
            "case_query_id": owner.case.query_id,
            "case_digest": current_case_digest,
            "root_identity_digest": current_root_identity_digest,
            "expectation_digest": owner.expectation.digest,
            "receipt_digest": owner.receipt.receipt_digest,
            "bundle_digest": owner.bundle.bundle_digest,
            "registry_manifest_digest": expected_manifest,
        }
    )
    if (
        owner.registry_manifest_digest != expected_manifest
        or owner.identity_digest != expected_identity
    ):
        raise PostgresError("E10 production planning owner identity changed")
    return expected_identity


def _mint_e10_production_planning_owner(
    *,
    case: E10Case,
    root: Path,
    expectation: E10PlanningExpectation,
    receipt: E10PlanningReceipt,
    bundle: E10AdmissionBundle,
) -> _E10ProductionPlanningOwner:
    for value, kind, identity in (
        (expectation, "expectation", expectation.digest),
        (receipt, "receipt", receipt.receipt_digest),
        (bundle, "admission_bundle", bundle.bundle_digest),
    ):
        _require_e10_production_source(
            value,
            kind=kind,
            identity_digest=identity,
        )
    inventory = _e10_registry_inventory()
    case_digest = _e10_production_case_digest(case)
    root_identity_digest = _e10_production_root_identity_digest(root)
    _, artifact_evidence_bindings = _e10_strict_artifact_contract(
        receipt,
        bundle,
    )
    manifest = _canonical_digest(
        {
            "schema": "e10_production_registry_manifest_v1",
            "expectation_digest": expectation.digest,
            "receipt_digest": receipt.receipt_digest,
            "bundle_digest": bundle.bundle_digest,
            "registry_inventory": [item.to_dict() for item in inventory],
            "artifact_evidence_bindings": [
                list(item) for item in artifact_evidence_bindings
            ],
            "case_digest": case_digest,
            "root_identity_digest": root_identity_digest,
        }
    )
    identity = _canonical_digest(
        {
            "schema": "e10_production_planning_owner_v1",
            "case_query_id": case.query_id,
            "case_digest": case_digest,
            "root_identity_digest": root_identity_digest,
            "expectation_digest": expectation.digest,
            "receipt_digest": receipt.receipt_digest,
            "bundle_digest": bundle.bundle_digest,
            "registry_manifest_digest": manifest,
        }
    )
    owner = _E10ProductionPlanningOwner(
        case=case,
        root=root,
        expectation=expectation,
        receipt=receipt,
        bundle=bundle,
        registry_inventory=inventory,
        artifact_evidence_bindings=artifact_evidence_bindings,
        case_digest=case_digest,
        root_identity_digest=root_identity_digest,
        registry_manifest_digest=manifest,
        identity_digest=identity,
    )
    object.__setattr__(
        owner,
        "_e10_production_owner_capability",
        _E10_PRODUCTION_OWNER_CAPABILITY,
    )
    key = id(owner)

    def _drop(reference: weakref.ReferenceType[Any]) -> None:
        registered = _REGISTERED_E10_PRODUCTION_OWNERS.get(key)
        if registered is not None and registered[0] is reference:
            _REGISTERED_E10_PRODUCTION_OWNERS.pop(key, None)

    _REGISTERED_E10_PRODUCTION_OWNERS[key] = (
        weakref.ref(owner, _drop),
        identity,
        case,
        root,
        expectation,
        receipt,
        bundle,
    )
    _require_e10_production_planning_owner(owner)
    return owner


def _e10_sql_fragment_digest(fragment: Optional[str]) -> str:
    normalized = "" if fragment is None else re.sub(r"\s+", " ", fragment.strip())
    return _canonical_digest({"sql_fragment": normalized})


def _strict_e10_bool(payload: Mapping[str, Any], key: str, *, label: str) -> bool:
    value = payload[key]
    if not isinstance(value, bool):
        raise ValueError(f"{label}.{key} must be boolean")
    return value


def _e10_planning_registry_entry_from_dict(
    payload: Any,
) -> E10PlanningRegistryEntry:
    if not isinstance(payload, Mapping):
        raise ValueError("E10 planning registry entry must be an object")
    _strict_e10_state_keys(
        payload,
        {"template_id", "spec_digest"},
        label="planning_registry_entry",
    )
    return E10PlanningRegistryEntry(
        template_id=_strict_e10_state_string(
            payload,
            "template_id",
            label="planning_registry_entry",
        ),
        spec_digest=_strict_e10_state_string(
            payload,
            "spec_digest",
            label="planning_registry_entry",
        ),
    )


def _e10_planning_context_from_dict(
    payload: Any,
    *,
    label: str,
) -> E10PlanningContextIdentity:
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be an object")
    _strict_e10_state_keys(
        payload,
        {"context_hash", "principal_id", "canonical_context", "version"},
        label=label,
    )
    context = payload["canonical_context"]
    version = payload["version"]
    if not isinstance(context, Mapping):
        raise ValueError(f"{label}.canonical_context must be an object")
    if not isinstance(version, int) or isinstance(version, bool) or version < 0:
        raise ValueError(f"{label}.version must be non-negative integer")
    principal_id = _strict_e10_state_string(payload, "principal_id", label=label)
    canonical_json = _canonical_json(context)
    if str(context.get("user_id")) != principal_id:
        raise ValueError(f"{label}.principal does not match canonical context")
    context_hash = _strict_e10_state_string(payload, "context_hash", label=label)
    if _canonical_digest(context) != context_hash:
        raise ValueError(f"{label}.semantic digest mismatch")
    return E10PlanningContextIdentity(
        context_hash=context_hash,
        principal_id=principal_id,
        canonical_context_json=canonical_json,
        version=version,
    )


def _e10_planning_scope_from_dict(
    payload: Any,
) -> E10PlanningScopeIdentity:
    label = "planning_artifact_scope"
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be an object")
    _strict_e10_state_keys(
        payload,
        {
            "policy_id",
            "principal_id",
            "context_hash",
            "rid_domain_id",
            "base_relation_oid",
            "policy_version",
            "membership_version",
            "key_name",
        },
        label=label,
    )
    integers: dict[str, int] = {}
    for key in ("base_relation_oid", "policy_version", "membership_version"):
        value = payload[key]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{label}.{key} must be non-negative integer")
        integers[key] = value
    if integers["base_relation_oid"] <= 0:
        raise ValueError(f"{label}.base_relation_oid must be positive")
    return E10PlanningScopeIdentity(
        policy_id=_strict_e10_state_string(payload, "policy_id", label=label),
        principal_id=_strict_e10_state_string(
            payload,
            "principal_id",
            label=label,
        ),
        context_hash=_strict_e10_state_string(
            payload,
            "context_hash",
            label=label,
        ),
        rid_domain_id=_strict_e10_state_string(
            payload,
            "rid_domain_id",
            label=label,
        ),
        base_relation_oid=integers["base_relation_oid"],
        policy_version=integers["policy_version"],
        membership_version=integers["membership_version"],
        key_name=_optional_e10_state_string(payload, "key_name", label=label),
    )


def _e10_planning_artifact_observation_from_dict(
    payload: Any,
) -> E10PlanningArtifactObservation:
    label = "planning_artifact_observation"
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be an object")
    _strict_e10_state_keys(
        payload,
        {
            "kind",
            "artifact_id",
            "physical_relation",
            "physical_relation_oid",
            "scope_identities",
            "dependencies",
            "artifact_contexts",
            "duplicate_identity",
            "key_identity_matches",
            "content_exact",
            "cross_kind_conflict",
        },
        label=label,
    )
    raw_scope = payload["scope_identities"]
    raw_dependencies = payload["dependencies"]
    raw_contexts = payload["artifact_contexts"]
    if not all(
        isinstance(value, list) for value in (raw_scope, raw_dependencies, raw_contexts)
    ):
        raise ValueError(f"{label} nested inventories must be lists")
    scopes = tuple(_e10_planning_scope_from_dict(item) for item in raw_scope)
    dependencies = tuple(
        _e10_dependency_state_from_dict(item) for item in raw_dependencies
    )
    contexts = tuple(
        _e10_planning_context_from_dict(item, label="planning_artifact_context")
        for item in raw_contexts
    )
    canonical_scopes = tuple(
        sorted(
            scopes,
            key=lambda item: (
                item.policy_id,
                item.principal_id,
                item.context_hash,
                item.rid_domain_id,
                item.base_relation_oid,
                item.policy_version,
                item.membership_version,
                item.key_name or "",
            ),
        )
    )
    canonical_dependencies = tuple(
        sorted(
            dependencies,
            key=lambda item: (item.dep_kind, item.dep_name, item.version_at_build),
        )
    )
    canonical_contexts = tuple(
        sorted(
            contexts,
            key=lambda item: (
                item.context_hash,
                item.principal_id,
                item.version,
                item.canonical_context_json,
            ),
        )
    )
    if (
        scopes != canonical_scopes
        or dependencies != canonical_dependencies
        or contexts != canonical_contexts
    ):
        raise ValueError(f"{label} nested inventory order is not canonical")
    if (
        len(set(scopes)) != len(scopes)
        or len(set(dependencies)) != len(dependencies)
        or len(set(contexts)) != len(contexts)
    ):
        raise ValueError(f"{label} nested inventory has duplicate entries")
    oid = _optional_e10_state_int(
        payload,
        "physical_relation_oid",
        label=label,
    )
    if oid is not None and oid <= 0:
        raise ValueError(f"{label}.physical_relation_oid must be positive")
    return E10PlanningArtifactObservation(
        kind=_strict_e10_state_string(payload, "kind", label=label),
        artifact_id=_strict_e10_state_string(payload, "artifact_id", label=label),
        physical_relation=_strict_e10_state_string(
            payload,
            "physical_relation",
            label=label,
        ),
        physical_relation_oid=oid,
        scope_identities=scopes,
        dependencies=dependencies,
        artifact_contexts=contexts,
        duplicate_identity=_strict_e10_bool(
            payload,
            "duplicate_identity",
            label=label,
        ),
        key_identity_matches=_strict_e10_bool(
            payload,
            "key_identity_matches",
            label=label,
        ),
        content_exact=_strict_e10_bool(payload, "content_exact", label=label),
        cross_kind_conflict=_strict_e10_bool(
            payload,
            "cross_kind_conflict",
            label=label,
        ),
    )


_E10_PLANNING_OBSERVATION_RAW_FIELDS = {
    "schema_version",
    "collector_version",
    "collector_sql_digest",
    "scope",
    "session_user",
    "current_user",
    "search_path",
    "row_security",
    "isolation_level",
    "snapshot_text",
    "case_query_id",
    "occurrence_id",
    "relation_name",
    "relation_oid",
    "rid_domain_id",
    "policy_id",
    "principal_id",
    "context_id",
    "context_hash",
    "canonical_context",
    "context_version",
    "current_base_version",
    "current_membership_version",
    "artifacts",
}


def _issue_e10_planning_catalog_observation(
    payload: Mapping[str, Any],
) -> E10PlanningCatalogObservation:
    label = "e10_planning_catalog_observation"
    _strict_e10_state_keys(payload, _E10_PLANNING_OBSERVATION_RAW_FIELDS, label=label)
    raw_artifacts = payload["artifacts"]
    if not isinstance(raw_artifacts, list):
        raise ValueError(f"{label}.artifacts must be a list")
    artifacts = tuple(
        _e10_planning_artifact_observation_from_dict(item) for item in raw_artifacts
    )
    if tuple(item.kind for item in artifacts) != E10_PLANNING_ARTIFACT_KINDS:
        raise ValueError(f"{label}.artifact order is not canonical")
    context = payload["canonical_context"]
    if not isinstance(context, Mapping):
        raise ValueError(f"{label}.canonical_context must be an object")
    relation_oid = _optional_e10_state_int(payload, "relation_oid", label=label)
    context_version = _optional_e10_state_int(payload, "context_version", label=label)
    base_version = _optional_e10_state_int(payload, "current_base_version", label=label)
    membership_version = _optional_e10_state_int(
        payload,
        "current_membership_version",
        label=label,
    )
    draft = E10PlanningCatalogObservation(
        schema_version=_strict_e10_state_string(payload, "schema_version", label=label),
        collector_version=_strict_e10_state_string(
            payload,
            "collector_version",
            label=label,
        ),
        collector_sql_digest=_strict_e10_state_string(
            payload,
            "collector_sql_digest",
            label=label,
        ),
        scope=_strict_e10_state_string(payload, "scope", label=label),
        session_user=_strict_e10_state_string(payload, "session_user", label=label),
        current_user=_strict_e10_state_string(payload, "current_user", label=label),
        search_path=_strict_e10_state_string(payload, "search_path", label=label),
        row_security=_strict_e10_state_string(payload, "row_security", label=label),
        isolation_level=_strict_e10_state_string(
            payload,
            "isolation_level",
            label=label,
        ),
        snapshot_text=_strict_e10_state_string(payload, "snapshot_text", label=label),
        case_query_id=_strict_e10_state_string(
            payload,
            "case_query_id",
            label=label,
        ),
        occurrence_id=_strict_e10_state_string(payload, "occurrence_id", label=label),
        relation_name=_strict_e10_state_string(payload, "relation_name", label=label),
        relation_oid=relation_oid,
        rid_domain_id=_strict_e10_state_string(payload, "rid_domain_id", label=label),
        policy_id=_strict_e10_state_string(payload, "policy_id", label=label),
        principal_id=_strict_e10_state_string(payload, "principal_id", label=label),
        context_id=_strict_e10_state_string(payload, "context_id", label=label),
        context_hash=_strict_e10_state_string(payload, "context_hash", label=label),
        canonical_context_json=_canonical_json(context),
        context_version=context_version,
        current_base_version=base_version,
        current_membership_version=membership_version,
        artifacts=artifacts,
        observation_digest="pending",
    )
    if draft.schema_version != E10_PLANNING_OBSERVATION_SCHEMA:
        raise ValueError("E10 planning observation schema is not trusted")
    if draft.collector_version != E10_PLANNING_COLLECTOR_VERSION:
        raise ValueError("E10 planning collector version is not trusted")
    if draft.scope not in {"production", "fixture"}:
        raise ValueError("E10 planning observation scope is invalid")
    if (
        draft.search_path != E10_STATE_SEARCH_PATH
        or draft.row_security != E10_STATE_ROW_SECURITY
    ):
        raise ValueError("E10 planning observation environment is not canonical")
    if draft.isolation_level != "repeatable read":
        raise ValueError("E10 planning observation isolation is not repeatable read")
    if relation_oid is not None and relation_oid <= 0:
        raise ValueError("E10 planning relation OID is invalid")
    if str(context.get("user_id")) != draft.principal_id:
        raise ValueError("E10 planning context principal mismatch")
    if _canonical_digest(context) != draft.context_hash:
        raise ValueError("E10 planning context digest mismatch")
    payload_without_digest = draft.to_dict()
    payload_without_digest.pop("observation_digest", None)
    return replace(
        draft,
        observation_digest=_canonical_digest(payload_without_digest),
    )


def _e10_planning_catalog_observation_from_dict(
    payload: Any,
) -> E10PlanningCatalogObservation:
    if not isinstance(payload, Mapping):
        raise ValueError("E10 planning observation must be an object")
    _strict_e10_state_keys(
        payload,
        _E10_PLANNING_OBSERVATION_RAW_FIELDS | {"observation_digest"},
        label="e10_planning_catalog_observation",
    )
    canonical = _issue_e10_planning_catalog_observation(
        {key: payload[key] for key in _E10_PLANNING_OBSERVATION_RAW_FIELDS}
    )
    if payload["observation_digest"] != canonical.observation_digest:
        raise ValueError("E10 planning observation digest mismatch")
    return canonical


_E10_SELECTED_ARTIFACT_OBSERVATION_RAW_FIELDS = (
    _E10_PLANNING_OBSERVATION_RAW_FIELDS - {"artifacts"}
) | {"artifact"}


def _issue_e10_selected_artifact_catalog_observation(
    payload: Mapping[str, Any],
) -> E10SelectedArtifactCatalogObservation:
    label = "e10_selected_artifact_catalog_observation"
    _strict_e10_state_keys(
        payload,
        _E10_SELECTED_ARTIFACT_OBSERVATION_RAW_FIELDS,
        label=label,
    )
    artifact = _e10_planning_artifact_observation_from_dict(payload["artifact"])
    context = payload["canonical_context"]
    if not isinstance(context, Mapping):
        raise ValueError(f"{label}.canonical_context must be an object")
    relation_oid = _optional_e10_state_int(payload, "relation_oid", label=label)
    context_version = _optional_e10_state_int(payload, "context_version", label=label)
    base_version = _optional_e10_state_int(payload, "current_base_version", label=label)
    membership_version = _optional_e10_state_int(
        payload,
        "current_membership_version",
        label=label,
    )
    draft = E10SelectedArtifactCatalogObservation(
        schema_version=_strict_e10_state_string(payload, "schema_version", label=label),
        collector_version=_strict_e10_state_string(
            payload,
            "collector_version",
            label=label,
        ),
        collector_sql_digest=_strict_e10_state_string(
            payload,
            "collector_sql_digest",
            label=label,
        ),
        scope=_strict_e10_state_string(payload, "scope", label=label),
        session_user=_strict_e10_state_string(payload, "session_user", label=label),
        current_user=_strict_e10_state_string(payload, "current_user", label=label),
        search_path=_strict_e10_state_string(payload, "search_path", label=label),
        row_security=_strict_e10_state_string(payload, "row_security", label=label),
        isolation_level=_strict_e10_state_string(
            payload,
            "isolation_level",
            label=label,
        ),
        snapshot_text=_strict_e10_state_string(payload, "snapshot_text", label=label),
        case_query_id=_strict_e10_state_string(
            payload,
            "case_query_id",
            label=label,
        ),
        occurrence_id=_strict_e10_state_string(payload, "occurrence_id", label=label),
        relation_name=_strict_e10_state_string(payload, "relation_name", label=label),
        relation_oid=relation_oid,
        rid_domain_id=_strict_e10_state_string(payload, "rid_domain_id", label=label),
        policy_id=_strict_e10_state_string(payload, "policy_id", label=label),
        principal_id=_strict_e10_state_string(payload, "principal_id", label=label),
        context_id=_strict_e10_state_string(payload, "context_id", label=label),
        context_hash=_strict_e10_state_string(payload, "context_hash", label=label),
        canonical_context_json=_canonical_json(context),
        context_version=context_version,
        current_base_version=base_version,
        current_membership_version=membership_version,
        artifact=artifact,
        observation_digest="pending",
    )
    if draft.schema_version != E10_SELECTED_ARTIFACT_OBSERVATION_SCHEMA:
        raise ValueError("E10 selected-artifact observation schema is not trusted")
    if draft.collector_version != E10_SELECTED_ARTIFACT_COLLECTOR_VERSION:
        raise ValueError("E10 selected-artifact collector version is not trusted")
    if draft.scope not in {"production", "fixture"}:
        raise ValueError("E10 selected-artifact observation scope is invalid")
    if (
        draft.search_path != E10_STATE_SEARCH_PATH
        or draft.row_security != E10_STATE_ROW_SECURITY
    ):
        raise ValueError("E10 selected-artifact observation environment is not canonical")
    if draft.isolation_level != "repeatable read":
        raise ValueError(
            "E10 selected-artifact observation isolation is not repeatable read"
        )
    if relation_oid is not None and relation_oid <= 0:
        raise ValueError("E10 selected-artifact relation OID is invalid")
    if artifact.kind not in E10_PLANNING_ARTIFACT_KINDS:
        raise ValueError("E10 selected-artifact kind is invalid")
    if str(context.get("user_id")) != draft.principal_id:
        raise ValueError("E10 selected-artifact context principal mismatch")
    if _canonical_digest(context) != draft.context_hash:
        raise ValueError("E10 selected-artifact context digest mismatch")
    payload_without_digest = draft.to_dict()
    payload_without_digest.pop("observation_digest", None)
    return replace(
        draft,
        observation_digest=_canonical_digest(payload_without_digest),
    )


def _e10_selected_artifact_catalog_observation_from_dict(
    payload: Any,
) -> E10SelectedArtifactCatalogObservation:
    if not isinstance(payload, Mapping):
        raise ValueError("E10 selected-artifact observation must be an object")
    _strict_e10_state_keys(
        payload,
        _E10_SELECTED_ARTIFACT_OBSERVATION_RAW_FIELDS | {"observation_digest"},
        label="e10_selected_artifact_catalog_observation",
    )
    canonical = _issue_e10_selected_artifact_catalog_observation(
        {key: payload[key] for key in _E10_SELECTED_ARTIFACT_OBSERVATION_RAW_FIELDS}
    )
    if payload["observation_digest"] != canonical.observation_digest:
        raise ValueError("E10 selected-artifact observation digest mismatch")
    return canonical


def _e10_planning_artifact_expectation_from_dict(
    payload: Any,
) -> E10PlanningArtifactExpectation:
    label = "planning_artifact_expectation"
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be an object")
    _strict_e10_state_keys(
        payload,
        {
            "kind",
            "artifact_id",
            "physical_relation",
            "declared",
            "dependency_profile",
            "key_name",
            "target_domain",
        },
        label=label,
    )
    if payload["target_domain"] != E10_PLANNING_TARGET_DOMAIN:
        raise ValueError(f"{label}.target_domain is not canonical")
    return E10PlanningArtifactExpectation(
        kind=_strict_e10_state_string(payload, "kind", label=label),
        artifact_id=_strict_e10_state_string(payload, "artifact_id", label=label),
        physical_relation=_strict_e10_state_string(
            payload,
            "physical_relation",
            label=label,
        ),
        declared=_strict_e10_bool(payload, "declared", label=label),
        dependency_profile=_strict_e10_state_string(
            payload,
            "dependency_profile",
            label=label,
        ),
        key_name=_optional_e10_state_string(payload, "key_name", label=label),
    )


def _e10_dependency_map_for_planning(
    observation: E10PlanningArtifactObservation,
) -> tuple[dict[str, E10ArtifactDependencyState], bool]:
    grouped: dict[str, list[E10ArtifactDependencyState]] = {}
    for dependency in observation.dependencies:
        grouped.setdefault(dependency.dep_kind, []).append(dependency)
    unique = {kind: items[0] for kind, items in grouped.items() if len(items) == 1}
    return unique, all(len(items) == 1 for items in grouped.values())


def _assess_e10_planning_artifact(
    expectation: E10PlanningExpectation,
    artifact_expectation: E10PlanningArtifactExpectation,
    observation: E10PlanningCatalogObservation,
    artifact: E10PlanningArtifactObservation,
) -> E10PlanningArtifactAssessment:
    dependencies, unique_dependencies = _e10_dependency_map_for_planning(artifact)
    required_dependency_kinds = (
        set(E10_STATE_DEPENDENCY_KINDS)
        if artifact_expectation.dependency_profile == "state9"
        else {"policy", "membership", "base", "context_scope", "rid_domain"}
    )
    dependency_set_complete = bool(
        unique_dependencies
        and set(dependencies) == required_dependency_kinds
        and len(artifact.dependencies) == len(required_dependency_kinds)
    )

    def dep(kind: str) -> Optional[E10ArtifactDependencyState]:
        return dependencies.get(kind)

    policy_dep = dep("policy")
    membership_dep = dep("membership")
    base_dep = dep("base")
    context_dep = dep("context_scope")
    rid_dep = dep("rid_domain")
    artifact_relation_dep = dep("artifact_relation")
    base_oid_dep = dep("base_relation_oid")
    principal_dep = dep("principal")
    artifact_kind_dep = dep("artifact_kind")

    observed = bool(
        artifact.physical_relation_oid is not None
        and (
            bool(artifact.scope_identities)
            if artifact.kind in {"auth_idx", "auth_idx_keyed"}
            else True
        )
    )
    expected_scope = E10PlanningScopeIdentity(
        policy_id=expectation.policy_id,
        principal_id=expectation.principal_id,
        context_hash=expectation.context_hash,
        rid_domain_id=expectation.rid_domain_id,
        base_relation_oid=int(observation.relation_oid or 0),
        policy_version=0,
        membership_version=int(
            membership_dep.version_at_build if membership_dep else -1
        ),
        key_name=(
            artifact_expectation.key_name if artifact.kind == "auth_idx_keyed" else None
        ),
    )
    if artifact.kind in {"auth_idx", "auth_idx_keyed"}:
        scope_matches = artifact.scope_identities == (expected_scope,)
        principal_matches = bool(
            scope_matches
            and len(artifact.artifact_contexts) == 1
            and artifact.artifact_contexts[0].principal_id == expectation.principal_id
        )
        context_matches = bool(
            principal_matches
            and context_dep is not None
            and context_dep.dep_name == expectation.context_hash
            and artifact.artifact_contexts[0].context_hash == expectation.context_hash
            and artifact.artifact_contexts[0].canonical_context_json
            == expectation.canonical_context_json
        )
    else:
        scope_matches = len(artifact.artifact_contexts) == 1
        principal_matches = bool(
            scope_matches
            and artifact.artifact_contexts[0].principal_id == expectation.principal_id
            and (
                principal_dep is None
                or principal_dep.dep_name == expectation.principal_id
            )
        )
        context_matches = bool(
            scope_matches
            and context_dep is not None
            and context_dep.dep_name == expectation.context_hash
            and artifact.artifact_contexts[0].context_hash == expectation.context_hash
            and artifact.artifact_contexts[0].canonical_context_json
            == expectation.canonical_context_json
        )
    policy_matches = bool(
        policy_dep is not None
        and policy_dep.dep_name == expectation.policy_id
        and policy_dep.version_at_build == 0
        and (
            artifact.kind == "mav"
            or all(
                scope.policy_id == expectation.policy_id and scope.policy_version == 0
                for scope in artifact.scope_identities
            )
        )
    )
    rid_domain_matches = bool(
        rid_dep is not None
        and rid_dep.dep_name == expectation.rid_domain_id
        and rid_dep.version_at_build == 0
        and (
            artifact.kind == "mav"
            or all(
                scope.rid_domain_id == expectation.rid_domain_id
                for scope in artifact.scope_identities
            )
        )
    )
    base_relation_matches = bool(
        observation.relation_oid is not None
        and base_dep is not None
        and base_dep.dep_name == expectation.relation_name
        and (
            artifact.kind == "mav"
            or all(
                scope.base_relation_oid == observation.relation_oid
                for scope in artifact.scope_identities
            )
        )
        and (
            base_oid_dep is None
            or (
                base_oid_dep.dep_name == f"public.{expectation.relation_name}"
                and base_oid_dep.version_at_build == observation.relation_oid
            )
        )
    )
    artifact_identity_matches = bool(
        artifact.kind == artifact_expectation.kind
        and artifact.artifact_id == artifact_expectation.artifact_id
        and artifact.physical_relation == artifact_expectation.physical_relation
        and (
            artifact_relation_dep is None
            or (
                artifact_relation_dep.dep_name == artifact_expectation.physical_relation
                and artifact_relation_dep.version_at_build
                == artifact.physical_relation_oid
            )
        )
        and (
            artifact_kind_dep is None
            or (
                artifact_kind_dep.dep_name == "mav"
                and artifact_kind_dep.version_at_build == 0
            )
        )
    )
    base_fresh = bool(
        base_dep is not None
        and observation.current_base_version is not None
        and base_dep.version_at_build == observation.current_base_version
    )
    membership_fresh = bool(
        membership_dep is not None
        and membership_dep.dep_name == "group_membership"
        and observation.current_membership_version is not None
        and membership_dep.version_at_build == observation.current_membership_version
        and (
            artifact.kind == "mav"
            or all(
                scope.membership_version == membership_dep.version_at_build
                for scope in artifact.scope_identities
            )
        )
    )
    context_fresh = bool(
        context_dep is not None
        and observation.context_version is not None
        and len(artifact.artifact_contexts) == 1
        and context_dep.version_at_build
        == artifact.artifact_contexts[0].version
        == observation.context_version
    )
    fresh = base_fresh and membership_fresh and context_fresh
    exact = bool(
        artifact.content_exact
        and not artifact.duplicate_identity
        and not artifact.cross_kind_conflict
    )
    keyed = artifact.kind == "auth_idx_keyed"
    key_domain_matches = bool(
        not keyed
        or (
            artifact.key_identity_matches
            and artifact_expectation.key_name == expectation.rid_col
            and scope_matches
        )
    )
    checks = {
        "not_declared": artifact_expectation.declared,
        "not_observed": observed,
        "artifact_identity_mismatch": artifact_identity_matches,
        "dependency_set_incomplete": dependency_set_complete,
        "stale": fresh,
        "wrong_context": context_matches,
        "scope_mismatch": scope_matches,
        "rid_domain_mismatch": rid_domain_matches,
        "base_relation_mismatch": base_relation_matches,
        "policy_mismatch": policy_matches,
        "principal_mismatch": principal_matches,
        "content_not_exact": exact,
        "key_domain_mismatch": key_domain_matches,
    }
    reasons = tuple(sorted(reason for reason, ok in checks.items() if not ok))
    return E10PlanningArtifactAssessment(
        kind=artifact.kind,
        artifact_id=artifact.artifact_id,
        declared=artifact_expectation.declared,
        target_domain=E10_PLANNING_TARGET_DOMAIN,
        observed=observed,
        artifact_identity_matches=artifact_identity_matches,
        dependency_set_complete=dependency_set_complete,
        fresh=fresh,
        context_matches=context_matches,
        scope_matches=scope_matches,
        rid_domain_matches=rid_domain_matches,
        base_relation_matches=base_relation_matches,
        policy_matches=policy_matches,
        principal_matches=principal_matches,
        exact=exact,
        keyed=keyed,
        key_domain_matches=key_domain_matches,
        usable=not reasons,
        reasons=reasons,
    )


def _e10_planning_core_reasons(
    expectation: E10PlanningExpectation,
    observation: E10PlanningCatalogObservation,
    *,
    expected_collector_sql_digest: str,
) -> tuple[str, ...]:
    checks = {
        "scope_mismatch": observation.scope == expectation.scope,
        "case_mismatch": observation.case_query_id == expectation.case_query_id,
        "occurrence_mismatch": observation.occurrence_id == expectation.occurrence_id,
        "relation_mismatch": observation.relation_name == expectation.relation_name,
        "relation_oid_missing": observation.relation_oid is not None,
        "rid_domain_mismatch": observation.rid_domain_id == expectation.rid_domain_id,
        "policy_mismatch": observation.policy_id == expectation.policy_id,
        "principal_mismatch": observation.principal_id == expectation.principal_id,
        "context_id_mismatch": observation.context_id == expectation.context_id,
        "context_hash_mismatch": observation.context_hash == expectation.context_hash,
        "context_payload_mismatch": observation.canonical_context_json
        == expectation.canonical_context_json,
        "context_version_mismatch": observation.context_version
        == expectation.context_version,
        "base_epoch_missing": observation.current_base_version is not None,
        "membership_epoch_missing": observation.current_membership_version is not None,
        "session_identity_mismatch": observation.session_user
        == observation.current_user,
        "collector_sql_mismatch": observation.collector_sql_digest
        == expected_collector_sql_digest,
        "artifact_inventory_mismatch": tuple(
            (item.kind, item.artifact_id, item.physical_relation)
            for item in observation.artifacts
        )
        == tuple(
            (item.kind, item.artifact_id, item.physical_relation)
            for item in expectation.artifacts
        ),
    }
    return tuple(sorted(reason for reason, ok in checks.items() if not ok))


def _issue_e10_planning_receipt(
    expectation: E10PlanningExpectation,
    observation: E10PlanningCatalogObservation,
    *,
    collector_sql_digest: str,
) -> E10PlanningReceipt:
    assessments = tuple(
        _assess_e10_planning_artifact(
            expectation,
            artifact_expectation,
            observation,
            artifact,
        )
        for artifact_expectation, artifact in zip(
            expectation.artifacts,
            observation.artifacts,
        )
    )
    reasons = _e10_planning_core_reasons(
        expectation,
        observation,
        expected_collector_sql_digest=collector_sql_digest,
    )
    usable = tuple(item.kind for item in assessments if item.usable)
    draft = E10PlanningReceipt(
        schema_version=E10_PLANNING_RECEIPT_SCHEMA,
        validator_version=E10_PLANNING_VALIDATOR_VERSION,
        scope=expectation.scope,
        expectation_digest=expectation.digest,
        policy_manifest_digest=expectation.policy_manifest_digest,
        policy_config_digest=expectation.policy_config_digest,
        policy_definition_digest=expectation.policy_definition_digest,
        exact_predicate_digest=expectation.exact_predicate_digest,
        guard_predicate_digest=expectation.guard_predicate_digest,
        query_predicate_digest=expectation.query_predicate_digest,
        registry_inventory=expectation.registry_inventory,
        declared_artifacts=tuple(
            item for item in expectation.artifacts if item.declared
        ),
        observation=observation,
        artifact_assessments=assessments,
        validated_usable_kinds=usable,
        reasons=reasons,
        receipt_digest="pending",
    )
    payload = draft.to_dict()
    payload.pop("receipt_digest", None)
    issued = replace(draft, receipt_digest=_canonical_digest(payload))
    return _register_e10_production_source(
        issued,
        kind="receipt",
        identity_digest=issued.receipt_digest,
    )


def _e10_planning_artifact_assessment_from_dict(
    payload: Any,
) -> E10PlanningArtifactAssessment:
    label = "planning_artifact_assessment"
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be an object")
    fields = {
        "kind",
        "artifact_id",
        "declared",
        "target_domain",
        "observed",
        "artifact_identity_matches",
        "dependency_set_complete",
        "fresh",
        "context_matches",
        "scope_matches",
        "rid_domain_matches",
        "base_relation_matches",
        "policy_matches",
        "principal_matches",
        "exact",
        "keyed",
        "key_domain_matches",
        "usable",
        "reasons",
    }
    _strict_e10_state_keys(payload, fields, label=label)
    reasons = payload["reasons"]
    if not isinstance(reasons, list) or any(
        not isinstance(item, str) or not item for item in reasons
    ):
        raise ValueError(f"{label}.reasons must be a string list")
    if reasons != sorted(set(reasons)):
        raise ValueError(f"{label}.reasons are not canonical")
    if payload["target_domain"] != E10_PLANNING_TARGET_DOMAIN:
        raise ValueError(f"{label}.target_domain is invalid")
    boolean_fields = fields - {
        "kind",
        "artifact_id",
        "target_domain",
        "reasons",
    }
    booleans = {
        key: _strict_e10_bool(payload, key, label=label) for key in boolean_fields
    }
    return E10PlanningArtifactAssessment(
        kind=_strict_e10_state_string(payload, "kind", label=label),
        artifact_id=_strict_e10_state_string(payload, "artifact_id", label=label),
        declared=booleans["declared"],
        target_domain=E10_PLANNING_TARGET_DOMAIN,
        observed=booleans["observed"],
        artifact_identity_matches=booleans["artifact_identity_matches"],
        dependency_set_complete=booleans["dependency_set_complete"],
        fresh=booleans["fresh"],
        context_matches=booleans["context_matches"],
        scope_matches=booleans["scope_matches"],
        rid_domain_matches=booleans["rid_domain_matches"],
        base_relation_matches=booleans["base_relation_matches"],
        policy_matches=booleans["policy_matches"],
        principal_matches=booleans["principal_matches"],
        exact=booleans["exact"],
        keyed=booleans["keyed"],
        key_domain_matches=booleans["key_domain_matches"],
        usable=booleans["usable"],
        reasons=tuple(reasons),
    )


def _e10_planning_receipt_from_dict(payload: Any) -> E10PlanningReceipt:
    label = "e10_planning_receipt"
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be an object")
    fields = {
        "schema_version",
        "validator_version",
        "scope",
        "expectation_digest",
        "policy_manifest_digest",
        "policy_config_digest",
        "policy_definition_digest",
        "exact_predicate_digest",
        "guard_predicate_digest",
        "query_predicate_digest",
        "registry_inventory",
        "declared_artifacts",
        "observation",
        "artifact_assessments",
        "validated_usable_kinds",
        "reasons",
        "receipt_digest",
    }
    _strict_e10_state_keys(payload, fields, label=label)
    list_fields = (
        "registry_inventory",
        "declared_artifacts",
        "artifact_assessments",
        "validated_usable_kinds",
        "reasons",
    )
    if any(not isinstance(payload[key], list) for key in list_fields):
        raise ValueError(f"{label} canonical inventories must be lists")
    registry = tuple(
        _e10_planning_registry_entry_from_dict(item)
        for item in payload["registry_inventory"]
    )
    declared = tuple(
        _e10_planning_artifact_expectation_from_dict(item)
        for item in payload["declared_artifacts"]
    )
    assessments = tuple(
        _e10_planning_artifact_assessment_from_dict(item)
        for item in payload["artifact_assessments"]
    )
    usable = tuple(payload["validated_usable_kinds"])
    reasons = tuple(payload["reasons"])
    if any(not isinstance(item, str) or not item for item in usable + reasons):
        raise ValueError(f"{label} string inventories are malformed")
    if registry != tuple(sorted(registry, key=lambda item: item.template_id)):
        raise ValueError(f"{label}.registry_inventory is not canonical")
    if tuple(item.kind for item in assessments) != E10_PLANNING_ARTIFACT_KINDS:
        raise ValueError(f"{label}.artifact_assessments are not canonical")
    if usable != tuple(kind for kind in E10_PLANNING_ARTIFACT_KINDS if kind in usable):
        raise ValueError(f"{label}.validated_usable_kinds are not canonical")
    if reasons != tuple(sorted(set(reasons))):
        raise ValueError(f"{label}.reasons are not canonical")
    draft = E10PlanningReceipt(
        schema_version=_strict_e10_state_string(payload, "schema_version", label=label),
        validator_version=_strict_e10_state_string(
            payload,
            "validator_version",
            label=label,
        ),
        scope=_strict_e10_state_string(payload, "scope", label=label),
        expectation_digest=_strict_e10_state_string(
            payload,
            "expectation_digest",
            label=label,
        ),
        policy_manifest_digest=_strict_e10_state_string(
            payload,
            "policy_manifest_digest",
            label=label,
        ),
        policy_config_digest=_strict_e10_state_string(
            payload,
            "policy_config_digest",
            label=label,
        ),
        policy_definition_digest=_strict_e10_state_string(
            payload,
            "policy_definition_digest",
            label=label,
        ),
        exact_predicate_digest=_strict_e10_state_string(
            payload,
            "exact_predicate_digest",
            label=label,
        ),
        guard_predicate_digest=_strict_e10_state_string(
            payload,
            "guard_predicate_digest",
            label=label,
        ),
        query_predicate_digest=_strict_e10_state_string(
            payload,
            "query_predicate_digest",
            label=label,
        ),
        registry_inventory=registry,
        declared_artifacts=declared,
        observation=_e10_planning_catalog_observation_from_dict(payload["observation"]),
        artifact_assessments=assessments,
        validated_usable_kinds=usable,
        reasons=reasons,
        receipt_digest="pending",
    )
    if draft.schema_version != E10_PLANNING_RECEIPT_SCHEMA:
        raise ValueError("E10 planning receipt schema is not trusted")
    if draft.validator_version != E10_PLANNING_VALIDATOR_VERSION:
        raise ValueError("E10 planning receipt validator is not trusted")
    canonical_payload = draft.to_dict()
    canonical_payload.pop("receipt_digest", None)
    canonical = replace(
        draft,
        receipt_digest=_canonical_digest(canonical_payload),
    )
    if payload["receipt_digest"] != canonical.receipt_digest:
        raise ValueError("E10 planning receipt digest mismatch")
    return canonical


def _replay_e10_planning_receipt(
    receipt: E10PlanningReceipt,
    expectation: E10PlanningExpectation,
    *,
    require_production: bool,
) -> E10PlanningReplay:
    reasons: list[str] = []
    try:
        canonical = _e10_planning_receipt_from_dict(receipt.to_dict())
    except (TypeError, ValueError) as exc:
        return E10PlanningReplay(
            schema_version=E10_PLANNING_REPLAY_SCHEMA,
            valid=False,
            scope=receipt.scope,
            receipt_digest=receipt.receipt_digest,
            validated_usable_kinds=(),
            reasons=(f"receipt_malformed:{type(exc).__name__}",),
        )
    expected_sql, expected_collector_digest = _e10_planning_collector_sql(expectation)
    del expected_sql
    recomputed = _issue_e10_planning_receipt(
        expectation,
        canonical.observation,
        collector_sql_digest=expected_collector_digest,
    )
    if canonical != recomputed:
        reasons.append("receipt_replay_mismatch")
    if require_production and canonical.scope != "production":
        reasons.append("production_receipt_required")
    if canonical.expectation_digest != expectation.digest:
        reasons.append("expectation_digest_mismatch")
    reasons.extend(canonical.reasons)
    unique_reasons = tuple(sorted(set(reasons)))
    return E10PlanningReplay(
        schema_version=E10_PLANNING_REPLAY_SCHEMA,
        valid=not unique_reasons,
        scope=canonical.scope,
        receipt_digest=canonical.receipt_digest,
        validated_usable_kinds=(
            canonical.validated_usable_kinds if not unique_reasons else ()
        ),
        reasons=unique_reasons,
    )


def _e10_parent_requirement_to_dict(
    requirement: ParentRequirement,
) -> dict[str, Any]:
    return {
        "logical_group_id": requirement.logical_group_id,
        "visible_columns": list(requirement.visible_columns),
        "required_order": list(requirement.required_order),
        "licensed_refinements": list(requirement.licensed_refinements),
        "residual_allowed": requirement.residual_allowed,
        "residual_deadline": requirement.residual_deadline,
        "min_safety_level": requirement.min_safety_level,
        "freshness_predicate": requirement.freshness_predicate,
        "context_predicate": requirement.context_predicate,
        "allowed_enforcers": list(requirement.allowed_enforcers),
        "observable_coverage": list(requirement.observable_coverage),
        "transparent": requirement.transparent,
        "unsafe_expression_boundary": requirement.unsafe_expression_boundary,
        "needs_branch_lineage": requirement.needs_branch_lineage,
        "future_rid_intersection": requirement.future_rid_intersection,
    }


_E10_PARENT_REQUIREMENT_FIELDS = set(
    _e10_parent_requirement_to_dict(ParentRequirement())
)


def _e10_parent_requirement_from_dict(payload: Any) -> ParentRequirement:
    label = "e10_admission_parent_requirement"
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be an object")
    _strict_e10_state_keys(payload, _E10_PARENT_REQUIREMENT_FIELDS, label=label)
    tuple_fields = (
        "visible_columns",
        "required_order",
        "licensed_refinements",
        "allowed_enforcers",
        "observable_coverage",
    )
    tuple_values: dict[str, tuple[str, ...]] = {}
    for key in tuple_fields:
        value = payload[key]
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not item for item in value
        ):
            raise ValueError(f"{label}.{key} must be a string list")
        if len(set(value)) != len(value):
            raise ValueError(f"{label}.{key} has duplicate entries")
        tuple_values[key] = tuple(value)
    bool_fields = (
        "residual_allowed",
        "transparent",
        "unsafe_expression_boundary",
        "needs_branch_lineage",
        "future_rid_intersection",
    )
    bool_values = {
        key: _strict_e10_bool(payload, key, label=label) for key in bool_fields
    }
    return ParentRequirement(
        logical_group_id=_optional_e10_state_string(
            payload,
            "logical_group_id",
            label=label,
        ),
        visible_columns=tuple_values["visible_columns"],
        required_order=tuple_values["required_order"],
        licensed_refinements=tuple_values["licensed_refinements"],
        residual_allowed=bool_values["residual_allowed"],
        residual_deadline=_strict_e10_state_string(
            payload,
            "residual_deadline",
            label=label,
        ),
        min_safety_level=_strict_e10_state_string(
            payload,
            "min_safety_level",
            label=label,
        ),
        freshness_predicate=_optional_e10_state_string(
            payload,
            "freshness_predicate",
            label=label,
        ),
        context_predicate=_optional_e10_state_string(
            payload,
            "context_predicate",
            label=label,
        ),
        allowed_enforcers=tuple_values["allowed_enforcers"],
        observable_coverage=tuple_values["observable_coverage"],
        transparent=bool_values["transparent"],
        unsafe_expression_boundary=bool_values["unsafe_expression_boundary"],
        needs_branch_lineage=bool_values["needs_branch_lineage"],
        future_rid_intersection=bool_values["future_rid_intersection"],
    )


def _e10_policy_access_target_from_dict(payload: Any) -> PolicyAccessTarget:
    label = "e10_admission_logical_target"
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be an object")
    _strict_e10_state_keys(
        payload,
        {
            "kind",
            "relation",
            "policy_id",
            "occurrence_id",
            "principal_id",
            "context_digest",
            "policy_predicate_digest",
        },
        label=label,
    )
    if payload["kind"] != "policy_access":
        raise ValueError(f"{label}.kind is invalid")
    return PolicyAccessTarget(
        relation=_strict_e10_state_string(payload, "relation", label=label),
        policy_id=_strict_e10_state_string(payload, "policy_id", label=label),
        occurrence_id=_strict_e10_state_string(
            payload,
            "occurrence_id",
            label=label,
        ),
        principal_id=_strict_e10_state_string(
            payload,
            "principal_id",
            label=label,
        ),
        context_digest=_strict_e10_state_string(
            payload,
            "context_digest",
            label=label,
        ),
        policy_predicate_digest=_strict_e10_state_string(
            payload,
            "policy_predicate_digest",
            label=label,
        ),
    )


def _e10_implementation_binding_from_dict(
    payload: Any,
) -> ImplementationTargetBinding:
    label = "e10_admission_implementation_binding"
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be an object")
    _strict_e10_state_keys(
        payload,
        {
            "template_id",
            "occurrence_id",
            "logical_target_digest",
            "implementation_target_kind",
            "rid_col",
            "context_digest",
            "refinement_kind",
            "refinement_predicate_digest",
        },
        label=label,
    )
    return ImplementationTargetBinding(
        template_id=_strict_e10_state_string(
            payload,
            "template_id",
            label=label,
        ),
        occurrence_id=_strict_e10_state_string(
            payload,
            "occurrence_id",
            label=label,
        ),
        logical_target_digest=_strict_e10_state_string(
            payload,
            "logical_target_digest",
            label=label,
        ),
        implementation_target_kind=_strict_e10_state_string(
            payload,
            "implementation_target_kind",
            label=label,
        ),
        rid_col=_strict_e10_state_string(payload, "rid_col", label=label),
        context_digest=_strict_e10_state_string(
            payload,
            "context_digest",
            label=label,
        ),
        refinement_kind=_optional_e10_state_string(
            payload,
            "refinement_kind",
            label=label,
        ),
        refinement_predicate_digest=_optional_e10_state_string(
            payload,
            "refinement_predicate_digest",
            label=label,
        ),
    )


def _e10_gamma_fact_to_dict(fact: GammaFact) -> dict[str, Any]:
    return {
        "fact_id": fact.fact_id,
        "kind": fact.kind,
        "subject_digest": fact.subject_digest,
        "verdict": fact.verdict,
        "validator_version": fact.validator_version,
        "snapshot_id": fact.snapshot_id,
        "evidence_digest": fact.evidence_digest,
        "dynamic": fact.dynamic,
    }


def _e10_gamma_fact_from_dict(payload: Any) -> GammaFact:
    label = "e10_admission_gamma_fact"
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be an object")
    _strict_e10_state_keys(
        payload,
        {
            "fact_id",
            "kind",
            "subject_digest",
            "verdict",
            "validator_version",
            "snapshot_id",
            "evidence_digest",
            "dynamic",
        },
        label=label,
    )
    return GammaFact(
        fact_id=_strict_e10_state_string(payload, "fact_id", label=label),
        kind=_strict_e10_state_string(payload, "kind", label=label),
        subject_digest=_strict_e10_state_string(
            payload,
            "subject_digest",
            label=label,
        ),
        verdict=_strict_e10_state_string(payload, "verdict", label=label),
        validator_version=_strict_e10_state_string(
            payload,
            "validator_version",
            label=label,
        ),
        snapshot_id=_strict_e10_state_string(
            payload,
            "snapshot_id",
            label=label,
        ),
        evidence_digest=_strict_e10_state_string(
            payload,
            "evidence_digest",
            label=label,
        ),
        dynamic=_strict_e10_bool(payload, "dynamic", label=label),
    )


def _e10_gamma_snapshot_to_dict(snapshot: GammaSnapshot) -> dict[str, Any]:
    return {
        "snapshot_id": snapshot.snapshot_id,
        "facts": [
            _e10_gamma_fact_to_dict(item)
            for item in sorted(snapshot.facts, key=lambda fact: fact.fact_id)
        ],
    }


def _e10_gamma_snapshot_from_dict(payload: Any) -> GammaSnapshot:
    label = "e10_admission_gamma_snapshot"
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be an object")
    _strict_e10_state_keys(payload, {"snapshot_id", "facts"}, label=label)
    raw_facts = payload["facts"]
    if not isinstance(raw_facts, list):
        raise ValueError(f"{label}.facts must be a list")
    facts = tuple(_e10_gamma_fact_from_dict(item) for item in raw_facts)
    if facts != tuple(sorted(facts, key=lambda fact: fact.fact_id)):
        raise ValueError(f"{label}.facts are not canonical")
    if len({fact.fact_id for fact in facts}) != len(facts):
        raise ValueError(f"{label}.facts contain duplicate identifiers")
    return GammaSnapshot(
        snapshot_id=_strict_e10_state_string(
            payload,
            "snapshot_id",
            label=label,
        ),
        facts=facts,
    )


def _e10_admission_evidence_digest_payload(
    *,
    kind: str,
    subject_digest: str,
    validator_version: str,
    snapshot_id: str,
    source_kind: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": E10_ADMISSION_EVIDENCE_SCHEMA,
        "kind": kind,
        "subject_digest": subject_digest,
        "validator_version": validator_version,
        "snapshot_id": snapshot_id,
        "source_kind": source_kind,
        "payload": dict(payload),
    }


def _e10_admission_fact_id(
    *,
    kind: str,
    subject_digest: str,
    snapshot_id: str,
    evidence_digest: str,
) -> str:
    identity = _canonical_digest(
        {
            "kind": kind,
            "subject_digest": subject_digest,
            "snapshot_id": snapshot_id,
            "evidence_digest": evidence_digest,
        }
    ).removeprefix("sha256:")
    return f"e10-admission:{kind}:{identity}"


def _e10_admission_evidence_from_dict(payload: Any) -> E10AdmissionEvidence:
    label = "e10_admission_evidence"
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be an object")
    _strict_e10_state_keys(
        payload,
        {
            "schema_version",
            "fact_id",
            "kind",
            "subject_digest",
            "validator_version",
            "snapshot_id",
            "source_kind",
            "payload",
            "evidence_digest",
        },
        label=label,
    )
    evidence_payload = payload["payload"]
    if not isinstance(evidence_payload, Mapping):
        raise ValueError(f"{label}.payload must be an object")
    schema_version = _strict_e10_state_string(
        payload,
        "schema_version",
        label=label,
    )
    if schema_version != E10_ADMISSION_EVIDENCE_SCHEMA:
        raise ValueError(f"{label}.schema_version is not trusted")
    kind = _strict_e10_state_string(payload, "kind", label=label)
    subject_digest = _strict_e10_state_string(
        payload,
        "subject_digest",
        label=label,
    )
    validator_version = _strict_e10_state_string(
        payload,
        "validator_version",
        label=label,
    )
    snapshot_id = _strict_e10_state_string(
        payload,
        "snapshot_id",
        label=label,
    )
    source_kind = _strict_e10_state_string(
        payload,
        "source_kind",
        label=label,
    )
    if source_kind not in E10_ADMISSION_EVIDENCE_SOURCE_KINDS:
        raise ValueError(f"{label}.source_kind is unknown")
    canonical_payload = dict(evidence_payload)
    evidence_digest = _canonical_digest(
        _e10_admission_evidence_digest_payload(
            kind=kind,
            subject_digest=subject_digest,
            validator_version=validator_version,
            snapshot_id=snapshot_id,
            source_kind=source_kind,
            payload=canonical_payload,
        )
    )
    if payload["evidence_digest"] != evidence_digest:
        raise ValueError(f"{label}.evidence_digest mismatch")
    fact_id = _e10_admission_fact_id(
        kind=kind,
        subject_digest=subject_digest,
        snapshot_id=snapshot_id,
        evidence_digest=evidence_digest,
    )
    if payload["fact_id"] != fact_id:
        raise ValueError(f"{label}.fact_id mismatch")
    return E10AdmissionEvidence(
        schema_version=schema_version,
        fact_id=fact_id,
        kind=kind,
        subject_digest=subject_digest,
        validator_version=validator_version,
        snapshot_id=snapshot_id,
        source_kind=source_kind,
        payload_json=_canonical_json(canonical_payload),
        evidence_digest=evidence_digest,
    )


def _e10_admission_dynamic_obligation_from_dict(
    payload: Any,
) -> E10AdmissionDynamicObligation:
    label = "e10_admission_dynamic_obligation"
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be an object")
    _strict_e10_state_keys(
        payload,
        {"kind", "artifact_id", "snapshot_id", "source_fact_id"},
        label=label,
    )
    kind = _strict_e10_state_string(payload, "kind", label=label)
    if kind not in E10_ADMISSION_DYNAMIC_OBLIGATION_KINDS:
        raise ValueError(f"{label}.kind is unknown")
    return E10AdmissionDynamicObligation(
        kind=kind,
        artifact_id=_strict_e10_state_string(
            payload,
            "artifact_id",
            label=label,
        ),
        snapshot_id=_strict_e10_state_string(
            payload,
            "snapshot_id",
            label=label,
        ),
        source_fact_id=_strict_e10_state_string(
            payload,
            "source_fact_id",
            label=label,
        ),
    )


_E10_ADMISSION_BUNDLE_FIELDS = {
    "schema_version",
    "issuer_version",
    "scope",
    "case_query_id",
    "receipt_digest",
    "expectation_digest",
    "observation_digest",
    "collector_sql_digest",
    "observation_snapshot_text",
    "snapshot_id",
    "registry_inventory",
    "exact_predicate_digest",
    "query_predicate_digest",
    "guard_predicate_digest",
    "residual_predicate_digest",
    "guard_lowering_digest",
    "logical_target",
    "implementation_target_bindings",
    "parent_requirement",
    "gamma_snapshot",
    "gamma_snapshot_digest",
    "evidence",
    "unresolved_dynamic_obligations",
    "bundle_digest",
}


def _e10_admission_bundle_from_dict(payload: Any) -> E10AdmissionBundle:
    label = "e10_admission_bundle"
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be an object")
    _strict_e10_state_keys(payload, _E10_ADMISSION_BUNDLE_FIELDS, label=label)
    list_fields = (
        "registry_inventory",
        "implementation_target_bindings",
        "evidence",
        "unresolved_dynamic_obligations",
    )
    if any(not isinstance(payload[key], list) for key in list_fields):
        raise ValueError(f"{label} canonical inventories must be lists")
    registry = tuple(
        _e10_planning_registry_entry_from_dict(item)
        for item in payload["registry_inventory"]
    )
    bindings = tuple(
        _e10_implementation_binding_from_dict(item)
        for item in payload["implementation_target_bindings"]
    )
    evidence = tuple(
        _e10_admission_evidence_from_dict(item) for item in payload["evidence"]
    )
    obligations = tuple(
        _e10_admission_dynamic_obligation_from_dict(item)
        for item in payload["unresolved_dynamic_obligations"]
    )
    if registry != tuple(sorted(registry, key=lambda item: item.template_id)):
        raise ValueError(f"{label}.registry_inventory is not canonical")
    if bindings != tuple(sorted(bindings, key=lambda item: item.template_id)):
        raise ValueError(f"{label}.implementation bindings are not canonical")
    if evidence != tuple(sorted(evidence, key=lambda item: item.fact_id)):
        raise ValueError(f"{label}.evidence is not canonical")

    def obligation_key(
        item: E10AdmissionDynamicObligation,
    ) -> tuple[str, str, str]:
        return (
            item.artifact_id,
            item.kind,
            item.source_fact_id,
        )

    if obligations != tuple(sorted(obligations, key=obligation_key)):
        raise ValueError(f"{label}.dynamic obligations are not canonical")
    if len({item.template_id for item in bindings}) != len(bindings):
        raise ValueError(f"{label}.implementation bindings have duplicates")
    if len({item.template_id for item in registry}) != len(registry):
        raise ValueError(f"{label}.registry inventory has duplicates")
    if len({item.fact_id for item in evidence}) != len(evidence):
        raise ValueError(f"{label}.evidence has duplicate fact identities")
    if len(set(obligations)) != len(obligations):
        raise ValueError(f"{label}.dynamic obligations have duplicates")
    gamma = _e10_gamma_snapshot_from_dict(payload["gamma_snapshot"])
    if payload["gamma_snapshot_digest"] != gamma.digest:
        raise ValueError(f"{label}.gamma snapshot digest mismatch")
    evidence_by_fact = {item.fact_id: item for item in evidence}
    if set(evidence_by_fact) != {fact.fact_id for fact in gamma.facts}:
        raise ValueError(f"{label}.fact/evidence inventory mismatch")
    for fact in gamma.facts:
        item = evidence_by_fact[fact.fact_id]
        expected_source_kind = E10_ADMISSION_SOURCE_KIND_BY_FACT_KIND.get(fact.kind)
        if (
            expected_source_kind is None
            or fact.verdict != "pass"
            or fact.dynamic
            or fact.validator_version != E10_ADMISSION_VALIDATOR_VERSION
            or fact.snapshot_id != gamma.snapshot_id
            or item.kind != fact.kind
            or item.subject_digest != fact.subject_digest
            or item.validator_version != fact.validator_version
            or item.snapshot_id != fact.snapshot_id
            or item.source_kind != expected_source_kind
            or item.evidence_digest != fact.evidence_digest
        ):
            raise ValueError(f"{label}.fact/evidence alignment mismatch")
    draft = E10AdmissionBundle(
        schema_version=_strict_e10_state_string(
            payload,
            "schema_version",
            label=label,
        ),
        issuer_version=_strict_e10_state_string(
            payload,
            "issuer_version",
            label=label,
        ),
        scope=_strict_e10_state_string(payload, "scope", label=label),
        case_query_id=_strict_e10_state_string(
            payload,
            "case_query_id",
            label=label,
        ),
        receipt_digest=_strict_e10_state_string(
            payload,
            "receipt_digest",
            label=label,
        ),
        expectation_digest=_strict_e10_state_string(
            payload,
            "expectation_digest",
            label=label,
        ),
        observation_digest=_strict_e10_state_string(
            payload,
            "observation_digest",
            label=label,
        ),
        collector_sql_digest=_strict_e10_state_string(
            payload,
            "collector_sql_digest",
            label=label,
        ),
        observation_snapshot_text=_strict_e10_state_string(
            payload,
            "observation_snapshot_text",
            label=label,
        ),
        snapshot_id=_strict_e10_state_string(
            payload,
            "snapshot_id",
            label=label,
        ),
        registry_inventory=registry,
        exact_predicate_digest=_strict_e10_state_string(
            payload,
            "exact_predicate_digest",
            label=label,
        ),
        query_predicate_digest=_strict_e10_state_string(
            payload,
            "query_predicate_digest",
            label=label,
        ),
        guard_predicate_digest=_strict_e10_state_string(
            payload,
            "guard_predicate_digest",
            label=label,
        ),
        residual_predicate_digest=_optional_e10_state_string(
            payload,
            "residual_predicate_digest",
            label=label,
        ),
        guard_lowering_digest=_optional_e10_state_string(
            payload,
            "guard_lowering_digest",
            label=label,
        ),
        logical_target=_e10_policy_access_target_from_dict(payload["logical_target"]),
        implementation_target_bindings=bindings,
        parent_requirement=_e10_parent_requirement_from_dict(
            payload["parent_requirement"]
        ),
        gamma_snapshot=gamma,
        evidence=evidence,
        unresolved_dynamic_obligations=obligations,
        bundle_digest="pending",
    )
    if draft.schema_version != E10_ADMISSION_BUNDLE_SCHEMA:
        raise ValueError("E10 admission bundle schema is not trusted")
    if draft.issuer_version != E10_ADMISSION_ISSUER_VERSION:
        raise ValueError("E10 admission bundle issuer is not trusted")
    if draft.scope not in {"production", "fixture"}:
        raise ValueError("E10 admission bundle scope is invalid")
    if draft.snapshot_id != gamma.snapshot_id:
        raise ValueError("E10 admission bundle snapshot identity mismatch")
    if any(item.snapshot_id != draft.snapshot_id for item in evidence):
        raise ValueError("E10 admission evidence snapshot mismatch")
    if any(item.snapshot_id != draft.snapshot_id for item in obligations):
        raise ValueError("E10 admission obligation snapshot mismatch")
    if {item.template_id for item in draft.implementation_target_bindings} != {
        item.template_id for item in draft.registry_inventory
    }:
        raise ValueError("E10 admission binding coverage mismatch")
    target_digest = draft.logical_target.digest
    for item in draft.implementation_target_bindings:
        try:
            target_kind = template_definition(item.template_id).target_kind
        except KeyError as exc:
            raise ValueError(
                "E10 admission implementation template is unknown"
            ) from exc
        if (
            item.logical_target_digest != target_digest
            or item.occurrence_id != draft.logical_target.occurrence_id
            or item.context_digest != draft.logical_target.context_digest
            or item.implementation_target_kind != target_kind
        ):
            raise ValueError("E10 admission implementation binding mismatch")
    fact_by_id = {item.fact_id: item for item in gamma.facts}
    if any(
        item.source_fact_id not in fact_by_id
        or fact_by_id[item.source_fact_id].kind != "artifact_validation"
        or fact_by_id[item.source_fact_id].subject_digest != item.artifact_id
        for item in obligations
    ):
        raise ValueError("E10 admission dynamic obligation source mismatch")
    canonical_payload = draft.to_dict()
    canonical_payload.pop("bundle_digest", None)
    canonical = replace(
        draft,
        bundle_digest=_canonical_digest(canonical_payload),
    )
    if payload["bundle_digest"] != canonical.bundle_digest:
        raise ValueError("E10 admission bundle digest mismatch")
    return canonical


_E10_STATE_RAW_FIELDS = {
    "schema_version",
    "collector_version",
    "session_user",
    "current_user",
    "search_path",
    "row_security",
    "isolation_level",
    "snapshot_text",
    "artifact_id",
    "physical_relation_oid",
    "base_relation_oid",
    "target_context_principal_id",
    "target_context_payload",
    "target_context_version",
    "artifact_context_principal_id",
    "artifact_context_payload",
    "artifact_context_version",
    "current_base_version",
    "current_membership_version",
    "dependencies",
}


def _strict_e10_state_keys(
    payload: Mapping[str, Any],
    expected: set[str],
    *,
    label: str,
) -> None:
    actual = set(payload)
    if actual != expected:
        raise ValueError(
            f"{label} schema mismatch; "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )


def _strict_e10_state_string(
    payload: Mapping[str, Any],
    key: str,
    *,
    label: str,
) -> str:
    value = payload[key]
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label}.{key} must be a non-empty string")
    return value


def _optional_e10_state_string(
    payload: Mapping[str, Any],
    key: str,
    *,
    label: str,
) -> Optional[str]:
    value = payload[key]
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label}.{key} must be null or a non-empty string")
    return value


def _optional_e10_state_int(
    payload: Mapping[str, Any],
    key: str,
    *,
    label: str,
) -> Optional[int]:
    value = payload[key]
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label}.{key} must be null or an integer")
    if value < 0:
        raise ValueError(f"{label}.{key} must be non-negative")
    return value


def _canonical_optional_context_payload(
    value: Any,
    *,
    label: str,
) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be null or a JSON object")
    return _canonical_json(value)


def _e10_dependency_state_from_dict(payload: Any) -> E10ArtifactDependencyState:
    if not isinstance(payload, Mapping):
        raise ValueError("E10 artifact dependency must be an object")
    _strict_e10_state_keys(
        payload,
        {"dep_kind", "dep_name", "version_at_build"},
        label="artifact_dependency",
    )
    version = payload["version_at_build"]
    if not isinstance(version, int) or isinstance(version, bool):
        raise ValueError("artifact_dependency.version_at_build must be an integer")
    if version < 0:
        raise ValueError("artifact_dependency.version_at_build must be non-negative")
    return E10ArtifactDependencyState(
        dep_kind=_strict_e10_state_string(
            payload,
            "dep_kind",
            label="artifact_dependency",
        ),
        dep_name=_strict_e10_state_string(
            payload,
            "dep_name",
            label="artifact_dependency",
        ),
        version_at_build=version,
    )


def _e10_catalog_state_digest_payload(
    observation: E10ArtifactStateObservation,
) -> dict[str, Any]:
    payload = observation.to_dict()
    for key in {
        "schema_version",
        "collector_version",
        "session_user",
        "current_user",
        "search_path",
        "row_security",
        "isolation_level",
        "snapshot_text",
        "catalog_state_digest",
        "observation_digest",
    }:
        payload.pop(key, None)
    return payload


def _e10_observation_digest_payload(
    observation: E10ArtifactStateObservation,
) -> dict[str, Any]:
    payload = observation.to_dict()
    payload.pop("observation_digest", None)
    return payload


def _issue_e10_artifact_state_observation(
    payload: Mapping[str, Any],
) -> E10ArtifactStateObservation:
    label = "e10_artifact_state_observation"
    _strict_e10_state_keys(payload, _E10_STATE_RAW_FIELDS, label=label)
    raw_dependencies = payload["dependencies"]
    if not isinstance(raw_dependencies, list):
        raise ValueError(f"{label}.dependencies must be a JSON list")
    dependencies = tuple(
        _e10_dependency_state_from_dict(item) for item in raw_dependencies
    )
    canonical_dependencies = tuple(
        sorted(
            dependencies,
            key=lambda item: (
                item.dep_kind,
                item.dep_name,
                item.version_at_build,
            ),
        )
    )
    if len(set(dependencies)) != len(dependencies):
        raise ValueError(f"{label}.dependencies contain a duplicate entry")
    if dependencies != canonical_dependencies:
        raise ValueError(f"{label}.dependencies are not in canonical order")
    draft = E10ArtifactStateObservation(
        schema_version=_strict_e10_state_string(
            payload,
            "schema_version",
            label=label,
        ),
        collector_version=_strict_e10_state_string(
            payload,
            "collector_version",
            label=label,
        ),
        session_user=_strict_e10_state_string(
            payload,
            "session_user",
            label=label,
        ),
        current_user=_strict_e10_state_string(
            payload,
            "current_user",
            label=label,
        ),
        search_path=_strict_e10_state_string(
            payload,
            "search_path",
            label=label,
        ),
        row_security=_strict_e10_state_string(
            payload,
            "row_security",
            label=label,
        ),
        isolation_level=_strict_e10_state_string(
            payload,
            "isolation_level",
            label=label,
        ),
        snapshot_text=_strict_e10_state_string(
            payload,
            "snapshot_text",
            label=label,
        ),
        artifact_id=_strict_e10_state_string(
            payload,
            "artifact_id",
            label=label,
        ),
        physical_relation_oid=_optional_e10_state_int(
            payload,
            "physical_relation_oid",
            label=label,
        ),
        base_relation_oid=_optional_e10_state_int(
            payload,
            "base_relation_oid",
            label=label,
        ),
        target_context_principal_id=_optional_e10_state_string(
            payload,
            "target_context_principal_id",
            label=label,
        ),
        target_context_payload_json=_canonical_optional_context_payload(
            payload["target_context_payload"],
            label=f"{label}.target_context_payload",
        ),
        target_context_version=_optional_e10_state_int(
            payload,
            "target_context_version",
            label=label,
        ),
        artifact_context_principal_id=_optional_e10_state_string(
            payload,
            "artifact_context_principal_id",
            label=label,
        ),
        artifact_context_payload_json=_canonical_optional_context_payload(
            payload["artifact_context_payload"],
            label=f"{label}.artifact_context_payload",
        ),
        artifact_context_version=_optional_e10_state_int(
            payload,
            "artifact_context_version",
            label=label,
        ),
        current_base_version=_optional_e10_state_int(
            payload,
            "current_base_version",
            label=label,
        ),
        current_membership_version=_optional_e10_state_int(
            payload,
            "current_membership_version",
            label=label,
        ),
        dependencies=dependencies,
        catalog_state_digest="pending",
        observation_digest="pending",
    )
    if draft.schema_version != E10_STATE_OBSERVATION_SCHEMA:
        raise ValueError("E10 artifact state observation schema is not trusted")
    if draft.collector_version != E10_STATE_COLLECTOR_VERSION:
        raise ValueError("E10 artifact state collector version is not trusted")
    if draft.search_path != E10_STATE_SEARCH_PATH:
        raise ValueError("E10 artifact state search_path is not canonical")
    if draft.row_security != E10_STATE_ROW_SECURITY:
        raise ValueError("E10 artifact state row_security setting is not canonical")
    if draft.isolation_level != "repeatable read":
        raise ValueError("E10 artifact state observation is not repeatable read")
    if any(
        oid is not None and oid <= 0
        for oid in (draft.physical_relation_oid, draft.base_relation_oid)
    ):
        raise ValueError("E10 artifact state relation OID is invalid")
    catalog_digest = _canonical_digest(_e10_catalog_state_digest_payload(draft))
    with_catalog = replace(draft, catalog_state_digest=catalog_digest)
    return replace(
        with_catalog,
        observation_digest=_canonical_digest(
            _e10_observation_digest_payload(with_catalog)
        ),
    )


def _e10_artifact_state_observation_from_dict(
    payload: Any,
) -> E10ArtifactStateObservation:
    if not isinstance(payload, Mapping):
        raise ValueError("E10 artifact state observation must be an object")
    _strict_e10_state_keys(
        payload,
        _E10_STATE_RAW_FIELDS | {"catalog_state_digest", "observation_digest"},
        label="e10_artifact_state_observation",
    )
    raw = {key: payload[key] for key in _E10_STATE_RAW_FIELDS}
    canonical = _issue_e10_artifact_state_observation(raw)
    if payload["catalog_state_digest"] != canonical.catalog_state_digest:
        raise ValueError("E10 artifact catalog state digest mismatch")
    if payload["observation_digest"] != canonical.observation_digest:
        raise ValueError("E10 artifact observation digest mismatch")
    return canonical


def _dependency_by_kind(
    observation: E10ArtifactStateObservation,
) -> tuple[dict[str, E10ArtifactDependencyState], bool]:
    grouped: dict[str, list[E10ArtifactDependencyState]] = {}
    for dependency in observation.dependencies:
        grouped.setdefault(dependency.dep_kind, []).append(dependency)
    complete = set(grouped) == set(E10_STATE_DEPENDENCY_KINDS) and all(
        len(items) == 1 for items in grouped.values()
    )
    return (
        {kind: items[0] for kind, items in grouped.items() if len(items) == 1},
        complete,
    )


def _assess_e10_artifact_state(
    observation: E10ArtifactStateObservation,
    expectation: E10ArtifactStateExpectation,
) -> E10ArtifactStateAssessment:
    dependencies, dependency_set_complete = _dependency_by_kind(observation)

    def dep(kind: str) -> Optional[E10ArtifactDependencyState]:
        return dependencies.get(kind)

    artifact_kind = dep("artifact_kind")
    artifact_relation = dep("artifact_relation")
    base = dep("base")
    base_oid = dep("base_relation_oid")
    context = dep("context_scope")
    membership = dep("membership")
    policy = dep("policy")
    principal = dep("principal")
    rid_domain = dep("rid_domain")

    artifact_identity_matches = bool(
        observation.artifact_id == expectation.artifact_id
        and artifact_kind is not None
        and artifact_kind.dep_name == expectation.artifact_kind
        and artifact_kind.version_at_build == 0
        and artifact_relation is not None
        and artifact_relation.dep_name == expectation.physical_relation
        and observation.physical_relation_oid is not None
        and artifact_relation.version_at_build == observation.physical_relation_oid
    )
    relation_identity_matches = bool(
        base is not None
        and base.dep_name == expectation.base_relation.removeprefix("public.")
        and base_oid is not None
        and base_oid.dep_name == expectation.base_relation
        and observation.base_relation_oid is not None
        and base_oid.version_at_build == observation.base_relation_oid
    )
    rid_identity_matches = bool(
        rid_domain is not None
        and rid_domain.dep_name == expectation.rid_domain_id
        and rid_domain.version_at_build == 0
    )
    policy_identity_matches = bool(
        policy is not None
        and policy.dep_name == expectation.policy_id
        and policy.version_at_build == 0
    )
    target_context_payload = (
        None
        if observation.target_context_payload_json is None
        else json.loads(observation.target_context_payload_json)
    )
    artifact_context_payload = (
        None
        if observation.artifact_context_payload_json is None
        else json.loads(observation.artifact_context_payload_json)
    )
    principal_matches = bool(
        principal is not None
        and principal.dep_name == expectation.principal_id
        and principal.version_at_build == 0
        and observation.target_context_principal_id == expectation.principal_id
        and observation.artifact_context_principal_id == principal.dep_name
        and isinstance(target_context_payload, Mapping)
        and str(target_context_payload.get("user_id")) == expectation.principal_id
        and isinstance(artifact_context_payload, Mapping)
        and str(artifact_context_payload.get("user_id")) == principal.dep_name
    )
    target_context_digest = (
        None
        if target_context_payload is None
        else _canonical_digest(target_context_payload)
    )
    artifact_context_digest = (
        None
        if artifact_context_payload is None
        else _canonical_digest(artifact_context_payload)
    )
    context_matches = bool(
        context is not None
        and context.dep_name == expectation.target_context_hash
        and target_context_digest == expectation.target_context_hash
        and artifact_context_digest == context.dep_name
        and observation.target_context_payload_json is not None
        and observation.artifact_context_payload_json
        == observation.target_context_payload_json
    )
    base_fresh = bool(
        base is not None
        and observation.current_base_version is not None
        and base.version_at_build == observation.current_base_version
    )
    context_fresh = bool(
        context is not None
        and observation.target_context_version is not None
        and observation.artifact_context_version is not None
        and observation.target_context_version
        == observation.artifact_context_version
        == context.version_at_build
    )
    membership_fresh = bool(
        membership is not None
        and membership.dep_name == "group_membership"
        and observation.current_membership_version is not None
        and membership.version_at_build == observation.current_membership_version
    )
    checks = {
        "dependency_set_incomplete": dependency_set_complete,
        "artifact_identity_mismatch": artifact_identity_matches,
        "relation_identity_mismatch": relation_identity_matches,
        "rid_identity_mismatch": rid_identity_matches,
        "policy_identity_mismatch": policy_identity_matches,
        "principal_mismatch": principal_matches,
        "context_mismatch": context_matches,
        "base_stale": base_fresh,
        "context_stale": context_fresh,
        "membership_stale": membership_fresh,
    }
    reasons = tuple(sorted(reason for reason, ok in checks.items() if not ok))
    return E10ArtifactStateAssessment(
        valid=not reasons,
        dependency_set_complete=dependency_set_complete,
        artifact_identity_matches=artifact_identity_matches,
        relation_identity_matches=relation_identity_matches,
        rid_identity_matches=rid_identity_matches,
        policy_identity_matches=policy_identity_matches,
        principal_matches=principal_matches,
        context_matches=context_matches,
        base_fresh=base_fresh,
        context_fresh=context_fresh,
        membership_fresh=membership_fresh,
        reasons=reasons,
    )


def _e10_artifact_state_observation_sql(
    expectation: E10ArtifactStateExpectation,
) -> str:
    base_name = expectation.base_relation.removeprefix("public.")
    return f"""
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL search_path TO pg_catalog, public;
SET LOCAL row_security = on;
WITH dependency_rows AS MATERIALIZED (
  SELECT dependency.dep_kind,
         dependency.dep_name,
         dependency.version_at_build
  FROM public.artifact_dependencies dependency
  WHERE dependency.artifact_id = {_quote(expectation.artifact_id)}
  ORDER BY dependency.dep_kind, dependency.dep_name, dependency.version_at_build
),
artifact_context_key AS MATERIALIZED (
  SELECT dependency.dep_name AS ctx_hash
  FROM dependency_rows dependency
  WHERE dependency.dep_kind = 'context_scope'
),
artifact_context AS MATERIALIZED (
  SELECT context.ctx_hash,
         context.user_id::text AS principal_id,
         context.canonical_context,
         version.version
  FROM artifact_context_key key
  JOIN public.synthetic_context context ON context.ctx_hash = key.ctx_hash
  JOIN public.context_versions version
    ON version.ctx_hash = context.ctx_hash
   AND version.canonical_context = context.canonical_context
),
target_context AS MATERIALIZED (
  SELECT context.ctx_hash,
         context.user_id::text AS principal_id,
         context.canonical_context,
         version.version
  FROM public.synthetic_context context
  JOIN public.context_versions version
    ON version.ctx_hash = context.ctx_hash
   AND version.canonical_context = context.canonical_context
  WHERE context.ctx_hash = {_quote(expectation.target_context_hash)}
)
SELECT jsonb_build_object(
  'schema_version', {_quote(E10_STATE_OBSERVATION_SCHEMA)},
  'collector_version', {_quote(E10_STATE_COLLECTOR_VERSION)},
  'session_user', session_user,
  'current_user', current_user,
  'search_path', current_setting('search_path'),
  'row_security', current_setting('row_security'),
  'isolation_level', current_setting('transaction_isolation'),
  'snapshot_text', pg_current_snapshot()::text,
  'artifact_id', {_quote(expectation.artifact_id)},
  'physical_relation_oid', to_regclass({_quote(expectation.physical_relation)})::oid::bigint,
  'base_relation_oid', to_regclass({_quote(expectation.base_relation)})::oid::bigint,
  'target_context_principal_id', (SELECT principal_id FROM target_context),
  'target_context_payload', (SELECT canonical_context FROM target_context),
  'target_context_version', (SELECT version FROM target_context),
  'artifact_context_principal_id', (SELECT principal_id FROM artifact_context),
  'artifact_context_payload', (SELECT canonical_context FROM artifact_context),
  'artifact_context_version', (SELECT version FROM artifact_context),
  'current_base_version', (
    SELECT version FROM public.base_versions WHERE relname = {_quote(base_name)}
  ),
  'current_membership_version', (
    SELECT version
    FROM public.membership_versions
    WHERE scope_name = 'group_membership'
  ),
  'dependencies', COALESCE(
    (
      SELECT jsonb_agg(
        jsonb_build_object(
          'dep_kind', dependency.dep_kind,
          'dep_name', dependency.dep_name,
          'version_at_build', dependency.version_at_build
        )
        ORDER BY dependency.dep_kind, dependency.dep_name, dependency.version_at_build
      )
      FROM dependency_rows dependency
    ),
    '[]'::jsonb
  )
)::text;
COMMIT;
"""


def _last_json_object(output: str, *, label: str) -> Mapping[str, Any]:
    for line in reversed(output.splitlines()):
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, Mapping):
            return payload
    raise PostgresError(f"{label} did not emit a JSON object")


def _collect_e10_artifact_state_observation(
    expectation: E10ArtifactStateExpectation,
    pg_env: PostgresEnv,
) -> E10ArtifactStateObservation:
    payload = _last_json_object(
        run_psql_command(
            _e10_artifact_state_observation_sql(expectation),
            pg_env,
        ),
        label="E10 artifact state observation",
    )
    try:
        return _issue_e10_artifact_state_observation(payload)
    except (TypeError, ValueError) as exc:
        raise PostgresError("E10 artifact state observation is malformed") from exc


def _load_manifest(manifest_path: Path) -> Mapping[str, Any]:
    with manifest_path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, Mapping):
        raise ValueError(f"E10 manifest must be an object: {manifest_path}")
    return data


def _dataset_record_from_manifest(
    manifest_path: Path, manifest: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    source = manifest if manifest is not None else _load_manifest(manifest_path)
    dataset = source.get("dataset") if isinstance(source, Mapping) else {}
    if not isinstance(dataset, Mapping):
        dataset = {}
    return {
        "name": str(dataset.get("name", "synthetic_saas")),
        "scale": str(dataset.get("scale", "1e5")),
        "seed": int(dataset.get("seed", 52)),
    }


def _context_ids_from_manifest(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    raw_contexts = manifest.get("contexts", ("ctx_000001",))
    if raw_contexts is None:
        raw_contexts = ("ctx_000001",)
    if not isinstance(raw_contexts, (list, tuple)):
        raise ValueError("E10 contexts must be a list of context ids")
    context_ids: list[str] = []
    for item in raw_contexts:
        if isinstance(item, Mapping):
            context_id = str(item.get("context_id") or item.get("id") or "")
        else:
            context_id = str(item)
        if not context_id:
            raise ValueError("E10 contexts contain an empty context id")
        context_ids.append(context_id)
    if not context_ids:
        raise ValueError("E10 manifest must contain at least one context")
    if len(set(context_ids)) != len(context_ids):
        raise ValueError(f"E10 contexts contain duplicates: {context_ids}")
    return tuple(context_ids)


def _identifier_suffix(value: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in value).strip("_") or "context"


def _artifact_ids_for_context(relname: str, context_id: str) -> dict[str, str]:
    suffix = _identifier_suffix(context_id)
    return {
        "auth": f"e10_{relname}_auth_idx_{suffix}",
        "keyed": f"e10_{relname}_auth_idx_keyed_{suffix}",
        "mav": f"e10_{relname}_mav_{suffix}",
    }


def _e10_negative_state_identifiers(
    case_query_id: str,
    context_id: str,
) -> tuple[str, str]:
    if case_query_id not in E10_NEGATIVE_STATE_KIND_BY_QUERY:
        raise ValueError(f"E10 case has no catalog-state lifecycle: {case_query_id}")
    identity = _canonical_digest(
        {"case_query_id": case_query_id, "context_id": context_id}
    ).removeprefix("sha256:")[:16]
    return (
        f"e10-state:{case_query_id}:{context_id}:{identity}",
        f"public.e10_state_mav_{identity}",
    )


def _e10_state_contexts_sql(context_id: str) -> str:
    return f"""
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL search_path TO pg_catalog, public;
SET LOCAL row_security = on;
WITH target AS MATERIALIZED (
  SELECT context.context_id,
         context.ctx_hash,
         context.user_id::text AS principal_id,
         context.canonical_context,
         version.version
  FROM public.synthetic_context context
  JOIN public.context_versions version
    ON version.ctx_hash = context.ctx_hash
   AND version.canonical_context = context.canonical_context
  WHERE context.context_id = {_quote(context_id)}
),
alternate AS MATERIALIZED (
  SELECT context.context_id,
         context.ctx_hash,
         context.user_id::text AS principal_id,
         context.canonical_context,
         version.version
  FROM public.synthetic_context context
  JOIN public.context_versions version
    ON version.ctx_hash = context.ctx_hash
   AND version.canonical_context = context.canonical_context
  WHERE context.context_id <> {_quote(context_id)}
  ORDER BY context.context_id
  LIMIT 1
)
SELECT jsonb_build_object(
  'target', (
    SELECT jsonb_build_object(
      'context_id', context_id,
      'ctx_hash', ctx_hash,
      'principal_id', principal_id,
      'canonical_context', canonical_context,
      'version', version
    )
    FROM target
  ),
  'alternate', (
    SELECT jsonb_build_object(
      'context_id', context_id,
      'ctx_hash', ctx_hash,
      'principal_id', principal_id,
      'canonical_context', canonical_context,
      'version', version
    )
    FROM alternate
  )
)::text;
COMMIT;
"""


def _parse_e10_state_context(payload: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise PostgresError(f"{label} context is missing")
    _strict_e10_state_keys(
        payload,
        {"context_id", "ctx_hash", "principal_id", "canonical_context", "version"},
        label=label,
    )
    version = payload["version"]
    if not isinstance(version, int) or isinstance(version, bool) or version < 0:
        raise PostgresError(f"{label}.version is invalid")
    canonical_context = payload["canonical_context"]
    if not isinstance(canonical_context, Mapping):
        raise PostgresError(f"{label}.canonical_context is invalid")
    principal_id = _strict_e10_state_string(
        payload,
        "principal_id",
        label=label,
    )
    if str(canonical_context.get("user_id")) != principal_id:
        raise PostgresError(f"{label}.canonical_context principal mismatch")
    return {
        "context_id": _strict_e10_state_string(
            payload,
            "context_id",
            label=label,
        ),
        "ctx_hash": _strict_e10_state_string(
            payload,
            "ctx_hash",
            label=label,
        ),
        "principal_id": principal_id,
        "canonical_context": dict(canonical_context),
        "version": version,
    }


def _load_e10_state_contexts(
    context_id: str,
    pg_env: PostgresEnv,
) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = _last_json_object(
        run_psql_command(_e10_state_contexts_sql(context_id), pg_env),
        label="E10 state context lookup",
    )
    _strict_e10_state_keys(payload, {"target", "alternate"}, label="state_contexts")
    return (
        _parse_e10_state_context(payload["target"], label="target_context"),
        _parse_e10_state_context(payload["alternate"], label="alternate_context"),
    )


def _e10_negative_state_spec(
    root: Path,
    case: E10Case,
    context_id: str,
    pg_env: PostgresEnv,
) -> E10NegativeStateSpec:
    state_kind = E10_NEGATIVE_STATE_KIND_BY_QUERY.get(case.query_id)
    if state_kind is None:
        raise ValueError(f"E10 case has no negative catalog state: {case.query_id}")
    relname, rid_col, policy_id, alias = _target_for_case(case)
    if relname != "document" or policy_id != "tenant_group":
        raise ValueError(
            "E10 negative catalog states require the document tenant_group target"
        )
    target_context, alternate_context = _load_e10_state_contexts(context_id, pg_env)
    for label, context in (
        ("target", target_context),
        ("alternate", alternate_context),
    ):
        if _canonical_digest(context["canonical_context"]) != context["ctx_hash"]:
            raise PostgresError(f"E10 {label} context semantic digest mismatch")
    build_context = (
        alternate_context if state_kind == "alternate_context" else target_context
    )
    if (
        state_kind == "alternate_context"
        and build_context["ctx_hash"] == target_context["ctx_hash"]
    ):
        raise PostgresError(
            "E10 alternate context does not have a distinct semantic identity"
        )
    policy = _load_policy(root, policy_id)
    exact_predicate = _render_policy_predicate(
        str(policy["exact_sql_template"]),
        alias=alias,
        rid_col=rid_col,
        context=build_context["canonical_context"],
        relname=relname,
    )
    artifact_id, physical_relation = _e10_negative_state_identifiers(
        case.query_id,
        context_id,
    )
    return E10NegativeStateSpec(
        case_query_id=case.query_id,
        state_kind=state_kind,
        relation=relname,
        rid_col=rid_col,
        policy_id=policy_id,
        alias=alias,
        artifact_id=artifact_id,
        physical_relation=physical_relation,
        target_context_id=str(target_context["context_id"]),
        target_context_hash=str(target_context["ctx_hash"]),
        target_principal_id=str(target_context["principal_id"]),
        target_context_payload_json=_canonical_json(
            target_context["canonical_context"]
        ),
        target_context_version=int(target_context["version"]),
        build_context_id=str(build_context["context_id"]),
        build_context_hash=str(build_context["ctx_hash"]),
        build_principal_id=str(build_context["principal_id"]),
        build_context_payload_json=_canonical_json(build_context["canonical_context"]),
        build_context_version=int(build_context["version"]),
        exact_predicate=exact_predicate,
    )


def _run_id_context_prefix(context_id: str) -> str:
    return (
        ""
        if context_id in {"ctx_000001", "e10_saas_case_study"}
        else f"{_identifier_suffix(context_id)}_"
    )


def _validate_manifest(manifest_path: Path, manifest: Mapping[str, Any]) -> None:
    if manifest.get("experiment") != "E10" or manifest.get("execution_tier") != "main":
        raise ValueError("e10-case-study requires an E10 main manifest")
    if manifest.get("stage") != "case_study":
        raise ValueError("e10-case-study requires stage: case_study")

    modes = {normalize_mode_id(str(item)) for item in manifest.get("modes", [])}
    if modes != REQUIRED_MODES:
        raise ValueError(
            "E10 modes do not match runner contract: "
            f"expected {sorted(REQUIRED_MODES)}, got {sorted(modes)}"
        )

    query_paths = {
        str(item.get("query_id")): str(item.get("path"))
        for item in manifest.get("queries", [])
        if isinstance(item, Mapping)
    }
    expected_queries = {case.query_id for case in CASES}
    missing = [
        query_id
        for query_id in expected_queries
        if query_paths.get(query_id) != "workloads/e10/case_study.sql"
    ]
    if missing:
        raise ValueError(
            f"E10 manifest query list does not match case-study queries in {manifest_path}: {missing}"
        )

    case_query_items = [
        item for item in manifest.get("case_queries", []) if isinstance(item, Mapping)
    ]
    case_query_ids = [str(item.get("id")) for item in case_query_items]
    if (
        len(case_query_ids) != len(expected_queries)
        or set(case_query_ids) != expected_queries
    ):
        raise ValueError(
            "E10 case_queries do not match runner contract: "
            f"expected {sorted(expected_queries)}, got {sorted(case_query_ids)}"
        )
    case_by_id = {case.query_id: case for case in CASES}
    choice_mismatches = sorted(
        (
            query_id,
            _expected_contract_choice_for_state(case_by_id[query_id]),
            str(item.get("expected_contract_choice")),
        )
        for item, query_id in zip(case_query_items, case_query_ids)
        if str(item.get("expected_contract_choice"))
        != _expected_contract_choice_for_state(case_by_id[query_id])
    )
    if choice_mismatches:
        rendered = ", ".join(
            f"{query_id}: expected {expected}, got {actual}"
            for query_id, expected, actual in choice_mismatches
        )
        raise ValueError(
            "E10 case_queries expected_contract_choice does not match declared "
            f"state semantics: {rendered}"
        )
    _context_ids_from_manifest(manifest)


def _target_for_case(case: E10Case) -> tuple[str, str, str, str]:
    if case.query_id in {
        "E10_Q1_support_ticket_lookup",
        "E10_Q11_ticket_exact_injection",
    }:
        return "ticket", "ticket_id", "tenant_only_ticket", "t"
    if case.query_id == "E10_Q5_invoice_region_purpose_join":
        return "invoice", "invoice_id", "purpose_region_invoice", "i"
    return "document", "doc_id", "tenant_group", "d"


def _mav_metadata_flags(case: E10Case) -> tuple[bool, bool]:
    fresh = case.mav_validity not in {"stale", "revoked"}
    context_matches = case.mav_validity != "wrong_context"
    return fresh, context_matches


def _mav_failure_symbol(case: E10Case) -> tuple[str, str]:
    return {
        "stale": ("stale", "E10_STALE_MAV_ACCEPTED"),
        "revoked": ("stale", "E10_REVOKED_MAV_ACCEPTED"),
        "wrong_context": ("wrong_context", "E10_WRONG_CONTEXT_MAV_ACCEPTED"),
    }.get(case.mav_validity, ("pass", ""))


def _e10_planning_metadata_flags(
    assessment: E10PlanningArtifactAssessment,
) -> dict[str, bool]:
    identity_scope = bool(
        assessment.observed
        and assessment.artifact_identity_matches
        and assessment.dependency_set_complete
        and assessment.policy_matches
        and assessment.principal_matches
    )
    return {
        "fresh": bool(
            assessment.fresh
            and assessment.observed
            and assessment.dependency_set_complete
        ),
        "context_matches": bool(
            assessment.context_matches and assessment.principal_matches
        ),
        "scope_matches": bool(assessment.scope_matches and identity_scope),
        "rid_domain_matches": assessment.rid_domain_matches,
        "base_relation_matches": assessment.base_relation_matches,
        "exact": assessment.exact,
        "keyed": assessment.keyed,
        "key_domain_matches": assessment.key_domain_matches,
    }


def _artifact_metadata_for_case(
    case: E10Case,
    relname: str,
    rid_col: str,
    artifact_ids: Mapping[str, str],
    artifact_rows: Mapping[str, int],
    build_ms: Mapping[str, float],
    storage_bytes: Mapping[str, int],
    *,
    planning_receipt: Optional[E10PlanningReceipt] = None,
    planning_expectation: Optional[E10PlanningExpectation] = None,
    require_production_receipt: bool = False,
) -> dict[str, ArtifactMetadata]:
    assessments: dict[str, E10PlanningArtifactAssessment] = {}
    if planning_receipt is not None or planning_expectation is not None:
        if planning_receipt is None or planning_expectation is None:
            raise PostgresError("E10 artifact metadata evidence is incomplete")
        replay = _replay_e10_planning_receipt(
            planning_receipt,
            planning_expectation,
            require_production=require_production_receipt,
        )
        if not replay.valid:
            raise PostgresError(
                "E10 artifact metadata observation replay failed: "
                + ";".join(replay.reasons)
            )
        expected_ids = {
            "auth": next(
                item.artifact_id
                for item in planning_expectation.artifacts
                if item.kind == "auth_idx"
            ),
            "keyed": next(
                item.artifact_id
                for item in planning_expectation.artifacts
                if item.kind == "auth_idx_keyed"
            ),
            "mav": next(
                item.artifact_id
                for item in planning_expectation.artifacts
                if item.kind == "mav"
            ),
        }
        if dict(artifact_ids) != expected_ids:
            raise PostgresError("E10 artifact observation ID binding mismatch")
        assessments = {
            item.kind: item for item in planning_receipt.artifact_assessments
        }
    else:
        mav_fresh, mav_context_matches = _mav_metadata_flags(case)
        assessments = {
            "auth_idx": E10PlanningArtifactAssessment(
                kind="auth_idx",
                artifact_id=artifact_ids["auth"],
                declared="auth_idx" in case.available_artifacts,
                target_domain=E10_PLANNING_TARGET_DOMAIN,
                observed=True,
                artifact_identity_matches=True,
                dependency_set_complete=True,
                fresh=True,
                context_matches=True,
                scope_matches=True,
                rid_domain_matches=True,
                base_relation_matches=True,
                policy_matches=True,
                principal_matches=True,
                exact=True,
                keyed=False,
                key_domain_matches=True,
                usable="auth_idx" in case.available_artifacts,
                reasons=(),
            ),
            "auth_idx_keyed": E10PlanningArtifactAssessment(
                kind="auth_idx_keyed",
                artifact_id=artifact_ids["keyed"],
                declared="auth_idx_keyed" in case.available_artifacts,
                target_domain=E10_PLANNING_TARGET_DOMAIN,
                observed=True,
                artifact_identity_matches=True,
                dependency_set_complete=True,
                fresh=True,
                context_matches=True,
                scope_matches=True,
                rid_domain_matches=True,
                base_relation_matches=True,
                policy_matches=True,
                principal_matches=True,
                exact=True,
                keyed=True,
                key_domain_matches=True,
                usable="auth_idx_keyed" in case.available_artifacts,
                reasons=(),
            ),
            "mav": E10PlanningArtifactAssessment(
                kind="mav",
                artifact_id=artifact_ids["mav"],
                declared="mav" in case.available_artifacts,
                target_domain=E10_PLANNING_TARGET_DOMAIN,
                observed=True,
                artifact_identity_matches=True,
                dependency_set_complete=True,
                fresh=mav_fresh,
                context_matches=mav_context_matches,
                scope_matches=mav_context_matches,
                rid_domain_matches=True,
                base_relation_matches=True,
                policy_matches=True,
                principal_matches=mav_context_matches,
                exact=True,
                keyed=False,
                key_domain_matches=True,
                usable=(
                    "mav" in case.available_artifacts
                    and mav_fresh
                    and mav_context_matches
                ),
                reasons=(),
            ),
        }
    auth_assessment = assessments["auth_idx"]
    keyed_assessment = assessments["auth_idx_keyed"]
    mav_assessment = assessments["mav"]
    auth_flags = _e10_planning_metadata_flags(auth_assessment)
    keyed_flags = _e10_planning_metadata_flags(keyed_assessment)
    mav_flags = _e10_planning_metadata_flags(mav_assessment)
    auth_rows = case.auth_cardinality_hint or artifact_rows.get("auth")
    artifacts = {
        "auth_idx": ArtifactMetadata(
            kind="auth_idx",
            artifact_id=artifact_ids["auth"],
            fresh=auth_flags["fresh"],
            context_matches=auth_flags["context_matches"],
            rid_domain_matches=auth_flags["rid_domain_matches"],
            base_relation_matches=auth_flags["base_relation_matches"],
            exact=auth_flags["exact"],
            scope_matches=auth_flags["scope_matches"],
            cardinality=auth_rows,
            rows=auth_rows,
            build_ms=build_ms.get("auth", 0.0),
            storage_bytes=storage_bytes.get("auth", 0),
        ),
        "auth_idx_keyed": ArtifactMetadata(
            kind="auth_idx_keyed",
            artifact_id=artifact_ids["keyed"],
            fresh=keyed_flags["fresh"],
            context_matches=keyed_flags["context_matches"],
            rid_domain_matches=keyed_flags["rid_domain_matches"],
            base_relation_matches=keyed_flags["base_relation_matches"],
            exact=keyed_flags["exact"],
            keyed=keyed_flags["keyed"],
            scope_matches=keyed_flags["scope_matches"],
            key_name=rid_col,
            key_domain_matches=keyed_flags["key_domain_matches"],
            supports_equality_key=keyed_flags["key_domain_matches"],
            cardinality=artifact_rows.get("keyed"),
            rows=artifact_rows.get("keyed"),
            build_ms=build_ms.get("keyed", 0.0),
            storage_bytes=storage_bytes.get("keyed", 0),
        ),
        "mav": ArtifactMetadata(
            kind="mav",
            artifact_id=artifact_ids["mav"],
            fresh=mav_flags["fresh"],
            context_matches=mav_flags["context_matches"],
            rid_domain_matches=mav_flags["rid_domain_matches"],
            base_relation_matches=mav_flags["base_relation_matches"],
            exact=mav_flags["exact"],
            scope_matches=mav_flags["scope_matches"],
            cardinality=artifact_rows.get("mav"),
            rows=artifact_rows.get("mav"),
            order_keys=(rid_col,),
            build_ms=build_ms.get("mav", 0.0),
            storage_bytes=storage_bytes.get("mav", 0),
        ),
    }
    return {
        key: value
        for key, value in artifacts.items()
        if key in case.available_artifacts
    }


def _required_artifact_for_template(template_id: str) -> Optional[str]:
    if template_id == "mav_scan_v1":
        return "mav"
    if template_id == "strong_auth_index_keyed_v1":
        return "auth_idx_keyed"
    if template_id in {"auth_index_enum_v1", "hybrid_intersect_v1"}:
        return "auth_idx"
    return None


def _artifact_unavailable_reason(case: E10Case, template_id: str) -> Optional[str]:
    required = _required_artifact_for_template(template_id)
    if required is None or required in case.available_artifacts:
        return None
    return f"artifact_unavailable:{required}"


def _template_unavailable_reason(case: E10Case, template_id: str) -> Optional[str]:
    artifact_reason = _artifact_unavailable_reason(case, template_id)
    if artifact_reason is not None:
        return artifact_reason
    if (
        template_id == "guard_candidate_plus_residual_v1"
        and case.complete_guard_sql_template is None
    ):
        return "contract_reject:policy_has_no_complete_guard"
    return None


def _root_rho_for_case(case: E10Case, rid_col: str) -> dict[str, Any]:
    unsafe_boundary = case.query_id in {
        E10_BARRIER_QUERY_ID,
        E10_GUARD_UNSAFE_STATIC_WITNESS_QUERY_ID,
    }
    rho: dict[str, Any] = {
        "logical_group_id": case.query_id,
        "transparent": not unsafe_boundary,
    }
    if "ordered_export" in case.query_shape:
        rho["required_order"] = (rid_col,)
    if unsafe_boundary:
        rho["unsafe_expression_boundary"] = True
    if case.query_id == "E10_Q6_own_plus_group_shared_union":
        rho["needs_branch_lineage"] = True
    return rho


def _planning_problem_for_case(
    case: E10Case,
    relname: str,
    rid_col: str,
    policy_id: str,
    artifacts: Mapping[str, ArtifactMetadata],
    base_rows: int,
    filtered_rows: int,
    *,
    query_predicate: Optional[str] = None,
    admission_bundle: Optional[E10AdmissionBundle] = None,
) -> PlanningProblem:
    if admission_bundle is not None:
        if not query_predicate or (
            _e10_sql_fragment_digest(query_predicate)
            != admission_bundle.query_predicate_digest
        ):
            raise PostgresError("E10 typed planning query predicate mismatch")
        if (
            admission_bundle.logical_target.relation != relname
            or admission_bundle.logical_target.policy_id != policy_id
            or admission_bundle.logical_target.occurrence_id != case.query_id
        ):
            raise PostgresError("E10 typed planning target mismatch")
    planner_artifacts = dict(artifacts)
    if case.query_shape != "key_lookup":
        planner_artifacts.pop("auth_idx_keyed", None)
    auth_artifact = planner_artifacts.get("auth_idx")
    auth_rows = (
        auth_artifact.cardinality
        if auth_artifact and auth_artifact.cardinality
        else case.row_count
    )
    query_selectivity = min(1.0, max(filtered_rows, 1) / max(base_rows, 1))
    auth_selectivity = min(1.0, max(int(auth_rows or 1), 1) / max(base_rows, 1))
    mav_artifact = planner_artifacts.get("mav")
    if mav_artifact is not None:
        filtered_auth_rows = max(
            1, int(max(filtered_rows, 1) * max(auth_selectivity, 0.000001))
        )
        if "ordered_export" in case.query_shape:
            filtered_auth_rows = min(filtered_auth_rows, max(case.row_count, 1))
        planner_artifacts["mav"] = replace(
            mav_artifact,
            rows=min(
                max(int(mav_artifact.rows or filtered_auth_rows), 1), filtered_auth_rows
            ),
            cardinality=min(
                max(int(mav_artifact.cardinality or filtered_auth_rows), 1),
                filtered_auth_rows,
            ),
        )
    typed_guard = False
    if admission_bundle is not None:
        target_subject = admission_bundle.logical_target.digest
        typed_guard = bool(
            admission_bundle.gamma_snapshot.has_pass(
                "complete_candidate_basis",
                subject_digest=target_subject,
                require_static=True,
            )
            and admission_bundle.gamma_snapshot.has_pass(
                "trusted_exact_residual_executable",
                subject_digest=target_subject,
                require_static=True,
            )
        )
    return PlanningProblem(
        relation=relname,
        policy_id=policy_id,
        occurrence_id=case.query_id,
        rid_col=rid_col,
        required_attrs=(rid_col,),
        required_ctx=("ctx_hash", "user_id"),
        exact_policy_safe=(
            case.exact_policy_safe if admission_bundle is None else False
        ),
        supports_guard=(
            case.complete_guard_sql_template is not None
            if admission_bundle is None
            else typed_guard
        ),
        has_safe_query_predicate=admission_bundle is None,
        gamma_snapshot=(
            None if admission_bundle is None else admission_bundle.gamma_snapshot
        ),
        logical_target=(
            None if admission_bundle is None else admission_bundle.logical_target
        ),
        implementation_target_bindings=(
            ()
            if admission_bundle is None
            else admission_bundle.implementation_target_bindings
        ),
        query_predicate=query_predicate,
        planning_execution_class=(
            "production_normal" if admission_bundle is not None else "diagnostic_only"
        ),
        require_typed_admission=admission_bundle is not None,
        artifacts=planner_artifacts,
        parent_requirement=(
            ParentRequirement()
            if admission_bundle is None
            else admission_bundle.parent_requirement
        ),
        cost_inputs=CostInputs(
            estimated_rows=max(base_rows, 1),
            query_selectivity=query_selectivity,
            auth_selectivity=auth_selectivity,
            guard_selectivity=max(auth_selectivity, query_selectivity),
            scan_cost_per_row=0.00003,
            # E10 barrier/guard/hybrid SQL uses MATERIALIZED CTE stages, so the
            # heuristic pre-rank charges the same write+rescan row surcharge.
            materialize_cost_per_row=0.00003,
            # Keep the heuristic conservative. The executable residual may
            # discharge a conjunct already proved by the complete guard, but
            # it is never charged as cheaper learned/calibrated work.
            residual_eval_cost=0.003,
            sort_cost=2.0 if "ordered_export" in case.query_shape else 0.0,
        ),
    )


def _text_digest(payload: str) -> str:
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _residual_predicate_for_alias(exact_predicate: str, alias: str) -> str:
    return exact_predicate.replace(f"{alias}.", "rcheck.")


def _residual_after_complete_guard(
    exact_predicate: str,
    complete_guard_predicate: str,
) -> str:
    """Remove a syntactically identical leading guard conjunct.

    The complete guard has already established this conjunct for every row in
    the materialized candidate relation. Removing only an exact textual match
    is fail-closed: compound or differently rendered policies retain the full
    exact predicate.
    """

    exact = exact_predicate.strip()
    guard = complete_guard_predicate.strip()
    prefix = f"({guard} AND "
    if exact.startswith(prefix) and exact.endswith(")"):
        residual = exact[len(prefix) : -1].strip()
        if residual:
            return residual
    return exact


def _e10_strict_artifact_contract(
    receipt: E10PlanningReceipt,
    bundle: E10AdmissionBundle,
) -> tuple[
    dict[str, StrictArtifactExpectation],
    tuple[tuple[str, str, str], ...],
]:
    """Derive strict H2 expectations only from replayed E10 evidence.

    E10's admission fact binds a larger catalog observation than the generic
    strict expectation format.  This finite projection retains each H2
    component and is coupled back to the exact admission-fact digest by the
    owner-bound production registry scope.
    """

    observation_by_artifact = {
        item.artifact_id: item for item in receipt.observation.artifacts
    }
    usable_artifact_ids = {
        item.artifact_id
        for item in receipt.artifact_assessments
        if item.declared and item.observed and item.usable
    }
    fact_by_artifact: dict[str, GammaFact] = {}
    for fact in bundle.gamma_snapshot.facts:
        if fact.kind != "artifact_validation" or not fact.accepted:
            continue
        if fact.subject_digest in fact_by_artifact:
            raise PostgresError("E10 strict artifact fact identity is ambiguous")
        fact_by_artifact[fact.subject_digest] = fact
    if set(fact_by_artifact) != usable_artifact_ids:
        raise PostgresError("E10 strict artifact fact inventory is incomplete")

    expectations: dict[str, StrictArtifactExpectation] = {}
    bindings: list[tuple[str, str, str]] = []
    required_dependency_kinds = (
        "base",
        "context_scope",
        "membership",
        "policy",
        "rid_domain",
    )
    for artifact_id in sorted(usable_artifact_ids):
        observation = observation_by_artifact.get(artifact_id)
        if observation is None:
            raise PostgresError("E10 strict artifact observation is missing")
        dependency_by_kind: dict[str, E10ArtifactDependencyState] = {}
        for dependency in observation.dependencies:
            if dependency.dep_kind not in required_dependency_kinds:
                continue
            if dependency.dep_kind in dependency_by_kind:
                raise PostgresError(
                    "E10 strict artifact dependency identity is ambiguous"
                )
            dependency_by_kind[dependency.dep_kind] = dependency
        if tuple(sorted(dependency_by_kind)) != tuple(
            sorted(required_dependency_kinds)
        ):
            raise PostgresError(
                "E10 strict artifact dependency projection is incomplete"
            )
        typed_dependencies = tuple(
            ArtifactDependencyExpectation(
                dependency.dep_kind,
                dependency.dep_name,
                dependency.version_at_build,
            )
            for dependency in dependency_by_kind.values()
        ) + (
            ArtifactDependencyExpectation(
                "execution_snapshot",
                bundle.snapshot_id,
                0,
            ),
        )
        identity_by_kind = {
            item.dep_kind: ArtifactDependencyIdentity(
                item.dep_kind,
                item.dep_name,
            )
            for item in typed_dependencies
        }
        expectation = StrictArtifactExpectation(
            dependencies=typed_dependencies,
            component_bindings=(
                ArtifactComponentBinding(
                    "freshness",
                    tuple(
                        identity_by_kind[kind]
                        for kind in ("base", "membership", "policy")
                    ),
                ),
                ArtifactComponentBinding(
                    "context",
                    (identity_by_kind["context_scope"],),
                ),
                ArtifactComponentBinding(
                    "snapshot",
                    (identity_by_kind["execution_snapshot"],),
                ),
                ArtifactComponentBinding(
                    "trusted_read",
                    tuple(identity_by_kind[kind] for kind in ("membership", "policy")),
                ),
                ArtifactComponentBinding(
                    "rid_materialization",
                    (identity_by_kind["rid_domain"],),
                ),
            ),
        )
        fact = fact_by_artifact[artifact_id]
        expectations[artifact_id] = expectation
        bindings.append((artifact_id, expectation.digest, fact.evidence_digest))
    return expectations, tuple(sorted(bindings))


def _emit_context_for_case(
    case: E10Case,
    problem: PlanningProblem,
    *,
    alias: str = "d",
    exact_predicate: str | None = None,
    guard_predicate: str | None = None,
    query_predicate: str | None = None,
    artifact_relations: Optional[Mapping[str, str]] = None,
    strict_artifact_expectations: Optional[
        Mapping[str, StrictArtifactExpectation]
    ] = None,
    planning_expectation: E10PlanningExpectation | None = None,
) -> EmitContext:
    template_user_id = "e10_planning_user"
    template_context_hash = "sha256:e10_planning_ctx"
    if planning_expectation is not None:
        relname, rid_col, policy_id, expected_alias = _target_for_case(case)
        expected_query_predicate = _e10_planning_query_predicate(
            case,
            expected_alias,
            rid_col,
        )
        if (
            planning_expectation.__class__ is not E10PlanningExpectation
            or planning_expectation.case_query_id != case.query_id
            or planning_expectation.occurrence_id != case.query_id
            or problem.occurrence_id != planning_expectation.occurrence_id
            or planning_expectation.relation_name != relname
            or problem.relation != relname
            or planning_expectation.rid_col != rid_col
            or problem.rid_col != rid_col
            or planning_expectation.policy_id != policy_id
            or problem.policy_id != policy_id
            or alias != expected_alias
            or exact_predicate is None
            or exact_predicate != planning_expectation.exact_predicate
            or _e10_sql_fragment_digest(exact_predicate)
            != planning_expectation.exact_predicate_digest
            or query_predicate is None
            or query_predicate != expected_query_predicate
            or _e10_sql_fragment_digest(query_predicate)
            != planning_expectation.query_predicate_digest
        ):
            raise PostgresError("E10 expectation-owned lowering identity mismatch")
        template_user_id = planning_expectation.principal_id
        template_context_hash = planning_expectation.context_hash
    effective_exact = exact_predicate or f"{alias}.tenant_id = 1"
    effective_guard = guard_predicate or effective_exact
    effective_query = query_predicate or effective_exact
    residual_id = f"{problem.policy_id}:exact_residual"
    effective_residual = _residual_after_complete_guard(
        effective_exact,
        effective_guard,
    )
    residual_predicate = _residual_predicate_for_alias(effective_residual, alias)
    artifact_ids = {
        kind: artifact.artifact_id for kind, artifact in problem.artifacts.items()
    }
    physical_relations = dict(artifact_relations or {})
    return EmitContext(
        default_rid_col=problem.rid_col,
        occurrence_relations={problem.occurrence_id: problem.relation},
        occurrence_aliases={problem.occurrence_id: alias},
        occurrence_rid_cols={problem.occurrence_id: problem.rid_col},
        exact_predicates={problem.occurrence_id: effective_exact},
        query_predicates={problem.occurrence_id: effective_query},
        guard_predicates={problem.occurrence_id: effective_guard},
        residual_predicates={
            residual_id: residual_predicate,
            f"{problem.occurrence_id}:{residual_id}": residual_predicate,
        },
        artifact_expectations=(
            dict(strict_artifact_expectations)
            if strict_artifact_expectations is not None
            else {
                artifact.artifact_id: {
                    "policy_id": problem.policy_id,
                    "context_predicate": "ctx_hash_matches_current_context",
                }
                for artifact in problem.artifacts.values()
            }
        ),
        template_params={
            problem.occurrence_id: {
                "carrier_columns": (
                    problem.rid_col,
                    *E10_EXTRA_HIDDEN_CARRIERS.get(case.query_id, ()),
                ),
                "artifact_ids": artifact_ids,
                "policy_id": problem.policy_id,
                "user_id": template_user_id,
                "ctx_hash": template_context_hash,
                "rid_domain_id": f"{problem.relation}.{problem.rid_col}",
                "base_rel_oid": f"public.{problem.relation}",
                "mav_relation": physical_relations.get(
                    "mav",
                    artifact_ids.get("mav", "mav_document_scope"),
                ),
                "mav_query_predicate": "true",
                "key_name": problem.rid_col,
                "key_predicate": (f"a.key_value = {alias}.{problem.rid_col}::text"),
            }
        },
        unsafe_log_params=(
            {
                f"{case.query_id}:audit": {
                    "event": "e10",
                    "query_id": case.query_id,
                    "label": "barrier_exact",
                    "occurrence_id": problem.occurrence_id,
                    "rid_expr": "unsafe_src.__rid",
                    "secret_expr": "unsafe_src.secret",
                }
            }
            if case.query_id
            in {E10_BARRIER_QUERY_ID, E10_GUARD_UNSAFE_STATIC_WITNESS_QUERY_ID}
            else {}
        ),
    )


def _planning_query_for_case(
    case: E10Case,
    *,
    problem: PlanningProblem,
    mode: str,
    alias: str = "d",
    exact_predicate: str | None = None,
    complete_guard_predicate: str | None = None,
    query_predicate: str | None = None,
    artifact_relations: Optional[Mapping[str, str]] = None,
    strict_artifact_expectations: Optional[
        Mapping[str, StrictArtifactExpectation]
    ] = None,
    planning_expectation: E10PlanningExpectation | None = None,
) -> PlanningQuery:
    hidden_carriers = _e10_required_hidden_carriers(case)
    protected_source: Any = ScanProtected(problem.occurrence_id, "chosen")
    if case.query_id == E10_BARRIER_QUERY_ID:
        protected_source = Select(
            protected_source,
            pred=_e10_planning_query_predicate(
                case,
                "sel",
                problem.rid_col,
            ),
            pred_kind="logical_target",
            expr_label=f"{case.query_id}:base_filter",
        )
    source = Project(
        protected_source,
        visible_A=(problem.rid_col,),
        hidden_H=hidden_carriers,
    )
    if case.query_id in {
        E10_BARRIER_QUERY_ID,
        E10_GUARD_UNSAFE_STATIC_WITNESS_QUERY_ID,
    }:
        source = UnsafeExpr(source, expr_label=f"{case.query_id}:audit")
    return PlanningQuery(
        ir_skeleton=Root(
            source,
            rho_root=_root_rho_for_case(case, problem.rid_col),
        ),
        occurrence_goals={
            problem.occurrence_id: OccurrenceGoal(problem, mode=mode),
        },
        mode=mode,
        emit_context=_emit_context_for_case(
            case,
            problem,
            alias=alias,
            exact_predicate=exact_predicate,
            guard_predicate=complete_guard_predicate,
            query_predicate=query_predicate,
            artifact_relations=artifact_relations,
            strict_artifact_expectations=strict_artifact_expectations,
            planning_expectation=planning_expectation,
        ),
    )


def _e10_required_hidden_carriers(case: E10Case) -> tuple[str, ...]:
    return tuple(sorted((*E10_EXTRA_HIDDEN_CARRIERS.get(case.query_id, ()), "__rid")))


def _e10_continuation_spec(
    case: E10Case,
    expectation: E10PlanningExpectation,
) -> ContinuationSpec:
    if case.query_id in {
        "E10_Q2_tenant_dashboard",
        "E10_Q8_stale_dashboard_mav",
    }:
        result_mode = "singleton_typed_scalar_set"
        result_columns = (
            TypedRootSchemaColumn(0, "authorized_count", "bigint", False),
        )
    else:
        result_mode = (
            "ordered_sequence"
            if case.query_id
            in {"E10_Q7_ordered_export", "E10_Q10_revoked_membership_mav"}
            else "typed_rid_set"
        )
        result_columns = (
            TypedRootSchemaColumn(
                0,
                expectation.rid_col,
                "bigint",
                False,
            ),
        )
    ordered_keys = (
        (f"d.{expectation.rid_col} ASC",) if result_mode == "ordered_sequence" else ()
    )
    row_limit = 1000 if result_mode == "ordered_sequence" else None
    return _mint_source_controlled_continuation_spec(
        spec_id="e10-semantic-result-v1:" + case.query_id,
        query_id=case.query_id,
        policy_id=expectation.policy_id,
        renderer_id="e10-finite-semantic-continuation-renderer",
        renderer_version="v1",
        result_mode=result_mode,
        required_hidden_carriers=_e10_required_hidden_carriers(case),
        result_columns=result_columns,
        ordered_keys=ordered_keys,
        row_limit=row_limit,
        continuation_sql=_e10_semantic_continuation_sql(case, expectation),
    )


def _e10_bound_runner_sql(
    case: E10Case,
    strict: StrictPlanningResult,
    expectation: E10PlanningExpectation,
) -> str:
    try:
        return _compose_exact_bound_runner_sql(
            strict,
            _e10_semantic_continuation_sql(case, expectation),
        )
    except ValueError as exc:
        raise PostgresError("E10 bound runner composition failed") from exc


def _e10_semantic_continuation_sql(
    case: E10Case,
    expectation: E10PlanningExpectation,
) -> str:
    """Return one finite continuation that never reads the protected base."""

    rid_col = expectation.rid_col
    filter_sql = _base_filter(case, "d", rid_col)
    if case.query_id in {
        "E10_Q2_tenant_dashboard",
        "E10_Q8_stale_dashboard_mav",
    }:
        return (
            "\nSELECT count(*)::bigint AS authorized_count\n"
            + "FROM caprls_access_root AS d\nWHERE "
            + filter_sql
        )
    if case.query_id == "E10_Q6_own_plus_group_shared_union":
        return f""",
caprls_branch_tagged AS MATERIALIZED (
  SELECT d.{rid_col} AS branch_rid, 'own'::text AS branch_tag
  FROM caprls_access_root AS d
  WHERE d.owner_id = {_quote(expectation.principal_id)}::bigint
  UNION ALL
  SELECT d.{rid_col} AS branch_rid, 'shared'::text AS branch_tag
  FROM caprls_access_root AS d
  JOIN public.share_acl AS a
    ON a.rid = d.{rid_col} AND a.relname = 'document'
  WHERE a.permission IN ('read', 'owner')
)
SELECT DISTINCT branch_rid AS {rid_col}
FROM caprls_branch_tagged""".rstrip()
    if case.query_id == "E10_Q5_invoice_region_purpose_join":
        return f"""
SELECT DISTINCT d.{rid_col} AS {rid_col}
FROM caprls_access_root AS d
JOIN public.user_account AS u ON u.user_id = d.account_id
WHERE {filter_sql}""".rstrip()
    if case.query_id in {
        "E10_Q7_ordered_export",
        "E10_Q10_revoked_membership_mav",
    }:
        return f"""
SELECT d.{rid_col} AS {rid_col}
FROM caprls_access_root AS d
ORDER BY d.{rid_col}
LIMIT 1000""".rstrip()
    return f"""
SELECT DISTINCT d.{rid_col} AS {rid_col}
FROM caprls_access_root AS d
WHERE {filter_sql}""".rstrip()


def _e10_describe_bound_runner_result(
    session: PostgresTransactionSession,
    *,
    continuation: ContinuationSpec,
    runner_sql: str,
) -> tuple[TypedRootSchemaColumn, ...]:
    schema_probe = (
        "SELECT * FROM (\n" + runner_sql + "\n) AS caprls_e10_bound_runner_schema_probe"
    )
    description = session._describe_result_columns_without_execution(schema_probe)
    rows = tuple(
        tuple(part.strip() for part in line.split("|", 1))
        for line in description.splitlines()
        if line.strip()
    )
    expected = continuation.result_columns
    if (
        len(rows) != len(expected)
        or any(len(row) != 2 for row in rows)
        or tuple(row[0] for row in rows) != tuple(item.name for item in expected)
        or tuple(row[1] for row in rows) != tuple(item.type_name for item in expected)
    ):
        raise PostgresError("E10 bound runner result schema contract mismatch")
    return expected


def _query_plan_payload(
    query_result: QueryPlanResult,
    planning_receipt: Optional[E10PlanningReceipt] = None,
    planning_admission_bundle: Optional[E10AdmissionBundle] = None,
) -> dict[str, Any]:
    payload = query_result.to_dict()
    emitted_sql = query_result.emitted_sql or ""
    payload["ok"] = query_result.ok
    payload["occurrence_ids"] = sorted(query_result.occurrence_results)
    payload["disabled_components"] = []
    payload["certificate_suppressed"] = False
    payload["emitted_sql"] = emitted_sql
    payload["emitted_sql_hash"] = _text_digest(emitted_sql) if emitted_sql else None
    if planning_receipt is not None:
        payload["planning_receipt"] = planning_receipt.to_dict()
        payload["planning_receipt_digest"] = planning_receipt.receipt_digest
    if planning_admission_bundle is not None:
        payload["planning_admission_bundle"] = planning_admission_bundle.to_dict()
        payload[
            "planning_admission_bundle_digest"
        ] = planning_admission_bundle.bundle_digest
    return payload


E10_RAWPG_RANKER_NAME = "pg-explain-raw"
E10_RAWPG_COST_MODEL_VERSION = "pg_explain_raw_v1"
E10_PRODUCTION_ROOT_COST_MODEL_VERSION = (
    "e10_bound_runner_explain_plus_candidate_access_v3"
)
E10_PRODUCTION_ROOT_EXECUTION_SCOPE = "exact_bound_semantic_runner"
E10_PRODUCTION_ROOT_EXECUTION_STATUS = "planning_bound_f2_runtime_pending"
E10_PRODUCTION_ROOT_EXECUTION_BLOCK_REASON = (
    "exact_runner_is_planning_bound_but_runtime_measurement_f2_is_pending"
)
E10_PRODUCTION_PLANNING_GUCS = {
    "row_security": "on",
    "jit": "off",
    "max_parallel_workers_per_gather": "0",
    "plan_cache_mode": "force_custom_plan",
}

# Maps template_id -> (pg_total_cost, prospective diagnostics) or None when no
# prospective EXPLAIN evidence is available for that candidate.
E10ExplainCostFn = Callable[[str], Optional[tuple[float, Mapping[str, Any]]]]


def _e10_query_key_cardinality(
    case: E10Case,
    problem: PlanningProblem,
) -> Optional[int]:
    """Return a prospective key-candidate count when the query declares one.

    The count is derived from the pre-selection query cardinality already held
    by ``PlanningProblem``.  It is deliberately unavailable for non-key query
    shapes, so the cost model cannot manufacture a hybrid advantage merely
    from a query label or from a post-execution measurement.
    """

    if case.query_shape != "key_lookup":
        return None
    protected_rows = max(int(problem.cost_inputs.estimated_rows), 1)
    selectivity = float(problem.cost_inputs.query_selectivity)
    if not math.isfinite(selectivity) or selectivity < 0.0:
        return None
    return max(
        1,
        min(
            protected_rows,
            int(round(protected_rows * selectivity)),
        ),
    )


def _e10_candidate_access_adjusted_cost(
    template_id: str,
    pg_total_cost: float,
    *,
    problem: PlanningProblem,
    query_key_cardinality: Optional[int],
) -> float:
    """Add the candidate-fetch work omitted by a plain bound-runner EXPLAIN.

    AuthorizationIndexSeek exposes every RID in the current-context artifact
    to a possible base-row fetch before the ordinary key predicate can reduce
    the logical candidate stream.  HybridIndexIntersect limits those fetches
    to the intersection with the independently known key candidates, while
    paying for its two materialized inputs.  PostgreSQL's plan cost remains
    the base estimate; this small structural term only distinguishes those two
    access paths when both cardinalities are available before execution.
    """

    raw_cost = float(pg_total_cost)
    if (
        not math.isfinite(raw_cost)
        or raw_cost < 0.0
        or query_key_cardinality is None
        or template_id not in {"auth_index_enum_v1", "hybrid_intersect_v1"}
    ):
        return raw_cost
    auth_artifact = problem.artifacts.get("auth_idx")
    if auth_artifact is None:
        return raw_cost
    context_rows_value = (
        auth_artifact.cardinality
        if auth_artifact.cardinality is not None
        else auth_artifact.rows
    )
    if context_rows_value is None:
        return raw_cost
    context_rows = max(int(context_rows_value), 1)
    key_rows = max(int(query_key_cardinality), 1)
    if key_rows >= context_rows:
        return raw_cost

    costs = problem.cost_inputs
    if template_id == "auth_index_enum_v1":
        # Only the rows excluded by the independent key candidate set are
        # additional fetches relative to the hybrid intersection.
        return raw_cost + (context_rows - key_rows) * costs.base_fetch_cost

    materialized_input_rows = context_rows + key_rows
    return raw_cost + key_rows * costs.scan_cost_per_row + (
        materialized_input_rows * costs.materialize_cost_per_row
    )


def _e10_plan_result_identity_digest(plan_result: PlanResult) -> str:
    if plan_result.__class__ is not PlanResult:
        raise PostgresError("E10 production plan result type is invalid")
    return _canonical_digest(
        {
            "schema": "e10_production_plan_result_identity_v1",
            "plan_result": plan_result.to_dict(),
        }
    )


def _register_e10_production_plan_lineage(
    plan_result: PlanResult,
    query_plan: Mapping[str, Any],
) -> None:
    query_plan_digest = _require_e10_production_query_plan_source(query_plan)
    registered = _REGISTERED_E10_PRODUCTION_QUERY_PLANS[id(query_plan)]
    if (
        plan_result.chosen_template is None
        or plan_result.chosen_template.template_id != registered[5]
    ):
        raise PostgresError("E10 production plan lineage changed selected root")
    _REGISTERED_E10_PRODUCTION_PLAN_LINEAGE[id(plan_result)] = (
        plan_result,
        query_plan,
        query_plan_digest,
        _e10_plan_result_identity_digest(plan_result),
    )


def _require_e10_production_plan_lineage(
    plan_result: PlanResult,
    query_plan: Mapping[str, Any],
) -> None:
    query_plan_digest = _require_e10_production_query_plan_source(query_plan)
    registered = _REGISTERED_E10_PRODUCTION_PLAN_LINEAGE.get(id(plan_result))
    if (
        registered is None
        or registered[0] is not plan_result
        or registered[1] is not query_plan
        or registered[2] != query_plan_digest
        or registered[3] != _e10_plan_result_identity_digest(plan_result)
    ):
        raise PostgresError(
            "E10 production plan result lacks sealed query-plan lineage"
        )


def _require_e10_query_plan_owner_batch_sources(
    query_plan: Mapping[str, Any],
    *,
    owner: _E10ProductionPlanningOwner,
    batch: PlanningEvidenceBatch,
) -> None:
    owner_identity = _require_e10_production_planning_owner(owner)
    _require_registered_batch(batch)
    if any(
        root.bound_runner.case_owner_identity_digest != owner_identity
        for root in batch.roots
    ):
        raise PostgresError(
            "E10 production planning batch contains a foreign owner-bound runner"
        )
    receipt_payload = query_plan.get("planning_receipt")
    if (
        receipt_payload.__class__ is not dict
        or receipt_payload != owner.receipt.to_dict()
        or query_plan.get("planning_receipt_digest") != owner.receipt.receipt_digest
    ):
        raise PostgresError(
            "E10 production query-plan planning receipt differs from its registered owner"
        )
    bundle_payload = query_plan.get("planning_admission_bundle")
    if (
        bundle_payload.__class__ is not dict
        or bundle_payload != owner.bundle.to_dict()
        or query_plan.get("planning_admission_bundle_digest")
        != owner.bundle.bundle_digest
    ):
        raise PostgresError(
            "E10 production query-plan admission bundle differs from its registered owner"
        )


def _register_e10_production_query_plan(
    query_plan: dict[str, Any],
    *,
    owner: _E10ProductionPlanningOwner,
    batch: PlanningEvidenceBatch,
    selected_plan_id: str,
    plan_result: PlanResult,
) -> None:
    if query_plan.__class__ is not dict or not selected_plan_id:
        raise PostgresError("E10 production query-plan issuance is invalid")
    _require_e10_query_plan_owner_batch_sources(
        query_plan,
        owner=owner,
        batch=batch,
    )
    if query_plan.get("production_planning_batch_digest") != batch.batch_digest:
        raise PostgresError("E10 production query-plan batch identity changed")
    expected_eligibility, completed_roots = _e10_completed_root_eligibility_payload(
        batch
    )
    if query_plan.get("production_completed_root_eligibility") != expected_eligibility:
        raise PostgresError(
            "E10 production query-plan eligibility differs from its batch"
        )
    selected_roots = tuple(
        root for root in batch.roots if root.plan_id == selected_plan_id
    )
    if len(selected_roots) != 1 or selected_plan_id not in {
        plan_id for _template_id, plan_id in completed_roots
    }:
        raise PostgresError("E10 production query-plan selected root is not unique")
    selected_root = selected_roots[0]
    bound_runner = selected_root.bound_runner
    if query_plan.get("production_bound_runner") != bound_runner.to_dict():
        raise PostgresError("E10 production query-plan bound runner changed")
    expected_cost = {
        "ranker": "public_completed_root_selector",
        "plan_id": selected_plan_id,
        "prospective_total_cost": float(selected_root.prospective_total_cost),
        "cost_model_version": batch.identity.cost_model_version,
        "planning_environment_digest": batch.identity.environment_digest,
    }
    if query_plan.get("production_chosen_cost") != expected_cost:
        raise PostgresError("E10 production chosen cost differs from its batch")
    selected_template = bound_runner.template_id
    audit = query_plan.get("production_root_selection")
    if (
        not isinstance(audit, Mapping)
        or audit.get("chosen_plan_id") != selected_plan_id
        or plan_result.chosen_template is None
        or plan_result.chosen_template.template_id != selected_template
    ):
        raise PostgresError("E10 production selected root changed")
    digest = _canonical_digest(query_plan)
    _REGISTERED_E10_PRODUCTION_QUERY_PLANS[id(query_plan)] = (
        query_plan,
        digest,
        owner,
        batch,
        selected_plan_id,
        selected_template,
        bound_runner,
    )
    _register_e10_production_plan_lineage(plan_result, query_plan)


def _require_e10_production_query_plan_source(
    query_plan: Mapping[str, Any],
) -> str:
    registered = _REGISTERED_E10_PRODUCTION_QUERY_PLANS.get(id(query_plan))
    if (
        registered is None
        or registered[0] is not query_plan
        or registered[1] != _canonical_digest(query_plan)
        or query_plan.get("production_planning_batch_digest")
        != registered[3].batch_digest
        or query_plan.get("production_root_selection", {}).get("chosen_plan_id")
        != registered[4]
        or query_plan.get("production_bound_runner") != registered[6].to_dict()
    ):
        raise PostgresError(
            "E10 production query plan is not the exact unchanged issued source"
        )
    _require_e10_query_plan_owner_batch_sources(
        query_plan,
        owner=registered[2],
        batch=registered[3],
    )
    selected_roots = tuple(
        root for root in registered[3].roots if root.plan_id == registered[4]
    )
    if (
        len(selected_roots) != 1
        or selected_roots[0].bound_runner is not registered[6]
        or registered[6].template_id != registered[5]
    ):
        raise PostgresError("E10 registered query-plan batch identity changed")
    return registered[1]


def _e10_registered_completed_root_for_template(
    query_plan: Mapping[str, Any],
    template_id: str,
) -> Any:
    _require_e10_production_query_plan_source(query_plan)
    registered = _REGISTERED_E10_PRODUCTION_QUERY_PLANS[id(query_plan)]
    matching = tuple(
        root
        for root in registered[3].roots
        if root.bound_runner.template_id == template_id
    )
    if len(matching) != 1:
        raise PostgresError("E10 completed template lacks one registered bound runner")
    return matching[0]


def _e10_production_root_execution_binding_payload() -> dict[str, Any]:
    """Return the exact complete-runner F1 seal with runtime still pending."""

    payload: dict[str, Any] = {
        "schema": "e10_production_root_execution_binding_v2",
        "planner_root_scope": E10_PRODUCTION_ROOT_EXECUTION_SCOPE,
        "status": E10_PRODUCTION_ROOT_EXECUTION_STATUS,
        "planning_root_sql_bound": True,
        "downstream_runner_sql_bound": True,
        "measurement_promotion": False,
        "runtime_body_execution_count": 0,
        "runtime_analyze_execution_count": 0,
        "reason": E10_PRODUCTION_ROOT_EXECUTION_BLOCK_REASON,
    }
    payload["binding_digest"] = _canonical_digest(payload)
    return payload


def _e10_completed_root_eligibility_payload(
    batch: PlanningEvidenceBatch,
) -> tuple[dict[str, Any], tuple[tuple[str, str], ...]]:
    """Project downstream eligibility only from the sealed frontier batch."""

    completed = tuple(
        sorted(
            (item.template_id, str(item.plan_id))
            for item in batch.frontier_entries
            if item.status == "completed_cost_eligible" and item.plan_id is not None
        )
    )
    structural = tuple(
        item.to_dict()
        for item in batch.frontier_entries
        if item.status == "structural_rejection"
    )
    evidence_failures = tuple(
        item.to_dict()
        for item in batch.frontier_entries
        if item.status == "evidence_failure"
    )
    payload: dict[str, Any] = {
        "schema": "e10_production_completed_root_eligibility_v1",
        "planning_batch_digest": batch.batch_digest,
        "completed_roots": [
            {"template_id": template_id, "plan_id": plan_id}
            for template_id, plan_id in completed
        ],
        "structural_rejections": list(structural),
        "evidence_failures": list(evidence_failures),
    }
    payload["eligibility_digest"] = _canonical_digest(payload)
    return payload, completed


def _require_e10_production_root_execution_binding(
    query_plan: Mapping[str, Any],
    *,
    template_id: Optional[str] = None,
) -> tuple[tuple[str, str], ...]:
    """Replay the exact issued complete-runner F1 boundary."""

    if not isinstance(query_plan, Mapping):
        raise PostgresError("E10 production root execution binding is missing")
    _require_e10_production_query_plan_source(query_plan)
    registered_query_plan = _REGISTERED_E10_PRODUCTION_QUERY_PLANS[id(query_plan)]
    expected_binding = _e10_production_root_execution_binding_payload()
    if query_plan.get("production_root_execution_binding") != expected_binding:
        raise PostgresError("E10 production root execution binding changed")
    bound_runner = query_plan.get("production_bound_runner")
    if not isinstance(bound_runner, Mapping):
        raise PostgresError("E10 production bound runner is missing")
    required_runner_keys = {
        "strict_result_identity_seal",
        "plan_id",
        "template_id",
        "query_id",
        "policy_id",
        "case_owner_identity_digest",
        "strict_complete_root_plan_digest",
        "strict_exact_sql_digest",
        "strict_sql_ast_digest",
        "renderer_id",
        "renderer_version",
        "ordered_keys",
        "row_limit",
        "strict_core_sql_digest",
        "continuation_sql_digest",
        "continuation",
        "continuation_digest",
        "result_contract_digest",
        "runner_sql",
        "runner_sql_digest",
        "session_contract_digest",
        "registry_digest",
        "snapshot_digest",
        "database_identity_digest",
        "catalog_digest",
        "planning_environment_digest",
        "identity_digest",
    }
    if set(bound_runner) != required_runner_keys:
        raise PostgresError("E10 production bound runner is malformed")
    continuation = bound_runner.get("continuation")
    runner_sql = bound_runner.get("runner_sql")
    if (
        not isinstance(continuation, Mapping)
        or type(runner_sql) is not str  # noqa: E721
        or not runner_sql
        or bound_runner.get("continuation_digest")
        != _canonical_digest(dict(continuation))
        or bound_runner != registered_query_plan[6].to_dict()
        or bound_runner.get("runner_sql_digest")
        != _canonical_digest({"exact_runner_sql": runner_sql})
        or continuation.get("result_contract_digest")
        != _canonical_digest(
            {
                "result_mode": continuation.get("result_mode"),
                "columns": continuation.get("result_columns"),
                "ordered_keys": continuation.get("ordered_keys"),
                "row_limit": continuation.get("row_limit"),
            }
        )
        or bound_runner.get("renderer_id") != continuation.get("renderer_id")
        or bound_runner.get("renderer_version") != continuation.get("renderer_version")
        or bound_runner.get("ordered_keys") != continuation.get("ordered_keys")
        or bound_runner.get("row_limit") != continuation.get("row_limit")
        or bound_runner.get("continuation_sql_digest")
        != continuation.get("continuation_sql_digest")
        or bound_runner.get("result_contract_digest")
        != continuation.get("result_contract_digest")
        or bound_runner.get("planning_environment_digest")
        != _canonical_digest(
            {
                "session_contract_digest": bound_runner.get("session_contract_digest"),
                "registry_digest": bound_runner.get("registry_digest"),
                "snapshot_digest": bound_runner.get("snapshot_digest"),
                "database_identity_digest": bound_runner.get(
                    "database_identity_digest"
                ),
                "catalog_digest": bound_runner.get("catalog_digest"),
                "case_owner_identity_digest": bound_runner.get(
                    "case_owner_identity_digest"
                ),
            }
        )
    ):
        raise PostgresError("E10 production bound runner SQL or continuation changed")
    identity_keys = (
        "strict_result_identity_seal",
        "plan_id",
        "template_id",
        "query_id",
        "policy_id",
        "case_owner_identity_digest",
        "strict_complete_root_plan_digest",
        "strict_exact_sql_digest",
        "strict_sql_ast_digest",
        "renderer_id",
        "renderer_version",
        "ordered_keys",
        "row_limit",
        "strict_core_sql_digest",
        "continuation_sql_digest",
        "continuation_digest",
        "result_contract_digest",
        "runner_sql_digest",
        "session_contract_digest",
        "registry_digest",
        "snapshot_digest",
        "database_identity_digest",
        "catalog_digest",
    )
    if bound_runner.get("identity_digest") != _canonical_digest(
        {key: bound_runner[key] for key in identity_keys}
    ):
        raise PostgresError("E10 production bound runner identity changed")
    eligibility = query_plan.get("production_completed_root_eligibility")
    if not isinstance(eligibility, Mapping):
        raise PostgresError("E10 production completed-root eligibility is missing")
    required_keys = {
        "schema",
        "planning_batch_digest",
        "completed_roots",
        "structural_rejections",
        "evidence_failures",
        "eligibility_digest",
    }
    if set(eligibility) != required_keys:
        raise PostgresError("E10 production completed-root eligibility is malformed")
    digest_payload = {
        key: eligibility[key] for key in required_keys if key != "eligibility_digest"
    }
    if (
        eligibility["schema"] != "e10_production_completed_root_eligibility_v1"
        or eligibility["eligibility_digest"] != _canonical_digest(digest_payload)
        or eligibility["planning_batch_digest"]
        != query_plan.get("production_planning_batch_digest")
    ):
        raise PostgresError("E10 production completed-root eligibility changed")
    completed_payload = eligibility["completed_roots"]
    structural_payload = eligibility["structural_rejections"]
    evidence_payload = eligibility["evidence_failures"]
    if (
        type(completed_payload) is not list  # noqa: E721
        or type(structural_payload) is not list  # noqa: E721
        or type(evidence_payload) is not list  # noqa: E721
    ):
        raise PostgresError("E10 production completed-root eligibility is untyped")
    completed: list[tuple[str, str]] = []
    for item in completed_payload:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"template_id", "plan_id"}
            or type(item["template_id"]) is not str  # noqa: E721
            or not item["template_id"]
            or type(item["plan_id"]) is not str  # noqa: E721
            or not item["plan_id"]
        ):
            raise PostgresError("E10 production completed-root identity is malformed")
        completed.append((item["template_id"], item["plan_id"]))
    normalized = tuple(sorted(completed))
    if (
        tuple(completed) != normalized
        or len(set(template for template, _plan in normalized)) != len(normalized)
        or len(set(plan for _template, plan in normalized)) != len(normalized)
    ):
        raise PostgresError("E10 production completed-root identity is ambiguous")
    audit = query_plan.get("production_root_selection")
    if not isinstance(audit, Mapping):
        raise PostgresError("E10 production root-selection audit is missing")
    if (
        audit.get("structural_rejections") != structural_payload
        or audit.get("evidence_failures") != evidence_payload
        or audit.get("completed_root_count") != len(normalized)
        or audit.get("frontier_size")
        != len(normalized) + len(structural_payload) + len(evidence_payload)
        or evidence_payload
        or audit.get("chosen_plan_id") not in {plan for _template, plan in normalized}
        or bound_runner.get("plan_id") != audit.get("chosen_plan_id")
        or (
            bound_runner.get("template_id"),
            bound_runner.get("plan_id"),
        )
        not in normalized
    ):
        raise PostgresError("E10 production frontier audit and eligibility differ")
    if template_id is not None and template_id not in {
        template for template, _plan in normalized
    }:
        raise PostgresError(
            "E10 production template is not a completed strict-root member"
        )
    return normalized


def _prospective_pg_cost(sql: str, pg_env: PostgresEnv) -> tuple[float, dict[str, Any]]:
    """Prospective RawPG estimate for one candidate's real measurement SQL.

    Plain EXPLAIN (no ANALYZE): the candidate is never executed, so no rows are
    observed and no measured outcome can leak into the selector.
    """

    explain_sql = (
        "SET jit = off; "
        "SET max_parallel_workers_per_gather = 0; "
        "SET plan_cache_mode = force_custom_plan; "
        "EXPLAIN (FORMAT JSON) " + sql.rstrip().rstrip(";") + ";"
    )
    explain_json = _extract_explain_json(run_psql_command(explain_sql, pg_env))
    plan = explain_json[0].get("Plan", {})
    if not isinstance(plan, Mapping):
        plan = {}
    return float(plan.get("Total Cost", 0.0)), {
        "pg_plan_rows": plan.get("Plan Rows"),
        "plan_hash": _explain_plan_hash(explain_json),
        "explain_prospective": True,
    }


def _rerank_plan_with_pg_explain(
    plan_result: PlanResult,
    *,
    problem: PlanningProblem,
    explain_cost_fn: E10ExplainCostFn,
) -> PlanResult:
    """Re-rank accepted candidates by zero-calibration RawPG EXPLAIN cost.

    Mirrors the promoted E3 ordering: clear stale heuristic pruning marks,
    replace costs with prospective pg_total_cost, re-apply rho-relative
    dominance under the new costs, and choose the argmin among unpruned
    candidates only. Admission is untouched: rejected candidates and their
    ledger reasons pass through unchanged.
    """

    # Raw PostgreSQL costs and the prototype heuristic use different units.
    # Reranking is therefore all-or-nothing across admitted candidates: if one
    # candidate lacks prospective EXPLAIN evidence, retain the original
    # heuristic plan instead of comparing mixed-unit costs.
    explain_evidence_by_template: dict[str, tuple[float, Mapping[str, Any]]] = {}
    for candidate in plan_result.candidates:
        if not candidate.accepted:
            continue
        explain_evidence = explain_cost_fn(candidate.template_id)
        if explain_evidence is None:
            return plan_result
        explain_evidence_by_template[candidate.template_id] = explain_evidence

    if not explain_evidence_by_template:
        return plan_result

    reranked_case = next(
        (case for case in CASES if case.query_id == problem.occurrence_id),
        None,
    )
    query_key_cardinality = (
        None
        if reranked_case is None
        else _e10_query_key_cardinality(reranked_case, problem)
    )
    candidates: list[CandidatePlan] = []
    for candidate in plan_result.candidates:
        unpruned_candidate = replace(candidate, pruned_by_dominance=None)
        if not candidate.accepted:
            candidates.append(unpruned_candidate)
            continue
        explain_evidence = explain_evidence_by_template[candidate.template_id]
        pg_total_cost, prospective = explain_evidence
        adjusted_cost = _e10_candidate_access_adjusted_cost(
            candidate.template_id,
            pg_total_cost,
            problem=problem,
            query_key_cardinality=query_key_cardinality,
        )
        diagnostics = dict(candidate.diagnostics)
        diagnostics.update(
            {
                "diagnostic_kind": "e10_candidate_cost",
                "ranker": E10_RAWPG_RANKER_NAME,
                "cost_model_version": E10_RAWPG_COST_MODEL_VERSION,
                "heuristic_cost": candidate.estimated_cost,
                "pg_total_cost": pg_total_cost,
                "prospective_access_adjusted_cost": adjusted_cost,
                **dict(prospective),
            }
        )
        candidates.append(
            replace(
                unpruned_candidate,
                estimated_cost=float(adjusted_cost),
                diagnostics=diagnostics,
            )
        )
    # RawPG promotion stays zero-calibration: only the rho-required sort
    # enforcer term already present in the heuristic path carries over.
    dominance_cost_inputs = CostInputs(sort_cost=problem.cost_inputs.sort_cost)
    dominance = apply_dominance_pruning(
        candidates,
        problem.parent_requirement,
        cost_inputs=dominance_cost_inputs,
        sort_enforcer_cost=problem.cost_inputs.sort_cost,
    )
    candidates_by_id = {
        candidate.template_id: candidate for candidate in dominance.candidates
    }
    restored_equal_cost = 0
    candidates = []
    for candidate in dominance.candidates:
        dominator = candidates_by_id.get(candidate.pruned_by_dominance or "")
        if dominator is not None:
            candidate_cost = cost_after_enforcers(
                candidate,
                problem.parent_requirement,
                dominance_cost_inputs,
            )
            dominator_cost = cost_after_enforcers(
                dominator,
                problem.parent_requirement,
                dominance_cost_inputs,
            )
            if abs(candidate_cost - dominator_cost) <= 1e-12:
                candidate = replace(candidate, pruned_by_dominance=None)
                restored_equal_cost += 1
        candidates.append(candidate)
    accepted = [
        candidate
        for candidate in candidates
        if candidate.accepted and candidate.pruned_by_dominance is None
    ]

    def rank_key(candidate: CandidatePlan) -> tuple[float, float, str]:
        heuristic_cost = candidate.diagnostics.get("heuristic_cost")
        try:
            heuristic_tie_break = float(heuristic_cost)
        except (TypeError, ValueError):
            heuristic_tie_break = float("inf")
        return (
            cost_after_enforcers(
                candidate,
                problem.parent_requirement,
                dominance_cost_inputs,
            ),
            heuristic_tie_break,
            candidate.template_id,
        )

    chosen = (
        min(
            accepted,
            key=rank_key,
        )
        if accepted
        else None
    )
    return replace(
        plan_result,
        dominance_checks=dominance.checks,
        dominance_pruned=dominance.pruned - restored_equal_cost,
        costed_templates=len(accepted),
        chosen_template=chosen,
        emitted_sql=None if chosen is None else chosen.emitted_sql,
        delivered_sigma={} if chosen is None else chosen.delivered_sigma,
        estimated_cost=None if chosen is None else chosen.estimated_cost,
        candidates=tuple(candidates),
    )


def _assert_e10_planning_receipt_gate(
    *,
    receipt: Optional[E10PlanningReceipt],
    expectation: Optional[E10PlanningExpectation],
    artifacts: Mapping[str, ArtifactMetadata],
    require_production: bool,
    require_complete_inventory: bool = True,
) -> Optional[E10PlanningReplay]:
    if receipt is None or expectation is None:
        if require_production:
            raise PostgresError("E10 production planning receipt is missing")
        return None
    replay = _replay_e10_planning_receipt(
        receipt,
        expectation,
        require_production=require_production,
    )
    if not replay.valid:
        raise PostgresError(
            "E10 planning receipt replay failed before planner entry: "
            + ";".join(replay.reasons)
        )
    if expectation.registry_inventory != _e10_registry_inventory():
        raise PostgresError(
            "E10 planning registry inventory changed before planner entry"
        )
    assessment_by_kind = {item.kind: item for item in receipt.artifact_assessments}
    declared_kinds = {item.kind for item in expectation.artifacts if item.declared}
    actual_kinds = set(artifacts)
    capability_matches = (
        actual_kinds == declared_kinds
        if require_complete_inventory
        else actual_kinds <= declared_kinds
    )
    if not capability_matches:
        raise PostgresError("E10 planner artifact capability inventory mismatch")
    for kind, metadata in artifacts.items():
        assessment = assessment_by_kind.get(kind)
        if assessment is None or not assessment.declared:
            raise PostgresError(
                f"E10 planner artifact {kind} is not declared by the receipt"
            )
        receipt_flags = _e10_planning_metadata_flags(assessment)
        expected_flags = {
            "artifact_id": assessment.artifact_id,
            **receipt_flags,
        }
        actual_flags = {
            "artifact_id": metadata.artifact_id,
            "fresh": metadata.fresh,
            "context_matches": metadata.context_matches,
            "scope_matches": metadata.scope_matches,
            "rid_domain_matches": metadata.rid_domain_matches,
            "base_relation_matches": metadata.base_relation_matches,
            "exact": metadata.exact,
            "keyed": metadata.keyed,
            "key_domain_matches": metadata.key_domain_matches,
        }
        if actual_flags != expected_flags:
            raise PostgresError(
                f"E10 planner artifact {kind} metadata is not receipt-derived"
            )
    return replay


def _assert_e10_admission_bundle_gate(
    *,
    root: Optional[Path],
    case: E10Case,
    bundle: Optional[E10AdmissionBundle],
    receipt: Optional[E10PlanningReceipt],
    expectation: Optional[E10PlanningExpectation],
    require_production: bool,
) -> Optional[E10AdmissionReplay]:
    if bundle is None or receipt is None or expectation is None or root is None:
        if require_production:
            raise PostgresError("E10 production typed admission bundle is missing")
        return None
    replay = _replay_e10_admission_bundle(
        bundle,
        root=root,
        case=case,
        receipt=receipt,
        expectation=expectation,
        require_production=require_production,
    )
    if not replay.valid:
        raise PostgresError(
            "E10 typed admission bundle replay failed before planner entry: "
            + ";".join(replay.reasons)
        )
    if bundle.registry_inventory != _e10_registry_inventory():
        raise PostgresError("E10 typed admission registry inventory changed")
    if tuple(
        item.template_id for item in bundle.implementation_target_bindings
    ) != tuple(item.template_id for item in bundle.registry_inventory):
        raise PostgresError("E10 typed admission binding coverage mismatch")
    for binding in bundle.implementation_target_bindings:
        if (
            binding.implementation_target_kind
            != template_definition(binding.template_id).target_kind
        ):
            raise PostgresError("E10 typed admission target kind mismatch")
    expected_artifact_subjects = {
        item.artifact_id
        for item in receipt.artifact_assessments
        if item.declared and item.observed and item.usable
    }
    actual_artifact_subjects = {
        fact.subject_digest
        for fact in bundle.gamma_snapshot.facts
        if fact.kind == "artifact_validation" and fact.accepted
    }
    if actual_artifact_subjects != expected_artifact_subjects:
        raise PostgresError("E10 typed admission artifact fact inventory mismatch")
    expected_obligations = {
        (kind, artifact_id)
        for artifact_id in expected_artifact_subjects
        for kind in E10_ADMISSION_DYNAMIC_OBLIGATION_KINDS
    }
    actual_obligations = {
        (item.kind, item.artifact_id) for item in bundle.unresolved_dynamic_obligations
    }
    if actual_obligations != expected_obligations:
        raise PostgresError("E10 typed admission dynamic obligation mismatch")
    relname, rid_col, policy_id, _alias = _target_for_case(case)
    target = bundle.logical_target
    if (
        target.relation != relname
        or target.policy_id != policy_id
        or target.occurrence_id != case.query_id
        or target.principal_id != expectation.principal_id
        or target.context_digest != expectation.context_hash
        or target.policy_predicate_digest != expectation.policy_definition_digest
    ):
        raise PostgresError("E10 typed admission logical target mismatch")
    if bundle.parent_requirement != _e10_parent_requirement_for_case(
        case,
        rid_col,
    ):
        raise PostgresError("E10 typed admission rho mismatch")
    return replay


def _assert_e10_admission_lowering_inputs(
    *,
    exact_predicate: Optional[str],
    complete_guard_predicate: Optional[str],
    query_predicate: Optional[str],
    expectation: Optional[E10PlanningExpectation],
    bundle: Optional[E10AdmissionBundle],
    require_production: bool,
) -> None:
    if not require_production:
        return
    if expectation is None or bundle is None:
        raise PostgresError("E10 production lowering identity is missing")
    expected_digests = {
        "exact": expectation.exact_predicate_digest,
        "guard": expectation.guard_predicate_digest,
        "query": expectation.query_predicate_digest,
    }
    bundle_digests = {
        "exact": bundle.exact_predicate_digest,
        "guard": bundle.guard_predicate_digest,
        "query": bundle.query_predicate_digest,
    }
    if bundle_digests != expected_digests:
        raise PostgresError("E10 production lowering evidence identity mismatch")
    if not isinstance(exact_predicate, str) or not exact_predicate.strip():
        raise PostgresError("E10 production exact lowering is missing")
    if exact_predicate != expectation.exact_predicate:
        raise PostgresError("E10 production exact lowering identity mismatch")
    if not isinstance(query_predicate, str) or not query_predicate.strip():
        raise PostgresError("E10 production query lowering is missing")

    no_guard_digest = _e10_sql_fragment_digest(None)
    if expected_digests["guard"] == no_guard_digest:
        if complete_guard_predicate is not None:
            raise PostgresError("E10 production guard lowering identity mismatch")
    elif (
        not isinstance(complete_guard_predicate, str)
        or not complete_guard_predicate.strip()
    ):
        raise PostgresError("E10 production guard lowering is missing")

    actual_digests = {
        "exact": _e10_sql_fragment_digest(exact_predicate),
        "guard": _e10_sql_fragment_digest(complete_guard_predicate),
        "query": _e10_sql_fragment_digest(query_predicate),
    }
    mismatches = sorted(
        kind
        for kind, digest in actual_digests.items()
        if digest != expected_digests[kind]
    )
    if mismatches:
        raise PostgresError(
            "E10 production lowering digest mismatch: " + ",".join(mismatches)
        )


def _assert_e10_typed_problem_identity(
    *,
    problem: PlanningProblem,
    query_predicate: Optional[str],
    expectation: Optional[E10PlanningExpectation],
    bundle: Optional[E10AdmissionBundle],
    require_production: bool,
) -> None:
    if not require_production:
        return
    if expectation is None or bundle is None or query_predicate is None:
        raise PostgresError("E10 production typed problem identity is missing")
    target = bundle.logical_target
    if (
        not problem.require_typed_admission
        or problem.logical_target != target
        or problem.parent_requirement != bundle.parent_requirement
        or problem.gamma_snapshot != bundle.gamma_snapshot
        or problem.implementation_target_bindings
        != bundle.implementation_target_bindings
        or problem.relation != target.relation
        or problem.policy_id != target.policy_id
        or problem.occurrence_id != target.occurrence_id
        or problem.rid_col != expectation.rid_col
        or problem.query_predicate != query_predicate
        or _e10_sql_fragment_digest(problem.query_predicate)
        != bundle.query_predicate_digest
    ):
        raise PostgresError("E10 production typed problem identity mismatch")


def _e10_production_session_contract(
    owner: _E10ProductionPlanningOwner,
) -> SessionContract:
    _require_e10_production_planning_owner(owner)
    return SessionContract(
        role=owner.receipt.observation.current_user,
        search_path=("pg_catalog", "public"),
        gucs=E10_PRODUCTION_PLANNING_GUCS,
        transaction_isolation="repeatable read",
        read_only=True,
    )


def _e10_catalog_select_for_transaction(
    expectation: E10PlanningExpectation,
) -> tuple[str, str]:
    script, collector_digest = _e10_planning_collector_sql(expectation)
    marker = "SELECT jsonb_build_object("
    start = script.find(marker)
    end = script.rfind(";\nCOMMIT;")
    if start < 0 or end <= start:
        raise PostgresError("E10 planning collector transaction shape changed")
    statement = script[start:end].strip()
    if (
        not statement.startswith(marker)
        or "BEGIN" in statement
        or "COMMIT" in statement
    ):
        raise PostgresError("E10 planning collector SELECT extraction failed")
    return statement, collector_digest


def _e10_catalog_static_payload(
    observation: E10PlanningCatalogObservation,
) -> dict[str, Any]:
    payload = observation.to_dict()
    payload.pop("snapshot_text", None)
    payload.pop("observation_digest", None)
    return payload


def _e10_planning_catalog_core_payload(
    observation: E10PlanningCatalogObservation
    | E10SelectedArtifactCatalogObservation,
) -> dict[str, Any]:
    payload = observation.to_dict()
    for key in (
        "schema_version",
        "collector_version",
        "collector_sql_digest",
        "snapshot_text",
        "artifacts",
        "artifact",
        "observation_digest",
    ):
        payload.pop(key, None)
    return payload


def _e10_observe_production_environment(
    session: PostgresTransactionSession,
    *,
    owner: _E10ProductionPlanningOwner,
    pg_env: PostgresEnv,
    session_contract: Optional[SessionContract] = None,
) -> Mapping[str, Any]:
    _require_e10_production_planning_owner(owner)
    if (
        type(pg_env.host) is not str  # noqa: E721
        or not pg_env.host
        or type(pg_env.port) is not int  # noqa: E721
        or isinstance(pg_env.port, bool)
        or not (1 <= pg_env.port <= 65535)
        or type(pg_env.user) is not str  # noqa: E721
        or not pg_env.user
        or type(pg_env.database) is not str  # noqa: E721
        or not pg_env.database
    ):
        raise PostgresError("E10 production PostgreSQL connection target is invalid")
    if owner.receipt.observation.session_user != pg_env.user:
        raise PostgresError(
            "E10 production PostgreSQL session user differs from connection target"
        )
    output = session.execute(
        "SELECT jsonb_build_object("
        "'current_database', current_database(), "
        "'session_user', session_user, "
        "'current_user', current_user, "
        "'search_path', current_setting('search_path'), "
        "'row_security', current_setting('row_security'), "
        "'jit', current_setting('jit'), "
        "'max_parallel_workers_per_gather', "
        "current_setting('max_parallel_workers_per_gather'), "
        "'plan_cache_mode', current_setting('plan_cache_mode'), "
        "'transaction_isolation', current_setting('transaction_isolation'), "
        "'transaction_read_only', current_setting('transaction_read_only'), "
        "'server_version_num', current_setting('server_version_num')"
        ")::text"
    )
    payload = _last_json_object(output, label="E10 production planning environment")
    effective_contract = (
        _e10_production_session_contract(owner)
        if session_contract is None
        else session_contract
    )
    if (
        effective_contract.role != owner.receipt.observation.current_user
        or effective_contract.search_path != ("pg_catalog", "public")
        or effective_contract.transaction_isolation != "repeatable read"
    ):
        raise PostgresError("E10 production environment contract changed")
    expected = {
        "current_database": pg_env.database,
        "session_user": pg_env.user,
        "current_user": owner.receipt.observation.current_user,
        "search_path": "pg_catalog, public",
        "row_security": "on",
        "jit": "off",
        "max_parallel_workers_per_gather": "0",
        "plan_cache_mode": "force_custom_plan",
        "transaction_isolation": "repeatable read",
        "transaction_read_only": "on" if effective_contract.read_only else "off",
    }
    mismatches = tuple(
        sorted(key for key, value in expected.items() if payload.get(key) != value)
    )
    if mismatches or not str(payload.get("server_version_num", "")):
        raise PostgresError(
            "E10 production planning environment drift: "
            + ",".join(mismatches or ("server_version_num",))
        )
    session.recheck_identity()
    _require_e10_production_planning_owner(owner)
    return payload


def _e10_replay_catalog_in_production_session(
    session: PostgresTransactionSession,
    *,
    owner: _E10ProductionPlanningOwner,
) -> E10PlanningCatalogObservation:
    _require_e10_production_planning_owner(owner)
    statement, collector_digest = _e10_catalog_select_for_transaction(owner.expectation)
    payload = _last_json_object(
        session.execute(statement),
        label="E10 production planning catalog replay",
    )
    actual = _issue_e10_planning_catalog_observation(payload)
    session.recheck_identity()
    _require_e10_production_planning_owner(owner)
    if (
        actual.collector_sql_digest != collector_digest
        or actual.snapshot_text != session.identity.snapshot_text
        or _e10_catalog_static_payload(actual)
        != _e10_catalog_static_payload(owner.receipt.observation)
    ):
        raise PostgresError(
            "E10 production planning catalog no longer matches replayed receipt"
        )
    return actual


def _e10_replay_selected_artifact_catalog_in_production_session(
    session: PostgresTransactionSession,
    *,
    owner: _E10ProductionPlanningOwner,
    artifact_id: str,
) -> E10SelectedArtifactCatalogObservation:
    """Observe only the selected artifact in the already-open H2 transaction."""

    _require_e10_production_planning_owner(owner)
    artifact_expectations = tuple(
        item for item in owner.expectation.artifacts if item.artifact_id == artifact_id
    )
    frozen_artifacts = tuple(
        item
        for item in owner.receipt.observation.artifacts
        if item.artifact_id == artifact_id
    )
    if len(artifact_expectations) != 1 or len(frozen_artifacts) != 1:
        raise PostgresError(
            "E10 selected artifact is not uniquely bound to the planning owner"
        )
    artifact_expectation = artifact_expectations[0]
    frozen_artifact = frozen_artifacts[0]
    if (
        artifact_expectation.kind != frozen_artifact.kind
        or artifact_expectation.physical_relation
        != frozen_artifact.physical_relation
    ):
        raise PostgresError("E10 selected artifact planning identity changed")
    statement, collector_digest = _e10_selected_artifact_catalog_sql(
        owner.expectation,
        artifact_id=artifact_id,
    )
    if (
        not statement.lstrip().startswith("SELECT ")
        or re.search(r"\b(?:BEGIN|COMMIT|SET)\b", statement, re.IGNORECASE)
        is not None
    ):
        raise PostgresError("E10 selected-artifact collector is not SELECT-only")
    payload = _last_json_object(
        session.execute(statement),
        label="E10 production selected-artifact catalog replay",
    )
    actual = _issue_e10_selected_artifact_catalog_observation(payload)
    session.recheck_identity()
    _require_e10_production_planning_owner(owner)
    assessment = _assess_e10_planning_artifact(
        owner.expectation,
        artifact_expectation,
        owner.receipt.observation,
        actual.artifact,
    )
    if (
        actual.collector_sql_digest != collector_digest
        or actual.snapshot_text != session.identity.snapshot_text
        or actual.artifact != frozen_artifact
        or actual.artifact.artifact_id != artifact_id
        or actual.artifact.kind != artifact_expectation.kind
        or _e10_planning_catalog_core_payload(actual)
        != _e10_planning_catalog_core_payload(owner.receipt.observation)
        or not assessment.usable
    ):
        raise PostgresError(
            "E10 selected artifact no longer matches the replayed planning receipt"
        )
    return actual


def _e10_describe_strict_root_schema(
    session: PostgresTransactionSession,
    *,
    owner: _E10ProductionPlanningOwner,
    strict: StrictPlanningResult,
) -> tuple[TypedRootSchemaColumn, ...]:
    _require_e10_production_planning_owner(owner)
    if strict.draft is None or strict.query_result is None:
        raise PostgresError("E10 strict root schema requires a complete draft")
    if not _e10_direct_rid_projection_proven(strict, owner):
        raise PostgresError(
            "E10 strict root schema lacks a finite direct-RID projection proof"
        )
    try:
        sigma = sigma_from_dict(strict.query_result.root_sigma)
    except Exception as exc:
        raise PostgresError("E10 strict root schema Sigma is malformed") from exc
    visible_names = _e10_exact_sigma_string_list(
        sigma.phys_props,
        "visible_attrs",
    )
    hidden_names = _e10_exact_sigma_string_list(
        sigma.phys_props,
        "hidden_attrs",
    )
    if (
        visible_names != (owner.expectation.rid_col,)
        or hidden_names != _e10_required_hidden_carriers(owner.case)
        or set(visible_names).intersection(hidden_names)
    ):
        raise PostgresError(
            "E10 strict root schema projection is outside the finite shape"
        )
    strict_body = strict.draft.sql_text.strip().rstrip(";")
    schema_probe = (
        "SELECT * FROM (\n" + strict_body + "\n) AS caprls_e10_strict_root_schema_probe"
    )
    description = session._describe_result_columns_without_execution(schema_probe)
    rows = tuple(
        tuple(part.strip() for part in line.split("|", 1))
        for line in description.splitlines()
        if line.strip()
    )
    expected_names = visible_names + hidden_names
    if (
        len(rows) != len(expected_names)
        or any(len(row) != 2 for row in rows)
        or tuple(row[0] for row in rows) != expected_names
        or any(not row[1] for row in rows)
    ):
        raise PostgresError("E10 strict root schema identity mismatch")
    relation_contract = E10_ACCESS_COLUMN_CONTRACTS.get(owner.expectation.relation_name)
    if relation_contract is None:
        raise PostgresError("E10 access-root relation contract is missing")
    metadata_by_name: dict[str, Mapping[str, Any]] = {}
    for ordinal, name in enumerate(expected_names):
        base_name = owner.expectation.rid_col if name == "__rid" else name
        contract = relation_contract.get(base_name)
        if contract is None:
            raise PostgresError("E10 access-root column contract is missing")
        metadata_sql = (
            "SELECT jsonb_build_object("
            "'name', attribute.attname, "
            "'type_name', format_type(attribute.atttypid, attribute.atttypmod), "
            "'nullable', NOT attribute.attnotnull, "
            "'collation', CASE WHEN attribute.attcollation = 0 THEN NULL "
            "ELSE attribute.attcollation::regcollation::text END"
            ")::text FROM pg_catalog.pg_attribute attribute "
            "WHERE attribute.attrelid = to_regclass("
            + _quote("public." + owner.expectation.relation_name)
            + ") AND attribute.attname = "
            + _quote(base_name)
            + " AND attribute.attnum > 0 AND NOT attribute.attisdropped"
        )
        metadata = _last_json_object(
            session.execute(metadata_sql),
            label="E10 production access-root schema metadata",
        )
        session.recheck_identity()
        _require_e10_production_planning_owner(owner)
        expected_type, expected_nullable = contract
        if (
            metadata.get("name") != base_name
            or metadata.get("type_name") != expected_type
            or rows[ordinal][1] != expected_type
            or metadata.get("nullable") is not expected_nullable
            or (
                metadata.get("collation") is not None
                and type(metadata.get("collation")) is not str  # noqa: E721
            )
        ):
            raise PostgresError("E10 strict root schema metadata mismatch")
        metadata_by_name[name] = metadata
    return tuple(
        TypedRootSchemaColumn(
            ordinal=ordinal,
            name=name,
            type_name=type_name,
            nullable=bool(metadata_by_name[name]["nullable"]),
            collation=metadata_by_name[name].get("collation"),
            visibility=("visible" if ordinal < len(visible_names) else "hidden"),
        )
        for ordinal, (name, type_name) in enumerate(rows)
    )


def _e10_direct_rid_projection_proven(
    strict: StrictPlanningResult,
    owner: _E10ProductionPlanningOwner,
) -> bool:
    """Prove that base RID catalog nullability applies to the root output.

    The finite E10 root projects the base RID column directly; it has no
    expression slot capable of manufacturing a nullable replacement.  The
    strict certificate/replay and root closure authenticate that exact IR.
    """

    query_result = strict.query_result
    if (
        query_result is None
        or strict.replay is None
        or not strict.replay.ok
        or strict.envelope is None
        or not query_result.root_closure.ok
        or not isinstance(query_result.bound_ir, Root)
    ):
        return False
    try:
        sigma = sigma_from_dict(query_result.root_sigma)
    except Exception:
        return False
    visible = sigma.phys_props.get("visible_attrs")
    if (
        type(visible) is not list  # noqa: E721
        or visible != [owner.expectation.rid_col]
    ):
        return False
    projects = tuple(
        node for node in walk(query_result.bound_ir) if isinstance(node, Project)
    )
    scans = tuple(
        node for node in walk(query_result.bound_ir) if isinstance(node, ScanProtected)
    )
    expected_hidden = _e10_required_hidden_carriers(owner.case)
    return bool(
        len(projects) == 1
        and projects[0].visible_A == (owner.expectation.rid_col,)
        and projects[0].hidden_H == expected_hidden
        and len(scans) == 1
        and scans[0].occurrence_id == owner.expectation.occurrence_id
    )


def _e10_exact_sigma_string_list(
    props: Mapping[str, Any],
    key: str,
) -> tuple[str, ...]:
    if key not in props or type(props[key]) is not list:  # noqa: E721
        raise PostgresError(f"E10 strict root Sigma {key} is missing or untyped")
    values = tuple(props[key])
    if (
        any(type(item) is not str or not item for item in values)  # noqa: E721
        or len(set(values)) != len(values)
    ):
        raise PostgresError(f"E10 strict root Sigma {key} is malformed")
    return values


def _e10_q4_unsafe_query_filter_order_proven(
    bound_ir: Any,
    problem: PlanningProblem,
) -> bool:
    """Prove Q4's ordinary filter is an authenticated unsafe-input child."""

    if problem.occurrence_id != E10_BARRIER_QUERY_ID:
        return True
    if not isinstance(bound_ir, Root):
        return False
    all_nodes = walk(bound_ir)
    unsafe_nodes = tuple(
        node
        for node in all_nodes
        if isinstance(node, UnsafeExpr)
        and node.expr_label == f"{E10_BARRIER_QUERY_ID}:audit"
    )
    expected_predicate = f"sel.{problem.rid_col} <= 20000"
    filter_nodes = tuple(
        node
        for node in all_nodes
        if isinstance(node, Select)
        and node.pred == expected_predicate
        and node.pred_kind == "logical_target"
        and node.expr_label == f"{E10_BARRIER_QUERY_ID}:base_filter"
    )
    if len(unsafe_nodes) != 1 or len(filter_nodes) != 1:
        return False
    return any(node is filter_nodes[0] for node in walk(unsafe_nodes[0].source))


def _e10_strict_root_physical_observation(
    strict: StrictPlanningResult,
) -> TypedRootPhysicalObservation:
    if strict.query_result is None:
        raise PostgresError("E10 strict root physical identity is missing")
    try:
        sigma = sigma_from_dict(strict.query_result.root_sigma)
    except Exception as exc:
        raise PostgresError("E10 strict root Sigma is malformed") from exc
    goals = tuple(strict.query_result.effective_occurrence_goals.values())
    if len(goals) != 1:
        raise PostgresError("E10 strict root must have one effective goal")
    problem = goals[0].problem
    if (
        strict.replay is None
        or not strict.replay.ok
        or strict.envelope is None
        or not strict.query_result.root_closure.ok
    ):
        raise PostgresError("E10 strict root physical proof is incomplete")
    if not _e10_q4_unsafe_query_filter_order_proven(
        strict.query_result.bound_ir,
        problem,
    ):
        raise PostgresError("E10 Q4 query-filter-before-unsafe ordering is unproven")
    phys = sigma.phys_props
    visible = _e10_exact_sigma_string_list(phys, "visible_attrs")
    hidden_values = _e10_exact_sigma_string_list(phys, "hidden_attrs")
    delivered_order = _e10_exact_sigma_string_list(phys, "delivered_order")
    if visible != (problem.rid_col,):
        raise PostgresError("E10 strict root visible Sigma is not exact RID-only")
    rid_props = sigma.rid_mat_props
    required_rid_keys = ("rid_domain", "surrogate_col", "carrier")
    if any(
        key not in rid_props
        or type(rid_props[key]) is not str  # noqa: E721
        or not rid_props[key]
        for key in required_rid_keys
    ):
        raise PostgresError("E10 strict root RID materialization proof is incomplete")
    rid_domain = rid_props["rid_domain"]
    surrogate_col = rid_props["surrogate_col"]
    carrier = rid_props["carrier"]
    if (
        rid_domain != f"{problem.relation}.{problem.rid_col}"
        or surrogate_col != problem.rid_col
        or carrier not in hidden_values
    ):
        raise PostgresError("E10 strict root RID materialization identity mismatch")

    nodes = walk(strict.query_result.bound_ir)
    materialize_nodes = tuple(node for node in nodes if isinstance(node, Materialize))
    materialized = bool(materialize_nodes)
    if "materialized" in phys:
        if (
            type(phys["materialized"]) is not bool  # noqa: E721
            or phys["materialized"] != materialized
        ):
            raise PostgresError("E10 strict root materialization evidence mismatch")
    elif materialized:
        raise PostgresError("E10 strict root materialization evidence is missing")

    validation_gates = tuple(node for node in nodes if isinstance(node, ValidationGate))
    validation_gate_ids = tuple(sorted({node.artifact_id for node in validation_gates}))
    if validation_gates:
        if (
            "validation_gate" not in phys
            or type(phys["validation_gate"]) is not str  # noqa: E721
            or phys["validation_gate"] not in validation_gate_ids
        ):
            raise PostgresError("E10 strict root validation-gate evidence mismatch")
    elif "validation_gate" in phys:
        raise PostgresError("E10 strict root has unproven validation-gate evidence")

    proven_coverage: list[str] = []
    for requirement in problem.parent_requirement.observable_coverage:
        if requirement.startswith("hidden_carrier:"):
            required_carrier = requirement.split(":", 1)[1]
            project_witness = any(
                isinstance(node, Project) and required_carrier in node.hidden_H
                for node in nodes
            )
            if (
                not required_carrier
                or required_carrier not in hidden_values
                or not project_witness
            ):
                raise PostgresError(
                    "E10 strict root hidden-carrier coverage is unproven"
                )
        elif requirement.startswith("unsafe_expr:"):
            required_label = requirement.split(":", 1)[1]
            if not required_label or not any(
                isinstance(node, UnsafeExpr) and node.expr_label == required_label
                for node in nodes
            ):
                raise PostgresError(
                    "E10 strict root unsafe-expression coverage is unproven"
                )
        elif requirement == "materialized" and materialized:
            pass
        else:
            raise PostgresError(
                "E10 strict root observable coverage is outside the finite proof"
            )
        proven_coverage.append(requirement)
    observable = {
        "materialized": str(materialized).lower(),
        "validation_gate": (
            "none" if not validation_gate_ids else ",".join(validation_gate_ids)
        ),
    }
    return TypedRootPhysicalObservation(
        delivered_order=delivered_order,
        observable_properties=tuple(sorted(observable.items())),
        cost_relevant_properties=(
            ("backend", "postgresql"),
            ("cost_model", E10_PRODUCTION_ROOT_COST_MODEL_VERSION),
        ),
        hidden_attrs_and_carriers=tuple(sorted(hidden_values)),
        observable_coverage=tuple(proven_coverage),
        rid_domain=rid_domain,
        rid_surrogate_col=surrogate_col,
        rid_carrier=carrier,
        rid_materialized=materialized,
    )


def _e10_production_planner_invocation(
    *,
    case: E10Case,
    problem: PlanningProblem,
    query: PlanningQuery,
    expectation: E10PlanningExpectation,
    receipt: E10PlanningReceipt,
    bundle: E10AdmissionBundle,
    root: Path,
    pg_env: PostgresEnv,
) -> E10PlannerInvocation:
    owner = _mint_e10_production_planning_owner(
        case=case,
        root=root,
        expectation=expectation,
        receipt=receipt,
        bundle=bundle,
    )
    if (
        owner.case is not case
        or owner.root is not root
        or owner.expectation is not expectation
        or owner.receipt is not receipt
        or owner.bundle is not bundle
    ):
        raise PostgresError("E10 production planning owner inputs changed")
    _require_e10_production_planning_owner(owner)
    owner_expectations, owner_artifact_bindings = _e10_strict_artifact_contract(
        owner.receipt,
        owner.bundle,
    )
    query_artifact_ids = {
        artifact.artifact_id for artifact in problem.artifacts.values()
    }
    if owner_artifact_bindings != owner.artifact_evidence_bindings or dict(
        query.emit_context.artifact_expectations
    ) != {
        artifact_id: artifact_expectation
        for artifact_id, artifact_expectation in owner_expectations.items()
        if artifact_id in query_artifact_ids
    }:
        raise PostgresError(
            "E10 production strict artifact contract changed before planning"
        )
    registry = _e10_registry()
    definitions = tuple(
        template_definition(item.template_id) for item in registry.template_specs()
    )
    scope = _mint_production_strict_registry_scope(
        registry,
        scope_id="e10-production:" + owner.identity_digest,
        manifest_digest=owner.registry_manifest_digest,
        expected_registry_digest=canonical_registry_digest(definitions),
        expected_template_ids=tuple(item.template_id for item in definitions),
        owner=owner,
        owner_identity_digest=owner.identity_digest,
        owner_validator=_require_e10_production_planning_owner,
        artifact_evidence_bindings=owner.artifact_evidence_bindings,
    )
    session_contract = _e10_production_session_contract(owner)
    request = StrictPlanningRequest(
        query=query,
        session_contract=session_contract,
        continuation=ContinuationTemplate("strict-identity-v1", "{{CORE_SQL}}"),
        registry_version="e10-production-registry-v1",
    )
    _require_e10_production_planning_owner(owner)
    enumerated = plan_query(
        query,
        registry=registry,
        feasibility_backtracking=False,
    )
    occurrence = enumerated.occurrence_results.get(problem.occurrence_id)
    if occurrence is None:
        raise PostgresError("E10 production admitted inventory is missing")
    admitted = tuple(
        sorted(
            (candidate for candidate in occurrence.candidates if candidate.accepted),
            key=lambda item: item.template_id,
        )
    )
    if not admitted or len({item.template_id for item in admitted}) != len(admitted):
        raise PostgresError("E10 production admitted inventory is invalid")
    expected_inventory = tuple(
        (candidate.template_id, _strict_planning_digest(candidate.to_dict()))
        for candidate in admitted
    )
    attempts: list[StrictPlanningResult] = []
    for candidate in admitted:
        _require_e10_production_planning_owner(owner)
        attempt = strict_plan_forced_alternative(
            request,
            occurrence_id=problem.occurrence_id,
            template_id=candidate.template_id,
            registry=registry,
            registry_scope=scope,
        )
        provenance = _require_forced_root_attempt_provenance(attempt)
        if provenance.admitted_candidate_inventory != expected_inventory:
            raise PostgresError("E10 production forced inventory drifted")
        attempts.append(attempt)
    _require_e10_production_planning_owner(owner)

    costs: dict[str, Any] = {}
    explain_digests: dict[str, str] = {}
    schemas: dict[str, tuple[TypedRootSchemaColumn, ...]] = {}
    runner_schemas: dict[str, tuple[TypedRootSchemaColumn, ...]] = {}
    runner_sql_by_plan: dict[str, str] = {}
    physical: dict[str, TypedRootPhysicalObservation] = {}
    static_digests: dict[str, str] = {}
    continuation = _e10_continuation_spec(case, expectation)
    query_key_cardinality = _e10_query_key_cardinality(case, problem)
    with PostgresTransactionSession(
        pg_env,
        read_only=session_contract.read_only,
    ) as session:
        for statement in (
            "SET LOCAL search_path TO pg_catalog, public",
            "SET LOCAL row_security = on",
            "SET LOCAL jit = off",
            "SET LOCAL max_parallel_workers_per_gather = 0",
            "SET LOCAL plan_cache_mode = force_custom_plan",
        ):
            session.execute(statement)
        environment = _e10_observe_production_environment(
            session,
            owner=owner,
            pg_env=pg_env,
            session_contract=session_contract,
        )
        catalog = _e10_replay_catalog_in_production_session(
            session,
            owner=owner,
        )
        for attempt in attempts:
            provenance = _require_forced_root_attempt_provenance(attempt)
            if provenance.outcome_status != "completed":
                continue
            assert attempt.draft is not None
            plan_id = attempt.draft.plan_id
            _require_e10_production_planning_owner(owner)
            _e10_observe_production_environment(
                session,
                owner=owner,
                pg_env=pg_env,
                session_contract=session_contract,
            )
            try:
                schemas[plan_id] = _e10_describe_strict_root_schema(
                    session,
                    owner=owner,
                    strict=attempt,
                )
            except (PostgresError, TypeError, ValueError):
                pass
            runner_body = _e10_bound_runner_sql(case, attempt, expectation)
            runner_sql_by_plan[plan_id] = runner_body
            try:
                runner_schemas[plan_id] = _e10_describe_bound_runner_result(
                    session,
                    continuation=continuation,
                    runner_sql=runner_body,
                )
            except (PostgresError, TypeError, ValueError):
                pass
            try:
                physical[plan_id] = _e10_strict_root_physical_observation(attempt)
            except (PostgresError, TypeError, ValueError):
                pass
            _require_e10_production_planning_owner(owner)
            try:
                explain_json = _extract_explain_json(
                    session.execute("EXPLAIN (FORMAT JSON) " + runner_body)
                )
            except (PostgresError, TypeError, ValueError, json.JSONDecodeError):
                session.recheck_identity()
                _require_e10_production_planning_owner(owner)
                continue
            session.recheck_identity()
            _require_e10_production_planning_owner(owner)
            explain_digest = _explain_plan_hash(explain_json)
            explain_digests[plan_id] = explain_digest
            plan = explain_json[0].get("Plan", {})
            if isinstance(plan, Mapping) and "Total Cost" in plan:
                # Preserve malformed values for the sealed batch classifier;
                # omission and invalid evidence are distinct fail-closed rows.
                raw_cost = plan["Total Cost"]
                costs[plan_id] = (
                    _e10_candidate_access_adjusted_cost(
                        provenance.template_id,
                        float(raw_cost),
                        problem=problem,
                        query_key_cardinality=query_key_cardinality,
                    )
                    if isinstance(raw_cost, (int, float))
                    and not isinstance(raw_cost, bool)
                    else raw_cost
                )
            try:
                verification = _verify_static_template(
                    provenance.template_id,
                    runner_body,
                    explain_json,
                )
            except PostgresError:
                verification = None
            if (
                verification is not None
                and verification.__class__ is StaticVerification
                and verification.status == "pass"
                and verification.reasons == []
                and verification.plan_hash == explain_digest
            ):
                static_digests[plan_id] = _canonical_digest(
                    {
                        "schema": "e10_bound_runner_static_verification_v2",
                        "template_id": provenance.template_id,
                        "bound_runner_sql_digest": _canonical_digest(
                            {"exact_runner_sql": runner_body}
                        ),
                        "explain_plan_digest": explain_digest,
                        "status": verification.status,
                        "reasons": list(verification.reasons),
                        "plan_hash": verification.plan_hash,
                    }
                )
        final_environment = _e10_observe_production_environment(
            session,
            owner=owner,
            pg_env=pg_env,
            session_contract=session_contract,
        )
        if final_environment != environment:
            raise PostgresError("E10 production planning environment changed")
        identity = session.recheck_identity()
        snapshot_digest = _canonical_digest(
            {
                "schema": "e10_production_planning_snapshot_v1",
                "transaction_identity": identity.to_dict(),
                "owner_identity": owner.identity_digest,
            }
        )
        database_digest = _canonical_digest(
            {
                "schema": "e10_production_database_identity_v1",
                "connection_target": {
                    "host": pg_env.host,
                    "port": pg_env.port,
                    "user": pg_env.user,
                    "database": pg_env.database,
                },
                "current_database": environment["current_database"],
                "session_user": environment["session_user"],
                "current_user": environment["current_user"],
                "server_version_num": environment["server_version_num"],
            }
        )
        catalog_digest = _canonical_digest(
            {
                "schema": "e10_production_catalog_replay_v1",
                "observation": catalog.to_dict(),
                "transaction_identity_digest": identity.digest,
            }
        )
        bound_runners: dict[str, BoundRunnerIdentity] = {}
        for attempt in attempts:
            provenance = _require_forced_root_attempt_provenance(attempt)
            if provenance.outcome_status != "completed" or attempt.draft is None:
                continue
            plan_id = attempt.draft.plan_id
            runner_body = runner_sql_by_plan.get(plan_id)
            if runner_body is None:
                continue
            bound_runners[plan_id] = _mint_bound_runner_identity(
                attempt,
                continuation_spec=continuation,
                runner_sql=runner_body,
                case_owner_identity_digest=owner.identity_digest,
                snapshot_digest=snapshot_digest,
                database_identity_digest=database_digest,
                catalog_digest=catalog_digest,
            )
        batch = _mint_production_planning_evidence_batch(
            attempts,
            bound_runners=bound_runners,
            prospective_costs=costs,
            explain_plan_digests=explain_digests,
            schemas=schemas,
            runner_schemas=runner_schemas,
            physical_observations=physical,
            static_verification_digests=static_digests,
            batch_id="e10:" + owner.identity_digest + ":" + identity.session_nonce,
            snapshot_digest=snapshot_digest,
            database_identity_digest=database_digest,
            catalog_digest=catalog_digest,
            cost_model_version=E10_PRODUCTION_ROOT_COST_MODEL_VERSION,
        )
        selection = select_completed_roots(
            batch,
            feature_flags=PlannerFeatureFlags(reference_dominance="enabled"),
        )
    if not selection.ok or selection.chosen is None:
        raise PostgresError(
            "E10 production root selection rejected the cell: "
            + ";".join(selection.audit.reasons)
            + ":"
            + _canonical_json(
                [item.to_dict() for item in selection.audit.evidence_failures]
            )
        )
    chosen_strict = selection.chosen.strict_result
    if chosen_strict.query_result is None:
        raise PostgresError(
            "E10 production selector returned an incomplete strict root"
        )
    chosen_occurrence = chosen_strict.query_result.occurrence_results[
        problem.occurrence_id
    ]
    eligibility, completed_roots = _e10_completed_root_eligibility_payload(batch)
    payload = _query_plan_payload(chosen_strict.query_result, receipt, bundle)
    payload["production_root_selection"] = selection.audit.to_dict()
    payload["production_planning_batch_digest"] = batch.batch_digest
    payload["production_completed_root_eligibility"] = eligibility
    payload[
        "production_root_execution_binding"
    ] = _e10_production_root_execution_binding_payload()
    payload["production_bound_runner"] = selection.chosen.bound_runner.to_dict()
    payload["production_chosen_cost"] = {
        "ranker": "public_completed_root_selector",
        "plan_id": selection.chosen.plan_id,
        "prospective_total_cost": (
            selection.chosen.prospective_cost.cost_after_all_enforcers
        ),
        "cost_model_version": selection.chosen.prospective_cost.cost_model_version,
        "planning_environment_digest": (
            selection.chosen.prospective_cost.planning_environment_digest
        ),
    }
    payload["heuristic_estimated_cost_is_diagnostic"] = True
    _register_e10_production_query_plan(
        payload,
        owner=owner,
        batch=batch,
        selected_plan_id=selection.chosen.plan_id,
        plan_result=chosen_occurrence,
    )
    replayed_completed_roots = _require_e10_production_root_execution_binding(payload)
    if replayed_completed_roots != completed_roots:
        raise PostgresError("E10 production completed-root projection changed")
    return E10PlannerInvocation(
        occurrence_result=chosen_occurrence,
        query_result=chosen_strict.query_result,
        query_plan=payload,
        problem=problem,
        planning_receipt=receipt,
        planning_admission_bundle=bundle,
        production_completed_roots=completed_roots,
    )


def _planner_invocation_for_case(
    case: E10Case,
    mode: str,
    *,
    relname: str,
    rid_col: str,
    policy_id: str,
    artifacts: Mapping[str, ArtifactMetadata],
    base_rows: int,
    filtered_rows: int,
    alias: str = "d",
    exact_predicate: str | None = None,
    complete_guard_predicate: str | None = None,
    query_predicate: str | None = None,
    explain_cost_fn: Optional[E10ExplainCostFn] = None,
    planning_receipt: Optional[E10PlanningReceipt] = None,
    planning_expectation: Optional[E10PlanningExpectation] = None,
    planning_admission_bundle: Optional[E10AdmissionBundle] = None,
    require_production_receipt: bool = False,
    root: Optional[Path] = None,
    artifact_relations: Optional[Mapping[str, str]] = None,
    pg_env: Optional[PostgresEnv] = None,
) -> E10PlannerInvocation:
    mode = normalize_mode_id(mode)
    _assert_e10_planning_receipt_gate(
        receipt=planning_receipt,
        expectation=planning_expectation,
        artifacts=artifacts,
        require_production=require_production_receipt,
    )
    _assert_e10_admission_bundle_gate(
        root=root,
        case=case,
        bundle=planning_admission_bundle,
        receipt=planning_receipt,
        expectation=planning_expectation,
        require_production=require_production_receipt,
    )
    _assert_e10_admission_lowering_inputs(
        exact_predicate=exact_predicate,
        complete_guard_predicate=complete_guard_predicate,
        query_predicate=query_predicate,
        expectation=planning_expectation,
        bundle=planning_admission_bundle,
        require_production=require_production_receipt,
    )
    problem = _planning_problem_for_case(
        case,
        relname,
        rid_col,
        policy_id,
        artifacts,
        base_rows,
        filtered_rows,
        query_predicate=query_predicate,
        admission_bundle=planning_admission_bundle,
    )
    _assert_e10_typed_problem_identity(
        problem=problem,
        query_predicate=query_predicate,
        expectation=planning_expectation,
        bundle=planning_admission_bundle,
        require_production=require_production_receipt,
    )
    strict_artifact_expectations: Optional[
        Mapping[str, StrictArtifactExpectation]
    ] = None
    if require_production_receipt and mode == ADMISSION_FIRST_MODE:
        if explain_cost_fn is not None:
            raise PostgresError(
                "E10 production planning rejects the legacy EXPLAIN callback"
            )
        if (
            root is None
            or pg_env is None
            or planning_expectation is None
            or planning_receipt is None
            or planning_admission_bundle is None
        ):
            raise PostgresError(
                "E10 production root planning requires internal PostgreSQL session inputs"
            )
        all_expectations, _ = _e10_strict_artifact_contract(
            planning_receipt,
            planning_admission_bundle,
        )
        problem_artifact_ids = {
            artifact.artifact_id for artifact in problem.artifacts.values()
        }
        strict_artifact_expectations = {
            artifact_id: expectation
            for artifact_id, expectation in all_expectations.items()
            if artifact_id in problem_artifact_ids
        }
    query = _planning_query_for_case(
        case,
        problem=problem,
        mode=mode,
        alias=alias,
        exact_predicate=exact_predicate,
        complete_guard_predicate=complete_guard_predicate,
        query_predicate=query_predicate,
        artifact_relations=artifact_relations,
        strict_artifact_expectations=strict_artifact_expectations,
        planning_expectation=(
            planning_expectation if require_production_receipt else None
        ),
    )
    effective_goal = derive_occurrence_goals(query)[problem.occurrence_id]
    effective_problem = effective_goal.problem
    if planning_admission_bundle is not None:
        if (
            effective_problem.parent_requirement
            != planning_admission_bundle.parent_requirement
        ):
            raise PostgresError("E10 typed admission rho differs from IR-derived rho")
        if (
            effective_problem.logical_target != planning_admission_bundle.logical_target
            or effective_problem.implementation_target_bindings
            != planning_admission_bundle.implementation_target_bindings
            or effective_problem.gamma_snapshot
            != planning_admission_bundle.gamma_snapshot
            or not effective_problem.require_typed_admission
        ):
            raise PostgresError(
                "E10 typed admission identity changed during IR derivation"
            )
    if require_production_receipt and mode == ADMISSION_FIRST_MODE:
        assert root is not None
        assert pg_env is not None
        assert planning_expectation is not None
        assert planning_receipt is not None
        assert planning_admission_bundle is not None
        return _e10_production_planner_invocation(
            case=case,
            problem=problem,
            query=query,
            expectation=planning_expectation,
            receipt=planning_receipt,
            bundle=planning_admission_bundle,
            root=root,
            pg_env=pg_env,
        )
    preplanned: Optional[dict[str, PlanResult]] = None
    if explain_cost_fn is not None and mode == ADMISSION_FIRST_MODE:
        if effective_problem.occurrence_id != problem.occurrence_id:
            effective_problem = replace(
                effective_problem,
                occurrence_id=problem.occurrence_id,
            )
        occurrence_result = plan_occurrence(
            effective_problem,
            effective_goal.mode or mode,
            registry=_e10_registry(),
        )
        occurrence_result = _rerank_plan_with_pg_explain(
            occurrence_result,
            problem=effective_problem,
            explain_cost_fn=explain_cost_fn,
        )
        preplanned = {problem.occurrence_id: occurrence_result}
    query_result = plan_query(
        query,
        registry=_e10_registry(),
        preplanned_occurrence_results=preplanned,
    )
    return E10PlannerInvocation(
        occurrence_result=query_result.occurrence_results[problem.occurrence_id],
        query_result=query_result,
        query_plan=_query_plan_payload(
            query_result,
            planning_receipt,
            planning_admission_bundle,
        ),
        problem=problem,
        planning_receipt=planning_receipt,
        planning_admission_bundle=planning_admission_bundle,
    )


def _query_plan_for_forced_candidate(
    case: E10Case,
    *,
    problem: PlanningProblem,
    occurrence_result: PlanResult,
    candidate: CandidatePlan,
    alias: str = "d",
    exact_predicate: str | None = None,
    complete_guard_predicate: str | None = None,
    query_predicate: str | None = None,
    planning_receipt: Optional[E10PlanningReceipt] = None,
    planning_expectation: Optional[E10PlanningExpectation] = None,
    planning_admission_bundle: Optional[E10AdmissionBundle] = None,
    require_production_receipt: bool = False,
    root: Optional[Path] = None,
    artifact_relations: Optional[Mapping[str, str]] = None,
) -> Mapping[str, Any]:
    _assert_e10_planning_receipt_gate(
        receipt=planning_receipt,
        expectation=planning_expectation,
        artifacts=problem.artifacts,
        require_production=require_production_receipt,
        require_complete_inventory=False,
    )
    _assert_e10_admission_bundle_gate(
        root=root,
        case=case,
        bundle=planning_admission_bundle,
        receipt=planning_receipt,
        expectation=planning_expectation,
        require_production=require_production_receipt,
    )
    _assert_e10_admission_lowering_inputs(
        exact_predicate=exact_predicate,
        complete_guard_predicate=complete_guard_predicate,
        query_predicate=query_predicate,
        expectation=planning_expectation,
        bundle=planning_admission_bundle,
        require_production=require_production_receipt,
    )
    _assert_e10_typed_problem_identity(
        problem=problem,
        query_predicate=query_predicate,
        expectation=planning_expectation,
        bundle=planning_admission_bundle,
        require_production=require_production_receipt,
    )
    if require_production_receipt:
        if candidate not in occurrence_result.candidates or not candidate.accepted:
            raise PostgresError(
                "E10 production forced candidate is not an admitted planner candidate"
            )
        required_artifact = _required_artifact_for_template(candidate.template_id)
        if required_artifact is not None:
            assessment = next(
                (
                    item
                    for item in planning_receipt.artifact_assessments
                    if item.kind == required_artifact
                ),
                None,
            )
            if (
                assessment is None
                or not assessment.usable
                or required_artifact not in problem.artifacts
            ):
                raise PostgresError(
                    "E10 production forced candidate lacks usable artifact evidence"
                )
    forced_result = replace(
        occurrence_result,
        chosen_template=candidate,
        emitted_sql=candidate.emitted_sql,
        delivered_sigma=dict(candidate.delivered_sigma),
        estimated_cost=candidate.estimated_cost,
    )
    query = _planning_query_for_case(
        case,
        problem=problem,
        mode=ADMISSION_FIRST_MODE,
        alias=alias,
        exact_predicate=exact_predicate,
        complete_guard_predicate=complete_guard_predicate,
        query_predicate=query_predicate,
        artifact_relations=artifact_relations,
        planning_expectation=(
            planning_expectation if require_production_receipt else None
        ),
    )
    if planning_admission_bundle is not None:
        effective = derive_occurrence_goals(query)[problem.occurrence_id].problem
        if (
            effective.parent_requirement != planning_admission_bundle.parent_requirement
            or effective.logical_target != planning_admission_bundle.logical_target
            or effective.implementation_target_bindings
            != planning_admission_bundle.implementation_target_bindings
            or effective.gamma_snapshot != planning_admission_bundle.gamma_snapshot
            or not effective.require_typed_admission
        ):
            raise PostgresError("E10 forced plan typed admission identity mismatch")
    query_result = plan_query(
        query,
        registry=_e10_registry(),
        preplanned_occurrence_results={problem.occurrence_id: forced_result},
    )
    return _query_plan_payload(
        query_result,
        planning_receipt,
        planning_admission_bundle,
    )


def _default_planner_invocation_for_case(
    case: E10Case,
    mode: str,
    context_id: str = "ctx_000001",
) -> Optional[E10PlannerInvocation]:
    mode = normalize_mode_id(mode)
    if mode != ADMISSION_FIRST_MODE:
        return None
    relname, rid_col, policy_id, _ = _target_for_case(case)
    base_rows = 100_000
    filtered_rows = max(case.row_count, 1)
    artifact_ids = _artifact_ids_for_context(relname, context_id)
    rows = {
        "auth": max(case.row_count, 1),
        "keyed": max(case.row_count, 1),
        "mav": max(case.row_count, 1),
    }
    artifacts = _artifact_metadata_for_case(
        case,
        relname,
        rid_col,
        artifact_ids,
        rows,
        {"auth": 4.0, "keyed": 4.0, "mav": 20.0},
        {"auth": 65536, "keyed": 65536, "mav": 65536},
    )
    return _planner_invocation_for_case(
        case,
        mode,
        relname=relname,
        rid_col=rid_col,
        policy_id=policy_id,
        artifacts=artifacts,
        base_rows=base_rows,
        filtered_rows=filtered_rows,
    )


def _default_plan_for_case(
    case: E10Case, mode: str, context_id: str = "ctx_000001"
) -> Optional[PlanResult]:
    invocation = _default_planner_invocation_for_case(case, mode, context_id=context_id)
    return None if invocation is None else invocation.occurrence_result


def _plan_choice(plan_result: Optional[PlanResult]) -> Optional[tuple[str, str]]:
    if plan_result is None or plan_result.chosen_template is None:
        return None
    return (
        plan_result.chosen_template.template_id,
        plan_result.chosen_template.alternative,
    )


def _chosen_rank(
    plan_result: Optional[PlanResult],
    eligible_template_ids: Optional[set[str]] = None,
) -> Optional[int]:
    if plan_result is None or plan_result.chosen_template is None:
        return None
    accepted = sorted(
        (
            candidate
            for candidate in plan_result.candidates
            if candidate.accepted
            and (
                eligible_template_ids is None
                or candidate.template_id in eligible_template_ids
            )
        ),
        key=lambda item: (float(item.estimated_cost or 0.0), item.template_id),
    )
    for idx, candidate in enumerate(accepted, start=1):
        if candidate.template_id == plan_result.chosen_template.template_id:
            return idx
    return None


def _render_policy_predicate(
    template: str,
    alias: str,
    rid_col: str,
    context: Mapping[str, Any],
    relname: str,
) -> str:
    values = {
        "ctx_tenant_id": str(int(context["tenant_id"])),
        "ctx_purpose": _quote(str(context["purpose"])),
        "ctx_region": _quote(str(context["region"])),
        "ctx_clearance": str(int(context["clearance"])),
        "user_id": str(int(context["user_id"])),
        "now": "TIMESTAMPTZ '2026-06-01 00:00:00+00'",
        "relname": _quote(relname),
        "rid_domain_id": _quote(f"{relname}.{rid_col}"),
    }
    rendered = template.replace("{alias}", alias).replace("{rid_col}", rid_col)
    for name, value in sorted(
        values.items(), key=lambda item: len(item[0]), reverse=True
    ):
        rendered = rendered.replace(f":{name}", value)
    leftovers = [part for part in rendered.split() if part.startswith(":")]
    if leftovers:
        raise PostgresError(
            f"cannot render E10 policy predicate; unresolved tokens: {leftovers}"
        )
    return rendered


def _e10_planning_expectation(
    *,
    root: Path,
    case: E10Case,
    context_id: str,
    context: Mapping[str, Any],
    context_hash: str,
    context_version: int,
    policy: Mapping[str, Any],
    exact_predicate: str,
    guard_predicate: Optional[str],
    query_predicate: str,
    artifact_ids: Mapping[str, str],
    mav_physical_relation: str,
    mav_dependency_profile: str,
    scope: str = "production",
) -> E10PlanningExpectation:
    relname, rid_col, policy_id, alias = _target_for_case(case)
    canonical_context = _canonical_json(context)
    if _canonical_digest(context) != context_hash:
        raise PostgresError("E10 planning expectation context digest mismatch")
    if str(context.get("user_id")) == "":
        raise PostgresError("E10 planning expectation principal is missing")
    if scope == "production" and query_predicate != _e10_planning_query_predicate(
        case, alias, rid_col
    ):
        raise PostgresError(
            "E10 production planning query predicate is not source-controlled"
        )
    policy_manifest_path = (
        root / "manifests" / "policies" / "synthetic_saas_policies.yaml"
    )
    definition_payload = _e10_policy_definition_payload(policy_id, policy)
    declared = set(case.available_artifacts)
    artifacts = (
        E10PlanningArtifactExpectation(
            kind="auth_idx",
            artifact_id=str(artifact_ids["auth"]),
            physical_relation="public.auth_idx",
            declared="auth_idx" in declared,
            dependency_profile="legacy5",
        ),
        E10PlanningArtifactExpectation(
            kind="auth_idx_keyed",
            artifact_id=str(artifact_ids["keyed"]),
            physical_relation="public.auth_idx_keyed",
            declared="auth_idx_keyed" in declared,
            dependency_profile="legacy5",
            key_name=rid_col,
        ),
        E10PlanningArtifactExpectation(
            kind="mav",
            artifact_id=str(artifact_ids["mav"]),
            physical_relation=mav_physical_relation,
            declared="mav" in declared,
            dependency_profile=mav_dependency_profile,
        ),
    )
    expectation = E10PlanningExpectation(
        scope=scope,
        case_query_id=case.query_id,
        occurrence_id=case.query_id,
        relation_name=relname,
        rid_col=rid_col,
        rid_domain_id=f"{relname}.{rid_col}",
        policy_id=policy_id,
        policy_manifest_digest=file_sha256(policy_manifest_path),
        policy_config_digest=_canonical_digest(dict(policy)),
        policy_definition_digest=_canonical_digest(definition_payload),
        exact_predicate=exact_predicate,
        exact_predicate_digest=_e10_sql_fragment_digest(exact_predicate),
        guard_predicate_digest=_e10_sql_fragment_digest(guard_predicate),
        query_predicate_digest=_e10_sql_fragment_digest(query_predicate),
        principal_id=str(context["user_id"]),
        context_id=context_id,
        context_hash=context_hash,
        canonical_context_json=canonical_context,
        context_version=context_version,
        registry_inventory=_e10_registry_inventory(),
        artifacts=artifacts,
    )
    return _register_e10_production_source(
        expectation,
        kind="expectation",
        identity_digest=expectation.digest,
    )


def _e10_policy_definition_payload(
    policy_id: str,
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "policy_id": policy_id,
        "exact_sql_template": policy.get("exact_sql_template"),
        "guard_sql_template": policy.get("guard_sql_template"),
        "rid_exact_sql_template": policy.get("rid_exact_sql_template"),
        "required_attrs": policy.get("required_attrs"),
        "required_ctx": policy.get("required_ctx"),
        "required_bindings": policy.get("required_bindings"),
        "applicable_relations": policy.get("applicable_relations"),
    }


_E10_SAFE_SCALAR_TOKEN_RE = re.compile(
    r"\s*(?:"
    r"(?P<qualified>[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*)|"
    r"(?P<string>'[A-Za-z0-9_ .:/+-]*')|"
    r"(?P<number>-?[0-9]+(?:\.[0-9]+)?)|"
    r"(?P<operator><=|>=|<>|!=|=|<|>)|"
    r"(?P<lparen>\()|(?P<rparen>\))|"
    r"(?P<word>[A-Za-z_][A-Za-z0-9_]*)"
    r")",
)


def _e10_safe_scalar_predicate_proof(
    predicate: str,
    *,
    alias: str,
) -> Optional[dict[str, Any]]:
    """Validate the finite side-effect-free scalar predicate grammar.

    The grammar admits only qualified columns, literals, boolean composition,
    scalar comparisons, and numeric/string BETWEEN.  Functions, subqueries,
    casts, comments, and unqualified identifiers are outside the finite IR and
    therefore receive no fact.
    """

    text = str(predicate).strip()
    if not text:
        return None
    tokens: list[tuple[str, str]] = []
    position = 0
    while position < len(text):
        match = _E10_SAFE_SCALAR_TOKEN_RE.match(text, position)
        if match is None:
            return None
        kind = str(match.lastgroup)
        value = match.group(kind)
        if kind == "word":
            keyword = value.upper()
            if keyword not in {"AND", "OR", "BETWEEN", "TRUE", "FALSE"}:
                return None
            tokens.append((keyword, keyword))
        elif kind == "qualified":
            qualifier, column = value.split(".", 1)
            if qualifier.lower() != alias.lower():
                return None
            tokens.append(("COLUMN", f"{qualifier.lower()}.{column.lower()}"))
        elif kind == "string":
            tokens.append(("LITERAL", value))
        elif kind == "number":
            tokens.append(("LITERAL", value))
        elif kind == "operator":
            tokens.append(("OP", value))
        elif kind == "lparen":
            tokens.append(("LPAREN", value))
        elif kind == "rparen":
            tokens.append(("RPAREN", value))
        else:  # pragma: no cover - exhaustive regex groups
            return None
        position = match.end()
    if text[position:].strip():
        return None
    index = 0

    def accept(kind: str) -> Optional[tuple[str, str]]:
        nonlocal index
        if index >= len(tokens) or tokens[index][0] != kind:
            return None
        token = tokens[index]
        index += 1
        return token

    def parse_literal() -> bool:
        return bool(accept("LITERAL") or accept("TRUE") or accept("FALSE"))

    def parse_factor() -> bool:
        nonlocal index
        start = index
        if accept("LPAREN"):
            if not parse_expression() or not accept("RPAREN"):
                index = start
                return False
            return True
        if accept("TRUE") or accept("FALSE"):
            return True
        if not accept("COLUMN"):
            index = start
            return False
        if accept("BETWEEN"):
            if not parse_literal() or not accept("AND") or not parse_literal():
                index = start
                return False
            return True
        if not accept("OP") or not parse_literal():
            index = start
            return False
        return True

    def parse_conjunction() -> bool:
        if not parse_factor():
            return False
        while index < len(tokens) and tokens[index][0] == "AND":
            accept("AND")
            if not parse_factor():
                return False
        return True

    def parse_expression() -> bool:
        if not parse_conjunction():
            return False
        while index < len(tokens) and tokens[index][0] == "OR":
            accept("OR")
            if not parse_conjunction():
                return False
        return True

    if not parse_expression() or index != len(tokens):
        return None
    return {
        "grammar": "e10_safe_scalar_predicate_v1",
        "alias": alias,
        "predicate_digest": canonical_predicate_digest(text),
        "tokens": [{"kind": kind, "value": value} for kind, value in tokens],
    }


def _e10_parent_requirement_for_case(
    case: E10Case,
    rid_col: str,
) -> ParentRequirement:
    unsafe_boundary = case.query_id in {
        E10_BARRIER_QUERY_ID,
        E10_GUARD_UNSAFE_STATIC_WITNESS_QUERY_ID,
    }
    hidden_coverage = tuple(
        f"hidden_carrier:{carrier}" for carrier in _e10_required_hidden_carriers(case)
    )
    observable_coverage = (
        (f"unsafe_expr:{case.query_id}:audit", *hidden_coverage)
        if unsafe_boundary
        else hidden_coverage
    )
    return ParentRequirement(
        logical_group_id=case.query_id,
        visible_columns=(rid_col,),
        required_order=(rid_col,) if "ordered_export" in case.query_shape else (),
        licensed_refinements=("query_filtered",),
        residual_allowed=True,
        residual_deadline=(
            "before_unsafe" if unsafe_boundary else "parent_transparent_boundary"
        ),
        min_safety_level="exact_authorized",
        freshness_predicate=None,
        context_predicate=None,
        allowed_enforcers=("residual_check", "validation_gate", "sort"),
        observable_coverage=observable_coverage,
        transparent=not unsafe_boundary,
        unsafe_expression_boundary=unsafe_boundary,
        needs_branch_lineage=(case.query_id == "E10_Q6_own_plus_group_shared_union"),
        future_rid_intersection=False,
    )


def _e10_guard_basis_payload(
    *,
    expectation: E10PlanningExpectation,
    exact_predicate: str,
    guard_predicate: Optional[str],
    alias: str,
) -> Optional[dict[str, Any]]:
    if guard_predicate is None or not guard_predicate.strip():
        return None
    guard_proof = _e10_safe_scalar_predicate_proof(
        guard_predicate,
        alias=alias,
    )
    if guard_proof is None:
        return None
    residual = _residual_after_complete_guard(
        exact_predicate,
        guard_predicate,
    )
    if not residual.strip() or _e10_sql_fragment_digest(
        residual
    ) == _e10_sql_fragment_digest(exact_predicate):
        return None
    guard_registry = next(
        (
            item
            for item in expectation.registry_inventory
            if item.template_id == "guard_candidate_plus_residual_v1"
        ),
        None,
    )
    if guard_registry is None:
        return None
    lowering_payload = {
        "contract": "e10_guard_lowering_v1",
        "occurrence_id": expectation.occurrence_id,
        "relation_name": expectation.relation_name,
        "rid_col": expectation.rid_col,
        "template_id": guard_registry.template_id,
        "template_spec_digest": guard_registry.spec_digest,
        "exact_predicate_digest": expectation.exact_predicate_digest,
        "guard_predicate_digest": expectation.guard_predicate_digest,
        "residual_predicate_digest": _e10_sql_fragment_digest(residual),
    }
    return {
        "guard_proof": guard_proof,
        "residual_predicate": residual,
        "residual_predicate_digest": _e10_sql_fragment_digest(residual),
        "lowering_payload": lowering_payload,
        "guard_lowering_digest": _canonical_digest(lowering_payload),
    }


def _e10_issue_admission_fact(
    *,
    kind: str,
    subject_digest: str,
    snapshot_id: str,
    source_kind: str,
    payload: Mapping[str, Any],
) -> tuple[GammaFact, E10AdmissionEvidence]:
    if source_kind not in E10_ADMISSION_EVIDENCE_SOURCE_KINDS:
        raise ValueError("E10 admission evidence source is unknown")
    canonical_payload = dict(payload)
    evidence_digest = _canonical_digest(
        _e10_admission_evidence_digest_payload(
            kind=kind,
            subject_digest=subject_digest,
            validator_version=E10_ADMISSION_VALIDATOR_VERSION,
            snapshot_id=snapshot_id,
            source_kind=source_kind,
            payload=canonical_payload,
        )
    )
    fact_id = _e10_admission_fact_id(
        kind=kind,
        subject_digest=subject_digest,
        snapshot_id=snapshot_id,
        evidence_digest=evidence_digest,
    )
    fact = GammaFact(
        fact_id=fact_id,
        kind=kind,
        subject_digest=subject_digest,
        verdict="pass",
        validator_version=E10_ADMISSION_VALIDATOR_VERSION,
        snapshot_id=snapshot_id,
        evidence_digest=evidence_digest,
        dynamic=False,
    )
    evidence = E10AdmissionEvidence(
        schema_version=E10_ADMISSION_EVIDENCE_SCHEMA,
        fact_id=fact_id,
        kind=kind,
        subject_digest=subject_digest,
        validator_version=E10_ADMISSION_VALIDATOR_VERSION,
        snapshot_id=snapshot_id,
        source_kind=source_kind,
        payload_json=_canonical_json(canonical_payload),
        evidence_digest=evidence_digest,
    )
    return fact, evidence


def _issue_e10_admission_bundle(
    *,
    root: Path,
    case: E10Case,
    receipt: E10PlanningReceipt,
    expectation: E10PlanningExpectation,
    require_production: bool,
) -> E10AdmissionBundle:
    receipt_replay = _replay_e10_planning_receipt(
        receipt,
        expectation,
        require_production=require_production,
    )
    if not receipt_replay.valid:
        raise PostgresError(
            "E10 admission bundle source receipt replay failed: "
            + ";".join(receipt_replay.reasons)
        )
    _validate_e10_record_planning_sources(
        root=root,
        case=case,
        expectation=expectation,
        context_id=expectation.context_id,
        context_hash=expectation.context_hash,
    )
    if expectation.registry_inventory != _e10_registry_inventory():
        raise PostgresError("E10 admission registry inventory changed")
    relname, rid_col, policy_id, alias = _target_for_case(case)
    policy = _load_policy(root, policy_id)
    context = json.loads(expectation.canonical_context_json)
    exact_predicate = _render_policy_predicate(
        str(policy["exact_sql_template"]),
        alias=alias,
        rid_col=rid_col,
        context=context,
        relname=relname,
    )
    query_predicate = _e10_planning_query_predicate(case, alias, rid_col)
    guard_predicate = (
        _complete_guard_predicate(case, alias, rid_col, context, relname)
        if case.complete_guard_sql_template is not None
        else None
    )
    if (
        _e10_sql_fragment_digest(exact_predicate) != expectation.exact_predicate_digest
        or _e10_sql_fragment_digest(query_predicate)
        != expectation.query_predicate_digest
        or _e10_sql_fragment_digest(guard_predicate)
        != expectation.guard_predicate_digest
    ):
        raise PostgresError("E10 admission rendered predicate identity mismatch")
    snapshot_id = _canonical_digest(
        {
            "contract": "e10_typed_admission_snapshot_v1",
            "receipt_digest": receipt.receipt_digest,
            "expectation_digest": expectation.digest,
            "observation_digest": receipt.observation.observation_digest,
            "collector_sql_digest": receipt.observation.collector_sql_digest,
            "snapshot_text": receipt.observation.snapshot_text,
        }
    )
    target = PolicyAccessTarget(
        relation=relname,
        policy_id=policy_id,
        occurrence_id=expectation.occurrence_id,
        principal_id=expectation.principal_id,
        context_digest=expectation.context_hash,
        policy_predicate_digest=expectation.policy_definition_digest,
    )
    bindings = tuple(
        sorted(
            (
                implementation_target_binding(
                    template_id=entry.template_id,
                    target=target,
                    rid_col=rid_col,
                    refinement_kind=(
                        "query_filtered"
                        if template_definition(entry.template_id).target_kind
                        == "query_filtered"
                        else None
                    ),
                    refinement_predicate=(
                        query_predicate
                        if template_definition(entry.template_id).target_kind
                        == "query_filtered"
                        else None
                    ),
                )
                for entry in expectation.registry_inventory
            ),
            key=lambda item: item.template_id,
        )
    )
    facts: dict[tuple[str, str], GammaFact] = {}
    evidence_by_fact: dict[str, E10AdmissionEvidence] = {}

    def add_fact(
        kind: str,
        subject_digest: str,
        source_kind: str,
        payload: Mapping[str, Any],
    ) -> GammaFact:
        fact, evidence = _e10_issue_admission_fact(
            kind=kind,
            subject_digest=subject_digest,
            snapshot_id=snapshot_id,
            source_kind=source_kind,
            payload=payload,
        )
        key = (kind, subject_digest)
        existing = facts.get(key)
        if existing is not None and existing != fact:
            raise PostgresError("E10 admission fact identity is ambiguous")
        facts[key] = fact
        evidence_by_fact[fact.fact_id] = evidence
        return fact

    trusted_policy_fact = add_fact(
        "trusted_exact_policy_executable",
        target.digest,
        "trusted_policy_executable",
        {
            "receipt_digest": receipt.receipt_digest,
            "expectation_digest": expectation.digest,
            "policy_manifest_digest": expectation.policy_manifest_digest,
            "policy_config_digest": expectation.policy_config_digest,
            "policy_definition_digest": expectation.policy_definition_digest,
            "rendered_exact_predicate_digest": expectation.exact_predicate_digest,
            "logical_target_digest": target.digest,
        },
    )
    del trusted_policy_fact
    predicate_binding_problem = PlanningProblem(
        relation=relname,
        policy_id=policy_id,
        occurrence_id=expectation.occurrence_id,
        rid_col=rid_col,
        logical_target=target,
        planning_execution_class="diagnostic_only",
    )
    add_fact(
        "exact_policy_predicate_binding",
        policy_predicate_binding_subject(
            predicate_binding_problem,
            exact_predicate,
        ),
        "exact_policy_expression",
        {
            "logical_target_digest": target.digest,
            "policy_definition_digest": expectation.policy_definition_digest,
            "rendered_exact_predicate_digest": expectation.exact_predicate_digest,
            "controlled_predicate_digest": canonical_predicate_digest(exact_predicate),
        },
    )
    exact_safety_proof = _e10_safe_scalar_predicate_proof(
        exact_predicate,
        alias=alias,
    )
    if exact_safety_proof is not None:
        add_fact(
            "exact_policy_safe",
            target.digest,
            "exact_policy_expression",
            {
                "logical_target_digest": target.digest,
                "policy_definition_digest": expectation.policy_definition_digest,
                "rendered_exact_predicate_digest": expectation.exact_predicate_digest,
                "proof": exact_safety_proof,
            },
        )
    query_safety_proof = _e10_safe_scalar_predicate_proof(
        query_predicate,
        alias=alias,
    )
    safe_query_fact: Optional[GammaFact] = None
    if query_safety_proof is not None:
        safe_query_fact = add_fact(
            "safe_query_predicate",
            target.digest,
            "query_predicate_expression",
            {
                "logical_target_digest": target.digest,
                "query_predicate_digest": expectation.query_predicate_digest,
                "proof": query_safety_proof,
            },
        )
    guard_basis = _e10_guard_basis_payload(
        expectation=expectation,
        exact_predicate=exact_predicate,
        guard_predicate=guard_predicate,
        alias=alias,
    )
    if guard_basis is not None:
        common_guard_payload = {
            "logical_target_digest": target.digest,
            "receipt_digest": receipt.receipt_digest,
            "exact_predicate_digest": expectation.exact_predicate_digest,
            "guard_predicate_digest": expectation.guard_predicate_digest,
            "residual_predicate_digest": guard_basis["residual_predicate_digest"],
            "guard_lowering_digest": guard_basis["guard_lowering_digest"],
            "guard_proof": guard_basis["guard_proof"],
            "lowering_payload": guard_basis["lowering_payload"],
        }
        add_fact(
            "complete_candidate_basis",
            target.digest,
            "guard_basis",
            {**common_guard_payload, "claim": "necessary_conjunct"},
        )
        add_fact(
            "trusted_exact_residual_executable",
            target.digest,
            "guard_basis",
            {**common_guard_payload, "claim": "nonempty_exact_residual"},
        )
    artifact_expectation_by_kind = {item.kind: item for item in expectation.artifacts}
    artifact_observation_by_kind = {
        item.kind: item for item in receipt.observation.artifacts
    }
    artifact_fact_by_kind: dict[str, GammaFact] = {}
    obligations: list[E10AdmissionDynamicObligation] = []
    for assessment in receipt.artifact_assessments:
        if not (assessment.declared and assessment.observed and assessment.usable):
            continue
        artifact_expectation = artifact_expectation_by_kind[assessment.kind]
        artifact_observation = artifact_observation_by_kind[assessment.kind]
        fact = add_fact(
            "artifact_validation",
            assessment.artifact_id,
            "artifact_assessment",
            {
                "receipt_digest": receipt.receipt_digest,
                "expectation_digest": expectation.digest,
                "observation_digest": receipt.observation.observation_digest,
                "snapshot_id": snapshot_id,
                "snapshot_text": receipt.observation.snapshot_text,
                "artifact_expectation": artifact_expectation.to_dict(),
                "artifact_observation": artifact_observation.to_dict(),
                "artifact_assessment": assessment.to_dict(),
            },
        )
        artifact_fact_by_kind[assessment.kind] = fact
        obligations.extend(
            E10AdmissionDynamicObligation(
                kind=kind,
                artifact_id=assessment.artifact_id,
                snapshot_id=snapshot_id,
                source_fact_id=fact.fact_id,
            )
            for kind in E10_ADMISSION_DYNAMIC_OBLIGATION_KINDS
        )
    for binding in bindings:
        definition = template_definition(binding.template_id)
        required_artifact_facts = tuple(
            artifact_fact_by_kind.get(kind)
            for kind in sorted(definition.required_artifacts)
        )
        prerequisites = tuple(
            item for item in required_artifact_facts if item is not None
        )
        all_artifacts_valid = len(prerequisites) == len(definition.required_artifacts)
        if binding.refinement_kind == "query_filtered":
            if safe_query_fact is None or not all_artifacts_valid:
                continue
            subject = target_refinement_subject_digest(
                binding,
                target,
                snapshot_id=snapshot_id,
            )
            add_fact(
                "target_refinement",
                subject,
                "implementation_target_binding",
                {
                    "logical_target": target.to_dict(),
                    "logical_target_digest": target.digest,
                    "implementation_binding": binding.to_dict(),
                    "implementation_binding_digest": binding.digest,
                    "query_predicate_digest": expectation.query_predicate_digest,
                    "prerequisite_fact_ids": sorted(
                        [safe_query_fact.fact_id]
                        + [item.fact_id for item in prerequisites]
                    ),
                },
            )
        elif binding.implementation_target_kind != "bare_occurrence":
            if not definition.required_artifacts or not all_artifacts_valid:
                continue
            subject = implementation_target_match_subject_digest(
                binding,
                target,
                snapshot_id=snapshot_id,
            )
            add_fact(
                "implementation_target_match",
                subject,
                "implementation_target_binding",
                {
                    "logical_target": target.to_dict(),
                    "logical_target_digest": target.digest,
                    "implementation_binding": binding.to_dict(),
                    "implementation_binding_digest": binding.digest,
                    "prerequisite_fact_ids": sorted(
                        item.fact_id for item in prerequisites
                    ),
                },
            )
    gamma = GammaSnapshot(
        snapshot_id=snapshot_id,
        facts=tuple(sorted(facts.values(), key=lambda fact: fact.fact_id)),
    )
    evidence = tuple(sorted(evidence_by_fact.values(), key=lambda item: item.fact_id))
    unresolved = tuple(
        sorted(
            obligations,
            key=lambda item: (
                item.artifact_id,
                item.kind,
                item.source_fact_id,
            ),
        )
    )
    draft = E10AdmissionBundle(
        schema_version=E10_ADMISSION_BUNDLE_SCHEMA,
        issuer_version=E10_ADMISSION_ISSUER_VERSION,
        scope=expectation.scope,
        case_query_id=case.query_id,
        receipt_digest=receipt.receipt_digest,
        expectation_digest=expectation.digest,
        observation_digest=receipt.observation.observation_digest,
        collector_sql_digest=receipt.observation.collector_sql_digest,
        observation_snapshot_text=receipt.observation.snapshot_text,
        snapshot_id=snapshot_id,
        registry_inventory=expectation.registry_inventory,
        exact_predicate_digest=expectation.exact_predicate_digest,
        query_predicate_digest=expectation.query_predicate_digest,
        guard_predicate_digest=expectation.guard_predicate_digest,
        residual_predicate_digest=(
            None
            if guard_basis is None
            else str(guard_basis["residual_predicate_digest"])
        ),
        guard_lowering_digest=(
            None if guard_basis is None else str(guard_basis["guard_lowering_digest"])
        ),
        logical_target=target,
        implementation_target_bindings=bindings,
        parent_requirement=_e10_parent_requirement_for_case(case, rid_col),
        gamma_snapshot=gamma,
        evidence=evidence,
        unresolved_dynamic_obligations=unresolved,
        bundle_digest="pending",
    )
    payload = draft.to_dict()
    payload.pop("bundle_digest", None)
    issued = replace(draft, bundle_digest=_canonical_digest(payload))
    canonical = _e10_admission_bundle_from_dict(issued.to_dict())
    return _register_e10_production_source(
        canonical,
        kind="admission_bundle",
        identity_digest=canonical.bundle_digest,
    )


def _replay_e10_admission_bundle(
    bundle: E10AdmissionBundle,
    *,
    root: Path,
    case: E10Case,
    receipt: E10PlanningReceipt,
    expectation: E10PlanningExpectation,
    require_production: bool,
) -> E10AdmissionReplay:
    reasons: list[str] = []
    try:
        canonical = _e10_admission_bundle_from_dict(bundle.to_dict())
    except (TypeError, ValueError) as exc:
        return E10AdmissionReplay(
            schema_version=E10_ADMISSION_REPLAY_SCHEMA,
            valid=False,
            scope=bundle.scope,
            bundle_digest=bundle.bundle_digest,
            receipt_digest=bundle.receipt_digest,
            snapshot_id=bundle.snapshot_id,
            gamma_snapshot_digest=bundle.gamma_snapshot.digest,
            unresolved_dynamic_obligations=(),
            reasons=(f"bundle_malformed:{type(exc).__name__}",),
        )
    try:
        recomputed = _issue_e10_admission_bundle(
            root=root,
            case=case,
            receipt=receipt,
            expectation=expectation,
            require_production=require_production,
        )
    except (PostgresError, TypeError, ValueError) as exc:
        reasons.append(f"bundle_source_replay_failed:{type(exc).__name__}")
        recomputed = None
    if recomputed is None or canonical != recomputed:
        reasons.append("bundle_replay_mismatch")
    if require_production and canonical.scope != "production":
        reasons.append("production_bundle_required")
    if canonical.case_query_id != case.query_id:
        reasons.append("bundle_case_mismatch")
    if canonical.receipt_digest != receipt.receipt_digest:
        reasons.append("bundle_receipt_mismatch")
    if canonical.expectation_digest != expectation.digest:
        reasons.append("bundle_expectation_mismatch")
    unique_reasons = tuple(sorted(set(reasons)))
    return E10AdmissionReplay(
        schema_version=E10_ADMISSION_REPLAY_SCHEMA,
        valid=not unique_reasons,
        scope=canonical.scope,
        bundle_digest=canonical.bundle_digest,
        receipt_digest=canonical.receipt_digest,
        snapshot_id=canonical.snapshot_id,
        gamma_snapshot_digest=canonical.gamma_snapshot.digest,
        unresolved_dynamic_obligations=(
            canonical.unresolved_dynamic_obligations if not unique_reasons else ()
        ),
        reasons=unique_reasons,
    )


def _e10_planning_sql_relation(qualified: str) -> tuple[str, str]:
    if not qualified.startswith("public."):
        raise ValueError("E10 planning artifact relation must use public schema")
    table = qualified.removeprefix("public.")
    if re.fullmatch(r"[a-z_][a-z0-9_]*", table) is None:
        raise ValueError("E10 planning artifact relation identifier is invalid")
    return qualified, table


def _e10_planning_dependency_json_sql(artifact_id: str) -> str:
    return f"""COALESCE(
      (
        SELECT jsonb_agg(
          jsonb_build_object(
            'dep_kind', dependency.dep_kind,
            'dep_name', dependency.dep_name,
            'version_at_build', dependency.version_at_build
          )
          ORDER BY dependency.dep_kind,
                   dependency.dep_name,
                   dependency.version_at_build
        )
        FROM public.artifact_dependencies dependency
        WHERE dependency.artifact_id = {_quote(artifact_id)}
      ),
      '[]'::jsonb
    )"""


def _e10_planning_context_json_sql(artifact_id: str) -> str:
    return f"""COALESCE(
      (
        SELECT jsonb_agg(context_identity ORDER BY context_identity::text)
        FROM (
          SELECT DISTINCT jsonb_build_object(
            'context_hash', context.ctx_hash,
            'principal_id', context.user_id::text,
            'canonical_context', context.canonical_context,
            'version', version.version
          ) AS context_identity
          FROM public.artifact_dependencies dependency
          JOIN public.synthetic_context context
            ON context.ctx_hash = dependency.dep_name
          JOIN public.context_versions version
            ON version.ctx_hash = context.ctx_hash
           AND version.canonical_context = context.canonical_context
          WHERE dependency.artifact_id = {_quote(artifact_id)}
            AND dependency.dep_kind = 'context_scope'
        ) contexts
      ),
      '[]'::jsonb
    )"""


def _e10_planning_scope_json_sql(
    *,
    table: str,
    artifact_id: str,
    keyed: bool,
) -> str:
    key_expr = "row_scope.key_name" if keyed else "NULL::text"
    return f"""COALESCE(
      (
        SELECT jsonb_agg(scope_identity ORDER BY scope_identity::text)
        FROM (
          SELECT DISTINCT jsonb_build_object(
            'policy_id', row_scope.policy_id,
            'principal_id', row_scope.user_id,
            'context_hash', row_scope.ctx_hash,
            'rid_domain_id', row_scope.rid_domain_id,
            'base_relation_oid', row_scope.base_rel_oid::bigint,
            'policy_version', row_scope.policy_version,
            'membership_version', row_scope.membership_version,
            'key_name', {key_expr}
          ) AS scope_identity
          FROM public.{table} row_scope
          WHERE row_scope.artifact_id = {_quote(artifact_id)}
        ) scopes
      ),
      '[]'::jsonb
    )"""


def _e10_planning_set_equal_sql(
    actual_sql: str,
    expected_sql: str,
) -> str:
    return f"""(
      NOT EXISTS (
        ({actual_sql})
        EXCEPT
        ({expected_sql})
      )
      AND NOT EXISTS (
        ({expected_sql})
        EXCEPT
        ({actual_sql})
      )
    )"""


def _e10_selected_artifact_catalog_sql(
    expectation: E10PlanningExpectation,
    *,
    artifact_id: str,
) -> tuple[str, str]:
    """Build a SELECT-only current-H2 observation for one registered artifact."""

    if expectation.scope not in {"production", "fixture"}:
        raise ValueError("E10 selected-artifact collector scope is invalid")
    if re.fullmatch(r"[a-z_][a-z0-9_]*", expectation.relation_name) is None:
        raise ValueError("E10 selected-artifact base relation identifier is invalid")
    if re.fullmatch(r"[a-z_][a-z0-9_]*", expectation.rid_col) is None:
        raise ValueError("E10 selected-artifact RID identifier is invalid")
    alias = {"document": "d", "ticket": "t", "invoice": "i"}.get(
        expectation.relation_name
    )
    if alias is None:
        raise ValueError(
            "E10 selected-artifact target relation is outside the finite workload"
        )
    selected = tuple(
        item for item in expectation.artifacts if item.artifact_id == artifact_id
    )
    if len(selected) != 1:
        raise ValueError("E10 selected-artifact identity is not uniquely registered")
    artifact = selected[0]
    artifact_by_kind = {item.kind: item for item in expectation.artifacts}
    _selected_relation, selected_table = _e10_planning_sql_relation(
        artifact.physical_relation
    )
    rid_expr = f"{alias}.{expectation.rid_col}"
    tenant_expr = f"{alias}.tenant_id"
    expected_rids = f"""SELECT {rid_expr} AS rid
        FROM public.{expectation.relation_name} {alias}
        WHERE {expectation.exact_predicate}"""
    expected_keyed = f"""SELECT {rid_expr} AS rid,
               {_quote(expectation.rid_col)}::text AS key_name,
               {rid_expr}::text AS key_value,
               ({rid_expr} / 1000)::text AS range_bucket
        FROM public.{expectation.relation_name} {alias}
        WHERE {expectation.exact_predicate}"""
    expected_mav = f"""SELECT {rid_expr} AS rid,
               {tenant_expr} AS tenant_id,
               {rid_expr}::text AS sort_key
        FROM public.{expectation.relation_name} {alias}
        WHERE {expectation.exact_predicate}"""

    if artifact.kind == "auth_idx":
        keyed = artifact_by_kind["auth_idx_keyed"]
        _keyed_relation, keyed_table = _e10_planning_sql_relation(
            keyed.physical_relation
        )
        actual = f"""SELECT selected_row.rid
        FROM public.{selected_table} selected_row
        WHERE selected_row.artifact_id = {_quote(artifact.artifact_id)}"""
        artifact_sql = f"""jsonb_build_object(
      'kind', 'auth_idx',
      'artifact_id', {_quote(artifact.artifact_id)},
      'physical_relation', {_quote(artifact.physical_relation)},
      'physical_relation_oid', to_regclass({_quote(artifact.physical_relation)})::oid::bigint,
      'scope_identities', {_e10_planning_scope_json_sql(table=selected_table, artifact_id=artifact.artifact_id, keyed=False)},
      'dependencies', {_e10_planning_dependency_json_sql(artifact.artifact_id)},
      'artifact_contexts', {_e10_planning_context_json_sql(artifact.artifact_id)},
      'duplicate_identity', EXISTS (
        SELECT 1 FROM public.{selected_table} duplicate
        WHERE duplicate.artifact_id = {_quote(artifact.artifact_id)}
        GROUP BY duplicate.rid HAVING count(*) > 1
      ),
      'key_identity_matches', true,
      'content_exact', {_e10_planning_set_equal_sql(actual, expected_rids)},
      'cross_kind_conflict', EXISTS (
        SELECT 1 FROM public.{keyed_table} conflict
        WHERE conflict.artifact_id = {_quote(artifact.artifact_id)}
      )
    )"""
    elif artifact.kind == "auth_idx_keyed":
        auth = artifact_by_kind["auth_idx"]
        _auth_relation, auth_table = _e10_planning_sql_relation(
            auth.physical_relation
        )
        actual = f"""SELECT selected_row.rid,
               selected_row.key_name,
               selected_row.key_value,
               selected_row.range_bucket
        FROM public.{selected_table} selected_row
        WHERE selected_row.artifact_id = {_quote(artifact.artifact_id)}"""
        artifact_sql = f"""jsonb_build_object(
      'kind', 'auth_idx_keyed',
      'artifact_id', {_quote(artifact.artifact_id)},
      'physical_relation', {_quote(artifact.physical_relation)},
      'physical_relation_oid', to_regclass({_quote(artifact.physical_relation)})::oid::bigint,
      'scope_identities', {_e10_planning_scope_json_sql(table=selected_table, artifact_id=artifact.artifact_id, keyed=True)},
      'dependencies', {_e10_planning_dependency_json_sql(artifact.artifact_id)},
      'artifact_contexts', {_e10_planning_context_json_sql(artifact.artifact_id)},
      'duplicate_identity', EXISTS (
        SELECT 1 FROM public.{selected_table} duplicate
        WHERE duplicate.artifact_id = {_quote(artifact.artifact_id)}
        GROUP BY duplicate.rid, duplicate.key_name, duplicate.key_value
        HAVING count(*) > 1
      ),
      'key_identity_matches', NOT EXISTS (
        SELECT 1 FROM public.{selected_table} key_check
        WHERE key_check.artifact_id = {_quote(artifact.artifact_id)}
          AND (
            key_check.key_name IS DISTINCT FROM {_quote(expectation.rid_col)}
            OR key_check.key_value IS DISTINCT FROM key_check.rid::text
            OR key_check.range_bucket IS DISTINCT FROM
               (key_check.rid / 1000)::text
          )
      ),
      'content_exact', {_e10_planning_set_equal_sql(actual, expected_keyed)},
      'cross_kind_conflict', EXISTS (
        SELECT 1 FROM public.{auth_table} conflict
        WHERE conflict.artifact_id = {_quote(artifact.artifact_id)}
      )
    )"""
    elif artifact.kind == "mav":
        auth = artifact_by_kind["auth_idx"]
        keyed = artifact_by_kind["auth_idx_keyed"]
        _auth_relation, auth_table = _e10_planning_sql_relation(
            auth.physical_relation
        )
        _keyed_relation, keyed_table = _e10_planning_sql_relation(
            keyed.physical_relation
        )
        actual = (
            f"SELECT rid, tenant_id, sort_key FROM public.{selected_table}"
        )
        artifact_sql = f"""jsonb_build_object(
      'kind', 'mav',
      'artifact_id', {_quote(artifact.artifact_id)},
      'physical_relation', {_quote(artifact.physical_relation)},
      'physical_relation_oid', to_regclass({_quote(artifact.physical_relation)})::oid::bigint,
      'scope_identities', '[]'::jsonb,
      'dependencies', {_e10_planning_dependency_json_sql(artifact.artifact_id)},
      'artifact_contexts', {_e10_planning_context_json_sql(artifact.artifact_id)},
      'duplicate_identity', EXISTS (
        SELECT 1 FROM public.{selected_table} duplicate
        GROUP BY duplicate.rid HAVING count(*) > 1
      ),
      'key_identity_matches', true,
      'content_exact', {_e10_planning_set_equal_sql(actual, expected_mav)},
      'cross_kind_conflict', (
        EXISTS (
          SELECT 1 FROM public.{auth_table} conflict
          WHERE conflict.artifact_id = {_quote(artifact.artifact_id)}
        )
        OR EXISTS (
          SELECT 1 FROM public.{keyed_table} conflict
          WHERE conflict.artifact_id = {_quote(artifact.artifact_id)}
        )
      )
    )"""
    else:
        raise ValueError("E10 selected-artifact kind is invalid")

    digest_marker = "sha256:__E10_SELECTED_ARTIFACT_COLLECTOR_SQL_DIGEST__"
    template = f"""SELECT jsonb_build_object(
  'schema_version', {_quote(E10_SELECTED_ARTIFACT_OBSERVATION_SCHEMA)},
  'collector_version', {_quote(E10_SELECTED_ARTIFACT_COLLECTOR_VERSION)},
  'collector_sql_digest', {_quote(digest_marker)},
  'scope', {_quote(expectation.scope)},
  'session_user', session_user,
  'current_user', current_user,
  'search_path', current_setting('search_path'),
  'row_security', current_setting('row_security'),
  'isolation_level', current_setting('transaction_isolation'),
  'snapshot_text', pg_current_snapshot()::text,
  'case_query_id', {_quote(expectation.case_query_id)},
  'occurrence_id', {_quote(expectation.occurrence_id)},
  'relation_name', {_quote(expectation.relation_name)},
  'relation_oid', to_regclass({_quote(f'public.{expectation.relation_name}')})::oid::bigint,
  'rid_domain_id', {_quote(expectation.rid_domain_id)},
  'policy_id', {_quote(expectation.policy_id)},
  'principal_id', {_quote(expectation.principal_id)},
  'context_id', target_context.context_id,
  'context_hash', target_context.ctx_hash,
  'canonical_context', target_context.canonical_context,
  'context_version', target_context.version,
  'current_base_version', (
    SELECT version FROM public.base_versions
    WHERE relname = {_quote(expectation.relation_name)}
  ),
  'current_membership_version', (
    SELECT version FROM public.membership_versions
    WHERE scope_name = 'group_membership'
  ),
  'artifact', {artifact_sql}
)::text
FROM (
  SELECT context.context_id,
         context.ctx_hash,
         context.canonical_context,
         version.version
  FROM public.synthetic_context context
  JOIN public.context_versions version
    ON version.ctx_hash = context.ctx_hash
   AND version.canonical_context = context.canonical_context
  WHERE context.context_id = {_quote(expectation.context_id)}
) target_context"""
    collector_digest = _canonical_digest({"collector_sql_template": template})
    return template.replace(digest_marker, collector_digest), collector_digest


def _e10_planning_collector_sql(
    expectation: E10PlanningExpectation,
) -> tuple[str, str]:
    if expectation.scope not in {"production", "fixture"}:
        raise ValueError("E10 planning collector scope is invalid")
    if re.fullmatch(r"[a-z_][a-z0-9_]*", expectation.relation_name) is None:
        raise ValueError("E10 planning base relation identifier is invalid")
    if re.fullmatch(r"[a-z_][a-z0-9_]*", expectation.rid_col) is None:
        raise ValueError("E10 planning RID identifier is invalid")
    alias = {"document": "d", "ticket": "t", "invoice": "i"}.get(
        expectation.relation_name
    )
    if alias is None:
        raise ValueError("E10 planning target relation is outside the finite workload")
    artifact_by_kind = {item.kind: item for item in expectation.artifacts}
    auth = artifact_by_kind["auth_idx"]
    keyed = artifact_by_kind["auth_idx_keyed"]
    mav = artifact_by_kind["mav"]
    _auth_relation, auth_table = _e10_planning_sql_relation(auth.physical_relation)
    _keyed_relation, keyed_table = _e10_planning_sql_relation(keyed.physical_relation)
    _mav_relation, mav_table = _e10_planning_sql_relation(mav.physical_relation)
    rid_expr = f"{alias}.{expectation.rid_col}"
    tenant_expr = f"{alias}.tenant_id"
    expected_rids = f"""SELECT {rid_expr} AS rid
        FROM public.{expectation.relation_name} {alias}
        WHERE {expectation.exact_predicate}"""
    expected_keyed = f"""SELECT {rid_expr} AS rid,
               {_quote(expectation.rid_col)}::text AS key_name,
               {rid_expr}::text AS key_value,
               ({rid_expr} / 1000)::text AS range_bucket
        FROM public.{expectation.relation_name} {alias}
        WHERE {expectation.exact_predicate}"""
    expected_mav = f"""SELECT {rid_expr} AS rid,
               {tenant_expr} AS tenant_id,
               {rid_expr}::text AS sort_key
        FROM public.{expectation.relation_name} {alias}
        WHERE {expectation.exact_predicate}"""
    auth_actual = f"""SELECT artifact.rid
        FROM public.{auth_table} artifact
        WHERE artifact.artifact_id = {_quote(auth.artifact_id)}"""
    keyed_actual = f"""SELECT artifact.rid,
               artifact.key_name,
               artifact.key_value,
               artifact.range_bucket
        FROM public.{keyed_table} artifact
        WHERE artifact.artifact_id = {_quote(keyed.artifact_id)}"""
    mav_actual = f"SELECT rid, tenant_id, sort_key FROM public.{mav_table}"
    digest_marker = "sha256:__E10_PLANNING_COLLECTOR_SQL_DIGEST__"
    template = f"""
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL search_path TO pg_catalog, public;
SET LOCAL row_security = on;
SELECT jsonb_build_object(
  'schema_version', {_quote(E10_PLANNING_OBSERVATION_SCHEMA)},
  'collector_version', {_quote(E10_PLANNING_COLLECTOR_VERSION)},
  'collector_sql_digest', {_quote(digest_marker)},
  'scope', {_quote(expectation.scope)},
  'session_user', session_user,
  'current_user', current_user,
  'search_path', current_setting('search_path'),
  'row_security', current_setting('row_security'),
  'isolation_level', current_setting('transaction_isolation'),
  'snapshot_text', pg_current_snapshot()::text,
  'case_query_id', {_quote(expectation.case_query_id)},
  'occurrence_id', {_quote(expectation.occurrence_id)},
  'relation_name', {_quote(expectation.relation_name)},
  'relation_oid', to_regclass({_quote(f'public.{expectation.relation_name}')})::oid::bigint,
  'rid_domain_id', {_quote(expectation.rid_domain_id)},
  'policy_id', {_quote(expectation.policy_id)},
  'principal_id', {_quote(expectation.principal_id)},
  'context_id', target_context.context_id,
  'context_hash', target_context.ctx_hash,
  'canonical_context', target_context.canonical_context,
  'context_version', target_context.version,
  'current_base_version', (
    SELECT version FROM public.base_versions
    WHERE relname = {_quote(expectation.relation_name)}
  ),
  'current_membership_version', (
    SELECT version FROM public.membership_versions
    WHERE scope_name = 'group_membership'
  ),
  'artifacts', jsonb_build_array(
    jsonb_build_object(
      'kind', 'auth_idx',
      'artifact_id', {_quote(auth.artifact_id)},
      'physical_relation', {_quote(auth.physical_relation)},
      'physical_relation_oid', to_regclass({_quote(auth.physical_relation)})::oid::bigint,
      'scope_identities', {_e10_planning_scope_json_sql(table=auth_table, artifact_id=auth.artifact_id, keyed=False)},
      'dependencies', {_e10_planning_dependency_json_sql(auth.artifact_id)},
      'artifact_contexts', {_e10_planning_context_json_sql(auth.artifact_id)},
      'duplicate_identity', EXISTS (
        SELECT 1 FROM public.{auth_table} duplicate
        WHERE duplicate.artifact_id = {_quote(auth.artifact_id)}
        GROUP BY duplicate.rid HAVING count(*) > 1
      ),
      'key_identity_matches', true,
      'content_exact', {_e10_planning_set_equal_sql(auth_actual, expected_rids)},
      'cross_kind_conflict', EXISTS (
        SELECT 1 FROM public.{keyed_table} conflict
        WHERE conflict.artifact_id = {_quote(auth.artifact_id)}
      )
    ),
    jsonb_build_object(
      'kind', 'auth_idx_keyed',
      'artifact_id', {_quote(keyed.artifact_id)},
      'physical_relation', {_quote(keyed.physical_relation)},
      'physical_relation_oid', to_regclass({_quote(keyed.physical_relation)})::oid::bigint,
      'scope_identities', {_e10_planning_scope_json_sql(table=keyed_table, artifact_id=keyed.artifact_id, keyed=True)},
      'dependencies', {_e10_planning_dependency_json_sql(keyed.artifact_id)},
      'artifact_contexts', {_e10_planning_context_json_sql(keyed.artifact_id)},
      'duplicate_identity', EXISTS (
        SELECT 1 FROM public.{keyed_table} duplicate
        WHERE duplicate.artifact_id = {_quote(keyed.artifact_id)}
        GROUP BY duplicate.rid, duplicate.key_name, duplicate.key_value
        HAVING count(*) > 1
      ),
      'key_identity_matches', NOT EXISTS (
        SELECT 1 FROM public.{keyed_table} key_check
        WHERE key_check.artifact_id = {_quote(keyed.artifact_id)}
          AND (
            key_check.key_name IS DISTINCT FROM {_quote(expectation.rid_col)}
            OR key_check.key_value IS DISTINCT FROM key_check.rid::text
            OR key_check.range_bucket IS DISTINCT FROM
               (key_check.rid / 1000)::text
          )
      ),
      'content_exact', {_e10_planning_set_equal_sql(keyed_actual, expected_keyed)},
      'cross_kind_conflict', EXISTS (
        SELECT 1 FROM public.{auth_table} conflict
        WHERE conflict.artifact_id = {_quote(keyed.artifact_id)}
      )
    ),
    jsonb_build_object(
      'kind', 'mav',
      'artifact_id', {_quote(mav.artifact_id)},
      'physical_relation', {_quote(mav.physical_relation)},
      'physical_relation_oid', to_regclass({_quote(mav.physical_relation)})::oid::bigint,
      'scope_identities', '[]'::jsonb,
      'dependencies', {_e10_planning_dependency_json_sql(mav.artifact_id)},
      'artifact_contexts', {_e10_planning_context_json_sql(mav.artifact_id)},
      'duplicate_identity', EXISTS (
        SELECT 1 FROM public.{mav_table} duplicate
        GROUP BY duplicate.rid HAVING count(*) > 1
      ),
      'key_identity_matches', true,
      'content_exact', {_e10_planning_set_equal_sql(mav_actual, expected_mav)},
      'cross_kind_conflict', (
        EXISTS (
          SELECT 1 FROM public.{auth_table} conflict
          WHERE conflict.artifact_id = {_quote(mav.artifact_id)}
        )
        OR EXISTS (
          SELECT 1 FROM public.{keyed_table} conflict
          WHERE conflict.artifact_id = {_quote(mav.artifact_id)}
        )
      )
    )
  )
)::text
FROM (
  SELECT context.context_id,
         context.ctx_hash,
         context.canonical_context,
         version.version
  FROM public.synthetic_context context
  JOIN public.context_versions version
    ON version.ctx_hash = context.ctx_hash
   AND version.canonical_context = context.canonical_context
  WHERE context.context_id = {_quote(expectation.context_id)}
) target_context;
COMMIT;
"""
    collector_digest = _canonical_digest({"collector_sql_template": template})
    return template.replace(digest_marker, collector_digest), collector_digest


def _collect_e10_planning_catalog_observation(
    expectation: E10PlanningExpectation,
    pg_env: PostgresEnv,
) -> tuple[E10PlanningCatalogObservation, str]:
    sql, collector_digest = _e10_planning_collector_sql(expectation)
    payload = _last_json_object(
        run_psql_command(sql, pg_env),
        label="E10 planning catalog observation",
    )
    try:
        observation = _issue_e10_planning_catalog_observation(payload)
    except (TypeError, ValueError) as exc:
        raise PostgresError("E10 planning catalog observation is malformed") from exc
    if observation.collector_sql_digest != collector_digest:
        raise PostgresError("E10 planning collector SQL digest mismatch")
    return observation, collector_digest


def _artifact_dependency_values(
    artifact_id: str,
    policy_id: str,
    ctx_hash: str,
    relname: str,
    rid_col: str,
) -> str:
    deps = [
        ("policy", policy_id, 0),
        ("membership", "group_membership", 0),
        ("base", relname, 0),
        ("context_scope", ctx_hash, 0),
        ("rid_domain", f"{relname}.{rid_col}", 0),
    ]
    return ",\n".join(
        f"({_quote(artifact_id)}, {_quote(kind)}, {_quote(name)}, {version})"
        for kind, name, version in deps
    )


def _e10_state_dependency_values(
    spec: E10NegativeStateSpec,
) -> str:
    base_relation = f"public.{spec.relation}"
    return ",\n".join(
        (
            f"({_quote(spec.artifact_id)}, 'artifact_kind', 'mav', 0)",
            f"({_quote(spec.artifact_id)}, 'artifact_relation', {_quote(spec.physical_relation)}, "
            f"{_quote(spec.physical_relation)}::regclass::oid::bigint)",
            f"({_quote(spec.artifact_id)}, 'base', {_quote(spec.relation)}, "
            "(SELECT version FROM public.base_versions "
            f"WHERE relname = {_quote(spec.relation)}))",
            f"({_quote(spec.artifact_id)}, 'base_relation_oid', {_quote(base_relation)}, "
            f"{_quote(base_relation)}::regclass::oid::bigint)",
            f"({_quote(spec.artifact_id)}, 'context_scope', {_quote(spec.build_context_hash)}, "
            "(SELECT version FROM public.context_versions "
            f"WHERE ctx_hash = {_quote(spec.build_context_hash)}))",
            f"({_quote(spec.artifact_id)}, 'membership', 'group_membership', "
            "(SELECT version FROM public.membership_versions "
            "WHERE scope_name = 'group_membership'))",
            f"({_quote(spec.artifact_id)}, 'policy', {_quote(spec.policy_id)}, 0)",
            f"({_quote(spec.artifact_id)}, 'principal', {_quote(spec.build_principal_id)}, 0)",
            f"({_quote(spec.artifact_id)}, 'rid_domain', "
            f"{_quote(f'{spec.relation}.{spec.rid_col}')}, 0)",
        )
    )


def _artifact_dependency_expected_json(
    policy_id: str, ctx_hash: str, relname: str, rid_col: str
) -> str:
    expected = [
        {"dep_kind": "policy", "dep_name": policy_id, "version_at_build": 0},
        {
            "dep_kind": "membership",
            "dep_name": "group_membership",
            "version_at_build": 0,
        },
        {"dep_kind": "base", "dep_name": relname, "version_at_build": 0},
        {"dep_kind": "context_scope", "dep_name": ctx_hash, "version_at_build": 0},
        {
            "dep_kind": "rid_domain",
            "dep_name": f"{relname}.{rid_col}",
            "version_at_build": 0,
        },
    ]
    return json.dumps(expected, sort_keys=True, separators=(",", ":"))


def _build_auth_idx_sql(
    artifact_id: str,
    policy_id: str,
    user_id: str,
    ctx_hash: str,
    relname: str,
    rid_col: str,
    alias: str,
    exact_predicate: str,
) -> str:
    return f"""
\\set ON_ERROR_STOP on
BEGIN;
DELETE FROM public.artifact_dependencies WHERE artifact_id = {_quote(artifact_id)};
DELETE FROM public.auth_idx WHERE artifact_id = {_quote(artifact_id)};
INSERT INTO public.artifact_dependencies(artifact_id, dep_kind, dep_name, version_at_build)
VALUES
{_artifact_dependency_values(
    artifact_id,
    policy_id,
    ctx_hash,
    relname,
    rid_col,
)};
INSERT INTO public.auth_idx(
  artifact_id, policy_id, user_id, ctx_hash, rid, rid_domain_id, base_rel_oid,
  policy_version, membership_version
)
SELECT
  {_quote(artifact_id)},
  {_quote(policy_id)},
  {_quote(user_id)},
  {_quote(ctx_hash)},
  {alias}.{rid_col},
  {_quote(f"{relname}.{rid_col}")},
  {_quote(f"public.{relname}")}::regclass::oid,
  0,
  0
FROM public.{relname} {alias}
WHERE {exact_predicate};
COMMIT;
ANALYZE public.auth_idx;
"""


def _build_keyed_sql(
    artifact_id: str,
    policy_id: str,
    user_id: str,
    ctx_hash: str,
    relname: str,
    rid_col: str,
    alias: str,
    exact_predicate: str,
) -> str:
    return f"""
\\set ON_ERROR_STOP on
BEGIN;
DELETE FROM public.artifact_dependencies WHERE artifact_id = {_quote(artifact_id)};
DELETE FROM public.auth_idx_keyed WHERE artifact_id = {_quote(artifact_id)};
INSERT INTO public.artifact_dependencies(artifact_id, dep_kind, dep_name, version_at_build)
VALUES
{_artifact_dependency_values(
    artifact_id,
    policy_id,
    ctx_hash,
    relname,
    rid_col,
)};
INSERT INTO public.auth_idx_keyed(
  artifact_id, policy_id, user_id, ctx_hash, key_name, key_value, range_bucket,
  rid, rid_domain_id, base_rel_oid, policy_version, membership_version
)
SELECT
  {_quote(artifact_id)},
  {_quote(policy_id)},
  {_quote(user_id)},
  {_quote(ctx_hash)},
  {_quote(rid_col)},
  {alias}.{rid_col}::text,
  ({alias}.{rid_col} / 1000)::text,
  {alias}.{rid_col},
  {_quote(f"{relname}.{rid_col}")},
  {_quote(f"public.{relname}")}::regclass::oid,
  0,
  0
FROM public.{relname} {alias}
WHERE {exact_predicate};
COMMIT;
ANALYZE public.auth_idx_keyed;
"""


def _mav_table(relname: str, context_id: str = "ctx_000001") -> str:
    return f"e10_mav_{relname}_{_identifier_suffix(context_id)}"


def _e10_mav_logical_rid_upgrade_sql(table: str, rid_col: str) -> str:
    if (
        re.fullmatch(r"[a-z_][a-z0-9_]*", table) is None
        or re.fullmatch(r"[a-z_][a-z0-9_]*", rid_col) is None
        or rid_col == "rid"
    ):
        raise ValueError("E10 MAV logical RID upgrade identity is invalid")
    return f"""ALTER TABLE public.{table}
  DROP COLUMN IF EXISTS {rid_col};
ALTER TABLE public.{table}
  ADD COLUMN {rid_col}
  bigint GENERATED ALWAYS AS (rid) STORED NOT NULL UNIQUE;"""


def _build_mav_sql(
    artifact_id: str,
    policy_id: str,
    ctx_hash: str,
    relname: str,
    rid_col: str,
    alias: str,
    exact_predicate: str,
    context_id: str = "ctx_000001",
) -> str:
    table = _mav_table(relname, context_id)
    tenant_expr = (
        f"{alias}.tenant_id" if relname in {"document", "ticket", "invoice"} else "0"
    )
    logical_rid_upgrade = _e10_mav_logical_rid_upgrade_sql(table, rid_col)
    return f"""
\\set ON_ERROR_STOP on
BEGIN;
CREATE TABLE IF NOT EXISTS public.{table} (
  rid bigint PRIMARY KEY,
  tenant_id bigint NOT NULL,
  sort_key text NOT NULL
);
{logical_rid_upgrade}
DELETE FROM public.artifact_dependencies WHERE artifact_id = {_quote(artifact_id)};
TRUNCATE public.{table};
INSERT INTO public.artifact_dependencies(artifact_id, dep_kind, dep_name, version_at_build)
VALUES
{_artifact_dependency_values(
    artifact_id,
    policy_id,
    ctx_hash,
    relname,
    rid_col,
)};
INSERT INTO public.{table}(rid, tenant_id, sort_key)
SELECT {alias}.{rid_col}, {tenant_expr}, {alias}.{rid_col}::text
FROM public.{relname} {alias}
WHERE {exact_predicate};
COMMIT;
ANALYZE public.{table};
"""


def _e10_state_table_name(spec: E10NegativeStateSpec) -> str:
    prefix = "public."
    if not spec.physical_relation.startswith(prefix):
        raise ValueError("E10 state relation must be in the public schema")
    table = spec.physical_relation[len(prefix) :]
    if re.fullmatch(r"[a-z_][a-z0-9_]*", table) is None:
        raise ValueError("E10 state relation identifier is invalid")
    return table


def _e10_context_assertion_sql(spec: E10NegativeStateSpec) -> str:
    return f"""
  IF NOT EXISTS (
    SELECT 1
    FROM public.synthetic_context context
    JOIN public.context_versions version
      ON version.ctx_hash = context.ctx_hash
     AND version.canonical_context = context.canonical_context
    WHERE context.context_id = {_quote(spec.target_context_id)}
      AND context.ctx_hash = {_quote(spec.target_context_hash)}
      AND context.user_id::text = {_quote(spec.target_principal_id)}
      AND context.canonical_context = {_quote(spec.target_context_payload_json)}::jsonb
      AND version.version = {spec.target_context_version}
  ) THEN
    RAISE EXCEPTION 'E10 target context changed before state materialization';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.synthetic_context context
    JOIN public.context_versions version
      ON version.ctx_hash = context.ctx_hash
     AND version.canonical_context = context.canonical_context
    WHERE context.context_id = {_quote(spec.build_context_id)}
      AND context.ctx_hash = {_quote(spec.build_context_hash)}
      AND context.user_id::text = {_quote(spec.build_principal_id)}
      AND context.canonical_context = {_quote(spec.build_context_payload_json)}::jsonb
      AND version.version = {spec.build_context_version}
  ) THEN
    RAISE EXCEPTION 'E10 build context changed before state materialization';
  END IF;
"""


def _e10_membership_witness_select_sql(spec: E10NegativeStateSpec) -> str:
    return f"""
WITH eligible_grants AS MATERIALIZED (
  SELECT DISTINCT document.doc_id AS witness_rid,
         membership.user_id,
         membership.group_id,
         membership.membership_version
  FROM public.document document
  JOIN public.share_acl acl
    ON acl.rid = document.doc_id
   AND acl.relname = 'document'
   AND acl.permission IN ('read', 'owner')
   AND TIMESTAMPTZ '2026-06-01 00:00:00+00'
       BETWEEN acl.valid_from AND acl.valid_to
  JOIN public.group_membership membership
    ON membership.group_id = acl.group_id
  WHERE membership.user_id = {_quote(spec.target_principal_id)}::bigint
    AND document.tenant_id <> (
      {_quote(spec.target_context_payload_json)}::jsonb ->> 'tenant_id'
    )::bigint
    AND document.owner_id <> {_quote(spec.target_principal_id)}::bigint
    AND document.public = false
),
unique_witness AS MATERIALIZED (
  SELECT grant_row.witness_rid
  FROM eligible_grants grant_row
  GROUP BY grant_row.witness_rid
  HAVING count(DISTINCT grant_row.group_id) = 1
  ORDER BY grant_row.witness_rid
  LIMIT 1
)
SELECT grant_row.user_id,
       grant_row.group_id,
       grant_row.membership_version,
       grant_row.witness_rid,
       1::bigint AS group_grant_count
FROM eligible_grants grant_row
JOIN unique_witness witness USING (witness_rid)
ORDER BY grant_row.group_id
LIMIT 1
"""


def _e10_negative_state_build_sql(spec: E10NegativeStateSpec) -> str:
    table = _e10_state_table_name(spec)
    tenant_expr = f"{spec.alias}.tenant_id"
    base_backup_sql = (
        "CREATE TEMP TABLE e10_state_base_backup ON COMMIT DROP AS\n"
        "SELECT document.doc_id AS rid, document.payload\n"
        "FROM public.document document\n"
        "ORDER BY document.doc_id\nLIMIT 1;"
        if spec.state_kind == "base_epoch_advanced"
        else (
            "CREATE TEMP TABLE e10_state_base_backup(rid bigint, payload jsonb) "
            "ON COMMIT DROP;"
        )
    )
    witness_sql = (
        "CREATE TEMP TABLE e10_state_membership_witness ON COMMIT DROP AS\n"
        + _e10_membership_witness_select_sql(spec).strip()
        + ";"
        if spec.state_kind == "membership_epoch_advanced"
        else (
            "CREATE TEMP TABLE e10_state_membership_witness("
            "user_id bigint, group_id bigint, membership_version bigint, "
            "witness_rid bigint, group_grant_count bigint) ON COMMIT DROP;"
        )
    )
    return f"""
BEGIN ISOLATION LEVEL REPEATABLE READ;
SET LOCAL search_path TO pg_catalog, public;
SET LOCAL row_security = on;
DO $$
BEGIN
  IF to_regclass({_quote(spec.physical_relation)}) IS NOT NULL THEN
    RAISE EXCEPTION 'E10 state relation already exists';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.artifact_dependencies
    WHERE artifact_id = {_quote(spec.artifact_id)}
  ) THEN
    RAISE EXCEPTION 'E10 state artifact identity already exists';
  END IF;
{_e10_context_assertion_sql(spec)}
  IF (SELECT count(*) FROM public.base_versions WHERE relname = {_quote(spec.relation)}) <> 1 THEN
    RAISE EXCEPTION 'E10 base epoch is missing or ambiguous';
  END IF;
  IF (
    SELECT count(*)
    FROM public.membership_versions
    WHERE scope_name = 'group_membership'
  ) <> 1 THEN
    RAISE EXCEPTION 'E10 membership epoch is missing or ambiguous';
  END IF;
END;
$$;
{base_backup_sql}
{witness_sql}
DO $$
BEGIN
  IF {_quote(spec.state_kind)} = 'base_epoch_advanced'
     AND (SELECT count(*) FROM e10_state_base_backup) <> 1 THEN
    RAISE EXCEPTION 'E10 base backup cardinality is not one';
  END IF;
  IF {_quote(spec.state_kind)} = 'membership_epoch_advanced'
     AND (
       (SELECT count(*) FROM e10_state_membership_witness) <> 1
       OR (SELECT group_grant_count FROM e10_state_membership_witness) <> 1
     ) THEN
    RAISE EXCEPTION 'E10 membership witness cardinality is not one';
  END IF;
END;
$$;
CREATE TABLE public.{table} (
  rid bigint PRIMARY KEY,
  {spec.rid_col} bigint GENERATED ALWAYS AS (rid) STORED NOT NULL UNIQUE,
  tenant_id bigint NOT NULL,
  sort_key text NOT NULL
);
INSERT INTO public.artifact_dependencies(
  artifact_id, dep_kind, dep_name, version_at_build
)
VALUES
{_e10_state_dependency_values(spec)};
INSERT INTO public.{table}(rid, tenant_id, sort_key)
SELECT {spec.alias}.{spec.rid_col},
       {tenant_expr},
       {spec.alias}.{spec.rid_col}::text
FROM public.{spec.relation} {spec.alias}
WHERE {spec.exact_predicate};
SELECT jsonb_build_object(
  'case_query_id', {_quote(spec.case_query_id)},
  'state_kind', {_quote(spec.state_kind)},
  'artifact_id', {_quote(spec.artifact_id)},
  'physical_relation', {_quote(spec.physical_relation)},
  'artifact_absent_before', true,
  'physical_relation_absent_before', true,
  'base_version', (
    SELECT version FROM public.base_versions WHERE relname = {_quote(spec.relation)}
  ),
  'membership_version', (
    SELECT version FROM public.membership_versions
    WHERE scope_name = 'group_membership'
  ),
  'target_context', jsonb_build_object(
    'context_id', {_quote(spec.target_context_id)},
    'ctx_hash', {_quote(spec.target_context_hash)},
    'principal_id', {_quote(spec.target_principal_id)},
    'canonical_context', {_quote(spec.target_context_payload_json)}::jsonb,
    'version', {spec.target_context_version}
  ),
  'build_context', jsonb_build_object(
    'context_id', {_quote(spec.build_context_id)},
    'ctx_hash', {_quote(spec.build_context_hash)},
    'principal_id', {_quote(spec.build_principal_id)},
    'canonical_context', {_quote(spec.build_context_payload_json)}::jsonb,
    'version', {spec.build_context_version}
  ),
  'base_row', (
    SELECT jsonb_build_object('rid', rid, 'payload', payload)
    FROM e10_state_base_backup
  ),
  'membership_witness', (
    SELECT jsonb_build_object(
      'user_id', user_id,
      'group_id', group_id,
      'membership_version', membership_version,
      'witness_rid', witness_rid,
      'group_grant_count', group_grant_count
    )
    FROM e10_state_membership_witness
  )
)::text;
COMMIT;
"""


_E10_BASELINE_FIELDS = {
    "case_query_id",
    "state_kind",
    "artifact_id",
    "physical_relation",
    "artifact_absent_before",
    "physical_relation_absent_before",
    "base_version",
    "membership_version",
    "target_context",
    "build_context",
    "base_row",
    "membership_witness",
}


def _parse_e10_materialization_baseline(
    payload: Any,
    spec: E10NegativeStateSpec,
) -> str:
    if not isinstance(payload, Mapping):
        raise PostgresError("E10 materialization baseline must be an object")
    _strict_e10_state_keys(payload, _E10_BASELINE_FIELDS, label="state_baseline")
    if payload["case_query_id"] != spec.case_query_id:
        raise PostgresError("E10 materialization baseline case mismatch")
    if payload["state_kind"] != spec.state_kind:
        raise PostgresError("E10 materialization baseline kind mismatch")
    if payload["artifact_id"] != spec.artifact_id:
        raise PostgresError("E10 materialization baseline artifact mismatch")
    if payload["physical_relation"] != spec.physical_relation:
        raise PostgresError("E10 materialization baseline relation mismatch")
    if payload["artifact_absent_before"] is not True:
        raise PostgresError("E10 materialization artifact identity was not clean")
    if payload["physical_relation_absent_before"] is not True:
        raise PostgresError("E10 materialization relation identity was not clean")
    for key in ("base_version", "membership_version"):
        value = payload[key]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise PostgresError(f"E10 materialization {key} is invalid")
    for key, expected in (
        (
            "target_context",
            {
                "context_id": spec.target_context_id,
                "ctx_hash": spec.target_context_hash,
                "principal_id": spec.target_principal_id,
                "canonical_context": json.loads(spec.target_context_payload_json),
                "version": spec.target_context_version,
            },
        ),
        (
            "build_context",
            {
                "context_id": spec.build_context_id,
                "ctx_hash": spec.build_context_hash,
                "principal_id": spec.build_principal_id,
                "canonical_context": json.loads(spec.build_context_payload_json),
                "version": spec.build_context_version,
            },
        ),
    ):
        if payload[key] != expected:
            raise PostgresError(f"E10 materialization {key} changed")
    base_row = payload["base_row"]
    if spec.state_kind == "base_epoch_advanced":
        if not isinstance(base_row, Mapping):
            raise PostgresError("E10 base state lacks its recovery row")
        _strict_e10_state_keys(base_row, {"rid", "payload"}, label="base_row")
        if (
            not isinstance(base_row["rid"], int)
            or isinstance(base_row["rid"], bool)
            or base_row["rid"] <= 0
        ):
            raise PostgresError("E10 base recovery RID is invalid")
        if not isinstance(base_row["payload"], Mapping):
            raise PostgresError("E10 base recovery payload is invalid")
    elif base_row is not None:
        raise PostgresError("E10 non-base state unexpectedly carries a base row")
    witness = payload["membership_witness"]
    if spec.state_kind == "membership_epoch_advanced":
        if not isinstance(witness, Mapping):
            raise PostgresError("E10 membership state lacks its recovery witness")
        _strict_e10_state_keys(
            witness,
            {
                "user_id",
                "group_id",
                "membership_version",
                "witness_rid",
                "group_grant_count",
            },
            label="membership_witness",
        )
        if any(
            not isinstance(witness[key], int) or isinstance(witness[key], bool)
            for key in witness
        ):
            raise PostgresError("E10 membership witness identity is invalid")
        if (
            any(witness[key] <= 0 for key in ("user_id", "group_id", "witness_rid"))
            or witness["membership_version"] < 0
        ):
            raise PostgresError("E10 membership witness identity is invalid")
        if witness["group_grant_count"] != 1:
            raise PostgresError("E10 membership witness grant count is not one")
        if str(witness["user_id"]) != spec.target_principal_id:
            raise PostgresError("E10 membership witness principal mismatch")
    elif witness is not None:
        raise PostgresError("E10 non-membership state unexpectedly carries a witness")
    return _canonical_json(payload)


def _e10_state_marker(spec: E10NegativeStateSpec) -> str:
    return _canonical_digest(
        {"case_query_id": spec.case_query_id, "artifact_id": spec.artifact_id}
    )


def _e10_expected_mutated_payload_json(
    spec: E10NegativeStateSpec,
    baseline: Mapping[str, Any],
) -> str:
    base_row = baseline.get("base_row")
    if not isinstance(base_row, Mapping) or not isinstance(
        base_row.get("payload"), Mapping
    ):
        raise PostgresError("E10 base mutation lacks a canonical recovery payload")
    payload = dict(base_row["payload"])
    payload["caprls_state_epoch"] = _e10_state_marker(spec)
    return _canonical_json(payload)


def _e10_expected_negative_observation(
    spec: E10NegativeStateSpec,
    built_observation: E10ArtifactStateObservation,
) -> E10ArtifactStateObservation:
    payload = built_observation.to_dict()
    raw = {key: payload[key] for key in _E10_STATE_RAW_FIELDS}
    if spec.state_kind == "base_epoch_advanced":
        if built_observation.current_base_version is None:
            raise PostgresError("E10 base epoch is missing before state transition")
        raw["current_base_version"] = built_observation.current_base_version + 1
    elif spec.state_kind == "membership_epoch_advanced":
        if built_observation.current_membership_version is None:
            raise PostgresError(
                "E10 membership epoch is missing before state transition"
            )
        raw["current_membership_version"] = (
            built_observation.current_membership_version + 1
        )
    elif spec.state_kind != "alternate_context":
        raise PostgresError("E10 state transition kind is unknown")
    return _issue_e10_artifact_state_observation(raw)


def _assert_e10_observation_guardable(
    spec: E10NegativeStateSpec,
    observation: E10ArtifactStateObservation,
) -> None:
    dependencies, complete = _dependency_by_kind(observation)
    expected = spec.expectation
    if not complete or len(observation.dependencies) != len(E10_STATE_DEPENDENCY_KINDS):
        raise PostgresError("E10 state observation lacks an exact dependency set")
    if not all(
        (
            observation.artifact_id == spec.artifact_id,
            observation.physical_relation_oid is not None,
            observation.base_relation_oid is not None,
            observation.target_context_principal_id == spec.target_principal_id,
            observation.target_context_payload_json == spec.target_context_payload_json,
            observation.target_context_version == spec.target_context_version,
            observation.artifact_context_principal_id == spec.build_principal_id,
            observation.artifact_context_payload_json
            == spec.build_context_payload_json,
            observation.artifact_context_version == spec.build_context_version,
            observation.current_base_version is not None,
            observation.current_membership_version is not None,
        )
    ):
        raise PostgresError("E10 state observation is not bound to the lifecycle spec")
    required_names = {
        "artifact_kind": "mav",
        "artifact_relation": spec.physical_relation,
        "base": spec.relation,
        "base_relation_oid": f"public.{spec.relation}",
        "context_scope": spec.build_context_hash,
        "membership": "group_membership",
        "policy": spec.policy_id,
        "principal": spec.build_principal_id,
        "rid_domain": f"{spec.relation}.{spec.rid_col}",
    }
    if any(
        dependencies[kind].dep_name != name for kind, name in required_names.items()
    ):
        raise PostgresError("E10 state observation dependency identity mismatch")
    if (
        dependencies["artifact_relation"].version_at_build
        != observation.physical_relation_oid
        or dependencies["base_relation_oid"].version_at_build
        != observation.base_relation_oid
        or dependencies["context_scope"].version_at_build != spec.build_context_version
        or expected.target_context_hash
        != _canonical_digest(json.loads(spec.target_context_payload_json))
        or spec.build_context_hash
        != _canonical_digest(json.loads(spec.build_context_payload_json))
    ):
        raise PostgresError("E10 state observation dependency version mismatch")
    if any(
        dependencies[kind].version_at_build != 0
        for kind in ("artifact_kind", "policy", "principal", "rid_domain")
    ):
        raise PostgresError("E10 state observation static dependency version mismatch")
    base_delta = (
        observation.current_base_version - dependencies["base"].version_at_build
    )
    membership_delta = (
        observation.current_membership_version
        - dependencies["membership"].version_at_build
    )
    if base_delta not in ({0, 1} if spec.state_kind == "base_epoch_advanced" else {0}):
        raise PostgresError("E10 state observation base epoch mismatch")
    if membership_delta not in (
        {0, 1} if spec.state_kind == "membership_epoch_advanced" else {0}
    ):
        raise PostgresError("E10 state observation membership epoch mismatch")


def _e10_state_lock_sql(spec: E10NegativeStateSpec) -> str:
    table = _e10_state_table_name(spec)
    return f"""
LOCK TABLE public.{table} IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.document IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE public.group_membership IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE public.artifact_dependencies IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE public.synthetic_context, public.context_versions IN SHARE MODE;
LOCK TABLE public.base_versions, public.membership_versions
  IN SHARE ROW EXCLUSIVE MODE;
"""


def _e10_current_identity_guard_sql(
    spec: E10NegativeStateSpec,
    expected: E10ArtifactStateObservation,
) -> str:
    _assert_e10_observation_guardable(spec, expected)
    expected_dependencies = [
        [item.dep_kind, item.dep_name, item.version_at_build]
        for item in expected.dependencies
    ]
    return f"""
DO $$
DECLARE
  actual_dependencies jsonb;
BEGIN
  IF to_regclass({_quote(spec.physical_relation)})::oid::bigint
     IS DISTINCT FROM {expected.physical_relation_oid} THEN
    RAISE EXCEPTION 'E10 state relation identity changed before restoration';
  END IF;
  IF to_regclass({_quote(f'public.{spec.relation}')})::oid::bigint
     IS DISTINCT FROM {expected.base_relation_oid} THEN
    RAISE EXCEPTION 'E10 base relation identity changed before restoration';
  END IF;
  SELECT COALESCE(
           jsonb_agg(
             jsonb_build_array(
               dependency.dep_kind,
               dependency.dep_name,
               dependency.version_at_build
             )
             ORDER BY dependency.dep_kind,
                      dependency.dep_name,
                      dependency.version_at_build
           ),
           '[]'::jsonb
         )
  INTO actual_dependencies
  FROM public.artifact_dependencies dependency
  WHERE dependency.artifact_id = {_quote(spec.artifact_id)};
  IF actual_dependencies IS DISTINCT FROM
     {_quote(_canonical_json(expected_dependencies))}::jsonb THEN
    RAISE EXCEPTION 'E10 state dependency identity changed before restoration';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.synthetic_context context
    JOIN public.context_versions version
      ON version.ctx_hash = context.ctx_hash
     AND version.canonical_context = context.canonical_context
    WHERE context.context_id = {_quote(spec.target_context_id)}
      AND context.ctx_hash = {_quote(spec.target_context_hash)}
      AND context.user_id::text = {_quote(spec.target_principal_id)}
      AND context.canonical_context =
          {_quote(spec.target_context_payload_json)}::jsonb
      AND version.version = {expected.target_context_version}
  ) THEN
    RAISE EXCEPTION 'E10 target context identity changed before restoration';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.synthetic_context context
    JOIN public.context_versions version
      ON version.ctx_hash = context.ctx_hash
     AND version.canonical_context = context.canonical_context
    WHERE context.context_id = {_quote(spec.build_context_id)}
      AND context.ctx_hash = {_quote(spec.build_context_hash)}
      AND context.user_id::text = {_quote(spec.build_principal_id)}
      AND context.canonical_context =
          {_quote(spec.build_context_payload_json)}::jsonb
      AND version.version = {expected.artifact_context_version}
  ) THEN
    RAISE EXCEPTION 'E10 build context identity changed before restoration';
  END IF;
  IF (
    SELECT version FROM public.base_versions
    WHERE relname = {_quote(spec.relation)}
  ) IS DISTINCT FROM {expected.current_base_version} THEN
    RAISE EXCEPTION 'E10 base epoch changed before restoration';
  END IF;
  IF (
    SELECT version FROM public.membership_versions
    WHERE scope_name = 'group_membership'
  ) IS DISTINCT FROM {expected.current_membership_version} THEN
    RAISE EXCEPTION 'E10 membership epoch changed before restoration';
  END IF;
END;
$$;
"""


def _e10_negative_state_mutation_sql(
    spec: E10NegativeStateSpec,
    baseline: Mapping[str, Any],
) -> Optional[str]:
    if spec.state_kind == "alternate_context":
        return None
    if spec.state_kind == "base_epoch_advanced":
        base_row = baseline["base_row"]
        base_version = int(baseline["base_version"])
        rid = int(base_row["rid"])
        original_payload = _canonical_json(base_row["payload"])
        marker = _e10_state_marker(spec)
        return f"""
BEGIN ISOLATION LEVEL REPEATABLE READ;
SET LOCAL search_path TO pg_catalog, public;
DO $$
BEGIN
  IF (SELECT version FROM public.base_versions WHERE relname = {_quote(spec.relation)})
     IS DISTINCT FROM {base_version} THEN
    RAISE EXCEPTION 'E10 base epoch changed before mutation';
  END IF;
  IF (
    SELECT payload FROM public.document WHERE doc_id = {rid}
  ) IS DISTINCT FROM {_quote(original_payload)}::jsonb THEN
    RAISE EXCEPTION 'E10 base recovery row changed before mutation';
  END IF;
END;
$$;
DO $$
DECLARE
  affected_rows integer;
BEGIN
  UPDATE public.document
  SET payload = jsonb_set(
    payload,
    '{{caprls_state_epoch}}',
    to_jsonb({_quote(marker)}::text),
    true
  )
  WHERE doc_id = {rid};
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'E10 base mutation count is not one';
  END IF;
  UPDATE public.base_versions
  SET version = {base_version + 1}
  WHERE relname = {_quote(spec.relation)}
    AND version = {base_version};
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'E10 base epoch mutation count is not one';
  END IF;
END;
$$;
DO $$
BEGIN
  IF (SELECT version FROM public.base_versions WHERE relname = {_quote(spec.relation)})
     IS DISTINCT FROM {base_version + 1} THEN
    RAISE EXCEPTION 'E10 base epoch did not advance';
  END IF;
END;
$$;
COMMIT;
"""
    witness = baseline["membership_witness"]
    membership_version = int(baseline["membership_version"])
    user_id = int(witness["user_id"])
    group_id = int(witness["group_id"])
    row_version = int(witness["membership_version"])
    witness_rid = int(witness["witness_rid"])
    witness_select = _e10_membership_witness_select_sql(spec).strip().rstrip(";")
    return f"""
BEGIN ISOLATION LEVEL REPEATABLE READ;
SET LOCAL search_path TO pg_catalog, public;
CREATE TEMP TABLE e10_state_membership_witness_recheck ON COMMIT DROP AS
{witness_select};
DO $$
BEGIN
  IF (SELECT count(*) FROM e10_state_membership_witness_recheck) <> 1
     OR (SELECT group_grant_count FROM e10_state_membership_witness_recheck) <> 1
     OR NOT EXISTS (
       SELECT 1 FROM e10_state_membership_witness_recheck
       WHERE user_id = {user_id}
         AND group_id = {group_id}
         AND membership_version = {row_version}
         AND witness_rid = {witness_rid}
     ) THEN
    RAISE EXCEPTION 'E10 membership witness changed before revocation';
  END IF;
  IF (
    SELECT version FROM public.membership_versions
    WHERE scope_name = 'group_membership'
  ) IS DISTINCT FROM {membership_version} THEN
    RAISE EXCEPTION 'E10 membership epoch changed before revocation';
  END IF;
END;
$$;
DO $$
DECLARE
  affected_rows integer;
BEGIN
  DELETE FROM public.group_membership
  WHERE user_id = {user_id}
    AND group_id = {group_id}
    AND membership_version = {row_version};
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'E10 membership revocation count is not one';
  END IF;
END;
$$;
DO $$
DECLARE
  affected_rows integer;
BEGIN
  UPDATE public.membership_versions
  SET version = {membership_version + 1}
  WHERE scope_name = 'group_membership'
    AND version = {membership_version};
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'E10 membership epoch mutation count is not one';
  END IF;
END;
$$;
DO $$
BEGIN
  IF (
    SELECT version FROM public.membership_versions
    WHERE scope_name = 'group_membership'
  ) IS DISTINCT FROM {membership_version + 1} THEN
    RAISE EXCEPTION 'E10 membership epoch did not advance';
  END IF;
END;
$$;
COMMIT;
"""


def _e10_negative_state_restore_sql(
    spec: E10NegativeStateSpec,
    baseline: Mapping[str, Any],
    expected_observation: E10ArtifactStateObservation,
) -> str:
    table = _e10_state_table_name(spec)
    identity_guard_sql = _e10_current_identity_guard_sql(
        spec,
        expected_observation,
    )
    restore_sql = ""
    if spec.state_kind == "base_epoch_advanced":
        base_version = int(baseline["base_version"])
        base_row = baseline["base_row"]
        rid = int(base_row["rid"])
        payload = _canonical_json(base_row["payload"])
        mutated_payload = _e10_expected_mutated_payload_json(spec, baseline)
        restore_sql = f"""
DO $$
DECLARE
  affected_rows integer;
BEGIN
  IF (SELECT version FROM public.base_versions WHERE relname = {_quote(spec.relation)})
     IS DISTINCT FROM {base_version + 1} THEN
    RAISE EXCEPTION 'E10 base epoch changed before restoration';
  END IF;
  IF (
    SELECT document.payload
    FROM public.document document
    WHERE document.doc_id = {rid}
  ) IS DISTINCT FROM {_quote(mutated_payload)}::jsonb THEN
    RAISE EXCEPTION 'E10 base payload changed before restoration';
  END IF;
  UPDATE public.document
  SET payload = {_quote(payload)}::jsonb
  WHERE doc_id = {rid};
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'E10 base restoration count is not one';
  END IF;
  UPDATE public.base_versions
  SET version = {base_version}
  WHERE relname = {_quote(spec.relation)}
    AND version = {base_version + 1};
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'E10 base epoch restoration count is not one';
  END IF;
END;
$$;
"""
    elif spec.state_kind == "membership_epoch_advanced":
        membership_version = int(baseline["membership_version"])
        witness = baseline["membership_witness"]
        user_id = int(witness["user_id"])
        group_id = int(witness["group_id"])
        row_version = int(witness["membership_version"])
        restore_sql = f"""
DO $$
DECLARE
  affected_rows integer;
BEGIN
  IF (
    SELECT version FROM public.membership_versions
    WHERE scope_name = 'group_membership'
  ) IS DISTINCT FROM {membership_version + 1} THEN
    RAISE EXCEPTION 'E10 membership epoch changed before restoration';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.group_membership
    WHERE user_id = {user_id} AND group_id = {group_id}
  ) THEN
    RAISE EXCEPTION 'E10 revoked membership unexpectedly reappeared';
  END IF;
  INSERT INTO public.group_membership(user_id, group_id, membership_version)
  VALUES ({user_id}, {group_id}, {row_version});
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'E10 membership restoration count is not one';
  END IF;
  UPDATE public.membership_versions
  SET version = {membership_version}
  WHERE scope_name = 'group_membership'
    AND version = {membership_version + 1};
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'E10 membership epoch restoration count is not one';
  END IF;
END;
$$;
"""
    return f"""
BEGIN ISOLATION LEVEL REPEATABLE READ;
SET LOCAL search_path TO pg_catalog, public;
{_e10_state_lock_sql(spec)}
{identity_guard_sql}
{restore_sql}
DO $$
DECLARE
  affected_rows integer;
BEGIN
  DELETE FROM public.artifact_dependencies
  WHERE artifact_id = {_quote(spec.artifact_id)};
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> {len(E10_STATE_DEPENDENCY_KINDS)} THEN
    RAISE EXCEPTION 'E10 state dependency cleanup count is not exact';
  END IF;
END;
$$;
DROP TABLE public.{table};
COMMIT;
"""


def _e10_restoration_probe_sql(
    spec: E10NegativeStateSpec,
    baseline: Mapping[str, Any],
) -> str:
    base_row = baseline.get("base_row")
    base_row_sql = "NULL::jsonb"
    if isinstance(base_row, Mapping):
        base_row_sql = (
            "(SELECT jsonb_build_object('rid', document.doc_id, 'payload', document.payload) "
            "FROM public.document document "
            f"WHERE document.doc_id = {int(base_row['rid'])})"
        )
    witness = baseline.get("membership_witness")
    witness_sql = "NULL::jsonb"
    if isinstance(witness, Mapping):
        user_id = int(witness["user_id"])
        group_id = int(witness["group_id"])
        witness_rid = int(witness["witness_rid"])
        witness_sql = f"""(
          SELECT jsonb_build_object(
            'user_id', membership.user_id,
            'group_id', membership.group_id,
            'membership_version', membership.membership_version,
            'witness_rid', {witness_rid},
            'group_grant_count', (
              SELECT count(DISTINCT other_membership.group_id)
              FROM public.share_acl acl
              JOIN public.group_membership other_membership
                ON other_membership.group_id = acl.group_id
              WHERE acl.rid = {witness_rid}
                AND acl.relname = 'document'
                AND acl.permission IN ('read', 'owner')
                AND other_membership.user_id = {user_id}
                AND TIMESTAMPTZ '2026-06-01 00:00:00+00'
                    BETWEEN acl.valid_from AND acl.valid_to
            )
          )
          FROM public.group_membership membership
          WHERE membership.user_id = {user_id}
            AND membership.group_id = {group_id}
        )"""
    return f"""
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL search_path TO pg_catalog, public;
SET LOCAL row_security = on;
SELECT jsonb_build_object(
  'case_query_id', {_quote(spec.case_query_id)},
  'state_kind', {_quote(spec.state_kind)},
  'artifact_id', {_quote(spec.artifact_id)},
  'physical_relation', {_quote(spec.physical_relation)},
  'artifact_absent_before', NOT EXISTS (
    SELECT 1 FROM public.artifact_dependencies
    WHERE artifact_id = {_quote(spec.artifact_id)}
  ),
  'physical_relation_absent_before', to_regclass({_quote(spec.physical_relation)}) IS NULL,
  'base_version', (
    SELECT version FROM public.base_versions WHERE relname = {_quote(spec.relation)}
  ),
  'membership_version', (
    SELECT version FROM public.membership_versions
    WHERE scope_name = 'group_membership'
  ),
  'target_context', (
    SELECT jsonb_build_object(
      'context_id', context.context_id,
      'ctx_hash', context.ctx_hash,
      'principal_id', context.user_id::text,
      'canonical_context', context.canonical_context,
      'version', version.version
    )
    FROM public.synthetic_context context
    JOIN public.context_versions version
      ON version.ctx_hash = context.ctx_hash
     AND version.canonical_context = context.canonical_context
    WHERE context.context_id = {_quote(spec.target_context_id)}
  ),
  'build_context', (
    SELECT jsonb_build_object(
      'context_id', context.context_id,
      'ctx_hash', context.ctx_hash,
      'principal_id', context.user_id::text,
      'canonical_context', context.canonical_context,
      'version', version.version
    )
    FROM public.synthetic_context context
    JOIN public.context_versions version
      ON version.ctx_hash = context.ctx_hash
     AND version.canonical_context = context.canonical_context
    WHERE context.context_id = {_quote(spec.build_context_id)}
  ),
  'base_row', {base_row_sql},
  'membership_witness', {witness_sql}
)::text;
COMMIT;
"""


def _e10_negative_state_artifact_cleanup_sql(
    spec: E10NegativeStateSpec,
    expected_observation: E10ArtifactStateObservation,
) -> str:
    table = _e10_state_table_name(spec)
    return f"""
BEGIN ISOLATION LEVEL REPEATABLE READ;
SET LOCAL search_path TO pg_catalog, public;
{_e10_state_lock_sql(spec)}
{_e10_current_identity_guard_sql(spec, expected_observation)}
DO $$
DECLARE
  affected_rows integer;
BEGIN
  DELETE FROM public.artifact_dependencies
  WHERE artifact_id = {_quote(spec.artifact_id)};
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> {len(E10_STATE_DEPENDENCY_KINDS)} THEN
    RAISE EXCEPTION 'E10 state dependency cleanup count is not exact';
  END IF;
END;
$$;
DROP TABLE public.{table};
COMMIT;
"""


def _assert_e10_clean_state_observation(
    observation: E10ArtifactStateObservation,
    expectation: E10ArtifactStateExpectation,
) -> None:
    clean = bool(
        observation.artifact_id == expectation.artifact_id
        and observation.physical_relation_oid is None
        and not observation.dependencies
        and observation.artifact_context_principal_id is None
        and observation.artifact_context_payload_json is None
        and observation.artifact_context_version is None
        and observation.base_relation_oid is not None
        and observation.target_context_principal_id == expectation.principal_id
        and observation.target_context_payload_json is not None
        and observation.target_context_version is not None
        and observation.current_base_version is not None
        and observation.current_membership_version is not None
    )
    if not clean:
        raise PostgresError(
            "E10 catalog state is not clean and complete before materialization"
        )


def _assert_e10_expected_negative_state(
    spec: E10NegativeStateSpec,
    assessment: E10ArtifactStateAssessment,
) -> None:
    common_checks = (
        assessment.dependency_set_complete,
        assessment.artifact_identity_matches,
        assessment.relation_identity_matches,
        assessment.rid_identity_matches,
        assessment.policy_identity_matches,
        assessment.context_fresh,
    )
    if not all(common_checks):
        raise PostgresError(
            "E10 materialized state did not preserve its required identities"
        )
    if assessment.valid:
        raise PostgresError(
            "E10 materialized state does not expose the requested isolated mismatch"
        )
    reasons = set(assessment.reasons)
    if spec.state_kind == "base_epoch_advanced":
        exact = bool(
            reasons == {"base_stale"}
            and assessment.principal_matches
            and assessment.context_matches
            and not assessment.base_fresh
            and assessment.membership_fresh
        )
    elif spec.state_kind == "alternate_context":
        exact = bool(
            "context_mismatch" in reasons
            and reasons <= {"context_mismatch", "principal_mismatch"}
            and not assessment.context_matches
            and assessment.base_fresh
            and assessment.membership_fresh
        )
    elif spec.state_kind == "membership_epoch_advanced":
        exact = bool(
            reasons == {"membership_stale"}
            and assessment.principal_matches
            and assessment.context_matches
            and assessment.base_fresh
            and not assessment.membership_fresh
        )
    else:
        exact = False
    if not exact:
        raise PostgresError(
            "E10 materialized state does not expose the requested isolated mismatch"
        )


def _e10_catalog_state_equal(
    left: E10ArtifactStateObservation,
    right: E10ArtifactStateObservation,
) -> bool:
    return bool(
        left.catalog_state_digest == right.catalog_state_digest
        and _e10_catalog_state_digest_payload(left)
        == _e10_catalog_state_digest_payload(right)
    )


def _assert_e10_handle_cross_binding(
    spec: E10NegativeStateSpec,
    baseline: Mapping[str, Any],
    pre_observation: E10ArtifactStateObservation,
    negative_observation: E10ArtifactStateObservation,
) -> None:
    _assert_e10_clean_state_observation(pre_observation, spec.expectation)
    _assert_e10_observation_guardable(spec, negative_observation)
    dependencies, complete = _dependency_by_kind(negative_observation)
    if not complete:
        raise PostgresError("E10 restoration handle dependency set is incomplete")
    base_version = int(baseline["base_version"])
    membership_version = int(baseline["membership_version"])
    expected_negative_base = base_version + (
        1 if spec.state_kind == "base_epoch_advanced" else 0
    )
    expected_negative_membership = membership_version + (
        1 if spec.state_kind == "membership_epoch_advanced" else 0
    )
    if not all(
        (
            pre_observation.base_relation_oid == negative_observation.base_relation_oid,
            pre_observation.target_context_principal_id
            == negative_observation.target_context_principal_id,
            pre_observation.target_context_payload_json
            == negative_observation.target_context_payload_json,
            pre_observation.target_context_version
            == negative_observation.target_context_version,
            pre_observation.current_base_version == base_version,
            pre_observation.current_membership_version == membership_version,
            negative_observation.current_base_version == expected_negative_base,
            negative_observation.current_membership_version
            == expected_negative_membership,
            dependencies["base"].version_at_build == base_version,
            dependencies["membership"].version_at_build == membership_version,
            dependencies["context_scope"].version_at_build
            == spec.build_context_version,
        )
    ):
        raise PostgresError("E10 restoration handle components are not cross-bound")


def _materialize_e10_negative_state(
    root: Path,
    case: E10Case,
    context_id: str,
    pg_env: PostgresEnv,
) -> E10NegativeStateHandle:
    """Materialize one validator-visible E10 state without planner feedback."""

    spec = _e10_negative_state_spec(root, case, context_id, pg_env)
    expectation = spec.expectation
    pre_observation = _collect_e10_artifact_state_observation(expectation, pg_env)
    _assert_e10_clean_state_observation(pre_observation, expectation)

    built = False
    built_observation: Optional[E10ArtifactStateObservation] = None
    expected_negative: Optional[E10ArtifactStateObservation] = None
    mutation_applied = False
    baseline_payload_json: Optional[str] = None
    mutation_sql: Optional[str] = None
    try:
        build_sql = _e10_negative_state_build_sql(spec)
        build_output = run_psql_command(build_sql, pg_env)
        built = True
        built_observation = _collect_e10_artifact_state_observation(
            expectation,
            pg_env,
        )
        _assert_e10_observation_guardable(spec, built_observation)
        built_assessment = _assess_e10_artifact_state(
            built_observation,
            expectation,
        )
        if spec.state_kind == "alternate_context":
            _assert_e10_expected_negative_state(spec, built_assessment)
        elif not built_assessment.valid:
            raise PostgresError(
                "E10 state artifact is not current immediately after materialization"
            )
        baseline_payload_json = _parse_e10_materialization_baseline(
            _last_json_object(
                build_output,
                label="E10 state materialization",
            ),
            spec,
        )
        baseline = json.loads(baseline_payload_json)
        expected_negative = _e10_expected_negative_observation(
            spec,
            built_observation,
        )
        mutation_sql = _e10_negative_state_mutation_sql(spec, baseline)
        if mutation_sql is not None:
            run_psql_command(mutation_sql, pg_env)
            mutation_applied = True

        negative_observation = _collect_e10_artifact_state_observation(
            expectation,
            pg_env,
        )
        if not _e10_catalog_state_equal(
            negative_observation,
            expected_negative,
        ):
            raise PostgresError(
                "E10 state transition produced an unexpected catalog state"
            )
        negative_assessment = _assess_e10_artifact_state(
            negative_observation,
            expectation,
        )
        _assert_e10_expected_negative_state(spec, negative_assessment)
        return E10NegativeStateHandle(
            spec=spec,
            baseline_payload_json=baseline_payload_json,
            baseline_digest=_canonical_digest(baseline),
            pre_observation=pre_observation,
            negative_observation=negative_observation,
            negative_assessment=negative_assessment,
        )
    except Exception as exc:
        if built:
            if built_observation is None:
                raise PostgresError(
                    "E10 state materialization failed after commit, but object "
                    "identity could not be established; state was preserved"
                ) from exc
            try:
                if (
                    baseline_payload_json is not None
                    and expected_negative is not None
                    and (mutation_sql is None or mutation_applied)
                ):
                    run_psql_command(
                        _e10_negative_state_restore_sql(
                            spec,
                            json.loads(baseline_payload_json),
                            expected_negative,
                        ),
                        pg_env,
                    )
                else:
                    run_psql_command(
                        _e10_negative_state_artifact_cleanup_sql(
                            spec,
                            built_observation,
                        ),
                        pg_env,
                    )
            except Exception as cleanup_exc:
                raise PostgresError(
                    "E10 state materialization failed and automatic restoration "
                    f"also failed; original={type(exc).__name__}: {exc}"
                ) from cleanup_exc
        raise


def _restore_e10_negative_state(
    handle: E10NegativeStateHandle,
    pg_env: PostgresEnv,
) -> E10StateRestoration:
    """Restore and independently verify the pre-materialization catalog state."""

    try:
        baseline = json.loads(handle.baseline_payload_json)
    except json.JSONDecodeError as exc:
        raise PostgresError("E10 restoration baseline is not valid JSON") from exc
    canonical_baseline = _parse_e10_materialization_baseline(baseline, handle.spec)
    if canonical_baseline != handle.baseline_payload_json:
        raise PostgresError("E10 restoration baseline is not canonical")
    if _canonical_digest(baseline) != handle.baseline_digest:
        raise PostgresError("E10 restoration baseline digest mismatch")

    try:
        canonical_pre = _e10_artifact_state_observation_from_dict(
            handle.pre_observation.to_dict()
        )
        canonical_negative = _e10_artifact_state_observation_from_dict(
            handle.negative_observation.to_dict()
        )
    except (TypeError, ValueError) as exc:
        raise PostgresError("E10 restoration handle observation mismatch") from exc
    if (
        canonical_pre != handle.pre_observation
        or canonical_negative != handle.negative_observation
    ):
        raise PostgresError("E10 restoration handle observation is not canonical")
    _assert_e10_handle_cross_binding(
        handle.spec,
        baseline,
        canonical_pre,
        canonical_negative,
    )

    recomputed_negative = _assess_e10_artifact_state(
        canonical_negative,
        handle.spec.expectation,
    )
    if recomputed_negative != handle.negative_assessment:
        raise PostgresError("E10 restoration handle assessment mismatch")
    _assert_e10_expected_negative_state(handle.spec, recomputed_negative)

    current_negative = _collect_e10_artifact_state_observation(
        handle.spec.expectation,
        pg_env,
    )
    if not _e10_catalog_state_equal(current_negative, canonical_negative):
        raise PostgresError(
            "E10 restoration current catalog state differs from the handle; "
            "state was preserved"
        )

    run_psql_command(
        _e10_negative_state_restore_sql(
            handle.spec,
            baseline,
            canonical_negative,
        ),
        pg_env,
    )
    restored_baseline_payload_json = _parse_e10_materialization_baseline(
        _last_json_object(
            run_psql_command(
                _e10_restoration_probe_sql(handle.spec, baseline),
                pg_env,
            ),
            label="E10 state restoration probe",
        ),
        handle.spec,
    )
    restored_baseline = json.loads(restored_baseline_payload_json)
    restored_baseline_digest = _canonical_digest(restored_baseline)
    data_exact = restored_baseline_digest == handle.baseline_digest

    restored_observation = _collect_e10_artifact_state_observation(
        handle.spec.expectation,
        pg_env,
    )
    restored_assessment = _assess_e10_artifact_state(
        restored_observation,
        handle.spec.expectation,
    )
    pre_assessment = _assess_e10_artifact_state(
        canonical_pre,
        handle.spec.expectation,
    )
    catalog_exact = (
        restored_observation.catalog_state_digest == canonical_pre.catalog_state_digest
    )
    assessment_exact = restored_assessment == pre_assessment
    result = E10StateRestoration(
        baseline_digest=handle.baseline_digest,
        restored_baseline_digest=restored_baseline_digest,
        pre_catalog_state_digest=canonical_pre.catalog_state_digest,
        restored_catalog_state_digest=restored_observation.catalog_state_digest,
        catalog_exact=catalog_exact,
        data_exact=data_exact,
        assessment_exact=assessment_exact,
        restored_assessment=restored_assessment,
    )
    if not (result.catalog_exact and result.data_exact and result.assessment_exact):
        raise PostgresError(
            "E10 state restoration did not recover the exact prior state"
        )
    return result


def _run_count(sql: str, pg_env: PostgresEnv) -> int:
    value = run_psql_command(sql, pg_env)
    for line in reversed(value.splitlines()):
        stripped = line.strip()
        if stripped and stripped.lstrip("-").isdigit():
            return int(stripped)
    raise PostgresError(f"E10 count query did not emit an integer:\n{value}")


def _require_e10_reference_match(
    case: E10Case,
    label: str,
    *,
    actual_row_count: int,
    reference_row_count: int,
) -> None:
    if actual_row_count != reference_row_count:
        raise PostgresError(
            "E10 independent reference mismatch for "
            f"{case.query_id}/{label}: "
            f"actual={actual_row_count}, reference={reference_row_count}"
        )


@dataclass(frozen=True)
class _E10StaticPreflight:
    template_id: str
    sql: str
    native_rls: bool
    verification: StaticVerification
    explain_json: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class _E10MeasuredQueryTiming(QueryTiming):
    measurement_explain_json: tuple[Mapping[str, Any], ...] = ()


def _e10_measurement_query_body(sql: str) -> str:
    if not isinstance(sql, str) or not sql.strip():
        raise PostgresError("E10 measurement SQL identity is missing")
    return sql.strip().rstrip(";")


def _plain_explain_sql(sql: str) -> str:
    body = _e10_measurement_query_body(sql)
    return f"""
SET jit = off;
SET max_parallel_workers_per_gather = 0;
EXPLAIN (FORMAT JSON) {body};
"""


def _analyze_explain_sql(sql: str) -> str:
    body = _e10_measurement_query_body(sql)
    return f"""
SET jit = off;
SET max_parallel_workers_per_gather = 0;
EXPLAIN (ANALYZE, FORMAT JSON, TIMING OFF, SUMMARY ON) {body};
"""


def _extract_explain_json(stdout: str) -> list[Mapping[str, Any]]:
    start = stdout.find("[")
    end = stdout.rfind("]")
    if start < 0 or end < start:
        raise PostgresError(f"E10 EXPLAIN did not emit JSON:\n{stdout}")
    payload = json.loads(stdout[start : end + 1])
    if not isinstance(payload, list) or not payload:
        raise PostgresError(f"E10 EXPLAIN JSON payload is empty:\n{stdout}")
    return payload


def _timing_from_explain_json(explain_json: list[Mapping[str, Any]]) -> QueryTiming:
    item = explain_json[0]
    return QueryTiming(
        planning_ms=float(item.get("Planning Time", 0.0)),
        execution_ms=float(item.get("Execution Time", 0.0)),
        static_verifier_explain_json=tuple(explain_json),
    )


def _explain_plan_hash(explain_json: list[Mapping[str, Any]]) -> str:
    plan = explain_json[0].get("Plan", {})
    if not isinstance(plan, Mapping):
        plan = {}
    return _digest(plan)


EXPLAIN_CONDITION_FIELDS = (
    "Filter",
    "Index Cond",
    "Recheck Cond",
    "Hash Cond",
    "Merge Cond",
    "Join Filter",
)

POLICY_EVAL_TOKEN_RE = re.compile(r"[a-z_][a-z0-9_]*|%\s*\d+")

POLICY_EVAL_STOPWORDS = {
    "a",
    "alias",
    "and",
    "as",
    "between",
    "by",
    "case",
    "count",
    "d",
    "false",
    "from",
    "gm",
    "i",
    "in",
    "is",
    "join",
    "not",
    "null",
    "on",
    "or",
    "pp",
    "public",
    "q",
    "select",
    "t",
    "text",
    "true",
    "u",
    "where",
}


def _walk_explain_nodes(
    explain_json: Iterable[Mapping[str, Any]],
) -> Iterable[Mapping[str, Any]]:
    def walk(node: Any) -> Iterable[Mapping[str, Any]]:
        if not isinstance(node, Mapping):
            return
        yield node
        children = node.get("Plans", ())
        if isinstance(children, list):
            for child in children:
                yield from walk(child)

    for item in explain_json:
        if isinstance(item, Mapping):
            yield from walk(item.get("Plan"))


def _node_condition_text(node: Mapping[str, Any]) -> str:
    return " ".join(
        str(node[field]).lower()
        for field in EXPLAIN_CONDITION_FIELDS
        if field in node and node[field] is not None
    )


def _policy_eval_fingerprint_tokens(predicate: str) -> tuple[str, ...]:
    tokens: list[str] = []
    for token in POLICY_EVAL_TOKEN_RE.findall(predicate.lower()):
        normalized = re.sub(r"\s+", "", token)
        if len(normalized) < 2 or normalized in POLICY_EVAL_STOPWORDS:
            continue
        if normalized.endswith("::text"):
            normalized = normalized.removesuffix("::text")
        tokens.append(normalized)
    return tuple(dict.fromkeys(tokens))


def _node_input_rows(node: Mapping[str, Any]) -> int:
    rows = float(node.get("Actual Rows", 0.0) or 0.0)
    removed = float(node.get("Rows Removed by Filter", 0.0) or 0.0)
    loops = float(node.get("Actual Loops", 1.0) or 0.0)
    return int(round((rows + removed) * loops))


def _policy_eval_rows_from_explain(
    explain_json: Iterable[Mapping[str, Any]],
    *,
    template_id: str,
    relname: str,
    exact_predicate: str,
) -> Optional[int]:
    """Count policy-bearing protected-relation inputs observed by EXPLAIN ANALYZE."""

    if _artifact_kind_for_template(template_id) is not None:
        return 0
    tokens = _policy_eval_fingerprint_tokens(exact_predicate)
    if not tokens:
        return 0 if exact_predicate.strip().lower() in {"true", "(true)"} else None
    total = 0
    matched = False
    relname_lower = relname.lower()
    for node in _walk_explain_nodes(explain_json):
        relation = str(node.get("Relation Name", "")).lower()
        cte_name = str(node.get("CTE Name", "")).lower()
        if relation != relname_lower and not (
            template_id == "guard_candidate_plus_residual_v1"
            and cte_name in {"cand", "guard_candidate"}
        ):
            continue
        condition = _node_condition_text(node)
        if condition and any(token in condition for token in tokens):
            matched = True
            total += _node_input_rows(node)
    return total if matched else None


def _static_verifier_template_id(template_id: str) -> str:
    if template_id == "native_pg_rls_physical_design_v1":
        return "native_pg_rls_v1"
    return template_id


def _verify_static_template(
    template_id: str,
    sql: str,
    explain_json: list[Mapping[str, Any]],
) -> StaticVerification:
    verification = verify_template_static(
        _static_verifier_template_id(template_id),
        sql,
        explain_json,
        _explain_plan_hash(explain_json),
    )
    if verification.status != "pass":
        raise PostgresError(
            f"E10 static verifier failed for {template_id}: "
            + "; ".join(verification.reasons)
        )
    return verification


def _verify_measurement_template(
    template_id: str,
    sql: str,
    explain_json: list[Mapping[str, Any]],
) -> StaticVerification:
    """Verify the executed query shape without prescribing catalog joins.

    Artifact identity, context, freshness, and RID-domain checks are executed
    by ``caprls_assert_artifact_valid`` in the same repeatable-read transaction
    as every artifact-backed measurement.  Requiring those catalog tables to
    also appear in the measured query duplicates that semantic check and
    constrains an implementation detail rather than correctness.
    """

    if template_id != "mav_scan_v1":
        return _verify_static_template(template_id, sql, explain_json)
    try:
        return _verify_static_template(template_id, sql, explain_json)
    except PostgresError:
        verification = verify_template_static(
            _static_verifier_template_id(template_id),
            sql,
            explain_json,
            _explain_plan_hash(explain_json),
        )
    shape_only_reasons = (
        "MaterializedAuthorizedViewScan SQL must bind MAV relation to artifact scope:",
        "MaterializedAuthorizedViewScan EXPLAIN plan must scan catalog binding relations:",
    )
    remaining = [
        reason
        for reason in verification.reasons
        if not reason.startswith(shape_only_reasons)
    ]
    verification = StaticVerification(
        status="pass" if not remaining else "fail",
        reasons=remaining,
        plan_hash=verification.plan_hash,
    )
    if verification.status != "pass":
        raise PostgresError(
            f"E10 static verifier failed for {template_id}: "
            + "; ".join(verification.reasons)
        )
    return verification


def _base_filter(case: E10Case, alias: str, rid_col: str) -> str:
    if case.query_id == "E10_Q1_support_ticket_lookup":
        return f"{alias}.{rid_col} BETWEEN 1 AND 100"
    if case.query_id == "E10_Q11_ticket_exact_injection":
        return f"{alias}.status = 'open' AND {alias}.priority >= 4 AND {alias}.{rid_col} BETWEEN 1 AND 20000"
    if case.query_id == "E10_Q2_tenant_dashboard":
        return f"{alias}.{rid_col} <= 50000"
    if case.query_id == "E10_Q8_stale_dashboard_mav":
        return f"{alias}.{rid_col} <= 50000"
    if case.query_id == "E10_Q3_cross_tenant_admin_audit":
        return f"{alias}.{rid_col} <= 80000"
    if case.query_id == "E10_Q9_wrong_context_mav":
        return f"{alias}.{rid_col} <= 80000"
    if case.query_id == "E10_Q4_shared_document_search_audit":
        return f"{alias}.{rid_col} <= 20000"
    if case.query_id == "E10_Q5_invoice_region_purpose_join":
        return f"{alias}.{rid_col} <= 30000"
    if case.query_id in {
        "E10_Q7_ordered_export",
        "E10_Q10_revoked_membership_mav",
    }:
        return "true"
    return f"{alias}.{rid_col} <= 60000"


def _e10_planning_query_predicate(
    case: E10Case,
    alias: str,
    rid_col: str,
) -> str:
    """Return the finite source-controlled predicate bound into F1 identity."""

    if case.query_id == "E10_Q6_own_plus_group_shared_union":
        return "true"
    return _base_filter(case, alias, rid_col)


def _carrier_projection_sql(
    *,
    case: E10Case,
    relname: str,
    rid_col: str,
    alias: str,
    include_secret: bool = False,
    required_columns: Optional[Iterable[str]] = None,
) -> str:
    if required_columns is not None:
        columns = tuple(dict.fromkeys((rid_col, *required_columns)))
    elif relname == "invoice":
        columns = (rid_col, "region", "account_id")
    elif relname == "ticket":
        columns = (rid_col, "tenant_id", "owner_id", "status", "priority")
    else:
        columns = (rid_col, "tenant_id", "owner_id", "public")
    if include_secret and "secret" not in columns:
        columns = columns + ("secret",)
    rendered = [f"{alias}.{column}" for column in columns]
    rendered.append(f"{alias}.{rid_col} AS __rid")
    return ", ".join(rendered)


def _barrier_continuation_required_columns(
    case: E10Case,
    rid_col: str,
) -> tuple[str, ...]:
    """Return columns that remain live after exact authorization.

    Exact-policy input columns need not be carried beyond the MATERIALIZED
    barrier.  Only the hidden RID carrier and columns consumed by the
    continuation remain live.
    """

    extra_by_shape = {
        "transparent_join_with_late_residual": ("account_id",),
        "branch_tagged_union_all": ("owner_id",),
        "search_with_unsafe_audit_udf": ("secret",),
        "ticket_exact_injection": ("status", "priority"),
    }
    return tuple(
        dict.fromkeys((rid_col, *extra_by_shape.get(case.query_shape, ())))
    )


def _safe_barrier_query_predicate(
    case: E10Case,
    alias: str,
    rid_col: str,
) -> Optional[str]:
    """Return a source query predicate that is safe to apply inside auth."""

    predicate = _base_filter(case, alias, rid_col)
    if case.query_shape == "ticket_exact_injection":
        return None
    if predicate.strip().lower() in {"true", "(true)"}:
        return None
    if _e10_safe_scalar_predicate_proof(predicate, alias=alias) is None:
        return None
    return predicate


def _base_query(
    case: E10Case,
    relname: str,
    rid_col: str,
    alias: str,
    exact_predicate: str,
    *,
    principal_id: Optional[str] = None,
) -> str:
    filter_sql = _base_filter(case, alias, rid_col)
    if case.query_id == "E10_Q4_shared_document_search_audit":
        return f"""
WITH auth AS MATERIALIZED (
  SELECT {alias}.{rid_col} AS rid, {alias}.{rid_col} AS __rid, {alias}.secret
  FROM public.{relname} {alias}
  WHERE {exact_predicate}
    AND {filter_sql}
)
SELECT count(*)
FROM auth d
WHERE public.unsafe_log('e10', {_quote(case.query_id)}, 'barrier_exact', 'case_occ_1', d.rid, d.secret)
"""
    if case.query_id == "E10_Q5_invoice_region_purpose_join":
        return f"""
SELECT count(*)
FROM public.invoice {alias}
JOIN public.user_account u ON u.user_id = {alias}.account_id
WHERE {exact_predicate}
  AND {filter_sql}
"""
    if case.query_id == "E10_Q6_own_plus_group_shared_union":
        if principal_id is None or not str(principal_id).strip():
            raise PostgresError("E10 Q6 requires the current context principal")
        projection_sql = _carrier_projection_sql(
            case=case,
            relname=relname,
            rid_col=rid_col,
            alias=alias,
            required_columns=_barrier_continuation_required_columns(case, rid_col),
        )
        return f"""
WITH auth AS MATERIALIZED (
  SELECT {projection_sql}
  FROM public.{relname} {alias}
  WHERE {exact_predicate}
),
branch_tagged AS MATERIALIZED (
  SELECT {alias}.{rid_col} AS branch_rid, 'own'::text AS branch_tag
  FROM auth {alias}
  WHERE {alias}.owner_id = {_quote(str(principal_id))}::bigint
  UNION ALL
  SELECT {alias}.{rid_col} AS branch_rid, 'shared'::text AS branch_tag
  FROM auth {alias}
  JOIN public.share_acl a
    ON a.rid = {alias}.{rid_col} AND a.relname = 'document'
  WHERE a.permission IN ('read', 'owner')
)
SELECT count(DISTINCT branch_rid)
FROM branch_tagged
"""
    if case.query_id in {
        "E10_Q7_ordered_export",
        "E10_Q10_revoked_membership_mav",
    }:
        return f"""
SELECT count(*)
FROM (
  SELECT {alias}.{rid_col}
  FROM public.{relname} {alias}
  WHERE {exact_predicate}
  ORDER BY {alias}.{rid_col}
  LIMIT 1000
) q
"""
    return f"""
SELECT count(*)
FROM public.{relname} {alias}
WHERE {exact_predicate}
  AND {filter_sql}
"""


def _complete_guard_predicate(
    case: E10Case,
    alias: str,
    rid_col: str,
    context: Mapping[str, Any],
    relname: str,
) -> str:
    if case.complete_guard_sql_template is None:
        raise PostgresError(f"E10 case {case.query_id} has no complete guard predicate")
    return _render_policy_predicate(
        case.complete_guard_sql_template,
        alias=alias,
        rid_col=rid_col,
        context=context,
        relname=relname,
    )


def _guard_unsafe_static_witness_case(root: Path) -> E10Case:
    policy = _load_policy(root, "tenant_group")
    guard_template = str(policy.get("guard_sql_template") or "")
    if not guard_template:
        raise PostgresError(
            "tenant_group policy lacks guard_sql_template for guard+unsafe witness"
        )
    return E10Case(
        query_id=E10_GUARD_UNSAFE_STATIC_WITNESS_QUERY_ID,
        label="Guard residual before unsafe audit witness",
        policy_mix="owner_shared_audit_logging",
        query_shape="guard_late_residual_before_unsafe_udf",
        contract_template_id="guard_candidate_plus_residual_v1",
        contract_alternative="Guard+LateResidual",
        contract_reason="complete guard is materialized and exact residual is checked before unsafe audit UDF observation",
        local_template_id="barrier_filter_v1",
        local_alternative="BarrierFilter",
        policy_evals=0,
        residual_checks=0,
        artifact_lookups=0,
        row_count=0,
        available_artifacts=(),
        complete_guard_sql_template=guard_template,
    )


def _guard_unsafe_static_witness_query(
    case: E10Case,
    relname: str,
    rid_col: str,
    alias: str,
    complete_guard_predicate: str,
    exact_residual_predicate: str,
) -> str:
    filter_sql = _base_filter(case, alias, rid_col)
    return f"""
WITH cand AS MATERIALIZED (
  SELECT {_carrier_projection_sql(case=case, relname=relname, rid_col=rid_col, alias=alias, include_secret=True)}
  FROM public.{relname} {alias}
  WHERE {complete_guard_predicate}
)
SELECT count(*)
FROM cand {alias}
WHERE CASE
  WHEN ({exact_residual_predicate}) AND ({filter_sql}) THEN
    public.unsafe_log(
      {_quote(E10_GUARD_UNSAFE_STATIC_WITNESS_RUN_ID)},
      {_quote(case.query_id)},
      'guard_late_residual_before_unsafe',
      'case_occ_1',
      {alias}.{rid_col},
      {alias}.secret
    )
  ELSE false
END
"""


def _guard_query(
    case: E10Case,
    relname: str,
    rid_col: str,
    alias: str,
    complete_guard_predicate: str,
    exact_residual_predicate: str,
) -> str:
    filter_sql = _base_filter(case, alias, rid_col)
    residual_predicate = _residual_after_complete_guard(
        exact_residual_predicate,
        complete_guard_predicate,
    )
    if case.query_id == "E10_Q5_invoice_region_purpose_join":
        return f"""
WITH cand AS MATERIALIZED (
  SELECT {_carrier_projection_sql(case=case, relname="invoice", rid_col=rid_col, alias=alias)}
  FROM public.invoice {alias}
  WHERE {complete_guard_predicate}
)
SELECT count(*)
FROM cand {alias}
JOIN public.user_account u ON u.user_id = {alias}.account_id
WHERE {residual_predicate}
  AND {filter_sql}
"""
    return f"""
WITH cand AS MATERIALIZED (
  SELECT {_carrier_projection_sql(case=case, relname=relname, rid_col=rid_col, alias=alias)}
  FROM public.{relname} {alias}
  WHERE {complete_guard_predicate}
)
SELECT count(*)
FROM cand {alias}
WHERE {residual_predicate}
  AND {filter_sql}
"""


def _guard_candidate_count_query(
    case: E10Case,
    relname: str,
    alias: str,
    complete_guard_predicate: str,
) -> str:
    if case.query_id == "E10_Q5_invoice_region_purpose_join":
        return f"""
SELECT count(*)
FROM public.invoice {alias}
WHERE {complete_guard_predicate}
"""
    return f"""
SELECT count(*)
FROM public.{relname} {alias}
WHERE {complete_guard_predicate}
"""


def _barrier_query(
    case: E10Case,
    relname: str,
    rid_col: str,
    alias: str,
    exact_predicate: str,
    *,
    principal_id: Optional[str] = None,
) -> str:
    filter_sql = _base_filter(case, alias, rid_col)
    pushed_filter_sql = _safe_barrier_query_predicate(case, alias, rid_col)
    exact_and_safe_query = exact_predicate + (
        f"\n    AND {pushed_filter_sql}" if pushed_filter_sql is not None else ""
    )
    outer_filter_sql = (
        ""
        if pushed_filter_sql is not None
        or filter_sql.strip().lower() in {"true", "(true)"}
        else f"\nWHERE {filter_sql}"
    )
    projection_sql = _carrier_projection_sql(
        case=case,
        relname=relname,
        rid_col=rid_col,
        alias=alias,
        required_columns=_barrier_continuation_required_columns(case, rid_col),
    )
    if case.query_id in {
        "E10_Q4_shared_document_search_audit",
        "E10_Q6_own_plus_group_shared_union",
    }:
        return _base_query(
            case,
            relname,
            rid_col,
            alias,
            exact_predicate,
            principal_id=principal_id,
        )
    if case.query_id == "E10_Q5_invoice_region_purpose_join":
        return f"""
WITH auth AS MATERIALIZED (
  SELECT {projection_sql}
  FROM public.invoice {alias}
  WHERE {exact_and_safe_query}
)
SELECT count(*)
FROM auth {alias}
JOIN public.user_account u ON u.user_id = {alias}.account_id
{outer_filter_sql}
"""
    if "ordered_export" in case.query_shape:
        return f"""
WITH auth AS MATERIALIZED (
  SELECT {projection_sql}
  FROM public.{relname} {alias}
  WHERE {exact_and_safe_query}
)
SELECT count(*)
FROM (
  SELECT {alias}.{rid_col}
  FROM auth {alias}
  ORDER BY {alias}.{rid_col}
  LIMIT 1000
) q
"""
    return f"""
WITH auth AS MATERIALIZED (
  SELECT {projection_sql}
  FROM public.{relname} {alias}
  WHERE {exact_and_safe_query}
)
SELECT count(*)
FROM auth {alias}
{outer_filter_sql}
"""


def _auth_query(
    case: E10Case,
    relname: str,
    rid_col: str,
    alias: str,
    artifact_id: str,
    policy_id: str,
    user_id: str,
    ctx_hash: str,
    keyed: bool = False,
) -> str:
    filter_sql = _base_filter(case, alias, rid_col)
    table = "auth_idx_keyed" if keyed else "auth_idx"
    key_filter = f"AND a.key_name = {_quote(rid_col)}" if keyed else ""
    key_value_filter = f"AND a.key_value = {alias}.{rid_col}::text" if keyed else ""
    if case.query_id in {
        "E10_Q7_ordered_export",
        "E10_Q10_revoked_membership_mav",
    }:
        return f"""
SELECT count(*)
FROM (
  SELECT {alias}.{rid_col}
  FROM public.{table} a
  JOIN public.{relname} {alias} ON {alias}.{rid_col} = a.rid
  WHERE a.artifact_id = {_quote(artifact_id)}
    AND a.policy_id = {_quote(policy_id)}
    AND a.user_id = {_quote(user_id)}
    AND a.ctx_hash = {_quote(ctx_hash)}
    {key_filter}
    AND a.rid_domain_id = {_quote(f"{relname}.{rid_col}")}
    AND a.base_rel_oid = {_quote(f"public.{relname}")}::regclass::oid
    {key_value_filter}
  ORDER BY {alias}.{rid_col}
  LIMIT 1000
) q
"""
    return f"""
SELECT count(*)
FROM public.{table} a
JOIN public.{relname} {alias} ON {alias}.{rid_col} = a.rid
WHERE a.artifact_id = {_quote(artifact_id)}
  AND a.policy_id = {_quote(policy_id)}
  AND a.user_id = {_quote(user_id)}
  AND a.ctx_hash = {_quote(ctx_hash)}
  {key_filter}
  AND a.rid_domain_id = {_quote(f"{relname}.{rid_col}")}
  AND a.base_rel_oid = {_quote(f"public.{relname}")}::regclass::oid
  AND {filter_sql}
  {key_value_filter}
"""


def _hybrid_query(
    case: E10Case,
    relname: str,
    rid_col: str,
    alias: str,
    artifact_id: str,
    policy_id: str,
    user_id: str,
    ctx_hash: str,
) -> str:
    filter_sql = _base_filter(case, alias, rid_col)
    ordered_limit = case.query_id in {
        "E10_Q7_ordered_export",
        "E10_Q10_revoked_membership_mav",
    }
    final_query = (
        "SELECT count(*)\n"
        "FROM (\n"
        "  SELECT q.rid\n"
        "  FROM q\n"
        "  JOIN a USING (rid)\n"
        "  ORDER BY q.rid\n"
        "  LIMIT 1000\n"
        ") ordered_authorized"
        if ordered_limit
        else "SELECT count(*)\nFROM q\nJOIN a USING (rid)"
    )
    return f"""
WITH q AS MATERIALIZED (
  SELECT {alias}.{rid_col} AS rid
  FROM public.{relname} {alias}
  WHERE {filter_sql}
),
a AS MATERIALIZED (
  SELECT ai.rid
  FROM public.auth_idx ai
  WHERE ai.artifact_id = {_quote(artifact_id)}
    AND ai.policy_id = {_quote(policy_id)}
    AND ai.user_id = {_quote(user_id)}
    AND ai.ctx_hash = {_quote(ctx_hash)}
    AND ai.rid_domain_id = {_quote(f"{relname}.{rid_col}")}
    AND ai.base_rel_oid = {_quote(f"public.{relname}")}::regclass::oid
)
{final_query}
"""


def _mav_query(
    case: E10Case,
    relname: str,
    context_id: str = "ctx_000001",
    mav_physical_relation: Optional[str] = None,
) -> str:
    if mav_physical_relation is None:
        table = _mav_table(relname, context_id)
    else:
        _qualified, table = _e10_planning_sql_relation(mav_physical_relation)
    if case.query_id in {"E10_Q7_ordered_export", "E10_Q10_revoked_membership_mav"}:
        return f"""
SELECT count(*)
FROM (
  SELECT rid
  FROM public.{table}
  ORDER BY rid
  LIMIT 1000
) q
"""
    upper = {
        "E10_Q1_support_ticket_lookup": 10000,
        "E10_Q11_ticket_exact_injection": 20000,
        "E10_Q2_tenant_dashboard": 50000,
        "E10_Q3_cross_tenant_admin_audit": 80000,
        "E10_Q4_shared_document_search_audit": 20000,
        "E10_Q5_invoice_region_purpose_join": 30000,
        "E10_Q6_own_plus_group_shared_union": 60000,
        "E10_Q8_stale_dashboard_mav": 50000,
        "E10_Q9_wrong_context_mav": 80000,
    }.get(case.query_id)
    where = f"WHERE rid <= {upper}" if upper else ""
    return f"SELECT count(*) FROM public.{table} {where}"


def _is_native_rls_template(template_id: str) -> bool:
    return template_id in E10_NATIVE_RLS_TEMPLATE_IDS


def _native_rls_policy_predicate(exact_predicate: str, alias: str) -> str:
    return exact_predicate.replace(f"{alias}.", "")


def _native_rls_query(
    case: E10Case,
    relname: str,
    rid_col: str,
    alias: str,
    *,
    policy_predicate: Optional[str] = None,
    principal_id: Optional[str] = None,
) -> str:
    annotation = (
        ""
        if policy_predicate is None
        else native_rls_policy_fingerprint_comment(
            _native_rls_policy_predicate(policy_predicate, alias)
        )
    )
    return (
        f"{annotation}\n"
        + _base_query(
            case,
            relname,
            rid_col,
            alias,
            "true",
            principal_id=principal_id,
        )
    )


def _native_rls_session_sql(sql: str) -> str:
    body = _e10_measurement_query_body(sql)
    return f"""
SET ROLE {E10_NATIVE_RLS_ROLE};
{body};
RESET ROLE;
"""


def _native_rls_plain_explain_sql(sql: str) -> str:
    body = _e10_measurement_query_body(sql)
    return f"""
SET jit = off;
SET max_parallel_workers_per_gather = 0;
SET ROLE {E10_NATIVE_RLS_ROLE};
EXPLAIN (FORMAT JSON) {body};
RESET ROLE;
"""


def _native_rls_explain_sql(sql: str) -> str:
    body = _e10_measurement_query_body(sql)
    return f"""
SET jit = off;
SET max_parallel_workers_per_gather = 0;
SET ROLE {E10_NATIVE_RLS_ROLE};
EXPLAIN (ANALYZE, FORMAT JSON, TIMING OFF, SUMMARY ON) {body};
RESET ROLE;
"""


def _require_e10_measurement_mode_identity(
    template_id: str,
    *,
    native_rls: bool,
) -> None:
    if not isinstance(template_id, str) or not template_id:
        raise PostgresError("E10 measurement template binding is missing")
    if _is_native_rls_template(template_id) is not native_rls:
        raise PostgresError(
            f"E10 measurement native-mode identity mismatch for {template_id}"
        )


def _run_e10_static_preflight(
    template_id: str,
    sql: str,
    pg_env: PostgresEnv,
    *,
    native_rls: bool,
) -> _E10StaticPreflight:
    _require_e10_measurement_mode_identity(
        template_id,
        native_rls=native_rls,
    )
    _e10_measurement_query_body(sql)
    explain_sql = (
        _native_rls_plain_explain_sql(sql) if native_rls else _plain_explain_sql(sql)
    )
    explain_json = _extract_explain_json(run_psql_command(explain_sql, pg_env))
    verification = _verify_measurement_template(template_id, sql, explain_json)
    return _E10StaticPreflight(
        template_id=template_id,
        sql=sql,
        native_rls=native_rls,
        verification=verification,
        explain_json=tuple(explain_json),
    )


def _require_e10_preflight_identity(
    preflight: _E10StaticPreflight,
    *,
    template_id: str,
    sql: str,
    native_rls: bool,
) -> None:
    if (
        not isinstance(preflight, _E10StaticPreflight)
        or preflight.template_id != template_id
        or preflight.sql != sql
        or preflight.native_rls is not native_rls
    ):
        raise PostgresError("E10 static preflight identity mismatch")


def _timing_with_static_preflight(
    measurement_explain_json: list[Mapping[str, Any]],
    preflight: _E10StaticPreflight,
) -> _E10MeasuredQueryTiming:
    timing = _timing_from_explain_json(measurement_explain_json)
    return _E10MeasuredQueryTiming(
        planning_ms=timing.planning_ms,
        execution_ms=timing.execution_ms,
        static_verifier_status=preflight.verification.status,
        static_verifier_plan_hash=preflight.verification.plan_hash,
        static_verifier_reasons=tuple(preflight.verification.reasons),
        static_verifier_explain_json=preflight.explain_json,
        measurement_explain_json=tuple(measurement_explain_json),
    )


def _measurement_explain_json(
    timing: QueryTiming,
) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(timing, _E10MeasuredQueryTiming):
        raise PostgresError("E10 measurement EXPLAIN evidence is missing")
    measured = tuple(timing.measurement_explain_json)
    if not measured:
        raise PostgresError("E10 measurement EXPLAIN JSON is empty")
    plan = measured[0].get("Plan")
    if not isinstance(plan, Mapping):
        raise PostgresError("E10 measurement EXPLAIN JSON lacks a root Plan")
    return measured


def _sql_for_template(
    case: E10Case,
    template_id: str,
    relname: str,
    rid_col: str,
    alias: str,
    exact_predicate: str,
    artifact_ids: Mapping[str, str],
    policy_id: str,
    user_id: str,
    ctx_hash: str,
    context_id: str = "ctx_000001",
    complete_guard_predicate: Optional[str] = None,
    mav_physical_relation: Optional[str] = None,
) -> str:
    if _is_native_rls_template(template_id):
        return _native_rls_session_sql(
            _native_rls_query(
                case,
                relname,
                rid_col,
                alias,
                policy_predicate=exact_predicate,
                principal_id=user_id,
            )
        )
    if template_id == "mav_scan_v1":
        return _mav_query(
            case,
            relname,
            context_id,
            mav_physical_relation=mav_physical_relation,
        )
    if template_id == "strong_auth_index_keyed_v1":
        return _auth_query(
            case,
            relname,
            rid_col,
            alias,
            artifact_ids["keyed"],
            policy_id,
            user_id,
            ctx_hash,
            keyed=True,
        )
    if template_id == "auth_index_enum_v1":
        return _auth_query(
            case,
            relname,
            rid_col,
            alias,
            artifact_ids["auth"],
            policy_id,
            user_id,
            ctx_hash,
        )
    if template_id == "hybrid_intersect_v1":
        return _hybrid_query(
            case,
            relname,
            rid_col,
            alias,
            artifact_ids["auth"],
            policy_id,
            user_id,
            ctx_hash,
        )
    if template_id == "barrier_filter_v1":
        return _barrier_query(
            case,
            relname,
            rid_col,
            alias,
            exact_predicate,
            principal_id=user_id,
        )
    if template_id == "guard_candidate_plus_residual_v1":
        if complete_guard_predicate is None:
            raise PostgresError(
                f"E10 guard template requires a complete guard predicate for {case.query_id}"
            )
        return _guard_query(
            case, relname, rid_col, alias, complete_guard_predicate, exact_predicate
        )
    return _base_query(
        case,
        relname,
        rid_col,
        alias,
        exact_predicate,
        principal_id=user_id,
    )


def _sql_for_mode(
    case: E10Case,
    mode: str,
    relname: str,
    rid_col: str,
    alias: str,
    exact_predicate: str,
    artifact_ids: Mapping[str, str],
    policy_id: str,
    user_id: str,
    ctx_hash: str,
    plan_result: Optional[PlanResult] = None,
    context_id: str = "ctx_000001",
    complete_guard_predicate: Optional[str] = None,
    mav_physical_relation: Optional[str] = None,
) -> str:
    template_choice = _plan_choice(plan_result) if mode == ADMISSION_FIRST_MODE else None
    template_id = (
        template_choice[0] if template_choice else _mode_template(case, mode)[0]
    )
    return _sql_for_template(
        case,
        template_id,
        relname,
        rid_col,
        alias,
        exact_predicate,
        artifact_ids,
        policy_id,
        user_id,
        ctx_hash,
        context_id,
        complete_guard_predicate=complete_guard_predicate,
        mav_physical_relation=mav_physical_relation,
    )


def _measure_query(
    template_id: str,
    sql: str,
    pg_env: PostgresEnv,
) -> tuple[QueryTiming, int, StaticVerification]:
    preflight = _run_e10_static_preflight(
        template_id,
        sql,
        pg_env,
        native_rls=False,
    )
    _require_e10_preflight_identity(
        preflight,
        template_id=template_id,
        sql=sql,
        native_rls=False,
    )
    row_count = _run_count(sql, pg_env)
    measurement_explain_json = _extract_explain_json(
        run_psql_command(_analyze_explain_sql(sql), pg_env)
    )
    return (
        _timing_with_static_preflight(measurement_explain_json, preflight),
        row_count,
        preflight.verification,
    )


def _measure_guard_unsafe_static_witness_query(
    sql: str,
    *,
    relname: str,
    rid_col: str,
    exact_predicate: str,
    pg_env: PostgresEnv,
) -> tuple[QueryTiming, int, StaticVerification, int, int]:
    run_psql_command(
        f"DELETE FROM public.udf_audit WHERE run_id = {_quote(E10_GUARD_UNSAFE_STATIC_WITNESS_RUN_ID)};",
        pg_env,
    )
    timing, row_count, verification = _measure_query(
        "guard_candidate_plus_residual_v1", sql, pg_env
    )
    audit_sql = f"""
SELECT jsonb_build_object(
  'udf_calls', count(*)::bigint,
  'unauthorized_observations',
    count(*) FILTER (
      WHERE d.{rid_col} IS NULL OR NOT COALESCE(({exact_predicate}), false)
    )::bigint
)::text
FROM public.udf_audit ua
LEFT JOIN public.{relname} d ON d.{rid_col} = ua.rid
WHERE ua.run_id = {_quote(E10_GUARD_UNSAFE_STATIC_WITNESS_RUN_ID)}
  AND ua.query_id = {_quote(E10_GUARD_UNSAFE_STATIC_WITNESS_QUERY_ID)}
  AND ua.occurrence_id = 'case_occ_1';
"""
    try:
        payload = json.loads(run_psql_command(audit_sql, pg_env).splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise PostgresError(
            "E10 guard+unsafe static witness audit did not emit JSON"
        ) from exc
    udf_calls = int(payload.get("udf_calls", 0))
    unauthorized = int(payload.get("unauthorized_observations", 0))
    if udf_calls <= 0:
        raise PostgresError(
            "E10 guard+unsafe static witness observed no unsafe UDF calls"
        )
    if unauthorized:
        raise PostgresError(
            "E10 guard+unsafe static witness observed unauthorized rows "
            f"before residual discharge: {unauthorized}"
        )
    return timing, row_count, verification, udf_calls, unauthorized


def _count_from_psql_output(stdout: str) -> int:
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("caprls_validated_row_count="):
            value = stripped.split("=", 1)[1]
            try:
                return int(value)
            except ValueError as exc:
                raise PostgresError(
                    f"E10 validated query emitted invalid row-count marker {stripped!r}"
                ) from exc
    raise PostgresError(
        f"E10 validated query did not emit a row-count marker:\n{stdout}"
    )


def _validated_query_script(sql: str, artifact_id: str, expected_json: str) -> str:
    body = sql.strip().rstrip(";")
    return f"""
SET jit = off;
SET max_parallel_workers_per_gather = 0;
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT 'caprls_validation_start_ms=' || (EXTRACT(EPOCH FROM clock_timestamp()) * 1000.0)::text;
SELECT public.caprls_assert_artifact_valid({_quote(artifact_id)}, {_quote(expected_json)}::jsonb);
SELECT 'caprls_validation_end_ms=' || (EXTRACT(EPOCH FROM clock_timestamp()) * 1000.0)::text;
EXPLAIN (ANALYZE, FORMAT JSON, TIMING OFF, SUMMARY ON) {body};
SELECT 'caprls_validated_row_count=' || caprls_validated_row_count.row_count::text
FROM (
{body}
) AS caprls_validated_row_count(row_count);
COMMIT;
"""


def _measure_validated_query(
    template_id: str,
    sql: str,
    artifact_id: str,
    expected_json: str,
    pg_env: PostgresEnv,
) -> tuple[QueryTiming, int, float, StaticVerification]:
    preflight = _run_e10_static_preflight(
        template_id,
        sql,
        pg_env,
        native_rls=False,
    )
    _require_e10_preflight_identity(
        preflight,
        template_id=template_id,
        sql=sql,
        native_rls=False,
    )
    output = run_psql_command(
        _validated_query_script(sql, artifact_id, expected_json), pg_env
    )
    measurement_explain_json = _extract_explain_json(output)
    timing = _timing_with_static_preflight(measurement_explain_json, preflight)
    row_count = _count_from_psql_output(output)
    validation_ms = _validation_ms_from_psql_output(output)
    return timing, row_count, validation_ms, preflight.verification


def _measure_native_rls_query(
    template_id: str,
    sql: str,
    pg_env: PostgresEnv,
) -> tuple[QueryTiming, int, StaticVerification]:
    preflight = _run_e10_static_preflight(
        template_id,
        sql,
        pg_env,
        native_rls=True,
    )
    _require_e10_preflight_identity(
        preflight,
        template_id=template_id,
        sql=sql,
        native_rls=True,
    )
    row_count = _run_count(_native_rls_session_sql(sql), pg_env)
    measurement_explain_json = _extract_explain_json(
        run_psql_command(_native_rls_explain_sql(sql), pg_env)
    )
    return (
        _timing_with_static_preflight(measurement_explain_json, preflight),
        row_count,
        preflight.verification,
    )


def _artifact_kind_for_template(template_id: str) -> Optional[str]:
    if template_id == "mav_scan_v1":
        return "mav"
    if template_id == "strong_auth_index_keyed_v1":
        return "keyed"
    if template_id in {"auth_index_enum_v1", "hybrid_intersect_v1"}:
        return "auth"
    return None


def _measured_mode_record(
    *,
    template_id: str,
    timing: QueryTiming,
    row_count: int,
    filtered_rows: int,
    guard_candidate_rows: Optional[int],
    explain_policy_evals: Optional[int],
    artifact_ids: Mapping[str, str],
    build_ms: Mapping[str, float],
    storage_bytes: Mapping[str, int],
    validation_ms: float = 0.0,
    same_snapshot: bool = False,
    validation_isolation_level: Optional[str] = None,
    static_verification: Optional[StaticVerification] = None,
    runner_sql: Optional[str] = None,
) -> E10ModeMeasurement:
    artifact_kind = _artifact_kind_for_template(template_id)
    artifact_lookups = 1 if artifact_kind is not None else 0
    if template_id == "guard_candidate_plus_residual_v1":
        candidate_rows = (
            None if guard_candidate_rows is None else int(guard_candidate_rows)
        )
        residual_checks = candidate_rows
        policy_evals = (
            None if explain_policy_evals is None else int(explain_policy_evals)
        )
        base_fetches = candidate_rows
    elif artifact_kind is not None:
        candidate_rows = row_count
        residual_checks = 0
        policy_evals = 0
        base_fetches = row_count
    elif _is_native_rls_template(template_id):
        candidate_rows = row_count
        residual_checks = 0
        policy_evals = (
            None if explain_policy_evals is None else int(explain_policy_evals)
        )
        base_fetches = row_count
    else:
        candidate_rows = filtered_rows
        residual_checks = 0
        policy_evals = (
            None if explain_policy_evals is None else int(explain_policy_evals)
        )
        base_fetches = filtered_rows
    return E10ModeMeasurement(
        timing=timing,
        row_count=row_count,
        policy_evals=policy_evals,
        residual_checks=residual_checks,
        candidate_rows=candidate_rows,
        authorized_rows=row_count,
        artifact_lookups=artifact_lookups,
        base_fetches=base_fetches,
        build_ms=build_ms.get(artifact_kind or "", 0.0),
        storage_bytes=storage_bytes.get(artifact_kind or "", 0),
        artifact_versions=(
            {artifact_ids[artifact_kind]: 0} if artifact_kind is not None else {}
        ),
        validation_ms=validation_ms,
        same_snapshot=same_snapshot,
        validation_isolation_level=validation_isolation_level,
        static_verifier_status="pass"
        if static_verification is None
        else static_verification.status,
        static_verifier_plan_hash=None
        if static_verification is None
        else static_verification.plan_hash,
        static_verifier_reasons=()
        if static_verification is None
        else tuple(static_verification.reasons),
        static_verifier_explain_json=timing.static_verifier_explain_json,
        runner_sql=runner_sql,
    )


def _e10_unsafe_pushdown_measurement(
    case: E10Case,
    relname: str,
    rid_col: str,
    alias: str,
    exact_predicate: str,
    pg_env: PostgresEnv,
) -> E10ModeMeasurement:
    if case.query_id != E10_BARRIER_QUERY_ID:
        raise PostgresError(
            f"E10 unsafe-pushdown diagnostic is only defined for {E10_BARRIER_QUERY_ID}"
        )
    if relname != "document" or rid_col != "doc_id":
        raise PostgresError("E10 unsafe-pushdown diagnostic expects document/doc_id")
    run_id = f"e10_{case.query_id}_unsafe_pushdown"
    filter_sql = _base_filter(case, alias, rid_col)
    script = f"""
SET jit = off;
SET max_parallel_workers_per_gather = 0;
TRUNCATE public.udf_audit;
DROP TABLE IF EXISTS pg_temp.oracle_authorized;
CREATE TEMP TABLE oracle_authorized AS
SELECT {alias}.{rid_col} AS rid
FROM public.{relname} {alias}
WHERE {exact_predicate}
  AND {filter_sql};
CREATE UNIQUE INDEX oracle_authorized_rid_idx ON oracle_authorized(rid);

DROP TABLE IF EXISTS pg_temp.e10_positive_result;
CREATE TEMP TABLE e10_positive_result AS
WITH raw AS MATERIALIZED (
  SELECT {alias}.*,
         public.unsafe_log(
           {_quote(run_id)},
           {_quote(case.query_id)},
           'raw_pushdown_positive_control',
           'case_occ_1',
           {alias}.{rid_col},
           {alias}.secret
         ) AS observed
  FROM public.{relname} {alias}
  WHERE {filter_sql}
)
SELECT count(*)::bigint AS row_count
FROM raw {alias}
WHERE observed
  AND {exact_predicate};

WITH audit AS (
  SELECT
    count(*)::bigint AS udf_calls,
    count(*) FILTER (WHERE o.rid IS NULL)::bigint AS unauthorized_observations
  FROM public.udf_audit a
  LEFT JOIN oracle_authorized o ON o.rid = a.rid
  WHERE a.run_id = {_quote(run_id)}
    AND a.occurrence_id = 'case_occ_1'
)
SELECT jsonb_build_object(
  'row_count', (SELECT row_count FROM e10_positive_result),
  'authorized_rows', (SELECT count(*) FROM oracle_authorized),
  'base_fetches', (SELECT count(*) FROM public.{relname} {alias} WHERE {filter_sql}),
  'udf_calls', (SELECT udf_calls FROM audit),
  'unauthorized_observations', (SELECT unauthorized_observations FROM audit)
)::text;
"""
    started = time.monotonic()
    output = run_psql_command(script, pg_env)
    elapsed_ms = (time.monotonic() - started) * 1000.0
    try:
        payload = json.loads(output.splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise PostgresError(
            f"E10 unsafe-pushdown diagnostic did not emit JSON: {output}"
        ) from exc
    unauthorized = int(payload["unauthorized_observations"])
    if unauthorized <= 0:
        raise PostgresError(
            "E10 unsafe-pushdown positive control observed no unauthorized rows"
        )
    return E10ModeMeasurement(
        timing=QueryTiming(planning_ms=0.0, execution_ms=elapsed_ms),
        row_count=int(payload["row_count"]),
        policy_evals=int(payload["base_fetches"]),
        residual_checks=0,
        candidate_rows=int(payload["udf_calls"]),
        authorized_rows=int(payload["authorized_rows"]),
        artifact_lookups=0,
        base_fetches=int(payload["base_fetches"]),
        build_ms=0.0,
        storage_bytes=0,
        artifact_versions={},
        udf_calls=int(payload["udf_calls"]),
        unauthorized_observations=unauthorized,
    )


def _prepare_e10_case_postgres_measurements(
    *,
    root: Path,
    case: E10Case,
    context_id: str,
    context: Mapping[str, Any],
    context_version: int,
    user_id: str,
    ctx_hash: str,
    pg_env: PostgresEnv,
    policies: Mapping[str, Mapping[str, Any]],
    exact: Mapping[tuple[str, str], str],
    shared_artifact_ids: Mapping[str, Mapping[str, str]],
    shared_artifact_rows: Mapping[str, Mapping[str, int]],
    shared_build_ms: Mapping[str, Mapping[str, float]],
    shared_storage_bytes: Mapping[str, Mapping[str, int]],
    base_rows: Mapping[str, int],
    negative_handle: Optional[E10NegativeStateHandle],
    measurements: dict[tuple[str, str], E10ModeMeasurement],
    plan_results: dict[tuple[str, str], PlanResult],
    query_plans: dict[tuple[str, str], Mapping[str, Any]],
    candidate_measurements: dict[tuple[str, str], E10ModeMeasurement],
    candidate_query_plans: dict[tuple[str, str], Mapping[str, Any]],
    diagnostic_measurements: dict[tuple[str, str], E10ModeMeasurement],
) -> tuple[
    E10PlanningReceipt,
    E10PlanningExpectation,
    E10AdmissionBundle,
]:
    relname, rid_col, policy_id, alias = _target_for_case(case)
    rel_exact = exact[(relname, alias)]
    complete_guard = (
        _complete_guard_predicate(case, alias, rid_col, context, relname)
        if case.complete_guard_sql_template is not None
        else None
    )
    filter_sql = _e10_planning_query_predicate(case, alias, rid_col)
    case_artifact_ids = dict(shared_artifact_ids[relname])
    mav_physical_relation = f"public.{_mav_table(relname, context_id)}"
    mav_dependency_profile = "legacy5"
    if negative_handle is not None:
        if negative_handle.spec.case_query_id != case.query_id:
            raise PostgresError("E10 negative lifecycle handle case mismatch")
        case_artifact_ids["mav"] = negative_handle.spec.artifact_id
        mav_physical_relation = negative_handle.spec.physical_relation
        mav_dependency_profile = "state9"
    planning_expectation = _e10_planning_expectation(
        root=root,
        case=case,
        context_id=context_id,
        context=context,
        context_hash=ctx_hash,
        context_version=context_version,
        policy=policies[policy_id],
        exact_predicate=rel_exact,
        guard_predicate=complete_guard,
        query_predicate=filter_sql,
        artifact_ids=case_artifact_ids,
        mav_physical_relation=mav_physical_relation,
        mav_dependency_profile=mav_dependency_profile,
        scope="fixture",
    )
    observation, collector_sql_digest = _collect_e10_planning_catalog_observation(
        planning_expectation,
        pg_env,
    )
    planning_receipt = _issue_e10_planning_receipt(
        planning_expectation,
        observation,
        collector_sql_digest=collector_sql_digest,
    )
    replay = _replay_e10_planning_receipt(
        planning_receipt,
        planning_expectation,
        require_production=False,
    )
    if not replay.valid:
        raise PostgresError(
            "E10 catalog observation failed before costing: "
            + ";".join(replay.reasons)
        )
    planning_admission_bundle = _issue_e10_admission_bundle(
        root=root,
        case=case,
        receipt=planning_receipt,
        expectation=planning_expectation,
        require_production=False,
    )
    admission_replay = _replay_e10_admission_bundle(
        planning_admission_bundle,
        root=root,
        case=case,
        receipt=planning_receipt,
        expectation=planning_expectation,
        require_production=False,
    )
    if not admission_replay.valid:
        raise PostgresError(
            "E10 typed admission failed before costing: "
            + ";".join(admission_replay.reasons)
        )

    filtered_rows = _run_count(
        f"SELECT count(*) FROM public.{relname} {alias} WHERE {filter_sql};",
        pg_env,
    )
    case_artifact_rows = dict(shared_artifact_rows[relname])
    case_build_ms = dict(shared_build_ms[relname])
    case_storage_bytes = dict(shared_storage_bytes[relname])
    if negative_handle is not None:
        _qualified, mav_table = _e10_planning_sql_relation(mav_physical_relation)
        case_artifact_rows["mav"] = _run_count(
            f"SELECT count(*) FROM public.{mav_table};",
            pg_env,
        )
        case_build_ms["mav"] = 0.0
        case_storage_bytes["mav"] = _relation_size_bytes(
            mav_physical_relation,
            pg_env,
        )
    artifacts = _artifact_metadata_for_case(
        case,
        relname,
        rid_col,
        case_artifact_ids,
        case_artifact_rows,
        case_build_ms,
        case_storage_bytes,
        planning_receipt=planning_receipt,
        planning_expectation=planning_expectation,
        require_production_receipt=False,
    )
    artifact_relations = {"mav": mav_physical_relation}
    assessment_by_kind = {
        item.kind: item for item in planning_receipt.artifact_assessments
    }

    def _receipt_allows_template(template_id: str) -> bool:
        required = _required_artifact_for_template(template_id)
        if required is None:
            return True
        assessment = assessment_by_kind.get(required)
        return bool(assessment is not None and assessment.usable)

    def _case_explain_cost(
        template_id: str,
    ) -> Optional[tuple[float, Mapping[str, Any]]]:
        if (
            _template_unavailable_reason(case, template_id) is not None
            or not _receipt_allows_template(template_id)
        ):
            return None
        sql = _sql_for_template(
            case,
            template_id,
            relname,
            rid_col,
            alias,
            rel_exact,
            case_artifact_ids,
            policy_id,
            user_id,
            ctx_hash,
            context_id,
            complete_guard_predicate=complete_guard,
            mav_physical_relation=mav_physical_relation,
        )
        return _prospective_pg_cost(sql, pg_env)

    invocation = _planner_invocation_for_case(
        case,
        ADMISSION_FIRST_MODE,
        relname=relname,
        rid_col=rid_col,
        policy_id=policy_id,
        artifacts=artifacts,
        base_rows=base_rows[relname],
        filtered_rows=filtered_rows,
        alias=alias,
        exact_predicate=rel_exact,
        complete_guard_predicate=complete_guard,
        query_predicate=filter_sql,
        planning_receipt=planning_receipt,
        planning_expectation=planning_expectation,
        planning_admission_bundle=planning_admission_bundle,
        require_production_receipt=False,
        root=root,
        artifact_relations=artifact_relations,
        explain_cost_fn=_case_explain_cost,
    )
    contract_plan = invocation.occurrence_result
    if invocation.production_completed_roots:
        raise PostgresError("E10 ordinary runner entered the retired production path")
    plan_results[(case.query_id, ADMISSION_FIRST_MODE)] = contract_plan
    query_plans[(case.query_id, ADMISSION_FIRST_MODE)] = invocation.query_plan

    # Selection is complete before this independent reference is executed.
    # The reference outcome cannot influence candidate admission or ranking.
    reference_row_count = _run_count(
        _base_query(
            case,
            relname,
            rid_col,
            alias,
            rel_exact,
            principal_id=user_id,
        ),
        pg_env,
    )

    for candidate in contract_plan.candidates:
        if (
            not candidate.accepted
            or _template_unavailable_reason(case, candidate.template_id) is not None
            or not _receipt_allows_template(candidate.template_id)
        ):
            continue
        candidate_sql = _sql_for_template(
            case,
            candidate.template_id,
            relname,
            rid_col,
            alias,
            rel_exact,
            case_artifact_ids,
            policy_id,
            user_id,
            ctx_hash,
            context_id,
            complete_guard_predicate=complete_guard,
            mav_physical_relation=mav_physical_relation,
        )
        candidate_artifact_kind = _artifact_kind_for_template(
            candidate.template_id
        )
        if candidate_artifact_kind is not None:
            (
                candidate_timing,
                candidate_row_count,
                candidate_validation_ms,
                candidate_static_verification,
            ) = _measure_validated_query(
                candidate.template_id,
                candidate_sql,
                case_artifact_ids[candidate_artifact_kind],
                _artifact_dependency_expected_json(
                    policy_id,
                    ctx_hash,
                    relname,
                    rid_col,
                ),
                pg_env,
            )
            candidate_same_snapshot = True
            candidate_isolation = "repeatable_read"
        else:
            (
                candidate_timing,
                candidate_row_count,
                candidate_static_verification,
            ) = _measure_query(candidate.template_id, candidate_sql, pg_env)
            candidate_validation_ms = 0.0
            candidate_same_snapshot = False
            candidate_isolation = None
        _require_e10_reference_match(
            case,
            candidate.template_id,
            actual_row_count=candidate_row_count,
            reference_row_count=reference_row_count,
        )
        guard_candidate_rows = (
            _run_count(
                _guard_candidate_count_query(
                    case,
                    relname,
                    alias,
                    complete_guard,
                ),
                pg_env,
            )
            if candidate.template_id == "guard_candidate_plus_residual_v1"
            and complete_guard is not None
            else None
        )
        explain_policy_evals = _policy_eval_rows_from_explain(
            _measurement_explain_json(candidate_timing),
            template_id=candidate.template_id,
            relname=relname,
            exact_predicate=rel_exact,
        )
        candidate_measurements[(case.query_id, candidate.template_id)] = (
            _measured_mode_record(
                template_id=candidate.template_id,
                timing=candidate_timing,
                row_count=candidate_row_count,
                filtered_rows=filtered_rows,
                guard_candidate_rows=guard_candidate_rows,
                explain_policy_evals=explain_policy_evals,
                artifact_ids=case_artifact_ids,
                build_ms=case_build_ms,
                storage_bytes=case_storage_bytes,
                validation_ms=candidate_validation_ms,
                same_snapshot=candidate_same_snapshot,
                validation_isolation_level=candidate_isolation,
                static_verification=candidate_static_verification,
                runner_sql=candidate_sql,
            )
        )
        candidate_query_plans[(case.query_id, candidate.template_id)] = (
            _query_plan_for_forced_candidate(
                case,
                problem=invocation.problem,
                occurrence_result=contract_plan,
                candidate=candidate,
                alias=alias,
                exact_predicate=rel_exact,
                complete_guard_predicate=complete_guard,
                query_predicate=filter_sql,
                planning_receipt=planning_receipt,
                planning_expectation=planning_expectation,
                planning_admission_bundle=planning_admission_bundle,
                require_production_receipt=False,
                root=root,
                artifact_relations=artifact_relations,
            )
        )

    for mode in sorted(REQUIRED_MODES, key=mode_execution_order_key):
        plan_result = plan_results.get((case.query_id, mode))
        template_choice = (
            _plan_choice(plan_result) if mode == ADMISSION_FIRST_MODE else None
        )
        template_id = (
            template_choice[0] if template_choice else _mode_template(case, mode)[0]
        )
        if _template_unavailable_reason(case, template_id) is not None:
            continue
        if not _receipt_allows_template(template_id):
            continue
        if _is_native_rls_template(template_id):
            sql = _native_rls_query(
                case,
                relname,
                rid_col,
                alias,
                policy_predicate=rel_exact,
                principal_id=user_id,
            )
            timing, row_count, static_verification = _measure_native_rls_query(
                template_id,
                sql,
                pg_env,
            )
            validation_ms = 0.0
            same_snapshot = False
            validation_isolation_level = None
        else:
            sql = _sql_for_mode(
                case,
                mode,
                relname,
                rid_col,
                alias,
                rel_exact,
                case_artifact_ids,
                policy_id,
                user_id,
                ctx_hash,
                plan_result=plan_result,
                context_id=context_id,
                complete_guard_predicate=complete_guard,
                mav_physical_relation=mav_physical_relation,
            )
            artifact_kind = _artifact_kind_for_template(template_id)
            if artifact_kind is not None:
                (
                    timing,
                    row_count,
                    validation_ms,
                    static_verification,
                ) = _measure_validated_query(
                    template_id,
                    sql,
                    case_artifact_ids[artifact_kind],
                    _artifact_dependency_expected_json(
                        policy_id,
                        ctx_hash,
                        relname,
                        rid_col,
                    ),
                    pg_env,
                )
                same_snapshot = True
                validation_isolation_level = "repeatable_read"
            else:
                timing, row_count, static_verification = _measure_query(
                    template_id,
                    sql,
                    pg_env,
                )
                validation_ms = 0.0
                same_snapshot = False
                validation_isolation_level = None
        _require_e10_reference_match(
            case,
            mode,
            actual_row_count=row_count,
            reference_row_count=reference_row_count,
        )
        guard_candidate_rows = (
            _run_count(
                _guard_candidate_count_query(
                    case,
                    relname,
                    alias,
                    complete_guard,
                ),
                pg_env,
            )
            if template_id == "guard_candidate_plus_residual_v1"
            and complete_guard is not None
            else None
        )
        explain_policy_evals = _policy_eval_rows_from_explain(
            _measurement_explain_json(timing),
            template_id=template_id,
            relname=relname,
            exact_predicate=rel_exact,
        )
        mode_measurement = _measured_mode_record(
            template_id=template_id,
            timing=timing,
            row_count=row_count,
            filtered_rows=filtered_rows,
            guard_candidate_rows=guard_candidate_rows,
            explain_policy_evals=explain_policy_evals,
            artifact_ids=case_artifact_ids,
            build_ms=case_build_ms,
            storage_bytes=case_storage_bytes,
            validation_ms=validation_ms,
            same_snapshot=same_snapshot,
            validation_isolation_level=validation_isolation_level,
            static_verification=static_verification,
            runner_sql=sql,
        )
        measurements[(case.query_id, mode)] = mode_measurement
    if case.query_id == E10_BARRIER_QUERY_ID:
        diagnostic_measurements[
            (case.query_id, DIAGNOSTIC_UNSAFE_PUSHDOWN_MODE)
        ] = _e10_unsafe_pushdown_measurement(
            case,
            relname,
            rid_col,
            alias,
            rel_exact,
            pg_env,
        )
    return (
        planning_receipt,
        planning_expectation,
        planning_admission_bundle,
    )


def _prepare_postgres_measurements(
    root: Path,
    manifest: Mapping[str, Any],
    pg_env: PostgresEnv,
    *,
    context_id: str,
    prepare_dataset: bool,
) -> E10PostgresMeasurements:
    dataset = manifest.get("dataset") or {}
    scale = str(dataset.get("scale", "1e5"))
    seed = int(dataset.get("seed", 52))
    if prepare_dataset:
        generate_synthetic_saas(
            root, pg_env, scale=scale, seed=seed, verify=True, output_dir=None
        )

    context = _load_context(context_id, pg_env)
    user_id = str(context["user_id"])
    target_context, _alternate_context = _load_e10_state_contexts(
        context_id,
        pg_env,
    )
    if target_context["context_id"] != context_id:
        raise PostgresError("E10 planning context identifier mismatch")
    if target_context["canonical_context"] != dict(context):
        raise PostgresError("E10 planning context payload mismatch")
    if target_context["principal_id"] != user_id:
        raise PostgresError("E10 planning context principal mismatch")
    ctx_hash = str(target_context["ctx_hash"])
    if _canonical_digest(context) != ctx_hash:
        raise PostgresError("E10 planning context semantic digest mismatch")
    context_version = int(target_context["version"])
    pg_version = run_psql_command("SHOW server_version;", pg_env)

    policies = {
        policy_id: _load_policy(root, policy_id)
        for policy_id in {
            "tenant_group",
            "tenant_only_ticket",
            "purpose_region_invoice",
        }
    }
    exact: dict[tuple[str, str], str] = {}
    for relname, rid_col, policy_id, alias in {
        _target_for_case(case) for case in CASES
    }:
        policy = policies[policy_id]
        exact[(relname, alias)] = _render_policy_predicate(
            str(policy["exact_sql_template"]),
            alias=alias,
            rid_col=rid_col,
            context=context,
            relname=relname,
        )
    for relname, _rid_col, _policy_id, alias in sorted(
        {_target_for_case(case) for case in CASES}
    ):
        configure_native_rls(
            rel=f"public.{relname}",
            policy_name=f"caprls_e10_policy_{relname}",
            predicate=_native_rls_policy_predicate(exact[(relname, alias)], alias),
            role_name=E10_NATIVE_RLS_ROLE,
            pg_env=pg_env,
        )

    artifact_ids: dict[str, dict[str, str]] = {}
    build_ms: dict[str, dict[str, float]] = {}
    storage_bytes: dict[str, dict[str, int]] = {}
    artifact_rows: dict[str, dict[str, int]] = {}
    base_rows: dict[str, int] = {}
    for relname, rid_col, policy_id, alias in sorted(
        {_target_for_case(case) for case in CASES}
    ):
        rel_exact = exact[(relname, alias)]
        artifact_ids[relname] = _artifact_ids_for_context(relname, context_id)
        build_ms[relname] = {
            "auth": _timed_sql_script(
                _build_auth_idx_sql(
                    artifact_ids[relname]["auth"],
                    policy_id,
                    user_id,
                    ctx_hash,
                    relname,
                    rid_col,
                    alias,
                    rel_exact,
                ),
                pg_env,
            ),
            "keyed": _timed_sql_script(
                _build_keyed_sql(
                    artifact_ids[relname]["keyed"],
                    policy_id,
                    user_id,
                    ctx_hash,
                    relname,
                    rid_col,
                    alias,
                    rel_exact,
                ),
                pg_env,
            ),
            "mav": _timed_sql_script(
                _build_mav_sql(
                    artifact_ids[relname]["mav"],
                    policy_id,
                    ctx_hash,
                    relname,
                    rid_col,
                    alias,
                    rel_exact,
                    context_id,
                ),
                pg_env,
            ),
        }
        storage_bytes[relname] = {
            "auth": _relation_size_bytes("public.auth_idx", pg_env),
            "keyed": _relation_size_bytes("public.auth_idx_keyed", pg_env),
            "mav": _relation_size_bytes(
                f"public.{_mav_table(relname, context_id)}", pg_env
            ),
        }
        artifact_rows[relname] = {
            "auth": _run_count(
                f"SELECT count(*) FROM public.auth_idx WHERE artifact_id = {_quote(artifact_ids[relname]['auth'])};",
                pg_env,
            ),
            "keyed": _run_count(
                f"SELECT count(*) FROM public.auth_idx_keyed WHERE artifact_id = {_quote(artifact_ids[relname]['keyed'])};",
                pg_env,
            ),
            "mav": _run_count(
                f"SELECT count(*) FROM public.{_mav_table(relname, context_id)};",
                pg_env,
            ),
        }
        base_rows[relname] = _run_count(
            f"SELECT count(*) FROM public.{relname};", pg_env
        )

    measurements: dict[tuple[str, str], E10ModeMeasurement] = {}
    plan_results: dict[tuple[str, str], PlanResult] = {}
    query_plans: dict[tuple[str, str], Mapping[str, Any]] = {}
    candidate_measurements: dict[tuple[str, str], E10ModeMeasurement] = {}
    candidate_query_plans: dict[tuple[str, str], Mapping[str, Any]] = {}
    diagnostic_measurements: dict[tuple[str, str], E10ModeMeasurement] = {}
    planning_receipts: dict[str, E10PlanningReceipt] = {}
    planning_expectations: dict[str, E10PlanningExpectation] = {}
    planning_admission_bundles: dict[str, E10AdmissionBundle] = {}
    for case in CASES:
        negative_handle: Optional[E10NegativeStateHandle] = None
        if case.query_id in E10_NEGATIVE_STATE_KIND_BY_QUERY:
            negative_handle = _materialize_e10_negative_state(
                root,
                case,
                context_id,
                pg_env,
            )
        try:
            (
                receipt,
                expectation,
                admission_bundle,
            ) = _prepare_e10_case_postgres_measurements(
                root=root,
                case=case,
                context_id=context_id,
                context=context,
                context_version=context_version,
                user_id=user_id,
                ctx_hash=ctx_hash,
                pg_env=pg_env,
                policies=policies,
                exact=exact,
                shared_artifact_ids=artifact_ids,
                shared_artifact_rows=artifact_rows,
                shared_build_ms=build_ms,
                shared_storage_bytes=storage_bytes,
                base_rows=base_rows,
                negative_handle=negative_handle,
                measurements=measurements,
                plan_results=plan_results,
                query_plans=query_plans,
                candidate_measurements=candidate_measurements,
                candidate_query_plans=candidate_query_plans,
                diagnostic_measurements=diagnostic_measurements,
            )
            planning_receipts[case.query_id] = receipt
            planning_expectations[case.query_id] = expectation
            planning_admission_bundles[case.query_id] = admission_bundle
        finally:
            if negative_handle is not None:
                _restore_e10_negative_state(negative_handle, pg_env)

    return E10PostgresMeasurements(
        pg_version=pg_version,
        context_id=context_id,
        ctx_hash=ctx_hash,
        measurements=measurements,
        plan_results=plan_results,
        candidate_measurements=candidate_measurements,
        diagnostic_measurements=diagnostic_measurements,
        query_plans=query_plans,
        candidate_query_plans=candidate_query_plans,
        planning_receipts=planning_receipts,
        planning_expectations=planning_expectations,
        planning_admission_bundles=planning_admission_bundles,
    )


def _mode_template(case: E10Case, mode: str) -> tuple[str, str]:
    mode = normalize_mode_id(mode)
    if mode == ADMISSION_FIRST_MODE:
        return case.contract_template_id, case.contract_alternative
    if mode == "local-greedy":
        return case.local_template_id, case.local_alternative
    if mode == DIAGNOSTIC_UNSAFE_PUSHDOWN_MODE:
        return "raw_pushdown_positive_control_v1", "UnsafeRawPushdownPositiveControl"
    return {
        "native-pg-rls": ("native_pg_rls_v1", "NativePG-RLS"),
        "native-pg-rls-physical-design": (
            "native_pg_rls_physical_design_v1",
            "NativePG-RLS+PhysicalDesign",
        ),
        "barrier-only": ("barrier_filter_v1", "BarrierFilter"),
        "auth-index-enum-only": ("auth_index_enum_v1", "AuthorizationIndexSeek"),
        "strong-auth-index": ("strong_auth_index_keyed_v1", "StrongAuthIndexBaseline"),
        "mav-only": ("mav_scan_v1", "MaterializedAuthorizedViewScan"),
        "guard-mandatory-discharge": (
            "guard_candidate_plus_residual_v1",
            "Guard+LateResidual",
        ),
    }[mode]


def _candidate_payload_for_v2(candidate: CandidatePlan) -> dict[str, Any]:
    payload = candidate.to_dict()
    payload.setdefault("kappa_sem", {})
    payload.setdefault("certificate", None)
    payload.setdefault("certificate_check", None)
    payload.setdefault("pruned_by_dominance", None)
    return payload


def _replay_e10_record_planning_receipt(
    *,
    case: E10Case,
    receipt: Optional[E10PlanningReceipt],
    expectation: Optional[E10PlanningExpectation],
    query_plan: Optional[Mapping[str, Any]],
    require_production: bool,
) -> Optional[E10PlanningReplay]:
    if receipt is None or expectation is None:
        if require_production:
            raise PostgresError("E10 production record lacks its planning receipt")
        return None
    if expectation.case_query_id != case.query_id:
        raise PostgresError("E10 record planning receipt case mismatch")
    if expectation.registry_inventory != _e10_registry_inventory():
        raise PostgresError("E10 record planning registry inventory changed")
    replay = _replay_e10_planning_receipt(
        receipt,
        expectation,
        require_production=require_production,
    )
    if not replay.valid:
        raise PostgresError(
            "E10 record planning receipt replay failed: " + ";".join(replay.reasons)
        )
    if query_plan is not None:
        if query_plan.get("planning_receipt_digest") != receipt.receipt_digest:
            raise PostgresError("E10 query-plan planning receipt digest mismatch")
        if query_plan.get("planning_receipt") != receipt.to_dict():
            raise PostgresError("E10 query-plan planning receipt payload mismatch")
    return replay


def _replay_e10_record_admission_bundle(
    *,
    root: Path,
    case: E10Case,
    bundle: Optional[E10AdmissionBundle],
    receipt: Optional[E10PlanningReceipt],
    expectation: Optional[E10PlanningExpectation],
    query_plan: Optional[Mapping[str, Any]],
    require_production: bool,
) -> Optional[E10AdmissionReplay]:
    if bundle is None or receipt is None or expectation is None:
        if require_production:
            raise PostgresError(
                "E10 production record lacks its typed admission bundle"
            )
        return None
    replay = _replay_e10_admission_bundle(
        bundle,
        root=root,
        case=case,
        receipt=receipt,
        expectation=expectation,
        require_production=require_production,
    )
    if not replay.valid:
        raise PostgresError(
            "E10 record typed admission replay failed: " + ";".join(replay.reasons)
        )
    if query_plan is not None:
        if query_plan.get("planning_admission_bundle_digest") != bundle.bundle_digest:
            raise PostgresError("E10 query-plan typed admission bundle digest mismatch")
        if query_plan.get("planning_admission_bundle") != bundle.to_dict():
            raise PostgresError(
                "E10 query-plan typed admission bundle payload mismatch"
            )
    return replay


def _validate_e10_record_planning_sources(
    *,
    root: Path,
    case: E10Case,
    expectation: E10PlanningExpectation,
    context_id: str,
    context_hash: Optional[str],
) -> None:
    if context_hash is None:
        raise PostgresError("E10 production record context digest is missing")
    relname, rid_col, policy_id, alias = _target_for_case(case)
    identity_checks = {
        "case": expectation.case_query_id == case.query_id,
        "occurrence": expectation.occurrence_id == case.query_id,
        "relation": expectation.relation_name == relname,
        "rid": expectation.rid_col == rid_col,
        "rid_domain": expectation.rid_domain_id == f"{relname}.{rid_col}",
        "policy": expectation.policy_id == policy_id,
        "context_id": expectation.context_id == context_id,
        "context_hash": expectation.context_hash == context_hash,
        "registry": expectation.registry_inventory == _e10_registry_inventory(),
    }
    mismatches = sorted(name for name, ok in identity_checks.items() if not ok)
    if mismatches:
        raise PostgresError(
            "E10 production record planning source identity mismatch: "
            + ",".join(mismatches)
        )
    policy_path = root / "manifests" / "policies" / "synthetic_saas_policies.yaml"
    policy = _load_policy(root, policy_id)
    if file_sha256(policy_path) != expectation.policy_manifest_digest:
        raise PostgresError("E10 production record policy manifest digest changed")
    if _canonical_digest(dict(policy)) != expectation.policy_config_digest:
        raise PostgresError("E10 production record policy configuration changed")
    if (
        _canonical_digest(_e10_policy_definition_payload(policy_id, policy))
        != expectation.policy_definition_digest
    ):
        raise PostgresError("E10 production record policy definition changed")
    context = json.loads(expectation.canonical_context_json)
    rendered_exact = _render_policy_predicate(
        str(policy["exact_sql_template"]),
        alias=alias,
        rid_col=rid_col,
        context=context,
        relname=relname,
    )
    rendered_guard = (
        _complete_guard_predicate(case, alias, rid_col, context, relname)
        if case.complete_guard_sql_template is not None
        else None
    )
    source_digests = {
        "exact": _e10_sql_fragment_digest(rendered_exact)
        == expectation.exact_predicate_digest,
        "guard": _e10_sql_fragment_digest(rendered_guard)
        == expectation.guard_predicate_digest,
        "query": _e10_sql_fragment_digest(
            _e10_planning_query_predicate(case, alias, rid_col)
        )
        == expectation.query_predicate_digest,
    }
    digest_mismatches = sorted(name for name, ok in source_digests.items() if not ok)
    if digest_mismatches:
        raise PostgresError(
            "E10 production record rendered planning source changed: "
            + ",".join(digest_mismatches)
        )
    expected_ids = _artifact_ids_for_context(relname, context_id)
    expected_mav_relation = f"public.{_mav_table(relname, context_id)}"
    expected_mav_profile = "legacy5"
    if case.query_id in E10_NEGATIVE_STATE_KIND_BY_QUERY:
        expected_ids["mav"], expected_mav_relation = _e10_negative_state_identifiers(
            case.query_id, context_id
        )
        expected_mav_profile = "state9"
    expected_artifacts = (
        ("auth_idx", expected_ids["auth"], "public.auth_idx", "legacy5"),
        (
            "auth_idx_keyed",
            expected_ids["keyed"],
            "public.auth_idx_keyed",
            "legacy5",
        ),
        ("mav", expected_ids["mav"], expected_mav_relation, expected_mav_profile),
    )
    actual_artifacts = tuple(
        (
            item.kind,
            item.artifact_id,
            item.physical_relation,
            item.dependency_profile,
        )
        for item in expectation.artifacts
    )
    if actual_artifacts != expected_artifacts:
        raise PostgresError("E10 production record artifact identity changed")
    if {item.kind for item in expectation.artifacts if item.declared} != set(
        case.available_artifacts
    ):
        raise PostgresError("E10 production record artifact capability changed")


def _record(
    root: Path,
    manifest_path: Path,
    case: E10Case,
    mode: str,
    run_kind: str = "normal_mode",
    candidate: Optional[CandidatePlan] = None,
    measurement: Optional[E10ModeMeasurement] = None,
    plan_result: Optional[PlanResult] = None,
    query_plan: Optional[Mapping[str, Any]] = None,
    pg_version: str = "not_executed_e10_case_study",
    context_id: str = "e10_saas_case_study",
    ctx_hash: Optional[str] = None,
    manifest: Mapping[str, Any] | None = None,
    planning_receipt: Optional[E10PlanningReceipt] = None,
    planning_expectation: Optional[E10PlanningExpectation] = None,
    planning_admission_bundle: Optional[E10AdmissionBundle] = None,
    require_production_receipt: bool = False,
) -> Dict[str, Any]:
    mode = normalize_mode_id(mode)
    manifest_payload = (
        manifest if manifest is not None else _load_manifest(manifest_path)
    )
    manifest_id = str(manifest_payload.get("manifest_id", "e10_case_study_v1"))
    dataset_payload = _dataset_record_from_manifest(manifest_path, manifest_payload)
    planning_replay = _replay_e10_record_planning_receipt(
        case=case,
        receipt=planning_receipt,
        expectation=planning_expectation,
        query_plan=query_plan,
        require_production=require_production_receipt,
    )
    admission_replay = _replay_e10_record_admission_bundle(
        root=root,
        case=case,
        bundle=planning_admission_bundle,
        receipt=planning_receipt,
        expectation=planning_expectation,
        query_plan=query_plan,
        require_production=require_production_receipt,
    )
    production_completed_roots: tuple[tuple[str, str], ...] = ()
    production_structural_rejections: dict[str, tuple[str, ...]] = {}
    production_binding_replayed = False
    if require_production_receipt:
        if planning_expectation is None:
            raise PostgresError("E10 production record planning expectation is missing")
        _validate_e10_record_planning_sources(
            root=root,
            case=case,
            expectation=planning_expectation,
            context_id=context_id,
            context_hash=ctx_hash,
        )
        if mode == ADMISSION_FIRST_MODE and (plan_result is None or query_plan is None):
            raise PostgresError(
                "E10 production contract record lacks its planner output"
            )
        requires_root_binding = mode == ADMISSION_FIRST_MODE or run_kind in {
            "template_candidate",
            "template_oracle_summary",
        }
        if requires_root_binding and query_plan is None:
            raise PostgresError(
                "E10 production record lacks its completed-root eligibility"
            )
        if requires_root_binding:
            if plan_result is None:
                raise PostgresError(
                    "E10 production record lacks exact plan-result lineage"
                )
            assert query_plan is not None
            production_completed_roots = _require_e10_production_root_execution_binding(
                query_plan
            )
            _require_e10_production_plan_lineage(plan_result, query_plan)
            eligibility = query_plan["production_completed_root_eligibility"]
            production_structural_rejections = {
                str(item["template_id"]): tuple(
                    str(reason) for reason in item["reasons"]
                )
                for item in eligibility["structural_rejections"]
            }
            production_binding_replayed = True
    if production_binding_replayed and measurement is not None:
        raise PostgresError(
            "E10 production F2 rejects legacy or unbound runtime measurements"
        )
    is_unsafe_pushdown_control = mode == DIAGNOSTIC_UNSAFE_PUSHDOWN_MODE
    if is_unsafe_pushdown_control and case.query_id != E10_BARRIER_QUERY_ID:
        raise ValueError(
            f"{DIAGNOSTIC_UNSAFE_PUSHDOWN_MODE} is only defined for {E10_BARRIER_QUERY_ID}"
        )
    if mode == ADMISSION_FIRST_MODE and plan_result is None:
        invocation = _default_planner_invocation_for_case(
            case, mode, context_id=context_id
        )
        if invocation is not None:
            plan_result = invocation.occurrence_result
            query_plan = invocation.query_plan
    elif mode == ADMISSION_FIRST_MODE and query_plan is None:
        invocation = _default_planner_invocation_for_case(
            case, mode, context_id=context_id
        )
        if invocation is not None:
            query_plan = invocation.query_plan
    template_choice = _plan_choice(plan_result) if mode == ADMISSION_FIRST_MODE else None
    if candidate is not None:
        template_id, alternative = candidate.template_id, candidate.alternative
    else:
        template_id, alternative = (
            template_choice if template_choice else _mode_template(case, mode)
        )
    completed_template_ids = {
        completed_template
        for completed_template, _plan_id in production_completed_roots
    }
    if production_binding_replayed and run_kind in {
        "template_candidate",
        "template_oracle_summary",
    }:
        if (
            candidate is None
            or plan_result is None
            or sum(item is candidate for item in plan_result.candidates) != 1
            or candidate.template_id != template_id
        ):
            raise PostgresError(
                "E10 production candidate lacks exact plan-result lineage"
            )
    sealed_structural_reasons: tuple[str, ...] = ()
    if production_binding_replayed and mode == ADMISSION_FIRST_MODE:
        if template_id not in completed_template_ids:
            raise PostgresError(
                "E10 production record template is outside the completed frontier"
            )
    if (
        production_binding_replayed
        and run_kind == "template_candidate"
        and candidate is not None
        and candidate.accepted
        and template_id not in completed_template_ids
    ):
        sealed_structural_reasons = production_structural_rejections.get(
            template_id,
            (),
        )
        if not sealed_structural_reasons:
            raise PostgresError(
                "E10 admitted production candidate lacks a sealed frontier outcome"
            )
        if measurement is not None:
            raise PostgresError(
                "E10 structurally rejected root entered the measurement pool"
            )
    production_root_evidence = None
    if production_binding_replayed and template_id in completed_template_ids:
        assert query_plan is not None
        production_root_evidence = _e10_registered_completed_root_for_template(
            query_plan,
            template_id,
        )
    planning_ms = 0.0
    execution_ms = 0.0
    total_ms = planning_ms + execution_ms
    uses_artifact = template_id in {
        "auth_index_enum_v1",
        "strong_auth_index_keyed_v1",
        "mav_scan_v1",
        "hybrid_intersect_v1",
    }
    artifact_status = "pass" if uses_artifact else "not_applicable"
    template_applicability = "applicable"
    template_applicability_reason: Optional[str] = None
    status = "pass"
    failure: Optional[dict[str, Any]] = None
    oracle_status = "match"
    known_invalid_accepted = False
    artifact_action = "execute"
    expected_artifact_action = "execute"
    artifact_failure_symbol: Optional[str] = None
    runtime_audit_status = "pass"
    udf_calls = (
        8
        if case.query_id == E10_BARRIER_QUERY_ID and not is_unsafe_pushdown_control
        else 0
    )
    unauthorized_observations = 0
    unavailable_reason = _template_unavailable_reason(case, template_id)
    if unavailable_reason is not None:
        artifact_status = "not_applicable"
        template_applicability = (
            "contract_reject"
            if unavailable_reason.startswith("contract_reject:")
            else "artifact_unavailable"
        )
        template_applicability_reason = unavailable_reason
        status = "expected_reject"
        oracle_status = "not_applicable"
        artifact_action = "reject"
        expected_artifact_action = "reject"
        failure = {"reason": unavailable_reason}
    if candidate is not None and not candidate.accepted:
        artifact_status = "not_applicable"
        template_applicability = candidate.template_applicability
        template_applicability_reason = ";".join(candidate.rejection_reasons) or None
        status = "expected_reject"
        oracle_status = "not_applicable"
        artifact_action = "reject"
        expected_artifact_action = "reject"
        failure = {"reason": template_applicability_reason}
    if sealed_structural_reasons:
        artifact_status = "not_applicable"
        template_applicability = "contract_reject"
        template_applicability_reason = ";".join(sealed_structural_reasons)
        status = "expected_reject"
        oracle_status = "not_applicable"
        artifact_action = "reject"
        expected_artifact_action = "reject"
        failure = {"reason": template_applicability_reason}
    required_receipt_artifact = _required_artifact_for_template(template_id)
    if planning_receipt is not None and required_receipt_artifact is not None:
        receipt_assessment = next(
            (
                item
                for item in planning_receipt.artifact_assessments
                if item.kind == required_receipt_artifact
            ),
            None,
        )
        if receipt_assessment is None or (
            receipt_assessment.declared and not receipt_assessment.usable
        ):
            reasons = (
                ("receipt_artifact_assessment_missing",)
                if receipt_assessment is None
                else receipt_assessment.reasons
            )
            if "wrong_context" in reasons:
                artifact_status = "wrong_context"
            elif "stale" in reasons:
                artifact_status = "stale"
            elif "rid_domain_mismatch" in reasons:
                artifact_status = "rid_mismatch"
            else:
                artifact_status = "not_applicable"
            template_applicability = "metadata_invalid"
            template_applicability_reason = ";".join(reasons)
            status = "expected_reject"
            oracle_status = "not_applicable"
            artifact_action = "reject"
            expected_artifact_action = "reject"
            failure = {"reason": template_applicability_reason}
    elif mode == "mav-only" and case.mav_validity != "fresh":
        artifact_status, artifact_failure_symbol = _mav_failure_symbol(case)
        template_applicability = "metadata_invalid"
        template_applicability_reason = f"mav metadata is {case.mav_validity}"
        status = "wrong_result"
        oracle_status = "mismatch"
        known_invalid_accepted = True
        expected_artifact_action = "reject"
        failure = {
            "symbol": artifact_failure_symbol,
            "message": f"mav-only accepted a {case.mav_validity} MAV without contract validation",
        }
    if is_unsafe_pushdown_control:
        status = "unsafe_observation"
        runtime_audit_status = "fail"
        udf_calls = max(case.policy_evals, case.row_count)
        unauthorized_observations = max(1, case.policy_evals - case.row_count)
        failure = {
            "reason": "E10-BARRIER diagnostic raw pushdown observed protected tuples before exact authorization"
        }
    if (
        mode == ADMISSION_FIRST_MODE
        and plan_result is not None
        and plan_result.chosen_template is None
    ):
        status = "expected_reject"
        template_applicability = "contract_reject"
        template_applicability_reason = "no admissible template after contract checking"
        failure = {
            "symbol": "E10_NO_ADMISSIBLE_TEMPLATE",
            "message": "AdmissionFirst planner found no admissible template",
        }
    if production_binding_replayed and status == "pass":
        status = "not_executed"
        oracle_status = "not_applicable"
        udf_calls = 0
        unauthorized_observations = 0
        failure = {
            "reason": E10_PRODUCTION_ROOT_EXECUTION_BLOCK_REASON,
        }
    if production_binding_replayed:
        runtime_audit_status = "not_executed"
    artifact_lookups: Optional[int] = None
    row_count = 0
    policy_evals: Optional[int] = None
    residual_checks: Optional[int] = None
    candidate_rows: Optional[int] = None
    authorized_rows: Optional[int] = None
    base_fetches: Optional[int] = None
    build_ms = 0.0
    storage_bytes = 0
    artifact_versions: dict[str, int] = {}
    validation_ms = 0.0
    same_snapshot = False
    validation_isolation_level: Optional[str] = None
    static_verifier_status = "pass"
    static_verifier_plan_hash: Optional[str] = None
    static_verifier_reasons: list[str] = []
    static_verification_evidence_digest: Optional[str] = None
    complete_root_plan_digest: Optional[str] = None
    if is_unsafe_pushdown_control:
        row_count = case.row_count
        policy_evals = case.policy_evals
        candidate_rows = udf_calls
        authorized_rows = case.row_count
        base_fetches = case.policy_evals
    context_hash = ctx_hash or _digest(
        {"query": case.query_id, "context_id": context_id}
    )
    trusted_state = {"case_study_model": 1}
    membership_version = 0
    context_version = 0
    base_version = 0
    if planning_replay is not None:
        trusted_state["planning_receipt_replayed"] = 1
        if planning_receipt is None:
            raise PostgresError("E10 replayed record lost its planning receipt")
        if (
            planning_receipt.observation.current_membership_version is None
            or planning_receipt.observation.context_version is None
            or planning_receipt.observation.current_base_version is None
        ):
            raise PostgresError("E10 replayed record has incomplete version evidence")
        membership_version = int(
            planning_receipt.observation.current_membership_version
        )
        context_version = int(planning_receipt.observation.context_version)
        base_version = int(planning_receipt.observation.current_base_version)
    if admission_replay is not None:
        trusted_state["typed_admission_bundle_replayed"] = 1
    amortization_model = "not_executed_no_postgres_measurement"
    if measurement is not None:
        planning_ms = measurement.timing.planning_ms
        execution_ms = measurement.timing.execution_ms
        validation_ms = measurement.validation_ms
        total_ms = measurement.timing.total_ms + validation_ms
        row_count = measurement.row_count
        policy_evals = measurement.policy_evals
        residual_checks = measurement.residual_checks
        candidate_rows = measurement.candidate_rows
        authorized_rows = measurement.authorized_rows
        artifact_lookups = measurement.artifact_lookups
        base_fetches = measurement.base_fetches
        build_ms = measurement.build_ms
        storage_bytes = measurement.storage_bytes
        artifact_versions = dict(measurement.artifact_versions)
        same_snapshot = measurement.same_snapshot
        validation_isolation_level = measurement.validation_isolation_level
        static_verifier_status = measurement.static_verifier_status
        static_verifier_plan_hash = measurement.static_verifier_plan_hash
        static_verifier_reasons = list(measurement.static_verifier_reasons)
        if static_verifier_status != "pass":
            status = "static_verifier_fail"
            oracle_status = "not_applicable"
            failure = {
                "reason": ";".join(static_verifier_reasons)
                or f"static verifier failed for {template_id}"
            }
        if measurement.udf_calls:
            udf_calls = measurement.udf_calls
        if measurement.unauthorized_observations:
            unauthorized_observations = measurement.unauthorized_observations
        trusted_state["postgres_case_probe"] = 1
        if same_snapshot:
            trusted_state["artifact_validation_same_snapshot"] = 1
        amortization_model = "postgres_measurement"
    elif status in {"expected_reject", "not_executed"}:
        planning_ms = 0.0
        execution_ms = 0.0
        total_ms = 0.0
        row_count = 0
        policy_evals = 0
        residual_checks = 0
        candidate_rows = 0
        authorized_rows = 0
        artifact_lookups = 0
        base_fetches = 0
        build_ms = 0.0
        storage_bytes = 0
        artifact_versions = {}
        validation_ms = 0.0
        same_snapshot = False
        validation_isolation_level = None
        amortization_model = (
            "rejected_not_executed"
            if status == "expected_reject"
            else "not_executed_no_postgres_measurement"
        )
    if production_binding_replayed:
        if production_root_evidence is None:
            static_verifier_status = "fail"
            static_verifier_reasons = ["template_has_no_completed_root_static_evidence"]
        else:
            static_verifier_status = "pass"
            static_verifier_plan_hash = production_root_evidence.explain_plan_digest
            static_verification_evidence_digest = (
                production_root_evidence.static_verification_digest
            )
            complete_root_plan_digest = (
                production_root_evidence.complete_root_plan_digest
            )
            static_verifier_reasons = []
    chosen_rank = _chosen_rank(
        plan_result,
        completed_template_ids if production_binding_replayed else None,
    )
    planner_payload = {
        "level": "B",
        "planning_time_ms": planning_ms,
        "generated_templates": plan_result.generated_templates
        if plan_result is not None
        else 1,
        "rejected_templates": plan_result.rejected_templates
        if plan_result is not None
        else 0,
        "costed_templates": plan_result.costed_templates
        if plan_result is not None
        else 1,
        "dominance_checks": plan_result.dominance_checks
        if plan_result is not None
        else 0,
        "dominance_pruned": plan_result.dominance_pruned
        if plan_result is not None
        else 0,
        "disabled_components": list(plan_result.disabled_components)
        if plan_result is not None
        else [],
        "rejection_reasons": dict(plan_result.rejection_reasons)
        if plan_result is not None
        else {},
        "chosen_estimated_cost": plan_result.estimated_cost
        if plan_result is not None
        else None,
        "chosen_rank_vs_template_oracle": chosen_rank,
        "local_feature_vector": None
        if mode != "local-greedy"
        else {"query_shape": case.query_shape},
        "parent_requirement_vector": (
            dict(plan_result.parent_requirement_vector)
            if plan_result is not None
            else {
                "policy_mix": case.policy_mix,
                "case_label": case.label,
            }
        ),
        "candidates": [
            _candidate_payload_for_v2(candidate) for candidate in plan_result.candidates
        ]
        if plan_result is not None
        else [],
        "delivered_sigma": dict(plan_result.delivered_sigma)
        if plan_result is not None
        else {},
    }
    if query_plan is not None:
        planner_payload["query_plan"] = dict(query_plan)
    if planning_receipt is not None and planning_replay is not None:
        planner_payload["planning_receipt"] = planning_receipt.to_dict()
        planner_payload["planning_receipt_digest"] = planning_receipt.receipt_digest
        planner_payload["planning_receipt_replay"] = planning_replay.to_dict()
        if planning_expectation is None:
            raise PostgresError("E10 replayed record lost its planning expectation")
        planner_payload["planning_expectation"] = planning_expectation.to_dict()
        planner_payload["planning_expectation_digest"] = planning_expectation.digest
    if planning_admission_bundle is not None and admission_replay is not None:
        planner_payload[
            "planning_admission_bundle"
        ] = planning_admission_bundle.to_dict()
        planner_payload[
            "planning_admission_bundle_digest"
        ] = planning_admission_bundle.bundle_digest
        planner_payload["planning_admission_bundle_replay"] = admission_replay.to_dict()
    best_candidate = None
    if plan_result is not None:
        accepted_candidates = sorted(
            (
                candidate
                for candidate in plan_result.candidates
                if candidate.accepted
                and (
                    not production_binding_replayed
                    or candidate.template_id in completed_template_ids
                )
            ),
            key=lambda item: (float(item.estimated_cost or 0.0), item.template_id),
        )
        best_candidate = accepted_candidates[0] if accepted_candidates else None
    base_template_oracle_eligibility = (
        run_kind == "template_candidate"
        and status == "pass"
        and template_applicability == "applicable"
    ) or mode == ADMISSION_FIRST_MODE
    template_oracle_eligible = bool(
        base_template_oracle_eligibility and not production_binding_replayed
    )
    template_oracle_exclusion_reason = (
        E10_PRODUCTION_ROOT_EXECUTION_STATUS
        if production_binding_replayed
        else (None if base_template_oracle_eligibility else template_applicability)
    )
    payload = {
        "query_id": case.query_id,
        "context_id": context_id,
        "mode": scientific_mode_key(mode),
        "template_id": template_id,
        "total_ms": total_ms,
        "row_count": row_count,
    }
    result_hash = _digest(payload)
    sql_payload = {
        "emitted_sql_path": "workloads/e10/case_study.sql",
        "emitted_sql_hash": file_sha256(root / "workloads" / "e10" / "case_study.sql"),
        "normalized_sql_hash": scientific_manifest_hash(manifest_path),
        "execution_sql_source": (
            E10_PRODUCTION_ROOT_EXECUTION_STATUS
            if production_binding_replayed
            else measurement.execution_sql_source
            if measurement is not None
            else "not_executed"
        ),
    }
    if production_binding_replayed:
        assert query_plan is not None
        sql_payload["planning_root_scope"] = E10_PRODUCTION_ROOT_EXECUTION_SCOPE
        sql_payload["planning_root_sql_bound"] = True
        sql_payload["measurement_promotion"] = False
        sql_payload["execution_binding_status"] = E10_PRODUCTION_ROOT_EXECUTION_STATUS
        if production_root_evidence is not None:
            matching_runner = production_root_evidence.bound_runner
            sql_payload["runner_sql"] = matching_runner.runner_sql
            sql_payload["runner_sql_hash"] = matching_runner.runner_sql_digest
            sql_payload[
                "bound_runner_identity_digest"
            ] = matching_runner.identity_digest
            sql_payload[
                "complete_root_plan_digest"
            ] = production_root_evidence.complete_root_plan_digest
            sql_payload[
                "explain_plan_digest"
            ] = production_root_evidence.explain_plan_digest
            sql_payload[
                "static_verification_digest"
            ] = production_root_evidence.static_verification_digest
    if measurement is not None and measurement.runner_sql:
        sql_payload["runner_sql"] = measurement.runner_sql
        sql_payload["runner_sql_hash"] = _digest({"runner_sql": measurement.runner_sql})
    if query_plan is not None:
        ir_equivalence_sql = query_plan.get("emitted_sql")
        if isinstance(ir_equivalence_sql, str) and ir_equivalence_sql.strip():
            sql_payload["ir_equivalence_runner_sql"] = ir_equivalence_sql
            sql_payload["ir_equivalence_runner_sql_hash"] = _digest(
                {"ir_equivalence_runner_sql": ir_equivalence_sql}
            )
    context_prefix = _run_id_context_prefix(context_id)
    return {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": f"E10_{context_prefix}{case.query_id}_{mode}"
        if run_kind == "normal_mode"
        else f"E10_{context_prefix}{case.query_id}_{run_kind}_{template_id}",
        "manifest_id": manifest_id,
        "manifest_hash": file_sha256(manifest_path),
        "experiment": "E10",
        "stage": "case_study",
        "run_kind": run_kind,
        "dataset": dataset_payload,
        "query": {
            "query_id": case.query_id,
            "path": "workloads/e10/case_study.sql",
            "params": {
                "label": case.label,
                "policy_mix": case.policy_mix,
                "query_shape": case.query_shape,
            },
        },
        "policy": {
            "policy_id": case.policy_mix,
            "policy_version": 0,
            "policy_sql_manifest_hash": file_sha256(
                root / "manifests" / "policies" / "synthetic_saas_policies.yaml"
            ),
        },
        "context": {"context_id": context_id, "ctx_hash": context_hash},
        "mode": mode,
        "template": {"template_id": template_id, "alternative": alternative},
        "template_applicability": {
            "status": template_applicability,
            "reason": template_applicability_reason,
        },
        "template_oracle": {
            "eligible_for_template_oracle": template_oracle_eligible,
            "template_oracle_exclusion_reason": (template_oracle_exclusion_reason),
            "oracle_kind": "BestEnumeratedAdmissible",
            "best_template_id": None
            if best_candidate is None
            else best_candidate.template_id,
            "best_estimated_cost": None
            if best_candidate is None
            else best_candidate.estimated_cost,
            "chosen_rank": chosen_rank,
        },
        "evaluation_role": (
            FINITE_TEMPLATE_UPPER_BOUND_ROLE
            if run_kind in {"template_candidate", "template_oracle_summary"}
            else load_mode_registry(root)[normalize_mode_id(mode)].evaluation_role
        ),
        "pg": {
            "version": pg_version,
            "gucs": {"jit": "off", "max_parallel_workers_per_gather": "0"},
        },
        "versions": {
            "policy": {case.policy_mix: 0},
            "membership": {"group_membership": membership_version},
            "context": {context_id: context_version},
            "trusted_state": trusted_state,
            "base": {"synthetic_saas": base_version},
            "artifacts": artifact_versions,
        },
        "planner": planner_payload,
        "static_verifier": {
            "status": static_verifier_status,
            "plan_hash": (
                static_verifier_plan_hash
                if production_root_evidence is not None
                else None
                if production_binding_replayed
                else static_verifier_plan_hash or result_hash
            ),
            "explain_path": None,
            "reasons": static_verifier_reasons,
            "evidence_digest": static_verification_evidence_digest,
            "complete_root_plan_digest": complete_root_plan_digest,
        },
        "artifact_validation": {
            "status": artifact_status,
            "action": artifact_action,
            "expected_action": expected_artifact_action,
            "failure_sqlstate": None,
            "failure_symbol": artifact_failure_symbol,
            "same_snapshot": same_snapshot,
            "isolation_level": validation_isolation_level,
        },
        "runtime_audit": {
            "status": runtime_audit_status,
            "audit_path": None,
            "udf_calls": udf_calls,
            "unauthorized_observations": unauthorized_observations,
            "client_errors": 0,
            "client_notices": 0,
        },
        "sql": sql_payload,
        "oracle_check": {
            "status": oracle_status,
            "oracle_kind": "bounded_saas_case_study",
            "set_diff_left": 0,
            "set_diff_right": 0,
            "known_invalid_accepted": known_invalid_accepted,
            "known_valid_rejected": False,
        },
        "timing_ms": {
            "planning": planning_ms,
            "execution": execution_ms,
            "verification": validation_ms,
            "total": total_ms,
        },
        "result": {
            "row_count": row_count,
            "result_hash": result_hash,
        },
        "pg_metrics": {
            "shared_read_blocks": 0,
            "shared_hit_blocks": 0,
            "temp_read_blocks": 0,
            "temp_written_blocks": 0,
        },
        "counts": {
            "policy_evals": policy_evals,
            "residual_checks": residual_checks,
            "candidate_rows": candidate_rows,
            "authorized_rows": authorized_rows,
            "artifact_lookups": artifact_lookups,
            "base_fetches": base_fetches,
        },
        "artifact_cost": {
            "query_only_ms": max(0.0, total_ms - validation_ms),
            "build_ms": build_ms,
            "refresh_ms": 0.0,
            "storage_bytes": storage_bytes,
            "validation_ms": validation_ms,
            "indexes_built": [template_id] if artifact_status == "pass" else [],
            "artifact_key_encoding_version": "artifact_key_encoding_v1",
            "amortization_model": amortization_model,
        },
        "implementation": {
            "git_commit": _git_commit(root),
            "docker_image_digest": "not_containerized",
            "python_version": platform.python_version(),
            "planner_language": "python",
        },
        "e10_case_study": {
            "query_label": case.label,
            "policy_mix": case.policy_mix,
            "selected_reason": case.contract_reason
            if mode == ADMISSION_FIRST_MODE
            else None,
            "admission_first_choice": alternative if mode == ADMISSION_FIRST_MODE else None,
            "mode_choice": alternative,
            "postgres_case_probe": measurement is not None,
            "mav_validity": case.mav_validity,
            "diagnostic_positive_control": is_unsafe_pushdown_control,
        },
        "status": status,
        "failure": failure,
    }


def _write_record(record: Mapping[str, Any], output_dir: Path) -> Path:
    issues = validate_raw_run_record(record)
    if issues:
        rendered = ", ".join(f"{issue.path}: {issue.message}" for issue in issues)
        raise ValueError(f"E10 raw record failed schema validation: {rendered}")
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_mode = str(record["mode"]).replace("-", "_")
    path = output_dir / f"{record['run_id'].replace('-', '_')}_{safe_mode}.json"
    with path.open("w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path


def run_e10_guard_unsafe_static_witness(
    root: Path,
    manifest_path: Path,
    output_dir: Path,
    pg_env: PostgresEnv,
    *,
    context_id: str = "ctx_000001",
    prepare_dataset: bool = True,
) -> E10StaticWitnessResult:
    manifest = _load_manifest(manifest_path)
    if prepare_dataset:
        dataset = manifest.get("dataset") or {}
        generate_synthetic_saas(
            root,
            pg_env,
            scale=str(dataset.get("scale", "1e5")),
            seed=int(dataset.get("seed", 52)),
            verify=True,
            output_dir=None,
        )

    case = _guard_unsafe_static_witness_case(root)
    relname, rid_col, policy_id, alias = _target_for_case(case)
    context = _load_context(context_id, pg_env)
    ctx_hash = str(
        run_psql_command(
            f"SELECT ctx_hash FROM public.synthetic_context WHERE context_id = {_quote(context_id)};",
            pg_env,
        )
    )
    policy = _load_policy(root, policy_id)
    exact = _render_policy_predicate(
        str(policy["exact_sql_template"]),
        alias=alias,
        rid_col=rid_col,
        context=context,
        relname=relname,
    )
    complete_guard = _complete_guard_predicate(case, alias, rid_col, context, relname)
    sql = _guard_unsafe_static_witness_query(
        case,
        relname,
        rid_col,
        alias,
        complete_guard,
        exact,
    )
    base_rows = _run_count(f"SELECT count(*) FROM public.{relname};", pg_env)
    filtered_rows = _run_count(
        f"SELECT count(*) FROM public.{relname} {alias} WHERE {_base_filter(case, alias, rid_col)};",
        pg_env,
    )
    invocation = _planner_invocation_for_case(
        case,
        E10_GUARD_UNSAFE_STATIC_WITNESS_MODE,
        relname=relname,
        rid_col=rid_col,
        policy_id=policy_id,
        artifacts={},
        base_rows=base_rows,
        filtered_rows=filtered_rows,
        alias=alias,
        exact_predicate=exact,
        complete_guard_predicate=complete_guard,
        query_predicate=_base_filter(case, alias, rid_col),
    )
    plan_result = invocation.occurrence_result
    if plan_result.chosen_template is None:
        raise PostgresError(
            "E10 guard+unsafe static witness planner produced no guard candidate"
        )

    (
        timing,
        row_count,
        static_verification,
        udf_calls,
        unauthorized,
    ) = _measure_guard_unsafe_static_witness_query(
        sql,
        relname=relname,
        rid_col=rid_col,
        exact_predicate=exact,
        pg_env=pg_env,
    )
    guard_candidate_rows = _run_count(
        _guard_candidate_count_query(case, relname, alias, complete_guard),
        pg_env,
    )
    explain_policy_evals = _policy_eval_rows_from_explain(
        _measurement_explain_json(timing),
        template_id="guard_candidate_plus_residual_v1",
        relname=relname,
        exact_predicate=exact,
    )
    measurement = _measured_mode_record(
        template_id="guard_candidate_plus_residual_v1",
        timing=timing,
        row_count=row_count,
        filtered_rows=filtered_rows,
        guard_candidate_rows=guard_candidate_rows,
        explain_policy_evals=explain_policy_evals,
        artifact_ids={},
        build_ms={},
        storage_bytes={},
        static_verification=static_verification,
    )
    measurement = replace(
        measurement,
        udf_calls=udf_calls,
        unauthorized_observations=unauthorized,
    )
    pg_version = run_psql_command("SHOW server_version;", pg_env)
    record = _record(
        root,
        manifest_path,
        case,
        E10_GUARD_UNSAFE_STATIC_WITNESS_MODE,
        measurement=measurement,
        plan_result=plan_result,
        query_plan=invocation.query_plan,
        pg_version=pg_version,
        context_id=context_id,
        ctx_hash=ctx_hash,
        manifest=manifest,
    )
    sql_digest = _digest({"sql": re.sub(r"\s+", " ", sql.strip())})
    record["run_id"] = f"E10_{case.query_id}_{E10_GUARD_UNSAFE_STATIC_WITNESS_MODE}"
    record["sql"]["emitted_sql_path"] = "generated:e10_guard_unsafe_static_witness.sql"
    record["sql"]["emitted_sql_hash"] = sql_digest
    record["sql"]["normalized_sql_hash"] = sql_digest
    attach_static_verifier_explain(
        record,
        output_dir,
        measurement.static_verifier_explain_json,
    )
    raw_path = _write_record(record, output_dir)
    return E10StaticWitnessResult(raw_result_paths=[raw_path], witness_records=1)


def _template_oracle_summary_record(
    *,
    root: Path,
    manifest_path: Path,
    manifest: Mapping[str, Any],
    case: E10Case,
    plan_result: PlanResult,
    candidate_measurements: Mapping[tuple[str, str], E10ModeMeasurement],
    pg_version: str,
    context_id: str,
    ctx_hash: str,
    planning_receipt: Optional[E10PlanningReceipt],
    planning_expectation: Optional[E10PlanningExpectation],
    planning_admission_bundle: Optional[E10AdmissionBundle],
    query_plan: Mapping[str, Any],
) -> Dict[str, Any]:
    if planning_expectation is None or planning_expectation.scope != "production":
        eligible: list[tuple[CandidatePlan, E10ModeMeasurement]] = []
        excluded: dict[str, int] = {}
        for candidate in plan_result.candidates:
            measurement = candidate_measurements.get(
                (case.query_id, candidate.template_id)
            )
            if candidate.accepted and measurement is not None:
                eligible.append((candidate, measurement))
            else:
                reason = (
                    "not_measured"
                    if candidate.accepted
                    else candidate.template_applicability
                )
                excluded[reason] = excluded.get(reason, 0) + 1
        if not eligible:
            raise PostgresError(
                f"E10 {case.query_id} has no measured admissible candidate"
            )
        best, best_measurement = min(
            eligible,
            key=lambda item: (
                item[1].timing.execution_ms,
                item[0].template_id,
            ),
        )
        chosen = plan_result.chosen_template
        chosen_measurement = (
            None
            if chosen is None
            else candidate_measurements.get(
                (case.query_id, chosen.template_id)
            )
        )
        chosen_execution_ms = (
            None
            if chosen_measurement is None
            else chosen_measurement.timing.execution_ms
        )
        gap = (
            None
            if chosen_execution_ms is None
            or best_measurement.timing.execution_ms <= 0
            else chosen_execution_ms / best_measurement.timing.execution_ms
        )
        record = _record(
            root=root,
            manifest_path=manifest_path,
            case=case,
            mode="template-oracle",
            run_kind="template_oracle_summary",
            candidate=best,
            measurement=best_measurement,
            plan_result=plan_result,
            query_plan=query_plan,
            pg_version=pg_version,
            context_id=context_id,
            ctx_hash=ctx_hash,
            manifest=manifest,
            planning_receipt=planning_receipt,
            planning_expectation=planning_expectation,
            planning_admission_bundle=planning_admission_bundle,
            require_production_receipt=False,
        )
        summary_payload = {
            "run_kind": "template_oracle_summary",
            "query_id": case.query_id,
            "context_id": context_id,
            "mode_under_test": ADMISSION_FIRST_MODE,
            "ranking_metric": "execution_time_ms",
            "eligible_templates": len(eligible),
            "excluded_templates": dict(sorted(excluded.items())),
            "best_template_id": best.template_id,
            "best_execution_ms": best_measurement.timing.execution_ms,
            "chosen_template_id": None if chosen is None else chosen.template_id,
            "chosen_execution_ms": chosen_execution_ms,
            "gap": gap,
            "estimated_rank": _chosen_rank(plan_result),
        }
        scientific_summary_payload = {
            **summary_payload,
            "mode_under_test": scientific_mode_key(ADMISSION_FIRST_MODE),
        }
        digest = _digest(scientific_summary_payload)
        record["run_id"] = (
            f"E10_{_run_id_context_prefix(context_id)}"
            f"{case.query_id}_template_oracle_summary"
        )
        record["template_oracle_summary"] = summary_payload
        record["template_oracle"]["best_template_id"] = best.template_id
        record["template_oracle"]["best_estimated_cost"] = best.estimated_cost
        record["result"]["result_hash"] = digest
        record["sql"]["normalized_sql_hash"] = digest
        record["static_verifier"]["plan_hash"] = digest
        return record

    completed_roots = _require_e10_production_root_execution_binding(query_plan)
    completed_template_ids = {template_id for template_id, _plan_id in completed_roots}
    unexpected_measurements = tuple(
        key for key in candidate_measurements if key[0] == case.query_id
    )
    if unexpected_measurements:
        raise PostgresError(
            "E10 production template oracle rejects legacy F2 measurements"
        )
    excluded: dict[str, int] = {}
    for candidate in plan_result.candidates:
        if candidate.accepted and candidate.template_id in completed_template_ids:
            reason = E10_PRODUCTION_ROOT_EXECUTION_STATUS
            excluded[reason] = excluded.get(reason, 0) + 1
        else:
            reason = (
                "strict_structural_rejection"
                if candidate.accepted
                else candidate.template_applicability
            )
            excluded[reason] = excluded.get(reason, 0) + 1
    chosen = plan_result.chosen_template
    if chosen is None or chosen.template_id not in completed_template_ids:
        raise PostgresError(
            "E10 template-oracle diagnostic escaped the completed frontier"
        )
    record = _record(
        root=root,
        manifest_path=manifest_path,
        case=case,
        mode="template-oracle",
        run_kind="template_oracle_summary",
        candidate=chosen,
        measurement=None,
        plan_result=plan_result,
        query_plan=query_plan,
        pg_version=pg_version,
        context_id=context_id,
        ctx_hash=ctx_hash,
        manifest=manifest,
        planning_receipt=planning_receipt,
        planning_expectation=planning_expectation,
        planning_admission_bundle=planning_admission_bundle,
        require_production_receipt=True,
    )
    summary_payload = {
        "run_kind": "template_oracle_summary",
        "query_id": case.query_id,
        "context_id": context_id,
        "mode_under_test": ADMISSION_FIRST_MODE,
        "ranking_metric": "not_executed",
        "eligible_templates": 0,
        "excluded_templates": dict(sorted(excluded.items())),
        "best_template_id": None,
        "best_execution_ms": None,
        "diagnostic_completed_templates": 0,
        "diagnostic_best_template_id": None,
        "diagnostic_best_execution_ms": None,
        "chosen_template_id": chosen.template_id,
        "chosen_execution_ms": None,
        "gap": None,
        "diagnostic_gap": None,
        "estimated_rank": _chosen_rank(plan_result, completed_template_ids),
        "promotion_status": E10_PRODUCTION_ROOT_EXECUTION_STATUS,
    }
    scientific_summary_payload = {
        **summary_payload,
        "mode_under_test": scientific_mode_key(ADMISSION_FIRST_MODE),
    }
    digest = _digest(scientific_summary_payload)
    record[
        "run_id"
    ] = f"E10_{_run_id_context_prefix(context_id)}{case.query_id}_template_oracle_summary"
    record["template_oracle_summary"] = summary_payload
    record["template_oracle"]["eligible_for_template_oracle"] = False
    record["template_oracle"][
        "template_oracle_exclusion_reason"
    ] = E10_PRODUCTION_ROOT_EXECUTION_STATUS
    record["template_oracle"]["best_template_id"] = None
    record["template_oracle"]["best_estimated_cost"] = None
    record["result"]["result_hash"] = digest
    record["sql"]["normalized_sql_hash"] = digest
    return record


def run_e10_case_study(
    root: Path,
    manifest_path: Path,
    output_dir: Path,
    pg_env: Optional[PostgresEnv] = None,
) -> E10StudyResult:
    manifest = _load_manifest(manifest_path)
    _validate_manifest(manifest_path, manifest)
    raw_paths: list[Path] = []
    correctness_paths: list[Path] = []
    dataset_prepared = False
    repetitions = protocol_from_manifest(manifest)
    chosen_alternatives = set()
    contract_records = 0
    normal_records = 0
    diagnostic_records = 0
    candidate_records = 0
    summary_records = 0
    context_ids = _context_ids_from_manifest(manifest)
    for repetition in iter_repetitions(repetitions):
        measurements_by_context: dict[str, E10PostgresMeasurements] = {}
        if pg_env is not None:
            for context_id in context_ids:
                prepare_dataset = not dataset_prepared
                measurements_by_context[context_id] = _prepare_postgres_measurements(
                    root,
                    manifest,
                    pg_env,
                    context_id=context_id,
                    prepare_dataset=prepare_dataset,
                )
                if prepare_dataset:
                    dataset_prepared = True
        for context_id in context_ids:
            measurements = measurements_by_context.get(context_id)
            base_context_kwargs: dict[str, Any] = {"context_id": context_id}
            if measurements is not None:
                base_context_kwargs.update(
                    {
                        "pg_version": measurements.pg_version,
                        "ctx_hash": measurements.ctx_hash,
                    }
                )
            for case in CASES:
                planning_receipt = (
                    None
                    if measurements is None
                    else measurements.planning_receipts.get(case.query_id)
                )
                planning_expectation = (
                    None
                    if measurements is None
                    else measurements.planning_expectations.get(case.query_id)
                )
                planning_admission_bundle = (
                    None
                    if measurements is None
                    else measurements.planning_admission_bundles.get(case.query_id)
                )
                for mode in sorted(REQUIRED_MODES, key=mode_execution_order_key):
                    kwargs = dict(base_context_kwargs)
                    measurement = None
                    if measurements is not None:
                        measurement = measurements.measurements.get(
                            (case.query_id, mode)
                        )
                        kwargs.update(
                            {
                                "measurement": measurement,
                                "plan_result": measurements.plan_results.get(
                                    (case.query_id, mode)
                                ),
                                "query_plan": measurements.query_plans.get(
                                    (case.query_id, mode)
                                ),
                                "planning_receipt": planning_receipt,
                                "planning_expectation": planning_expectation,
                                "planning_admission_bundle": planning_admission_bundle,
                                "require_production_receipt": False,
                            }
                        )
                    record = _record(
                        root, manifest_path, case, mode, manifest=manifest, **kwargs
                    )
                    attach_repetition(record, repetition)
                    attach_static_verifier_explain(
                        record,
                        output_dir,
                        None
                        if measurement is None
                        else measurement.static_verifier_explain_json,
                    )
                    raw_paths.append(_write_record(record, output_dir))
                    normal_records += 1
                    if mode == ADMISSION_FIRST_MODE:
                        chosen_alternatives.add(record["template"]["alternative"])
                        contract_records += 1
                if case.query_id == E10_BARRIER_QUERY_ID:
                    kwargs = dict(base_context_kwargs)
                    measurement = None
                    if measurements is not None:
                        measurement = measurements.diagnostic_measurements.get(
                            (case.query_id, DIAGNOSTIC_UNSAFE_PUSHDOWN_MODE)
                        )
                        kwargs["measurement"] = measurement
                    record = _record(
                        root,
                        manifest_path,
                        case,
                        DIAGNOSTIC_UNSAFE_PUSHDOWN_MODE,
                        manifest=manifest,
                        **kwargs,
                    )
                    attach_repetition(record, repetition)
                    attach_static_verifier_explain(
                        record,
                        output_dir,
                        None
                        if measurement is None
                        else measurement.static_verifier_explain_json,
                    )
                    raw_paths.append(_write_record(record, output_dir))
                    normal_records += 1
                    diagnostic_records += 1
                if measurements is not None:
                    plan_result = measurements.plan_results[
                        (case.query_id, ADMISSION_FIRST_MODE)
                    ]
                    for candidate in plan_result.candidates:
                        measurement = measurements.candidate_measurements.get(
                            (case.query_id, candidate.template_id)
                        )
                        record = _record(
                            root,
                            manifest_path,
                            case,
                            "template-oracle",
                            run_kind="template_candidate",
                            candidate=candidate,
                            measurement=measurement,
                            plan_result=plan_result,
                            query_plan=measurements.candidate_query_plans.get(
                                (case.query_id, candidate.template_id)
                            ),
                            pg_version=measurements.pg_version,
                            context_id=measurements.context_id,
                            ctx_hash=measurements.ctx_hash,
                            manifest=manifest,
                            planning_receipt=planning_receipt,
                            planning_expectation=planning_expectation,
                            planning_admission_bundle=planning_admission_bundle,
                            require_production_receipt=False,
                        )
                        attach_repetition(record, repetition)
                        attach_static_verifier_explain(
                            record,
                            output_dir,
                            None
                            if measurement is None
                            else measurement.static_verifier_explain_json,
                        )
                        raw_paths.append(_write_record(record, output_dir))
                        candidate_records += 1
                    summary = _template_oracle_summary_record(
                        root=root,
                        manifest_path=manifest_path,
                        manifest=manifest,
                        case=case,
                        plan_result=plan_result,
                        candidate_measurements=measurements.candidate_measurements,
                        pg_version=measurements.pg_version,
                        context_id=measurements.context_id,
                        ctx_hash=measurements.ctx_hash,
                        planning_receipt=planning_receipt,
                        planning_expectation=planning_expectation,
                        planning_admission_bundle=planning_admission_bundle,
                        query_plan=measurements.query_plans[
                            (case.query_id, ADMISSION_FIRST_MODE)
                        ],
                    )
                    attach_repetition(summary, repetition)
                    raw_paths.append(_write_record(summary, output_dir))
                    summary_records += 1
    return E10StudyResult(
        raw_result_paths=raw_paths,
        correctness_result_paths=correctness_paths,
        correctness_records=len(correctness_paths),
        normal_records=normal_records,
        diagnostic_records=diagnostic_records,
        candidate_records=candidate_records,
        summary_records=summary_records,
        query_count=len(CASES),
        contract_records=contract_records,
        chosen_alternatives=len(chosen_alternatives),
    )
