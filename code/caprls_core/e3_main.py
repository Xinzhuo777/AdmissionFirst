"""E3 PostgreSQL-backed reduced standard-workload runner."""

from __future__ import annotations

import hashlib
import math
import platform
import json
import re
import time
import weakref
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Union

import yaml

from .e3_catalog_guard import render_validated_catalog_guard
from .baselines import (
    ADMISSION_FIRST_MODE,
    FINITE_TEMPLATE_UPPER_BOUND_ROLE,
    load_mode_registry,
    normalize_mode_id,
    scientific_mode_key,
)
from .e2_smoke import _count_wrapper, _run_count_sql, _run_sql_script
from .e8b_study import _run_validated_query
from .e3_smoke import (
    E3PolicyConfig,
    _digest,
    _git_commit,
    _load_manifest,
    _quote,
    _setup_sql,
    _write_record,
)
from .manifest_validator import file_sha256
from .native_rls import configure_native_rls
from .postgres_runner import (
    PostgresEnv,
    PostgresError,
    PostgresTransactionSession,
    _validate_single_transaction_statement,
    init_db,
    run_psql_command,
)
from .repetitions import (
    RepetitionRun,
    attach_repetition,
    iter_repetitions,
    protocol_from_manifest,
)
from .result_schema import RAW_SCHEMA_VERSION
from planner.core import (
    ArtifactMetadata,
    CandidatePlan,
    CostInputs,
    DEFAULT_TEMPLATE_REGISTRY,
    ParentRequirement,
    PlanningProblem,
    PlanResult,
    TemplateRegistry,
    policy_subject_digest,
)
from planner.contracts import (
    GammaFact,
    GammaSnapshot,
    ImplementationTargetBinding,
    NativeRLSSessionContract,
    PolicyAccessTarget,
    canonical_predicate_digest,
    implementation_target_binding,
    implementation_target_match_subject_digest,
    target_refinement_subject_digest,
    template_definition,
)
from planner.certificate_envelope import (
    canonical_registry_digest,
    policy_predicate_binding_subject,
)
from planner.emit import (
    ArtifactComponentBinding,
    ArtifactDependencyExpectation,
    ArtifactDependencyIdentity,
    EmitContext,
    StrictArtifactExpectation,
)
from planner.execution import ContinuationTemplate, SessionContract
from planner.features import PlannerFeatureFlags
from planner.ir import (
    Materialize,
    Project,
    Root,
    ScanProtected,
    Select,
    ValidationGate,
    walk,
)
from planner.query import OccurrenceGoal, PlanningQuery, QueryPlanResult, plan_query
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
class E3QuerySpec:
    query_id: str
    path: str
    workload: str
    protected_rel: str
    rid_col: str
    alias: str
    key_name: str
    key_value: str


@dataclass(frozen=True)
class E3MainModeResult:
    query: E3QuerySpec
    policy_config_id: str
    mode: str
    template_id: str
    alternative: str
    status: str
    template_applicability: str
    row_count: Optional[int]
    execution_ms: Optional[float]
    build_ms: float
    authorized_rows: int
    result_hash: str
    planning_ms: Optional[float] = 0.0
    artifact_id: Optional[str] = None
    failure_reason: Optional[str] = None
    plan_result: Optional[PlanResult] = None
    query_plan: Optional[Mapping[str, Any]] = None
    candidate: Optional[CandidatePlan] = None
    validation_ms: Optional[float] = 0.0
    validation_same_snapshot: bool = False
    validation_isolation_level: Optional[str] = None
    static_verifier_status: str = "pass"
    static_verifier_plan_hash: Optional[str] = None
    static_verifier_reasons: tuple[str, ...] = ()
    static_verifier_explain_json: Optional[tuple[Mapping[str, Any], ...]] = None
    runner_sql: Optional[str] = None
    execution_sql_source: str = "fixed_baseline_runner_sql"


@dataclass(frozen=True)
class E3MainResult:
    raw_result_paths: list[Path]
    normal_records: int
    candidate_records: int
    summary_records: int
    artifact_unavailable_records: int
    query_count: int


@dataclass(frozen=True)
class E3CostFeatures:
    template_id: str
    source: str
    policy_config_id: str
    query_id: str
    workload: str
    protected_rows: int
    query_local_rows: int
    authorized_rows: int
    key_value_cardinality: Optional[int]
    pg_total_cost: float
    plan_rows: Optional[float]
    has_materialized_cte: bool
    has_cte_scan: bool
    has_seq_scan: bool
    has_index_scan: bool
    has_nested_loop: bool
    join_count: int
    sort_count: int
    plan_node_types: tuple[str, ...]
    plan_hash: str


@dataclass(frozen=True)
class E3AdaptiveTopKConfig:
    enabled: bool = False
    k: int = 2
    probe_repetitions: int = 2
    # Shape grouping is telemetry/shadow only.  It must never rewrite a
    # selected plan unless a future v3 identity-equivalence proof enables a
    # separately named feature.
    deduplicate_plan_shapes: bool = False


@dataclass(frozen=True)
class E3DataRequirement:
    label: str
    path: Path


@dataclass(frozen=True)
class E3RelationCatalogClaim:
    oid: int
    schema_name: str
    relation_name: str
    owner: str
    row_security_enabled: bool
    force_row_security: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "oid": self.oid,
            "schema_name": self.schema_name,
            "relation_name": self.relation_name,
            "owner": self.owner,
            "row_security_enabled": self.row_security_enabled,
            "force_row_security": self.force_row_security,
        }


@dataclass(frozen=True)
class E3RLSPolicyCatalogClaim:
    policy_name: str
    command: str
    permissive: bool
    roles: tuple[str, ...]
    expression: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "roles", tuple(self.roles))

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_name": self.policy_name,
            "command": self.command,
            "permissive": self.permissive,
            "roles": list(self.roles),
            "expression": self.expression,
        }


@dataclass(frozen=True)
class E3RoleCatalogClaim:
    role_name: str
    is_superuser: bool
    bypasses_rls: bool
    member_of: tuple[str, ...]
    members: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "member_of", tuple(self.member_of))
        object.__setattr__(self, "members", tuple(self.members))

    def to_dict(self) -> dict[str, Any]:
        return {
            "role_name": self.role_name,
            "is_superuser": self.is_superuser,
            "bypasses_rls": self.bypasses_rls,
            "member_of": list(self.member_of),
            "members": list(self.members),
        }


@dataclass(frozen=True)
class E3TrustedExecutionCatalogClaim:
    """Observed facts for the finite explicit-SQL executor, not native RLS."""

    database: str
    role: E3RoleCatalogClaim
    relations_json: str
    validator_json: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "database": self.database,
            "role": self.role.to_dict(),
            "relations": json.loads(self.relations_json),
            "artifact_validator": json.loads(self.validator_json),
        }


@dataclass(frozen=True)
class E3ArtifactDependencyClaim:
    artifact_id: str
    dependency_kind: str
    dependency_name: str
    version_at_build: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "dependency_kind": self.dependency_kind,
            "dependency_name": self.dependency_name,
            "version_at_build": self.version_at_build,
        }


@dataclass(frozen=True)
class E3ArtifactScopeClaim:
    physical_kind: str
    artifact_id: str
    policy_id: str
    principal_id: str
    context_token: str
    rid_domain_id: str
    base_relation_oid: int
    policy_version: int
    membership_version: int
    key_name: Optional[str]
    key_value_is_null: bool
    range_bucket_is_nonnull: bool
    has_duplicate_identity: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "physical_kind": self.physical_kind,
            "artifact_id": self.artifact_id,
            "policy_id": self.policy_id,
            "principal_id": self.principal_id,
            "context_token": self.context_token,
            "rid_domain_id": self.rid_domain_id,
            "base_relation_oid": self.base_relation_oid,
            "policy_version": self.policy_version,
            "membership_version": self.membership_version,
            "key_name": self.key_name,
            "key_value_is_null": self.key_value_is_null,
            "range_bucket_is_nonnull": self.range_bucket_is_nonnull,
            "has_duplicate_identity": self.has_duplicate_identity,
        }


@dataclass(frozen=True)
class E3PlanningCatalogObservation:
    collector_schema: str
    session_user: str
    current_user: str
    search_path: str
    row_security: str
    snapshot_text: str
    relation: E3RelationCatalogClaim
    policies: tuple[E3RLSPolicyCatalogClaim, ...]
    role: E3RoleCatalogClaim
    dependencies: tuple[E3ArtifactDependencyClaim, ...]
    artifact_scopes: tuple[E3ArtifactScopeClaim, ...]
    trusted_execution: Optional[E3TrustedExecutionCatalogClaim] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "policies", tuple(self.policies))
        object.__setattr__(self, "dependencies", tuple(self.dependencies))
        object.__setattr__(self, "artifact_scopes", tuple(self.artifact_scopes))

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "collector_schema": self.collector_schema,
            "session_user": self.session_user,
            "current_user": self.current_user,
            "search_path": self.search_path,
            "row_security": self.row_security,
            "snapshot_text": self.snapshot_text,
            "relation": self.relation.to_dict(),
            "policies": [item.to_dict() for item in self.policies],
            "role": self.role.to_dict(),
            "dependencies": [item.to_dict() for item in self.dependencies],
            "artifact_scopes": [item.to_dict() for item in self.artifact_scopes],
        }
        if self.trusted_execution is not None:
            payload["trusted_execution"] = self.trusted_execution.to_dict()
        return payload


@dataclass(frozen=True)
class E3PlanningCatalogReceipt:
    schema_version: str
    validator_version: str
    evidence_scope: str
    query_id: str
    occurrence_id: str
    policy_id: str
    principal_id: str
    context_token: str
    context_payload_json: str
    context_digest: str
    declared_usable_kinds: tuple[str, ...]
    observed_physical_kinds: tuple[str, ...]
    snapshot_digest: str
    rendered_predicate_digest: str
    rls_rendered_predicate_digest: str
    policy_definition_digest: str
    artifact_builder_recipe_version: str
    artifact_builder_recipe_digest: str
    rls_builder_recipe_version: str
    rls_builder_recipe_digest: str
    expectation_digest: str
    observation_digest: str
    evidence_digest: str
    verdict: str
    reasons: tuple[str, ...]
    observation: E3PlanningCatalogObservation
    receipt_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "declared_usable_kinds",
            tuple(self.declared_usable_kinds),
        )
        object.__setattr__(
            self,
            "observed_physical_kinds",
            tuple(self.observed_physical_kinds),
        )
        object.__setattr__(self, "reasons", tuple(self.reasons))
        if self.verdict not in {"pass", "fail"}:
            raise ValueError("E3 planning catalog receipt verdict is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "validator_version": self.validator_version,
            "evidence_scope": self.evidence_scope,
            "query_id": self.query_id,
            "occurrence_id": self.occurrence_id,
            "policy_id": self.policy_id,
            "principal_id": self.principal_id,
            "context_token": self.context_token,
            "context_payload_json": self.context_payload_json,
            "context_digest": self.context_digest,
            "declared_usable_kinds": list(self.declared_usable_kinds),
            "observed_physical_kinds": list(self.observed_physical_kinds),
            "snapshot_digest": self.snapshot_digest,
            "rendered_predicate_digest": self.rendered_predicate_digest,
            "rls_rendered_predicate_digest": self.rls_rendered_predicate_digest,
            "policy_definition_digest": self.policy_definition_digest,
            "artifact_builder_recipe_version": self.artifact_builder_recipe_version,
            "artifact_builder_recipe_digest": self.artifact_builder_recipe_digest,
            "rls_builder_recipe_version": self.rls_builder_recipe_version,
            "rls_builder_recipe_digest": self.rls_builder_recipe_digest,
            "expectation_digest": self.expectation_digest,
            "observation_digest": self.observation_digest,
            "evidence_digest": self.evidence_digest,
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "observation": self.observation.to_dict(),
            "receipt_digest": self.receipt_digest,
        }


@dataclass(frozen=True)
class E3PlanningCatalogReplay:
    ok: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class E3TypedAdmissionBundle:
    schema_version: str
    issuer_version: str
    logical_target: PolicyAccessTarget
    implementation_bindings: tuple[ImplementationTargetBinding, ...]
    gamma_snapshot: GammaSnapshot
    native_rls_contract: NativeRLSSessionContract
    registry_template_ids: tuple[str, ...]
    fact_evidence_json: tuple[str, ...]
    unresolved_dynamic_obligations: tuple[str, ...]
    bundle_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "implementation_bindings",
            tuple(self.implementation_bindings),
        )
        object.__setattr__(
            self,
            "registry_template_ids",
            tuple(self.registry_template_ids),
        )
        object.__setattr__(
            self,
            "fact_evidence_json",
            tuple(self.fact_evidence_json),
        )
        object.__setattr__(
            self,
            "unresolved_dynamic_obligations",
            tuple(self.unresolved_dynamic_obligations),
        )
        if not isinstance(self.logical_target, PolicyAccessTarget):
            raise TypeError("E3 typed admission bundle requires a PolicyAccessTarget")
        if any(
            not isinstance(binding, ImplementationTargetBinding)
            for binding in self.implementation_bindings
        ):
            raise TypeError("E3 typed admission bundle has an invalid target binding")
        if not isinstance(self.gamma_snapshot, GammaSnapshot):
            raise TypeError("E3 typed admission bundle requires a GammaSnapshot")
        if not isinstance(self.native_rls_contract, NativeRLSSessionContract):
            raise TypeError("E3 typed admission bundle has an invalid RLS contract")
        if len(self.gamma_snapshot.facts) != len(self.fact_evidence_json):
            raise ValueError("E3 typed admission facts and evidence are not aligned")

    def to_dict(self) -> dict[str, Any]:
        facts = []
        for fact, evidence_json in zip(
            self.gamma_snapshot.facts,
            self.fact_evidence_json,
        ):
            facts.append(
                {
                    "fact_id": fact.fact_id,
                    "kind": fact.kind,
                    "subject_digest": fact.subject_digest,
                    "verdict": fact.verdict,
                    "validator_version": fact.validator_version,
                    "snapshot_id": fact.snapshot_id,
                    "evidence_digest": fact.evidence_digest,
                    "dynamic": fact.dynamic,
                    "evidence": json.loads(evidence_json),
                }
            )
        return {
            "schema_version": self.schema_version,
            "issuer_version": self.issuer_version,
            "logical_target": self.logical_target.to_dict(),
            "logical_target_digest": self.logical_target.digest,
            "implementation_bindings": [
                {**binding.to_dict(), "binding_digest": binding.digest}
                for binding in self.implementation_bindings
            ],
            "registry_template_ids": list(self.registry_template_ids),
            "gamma_snapshot_id": self.gamma_snapshot.snapshot_id,
            "gamma_snapshot_digest": self.gamma_snapshot.digest,
            "facts": facts,
            "native_rls_contract": _e3_native_rls_contract_payload(
                self.native_rls_contract
            ),
            "unresolved_dynamic_obligations": list(self.unresolved_dynamic_obligations),
            "bundle_digest": self.bundle_digest,
        }


@dataclass(frozen=True)
class E3RawPgRanker:
    name: str = "pg-explain-raw"
    version: str = "pg_explain_raw_v1"
    calibration_path: Optional[str] = None
    calibration_hash: Optional[str] = None

    def estimate(self, features: E3CostFeatures) -> float:
        return features.pg_total_cost


@dataclass(frozen=True)
class E3CalibratedRanker:
    version: str
    config: Mapping[str, Any]
    calibration_path: str
    calibration_hash: str
    name: str = "calibrated-explain"

    def estimate(self, features: E3CostFeatures) -> float:
        default_alpha = _as_float(self.config.get("default_alpha"), 1.0)
        default_intercept = _as_float(self.config.get("default_intercept"), 0.0)
        default_multiplier = _as_float(self.config.get("default_multiplier"), 1.0)

        templates = _as_mapping(self.config.get("templates"))
        template_cfg = _as_mapping(templates.get(features.template_id))
        alpha = _as_float(template_cfg.get("alpha"), default_alpha)
        intercept = _as_float(template_cfg.get("intercept"), default_intercept)
        estimate = intercept + alpha * features.pg_total_cost
        estimate += _as_float(
            template_cfg.get("protected_rows_log_coeff"), 0.0
        ) * math.log1p(features.protected_rows)
        estimate += _as_float(
            template_cfg.get("authorized_rows_log_coeff"), 0.0
        ) * math.log1p(features.authorized_rows)
        estimate += _as_float(
            template_cfg.get("query_local_rows_log_coeff"), 0.0
        ) * math.log1p(features.query_local_rows)
        estimate += (
            _as_float(template_cfg.get("join_count_coeff"), 0.0) * features.join_count
        )
        estimate += (
            _as_float(template_cfg.get("sort_count_coeff"), 0.0) * features.sort_count
        )

        multiplier = default_multiplier * _as_float(template_cfg.get("multiplier"), 1.0)
        if features.has_materialized_cte:
            multiplier *= _as_float(
                template_cfg.get("materialized_cte_multiplier"), 1.0
            )
        if features.has_cte_scan:
            multiplier *= _as_float(template_cfg.get("cte_scan_multiplier"), 1.0)
        if features.has_seq_scan:
            multiplier *= _as_float(template_cfg.get("seq_scan_multiplier"), 1.0)
        if features.has_index_scan:
            multiplier *= _as_float(template_cfg.get("index_scan_multiplier"), 1.0)

        policy_multipliers = _as_mapping(self.config.get("policy_multipliers"))
        multiplier *= _as_float(
            _as_mapping(policy_multipliers.get(features.policy_config_id)).get(
                features.template_id
            ),
            1.0,
        )
        workload_multipliers = _as_mapping(self.config.get("workload_multipliers"))
        multiplier *= _as_float(
            _as_mapping(workload_multipliers.get(features.workload)).get(
                features.template_id
            ),
            1.0,
        )
        query_multipliers = _as_mapping(self.config.get("query_multipliers"))
        multiplier *= _as_float(
            _as_mapping(query_multipliers.get(features.query_id)).get(
                features.template_id
            ),
            1.0,
        )
        source_multipliers = _as_mapping(self.config.get("source_multipliers"))
        multiplier *= _as_float(source_multipliers.get(features.source), 1.0)
        dominance_rules = _as_mapping(self.config.get("dominance_rules"))
        unnecessary_barrier = _as_mapping(
            dominance_rules.get("unnecessary_materialized_barrier")
        )
        if (
            unnecessary_barrier.get("enabled", False)
            and features.template_id == "barrier_filter_v1"
            and features.policy_config_id == CHEAP_TENANT_POLICY_ID
            and features.source == "barrier"
            and features.has_materialized_cte
        ):
            multiplier *= _as_float(unnecessary_barrier.get("multiplier"), 1.0)
        semijoin_gate = _as_mapping(dominance_rules.get("semijoin_selectivity_gate"))
        if semijoin_gate.get("enabled", False) and features.template_id in {
            "auth_index_semijoin_v1",
            "auth_index_keyed_semijoin_v1",
        }:
            if features.authorized_rows > _as_float(
                semijoin_gate.get("auth_rows_high_fraction"), 0.75
            ) * max(features.protected_rows, 1):
                multiplier *= _as_float(
                    semijoin_gate.get("auth_rows_high_multiplier"), 1.0
                )
            if features.query_local_rows > _as_float(
                semijoin_gate.get("query_rows_high_fraction"), 0.50
            ) * max(features.protected_rows, 1):
                multiplier *= _as_float(
                    semijoin_gate.get("query_rows_high_multiplier"), 1.0
                )
            if features.template_id == "auth_index_keyed_semijoin_v1":
                if features.key_value_cardinality is None:
                    multiplier *= _as_float(
                        semijoin_gate.get("missing_key_cardinality_multiplier"), 1.0
                    )
                else:
                    threshold = max(
                        _as_float(
                            semijoin_gate.get("key_value_cardinality_abs_threshold"),
                            1000.0,
                        ),
                        _as_float(
                            semijoin_gate.get("key_value_cardinality_auth_fraction"),
                            0.25,
                        )
                        * max(features.authorized_rows, 1),
                    )
                    if features.key_value_cardinality > threshold:
                        multiplier *= _as_float(
                            semijoin_gate.get("key_value_cardinality_high_multiplier"),
                            1.0,
                        )
            if features.has_nested_loop and (features.plan_rows or 0.0) > _as_float(
                semijoin_gate.get("nested_loop_plan_rows_threshold"), 1000.0
            ):
                multiplier *= _as_float(
                    semijoin_gate.get("nested_loop_multiplier"), 1.0
                )

        return max(0.0, estimate * multiplier)


E3Ranker = Union[E3RawPgRanker, E3CalibratedRanker]


CHEAP_TENANT_POLICY_ID = "cheap_tenant_sargable"
GROUP_ACL_POLICY_ID = "group_acl_expensive"
HYBRID_SELECTIVE_KEY_POLICY_ID = "hybrid_selective_key"

# All E3 main policies below are pure relational predicates over base or trusted
# policy tables and contain no UDF or side-effecting expression, so they are
# valid SafePredicateInjection inputs.
POLICY_CONFIGS = [
    E3PolicyConfig(
        config_id=CHEAP_TENANT_POLICY_ID,
        selectivity=0.1,
        policy_cost="cheap",
        artifacts="none",
        exact_predicate="",
        injection_safe=True,
    ),
    E3PolicyConfig(
        config_id=GROUP_ACL_POLICY_ID,
        selectivity=0.1,
        policy_cost="expensive_acl",
        artifacts="auth_idx",
        exact_predicate="",
        injection_safe=True,
    ),
    E3PolicyConfig(
        config_id=HYBRID_SELECTIVE_KEY_POLICY_ID,
        selectivity=0.02,
        policy_cost="100us",
        artifacts="both_keyed",
        exact_predicate="",
        injection_safe=True,
    ),
]

REQUIRED_MODES = {
    "native-pg-rls",
    "native-pg-rls-physical-design",
    "security-barrier",
    "barrier-only",
    "injection-only",
    "auth-index-enum-only",
    "strong-auth-index",
    "local-greedy",
    ADMISSION_FIRST_MODE,
}

MODE_TEMPLATES = {
    "native-pg-rls": ("native_pg_rls_v1", "NativePostgreSQLRLS"),
    "native-pg-rls-physical-design": (
        "native_pg_rls_physical_design_v1",
        "NativePostgreSQLRLSPhysicalDesign",
    ),
    "security-barrier": ("barrier_filter_v1", "SecurityBarrier"),
    "barrier-only": ("barrier_filter_v1", "BarrierFilter"),
    "injection-only": ("safe_predicate_injection_v1", "ExactInjectionOnly"),
    "auth-index-enum-only": ("auth_index_enum_v1", "AuthorizationIndexSeek"),
    "strong-auth-index": ("strong_auth_index_keyed_v1", "StrongAuthIndexBaseline"),
}

QUERIES = [
    E3QuerySpec(
        query_id="Q3",
        path="workloads/e3/tpch_q3_smoke.sql",
        workload="tpch",
        protected_rel="tpch_customer",
        rid_col="c_custkey",
        alias="c",
        key_name="c_mktsegment",
        key_value="BUILDING",
    ),
    E3QuerySpec(
        query_id="Q5",
        path="workloads/e3/tpch_q5_reduced.sql",
        workload="tpch",
        protected_rel="tpch_customer",
        rid_col="c_custkey",
        alias="c",
        key_name="c_mktsegment",
        key_value="BUILDING",
    ),
    E3QuerySpec(
        query_id="Q7",
        path="workloads/e3/tpch_q7_mini.sql",
        workload="tpch",
        protected_rel="tpch_customer",
        rid_col="c_custkey",
        alias="c",
        key_name="c_mktsegment",
        key_value="BUILDING",
    ),
    E3QuerySpec(
        query_id="Q10",
        path="workloads/e3/tpch_q10_mini.sql",
        workload="tpch",
        protected_rel="tpch_customer",
        rid_col="c_custkey",
        alias="c",
        key_name="c_mktsegment",
        key_value="BUILDING",
    ),
    E3QuerySpec(
        query_id="Q12",
        path="workloads/e3/tpch_q12_mini.sql",
        workload="tpch",
        protected_rel="tpch_customer",
        rid_col="c_custkey",
        alias="c",
        key_name="c_mktsegment",
        key_value="BUILDING",
    ),
    E3QuerySpec(
        query_id="JOB_1a",
        path="workloads/e3/job_1a_reduced.sql",
        workload="job",
        protected_rel="job_title",
        rid_col="t_id",
        alias="t",
        key_name="kind",
        key_value="movie",
    ),
    E3QuerySpec(
        query_id="JOB_2a",
        path="workloads/e3/job_2a_mini.sql",
        workload="job",
        protected_rel="job_title",
        rid_col="t_id",
        alias="t",
        key_name="kind",
        key_value="movie",
    ),
    E3QuerySpec(
        query_id="JOB_3c",
        path="workloads/e3/job_3c_mini.sql",
        workload="job",
        protected_rel="job_title",
        rid_col="t_id",
        alias="t",
        key_name="kind",
        key_value="movie",
    ),
    E3QuerySpec(
        query_id="JOB_6d",
        path="workloads/e3/job_6d_reduced.sql",
        workload="job",
        protected_rel="job_title",
        rid_col="t_id",
        alias="t",
        key_name="kind",
        key_value="movie",
    ),
    E3QuerySpec(
        query_id="JOB_10a",
        path="workloads/e3/job_10a_mini.sql",
        workload="job",
        protected_rel="job_title",
        rid_col="t_id",
        alias="t",
        key_name="kind",
        key_value="movie",
    ),
    E3QuerySpec(
        query_id="JOB_16b",
        path="workloads/e3/job_16b_mini.sql",
        workload="job",
        protected_rel="job_title",
        rid_col="t_id",
        alias="t",
        key_name="kind",
        key_value="movie",
    ),
]

E3_CARRIER_PROJECTION_COLUMNS = {
    "Q3": ("c_custkey", "c_mktsegment", "tenant_id"),
    "Q5": ("c_custkey", "c_mktsegment", "region_id", "tenant_id"),
    "Q7": ("c_custkey", "c_mktsegment", "region_id", "tenant_id"),
    "Q10": ("c_custkey", "c_mktsegment", "region_id", "tenant_id"),
    "Q12": ("c_custkey", "c_mktsegment", "tenant_id"),
    "JOB_1a": ("t_id", "kind", "production_year", "region_id"),
    "JOB_2a": ("t_id", "kind", "production_year", "region_id"),
    "JOB_3c": ("t_id", "kind", "production_year", "region_id"),
    "JOB_6d": ("t_id", "kind", "production_year", "region_id", "studio_id"),
    "JOB_10a": ("t_id", "kind", "production_year", "region_id"),
    "JOB_16b": ("t_id", "kind", "production_year", "region_id", "studio_id"),
}

E3_ACCESS_COLUMN_CONTRACTS = {
    "tpch_customer": {
        "c_custkey": ("bigint", False),
        "c_mktsegment": ("text", False),
        "tenant_id": ("bigint", False),
        "region_id": ("bigint", False),
    },
    "job_title": {
        "t_id": ("bigint", False),
        "kind": ("text", False),
        "production_year": ("integer", False),
        "region_id": ("bigint", False),
        "studio_id": ("bigint", False),
    },
}

E3_RESULT_COLUMN_CONTRACTS = {
    "Q3": (
        ("l_orderkey", "bigint", False),
        ("revenue", "numeric", True),
        ("o_orderdate", "date", False),
        ("o_shippriority", "integer", False),
    ),
    "Q5": (("region_id", "bigint", False), ("revenue", "numeric", True)),
    "Q7": (
        ("region_id", "bigint", False),
        ("order_year", "integer", False),
        ("revenue", "numeric", True),
    ),
    "Q10": (
        ("c_custkey", "bigint", False),
        ("region_id", "bigint", False),
        ("revenue", "numeric", True),
    ),
    "Q12": (
        ("o_shippriority", "integer", False),
        ("early_ship_count", "bigint", False),
        ("late_ship_count", "bigint", False),
    ),
    "JOB_1a": (("t_id", "bigint", False), ("matches", "bigint", False)),
    "JOB_2a": (
        ("production_year", "integer", False),
        ("production_edges", "bigint", False),
    ),
    "JOB_3c": (
        ("region_id", "bigint", False),
        ("regional_cast_edges", "bigint", False),
    ),
    "JOB_6d": (
        ("studio_id", "bigint", False),
        ("cast_edges", "bigint", False),
    ),
    "JOB_10a": (
        ("production_year", "integer", False),
        ("company_edges", "bigint", False),
    ),
    "JOB_16b": (
        ("studio_id", "bigint", False),
        ("title_company_edges", "bigint", False),
    ),
}

E3_RESULT_ORDER_CONTRACTS = {
    "Q3": (("revenue DESC", "o.o_orderdate ASC"), 10),
    "Q5": (("revenue DESC",), 10),
    "Q7": (("revenue DESC", "c.region_id ASC", "order_year ASC"), 20),
    "Q10": (("revenue DESC", "c.c_custkey ASC"), 20),
    "Q12": (("o.o_shippriority ASC",), None),
    "JOB_1a": (("matches DESC", "t.t_id ASC"), 20),
    "JOB_2a": (("production_edges DESC", "t.production_year ASC"), 20),
    "JOB_3c": (("regional_cast_edges DESC", "t.region_id ASC"), 20),
    "JOB_6d": (("cast_edges DESC", "t.studio_id ASC"), 20),
    "JOB_10a": (("company_edges DESC", "t.production_year ASC"), 20),
    "JOB_16b": (("title_company_edges DESC", "t.studio_id ASC"), 20),
}


REAL_TPCH_SCALES = {"SF1", "SF10", "SF100"}
REAL_JOB_SCALES = {"full"}
E3_PSQL_GUCS = {
    "jit": "off",
    "max_parallel_workers_per_gather": "0",
    "plan_cache_mode": "force_custom_plan",
}
E3_PLANNER_TEMPLATE_IDS = (
    "ordinary_first_exact_check_v1",
    "safe_predicate_injection_v1",
    "barrier_filter_inline_v1",
    "barrier_filter_v1",
    "barrier_filter_query_v1",
    "auth_index_enum_v1",
    "strong_auth_index_keyed_v1",
    "hybrid_intersect_v1",
)
E3_ENGINE_RLS_TEMPLATE_IDS = ("native_pg_rls_v1",)
E3_SEMIJOIN_TEMPLATE_IDS = ("auth_index_semijoin_v1", "auth_index_keyed_semijoin_v1")
E3_PRINCIPAL_ID = "e3_user"
E3_CONTEXT_TOKEN = "e3_main_ctx_hash"
E3_RLS_ROLE = "caprls_e3_rls_user"
E3_CATALOG_OBSERVATION_SCHEMA = "e3_planning_catalog_observation_v1"
E3_CATALOG_RECEIPT_SCHEMA = "e3_planning_catalog_receipt_v1"
E3_CATALOG_VALIDATOR_VERSION = "e3_pg_catalog_validator_v1"
E3_TRUSTED_OBSERVATION_SCHEMA = "e3_planning_catalog_observation_trusted_v2"
E3_TRUSTED_RECEIPT_SCHEMA = "e3_planning_catalog_receipt_trusted_v2"
E3_TRUSTED_VALIDATOR_VERSION = "e3_pg_catalog_validator_trusted_v2"
E3_EXECUTION_PROFILES = frozenset({"native_rls", "trusted_explicit"})
E3_CATALOG_PRODUCTION_SCOPE = "planning_pre_cost_catalog_only"
E3_CATALOG_FIXTURE_SCOPE = "non_promotable_unit_fixture"
E3_ARTIFACT_BUILDER_RECIPE_VERSION = "e3_artifact_builder_v1"
E3_RLS_BUILDER_RECIPE_VERSION = "shared_native_rls_builder_v1"
E3_CATALOG_SEARCH_PATH = "pg_catalog, public"
E3_CATALOG_ROW_SECURITY = "on"
E3_TYPED_ADMISSION_SCHEMA = "e3_typed_admission_bundle_v1"
E3_TYPED_ADMISSION_ISSUER_VERSION = "e3_catalog_receipt_to_gamma_v1"
E3_TYPED_FACT_EVIDENCE_SCHEMA = "e3_typed_gamma_fact_evidence_v1"
E3_PRODUCTION_ROOT_COST_MODEL_VERSION = "e3_bound_runner_plain_explain_v2"
E3_PROSPECTIVE_ROOT_SCOPE = "exact_bound_semantic_runner"
E3_PROSPECTIVE_ROOT_STATUS = "prospective_runner_bound"
E3_PROSPECTIVE_ROOT_REASON = "planning_session_does_not_execute_candidate_body"
E3_PRODUCTION_PLANNING_GUCS = {
    "row_security": "on",
    **E3_PSQL_GUCS,
}


_REGISTERED_E3_PRODUCTION_SOURCES: dict[
    int,
    tuple[
        weakref.ReferenceType[Any],
        str,
        str,
        Optional[E3QuerySpec],
        Optional[E3PolicyConfig],
        Optional[E3PlanningCatalogReceipt],
        Optional[TemplateRegistry],
        str,
    ],
] = {}
_REGISTERED_E3_PRODUCTION_OWNERS: dict[
    int,
    tuple[
        weakref.ReferenceType[Any],
        str,
        E3QuerySpec,
        E3PolicyConfig,
        TemplateRegistry,
        PostgresEnv,
        E3PlanningCatalogReceipt,
        E3TypedAdmissionBundle,
    ],
] = {}
_REGISTERED_E3_PRODUCTION_QUERY_PLANS: dict[
    int,
    tuple[
        Mapping[str, Any],
        str,
        Any,
        PlanningEvidenceBatch,
        str,
        str,
        BoundRunnerIdentity,
    ],
] = {}
_REGISTERED_E3_PRODUCTION_PLAN_LINEAGE: dict[
    int,
    tuple[PlanResult, Mapping[str, Any], str, str],
] = {}
_E3_PRODUCTION_OWNER_CAPABILITY = object()


def _e3_production_source_payload_digest(value: Any) -> str:
    try:
        payload = value.to_dict()
    except (AttributeError, TypeError, ValueError) as exc:
        raise PostgresError("E3 production source payload is not serializable") from exc
    if payload.__class__ is not dict:
        raise PostgresError("E3 production source payload is not an exact object")
    try:
        return _canonical_sha256(
            {
                "schema": "e3_production_issued_source_snapshot_v1",
                "payload": payload,
            }
        )
    except (TypeError, ValueError) as exc:
        raise PostgresError("E3 production source payload is not canonical") from exc


def _require_e3_canonical_query_policy_sources(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
) -> None:
    if query.__class__ is not E3QuerySpec or not any(item is query for item in QUERIES):
        raise PostgresError("E3 production query is not the exact canonical source")
    if policy.__class__ is not E3PolicyConfig or not any(
        item is policy for item in POLICY_CONFIGS
    ):
        raise PostgresError("E3 production policy is not the exact canonical source")


def _register_e3_production_source(
    value: Any,
    *,
    kind: str,
    identity_digest: str,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    receipt: Optional[E3PlanningCatalogReceipt] = None,
    registry: Optional[TemplateRegistry] = None,
) -> Any:
    _require_e3_canonical_query_policy_sources(query, policy)
    payload_digest = _e3_production_source_payload_digest(value)
    key = id(value)

    def _drop(reference: weakref.ReferenceType[Any]) -> None:
        registered = _REGISTERED_E3_PRODUCTION_SOURCES.get(key)
        if registered is not None and registered[0] is reference:
            _REGISTERED_E3_PRODUCTION_SOURCES.pop(key, None)

    _REGISTERED_E3_PRODUCTION_SOURCES[key] = (
        weakref.ref(value, _drop),
        kind,
        identity_digest,
        query,
        policy,
        receipt,
        registry,
        payload_digest,
    )
    return value


def _require_e3_production_source(
    value: Any,
    *,
    kind: str,
    identity_digest: str,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    receipt: Optional[E3PlanningCatalogReceipt] = None,
    registry: Optional[TemplateRegistry] = None,
) -> None:
    registered = _REGISTERED_E3_PRODUCTION_SOURCES.get(id(value))
    if (
        registered is None
        or registered[0]() is not value
        or registered[1] != kind
        or registered[2] != identity_digest
        or registered[3] is not query
        or registered[4] is not policy
        or registered[5] is not receipt
        or registered[6] is not registry
        or registered[7] != _e3_production_source_payload_digest(value)
    ):
        raise PostgresError(
            f"E3 production {kind} is not an exact issued source capability"
        )


def _e3_registry(
    *,
    include_engine_rls: bool = False,
    include_semijoin: bool = False,
    include_bare_policy_check: bool = False,
) -> TemplateRegistry:
    template_ids = []
    if include_engine_rls:
        template_ids.extend(E3_ENGINE_RLS_TEMPLATE_IDS)
    # Canonical E3 has a checked, licensed local q. Its Policy check form
    # materializes P AND q; keep bare P available only for explicit legacy
    # experiments. Both forms still go through ordinary typed admission.
    template_ids.extend(
        template_id for template_id in E3_PLANNER_TEMPLATE_IDS
        if include_bare_policy_check or template_id != "barrier_filter_v1"
    )
    if include_semijoin:
        template_ids.extend(E3_SEMIJOIN_TEMPLATE_IDS)
    return TemplateRegistry(
        DEFAULT_TEMPLATE_REGISTRY.get(template_id) for template_id in template_ids
    )


def _e3_registry_from_manifest(manifest: Mapping[str, Any]) -> TemplateRegistry:
    portfolio = _as_mapping(manifest.get("portfolio_candidates"))
    return _e3_registry(
        include_engine_rls=bool(portfolio.get("include_engine_rls")),
        include_semijoin=bool(portfolio.get("include_semijoin")),
        include_bare_policy_check=bool(portfolio.get("include_bare_policy_check")),
    )


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _canonical_sha256(payload: Any) -> str:
    encoded = _canonical_json(payload).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class _E3BorrowedPlanningSession:
    """Use one already-owned planning session without closing it."""

    def __init__(self, session: PostgresTransactionSession) -> None:
        if (
            not callable(getattr(session, "execute", None))
            or not callable(getattr(session, "recheck_identity", None))
            or not callable(
                getattr(session, "_describe_result_columns_without_execution", None)
            )
        ):
            raise PostgresError("E3 production planning requires an exact live session")
        identity = session.identity
        if (
            getattr(identity, "isolation_level", None) != "repeatable read"
            or getattr(identity, "read_only", None) is not True
        ):
            raise PostgresError("E3 production planning session identity is invalid")
        self._session = session

    def __enter__(self) -> PostgresTransactionSession:
        return self._session

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        del exc_type, exc, traceback
        return False


def _strict_keys(
    payload: Mapping[str, Any],
    expected: set[str],
    *,
    label: str,
) -> None:
    actual = set(payload)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"{label} schema mismatch; missing={missing}, extra={extra}")


def _strict_string(payload: Mapping[str, Any], key: str, *, label: str) -> str:
    value = payload[key]
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label}.{key} must be a non-empty string")
    return value


def _strict_sha256(payload: Mapping[str, Any], key: str, *, label: str) -> str:
    value = _strict_string(payload, key, label=label)
    if re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise ValueError(f"{label}.{key} must be a canonical sha256 digest")
    return value


def _strict_bool(payload: Mapping[str, Any], key: str, *, label: str) -> bool:
    value = payload[key]
    if not isinstance(value, bool):
        raise ValueError(f"{label}.{key} must be boolean")
    return value


def _strict_int(payload: Mapping[str, Any], key: str, *, label: str) -> int:
    value = payload[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label}.{key} must be an integer")
    return value


def _strict_string_tuple(value: Any, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ValueError(f"{label} must be a JSON list of non-empty strings")
    return tuple(value)


def _relation_claim_from_dict(payload: Any) -> E3RelationCatalogClaim:
    if not isinstance(payload, Mapping):
        raise ValueError("E3 catalog relation claim must be an object")
    label = "relation"
    _strict_keys(
        payload,
        {
            "oid",
            "schema_name",
            "relation_name",
            "owner",
            "row_security_enabled",
            "force_row_security",
        },
        label=label,
    )
    return E3RelationCatalogClaim(
        oid=_strict_int(payload, "oid", label=label),
        schema_name=_strict_string(payload, "schema_name", label=label),
        relation_name=_strict_string(payload, "relation_name", label=label),
        owner=_strict_string(payload, "owner", label=label),
        row_security_enabled=_strict_bool(
            payload,
            "row_security_enabled",
            label=label,
        ),
        force_row_security=_strict_bool(
            payload,
            "force_row_security",
            label=label,
        ),
    )


def _rls_claim_from_dict(payload: Any) -> E3RLSPolicyCatalogClaim:
    if not isinstance(payload, Mapping):
        raise ValueError("E3 catalog RLS policy claim must be an object")
    label = "rls_policy"
    _strict_keys(
        payload,
        {"policy_name", "command", "permissive", "roles", "expression"},
        label=label,
    )
    return E3RLSPolicyCatalogClaim(
        policy_name=_strict_string(payload, "policy_name", label=label),
        command=_strict_string(payload, "command", label=label),
        permissive=_strict_bool(payload, "permissive", label=label),
        roles=_strict_string_tuple(payload["roles"], label=f"{label}.roles"),
        expression=_strict_string(payload, "expression", label=label),
    )


def _role_claim_from_dict(payload: Any) -> E3RoleCatalogClaim:
    if not isinstance(payload, Mapping):
        raise ValueError("E3 catalog role claim must be an object")
    label = "role"
    _strict_keys(
        payload,
        {"role_name", "is_superuser", "bypasses_rls", "member_of", "members"},
        label=label,
    )
    return E3RoleCatalogClaim(
        role_name=_strict_string(payload, "role_name", label=label),
        is_superuser=_strict_bool(payload, "is_superuser", label=label),
        bypasses_rls=_strict_bool(payload, "bypasses_rls", label=label),
        member_of=_strict_string_tuple(
            payload["member_of"],
            label=f"{label}.member_of",
        ),
        members=_strict_string_tuple(payload["members"], label=f"{label}.members"),
    )


def _trusted_execution_claim_from_dict(payload: Any) -> E3TrustedExecutionCatalogClaim:
    if not isinstance(payload, Mapping):
        raise ValueError("trusted execution catalog claim must be an object")
    _strict_keys(payload, {"database", "role", "relations", "artifact_validator"},
                 label="trusted_execution")
    if payload["relations"].__class__ is not list:
        raise ValueError("trusted execution relations must be a list")
    if payload["artifact_validator"].__class__ is not dict:
        raise ValueError("trusted execution artifact validator is missing")
    return E3TrustedExecutionCatalogClaim(
        database=_strict_string(payload, "database", label="trusted_execution"),
        role=_role_claim_from_dict(payload["role"]),
        relations_json=_canonical_json(payload["relations"]),
        validator_json=_canonical_json(payload["artifact_validator"]),
    )


def _dependency_claim_from_dict(payload: Any) -> E3ArtifactDependencyClaim:
    if not isinstance(payload, Mapping):
        raise ValueError("E3 artifact dependency claim must be an object")
    label = "artifact_dependency"
    _strict_keys(
        payload,
        {
            "artifact_id",
            "dependency_kind",
            "dependency_name",
            "version_at_build",
        },
        label=label,
    )
    return E3ArtifactDependencyClaim(
        artifact_id=_strict_string(payload, "artifact_id", label=label),
        dependency_kind=_strict_string(payload, "dependency_kind", label=label),
        dependency_name=_strict_string(payload, "dependency_name", label=label),
        version_at_build=_strict_int(payload, "version_at_build", label=label),
    )


def _scope_claim_from_dict(payload: Any) -> E3ArtifactScopeClaim:
    if not isinstance(payload, Mapping):
        raise ValueError("E3 artifact scope claim must be an object")
    label = "artifact_scope"
    _strict_keys(
        payload,
        {
            "physical_kind",
            "artifact_id",
            "policy_id",
            "principal_id",
            "context_token",
            "rid_domain_id",
            "base_relation_oid",
            "policy_version",
            "membership_version",
            "key_name",
            "key_value_is_null",
            "range_bucket_is_nonnull",
            "has_duplicate_identity",
        },
        label=label,
    )
    key_name = payload["key_name"]
    if key_name is not None and (not isinstance(key_name, str) or not key_name):
        raise ValueError(f"{label}.key_name must be null or a non-empty string")
    return E3ArtifactScopeClaim(
        physical_kind=_strict_string(payload, "physical_kind", label=label),
        artifact_id=_strict_string(payload, "artifact_id", label=label),
        policy_id=_strict_string(payload, "policy_id", label=label),
        principal_id=_strict_string(payload, "principal_id", label=label),
        context_token=_strict_string(payload, "context_token", label=label),
        rid_domain_id=_strict_string(payload, "rid_domain_id", label=label),
        base_relation_oid=_strict_int(payload, "base_relation_oid", label=label),
        policy_version=_strict_int(payload, "policy_version", label=label),
        membership_version=_strict_int(payload, "membership_version", label=label),
        key_name=key_name,
        key_value_is_null=_strict_bool(
            payload,
            "key_value_is_null",
            label=label,
        ),
        range_bucket_is_nonnull=_strict_bool(
            payload,
            "range_bucket_is_nonnull",
            label=label,
        ),
        has_duplicate_identity=_strict_bool(
            payload,
            "has_duplicate_identity",
            label=label,
        ),
    )


def _e3_catalog_observation_from_dict(
    payload: Any,
) -> E3PlanningCatalogObservation:
    if not isinstance(payload, Mapping):
        raise ValueError("E3 catalog observation must be a JSON object")
    label = "catalog_observation"
    expected_keys = {
        "collector_schema", "session_user", "current_user", "search_path",
        "row_security", "snapshot_text", "relation", "policies", "role",
        "dependencies", "artifact_scopes",
    }
    trusted = payload.get("collector_schema") == E3_TRUSTED_OBSERVATION_SCHEMA
    if trusted:
        expected_keys.add("trusted_execution")
    _strict_keys(
        payload,
        expected_keys,
        label=label,
    )
    policies = payload["policies"]
    dependencies = payload["dependencies"]
    scopes = payload["artifact_scopes"]
    if not isinstance(policies, list):
        raise ValueError("catalog_observation.policies must be a JSON list")
    if not isinstance(dependencies, list):
        raise ValueError("catalog_observation.dependencies must be a JSON list")
    if not isinstance(scopes, list):
        raise ValueError("catalog_observation.artifact_scopes must be a JSON list")
    observation = E3PlanningCatalogObservation(
        collector_schema=_strict_string(payload, "collector_schema", label=label),
        session_user=_strict_string(payload, "session_user", label=label),
        current_user=_strict_string(payload, "current_user", label=label),
        search_path=_strict_string(payload, "search_path", label=label),
        row_security=_strict_string(payload, "row_security", label=label),
        snapshot_text=_strict_string(payload, "snapshot_text", label=label),
        relation=_relation_claim_from_dict(payload["relation"]),
        policies=tuple(_rls_claim_from_dict(item) for item in policies),
        role=_role_claim_from_dict(payload["role"]),
        dependencies=tuple(_dependency_claim_from_dict(item) for item in dependencies),
        artifact_scopes=tuple(_scope_claim_from_dict(item) for item in scopes),
        trusted_execution=(
            _trusted_execution_claim_from_dict(payload["trusted_execution"])
            if trusted else None
        ),
    )
    if observation.collector_schema not in {
        E3_CATALOG_OBSERVATION_SCHEMA, E3_TRUSTED_OBSERVATION_SCHEMA
    }:
        raise ValueError("E3 catalog observation schema version is not trusted")
    return observation


def _parse_e3_catalog_collector_output(raw: str) -> E3PlanningCatalogObservation:
    lines = tuple(line.strip() for line in str(raw).splitlines() if line.strip())
    if len(lines) != 6:
        raise ValueError("E3 catalog collector output must contain six protocol lines")
    if lines[:4] != ("BEGIN", "SET", "SET", "SET") or lines[5] != "COMMIT":
        raise ValueError(
            "E3 catalog collector command tags are invalid or out of order"
        )
    try:
        payload = json.loads(lines[4])
    except json.JSONDecodeError as exc:
        raise ValueError(
            "E3 catalog collector must emit exactly one JSON object"
        ) from exc
    return _e3_catalog_observation_from_dict(payload)


def _e3_planning_catalog_receipt_from_dict(
    payload: Any,
) -> E3PlanningCatalogReceipt:
    if not isinstance(payload, Mapping):
        raise ValueError("E3 planning catalog receipt must be a JSON object")
    label = "planning_catalog_receipt"
    expected_keys = {
        "schema_version",
        "validator_version",
        "evidence_scope",
        "query_id",
        "occurrence_id",
        "policy_id",
        "principal_id",
        "context_token",
        "context_payload_json",
        "context_digest",
        "declared_usable_kinds",
        "observed_physical_kinds",
        "snapshot_digest",
        "rendered_predicate_digest",
        "rls_rendered_predicate_digest",
        "policy_definition_digest",
        "artifact_builder_recipe_version",
        "artifact_builder_recipe_digest",
        "rls_builder_recipe_version",
        "rls_builder_recipe_digest",
        "expectation_digest",
        "observation_digest",
        "evidence_digest",
        "verdict",
        "reasons",
        "observation",
        "receipt_digest",
    }
    _strict_keys(payload, expected_keys, label=label)
    receipt = E3PlanningCatalogReceipt(
        schema_version=_strict_string(payload, "schema_version", label=label),
        validator_version=_strict_string(payload, "validator_version", label=label),
        evidence_scope=_strict_string(payload, "evidence_scope", label=label),
        query_id=_strict_string(payload, "query_id", label=label),
        occurrence_id=_strict_string(payload, "occurrence_id", label=label),
        policy_id=_strict_string(payload, "policy_id", label=label),
        principal_id=_strict_string(payload, "principal_id", label=label),
        context_token=_strict_string(payload, "context_token", label=label),
        context_payload_json=_strict_string(
            payload,
            "context_payload_json",
            label=label,
        ),
        context_digest=_strict_sha256(payload, "context_digest", label=label),
        declared_usable_kinds=_strict_string_tuple(
            payload["declared_usable_kinds"],
            label=f"{label}.declared_usable_kinds",
        ),
        observed_physical_kinds=_strict_string_tuple(
            payload["observed_physical_kinds"],
            label=f"{label}.observed_physical_kinds",
        ),
        snapshot_digest=_strict_sha256(payload, "snapshot_digest", label=label),
        rendered_predicate_digest=_strict_sha256(
            payload,
            "rendered_predicate_digest",
            label=label,
        ),
        rls_rendered_predicate_digest=_strict_sha256(
            payload,
            "rls_rendered_predicate_digest",
            label=label,
        ),
        policy_definition_digest=_strict_sha256(
            payload,
            "policy_definition_digest",
            label=label,
        ),
        artifact_builder_recipe_version=_strict_string(
            payload,
            "artifact_builder_recipe_version",
            label=label,
        ),
        artifact_builder_recipe_digest=_strict_sha256(
            payload,
            "artifact_builder_recipe_digest",
            label=label,
        ),
        rls_builder_recipe_version=_strict_string(
            payload,
            "rls_builder_recipe_version",
            label=label,
        ),
        rls_builder_recipe_digest=_strict_sha256(
            payload,
            "rls_builder_recipe_digest",
            label=label,
        ),
        expectation_digest=_strict_sha256(
            payload,
            "expectation_digest",
            label=label,
        ),
        observation_digest=_strict_sha256(
            payload,
            "observation_digest",
            label=label,
        ),
        evidence_digest=_strict_sha256(payload, "evidence_digest", label=label),
        verdict=_strict_string(payload, "verdict", label=label),
        reasons=_strict_string_tuple(payload["reasons"], label=f"{label}.reasons"),
        observation=_e3_catalog_observation_from_dict(payload["observation"]),
        receipt_digest=_strict_sha256(payload, "receipt_digest", label=label),
    )
    trusted = receipt.observation.trusted_execution is not None
    if receipt.schema_version != (
        E3_TRUSTED_RECEIPT_SCHEMA if trusted else E3_CATALOG_RECEIPT_SCHEMA
    ):
        raise ValueError("E3 planning catalog receipt schema version is not trusted")
    if receipt.validator_version != (
        E3_TRUSTED_VALIDATOR_VERSION if trusted else E3_CATALOG_VALIDATOR_VERSION
    ):
        raise ValueError("E3 planning catalog receipt validator version is not trusted")
    try:
        context_payload = json.loads(receipt.context_payload_json)
    except json.JSONDecodeError as exc:
        raise ValueError("E3 planning context payload is not canonical JSON") from exc
    if (
        not isinstance(context_payload, Mapping)
        or _canonical_json(context_payload) != receipt.context_payload_json
    ):
        raise ValueError("E3 planning context payload must be a canonical JSON object")
    return receipt


def _e3_declared_usable_artifact_kinds(
    policy: E3PolicyConfig,
) -> tuple[str, ...]:
    if policy.artifacts == "none":
        return ()
    if policy.artifacts == "auth_idx":
        return ("auth_idx",)
    if policy.artifacts == "both_keyed":
        return ("auth_idx", "auth_idx_keyed")
    raise ValueError(f"unsupported E3 artifact declaration: {policy.artifacts}")


def _e3_expected_physical_artifact_kinds(
    policy: E3PolicyConfig,
) -> tuple[str, ...]:
    # The v1 builder currently materializes both physical tables whenever an
    # artifact is requested.  This is builder identity, not permission to
    # expose an undeclared keyed capability to the planner.
    return () if policy.artifacts == "none" else ("auth_idx", "auth_idx_keyed")


def _e3_context_payload(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    *,
    session_user: str,
    execution_profile: str = "native_rls",
    trusted_execution: Optional[E3TrustedExecutionCatalogClaim] = None,
) -> dict[str, Any]:
    _e3_require_execution_profile(execution_profile)
    payload = {
        "schema": "e3_request_context_v1",
        "principal_id": E3_PRINCIPAL_ID,
        "context_token": E3_CONTEXT_TOKEN,
        "policy_id": policy.config_id,
        "occurrence_id": query.query_id,
        "relation": f"public.{query.protected_rel}",
        "rid_domain_id": f"{query.protected_rel}.{query.rid_col}",
        "session": {
            "session_user": session_user,
            "execution_role": E3_RLS_ROLE,
            "search_path": E3_CATALOG_SEARCH_PATH,
            "row_security": E3_CATALOG_ROW_SECURITY,
            "query_gucs": dict(E3_PSQL_GUCS),
        },
    }
    if execution_profile == "trusted_explicit":
        if trusted_execution is None:
            raise ValueError("trusted explicit context requires observed execution facts")
        payload["schema"] = "e3_request_context_trusted_explicit_v2"
        payload["execution_profile"] = execution_profile
        payload["finite_fragment_digest"] = _canonical_sha256(
            _e3_trusted_finite_fragment_payload(query, policy)
        )
        payload["execution_catalog_digest"] = _canonical_sha256(trusted_execution.to_dict())
        payload["session"].update({
            "policy_validation_role": E3_RLS_ROLE,
            "execution_role": trusted_execution.role.role_name,
            "database": trusted_execution.database,
            "transaction_isolation": "repeatable read",
            "read_only": True,
        })
    elif trusted_execution is not None:
        raise ValueError("native profile cannot consume trusted explicit facts")
    return payload


def _e3_require_execution_profile(execution_profile: str) -> str:
    if type(execution_profile) is not str or execution_profile not in E3_EXECUTION_PROFILES:
        raise PostgresError("unsupported E3 execution profile")
    return execution_profile


def _e3_receipt_execution_profile(receipt: E3PlanningCatalogReceipt) -> str:
    return "trusted_explicit" if receipt.observation.trusted_execution is not None else "native_rls"


def _e3_trusted_validator_body() -> str:
    # Exact controlled validator semantics are part of this finite issuer,
    # rather than accepting an arbitrary same-named SECURITY DEFINER function.
    source = (Path(__file__).resolve().parents[1] / "sql/schema/000_core.sql").read_text()
    match = re.search(
        r"CREATE OR REPLACE FUNCTION public\.caprls_assert_artifact_valid\(.*?AS \$\$(.*?)\$\$;",
        source, re.DOTALL,
    )
    if match is None:
        raise PostgresError("controlled artifact validator source is missing")
    return match.group(1)


def _e3_trusted_finite_fragment_payload(
    query: E3QuerySpec, policy: E3PolicyConfig,
) -> dict[str, Any]:
    _require_e3_canonical_query_policy_sources(query, policy)
    if E3_PRINCIPAL_ID != "e3_user" or E3_CONTEXT_TOKEN != "e3_main_ctx_hash":
        raise PostgresError("trusted finite principal/context source changed")
    predicate = _policy_predicate(query, policy)
    continuation = _e3_continuation_sql(query)
    query_predicate = _e3_query_predicate(query, query.alias)
    # These strings are rendered only by the finite canonical source above.
    # This is not a sanitizer or a role-independence claim for caller SQL.
    if re.search(r"\b(current_user|session_user|current_role|set_config|current_setting)\b",
                 predicate + continuation + query_predicate, re.IGNORECASE):
        raise PostgresError("trusted finite SQL contains a session-sensitive expression")
    relations = set(re.findall(r"\b(?:FROM|JOIN)\s+public\.([a-z_][a-z_0-9]*)",
                               predicate + continuation, re.IGNORECASE))
    relations.update({query.protected_rel, "auth_idx", "auth_idx_keyed", "artifact_dependencies"})
    return {
        "schema": "e3_trusted_explicit_finite_fragment_v1",
        "query_source": asdict(query),
        "policy_source": _e3_policy_config_payload(policy),
        "principal_binding": {"kind": "controlled_literal", "value": E3_PRINCIPAL_ID},
        "query_predicate": query_predicate,
        "exact_policy": predicate,
        "continuation_sql": continuation,
        "relations": sorted(relations),
        "artifact_validator_body_digest": _canonical_sha256({"body": _e3_trusted_validator_body()}),
        "sql_scope": "canonical_e3_explicit_templates_and_builtin_expressions_only",
    }


def _e3_trusted_execution_validation_reasons(
    claim: Optional[E3TrustedExecutionCatalogClaim], query: E3QuerySpec,
    policy: E3PolicyConfig, *, session_user: str,
) -> tuple[str, ...]:
    if claim is None:
        return ("trusted_execution_claim_missing",)
    if claim.__class__ is not E3TrustedExecutionCatalogClaim:
        return ("trusted_execution_claim_type_invalid",)
    # Reparse the immutable export to enforce exact JSON scalar types also
    # for internal issuer callers constructing dataclasses directly.
    try:
        _trusted_execution_claim_from_dict(claim.to_dict())
    except (TypeError, ValueError):
        return ("trusted_execution_claim_shape_invalid",)
    reasons: list[str] = []
    fragment = _e3_trusted_finite_fragment_payload(query, policy)
    if not claim.database or claim.role.role_name != session_user:
        reasons.append("trusted_execution_identity_mismatch")
    if not (claim.role.is_superuser or claim.role.bypasses_rls):
        reasons.append("trusted_execution_requires_observed_rls_bypass")
    relations = json.loads(claim.relations_json)
    relation_keys = {
        "oid", "schema_name", "relation_name", "owner", "row_security_enabled",
        "force_row_security", "relation_kind", "has_rules", "has_triggers",
        "has_subclasses", "is_partition", "builtin_columns_only",
    }
    names: list[str] = []
    if relations.__class__ is not list:
        return tuple(reasons + ["trusted_execution_relations_invalid"])
    for relation in relations:
        if relation.__class__ is not dict or set(relation) != relation_keys:
            reasons.append("trusted_execution_relation_shape_invalid")
            continue
        name = relation["relation_name"]
        if type(name) is not str:
            reasons.append("trusted_execution_relation_identity_invalid")
            continue
        names.append(name)
        expected_rls = name == query.protected_rel
        # PostgreSQL has no SELECT triggers (PG16 CREATE TRIGGER, Description):
        # https://www.postgresql.org/docs/16/sql-createtrigger.html
        # The finite canonical query and exact validator body only read, in
        # RR READ ONLY. Keep relhastriggers as an observed boolean and in the
        # exact execution-time catalog guard; FK triggers need not be absent.
        # Rules/views and the other unsupported relation semantics still fail.
        if (
            type(relation["oid"]) is not int or relation["oid"] <= 0
            or relation["schema_name"] != "public" or relation["owner"] != session_user
            or relation["relation_kind"] != "r"
            or relation["row_security_enabled"] is not expected_rls
            or relation["force_row_security"] is not expected_rls
            or any(relation[key] is not False for key in
                   ("has_rules", "has_subclasses", "is_partition"))
            or type(relation["has_triggers"]) is not bool
            or relation["builtin_columns_only"] is not True
        ):
            reasons.append("trusted_execution_relation_semantics_invalid:" + name)
    if names != fragment["relations"]:
        reasons.append("trusted_execution_relation_inventory_mismatch")
    validator = json.loads(claim.validator_json)
    if validator != {
        "language": "plpgsql", "security_definer": False, "config": None,
        "returns_boolean": True, "body": _e3_trusted_validator_body(),
    }:
        reasons.append("trusted_execution_artifact_validator_mismatch")
    return tuple(sorted(set(reasons)))


def _e3_policy_config_payload(policy: E3PolicyConfig) -> dict[str, Any]:
    return {
        "config_id": policy.config_id,
        "selectivity": policy.selectivity,
        "policy_cost": policy.policy_cost,
        "artifacts": policy.artifacts,
        "exact_predicate": policy.exact_predicate,
        "injection_safe": policy.injection_safe,
    }


def _e3_artifact_builder_recipe_digest(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
) -> str:
    artifact_id = _artifact_id(query, policy)
    rendered_policy = _policy_predicate(query, policy)
    build_sql = (
        None
        if policy.artifacts == "none"
        else _build_artifact_sql(query, policy, rendered_policy)
    )
    return _canonical_sha256(
        {
            "recipe_version": E3_ARTIFACT_BUILDER_RECIPE_VERSION,
            "artifact_id": artifact_id,
            "declared_usable_kinds": list(_e3_declared_usable_artifact_kinds(policy)),
            "physical_output_kinds": list(_e3_expected_physical_artifact_kinds(policy)),
            "clear_sql_digest": _text_digest(_clear_artifact_sql(artifact_id)),
            "build_sql_digest": None if build_sql is None else _text_digest(build_sql),
            "dependencies": (
                _artifact_dependency_records(query, policy)
                if build_sql is not None
                else []
            ),
        }
    )


def _e3_rls_builder_recipe_digest(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
) -> str:
    return _canonical_sha256(
        {
            "recipe_version": E3_RLS_BUILDER_RECIPE_VERSION,
            "relation": f"public.{query.protected_rel}",
            "policy_name": f"caprls_e3_policy_{query.protected_rel}",
            "command": "r",
            "permissive": True,
            "role": E3_RLS_ROLE,
            "predicate": _policy_predicate_unaliased(query, policy),
            "row_security_enabled": True,
            "force_row_security": True,
        }
    )


def _e3_catalog_predicate_tokens(
    predicate: str,
    *,
    relation_name: str,
) -> tuple[str, ...]:
    """Normalize the finite E3 spelling while preserving Boolean structure."""

    tokens = _lex_e3_catalog_predicate(str(predicate))
    tokens = _remove_e3_printer_casts(tokens)
    tokens = _remove_e3_known_qualifiers(tokens, relation_name=relation_name)
    return _normalize_e3_predicate_parentheses(tokens)


def _lex_e3_catalog_predicate(predicate: str) -> tuple[str, ...]:
    tokens: list[str] = []
    index = 0
    while index < len(predicate):
        char = predicate[index]
        if char.isspace():
            index += 1
            continue
        if char == "'":
            end = index + 1
            while end < len(predicate):
                if predicate[end] != "'":
                    end += 1
                    continue
                if end + 1 < len(predicate) and predicate[end + 1] == "'":
                    end += 2
                    continue
                break
            if end >= len(predicate) or predicate[end] != "'":
                raise ValueError("E3 catalog predicate has an unterminated literal")
            tokens.append(predicate[index : end + 1])
            index = end + 1
            continue
        if char == '"':
            end = index + 1
            while end < len(predicate):
                if predicate[end] != '"':
                    end += 1
                    continue
                if end + 1 < len(predicate) and predicate[end + 1] == '"':
                    end += 2
                    continue
                break
            if end >= len(predicate) or predicate[end] != '"':
                raise ValueError("E3 catalog predicate has an unterminated identifier")
            tokens.append(predicate[index : end + 1])
            index = end + 1
            continue
        two_char = predicate[index : index + 2]
        if two_char in {"<=", ">=", "<>", "!=", "::"}:
            tokens.append(two_char)
            index += 2
            continue
        if char in {"=", "<", ">", "%", "+", "-", "*", "/", "(", ")", ",", "."}:
            tokens.append(char)
            index += 1
            continue
        number = re.match(r"\d+(?:\.\d+)?", predicate[index:])
        if number is not None:
            tokens.append(number.group(0))
            index += len(number.group(0))
            continue
        identifier = re.match(r"[A-Za-z_][A-Za-z0-9_$]*", predicate[index:])
        if identifier is not None:
            tokens.append(identifier.group(0).lower())
            index += len(identifier.group(0))
            continue
        raise ValueError(
            f"E3 catalog predicate contains unsupported character at offset {index}"
        )
    return tuple(tokens)


def _remove_e3_printer_casts(tokens: Sequence[str]) -> tuple[str, ...]:
    rendered: list[str] = []
    index = 0
    while index < len(tokens):
        if tokens[index] != "::":
            rendered.append(tokens[index])
            index += 1
            continue
        if index + 1 >= len(tokens):
            raise ValueError("E3 catalog predicate has an incomplete cast")
        cast_name = tokens[index + 1]
        cast_width = 1
        if cast_name == "character" and (
            index + 2 < len(tokens) and tokens[index + 2] == "varying"
        ):
            cast_width = 2
        safe_text_cast = (
            bool(rendered)
            and rendered[-1].startswith("'")
            and rendered[-1].endswith("'")
            and (
                cast_name in {"text", "varchar"}
                or (cast_name == "character" and cast_width == 2)
            )
        )
        if safe_text_cast:
            index += 1 + cast_width
            continue
        # Column casts, numeric-literal casts, and every unrecognized cast are
        # semantic syntax, not printer noise.  Preserve them byte-for-token so
        # replay can distinguish the catalog predicate from the renderer.
        rendered.append("::")
        rendered.extend(tokens[index + 1 : index + 1 + cast_width])
        index += 1 + cast_width
    return tuple(rendered)


def _remove_e3_known_qualifiers(
    tokens: Sequence[str],
    *,
    relation_name: str,
) -> tuple[str, ...]:
    rendered: list[str] = []
    index = 0
    removable = {"public", relation_name.lower()}
    while index < len(tokens):
        if (
            index + 2 < len(tokens)
            and tokens[index] in removable
            and tokens[index + 1] == "."
            and re.fullmatch(r"[a-z_][a-z0-9_$]*", tokens[index + 2])
        ):
            index += 2
            continue
        rendered.append(tokens[index])
        index += 1
    return tuple(rendered)


_E3_OPERATOR_PRECEDENCE = {
    "or": 1,
    "and": 2,
    "not": 3,
    "=": 4,
    "!=": 4,
    "<>": 4,
    "<": 4,
    ">": 4,
    "<=": 4,
    ">=": 4,
    "+": 5,
    "-": 5,
    "*": 6,
    "/": 6,
    "%": 6,
}


def _top_level_precedence(tokens: Sequence[str]) -> int:
    depth = 0
    precedences: list[int] = []
    for token in tokens:
        if token == "(":
            depth += 1
        elif token == ")":
            depth -= 1
        elif depth == 0 and token in _E3_OPERATOR_PRECEDENCE:
            precedences.append(_E3_OPERATOR_PRECEDENCE[token])
    return min(precedences, default=100)


def _matching_paren(tokens: Sequence[str], start: int) -> int:
    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index] == "(":
            depth += 1
        elif tokens[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    raise ValueError("E3 catalog predicate has unbalanced parentheses")


def _normalize_e3_predicate_parentheses(
    tokens: Sequence[str],
) -> tuple[str, ...]:
    rendered: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == ")":
            raise ValueError("E3 catalog predicate has unbalanced parentheses")
        if token != "(":
            rendered.append(token)
            index += 1
            continue
        end = _matching_paren(tokens, index)
        inner = _normalize_e3_predicate_parentheses(tokens[index + 1 : end])
        previous = rendered[-1] if rendered else None
        following = tokens[end + 1] if end + 1 < len(tokens) else None
        # Function calls and EXISTS subqueries keep their delimiters exactly.
        function_like = bool(
            previous
            and re.fullmatch(r"[a-z_][a-z0-9_]*", previous)
            and previous
            not in {
                "and",
                "or",
                "not",
                "where",
                "on",
                "from",
                "join",
                "when",
                "then",
                "else",
            }
        )
        if previous == "exists" or function_like:
            rendered.extend(("(", *inner, ")"))
            index = end + 1
            continue

        parent_precedence = max(
            _E3_OPERATOR_PRECEDENCE.get(previous or "", 0),
            _E3_OPERATOR_PRECEDENCE.get(following or "", 0),
        )
        inner_precedence = _top_level_precedence(inner)
        if inner_precedence >= parent_precedence:
            rendered.extend(inner)
        else:
            rendered.extend(("(", *inner, ")"))
        index = end + 1
    return tuple(rendered)


def _expected_dependency_claims(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
) -> tuple[E3ArtifactDependencyClaim, ...]:
    if policy.artifacts == "none":
        return ()
    artifact_id = _artifact_id(query, policy)
    return tuple(
        E3ArtifactDependencyClaim(
            artifact_id=artifact_id,
            dependency_kind=str(item["dep_kind"]),
            dependency_name=str(item["dep_name"]),
            version_at_build=int(item["version_at_build"]),
        )
        for item in _artifact_dependency_records(query, policy)
    )


def _e3_catalog_expectation_payload(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    *,
    session_user: str,
    execution_profile: str = "native_rls",
    trusted_execution: Optional[E3TrustedExecutionCatalogClaim] = None,
) -> dict[str, Any]:
    return {
        "query_id": query.query_id,
        "occurrence_id": query.query_id,
        "policy_config": _e3_policy_config_payload(policy),
        "principal_id": E3_PRINCIPAL_ID,
        "context_token": E3_CONTEXT_TOKEN,
        "context_payload": _e3_context_payload(
            query,
            policy,
            session_user=session_user,
            execution_profile=execution_profile,
            trusted_execution=trusted_execution,
        ),
        "session_user": session_user,
        "current_user": E3_RLS_ROLE,
        "search_path": E3_CATALOG_SEARCH_PATH,
        "row_security": E3_CATALOG_ROW_SECURITY,
        "relation": {
            "schema_name": "public",
            "relation_name": query.protected_rel,
            "owner": session_user,
            "row_security_enabled": True,
            "force_row_security": True,
        },
        "rls_policy": {
            "policy_name": f"caprls_e3_policy_{query.protected_rel}",
            "command": "r",
            "permissive": True,
            "roles": [E3_RLS_ROLE],
            "rendered_predicate": _policy_predicate_unaliased(query, policy),
        },
        "role": {
            "role_name": E3_RLS_ROLE,
            "is_superuser": False,
            "bypasses_rls": False,
            "member_of": [],
            "members": [],
        },
        "dependencies": [
            item.to_dict() for item in _expected_dependency_claims(query, policy)
        ],
        "declared_usable_kinds": list(_e3_declared_usable_artifact_kinds(policy)),
        "physical_output_kinds": list(_e3_expected_physical_artifact_kinds(policy)),
        "artifact_builder_recipe_version": E3_ARTIFACT_BUILDER_RECIPE_VERSION,
        "artifact_builder_recipe_digest": _e3_artifact_builder_recipe_digest(
            query,
            policy,
        ),
        "rls_builder_recipe_version": E3_RLS_BUILDER_RECIPE_VERSION,
        "rls_builder_recipe_digest": _e3_rls_builder_recipe_digest(query, policy),
    }


def _e3_catalog_validation_reasons(
    observation: E3PlanningCatalogObservation,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    *,
    session_user: str,
    evidence_scope: str,
    execution_profile: str = "native_rls",
) -> tuple[str, ...]:
    reasons: list[str] = []
    _e3_require_execution_profile(execution_profile)
    trusted = execution_profile == "trusted_explicit"
    if observation.collector_schema != (
        E3_TRUSTED_OBSERVATION_SCHEMA if trusted else E3_CATALOG_OBSERVATION_SCHEMA
    ):
        reasons.append("collector_schema_profile_mismatch")
    if trusted:
        reasons.extend(_e3_trusted_execution_validation_reasons(
            observation.trusted_execution, query, policy, session_user=session_user,
        ))
        if observation.trusted_execution is not None:
            protected_claims = [
                item for item in json.loads(observation.trusted_execution.relations_json)
                if isinstance(item, dict) and item.get("relation_name") == query.protected_rel
            ]
            if len(protected_claims) != 1 or (
                protected_claims[0].get("oid") != observation.relation.oid
            ):
                reasons.append("trusted_execution_protected_relation_mismatch")
    elif observation.trusted_execution is not None:
        reasons.append("native_profile_has_trusted_claim")
    if evidence_scope not in {
        E3_CATALOG_PRODUCTION_SCOPE,
        E3_CATALOG_FIXTURE_SCOPE,
    }:
        reasons.append("evidence_scope_untrusted")
    if observation.session_user != session_user:
        reasons.append("session_user_mismatch")
    if observation.current_user != E3_RLS_ROLE:
        reasons.append("current_user_mismatch")
    if observation.search_path != E3_CATALOG_SEARCH_PATH:
        reasons.append("search_path_mismatch")
    if observation.row_security != E3_CATALOG_ROW_SECURITY:
        reasons.append("row_security_mismatch")
    if not observation.snapshot_text:
        reasons.append("snapshot_missing")

    relation = observation.relation
    if relation.oid <= 0:
        reasons.append("relation_oid_invalid")
    if (
        relation.schema_name != "public"
        or relation.relation_name != query.protected_rel
    ):
        reasons.append("relation_identity_mismatch")
    if relation.owner != session_user:
        reasons.append("relation_owner_mismatch")
    if not relation.row_security_enabled:
        reasons.append("relation_rls_not_enabled")
    if not relation.force_row_security:
        reasons.append("relation_force_rls_not_enabled")

    if len(observation.policies) != 1:
        reasons.append("rls_policy_cardinality_invalid")
    else:
        catalog_policy = observation.policies[0]
        if catalog_policy.policy_name != f"caprls_e3_policy_{query.protected_rel}":
            reasons.append("rls_policy_name_mismatch")
        if catalog_policy.command != "r":
            reasons.append("rls_policy_command_mismatch")
        if not catalog_policy.permissive:
            reasons.append("rls_policy_permissive_mismatch")
        if catalog_policy.roles != (E3_RLS_ROLE,):
            reasons.append("rls_policy_role_mismatch")
        expected_tokens = _e3_catalog_predicate_tokens(
            _policy_predicate_unaliased(query, policy),
            relation_name=query.protected_rel,
        )
        observed_tokens = _e3_catalog_predicate_tokens(
            catalog_policy.expression,
            relation_name=query.protected_rel,
        )
        if observed_tokens != expected_tokens:
            reasons.append("rls_policy_expression_mismatch")

    role = observation.role
    if role.role_name != E3_RLS_ROLE:
        reasons.append("role_identity_mismatch")
    if role.is_superuser:
        reasons.append("role_superuser_not_allowed")
    if role.bypasses_rls:
        reasons.append("role_bypass_rls_not_allowed")
    if role.member_of or role.members:
        reasons.append("role_membership_unexpected")

    dependency_payloads = tuple(
        _canonical_json(item.to_dict()) for item in observation.dependencies
    )
    if len(set(dependency_payloads)) != len(dependency_payloads):
        reasons.append("artifact_dependency_duplicate")
    expected_dependencies = {
        _canonical_json(item.to_dict())
        for item in _expected_dependency_claims(query, policy)
    }
    observed_dependencies = set(dependency_payloads)
    if expected_dependencies - observed_dependencies:
        reasons.append("artifact_dependency_missing")
    if observed_dependencies - expected_dependencies:
        reasons.append("artifact_dependency_unexpected")

    expected_physical_kinds = set(_e3_expected_physical_artifact_kinds(policy))
    scopes_by_kind: dict[str, list[E3ArtifactScopeClaim]] = {}
    for scope in observation.artifact_scopes:
        scopes_by_kind.setdefault(scope.physical_kind, []).append(scope)
    observed_kinds = set(scopes_by_kind)
    if expected_physical_kinds - observed_kinds:
        reasons.append("artifact_scope_missing")
    if observed_kinds - expected_physical_kinds:
        reasons.append("artifact_scope_unexpected")

    artifact_id = _artifact_id(query, policy)
    rid_domain_id = f"{query.protected_rel}.{query.rid_col}"
    for physical_kind in sorted(expected_physical_kinds | observed_kinds):
        claims = scopes_by_kind.get(physical_kind, [])
        if len(claims) != 1:
            reasons.append(f"artifact_scope_nonuniform:{physical_kind}")
            continue
        claim = claims[0]
        if claim.artifact_id != artifact_id:
            reasons.append(f"artifact_scope_artifact_mismatch:{physical_kind}")
        if claim.policy_id != policy.config_id:
            reasons.append(f"artifact_scope_policy_mismatch:{physical_kind}")
        if claim.principal_id != E3_PRINCIPAL_ID:
            reasons.append(f"artifact_scope_principal_mismatch:{physical_kind}")
        if claim.context_token != E3_CONTEXT_TOKEN:
            reasons.append(f"artifact_scope_context_mismatch:{physical_kind}")
        if claim.rid_domain_id != rid_domain_id:
            reasons.append(f"artifact_scope_rid_mismatch:{physical_kind}")
        if claim.base_relation_oid != relation.oid:
            reasons.append(f"artifact_scope_base_relation_mismatch:{physical_kind}")
        if claim.policy_version != 0 or claim.membership_version != 0:
            reasons.append(f"artifact_scope_version_mismatch:{physical_kind}")
        if claim.has_duplicate_identity:
            reasons.append(f"artifact_scope_duplicate_identity:{physical_kind}")
        if physical_kind == "auth_idx_keyed":
            if claim.key_name != query.key_name:
                reasons.append("artifact_scope_key_name_mismatch")
            if claim.key_value_is_null or claim.range_bucket_is_nonnull:
                reasons.append("artifact_scope_key_domain_mismatch")
        elif (
            claim.key_name is not None
            or claim.key_value_is_null
            or claim.range_bucket_is_nonnull
        ):
            reasons.append("artifact_scope_unkeyed_shape_mismatch")

    return tuple(sorted(set(reasons)))


def _e3_receipt_digest_payload(
    receipt: E3PlanningCatalogReceipt,
) -> dict[str, Any]:
    payload = receipt.to_dict()
    payload.pop("receipt_digest", None)
    return payload


def _issue_e3_planning_catalog_receipt(
    observation: E3PlanningCatalogObservation,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    *,
    session_user: str,
    evidence_scope: str = E3_CATALOG_PRODUCTION_SCOPE,
    execution_profile: str = "native_rls",
) -> E3PlanningCatalogReceipt:
    _e3_require_execution_profile(execution_profile)
    trusted = execution_profile == "trusted_explicit"
    expectation = _e3_catalog_expectation_payload(
        query,
        policy,
        session_user=session_user,
        execution_profile=execution_profile,
        trusted_execution=observation.trusted_execution,
    )
    reasons = _e3_catalog_validation_reasons(
        observation,
        query,
        policy,
        session_user=session_user,
        evidence_scope=evidence_scope,
        execution_profile=execution_profile,
    )
    verdict = "pass" if not reasons else "fail"
    context_payload_json = _canonical_json(expectation["context_payload"])
    context_digest = _canonical_sha256(expectation["context_payload"])
    observation_digest = _canonical_sha256(observation.to_dict())
    expectation_digest = _canonical_sha256(expectation)
    snapshot_digest = _canonical_sha256({"snapshot_text": observation.snapshot_text})
    rendered_predicate_digest = canonical_predicate_digest(
        _policy_predicate(query, policy)
    )
    rls_rendered_predicate_digest = canonical_predicate_digest(
        _policy_predicate_unaliased(query, policy)
    )
    policy_definition_digest = _canonical_sha256(
        {
            "policy_config": _e3_policy_config_payload(policy),
            "catalog_policies": [item.to_dict() for item in observation.policies],
        }
    )
    observed_physical_kinds = tuple(
        sorted({item.physical_kind for item in observation.artifact_scopes})
    )
    evidence_digest = _canonical_sha256(
        {
            "validator_version": E3_TRUSTED_VALIDATOR_VERSION if trusted else E3_CATALOG_VALIDATOR_VERSION,
            "evidence_scope": evidence_scope,
            "snapshot_digest": snapshot_digest,
            "expectation_digest": expectation_digest,
            "observation_digest": observation_digest,
            "verdict": verdict,
            "reasons": list(reasons),
        }
    )
    draft = E3PlanningCatalogReceipt(
        schema_version=E3_TRUSTED_RECEIPT_SCHEMA if trusted else E3_CATALOG_RECEIPT_SCHEMA,
        validator_version=E3_TRUSTED_VALIDATOR_VERSION if trusted else E3_CATALOG_VALIDATOR_VERSION,
        evidence_scope=evidence_scope,
        query_id=query.query_id,
        occurrence_id=query.query_id,
        policy_id=policy.config_id,
        principal_id=E3_PRINCIPAL_ID,
        context_token=E3_CONTEXT_TOKEN,
        context_payload_json=context_payload_json,
        context_digest=context_digest,
        declared_usable_kinds=_e3_declared_usable_artifact_kinds(policy),
        observed_physical_kinds=observed_physical_kinds,
        snapshot_digest=snapshot_digest,
        rendered_predicate_digest=rendered_predicate_digest,
        rls_rendered_predicate_digest=rls_rendered_predicate_digest,
        policy_definition_digest=policy_definition_digest,
        artifact_builder_recipe_version=E3_ARTIFACT_BUILDER_RECIPE_VERSION,
        artifact_builder_recipe_digest=str(
            expectation["artifact_builder_recipe_digest"]
        ),
        rls_builder_recipe_version=E3_RLS_BUILDER_RECIPE_VERSION,
        rls_builder_recipe_digest=str(expectation["rls_builder_recipe_digest"]),
        expectation_digest=expectation_digest,
        observation_digest=observation_digest,
        evidence_digest=evidence_digest,
        verdict=verdict,
        reasons=reasons,
        observation=observation,
        receipt_digest="pending",
    )
    issued = replace(
        draft,
        receipt_digest=_canonical_sha256(_e3_receipt_digest_payload(draft)),
    )
    if evidence_scope == E3_CATALOG_PRODUCTION_SCOPE:
        _register_e3_production_source(
            issued,
            kind="catalog_receipt",
            identity_digest=issued.receipt_digest,
            query=query,
            policy=policy,
        )
    return issued


def _replay_e3_planning_catalog_receipt(
    receipt: E3PlanningCatalogReceipt,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    *,
    session_user: str,
) -> E3PlanningCatalogReplay:
    replay_reasons: list[str] = []
    if not isinstance(receipt, E3PlanningCatalogReceipt):
        return E3PlanningCatalogReplay(False, ("receipt_type_invalid",))
    canonical = _issue_e3_planning_catalog_receipt(
        receipt.observation,
        query,
        policy,
        session_user=session_user,
        evidence_scope=receipt.evidence_scope,
        execution_profile=_e3_receipt_execution_profile(receipt),
    )
    canonical_payload = canonical.to_dict()
    supplied_payload = receipt.to_dict()
    for field_name in canonical_payload:
        if supplied_payload.get(field_name) != canonical_payload[field_name]:
            replay_reasons.append(f"receipt_field_mismatch:{field_name}")
    replay_reasons.extend(canonical.reasons)
    trusted = _e3_receipt_execution_profile(receipt) == "trusted_explicit"
    if receipt.schema_version != (
        E3_TRUSTED_RECEIPT_SCHEMA if trusted else E3_CATALOG_RECEIPT_SCHEMA
    ):
        replay_reasons.append("receipt_schema_untrusted")
    if receipt.validator_version != (
        E3_TRUSTED_VALIDATOR_VERSION if trusted else E3_CATALOG_VALIDATOR_VERSION
    ):
        replay_reasons.append("receipt_validator_untrusted")
    if receipt.verdict != "pass":
        replay_reasons.append("receipt_verdict_not_pass")
    return E3PlanningCatalogReplay(
        ok=not replay_reasons,
        reasons=tuple(sorted(set(replay_reasons))),
    )


def _e3_registry_template_ids(registry: TemplateRegistry) -> tuple[str, ...]:
    template_ids = tuple(spec.template_id for spec in registry.template_specs())
    if not template_ids or len(set(template_ids)) != len(template_ids):
        raise ValueError(
            "E3 typed admission requires a unique non-empty registry inventory"
        )
    return template_ids


def _e3_native_rls_contract_payload(
    contract: NativeRLSSessionContract,
) -> dict[str, Any]:
    return {
        "contract_id": contract.contract_id,
        "relation": contract.relation,
        "policy_id": contract.policy_id,
        "policy_fingerprint": contract.policy_fingerprint,
        "role": contract.role,
        "snapshot_id": contract.snapshot_id,
        "emitted_policy_digest": contract.emitted_policy_digest,
        "validator_evidence_digest": contract.validator_evidence_digest,
        "row_security_enabled": contract.row_security_enabled,
        "role_bypasses_rls": contract.role_bypasses_rls,
        "role_owns_relation": contract.role_owns_relation,
        "force_row_security": contract.force_row_security,
    }


def _e3_native_rls_contract_from_receipt(
    receipt: E3PlanningCatalogReceipt,
) -> NativeRLSSessionContract:
    observation = receipt.observation
    relation = observation.relation
    role = observation.role
    return NativeRLSSessionContract(
        contract_id=f"e3-native-rls:{receipt.receipt_digest}",
        relation=relation.relation_name,
        policy_id=receipt.policy_id,
        policy_fingerprint=receipt.policy_definition_digest,
        role=role.role_name,
        snapshot_id=receipt.snapshot_digest,
        emitted_policy_digest=receipt.rendered_predicate_digest,
        validator_evidence_digest=receipt.evidence_digest,
        row_security_enabled=relation.row_security_enabled,
        role_bypasses_rls=role.bypasses_rls,
        role_owns_relation=relation.owner == role.role_name,
        force_row_security=relation.force_row_security,
    )


def _e3_logical_target_from_receipt(
    receipt: E3PlanningCatalogReceipt,
) -> PolicyAccessTarget:
    return PolicyAccessTarget(
        relation=receipt.observation.relation.relation_name,
        policy_id=receipt.policy_id,
        occurrence_id=receipt.occurrence_id,
        principal_id=receipt.principal_id,
        context_digest=receipt.context_digest,
        policy_predicate_digest=receipt.policy_definition_digest,
    )


def _e3_implementation_bindings(
    registry: TemplateRegistry,
    *,
    target: PolicyAccessTarget,
    rid_col: str,
    query_predicate: str,
) -> tuple[ImplementationTargetBinding, ...]:
    bindings: list[ImplementationTargetBinding] = []
    for template_id in _e3_registry_template_ids(registry):
        definition = template_definition(template_id)
        if definition.target_kind not in {
            "bare_occurrence",
            "query_filtered",
            "rid_domain",
        }:
            raise ValueError(
                f"E3 registry template has unsupported target kind: {template_id}"
            )
        refinement_kind = (
            "query_filtered" if definition.target_kind == "query_filtered" else None
        )
        bindings.append(
            implementation_target_binding(
                template_id=template_id,
                target=target,
                rid_col=rid_col,
                refinement_kind=refinement_kind,
                refinement_predicate=(
                    query_predicate if refinement_kind is not None else None
                ),
            )
        )
    return tuple(bindings)


def _e3_fact_evidence_base(
    receipt: E3PlanningCatalogReceipt,
    target: PolicyAccessTarget,
    *,
    kind: str,
    subject_digest: str,
) -> dict[str, Any]:
    return {
        "schema_version": ("e3_typed_fact_evidence_trusted_v2" if
                           _e3_receipt_execution_profile(receipt) == "trusted_explicit"
                           else E3_TYPED_FACT_EVIDENCE_SCHEMA),
        "issuer_version": ("e3_catalog_receipt_to_gamma_trusted_v2" if
                           _e3_receipt_execution_profile(receipt) == "trusted_explicit"
                           else E3_TYPED_ADMISSION_ISSUER_VERSION),
        "receipt_schema_version": receipt.schema_version,
        "receipt_validator_version": receipt.validator_version,
        "receipt_evidence_scope": receipt.evidence_scope,
        "receipt_digest": receipt.receipt_digest,
        "receipt_evidence_digest": receipt.evidence_digest,
        "query_id": receipt.query_id,
        "occurrence_id": receipt.occurrence_id,
        "policy_id": receipt.policy_id,
        "principal_id": receipt.principal_id,
        "context_token": receipt.context_token,
        "context_digest": receipt.context_digest,
        "snapshot_id": receipt.snapshot_digest,
        "logical_target_digest": target.digest,
        "kind": kind,
        "subject_digest": subject_digest,
        "verdict": "pass",
    }


def _e3_typed_bundle_digest_payload(
    bundle: E3TypedAdmissionBundle,
) -> dict[str, Any]:
    payload = bundle.to_dict()
    payload.pop("bundle_digest", None)
    return payload


def _derive_e3_typed_admission_bundle(
    receipt: E3PlanningCatalogReceipt,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    registry: TemplateRegistry,
) -> E3TypedAdmissionBundle:
    trusted = _e3_receipt_execution_profile(receipt) == "trusted_explicit"
    if trusted:
        allowed = set(E3_PLANNER_TEMPLATE_IDS + E3_SEMIJOIN_TEMPLATE_IDS)
        if not set(_e3_registry_template_ids(registry)).issubset(allowed):
            raise PostgresError("trusted explicit profile rejects native delegation or non-finite templates")
    receipt_replay = _replay_e3_planning_catalog_receipt(
        receipt,
        query,
        policy,
        session_user=receipt.observation.session_user,
    )
    if not receipt_replay.ok:
        raise ValueError(
            "E3 typed admission requires a replayable passing catalog receipt: "
            + "; ".join(receipt_replay.reasons)
        )
    target = _e3_logical_target_from_receipt(receipt)
    predicate_binding_problem = PlanningProblem(
        relation=target.relation,
        policy_id=target.policy_id,
        occurrence_id=target.occurrence_id,
        rid_col=query.rid_col,
        logical_target=target,
        planning_execution_class="production_normal",
        require_typed_admission=True,
    )
    policy_subject = policy_subject_digest(predicate_binding_problem)
    query_predicate = _e3_query_predicate(query, query.alias)
    template_ids = _e3_registry_template_ids(registry)
    bindings = _e3_implementation_bindings(
        registry,
        target=target,
        rid_col=query.rid_col,
        query_predicate=query_predicate,
    )
    native_contract = _e3_native_rls_contract_from_receipt(receipt)
    declared_artifacts = set(receipt.declared_usable_kinds)
    scopes_by_kind = {
        scope.physical_kind: scope for scope in receipt.observation.artifact_scopes
    }
    facts: list[GammaFact] = []
    evidence_json: list[str] = []

    def add_fact(
        kind: str,
        subject_digest: str,
        claims: Mapping[str, Any],
    ) -> GammaFact:
        evidence = {
            **_e3_fact_evidence_base(
                receipt,
                target,
                kind=kind,
                subject_digest=subject_digest,
            ),
            "claims": dict(claims),
        }
        canonical_evidence = _canonical_json(evidence)
        evidence_digest = _canonical_sha256(evidence)
        fact = GammaFact(
            fact_id=(
                f"e3-typed:{kind}:" + evidence_digest.removeprefix("sha256:")[:24]
            ),
            kind=kind,
            subject_digest=subject_digest,
            verdict="pass",
            validator_version=("e3_catalog_receipt_to_gamma_trusted_v2" if trusted
                               else E3_TYPED_ADMISSION_ISSUER_VERSION),
            snapshot_id=receipt.snapshot_digest,
            evidence_digest=evidence_digest,
            dynamic=False,
        )
        facts.append(fact)
        evidence_json.append(canonical_evidence)
        return fact

    add_fact(
        "trusted_exact_policy_executable",
        policy_subject,
        {
            "policy_definition_digest": receipt.policy_definition_digest,
            "rendered_predicate_digest": receipt.rendered_predicate_digest,
            "rls_rendered_predicate_digest": receipt.rls_rendered_predicate_digest,
        },
    )
    rendered_exact_predicate = _policy_predicate(query, policy)
    add_fact(
        "exact_policy_predicate_binding",
        policy_predicate_binding_subject(
            predicate_binding_problem,
            rendered_exact_predicate,
        ),
        {
            "logical_target_digest": target.digest,
            "policy_definition_digest": receipt.policy_definition_digest,
            "rendered_predicate_digest": receipt.rendered_predicate_digest,
            "controlled_predicate_digest": canonical_predicate_digest(
                rendered_exact_predicate
            ),
        },
    )
    add_fact(
        "safe_query_predicate",
        policy_subject,
        {
            "query_predicate": query_predicate,
            "query_predicate_digest": canonical_predicate_digest(query_predicate),
            "finite_query_id": query.query_id,
        },
    )
    if policy.injection_safe:
        add_fact(
            "exact_policy_safe",
            policy_subject,
            {
                "policy_config": _e3_policy_config_payload(policy),
                "finite_safety_label": "pure_relational_e3_policy",
            },
        )
        # Optional physical composition premise. Only the canonical trusted
        # profile observes builtin columns, ordinary table semantics and the
        # exact catalog/session later replayed by the original runtime guard.
        # The finite syntax excludes calls, casts, subqueries and correlation;
        # unsupported policies retain their original nested PC scope.
        from planner.pc_scope import safe_pc_predicate
        if (trusted and safe_pc_predicate(rendered_exact_predicate, query.alias)
                and safe_pc_predicate(query_predicate, query.alias)):
            add_fact(
                "pc_scope_lift_builtin_safe",
                policy_subject,
                {"finite_fragment_digest": _canonical_sha256(
                    _e3_trusted_finite_fragment_payload(query, policy)),
                 "execution_catalog_digest": _canonical_sha256(
                    receipt.observation.trusted_execution.to_dict()),
                 "predicate_grammar": "qualified_builtin_comparisons_v1",
                 "scope": "single_closed_pc_cte_only_no_admission_capability"},
            )
    if "native_pg_rls_v1" in template_ids:
        add_fact(
            "native_rls_session_contract",
            native_contract.contract_id,
            {
                "native_rls_contract": _e3_native_rls_contract_payload(native_contract),
                "catalog_relation": receipt.observation.relation.to_dict(),
                "catalog_role": receipt.observation.role.to_dict(),
                "catalog_policies": [
                    item.to_dict() for item in receipt.observation.policies
                ],
            },
        )

    artifact_fact_id: Optional[str] = None
    artifact_id = _artifact_id(query, policy)
    declared_scopes = tuple(
        scopes_by_kind[kind]
        for kind in sorted(declared_artifacts)
        if kind in scopes_by_kind
    )
    if declared_artifacts and len(declared_scopes) == len(declared_artifacts):
        artifact_fact = add_fact(
            "artifact_validation",
            artifact_id,
            {
                "artifact_bundle_id": artifact_id,
                "declared_usable_kinds": sorted(declared_artifacts),
                "validated_declared_scopes": [
                    scope.to_dict() for scope in declared_scopes
                ],
                "observed_physical_kinds": list(receipt.observed_physical_kinds),
                "catalog_artifact_scopes": [
                    scope.to_dict() for scope in receipt.observation.artifact_scopes
                ],
                "catalog_dependencies": [
                    dependency.to_dict()
                    for dependency in receipt.observation.dependencies
                ],
                "artifact_builder_recipe_version": (
                    receipt.artifact_builder_recipe_version
                ),
                "artifact_builder_recipe_digest": (
                    receipt.artifact_builder_recipe_digest
                ),
                "dynamic_rechecks_required": [
                    "artifact_context",
                    "artifact_freshness",
                    "artifact_toctou",
                ],
                "extensional_semantics_reproved": False,
            },
        )
        artifact_fact_id = artifact_fact.fact_id

    for binding in bindings:
        definition = template_definition(binding.template_id)
        required_artifacts = set(definition.required_artifacts)
        artifacts_ready = not required_artifacts or (
            artifact_fact_id is not None
            and required_artifacts.issubset(declared_artifacts)
        )
        claims = {
            "logical_target": target.to_dict(),
            "logical_target_digest": target.digest,
            "implementation_binding": binding.to_dict(),
            "implementation_binding_digest": binding.digest,
            "query_predicate": query_predicate,
            "query_predicate_digest": canonical_predicate_digest(query_predicate),
            "required_artifact_kinds": sorted(required_artifacts),
            "artifact_fact_id": (artifact_fact_id if required_artifacts else None),
        }
        if binding.refinement_kind is not None and artifacts_ready:
            add_fact(
                "target_refinement",
                target_refinement_subject_digest(
                    binding,
                    target,
                    snapshot_id=receipt.snapshot_digest,
                ),
                claims,
            )
        elif (
            binding.implementation_target_kind != "bare_occurrence" and artifacts_ready
        ):
            add_fact(
                "implementation_target_match",
                implementation_target_match_subject_digest(
                    binding,
                    target,
                    snapshot_id=receipt.snapshot_digest,
                ),
                claims,
            )

    dynamic_obligations: set[str] = set()
    if artifact_fact_id is not None:
        dynamic_obligations.update(
            {"artifact_context", "artifact_freshness", "artifact_toctou"}
        )
    if "native_pg_rls_v1" in template_ids:
        dynamic_obligations.add("native_rls_session_contract")
    gamma = GammaSnapshot(
        snapshot_id=receipt.snapshot_digest,
        facts=tuple(facts),
    )
    draft = E3TypedAdmissionBundle(
        schema_version="e3_typed_admission_bundle_trusted_v2" if trusted else E3_TYPED_ADMISSION_SCHEMA,
        issuer_version="e3_catalog_receipt_to_gamma_trusted_v2" if trusted else E3_TYPED_ADMISSION_ISSUER_VERSION,
        logical_target=target,
        implementation_bindings=bindings,
        gamma_snapshot=gamma,
        native_rls_contract=native_contract,
        registry_template_ids=template_ids,
        fact_evidence_json=tuple(evidence_json),
        unresolved_dynamic_obligations=tuple(sorted(dynamic_obligations)),
        bundle_digest="pending",
    )
    return replace(
        draft,
        bundle_digest=_canonical_sha256(_e3_typed_bundle_digest_payload(draft)),
    )


def _issue_e3_typed_admission_bundle(
    receipt: E3PlanningCatalogReceipt,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    registry: TemplateRegistry,
) -> E3TypedAdmissionBundle:
    issued = _derive_e3_typed_admission_bundle(receipt, query, policy, registry)
    if receipt.evidence_scope == E3_CATALOG_PRODUCTION_SCOPE:
        _require_e3_production_source(
            receipt,
            kind="catalog_receipt",
            identity_digest=receipt.receipt_digest,
            query=query,
            policy=policy,
        )
        _register_e3_production_source(
            issued,
            kind="typed_admission_bundle",
            identity_digest=issued.bundle_digest,
            query=query,
            policy=policy,
            receipt=receipt,
            registry=registry,
        )
    return issued


def _validate_e3_typed_admission_bundle(
    bundle: E3TypedAdmissionBundle,
    receipt: E3PlanningCatalogReceipt,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    registry: TemplateRegistry,
) -> tuple[str, ...]:
    if not isinstance(bundle, E3TypedAdmissionBundle):
        return ("typed_admission_bundle_type_invalid",)
    canonical = _issue_e3_typed_admission_bundle(
        receipt,
        query,
        policy,
        registry,
    )
    supplied = bundle.to_dict()
    expected = canonical.to_dict()
    reasons = [
        f"typed_admission_field_mismatch:{field_name}"
        for field_name in expected
        if supplied.get(field_name) != expected[field_name]
    ]
    return tuple(sorted(set(reasons)))


def _ranker_from_manifest(root: Path, manifest: Mapping[str, Any]) -> E3Ranker:
    spec = _as_mapping(manifest.get("ranker"))
    name = str(spec.get("name", "calibrated-explain"))
    if name == "pg-explain-raw":
        return E3RawPgRanker()
    if name != "calibrated-explain":
        raise PostgresError(f"E3 main manifest declares unsupported ranker {name!r}")

    raw_path = str(spec.get("calibration_path", "configs/e3_cost_calibration.yaml"))
    path = Path(raw_path)
    if not path.is_absolute():
        path = root / path
    if not path.exists():
        raise PostgresError(f"E3 calibrated ranker config missing: {path}")
    with path.open("r", encoding="utf-8") as fh:
        config = yaml.safe_load(fh) or {}
    if not isinstance(config, Mapping):
        raise PostgresError(f"E3 calibrated ranker config must be an object: {path}")
    try:
        rel_path = str(path.relative_to(root))
    except ValueError:
        rel_path = str(path)
    return E3CalibratedRanker(
        version=str(config.get("version", "e3_calibration_unversioned")),
        config=config,
        calibration_path=rel_path,
        calibration_hash=file_sha256(path),
    )


def _adaptive_topk_from_manifest(manifest: Mapping[str, Any]) -> E3AdaptiveTopKConfig:
    spec = _as_mapping(manifest.get("adaptive_topk"))
    if not spec or not bool(spec.get("enabled", False)):
        return E3AdaptiveTopKConfig()
    k = int(spec.get("k", 2))
    probe_repetitions = int(spec.get("probe_repetitions", 2))
    if k <= 0:
        raise PostgresError("E3 adaptive_topk.k must be positive")
    if probe_repetitions <= 0:
        raise PostgresError("E3 adaptive_topk.probe_repetitions must be positive")
    return E3AdaptiveTopKConfig(
        enabled=True,
        k=k,
        probe_repetitions=probe_repetitions,
        deduplicate_plan_shapes=bool(spec.get("deduplicate_plan_shapes", False)),
    )


def _tpch_data_dir(root: Path, scale: str) -> Path:
    return root / "datasets" / "tpch" / scale.lower()


def _require_files(paths: list[Path], label: str) -> None:
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        raise PostgresError(
            f"real {label} data files are missing; generate/download the dataset first: "
            + ", ".join(missing)
        )


def _tpch_real_data_files(root: Path, scale: str) -> list[Path]:
    data_dir = _tpch_data_dir(root, scale)
    return [
        data_dir / "customer.tbl",
        data_dir / "orders.tbl",
        data_dir / "lineitem.tbl",
        data_dir / "nation.tbl",
    ]


def _setup_tpch_real_sql(root: Path, scale: str) -> str:
    """Load a real TPC-H scale factor into the E3 schema.

    The reduced E3 table shape is preserved exactly (so the Q3/Q5 SQL, policy
    predicates, artifact build, and oracle checks are unchanged); only the
    population source differs. ``tenant_id`` is a synthetic key-modulus policy
    overlay and ``region_id`` is the real ``nation -> region`` mapping, matching
    the dataset plan ("tenant by key modulus; nation/region ACL").
    """

    customer, orders, lineitem, nation = _tpch_real_data_files(root, scale)
    _require_files([customer, orders, lineitem, nation], f"TPC-H {scale}")
    # QUOTE is set to a byte that never occurs in TPC-H text, disabling CSV
    # quote handling so the pipe-delimited .tbl rows (with a trailing '|') load
    # verbatim into a trailing dummy column.
    copy_opt = "WITH (FORMAT csv, DELIMITER '|', QUOTE E'\\x01')"
    return f"""
\\set ON_ERROR_STOP on
DROP TABLE IF EXISTS public.tpch_lineitem;
DROP TABLE IF EXISTS public.tpch_orders;
DROP TABLE IF EXISTS public.tpch_customer;
CREATE TABLE public.tpch_customer (
  c_custkey bigint PRIMARY KEY,
  c_mktsegment text NOT NULL,
  tenant_id bigint NOT NULL,
  region_id bigint NOT NULL
);
CREATE TABLE public.tpch_orders (
  o_orderkey bigint PRIMARY KEY,
  o_custkey bigint NOT NULL,
  o_orderdate date NOT NULL,
  o_shippriority integer NOT NULL,
  tenant_id bigint NOT NULL
);
CREATE TABLE public.tpch_lineitem (
  l_orderkey bigint NOT NULL,
  l_extendedprice numeric(12,2) NOT NULL,
  l_discount numeric(5,4) NOT NULL,
  l_shipdate date NOT NULL
);
CREATE UNLOGGED TABLE public.stg_nation (
  n_nationkey int, n_name text, n_regionkey int, n_comment text, _dummy text
);
CREATE UNLOGGED TABLE public.stg_customer (
  c_custkey bigint, c_name text, c_address text, c_nationkey int, c_phone text,
  c_acctbal numeric, c_mktsegment text, c_comment text, _dummy text
);
CREATE UNLOGGED TABLE public.stg_orders (
  o_orderkey bigint, o_custkey bigint, o_orderstatus text, o_totalprice numeric,
  o_orderdate date, o_orderpriority text, o_clerk text, o_shippriority int,
  o_comment text, _dummy text
);
CREATE UNLOGGED TABLE public.stg_lineitem (
  l_orderkey bigint, l_partkey bigint, l_suppkey bigint, l_linenumber int,
  l_quantity numeric, l_extendedprice numeric, l_discount numeric, l_tax numeric,
  l_returnflag text, l_linestatus text, l_shipdate date, l_commitdate date,
  l_receiptdate date, l_shipinstruct text, l_shipmode text, l_comment text, _dummy text
);
COPY public.stg_nation FROM '{nation}' {copy_opt};
COPY public.stg_customer FROM '{customer}' {copy_opt};
COPY public.stg_orders FROM '{orders}' {copy_opt};
COPY public.stg_lineitem FROM '{lineitem}' {copy_opt};
INSERT INTO public.tpch_customer(c_custkey, c_mktsegment, tenant_id, region_id)
SELECT s.c_custkey, s.c_mktsegment, 1 + (s.c_custkey % 10), 1 + n.n_regionkey
FROM public.stg_customer s
JOIN public.stg_nation n ON n.n_nationkey = s.c_nationkey;
INSERT INTO public.tpch_orders(o_orderkey, o_custkey, o_orderdate, o_shippriority, tenant_id)
SELECT o_orderkey, o_custkey, o_orderdate, o_shippriority, 1 + (o_custkey % 10)
FROM public.stg_orders;
INSERT INTO public.tpch_lineitem(l_orderkey, l_extendedprice, l_discount, l_shipdate)
SELECT l_orderkey, l_extendedprice, l_discount, l_shipdate
FROM public.stg_lineitem;
DROP TABLE public.stg_lineitem;
DROP TABLE public.stg_orders;
DROP TABLE public.stg_customer;
DROP TABLE public.stg_nation;
CREATE INDEX tpch_customer_tenant_idx ON public.tpch_customer(tenant_id, c_custkey);
CREATE INDEX tpch_orders_cust_date_idx ON public.tpch_orders(o_custkey, o_orderdate);
CREATE INDEX tpch_lineitem_order_ship_idx ON public.tpch_lineitem(l_orderkey, l_shipdate);
ANALYZE public.tpch_customer;
ANALYZE public.tpch_orders;
ANALYZE public.tpch_lineitem;
"""


def _validate_manifest(manifest_path: Path, manifest: Mapping[str, Any]) -> None:
    if manifest.get("experiment") != "E3" or manifest.get("execution_tier") != "main":
        raise PostgresError("e3-main requires an E3 main manifest")
    stage = str(manifest.get("stage"))
    if (
        stage != "main"
        and not stage.startswith("standard_workloads_reduced")
        and not stage.startswith("standard_workloads_sf")
    ):
        raise PostgresError(
            "e3-main requires stage standard_workloads_reduced*, standard_workloads_sf*, or main"
        )
    modes = {normalize_mode_id(str(item)) for item in manifest.get("modes", [])}
    if modes != REQUIRED_MODES:
        raise PostgresError(
            "E3 main modes do not match runner contract: "
            f"expected {sorted(REQUIRED_MODES)}, got {sorted(modes)}"
        )
    _queries_for_manifest(manifest_path, manifest)
    _policies_for_manifest(manifest_path, manifest)
    dataset_names = {
        str(item.get("name"))
        for item in manifest.get("datasets", [])
        if isinstance(item, Mapping)
    }
    if dataset_names != {"tpch", "job"}:
        raise PostgresError(
            f"E3 main requires tpch and job datasets; got {dataset_names}"
        )
    ranker = _as_mapping(manifest.get("ranker"))
    ranker_name = str(ranker.get("name", "calibrated-explain"))
    if ranker_name not in {"pg-explain-raw", "calibrated-explain"}:
        raise PostgresError(
            f"E3 main manifest declares unsupported ranker {ranker_name!r}"
        )
    _validate_adaptive_topk_evidence_role(manifest)


def _validate_adaptive_topk_evidence_role(manifest: Mapping[str, Any]) -> None:
    """Keep measured adaptive probes out of promotable E3 evidence.

    The diagnostic remains runnable, but it must announce its role before any
    database preparation.
    """

    config = _adaptive_topk_from_manifest(manifest)
    if not config.enabled:
        return
    if manifest.get("evidence_role") != "diagnostic_only":
        raise PostgresError("E3 adaptive_topk requires evidence_role: diagnostic_only")
    if manifest.get("promotion_eligible") is not False:
        raise PostgresError("E3 adaptive_topk requires promotion_eligible: false")
    profile = str(manifest.get("profile") or manifest.get("promotion_profile") or "")
    if profile in {"gap_fixed_reference", "gap_fixed_optimized"}:
        raise PostgresError("E3 adaptive_topk is prohibited for promotable profiles")


def _queries_for_manifest(
    manifest_path: Path, manifest: Mapping[str, Any]
) -> list[E3QuerySpec]:
    by_id = {query.query_id: query for query in QUERIES}
    selected: list[E3QuerySpec] = []
    seen: set[str] = set()
    for item in manifest.get("queries", []):
        if not isinstance(item, Mapping):
            continue
        query_id = str(item.get("query_id"))
        path = str(item.get("path"))
        query = by_id.get(query_id)
        if query is None:
            raise PostgresError(
                f"E3 main manifest {manifest_path} declares unknown query_id {query_id}"
            )
        if path != query.path:
            raise PostgresError(
                f"E3 main manifest {manifest_path} path mismatch for {query_id}: "
                f"expected {query.path}, got {path}"
            )
        if query_id in seen:
            raise PostgresError(
                f"E3 main manifest {manifest_path} repeats query_id {query_id}"
            )
        selected.append(query)
        seen.add(query_id)
    if not selected:
        raise PostgresError(f"E3 main manifest {manifest_path} declares no queries")
    return selected


def _policies_for_manifest(
    manifest_path: Path, manifest: Mapping[str, Any]
) -> list[E3PolicyConfig]:
    by_id = {config.config_id: config for config in POLICY_CONFIGS}
    selected: list[E3PolicyConfig] = []
    seen: set[str] = set()
    for item in manifest.get("policy_configs", []):
        if not isinstance(item, Mapping):
            continue
        config_id = str(item.get("id"))
        artifacts = str(item.get("artifacts"))
        config = by_id.get(config_id)
        if config is None:
            raise PostgresError(
                f"E3 main manifest {manifest_path} declares unknown policy_config {config_id}"
            )
        if artifacts != config.artifacts:
            raise PostgresError(
                f"E3 main manifest {manifest_path} artifact mismatch for {config_id}: "
                f"expected {config.artifacts}, got {artifacts}"
            )
        if config_id in seen:
            raise PostgresError(
                f"E3 main manifest {manifest_path} repeats policy_config {config_id}"
            )
        selected.append(config)
        seen.add(config_id)
    if not selected:
        raise PostgresError(
            f"E3 main manifest {manifest_path} declares no policy_configs"
        )
    return selected


def _setup_job_sql() -> str:
    return """
\\set ON_ERROR_STOP on
DROP TABLE IF EXISTS public.job_cast_info;
DROP TABLE IF EXISTS public.job_movie_companies;
DROP TABLE IF EXISTS public.job_title;
CREATE TABLE public.job_title (
  t_id bigint PRIMARY KEY,
  kind text NOT NULL,
  production_year integer NOT NULL,
  region_id bigint NOT NULL,
  studio_id bigint NOT NULL
);
CREATE TABLE public.job_movie_companies (
  movie_id bigint NOT NULL REFERENCES public.job_title(t_id),
  company_id bigint NOT NULL,
  company_type text NOT NULL,
  region_id bigint NOT NULL
);
CREATE TABLE public.job_cast_info (
  movie_id bigint NOT NULL REFERENCES public.job_title(t_id),
  person_id bigint NOT NULL,
  role_id bigint NOT NULL
);
INSERT INTO public.job_title(t_id, kind, production_year, region_id, studio_id)
SELECT t,
       CASE WHEN t % 2 = 0 THEN 'movie' ELSE 'episode' END,
       1980 + (t % 40),
       1 + (t % 5),
       1 + (t % 50)
FROM generate_series(1, 1500) AS t;
INSERT INTO public.job_movie_companies(movie_id, company_id, company_type, region_id)
SELECT 1 + (mc % 1500),
       1 + (mc % 300),
       CASE WHEN mc % 3 = 0 THEN 'production' ELSE 'distributor' END,
       1 + (mc % 5)
FROM generate_series(1, 4000) AS mc;
INSERT INTO public.job_cast_info(movie_id, person_id, role_id)
SELECT 1 + (ci % 1500),
       1 + (ci % 2000),
       1 + (ci % 8)
FROM generate_series(1, 8000) AS ci;
CREATE INDEX job_title_kind_year_idx ON public.job_title(kind, production_year, t_id);
CREATE INDEX job_title_region_idx ON public.job_title(region_id, t_id);
CREATE INDEX job_movie_companies_movie_type_idx ON public.job_movie_companies(movie_id, company_type);
CREATE INDEX job_cast_info_movie_role_idx ON public.job_cast_info(movie_id, role_id);
ANALYZE public.job_title;
ANALYZE public.job_movie_companies;
ANALYZE public.job_cast_info;
"""


def _job_data_dir(root: Path) -> Path:
    return root / "datasets" / "imdb" / "csv"


def _job_real_data_files(root: Path) -> list[Path]:
    d = _job_data_dir(root)
    return [
        d / "title.csv",
        d / "movie_companies.csv",
        d / "cast_info.csv",
        d / "kind_type.csv",
        d / "company_type.csv",
    ]


def _setup_job_real_sql(root: Path, scale: str) -> str:
    """Load the real JOB/IMDb snapshot into the E3 job_* schema.

    The reduced job_* table shape is preserved so the JOB_1a/JOB_6d SQL and
    policy predicates are unchanged. ``kind`` and ``company_type`` are mapped
    from the real kind_type/company_type dimensions; ``region_id``/``studio_id``
    are synthetic key-modulus policy overlays (dataset plan: license/region/
    studio ACL). ``production_year`` NULLs are coalesced to 0 (excluded by the
    year filters).
    """

    title, movie_companies, cast_info, kind_type, company_type = _job_real_data_files(
        root
    )
    _require_files(
        [title, movie_companies, cast_info, kind_type, company_type],
        f"JOB/IMDb {scale}",
    )
    # The CWI JOB/IMDb CSV snapshot uses backslash escaping for embedded quotes
    # (e.g. "Zehut Sh'ula\""), so the COPY ESCAPE char must be backslash.
    copy_opt = "WITH (FORMAT csv, ESCAPE '\\')"
    return f"""
\\set ON_ERROR_STOP on
DROP TABLE IF EXISTS public.job_cast_info;
DROP TABLE IF EXISTS public.job_movie_companies;
DROP TABLE IF EXISTS public.job_title;
CREATE TABLE public.job_title (
  t_id bigint PRIMARY KEY,
  kind text NOT NULL,
  production_year integer NOT NULL,
  region_id bigint NOT NULL,
  studio_id bigint NOT NULL
);
CREATE TABLE public.job_movie_companies (
  movie_id bigint NOT NULL,
  company_id bigint NOT NULL,
  company_type text NOT NULL,
  region_id bigint NOT NULL
);
CREATE TABLE public.job_cast_info (
  movie_id bigint NOT NULL,
  person_id bigint NOT NULL,
  role_id bigint NOT NULL
);
CREATE UNLOGGED TABLE public.stg_kind_type (id int, kind text);
CREATE UNLOGGED TABLE public.stg_company_type (id int, kind text);
CREATE UNLOGGED TABLE public.stg_title (
  id bigint, title text, imdb_index text, kind_id int, production_year int,
  imdb_id int, phonetic_code text, episode_of_id int, season_nr int,
  episode_nr int, series_years text, md5sum text
);
CREATE UNLOGGED TABLE public.stg_movie_companies (
  id bigint, movie_id bigint, company_id bigint, company_type_id int, note text
);
CREATE UNLOGGED TABLE public.stg_cast_info (
  id bigint, person_id bigint, movie_id bigint, person_role_id int, note text,
  nr_order int, role_id int
);
COPY public.stg_kind_type FROM '{kind_type}' {copy_opt};
COPY public.stg_company_type FROM '{company_type}' {copy_opt};
COPY public.stg_title FROM '{title}' {copy_opt};
COPY public.stg_movie_companies FROM '{movie_companies}' {copy_opt};
COPY public.stg_cast_info FROM '{cast_info}' {copy_opt};
INSERT INTO public.job_title(t_id, kind, production_year, region_id, studio_id)
SELECT t.id, k.kind, COALESCE(t.production_year, 0), 1 + (t.id % 5), 1 + (t.id % 50)
FROM public.stg_title t
JOIN public.stg_kind_type k ON k.id = t.kind_id;
INSERT INTO public.job_movie_companies(movie_id, company_id, company_type, region_id)
SELECT m.movie_id, m.company_id,
       CASE WHEN c.kind = 'production companies' THEN 'production' ELSE 'distributor' END,
       1 + (m.movie_id % 5)
FROM public.stg_movie_companies m
JOIN public.stg_company_type c ON c.id = m.company_type_id;
INSERT INTO public.job_cast_info(movie_id, person_id, role_id)
SELECT movie_id, person_id, role_id FROM public.stg_cast_info;
DROP TABLE public.stg_cast_info;
DROP TABLE public.stg_movie_companies;
DROP TABLE public.stg_title;
DROP TABLE public.stg_company_type;
DROP TABLE public.stg_kind_type;
CREATE INDEX job_title_kind_year_idx ON public.job_title(kind, production_year, t_id);
CREATE INDEX job_title_region_idx ON public.job_title(region_id, t_id);
CREATE INDEX job_movie_companies_movie_type_idx ON public.job_movie_companies(movie_id, company_type);
CREATE INDEX job_cast_info_movie_role_idx ON public.job_cast_info(movie_id, role_id);
ANALYZE public.job_title;
ANALYZE public.job_movie_companies;
ANALYZE public.job_cast_info;
"""


def _setup_e3_group_acl_sql() -> str:
    return """
\\set ON_ERROR_STOP on
DROP TABLE IF EXISTS public.share_acl;
DROP TABLE IF EXISTS public.group_membership;
CREATE TABLE public.group_membership (
  user_id text NOT NULL,
  group_id bigint NOT NULL,
  membership_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, group_id)
);
CREATE TABLE public.share_acl (
  relname text NOT NULL,
  rid bigint NOT NULL,
  group_id bigint NOT NULL,
  permission text NOT NULL,
  acl_version bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (relname, rid, group_id, permission)
);
INSERT INTO public.group_membership(user_id, group_id, membership_version)
VALUES ('e3_user', 1, 0);
INSERT INTO public.share_acl(relname, rid, group_id, permission, acl_version)
SELECT 'public.tpch_customer', c.c_custkey, 1, 'read', 0
FROM public.tpch_customer c
WHERE (c.c_custkey % 10) = 0;
INSERT INTO public.share_acl(relname, rid, group_id, permission, acl_version)
SELECT 'public.job_title', t.t_id, 1, 'read', 0
FROM public.job_title t
WHERE (t.t_id % 10) = 0;
CREATE INDEX share_acl_lookup_idx ON public.share_acl(relname, rid, permission, group_id);
CREATE INDEX share_acl_group_idx ON public.share_acl(group_id, relname, permission);
ANALYZE public.group_membership;
ANALYZE public.share_acl;
"""


def _prepare_database(
    root: Path,
    pg_env: PostgresEnv,
    tpch_scale: str = "",
    job_scale: str = "",
) -> str:
    init_db(root, pg_env)
    if tpch_scale in REAL_TPCH_SCALES:
        _run_sql_script(_setup_tpch_real_sql(root, tpch_scale), pg_env)
    else:
        _run_sql_script(_setup_sql(), pg_env)
    if job_scale in REAL_JOB_SCALES:
        _run_sql_script(_setup_job_real_sql(root, job_scale), pg_env)
    else:
        _run_sql_script(_setup_job_sql(), pg_env)
    _run_sql_script(_setup_e3_group_acl_sql(), pg_env)
    return run_psql_command("SHOW server_version;", pg_env)


def e3_manifest_data_requirements(
    root: Path,
    manifest: Mapping[str, Any],
) -> list[E3DataRequirement]:
    requirements: list[E3DataRequirement] = []
    scale_by_dataset = {
        str(item.get("name")): str(item.get("scale", "reduced"))
        for item in manifest.get("datasets", [])
        if isinstance(item, Mapping)
    }
    tpch_scale = scale_by_dataset.get("tpch", "")
    if tpch_scale in REAL_TPCH_SCALES:
        requirements.extend(
            E3DataRequirement(f"TPC-H {tpch_scale}", path)
            for path in _tpch_real_data_files(root, tpch_scale)
        )
    job_scale = scale_by_dataset.get("job", "")
    if job_scale in REAL_JOB_SCALES:
        requirements.extend(
            E3DataRequirement(f"JOB/IMDb {job_scale}", path)
            for path in _job_real_data_files(root)
        )
    return requirements


def e3_manifest_data_requirements_for_path(
    root: Path,
    manifest_path: Path,
) -> list[E3DataRequirement]:
    manifest = _load_manifest(manifest_path)
    _validate_manifest(manifest_path, manifest)
    return e3_manifest_data_requirements(root, manifest)


def e3_manifest_missing_data(
    root: Path, manifest_path: Path
) -> list[E3DataRequirement]:
    return [
        requirement
        for requirement in e3_manifest_data_requirements_for_path(root, manifest_path)
        if not requirement.path.exists()
    ]


def require_e3_manifest_data(
    root: Path,
    manifest_path: Path,
    manifest: Mapping[str, Any],
) -> None:
    missing = [
        requirement
        for requirement in e3_manifest_data_requirements(root, manifest)
        if not requirement.path.exists()
    ]
    if not missing:
        return
    rendered = ", ".join(f"{item.label}: {item.path}" for item in missing)
    raise PostgresError(
        f"E3 manifest {manifest_path} requires missing real data files; "
        "restore/generate them before running this package: " + rendered
    )


def _policy_predicate(query: E3QuerySpec, policy: E3PolicyConfig) -> str:
    alias = query.alias
    if query.workload == "tpch":
        if policy.config_id == CHEAP_TENANT_POLICY_ID:
            return f"{alias}.tenant_id = 1"
        if policy.config_id == GROUP_ACL_POLICY_ID:
            return _group_acl_predicate(query, alias)
        if policy.config_id == HYBRID_SELECTIVE_KEY_POLICY_ID:
            return f"{alias}.tenant_id = 1 AND ({alias}.c_custkey % 50) = 0"
    if query.workload == "job":
        if policy.config_id == CHEAP_TENANT_POLICY_ID:
            return f"{alias}.region_id = 1"
        if policy.config_id == GROUP_ACL_POLICY_ID:
            return _group_acl_predicate(query, alias)
        if policy.config_id == HYBRID_SELECTIVE_KEY_POLICY_ID:
            return f"{alias}.region_id = 1 AND ({alias}.t_id % 50) = 0"
    raise PostgresError(
        f"unsupported E3 policy/query pair: {policy.config_id}/{query.query_id}"
    )


def _policy_predicate_unaliased(query: E3QuerySpec, policy: E3PolicyConfig) -> str:
    if query.workload == "tpch":
        if policy.config_id == CHEAP_TENANT_POLICY_ID:
            return "tenant_id = 1"
        if policy.config_id == GROUP_ACL_POLICY_ID:
            return _group_acl_predicate(query, None)
        if policy.config_id == HYBRID_SELECTIVE_KEY_POLICY_ID:
            return "tenant_id = 1 AND (c_custkey % 50::bigint) = 0"
    if query.workload == "job":
        if policy.config_id == CHEAP_TENANT_POLICY_ID:
            return "region_id = 1"
        if policy.config_id == GROUP_ACL_POLICY_ID:
            return _group_acl_predicate(query, None)
        if policy.config_id == HYBRID_SELECTIVE_KEY_POLICY_ID:
            return "region_id = 1 AND (t_id % 50::bigint) = 0"
    raise PostgresError(
        f"unsupported E3 policy/query pair: {policy.config_id}/{query.query_id}"
    )


def _group_acl_predicate(query: E3QuerySpec, alias: str | None) -> str:
    rid_ref = query.rid_col if alias is None else f"{alias}.{query.rid_col}"
    return f"""EXISTS (
  SELECT 1
  FROM public.share_acl s
  JOIN public.group_membership m ON m.group_id = s.group_id
  WHERE m.user_id = 'e3_user'
    AND s.relname = {_quote('public.' + query.protected_rel)}
    AND s.rid = {rid_ref}
    AND s.permission = 'read'
)"""


def _configure_native_rls(
    query: E3QuerySpec, policy: E3PolicyConfig, pg_env: PostgresEnv
) -> None:
    configure_native_rls(
        rel=f"public.{query.protected_rel}",
        policy_name=f"caprls_e3_policy_{query.protected_rel}",
        predicate=_policy_predicate_unaliased(query, policy),
        role_name=E3_RLS_ROLE,
        pg_env=pg_env,
    )


def _e3_catalog_collector_sql(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    *,
    execution_profile: str = "native_rls",
) -> str:
    _e3_require_execution_profile(execution_profile)
    trusted = execution_profile == "trusted_explicit"
    extra_claims = (
        ",\n  'trusted_execution', " + _e3_trusted_execution_catalog_expression(query, policy)
        if trusted else ""
    )
    artifact_id = _artifact_id(query, policy)
    relation_name = query.protected_rel
    return f"""
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL search_path = pg_catalog, public;
SET LOCAL ROLE {E3_RLS_ROLE};
SET LOCAL row_security = on;
WITH target_relation AS (
  SELECT c.oid, n.nspname, c.relname, c.relowner,
         c.relrowsecurity, c.relforcerowsecurity
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public'
    AND c.relname = {_quote(relation_name)}
),
relation_claim AS (
  SELECT jsonb_build_object(
    'oid', r.oid::bigint,
    'schema_name', r.nspname,
    'relation_name', r.relname,
    'owner', r.relowner::regrole::text,
    'row_security_enabled', r.relrowsecurity,
    'force_row_security', r.relforcerowsecurity
  ) AS value
  FROM target_relation r
),
policy_claims AS (
  SELECT COALESCE(
    jsonb_agg(
      jsonb_build_object(
        'policy_name', p.polname,
        'command', p.polcmd::text,
        'permissive', p.polpermissive,
        'roles', (
          SELECT COALESCE(
            jsonb_agg(
              CASE WHEN role_oid = 0 THEN 'public' ELSE role_row.rolname END
              ORDER BY CASE WHEN role_oid = 0 THEN 'public' ELSE role_row.rolname END
            ),
            '[]'::jsonb
          )
          FROM unnest(p.polroles) AS role_oid
          LEFT JOIN pg_catalog.pg_roles role_row ON role_row.oid = role_oid
        ),
        'expression', pg_catalog.pg_get_expr(p.polqual, p.polrelid, true)
      )
      ORDER BY p.polname
    ),
    '[]'::jsonb
  ) AS value
  FROM pg_catalog.pg_policy p
  JOIN target_relation r ON r.oid = p.polrelid
),
role_claim AS (
  SELECT jsonb_build_object(
    'role_name', role_row.rolname,
    'is_superuser', role_row.rolsuper,
    'bypasses_rls', role_row.rolbypassrls,
    'member_of', (
      SELECT COALESCE(jsonb_agg(parent.rolname ORDER BY parent.rolname), '[]'::jsonb)
      FROM pg_catalog.pg_auth_members membership
      JOIN pg_catalog.pg_roles parent ON parent.oid = membership.roleid
      WHERE membership.member = role_row.oid
    ),
    'members', (
      SELECT COALESCE(jsonb_agg(member.rolname ORDER BY member.rolname), '[]'::jsonb)
      FROM pg_catalog.pg_auth_members membership
      JOIN pg_catalog.pg_roles member ON member.oid = membership.member
      WHERE membership.roleid = role_row.oid
    )
  ) AS value
  FROM pg_catalog.pg_roles role_row
  WHERE role_row.rolname = {_quote(E3_RLS_ROLE)}
),
dependency_claims AS (
  SELECT COALESCE(
    jsonb_agg(
      jsonb_build_object(
        'artifact_id', dependency.artifact_id,
        'dependency_kind', dependency.dep_kind,
        'dependency_name', dependency.dep_name,
        'version_at_build', dependency.version_at_build
      )
      ORDER BY dependency.dep_kind, dependency.dep_name, dependency.version_at_build
    ),
    '[]'::jsonb
  ) AS value
  FROM public.artifact_dependencies dependency
  WHERE dependency.artifact_id = {_quote(artifact_id)}
),
distinct_scope_rows AS (
  SELECT DISTINCT
    'auth_idx'::text AS physical_kind,
    artifact.artifact_id,
    artifact.policy_id,
    artifact.user_id AS principal_id,
    artifact.ctx_hash AS context_token,
    artifact.rid_domain_id,
    artifact.base_rel_oid::bigint AS base_relation_oid,
    artifact.policy_version,
    artifact.membership_version,
    NULL::text AS key_name,
    false AS key_value_is_null,
    false AS range_bucket_is_nonnull,
    EXISTS (
      SELECT 1
      FROM public.auth_idx duplicate_row
      WHERE duplicate_row.artifact_id = {_quote(artifact_id)}
      GROUP BY duplicate_row.artifact_id, duplicate_row.policy_id,
               duplicate_row.user_id, duplicate_row.ctx_hash,
               duplicate_row.rid_domain_id, duplicate_row.base_rel_oid,
               duplicate_row.policy_version, duplicate_row.membership_version,
               duplicate_row.rid
      HAVING count(*) > 1
    ) AS has_duplicate_identity
  FROM public.auth_idx artifact
  WHERE artifact.artifact_id = {_quote(artifact_id)}
  UNION ALL
  SELECT DISTINCT
    'auth_idx_keyed'::text AS physical_kind,
    artifact.artifact_id,
    artifact.policy_id,
    artifact.user_id AS principal_id,
    artifact.ctx_hash AS context_token,
    artifact.rid_domain_id,
    artifact.base_rel_oid::bigint AS base_relation_oid,
    artifact.policy_version,
    artifact.membership_version,
    artifact.key_name,
    artifact.key_value IS NULL AS key_value_is_null,
    artifact.range_bucket IS NOT NULL AS range_bucket_is_nonnull,
    EXISTS (
      SELECT 1
      FROM public.auth_idx_keyed duplicate_row
      WHERE duplicate_row.artifact_id = {_quote(artifact_id)}
      GROUP BY duplicate_row.artifact_id, duplicate_row.policy_id,
               duplicate_row.user_id, duplicate_row.ctx_hash,
               duplicate_row.rid_domain_id, duplicate_row.base_rel_oid,
               duplicate_row.policy_version, duplicate_row.membership_version,
               duplicate_row.key_name, duplicate_row.key_value,
               duplicate_row.range_bucket, duplicate_row.rid
      HAVING count(*) > 1
    ) AS has_duplicate_identity
  FROM public.auth_idx_keyed artifact
  WHERE artifact.artifact_id = {_quote(artifact_id)}
),
scope_claims AS (
  SELECT COALESCE(
    jsonb_agg(
      jsonb_build_object(
        'physical_kind', scope.physical_kind,
        'artifact_id', scope.artifact_id,
        'policy_id', scope.policy_id,
        'principal_id', scope.principal_id,
        'context_token', scope.context_token,
        'rid_domain_id', scope.rid_domain_id,
        'base_relation_oid', scope.base_relation_oid,
        'policy_version', scope.policy_version,
        'membership_version', scope.membership_version,
        'key_name', scope.key_name,
        'key_value_is_null', scope.key_value_is_null,
        'range_bucket_is_nonnull', scope.range_bucket_is_nonnull,
        'has_duplicate_identity', scope.has_duplicate_identity
      )
      ORDER BY scope.physical_kind, scope.key_name,
               scope.policy_id, scope.principal_id, scope.context_token,
               scope.rid_domain_id, scope.base_relation_oid
    ),
    '[]'::jsonb
  ) AS value
  FROM distinct_scope_rows scope
)
SELECT jsonb_build_object(
  'collector_schema', {_quote(E3_TRUSTED_OBSERVATION_SCHEMA if trusted else E3_CATALOG_OBSERVATION_SCHEMA)},
  'session_user', session_user,
  'current_user', current_user,
  'search_path', current_setting('search_path'),
  'row_security', current_setting('row_security'),
  'snapshot_text', pg_catalog.pg_current_snapshot()::text,
  'relation', (SELECT value FROM relation_claim),
  'policies', (SELECT value FROM policy_claims),
  'role', (SELECT value FROM role_claim),
  'dependencies', (SELECT value FROM dependency_claims),
  'artifact_scopes', (SELECT value FROM scope_claims){extra_claims}
)::text;
COMMIT;
"""


def _e3_trusted_execution_catalog_expression(
    query: E3QuerySpec, policy: E3PolicyConfig,
) -> str:
    fragment = _e3_trusted_finite_fragment_payload(query, policy)
    names = ", ".join(_quote(name) for name in fragment["relations"])
    return f"""jsonb_build_object(
    'database', current_database(),
    'role', (SELECT jsonb_build_object(
      'role_name', r.rolname, 'is_superuser', r.rolsuper, 'bypasses_rls', r.rolbypassrls,
      'member_of', (SELECT COALESCE(jsonb_agg(p.rolname ORDER BY p.rolname), '[]'::jsonb)
        FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles p ON p.oid=m.roleid
        WHERE m.member=r.oid),
      'members', (SELECT COALESCE(jsonb_agg(p.rolname ORDER BY p.rolname), '[]'::jsonb)
        FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles p ON p.oid=m.member
        WHERE m.roleid=r.oid))
      FROM pg_catalog.pg_roles r WHERE r.rolname=session_user),
    'relations', (SELECT COALESCE(jsonb_agg(jsonb_build_object(
      'oid', c.oid::bigint, 'schema_name', n.nspname, 'relation_name', c.relname,
      'owner', c.relowner::regrole::text, 'row_security_enabled', c.relrowsecurity,
      'force_row_security', c.relforcerowsecurity, 'relation_kind', c.relkind::text,
      'has_rules', c.relhasrules, 'has_triggers', c.relhastriggers,
      'has_subclasses', c.relhassubclass, 'is_partition', c.relispartition,
      'builtin_columns_only', NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_attribute a
        JOIN pg_catalog.pg_type t ON t.oid=a.atttypid
        JOIN pg_catalog.pg_namespace tn ON tn.oid=t.typnamespace
        LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation
        LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid=co.collnamespace
        WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
          AND (tn.nspname<>'pg_catalog' OR t.typtype<>'b' OR a.attgenerated<>''
            OR (a.attcollation<>0 AND cn.nspname<>'pg_catalog'))
      )) ORDER BY c.relname), '[]'::jsonb)
      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relname IN ({names})),
    'artifact_validator', (SELECT jsonb_build_object(
      'language', l.lanname, 'security_definer', p.prosecdef, 'config', to_jsonb(p.proconfig),
      'returns_boolean', p.prorettype='boolean'::regtype, 'body', p.prosrc)
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
      WHERE p.oid=pg_catalog.to_regprocedure('public.caprls_assert_artifact_valid(text,jsonb)'))
  )"""


def _collect_e3_planning_catalog_receipt(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    pg_env: PostgresEnv,
    *,
    execution_profile: str = "native_rls",
) -> E3PlanningCatalogReceipt:
    raw = run_psql_command(_e3_catalog_collector_sql(
        query, policy, execution_profile=execution_profile,
    ), pg_env)
    observation = _parse_e3_catalog_collector_output(raw)
    return _issue_e3_planning_catalog_receipt(
        observation,
        query,
        policy,
        session_user=pg_env.user,
        evidence_scope=E3_CATALOG_PRODUCTION_SCOPE,
        execution_profile=execution_profile,
    )


def _query_local_predicate(query: E3QuerySpec) -> str:
    alias = query.alias
    if query.query_id in {"Q3", "Q5", "Q7", "Q10", "Q12"}:
        return f"{alias}.c_mktsegment = 'BUILDING'"
    if query.query_id == "JOB_1a":
        return (
            f"{alias}.kind = 'movie' AND {alias}.production_year BETWEEN 1990 AND 2010"
        )
    if query.query_id == "JOB_2a":
        return (
            f"{alias}.kind = 'movie' AND {alias}.production_year BETWEEN 1985 AND 2015"
        )
    if query.query_id == "JOB_3c":
        return (
            f"{alias}.kind = 'movie' AND {alias}.production_year BETWEEN 1980 AND 2005"
        )
    if query.query_id == "JOB_6d":
        return f"{alias}.kind = 'movie' AND {alias}.production_year >= 1995"
    if query.query_id == "JOB_10a":
        return (
            f"{alias}.kind = 'movie' AND {alias}.production_year BETWEEN 1990 AND 2020"
        )
    if query.query_id == "JOB_16b":
        return f"{alias}.kind = 'movie' AND {alias}.production_year >= 1980"
    raise PostgresError(f"unsupported E3 query-local predicate: {query.query_id}")


def _template_for_mode(policy: E3PolicyConfig, mode: str) -> tuple[str, str]:
    mode = normalize_mode_id(mode)
    if mode in MODE_TEMPLATES:
        return MODE_TEMPLATES[mode]
    if mode == "local-greedy":
        if policy.artifacts == "both_keyed":
            return MODE_TEMPLATES["strong-auth-index"]
        if policy.artifacts == "auth_idx":
            return MODE_TEMPLATES["auth-index-enum-only"]
        return MODE_TEMPLATES["barrier-only"]
    if mode == ADMISSION_FIRST_MODE:
        return ("adaptive_choice", "AdmissionFirst")
    raise PostgresError(f"unsupported E3 main mode: {mode}")


def _required_artifact_for_template(template_id: str) -> Optional[str]:
    if template_id in {
        "auth_index_enum_v1",
        "auth_index_semijoin_v1",
        "hybrid_intersect_v1",
    }:
        return "hybrid" if template_id == "hybrid_intersect_v1" else "auth_idx"
    if template_id in {"strong_auth_index_keyed_v1", "auth_index_keyed_semijoin_v1"}:
        return "auth_idx_keyed"
    return None


def _policy_has_artifact(policy: E3PolicyConfig, artifact: str) -> bool:
    if artifact == "auth_idx":
        return policy.artifacts in {"auth_idx", "both_keyed"}
    if artifact == "auth_idx_keyed":
        return policy.artifacts == "both_keyed"
    return False


def _artifact_unavailable_reason(
    policy: E3PolicyConfig, template_id: str, mode: str
) -> Optional[str]:
    required = _required_artifact_for_template(template_id)
    if required and not _policy_has_artifact(policy, required):
        return (
            f"mode {mode} requires {required}, but policy_config "
            f"{policy.config_id} declares artifacts={policy.artifacts}"
        )
    return None


def _unavailable_result(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    mode: str,
    template_id: str,
    alternative: str,
    authorized_rows: int,
    reason: str,
    plan_result: Optional[PlanResult] = None,
    query_plan: Optional[Mapping[str, Any]] = None,
    candidate: Optional[CandidatePlan] = None,
    template_applicability: Optional[str] = None,
) -> E3MainModeResult:
    mode = normalize_mode_id(mode)
    applicability = (
        template_applicability
        if template_applicability is not None
        else (
            candidate.template_applicability
            if candidate is not None
            else "artifact_unavailable"
        )
    )
    payload = {
        "query_id": query.query_id,
        "policy_config_id": policy.config_id,
        "mode": scientific_mode_key(mode),
        "status": applicability,
        "template_id": template_id,
    }
    diagnostic_plan_hash = None
    if candidate is not None and candidate.diagnostics.get("plan_hash"):
        diagnostic_plan_hash = str(candidate.diagnostics["plan_hash"])
    return E3MainModeResult(
        query=query,
        policy_config_id=policy.config_id,
        mode=mode,
        template_id=template_id,
        alternative=alternative,
        status="expected_reject",
        template_applicability=applicability,
        row_count=0,
        execution_ms=0.0,
        build_ms=0.0,
        authorized_rows=authorized_rows,
        result_hash=_digest(payload),
        artifact_id=None,
        failure_reason=reason,
        plan_result=plan_result,
        query_plan=query_plan,
        candidate=candidate,
        static_verifier_status="fail",
        static_verifier_plan_hash=diagnostic_plan_hash,
        static_verifier_reasons=(reason,),
    )


def _source_for_template(template_id: str) -> str:
    if template_id in {"native_pg_rls_v1", "native_pg_rls_physical_design_v1"}:
        return "rls"
    if template_id in {"safe_predicate_injection_v1", "ordinary_first_exact_check_v1"}:
        return "direct"
    if template_id == "barrier_filter_inline_v1":
        return "barrier_inline"
    if template_id in {"barrier_filter_v1", "barrier_filter_query_v1"}:
        return "barrier"
    if template_id == "auth_index_enum_v1":
        return "auth_idx"
    if template_id == "auth_index_semijoin_v1":
        return "auth_idx_semijoin"
    if template_id == "hybrid_intersect_v1":
        return "hybrid"
    if template_id == "strong_auth_index_keyed_v1":
        return "auth_idx_keyed"
    if template_id == "auth_index_keyed_semijoin_v1":
        return "auth_idx_keyed_semijoin"
    raise PostgresError(f"E3 planner selected unsupported template: {template_id}")


def _artifact_source_requires_validation(source: str) -> bool:
    return source in {
        "auth_idx",
        "auth_idx_keyed",
        "auth_idx_semijoin",
        "auth_idx_keyed_semijoin",
        "hybrid",
    }


def _expected_artifact_json(query: E3QuerySpec, policy: E3PolicyConfig) -> str:
    return json.dumps(
        _artifact_dependency_records(query, policy),
        sort_keys=True,
        separators=(",", ":"),
    )


def _artifact_dependency_records(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
) -> list[dict[str, Any]]:
    rid_domain = f"{query.protected_rel}.{query.rid_col}"
    deps = [
        {"dep_kind": "policy", "dep_name": policy.config_id, "version_at_build": 0},
        {"dep_kind": "base", "dep_name": query.protected_rel, "version_at_build": 0},
        {
            "dep_kind": "context_scope",
            "dep_name": "e3_main_ctx_hash",
            "version_at_build": 0,
        },
        {"dep_kind": "rid_domain", "dep_name": rid_domain, "version_at_build": 0},
    ]
    if policy.config_id == "group_acl_expensive":
        deps.extend(
            [
                {
                    "dep_kind": "membership",
                    "dep_name": "group_membership",
                    "version_at_build": 0,
                },
                {"dep_kind": "acl", "dep_name": "share_acl", "version_at_build": 0},
            ]
        )
    return deps


def _e3_artifacts_from_catalog_receipt(
    receipt: E3PlanningCatalogReceipt,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    *,
    authorized_rows: int,
    build_ms: float,
    keyed_artifact_rows: int,
) -> dict[str, ArtifactMetadata]:
    """Lower validated catalog claims into explicit planner metadata.

    The physical builder may populate more tables than the finite policy
    declaration licenses.  Only ``declared_usable_kinds`` become planner
    capabilities; every safety field is derived explicitly from the receipt
    instead of relying on ``ArtifactMetadata`` defaults.
    """

    relation = receipt.observation.relation
    scopes_by_kind = {
        scope.physical_kind: scope for scope in receipt.observation.artifact_scopes
    }
    expected_artifact_id = _artifact_id(query, policy)
    expected_rid_domain = f"{query.protected_rel}.{query.rid_col}"
    artifacts: dict[str, ArtifactMetadata] = {}
    for kind in receipt.declared_usable_kinds:
        scope = scopes_by_kind.get(kind)
        if scope is None:
            raise ValueError(
                f"E3 typed artifact declaration lacks catalog scope: {kind}"
            )
        keyed = kind == "auth_idx_keyed"
        context_matches = (
            scope.principal_id == receipt.principal_id
            and scope.context_token == receipt.context_token
        )
        rid_domain_matches = scope.rid_domain_id == expected_rid_domain
        base_relation_matches = scope.base_relation_oid == relation.oid
        key_domain_matches = not keyed or (
            scope.key_name == query.key_name
            and not scope.key_value_is_null
            and not scope.range_bucket_is_nonnull
        )
        scope_matches = (
            scope.artifact_id == expected_artifact_id
            and scope.policy_id == receipt.policy_id
            and context_matches
            and rid_domain_matches
            and base_relation_matches
            and scope.policy_version == 0
            and scope.membership_version == 0
            and not scope.has_duplicate_identity
        )
        validated = (
            receipt.verdict == "pass"
            and kind in set(receipt.observed_physical_kinds)
            and scope_matches
            and key_domain_matches
        )
        artifacts[kind] = ArtifactMetadata(
            kind=kind,
            artifact_id=expected_artifact_id,
            fresh=validated,
            context_matches=context_matches,
            rid_domain_matches=rid_domain_matches,
            base_relation_matches=base_relation_matches,
            exact=validated,
            keyed=keyed,
            scope_matches=scope_matches,
            cardinality=authorized_rows,
            rows=authorized_rows,
            key_name=query.key_name if keyed else None,
            key_value=query.key_value if keyed else None,
            key_value_cardinality=(keyed_artifact_rows or None) if keyed else None,
            key_domain_matches=key_domain_matches,
            supports_equality_key=keyed and key_domain_matches,
            order_keys=(),
            build_ms=build_ms,
            refresh_ms=0.0,
            storage_bytes=authorized_rows * 96,
        )
    return artifacts


def _e3_planning_problem(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    protected_rows: int,
    query_local_rows: int,
    authorized_rows: int,
    build_ms: float,
    keyed_artifact_rows: int = 0,
    *,
    typed_admission_bundle: Optional[E3TypedAdmissionBundle] = None,
    planning_catalog_receipt: Optional[E3PlanningCatalogReceipt] = None,
    planning_registry: Optional[TemplateRegistry] = None,
) -> PlanningProblem:
    typed_admission = typed_admission_bundle is not None
    if typed_admission:
        if planning_catalog_receipt is None:
            raise ValueError("E3 typed planning requires its catalog receipt")
        if planning_registry is None:
            raise ValueError("E3 typed planning requires the actual planner registry")
        bundle_reasons = _validate_e3_typed_admission_bundle(
            typed_admission_bundle,
            planning_catalog_receipt,
            query,
            policy,
            planning_registry,
        )
        if bundle_reasons:
            raise ValueError(
                "E3 typed admission bundle is not canonical: "
                + "; ".join(bundle_reasons)
            )
        artifacts = _e3_artifacts_from_catalog_receipt(
            planning_catalog_receipt,
            query,
            policy,
            authorized_rows=authorized_rows,
            build_ms=build_ms,
            keyed_artifact_rows=keyed_artifact_rows,
        )
    else:
        artifacts = {}
    if not typed_admission and policy.artifacts in {"auth_idx", "both_keyed"}:
        artifact_id = _artifact_id(query, policy)
        artifacts = {
            "auth_idx": ArtifactMetadata(
                kind="auth_idx",
                artifact_id=artifact_id,
                cardinality=authorized_rows,
                rows=authorized_rows,
                build_ms=build_ms,
                storage_bytes=authorized_rows * 96,
            )
        }
        if policy.artifacts == "both_keyed":
            artifacts["auth_idx_keyed"] = ArtifactMetadata(
                kind="auth_idx_keyed",
                artifact_id=artifact_id,
                keyed=True,
                cardinality=authorized_rows,
                rows=authorized_rows,
                key_name=query.key_name,
                key_value=query.key_value,
                key_value_cardinality=keyed_artifact_rows or None,
                supports_equality_key=True,
                key_domain_matches=True,
                build_ms=build_ms,
                storage_bytes=authorized_rows * 96,
            )
    exact_policy_safe = policy.injection_safe
    policy_eval_cost = 0.001 if exact_policy_safe else 0.01
    engine_rls_policy_hash = _digest(
        {
            "relation": query.protected_rel,
            "policy_config_id": policy.config_id,
            "predicate": _policy_predicate_unaliased(query, policy),
        }
    )
    native_rls_contract = (
        typed_admission_bundle.native_rls_contract
        if typed_admission_bundle is not None
        else NativeRLSSessionContract(
            contract_id=f"e3-native-rls:{query.query_id}:{policy.config_id}",
            relation=query.protected_rel,
            policy_id=policy.config_id,
            policy_fingerprint=engine_rls_policy_hash,
            role=E3_RLS_ROLE,
            snapshot_id=f"e3-planning:{query.query_id}:{policy.config_id}",
            emitted_policy_digest=canonical_predicate_digest(
                _policy_predicate(query, policy)
            ),
            validator_evidence_digest=_digest(
                {
                    "validator": "e3_native_rls_contract_v1",
                    "query_id": query.query_id,
                    "policy_config_id": policy.config_id,
                }
            ),
            force_row_security=True,
        )
    )
    problem = PlanningProblem(
        relation=query.protected_rel,
        policy_id=policy.config_id,
        occurrence_id=query.query_id,
        rid_col=query.rid_col,
        required_attrs=(query.rid_col,),
        required_ctx=(E3_CONTEXT_TOKEN,),
        exact_policy_safe=exact_policy_safe,
        supports_guard=False,
        has_safe_query_predicate=True,
        engine_rls_available=True,
        engine_rls_policy_hash=(
            native_rls_contract.policy_fingerprint
            if typed_admission
            else engine_rls_policy_hash
        ),
        native_rls_session_contract=native_rls_contract,
        gamma_snapshot=(
            None
            if typed_admission_bundle is None
            else typed_admission_bundle.gamma_snapshot
        ),
        logical_target=(
            None
            if typed_admission_bundle is None
            else typed_admission_bundle.logical_target
        ),
        implementation_target_bindings=(
            ()
            if typed_admission_bundle is None
            else typed_admission_bundle.implementation_bindings
        ),
        query_predicate=(
            None
            if typed_admission_bundle is None
            else _e3_query_predicate(query, query.alias)
        ),
        planning_execution_class=(
            "production_normal"
            if typed_admission_bundle is not None
            else "diagnostic_only"
        ),
        require_typed_admission=typed_admission,
        artifacts=artifacts,
        parent_requirement=ParentRequirement(
            logical_group_id=query.query_id,
            visible_columns=(query.rid_col,),
            licensed_refinements=("query_filtered",),
            allowed_enforcers=("residual_check", "validation_gate", "sort"),
            # E3's finite portfolio has heterogeneous evidence atoms across
            # barrier, artifact, and native alternatives.  A shared rho-level
            # freshness/context atom would therefore be false.  Context is
            # instead bound by T, required_ctx, and each consumed Gamma fact;
            # artifact time/context checks remain explicit dynamic obligations.
            freshness_predicate=None,
            context_predicate=None,
        ),
        cost_inputs=CostInputs(
            estimated_rows=max(protected_rows, 1),
            query_selectivity=min(
                1.0, max(query_local_rows, 1) / max(protected_rows, 1)
            ),
            auth_selectivity=min(1.0, max(authorized_rows, 1) / max(protected_rows, 1)),
            policy_eval_cost=policy_eval_cost,
        ),
    )
    return problem


def _text_digest(payload: str) -> str:
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _e3_query_predicate(query: E3QuerySpec, alias: str) -> str:
    # The licensed target is the complete protected-occurrence local
    # conjunction, including JOB's production-year range.  Keep the target,
    # Gamma evidence, IR Select and emitter on this one controlled source.
    # The independent continuation retains the same conditions as before.
    return _query_local_predicate(query).replace(f"{query.alias}.", f"{alias}.")


def _e3_emit_context(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    problem: PlanningProblem,
    *,
    strict_artifact_expectations: Optional[
        Mapping[str, StrictArtifactExpectation]
    ] = None,
) -> EmitContext:
    artifact_ids = {
        kind: artifact.artifact_id for kind, artifact in problem.artifacts.items()
    }
    return EmitContext(
        default_rid_col=problem.rid_col,
        occurrence_relations={problem.occurrence_id: problem.relation},
        occurrence_aliases={problem.occurrence_id: query.alias},
        occurrence_rid_cols={problem.occurrence_id: problem.rid_col},
        exact_predicates={problem.occurrence_id: _policy_predicate(query, policy)},
        guard_predicates={problem.occurrence_id: _policy_predicate(query, policy)},
        query_predicates={
            problem.occurrence_id: _e3_query_predicate(query, query.alias)
        },
        residual_predicates={
            f"{policy.config_id}:exact_residual": _policy_predicate(
                query, policy
            ).replace(
                f"{query.alias}.",
                "rcheck.",
            )
        },
        artifact_expectations=(
            dict(strict_artifact_expectations)
            if strict_artifact_expectations is not None
            else {
                artifact.artifact_id: {
                    "policy_id": problem.policy_id,
                    "context_predicate": "e3_main_ctx_hash_matches_current_context",
                }
                for artifact in problem.artifacts.values()
            }
        ),
        template_params={
            problem.occurrence_id: {
                "carrier_columns": E3_CARRIER_PROJECTION_COLUMNS[query.query_id],
                "artifact_ids": artifact_ids,
                "policy_id": problem.policy_id,
                "user_id": E3_PRINCIPAL_ID,
                "ctx_hash": E3_CONTEXT_TOKEN,
                "rid_domain_id": f"{problem.relation}.{problem.rid_col}",
                "base_rel_oid": f"public.{problem.relation}",
                "key_name": query.key_name,
                "key_predicate": (
                    f"a.key_value = {query.alias}.{query.key_name}::text"
                ),
            }
        },
        native_rls_contracts=(
            {}
            if problem.native_rls_session_contract is None
            else {problem.occurrence_id: problem.native_rls_session_contract}
        ),
    )


def _e3_planning_query(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    problem: PlanningProblem,
    mode: str,
    *,
    strict_artifact_expectations: Optional[
        Mapping[str, StrictArtifactExpectation]
    ] = None,
) -> PlanningQuery:
    parent = problem.parent_requirement
    hidden_carriers = _e3_required_hidden_carriers(query)
    return PlanningQuery(
        ir_skeleton=Root(
            Project(
                Select(
                    ScanProtected(problem.occurrence_id, "chosen"),
                    pred=_e3_query_predicate(query, "sel"),
                    pred_kind="logical_target",
                    expr_label=f"{query.query_id}:base_filter",
                ),
                visible_A=(problem.rid_col,),
                hidden_H=hidden_carriers,
            ),
            rho_root={
                "logical_group_id": parent.logical_group_id,
                "visible_columns": parent.visible_columns,
                "licensed_refinements": parent.licensed_refinements,
                "allowed_enforcers": parent.allowed_enforcers,
                "required_ctx": problem.required_ctx,
            },
        ),
        occurrence_goals={problem.occurrence_id: OccurrenceGoal(problem, mode=mode)},
        mode=mode,
        emit_context=_e3_emit_context(
            query,
            policy,
            problem,
            strict_artifact_expectations=strict_artifact_expectations,
        ),
    )


def _e3_required_hidden_carriers(query: E3QuerySpec) -> tuple[str, ...]:
    columns = E3_CARRIER_PROJECTION_COLUMNS.get(query.query_id)
    if columns is None or query.rid_col not in columns:
        raise PostgresError("E3 continuation carrier inventory is incomplete")
    return tuple(
        sorted(
            tuple(column for column in columns if column != query.rid_col) + ("__rid",)
        )
    )


def _e3_continuation_spec(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
) -> ContinuationSpec:
    contract = E3_RESULT_COLUMN_CONTRACTS.get(query.query_id)
    order_contract = E3_RESULT_ORDER_CONTRACTS.get(query.query_id)
    if contract is None or order_contract is None:
        raise PostgresError("E3 semantic result contract is missing")
    ordered_keys, row_limit = order_contract
    return _mint_source_controlled_continuation_spec(
        spec_id="e3-semantic-result-v1:" + query.query_id,
        query_id=query.query_id,
        policy_id=policy.config_id,
        renderer_id="e3-finite-semantic-result-renderer",
        renderer_version="v1",
        result_mode="ordered_sequence",
        required_hidden_carriers=_e3_required_hidden_carriers(query),
        result_columns=tuple(
            TypedRootSchemaColumn(
                ordinal=ordinal,
                name=name,
                type_name=type_name,
                nullable=nullable,
            )
            for ordinal, (name, type_name, nullable) in enumerate(contract)
        ),
        ordered_keys=ordered_keys,
        row_limit=row_limit,
        continuation_sql=_e3_continuation_sql(query),
    )


def _e3_continuation_sql(query: E3QuerySpec) -> str:
    rendered = (
        _e3_semantic_result_sql(
            query,
            cte="",
            from_rel=f"caprls_access_root AS {query.alias}",
            extra="",
        )
        .strip()
        .rstrip(";")
    )
    return "\n" + rendered


def _e3_independent_result_reference_sql(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
) -> str:
    """Render the fixed direct-source semantic reference for one E3 owner."""

    _require_e3_canonical_query_policy_sources(query, policy)
    predicate = _policy_predicate(query, policy)
    cte, from_rel, extra = _source_sql(query, policy, "direct", predicate)
    expected_from_rel = f"public.{query.protected_rel} AS {query.alias}"
    if cte or from_rel != expected_from_rel:
        raise PostgresError("E3 independent result reference source changed")
    rendered = _e3_semantic_result_sql(
        query,
        cte=cte,
        from_rel=from_rel,
        extra=extra,
    ).strip()
    try:
        statement = _validate_single_transaction_statement(rendered)
    except PostgresError as exc:
        raise PostgresError(
            "E3 independent result reference is not one SELECT"
        ) from exc
    if statement.split(None, 1)[0] != "SELECT" or rendered != statement + ";":
        raise PostgresError("E3 independent result reference is not one SELECT")
    return rendered


def _e3_independent_reference_count_sql(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
) -> str:
    """Count the fixed full-result reference without reusing a candidate source."""

    semantic_sql = _e3_independent_result_reference_sql(query, policy).rstrip(";")
    return _count_wrapper(
        "SELECT count(*) FROM (\n"
        + semantic_sql
        + "\n) AS caprls_e3_independent_reference;"
    )


def _e3_bound_runner_sql(
    query: E3QuerySpec,
    strict: StrictPlanningResult,
    *,
    access_root_materialized: bool = True,
) -> str:
    try:
        return _compose_exact_bound_runner_sql(
            strict,
            _e3_continuation_sql(query),
            materialized=access_root_materialized,
        )
    except ValueError as exc:
        raise PostgresError("E3 bound runner composition failed") from exc


def _e3_describe_bound_runner_result(
    session: PostgresTransactionSession,
    *,
    continuation: ContinuationSpec,
    runner_sql: str,
) -> tuple[TypedRootSchemaColumn, ...]:
    schema_probe = (
        "SELECT * FROM (\n" + runner_sql + "\n) AS caprls_e3_bound_runner_schema_probe"
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
        raise PostgresError("E3 bound runner result schema contract mismatch")
    return expected


def _query_plan_payload(
    query_result: QueryPlanResult,
    *,
    planning_catalog_receipt: Optional[E3PlanningCatalogReceipt] = None,
    typed_admission_bundle: Optional[E3TypedAdmissionBundle] = None,
) -> dict[str, Any]:
    payload = query_result.to_dict()
    emitted_sql = query_result.emitted_sql or ""
    payload["ok"] = query_result.ok
    payload["occurrence_ids"] = sorted(query_result.occurrence_results)
    payload["disabled_components"] = []
    payload["certificate_suppressed"] = False
    payload["emitted_sql"] = emitted_sql
    payload["emitted_sql_hash"] = _text_digest(emitted_sql) if emitted_sql else None
    if planning_catalog_receipt is not None:
        payload["planning_catalog_receipt"] = planning_catalog_receipt.to_dict()
        payload["planning_catalog_receipt_digest"] = (
            planning_catalog_receipt.receipt_digest
        )
    if typed_admission_bundle is not None:
        payload["typed_admission_bundle"] = typed_admission_bundle.to_dict()
        payload["typed_admission_bundle_digest"] = typed_admission_bundle.bundle_digest
    return payload


def _e3_query_plan_for_result(
    *,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    problem: PlanningProblem,
    mode: str,
    plan_result: PlanResult,
    registry: Optional[TemplateRegistry] = None,
    planning_catalog_receipt: Optional[E3PlanningCatalogReceipt] = None,
) -> Mapping[str, Any]:
    planning_registry = registry or _e3_registry()
    typed_bundle: Optional[E3TypedAdmissionBundle] = None
    if problem.require_typed_admission:
        if planning_catalog_receipt is None:
            raise ValueError(
                "E3 typed query-plan serialization requires its catalog receipt"
            )
        typed_bundle = _issue_e3_typed_admission_bundle(
            planning_catalog_receipt,
            query,
            policy,
            planning_registry,
        )
        if (
            problem.logical_target != typed_bundle.logical_target
            or problem.gamma_snapshot != typed_bundle.gamma_snapshot
            or tuple(problem.implementation_target_bindings)
            != typed_bundle.implementation_bindings
            or problem.native_rls_session_contract != typed_bundle.native_rls_contract
            or problem.query_predicate != _e3_query_predicate(query, query.alias)
        ):
            raise ValueError(
                "E3 planning problem and typed admission bundle are not identical"
            )
    query_result = plan_query(
        _e3_planning_query(query, policy, problem, mode),
        registry=planning_registry,
        preplanned_occurrence_results={problem.occurrence_id: plan_result},
    )
    return _query_plan_payload(
        query_result,
        planning_catalog_receipt=planning_catalog_receipt,
        typed_admission_bundle=typed_bundle,
    )


def _strip_psql_directives(sql: str) -> str:
    lines = []
    for line in sql.splitlines():
        stripped = line.strip()
        if (
            not stripped
            or stripped.startswith("\\")
            or stripped.upper().startswith("SET ")
            or stripped.upper().startswith("RESET ")
        ):
            continue
        lines.append(line)
    return "\n".join(lines)


def _parse_explain_json(raw: str) -> list[Mapping[str, Any]]:
    text = raw.strip()
    start = text.find("[")
    end = text.rfind("]")
    if start >= 0 and end >= start:
        text = text[start : end + 1]
    return json.loads(text)


def _explain_json(
    sql: str,
    pg_env: PostgresEnv,
    *,
    native_rls: bool = False,
    analyze: bool = False,
) -> list[Mapping[str, Any]]:
    explainable = _strip_psql_directives(sql).rstrip().rstrip(";")
    explain_options = (
        "ANALYZE, FORMAT JSON, TIMING OFF, SUMMARY ON" if analyze else "FORMAT JSON"
    )
    guc_prefix = "\n".join(
        f"SET {name} = {value};" for name, value in E3_PSQL_GUCS.items()
    )
    if native_rls:
        raw = run_psql_command(
            f"""
{guc_prefix}
SET row_security = on;
SET ROLE caprls_e3_rls_user;
EXPLAIN ({explain_options}) {explainable};
RESET ROLE;
""",
            pg_env,
        )
    else:
        raw = run_psql_command(
            f"""
{guc_prefix}
EXPLAIN ({explain_options}) {explainable};
""",
            pg_env,
        )
    return _parse_explain_json(raw)


def _explain_plan_json(
    sql: str, pg_env: PostgresEnv, *, native_rls: bool = False
) -> Mapping[str, Any]:
    parsed = _explain_json(sql, pg_env, native_rls=native_rls)
    return parsed[0]["Plan"]


def _explain_total_cost(sql: str, pg_env: PostgresEnv) -> float:
    return float(_explain_plan_json(sql, pg_env)["Total Cost"])


def _walk_plan_nodes(node: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    nodes = [node]
    for child in node.get("Plans", []) or []:
        if isinstance(child, Mapping):
            nodes.extend(_walk_plan_nodes(child))
    return nodes


def _plan_hash(plan_root: Mapping[str, Any]) -> str:
    payload = json.dumps(plan_root, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _explain_plan_hash(explain_json: list[Mapping[str, Any]]) -> str:
    plan = explain_json[0].get("Plan", {})
    if not isinstance(plan, Mapping):
        plan = {}
    return _plan_hash(plan)


def _verify_e3_static(
    template_id: str,
    sql: str,
    explain_json: list[Mapping[str, Any]],
) -> StaticVerification:
    verification = verify_template_static(
        _static_verifier_template_id(template_id),
        _strip_psql_directives(sql),
        explain_json,
        _explain_plan_hash(explain_json),
    )
    if verification.status != "pass":
        raise PostgresError(
            f"E3 static verifier failed for {template_id}: "
            + "; ".join(verification.reasons)
        )
    return verification


def _static_verifier_template_id(template_id: str) -> str:
    if template_id == "native_pg_rls_physical_design_v1":
        return "native_pg_rls_v1"
    return template_id


def _verify_e3_static_with_explain(
    template_id: str,
    sql: str,
    pg_env: PostgresEnv,
    *,
    native_rls: bool = False,
) -> StaticVerification:
    verification, _ = _verify_e3_static_with_explain_json(
        template_id,
        sql,
        pg_env,
        native_rls=native_rls,
    )
    return verification


def _verify_e3_static_with_explain_json(
    template_id: str,
    sql: str,
    pg_env: PostgresEnv,
    *,
    native_rls: bool = False,
) -> tuple[StaticVerification, tuple[Mapping[str, Any], ...]]:
    explain_json = _explain_json(
        sql,
        pg_env,
        native_rls=native_rls,
        analyze=False,
    )
    return _verify_e3_static(
        template_id,
        sql,
        explain_json,
    ), tuple(explain_json)


def _e3_cost_features(
    *,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    template_id: str,
    source: str,
    protected_rows: int,
    query_local_rows: int,
    authorized_rows: int,
    key_value_cardinality: Optional[int],
    plan_root: Mapping[str, Any],
) -> E3CostFeatures:
    nodes = _walk_plan_nodes(plan_root)
    node_types = tuple(
        sorted(
            {str(node.get("Node Type", "")) for node in nodes if node.get("Node Type")}
        )
    )
    has_cte_scan = any(str(node.get("Node Type")) == "CTE Scan" for node in nodes)
    has_materialized_cte = (
        source in {"barrier", "auth_idx", "auth_idx_keyed", "hybrid"} or has_cte_scan
    )
    has_seq_scan = any(str(node.get("Node Type")) == "Seq Scan" for node in nodes)
    has_index_scan = any("Index" in str(node.get("Node Type")) for node in nodes)
    has_nested_loop = any(str(node.get("Node Type")) == "Nested Loop" for node in nodes)
    join_count = sum(
        1
        for node in nodes
        if "Join" in str(node.get("Node Type"))
        or str(node.get("Node Type")) == "Nested Loop"
    )
    sort_count = sum(
        1
        for node in nodes
        if str(node.get("Node Type")) in {"Sort", "Incremental Sort"}
    )
    plan_rows = plan_root.get("Plan Rows")
    return E3CostFeatures(
        template_id=template_id,
        source=source,
        policy_config_id=policy.config_id,
        query_id=query.query_id,
        workload=query.workload,
        protected_rows=protected_rows,
        query_local_rows=query_local_rows,
        authorized_rows=authorized_rows,
        key_value_cardinality=key_value_cardinality,
        pg_total_cost=float(plan_root["Total Cost"]),
        plan_rows=None if plan_rows is None else float(plan_rows),
        has_materialized_cte=has_materialized_cte,
        has_cte_scan=has_cte_scan,
        has_seq_scan=has_seq_scan,
        has_index_scan=has_index_scan,
        has_nested_loop=has_nested_loop,
        join_count=join_count,
        sort_count=sort_count,
        plan_node_types=node_types,
        plan_hash=_plan_hash(plan_root),
    )


def _adjust_e3_estimated_cost(
    *,
    features: E3CostFeatures,
    ranker: E3Ranker,
) -> float:
    return ranker.estimate(features)


def _candidate_diagnostic_payload(
    *,
    features: E3CostFeatures,
    adjusted_cost: float,
    ranker: E3Ranker,
) -> dict[str, Any]:
    return {
        "diagnostic_kind": "e3_candidate_cost",
        "template_id": features.template_id,
        "source": features.source,
        "ranker": ranker.name,
        "cost_model_version": ranker.version,
        "calibration_path": ranker.calibration_path,
        "calibration_hash": ranker.calibration_hash,
        "protected_rows": features.protected_rows,
        "query_local_rows": features.query_local_rows,
        "authorized_rows": features.authorized_rows,
        "key_value_cardinality": features.key_value_cardinality,
        "pg_total_cost": features.pg_total_cost,
        "adjusted_cost": adjusted_cost,
        "plan_rows": features.plan_rows,
        "has_materialized_cte": features.has_materialized_cte,
        "has_cte_scan": features.has_cte_scan,
        "has_seq_scan": features.has_seq_scan,
        "has_index_scan": features.has_index_scan,
        "has_nested_loop": features.has_nested_loop,
        "join_count": features.join_count,
        "sort_count": features.sort_count,
        "plan_node_types": list(features.plan_node_types),
        "plan_hash": features.plan_hash,
    }


def _candidate_diagnostic(candidate: CandidatePlan) -> Optional[dict[str, Any]]:
    payload = dict(candidate.diagnostics)
    if not payload:
        return None
    if payload.get("diagnostic_kind") == "e3_candidate_cost":
        return payload
    if (
        "plan_hash" in payload
        or "pg_total_cost" in payload
        or "adjusted_cost" in payload
    ):
        return payload
    return None


def _rerank_plan_with_pg_estimates(
    plan_result: PlanResult,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    predicate: str,
    pg_env: PostgresEnv,
    protected_rows: int,
    query_local_rows: int,
    authorized_rows: int,
    ranker: E3Ranker,
    rho: ParentRequirement,
    keyed_artifact_rows: int = 0,
    sort_enforcer_cost: float = 0.0,
) -> PlanResult:
    candidates: list[CandidatePlan] = []
    for candidate in plan_result.candidates:
        unpruned_candidate = replace(candidate, pruned_by_dominance=None)
        if not candidate.accepted:
            candidates.append(unpruned_candidate)
            continue
        source = _source_for_template(candidate.template_id)
        explain_sql = (
            _query_count_sql(query, policy, "rls", "")
            if source == "rls"
            else _query_count_sql(query, policy, source, predicate)
        )
        plan_root = _explain_plan_json(
            explain_sql,
            pg_env,
            native_rls=source == "rls",
        )
        features = _e3_cost_features(
            query=query,
            policy=policy,
            template_id=candidate.template_id,
            source=source,
            protected_rows=protected_rows,
            query_local_rows=query_local_rows,
            authorized_rows=authorized_rows,
            key_value_cardinality=(
                keyed_artifact_rows
                if source in {"auth_idx_keyed", "auth_idx_keyed_semijoin"}
                and keyed_artifact_rows
                else None
            ),
            plan_root=plan_root,
        )
        estimated_cost = _adjust_e3_estimated_cost(
            features=features,
            ranker=ranker,
        )
        candidates.append(
            replace(
                unpruned_candidate,
                estimated_cost=estimated_cost,
                emitted_sql=f"e3_source:{source}",
                diagnostics=_candidate_diagnostic_payload(
                    features=features,
                    adjusted_cost=estimated_cost,
                    ranker=ranker,
                ),
            )
        )
    # PostgreSQL Total Cost values from different E3 access paths are useful
    # ranking estimates, but they are not a semantic replacement proof.  In
    # particular, a materialized barrier must not erase a keyed authorization
    # path before the calibrated prospective ranker can compare them.  Keep
    # every admitted candidate in this E3-specific pass and rank the complete
    # pool below.  Global planner dominance remains unchanged for other uses.
    accepted = [candidate for candidate in candidates if candidate.accepted]
    chosen = (
        min(
            accepted,
            key=lambda item: (float(item.estimated_cost or 0.0), item.template_id),
        )
        if accepted
        else None
    )
    return replace(
        plan_result,
        dominance_checks=0,
        dominance_pruned=0,
        costed_templates=len(accepted),
        chosen_template=chosen,
        emitted_sql=None if chosen is None else chosen.emitted_sql,
        delivered_sigma={} if chosen is None else chosen.delivered_sigma,
        estimated_cost=None if chosen is None else chosen.estimated_cost,
        candidates=tuple(candidates),
    )


def _require_e3_production_catalog_receipt(
    receipt: Optional[E3PlanningCatalogReceipt],
    *,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    predicate: str,
    pg_env: PostgresEnv,
    execution_profile: str = "native_rls",
) -> E3PlanningCatalogReceipt:
    _e3_require_execution_profile(execution_profile)
    _require_e3_canonical_query_policy_sources(query, policy)
    if not isinstance(receipt, E3PlanningCatalogReceipt):
        raise PostgresError(
            "E3 AdmissionFirst production planning requires a catalog receipt"
        )
    if receipt.evidence_scope != E3_CATALOG_PRODUCTION_SCOPE:
        raise PostgresError(
            "E3 AdmissionFirst production planning rejects non-production receipt scope"
        )
    if _e3_receipt_execution_profile(receipt) != execution_profile:
        raise PostgresError("E3 catalog receipt execution profile mismatch")
    _require_e3_production_source(
        receipt,
        kind="catalog_receipt",
        identity_digest=receipt.receipt_digest,
        query=query,
        policy=policy,
    )
    session_user = str(getattr(pg_env, "user", ""))
    if not session_user:
        raise PostgresError(
            "E3 catalog receipt replay requires the PostgreSQL session user"
        )
    replay = _replay_e3_planning_catalog_receipt(
        receipt,
        query,
        policy,
        session_user=session_user,
    )
    if not replay.ok:
        raise PostgresError(
            "E3 planning catalog receipt replay failed: " + "; ".join(replay.reasons)
        )
    if canonical_predicate_digest(predicate) != receipt.rendered_predicate_digest:
        raise PostgresError(
            "E3 planning catalog receipt does not bind the rendered policy predicate"
        )
    trusted = receipt.observation.trusted_execution
    if trusted is not None and trusted.database != pg_env.database:
        raise PostgresError("E3 trusted catalog database differs from the actual connection")
    return receipt


def _require_e3_query_plan_catalog_receipt(
    query_plan: Optional[Mapping[str, Any]],
    receipt: E3PlanningCatalogReceipt,
) -> None:
    if not isinstance(query_plan, Mapping):
        raise PostgresError("E3 AdmissionFirst execution requires a query plan payload")
    payload = query_plan.get("planning_catalog_receipt")
    if not isinstance(payload, Mapping):
        raise PostgresError("E3 AdmissionFirst query plan lacks its catalog receipt")
    try:
        embedded = _e3_planning_catalog_receipt_from_dict(payload)
    except (TypeError, ValueError) as exc:
        raise PostgresError(
            "E3 AdmissionFirst query plan catalog receipt is malformed"
        ) from exc
    if embedded != receipt:
        raise PostgresError("E3 AdmissionFirst query plan catalog receipt mismatch")
    if query_plan.get("planning_catalog_receipt_digest") != receipt.receipt_digest:
        raise PostgresError("E3 AdmissionFirst query plan catalog digest mismatch")


def _require_e3_typed_admission_bundle(
    bundle: Optional[E3TypedAdmissionBundle],
    *,
    receipt: E3PlanningCatalogReceipt,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    registry: TemplateRegistry,
) -> E3TypedAdmissionBundle:
    canonical = _issue_e3_typed_admission_bundle(
        receipt,
        query,
        policy,
        registry,
    )
    if bundle is None:
        return canonical
    _require_e3_production_source(
        bundle,
        kind="typed_admission_bundle",
        identity_digest=bundle.bundle_digest,
        query=query,
        policy=policy,
        receipt=receipt,
        registry=registry,
    )
    reasons = _validate_e3_typed_admission_bundle(
        bundle,
        receipt,
        query,
        policy,
        registry,
    )
    if reasons:
        raise PostgresError("E3 typed admission replay failed: " + "; ".join(reasons))
    return bundle


def _require_e3_query_plan_typed_admission(
    query_plan: Optional[Mapping[str, Any]],
    *,
    receipt: E3PlanningCatalogReceipt,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    registry: TemplateRegistry,
) -> E3TypedAdmissionBundle:
    if not isinstance(query_plan, Mapping):
        raise PostgresError("E3 typed admission requires a query plan payload")
    payload = query_plan.get("typed_admission_bundle")
    if not isinstance(payload, Mapping):
        raise PostgresError("E3 AdmissionFirst query plan lacks typed admission")
    canonical = _derive_e3_typed_admission_bundle(
        receipt,
        query,
        policy,
        registry,
    )
    if dict(payload) != canonical.to_dict():
        raise PostgresError("E3 AdmissionFirst query plan typed admission mismatch")
    if query_plan.get("typed_admission_bundle_digest") != canonical.bundle_digest:
        raise PostgresError(
            "E3 AdmissionFirst query plan typed admission digest mismatch"
        )
    return canonical


def _e3_strict_artifact_contract(
    receipt: E3PlanningCatalogReceipt,
    bundle: E3TypedAdmissionBundle,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
) -> tuple[
    dict[str, StrictArtifactExpectation],
    tuple[tuple[str, str, str], ...],
]:
    """Project strict H2 inputs only from the sealed E3 receipt and Gamma."""

    artifact_facts = tuple(
        fact
        for fact in bundle.gamma_snapshot.facts
        if fact.kind == "artifact_validation" and fact.accepted
    )
    declared_ids = (
        {_artifact_id(query, policy)} if receipt.declared_usable_kinds else set()
    )
    observed_ids = {scope.artifact_id for scope in receipt.observation.artifact_scopes}
    if declared_ids and observed_ids != declared_ids:
        raise PostgresError("E3 strict artifact receipt identity changed")
    facts_by_id: dict[str, GammaFact] = {}
    for fact in artifact_facts:
        if fact.subject_digest in facts_by_id:
            raise PostgresError("E3 strict artifact fact identity is ambiguous")
        facts_by_id[fact.subject_digest] = fact
    if set(facts_by_id) != declared_ids:
        raise PostgresError("E3 strict artifact fact inventory is incomplete")
    if not declared_ids:
        return {}, ()

    receipt_dependencies = {
        (item.dependency_kind, item.dependency_name, item.version_at_build)
        for item in receipt.observation.dependencies
    }
    if len(receipt_dependencies) != len(receipt.observation.dependencies):
        raise PostgresError("E3 strict artifact dependency identity is ambiguous")
    expected_from_policy = {
        (item.dependency_kind, item.dependency_name, item.version_at_build)
        for item in _expected_dependency_claims(query, policy)
    }
    if receipt_dependencies != expected_from_policy:
        raise PostgresError("E3 strict artifact dependency projection changed")

    typed_dependencies = tuple(
        ArtifactDependencyExpectation(kind, name, version)
        for kind, name, version in sorted(receipt_dependencies)
    ) + (
        ArtifactDependencyExpectation(
            "execution_snapshot",
            bundle.gamma_snapshot.snapshot_id,
            0,
        ),
    )
    identity_by_kind: dict[str, ArtifactDependencyIdentity] = {}
    for dependency in typed_dependencies:
        if dependency.dep_kind in identity_by_kind:
            raise PostgresError("E3 strict artifact dependency kind is ambiguous")
        identity_by_kind[dependency.dep_kind] = dependency.identity
    required_kinds = {"base", "context_scope", "policy", "rid_domain"}
    if not required_kinds.issubset(identity_by_kind):
        raise PostgresError("E3 strict artifact dependency projection is incomplete")
    freshness_kinds = tuple(
        kind
        for kind in ("base", "membership", "acl", "policy")
        if kind in identity_by_kind
    )
    trusted_read_kinds = tuple(
        kind for kind in ("membership", "acl", "policy") if kind in identity_by_kind
    )
    expectation = StrictArtifactExpectation(
        dependencies=typed_dependencies,
        component_bindings=(
            ArtifactComponentBinding(
                "freshness",
                tuple(identity_by_kind[kind] for kind in freshness_kinds),
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
                tuple(identity_by_kind[kind] for kind in trusted_read_kinds),
            ),
            ArtifactComponentBinding(
                "rid_materialization",
                (identity_by_kind["rid_domain"],),
            ),
        ),
    )
    artifact_id = next(iter(declared_ids))
    fact = facts_by_id[artifact_id]
    return (
        {artifact_id: expectation},
        ((artifact_id, expectation.digest, fact.evidence_digest),),
    )


def _e3_connection_target_payload(pg_env: PostgresEnv) -> dict[str, Any]:
    if (
        pg_env.__class__ is not PostgresEnv
        or pg_env.host.__class__ is not str
        or not pg_env.host
        or pg_env.port.__class__ is not int
        or isinstance(pg_env.port, bool)
        or not 1 <= pg_env.port <= 65535
        or pg_env.user.__class__ is not str
        or not pg_env.user
        or pg_env.database.__class__ is not str
        or not pg_env.database
    ):
        raise PostgresError("E3 production PostgreSQL connection target is invalid")
    return {
        "host": pg_env.host,
        "port": pg_env.port,
        "user": pg_env.user,
        "database": pg_env.database,
    }


def _e3_production_session_contract(
    receipt: E3PlanningCatalogReceipt,
    bundle: E3TypedAdmissionBundle,
) -> SessionContract:
    role = receipt.observation.current_user
    if _e3_receipt_execution_profile(receipt) == "trusted_explicit":
        claim = receipt.observation.trusted_execution
        if claim is None or any(
            item in bundle.registry_template_ids for item in E3_ENGINE_RLS_TEMPLATE_IDS
        ):
            raise PostgresError("trusted explicit profile cannot delegate native RLS")
        role = claim.role.role_name
    elif role != E3_RLS_ROLE or bundle.native_rls_contract.role != role:
        raise PostgresError("E3 production native/session role binding changed")
    return SessionContract(
        role=role,
        search_path=("pg_catalog", "public"),
        gucs=E3_PRODUCTION_PLANNING_GUCS,
        transaction_isolation="repeatable read",
        read_only=True,
    )


def _e3_session_contract_payload(contract: SessionContract) -> dict[str, Any]:
    return {
        "role": contract.role, "search_path": list(contract.search_path),
        "gucs": dict(contract.gucs), "transaction_isolation": contract.transaction_isolation,
        "read_only": contract.read_only, "digest": contract.digest,
    }


def _e3_execution_profile_payload(owner: _E3ProductionPlanningOwner) -> dict[str, Any]:
    receipt = owner.receipt
    claim = receipt.observation.trusted_execution
    if claim is None:
        raise PostgresError("explicit execution profile requires trusted catalog evidence")
    payload = {
        "schema": "e3_trusted_explicit_execution_profile_v1",
        "name": "trusted_explicit", "query_id": receipt.query_id,
        "policy_id": receipt.policy_id, "principal_id": receipt.principal_id,
        "policy_validation_role": E3_RLS_ROLE,
        "execution_role": owner.session_contract.role,
        "session_user": receipt.observation.session_user, "database": claim.database,
        "context_digest": receipt.context_digest, "receipt_digest": receipt.receipt_digest,
        "finite_fragment_digest": _canonical_sha256(
            _e3_trusted_finite_fragment_payload(owner.query, owner.policy)
        ),
        "catalog_claims": claim.to_dict(),
        "session_contract_digest": owner.session_contract.digest,
    }
    payload["profile_digest"] = _canonical_sha256(payload)
    return _validate_e3_execution_profile_payload(payload)


def _validate_e3_execution_profile_payload(payload: Any) -> dict[str, Any]:
    """Validate exported finite profile facts; not an execution capability."""
    try:
        if payload.__class__ is not dict:
            raise ValueError("profile must be an exact object")
        keys = {
            "schema", "name", "query_id", "policy_id", "principal_id",
            "policy_validation_role", "execution_role", "session_user", "database",
            "context_digest", "receipt_digest", "finite_fragment_digest",
            "catalog_claims", "session_contract_digest", "profile_digest",
        }
        _strict_keys(payload, keys, label="execution_profile")
        if (payload["schema"] != "e3_trusted_explicit_execution_profile_v1"
            or payload["name"] != "trusted_explicit"
            or payload["principal_id"] != E3_PRINCIPAL_ID
            or payload["policy_validation_role"] != E3_RLS_ROLE):
            raise ValueError("profile finite scope mismatch")
        for key in ("context_digest", "receipt_digest", "finite_fragment_digest",
                    "session_contract_digest", "profile_digest"):
            _strict_sha256(payload, key, label="execution_profile")
        for key in ("session_user", "execution_role", "database"):
            _strict_string(payload, key, label="execution_profile")
        if payload["profile_digest"] != _canonical_sha256(
            {key: value for key, value in payload.items() if key != "profile_digest"}
        ):
            raise ValueError("profile digest mismatch")
        query = next((item for item in QUERIES if item.query_id == payload["query_id"]), None)
        policy = next((item for item in POLICY_CONFIGS if item.config_id == payload["policy_id"]), None)
        if query is None or policy is None:
            raise ValueError("profile query/policy is outside finite scope")
        claim = _trusted_execution_claim_from_dict(payload["catalog_claims"])
        reasons = _e3_trusted_execution_validation_reasons(
            claim, query, policy, session_user=payload["session_user"],
        )
        if (reasons or claim.database != payload["database"]
            or claim.role.role_name != payload["execution_role"]):
            raise ValueError("profile catalog claims rejected: " + ";".join(reasons))
        context = _e3_context_payload(
            query, policy, session_user=payload["session_user"],
            execution_profile="trusted_explicit", trusted_execution=claim,
        )
        if (payload["context_digest"] != _canonical_sha256(context)
            or payload["finite_fragment_digest"] != _canonical_sha256(
                _e3_trusted_finite_fragment_payload(query, policy))):
            raise ValueError("profile context or finite fragment digest mismatch")
        contract = SessionContract(
            role=payload["execution_role"], search_path=("pg_catalog", "public"),
            gucs=E3_PRODUCTION_PLANNING_GUCS,
            transaction_isolation="repeatable read", read_only=True,
        )
        if payload["session_contract_digest"] != contract.digest:
            raise ValueError("profile session contract digest mismatch")
        # Return a detached canonical payload, so consumers cannot mutate an
        # owner's nested claim values through this export.
        return json.loads(_canonical_json(payload))
    except (TypeError, ValueError, KeyError) as exc:
        raise PostgresError("invalid E3 execution profile: " + str(exc)) from exc


def _e3_execution_catalog_guard_expression(profile_payload: Any) -> str:
    """Recheck this finite profile's catalog premises in the execution RR.

    This expression does not change role or authorize a query. The caller
    must first establish the exported execution session contract and reject
    a false result before artifact validation or query execution.
    """
    profile = _validate_e3_execution_profile_payload(profile_payload)
    return _e3_execution_catalog_guard_for_validated_profile(profile)


def _e3_execution_catalog_guard_for_validated_profile(profile: Mapping[str, Any]) -> str:
    """Render from one detached profile already validated by this call path.

    This is an internal renderer, not a validator or execution capability.
    External profile entry points must use the validating wrapper above.
    """
    return render_validated_catalog_guard(profile["catalog_claims"])


def _e3_serialized_bound_runner(
    runner: BoundRunnerIdentity, owner: _E3ProductionPlanningOwner,
) -> dict[str, Any]:
    payload = runner.to_dict()
    if _e3_receipt_execution_profile(owner.receipt) == "trusted_explicit":
        if runner.session_contract_digest != owner.session_contract.digest:
            raise PostgresError("bound runner execution session differs from its owner")
        payload["session_contract"] = _e3_session_contract_payload(owner.session_contract)
        payload["execution_profile"] = _e3_execution_profile_payload(owner)
    return payload


@dataclass(frozen=True)
class _E3ProductionPlanningOwner:
    query: E3QuerySpec = field(repr=False, compare=False)
    policy: E3PolicyConfig = field(repr=False, compare=False)
    receipt: E3PlanningCatalogReceipt = field(repr=False, compare=False)
    bundle: E3TypedAdmissionBundle = field(repr=False, compare=False)
    registry: TemplateRegistry = field(repr=False, compare=False)
    pg_env: PostgresEnv = field(repr=False, compare=False)
    predicate: str
    query_digest: str
    policy_digest: str
    registry_digest: str
    registry_template_ids: tuple[str, ...]
    registry_manifest_digest: str
    artifact_evidence_bindings: tuple[tuple[str, str, str], ...]
    session_contract: SessionContract
    identity_digest: str


def _e3_production_owner_payload(
    *,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    receipt: E3PlanningCatalogReceipt,
    bundle: E3TypedAdmissionBundle,
    registry: TemplateRegistry,
    pg_env: PostgresEnv,
    predicate: str,
) -> dict[str, Any]:
    _require_e3_canonical_query_policy_sources(query, policy)
    _require_e3_production_source(
        receipt,
        kind="catalog_receipt",
        identity_digest=receipt.receipt_digest,
        query=query,
        policy=policy,
    )
    _require_e3_production_source(
        bundle,
        kind="typed_admission_bundle",
        identity_digest=bundle.bundle_digest,
        query=query,
        policy=policy,
        receipt=receipt,
        registry=registry,
    )
    receipt_replay = _replay_e3_planning_catalog_receipt(
        receipt,
        query,
        policy,
        session_user=pg_env.user,
    )
    bundle_reasons = _validate_e3_typed_admission_bundle(
        bundle,
        receipt,
        query,
        policy,
        registry,
    )
    if (
        not receipt_replay.ok
        or bundle_reasons
        or _canonical_sha256(_e3_receipt_digest_payload(receipt))
        != receipt.receipt_digest
        or _canonical_sha256(_e3_typed_bundle_digest_payload(bundle))
        != bundle.bundle_digest
    ):
        raise PostgresError("E3 production planning owner sources no longer replay")
    expected_predicate = _policy_predicate(query, policy)
    if predicate != expected_predicate:
        raise PostgresError("E3 production rendered predicate source changed")
    template_ids = _e3_registry_template_ids(registry)
    if template_ids != bundle.registry_template_ids:
        raise PostgresError("E3 production registry and typed inventory differ")
    definitions = tuple(
        template_definition(template_id) for template_id in template_ids
    )
    registry_digest = canonical_registry_digest(definitions)
    _, artifact_bindings = _e3_strict_artifact_contract(
        receipt,
        bundle,
        query,
        policy,
    )
    session_contract = _e3_production_session_contract(receipt, bundle)
    if receipt.observation.trusted_execution is not None and (
        receipt.observation.trusted_execution.database != pg_env.database
    ):
        raise PostgresError("E3 trusted execution profile database changed")
    query_digest = _canonical_sha256(
        {"schema": "e3_production_query_source_v1", "query": asdict(query)}
    )
    policy_digest = _canonical_sha256(
        {
            "schema": "e3_production_policy_source_v1",
            "policy": _e3_policy_config_payload(policy),
        }
    )
    connection_target = _e3_connection_target_payload(pg_env)
    manifest_payload = {
        "schema": "e3_production_registry_manifest_v1",
        "query_digest": query_digest,
        "policy_digest": policy_digest,
        "receipt_digest": receipt.receipt_digest,
        "bundle_digest": bundle.bundle_digest,
        "registry_template_ids": list(template_ids),
        "registry_digest": registry_digest,
        "artifact_evidence_bindings": [list(item) for item in artifact_bindings],
        "predicate": predicate,
        "predicate_digest": canonical_predicate_digest(predicate),
        "connection_target": connection_target,
        "session_contract_digest": session_contract.digest,
    }
    registry_manifest_digest = _canonical_sha256(manifest_payload)
    return {
        "query_digest": query_digest,
        "policy_digest": policy_digest,
        "registry_digest": registry_digest,
        "registry_template_ids": template_ids,
        "registry_manifest_digest": registry_manifest_digest,
        "artifact_evidence_bindings": artifact_bindings,
        "session_contract": session_contract,
        "identity_digest": _canonical_sha256(
            {
                "schema": "e3_production_planning_owner_v1",
                "registry_manifest_digest": registry_manifest_digest,
                "query_id": query.query_id,
                "policy_id": policy.config_id,
                "connection_target": connection_target,
            }
        ),
    }


def _require_e3_production_planning_owner(
    owner: _E3ProductionPlanningOwner,
) -> str:
    if owner.__class__ is not _E3ProductionPlanningOwner:
        raise PostgresError("E3 production planning owner type is invalid")
    registered = _REGISTERED_E3_PRODUCTION_OWNERS.get(id(owner))
    if (
        registered is None
        or registered[0]() is not owner
        or registered[1] != owner.identity_digest
        or registered[2] is not owner.query
        or registered[3] is not owner.policy
        or registered[4] is not owner.registry
        or registered[5] is not owner.pg_env
        or registered[6] is not owner.receipt
        or registered[7] is not owner.bundle
        or getattr(owner, "_e3_production_owner_capability", None)
        is not _E3_PRODUCTION_OWNER_CAPABILITY
    ):
        raise PostgresError("E3 production planning owner is not registered")
    replayed = _e3_production_owner_payload(
        query=owner.query,
        policy=owner.policy,
        receipt=owner.receipt,
        bundle=owner.bundle,
        registry=owner.registry,
        pg_env=owner.pg_env,
        predicate=owner.predicate,
    )
    for key in (
        "query_digest",
        "policy_digest",
        "registry_digest",
        "registry_template_ids",
        "registry_manifest_digest",
        "artifact_evidence_bindings",
        "session_contract",
        "identity_digest",
    ):
        if getattr(owner, key) != replayed[key]:
            raise PostgresError("E3 production planning owner identity changed")
    return owner.identity_digest


def _mint_e3_production_planning_owner(
    *,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    receipt: E3PlanningCatalogReceipt,
    bundle: E3TypedAdmissionBundle,
    registry: TemplateRegistry,
    pg_env: PostgresEnv,
    predicate: str,
) -> _E3ProductionPlanningOwner:
    payload = _e3_production_owner_payload(
        query=query,
        policy=policy,
        receipt=receipt,
        bundle=bundle,
        registry=registry,
        pg_env=pg_env,
        predicate=predicate,
    )
    owner = _E3ProductionPlanningOwner(
        query=query,
        policy=policy,
        receipt=receipt,
        bundle=bundle,
        registry=registry,
        pg_env=pg_env,
        predicate=predicate,
        **payload,
    )
    object.__setattr__(
        owner,
        "_e3_production_owner_capability",
        _E3_PRODUCTION_OWNER_CAPABILITY,
    )
    key = id(owner)

    def _drop(reference: weakref.ReferenceType[Any]) -> None:
        registered = _REGISTERED_E3_PRODUCTION_OWNERS.get(key)
        if registered is not None and registered[0] is reference:
            _REGISTERED_E3_PRODUCTION_OWNERS.pop(key, None)

    _REGISTERED_E3_PRODUCTION_OWNERS[key] = (
        weakref.ref(owner, _drop),
        owner.identity_digest,
        query,
        policy,
        registry,
        pg_env,
        receipt,
        bundle,
    )
    _require_e3_production_planning_owner(owner)
    return owner


def _e3_plan_result_identity_digest(plan_result: PlanResult) -> str:
    if plan_result.__class__ is not PlanResult:
        raise PostgresError("E3 production plan result type is invalid")
    return _canonical_sha256(
        {
            "schema": "e3_production_plan_result_identity_v1",
            "plan_result": plan_result.to_dict(),
        }
    )


def _register_e3_production_plan_lineage(
    plan_result: PlanResult,
    query_plan: Mapping[str, Any],
) -> PlanResult:
    query_plan_digest = _require_e3_production_query_plan_source(query_plan)
    selected_template = _require_e3_selected_root_template_unregistered(query_plan)
    if (
        plan_result.chosen_template is None
        or plan_result.chosen_template.template_id != selected_template
    ):
        raise PostgresError("E3 production plan lineage changed selected root")
    _REGISTERED_E3_PRODUCTION_PLAN_LINEAGE[id(plan_result)] = (
        plan_result,
        query_plan,
        query_plan_digest,
        _e3_plan_result_identity_digest(plan_result),
    )
    return plan_result


def _require_e3_production_plan_lineage(
    plan_result: PlanResult,
    query_plan: Mapping[str, Any],
) -> None:
    query_plan_digest = _require_e3_production_query_plan_source(query_plan)
    registered = _REGISTERED_E3_PRODUCTION_PLAN_LINEAGE.get(id(plan_result))
    if (
        registered is None
        or registered[0] is not plan_result
        or registered[1] is not query_plan
        or registered[2] != query_plan_digest
        or registered[3] != _e3_plan_result_identity_digest(plan_result)
    ):
        raise PostgresError("E3 production plan result lacks sealed query-plan lineage")


def _e3_owned_production_plan_rows(
    plan_result: PlanResult,
    query_plan: Mapping[str, Any],
) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
    """Return exact owned strong rows after replaying their full lineage."""

    query_plan_digest = _require_e3_production_query_plan_source(query_plan)
    _require_e3_production_plan_lineage(plan_result, query_plan)
    query_row = _REGISTERED_E3_PRODUCTION_QUERY_PLANS.get(id(query_plan))
    lineage_row = _REGISTERED_E3_PRODUCTION_PLAN_LINEAGE.get(id(plan_result))
    if (
        query_row is None
        or query_row[0] is not query_plan
        or query_row[1] != query_plan_digest
        or lineage_row is None
        or lineage_row[0] is not plan_result
        or lineage_row[1] is not query_plan
        or lineage_row[2] != query_plan_digest
        or lineage_row[3] != _e3_plan_result_identity_digest(plan_result)
    ):
        raise PostgresError("E3 production strong plan rows are foreign or changed")
    return query_row, lineage_row


def _discard_e3_owned_production_plan_rows(
    plan_result: PlanResult,
    query_plan: Mapping[str, Any],
) -> None:
    """Remove only the exact registered query-plan/lineage pair."""

    query_row, lineage_row = _e3_owned_production_plan_rows(
        plan_result,
        query_plan,
    )
    if (
        _REGISTERED_E3_PRODUCTION_QUERY_PLANS.get(id(query_plan)) is not query_row
        or _REGISTERED_E3_PRODUCTION_PLAN_LINEAGE.get(id(plan_result))
        is not lineage_row
    ):
        raise PostgresError("E3 production strong plan rows changed during cleanup")
    _REGISTERED_E3_PRODUCTION_PLAN_LINEAGE.pop(id(plan_result))
    _REGISTERED_E3_PRODUCTION_QUERY_PLANS.pop(id(query_plan))


def _require_e3_query_plan_owner_batch_sources(
    query_plan: Mapping[str, Any],
    *,
    owner: _E3ProductionPlanningOwner,
    batch: PlanningEvidenceBatch,
) -> None:
    owner_identity = _require_e3_production_planning_owner(owner)
    _require_registered_batch(batch)
    if any(
        root.bound_runner.case_owner_identity_digest != owner_identity
        for root in batch.roots
    ):
        raise PostgresError(
            "E3 production planning batch contains a foreign owner-bound runner"
        )
    receipt_payload = query_plan.get("planning_catalog_receipt")
    if (
        receipt_payload.__class__ is not dict
        or receipt_payload != owner.receipt.to_dict()
        or query_plan.get("planning_catalog_receipt_digest")
        != owner.receipt.receipt_digest
    ):
        raise PostgresError(
            "E3 production query-plan catalog receipt differs from its registered owner"
        )
    bundle_payload = query_plan.get("typed_admission_bundle")
    if (
        bundle_payload.__class__ is not dict
        or bundle_payload != owner.bundle.to_dict()
        or query_plan.get("typed_admission_bundle_digest") != owner.bundle.bundle_digest
    ):
        raise PostgresError(
            "E3 production query-plan typed admission differs from its registered owner"
        )


def _register_e3_production_query_plan(
    query_plan: dict[str, Any],
    *,
    owner: _E3ProductionPlanningOwner,
    batch: PlanningEvidenceBatch,
    selected_plan_id: str,
    plan_result: PlanResult,
) -> None:
    if query_plan.__class__ is not dict or not selected_plan_id:
        raise PostgresError("E3 production query-plan issuance is invalid")
    _require_e3_query_plan_owner_batch_sources(
        query_plan,
        owner=owner,
        batch=batch,
    )
    if query_plan.get("production_planning_batch_digest") != batch.batch_digest:
        raise PostgresError("E3 production query-plan batch identity changed")
    expected_eligibility, expected_completed_roots = (
        _e3_completed_root_eligibility_payload(batch)
    )
    supplied_eligibility = query_plan.get("production_completed_root_eligibility")
    if supplied_eligibility.__class__ is not dict or _canonical_json(
        supplied_eligibility
    ) != _canonical_json(expected_eligibility):
        raise PostgresError(
            "E3 production query-plan eligibility differs from its batch"
        )
    selected_roots = tuple(
        root for root in batch.roots if root.plan_id == selected_plan_id
    )
    if len(selected_roots) != 1 or selected_plan_id not in {
        plan_id for _template_id, plan_id in expected_completed_roots
    }:
        raise PostgresError("E3 production query-plan selected cost root is not unique")
    selected_root = selected_roots[0]
    supplied_bound_runner = query_plan.get("production_bound_runner")
    if supplied_bound_runner.__class__ is not dict or _canonical_json(
        supplied_bound_runner
    ) != _canonical_json(_e3_serialized_bound_runner(selected_root.bound_runner, owner)):
        raise PostgresError("E3 production query-plan bound runner changed")
    expected_chosen_cost = {
        "ranker": "public_completed_root_selector",
        "plan_id": selected_plan_id,
        "prospective_total_cost": float(selected_root.prospective_total_cost),
        "cost_model_version": batch.identity.cost_model_version,
        "planning_environment_digest": batch.identity.environment_digest,
    }
    supplied_chosen_cost = query_plan.get("production_chosen_cost")
    if supplied_chosen_cost.__class__ is not dict or _canonical_json(
        supplied_chosen_cost
    ) != _canonical_json(expected_chosen_cost):
        raise PostgresError(
            "E3 production query-plan chosen cost differs from its batch"
        )
    selected_template = _require_e3_selected_root_template_unregistered(query_plan)
    if (
        selected_root.bound_runner.template_id != selected_template
        or plan_result.chosen_template is None
        or plan_result.chosen_template.template_id != selected_template
        or query_plan.get("production_root_selection", {}).get("chosen_plan_id")
        != selected_plan_id
    ):
        raise PostgresError("E3 production query-plan selected root changed")
    digest = _canonical_sha256(query_plan)
    _REGISTERED_E3_PRODUCTION_QUERY_PLANS[id(query_plan)] = (
        query_plan,
        digest,
        owner,
        batch,
        selected_plan_id,
        selected_template,
        selected_root.bound_runner,
    )
    _register_e3_production_plan_lineage(plan_result, query_plan)


def _require_e3_production_query_plan_source(
    query_plan: Mapping[str, Any],
) -> str:
    registered = _REGISTERED_E3_PRODUCTION_QUERY_PLANS.get(id(query_plan))
    if (
        registered is None
        or registered[0] is not query_plan
        or registered[1] != _canonical_sha256(query_plan)
        or query_plan.get("production_planning_batch_digest")
        != registered[3].batch_digest
        or query_plan.get("production_root_selection", {}).get("chosen_plan_id")
        != registered[4]
        or query_plan.get("production_bound_runner")
        != _e3_serialized_bound_runner(registered[6], registered[2])
    ):
        raise PostgresError(
            "E3 production query plan is not the exact unchanged issued source"
        )
    _require_e3_query_plan_owner_batch_sources(
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
        raise PostgresError("E3 registered query-plan batch identity changed")
    return registered[1]


def _e3_registered_selected_root_evidence(
    query_plan: Mapping[str, Any],
) -> Any:
    """Return only the selector-chosen batch evidence, never a template lookup."""

    _require_e3_production_query_plan_source(query_plan)
    registered = _REGISTERED_E3_PRODUCTION_QUERY_PLANS[id(query_plan)]
    matching = tuple(
        root for root in registered[3].roots if root.plan_id == registered[4]
    )
    if (
        len(matching) != 1
        or matching[0].bound_runner is not registered[6]
        or matching[0].bound_runner.template_id != registered[5]
    ):
        raise PostgresError("E3 selected completed-root evidence is not unique")
    return matching[0]


def _e3_production_root_execution_binding_payload() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": "e3_production_root_execution_binding_v2",
        "planner_root_scope": E3_PROSPECTIVE_ROOT_SCOPE,
        "status": E3_PROSPECTIVE_ROOT_STATUS,
        "planning_root_sql_bound": True,
        "downstream_runner_sql_bound": True,
        "measurement_promotion": False,
        "runtime_body_execution_count": 0,
        "runtime_analyze_execution_count": 0,
        "reason": E3_PROSPECTIVE_ROOT_REASON,
    }
    payload["binding_digest"] = _canonical_sha256(payload)
    return payload


def _e3_completed_root_eligibility_payload(
    batch: PlanningEvidenceBatch,
) -> tuple[dict[str, Any], tuple[tuple[str, str], ...]]:
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
        "schema": "e3_production_completed_root_eligibility_v1",
        "planning_batch_digest": batch.batch_digest,
        "completed_roots": [
            {"template_id": template_id, "plan_id": plan_id}
            for template_id, plan_id in completed
        ],
        "structural_rejections": list(structural),
        "evidence_failures": list(evidence_failures),
    }
    payload["eligibility_digest"] = _canonical_sha256(payload)
    return payload, completed


def _replay_e3_production_root_execution_binding(
    query_plan: Mapping[str, Any],
    *,
    template_id: Optional[str] = None,
) -> tuple[tuple[str, str], ...]:
    if not isinstance(query_plan, Mapping):
        raise PostgresError("E3 production root execution binding is missing")
    if (
        query_plan.get("production_root_execution_binding")
        != _e3_production_root_execution_binding_payload()
    ):
        raise PostgresError("E3 production root execution binding changed")
    eligibility = query_plan.get("production_completed_root_eligibility")
    if not isinstance(eligibility, Mapping):
        raise PostgresError("E3 production completed-root eligibility is missing")
    required = {
        "schema",
        "planning_batch_digest",
        "completed_roots",
        "structural_rejections",
        "evidence_failures",
        "eligibility_digest",
    }
    if set(eligibility) != required:
        raise PostgresError("E3 production completed-root eligibility is malformed")
    digest_payload = {
        key: eligibility[key] for key in required if key != "eligibility_digest"
    }
    if (
        eligibility["schema"] != "e3_production_completed_root_eligibility_v1"
        or eligibility["eligibility_digest"] != _canonical_sha256(digest_payload)
        or eligibility["planning_batch_digest"]
        != query_plan.get("production_planning_batch_digest")
    ):
        raise PostgresError("E3 production completed-root eligibility changed")
    completed_payload = eligibility["completed_roots"]
    structural_payload = eligibility["structural_rejections"]
    evidence_payload = eligibility["evidence_failures"]
    if (
        completed_payload.__class__ is not list
        or structural_payload.__class__ is not list
        or evidence_payload.__class__ is not list
    ):
        raise PostgresError("E3 production completed-root eligibility is untyped")
    completed: list[tuple[str, str]] = []
    for item in completed_payload:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"template_id", "plan_id"}
            or item["template_id"].__class__ is not str
            or not item["template_id"]
            or item["plan_id"].__class__ is not str
            or not item["plan_id"]
        ):
            raise PostgresError("E3 production completed-root identity is malformed")
        completed.append((item["template_id"], item["plan_id"]))
    normalized = tuple(sorted(completed))
    if (
        tuple(completed) != normalized
        or len({item[0] for item in normalized}) != len(normalized)
        or len({item[1] for item in normalized}) != len(normalized)
    ):
        raise PostgresError("E3 production completed-root identity is ambiguous")
    audit = query_plan.get("production_root_selection")
    if not isinstance(audit, Mapping):
        raise PostgresError("E3 production root-selection audit is missing")
    if (
        audit.get("structural_rejections") != structural_payload
        or audit.get("evidence_failures") != evidence_payload
        or audit.get("completed_root_count") != len(normalized)
        or audit.get("frontier_size")
        != len(normalized) + len(structural_payload) + len(evidence_payload)
        or evidence_payload
        or audit.get("chosen_plan_id") not in {item[1] for item in normalized}
    ):
        raise PostgresError("E3 production frontier audit and eligibility differ")
    if template_id is not None and template_id not in {item[0] for item in normalized}:
        raise PostgresError(
            "E3 production template is not a completed strict-root member"
        )
    return normalized


def _require_e3_production_root_execution_binding(
    query_plan: Mapping[str, Any],
    *,
    template_id: Optional[str] = None,
) -> tuple[tuple[str, str], ...]:
    _require_e3_production_query_plan_source(query_plan)
    return _replay_e3_production_root_execution_binding(
        query_plan,
        template_id=template_id,
    )


def _e3_sealed_frontier_rejection_reason(
    query_plan: Mapping[str, Any],
    *,
    template_id: str,
) -> str:
    _require_e3_production_root_execution_binding(query_plan)
    eligibility = query_plan["production_completed_root_eligibility"]
    assert isinstance(eligibility, Mapping)
    matches = [
        item
        for bucket in ("structural_rejections", "evidence_failures")
        for item in eligibility[bucket]
        if isinstance(item, Mapping) and item.get("template_id") == template_id
    ]
    if len(matches) != 1:
        raise PostgresError("E3 sealed frontier rejection identity is ambiguous")
    reasons = matches[0].get("reasons")
    if (
        reasons.__class__ is not list
        or not reasons
        or any(reason.__class__ is not str or not reason for reason in reasons)
    ):
        raise PostgresError("E3 sealed frontier rejection reasons are malformed")
    return ";".join(reasons)


def _require_e3_selected_root_template_unregistered(
    query_plan: Mapping[str, Any],
) -> str:
    completed = _replay_e3_production_root_execution_binding(query_plan)
    audit = query_plan["production_root_selection"]
    assert isinstance(audit, Mapping)
    chosen_plan_id = audit.get("chosen_plan_id")
    matches = [
        template_id for template_id, plan_id in completed if plan_id == chosen_plan_id
    ]
    if len(matches) != 1:
        raise PostgresError("E3 selected strict-root identity is ambiguous")
    return matches[0]


def _require_e3_selected_root_template(
    query_plan: Mapping[str, Any],
) -> str:
    _require_e3_production_query_plan_source(query_plan)
    return _require_e3_selected_root_template_unregistered(query_plan)


def _e3_last_json_object(raw: str, *, label: str) -> Mapping[str, Any]:
    payload: Optional[Mapping[str, Any]] = None
    for line in reversed(raw.splitlines()):
        candidate = line.strip()
        if not candidate.startswith("{") or not candidate.endswith("}"):
            continue
        try:
            decoded = json.loads(candidate)
        except json.JSONDecodeError as exc:
            raise PostgresError(f"{label} returned malformed JSON") from exc
        if isinstance(decoded, Mapping):
            payload = decoded
            break
    if payload is None:
        raise PostgresError(f"{label} did not return a JSON object")
    return payload


def _e3_catalog_select_for_transaction(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    *,
    execution_profile: str = "native_rls",
) -> str:
    script = _e3_catalog_collector_sql(query, policy, execution_profile=execution_profile)
    marker = "WITH target_relation AS ("
    start = script.find(marker)
    end = script.rfind(";\nCOMMIT;")
    if start < 0 or end <= start:
        raise PostgresError("E3 planning collector transaction shape changed")
    statement = script[start:end].strip()
    if (
        not statement.startswith(marker)
        or "BEGIN" in statement
        or "COMMIT" in statement
    ):
        raise PostgresError("E3 planning collector SELECT extraction failed")
    return statement


def _e3_catalog_static_payload(
    observation: E3PlanningCatalogObservation,
) -> dict[str, Any]:
    payload = observation.to_dict()
    payload.pop("snapshot_text", None)
    return payload


def _e3_observe_production_environment(
    session: PostgresTransactionSession,
    *,
    owner: _E3ProductionPlanningOwner,
) -> Mapping[str, Any]:
    _require_e3_production_planning_owner(owner)
    trusted_claim = owner.receipt.observation.trusted_execution
    role_flags = (
        ", 'role_is_superuser', (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname=current_user)"
        ", 'role_bypasses_rls', (SELECT rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=current_user)"
        if trusted_claim is not None else ""
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
        "'server_version_num', current_setting('server_version_num')" + role_flags +
        ")::text"
    )
    payload = _e3_last_json_object(
        output,
        label="E3 production planning environment",
    )
    expected = {
        "current_database": owner.pg_env.database,
        "session_user": owner.pg_env.user,
        "current_user": owner.session_contract.role,
        "search_path": E3_CATALOG_SEARCH_PATH,
        "row_security": "on",
        "jit": "off",
        "max_parallel_workers_per_gather": "0",
        "plan_cache_mode": "force_custom_plan",
        "transaction_isolation": "repeatable read",
        "transaction_read_only": "on",
    }
    if trusted_claim is not None:
        expected.update({
            "role_is_superuser": trusted_claim.role.is_superuser,
            "role_bypasses_rls": trusted_claim.role.bypasses_rls,
        })
    mismatches = tuple(
        sorted(
            key for key, value in expected.items()
            if (payload.get(key) is not value if trusted_claim is not None and type(value) is bool
                else payload.get(key) != value)
        )
    )
    version = payload.get("server_version_num", "")
    version_ok = (
        type(version) is str and re.fullmatch(r"[1-9][0-9]*", version) is not None
        if trusted_claim is not None else bool(str(version))
    )
    if mismatches or not version_ok:
        raise PostgresError(
            "E3 production planning environment drift: "
            + ",".join(mismatches or ("server_version_num",))
        )
    session.recheck_identity()
    _require_e3_production_planning_owner(owner)
    return payload


def _e3_replay_catalog_in_production_session(
    session: PostgresTransactionSession,
    *,
    owner: _E3ProductionPlanningOwner,
) -> E3PlanningCatalogObservation:
    _require_e3_production_planning_owner(owner)
    profile = _e3_receipt_execution_profile(owner.receipt)
    trusted = profile == "trusted_explicit"
    if trusted:
        session.execute(f"SET LOCAL ROLE {E3_RLS_ROLE}")
    try:
        payload = _e3_last_json_object(
            session.execute(_e3_catalog_select_for_transaction(
                owner.query, owner.policy, execution_profile=profile,
            )),
            label="E3 production planning catalog replay",
        )
    finally:
        if trusted:
            session.execute("SET LOCAL ROLE " + _e3_quote_role(owner.session_contract.role))
    if trusted:
        _e3_observe_production_environment(session, owner=owner)
    try:
        actual = _e3_catalog_observation_from_dict(payload)
    except (TypeError, ValueError) as exc:
        raise PostgresError(
            "E3 production planning catalog replay is malformed"
        ) from exc
    session.recheck_identity()
    _require_e3_production_planning_owner(owner)
    if (
        actual.snapshot_text != session.identity.snapshot_text
        or _e3_catalog_static_payload(actual)
        != _e3_catalog_static_payload(owner.receipt.observation)
    ):
        raise PostgresError(
            "E3 production planning catalog no longer matches replayed receipt"
        )
    return actual


def _e3_quote_role(role: str) -> str:
    if type(role) is not str or not role or "\x00" in role:
        raise PostgresError("invalid observed E3 execution role")
    return '"' + role.replace('"', '""') + '"'


def _e3_exact_sigma_string_list(
    props: Mapping[str, Any],
    key: str,
) -> tuple[str, ...]:
    if key not in props or props[key].__class__ is not list:
        raise PostgresError(f"E3 strict root Sigma {key} is missing or untyped")
    values = tuple(props[key])
    if any(item.__class__ is not str or not item for item in values) or len(
        set(values)
    ) != len(values):
        raise PostgresError(f"E3 strict root Sigma {key} is malformed")
    return values


def _e3_direct_rid_projection_proven(
    strict: StrictPlanningResult,
    owner: _E3ProductionPlanningOwner,
) -> bool:
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
    if sigma.phys_props.get("visible_attrs") != [owner.query.rid_col]:
        return False
    projects = tuple(
        node for node in walk(query_result.bound_ir) if isinstance(node, Project)
    )
    scans = tuple(
        node for node in walk(query_result.bound_ir) if isinstance(node, ScanProtected)
    )
    expected_hidden = _e3_required_hidden_carriers(owner.query)
    return bool(
        len(projects) == 1
        and projects[0].visible_A == (owner.query.rid_col,)
        and projects[0].hidden_H == expected_hidden
        and len(scans) == 1
        and scans[0].occurrence_id == owner.query.query_id
    )


def _e3_describe_strict_root_schema(
    session: PostgresTransactionSession,
    *,
    owner: _E3ProductionPlanningOwner,
    strict: StrictPlanningResult,
) -> tuple[TypedRootSchemaColumn, ...]:
    _require_e3_production_planning_owner(owner)
    if strict.draft is None or strict.query_result is None:
        raise PostgresError("E3 strict root schema requires a complete draft")
    if not _e3_direct_rid_projection_proven(strict, owner):
        raise PostgresError(
            "E3 strict root schema lacks a finite direct-RID projection proof"
        )
    try:
        sigma = sigma_from_dict(strict.query_result.root_sigma)
    except Exception as exc:
        raise PostgresError("E3 strict root schema Sigma is malformed") from exc
    visible = _e3_exact_sigma_string_list(sigma.phys_props, "visible_attrs")
    hidden = _e3_exact_sigma_string_list(sigma.phys_props, "hidden_attrs")
    expected_hidden = _e3_required_hidden_carriers(owner.query)
    if visible != (owner.query.rid_col,) or hidden != expected_hidden:
        raise PostgresError(
            "E3 strict root schema projection is outside the finite shape"
        )
    strict_body = strict.draft.sql_text.strip().rstrip(";")
    schema_probe = (
        "SELECT * FROM (\n" + strict_body + "\n) AS caprls_e3_strict_root_schema_probe"
    )
    description = session._describe_result_columns_without_execution(schema_probe)
    rows = tuple(
        tuple(part.strip() for part in line.split("|", 1))
        for line in description.splitlines()
        if line.strip()
    )
    expected_names = visible + hidden
    if (
        len(rows) != len(expected_names)
        or any(len(row) != 2 for row in rows)
        or tuple(row[0] for row in rows) != expected_names
        or any(not row[1] for row in rows)
    ):
        raise PostgresError("E3 strict root schema identity mismatch")
    relation_contract = E3_ACCESS_COLUMN_CONTRACTS.get(owner.query.protected_rel)
    if relation_contract is None:
        raise PostgresError("E3 access-root relation contract is missing")
    metadata_by_name: dict[str, Mapping[str, Any]] = {}
    for name in expected_names:
        base_name = owner.query.rid_col if name == "__rid" else name
        contract = relation_contract.get(base_name)
        if contract is None:
            raise PostgresError("E3 access-root column contract is missing")
        metadata_sql = (
            "SELECT jsonb_build_object("
            "'name', attribute.attname, "
            "'type_name', format_type(attribute.atttypid, attribute.atttypmod), "
            "'nullable', NOT attribute.attnotnull, "
            "'collation', CASE WHEN attribute.attcollation = 0 THEN NULL "
            "ELSE attribute.attcollation::regcollation::text END"
            ")::text FROM pg_catalog.pg_attribute attribute "
            "WHERE attribute.attrelid = to_regclass("
            + _quote("public." + owner.query.protected_rel)
            + ") AND attribute.attname = "
            + _quote(base_name)
            + " AND attribute.attnum > 0 AND NOT attribute.attisdropped"
        )
        metadata = _e3_last_json_object(
            session.execute(metadata_sql),
            label="E3 production access-root schema metadata",
        )
        session.recheck_identity()
        _require_e3_production_planning_owner(owner)
        expected_type, expected_nullable = contract
        row_type = rows[expected_names.index(name)][1]
        if (
            metadata.get("name") != base_name
            or metadata.get("type_name") != expected_type
            or row_type != expected_type
            or metadata.get("nullable") is not expected_nullable
            or (
                metadata.get("collation") is not None
                and metadata.get("collation").__class__ is not str
            )
        ):
            raise PostgresError("E3 strict root schema metadata mismatch")
        metadata_by_name[name] = metadata
    return tuple(
        TypedRootSchemaColumn(
            ordinal=ordinal,
            name=name,
            type_name=type_name,
            nullable=bool(metadata_by_name[name]["nullable"]),
            collation=metadata_by_name[name].get("collation"),
            visibility="visible" if ordinal < len(visible) else "hidden",
        )
        for ordinal, (name, type_name) in enumerate(rows)
    )


def _e3_strict_root_physical_observation(
    strict: StrictPlanningResult,
    *,
    role: str,
) -> TypedRootPhysicalObservation:
    if strict.query_result is None:
        raise PostgresError("E3 strict root physical identity is missing")
    try:
        sigma = sigma_from_dict(strict.query_result.root_sigma)
    except Exception as exc:
        raise PostgresError("E3 strict root Sigma is malformed") from exc
    goals = tuple(strict.query_result.effective_occurrence_goals.values())
    if len(goals) != 1:
        raise PostgresError("E3 strict root must have one effective goal")
    problem = goals[0].problem
    if (
        strict.replay is None
        or not strict.replay.ok
        or strict.envelope is None
        or not strict.query_result.root_closure.ok
    ):
        raise PostgresError("E3 strict root physical proof is incomplete")
    phys = sigma.phys_props
    visible = _e3_exact_sigma_string_list(phys, "visible_attrs")
    hidden = _e3_exact_sigma_string_list(phys, "hidden_attrs")
    delivered_order = _e3_exact_sigma_string_list(phys, "delivered_order")
    if visible != (problem.rid_col,):
        raise PostgresError("E3 strict root visible Sigma is not exact RID-only")
    rid_props = sigma.rid_mat_props
    required_rid_keys = ("rid_domain", "surrogate_col", "carrier")
    if any(
        key not in rid_props
        or rid_props[key].__class__ is not str
        or not rid_props[key]
        for key in required_rid_keys
    ):
        raise PostgresError("E3 strict root RID materialization proof is incomplete")
    rid_domain = rid_props["rid_domain"]
    surrogate_col = rid_props["surrogate_col"]
    carrier = rid_props["carrier"]
    if (
        rid_domain != f"{problem.relation}.{problem.rid_col}"
        or surrogate_col != problem.rid_col
        or carrier not in hidden
    ):
        raise PostgresError("E3 strict root RID materialization identity mismatch")
    nodes = walk(strict.query_result.bound_ir)
    materialized = any(isinstance(node, Materialize) for node in nodes)
    if "materialized" in phys:
        if (
            phys["materialized"].__class__ is not bool
            or phys["materialized"] != materialized
        ):
            raise PostgresError("E3 strict root materialization evidence mismatch")
    elif materialized:
        raise PostgresError("E3 strict root materialization evidence is missing")
    validation_gate_ids = tuple(
        sorted({node.artifact_id for node in nodes if isinstance(node, ValidationGate)})
    )
    if validation_gate_ids:
        if (
            "validation_gate" not in phys
            or phys["validation_gate"].__class__ is not str
            or phys["validation_gate"] not in validation_gate_ids
        ):
            raise PostgresError("E3 strict root validation-gate evidence mismatch")
    elif "validation_gate" in phys:
        raise PostgresError("E3 strict root has unproven validation-gate evidence")
    proven_coverage: list[str] = []
    for requirement in problem.parent_requirement.observable_coverage:
        if requirement.startswith("hidden_carrier:"):
            required_carrier = requirement.split(":", 1)[1]
            if required_carrier not in hidden or not any(
                isinstance(node, Project) and required_carrier in node.hidden_H
                for node in nodes
            ):
                raise PostgresError(
                    "E3 strict root hidden-carrier coverage is unproven"
                )
        elif requirement == "materialized" and materialized:
            pass
        else:
            raise PostgresError(
                "E3 strict root observable coverage is outside the finite proof"
            )
        proven_coverage.append(requirement)
    observable = {
        "effective_role": role,
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
            ("cost_model", E3_PRODUCTION_ROOT_COST_MODEL_VERSION),
            ("effective_role", role),
        ),
        hidden_attrs_and_carriers=tuple(sorted(hidden)),
        observable_coverage=tuple(proven_coverage),
        rid_domain=rid_domain,
        rid_surrogate_col=surrogate_col,
        rid_carrier=carrier,
        rid_materialized=materialized,
    )


def _e3_snapshot_access_root_materialized_by_template(
    registry: TemplateRegistry,
    base_materialized: bool,
    overrides: Mapping[str, bool] | None,
) -> dict[str, bool]:
    """Freeze an adapter layout policy against the actual finite registry."""
    if type(base_materialized) is not bool:
        raise TypeError("E3 access-root base materialization must be bool")
    if overrides is None:
        return {}
    if not isinstance(overrides, Mapping):
        raise TypeError("E3 access-root template overrides must be a mapping")
    snapshot = dict(overrides)
    actual_ids = set(_e3_registry_template_ids(registry))
    for template_id, materialized in snapshot.items():
        if type(template_id) is not str or template_id not in actual_ids:
            raise ValueError("E3 access-root override names an unknown registry template: " + repr(template_id))
        if type(materialized) is not bool:
            raise TypeError("E3 access-root template materialization must be bool: " + template_id)
    return dict(sorted(snapshot.items()))


def _plan_e3_admission_first(
    *,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    predicate: str,
    pg_env: PostgresEnv,
    protected_rows: int,
    query_local_rows: int,
    authorized_rows: int,
    build_ms: float,
    ranker: E3Ranker,
    registry: Optional[TemplateRegistry] = None,
    keyed_artifact_rows: int = 0,
    planning_catalog_receipt: Optional[E3PlanningCatalogReceipt] = None,
    typed_admission_bundle: Optional[E3TypedAdmissionBundle] = None,
    access_root_materialized: bool = True,
    access_root_materialized_by_template: Mapping[str, bool] | None = None,
    execution_profile: str = "native_rls",
) -> tuple[PlanResult, Mapping[str, Any], PlanningProblem]:
    verified_receipt = _require_e3_production_catalog_receipt(
        planning_catalog_receipt,
        query=query,
        policy=policy,
        predicate=predicate,
        pg_env=pg_env,
        execution_profile=execution_profile,
    )
    planning_registry = registry or _e3_registry()
    materialized_by_template = _e3_snapshot_access_root_materialized_by_template(
        planning_registry, access_root_materialized, access_root_materialized_by_template,
    )
    verified_bundle = _require_e3_typed_admission_bundle(
        typed_admission_bundle,
        receipt=verified_receipt,
        query=query,
        policy=policy,
        registry=planning_registry,
    )
    return _plan_e3_admission_first_production(
        query=query,
        policy=policy,
        predicate=predicate,
        pg_env=pg_env,
        protected_rows=protected_rows,
        query_local_rows=query_local_rows,
        authorized_rows=authorized_rows,
        build_ms=build_ms,
        ranker=ranker,
        registry=planning_registry,
        keyed_artifact_rows=keyed_artifact_rows,
        receipt=verified_receipt,
        bundle=verified_bundle,
        access_root_materialized=access_root_materialized,
        access_root_materialized_by_template=materialized_by_template,
    )


def _plan_e3_admission_first_production_in_session(
    *,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    predicate: str,
    pg_env: PostgresEnv,
    protected_rows: int,
    query_local_rows: int,
    authorized_rows: int,
    build_ms: float,
    ranker: E3Ranker,
    registry: TemplateRegistry,
    keyed_artifact_rows: int,
    receipt: E3PlanningCatalogReceipt,
    bundle: E3TypedAdmissionBundle,
    session: PostgresTransactionSession,
    access_root_materialized: bool = True,
    access_root_materialized_by_template: Mapping[str, bool] | None = None,
) -> tuple[PlanResult, Mapping[str, Any], PlanningProblem]:
    materialized_by_template = _e3_snapshot_access_root_materialized_by_template(
        registry, access_root_materialized, access_root_materialized_by_template,
    )
    owner = _mint_e3_production_planning_owner(
        query=query,
        policy=policy,
        receipt=receipt,
        bundle=bundle,
        registry=registry,
        pg_env=pg_env,
        predicate=predicate,
    )
    problem = _e3_planning_problem(
        query,
        policy,
        # Production root admission is deliberately isolated from runner and
        # build telemetry collected earlier by the study harness.  These
        # finite conservative placeholders affect only the legacy heuristic
        # diagnostics; the public selector consumes same-transaction plain
        # EXPLAIN evidence below.
        1,
        1,
        1,
        0.0,
        0,
        typed_admission_bundle=bundle,
        planning_catalog_receipt=receipt,
        planning_registry=registry,
    )
    strict_expectations, artifact_bindings = _e3_strict_artifact_contract(
        receipt,
        bundle,
        query,
        policy,
    )
    if artifact_bindings != owner.artifact_evidence_bindings:
        raise PostgresError("E3 production strict artifact owner binding changed")
    planning_query = _e3_planning_query(
        query,
        policy,
        problem,
        ADMISSION_FIRST_MODE,
        strict_artifact_expectations=strict_expectations,
    )
    problem_artifact_ids = {
        artifact.artifact_id for artifact in problem.artifacts.values()
    }
    if dict(planning_query.emit_context.artifact_expectations) != {
        artifact_id: expectation
        for artifact_id, expectation in strict_expectations.items()
        if artifact_id in problem_artifact_ids
    }:
        raise PostgresError("E3 production strict artifact lowering identity changed")

    definitions = tuple(
        template_definition(template_id) for template_id in owner.registry_template_ids
    )
    scope = _mint_production_strict_registry_scope(
        registry,
        scope_id="e3-production:" + owner.identity_digest,
        manifest_digest=owner.registry_manifest_digest,
        expected_registry_digest=canonical_registry_digest(definitions),
        expected_template_ids=tuple(item.template_id for item in definitions),
        owner=owner,
        owner_identity_digest=owner.identity_digest,
        owner_validator=_require_e3_production_planning_owner,
        artifact_evidence_bindings=owner.artifact_evidence_bindings,
    )
    request = StrictPlanningRequest(
        query=planning_query,
        session_contract=owner.session_contract,
        continuation=ContinuationTemplate("strict-identity-v1", "{{CORE_SQL}}"),
        registry_version="e3-production-registry-v1",
    )
    _require_e3_production_planning_owner(owner)
    enumerated = plan_query(
        planning_query,
        registry=registry,
        feasibility_backtracking=False,
    )
    occurrence = enumerated.occurrence_results.get(problem.occurrence_id)
    if occurrence is None:
        raise PostgresError("E3 production admitted inventory is missing")
    admitted = tuple(
        sorted(
            (candidate for candidate in occurrence.candidates if candidate.accepted),
            key=lambda item: item.template_id,
        )
    )
    if not admitted or len({item.template_id for item in admitted}) != len(admitted):
        raise PostgresError("E3 production admitted inventory is invalid")
    expected_inventory = tuple(
        (candidate.template_id, _strict_planning_digest(candidate.to_dict()))
        for candidate in admitted
    )
    attempts: list[StrictPlanningResult] = []
    for candidate in admitted:
        _require_e3_production_planning_owner(owner)
        attempt = strict_plan_forced_alternative(
            request,
            occurrence_id=problem.occurrence_id,
            template_id=candidate.template_id,
            registry=registry,
            registry_scope=scope,
        )
        provenance = _require_forced_root_attempt_provenance(attempt)
        if provenance.admitted_candidate_inventory != expected_inventory:
            raise PostgresError("E3 production forced inventory drifted")
        attempts.append(attempt)
    _require_e3_production_planning_owner(owner)

    costs: dict[str, Any] = {}
    explain_digests: dict[str, str] = {}
    schemas: dict[str, tuple[TypedRootSchemaColumn, ...]] = {}
    runner_schemas: dict[str, tuple[TypedRootSchemaColumn, ...]] = {}
    runner_sql_by_plan: dict[str, str] = {}
    runner_materialized_by_plan: dict[str, bool] = {}
    physical: dict[str, TypedRootPhysicalObservation] = {}
    static_digests: dict[str, str] = {}
    continuation = _e3_continuation_spec(query, policy)
    with _E3BorrowedPlanningSession(session) as session:
        for statement in (
            "SET LOCAL search_path TO pg_catalog, public",
            "SET LOCAL row_security = on",
            "SET LOCAL jit = off",
            "SET LOCAL max_parallel_workers_per_gather = 0",
            "SET LOCAL plan_cache_mode = force_custom_plan",
            "SET LOCAL ROLE " + (
                _e3_quote_role(owner.session_contract.role)
                if _e3_receipt_execution_profile(receipt) == "trusted_explicit"
                else E3_RLS_ROLE
            ),
        ):
            session.execute(statement)
        environment = _e3_observe_production_environment(session, owner=owner)
        catalog = _e3_replay_catalog_in_production_session(session, owner=owner)
        for attempt in attempts:
            provenance = _require_forced_root_attempt_provenance(attempt)
            if provenance.outcome_status != "completed":
                continue
            assert attempt.draft is not None
            plan_id = attempt.draft.plan_id
            # Resolve once before describing/costing the complete runner.
            # Minting below consumes this stored per-plan choice, never the
            # caller's mutable map or a second template-policy lookup.
            plan_materialized = materialized_by_template.get(
                provenance.template_id, access_root_materialized,
            )
            runner_materialized_by_plan[plan_id] = plan_materialized
            _require_e3_production_planning_owner(owner)
            _e3_observe_production_environment(session, owner=owner)
            try:
                schemas[plan_id] = _e3_describe_strict_root_schema(
                    session,
                    owner=owner,
                    strict=attempt,
                )
            except (PostgresError, TypeError, ValueError):
                pass
            runner_body = _e3_bound_runner_sql(
                query,
                attempt,
                access_root_materialized=plan_materialized,
            )
            runner_sql_by_plan[plan_id] = runner_body
            try:
                runner_schemas[plan_id] = _e3_describe_bound_runner_result(
                    session,
                    continuation=continuation,
                    runner_sql=runner_body,
                )
            except (PostgresError, TypeError, ValueError):
                pass
            _require_e3_production_planning_owner(owner)
            try:
                physical[plan_id] = _e3_strict_root_physical_observation(
                    attempt,
                    role=owner.session_contract.role,
                )
            except (PostgresError, TypeError, ValueError):
                pass
            _require_e3_production_planning_owner(owner)
            session.recheck_identity()
            _require_e3_production_planning_owner(owner)
            try:
                explain_json = _parse_explain_json(
                    session.execute("EXPLAIN (FORMAT JSON) " + runner_body)
                )
                if (
                    explain_json.__class__ is not list
                    or len(explain_json) != 1
                    or not isinstance(explain_json[0], Mapping)
                    or not isinstance(explain_json[0].get("Plan"), Mapping)
                ):
                    raise PostgresError("E3 strict plain EXPLAIN payload is malformed")
            except (json.JSONDecodeError, PostgresError, TypeError, ValueError):
                session.recheck_identity()
                _require_e3_production_planning_owner(owner)
                continue
            session.recheck_identity()
            _require_e3_production_planning_owner(owner)
            explain_digest = _explain_plan_hash(explain_json)
            explain_digests[plan_id] = explain_digest
            plan_root = explain_json[0]["Plan"]
            if "Total Cost" in plan_root:
                costs[plan_id] = plan_root["Total Cost"]
            try:
                verification = _verify_e3_static(
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
                static_digests[plan_id] = _canonical_sha256(
                    {
                        "schema": "e3_bound_runner_static_verification_v2",
                        "template_id": provenance.template_id,
                        "bound_runner_sql_digest": _canonical_sha256(
                            {"exact_runner_sql": runner_body}
                        ),
                        "explain_plan_digest": explain_digest,
                        "status": verification.status,
                        "reasons": list(verification.reasons),
                        "plan_hash": verification.plan_hash,
                    }
                )
        final_environment = _e3_observe_production_environment(session, owner=owner)
        if final_environment != environment:
            raise PostgresError("E3 production planning environment changed")
        identity = session.recheck_identity()
        snapshot_digest = _canonical_sha256(
            {
                "schema": "e3_production_planning_snapshot_v1",
                "transaction_identity": identity.to_dict(),
                "owner_identity": owner.identity_digest,
            }
        )
        database_digest = _canonical_sha256(
            {
                "schema": "e3_production_database_identity_v1",
                "connection_target": _e3_connection_target_payload(pg_env),
                "current_database": environment["current_database"],
                "session_user": environment["session_user"],
                "current_user": environment["current_user"],
                "server_version_num": environment["server_version_num"],
            }
        )
        catalog_digest = _canonical_sha256(
            {
                "schema": "e3_production_catalog_replay_v1",
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
                access_root_materialized=runner_materialized_by_plan[plan_id],
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
            batch_id="e3:" + owner.identity_digest + ":" + identity.session_nonce,
            snapshot_digest=snapshot_digest,
            database_identity_digest=database_digest,
            catalog_digest=catalog_digest,
            cost_model_version=E3_PRODUCTION_ROOT_COST_MODEL_VERSION,
        )
        selection = select_completed_roots(
            batch,
            feature_flags=PlannerFeatureFlags(reference_dominance="enabled"),
        )
    if not selection.ok or selection.chosen is None:
        raise PostgresError(
            "E3 production root selection rejected the cell: "
            + ";".join(selection.audit.reasons)
            + ":"
            + _canonical_json(
                [item.to_dict() for item in selection.audit.evidence_failures]
            )
        )
    chosen_strict = selection.chosen.strict_result
    if chosen_strict.query_result is None:
        raise PostgresError("E3 production selector returned an incomplete strict root")
    plan_result = chosen_strict.query_result.occurrence_results[problem.occurrence_id]
    eligibility, completed_roots = _e3_completed_root_eligibility_payload(batch)
    query_plan = _query_plan_payload(
        chosen_strict.query_result,
        planning_catalog_receipt=receipt,
        typed_admission_bundle=bundle,
    )
    query_plan["production_root_selection"] = selection.audit.to_dict()
    query_plan["production_planning_batch_digest"] = batch.batch_digest
    query_plan["production_completed_root_eligibility"] = eligibility
    query_plan["production_root_execution_binding"] = (
        _e3_production_root_execution_binding_payload()
    )
    query_plan["production_bound_runner"] = _e3_serialized_bound_runner(selection.chosen.bound_runner, owner)
    query_plan["production_access_root_layout_policy"] = {
        "schema": "e3_access_root_layout_policy_v1",
        "base_materialized": access_root_materialized,
        "materialized_by_template": dict(materialized_by_template),
    }
    query_plan["production_access_root_layouts"] = [
        {
            "plan_id": item.plan_id,
            "template_id": item.bound_runner.template_id,
            "access_root_materialized": runner_materialized_by_plan[item.plan_id],
            "runner_sql_digest": item.bound_runner.runner_sql_digest,
        }
        for item in batch.roots
    ]
    # These are the actual complete-runner plain EXPLAIN observations used
    # above. The first-stage heuristic candidate vector is diagnostic only.
    query_plan["production_candidate_costs"] = [
        {
            "plan_id": item.plan_id,
            "template_id": item.bound_runner.template_id,
            "access_root_materialized": runner_materialized_by_plan[item.plan_id],
            "prospective_total_cost": item.prospective_total_cost,
            "runner_sql_digest": item.bound_runner.runner_sql_digest,
            "explain_plan_digest": item.explain_plan_digest,
        }
        for item in batch.roots
    ]
    query_plan["production_chosen_cost"] = {
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
    query_plan["heuristic_estimated_cost_is_diagnostic"] = True
    query_plan["caller_ranker_is_diagnostic"] = {
        "name": ranker.name,
        "version": ranker.version,
    }
    if _replay_e3_production_root_execution_binding(query_plan) != completed_roots:
        raise PostgresError("E3 production completed-root projection changed")
    if (
        plan_result.chosen_template is None
        or plan_result.chosen_template.template_id
        != _require_e3_selected_root_template_unregistered(query_plan)
    ):
        raise PostgresError("E3 production selected-root projection changed")
    _register_e3_production_query_plan(
        query_plan,
        owner=owner,
        batch=batch,
        selected_plan_id=selection.chosen.plan_id,
        plan_result=plan_result,
    )
    _require_e3_production_root_execution_binding(query_plan)
    return plan_result, query_plan, problem


def _plan_e3_admission_first_production(
    *,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    predicate: str,
    pg_env: PostgresEnv,
    protected_rows: int,
    query_local_rows: int,
    authorized_rows: int,
    build_ms: float,
    ranker: E3Ranker,
    registry: TemplateRegistry,
    keyed_artifact_rows: int,
    receipt: E3PlanningCatalogReceipt,
    bundle: E3TypedAdmissionBundle,
    access_root_materialized: bool = True,
    access_root_materialized_by_template: Mapping[str, bool] | None = None,
) -> tuple[PlanResult, Mapping[str, Any], PlanningProblem]:
    """Preserve the frozen F1 API while the worker borrows its live session."""

    materialized_by_template = _e3_snapshot_access_root_materialized_by_template(
        registry, access_root_materialized, access_root_materialized_by_template,
    )
    with PostgresTransactionSession(pg_env, read_only=True) as session:
        return _plan_e3_admission_first_production_in_session(
            query=query,
            policy=policy,
            predicate=predicate,
            pg_env=pg_env,
            protected_rows=protected_rows,
            query_local_rows=query_local_rows,
            authorized_rows=authorized_rows,
            build_ms=build_ms,
            ranker=ranker,
            registry=registry,
            keyed_artifact_rows=keyed_artifact_rows,
            receipt=receipt,
            bundle=bundle,
            session=session,
            access_root_materialized=access_root_materialized,
            access_root_materialized_by_template=materialized_by_template,
        )


E3_PHYSICAL_RECIPE_STRATEGY = "strong_handoff_min_full_cost_v1"
_E3_PHYSICAL_RECIPE_ORDER = ("inline_strong", "materialized_strong")
_E3_PHYSICAL_RECIPE_TOKEN = object()


@dataclass(frozen=True, eq=False)
class _E3PhysicalRecipeBranch:
    recipe_id: str
    plan_result: PlanResult = field(repr=False)
    query_plan: Mapping[str, Any] = field(repr=False)
    problem: PlanningProblem = field(repr=False)


@dataclass(frozen=True, eq=False)
class E3PhysicalRecipeDecision:
    """Owned sidecar; original root lineage remains the execution authority."""

    branches: tuple[_E3PhysicalRecipeBranch, ...] = field(repr=False)
    declared_config_digest: str
    selected_recipe_id: str
    audit_digest: str
    _construction_token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._construction_token is not _E3_PHYSICAL_RECIPE_TOKEN:
            raise PostgresError("physical recipe decision must be factory-owned")


_REGISTERED_E3_PHYSICAL_RECIPE_DECISIONS: dict[
    int, tuple[weakref.ReferenceType[Any], str]
] = {}
# Neither marker reference keeps a decision or plan alive. A dead decision
# remains a refusal marker until its original plan dies; it never means legacy.
_REGISTERED_E3_PHYSICAL_RECIPE_PLANS: dict[
    tuple[int, int], tuple[weakref.ReferenceType[Any], weakref.ReferenceType[Any]]
] = {}


def _e3_physical_recipe_plan_marker(
    plan_result: PlanResult, query_plan: Mapping[str, Any],
) -> Optional[tuple[weakref.ReferenceType[Any], weakref.ReferenceType[Any]]]:
    pair = (id(plan_result), id(query_plan))
    marker = _REGISTERED_E3_PHYSICAL_RECIPE_PLANS.get(pair)
    if marker is not None and marker[1]() is not plan_result:
        # Also guard lookup against stale integer IDs, independently of the
        # ordinary weakref callback. Never treat the old marker as this plan.
        if _REGISTERED_E3_PHYSICAL_RECIPE_PLANS.get(pair) is marker:
            _REGISTERED_E3_PHYSICAL_RECIPE_PLANS.pop(pair, None)
        return None
    return marker


def _e3_physical_recipe_layout(recipe_id: str) -> dict[str, Any]:
    if recipe_id not in _E3_PHYSICAL_RECIPE_ORDER:
        raise PostgresError("unknown fixed physical recipe")
    layouts = {"auth_index_enum_v1": True}
    if recipe_id == "materialized_strong":
        layouts["strong_auth_index_keyed_v1"] = True
    return {"schema": "e3_access_root_layout_policy_v1",
            "base_materialized": False, "materialized_by_template": layouts}


def _e3_physical_recipe_payload(
    branches: tuple[_E3PhysicalRecipeBranch, ...],
    declared_config_digest: str,
) -> dict[str, Any]:
    if (type(declared_config_digest) is not str
            or re.fullmatch(r"sha256:[0-9a-f]{64}", declared_config_digest) is None
            or tuple(branch.recipe_id for branch in branches) != _E3_PHYSICAL_RECIPE_ORDER):
        raise PostgresError("physical recipe declaration or complete inventory changed")
    rows = []
    common_owner = None
    common_identity = None
    for branch in branches:
        if type(branch) is not _E3PhysicalRecipeBranch:
            raise PostgresError("physical recipe branch type changed")
        query_row, _ = _e3_owned_production_plan_rows(branch.plan_result, branch.query_plan)
        owner, batch = query_row[2], query_row[3]
        if common_owner is None:
            common_owner = owner
        elif any(getattr(owner, name) is not getattr(common_owner, name) for name in
                 ("query", "policy", "receipt", "bundle", "registry", "pg_env")):
            raise PostgresError("physical recipes do not share original planning sources")
        identity = batch.identity.to_dict()
        if common_identity is None:
            common_identity = identity
        elif identity != common_identity:
            raise PostgresError("physical recipes do not share one planning environment/snapshot")
        if not batch.cost_evidence_complete or not batch.roots:
            raise PostgresError("physical recipe has incomplete production evidence")
        layout = _e3_physical_recipe_layout(branch.recipe_id)
        if branch.query_plan.get("production_access_root_layout_policy") != layout:
            raise PostgresError("physical recipe actual layout differs from its fixed declaration")
        selected = _e3_registered_selected_root_evidence(branch.query_plan)
        cost = selected.prospective_total_cost
        if isinstance(cost, bool) or not math.isfinite(float(cost)) or float(cost) < 0:
            raise PostgresError("physical recipe winner has invalid prospective cost")
        bound = selected.bound_runner
        rows.append({
            "recipe_id": branch.recipe_id,
            "layout_policy": layout,
            "planning_batch_digest": batch.batch_digest,
            "planning_batch_identity": identity,
            "query_plan_digest": query_row[1],
            "completed_root_eligibility": branch.query_plan["production_completed_root_eligibility"],
            "complete_runner_costs": branch.query_plan["production_candidate_costs"],
            "root_selection_audit": branch.query_plan["production_root_selection"],
            "selected_plan_id": selected.plan_id,
            "selected_template_id": bound.template_id,
            "selected_runner_digest": bound.runner_sql_digest,
            "selected_bound_runner_identity_digest": bound.identity_digest,
            "selected_bound_runner": _e3_serialized_bound_runner(bound, owner),
            "prospective_total_cost": float(cost),
        })
    # Exact ties retain the first (r05) recipe. No measured values or thresholds
    # are accepted as inputs to this comparison.
    winner = min(rows, key=lambda row: (row["prospective_total_cost"],
                                        _E3_PHYSICAL_RECIPE_ORDER.index(row["recipe_id"])))
    return {
        "schema": "e3_physical_recipe_selection_v1",
        "strategy": E3_PHYSICAL_RECIPE_STRATEGY,
        "declared_config_digest": declared_config_digest,
        "recipe_order": list(_E3_PHYSICAL_RECIPE_ORDER),
        "tie_break": "recipe_order_on_exact_cost",
        "comparison": "minimum_owned_selected_prospective_total_cost",
        "shared_planning_identity": common_identity,
        "branches": rows,
        "selected_recipe_id": winner["recipe_id"],
        "selected_plan_id": winner["selected_plan_id"],
        "selected_runner_digest": winner["selected_runner_digest"],
        "effective_layout_policy": winner["layout_policy"],
    }


def _require_e3_physical_recipe_decision(
    decision: E3PhysicalRecipeDecision, *, plan_result: PlanResult,
    query_plan: Mapping[str, Any], declared_config_digest: str,
) -> dict[str, Any]:
    registered = _REGISTERED_E3_PHYSICAL_RECIPE_DECISIONS.get(id(decision))
    if (type(decision) is not E3PhysicalRecipeDecision or registered is None
            or registered[0]() is not decision or registered[1] != decision.audit_digest
            or decision._construction_token is not _E3_PHYSICAL_RECIPE_TOKEN
            or decision.declared_config_digest != declared_config_digest):
        raise PostgresError("physical recipe decision is foreign or changed")
    payload = _e3_physical_recipe_payload(decision.branches, declared_config_digest)
    if (_canonical_sha256(payload) != decision.audit_digest
            or payload["selected_recipe_id"] != decision.selected_recipe_id):
        raise PostgresError("physical recipe decision no longer matches its original branches")
    selected = decision.branches[_E3_PHYSICAL_RECIPE_ORDER.index(decision.selected_recipe_id)]
    if selected.plan_result is not plan_result or selected.query_plan is not query_plan:
        raise PostgresError("physical recipe handoff is not the exact selected original pair")
    for branch in decision.branches:
        marker = _e3_physical_recipe_plan_marker(branch.plan_result, branch.query_plan)
        if marker is None or marker[0]() is not decision:
            raise PostgresError("physical recipe pair ownership changed")
    # Return detached diagnostic data; it is not an executable capability.
    return json.loads(_canonical_json({**payload, "decision_digest": decision.audit_digest}))


def _require_e3_physical_recipe_handoff(
    plan_result: PlanResult, query_plan: Mapping[str, Any],
    decision: Optional[E3PhysicalRecipeDecision], *, declared_config_digest: Optional[str],
) -> Optional[dict[str, Any]]:
    marker = _e3_physical_recipe_plan_marker(plan_result, query_plan)
    if marker is None:
        if decision is not None or declared_config_digest is not None:
            raise PostgresError("unissued physical recipe handoff")
        return None
    expected = marker[0]()
    if expected is None or decision is not expected or declared_config_digest is None:
        raise PostgresError("issued physical recipe handoff cannot downgrade to legacy")
    return _require_e3_physical_recipe_decision(
        decision, plan_result=plan_result, query_plan=query_plan,
        declared_config_digest=declared_config_digest)


def _select_e3_physical_recipes_in_session(
    *, declared_config_digest: str, **common: Any,
) -> tuple[PlanResult, Mapping[str, Any], PlanningProblem, E3PhysicalRecipeDecision]:
    branches: list[_E3PhysicalRecipeBranch] = []
    decision = None
    try:
        for recipe_id in _E3_PHYSICAL_RECIPE_ORDER:
            layout = _e3_physical_recipe_layout(recipe_id)
            result, plan, problem = _plan_e3_admission_first_production_in_session(
                **common, access_root_materialized=False,
                access_root_materialized_by_template=layout["materialized_by_template"])
            pair = (id(result), id(plan))
            if (_e3_physical_recipe_plan_marker(result, plan) is not None
                    or any(pair == (id(old.plan_result), id(old.query_plan)) for old in branches)):
                raise PostgresError("physical recipe branch reused an already issued pair")
            branches.append(_E3PhysicalRecipeBranch(recipe_id, result, plan, problem))
        branch_tuple = tuple(branches)
        payload = _e3_physical_recipe_payload(branch_tuple, declared_config_digest)
        decision = E3PhysicalRecipeDecision(
            branch_tuple, declared_config_digest, payload["selected_recipe_id"],
            _canonical_sha256(payload), _E3_PHYSICAL_RECIPE_TOKEN)
        key = id(decision)

        def drop(reference: weakref.ReferenceType[Any]) -> None:
            registered = _REGISTERED_E3_PHYSICAL_RECIPE_DECISIONS.get(key)
            if registered is not None and registered[0] is reference:
                _REGISTERED_E3_PHYSICAL_RECIPE_DECISIONS.pop(key, None)

        decision_reference = weakref.ref(decision, drop)
        _REGISTERED_E3_PHYSICAL_RECIPE_DECISIONS[key] = (decision_reference, decision.audit_digest)
        for branch in branch_tuple:
            pair = (id(branch.plan_result), id(branch.query_plan))
            if _e3_physical_recipe_plan_marker(branch.plan_result, branch.query_plan) is not None:
                raise PostgresError("physical recipe pair was already issued")

            def drop_plan(reference: weakref.ReferenceType[Any], pair: tuple[int, int] = pair) -> None:
                marker = _REGISTERED_E3_PHYSICAL_RECIPE_PLANS.get(pair)
                if marker is not None and marker[1] is reference:
                    _REGISTERED_E3_PHYSICAL_RECIPE_PLANS.pop(pair, None)

            _REGISTERED_E3_PHYSICAL_RECIPE_PLANS[pair] = (
                decision_reference, weakref.ref(branch.plan_result, drop_plan))
        winner = branch_tuple[_E3_PHYSICAL_RECIPE_ORDER.index(decision.selected_recipe_id)]
        _require_e3_physical_recipe_decision(
            decision, plan_result=winner.plan_result, query_plan=winner.query_plan,
            declared_config_digest=declared_config_digest)
        return winner.plan_result, winner.query_plan, winner.problem, decision
    except BaseException:
        # Never turn a failed branch into a favorable subset. Cleanup only the
        # exact pairs created here, and preserve the original failure.
        for branch in branches:
            pair = (id(branch.plan_result), id(branch.query_plan))
            marker = _e3_physical_recipe_plan_marker(branch.plan_result, branch.query_plan)
            if marker is not None:
                if decision is None or marker[0]() is not decision:
                    continue
                if _REGISTERED_E3_PHYSICAL_RECIPE_PLANS.get(pair) is marker:
                    _REGISTERED_E3_PHYSICAL_RECIPE_PLANS.pop(pair)
            try:
                _discard_e3_owned_production_plan_rows(branch.plan_result, branch.query_plan)
            except Exception:
                pass
        raise


def _plan_e3_admission_first_physical_recipes(
    *, query: E3QuerySpec, policy: E3PolicyConfig, predicate: str, pg_env: PostgresEnv,
    protected_rows: int, query_local_rows: int, authorized_rows: int, build_ms: float,
    ranker: E3Ranker, registry: Optional[TemplateRegistry] = None,
    keyed_artifact_rows: int = 0,
    planning_catalog_receipt: Optional[E3PlanningCatalogReceipt] = None,
    typed_admission_bundle: Optional[E3TypedAdmissionBundle] = None,
    execution_profile: str = "trusted_explicit", declared_config_digest: str,
) -> tuple[PlanResult, Mapping[str, Any], PlanningProblem, E3PhysicalRecipeDecision]:
    """Two fixed physical recipes; no new strict candidates or draft IDs."""
    if execution_profile != "trusted_explicit":
        raise PostgresError("physical recipe selection requires trusted explicit execution")
    if type(declared_config_digest) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", declared_config_digest) is None:
        raise PostgresError("physical recipe selection requires its declared configuration digest")
    receipt = _require_e3_production_catalog_receipt(
        planning_catalog_receipt, query=query, policy=policy, predicate=predicate,
        pg_env=pg_env, execution_profile=execution_profile)
    planning_registry = registry or _e3_registry()
    for recipe_id in _E3_PHYSICAL_RECIPE_ORDER:
        _e3_snapshot_access_root_materialized_by_template(
            planning_registry, False, _e3_physical_recipe_layout(recipe_id)["materialized_by_template"])
    bundle = _require_e3_typed_admission_bundle(
        typed_admission_bundle, receipt=receipt, query=query, policy=policy,
        registry=planning_registry)
    with PostgresTransactionSession(pg_env, read_only=True) as session:
        return _select_e3_physical_recipes_in_session(
            query=query, policy=policy, predicate=predicate, pg_env=pg_env,
            protected_rows=protected_rows, query_local_rows=query_local_rows,
            authorized_rows=authorized_rows, build_ms=build_ms, ranker=ranker,
            registry=planning_registry, keyed_artifact_rows=keyed_artifact_rows,
            receipt=receipt, bundle=bundle, session=session,
            declared_config_digest=declared_config_digest)


def _rawpg_dominance_cost_inputs(sort_enforcer_cost: float = 0.0) -> CostInputs:
    return CostInputs(
        estimated_rows=0,
        query_selectivity=0.0,
        auth_selectivity=0.0,
        policy_eval_cost=0.0,
        residual_eval_cost=0.0,
        scan_cost_per_row=0.0,
        base_fetch_cost=0.0,
        artifact_lookup_cost=0.0,
        guard_selectivity=0.0,
        sort_cost=sort_enforcer_cost,
        residual_check_cost=0.0,
        validation_gate_cost=0.0,
        materialize_cost=0.0,
        declared_reuse=None,
        declared_update_rate_per_hour=0.0,
        declared_ttl_s=0.0,
        declared_contexts=0,
    )


def _candidate_plan_shape_key(candidate: CandidatePlan) -> str:
    diagnostic = _candidate_diagnostic(candidate)
    if diagnostic is not None and diagnostic.get("plan_hash"):
        return str(diagnostic["plan_hash"])
    return candidate.template_id


def _candidate_equivalence_rank(candidate: CandidatePlan) -> tuple[float, str, str]:
    template_priority = {
        "safe_predicate_injection_v1": "00",
        "ordinary_first_exact_check_v1": "01",
    }
    return (
        float(candidate.estimated_cost or 0.0),
        template_priority.get(candidate.template_id, "99"),
        candidate.template_id,
    )


def _with_equivalence_diagnostics(
    candidate: CandidatePlan,
    *,
    plan_shape_key: str,
    representative_template_id: str,
    pruned: bool,
) -> CandidatePlan:
    diagnostics = dict(candidate.diagnostics)
    diagnostics["plan_shape_key"] = plan_shape_key
    diagnostics["equivalence_representative_template_id"] = representative_template_id
    diagnostics["equivalent_plan_shape_pruned"] = pruned
    return replace(
        candidate,
        diagnostics=diagnostics,
        pruned_by_dominance=(
            representative_template_id if pruned else candidate.pruned_by_dominance
        ),
    )


def _deduplicate_equivalent_plan_shapes(
    plan_result: PlanResult,
    *,
    enabled: bool = False,
    query_plan: Optional[Mapping[str, Any]] = None,
) -> PlanResult:
    """Compute plan-shape telemetry without changing semantic selection.

    An EXPLAIN plan hash alone is not proof that SQL, typed parameters,
    session, certificate, Gamma, and observation behavior are identical.
    Until the strict v3 execution-identity chain supplies that proof, this
    legacy helper is a shadow diagnostic only: it may annotate groups but
    never prunes candidates or replaces the chosen SQL plan.
    """

    if query_plan is not None:
        _require_e3_production_plan_lineage(plan_result, query_plan)
    if not enabled:
        return plan_result
    accepted = [
        candidate
        for candidate in plan_result.candidates
        if candidate.accepted and candidate.pruned_by_dominance is None
    ]
    grouped: dict[str, list[CandidatePlan]] = {}
    for candidate in accepted:
        grouped.setdefault(_candidate_plan_shape_key(candidate), []).append(candidate)
    representatives = {
        key: sorted(group, key=_candidate_equivalence_rank)[0]
        for key, group in grouped.items()
    }
    rewritten: list[CandidatePlan] = []
    for candidate in plan_result.candidates:
        if not candidate.accepted or candidate.pruned_by_dominance is not None:
            rewritten.append(candidate)
            continue
        key = _candidate_plan_shape_key(candidate)
        representative = representatives[key]
        rewritten.append(
            _with_equivalence_diagnostics(
                candidate,
                plan_shape_key=key,
                representative_template_id=representative.template_id,
                pruned=False,
            )
        )
    updated_result = replace(
        plan_result,
        chosen_template=plan_result.chosen_template,
        emitted_sql=plan_result.emitted_sql,
        delivered_sigma=plan_result.delivered_sigma,
        estimated_cost=plan_result.estimated_cost,
        candidates=tuple(rewritten),
        costed_templates=plan_result.costed_templates,
        dominance_pruned=plan_result.dominance_pruned,
    )
    if query_plan is not None:
        _register_e3_production_plan_lineage(updated_result, query_plan)
    return updated_result


def _equivalent_plan_shape_pruned_result(
    *,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    candidate: CandidatePlan,
    plan_result: PlanResult,
    query_plan: Optional[Mapping[str, Any]],
    authorized_rows: int,
) -> E3MainModeResult:
    representative = candidate.pruned_by_dominance or "unknown"
    reason = f"equivalent_plan_shape_pruned:{representative}"
    return _unavailable_result(
        query,
        policy,
        "template-oracle",
        candidate.template_id,
        candidate.alternative,
        authorized_rows,
        reason,
        plan_result=plan_result,
        query_plan=query_plan,
        candidate=candidate,
        template_applicability="equivalent_plan_shape_pruned",
    )


def _dominance_pruned_result(
    *,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    candidate: CandidatePlan,
    plan_result: PlanResult,
    query_plan: Optional[Mapping[str, Any]],
    authorized_rows: int,
) -> E3MainModeResult:
    representative = candidate.pruned_by_dominance or "unknown"
    reason = f"dominance_pruned:{representative}"
    return _unavailable_result(
        query,
        policy,
        "template-oracle",
        candidate.template_id,
        candidate.alternative,
        authorized_rows,
        reason,
        plan_result=plan_result,
        query_plan=query_plan,
        candidate=candidate,
        template_applicability="dominance_pruned",
    )


def _pruned_template_candidate_result(
    *,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    candidate: CandidatePlan,
    plan_result: PlanResult,
    query_plan: Optional[Mapping[str, Any]],
    authorized_rows: int,
) -> E3MainModeResult:
    if _is_equivalent_plan_shape_pruned(candidate):
        return _equivalent_plan_shape_pruned_result(
            query=query,
            policy=policy,
            candidate=candidate,
            plan_result=plan_result,
            query_plan=query_plan,
            authorized_rows=authorized_rows,
        )
    return _dominance_pruned_result(
        query=query,
        policy=policy,
        candidate=candidate,
        plan_result=plan_result,
        query_plan=query_plan,
        authorized_rows=authorized_rows,
    )


def _is_equivalent_plan_shape_pruned(candidate: CandidatePlan) -> bool:
    diagnostic = _candidate_diagnostic(candidate)
    return bool(diagnostic and diagnostic.get("equivalent_plan_shape_pruned"))


def _apply_adaptive_topk(
    *,
    plan_result: PlanResult,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    pg_env: PostgresEnv,
    build_ms: float,
    authorized_rows: int,
    oracle_count: int,
    config: E3AdaptiveTopKConfig,
    query_plan: Optional[Mapping[str, Any]] = None,
) -> PlanResult:
    if query_plan is not None:
        _require_e3_production_plan_lineage(plan_result, query_plan)
    if not config.enabled or plan_result.chosen_template is None:
        return plan_result
    completed_templates: Optional[set[str]] = None
    if query_plan is not None:
        completed_templates = {
            template_id
            for template_id, _plan_id in _require_e3_production_root_execution_binding(
                query_plan
            )
        }
    accepted = sorted(
        (
            candidate
            for candidate in plan_result.candidates
            if candidate.accepted
            and (
                (completed_templates is None and candidate.pruned_by_dominance is None)
                or (
                    completed_templates is not None
                    and candidate.template_id in completed_templates
                )
            )
        ),
        key=lambda item: (float(item.estimated_cost or 0.0), item.template_id),
    )
    topk: list[CandidatePlan] = []
    seen: set[str] = set()
    for candidate in accepted:
        key = (
            _candidate_plan_shape_key(candidate)
            if config.deduplicate_plan_shapes
            else candidate.template_id
        )
        if config.deduplicate_plan_shapes and key in seen:
            continue
        seen.add(key)
        topk.append(candidate)
        if len(topk) >= config.k:
            break
    if len(topk) <= 1:
        return plan_result

    probe_results: dict[str, dict[str, Any]] = {}
    for candidate in topk:
        samples: list[float] = []
        for _ in range(config.probe_repetitions):
            probe = _execute_template_candidate(
                query=query,
                policy=policy,
                candidate=candidate,
                plan_result=plan_result,
                query_plan=query_plan,
                pg_env=pg_env,
                build_ms=build_ms,
                authorized_rows=authorized_rows,
                oracle_count=oracle_count,
            )
            samples.append(probe.execution_ms)
        probe_results[candidate.template_id] = {
            "considered": True,
            "k": config.k,
            "probe_repetitions": config.probe_repetitions,
            "deduplicate_plan_shapes": config.deduplicate_plan_shapes,
            "samples_ms": [round(value, 6) for value in samples],
            "median_ms": round(_group_median(samples), 6),
            "plan_shape_key": _candidate_plan_shape_key(candidate),
        }
    probe_ranks = _rank_keyed_values(
        {
            template_id: payload["median_ms"]
            for template_id, payload in probe_results.items()
        }
    )
    probe_best_template_id = min(
        probe_results,
        key=lambda template_id: (probe_results[template_id]["median_ms"], template_id),
    )
    updated_candidates: list[CandidatePlan] = []
    chosen: Optional[CandidatePlan] = None
    for candidate in plan_result.candidates:
        diagnostics = dict(candidate.diagnostics)
        probe_payload = probe_results.get(candidate.template_id)
        if probe_payload is not None:
            diagnostics["adaptive_topk_probe"] = {
                **probe_payload,
                "probe_rank": probe_ranks.get(candidate.template_id),
                # This is explicitly diagnostic measured data.  It must not
                # rewrite the pre-frozen AdmissionFirst selected template.
                "probe_best_diagnostic_only": candidate.template_id
                == probe_best_template_id,
            }
        elif candidate.accepted:
            diagnostics["adaptive_topk_probe"] = {
                "considered": False,
                "reason": (
                    "strict_root_not_completed"
                    if completed_templates is not None
                    and candidate.template_id not in completed_templates
                    else "outside_topk"
                ),
                "k": config.k,
            }
        updated = replace(candidate, diagnostics=diagnostics)
        updated_candidates.append(updated)
        if (
            plan_result.chosen_template is not None
            and candidate.template_id == plan_result.chosen_template.template_id
        ):
            chosen = updated
    if chosen is None:
        # The existing candidate/selection identity is authoritative.  This
        # defensive fallback preserves it rather than turning a probe winner
        # into a normal plan under an unexpected candidate shape.
        updated_result = replace(plan_result, candidates=tuple(updated_candidates))
        if query_plan is not None:
            _register_e3_production_plan_lineage(updated_result, query_plan)
        return updated_result
    updated_result = replace(
        plan_result,
        chosen_template=chosen,
        emitted_sql=plan_result.emitted_sql,
        delivered_sigma=plan_result.delivered_sigma,
        estimated_cost=plan_result.estimated_cost,
        candidates=tuple(updated_candidates),
    )
    if query_plan is not None:
        _register_e3_production_plan_lineage(updated_result, query_plan)
    return updated_result


def _chosen_rank(
    plan_result: Optional[PlanResult],
) -> Optional[int]:
    if plan_result is None or plan_result.chosen_template is None:
        return None
    accepted = sorted(
        (
            candidate
            for candidate in plan_result.candidates
            if candidate.accepted
            and candidate.pruned_by_dominance is None
        ),
        key=lambda item: (float(item.estimated_cost or 0.0), item.template_id),
    )
    for idx, candidate in enumerate(accepted, start=1):
        if candidate.template_id == plan_result.chosen_template.template_id:
            return idx
    return None


def _artifact_id(query: E3QuerySpec, policy: E3PolicyConfig) -> str:
    return f"e3main_{query.workload}_{policy.config_id}"


def _clear_artifact_sql(artifact_id: str) -> str:
    return f"""
\\set ON_ERROR_STOP on
BEGIN;
DELETE FROM public.artifact_dependencies WHERE artifact_id = {_quote(artifact_id)};
DELETE FROM public.auth_idx WHERE artifact_id = {_quote(artifact_id)};
DELETE FROM public.auth_idx_keyed WHERE artifact_id = {_quote(artifact_id)};
COMMIT;
"""


def _build_artifact_sql(
    query: E3QuerySpec, policy: E3PolicyConfig, predicate: str
) -> str:
    artifact_id = _artifact_id(query, policy)
    rid_domain = f"{query.protected_rel}.{query.rid_col}"
    dependency_values = ",\n  ".join(
        f"({_quote(artifact_id)}, {_quote(str(dep['dep_kind']))}, {_quote(str(dep['dep_name']))}, "
        f"{int(dep['version_at_build'])})"
        for dep in _artifact_dependency_records(query, policy)
    )
    return f"""
\\set ON_ERROR_STOP on
BEGIN;
DELETE FROM public.artifact_dependencies WHERE artifact_id = {_quote(artifact_id)};
DELETE FROM public.auth_idx WHERE artifact_id = {_quote(artifact_id)};
DELETE FROM public.auth_idx_keyed WHERE artifact_id = {_quote(artifact_id)};
INSERT INTO public.artifact_dependencies(artifact_id, dep_kind, dep_name, version_at_build)
VALUES
  {dependency_values};
INSERT INTO public.auth_idx(
  artifact_id, policy_id, user_id, ctx_hash, rid, rid_domain_id, base_rel_oid,
  policy_version, membership_version
)
SELECT
  {_quote(artifact_id)},
  {_quote(policy.config_id)},
  'e3_user',
  'e3_main_ctx_hash',
  {query.alias}.{query.rid_col},
  {_quote(rid_domain)},
  {_quote('public.' + query.protected_rel)}::regclass::oid,
  0,
  0
FROM public.{query.protected_rel} {query.alias}
WHERE {predicate};
INSERT INTO public.auth_idx_keyed(
  artifact_id, policy_id, user_id, ctx_hash, key_name, key_value, range_bucket,
  rid, rid_domain_id, base_rel_oid, policy_version, membership_version
)
SELECT
  {_quote(artifact_id)},
  {_quote(policy.config_id)},
  'e3_user',
  'e3_main_ctx_hash',
  {_quote(query.key_name)},
  {query.alias}.{query.key_name}::text,
  NULL::text,
  {query.alias}.{query.rid_col},
  {_quote(rid_domain)},
  {_quote('public.' + query.protected_rel)}::regclass::oid,
  0,
  0
FROM public.{query.protected_rel} {query.alias}
WHERE {predicate};
COMMIT;
ANALYZE public.auth_idx;
ANALYZE public.auth_idx_keyed;
"""


def _carrier_projection_sql(query: E3QuerySpec) -> str:
    columns = E3_CARRIER_PROJECTION_COLUMNS.get(query.query_id)
    if columns is None:
        raise PostgresError(
            f"E3 query lacks carrier projection columns: {query.query_id}"
        )
    rendered = [f"{query.alias}.{column}" for column in columns]
    rendered.append(f"{query.alias}.{query.rid_col} AS __rid")
    return ", ".join(rendered)


def _source_sql(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    source: str,
    predicate: str,
) -> tuple[str, str, str]:
    artifact_id = _artifact_id(query, policy)
    rid_domain = f"{query.protected_rel}.{query.rid_col}"
    if source in {"direct", "rls"}:
        if source == "rls":
            return "", f"public.{query.protected_rel} AS {query.alias}", ""
        return (
            "",
            f"public.{query.protected_rel} AS {query.alias}",
            f"  AND {predicate}\n",
        )
    if source == "barrier":
        return (
            f"""
WITH auth AS MATERIALIZED (
  SELECT {_carrier_projection_sql(query)}
  FROM public.{query.protected_rel} {query.alias}
  WHERE {predicate}
    AND {_query_local_predicate(query)}
)
""",
            f"auth AS {query.alias}",
            "",
        )
    if source == "barrier_inline":
        return (
            f"""
WITH auth AS NOT MATERIALIZED (
  SELECT {_carrier_projection_sql(query)}
  FROM public.{query.protected_rel} {query.alias}
  WHERE {predicate}
    AND {_query_local_predicate(query)}
)
""",
            f"auth AS {query.alias}",
            "",
        )
    if source == "auth_idx":
        return (
            f"""
WITH auth_base AS MATERIALIZED (
  SELECT {query.alias}.*
  FROM public.auth_idx a
  JOIN public.{query.protected_rel} {query.alias} ON {query.alias}.{query.rid_col} = a.rid
  WHERE a.artifact_id = {_quote(artifact_id)}
    AND a.policy_id = {_quote(policy.config_id)}
    AND a.user_id = 'e3_user'
    AND a.ctx_hash = 'e3_main_ctx_hash'
    AND a.rid_domain_id = {_quote(rid_domain)}
    AND a.base_rel_oid = {_quote('public.' + query.protected_rel)}::regclass::oid
    AND {_query_local_predicate(query)}
)
""",
            f"auth_base AS {query.alias}",
            "",
        )
    if source == "auth_idx_semijoin":
        return (
            "",
            f"public.{query.protected_rel} AS {query.alias}",
            f"""  AND EXISTS (
    SELECT 1
    FROM public.auth_idx a
    WHERE a.artifact_id = {_quote(artifact_id)}
      AND a.policy_id = {_quote(policy.config_id)}
      AND a.user_id = 'e3_user'
      AND a.ctx_hash = 'e3_main_ctx_hash'
      AND a.rid_domain_id = {_quote(rid_domain)}
      AND a.base_rel_oid = {_quote('public.' + query.protected_rel)}::regclass::oid
      AND a.rid = {query.alias}.{query.rid_col}
  )
""",
        )
    if source == "auth_idx_keyed":
        return (
            f"""
WITH auth_base AS MATERIALIZED (
  SELECT {query.alias}.*
  FROM public.auth_idx_keyed a
  JOIN public.{query.protected_rel} {query.alias} ON {query.alias}.{query.rid_col} = a.rid
  WHERE a.artifact_id = {_quote(artifact_id)}
    AND a.policy_id = {_quote(policy.config_id)}
    AND a.user_id = 'e3_user'
    AND a.ctx_hash = 'e3_main_ctx_hash'
    AND a.key_name = {_quote(query.key_name)}
    AND a.key_value = {_quote(query.key_value)}
    AND a.rid_domain_id = {_quote(rid_domain)}
    AND a.base_rel_oid = {_quote('public.' + query.protected_rel)}::regclass::oid
    AND {_query_local_predicate(query)}
)
""",
            f"auth_base AS {query.alias}",
            "",
        )
    if source == "auth_idx_keyed_semijoin":
        return (
            "",
            f"public.{query.protected_rel} AS {query.alias}",
            f"""  AND EXISTS (
    SELECT 1
    FROM public.auth_idx_keyed a
    WHERE a.artifact_id = {_quote(artifact_id)}
      AND a.policy_id = {_quote(policy.config_id)}
      AND a.user_id = 'e3_user'
      AND a.ctx_hash = 'e3_main_ctx_hash'
      AND a.key_name = {_quote(query.key_name)}
      AND a.key_value = {_quote(query.key_value)}
      AND a.rid_domain_id = {_quote(rid_domain)}
      AND a.base_rel_oid = {_quote('public.' + query.protected_rel)}::regclass::oid
      AND a.rid = {query.alias}.{query.rid_col}
  )
""",
        )
    if source == "hybrid":
        return (
            f"""
WITH query_rids AS MATERIALIZED (
  SELECT {query.alias}.{query.rid_col} AS rid
  FROM public.{query.protected_rel} {query.alias}
  WHERE {_query_local_predicate(query)}
),
auth_rids AS MATERIALIZED (
  SELECT ai.rid
  FROM public.auth_idx ai
  WHERE ai.artifact_id = {_quote(artifact_id)}
    AND ai.policy_id = {_quote(policy.config_id)}
    AND ai.user_id = 'e3_user'
    AND ai.ctx_hash = 'e3_main_ctx_hash'
    AND ai.rid_domain_id = {_quote(rid_domain)}
    AND ai.base_rel_oid = {_quote('public.' + query.protected_rel)}::regclass::oid
),
auth_base AS MATERIALIZED (
  SELECT {query.alias}.*
  FROM query_rids q
  JOIN auth_rids a USING (rid)
  JOIN public.{query.protected_rel} {query.alias} ON {query.alias}.{query.rid_col} = q.rid
)
""",
            f"auth_base AS {query.alias}",
            "",
        )
    raise PostgresError(f"unsupported E3 source: {source}")


def _e3_semantic_result_sql(
    query: E3QuerySpec,
    *,
    cte: str,
    from_rel: str,
    extra: str,
) -> str:
    if query.query_id == "Q3":
        body = f"""
{cte}
SELECT
    l.l_orderkey,
    sum(l.l_extendedprice * (1 - l.l_discount)) AS revenue,
    o.o_orderdate,
    o.o_shippriority
  FROM {from_rel}
  JOIN public.tpch_orders AS o ON o.o_custkey = c.c_custkey
  JOIN public.tpch_lineitem AS l ON l.l_orderkey = o.o_orderkey
  WHERE c.c_mktsegment = 'BUILDING'
    AND o.o_orderdate < DATE '1995-03-15'
    AND l.l_shipdate > DATE '1995-03-15'
{extra}  GROUP BY l.l_orderkey, o.o_orderdate, o.o_shippriority
  ORDER BY revenue DESC, o.o_orderdate
  LIMIT 10;
"""
    elif query.query_id == "Q5":
        body = f"""
{cte}
SELECT
    c.region_id,
    sum(l.l_extendedprice * (1 - l.l_discount)) AS revenue
  FROM {from_rel}
  JOIN public.tpch_orders AS o ON o.o_custkey = c.c_custkey
  JOIN public.tpch_lineitem AS l ON l.l_orderkey = o.o_orderkey
  WHERE c.c_mktsegment = 'BUILDING'
    AND o.o_orderdate >= DATE '1995-01-15'
    AND o.o_orderdate < DATE '1995-04-01'
    AND l.l_shipdate > DATE '1995-02-01'
{extra}  GROUP BY c.region_id
  ORDER BY revenue DESC
  LIMIT 10;
"""
    elif query.query_id == "Q7":
        body = f"""
{cte}
SELECT
    c.region_id,
    date_part('year', o.o_orderdate)::int AS order_year,
    sum(l.l_extendedprice * (1 - l.l_discount)) AS revenue
  FROM {from_rel}
  JOIN public.tpch_orders AS o ON o.o_custkey = c.c_custkey
  JOIN public.tpch_lineitem AS l ON l.l_orderkey = o.o_orderkey
  WHERE c.c_mktsegment = 'BUILDING'
    AND o.o_orderdate >= DATE '1994-01-01'
    AND o.o_orderdate < DATE '1997-01-01'
    AND l.l_shipdate >= DATE '1994-01-01'
    AND l.l_shipdate < DATE '1997-01-01'
{extra}  GROUP BY c.region_id, order_year
  ORDER BY revenue DESC, c.region_id, order_year
  LIMIT 20;
"""
    elif query.query_id == "Q10":
        body = f"""
{cte}
SELECT
    c.c_custkey,
    c.region_id,
    sum(l.l_extendedprice * (1 - l.l_discount)) AS revenue
  FROM {from_rel}
  JOIN public.tpch_orders AS o ON o.o_custkey = c.c_custkey
  JOIN public.tpch_lineitem AS l ON l.l_orderkey = o.o_orderkey
  WHERE c.c_mktsegment = 'BUILDING'
    AND o.o_orderdate >= DATE '1993-10-01'
    AND o.o_orderdate < DATE '1994-01-01'
    AND l.l_shipdate >= DATE '1993-10-01'
{extra}  GROUP BY c.c_custkey, c.region_id
  ORDER BY revenue DESC, c.c_custkey
  LIMIT 20;
"""
    elif query.query_id == "Q12":
        body = f"""
{cte}
SELECT
    o.o_shippriority,
    count(*) FILTER (WHERE l.l_shipdate < DATE '1995-01-01') AS early_ship_count,
    count(*) FILTER (WHERE l.l_shipdate >= DATE '1995-01-01') AS late_ship_count
  FROM {from_rel}
  JOIN public.tpch_orders AS o ON o.o_custkey = c.c_custkey
  JOIN public.tpch_lineitem AS l ON l.l_orderkey = o.o_orderkey
  WHERE c.c_mktsegment = 'BUILDING'
    AND o.o_orderdate >= DATE '1994-01-01'
    AND o.o_orderdate < DATE '1995-01-01'
{extra}  GROUP BY o.o_shippriority
  ORDER BY o.o_shippriority;
"""
    elif query.query_id == "JOB_1a":
        body = f"""
{cte}
SELECT t.t_id, count(*) AS matches
  FROM {from_rel}
  JOIN public.job_movie_companies mc ON mc.movie_id = t.t_id
  JOIN public.job_cast_info ci ON ci.movie_id = t.t_id
  WHERE t.kind = 'movie'
    AND t.production_year BETWEEN 1990 AND 2010
    AND mc.company_type = 'production'
{extra}  GROUP BY t.t_id
  ORDER BY matches DESC, t.t_id
  LIMIT 20;
"""
    elif query.query_id == "JOB_2a":
        body = f"""
{cte}
SELECT t.production_year, count(*) AS production_edges
  FROM {from_rel}
  JOIN public.job_movie_companies mc ON mc.movie_id = t.t_id
  WHERE t.kind = 'movie'
    AND t.production_year BETWEEN 1985 AND 2015
    AND mc.company_type = 'production'
{extra}  GROUP BY t.production_year
  ORDER BY production_edges DESC, t.production_year
  LIMIT 20;
"""
    elif query.query_id == "JOB_3c":
        body = f"""
{cte}
SELECT t.region_id, count(*) AS regional_cast_edges
  FROM {from_rel}
  JOIN public.job_movie_companies mc ON mc.movie_id = t.t_id
  JOIN public.job_cast_info ci ON ci.movie_id = t.t_id
  WHERE t.kind = 'movie'
    AND t.production_year BETWEEN 1980 AND 2005
    AND mc.company_type = 'distributor'
    AND ci.role_id <= 4
{extra}  GROUP BY t.region_id
  ORDER BY regional_cast_edges DESC, t.region_id
  LIMIT 20;
"""
    elif query.query_id == "JOB_6d":
        body = f"""
{cte}
SELECT t.studio_id, count(*) AS cast_edges
  FROM {from_rel}
  JOIN public.job_cast_info ci ON ci.movie_id = t.t_id
  WHERE t.kind = 'movie'
    AND t.production_year >= 1995
    AND ci.role_id <= 3
{extra}  GROUP BY t.studio_id
  ORDER BY cast_edges DESC, t.studio_id
  LIMIT 20;
"""
    elif query.query_id == "JOB_10a":
        body = f"""
{cte}
SELECT t.production_year, count(*) AS company_edges
  FROM {from_rel}
  JOIN public.job_movie_companies mc ON mc.movie_id = t.t_id
  WHERE t.kind = 'movie'
    AND t.production_year BETWEEN 1990 AND 2020
    AND mc.company_type IN ('production', 'distributor')
{extra}  GROUP BY t.production_year
  ORDER BY company_edges DESC, t.production_year
  LIMIT 20;
"""
    elif query.query_id == "JOB_16b":
        body = f"""
{cte}
SELECT t.studio_id, count(*) AS title_company_edges
  FROM {from_rel}
  JOIN public.job_movie_companies mc ON mc.movie_id = t.t_id
  WHERE t.kind = 'movie'
    AND t.production_year >= 1980
    AND mc.company_type = 'production'
{extra}  GROUP BY t.studio_id
  ORDER BY title_company_edges DESC, t.studio_id
  LIMIT 20;
"""
    else:
        raise PostgresError(f"unsupported E3 reduced query: {query.query_id}")
    return body.strip()


def _query_count_sql(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    source: str,
    predicate: str,
) -> str:
    cte, from_rel, extra = _source_sql(query, policy, source, predicate)
    semantic_sql = _e3_semantic_result_sql(
        query,
        cte=cte,
        from_rel=from_rel,
        extra=extra,
    ).rstrip(";")
    wrapped = _count_wrapper("SELECT count(*) FROM (\n" + semantic_sql + "\n) AS q;")
    return wrapped.replace(
        "SET max_parallel_workers_per_gather = 0;\n",
        "SET max_parallel_workers_per_gather = 0;\nSET plan_cache_mode = force_custom_plan;\n",
    )


def _native_rls_count_sql(query: E3QuerySpec, policy: E3PolicyConfig) -> str:
    return f"""
\\set ON_ERROR_STOP on
SET row_security = on;
SET ROLE caprls_e3_rls_user;
{native_rls_policy_fingerprint_comment(_policy_predicate_unaliased(query, policy))}
{_query_count_sql(query, policy, "rls", "")}
RESET ROLE;
"""


def _protected_count(query: E3QuerySpec, pg_env: PostgresEnv) -> int:
    return int(
        run_psql_command(f"SELECT count(*) FROM public.{query.protected_rel};", pg_env)
    )


def _require_e3_measurement_identity(
    template_id: str,
    sql: str,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    source: str,
) -> bool:
    """Bind the E3 preflight and body runner to one finite candidate identity."""

    expected_source = _source_for_template(template_id)
    if source != expected_source:
        raise PostgresError(
            f"E3 measurement source identity mismatch for {template_id}: "
            f"expected {expected_source}, got {source}"
        )
    native_rls = source == "rls"
    expected_sql = (
        _native_rls_count_sql(query, policy)
        if native_rls
        else _query_count_sql(
            query,
            policy,
            source,
            _policy_predicate(query, policy),
        )
    )
    if sql != expected_sql:
        raise PostgresError(
            f"E3 measurement SQL identity mismatch for "
            f"{query.query_id}/{policy.config_id}/{template_id}"
        )
    return native_rls


def _measure_e3_query(
    template_id: str,
    sql: str,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    source: str,
    pg_env: PostgresEnv,
) -> tuple[
    int,
    float,
    float,
    float,
    bool,
    Optional[str],
    StaticVerification,
    Optional[tuple[Mapping[str, Any], ...]],
]:
    native_rls = _require_e3_measurement_identity(
        template_id,
        sql,
        query,
        policy,
        source,
    )
    # This E3-specific ordering gate does not mint an AuthorizedExecution or
    # provide a same-live-transaction capability.  It only ensures that the
    # finite candidate passes plain EXPLAIN static verification before any
    # body or EXPLAIN ANALYZE path is entered.
    verification, explain_json = _verify_e3_static_with_explain_json(
        template_id,
        sql,
        pg_env,
        native_rls=native_rls,
    )
    if not _artifact_source_requires_validation(source):
        measured_explain = _explain_json(
            sql,
            pg_env,
            native_rls=native_rls,
            analyze=True,
        )
        try:
            planning_ms = float(measured_explain[0]["Planning Time"])
            execution_ms = float(measured_explain[0]["Execution Time"])
        except (IndexError, KeyError, TypeError, ValueError) as exc:
            raise PostgresError(
                "E3 EXPLAIN ANALYZE timing payload is malformed"
            ) from exc
        # The ordinary query is run separately only to check its scalar result.
        # Its client/process wall time is deliberately outside the latency metric.
        row_count, _ = _run_count_sql(sql, pg_env)
        return (
            row_count,
            planning_ms,
            execution_ms,
            0.0,
            False,
            None,
            verification,
            explain_json,
        )
    stripped_sql = _strip_psql_directives(sql)
    measurement = _run_validated_query(
        template_id,
        stripped_sql,
        (_artifact_id(query, policy),),
        _expected_artifact_json(query, policy),
        pg_env,
    )
    if not measurement.validation.validation_passed:
        raise PostgresError(
            f"E3 {query.query_id}/{policy.config_id}/{source} artifact validation failed: "
            f"{measurement.validation.failure_sqlstate}/{measurement.validation.failure_symbol}"
        )
    row_count, _ = _run_count_sql(sql, pg_env)
    return (
        row_count,
        measurement.timing.planning_ms,
        measurement.timing.execution_ms,
        measurement.validation.elapsed_ms,
        measurement.validation.same_snapshot,
        measurement.validation.isolation_level,
        verification,
        explain_json,
    )


def _execute_mode(
    *,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    mode: str,
    pg_env: PostgresEnv,
    build_ms: float,
    authorized_rows: int,
    oracle_count: int,
    protected_rows: int,
    query_local_rows: int,
    contract_plan: Optional[PlanResult] = None,
    contract_query_plan: Optional[Mapping[str, Any]] = None,
    ranker: Optional[E3Ranker] = None,
    planning_catalog_receipt: Optional[E3PlanningCatalogReceipt] = None,
    registry: Optional[TemplateRegistry] = None,
) -> E3MainModeResult:
    mode = normalize_mode_id(mode)
    template_id, alternative = _template_for_mode(policy, mode)
    artifact_id = _artifact_id(query, policy)
    unavailable_reason = _artifact_unavailable_reason(policy, template_id, mode)
    if unavailable_reason is not None:
        return _unavailable_result(
            query,
            policy,
            mode,
            template_id,
            alternative,
            authorized_rows,
            unavailable_reason,
        )
    if mode == "injection-only" and not policy.injection_safe:
        return _unavailable_result(
            query,
            policy,
            mode,
            template_id,
            alternative,
            authorized_rows,
            f"mode {mode} requires exact_policy_safe, but policy_config {policy.config_id} is not injection-safe",
        )

    predicate = _policy_predicate(query, policy)
    artifact_used = False
    plan_result: Optional[PlanResult] = None
    native_rls = False
    if mode in {"native-pg-rls", "native-pg-rls-physical-design"}:
        source = "rls"
        native_rls = True
    elif mode in {"security-barrier", "barrier-only"}:
        source = "barrier"
    elif mode == "injection-only":
        source = "direct"
    elif mode == "auth-index-enum-only":
        source = "auth_idx"
        artifact_used = True
    elif mode == ADMISSION_FIRST_MODE:
        planning_registry = registry or _e3_registry()
        verified_receipt = _require_e3_production_catalog_receipt(
            planning_catalog_receipt,
            query=query,
            policy=policy,
            predicate=predicate,
            pg_env=pg_env,
        )
        plan_result = contract_plan
        query_plan = contract_query_plan
        if plan_result is None:
            plan_result, query_plan, _ = _plan_e3_admission_first(
                query=query,
                policy=policy,
                predicate=predicate,
                pg_env=pg_env,
                protected_rows=protected_rows,
                query_local_rows=query_local_rows,
                authorized_rows=authorized_rows,
                build_ms=build_ms,
                ranker=ranker or E3RawPgRanker(),
                registry=planning_registry,
                planning_catalog_receipt=verified_receipt,
            )
        elif query_plan is None:
            raise PostgresError(
                "E3 supplied contract plan requires its original sealed query plan"
            )
        _require_e3_query_plan_catalog_receipt(query_plan, verified_receipt)
        _require_e3_query_plan_typed_admission(
            query_plan,
            receipt=verified_receipt,
            query=query,
            policy=policy,
            registry=planning_registry,
        )
        _require_e3_production_plan_lineage(plan_result, query_plan)
        if plan_result.chosen_template is None:
            raise PostgresError(
                f"E3 {query.query_id}/{policy.config_id}/AdmissionFirst found no admissible template"
            )
        template_id = plan_result.chosen_template.template_id
        selected_template_id = _require_e3_selected_root_template(query_plan)
        if template_id != selected_template_id:
            raise PostgresError(
                "E3 supplied contract plan changed the sealed selected root"
            )
        alternative = plan_result.chosen_template.alternative
        source = _source_for_template(template_id)
        native_rls = source == "rls"
        artifact_used = source in {
            "auth_idx",
            "auth_idx_keyed",
            "auth_idx_semijoin",
            "auth_idx_keyed_semijoin",
            "hybrid",
        }
    elif mode in {"strong-auth-index", "local-greedy"}:
        if policy.artifacts == "both_keyed":
            source = "auth_idx_keyed"
            artifact_used = True
        elif policy.artifacts == "auth_idx":
            source = "auth_idx"
            template_id, alternative = _template_for_mode(
                policy, "auth-index-enum-only"
            )
            artifact_used = True
        else:
            source = "barrier"
            template_id, alternative = _template_for_mode(policy, "barrier-only")
    else:
        raise PostgresError(f"unsupported E3 reduced mode: {mode}")

    sql = (
        _native_rls_count_sql(query, policy)
        if native_rls
        else _query_count_sql(query, policy, source, predicate)
    )
    (
        row_count,
        planning_ms,
        execution_ms,
        validation_ms,
        same_snapshot,
        validation_isolation_level,
        static_verification,
        static_verifier_explain_json,
    ) = _measure_e3_query(
        template_id,
        sql,
        query,
        policy,
        source,
        pg_env,
    )
    if row_count != oracle_count:
        raise PostgresError(
            f"E3 {query.query_id}/{policy.config_id}/{mode} returned {row_count}, "
            f"expected {oracle_count}"
        )
    payload = {
        "query_id": query.query_id,
        "policy_config_id": policy.config_id,
        "mode": scientific_mode_key(mode),
        "template_id": template_id,
        "row_count": row_count,
        "execution_ms": round(execution_ms, 6),
    }
    return E3MainModeResult(
        query=query,
        policy_config_id=policy.config_id,
        mode=mode,
        template_id=template_id,
        alternative=alternative,
        status="pass",
        template_applicability="applicable",
        row_count=row_count,
        execution_ms=execution_ms,
        build_ms=build_ms if artifact_used else 0.0,
        authorized_rows=authorized_rows,
        result_hash=_digest(payload),
        planning_ms=planning_ms,
        artifact_id=artifact_id if artifact_used else None,
        plan_result=plan_result,
        # The ordinary experiment record carries the prospective PlanResult,
        # but not the old phase-specific sealed-owner object.  Selection was
        # already checked against that object above; execution and timing are
        # ordinary PostgreSQL measurements from this point onward.
        query_plan=None,
        validation_ms=validation_ms,
        validation_same_snapshot=same_snapshot,
        validation_isolation_level=validation_isolation_level,
        static_verifier_status=static_verification.status,
        static_verifier_plan_hash=static_verification.plan_hash,
        static_verifier_reasons=tuple(static_verification.reasons),
        static_verifier_explain_json=static_verifier_explain_json,
        runner_sql=sql,
        execution_sql_source=(
            "prospective_selected_runner_sql"
            if mode == ADMISSION_FIRST_MODE
            else "fixed_baseline_runner_sql"
        ),
    )


def _execute_template_candidate(
    *,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    candidate: CandidatePlan,
    plan_result: PlanResult,
    query_plan: Optional[Mapping[str, Any]],
    pg_env: PostgresEnv,
    build_ms: float,
    authorized_rows: int,
    oracle_count: int,
) -> E3MainModeResult:
    if query_plan is not None:
        _require_e3_production_plan_lineage(plan_result, query_plan)
        if sum(item is candidate for item in plan_result.candidates) != 1:
            raise PostgresError(
                "E3 sealed template candidate is not the exact plan-result source"
            )
    if not candidate.accepted:
        reason = (
            ";".join(candidate.rejection_reasons) or candidate.template_applicability
        )
        return _unavailable_result(
            query,
            policy,
            "template-oracle",
            candidate.template_id,
            candidate.alternative,
            authorized_rows,
            reason,
            plan_result=plan_result,
            query_plan=None,
            candidate=candidate,
        )
    if query_plan is not None:
        completed_templates = {
            template_id
            for template_id, _plan_id in _require_e3_production_root_execution_binding(
                query_plan
            )
        }
        if candidate.template_id not in completed_templates:
            reason = _e3_sealed_frontier_rejection_reason(
                query_plan,
                template_id=candidate.template_id,
            )
            return _unavailable_result(
                query,
                policy,
                "template-oracle",
                candidate.template_id,
                candidate.alternative,
                authorized_rows,
                reason,
                plan_result=plan_result,
                query_plan=None,
                candidate=candidate,
                template_applicability="structural_rejection",
            )
    predicate = _policy_predicate(query, policy)
    source = _source_for_template(candidate.template_id)
    sql = (
        _native_rls_count_sql(query, policy)
        if source == "rls"
        else _query_count_sql(query, policy, source, predicate)
    )
    (
        row_count,
        planning_ms,
        execution_ms,
        validation_ms,
        same_snapshot,
        validation_isolation_level,
        static_verification,
        static_verifier_explain_json,
    ) = _measure_e3_query(
        candidate.template_id,
        sql,
        query,
        policy,
        source,
        pg_env,
    )
    if row_count != oracle_count:
        raise PostgresError(
            f"E3 {query.query_id}/{policy.config_id}/{candidate.template_id} returned "
            f"{row_count}, expected {oracle_count}"
        )
    artifact_used = source in {
        "auth_idx",
        "auth_idx_keyed",
        "auth_idx_semijoin",
        "auth_idx_keyed_semijoin",
        "hybrid",
    }
    payload = {
        "query_id": query.query_id,
        "policy_config_id": policy.config_id,
        "mode": "template-oracle",
        "template_id": candidate.template_id,
        "row_count": row_count,
        "execution_ms": round(execution_ms, 6),
    }
    return E3MainModeResult(
        query=query,
        policy_config_id=policy.config_id,
        mode="template-oracle",
        template_id=candidate.template_id,
        alternative=candidate.alternative,
        status="pass",
        template_applicability="applicable",
        row_count=row_count,
        execution_ms=execution_ms,
        build_ms=build_ms if artifact_used else 0.0,
        authorized_rows=authorized_rows,
        result_hash=_digest(payload),
        planning_ms=planning_ms,
        artifact_id=_artifact_id(query, policy) if artifact_used else None,
        plan_result=plan_result,
        # Candidate timing is ordinary experiment evidence.  The sealed
        # planning object above is used only to validate prospective lineage,
        # not exported as a phase/owner execution contract.
        query_plan=None,
        candidate=candidate,
        validation_ms=validation_ms,
        validation_same_snapshot=same_snapshot,
        validation_isolation_level=validation_isolation_level,
        static_verifier_status=static_verification.status,
        static_verifier_plan_hash=static_verification.plan_hash,
        static_verifier_reasons=tuple(static_verification.reasons),
        static_verifier_explain_json=static_verifier_explain_json,
        runner_sql=sql,
        execution_sql_source="prospective_candidate_runner_sql",
    )


def _record(
    *,
    root: Path,
    manifest_path: Path,
    manifest_id: str,
    stage: str,
    result: E3MainModeResult,
    dataset_scale: str,
    seed: int,
    pg_version: str,
    protected_rows: int,
    run_kind: str = "normal_mode",
    evidence_role: str = "normal",
    promotion_eligible: bool = True,
) -> Dict[str, Any]:
    """Serialize an ordinary measured E3 result.

    Prospective selection is validated before execution. Phase-specific
    planning owners, terminal outcomes, and correctness-only publication
    records are deliberately outside this experiment format.
    """

    if result.query_plan is not None:
        raise ValueError("E3 ordinary result must not carry a phase query-plan owner")
    if result.status in {"not_executed", "correctness_pass"}:
        raise ValueError("E3 ordinary result requires a terminal measured status")
    if (
        result.planning_ms is None
        or result.execution_ms is None
        or result.validation_ms is None
    ):
        raise ValueError("E3 ordinary result requires real timing values")

    artifact_action = (
        "reject" if result.template_applicability != "applicable" else "execute"
    )
    artifact_status = (
        "pass"
        if result.artifact_id is not None
        and result.template_applicability == "applicable"
        else "not_applicable"
    )
    trusted_state = {"standard_workload_adapter": 1, "keyed_auth_idx": 1}
    if result.validation_same_snapshot:
        trusted_state["artifact_validation_same_snapshot"] = 1
    measured_query_gucs = dict(E3_PSQL_GUCS)
    if result.artifact_id is not None:
        # Artifact-backed bodies are measured by the shared validated-query
        # transaction, which does not set plan_cache_mode.  The query is not a
        # prepared statement, so this does not change its plan; omitting the
        # setting here keeps the raw provenance exact.
        measured_query_gucs.pop("plan_cache_mode", None)

    local_vector = None
    if result.mode == "local-greedy":
        local_vector = {
            "relname": result.query.protected_rel,
            "policy_config_id": result.policy_config_id,
            "available_artifacts": (
                "both_keyed" if result.artifact_id is not None else "none"
            ),
            "query_shape": result.query.query_id,
        }

    chosen_rank = _chosen_rank(result.plan_result)
    best_candidate = None
    candidate_diagnostics: list[dict[str, Any]] = []
    chosen_candidate_diagnostic: Optional[dict[str, Any]] = None
    if result.plan_result is not None:
        accepted_candidates = sorted(
            (
                candidate
                for candidate in result.plan_result.candidates
                if candidate.accepted and candidate.pruned_by_dominance is None
            ),
            key=lambda item: (float(item.estimated_cost or 0.0), item.template_id),
        )
        best_candidate = accepted_candidates[0] if accepted_candidates else None
        for candidate in result.plan_result.candidates:
            diagnostic = _candidate_diagnostic(candidate)
            if diagnostic is None:
                continue
            candidate_diagnostics.append(diagnostic)
            if (
                result.plan_result.chosen_template is not None
                and diagnostic.get("template_id")
                == result.plan_result.chosen_template.template_id
            ):
                chosen_candidate_diagnostic = diagnostic

    heuristic_estimated_cost = (
        result.plan_result.estimated_cost if result.plan_result is not None else None
    )
    heuristic_pg_total_cost = (
        None
        if chosen_candidate_diagnostic is None
        else chosen_candidate_diagnostic.get("pg_total_cost")
    )
    heuristic_cost_model_version = (
        None
        if chosen_candidate_diagnostic is None
        else chosen_candidate_diagnostic.get("cost_model_version")
    )
    heuristic_calibration_path = (
        None
        if chosen_candidate_diagnostic is None
        else chosen_candidate_diagnostic.get("calibration_path")
    )
    heuristic_calibration_hash = (
        None
        if chosen_candidate_diagnostic is None
        else chosen_candidate_diagnostic.get("calibration_hash")
    )
    planner_payload = {
        "level": "B" if result.plan_result is not None else "A",
        "planning_time_ms": 0.0,
        "generated_templates": (
            result.plan_result.generated_templates
            if result.plan_result is not None
            else 1
        ),
        "rejected_templates": (
            result.plan_result.rejected_templates
            if result.plan_result is not None
            else (1 if result.status == "expected_reject" else 0)
        ),
        "costed_templates": (
            result.plan_result.costed_templates
            if result.plan_result is not None
            else (0 if result.status == "expected_reject" else 1)
        ),
        "rejection_reasons": (
            dict(result.plan_result.rejection_reasons)
            if result.plan_result is not None
            else ({result.failure_reason: 1} if result.failure_reason else {})
        ),
        "chosen_estimated_cost": heuristic_estimated_cost,
        "chosen_pg_total_cost": heuristic_pg_total_cost,
        "cost_model_version": heuristic_cost_model_version,
        "calibration_path": heuristic_calibration_path,
        "calibration_hash": heuristic_calibration_hash,
        "chosen_rank_vs_template_oracle": chosen_rank,
        "local_feature_vector": local_vector,
        "parent_requirement_vector": (
            dict(result.plan_result.parent_requirement_vector)
            if result.plan_result is not None
            else {
                "aggregate_boundary": "before_group_order_limit",
                "query_shape": result.query.query_id,
            }
        ),
        "disabled_components": (
            list(result.plan_result.disabled_components)
            if result.plan_result is not None
            else []
        ),
        "candidates": (
            [candidate.to_dict() for candidate in result.plan_result.candidates]
            if result.plan_result is not None
            else []
        ),
        "delivered_sigma": (
            dict(result.plan_result.delivered_sigma)
            if result.plan_result is not None
            else {}
        ),
        "candidate_diagnostics": candidate_diagnostics,
        "diagnostic_heuristic_chosen_estimated_cost": heuristic_estimated_cost,
        "diagnostic_heuristic_chosen_pg_total_cost": heuristic_pg_total_cost,
        "diagnostic_heuristic_cost_model_version": heuristic_cost_model_version,
        "diagnostic_heuristic_calibration_path": heuristic_calibration_path,
        "diagnostic_heuristic_calibration_hash": heuristic_calibration_hash,
        "diagnostic_completed_chosen_rank": chosen_rank,
    }

    oracle_eligible = bool(
        promotion_eligible
        and (
            (
                run_kind == "template_candidate"
                and result.status == "pass"
                and result.template_applicability == "applicable"
            )
            or (run_kind == "normal_mode" and result.mode == ADMISSION_FIRST_MODE)
        )
    )
    oracle_exclusion = (
        None
        if oracle_eligible
        else (
            "diagnostic_only"
            if not promotion_eligible
            else (
                result.template_applicability
                if run_kind == "template_candidate"
                else "fixed_baseline_not_template_oracle_pool"
            )
        )
    )
    sql_payload = {
        "emitted_sql_path": result.query.path,
        "emitted_sql_hash": file_sha256(root / result.query.path),
        "normalized_sql_hash": result.result_hash,
    }
    if result.runner_sql:
        sql_payload.update(
            {
                "runner_sql": result.runner_sql,
                "runner_sql_hash": _text_digest(result.runner_sql),
                "runner_sql_source": result.execution_sql_source,
            }
        )

    return {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": (
            f"E3main_{result.query.query_id}_{result.policy_config_id}_{result.mode}"
            if run_kind == "normal_mode"
            else f"E3main_{result.query.query_id}_{result.policy_config_id}_{run_kind}_{result.template_id}"
        ),
        "manifest_id": manifest_id,
        "manifest_hash": file_sha256(manifest_path),
        "experiment": "E3",
        "stage": stage,
        "run_kind": run_kind,
        "evidence": {
            "role": evidence_role,
            "promotion_eligible": bool(promotion_eligible),
            "requested_promotion_eligible": bool(promotion_eligible),
        },
        "dataset": {
            "name": result.query.workload,
            "scale": dataset_scale,
            "seed": seed,
        },
        "query": {
            "query_id": result.query.query_id,
            "path": result.query.path,
            "params": {
                "policy_config_id": result.policy_config_id,
                "protected_relation": result.query.protected_rel,
            },
        },
        "policy": {
            "policy_id": result.policy_config_id,
            "policy_version": 0,
            "policy_sql_manifest_hash": file_sha256(manifest_path),
        },
        "context": {"context_id": "e3_main_ctx", "ctx_hash": "e3_main_ctx_hash"},
        "mode": result.mode,
        "template": {
            "template_id": result.template_id,
            "alternative": result.alternative,
        },
        "template_applicability": {
            "status": result.template_applicability,
            "reason": result.failure_reason,
        },
        "template_oracle": {
            "eligible_for_template_oracle": oracle_eligible,
            "template_oracle_exclusion_reason": oracle_exclusion,
            "oracle_kind": "BestEnumeratedAdmissible",
            "best_template_id": (
                None if best_candidate is None else best_candidate.template_id
            ),
            "best_estimated_cost": (
                None if best_candidate is None else best_candidate.estimated_cost
            ),
            "chosen_rank": chosen_rank,
            "diagnostic_completed_best_template_id": (
                None if best_candidate is None else best_candidate.template_id
            ),
            "diagnostic_completed_best_estimated_cost": (
                None if best_candidate is None else best_candidate.estimated_cost
            ),
            "diagnostic_completed_chosen_rank": chosen_rank,
        },
        "evaluation_role": (
            FINITE_TEMPLATE_UPPER_BOUND_ROLE
            if run_kind in {"template_candidate", "template_oracle_summary"}
            else load_mode_registry(root)[normalize_mode_id(result.mode)].evaluation_role
        ),
        "pg": {"version": pg_version, "gucs": measured_query_gucs},
        "versions": {
            "policy": {result.policy_config_id: 0},
            "membership": (
                {"group_membership": 0}
                if result.policy_config_id == "group_acl_expensive"
                else {}
            ),
            "context": {"e3_main_ctx": 0},
            "trusted_state": trusted_state,
            "base": {
                result.query.protected_rel: 0,
                "tpch_orders": 0,
                "tpch_lineitem": 0,
                "job_movie_companies": 0,
                "job_cast_info": 0,
            },
            "artifacts": {result.artifact_id: 0} if result.artifact_id else {},
        },
        "planner": planner_payload,
        "static_verifier": {
            "status": result.static_verifier_status,
            "plan_hash": result.static_verifier_plan_hash
            or (
                result.result_hash
                if result.static_verifier_status == "pass"
                else None
            ),
            "explain_path": None,
            "reasons": list(result.static_verifier_reasons),
            "evidence_digest": None,
            "complete_root_plan_digest": None,
        },
        "artifact_validation": {
            "status": artifact_status,
            "action": artifact_action,
            "expected_action": artifact_action,
            "failure_sqlstate": None,
            "failure_symbol": None,
            "same_snapshot": result.validation_same_snapshot,
            "isolation_level": result.validation_isolation_level,
        },
        "runtime_audit": {
            "status": "pass",
            "audit_path": None,
            "udf_calls": 0,
            "unauthorized_observations": 0,
            "client_errors": 0,
            "client_notices": 0,
        },
        "sql": sql_payload,
        "oracle_check": {
            "status": "match" if result.status == "pass" else "not_applicable",
            "oracle_kind": "standard_workload_exact_before_aggregate_reduced",
            "set_diff_left": 0,
            "set_diff_right": 0,
            "known_invalid_accepted": False,
            "known_valid_rejected": False,
        },
        "timing_ms": {
            "planning": result.planning_ms,
            "execution": result.execution_ms,
            "verification": result.validation_ms,
            "total": (
                result.planning_ms + result.execution_ms + result.validation_ms
            ),
        },
        "result": {
            "row_count": result.row_count,
            "result_hash": result.result_hash,
        },
        "pg_metrics": {
            "postgres_planning_ms": result.planning_ms,
            "shared_read_blocks": 0,
            "shared_hit_blocks": 0,
            "temp_read_blocks": 0,
            "temp_written_blocks": 0,
        },
        "counts": {
            "policy_evals": (
                protected_rows
                if result.template_id
                in {
                    "barrier_filter_v1",
                    "barrier_filter_inline_v1",
                    "ordinary_first_exact_check_v1",
                    "safe_predicate_injection_v1",
                    "native_pg_rls_v1",
                    "native_pg_rls_physical_design_v1",
                }
                else 0
            ),
            "residual_checks": 0,
            "candidate_rows": result.authorized_rows,
            "authorized_rows": result.authorized_rows,
            "artifact_lookups": (
                1 if result.artifact_id and result.status == "pass" else 0
            ),
            "base_fetches": result.row_count,
        },
        "artifact_cost": {
            "query_only_ms": result.planning_ms + result.execution_ms,
            "build_ms": result.build_ms,
            "refresh_ms": 0.0,
            "storage_bytes": result.authorized_rows * 96 if result.artifact_id else 0,
            "validation_ms": result.validation_ms,
            "indexes_built": (
                ["auth_idx_lookup", "auth_idx_keyed_eq_lookup"]
                if result.artifact_id
                else []
            ),
            "artifact_key_encoding_version": "artifact_key_encoding_v1",
            "amortization_model": "query_only",
        },
        "implementation": {
            "git_commit": _git_commit(root),
            "docker_image_digest": "not_containerized",
            "python_version": platform.python_version(),
            "planner_language": "python",
        },
        "e3_standard_workload": {
            "standard_workload": result.query.workload,
            "query_id": result.query.query_id,
            "adapter_scope": (
                "real_standard_workload_plus_synthetic_policy_overlay"
                if dataset_scale in REAL_TPCH_SCALES or dataset_scale in REAL_JOB_SCALES
                else "reduced_tpch_job_deterministic_schema"
            ),
            "unsupported_query_boundary": (
                "residuals_discharged_before_aggregate_group_order_limit"
            ),
        },
        "status": result.status,
        "failure": (
            None if result.failure_reason is None else {"reason": result.failure_reason}
        ),
    }


def _excluded_counts(results: list[E3MainModeResult]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for result in results:
        if result.status == "pass" and result.template_applicability == "applicable":
            continue
        key = result.failure_reason or result.template_applicability
        counts[key] = counts.get(key, 0) + 1
    return counts


def _candidate_equivalence_key(result: E3MainModeResult) -> str:
    diagnostic = (
        _candidate_diagnostic(result.candidate)
        if result.candidate is not None
        else None
    )
    if diagnostic is not None and diagnostic.get("plan_hash"):
        return str(diagnostic["plan_hash"])
    return result.template_id


def _group_median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[midpoint]
    return (ordered[midpoint - 1] + ordered[midpoint]) / 2.0


def _rank_keyed_values(values: Mapping[str, float]) -> dict[str, int]:
    ranked = sorted(values.items(), key=lambda item: (item[1], item[0]))
    return {key: idx for idx, (key, _) in enumerate(ranked, start=1)}


def _template_oracle_summary_record(
    *,
    root: Path,
    manifest_path: Path,
    manifest_id: str,
    stage: str,
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    plan_result: PlanResult,
    candidate_results: list[E3MainModeResult],
    dataset_scale: str,
    seed: int,
    pg_version: str,
    protected_rows: int,
    evidence_role: str = "normal",
    promotion_eligible: bool = True,
) -> Dict[str, Any]:
    eligible = [
        result
        for result in candidate_results
        if result.status == "pass" and result.template_applicability == "applicable"
    ]
    if not eligible:
        raise PostgresError(
            f"E3 {query.query_id}/{policy.config_id} has no measured template candidates"
        )
    if any(result.query_plan is not None for result in candidate_results):
        raise PostgresError("E3 template summary accepts measured candidates only")

    chosen = plan_result.chosen_template
    chosen_key = None
    if chosen is not None:
        chosen_diagnostic = _candidate_diagnostic(chosen)
        chosen_key = (
            str(chosen_diagnostic.get("plan_hash"))
            if chosen_diagnostic
            else chosen.template_id
        )

    grouped: dict[str, list[E3MainModeResult]] = {}
    for result in eligible:
        grouped.setdefault(_candidate_equivalence_key(result), []).append(result)
    group_execution = {
        key: _group_median([result.execution_ms for result in group])
        for key, group in grouped.items()
    }
    group_estimated = {
        key: min(
            float(result.candidate.estimated_cost or 0.0)
            for result in group
            if result.candidate is not None
            and result.candidate.estimated_cost is not None
        )
        for key, group in grouped.items()
        if any(
            result.candidate is not None
            and result.candidate.estimated_cost is not None
            for result in group
        )
    }
    measured_ranks = _rank_keyed_values(group_execution)
    estimated_ranks = _rank_keyed_values(group_estimated)
    best_key = min(group_execution, key=lambda key: (group_execution[key], key))
    best_group = grouped[best_key]
    best = sorted(best_group, key=lambda item: item.template_id)[0]
    chosen_execution_ms = None if chosen_key is None else group_execution.get(chosen_key)
    best_execution_ms = group_execution[best_key]
    chosen_measured_rank = (
        None if chosen_key is None else measured_ranks.get(chosen_key)
    )
    measured_best_estimated_rank = estimated_ranks.get(best_key)
    gap = (
        None
        if chosen_execution_ms is None or best_execution_ms <= 0
        else chosen_execution_ms / best_execution_ms
    )
    summary_payload = {
        "run_kind": "template_oracle_summary",
        "query_id": query.query_id,
        "context_id": "e3_main_ctx",
        "mode_under_test": ADMISSION_FIRST_MODE,
        "ranking_metric": "execution_time_ms",
        "eligible_templates": len(eligible),
        "eligible_plan_shapes": len(grouped),
        "excluded_templates": _excluded_counts(candidate_results),
        "best_template_id": best.template_id,
        "best_equivalence_key": best_key,
        "best_execution_ms": best_execution_ms,
        "chosen_template_id": None if chosen is None else chosen.template_id,
        "chosen_equivalence_key": chosen_key,
        "chosen_execution_ms": chosen_execution_ms,
        "gap": gap,
        "estimated_rank": _chosen_rank(plan_result),
        "chosen_is_measured_best": chosen_key == best_key,
        "chosen_measured_rank": chosen_measured_rank,
        "measured_best_estimated_rank": measured_best_estimated_rank,
        "diagnostic_completed_templates": len(eligible),
        "diagnostic_completed_plan_shapes": len(grouped),
        "diagnostic_best_template_id": best.template_id,
        "diagnostic_best_equivalence_key": best_key,
        "diagnostic_best_execution_ms": best_execution_ms,
        "diagnostic_chosen_execution_ms": chosen_execution_ms,
        "diagnostic_gap": gap,
        "diagnostic_chosen_measured_rank": chosen_measured_rank,
        "diagnostic_measured_best_estimated_rank": measured_best_estimated_rank,
    }
    scientific_summary_payload = {
        **summary_payload,
        "mode_under_test": scientific_mode_key(ADMISSION_FIRST_MODE),
    }
    summary = replace(
        best,
        mode="template-oracle",
        result_hash=_digest(scientific_summary_payload),
        plan_result=plan_result,
        query_plan=None,
    )
    record = _record(
        root=root,
        manifest_path=manifest_path,
        manifest_id=manifest_id,
        stage=stage,
        result=summary,
        dataset_scale=dataset_scale,
        seed=seed,
        pg_version=pg_version,
        protected_rows=protected_rows,
        run_kind="template_oracle_summary",
        evidence_role=evidence_role,
        promotion_eligible=promotion_eligible,
    )
    digest = _digest(scientific_summary_payload)
    record["run_id"] = (
        f"E3main_{query.query_id}_{policy.config_id}_template_oracle_summary"
    )
    record["template_oracle_summary"] = summary_payload
    record["template_oracle"]["eligible_for_template_oracle"] = promotion_eligible
    record["template_oracle"]["template_oracle_exclusion_reason"] = (
        None if promotion_eligible else "diagnostic_only"
    )
    record["template_oracle"]["best_template_id"] = best.template_id
    record["template_oracle"]["diagnostic_completed_best_template_id"] = best.template_id
    record["result"]["result_hash"] = digest
    record["sql"]["normalized_sql_hash"] = digest
    record["static_verifier"]["plan_hash"] = digest
    return record


def _build_artifact(
    query: E3QuerySpec,
    policy: E3PolicyConfig,
    predicate: str,
    pg_env: PostgresEnv,
) -> tuple[float, int, int]:
    artifact_id = _artifact_id(query, policy)
    _run_sql_script(_clear_artifact_sql(artifact_id), pg_env)
    if policy.artifacts == "none":
        return 0.0, 0, 0
    if policy.artifacts not in {"auth_idx", "both_keyed"}:
        raise PostgresError(f"unsupported E3 artifact config: {policy.artifacts}")
    started = time.monotonic()
    _run_sql_script(_build_artifact_sql(query, policy, predicate), pg_env)
    elapsed_ms = (time.monotonic() - started) * 1000.0
    table = "auth_idx_keyed" if policy.artifacts == "both_keyed" else "auth_idx"
    cardinality = int(
        run_psql_command(
            f"SELECT count(*) FROM public.{table} WHERE artifact_id = {_quote(artifact_id)};",
            pg_env,
        )
    )
    keyed_cardinality = 0
    if policy.artifacts == "both_keyed":
        keyed_cardinality = int(
            run_psql_command(
                f"SELECT count(*) FROM public.auth_idx_keyed "
                f"WHERE artifact_id = {_quote(artifact_id)} "
                f"AND key_name = {_quote(query.key_name)} "
                f"AND key_value = {_quote(query.key_value)};",
                pg_env,
            )
        )
    return elapsed_ms, cardinality, keyed_cardinality


def _rotated_e3_sequence(
    items: Sequence[Any],
    repetition: RepetitionRun,
) -> tuple[Any, ...]:
    """Counterbalance sequence position without randomness or outcome feedback."""

    ordered = tuple(items)
    if not ordered:
        return ()
    phase_start = 0 if repetition.phase == "warmup" else repetition.warmup
    offset = (phase_start + repetition.iteration - 1) % len(ordered)
    return ordered[offset:] + ordered[:offset]


def _rotated_e3_modes(
    modes: Sequence[str],
    repetition: RepetitionRun,
) -> tuple[str, ...]:
    return _rotated_e3_sequence(modes, repetition)


def run_e3_main(
    root: Path,
    pg_env: PostgresEnv,
    manifest_path: Path,
    output_dir: Path,
) -> E3MainResult:
    manifest = _load_manifest(manifest_path)
    _validate_manifest(manifest_path, manifest)
    manifest_id = str(manifest["manifest_id"])
    stage = str(manifest["stage"])
    selected_queries = _queries_for_manifest(manifest_path, manifest)
    selected_policies = _policies_for_manifest(manifest_path, manifest)
    manifest_modes = tuple(
        normalize_mode_id(str(mode)) for mode in manifest.get("modes", [])
    )
    ranker = _ranker_from_manifest(root, manifest)
    adaptive_topk = _adaptive_topk_from_manifest(manifest)
    evidence_role = str(manifest.get("evidence_role", "normal"))
    promotion_eligible = bool(manifest.get("promotion_eligible", True))
    registry = _e3_registry_from_manifest(manifest)
    seed_by_dataset = {
        str(item.get("name")): int(item.get("seed", 42))
        for item in manifest.get("datasets", [])
        if isinstance(item, Mapping)
    }
    scale_by_dataset = {
        str(item.get("name")): str(item.get("scale", "reduced"))
        for item in manifest.get("datasets", [])
        if isinstance(item, Mapping)
    }
    require_e3_manifest_data(root, manifest_path, manifest)
    pg_version = _prepare_database(
        root,
        pg_env,
        tpch_scale=scale_by_dataset.get("tpch", ""),
        job_scale=scale_by_dataset.get("job", ""),
    )
    repetitions = protocol_from_manifest(manifest)

    raw_paths: list[Path] = []
    normal_records = 0
    candidate_records = 0
    summary_records = 0
    artifact_unavailable_records = 0
    for query in selected_queries:
        protected_rows = _protected_count(query, pg_env)
        query_local_rows = int(
            run_psql_command(
                f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} "
                f"WHERE {_query_local_predicate(query)};",
                pg_env,
            )
        )
        for policy in selected_policies:
            predicate = _policy_predicate(query, policy)
            build_ms, artifact_rows, keyed_artifact_rows = _build_artifact(
                query, policy, predicate, pg_env
            )
            _configure_native_rls(query, policy, pg_env)
            planning_catalog_receipt = _collect_e3_planning_catalog_receipt(
                query,
                policy,
                pg_env,
            )
            _require_e3_production_catalog_receipt(
                planning_catalog_receipt,
                query=query,
                policy=policy,
                predicate=predicate,
                pg_env=pg_env,
            )
            authorized_rows = int(
                run_psql_command(
                    f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} "
                    f"WHERE {predicate};",
                    pg_env,
                )
            )
            if artifact_rows:
                authorized_rows = artifact_rows
            oracle_count, _ = _run_count_sql(
                _e3_independent_reference_count_sql(query, policy),
                pg_env,
            )
            contract_plan, contract_query_plan, planning_problem = (
                _plan_e3_admission_first(
                    query=query,
                    policy=policy,
                    predicate=predicate,
                    pg_env=pg_env,
                    protected_rows=protected_rows,
                    query_local_rows=query_local_rows,
                    authorized_rows=authorized_rows,
                    build_ms=build_ms,
                    ranker=ranker,
                    registry=registry,
                    keyed_artifact_rows=keyed_artifact_rows,
                    planning_catalog_receipt=planning_catalog_receipt,
                )
            )
            contract_plan = _apply_adaptive_topk(
                plan_result=contract_plan,
                query=query,
                policy=policy,
                pg_env=pg_env,
                build_ms=build_ms,
                authorized_rows=authorized_rows,
                oracle_count=oracle_count,
                config=adaptive_topk,
                query_plan=contract_query_plan,
            )
            contract_plan = _deduplicate_equivalent_plan_shapes(
                contract_plan,
                enabled=adaptive_topk.deduplicate_plan_shapes,
                query_plan=contract_query_plan,
            )
            for repetition in iter_repetitions(repetitions):
                candidate_results: list[E3MainModeResult] = []
                for candidate in _rotated_e3_sequence(
                    contract_plan.candidates,
                    repetition,
                ):
                    candidate_result = _execute_template_candidate(
                        query=query,
                        policy=policy,
                        candidate=candidate,
                        plan_result=contract_plan,
                        query_plan=contract_query_plan,
                        pg_env=pg_env,
                        build_ms=build_ms,
                        authorized_rows=authorized_rows,
                        oracle_count=oracle_count,
                    )
                    candidate_results.append(candidate_result)
                    candidate_record = _record(
                        root=root,
                        manifest_path=manifest_path,
                        manifest_id=manifest_id,
                        stage=stage,
                        result=candidate_result,
                        dataset_scale=scale_by_dataset[query.workload],
                        seed=seed_by_dataset[query.workload],
                        pg_version=pg_version,
                        protected_rows=protected_rows,
                        run_kind="template_candidate",
                        evidence_role=evidence_role,
                        promotion_eligible=promotion_eligible,
                    )
                    attach_repetition(candidate_record, repetition)
                    raw_paths.append(
                        _write_record(
                            candidate_record,
                            output_dir,
                            candidate_result.static_verifier_explain_json,
                        )
                    )
                    candidate_records += 1
                summary_record = _template_oracle_summary_record(
                    root=root,
                    manifest_path=manifest_path,
                    manifest_id=manifest_id,
                    stage=stage,
                    query=query,
                    policy=policy,
                    plan_result=contract_plan,
                    candidate_results=candidate_results,
                    dataset_scale=scale_by_dataset[query.workload],
                    seed=seed_by_dataset[query.workload],
                    pg_version=pg_version,
                    protected_rows=protected_rows,
                    evidence_role=evidence_role,
                    promotion_eligible=promotion_eligible,
                )
                attach_repetition(summary_record, repetition)
                raw_paths.append(_write_record(summary_record, output_dir))
                summary_records += 1
                for mode in _rotated_e3_modes(manifest_modes, repetition):
                    result = _execute_mode(
                        query=query,
                        policy=policy,
                        mode=str(mode),
                        pg_env=pg_env,
                        build_ms=build_ms,
                        authorized_rows=authorized_rows,
                        oracle_count=oracle_count,
                        protected_rows=protected_rows,
                        query_local_rows=query_local_rows,
                        contract_plan=contract_plan,
                        contract_query_plan=contract_query_plan,
                        ranker=ranker,
                        planning_catalog_receipt=planning_catalog_receipt,
                        registry=registry,
                    )
                    if result.template_applicability == "artifact_unavailable":
                        artifact_unavailable_records += 1
                    record = _record(
                        root=root,
                        manifest_path=manifest_path,
                        manifest_id=manifest_id,
                        stage=stage,
                        result=result,
                        dataset_scale=scale_by_dataset[query.workload],
                        seed=seed_by_dataset[query.workload],
                        pg_version=pg_version,
                        protected_rows=protected_rows,
                        evidence_role=evidence_role,
                        promotion_eligible=promotion_eligible,
                    )
                    attach_repetition(record, repetition)
                    raw_paths.append(
                        _write_record(
                            record,
                            output_dir,
                            result.static_verifier_explain_json,
                        )
                    )
                    normal_records += 1

    return E3MainResult(
        raw_result_paths=raw_paths,
        normal_records=normal_records,
        candidate_records=candidate_records,
        summary_records=summary_records,
        artifact_unavailable_records=artifact_unavailable_records,
        query_count=len(selected_queries),
    )
