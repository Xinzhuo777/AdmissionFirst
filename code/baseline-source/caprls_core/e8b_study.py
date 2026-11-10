"""E8b bounded artifact freshness and maintenance study runner."""

from __future__ import annotations

import hashlib
import json
import math
import platform
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field, fields, replace
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

import yaml

from .artifact_economics import (
    ArtifactEconomics,
    amortized_artifact_latency_ms,
    estimated_invalidation_count,
    maintenance_total_ms,
)
from .baselines import (
    ADMISSION_FIRST_MODE,
    load_mode_registry,
    mode_execution_order_key,
    normalize_mode_id,
    scientific_mode_key,
)
from .explain_artifacts import attach_static_verifier_explain
from .manifest_validator import file_sha256, scientific_manifest_hash
from .oracle_audit import _load_context, _load_policy, _quote, _render_exact_predicate
from .postgres_runner import PostgresEnv, PostgresError, run_psql_command, run_psql_file
from .repetitions import (
    RepetitionRun,
    attach_repetition,
    iter_repetitions,
    protocol_from_manifest,
)
from .result_schema import RAW_SCHEMA_VERSION, validate_raw_run_record
from .synthetic_saas import generate_synthetic_saas
from planner.emit import (
    ArtifactComponentBinding,
    ArtifactDependencyExpectation,
    ArtifactDependencyIdentity,
    EmitContext,
    StrictArtifactExpectation,
)
from planner.contracts import (
    GammaFact,
    GammaSnapshot,
    ImplementationTargetBinding,
    PolicyAccessTarget,
    implementation_target_binding,
    implementation_target_match_subject_digest,
    target_refinement_subject_digest,
    template_definition,
)
from planner.core import (
    DEFAULT_TEMPLATE_REGISTRY,
    ArtifactMetadata,
    CostInputs,
    PlanningProblem,
    TemplateRegistry,
    policy_subject_digest,
)
from planner.ir import Project, Root, ScanProtected
from planner.query import OccurrenceGoal, PlanningQuery, QueryPlanResult, plan_query
from planner.verifier.static import StaticVerification, verify_template_static


SQLSTATE_RE = re.compile(r"\b(P8A0[1-4])\b")
SYMBOL_RE = re.compile(r"\b(CAPRLS_[A-Z_]+)\b")
SQLSTATE_BY_SYMBOL = {
    "CAPRLS_ARTIFACT_STALE": "P8A01",
    "CAPRLS_CONTEXT_MISMATCH": "P8A02",
    "CAPRLS_RID_MISMATCH": "P8A03",
    "CAPRLS_TOCTOU_FAIL": "P8A04",
}

E8B_PLANNING_VALIDATOR_VERSION = "e8b-planning-admission-validator-v3"
E8B_POLICY_VALIDATOR_VERSION = "e8b-finite-policy-validator-v1"
E8B_ARTIFACT_VALIDATOR_VERSION = "e8b-artifact-catalog-validator-v1"
E8B_PLANNING_EVIDENCE_SCOPE = "fixture_metadata_non_promotable_diagnostic"
E8B_POSTGRES_PLANNING_EVIDENCE_SCOPE = (
    "postgres_catalog_planning_only_not_execution_authorization"
)
E8B_FIXTURE_PRINCIPAL_ID = "e8b_planning_user"
E8B_FIXTURE_CONTEXT_HASH = "sha256:" + hashlib.sha256(
    b"e8b_planning_context"
).hexdigest()
E8B_FIXTURE_EXACT_PREDICATE = "d.tenant_id = 1"
E8B_FIXTURE_SAFE_QUERY_LABEL = "registered_fixture_exact_predicate_is_safe_query_v1"
E8B_STRICT_BASE_RELATION = "document"
E8B_STRICT_RID_DOMAIN_ID = "document.doc_id"
E8B_STRICT_SNAPSHOT_DEPENDENCY = "document_snapshot"


@dataclass(frozen=True)
class E8bCase:
    test_id: str
    query_shape: str
    artifact_type: str
    update_rate_per_hour: float
    ttl_s: int
    contexts: int
    artifact_status: str
    contract_action: str
    expected_effect: str
    failure_sqlstate: Optional[str] = None
    failure_symbol: Optional[str] = None
    amortization_q: int = 1


CASES = [
    E8bCase(
        test_id="E8b_low_update_auth_idx_lookup",
        query_shape="single_key_lookup",
        artifact_type="auth_idx",
        update_rate_per_hour=0.0,
        ttl_s=3600,
        contexts=10,
        artifact_status="pass",
        contract_action="execute",
        expected_effect="artifact_hit",
    ),
    E8bCase(
        test_id="E8b_revocation_fallback_latency",
        query_shape="group_acl_lookup_after_revocation",
        artifact_type="auth_idx",
        update_rate_per_hour=0.1,
        ttl_s=3600,
        contexts=1000,
        artifact_status="stale",
        contract_action="fallback",
        expected_effect="fallback_overhead",
        failure_sqlstate="P8A01",
        failure_symbol="CAPRLS_ARTIFACT_STALE",
    ),
    E8bCase(
        test_id="E8b_mav_refresh_latency",
        query_shape="dashboard_mav_refresh",
        artifact_type="mav",
        update_rate_per_hour=0.01,
        ttl_s=60,
        contexts=1000,
        artifact_status="stale",
        contract_action="refresh",
        expected_effect="refresh_overhead",
        failure_sqlstate="P8A01",
        failure_symbol="CAPRLS_ARTIFACT_STALE",
    ),
    E8bCase(
        test_id="E8b_context_scope_explosion",
        query_shape="purpose_scoped_dashboard_many_contexts",
        artifact_type="both",
        update_rate_per_hour=0.001,
        ttl_s=3600,
        contexts=100000,
        artifact_status="wrong_context",
        contract_action="reject",
        expected_effect="context_scope_rejection",
        failure_sqlstate="P8A02",
        failure_symbol="CAPRLS_CONTEXT_MISMATCH",
    ),
    E8bCase(
        test_id="E8b_rid_snapshot_mismatch",
        query_shape="join_after_base_snapshot_change",
        artifact_type="both",
        update_rate_per_hour=0.01,
        ttl_s=3600,
        contexts=1000,
        artifact_status="rid_mismatch",
        contract_action="replan",
        expected_effect="rid_replan_overhead",
        failure_sqlstate="P8A03",
        failure_symbol="CAPRLS_RID_MISMATCH",
    ),
    E8bCase(
        test_id="E8b_ttl_expired_valid_versions",
        query_shape="ttl_policy_refresh_without_dependency_mismatch",
        artifact_type="auth_idx",
        update_rate_per_hour=0.0,
        ttl_s=1,
        contexts=1000,
        artifact_status="pass",
        contract_action="refresh",
        expected_effect="ttl_refresh_policy_cost",
    ),
]

REQUIRED_MODES = {
    ADMISSION_FIRST_MODE,
    "conservative-barrier",
    "naive-artifact-only",
    "mav-no-version",
    "naive-auth-index-no-scope",
    "native-pg-rls",
    "native-pg-rls-physical-design",
}

E8COST_MODES = {
    ADMISSION_FIRST_MODE,
    "conservative-barrier",
    "native-pg-rls-physical-design",
    "auth-index-enum-only",
    "mav-only",
    "naive-artifact-only",
    "mav-no-version",
    "stale-artifact-user",
}

UPDATE_RATE_LEVELS = (
    (0.0, "U0pct"),
    (0.001, "U0_1pct"),
    (0.01, "U1pct"),
    (0.1, "U10pct"),
)
QUERY_REUSE_LEVELS = (1, 10, 100, 1000)


def _e8cost_cases() -> list[E8bCase]:
    cases: list[E8bCase] = []
    for q in QUERY_REUSE_LEVELS:
        for update_rate, update_label in UPDATE_RATE_LEVELS:
            cases.append(
                E8bCase(
                    test_id=f"E8cost_mav_dash_Q{q}_{update_label}",
                    query_shape="dashboard_repeated_authorized_count",
                    artifact_type="mav",
                    update_rate_per_hour=update_rate,
                    ttl_s=3600,
                    contexts=1000,
                    artifact_status="pass",
                    contract_action="execute",
                    expected_effect="mav_amortization_sweep",
                    amortization_q=q,
                )
            )
            cases.append(
                E8bCase(
                    test_id=f"E8cost_authidx_sparse_Q{q}_{update_label}",
                    query_shape="sparse_cross_tenant_export",
                    artifact_type="auth_idx",
                    update_rate_per_hour=update_rate,
                    ttl_s=3600,
                    contexts=100000,
                    artifact_status="pass",
                    contract_action="execute",
                    expected_effect="auth_index_sparse_sweep",
                    amortization_q=q,
                )
            )
            cases.append(
                E8bCase(
                    test_id=f"E8cost_stale_fallback_Q{q}_{update_label}",
                    query_shape="stale_membership_fallback",
                    artifact_type="auth_idx",
                    update_rate_per_hour=update_rate,
                    ttl_s=3600,
                    contexts=1000,
                    artifact_status="stale",
                    contract_action="fallback",
                    expected_effect="stale_artifact_fallback_sweep",
                    failure_sqlstate="P8A01",
                    failure_symbol="CAPRLS_ARTIFACT_STALE",
                    amortization_q=q,
                )
            )
    return cases


E8COST_CASES = tuple(_e8cost_cases())


def _cases_for_stage(stage: str) -> Sequence[E8bCase]:
    if stage == "freshness_maintenance":
        return tuple(CASES)
    if stage == "artifact_cost_update_rate":
        return E8COST_CASES
    raise ValueError(f"unsupported E8b stage: {stage}")


def _modes_for_stage(stage: str) -> set[str]:
    if stage == "freshness_maintenance":
        return set(REQUIRED_MODES)
    if stage == "artifact_cost_update_rate":
        return set(E8COST_MODES)
    raise ValueError(f"unsupported E8b stage: {stage}")


@dataclass(frozen=True)
class ModeOutcome:
    status: str
    artifact_status: str
    action: str
    template_id: str
    alternative: str
    failure_reason: Optional[str]
    planner_candidates: tuple[Mapping[str, Any], ...] = ()
    planner_choice_reason: Optional[str] = None
    planner_query_plan: Optional[Mapping[str, Any]] = None


@dataclass(frozen=True)
class PlannerInvocation:
    occurrence_result: Any
    query_result: QueryPlanResult
    query_plan: Mapping[str, Any]


@dataclass(frozen=True)
class E8bStudyResult:
    raw_result_paths: list[Path]
    normal_records: int
    contract_records: int
    diagnostic_wrong_results: int
    fallback_records: int
    refresh_records: int


@dataclass(frozen=True)
class QueryTiming:
    planning_ms: float
    execution_ms: float
    static_verifier_status: str = "pass"
    static_verifier_plan_hash: Optional[str] = None
    static_verifier_reasons: tuple[str, ...] = ()
    static_verifier_explain_json: Optional[tuple[Mapping[str, Any], ...]] = None

    @property
    def total_ms(self) -> float:
        return self.planning_ms + self.execution_ms


@dataclass(frozen=True)
class ValidationTiming:
    validation_passed: bool
    failure_sqlstate: Optional[str]
    failure_symbol: Optional[str]
    elapsed_ms: float
    same_snapshot: bool = False
    isolation_level: Optional[str] = None


@dataclass(frozen=True)
class ValidatedQueryMeasurement:
    timing: QueryTiming
    row_count: int
    validation: ValidationTiming


@dataclass(frozen=True)
class E8bPolicyValidatorReceipt:
    validator_version: str
    evidence_scope: str
    promotable: bool
    policy_id: str
    relation: str
    rid_col: str
    principal_id: str
    context_hash: str
    policy_definition_digest: str
    context_digest: str
    exact_predicate: str
    exact_predicate_digest: str
    safe_query_label: str
    receipt_digest: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class E8bArtifactValidatorReceipt:
    validator_version: str
    evidence_scope: str
    promotable: bool
    artifact_id: str
    context_hash: str
    expected_contract_digest: str
    planning_snapshot_id: str
    verdict: str
    failure_sqlstate: Optional[str]
    failure_symbol: Optional[str]
    same_snapshot: bool
    isolation_level: Optional[str]
    evidence_digest: str

    @property
    def accepted(self) -> bool:
        return self.verdict == "pass"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class E8bSqlContext:
    policy_id: str
    user_id: str
    ctx_hash: str
    exact_predicate: str
    valid_expected_json: str
    auth_artifact_id: str
    mav_artifact_id: str
    policy_validation: E8bPolicyValidatorReceipt


def _e8b_artifact_dependency_rows(
    policy_id: str,
    context_hash: str,
) -> tuple[ArtifactDependencyExpectation, ...]:
    """Return the finite E8b catalog row order used by both artifact builders."""

    return (
        ArtifactDependencyExpectation("policy", policy_id, 0),
        ArtifactDependencyExpectation("membership", "group_membership", 0),
        ArtifactDependencyExpectation("base", E8B_STRICT_BASE_RELATION, 0),
        ArtifactDependencyExpectation("context_scope", context_hash, 0),
        ArtifactDependencyExpectation("rid_domain", E8B_STRICT_RID_DOMAIN_ID, 0),
        ArtifactDependencyExpectation(
            "toctou",
            E8B_STRICT_SNAPSHOT_DEPENDENCY,
            0,
        ),
    )


def _e8b_artifact_component_bindings(
    dependency_rows: Sequence[ArtifactDependencyExpectation],
) -> tuple[ArtifactComponentBinding, ...]:
    identities = {
        item.dep_kind: ArtifactDependencyIdentity(item.dep_kind, item.dep_name)
        for item in dependency_rows
    }
    return (
        ArtifactComponentBinding(
            "freshness",
            (
                identities["policy"],
                identities["membership"],
                identities["base"],
            ),
        ),
        ArtifactComponentBinding("context", (identities["context_scope"],)),
        ArtifactComponentBinding("snapshot", (identities["toctou"],)),
        ArtifactComponentBinding(
            "trusted_read",
            (identities["policy"], identities["membership"]),
        ),
        ArtifactComponentBinding(
            "rid_materialization",
            (identities["rid_domain"],),
        ),
    )


@dataclass(frozen=True)
class E8bArtifactRecipeSpec:
    """Canonical typed source for E8b build rows and strict H2 components."""

    artifact_id: str
    policy_id: str
    context_hash: str
    dependency_rows: tuple[ArtifactDependencyExpectation, ...]
    artifact_expectation: StrictArtifactExpectation
    _construction_digest: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "dependency_rows", tuple(self.dependency_rows))
        self._validate()
        object.__setattr__(self, "_construction_digest", self._current_digest())

    def _validate(self) -> None:
        if (
            self.artifact_id.__class__ is not str
            or not self.artifact_id
            or self.policy_id.__class__ is not str
            or not self.policy_id
            or self.context_hash.__class__ is not str
            or re.fullmatch(r"sha256:[0-9a-f]{64}", self.context_hash) is None
        ):
            raise ValueError("E8b artifact recipe identity is not canonical")
        expected_rows = _e8b_artifact_dependency_rows(
            self.policy_id,
            self.context_hash,
        )
        if self.dependency_rows != expected_rows:
            raise ValueError("E8b artifact recipe dependency rows are not canonical")
        if self.artifact_expectation.__class__ is not StrictArtifactExpectation:
            raise TypeError("E8b artifact recipe requires a strict typed expectation")
        self.artifact_expectation.assert_valid()
        expected = StrictArtifactExpectation(
            dependencies=expected_rows,
            component_bindings=_e8b_artifact_component_bindings(expected_rows),
        )
        if self.artifact_expectation != expected:
            raise ValueError("E8b artifact recipe component bindings are not canonical")

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "policy_id": self.policy_id,
            "context_hash": self.context_hash,
            "dependency_rows_in_builder_order": [
                item.to_dict() for item in self.dependency_rows
            ],
            "artifact_expectation_digest": self.artifact_expectation.digest,
        }

    def _current_digest(self) -> str:
        return _digest(self._identity_payload())

    def assert_valid(self) -> None:
        self._validate()
        if self._current_digest() != self._construction_digest:
            raise ValueError("E8b artifact recipe changed after construction")

    @property
    def digest(self) -> str:
        self.assert_valid()
        return self._construction_digest


@dataclass(frozen=True)
class E8bPlanningValidatorReceipt:
    """Planning-only validation receipt for the bounded E8b fixture.

    This receipt is deliberately not a live PostgreSQL H2 authorization.  It
    binds the typed Gamma snapshot to the full occurrence identity used by
    this adapter so a fact issued for another principal, context, occurrence,
    RID domain, or planning snapshot cannot be replayed here.
    """

    validator_version: str
    evidence_scope: str
    principal_id: str
    context_hash: str
    policy_id: str
    relation: str
    occurrence_id: str
    rid_col: str
    rid_domain_id: str
    policy_subject_digest: str
    exact_predicate_digest: str
    logical_target: PolicyAccessTarget
    implementation_target_bindings: tuple[ImplementationTargetBinding, ...]
    artifact_metadata_digest: str
    planning_snapshot_id: str
    gamma_snapshot: GammaSnapshot
    receipt_digest: str
    fact_evidence: tuple[Mapping[str, Any], ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "implementation_target_bindings",
            tuple(self.implementation_target_bindings),
        )
        if not isinstance(self.logical_target, PolicyAccessTarget):
            raise TypeError("E8b planning receipt logical target has invalid type")
        if any(
            not isinstance(binding, ImplementationTargetBinding)
            for binding in self.implementation_target_bindings
        ):
            raise TypeError("E8b planning receipt target binding has invalid type")
        if not self.implementation_target_bindings:
            raise ValueError("E8b planning receipt requires target bindings")
        if self.policy_subject_digest != self.logical_target.digest:
            raise ValueError("E8b planning receipt policy subject does not match target")
        if (
            self.relation != self.logical_target.relation
            or self.policy_id != self.logical_target.policy_id
            or self.occurrence_id != self.logical_target.occurrence_id
            or self.principal_id != self.logical_target.principal_id
        ):
            raise ValueError("E8b planning receipt scalar identity disagrees with target")
        template_ids = tuple(
            binding.template_id for binding in self.implementation_target_bindings
        )
        if len(set(template_ids)) != len(template_ids):
            raise ValueError("E8b planning receipt has duplicate target bindings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "validator_version": self.validator_version,
            "evidence_scope": self.evidence_scope,
            "principal_id": self.principal_id,
            "context_hash": self.context_hash,
            "policy_id": self.policy_id,
            "relation": self.relation,
            "occurrence_id": self.occurrence_id,
            "rid_col": self.rid_col,
            "rid_domain_id": self.rid_domain_id,
            "policy_subject_digest": self.policy_subject_digest,
            "exact_predicate_digest": self.exact_predicate_digest,
            "logical_target": self.logical_target.to_dict(),
            "implementation_target_bindings": [
                binding.to_dict() for binding in self.implementation_target_bindings
            ],
            "artifact_metadata_digest": self.artifact_metadata_digest,
            "planning_snapshot_id": self.planning_snapshot_id,
            "gamma_snapshot_digest": self.gamma_snapshot.digest,
            "receipt_digest": self.receipt_digest,
            "facts": [
                {
                    "fact_id": fact.fact_id,
                    "kind": fact.kind,
                    "subject_digest": fact.subject_digest,
                    "verdict": fact.verdict,
                    "validator_version": fact.validator_version,
                    "snapshot_id": fact.snapshot_id,
                    "evidence_digest": fact.evidence_digest,
                    "dynamic": fact.dynamic,
                    "evidence": dict(self.fact_evidence[index]),
                }
                for index, fact in enumerate(self.gamma_snapshot.facts)
            ],
        }


E8B_DOCUMENT_CARRIER_COLUMNS = ("doc_id", "tenant_id", "owner_id", "public", "region")


@dataclass(frozen=True)
class PostgresMeasurements:
    pg_version: str
    context_id: str
    ctx_hash: str
    policy_id: str
    user_id: str
    exact_predicate: str
    valid_expected_json: str
    auth_artifact_id: str
    mav_artifact_id: str
    authorized_count: int
    total_rows: int
    build_auth_ms: float
    build_mav_ms: float
    refresh_auth_ms: float
    refresh_mav_ms: float
    storage_auth_bytes: int
    storage_mav_bytes: int
    barrier: QueryTiming
    auth_idx: QueryTiming
    mav: QueryTiming
    hybrid: QueryTiming
    validation_by_case: Mapping[str, ValidationTiming]
    artifact_validation_by_case: Mapping[str, E8bArtifactValidatorReceipt]
    valid_artifact_validation_by_kind: Mapping[str, E8bArtifactValidatorReceipt]
    policy_validation: E8bPolicyValidatorReceipt
    validated_artifact_queries: Mapping[str, ValidatedQueryMeasurement]
    query_plan_by_template: Mapping[str, Mapping[str, Any]]


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


def _e8b_artifact_recipe_spec(
    artifact_id: str,
    policy_id: str,
    context_hash: str,
) -> E8bArtifactRecipeSpec:
    dependency_rows = _e8b_artifact_dependency_rows(policy_id, context_hash)
    return E8bArtifactRecipeSpec(
        artifact_id=artifact_id,
        policy_id=policy_id,
        context_hash=context_hash,
        dependency_rows=dependency_rows,
        artifact_expectation=StrictArtifactExpectation(
            dependencies=dependency_rows,
            component_bindings=_e8b_artifact_component_bindings(dependency_rows),
        ),
    )


def _planning_receipt_digest_payload(
    receipt: E8bPlanningValidatorReceipt,
) -> dict[str, Any]:
    return {
        "validator_version": receipt.validator_version,
        "evidence_scope": receipt.evidence_scope,
        "principal_id": receipt.principal_id,
        "context_hash": receipt.context_hash,
        "policy_id": receipt.policy_id,
        "relation": receipt.relation,
        "occurrence_id": receipt.occurrence_id,
        "rid_col": receipt.rid_col,
        "rid_domain_id": receipt.rid_domain_id,
        "policy_subject_digest": receipt.policy_subject_digest,
        "exact_predicate_digest": receipt.exact_predicate_digest,
        "logical_target": receipt.logical_target.to_dict(),
        "logical_target_digest": receipt.logical_target.digest,
        "implementation_target_bindings": [
            binding.to_dict() for binding in receipt.implementation_target_bindings
        ],
        "implementation_target_binding_digests": [
            binding.digest for binding in receipt.implementation_target_bindings
        ],
        "artifact_metadata_digest": receipt.artifact_metadata_digest,
        "planning_snapshot_id": receipt.planning_snapshot_id,
        "gamma_snapshot_digest": receipt.gamma_snapshot.digest,
    }


def _load_manifest(manifest_path: Path) -> Mapping[str, Any]:
    with manifest_path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, Mapping):
        raise ValueError(f"E8b manifest must be an object: {manifest_path}")
    return data


_E8COST_LEGACY_MANIFEST_ID = "e8_cost_update_rate_v1"
_E8COST_V3_MANIFEST_ID = "e8_cost_update_rate_v1_taxonomy_v3"
_E8COST_LEGACY_MANIFEST_PATH = "manifests/experiments/e8_cost_update_rate.yaml"
_E8COST_V3_MANIFEST_PATH = "manifests/experiments/v3/e8_cost_update_rate.yaml"
_E8COST_LEGACY_MANIFEST_SHA256 = (
    "sha256:a8fb6186b054961f091c49636a457e5f9de4bd37388fe5b65d41a37f40884d0c"
)


def _e8cost_manifest_identity(root: Path, manifest_path: Path) -> str:
    """Return the sealed legacy/v3 E8-COST manifest id."""

    legacy_path = root / _E8COST_LEGACY_MANIFEST_PATH
    v3_path = root / _E8COST_V3_MANIFEST_PATH
    expected_manifest_id = {
        legacy_path: _E8COST_LEGACY_MANIFEST_ID,
        v3_path: _E8COST_V3_MANIFEST_ID,
    }.get(manifest_path)
    if expected_manifest_id is None:
        raise TypeError("E8-COST accounting projection manifest is not sealed")
    manifest = _load_manifest(manifest_path)
    if manifest.get("manifest_id") != expected_manifest_id:
        raise TypeError("E8-COST accounting projection manifest id changed")
    if manifest_path == v3_path:
        lineage = manifest.get("lineage") or {}
        if (
            lineage.get("predecessor_path") != _E8COST_LEGACY_MANIFEST_PATH
            or lineage.get("predecessor_sha256")
            != _E8COST_LEGACY_MANIFEST_SHA256
            or lineage.get("migration") != "admission-first-taxonomy-v3"
        ):
            raise TypeError("E8-COST accounting projection lineage changed")
    return expected_manifest_id


def _validate_manifest(manifest_path: Path, manifest: Mapping[str, Any]) -> None:
    if manifest.get("experiment") != "E8" or manifest.get("execution_tier") != "main":
        raise ValueError("e8b-study requires an E8 main manifest")
    stage = str(manifest.get("stage"))
    cases = _cases_for_stage(stage)
    required_modes = _modes_for_stage(stage)

    modes = {normalize_mode_id(str(item)) for item in manifest.get("modes", [])}
    if modes != required_modes:
        raise ValueError(
            "E8b modes do not match runner contract: "
            f"expected {sorted(required_modes)}, got {sorted(modes)}"
        )

    query_paths = {
        str(item.get("query_id")): str(item.get("path"))
        for item in manifest.get("queries", [])
        if isinstance(item, Mapping)
    }
    missing = [
        case.test_id
        for case in cases
        if query_paths.get(case.test_id) != "workloads/e8/freshness_maintenance.sql"
    ]
    if missing:
        raise ValueError(
            f"E8b manifest query list does not match maintenance cases in {manifest_path}: {missing}"
        )

    maintenance_cases = {
        str(item.get("id"))
        for item in manifest.get("maintenance_cases", [])
        if isinstance(item, Mapping)
    }
    expected = {case.test_id for case in cases}
    if maintenance_cases != expected:
        raise ValueError(
            "E8b maintenance_cases do not match runner contract: "
            f"expected {sorted(expected)}, got {sorted(maintenance_cases)}"
        )


def _write_temp_sql(sql: str) -> Path:
    tmp = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".sql", delete=False)
    with tmp:
        tmp.write(sql)
    return Path(tmp.name)


def _run_sql_script(sql: str, pg_env: PostgresEnv) -> str:
    path = _write_temp_sql(sql)
    try:
        return run_psql_file(path, pg_env)
    finally:
        path.unlink(missing_ok=True)


def _timed_sql_script(sql: str, pg_env: PostgresEnv) -> float:
    started = time.monotonic()
    _run_sql_script(sql, pg_env)
    return (time.monotonic() - started) * 1000.0


def _artifact_dependency_values(artifact_id: str, policy_id: str, ctx_hash: str) -> str:
    recipe_spec = _e8b_artifact_recipe_spec(artifact_id, policy_id, ctx_hash)
    return ",\n".join(
        "("
        f"{_quote(recipe_spec.artifact_id)}, "
        f"{_quote(item.dep_kind)}, {_quote(item.dep_name)}, {item.version_at_build}"
        ")"
        for item in recipe_spec.dependency_rows
    )


def _build_auth_idx_sql(
    artifact_id: str,
    policy_id: str,
    user_id: str,
    ctx_hash: str,
    exact_predicate: str,
) -> str:
    return f"""
\\set ON_ERROR_STOP on
BEGIN;
DELETE FROM public.artifact_dependencies WHERE artifact_id = {_quote(artifact_id)};
DELETE FROM public.auth_idx WHERE artifact_id = {_quote(artifact_id)};
INSERT INTO public.artifact_dependencies(artifact_id, dep_kind, dep_name, version_at_build)
VALUES
{_artifact_dependency_values(artifact_id, policy_id, ctx_hash)};
INSERT INTO public.auth_idx(
  artifact_id, policy_id, user_id, ctx_hash, rid, rid_domain_id, base_rel_oid,
  policy_version, membership_version
)
SELECT
  {_quote(artifact_id)},
  {_quote(policy_id)},
  {_quote(user_id)},
  {_quote(ctx_hash)},
  d.doc_id,
  'document.doc_id',
  'public.document'::regclass::oid,
  0,
  0
FROM public.document d
WHERE {exact_predicate};
COMMIT;
ANALYZE public.auth_idx;
"""


def _build_mav_sql(
    artifact_id: str,
    policy_id: str,
    ctx_hash: str,
    exact_predicate: str,
) -> str:
    return f"""
\\set ON_ERROR_STOP on
BEGIN;
CREATE TABLE IF NOT EXISTS public.e8b_mav_document_ctx_000001 (
  doc_id bigint PRIMARY KEY,
  tenant_id bigint NOT NULL,
  owner_id bigint NOT NULL,
  region text NOT NULL,
  public boolean NOT NULL
);
DELETE FROM public.artifact_dependencies WHERE artifact_id = {_quote(artifact_id)};
TRUNCATE public.e8b_mav_document_ctx_000001;
INSERT INTO public.artifact_dependencies(artifact_id, dep_kind, dep_name, version_at_build)
VALUES
{_artifact_dependency_values(artifact_id, policy_id, ctx_hash)};
INSERT INTO public.e8b_mav_document_ctx_000001(doc_id, tenant_id, owner_id, region, public)
SELECT d.doc_id, d.tenant_id, d.owner_id, d.region, d.public
FROM public.document d
WHERE {exact_predicate};
COMMIT;
ANALYZE public.e8b_mav_document_ctx_000001;
"""


def _first_match(pattern: re.Pattern[str], text: str) -> Optional[str]:
    match = pattern.search(text)
    return match.group(1) if match else None


def _expected_json(case: E8bCase, ctx_hash: str) -> str:
    if case.artifact_status == "wrong_context":
        expected = {
            "dep_kind": "context_scope",
            "dep_name": "sha256:e8b_wrong_context_scope",
            "version_at_build": 0,
        }
    elif case.artifact_status == "rid_mismatch":
        expected = {
            "dep_kind": "rid_domain",
            "dep_name": "ticket.ticket_id",
            "version_at_build": 0,
        }
    elif case.artifact_status == "stale":
        expected = {
            "dep_kind": "membership" if case.artifact_type == "auth_idx" else "policy",
            "dep_name": "group_membership" if case.artifact_type == "auth_idx" else "tenant_group",
            "version_at_build": 1,
        }
    else:
        expected = {
            "dep_kind": "context_scope",
            "dep_name": ctx_hash,
            "version_at_build": 0,
        }
    if case.failure_sqlstate:
        expected["failure_sqlstate"] = case.failure_sqlstate
    if case.failure_symbol:
        expected["failure_symbol"] = case.failure_symbol
    return json.dumps([expected], sort_keys=True, separators=(",", ":"))


def _validation_statements(artifact_ids: Sequence[str], expected_json: str) -> str:
    return "\n".join(
        "SELECT public.caprls_assert_artifact_valid("
        f"{_quote(artifact_id)}, {_quote(expected_json)}::jsonb);"
        for artifact_id in artifact_ids
    )


def _validation_gate_script(
    artifact_id: str,
    expected_json: str,
    isolation_level: str = "repeatable_read",
) -> str:
    sql_isolation = isolation_level.replace("_", " ").upper()
    return f"""
SET jit = off;
SET max_parallel_workers_per_gather = 0;
BEGIN ISOLATION LEVEL {sql_isolation};
{_validation_statements((artifact_id,), expected_json)}
COMMIT;
"""


@dataclass(frozen=True)
class _E8bStaticPreflight:
    template_id: str
    sql: str
    verification: StaticVerification
    explain_json: tuple[Mapping[str, Any], ...]


def _e8b_measurement_query_body(sql: str) -> str:
    if not isinstance(sql, str) or not sql.strip():
        raise PostgresError("E8b measurement SQL identity is missing")
    return sql.strip().rstrip(";")


def _plain_explain_sql(sql: str) -> str:
    body = _e8b_measurement_query_body(sql)
    return f"""
SET jit = off;
SET max_parallel_workers_per_gather = 0;
EXPLAIN (FORMAT JSON) {body};
"""


def _analyze_explain_sql(sql: str) -> str:
    body = _e8b_measurement_query_body(sql)
    return f"""
SET jit = off;
SET max_parallel_workers_per_gather = 0;
EXPLAIN (ANALYZE, FORMAT JSON, TIMING OFF, SUMMARY ON) {body};
"""


def _validated_query_script(sql: str, artifact_ids: Sequence[str], expected_json: str) -> str:
    body = _e8b_measurement_query_body(sql)
    return f"""
SET jit = off;
SET max_parallel_workers_per_gather = 0;
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT 'caprls_validation_start_ms=' || (EXTRACT(EPOCH FROM clock_timestamp()) * 1000.0)::text;
{_validation_statements(tuple(artifact_ids), expected_json)}
SELECT 'caprls_validation_end_ms=' || (EXTRACT(EPOCH FROM clock_timestamp()) * 1000.0)::text;
EXPLAIN (ANALYZE, FORMAT JSON, TIMING OFF, SUMMARY ON) {body};
COMMIT;
"""


def _split_ir_sql_statements(emitted_sql: str) -> list[str]:
    statements = [
        statement.strip()
        for statement in emitted_sql.strip().split(";")
        if statement.strip()
    ]
    if not statements:
        raise PostgresError("cannot execute empty E8b IR-emitted SQL")
    return statements


def _row_sql_from_ir_emitted_sql(emitted_sql: str) -> str:
    statements = _split_ir_sql_statements(emitted_sql)
    query_statements = [
        statement
        for statement in statements
        if statement.upper().startswith(("SELECT", "WITH"))
        and "caprls_assert_artifact_valid" not in statement
    ]
    if not query_statements:
        raise PostgresError(f"E8b IR-emitted SQL lacks row-producing SELECT:\n{emitted_sql}")
    return query_statements[-1]


def _validation_ms_from_psql_output(stdout: str) -> float:
    started: Optional[float] = None
    ended: Optional[float] = None
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("caprls_validation_start_ms="):
            started = float(stripped.split("=", 1)[1])
        elif stripped.startswith("caprls_validation_end_ms="):
            ended = float(stripped.split("=", 1)[1])
    if started is None or ended is None:
        raise PostgresError(f"E8b validated query did not emit validation timing markers:\n{stdout}")
    return max(0.0, ended - started)


def _row_count_from_explain_json(explain_json: Sequence[Mapping[str, Any]]) -> int:
    if not explain_json:
        raise PostgresError("E8b EXPLAIN JSON payload is empty")
    plan = explain_json[0].get("Plan")
    if not isinstance(plan, Mapping):
        raise PostgresError(f"E8b EXPLAIN JSON lacks root plan: {explain_json}")
    actual_rows = float(plan.get("Actual Rows", 0.0) or 0.0)
    actual_loops = float(plan.get("Actual Loops", 1.0) or 1.0)
    return int(round(actual_rows * actual_loops))


def _run_validation_gate(
    artifact_id: str,
    expected_json: str,
    pg_env: PostgresEnv,
    fallback_sqlstate: Optional[str] = None,
    fallback_symbol: Optional[str] = None,
    isolation_level: str = "repeatable_read",
    same_snapshot: bool = True,
) -> ValidationTiming:
    started = time.monotonic()
    try:
        run_psql_command(_validation_gate_script(artifact_id, expected_json, isolation_level), pg_env)
    except PostgresError as exc:
        elapsed_ms = (time.monotonic() - started) * 1000.0
        message = str(exc)
        symbol = _first_match(SYMBOL_RE, message) or fallback_symbol
        sqlstate = _first_match(SQLSTATE_RE, message) or fallback_sqlstate
        if symbol and sqlstate is None:
            sqlstate = SQLSTATE_BY_SYMBOL.get(symbol)
        return ValidationTiming(
            validation_passed=False,
            failure_sqlstate=sqlstate,
            failure_symbol=symbol,
            elapsed_ms=elapsed_ms,
            same_snapshot=same_snapshot,
            isolation_level=isolation_level,
        )
    return ValidationTiming(
        validation_passed=True,
        failure_sqlstate=None,
        failure_symbol=None,
        elapsed_ms=(time.monotonic() - started) * 1000.0,
        same_snapshot=same_snapshot,
        isolation_level=isolation_level,
    )


def _run_validated_query(
    template_id: str,
    sql: str,
    artifact_ids: Sequence[str],
    expected_json: str,
    pg_env: PostgresEnv,
    fallback_sqlstate: Optional[str] = None,
    fallback_symbol: Optional[str] = None,
) -> ValidatedQueryMeasurement:
    artifact_ids = tuple(artifact_ids)
    preflight = _run_e8b_static_preflight(
        template_id,
        sql,
        pg_env,
        artifact_catalog_validated_in_transaction=bool(artifact_ids),
    )
    _require_e8b_preflight_identity(
        preflight,
        template_id=template_id,
        sql=sql,
    )
    started = time.monotonic()
    try:
        output = run_psql_command(_validated_query_script(sql, artifact_ids, expected_json), pg_env)
    except PostgresError as exc:
        elapsed_ms = (time.monotonic() - started) * 1000.0
        message = str(exc)
        symbol = _first_match(SYMBOL_RE, message) or fallback_symbol
        sqlstate = _first_match(SQLSTATE_RE, message) or fallback_sqlstate
        if symbol and sqlstate is None:
            sqlstate = SQLSTATE_BY_SYMBOL.get(symbol)
        return ValidatedQueryMeasurement(
            timing=_timing_from_e8b_static_preflight(preflight),
            row_count=0,
            validation=ValidationTiming(
                validation_passed=False,
                failure_sqlstate=sqlstate,
                failure_symbol=symbol,
                elapsed_ms=elapsed_ms,
                same_snapshot=True,
                isolation_level="repeatable_read",
            ),
        )
    elapsed_ms = (time.monotonic() - started) * 1000.0
    measurement_explain_json = _extract_explain_json(output)
    timing = _timing_with_e8b_static_preflight(
        measurement_explain_json,
        preflight,
    )
    validation_ms = _validation_ms_from_psql_output(output)
    return ValidatedQueryMeasurement(
        timing=timing,
        row_count=_row_count_from_explain_json(measurement_explain_json),
        validation=ValidationTiming(
            validation_passed=True,
            failure_sqlstate=None,
            failure_symbol=None,
            elapsed_ms=validation_ms,
            same_snapshot=True,
            isolation_level="repeatable_read",
        ),
    )


def _extract_explain_json(stdout: str) -> list[Mapping[str, Any]]:
    start = stdout.find("[")
    end = stdout.rfind("]")
    if start < 0 or end < start:
        raise PostgresError(f"E8b EXPLAIN did not emit JSON:\n{stdout}")
    payload = json.loads(stdout[start : end + 1])
    if not isinstance(payload, list) or not payload:
        raise PostgresError(f"E8b EXPLAIN JSON payload is empty:\n{stdout}")
    return payload


def _explain_plan_hash(explain_json: list[Mapping[str, Any]]) -> str:
    plan = explain_json[0].get("Plan", {})
    if not isinstance(plan, Mapping):
        plan = {}
    return _digest(plan)


def _timing_from_explain_json(
    explain_json: list[Mapping[str, Any]],
    verification: StaticVerification | None = None,
) -> QueryTiming:
    item = explain_json[0]
    return QueryTiming(
        planning_ms=float(item.get("Planning Time", 0.0)),
        execution_ms=float(item.get("Execution Time", 0.0)),
        static_verifier_status="pass" if verification is None else verification.status,
        static_verifier_plan_hash=None if verification is None else verification.plan_hash,
        static_verifier_reasons=() if verification is None else tuple(verification.reasons),
        static_verifier_explain_json=tuple(explain_json),
    )


def _verify_static_template(
    template_id: str,
    sql: str,
    explain_json: list[Mapping[str, Any]],
) -> StaticVerification:
    verification = verify_template_static(template_id, sql, explain_json, _explain_plan_hash(explain_json))
    if verification.status != "pass":
        raise PostgresError(
            f"E8b static verifier failed for {template_id}: "
            + "; ".join(verification.reasons)
        )
    return verification


def _verify_artifact_validated_measurement_template(
    template_id: str,
    sql: str,
    explain_json: list[Mapping[str, Any]],
) -> StaticVerification:
    """Verify a query whose artifact scope is checked in its transaction.

    ``_run_validated_query`` calls ``caprls_assert_artifact_valid`` for every
    artifact immediately before the measured body in the same repeatable-read
    transaction.  For a MAV scan, requiring the body to join the catalog and
    RID-domain relations repeats that check and prescribes an implementation
    detail.  Only those two catalog-binding reasons are discharged here; all
    MAV relation, base-relation, and other template-shape reasons remain hard
    failures.
    """

    if template_id != "mav_scan_v1":
        return _verify_static_template(template_id, sql, explain_json)
    verification = verify_template_static(
        template_id,
        sql,
        explain_json,
        _explain_plan_hash(explain_json),
    )
    catalog_binding_reasons = (
        "MaterializedAuthorizedViewScan SQL must bind MAV relation to artifact scope:",
        "MaterializedAuthorizedViewScan EXPLAIN plan must scan catalog binding relations:",
    )
    remaining = [
        reason
        for reason in verification.reasons
        if not reason.startswith(catalog_binding_reasons)
    ]
    result = StaticVerification(
        status="pass" if not remaining else "fail",
        reasons=remaining,
        plan_hash=verification.plan_hash,
    )
    if result.status != "pass":
        raise PostgresError(
            f"E8b static verifier failed for {template_id}: "
            + "; ".join(result.reasons)
        )
    return result


def _run_e8b_static_preflight(
    template_id: str,
    sql: str,
    pg_env: PostgresEnv,
    *,
    artifact_catalog_validated_in_transaction: bool = False,
) -> _E8bStaticPreflight:
    if not isinstance(template_id, str) or not template_id:
        raise PostgresError("E8b measurement template binding is missing")
    _e8b_measurement_query_body(sql)
    explain_json = _extract_explain_json(
        run_psql_command(_plain_explain_sql(sql), pg_env)
    )
    verification = (
        _verify_artifact_validated_measurement_template(
            template_id,
            sql,
            explain_json,
        )
        if artifact_catalog_validated_in_transaction
        else _verify_static_template(template_id, sql, explain_json)
    )
    return _E8bStaticPreflight(
        template_id=template_id,
        sql=sql,
        verification=verification,
        explain_json=tuple(explain_json),
    )


def _require_e8b_preflight_identity(
    preflight: _E8bStaticPreflight,
    *,
    template_id: str,
    sql: str,
) -> None:
    if (
        not isinstance(preflight, _E8bStaticPreflight)
        or preflight.template_id != template_id
        or preflight.sql != sql
    ):
        raise PostgresError("E8b static preflight identity mismatch")


def _timing_from_e8b_static_preflight(
    preflight: _E8bStaticPreflight,
) -> QueryTiming:
    return QueryTiming(
        planning_ms=0.0,
        execution_ms=0.0,
        static_verifier_status=preflight.verification.status,
        static_verifier_plan_hash=preflight.verification.plan_hash,
        static_verifier_reasons=tuple(preflight.verification.reasons),
        static_verifier_explain_json=preflight.explain_json,
    )


def _timing_with_e8b_static_preflight(
    measurement_explain_json: list[Mapping[str, Any]],
    preflight: _E8bStaticPreflight,
) -> QueryTiming:
    timing = _timing_from_explain_json(measurement_explain_json)
    return replace(
        timing,
        static_verifier_status=preflight.verification.status,
        static_verifier_plan_hash=preflight.verification.plan_hash,
        static_verifier_reasons=tuple(preflight.verification.reasons),
        static_verifier_explain_json=preflight.explain_json,
    )


def _extract_explain_times(stdout: str) -> QueryTiming:
    return _timing_from_explain_json(_extract_explain_json(stdout))


def _query_timing(template_id: str, sql: str, pg_env: PostgresEnv) -> QueryTiming:
    preflight = _run_e8b_static_preflight(template_id, sql, pg_env)
    _require_e8b_preflight_identity(
        preflight,
        template_id=template_id,
        sql=sql,
    )
    measurement_explain_json = _extract_explain_json(
        run_psql_command(_analyze_explain_sql(sql), pg_env)
    )
    return _timing_with_e8b_static_preflight(
        measurement_explain_json,
        preflight,
    )


def _relation_size_bytes(regclass: str, pg_env: PostgresEnv) -> int:
    value = run_psql_command(f"SELECT pg_total_relation_size({_quote(regclass)}::regclass);", pg_env)
    return int(value)


def _representative_case_for_template(
    cases: Sequence[E8bCase],
    template_id: str,
) -> E8bCase:
    if template_id == "mav_scan_v1":
        for case in cases:
            if case.artifact_type in {"mav", "both"}:
                return case
    if template_id == "hybrid_intersect_v1":
        for case in cases:
            if case.artifact_type == "both":
                return case
    if template_id == "auth_index_enum_v1":
        for case in cases:
            if case.artifact_type in {"auth_idx", "both"}:
                return case
    return cases[0]


def _ir_query_plan_for_template(
    cases: Sequence[E8bCase],
    template_id: str,
    sql_context: E8bSqlContext,
    artifact_validation_by_kind: Mapping[str, E8bArtifactValidatorReceipt],
) -> Mapping[str, Any]:
    case = _representative_case_for_template(cases, template_id)
    artifact_kind = _artifact_kind_for_template(template_id)
    result = _planner_result_for_templates(
        case,
        template_ids=(template_id,),
        target_template_id=template_id,
        artifact_status="pass",
        sql_context=sql_context,
        artifact_validation_receipts=(
            {}
            if artifact_kind is None
            else {artifact_kind: artifact_validation_by_kind[artifact_kind]}
        ),
    )
    if not result.query_result.ok:
        raise PostgresError(
            f"E8b IR planner did not admit {template_id}: {result.query_plan.get('root_closure')}"
        )
    emitted_sql = str(result.query_plan.get("emitted_sql") or "")
    if not emitted_sql:
        raise PostgresError(f"E8b IR planner emitted empty SQL for {template_id}")
    return result.query_plan


def _artifact_query_timing(
    case: E8bCase,
    mode: str,
    measurements: PostgresMeasurements,
) -> QueryTiming:
    if mode in {"mav-only", "mav-no-version"}:
        return measurements.mav
    if mode in {"auth-index-enum-only", "naive-auth-index-no-scope"}:
        return measurements.auth_idx
    if case.artifact_type == "mav":
        return measurements.mav
    if case.artifact_type == "both":
        return measurements.hybrid
    return measurements.auth_idx


def _artifact_query_key(case: E8bCase, mode: str) -> str:
    if mode in {"mav-only", "mav-no-version"}:
        return "mav"
    if mode in {"auth-index-enum-only", "naive-auth-index-no-scope"}:
        return "auth_idx"
    if case.artifact_type == "mav":
        return "mav"
    if case.artifact_type == "both":
        return "hybrid"
    return "auth_idx"


def _validates_artifact_for_mode(mode: str) -> bool:
    return mode in {ADMISSION_FIRST_MODE, "auth-index-enum-only", "mav-only"}


def _artifact_build_ms(case: E8bCase, mode: str, measurements: PostgresMeasurements) -> float:
    if mode in {"mav-only", "mav-no-version"}:
        return measurements.build_mav_ms
    if mode in {"auth-index-enum-only", "naive-auth-index-no-scope"}:
        return measurements.build_auth_ms
    if case.artifact_type == "mav":
        return measurements.build_mav_ms
    if case.artifact_type == "both":
        return measurements.build_auth_ms + measurements.build_mav_ms
    return measurements.build_auth_ms


def _artifact_refresh_ms(case: E8bCase, mode: str, measurements: PostgresMeasurements) -> float:
    if mode in {"mav-only", "mav-no-version"}:
        return measurements.refresh_mav_ms
    if mode in {"auth-index-enum-only", "naive-auth-index-no-scope"}:
        return measurements.refresh_auth_ms
    if case.artifact_type == "mav":
        return measurements.refresh_mav_ms
    if case.artifact_type == "both":
        return measurements.refresh_auth_ms + measurements.refresh_mav_ms
    return measurements.refresh_auth_ms


def _artifact_storage_bytes(case: E8bCase, mode: str, measurements: PostgresMeasurements) -> int:
    if mode in {"mav-only", "mav-no-version"}:
        return measurements.storage_mav_bytes
    if mode in {"auth-index-enum-only", "naive-auth-index-no-scope"}:
        return measurements.storage_auth_bytes
    if case.artifact_type == "mav":
        return measurements.storage_mav_bytes
    if case.artifact_type == "both":
        return measurements.storage_auth_bytes + measurements.storage_mav_bytes
    return measurements.storage_auth_bytes


def _prepare_postgres_measurements(
    root: Path,
    manifest: Mapping[str, Any],
    cases: Sequence[E8bCase],
    pg_env: PostgresEnv,
) -> PostgresMeasurements:
    dataset = manifest.get("dataset") or {}
    scale = str(dataset.get("scale", "1e5"))
    seed = int(dataset.get("seed", 51))
    generate_synthetic_saas(root, pg_env, scale=scale, seed=seed, verify=True, output_dir=None)

    policy_app = (manifest.get("policy_applications") or [{}])[0]
    policy_id = str(policy_app.get("policy_id", "tenant_group"))
    policy = _load_policy(root, policy_id)
    if "document" not in policy.get("applicable_relations", []):
        raise PostgresError(f"policy {policy_id} is not applicable to document")

    context_id = "ctx_000001"
    context = _load_context(context_id, pg_env)
    user_id = str(context["user_id"])
    ctx_hash = str(
        run_psql_command(
            f"SELECT ctx_hash FROM public.synthetic_context WHERE context_id = {_quote(context_id)};",
            pg_env,
        )
    )
    exact_predicate = _render_exact_predicate(
        str(policy["exact_sql_template"]),
        alias="d",
        rid_col="doc_id",
        context=context,
        relname="document",
    )
    authorized_count = int(
        run_psql_command(f"SELECT count(*) FROM public.document d WHERE {exact_predicate};", pg_env)
    )
    total_rows = int(run_psql_command("SELECT count(*) FROM public.document;", pg_env))
    if not (0 < authorized_count < total_rows):
        raise PostgresError(
            "E8b study requires both authorized and unauthorized document rows; "
            f"got authorized={authorized_count}, total={total_rows}"
        )

    auth_artifact_id = "e8b_auth_idx_ctx_000001"
    mav_artifact_id = "e8b_mav_ctx_000001"
    pg_version = run_psql_command("SHOW server_version;", pg_env)
    valid_expected_json = json.dumps(
        [{"dep_kind": "context_scope", "dep_name": ctx_hash, "version_at_build": 0}],
        sort_keys=True,
        separators=(",", ":"),
    )
    policy_validation = _live_policy_validator_receipt(
        policy_id=policy_id,
        policy=policy,
        context=context,
        principal_id=user_id,
        context_hash=ctx_hash,
        exact_predicate=exact_predicate,
    )
    sql_context = E8bSqlContext(
        policy_id=policy_id,
        user_id=user_id,
        ctx_hash=ctx_hash,
        exact_predicate=exact_predicate,
        valid_expected_json=valid_expected_json,
        auth_artifact_id=auth_artifact_id,
        mav_artifact_id=mav_artifact_id,
        policy_validation=policy_validation,
    )
    build_auth_ms = _timed_sql_script(
        _build_auth_idx_sql(auth_artifact_id, policy_id, user_id, ctx_hash, exact_predicate),
        pg_env,
    )
    build_mav_ms = _timed_sql_script(
        _build_mav_sql(mav_artifact_id, policy_id, ctx_hash, exact_predicate),
        pg_env,
    )
    valid_validation_by_kind = {
        "auth_idx": _run_validation_gate(auth_artifact_id, valid_expected_json, pg_env),
        "mav": _run_validation_gate(mav_artifact_id, valid_expected_json, pg_env),
    }
    if any(not validation.validation_passed for validation in valid_validation_by_kind.values()):
        raise PostgresError("E8b valid artifact catalog validation failed before planning")
    valid_artifact_validation_by_kind = {
        "auth_idx": _postgres_artifact_validator_receipt(
            artifact_id=auth_artifact_id,
            context_hash=ctx_hash,
            expected_json=valid_expected_json,
            validation=valid_validation_by_kind["auth_idx"],
        ),
        "mav": _postgres_artifact_validator_receipt(
            artifact_id=mav_artifact_id,
            context_hash=ctx_hash,
            expected_json=valid_expected_json,
            validation=valid_validation_by_kind["mav"],
        ),
    }

    validation_by_case: dict[str, ValidationTiming] = {}
    artifact_validation_by_case: dict[str, E8bArtifactValidatorReceipt] = {}
    for case in cases:
        artifact_id = mav_artifact_id if case.artifact_type == "mav" else auth_artifact_id
        expected_json = _expected_json(case, ctx_hash)
        validation = _run_validation_gate(
            artifact_id,
            expected_json,
            pg_env,
        )
        # Expected labels are assertions on the independent validator, never
        # inputs used to issue a pass fact.
        if case.failure_sqlstate is None and not validation.validation_passed:
            raise PostgresError(f"{case.test_id}: validation unexpectedly failed")
        if case.failure_sqlstate is not None and (
            validation.validation_passed
            or validation.failure_sqlstate != case.failure_sqlstate
            or validation.failure_symbol != case.failure_symbol
        ):
            raise PostgresError(f"{case.test_id}: independent validation disagrees with case")
        validation_by_case[case.test_id] = validation
        artifact_validation_by_case[case.test_id] = _postgres_artifact_validator_receipt(
            artifact_id=artifact_id,
            context_hash=ctx_hash,
            expected_json=expected_json,
            validation=validation,
        )

    barrier_plan = _ir_query_plan_for_template(
        cases, "barrier_filter_v1", sql_context, valid_artifact_validation_by_kind
    )
    auth_idx_plan = _ir_query_plan_for_template(
        cases, "auth_index_enum_v1", sql_context, valid_artifact_validation_by_kind
    )
    mav_plan = _ir_query_plan_for_template(
        cases, "mav_scan_v1", sql_context, valid_artifact_validation_by_kind
    )
    hybrid_plan = _ir_query_plan_for_template(
        cases, "hybrid_intersect_v1", sql_context, valid_artifact_validation_by_kind
    )
    barrier_sql = _row_sql_from_ir_emitted_sql(str(barrier_plan["emitted_sql"]))
    auth_idx_sql = _row_sql_from_ir_emitted_sql(str(auth_idx_plan["emitted_sql"]))
    mav_sql = _row_sql_from_ir_emitted_sql(str(mav_plan["emitted_sql"]))
    hybrid_sql = _row_sql_from_ir_emitted_sql(str(hybrid_plan["emitted_sql"]))
    barrier = _query_timing("barrier_filter_v1", barrier_sql, pg_env)
    auth_idx = _query_timing("auth_index_enum_v1", auth_idx_sql, pg_env)
    mav = _query_timing("mav_scan_v1", mav_sql, pg_env)
    hybrid = _query_timing("hybrid_intersect_v1", hybrid_sql, pg_env)
    validated_artifact_queries = {
        "auth_idx": _run_validated_query(
            "auth_index_enum_v1",
            auth_idx_sql,
            (auth_artifact_id,),
            valid_expected_json,
            pg_env,
        ),
        "mav": _run_validated_query(
            "mav_scan_v1",
            mav_sql,
            (mav_artifact_id,),
            valid_expected_json,
            pg_env,
        ),
        "hybrid": _run_validated_query(
            "hybrid_intersect_v1",
            hybrid_sql,
            (auth_artifact_id, mav_artifact_id),
            valid_expected_json,
            pg_env,
        ),
    }
    for query_key, measurement in validated_artifact_queries.items():
        if not measurement.validation.validation_passed:
            raise PostgresError(
                f"E8b validated {query_key} measurement unexpectedly failed: "
                f"{measurement.validation.failure_sqlstate}/{measurement.validation.failure_symbol}"
            )

    storage_auth_bytes = _relation_size_bytes("public.auth_idx", pg_env)
    storage_mav_bytes = _relation_size_bytes("public.e8b_mav_document_ctx_000001", pg_env)
    refresh_auth_ms = _timed_sql_script(
        _build_auth_idx_sql(auth_artifact_id, policy_id, user_id, ctx_hash, exact_predicate),
        pg_env,
    )
    refresh_mav_ms = _timed_sql_script(
        _build_mav_sql(mav_artifact_id, policy_id, ctx_hash, exact_predicate),
        pg_env,
    )

    return PostgresMeasurements(
        pg_version=pg_version,
        context_id=context_id,
        ctx_hash=ctx_hash,
        policy_id=policy_id,
        user_id=user_id,
        exact_predicate=exact_predicate,
        valid_expected_json=valid_expected_json,
        auth_artifact_id=auth_artifact_id,
        mav_artifact_id=mav_artifact_id,
        authorized_count=authorized_count,
        total_rows=total_rows,
        build_auth_ms=build_auth_ms,
        build_mav_ms=build_mav_ms,
        refresh_auth_ms=refresh_auth_ms,
        refresh_mav_ms=refresh_mav_ms,
        storage_auth_bytes=storage_auth_bytes,
        storage_mav_bytes=storage_mav_bytes,
        barrier=barrier,
        auth_idx=auth_idx,
        mav=mav,
        hybrid=hybrid,
        validation_by_case=validation_by_case,
        artifact_validation_by_case=artifact_validation_by_case,
        valid_artifact_validation_by_kind=valid_artifact_validation_by_kind,
        policy_validation=policy_validation,
        validated_artifact_queries=validated_artifact_queries,
        query_plan_by_template={
            "barrier_filter_v1": barrier_plan,
            "auth_index_enum_v1": auth_idx_plan,
            "mav_scan_v1": mav_plan,
            "hybrid_intersect_v1": hybrid_plan,
        },
    )


TOCTOU_POSITIVE_CASE = E8bCase(
    test_id="E8b_toctou_same_snapshot_rr",
    query_shape="same_snapshot_revocation_witness",
    artifact_type="auth_idx",
    update_rate_per_hour=0.0,
    ttl_s=3600,
    contexts=1000,
    artifact_status="pass",
    contract_action="execute",
    expected_effect="same_snapshot_artifact_execution",
)

TOCTOU_DIAGNOSTIC_CASE = E8bCase(
    test_id="E8b_toctou_read_committed_positive_control",
    query_shape="independent_validation_then_revocation",
    artifact_type="auth_idx",
    update_rate_per_hour=0.0,
    ttl_s=3600,
    contexts=1000,
    artifact_status="toctou_fail",
    contract_action="execute",
    expected_effect="CAPRLS_TOCTOU_FAIL",
    failure_sqlstate="P8A04",
    failure_symbol="CAPRLS_TOCTOU_FAIL",
)


def _toctou_expected_json() -> str:
    return json.dumps(
        [
            {
                "dep_kind": "toctou",
                "dep_name": "document_snapshot",
                "version_at_build": 0,
                "failure_sqlstate": "P8A04",
                "failure_symbol": "CAPRLS_TOCTOU_FAIL",
            }
        ],
        sort_keys=True,
        separators=(",", ":"),
    )


def _toctou_auth_idx_row_sql(measurements: PostgresMeasurements) -> str:
    query_plan = measurements.query_plan_by_template.get("auth_index_enum_v1")
    if query_plan is None:
        raise PostgresError("E8b TOCTOU witness requires auth-index IR query plan")
    emitted_sql = str(query_plan.get("emitted_sql", ""))
    return _row_sql_from_ir_emitted_sql(emitted_sql)


def _toctou_ir_count_sql(row_sql: str) -> str:
    body = row_sql.strip().rstrip(";")
    return f"SELECT count(*) FROM (\n{body}\n) caprls_toctou_ir"


def _toctou_ir_hash_expr(row_sql: str) -> str:
    body = row_sql.strip().rstrip(";")
    return f"""
SELECT md5(COALESCE(string_agg(q.doc_id::text, ',' ORDER BY q.doc_id), ''))
FROM (
{body}
) q
"""


def _toctou_mutation_sql(artifact_id: str, rid: int, replacement_ctx_hash: str) -> str:
    return f"""
BEGIN;
UPDATE public.artifact_dependencies
SET version_at_build = version_at_build + 1
WHERE artifact_id = {_quote(artifact_id)}
  AND dep_kind = 'toctou'
  AND dep_name = 'document_snapshot';
UPDATE public.auth_idx
SET ctx_hash = {_quote(replacement_ctx_hash)}
WHERE artifact_id = {_quote(artifact_id)}
  AND rid = {int(rid)};
COMMIT;
"""


def _toctou_restore_sql(artifact_id: str, rid: int, ctx_hash: str) -> str:
    return f"""
BEGIN;
UPDATE public.auth_idx
SET ctx_hash = {_quote(ctx_hash)}
WHERE artifact_id = {_quote(artifact_id)}
  AND rid = {int(rid)};
UPDATE public.artifact_dependencies
SET version_at_build = 0
WHERE artifact_id = {_quote(artifact_id)}
  AND dep_kind = 'toctou'
  AND dep_name = 'document_snapshot';
COMMIT;
"""


def _parse_key_value_lines(stdout: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in stdout.splitlines():
        stripped = line.strip()
        if "=" in stripped:
            key, value = stripped.split("=", 1)
            parsed[key] = value
    return parsed


def _run_psql_file_async(sql_path: Path, pg_env: PostgresEnv) -> subprocess.Popen[str]:
    psql = shutil.which("psql")
    if not psql:
        raise PostgresError("required PostgreSQL tool not found on PATH: psql")
    return subprocess.Popen(
        [
            psql,
            "--no-align",
            "--tuples-only",
            "--set",
            "ON_ERROR_STOP=1",
            "--file",
            str(sql_path),
        ],
        env=pg_env.to_env(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _run_toctou_rr_positive(
    pg_env: PostgresEnv,
    measurements: PostgresMeasurements,
    rid: int,
    replacement_ctx_hash: str,
) -> Mapping[str, Any]:
    expected_json = _toctou_expected_json()
    row_sql = _toctou_auth_idx_row_sql(measurements)
    count_sql = _toctou_ir_count_sql(row_sql)
    hash_sql = _toctou_ir_hash_expr(row_sql)
    script = f"""
\\set ON_ERROR_STOP on
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT public.caprls_assert_artifact_valid(
  {_quote(measurements.auth_artifact_id)},
  {_quote(expected_json)}::jsonb
);
SELECT 'before_count=' || ({count_sql});
SELECT 'before_hash=' || ({hash_sql});
SELECT pg_sleep(1.0);
SELECT 'after_count=' || ({count_sql});
SELECT 'after_hash=' || ({hash_sql});
COMMIT;
"""
    path = _write_temp_sql(script)
    proc = _run_psql_file_async(path, pg_env)
    try:
        time.sleep(0.25)
        run_psql_command(
            _toctou_mutation_sql(measurements.auth_artifact_id, rid, replacement_ctx_hash),
            pg_env,
        )
        stdout, stderr = proc.communicate(timeout=10)
    finally:
        path.unlink(missing_ok=True)
    if proc.returncode != 0:
        raise PostgresError(
            "E8b TOCTOU RR witness failed\n"
            f"stdout:\n{stdout}\n"
            f"stderr:\n{stderr}"
        )
    parsed = _parse_key_value_lines(stdout)
    snapshot_match = (
        parsed.get("before_count") == parsed.get("after_count")
        and parsed.get("before_hash") == parsed.get("after_hash")
    )
    if not snapshot_match:
        raise PostgresError(
            f"E8b TOCTOU RR witness did not preserve snapshot: {parsed}"
        )
    return {
        "role": "same_snapshot_positive",
        "before_count": int(parsed["before_count"]),
        "after_count": int(parsed["after_count"]),
        "before_hash": parsed["before_hash"],
        "after_hash": parsed["after_hash"],
        "snapshot_match": True,
        "mutated_rid": int(rid),
        "concurrent_dependency_bumped": True,
    }


def _run_toctou_read_committed_control(
    pg_env: PostgresEnv,
    measurements: PostgresMeasurements,
    rid: int,
    replacement_ctx_hash: str,
) -> Mapping[str, Any]:
    expected_json = _toctou_expected_json()
    row_sql = _toctou_auth_idx_row_sql(measurements)
    count_sql = _toctou_ir_count_sql(row_sql)
    hash_sql = _toctou_ir_hash_expr(row_sql)
    validation_before = _run_validation_gate(
        measurements.auth_artifact_id,
        expected_json,
        pg_env,
        isolation_level="read_committed",
        same_snapshot=False,
    )
    if not validation_before.validation_passed:
        raise PostgresError(
            "E8b TOCTOU diagnostic pre-validation unexpectedly failed: "
            f"{validation_before.failure_sqlstate}/{validation_before.failure_symbol}"
        )
    before_count = int(run_psql_command(count_sql, pg_env))
    before_hash = run_psql_command(hash_sql, pg_env)
    run_psql_command(
        _toctou_mutation_sql(measurements.auth_artifact_id, rid, replacement_ctx_hash),
        pg_env,
    )
    after_count = int(run_psql_command(count_sql, pg_env))
    after_hash = run_psql_command(hash_sql, pg_env)
    validation_after = _run_validation_gate(
        measurements.auth_artifact_id,
        expected_json,
        pg_env,
        fallback_sqlstate="P8A04",
        fallback_symbol="CAPRLS_TOCTOU_FAIL",
        isolation_level="read_committed",
        same_snapshot=False,
    )
    if validation_after.validation_passed:
        raise PostgresError("E8b TOCTOU diagnostic post-validation unexpectedly passed")
    if validation_after.failure_sqlstate != "P8A04" or validation_after.failure_symbol != "CAPRLS_TOCTOU_FAIL":
        raise PostgresError(
            "E8b TOCTOU diagnostic produced wrong failure: "
            f"{validation_after.failure_sqlstate}/{validation_after.failure_symbol}"
        )
    mismatch = before_count != after_count or before_hash != after_hash
    if not mismatch:
        raise PostgresError("E8b TOCTOU diagnostic did not observe the post-revoke row-set change")
    return {
        "role": "read_committed_positive_control",
        "before_count": before_count,
        "after_count": after_count,
        "before_hash": before_hash,
        "after_hash": after_hash,
        "snapshot_match": False,
        "mutated_rid": int(rid),
        "validation_before_ms": validation_before.elapsed_ms,
        "validation_after_ms": validation_after.elapsed_ms,
        "failure_sqlstate": validation_after.failure_sqlstate,
        "failure_symbol": validation_after.failure_symbol,
    }


def _toctou_metrics(
    *,
    row_count: int,
    validation_ms: float,
    same_snapshot: bool,
    isolation_level: str,
    wrong_result: bool = False,
) -> dict[str, Any]:
    return {
        "planning_ms": 0.0,
        "total_ms": validation_ms,
        "execution_ms": 0.0,
        "query_only_ms": 0.0,
        "version_check_overhead_ms": validation_ms,
        "invalidation_count": 1.0,
        "artifact_hit_rate": 1.0 if not wrong_result else 0.0,
        "build_ms": 0.0,
        "refresh_ms": 0.0,
        "fallback_ms": 0.0,
        "maintenance_unit_ms": 0.0,
        "storage_bytes": 8192.0,
        "authorized_rows": float(row_count),
        "candidate_rows": float(row_count),
        "total_rows": float(row_count),
        "artifact_lookups": 1.0,
        "artifact_validation_same_snapshot": 1.0 if same_snapshot else 0.0,
        "artifact_validation_isolation_level": isolation_level,
    }


def _toctou_witness_records(
    root: Path,
    manifest_path: Path,
    measurements: PostgresMeasurements,
    pg_env: PostgresEnv,
    manifest_id: str,
    dataset_scale: str,
    dataset_seed: int,
) -> list[dict[str, Any]]:
    rid = int(
        run_psql_command(
            f"""
SELECT rid
FROM public.auth_idx
WHERE artifact_id = {_quote(measurements.auth_artifact_id)}
  AND policy_id = {_quote(measurements.policy_id)}
  AND ctx_hash = {_quote(measurements.ctx_hash)}
ORDER BY rid
LIMIT 1;
""",
            pg_env,
        )
    )
    replacement_ctx_hash = "sha256:e8b_toctou_revoked_context"
    auth_idx_query_plan = _planner_result_for_templates(
        TOCTOU_POSITIVE_CASE,
        template_ids=("auth_index_enum_v1",),
        target_template_id="auth_index_enum_v1",
        sql_context=measurements,
        artifact_validation_receipts={
            "auth_idx": measurements.valid_artifact_validation_by_kind["auth_idx"]
        },
    ).query_plan
    records: list[dict[str, Any]] = []
    try:
        positive = _run_toctou_rr_positive(pg_env, measurements, rid, replacement_ctx_hash)
        positive_record = _record(
            root=root,
            manifest_path=manifest_path,
            case=TOCTOU_POSITIVE_CASE,
            mode=ADMISSION_FIRST_MODE,
            outcome=_mode_outcome(TOCTOU_POSITIVE_CASE, ADMISSION_FIRST_MODE),
            metrics_override=_toctou_metrics(
                row_count=int(positive["after_count"]),
                validation_ms=0.0,
                same_snapshot=True,
                isolation_level="repeatable_read",
            ),
            pg_version=measurements.pg_version,
            policy_id=measurements.policy_id,
            context_id=measurements.context_id,
            ctx_hash=measurements.ctx_hash,
            principal_id=measurements.user_id,
            exact_predicate=measurements.exact_predicate,
            planning_evidence_scope=E8B_POSTGRES_PLANNING_EVIDENCE_SCOPE,
            artifact_versions={measurements.auth_artifact_id: 0},
            manifest_id=manifest_id,
            stage="freshness_maintenance",
            dataset_scale=dataset_scale,
            dataset_seed=dataset_seed,
            execution_sql_source="planner_ir_emitted",
            query_plan_payload_override=auth_idx_query_plan,
        )
        positive_record["e8b_toctou_witness"] = dict(positive)
        records.append(positive_record)
    finally:
        run_psql_command(
            _toctou_restore_sql(measurements.auth_artifact_id, rid, measurements.ctx_hash),
            pg_env,
        )

    try:
        diagnostic = _run_toctou_read_committed_control(pg_env, measurements, rid, replacement_ctx_hash)
        diagnostic_outcome = _mode_outcome(TOCTOU_DIAGNOSTIC_CASE, "naive-artifact-only")
        diagnostic_record = _record(
            root=root,
            manifest_path=manifest_path,
            case=TOCTOU_DIAGNOSTIC_CASE,
            mode="naive-artifact-only",
            outcome=diagnostic_outcome,
            metrics_override=_toctou_metrics(
                row_count=int(diagnostic["after_count"]),
                validation_ms=float(diagnostic["validation_after_ms"]),
                same_snapshot=False,
                isolation_level="read_committed",
                wrong_result=True,
            ),
            pg_version=measurements.pg_version,
            policy_id=measurements.policy_id,
            context_id=measurements.context_id,
            ctx_hash=measurements.ctx_hash,
            principal_id=measurements.user_id,
            exact_predicate=measurements.exact_predicate,
            planning_evidence_scope=E8B_POSTGRES_PLANNING_EVIDENCE_SCOPE,
            artifact_versions={measurements.auth_artifact_id: 0},
            manifest_id=manifest_id,
            stage="freshness_maintenance",
            dataset_scale=dataset_scale,
            dataset_seed=dataset_seed,
            execution_sql_source="planner_ir_emitted",
            query_plan_payload_override=auth_idx_query_plan,
        )
        diagnostic_record["e8b_toctou_witness"] = dict(diagnostic)
        records.append(diagnostic_record)
    finally:
        run_psql_command(
            _toctou_restore_sql(measurements.auth_artifact_id, rid, measurements.ctx_hash),
            pg_env,
        )
    return records


def _evaluation_role(root: Path, mode: str) -> str:
    return load_mode_registry(root)[normalize_mode_id(mode)].evaluation_role


def _template_for_mode(mode: str, case: E8bCase) -> tuple[str, str]:
    mode = normalize_mode_id(mode)
    if mode in {"conservative-barrier", "native-pg-rls", "native-pg-rls-physical-design"}:
        return ("barrier_filter_v1", "BarrierFilter")
    if mode in {"auth-index-enum-only", "naive-auth-index-no-scope"}:
        return ("auth_index_enum_v1", "AuthorizationIndexSeek")
    if mode in {"mav-only", "mav-no-version"}:
        return ("mav_scan_v1", "MaterializedAuthorizedViewScan")
    if mode == "stale-artifact-user":
        if case.artifact_type == "mav":
            return ("mav_scan_v1", "MaterializedAuthorizedViewScan")
        if case.artifact_type == "both":
            return ("hybrid_intersect_v1", "HybridIndexIntersect")
        return ("auth_index_enum_v1", "AuthorizationIndexSeek")
    if case.artifact_type == "mav":
        return ("mav_scan_v1", "MaterializedAuthorizedViewScan")
    if case.artifact_type == "both":
        return ("hybrid_intersect_v1", "HybridIndexIntersect")
    return ("auth_index_enum_v1", "AuthorizationIndexSeek")


def _artifact_kind_for_template(template_id: str) -> Optional[str]:
    if template_id == "mav_scan_v1":
        return "mav"
    if template_id in {"auth_index_enum_v1", "hybrid_intersect_v1"}:
        return "auth_idx"
    return None


def _artifact_metadata_for_case(
    case: E8bCase,
    *,
    template_id: str,
    artifact_status: Optional[str] = None,
    artifact_ids: Optional[Mapping[str, str]] = None,
    artifact_validation_receipts: Optional[
        Mapping[str, E8bArtifactValidatorReceipt]
    ] = None,
) -> dict[str, ArtifactMetadata]:
    kind = _artifact_kind_for_template(template_id)
    if kind is None:
        return {}
    status = case.artifact_status if artifact_status is None else artifact_status
    validator_receipt = (
        artifact_validation_receipts.get(kind)
        if artifact_validation_receipts is not None
        else None
    )
    if artifact_validation_receipts is not None and validator_receipt is None:
        raise ValueError(f"missing E8b artifact validator receipt for {kind}")
    is_mav = kind == "mav"
    artifact_id = (
        validator_receipt.artifact_id
        if validator_receipt is not None
        else str(artifact_ids[kind])
        if artifact_ids is not None and kind in artifact_ids
        else f"e8b_{kind}_{case.test_id}"
    )
    if validator_receipt is None:
        fresh = status != "stale"
        context_matches = status != "wrong_context"
        rid_domain_matches = status != "rid_mismatch"
        exact = True
    else:
        _replay_artifact_validator_receipt(validator_receipt)
        failure_symbol = validator_receipt.failure_symbol
        fresh = validator_receipt.accepted or failure_symbol not in {
            "CAPRLS_ARTIFACT_STALE",
            "CAPRLS_TOCTOU_FAIL",
        }
        context_matches = validator_receipt.accepted or failure_symbol != (
            "CAPRLS_CONTEXT_MISMATCH"
        )
        rid_domain_matches = validator_receipt.accepted or failure_symbol != (
            "CAPRLS_RID_MISMATCH"
        )
        # An unclassified validator failure must not look usable to legacy
        # metadata checks that accompany the typed fact.
        exact = validator_receipt.accepted or failure_symbol is not None
    return {
        kind: ArtifactMetadata(
            kind=kind,
            artifact_id=artifact_id,
            fresh=fresh,
            context_matches=context_matches,
            scope_matches=context_matches,
            rid_domain_matches=rid_domain_matches,
            base_relation_matches=rid_domain_matches,
            exact=exact,
            cardinality=180 if is_mav else 120,
            rows=180 if is_mav else 120,
            build_ms=20.0 if is_mav else 4.0,
            refresh_ms=12.0 if is_mav else 4.0,
            storage_bytes=4096 * max(1, case.contexts) * (2 if case.artifact_type == "both" else 1),
        )
    }


def _allowed_enforcers_for_case(case: E8bCase) -> tuple[str, ...]:
    # The bounded IR continuation permits a validation gate.  Fallback and
    # refresh are trial-protocol actions, not root enforcers inferred from the
    # case's expected outcome.
    return ("validation_gate",)


def _root_rho_for_case(case: E8bCase) -> dict[str, Any]:
    return {
        "logical_group_id": case.test_id,
        "allowed_enforcers": _allowed_enforcers_for_case(case),
    }


def _artifact_validation_claims(problem: PlanningProblem) -> dict[str, Mapping[str, Any]]:
    claims: dict[str, Mapping[str, Any]] = {}
    for declared_kind, artifact in sorted(problem.artifacts.items()):
        checks = {
            "declared_kind_matches": declared_kind == artifact.kind,
            "artifact_id_present": bool(artifact.artifact_id),
            "fresh": artifact.fresh,
            "context_matches": artifact.context_matches,
            "scope_matches": artifact.scope_matches,
            "rid_domain_matches": artifact.rid_domain_matches,
            "base_relation_matches": artifact.base_relation_matches,
            "exact": artifact.exact,
        }
        if artifact.keyed:
            checks["key_domain_matches"] = artifact.key_domain_matches
        claims[declared_kind] = {
            "artifact_id": artifact.artifact_id,
            "artifact_kind": artifact.kind,
            "checks": checks,
            "accepted": all(checks.values()),
        }
    return claims


def _policy_validator_receipt_payload(
    receipt: E8bPolicyValidatorReceipt,
) -> dict[str, Any]:
    payload = receipt.to_dict()
    payload.pop("receipt_digest", None)
    return payload


def _fixture_policy_validator_receipt(
    *,
    principal_id: str,
    context_hash: str,
    exact_predicate: str,
) -> E8bPolicyValidatorReceipt:
    if (
        principal_id != E8B_FIXTURE_PRINCIPAL_ID
        or context_hash != E8B_FIXTURE_CONTEXT_HASH
        or exact_predicate != E8B_FIXTURE_EXACT_PREDICATE
    ):
        raise ValueError("unknown E8b fixture policy/principal/context/predicate")
    definition = {
        "policy_id": "tenant_group",
        "relation": "document",
        "rid_col": "doc_id",
        "exact_predicate": E8B_FIXTURE_EXACT_PREDICATE,
        "safe_query_label": E8B_FIXTURE_SAFE_QUERY_LABEL,
    }
    draft = E8bPolicyValidatorReceipt(
        validator_version=E8B_POLICY_VALIDATOR_VERSION,
        evidence_scope=E8B_PLANNING_EVIDENCE_SCOPE,
        promotable=False,
        policy_id="tenant_group",
        relation="document",
        rid_col="doc_id",
        principal_id=principal_id,
        context_hash=context_hash,
        policy_definition_digest=_digest(definition),
        context_digest=_digest(
            {"principal_id": principal_id, "context_hash": context_hash}
        ),
        exact_predicate=exact_predicate,
        exact_predicate_digest=_text_digest(exact_predicate),
        safe_query_label=E8B_FIXTURE_SAFE_QUERY_LABEL,
        receipt_digest="pending",
    )
    return replace(
        draft,
        receipt_digest=_digest(_policy_validator_receipt_payload(draft)),
    )


def _live_policy_validator_receipt(
    *,
    policy_id: str,
    policy: Mapping[str, Any],
    context: Mapping[str, Any],
    principal_id: str,
    context_hash: str,
    exact_predicate: str,
) -> E8bPolicyValidatorReceipt:
    if policy_id != "tenant_group" or "document" not in policy.get(
        "applicable_relations", ()
    ):
        raise PostgresError("E8b live policy validator received an unknown policy target")
    rendered = _render_exact_predicate(
        str(policy.get("exact_sql_template", "")),
        alias="d",
        rid_col="doc_id",
        context=context,
        relname="document",
    )
    if exact_predicate != rendered or principal_id != str(context.get("user_id", "")):
        raise PostgresError("E8b live policy predicate/principal is not renderer-originated")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", context_hash):
        raise PostgresError("E8b live policy context hash is not canonical")
    draft = E8bPolicyValidatorReceipt(
        validator_version=E8B_POLICY_VALIDATOR_VERSION,
        evidence_scope=E8B_POSTGRES_PLANNING_EVIDENCE_SCOPE,
        promotable=True,
        policy_id=policy_id,
        relation="document",
        rid_col="doc_id",
        principal_id=principal_id,
        context_hash=context_hash,
        policy_definition_digest=_digest({"policy_id": policy_id, "policy": dict(policy)}),
        context_digest=_digest({"context": dict(context), "context_hash": context_hash}),
        exact_predicate=rendered,
        exact_predicate_digest=_text_digest(rendered),
        safe_query_label="query_predicate_equals_renderer_originated_exact_policy_v1",
        receipt_digest="pending",
    )
    return replace(
        draft,
        receipt_digest=_digest(_policy_validator_receipt_payload(draft)),
    )


def _replay_policy_validator_receipt(receipt: E8bPolicyValidatorReceipt) -> None:
    if receipt.validator_version != E8B_POLICY_VALIDATOR_VERSION:
        raise ValueError("untrusted E8b policy validator version")
    if receipt.exact_predicate_digest != _text_digest(receipt.exact_predicate):
        raise ValueError("E8b policy predicate digest mismatch")
    if receipt.receipt_digest != _digest(_policy_validator_receipt_payload(receipt)):
        raise ValueError("E8b policy validator receipt digest mismatch")
    if receipt.evidence_scope == E8B_PLANNING_EVIDENCE_SCOPE:
        if receipt.promotable:
            raise ValueError("fixture policy evidence cannot be promotable")
        if receipt != _fixture_policy_validator_receipt(
            principal_id=receipt.principal_id,
            context_hash=receipt.context_hash,
            exact_predicate=receipt.exact_predicate,
        ):
            raise ValueError("E8b fixture policy receipt is not canonical")
    elif receipt.evidence_scope == E8B_POSTGRES_PLANNING_EVIDENCE_SCOPE:
        if (
            not receipt.promotable
            or receipt.safe_query_label
            != "query_predicate_equals_renderer_originated_exact_policy_v1"
        ):
            raise ValueError("invalid PostgreSQL policy validator safety receipt")
    else:
        raise ValueError("unknown E8b policy evidence scope")


def _artifact_validator_receipt_payload(
    receipt: E8bArtifactValidatorReceipt,
) -> dict[str, Any]:
    payload = receipt.to_dict()
    payload.pop("evidence_digest", None)
    return payload


def _make_artifact_validator_receipt(
    *,
    evidence_scope: str,
    promotable: bool,
    artifact_id: str,
    context_hash: str,
    expected_contract_digest: str,
    validation: ValidationTiming,
) -> E8bArtifactValidatorReceipt:
    snapshot_id = _digest(
        {
            "validator_version": E8B_ARTIFACT_VALIDATOR_VERSION,
            "evidence_scope": evidence_scope,
            "artifact_id": artifact_id,
            "context_hash": context_hash,
            "expected_contract_digest": expected_contract_digest,
        }
    )
    draft = E8bArtifactValidatorReceipt(
        validator_version=E8B_ARTIFACT_VALIDATOR_VERSION,
        evidence_scope=evidence_scope,
        promotable=promotable,
        artifact_id=artifact_id,
        context_hash=context_hash,
        expected_contract_digest=expected_contract_digest,
        planning_snapshot_id=snapshot_id,
        verdict="pass" if validation.validation_passed else "fail",
        failure_sqlstate=validation.failure_sqlstate,
        failure_symbol=validation.failure_symbol,
        same_snapshot=validation.same_snapshot,
        isolation_level=validation.isolation_level,
        evidence_digest="pending",
    )
    return replace(
        draft,
        evidence_digest=_digest(_artifact_validator_receipt_payload(draft)),
    )


def _replay_artifact_validator_receipt(
    receipt: E8bArtifactValidatorReceipt,
) -> None:
    if receipt.validator_version != E8B_ARTIFACT_VALIDATOR_VERSION:
        raise ValueError("untrusted E8b artifact validator version")
    if receipt.evidence_scope not in {
        E8B_PLANNING_EVIDENCE_SCOPE,
        E8B_POSTGRES_PLANNING_EVIDENCE_SCOPE,
    }:
        raise ValueError("unknown E8b artifact evidence scope")
    expected_snapshot = _digest(
        {
            "validator_version": receipt.validator_version,
            "evidence_scope": receipt.evidence_scope,
            "artifact_id": receipt.artifact_id,
            "context_hash": receipt.context_hash,
            "expected_contract_digest": receipt.expected_contract_digest,
        }
    )
    if receipt.planning_snapshot_id != expected_snapshot:
        raise ValueError("E8b artifact validator snapshot mismatch")
    if receipt.evidence_digest != _digest(_artifact_validator_receipt_payload(receipt)):
        raise ValueError("E8b artifact validator evidence digest mismatch")
    if receipt.verdict not in {"pass", "fail"}:
        raise ValueError("invalid E8b artifact validator verdict")
    if receipt.evidence_scope == E8B_POSTGRES_PLANNING_EVIDENCE_SCOPE and (
        not receipt.promotable
        or not receipt.same_snapshot
        or receipt.isolation_level != "repeatable_read"
    ):
        raise ValueError("PostgreSQL planning validation lacks repeatable-read evidence")
    if receipt.evidence_scope == E8B_PLANNING_EVIDENCE_SCOPE and receipt.promotable:
        raise ValueError("fixture artifact evidence cannot be promotable")


def _fixture_artifact_validator_receipts(
    problem: PlanningProblem,
    *,
    context_hash: str,
) -> dict[str, E8bArtifactValidatorReceipt]:
    receipts: dict[str, E8bArtifactValidatorReceipt] = {}
    for kind, claim in _artifact_validation_claims(problem).items():
        checks = dict(claim["checks"])
        failure_symbol = None
        failure_sqlstate = None
        if not bool(claim["accepted"]):
            if not checks.get("fresh", True):
                failure_symbol = "CAPRLS_ARTIFACT_STALE"
            elif not checks.get("context_matches", True) or not checks.get(
                "scope_matches", True
            ):
                failure_symbol = "CAPRLS_CONTEXT_MISMATCH"
            elif not checks.get("rid_domain_matches", True) or not checks.get(
                "base_relation_matches", True
            ):
                failure_symbol = "CAPRLS_RID_MISMATCH"
            if failure_symbol is not None:
                failure_sqlstate = SQLSTATE_BY_SYMBOL[failure_symbol]
        validation = ValidationTiming(
            validation_passed=bool(claim["accepted"]),
            failure_sqlstate=failure_sqlstate,
            failure_symbol=failure_symbol,
            elapsed_ms=0.0,
            same_snapshot=False,
            isolation_level=None,
        )
        receipts[kind] = _make_artifact_validator_receipt(
            evidence_scope=E8B_PLANNING_EVIDENCE_SCOPE,
            promotable=False,
            artifact_id=str(claim["artifact_id"]),
            context_hash=context_hash,
            expected_contract_digest=_digest({"fixture_artifact_claim": dict(claim)}),
            validation=validation,
        )
    return receipts


def _postgres_artifact_validator_receipt(
    *,
    artifact_id: str,
    context_hash: str,
    expected_json: str,
    validation: ValidationTiming,
) -> E8bArtifactValidatorReceipt:
    receipt = _make_artifact_validator_receipt(
        evidence_scope=E8B_POSTGRES_PLANNING_EVIDENCE_SCOPE,
        promotable=True,
        artifact_id=artifact_id,
        context_hash=context_hash,
        expected_contract_digest=_text_digest(expected_json),
        validation=validation,
    )
    _replay_artifact_validator_receipt(receipt)
    return receipt


def _logical_target_from_policy_receipt(
    receipt: E8bPolicyValidatorReceipt,
    *,
    occurrence_id: str,
) -> PolicyAccessTarget:
    return PolicyAccessTarget(
        relation=receipt.relation,
        policy_id=receipt.policy_id,
        occurrence_id=occurrence_id,
        principal_id=receipt.principal_id,
        context_digest=receipt.context_digest,
        policy_predicate_digest=receipt.policy_definition_digest,
    )


def _implementation_bindings_for_templates(
    template_ids: Sequence[str],
    *,
    target: PolicyAccessTarget,
    rid_col: str,
    query_predicate: str,
) -> tuple[ImplementationTargetBinding, ...]:
    ordered_ids = tuple(str(item) for item in template_ids)
    if not ordered_ids or len(set(ordered_ids)) != len(ordered_ids):
        raise ValueError("E8b target binding template IDs must be nonempty and unique")
    bindings: list[ImplementationTargetBinding] = []
    for template_id in ordered_ids:
        definition = template_definition(template_id)
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


def _planning_target_binding(
    problem: PlanningProblem,
    *,
    principal_id: str,
    context_hash: str,
    exact_predicate: str,
) -> dict[str, Any]:
    logical_target = problem.logical_target
    if not isinstance(logical_target, PolicyAccessTarget):
        raise ValueError("E8b planning target requires typed PolicyAccessTarget")
    return {
        "principal_id": principal_id,
        "context_hash": context_hash,
        "policy_id": problem.policy_id,
        "relation": problem.relation,
        "occurrence_id": problem.occurrence_id,
        "rid_col": problem.rid_col,
        "rid_domain_id": f"{problem.relation}.{problem.rid_col}",
        "policy_subject_digest": policy_subject_digest(problem),
        "exact_predicate_digest": _text_digest(exact_predicate),
        "logical_target": logical_target.to_dict(),
        "logical_target_digest": logical_target.digest,
        "implementation_target_bindings": [
            binding.to_dict()
            for binding in problem.implementation_target_bindings
        ],
        "implementation_target_binding_digests": [
            binding.digest for binding in problem.implementation_target_bindings
        ],
    }


def _issue_e8b_planning_validator_receipt(
    problem: PlanningProblem,
    *,
    principal_id: str,
    context_hash: str,
    exact_predicate: str,
    policy_validation: Optional[E8bPolicyValidatorReceipt] = None,
    artifact_validation_receipts: Optional[
        Mapping[str, E8bArtifactValidatorReceipt]
    ] = None,
    planning_snapshot_id: Optional[str] = None,
) -> E8bPlanningValidatorReceipt:
    """Validate bounded fixture metadata and issue a deterministic typed Gamma.

    The validator consumes explicit target identity plus artifact metadata.  It
    never reads ``E8bCase.artifact_status`` or a chosen template/outcome, and
    its receipt is planning-only: live freshness/context/TOCTOU remain dynamic
    execution obligations recorded by typed admission.
    """

    policy_receipt = policy_validation or _fixture_policy_validator_receipt(
        principal_id=principal_id,
        context_hash=context_hash,
        exact_predicate=exact_predicate,
    )
    _replay_policy_validator_receipt(policy_receipt)
    if (
        policy_receipt.principal_id != principal_id
        or policy_receipt.context_hash != context_hash
        or policy_receipt.policy_id != problem.policy_id
        or policy_receipt.relation != problem.relation
        or policy_receipt.rid_col != problem.rid_col
        or policy_receipt.exact_predicate != exact_predicate
    ):
        raise ValueError("E8b policy validator receipt does not match planning target")
    expected_logical_target = _logical_target_from_policy_receipt(
        policy_receipt,
        occurrence_id=problem.occurrence_id,
    )
    if problem.logical_target != expected_logical_target:
        raise ValueError("E8b logical target does not match policy validator receipt")
    if problem.query_predicate != exact_predicate:
        raise ValueError("E8b query predicate does not match validated exact predicate")
    if not problem.implementation_target_bindings:
        raise ValueError("E8b planning target requires implementation bindings")
    expected_bindings = _implementation_bindings_for_templates(
        tuple(
            binding.template_id
            for binding in problem.implementation_target_bindings
        ),
        target=expected_logical_target,
        rid_col=problem.rid_col,
        query_predicate=exact_predicate,
    )
    if tuple(problem.implementation_target_bindings) != expected_bindings:
        raise ValueError("E8b implementation target binding is not canonical")
    binding_artifact_kinds = {
        kind
        for binding in expected_bindings
        for kind in template_definition(binding.template_id).required_artifacts
    }
    if binding_artifact_kinds != set(problem.artifacts):
        raise ValueError("E8b implementation bindings and artifact set disagree")

    target = _planning_target_binding(
        problem,
        principal_id=principal_id,
        context_hash=context_hash,
        exact_predicate=exact_predicate,
    )
    artifact_receipts = dict(
        artifact_validation_receipts
        if artifact_validation_receipts is not None
        else _fixture_artifact_validator_receipts(problem, context_hash=context_hash)
    )
    if set(artifact_receipts) != set(problem.artifacts):
        raise ValueError("E8b artifact validator receipt set does not match artifacts")
    for kind, artifact in problem.artifacts.items():
        artifact_receipt = artifact_receipts[kind]
        _replay_artifact_validator_receipt(artifact_receipt)
        if (
            artifact_receipt.artifact_id != artifact.artifact_id
            or artifact_receipt.context_hash != context_hash
            or artifact_receipt.evidence_scope != policy_receipt.evidence_scope
        ):
            raise ValueError("E8b artifact validator receipt identity/scope mismatch")
    artifact_evidence = {
        kind: receipt.to_dict() for kind, receipt in sorted(artifact_receipts.items())
    }
    artifact_metadata_digest = _digest({"artifact_validator_receipts": artifact_evidence})
    evidence_scope = policy_receipt.evidence_scope
    snapshot_id = planning_snapshot_id or _digest(
        {
            "snapshot_kind": "e8b_validator_bound_planning_snapshot_v3",
            "validator_version": E8B_PLANNING_VALIDATOR_VERSION,
            "evidence_scope": evidence_scope,
            "target": target,
            "policy_validator_receipt_digest": policy_receipt.receipt_digest,
            "artifact_metadata_digest": artifact_metadata_digest,
        }
    )
    # A safe-query fact is issued only for the validator's explicit safety
    # label and exact predicate identity, never for an arbitrary SQL string.
    policy_accepted = bool(policy_receipt.safe_query_label)
    fact_evidence: list[Mapping[str, Any]] = []

    def fact(
        kind: str,
        subject_digest: str,
        accepted: bool,
        claims: Mapping[str, Any],
    ) -> GammaFact:
        evidence = {
            "validator_version": E8B_PLANNING_VALIDATOR_VERSION,
            "evidence_scope": evidence_scope,
            "planning_snapshot_id": snapshot_id,
            "target": target,
            "kind": kind,
            "subject_digest": subject_digest,
            "verdict": "pass" if accepted else "fail",
            "claims": claims,
        }
        fact_evidence.append(evidence)
        fact_seed = _digest(evidence).removeprefix("sha256:")[:20]
        return GammaFact(
            fact_id=f"e8b-planning:{kind}:{fact_seed}",
            kind=kind,
            subject_digest=subject_digest,
            verdict="pass" if accepted else "fail",
            validator_version=E8B_PLANNING_VALIDATOR_VERSION,
            snapshot_id=snapshot_id,
            evidence_digest=_digest(evidence),
            dynamic=False,
        )

    policy_subject = policy_subject_digest(problem)
    facts: list[GammaFact] = [
        fact(
            "trusted_exact_policy_executable",
            policy_subject,
            policy_accepted,
            {"policy_validator_receipt": policy_receipt.to_dict()},
        ),
        fact(
            "safe_query_predicate",
            policy_subject,
            policy_accepted,
            {
                "policy_validator_receipt": policy_receipt.to_dict(),
                "safe_query_label": policy_receipt.safe_query_label,
            },
        ),
    ]
    for declared_kind, artifact_receipt in sorted(artifact_receipts.items()):
        facts.append(
            fact(
                "artifact_validation",
                artifact_receipt.artifact_id,
                artifact_receipt.accepted,
                {
                    "declared_kind": declared_kind,
                    "artifact_validator_receipt": artifact_receipt.to_dict(),
                },
            )
        )
    logical_target = problem.logical_target
    assert isinstance(logical_target, PolicyAccessTarget)
    for binding in problem.implementation_target_bindings:
        definition = template_definition(binding.template_id)
        missing_binding_receipts = set(definition.required_artifacts) - set(
            artifact_receipts
        )
        if missing_binding_receipts:
            raise ValueError(
                "E8b target binding lacks required artifact receipts: "
                + ", ".join(sorted(missing_binding_receipts))
            )
        relevant_artifact_receipts = {
            kind: artifact_receipts[kind].to_dict()
            for kind in sorted(definition.required_artifacts)
            if kind in artifact_receipts
        }
        binding_claims = {
            "logical_target": logical_target.to_dict(),
            "logical_target_digest": logical_target.digest,
            "implementation_target_binding": binding.to_dict(),
            "implementation_target_binding_digest": binding.digest,
            "policy_validator_receipt": policy_receipt.to_dict(),
            "artifact_validator_receipts": relevant_artifact_receipts,
            "query_predicate": exact_predicate,
        }
        binding_accepted = policy_accepted and all(
            artifact_receipts[kind].accepted
            for kind in definition.required_artifacts
        )
        if binding.refinement_kind is not None:
            facts.append(
                fact(
                    "target_refinement",
                    target_refinement_subject_digest(
                        binding,
                        logical_target,
                        snapshot_id=snapshot_id,
                    ),
                    binding_accepted,
                    binding_claims,
                )
            )
        elif binding.implementation_target_kind != "bare_occurrence":
            facts.append(
                fact(
                    "implementation_target_match",
                    implementation_target_match_subject_digest(
                        binding,
                        logical_target,
                        snapshot_id=snapshot_id,
                    ),
                    binding_accepted,
                    binding_claims,
                )
            )
    gamma = GammaSnapshot(snapshot_id=snapshot_id, facts=tuple(facts))
    draft_receipt = E8bPlanningValidatorReceipt(
        validator_version=E8B_PLANNING_VALIDATOR_VERSION,
        evidence_scope=evidence_scope,
        principal_id=principal_id,
        context_hash=context_hash,
        policy_id=problem.policy_id,
        relation=problem.relation,
        occurrence_id=problem.occurrence_id,
        rid_col=problem.rid_col,
        rid_domain_id=f"{problem.relation}.{problem.rid_col}",
        policy_subject_digest=target["policy_subject_digest"],
        exact_predicate_digest=target["exact_predicate_digest"],
        logical_target=logical_target,
        implementation_target_bindings=tuple(problem.implementation_target_bindings),
        artifact_metadata_digest=artifact_metadata_digest,
        planning_snapshot_id=snapshot_id,
        gamma_snapshot=gamma,
        receipt_digest="pending",
        fact_evidence=tuple(fact_evidence),
    )
    return replace(
        draft_receipt,
        receipt_digest=_digest(_planning_receipt_digest_payload(draft_receipt)),
    )


def _validate_e8b_planning_validator_receipt(
    problem: PlanningProblem,
    receipt: E8bPlanningValidatorReceipt,
    *,
    principal_id: str,
    context_hash: str,
    exact_predicate: str,
    policy_validation: Optional[E8bPolicyValidatorReceipt] = None,
    artifact_validation_receipts: Optional[
        Mapping[str, E8bArtifactValidatorReceipt]
    ] = None,
    planning_snapshot_id: Optional[str] = None,
) -> None:
    """Fail closed unless receipt, expected identity, and attached Gamma agree."""

    expected = _issue_e8b_planning_validator_receipt(
        replace(problem, gamma_snapshot=None),
        principal_id=principal_id,
        context_hash=context_hash,
        exact_predicate=exact_predicate,
        policy_validation=policy_validation,
        artifact_validation_receipts=artifact_validation_receipts,
        planning_snapshot_id=planning_snapshot_id,
    )
    if receipt != expected:
        raise ValueError("E8b planning validator receipt does not match expected target/snapshot")
    if problem.gamma_snapshot != receipt.gamma_snapshot:
        raise ValueError("E8b PlanningProblem Gamma does not match its validator receipt")
    if receipt.gamma_snapshot.snapshot_id != receipt.planning_snapshot_id:
        raise ValueError("E8b validator receipt snapshot does not match Gamma snapshot")


def _planning_problem_and_receipt_for_case(
    case: E8bCase,
    *,
    template_id: str,
    template_ids: Optional[Sequence[str]] = None,
    artifact_status: Optional[str] = None,
    artifact_ids: Optional[Mapping[str, str]] = None,
    principal_id: str = E8B_FIXTURE_PRINCIPAL_ID,
    context_hash: str = E8B_FIXTURE_CONTEXT_HASH,
    exact_predicate: str = E8B_FIXTURE_EXACT_PREDICATE,
    policy_validation: Optional[E8bPolicyValidatorReceipt] = None,
    artifact_validation_receipts: Optional[
        Mapping[str, E8bArtifactValidatorReceipt]
    ] = None,
    planning_snapshot_id: Optional[str] = None,
) -> tuple[PlanningProblem, E8bPlanningValidatorReceipt]:
    policy_receipt = policy_validation or _fixture_policy_validator_receipt(
        principal_id=principal_id,
        context_hash=context_hash,
        exact_predicate=exact_predicate,
    )
    _replay_policy_validator_receipt(policy_receipt)
    logical_target = _logical_target_from_policy_receipt(
        policy_receipt,
        occurrence_id=case.test_id,
    )
    bound_template_ids = tuple(template_ids or (template_id,))
    target_bindings = _implementation_bindings_for_templates(
        bound_template_ids,
        target=logical_target,
        rid_col="doc_id",
        query_predicate=exact_predicate,
    )
    draft = PlanningProblem(
        planning_execution_class="production_normal",
        relation="document",
        policy_id="tenant_group",
        occurrence_id=case.test_id,
        rid_col="doc_id",
        required_attrs=("tenant_id", "region"),
        required_ctx=("ctx_hash",),
        exact_policy_safe=False,
        supports_guard=True,
        has_safe_query_predicate=False,
        logical_target=logical_target,
        implementation_target_bindings=target_bindings,
        query_predicate=exact_predicate,
        require_typed_admission=True,
        artifacts=_artifact_metadata_for_case(
            case,
            template_id=template_id,
            artifact_status=artifact_status,
            artifact_ids=artifact_ids,
            artifact_validation_receipts=artifact_validation_receipts,
        ),
        cost_inputs=CostInputs(
            estimated_rows=1000,
            query_selectivity=0.18,
            auth_selectivity=0.18,
            artifact_lookup_cost=0.2,
            declared_reuse=case.amortization_q,
            declared_update_rate_per_hour=case.update_rate_per_hour,
            declared_ttl_s=float(case.ttl_s),
            declared_contexts=case.contexts,
        ),
    )
    receipt = _issue_e8b_planning_validator_receipt(
        draft,
        principal_id=principal_id,
        context_hash=context_hash,
        exact_predicate=exact_predicate,
        policy_validation=policy_receipt,
        artifact_validation_receipts=artifact_validation_receipts,
        planning_snapshot_id=planning_snapshot_id,
    )
    problem = replace(draft, gamma_snapshot=receipt.gamma_snapshot)
    _validate_e8b_planning_validator_receipt(
        problem,
        receipt,
        principal_id=principal_id,
        context_hash=context_hash,
        exact_predicate=exact_predicate,
        policy_validation=policy_receipt,
        artifact_validation_receipts=artifact_validation_receipts,
        planning_snapshot_id=planning_snapshot_id,
    )
    return problem, receipt


def _planning_problem_for_case(
    case: E8bCase,
    *,
    template_id: str,
    template_ids: Optional[Sequence[str]] = None,
    artifact_status: Optional[str] = None,
    artifact_ids: Optional[Mapping[str, str]] = None,
    principal_id: str = E8B_FIXTURE_PRINCIPAL_ID,
    context_hash: str = E8B_FIXTURE_CONTEXT_HASH,
    exact_predicate: str = E8B_FIXTURE_EXACT_PREDICATE,
    policy_validation: Optional[E8bPolicyValidatorReceipt] = None,
    artifact_validation_receipts: Optional[
        Mapping[str, E8bArtifactValidatorReceipt]
    ] = None,
    planning_snapshot_id: Optional[str] = None,
) -> PlanningProblem:
    problem, _receipt = _planning_problem_and_receipt_for_case(
        case,
        template_id=template_id,
        template_ids=template_ids,
        artifact_status=artifact_status,
        artifact_ids=artifact_ids,
        principal_id=principal_id,
        context_hash=context_hash,
        exact_predicate=exact_predicate,
        policy_validation=policy_validation,
        artifact_validation_receipts=artifact_validation_receipts,
        planning_snapshot_id=planning_snapshot_id,
    )
    return problem


def _registry_for_templates(template_ids: Sequence[str]) -> TemplateRegistry:
    return TemplateRegistry(
        tuple(DEFAULT_TEMPLATE_REGISTRY.get(template_id) for template_id in template_ids)
    )


def _text_digest(payload: str) -> str:
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _emit_context_for_case(
    problem: PlanningProblem,
    *,
    sql_context: Optional[E8bSqlContext] = None,
) -> EmitContext:
    exact_predicate = (
        E8B_FIXTURE_EXACT_PREDICATE if sql_context is None else sql_context.exact_predicate
    )
    template_params: dict[str, Any] = {
        "carrier_columns": E8B_DOCUMENT_CARRIER_COLUMNS,
        "artifact_ids": {
            kind: artifact.artifact_id for kind, artifact in problem.artifacts.items()
        },
        "policy_id": problem.policy_id,
        "user_id": E8B_FIXTURE_PRINCIPAL_ID,
        "ctx_hash": E8B_FIXTURE_CONTEXT_HASH,
        "rid_domain_id": f"{problem.relation}.{problem.rid_col}",
        "base_rel_oid": f"public.{problem.relation}",
        "mav_relation": "mav_document_scope",
        "mav_query_predicate": "true",
    }
    artifact_expectation: Any = {
        "policy_id": problem.policy_id,
        "context_predicate": "ctx_hash_matches_current_context",
    }
    if sql_context is not None:
        template_params.update(
            {
                "artifact_ids": {
                    "auth_idx": sql_context.auth_artifact_id,
                    "mav": sql_context.mav_artifact_id,
                },
                "policy_id": sql_context.policy_id,
                "user_id": sql_context.user_id,
                "ctx_hash": sql_context.ctx_hash,
                "rid_domain_id": "document.doc_id",
                "base_rel_oid": "public.document",
                "mav_relation": "e8b_mav_document_ctx_000001",
                "mav_query_predicate": "true",
            }
        )
        artifact_expectation = json.loads(sql_context.valid_expected_json)
    return EmitContext(
        default_rid_col=problem.rid_col,
        occurrence_relations={problem.occurrence_id: problem.relation},
        occurrence_aliases={problem.occurrence_id: "d"},
        occurrence_rid_cols={problem.occurrence_id: problem.rid_col},
        exact_predicates={problem.occurrence_id: exact_predicate},
        query_predicates={problem.occurrence_id: exact_predicate},
        guard_predicates={problem.occurrence_id: exact_predicate},
        residual_predicates={"tenant_group:exact_residual": "rcheck.tenant_id = 1"},
        artifact_expectations={
            artifact.artifact_id: artifact_expectation
            for artifact in problem.artifacts.values()
        },
        template_params={problem.occurrence_id: template_params} if template_params else {},
    )


def _planning_query_for_case(
    case: E8bCase,
    *,
    problem: PlanningProblem,
    template_id: str,
    sql_context: Optional[E8bSqlContext] = None,
) -> PlanningQuery:
    return PlanningQuery(
        ir_skeleton=Root(
            Project(
                ScanProtected(problem.occurrence_id, "chosen"),
                visible_A=("doc_id", "tenant_id", "region"),
                hidden_H=(),
            ),
            rho_root=_root_rho_for_case(case),
        ),
        occurrence_goals={
            problem.occurrence_id: OccurrenceGoal(problem, mode=ADMISSION_FIRST_MODE),
        },
        mode=ADMISSION_FIRST_MODE,
        emit_context=_emit_context_for_case(problem, sql_context=sql_context),
    )


def _query_plan_payload(
    query_result: QueryPlanResult,
    *,
    planning_receipt: E8bPlanningValidatorReceipt,
) -> dict[str, Any]:
    payload = query_result.to_dict()
    emitted_sql = query_result.emitted_sql or ""
    payload["ok"] = query_result.ok
    payload["occurrence_ids"] = sorted(query_result.occurrence_results)
    payload["disabled_components"] = []
    payload["certificate_suppressed"] = False
    payload["emitted_sql"] = emitted_sql
    payload["emitted_sql_hash"] = _text_digest(emitted_sql) if emitted_sql else None
    payload["planning_admission_receipt"] = planning_receipt.to_dict()
    return payload


def _planner_result_for_templates(
    case: E8bCase,
    *,
    template_ids: Sequence[str],
    target_template_id: str,
    artifact_status: Optional[str] = None,
    sql_context: Optional[E8bSqlContext] = None,
    artifact_validation_receipts: Optional[
        Mapping[str, E8bArtifactValidatorReceipt]
    ] = None,
):
    principal_id = (
        E8B_FIXTURE_PRINCIPAL_ID if sql_context is None else sql_context.user_id
    )
    context_hash = (
        E8B_FIXTURE_CONTEXT_HASH if sql_context is None else sql_context.ctx_hash
    )
    exact_predicate = (
        E8B_FIXTURE_EXACT_PREDICATE
        if sql_context is None
        else sql_context.exact_predicate
    )
    problem, planning_receipt = _planning_problem_and_receipt_for_case(
        case,
        template_id=target_template_id,
        template_ids=template_ids,
        artifact_status=artifact_status,
        artifact_ids=None
        if sql_context is None
        else {"auth_idx": sql_context.auth_artifact_id, "mav": sql_context.mav_artifact_id},
        principal_id=principal_id,
        context_hash=context_hash,
        exact_predicate=exact_predicate,
        policy_validation=None if sql_context is None else sql_context.policy_validation,
        artifact_validation_receipts=artifact_validation_receipts,
    )
    # This is the adapter trust boundary.  Recheck the validator receipt and
    # the Gamma attached to the problem immediately before contract admission.
    _validate_e8b_planning_validator_receipt(
        problem,
        planning_receipt,
        principal_id=principal_id,
        context_hash=context_hash,
        exact_predicate=exact_predicate,
        policy_validation=None if sql_context is None else sql_context.policy_validation,
        artifact_validation_receipts=artifact_validation_receipts,
    )
    query_result = plan_query(
        _planning_query_for_case(
            case,
            problem=problem,
            template_id=target_template_id,
            sql_context=sql_context,
        ),
        registry=_registry_for_templates(template_ids),
    )
    return PlannerInvocation(
        occurrence_result=query_result.occurrence_results[problem.occurrence_id],
        query_result=query_result,
        query_plan=_query_plan_payload(
            query_result,
            planning_receipt=planning_receipt,
        ),
    )


def _planner_candidates_with_action(
    candidates: Sequence[Any],
    *,
    action_by_template: Mapping[str, str],
    cost_metric: str = "planner_estimated_ms",
    estimated_cost_by_template: Optional[Mapping[str, Optional[float]]] = None,
) -> list[dict[str, Any]]:
    rendered: list[dict[str, Any]] = []
    estimated_cost_by_template = estimated_cost_by_template or {}
    for candidate in candidates:
        payload = candidate.to_dict() if hasattr(candidate, "to_dict") else dict(candidate)
        template_id = str(payload.get("template_id", ""))
        payload["action"] = action_by_template.get(template_id, "execute")
        payload["cost_metric"] = cost_metric
        if template_id in estimated_cost_by_template:
            payload["estimated_cost"] = estimated_cost_by_template[template_id]
        rendered.append(payload)
    return rendered


def _candidate_rejection_reason(candidates: Sequence[Mapping[str, Any]]) -> Optional[str]:
    for candidate in candidates:
        reasons = candidate.get("rejection_reasons")
        if isinstance(reasons, list) and reasons:
            return str(reasons[0])
    return None


def _artifact_receipts_for_case(
    case: E8bCase,
    template_id: str,
    measurements: Optional[PostgresMeasurements],
    *,
    refreshed: bool = False,
) -> Optional[Mapping[str, E8bArtifactValidatorReceipt]]:
    if measurements is None:
        return None
    kind = _artifact_kind_for_template(template_id)
    if kind is None:
        return {}
    receipt = (
        measurements.valid_artifact_validation_by_kind[kind]
        if refreshed
        else measurements.artifact_validation_by_case[case.test_id]
    )
    return {kind: receipt}


def _assert_case_artifact_validator_agreement(
    case: E8bCase,
    receipts: Optional[Mapping[str, E8bArtifactValidatorReceipt]],
) -> None:
    if not receipts:
        return
    validator_accepted = next(iter(receipts.values())).accepted
    expected_valid = case.artifact_status == "pass"
    if validator_accepted != expected_valid:
        raise PostgresError(
            f"{case.test_id}: case label disagrees with independent artifact validator"
        )


def _contract_planner_outcome(
    case: E8bCase,
    *,
    measurements: Optional["PostgresMeasurements"] = None,
    cost_ranked: bool = False,
) -> ModeOutcome:
    target_template_id, target_alternative = _template_for_mode(ADMISSION_FIRST_MODE, case)
    target_ids = (target_template_id,)
    fallback_ids = (target_template_id, "barrier_filter_v1")
    case_receipts = _artifact_receipts_for_case(
        case, target_template_id, measurements
    )
    if measurements is not None:
        _assert_case_artifact_validator_agreement(case, case_receipts)

    if case.contract_action in {"fallback", "replan"}:
        result = _planner_result_for_templates(
            case,
            template_ids=fallback_ids,
            target_template_id=target_template_id,
            sql_context=measurements,
            artifact_validation_receipts=case_receipts,
        )
        candidates = _planner_candidates_with_action(
            result.occurrence_result.candidates,
            action_by_template={
                target_template_id: case.contract_action,
                "barrier_filter_v1": case.contract_action,
            },
        )
        return ModeOutcome(
            status="pass",
            artifact_status=case.artifact_status,
            action=case.contract_action,
            template_id="barrier_filter_v1",
            alternative="BarrierFilter",
            failure_reason=None,
            planner_candidates=tuple(candidates),
            planner_choice_reason=f"metadata_{case.artifact_status}_{case.contract_action}",
            planner_query_plan=result.query_plan,
        )

    if case.contract_action == "reject":
        result = _planner_result_for_templates(
            case,
            template_ids=target_ids,
            target_template_id=target_template_id,
            sql_context=measurements,
            artifact_validation_receipts=case_receipts,
        )
        candidates = _planner_candidates_with_action(
            result.occurrence_result.candidates,
            action_by_template={target_template_id: "reject"},
        )
        failure_reason = _candidate_rejection_reason(candidates) or (
            f"AdmissionFirst rejected invalid artifact: {case.failure_symbol}"
        )
        return ModeOutcome(
            status="expected_reject",
            artifact_status=case.artifact_status,
            action="reject",
            template_id=target_template_id,
            alternative=target_alternative,
            failure_reason=failure_reason,
            planner_candidates=tuple(candidates),
            planner_choice_reason="metadata_invalid_reject",
            planner_query_plan=result.query_plan,
        )

    if case.contract_action == "refresh" and case.artifact_status != "pass":
        pre_refresh = _planner_result_for_templates(
            case,
            template_ids=target_ids,
            target_template_id=target_template_id,
            sql_context=measurements,
            artifact_validation_receipts=case_receipts,
        )
        refreshed = _planner_result_for_templates(
            case,
            template_ids=target_ids,
            target_template_id=target_template_id,
            artifact_status="pass",
            sql_context=measurements,
            artifact_validation_receipts=_artifact_receipts_for_case(
                case, target_template_id, measurements, refreshed=True
            ),
        )
        candidates = _planner_candidates_with_action(
            pre_refresh.occurrence_result.candidates,
            action_by_template={target_template_id: "refresh"},
        )
        candidates.extend(
            _planner_candidates_with_action(
                refreshed.occurrence_result.candidates,
                action_by_template={target_template_id: "refresh"},
            )
        )
        return ModeOutcome(
            status="pass",
            artifact_status=case.artifact_status,
            action="refresh",
            template_id=target_template_id,
            alternative=target_alternative,
            failure_reason=None,
            planner_candidates=tuple(candidates),
            planner_choice_reason="metadata_stale_refresh",
            planner_query_plan=refreshed.query_plan,
        )

    result = _planner_result_for_templates(
        case,
        template_ids=target_ids if not cost_ranked else fallback_ids,
        target_template_id=target_template_id,
        sql_context=measurements,
        artifact_validation_receipts=case_receipts,
    )
    candidates = _planner_candidates_with_action(
        result.occurrence_result.candidates,
        action_by_template={target_template_id: case.contract_action, "barrier_filter_v1": "execute"},
    )
    chosen_template = result.occurrence_result.chosen_template
    return ModeOutcome(
        status="pass",
        artifact_status=case.artifact_status,
        action=case.contract_action,
        template_id=target_template_id if chosen_template is None else chosen_template.template_id,
        alternative=target_alternative if chosen_template is None else chosen_template.alternative,
        failure_reason=None,
        planner_candidates=tuple(candidates),
        planner_choice_reason=(
            "refresh_policy_valid_versions"
            if case.contract_action == "refresh"
            else "metadata_valid_execute"
        ),
        planner_query_plan=result.query_plan,
    )


def _mode_outcome(case: E8bCase, mode: str) -> ModeOutcome:
    mode = normalize_mode_id(mode)
    template_id, alternative = _template_for_mode(mode, case)
    if mode == ADMISSION_FIRST_MODE:
        return _contract_planner_outcome(case)

    if mode == "conservative-barrier":
        return ModeOutcome(
            status="pass",
            artifact_status="not_applicable",
            action="execute",
            template_id="barrier_filter_v1",
            alternative="BarrierFilter",
            failure_reason=None,
        )

    if mode in {"native-pg-rls", "native-pg-rls-physical-design"}:
        return ModeOutcome(
            status="pass",
            artifact_status="not_applicable",
            action="execute",
            template_id="native_pg_rls_v1",
            alternative="NativePG-RLS",
            failure_reason=None,
        )

    if mode in {"auth-index-enum-only", "mav-only"}:
        if case.artifact_status in {"stale", "wrong_context", "rid_mismatch", "toctou_fail"}:
            return ModeOutcome(
                status="expected_reject",
                artifact_status=case.artifact_status,
                action="reject",
                template_id=template_id,
                alternative=alternative,
                failure_reason=f"{mode} rejected invalid artifact metadata: {case.failure_symbol}",
            )
        return ModeOutcome(
            status="pass",
            artifact_status=case.artifact_status,
            action="execute",
            template_id=template_id,
            alternative=alternative,
            failure_reason=None,
        )

    wrong = False
    if mode == "naive-artifact-only":
        wrong = case.artifact_status in {"stale", "wrong_context", "rid_mismatch", "toctou_fail"}
    elif mode == "mav-no-version":
        wrong = case.artifact_type in {"mav", "both"} and case.artifact_status in {"stale", "toctou_fail"}
    elif mode == "naive-auth-index-no-scope":
        wrong = case.artifact_type in {"auth_idx", "both"} and case.artifact_status in {"wrong_context", "rid_mismatch"}
    elif mode == "stale-artifact-user":
        wrong = case.artifact_status in {"stale", "wrong_context", "rid_mismatch", "toctou_fail"}
    status = "wrong_result" if wrong else "pass"
    return ModeOutcome(
        status=status,
        artifact_status=case.artifact_status,
        action="execute",
        template_id=template_id,
        alternative=alternative,
        failure_reason=(
            f"{mode} ignored artifact metadata for {case.expected_effect}" if wrong else None
        ),
    )


def _maintenance_metrics(case: E8bCase, mode: str, outcome: ModeOutcome) -> dict[str, float]:
    version_check_overhead_ms = 0.2 + min(case.contexts, 100000) * 0.00002
    update_pressure = case.update_rate_per_hour * (case.ttl_s / 3600.0)
    invalidation_count = estimated_invalidation_count(
        update_rate_per_hour=case.update_rate_per_hour,
        ttl_s=case.ttl_s,
        contexts=case.contexts,
    )
    artifact_hit_rate = max(0.0, 1.0 - min(1.0, update_pressure))

    base_ms = 8.0 + len(case.query_shape) * 0.15
    contract_barrier_choice = mode == ADMISSION_FIRST_MODE and outcome.template_id == "barrier_filter_v1"
    if contract_barrier_choice:
        total_ms = version_check_overhead_ms + base_ms * 2.6
        artifact_hit_rate = 0.0
    elif mode == ADMISSION_FIRST_MODE:
        total_ms = base_ms + version_check_overhead_ms
        if outcome.action == "fallback":
            total_ms += base_ms * 1.8
        elif outcome.action == "refresh":
            total_ms += 12.0 + invalidation_count * 0.2
        elif outcome.action == "replan":
            total_ms += 4.0 + version_check_overhead_ms
        elif outcome.action == "reject":
            total_ms = version_check_overhead_ms
    elif mode == "conservative-barrier":
        total_ms = base_ms * 2.6
        artifact_hit_rate = 0.0
    elif mode == "native-pg-rls":
        total_ms = base_ms * 2.1
        artifact_hit_rate = 0.0
    elif mode == "native-pg-rls-physical-design":
        total_ms = base_ms * 1.55
        artifact_hit_rate = 0.0
    else:
        total_ms = base_ms * 0.85
    return {
        "planning_ms": 0.0,
        "total_ms": total_ms,
        "execution_ms": total_ms,
        "query_only_ms": total_ms,
        "version_check_overhead_ms": version_check_overhead_ms if mode == ADMISSION_FIRST_MODE else 0.0,
        "invalidation_count": float(invalidation_count),
        "artifact_hit_rate": artifact_hit_rate,
        "build_ms": 0.0 if contract_barrier_choice else (20.0 if case.artifact_type in {"mav", "both"} else 4.0),
        "refresh_ms": 12.0 if outcome.action == "refresh" and not contract_barrier_choice else 0.0,
        "fallback_ms": base_ms * 1.8 if outcome.action == "fallback" else 0.0,
        "maintenance_unit_ms": 0.0 if contract_barrier_choice else (12.0 if case.artifact_type in {"mav", "both"} else 4.0),
        "storage_bytes": 0.0 if contract_barrier_choice else 4096.0 * max(1, case.contexts) * (2 if case.artifact_type == "both" else 1),
        "authorized_rows": 100.0,
        "candidate_rows": 100.0,
        "total_rows": 1000.0,
        "artifact_lookups": 0.0
        if mode in {"conservative-barrier", "native-pg-rls", "native-pg-rls-physical-design"}
        or contract_barrier_choice
        else 1.0,
    }


def _postgres_metrics(case: E8bCase, mode: str, outcome: ModeOutcome, measurements: PostgresMeasurements) -> dict[str, Any]:
    mode = normalize_mode_id(mode)
    update_pressure = case.update_rate_per_hour * (case.ttl_s / 3600.0)
    invalidation_count = int(math.ceil(update_pressure * max(1, case.contexts / 1000)))
    artifact_hit_rate = max(0.0, 1.0 - min(1.0, update_pressure))
    validates_artifact = _validates_artifact_for_mode(mode)
    validation = measurements.validation_by_case[case.test_id]
    validated_query = (
        measurements.validated_artifact_queries[_artifact_query_key(case, mode)]
        if validates_artifact
        else None
    )
    selected = _artifact_query_timing(case, mode, measurements)
    build_ms = _artifact_build_ms(case, mode, measurements)
    maintenance_unit_ms = _artifact_refresh_ms(case, mode, measurements)
    refresh_ms = 0.0
    fallback_ms = 0.0
    verification_ms = validation.elapsed_ms if validates_artifact else 0.0
    artifact_validation_same_snapshot = bool(validation.same_snapshot) if validates_artifact else False
    artifact_validation_isolation_level = validation.isolation_level if artifact_validation_same_snapshot else None
    query_only_ms = selected.total_ms
    uses_validated_artifact_query = (
        validated_query is not None
        and outcome.status != "expected_reject"
        and outcome.action not in {"fallback", "replan"}
        and outcome.template_id != "barrier_filter_v1"
    )
    if uses_validated_artifact_query:
        selected = validated_query.timing
        query_only_ms = selected.total_ms
        if validation.validation_passed:
            verification_ms = validated_query.validation.elapsed_ms
        else:
            verification_ms = validation.elapsed_ms + validated_query.validation.elapsed_ms
        artifact_validation_same_snapshot = True
        artifact_validation_isolation_level = "repeatable_read"

    if outcome.status == "expected_reject":
        planning_ms = 0.0
        execution_ms = 0.0
        total_ms = verification_ms
        query_only_ms = 0.0
        storage_bytes = 0.0
        artifact_lookups = 0.0
    elif mode in {"conservative-barrier", "native-pg-rls", "native-pg-rls-physical-design"}:
        selected = measurements.barrier
        query_only_ms = selected.total_ms
        artifact_hit_rate = 0.0
        execution_ms = selected.execution_ms
        planning_ms = selected.planning_ms
        total_ms = selected.total_ms
        storage_bytes = 0.0
        artifact_lookups = 0.0
    elif mode == ADMISSION_FIRST_MODE:
        if outcome.action == "reject":
            planning_ms = 0.0
            execution_ms = 0.0
            total_ms = verification_ms
            query_only_ms = 0.0
        elif outcome.template_id == "barrier_filter_v1" and outcome.action == "execute":
            selected = measurements.barrier
            query_only_ms = selected.total_ms
            fallback_ms = 0.0
            planning_ms = selected.planning_ms
            execution_ms = selected.execution_ms
            total_ms = verification_ms + selected.total_ms
            artifact_hit_rate = 0.0
        elif outcome.action in {"fallback", "replan"}:
            selected = measurements.barrier
            query_only_ms = selected.total_ms
            fallback_ms = selected.total_ms
            planning_ms = selected.planning_ms
            execution_ms = selected.execution_ms
            total_ms = verification_ms + selected.total_ms
            artifact_hit_rate = 0.0
        elif outcome.action == "refresh":
            refresh_ms = _artifact_refresh_ms(case, mode, measurements)
            query_only_ms = selected.total_ms
            planning_ms = selected.planning_ms
            execution_ms = selected.execution_ms + refresh_ms
            total_ms = verification_ms + refresh_ms + selected.total_ms
        else:
            query_only_ms = selected.total_ms
            planning_ms = selected.planning_ms
            execution_ms = selected.execution_ms
            total_ms = verification_ms + selected.total_ms
        storage_bytes = 0.0 if outcome.template_id == "barrier_filter_v1" else float(_artifact_storage_bytes(case, mode, measurements))
        artifact_lookups = 0.0 if outcome.action == "reject" or outcome.template_id == "barrier_filter_v1" else 1.0
    else:
        query_only_ms = selected.total_ms
        planning_ms = selected.planning_ms
        execution_ms = selected.execution_ms
        total_ms = selected.total_ms + verification_ms
        storage_bytes = float(_artifact_storage_bytes(case, mode, measurements))
        artifact_lookups = 1.0

    return {
        "planning_ms": planning_ms,
        "total_ms": total_ms,
        "execution_ms": execution_ms,
        "query_only_ms": query_only_ms,
        "version_check_overhead_ms": verification_ms,
        "invalidation_count": float(invalidation_count),
        "artifact_hit_rate": artifact_hit_rate,
        "build_ms": build_ms if artifact_lookups else 0.0,
        "refresh_ms": refresh_ms,
        "fallback_ms": fallback_ms,
        "maintenance_unit_ms": maintenance_unit_ms if artifact_lookups else 0.0,
        "storage_bytes": storage_bytes,
        "authorized_rows": float(measurements.authorized_count),
        "candidate_rows": float(measurements.authorized_count),
        "total_rows": float(measurements.total_rows),
        "artifact_lookups": artifact_lookups,
        "artifact_validation_same_snapshot": 1.0 if artifact_validation_same_snapshot else 0.0,
        "artifact_validation_isolation_level": artifact_validation_isolation_level or "",
        "static_verifier_status": selected.static_verifier_status,
        "static_verifier_plan_hash": selected.static_verifier_plan_hash or "",
        "static_verifier_reasons": list(selected.static_verifier_reasons),
        "static_verifier_explain_json": selected.static_verifier_explain_json,
    }


def _amortized_ms(
    query_ms: float,
    build_ms: float,
    maintenance_ms_total: float,
    fallback_ms: float,
    q: int,
) -> float:
    return amortized_artifact_latency_ms(
        ArtifactEconomics(
            query_ms=query_ms,
            build_ms=build_ms,
            maintenance_ms_total=maintenance_ms_total,
            fallback_ms=fallback_ms,
            reuse=q,
        )
    )


def _sql_provenance(
    root: Path,
    manifest_path: Path,
    case: E8bCase,
    mode: str,
    query_plan_payload: Mapping[str, Any] | None,
    execution_sql_source: str,
) -> dict[str, Any]:
    if execution_sql_source == "planner_ir_emitted" and query_plan_payload is not None:
        emitted_hash = query_plan_payload.get("emitted_sql_hash")
        if isinstance(emitted_hash, str) and emitted_hash.startswith("sha256:"):
            safe_mode = mode.replace("-", "_")
            return {
                "emitted_sql_path": f"generated:{case.test_id}_{safe_mode}_ir.sql",
                "emitted_sql_hash": emitted_hash,
                "normalized_sql_hash": emitted_hash,
                "execution_sql_source": execution_sql_source,
            }
    return {
        "emitted_sql_path": "workloads/e8/freshness_maintenance.sql",
        "emitted_sql_hash": file_sha256(root / "workloads" / "e8" / "freshness_maintenance.sql"),
        "normalized_sql_hash": scientific_manifest_hash(manifest_path),
        "execution_sql_source": execution_sql_source,
    }


def _strict_receipt_kwargs(receipt_type: type, payload: Mapping[str, Any]) -> dict[str, Any]:
    names = {item.name for item in fields(receipt_type)}
    if set(payload) != names:
        raise ValueError(f"malformed {receipt_type.__name__} fields")
    return dict(payload)


def _policy_receipt_from_dict(payload: Mapping[str, Any]) -> E8bPolicyValidatorReceipt:
    if not isinstance(payload.get("promotable"), bool):
        raise ValueError("invalid policy receipt promotable flag")
    receipt = E8bPolicyValidatorReceipt(
        **_strict_receipt_kwargs(E8bPolicyValidatorReceipt, payload)
    )
    _replay_policy_validator_receipt(receipt)
    return receipt


def _artifact_receipt_from_dict(
    payload: Mapping[str, Any],
) -> E8bArtifactValidatorReceipt:
    if not isinstance(payload.get("promotable"), bool) or not isinstance(
        payload.get("same_snapshot"), bool
    ):
        raise ValueError("invalid artifact receipt boolean field")
    receipt = E8bArtifactValidatorReceipt(
        **_strict_receipt_kwargs(E8bArtifactValidatorReceipt, payload)
    )
    _replay_artifact_validator_receipt(receipt)
    return receipt


def _policy_access_target_from_dict(payload: Any) -> PolicyAccessTarget:
    if not isinstance(payload, Mapping) or payload.get("kind") != "policy_access":
        raise ValueError("serialized E8b receipt requires typed logical target")
    expected = {
        "kind",
        "relation",
        "policy_id",
        "occurrence_id",
        "principal_id",
        "context_digest",
        "policy_predicate_digest",
    }
    if set(payload) != expected:
        raise ValueError("serialized E8b logical target schema mismatch")
    return PolicyAccessTarget(
        relation=str(payload["relation"]),
        policy_id=str(payload["policy_id"]),
        occurrence_id=str(payload["occurrence_id"]),
        principal_id=str(payload["principal_id"]),
        context_digest=str(payload["context_digest"]),
        policy_predicate_digest=str(payload["policy_predicate_digest"]),
    )


def _implementation_target_binding_from_dict(
    payload: Any,
) -> ImplementationTargetBinding:
    if not isinstance(payload, Mapping):
        raise ValueError("serialized E8b target binding is malformed")
    expected = {
        "template_id",
        "occurrence_id",
        "logical_target_digest",
        "implementation_target_kind",
        "rid_col",
        "context_digest",
        "refinement_kind",
        "refinement_predicate_digest",
    }
    if set(payload) != expected:
        raise ValueError("serialized E8b target binding schema mismatch")
    return ImplementationTargetBinding(
        template_id=str(payload["template_id"]),
        occurrence_id=str(payload["occurrence_id"]),
        logical_target_digest=str(payload["logical_target_digest"]),
        implementation_target_kind=str(payload["implementation_target_kind"]),
        rid_col=str(payload["rid_col"]),
        context_digest=str(payload["context_digest"]),
        refinement_kind=(
            None
            if payload["refinement_kind"] is None
            else str(payload["refinement_kind"])
        ),
        refinement_predicate_digest=(
            None
            if payload["refinement_predicate_digest"] is None
            else str(payload["refinement_predicate_digest"])
        ),
    )


def _planning_receipt_from_dict(
    payload: Mapping[str, Any],
) -> E8bPlanningValidatorReceipt:
    if payload.get("validator_version") != E8B_PLANNING_VALIDATOR_VERSION:
        raise ValueError("untrusted serialized E8b planning validator version")
    facts_payload = payload.get("facts")
    if not isinstance(facts_payload, list) or not facts_payload:
        raise ValueError("E8b planning receipt requires serialized facts")
    facts: list[GammaFact] = []
    evidence_payloads: list[Mapping[str, Any]] = []
    for item in facts_payload:
        if not isinstance(item, Mapping) or not isinstance(item.get("evidence"), Mapping):
            raise ValueError("malformed E8b serialized Gamma fact")
        evidence = dict(item["evidence"])
        fact = GammaFact(
            fact_id=str(item.get("fact_id", "")),
            kind=str(item.get("kind", "")),
            subject_digest=str(item.get("subject_digest", "")),
            verdict=str(item.get("verdict", "")),
            validator_version=str(item.get("validator_version", "")),
            snapshot_id=str(item.get("snapshot_id", "")),
            evidence_digest=str(item.get("evidence_digest", "")),
            dynamic=item.get("dynamic") is True,
        )
        if item.get("dynamic") is not fact.dynamic:
            raise ValueError("invalid serialized Gamma dynamic flag")
        if fact.evidence_digest != _digest(evidence):
            raise ValueError("serialized Gamma fact evidence digest mismatch")
        if (
            evidence.get("validator_version") != fact.validator_version
            or evidence.get("evidence_scope") != payload.get("evidence_scope")
            or evidence.get("planning_snapshot_id") != fact.snapshot_id
            or evidence.get("kind") != fact.kind
            or evidence.get("subject_digest") != fact.subject_digest
            or evidence.get("verdict") != fact.verdict
        ):
            raise ValueError("serialized Gamma fact fields disagree with evidence")
        facts.append(fact)
        evidence_payloads.append(evidence)

    snapshot_id = str(payload.get("planning_snapshot_id", ""))
    gamma = GammaSnapshot(snapshot_id=snapshot_id, facts=tuple(facts))
    if gamma.digest != payload.get("gamma_snapshot_digest"):
        raise ValueError("serialized Gamma snapshot digest mismatch")
    logical_target = _policy_access_target_from_dict(payload.get("logical_target"))
    binding_payloads = payload.get("implementation_target_bindings")
    if not isinstance(binding_payloads, list) or not binding_payloads:
        raise ValueError("serialized E8b receipt requires target bindings")
    target_bindings = tuple(
        _implementation_target_binding_from_dict(item) for item in binding_payloads
    )
    receipt = E8bPlanningValidatorReceipt(
        validator_version=str(payload.get("validator_version", "")),
        evidence_scope=str(payload.get("evidence_scope", "")),
        principal_id=str(payload.get("principal_id", "")),
        context_hash=str(payload.get("context_hash", "")),
        policy_id=str(payload.get("policy_id", "")),
        relation=str(payload.get("relation", "")),
        occurrence_id=str(payload.get("occurrence_id", "")),
        rid_col=str(payload.get("rid_col", "")),
        rid_domain_id=str(payload.get("rid_domain_id", "")),
        policy_subject_digest=str(payload.get("policy_subject_digest", "")),
        exact_predicate_digest=str(payload.get("exact_predicate_digest", "")),
        logical_target=logical_target,
        implementation_target_bindings=target_bindings,
        artifact_metadata_digest=str(payload.get("artifact_metadata_digest", "")),
        planning_snapshot_id=snapshot_id,
        gamma_snapshot=gamma,
        receipt_digest=str(payload.get("receipt_digest", "")),
        fact_evidence=tuple(evidence_payloads),
    )
    if receipt.receipt_digest != _digest(_planning_receipt_digest_payload(receipt)):
        raise ValueError("serialized E8b planning receipt digest mismatch")
    return receipt


def _validate_contract_query_plan_for_record(
    *,
    case: E8bCase,
    mode: str,
    outcome: ModeOutcome,
    query_plan_payload: Optional[Mapping[str, Any]],
    policy_id: str,
    principal_id: str,
    context_hash: str,
    exact_predicate: str,
    evidence_scope: str,
) -> Optional[E8bPlanningValidatorReceipt]:
    """Reject malformed AdmissionFirst evidence before a raw pass is built."""

    if mode != ADMISSION_FIRST_MODE:
        return None
    if not isinstance(query_plan_payload, Mapping):
        raise ValueError("AdmissionFirst E8b record requires a planner query plan")
    receipt_payload = query_plan_payload.get("planning_admission_receipt")
    if not isinstance(receipt_payload, Mapping):
        raise ValueError("AdmissionFirst E8b record requires a planning validator receipt")
    receipt = _planning_receipt_from_dict(receipt_payload)
    if receipt.validator_version != E8B_PLANNING_VALIDATOR_VERSION:
        raise ValueError("AdmissionFirst E8b record has an untrusted planning validator version")
    expected_problem = PlanningProblem(
        planning_execution_class="production_normal",
        relation="document",
        policy_id=policy_id,
        occurrence_id=case.test_id,
        rid_col="doc_id",
        logical_target=receipt.logical_target,
        implementation_target_bindings=receipt.implementation_target_bindings,
        query_predicate=exact_predicate,
        require_typed_admission=True,
    )
    if (
        receipt.evidence_scope != evidence_scope
        or receipt.principal_id != principal_id
        or receipt.context_hash != context_hash
        or receipt.policy_id != policy_id
        or receipt.relation != "document"
        or receipt.occurrence_id != case.test_id
        or receipt.rid_col != "doc_id"
        or receipt.rid_domain_id != "document.doc_id"
        or receipt.logical_target.relation != "document"
        or receipt.logical_target.policy_id != policy_id
        or receipt.logical_target.occurrence_id != case.test_id
        or receipt.logical_target.principal_id != principal_id
        or receipt.policy_subject_digest != receipt.logical_target.digest
        or receipt.exact_predicate_digest != _text_digest(exact_predicate)
    ):
        raise ValueError("AdmissionFirst E8b receipt identity mismatch")

    artifact_receipts: dict[str, E8bArtifactValidatorReceipt] = {}
    policy_receipts: list[E8bPolicyValidatorReceipt] = []
    policy_fact_counts = {
        "trusted_exact_policy_executable": 0,
        "safe_query_predicate": 0,
    }
    target_fact_bindings: list[str] = []
    binding_artifact_claims: list[
        tuple[str, Mapping[str, E8bArtifactValidatorReceipt]]
    ] = []
    target = _planning_target_binding(
        expected_problem,
        principal_id=principal_id,
        context_hash=context_hash,
        exact_predicate=exact_predicate,
    )
    for fact, evidence in zip(receipt.gamma_snapshot.facts, receipt.fact_evidence):
        if evidence.get("target") != target:
            raise ValueError("serialized Gamma target binding mismatch")
        claims = evidence.get("claims")
        if not isinstance(claims, Mapping):
            raise ValueError("serialized Gamma fact lacks validator claims")
        if fact.kind in {"trusted_exact_policy_executable", "safe_query_predicate"}:
            policy_fact_counts[fact.kind] += 1
            policy_payload = claims.get("policy_validator_receipt")
            if not isinstance(policy_payload, Mapping):
                raise ValueError("policy Gamma fact lacks validator receipt")
            policy_receipt = _policy_receipt_from_dict(policy_payload)
            policy_receipts.append(policy_receipt)
            if (
                not fact.accepted
                or fact.subject_digest != receipt.policy_subject_digest
                or policy_receipt.principal_id != principal_id
                or policy_receipt.context_hash != context_hash
                or policy_receipt.exact_predicate != exact_predicate
                or policy_receipt.evidence_scope != evidence_scope
            ):
                raise ValueError("policy Gamma fact/receipt mismatch")
        elif fact.kind == "artifact_validation":
            artifact_payload = claims.get("artifact_validator_receipt")
            declared_kind = str(claims.get("declared_kind", ""))
            if not isinstance(artifact_payload, Mapping) or not declared_kind:
                raise ValueError("artifact Gamma fact lacks validator receipt")
            artifact_receipt = _artifact_receipt_from_dict(artifact_payload)
            if declared_kind in artifact_receipts:
                raise ValueError("duplicate E8b artifact Gamma fact")
            artifact_receipts[declared_kind] = artifact_receipt
            if (
                fact.subject_digest != artifact_receipt.artifact_id
                or fact.accepted != artifact_receipt.accepted
                or artifact_receipt.context_hash != context_hash
                or artifact_receipt.evidence_scope != evidence_scope
            ):
                raise ValueError("artifact Gamma fact/receipt mismatch")
        elif fact.kind in {"implementation_target_match", "target_refinement"}:
            policy_payload = claims.get("policy_validator_receipt")
            binding_payload = claims.get("implementation_target_binding")
            logical_target_payload = claims.get("logical_target")
            artifact_payloads = claims.get("artifact_validator_receipts")
            if (
                not isinstance(policy_payload, Mapping)
                or not isinstance(binding_payload, Mapping)
                or not isinstance(logical_target_payload, Mapping)
                or not isinstance(artifact_payloads, Mapping)
            ):
                raise ValueError("target Gamma fact lacks typed validator claims")
            policy_receipt = _policy_receipt_from_dict(policy_payload)
            policy_receipts.append(policy_receipt)
            binding = _implementation_target_binding_from_dict(binding_payload)
            logical_target = _policy_access_target_from_dict(logical_target_payload)
            if (
                logical_target != receipt.logical_target
                or binding not in receipt.implementation_target_bindings
                or claims.get("logical_target_digest") != logical_target.digest
                or claims.get("implementation_target_binding_digest")
                != binding.digest
                or claims.get("query_predicate") != exact_predicate
            ):
                raise ValueError("target Gamma fact binding claims mismatch")
            definition = template_definition(binding.template_id)
            parsed_artifacts: dict[str, E8bArtifactValidatorReceipt] = {}
            for kind, artifact_payload in artifact_payloads.items():
                if not isinstance(artifact_payload, Mapping):
                    raise ValueError("target Gamma fact artifact claim is malformed")
                parsed = _artifact_receipt_from_dict(artifact_payload)
                if (
                    parsed.context_hash != context_hash
                    or parsed.evidence_scope != evidence_scope
                ):
                    raise ValueError("target Gamma artifact receipt identity mismatch")
                parsed_artifacts[str(kind)] = parsed
            if set(parsed_artifacts) != set(definition.required_artifacts):
                raise ValueError("target Gamma fact artifact receipt set mismatch")
            expected_subject = (
                target_refinement_subject_digest(
                    binding,
                    logical_target,
                    snapshot_id=receipt.planning_snapshot_id,
                )
                if fact.kind == "target_refinement"
                else implementation_target_match_subject_digest(
                    binding,
                    logical_target,
                    snapshot_id=receipt.planning_snapshot_id,
                )
            )
            expected_accepted = bool(policy_receipt.safe_query_label) and all(
                item.accepted for item in parsed_artifacts.values()
            )
            if (
                fact.subject_digest != expected_subject
                or fact.accepted != expected_accepted
                or (
                    fact.kind == "target_refinement"
                    and binding.refinement_kind is None
                )
                or (
                    fact.kind == "implementation_target_match"
                    and (
                        binding.refinement_kind is not None
                        or binding.implementation_target_kind == "bare_occurrence"
                    )
                )
            ):
                raise ValueError("target Gamma fact subject/verdict mismatch")
            target_fact_bindings.append(binding.template_id)
            binding_artifact_claims.append((binding.template_id, parsed_artifacts))
        else:
            raise ValueError(f"unexpected E8b Gamma fact kind: {fact.kind}")
    if not policy_receipts or any(item != policy_receipts[0] for item in policy_receipts):
        raise ValueError("inconsistent policy validator receipts across Gamma facts")
    if any(count != 1 for count in policy_fact_counts.values()):
        raise ValueError("serialized E8b policy fact multiplicity mismatch")
    policy_receipt = policy_receipts[0]
    expected_logical_target = _logical_target_from_policy_receipt(
        policy_receipt,
        occurrence_id=case.test_id,
    )
    expected_bindings = _implementation_bindings_for_templates(
        tuple(
            binding.template_id
            for binding in receipt.implementation_target_bindings
        ),
        target=expected_logical_target,
        rid_col="doc_id",
        query_predicate=exact_predicate,
    )
    if (
        receipt.logical_target != expected_logical_target
        or receipt.implementation_target_bindings != expected_bindings
        or receipt.policy_subject_digest != expected_logical_target.digest
    ):
        raise ValueError("serialized E8b target/binding does not match policy receipt")
    expected_target_fact_bindings = sorted(
        binding.template_id
        for binding in receipt.implementation_target_bindings
        if binding.refinement_kind is not None
        or binding.implementation_target_kind != "bare_occurrence"
    )
    if sorted(target_fact_bindings) != expected_target_fact_bindings:
        raise ValueError("serialized E8b target fact coverage mismatch")
    expected_artifact_kinds = {
        kind
        for binding in receipt.implementation_target_bindings
        for kind in template_definition(binding.template_id).required_artifacts
    }
    if set(artifact_receipts) != expected_artifact_kinds:
        raise ValueError("serialized E8b artifact fact coverage mismatch")
    for template_id, claimed_artifacts in binding_artifact_claims:
        definition = template_definition(template_id)
        expected_claimed_artifacts = {
            kind: artifact_receipts[kind]
            for kind in definition.required_artifacts
            if kind in artifact_receipts
        }
        if claimed_artifacts != expected_claimed_artifacts:
            raise ValueError("serialized E8b target artifact claims mismatch")
    expected_artifact_digest = _digest(
        {
            "artifact_validator_receipts": {
                kind: item.to_dict() for kind, item in sorted(artifact_receipts.items())
            }
        }
    )
    if receipt.artifact_metadata_digest != expected_artifact_digest:
        raise ValueError("artifact validator receipt-set digest mismatch")
    expected_snapshot = _digest(
        {
            "snapshot_kind": "e8b_validator_bound_planning_snapshot_v3",
            "validator_version": receipt.validator_version,
            "evidence_scope": receipt.evidence_scope,
            "target": target,
            "policy_validator_receipt_digest": policy_receipts[0].receipt_digest,
            "artifact_metadata_digest": receipt.artifact_metadata_digest,
        }
    )
    if receipt.planning_snapshot_id != expected_snapshot:
        raise ValueError("serialized E8b planning snapshot mismatch")

    occurrence_results = query_plan_payload.get("occurrence_results")
    occurrence = (
        occurrence_results.get(case.test_id)
        if isinstance(occurrence_results, Mapping)
        else None
    )
    candidates = occurrence.get("candidates") if isinstance(occurrence, Mapping) else None
    if not isinstance(candidates, list) or not candidates:
        raise ValueError("query plan lacks occurrence candidates for receipt replay")
    receipt_bindings_by_template = {
        binding.template_id: binding
        for binding in receipt.implementation_target_bindings
    }
    candidate_template_ids = {
        str(candidate.get("template_id", ""))
        for candidate in candidates
        if isinstance(candidate, Mapping)
    }
    if candidate_template_ids != set(receipt_bindings_by_template):
        raise ValueError("candidate set does not match receipt target bindings")
    for candidate in candidates:
        admission = (
            candidate.get("diagnostics", {}).get("admission", {})
            if isinstance(candidate, Mapping)
            else {}
        )
        memo = admission.get("memo_goal") if isinstance(admission, Mapping) else None
        candidate_binding_payload = (
            admission.get("implementation_target_binding")
            if isinstance(admission, Mapping)
            else None
        )
        candidate_binding = _implementation_target_binding_from_dict(
            {
                key: value
                for key, value in candidate_binding_payload.items()
                if key != "binding_digest"
            }
        ) if isinstance(candidate_binding_payload, Mapping) else None
        candidate_template_id = str(candidate.get("template_id", ""))
        if not isinstance(memo, Mapping) or (
            memo.get("gamma_snapshot_id") != receipt.planning_snapshot_id
            or memo.get("gamma_snapshot_digest") != receipt.gamma_snapshot.digest
            or memo.get("logical_target_digest") != receipt.logical_target.digest
            or memo.get("logical_target") != receipt.logical_target.to_dict()
            or candidate_binding
            != receipt_bindings_by_template.get(candidate_template_id)
            or (
                isinstance(candidate_binding_payload, Mapping)
                and candidate_binding_payload.get("binding_digest")
                != candidate_binding.digest
            )
        ):
            raise ValueError("candidate memo Gamma does not match planning receipt")

    if outcome.status == "pass":
        root_sigma = query_plan_payload.get("root_sigma")
        physprops = root_sigma.get("PhysProps") if isinstance(root_sigma, Mapping) else None
        if not isinstance(physprops, Mapping) or physprops.get(
            "gamma_snapshot_digest"
        ) != receipt.gamma_snapshot.digest:
            raise ValueError("root Sigma Gamma does not match planning receipt")

    emitted_sql = query_plan_payload.get("emitted_sql")
    certificate = query_plan_payload.get("certificate")
    certificate_check = query_plan_payload.get("certificate_check")
    root_closure = query_plan_payload.get("root_closure")
    root_ok = isinstance(root_closure, Mapping) and root_closure.get("ok") is True
    if outcome.status == "expected_reject":
        if query_plan_payload.get("ok") is not False:
            raise ValueError("expected-reject E8b plan must fail closed")
        if emitted_sql or certificate is not None or certificate_check is not None:
            raise ValueError("expected-reject E8b plan must not carry executable evidence")
        return receipt
    if outcome.status != "pass":
        return receipt
    if query_plan_payload.get("ok") is not True or not root_ok:
        raise ValueError("AdmissionFirst E8b pass requires root closure")
    if not isinstance(emitted_sql, str) or not emitted_sql.strip():
        raise ValueError("AdmissionFirst E8b pass requires non-empty emitted SQL")
    if not isinstance(certificate, (list, tuple)) or not certificate:
        raise ValueError("AdmissionFirst E8b pass requires a non-empty certificate")
    if not isinstance(certificate_check, Mapping) or certificate_check.get("status") != "pass":
        raise ValueError("AdmissionFirst E8b pass requires a passing certificate replay")
    return receipt


def _candidate_dynamic_fact_kinds(candidate: Mapping[str, Any]) -> tuple[str, ...]:
    diagnostics = candidate.get("diagnostics")
    admission = diagnostics.get("admission") if isinstance(diagnostics, Mapping) else None
    kinds = (
        admission.get("required_dynamic_fact_kinds")
        if isinstance(admission, Mapping)
        else ()
    )
    if not isinstance(kinds, (list, tuple)):
        return ()
    return tuple(sorted({str(kind) for kind in kinds}))


def _run_actual_reference_check(
    case: E8bCase,
    outcome: ModeOutcome,
    measurements: PostgresMeasurements,
    pg_env: PostgresEnv,
) -> dict[str, Any]:
    """Execute the selected body and independent reference in one RR snapshot."""

    initial_validation = measurements.validation_by_case[case.test_id]
    if outcome.status == "expected_reject":
        if initial_validation.validation_passed:
            raise PostgresError(
                f"{case.test_id}: reject action lacks a failing freshness check"
            )
        return {
            "schema": "e8b_actual_reference_check_v1",
            "action": outcome.action,
            "artifact_status": outcome.artifact_status,
            "initial_validation_passed": False,
            "failure_sqlstate": initial_validation.failure_sqlstate,
            "failure_symbol": initial_validation.failure_symbol,
            "selected_body_execution": False,
            "reference_execution": False,
            "same_snapshot": False,
            "isolation_level": None,
            "actual_count": 0,
            "reference_count": None,
            "set_diff_left": None,
            "set_diff_right": None,
            "actual_hash": None,
            "reference_hash": None,
        }

    query_plan = outcome.planner_query_plan
    if not isinstance(query_plan, Mapping):
        query_plan = measurements.query_plan_by_template.get(outcome.template_id)
    if not isinstance(query_plan, Mapping):
        raise PostgresError(f"{case.test_id}: selected query plan is missing")
    actual_sql = _row_sql_from_ir_emitted_sql(
        str(query_plan.get("emitted_sql", ""))
    )

    artifact_ids: tuple[str, ...] = ()
    if outcome.template_id == "auth_index_enum_v1":
        artifact_ids = (measurements.auth_artifact_id,)
    elif outcome.template_id == "mav_scan_v1":
        artifact_ids = (measurements.mav_artifact_id,)
    elif outcome.template_id == "hybrid_intersect_v1":
        artifact_ids = (
            measurements.auth_artifact_id,
            measurements.mav_artifact_id,
        )
    validation_cte = ""
    validation_join = ""
    if artifact_ids:
        calls = ",\n    ".join(
            "public.caprls_assert_artifact_valid("
            f"{_quote(artifact_id)}, "
            f"{_quote(measurements.valid_expected_json)}::jsonb"
            f") AS artifact_{index}_valid"
            for index, artifact_id in enumerate(artifact_ids, start=1)
        )
        validation_cte = (
            "validation AS MATERIALIZED (\n"
            f"  SELECT {calls}\n"
            "),\n"
        )
        validation_join = "CROSS JOIN validation"

    reference_sql = (
        "SELECT d.doc_id, d.tenant_id, d.region "
        "FROM public.document d "
        f"WHERE {measurements.exact_predicate}"
    )
    sql = f"""
BEGIN ISOLATION LEVEL REPEATABLE READ;
WITH
{validation_cte}actual_rows AS MATERIALIZED (
  SELECT q.doc_id::bigint AS doc_id,
         q.tenant_id::bigint AS tenant_id,
         q.region::text AS region
  FROM (
{actual_sql}
  ) AS q
  {validation_join}
),
reference_rows AS MATERIALIZED (
  {reference_sql}
),
actual_set AS MATERIALIZED (
  SELECT DISTINCT doc_id, tenant_id, region FROM actual_rows
),
reference_set AS MATERIALIZED (
  SELECT DISTINCT doc_id, tenant_id, region FROM reference_rows
),
left_only AS MATERIALIZED (
  SELECT * FROM actual_set EXCEPT SELECT * FROM reference_set
),
right_only AS MATERIALIZED (
  SELECT * FROM reference_set EXCEPT SELECT * FROM actual_set
)
SELECT pg_catalog.json_build_object(
  'actual_count', (SELECT count(*) FROM actual_rows),
  'reference_count', (SELECT count(*) FROM reference_rows),
  'actual_distinct_count', (SELECT count(*) FROM actual_set),
  'reference_distinct_count', (SELECT count(*) FROM reference_set),
  'set_diff_left', (SELECT count(*) FROM left_only),
  'set_diff_right', (SELECT count(*) FROM right_only),
  'actual_hash', (
    SELECT md5(COALESCE(string_agg(
      pg_catalog.jsonb_build_array(doc_id, tenant_id, region)::text,
      E'\\n' ORDER BY doc_id, tenant_id, region
    ), '')) FROM actual_rows
  ),
  'reference_hash', (
    SELECT md5(COALESCE(string_agg(
      pg_catalog.jsonb_build_array(doc_id, tenant_id, region)::text,
      E'\\n' ORDER BY doc_id, tenant_id, region
    ), '')) FROM reference_rows
  )
)::text;
ROLLBACK;
"""
    stdout = run_psql_command(sql, pg_env)
    payload: Mapping[str, Any] | None = None
    for line in reversed(stdout.splitlines()):
        candidate = line.strip()
        if candidate.startswith("{") and candidate.endswith("}"):
            parsed = json.loads(candidate)
            if isinstance(parsed, Mapping):
                payload = parsed
                break
    if payload is None:
        raise PostgresError(
            f"{case.test_id}: actual/reference check returned no JSON result"
        )

    integer_fields = (
        "actual_count",
        "reference_count",
        "actual_distinct_count",
        "reference_distinct_count",
        "set_diff_left",
        "set_diff_right",
    )
    if any(
        payload.get(field).__class__ is not int
        for field in integer_fields
    ):
        raise PostgresError(
            f"{case.test_id}: actual/reference counts are malformed"
        )
    actual_count = int(payload["actual_count"])
    reference_count = int(payload["reference_count"])
    matches = (
        actual_count == reference_count == measurements.authorized_count
        and payload["actual_distinct_count"] == actual_count
        and payload["reference_distinct_count"] == reference_count
        and payload["set_diff_left"] == 0
        and payload["set_diff_right"] == 0
        and payload.get("actual_hash") == payload.get("reference_hash")
    )
    if not matches:
        raise PostgresError(
            f"{case.test_id}: selected body differs from independent reference: "
            f"{dict(payload)}"
        )
    return {
        "schema": "e8b_actual_reference_check_v1",
        "action": outcome.action,
        "artifact_status": outcome.artifact_status,
        "initial_validation_passed": initial_validation.validation_passed,
        "failure_sqlstate": initial_validation.failure_sqlstate,
        "failure_symbol": initial_validation.failure_symbol,
        "selected_body_execution": True,
        "reference_execution": True,
        "same_snapshot": True,
        "isolation_level": "repeatable_read",
        "validated_artifact_count": len(artifact_ids),
        **dict(payload),
    }


def _attach_actual_reference_check(
    record: Dict[str, Any],
    evidence: Mapping[str, Any],
) -> None:
    record["e8b_execution_evidence"] = dict(evidence)
    executed = evidence.get("selected_body_execution") is True
    record["runtime_audit"]["body_execution_count"] = 1 if executed else 0
    record["runtime_audit"]["reference_execution_count"] = (
        1 if evidence.get("reference_execution") is True else 0
    )
    if not executed:
        record["oracle_check"].update(
            {
                "status": "not_applicable",
                "oracle_kind": "expected_reject_no_body_execution",
                "set_diff_left": 0,
                "set_diff_right": 0,
                "known_invalid_accepted": False,
                "known_valid_rejected": False,
            }
        )
        return
    row_count = int(evidence["actual_count"])
    record["oracle_check"].update(
        {
            "status": "match",
            "oracle_kind": "same_snapshot_independent_authorized_set",
            "set_diff_left": int(evidence["set_diff_left"]),
            "set_diff_right": int(evidence["set_diff_right"]),
            "known_invalid_accepted": False,
            "known_valid_rejected": False,
        }
    )
    record["result"] = {
        "row_count": row_count,
        "result_hash": _digest(
            {
                "canonical_visible_rows_md5": evidence["actual_hash"],
                "row_count": row_count,
            }
        ),
    }
    record["counts"]["authorized_rows"] = row_count


def _record(
    root: Path,
    manifest_path: Path,
    case: E8bCase,
    mode: str,
    outcome: ModeOutcome,
    metrics_override: Optional[Mapping[str, Any]] = None,
    pg_version: str = "not_executed_e8b_bounded_main",
    policy_id: str = "tenant_group",
    context_id: str = "e8b_bounded_main",
    ctx_hash: Optional[str] = None,
    principal_id: Optional[str] = None,
    exact_predicate: Optional[str] = None,
    planning_evidence_scope: Optional[str] = None,
    artifact_versions: Optional[Mapping[str, int]] = None,
    manifest_id: str = "e8b_freshness_maintenance_v1",
    stage: str = "freshness_maintenance",
    dataset_scale: str = "1e5",
    dataset_seed: int = 51,
    execution_sql_source: Optional[str] = None,
    query_plan_payload_override: Optional[Mapping[str, Any]] = None,
# BEGIN PHASE_B_E8COST_PROJECTION_RECORD_CAPABILITY
    _e8cost_projection_capability: object | None = None,
# END PHASE_B_E8COST_PROJECTION_RECORD_CAPABILITY
) -> Dict[str, Any]:
    mode = normalize_mode_id(mode)
# BEGIN PHASE_B_E8COST_GENERIC_RECORD_REJECTION
    if _e8cost_projection_capability is not None and not (
        _is_e8cost_projection_capability(_e8cost_projection_capability)
    ):
        raise ValueError("E8-COST accounting projection capability is not exact")
    if (
        stage == "artifact_cost_update_rate"
        and mode == ADMISSION_FIRST_MODE
        and not _is_e8cost_projection_capability(_e8cost_projection_capability)
    ):
        raise ValueError(
            "E8-COST AdmissionFirst records require the exact accounting "
            "projection constructor"
        )
# END PHASE_B_E8COST_GENERIC_RECORD_REJECTION
    metrics = dict(metrics_override) if metrics_override is not None else _maintenance_metrics(case, mode, outcome)
    query_plan_payload = query_plan_payload_override or outcome.planner_query_plan
    expected_principal = principal_id or E8B_FIXTURE_PRINCIPAL_ID
    expected_context_hash = ctx_hash or (
        E8B_FIXTURE_CONTEXT_HASH
        if mode == ADMISSION_FIRST_MODE
        else _digest({"case": case.test_id})
    )
    expected_exact_predicate = exact_predicate or E8B_FIXTURE_EXACT_PREDICATE
    expected_evidence_scope = planning_evidence_scope or E8B_PLANNING_EVIDENCE_SCOPE
    planning_receipt = _validate_contract_query_plan_for_record(
        case=case,
        mode=mode,
        outcome=outcome,
        query_plan_payload=query_plan_payload,
        policy_id=policy_id,
        principal_id=expected_principal,
        context_hash=expected_context_hash,
        exact_predicate=expected_exact_predicate,
        evidence_scope=expected_evidence_scope,
    )
    context_hash = expected_context_hash
    used_postgres_measurements = not pg_version.startswith("not_executed")
    actual_execution_sql_source = execution_sql_source or (
        "benchmark_probe_sql" if used_postgres_measurements else "not_executed"
    )
    if outcome.status == "expected_reject":
        actual_execution_sql_source = "not_executed"
    trusted_state = {"artifact_validation_model": 2}
    if used_postgres_measurements:
        trusted_state["postgres_artifact_measurement"] = 1
    query_only_ms = float(metrics.get("query_only_ms", metrics["total_ms"]))
    validation_ms = float(metrics["version_check_overhead_ms"])
    artifact_validation_same_snapshot = bool(metrics.get("artifact_validation_same_snapshot", 0.0))
    artifact_validation_isolation_level = (
        str(metrics.get("artifact_validation_isolation_level") or "") or None
    )
    if artifact_validation_same_snapshot:
        trusted_state["artifact_validation_same_snapshot"] = 1
    fallback_ms = float(metrics["fallback_ms"])
    build_ms = float(metrics["build_ms"])
    storage_bytes = int(metrics["storage_bytes"])
    storage_pages = math.ceil(storage_bytes / 8192) if storage_bytes else 0
    invalidation_count = int(metrics["invalidation_count"])
    maintenance_unit_ms = float(metrics.get("maintenance_unit_ms", metrics["refresh_ms"]))
    maintenance_ms_total = (
        maintenance_total_ms(
            maintenance_unit_ms=maintenance_unit_ms,
            invalidation_count=invalidation_count,
        )
        if stage == "artifact_cost_update_rate"
        else float(metrics["refresh_ms"])
    )
    artifact_cost_models = {
        "query_only": query_only_ms,
        "build_plus_single_query": _amortized_ms(
            query_ms=query_only_ms,
            build_ms=build_ms,
            maintenance_ms_total=maintenance_ms_total,
            fallback_ms=0.0,
            q=1,
        ),
        "amortized_Q100_U1pct": _amortized_ms(
            query_ms=query_only_ms,
            build_ms=build_ms,
            maintenance_ms_total=maintenance_ms_total,
            fallback_ms=0.0,
            q=100,
        ),
        "amortized_Q1000_U0pct": _amortized_ms(
            query_ms=query_only_ms,
            build_ms=build_ms,
            maintenance_ms_total=0.0,
            fallback_ms=0.0,
            q=1000,
        ),
        "declared_Q_U": _amortized_ms(
            query_ms=query_only_ms,
            build_ms=build_ms,
            maintenance_ms_total=maintenance_ms_total,
            fallback_ms=fallback_ms,
            q=case.amortization_q,
        ),
    }
    planner_candidates = list(outcome.planner_candidates)
    accepted_planner_candidates = [
        candidate for candidate in planner_candidates if bool(candidate.get("accepted"))
    ]
    chosen_candidate = next(
        (
            candidate
            for candidate in accepted_planner_candidates
            if candidate.get("template_id") == outcome.template_id
            and candidate.get("action") == outcome.action
        ),
        None,
    )
    chosen_estimated_cost = (
        chosen_candidate.get("estimated_cost")
        if chosen_candidate is not None
        else metrics["total_ms"]
    )
    candidate_dynamic_fact_kinds = sorted(
        {
            kind
            for candidate in planner_candidates
            for kind in _candidate_dynamic_fact_kinds(candidate)
        }
    )
    execution_dynamic_fact_kinds = (
        list(_candidate_dynamic_fact_kinds(chosen_candidate))
        if chosen_candidate is not None
        else []
    )
    metrics_for_hash = {
        key: value
        for key, value in metrics.items()
        if key != "static_verifier_explain_json"
    }
    payload = {
        "test_id": case.test_id,
        "mode": mode,
        "status": outcome.status,
        "artifact_status": outcome.artifact_status,
        "action": outcome.action,
        "metrics": metrics_for_hash,
    }
    result_hash = _digest(
        {
            **payload,
            "mode": scientific_mode_key(mode),
        }
    )
    invalid_metadata = outcome.artifact_status in {
        "stale",
        "wrong_context",
        "rid_mismatch",
        "toctou_fail",
    }
    template_applicability = "metadata_invalid" if invalid_metadata else "applicable"
    failure = None
    if outcome.status != "pass":
        failure = {
            "reason": outcome.failure_reason,
            "expected_effect": case.expected_effect,
        }
    uses_barrier_execution = outcome.template_id == "barrier_filter_v1"

    record = {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": f"E8b_{case.test_id}_{mode}",
        "manifest_id": manifest_id,
        "manifest_hash": file_sha256(manifest_path),
        "experiment": "E8",
        "stage": stage,
        "run_kind": "normal_mode",
        "dataset": {"name": "synthetic_saas", "scale": dataset_scale, "seed": dataset_seed},
        "query": {
            "query_id": case.test_id,
            "path": "workloads/e8/freshness_maintenance.sql",
            "params": {
                "query_shape": case.query_shape,
                "artifact_type": case.artifact_type,
                "update_rate_per_hour": case.update_rate_per_hour,
                "ttl_s": case.ttl_s,
                "contexts": case.contexts,
                "expected_action": case.contract_action,
                "expected_effect": case.expected_effect,
                "amortization_q": case.amortization_q,
            },
        },
        "policy": {
            "policy_id": policy_id,
            "policy_version": 0,
            "policy_sql_manifest_hash": file_sha256(root / "manifests" / "policies" / "synthetic_saas_policies.yaml"),
        },
        "context": {"context_id": context_id, "ctx_hash": context_hash},
        "mode": mode,
        "template": {"template_id": outcome.template_id, "alternative": outcome.alternative},
        "template_applicability": {
            "status": template_applicability,
            "reason": outcome.failure_reason if template_applicability == "metadata_invalid" else None,
        },
        "template_oracle": {
            "eligible_for_template_oracle": False,
            "template_oracle_exclusion_reason": "E8b_freshness_maintenance_not_template_oracle_pool",
        },
        "evaluation_role": _evaluation_role(root, mode),
        "pg": {
            "version": pg_version,
            "gucs": {"jit": "off", "max_parallel_workers_per_gather": "0"},
        },
        "versions": {
            "policy": {policy_id: 0},
            "membership": {"group_membership": 0},
            "context": {context_id: 0},
            "trusted_state": trusted_state,
            "base": {"document": 0},
            "artifacts": dict(artifact_versions or {f"{case.artifact_type}_{case.test_id}": 0}),
        },
        "planner": {
            "level": "B",
            "disabled_components": [],
            "planning_time_ms": metrics["planning_ms"],
            "generated_templates": len(planner_candidates) if planner_candidates else 2,
            "rejected_templates": (
                sum(1 for candidate in planner_candidates if not bool(candidate.get("accepted")))
                if planner_candidates
                else (1 if outcome.status == "expected_reject" else 0)
            ),
            "costed_templates": (
                sum(
                    1
                    for candidate in accepted_planner_candidates
                    if candidate.get("estimated_cost") is not None
                )
                if planner_candidates
                else (0 if outcome.status == "expected_reject" else 1)
            ),
            "rejection_reasons": {outcome.failure_reason: 1} if outcome.status == "expected_reject" and outcome.failure_reason else {},
            "chosen_estimated_cost": chosen_estimated_cost,
            "chosen_rank_vs_template_oracle": None,
            "choice_reason": outcome.planner_choice_reason,
            "candidates": planner_candidates,
            "delivered_sigma": dict(chosen_candidate.get("delivered_sigma", {}))
            if chosen_candidate is not None
            else {},
            "local_feature_vector": {
                "artifact_type": case.artifact_type,
                "update_rate_per_hour": case.update_rate_per_hour,
                "ttl_s": case.ttl_s,
            },
            "parent_requirement_vector": {
                "query_shape": case.query_shape,
                "contexts": case.contexts,
            },
        },
        "static_verifier": {
            "status": str(metrics.get("static_verifier_status") or "pass"),
            "plan_hash": str(metrics.get("static_verifier_plan_hash") or result_hash),
            "explain_path": None,
            "reasons": list(metrics.get("static_verifier_reasons") or []),
        },
        "artifact_validation": {
            "status": outcome.artifact_status,
            "action": outcome.action,
            "expected_action": case.contract_action if mode == ADMISSION_FIRST_MODE else outcome.action,
            "failure_sqlstate": case.failure_sqlstate if invalid_metadata else None,
            "failure_symbol": case.failure_symbol if invalid_metadata else None,
            "same_snapshot": artifact_validation_same_snapshot,
            "isolation_level": artifact_validation_isolation_level,
            "planning_evidence_scope": (
                planning_receipt.evidence_scope if planning_receipt is not None else None
            ),
            "planning_verdict_is_execution_authorization": False,
            "planning_evidence_promotable": bool(
                planning_receipt is not None
                and planning_receipt.evidence_scope
                == E8B_POSTGRES_PLANNING_EVIDENCE_SCOPE
            ),
            "candidate_required_dynamic_fact_kinds": candidate_dynamic_fact_kinds,
            "execution_required_dynamic_fact_kinds": execution_dynamic_fact_kinds,
            "planning_receipt_digest": (
                planning_receipt.receipt_digest
                if planning_receipt is not None
                else None
            ),
        },
        "runtime_audit": {
            "status": "pass",
            "audit_path": None,
            "udf_calls": 0,
            "unauthorized_observations": 0,
            "client_errors": 0,
            "client_notices": 0,
        },
        "sql": _sql_provenance(
            root,
            manifest_path,
            case,
            mode,
            query_plan_payload,
            actual_execution_sql_source,
        ),
        "oracle_check": {
            "status": "mismatch" if outcome.status == "wrong_result" else "match",
            "oracle_kind": "bounded_artifact_freshness_maintenance",
            "set_diff_left": 1 if outcome.status == "wrong_result" else 0,
            "set_diff_right": 0,
            "known_invalid_accepted": bool(outcome.status == "wrong_result"),
            "known_valid_rejected": False,
        },
        "timing_ms": {
            "planning": metrics["planning_ms"],
            "execution": metrics["execution_ms"],
            "verification": metrics["version_check_overhead_ms"],
            "total": metrics["total_ms"],
        },
        "result": {
            "row_count": 0 if outcome.status == "expected_reject" else int(metrics["authorized_rows"]),
            "result_hash": result_hash,
        },
        "pg_metrics": {
            "shared_read_blocks": 0,
            "shared_hit_blocks": 0,
            "temp_read_blocks": 0,
            "temp_written_blocks": 0,
        },
        "counts": {
            "policy_evals": int(metrics["total_rows"])
            if mode in {"conservative-barrier", "native-pg-rls", "native-pg-rls-physical-design"}
            or uses_barrier_execution
            or outcome.action in {"fallback", "replan"}
            else 0,
            "residual_checks": 0,
            "candidate_rows": int(metrics["candidate_rows"]),
            "authorized_rows": int(metrics["authorized_rows"]),
            "artifact_lookups": int(metrics["artifact_lookups"]),
            "base_fetches": int(metrics["total_rows"])
            if outcome.action in {"fallback", "replan"}
            or mode in {"conservative-barrier", "native-pg-rls", "native-pg-rls-physical-design"}
            or uses_barrier_execution
            else int(metrics["authorized_rows"]),
            "invalidation_count": int(metrics["invalidation_count"]),
        },
        "artifact_cost": {
            "query_only_ms": query_only_ms,
            "build_ms": build_ms,
            "refresh_ms": metrics["refresh_ms"],
            "refresh_unit_ms": maintenance_unit_ms,
            "storage_bytes": storage_bytes,
            "indexes_built": [case.artifact_type] if int(metrics["artifact_lookups"]) else [],
            "artifact_key_encoding_version": "artifact_key_encoding_v1",
            "amortization_model": "postgres_measurement"
            if used_postgres_measurements
            else "not_executed_no_postgres_measurement",
            "Q": case.amortization_q,
            "U": case.update_rate_per_hour,
            "update_rate": case.update_rate_per_hour,
            "invalidated_rows": invalidation_count,
            "table_pages": storage_pages,
            "index_pages": storage_pages,
            "validation_ms": validation_ms,
            "maintenance_ms_total": maintenance_ms_total,
            "fallback_ms": fallback_ms,
            "refresh_policy": outcome.action,
            "amortized_latency_ms": artifact_cost_models,
        },
        "implementation": {
            "git_commit": _git_commit(root),
            "docker_image_digest": "not_containerized",
            "python_version": platform.python_version(),
            "planner_language": "python",
        },
        "e8b_maintenance_case": {
            **payload,
            "artifact_hit_rate": metrics["artifact_hit_rate"],
            "invalidation_count": int(metrics["invalidation_count"]),
            "fallback_ms": metrics["fallback_ms"],
            "refresh_ms": metrics["refresh_ms"],
            "version_check_overhead_ms": metrics["version_check_overhead_ms"],
        },
        "status": outcome.status,
        "failure": failure,
    }
    if query_plan_payload is not None:
        record["planner"]["query_plan"] = dict(query_plan_payload)
    return record


# BEGIN PHASE_B_E8COST_ACCOUNTING_PROJECTION_CONSTRUCTOR
def _make_e8cost_accounting_projection_constructor():
    """Mint only the finite E8-COST accounting projections."""

    capability = object()
    exact_cases = tuple(E8COST_CASES)
    exact_case_payloads = {id(case): asdict(case) for case in exact_cases}
    exact_query_ids = frozenset(case.test_id for case in exact_cases)
    if len(exact_cases) != 48 or len(exact_query_ids) != 48:
        raise AssertionError("E8-COST accounting projection inventory is not exact")

    def is_capability(candidate: object | None) -> bool:
        return candidate is capability

    def authority_flags() -> dict[str, bool]:
        return {
            "integrity_only": True,
            "production_planner_authority": False,
            "selection_authority": False,
            "execution_authority": False,
            "result_evidence": False,
            "f3_selection_authority": False,
        }

    def body_probe(
        *,
        body_probe_id: str,
        body_kind: str,
        template_id: str,
        alternative: str,
        timing: QueryTiming,
        validated: Optional[ValidatedQueryMeasurement] = None,
    ) -> dict[str, Any]:
        validation = None
        row_count = None
        if validated is not None:
            row_count = validated.row_count
            validation = {
                "status": (
                    "pass" if validated.validation.validation_passed else "fail"
                ),
                "failure_sqlstate": validated.validation.failure_sqlstate,
                "failure_symbol": validated.validation.failure_symbol,
                "elapsed_ms": float(validated.validation.elapsed_ms),
                "same_snapshot": validated.validation.same_snapshot,
                "isolation_level": validated.validation.isolation_level,
            }
        return {
            "body_probe_id": body_probe_id,
            "body_kind": body_kind,
            "template_id": template_id,
            "alternative": alternative,
            "planning_ms": float(timing.planning_ms),
            "execution_ms": float(timing.execution_ms),
            "total_ms": float(timing.total_ms),
            "row_count": row_count,
            "validation": validation,
            "probe_body_execution_count": 1,
            "selected_body_execution": False,
            "ownership": "shared_postgres_probe_inventory",
            **authority_flags(),
        }

    def build(
        *,
        root: Path,
        manifest_path: Path,
        case: E8bCase,
        measurements: PostgresMeasurements,
        repetition: RepetitionRun,
    ) -> Dict[str, Any]:
        try:
            path_type = type(Path())
            expected_manifest_id = _e8cost_manifest_identity(root, manifest_path)
            if (
                root.__class__ is not path_type
                or manifest_path.__class__ is not path_type
                or case.__class__ is not E8bCase
                or not any(case is candidate for candidate in exact_cases)
                or asdict(case) != exact_case_payloads.get(id(case))
                or measurements.__class__ is not PostgresMeasurements
                or repetition.__class__ is not RepetitionRun
                or repetition.phase not in {"warmup", "measured"}
                or repetition.iteration.__class__ is not int
                or repetition.warmup != 5
                or repetition.warmup.__class__ is not int
                or repetition.measured != 10
                or repetition.measured.__class__ is not int
                or (
                    repetition.phase == "warmup"
                    and not 1 <= repetition.iteration <= 5
                )
                or (
                    repetition.phase == "measured"
                    and not 1 <= repetition.iteration <= 10
                )
            ):
                raise TypeError("E8-COST accounting projection owners are not exact")

            if (
                measurements.pg_version.__class__ is not str
                or not measurements.pg_version
                or measurements.pg_version.startswith("not_executed")
                or measurements.policy_id != "tenant_group"
                or measurements.context_id.__class__ is not str
                or not measurements.context_id
                or measurements.ctx_hash.__class__ is not str
                or re.fullmatch(r"sha256:[0-9a-f]{64}", measurements.ctx_hash)
                is None
                or measurements.user_id.__class__ is not str
                or not measurements.user_id
                or measurements.auth_artifact_id.__class__ is not str
                or not measurements.auth_artifact_id
                or measurements.mav_artifact_id.__class__ is not str
                or not measurements.mav_artifact_id
                or measurements.validation_by_case.__class__ is not dict
                or frozenset(measurements.validation_by_case) != exact_query_ids
                or measurements.validated_artifact_queries.__class__ is not dict
                or frozenset(measurements.validated_artifact_queries)
                != frozenset({"auth_idx", "mav", "hybrid"})
                or any(
                    timing.__class__ is not QueryTiming
                    for timing in (
                        measurements.barrier,
                        measurements.auth_idx,
                        measurements.mav,
                        measurements.hybrid,
                    )
                )
                or any(
                    validation.__class__ is not ValidationTiming
                    for validation in measurements.validation_by_case.values()
                )
                or any(
                    validated.__class__ is not ValidatedQueryMeasurement
                    for validated in measurements.validated_artifact_queries.values()
                )
            ):
                raise ValueError("E8-COST shared PostgreSQL probe identity changed")

            target_template_id, target_alternative = _template_for_mode(
                ADMISSION_FIRST_MODE, case
            )
            if case.artifact_type == "mav":
                expected_target = (
                    "mav_scan_v1",
                    "MaterializedAuthorizedViewScan",
                )
                family = "MAV-DASH"
            elif case.artifact_status == "stale":
                expected_target = (
                    "auth_index_enum_v1",
                    "AuthorizationIndexSeek",
                )
                family = "STALE-FALLBACK"
            else:
                expected_target = (
                    "auth_index_enum_v1",
                    "AuthorizationIndexSeek",
                )
                family = "AUTHIDX-SPARSE"
            if (target_template_id, target_alternative) != expected_target:
                raise ValueError("E8-COST projected template registry changed")

            barrier_outcome = ModeOutcome(
                status="pass",
                artifact_status="not_applicable",
                action="execute",
                template_id="barrier_filter_v1",
                alternative="BarrierFilter",
                failure_reason=None,
            )
            barrier_metrics = _postgres_metrics(
                case,
                "conservative-barrier",
                barrier_outcome,
                measurements,
            )
            validated_auth = measurements.validated_artifact_queries["auth_idx"]
            validated_mav = measurements.validated_artifact_queries["mav"]
            validated_hybrid = measurements.validated_artifact_queries["hybrid"]
            body_probe_inventory = [
                body_probe(
                    body_probe_id="barrier_explain_analyze_query",
                    body_kind="postgres_explain_analyze_query_body",
                    template_id="barrier_filter_v1",
                    alternative="BarrierFilter",
                    timing=measurements.barrier,
                ),
                body_probe(
                    body_probe_id="auth_index_explain_analyze_query",
                    body_kind="postgres_explain_analyze_query_body",
                    template_id="auth_index_enum_v1",
                    alternative="AuthorizationIndexSeek",
                    timing=measurements.auth_idx,
                ),
                body_probe(
                    body_probe_id="mav_explain_analyze_query",
                    body_kind="postgres_explain_analyze_query_body",
                    template_id="mav_scan_v1",
                    alternative="MaterializedAuthorizedViewScan",
                    timing=measurements.mav,
                ),
                body_probe(
                    body_probe_id="hybrid_explain_analyze_query",
                    body_kind="postgres_explain_analyze_query_body",
                    template_id="hybrid_intersect_v1",
                    alternative="HybridIndexIntersect",
                    timing=measurements.hybrid,
                ),
                body_probe(
                    body_probe_id="auth_index_validated_query",
                    body_kind="postgres_same_snapshot_validated_query_body",
                    template_id="auth_index_enum_v1",
                    alternative="AuthorizationIndexSeek",
                    timing=validated_auth.timing,
                    validated=validated_auth,
                ),
                body_probe(
                    body_probe_id="mav_validated_query",
                    body_kind="postgres_same_snapshot_validated_query_body",
                    template_id="mav_scan_v1",
                    alternative="MaterializedAuthorizedViewScan",
                    timing=validated_mav.timing,
                    validated=validated_mav,
                ),
                body_probe(
                    body_probe_id="hybrid_validated_query",
                    body_kind="postgres_same_snapshot_validated_query_body",
                    template_id="hybrid_intersect_v1",
                    alternative="HybridIndexIntersect",
                    timing=validated_hybrid.timing,
                    validated=validated_hybrid,
                ),
            ]

            def common_observation(
                *,
                observation_id: str,
                artifact_kind: str,
                build_ms: float,
                refresh_ms: float,
                storage_bytes: int,
            ) -> dict[str, Any]:
                return {
                    "observation_id": observation_id,
                    "observation_kind": (
                        "postgres_maintenance_storage_observation"
                    ),
                    "artifact_kind": artifact_kind,
                    "build_ms": float(build_ms),
                    "refresh_ms": float(refresh_ms),
                    "storage_bytes": int(storage_bytes),
                    "build_body_execution_count": 1,
                    "refresh_body_execution_count": 1,
                    "storage_observation_count": 1,
                    "selected_body_execution": False,
                    "ownership": "shared_postgres_accounting_observations",
                    **authority_flags(),
                }

            common_accounting_observations = {
                "schema": (
                    "e8cost_common_maintenance_storage_observations_v1"
                ),
                "ownership": "shared_postgres_accounting_observations",
                "selected_body_execution": False,
                **authority_flags(),
                "observations": [
                    common_observation(
                        observation_id="auth_index_maintenance_storage",
                        artifact_kind="auth_idx",
                        build_ms=measurements.build_auth_ms,
                        refresh_ms=measurements.refresh_auth_ms,
                        storage_bytes=measurements.storage_auth_bytes,
                    ),
                    common_observation(
                        observation_id="mav_maintenance_storage",
                        artifact_kind="mav",
                        build_ms=measurements.build_mav_ms,
                        refresh_ms=measurements.refresh_mav_ms,
                        storage_bytes=measurements.storage_mav_bytes,
                    ),
                ],
            }
            case_validation = measurements.validation_by_case[case.test_id]
            case_validation_observation = {
                "schema": "e8cost_case_validation_observation_v1",
                "observation_id": "case_specific_artifact_validation",
                "case_query_id": case.test_id,
                "status": (
                    "pass" if case_validation.validation_passed else "fail"
                ),
                "failure_sqlstate": case_validation.failure_sqlstate,
                "failure_symbol": case_validation.failure_symbol,
                "elapsed_ms": float(case_validation.elapsed_ms),
                "same_snapshot": case_validation.same_snapshot,
                "isolation_level": case_validation.isolation_level,
                "probe_body_execution_count": 1,
                "selected_body_execution": False,
                "ownership": "case_specific_accounting_validation_observation",
                **authority_flags(),
            }

            declared_inputs = {
                "family": family,
                "Q": case.amortization_q,
                "U": case.update_rate_per_hour,
                "query_shape": case.query_shape,
                "artifact_type": case.artifact_type,
                "ttl_s": case.ttl_s,
                "contexts": case.contexts,
                "artifact_status": case.artifact_status,
                "contract_action": case.contract_action,
                "expected_effect": case.expected_effect,
            }
            body_probe_by_id = {
                item["body_probe_id"]: item for item in body_probe_inventory
            }
            common_observation_by_id = {
                item["observation_id"]: item
                for item in common_accounting_observations["observations"]
            }

            def accounting_alternative(
                *,
                template_id: str,
                alternative: str,
                action: str,
                query_body_probe_id: str,
                fallback_body_probe_id: str | None,
                maintenance_storage_observation_id: str | None,
                uses_case_validation_observation: bool,
            ) -> dict[str, Any]:
                query_only_ms = float(
                    body_probe_by_id[query_body_probe_id]["total_ms"]
                )
                fallback_ms = (
                    float(
                        body_probe_by_id[fallback_body_probe_id]["total_ms"]
                    )
                    if fallback_body_probe_id is not None
                    else 0.0
                )
                accounting_observation = (
                    common_observation_by_id[
                        maintenance_storage_observation_id
                    ]
                    if maintenance_storage_observation_id is not None
                    else None
                )
                build_ms = (
                    float(accounting_observation["build_ms"])
                    if accounting_observation is not None
                    else 0.0
                )
                maintenance_unit = (
                    float(accounting_observation["refresh_ms"])
                    if accounting_observation is not None
                    else 0.0
                )
                storage_bytes = (
                    int(accounting_observation["storage_bytes"])
                    if accounting_observation is not None
                    else 0
                )
                invalidation_count = estimated_invalidation_count(
                    update_rate_per_hour=case.update_rate_per_hour,
                    ttl_s=case.ttl_s,
                    contexts=case.contexts,
                )
                maintenance_total = maintenance_total_ms(
                    maintenance_unit_ms=maintenance_unit,
                    invalidation_count=invalidation_count,
                )
                validation_ms = (
                    float(case_validation_observation["elapsed_ms"])
                    if uses_case_validation_observation
                    else 0.0
                )
                return {
                    "projected_template_id": template_id,
                    "projected_alternative": alternative,
                    "projected_action": action,
                    "query_body_probe_id": query_body_probe_id,
                    "fallback_body_probe_id": fallback_body_probe_id,
                    "maintenance_storage_observation_id": (
                        maintenance_storage_observation_id
                    ),
                    "case_validation_observation_id": (
                        "case_specific_artifact_validation"
                        if uses_case_validation_observation
                        else None
                    ),
                    "query_only_ms": query_only_ms,
                    "build_ms": build_ms,
                    "maintenance_unit_ms": maintenance_unit,
                    "maintenance_ms_total": maintenance_total,
                    "fallback_ms": fallback_ms,
                    "validation_ms": validation_ms,
                    "storage_bytes": storage_bytes,
                    "amortized_latency_ms": _amortized_ms(
                        query_ms=query_only_ms,
                        build_ms=build_ms,
                        maintenance_ms_total=maintenance_total,
                        fallback_ms=fallback_ms,
                        q=case.amortization_q,
                    ),
                    **authority_flags(),
                }

            if family == "STALE-FALLBACK":
                alternatives = [
                    accounting_alternative(
                        template_id="barrier_filter_v1",
                        alternative="BarrierFilter",
                        action="fallback",
                        query_body_probe_id=(
                            "barrier_explain_analyze_query"
                        ),
                        fallback_body_probe_id=(
                            "barrier_explain_analyze_query"
                        ),
                        maintenance_storage_observation_id=None,
                        uses_case_validation_observation=True,
                    )
                ]
                projection_reason = (
                    "metadata_stale_accounting_fallback_projection"
                )
            else:
                alternatives = [
                    accounting_alternative(
                        template_id=target_template_id,
                        alternative=target_alternative,
                        action="execute",
                        query_body_probe_id=(
                            "mav_validated_query"
                            if family == "MAV-DASH"
                            else "auth_index_validated_query"
                        ),
                        fallback_body_probe_id=None,
                        maintenance_storage_observation_id=(
                            "mav_maintenance_storage"
                            if family == "MAV-DASH"
                            else "auth_index_maintenance_storage"
                        ),
                        uses_case_validation_observation=True,
                    ),
                    accounting_alternative(
                        template_id="barrier_filter_v1",
                        alternative="BarrierFilter",
                        action="execute",
                        query_body_probe_id=(
                            "barrier_explain_analyze_query"
                        ),
                        fallback_body_probe_id=None,
                        maintenance_storage_observation_id=None,
                        uses_case_validation_observation=False,
                    ),
                ]
                projection_reason = "observed_declared_q_u_accounting_minimum"

            minimum = min(
                alternatives,
                key=lambda item: item["amortized_latency_ms"],
            )
            observed_accounting_minimum = {
                "projected_template_id": minimum["projected_template_id"],
                "projected_alternative": minimum["projected_alternative"],
                "projected_action": minimum["projected_action"],
                "projection_reason": projection_reason,
                "amortized_latency_ms": minimum["amortized_latency_ms"],
                **authority_flags(),
            }

            record = _record(
                root=root,
                manifest_path=manifest_path,
                case=case,
                mode="conservative-barrier",
                outcome=barrier_outcome,
                metrics_override=barrier_metrics,
                pg_version=measurements.pg_version,
                policy_id=measurements.policy_id,
                context_id=measurements.context_id,
                ctx_hash=measurements.ctx_hash,
                principal_id=measurements.user_id,
                exact_predicate=measurements.exact_predicate,
                artifact_versions={},
                manifest_id=expected_manifest_id,
                stage="artifact_cost_update_rate",
                dataset_scale="1e6",
                dataset_seed=47,
                execution_sql_source="not_executed",
                _e8cost_projection_capability=capability,
            )
            record["run_id"] = (
                f"E8b_{case.test_id}_admission_first_accounting_projection"
            )
            attach_repetition(record, repetition)
            repetition_identity = dict(record["measurement"])
            shared_probe_owner_payload = {
                "schema": "e8cost_shared_postgres_probe_owner_v2",
                "role": "shared_postgres_probe_inventory",
                "manifest": {
                    "manifest_id": expected_manifest_id,
                    "manifest_hash": record["manifest_hash"],
                },
                "repetition": repetition_identity,
                "postgres_identity": {
                    "version": measurements.pg_version,
                    "gucs": {
                        "jit": "off",
                        "max_parallel_workers_per_gather": "0",
                    },
                    "policy_id": measurements.policy_id,
                    "context_id": measurements.context_id,
                    "ctx_hash": measurements.ctx_hash,
                    "principal_id": measurements.user_id,
                    "auth_artifact_id": measurements.auth_artifact_id,
                    "mav_artifact_id": measurements.mav_artifact_id,
                },
                "body_probe_inventory_digest": _digest(
                    {
                        "schema": "e8cost_shared_body_probe_inventory_v1",
                        "body_probe_inventory": body_probe_inventory,
                    }
                ),
                "common_accounting_observations_digest": _digest(
                    {
                        "schema": (
                            "e8cost_common_accounting_observations_digest_v1"
                        ),
                        "common_accounting_observations": (
                            common_accounting_observations
                        ),
                    }
                ),
                **authority_flags(),
            }
            shared_probe_owner = {
                **shared_probe_owner_payload,
                "integrity_digest": _digest(shared_probe_owner_payload),
            }
            case_validation_observation_digest = _digest(
                {
                    "schema": "e8cost_case_validation_observation_digest_v1",
                    "case_validation_observation": (
                        case_validation_observation
                    ),
                }
            )
            projection_owner_payload = {
                "schema": "e8cost_accounting_projection_owner_v1",
                "role": "accounting_projection_owner",
                "shared_probe_owner_digest": (
                    shared_probe_owner["integrity_digest"]
                ),
                "query": {
                    "query_id": case.test_id,
                    "path": "workloads/e8/freshness_maintenance.sql",
                },
                "declared_inputs": dict(declared_inputs),
                "case_validation_observation_digest": (
                    case_validation_observation_digest
                ),
                **authority_flags(),
            }
            projection_owner = {
                **projection_owner_payload,
                "integrity_digest": _digest(projection_owner_payload),
            }
            projection_integrity_payload = {
                "schema": "e8cost_projection_integrity_v2",
                "projection_owner_digest": projection_owner["integrity_digest"],
                **authority_flags(),
                "accounting_alternatives": alternatives,
                "observed_accounting_minimum": observed_accounting_minimum,
            }
            projection_integrity_digest = _digest(
                projection_integrity_payload
            )
            projection_integrity = {
                key: value
                for key, value in projection_integrity_payload.items()
                if key
                not in {
                    "accounting_alternatives",
                    "observed_accounting_minimum",
                }
            }
            projection_integrity["integrity_digest"] = (
                projection_integrity_digest
            )

            record["query"] = {
                "query_id": case.test_id,
                "path": "workloads/e8/freshness_maintenance.sql",
                "params": {},
            }
            record["mode"] = ADMISSION_FIRST_MODE
            record["template"] = {
                "template_id": None,
                "alternative": None,
                "role": "no_selected_template_accounting_projection",
                "selection_authority": False,
                "execution_authority": False,
            }
            record["template_applicability"] = {
                "status": "policy_not_applicable",
                "reason": "accounting_projection_has_no_selected_template",
                "selection_authority": False,
            }
            record["template_oracle"] = {
                "eligible_for_template_oracle": False,
                "template_oracle_exclusion_reason": (
                    "E8-COST_accounting_projection_not_selection_evidence"
                ),
            }
            record["evaluation_role"] = _evaluation_role(
                root, ADMISSION_FIRST_MODE
            )
            record["versions"] = {
                "policy": {measurements.policy_id: 0},
                "membership": {"group_membership": 0},
                "context": {measurements.context_id: 0},
                "trusted_state": {
                    "shared_body_probe_inventory_observed": 1,
                    "common_accounting_observations_observed": 1,
                    "case_validation_observation_observed": 1,
                    "planner_selection_observed": 0,
                    "selected_body_execution": 0,
                    "result_equality_observed": 0,
                },
                "base": {"document": 0},
                "artifacts": {},
            }
            record["planner"] = {
                "level": None,
                "disabled_components": [],
                "planning_time_ms": None,
                "generated_templates": None,
                "rejected_templates": None,
                "costed_templates": None,
                "rejection_reasons": {},
                "chosen_estimated_cost": None,
                "chosen_rank_vs_template_oracle": None,
                "choice_reason": None,
                "candidates": [],
                "delivered_sigma": {},
                "local_feature_vector": {},
                "parent_requirement_vector": {},
                "planner_run_observed": False,
                "selection_authority": False,
                "execution_authority": False,
                "f3_selection_authority": False,
            }
            record["static_verifier"] = {
                "status": "not_executed",
                "plan_hash": None,
                "explain_path": None,
                "reasons": [],
                "evidence_kind": "accounting_projection_no_plan",
            }
            record["artifact_validation"] = {
                "status": "not_applicable",
                "action": "not_applicable",
                "expected_action": "not_applicable",
                "failure_sqlstate": None,
                "failure_symbol": None,
                "same_snapshot": False,
                "isolation_level": None,
                "record_promotion_eligible": False,
                "selection_authority": False,
                "execution_authority": False,
            }
            record["runtime_audit"] = {
                "status": "not_executed",
                "audit_path": None,
                "udf_calls": None,
                "unauthorized_observations": None,
                "client_errors": None,
                "client_notices": None,
                "selected_body_execution": False,
            }
            record["sql"] = {
                "emitted_sql_path": None,
                "emitted_sql_hash": None,
                "normalized_sql_hash": None,
                "execution_sql_source": "not_executed",
                "measurement_promotion": False,
                "selection_authority": False,
                "execution_authority": False,
                "selected_body_execution": False,
            }
            record["oracle_check"] = {
                "status": "not_applicable",
                "oracle_kind": "not_applicable",
                "set_diff_left": None,
                "set_diff_right": None,
                "known_invalid_accepted": False,
                "known_valid_rejected": False,
            }
            record["timing_ms"] = {
                "planning": None,
                "execution": None,
                "verification": None,
                "total": None,
            }
            record["result"] = {
                "row_count": None,
                "result_hash": None,
                "selection_authority": False,
                "execution_authority": False,
                "result_evidence": False,
            }
            record["pg_metrics"] = {
                "shared_read_blocks": None,
                "shared_hit_blocks": None,
                "temp_read_blocks": None,
                "temp_written_blocks": None,
            }
            record["counts"] = {
                "policy_evals": None,
                "residual_checks": None,
                "candidate_rows": None,
                "authorized_rows": None,
                "artifact_lookups": None,
                "base_fetches": None,
                "invalidation_count": None,
            }
            record["artifact_cost"] = {
                "query_only_ms": None,
                "validation_ms": None,
                "build_ms": None,
                "refresh_ms": None,
                "refresh_unit_ms": None,
                "storage_bytes": None,
                "indexes_built": [],
                "artifact_key_encoding_version": "not_applicable",
                "amortization_model": "not_applicable",
                "Q": None,
                "U": None,
                "update_rate": None,
                "invalidated_rows": None,
                "table_pages": None,
                "index_pages": None,
                "maintenance_ms_total": None,
                "fallback_ms": None,
                "refresh_policy": None,
                "amortized_latency_ms": None,
                "accounting_probe": {
                    "schema": "e8cost_accounting_probe_v2",
                    "evidence_role": "accounting_probe_only",
                    **authority_flags(),
                    "declared_inputs": declared_inputs,
                    "body_probe_inventory": body_probe_inventory,
                    "common_accounting_observations": (
                        common_accounting_observations
                    ),
                    "case_validation_observation": (
                        case_validation_observation
                    ),
                    "shared_probe_owner": shared_probe_owner,
                    "projection_owner": projection_owner,
                    "accounting_alternatives": alternatives,
                    "observed_accounting_minimum": (
                        observed_accounting_minimum
                    ),
                    "projection_integrity": projection_integrity,
                },
            }
            record["evidence"] = {
                "schema": "e8cost_accounting_gate_projection_v2",
                "role": "accounting_gate_projection",
                "promotion_eligible": False,
                "selection_authority": False,
                "execution_authority": False,
                "result_evidence": False,
                "f3_selection_authority": False,
                "planner_choice_evidence": False,
                "integrity_only": True,
                "shared_probe_owner_digest": (
                    shared_probe_owner["integrity_digest"]
                ),
                "projection_owner_digest": projection_owner["integrity_digest"],
                "projection_integrity_digest": (
                    projection_integrity_digest
                ),
            }
            record.pop("e8b_maintenance_case", None)
            record["status"] = "not_executed"
            record["failure"] = None

            issues = validate_raw_run_record(record)
            if issues:
                rendered = ", ".join(
                    f"{issue.path}: {issue.message}" for issue in issues
                )
                raise ValueError(rendered)
            return record
        except Exception:
            raise ValueError(
                "E8-COST accounting projection record failed closed"
            ) from None

    return build, is_capability


(
    _e8cost_accounting_projection_record,
    _is_e8cost_projection_capability,
) = _make_e8cost_accounting_projection_constructor()
# END PHASE_B_E8COST_ACCOUNTING_PROJECTION_CONSTRUCTOR


def _write_record(record: Mapping[str, Any], output_dir: Path) -> Path:
    issues = validate_raw_run_record(record)
    if issues:
        rendered = ", ".join(f"{issue.path}: {issue.message}" for issue in issues)
        raise ValueError(f"E8b raw record failed schema validation: {rendered}")
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_mode = str(record["mode"]).replace("-", "_")
    path = output_dir / f"{record['run_id'].replace('-', '_')}_{safe_mode}.json"
    with path.open("w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path


def run_e8b_study(
    root: Path,
    manifest_path: Path,
    output_dir: Path,
    pg_env: Optional[PostgresEnv] = None,
) -> E8bStudyResult:
    manifest = _load_manifest(manifest_path)
    _validate_manifest(manifest_path, manifest)
    stage = str(manifest.get("stage"))
    cases = _cases_for_stage(stage)
    modes = sorted(_modes_for_stage(stage), key=mode_execution_order_key)
    if ADMISSION_FIRST_MODE in modes and pg_env is None:
        raise ValueError(
            "e8b-study AdmissionFirst manifests require a PostgreSQL environment"
        )
    dataset = manifest.get("dataset") or {}
    dataset_scale = str(dataset.get("scale", "1e5"))
    dataset_seed = int(dataset.get("seed", 51))
    manifest_id = str(manifest.get("manifest_id", "e8b_freshness_maintenance_v1"))
    repetitions = protocol_from_manifest(manifest)

    raw_paths: list[Path] = []
    contract_records = 0
    diagnostic_wrong_results = 0
    fallback_records = 0
    refresh_records = 0

    for repetition in iter_repetitions(repetitions):
        measurements = (
            _prepare_postgres_measurements(root, manifest, cases, pg_env)
            if pg_env is not None
            else None
        )
        for case in cases:
            for mode in modes:
                if (
                    stage == "artifact_cost_update_rate"
                    and mode == ADMISSION_FIRST_MODE
                ):
                    if measurements is None:
                        raise ValueError(
                            "E8-COST accounting projections require PostgreSQL probes"
                        )
                    record = _e8cost_accounting_projection_record(
                        root=root,
                        manifest_path=manifest_path,
                        case=case,
                        measurements=measurements,
                        repetition=repetition,
                    )
                    raw_paths.append(_write_record(record, output_dir))
                    contract_records += 1
                    continue

                static_verifier_explain_json = None
                if mode == ADMISSION_FIRST_MODE:
                    outcome = _contract_planner_outcome(
                        case,
                        measurements=measurements,
                    )
                else:
                    outcome = _mode_outcome(case, mode)

                record_kwargs: dict[str, Any] = {}
                if measurements is not None:
                    metrics = _postgres_metrics(
                        case,
                        mode,
                        outcome,
                        measurements,
                    )
                    static_verifier_explain_json = metrics.get(
                        "static_verifier_explain_json"
                    )
                    artifact_versions: dict[str, int] = {}
                    if mode not in {
                        "conservative-barrier",
                        "native-pg-rls",
                        "native-pg-rls-physical-design",
                    }:
                        if mode == "mav-no-version":
                            artifact_versions[measurements.mav_artifact_id] = 0
                        elif case.artifact_type in {"auth_idx", "both"}:
                            artifact_versions[measurements.auth_artifact_id] = 0
                        if (
                            mode != "mav-no-version"
                            and case.artifact_type in {"mav", "both"}
                        ):
                            artifact_versions[measurements.mav_artifact_id] = 0
                    record_kwargs = {
                        "metrics_override": metrics,
                        "pg_version": measurements.pg_version,
                        "policy_id": measurements.policy_id,
                        "context_id": measurements.context_id,
                        "ctx_hash": measurements.ctx_hash,
                        "principal_id": measurements.user_id,
                        "exact_predicate": measurements.exact_predicate,
                        "planning_evidence_scope": (
                            E8B_POSTGRES_PLANNING_EVIDENCE_SCOPE
                        ),
                        "artifact_versions": artifact_versions
                        or {f"{case.artifact_type}_{case.test_id}": 0},
                    }
                    template_probe = measurements.query_plan_by_template.get(
                        outcome.template_id
                    )
                    if outcome.status == "expected_reject":
                        record_kwargs["execution_sql_source"] = "not_executed"
                    elif (
                        mode == ADMISSION_FIRST_MODE
                        and outcome.planner_query_plan is not None
                    ):
                        record_kwargs["execution_sql_source"] = (
                            "planner_ir_emitted"
                        )
                    elif template_probe is not None:
                        record_kwargs["execution_sql_source"] = (
                            "planner_ir_emitted"
                        )
                        record_kwargs["query_plan_payload_override"] = (
                            template_probe
                        )
                    else:
                        record_kwargs["execution_sql_source"] = (
                            "native_baseline_sql"
                        )

                record = _record(
                    root,
                    manifest_path,
                    case,
                    mode,
                    outcome,
                    manifest_id=manifest_id,
                    stage=stage,
                    dataset_scale=dataset_scale,
                    dataset_seed=dataset_seed,
                    **record_kwargs,
                )
                if (
                    stage == "freshness_maintenance"
                    and mode == ADMISSION_FIRST_MODE
                ):
                    if measurements is None or pg_env is None:
                        raise ValueError(
                            "E8b actual/reference check requires PostgreSQL"
                        )
                    _attach_actual_reference_check(
                        record,
                        _run_actual_reference_check(
                            case,
                            outcome,
                            measurements,
                            pg_env,
                        ),
                    )
                attach_repetition(record, repetition)
                attach_static_verifier_explain(
                    record,
                    output_dir,
                    static_verifier_explain_json,
                )
                raw_paths.append(_write_record(record, output_dir))

                if mode == ADMISSION_FIRST_MODE:
                    contract_records += 1
                if outcome.status == "wrong_result":
                    diagnostic_wrong_results += 1
                if outcome.action == "fallback":
                    fallback_records += 1
                if outcome.action == "refresh":
                    refresh_records += 1

        if (
            stage == "freshness_maintenance"
            and measurements is not None
            and pg_env is not None
        ):
            for record in _toctou_witness_records(
                root=root,
                manifest_path=manifest_path,
                measurements=measurements,
                pg_env=pg_env,
                manifest_id=manifest_id,
                dataset_scale=dataset_scale,
                dataset_seed=dataset_seed,
            ):
                attach_repetition(record, repetition)
                static_verifier_explain_json = None
                if record.get("status") == "pass":
                    auth_idx_measurement = (
                        measurements.validated_artifact_queries.get("auth_idx")
                    )
                    if auth_idx_measurement is not None:
                        timing = auth_idx_measurement.timing
                        static_verifier = record.get("static_verifier")
                        if isinstance(static_verifier, dict):
                            static_verifier["status"] = (
                                timing.static_verifier_status
                            )
                            static_verifier["plan_hash"] = (
                                timing.static_verifier_plan_hash
                                or static_verifier["plan_hash"]
                            )
                            static_verifier["reasons"] = list(
                                timing.static_verifier_reasons
                            )
                        static_verifier_explain_json = (
                            timing.static_verifier_explain_json
                        )
                attach_static_verifier_explain(
                    record,
                    output_dir,
                    static_verifier_explain_json,
                )
                raw_paths.append(_write_record(record, output_dir))
                if record["mode"] == ADMISSION_FIRST_MODE:
                    contract_records += 1
                if record["status"] == "wrong_result":
                    diagnostic_wrong_results += 1

    return E8bStudyResult(
        raw_result_paths=raw_paths,
        normal_records=len(raw_paths),
        contract_records=contract_records,
        diagnostic_wrong_results=diagnostic_wrong_results,
        fallback_records=fallback_records,
        refresh_records=refresh_records,
    )
