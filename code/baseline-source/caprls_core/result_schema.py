"""Raw result schema checks for Phase 0 and later verifiers."""

from __future__ import annotations

import hashlib
import json
# BEGIN PHASE_B_E8COST_ACCOUNTING_PROJECTION_IMPORTS
import math
# END PHASE_B_E8COST_ACCOUNTING_PROJECTION_IMPORTS
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping

from .baselines import (
    ADMISSION_FIRST_MODE,
    ADMISSION_FIRST_NO_DOMINANCE_MODE,
    ALLOWED_BASELINE_CLASSES,
    ALLOWED_EVALUATION_ROLES,
    LEGACY_CONTRACT_AWARE_MODE,
    LEGACY_CONTRACT_AWARE_NO_DOMINANCE_MODE,
    ModeSpec,
    POLICY_ENFORCEMENT_ROLE,
    normalize_evaluation_role,
    normalize_mode_id,
)
from planner.core import DISABLED_COMPONENTS


LEGACY_RAW_SCHEMA_VERSION = "caprls-run-v1"
PREVIOUS_RAW_SCHEMA_VERSION = "caprls-run-v2"
RAW_SCHEMA_VERSION = "caprls-run-v3"
LEGACY_RAW_SCHEMA_VERSIONS = {
    LEGACY_RAW_SCHEMA_VERSION,
    PREVIOUS_RAW_SCHEMA_VERSION,
}
ALLOWED_RAW_SCHEMA_VERSIONS = {
    *LEGACY_RAW_SCHEMA_VERSIONS,
    RAW_SCHEMA_VERSION,
}

STATIC_VERIFIER_TEMPLATE_WITNESS_MODE = "static-verifier-template-witness"
STATIC_VERIFIER_TEMPLATE_WITNESS_MANIFEST_ID = "static_verifier_template_witness_v1"

ALLOWED_STATUS = {
    "pass",
    "correctness_pass",
    "not_executed",
    "expected_reject",
    "wrong_result",
    "unsafe_observation",
    "static_verifier_fail",
    "runtime_audit_fail",
    "timeout",
    "oom",
    "planner_error",
    "pg_error",
    "infra_error",
}

ALLOWED_RUN_KIND = {
    "normal_mode",
    "template_candidate",
    "template_oracle_summary",
}

ALLOWED_TEMPLATE_APPLICABILITY = {
    "applicable",
    "contract_reject",
    "artifact_unavailable",
    "metadata_invalid",
    "policy_not_applicable",
    "dominance_pruned",
    "equivalent_plan_shape_pruned",
}

ALLOWED_ARTIFACT_VALIDATION_STATUS = {
    "pass",
    "stale",
    "wrong_context",
    "rid_mismatch",
    "toctou_fail",
    "not_applicable",
}

ALLOWED_ARTIFACT_ACTION = {
    "execute",
    "reject",
    "fallback",
    "refresh",
    "replan",
}

ALLOWED_STATIC_VERIFIER_STATUS = {
    "pass",
    "fail",
}

ALLOWED_RUNTIME_AUDIT_STATUS = {
    "pass",
    "fail",
    "not_executed",
}

ALLOWED_ORACLE_CHECK_STATUS = {
    "match",
    "mismatch",
    "not_applicable",
}

ALLOWED_AMORTIZATION_MODEL = {
    "query_only",
    "declared_q_u",
    "not_applicable",
    "not_executed_no_postgres_measurement",
    "postgres_measurement",
    "rejected_not_executed",
}

LEGACY_ALLOWED_AMORTIZATION_MODEL = ALLOWED_AMORTIZATION_MODEL | {
    "bounded_case_study",
    "bounded_main_model",
    "bounded_main_maintenance_model",
    "not_applicable_planner_overhead",
}

REQUIRED_TOP_LEVEL = [
    "schema_version",
    "run_id",
    "manifest_id",
    "manifest_hash",
    "experiment",
    "stage",
    "run_kind",
    "dataset",
    "query",
    "policy",
    "context",
    "mode",
    "template",
    "template_applicability",
    "template_oracle",
    "pg",
    "versions",
    "planner",
    "static_verifier",
    "artifact_validation",
    "runtime_audit",
    "sql",
    "oracle_check",
    "timing_ms",
    "result",
    "pg_metrics",
    "counts",
    "artifact_cost",
    "implementation",
    "status",
    "failure",
]

LEGACY_IDENTITY_FIELDS = ["baseline_class"]
V3_IDENTITY_FIELDS = ["evaluation_role"]

REQUIRED_NESTED = [
    "query.query_id",
    "query.params",
    "policy.policy_id",
    "policy.policy_version",
    "policy.policy_sql_manifest_hash",
    "context.context_id",
    "context.ctx_hash",
    "template.template_id",
    "template.alternative",
    "template_applicability.status",
    "template_oracle.eligible_for_template_oracle",
    "pg.version",
    "pg.gucs",
    "planner.generated_templates",
    "planner.rejected_templates",
    "planner.costed_templates",
    "planner.chosen_estimated_cost",
    "planner.chosen_rank_vs_template_oracle",
    "planner.candidates",
    "planner.delivered_sigma",
    "static_verifier.status",
    "static_verifier.plan_hash",
    "artifact_validation.status",
    "artifact_validation.action",
    "artifact_validation.expected_action",
    "artifact_validation.failure_sqlstate",
    "artifact_validation.failure_symbol",
    "runtime_audit.status",
    "runtime_audit.udf_calls",
    "runtime_audit.unauthorized_observations",
    "oracle_check.status",
    "oracle_check.set_diff_left",
    "oracle_check.set_diff_right",
    "sql.emitted_sql_hash",
    "sql.normalized_sql_hash",
    "timing_ms.planning",
    "timing_ms.execution",
    "timing_ms.verification",
    "timing_ms.total",
    "result.row_count",
    "result.result_hash",
    "pg_metrics.shared_read_blocks",
    "pg_metrics.shared_hit_blocks",
    "counts.policy_evals",
    "counts.residual_checks",
    "counts.candidate_rows",
    "counts.authorized_rows",
    "counts.artifact_lookups",
    "counts.base_fetches",
    "artifact_cost.query_only_ms",
    "artifact_cost.build_ms",
    "artifact_cost.refresh_ms",
    "artifact_cost.storage_bytes",
    "implementation.git_commit",
    "implementation.docker_image_digest",
    "implementation.python_version",
    "implementation.planner_language",
]

V2_REQUIRED_NESTED = [
    "planner.disabled_components",
    "artifact_validation.same_snapshot",
    "artifact_validation.isolation_level",
]

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

DIGEST_PATHS = [
    "manifest_hash",
    "policy.policy_sql_manifest_hash",
    "sql.emitted_sql_hash",
    "sql.normalized_sql_hash",
    "result.result_hash",
]

NONEMPTY_STRING_PATHS = [
    "run_id",
    "manifest_id",
    "experiment",
    "stage",
    "dataset.name",
    "dataset.scale",
    "query.query_id",
    "policy.policy_id",
    "context.context_id",
    "context.ctx_hash",
    "mode",
    "template.template_id",
    "template.alternative",
    "pg.version",
    "implementation.git_commit",
    "implementation.python_version",
    "implementation.planner_language",
]

NONNEGATIVE_NUMBER_PATHS = [
    "timing_ms.planning",
    "timing_ms.execution",
    "timing_ms.verification",
    "timing_ms.total",
    "artifact_cost.query_only_ms",
    "artifact_cost.validation_ms",
    "artifact_cost.build_ms",
    "artifact_cost.refresh_ms",
]

NONNEGATIVE_INT_PATHS = [
    "planner.generated_templates",
    "planner.rejected_templates",
    "planner.costed_templates",
    "runtime_audit.udf_calls",
    "runtime_audit.unauthorized_observations",
    "oracle_check.set_diff_left",
    "oracle_check.set_diff_right",
    "result.row_count",
    "pg_metrics.shared_read_blocks",
    "pg_metrics.shared_hit_blocks",
    "pg_metrics.temp_read_blocks",
    "pg_metrics.temp_written_blocks",
    "artifact_cost.storage_bytes",
]

COUNT_PATHS = [
    "counts.policy_evals",
    "counts.residual_checks",
    "counts.candidate_rows",
    "counts.authorized_rows",
    "counts.artifact_lookups",
    "counts.base_fetches",
]

COUNT_NULL_SEMANTICS = {
    "counts.policy_evals": (
        "null means the archived execution evidence did not expose a "
        "policy-bearing protected-relation node; no estimated fallback was "
        "substituted"
    ),
    "counts.residual_checks": (
        "null means residual-check executions were not directly observable "
        "for this run"
    ),
    "counts.candidate_rows": (
        "null means the candidate relation/cardinality was not directly "
        "counted or visible in EXPLAIN"
    ),
    "counts.authorized_rows": (
        "null means authorized output cardinality was not measured separately "
        "from the result row count"
    ),
    "counts.artifact_lookups": (
        "null means artifact lookup count was not observable for this run"
    ),
    "counts.base_fetches": (
        "null means base-relation fetches were not observable for this run"
    ),
}

# BEGIN PHASE_B_E8COST_ACCOUNTING_PROJECTION_SCHEMA_CONSTANTS
E8COST_ACCOUNTING_PROJECTION_SCHEMA = "e8cost_accounting_gate_projection_v2"
E8COST_ACCOUNTING_PROBE_SCHEMA = "e8cost_accounting_probe_v2"
E8COST_SHARED_PROBE_OWNER_SCHEMA = "e8cost_shared_postgres_probe_owner_v2"
E8COST_PROJECTION_OWNER_SCHEMA = "e8cost_accounting_projection_owner_v1"
E8COST_PROJECTION_INTEGRITY_SCHEMA = "e8cost_projection_integrity_v2"
E8COST_COMMON_ACCOUNTING_OBSERVATIONS_SCHEMA = (
    "e8cost_common_maintenance_storage_observations_v1"
)
E8COST_CASE_VALIDATION_OBSERVATION_SCHEMA = (
    "e8cost_case_validation_observation_v1"
)
E8COST_ACCOUNTING_MANIFEST_ID = "e8_cost_update_rate_v1"
E8COST_ACCOUNTING_V3_MANIFEST_ID = "e8_cost_update_rate_v1_taxonomy_v3"
E8COST_ACCOUNTING_QUERY_PATH = "workloads/e8/freshness_maintenance.sql"
E8COST_REQUIRED_WARMUP_REPETITIONS = 5
E8COST_REQUIRED_MEASURED_REPETITIONS = 10
E8COST_ACCOUNTING_Q_LEVELS = (1, 10, 100, 1000)
E8COST_ACCOUNTING_U_LEVELS = (
    (0.0, "U0pct"),
    (0.001, "U0_1pct"),
    (0.01, "U1pct"),
    (0.1, "U10pct"),
)
E8COST_SHARED_BODY_PROBE_IDS = (
    "barrier_explain_analyze_query",
    "auth_index_explain_analyze_query",
    "mav_explain_analyze_query",
    "hybrid_explain_analyze_query",
    "auth_index_validated_query",
    "mav_validated_query",
    "hybrid_validated_query",
)
E8COST_SHARED_BODY_PROBE_SPECS = {
    "barrier_explain_analyze_query": {
        "body_kind": "postgres_explain_analyze_query_body",
        "template_id": "barrier_filter_v1",
        "alternative": "BarrierFilter",
        "validated": False,
    },
    "auth_index_explain_analyze_query": {
        "body_kind": "postgres_explain_analyze_query_body",
        "template_id": "auth_index_enum_v1",
        "alternative": "AuthorizationIndexSeek",
        "validated": False,
    },
    "mav_explain_analyze_query": {
        "body_kind": "postgres_explain_analyze_query_body",
        "template_id": "mav_scan_v1",
        "alternative": "MaterializedAuthorizedViewScan",
        "validated": False,
    },
    "hybrid_explain_analyze_query": {
        "body_kind": "postgres_explain_analyze_query_body",
        "template_id": "hybrid_intersect_v1",
        "alternative": "HybridIndexIntersect",
        "validated": False,
    },
    "auth_index_validated_query": {
        "body_kind": "postgres_same_snapshot_validated_query_body",
        "template_id": "auth_index_enum_v1",
        "alternative": "AuthorizationIndexSeek",
        "validated": True,
    },
    "mav_validated_query": {
        "body_kind": "postgres_same_snapshot_validated_query_body",
        "template_id": "mav_scan_v1",
        "alternative": "MaterializedAuthorizedViewScan",
        "validated": True,
    },
    "hybrid_validated_query": {
        "body_kind": "postgres_same_snapshot_validated_query_body",
        "template_id": "hybrid_intersect_v1",
        "alternative": "HybridIndexIntersect",
        "validated": True,
    },
}
E8COST_COMMON_ACCOUNTING_OBSERVATION_IDS = (
    "auth_index_maintenance_storage",
    "mav_maintenance_storage",
)
E8COST_ACCOUNTING_FAMILY_SPECS = {
    "MAV-DASH": {
        "query_prefix": "mav_dash",
        "query_shape": "dashboard_repeated_authorized_count",
        "artifact_type": "mav",
        "contexts": 1000,
        "artifact_status": "pass",
        "contract_action": "execute",
        "expected_effect": "mav_amortization_sweep",
        "projection_action": "execute",
        "projection_reason": "observed_declared_q_u_accounting_minimum",
        "alternatives": (
            ("mav_scan_v1", "MaterializedAuthorizedViewScan"),
            ("barrier_filter_v1", "BarrierFilter"),
        ),
    },
    "AUTHIDX-SPARSE": {
        "query_prefix": "authidx_sparse",
        "query_shape": "sparse_cross_tenant_export",
        "artifact_type": "auth_idx",
        "contexts": 100000,
        "artifact_status": "pass",
        "contract_action": "execute",
        "expected_effect": "auth_index_sparse_sweep",
        "projection_action": "execute",
        "projection_reason": "observed_declared_q_u_accounting_minimum",
        "alternatives": (
            ("auth_index_enum_v1", "AuthorizationIndexSeek"),
            ("barrier_filter_v1", "BarrierFilter"),
        ),
    },
    "STALE-FALLBACK": {
        "query_prefix": "stale_fallback",
        "query_shape": "stale_membership_fallback",
        "artifact_type": "auth_idx",
        "contexts": 1000,
        "artifact_status": "stale",
        "contract_action": "fallback",
        "expected_effect": "stale_artifact_fallback_sweep",
        "projection_action": "fallback",
        "projection_reason": "metadata_stale_accounting_fallback_projection",
        "alternatives": (("barrier_filter_v1", "BarrierFilter"),),
    },
}


def _e8cost_accounting_projection_registry() -> dict[str, dict[str, Any]]:
    registry: dict[str, dict[str, Any]] = {}
    for q_value in E8COST_ACCOUNTING_Q_LEVELS:
        for u_value, u_label in E8COST_ACCOUNTING_U_LEVELS:
            for family, spec in E8COST_ACCOUNTING_FAMILY_SPECS.items():
                query_id = (
                    f"E8cost_{spec['query_prefix']}_Q{q_value}_{u_label}"
                )
                registry[query_id] = {
                    "family": family,
                    "Q": q_value,
                    "U": u_value,
                    "query_shape": spec["query_shape"],
                    "artifact_type": spec["artifact_type"],
                    "ttl_s": 3600,
                    "contexts": spec["contexts"],
                    "artifact_status": spec["artifact_status"],
                    "contract_action": spec["contract_action"],
                    "expected_effect": spec["expected_effect"],
                    "projection_action": spec["projection_action"],
                    "projection_reason": spec["projection_reason"],
                    "alternatives": spec["alternatives"],
                }
    if len(registry) != 48:
        raise AssertionError("E8-COST projection registry is not exact")
    return registry


E8COST_ACCOUNTING_PROJECTION_REGISTRY = (
    _e8cost_accounting_projection_registry()
)
E8COST_ACCOUNTING_PROJECTION_NULL_DIGEST_PATHS = frozenset(
    {
        "sql.emitted_sql_hash",
        "sql.normalized_sql_hash",
        "result.result_hash",
    }
)
E8COST_ACCOUNTING_PROJECTION_NULL_STRING_PATHS = frozenset(
    {"template.template_id", "template.alternative"}
)
E8COST_ACCOUNTING_PROJECTION_NULL_NUMBER_PATHS = frozenset(
    {
        "timing_ms.planning",
        "timing_ms.execution",
        "timing_ms.verification",
        "timing_ms.total",
        "artifact_cost.query_only_ms",
        "artifact_cost.validation_ms",
        "artifact_cost.build_ms",
        "artifact_cost.refresh_ms",
    }
)
E8COST_ACCOUNTING_PROJECTION_NULL_INT_PATHS = frozenset(
    {
        "planner.generated_templates",
        "planner.rejected_templates",
        "planner.costed_templates",
        "runtime_audit.udf_calls",
        "runtime_audit.unauthorized_observations",
        "oracle_check.set_diff_left",
        "oracle_check.set_diff_right",
        "result.row_count",
        "pg_metrics.shared_read_blocks",
        "pg_metrics.shared_hit_blocks",
        "pg_metrics.temp_read_blocks",
        "pg_metrics.temp_written_blocks",
        "artifact_cost.storage_bytes",
    }
)
# END PHASE_B_E8COST_ACCOUNTING_PROJECTION_SCHEMA_CONSTANTS
REQUIRED_CANDIDATE_FIELDS = [
    "template_id",
    "alternative",
    "accepted",
    "template_applicability",
    "rejection_reasons",
    "estimated_cost",
    "delivered_sigma",
]

V2_REQUIRED_CANDIDATE_FIELDS = [
    "template_id",
    "alternative",
    "accepted",
    "template_applicability",
    "rejection_reasons",
    "estimated_cost",
    "kappa_sem",
    "delivered_sigma",
    "certificate",
    "certificate_check",
    "pruned_by_dominance",
]


@dataclass(frozen=True)
class SchemaIssue:
    path: str
    message: str


@dataclass(frozen=True)
class NormalizedRunIdentity:
    """Canonical mode and role extracted from one versioned run record."""

    mode: str
    evaluation_role: str


def _normalize_static_verifier_template_witness_identity(
    record: Mapping[str, Any],
) -> NormalizedRunIdentity | None:
    """Validate the one non-evaluation pseudo-mode used by witness records."""

    mode = record.get("mode")
    if mode != STATIC_VERIFIER_TEMPLATE_WITNESS_MODE:
        return None
    if (
        record.get("manifest_id") != STATIC_VERIFIER_TEMPLATE_WITNESS_MANIFEST_ID
        or record.get("experiment") != "STATIC_VERIFIER"
        or record.get("stage") != "template_witness"
    ):
        raise ValueError(
            f"mode {STATIC_VERIFIER_TEMPLATE_WITNESS_MODE!r} is reserved for "
            "the static-verifier template-witness manifest"
        )

    schema_version = record.get("schema_version")
    if schema_version == PREVIOUS_RAW_SCHEMA_VERSION:
        if "evaluation_role" in record:
            raise ValueError("v2 static-verifier witness records must not contain evaluation_role")
        if record.get("baseline_class") != "production_safe":
            raise ValueError(
                "v2 static-verifier witness records require baseline_class "
                "'production_safe'"
            )
        evaluation_role = POLICY_ENFORCEMENT_ROLE
    elif schema_version == RAW_SCHEMA_VERSION:
        if "baseline_class" in record:
            raise ValueError("v3 static-verifier witness records must not contain baseline_class")
        if record.get("evaluation_role") != POLICY_ENFORCEMENT_ROLE:
            raise ValueError(
                "v3 static-verifier witness records require evaluation_role "
                f"{POLICY_ENFORCEMENT_ROLE!r}"
            )
        evaluation_role = POLICY_ENFORCEMENT_ROLE
    else:
        raise ValueError(
            "static-verifier witness records require schema_version "
            f"{PREVIOUS_RAW_SCHEMA_VERSION!r} or {RAW_SCHEMA_VERSION!r}"
        )

    return NormalizedRunIdentity(
        mode=STATIC_VERIFIER_TEMPLATE_WITNESS_MODE,
        evaluation_role=evaluation_role,
    )


def normalize_run_identity(
    record: Mapping[str, Any],
    *,
    mode_registry: Mapping[str, ModeSpec] | None = None,
) -> NormalizedRunIdentity:
    """Validate the versioned identity fields and return canonical values."""

    schema_version = record.get("schema_version")
    mode = record.get("mode")
    if not isinstance(mode, str) or not mode:
        raise ValueError("mode is missing or invalid")

    static_witness_identity = _normalize_static_verifier_template_witness_identity(
        record
    )
    if static_witness_identity is not None:
        return static_witness_identity

    if schema_version in LEGACY_RAW_SCHEMA_VERSIONS:
        if "evaluation_role" in record:
            raise ValueError("v1/v2 records must not contain evaluation_role")
        if "baseline_class" not in record:
            raise ValueError("v1/v2 records require baseline_class")
        if mode in {ADMISSION_FIRST_MODE, ADMISSION_FIRST_NO_DOMINANCE_MODE}:
            raise ValueError("v1/v2 records must use the legacy mode id")
        role = record.get("baseline_class")
        if role not in ALLOWED_BASELINE_CLASSES:
            raise ValueError(f"invalid legacy baseline_class {role!r}")
    elif schema_version == RAW_SCHEMA_VERSION:
        if "baseline_class" in record:
            raise ValueError("v3 records must not contain baseline_class")
        if "evaluation_role" not in record:
            raise ValueError("v3 records require evaluation_role")
        if mode in {
            LEGACY_CONTRACT_AWARE_MODE,
            LEGACY_CONTRACT_AWARE_NO_DOMINANCE_MODE,
        }:
            raise ValueError("v3 records must use the canonical mode id")
        role = record.get("evaluation_role")
        if role not in ALLOWED_EVALUATION_ROLES:
            raise ValueError(f"invalid canonical evaluation_role {role!r}")
    else:
        raise ValueError(f"unsupported schema_version {schema_version!r}")

    identity = NormalizedRunIdentity(
        mode=normalize_mode_id(mode),
        evaluation_role=normalize_evaluation_role(role),
    )
    if mode_registry is not None:
        spec = mode_registry.get(identity.mode)
        if spec is None:
            raise ValueError(f"mode {identity.mode!r} is absent from the registry")
        if spec.evaluation_role != identity.evaluation_role:
            raise ValueError(
                f"mode {identity.mode!r} requires evaluation_role "
                f"{spec.evaluation_role!r}, got {identity.evaluation_role!r}"
            )
    return identity


def _get_path(record: Mapping[str, Any], path: str) -> Any:
    cur: Any = record
    for part in path.split("."):
        if not isinstance(cur, Mapping) or part not in cur:
            raise KeyError(path)
        cur = cur[part]
    return cur


def _require_paths(
    record: Mapping[str, Any], paths: Iterable[str]
) -> List[SchemaIssue]:
    issues: List[SchemaIssue] = []
    for path in paths:
        try:
            _get_path(record, path)
        except KeyError:
            issues.append(SchemaIssue(path=path, message="missing required field"))
    return issues


def _path_exists(record: Mapping[str, Any], path: str) -> bool:
    try:
        _get_path(record, path)
    except KeyError:
        return False
    return True


def _sha256_issue(record: Mapping[str, Any], path: str) -> SchemaIssue | None:
    if not _path_exists(record, path):
        return None
    value = _get_path(record, path)
    if not isinstance(value, str) or not SHA256_RE.match(value):
        return SchemaIssue(path=path, message="must be a sha256: digest")
    return None


def _nonempty_string_issue(record: Mapping[str, Any], path: str) -> SchemaIssue | None:
    if not _path_exists(record, path):
        return None
    value = _get_path(record, path)
    if not isinstance(value, str) or not value:
        return SchemaIssue(path=path, message="must be a non-empty string")
    return None


def _nonnegative_number_issue(
    record: Mapping[str, Any], path: str
) -> SchemaIssue | None:
    if not _path_exists(record, path):
        return None
    value = _get_path(record, path)
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
        return SchemaIssue(path=path, message="must be a non-negative number")
    return None


def _nonnegative_int_issue(record: Mapping[str, Any], path: str) -> SchemaIssue | None:
    if not _path_exists(record, path):
        return None
    value = _get_path(record, path)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return SchemaIssue(path=path, message="must be a non-negative integer")
    return None


def _nullable_nonnegative_int_issue(
    record: Mapping[str, Any],
    path: str,
    *,
    allow_null: bool,
) -> SchemaIssue | None:
    if not _path_exists(record, path):
        return None
    value = _get_path(record, path)
    if allow_null and value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        message = "must be a non-negative integer"
        if allow_null:
            message += " or null when the count is not directly observable"
        return SchemaIssue(path=path, message=message)
    return None


def _uses_v2_extensions(record: Mapping[str, Any]) -> bool:
    return record.get("schema_version") in {
        PREVIOUS_RAW_SCHEMA_VERSION,
        RAW_SCHEMA_VERSION,
    }


def _is_v3(record: Mapping[str, Any]) -> bool:
    return record.get("schema_version") == RAW_SCHEMA_VERSION


def _is_certificate_suppressed_diagnostic(candidate: Mapping[str, Any]) -> bool:
    diagnostics = candidate.get("diagnostics")
    if not isinstance(diagnostics, Mapping):
        return False
    disabled_components = diagnostics.get("disabled_components")
    if (
        diagnostics.get("diagnostic_ablation") is not True
        or diagnostics.get("certificate_suppressed") is not True
        or isinstance(disabled_components, (str, bytes))
        or not isinstance(disabled_components, list)
        or not disabled_components
    ):
        return False
    return all(str(item) in DISABLED_COMPONENTS for item in disabled_components)


# BEGIN PHASE_B_E8COST_ACCOUNTING_PROJECTION_VALIDATOR
def _e8cost_accounting_integrity_digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _claims_e8cost_accounting_projection(record: Mapping[str, Any]) -> bool:
    evidence = record.get("evidence")
    evidence_claim = isinstance(evidence, Mapping) and (
        evidence.get("schema") == E8COST_ACCOUNTING_PROJECTION_SCHEMA
        or evidence.get("role") == "accounting_gate_projection"
    )
    try:
        canonical_mode = normalize_mode_id(record.get("mode"))
    except ValueError:
        canonical_mode = None
    outer_claim = (
        record.get("experiment") == "E8"
        and record.get("stage") == "artifact_cost_update_rate"
        and canonical_mode == ADMISSION_FIRST_MODE
        and record.get("status") != "correctness_pass"
    )
    return bool(evidence_claim or outer_claim)


def _validate_e8cost_accounting_projection(
    record: Mapping[str, Any],
) -> tuple[bool, List[SchemaIssue]]:
    """Validate the finite E8-COST nonexecution accounting family."""

    branch = _claims_e8cost_accounting_projection(record)
    issues: List[SchemaIssue] = []
    if not branch:
        return False, issues

    def fixed(path: str, expected: Any) -> None:
        try:
            value = _get_path(record, path)
        except KeyError:
            issues.append(
                SchemaIssue(path=path, message="missing E8-COST projection field")
            )
            return
        exact_type = expected is not None and value.__class__ is not expected.__class__
        if value != expected or exact_type:
            issues.append(
                SchemaIssue(
                    path=path,
                    message=f"must equal {expected!r} for E8-COST projection",
                )
            )

    def exact_mapping(path: str, fields: frozenset[str]) -> Mapping[str, Any]:
        if path == "$":
            value = record
        else:
            try:
                value = _get_path(record, path)
            except KeyError:
                issues.append(
                    SchemaIssue(
                        path=path,
                        message="missing E8-COST projection mapping",
                    )
                )
                return {}
        if value.__class__ is not dict:
            issues.append(SchemaIssue(path=path, message="must be an exact mapping"))
            return {}
        actual = frozenset(value)
        if actual != fields:
            issues.append(
                SchemaIssue(
                    path=path,
                    message=(
                        "must have exact E8-COST projection fields; "
                        f"missing={sorted(fields - actual)!r}, "
                        f"extra={sorted(actual - fields)!r}"
                    ),
                )
            )
        return value

    def nonnegative_number(
        path: str,
        value: Any,
        *,
        exact_int: bool = False,
    ) -> None:
        if exact_int:
            valid = value.__class__ is int and value >= 0
        else:
            valid = value.__class__ is float and value >= 0.0
        if not valid:
            kind = "integer" if exact_int else "float"
            issues.append(
                SchemaIssue(path=path, message=f"must be a non-negative exact {kind}")
            )

    authority_fields = frozenset(
        {
            "integrity_only",
            "production_planner_authority",
            "selection_authority",
            "execution_authority",
            "result_evidence",
            "f3_selection_authority",
        }
    )
    authority_values = (
        ("integrity_only", True),
        ("production_planner_authority", False),
        ("selection_authority", False),
        ("execution_authority", False),
        ("result_evidence", False),
        ("f3_selection_authority", False),
    )

    identity_fields = V3_IDENTITY_FIELDS if _is_v3(record) else LEGACY_IDENTITY_FIELDS
    exact_mapping(
        "$",
        frozenset(REQUIRED_TOP_LEVEL)
        | frozenset(identity_fields)
        | frozenset({"evidence", "measurement"}),
    )
    for forbidden in ("correctness_evidence", "e8b_maintenance_case"):
        if forbidden in record:
            issues.append(
                SchemaIssue(
                    path=forbidden,
                    message="is forbidden on E8-COST accounting projections",
                )
            )

    identity_expectations = (
        (("evaluation_role", POLICY_ENFORCEMENT_ROLE),)
        if _is_v3(record)
        else (("baseline_class", "production_safe"),)
    )
    mode_id = ADMISSION_FIRST_MODE if _is_v3(record) else LEGACY_CONTRACT_AWARE_MODE
    allowed_manifest_ids = (
        {E8COST_ACCOUNTING_MANIFEST_ID, E8COST_ACCOUNTING_V3_MANIFEST_ID}
        if _is_v3(record)
        else {E8COST_ACCOUNTING_MANIFEST_ID}
    )
    manifest_id = record.get("manifest_id")
    if manifest_id not in allowed_manifest_ids:
        issues.append(
            SchemaIssue(
                path="manifest_id",
                message=(
                    "must identify the legacy or taxonomy-v3 E8-COST manifest"
                ),
            )
        )
    projection_schema_version = (
        RAW_SCHEMA_VERSION if _is_v3(record) else PREVIOUS_RAW_SCHEMA_VERSION
    )
    for path, expected in (
        ("schema_version", projection_schema_version),
        ("experiment", "E8"),
        ("stage", "artifact_cost_update_rate"),
        ("run_kind", "normal_mode"),
        ("dataset.name", "synthetic_saas"),
        ("dataset.scale", "1e6"),
        ("dataset.seed", 47),
        ("query.path", E8COST_ACCOUNTING_QUERY_PATH),
        ("query.params", {}),
        ("policy.policy_id", "tenant_group"),
        ("policy.policy_version", 0),
        ("mode", mode_id),
        ("template.template_id", None),
        ("template.alternative", None),
        ("template.role", "no_selected_template_accounting_projection"),
        ("template.selection_authority", False),
        ("template.execution_authority", False),
        ("template_applicability.status", "policy_not_applicable"),
        (
            "template_applicability.reason",
            "accounting_projection_has_no_selected_template",
        ),
        ("template_applicability.selection_authority", False),
        ("template_oracle.eligible_for_template_oracle", False),
        (
            "template_oracle.template_oracle_exclusion_reason",
            "E8-COST_accounting_projection_not_selection_evidence",
        ),
        ("pg.gucs", {"jit": "off", "max_parallel_workers_per_gather": "0"}),
        ("versions.policy", {"tenant_group": 0}),
        ("versions.membership", {"group_membership": 0}),
        ("versions.base", {"document": 0}),
        ("versions.artifacts", {}),
        (
            "versions.trusted_state",
            {
                "shared_body_probe_inventory_observed": 1,
                "common_accounting_observations_observed": 1,
                "case_validation_observation_observed": 1,
                "planner_selection_observed": 0,
                "selected_body_execution": 0,
                "result_equality_observed": 0,
            },
        ),
        ("planner.level", None),
        ("planner.disabled_components", []),
        ("planner.planning_time_ms", None),
        ("planner.generated_templates", None),
        ("planner.rejected_templates", None),
        ("planner.costed_templates", None),
        ("planner.rejection_reasons", {}),
        ("planner.chosen_estimated_cost", None),
        ("planner.chosen_rank_vs_template_oracle", None),
        ("planner.choice_reason", None),
        ("planner.candidates", []),
        ("planner.delivered_sigma", {}),
        ("planner.local_feature_vector", {}),
        ("planner.parent_requirement_vector", {}),
        ("planner.planner_run_observed", False),
        ("planner.selection_authority", False),
        ("planner.execution_authority", False),
        ("planner.f3_selection_authority", False),
        ("static_verifier.status", "not_executed"),
        ("static_verifier.plan_hash", None),
        ("static_verifier.explain_path", None),
        ("static_verifier.reasons", []),
        ("static_verifier.evidence_kind", "accounting_projection_no_plan"),
        ("artifact_validation.status", "not_applicable"),
        ("artifact_validation.action", "not_applicable"),
        ("artifact_validation.expected_action", "not_applicable"),
        ("artifact_validation.failure_sqlstate", None),
        ("artifact_validation.failure_symbol", None),
        ("artifact_validation.same_snapshot", False),
        ("artifact_validation.isolation_level", None),
        ("artifact_validation.record_promotion_eligible", False),
        ("artifact_validation.selection_authority", False),
        ("artifact_validation.execution_authority", False),
        ("runtime_audit.status", "not_executed"),
        ("runtime_audit.audit_path", None),
        ("runtime_audit.udf_calls", None),
        ("runtime_audit.unauthorized_observations", None),
        ("runtime_audit.client_errors", None),
        ("runtime_audit.client_notices", None),
        ("runtime_audit.selected_body_execution", False),
        ("sql.emitted_sql_path", None),
        ("sql.emitted_sql_hash", None),
        ("sql.normalized_sql_hash", None),
        ("sql.execution_sql_source", "not_executed"),
        ("sql.measurement_promotion", False),
        ("sql.selection_authority", False),
        ("sql.execution_authority", False),
        ("sql.selected_body_execution", False),
        ("oracle_check.status", "not_applicable"),
        ("oracle_check.oracle_kind", "not_applicable"),
        ("oracle_check.set_diff_left", None),
        ("oracle_check.set_diff_right", None),
        ("oracle_check.known_invalid_accepted", False),
        ("oracle_check.known_valid_rejected", False),
        ("timing_ms.planning", None),
        ("timing_ms.execution", None),
        ("timing_ms.verification", None),
        ("timing_ms.total", None),
        ("result.row_count", None),
        ("result.result_hash", None),
        ("result.selection_authority", False),
        ("result.execution_authority", False),
        ("result.result_evidence", False),
        ("pg_metrics.shared_read_blocks", None),
        ("pg_metrics.shared_hit_blocks", None),
        ("pg_metrics.temp_read_blocks", None),
        ("pg_metrics.temp_written_blocks", None),
        ("counts.policy_evals", None),
        ("counts.residual_checks", None),
        ("counts.candidate_rows", None),
        ("counts.authorized_rows", None),
        ("counts.artifact_lookups", None),
        ("counts.base_fetches", None),
        ("counts.invalidation_count", None),
        ("artifact_cost.query_only_ms", None),
        ("artifact_cost.validation_ms", None),
        ("artifact_cost.build_ms", None),
        ("artifact_cost.refresh_ms", None),
        ("artifact_cost.refresh_unit_ms", None),
        ("artifact_cost.storage_bytes", None),
        ("artifact_cost.indexes_built", []),
        ("artifact_cost.artifact_key_encoding_version", "not_applicable"),
        ("artifact_cost.amortization_model", "not_applicable"),
        ("artifact_cost.Q", None),
        ("artifact_cost.U", None),
        ("artifact_cost.update_rate", None),
        ("artifact_cost.invalidated_rows", None),
        ("artifact_cost.table_pages", None),
        ("artifact_cost.index_pages", None),
        ("artifact_cost.maintenance_ms_total", None),
        ("artifact_cost.fallback_ms", None),
        ("artifact_cost.refresh_policy", None),
        ("artifact_cost.amortized_latency_ms", None),
        ("status", "not_executed"),
        ("failure", None),
        ("evidence.schema", E8COST_ACCOUNTING_PROJECTION_SCHEMA),
        ("evidence.role", "accounting_gate_projection"),
        ("evidence.promotion_eligible", False),
        ("evidence.selection_authority", False),
        ("evidence.execution_authority", False),
        ("evidence.result_evidence", False),
        ("evidence.f3_selection_authority", False),
        ("evidence.planner_choice_evidence", False),
        ("evidence.integrity_only", True),
        *identity_expectations,
    ):
        fixed(path, expected)

    exact_mapping("dataset", frozenset({"name", "scale", "seed"}))
    exact_mapping("query", frozenset({"query_id", "path", "params"}))
    exact_mapping(
        "policy",
        frozenset({"policy_id", "policy_version", "policy_sql_manifest_hash"}),
    )
    exact_mapping("context", frozenset({"context_id", "ctx_hash"}))
    exact_mapping(
        "template",
        frozenset(
            {
                "template_id",
                "alternative",
                "role",
                "selection_authority",
                "execution_authority",
            }
        ),
    )
    exact_mapping(
        "template_applicability",
        frozenset({"status", "reason", "selection_authority"}),
    )
    exact_mapping(
        "template_oracle",
        frozenset(
            {
                "eligible_for_template_oracle",
                "template_oracle_exclusion_reason",
            }
        ),
    )
    exact_mapping("pg", frozenset({"version", "gucs"}))
    exact_mapping(
        "versions",
        frozenset(
            {"policy", "membership", "context", "trusted_state", "base", "artifacts"}
        ),
    )
    exact_mapping(
        "planner",
        frozenset(
            {
                "level",
                "disabled_components",
                "planning_time_ms",
                "generated_templates",
                "rejected_templates",
                "costed_templates",
                "rejection_reasons",
                "chosen_estimated_cost",
                "chosen_rank_vs_template_oracle",
                "choice_reason",
                "candidates",
                "delivered_sigma",
                "local_feature_vector",
                "parent_requirement_vector",
                "planner_run_observed",
                "selection_authority",
                "execution_authority",
                "f3_selection_authority",
            }
        ),
    )
    exact_mapping(
        "static_verifier",
        frozenset({"status", "plan_hash", "explain_path", "reasons", "evidence_kind"}),
    )
    exact_mapping(
        "artifact_validation",
        frozenset(
            {
                "status",
                "action",
                "expected_action",
                "failure_sqlstate",
                "failure_symbol",
                "same_snapshot",
                "isolation_level",
                "record_promotion_eligible",
                "selection_authority",
                "execution_authority",
            }
        ),
    )
    exact_mapping(
        "runtime_audit",
        frozenset(
            {
                "status",
                "audit_path",
                "udf_calls",
                "unauthorized_observations",
                "client_errors",
                "client_notices",
                "selected_body_execution",
            }
        ),
    )
    exact_mapping(
        "sql",
        frozenset(
            {
                "emitted_sql_path",
                "emitted_sql_hash",
                "normalized_sql_hash",
                "execution_sql_source",
                "measurement_promotion",
                "selection_authority",
                "execution_authority",
                "selected_body_execution",
            }
        ),
    )
    exact_mapping(
        "oracle_check",
        frozenset(
            {
                "status",
                "oracle_kind",
                "set_diff_left",
                "set_diff_right",
                "known_invalid_accepted",
                "known_valid_rejected",
            }
        ),
    )
    exact_mapping("timing_ms", frozenset({"planning", "execution", "verification", "total"}))
    exact_mapping(
        "result",
        frozenset(
            {
                "row_count",
                "result_hash",
                "selection_authority",
                "execution_authority",
                "result_evidence",
            }
        ),
    )
    exact_mapping(
        "pg_metrics",
        frozenset(
            {"shared_read_blocks", "shared_hit_blocks", "temp_read_blocks", "temp_written_blocks"}
        ),
    )
    exact_mapping(
        "counts",
        frozenset(
            {
                "policy_evals",
                "residual_checks",
                "candidate_rows",
                "authorized_rows",
                "artifact_lookups",
                "base_fetches",
                "invalidation_count",
            }
        ),
    )
    exact_mapping(
        "artifact_cost",
        frozenset(
            {
                "query_only_ms",
                "validation_ms",
                "build_ms",
                "refresh_ms",
                "refresh_unit_ms",
                "storage_bytes",
                "indexes_built",
                "artifact_key_encoding_version",
                "amortization_model",
                "Q",
                "U",
                "update_rate",
                "invalidated_rows",
                "table_pages",
                "index_pages",
                "maintenance_ms_total",
                "fallback_ms",
                "refresh_policy",
                "amortized_latency_ms",
                "accounting_probe",
            }
        ),
    )
    exact_mapping(
        "implementation",
        frozenset(
            {"git_commit", "docker_image_digest", "python_version", "planner_language"}
        ),
    )
    exact_mapping(
        "evidence",
        frozenset(
            {
                "schema",
                "role",
                "promotion_eligible",
                "selection_authority",
                "execution_authority",
                "result_evidence",
                "f3_selection_authority",
                "planner_choice_evidence",
                "integrity_only",
                "shared_probe_owner_digest",
                "projection_owner_digest",
                "projection_integrity_digest",
            }
        ),
    )
    measurement = exact_mapping(
        "measurement",
        frozenset(
            {"phase", "iteration", "warmup_repetitions", "measured_repetitions"}
        ),
    )

    query_id = record.get("query", {}).get("query_id")
    identity = E8COST_ACCOUNTING_PROJECTION_REGISTRY.get(query_id)
    if identity is None:
        issues.append(
            SchemaIssue(
                path="query.query_id",
                message="must be one of the exact 48 E8-COST projection identities",
            )
        )

    phase = measurement.get("phase")
    iteration = measurement.get("iteration")
    warmup = measurement.get("warmup_repetitions")
    measured = measurement.get("measured_repetitions")
    if phase not in {"warmup", "measured"}:
        issues.append(SchemaIssue(path="measurement.phase", message="invalid repetition phase"))
    if warmup.__class__ is not int or warmup != E8COST_REQUIRED_WARMUP_REPETITIONS:
        issues.append(
            SchemaIssue(
                path="measurement.warmup_repetitions",
                message="must equal the exact five-repetition warmup protocol",
            )
        )
    if measured.__class__ is not int or measured != E8COST_REQUIRED_MEASURED_REPETITIONS:
        issues.append(
            SchemaIssue(
                path="measurement.measured_repetitions",
                message="must equal the exact ten-repetition measured protocol",
            )
        )
    maximum_iteration = {
        "warmup": E8COST_REQUIRED_WARMUP_REPETITIONS,
        "measured": E8COST_REQUIRED_MEASURED_REPETITIONS,
    }.get(phase)
    if (
        iteration.__class__ is not int
        or maximum_iteration is None
        or not 1 <= iteration <= maximum_iteration
    ):
        issues.append(
            SchemaIssue(
                path="measurement.iteration",
                message="must be in the exact phase-specific repetition range",
            )
        )
    if maximum_iteration is not None and iteration.__class__ is int:
        suffix = "warmup" if phase == "warmup" else "rep"
        mode_token = "admission_first" if _is_v3(record) else "contract_aware"
        fixed(
            "run_id",
            f"E8b_{query_id}_{mode_token}_accounting_projection_{suffix}{iteration:02d}",
        )

    context = record.get("context", {})
    context_id = context.get("context_id")
    fixed("versions.context", {context_id: 0})

    def check_authority(value: Mapping[str, Any], prefix: str) -> None:
        for field, expected in authority_values:
            actual = value.get(field)
            if actual != expected or actual.__class__ is not expected.__class__:
                issues.append(
                    SchemaIssue(
                        path=f"{prefix}.{field}",
                        message="must carry no planner, selection, execution, result, or F3 authority",
                    )
                )

    accounting = exact_mapping(
        "artifact_cost.accounting_probe",
        frozenset(
            {
                "schema",
                "evidence_role",
                "declared_inputs",
                "body_probe_inventory",
                "common_accounting_observations",
                "case_validation_observation",
                "shared_probe_owner",
                "projection_owner",
                "accounting_alternatives",
                "observed_accounting_minimum",
                "projection_integrity",
            }
        )
        | authority_fields,
    )
    fixed("artifact_cost.accounting_probe.schema", E8COST_ACCOUNTING_PROBE_SCHEMA)
    fixed("artifact_cost.accounting_probe.evidence_role", "accounting_probe_only")
    check_authority(accounting, "artifact_cost.accounting_probe")

    declared_input_fields = frozenset(
        {
            "family",
            "Q",
            "U",
            "query_shape",
            "artifact_type",
            "ttl_s",
            "contexts",
            "artifact_status",
            "contract_action",
            "expected_effect",
        }
    )
    exact_mapping(
        "artifact_cost.accounting_probe.declared_inputs",
        declared_input_fields,
    )
    if identity is not None:
        for field in declared_input_fields:
            fixed(
                f"artifact_cost.accounting_probe.declared_inputs.{field}",
                identity[field],
            )

    body_probe_inventory = accounting.get("body_probe_inventory")
    body_probe_by_id: dict[str, Mapping[str, Any]] = {}
    if (
        body_probe_inventory.__class__ is not list
        or len(body_probe_inventory) != len(E8COST_SHARED_BODY_PROBE_IDS)
    ):
        issues.append(
            SchemaIssue(
                path="artifact_cost.accounting_probe.body_probe_inventory",
                message="must be the exact ordered seven-body PostgreSQL inventory",
            )
        )
        body_probe_inventory = []
    body_probe_fields = frozenset(
        {
            "body_probe_id",
            "body_kind",
            "template_id",
            "alternative",
            "planning_ms",
            "execution_ms",
            "total_ms",
            "row_count",
            "validation",
            "probe_body_execution_count",
            "selected_body_execution",
            "ownership",
        }
    ) | authority_fields
    validation_fields = frozenset(
        {
            "status",
            "failure_sqlstate",
            "failure_symbol",
            "elapsed_ms",
            "same_snapshot",
            "isolation_level",
        }
    )
    for index, expected_probe_id in enumerate(E8COST_SHARED_BODY_PROBE_IDS):
        if index >= len(body_probe_inventory):
            break
        body_probe = body_probe_inventory[index]
        prefix = f"artifact_cost.accounting_probe.body_probe_inventory[{index}]"
        if body_probe.__class__ is not dict:
            issues.append(
                SchemaIssue(path=prefix, message="must be an exact body-probe mapping")
            )
            continue
        if frozenset(body_probe) != body_probe_fields:
            issues.append(
                SchemaIssue(path=prefix, message="must have exact body-probe fields")
            )
        if body_probe.get("body_probe_id") != expected_probe_id:
            issues.append(
                SchemaIssue(
                    path=f"{prefix}.body_probe_id",
                    message="body-probe order or identity changed",
                )
            )
        body_probe_by_id[str(body_probe.get("body_probe_id"))] = body_probe
        spec = E8COST_SHARED_BODY_PROBE_SPECS[expected_probe_id]
        for field in ("body_kind", "template_id", "alternative"):
            expected = spec[field]
            actual = body_probe.get(field)
            if actual != expected or actual.__class__ is not expected.__class__:
                issues.append(
                    SchemaIssue(path=f"{prefix}.{field}", message="body identity changed")
                )
        for field in ("planning_ms", "execution_ms", "total_ms"):
            nonnegative_number(f"{prefix}.{field}", body_probe.get(field))
        planning = body_probe.get("planning_ms")
        execution = body_probe.get("execution_ms")
        total = body_probe.get("total_ms")
        if (
            planning.__class__ is float
            and execution.__class__ is float
            and total.__class__ is float
            and total != planning + execution
        ):
            issues.append(
                SchemaIssue(
                    path=f"{prefix}.total_ms",
                    message="must equal the one body's planning plus execution time",
                )
            )
        for field, expected in (
            ("probe_body_execution_count", 1),
            ("selected_body_execution", False),
            ("ownership", "shared_postgres_probe_inventory"),
        ):
            actual = body_probe.get(field)
            if actual != expected or actual.__class__ is not expected.__class__:
                issues.append(
                    SchemaIssue(path=f"{prefix}.{field}", message="body-probe contract changed")
                )
        check_authority(body_probe, prefix)
        if spec["validated"]:
            row_count = body_probe.get("row_count")
            if row_count.__class__ is not int or row_count < 0:
                issues.append(
                    SchemaIssue(
                        path=f"{prefix}.row_count",
                        message="validated body must carry a non-negative exact row count",
                    )
                )
            validation = body_probe.get("validation")
            if validation.__class__ is not dict:
                issues.append(
                    SchemaIssue(
                        path=f"{prefix}.validation",
                        message="validated body must carry exact validation evidence",
                    )
                )
                validation = {}
            elif frozenset(validation) != validation_fields:
                issues.append(
                    SchemaIssue(
                        path=f"{prefix}.validation",
                        message="validated body must carry exact validation fields",
                    )
                )
            for field, expected in (
                ("status", "pass"),
                ("failure_sqlstate", None),
                ("failure_symbol", None),
                ("same_snapshot", True),
                ("isolation_level", "repeatable_read"),
            ):
                actual = validation.get(field)
                exact_type = expected is not None and actual.__class__ is not expected.__class__
                if actual != expected or exact_type:
                    issues.append(
                        SchemaIssue(
                            path=f"{prefix}.validation.{field}",
                            message="validated shared body contract changed",
                        )
                    )
            nonnegative_number(
                f"{prefix}.validation.elapsed_ms",
                validation.get("elapsed_ms"),
            )
        else:
            for field in ("row_count", "validation"):
                if body_probe.get(field) is not None:
                    issues.append(
                        SchemaIssue(
                            path=f"{prefix}.{field}",
                            message="EXPLAIN ANALYZE body must not claim validation evidence",
                        )
                    )

    common = exact_mapping(
        "artifact_cost.accounting_probe.common_accounting_observations",
        frozenset(
            {
                "schema",
                "ownership",
                "selected_body_execution",
                "observations",
            }
        )
        | authority_fields,
    )
    fixed(
        "artifact_cost.accounting_probe.common_accounting_observations.schema",
        E8COST_COMMON_ACCOUNTING_OBSERVATIONS_SCHEMA,
    )
    fixed(
        "artifact_cost.accounting_probe.common_accounting_observations.ownership",
        "shared_postgres_accounting_observations",
    )
    fixed(
        "artifact_cost.accounting_probe.common_accounting_observations.selected_body_execution",
        False,
    )
    check_authority(
        common,
        "artifact_cost.accounting_probe.common_accounting_observations",
    )
    common_observations = common.get("observations")
    common_by_id: dict[str, Mapping[str, Any]] = {}
    if (
        common_observations.__class__ is not list
        or len(common_observations) != len(E8COST_COMMON_ACCOUNTING_OBSERVATION_IDS)
    ):
        issues.append(
            SchemaIssue(
                path="artifact_cost.accounting_probe.common_accounting_observations.observations",
                message="must be the exact ordered maintenance/storage observation inventory",
            )
        )
        common_observations = []
    common_observation_fields = frozenset(
        {
            "observation_id",
            "observation_kind",
            "artifact_kind",
            "build_ms",
            "refresh_ms",
            "storage_bytes",
            "build_body_execution_count",
            "refresh_body_execution_count",
            "storage_observation_count",
            "selected_body_execution",
            "ownership",
        }
    ) | authority_fields
    for index, expected_observation_id in enumerate(
        E8COST_COMMON_ACCOUNTING_OBSERVATION_IDS
    ):
        if index >= len(common_observations):
            break
        observation = common_observations[index]
        prefix = (
            "artifact_cost.accounting_probe.common_accounting_observations."
            f"observations[{index}]"
        )
        if observation.__class__ is not dict:
            issues.append(
                SchemaIssue(path=prefix, message="must be an exact common observation")
            )
            continue
        if frozenset(observation) != common_observation_fields:
            issues.append(
                SchemaIssue(path=prefix, message="must have exact common-observation fields")
            )
        if observation.get("observation_id") != expected_observation_id:
            issues.append(
                SchemaIssue(
                    path=f"{prefix}.observation_id",
                    message="common-observation order or identity changed",
                )
            )
        common_by_id[str(observation.get("observation_id"))] = observation
        expected_artifact_kind = (
            "auth_idx"
            if expected_observation_id == "auth_index_maintenance_storage"
            else "mav"
        )
        for field, expected in (
            ("observation_kind", "postgres_maintenance_storage_observation"),
            ("artifact_kind", expected_artifact_kind),
            ("build_body_execution_count", 1),
            ("refresh_body_execution_count", 1),
            ("storage_observation_count", 1),
            ("selected_body_execution", False),
            ("ownership", "shared_postgres_accounting_observations"),
        ):
            actual = observation.get(field)
            if actual != expected or actual.__class__ is not expected.__class__:
                issues.append(
                    SchemaIssue(path=f"{prefix}.{field}", message="common observation changed")
                )
        for field in ("build_ms", "refresh_ms"):
            nonnegative_number(f"{prefix}.{field}", observation.get(field))
        nonnegative_number(
            f"{prefix}.storage_bytes",
            observation.get("storage_bytes"),
            exact_int=True,
        )
        check_authority(observation, prefix)

    case_validation = exact_mapping(
        "artifact_cost.accounting_probe.case_validation_observation",
        frozenset(
            {
                "schema",
                "observation_id",
                "case_query_id",
                "status",
                "failure_sqlstate",
                "failure_symbol",
                "elapsed_ms",
                "same_snapshot",
                "isolation_level",
                "probe_body_execution_count",
                "selected_body_execution",
                "ownership",
            }
        )
        | authority_fields,
    )
    for path, expected in (
        (
            "artifact_cost.accounting_probe.case_validation_observation.schema",
            E8COST_CASE_VALIDATION_OBSERVATION_SCHEMA,
        ),
        (
            "artifact_cost.accounting_probe.case_validation_observation.observation_id",
            "case_specific_artifact_validation",
        ),
        (
            "artifact_cost.accounting_probe.case_validation_observation.case_query_id",
            query_id,
        ),
        (
            "artifact_cost.accounting_probe.case_validation_observation.same_snapshot",
            True,
        ),
        (
            "artifact_cost.accounting_probe.case_validation_observation.isolation_level",
            "repeatable_read",
        ),
        (
            "artifact_cost.accounting_probe.case_validation_observation.probe_body_execution_count",
            1,
        ),
        (
            "artifact_cost.accounting_probe.case_validation_observation.selected_body_execution",
            False,
        ),
        (
            "artifact_cost.accounting_probe.case_validation_observation.ownership",
            "case_specific_accounting_validation_observation",
        ),
    ):
        fixed(path, expected)
    if identity is not None and identity["artifact_status"] == "stale":
        expected_validation = (
            ("status", "fail"),
            ("failure_sqlstate", "P8A01"),
            ("failure_symbol", "CAPRLS_ARTIFACT_STALE"),
        )
    else:
        expected_validation = (
            ("status", "pass"),
            ("failure_sqlstate", None),
            ("failure_symbol", None),
        )
    for field, expected in expected_validation:
        fixed(
            f"artifact_cost.accounting_probe.case_validation_observation.{field}",
            expected,
        )
    nonnegative_number(
        "artifact_cost.accounting_probe.case_validation_observation.elapsed_ms",
        case_validation.get("elapsed_ms"),
    )
    check_authority(
        case_validation,
        "artifact_cost.accounting_probe.case_validation_observation",
    )

    shared_owner = exact_mapping(
        "artifact_cost.accounting_probe.shared_probe_owner",
        frozenset(
            {
                "schema",
                "role",
                "manifest",
                "repetition",
                "postgres_identity",
                "body_probe_inventory_digest",
                "common_accounting_observations_digest",
                "integrity_digest",
            }
        )
        | authority_fields,
    )
    fixed(
        "artifact_cost.accounting_probe.shared_probe_owner.schema",
        E8COST_SHARED_PROBE_OWNER_SCHEMA,
    )
    fixed(
        "artifact_cost.accounting_probe.shared_probe_owner.role",
        "shared_postgres_probe_inventory",
    )
    check_authority(
        shared_owner,
        "artifact_cost.accounting_probe.shared_probe_owner",
    )
    exact_mapping(
        "artifact_cost.accounting_probe.shared_probe_owner.manifest",
        frozenset({"manifest_id", "manifest_hash"}),
    )
    exact_mapping(
        "artifact_cost.accounting_probe.shared_probe_owner.repetition",
        frozenset(
            {"phase", "iteration", "warmup_repetitions", "measured_repetitions"}
        ),
    )
    postgres_identity = exact_mapping(
        "artifact_cost.accounting_probe.shared_probe_owner.postgres_identity",
        frozenset(
            {
                "version",
                "gucs",
                "policy_id",
                "context_id",
                "ctx_hash",
                "principal_id",
                "auth_artifact_id",
                "mav_artifact_id",
            }
        ),
    )
    for left_path, right_path in (
        (
            "artifact_cost.accounting_probe.shared_probe_owner.manifest.manifest_id",
            "manifest_id",
        ),
        (
            "artifact_cost.accounting_probe.shared_probe_owner.manifest.manifest_hash",
            "manifest_hash",
        ),
        (
            "artifact_cost.accounting_probe.shared_probe_owner.repetition",
            "measurement",
        ),
        (
            "artifact_cost.accounting_probe.shared_probe_owner.postgres_identity.version",
            "pg.version",
        ),
        (
            "artifact_cost.accounting_probe.shared_probe_owner.postgres_identity.gucs",
            "pg.gucs",
        ),
        (
            "artifact_cost.accounting_probe.shared_probe_owner.postgres_identity.policy_id",
            "policy.policy_id",
        ),
        (
            "artifact_cost.accounting_probe.shared_probe_owner.postgres_identity.context_id",
            "context.context_id",
        ),
        (
            "artifact_cost.accounting_probe.shared_probe_owner.postgres_identity.ctx_hash",
            "context.ctx_hash",
        ),
    ):
        try:
            left = _get_path(record, left_path)
            right = _get_path(record, right_path)
        except KeyError:
            continue
        if left != right or left.__class__ is not right.__class__:
            issues.append(
                SchemaIssue(path=left_path, message=f"must match {right_path}")
            )
    for field in ("principal_id", "auth_artifact_id", "mav_artifact_id"):
        value = postgres_identity.get(field)
        if value.__class__ is not str or not value:
            issues.append(
                SchemaIssue(
                    path=(
                        "artifact_cost.accounting_probe.shared_probe_owner."
                        f"postgres_identity.{field}"
                    ),
                    message="must be a non-empty exact PostgreSQL probe identity",
                )
            )

    body_inventory_digest = _e8cost_accounting_integrity_digest(
        {
            "schema": "e8cost_shared_body_probe_inventory_v1",
            "body_probe_inventory": body_probe_inventory,
        }
    )
    common_observations_digest = _e8cost_accounting_integrity_digest(
        {
            "schema": "e8cost_common_accounting_observations_digest_v1",
            "common_accounting_observations": common,
        }
    )
    if shared_owner.get("body_probe_inventory_digest") != body_inventory_digest:
        issues.append(
            SchemaIssue(
                path="artifact_cost.accounting_probe.shared_probe_owner.body_probe_inventory_digest",
                message="must bind the exact ordered seven-body inventory",
            )
        )
    if (
        shared_owner.get("common_accounting_observations_digest")
        != common_observations_digest
    ):
        issues.append(
            SchemaIssue(
                path=(
                    "artifact_cost.accounting_probe.shared_probe_owner."
                    "common_accounting_observations_digest"
                ),
                message="must bind the exact ordered common-observation inventory",
            )
        )
    shared_owner_payload = dict(shared_owner)
    shared_owner_digest = shared_owner_payload.pop("integrity_digest", None)
    expected_shared_owner_digest = _e8cost_accounting_integrity_digest(
        shared_owner_payload
    )
    if shared_owner_digest != expected_shared_owner_digest:
        issues.append(
            SchemaIssue(
                path="artifact_cost.accounting_probe.shared_probe_owner.integrity_digest",
                message="shared owner digest does not bind manifest/repetition/PG/body/common identity",
            )
        )

    case_validation_digest = _e8cost_accounting_integrity_digest(
        {
            "schema": "e8cost_case_validation_observation_digest_v1",
            "case_validation_observation": case_validation,
        }
    )
    projection_owner = exact_mapping(
        "artifact_cost.accounting_probe.projection_owner",
        frozenset(
            {
                "schema",
                "role",
                "shared_probe_owner_digest",
                "query",
                "declared_inputs",
                "case_validation_observation_digest",
                "integrity_digest",
            }
        )
        | authority_fields,
    )
    fixed(
        "artifact_cost.accounting_probe.projection_owner.schema",
        E8COST_PROJECTION_OWNER_SCHEMA,
    )
    fixed(
        "artifact_cost.accounting_probe.projection_owner.role",
        "accounting_projection_owner",
    )
    check_authority(
        projection_owner,
        "artifact_cost.accounting_probe.projection_owner",
    )
    exact_mapping(
        "artifact_cost.accounting_probe.projection_owner.query",
        frozenset({"query_id", "path"}),
    )
    exact_mapping(
        "artifact_cost.accounting_probe.projection_owner.declared_inputs",
        declared_input_fields,
    )
    for left_path, right_path in (
        (
            "artifact_cost.accounting_probe.projection_owner.query.query_id",
            "query.query_id",
        ),
        (
            "artifact_cost.accounting_probe.projection_owner.query.path",
            "query.path",
        ),
        (
            "artifact_cost.accounting_probe.projection_owner.declared_inputs",
            "artifact_cost.accounting_probe.declared_inputs",
        ),
    ):
        try:
            left = _get_path(record, left_path)
            right = _get_path(record, right_path)
        except KeyError:
            continue
        if left != right or left.__class__ is not right.__class__:
            issues.append(
                SchemaIssue(path=left_path, message=f"must match {right_path}")
            )
    if projection_owner.get("shared_probe_owner_digest") != shared_owner_digest:
        issues.append(
            SchemaIssue(
                path="artifact_cost.accounting_probe.projection_owner.shared_probe_owner_digest",
                message="must reference the exact recomputed shared owner digest",
            )
        )
    if (
        projection_owner.get("case_validation_observation_digest")
        != case_validation_digest
    ):
        issues.append(
            SchemaIssue(
                path=(
                    "artifact_cost.accounting_probe.projection_owner."
                    "case_validation_observation_digest"
                ),
                message="must bind the exact case-validation observation",
            )
        )
    projection_owner_payload = dict(projection_owner)
    projection_owner_digest = projection_owner_payload.pop("integrity_digest", None)
    expected_projection_owner_digest = _e8cost_accounting_integrity_digest(
        projection_owner_payload
    )
    if projection_owner_digest != expected_projection_owner_digest:
        issues.append(
            SchemaIssue(
                path="artifact_cost.accounting_probe.projection_owner.integrity_digest",
                message="projection owner digest does not bind shared/query/input/case identity",
            )
        )

    alternatives = accounting.get("accounting_alternatives")
    expected_alternatives = identity["alternatives"] if identity is not None else ()
    if (
        alternatives.__class__ is not list
        or len(alternatives) != len(expected_alternatives)
    ):
        issues.append(
            SchemaIssue(
                path="artifact_cost.accounting_probe.accounting_alternatives",
                message="accounting alternative inventory changed",
            )
        )
        alternatives = []
    alternative_fields = frozenset(
        {
            "projected_template_id",
            "projected_alternative",
            "projected_action",
            "query_body_probe_id",
            "fallback_body_probe_id",
            "maintenance_storage_observation_id",
            "case_validation_observation_id",
            "query_only_ms",
            "build_ms",
            "maintenance_unit_ms",
            "maintenance_ms_total",
            "fallback_ms",
            "validation_ms",
            "storage_bytes",
            "amortized_latency_ms",
        }
    ) | authority_fields
    q_value = identity["Q"] if identity is not None else 1
    for index, expected_template in enumerate(expected_alternatives):
        if index >= len(alternatives):
            break
        alternative = alternatives[index]
        prefix = f"artifact_cost.accounting_probe.accounting_alternatives[{index}]"
        if alternative.__class__ is not dict:
            issues.append(
                SchemaIssue(path=prefix, message="must be an exact alternative mapping")
            )
            continue
        if frozenset(alternative) != alternative_fields:
            issues.append(
                SchemaIssue(path=prefix, message="must have exact alternative fields")
            )
        expected_template_id, expected_alternative = expected_template
        for field, expected in (
            ("projected_template_id", expected_template_id),
            ("projected_alternative", expected_alternative),
            (
                "projected_action",
                identity["projection_action"] if identity is not None else None,
            ),
        ):
            actual = alternative.get(field)
            exact_type = expected is not None and actual.__class__ is not expected.__class__
            if actual != expected or exact_type:
                issues.append(
                    SchemaIssue(path=f"{prefix}.{field}", message="projection identity changed")
                )
        check_authority(alternative, prefix)

        family = identity["family"] if identity is not None else None
        if expected_template_id == "barrier_filter_v1":
            expected_links = {
                "query_body_probe_id": "barrier_explain_analyze_query",
                "fallback_body_probe_id": (
                    "barrier_explain_analyze_query"
                    if family == "STALE-FALLBACK"
                    else None
                ),
                "maintenance_storage_observation_id": None,
                "case_validation_observation_id": (
                    "case_specific_artifact_validation"
                    if family == "STALE-FALLBACK"
                    else None
                ),
            }
        elif expected_template_id == "mav_scan_v1":
            expected_links = {
                "query_body_probe_id": "mav_validated_query",
                "fallback_body_probe_id": None,
                "maintenance_storage_observation_id": "mav_maintenance_storage",
                "case_validation_observation_id": "case_specific_artifact_validation",
            }
        else:
            expected_links = {
                "query_body_probe_id": "auth_index_validated_query",
                "fallback_body_probe_id": None,
                "maintenance_storage_observation_id": "auth_index_maintenance_storage",
                "case_validation_observation_id": "case_specific_artifact_validation",
            }
        for field, expected in expected_links.items():
            actual = alternative.get(field)
            exact_type = expected is not None and actual.__class__ is not expected.__class__
            if actual != expected or exact_type:
                issues.append(
                    SchemaIssue(path=f"{prefix}.{field}", message="observation binding changed")
                )

        query_probe = body_probe_by_id.get(expected_links["query_body_probe_id"])
        fallback_probe = body_probe_by_id.get(
            expected_links["fallback_body_probe_id"] or ""
        )
        maintenance_observation = common_by_id.get(
            expected_links["maintenance_storage_observation_id"] or ""
        )
        expected_values: dict[str, float | int] = {
            "query_only_ms": (
                float(query_probe.get("total_ms", 0.0))
                if query_probe is not None
                else 0.0
            ),
            "build_ms": (
                float(maintenance_observation.get("build_ms", 0.0))
                if maintenance_observation is not None
                else 0.0
            ),
            "maintenance_unit_ms": (
                float(maintenance_observation.get("refresh_ms", 0.0))
                if maintenance_observation is not None
                else 0.0
            ),
            "fallback_ms": (
                float(fallback_probe.get("total_ms", 0.0))
                if fallback_probe is not None
                else 0.0
            ),
            "validation_ms": (
                float(case_validation.get("elapsed_ms", 0.0))
                if expected_links["case_validation_observation_id"] is not None
                else 0.0
            ),
            "storage_bytes": (
                int(maintenance_observation.get("storage_bytes", 0))
                if maintenance_observation is not None
                else 0
            ),
        }
        invalidation_count = 0
        if identity is not None:
            update_pressure = identity["U"] * (identity["ttl_s"] / 3600.0)
            invalidation_count = int(
                math.ceil(update_pressure * max(1, identity["contexts"] / 1000))
            )
        expected_values["maintenance_ms_total"] = (
            expected_values["maintenance_unit_ms"] * invalidation_count
        )
        expected_values["amortized_latency_ms"] = (
            expected_values["query_only_ms"]
            + (
                expected_values["build_ms"]
                + expected_values["maintenance_ms_total"]
                + expected_values["fallback_ms"]
            )
            / q_value
        )
        for field, expected in expected_values.items():
            actual = alternative.get(field)
            if actual != expected or actual.__class__ is not expected.__class__:
                issues.append(
                    SchemaIssue(path=f"{prefix}.{field}", message="derived accounting value changed")
                )

    observed = exact_mapping(
        "artifact_cost.accounting_probe.observed_accounting_minimum",
        frozenset(
            {
                "projected_template_id",
                "projected_alternative",
                "projected_action",
                "projection_reason",
                "amortized_latency_ms",
            }
        )
        | authority_fields,
    )
    if alternatives:
        minimum = min(
            alternatives,
            key=lambda item: item.get("amortized_latency_ms", float("inf")),
        )
        for field in (
            "projected_template_id",
            "projected_alternative",
            "projected_action",
            "amortized_latency_ms",
        ):
            actual = observed.get(field)
            expected = minimum.get(field)
            if actual != expected or actual.__class__ is not expected.__class__:
                issues.append(
                    SchemaIssue(
                        path=(
                            "artifact_cost.accounting_probe."
                            f"observed_accounting_minimum.{field}"
                        ),
                        message="must match the exact accounting minimum",
                    )
                )
    if identity is not None:
        fixed(
            "artifact_cost.accounting_probe.observed_accounting_minimum.projection_reason",
            identity["projection_reason"],
        )
    check_authority(
        observed,
        "artifact_cost.accounting_probe.observed_accounting_minimum",
    )

    projection_integrity = exact_mapping(
        "artifact_cost.accounting_probe.projection_integrity",
        frozenset({"schema", "projection_owner_digest", "integrity_digest"})
        | authority_fields,
    )
    fixed(
        "artifact_cost.accounting_probe.projection_integrity.schema",
        E8COST_PROJECTION_INTEGRITY_SCHEMA,
    )
    check_authority(
        projection_integrity,
        "artifact_cost.accounting_probe.projection_integrity",
    )
    if (
        projection_integrity.get("projection_owner_digest")
        != projection_owner_digest
    ):
        issues.append(
            SchemaIssue(
                path="artifact_cost.accounting_probe.projection_integrity.projection_owner_digest",
                message="must reference the exact recomputed projection owner digest",
            )
        )
    projection_integrity_payload = dict(projection_integrity)
    projection_integrity_digest = projection_integrity_payload.pop(
        "integrity_digest", None
    )
    projection_integrity_payload["accounting_alternatives"] = alternatives
    projection_integrity_payload["observed_accounting_minimum"] = observed
    expected_projection_integrity_digest = _e8cost_accounting_integrity_digest(
        projection_integrity_payload
    )
    if projection_integrity_digest != expected_projection_integrity_digest:
        issues.append(
            SchemaIssue(
                path="artifact_cost.accounting_probe.projection_integrity.integrity_digest",
                message="projection integrity digest does not bind owner/alternatives/minimum",
            )
        )

    evidence = record.get("evidence", {})
    for field, expected in (
        ("shared_probe_owner_digest", shared_owner_digest),
        ("projection_owner_digest", projection_owner_digest),
        ("projection_integrity_digest", projection_integrity_digest),
    ):
        if evidence.get(field) != expected:
            issues.append(
                SchemaIssue(
                    path=f"evidence.{field}",
                    message="must match the exact recomputed ownership chain digest",
                )
            )

    return branch, issues
# END PHASE_B_E8COST_ACCOUNTING_PROJECTION_VALIDATOR


def validate_raw_run_record(
    record: Mapping[str, Any],
    *,
    mode_registry: Mapping[str, ModeSpec] | None = None,
) -> List[SchemaIssue]:
    """Return schema issues for one raw run JSON object."""

    has_v2_semantics = _uses_v2_extensions(record)
    issues = _require_paths(record, REQUIRED_TOP_LEVEL)
    issues.extend(_require_paths(record, REQUIRED_NESTED))
    if has_v2_semantics:
        issues.extend(_require_paths(record, V2_REQUIRED_NESTED))
# BEGIN PHASE_B_E8COST_ACCOUNTING_PROJECTION_DISPATCH
    projection_branch, projection_issues = (
        _validate_e8cost_accounting_projection(record)
    )
    issues.extend(projection_issues)
# END PHASE_B_E8COST_ACCOUNTING_PROJECTION_DISPATCH

    if record.get("schema_version") not in ALLOWED_RAW_SCHEMA_VERSIONS:
        issues.append(
            SchemaIssue(
                path="schema_version",
                message=f"expected one of {sorted(ALLOWED_RAW_SCHEMA_VERSIONS)!r}",
            )
        )
    else:
        try:
            normalize_run_identity(record, mode_registry=mode_registry)
        except ValueError as exc:
            message = str(exc)
            if "evaluation_role" in message:
                path = "evaluation_role"
            elif "baseline_class" in message:
                path = "baseline_class"
            elif "mode" in message:
                path = "mode"
            else:
                path = "schema_version"
            issues.append(SchemaIssue(path=path, message=message))

    if record.get("run_kind") not in ALLOWED_RUN_KIND:
        issues.append(SchemaIssue(path="run_kind", message="invalid run_kind"))

    if record.get("status") not in ALLOWED_STATUS:
        issues.append(SchemaIssue(path="status", message="invalid status"))

    for path in DIGEST_PATHS:
# BEGIN PHASE_B_E8COST_ACCOUNTING_PROJECTION_NULL_DIGEST
        if (
            projection_branch
            and path in E8COST_ACCOUNTING_PROJECTION_NULL_DIGEST_PATHS
            and _path_exists(record, path)
            and _get_path(record, path) is None
        ):
            continue
# END PHASE_B_E8COST_ACCOUNTING_PROJECTION_NULL_DIGEST
        issue = _sha256_issue(record, path)
        if issue is not None:
            issues.append(issue)

    for path in NONEMPTY_STRING_PATHS:
# BEGIN PHASE_B_E8COST_ACCOUNTING_PROJECTION_NULL_STRING
        if (
            projection_branch
            and path in E8COST_ACCOUNTING_PROJECTION_NULL_STRING_PATHS
            and _path_exists(record, path)
            and _get_path(record, path) is None
        ):
            continue
# END PHASE_B_E8COST_ACCOUNTING_PROJECTION_NULL_STRING
        issue = _nonempty_string_issue(record, path)
        if issue is not None:
            issues.append(issue)

    for path in NONNEGATIVE_NUMBER_PATHS:
# BEGIN PHASE_B_E8COST_ACCOUNTING_PROJECTION_NULL_NUMBER
        if (
            projection_branch
            and path in E8COST_ACCOUNTING_PROJECTION_NULL_NUMBER_PATHS
            and _path_exists(record, path)
            and _get_path(record, path) is None
        ):
            continue
# END PHASE_B_E8COST_ACCOUNTING_PROJECTION_NULL_NUMBER
        issue = _nonnegative_number_issue(record, path)
        if issue is not None:
            issues.append(issue)

    for path in NONNEGATIVE_INT_PATHS:
# BEGIN PHASE_B_E8COST_ACCOUNTING_PROJECTION_NULL_INT
        if (
            projection_branch
            and path in E8COST_ACCOUNTING_PROJECTION_NULL_INT_PATHS
            and _path_exists(record, path)
            and _get_path(record, path) is None
        ):
            continue
# END PHASE_B_E8COST_ACCOUNTING_PROJECTION_NULL_INT
        issue = _nonnegative_int_issue(record, path)
        if issue is not None:
            issues.append(issue)

    for path in COUNT_PATHS:
        issue = _nullable_nonnegative_int_issue(
            record, path, allow_null=has_v2_semantics
        )
        if issue is not None:
            issues.append(issue)

    applicability = record.get("template_applicability", {})
    if isinstance(applicability, Mapping):
        if applicability.get("status") not in ALLOWED_TEMPLATE_APPLICABILITY:
            issues.append(
                SchemaIssue(
                    path="template_applicability.status",
                    message="invalid template applicability status",
                )
            )

    template_oracle = record.get("template_oracle", {})
    if isinstance(template_oracle, Mapping):
        if not isinstance(template_oracle.get("eligible_for_template_oracle"), bool):
            issues.append(
                SchemaIssue(
                    path="template_oracle.eligible_for_template_oracle",
                    message="must be boolean",
                )
            )

    pg = record.get("pg", {})
    if isinstance(pg, Mapping):
        gucs = pg.get("gucs")
        if not isinstance(gucs, Mapping) or not gucs:
            issues.append(
                SchemaIssue(path="pg.gucs", message="must be a non-empty mapping")
            )

    planner = record.get("planner", {})
    if isinstance(planner, Mapping):
        disabled_components = planner.get("disabled_components")
        if "disabled_components" in planner:
            if isinstance(disabled_components, (str, bytes)) or not isinstance(
                disabled_components, list
            ):
                issues.append(
                    SchemaIssue(
                        path="planner.disabled_components",
                        message="must be a list",
                    )
                )
            else:
                unknown = sorted(
                    str(item)
                    for item in disabled_components
                    if str(item) not in DISABLED_COMPONENTS
                )
                if unknown:
                    issues.append(
                        SchemaIssue(
                            path="planner.disabled_components",
                            message=f"unknown disabled components: {unknown}",
                        )
                    )
        rejection_reasons = planner.get("rejection_reasons")
        if "rejection_reasons" in planner and not isinstance(
            rejection_reasons, Mapping
        ):
            issues.append(
                SchemaIssue(
                    path="planner.rejection_reasons", message="must be a mapping"
                )
            )
        delivered_sigma = planner.get("delivered_sigma")
        if "delivered_sigma" in planner and not isinstance(delivered_sigma, Mapping):
            issues.append(
                SchemaIssue(path="planner.delivered_sigma", message="must be a mapping")
            )
        planner_certificate = planner.get("certificate")
        if "certificate" in planner and planner_certificate is not None:
            if not isinstance(planner_certificate, list):
                issues.append(
                    SchemaIssue(
                        path="planner.certificate", message="must be a list or null"
                    )
                )
            elif record.get("status") == "pass" and not planner_certificate:
                issues.append(
                    SchemaIssue(
                        path="planner.certificate",
                        message="pass records with planner certificate must carry at least one step",
                    )
                )
        planner_certificate_check = planner.get("certificate_check")
        if "certificate_check" in planner and planner_certificate_check is not None:
            if not isinstance(planner_certificate_check, Mapping):
                issues.append(
                    SchemaIssue(
                        path="planner.certificate_check",
                        message="must be a mapping or null",
                    )
                )
            elif (
                record.get("status") == "pass"
                and planner_certificate_check.get("status") != "pass"
            ):
                issues.append(
                    SchemaIssue(
                        path="planner.certificate_check.status",
                        message="pass records with planner certificate_check must pass",
                    )
                )
        query_plan = planner.get("query_plan")
        if "query_plan" in planner:
            if not isinstance(query_plan, Mapping):
                issues.append(
                    SchemaIssue(path="planner.query_plan", message="must be a mapping")
                )
            else:
                query_root_sigma = query_plan.get("root_sigma")
                if "root_sigma" in query_plan and not isinstance(
                    query_root_sigma, Mapping
                ):
                    issues.append(
                        SchemaIssue(
                            path="planner.query_plan.root_sigma",
                            message="must be a mapping",
                        )
                    )
                query_root_closure = query_plan.get("root_closure")
                if "root_closure" in query_plan and not isinstance(
                    query_root_closure, Mapping
                ):
                    issues.append(
                        SchemaIssue(
                            path="planner.query_plan.root_closure",
                            message="must be a mapping",
                        )
                    )
                query_emitted_sql = query_plan.get("emitted_sql")
                if "emitted_sql" in query_plan and not isinstance(
                    query_emitted_sql, str
                ):
                    issues.append(
                        SchemaIssue(
                            path="planner.query_plan.emitted_sql",
                            message="must be a string",
                        )
                    )
                query_emitted_sql_hash = query_plan.get("emitted_sql_hash")
                if (
                    "emitted_sql_hash" in query_plan
                    and query_emitted_sql_hash is not None
                    and (
                        not isinstance(query_emitted_sql_hash, str)
                        or not SHA256_RE.match(query_emitted_sql_hash)
                    )
                ):
                    issues.append(
                        SchemaIssue(
                            path="planner.query_plan.emitted_sql_hash",
                            message="must be a sha256: digest or null",
                        )
                    )
                query_certificate = query_plan.get("certificate")
                certificate_suppressed = bool(query_plan.get("certificate_suppressed"))
                if "certificate" in query_plan and query_certificate is not None:
                    if not isinstance(query_certificate, list):
                        issues.append(
                            SchemaIssue(
                                path="planner.query_plan.certificate",
                                message="must be a list or null",
                            )
                        )
                    elif not query_certificate and not certificate_suppressed:
                        issues.append(
                            SchemaIssue(
                                path="planner.query_plan.certificate",
                                message="unsuppressed query certificate must carry at least one step",
                            )
                        )
                query_certificate_check = query_plan.get("certificate_check")
                if (
                    "certificate_check" in query_plan
                    and query_certificate_check is not None
                ):
                    if not isinstance(query_certificate_check, Mapping):
                        issues.append(
                            SchemaIssue(
                                path="planner.query_plan.certificate_check",
                                message="must be a mapping or null",
                            )
                        )
                    elif query_certificate_check.get("status") != "pass":
                        issues.append(
                            SchemaIssue(
                                path="planner.query_plan.certificate_check.status",
                                message="query certificate_check must pass",
                            )
                        )
                if (
                    record.get("status") == "pass"
                    and not certificate_suppressed
                    and query_certificate is None
                ):
                    issues.append(
                        SchemaIssue(
                            path="planner.query_plan.certificate",
                            message="pass query plans must carry certificate unless explicitly suppressed",
                        )
                    )
        candidates = planner.get("candidates")
        if "candidates" in planner and not isinstance(candidates, list):
            issues.append(
                SchemaIssue(path="planner.candidates", message="must be a list")
            )
        elif isinstance(candidates, list):
            for index, candidate in enumerate(candidates):
                prefix = f"planner.candidates[{index}]"
                if not isinstance(candidate, Mapping):
                    issues.append(SchemaIssue(path=prefix, message="must be an object"))
                    continue
                required_candidate_fields = (
                    V2_REQUIRED_CANDIDATE_FIELDS
                    if has_v2_semantics
                    else REQUIRED_CANDIDATE_FIELDS
                )
                for field in required_candidate_fields:
                    if field not in candidate:
                        issues.append(
                            SchemaIssue(
                                path=f"{prefix}.{field}",
                                message="missing required candidate field",
                            )
                        )
                accepted = candidate.get("accepted")
                if "accepted" in candidate and not isinstance(accepted, bool):
                    issues.append(
                        SchemaIssue(
                            path=f"{prefix}.accepted", message="must be boolean"
                        )
                    )
                applicability = candidate.get("template_applicability")
                if (
                    "template_applicability" in candidate
                    and applicability not in ALLOWED_TEMPLATE_APPLICABILITY
                ):
                    issues.append(
                        SchemaIssue(
                            path=f"{prefix}.template_applicability",
                            message="invalid template applicability status",
                        )
                    )
                candidate_sigma = candidate.get("delivered_sigma")
                if "delivered_sigma" in candidate and not isinstance(
                    candidate_sigma, Mapping
                ):
                    issues.append(
                        SchemaIssue(
                            path=f"{prefix}.delivered_sigma",
                            message="must be a mapping",
                        )
                    )
                candidate_kappa = candidate.get("kappa_sem")
                if (
                    has_v2_semantics
                    and "kappa_sem" in candidate
                    and not isinstance(candidate_kappa, Mapping)
                ):
                    issues.append(
                        SchemaIssue(
                            path=f"{prefix}.kappa_sem",
                            message="must be a mapping",
                        )
                    )
                candidate_reasons = candidate.get("rejection_reasons")
                if "rejection_reasons" in candidate and not isinstance(
                    candidate_reasons, list
                ):
                    issues.append(
                        SchemaIssue(
                            path=f"{prefix}.rejection_reasons",
                            message="must be a list",
                        )
                    )
                elif accepted is False and not candidate_reasons:
                    issues.append(
                        SchemaIssue(
                            path=f"{prefix}.rejection_reasons",
                            message="rejected candidates must record at least one reason",
                        )
                    )
                if has_v2_semantics:
                    certificate = candidate.get("certificate")
                    certificate_check = candidate.get("certificate_check")
                    pruned_by = candidate.get("pruned_by_dominance")
                    if pruned_by is not None and not isinstance(pruned_by, str):
                        issues.append(
                            SchemaIssue(
                                path=f"{prefix}.pruned_by_dominance",
                                message="must be a string or null",
                            )
                        )
                    if accepted is True:
                        certificate_suppressed = _is_certificate_suppressed_diagnostic(
                            candidate
                        )
                        if certificate_suppressed:
                            if certificate is not None:
                                issues.append(
                                    SchemaIssue(
                                        path=f"{prefix}.certificate",
                                        message="certificate-suppressed diagnostic candidates must not carry a certificate",
                                    )
                                )
                            if certificate_check is not None:
                                issues.append(
                                    SchemaIssue(
                                        path=f"{prefix}.certificate_check",
                                        message="certificate-suppressed diagnostic candidates must not carry certificate_check",
                                    )
                                )
                        elif not isinstance(certificate, list) or not certificate:
                            issues.append(
                                SchemaIssue(
                                    path=f"{prefix}.certificate",
                                    message="accepted v2 candidates must carry a non-empty certificate",
                                )
                            )
                        if certificate_suppressed:
                            pass
                        elif not isinstance(certificate_check, Mapping):
                            issues.append(
                                SchemaIssue(
                                    path=f"{prefix}.certificate_check",
                                    message="accepted v2 candidates must carry certificate_check",
                                )
                            )
                        elif certificate_check.get("status") != "pass":
                            issues.append(
                                SchemaIssue(
                                    path=f"{prefix}.certificate_check.status",
                                    message="accepted v2 candidate certificate_check must pass",
                                )
                            )
                    else:
                        if certificate is not None:
                            issues.append(
                                SchemaIssue(
                                    path=f"{prefix}.certificate",
                                    message="rejected v2 candidates must not carry a certificate",
                                )
                            )
                        if certificate_check is not None:
                            issues.append(
                                SchemaIssue(
                                    path=f"{prefix}.certificate_check",
                                    message="rejected v2 candidates must not carry certificate_check",
                                )
                            )

    static_verifier = record.get("static_verifier", {})
# BEGIN PHASE_B_E8COST_ACCOUNTING_PROJECTION_STATIC_STATUS
    if projection_branch:
        static_verifier = {"status": "fail", "plan_hash": None}
# END PHASE_B_E8COST_ACCOUNTING_PROJECTION_STATIC_STATUS
    if isinstance(static_verifier, Mapping):
        static_status = static_verifier.get("status")
        if static_status not in ALLOWED_STATIC_VERIFIER_STATUS:
            issues.append(
                SchemaIssue(
                    path="static_verifier.status",
                    message="invalid static verifier status",
                )
            )
        plan_hash = static_verifier.get("plan_hash")
        if static_status == "pass" or plan_hash is not None:
            issue = _sha256_issue(record, "static_verifier.plan_hash")
            if issue is not None:
                issues.append(issue)

    artifact_validation = record.get("artifact_validation", {})
# BEGIN PHASE_B_E8COST_ACCOUNTING_PROJECTION_ACTION_STATUS
    if projection_branch and isinstance(artifact_validation, Mapping):
        artifact_validation = {
            **artifact_validation,
            "action": "execute",
            "expected_action": "execute",
        }
# END PHASE_B_E8COST_ACCOUNTING_PROJECTION_ACTION_STATUS
    if isinstance(artifact_validation, Mapping):
        if artifact_validation.get("status") not in ALLOWED_ARTIFACT_VALIDATION_STATUS:
            issues.append(
                SchemaIssue(
                    path="artifact_validation.status",
                    message="invalid artifact validation status",
                )
            )
        if artifact_validation.get("action") not in ALLOWED_ARTIFACT_ACTION:
            issues.append(
                SchemaIssue(
                    path="artifact_validation.action",
                    message="invalid artifact validation action",
                )
            )
        if artifact_validation.get("expected_action") not in ALLOWED_ARTIFACT_ACTION:
            issues.append(
                SchemaIssue(
                    path="artifact_validation.expected_action",
                    message="invalid expected artifact validation action",
                )
            )
        if "same_snapshot" in artifact_validation and not isinstance(
            artifact_validation.get("same_snapshot"), bool
        ):
            issues.append(
                SchemaIssue(
                    path="artifact_validation.same_snapshot",
                    message="must be boolean",
                )
            )
        isolation_level = artifact_validation.get("isolation_level")
        if "isolation_level" in artifact_validation and isolation_level is not None:
            if not isinstance(isolation_level, str) or not isolation_level:
                issues.append(
                    SchemaIssue(
                        path="artifact_validation.isolation_level",
                        message="must be a non-empty string or null",
                    )
                )

    runtime_audit = record.get("runtime_audit", {})
    if isinstance(runtime_audit, Mapping):
        if runtime_audit.get("status") not in ALLOWED_RUNTIME_AUDIT_STATUS:
            issues.append(
                SchemaIssue(
                    path="runtime_audit.status", message="invalid runtime audit status"
                )
            )

    oracle_check = record.get("oracle_check", {})
    if isinstance(oracle_check, Mapping):
        if oracle_check.get("status") not in ALLOWED_ORACLE_CHECK_STATUS:
            issues.append(
                SchemaIssue(
                    path="oracle_check.status", message="invalid oracle check status"
                )
            )

    artifact_cost = record.get("artifact_cost", {})
    if isinstance(artifact_cost, Mapping) and "amortization_model" in artifact_cost:
        allowed_models = (
            ALLOWED_AMORTIZATION_MODEL
            if has_v2_semantics
            else LEGACY_ALLOWED_AMORTIZATION_MODEL
        )
        if artifact_cost.get("amortization_model") not in allowed_models:
            issues.append(
                SchemaIssue(
                    path="artifact_cost.amortization_model",
                    message="invalid amortization_model",
                )
            )

    docker_digest = record.get("implementation", {}).get("docker_image_digest")
    if docker_digest != "not_containerized" and (
        not isinstance(docker_digest, str) or not SHA256_RE.match(docker_digest)
    ):
        issues.append(
            SchemaIssue(
                path="implementation.docker_image_digest",
                message="must be a sha256: digest or 'not_containerized'",
            )
        )

    git_commit = record.get("implementation", {}).get("git_commit")
    if not git_commit:
        issues.append(
            SchemaIssue(
                path="implementation.git_commit", message="git_commit is required"
            )
        )

    return issues


def required_schema_summary() -> Dict[str, Any]:
    return {
        "schema_version": RAW_SCHEMA_VERSION,
        "legacy_schema_version": LEGACY_RAW_SCHEMA_VERSION,
        "previous_schema_version": PREVIOUS_RAW_SCHEMA_VERSION,
        "allowed_schema_versions": sorted(ALLOWED_RAW_SCHEMA_VERSIONS),
        "top_level": list(REQUIRED_TOP_LEVEL),
        "legacy_identity_fields": list(LEGACY_IDENTITY_FIELDS),
        "v3_identity_fields": list(V3_IDENTITY_FIELDS),
        "nested": list(REQUIRED_NESTED),
        "v2_nested": list(V2_REQUIRED_NESTED),
        "status": sorted(ALLOWED_STATUS),
        "run_kind": sorted(ALLOWED_RUN_KIND),
        "baseline_class": sorted(ALLOWED_BASELINE_CLASSES),
        "evaluation_role": sorted(ALLOWED_EVALUATION_ROLES),
        "template_applicability": sorted(ALLOWED_TEMPLATE_APPLICABILITY),
        "artifact_validation_status": sorted(ALLOWED_ARTIFACT_VALIDATION_STATUS),
        "artifact_validation_action": sorted(ALLOWED_ARTIFACT_ACTION),
        "amortization_model": sorted(ALLOWED_AMORTIZATION_MODEL),
        "nullable_counts_v2": dict(COUNT_NULL_SEMANTICS),
    }
