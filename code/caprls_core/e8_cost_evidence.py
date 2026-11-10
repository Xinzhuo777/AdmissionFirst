"""Exact evidence classification for the finite E8-COST reporting seam."""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
    POLICY_ENFORCEMENT_ROLE,
    normalize_mode_id,
)
from .result_schema import RAW_SCHEMA_VERSION, normalize_run_identity

# BEGIN PHASE_B2A_E8COST_EVIDENCE_CLASSIFICATION
import hashlib
import json
import math
import re
from typing import Any, Mapping


E8COST_ACCOUNTING_PROJECTION = "accounting_projection"
E8COST_GATE_REJECT = "gate_reject"
E8COST_RESULT_EXECUTION = "result_execution"
E8COST_EVIDENCE_CLASSES = (
    E8COST_ACCOUNTING_PROJECTION,
    E8COST_GATE_REJECT,
    E8COST_RESULT_EXECUTION,
)
E8COST_MANIFEST_ID = "e8_cost_update_rate_v1"
E8COST_V3_MANIFEST_ID = "e8_cost_update_rate_v1_taxonomy_v3"
E8COST_MANIFEST_IDS = frozenset({E8COST_MANIFEST_ID, E8COST_V3_MANIFEST_ID})
E8COST_STAGE = "artifact_cost_update_rate"
E8COST_PROJECTION_SCHEMA = "e8cost_accounting_gate_projection_v2"
E8COST_ACCOUNTING_SCHEMA = "e8cost_accounting_probe_v2"
E8COST_SHARED_OWNER_SCHEMA = "e8cost_shared_postgres_probe_owner_v2"
E8COST_PROJECTION_OWNER_SCHEMA = "e8cost_accounting_projection_owner_v1"
E8COST_PROJECTION_INTEGRITY_SCHEMA = "e8cost_projection_integrity_v2"
E8COST_BODY_PROBE_IDS = (
    "barrier_explain_analyze_query",
    "auth_index_explain_analyze_query",
    "mav_explain_analyze_query",
    "hybrid_explain_analyze_query",
    "auth_index_validated_query",
    "mav_validated_query",
    "hybrid_validated_query",
)
E8COST_COMMON_OBSERVATION_IDS = (
    "auth_index_maintenance_storage",
    "mav_maintenance_storage",
)
E8COST_GATE_REJECT_MODES = frozenset({"auth-index-enum-only", "mav-only"})
E8COST_RESULT_EXECUTION_MODES = frozenset(
    {
        "auth-index-enum-only",
        "conservative-barrier",
        "mav-no-version",
        "mav-only",
        "naive-artifact-only",
        "native-pg-rls-physical-design",
        "stale-artifact-user",
    }
)


E8COST_EXECUTED_SQL_SOURCES = frozenset({"planner_ir_emitted", "native_baseline_sql"})
E8COST_AUTHORITY_FALSE_FIELDS = (
    "production_planner_authority",
    "selection_authority",
    "execution_authority",
    "result_evidence",
    "f3_selection_authority",
)
E8COST_PROJECTION_TOP_LEVEL_FIELDS = frozenset(
    {
        "artifact_cost",
        "artifact_validation",
        "context",
        "counts",
        "dataset",
        "evidence",
        "experiment",
        "failure",
        "implementation",
        "manifest_hash",
        "manifest_id",
        "measurement",
        "mode",
        "oracle_check",
        "pg",
        "pg_metrics",
        "planner",
        "policy",
        "query",
        "result",
        "run_id",
        "run_kind",
        "runtime_audit",
        "schema_version",
        "sql",
        "stage",
        "static_verifier",
        "status",
        "template",
        "template_applicability",
        "template_oracle",
        "timing_ms",
        "versions",
    }
)
E8COST_ACCOUNTING_PROBE_FIELDS = frozenset(
    {
        "schema",
        "evidence_role",
        "integrity_only",
        "production_planner_authority",
        "selection_authority",
        "execution_authority",
        "result_evidence",
        "f3_selection_authority",
        "body_probe_inventory",
        "common_accounting_observations",
        "case_validation_observation",
        "shared_probe_owner",
        "declared_inputs",
        "projection_owner",
        "accounting_alternatives",
        "observed_accounting_minimum",
        "projection_integrity",
    }
)
E8COST_DECLARED_INPUT_FIELDS = frozenset(
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
E8COST_BODY_PROBE_FIELDS = frozenset(
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
        "integrity_only",
        "production_planner_authority",
        "selection_authority",
        "execution_authority",
        "result_evidence",
        "f3_selection_authority",
    }
)
E8COST_VALIDATION_FIELDS = frozenset(
    {
        "status",
        "failure_sqlstate",
        "failure_symbol",
        "elapsed_ms",
        "same_snapshot",
        "isolation_level",
    }
)
E8COST_COMMON_OBSERVATION_CONTAINER_FIELDS = frozenset(
    {
        "schema",
        "ownership",
        "selected_body_execution",
        "integrity_only",
        "production_planner_authority",
        "selection_authority",
        "execution_authority",
        "result_evidence",
        "f3_selection_authority",
        "observations",
    }
)
E8COST_COMMON_OBSERVATION_FIELDS = frozenset(
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
        "integrity_only",
        "production_planner_authority",
        "selection_authority",
        "execution_authority",
        "result_evidence",
        "f3_selection_authority",
    }
)
E8COST_CASE_VALIDATION_FIELDS = frozenset(
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
        "integrity_only",
        "production_planner_authority",
        "selection_authority",
        "execution_authority",
        "result_evidence",
        "f3_selection_authority",
    }
)
E8COST_SHARED_OWNER_FIELDS = frozenset(
    {
        "schema",
        "role",
        "manifest",
        "repetition",
        "postgres_identity",
        "body_probe_inventory_digest",
        "common_accounting_observations_digest",
        "integrity_only",
        "production_planner_authority",
        "selection_authority",
        "execution_authority",
        "result_evidence",
        "f3_selection_authority",
        "integrity_digest",
    }
)
E8COST_SHARED_POSTGRES_IDENTITY_FIELDS = frozenset(
    {
        "version",
        "policy_id",
        "context_id",
        "principal_id",
        "ctx_hash",
        "auth_artifact_id",
        "mav_artifact_id",
        "gucs",
    }
)
E8COST_PROJECTION_OWNER_FIELDS = frozenset(
    {
        "schema",
        "role",
        "shared_probe_owner_digest",
        "query",
        "declared_inputs",
        "case_validation_observation_digest",
        "integrity_only",
        "production_planner_authority",
        "selection_authority",
        "execution_authority",
        "result_evidence",
        "f3_selection_authority",
        "integrity_digest",
    }
)
E8COST_ACCOUNTING_ALTERNATIVE_FIELDS = frozenset(
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
        "integrity_only",
        "production_planner_authority",
        "selection_authority",
        "execution_authority",
        "result_evidence",
        "f3_selection_authority",
    }
)
E8COST_ACCOUNTING_MINIMUM_FIELDS = frozenset(
    {
        "projected_template_id",
        "projected_alternative",
        "projected_action",
        "projection_reason",
        "amortized_latency_ms",
        "integrity_only",
        "production_planner_authority",
        "selection_authority",
        "execution_authority",
        "result_evidence",
        "f3_selection_authority",
    }
)
E8COST_PROJECTION_INTEGRITY_FIELDS = frozenset(
    {
        "schema",
        "projection_owner_digest",
        "integrity_only",
        "production_planner_authority",
        "selection_authority",
        "execution_authority",
        "result_evidence",
        "f3_selection_authority",
        "integrity_digest",
    }
)


class E8CostEvidenceClassificationError(ValueError):
    """Raised when an E8-COST row has ambiguous or invalid evidence provenance."""


def is_e8_cost_record(record: Mapping[str, Any]) -> bool:
    """Return whether *record* is in the exact E8-COST reporting family."""

    return record.get("experiment") == "E8" and record.get("stage") == E8COST_STAGE


def _fail(message: str) -> None:
    raise E8CostEvidenceClassificationError(message)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if value.__class__ is not dict:
        _fail(f"{label} must be an exact mapping")
    return value


def _digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _sha256(value: Any) -> bool:
    return (
        value.__class__ is str
        and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
    )


def _number(value: Any) -> bool:
    return (
        value.__class__ in {int, float}
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) >= 0.0
    )


def _authority_is_false(
    mapping: Mapping[str, Any],
    label: str,
    *,
    allow_missing_production: bool = False,
) -> None:
    if mapping.get("integrity_only") is not True:
        _fail(f"{label}.integrity_only must be true")
    for field in E8COST_AUTHORITY_FALSE_FIELDS:
        if (
            allow_missing_production
            and field == "production_planner_authority"
            and field not in mapping
        ):
            continue
        if mapping.get(field) is not False:
            _fail(f"{label}.{field} must be false")


def _reject_explicit_body_authority(record: Mapping[str, Any], label: str) -> None:
    sql = _mapping(record.get("sql"), "sql")
    result = _mapping(record.get("result"), "result")
    for mapping, field in (
        (sql, "selected_body_execution"),
        (sql, "execution_authority"),
        (result, "execution_authority"),
        (result, "result_evidence"),
    ):
        if mapping.get(field) is True:
            _fail(f"{label} cannot carry explicit {field}=true")


def _exact_outer_mapping(
    record: Mapping[str, Any],
    field: str,
    expected: Mapping[str, Any],
) -> None:
    actual = _mapping(record.get(field), field)
    if actual != expected:
        _fail(f"accounting projection outer {field} boundary changed")


def _exact_keys(
    mapping: Mapping[str, Any],
    expected: set[str] | frozenset[str],
    label: str,
) -> None:
    if set(mapping) != expected:
        _fail(f"accounting projection outer {label} fields changed")


def _validate_projection_outer_boundary(record: Mapping[str, Any]) -> None:
    """Reject selected-body, result, or ordinary-cost evidence outside the probe."""

    top_level_fields = set(record)
    top_level_fields.discard("_raw_path")
    role_field = (
        "evaluation_role"
        if record.get("schema_version") == RAW_SCHEMA_VERSION
        else "baseline_class"
    )
    if top_level_fields != E8COST_PROJECTION_TOP_LEVEL_FIELDS | {role_field}:
        _fail("accounting projection top-level boundary changed")
    try:
        identity = normalize_run_identity(record)
    except ValueError as exc:
        _fail(f"accounting projection outer identity invalid: {exc}")
    if (
        identity.evaluation_role != POLICY_ENFORCEMENT_ROLE
        or record.get("failure") is not None
    ):
        _fail("accounting projection outer identity changed")

    query = _mapping(record.get("query"), "query")
    if set(query) != {"query_id", "path", "params"} or query.get("params") != {}:
        _fail("accounting projection cannot carry outer query-plan inputs")
    dataset = _mapping(record.get("dataset"), "dataset")
    context = _mapping(record.get("context"), "context")
    policy = _mapping(record.get("policy"), "policy")
    measurement = _mapping(record.get("measurement"), "measurement")
    pg = _mapping(record.get("pg"), "pg")
    implementation = _mapping(record.get("implementation"), "implementation")
    _exact_keys(dataset, {"name", "scale", "seed"}, "dataset")
    _exact_keys(context, {"context_id", "ctx_hash"}, "context")
    _exact_keys(
        policy,
        {
            "policy_id",
            "policy_sql_manifest_hash",
            "policy_version",
        },
        "policy",
    )
    _exact_keys(
        measurement,
        {
            "phase",
            "iteration",
            "warmup_repetitions",
            "measured_repetitions",
        },
        "measurement",
    )
    _exact_keys(pg, {"version", "gucs"}, "pg")
    pg_gucs = _mapping(pg.get("gucs"), "pg.gucs")
    _exact_keys(
        pg_gucs,
        {"jit", "max_parallel_workers_per_gather"},
        "pg.gucs",
    )
    _exact_keys(
        implementation,
        {
            "docker_image_digest",
            "git_commit",
            "planner_language",
            "python_version",
        },
        "implementation",
    )

    _exact_outer_mapping(
        record,
        "planner",
        {
            "planning_time_ms": None,
            "generated_templates": None,
            "rejected_templates": None,
            "costed_templates": None,
            "candidates": [],
            "chosen_estimated_cost": None,
            "chosen_rank_vs_template_oracle": None,
            "choice_reason": None,
            "level": None,
            "local_feature_vector": {},
            "parent_requirement_vector": {},
            "delivered_sigma": {},
            "rejection_reasons": {},
            "disabled_components": [],
            "planner_run_observed": False,
            "selection_authority": False,
            "execution_authority": False,
            "f3_selection_authority": False,
        },
    )
    _exact_outer_mapping(
        record,
        "static_verifier",
        {
            "status": "not_executed",
            "plan_hash": None,
            "explain_path": None,
            "reasons": [],
            "evidence_kind": "accounting_projection_no_plan",
        },
    )
    _exact_outer_mapping(
        record,
        "template",
        {
            "template_id": None,
            "alternative": None,
            "role": "no_selected_template_accounting_projection",
            "selection_authority": False,
            "execution_authority": False,
        },
    )
    _exact_outer_mapping(
        record,
        "template_applicability",
        {
            "status": "policy_not_applicable",
            "reason": "accounting_projection_has_no_selected_template",
            "selection_authority": False,
        },
    )
    _exact_outer_mapping(
        record,
        "template_oracle",
        {
            "eligible_for_template_oracle": False,
            "template_oracle_exclusion_reason": (
                "E8-COST_accounting_projection_not_selection_evidence"
            ),
        },
    )
    _exact_outer_mapping(
        record,
        "artifact_validation",
        {
            "status": "not_applicable",
            "action": "not_applicable",
            "expected_action": "not_applicable",
            "failure_sqlstate": None,
            "failure_symbol": None,
            "same_snapshot": False,
            "isolation_level": None,
            "selection_authority": False,
            "execution_authority": False,
            "record_promotion_eligible": False,
        },
    )
    _exact_outer_mapping(
        record,
        "sql",
        {
            "emitted_sql_path": None,
            "emitted_sql_hash": None,
            "normalized_sql_hash": None,
            "execution_sql_source": "not_executed",
            "selected_body_execution": False,
            "selection_authority": False,
            "execution_authority": False,
            "measurement_promotion": False,
        },
    )
    _exact_outer_mapping(
        record,
        "runtime_audit",
        {
            "status": "not_executed",
            "unauthorized_observations": None,
            "udf_calls": None,
            "client_notices": None,
            "client_errors": None,
            "audit_path": None,
            "selected_body_execution": False,
        },
    )
    _exact_outer_mapping(
        record,
        "timing_ms",
        {
            "planning": None,
            "execution": None,
            "verification": None,
            "total": None,
        },
    )
    _exact_outer_mapping(
        record,
        "result",
        {
            "row_count": None,
            "result_hash": None,
            "selection_authority": False,
            "execution_authority": False,
            "result_evidence": False,
        },
    )
    _exact_outer_mapping(
        record,
        "oracle_check",
        {
            "status": "not_applicable",
            "known_invalid_accepted": False,
            "known_valid_rejected": False,
            "oracle_kind": "not_applicable",
            "set_diff_left": None,
            "set_diff_right": None,
        },
    )
    _exact_outer_mapping(
        record,
        "counts",
        {
            "policy_evals": None,
            "residual_checks": None,
            "candidate_rows": None,
            "authorized_rows": None,
            "artifact_lookups": None,
            "base_fetches": None,
            "invalidation_count": None,
        },
    )
    _exact_outer_mapping(
        record,
        "pg_metrics",
        {
            "shared_hit_blocks": None,
            "shared_read_blocks": None,
            "temp_read_blocks": None,
            "temp_written_blocks": None,
        },
    )

    artifact_cost = _mapping(record.get("artifact_cost"), "artifact_cost")
    ordinary_cost = dict(artifact_cost)
    ordinary_cost.pop("accounting_probe", None)
    if ordinary_cost != {
        "query_only_ms": None,
        "build_ms": None,
        "refresh_ms": None,
        "storage_bytes": None,
        "amortization_model": "not_applicable",
        "Q": None,
        "U": None,
        "update_rate": None,
        "invalidated_rows": None,
        "table_pages": None,
        "index_pages": None,
        "validation_ms": None,
        "maintenance_ms_total": None,
        "fallback_ms": None,
        "refresh_policy": None,
        "refresh_unit_ms": None,
        "indexes_built": [],
        "artifact_key_encoding_version": "not_applicable",
        "amortized_latency_ms": None,
    }:
        _fail("accounting projection carries ordinary artifact-cost evidence")

    versions = _mapping(record.get("versions"), "versions")
    trusted_state = _mapping(versions.get("trusted_state"), "versions.trusted_state")
    if trusted_state != {
        "shared_body_probe_inventory_observed": 1,
        "common_accounting_observations_observed": 1,
        "case_validation_observation_observed": 1,
        "planner_selection_observed": 0,
        "selected_body_execution": 0,
        "result_equality_observed": 0,
    }:
        _fail("accounting projection trusted-state authority changed")
    if versions != {
        "base": {"document": 0},
        "membership": {"group_membership": 0},
        "policy": {str(policy.get("policy_id")): 0},
        "context": {str(context.get("context_id")): 0},
        "artifacts": {},
        "trusted_state": dict(trusted_state),
    }:
        _fail("accounting projection outer versions boundary changed")


def _classify_projection(record: Mapping[str, Any]) -> str:
    if normalize_mode_id(str(record.get("mode", ""))) != ADMISSION_FIRST_MODE:
        _fail("accounting projection must be AdmissionFirst")
    if record.get("status") != "not_executed":
        _fail("accounting projection status must be not_executed")
    if record.get("run_kind") != "normal_mode":
        _fail("accounting projection run_kind must be normal_mode")
    _validate_projection_outer_boundary(record)

    evidence = _mapping(record.get("evidence"), "evidence")
    if set(evidence) != {
        "schema",
        "role",
        "integrity_only",
        "promotion_eligible",
        "planner_choice_evidence",
        "selection_authority",
        "execution_authority",
        "result_evidence",
        "f3_selection_authority",
        "shared_probe_owner_digest",
        "projection_owner_digest",
        "projection_integrity_digest",
    }:
        _fail("accounting projection outer evidence fields changed")
    if (
        evidence.get("schema") != E8COST_PROJECTION_SCHEMA
        or evidence.get("role") != "accounting_gate_projection"
        or evidence.get("promotion_eligible") is not False
        or evidence.get("planner_choice_evidence") is not False
    ):
        _fail("accounting projection evidence identity changed")
    _authority_is_false(
        evidence,
        "evidence",
        allow_missing_production=True,
    )

    accounting = _mapping(
        _mapping(record.get("artifact_cost"), "artifact_cost").get("accounting_probe"),
        "artifact_cost.accounting_probe",
    )
    _exact_keys(
        accounting,
        E8COST_ACCOUNTING_PROBE_FIELDS,
        "artifact_cost.accounting_probe",
    )
    if (
        accounting.get("schema") != E8COST_ACCOUNTING_SCHEMA
        or accounting.get("evidence_role") != "accounting_probe_only"
    ):
        _fail("accounting projection payload identity changed")
    _authority_is_false(accounting, "artifact_cost.accounting_probe")

    body_inventory = accounting.get("body_probe_inventory")
    if (
        body_inventory.__class__ is not list
        or tuple(
            item.get("body_probe_id") if item.__class__ is dict else None
            for item in body_inventory
        )
        != E8COST_BODY_PROBE_IDS
    ):
        _fail("accounting projection body inventory changed")
    for index, body in enumerate(body_inventory):
        body = _mapping(body, f"body_probe_inventory[{index}]")
        _exact_keys(
            body,
            E8COST_BODY_PROBE_FIELDS,
            f"body_probe_inventory[{index}]",
        )
        if (
            body.get("probe_body_execution_count") != 1
            or body.get("probe_body_execution_count").__class__ is not int
            or body.get("selected_body_execution") is not False
            or body.get("ownership") != "shared_postgres_probe_inventory"
        ):
            _fail(f"body_probe_inventory[{index}] execution provenance changed")
        _authority_is_false(body, f"body_probe_inventory[{index}]")
        if not all(
            _number(body.get(field))
            for field in ("planning_ms", "execution_ms", "total_ms")
        ):
            _fail(f"body_probe_inventory[{index}] timing shape changed")
        validation = body.get("validation")
        if index < 4:
            if (
                body.get("body_kind") != "postgres_explain_analyze_query_body"
                or validation is not None
                or body.get("row_count") is not None
            ):
                _fail(f"body_probe_inventory[{index}] explain shape changed")
        else:
            if (
                body.get("body_kind") != "postgres_same_snapshot_validated_query_body"
                or body.get("row_count").__class__ is not int
                or body.get("row_count") < 0
            ):
                _fail(f"body_probe_inventory[{index}] validated shape changed")
            validation_mapping = _mapping(
                validation, f"body_probe_inventory[{index}].validation"
            )
            _exact_keys(
                validation_mapping,
                E8COST_VALIDATION_FIELDS,
                f"body_probe_inventory[{index}].validation",
            )
            if (
                validation_mapping.get("status") != "pass"
                or validation_mapping.get("failure_sqlstate") is not None
                or validation_mapping.get("failure_symbol") is not None
                or not _number(validation_mapping.get("elapsed_ms"))
                or validation_mapping.get("same_snapshot") is not True
                or validation_mapping.get("isolation_level") != "repeatable_read"
            ):
                _fail(f"body_probe_inventory[{index}] validation shape changed")

    common = _mapping(
        accounting.get("common_accounting_observations"),
        "common_accounting_observations",
    )
    _exact_keys(
        common,
        E8COST_COMMON_OBSERVATION_CONTAINER_FIELDS,
        "common_accounting_observations",
    )
    observations = common.get("observations")
    if (
        observations.__class__ is not list
        or tuple(
            item.get("observation_id") if item.__class__ is dict else None
            for item in observations
        )
        != E8COST_COMMON_OBSERVATION_IDS
    ):
        _fail("common accounting observation inventory changed")
    if (
        common.get("schema") != "e8cost_common_maintenance_storage_observations_v1"
        or common.get("ownership") != "shared_postgres_accounting_observations"
        or common.get("selected_body_execution") is not False
    ):
        _fail("common accounting observations cannot be selected execution")
    _authority_is_false(common, "common_accounting_observations")
    for index, observation in enumerate(observations):
        observation = _mapping(
            observation,
            f"common_accounting_observations.observations[{index}]",
        )
        _exact_keys(
            observation,
            E8COST_COMMON_OBSERVATION_FIELDS,
            f"common_accounting_observations.observations[{index}]",
        )
        expected_artifact_kind = ("auth_idx", "mav")[index]
        if (
            observation.get("observation_kind")
            != "postgres_maintenance_storage_observation"
            or observation.get("ownership") != "shared_postgres_accounting_observations"
            or observation.get("artifact_kind") != expected_artifact_kind
            or observation.get("build_body_execution_count") != 1
            or observation.get("refresh_body_execution_count") != 1
            or observation.get("storage_observation_count") != 1
            or observation.get("selected_body_execution") is not False
            or not all(
                _number(observation.get(field))
                for field in ("build_ms", "refresh_ms", "storage_bytes")
            )
        ):
            _fail(f"common observation {index} execution provenance changed")
        _authority_is_false(observation, f"common_observation[{index}]")

    case_validation = _mapping(
        accounting.get("case_validation_observation"),
        "case_validation_observation",
    )
    _exact_keys(
        case_validation,
        E8COST_CASE_VALIDATION_FIELDS,
        "case_validation_observation",
    )
    if (
        case_validation.get("schema") != "e8cost_case_validation_observation_v1"
        or case_validation.get("observation_id") != "case_specific_artifact_validation"
        or case_validation.get("ownership")
        != "case_specific_accounting_validation_observation"
        or case_validation.get("case_query_id")
        != _mapping(record.get("query"), "query").get("query_id")
        or case_validation.get("probe_body_execution_count") != 1
        or case_validation.get("selected_body_execution") is not False
        or not _number(case_validation.get("elapsed_ms"))
        or case_validation.get("same_snapshot") is not True
        or case_validation.get("isolation_level") != "repeatable_read"
    ):
        _fail("case validation observation provenance changed")
    if case_validation.get("status") == "pass":
        if (
            case_validation.get("failure_sqlstate") is not None
            or case_validation.get("failure_symbol") is not None
        ):
            _fail("passing case validation carries failure identity")
    elif case_validation.get("status") == "fail":
        if (
            case_validation.get("failure_sqlstate") != "P8A01"
            or case_validation.get("failure_symbol") != "CAPRLS_ARTIFACT_STALE"
        ):
            _fail("failed case validation identity changed")
    else:
        _fail("case validation status changed")
    _authority_is_false(case_validation, "case_validation_observation")

    shared_owner = _mapping(accounting.get("shared_probe_owner"), "shared_probe_owner")
    _exact_keys(shared_owner, E8COST_SHARED_OWNER_FIELDS, "shared_probe_owner")
    if (
        shared_owner.get("schema") != E8COST_SHARED_OWNER_SCHEMA
        or shared_owner.get("role") != "shared_postgres_probe_inventory"
    ):
        _fail("shared probe owner schema changed")
    _authority_is_false(shared_owner, "shared_probe_owner")
    body_digest = _digest(
        {
            "schema": "e8cost_shared_body_probe_inventory_v1",
            "body_probe_inventory": body_inventory,
        }
    )
    common_digest = _digest(
        {
            "schema": "e8cost_common_accounting_observations_digest_v1",
            "common_accounting_observations": common,
        }
    )
    if shared_owner.get("body_probe_inventory_digest") != body_digest:
        _fail("shared owner does not bind exact body inventory")
    if shared_owner.get("common_accounting_observations_digest") != common_digest:
        _fail("shared owner does not bind exact common observations")
    shared_manifest = _mapping(
        shared_owner.get("manifest"), "shared_probe_owner.manifest"
    )
    _exact_keys(
        shared_manifest,
        {"manifest_id", "manifest_hash"},
        "shared_probe_owner.manifest",
    )
    if shared_manifest != {
        "manifest_id": record.get("manifest_id"),
        "manifest_hash": record.get("manifest_hash"),
    }:
        _fail("shared owner does not bind exact manifest identity")
    shared_repetition = _mapping(
        shared_owner.get("repetition"), "shared_probe_owner.repetition"
    )
    _exact_keys(
        shared_repetition,
        {
            "phase",
            "iteration",
            "warmup_repetitions",
            "measured_repetitions",
        },
        "shared_probe_owner.repetition",
    )
    if shared_repetition != record.get("measurement"):
        _fail("shared owner does not bind exact repetition identity")
    postgres_identity = _mapping(
        shared_owner.get("postgres_identity"),
        "shared_probe_owner.postgres_identity",
    )
    _exact_keys(
        postgres_identity,
        E8COST_SHARED_POSTGRES_IDENTITY_FIELDS,
        "shared_probe_owner.postgres_identity",
    )
    postgres_gucs = _mapping(
        postgres_identity.get("gucs"),
        "shared_probe_owner.postgres_identity.gucs",
    )
    _exact_keys(
        postgres_gucs,
        {"jit", "max_parallel_workers_per_gather"},
        "shared_probe_owner.postgres_identity.gucs",
    )
    context = _mapping(record.get("context"), "context")
    policy = _mapping(record.get("policy"), "policy")
    pg = _mapping(record.get("pg"), "pg")
    for field, expected in (
        ("context_id", context.get("context_id")),
        ("ctx_hash", context.get("ctx_hash")),
        ("policy_id", policy.get("policy_id")),
        ("version", pg.get("version")),
        ("gucs", pg.get("gucs")),
    ):
        if postgres_identity.get(field) != expected:
            _fail(f"shared owner does not bind postgres {field}")
    shared_payload = dict(shared_owner)
    shared_digest = shared_payload.pop("integrity_digest", None)
    if not _sha256(shared_digest) or shared_digest != _digest(shared_payload):
        _fail("shared owner integrity digest changed")

    projection_owner = _mapping(accounting.get("projection_owner"), "projection_owner")
    _exact_keys(
        projection_owner,
        E8COST_PROJECTION_OWNER_FIELDS,
        "projection_owner",
    )
    if (
        projection_owner.get("schema") != E8COST_PROJECTION_OWNER_SCHEMA
        or projection_owner.get("role") != "accounting_projection_owner"
    ):
        _fail("projection owner schema changed")
    _authority_is_false(projection_owner, "projection_owner")
    if projection_owner.get("shared_probe_owner_digest") != shared_digest:
        _fail("projection owner does not bind shared owner")
    query = _mapping(record.get("query"), "query")
    owner_query = _mapping(projection_owner.get("query"), "projection_owner.query")
    _exact_keys(owner_query, {"query_id", "path"}, "projection_owner.query")
    if owner_query != {
        "query_id": query.get("query_id"),
        "path": query.get("path"),
    }:
        _fail("projection owner does not bind exact query")
    declared_inputs = _mapping(accounting.get("declared_inputs"), "declared_inputs")
    _exact_keys(declared_inputs, E8COST_DECLARED_INPUT_FIELDS, "declared_inputs")
    owner_declared_inputs = _mapping(
        projection_owner.get("declared_inputs"),
        "projection_owner.declared_inputs",
    )
    _exact_keys(
        owner_declared_inputs,
        E8COST_DECLARED_INPUT_FIELDS,
        "projection_owner.declared_inputs",
    )
    if owner_declared_inputs != declared_inputs:
        _fail("projection owner does not bind declared inputs")
    case_digest = _digest(
        {
            "schema": "e8cost_case_validation_observation_digest_v1",
            "case_validation_observation": case_validation,
        }
    )
    if projection_owner.get("case_validation_observation_digest") != case_digest:
        _fail("projection owner does not bind case validation")
    projection_owner_payload = dict(projection_owner)
    projection_owner_digest = projection_owner_payload.pop("integrity_digest", None)
    if not _sha256(projection_owner_digest) or projection_owner_digest != _digest(
        projection_owner_payload
    ):
        _fail("projection owner integrity digest changed")

    alternatives = accounting.get("accounting_alternatives")
    if alternatives.__class__ is not list or not alternatives:
        _fail("projection alternatives must be a non-empty exact list")
    for index, alternative in enumerate(alternatives):
        alternative = _mapping(alternative, f"accounting_alternatives[{index}]")
        _exact_keys(
            alternative,
            E8COST_ACCOUNTING_ALTERNATIVE_FIELDS,
            f"accounting_alternatives[{index}]",
        )
        _authority_is_false(alternative, f"accounting_alternatives[{index}]")
        if alternative.get("projected_action") not in {"execute", "fallback"}:
            _fail(f"accounting_alternatives[{index}] action changed")
        if (
            not alternative.get("projected_template_id")
            or not alternative.get("projected_alternative")
            or not _number(alternative.get("amortized_latency_ms"))
        ):
            _fail(f"accounting_alternatives[{index}] identity is incomplete")
        if not all(
            _number(alternative.get(field))
            for field in (
                "query_only_ms",
                "build_ms",
                "maintenance_unit_ms",
                "maintenance_ms_total",
                "fallback_ms",
                "validation_ms",
                "storage_bytes",
            )
        ):
            _fail(f"accounting_alternatives[{index}] accounting shape changed")
    minimum = _mapping(
        accounting.get("observed_accounting_minimum"),
        "observed_accounting_minimum",
    )
    _exact_keys(
        minimum,
        E8COST_ACCOUNTING_MINIMUM_FIELDS,
        "observed_accounting_minimum",
    )
    _authority_is_false(minimum, "observed_accounting_minimum")
    if not _number(minimum.get("amortized_latency_ms")):
        _fail("observed accounting minimum must carry finite accounting latency")
    expected_reason = {
        "execute": "observed_declared_q_u_accounting_minimum",
        "fallback": "metadata_stale_accounting_fallback_projection",
    }.get(minimum.get("projected_action"))
    if expected_reason is None or minimum.get("projection_reason") != expected_reason:
        _fail("observed accounting minimum action/reason identity changed")
    minimum_identity = (
        minimum.get("projected_template_id"),
        minimum.get("projected_alternative"),
        minimum.get("projected_action"),
        float(minimum.get("amortized_latency_ms")),
    )
    alternative_identities = {
        (
            alternative.get("projected_template_id"),
            alternative.get("projected_alternative"),
            alternative.get("projected_action"),
            float(alternative.get("amortized_latency_ms")),
        )
        for alternative in alternatives
    }
    if minimum_identity not in alternative_identities or minimum_identity[3] != min(
        identity[3] for identity in alternative_identities
    ):
        _fail(
            "observed accounting minimum does not match the exact minimum alternative"
        )

    projection_integrity = _mapping(
        accounting.get("projection_integrity"), "projection_integrity"
    )
    _exact_keys(
        projection_integrity,
        E8COST_PROJECTION_INTEGRITY_FIELDS,
        "projection_integrity",
    )
    if projection_integrity.get("schema") != E8COST_PROJECTION_INTEGRITY_SCHEMA:
        _fail("projection integrity schema changed")
    _authority_is_false(projection_integrity, "projection_integrity")
    if projection_integrity.get("projection_owner_digest") != projection_owner_digest:
        _fail("projection integrity does not bind projection owner")
    integrity_payload = dict(projection_integrity)
    projection_integrity_digest = integrity_payload.pop("integrity_digest", None)
    integrity_payload["accounting_alternatives"] = alternatives
    integrity_payload["observed_accounting_minimum"] = minimum
    if not _sha256(
        projection_integrity_digest
    ) or projection_integrity_digest != _digest(integrity_payload):
        _fail("projection integrity digest changed")
    for field, expected in (
        ("shared_probe_owner_digest", shared_digest),
        ("projection_owner_digest", projection_owner_digest),
        ("projection_integrity_digest", projection_integrity_digest),
    ):
        if evidence.get(field) != expected:
            _fail(f"evidence.{field} does not bind projection ownership chain")

    sql = _mapping(record.get("sql"), "sql")
    runtime = _mapping(record.get("runtime_audit"), "runtime_audit")
    result = _mapping(record.get("result"), "result")
    timing = _mapping(record.get("timing_ms"), "timing_ms")
    template = _mapping(record.get("template"), "template")
    if (
        sql.get("execution_sql_source") != "not_executed"
        or sql.get("selected_body_execution") is not False
        or runtime.get("status") != "not_executed"
        or runtime.get("selected_body_execution") is not False
        or result.get("row_count") is not None
        or result.get("result_hash") is not None
        or any(
            timing.get(field) is not None
            for field in ("planning", "execution", "total")
        )
        or template.get("template_id") is not None
        or template.get("alternative") is not None
    ):
        _fail("accounting projection ambiguously claims selected/result execution")
    return E8COST_ACCOUNTING_PROJECTION


def _classify_gate_reject(record: Mapping[str, Any]) -> str:
    mode = normalize_mode_id(str(record.get("mode", "")))
    if mode not in E8COST_GATE_REJECT_MODES:
        _fail("gate reject mode is outside the exact E8-COST gate inventory")
    validation = _mapping(record.get("artifact_validation"), "artifact_validation")
    sql = _mapping(record.get("sql"), "sql")
    timing = _mapping(record.get("timing_ms"), "timing_ms")
    oracle = _mapping(record.get("oracle_check"), "oracle_check")
    if (
        record.get("status") != "expected_reject"
        or validation.get("status") != "stale"
        or validation.get("action") != "reject"
        or validation.get("expected_action") != "reject"
        or validation.get("failure_sqlstate") != "P8A01"
        or validation.get("failure_symbol") != "CAPRLS_ARTIFACT_STALE"
        or sql.get("execution_sql_source") != "not_executed"
        or _number(timing.get("execution")) is not True
        or float(timing.get("execution")) != 0.0
        or oracle.get("known_invalid_accepted") is not False
    ):
        _fail("gate reject provenance is not exact")
    _reject_explicit_body_authority(record, "gate reject")
    return E8COST_GATE_REJECT


def _classify_result_execution(record: Mapping[str, Any]) -> str:
    mode = normalize_mode_id(str(record.get("mode", "")))
    if mode not in E8COST_RESULT_EXECUTION_MODES:
        _fail("result execution mode is outside the exact E8-COST inventory")
    if mode == ADMISSION_FIRST_MODE:
        _fail("AdmissionFirst E8-COST rows cannot be result executions")
    status = record.get("status")
    validation = _mapping(record.get("artifact_validation"), "artifact_validation")
    sql = _mapping(record.get("sql"), "sql")
    timing = _mapping(record.get("timing_ms"), "timing_ms")
    result = _mapping(record.get("result"), "result")
    oracle = _mapping(record.get("oracle_check"), "oracle_check")
    if (
        status not in {"pass", "wrong_result"}
        or validation.get("action") != "execute"
        or sql.get("execution_sql_source") not in E8COST_EXECUTED_SQL_SOURCES
        or not _number(timing.get("execution"))
        or result.get("row_count").__class__ is not int
        or result.get("row_count") < 0
        or not _sha256(result.get("result_hash"))
    ):
        _fail("result execution lacks exact SQL/body/result provenance")
    if status == "pass" and (
        oracle.get("status") != "match"
        or oracle.get("known_invalid_accepted") is not False
    ):
        _fail("passing result execution lacks exact oracle reconciliation")
    if status == "wrong_result" and (
        oracle.get("status") != "mismatch"
        or oracle.get("known_invalid_accepted") is not True
    ):
        _fail("wrong-result execution lacks exact diagnostic oracle evidence")
    if sql.get("selected_body_execution") is False:
        _fail("executed SQL cannot explicitly deny selected body execution")
    if result.get("result_evidence") is False:
        _fail("result execution cannot explicitly deny result evidence")
    return E8COST_RESULT_EXECUTION


def classify_e8_cost_evidence(record: Mapping[str, Any]) -> str | None:
    """Classify one exact E8-COST raw row or reject ambiguous provenance.

    Non-E8-COST records return ``None`` without changing any other experiment's
    reporting semantics.  The classification never treats a result hash alone
    as proof that a selected SQL body executed.
    """

    if not is_e8_cost_record(record):
        return None
    if record.get("manifest_id") not in E8COST_MANIFEST_IDS:
        _fail("E8-COST manifest identity changed")
    if record.get("run_kind") != "normal_mode":
        _fail("E8-COST evidence classification requires normal_mode")

    evidence = record.get("evidence")
    claims_projection = (
        isinstance(evidence, Mapping)
        and (
            evidence.get("schema") == E8COST_PROJECTION_SCHEMA
            or evidence.get("role") == "accounting_gate_projection"
        )
    ) or isinstance(
        _mapping(record.get("artifact_cost"), "artifact_cost").get("accounting_probe"),
        Mapping,
    )
    if claims_projection:
        return _classify_projection(record)
    if evidence not in (None, {}):
        _fail("non-projection E8-COST row carries ambiguous evidence payload")
    if normalize_mode_id(str(record.get("mode", ""))) == ADMISSION_FIRST_MODE:
        _fail("legacy AdmissionFirst E8-COST execution masquerade is forbidden")
    if record.get("status") == "expected_reject":
        return _classify_gate_reject(record)
    return _classify_result_execution(record)


# END PHASE_B2A_E8COST_EVIDENCE_CLASSIFICATION
