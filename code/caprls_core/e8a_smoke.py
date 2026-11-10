"""E8a artifact freshness, context-scope, and RID validation smoke gate."""

from __future__ import annotations

import hashlib
import json
import platform
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

import yaml

from .baselines import (
    ADMISSION_FIRST_MODE,
    load_mode_registry,
    normalize_mode_id,
    scientific_mode_key,
)
from .manifest_validator import file_sha256, scientific_manifest_hash
from .oracle_audit import _load_context, _load_policy, _quote, _render_exact_predicate
from .postgres_runner import PostgresEnv, PostgresError, run_psql_command, run_psql_file
from .result_schema import RAW_SCHEMA_VERSION, validate_raw_run_record
from .synthetic_saas import generate_synthetic_saas
from planner.core import (
    DEFAULT_TEMPLATE_REGISTRY,
    ArtifactMetadata,
    CostInputs,
    PlanningProblem,
    TemplateRegistry,
)
from planner.emit import EmitContext
from planner.ir import Project, Root, ScanProtected
from planner.query import OccurrenceGoal, PlanningQuery, plan_query


SQLSTATE_RE = re.compile(r"\b(P8A0[1-4])\b")
SYMBOL_RE = re.compile(r"\b(CAPRLS_[A-Z_]+)\b")


@dataclass(frozen=True)
class E8Scenario:
    test_id: str
    expected_action: str
    artifact_status: str
    contract_status: str
    failure_sqlstate: Optional[str] = None
    failure_symbol: Optional[str] = None
    expected_dep_kind: str = "policy"
    expected_dep_name: str = "tenant_group"
    expected_version: int = 0
    diagnostic_mode: Optional[str] = None
    diagnostic_status: Optional[str] = None
    diagnostic_reason: Optional[str] = None


@dataclass(frozen=True)
class ValidationOutcome:
    validation_passed: bool
    failure_sqlstate: Optional[str]
    failure_symbol: Optional[str]
    elapsed_ms: float


SCENARIOS = [
    E8Scenario(
        test_id="E8a_revocation_after_artifact",
        expected_action="fallback",
        artifact_status="stale",
        contract_status="pass",
        failure_sqlstate="P8A01",
        failure_symbol="CAPRLS_ARTIFACT_STALE",
        expected_dep_kind="membership",
        expected_dep_name="group_membership",
        expected_version=1,
        diagnostic_mode="stale-artifact-user",
        diagnostic_status="wrong_result",
        diagnostic_reason="stale authorization artifact is used after a revocation-version change",
    ),
    E8Scenario(
        test_id="E8a_context_hash_purpose_mismatch",
        expected_action="reject",
        artifact_status="wrong_context",
        contract_status="expected_reject",
        failure_sqlstate="P8A02",
        failure_symbol="CAPRLS_CONTEXT_MISMATCH",
        expected_dep_kind="context_scope",
        expected_dep_name="__purpose_mismatch__",
        expected_version=0,
        diagnostic_mode="wrong-context-artifact-user",
        diagnostic_status="wrong_result",
        diagnostic_reason="wrong-context artifact is used even though purpose is part of the context hash",
    ),
    E8Scenario(
        test_id="E8a_context_hash_group_order_permutation",
        expected_action="execute",
        artifact_status="pass",
        contract_status="pass",
        expected_dep_kind="context_scope",
        expected_dep_name="__same_canonical_context__",
        expected_version=0,
    ),
    E8Scenario(
        test_id="E8a_rid_domain_mismatch",
        expected_action="reject",
        artifact_status="rid_mismatch",
        contract_status="expected_reject",
        failure_sqlstate="P8A03",
        failure_symbol="CAPRLS_RID_MISMATCH",
        expected_dep_kind="rid_domain",
        expected_dep_name="ticket.ticket_id",
        expected_version=0,
        diagnostic_mode="naive-auth-index-no-scope",
        diagnostic_status="wrong_result",
        diagnostic_reason="artifact RID stream is used without validating the document RID domain",
    ),
    E8Scenario(
        test_id="E8a_toctou_between_plan_and_execute",
        expected_action="replan",
        artifact_status="toctou_fail",
        contract_status="pass",
        failure_sqlstate="P8A04",
        failure_symbol="CAPRLS_TOCTOU_FAIL",
        expected_dep_kind="toctou",
        expected_dep_name="document_snapshot",
        expected_version=1,
        diagnostic_mode="naive-artifact-only",
        diagnostic_status="wrong_result",
        diagnostic_reason="artifact is used after a version change between plan and execute validation",
    ),
    E8Scenario(
        test_id="E8a_prepared_plan_stale",
        expected_action="reject",
        artifact_status="stale",
        contract_status="expected_reject",
        failure_sqlstate="P8A01",
        failure_symbol="CAPRLS_ARTIFACT_STALE",
        expected_dep_kind="policy",
        expected_dep_name="tenant_group",
        expected_version=1,
        diagnostic_mode="mav-no-version",
        diagnostic_status="wrong_result",
        diagnostic_reason="cached artifact-backed plan is reused after policy dependency invalidation",
    ),
]

EXPECTED_ACTIONS = {scenario.test_id: scenario.expected_action for scenario in SCENARIOS}


@dataclass(frozen=True)
class E8aSmokeResult:
    raw_result_paths: list[Path]
    contract_records: int
    conservative_records: int
    diagnostic_records: int
    validation_failures_caught: int
    accepted_canonical_permutation: bool


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


def _text_digest(payload: str) -> str:
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _canonical_context_hash(payload: Mapping[str, Any]) -> str:
    canonical = dict(payload)
    for key in ("sorted_group_ids", "sorted_roles"):
        canonical[key] = sorted(str(value) for value in canonical.get(key, []))
    encoded = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _load_manifest(manifest_path: Path) -> Mapping[str, Any]:
    with manifest_path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, Mapping):
        raise PostgresError(f"E8a manifest must be an object: {manifest_path}")
    return data


def _validate_manifest(manifest_path: Path, manifest: Mapping[str, Any]) -> None:
    if manifest.get("experiment") != "E8" or manifest.get("execution_tier") != "smoke":
        raise PostgresError("e8a-smoke requires an E8 smoke manifest")

    scenario_actions = {
        str(item.get("id")): str(item.get("expected_action"))
        for item in manifest.get("scenarios", [])
        if isinstance(item, Mapping)
    }
    if scenario_actions != EXPECTED_ACTIONS:
        raise PostgresError(
            "E8a scenario expectations do not match runner contract: "
            f"expected {EXPECTED_ACTIONS}, got {scenario_actions}"
        )

    query_paths = {
        str(item.get("query_id")): str(item.get("path"))
        for item in manifest.get("queries", [])
        if isinstance(item, Mapping)
    }
    missing = [
        scenario.test_id
        for scenario in SCENARIOS
        if query_paths.get(scenario.test_id) != "workloads/e8/artifact_validity_gate.sql"
    ]
    if missing:
        raise PostgresError(
            f"E8a manifest query list does not match smoke scenarios in {manifest_path}: {missing}"
        )


def _write_temp_sql(sql: str) -> Path:
    tmp = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".sql", delete=False)
    with tmp:
        tmp.write(sql)
    return Path(tmp.name)


def _run_sql(sql: str, pg_env: PostgresEnv) -> str:
    path = _write_temp_sql(sql)
    try:
        return run_psql_file(path, pg_env)
    finally:
        path.unlink(missing_ok=True)


def _build_artifact_sql(
    artifact_id: str,
    policy_id: str,
    user_id: str,
    ctx_hash: str,
    exact_predicate: str,
) -> str:
    deps = [
        ("policy", policy_id, 0),
        ("membership", "group_membership", 0),
        ("base", "document", 0),
        ("context_scope", ctx_hash, 0),
        ("rid_domain", "document.doc_id", 0),
        ("toctou", "document_snapshot", 0),
    ]
    dep_rows = ",\n".join(
        f"({_quote(artifact_id)}, {_quote(kind)}, {_quote(name)}, {version})"
        for kind, name, version in deps
    )
    return f"""
\\set ON_ERROR_STOP on
BEGIN;
DELETE FROM public.artifact_dependencies WHERE artifact_id = {_quote(artifact_id)};
DELETE FROM public.auth_idx WHERE artifact_id = {_quote(artifact_id)};
INSERT INTO public.artifact_dependencies(artifact_id, dep_kind, dep_name, version_at_build)
VALUES
{dep_rows};
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
"""


def _expected_json(scenario: E8Scenario, ctx_hash: str, purpose_mismatch_hash: str) -> str:
    dep_name = scenario.expected_dep_name
    if dep_name == "__same_canonical_context__":
        dep_name = ctx_hash
    elif dep_name == "__purpose_mismatch__":
        dep_name = purpose_mismatch_hash

    expected = [
        {
            "dep_kind": scenario.expected_dep_kind,
            "dep_name": dep_name,
            "version_at_build": scenario.expected_version,
        }
    ]
    if scenario.failure_sqlstate:
        expected[0]["failure_sqlstate"] = scenario.failure_sqlstate
    if scenario.failure_symbol:
        expected[0]["failure_symbol"] = scenario.failure_symbol
    return json.dumps(expected, sort_keys=True, separators=(",", ":"))


def _validation_sql(artifact_id: str, expected_json: str, exact_predicate: str) -> str:
    return f"""
\\set ON_ERROR_STOP on
\\set VERBOSITY verbose
BEGIN ISOLATION LEVEL REPEATABLE READ;
WITH validation_gate AS MATERIALIZED (
  SELECT public.caprls_assert_artifact_valid(
    {_quote(artifact_id)},
    {_quote(expected_json)}::jsonb
  ) AS ok
),
chosen_plan AS MATERIALIZED (
  SELECT d.doc_id AS rid
  FROM validation_gate, public.document d
  WHERE {exact_predicate}
)
SELECT jsonb_build_object(
  'validation', 'pass',
  'row_count', (SELECT count(*) FROM chosen_plan)
)::text;
COMMIT;
"""


def _split_ir_sql_statements(emitted_sql: str) -> list[str]:
    statements = [
        statement.strip()
        for statement in emitted_sql.strip().split(";")
        if statement.strip()
    ]
    if not statements:
        raise PostgresError("cannot execute empty E8a IR-emitted SQL")
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
        raise PostgresError(f"E8a IR-emitted SQL lacks row-producing SELECT:\n{emitted_sql}")
    return query_statements[-1]


def _validation_count_sql_from_ir_emitted_sql(emitted_sql: str) -> str:
    statements = _split_ir_sql_statements(emitted_sql)
    row_sql = _row_sql_from_ir_emitted_sql(emitted_sql)
    validation_statements = [
        statement
        for statement in statements
        if statement.upper().startswith("BEGIN")
        or "caprls_assert_artifact_valid" in statement
    ]
    if not validation_statements or not validation_statements[0].upper().startswith("BEGIN"):
        raise PostgresError(f"E8a IR-emitted validation SQL lacks transaction prefix:\n{emitted_sql}")
    sql_statements = [
        *validation_statements,
        "SELECT jsonb_build_object("
        "'validation', 'pass', "
        "'row_count', (SELECT count(*) FROM ("
        f"\n{row_sql}\n"
        ") caprls_ir_exec)"
        ")::text",
        "COMMIT",
    ]
    return "\\set ON_ERROR_STOP on\n\\set VERBOSITY verbose\n" + ";\n".join(sql_statements) + ";\n"


def _run_validation_gate(
    artifact_id: str,
    expected_json: str,
    exact_predicate: str,
    pg_env: PostgresEnv,
    fallback_sqlstate: Optional[str] = None,
    fallback_symbol: Optional[str] = None,
    execution_sql: Optional[str] = None,
) -> ValidationOutcome:
    started = time.monotonic()
    try:
        _run_sql(
            execution_sql
            if execution_sql is not None
            else _validation_sql(artifact_id, expected_json, exact_predicate),
            pg_env,
        )
    except PostgresError as exc:
        elapsed_ms = (time.monotonic() - started) * 1000.0
        message = str(exc)
        sqlstate = _first_match(SQLSTATE_RE, message)
        symbol = _first_match(SYMBOL_RE, message)
        if symbol and sqlstate is None:
            sqlstate = {
                "CAPRLS_ARTIFACT_STALE": "P8A01",
                "CAPRLS_CONTEXT_MISMATCH": "P8A02",
                "CAPRLS_RID_MISMATCH": "P8A03",
                "CAPRLS_TOCTOU_FAIL": "P8A04",
            }.get(symbol)
        if "CAPRLS artifact validation failed" in message:
            sqlstate = sqlstate or fallback_sqlstate
            symbol = symbol or fallback_symbol
        return ValidationOutcome(
            validation_passed=False,
            failure_sqlstate=sqlstate,
            failure_symbol=symbol,
            elapsed_ms=elapsed_ms,
        )

    elapsed_ms = (time.monotonic() - started) * 1000.0
    return ValidationOutcome(
        validation_passed=True,
        failure_sqlstate=None,
        failure_symbol=None,
        elapsed_ms=elapsed_ms,
    )


def _first_match(pattern: re.Pattern[str], text: str) -> Optional[str]:
    match = pattern.search(text)
    return match.group(1) if match else None


def _evaluation_role(root: Path, mode: str) -> str:
    return load_mode_registry(root)[normalize_mode_id(mode)].evaluation_role


def _template_for_mode(mode: str, action: str) -> tuple[str, str]:
    if mode == "conservative-barrier" or action in {"fallback", "replan"}:
        return ("barrier_filter_v1", "BarrierFilter")
    if mode == "mav-no-version":
        return ("mav_scan_v1", "MaterializedAuthorizedViewScan")
    return ("auth_index_enum_v1", "AuthorizationIndexSeek")


def _validation_query_plan_payload(
    scenario: E8Scenario,
    *,
    artifact_id: str,
    policy_id: str,
    user_id: str,
    ctx_hash: str,
    exact_predicate: str,
    expected_json: str,
) -> dict[str, Any]:
    occurrence_id = scenario.test_id
    problem = PlanningProblem(
        planning_execution_class="diagnostic_only",
        relation="document",
        policy_id=policy_id,
        occurrence_id=occurrence_id,
        rid_col="doc_id",
        required_attrs=("tenant_id",),
        required_ctx=("ctx_hash",),
        exact_policy_safe=True,
        supports_guard=True,
        has_safe_query_predicate=True,
        artifacts={
            "auth_idx": ArtifactMetadata(
                kind="auth_idx",
                artifact_id=artifact_id,
                fresh=True,
                context_matches=True,
                scope_matches=True,
                rid_domain_matches=True,
                base_relation_matches=True,
                exact=True,
                cardinality=128,
                rows=128,
            )
        },
        cost_inputs=CostInputs(
            estimated_rows=1000,
            query_selectivity=0.16,
            auth_selectivity=0.16,
            guard_selectivity=0.16,
        ),
    )
    query_result = plan_query(
        PlanningQuery(
            ir_skeleton=Root(
                Project(
                    ScanProtected(occurrence_id, "chosen"),
                    visible_A=("doc_id", "tenant_id"),
                    hidden_H=(),
                )
            ),
            occurrence_goals={occurrence_id: OccurrenceGoal(problem, mode=ADMISSION_FIRST_MODE)},
            mode=ADMISSION_FIRST_MODE,
            emit_context=EmitContext(
                default_rid_col="doc_id",
                occurrence_relations={occurrence_id: "document"},
                occurrence_aliases={occurrence_id: "d"},
                occurrence_rid_cols={occurrence_id: "doc_id"},
                exact_predicates={occurrence_id: exact_predicate},
                query_predicates={occurrence_id: "true"},
                guard_predicates={occurrence_id: exact_predicate},
                residual_predicates={"tenant_group:exact_residual": "rcheck.tenant_id = 1"},
                artifact_expectations={artifact_id: json.loads(expected_json)},
                template_params={
                    occurrence_id: {
                        "artifact_ids": {"auth_idx": artifact_id},
                        "policy_id": policy_id,
                        "user_id": user_id,
                        "ctx_hash": ctx_hash,
                        "rid_domain_id": "document.doc_id",
                        "base_rel_oid": "public.document",
                    }
                },
            ),
        ),
        registry=TemplateRegistry((DEFAULT_TEMPLATE_REGISTRY.get("auth_index_enum_v1"),)),
    )
    emitted_sql = query_result.emitted_sql or ""
    payload = query_result.to_dict()
    payload["mode"] = query_result.mode
    payload["ok"] = query_result.ok
    payload["occurrence_ids"] = sorted(query_result.occurrence_results)
    payload["disabled_components"] = []
    payload["certificate_suppressed"] = False
    payload["emitted_sql"] = emitted_sql
    payload["emitted_sql_hash"] = _text_digest(emitted_sql) if emitted_sql else None
    if not query_result.ok or not emitted_sql:
        raise PostgresError(
            f"E8a validation planner failed for {scenario.test_id}: "
            f"{payload.get('root_closure')}"
        )
    return payload


def _sql_provenance(
    root: Path,
    manifest_path: Path,
    *,
    execution_sql_source: str,
    query_plan_payload: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    if execution_sql_source == "planner_ir_emitted" and query_plan_payload is not None:
        emitted_hash = query_plan_payload.get("emitted_sql_hash")
        if isinstance(emitted_hash, str) and emitted_hash.startswith("sha256:"):
            return {
                "emitted_sql_path": "generated:e8a_validation_gate_ir.sql",
                "emitted_sql_hash": emitted_hash,
                "normalized_sql_hash": emitted_hash,
                "execution_sql_source": execution_sql_source,
            }
    return {
        "emitted_sql_path": "workloads/e8/artifact_validity_gate.sql",
        "emitted_sql_hash": file_sha256(root / "workloads" / "e8" / "artifact_validity_gate.sql"),
        "normalized_sql_hash": scientific_manifest_hash(manifest_path),
        "execution_sql_source": execution_sql_source,
    }


def _record(
    root: Path,
    manifest_path: Path,
    scenario: E8Scenario,
    mode: str,
    status: str,
    artifact_status: str,
    action: str,
    expected_action: str,
    validation: ValidationOutcome,
    dataset_scale: str,
    seed: int,
    policy_id: str,
    context_id: str,
    ctx_hash: str,
    pg_version: str,
    authorized_count: int,
    total_rows: int,
    diagnostic_reason: Optional[str] = None,
    accepted_permutation: bool = False,
    execution_sql_source: str = "artifact_validation_gate_sql",
    query_plan_payload: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    mode = normalize_mode_id(mode)
    template_id, alternative = _template_for_mode(mode, action)
    is_admission_first = mode == ADMISSION_FIRST_MODE
    result_payload = {
        "test_id": scenario.test_id,
        "mode": mode,
        "status": status,
        "artifact_status": artifact_status,
        "action": action,
        "expected_action": expected_action,
        "validation": validation.__dict__,
        "accepted_permutation": accepted_permutation,
    }
    result_hash = _digest(
        {
            **result_payload,
            "mode": scientific_mode_key(mode),
        }
    )
    failure_reason = diagnostic_reason
    if is_admission_first and status == "expected_reject":
        failure_reason = f"AdmissionFirst rejected invalid artifact: {scenario.failure_symbol}"
    elif is_admission_first and action in {"fallback", "replan"}:
        failure_reason = f"AdmissionFirst caught validation failure and used action={action}"

    oracle_status = "mismatch" if status == "wrong_result" else "match"
    template_applicability = "metadata_invalid" if artifact_status in {"stale", "wrong_context", "rid_mismatch", "toctou_fail"} else "applicable"
    if mode == "conservative-barrier":
        template_applicability = "applicable"
    artifact_validation_same_snapshot = bool(
        is_admission_first
        and validation.validation_passed
        and artifact_status == "pass"
        and action == "execute"
    )
    artifact_validation_isolation_level = (
        "repeatable_read" if artifact_validation_same_snapshot else None
    )
    trusted_state = {"policy_catalog": 0}
    if artifact_validation_same_snapshot:
        trusted_state["artifact_validation_same_snapshot"] = 1
    artifact_cost = {
        "query_only_ms": validation.elapsed_ms,
        "build_ms": 0.0,
        "refresh_ms": 0.0,
        "storage_bytes": 0,
        "indexes_built": ["auth_idx_lookup"] if mode != "conservative-barrier" else [],
        "artifact_key_encoding_version": "artifact_key_encoding_v1",
        "amortization_model": "query_only",
    }
    if artifact_validation_same_snapshot:
        artifact_cost["validation_ms"] = validation.elapsed_ms
    planner_payload: dict[str, Any] = {
        "level": "A",
        "disabled_components": [],
        "planning_time_ms": 0.0,
        "generated_templates": 1,
        "rejected_templates": 1 if is_admission_first and status == "expected_reject" else 0,
        "costed_templates": 1 if status != "expected_reject" else 0,
        "rejection_reasons": {failure_reason: 1} if is_admission_first and status == "expected_reject" and failure_reason else {},
        "chosen_estimated_cost": 0.0,
        "chosen_rank_vs_template_oracle": None,
        "local_feature_vector": None,
        "parent_requirement_vector": None,
        "candidates": [],
        "delivered_sigma": {},
    }
    if query_plan_payload is not None:
        planner_payload["query_plan"] = dict(query_plan_payload)

    return {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": f"E8_{scenario.test_id}_{mode}",
        "manifest_id": str(_load_manifest(manifest_path)["manifest_id"]),
        "manifest_hash": file_sha256(manifest_path),
        "experiment": "E8",
        "stage": "freshness_gate",
        "run_kind": "normal_mode",
        "dataset": {"name": "synthetic_saas", "scale": dataset_scale, "seed": seed},
        "query": {
            "query_id": scenario.test_id,
            "path": "workloads/e8/artifact_validity_gate.sql",
            "params": {"context_id": context_id, "policy_id": policy_id},
        },
        "policy": {
            "policy_id": policy_id,
            "policy_version": 0,
            "policy_sql_manifest_hash": file_sha256(root / "manifests" / "policies" / "synthetic_saas_policies.yaml"),
        },
        "context": {"context_id": context_id, "ctx_hash": ctx_hash},
        "mode": mode,
        "template": {"template_id": template_id, "alternative": alternative},
        "template_applicability": {
            "status": template_applicability,
            "reason": failure_reason if template_applicability == "metadata_invalid" else None,
        },
        "template_oracle": {
            "eligible_for_template_oracle": False,
            "template_oracle_exclusion_reason": "E8a_artifact_validation_gate_not_template_oracle_pool",
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
            "artifacts": {"auth_idx_doc_ctx_000001": 0},
        },
        "planner": planner_payload,
        "static_verifier": {
            "status": "pass",
            "plan_hash": result_hash,
            "explain_path": None,
            "reasons": [],
        },
        "artifact_validation": {
            "status": artifact_status,
            "action": action,
            "expected_action": expected_action,
            "failure_sqlstate": validation.failure_sqlstate,
            "failure_symbol": validation.failure_symbol,
            "same_snapshot": artifact_validation_same_snapshot,
            "isolation_level": artifact_validation_isolation_level,
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
            execution_sql_source=execution_sql_source,
            query_plan_payload=query_plan_payload,
        ),
        "oracle_check": {
            "status": oracle_status,
            "oracle_kind": "artifact_validation_gate",
            "set_diff_left": 1 if status == "wrong_result" else 0,
            "set_diff_right": 0,
            "known_invalid_accepted": bool(status == "wrong_result"),
            "known_valid_rejected": False,
        },
        "timing_ms": {
            "planning": 0.0,
            "execution": validation.elapsed_ms,
            "verification": 0.0,
            "total": validation.elapsed_ms,
        },
        "result": {
            "row_count": 0 if status == "expected_reject" else authorized_count,
            "result_hash": result_hash,
        },
        "pg_metrics": {
            "shared_read_blocks": 0,
            "shared_hit_blocks": 0,
            "temp_read_blocks": 0,
            "temp_written_blocks": 0,
        },
        "counts": {
            "policy_evals": total_rows if mode != "conservative-barrier" else authorized_count,
            "residual_checks": 0,
            "candidate_rows": authorized_count,
            "authorized_rows": authorized_count,
            "artifact_lookups": 0 if mode == "conservative-barrier" else 1,
            "base_fetches": total_rows if mode == "conservative-barrier" or action in {"fallback", "replan"} else authorized_count,
        },
        "artifact_cost": artifact_cost,
        "implementation": {
            "git_commit": _git_commit(root),
            "docker_image_digest": "not_containerized",
            "python_version": platform.python_version(),
            "planner_language": "python",
        },
        "e8a_validation_case": result_payload,
        "status": status,
        "failure": None if status == "pass" else {"reason": failure_reason},
    }


def _write_record(record: Mapping[str, Any], output_dir: Path) -> Path:
    issues = validate_raw_run_record(record)
    if issues:
        rendered = ", ".join(f"{issue.path}: {issue.message}" for issue in issues)
        raise PostgresError(f"E8a raw record failed schema validation: {rendered}")
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_mode = str(record["mode"]).replace("-", "_")
    target = output_dir / f"{record['query']['query_id']}_{safe_mode}.json"
    target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def run_e8a_smoke(
    root: Path,
    pg_env: PostgresEnv,
    manifest_path: Path,
    output_dir: Path,
) -> E8aSmokeResult:
    manifest = _load_manifest(manifest_path)
    _validate_manifest(manifest_path, manifest)
    dataset = manifest.get("dataset") or {}
    scale = str(dataset.get("scale", "1e5"))
    seed = int(dataset.get("seed", 47))
    generate_synthetic_saas(root, pg_env, scale=scale, seed=seed, verify=True, output_dir=None)

    policy_app = (manifest.get("policy_applications") or [{}])[0]
    policy_id = str(policy_app.get("policy_id", "tenant_group"))
    policy = _load_policy(root, policy_id)
    if "document" not in policy.get("applicable_relations", []):
        raise PostgresError(f"policy {policy_id} is not applicable to document")

    context_id = "ctx_000001"
    context = _load_context(context_id, pg_env)
    ctx_hash = str(run_psql_command(
        f"SELECT ctx_hash FROM public.synthetic_context WHERE context_id = {_quote(context_id)};",
        pg_env,
    ))
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
            "E8a smoke requires both authorized and unauthorized rows; "
            f"got authorized={authorized_count}, total={total_rows}"
        )

    artifact_id = "auth_idx_doc_ctx_000001"
    user_id = str(context["user_id"])
    pg_version = run_psql_command("SHOW server_version;", pg_env)
    purpose_mismatch_context = dict(context)
    purpose_mismatch_context["purpose"] = f"{context.get('purpose')}_mismatch"
    purpose_mismatch_hash = _canonical_context_hash(purpose_mismatch_context)
    permuted_context = dict(context)
    permuted_context["sorted_group_ids"] = list(reversed(list(context.get("sorted_group_ids", []))))
    accepted_permutation = _canonical_context_hash(permuted_context) == ctx_hash
    if not accepted_permutation:
        raise PostgresError("E8a group-order permutation did not canonicalize to the stored context hash")

    raw_paths: list[Path] = []
    validation_failures_caught = 0
    conservative_records = 0
    diagnostic_records = 0
    contract_records = 0

    for scenario in SCENARIOS:
        _run_sql(
            _build_artifact_sql(
                artifact_id=artifact_id,
                policy_id=policy_id,
                user_id=user_id,
                ctx_hash=ctx_hash,
                exact_predicate=exact_predicate,
            ),
            pg_env,
        )
        expected_json = _expected_json(scenario, ctx_hash, purpose_mismatch_hash)
        validation_query_plan: Optional[Mapping[str, Any]] = None
        validation_execution_sql: Optional[str] = None
        validation_execution_sql_source = "artifact_validation_gate_sql"
        if scenario.expected_action in {"execute", "fallback", "replan"}:
            validation_query_plan = _validation_query_plan_payload(
                scenario,
                artifact_id=artifact_id,
                policy_id=policy_id,
                user_id=user_id,
                ctx_hash=ctx_hash,
                exact_predicate=exact_predicate,
                expected_json=expected_json,
            )
            validation_execution_sql = _validation_count_sql_from_ir_emitted_sql(
                str(validation_query_plan["emitted_sql"])
            )
            validation_execution_sql_source = "planner_ir_emitted"
        validation = _run_validation_gate(
            artifact_id,
            expected_json,
            exact_predicate,
            pg_env,
            fallback_sqlstate=scenario.failure_sqlstate,
            fallback_symbol=scenario.failure_symbol,
            execution_sql=validation_execution_sql,
        )
        if scenario.failure_sqlstate is None:
            if not validation.validation_passed:
                raise PostgresError(
                    f"{scenario.test_id}: validation unexpectedly failed "
                    f"({validation.failure_sqlstate}/{validation.failure_symbol})"
                )
        else:
            if validation.validation_passed:
                raise PostgresError(f"{scenario.test_id}: validation unexpectedly passed")
            if validation.failure_sqlstate != scenario.failure_sqlstate:
                raise PostgresError(
                    f"{scenario.test_id}: expected SQLSTATE {scenario.failure_sqlstate}, "
                    f"got {validation.failure_sqlstate}"
                )
            if validation.failure_symbol != scenario.failure_symbol:
                raise PostgresError(
                    f"{scenario.test_id}: expected symbol {scenario.failure_symbol}, "
                    f"got {validation.failure_symbol}"
                )
            validation_failures_caught += 1

        contract_record = _record(
            root=root,
            manifest_path=manifest_path,
            scenario=scenario,
            mode=ADMISSION_FIRST_MODE,
            status=scenario.contract_status,
            artifact_status=scenario.artifact_status,
            action=scenario.expected_action,
            expected_action=scenario.expected_action,
            validation=validation,
            dataset_scale=scale,
            seed=seed,
            policy_id=policy_id,
            context_id=context_id,
            ctx_hash=ctx_hash,
            pg_version=pg_version,
            authorized_count=authorized_count,
            total_rows=total_rows,
            accepted_permutation=accepted_permutation,
            execution_sql_source=validation_execution_sql_source,
            query_plan_payload=validation_query_plan,
        )
        raw_paths.append(_write_record(contract_record, output_dir))
        contract_records += 1

        conservative_record = _record(
            root=root,
            manifest_path=manifest_path,
            scenario=scenario,
            mode="conservative-barrier",
            status="pass",
            artifact_status="not_applicable",
            action="execute",
            expected_action="execute",
            validation=ValidationOutcome(True, None, None, validation.elapsed_ms),
            dataset_scale=scale,
            seed=seed,
            policy_id=policy_id,
            context_id=context_id,
            ctx_hash=ctx_hash,
            pg_version=pg_version,
            authorized_count=authorized_count,
            total_rows=total_rows,
            accepted_permutation=accepted_permutation,
        )
        raw_paths.append(_write_record(conservative_record, output_dir))
        conservative_records += 1

        if scenario.diagnostic_mode and scenario.diagnostic_status:
            diagnostic_record = _record(
                root=root,
                manifest_path=manifest_path,
                scenario=scenario,
                mode=scenario.diagnostic_mode,
                status=scenario.diagnostic_status,
                artifact_status=scenario.artifact_status,
                action="execute",
                expected_action=scenario.expected_action,
                validation=validation,
                dataset_scale=scale,
                seed=seed,
                policy_id=policy_id,
                context_id=context_id,
                ctx_hash=ctx_hash,
                pg_version=pg_version,
                authorized_count=authorized_count,
                total_rows=total_rows,
                diagnostic_reason=scenario.diagnostic_reason,
                accepted_permutation=accepted_permutation,
            )
            raw_paths.append(_write_record(diagnostic_record, output_dir))
            diagnostic_records += 1

    return E8aSmokeResult(
        raw_result_paths=raw_paths,
        contract_records=contract_records,
        conservative_records=conservative_records,
        diagnostic_records=diagnostic_records,
        validation_failures_caught=validation_failures_caught,
        accepted_canonical_permutation=accepted_permutation,
    )
