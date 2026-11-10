"""Manifest-driven E7 direct-observation runtime audit smoke gate."""

from __future__ import annotations

import hashlib
import json
import platform
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

import yaml

from .baselines import (
    ADMISSION_FIRST_MODE,
    load_mode_registry,
    normalize_mode_id,
    scientific_mode_key,
)
from .manifest_validator import file_sha256, scientific_manifest_hash
from .oracle_audit import (
    _load_context,
    _load_policy,
    _quote,
    _render_exact_predicate,
    _write_temp_sql,
)
from .postgres_runner import PostgresEnv, PostgresError, run_psql_command, run_psql_file
from .result_schema import RAW_SCHEMA_VERSION, validate_raw_run_record
from .synthetic_saas import generate_synthetic_saas
from planner.core import (
    DEFAULT_TEMPLATE_REGISTRY,
    ParentRequirement,
    PlanningProblem,
    TemplateRegistry,
)
from planner.ir import Root, ScanProtected, UnsafeExpr
from planner.query import OccurrenceGoal, PlanningQuery, plan_query


@dataclass(frozen=True)
class E7Case:
    test_id: str
    mode: str
    query_path: str
    template_id: str
    alternative: str
    expected: str
    status: str
    static_status: str = "pass"
    template_applicability: str = "applicable"
    failure_reason: Optional[str] = None
    forced_diagnostic_execution: bool = False


@dataclass(frozen=True)
class E7Observation:
    udf_calls: int
    unauthorized_observations: int
    client_errors: int = 0
    client_notices: int = 0


E7_CASES = [
    E7Case(
        test_id="E7_contract_unsafe_where",
        mode=ADMISSION_FIRST_MODE,
        query_path="workloads/e7/unsafe_where.sql",
        template_id="barrier_filter_v1",
        alternative="BarrierFilter",
        expected="zero_unauthorized_observations",
        status="pass",
    ),
    E7Case(
        test_id="E7_positive_raw_pushdown",
        mode="unsafe-pushdown-positive-control",
        query_path="workloads/e7/unsafe_where.sql",
        template_id="raw_pushdown_positive_control_v1",
        alternative="UnsafeRawPushdownPositiveControl",
        expected="unauthorized_observations",
        status="unsafe_observation",
        failure_reason="diagnostic unsafe pushdown observed protected rows before exact authorization",
    ),
    E7Case(
        test_id="E7_guard_late_before_unsafe",
        mode="guard-late-only",
        query_path="workloads/e7/unsafe_where.sql",
        template_id="guard_candidate_plus_residual_v1",
        alternative="Guard+LateResidual",
        expected="unsafe_observation_or_verifier_reject",
        status="static_verifier_fail",
        static_status="fail",
        template_applicability="contract_reject",
        failure_reason="GuardLateOnly is rejected when an unsafe expression would run before residual discharge",
        forced_diagnostic_execution=True,
    ),
    E7Case(
        test_id="E7_guard_mandatory_discharge",
        mode="guard-mandatory-discharge",
        query_path="workloads/e7/unsafe_where.sql",
        template_id="guard_candidate_plus_residual_v1",
        alternative="GuardMandatoryDischarge",
        expected="zero_unauthorized_observations",
        status="pass",
    ),
    E7Case(
        test_id="E7_unsafe_throw",
        mode="unsafe-pushdown-positive-control",
        query_path="workloads/e7/unsafe_throw.sql",
        template_id="unsafe_throw_positive_control_v1",
        alternative="UnsafeThrowPositiveControl",
        expected="client_error_or_notice_captured",
        status="unsafe_observation",
        failure_reason="diagnostic unsafe_throw raised a client-visible error on an unauthorized sentinel",
    ),
]

EXPECTED_E7_SMOKE = {case.test_id: case.expected for case in E7_CASES}


@dataclass(frozen=True)
class E7SmokeResult:
    raw_result_paths: list[Path]
    authorized_count: int
    total_rows: int
    contract_unauthorized_observations: int
    positive_unauthorized_observations: int
    guard_late_unauthorized_observations: int
    mandatory_unauthorized_observations: int
    throw_client_errors: int


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


def _text_digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _load_manifest(manifest_path: Path) -> Mapping[str, Any]:
    with manifest_path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, Mapping):
        raise PostgresError(f"E7 manifest must be an object: {manifest_path}")
    return data


def _validate_manifest(manifest_path: Path, manifest: Mapping[str, Any]) -> None:
    if manifest.get("experiment") != "E7" or manifest.get("execution_tier") != "smoke":
        raise PostgresError("e7-smoke requires an E7 smoke manifest")

    expected = {
        str(item.get("test_id")): str(item.get("expected"))
        for item in manifest.get("smoke_expectations", [])
        if isinstance(item, Mapping)
    }
    if expected != EXPECTED_E7_SMOKE:
        raise PostgresError(
            "E7 smoke expectations do not match runner contract: "
            f"expected {EXPECTED_E7_SMOKE}, got {expected}"
        )

    query_paths = {
        str(item.get("query_id")): str(item.get("path"))
        for item in manifest.get("queries", [])
        if isinstance(item, Mapping)
    }
    missing = [
        case.test_id
        for case in E7_CASES
        if query_paths.get(case.test_id) != case.query_path
    ]
    if missing:
        raise PostgresError(
            f"E7 manifest query list does not match smoke cases in {manifest_path}: {missing}"
        )


def _audit_projection(run_id: str) -> str:
    return f"""
SELECT
  {_quote(run_id)}::text AS run_id,
  count(*)::bigint AS udf_calls,
  count(*) FILTER (WHERE o.rid IS NULL)::bigint AS unauthorized_observations
FROM public.udf_audit a
LEFT JOIN oracle_authorized o ON o.rid = a.rid
WHERE a.run_id = {_quote(run_id)}
  AND a.occurrence_id = 'document_occ_1'
"""


def _runtime_log_script(exact_predicate: str, guard_predicate: str, context_id: str) -> str:
    contract_run = f"e7_{context_id}_contract"
    positive_run = f"e7_{context_id}_positive"
    guard_run = f"e7_{context_id}_guard_late"
    mandatory_run = f"e7_{context_id}_mandatory"
    return f"""
\\set ON_ERROR_STOP on
SET jit = off;
SET max_parallel_workers_per_gather = 0;
TRUNCATE public.udf_audit;
DROP TABLE IF EXISTS pg_temp.oracle_authorized;
CREATE TEMP TABLE oracle_authorized AS
SELECT d.doc_id AS rid
FROM public.document d
WHERE {exact_predicate};
CREATE UNIQUE INDEX oracle_authorized_rid_idx ON oracle_authorized(rid);

WITH auth AS MATERIALIZED (
  SELECT d.*, d.doc_id AS __rid
  FROM public.document d
  WHERE {exact_predicate}
)
SELECT count(*)
FROM auth
WHERE public.unsafe_log({_quote(contract_run)}, 'E7_contract_unsafe_where', 'contract_barrier_exact', 'document_occ_1', __rid, secret);

CREATE TEMP TABLE contract_audit AS
{_audit_projection(contract_run)};

TRUNCATE public.udf_audit;
WITH raw AS MATERIALIZED (
  SELECT d.*,
         d.doc_id AS __rid,
         public.unsafe_log({_quote(positive_run)}, 'E7_positive_raw_pushdown', 'raw_pushdown_positive_control', 'document_occ_1', d.doc_id, d.secret) AS observed
  FROM public.document d
)
SELECT count(*)
FROM raw d
WHERE observed
  AND {exact_predicate};

CREATE TEMP TABLE positive_audit AS
{_audit_projection(positive_run)};

TRUNCATE public.udf_audit;
WITH guard_candidate AS MATERIALIZED (
  SELECT d.*,
         d.doc_id AS __rid,
         public.unsafe_log({_quote(guard_run)}, 'E7_guard_late_before_unsafe', 'guard_late_forced_diagnostic', 'document_occ_1', d.doc_id, d.secret) AS observed
  FROM public.document d
  WHERE {guard_predicate}
)
SELECT count(*)
FROM guard_candidate d
WHERE observed
  AND {exact_predicate};

CREATE TEMP TABLE guard_late_audit AS
{_audit_projection(guard_run)};

TRUNCATE public.udf_audit;
WITH discharged AS MATERIALIZED (
  SELECT d.*, d.doc_id AS __rid
  FROM public.document d
  WHERE {exact_predicate}
),
observed AS MATERIALIZED (
  SELECT d.*,
         public.unsafe_log({_quote(mandatory_run)}, 'E7_guard_mandatory_discharge', 'guard_mandatory_discharge', 'document_occ_1', d.__rid, d.secret) AS observed
  FROM discharged d
)
SELECT count(*)
FROM observed
WHERE observed;

CREATE TEMP TABLE mandatory_audit AS
{_audit_projection(mandatory_run)};

SELECT jsonb_build_object(
  'context_id', {_quote(context_id)},
  'authorized_count', (SELECT count(*) FROM oracle_authorized),
  'total_rows', (SELECT count(*) FROM public.document),
  'contract', (SELECT to_jsonb(contract_audit) FROM contract_audit),
  'positive', (SELECT to_jsonb(positive_audit) FROM positive_audit),
  'guard_late', (SELECT to_jsonb(guard_late_audit) FROM guard_late_audit),
  'mandatory', (SELECT to_jsonb(mandatory_audit) FROM mandatory_audit)
)::text;
"""


def _throw_script(exact_predicate: str, context_id: str) -> str:
    throw_run = f"e7_{context_id}_unsafe_throw"
    return f"""
\\set ON_ERROR_STOP on
SET jit = off;
SET max_parallel_workers_per_gather = 0;
DROP TABLE IF EXISTS pg_temp.oracle_authorized;
CREATE TEMP TABLE oracle_authorized AS
SELECT d.doc_id AS rid
FROM public.document d
WHERE {exact_predicate};

WITH sentinel AS MATERIALIZED (
  SELECT d.secret
  FROM public.document d
  LEFT JOIN oracle_authorized o ON o.rid = d.doc_id
  WHERE o.rid IS NULL
  ORDER BY d.doc_id
  LIMIT 1
),
raw AS MATERIALIZED (
  SELECT d.doc_id,
         public.unsafe_throw(
           {_quote(throw_run)},
           'E7_unsafe_throw',
           'unsafe_throw_positive_control',
           'document_occ_1',
           d.doc_id,
           d.secret,
           (SELECT secret FROM sentinel)
         ) AS observed
  FROM public.document d
)
SELECT count(*)
FROM raw
WHERE observed;
"""


def _run_json_script(sql: str, pg_env: PostgresEnv) -> Mapping[str, Any]:
    path = _write_temp_sql(sql)
    try:
        stdout = run_psql_file(path, pg_env)
    finally:
        path.unlink(missing_ok=True)
    payload = ""
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            payload = stripped
    if not payload:
        raise PostgresError(f"E7 smoke SQL did not emit JSON:\n{stdout}")
    return json.loads(payload)


def _run_throw_script(sql: str, pg_env: PostgresEnv) -> E7Observation:
    path = _write_temp_sql(sql)
    try:
        run_psql_file(path, pg_env)
    except PostgresError as exc:
        message = str(exc)
        if "CAPRLS unsafe_throw observed sentinel" not in message:
            raise
        return E7Observation(
            udf_calls=1,
            unauthorized_observations=1,
            client_errors=1,
            client_notices=0,
        )
    finally:
        path.unlink(missing_ok=True)
    raise PostgresError("E7 unsafe_throw positive control did not raise the expected error")


def _observation(payload: Mapping[str, Any]) -> E7Observation:
    return E7Observation(
        udf_calls=int(payload["udf_calls"]),
        unauthorized_observations=int(payload["unauthorized_observations"]),
    )


def _evaluation_role(root: Path, mode: str) -> str:
    return load_mode_registry(root)[normalize_mode_id(mode)].evaluation_role


def _planner_evidence_for_case(case: E7Case) -> Optional[Dict[str, Any]]:
    if case.status != "pass":
        return None

    template = DEFAULT_TEMPLATE_REGISTRY.get(case.template_id)
    parent_requirement = ParentRequirement(
        unsafe_expression_boundary=True,
        allowed_enforcers=("residual_check",),
    )
    is_guard = case.template_id == "guard_candidate_plus_residual_v1"
    problem = PlanningProblem(
        planning_execution_class="diagnostic_only",
        relation="document",
        policy_id="tenant_group",
        occurrence_id="document_occ_1",
        rid_col="doc_id",
        required_attrs=("tenant_id", "purpose") if is_guard else (),
        exact_policy_safe=True,
        supports_guard=is_guard,
        has_safe_query_predicate=is_guard,
        parent_requirement=parent_requirement,
    )
    query_result = plan_query(
        PlanningQuery(
            ir_skeleton=Root(
                UnsafeExpr(
                    ScanProtected("document_occ_1", "chosen"),
                    expr_label=case.test_id,
                ),
                rho_root={
                    "unsafe_expression_boundary": True,
                    "allowed_enforcers": ["residual_check"],
                },
            ),
            occurrence_goals={"document_occ_1": OccurrenceGoal(problem)},
            mode=normalize_mode_id(case.mode),
        ),
        registry=TemplateRegistry((template,)),
    )
    occurrence = query_result.occurrence_results["document_occ_1"]
    chosen = occurrence.chosen_template
    if not query_result.ok or chosen is None or chosen.template_id != case.template_id:
        raise PostgresError(f"E7 planner evidence did not admit expected template {case.template_id}")
    query_payload = query_result.to_dict()
    emitted_sql = query_result.emitted_sql or ""
    query_payload["ok"] = query_result.ok
    query_payload["emitted_sql_hash"] = _text_digest(emitted_sql) if emitted_sql else None
    return {
        "occurrence": occurrence.to_dict(),
        "query_plan": query_payload,
    }


def _record(
    root: Path,
    manifest_path: Path,
    case: E7Case,
    observation: E7Observation,
    authorized_count: int,
    total_rows: int,
    scale: str,
    seed: int,
    policy_id: str,
    context_id: str,
    pg_version: str,
    elapsed_ms: float,
) -> Dict[str, Any]:
    mode = normalize_mode_id(case.mode)
    runtime_status = (
        "fail"
        if observation.unauthorized_observations > 0 or observation.client_errors > 0
        else "pass"
    )
    static_reasons = [case.failure_reason] if case.static_status != "pass" and case.failure_reason else []
    row_count = 0 if observation.client_errors else authorized_count
    payload = {
        "test_id": case.test_id,
        "mode": mode,
        "expected": case.expected,
        "status": case.status,
        "authorized_count": authorized_count,
        "total_rows": total_rows,
        "observation": observation.__dict__,
        "static_status": case.static_status,
        "forced_diagnostic_execution": case.forced_diagnostic_execution,
    }
    result_hash = _digest(
        {
            **payload,
            "mode": scientific_mode_key(mode),
        }
    )
    failure = None
    if case.status != "pass":
        failure = {
            "reason": case.failure_reason,
            "expected_by_e7_smoke": case.expected,
        }
    planner_evidence = _planner_evidence_for_case(case)
    occurrence_planner = planner_evidence["occurrence"] if planner_evidence else {}
    query_plan = planner_evidence["query_plan"] if planner_evidence else None
    return {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": f"E7_{case.test_id}_{mode}",
        "manifest_id": str(_load_manifest(manifest_path)["manifest_id"]),
        "manifest_hash": file_sha256(manifest_path),
        "experiment": "E7",
        "stage": "smoke",
        "run_kind": "normal_mode",
        "dataset": {"name": "synthetic_saas", "scale": scale, "seed": seed},
        "query": {
            "query_id": case.test_id,
            "path": case.query_path,
            "params": {"context_id": context_id, "policy_id": policy_id},
        },
        "policy": {
            "policy_id": policy_id,
            "policy_version": 0,
            "policy_sql_manifest_hash": file_sha256(root / "manifests" / "policies" / "synthetic_saas_policies.yaml"),
        },
        "context": {"context_id": context_id, "ctx_hash": result_hash},
        "mode": mode,
        "template": {"template_id": case.template_id, "alternative": case.alternative},
        "template_applicability": {
            "status": case.template_applicability,
            "reason": case.failure_reason if case.template_applicability != "applicable" else None,
        },
        "template_oracle": {
            "eligible_for_template_oracle": False,
            "template_oracle_exclusion_reason": "E7_runtime_audit_gate_not_template_oracle_pool",
        },
        "evaluation_role": _evaluation_role(root, mode),
        "pg": {
            "version": pg_version,
            "gucs": {"jit": "off", "max_parallel_workers_per_gather": "0"},
        },
        "versions": {
            "policy": {policy_id: 0},
            "membership": {"all": 0},
            "context": {context_id: 0},
            "trusted_state": {"policy_catalog": 0},
            "base": {"document": 0, "share_acl": 0, "group_membership": 0},
            "artifacts": {},
        },
        "planner": {
            "level": "A",
            "planning_time_ms": 0.0,
            "generated_templates": int(occurrence_planner.get("generated_templates", 1)),
            "rejected_templates": int(
                occurrence_planner.get("rejected_templates", 1 if case.static_status != "pass" else 0)
            ),
            "costed_templates": int(
                occurrence_planner.get("costed_templates", 0 if case.static_status != "pass" else 1)
            ),
            "rejection_reasons": occurrence_planner.get(
                "rejection_reasons",
                {case.failure_reason: 1}
                if case.static_status != "pass" and case.failure_reason
                else {},
            ),
            "chosen_estimated_cost": occurrence_planner.get("estimated_cost", 0.0),
            "chosen_rank_vs_template_oracle": None,
            "local_feature_vector": occurrence_planner.get("local_feature_vector"),
            "parent_requirement_vector": occurrence_planner.get("parent_requirement_vector"),
            "disabled_components": [],
            "candidates": occurrence_planner.get("candidates", []),
            "delivered_sigma": occurrence_planner.get("delivered_sigma", {}),
            **({"query_plan": query_plan} if query_plan else {}),
        },
        "static_verifier": {
            "status": case.static_status,
            "plan_hash": result_hash,
            "explain_path": None,
            "reasons": static_reasons,
        },
        "artifact_validation": {
            "status": "not_applicable",
            "action": "execute",
            "expected_action": "execute",
            "failure_sqlstate": None,
            "failure_symbol": None,
            "same_snapshot": False,
            "isolation_level": None,
        },
        "runtime_audit": {
            "status": runtime_status,
            "audit_path": None,
            "udf_calls": observation.udf_calls,
            "unauthorized_observations": observation.unauthorized_observations,
            "client_errors": observation.client_errors,
            "client_notices": observation.client_notices,
        },
        "sql": {
            "emitted_sql_path": case.query_path,
            "emitted_sql_hash": file_sha256(root / case.query_path),
            "normalized_sql_hash": scientific_manifest_hash(manifest_path),
        },
        "oracle_check": {
            "status": "match",
            "oracle_kind": "set_core_occurrence_indexed",
            "set_diff_left": 0,
            "set_diff_right": 0,
            "known_invalid_accepted": False,
            "known_valid_rejected": False,
        },
        "timing_ms": {
            "planning": 0.0,
            "execution": elapsed_ms,
            "verification": 0.0,
            "total": elapsed_ms,
        },
        "result": {"row_count": row_count, "result_hash": result_hash},
        "pg_metrics": {
            "shared_read_blocks": 0,
            "shared_hit_blocks": 0,
            "temp_read_blocks": 0,
            "temp_written_blocks": 0,
        },
        "counts": {
            "policy_evals": total_rows,
            "residual_checks": authorized_count if case.mode == "guard-mandatory-discharge" else 0,
            "candidate_rows": observation.udf_calls,
            "authorized_rows": authorized_count,
            "artifact_lookups": 0,
            "base_fetches": total_rows,
            **(
                {
                    "memo_groups": query_plan.get("memo_groups"),
                    "ir_node_count": query_plan.get("ir_node_count"),
                    "serialized_state_bytes": query_plan.get("serialized_state_bytes"),
                }
                if query_plan
                else {}
            ),
        },
        "artifact_cost": {
            "query_only_ms": elapsed_ms,
            "build_ms": 0.0,
            "refresh_ms": 0.0,
            "storage_bytes": 0,
            "indexes_built": [],
            "artifact_key_encoding_version": "artifact_key_encoding_v1",
            "amortization_model": "query_only",
        },
        "implementation": {
            "git_commit": _git_commit(root),
            "docker_image_digest": "not_containerized",
            "python_version": platform.python_version(),
            "planner_language": "python",
        },
        "e7_runtime_safety": payload,
        "status": case.status,
        "failure": failure,
    }


def _write_record(record: Mapping[str, Any], output_dir: Path) -> Path:
    issues = validate_raw_run_record(record)
    if issues:
        rendered = ", ".join(f"{issue.path}: {issue.message}" for issue in issues)
        raise PostgresError(f"E7 raw record failed schema validation: {rendered}")
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_mode = str(record["mode"]).replace("-", "_")
    target = output_dir / f"{record['query']['query_id']}_{safe_mode}.json"
    target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def run_e7_smoke(
    root: Path,
    pg_env: PostgresEnv,
    manifest_path: Path,
    output_dir: Path,
) -> E7SmokeResult:
    manifest = _load_manifest(manifest_path)
    _validate_manifest(manifest_path, manifest)

    dataset = manifest.get("dataset") or {}
    scale = str(dataset.get("scale", "1e3"))
    seed = int(dataset.get("seed", 42))
    generate_synthetic_saas(root, pg_env, scale=scale, seed=seed, verify=True, output_dir=None)

    policy_app = (manifest.get("policy_applications") or [{}])[0]
    policy_id = str(policy_app.get("policy_id", "tenant_group"))
    policy = _load_policy(root, policy_id)
    if "document" not in policy.get("applicable_relations", []):
        raise PostgresError(f"policy {policy_id} is not applicable to document")

    context_id = "ctx_000001"
    context = _load_context(context_id, pg_env)
    exact_predicate = _render_exact_predicate(
        str(policy["exact_sql_template"]),
        alias="d",
        rid_col="doc_id",
        context=context,
        relname="document",
    )
    guard_template = policy.get("guard_sql_template")
    if not guard_template:
        raise PostgresError(f"policy {policy_id} has no guard template for E7 guard-late smoke")
    guard_predicate = _render_exact_predicate(
        str(guard_template),
        alias="d",
        rid_col="doc_id",
        context=context,
        relname="document",
    )

    pg_version = run_psql_command("SHOW server_version;", pg_env)
    started = time.monotonic()
    log_payload = _run_json_script(
        _runtime_log_script(exact_predicate, guard_predicate, context_id),
        pg_env,
    )
    log_elapsed_ms = (time.monotonic() - started) * 1000.0

    authorized_count = int(log_payload["authorized_count"])
    total_rows = int(log_payload["total_rows"])
    if not (0 < authorized_count < total_rows):
        raise PostgresError(
            "E7 smoke requires both authorized and unauthorized rows; "
            f"got authorized={authorized_count}, total={total_rows}"
        )

    observations = {
        "E7_contract_unsafe_where": _observation(log_payload["contract"]),
        "E7_positive_raw_pushdown": _observation(log_payload["positive"]),
        "E7_guard_late_before_unsafe": _observation(log_payload["guard_late"]),
        "E7_guard_mandatory_discharge": _observation(log_payload["mandatory"]),
    }
    if observations["E7_contract_unsafe_where"].unauthorized_observations != 0:
        raise PostgresError("AdmissionFirst E7 smoke observed unauthorized rows")
    if observations["E7_positive_raw_pushdown"].unauthorized_observations <= 0:
        raise PostgresError("E7 unsafe pushdown positive control observed no unauthorized rows")
    if observations["E7_guard_late_before_unsafe"].unauthorized_observations <= 0:
        raise PostgresError("E7 forced GuardLate diagnostic observed no unauthorized rows")
    if observations["E7_guard_mandatory_discharge"].unauthorized_observations != 0:
        raise PostgresError("GuardMandatoryDischarge E7 smoke observed unauthorized rows")

    throw_started = time.monotonic()
    observations["E7_unsafe_throw"] = _run_throw_script(
        _throw_script(exact_predicate, context_id),
        pg_env,
    )
    throw_elapsed_ms = (time.monotonic() - throw_started) * 1000.0

    raw_paths: list[Path] = []
    for case in E7_CASES:
        elapsed_ms = throw_elapsed_ms if case.test_id == "E7_unsafe_throw" else log_elapsed_ms
        record = _record(
            root=root,
            manifest_path=manifest_path,
            case=case,
            observation=observations[case.test_id],
            authorized_count=authorized_count,
            total_rows=total_rows,
            scale=scale,
            seed=seed,
            policy_id=policy_id,
            context_id=context_id,
            pg_version=pg_version,
            elapsed_ms=elapsed_ms,
        )
        raw_paths.append(_write_record(record, output_dir))

    return E7SmokeResult(
        raw_result_paths=raw_paths,
        authorized_count=authorized_count,
        total_rows=total_rows,
        contract_unauthorized_observations=observations["E7_contract_unsafe_where"].unauthorized_observations,
        positive_unauthorized_observations=observations["E7_positive_raw_pushdown"].unauthorized_observations,
        guard_late_unauthorized_observations=observations["E7_guard_late_before_unsafe"].unauthorized_observations,
        mandatory_unauthorized_observations=observations["E7_guard_mandatory_discharge"].unauthorized_observations,
        throw_client_errors=observations["E7_unsafe_throw"].client_errors,
    )
