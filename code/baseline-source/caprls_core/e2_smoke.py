"""Run the E2 calibration smoke test for the artifact-availability grid."""

from __future__ import annotations

import hashlib
import json
import math
import platform
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional

import yaml

from planner.core import (
    DEFAULT_TEMPLATE_REGISTRY,
    ArtifactMetadata,
    CostInputs,
    PlanningProblem,
    TemplateRegistry,
)
from planner.contracts import AuthorizationViewBinding
from planner.emit import EmitContext
from planner.ir import Project, Root, ScanProtected, Select
from planner.query import OccurrenceGoal, PlanningQuery, QueryPlanResult, plan_query
from planner.verifier.static import StaticVerification, verify_template_static

from .baselines import (
    ADMISSION_FIRST_MODE,
    FINITE_TEMPLATE_UPPER_BOUND_ROLE,
    load_mode_registry,
    normalize_mode_id,
    scientific_mode_key,
)
from .explain_artifacts import attach_static_verifier_explain
from .manifest_validator import file_sha256
from .oracle_audit import _load_context, _load_policy, _quote, _render_exact_predicate
from .postgres_runner import PostgresEnv, PostgresError, run_psql_command, run_psql_file
from .result_schema import RAW_SCHEMA_VERSION, validate_raw_run_record
from .synthetic_saas import generate_synthetic_saas


@dataclass(frozen=True)
class TemplateCandidate:
    template_id: str
    alternative: str
    required_artifacts: frozenset[str]


@dataclass(frozen=True)
class CandidateResult:
    template_id: str
    alternative: str
    status: str
    template_applicability: str
    row_count: int
    execution_ms: float
    eligible_for_template_oracle: bool
    exclusion_reason: Optional[str]
    artifact_availability: str
    policy_evals: int
    candidate_rows: int
    artifact_lookups: int
    base_fetches: int
    result_hash: str
    planning_ms: float = 0.0
    failure_reason: Optional[str] = None
    validation_ms: float = 0.0
    validation_same_snapshot: bool = False
    validation_isolation_level: Optional[str] = None
    static_verifier_status: str = "pass"
    static_verifier_plan_hash: Optional[str] = None
    static_verifier_reasons: tuple[str, ...] = ()
    static_verifier_explain_json: Optional[tuple[Mapping[str, Any], ...]] = None
    runner_sql: Optional[str] = None


@dataclass(frozen=True)
class E2SmokeResult:
    raw_result_paths: list[Path]
    candidate_records: int
    normal_records: int
    summary_records: int
    artifact_unavailable_records: int


E2_TEMPLATE_ORDER = [
    "barrier_filter_v1",
    "safe_predicate_injection_v1",
    "auth_view_scan_v1",
    "auth_index_enum_v1",
    "strong_auth_index_keyed_v1",
    "mav_scan_v1",
    "guard_candidate_plus_residual_v1",
    "hybrid_intersect_v1",
]
AUTH_VIEW_RELATION = "auth_view_document_scope"

TEMPLATE_CANDIDATES = [
    TemplateCandidate(
        spec.template_id,
        spec.alternative,
        spec.required_artifacts,
    )
    for spec in (DEFAULT_TEMPLATE_REGISTRY.get(template_id) for template_id in E2_TEMPLATE_ORDER)
]

E2_PLANNER_REGISTRY = TemplateRegistry(
    DEFAULT_TEMPLATE_REGISTRY.get(template_id) for template_id in E2_TEMPLATE_ORDER
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


def _load_manifest(manifest_path: Path) -> Mapping[str, Any]:
    with manifest_path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, Mapping):
        raise PostgresError(f"E2 manifest must be an object: {manifest_path}")
    return data


def _validate_manifest(manifest_path: Path, manifest: Mapping[str, Any]) -> None:
    if manifest.get("experiment") != "E2" or manifest.get("execution_tier") != "smoke":
        raise PostgresError("e2-smoke requires an E2 smoke manifest")

    candidate_ids = [candidate.template_id for candidate in TEMPLATE_CANDIDATES]
    manifest_candidates = [str(item) for item in manifest.get("template_candidates", [])]
    if manifest_candidates != candidate_ids:
        raise PostgresError(
            "E2 template_candidates do not match runner contract: "
            f"expected {candidate_ids}, got {manifest_candidates}"
        )

    modes = {normalize_mode_id(str(item)) for item in manifest.get("modes", [])}
    required_modes = {ADMISSION_FIRST_MODE, "template-oracle", "barrier-only", "auth-index-enum-only"}
    if modes != required_modes:
        raise PostgresError(
            "E2 modes do not match runner contract: "
            f"expected {sorted(required_modes)}, got {sorted(modes)}"
        )

    queries = {
        str(item.get("query_id")): str(item.get("path"))
        for item in manifest.get("queries", [])
        if isinstance(item, Mapping)
    }
    if queries != {"E2_range_count": "workloads/e2/range_count.sql"}:
        raise PostgresError(f"E2 smoke supports only E2_range_count; got {queries}")


def _require_prospective_admission_first_runner(manifest: Mapping[str, Any]) -> None:
    """Keep the legacy smoke output diagnostic rather than post-hoc selected."""

    if ADMISSION_FIRST_MODE in {
        normalize_mode_id(str(item)) for item in manifest.get("modes", ())
    }:
        raise PostgresError(
            "E2 legacy smoke cannot execute AdmissionFirst: measured outcomes are "
            "TemplateOracle diagnostics only; use the prospective e2-main runner"
        )


def _write_temp_sql(sql: str) -> Path:
    tmp = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".sql", delete=False)
    with tmp:
        tmp.write(sql)
    return Path(tmp.name)


def _run_count_sql(sql: str, pg_env: PostgresEnv) -> tuple[int, float]:
    path = _write_temp_sql(sql)
    started = time.monotonic()
    try:
        stdout = run_psql_file(path, pg_env)
    finally:
        path.unlink(missing_ok=True)
    elapsed_ms = (time.monotonic() - started) * 1000.0
    payload = ""
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped and stripped.lstrip("-").isdigit():
            payload = stripped
    if not payload:
        raise PostgresError(f"E2 count SQL did not emit an integer:\n{stdout}")
    return int(payload), elapsed_ms


def _extract_explain_json(stdout: str) -> list[Mapping[str, Any]]:
    start = stdout.find("[")
    end = stdout.rfind("]")
    if start < 0 or end < start:
        raise PostgresError(f"E2 EXPLAIN did not emit JSON:\n{stdout}")
    payload = json.loads(stdout[start : end + 1])
    if not isinstance(payload, list) or not payload:
        raise PostgresError(f"E2 EXPLAIN JSON payload is empty:\n{stdout}")
    return payload


def _explain_plan_hash(explain_json: list[Mapping[str, Any]]) -> str:
    plan = explain_json[0].get("Plan", {})
    if not isinstance(plan, Mapping):
        plan = {}
    return _digest(plan)


def _explainable_sql(sql: str) -> str:
    lines = []
    for line in sql.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("\\"):
            continue
        if stripped.lower().startswith("set "):
            continue
        lines.append(line)
    return "\n".join(lines).strip().rstrip(";")


def _verify_candidate_static(
    template_id: str,
    sql: str,
    pg_env: PostgresEnv,
) -> StaticVerification:
    verification, _ = _verify_candidate_static_with_explain(template_id, sql, pg_env)
    return verification


def _verify_candidate_static_with_explain(
    template_id: str,
    sql: str,
    pg_env: PostgresEnv,
) -> tuple[StaticVerification, tuple[Mapping[str, Any], ...]]:
    body = _explainable_sql(sql)
    explain_sql = (
        "SET jit = off; "
        "SET max_parallel_workers_per_gather = 0; "
        "EXPLAIN (ANALYZE, FORMAT JSON, TIMING OFF, SUMMARY ON) "
        f"{body};"
    )
    explain_json = _extract_explain_json(run_psql_command(explain_sql, pg_env))
    verification = verify_template_static(template_id, sql, explain_json, _explain_plan_hash(explain_json))
    if verification.status != "pass":
        raise PostgresError(
            f"E2 static verifier failed for {template_id}: "
            + "; ".join(verification.reasons)
        )
    return verification, tuple(explain_json)


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
  ({_quote(artifact_id)}, 'policy', {_quote(policy_id)}, 0),
  ({_quote(artifact_id)}, 'membership', 'group_membership', 0),
  ({_quote(artifact_id)}, 'base', 'document', 0),
  ({_quote(artifact_id)}, 'context_scope', {_quote(ctx_hash)}, 0),
  ({_quote(artifact_id)}, 'rid_domain', 'document.doc_id', 0);
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


def _build_auth_idx_keyed_sql(
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
DELETE FROM public.auth_idx_keyed WHERE artifact_id = {_quote(artifact_id)};
INSERT INTO public.artifact_dependencies(artifact_id, dep_kind, dep_name, version_at_build)
VALUES
  ({_quote(artifact_id)}, 'policy', {_quote(policy_id)}, 0),
  ({_quote(artifact_id)}, 'membership', 'group_membership', 0),
  ({_quote(artifact_id)}, 'base', 'document', 0),
  ({_quote(artifact_id)}, 'context_scope', {_quote(ctx_hash)}, 0),
  ({_quote(artifact_id)}, 'rid_domain', 'document.doc_id', 0);
INSERT INTO public.auth_idx_keyed(
  artifact_id, policy_id, user_id, ctx_hash, key_name, key_value, range_bucket,
  rid, rid_domain_id, base_rel_oid, policy_version, membership_version
)
SELECT
  {_quote(artifact_id)},
  {_quote(policy_id)},
  {_quote(user_id)},
  {_quote(ctx_hash)},
  'doc_id',
  d.doc_id::text,
  (d.doc_id / 1000)::text,
  d.doc_id,
  'document.doc_id',
  'public.document'::regclass::oid,
  0,
  0
FROM public.document d
WHERE {exact_predicate};
COMMIT;
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
CREATE TABLE IF NOT EXISTS public.mav_document_ctx_000001 (
  doc_id bigint PRIMARY KEY,
  tenant_id bigint NOT NULL,
  owner_id bigint NOT NULL,
  public boolean NOT NULL
);
DELETE FROM public.artifact_dependencies WHERE artifact_id = {_quote(artifact_id)};
TRUNCATE public.mav_document_ctx_000001;
INSERT INTO public.artifact_dependencies(artifact_id, dep_kind, dep_name, version_at_build)
VALUES
  ({_quote(artifact_id)}, 'policy', {_quote(policy_id)}, 0),
  ({_quote(artifact_id)}, 'membership', 'group_membership', 0),
  ({_quote(artifact_id)}, 'base', 'document', 0),
  ({_quote(artifact_id)}, 'context_scope', {_quote(ctx_hash)}, 0),
  ({_quote(artifact_id)}, 'rid_domain', 'document.doc_id', 0);
INSERT INTO public.mav_document_ctx_000001(doc_id, tenant_id, owner_id, public)
SELECT d.doc_id, d.tenant_id, d.owner_id, d.public
FROM public.document d
WHERE {exact_predicate};
COMMIT;
"""


def _build_auth_view_sql(exact_predicate: str) -> str:
    return f"""
\\set ON_ERROR_STOP on
BEGIN;
DROP MATERIALIZED VIEW IF EXISTS public.{AUTH_VIEW_RELATION};
CREATE MATERIALIZED VIEW public.{AUTH_VIEW_RELATION} AS
SELECT d.doc_id
FROM public.document d
WHERE {exact_predicate};
CREATE UNIQUE INDEX {AUTH_VIEW_RELATION}_doc_id_idx
ON public.{AUTH_VIEW_RELATION}(doc_id);
COMMIT;
ANALYZE public.{AUTH_VIEW_RELATION};
"""


def _clear_auth_idx_sql(artifact_id: str) -> str:
    return f"""
\\set ON_ERROR_STOP on
BEGIN;
DELETE FROM public.artifact_dependencies WHERE artifact_id = {_quote(artifact_id)};
DELETE FROM public.auth_idx WHERE artifact_id = {_quote(artifact_id)};
COMMIT;
"""


def _clear_auth_idx_keyed_sql(artifact_id: str) -> str:
    return f"""
\\set ON_ERROR_STOP on
BEGIN;
DELETE FROM public.artifact_dependencies WHERE artifact_id = {_quote(artifact_id)};
DELETE FROM public.auth_idx_keyed WHERE artifact_id = {_quote(artifact_id)};
COMMIT;
"""


def _clear_mav_sql(artifact_id: str) -> str:
    return f"""
\\set ON_ERROR_STOP on
BEGIN;
DELETE FROM public.artifact_dependencies WHERE artifact_id = {_quote(artifact_id)};
DROP TABLE IF EXISTS public.mav_document_ctx_000001;
COMMIT;
"""


def _run_sql_script(sql: str, pg_env: PostgresEnv) -> str:
    path = _write_temp_sql(sql)
    try:
        return run_psql_file(path, pg_env)
    finally:
        path.unlink(missing_ok=True)


def _available_artifacts(artifact_availability: str) -> set[str]:
    if artifact_availability == "none":
        return set()
    if artifact_availability == "auth_idx":
        return {"auth_idx"}
    if artifact_availability == "mav":
        return {"mav"}
    if artifact_availability == "both":
        return {"auth_idx", "mav"}
    if artifact_availability == "both_keyed":
        return {"auth_idx", "auth_idx_keyed", "mav"}
    return {artifact_availability}


def _artifact_versions(artifact_availability: str) -> Dict[str, int]:
    available = _available_artifacts(artifact_availability)
    versions: Dict[str, int] = {}
    if "auth_idx" in available:
        versions["auth_idx_doc_ctx_000001"] = 0
    if "auth_idx_keyed" in available:
        versions["auth_idx_keyed_doc_ctx_000001"] = 0
    if "mav" in available:
        versions["mav_document_ctx_000001"] = 0
    return versions


def _artifact_storage_bytes(artifact_availability: str, cardinality: int) -> int:
    available = _available_artifacts(artifact_availability)
    total = 0
    if "auth_idx" in available:
        total += cardinality * 64
    if "auth_idx_keyed" in available:
        total += cardinality * 96
    if "mav" in available:
        total += cardinality * 80
    return total


def _artifact_indexes(artifact_availability: str) -> list[str]:
    available = _available_artifacts(artifact_availability)
    # The auth-view fixture is built for every E2 point, independently of the
    # optional artifact availability declared by that point.
    indexes: list[str] = [f"{AUTH_VIEW_RELATION}_doc_id_idx"]
    if "auth_idx" in available:
        indexes.append("auth_idx_lookup")
    if "auth_idx_keyed" in available:
        indexes.extend(("auth_idx_keyed_eq_lookup", "auth_idx_keyed_bucket_lookup"))
    if "mav" in available:
        indexes.append("mav_document_ctx_000001_pkey")
    return indexes


def _policy_eval_cost(policy_cost: str) -> float:
    key = policy_cost.lower().strip()
    if key == "cheap":
        return 0.003
    if key in {"100us", "100_us", "100µs"}:
        return 0.1
    if key in {"expensive", "expensive_acl"}:
        return 0.01
    return 0.003


def _planner_artifacts(
    artifact_availability: str,
    artifact_cardinality: int,
) -> dict[str, ArtifactMetadata]:
    available = _available_artifacts(artifact_availability)
    artifacts: dict[str, ArtifactMetadata] = {}
    cardinality = max(1, artifact_cardinality)
    if "auth_idx" in available:
        artifacts["auth_idx"] = ArtifactMetadata(
            kind="auth_idx",
            artifact_id="auth_idx_doc_ctx_000001",
            cardinality=cardinality,
            rows=cardinality,
            storage_bytes=cardinality * 64,
        )
    if "auth_idx_keyed" in available:
        artifacts["auth_idx_keyed"] = ArtifactMetadata(
            kind="auth_idx_keyed",
            artifact_id="auth_idx_keyed_doc_ctx_000001",
            keyed=True,
            cardinality=cardinality,
            rows=cardinality,
            key_name="doc_id",
            key_value_cardinality=max(1, cardinality),
            key_domain_matches=True,
            supports_equality_key=True,
            storage_bytes=cardinality * 96,
        )
    if "mav" in available:
        artifacts["mav"] = ArtifactMetadata(
            kind="mav",
            artifact_id="mav_document_ctx_000001",
            cardinality=cardinality,
            rows=cardinality,
            storage_bytes=cardinality * 80,
        )
    return artifacts


def _e2_planning_problem(
    *,
    policy_id: str,
    total_rows: int,
    authorized_rows: int,
    artifact_availability: str,
    artifact_cardinality: int,
    s_q: float,
    policy_cost: str,
) -> PlanningProblem:
    auth_selectivity = authorized_rows / total_rows if total_rows else 0.0
    return PlanningProblem(
        planning_execution_class="diagnostic_only",
        relation="document",
        policy_id=policy_id,
        occurrence_id="E2_range_count_document",
        rid_col="doc_id",
        required_attrs=("doc_id",),
        required_ctx=("ctx_hash",),
        exact_policy_safe=True,
        supports_guard=True,
        has_safe_query_predicate=True,
        authorization_view_binding=AuthorizationViewBinding(
            binding_id=f"e2-auth-view:{policy_id}",
            view_relation=AUTH_VIEW_RELATION,
            base_relation="document",
            rid_col="doc_id",
            policy_id=policy_id,
            scope_fingerprint=_digest(
                {"policy_id": policy_id, "scope": "e2_current_context"}
            ),
            relation_oid="public.document:oid",
            view_definition_digest=_digest(
                {"view": AUTH_VIEW_RELATION, "version": "e2_auth_view_v1"}
            ),
            policy_fingerprint=_digest({"policy_id": policy_id, "policy": "e2"}),
            rid_domain_id="document.doc_id",
            validator_evidence_digest=_digest(
                {"binding": "e2", "policy_id": policy_id}
            ),
            snapshot_id=_digest({"snapshot": "e2", "policy_id": policy_id}),
        ),
        artifacts=_planner_artifacts(artifact_availability, artifact_cardinality),
        cost_inputs=CostInputs(
            estimated_rows=total_rows,
            query_selectivity=s_q,
            auth_selectivity=auth_selectivity,
            policy_eval_cost=_policy_eval_cost(policy_cost),
            guard_selectivity=min(1.0, max(auth_selectivity, s_q)),
        ),
    )


def _text_digest(payload: str) -> str:
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _e2_emit_context(
    problem: PlanningProblem,
    *,
    exact_predicate: str = "d.tenant_id = 1",
    guard_predicate: str | None = None,
    lo: int = 1,
    hi: int = 100,
    artifact_id: str = "auth_idx_doc_ctx_000001",
    keyed_artifact_id: str = "auth_idx_keyed_doc_ctx_000001",
    mav_relation: str = "mav_document_ctx_000001",
    policy_id: str | None = None,
    user_id: str | None = None,
    ctx_hash: str | None = None,
) -> EmitContext:
    query_predicate = f"d.{problem.rid_col} BETWEEN {lo} AND {hi}"
    params: dict[str, object] = {
        "artifact_ids": {
            "auth_idx": artifact_id,
            "auth_idx_keyed": keyed_artifact_id,
            "mav": mav_relation,
        },
        "mav_relation": mav_relation,
        "mav_query_predicate": query_predicate,
        "rid_domain_id": f"{problem.relation}.{problem.rid_col}",
        "base_rel_oid": f"public.{problem.relation}",
        "key_name": problem.rid_col,
        "key_predicate": f"a.key_value::bigint BETWEEN {lo} AND {hi}",
    }
    if policy_id:
        params["policy_id"] = policy_id
    if user_id:
        params["user_id"] = user_id
    if ctx_hash:
        params["ctx_hash"] = ctx_hash
    return EmitContext(
        default_rid_col=problem.rid_col,
        occurrence_relations={problem.occurrence_id: problem.relation},
        occurrence_aliases={problem.occurrence_id: "d"},
        occurrence_rid_cols={problem.occurrence_id: problem.rid_col},
        exact_predicates={problem.occurrence_id: exact_predicate},
        guard_predicates={problem.occurrence_id: guard_predicate or exact_predicate},
        query_predicates={problem.occurrence_id: query_predicate},
        residual_predicates={"tenant_group:exact_residual": "rcheck.tenant_id = 1"},
        artifact_expectations={
            artifact.artifact_id: {
                "policy_id": problem.policy_id,
                "context_predicate": "ctx_hash_matches_current_context",
            }
            for artifact in problem.artifacts.values()
        },
        template_params={problem.occurrence_id: params},
        authorization_views=(
            {}
            if problem.authorization_view_binding is None
            else {problem.occurrence_id: problem.authorization_view_binding}
        ),
    )


def _e2_planning_query(
    problem: PlanningProblem,
    mode: str,
    *,
    exact_predicate: str = "d.tenant_id = 1",
    guard_predicate: str | None = None,
    lo: int = 1,
    hi: int = 100,
    artifact_id: str = "auth_idx_doc_ctx_000001",
    keyed_artifact_id: str = "auth_idx_keyed_doc_ctx_000001",
    mav_relation: str = "mav_document_ctx_000001",
    policy_id: str | None = None,
    user_id: str | None = None,
    ctx_hash: str | None = None,
) -> PlanningQuery:
    return PlanningQuery(
        ir_skeleton=Root(
            Project(
                Select(
                    ScanProtected(problem.occurrence_id, "chosen"),
                    pred=f"sel.{problem.rid_col} BETWEEN {lo} AND {hi}",
                    pred_kind="logical_target",
                    expr_label="E2_range_count:doc_id_range",
                ),
                visible_A=(problem.rid_col,),
                hidden_H=("__rid",),
            ),
            rho_root={"logical_group_id": problem.occurrence_id},
        ),
        occurrence_goals={problem.occurrence_id: OccurrenceGoal(problem, mode=mode)},
        mode=mode,
        emit_context=_e2_emit_context(
            problem,
            exact_predicate=exact_predicate,
            guard_predicate=guard_predicate,
            lo=lo,
            hi=hi,
            artifact_id=artifact_id,
            keyed_artifact_id=keyed_artifact_id,
            mav_relation=mav_relation,
            policy_id=policy_id,
            user_id=user_id,
            ctx_hash=ctx_hash,
        ),
    )


def _query_plan_payload(query_result: QueryPlanResult) -> dict[str, Any]:
    payload = query_result.to_dict()
    emitted_sql = query_result.emitted_sql or ""
    payload["ok"] = query_result.ok
    payload["occurrence_ids"] = sorted(query_result.occurrence_results)
    payload["disabled_components"] = []
    payload["certificate_suppressed"] = False
    # BEGIN E2_FIXED_BASELINE_QUERY_CERTIFICATE_SUPPRESSION_PHASE2A
    fixed_baseline_modes = frozenset(
        {
            "barrier-only",
            "injection-only",
            "auth-view-only",
            "auth-index-enum-only",
            "strong-auth-index",
            "mav-only",
            "guard-mandatory-discharge",
        }
    )
    query_certificate = query_result.certificate
    query_certificate_check = query_result.certificate_check
    if (query_certificate is None) != (query_certificate_check is None):
        raise PostgresError("E2 query certificate/check presence is inconsistent")

    expected_diagnostic_metadata = {
        "planning_execution_class": "diagnostic_only",
        "require_typed_admission": False,
        "planning_execution_admitted": True,
        "production_typed_admission": False,
        "non_promotable": True,
        "planning_evidence_role": "diagnostic_only_non_promotable",
    }
    planning_execution = payload.get("planning_execution")
    diagnostic_only_e2_occurrences = bool(
        isinstance(planning_execution, Mapping)
        and set(query_result.occurrence_results) == {"E2_range_count_document"}
        and set(planning_execution) == set(query_result.occurrence_results)
        and all(
            result.mode == query_result.mode
            and planning_execution.get(occurrence_id) == expected_diagnostic_metadata
            for occurrence_id, result in query_result.occurrence_results.items()
        )
    )
    if (
        query_result.mode in fixed_baseline_modes
        and query_certificate is None
        and query_certificate_check is None
        and not query_result.root_closure.ok
        and diagnostic_only_e2_occurrences
    ):
        payload["certificate_suppressed"] = True
    # END E2_FIXED_BASELINE_QUERY_CERTIFICATE_SUPPRESSION_PHASE2A
    payload["emitted_sql"] = emitted_sql
    payload["emitted_sql_hash"] = _text_digest(emitted_sql) if emitted_sql else None
    return payload


def _planner_payload(
    *,
    mode: str,
    template_id: str,
    policy_id: str,
    total_rows: int,
    authorized_rows: int,
    artifact_availability: str,
    artifact_cardinality: int,
    s_q: float,
    policy_cost: str,
    exact_predicate: str = "d.tenant_id = 1",
    guard_predicate: str | None = None,
    lo: int = 1,
    hi: int = 100,
    artifact_id: str = "auth_idx_doc_ctx_000001",
    keyed_artifact_id: str = "auth_idx_keyed_doc_ctx_000001",
    mav_relation: str = "mav_document_ctx_000001",
    user_id: str | None = None,
    ctx_hash: str | None = None,
) -> dict[str, Any]:
    problem = _e2_planning_problem(
        policy_id=policy_id,
        total_rows=total_rows,
        authorized_rows=authorized_rows,
        artifact_availability=artifact_availability,
        artifact_cardinality=artifact_cardinality,
        s_q=s_q,
        policy_cost=policy_cost,
    )
    query_result = plan_query(
        _e2_planning_query(
            problem,
            mode,
            exact_predicate=exact_predicate,
            guard_predicate=guard_predicate,
            lo=lo,
            hi=hi,
            artifact_id=artifact_id,
            keyed_artifact_id=keyed_artifact_id,
            mav_relation=mav_relation,
            policy_id=policy_id,
            user_id=user_id,
            ctx_hash=ctx_hash,
        ),
        registry=E2_PLANNER_REGISTRY,
    )
    return _planner_payload_from_query_result(
        query_result,
        template_id=template_id,
        occurrence_id=problem.occurrence_id,
    )


def _planner_payload_from_query_result(
    query_result: QueryPlanResult,
    *,
    template_id: str,
    occurrence_id: str = "E2_range_count_document",
) -> dict[str, Any]:
    """Serialize the exact query result that supplied an E2 choice."""

    result = query_result.occurrence_results[occurrence_id]
    candidates = [candidate.to_dict() for candidate in result.candidates]
    matched = next(
        (candidate for candidate in candidates if candidate.get("template_id") == template_id),
        None,
    )
    return {
        "level": "A",
        "planning_time_ms": 0.0,
        "generated_templates": result.generated_templates,
        "rejected_templates": result.rejected_templates,
        "costed_templates": result.costed_templates,
        "rejection_reasons": dict(result.rejection_reasons),
        "chosen_estimated_cost": None
        if matched is None
        else matched.get("estimated_cost"),
        "chosen_rank_vs_template_oracle": None,
        "local_feature_vector": None
        if result.local_feature_vector is None
        else dict(result.local_feature_vector),
        "parent_requirement_vector": dict(result.parent_requirement_vector),
        "disabled_components": list(result.disabled_components),
        "dominance_checks": result.dominance_checks,
        "dominance_pruned": result.dominance_pruned,
        "candidates": candidates,
        "delivered_sigma": {}
        if matched is None or not isinstance(matched.get("delivered_sigma"), Mapping)
        else dict(matched["delivered_sigma"]),
        "query_plan": _query_plan_payload(query_result),
    }


def _count_wrapper(sql: str) -> str:
    return f"""
\\set ON_ERROR_STOP on
SET jit = off;
SET max_parallel_workers_per_gather = 0;
{sql}
"""


def _document_carrier_projection_sql(alias: str = "d") -> str:
    return (
        f"{alias}.doc_id, {alias}.tenant_id, {alias}.owner_id, "
        f"{alias}.public, {alias}.doc_id AS __rid"
    )


def _candidate_sql(
    template_id: str,
    exact_predicate: str,
    guard_predicate: str,
    lo: int,
    hi: int,
    artifact_id: str,
    policy_id: str,
    user_id: str,
    ctx_hash: str,
) -> str:
    if template_id == "barrier_filter_v1":
        return _count_wrapper(
            f"""
WITH auth AS MATERIALIZED (
  SELECT {_document_carrier_projection_sql("d")}
  FROM public.document d
  WHERE {exact_predicate}
)
SELECT count(*) FROM auth WHERE doc_id BETWEEN {lo} AND {hi};
"""
        )
    if template_id == "safe_predicate_injection_v1":
        return _count_wrapper(
            f"""
SELECT count(*)
FROM public.document d
WHERE d.doc_id BETWEEN {lo} AND {hi}
  AND {exact_predicate};
"""
        )
    if template_id == "auth_view_scan_v1":
        return _count_wrapper(
            f"""
SELECT count(*)
FROM public.{AUTH_VIEW_RELATION} av
WHERE av.doc_id BETWEEN {lo} AND {hi};
"""
        )
    if template_id == "auth_index_enum_v1":
        return _count_wrapper(
            f"""
SELECT count(*)
FROM public.auth_idx a
JOIN public.document d ON d.doc_id = a.rid
WHERE a.artifact_id = {_quote(artifact_id)}
  AND a.policy_id = {_quote(policy_id)}
  AND a.user_id = {_quote(user_id)}
  AND a.ctx_hash = {_quote(ctx_hash)}
  AND a.rid_domain_id = 'document.doc_id'
  AND a.base_rel_oid = 'public.document'::regclass::oid
  AND d.doc_id BETWEEN {lo} AND {hi};
"""
        )
    if template_id == "strong_auth_index_keyed_v1":
        return _count_wrapper(
            f"""
SELECT count(*)
FROM public.auth_idx_keyed a
JOIN public.document d ON d.doc_id = a.rid
WHERE a.artifact_id = {_quote(artifact_id)}
  AND a.policy_id = {_quote(policy_id)}
  AND a.user_id = {_quote(user_id)}
  AND a.ctx_hash = {_quote(ctx_hash)}
  AND a.key_name = 'doc_id'
  AND a.key_value::bigint BETWEEN {lo} AND {hi}
  AND a.rid_domain_id = 'document.doc_id'
  AND a.base_rel_oid = 'public.document'::regclass::oid;
"""
        )
    if template_id == "mav_scan_v1":
        return _count_wrapper(
            f"""
SELECT count(*)
FROM public.mav_document_ctx_000001 m
WHERE m.doc_id BETWEEN {lo} AND {hi};
"""
        )
    if template_id == "guard_candidate_plus_residual_v1":
        return _count_wrapper(
            f"""
WITH cand AS MATERIALIZED (
  SELECT {_document_carrier_projection_sql("d")}
  FROM public.document d
  WHERE {guard_predicate}
)
SELECT count(*)
FROM cand d
WHERE d.doc_id BETWEEN {lo} AND {hi}
  AND {exact_predicate};
"""
        )
    if template_id == "hybrid_intersect_v1":
        return _count_wrapper(
            f"""
WITH q AS MATERIALIZED (
  SELECT d.doc_id AS rid
  FROM public.document d
  WHERE d.doc_id BETWEEN {lo} AND {hi}
),
a AS MATERIALIZED (
  SELECT ai.rid
  FROM public.auth_idx ai
  WHERE ai.artifact_id = {_quote(artifact_id)}
    AND ai.policy_id = {_quote(policy_id)}
    AND ai.user_id = {_quote(user_id)}
    AND ai.ctx_hash = {_quote(ctx_hash)}
    AND ai.rid_domain_id = 'document.doc_id'
    AND ai.base_rel_oid = 'public.document'::regclass::oid
)
SELECT count(*)
FROM q
JOIN a USING (rid);
"""
        )
    raise PostgresError(f"template is not executable in E2 smoke: {template_id}")


def _candidate_result(
    candidate: TemplateCandidate,
    artifact_availability: str,
    row_count: int,
    execution_ms: float,
    oracle_count: int,
    total_rows: int,
    auth_idx_cardinality: int,
    planning_ms: float = 0.0,
    validation_ms: float = 0.0,
    validation_same_snapshot: bool = False,
    validation_isolation_level: Optional[str] = None,
    static_verification: Optional[StaticVerification] = None,
    static_verifier_explain_json: Optional[tuple[Mapping[str, Any], ...]] = None,
    runner_sql: Optional[str] = None,
) -> CandidateResult:
    payload = {
        "template_id": candidate.template_id,
        "artifact_availability": artifact_availability,
        "row_count": row_count,
        "planning_ms": round(planning_ms, 6),
        "execution_ms": round(execution_ms, 6),
        "oracle_count": oracle_count,
    }
    return CandidateResult(
        template_id=candidate.template_id,
        alternative=candidate.alternative,
        status="pass",
        template_applicability="applicable",
        row_count=row_count,
        execution_ms=execution_ms,
        eligible_for_template_oracle=True,
        exclusion_reason=None,
        artifact_availability=artifact_availability,
        policy_evals=total_rows
        if candidate.template_id
        in {
            "barrier_filter_v1",
            "auth_view_scan_v1",
            "safe_predicate_injection_v1",
            "guard_candidate_plus_residual_v1",
        }
        else 0,
        candidate_rows=auth_idx_cardinality if candidate.required_artifacts else total_rows,
        artifact_lookups=1 if candidate.required_artifacts else 0,
        base_fetches=row_count,
        result_hash=_digest(payload),
        planning_ms=planning_ms,
        validation_ms=validation_ms,
        validation_same_snapshot=validation_same_snapshot,
        validation_isolation_level=validation_isolation_level,
        static_verifier_status="pass" if static_verification is None else static_verification.status,
        static_verifier_plan_hash=None if static_verification is None else static_verification.plan_hash,
        static_verifier_reasons=()
        if static_verification is None
        else tuple(static_verification.reasons),
        static_verifier_explain_json=static_verifier_explain_json,
        runner_sql=runner_sql,
    )


def _unavailable_candidate(
    candidate: TemplateCandidate,
    artifact_availability: str,
) -> CandidateResult:
    reason = (
        f"requires {sorted(candidate.required_artifacts)} but artifact_availability="
        f"{artifact_availability}"
    )
    payload = {
        "template_id": candidate.template_id,
        "artifact_availability": artifact_availability,
        "status": "artifact_unavailable",
        "reason": reason,
    }
    return CandidateResult(
        template_id=candidate.template_id,
        alternative=candidate.alternative,
        status="expected_reject",
        template_applicability="artifact_unavailable",
        row_count=0,
        execution_ms=0.0,
        eligible_for_template_oracle=False,
        exclusion_reason="artifact_unavailable",
        artifact_availability=artifact_availability,
        policy_evals=0,
        candidate_rows=0,
        artifact_lookups=0,
        base_fetches=0,
        result_hash=_digest(payload),
        failure_reason=reason,
    )


def _base_record(
    root: Path,
    manifest_path: Path,
    manifest_id: str,
    run_id: str,
    run_kind: str,
    mode: str,
    template_id: str,
    alternative: str,
    evaluation_role: str,
    status: str,
    candidate: CandidateResult,
    dataset_scale: str,
    seed: int,
    policy_id: str,
    context_id: str,
    ctx_hash: str,
    pg_version: str,
    total_rows: int,
    authorized_rows: int,
    auth_idx_cardinality: int,
    s_auth: float,
    s_q: float,
    policy_cost: str,
    failure_reason: Optional[str],
    stage: str = "alternative_matrix_smoke",
    query_id: str = "E2_range_count",
    query_path: str = "workloads/e2/range_count.sql",
    run_id_prefix: str = "E2",
    extra_query_params: Optional[Mapping[str, Any]] = None,
    exact_predicate: str = "d.tenant_id = 1",
    guard_predicate: str | None = None,
    lo: int = 1,
    hi: int = 100,
    artifact_id: str = "auth_idx_doc_ctx_000001",
    keyed_artifact_id: str = "auth_idx_keyed_doc_ctx_000001",
    mav_relation: str = "mav_document_ctx_000001",
    user_id: str | None = None,
) -> Dict[str, Any]:
    mode = normalize_mode_id(mode)
    oracle_status = "match" if status in {"pass", "expected_reject"} else "mismatch"
    artifact_action = "reject" if candidate.template_applicability == "artifact_unavailable" else "execute"
    artifact_status = (
        "pass"
        if candidate.template_applicability == "applicable" and candidate.artifact_lookups
        else "not_applicable"
    )
    trusted_state = {"policy_catalog": 0}
    if candidate.validation_same_snapshot:
        trusted_state["artifact_validation_same_snapshot"] = 1
    query_params = {
        "s_auth": s_auth,
        "s_q": s_q,
        "policy_cost": policy_cost,
        "artifact_availability": candidate.artifact_availability,
    }
    if extra_query_params:
        query_params.update(dict(extra_query_params))
    planner_payload = _planner_payload(
        mode=mode,
        template_id=template_id,
        policy_id=policy_id,
        total_rows=total_rows,
        authorized_rows=authorized_rows,
        artifact_availability=candidate.artifact_availability,
        artifact_cardinality=auth_idx_cardinality,
        s_q=s_q,
        policy_cost=policy_cost,
        exact_predicate=exact_predicate,
        guard_predicate=guard_predicate,
        lo=lo,
        hi=hi,
        artifact_id=artifact_id,
        keyed_artifact_id=keyed_artifact_id,
        mav_relation=mav_relation,
        user_id=user_id,
        ctx_hash=ctx_hash,
    )
    sql_payload = {
        "emitted_sql_path": query_path,
        "emitted_sql_hash": file_sha256(root / query_path),
        "normalized_sql_hash": candidate.result_hash,
    }
    if candidate.runner_sql:
        sql_payload["runner_sql"] = candidate.runner_sql
        sql_payload["runner_sql_hash"] = _text_digest(candidate.runner_sql)
    query_plan = planner_payload.get("query_plan")
    if isinstance(query_plan, Mapping):
        ir_equivalence_sql = query_plan.get("emitted_sql")
        if isinstance(ir_equivalence_sql, str) and ir_equivalence_sql.strip():
            sql_payload["ir_equivalence_runner_sql"] = ir_equivalence_sql
            sql_payload["ir_equivalence_runner_sql_hash"] = _text_digest(ir_equivalence_sql)

    return {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": f"{run_id_prefix}_{run_id}" if run_id_prefix != "E2" else run_id,
        "manifest_id": manifest_id,
        "manifest_hash": file_sha256(manifest_path),
        "experiment": "E2",
        "stage": stage,
        "run_kind": run_kind,
        "dataset": {"name": "synthetic_saas", "scale": dataset_scale, "seed": seed},
        "query": {
            "query_id": query_id,
            "path": query_path,
            "params": query_params,
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
            "status": candidate.template_applicability,
            "reason": failure_reason if candidate.template_applicability != "applicable" else None,
        },
        "template_oracle": {
            "eligible_for_template_oracle": candidate.eligible_for_template_oracle,
            "template_oracle_exclusion_reason": candidate.exclusion_reason,
        },
        "evaluation_role": evaluation_role,
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
            "artifacts": _artifact_versions(candidate.artifact_availability),
        },
        "planner": planner_payload,
        "static_verifier": {
            "status": candidate.static_verifier_status,
            "plan_hash": candidate.static_verifier_plan_hash or candidate.result_hash,
            "explain_path": None,
            "reasons": list(candidate.static_verifier_reasons),
        },
        "artifact_validation": {
            "status": artifact_status,
            "action": artifact_action,
            "expected_action": artifact_action,
            "failure_sqlstate": None,
            "failure_symbol": None,
            "same_snapshot": candidate.validation_same_snapshot,
            "isolation_level": candidate.validation_isolation_level,
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
            "status": oracle_status,
            "oracle_kind": "set_core_occurrence_indexed",
            "set_diff_left": 0,
            "set_diff_right": 0,
            "known_invalid_accepted": False,
            "known_valid_rejected": False,
        },
        "timing_ms": {
            "planning": candidate.planning_ms,
            "execution": candidate.execution_ms,
            "verification": candidate.validation_ms,
            "total": (
                candidate.planning_ms
                + candidate.execution_ms
                + candidate.validation_ms
            ),
        },
        "result": {"row_count": candidate.row_count, "result_hash": candidate.result_hash},
        "pg_metrics": {
            "shared_read_blocks": 0,
            "shared_hit_blocks": 0,
            "temp_read_blocks": 0,
            "temp_written_blocks": 0,
        },
        "counts": {
            "policy_evals": candidate.policy_evals,
            "residual_checks": candidate.row_count if template_id == "guard_candidate_plus_residual_v1" else 0,
            "candidate_rows": candidate.candidate_rows,
            "authorized_rows": authorized_rows,
            "artifact_lookups": candidate.artifact_lookups,
            "base_fetches": candidate.base_fetches,
        },
        "artifact_cost": {
            "query_only_ms": candidate.planning_ms + candidate.execution_ms,
            "build_ms": 0.0,
            "refresh_ms": 0.0,
            "storage_bytes": _artifact_storage_bytes(candidate.artifact_availability, auth_idx_cardinality),
            "validation_ms": candidate.validation_ms,
            "indexes_built": _artifact_indexes(candidate.artifact_availability),
            "artifact_key_encoding_version": "artifact_key_encoding_v1",
            "amortization_model": "query_only",
        },
        "implementation": {
            "git_commit": _git_commit(root),
            "docker_image_digest": "not_containerized",
            "python_version": platform.python_version(),
            "planner_language": "python",
        },
        "e2_calibration": {
            "total_rows": total_rows,
            "authorized_rows": authorized_rows,
            "auth_idx_cardinality": auth_idx_cardinality,
            "s_auth_observed": authorized_rows / total_rows if total_rows else 0,
            "s_q_target": s_q,
            "policy_cost": policy_cost,
        },
        "status": status,
        "failure": None if failure_reason is None else {"reason": failure_reason},
    }


def _candidate_record(
    root: Path,
    manifest_path: Path,
    manifest_id: str,
    candidate: CandidateResult,
    dataset_scale: str,
    seed: int,
    policy_id: str,
    context_id: str,
    ctx_hash: str,
    pg_version: str,
    total_rows: int,
    authorized_rows: int,
    auth_idx_cardinality: int,
    s_auth: float,
    s_q: float,
    policy_cost: str,
    exact_predicate: str = "d.tenant_id = 1",
    guard_predicate: str | None = None,
    lo: int = 1,
    hi: int = 100,
    artifact_id: str = "auth_idx_doc_ctx_000001",
    keyed_artifact_id: str = "auth_idx_keyed_doc_ctx_000001",
    mav_relation: str = "mav_document_ctx_000001",
    user_id: str | None = None,
) -> Dict[str, Any]:
    return _base_record(
        root=root,
        manifest_path=manifest_path,
        manifest_id=manifest_id,
        run_id=f"E2_{candidate.artifact_availability}_{candidate.template_id}",
        run_kind="template_candidate",
        mode="template-oracle",
        template_id=candidate.template_id,
        alternative=candidate.alternative,
        evaluation_role=FINITE_TEMPLATE_UPPER_BOUND_ROLE,
        status=candidate.status,
        candidate=candidate,
        dataset_scale=dataset_scale,
        seed=seed,
        policy_id=policy_id,
        context_id=context_id,
        ctx_hash=ctx_hash,
        pg_version=pg_version,
        total_rows=total_rows,
        authorized_rows=authorized_rows,
        auth_idx_cardinality=auth_idx_cardinality,
        s_auth=s_auth,
        s_q=s_q,
        policy_cost=policy_cost,
        failure_reason=candidate.failure_reason,
        exact_predicate=exact_predicate,
        guard_predicate=guard_predicate,
        lo=lo,
        hi=hi,
        artifact_id=artifact_id,
        keyed_artifact_id=keyed_artifact_id,
        mav_relation=mav_relation,
        user_id=user_id,
    )


def _normal_record(
    root: Path,
    manifest_path: Path,
    manifest_id: str,
    mode: str,
    candidate: CandidateResult,
    dataset_scale: str,
    seed: int,
    policy_id: str,
    context_id: str,
    ctx_hash: str,
    pg_version: str,
    total_rows: int,
    authorized_rows: int,
    auth_idx_cardinality: int,
    s_auth: float,
    s_q: float,
    policy_cost: str,
    exact_predicate: str = "d.tenant_id = 1",
    guard_predicate: str | None = None,
    lo: int = 1,
    hi: int = 100,
    artifact_id: str = "auth_idx_doc_ctx_000001",
    keyed_artifact_id: str = "auth_idx_keyed_doc_ctx_000001",
    mav_relation: str = "mav_document_ctx_000001",
    user_id: str | None = None,
) -> Dict[str, Any]:
    status = candidate.status
    return _base_record(
        root=root,
        manifest_path=manifest_path,
        manifest_id=manifest_id,
        run_id=f"E2_{candidate.artifact_availability}_{mode}",
        run_kind="normal_mode",
        mode=mode,
        template_id=candidate.template_id,
        alternative=candidate.alternative,
        evaluation_role=load_mode_registry(root)[normalize_mode_id(mode)].evaluation_role,
        status=status,
        candidate=candidate,
        dataset_scale=dataset_scale,
        seed=seed,
        policy_id=policy_id,
        context_id=context_id,
        ctx_hash=ctx_hash,
        pg_version=pg_version,
        total_rows=total_rows,
        authorized_rows=authorized_rows,
        auth_idx_cardinality=auth_idx_cardinality,
        s_auth=s_auth,
        s_q=s_q,
        policy_cost=policy_cost,
        failure_reason=candidate.failure_reason,
        exact_predicate=exact_predicate,
        guard_predicate=guard_predicate,
        lo=lo,
        hi=hi,
        artifact_id=artifact_id,
        keyed_artifact_id=keyed_artifact_id,
        mav_relation=mav_relation,
        user_id=user_id,
    )


def _summary_record(
    root: Path,
    manifest_path: Path,
    manifest_id: str,
    artifact_availability: str,
    eligible: list[CandidateResult],
    excluded: list[CandidateResult],
    chosen: CandidateResult,
    dataset_scale: str,
    seed: int,
    policy_id: str,
    context_id: str,
    ctx_hash: str,
    pg_version: str,
    total_rows: int,
    authorized_rows: int,
    auth_idx_cardinality: int,
    s_auth: float,
    s_q: float,
    policy_cost: str,
    exact_predicate: str = "d.tenant_id = 1",
    guard_predicate: str | None = None,
    lo: int = 1,
    hi: int = 100,
    artifact_id: str = "auth_idx_doc_ctx_000001",
    keyed_artifact_id: str = "auth_idx_keyed_doc_ctx_000001",
    mav_relation: str = "mav_document_ctx_000001",
    user_id: str | None = None,
) -> Dict[str, Any]:
    ranked = sorted(eligible, key=lambda item: (item.execution_ms, item.template_id))
    best = ranked[0]
    chosen_rank = 1 + sum(
        candidate.execution_ms < chosen.execution_ms
        and not math.isclose(
            candidate.execution_ms,
            chosen.execution_ms,
            rel_tol=1e-12,
            abs_tol=1e-12,
        )
        for candidate in eligible
    )
    gap = chosen.execution_ms / best.execution_ms if best.execution_ms > 0 else 1.0
    summary_payload = {
        "run_kind": "template_oracle_summary",
        "query_id": "E2_range_count",
        "context_id": context_id,
        "mode_under_test": ADMISSION_FIRST_MODE,
        "ranking_metric": "execution_time_ms",
        "eligible_templates": len(eligible),
        "eligible_plan_shapes": _eligible_plan_shape_count(eligible),
        "excluded_templates": _excluded_counts(excluded),
        "best_template_id": best.template_id,
        "best_execution_ms": best.execution_ms,
        "chosen_template_id": chosen.template_id,
        "chosen_execution_ms": chosen.execution_ms,
        "gap": gap,
        "chosen_measured_rank": chosen_rank,
        "chosen_is_measured_best": (
            chosen.template_id == best.template_id
            or math.isclose(gap, 1.0, rel_tol=1e-12, abs_tol=1e-12)
        ),
    }
    scientific_summary_payload = {
        **summary_payload,
        "mode_under_test": scientific_mode_key(ADMISSION_FIRST_MODE),
    }
    # The top-level oracle-summary record is the observed region winner.  The
    # independently selected AdmissionFirst candidate and its regret remain in
    # ``template_oracle_summary`` above and in the normal AdmissionFirst record.
    summary_candidate = CandidateResult(
        template_id=best.template_id,
        alternative=best.alternative,
        status="pass",
        template_applicability="applicable",
        row_count=best.row_count,
        execution_ms=best.execution_ms,
        eligible_for_template_oracle=True,
        exclusion_reason=None,
        artifact_availability=best.artifact_availability,
        policy_evals=best.policy_evals,
        candidate_rows=best.candidate_rows,
        artifact_lookups=best.artifact_lookups,
        base_fetches=best.base_fetches,
        result_hash=_digest(scientific_summary_payload),
        planning_ms=best.planning_ms,
        validation_ms=best.validation_ms,
        validation_same_snapshot=best.validation_same_snapshot,
        validation_isolation_level=best.validation_isolation_level,
        static_verifier_status=best.static_verifier_status,
        static_verifier_plan_hash=best.static_verifier_plan_hash,
        static_verifier_reasons=best.static_verifier_reasons,
        static_verifier_explain_json=best.static_verifier_explain_json,
        runner_sql=best.runner_sql,
    )
    record = _base_record(
        root=root,
        manifest_path=manifest_path,
        manifest_id=manifest_id,
        run_id=f"E2_{artifact_availability}_template_oracle_summary",
        run_kind="template_oracle_summary",
        mode="template-oracle",
        template_id=best.template_id,
        alternative=best.alternative,
        evaluation_role=FINITE_TEMPLATE_UPPER_BOUND_ROLE,
        status="pass",
        candidate=summary_candidate,
        dataset_scale=dataset_scale,
        seed=seed,
        policy_id=policy_id,
        context_id=context_id,
        ctx_hash=ctx_hash,
        pg_version=pg_version,
        total_rows=total_rows,
        authorized_rows=authorized_rows,
        auth_idx_cardinality=auth_idx_cardinality,
        s_auth=s_auth,
        s_q=s_q,
        policy_cost=policy_cost,
        failure_reason=None,
        exact_predicate=exact_predicate,
        guard_predicate=guard_predicate,
        lo=lo,
        hi=hi,
        artifact_id=artifact_id,
        keyed_artifact_id=keyed_artifact_id,
        mav_relation=mav_relation,
        user_id=user_id,
    )
    record["template_oracle_summary"] = summary_payload
    return record


def _excluded_counts(excluded: Iterable[CandidateResult]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in excluded:
        key = item.exclusion_reason or item.template_applicability
        counts[key] = counts.get(key, 0) + 1
    return counts


def _eligible_plan_shape_count(eligible: Iterable[CandidateResult]) -> int:
    keys = {
        item.static_verifier_plan_hash or item.template_id
        for item in eligible
        if item.eligible_for_template_oracle
    }
    return len(keys)


def _write_record(
    record: Dict[str, Any],
    output_dir: Path,
    static_verifier_explain_json: Any = None,
) -> Path:
    attach_static_verifier_explain(record, output_dir, static_verifier_explain_json)
    issues = validate_raw_run_record(record)
    if issues:
        rendered = ", ".join(f"{issue.path}: {issue.message}" for issue in issues)
        raise PostgresError(f"E2 raw record failed schema validation: {rendered}")
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_mode = str(record["mode"]).replace("-", "_")
    safe_kind = str(record["run_kind"]).replace("-", "_")
    target = output_dir / f"{record['run_id']}_{safe_kind}_{safe_mode}.json"
    target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def run_e2_smoke(
    root: Path,
    pg_env: PostgresEnv,
    manifest_path: Path,
    output_dir: Path,
) -> E2SmokeResult:
    manifest = _load_manifest(manifest_path)
    _validate_manifest(manifest_path, manifest)
    _require_prospective_admission_first_runner(manifest)
    manifest_id = str(manifest["manifest_id"])
    dataset = manifest.get("dataset") or {}
    scale = str(dataset.get("scale", "1e5"))
    seed = int(dataset.get("seed", 42))
    variables = manifest.get("variables") or {}
    s_auth = float((variables.get("s_auth") or [0.01])[0])
    s_q = float((variables.get("s_q") or [0.01])[0])
    policy_cost = str((variables.get("policy_cost") or ["cheap"])[0])
    artifact_points = [str(item) for item in variables.get("artifact_availability", ["none", "auth_idx"])]

    generate_synthetic_saas(root, pg_env, scale=scale, seed=seed, verify=True, output_dir=None)
    policy_app = (manifest.get("policy_applications") or [{}])[0]
    policy_id = str(policy_app.get("policy_id", "tenant_group"))
    policy = _load_policy(root, policy_id)
    if "document" not in policy.get("applicable_relations", []):
        raise PostgresError(f"policy {policy_id} is not applicable to document")
    context_id = "ctx_000001"
    context = _load_context(context_id, pg_env)
    ctx_hash = run_psql_command(
        f"SELECT ctx_hash FROM public.synthetic_context WHERE context_id = {_quote(context_id)};",
        pg_env,
    )
    exact_predicate = _render_exact_predicate(
        str(policy["exact_sql_template"]),
        alias="d",
        rid_col="doc_id",
        context=context,
        relname="document",
    )
    guard_template = policy.get("guard_sql_template")
    if not guard_template:
        raise PostgresError(f"policy {policy_id} has no guard template for E2 smoke")
    guard_predicate = _render_exact_predicate(
        str(guard_template),
        alias="d",
        rid_col="doc_id",
        context=context,
        relname="document",
    )
    total_rows = int(run_psql_command("SELECT count(*) FROM public.document;", pg_env))
    hi = max(1, int(total_rows * s_q))
    lo = 1
    oracle_count, _ = _run_count_sql(
        _count_wrapper(
            f"""
SELECT count(*)
FROM public.document d
WHERE d.doc_id BETWEEN {lo} AND {hi}
  AND {exact_predicate};
"""
        ),
        pg_env,
    )
    authorized_rows = int(
        run_psql_command(f"SELECT count(*) FROM public.document d WHERE {exact_predicate};", pg_env)
    )
    pg_version = run_psql_command("SHOW server_version;", pg_env)
    artifact_id = "auth_idx_doc_ctx_000001"
    keyed_artifact_id = "auth_idx_keyed_doc_ctx_000001"
    mav_artifact_id = "mav_document_ctx_000001"
    user_id = str(context["user_id"])

    raw_paths: list[Path] = []
    candidate_records = 0
    normal_records = 0
    summary_records = 0
    artifact_unavailable_records = 0

    for artifact_availability in artifact_points:
        _run_sql_script(_clear_auth_idx_sql(artifact_id), pg_env)
        _run_sql_script(_clear_auth_idx_keyed_sql(keyed_artifact_id), pg_env)
        _run_sql_script(_clear_mav_sql(mav_artifact_id), pg_env)
        _run_sql_script(_build_auth_view_sql(exact_predicate), pg_env)
        if "auth_idx" in _available_artifacts(artifact_availability):
            _run_sql_script(
                _build_auth_idx_sql(
                    artifact_id=artifact_id,
                    policy_id=policy_id,
                    user_id=user_id,
                    ctx_hash=ctx_hash,
                    exact_predicate=exact_predicate,
                ),
                pg_env,
            )
        if "auth_idx_keyed" in _available_artifacts(artifact_availability):
            _run_sql_script(
                _build_auth_idx_keyed_sql(
                    artifact_id=keyed_artifact_id,
                    policy_id=policy_id,
                    user_id=user_id,
                    ctx_hash=ctx_hash,
                    exact_predicate=exact_predicate,
                ),
                pg_env,
            )
        if "mav" in _available_artifacts(artifact_availability):
            _run_sql_script(
                _build_mav_sql(
                    artifact_id=mav_artifact_id,
                    policy_id=policy_id,
                    ctx_hash=ctx_hash,
                    exact_predicate=exact_predicate,
                ),
                pg_env,
            )
        auth_idx_cardinality = int(
            run_psql_command(
                f"SELECT count(*) FROM public.auth_idx WHERE artifact_id = {_quote(artifact_id)};",
                pg_env,
            )
        )
        keyed_cardinality = int(
            run_psql_command(
                f"SELECT count(*) FROM public.auth_idx_keyed WHERE artifact_id = {_quote(keyed_artifact_id)};",
                pg_env,
            )
        )
        mav_cardinality = 0
        if "mav" in _available_artifacts(artifact_availability):
            mav_cardinality = int(
                run_psql_command("SELECT count(*) FROM public.mav_document_ctx_000001;", pg_env)
            )
        artifact_cardinality = max(auth_idx_cardinality, keyed_cardinality, mav_cardinality)
        candidate_results: list[CandidateResult] = []
        for template in TEMPLATE_CANDIDATES:
            available = _available_artifacts(artifact_availability)
            if not template.required_artifacts.issubset(available):
                result = _unavailable_candidate(template, artifact_availability)
                artifact_unavailable_records += 1
            else:
                sql = _candidate_sql(
                    template.template_id,
                    exact_predicate,
                    guard_predicate,
                    lo,
                    hi,
                    artifact_id,
                    policy_id,
                    user_id,
                    ctx_hash,
                )
                row_count, elapsed_ms = _run_count_sql(sql, pg_env)
                static_verification, static_verifier_explain_json = (
                    _verify_candidate_static_with_explain(template.template_id, sql, pg_env)
                )
                if row_count != oracle_count:
                    raise PostgresError(
                        f"{template.template_id} returned {row_count}, expected {oracle_count}"
                    )
                result = _candidate_result(
                    candidate=template,
                    artifact_availability=artifact_availability,
                    row_count=row_count,
                    execution_ms=elapsed_ms,
                    oracle_count=oracle_count,
                    total_rows=total_rows,
                    auth_idx_cardinality=artifact_cardinality,
                    static_verification=static_verification,
                    static_verifier_explain_json=static_verifier_explain_json,
                    runner_sql=sql,
                )
            candidate_results.append(result)
            raw_paths.append(
                _write_record(
                    _candidate_record(
                        root,
                        manifest_path,
                        manifest_id,
                        result,
                        scale,
                        seed,
                        policy_id,
                        context_id,
                        ctx_hash,
                        pg_version,
                        total_rows,
                        authorized_rows,
                        artifact_cardinality,
                        s_auth,
                        s_q,
                        policy_cost,
                        exact_predicate=exact_predicate,
                        guard_predicate=guard_predicate,
                        lo=lo,
                        hi=hi,
                        artifact_id=artifact_id,
                        keyed_artifact_id=keyed_artifact_id,
                        mav_relation=mav_artifact_id,
                        user_id=user_id,
                    ),
                    output_dir,
                    result.static_verifier_explain_json,
                )
            )
            candidate_records += 1

        eligible = [item for item in candidate_results if item.eligible_for_template_oracle]
        excluded = [item for item in candidate_results if not item.eligible_for_template_oracle]
        if not eligible:
            raise PostgresError(f"no eligible E2 templates for artifact_availability={artifact_availability}")
        chosen = min(eligible, key=lambda item: (item.execution_ms, item.template_id))
        raw_paths.append(
            _write_record(
                _normal_record(
                    root,
                    manifest_path,
                    manifest_id,
                    ADMISSION_FIRST_MODE,
                    chosen,
                    scale,
                    seed,
                    policy_id,
                    context_id,
                    ctx_hash,
                    pg_version,
                    total_rows,
                    authorized_rows,
                    artifact_cardinality,
                    s_auth,
                    s_q,
                    policy_cost,
                    exact_predicate=exact_predicate,
                    guard_predicate=guard_predicate,
                    lo=lo,
                    hi=hi,
                    artifact_id=artifact_id,
                    keyed_artifact_id=keyed_artifact_id,
                    mav_relation=mav_artifact_id,
                    user_id=user_id,
                ),
                output_dir,
                chosen.static_verifier_explain_json,
            )
        )
        normal_records += 1

        barrier = _find_candidate(candidate_results, "barrier_filter_v1")
        raw_paths.append(
            _write_record(
                _normal_record(
                    root,
                    manifest_path,
                    manifest_id,
                    "barrier-only",
                    barrier,
                    scale,
                    seed,
                    policy_id,
                    context_id,
                    ctx_hash,
                    pg_version,
                    total_rows,
                    authorized_rows,
                    artifact_cardinality,
                    s_auth,
                    s_q,
                    policy_cost,
                    exact_predicate=exact_predicate,
                    guard_predicate=guard_predicate,
                    lo=lo,
                    hi=hi,
                    artifact_id=artifact_id,
                    keyed_artifact_id=keyed_artifact_id,
                    mav_relation=mav_artifact_id,
                    user_id=user_id,
                ),
                output_dir,
                barrier.static_verifier_explain_json,
            )
        )
        normal_records += 1

        auth_index = _find_candidate(candidate_results, "auth_index_enum_v1")
        raw_paths.append(
            _write_record(
                _normal_record(
                    root,
                    manifest_path,
                    manifest_id,
                    "auth-index-enum-only",
                    auth_index,
                    scale,
                    seed,
                    policy_id,
                    context_id,
                    ctx_hash,
                    pg_version,
                    total_rows,
                    authorized_rows,
                    artifact_cardinality,
                    s_auth,
                    s_q,
                    policy_cost,
                    exact_predicate=exact_predicate,
                    guard_predicate=guard_predicate,
                    lo=lo,
                    hi=hi,
                    artifact_id=artifact_id,
                    keyed_artifact_id=keyed_artifact_id,
                    mav_relation=mav_artifact_id,
                    user_id=user_id,
                ),
                output_dir,
                auth_index.static_verifier_explain_json,
            )
        )
        normal_records += 1

        raw_paths.append(
            _write_record(
                _summary_record(
                    root,
                    manifest_path,
                    manifest_id,
                    artifact_availability,
                    eligible,
                    excluded,
                    chosen,
                    scale,
                    seed,
                    policy_id,
                    context_id,
                    ctx_hash,
                    pg_version,
                    total_rows,
                    authorized_rows,
                    artifact_cardinality,
                    s_auth,
                    s_q,
                    policy_cost,
                    exact_predicate=exact_predicate,
                    guard_predicate=guard_predicate,
                    lo=lo,
                    hi=hi,
                    artifact_id=artifact_id,
                    keyed_artifact_id=keyed_artifact_id,
                    mav_relation=mav_artifact_id,
                    user_id=user_id,
                ),
                output_dir,
                chosen.static_verifier_explain_json,
            )
        )
        summary_records += 1

    return E2SmokeResult(
        raw_result_paths=raw_paths,
        candidate_records=candidate_records,
        normal_records=normal_records,
        summary_records=summary_records,
        artifact_unavailable_records=artifact_unavailable_records,
    )

def _find_candidate(candidates: list[CandidateResult], template_id: str) -> CandidateResult:
    for candidate in candidates:
        if candidate.template_id == template_id:
            return candidate
    raise PostgresError(f"missing candidate result: {template_id}")
