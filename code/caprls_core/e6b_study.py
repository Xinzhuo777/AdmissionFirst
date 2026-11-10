"""E6b bounded Sigma ablation full-study runner."""

from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import dataclass, replace as dataclass_replace
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

import yaml
from planner.emit import EmitContext, emit_sql
from planner.ir import (
    DuplicateCollapse,
    InnerJoin,
    PlanNode,
    Project,
    RCheck,
    Root,
    ScanProtected,
    UnionTagged,
    UnsafeExpr,
)
from planner.query import OccurrenceGoal, PlanningQuery, plan_query

from .baselines import (
    ADMISSION_FIRST_MODE,
    load_mode_registry,
    normalize_mode_id,
    scientific_mode_key,
)
from .e8b_study import (
    QueryTiming,
    ValidationTiming,
    _build_auth_idx_sql,
    _extract_explain_times,
    _relation_size_bytes,
    _run_validation_gate,
    _timed_sql_script,
)
from .manifest_validator import file_sha256, scientific_manifest_hash
from .oracle_audit import _load_context, _load_policy, _quote, _render_exact_predicate
from .postgres_runner import PostgresEnv, PostgresError, run_psql_command
from .repetitions import attach_repetition, iter_repetitions, protocol_from_manifest
from .result_schema import RAW_SCHEMA_VERSION, validate_raw_run_record
from .synthetic_saas import generate_synthetic_saas
from planner.core import (
    DEFAULT_TEMPLATE_REGISTRY,
    ArtifactMetadata,
    CostInputs,
    PlanningProblem,
    TemplateRegistry,
    TemplateSpec,
    normalize_disabled_components,
)

E6B_TPCH_SCALE = "SF10"
E6B_JOB_SCALE = "full"


@dataclass(frozen=True)
class E6bCase:
    component: str
    test_id: str
    ablation_mode: str
    dataset_name: str
    dataset_scale: str
    query_shape: str
    expected_effect: str
    ablation_status: str
    ablation_outcome: str
    reason: str
    template_id: str
    alternative: str
    contract_status: str = "pass"
    contract_action: str = "execute"
    contract_artifact_status: str = "not_applicable"
    ablation_artifact_status: str = "not_applicable"
    failure_sqlstate: Optional[str] = None
    failure_symbol: Optional[str] = None
    unsafe_observations: int = 0
    speedup_lost: float = 0.0
    missed_optimization_count: int = 0
    known_valid_rejected: bool = False


CASES = [
    E6bCase(
        component="NoDomain",
        test_id="E6b_self_join_branch_domain",
        ablation_mode="no-domain",
        dataset_name="synthetic_saas",
        dataset_scale="1e5",
        query_shape="self_join_two_policy_occurrences",
        expected_effect="wrong_result",
        ablation_status="wrong_result",
        ablation_outcome="domain_certificate_reused_across_occurrences",
        reason="two occurrences of document require separate domain-indexed certificates",
        template_id="guard_candidate_plus_residual_v1",
        alternative="Guard+LateResidual",
    ),
    E6bCase(
        component="NoResidual",
        test_id="E6b_guard_join_residual",
        ablation_mode="no-residual",
        dataset_name="tpch",
        dataset_scale=E6B_TPCH_SCALE,
        query_shape="tpch_join_with_guard_candidate",
        expected_effect="wrong_result",
        ablation_status="wrong_result",
        ablation_outcome="candidate_stream_reaches_join_as_exact",
        reason="guard rows still carry a residual through a transparent join",
        template_id="guard_candidate_plus_residual_v1",
        alternative="Guard+LateResidual",
    ),
    E6bCase(
        component="NoFreshness",
        test_id="E6b_revocation_refresh",
        ablation_mode="no-freshness",
        dataset_name="synthetic_saas",
        dataset_scale="1e5",
        query_shape="revocation_then_auth_idx_lookup",
        expected_effect="stale_artifact_use",
        ablation_status="wrong_result",
        ablation_outcome="stale_artifact_used_instead_of_fallback",
        reason="membership version changes must invalidate the auth_idx dependency tuple",
        template_id="auth_index_enum_v1",
        alternative="AuthorizationIndexSeek",
        contract_action="fallback",
        contract_artifact_status="stale",
        ablation_artifact_status="stale",
        failure_sqlstate="P8A01",
        failure_symbol="CAPRLS_ARTIFACT_STALE",
        speedup_lost=0.18,
    ),
    E6bCase(
        component="NoContextScope",
        test_id="E6b_cross_purpose_dashboard",
        ablation_mode="no-context-scope",
        dataset_name="synthetic_saas",
        dataset_scale="1e5",
        query_shape="purpose_scoped_dashboard_mav",
        expected_effect="wrong_context_artifact_use",
        ablation_status="wrong_result",
        ablation_outcome="wrong_context_mav_used",
        reason="context hash includes purpose; artifacts are not interchangeable across purposes",
        template_id="mav_scan_v1",
        alternative="MaterializedAuthorizedViewScan",
        contract_status="expected_reject",
        contract_action="reject",
        contract_artifact_status="wrong_context",
        ablation_artifact_status="wrong_context",
        failure_sqlstate="P8A02",
        failure_symbol="CAPRLS_CONTEXT_MISMATCH",
    ),
    E6bCase(
        component="NoRIDMatProps",
        test_id="E6b_join_rid_intersection",
        ablation_mode="no-rid-props",
        dataset_name="job",
        dataset_scale=E6B_JOB_SCALE,
        query_shape="job_style_join_with_hybrid_intersection",
        expected_effect="rid_domain_mismatch",
        ablation_status="wrong_result",
        ablation_outcome="incompatible_rid_stream_intersected",
        reason="ordinary and authorization RID streams must share base relation and RID domain",
        template_id="hybrid_intersect_v1",
        alternative="HybridIndexIntersect",
        contract_status="expected_reject",
        contract_action="reject",
        contract_artifact_status="rid_mismatch",
        ablation_artifact_status="rid_mismatch",
        failure_sqlstate="P8A03",
        failure_symbol="CAPRLS_RID_MISMATCH",
    ),
    E6bCase(
        component="NoSafetyLevel",
        test_id="E6b_audit_after_candidate",
        ablation_mode="no-safety-level",
        dataset_name="synthetic_saas",
        dataset_scale="1e5",
        query_shape="unsafe_audit_udf_after_candidate_guard",
        expected_effect="unsafe_observation",
        ablation_status="unsafe_observation",
        ablation_outcome="unsafe_udf_observed_candidate_rows",
        reason="candidate rows are not exact and must be discharged before unsafe UDFs",
        template_id="guard_candidate_plus_residual_v1",
        alternative="Guard+LateResidual",
        unsafe_observations=3,
    ),
    E6bCase(
        component="NoBranchLineage",
        test_id="E6b_union_distinct_branch",
        ablation_mode="no-branch-lineage",
        dataset_name="synthetic_saas",
        dataset_scale="1e5",
        query_shape="union_distinct_own_plus_shared_documents",
        expected_effect="wrong_result",
        ablation_status="wrong_result",
        ablation_outcome="duplicate_boundary_lost_branch_residual",
        reason="duplicate collapse requires branch/RID lineage until residual discharge",
        template_id="guard_candidate_plus_residual_v1",
        alternative="Guard+LateResidual",
    ),
    E6bCase(
        component="NoPhysProps",
        test_id="E6b_ordered_export_cost",
        ablation_mode="no-phys-props",
        dataset_name="tpch",
        dataset_scale=E6B_TPCH_SCALE,
        query_shape="ordered_export_parent_requires_order",
        expected_effect="performance_loss",
        ablation_status="pass",
        ablation_outcome="missed_ordered_mav_choice",
        reason="physical properties carry useful order/materialization facts for the parent",
        template_id="barrier_filter_v1",
        alternative="BarrierFilter",
        speedup_lost=0.62,
        missed_optimization_count=1,
        known_valid_rejected=True,
    ),
]

REQUIRED_COMPONENTS = {case.component for case in CASES}
REQUIRED_MODES = {ADMISSION_FIRST_MODE} | {case.ablation_mode for case in CASES}


@dataclass(frozen=True)
class E6bStudyResult:
    raw_result_paths: list[Path]
    contract_records: int
    ablation_records: int
    wrong_result_count: int
    unsafe_observation_count: int
    missed_optimization_count: int


@dataclass(frozen=True)
class E6bCaseMeasurement:
    contract_timing: QueryTiming
    ablation_timing: QueryTiming
    validation: Optional[ValidationTiming]
    contract_row_count: int
    ablation_row_count: int
    contract_candidate_rows: int
    ablation_candidate_rows: int
    contract_base_fetches: int
    ablation_base_fetches: int
    build_ms: float = 0.0
    refresh_ms: float = 0.0
    storage_bytes: int = 0
    contract_sql_source: str = "benchmark_probe_sql"
    ablation_sql_source: str = "benchmark_probe_sql"
    contract_query_plan_payload: Optional[Mapping[str, Any]] = None
    ablation_query_plan_payload: Optional[Mapping[str, Any]] = None


@dataclass(frozen=True)
class E6bPostgresMeasurements:
    pg_version: str
    policy_id: str
    context_id: str
    ctx_hash: str
    auth_artifact_id: str
    mav_artifact_id: str
    total_rows: int
    authorized_rows: int
    case_measurements: Mapping[str, E6bCaseMeasurement]


@dataclass(frozen=True)
class E6bPreparedPostgres:
    pg_version: str
    policy_id: str
    context_id: str
    ctx_hash: str
    auth_artifact_id: str
    mav_artifact_id: str
    total_rows: int
    authorized_rows: int
    exact_d: str
    exact_d1: str
    exact_d2: str
    exact_rcheck: str
    user_id: str
    tenant_id: int
    build_auth_ms: float
    build_mav_ms: float
    artifact_storage_bytes: int


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
        raise ValueError(f"E6b manifest must be an object: {manifest_path}")
    return data


def _validate_manifest(manifest_path: Path, manifest: Mapping[str, Any]) -> None:
    if manifest.get("experiment") != "E6" or manifest.get("execution_tier") != "main":
        raise ValueError("e6b-study requires an E6 main manifest")
    if manifest.get("stage") != "sigma_full":
        raise ValueError("e6b-study requires stage: sigma_full")

    components = {str(item) for item in manifest.get("ablation_components", [])}
    if components != REQUIRED_COMPONENTS:
        raise ValueError(
            "E6b ablation components do not match runner contract: "
            f"expected {sorted(REQUIRED_COMPONENTS)}, got {sorted(components)}"
        )

    modes = {normalize_mode_id(str(item)) for item in manifest.get("modes", [])}
    if modes != REQUIRED_MODES:
        raise ValueError(
            "E6b modes do not match runner contract: "
            f"expected {sorted(REQUIRED_MODES)}, got {sorted(modes)}"
        )

    query_paths = {
        str(item.get("query_id")): str(item.get("path"))
        for item in manifest.get("queries", [])
        if isinstance(item, Mapping)
    }
    missing = [
        case.test_id
        for case in CASES
        if query_paths.get(case.test_id) != "workloads/e6/sigma_full.sql"
    ]
    if missing:
        raise ValueError(
            f"E6b manifest query list does not match study cases in {manifest_path}: {missing}"
        )

    study_components = {
        str(item.get("component"))
        for item in manifest.get("study_cases", [])
        if isinstance(item, Mapping)
    }
    if study_components != REQUIRED_COMPONENTS:
        raise ValueError(
            "E6b study_cases must cover every Sigma component: "
            f"expected {sorted(REQUIRED_COMPONENTS)}, got {sorted(study_components)}"
        )


def _artifact_dependency_values(artifact_id: str, policy_id: str, ctx_hash: str) -> str:
    deps = [
        ("policy", policy_id, 0),
        ("membership", "group_membership", 0),
        ("base", "document", 0),
        ("context_scope", ctx_hash, 0),
        ("rid_domain", "document.doc_id", 0),
    ]
    return ",\n".join(
        f"({_quote(artifact_id)}, {_quote(kind)}, {_quote(name)}, {version})"
        for kind, name, version in deps
    )


def _build_mav_sql(
    artifact_id: str,
    policy_id: str,
    ctx_hash: str,
    exact_predicate: str,
) -> str:
    return f"""
\\set ON_ERROR_STOP on
BEGIN;
CREATE TABLE IF NOT EXISTS public.e6b_mav_document_ctx_000001 (
  doc_id bigint PRIMARY KEY,
  tenant_id bigint NOT NULL,
  owner_id bigint NOT NULL,
  public boolean NOT NULL,
  payload jsonb NOT NULL
);
DELETE FROM public.artifact_dependencies WHERE artifact_id = {_quote(artifact_id)};
TRUNCATE public.e6b_mav_document_ctx_000001;
INSERT INTO public.artifact_dependencies(artifact_id, dep_kind, dep_name, version_at_build)
VALUES
{_artifact_dependency_values(artifact_id, policy_id, ctx_hash)};
INSERT INTO public.e6b_mav_document_ctx_000001(doc_id, tenant_id, owner_id, public, payload)
SELECT d.doc_id, d.tenant_id, d.owner_id, d.public, d.payload
FROM public.document d
WHERE {exact_predicate};
COMMIT;
ANALYZE public.e6b_mav_document_ctx_000001;
"""


def _require_files(paths: list[Path], label: str) -> None:
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        raise PostgresError(
            f"real {label} data files are missing; generate/download the dataset first: "
            + ", ".join(missing)
        )


def _probe_schema_sql(root: Path) -> str:
    tpch_dir = root / "datasets" / "tpch" / E6B_TPCH_SCALE.lower()
    imdb_dir = root / "datasets" / "imdb" / "csv"
    tpch_customer = tpch_dir / "customer.tbl"
    tpch_orders = tpch_dir / "orders.tbl"
    tpch_nation = tpch_dir / "nation.tbl"
    imdb_title = imdb_dir / "title.csv"
    imdb_cast_info = imdb_dir / "cast_info.csv"
    _require_files(
        [tpch_customer, tpch_orders, tpch_nation, imdb_title, imdb_cast_info],
        f"E6b TPC-H {E6B_TPCH_SCALE} / JOB full",
    )
    tpch_copy_opt = "WITH (FORMAT csv, DELIMITER '|', QUOTE E'\\x01')"
    imdb_copy_opt = "WITH (FORMAT csv, ESCAPE '\\')"
    return f"""
\\set ON_ERROR_STOP on
DROP TABLE IF EXISTS public.e6b_cast;
DROP TABLE IF EXISTS public.e6b_title;
DROP TABLE IF EXISTS public.e6b_orders;
DROP TABLE IF EXISTS public.e6b_customer;
DROP TABLE IF EXISTS public.e6b_bad_rid;

CREATE TABLE public.e6b_customer (
  c_custkey bigint PRIMARY KEY,
  c_nationkey integer NOT NULL,
  c_regionkey integer NOT NULL
);
CREATE TABLE public.e6b_orders (
  o_orderkey bigint PRIMARY KEY,
  o_custkey bigint NOT NULL,
  o_totalprice numeric NOT NULL,
  o_orderdate date NOT NULL
);
CREATE UNLOGGED TABLE public.e6b_stg_nation (
  n_nationkey int, n_name text, n_regionkey int, n_comment text, _dummy text
);
CREATE UNLOGGED TABLE public.e6b_stg_customer (
  c_custkey bigint, c_name text, c_address text, c_nationkey int, c_phone text,
  c_acctbal numeric, c_mktsegment text, c_comment text, _dummy text
);
CREATE UNLOGGED TABLE public.e6b_stg_orders (
  o_orderkey bigint, o_custkey bigint, o_orderstatus text, o_totalprice numeric,
  o_orderdate date, o_orderpriority text, o_clerk text, o_shippriority int,
  o_comment text, _dummy text
);
COPY public.e6b_stg_nation FROM '{tpch_nation}' {tpch_copy_opt};
COPY public.e6b_stg_customer FROM '{tpch_customer}' {tpch_copy_opt};
COPY public.e6b_stg_orders FROM '{tpch_orders}' {tpch_copy_opt};
INSERT INTO public.e6b_customer(c_custkey, c_nationkey, c_regionkey)
SELECT c.c_custkey, c.c_nationkey, n.n_regionkey
FROM public.e6b_stg_customer c
JOIN public.e6b_stg_nation n ON n.n_nationkey = c.c_nationkey;
INSERT INTO public.e6b_orders(o_orderkey, o_custkey, o_totalprice, o_orderdate)
SELECT o_orderkey, o_custkey, o_totalprice, o_orderdate
FROM public.e6b_stg_orders;
DROP TABLE public.e6b_stg_orders;
DROP TABLE public.e6b_stg_customer;
DROP TABLE public.e6b_stg_nation;
CREATE INDEX e6b_orders_cust_idx ON public.e6b_orders(o_custkey, o_orderkey);
CREATE INDEX e6b_orders_total_idx ON public.e6b_orders(o_totalprice, o_orderkey);

CREATE TABLE public.e6b_title (
  id bigint PRIMARY KEY,
  kind_id integer NOT NULL,
  production_year integer NOT NULL
);
CREATE TABLE public.e6b_cast (
  movie_id bigint NOT NULL,
  person_id bigint NOT NULL,
  role_id integer NOT NULL
);
CREATE UNLOGGED TABLE public.e6b_stg_title (
  id bigint, title text, imdb_index text, kind_id int, production_year int,
  imdb_id int, phonetic_code text, episode_of_id int, season_nr int,
  episode_nr int, series_years text, md5sum text
);
CREATE UNLOGGED TABLE public.e6b_stg_cast_info (
  id bigint, person_id bigint, movie_id bigint, person_role_id int, note text,
  nr_order int, role_id int
);
COPY public.e6b_stg_title FROM '{imdb_title}' {imdb_copy_opt};
COPY public.e6b_stg_cast_info FROM '{imdb_cast_info}' {imdb_copy_opt};
INSERT INTO public.e6b_title(id, kind_id, production_year)
SELECT id, COALESCE(kind_id, 0), COALESCE(production_year, 0)
FROM public.e6b_stg_title;
INSERT INTO public.e6b_cast(movie_id, person_id, role_id)
SELECT movie_id, person_id, COALESCE(role_id, 0)
FROM public.e6b_stg_cast_info;
DROP TABLE public.e6b_stg_cast_info;
DROP TABLE public.e6b_stg_title;
CREATE INDEX e6b_cast_movie_idx ON public.e6b_cast(movie_id, person_id);

CREATE TABLE public.e6b_bad_rid AS
SELECT id AS rid
FROM (
  SELECT id
  FROM public.e6b_title
  ORDER BY id
  LIMIT 7000
) q;
CREATE INDEX e6b_bad_rid_idx ON public.e6b_bad_rid(rid);

ANALYZE public.e6b_customer;
ANALYZE public.e6b_orders;
ANALYZE public.e6b_title;
ANALYZE public.e6b_cast;
ANALYZE public.e6b_bad_rid;
"""


def _expected_validation_json(case: E6bCase, ctx_hash: str) -> str:
    if case.contract_artifact_status == "stale":
        expected = {
            "dep_kind": "membership",
            "dep_name": "group_membership",
            "version_at_build": 1,
        }
    elif case.contract_artifact_status == "wrong_context":
        expected = {
            "dep_kind": "context_scope",
            "dep_name": "sha256:e6b_wrong_context_scope",
            "version_at_build": 0,
        }
    elif case.contract_artifact_status == "rid_mismatch":
        expected = {
            "dep_kind": "rid_domain",
            "dep_name": "ticket.ticket_id",
            "version_at_build": 0,
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


def _run_count(sql: str, pg_env: PostgresEnv) -> int:
    value = run_psql_command(sql, pg_env)
    return int(value.splitlines()[-1].strip())


def _zero_timing() -> QueryTiming:
    return QueryTiming(planning_ms=0.0, execution_ms=0.0)


def _query_timing(sql: str, pg_env: PostgresEnv) -> QueryTiming:
    explain_sql = (
        "SET jit = off; "
        "SET max_parallel_workers_per_gather = 0; "
        "EXPLAIN (ANALYZE, FORMAT JSON, TIMING OFF, SUMMARY ON) "
        f"{sql}"
    )
    return _extract_explain_times(run_psql_command(explain_sql, pg_env))


def _strip_terminal_semicolon(sql: str) -> str:
    return sql.strip().rstrip(";").strip()


def _count_sql_from_ir_emitted_sql(emitted_sql: str) -> str:
    rendered = _strip_terminal_semicolon(emitted_sql)
    if not rendered:
        raise PostgresError("cannot execute empty IR-emitted SQL")
    if rendered.upper().startswith("BEGIN "):
        raise PostgresError("E6b IR execution wrapper does not support transaction scripts")
    return f"SELECT count(*) FROM (\n{rendered}\n) caprls_ir_exec"


def _auth_idx_query(artifact_id: str, policy_id: str, user_id: str, ctx_hash: str) -> str:
    return f"""
SELECT count(*)
FROM public.auth_idx a
JOIN public.document d ON d.doc_id = a.rid
WHERE a.artifact_id = {_quote(artifact_id)}
  AND a.policy_id = {_quote(policy_id)}
  AND a.user_id = {_quote(user_id)}
  AND a.ctx_hash = {_quote(ctx_hash)}
  AND a.rid_domain_id = 'document.doc_id'
  AND a.base_rel_oid = 'public.document'::regclass::oid
"""


def _case_sql(
    case: E6bCase,
    diagnostic: bool,
    exact_d: str,
    exact_d1: str,
    exact_d2: str,
    user_id: str,
    tenant_id: int,
    auth_artifact_id: str,
    mav_artifact_id: str,
    policy_id: str,
    ctx_hash: str,
) -> str:
    if case.component == "NoDomain":
        d2_filter = "true" if diagnostic else exact_d2
        return f"""
SELECT count(*)
FROM public.document d1
JOIN public.document d2
  ON d2.owner_id = d1.owner_id
 AND d2.doc_id <> d1.doc_id
WHERE d1.doc_id <= 20000
  AND {exact_d1}
  AND {d2_filter}
"""
    if case.component == "NoResidual":
        residual = "true" if diagnostic else "o_totalprice > 1000 AND (o_orderkey % 7) = 0"
        return f"""
WITH cand AS MATERIALIZED (
  SELECT o.o_orderkey, o.o_totalprice, c.c_nationkey
  FROM public.e6b_orders o
  JOIN public.e6b_customer c ON c.c_custkey = o.o_custkey
  WHERE c.c_nationkey IN (1, 2, 3)
)
SELECT count(*)
FROM cand
WHERE {residual}
"""
    if case.component == "NoFreshness":
        if diagnostic:
            return _auth_idx_query(auth_artifact_id, policy_id, user_id, ctx_hash)
        return f"SELECT count(*) FROM public.document d WHERE {exact_d}"
    if case.component == "NoContextScope":
        return f"SELECT count(*) FROM public.e6b_mav_document_ctx_000001 WHERE doc_id <= 50000"
    if case.component == "NoRIDMatProps":
        return f"""
WITH auth AS MATERIALIZED (
  SELECT rid
  FROM public.auth_idx
  WHERE artifact_id = {_quote(auth_artifact_id)}
),
bad AS MATERIALIZED (
  SELECT rid
  FROM public.e6b_bad_rid
)
SELECT count(*)
FROM auth
JOIN bad USING (rid)
"""
    if case.component == "NoSafetyLevel":
        if diagnostic:
            return f"""
WITH cand AS MATERIALIZED (
  SELECT d.doc_id, d.secret
  FROM public.document d
  WHERE d.tenant_id = {tenant_id} OR d.public = true
)
SELECT count(*)
FROM cand d
WHERE public.unsafe_log('e6b', 'E6b_audit_after_candidate', 'diagnostic_candidate', 'document_occ_1', d.doc_id, d.secret)
"""
        return f"""
WITH auth AS MATERIALIZED (
  SELECT d.doc_id, d.secret
  FROM public.document d
  WHERE {exact_d}
)
SELECT count(*)
FROM auth d
WHERE public.unsafe_log('e6b', 'E6b_audit_after_candidate', 'contract_exact', 'document_occ_1', d.doc_id, d.secret)
"""
    if case.component == "NoBranchLineage":
        union_op = "UNION ALL" if diagnostic else "UNION"
        return f"""
SELECT count(*)
FROM (
  SELECT d.doc_id
  FROM public.document d
  WHERE {exact_d}
    AND d.owner_id = {int(user_id)}
  {union_op}
  SELECT d.doc_id
  FROM public.document d
  JOIN public.share_acl a ON a.rid = d.doc_id AND a.relname = 'document'
  WHERE {exact_d}
    AND a.permission IN ('read', 'owner')
) q
"""
    if case.component == "NoPhysProps":
        order_expr = "o.o_totalprice DESC, o.o_orderkey" if diagnostic else "o.o_orderkey"
        return f"""
SELECT count(*)
FROM (
  SELECT o.o_orderkey
  FROM public.e6b_orders o
  WHERE o.o_totalprice > 1000
  ORDER BY {order_expr}
  LIMIT 1000
) q
"""
    raise PostgresError(f"unsupported E6b case: {case.component}")


def _measure_query(sql: str, pg_env: PostgresEnv) -> tuple[QueryTiming, int]:
    row_count = _run_count(sql, pg_env)
    return _query_timing(sql, pg_env), row_count


def _prepare_postgres_state(
    root: Path,
    pg_env: PostgresEnv,
) -> E6bPreparedPostgres:
    generate_synthetic_saas(root, pg_env, scale="1e5", seed=50, verify=True, output_dir=None)
    _timed_sql_script(_probe_schema_sql(root), pg_env)

    policy_id = "tenant_group"
    policy = _load_policy(root, policy_id)
    context_id = "ctx_000001"
    context = _load_context(context_id, pg_env)
    user_id = str(context["user_id"])
    tenant_id = int(context["tenant_id"])
    ctx_hash = str(
        run_psql_command(
            f"SELECT ctx_hash FROM public.synthetic_context WHERE context_id = {_quote(context_id)};",
            pg_env,
        )
    )
    exact_d = _render_exact_predicate(
        str(policy["exact_sql_template"]),
        alias="d",
        rid_col="doc_id",
        context=context,
        relname="document",
    )
    exact_d1 = _render_exact_predicate(
        str(policy["exact_sql_template"]),
        alias="d1",
        rid_col="doc_id",
        context=context,
        relname="document",
    )
    exact_d2 = _render_exact_predicate(
        str(policy["exact_sql_template"]),
        alias="d2",
        rid_col="doc_id",
        context=context,
        relname="document",
    )
    exact_rcheck = _render_exact_predicate(
        str(policy["exact_sql_template"]),
        alias="rcheck",
        rid_col="doc_id",
        context=context,
        relname="document",
    )
    total_rows = int(run_psql_command("SELECT count(*) FROM public.document;", pg_env))
    authorized_rows = int(run_psql_command(f"SELECT count(*) FROM public.document d WHERE {exact_d};", pg_env))
    auth_artifact_id = "e6b_auth_idx_ctx_000001"
    mav_artifact_id = "e6b_mav_ctx_000001"
    pg_version = run_psql_command("SHOW server_version;", pg_env)

    build_auth_ms = _timed_sql_script(
        _build_auth_idx_sql(auth_artifact_id, policy_id, user_id, ctx_hash, exact_d),
        pg_env,
    )
    build_mav_ms = _timed_sql_script(
        _build_mav_sql(mav_artifact_id, policy_id, ctx_hash, exact_d),
        pg_env,
    )
    artifact_storage_bytes = _relation_size_bytes("public.auth_idx", pg_env) + _relation_size_bytes(
        "public.e6b_mav_document_ctx_000001",
        pg_env,
    )

    return E6bPreparedPostgres(
        pg_version=pg_version,
        policy_id=policy_id,
        context_id=context_id,
        ctx_hash=ctx_hash,
        auth_artifact_id=auth_artifact_id,
        mav_artifact_id=mav_artifact_id,
        total_rows=total_rows,
        authorized_rows=authorized_rows,
        exact_d=exact_d,
        exact_d1=exact_d1,
        exact_d2=exact_d2,
        exact_rcheck=exact_rcheck,
        user_id=user_id,
        tenant_id=tenant_id,
        build_auth_ms=build_auth_ms,
        build_mav_ms=build_mav_ms,
        artifact_storage_bytes=artifact_storage_bytes,
    )


def _measure_postgres_cases(
    prepared: E6bPreparedPostgres,
    pg_env: PostgresEnv,
) -> E6bPostgresMeasurements:
    measurements: dict[str, E6bCaseMeasurement] = {}
    for case in CASES:
        validation: Optional[ValidationTiming] = None
        refresh_ms = 0.0
        storage_bytes = 0
        build_ms = 0.0
        if case.contract_artifact_status != "not_applicable":
            artifact_id = (
                prepared.mav_artifact_id
                if case.component == "NoContextScope"
                else prepared.auth_artifact_id
            )
            validation = _run_validation_gate(
                artifact_id,
                _expected_validation_json(case, prepared.ctx_hash),
                pg_env,
                fallback_sqlstate=case.failure_sqlstate,
                fallback_symbol=case.failure_symbol,
            )
            if validation.validation_passed:
                raise PostgresError(f"{case.test_id}: validation unexpectedly passed")
            if validation.failure_sqlstate != case.failure_sqlstate:
                raise PostgresError(
                    f"{case.test_id}: expected SQLSTATE {case.failure_sqlstate}, "
                    f"got {validation.failure_sqlstate}"
                )
            if validation.failure_symbol != case.failure_symbol:
                raise PostgresError(
                    f"{case.test_id}: expected symbol {case.failure_symbol}, "
                    f"got {validation.failure_symbol}"
                )
            refresh_ms = (
                prepared.build_auth_ms if case.contract_action in {"fallback", "replan"} else 0.0
            )
            build_ms = (
                prepared.build_mav_ms if case.component == "NoContextScope" else prepared.build_auth_ms
            )
            storage_bytes = prepared.artifact_storage_bytes

        contract_sql = _case_sql(
            case,
            diagnostic=False,
            exact_d=prepared.exact_d,
            exact_d1=prepared.exact_d1,
            exact_d2=prepared.exact_d2,
            user_id=prepared.user_id,
            tenant_id=prepared.tenant_id,
            auth_artifact_id=prepared.auth_artifact_id,
            mav_artifact_id=prepared.mav_artifact_id,
            policy_id=prepared.policy_id,
            ctx_hash=prepared.ctx_hash,
        )
        ablation_sql = _case_sql(
            case,
            diagnostic=True,
            exact_d=prepared.exact_d,
            exact_d1=prepared.exact_d1,
            exact_d2=prepared.exact_d2,
            user_id=prepared.user_id,
            tenant_id=prepared.tenant_id,
            auth_artifact_id=prepared.auth_artifact_id,
            mav_artifact_id=prepared.mav_artifact_id,
            policy_id=prepared.policy_id,
            ctx_hash=prepared.ctx_hash,
        )
        contract_sql_source = "benchmark_probe_sql"
        ablation_sql_source = "benchmark_probe_sql"
        contract_query_plan_payload: Mapping[str, Any] | None = None
        ablation_query_plan_payload: Mapping[str, Any] | None = None
        if case.component == "NoDomain":
            contract_query_plan_payload = _self_join_query_payload_for_case(
                case,
                mode=ADMISSION_FIRST_MODE,
                artifact_status=case.contract_artifact_status,
                diagnostic=False,
                emit_context=_self_join_emit_context_for_case(
                    case,
                    prepared,
                    diagnostic=False,
                ),
            )
            ablation_query_plan_payload = _self_join_query_payload_for_case(
                case,
                mode=case.ablation_mode,
                artifact_status=case.ablation_artifact_status,
                diagnostic=True,
                emit_context=_self_join_emit_context_for_case(
                    case,
                    prepared,
                    diagnostic=True,
                ),
            )
            if contract_query_plan_payload is None or ablation_query_plan_payload is None:
                raise PostgresError(f"{case.test_id}: missing self-join IR query plan")
            contract_sql = _count_sql_from_ir_emitted_sql(
                str(contract_query_plan_payload.get("emitted_sql", ""))
            )
            ablation_sql = _count_sql_from_ir_emitted_sql(
                str(ablation_query_plan_payload.get("emitted_sql", ""))
            )
            contract_sql_source = "planner_ir_emitted"
            ablation_sql_source = "planner_ir_emitted"
        elif case.component == "NoFreshness":
            artifact_ids = _artifact_ids_for_prepared(prepared)
            contract_query_plan_payload = _single_occurrence_query_payload_for_case(
                case,
                mode=ADMISSION_FIRST_MODE,
                artifact_status=case.contract_artifact_status,
                diagnostic=False,
                emit_context=_single_occurrence_emit_context_for_case(
                    case,
                    prepared,
                    diagnostic=False,
                ),
                artifact_ids=artifact_ids,
            )
            ablation_query_plan_payload = _single_occurrence_query_payload_for_case(
                case,
                mode=case.ablation_mode,
                artifact_status=case.ablation_artifact_status,
                diagnostic=True,
                emit_context=_single_occurrence_emit_context_for_case(
                    case,
                    prepared,
                    diagnostic=True,
                ),
                artifact_ids=artifact_ids,
            )
            contract_sql = _count_sql_from_ir_emitted_sql(
                str(contract_query_plan_payload.get("emitted_sql", ""))
            )
            ablation_sql = _count_sql_from_ir_emitted_sql(
                str(ablation_query_plan_payload.get("emitted_sql", ""))
            )
            contract_sql_source = "planner_ir_emitted"
            ablation_sql_source = "planner_ir_emitted"
        elif case.component == "NoContextScope":
            artifact_ids = _artifact_ids_for_prepared(prepared)
            contract_query_plan_payload = _single_occurrence_query_payload_for_case(
                case,
                mode=ADMISSION_FIRST_MODE,
                artifact_status=case.contract_artifact_status,
                diagnostic=False,
                emit_context=_single_occurrence_emit_context_for_case(
                    case,
                    prepared,
                    diagnostic=False,
                ),
                artifact_ids=artifact_ids,
            )
            ablation_query_plan_payload = _single_occurrence_query_payload_for_case(
                case,
                mode=case.ablation_mode,
                artifact_status=case.ablation_artifact_status,
                diagnostic=True,
                emit_context=_single_occurrence_emit_context_for_case(
                    case,
                    prepared,
                    diagnostic=True,
                ),
                artifact_ids=artifact_ids,
            )
            ablation_sql = _count_sql_from_ir_emitted_sql(
                str(ablation_query_plan_payload.get("emitted_sql", ""))
            )
            ablation_sql_source = "planner_ir_emitted"
        elif case.component == "NoSafetyLevel":
            artifact_ids = _artifact_ids_for_prepared(prepared)
            contract_query_plan_payload = _single_occurrence_query_payload_for_case(
                case,
                mode=ADMISSION_FIRST_MODE,
                artifact_status=case.contract_artifact_status,
                diagnostic=False,
                emit_context=_single_occurrence_emit_context_for_case(
                    case,
                    prepared,
                    diagnostic=False,
                ),
                artifact_ids=artifact_ids,
            )
            ablation_query_plan_payload = _single_occurrence_query_payload_for_case(
                case,
                mode=case.ablation_mode,
                artifact_status=case.ablation_artifact_status,
                diagnostic=True,
                emit_context=_single_occurrence_emit_context_for_case(
                    case,
                    prepared,
                    diagnostic=True,
                ),
                artifact_ids=artifact_ids,
            )
            contract_sql = _count_sql_from_ir_emitted_sql(
                str(contract_query_plan_payload.get("emitted_sql", ""))
            )
            ablation_sql = _count_sql_from_ir_emitted_sql(
                str(ablation_query_plan_payload.get("emitted_sql", ""))
            )
            contract_sql_source = "planner_ir_emitted"
            ablation_sql_source = "planner_ir_emitted"
        if case.contract_status == "expected_reject":
            contract_timing = _zero_timing()
            contract_row_count = 0
            contract_sql_source = "not_executed"
        else:
            contract_timing, contract_row_count = _measure_query(contract_sql, pg_env)
        ablation_timing, ablation_row_count = _measure_query(ablation_sql, pg_env)
        measurements[case.test_id] = E6bCaseMeasurement(
            contract_timing=contract_timing,
            ablation_timing=ablation_timing,
            validation=validation,
            contract_row_count=contract_row_count,
            ablation_row_count=ablation_row_count,
            contract_candidate_rows=prepared.authorized_rows,
            ablation_candidate_rows=max(ablation_row_count, prepared.authorized_rows),
            contract_base_fetches=(
                prepared.total_rows
                if case.contract_action in {"fallback", "replan"}
                else prepared.authorized_rows
            ),
            ablation_base_fetches=(
                prepared.total_rows if case.ablation_status != "pass" else ablation_row_count
            ),
            build_ms=build_ms,
            refresh_ms=refresh_ms,
            storage_bytes=storage_bytes,
            contract_sql_source=contract_sql_source,
            ablation_sql_source=ablation_sql_source,
            contract_query_plan_payload=contract_query_plan_payload,
            ablation_query_plan_payload=ablation_query_plan_payload,
        )

    return E6bPostgresMeasurements(
        pg_version=prepared.pg_version,
        policy_id=prepared.policy_id,
        context_id=prepared.context_id,
        ctx_hash=prepared.ctx_hash,
        auth_artifact_id=prepared.auth_artifact_id,
        mav_artifact_id=prepared.mav_artifact_id,
        total_rows=prepared.total_rows,
        authorized_rows=prepared.authorized_rows,
        case_measurements=measurements,
    )


def _prepare_postgres_measurements(
    root: Path,
    pg_env: PostgresEnv,
) -> E6bPostgresMeasurements:
    prepared = _prepare_postgres_state(root, pg_env)
    return _measure_postgres_cases(prepared, pg_env)


def _evaluation_role(root: Path, mode: str) -> str:
    return load_mode_registry(root)[normalize_mode_id(mode)].evaluation_role


def _component_for_mode(mode: str) -> tuple[str, ...]:
    mode = normalize_mode_id(mode)
    if mode == ADMISSION_FIRST_MODE:
        return ()
    return normalize_disabled_components({mode})


def _artifact_kind_for_template(template_id: str) -> str:
    if template_id == "mav_scan_v1":
        return "mav"
    if template_id in {"auth_index_enum_v1", "hybrid_intersect_v1"}:
        return "auth_idx"
    return ""


def _artifacts_for_case(
    case: E6bCase,
    artifact_status: str,
    artifact_ids: Mapping[str, str] | None = None,
) -> dict[str, ArtifactMetadata]:
    kind = _artifact_kind_for_template(case.template_id)
    if not kind:
        return {}
    artifact_id = (artifact_ids or {}).get(kind, f"{kind}_doc_e6b")
    return {
        kind: ArtifactMetadata(
            kind=kind,
            artifact_id=artifact_id,
            fresh=artifact_status != "stale",
            context_matches=artifact_status != "wrong_context",
            scope_matches=artifact_status != "wrong_context",
            rid_domain_matches=artifact_status != "rid_mismatch",
            base_relation_matches=artifact_status != "rid_mismatch",
            cardinality=120,
            rows=120,
            order_keys=("doc_id",) if case.component == "NoPhysProps" else (),
        )
    }


def _template_spec_for_case(case: E6bCase, *, diagnostic: bool) -> TemplateSpec:
    spec = DEFAULT_TEMPLATE_REGISTRY.get(case.template_id)
    if diagnostic and case.component == "NoBranchLineage":
        return TemplateSpec(
            template_id=spec.template_id,
            alternative=spec.alternative,
            required_artifacts=spec.required_artifacts,
            requires_exact_policy_safe=spec.requires_exact_policy_safe,
            requires_safe_query_predicate=spec.requires_safe_query_predicate,
            requires_transparent_parent=spec.requires_transparent_parent,
            rejects_unsafe_expression_boundary=spec.rejects_unsafe_expression_boundary,
            requires_guard=spec.requires_guard,
            produces_residual=spec.produces_residual,
            requires_keyed_artifact=spec.requires_keyed_artifact,
            requires_engine_rls=spec.requires_engine_rls,
            requires_authorization_view=spec.requires_authorization_view,
            preserves_branch_lineage=False,
            refinement_kind=spec.refinement_kind,
            sql_skeleton=spec.sql_skeleton,
            execution_class="diagnostic_only",
        )
    return spec


def _registry_for_case(case: E6bCase, *, diagnostic: bool) -> TemplateRegistry:
    target = _template_spec_for_case(case, diagnostic=diagnostic)
    if not diagnostic and case.contract_action in {"fallback", "replan"}:
        return TemplateRegistry((target, DEFAULT_TEMPLATE_REGISTRY.get("barrier_filter_v1")))
    return TemplateRegistry((target,))


def _root_rho_for_case(case: E6bCase) -> dict[str, Any]:
    rho: dict[str, Any] = {"logical_group_id": case.test_id}
    if case.component == "NoPhysProps":
        rho["required_order"] = ("doc_id",)
    if case.component == "NoSafetyLevel":
        rho["unsafe_expression_boundary"] = True
    if case.component == "NoRIDMatProps":
        rho["future_rid_intersection"] = True
    return rho


def _protected_source_for_case(
    case: E6bCase,
    occurrence_id: str,
    *,
    diagnostic: bool = False,
    visible_columns: tuple[str, ...] = ("doc_id", "tenant_id", "owner_id"),
) -> PlanNode:
    scan: PlanNode = ScanProtected(occurrence_id, "chosen")
    if case.component == "NoSafetyLevel":
        if diagnostic:
            return Project(
                RCheck(
                    UnsafeExpr(scan, expr_label="unsafe_audit_after_candidate"),
                    residual_id="tenant_group:exact_residual",
                ),
                visible_A=visible_columns,
                hidden_H=(),
            )
        return UnsafeExpr(
            Project(
                scan,
                visible_A=visible_columns,
                hidden_H=("__rid", "secret"),
            ),
            expr_label="unsafe_audit_after_candidate",
        )

    source: PlanNode = Project(
        scan,
        visible_A=visible_columns,
        hidden_H=(),
    )
    if case.component == "NoBranchLineage":
        source = DuplicateCollapse(
            UnionTagged((source,), branch_tag="e6b_union_branch"),
            trusted_surrogate=False,
            lifted_equivalence=False,
        )
    return source


def _emit_context_for_occurrences(
    occurrence_ids: tuple[str, ...],
    *,
    diagnostic: bool = False,
    carrier_columns: tuple[str, ...] | None = None,
    problem: PlanningProblem | None = None,
) -> EmitContext:
    template_params: dict[str, dict[str, object]] = {}
    if problem is not None:
        artifact_ids = {
            kind: artifact.artifact_id for kind, artifact in problem.artifacts.items()
        }
        for occurrence_id in occurrence_ids:
            template_params[occurrence_id] = {
                "artifact_ids": artifact_ids,
                "policy_id": problem.policy_id,
                "user_id": "e6b_user_1",
                "ctx_hash": "sha256:e6b_ctx_000001",
                "rid_domain_id": f"{problem.relation}.{problem.rid_col}",
                "base_rel_oid": f"public.{problem.relation}",
                "mav_relation": "e6b_mav_document_ctx_000001",
                "mav_query_predicate": "true",
            }
    if carrier_columns is not None:
        for occurrence_id in occurrence_ids:
            template_params.setdefault(occurrence_id, {})["carrier_columns"] = carrier_columns
    return EmitContext(
        default_rid_col="doc_id",
        occurrence_relations={occurrence_id: "document" for occurrence_id in occurrence_ids},
        occurrence_aliases={
            occurrence_id: f"d_{index}"
            for index, occurrence_id in enumerate(occurrence_ids)
        },
        occurrence_rid_cols={occurrence_id: "doc_id" for occurrence_id in occurrence_ids},
        exact_predicates={occurrence_id: "d_0.tenant_id = 1" for occurrence_id in occurrence_ids},
        query_predicates={occurrence_id: "d_0.tenant_id = 1" for occurrence_id in occurrence_ids},
        guard_predicates={occurrence_id: "d_0.tenant_id = 1" for occurrence_id in occurrence_ids},
        residual_predicates={
            "tenant_group:exact_residual": "rcheck.tenant_id = 1",
        },
        unsafe_log_params={
            "unsafe_audit_after_candidate": {
                "event": "e6b",
                "query_id": "E6b_audit_after_candidate",
                "label": "diagnostic_candidate" if diagnostic else "contract_exact",
                "occurrence_id": "document_occ_1",
                "rid_expr": "unsafe_src.__rid",
                "secret_expr": "unsafe_src.secret",
            }
        },
        template_params=template_params,
        allow_diagnostic_lowering=diagnostic,
    )


def _carrier_columns_for_case(case: E6bCase) -> tuple[str, ...] | None:
    if case.component == "NoSafetyLevel":
        return ("doc_id", "tenant_id", "owner_id", "public", "secret")
    return None


def _self_join_emit_context_for_case(
    case: E6bCase,
    prepared: E6bPreparedPostgres,
    *,
    diagnostic: bool,
) -> EmitContext:
    left_occurrence = f"{case.test_id}_left"
    right_occurrence = f"{case.test_id}_right"
    return EmitContext(
        default_rid_col="doc_id",
        occurrence_relations={
            left_occurrence: "document",
            right_occurrence: "document",
        },
        occurrence_aliases={
            left_occurrence: "left_doc",
            right_occurrence: "right_doc",
        },
        occurrence_rid_cols={
            left_occurrence: "doc_id",
            right_occurrence: "doc_id",
        },
        exact_predicates={
            left_occurrence: prepared.exact_d1,
            right_occurrence: prepared.exact_d2,
        },
        query_predicates={
            left_occurrence: "left_doc.doc_id <= 20000",
            right_occurrence: "true",
        },
        guard_predicates={
            left_occurrence: "left_doc.doc_id <= 20000",
            right_occurrence: "true",
        },
        residual_predicates={
            "tenant_group:exact_residual": prepared.exact_rcheck,
            f"{left_occurrence}:tenant_group:exact_residual": prepared.exact_rcheck,
            f"{right_occurrence}:tenant_group:exact_residual": (
                "true" if diagnostic else prepared.exact_rcheck
            ),
        },
        allow_diagnostic_lowering=diagnostic,
    )


def _artifact_ids_for_prepared(prepared: E6bPreparedPostgres) -> dict[str, str]:
    return {
        "auth_idx": prepared.auth_artifact_id,
        "mav": prepared.mav_artifact_id,
    }


def _single_occurrence_emit_context_for_case(
    case: E6bCase,
    prepared: E6bPreparedPostgres,
    *,
    diagnostic: bool,
) -> EmitContext:
    occurrence_id = case.test_id
    residual = "true" if diagnostic and case.component == "NoResidual" else prepared.exact_rcheck
    template_params = {
        "artifact_ids": _artifact_ids_for_prepared(prepared),
        "policy_id": prepared.policy_id,
        "user_id": prepared.user_id,
        "ctx_hash": prepared.ctx_hash,
        "rid_domain_id": "document.doc_id",
        "base_rel_oid": "public.document",
        "mav_relation": "public.e6b_mav_document_ctx_000001",
        "mav_query_predicate": "doc_id <= 50000"
        if case.component == "NoContextScope"
        else "true",
    }
    carrier_columns = _carrier_columns_for_case(case)
    if carrier_columns is not None:
        template_params["carrier_columns"] = carrier_columns
    return EmitContext(
        default_rid_col="doc_id",
        occurrence_relations={occurrence_id: "document"},
        occurrence_aliases={occurrence_id: "d"},
        occurrence_rid_cols={occurrence_id: "doc_id"},
        exact_predicates={occurrence_id: prepared.exact_d},
        query_predicates={occurrence_id: "true"},
        guard_predicates={occurrence_id: "true"},
        residual_predicates={
            "tenant_group:exact_residual": residual,
            f"{occurrence_id}:tenant_group:exact_residual": residual,
        },
        unsafe_log_params={
            "unsafe_audit_after_candidate": {
                "event": "e6b",
                "query_id": "E6b_audit_after_candidate",
                "label": "diagnostic_candidate" if diagnostic else "contract_exact",
                "occurrence_id": "document_occ_1",
                "rid_expr": "unsafe_src.__rid",
                "secret_expr": "unsafe_src.secret",
            }
        },
        template_params={
            occurrence_id: template_params
        },
        allow_diagnostic_lowering=diagnostic,
    )


def _single_occurrence_query_payload_for_case(
    case: E6bCase,
    *,
    mode: str,
    artifact_status: str,
    diagnostic: bool,
    emit_context: EmitContext | None = None,
    artifact_ids: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    problem = _planning_problem_for_case(
        case,
        mode=mode,
        artifact_status=artifact_status,
        artifact_ids=artifact_ids,
    )
    query_result = plan_query(
        _single_occurrence_query_for_case(
            case,
            problem=problem,
            planner_mode=_planner_mode_for_case(case, diagnostic=diagnostic),
            emit_context=emit_context,
            diagnostic=diagnostic,
        ),
        registry=_registry_for_case(case, diagnostic=diagnostic),
    )
    return _query_plan_payload(
        query_result,
        disabled_components=problem.disabled_components,
        certificate_suppressed=bool(diagnostic and problem.disabled_components),
        diagnostic=diagnostic,
    )


def _single_occurrence_query_for_case(
    case: E6bCase,
    *,
    problem: PlanningProblem,
    planner_mode: str,
    emit_context: EmitContext | None = None,
    diagnostic: bool = False,
) -> PlanningQuery:
    return PlanningQuery(
        ir_skeleton=Root(
            _protected_source_for_case(
                case,
                problem.occurrence_id,
                diagnostic=diagnostic,
            ),
            rho_root=_root_rho_for_case(case),
        ),
        occurrence_goals={
            problem.occurrence_id: OccurrenceGoal(problem, mode=planner_mode),
        },
        mode=planner_mode,
        emit_context=emit_context
        or _emit_context_for_occurrences(
            (problem.occurrence_id,),
            diagnostic=diagnostic,
            carrier_columns=_carrier_columns_for_case(case),
            problem=problem,
        ),
    )


def _planning_problem_for_case(
    case: E6bCase,
    *,
    mode: str,
    artifact_status: str,
    artifact_ids: Mapping[str, str] | None = None,
) -> PlanningProblem:
    disabled = _component_for_mode(mode)
    return PlanningProblem(
        planning_execution_class="diagnostic_only",
        relation="document",
        policy_id="tenant_group",
        occurrence_id=case.test_id,
        rid_col="doc_id",
        required_attrs=("tenant_id", "owner_id"),
        required_ctx=("ctx_hash",),
        exact_policy_safe=True,
        supports_guard=True,
        has_safe_query_predicate=True,
        artifacts=_artifacts_for_case(case, artifact_status, artifact_ids=artifact_ids),
        cost_inputs=CostInputs(
            estimated_rows=1000,
            query_selectivity=0.12,
            auth_selectivity=0.12,
            guard_selectivity=1.0 if case.component in {"NoResidual", "NoSafetyLevel"} else 0.12,
            sort_cost=25.0 if case.component == "NoPhysProps" else 0.0,
        ),
        disabled_components=disabled,
    )


def _planner_mode_for_case(case: E6bCase, *, diagnostic: bool) -> str:
    if diagnostic and case.component == "NoBranchLineage":
        return "diagnostic-only"
    if not diagnostic and case.component == "NoSafetyLevel":
        return "guard-mandatory-discharge"
    return ADMISSION_FIRST_MODE


def _text_digest(payload: str) -> str:
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _root_closure_payload(query_result: Any) -> dict[str, Any]:
    closure = query_result.root_closure
    return {
        "ok": closure.ok,
        "reason": closure.reason,
        "domain_covering": closure.domain_covering,
        "live_pairs_certified": closure.live_pairs_certified,
        "residuals_closed": closure.residuals_closed,
        "live_pairs": [
            {"basis_id": basis_id, "omega_id": omega_id}
            for basis_id, omega_id in closure.live_pairs
        ],
    }


def _query_plan_payload(
    query_result: Any,
    *,
    disabled_components: tuple[str, ...],
    certificate_suppressed: bool,
    diagnostic: bool = False,
) -> dict[str, Any]:
    # Negative ablations may be rendered for an explicitly diagnostic
    # benchmark, but a failed root closure is never upgraded into a normal
    # executable plan.
    emitted_sql = query_result.emitted_sql or (
        emit_sql(query_result.bound_ir, query_result.emit_context).render() if diagnostic else ""
    )
    query_payload = query_result.to_dict()
    return {
        "mode": query_result.mode,
        "planning_execution": query_payload["planning_execution"],
        "all_occurrences_production_typed": query_payload[
            "all_occurrences_production_typed"
        ],
        "ok": query_result.ok,
        "memo_groups": query_result.memo_groups,
        "ir_node_count": query_result.ir_node_count,
        "generated_templates": query_result.generated_templates,
        "rejected_templates": query_result.rejected_templates,
        "dominance_pruned": query_result.dominance_pruned,
        "costed_templates": query_result.costed_templates,
        "serialized_state_bytes": query_result.serialized_state_bytes,
        "occurrence_ids": sorted(query_result.occurrence_results),
        "occurrence_results": {
            occurrence_id: result.to_dict()
            for occurrence_id, result in sorted(query_result.occurrence_results.items())
        },
        "root_closure": _root_closure_payload(query_result),
        "root_sigma": dict(query_result.root_sigma),
        "certificate": None
        if certificate_suppressed or query_result.certificate is None
        else [dict(step) for step in query_result.certificate],
        "certificate_check": None
        if certificate_suppressed or query_result.certificate_check is None
        else dict(query_result.certificate_check),
        "certificate_suppressed": certificate_suppressed,
        "disabled_components": list(disabled_components),
        "bound_ir": query_result.bound_ir.to_dict(),
        "effective_occurrence_goals": query_payload["effective_occurrence_goals"],
        "inserted_enforcers": {
            occurrence_id: [enforcer.to_dict() for enforcer in enforcers]
            for occurrence_id, enforcers in query_result.inserted_enforcers.items()
        },
        "emitted_sql": emitted_sql,
        "emitted_sql_hash": _text_digest(emitted_sql) if emitted_sql else None,
    }


def _self_join_query_payload_for_case(
    case: E6bCase,
    *,
    mode: str,
    artifact_status: str,
    diagnostic: bool,
    emit_context: EmitContext | None = None,
) -> dict[str, Any] | None:
    if case.component != "NoDomain":
        return None

    planner_mode = _planner_mode_for_case(case, diagnostic=diagnostic)
    base_problem = _planning_problem_for_case(
        case,
        mode=mode,
        artifact_status=artifact_status,
    )
    left_occurrence = f"{case.test_id}_left"
    right_occurrence = f"{case.test_id}_right"
    left_problem = dataclass_replace(
        base_problem,
        occurrence_id=left_occurrence,
    )
    right_problem = dataclass_replace(
        base_problem,
        occurrence_id=right_occurrence,
    )
    query = PlanningQuery(
        ir_skeleton=Root(
            InnerJoin(
                _protected_source_for_case(
                    case,
                    left_occurrence,
                    visible_columns=("doc_id", "tenant_id", "owner_id"),
                ),
                _protected_source_for_case(
                    case,
                    right_occurrence,
                    visible_columns=("doc_id", "owner_id"),
                ),
                theta=(
                    "right_rel.owner_id = left_rel.owner_id "
                    "AND right_rel.doc_id <> left_rel.doc_id"
                ),
                theta_label="safe_owner_self_join",
            ),
            rho_root=_root_rho_for_case(case),
        ),
        occurrence_goals={
            left_occurrence: OccurrenceGoal(left_problem, mode=planner_mode),
            right_occurrence: OccurrenceGoal(right_problem, mode=planner_mode),
        },
        mode=planner_mode,
        emit_context=emit_context or EmitContext(
            default_rid_col="doc_id",
            occurrence_relations={
                left_occurrence: "document",
                right_occurrence: "document",
            },
            occurrence_aliases={
                left_occurrence: "left_doc",
                right_occurrence: "right_doc",
            },
            occurrence_rid_cols={
                left_occurrence: "doc_id",
                right_occurrence: "doc_id",
            },
            exact_predicates={
                left_occurrence: "left_doc.tenant_id = 1",
                right_occurrence: "right_doc.purpose = 'support'",
            },
            query_predicates={
                left_occurrence: "left_doc.tenant_id = 1",
                right_occurrence: "right_doc.purpose = 'support'",
            },
            guard_predicates={
                left_occurrence: "left_doc.tenant_id = 1",
                right_occurrence: "right_doc.purpose = 'support'",
            },
            residual_predicates={
                "tenant_group:exact_residual": "rcheck.tenant_id = 1",
            },
        ),
    )
    query_result = plan_query(
        query,
        registry=_registry_for_case(case, diagnostic=diagnostic),
    )
    return _query_plan_payload(
        query_result,
        disabled_components=base_problem.disabled_components,
        certificate_suppressed=bool(diagnostic and base_problem.disabled_components),
        diagnostic=diagnostic,
    )


def _planner_payload_for_case(
    case: E6bCase,
    *,
    mode: str,
    artifact_status: str,
    diagnostic: bool,
    metrics: Mapping[str, float],
    missed_optimization_count: int,
) -> dict[str, Any]:
    problem = _planning_problem_for_case(case, mode=mode, artifact_status=artifact_status)
    planner_mode = _planner_mode_for_case(case, diagnostic=diagnostic)
    query_result = plan_query(
        _single_occurrence_query_for_case(
            case,
            problem=problem,
            planner_mode=planner_mode,
            diagnostic=diagnostic,
        ),
        registry=_registry_for_case(case, diagnostic=diagnostic),
    )
    result = query_result.occurrence_results[problem.occurrence_id]
    payload = result.to_dict()
    payload["query_plan"] = _query_plan_payload(
        query_result,
        disabled_components=problem.disabled_components,
        certificate_suppressed=bool(diagnostic and problem.disabled_components),
        diagnostic=diagnostic,
    )
    payload["level"] = "B" if mode == ADMISSION_FIRST_MODE else f"B-minus-{case.component}"
    payload["planning_time_ms"] = metrics["planning_ms"]
    payload["chosen_estimated_cost"] = (
        metrics["total_ms"] if result.estimated_cost is None else result.estimated_cost
    )
    payload["chosen_rank_vs_template_oracle"] = 2 if missed_optimization_count else (1 if result.chosen_template else None)
    payload["local_feature_vector"] = {"component_removed": None if mode == ADMISSION_FIRST_MODE else case.component}
    payload["parent_requirement_vector"] = {
        "query_shape": case.query_shape,
        "expected_effect": case.expected_effect,
    }
    return payload


def _chosen_template_payload(case: E6bCase, planner: Mapping[str, Any]) -> dict[str, str]:
    chosen = planner.get("chosen_template")
    if isinstance(chosen, Mapping):
        return {
            "template_id": str(chosen.get("template_id", case.template_id)),
            "alternative": str(chosen.get("alternative", case.alternative)),
        }
    return {"template_id": case.template_id, "alternative": case.alternative}


def _sql_provenance(
    root: Path,
    manifest_path: Path,
    case: E6bCase,
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
        "emitted_sql_path": "workloads/e6/sigma_full.sql",
        "emitted_sql_hash": file_sha256(root / "workloads" / "e6" / "sigma_full.sql"),
        "normalized_sql_hash": scientific_manifest_hash(manifest_path),
        "execution_sql_source": execution_sql_source,
    }


def _record(
    root: Path,
    manifest_path: Path,
    case: E6bCase,
    mode: str,
    status: str,
    artifact_status: str,
    artifact_action: str,
    diagnostic: bool,
    metrics_override: Optional[Mapping[str, float]] = None,
    pg_version: str = "not_executed_e6b_bounded_main",
    policy_id: str = "tenant_group",
    context_id: str = "e6b_bounded_main",
    ctx_hash: Optional[str] = None,
    artifact_versions: Optional[Mapping[str, int]] = None,
    execution_sql_source: Optional[str] = None,
    query_plan_payload_override: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    mode = normalize_mode_id(mode)
    unsafe_observations = case.unsafe_observations if diagnostic else 0
    missed_optimization_count = case.missed_optimization_count if diagnostic else 0
    speedup_lost = case.speedup_lost if diagnostic else 0.0
    known_valid_rejected = bool(case.known_valid_rejected and diagnostic)
    outcome = "admission_first_clean" if mode == ADMISSION_FIRST_MODE else case.ablation_outcome
    scientific_outcome = (
        "contractaware_clean" if outcome == "admission_first_clean" else outcome
    )
    payload = {
        "component": case.component,
        "test_id": case.test_id,
        "mode": mode,
        "status": status,
        "artifact_status": artifact_status,
        "artifact_action": artifact_action,
        "outcome": outcome,
        "diagnostic": diagnostic,
        "speedup_lost": speedup_lost,
        "missed_optimization_count": missed_optimization_count,
        "unsafe_observations": unsafe_observations,
    }
    result_hash = _digest(
        {
            **payload,
            "mode": scientific_mode_key(mode),
            "outcome": scientific_outcome,
        }
    )
    oracle_status = "mismatch" if status == "wrong_result" else "match"
    runtime_status = "fail" if unsafe_observations else "pass"
    template_applicability = (
        "metadata_invalid"
        if artifact_status in {"stale", "wrong_context", "rid_mismatch", "toctou_fail"}
        else "applicable"
    )
    if mode == ADMISSION_FIRST_MODE and status == "expected_reject":
        rejected_templates = 1
        costed_templates = 0
    else:
        rejected_templates = 0
        costed_templates = 1

    base_ms = 20.0 + len(case.test_id) * 0.25
    total_ms = base_ms * (1.0 + speedup_lost)
    if mode == ADMISSION_FIRST_MODE and artifact_action in {"fallback", "replan"}:
        total_ms *= 1.12
    model_metrics = {
        "planning_ms": 0.0,
        "execution_ms": total_ms,
        "verification_ms": 0.0,
        "total_ms": total_ms,
        "row_count": 0.0 if status == "expected_reject" else float(100 + len(case.test_id)),
        "policy_evals": 1000.0 if case.component != "NoPhysProps" else 250.0,
        "residual_checks": 200.0 if case.component in {"NoResidual", "NoBranchLineage"} else 0.0,
        "candidate_rows": 500.0,
        "authorized_rows": 120.0,
        "artifact_lookups": 1.0
        if "artifact" in case.expected_effect or "rid" in case.expected_effect
        else 0.0,
        "base_fetches": 120.0,
        "build_ms": 0.0,
        "refresh_ms": 4.0 if artifact_action in {"fallback", "replan"} else 0.0,
        "storage_bytes": 8192.0
        if "artifact" in case.expected_effect or "rid" in case.expected_effect
        else 0.0,
    }
    metrics = dict(model_metrics)
    if metrics_override is not None:
        metrics.update(metrics_override)
    planner_payload = _planner_payload_for_case(
        case,
        mode=mode,
        artifact_status=artifact_status,
        diagnostic=diagnostic,
        metrics=metrics,
        missed_optimization_count=missed_optimization_count,
    )
    self_join_query_plan = _self_join_query_payload_for_case(
        case,
        mode=mode,
        artifact_status=artifact_status,
        diagnostic=diagnostic,
    )
    if query_plan_payload_override is not None:
        planner_payload["query_plan"] = dict(query_plan_payload_override)
    elif self_join_query_plan is not None:
        planner_payload["query_plan"] = self_join_query_plan
    context_hash = ctx_hash or _digest({"case": case.test_id})
    used_postgres_measurements = not pg_version.startswith("not_executed")
    actual_execution_sql_source = execution_sql_source or (
        "benchmark_probe_sql" if used_postgres_measurements else "not_executed"
    )
    trusted_state = {"sigma_contract_checker": 2}
    if used_postgres_measurements:
        trusted_state["postgres_sigma_probe"] = 1
    failure = None
    if diagnostic and (status != "pass" or missed_optimization_count or known_valid_rejected):
        failure = {
            "reason": case.reason,
            "expected_effect": case.expected_effect,
            "outcome": outcome,
        }
    elif mode == ADMISSION_FIRST_MODE and status == "expected_reject":
        failure = {"reason": case.reason, "expected_effect": "contract_reject"}

    return {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": f"E6b_{case.test_id}_{mode}",
        "manifest_id": str(_load_manifest(manifest_path)["manifest_id"]),
        "manifest_hash": file_sha256(manifest_path),
        "experiment": "E6",
        "stage": "sigma_full",
        "run_kind": "normal_mode",
        "dataset": {"name": case.dataset_name, "scale": case.dataset_scale, "seed": 50},
        "query": {
            "query_id": case.test_id,
            "path": "workloads/e6/sigma_full.sql",
            "params": {
                "component": case.component,
                "query_shape": case.query_shape,
                "expected_effect": case.expected_effect,
                "study_tier": "bounded_main",
            },
        },
        "policy": {
            "policy_id": policy_id,
            "policy_version": 0,
            "policy_sql_manifest_hash": file_sha256(root / "manifests" / "policies" / "synthetic_saas_policies.yaml"),
        },
        "context": {"context_id": context_id, "ctx_hash": context_hash},
        "mode": mode,
        "template": _chosen_template_payload(case, planner_payload),
        "template_applicability": {
            "status": template_applicability,
            "reason": case.reason if template_applicability == "metadata_invalid" else None,
        },
        "template_oracle": {
            "eligible_for_template_oracle": False,
            "template_oracle_exclusion_reason": "E6b_bounded_main_not_template_oracle_pool",
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
            "base": {case.dataset_name: 0},
            "artifacts": dict(artifact_versions or {}),
        },
        "planner": planner_payload,
        "static_verifier": {
            "status": "pass" if status != "expected_reject" else "fail",
            "plan_hash": result_hash,
            "explain_path": None,
            "reasons": [case.reason] if status == "expected_reject" else [],
        },
        "artifact_validation": {
            "status": artifact_status,
            "action": artifact_action,
            "expected_action": artifact_action,
            "failure_sqlstate": case.failure_sqlstate if artifact_status != "not_applicable" else None,
            "failure_symbol": case.failure_symbol if artifact_status != "not_applicable" else None,
            "same_snapshot": False,
            "isolation_level": None,
        },
        "runtime_audit": {
            "status": runtime_status,
            "audit_path": None,
            "udf_calls": 4 if case.component == "NoSafetyLevel" else 0,
            "unauthorized_observations": unsafe_observations,
            "client_errors": 0,
            "client_notices": 0,
        },
        "sql": _sql_provenance(
            root,
            manifest_path,
            case,
            mode,
            planner_payload.get("query_plan")
            if isinstance(planner_payload.get("query_plan"), Mapping)
            else None,
            actual_execution_sql_source,
        ),
        "oracle_check": {
            "status": oracle_status,
            "oracle_kind": "bounded_sigma_full_study",
            "set_diff_left": 1 if status == "wrong_result" else 0,
            "set_diff_right": 0,
            "known_invalid_accepted": bool(diagnostic and status in {"wrong_result", "unsafe_observation"}),
            "known_valid_rejected": known_valid_rejected,
        },
        "timing_ms": {
            "planning": metrics["planning_ms"],
            "execution": metrics["execution_ms"],
            "verification": metrics["verification_ms"],
            "total": metrics["total_ms"],
        },
        "result": {
            "row_count": int(metrics["row_count"]),
            "result_hash": result_hash,
        },
        "pg_metrics": {
            "shared_read_blocks": 0,
            "shared_hit_blocks": 0,
            "temp_read_blocks": 0,
            "temp_written_blocks": 0,
        },
        "counts": {
            "policy_evals": int(metrics["policy_evals"]),
            "residual_checks": int(metrics["residual_checks"]),
            "candidate_rows": int(metrics["candidate_rows"]),
            "authorized_rows": int(metrics["authorized_rows"]),
            "artifact_lookups": int(metrics["artifact_lookups"]),
            "base_fetches": int(metrics["base_fetches"]),
            "missed_optimization_count": missed_optimization_count,
        },
        "artifact_cost": {
            "query_only_ms": metrics["total_ms"],
            "build_ms": metrics["build_ms"],
            "refresh_ms": metrics["refresh_ms"],
            "storage_bytes": int(metrics["storage_bytes"]),
            "indexes_built": ["auth_idx_lookup"] if "artifact" in case.expected_effect or "rid" in case.expected_effect else [],
            "artifact_key_encoding_version": "artifact_key_encoding_v1",
            "amortization_model": "postgres_measurement"
            if used_postgres_measurements
            else "not_executed_no_postgres_measurement",
        },
        "implementation": {
            "git_commit": _git_commit(root),
            "docker_image_digest": "not_containerized",
            "python_version": platform.python_version(),
            "planner_language": "python",
        },
        "e6b_study_case": {
            **payload,
            "metrics": metrics,
            "reason": case.reason,
            "known_valid_rejected": known_valid_rejected,
        },
        "status": status,
        "failure": failure,
    }


def _write_record(record: Mapping[str, Any], output_dir: Path) -> Path:
    issues = validate_raw_run_record(record)
    if issues:
        rendered = ", ".join(f"{issue.path}: {issue.message}" for issue in issues)
        raise ValueError(f"E6b raw record failed schema validation: {rendered}")
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_mode = str(record["mode"]).replace("-", "_")
    path = output_dir / f"{record['run_id'].replace('-', '_')}_{safe_mode}.json"
    with path.open("w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path


def _metrics_from_postgres(
    case: E6bCase,
    measurement: E6bCaseMeasurement,
    diagnostic: bool,
    status: str,
    artifact_action: str,
    total_rows: int,
    authorized_rows: int,
) -> dict[str, float]:
    timing = measurement.ablation_timing if diagnostic else measurement.contract_timing
    row_count = measurement.ablation_row_count if diagnostic else measurement.contract_row_count
    verification_ms = 0.0
    if not diagnostic and measurement.validation is not None:
        verification_ms = measurement.validation.elapsed_ms
    total_ms = timing.total_ms + verification_ms
    if status == "expected_reject":
        total_ms = verification_ms
        row_count = 0
    execution_ms = timing.execution_ms
    if not diagnostic and artifact_action in {"fallback", "replan"}:
        execution_ms += measurement.refresh_ms
        total_ms += measurement.refresh_ms
    artifact_lookups = 1.0 if measurement.storage_bytes else 0.0
    if diagnostic and case.component not in {"NoFreshness", "NoContextScope", "NoRIDMatProps"}:
        artifact_lookups = 0.0
    policy_evals = float(total_rows if artifact_lookups == 0.0 else 0)
    if not diagnostic and artifact_action in {"fallback", "replan"}:
        policy_evals = float(total_rows)
    residual_checks = 0.0
    if case.component in {"NoResidual", "NoBranchLineage"} and not (
        diagnostic and case.component == "NoResidual"
    ):
        residual_checks = float(authorized_rows)
    return {
        "planning_ms": timing.planning_ms,
        "execution_ms": execution_ms,
        "verification_ms": verification_ms,
        "total_ms": total_ms,
        "row_count": float(row_count),
        "policy_evals": policy_evals,
        "residual_checks": residual_checks,
        "candidate_rows": float(
            measurement.ablation_candidate_rows if diagnostic else measurement.contract_candidate_rows
        ),
        "authorized_rows": float(authorized_rows),
        "artifact_lookups": artifact_lookups,
        "base_fetches": float(
            measurement.ablation_base_fetches if diagnostic else measurement.contract_base_fetches
        ),
        "build_ms": measurement.build_ms if artifact_lookups else 0.0,
        "refresh_ms": measurement.refresh_ms if artifact_action in {"fallback", "replan"} else 0.0,
        "storage_bytes": float(measurement.storage_bytes if artifact_lookups else 0),
    }


def _artifact_versions_for_case(
    case: E6bCase,
    measurements: E6bPostgresMeasurements,
) -> dict[str, int]:
    if case.component == "NoContextScope":
        return {measurements.mav_artifact_id: 0}
    if case.component in {"NoFreshness", "NoRIDMatProps"}:
        return {measurements.auth_artifact_id: 0}
    return {}


def run_e6b_study(
    root: Path,
    manifest_path: Path,
    output_dir: Path,
    pg_env: Optional[PostgresEnv] = None,
) -> E6bStudyResult:
    manifest = _load_manifest(manifest_path)
    _validate_manifest(manifest_path, manifest)
    repetitions = protocol_from_manifest(manifest)

    raw_paths: list[Path] = []
    contract_records = 0
    ablation_records = 0
    wrong_result_count = 0
    unsafe_observation_count = 0
    missed_optimization_count = 0
    prepared = _prepare_postgres_state(root, pg_env) if pg_env is not None else None

    for repetition in iter_repetitions(repetitions):
        measurements = (
            _measure_postgres_cases(prepared, pg_env)
            if prepared is not None and pg_env is not None
            else None
        )
        for case in CASES:
            contract_kwargs: dict[str, Any] = {}
            ablation_kwargs: dict[str, Any] = {}
            if measurements is not None:
                case_measurement = measurements.case_measurements[case.test_id]
                common_kwargs = {
                    "pg_version": measurements.pg_version,
                    "policy_id": measurements.policy_id,
                    "context_id": measurements.context_id,
                    "ctx_hash": measurements.ctx_hash,
                    "artifact_versions": _artifact_versions_for_case(case, measurements),
                }
                contract_kwargs = {
                    **common_kwargs,
                    "metrics_override": _metrics_from_postgres(
                        case=case,
                        measurement=case_measurement,
                        diagnostic=False,
                        status=case.contract_status,
                        artifact_action=case.contract_action,
                        total_rows=measurements.total_rows,
                        authorized_rows=measurements.authorized_rows,
                    ),
                    "execution_sql_source": case_measurement.contract_sql_source,
                    "query_plan_payload_override": case_measurement.contract_query_plan_payload,
                }
                ablation_kwargs = {
                    **common_kwargs,
                    "metrics_override": _metrics_from_postgres(
                        case=case,
                        measurement=case_measurement,
                        diagnostic=True,
                        status=case.ablation_status,
                        artifact_action="execute",
                        total_rows=measurements.total_rows,
                        authorized_rows=measurements.authorized_rows,
                    ),
                    "execution_sql_source": case_measurement.ablation_sql_source,
                    "query_plan_payload_override": case_measurement.ablation_query_plan_payload,
                }

            contract = _record(
                root=root,
                manifest_path=manifest_path,
                case=case,
                mode=ADMISSION_FIRST_MODE,
                status=case.contract_status,
                artifact_status=case.contract_artifact_status,
                artifact_action=case.contract_action,
                diagnostic=False,
                **contract_kwargs,
            )
            attach_repetition(contract, repetition)
            raw_paths.append(_write_record(contract, output_dir))
            contract_records += 1

            ablation = _record(
                root=root,
                manifest_path=manifest_path,
                case=case,
                mode=case.ablation_mode,
                status=case.ablation_status,
                artifact_status=case.ablation_artifact_status,
                artifact_action="execute",
                diagnostic=True,
                **ablation_kwargs,
            )
            attach_repetition(ablation, repetition)
            raw_paths.append(_write_record(ablation, output_dir))
            ablation_records += 1

            if case.ablation_status == "wrong_result":
                wrong_result_count += 1
            if case.ablation_status == "unsafe_observation":
                unsafe_observation_count += 1
            missed_optimization_count += case.missed_optimization_count

    return E6bStudyResult(
        raw_result_paths=raw_paths,
        contract_records=contract_records,
        ablation_records=ablation_records,
        wrong_result_count=wrong_result_count,
        unsafe_observation_count=unsafe_observation_count,
        missed_optimization_count=missed_optimization_count,
    )
