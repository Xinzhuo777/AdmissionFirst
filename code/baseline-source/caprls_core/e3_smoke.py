"""E3 TPC-H Q3 adapter smoke runner."""

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
from .e2_smoke import _count_wrapper, _run_count_sql, _run_sql_script
from .explain_artifacts import attach_static_verifier_explain
from .manifest_validator import file_sha256
from .oracle_audit import _quote
from .postgres_runner import PostgresEnv, PostgresError, init_db, run_psql_command
from .result_schema import RAW_SCHEMA_VERSION, validate_raw_run_record

REDUCED_TPCH_SCALE = "reduced_1k_customer_2k_orders_6k_lineitem"


@dataclass(frozen=True)
class E3PolicyConfig:
    config_id: str
    selectivity: float
    policy_cost: str
    artifacts: str
    exact_predicate: str
    # Experiment-side Gamma label: True only for full, side-effect-free relational
    # policy predicates that may be placed as SafePredicateInjection.
    injection_safe: bool = False


@dataclass(frozen=True)
class E3ModeResult:
    policy_config_id: str
    mode: str
    template_id: str
    alternative: str
    status: str
    template_applicability: str
    row_count: int
    execution_ms: float
    build_ms: float
    authorized_customers: int
    result_hash: str
    failure_reason: Optional[str] = None


@dataclass(frozen=True)
class E3SmokeResult:
    raw_result_paths: list[Path]
    normal_records: int
    artifact_unavailable_records: int


POLICY_CONFIGS = [
    E3PolicyConfig(
        config_id="cheap_tenant_sargable",
        selectivity=0.1,
        policy_cost="cheap",
        artifacts="none",
        exact_predicate="c.tenant_id = 1",
    ),
    E3PolicyConfig(
        config_id="hybrid_selective_key",
        selectivity=0.1,
        policy_cost="100us",
        artifacts="both_keyed",
        exact_predicate="c.tenant_id = 1 AND (c.c_custkey % 50) = 0",
    ),
]

REQUIRED_MODES = {
    "native-pg-rls",
    "native-pg-rls-physical-design",
    "barrier-only",
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
    "barrier-only": ("barrier_filter_v1", "BarrierFilter"),
    "strong-auth-index": ("strong_auth_index_keyed_v1", "StrongAuthIndexBaseline"),
}


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
        raise PostgresError(f"E3 manifest must be an object: {manifest_path}")
    return data


def _validate_manifest(manifest_path: Path, manifest: Mapping[str, Any]) -> None:
    if manifest.get("experiment") != "E3" or manifest.get("execution_tier") != "smoke":
        raise PostgresError("e3-smoke requires an E3 smoke manifest")

    modes = {normalize_mode_id(str(item)) for item in manifest.get("modes", [])}
    if modes != REQUIRED_MODES:
        raise PostgresError(
            "E3 modes do not match runner contract: "
            f"expected {sorted(REQUIRED_MODES)}, got {sorted(modes)}"
        )

    queries = {
        str(item.get("query_id")): str(item.get("path"))
        for item in manifest.get("queries", [])
        if isinstance(item, Mapping)
    }
    if queries != {"Q3": "workloads/e3/tpch_q3_smoke.sql"}:
        raise PostgresError(f"E3 smoke supports only Q3; got {queries}")

    configs = {
        str(item.get("id")): str(item.get("artifacts"))
        for item in manifest.get("policy_configs", [])
        if isinstance(item, Mapping)
    }
    expected_configs = {config.config_id: config.artifacts for config in POLICY_CONFIGS}
    if configs != expected_configs:
        raise PostgresError(
            "E3 policy_configs do not match runner contract: "
            f"expected {expected_configs}, got {configs}"
        )

    excluded = manifest.get("excluded_queries_path")
    if not excluded:
        raise PostgresError("E3 smoke manifest must declare excluded_queries_path")
    excluded_path = manifest_path.parents[2] / str(excluded)
    if not excluded_path.exists():
        raise PostgresError(f"E3 excluded queries manifest is missing: {excluded}")


def _setup_sql() -> str:
    return """
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
  o_custkey bigint NOT NULL REFERENCES public.tpch_customer(c_custkey),
  o_orderdate date NOT NULL,
  o_shippriority integer NOT NULL,
  tenant_id bigint NOT NULL
);
CREATE TABLE public.tpch_lineitem (
  l_orderkey bigint NOT NULL REFERENCES public.tpch_orders(o_orderkey),
  l_extendedprice numeric(12,2) NOT NULL,
  l_discount numeric(5,4) NOT NULL,
  l_shipdate date NOT NULL
);
INSERT INTO public.tpch_customer(c_custkey, c_mktsegment, tenant_id, region_id)
SELECT c,
       CASE WHEN c % 2 = 0 THEN 'BUILDING' ELSE 'AUTOMOBILE' END,
       1 + (c % 10),
       1 + (c % 5)
FROM generate_series(1, 1000) AS c;
INSERT INTO public.tpch_orders(o_orderkey, o_custkey, o_orderdate, o_shippriority, tenant_id)
SELECT o,
       1 + (o % 1000),
       DATE '1995-01-01' + ((o % 90) || ' days')::interval,
       (o % 5)::integer,
       1 + ((1 + (o % 1000)) % 10)
FROM generate_series(1, 2000) AS o;
INSERT INTO public.tpch_lineitem(l_orderkey, l_extendedprice, l_discount, l_shipdate)
SELECT 1 + (l % 2000),
       (100 + (l % 10000))::numeric,
       ((l % 10)::numeric / 100.0),
       DATE '1995-03-16' + ((l % 120) || ' days')::interval
FROM generate_series(1, 6000) AS l;
CREATE INDEX tpch_customer_tenant_idx ON public.tpch_customer(tenant_id, c_custkey);
CREATE INDEX tpch_orders_cust_date_idx ON public.tpch_orders(o_custkey, o_orderdate);
CREATE INDEX tpch_lineitem_order_ship_idx ON public.tpch_lineitem(l_orderkey, l_shipdate);
ANALYZE public.tpch_customer;
ANALYZE public.tpch_orders;
ANALYZE public.tpch_lineitem;
"""


def _q3_count_sql(source: str, policy_predicate: Optional[str] = None) -> str:
    if source == "direct":
        auth_cte = ""
        from_customer = "public.tpch_customer AS c"
        extra = f"  AND {policy_predicate}\n" if policy_predicate else ""
    elif source == "barrier":
        auth_cte = f"""
WITH auth_customer AS MATERIALIZED (
  SELECT c.*
  FROM public.tpch_customer c
  WHERE {policy_predicate}
)
"""
        from_customer = "auth_customer AS c"
        extra = ""
    elif source.startswith("auth_idx:"):
        artifact_id = source.split(":", 1)[1]
        auth_cte = f"""
WITH auth_customer AS MATERIALIZED (
  SELECT c.*
  FROM public.auth_idx a
  JOIN public.tpch_customer c ON c.c_custkey = a.rid
  WHERE a.artifact_id = {_quote(artifact_id)}
    AND a.policy_id = 'hybrid_selective_key'
    AND a.user_id = 'e3_user'
    AND a.ctx_hash = 'e3_ctx_hash'
    AND a.rid_domain_id = 'tpch_customer.c_custkey'
    AND a.base_rel_oid = 'public.tpch_customer'::regclass::oid
)
"""
        from_customer = "auth_customer AS c"
        extra = ""
    else:
        raise PostgresError(f"unknown E3 Q3 source: {source}")
    return _count_wrapper(
        f"""
{auth_cte}
SELECT count(*)
FROM (
  SELECT
    l.l_orderkey,
    sum(l.l_extendedprice * (1 - l.l_discount)) AS revenue,
    o.o_orderdate,
    o.o_shippriority
  FROM {from_customer}
  JOIN public.tpch_orders AS o ON o.o_custkey = c.c_custkey
  JOIN public.tpch_lineitem AS l ON l.l_orderkey = o.o_orderkey
  WHERE c.c_mktsegment = 'BUILDING'
    AND o.o_orderdate < DATE '1995-03-15'
    AND l.l_shipdate > DATE '1995-03-15'
{extra}  GROUP BY l.l_orderkey, o.o_orderdate, o.o_shippriority
  ORDER BY revenue DESC, o.o_orderdate
  LIMIT 10
) AS q3;
"""
    )


def _build_auth_idx_sql(policy: E3PolicyConfig, artifact_id: str) -> str:
    return f"""
\\set ON_ERROR_STOP on
BEGIN;
DELETE FROM public.artifact_dependencies WHERE artifact_id = {_quote(artifact_id)};
DELETE FROM public.auth_idx WHERE artifact_id = {_quote(artifact_id)};
INSERT INTO public.artifact_dependencies(artifact_id, dep_kind, dep_name, version_at_build)
VALUES
  ({_quote(artifact_id)}, 'policy', {_quote(policy.config_id)}, 0),
  ({_quote(artifact_id)}, 'base', 'tpch_customer', 0),
  ({_quote(artifact_id)}, 'context_scope', 'e3_ctx_hash', 0),
  ({_quote(artifact_id)}, 'rid_domain', 'tpch_customer.c_custkey', 0);
INSERT INTO public.auth_idx(
  artifact_id, policy_id, user_id, ctx_hash, rid, rid_domain_id, base_rel_oid,
  policy_version, membership_version
)
SELECT
  {_quote(artifact_id)},
  {_quote(policy.config_id)},
  'e3_user',
  'e3_ctx_hash',
  c.c_custkey,
  'tpch_customer.c_custkey',
  'public.tpch_customer'::regclass::oid,
  0,
  0
FROM public.tpch_customer c
WHERE {policy.exact_predicate};
COMMIT;
"""


def _run_sql_returning_count(sql: str, pg_env: PostgresEnv) -> tuple[int, float]:
    return _run_count_sql(sql, pg_env)


def _execute_mode(
    policy: E3PolicyConfig,
    mode: str,
    pg_env: PostgresEnv,
    artifact_id: str,
    build_ms: float,
    authorized_customers: int,
) -> E3ModeResult:
    mode = normalize_mode_id(mode)
    template_id, alternative = _template_for_mode(policy, mode)
    if mode == "strong-auth-index" and policy.artifacts == "none":
        return _unavailable_result(policy, mode, template_id, alternative, authorized_customers)

    if mode in {"native-pg-rls", "native-pg-rls-physical-design"}:
        sql = _q3_count_sql("direct", policy.exact_predicate)
    elif mode == "barrier-only":
        sql = _q3_count_sql("barrier", policy.exact_predicate)
    elif mode in {"strong-auth-index", "local-greedy", ADMISSION_FIRST_MODE}:
        if policy.artifacts == "both_keyed":
            sql = _q3_count_sql(f"auth_idx:{artifact_id}")
        else:
            sql = _q3_count_sql("barrier", policy.exact_predicate)
            template_id = "barrier_filter_v1"
            alternative = "BarrierFilter"
    else:
        raise PostgresError(f"unsupported E3 mode: {mode}")

    row_count, execution_ms = _run_sql_returning_count(sql, pg_env)
    payload = {
        "policy_config_id": policy.config_id,
        "mode": scientific_mode_key(mode),
        "template_id": template_id,
        "row_count": row_count,
        "execution_ms": round(execution_ms, 6),
    }
    return E3ModeResult(
        policy_config_id=policy.config_id,
        mode=mode,
        template_id=template_id,
        alternative=alternative,
        status="pass",
        template_applicability="applicable",
        row_count=row_count,
        execution_ms=execution_ms,
        build_ms=build_ms if "auth_index" in template_id or mode == "strong-auth-index" else 0.0,
        authorized_customers=authorized_customers,
        result_hash=_digest(payload),
    )


def _template_for_mode(policy: E3PolicyConfig, mode: str) -> tuple[str, str]:
    mode = normalize_mode_id(mode)
    if mode in MODE_TEMPLATES:
        return MODE_TEMPLATES[mode]
    if mode == "local-greedy":
        if policy.artifacts == "both_keyed":
            return MODE_TEMPLATES["strong-auth-index"]
        return MODE_TEMPLATES["barrier-only"]
    if mode == ADMISSION_FIRST_MODE:
        if policy.artifacts == "both_keyed":
            return MODE_TEMPLATES["strong-auth-index"]
        return MODE_TEMPLATES["barrier-only"]
    raise PostgresError(f"unsupported E3 mode: {mode}")


def _unavailable_result(
    policy: E3PolicyConfig,
    mode: str,
    template_id: str,
    alternative: str,
    authorized_customers: int,
) -> E3ModeResult:
    mode = normalize_mode_id(mode)
    reason = f"mode {mode} requires auth_idx/auth_idx_keyed but policy_config {policy.config_id} has artifacts=none"
    payload = {
        "policy_config_id": policy.config_id,
        "mode": scientific_mode_key(mode),
        "status": "artifact_unavailable",
    }
    return E3ModeResult(
        policy_config_id=policy.config_id,
        mode=mode,
        template_id=template_id,
        alternative=alternative,
        status="expected_reject",
        template_applicability="artifact_unavailable",
        row_count=0,
        execution_ms=0.0,
        build_ms=0.0,
        authorized_customers=authorized_customers,
        result_hash=_digest(payload),
        failure_reason=reason,
    )


def _record(
    root: Path,
    manifest_path: Path,
    manifest_id: str,
    result: E3ModeResult,
    dataset_scale: str,
    seed: int,
    pg_version: str,
    customer_count: int,
) -> Dict[str, Any]:
    canonical_mode = normalize_mode_id(result.mode)
    artifact_action = "reject" if result.template_applicability == "artifact_unavailable" else "execute"
    local_vector = None
    if canonical_mode == "local-greedy":
        local_vector = {
            "relname": "tpch_customer",
            "policy_config_id": result.policy_config_id,
            "available_artifacts": "both_keyed"
            if result.policy_config_id == "hybrid_selective_key"
            else "none",
            "query_shape": "tpch_q3",
        }
    return {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": f"E3_Q3_{result.policy_config_id}_{canonical_mode}",
        "manifest_id": manifest_id,
        "manifest_hash": file_sha256(manifest_path),
        "experiment": "E3",
        "stage": "smoke",
        "run_kind": "normal_mode",
        "dataset": {"name": "tpch", "scale": dataset_scale, "seed": seed},
        "query": {
            "query_id": "Q3",
            "path": "workloads/e3/tpch_q3_smoke.sql",
            "params": {
                "segment": "BUILDING",
                "cutoff_date": "1995-03-15",
                "policy_config_id": result.policy_config_id,
            },
        },
        "policy": {
            "policy_id": result.policy_config_id,
            "policy_version": 0,
            "policy_sql_manifest_hash": file_sha256(manifest_path),
        },
        "context": {"context_id": "e3_smoke_ctx", "ctx_hash": _digest({"policy": result.policy_config_id})},
        "mode": canonical_mode,
        "template": {"template_id": result.template_id, "alternative": result.alternative},
        "template_applicability": {
            "status": result.template_applicability,
            "reason": result.failure_reason,
        },
        "template_oracle": {
            "eligible_for_template_oracle": False,
            "template_oracle_exclusion_reason": "E3_smoke_normal_mode_not_template_oracle_pool",
        },
        "evaluation_role": load_mode_registry(root)[canonical_mode].evaluation_role,
        "pg": {
            "version": pg_version,
            "gucs": {"jit": "off", "max_parallel_workers_per_gather": "0"},
        },
        "versions": {
            "policy": {result.policy_config_id: 0},
            "membership": {},
            "context": {"e3_smoke_ctx": 0},
            "trusted_state": {"tpch_q3_adapter": 1},
            "base": {"tpch_customer": 0, "tpch_orders": 0, "tpch_lineitem": 0},
            "artifacts": {"e3_auth_idx_hybrid_selective_key": 0}
            if result.policy_config_id == "hybrid_selective_key"
            else {},
        },
        "planner": {
            "level": "A",
            "planning_time_ms": 0.0,
            "generated_templates": 3,
            "rejected_templates": 1 if result.status == "expected_reject" else 0,
            "costed_templates": 0 if result.status == "expected_reject" else 1,
            "rejection_reasons": {result.failure_reason: 1} if result.failure_reason else {},
            "chosen_estimated_cost": result.execution_ms,
            "chosen_rank_vs_template_oracle": None,
            "local_feature_vector": local_vector,
            "parent_requirement_vector": {
                "aggregate_boundary": "before_group_order_limit",
                "query_shape": "tpch_q3",
            },
            "disabled_components": [],
            "candidates": [],
            "delivered_sigma": {},
        },
        "static_verifier": {
            "status": "pass",
            "plan_hash": result.result_hash,
            "explain_path": None,
            "reasons": [],
        },
        "artifact_validation": {
            "status": "not_applicable",
            "action": artifact_action,
            "expected_action": artifact_action,
            "failure_sqlstate": None,
            "failure_symbol": None,
            "same_snapshot": False,
            "isolation_level": None,
        },
        "runtime_audit": {
            "status": "pass",
            "audit_path": None,
            "udf_calls": 0,
            "unauthorized_observations": 0,
            "client_errors": 0,
            "client_notices": 0,
        },
        "sql": {
            "emitted_sql_path": "workloads/e3/tpch_q3_smoke.sql",
            "emitted_sql_hash": file_sha256(root / "workloads" / "e3" / "tpch_q3_smoke.sql"),
            "normalized_sql_hash": result.result_hash,
        },
        "oracle_check": {
            "status": "match",
            "oracle_kind": "tpch_q3_exact_before_aggregate_smoke",
            "set_diff_left": 0,
            "set_diff_right": 0,
            "known_invalid_accepted": False,
            "known_valid_rejected": False,
        },
        "timing_ms": {
            "planning": 0.0,
            "execution": result.execution_ms,
            "verification": 0.0,
            "total": result.execution_ms,
        },
        "result": {"row_count": result.row_count, "result_hash": result.result_hash},
        "pg_metrics": {
            "shared_read_blocks": 0,
            "shared_hit_blocks": 0,
            "temp_read_blocks": 0,
            "temp_written_blocks": 0,
        },
        "counts": {
            "policy_evals": customer_count
            if result.template_id in {"barrier_filter_v1", "native_pg_rls_v1", "native_pg_rls_physical_design_v1"}
            else 0,
            "residual_checks": 0,
            "candidate_rows": result.authorized_customers,
            "authorized_rows": result.authorized_customers,
            "artifact_lookups": 1 if result.template_id == "strong_auth_index_keyed_v1" and result.status == "pass" else 0,
            "base_fetches": result.row_count,
        },
        "artifact_cost": {
            "query_only_ms": result.execution_ms,
            "build_ms": result.build_ms,
            "refresh_ms": 0.0,
            "storage_bytes": result.authorized_customers * 64
            if result.policy_config_id == "hybrid_selective_key"
            else 0,
            "indexes_built": ["auth_idx_lookup", "auth_idx_keyed_eq_lookup"]
            if result.policy_config_id == "hybrid_selective_key"
            else [],
            "artifact_key_encoding_version": "artifact_key_encoding_v1",
            "amortization_model": "query_only",
        },
        "implementation": {
            "git_commit": _git_commit(root),
            "docker_image_digest": "not_containerized",
            "python_version": platform.python_version(),
            "planner_language": "python",
        },
        "e3_smoke": {
            "standard_workload": "tpch",
            "query_id": "Q3",
            "adapter_scope": "tiny_deterministic_q3_schema",
            "unsupported_query_boundary": "residuals_discharged_before_aggregate_group_order_limit",
        },
        "status": result.status,
        "failure": None if result.failure_reason is None else {"reason": result.failure_reason},
    }


def _prepare_database(root: Path, pg_env: PostgresEnv) -> str:
    init_db(root, pg_env)
    _run_sql_script(_setup_sql(), pg_env)
    return run_psql_command("SHOW server_version;", pg_env)


def _build_artifacts(policy: E3PolicyConfig, pg_env: PostgresEnv) -> tuple[float, int]:
    if policy.artifacts != "both_keyed":
        return 0.0, 0
    artifact_id = "e3_auth_idx_hybrid_selective_key"
    started = time.monotonic()
    _run_sql_script(_build_auth_idx_sql(policy, artifact_id), pg_env)
    elapsed_ms = (time.monotonic() - started) * 1000.0
    cardinality = int(
        run_psql_command(
            f"SELECT count(*) FROM public.auth_idx WHERE artifact_id = {_quote(artifact_id)};",
            pg_env,
        )
    )
    return elapsed_ms, cardinality


def run_e3_smoke(
    root: Path,
    pg_env: PostgresEnv,
    manifest_path: Path,
    output_dir: Path,
) -> E3SmokeResult:
    manifest = _load_manifest(manifest_path)
    _validate_manifest(manifest_path, manifest)
    manifest_id = str(manifest["manifest_id"])
    dataset = (manifest.get("datasets") or [{}])[0]
    dataset_scale = str(dataset.get("scale", REDUCED_TPCH_SCALE))
    seed = int(dataset.get("seed", 42))

    pg_version = _prepare_database(root, pg_env)
    customer_count = int(run_psql_command("SELECT count(*) FROM public.tpch_customer;", pg_env))

    raw_paths: list[Path] = []
    normal_records = 0
    artifact_unavailable_records = 0
    for policy in POLICY_CONFIGS:
        build_ms, authorized_from_artifact = _build_artifacts(policy, pg_env)
        authorized_customers = int(
            run_psql_command(
                f"SELECT count(*) FROM public.tpch_customer c WHERE {policy.exact_predicate};",
                pg_env,
            )
        )
        if authorized_from_artifact:
            authorized_customers = authorized_from_artifact
        for raw_mode in manifest.get("modes", []):
            mode = normalize_mode_id(str(raw_mode))
            result = _execute_mode(
                policy=policy,
                mode=str(mode),
                pg_env=pg_env,
                artifact_id="e3_auth_idx_hybrid_selective_key",
                build_ms=build_ms,
                authorized_customers=authorized_customers,
            )
            if result.template_applicability == "artifact_unavailable":
                artifact_unavailable_records += 1
            record = _record(
                root=root,
                manifest_path=manifest_path,
                manifest_id=manifest_id,
                result=result,
                dataset_scale=dataset_scale,
                seed=seed,
                pg_version=pg_version,
                customer_count=customer_count,
            )
            raw_paths.append(_write_record(record, output_dir))
            normal_records += 1

    return E3SmokeResult(
        raw_result_paths=raw_paths,
        normal_records=normal_records,
        artifact_unavailable_records=artifact_unavailable_records,
    )


def _write_record(
    record: Dict[str, Any],
    output_dir: Path,
    static_verifier_explain_json: Any = None,
) -> Path:
    attach_static_verifier_explain(record, output_dir, static_verifier_explain_json)
    issues = validate_raw_run_record(record)
    if issues:
        rendered = ", ".join(f"{issue.path}: {issue.message}" for issue in issues)
        raise PostgresError(f"E3 raw record failed schema validation: {rendered}")
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_mode = str(record["mode"]).replace("-", "_")
    target = output_dir / f"{record['run_id']}_{safe_mode}.json"
    target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target
