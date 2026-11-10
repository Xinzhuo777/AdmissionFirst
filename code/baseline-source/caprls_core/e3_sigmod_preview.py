"""Minimal correctness-and-timing preview for the E3 SIGMOD experiment.

This is a direct experiment path. For each selected query/policy cell it
chooses AdmissionFirst from prospective
PostgreSQL costs, checks every measured mode against an independent full-row
reference, and only then records warm-cache timing repetitions.
"""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
    normalize_mode_id,
)

import csv
import hashlib
import json
import statistics
import time
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

from . import e3_main as e3
from .e3_smoke import _git_commit, _load_manifest
from .e8b_study import _validation_statements
from .manifest_validator import file_sha256
from .postgres_runner import (
    PostgresEnv,
    PostgresError,
    _validate_single_transaction_statement,
    run_psql_command,
)
from .repetitions import RepetitionProtocol, protocol_from_manifest


DEFAULT_PREVIEW_MODES = (
    "native-pg-rls",
    "barrier-only",
    "injection-only",
    "auth-index-enum-only",
    "strong-auth-index",
    "local-greedy",
    ADMISSION_FIRST_MODE,
)


@dataclass(frozen=True)
class ExecutionSpec:
    mode: str
    template_id: str
    alternative: str
    sql: str
    sql_source: str
    result_columns: tuple[tuple[str, str, bool], ...] = ()
    role: Optional[str] = None
    artifact_ids: tuple[str, ...] = ()
    expected_artifact_json: Optional[str] = None


@dataclass(frozen=True)
class PreparedMode:
    mode: str
    spec: Optional[ExecutionSpec]
    unavailable_reason: Optional[str] = None


@dataclass(frozen=True)
class PreparedCell:
    query_id: str
    workload: str
    policy_id: str
    dataset_scale: str
    seed: int
    pg_version: str
    protected_rows: int
    authorized_rows: int
    artifact_build_ms: float
    reference: ExecutionSpec
    modes: tuple[PreparedMode, ...]
    selected_template_id: str
    selected_plan_id: str
    selected_runner_digest: str
    prospective_total_cost: float
    selection_wall_ms: float


@dataclass(frozen=True)
class CanonicalResult:
    row_count: int
    canonical_rows: tuple[str, ...]
    result_digest: str


@dataclass(frozen=True)
class TimingSample:
    postgres_planning_ms: float
    execution_ms: float
    database_total_ms: float


@dataclass(frozen=True)
class ModeOutcome:
    prepared: PreparedMode
    status: str
    failure_reason: Optional[str]
    reference: CanonicalResult
    actual: Optional[CanonicalResult]
    actual_only_rows: int
    reference_only_rows: int
    samples: tuple[TimingSample, ...]


@dataclass(frozen=True)
class E3SigmodPreviewResult:
    run_paths: tuple[Path, ...]
    summary_csv_path: Path
    cell_count: int
    passed_modes: int
    correctness_failed_modes: int
    execution_failed_modes: int
    failed_cells: int
    unavailable_modes: int


@dataclass(frozen=True)
class _CellFailure:
    index: int
    query_id: str
    workload: str
    policy_id: str
    status: str
    reason: str
    cell: Optional[PreparedCell] = None


_SUMMARY_FIELDS = (
    "manifest_id",
    "manifest_sha256",
    "git_commit",
    "query_id",
    "workload",
    "dataset_scale",
    "seed",
    "policy_id",
    "mode",
    "template_id",
    "alternative",
    "status",
    "failure_reason",
    "row_count",
    "reference_row_count",
    "result_digest",
    "reference_digest",
    "actual_only_rows",
    "reference_only_rows",
    "ordered_sequence_match",
    "measurement_protocol",
    "warmup_repetitions",
    "measured_repetitions",
    "median_end_to_end_ms_including_validation_and_client",
    "native_median_end_to_end_ms_including_validation_and_client",
    "end_to_end_speedup_vs_native_including_validation_and_client",
    "median_postgres_query_execution_ms",
    "p10_postgres_query_execution_ms",
    "p90_postgres_query_execution_ms",
    "median_postgres_planning_ms",
    "native_median_postgres_query_execution_ms",
    "postgres_query_execution_speedup_vs_native",
    "admission_first_selected_template",
    "prospective_total_cost",
    "selection_wall_ms",
    "selected_runner_digest",
    "sql_digest",
    "artifact_build_ms",
    "protected_rows",
    "authorized_rows",
)


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_row(value: Any) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def canonical_result_from_row_texts(rows: Sequence[str]) -> CanonicalResult:
    canonical_rows = tuple(rows)
    if any(not isinstance(row, str) for row in canonical_rows):
        raise ValueError("canonical PostgreSQL rows must be text")
    # The digest identifies the authoritative multiset, not incidental tie
    # ordering. Length prefixes keep the encoding unambiguous while preserving
    # every byte of PostgreSQL's to_jsonb(row)::text representation.
    digest_input = "".join(
        f"{len(encoded):016x}:" + encoded.decode("utf-8")
        for encoded in (
            row.encode("utf-8")
            for row in sorted(canonical_rows)
        )
    )
    return CanonicalResult(
        row_count=len(canonical_rows),
        canonical_rows=canonical_rows,
        result_digest=_sha256_text(digest_input),
    )


def canonical_result_from_rows(rows: Sequence[Any]) -> CanonicalResult:
    """Build an in-memory test result using the live row-text semantics."""

    return canonical_result_from_row_texts(
        tuple(_canonical_row(row) for row in rows)
    )


def _bag_difference(
    actual: CanonicalResult,
    reference: CanonicalResult,
) -> tuple[int, int]:
    actual_counts = Counter(actual.canonical_rows)
    reference_counts = Counter(reference.canonical_rows)
    return (
        sum((actual_counts - reference_counts).values()),
        sum((reference_counts - actual_counts).values()),
    )


_UNSUPPORTED_FLOAT_RESULT_TYPES = frozenset(
    {"real", "float4", "double precision", "float8"}
)


def _validate_result_columns(
    result_columns: Sequence[tuple[str, str, bool]],
) -> tuple[tuple[str, str, bool], ...]:
    if not result_columns:
        raise PostgresError("E3 preview result column contract is missing")
    validated: list[tuple[str, str, bool]] = []
    seen_names: set[str] = set()
    for column in result_columns:
        if not isinstance(column, tuple) or len(column) != 3:
            raise PostgresError("E3 preview result column contract is malformed")
        name, type_name, nullable = column
        if (
            not isinstance(name, str)
            or not name
            or name in seen_names
            or not isinstance(type_name, str)
            or not type_name.strip()
            or not isinstance(nullable, bool)
        ):
            raise PostgresError("E3 preview result column contract is malformed")
        normalized_type = " ".join(type_name.lower().split())
        if (
            normalized_type in _UNSUPPORTED_FLOAT_RESULT_TYPES
            or normalized_type.startswith("float(")
        ):
            raise PostgresError(
                "E3 preview does not accept float4/float8 result columns "
                "without a declared comparison policy"
            )
        seen_names.add(name)
        validated.append((name, normalized_type, nullable))
    return tuple(validated)


def _result_columns_for(
    query: e3.E3QuerySpec,
) -> tuple[tuple[str, str, bool], ...]:
    result_columns = e3.E3_RESULT_COLUMN_CONTRACTS.get(query.query_id)
    if result_columns is None:
        raise PostgresError(
            f"E3 preview result column contract is missing for {query.query_id}"
        )
    return _validate_result_columns(result_columns)


def _single_query(sql: str) -> str:
    statement = _validate_single_transaction_statement(sql)
    head = statement.split(None, 1)[0].upper()
    if head not in {"SELECT", "WITH"}:
        raise PostgresError("E3 preview execution SQL must be SELECT- or WITH-headed")
    return statement


def _transaction_script(spec: ExecutionSpec, body: str) -> str:
    validation = ""
    if spec.artifact_ids:
        if not spec.expected_artifact_json:
            raise PostgresError("artifact-backed E3 preview SQL lacks expected dependencies")
        validation = _validation_statements(
            spec.artifact_ids,
            spec.expected_artifact_json,
        )
    role = ""
    if spec.role is not None:
        if spec.role != e3.E3_RLS_ROLE:
            raise PostgresError("E3 preview received an unsupported execution role")
        role = f"SET LOCAL ROLE {spec.role};"
    return f"""
BEGIN ISOLATION LEVEL REPEATABLE READ;
SET LOCAL search_path TO pg_catalog, public;
SET LOCAL jit = off;
SET LOCAL max_parallel_workers_per_gather = 0;
SET LOCAL plan_cache_mode = force_custom_plan;
{validation}
SET LOCAL row_security = on;
{role}
{body};
COMMIT;
"""


def _canonicalize_live(spec: ExecutionSpec, pg_env: PostgresEnv) -> CanonicalResult:
    _validate_result_columns(spec.result_columns)
    statement = _single_query(spec.sql)
    body = f"""
WITH caprls_preview_source AS MATERIALIZED (
{statement}
),
caprls_preview_numbered AS MATERIALIZED (
  SELECT
    pg_catalog.row_number() OVER () AS row_ordinal,
    pg_catalog.to_jsonb(caprls_preview_source)::text AS row_json_text
  FROM caprls_preview_source
)
SELECT pg_catalog.jsonb_build_object(
  'row_count', pg_catalog.count(*),
  'rows', COALESCE(
    pg_catalog.jsonb_agg(row_json_text ORDER BY row_ordinal),
    '[]'::pg_catalog.jsonb
  )
)::text
FROM caprls_preview_numbered
""".strip()
    raw = run_psql_command(_transaction_script(spec, body), pg_env)
    payload = e3._e3_last_json_object(raw, label="E3 preview full-row query")
    rows = payload.get("rows")
    if not isinstance(rows, list) or any(not isinstance(row, str) for row in rows):
        raise PostgresError("E3 preview full-row query returned malformed rows")
    result = canonical_result_from_row_texts(rows)
    if payload.get("row_count") != result.row_count:
        raise PostgresError("E3 preview full-row query returned an inconsistent count")
    return result


def _measure_live(spec: ExecutionSpec, pg_env: PostgresEnv) -> TimingSample:
    statement = _single_query(spec.sql)
    body = "EXPLAIN (ANALYZE, FORMAT JSON, TIMING OFF, SUMMARY ON) " + statement
    started = time.perf_counter()
    raw = run_psql_command(_transaction_script(spec, body), pg_env)
    total_ms = (time.perf_counter() - started) * 1000.0
    try:
        parsed = e3._parse_explain_json(raw)
        if len(parsed) != 1 or not isinstance(parsed[0], Mapping):
            raise ValueError("expected one EXPLAIN document")
        planning_ms = float(parsed[0]["Planning Time"])
        execution_ms = float(parsed[0]["Execution Time"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PostgresError("E3 preview returned malformed EXPLAIN ANALYZE JSON") from exc
    return TimingSample(
        postgres_planning_ms=planning_ms,
        execution_ms=execution_ms,
        database_total_ms=total_ms,
    )


def _artifact_validation_for(
    query: e3.E3QuerySpec,
    policy: e3.E3PolicyConfig,
    source: str,
) -> tuple[tuple[str, ...], Optional[str]]:
    if not e3._artifact_source_requires_validation(source):
        return (), None
    return (
        (e3._artifact_id(query, policy),),
        e3._expected_artifact_json(query, policy),
    )


def _fixed_mode(
    query: e3.E3QuerySpec,
    policy: e3.E3PolicyConfig,
    mode: str,
) -> PreparedMode:
    template_id, alternative = e3._template_for_mode(policy, mode)
    unavailable = e3._artifact_unavailable_reason(policy, template_id, mode)
    if mode == "injection-only" and not policy.injection_safe:
        unavailable = (
            f"mode {mode} requires an injection-safe exact policy predicate"
        )
    if unavailable is not None:
        return PreparedMode(mode=mode, spec=None, unavailable_reason=unavailable)

    source = e3._source_for_template(template_id)
    predicate = e3._policy_predicate(query, policy)
    cte, from_rel, extra = e3._source_sql(query, policy, source, predicate)
    sql = e3._e3_semantic_result_sql(
        query,
        cte=cte,
        from_rel=from_rel,
        extra=extra,
    )
    artifact_ids, expected_json = _artifact_validation_for(query, policy, source)
    return PreparedMode(
        mode=mode,
        spec=ExecutionSpec(
            mode=mode,
            template_id=template_id,
            alternative=alternative,
            sql=sql,
            sql_source=source,
            result_columns=_result_columns_for(query),
            role=e3.E3_RLS_ROLE if source == "rls" else None,
            artifact_ids=artifact_ids,
            expected_artifact_json=expected_json,
        ),
    )


def _prepare_cell_live(
    *,
    query: e3.E3QuerySpec,
    policy: e3.E3PolicyConfig,
    modes: Sequence[str],
    pg_env: PostgresEnv,
    ranker: e3.E3Ranker,
    registry: Any,
    dataset_scale: str,
    seed: int,
    pg_version: str,
    access_root_materialized: bool = True,
) -> PreparedCell:
    protected_rows = e3._protected_count(query, pg_env)
    query_local_rows = int(
        run_psql_command(
            f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} "
            f"WHERE {e3._query_local_predicate(query)};",
            pg_env,
        )
    )
    predicate = e3._policy_predicate(query, policy)
    build_ms, artifact_rows, keyed_artifact_rows = e3._build_artifact(
        query,
        policy,
        predicate,
        pg_env,
    )
    e3._configure_native_rls(query, policy, pg_env)
    receipt = e3._collect_e3_planning_catalog_receipt(query, policy, pg_env)
    authorized_rows = int(
        run_psql_command(
            f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} "
            f"WHERE {predicate};",
            pg_env,
        )
    )
    if artifact_rows:
        authorized_rows = artifact_rows

    selection_started = time.perf_counter()
    plan_result, query_plan, _problem = e3._plan_e3_admission_first(
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
        planning_catalog_receipt=receipt,
        access_root_materialized=access_root_materialized,
    )
    selection_wall_ms = (time.perf_counter() - selection_started) * 1000.0

    selected_template = e3._require_e3_selected_root_template(query_plan)
    bound = query_plan.get("production_bound_runner")
    chosen_cost = query_plan.get("production_chosen_cost")
    if not isinstance(bound, Mapping) or not isinstance(chosen_cost, Mapping):
        raise PostgresError("E3 preview selection lacks its bound runner or prospective cost")
    if bound.get("template_id") != selected_template:
        raise PostgresError("E3 preview selected template and bound runner differ")
    runner_sql = bound.get("runner_sql")
    if not isinstance(runner_sql, str) or not runner_sql.strip():
        raise PostgresError("E3 preview selected runner SQL is missing")
    selected_plan_id = bound.get("plan_id")
    selected_runner_digest = bound.get("runner_sql_digest")
    if not isinstance(selected_plan_id, str) or not isinstance(selected_runner_digest, str):
        raise PostgresError("E3 preview selected runner identity is malformed")
    if selected_runner_digest != e3._canonical_sha256(
        {"exact_runner_sql": runner_sql}
    ):
        raise PostgresError("E3 preview selected runner SQL digest does not match")
    try:
        prospective_total_cost = float(chosen_cost["prospective_total_cost"])
    except (KeyError, TypeError, ValueError) as exc:
        raise PostgresError("E3 preview prospective selected cost is malformed") from exc
    if plan_result.chosen_template is None:
        raise PostgresError("E3 preview planner did not choose a template")

    selected_source = e3._source_for_template(selected_template)
    artifact_ids, expected_json = _artifact_validation_for(
        query,
        policy,
        selected_source,
    )
    contract_spec = ExecutionSpec(
        mode=ADMISSION_FIRST_MODE,
        template_id=selected_template,
        alternative=plan_result.chosen_template.alternative,
        sql=runner_sql,
        sql_source=selected_source,
        result_columns=_result_columns_for(query),
        role=e3.E3_RLS_ROLE if selected_source == "rls" else None,
        artifact_ids=artifact_ids,
        expected_artifact_json=expected_json,
    )

    prepared_modes = []
    for mode in modes:
        if mode == ADMISSION_FIRST_MODE:
            prepared_modes.append(PreparedMode(mode=mode, spec=contract_spec))
        else:
            prepared_modes.append(_fixed_mode(query, policy, mode))

    return PreparedCell(
        query_id=query.query_id,
        workload=query.workload,
        policy_id=policy.config_id,
        dataset_scale=dataset_scale,
        seed=seed,
        pg_version=pg_version,
        protected_rows=protected_rows,
        authorized_rows=authorized_rows,
        artifact_build_ms=build_ms,
        reference=ExecutionSpec(
            mode="independent-reference",
            template_id="direct_independent_reference_v1",
            alternative="IndependentReference",
            sql=e3._e3_independent_result_reference_sql(query, policy),
            sql_source="direct-independent-reference",
            result_columns=_result_columns_for(query),
        ),
        modes=tuple(prepared_modes),
        selected_template_id=selected_template,
        selected_plan_id=selected_plan_id,
        selected_runner_digest=selected_runner_digest,
        prospective_total_cost=prospective_total_cost,
        selection_wall_ms=selection_wall_ms,
    )


def _percentile(values: Sequence[float], percentile: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(float(item) for item in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _median(values: Iterable[float]) -> Optional[float]:
    materialized = [float(item) for item in values]
    return statistics.median(materialized) if materialized else None


def _float_field(value: Optional[float]) -> str:
    return "" if value is None else f"{value:.6f}"


def _safe_name(value: str) -> str:
    rendered = "".join(char if char.isalnum() or char in "-_" else "_" for char in value)
    return rendered or "unnamed"


def _base_record(
    *,
    manifest_id: str,
    manifest_digest: str,
    git_commit: str,
    cell: PreparedCell,
    outcome: ModeOutcome,
    correctness_only: bool,
) -> dict[str, Any]:
    spec = outcome.prepared.spec
    return {
        "schema": "e3_sigmod_preview_run_v2",
        "experiment": "E3",
        "manifest_id": manifest_id,
        "manifest_sha256": manifest_digest,
        "git_commit": git_commit,
        "query_id": cell.query_id,
        "workload": cell.workload,
        "dataset_scale": cell.dataset_scale,
        "seed": cell.seed,
        "policy_id": cell.policy_id,
        "postgres_version": cell.pg_version,
        "mode": outcome.prepared.mode,
        "template_id": None if spec is None else spec.template_id,
        "alternative": None if spec is None else spec.alternative,
        "status": outcome.status,
        "failure_reason": outcome.failure_reason,
        "measurement_protocol": (
            "not_applicable/correctness_only"
            if correctness_only
            else "warm_cache_repetitions"
        ),
        "correctness": {
            "method": "full_row_jsonb_multiset_equality",
            "canonical_row_representation": "postgresql_to_jsonb_row_text",
            "bag_difference_role": "authoritative",
            "order_role": "diagnostic_only",
            "reference": "independent_direct_policy_sql",
            "reference_row_count": outcome.reference.row_count,
            "reference_digest": outcome.reference.result_digest,
            "row_count": None if outcome.actual is None else outcome.actual.row_count,
            "result_digest": None if outcome.actual is None else outcome.actual.result_digest,
            "actual_only_rows": outcome.actual_only_rows,
            "reference_only_rows": outcome.reference_only_rows,
            "ordered_sequence_match": bool(
                outcome.actual is not None
                and outcome.actual.canonical_rows
                == outcome.reference.canonical_rows
            ),
        },
        "admission_first_selection": {
            "method": "prospective_explain_and_catalog_cost_only",
            "measured_runtime_used_for_selection": False,
            "selected_template_id": cell.selected_template_id,
            "selected_plan_id": cell.selected_plan_id,
            "selected_runner_digest": cell.selected_runner_digest,
            "prospective_total_cost": cell.prospective_total_cost,
            "selection_wall_ms": cell.selection_wall_ms,
        },
        "sql": {
            "source": None if spec is None else spec.sql_source,
            "digest": None if spec is None else _sha256_text(_single_query(spec.sql)),
            "text": None if spec is None else _single_query(spec.sql),
        },
        "artifact": {
            "build_ms": cell.artifact_build_ms,
            "validated_in_same_transaction": bool(spec and spec.artifact_ids),
        },
        "protected_rows": cell.protected_rows,
        "authorized_rows": cell.authorized_rows,
    }


def _summary_row(
    *,
    manifest_id: str,
    cell: PreparedCell,
    outcome: ModeOutcome,
    protocol: RepetitionProtocol,
    correctness_only: bool,
    manifest_digest: str,
    git_commit: str,
    native_execution_median_ms: Optional[float],
    native_end_to_end_median_ms: Optional[float],
) -> dict[str, Any]:
    spec = outcome.prepared.spec
    execution_values = [sample.execution_ms for sample in outcome.samples]
    median_execution = _median(execution_values)
    speedup = None
    if (
        native_execution_median_ms is not None
        and median_execution is not None
        and median_execution > 0
    ):
        speedup = native_execution_median_ms / median_execution
    median_total = _median(
        sample.database_total_ms for sample in outcome.samples
    )
    total_speedup = None
    if (
        native_end_to_end_median_ms is not None
        and median_total is not None
        and median_total > 0
    ):
        total_speedup = native_end_to_end_median_ms / median_total
    return {
        "manifest_id": manifest_id,
        "manifest_sha256": manifest_digest,
        "git_commit": git_commit,
        "query_id": cell.query_id,
        "workload": cell.workload,
        "dataset_scale": cell.dataset_scale,
        "seed": cell.seed,
        "policy_id": cell.policy_id,
        "mode": outcome.prepared.mode,
        "template_id": "" if spec is None else spec.template_id,
        "alternative": "" if spec is None else spec.alternative,
        "status": outcome.status,
        "failure_reason": outcome.failure_reason or "",
        "row_count": "" if outcome.actual is None else outcome.actual.row_count,
        "reference_row_count": outcome.reference.row_count,
        "result_digest": "" if outcome.actual is None else outcome.actual.result_digest,
        "reference_digest": outcome.reference.result_digest,
        "actual_only_rows": outcome.actual_only_rows,
        "reference_only_rows": outcome.reference_only_rows,
        "ordered_sequence_match": (
            ""
            if outcome.actual is None
            else str(
                outcome.actual.canonical_rows == outcome.reference.canonical_rows
            ).lower()
        ),
        "measurement_protocol": (
            "not_applicable/correctness_only"
            if correctness_only
            else "warm_cache_repetitions"
        ),
        "warmup_repetitions": protocol.warmup if outcome.status == "pass" else 0,
        "measured_repetitions": len(outcome.samples),
        "median_end_to_end_ms_including_validation_and_client": _float_field(
            median_total
        ),
        "native_median_end_to_end_ms_including_validation_and_client": (
            _float_field(native_end_to_end_median_ms)
        ),
        "end_to_end_speedup_vs_native_including_validation_and_client": (
            _float_field(total_speedup)
        ),
        "median_postgres_query_execution_ms": _float_field(median_execution),
        "p10_postgres_query_execution_ms": _float_field(
            _percentile(execution_values, 0.10)
        ),
        "p90_postgres_query_execution_ms": _float_field(
            _percentile(execution_values, 0.90)
        ),
        "median_postgres_planning_ms": _float_field(
            _median(sample.postgres_planning_ms for sample in outcome.samples)
        ),
        "native_median_postgres_query_execution_ms": _float_field(
            native_execution_median_ms
        ),
        "postgres_query_execution_speedup_vs_native": _float_field(speedup),
        "admission_first_selected_template": cell.selected_template_id,
        "prospective_total_cost": _float_field(cell.prospective_total_cost),
        "selection_wall_ms": _float_field(cell.selection_wall_ms),
        "selected_runner_digest": cell.selected_runner_digest,
        "sql_digest": "" if spec is None else _sha256_text(_single_query(spec.sql)),
        "artifact_build_ms": _float_field(cell.artifact_build_ms),
        "protected_rows": cell.protected_rows,
        "authorized_rows": cell.authorized_rows,
    }


def _write_json(path: Path, payload: Mapping[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _require_empty_output_dir(output_dir: Path) -> None:
    if output_dir.exists() and (
        not output_dir.is_dir() or next(output_dir.iterdir(), None) is not None
    ):
        raise ValueError(
            f"E3 preview output directory must be new or empty: {output_dir}"
        )


def _case_labels(case: Any) -> tuple[str, str, str]:
    if isinstance(case, tuple) and len(case) == 2:
        query, policy = case
        return (
            str(getattr(query, "query_id", "")),
            str(getattr(query, "workload", "")),
            str(getattr(policy, "config_id", "")),
        )
    return str(case), "", ""


def _cell_failure_outputs(
    *,
    failure: _CellFailure,
    manifest_id: str,
    manifest_digest: str,
    git_commit: str,
    runs_dir: Path,
    correctness_only: bool,
) -> tuple[dict[str, Any], Path]:
    cell = failure.cell
    row = {field: "" for field in _SUMMARY_FIELDS}
    row.update(
        {
            "manifest_id": manifest_id,
            "manifest_sha256": manifest_digest,
            "git_commit": git_commit,
            "query_id": failure.query_id,
            "workload": failure.workload,
            "policy_id": failure.policy_id,
            "mode": "__cell__",
            "status": failure.status,
            "failure_reason": failure.reason,
            "measurement_protocol": (
                "not_applicable/correctness_only"
                if correctness_only
                else "warm_cache_repetitions"
            ),
        }
    )
    if cell is not None:
        row.update(
            {
                "dataset_scale": cell.dataset_scale,
                "seed": cell.seed,
                "admission_first_selected_template": cell.selected_template_id,
                "prospective_total_cost": _float_field(
                    cell.prospective_total_cost
                ),
                "selection_wall_ms": _float_field(cell.selection_wall_ms),
                "selected_runner_digest": cell.selected_runner_digest,
                "artifact_build_ms": _float_field(cell.artifact_build_ms),
                "protected_rows": cell.protected_rows,
                "authorized_rows": cell.authorized_rows,
            }
        )
    stem = f"cell{failure.index:03d}_{_safe_name(failure.query_id)}_{_safe_name(failure.policy_id)}"
    record = {
        "schema": "e3_sigmod_preview_cell_failure_v1",
        "experiment": "E3",
        "manifest_id": manifest_id,
        "manifest_sha256": manifest_digest,
        "git_commit": git_commit,
        "run_id": f"E3_preview_{stem}_{failure.status}",
        "query_id": failure.query_id,
        "workload": failure.workload,
        "policy_id": failure.policy_id,
        "status": failure.status,
        "failure_reason": failure.reason,
        "measurement_protocol": (
            "not_applicable/correctness_only"
            if correctness_only
            else "warm_cache_repetitions"
        ),
        "measurement": None,
    }
    path = runs_dir / f"e3_preview_{stem}_{failure.status}.json"
    return row, _write_json(path, record)


def _execute_preview_cells(
    *,
    cases: Sequence[Any],
    prepare_cell: Callable[[Any], PreparedCell],
    prepare_measurement: Optional[Callable[[PreparedCell], None]] = None,
    canonicalize: Callable[[ExecutionSpec], CanonicalResult],
    measure: Callable[[ExecutionSpec], TimingSample],
    protocol: RepetitionProtocol,
    output_dir: Path,
    manifest_id: str,
    manifest_digest: str,
    git_commit: str,
    correctness_only: bool = False,
) -> E3SigmodPreviewResult:
    if correctness_only:
        if protocol.warmup != 0 or protocol.measured != 0:
            raise ValueError(
                "E3 correctness-only preview requires warmup = measured = 0"
            )
    elif protocol.warmup < 0 or protocol.measured <= 0:
        raise ValueError("E3 preview requires warmup >= 0 and measured > 0")

    _require_empty_output_dir(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    runs_dir = output_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    summary_rows: list[dict[str, Any]] = []
    run_paths: list[Path] = []
    passed_modes = 0
    correctness_failed_modes = 0
    execution_failed_modes = 0
    unavailable_modes = 0
    failures: list[_CellFailure] = []
    correctness_campaign: list[tuple[PreparedCell, list[ModeOutcome]]] = []

    # Complete prospective selection and correctness for every cell before
    # the first warmup or timed execution is allowed to run.
    for index, case in enumerate(cases, start=1):
        query_id, workload, policy_id = _case_labels(case)
        # The live implementation performs prospective selection here, before
        # either reference/actual rows or measured runtimes are available.
        try:
            cell = prepare_cell(case)
        except (PostgresError, ValueError) as exc:
            failures.append(
                _CellFailure(
                    index,
                    query_id,
                    workload,
                    policy_id,
                    "preparation_error",
                    str(exc),
                )
            )
            continue
        try:
            reference = canonicalize(cell.reference)
        except (PostgresError, ValueError) as exc:
            failures.append(
                _CellFailure(
                    index,
                    cell.query_id,
                    cell.workload,
                    cell.policy_id,
                    "reference_error",
                    str(exc),
                    cell,
                )
            )
            continue
        outcomes: list[ModeOutcome] = []
        for prepared in cell.modes:
            if prepared.spec is None:
                unavailable_modes += 1
                outcomes.append(
                    ModeOutcome(
                        prepared=prepared,
                        status="artifact_unavailable",
                        failure_reason=prepared.unavailable_reason,
                        reference=reference,
                        actual=None,
                        actual_only_rows=0,
                        reference_only_rows=0,
                        samples=(),
                    )
                )
                continue

            try:
                actual = canonicalize(prepared.spec)
            except (PostgresError, ValueError) as exc:
                outcomes.append(
                    ModeOutcome(
                        prepared=prepared,
                        status="execution_error",
                        failure_reason=str(exc),
                        reference=reference,
                        actual=None,
                        actual_only_rows=0,
                        reference_only_rows=0,
                        samples=(),
                    )
                )
                continue
            actual_only, reference_only = _bag_difference(actual, reference)
            if actual_only or reference_only:
                outcomes.append(
                    ModeOutcome(
                        prepared=prepared,
                        status="correctness_fail",
                        failure_reason=(
                            "full-row multiset differs from independent reference"
                        ),
                        reference=reference,
                        actual=actual,
                        actual_only_rows=actual_only,
                        reference_only_rows=reference_only,
                        samples=(),
                    )
                )
                continue

            outcomes.append(
                ModeOutcome(
                    prepared=prepared,
                    status="pass",
                    failure_reason=None,
                    reference=reference,
                    actual=actual,
                    actual_only_rows=0,
                    reference_only_rows=0,
                    samples=(),
                )
            )

        correctness_campaign.append((cell, outcomes))

    if correctness_only:
        timed_campaign = correctness_campaign
    else:
        timed_campaign: list[tuple[PreparedCell, list[ModeOutcome]]] = []
        for cell, outcomes in correctness_campaign:
            if prepare_measurement is not None:
                prepare_measurement(cell)
            eligible = [
                index
                for index, outcome in enumerate(outcomes)
                if outcome.status == "pass" and outcome.prepared.spec is not None
            ]
            samples_by_index: dict[int, list[TimingSample]] = {
                index: [] for index in eligible
            }
            timing_errors: dict[int, str] = {}
            round_index = 0

            def run_round(*, collect: bool) -> None:
                nonlocal round_index
                rotation = round_index % len(eligible) if eligible else 0
                order = eligible[rotation:] + eligible[:rotation]
                for index in order:
                    if index in timing_errors:
                        continue
                    spec = outcomes[index].prepared.spec
                    assert spec is not None
                    try:
                        sample = measure(spec)
                    except (PostgresError, ValueError) as exc:
                        timing_errors[index] = str(exc)
                    else:
                        if collect:
                            samples_by_index[index].append(sample)
                round_index += 1

            for _ in range(protocol.warmup):
                run_round(collect=False)
            for _ in range(protocol.measured):
                run_round(collect=True)

            timed_outcomes = []
            for index, outcome in enumerate(outcomes):
                if index in timing_errors:
                    timed_outcomes.append(
                        replace(
                            outcome,
                            status="timing_error",
                            failure_reason=timing_errors[index],
                            samples=(),
                        )
                    )
                elif index in samples_by_index:
                    timed_outcomes.append(
                        replace(outcome, samples=tuple(samples_by_index[index]))
                    )
                else:
                    timed_outcomes.append(outcome)
            timed_campaign.append((cell, timed_outcomes))

    for cell, outcomes in timed_campaign:
        passed_modes += sum(outcome.status == "pass" for outcome in outcomes)
        correctness_failed_modes += sum(
            outcome.status == "correctness_fail" for outcome in outcomes
        )
        execution_failed_modes += sum(
            outcome.status in {"execution_error", "timing_error"}
            for outcome in outcomes
        )

        native_execution_median_ms = next(
            (
                _median(sample.execution_ms for sample in outcome.samples)
                for outcome in outcomes
                if outcome.prepared.mode == "native-pg-rls"
                and outcome.status == "pass"
            ),
            None,
        )
        native_end_to_end_median_ms = next(
            (
                _median(sample.database_total_ms for sample in outcome.samples)
                for outcome in outcomes
                if outcome.prepared.mode == "native-pg-rls"
                and outcome.status == "pass"
            ),
            None,
        )
        for outcome in outcomes:
            summary_rows.append(
                _summary_row(
                    manifest_id=manifest_id,
                    cell=cell,
                    outcome=outcome,
                    protocol=protocol,
                    correctness_only=correctness_only,
                    manifest_digest=manifest_digest,
                    git_commit=git_commit,
                    native_execution_median_ms=native_execution_median_ms,
                    native_end_to_end_median_ms=native_end_to_end_median_ms,
                )
            )
            base = _base_record(
                manifest_id=manifest_id,
                manifest_digest=manifest_digest,
                git_commit=git_commit,
                cell=cell,
                outcome=outcome,
                correctness_only=correctness_only,
            )
            stem = "_".join(
                _safe_name(item)
                for item in (cell.query_id, cell.policy_id, outcome.prepared.mode)
            )
            if outcome.status == "pass" and not correctness_only:
                for iteration, sample in enumerate(outcome.samples, start=1):
                    record = dict(base)
                    record["run_id"] = f"E3_preview_{stem}_rep{iteration:02d}"
                    record["repetition"] = {
                        "phase": "measured",
                        "iteration": iteration,
                        "warmup_repetitions": protocol.warmup,
                        "measured_repetitions": protocol.measured,
                    }
                    record["measurement"] = {
                        "end_to_end_ms_including_validation_and_client": (
                            sample.database_total_ms
                        ),
                        "postgres_planning_ms": sample.postgres_planning_ms,
                        "postgres_query_execution_ms": sample.execution_ms,
                        "artifact_validation_required": bool(
                            outcome.prepared.spec
                            and outcome.prepared.spec.artifact_ids
                        ),
                    }
                    path = runs_dir / f"e3_preview_{stem}_rep{iteration:02d}.json"
                    run_paths.append(_write_json(path, record))
            else:
                record = dict(base)
                record["run_id"] = f"E3_preview_{stem}_outcome"
                record["repetition"] = None
                record["measurement"] = None
                path = runs_dir / f"e3_preview_{stem}_outcome.json"
                run_paths.append(_write_json(path, record))

    for failure in failures:
        row, path = _cell_failure_outputs(
            failure=failure,
            manifest_id=manifest_id,
            manifest_digest=manifest_digest,
            git_commit=git_commit,
            runs_dir=runs_dir,
            correctness_only=correctness_only,
        )
        summary_rows.append(row)
        run_paths.append(path)

    summary_path = output_dir / "summary.csv"
    with summary_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=list(_SUMMARY_FIELDS),
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    return E3SigmodPreviewResult(
        run_paths=tuple(run_paths),
        summary_csv_path=summary_path,
        cell_count=len(cases),
        passed_modes=passed_modes,
        correctness_failed_modes=correctness_failed_modes,
        execution_failed_modes=execution_failed_modes,
        failed_cells=len(failures),
        unavailable_modes=unavailable_modes,
    )


def _select_items(
    items: Sequence[Any],
    requested: Optional[Sequence[str]],
    *,
    key: Callable[[Any], str],
    label: str,
) -> list[Any]:
    if requested is None:
        return list(items)
    names = tuple(str(item) for item in requested)
    if len(names) != len(set(names)):
        raise ValueError(f"E3 preview repeats a {label}")
    by_name = {key(item): item for item in items}
    unknown = [name for name in names if name not in by_name]
    if unknown:
        raise ValueError(f"E3 preview declares unknown {label}(s): {', '.join(unknown)}")
    return [by_name[name] for name in names]


def run_e3_sigmod_preview(
    *,
    root: Path,
    pg_env: PostgresEnv,
    manifest_path: Path,
    output_dir: Path,
    query_ids: Optional[Sequence[str]] = None,
    policy_ids: Optional[Sequence[str]] = None,
    modes: Optional[Sequence[str]] = None,
    warmup: Optional[int] = None,
    measured: Optional[int] = None,
    correctness_only: bool = False,
) -> E3SigmodPreviewResult:
    """Run a small, honest E3 correctness and performance preview."""

    _require_empty_output_dir(output_dir)
    manifest = _load_manifest(manifest_path)
    e3._validate_manifest(manifest_path, manifest)
    e3.require_e3_manifest_data(root, manifest_path, manifest)
    selected_queries = _select_items(
        e3._queries_for_manifest(manifest_path, manifest),
        query_ids,
        key=lambda item: item.query_id,
        label="query_id",
    )
    selected_policies = _select_items(
        e3._policies_for_manifest(manifest_path, manifest),
        policy_ids,
        key=lambda item: item.config_id,
        label="policy_id",
    )
    if not selected_queries or not selected_policies:
        raise ValueError("E3 preview requires at least one query and one policy")
    declared_modes = tuple(
        normalize_mode_id(str(item)) for item in manifest.get("modes", ())
    )
    selected_modes = tuple(
        _select_items(
            declared_modes,
            DEFAULT_PREVIEW_MODES if modes is None else modes,
            key=str,
            label="mode",
        )
    )
    if not selected_modes:
        raise ValueError("E3 preview requires at least one mode")
    scale_check = manifest.get("scale_check") or {}
    if not isinstance(scale_check, Mapping):
        raise ValueError("E3 preview scale_check must be a mapping")
    wrapper_strategy = str(
        scale_check.get("bound_runner_wrapper", "materialized")
    )
    if wrapper_strategy not in {
        "materialized",
        "not_materialized_single_reference",
    }:
        raise ValueError(
            "E3 preview bound_runner_wrapper must be materialized or "
            "not_materialized_single_reference"
        )
    access_root_materialized = wrapper_strategy == "materialized"

    manifest_protocol = protocol_from_manifest(manifest)
    if correctness_only:
        requested_warmup = 0 if warmup is None else int(warmup)
        requested_measured = 0 if measured is None else int(measured)
        protocol = RepetitionProtocol(
            warmup=requested_warmup,
            measured=requested_measured,
        )
        if protocol.warmup != 0 or protocol.measured != 0:
            raise ValueError(
                "E3 correctness-only preview requires warmup = measured = 0"
            )
    else:
        protocol = RepetitionProtocol(
            warmup=manifest_protocol.warmup if warmup is None else int(warmup),
            measured=manifest_protocol.measured if measured is None else int(measured),
        )
        if protocol.warmup < 0 or protocol.measured <= 0:
            raise ValueError("E3 preview requires warmup >= 0 and measured > 0")

    scale_by_dataset = {
        str(item.get("name")): str(item.get("scale", "reduced"))
        for item in manifest.get("datasets", ())
        if isinstance(item, Mapping)
    }
    seed_by_dataset = {
        str(item.get("name")): int(item.get("seed", 42))
        for item in manifest.get("datasets", ())
        if isinstance(item, Mapping)
    }
    pg_version = e3._prepare_database(
        root,
        pg_env,
        tpch_scale=scale_by_dataset.get("tpch", ""),
        job_scale=scale_by_dataset.get("job", ""),
    )
    ranker = e3._ranker_from_manifest(root, manifest)
    registry = e3._e3_registry_from_manifest(manifest)
    cases = tuple(
        (query, policy)
        for query in selected_queries
        for policy in selected_policies
    )

    def prepare(case: Any) -> PreparedCell:
        query, policy = case
        return _prepare_cell_live(
            query=query,
            policy=policy,
            modes=selected_modes,
            pg_env=pg_env,
            ranker=ranker,
            registry=registry,
            dataset_scale=scale_by_dataset[query.workload],
            seed=seed_by_dataset[query.workload],
            pg_version=pg_version,
            access_root_materialized=access_root_materialized,
        )

    query_by_id = {query.query_id: query for query in selected_queries}
    policy_by_id = {policy.config_id: policy for policy in selected_policies}

    def prepare_measurement(cell: PreparedCell) -> None:
        # Cell preparation changes the table's global RLS policy.  Restore the
        # current cell after the prospective campaign and before its warmups.
        e3._configure_native_rls(
            query_by_id[cell.query_id],
            policy_by_id[cell.policy_id],
            pg_env,
        )

    return _execute_preview_cells(
        cases=cases,
        prepare_cell=prepare,
        prepare_measurement=prepare_measurement,
        canonicalize=lambda spec: _canonicalize_live(spec, pg_env),
        measure=lambda spec: _measure_live(spec, pg_env),
        protocol=protocol,
        output_dir=output_dir,
        manifest_id=str(manifest["manifest_id"]),
        manifest_digest=file_sha256(manifest_path),
        git_commit=_git_commit(root),
        correctness_only=correctness_only,
    )
