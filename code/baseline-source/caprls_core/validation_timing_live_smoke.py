"""Live smoke for artifact validation timing accounting."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .e8b_study import (
    _extract_explain_json,
    _row_count_from_explain_json,
    _timing_from_explain_json,
    _validated_query_script,
    _validation_ms_from_psql_output,
)
from .postgres_runner import PostgresEnv, run_psql_command


ARTIFACT_ID = "caprls_validation_timing_live_smoke"
EXPECTED_JSON = '[{"dep_kind":"context_scope","dep_name":"sha256:validation_timing_live_smoke","version_at_build":0}]'


@dataclass(frozen=True)
class ValidationTimingLiveSmokeIssue:
    path: str
    message: str


@dataclass(frozen=True)
class ValidationTimingLiveSmokeReport:
    issues: tuple[ValidationTimingLiveSmokeIssue, ...]
    details: Mapping[str, Any]

    @property
    def ok(self) -> bool:
        return not self.issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "details": dict(self.details),
            "issues": [issue.__dict__ for issue in self.issues],
        }


def _quote_sql(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _install_smoke_function_sql() -> str:
    return f"""
CREATE OR REPLACE FUNCTION public.caprls_assert_artifact_valid(artifact_id text, expected jsonb)
RETURNS boolean
LANGUAGE plpgsql
AS $$
BEGIN
  IF artifact_id <> {_quote_sql(ARTIFACT_ID)} THEN
    RAISE EXCEPTION 'unexpected artifact id: %', artifact_id;
  END IF;
  IF expected <> {_quote_sql(EXPECTED_JSON)}::jsonb THEN
    RAISE EXCEPTION 'unexpected validation payload: %', expected;
  END IF;
  RETURN true;
END
$$;
"""


def _independent_validation_script() -> str:
    return f"""
SET jit = off;
SET max_parallel_workers_per_gather = 0;
BEGIN ISOLATION LEVEL REPEATABLE READ;
SELECT 'caprls_independent_validation_start_ms=' || (EXTRACT(EPOCH FROM clock_timestamp()) * 1000.0)::text;
SELECT public.caprls_assert_artifact_valid({_quote_sql(ARTIFACT_ID)}, {_quote_sql(EXPECTED_JSON)}::jsonb);
SELECT 'caprls_independent_validation_end_ms=' || (EXTRACT(EPOCH FROM clock_timestamp()) * 1000.0)::text;
COMMIT;
"""


def _marker_delta_ms(stdout: str, *, start_marker: str, end_marker: str) -> float:
    started: float | None = None
    ended: float | None = None
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith(start_marker):
            started = float(stripped.split("=", 1)[1])
        elif stripped.startswith(end_marker):
            ended = float(stripped.split("=", 1)[1])
    if started is None or ended is None:
        raise ValueError(f"validation timing smoke output lacks markers:\n{stdout}")
    return max(0.0, ended - started)


def validate_validation_timing_live_smoke(
    pg_env: PostgresEnv,
    *,
    query_rows: int = 200_000,
    max_validation_ms: float = 100.0,
    max_absolute_audit_ms: float = 50.0,
    max_execution_fraction: float = 0.30,
    same_scale_slack_ms: float = 25.0,
    same_scale_multiplier: float = 10.0,
) -> ValidationTimingLiveSmokeReport:
    if query_rows <= 0:
        raise ValueError("query_rows must be positive")
    issues: list[ValidationTimingLiveSmokeIssue] = []

    run_psql_command(_install_smoke_function_sql(), pg_env)
    independent_output = run_psql_command(_independent_validation_script(), pg_env)
    independent_ms = _marker_delta_ms(
        independent_output,
        start_marker="caprls_independent_validation_start_ms=",
        end_marker="caprls_independent_validation_end_ms=",
    )

    query_sql = f"SELECT count(*) FROM generate_series(1, {int(query_rows)}) AS smoke_row(i)"
    validated_output = run_psql_command(
        _validated_query_script(query_sql, (ARTIFACT_ID,), EXPECTED_JSON),
        pg_env,
    )
    validated_ms = _validation_ms_from_psql_output(validated_output)
    explain_json = _extract_explain_json(validated_output)
    timing = _timing_from_explain_json(explain_json)
    row_count = _row_count_from_explain_json(explain_json)
    audit_bound_ms = max(max_absolute_audit_ms, max_execution_fraction * timing.execution_ms)
    same_scale_bound_ms = max(same_scale_slack_ms, same_scale_multiplier * max(independent_ms, 1e-9))

    if validated_ms >= max_validation_ms:
        issues.append(
            ValidationTimingLiveSmokeIssue(
                "validation_timing_live_smoke",
                f"validated-query validation_ms exceeds live smoke bound: {validated_ms:.6g} >= {max_validation_ms:.6g}",
            )
        )
    if validated_ms >= audit_bound_ms:
        issues.append(
            ValidationTimingLiveSmokeIssue(
                "validation_timing_live_smoke",
                "validated-query validation_ms exceeds regenerated-package audit bound: "
                f"validation_ms={validated_ms:.6g}, execution_ms={timing.execution_ms:.6g}, "
                f"threshold_ms={audit_bound_ms:.6g}",
            )
        )
    if abs(validated_ms - independent_ms) > same_scale_bound_ms:
        issues.append(
            ValidationTimingLiveSmokeIssue(
                "validation_timing_live_smoke",
                "validated-query marker timing is not comparable to independent validation gate: "
                f"validated_ms={validated_ms:.6g}, independent_ms={independent_ms:.6g}, "
                f"allowed_delta_ms={same_scale_bound_ms:.6g}",
            )
        )

    details = {
        "schema_version": "caprls-validation-timing-live-smoke-v1",
        "artifact_id": ARTIFACT_ID,
        "query_rows": query_rows,
        "result_row_count": row_count,
        "independent_validation_ms": independent_ms,
        "validated_query_validation_ms": validated_ms,
        "query_planning_ms": timing.planning_ms,
        "query_execution_ms": timing.execution_ms,
        "max_validation_ms": max_validation_ms,
        "audit_bound_ms": audit_bound_ms,
        "same_scale_bound_ms": same_scale_bound_ms,
    }
    return ValidationTimingLiveSmokeReport(issues=tuple(issues), details=details)


def write_validation_timing_live_smoke_report(
    *,
    output_path: Path,
    report: ValidationTimingLiveSmokeReport,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
