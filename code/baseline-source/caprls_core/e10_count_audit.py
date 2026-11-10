"""Audit E10 count fields against archived EXPLAIN evidence."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .e10_study import (
    CASES,
    _policy_eval_rows_from_explain,
    _render_policy_predicate,
    _target_for_case,
)
from .oracle_audit import _load_policy


RAW_SUBDIR = "SIGMOD_CURRENT_E10"
POSTGRES_MEASUREMENT = "postgres_measurement"


@dataclass(frozen=True)
class E10CountAuditIssue:
    path: str
    message: str


@dataclass(frozen=True)
class E10CountAuditReport:
    issues: tuple[E10CountAuditIssue, ...]
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


def _get(record: Mapping[str, Any], dotted_path: str, default: Any = None) -> Any:
    current: Any = record
    for part in dotted_path.split("."):
        if not isinstance(current, Mapping):
            return default
        current = current.get(part, default)
    return current


def _maybe_int(value: Any) -> int | None:
    if isinstance(value, bool) or value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_sidecar_path(path: Path) -> bool:
    return path.name.startswith(".") or "explain" in path.parts


def _load_raw_records(e10_dir: Path, issues: list[E10CountAuditIssue]) -> list[tuple[Path, Mapping[str, Any]]]:
    if not e10_dir.exists():
        issues.append(E10CountAuditIssue(str(e10_dir), "missing E10 raw directory"))
        return []
    records: list[tuple[Path, Mapping[str, Any]]] = []
    for path in sorted(item for item in e10_dir.rglob("*.json") if not _is_sidecar_path(item)):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            issues.append(E10CountAuditIssue(str(path), f"invalid JSON: {exc}"))
            continue
        if not isinstance(payload, Mapping):
            issues.append(E10CountAuditIssue(str(path), "raw record must be a JSON object"))
            continue
        records.append((path, payload))
    if not records:
        issues.append(E10CountAuditIssue(str(e10_dir), "E10 raw directory has no JSON records"))
    return records


def _resolve_explain_path(raw_record_path: Path, explain_path: str) -> Path:
    path = Path(explain_path)
    if path.is_absolute():
        return path
    return raw_record_path.parent / path


def _load_explain_json(raw_record_path: Path, explain_path: str) -> Sequence[Mapping[str, Any]] | None:
    path = _resolve_explain_path(raw_record_path, explain_path)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, list):
        return None
    return tuple(item for item in payload if isinstance(item, Mapping))


def _audit_context() -> Mapping[str, Any]:
    return {
        "tenant_id": 1,
        "purpose": "purpose_audit",
        "region": "region_audit",
        "clearance": 3,
        "user_id": 1,
    }


def _exact_predicate_for_query(project_root: Path, query_id: str) -> tuple[str, str] | None:
    case = {case.query_id: case for case in CASES}.get(query_id)
    if case is None:
        return None
    relname, rid_col, policy_id, alias = _target_for_case(case)
    policy = _load_policy(project_root, policy_id)
    template = policy.get("exact_sql_template")
    if not isinstance(template, str) or not template:
        return None
    return (
        relname,
        _render_policy_predicate(
            template,
            alias=alias,
            rid_col=rid_col,
            context=_audit_context(),
            relname=relname,
        ),
    )


def _is_postgres_measured_pass(record: Mapping[str, Any]) -> bool:
    return (
        record.get("experiment") == "E10"
        and record.get("status") == "pass"
        and record.get("run_kind") in {"normal_mode", "template_candidate"}
        and _get(record, "artifact_cost.amortization_model") == POSTGRES_MEASUREMENT
    )


def validate_e10_count_sources(
    raw_dir: Path,
    *,
    raw_subdir: str = RAW_SUBDIR,
    project_root: Path | None = None,
    require_observable: bool = True,
) -> E10CountAuditReport:
    """Compare E10 recorded count fields against archived EXPLAIN JSON."""

    project = Path(".").resolve() if project_root is None else project_root.resolve()
    issues: list[E10CountAuditIssue] = []
    e10_dir = raw_dir / raw_subdir
    records = _load_raw_records(e10_dir, issues)
    details: dict[str, Any] = {
        "raw_subdir": raw_subdir,
        "record_count": len(records),
        "checked_record_count": 0,
        "skipped_record_count": 0,
        "missing_explain_count": 0,
        "unobservable_policy_eval_count": 0,
        "mismatch_count": 0,
        "checked_by_template": {},
    }
    checked_by_template: Counter[str] = Counter()
    skipped_by_reason: Counter[str] = Counter()

    for path, record in records:
        if not _is_postgres_measured_pass(record):
            details["skipped_record_count"] += 1
            skipped_by_reason["not_measured_pass"] += 1
            continue
        template_id = str(_get(record, "template.template_id", ""))
        query_id = str(_get(record, "query.query_id", ""))
        recorded_policy_evals_raw = _get(record, "counts.policy_evals")
        recorded_policy_evals = _maybe_int(recorded_policy_evals_raw)
        explain_path = _get(record, "static_verifier.explain_path")
        if not isinstance(explain_path, str) or not explain_path:
            details["missing_explain_count"] += 1
            issues.append(E10CountAuditIssue(str(path), "measured pass row lacks static_verifier.explain_path"))
            continue
        explain_json = _load_explain_json(path, explain_path)
        if explain_json is None:
            details["missing_explain_count"] += 1
            issues.append(E10CountAuditIssue(str(path), f"cannot read EXPLAIN artifact: {explain_path}"))
            continue
        predicate = _exact_predicate_for_query(project, query_id)
        if predicate is None:
            issues.append(E10CountAuditIssue(str(path), f"cannot resolve exact policy predicate for {query_id}"))
            continue
        relname, exact_predicate = predicate
        expected = _policy_eval_rows_from_explain(
            explain_json,
            template_id=template_id,
            relname=relname,
            exact_predicate=exact_predicate,
        )
        if expected is None:
            details["unobservable_policy_eval_count"] += 1
            if recorded_policy_evals_raw is not None:
                issues.append(
                    E10CountAuditIssue(
                        str(path),
                        "counts.policy_evals must be null when EXPLAIN has no observable policy node",
                    )
                )
                continue
            if require_observable:
                issues.append(
                    E10CountAuditIssue(
                        str(path),
                        "policy_evals cannot be derived from EXPLAIN policy-bearing node",
                    )
                )
            continue
        if recorded_policy_evals is None:
            issues.append(E10CountAuditIssue(str(path), "counts.policy_evals is missing or not an integer"))
            continue
        details["checked_record_count"] += 1
        checked_by_template[template_id] += 1
        if recorded_policy_evals != expected:
            details["mismatch_count"] += 1
            issues.append(
                E10CountAuditIssue(
                    str(path),
                    f"counts.policy_evals {recorded_policy_evals} != EXPLAIN-derived {expected}",
                )
            )

    details["checked_by_template"] = dict(sorted(checked_by_template.items()))
    details["skipped_by_reason"] = dict(sorted(skipped_by_reason.items()))
    return E10CountAuditReport(issues=tuple(issues), details=details)
