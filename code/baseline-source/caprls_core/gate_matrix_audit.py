"""Validation for the X5/G1 contract gate-matrix evidence package."""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
    normalize_mode_id,
)

import csv
import json
import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


BAD_CONTRACT_STATUSES = {"wrong_result", "unsafe_observation"}
REJECT_STATUSES = {"expected_reject", "static_verifier_fail"}
VALID_ARTIFACT_STATUSES = {"", "not_applicable", "pass"}
SAFE_ARTIFACT_ACTIONS = {"execute", "reject", "fallback", "refresh", "replan"}
INVALID_ARTIFACT_ACTIONS = {"reject", "fallback", "refresh", "replan"}

FIG2_DIR = "fig2_contract_matrix"
FIG2_SOURCE = "fig2_contract_matrix_source.csv"
FIG7_DIR = "fig7_sigma_ablation"
FIG7_SOURCE = "fig7_sigma_ablation_source.csv"

RAW_SUITES = {
    "E1": "E1",
    "E6A": "E6",
    "E6B": "E6B_PROTOCOL",
    "E7": "E7",
    "E8A": "E8",
    "E8B": "E8B_PROTOCOL",
}
PROTOCOL_SUITES = {"E6B", "E8B"}

BEFORE_COST_CASES = (
    ("low_cost_stale_artifact", "E8A", "E8a_prepared_plan_stale", ADMISSION_FIRST_MODE),
    ("rid_incompatible_intersection", "E6B", "E6b_join_rid_intersection", ADMISSION_FIRST_MODE),
    ("unsafe_udf_contract_gate", "E1", "E1_unsafe_udf_before_auth", ADMISSION_FIRST_MODE),
    ("unsafe_udf_static_gate", "E7", "E7_guard_late_before_unsafe", "guard-late-only"),
    ("incomplete_guard", "E1", "E1_incomplete_guard", ADMISSION_FIRST_MODE),
    ("projection_dropped_residual_carrier", "E1", "E1_projection_drops_carrier", ADMISSION_FIRST_MODE),
)

SIGMA_ABLATIONS = (
    ("NoRIDMatProps", "E6b_join_rid_intersection", "no-rid-props", "wrong_result", "correctness"),
    ("NoSafetyLevel", "E6b_audit_after_candidate", "no-safety-level", "unsafe_observation", "safety"),
    ("NoContextScope", "E6b_cross_purpose_dashboard", "no-context-scope", "wrong_result", "correctness"),
    ("NoFreshness", "E6b_revocation_refresh", "no-freshness", "wrong_result", "correctness"),
    ("NoDomain", "E6b_self_join_branch_domain", "no-domain", "wrong_result", "correctness"),
    ("NoBranchLineage", "E6b_union_distinct_branch", "no-branch-lineage", "wrong_result", "correctness"),
    ("NoResidual", "E6b_guard_join_residual", "no-residual", "wrong_result", "correctness"),
    ("NoPhysProps", "E6b_ordered_export_cost", "no-phys-props", "pass", "performance"),
)

E8B_REQUIRED_ACTIONS = {"execute", "fallback", "refresh", "reject", "replan"}


@dataclass(frozen=True)
class GateMatrixAuditIssue:
    path: str
    message: str


@dataclass(frozen=True)
class GateMatrixAuditReport:
    issues: tuple[GateMatrixAuditIssue, ...]
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


@dataclass(frozen=True)
class _RawRecord:
    suite: str
    suite_dir: str
    path: Path
    record: Mapping[str, Any]


def _get(record: Mapping[str, Any], dotted_path: str, default: Any = "") -> Any:
    current: Any = record
    for part in dotted_path.split("."):
        if not isinstance(current, Mapping):
            return default
        current = current.get(part, default)
    return current


def _truth(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return False


def _maybe_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(parsed):
        return None
    return parsed


def _maybe_int(value: Any) -> int | None:
    parsed = _maybe_float(value)
    if parsed is None:
        return None
    return int(parsed)


def _query_id(item: _RawRecord) -> str:
    return str(_get(item.record, "query.query_id"))


def _mode(item: _RawRecord) -> str:
    return normalize_mode_id(str(item.record.get("mode", "")))


def _status(item: _RawRecord) -> str:
    return str(item.record.get("status", ""))


def _unauthorized_observations(item: _RawRecord) -> int:
    return int(_maybe_int(_get(item.record, "runtime_audit.unauthorized_observations", 0)) or 0)


def _udf_calls(item: _RawRecord) -> int:
    return int(_maybe_int(_get(item.record, "runtime_audit.udf_calls", 0)) or 0)


def _client_observations(item: _RawRecord) -> int:
    client_errors = int(_maybe_int(_get(item.record, "runtime_audit.client_errors", 0)) or 0)
    client_notices = int(_maybe_int(_get(item.record, "runtime_audit.client_notices", 0)) or 0)
    return client_errors + client_notices


def _known_invalid_accepted(item: _RawRecord) -> bool:
    return _truth(_get(item.record, "oracle_check.known_invalid_accepted", False))


def _known_valid_rejected(item: _RawRecord) -> bool:
    return _truth(_get(item.record, "oracle_check.known_valid_rejected", False))


def _planner_costed(item: _RawRecord) -> int:
    return int(_maybe_int(_get(item.record, "planner.costed_templates", 0)) or 0)


def _planner_rejected(item: _RawRecord) -> int:
    return int(_maybe_int(_get(item.record, "planner.rejected_templates", 0)) or 0)


def _has_rejection_reason(item: _RawRecord) -> bool:
    rejection_reasons = _get(item.record, "planner.rejection_reasons", {})
    static_reasons = _get(item.record, "static_verifier.reasons", [])
    template_reason = _get(item.record, "template_applicability.reason", "")
    failure_reason = _get(item.record, "failure.reason", "")
    return bool(rejection_reasons or static_reasons or template_reason or failure_reason)


def _artifact_validation(item: _RawRecord) -> Mapping[str, Any]:
    value = item.record.get("artifact_validation")
    if isinstance(value, Mapping):
        return value
    return {}


def _artifact_action(item: _RawRecord) -> str:
    return str(_artifact_validation(item).get("action", ""))


def _artifact_status(item: _RawRecord) -> str:
    return str(_artifact_validation(item).get("status", ""))


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _is_auxiliary_json_path(path: Path) -> bool:
    return path.name.startswith(".") or "explain" in path.parts


def _load_raw_records(raw_dir: Path, issues: list[GateMatrixAuditIssue], details: dict[str, Any]) -> list[_RawRecord]:
    records: list[_RawRecord] = []
    suite_counts: dict[str, int] = {}
    for suite, subdir in RAW_SUITES.items():
        suite_dir = raw_dir / subdir
        if not suite_dir.exists():
            issues.append(GateMatrixAuditIssue(str(suite_dir), "missing required raw suite directory"))
            suite_counts[suite] = 0
            continue
        count = 0
        for path in sorted(item for item in suite_dir.rglob("*.json") if not _is_auxiliary_json_path(item)):
            try:
                parsed = json.loads(path.read_text(encoding="utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                issues.append(GateMatrixAuditIssue(str(path), f"invalid JSON: {exc}"))
                continue
            if not isinstance(parsed, Mapping):
                issues.append(GateMatrixAuditIssue(str(path), "raw result must be a JSON object"))
                continue
            records.append(_RawRecord(suite=suite, suite_dir=subdir, path=path, record=parsed))
            count += 1
        suite_counts[suite] = count
        if count == 0:
            issues.append(GateMatrixAuditIssue(str(suite_dir), "raw suite has no JSON records"))
    details["raw_suite_record_counts"] = dict(sorted(suite_counts.items()))
    return records


def _validate_summary_dirs(summary_dir: Path | None, issues: list[GateMatrixAuditIssue], details: dict[str, Any]) -> None:
    if summary_dir is None:
        details["summary_validation"] = "skipped"
        return
    present: dict[str, bool] = {}
    for suite, subdir in RAW_SUITES.items():
        summary_path = summary_dir / subdir / "summary.json"
        present[suite] = summary_path.exists()
        if not summary_path.exists():
            issues.append(GateMatrixAuditIssue(str(summary_path), "missing required summary.json"))
    details["summary_dirs_present"] = present


def _records_matching(records: Iterable[_RawRecord], suite: str, query_id: str, mode: str) -> list[_RawRecord]:
    return [
        item
        for item in records
        if item.suite == suite and _query_id(item) == query_id and _mode(item) == mode
    ]


def _validate_protocol(
    *,
    items: Sequence[_RawRecord],
    expected_warmup: int,
    expected_measured: int,
    path_label: str,
    issues: list[GateMatrixAuditIssue],
) -> dict[str, Any]:
    phase_iterations: dict[str, list[int]] = defaultdict(list)
    measurement_declared = True
    for item in items:
        phase = str(_get(item.record, "measurement.phase", ""))
        iteration = _maybe_int(_get(item.record, "measurement.iteration", None))
        warmup_repetitions = _maybe_int(_get(item.record, "measurement.warmup_repetitions", None))
        measured_repetitions = _maybe_int(_get(item.record, "measurement.measured_repetitions", None))
        if phase not in {"warmup", "measured"} or iteration is None:
            measurement_declared = False
            issues.append(GateMatrixAuditIssue(str(item.path), f"{path_label} is missing measurement phase/iteration"))
            continue
        if warmup_repetitions != expected_warmup or measured_repetitions != expected_measured:
            issues.append(
                GateMatrixAuditIssue(
                    str(item.path),
                    f"{path_label} declares warmup/measured "
                    f"{warmup_repetitions}/{measured_repetitions}, expected {expected_warmup}/{expected_measured}",
                )
            )
        phase_iterations[phase].append(iteration)

    expected = {"warmup": expected_warmup, "measured": expected_measured}
    observed: dict[str, Any] = {}
    for phase, expected_count in expected.items():
        iterations = phase_iterations.get(phase, [])
        unique = sorted(set(iterations))
        observed[phase] = {"count": len(iterations), "unique_iterations": unique}
        if len(iterations) != expected_count or unique != list(range(1, expected_count + 1)):
            issues.append(
                GateMatrixAuditIssue(
                    path_label,
                    f"{phase} repetitions {unique} with count {len(iterations)} "
                    f"do not match expected 1..{expected_count}",
                )
            )
        if len(iterations) != len(unique):
            issues.append(GateMatrixAuditIssue(path_label, f"{phase} repetitions contain duplicate iterations"))
    observed["declared"] = measurement_declared
    return observed


def _finite_median(items: Iterable[_RawRecord], dotted_path: str) -> float | None:
    values: list[float] = []
    for item in items:
        if str(_get(item.record, "measurement.phase", "")) != "measured":
            continue
        parsed = _maybe_float(_get(item.record, dotted_path, None))
        if parsed is not None:
            values.append(parsed)
    if not values:
        return None
    return float(statistics.median(values))


def _validate_admission_first_zero(
    records: Sequence[_RawRecord],
    issues: list[GateMatrixAuditIssue],
    details: dict[str, Any],
) -> None:
    status_counts: dict[str, dict[str, int]] = {}
    for suite in RAW_SUITES:
        suite_records = [item for item in records if item.suite == suite and _mode(item) == ADMISSION_FIRST_MODE]
        status_counts[suite] = dict(sorted(Counter(_status(item) for item in suite_records).items()))
        if not suite_records:
            issues.append(GateMatrixAuditIssue(suite, "missing AdmissionFirst rows"))
        for item in suite_records:
            status = _status(item)
            if status in BAD_CONTRACT_STATUSES:
                issues.append(GateMatrixAuditIssue(str(item.path), f"AdmissionFirst produced {status}"))
            if _known_invalid_accepted(item):
                issues.append(GateMatrixAuditIssue(str(item.path), "AdmissionFirst accepted a known-invalid candidate"))
            if _known_valid_rejected(item):
                issues.append(GateMatrixAuditIssue(str(item.path), "AdmissionFirst rejected a known-valid finite-template candidate"))
            if _unauthorized_observations(item) != 0:
                issues.append(GateMatrixAuditIssue(str(item.path), "AdmissionFirst recorded unauthorized observations"))
    details["admission_first_status_counts"] = status_counts


def _validate_before_cost_rejections(
    records: Sequence[_RawRecord],
    issues: list[GateMatrixAuditIssue],
    details: dict[str, Any],
) -> None:
    case_details: dict[str, Any] = {}
    for case_name, suite, query_id, mode in BEFORE_COST_CASES:
        matches = _records_matching(records, suite, query_id, mode)
        case_details[case_name] = {
            "suite": suite,
            "query_id": query_id,
            "mode": mode,
            "records": len(matches),
            "status_counts": dict(sorted(Counter(_status(item) for item in matches).items())),
        }
        if not matches:
            issues.append(GateMatrixAuditIssue(f"{suite}:{query_id}:{mode}", f"missing before-cost rejection case {case_name}"))
            continue
        for item in matches:
            if _status(item) not in REJECT_STATUSES:
                issues.append(
                    GateMatrixAuditIssue(str(item.path), f"{case_name} status {_status(item)!r} is not a rejection status")
                )
            if _planner_costed(item) != 0:
                issues.append(GateMatrixAuditIssue(str(item.path), f"{case_name} reached costing before rejection"))
            if _planner_rejected(item) <= 0:
                issues.append(GateMatrixAuditIssue(str(item.path), f"{case_name} did not record a rejected template"))
            if not _has_rejection_reason(item):
                issues.append(GateMatrixAuditIssue(str(item.path), f"{case_name} lacks a rejection reason"))
    details["before_cost_rejections"] = case_details


def _validate_sigma_ablation(
    records: Sequence[_RawRecord],
    *,
    expected_warmup: int,
    expected_measured: int,
    issues: list[GateMatrixAuditIssue],
    details: dict[str, Any],
) -> None:
    sigma_details: dict[str, Any] = {}
    for component, query_id, diagnostic_mode, expected_status, witness_kind in SIGMA_ABLATIONS:
        af_items = _records_matching(records, "E6B", query_id, ADMISSION_FIRST_MODE)
        diagnostic_items = _records_matching(records, "E6B", query_id, diagnostic_mode)
        component_details: dict[str, Any] = {
            "query_id": query_id,
            "diagnostic_mode": diagnostic_mode,
            "witness_kind": witness_kind,
            "admission_first_records": len(af_items),
            "diagnostic_records": len(diagnostic_items),
            "admission_first_status_counts": dict(sorted(Counter(_status(item) for item in af_items).items())),
            "diagnostic_status_counts": dict(sorted(Counter(_status(item) for item in diagnostic_items).items())),
        }
        sigma_details[component] = component_details

        if not af_items:
            issues.append(GateMatrixAuditIssue(f"E6B:{query_id}:{ADMISSION_FIRST_MODE}", f"missing AdmissionFirst row for {component}"))
        else:
            component_details["admission_first_protocol"] = _validate_protocol(
                items=af_items,
                expected_warmup=expected_warmup,
                expected_measured=expected_measured,
                path_label=f"E6B:{query_id}:{ADMISSION_FIRST_MODE}",
                issues=issues,
            )
            for item in af_items:
                if _status(item) in BAD_CONTRACT_STATUSES:
                    issues.append(GateMatrixAuditIssue(str(item.path), f"AdmissionFirst {component} row produced {_status(item)}"))
                if _known_invalid_accepted(item) or _known_valid_rejected(item):
                    issues.append(GateMatrixAuditIssue(str(item.path), f"AdmissionFirst {component} row has an oracle failure flag"))
                if _unauthorized_observations(item) != 0:
                    issues.append(GateMatrixAuditIssue(str(item.path), f"AdmissionFirst {component} row observed unauthorized data"))

        if not diagnostic_items:
            issues.append(GateMatrixAuditIssue(f"E6B:{query_id}:{diagnostic_mode}", f"missing diagnostic row for {component}"))
            continue
        component_details["diagnostic_protocol"] = _validate_protocol(
            items=diagnostic_items,
            expected_warmup=expected_warmup,
            expected_measured=expected_measured,
            path_label=f"E6B:{query_id}:{diagnostic_mode}",
            issues=issues,
        )

        if witness_kind == "performance":
            if any(_status(item) != "pass" for item in diagnostic_items):
                issues.append(GateMatrixAuditIssue(f"E6B:{query_id}:{diagnostic_mode}", "NoPhysProps witness must stay semantically safe"))
            if not any(_known_valid_rejected(item) for item in diagnostic_items) and not any(
                (_maybe_int(_get(item.record, "counts.missed_optimization_count", 0)) or 0) > 0
                for item in diagnostic_items
            ):
                issues.append(
                    GateMatrixAuditIssue(
                        f"E6B:{query_id}:{diagnostic_mode}",
                        "NoPhysProps witness lacks known-valid-rejected or missed-optimization evidence",
                    )
                )
            af_execution_median = _finite_median(af_items, "timing_ms.execution")
            diagnostic_execution_median = _finite_median(diagnostic_items, "timing_ms.execution")
            af_total_median = _finite_median(af_items, "timing_ms.total")
            diagnostic_total_median = _finite_median(diagnostic_items, "timing_ms.total")
            component_details["admission_first_execution_ms_median"] = af_execution_median
            component_details["diagnostic_execution_ms_median"] = diagnostic_execution_median
            component_details["admission_first_total_ms_median"] = af_total_median
            component_details["diagnostic_total_ms_median"] = diagnostic_total_median
            if (
                af_execution_median is None
                or diagnostic_execution_median is None
                or diagnostic_execution_median <= af_execution_median
            ) and (
                af_total_median is None
                or diagnostic_total_median is None
                or diagnostic_total_median <= af_total_median
            ):
                issues.append(
                    GateMatrixAuditIssue(
                        f"E6B:{query_id}:{diagnostic_mode}",
                        "NoPhysProps diagnostic median is not slower than AdmissionFirst",
                    )
                )
            continue

        bad_status_count = sum(1 for item in diagnostic_items if _status(item) == expected_status)
        if bad_status_count != len(diagnostic_items):
            issues.append(
                GateMatrixAuditIssue(
                    f"E6B:{query_id}:{diagnostic_mode}",
                    f"diagnostic status count for {expected_status} is {bad_status_count}/{len(diagnostic_items)}",
                )
            )
        if not any(_known_invalid_accepted(item) for item in diagnostic_items):
            issues.append(
                GateMatrixAuditIssue(
                    f"E6B:{query_id}:{diagnostic_mode}",
                    "diagnostic row lacks known-invalid-accepted oracle flag",
                )
            )
        if expected_status == "unsafe_observation" and not any(_unauthorized_observations(item) > 0 for item in diagnostic_items):
            issues.append(
                GateMatrixAuditIssue(
                    f"E6B:{query_id}:{diagnostic_mode}",
                    "unsafe diagnostic row lacks unauthorized-observation evidence",
                )
            )

    details["sigma_ablation"] = sigma_details


def _require_one(
    records: Sequence[_RawRecord],
    suite: str,
    query_id: str,
    mode: str,
    issues: list[GateMatrixAuditIssue],
) -> _RawRecord | None:
    matches = _records_matching(records, suite, query_id, mode)
    if not matches:
        issues.append(GateMatrixAuditIssue(f"{suite}:{query_id}:{mode}", "missing required evidence row"))
        return None
    return matches[0]


def _validate_e7_direct_observation(
    records: Sequence[_RawRecord],
    issues: list[GateMatrixAuditIssue],
    details: dict[str, Any],
) -> None:
    e7_details: dict[str, Any] = {}
    contract = _require_one(records, "E7", "E7_contract_unsafe_where", ADMISSION_FIRST_MODE, issues)
    if contract is not None:
        e7_details["contract_unsafe_where"] = {
            "status": _status(contract),
            "udf_calls": _udf_calls(contract),
            "unauthorized_observations": _unauthorized_observations(contract),
        }
        if _status(contract) != "pass" or _unauthorized_observations(contract) != 0 or _udf_calls(contract) <= 0:
            issues.append(GateMatrixAuditIssue(str(contract.path), "E7 AdmissionFirst direct-observation row is not clean"))

    raw_pushdown = _require_one(records, "E7", "E7_positive_raw_pushdown", "unsafe-pushdown-positive-control", issues)
    if raw_pushdown is not None:
        e7_details["positive_raw_pushdown"] = {
            "status": _status(raw_pushdown),
            "udf_calls": _udf_calls(raw_pushdown),
            "unauthorized_observations": _unauthorized_observations(raw_pushdown),
        }
        if _status(raw_pushdown) != "unsafe_observation" or _unauthorized_observations(raw_pushdown) <= 0:
            issues.append(GateMatrixAuditIssue(str(raw_pushdown.path), "E7 raw-pushdown positive control did not expose unauthorized observations"))

    unsafe_throw = _require_one(records, "E7", "E7_unsafe_throw", "unsafe-pushdown-positive-control", issues)
    if unsafe_throw is not None:
        e7_details["unsafe_throw"] = {
            "status": _status(unsafe_throw),
            "client_observations": _client_observations(unsafe_throw),
            "unauthorized_observations": _unauthorized_observations(unsafe_throw),
        }
        if (
            _status(unsafe_throw) != "unsafe_observation"
            or _unauthorized_observations(unsafe_throw) <= 0
            or _client_observations(unsafe_throw) <= 0
        ):
            issues.append(GateMatrixAuditIssue(str(unsafe_throw.path), "E7 throwing UDF positive control lacks client-visible evidence"))

    guard_late = _require_one(records, "E7", "E7_guard_late_before_unsafe", "guard-late-only", issues)
    if guard_late is not None:
        e7_details["guard_late_static_gate"] = {
            "status": _status(guard_late),
            "costed_templates": _planner_costed(guard_late),
            "rejected_templates": _planner_rejected(guard_late),
        }
        if _status(guard_late) != "static_verifier_fail" or _planner_costed(guard_late) != 0 or _planner_rejected(guard_late) <= 0:
            issues.append(GateMatrixAuditIssue(str(guard_late.path), "E7 guard-late row was not rejected before costing"))

    details["e7_direct_observation"] = e7_details


def _validate_artifact_validation(
    records: Sequence[_RawRecord],
    *,
    expected_warmup: int,
    expected_measured: int,
    issues: list[GateMatrixAuditIssue],
    details: dict[str, Any],
) -> None:
    action_counts: Counter[str] = Counter()
    invalid_status_counts: Counter[str] = Counter()
    for item in records:
        validation = _artifact_validation(item)
        if not validation:
            continue
        action = str(validation.get("action", ""))
        status = str(validation.get("status", ""))
        expected_action = str(validation.get("expected_action", ""))
        action_counts[action] += 1
        enforce_contract_gate = _mode(item) == ADMISSION_FIRST_MODE
        if action and action not in SAFE_ARTIFACT_ACTIONS:
            issues.append(GateMatrixAuditIssue(str(item.path), f"unknown artifact_validation.action {action!r}"))
        if enforce_contract_gate and expected_action and action and expected_action != action:
            issues.append(GateMatrixAuditIssue(str(item.path), "artifact_validation.action does not match expected_action"))
        if status not in VALID_ARTIFACT_STATUSES:
            invalid_status_counts[status] += 1
            if not enforce_contract_gate:
                continue
            if action not in INVALID_ARTIFACT_ACTIONS:
                issues.append(GateMatrixAuditIssue(str(item.path), f"invalid artifact status {status!r} used action {action!r}"))
            if not validation.get("failure_sqlstate") or not validation.get("failure_symbol"):
                issues.append(GateMatrixAuditIssue(str(item.path), f"invalid artifact status {status!r} lacks SQLSTATE/symbol"))
            if action == "reject" and (_planner_costed(item) != 0 or _planner_rejected(item) <= 0):
                issues.append(GateMatrixAuditIssue(str(item.path), "artifact reject did not happen before costing"))

    e8b_contract = [
        item
        for item in records
        if item.suite == "E8B" and _mode(item) == ADMISSION_FIRST_MODE
    ]
    e8b_action_counts = Counter(_artifact_action(item) for item in e8b_contract)
    missing_actions = sorted(E8B_REQUIRED_ACTIONS - set(e8b_action_counts))
    if missing_actions:
        issues.append(GateMatrixAuditIssue("E8B", f"missing AdmissionFirst artifact action(s): {', '.join(missing_actions)}"))
    e8b_protocol: dict[str, Any] = {}
    for query_id in sorted({_query_id(item) for item in e8b_contract}):
        cell = [item for item in e8b_contract if _query_id(item) == query_id]
        e8b_protocol[query_id] = _validate_protocol(
            items=cell,
            expected_warmup=expected_warmup,
            expected_measured=expected_measured,
            path_label=f"E8B:{query_id}:{ADMISSION_FIRST_MODE}",
            issues=issues,
        )

    details["artifact_validation"] = {
        "action_counts": dict(sorted(action_counts.items())),
        "invalid_status_counts": dict(sorted(invalid_status_counts.items())),
        "e8b_admission_first_action_counts": dict(sorted(e8b_action_counts.items())),
        "e8b_admission_first_protocol": e8b_protocol,
    }


def _validate_figures(
    figure_dir: Path | None,
    *,
    expected_warmup: int,
    expected_measured: int,
    issues: list[GateMatrixAuditIssue],
    details: dict[str, Any],
) -> None:
    if figure_dir is None:
        details["figure_validation"] = "skipped"
        return

    fig_details: dict[str, Any] = {}
    fig2_path = figure_dir / FIG2_DIR / FIG2_SOURCE
    if not fig2_path.exists():
        issues.append(GateMatrixAuditIssue(str(fig2_path), "missing Fig2 contract-matrix source CSV"))
    else:
        rows = _read_csv(fig2_path)
        contract_rows = [
            row
            for row in rows
            if normalize_mode_id(str(row.get("mode", ""))) == ADMISSION_FIRST_MODE
        ]
        diagnostic_bad = [
            row
            for row in rows
            if normalize_mode_id(str(row.get("mode", ""))) != ADMISSION_FIRST_MODE
            and row.get("status") in BAD_CONTRACT_STATUSES
        ]
        contract_bad = [row for row in contract_rows if row.get("status") in BAD_CONTRACT_STATUSES]
        fig_details["fig2_rows"] = len(rows)
        fig_details["fig2_admission_first_rows"] = len(contract_rows)
        fig_details["fig2_diagnostic_bad_rows"] = len(diagnostic_bad)
        if contract_bad:
            issues.append(GateMatrixAuditIssue(str(fig2_path), "Fig2 contains AdmissionFirst wrong/unsafe rows"))
        if not diagnostic_bad:
            issues.append(GateMatrixAuditIssue(str(fig2_path), "Fig2 lacks diagnostic wrong/unsafe positive controls"))

    fig7_path = figure_dir / FIG7_DIR / FIG7_SOURCE
    if not fig7_path.exists():
        issues.append(GateMatrixAuditIssue(str(fig7_path), "missing Fig7 Sigma-ablation source CSV"))
    else:
        rows = _read_csv(fig7_path)
        fig_details["fig7_rows"] = len(rows)
        fig7_lookup = {
            (
                row.get("component", ""),
                row.get("case_id", ""),
                normalize_mode_id(str(row.get("mode", ""))),
            ): row
            for row in rows
        }
        for component, query_id, diagnostic_mode, expected_status, _witness_kind in SIGMA_ABLATIONS:
            for mode, label in ((ADMISSION_FIRST_MODE, "AdmissionFirst"), (diagnostic_mode, "diagnostic")):
                row = fig7_lookup.get((component, query_id, mode))
                if row is None:
                    issues.append(GateMatrixAuditIssue(str(fig7_path), f"Fig7 missing {label} row for {component}"))
                    continue
                sample_count = _maybe_int(row.get("sample_count"))
                warmup_count = _maybe_int(row.get("warmup_count"))
                if sample_count != expected_measured or warmup_count != expected_warmup:
                    issues.append(
                        GateMatrixAuditIssue(
                            str(fig7_path),
                            f"Fig7 {component}/{mode} counts {warmup_count}/{sample_count} "
                            f"do not match {expected_warmup}/{expected_measured}",
                        )
                    )
                if row.get("protocol_status") != "ok":
                    issues.append(GateMatrixAuditIssue(str(fig7_path), f"Fig7 {component}/{mode} protocol_status is not ok"))
            diagnostic_row = fig7_lookup.get((component, query_id, diagnostic_mode))
            if diagnostic_row is not None and diagnostic_row.get("status") != expected_status:
                issues.append(
                    GateMatrixAuditIssue(
                        str(fig7_path),
                        f"Fig7 {component}/{diagnostic_mode} status {diagnostic_row.get('status')} != {expected_status}",
                    )
                )
    details["figures"] = fig_details


def validate_gate_matrix(
    raw_dir: Path,
    summary_dir: Path | None = None,
    figure_dir: Path | None = None,
    *,
    expected_warmup: int = 5,
    expected_measured: int = 10,
) -> GateMatrixAuditReport:
    """Validate current gate evidence without treating smoke rows as protocol rows."""

    issues: list[GateMatrixAuditIssue] = []
    details: dict[str, Any] = {
        "expected_protocol": {
            "protocol_suites": sorted(PROTOCOL_SUITES),
            "warmup": expected_warmup,
            "measured": expected_measured,
        }
    }

    records = _load_raw_records(raw_dir, issues, details)
    _validate_summary_dirs(summary_dir, issues, details)
    _validate_admission_first_zero(records, issues, details)
    _validate_before_cost_rejections(records, issues, details)
    _validate_sigma_ablation(
        records,
        expected_warmup=expected_warmup,
        expected_measured=expected_measured,
        issues=issues,
        details=details,
    )
    _validate_e7_direct_observation(records, issues, details)
    _validate_artifact_validation(
        records,
        expected_warmup=expected_warmup,
        expected_measured=expected_measured,
        issues=issues,
        details=details,
    )
    _validate_figures(
        figure_dir,
        expected_warmup=expected_warmup,
        expected_measured=expected_measured,
        issues=issues,
        details=details,
    )

    return GateMatrixAuditReport(issues=tuple(issues), details=details)
