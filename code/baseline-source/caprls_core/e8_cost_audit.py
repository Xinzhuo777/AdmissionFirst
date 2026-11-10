"""Validation for the X7 E8 artifact-cost accounting package."""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
    normalize_mode_id,
)

import csv
import json
import math
# BEGIN PHASE_B2A_E8COST_AUDIT_STDLIB_IMPORTS
import re
# END PHASE_B2A_E8COST_AUDIT_STDLIB_IMPORTS
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .artifact_economics import ArtifactEconomics, amortized_artifact_latency_ms
# BEGIN PHASE_B2A_E8COST_AUDIT_IMPORTS
from .e8_cost_evidence import (
    E8COST_ACCOUNTING_PROJECTION,
    E8COST_EVIDENCE_CLASSES,
    E8COST_GATE_REJECT,
    E8COST_RESULT_EXECUTION,
    E8CostEvidenceClassificationError,
    classify_e8_cost_evidence,
)
# END PHASE_B2A_E8COST_AUDIT_IMPORTS


SUMMARY_SUBDIR = "E8_COST_1E6"
MANIFEST_ID = "e8_cost_update_rate_v1"
V3_MANIFEST_ID = "e8_cost_update_rate_v1_taxonomy_v3"
MANIFEST_IDS = frozenset({MANIFEST_ID, V3_MANIFEST_ID})
EXPECTED_STAGE = "artifact_cost_update_rate"
EXPECTED_DATASET = {"name": "synthetic_saas", "scale": "1e6", "seed": 47}
EXPECTED_Q_VALUES = {1, 10, 100, 1000}
EXPECTED_U_VALUES = {0.0, 0.001, 0.01, 0.1}
EXPECTED_PREFIXES = {
    "E8cost_mav_dash": "MAV-DASH",
    "E8cost_authidx_sparse": "AUTHIDX-SPARSE",
    "E8cost_stale_fallback": "STALE-FALLBACK",
}
EXPECTED_SCENARIO_COUNT = 48
EXPECTED_CELL_COUNT = 384
EXPECTED_MEASURED_RECORD_COUNT = 3840
EXPECTED_RAW_RECORD_COUNT = 5760
REQUIRED_MODES = {
    "auth-index-enum-only",
    "conservative-barrier",
    ADMISSION_FIRST_MODE,
    "mav-no-version",
    "mav-only",
    "naive-artifact-only",
    "native-pg-rls-physical-design",
    "stale-artifact-user",
}
EXPECTED_MODE_COUNTS = {mode: 720 for mode in REQUIRED_MODES}
REQUIRED_COST_COLUMNS = (
    "query_id",
    "mode",
    "artifact_type",
    "query_shape",
    "expected_action",
    "update_rate_per_hour",
    "dominant_status",
    "dominant_action",
    "dominant_template_id",
    "choice_reason_counts",
    "status_counts",
    "wrong_result_count",
    "known_invalid_accepted_count",
    "sample_count",
    "query_only_ms_median",
    "build_ms_median",
    "refresh_ms_median",
    "maintenance_ms_total_median",
    "fallback_ms_median",
    "storage_bytes_median",
    "amortized_build_plus_single_query_ms_median",
    "amortized_q100_u1pct_ms_median",
    "amortized_declared_q_u_ms_median",
)
# BEGIN PHASE_B2A_E8COST_AUDIT_CONTRACT
EXPECTED_WARMUP_RECORD_COUNT = 1920
EXPECTED_CLASS_RAW_RECORD_COUNTS = {
    E8COST_ACCOUNTING_PROJECTION: 720,
    E8COST_GATE_REJECT: 480,
    E8COST_RESULT_EXECUTION: 4560,
}
EXPECTED_CLASS_MEASURED_RECORD_COUNTS = {
    E8COST_ACCOUNTING_PROJECTION: 480,
    E8COST_GATE_REJECT: 320,
    E8COST_RESULT_EXECUTION: 3040,
}
EXPECTED_CLASS_WARMUP_RECORD_COUNTS = {
    E8COST_ACCOUNTING_PROJECTION: 240,
    E8COST_GATE_REJECT: 160,
    E8COST_RESULT_EXECUTION: 1520,
}
EXPECTED_CLASS_CELL_COUNTS = {
    E8COST_ACCOUNTING_PROJECTION: 48,
    E8COST_GATE_REJECT: 32,
    E8COST_RESULT_EXECUTION: 304,
}
EXPECTED_EXECUTED_PASS_COUNT = 2720
EXPECTED_EXECUTED_WRONG_COUNT = 320
EXPECTED_EXECUTED_DENOMINATOR = 3040
EXPECTED_PROJECTED_ACTION_CELL_COUNTS = {"execute": 32, "fallback": 16}
EXPECTED_PROJECTED_ACTION_MEASURED_RECORD_COUNTS = {
    "execute": 320,
    "fallback": 160,
}
EXPECTED_PROJECTED_TEMPLATE_CELL_COUNTS = {
    "auth_index_enum_v1": 16,
    "barrier_filter_v1": 16,
    "mav_scan_v1": 16,
}
EXPECTED_PROJECTED_TEMPLATE_MEASURED_RECORD_COUNTS = {
    "auth_index_enum_v1": 160,
    "barrier_filter_v1": 160,
    "mav_scan_v1": 160,
}
EXPECTED_RAW_STATUS_COUNTS = {
    "expected_reject": 480,
    "not_executed": 720,
    "pass": 4080,
    "wrong_result": 480,
}
EXPECTED_MEASURED_WRONG_BY_MODE = {
    "naive-artifact-only": 160,
    "stale-artifact-user": 160,
}
E8COST_QUERY_ID_RE = re.compile(
    r"^E8cost_(mav_dash|authidx_sparse|stale_fallback)_"
    r"Q(1|10|100|1000)_U(0|0_1|1|10)pct$"
)
B2A_REQUIRED_COST_COLUMNS = (
    "query_id",
    "mode",
    "e8cost_evidence_class",
    "accounting_family",
    "accounting_q",
    "accounting_u",
    "sample_count",
    "warmup_count",
    "total_record_count",
    "accounting_projection_record_count",
    "gate_reject_record_count",
    "result_execution_record_count",
    "executed_pass_count",
    "executed_wrong_result_count",
    "executed_result_denominator",
    "executed_wrong_result_rate",
    "invalid_gate_admission_count",
    "projected_action_accounting_counts",
    "projected_template_accounting_counts",
    "observed_accounting_minimum_template_counts",
    "observed_accounting_minimum_action_counts",
    "observed_accounting_minimum_amortized_latency_ms_median",
    "projected_case_validation_ms_median",
    "gate_accounting_validation_ms_median",
    "executed_query_only_ms_median",
    "executed_execution_ms_median",
    "executed_total_ms_median",
    "observed_accounting_declared_q_u_ms_median",
)
B2A_FORBIDDEN_SUMMARY_KEYS = frozenset(
    {
        "admission_first_wrong_results",
        "admission_first_expected_rejects",
        "diagnostic_wrong_results",
        "admission_first_actions",
        "admission_first_choice_reasons",
        "admission_first_templates",
        "best_query_only_by_scenario",
        "best_amortized_q100_u1pct_by_scenario",
        "best_amortized_declared_q_u_by_scenario",
        "diagnostic_modes_excluded_from_best_tables",
    }
)
B2A_FORBIDDEN_COST_COLUMNS = frozenset(
    {
        "dominant_template_id",
        "dominant_status",
        "dominant_action",
        "choice_reason_counts",
        "wrong_result_count",
        "known_invalid_accepted_count",
        "admission_first_wrong_results",
        "chosen_template_id",
        "winner",
    }
)
# END PHASE_B2A_E8COST_AUDIT_CONTRACT


@dataclass(frozen=True)
class E8CostAuditIssue:
    path: str
    message: str


@dataclass(frozen=True)
class E8CostAuditReport:
    issues: tuple[E8CostAuditIssue, ...]
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


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _maybe_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def _maybe_int(value: Any) -> int | None:
    parsed = _maybe_float(value)
    if parsed is None:
        return None
    return int(parsed)


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


def _close(left: float | None, right: float | None, *, abs_tol: float = 1e-6) -> bool:
    if left is None or right is None:
        return False
    return math.isclose(left, right, rel_tol=1e-9, abs_tol=abs_tol)


def _json_counter_keys(value: Any) -> set[str]:
    if not isinstance(value, str) or not value.strip():
        return set()
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return set()
    if not isinstance(parsed, Mapping):
        return set()
    return {
        str(key)
        for key, raw_count in parsed.items()
        if (_maybe_int(raw_count) or 0) > 0
    }


def _query_family(query_id: str) -> str | None:
    for prefix, label in EXPECTED_PREFIXES.items():
        if query_id.startswith(prefix):
            return label
    return None


def _is_sidecar_path(path: Path) -> bool:
    return path.name.startswith("._") or path.name.startswith(".") or "explain" in path.parts


def _load_records(raw_dir: Path, issues: list[E8CostAuditIssue]) -> list[tuple[Path, Mapping[str, Any]]]:
    cost_dir = raw_dir / SUMMARY_SUBDIR
    if not cost_dir.exists():
        issues.append(E8CostAuditIssue(str(cost_dir), "missing E8_COST_1E6 raw directory"))
        return []

    records: list[tuple[Path, Mapping[str, Any]]] = []
    for path in sorted(item for item in cost_dir.rglob("*.json") if not _is_sidecar_path(item)):
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            issues.append(E8CostAuditIssue(str(path), f"invalid JSON: {exc}"))
            continue
        if not isinstance(parsed, Mapping):
            issues.append(E8CostAuditIssue(str(path), "raw result must be a JSON object"))
            continue
        records.append((path, parsed))
    return records


def _validate_summary(
    summary_dir: Path | None,
    expected_warmup: int,
    expected_measured: int,
    issues: list[E8CostAuditIssue],
    details: dict[str, Any],
) -> None:
    if summary_dir is None:
        details["summary_validation"] = "skipped"
        return
    summary_path = summary_dir / SUMMARY_SUBDIR / "summary.json"
    cost_path = summary_dir / SUMMARY_SUBDIR / "artifact_cost_analysis.csv"
    if not summary_path.exists():
        issues.append(E8CostAuditIssue(str(summary_path), "missing E8-COST summary.json"))
        return
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        issues.append(E8CostAuditIssue(str(summary_path), f"invalid summary JSON: {exc}"))
        return

    protocol = summary.get("measurement_protocol", {})
    artifact_summary = summary.get("artifact_cost_analysis", {})
    mode_counts = summary.get("mode_counts", {})
    details["summary"] = {
        "record_count": summary.get("record_count"),
        "mode_counts": mode_counts,
        "measurement_protocol": protocol,
        "artifact_cost_analysis": {
            key: artifact_summary.get(key)
            for key in (
                "artifact_cost_cell_count",
                "scenario_count",
                "measured_record_count",
                "admission_first_wrong_results",
                "diagnostic_wrong_results",
                "admission_first_choice_reasons",
                "admission_first_templates",
            )
        },
    }
    if summary.get("input_dir") != "results/raw/E8_COST_1E6":
        issues.append(E8CostAuditIssue(str(summary_path), "summary input_dir is not E8_COST_1E6"))
    if _maybe_int(summary.get("record_count")) != EXPECTED_RAW_RECORD_COUNT:
        issues.append(E8CostAuditIssue(str(summary_path), "E8-COST raw record count changed"))
    if isinstance(mode_counts, Mapping):
        canonical_mode_counts: dict[str, int | None] = {}
        for raw_mode, raw_count in mode_counts.items():
            try:
                mode = normalize_mode_id(str(raw_mode))
            except ValueError:
                issues.append(
                    E8CostAuditIssue(
                        str(summary_path),
                        f"E8-COST summary has unknown mode {raw_mode!r}",
                    )
                )
                continue
            if mode in canonical_mode_counts:
                issues.append(
                    E8CostAuditIssue(
                        str(summary_path),
                        f"E8-COST summary contains duplicate aliases for {mode}",
                    )
                )
                continue
            canonical_mode_counts[mode] = _maybe_int(raw_count)
        details["summary"]["canonical_mode_counts"] = canonical_mode_counts
        for mode, expected in EXPECTED_MODE_COUNTS.items():
            if canonical_mode_counts.get(mode) != expected:
                issues.append(E8CostAuditIssue(str(summary_path), f"E8-COST mode count for {mode} changed"))
    if isinstance(protocol, Mapping):
        if protocol.get("status") != "ok":
            issues.append(E8CostAuditIssue(str(summary_path), "E8-COST protocol status is not ok"))
        if _maybe_int(protocol.get("cell_count")) != EXPECTED_CELL_COUNT:
            issues.append(E8CostAuditIssue(str(summary_path), "E8-COST protocol cell_count changed"))
        if _maybe_int(protocol.get("cells_meeting_required_repetitions")) != EXPECTED_CELL_COUNT:
            issues.append(E8CostAuditIssue(str(summary_path), "not all E8-COST cells meet repetitions"))
        if _maybe_int(protocol.get("required_warmup_repetitions")) != expected_warmup:
            issues.append(E8CostAuditIssue(str(summary_path), "E8-COST warmup repetition count changed"))
        if _maybe_int(protocol.get("required_measured_repetitions")) != expected_measured:
            issues.append(E8CostAuditIssue(str(summary_path), "E8-COST measured repetition count changed"))
    if isinstance(artifact_summary, Mapping):
        if _maybe_int(artifact_summary.get("artifact_cost_cell_count")) != EXPECTED_CELL_COUNT:
            issues.append(E8CostAuditIssue(str(summary_path), "artifact cost cell count changed"))
        if _maybe_int(artifact_summary.get("scenario_count")) != EXPECTED_SCENARIO_COUNT:
            issues.append(E8CostAuditIssue(str(summary_path), "artifact cost scenario count changed"))
        if _maybe_int(artifact_summary.get("measured_record_count")) != EXPECTED_MEASURED_RECORD_COUNT:
            issues.append(E8CostAuditIssue(str(summary_path), "artifact cost measured record count changed"))
        if _maybe_int(artifact_summary.get("admission_first_wrong_results")) != 0:
            issues.append(E8CostAuditIssue(str(summary_path), "AdmissionFirst has wrong results in E8-COST"))
        if (_maybe_int(artifact_summary.get("diagnostic_wrong_results")) or 0) <= 0:
            issues.append(E8CostAuditIssue(str(summary_path), "E8-COST lacks diagnostic wrong-result controls"))
        reasons = artifact_summary.get("admission_first_choice_reasons", {})
        if isinstance(reasons, Mapping):
            for reason in (
                "declared_Q_U_cost_ranked_artifact",
                "declared_Q_U_cost_ranked_barrier",
                "metadata_stale_fallback",
            ):
                if (_maybe_int(reasons.get(reason)) or 0) <= 0:
                    issues.append(E8CostAuditIssue(str(summary_path), f"missing AdmissionFirst choice reason {reason}"))
    if not cost_path.exists():
        issues.append(E8CostAuditIssue(str(cost_path), "missing artifact_cost_analysis.csv"))


def _validate_cost_csv(
    summary_dir: Path | None,
    expected_measured: int,
    issues: list[E8CostAuditIssue],
    details: dict[str, Any],
) -> None:
    if summary_dir is None:
        return
    cost_path = summary_dir / SUMMARY_SUBDIR / "artifact_cost_analysis.csv"
    if not cost_path.exists():
        return
    rows = _read_csv(cost_path)
    if len(rows) != EXPECTED_CELL_COUNT:
        issues.append(E8CostAuditIssue(str(cost_path), "artifact cost row count changed"))
    fieldnames = set(rows[0].keys()) if rows else set()
    for field in REQUIRED_COST_COLUMNS:
        if field not in fieldnames:
            issues.append(E8CostAuditIssue(str(cost_path), f"missing artifact cost column {field}"))

    families = Counter()
    modes = Counter()
    wrong_by_family = Counter()
    contract_rows = []
    contract_reason_cells: Counter[str] = Counter()
    for row in rows:
        query_id = str(row.get("query_id", ""))
        mode = normalize_mode_id(str(row.get("mode", "")))
        family = _query_family(query_id)
        if family is None:
            issues.append(E8CostAuditIssue(str(cost_path), f"unexpected E8-COST query_id {query_id}"))
        else:
            families[family] += 1
        modes[mode] += 1
        sample_count = _maybe_int(row.get("sample_count"))
        if sample_count != expected_measured:
            issues.append(E8CostAuditIssue(str(cost_path), "artifact cost row does not use measured repetitions"))
        for field in (
            "query_only_ms_median",
            "build_ms_median",
            "refresh_ms_median",
            "maintenance_ms_total_median",
            "fallback_ms_median",
            "storage_bytes_median",
            "amortized_build_plus_single_query_ms_median",
            "amortized_q100_u1pct_ms_median",
            "amortized_declared_q_u_ms_median",
        ):
            value = _maybe_float(row.get(field))
            if value is None or value < 0:
                issues.append(E8CostAuditIssue(str(cost_path), f"row lacks nonnegative {field}"))
        wrong_count = _maybe_int(row.get("wrong_result_count")) or 0
        if family is not None:
            wrong_by_family[family] += wrong_count
        if mode == ADMISSION_FIRST_MODE:
            contract_rows.append(row)
            for reason in _json_counter_keys(row.get("choice_reason_counts")):
                contract_reason_cells[reason] += 1
            if wrong_count != 0:
                issues.append(E8CostAuditIssue(str(cost_path), "AdmissionFirst cost row has wrong results"))

    for family in EXPECTED_PREFIXES.values():
        if families[family] != 16 * len(REQUIRED_MODES):
            issues.append(E8CostAuditIssue(str(cost_path), f"missing rows for {family} sweep"))
    for mode in REQUIRED_MODES:
        if modes[mode] != EXPECTED_SCENARIO_COUNT:
            issues.append(E8CostAuditIssue(str(cost_path), f"missing mode {mode} cost rows"))
    if wrong_by_family["STALE-FALLBACK"] <= 0:
        issues.append(E8CostAuditIssue(str(cost_path), "STALE-FALLBACK lacks diagnostic wrong-result rows"))

    action_counts = Counter(row.get("dominant_action", "") for row in contract_rows)
    template_counts = Counter(row.get("dominant_template_id", "") for row in contract_rows)
    details["artifact_cost_csv"] = {
        "row_count": len(rows),
        "families": dict(sorted(families.items())),
        "modes": dict(sorted(modes.items())),
        "admission_first_actions": dict(sorted(action_counts.items())),
        "admission_first_templates": dict(sorted(template_counts.items())),
        "admission_first_choice_reason_cells": dict(sorted(contract_reason_cells.items())),
        "admission_first_cell_count": len(contract_rows),
        "admission_first_wrong_results": sum(
            _maybe_int(row.get("wrong_result_count")) or 0
            for row in contract_rows
        ),
        "wrong_results_by_family": dict(sorted(wrong_by_family.items())),
    }
    if action_counts.get("fallback", 0) <= 0:
        issues.append(E8CostAuditIssue(str(cost_path), "AdmissionFirst never reports fallback"))
    if template_counts.get("barrier_filter_v1", 0) <= 0:
        issues.append(E8CostAuditIssue(str(cost_path), "AdmissionFirst never chooses barrier in E8-COST"))
    if template_counts.get("mav_scan_v1", 0) <= 0:
        issues.append(E8CostAuditIssue(str(cost_path), "AdmissionFirst never chooses MAV in E8-COST"))


def _validate_raw_records(
    raw_dir: Path,
    expected_warmup: int,
    expected_measured: int,
    issues: list[E8CostAuditIssue],
    details: dict[str, Any],
) -> None:
    loaded = _load_records(raw_dir, issues)
    if len(loaded) != EXPECTED_RAW_RECORD_COUNT:
        issues.append(E8CostAuditIssue(str(raw_dir / SUMMARY_SUBDIR), "E8-COST raw file count changed"))

    phase_counts: Counter[str] = Counter()
    family_q_u: defaultdict[str, set[tuple[int, float]]] = defaultdict(set)
    contract_choice_reasons: Counter[str] = Counter()
    contract_templates: Counter[str] = Counter()
    contract_actions: Counter[str] = Counter()
    contract_cost_delta: list[float] = []
    diagnostic_wrong: Counter[str] = Counter()
    stale_contract_fallbacks = 0
    stale_diagnostic_wrong = 0
    checked_artifact_cost_payloads = 0
    declared_qu_mismatches = 0
    missing_validation_ms_payloads = 0

    for path, record in loaded:
        if record.get("manifest_id") not in MANIFEST_IDS:
            issues.append(E8CostAuditIssue(str(path), "record manifest_id is not a sealed E8-COST identity"))
        if record.get("stage") != EXPECTED_STAGE:
            issues.append(E8CostAuditIssue(str(path), "record stage is not artifact_cost_update_rate"))
        dataset = record.get("dataset", {})
        if isinstance(dataset, Mapping):
            for key, expected in EXPECTED_DATASET.items():
                if dataset.get(key) != expected:
                    issues.append(E8CostAuditIssue(str(path), f"record dataset {key} is not {expected}"))
        else:
            issues.append(E8CostAuditIssue(str(path), "record lacks dataset object"))
        query_id = str(_get(record, "query.query_id"))
        family = _query_family(query_id)
        if family is None:
            issues.append(E8CostAuditIssue(str(path), f"unexpected query_id {query_id}"))
        params = _get(record, "query.params", {})
        q_value = _maybe_int(_get(record, "artifact_cost.Q"))
        u_value = _maybe_float(_get(record, "artifact_cost.U"))
        if q_value not in EXPECTED_Q_VALUES:
            issues.append(E8CostAuditIssue(str(path), "record has unexpected amortization Q"))
        if u_value not in EXPECTED_U_VALUES:
            issues.append(E8CostAuditIssue(str(path), "record has unexpected update rate U"))
        if family is not None and q_value is not None and u_value is not None:
            family_q_u[family].add((q_value, u_value))
        if isinstance(params, Mapping) and q_value != _maybe_int(params.get("amortization_q")):
            issues.append(E8CostAuditIssue(str(path), "artifact_cost.Q does not match query params"))
        artifact_cost = record.get("artifact_cost")
        if isinstance(artifact_cost, Mapping) and q_value is not None:
            checked_artifact_cost_payloads += 1
            query_only_ms = _maybe_float(artifact_cost.get("query_only_ms"))
            build_ms = _maybe_float(artifact_cost.get("build_ms"))
            maintenance_ms_total = _maybe_float(artifact_cost.get("maintenance_ms_total"))
            fallback_ms = _maybe_float(artifact_cost.get("fallback_ms"))
            validation_ms = _maybe_float(artifact_cost.get("validation_ms"))
            amortized = artifact_cost.get("amortized_latency_ms")
            declared_qu = _maybe_float(_get(artifact_cost, "amortized_latency_ms.declared_Q_U"))
            query_only_model = _maybe_float(_get(artifact_cost, "amortized_latency_ms.query_only"))
            if not isinstance(amortized, Mapping):
                declared_qu_mismatches += 1
                issues.append(E8CostAuditIssue(str(path), "artifact_cost lacks amortized_latency_ms payload"))
            elif not _close(query_only_model, query_only_ms):
                declared_qu_mismatches += 1
                issues.append(E8CostAuditIssue(str(path), "artifact cost query_only model changed"))
            if validation_ms is None:
                missing_validation_ms_payloads += 1
                issues.append(E8CostAuditIssue(str(path), "artifact_cost lacks validation_ms payload"))
            if None in (query_only_ms, build_ms, maintenance_ms_total, fallback_ms, declared_qu):
                declared_qu_mismatches += 1
                issues.append(E8CostAuditIssue(str(path), "artifact_cost lacks declared Q/U accounting inputs"))
            else:
                expected_declared = amortized_artifact_latency_ms(
                    ArtifactEconomics(
                        query_ms=query_only_ms or 0.0,
                        build_ms=build_ms or 0.0,
                        maintenance_ms_total=maintenance_ms_total or 0.0,
                        fallback_ms=fallback_ms or 0.0,
                        reuse=q_value,
                    )
                )
                if not _close(declared_qu, expected_declared):
                    declared_qu_mismatches += 1
                    issues.append(
                        E8CostAuditIssue(
                            str(path),
                            "artifact_cost declared_Q_U no longer matches query/build/maintenance/fallback accounting",
                        )
                    )
        phase = str(_get(record, "measurement.phase", "measured"))
        phase_counts[phase] += 1

        mode = normalize_mode_id(str(record.get("mode", "")))
        status = str(record.get("status", ""))
        action = str(_get(record, "artifact_validation.action"))
        template_id = str(_get(record, "template.template_id"))
        if mode == ADMISSION_FIRST_MODE:
            contract_actions[action] += 1
            contract_templates[template_id] += 1
            reason = str(_get(record, "planner.choice_reason"))
            contract_choice_reasons[reason] += 1
            if status == "wrong_result" or _truth(_get(record, "oracle_check.known_invalid_accepted")):
                issues.append(E8CostAuditIssue(str(path), "AdmissionFirst accepted a wrong or known-invalid result"))
            if query_id.startswith("E8cost_stale_fallback"):
                if action == "fallback" and template_id == "barrier_filter_v1":
                    stale_contract_fallbacks += 1
                else:
                    issues.append(E8CostAuditIssue(str(path), "STALE-FALLBACK AdmissionFirst did not fallback to barrier"))
            candidates = _get(record, "planner.candidates", [])
            if reason in {"declared_Q_U_cost_ranked_artifact", "declared_Q_U_cost_ranked_barrier"}:
                if not isinstance(candidates, Sequence) or isinstance(candidates, (str, bytes)) or len(candidates) < 2:
                    issues.append(E8CostAuditIssue(str(path), "cost-ranked AdmissionFirst row lacks candidate cost waterfall"))
                else:
                    accepted = [
                        item
                        for item in candidates
                        if isinstance(item, Mapping) and item.get("accepted") and _maybe_float(item.get("estimated_cost")) is not None
                    ]
                    if len(accepted) < 2:
                        issues.append(E8CostAuditIssue(str(path), "candidate cost waterfall lacks two accepted alternatives"))
                    else:
                        costs = [float(item["estimated_cost"]) for item in accepted]
                        chosen = _maybe_float(_get(record, "planner.chosen_estimated_cost"))
                        if chosen is None:
                            issues.append(E8CostAuditIssue(str(path), "missing chosen estimated cost"))
                        else:
                            best = min(costs)
                            contract_cost_delta.append(chosen - best)
                            if abs(chosen - best) > 1e-6:
                                issues.append(E8CostAuditIssue(str(path), "AdmissionFirst did not choose minimum declared Q/U cost"))
                        metrics = {str(item.get("cost_metric")) for item in accepted}
                        if metrics != {"declared_Q_U_amortized_ms"}:
                            issues.append(E8CostAuditIssue(str(path), "candidate costs are not declared Q/U amortized costs"))
            if reason == "metadata_stale_fallback":
                if str(_get(record, "artifact_validation.failure_sqlstate")) != "P8A01":
                    issues.append(E8CostAuditIssue(str(path), "stale fallback lacks P8A01 SQLSTATE"))
                if str(_get(record, "artifact_validation.failure_symbol")) != "CAPRLS_ARTIFACT_STALE":
                    issues.append(E8CostAuditIssue(str(path), "stale fallback lacks CAPRLS_ARTIFACT_STALE symbol"))
        elif status == "wrong_result":
            diagnostic_wrong[mode] += 1
            if query_id.startswith("E8cost_stale_fallback"):
                stale_diagnostic_wrong += 1

    expected_measured_records = EXPECTED_CELL_COUNT * expected_measured
    expected_warmup_records = EXPECTED_CELL_COUNT * expected_warmup
    if phase_counts.get("measured", 0) != expected_measured_records:
        issues.append(E8CostAuditIssue(str(raw_dir / SUMMARY_SUBDIR), "measured raw record count changed"))
    if phase_counts.get("warmup", 0) != expected_warmup_records:
        issues.append(E8CostAuditIssue(str(raw_dir / SUMMARY_SUBDIR), "warmup raw record count changed"))
    expected_qu = {(q, u) for q in EXPECTED_Q_VALUES for u in EXPECTED_U_VALUES}
    for family in EXPECTED_PREFIXES.values():
        if family_q_u[family] != expected_qu:
            issues.append(E8CostAuditIssue(str(raw_dir / SUMMARY_SUBDIR), f"{family} does not cover all Q/U cells"))
    if contract_choice_reasons.get("declared_Q_U_cost_ranked_barrier", 0) <= 0:
        issues.append(E8CostAuditIssue(str(raw_dir / SUMMARY_SUBDIR), "no cost-ranked barrier choices"))
    if contract_choice_reasons.get("declared_Q_U_cost_ranked_artifact", 0) <= 0:
        issues.append(E8CostAuditIssue(str(raw_dir / SUMMARY_SUBDIR), "no cost-ranked artifact choices"))
    if contract_choice_reasons.get("metadata_stale_fallback", 0) <= 0:
        issues.append(E8CostAuditIssue(str(raw_dir / SUMMARY_SUBDIR), "no metadata-stale fallback choices"))
    if stale_contract_fallbacks <= 0 or stale_diagnostic_wrong <= 0:
        issues.append(E8CostAuditIssue(str(raw_dir / SUMMARY_SUBDIR), "STALE-FALLBACK contrast is missing"))

    details["raw"] = {
        "record_count": len(loaded),
        "phase_counts": dict(sorted(phase_counts.items())),
        "families_q_u_count": {key: len(value) for key, value in sorted(family_q_u.items())},
        "admission_first_choice_reasons": dict(sorted(contract_choice_reasons.items())),
        "admission_first_templates": dict(sorted(contract_templates.items())),
        "admission_first_actions": dict(sorted(contract_actions.items())),
        "diagnostic_wrong_results": dict(sorted(diagnostic_wrong.items())),
        "stale_contract_fallbacks": stale_contract_fallbacks,
        "stale_diagnostic_wrong_results": stale_diagnostic_wrong,
        "checked_artifact_cost_payloads": checked_artifact_cost_payloads,
        "declared_qu_payload_mismatches": declared_qu_mismatches,
        "missing_validation_ms_payloads": missing_validation_ms_payloads,
        "max_cost_choice_delta": max((abs(value) for value in contract_cost_delta), default=0.0),
        "median_cost_choice_delta": statistics.median(
            [abs(value) for value in contract_cost_delta]
        )
        if contract_cost_delta
        else 0.0,
    }


# BEGIN PHASE_B2A_E8COST_AUDIT_VALIDATOR
def _b2a_int(value: Any) -> int | None:
    """Parse an exact nonnegative integer from JSON or a CSV scalar."""

    if value.__class__ is int:
        return value if value >= 0 else None
    if value.__class__ is str and value.isascii() and value.isdecimal():
        if value != "0" and value.startswith("0"):
            return None
        return int(value)
    return None


def _b2a_query_identity(query_id: str) -> tuple[str, int, float] | None:
    match = E8COST_QUERY_ID_RE.fullmatch(query_id)
    if match is None:
        return None
    family = {
        "mav_dash": "MAV-DASH",
        "authidx_sparse": "AUTHIDX-SPARSE",
        "stale_fallback": "STALE-FALLBACK",
    }[match.group(1)]
    update_rate = {
        "0": 0.0,
        "0_1": 0.001,
        "1": 0.01,
        "10": 0.1,
    }[match.group(3)]
    return family, int(match.group(2)), update_rate


def _counter_mapping(value: Any) -> dict[str, int]:
    if isinstance(value, Mapping):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
    else:
        return {}
    if not isinstance(parsed, Mapping):
        return {}
    output: dict[str, int] = {}
    for key, raw_count in parsed.items():
        count = _b2a_int(raw_count)
        if count is None or count < 0:
            return {}
        output[str(key)] = count
    return output


def _projection_invalid_gate_admission(record: Mapping[str, Any]) -> bool:
    accounting = _get(record, "artifact_cost.accounting_probe", {})
    if not isinstance(accounting, Mapping):
        return True
    validation = accounting.get("case_validation_observation")
    alternatives = accounting.get("accounting_alternatives")
    if not isinstance(validation, Mapping) or not isinstance(alternatives, list):
        return True
    return validation.get("status") != "pass" and any(
        isinstance(alternative, Mapping)
        and alternative.get("projected_action") == "execute"
        for alternative in alternatives
    )


def _validate_b2a_raw(
    raw_dir: Path,
    expected_warmup: int,
    expected_measured: int,
    issues: list[E8CostAuditIssue],
    details: dict[str, Any],
) -> None:
    loaded = _load_records(raw_dir, issues)
    base_path = raw_dir / SUMMARY_SUBDIR
    if len(loaded) != EXPECTED_RAW_RECORD_COUNT:
        issues.append(
            E8CostAuditIssue(str(base_path), "E8-COST raw file count changed")
        )

    class_raw: Counter[str] = Counter()
    class_measured: Counter[str] = Counter()
    class_warmup: Counter[str] = Counter()
    class_cells: defaultdict[str, set[tuple[str, str]]] = defaultdict(set)
    phases: Counter[str] = Counter()
    modes: Counter[str] = Counter()
    cell_repetitions: defaultdict[
        tuple[str, str], Counter[tuple[str, int]]
    ] = defaultdict(Counter)
    family_q_u: defaultdict[str, set[tuple[int, float]]] = defaultdict(set)
    projected_action_measured: Counter[str] = Counter()
    projected_action_cells: Counter[str] = Counter()
    projected_template_measured: Counter[str] = Counter()
    projected_template_cells: Counter[str] = Counter()
    projection_cell_actions: defaultdict[tuple[str, str], set[str]] = defaultdict(
        set
    )
    projection_cell_templates: defaultdict[
        tuple[str, str], set[str]
    ] = defaultdict(set)
    executed_pass = 0
    executed_wrong = 0
    invalid_gate_admissions = 0
    measured_invalid_gate_admissions = 0
    declared_qu_mismatches = 0
    classification_violations = 0
    stale_wrong_by_mode: Counter[str] = Counter()
    manifest_hashes: set[str] = set()
    statuses: Counter[str] = Counter()

    for path, record in loaded:
        if record.get("manifest_id") not in MANIFEST_IDS:
            issues.append(
                E8CostAuditIssue(str(path), "record manifest_id changed")
            )
        if record.get("experiment") != "E8" or record.get("stage") != EXPECTED_STAGE:
            issues.append(
                E8CostAuditIssue(str(path), "record is not exact E8-COST")
            )
        if record.get("run_kind") != "normal_mode":
            issues.append(
                E8CostAuditIssue(str(path), "record run_kind is not normal_mode")
            )
        dataset = record.get("dataset")
        if dataset != EXPECTED_DATASET:
            issues.append(E8CostAuditIssue(str(path), "record dataset changed"))
        manifest_hash = record.get("manifest_hash")
        if (
            manifest_hash.__class__ is not str
            or re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_hash) is None
        ):
            issues.append(
                E8CostAuditIssue(str(path), "record manifest_hash is not exact")
            )
        else:
            manifest_hashes.add(manifest_hash)
        try:
            evidence_class = classify_e8_cost_evidence(record)
        except E8CostEvidenceClassificationError as exc:
            classification_violations += 1
            issues.append(
                E8CostAuditIssue(
                    str(path),
                    f"ambiguous E8-COST evidence classification: {exc}",
                )
            )
            continue
        if evidence_class not in E8COST_EVIDENCE_CLASSES:
            classification_violations += 1
            issues.append(
                E8CostAuditIssue(str(path), "record lacks E8-COST evidence class")
            )
            continue

        query_id = str(_get(record, "query.query_id"))
        mode = normalize_mode_id(str(record.get("mode", "")))
        query_identity = _b2a_query_identity(query_id)
        family = query_identity[0] if query_identity is not None else None
        phase = str(_get(record, "measurement.phase"))
        iteration = _b2a_int(_get(record, "measurement.iteration"))
        warmup = _b2a_int(_get(record, "measurement.warmup_repetitions"))
        measured = _b2a_int(_get(record, "measurement.measured_repetitions"))
        if family is None:
            issues.append(
                E8CostAuditIssue(str(path), f"unexpected query_id {query_id}")
            )
            continue
        if mode not in REQUIRED_MODES:
            issues.append(E8CostAuditIssue(str(path), f"unexpected mode {mode}"))
        if warmup != expected_warmup or measured != expected_measured:
            issues.append(
                E8CostAuditIssue(str(path), "record repetition protocol changed")
            )
        phase_limit = {
            "warmup": expected_warmup,
            "measured": expected_measured,
        }.get(phase)
        if iteration is None or phase_limit is None or not 1 <= iteration <= phase_limit:
            issues.append(
                E8CostAuditIssue(str(path), "record repetition identity changed")
            )
            continue
        cell = (query_id, mode)
        cell_repetitions[cell][(phase, iteration)] += 1
        phases[phase] += 1
        modes[mode] += 1
        class_raw[evidence_class] += 1
        statuses[str(record.get("status"))] += 1
        class_cells[evidence_class].add(cell)
        if phase == "measured":
            class_measured[evidence_class] += 1
        else:
            class_warmup[evidence_class] += 1

        expected_class = (
            E8COST_ACCOUNTING_PROJECTION
            if mode == ADMISSION_FIRST_MODE
            else (
                E8COST_GATE_REJECT
                if family == "STALE-FALLBACK"
                and mode in {"auth-index-enum-only", "mav-only"}
                else E8COST_RESULT_EXECUTION
            )
        )
        if evidence_class != expected_class:
            issues.append(
                E8CostAuditIssue(
                    str(path), "record evidence class does not match exact cell"
                )
            )
        expected_status = {
            E8COST_ACCOUNTING_PROJECTION: "not_executed",
            E8COST_GATE_REJECT: "expected_reject",
        }.get(expected_class)
        if expected_status is None:
            expected_status = (
                "wrong_result"
                if family == "STALE-FALLBACK"
                and mode in {"naive-artifact-only", "stale-artifact-user"}
                else "pass"
            )
        if record.get("status") != expected_status:
            issues.append(
                E8CostAuditIssue(
                    str(path), "record status does not match exact cell"
                )
            )

        if evidence_class == E8COST_ACCOUNTING_PROJECTION:
            declared = _get(
                record,
                "artifact_cost.accounting_probe.declared_inputs",
                {},
            )
            if not isinstance(declared, Mapping):
                issues.append(
                    E8CostAuditIssue(str(path), "projection declared inputs missing")
                )
                continue
            q_value = _b2a_int(declared.get("Q"))
            u_value = _maybe_float(declared.get("U"))
            if declared.get("family") != family:
                issues.append(
                    E8CostAuditIssue(str(path), "projection family identity changed")
                )
            expected_action = (
                "fallback" if family == "STALE-FALLBACK" else "execute"
            )
            expected_artifact_status = (
                "stale" if family == "STALE-FALLBACK" else "pass"
            )
            if (
                declared.get("contract_action") != expected_action
                or declared.get("artifact_status") != expected_artifact_status
            ):
                issues.append(
                    E8CostAuditIssue(
                        str(path), "projection declared gate identity changed"
                    )
                )
            invalid = _projection_invalid_gate_admission(record)
            invalid_gate_admissions += int(invalid)
            measured_invalid_gate_admissions += int(
                invalid and phase == "measured"
            )
            minimum = _get(
                record,
                "artifact_cost.accounting_probe.observed_accounting_minimum",
                {},
            )
            if not isinstance(minimum, Mapping):
                issues.append(
                    E8CostAuditIssue(str(path), "projection minimum is missing")
                )
                continue
            action = str(minimum.get("projected_action") or "")
            template = str(minimum.get("projected_template_id") or "")
            expected_template = {
                "MAV-DASH": "mav_scan_v1",
                "AUTHIDX-SPARSE": "auth_index_enum_v1",
                "STALE-FALLBACK": "barrier_filter_v1",
            }[family]
            if action != expected_action or template != expected_template:
                issues.append(
                    E8CostAuditIssue(
                        str(path), "projection minimum identity changed"
                    )
                )
            if phase == "measured":
                projected_action_measured[action] += 1
                projected_template_measured[template] += 1
                projection_cell_actions[cell].add(action)
                projection_cell_templates[cell].add(template)
        else:
            q_value = _b2a_int(_get(record, "artifact_cost.Q"))
            u_value = _maybe_float(_get(record, "artifact_cost.U"))
            params = _get(record, "query.params", {})
            if not isinstance(params, Mapping):
                issues.append(
                    E8CostAuditIssue(str(path), "query params are missing")
                )
            else:
                if q_value != _b2a_int(params.get("amortization_q")):
                    issues.append(
                        E8CostAuditIssue(
                            str(path), "artifact Q does not match query params"
                        )
                    )
                if not _close(u_value, _maybe_float(params.get("update_rate_per_hour"))):
                    issues.append(
                        E8CostAuditIssue(
                            str(path), "artifact U does not match query params"
                        )
                    )
            artifact_cost = record.get("artifact_cost")
            if isinstance(artifact_cost, Mapping) and q_value is not None:
                query_ms = _maybe_float(artifact_cost.get("query_only_ms"))
                build_ms = _maybe_float(artifact_cost.get("build_ms"))
                maintenance_ms = _maybe_float(
                    artifact_cost.get("maintenance_ms_total")
                )
                fallback_ms = _maybe_float(artifact_cost.get("fallback_ms"))
                declared_qu = _maybe_float(
                    _get(
                        artifact_cost,
                        "amortized_latency_ms.declared_Q_U",
                        None,
                    )
                )
                if None in (
                    query_ms,
                    build_ms,
                    maintenance_ms,
                    fallback_ms,
                    declared_qu,
                ):
                    declared_qu_mismatches += 1
                    issues.append(
                        E8CostAuditIssue(
                            str(path), "nonprojection Q/U accounting is incomplete"
                        )
                    )
                else:
                    expected = amortized_artifact_latency_ms(
                        ArtifactEconomics(
                            query_ms=float(query_ms),
                            build_ms=float(build_ms),
                            maintenance_ms_total=float(maintenance_ms),
                            fallback_ms=float(fallback_ms),
                            reuse=q_value,
                        )
                    )
                    if not _close(declared_qu, expected):
                        declared_qu_mismatches += 1
                        issues.append(
                            E8CostAuditIssue(
                                str(path),
                                "declared Q/U accounting formula changed",
                            )
                        )
        expected_q = query_identity[1]
        expected_u = query_identity[2]
        if (
            q_value not in EXPECTED_Q_VALUES
            or u_value not in EXPECTED_U_VALUES
            or q_value != expected_q
            or not _close(u_value, expected_u)
        ):
            issues.append(E8CostAuditIssue(str(path), "record Q/U identity changed"))
        elif family is not None:
            family_q_u[family].add((q_value, u_value))

        if evidence_class == E8COST_RESULT_EXECUTION and phase == "measured":
            if record.get("status") == "pass":
                executed_pass += 1
            elif record.get("status") == "wrong_result":
                executed_wrong += 1
                stale_wrong_by_mode[mode] += 1

    for actions in projection_cell_actions.values():
        projected_action_cells.update(actions)
    for templates in projection_cell_templates.values():
        projected_template_cells.update(templates)
    expected_repetitions = {
        *(('warmup', index) for index in range(1, expected_warmup + 1)),
        *(('measured', index) for index in range(1, expected_measured + 1)),
    }
    if len(cell_repetitions) != EXPECTED_CELL_COUNT:
        issues.append(E8CostAuditIssue(str(base_path), "raw cell count changed"))
    for cell, repetitions in cell_repetitions.items():
        if set(repetitions) != expected_repetitions or any(
            count != 1 for count in repetitions.values()
        ):
            issues.append(
                E8CostAuditIssue(
                    str(base_path),
                    f"cell {cell[0]}/{cell[1]} repetition inventory changed",
                )
            )
    expected_qu = {(q, u) for q in EXPECTED_Q_VALUES for u in EXPECTED_U_VALUES}
    for family in EXPECTED_PREFIXES.values():
        if family_q_u[family] != expected_qu:
            issues.append(
                E8CostAuditIssue(
                    str(base_path), f"{family} Q/U coverage changed"
                )
            )
    for mode, count in EXPECTED_MODE_COUNTS.items():
        if modes[mode] != count:
            issues.append(
                E8CostAuditIssue(str(base_path), f"raw mode count changed for {mode}")
            )
    if phases != Counter({"measured": 3840, "warmup": 1920}):
        issues.append(E8CostAuditIssue(str(base_path), "raw phase counts changed"))
    if statuses != Counter(EXPECTED_RAW_STATUS_COUNTS):
        issues.append(E8CostAuditIssue(str(base_path), "raw status counts changed"))
    if len(manifest_hashes) != 1:
        issues.append(
            E8CostAuditIssue(str(base_path), "raw manifest hash identity changed")
        )
    for label, actual, expected in (
        ("raw", class_raw, EXPECTED_CLASS_RAW_RECORD_COUNTS),
        ("measured", class_measured, EXPECTED_CLASS_MEASURED_RECORD_COUNTS),
        ("warmup", class_warmup, EXPECTED_CLASS_WARMUP_RECORD_COUNTS),
    ):
        if {key: actual.get(key, 0) for key in E8COST_EVIDENCE_CLASSES} != expected:
            issues.append(
                E8CostAuditIssue(str(base_path), f"{label} evidence populations changed")
            )
    observed_class_cells = {
        key: len(class_cells[key]) for key in E8COST_EVIDENCE_CLASSES
    }
    if observed_class_cells != EXPECTED_CLASS_CELL_COUNTS:
        issues.append(E8CostAuditIssue(str(base_path), "evidence class cells changed"))
    if projected_action_cells != Counter(EXPECTED_PROJECTED_ACTION_CELL_COUNTS):
        issues.append(
            E8CostAuditIssue(str(base_path), "projected action cell counts changed")
        )
    if projected_action_measured != Counter(
        EXPECTED_PROJECTED_ACTION_MEASURED_RECORD_COUNTS
    ):
        issues.append(
            E8CostAuditIssue(
                str(base_path), "projected measured action counts changed"
            )
        )
    if projected_template_cells != Counter(
        EXPECTED_PROJECTED_TEMPLATE_CELL_COUNTS
    ):
        issues.append(
            E8CostAuditIssue(str(base_path), "projected template cell counts changed")
        )
    if projected_template_measured != Counter(
        EXPECTED_PROJECTED_TEMPLATE_MEASURED_RECORD_COUNTS
    ):
        issues.append(
            E8CostAuditIssue(
                str(base_path), "projected measured template counts changed"
            )
        )
    if invalid_gate_admissions != 0:
        issues.append(
            E8CostAuditIssue(str(base_path), "invalid gate admission count is not zero")
        )
    if (executed_pass, executed_wrong) != (
        EXPECTED_EXECUTED_PASS_COUNT,
        EXPECTED_EXECUTED_WRONG_COUNT,
    ):
        issues.append(
            E8CostAuditIssue(str(base_path), "executed result basis changed")
        )
    if stale_wrong_by_mode != Counter(EXPECTED_MEASURED_WRONG_BY_MODE):
        issues.append(
            E8CostAuditIssue(str(base_path), "wrong-result mode basis changed")
        )

    details["raw"] = {
        "record_count": len(loaded),
        "phase_counts": dict(sorted(phases.items())),
        "mode_counts": dict(sorted(modes.items())),
        "evidence_class_raw_record_counts": {
            key: class_raw.get(key, 0) for key in E8COST_EVIDENCE_CLASSES
        },
        "evidence_class_measured_record_counts": {
            key: class_measured.get(key, 0) for key in E8COST_EVIDENCE_CLASSES
        },
        "evidence_class_warmup_record_counts": {
            key: class_warmup.get(key, 0) for key in E8COST_EVIDENCE_CLASSES
        },
        "evidence_class_cell_counts": observed_class_cells,
        "projected_action_accounting_cell_counts": dict(
            sorted(projected_action_cells.items())
        ),
        "projected_action_accounting_measured_record_counts": dict(
            sorted(projected_action_measured.items())
        ),
        "projected_template_accounting_measured_record_counts": dict(
            sorted(projected_template_measured.items())
        ),
        "projected_template_accounting_cell_counts": dict(
            sorted(projected_template_cells.items())
        ),
        "invalid_gate_admission_count": invalid_gate_admissions,
        "measured_invalid_gate_admission_count": measured_invalid_gate_admissions,
        "executed_pass_count": executed_pass,
        "executed_wrong_result_count": executed_wrong,
        "executed_result_denominator": executed_pass + executed_wrong,
        "executed_wrong_result_rate": (
            executed_wrong / (executed_pass + executed_wrong)
            if executed_pass + executed_wrong
            else None
        ),
        "stale_wrong_results_by_mode": dict(sorted(stale_wrong_by_mode.items())),
        "declared_qu_payload_mismatches": declared_qu_mismatches,
        "classification_violation_count": classification_violations,
    }


def _validate_b2a_cost_csv(
    summary_dir: Path | None,
    expected_warmup: int,
    expected_measured: int,
    issues: list[E8CostAuditIssue],
    details: dict[str, Any],
) -> None:
    if summary_dir is None:
        details["artifact_cost_csv_validation"] = "skipped"
        return
    path = summary_dir / SUMMARY_SUBDIR / "artifact_cost_analysis.csv"
    if not path.exists():
        issues.append(E8CostAuditIssue(str(path), "missing artifact cost CSV"))
        return
    rows = _read_csv(path)
    if len(rows) != EXPECTED_CELL_COUNT:
        issues.append(E8CostAuditIssue(str(path), "artifact cost row count changed"))
    fields = set(rows[0]) if rows else set()
    for field in B2A_REQUIRED_COST_COLUMNS:
        if field not in fields:
            issues.append(
                E8CostAuditIssue(str(path), f"missing artifact cost column {field}")
            )
    for field in B2A_FORBIDDEN_COST_COLUMNS & fields:
        issues.append(
            E8CostAuditIssue(str(path), f"forbidden legacy cost column {field}")
        )

    cells: set[tuple[str, str]] = set()
    class_cells: Counter[str] = Counter()
    class_records: Counter[str] = Counter()
    executed_pass = 0
    executed_wrong = 0
    executed_denominator = 0
    invalid_admissions = 0
    projected_actions: Counter[str] = Counter()
    projected_action_cells: Counter[str] = Counter()
    projected_templates: Counter[str] = Counter()
    projected_template_cells: Counter[str] = Counter()
    for row in rows:
        query_id = str(row.get("query_id", ""))
        mode = normalize_mode_id(str(row.get("mode", "")))
        cell = (query_id, mode)
        if cell in cells:
            issues.append(E8CostAuditIssue(str(path), "duplicate artifact cost cell"))
        cells.add(cell)
        evidence_class = str(row.get("e8cost_evidence_class", ""))
        if evidence_class not in E8COST_EVIDENCE_CLASSES:
            issues.append(
                E8CostAuditIssue(str(path), "artifact cost row lacks evidence class")
            )
            continue
        query_identity = _b2a_query_identity(query_id)
        if query_identity is None or mode not in REQUIRED_MODES:
            issues.append(
                E8CostAuditIssue(str(path), "artifact cost cell identity changed")
            )
            continue
        expected_class = (
            E8COST_ACCOUNTING_PROJECTION
            if mode == ADMISSION_FIRST_MODE
            else (
                E8COST_GATE_REJECT
                if query_identity[0] == "STALE-FALLBACK"
                and mode in {"auth-index-enum-only", "mav-only"}
                else E8COST_RESULT_EXECUTION
            )
        )
        if evidence_class != expected_class:
            issues.append(
                E8CostAuditIssue(
                    str(path), "artifact cost evidence class changed for cell"
                )
            )
        class_cells[evidence_class] += 1
        if query_identity[0] != row.get("accounting_family"):
            issues.append(
                E8CostAuditIssue(str(path), "artifact cost family identity changed")
            )
        if _b2a_int(row.get("accounting_q")) != query_identity[1]:
            issues.append(E8CostAuditIssue(str(path), "artifact cost Q changed"))
        if not _close(
            _maybe_float(row.get("accounting_u")), query_identity[2]
        ):
            issues.append(E8CostAuditIssue(str(path), "artifact cost U changed"))
        if (
            _b2a_int(row.get("sample_count")) != expected_measured
            or _b2a_int(row.get("warmup_count")) != expected_warmup
            or _b2a_int(row.get("total_record_count"))
            != expected_warmup + expected_measured
        ):
            issues.append(E8CostAuditIssue(str(path), "cost row protocol changed"))
        class_count_field = {
            E8COST_ACCOUNTING_PROJECTION: "accounting_projection_record_count",
            E8COST_GATE_REJECT: "gate_reject_record_count",
            E8COST_RESULT_EXECUTION: "result_execution_record_count",
        }[evidence_class]
        class_count = _b2a_int(row.get(class_count_field)) or 0
        class_records[evidence_class] += class_count
        other_count_fields = {
            "accounting_projection_record_count",
            "gate_reject_record_count",
            "result_execution_record_count",
        } - {class_count_field}
        if class_count != expected_measured or any(
            (_b2a_int(row.get(field)) or 0) != 0
            for field in other_count_fields
        ):
            issues.append(
                E8CostAuditIssue(str(path), "cost row evidence population changed")
            )
        cell_pass = _b2a_int(row.get("executed_pass_count")) or 0
        cell_wrong = _b2a_int(row.get("executed_wrong_result_count")) or 0
        cell_denominator = _b2a_int(row.get("executed_result_denominator")) or 0
        executed_pass += cell_pass
        executed_wrong += cell_wrong
        executed_denominator += cell_denominator
        invalid_admissions += (
            _b2a_int(row.get("invalid_gate_admission_count")) or 0
        )
        if evidence_class == E8COST_RESULT_EXECUTION:
            if cell_denominator != expected_measured or cell_pass + cell_wrong != cell_denominator:
                issues.append(
                    E8CostAuditIssue(str(path), "executed cost-row denominator changed")
                )
            if _maybe_float(row.get("executed_execution_ms_median")) is None:
                issues.append(
                    E8CostAuditIssue(str(path), "result execution lacks executed median")
                )
        else:
            if cell_denominator != 0 or cell_pass != 0 or cell_wrong != 0:
                issues.append(
                    E8CostAuditIssue(
                        str(path),
                        "non-result row entered executed denominator",
                    )
                )
            for field in (
                "executed_query_only_ms_median",
                "executed_execution_ms_median",
                "executed_total_ms_median",
            ):
                if row.get(field) not in (None, ""):
                    issues.append(
                        E8CostAuditIssue(
                            str(path),
                            "non-result row carries executed performance median",
                        )
                    )
                    break
        if evidence_class == E8COST_ACCOUNTING_PROJECTION:
            action_counts = _counter_mapping(
                row.get("projected_action_accounting_counts")
            )
            template_counts = _counter_mapping(
                row.get("projected_template_accounting_counts")
            )
            expected_action = (
                "fallback"
                if query_identity[0] == "STALE-FALLBACK"
                else "execute"
            )
            expected_template = {
                "MAV-DASH": "mav_scan_v1",
                "AUTHIDX-SPARSE": "auth_index_enum_v1",
                "STALE-FALLBACK": "barrier_filter_v1",
            }[query_identity[0]]
            if action_counts != {expected_action: expected_measured}:
                issues.append(
                    E8CostAuditIssue(
                        str(path), "cost CSV projection action changed"
                    )
                )
            if template_counts != {expected_template: expected_measured}:
                issues.append(
                    E8CostAuditIssue(
                        str(path), "cost CSV projection template changed"
                    )
                )
            projected_actions.update(action_counts)
            projected_templates.update(template_counts)
            projected_action_cells[expected_action] += 1
            projected_template_cells[expected_template] += 1
    if class_cells != Counter(EXPECTED_CLASS_CELL_COUNTS):
        issues.append(E8CostAuditIssue(str(path), "cost CSV class cells changed"))
    if class_records != Counter(EXPECTED_CLASS_MEASURED_RECORD_COUNTS):
        issues.append(E8CostAuditIssue(str(path), "cost CSV class records changed"))
    if projected_actions != Counter(
        EXPECTED_PROJECTED_ACTION_MEASURED_RECORD_COUNTS
    ):
        issues.append(E8CostAuditIssue(str(path), "cost CSV projected actions changed"))
    if projected_action_cells != Counter(EXPECTED_PROJECTED_ACTION_CELL_COUNTS):
        issues.append(
            E8CostAuditIssue(str(path), "cost CSV projected action cells changed")
        )
    if projected_templates != Counter(
        EXPECTED_PROJECTED_TEMPLATE_MEASURED_RECORD_COUNTS
    ):
        issues.append(
            E8CostAuditIssue(str(path), "cost CSV projected templates changed")
        )
    if projected_template_cells != Counter(
        EXPECTED_PROJECTED_TEMPLATE_CELL_COUNTS
    ):
        issues.append(
            E8CostAuditIssue(str(path), "cost CSV projected template cells changed")
        )
    if invalid_admissions != 0:
        issues.append(E8CostAuditIssue(str(path), "cost CSV has invalid gate admission"))
    if (executed_pass, executed_wrong, executed_denominator) != (
        EXPECTED_EXECUTED_PASS_COUNT,
        EXPECTED_EXECUTED_WRONG_COUNT,
        EXPECTED_EXECUTED_DENOMINATOR,
    ):
        issues.append(E8CostAuditIssue(str(path), "cost CSV denominator drift"))
    details["artifact_cost_csv"] = {
        "row_count": len(rows),
        "evidence_class_cell_counts": dict(sorted(class_cells.items())),
        "evidence_class_measured_record_counts": dict(
            sorted(class_records.items())
        ),
        "projected_action_accounting_measured_record_counts": dict(
            sorted(projected_actions.items())
        ),
        "projected_action_accounting_cell_counts": dict(
            sorted(projected_action_cells.items())
        ),
        "projected_template_accounting_measured_record_counts": dict(
            sorted(projected_templates.items())
        ),
        "projected_template_accounting_cell_counts": dict(
            sorted(projected_template_cells.items())
        ),
        "invalid_gate_admission_count": invalid_admissions,
        "executed_pass_count": executed_pass,
        "executed_wrong_result_count": executed_wrong,
        "executed_result_denominator": executed_denominator,
        "executed_wrong_result_rate": (
            executed_wrong / executed_denominator
            if executed_denominator
            else None
        ),
    }


def _validate_b2a_summary(
    summary_dir: Path | None,
    expected_warmup: int,
    expected_measured: int,
    issues: list[E8CostAuditIssue],
    details: dict[str, Any],
) -> None:
    if summary_dir is None:
        details["summary_validation"] = "skipped"
        return
    path = summary_dir / SUMMARY_SUBDIR / "summary.json"
    if not path.exists():
        issues.append(E8CostAuditIssue(str(path), "missing E8-COST summary"))
        return
    try:
        summary = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        issues.append(E8CostAuditIssue(str(path), f"invalid summary JSON: {exc}"))
        return
    if not isinstance(summary, Mapping):
        issues.append(E8CostAuditIssue(str(path), "summary must be a mapping"))
        return
    protocol = summary.get("measurement_protocol")
    analysis = summary.get("artifact_cost_analysis")
    if not isinstance(protocol, Mapping) or not isinstance(analysis, Mapping):
        issues.append(E8CostAuditIssue(str(path), "summary contract is incomplete"))
        return
    if summary.get("experiment") != "E8":
        issues.append(E8CostAuditIssue(str(path), "summary experiment changed"))
    if summary.get("input_dir") != "results/raw/E8_COST_1E6":
        issues.append(E8CostAuditIssue(str(path), "summary input_dir changed"))
    if summary.get("run_kind_counts") != {
        "normal_mode": EXPECTED_RAW_RECORD_COUNT
    }:
        issues.append(E8CostAuditIssue(str(path), "summary run kind changed"))
    if summary.get("status_counts") != EXPECTED_RAW_STATUS_COUNTS:
        issues.append(E8CostAuditIssue(str(path), "summary status counts changed"))
    forbidden = B2A_FORBIDDEN_SUMMARY_KEYS & set(analysis)
    if forbidden:
        issues.append(
            E8CostAuditIssue(
                str(path),
                f"summary carries forbidden AdmissionFirst correctness/choice keys {sorted(forbidden)!r}",
            )
        )
    if _b2a_int(summary.get("record_count")) != EXPECTED_RAW_RECORD_COUNT:
        issues.append(E8CostAuditIssue(str(path), "summary raw count changed"))
    mode_counts = summary.get("mode_counts")
    if (
        not isinstance(mode_counts, Mapping)
        or set(mode_counts) != REQUIRED_MODES
        or {
            mode: _b2a_int(mode_counts.get(mode)) for mode in REQUIRED_MODES
        }
        != EXPECTED_MODE_COUNTS
    ):
        issues.append(E8CostAuditIssue(str(path), "summary mode counts changed"))
    for field, expected in (
        ("cell_count", EXPECTED_CELL_COUNT),
        ("cells_meeting_required_repetitions", EXPECTED_CELL_COUNT),
        ("required_warmup_repetitions", expected_warmup),
        ("required_measured_repetitions", expected_measured),
        ("insufficient_repetition_cells", 0),
    ):
        if _b2a_int(protocol.get(field)) != expected:
            issues.append(
                E8CostAuditIssue(str(path), f"summary protocol {field} changed")
            )
    if protocol.get("status") != "ok":
        issues.append(E8CostAuditIssue(str(path), "summary protocol is not ok"))
    expected_scalars = {
        "artifact_cost_cell_count": EXPECTED_CELL_COUNT,
        "scenario_count": EXPECTED_SCENARIO_COUNT,
        "raw_record_count": EXPECTED_RAW_RECORD_COUNT,
        "measured_record_count": EXPECTED_MEASURED_RECORD_COUNT,
        "warmup_record_count": EXPECTED_WARMUP_RECORD_COUNT,
        "accounting_projection_record_count": 720,
        "accounting_projection_measured_record_count": 480,
        "accounting_projection_warmup_record_count": 240,
        "accounting_projection_cell_count": 48,
        "gate_reject_record_count": 480,
        "gate_reject_measured_record_count": 320,
        "gate_reject_warmup_record_count": 160,
        "gate_reject_cell_count": 32,
        "result_execution_record_count": 4560,
        "result_execution_measured_record_count": 3040,
        "result_execution_warmup_record_count": 1520,
        "result_execution_cell_count": 304,
        "executed_pass_count": EXPECTED_EXECUTED_PASS_COUNT,
        "executed_wrong_result_count": EXPECTED_EXECUTED_WRONG_COUNT,
        "executed_result_denominator": EXPECTED_EXECUTED_DENOMINATOR,
        "invalid_gate_admission_count": 0,
        "measured_invalid_gate_admission_count": 0,
    }
    for field, expected in expected_scalars.items():
        if _b2a_int(analysis.get(field)) != expected:
            issues.append(
                E8CostAuditIssue(str(path), f"summary {field} changed")
            )
    if not _close(
        _maybe_float(analysis.get("executed_wrong_result_rate")),
        EXPECTED_EXECUTED_WRONG_COUNT / EXPECTED_EXECUTED_DENOMINATOR,
    ):
        issues.append(E8CostAuditIssue(str(path), "summary wrong-result rate changed"))
    if analysis.get("performance_ranking_eligible") is not False:
        issues.append(E8CostAuditIssue(str(path), "E8-COST became payoff eligible"))
    if analysis.get("planner_choice_authority") is not False:
        issues.append(E8CostAuditIssue(str(path), "E8-COST gained planner-choice authority"))
    if _counter_mapping(
        analysis.get("projected_action_accounting_cell_counts")
    ) != EXPECTED_PROJECTED_ACTION_CELL_COUNTS:
        issues.append(E8CostAuditIssue(str(path), "summary projected action cells changed"))
    if _counter_mapping(
        analysis.get("projected_action_accounting_record_counts")
    ) != EXPECTED_PROJECTED_ACTION_MEASURED_RECORD_COUNTS:
        issues.append(
            E8CostAuditIssue(str(path), "summary projected action records changed")
        )
    for field, expected in (
        ("evidence_class_raw_record_counts", EXPECTED_CLASS_RAW_RECORD_COUNTS),
        (
            "evidence_class_measured_record_counts",
            EXPECTED_CLASS_MEASURED_RECORD_COUNTS,
        ),
        (
            "evidence_class_warmup_record_counts",
            EXPECTED_CLASS_WARMUP_RECORD_COUNTS,
        ),
        ("evidence_class_cell_counts", EXPECTED_CLASS_CELL_COUNTS),
        (
            "projected_template_accounting_cell_counts",
            EXPECTED_PROJECTED_TEMPLATE_CELL_COUNTS,
        ),
        (
            "projected_template_accounting_record_counts",
            EXPECTED_PROJECTED_TEMPLATE_MEASURED_RECORD_COUNTS,
        ),
        (
            "observed_accounting_minimum_action_record_counts",
            EXPECTED_PROJECTED_ACTION_MEASURED_RECORD_COUNTS,
        ),
        (
            "observed_accounting_minimum_template_record_counts",
            EXPECTED_PROJECTED_TEMPLATE_MEASURED_RECORD_COUNTS,
        ),
    ):
        if _counter_mapping(analysis.get(field)) != expected:
            issues.append(
                E8CostAuditIssue(str(path), f"summary {field} changed")
            )
    details["summary"] = {
        "record_count": summary.get("record_count"),
        "mode_counts": mode_counts,
        "measurement_protocol": protocol,
        "artifact_cost_analysis": dict(analysis),
    }


def _validate_e8_cost_b2a(
    raw_dir: Path,
    summary_dir: Path | None,
    *,
    expected_warmup: int,
    expected_measured: int,
) -> E8CostAuditReport:
    issues: list[E8CostAuditIssue] = []
    details: dict[str, Any] = {
        "manifest_id": MANIFEST_ID,
        "summary_subdir": SUMMARY_SUBDIR,
        "expected_dataset": dict(EXPECTED_DATASET),
        "evidence_contract": "e8cost_accounting_gate_result_v2",
    }
    if expected_warmup != 5 or expected_measured != 10:
        issues.append(
            E8CostAuditIssue(
                SUMMARY_SUBDIR,
                "E8-COST audit requires the exact 5+10 protocol",
            )
        )
    _validate_b2a_raw(
        raw_dir,
        expected_warmup,
        expected_measured,
        issues,
        details,
    )
    _validate_b2a_cost_csv(
        summary_dir,
        expected_warmup,
        expected_measured,
        issues,
        details,
    )
    _validate_b2a_summary(
        summary_dir,
        expected_warmup,
        expected_measured,
        issues,
        details,
    )
    raw = details.get("raw", {})
    csv_details = details.get("artifact_cost_csv", {})
    summary = details.get("summary", {})
    analysis = (
        summary.get("artifact_cost_analysis", {})
        if isinstance(summary, Mapping)
        else {}
    )
    for label, observed in (
        ("raw", raw),
        ("artifact_cost_csv", csv_details),
        ("summary", analysis),
    ):
        if not isinstance(observed, Mapping):
            continue
        if _b2a_int(observed.get("executed_result_denominator")) not in {
            None,
            EXPECTED_EXECUTED_DENOMINATOR,
        }:
            issues.append(
                E8CostAuditIssue(
                    SUMMARY_SUBDIR,
                    f"{label} executed denominator drift",
                )
            )
    details["stability"] = {
        "cell_count": EXPECTED_CELL_COUNT,
        "scenario_count": EXPECTED_SCENARIO_COUNT,
        "raw_record_count": raw.get("record_count") if isinstance(raw, Mapping) else None,
        "measured_record_count": EXPECTED_MEASURED_RECORD_COUNT,
        "warmup_record_count": EXPECTED_WARMUP_RECORD_COUNT,
        "evidence_class_cell_counts": EXPECTED_CLASS_CELL_COUNTS,
        "evidence_class_raw_record_counts": EXPECTED_CLASS_RAW_RECORD_COUNTS,
        "evidence_class_measured_record_counts": EXPECTED_CLASS_MEASURED_RECORD_COUNTS,
        "evidence_class_warmup_record_counts": EXPECTED_CLASS_WARMUP_RECORD_COUNTS,
        "projected_action_accounting_cell_counts": EXPECTED_PROJECTED_ACTION_CELL_COUNTS,
        "projected_action_accounting_measured_record_counts": (
            EXPECTED_PROJECTED_ACTION_MEASURED_RECORD_COUNTS
        ),
        "invalid_gate_admission_count": (
            raw.get("invalid_gate_admission_count")
            if isinstance(raw, Mapping)
            else None
        ),
        "executed_pass_count": EXPECTED_EXECUTED_PASS_COUNT,
        "executed_wrong_result_count": EXPECTED_EXECUTED_WRONG_COUNT,
        "executed_result_denominator": EXPECTED_EXECUTED_DENOMINATOR,
        "executed_wrong_result_rate": (
            EXPECTED_EXECUTED_WRONG_COUNT / EXPECTED_EXECUTED_DENOMINATOR
        ),
        "status": "pass" if not issues else "fail",
    }
    return E8CostAuditReport(tuple(issues), details)
# END PHASE_B2A_E8COST_AUDIT_VALIDATOR
def validate_e8_cost_accounting(
    raw_dir: Path,
    summary_dir: Path | None,
    *,
    expected_warmup: int = 5,
    expected_measured: int = 10,
) -> E8CostAuditReport:
# BEGIN PHASE_B2A_E8COST_AUDIT_ROUTE
    return _validate_e8_cost_b2a(
        raw_dir,
        summary_dir,
        expected_warmup=expected_warmup,
        expected_measured=expected_measured,
    )
# END PHASE_B2A_E8COST_AUDIT_ROUTE
    issues: list[E8CostAuditIssue] = []
    details: dict[str, Any] = {
        "manifest_id": MANIFEST_ID,
        "summary_subdir": SUMMARY_SUBDIR,
        "expected_dataset": dict(EXPECTED_DATASET),
    }
    _validate_summary(summary_dir, expected_warmup, expected_measured, issues, details)
    _validate_cost_csv(summary_dir, expected_measured, issues, details)
    _validate_raw_records(raw_dir, expected_warmup, expected_measured, issues, details)
    artifact_summary = (
        details.get("summary", {})
        .get("artifact_cost_analysis", {})
        if isinstance(details.get("summary"), Mapping)
        else {}
    )
    csv_details = details.get("artifact_cost_csv", {})
    raw_details = details.get("raw", {})
    details["stability"] = {
        "cell_count": EXPECTED_CELL_COUNT,
        "scenario_count": EXPECTED_SCENARIO_COUNT,
        "raw_record_count": raw_details.get("record_count"),
        "measured_record_count": artifact_summary.get("measured_record_count"),
        "admission_first_cell_count": csv_details.get("admission_first_cell_count"),
        "admission_first_wrong_results": artifact_summary.get("admission_first_wrong_results"),
        "diagnostic_wrong_controls": artifact_summary.get("diagnostic_wrong_results"),
        "admission_first_action_cells": csv_details.get("admission_first_actions", {}),
        "admission_first_template_cells": csv_details.get("admission_first_templates", {}),
        "admission_first_choice_reason_cells": csv_details.get("admission_first_choice_reason_cells", {}),
        "raw_max_cost_choice_delta": raw_details.get("max_cost_choice_delta"),
        "raw_median_cost_choice_delta": raw_details.get("median_cost_choice_delta"),
        "checked_artifact_cost_payloads": raw_details.get("checked_artifact_cost_payloads"),
        "declared_qu_payload_mismatches": raw_details.get("declared_qu_payload_mismatches"),
        "missing_validation_ms_payloads": raw_details.get("missing_validation_ms_payloads"),
        "status": "pass" if not issues else "fail",
    }
    return E8CostAuditReport(issues=tuple(issues), details=details)
