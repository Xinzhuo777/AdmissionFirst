"""Validation for E9 planner-overhead accounting."""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
    ADMISSION_FIRST_NO_DOMINANCE_MODE,
    normalize_mode_id,
)

import csv
import json
import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


FIG8_DIR = "fig8_e9_overhead"
FIG8_SOURCE = "fig8_e9_overhead_source.csv"
SUMMARY_SUBDIR = "SIGMOD_CURRENT_E9"

EXPECTED_MODES = {
    ADMISSION_FIRST_MODE: 225,
    ADMISSION_FIRST_NO_DOMINANCE_MODE: 225,
    "local-greedy": 225,
}
EXPECTED_CELL_COUNT = 45
EXPECTED_SOURCE_ROWS = 45
MIN_ROWS_PER_RELATION = 10_000
# The protocol treats per-cell and maximum latency as reported values, not
# pass/fail thresholds. Retain one coarse aggregate regression check at the
# protocol's declared 50-100 ms simple-query target.
MAX_ADMISSION_FIRST_MEDIAN_PLANNING_MS = 100.0
MAX_ADMISSION_FIRST_PLANNING_TOTAL_RATIO = 0.70
MAX_ANY_PLANNING_TOTAL_RATIO = 0.95

REQUIRED_NUMERIC_COLUMNS = (
    "planning_ms_median",
    "execution_ms_median",
    "total_ms_median",
    "planning_total_ratio",
    "generated_templates_median",
    "rejected_templates_median",
    "dominance_pruned_median",
    "costed_templates_median",
    "dominance_checks_median",
    "memo_groups_median",
    "peak_memory_bytes_median",
    "serialized_state_bytes_median",
    "pruning_ratio",
)


@dataclass(frozen=True)
class E9OverheadAuditIssue:
    path: str
    message: str


@dataclass(frozen=True)
class E9OverheadAuditReport:
    issues: tuple[E9OverheadAuditIssue, ...]
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


def _has_hash(row: Mapping[str, str], field: str) -> bool:
    return bool(str(row.get(field, "")).strip())


def _validate_summary(
    summary_dir: Path | None,
    issues: list[E9OverheadAuditIssue],
    details: dict[str, Any],
) -> None:
    if summary_dir is None:
        details["summary_validation"] = "skipped"
        return
    summary_path = summary_dir / SUMMARY_SUBDIR / "summary.json"
    if not summary_path.exists():
        issues.append(E9OverheadAuditIssue(str(summary_path), "missing E9 summary.json"))
        return
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        issues.append(E9OverheadAuditIssue(str(summary_path), f"invalid summary JSON: {exc}"))
        return

    protocol = summary.get("measurement_protocol", {})
    mode_counts = summary.get("mode_counts", {})
    details["summary"] = {
        "record_count": summary.get("record_count"),
        "measurement_protocol": protocol,
        "mode_counts": mode_counts,
    }
    if summary.get("record_count") != 675:
        issues.append(E9OverheadAuditIssue(str(summary_path), "E9 record_count changed from 675"))
    if isinstance(protocol, Mapping):
        if protocol.get("status") != "ok":
            issues.append(E9OverheadAuditIssue(str(summary_path), "E9 protocol status is not ok"))
        if _maybe_int(protocol.get("cell_count")) != EXPECTED_CELL_COUNT:
            issues.append(E9OverheadAuditIssue(str(summary_path), "E9 protocol cell_count changed"))
        if _maybe_int(protocol.get("cells_meeting_required_repetitions")) != EXPECTED_CELL_COUNT:
            issues.append(E9OverheadAuditIssue(str(summary_path), "not all E9 cells meet required repetitions"))
        if _maybe_int(protocol.get("required_warmup_repetitions")) != 5:
            issues.append(E9OverheadAuditIssue(str(summary_path), "E9 warmup repetition count changed"))
        if _maybe_int(protocol.get("required_measured_repetitions")) != 10:
            issues.append(E9OverheadAuditIssue(str(summary_path), "E9 measured repetition count changed"))
    if isinstance(mode_counts, Mapping):
        canonical_mode_counts: dict[str, int | None] = {}
        raw_by_canonical: dict[str, str] = {}
        for raw_mode, raw_count in mode_counts.items():
            try:
                mode = normalize_mode_id(str(raw_mode))
            except ValueError:
                issues.append(
                    E9OverheadAuditIssue(
                        str(summary_path),
                        f"E9 summary has unknown mode {raw_mode!r}",
                    )
                )
                continue
            if mode in canonical_mode_counts:
                issues.append(
                    E9OverheadAuditIssue(
                        str(summary_path),
                        "E9 summary contains duplicate legacy/canonical aliases for "
                        f"{mode}: {raw_by_canonical[mode]!r} and {raw_mode!r}",
                    )
                )
                continue
            raw_by_canonical[mode] = str(raw_mode)
            canonical_mode_counts[mode] = _maybe_int(raw_count)
        details["summary"]["canonical_mode_counts"] = canonical_mode_counts
        for mode, expected in EXPECTED_MODES.items():
            if canonical_mode_counts.get(mode) != expected:
                issues.append(E9OverheadAuditIssue(str(summary_path), f"E9 mode count for {mode} changed"))
    _validate_summary_runs(summary_path.parent, issues, details)


def _validate_summary_runs(
    e9_summary_dir: Path,
    issues: list[E9OverheadAuditIssue],
    details: dict[str, Any],
) -> None:
    runs_path = e9_summary_dir / "runs.csv"
    if not runs_path.exists():
        issues.append(E9OverheadAuditIssue(str(runs_path), "missing E9 summarized runs.csv"))
        return
    rows = _read_csv(runs_path)
    planning_by_mode: dict[str, list[float]] = defaultdict(list)
    measured_count = 0
    for row in rows:
        if row.get("measurement_phase") != "measured":
            continue
        measured_count += 1
        mode = normalize_mode_id(str(row.get("mode", "")))
        planning_ms = _maybe_float(row.get("planning_ms"))
        if planning_ms is None:
            issues.append(E9OverheadAuditIssue(str(runs_path), "measured E9 row lacks numeric planning_ms"))
            continue
        planning_by_mode[mode].append(planning_ms)
    if measured_count == 0:
        issues.append(E9OverheadAuditIssue(str(runs_path), "E9 summarized runs.csv has no measured rows"))
    admission_first = planning_by_mode.get(ADMISSION_FIRST_MODE, [])
    if (
        admission_first
        and statistics.median(admission_first)
        > MAX_ADMISSION_FIRST_MEDIAN_PLANNING_MS
    ):
        issues.append(
            E9OverheadAuditIssue(
                str(runs_path),
                "E9 AdmissionFirst median planning time exceeds the protocol's "
                "100 ms simple-query target",
            )
        )
    details["runs"] = {
        "measured_record_count": measured_count,
        "admission_first_median_planning_ms": (
            statistics.median(admission_first) if admission_first else None
        ),
        "max_measured_planning_ms": max(
            (value for values in planning_by_mode.values() for value in values),
            default=None,
        ),
        "max_measured_planning_ms_by_mode": {
            mode: max(values)
            for mode, values in sorted(planning_by_mode.items())
            if values
        },
    }


def _numeric(row: Mapping[str, str], field: str, source_path: Path, issues: list[E9OverheadAuditIssue]) -> float | None:
    parsed = _maybe_float(row.get(field))
    if parsed is None:
        issues.append(E9OverheadAuditIssue(str(source_path), f"row lacks numeric {field}"))
        return None
    if parsed < 0:
        issues.append(E9OverheadAuditIssue(str(source_path), f"row has negative {field}"))
    return parsed


def _validate_fig8(
    figure_dir: Path,
    issues: list[E9OverheadAuditIssue],
    details: dict[str, Any],
) -> None:
    source_path = figure_dir / FIG8_DIR / FIG8_SOURCE
    if not source_path.exists():
        issues.append(E9OverheadAuditIssue(str(source_path), "missing Fig8 E9 source CSV"))
        return
    rows = _read_csv(source_path)
    fieldnames = set(rows[0].keys()) if rows else set()
    missing_columns = [field for field in REQUIRED_NUMERIC_COLUMNS if field not in fieldnames]
    for field in missing_columns:
        issues.append(E9OverheadAuditIssue(str(source_path), f"missing Fig8 column {field}"))

    mode_counts = Counter(
        normalize_mode_id(str(row.get("mode", ""))) for row in rows
    )
    ratio_by_mode: dict[str, list[float]] = defaultdict(list)
    planning_by_mode: dict[str, list[float]] = defaultdict(list)
    dominance_pruned_by_mode: dict[str, list[float]] = defaultdict(list)
    point_metrics: dict[tuple[str, str, str, str, str], dict[str, dict[str, float]]] = defaultdict(dict)
    memory_values: list[float] = []
    pruning_values: list[float] = []
    row_scales: set[int] = set()
    point_keys = {
        (
            row.get("tier", ""),
            row.get("protected_occurrences", ""),
            row.get("alternatives_per_occurrence", ""),
            row.get("joins", ""),
            row.get("residuals", ""),
        )
        for row in rows
    }

    if len(rows) != EXPECTED_SOURCE_ROWS:
        issues.append(E9OverheadAuditIssue(str(source_path), "Fig8 source row count changed"))
    for mode in EXPECTED_MODES:
        if mode_counts.get(mode, 0) != 15:
            issues.append(E9OverheadAuditIssue(str(source_path), f"Fig8 source has wrong row count for {mode}"))
    if len(point_keys) != 15:
        issues.append(E9OverheadAuditIssue(str(source_path), "Fig8 source does not expose the 15 E9 tier points"))

    for row in rows:
        mode = normalize_mode_id(str(row.get("mode", "")))
        if row.get("protocol_status") != "ok":
            issues.append(E9OverheadAuditIssue(str(source_path), "Fig8 row has non-ok protocol status"))
        if _maybe_int(row.get("sample_count")) != 10 or _maybe_int(row.get("warmup_count")) != 5:
            issues.append(E9OverheadAuditIssue(str(source_path), "Fig8 row does not carry 5+10 protocol counts"))

        scale = _maybe_int(row.get("rows_per_relation"))
        if scale is None or scale < MIN_ROWS_PER_RELATION:
            issues.append(E9OverheadAuditIssue(str(source_path), "E9 row does not report analytical-scale rows_per_relation"))
        elif scale is not None:
            row_scales.add(scale)

        if row.get("planner_level") != "B":
            issues.append(E9OverheadAuditIssue(str(source_path), "E9 row does not mark planner level B"))
        if not row.get("parent_requirement_vector"):
            issues.append(E9OverheadAuditIssue(str(source_path), "E9 row lacks parent requirement vector"))
        if mode == "local-greedy" and not row.get("local_feature_vector"):
            issues.append(E9OverheadAuditIssue(str(source_path), "local-greedy row lacks local feature vector"))
        for field in ("result_hash", "static_plan_hash", "emitted_sql_hash"):
            if not _has_hash(row, field):
                issues.append(E9OverheadAuditIssue(str(source_path), f"E9 row lacks {field}"))
        for field in ("static_plan_hash", "emitted_sql_hash"):
            if ";" in str(row.get(field, "")):
                issues.append(E9OverheadAuditIssue(str(source_path), f"E9 row has unstable {field} set"))

        numeric = {
            field: _numeric(row, field, source_path, issues)
            for field in REQUIRED_NUMERIC_COLUMNS
            if field in fieldnames
        }
        planning_ms = numeric.get("planning_ms_median")
        ratio = numeric.get("planning_total_ratio")
        generated = numeric.get("generated_templates_median")
        rejected = numeric.get("rejected_templates_median")
        dominance_pruned = numeric.get("dominance_pruned_median")
        costed = numeric.get("costed_templates_median")
        memory = numeric.get("peak_memory_bytes_median")
        pruning_ratio = numeric.get("pruning_ratio")
        memo_groups = numeric.get("memo_groups_median")

        if planning_ms is not None:
            planning_by_mode[mode].append(planning_ms)
        if ratio is not None:
            ratio_by_mode[mode].append(ratio)
            if ratio > MAX_ANY_PLANNING_TOTAL_RATIO:
                issues.append(E9OverheadAuditIssue(str(source_path), f"{mode} planning/total ratio exceeds IR-overhead bound"))
        if dominance_pruned is not None:
            dominance_pruned_by_mode[mode].append(dominance_pruned)
        if memory is not None:
            memory_values.append(memory)
        if pruning_ratio is not None:
            pruning_values.append(pruning_ratio)
        if memo_groups is not None and memo_groups <= 0:
            issues.append(E9OverheadAuditIssue(str(source_path), "E9 memo group count is not positive"))
        if ratio is not None and not (0.0 <= ratio <= 1.0):
            issues.append(E9OverheadAuditIssue(str(source_path), "E9 planning/total ratio is outside [0,1]"))
        if generated is not None and generated <= 0:
            issues.append(E9OverheadAuditIssue(str(source_path), "E9 generated template count is not positive"))
        if costed is not None and costed <= 0:
            issues.append(E9OverheadAuditIssue(str(source_path), "E9 costed template count is not positive"))
        if generated is not None and rejected is not None and rejected > generated:
            issues.append(E9OverheadAuditIssue(str(source_path), "E9 rejected templates exceed generated templates"))
        if (
            generated is not None
            and rejected is not None
            and dominance_pruned is not None
            and costed is not None
            and abs((rejected + dominance_pruned + costed) - generated) > 1e-6
        ):
            issues.append(E9OverheadAuditIssue(str(source_path), "E9 planner template ledger does not balance"))
        if generated and dominance_pruned is not None and pruning_ratio is not None:
            expected_ratio = dominance_pruned / generated
            if abs(pruning_ratio - expected_ratio) > 1e-6:
                issues.append(E9OverheadAuditIssue(str(source_path), "E9 pruning ratio does not match dominance_pruned/generated"))
        if mode and planning_ms is not None and dominance_pruned is not None and costed is not None:
            key = (
                row.get("tier", ""),
                row.get("protected_occurrences", ""),
                row.get("alternatives_per_occurrence", ""),
                row.get("joins", ""),
                row.get("residuals", ""),
            )
            point_metrics[key][mode] = {
                "planning_ms": planning_ms,
                "dominance_pruned": dominance_pruned,
                "costed_templates": costed,
                "pruning_ratio": pruning_ratio if pruning_ratio is not None else 0.0,
            }

    contract_ratios = ratio_by_mode.get(ADMISSION_FIRST_MODE, [])
    if contract_ratios and max(contract_ratios) > MAX_ADMISSION_FIRST_PLANNING_TOTAL_RATIO:
        issues.append(E9OverheadAuditIssue(str(source_path), "AdmissionFirst planning/total ratio is still dominant"))
    contract_pruning = dominance_pruned_by_mode.get(ADMISSION_FIRST_MODE, [])
    no_dominance_pruning = dominance_pruned_by_mode.get(ADMISSION_FIRST_NO_DOMINANCE_MODE, [])
    if not no_dominance_pruning:
        issues.append(E9OverheadAuditIssue(str(source_path), "NoDominance rows are absent from E9 Fig8 source"))
    elif any(value != 0 for value in no_dominance_pruning):
        issues.append(E9OverheadAuditIssue(str(source_path), "NoDominance rows unexpectedly report dominance pruning"))

    paired_savings: list[float] = []
    paired_planning_delta: list[float] = []
    missing_pair_count = 0
    for per_mode in point_metrics.values():
        contract = per_mode.get(ADMISSION_FIRST_MODE)
        no_dominance = per_mode.get(ADMISSION_FIRST_NO_DOMINANCE_MODE)
        if contract is None or no_dominance is None:
            missing_pair_count += 1
            continue
        saved = no_dominance["costed_templates"] - contract["costed_templates"]
        paired_savings.append(saved)
        paired_planning_delta.append(no_dominance["planning_ms"] - contract["planning_ms"])
        if saved < 0:
            issues.append(E9OverheadAuditIssue(str(source_path), "AdmissionFirst costs more templates than NoDominance for a paired E9 point"))
    if missing_pair_count:
        issues.append(E9OverheadAuditIssue(str(source_path), "E9 dominance ablation lacks paired AdmissionFirst/NoDominance rows"))

    details["fig8"] = {
        "source_row_count": len(rows),
        "mode_counts": dict(sorted(mode_counts.items())),
        "row_scales": sorted(row_scales),
        "max_planning_ms": max((value for values in planning_by_mode.values() for value in values), default=None),
        "max_peak_memory_bytes": max(memory_values, default=None),
        "max_pruning_ratio": max(pruning_values, default=None),
        "planning_total_ratio_by_mode": {
            mode: {
                "median": statistics.median(values),
                "max": max(values),
            }
            for mode, values in sorted(ratio_by_mode.items())
            if values
        },
        "dominance_ablation": {
            "paired_point_count": len(paired_savings),
            "admission_first_max_pruned": max(contract_pruning, default=None),
            "admission_first_median_pruned": statistics.median(contract_pruning) if contract_pruning else None,
            "no_dominance_max_pruned": max(no_dominance_pruning, default=None),
            "median_costed_templates_saved": statistics.median(paired_savings) if paired_savings else None,
            "max_costed_templates_saved": max(paired_savings, default=None),
            "median_no_dominance_minus_admission_first_planning_ms": (
                statistics.median(paired_planning_delta) if paired_planning_delta else None
            ),
        },
    }


def validate_e9_overhead(
    *,
    summary_dir: Path | None = None,
    figure_dir: Path,
) -> E9OverheadAuditReport:
    issues: list[E9OverheadAuditIssue] = []
    details: dict[str, Any] = {}
    _validate_summary(summary_dir, issues, details)
    _validate_fig8(figure_dir, issues, details)
    return E9OverheadAuditReport(tuple(issues), details)
