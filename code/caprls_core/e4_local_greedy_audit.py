"""Validation for E4 local-greedy paired-continuation evidence."""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
    normalize_mode_id,
)

import csv
import json
import math
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


FIG6_DIR = "fig6_e4_local_greedy"
FIG6_SOURCE = "fig6_e4_local_greedy_source.csv"
SUMMARY_SUBDIR = "E4_PROTOCOL"

EXPECTED_PAIRS = {
    "selective_ordinary_predicate": {
        "neutral_parent": "no_query_predicate",
        "stress_parent": "key_point_predicate",
        "stress_kind": "selective-parent-predicate",
        "min_regret": 1.5,
    },
    "unsafe_downstream_expression": {
        "neutral_parent": "safe_join_then_residual",
        "stress_parent": "immediate_unsafe_log",
        "stress_kind": "unsafe-downstream-expression",
        "min_regret": None,
    },
    "parent_requires_order": {
        "neutral_parent": "hash_join",
        "stress_parent": "merge_join_order_by",
        "stress_kind": "required-order",
        "min_regret": 1.5,
    },
    "join_continuation": {
        "neutral_parent": "selective_dimension_first",
        "stress_parent": "high_fanout_before_boundary",
        "stress_kind": "high-fanout-continuation",
        "min_regret": 1.5,
    },
}


@dataclass(frozen=True)
class E4LocalGreedyAuditIssue:
    path: str
    message: str


@dataclass(frozen=True)
class E4LocalGreedyAuditReport:
    issues: tuple[E4LocalGreedyAuditIssue, ...]
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


def _json_mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, Mapping) else {}


def _has_hash(row: Mapping[str, str], *fields: str) -> bool:
    return any(bool(row.get(field)) for field in fields)


def _validate_summary(
    summary_dir: Path | None,
    issues: list[E4LocalGreedyAuditIssue],
    details: dict[str, Any],
) -> None:
    if summary_dir is None:
        details["summary_validation"] = "skipped"
        return
    summary_path = summary_dir / SUMMARY_SUBDIR / "summary.json"
    if not summary_path.exists():
        issues.append(E4LocalGreedyAuditIssue(str(summary_path), "missing E4 summary.json"))
        return
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        issues.append(E4LocalGreedyAuditIssue(str(summary_path), f"invalid summary JSON: {exc}"))
        return
    protocol = summary.get("measurement_protocol", {})
    mode_counts = summary.get("mode_counts", {})
    details["summary"] = {
        "record_count": summary.get("record_count"),
        "measurement_protocol": protocol,
        "mode_counts": mode_counts,
    }
    if isinstance(protocol, Mapping):
        if protocol.get("status") != "ok":
            issues.append(E4LocalGreedyAuditIssue(str(summary_path), "E4 protocol status is not ok"))
        if _maybe_int(protocol.get("cell_count")) != 32:
            issues.append(E4LocalGreedyAuditIssue(str(summary_path), "E4 protocol cell_count is not 32"))
        if _maybe_int(protocol.get("cells_meeting_required_repetitions")) != 32:
            issues.append(E4LocalGreedyAuditIssue(str(summary_path), "not all E4 cells meet required repetitions"))
        if _maybe_int(protocol.get("required_warmup_repetitions")) != 5:
            issues.append(E4LocalGreedyAuditIssue(str(summary_path), "E4 warmup repetition count changed"))
        if _maybe_int(protocol.get("required_measured_repetitions")) != 10:
            issues.append(E4LocalGreedyAuditIssue(str(summary_path), "E4 measured repetition count changed"))
    if isinstance(mode_counts, Mapping):
        canonical_mode_counts: dict[str, int | None] = {}
        for raw_mode, raw_count in mode_counts.items():
            try:
                mode = normalize_mode_id(str(raw_mode))
            except ValueError:
                issues.append(
                    E4LocalGreedyAuditIssue(
                        str(summary_path),
                        f"E4 summary has unknown mode {raw_mode!r}",
                    )
                )
                continue
            if mode in canonical_mode_counts:
                issues.append(
                    E4LocalGreedyAuditIssue(
                        str(summary_path),
                        f"E4 summary contains duplicate aliases for {mode}",
                    )
                )
                continue
            canonical_mode_counts[mode] = _maybe_int(raw_count)
        details["summary"]["canonical_mode_counts"] = canonical_mode_counts
        if canonical_mode_counts.get(ADMISSION_FIRST_MODE) != 120:
            issues.append(E4LocalGreedyAuditIssue(str(summary_path), "AdmissionFirst raw count changed"))
        if canonical_mode_counts.get("local-greedy") != 120:
            issues.append(E4LocalGreedyAuditIssue(str(summary_path), "local-greedy raw count changed"))


def _validate_fig6(
    figure_dir: Path,
    issues: list[E4LocalGreedyAuditIssue],
    details: dict[str, Any],
) -> None:
    source_path = figure_dir / FIG6_DIR / FIG6_SOURCE
    if not source_path.exists():
        issues.append(E4LocalGreedyAuditIssue(str(source_path), "missing Fig6 E4 source CSV"))
        return
    rows = _read_csv(source_path)
    by_key = {
        (
            row.get("pair_id"),
            row.get("parent"),
            normalize_mode_id(str(row.get("mode", ""))),
        ): row
        for row in rows
    }
    details["fig6"] = {
        "source_row_count": len(rows),
        "pairs": sorted({row.get("pair_id", "") for row in rows}),
    }
    pair_summaries: list[dict[str, Any]] = []

    for pair_id, spec in EXPECTED_PAIRS.items():
        pair_rows = [row for row in rows if row.get("pair_id") == pair_id]
        if len(pair_rows) != 4:
            issues.append(E4LocalGreedyAuditIssue(str(source_path), f"{pair_id} does not have four mode/parent rows"))
            continue
        for row in pair_rows:
            if row.get("protocol_status") != "ok":
                issues.append(E4LocalGreedyAuditIssue(str(source_path), f"{pair_id} has non-ok protocol row"))
            if _maybe_int(row.get("sample_count")) != 10 or _maybe_int(row.get("warmup_count")) != 5:
                issues.append(E4LocalGreedyAuditIssue(str(source_path), f"{pair_id} row does not carry 5+10 protocol counts"))
            if not row.get("local_feature_vector"):
                issues.append(E4LocalGreedyAuditIssue(str(source_path), f"{pair_id} row lacks local feature vector"))
            if not row.get("parent_requirement_vector"):
                issues.append(E4LocalGreedyAuditIssue(str(source_path), f"{pair_id} row lacks parent requirement vector"))
            if not _has_hash(row, "result_hash", "result_hashes") or not _has_hash(
                row,
                "static_plan_hash",
                "static_plan_hashes",
            ):
                issues.append(E4LocalGreedyAuditIssue(str(source_path), f"{pair_id} row lacks result/static plan hash"))
            if not _has_hash(row, "emitted_sql_hash", "emitted_sql_hashes"):
                issues.append(E4LocalGreedyAuditIssue(str(source_path), f"{pair_id} row lacks emitted SQL hash"))

        local_vectors = {row.get("local_feature_vector") for row in pair_rows}
        if len(local_vectors) != 1:
            issues.append(E4LocalGreedyAuditIssue(str(source_path), f"{pair_id} parents do not share the same local feature vector"))
        parent_vectors = {row.get("parent_requirement_vector") for row in pair_rows}
        parent_continuations = {row.get("parent_continuation_id") or row.get("parent") for row in pair_rows}
        if len(parent_vectors) < 2:
            if pair_id != "join_continuation" or len(parent_continuations) < 2:
                issues.append(E4LocalGreedyAuditIssue(str(source_path), f"{pair_id} does not expose differing parent requirements"))

        neutral_parent = str(spec["neutral_parent"])
        stress_parent = str(spec["stress_parent"])
        neutral_contract = by_key.get((pair_id, neutral_parent, ADMISSION_FIRST_MODE))
        neutral_local = by_key.get((pair_id, neutral_parent, "local-greedy"))
        stress_contract = by_key.get((pair_id, stress_parent, ADMISSION_FIRST_MODE))
        stress_local = by_key.get((pair_id, stress_parent, "local-greedy"))
        if not all([neutral_contract, neutral_local, stress_contract, stress_local]):
            issues.append(E4LocalGreedyAuditIssue(str(source_path), f"{pair_id} missing expected neutral/stress rows"))
            continue

        neutral_ratio = _maybe_float(neutral_local.get("regret_vs_contract")) or 0.0
        stress_ratio = _maybe_float(stress_local.get("regret_vs_contract")) or 0.0
        if neutral_local.get("status") != "pass" or neutral_contract.get("status") != "pass":
            issues.append(E4LocalGreedyAuditIssue(str(source_path), f"{pair_id} neutral parent is not a pass/pass control"))
        if not (0.95 <= neutral_ratio <= 1.05):
            issues.append(E4LocalGreedyAuditIssue(str(source_path), f"{pair_id} neutral parent is not a near-tie"))

        if pair_id == "unsafe_downstream_expression":
            if stress_local.get("status") != "expected_reject":
                issues.append(E4LocalGreedyAuditIssue(str(source_path), "unsafe downstream stress row must reject LocalGreedy"))
            stress_evidence = "expected_reject"
        else:
            min_regret = float(spec["min_regret"])
            if stress_local.get("status") != "pass" or stress_contract.get("status") != "pass":
                issues.append(E4LocalGreedyAuditIssue(str(source_path), f"{pair_id} stress parent is not pass/pass"))
            if stress_ratio < min_regret:
                issues.append(E4LocalGreedyAuditIssue(str(source_path), f"{pair_id} stress regret {stress_ratio:.3f} below {min_regret:.3f}"))
            stress_evidence = stress_ratio

        pair_summaries.append(
            {
                "pair_id": pair_id,
                "stress_kind": spec["stress_kind"],
                "neutral_parent": neutral_parent,
                "stress_parent": stress_parent,
                "neutral_regret_vs_contract": neutral_ratio,
                "stress_regret_or_reject": stress_evidence,
                "contract_stress_template": stress_contract.get("observed_template_ids") or stress_contract.get("template_id"),
                "local_stress_template": stress_local.get("observed_template_ids") or stress_local.get("template_id"),
                "parent_requirement_vectors": len(parent_vectors),
                "parent_continuations": sorted(parent_continuations),
            }
        )
    details["pair_summaries"] = pair_summaries


def validate_e4_local_greedy(
    *,
    summary_dir: Path | None = None,
    figure_dir: Path,
) -> E4LocalGreedyAuditReport:
    issues: list[E4LocalGreedyAuditIssue] = []
    details: dict[str, Any] = {}
    _validate_summary(summary_dir, issues, details)
    _validate_fig6(figure_dir, issues, details)
    return E4LocalGreedyAuditReport(tuple(issues), details)
