"""Validation for E5 fixed-representation regret witnesses."""

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
from typing import Any, Mapping


FIG5_DIR = "fig5_e5_template_regret"
FIG5_SOURCE = "fig5_e5_template_regret_source.csv"
SUMMARY_SUBDIR = "E5_PROTOCOL"

EXPECTED_WITNESSES = {
    "W1": {
        "witness_id": "barrier_bad_auth_singleton",
        "fixed_mode": "barrier-only",
        "expected_best_mode": "auth-index-enum-only",
        "min_regret": 1.2,
    },
    "W2": {
        "witness_id": "auth_enum_bad_point_query",
        "fixed_mode": "auth-index-enum-only",
        "expected_best_mode": "injection-only",
        "min_regret": 1.2,
    },
    "W3": {
        "witness_id": "mav_bad_single_use_refresh",
        "fixed_mode": "mav-only",
        "expected_best_mode": "injection-only",
        "min_regret": 1.2,
    },
    "W4": {
        "witness_id": "guard_bad_unselective_residual",
        "fixed_mode": "guard-mandatory-discharge",
        "expected_best_mode": "auth-index-enum-only",
        "min_regret": 1.2,
    },
    "W5": {
        "witness_id": "injection_bad_expensive_singleton",
        "fixed_mode": "injection-only",
        "expected_best_mode": "auth-index-enum-only",
        "min_regret": 1.2,
    },
}

POSITIVE_CONTROL = {
    "witness_id": "mav_good_repeated_dashboard",
    "fixed_mode": "mav-only",
    "max_regret": 1.10,
}


@dataclass(frozen=True)
class E5FixedRegretAuditIssue:
    path: str
    message: str


@dataclass(frozen=True)
class E5FixedRegretAuditReport:
    issues: tuple[E5FixedRegretAuditIssue, ...]
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


def _validate_summary(
    summary_dir: Path | None,
    issues: list[E5FixedRegretAuditIssue],
    details: dict[str, Any],
) -> None:
    if summary_dir is None:
        details["summary_validation"] = "skipped"
        return
    summary_path = summary_dir / SUMMARY_SUBDIR / "summary.json"
    if not summary_path.exists():
        issues.append(E5FixedRegretAuditIssue(str(summary_path), "missing E5 summary.json"))
        return
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        issues.append(E5FixedRegretAuditIssue(str(summary_path), f"invalid summary JSON: {exc}"))
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
            issues.append(E5FixedRegretAuditIssue(str(summary_path), "E5 protocol status is not ok"))
        if _maybe_int(protocol.get("required_warmup_repetitions")) != 5:
            issues.append(E5FixedRegretAuditIssue(str(summary_path), "E5 warmup repetition count changed"))
        if _maybe_int(protocol.get("required_measured_repetitions")) != 10:
            issues.append(E5FixedRegretAuditIssue(str(summary_path), "E5 measured repetition count changed"))
        if _maybe_int(protocol.get("cells_meeting_required_repetitions")) != _maybe_int(protocol.get("cell_count")):
            issues.append(E5FixedRegretAuditIssue(str(summary_path), "not all E5 cells meet required repetitions"))
    if isinstance(mode_counts, Mapping):
        canonical_mode_counts: dict[str, int | None] = {}
        for raw_mode, raw_count in mode_counts.items():
            try:
                mode = normalize_mode_id(str(raw_mode))
            except ValueError:
                issues.append(
                    E5FixedRegretAuditIssue(
                        str(summary_path),
                        f"E5 summary has unknown mode {raw_mode!r}",
                    )
                )
                continue
            if mode in canonical_mode_counts:
                issues.append(
                    E5FixedRegretAuditIssue(
                        str(summary_path),
                        f"E5 summary contains duplicate aliases for {mode}",
                    )
                )
                continue
            canonical_mode_counts[mode] = _maybe_int(raw_count)
        details["summary"]["canonical_mode_counts"] = canonical_mode_counts
        for mode in {
            "barrier-only",
            "auth-index-enum-only",
            "strong-auth-index",
            "mav-only",
            "injection-only",
            "guard-mandatory-discharge",
            ADMISSION_FIRST_MODE,
            "template-oracle",
        }:
            if canonical_mode_counts.get(mode) is None:
                issues.append(E5FixedRegretAuditIssue(str(summary_path), f"E5 mode count missing {mode}"))


def _validate_fig5(
    figure_dir: Path,
    issues: list[E5FixedRegretAuditIssue],
    details: dict[str, Any],
) -> None:
    source_path = figure_dir / FIG5_DIR / FIG5_SOURCE
    if not source_path.exists():
        issues.append(E5FixedRegretAuditIssue(str(source_path), "missing Fig5 E5 source CSV"))
        return
    rows = _read_csv(source_path)
    details["fig5"] = {
        "source_row_count": len(rows),
        "witnesses": sorted({row.get("witness_id", "") for row in rows}),
    }
    by_witness: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_witness[row.get("witness_id", "")].append(row)

    witness_summaries: list[dict[str, Any]] = []
    for theory_witness, spec in EXPECTED_WITNESSES.items():
        witness_id = str(spec["witness_id"])
        fixed_mode = str(spec["fixed_mode"])
        expected_best_mode = str(spec["expected_best_mode"])
        group = by_witness.get(witness_id, [])
        if not group:
            issues.append(E5FixedRegretAuditIssue(str(source_path), f"missing {theory_witness}/{witness_id} rows"))
            continue
        fixed_rows = [
            row
            for row in group
            if normalize_mode_id(str(row.get("mode", ""))) == fixed_mode
        ]
        if not fixed_rows:
            issues.append(E5FixedRegretAuditIssue(str(source_path), f"{theory_witness} missing fixed-mode row {fixed_mode}"))
            continue
        for row in fixed_rows:
            if row.get("protocol_status") != "ok":
                issues.append(E5FixedRegretAuditIssue(str(source_path), f"{theory_witness} has non-ok protocol row"))
            if _maybe_int(row.get("sample_count")) != 10 or _maybe_int(row.get("warmup_count")) != 5:
                issues.append(E5FixedRegretAuditIssue(str(source_path), f"{theory_witness} row does not carry 5+10 protocol counts"))
            if row.get("theory_witness") != theory_witness:
                issues.append(E5FixedRegretAuditIssue(str(source_path), f"{witness_id} lacks theory witness label {theory_witness}"))
            if row.get("fixed_mode_under_test") != fixed_mode:
                issues.append(E5FixedRegretAuditIssue(str(source_path), f"{theory_witness} fixed-mode label changed"))
            if row.get("expected_best_mode") != expected_best_mode:
                issues.append(E5FixedRegretAuditIssue(str(source_path), f"{theory_witness} expected-best label changed"))

        fixed_regrets = [
            parsed
            for parsed in (_maybe_float(row.get("template_regret")) for row in fixed_rows)
            if parsed is not None
        ]
        if not fixed_regrets:
            issues.append(E5FixedRegretAuditIssue(str(source_path), f"{theory_witness} has no numeric fixed-mode regret"))
            continue
        max_regret = max(fixed_regrets)
        if max_regret < float(spec["min_regret"]):
            issues.append(
                E5FixedRegretAuditIssue(
                    str(source_path),
                    f"{theory_witness} max fixed-mode regret {max_regret:.3f} below {float(spec['min_regret']):.3f}",
                )
            )
        witness_summaries.append(
            {
                "theory_witness": theory_witness,
                "witness_id": witness_id,
                "fixed_mode": fixed_mode,
                "max_fixed_regret": max_regret,
                "n_values": sorted({row.get("N", "") for row in fixed_rows}),
            }
        )

    control_rows = [
        row
        for row in by_witness.get(POSITIVE_CONTROL["witness_id"], [])
        if normalize_mode_id(str(row.get("mode", "")))
        == POSITIVE_CONTROL["fixed_mode"]
    ]
    if not control_rows:
        issues.append(E5FixedRegretAuditIssue(str(source_path), "missing MAV positive-control row"))
    else:
        regrets = [
            parsed
            for parsed in (_maybe_float(row.get("template_regret")) for row in control_rows)
            if parsed is not None
        ]
        if not regrets or min(regrets) > float(POSITIVE_CONTROL["max_regret"]):
            issues.append(E5FixedRegretAuditIssue(str(source_path), "MAV positive control is not near oracle"))
        else:
            details["positive_control"] = {
                "witness_id": POSITIVE_CONTROL["witness_id"],
                "min_mav_regret": min(regrets),
            }
    details["witness_summaries"] = witness_summaries


def validate_e5_fixed_regret(
    *,
    summary_dir: Path | None = None,
    figure_dir: Path,
) -> E5FixedRegretAuditReport:
    issues: list[E5FixedRegretAuditIssue] = []
    details: dict[str, Any] = {}
    _validate_summary(summary_dir, issues, details)
    _validate_fig5(figure_dir, issues, details)
    return E5FixedRegretAuditReport(tuple(issues), details)
