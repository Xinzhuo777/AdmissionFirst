"""Audit artifact validation timing for regenerated raw evidence packages."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .e8_cost_evidence import (
    E8COST_ACCOUNTING_PROJECTION,
    E8COST_GATE_REJECT,
    E8CostEvidenceClassificationError,
    classify_e8_cost_evidence,
    is_e8_cost_record,
)

DEFAULT_PACKAGES = (
    "E3_SF1_RAWPG_V1",
    "E8",
    "E8_COST_1E6",
    "SIGMOD_CURRENT_E9",
    "SIGMOD_CURRENT_E10",
)


@dataclass(frozen=True)
class ValidationTimingIssue:
    path: str
    message: str


@dataclass(frozen=True)
class ValidationTimingReport:
    issues: tuple[ValidationTimingIssue, ...]
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


def _visible_json_paths(path: Path) -> Iterable[Path]:
    if not path.exists():
        return ()
    if path.is_file():
        return (path,) if path.suffix == ".json" and not path.name.startswith("._") else ()
    return (
        item
        for item in sorted(path.rglob("*.json"))
        if not item.name.startswith("._")
    )


def _get(mapping: Mapping[str, Any], dotted: str) -> Any:
    current: Any = mapping
    for part in dotted.split("."):
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current


def _float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or value in (None, ""):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    if isinstance(value, str):
        try:
            parsed = int(value)
        except ValueError:
            return None
        return parsed if str(parsed) == value.strip() else None
    return None


def _artifact_backed_validation(record: Mapping[str, Any]) -> bool:
    validation = record.get("artifact_validation")
    if not isinstance(validation, Mapping):
        return False
    return (
        validation.get("status") == "pass"
        and validation.get("action") == "execute"
        and validation.get("same_snapshot") is True
    )


def _artifact_state_key(validation: Mapping[str, Any]) -> str:
    same_snapshot = validation.get("same_snapshot")
    if same_snapshot is True:
        snapshot = "same_snapshot=true"
    elif same_snapshot is False:
        snapshot = "same_snapshot=false"
    else:
        snapshot = "same_snapshot=unknown"
    return f"{validation.get('status', '')}|{validation.get('action', '')}|{snapshot}"


def _is_sha256_hash(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)


def validate_validation_timing(
    *,
    raw_dir: Path,
    packages: Iterable[str] = DEFAULT_PACKAGES,
    max_absolute_ms: float = 50.0,
    max_execution_fraction: float = 0.30,
    min_checked_per_package: int = 1,
) -> ValidationTimingReport:
    if min_checked_per_package < 0:
        raise ValueError("min_checked_per_package must be non-negative")
    issues: list[ValidationTimingIssue] = []
    checked = 0
    skipped = 0
    package_details: dict[str, dict[str, Any]] = {}
    for package in packages:
        package_path = raw_dir / package
        artifact_state_counts: Counter[str] = Counter()
        artifact_status_counts: Counter[str] = Counter()
        artifact_action_counts: Counter[str] = Counter()
        checked_oracle_status_counts: Counter[str] = Counter()
        checked_oracle_kind_counts: Counter[str] = Counter()
        package_info = {
            "path": str(package_path),
            "exists": package_path.exists(),
            "record_count": 0,
            "checked_record_count": 0,
            "violation_count": 0,
            "validation_metadata_violation_count": 0,
            "timing_violation_count": 0,
            "row_count_violation_count": 0,
            "result_hash_violation_count": 0,
            "oracle_violation_count": 0,
            "coverage_violation_count": 0,
            "max_validation_ms": None,
            "max_threshold_ms": None,
            "artifact_validation_state_counts": {},
            "artifact_validation_status_counts": {},
            "artifact_validation_action_counts": {},
            "checked_oracle_status_counts": {},
            "checked_oracle_kind_counts": {},
        }
        package_details[package] = package_info
        if not package_path.exists():
            issues.append(ValidationTimingIssue(str(package_path), "raw package does not exist"))
            continue
        for path in _visible_json_paths(package_path):
            package_info["record_count"] += 1
            try:
                with path.open("r", encoding="utf-8") as fh:
                    record = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                issues.append(ValidationTimingIssue(str(path), f"failed to read raw JSON: {exc}"))
                continue
            if isinstance(record, Mapping) and is_e8_cost_record(record):
                package_info.setdefault(
                    "e8cost_evidence_class_counts", {}
                )
                package_info.setdefault(
                    "e8cost_evidence_classification_violation_count", 0
                )
                try:
                    evidence_class = classify_e8_cost_evidence(record)
                except E8CostEvidenceClassificationError as exc:
                    package_info["violation_count"] += 1
                    package_info[
                        "e8cost_evidence_classification_violation_count"
                    ] += 1
                    issues.append(
                        ValidationTimingIssue(
                            str(path),
                            f"ambiguous E8-COST evidence classification: {exc}",
                        )
                    )
                    skipped += 1
                    continue
                class_counts = package_info["e8cost_evidence_class_counts"]
                class_counts[evidence_class] = class_counts.get(evidence_class, 0) + 1
                if evidence_class in {
                    E8COST_ACCOUNTING_PROJECTION,
                    E8COST_GATE_REJECT,
                }:
                    if evidence_class == E8COST_ACCOUNTING_PROJECTION:
                        accounting_ms = _float(
                            _get(
                                record,
                                "artifact_cost.accounting_probe."
                                "case_validation_observation.elapsed_ms",
                            )
                        )
                        count_key = (
                            "projected_accounting_validation_record_count"
                        )
                        max_key = "projected_accounting_validation_ms_max"
                    else:
                        accounting_ms = _float(
                            _get(record, "artifact_cost.validation_ms")
                        )
                        count_key = "gate_accounting_validation_record_count"
                        max_key = "gate_accounting_validation_ms_max"
                    package_info[count_key] = package_info.get(count_key, 0) + 1
                    if accounting_ms is not None:
                        prior = package_info.get(max_key)
                        package_info[max_key] = (
                            accounting_ms
                            if prior is None
                            else max(float(prior), accounting_ms)
                        )
                    skipped += 1
                    continue
            validation = record.get("artifact_validation") if isinstance(record, Mapping) else None
            if isinstance(validation, Mapping):
                artifact_state_counts[_artifact_state_key(validation)] += 1
                artifact_status_counts[str(validation.get("status", ""))] += 1
                artifact_action_counts[str(validation.get("action", ""))] += 1
            if not isinstance(record, Mapping) or not _artifact_backed_validation(record):
                skipped += 1
                continue
            if not isinstance(validation, Mapping):
                issues.append(ValidationTimingIssue(str(path), "artifact_validation payload must be an object"))
                package_info["violation_count"] += 1
                package_info["validation_metadata_violation_count"] += 1
                continue
            expected_action = validation.get("expected_action")
            isolation_level = validation.get("isolation_level")
            failure_sqlstate = validation.get("failure_sqlstate")
            failure_symbol = validation.get("failure_symbol")
            if expected_action != "execute":
                package_info["violation_count"] += 1
                package_info["validation_metadata_violation_count"] += 1
                issues.append(
                    ValidationTimingIssue(
                        str(path),
                        "artifact-backed same-snapshot row must have artifact_validation.expected_action='execute'",
                    )
                )
            if isolation_level != "repeatable_read":
                package_info["violation_count"] += 1
                package_info["validation_metadata_violation_count"] += 1
                issues.append(
                    ValidationTimingIssue(
                        str(path),
                        "artifact-backed same-snapshot row must use repeatable_read isolation",
                    )
                )
            if failure_sqlstate is not None or failure_symbol is not None:
                package_info["violation_count"] += 1
                package_info["validation_metadata_violation_count"] += 1
                issues.append(
                    ValidationTimingIssue(
                        str(path),
                        "artifact-backed same-snapshot pass row must not carry failure_sqlstate/failure_symbol",
                    )
                )
            validation_ms = _float(_get(record, "artifact_cost.validation_ms"))
            execution_ms = _float(_get(record, "timing_ms.execution"))
            if validation_ms is None:
                issues.append(
                    ValidationTimingIssue(
                        str(path),
                        "artifact-backed same-snapshot row is missing artifact_cost.validation_ms",
                    )
                )
                package_info["violation_count"] += 1
                package_info["timing_violation_count"] += 1
                continue
            if execution_ms is None:
                issues.append(
                    ValidationTimingIssue(
                        str(path),
                        "artifact-backed same-snapshot row is missing timing_ms.execution",
                    )
                )
                package_info["violation_count"] += 1
                package_info["timing_violation_count"] += 1
                continue
            threshold = max(max_absolute_ms, max_execution_fraction * execution_ms)
            checked += 1
            package_info["checked_record_count"] += 1
            package_info["max_validation_ms"] = max(
                validation_ms,
                package_info["max_validation_ms"] or validation_ms,
            )
            package_info["max_threshold_ms"] = max(
                threshold,
                package_info["max_threshold_ms"] or threshold,
            )
            if validation_ms >= threshold:
                package_info["violation_count"] += 1
                package_info["timing_violation_count"] += 1
                issues.append(
                    ValidationTimingIssue(
                        str(path),
                        "artifact validation timing exceeds regenerated-package bound: "
                        f"validation_ms={validation_ms:.6g}, execution_ms={execution_ms:.6g}, "
                        f"threshold_ms={threshold:.6g}",
                    )
                )
            row_count = _int(_get(record, "result.row_count"))
            if row_count is None or row_count < 0:
                package_info["violation_count"] += 1
                package_info["row_count_violation_count"] += 1
                issues.append(
                    ValidationTimingIssue(
                        str(path),
                        "artifact-backed same-snapshot row is missing a non-negative integer result.row_count",
                    )
                )
            result_hash = _get(record, "result.result_hash")
            if not _is_sha256_hash(result_hash):
                package_info["violation_count"] += 1
                package_info["result_hash_violation_count"] += 1
                issues.append(
                    ValidationTimingIssue(
                        str(path),
                        "artifact-backed same-snapshot row is missing a sha256 result.result_hash",
                    )
                )
            oracle_check = record.get("oracle_check")
            if isinstance(oracle_check, Mapping):
                status = str(oracle_check.get("status", ""))
                oracle_kind = str(oracle_check.get("oracle_kind", ""))
                checked_oracle_status_counts[status] += 1
                checked_oracle_kind_counts[oracle_kind] += 1
                set_diff_left = _int(oracle_check.get("set_diff_left"))
                set_diff_right = _int(oracle_check.get("set_diff_right"))
                if status != "match" or set_diff_left != 0 or set_diff_right != 0:
                    package_info["violation_count"] += 1
                    package_info["oracle_violation_count"] += 1
                    issues.append(
                        ValidationTimingIssue(
                            str(path),
                            "artifact-backed same-snapshot row failed oracle row/set reconciliation: "
                            f"status={status!r}, set_diff_left={oracle_check.get('set_diff_left')!r}, "
                            f"set_diff_right={oracle_check.get('set_diff_right')!r}",
                        )
                    )
            else:
                checked_oracle_status_counts["<missing>"] += 1
                package_info["violation_count"] += 1
                package_info["oracle_violation_count"] += 1
                issues.append(
                    ValidationTimingIssue(
                        str(path),
                        "artifact-backed same-snapshot row is missing oracle_check",
                    )
                )
        if package_info["checked_record_count"] < min_checked_per_package:
            package_info["violation_count"] += 1
            package_info["coverage_violation_count"] += 1
            issues.append(
                ValidationTimingIssue(
                    str(package_path),
                    "raw package has too few artifact-backed same-snapshot execute rows checked: "
                    f"checked={package_info['checked_record_count']}, "
                    f"min_checked_per_package={min_checked_per_package}",
                )
            )
        package_info["artifact_validation_state_counts"] = dict(sorted(artifact_state_counts.items()))
        package_info["artifact_validation_status_counts"] = dict(sorted(artifact_status_counts.items()))
        package_info["artifact_validation_action_counts"] = dict(sorted(artifact_action_counts.items()))
        package_info["checked_oracle_status_counts"] = dict(sorted(checked_oracle_status_counts.items()))
        package_info["checked_oracle_kind_counts"] = dict(sorted(checked_oracle_kind_counts.items()))
    details = {
        "schema_version": "caprls-validation-timing-audit-v1",
        "raw_dir": str(raw_dir),
        "packages": package_details,
        "checked_record_count": checked,
        "skipped_record_count": skipped,
        "violation_count": sum(info["violation_count"] for info in package_details.values()),
        "validation_metadata_violation_count": sum(
            info["validation_metadata_violation_count"] for info in package_details.values()
        ),
        "timing_violation_count": sum(info["timing_violation_count"] for info in package_details.values()),
        "row_count_violation_count": sum(info["row_count_violation_count"] for info in package_details.values()),
        "result_hash_violation_count": sum(info["result_hash_violation_count"] for info in package_details.values()),
        "oracle_violation_count": sum(info["oracle_violation_count"] for info in package_details.values()),
        "coverage_violation_count": sum(info["coverage_violation_count"] for info in package_details.values()),
        "max_absolute_ms": max_absolute_ms,
        "max_execution_fraction": max_execution_fraction,
        "min_checked_per_package": min_checked_per_package,
    }
    return ValidationTimingReport(tuple(issues), details)
