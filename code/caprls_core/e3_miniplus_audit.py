"""Validation for the E3 Mini+ mixed-workload evidence package."""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
    mode_execution_order_key,
    normalize_mode_id,
)

import csv
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


RAW_SUBDIR = "E3_SF1_RAWPG_V1"
SUMMARY_SUBDIR = "E3_SF1_RAWPG_V1"
FIG4_DIR = "fig4_e3_speedup"
FIG4_SOURCE = "fig4_e3_speedup_source.csv"
FIG4_HONESTY_SOURCE = "fig4_e3_honesty_audit.csv"

EXPECTED_RECORD_COUNT = 8415
EXPECTED_TEMPLATE_ORACLE_RECORD_COUNT = 3960
EXPECTED_NORMAL_MODES = (
    "auth-index-enum-only",
    "barrier-only",
    ADMISSION_FIRST_MODE,
    "injection-only",
    "local-greedy",
    "native-pg-rls",
    "native-pg-rls-physical-design",
    "security-barrier",
    "strong-auth-index",
)
EXPECTED_QUERY_IDS = (
    "JOB_10a",
    "JOB_16b",
    "JOB_1a",
    "JOB_2a",
    "JOB_3c",
    "JOB_6d",
    "Q10",
    "Q12",
    "Q3",
    "Q5",
    "Q7",
)
EXPECTED_POLICY_CONFIGS = (
    "cheap_tenant_sargable",
    "group_acl_expensive",
    "hybrid_selective_key",
)
EXPECTED_POLICY_MODE_STATUS = {
    "cheap_tenant_sargable": {
        "auth-index-enum-only": "expected_reject",
        "barrier-only": "pass",
        ADMISSION_FIRST_MODE: "pass",
        "injection-only": "pass",
        "local-greedy": "pass",
        "native-pg-rls": "pass",
        "native-pg-rls-physical-design": "pass",
        "security-barrier": "pass",
        "strong-auth-index": "expected_reject",
    },
    "group_acl_expensive": {
        "auth-index-enum-only": "pass",
        "barrier-only": "pass",
        ADMISSION_FIRST_MODE: "pass",
        "injection-only": "pass",
        "local-greedy": "pass",
        "native-pg-rls": "pass",
        "native-pg-rls-physical-design": "pass",
        "security-barrier": "pass",
        "strong-auth-index": "expected_reject",
    },
    "hybrid_selective_key": {
        "auth-index-enum-only": "pass",
        "barrier-only": "pass",
        ADMISSION_FIRST_MODE: "pass",
        "injection-only": "pass",
        "local-greedy": "pass",
        "native-pg-rls": "pass",
        "native-pg-rls-physical-design": "pass",
        "security-barrier": "pass",
        "strong-auth-index": "pass",
    },
}
NATIVE_RLS_MODES = {"native-pg-rls", "native-pg-rls-physical-design"}
BAD_CONTRACT_STATUSES = {"wrong_result", "unsafe_observation"}
DEFAULT_SLOWDOWN_MAX = 1.20
FIG4_REQUIRED_CDF_COMPARISONS = (
    "best-single-fixed-mode",
    "local-greedy",
    "native-pg-rls-physical-design",
)

LEGACY_TAXONOMY_FIELD_ALIASES = {
    "best_production_safe_mode": "best_policy_enforcement_mode",
    "best_production_safe_modes": "best_policy_enforcement_modes",
    "production_safe_mode_count": "policy_enforcement_mode_count",
    "contractaware_total_ms_median": "admission_first_total_ms_median",
    "contractaware_mode_total_ms_median": "admission_first_mode_total_ms_median",
    "contractaware_runner_sql_hash": "admission_first_runner_sql_hash",
    "contractaware_canonical_sample_count": "admission_first_canonical_sample_count",
    "contractaware_slowdown_vs_fastest": "admission_first_slowdown_vs_fastest",
    "contractaware_outcome": "admission_first_outcome",
    "contractaware_speedup_vs_comparator": "admission_first_speedup_vs_comparator",
    "contractaware_slowdown_vs_comparator": "admission_first_slowdown_vs_comparator",
    "contractaware_outcome_counts": "admission_first_outcome_counts",
    "contractaware_slowdown_median": "admission_first_slowdown_median",
    "contractaware_slowdown_p90": "admission_first_slowdown_p90",
    "contractaware_slowdown_max": "admission_first_slowdown_max",
    "worst_contractaware_loss": "worst_admission_first_loss",
}
LEGACY_TAXONOMY_VALUE_ALIASES = {
    "contractaware_loss": "admission_first_loss",
    "contractaware_win_or_tie": "admission_first_win_or_tie",
}
MODE_VALUE_FIELDS = {
    "mode",
    "best_policy_enforcement_mode",
    "best_winner_bucket",
    "comparator_mode",
    "best_single_fixed_mode",
}


def _canonical_mode_value(value: Any) -> Any:
    if not isinstance(value, str) or not value:
        return value
    try:
        return normalize_mode_id(value)
    except ValueError:
        return value


def _canonicalize_taxonomy_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize legacy frozen taxonomy spellings at the read boundary."""
    canonical: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        key = LEGACY_TAXONOMY_FIELD_ALIASES.get(
            str(raw_key),
            LEGACY_TAXONOMY_VALUE_ALIASES.get(str(raw_key), str(raw_key)),
        )
        if isinstance(raw_value, Mapping):
            item: Any = _canonicalize_taxonomy_mapping(raw_value)
        elif isinstance(raw_value, list):
            item = [
                _canonicalize_taxonomy_mapping(entry)
                if isinstance(entry, Mapping)
                else entry
                for entry in raw_value
            ]
        else:
            item = LEGACY_TAXONOMY_VALUE_ALIASES.get(raw_value, raw_value)
        if key in MODE_VALUE_FIELDS:
            item = _canonical_mode_value(item)
        if key not in canonical or str(raw_key) == key:
            canonical[key] = item

    encoded_modes = canonical.get("best_policy_enforcement_modes")
    if isinstance(encoded_modes, str) and encoded_modes:
        try:
            decoded_modes = json.loads(encoded_modes)
        except json.JSONDecodeError:
            pass
        else:
            if isinstance(decoded_modes, list):
                canonical["best_policy_enforcement_modes"] = json.dumps(
                    [_canonical_mode_value(item) for item in decoded_modes],
                    separators=(",", ":"),
                )

    winner_counts = canonical.get("winner_bucket_counts")
    if isinstance(winner_counts, Mapping):
        canonical["winner_bucket_counts"] = {
            str(_canonical_mode_value(key)): count
            for key, count in winner_counts.items()
        }
    elif isinstance(winner_counts, str) and winner_counts:
        try:
            decoded_counts = json.loads(winner_counts)
        except json.JSONDecodeError:
            pass
        else:
            if isinstance(decoded_counts, Mapping):
                canonical["winner_bucket_counts"] = json.dumps(
                    {
                        str(_canonical_mode_value(key)): count
                        for key, count in decoded_counts.items()
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
    return canonical


@dataclass(frozen=True)
class E3MiniPlusAuditIssue:
    path: str
    message: str


@dataclass(frozen=True)
class E3MiniPlusAuditReport:
    issues: tuple[E3MiniPlusAuditIssue, ...]
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
    return parsed if math.isfinite(parsed) else None


def _maybe_int(value: Any) -> int | None:
    parsed = _maybe_float(value)
    if parsed is None:
        return None
    return int(parsed)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        return [
            _canonicalize_taxonomy_mapping(row)
            for row in csv.DictReader(fh)
        ]


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


def _row_status(row: Mapping[str, Any]) -> str:
    if row.get("status"):
        return str(row["status"])
    counts = _json_mapping(row.get("status_counts"))
    if len(counts) == 1:
        return str(next(iter(counts)))
    if counts:
        return "mixed"
    return ""


def _load_raw_records(raw_dir: Path, issues: list[E3MiniPlusAuditIssue]) -> list[_RawRecord]:
    e3_dir = raw_dir / RAW_SUBDIR
    if not e3_dir.exists():
        issues.append(E3MiniPlusAuditIssue(str(e3_dir), "missing E3 Mini+ raw directory"))
        return []
    records: list[_RawRecord] = []
    for path in sorted(e3_dir.rglob("*.json")):
        if path.name.startswith("._") or "explain" in path.parts:
            continue
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            issues.append(E3MiniPlusAuditIssue(str(path), f"invalid JSON: {exc}"))
            continue
        if not isinstance(parsed, Mapping):
            issues.append(E3MiniPlusAuditIssue(str(path), "raw result must be a JSON object"))
            continue
        records.append(_RawRecord(path=path, record=parsed))
    if not records:
        issues.append(E3MiniPlusAuditIssue(str(e3_dir), "E3 Mini+ raw directory has no JSON records"))
    return records


def _query_id(item: _RawRecord) -> str:
    return str(_get(item.record, "query.query_id"))


def _policy_config_id(item: _RawRecord) -> str:
    return str(_get(item.record, "query.params.policy_config_id", _get(item.record, "policy.policy_id")))


def _mode(item: _RawRecord) -> str:
    return normalize_mode_id(str(item.record.get("mode", "")))


def _status(item: _RawRecord) -> str:
    return str(item.record.get("status", ""))


def _validate_raw_records(
    records: Sequence[_RawRecord],
    *,
    expected_record_count: int,
    expected_warmup: int,
    expected_measured: int,
    issues: list[E3MiniPlusAuditIssue],
    details: dict[str, Any],
) -> None:
    mode_counts = Counter(_mode(item) for item in records)
    run_kind_counts = Counter(str(item.record.get("run_kind", "")) for item in records)
    details["raw_record_count"] = len(records)
    details["raw_mode_counts"] = dict(sorted(mode_counts.items()))
    details["raw_run_kind_counts"] = dict(sorted(run_kind_counts.items()))
    if len(records) != expected_record_count:
        issues.append(
            E3MiniPlusAuditIssue(
                str(RAW_SUBDIR),
                f"E3 Mini+ raw record count {len(records)} does not match expected {expected_record_count}",
            )
        )

    expected_normal_count = len(EXPECTED_QUERY_IDS) * len(EXPECTED_POLICY_CONFIGS) * (
        expected_warmup + expected_measured
    )
    for mode in EXPECTED_NORMAL_MODES:
        if mode_counts.get(mode, 0) != expected_normal_count:
            issues.append(
                E3MiniPlusAuditIssue(
                    str(RAW_SUBDIR),
                    f"mode {mode} has {mode_counts.get(mode, 0)} raw records, expected {expected_normal_count}",
                )
            )
    if mode_counts.get("template-oracle", 0) != EXPECTED_TEMPLATE_ORACLE_RECORD_COUNT:
        issues.append(
            E3MiniPlusAuditIssue(
                str(RAW_SUBDIR),
                "template-oracle raw record count does not match the frozen E3 Mini+ package",
            )
        )

    contract_records = [item for item in records if _mode(item) == ADMISSION_FIRST_MODE]
    native_records = [item for item in records if _mode(item) in NATIVE_RLS_MODES]
    details["admission_first_raw_status_counts"] = dict(sorted(Counter(_status(item) for item in contract_records).items()))
    details["native_rls_raw_status_counts"] = dict(sorted(Counter(_status(item) for item in native_records).items()))
    for item in contract_records:
        if _status(item) in BAD_CONTRACT_STATUSES:
            issues.append(E3MiniPlusAuditIssue(str(item.path), f"AdmissionFirst produced {_status(item)}"))
        if _truth(_get(item.record, "oracle_check.known_invalid_accepted", False)):
            issues.append(E3MiniPlusAuditIssue(str(item.path), "AdmissionFirst accepted a known-invalid candidate"))
        if _truth(_get(item.record, "oracle_check.known_valid_rejected", False)):
            issues.append(E3MiniPlusAuditIssue(str(item.path), "AdmissionFirst rejected a known-valid candidate"))
        if _maybe_int(_get(item.record, "runtime_audit.unauthorized_observations", 0)) != 0:
            issues.append(E3MiniPlusAuditIssue(str(item.path), "AdmissionFirst recorded unauthorized observations"))
    for item in native_records:
        if _status(item) != "pass":
            issues.append(E3MiniPlusAuditIssue(str(item.path), f"native RLS mode produced {_status(item)}"))
        if _maybe_int(_get(item.record, "runtime_audit.unauthorized_observations", 0)) != 0:
            issues.append(E3MiniPlusAuditIssue(str(item.path), "native RLS row recorded unauthorized observations"))


def _validate_summary(
    summary_dir: Path | None,
    *,
    expected_record_count: int,
    expected_warmup: int,
    expected_measured: int,
    issues: list[E3MiniPlusAuditIssue],
    details: dict[str, Any],
) -> None:
    if summary_dir is None:
        details["summary_validation"] = "skipped"
        return
    summary_path = summary_dir / SUMMARY_SUBDIR / "summary.json"
    if not summary_path.exists():
        issues.append(E3MiniPlusAuditIssue(str(summary_path), "missing E3 Mini+ summary.json"))
        return
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        issues.append(E3MiniPlusAuditIssue(str(summary_path), f"invalid summary JSON: {exc}"))
        return
    if not isinstance(summary, Mapping):
        issues.append(E3MiniPlusAuditIssue(str(summary_path), "summary must be a JSON object"))
        return

    protocol = summary.get("measurement_protocol", {})
    mode_counts = summary.get("mode_counts", {})
    details["summary"] = {
        "record_count": summary.get("record_count"),
        "measurement_protocol": protocol,
        "mode_counts": mode_counts,
        "manifest_hashes": summary.get("manifest_hashes"),
        "e3_loss_table_summary": summary.get("e3_loss_table_summary", {}),
    }
    if _maybe_int(summary.get("record_count")) != expected_record_count:
        issues.append(E3MiniPlusAuditIssue(str(summary_path), "summary record_count is not the frozen E3 Mini+ count"))
    if isinstance(protocol, Mapping):
        if protocol.get("status") != "ok":
            issues.append(E3MiniPlusAuditIssue(str(summary_path), "E3 Mini+ measurement protocol status is not ok"))
        if _maybe_int(protocol.get("cell_count")) != 363:
            issues.append(E3MiniPlusAuditIssue(str(summary_path), "E3 Mini+ summary cell_count is not 363"))
        if _maybe_int(protocol.get("cells_meeting_required_repetitions")) != 363:
            issues.append(E3MiniPlusAuditIssue(str(summary_path), "not all E3 Mini+ cells meet required repetitions"))
        if _maybe_int(protocol.get("required_warmup_repetitions")) != expected_warmup:
            issues.append(E3MiniPlusAuditIssue(str(summary_path), "summary warmup repetition count changed"))
        if _maybe_int(protocol.get("required_measured_repetitions")) != expected_measured:
            issues.append(E3MiniPlusAuditIssue(str(summary_path), "summary measured repetition count changed"))
    if isinstance(mode_counts, Mapping):
        canonical_mode_counts: dict[str, int | None] = {}
        for raw_mode, raw_count in mode_counts.items():
            try:
                mode = normalize_mode_id(str(raw_mode))
            except ValueError:
                issues.append(
                    E3MiniPlusAuditIssue(
                        str(summary_path),
                        f"summary has unknown mode {raw_mode!r}",
                    )
                )
                continue
            if mode in canonical_mode_counts:
                issues.append(
                    E3MiniPlusAuditIssue(
                        str(summary_path),
                        f"summary contains duplicate aliases for {mode}",
                    )
                )
                continue
            canonical_mode_counts[mode] = _maybe_int(raw_count)
        details["summary"]["canonical_mode_counts"] = canonical_mode_counts
        expected_normal_count = len(EXPECTED_QUERY_IDS) * len(EXPECTED_POLICY_CONFIGS) * (
            expected_warmup + expected_measured
        )
        for mode in EXPECTED_NORMAL_MODES:
            if canonical_mode_counts.get(mode) != expected_normal_count:
                issues.append(E3MiniPlusAuditIssue(str(summary_path), f"summary mode_count for {mode} changed"))


def _validate_cell_stats(
    summary_dir: Path | None,
    *,
    expected_warmup: int,
    expected_measured: int,
    issues: list[E3MiniPlusAuditIssue],
    details: dict[str, Any],
) -> None:
    if summary_dir is None:
        return
    cell_stats_path = summary_dir / SUMMARY_SUBDIR / "cell_stats.csv"
    if not cell_stats_path.exists():
        issues.append(E3MiniPlusAuditIssue(str(cell_stats_path), "missing E3 Mini+ cell_stats.csv"))
        return
    rows = _read_csv(cell_stats_path)
    normal_rows = [row for row in rows if row.get("run_kind") == "normal_mode"]
    by_cell: dict[tuple[str, str, str], dict[str, str]] = {}
    for row in normal_rows:
        key = (
            row.get("query_id", ""),
            row.get("param_policy_config_id", ""),
            normalize_mode_id(str(row.get("mode", ""))),
        )
        by_cell[key] = row
    details["cell_stats"] = {
        "row_count": len(rows),
        "normal_mode_row_count": len(normal_rows),
        "query_ids": sorted({row.get("query_id", "") for row in normal_rows}),
        "policy_config_ids": sorted({row.get("param_policy_config_id", "") for row in normal_rows}),
    }
    for query_id in EXPECTED_QUERY_IDS:
        for policy_config_id in EXPECTED_POLICY_CONFIGS:
            for mode, expected_status in EXPECTED_POLICY_MODE_STATUS[policy_config_id].items():
                key = (query_id, policy_config_id, mode)
                row = by_cell.get(key)
                if row is None:
                    issues.append(E3MiniPlusAuditIssue(str(cell_stats_path), f"missing cell_stats row {key}"))
                    continue
                if _row_status(row) != expected_status:
                    issues.append(
                        E3MiniPlusAuditIssue(
                            str(cell_stats_path),
                            f"{key} status {_row_status(row)} does not match expected {expected_status}",
                        )
                    )
                if _maybe_int(row.get("sample_count")) != expected_measured:
                    issues.append(E3MiniPlusAuditIssue(str(cell_stats_path), f"{key} sample_count changed"))
                if _maybe_int(row.get("warmup_count")) != expected_warmup:
                    issues.append(E3MiniPlusAuditIssue(str(cell_stats_path), f"{key} warmup_count changed"))
                if row.get("protocol_status") != "ok":
                    issues.append(E3MiniPlusAuditIssue(str(cell_stats_path), f"{key} protocol_status is not ok"))


def _winner_bucket(mode: str) -> str:
    if mode == ADMISSION_FIRST_MODE:
        return ADMISSION_FIRST_MODE
    if mode.startswith("native-pg-rls"):
        return "native-pg-rls"
    if mode == "local-greedy":
        return "local-greedy"
    return "fixed-mode"


def _validate_fig4_honesty_audit(
    *,
    figure_dir: Path,
    fig_config_path: Path,
    derived_rows: Sequence[Mapping[str, Any]],
    issues: list[E3MiniPlusAuditIssue],
    details: dict[str, Any],
) -> None:
    audit_path = figure_dir / FIG4_DIR / FIG4_HONESTY_SOURCE
    if not audit_path.exists():
        issues.append(E3MiniPlusAuditIssue(str(audit_path), "missing Fig4 E3 honesty audit CSV"))
        return
    rows = _read_csv(audit_path)
    heatmap_rows = [row for row in rows if row.get("row_type") == "heatmap_cell"]
    cdf_rows = [row for row in rows if row.get("row_type") == "cdf_point"]
    cdf_summary_rows = [row for row in rows if row.get("row_type") == "cdf_summary"]
    plan_choice_rows = [row for row in rows if row.get("row_type") == "plan_choice_stack"]
    summary_rows = [row for row in rows if row.get("row_type") == "summary"]
    details["fig4_honesty_audit"] = {
        "source": str(audit_path),
        "row_count": len(rows),
        "heatmap_cell_count": len(heatmap_rows),
        "cdf_point_count": len(cdf_rows),
        "cdf_summary_count": len(cdf_summary_rows),
        "plan_choice_stack_count": len(plan_choice_rows),
    }
    if not rows:
        issues.append(E3MiniPlusAuditIssue(str(audit_path), "Fig4 honesty audit CSV is empty"))
        return
    required_columns = {
        "row_type",
        "query_id",
        "policy_config_id",
        "best_policy_enforcement_mode",
        "best_winner_bucket",
        "admission_first_slowdown_vs_fastest",
        "comparison",
        "admission_first_speedup_vs_comparator",
        "cdf_rank",
        "cdf_fraction",
        "chosen_template_id",
        "chosen_family",
        "cell_count",
    }
    missing_columns = sorted(required_columns - set(rows[0]))
    if missing_columns:
        issues.append(E3MiniPlusAuditIssue(str(audit_path), f"Fig4 honesty audit lacks columns: {', '.join(missing_columns)}"))

    expected_heatmap = {
        (str(row.get("query_id")), str(row.get("policy_config_id"))): row
        for row in derived_rows
    }
    observed_heatmap = {
        (row.get("query_id"), row.get("policy_config_id")): row
        for row in heatmap_rows
    }
    missing_heatmap = sorted(set(expected_heatmap) - set(observed_heatmap))
    extra_heatmap = sorted(set(observed_heatmap) - set(expected_heatmap))
    if missing_heatmap:
        issues.append(E3MiniPlusAuditIssue(str(audit_path), f"Fig4 honesty audit missing heatmap cells: {missing_heatmap}"))
    if extra_heatmap:
        issues.append(E3MiniPlusAuditIssue(str(audit_path), f"Fig4 honesty audit has extra heatmap cells: {extra_heatmap}"))
    for key, expected in expected_heatmap.items():
        observed = observed_heatmap.get(key)
        if not observed:
            continue
        if observed.get("best_policy_enforcement_mode") != expected.get("best_policy_enforcement_mode"):
            issues.append(E3MiniPlusAuditIssue(str(audit_path), f"{key} best mode differs from Fig4/loss derivation"))
        if observed.get("best_winner_bucket") != expected.get("best_winner_bucket"):
            issues.append(E3MiniPlusAuditIssue(str(audit_path), f"{key} winner bucket differs from Fig4/loss derivation"))
        observed_slowdown = _maybe_float(observed.get("admission_first_slowdown_vs_fastest"))
        expected_slowdown = _maybe_float(expected.get("admission_first_slowdown_vs_fastest"))
        if observed_slowdown is None or expected_slowdown is None or abs(observed_slowdown - expected_slowdown) > 1e-9:
            issues.append(E3MiniPlusAuditIssue(str(audit_path), f"{key} slowdown differs from Fig4/loss derivation"))

    cdf_by_comparison: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in cdf_rows:
        cdf_by_comparison[row.get("comparison", "")].append(row)
        if (_maybe_float(row.get("admission_first_speedup_vs_comparator")) or 0.0) <= 0.0:
            issues.append(E3MiniPlusAuditIssue(str(audit_path), "CDF point has non-positive AdmissionFirst speedup"))
        if (_maybe_float(row.get("cdf_fraction")) or 0.0) <= 0.0 or (_maybe_float(row.get("cdf_fraction")) or 0.0) > 1.0:
            issues.append(E3MiniPlusAuditIssue(str(audit_path), "CDF point has invalid cdf_fraction"))
    if set(cdf_by_comparison) != set(FIG4_REQUIRED_CDF_COMPARISONS):
        issues.append(E3MiniPlusAuditIssue(str(audit_path), "Fig4 honesty audit CDF comparisons differ from required set"))
    for comparison in FIG4_REQUIRED_CDF_COMPARISONS:
        group = cdf_by_comparison.get(comparison, [])
        if len(group) != len(EXPECTED_QUERY_IDS) * len(EXPECTED_POLICY_CONFIGS):
            issues.append(E3MiniPlusAuditIssue(str(audit_path), f"{comparison} CDF does not cover all 33 cells"))
            continue
        ranks = sorted(_maybe_int(row.get("cdf_rank")) or 0 for row in group)
        if ranks != list(range(1, len(group) + 1)):
            issues.append(E3MiniPlusAuditIssue(str(audit_path), f"{comparison} CDF ranks are not contiguous"))
    summary_comparisons = {row.get("comparison", "") for row in cdf_summary_rows}
    if summary_comparisons != set(FIG4_REQUIRED_CDF_COMPARISONS):
        issues.append(E3MiniPlusAuditIssue(str(audit_path), "Fig4 honesty audit CDF summaries differ from required set"))

    plan_choice_total = sum(_maybe_int(row.get("cell_count")) or 0 for row in plan_choice_rows)
    plan_policy_configs = {row.get("policy_config_id", "") for row in plan_choice_rows}
    plan_segments = [(row.get("policy_config_id", ""), row.get("chosen_family", "")) for row in plan_choice_rows]
    details["fig4_plan_choice"] = {
        "cell_count": plan_choice_total,
        "segment_count": len(plan_segments),
        "policy_configs": sorted(plan_policy_configs),
        "families": sorted({row.get("chosen_family", "") for row in plan_choice_rows}),
    }
    if len(plan_segments) != len(set(plan_segments)):
        issues.append(E3MiniPlusAuditIssue(str(audit_path), "Fig4 plan-choice stack has duplicate policy/family segments"))
    if plan_choice_total != len(EXPECTED_QUERY_IDS) * len(EXPECTED_POLICY_CONFIGS):
        issues.append(E3MiniPlusAuditIssue(str(audit_path), "Fig4 plan-choice stack does not sum to 33 cells"))
    if plan_policy_configs != set(EXPECTED_POLICY_CONFIGS):
        issues.append(E3MiniPlusAuditIssue(str(audit_path), "Fig4 plan-choice stack does not cover all policy configs"))
    if not summary_rows:
        issues.append(E3MiniPlusAuditIssue(str(audit_path), "Fig4 honesty audit lacks summary row"))

    if fig_config_path.exists():
        try:
            config = json.loads(fig_config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            config = {}
        companion_sources = config.get("companion_sources", [])
        companion_names = [str(item) for item in companion_sources] if isinstance(companion_sources, list) else []
        if not str(config.get("honesty_audit_csv", "")).endswith(FIG4_HONESTY_SOURCE):
            issues.append(E3MiniPlusAuditIssue(str(fig_config_path), "Fig4 config does not declare honesty_audit_csv"))
        if not any(item.endswith(FIG4_HONESTY_SOURCE) for item in companion_names):
            issues.append(E3MiniPlusAuditIssue(str(fig_config_path), "Fig4 config companion_sources lacks honesty audit CSV"))


def _validate_fig4_and_loss_table(
    summary_dir: Path | None,
    figure_dir: Path | None,
    *,
    slowdown_max: float,
    issues: list[E3MiniPlusAuditIssue],
    details: dict[str, Any],
) -> None:
    if figure_dir is None:
        details["figure_validation"] = "skipped"
        return
    fig_source_path = figure_dir / FIG4_DIR / FIG4_SOURCE
    fig_config_path = figure_dir / FIG4_DIR / "fig4_e3_speedup_config.json"
    if not fig_source_path.exists():
        issues.append(E3MiniPlusAuditIssue(str(fig_source_path), "missing Fig4 E3 source CSV"))
        return
    rows = _read_csv(fig_source_path)
    by_cell: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        if row.get("status") == "pass":
            by_cell[(row.get("query_id", ""), row.get("policy_config_id", ""))].append(row)
        if row.get("protocol_status") != "ok":
            issues.append(E3MiniPlusAuditIssue(str(fig_source_path), "Fig4 source contains a non-ok protocol row"))
        if _maybe_int(row.get("sample_count")) != 10 or _maybe_int(row.get("warmup_count")) != 5:
            issues.append(E3MiniPlusAuditIssue(str(fig_source_path), "Fig4 source row does not carry 5+10 protocol counts"))
    details["fig4"] = {
        "source_row_count": len(rows),
        "cell_count": len(by_cell),
        "mode_counts": dict(
            sorted(
                Counter(
                    normalize_mode_id(str(row.get("mode", ""))) for row in rows
                ).items()
            )
        ),
    }
    if len(by_cell) != len(EXPECTED_QUERY_IDS) * len(EXPECTED_POLICY_CONFIGS):
        issues.append(E3MiniPlusAuditIssue(str(fig_source_path), "Fig4 does not cover all 33 query/policy cells"))
    if fig_config_path.exists():
        try:
            config = json.loads(fig_config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            issues.append(E3MiniPlusAuditIssue(str(fig_config_path), f"invalid Fig4 config JSON: {exc}"))
        else:
            details["fig4_config"] = {
                "source_file": config.get("source_file"),
                "uses_protocol_cell_stats": config.get("uses_protocol_cell_stats"),
                "summary_directories": config.get("summary_directories"),
                "record_count": config.get("record_count"),
            }
            if config.get("source_file") != "cell_stats.csv":
                issues.append(E3MiniPlusAuditIssue(str(fig_config_path), "Fig4 source_file is not cell_stats.csv"))
            if config.get("uses_protocol_cell_stats") is not True:
                issues.append(E3MiniPlusAuditIssue(str(fig_config_path), "Fig4 does not declare protocol cell_stats source"))

    derived_rows: list[dict[str, Any]] = []
    slowdowns: list[float] = []
    winner_counts: Counter[str] = Counter()
    for (query_id, policy_config_id), cell_rows in sorted(by_cell.items()):
        by_mode = {
            normalize_mode_id(str(row.get("mode", ""))): row for row in cell_rows
        }
        contract = by_mode.get(ADMISSION_FIRST_MODE)
        if contract is None:
            issues.append(E3MiniPlusAuditIssue(str(fig_source_path), f"missing AdmissionFirst Fig4 row for {(query_id, policy_config_id)}"))
            continue
        contract_ms = _maybe_float(contract.get("total_ms_median"))
        if contract_ms is None or contract_ms <= 0:
            issues.append(E3MiniPlusAuditIssue(str(fig_source_path), f"invalid AdmissionFirst timing for {(query_id, policy_config_id)}"))
            continue
        finite_rows = [
            row
            for row in cell_rows
            if _maybe_float(row.get("total_ms_median")) is not None
            and (_maybe_float(row.get("total_ms_median")) or 0.0) > 0.0
        ]
        best = min(
            finite_rows,
            key=lambda row: (
                _maybe_float(row.get("total_ms_median")) or math.inf,
                mode_execution_order_key(str(row.get("mode") or "")),
            ),
        )
        best_ms = _maybe_float(best.get("total_ms_median")) or 0.0
        slowdown = contract_ms / best_ms if best_ms > 0 else math.inf
        bucket = _winner_bucket(
            normalize_mode_id(str(best.get("mode", "")))
            if slowdown > 1.01
            else ADMISSION_FIRST_MODE
        )
        slowdowns.append(slowdown)
        winner_counts[bucket] += 1
        derived_rows.append(
            {
                "query_id": query_id,
                "policy_config_id": policy_config_id,
                "best_policy_enforcement_mode": normalize_mode_id(
                    str(best.get("mode", ""))
                ),
                "best_winner_bucket": bucket,
                "admission_first_slowdown_vs_fastest": slowdown,
            }
        )

    if slowdowns:
        sorted_slowdowns = sorted(slowdowns)
        p90_index = max(0, math.ceil(0.9 * len(sorted_slowdowns)) - 1)
        slowdown_summary = {
            "cell_count": len(slowdowns),
            "admission_first_slowdown_median": sorted_slowdowns[len(sorted_slowdowns) // 2]
            if len(sorted_slowdowns) % 2
            else (sorted_slowdowns[len(sorted_slowdowns) // 2 - 1] + sorted_slowdowns[len(sorted_slowdowns) // 2]) / 2.0,
            "admission_first_slowdown_p90": sorted_slowdowns[p90_index],
            "admission_first_slowdown_max": sorted_slowdowns[-1],
            "winner_bucket_counts": dict(sorted(winner_counts.items())),
        }
        details["derived_loss_summary"] = slowdown_summary
        if slowdown_summary["admission_first_slowdown_median"] > slowdown_max:
            issues.append(
                E3MiniPlusAuditIssue(
                    str(fig_source_path),
                    "AdmissionFirst median slowdown vs fastest policy-enforcement baseline exceeds threshold",
                )
            )
        if winner_counts.get("native-pg-rls", 0) == 0:
            issues.append(E3MiniPlusAuditIssue(str(fig_source_path), "Fig4/loss evidence contains no native RLS wins"))
        if winner_counts.get("fixed-mode", 0) == 0:
            issues.append(E3MiniPlusAuditIssue(str(fig_source_path), "Fig4/loss evidence contains no fixed/manual wins"))

    _validate_fig4_honesty_audit(
        figure_dir=figure_dir,
        fig_config_path=fig_config_path,
        derived_rows=derived_rows,
        issues=issues,
        details=details,
    )

    if summary_dir is None:
        return
    loss_csv = summary_dir / SUMMARY_SUBDIR / "e3_loss_table.csv"
    loss_summary_json = summary_dir / SUMMARY_SUBDIR / "e3_loss_table_summary.json"
    if not loss_csv.exists():
        issues.append(E3MiniPlusAuditIssue(str(loss_csv), "missing generated E3 loss table CSV"))
    else:
        loss_rows = _read_csv(loss_csv)
        details["loss_table_row_count"] = len(loss_rows)
        if len(loss_rows) != len(derived_rows):
            issues.append(E3MiniPlusAuditIssue(str(loss_csv), "loss table row count does not match Fig4 cells"))
        observed = {
            (row.get("query_id"), row.get("policy_config_id")): (
                row.get("best_policy_enforcement_mode"),
                row.get("best_winner_bucket"),
            )
            for row in loss_rows
        }
        for row in derived_rows:
            key = (row["query_id"], row["policy_config_id"])
            if observed.get(key) != (row["best_policy_enforcement_mode"], row["best_winner_bucket"]):
                issues.append(E3MiniPlusAuditIssue(str(loss_csv), f"loss table winner mismatch for {key}"))
    if not loss_summary_json.exists():
        issues.append(E3MiniPlusAuditIssue(str(loss_summary_json), "missing generated E3 loss table summary JSON"))
    else:
        try:
            parsed_loss_summary = json.loads(loss_summary_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            issues.append(E3MiniPlusAuditIssue(str(loss_summary_json), f"invalid loss summary JSON: {exc}"))
        else:
            loss_summary = (
                _canonicalize_taxonomy_mapping(parsed_loss_summary)
                if isinstance(parsed_loss_summary, Mapping)
                else parsed_loss_summary
            )
            details["loss_table_summary"] = loss_summary
            if _maybe_int(loss_summary.get("cell_count")) != len(EXPECTED_QUERY_IDS) * len(EXPECTED_POLICY_CONFIGS):
                issues.append(E3MiniPlusAuditIssue(str(loss_summary_json), "loss summary cell_count is not 33"))
            if (_maybe_float(loss_summary.get("admission_first_slowdown_median")) or math.inf) > slowdown_max:
                issues.append(E3MiniPlusAuditIssue(str(loss_summary_json), "loss summary median slowdown exceeds threshold"))


def _validate_native_rls_source(
    source_path: Path | None,
    issues: list[E3MiniPlusAuditIssue],
    details: dict[str, Any],
) -> None:
    if source_path is None:
        details["native_rls_source_validation"] = "skipped"
        return
    if not source_path.exists():
        issues.append(E3MiniPlusAuditIssue(str(source_path), "missing E3 source file for native RLS audit"))
        return
    text = source_path.read_text(encoding="utf-8")
    helper_path = source_path.with_name("native_rls.py")
    helper_text = ""
    if "configure_native_rls" in text and helper_path.exists():
        helper_text = helper_path.read_text(encoding="utf-8")
        details["native_rls_helper_source"] = str(helper_path)
    combined = text + "\n" + helper_text
    present = {
        "role_create": (
            "CREATE ROLE caprls_e3_rls_user" in combined
            or (
                "CREATE ROLE {role_name}" in combined
                and 'role_name="caprls_e3_rls_user"' in combined
            )
        ),
        "force_rls": "FORCE ROW LEVEL SECURITY" in combined,
        "create_policy": "CREATE POLICY" in combined,
        "row_security_on": "SET row_security = on;" in combined,
        "set_role": "SET ROLE caprls_e3_rls_user;" in combined,
        "explain_json": (
            "EXPLAIN (FORMAT JSON)" in combined
            or ("EXPLAIN (" in combined and "FORMAT JSON" in combined)
        ),
        "native_mode_branch": 'mode in {"native-pg-rls", "native-pg-rls-physical-design"}' in combined,
        "native_execution_flag": "native_rls = True" in combined,
    }
    details["native_rls_source"] = present
    for name, ok in present.items():
        if not ok:
            issues.append(E3MiniPlusAuditIssue(str(source_path), f"native RLS source proof missing {name}"))


def validate_e3_miniplus(
    raw_dir: Path,
    *,
    summary_dir: Path | None = None,
    figure_dir: Path | None = None,
    source_path: Path | None = Path("caprls_core/e3_main.py"),
    expected_record_count: int = EXPECTED_RECORD_COUNT,
    expected_warmup: int = 5,
    expected_measured: int = 10,
    slowdown_max: float = DEFAULT_SLOWDOWN_MAX,
) -> E3MiniPlusAuditReport:
    issues: list[E3MiniPlusAuditIssue] = []
    details: dict[str, Any] = {
        "expected_record_count": expected_record_count,
        "expected_warmup": expected_warmup,
        "expected_measured": expected_measured,
        "slowdown_threshold": slowdown_max,
    }
    records = _load_raw_records(raw_dir, issues)
    if records:
        _validate_raw_records(
            records,
            expected_record_count=expected_record_count,
            expected_warmup=expected_warmup,
            expected_measured=expected_measured,
            issues=issues,
            details=details,
        )
    _validate_summary(
        summary_dir,
        expected_record_count=expected_record_count,
        expected_warmup=expected_warmup,
        expected_measured=expected_measured,
        issues=issues,
        details=details,
    )
    _validate_cell_stats(
        summary_dir,
        expected_warmup=expected_warmup,
        expected_measured=expected_measured,
        issues=issues,
        details=details,
    )
    _validate_fig4_and_loss_table(
        summary_dir,
        figure_dir,
        slowdown_max=slowdown_max,
        issues=issues,
        details=details,
    )
    _validate_native_rls_source(source_path, issues, details)
    return E3MiniPlusAuditReport(tuple(issues), details)
