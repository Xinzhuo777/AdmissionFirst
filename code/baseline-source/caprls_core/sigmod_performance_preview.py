"""Create a transparent performance preview from existing experiment results.

This module only aggregates already-produced, paper-facing summaries.  It
does not edit raw measurements, rerun experiments, or depend on a freeze or
promotion workflow.  Every comparison keeps its full denominator and reports
losses as well as wins.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import yaml

from .baselines import (
    ADMISSION_FIRST_MODE,
    EvaluationRole,
    mode_execution_order_key,
    normalize_evaluation_role,
    normalize_mode_id,
)


class PerformancePreviewError(ValueError):
    """The summarized evidence cannot support a transparent preview."""


# Keep active v3 aggregation away from the tracked, frozen paper authority.
DEFAULT_OUTPUT_DIR = Path("results/v3/summarized/SIGMOD_CURRENT")


@dataclass(frozen=True)
class SourceSpec:
    family: str
    experiment: str
    manifest_path: str
    expected_protocol_status: str


SOURCE_SPECS: Tuple[SourceSpec, ...] = (
    SourceSpec(
        "E2_PROTOCOL",
        "E2",
        "manifests/experiments/e2_alternative_matrix_reduced.yaml",
        "ok",
    ),
    SourceSpec(
        "E3_SF1_RAWPG_V1",
        "E3",
        "manifests/experiments/e3_standard_sf1_rawpg.yaml",
        "ok",
    ),
    SourceSpec(
        "E4_PROTOCOL",
        "E4",
        "manifests/experiments/e4_pairs_reduced.yaml",
        "ok",
    ),
    SourceSpec(
        "E5_PROTOCOL",
        "E5",
        "manifests/experiments/e5_regret_reduced.yaml",
        "ok",
    ),
    SourceSpec(
        "SIGMOD_CURRENT_E9",
        "E9",
        "manifests/experiments/e9_overhead.yaml",
        "ok",
    ),
    SourceSpec(
        "SIGMOD_CURRENT_E10",
        "E10",
        "manifests/experiments/e10_case_study.yaml",
        "ok",
    ),
)


@dataclass(frozen=True)
class Expectations:
    e2_cells: int = 8
    e3_cells: int = 33
    e4_variants: int = 8
    e5_witnesses: int = 6
    e5_cells: int = 12
    e8_scenarios: int = 48
    e8_modes_per_scenario: int = 8
    e9_mode_cells: int = 45
    e10_cells: int = 11
    e10_observations_per_cell: int = 10
    e10_records: int = 2820
    e10_run_units: int = 188
    e10_pass_records: int = 1485
    e10_expected_reject_records: int = 1320
    e10_unsafe_control_records: int = 15
    repeated_warmups: int = 5
    repeated_measurements: int = 10


DEFAULT_EXPECTATIONS = Expectations()
TIE_TOLERANCE = 0.01
E2_STEADY_STATE_LATENCY_METRIC = "steady_state_query_plus_artifact_validation_ms"
E2_SELECTION_TIMING_SCOPE = "cell_level_full_selection_client_wall_ms_not_amortized"
E2_QUERY_TIMING_SCOPE = "postgres_server_planning_plus_execution_ms"
E2_STEADY_STATE_LATENCY_NOTE = (
    "E2 source total_ms_median is reported as "
    "steady_state_query_plus_artifact_validation_ms: PostgreSQL server planning "
    "+ execution + artifact-validation time. Prospective selector and EXPLAIN "
    "client-wall time are reported separately and are not amortized into this latency."
)

CSV_COLUMNS: Tuple[str, ...] = (
    "section",
    "comparison",
    "metric_kind",
    "metric_scope",
    "ratio_definition",
    "cell_count",
    "observation_count",
    "median",
    "geometric_mean",
    "p90_linear",
    "max",
    "min",
    "wins",
    "ties",
    "losses",
    "top1_count",
    "top1_rate",
    "top3_count",
    "top3_rate",
    "source_path",
    "manifest_id",
    "manifest_hashes",
    "git_commits",
    "protocol_status",
    "notes",
)


@dataclass(frozen=True)
class PerformancePreviewResult:
    metrics_csv: Path
    summary_json: Path
    summary: Mapping[str, Any]


def _fail(message: str) -> None:
    raise PerformancePreviewError(message)


def _output_reference(repo_root: Path, path: Path) -> str:
    """Return a repository-relative output path when one is available."""

    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _canonical_taxonomy_key(key: str) -> str:
    replacements = (
        ("contractaware", "admission_first"),
        ("best_production_safe", "fastest_policy_enforcement"),
        ("fastest_production_safe", "fastest_policy_enforcement"),
        ("production_safe_mode_count", "policy_enforcement_mode_count"),
    )
    for legacy, current in replacements:
        if legacy in key:
            return key.replace(legacy, current)
    return key


def _canonicalize_taxonomy_keys(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            _canonical_taxonomy_key(str(key)): _canonicalize_taxonomy_keys(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_canonicalize_taxonomy_keys(item) for item in value]
    return value


def _read_json(path: Path) -> Mapping[str, Any]:
    if not path.is_file():
        _fail("missing JSON source: {}".format(path))
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PerformancePreviewError("invalid JSON source {}: {}".format(path, exc)) from exc
    if not isinstance(value, Mapping):
        _fail("JSON source must contain an object: {}".format(path))
    return _canonicalize_taxonomy_keys(value)


def _read_yaml(path: Path) -> Mapping[str, Any]:
    if not path.is_file():
        _fail("missing YAML source: {}".format(path))
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise PerformancePreviewError("invalid YAML source {}: {}".format(path, exc)) from exc
    if not isinstance(value, Mapping):
        _fail("YAML source must contain an object: {}".format(path))
    return value


def _read_csv(path: Path, required: Iterable[str]) -> List[Dict[str, str]]:
    if not path.is_file():
        _fail("missing CSV source: {}".format(path))
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or ())
        required_fields = set(required)
        if "baseline_class" in required_fields and "evaluation_role" in fields:
            required_fields.remove("baseline_class")
        available_fields = fields | {_canonical_taxonomy_key(field) for field in fields}
        missing = sorted(required_fields - available_fields)
        if missing:
            _fail("{} is missing columns: {}".format(path, ", ".join(missing)))
        rows = [dict(row) for row in reader]
    for row in rows:
        for key in list(row):
            canonical_key = _canonical_taxonomy_key(key)
            if canonical_key != key and canonical_key not in row:
                row[canonical_key] = row[key]
        if row.get("mode"):
            row["mode"] = normalize_mode_id(row["mode"])
        if row.get("fastest_policy_enforcement_mode"):
            row["fastest_policy_enforcement_mode"] = normalize_mode_id(
                row["fastest_policy_enforcement_mode"]
            )
        role = row.get("evaluation_role") or row.get("baseline_class")
        if role:
            row["evaluation_role"] = normalize_evaluation_role(role)
    return rows


def _as_int(value: Any, label: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise PerformancePreviewError("{} must be an integer, got {!r}".format(label, value)) from exc


def _as_float(value: Any, label: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise PerformancePreviewError("{} must be numeric, got {!r}".format(label, value)) from exc
    if not math.isfinite(result):
        _fail("{} must be finite, got {!r}".format(label, value))
    return result


def _is_true(value: Any) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def _status_counts(row: Mapping[str, str], source: Path) -> Mapping[str, int]:
    try:
        value = json.loads(row.get("status_counts", ""))
    except json.JSONDecodeError as exc:
        raise PerformancePreviewError("{} contains invalid status_counts".format(source)) from exc
    if not isinstance(value, Mapping):
        _fail("{} status_counts must be an object".format(source))
    return {str(key): _as_int(count, "status_counts.{}".format(key)) for key, count in value.items()}


def _is_pass_row(row: Mapping[str, str], source: Path) -> bool:
    counts = _status_counts(row, source)
    return set(counts) == {"pass"} and counts["pass"] > 0


def _manifest_id(text: str, path: Path) -> str:
    for line in text.splitlines():
        if line.startswith("manifest_id:"):
            value = line.split(":", 1)[1].strip().strip("'\"")
            if value:
                return value
    _fail("{} does not declare manifest_id".format(path))
    raise AssertionError("unreachable")


def _load_provenance(repo_root: Path, spec: SourceSpec) -> Dict[str, Any]:
    summary_path = repo_root / "results" / "summarized" / spec.family / "summary.json"
    summary = _read_json(summary_path)
    if summary.get("experiment") != spec.experiment:
        _fail("{} has unexpected experiment {!r}".format(summary_path, summary.get("experiment")))
    protocol = summary.get("measurement_protocol")
    if not isinstance(protocol, Mapping):
        _fail("{} lacks measurement_protocol".format(summary_path))
    if protocol.get("status") != spec.expected_protocol_status:
        _fail(
            "{} has protocol status {!r}; expected {!r}".format(
                summary_path, protocol.get("status"), spec.expected_protocol_status
            )
        )
    manifest_path = repo_root / spec.manifest_path
    if not manifest_path.is_file():
        _fail("missing manifest: {}".format(manifest_path))
    manifest_text = manifest_path.read_text(encoding="utf-8")
    manifest_hash = "sha256:" + hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    recorded_hashes = sorted(str(item) for item in summary.get("manifest_hashes", []))
    if recorded_hashes != [manifest_hash]:
        _fail(
            "{} manifest hashes {!r} do not match {}".format(
                summary_path, recorded_hashes, manifest_hash
            )
        )
    commits = sorted(str(item) for item in summary.get("git_commits", []) if str(item))
    if not commits:
        _fail("{} does not record a Git commit".format(summary_path))
    return {
        "family": spec.family,
        "experiment": spec.experiment,
        "manifest_path": spec.manifest_path,
        "manifest_id": _manifest_id(manifest_text, manifest_path),
        "manifest_hashes": recorded_hashes,
        "git_commits": commits,
        "protocol_status": protocol["status"],
        "required_warmup_repetitions": protocol.get("required_warmup_repetitions"),
        "required_measured_repetitions": protocol.get("required_measured_repetitions"),
        "raw_directory": str(summary.get("input_dir", "")),
        "summary_path": "results/summarized/{}/summary.json".format(spec.family),
        "summary": summary,
    }


def _median(values: Sequence[float]) -> float:
    if not values:
        _fail("cannot summarize an empty metric")
    return float(statistics.median(values))


def _geometric_mean(values: Sequence[float]) -> float:
    if not values or any(value <= 0.0 for value in values):
        _fail("geometric mean requires positive values")
    return math.exp(sum(math.log(value) for value in values) / len(values))


def _percentile_linear(values: Sequence[float], q: float) -> float:
    if not values:
        _fail("cannot compute a percentile of no values")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = q * (len(ordered) - 1)
    lower = int(math.floor(rank))
    upper = int(math.ceil(rank))
    if lower == upper:
        return ordered[lower]
    weight = rank - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _distribution_summary(values: Sequence[float], unit: str) -> Dict[str, Any]:
    if not values:
        _fail("cannot summarize an empty distribution")
    return {
        "observation_count": len(values),
        "unit": unit,
        "median": _median(values),
        "p90_linear": _percentile_linear(values, 0.9),
        "max": max(values),
        "min": min(values),
    }


def _classify_ratio(value: float, higher_favors_admission_first: bool) -> str:
    if higher_favors_admission_first:
        if value > 1.0 + TIE_TOLERANCE:
            return "win"
        if value < 1.0 - TIE_TOLERANCE:
            return "loss"
        return "tie"
    if value < 1.0 - TIE_TOLERANCE:
        return "win"
    if value > 1.0 + TIE_TOLERANCE:
        return "loss"
    return "tie"


def _ratio_summary(
    records: Sequence[Mapping[str, Any]],
    ratio_definition: str,
    higher_favors_admission_first: bool,
    inclusive_fastest: bool = False,
) -> Dict[str, Any]:
    if not records:
        _fail("comparison {} has no cells".format(ratio_definition))
    values = [_as_float(record["ratio"], "comparison ratio") for record in records]
    outcomes: Counter[str] = Counter()
    detailed: List[Dict[str, Any]] = []
    for record, value in zip(records, values):
        if inclusive_fastest:
            if math.isclose(value, 1.0, rel_tol=1e-12, abs_tol=1e-12):
                outcome = "win"
            elif value <= 1.0 + TIE_TOLERANCE:
                outcome = "tie"
            else:
                outcome = "loss"
        else:
            outcome = _classify_ratio(value, higher_favors_admission_first)
        outcomes[outcome] += 1
        item = dict(record)
        item["outcome"] = outcome
        detailed.append(item)
    return {
        "ratio_definition": ratio_definition,
        "higher_favors_admission_first": higher_favors_admission_first,
        "tie_tolerance": TIE_TOLERANCE,
        "cell_count": len(values),
        "median": _median(values),
        "geometric_mean": _geometric_mean(values),
        "p90_linear": _percentile_linear(values, 0.9),
        "max": max(values),
        "min": min(values),
        "wins": outcomes["win"],
        "ties": outcomes["tie"],
        "losses": outcomes["loss"],
        "loss_cells": [item for item in detailed if item["outcome"] == "loss"],
        "cells": detailed,
    }


def _validate_repeated_row(
    row: Mapping[str, str],
    source: Path,
    expectations: Expectations,
) -> None:
    if row.get("protocol_status") != "ok":
        _fail("{} contains a non-protocol row".format(source))
    if _as_int(row.get("sample_count"), "sample_count") != expectations.repeated_measurements:
        _fail("{} contains a row with the wrong measured count".format(source))
    if _as_int(row.get("warmup_count"), "warmup_count") != expectations.repeated_warmups:
        _fail("{} contains a row with the wrong warmup count".format(source))
    if not _is_pass_row(row, source):
        _fail("{} contains a non-pass row in a required comparison".format(source))


def _source_fields(provenance: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        key: provenance[key]
        for key in (
            "family",
            "experiment",
            "manifest_path",
            "manifest_id",
            "manifest_hashes",
            "git_commits",
            "protocol_status",
            "required_warmup_repetitions",
            "required_measured_repetitions",
            "raw_directory",
            "summary_path",
        )
    }


def _validate_manifest_rows(
    rows: Sequence[Mapping[str, str]],
    provenance: Mapping[str, Any],
    source: Path,
) -> None:
    observed = sorted(
        {
            item
            for row in rows
            for item in str(row.get("manifest_hashes", "")).split(";")
            if item
        }
    )
    if observed != provenance["manifest_hashes"]:
        _fail("{} manifest provenance disagrees with summary".format(source))


def _aggregate_e2(
    repo_root: Path,
    provenance: Mapping[str, Any],
    expectations: Expectations,
) -> Dict[str, Any]:
    source = repo_root / "results" / "summarized" / "E2_PROTOCOL" / "cell_stats.csv"
    rows = _read_csv(
        source,
        {
            "run_kind",
            "mode",
            "baseline_class",
            "param_grid_point",
            "protocol_status",
            "sample_count",
            "warmup_count",
            "status_counts",
            "total_ms_median",
            "prospective_selection_wall_ms_median",
            "prospective_explain_wall_ms_median",
            "prospective_selection_timing_scope",
            "query_timing_scope",
            "manifest_hashes",
        },
    )
    normal = [row for row in rows if row["run_kind"] == "normal_mode"]
    _validate_manifest_rows(normal, provenance, source)
    by_cell: Dict[str, Dict[str, Dict[str, str]]] = defaultdict(dict)
    for row in normal:
        if row["mode"] in by_cell[row["param_grid_point"]]:
            _fail("{} contains a duplicate E2 cell/mode".format(source))
        by_cell[row["param_grid_point"]][row["mode"]] = row
    af_cells = {cell: modes.get(ADMISSION_FIRST_MODE) for cell, modes in by_cell.items()}
    if len(af_cells) != expectations.e2_cells or any(row is None for row in af_cells.values()):
        _fail("{} does not contain {} AdmissionFirst cells".format(source, expectations.e2_cells))
    for row in af_cells.values():
        assert row is not None
        _validate_repeated_row(row, source, expectations)

    selection_wall_values: List[float] = []
    explain_wall_values: List[float] = []
    for cell_id, row in sorted(af_cells.items()):
        assert row is not None
        selection_scope = str(row.get("prospective_selection_timing_scope") or "").strip()
        if selection_scope != E2_SELECTION_TIMING_SCOPE:
            _fail(
                "{} E2 cell {} has unstable or unexpected prospective selection timing "
                "scope {!r}; expected {!r}".format(
                    source,
                    cell_id,
                    selection_scope,
                    E2_SELECTION_TIMING_SCOPE,
                )
            )
        query_scope = str(row.get("query_timing_scope") or "").strip()
        if query_scope != E2_QUERY_TIMING_SCOPE:
            _fail(
                "{} E2 cell {} has unstable or unexpected query timing scope {!r}; "
                "expected {!r}".format(
                    source,
                    cell_id,
                    query_scope,
                    E2_QUERY_TIMING_SCOPE,
                )
            )
        selection_wall_ms = _as_float(
            row["prospective_selection_wall_ms_median"],
            "E2 prospective_selection_wall_ms_median",
        )
        explain_wall_ms = _as_float(
            row["prospective_explain_wall_ms_median"],
            "E2 prospective_explain_wall_ms_median",
        )
        if selection_wall_ms < 0.0 or explain_wall_ms < 0.0:
            _fail("{} E2 selector wall time must be non-negative".format(source))
        selection_wall_values.append(selection_wall_ms)
        explain_wall_values.append(explain_wall_ms)

    comparison_modes = sorted(
        {
            mode
            for modes in by_cell.values()
            for mode, row in modes.items()
            if mode != ADMISSION_FIRST_MODE
            and row["evaluation_role"] == EvaluationRole.POLICY_ENFORCEMENT.value
        },
        key=mode_execution_order_key,
    )
    comparisons: List[Dict[str, Any]] = []
    for mode in comparison_modes:
        records = []
        unavailable = []
        for cell_id, modes in sorted(by_cell.items()):
            admission_first = modes[ADMISSION_FIRST_MODE]
            comparator = modes.get(mode)
            if comparator is None or not _is_pass_row(comparator, source):
                unavailable.append(cell_id)
                continue
            _validate_repeated_row(comparator, source, expectations)
            admission_first_ms = _as_float(admission_first["total_ms_median"], "E2 AdmissionFirst total_ms_median")
            baseline_ms = _as_float(comparator["total_ms_median"], "E2 baseline total_ms_median")
            records.append(
                {
                    "cell_id": cell_id,
                    "baseline_mode": mode,
                    "admission_first_total_ms_median": admission_first_ms,
                    "baseline_total_ms_median": baseline_ms,
                    "ratio": baseline_ms / admission_first_ms,
                }
            )
        if records:
            summary = _ratio_summary(
                records,
                "baseline_{}_median / admission_first_{}_median".format(
                    E2_STEADY_STATE_LATENCY_METRIC,
                    E2_STEADY_STATE_LATENCY_METRIC,
                ),
                True,
            )
            summary["comparison"] = mode
            summary["unavailable_or_rejected_cells"] = unavailable
            comparisons.append(summary)

    fastest_records = []
    for cell_id, modes in sorted(by_cell.items()):
        admission_first = modes[ADMISSION_FIRST_MODE]
        applicable = [
            row
            for mode, row in modes.items()
            if mode != ADMISSION_FIRST_MODE
            and row["evaluation_role"] == EvaluationRole.POLICY_ENFORCEMENT.value
            and _is_pass_row(row, source)
        ]
        if not applicable:
            _fail("E2 cell {} has no applicable fixed baseline".format(cell_id))
        fastest = min(
            applicable,
            key=lambda row: (
                _as_float(row["total_ms_median"], "total_ms_median"),
                mode_execution_order_key(row["mode"]),
            ),
        )
        admission_first_ms = _as_float(admission_first["total_ms_median"], "total_ms_median")
        baseline_ms = _as_float(fastest["total_ms_median"], "total_ms_median")
        fastest_records.append(
            {
                "cell_id": cell_id,
                "baseline_mode": fastest["mode"],
                "admission_first_total_ms_median": admission_first_ms,
                "baseline_total_ms_median": baseline_ms,
                "ratio": baseline_ms / admission_first_ms,
            }
        )
    fastest = _ratio_summary(
        fastest_records,
        "fastest_applicable_fixed_{}_median / admission_first_{}_median".format(
            E2_STEADY_STATE_LATENCY_METRIC,
            E2_STEADY_STATE_LATENCY_METRIC,
        ),
        True,
    )
    fastest["comparison"] = "fastest-applicable-fixed"

    oracle_path = repo_root / "results" / "summarized" / "E2_PROTOCOL" / "template_oracle_summary.json"
    oracle = _read_json(oracle_path)
    if _as_int(oracle.get("oracle_cell_count"), "E2 oracle_cell_count") != expectations.e2_cells:
        _fail("{} has the wrong oracle cell count".format(oracle_path))
    return {
        "source": {
            **_source_fields(provenance),
            "metric_source": "results/summarized/E2_PROTOCOL/cell_stats.csv",
            "oracle_source": "results/summarized/E2_PROTOCOL/template_oracle_summary.json",
        },
        "denominator_cells": expectations.e2_cells,
        "latency_metric": E2_STEADY_STATE_LATENCY_METRIC,
        "latency_source_column": "total_ms_median",
        "admission_first_prospective_selection": {
            "cell_count": expectations.e2_cells,
            "observation_level": "one case-level value per AdmissionFirst case",
            "selection_timing_scope": E2_SELECTION_TIMING_SCOPE,
            "query_timing_scope": E2_QUERY_TIMING_SCOPE,
            "prospective_selection_wall_ms_median": _distribution_summary(
                selection_wall_values,
                "ms",
            ),
            "prospective_explain_wall_ms_median": _distribution_summary(
                explain_wall_values,
                "ms",
            ),
            "note": (
                "Selector distributions contain one case-level measurement for each of "
                "the {} E2 AdmissionFirst cases; repeated query measurements are not "
                "counted as independent selector runs, and selector time is not included "
                "in steady-state query latency."
            ).format(expectations.e2_cells),
        },
        "admission_first_measured_best": {
            "count": _as_int(oracle.get("chosen_is_measured_best_count"), "E2 chosen best"),
            "rate": oracle.get("chosen_is_measured_best_rate"),
            "oracle_gap_median": oracle.get("median_oracle_gap"),
            "oracle_gap_p90": oracle.get("p90_oracle_gap"),
            "oracle_gap_max": oracle.get("max_oracle_gap"),
        },
        "fastest_applicable_fixed": fastest,
        "fixed_mode_comparisons": comparisons,
        "note": (
            "E2 has no NativePG baseline; fixed-mode comparisons include every cell "
            "where that fixed mode passed and report all unavailable cells. "
            + E2_STEADY_STATE_LATENCY_NOTE
        ),
    }


def _aggregate_e3(
    repo_root: Path,
    provenance: Mapping[str, Any],
    expectations: Expectations,
) -> Dict[str, Any]:
    source = repo_root / "results" / "summarized" / "E3_SF1_RAWPG_V1" / "e3_loss_table.csv"
    rows = _read_csv(
        source,
        {
            "query_id",
            "policy_config_id",
            "fastest_policy_enforcement_mode",
            "best_total_ms_median",
            "admission_first_total_ms_median",
            "admission_first_slowdown_vs_fastest",
            "native_pg_rls_total_ms_median",
            "native_pg_rls_physical_design_total_ms_median",
            "sample_count",
            "warmup_count",
            "protocol_status",
            "manifest_hashes",
        },
    )
    if len(rows) != expectations.e3_cells:
        _fail("{} has {} cells; expected {}".format(source, len(rows), expectations.e3_cells))
    keys = {(row["query_id"], row["policy_config_id"]) for row in rows}
    if len(keys) != expectations.e3_cells:
        _fail("{} contains duplicate E3 cells".format(source))
    recorded_manifests = sorted({row["manifest_hashes"] for row in rows})
    if recorded_manifests != provenance["manifest_hashes"]:
        _fail("{} manifest provenance disagrees with summary".format(source))
    for row in rows:
        if row["protocol_status"] != "ok":
            _fail("{} contains a non-protocol E3 cell".format(source))
        if _as_int(row["sample_count"], "E3 sample_count") != expectations.repeated_measurements:
            _fail("{} contains the wrong E3 measured count".format(source))
        if _as_int(row["warmup_count"], "E3 warmup_count") != expectations.repeated_warmups:
            _fail("{} contains the wrong E3 warmup count".format(source))

    def records_for(column: str, slowdown: bool) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        for row in rows:
            admission_first_ms = _as_float(row["admission_first_total_ms_median"], "E3 AdmissionFirst latency")
            baseline_ms = _as_float(row[column], "E3 baseline latency")
            ratio = admission_first_ms / baseline_ms if slowdown else baseline_ms / admission_first_ms
            if slowdown:
                recorded = _as_float(
                    row["admission_first_slowdown_vs_fastest"],
                    "E3 recorded slowdown versus fastest",
                )
                if ratio < 1.0 or not math.isclose(
                    ratio, recorded, rel_tol=1e-12, abs_tol=1e-12
                ):
                    _fail("{} contains an inconsistent fastest baseline".format(source))
            records.append(
                {
                    "cell_id": "{}/{}".format(row["query_id"], row["policy_config_id"]),
                    "query_id": row["query_id"],
                    "policy_config_id": row["policy_config_id"],
                    "baseline_mode": row["fastest_policy_enforcement_mode"] if slowdown else column,
                    "admission_first_total_ms_median": admission_first_ms,
                    "baseline_total_ms_median": baseline_ms,
                    "ratio": ratio,
                }
            )
        return records

    native = _ratio_summary(
        records_for("native_pg_rls_total_ms_median", False),
        "native_pg_rls_total_ms_median / admission_first_total_ms_median",
        True,
    )
    native["comparison"] = "NativePG-RLS"
    native_pd = _ratio_summary(
        records_for("native_pg_rls_physical_design_total_ms_median", False),
        "native_pg_rls_physical_design_total_ms_median / admission_first_total_ms_median",
        True,
    )
    native_pd["comparison"] = "NativePG-RLS+PD"
    fastest = _ratio_summary(
        records_for("best_total_ms_median", True),
        "admission_first_total_ms_median / fastest_policy_enforcement_total_ms_median",
        False,
        inclusive_fastest=True,
    )
    fastest["comparison"] = "fastest-policy-enforcement"

    loss_summary_path = (
        repo_root
        / "results"
        / "summarized"
        / "E3_SF1_RAWPG_V1"
        / "e3_loss_table_summary.json"
    )
    source_summary = _read_json(loss_summary_path)
    if _as_int(source_summary.get("cell_count"), "E3 source cell_count") != expectations.e3_cells:
        _fail("{} has the wrong E3 denominator".format(loss_summary_path))
    canonicalization = source_summary.get("runner_sql_canonicalization")
    if not isinstance(canonicalization, Mapping):
        _fail("{} lacks runner-SQL canonicalization metadata".format(loss_summary_path))
    if canonicalization.get("method") != "pooled_measured_samples_by_exact_runner_sql_hash_v1":
        _fail("{} uses an unexpected runner-SQL canonicalization method".format(loss_summary_path))
    if canonicalization.get("selector_changed") is not False:
        _fail("{} does not attest that canonicalization left the selector unchanged".format(loss_summary_path))
    if _as_int(
        canonicalization.get("mode_rows_retained"),
        "E3 canonicalization mode_rows_retained",
    ) < expectations.e3_cells:
        _fail("{} does not retain the full E3 mode denominator".format(loss_summary_path))
    fastest["source_reported_nearest_rank_p90"] = source_summary.get("admission_first_slowdown_p90")
    source_winners = source_summary.get("winner_bucket_counts", {})
    if isinstance(source_winners, Mapping):
        normalized_winners: Dict[str, Any] = {}
        for name, count in source_winners.items():
            try:
                name = normalize_mode_id(str(name))
            except ValueError:
                name = str(name)
            normalized_winners[name] = count
        fastest["winner_bucket_counts"] = normalized_winners
    else:
        fastest["winner_bucket_counts"] = {}
    fastest["runner_sql_canonicalization"] = dict(canonicalization)
    return {
        "source": {
            **_source_fields(provenance),
            "metric_source": "results/summarized/E3_SF1_RAWPG_V1/e3_loss_table.csv",
            "source_summary": "results/summarized/E3_SF1_RAWPG_V1/e3_loss_table_summary.json",
        },
        "denominator_cells": expectations.e3_cells,
        "latency_metric": "runner-SQL-canonicalized total_ms_median",
        "runner_sql_canonicalization": dict(canonicalization),
        "comparisons": [native, native_pd, fastest],
        "p90_note": "Preview p90 uses linear interpolation for every section; the formal E3 loss summary's nearest-rank p90 is retained separately. Exact duplicate runner_sql_hash modes share the median of their pooled measured samples before fastest policy-enforcement selection; every mode row remains reported and the selector is unchanged.",
    }


def _aggregate_e4(
    repo_root: Path,
    provenance: Mapping[str, Any],
    expectations: Expectations,
) -> Dict[str, Any]:
    source = repo_root / "results" / "summarized" / "E4_PROTOCOL" / "cell_stats.csv"
    rows = _read_csv(
        source,
        {
            "run_kind",
            "query_id",
            "mode",
            "param_pair_id",
            "status_counts",
            "total_ms_median",
            "sample_count",
            "warmup_count",
            "protocol_status",
            "manifest_hashes",
        },
    )
    normal = [row for row in rows if row["run_kind"] == "normal_mode" and row["mode"] in {ADMISSION_FIRST_MODE, "local-greedy"}]
    _validate_manifest_rows(normal, provenance, source)
    for row in normal:
        if (
            row["protocol_status"] != "ok"
            or _as_int(row["sample_count"], "E4 sample_count")
            != expectations.repeated_measurements
            or _as_int(row["warmup_count"], "E4 warmup_count")
            != expectations.repeated_warmups
        ):
            _fail("{} contains an E4 row with unexpected repetition metadata".format(source))
    by_query: Dict[str, Dict[str, Dict[str, str]]] = defaultdict(dict)
    for row in normal:
        if row["mode"] in by_query[row["query_id"]]:
            _fail("{} contains a duplicate E4 cell/mode".format(source))
        by_query[row["query_id"]][row["mode"]] = row
    if len(by_query) != expectations.e4_variants:
        _fail("{} has {} E4 variants; expected {}".format(source, len(by_query), expectations.e4_variants))
    details = []
    stress_records = []
    control_records = []
    for query_id, modes in sorted(by_query.items()):
        if set(modes) != {ADMISSION_FIRST_MODE, "local-greedy"}:
            _fail("E4 variant {} lacks one compared mode".format(query_id))
        admission_first = modes[ADMISSION_FIRST_MODE]
        local = modes["local-greedy"]
        if not _is_pass_row(admission_first, source):
            _fail("E4 AdmissionFirst did not pass {}".format(query_id))
        admission_first_ms = _as_float(admission_first["total_ms_median"], "E4 AdmissionFirst latency")
        local_status = _status_counts(local, source)
        is_stress = query_id.endswith("_B")
        detail: Dict[str, Any] = {
            "pair_id": admission_first["param_pair_id"],
            "query_id": query_id,
            "variant": "stress" if is_stress else "control",
            "admission_first_status": "pass",
            "local_greedy_status_counts": local_status,
            "admission_first_total_ms": admission_first_ms,
        }
        if set(local_status) == {"pass"}:
            local_ms = _as_float(local["total_ms_median"], "E4 LocalGreedy latency")
            detail["local_greedy_total_ms"] = local_ms
            detail["admission_first_speedup"] = local_ms / admission_first_ms
            record = {
                "cell_id": query_id,
                "pair_id": admission_first["param_pair_id"],
                "admission_first_total_ms_median": admission_first_ms,
                "baseline_total_ms_median": local_ms,
                "baseline_mode": "local-greedy",
                "ratio": local_ms / admission_first_ms,
            }
            (stress_records if is_stress else control_records).append(record)
        details.append(detail)
    stress = _ratio_summary(
        stress_records,
        "local_greedy_total_ms / admission_first_total_ms",
        True,
    )
    stress["comparison"] = "LocalGreedy stress variants with numeric outcomes"
    control = _ratio_summary(
        control_records,
        "local_greedy_total_ms / admission_first_total_ms",
        True,
    )
    control["comparison"] = "LocalGreedy neutral controls"
    return {
        "source": {
            **_source_fields(provenance),
            "metric_source": "results/summarized/E4_PROTOCOL/cell_stats.csv",
        },
        "variant_count": expectations.e4_variants,
        "pair_count": len({detail["pair_id"] for detail in details}),
        "stress_comparison": stress,
        "neutral_control_comparison": control,
        "expected_reject_stress_count": sum(
            detail["variant"] == "stress"
            and set(detail["local_greedy_status_counts"]) == {"expected_reject"}
            for detail in details
        ),
        "variants": details,
        "evidence_grade": "repeated_protocol",
        "limitation": (
            "E4 is a controlled parent-continuation study with declared templates, "
            "not a prospective AdmissionFirst experiment."
        ),
    }


def _aggregate_e5(
    repo_root: Path,
    provenance: Mapping[str, Any],
    expectations: Expectations,
) -> Dict[str, Any]:
    source = repo_root / "results" / "summarized" / "E5_PROTOCOL" / "cell_stats.csv"
    rows = _read_csv(
        source,
        {
            "run_kind",
            "mode",
            "param_witness_id",
            "param_witness_kind",
            "param_fixed_mode_under_test",
            "param_N",
            "e5_regret_ratio_median",
            "e5_effective_latency_ms_median",
            "e5_best_effective_latency_ms_median",
            "status_counts",
            "sample_count",
            "warmup_count",
            "protocol_status",
            "manifest_hashes",
        },
    )
    normal = [row for row in rows if row["run_kind"] == "normal_mode"]
    _validate_manifest_rows(normal, provenance, source)
    for row in normal:
        if (
            row["protocol_status"] != "ok"
            or _as_int(row["sample_count"], "E5 sample_count")
            != expectations.repeated_measurements
            or _as_int(row["warmup_count"], "E5 warmup_count")
            != expectations.repeated_warmups
        ):
            _fail("{} contains an E5 row with unexpected repetition metadata".format(source))
    by_cell: Dict[Tuple[str, str], Dict[str, Dict[str, str]]] = defaultdict(dict)
    for row in normal:
        key = (row["param_witness_id"], row["param_N"])
        if row["mode"] in by_cell[key]:
            _fail("{} contains a duplicate E5 cell/mode".format(source))
        by_cell[key][row["mode"]] = row
    witness_ids = {key[0] for key in by_cell}
    if len(witness_ids) != expectations.e5_witnesses:
        _fail(
            "{} has {} E5 witnesses; expected {}".format(
                source, len(witness_ids), expectations.e5_witnesses
            )
        )
    if len(by_cell) != expectations.e5_cells:
        _fail(
            "{} has {} E5 witness/N cells; expected {}".format(
                source, len(by_cell), expectations.e5_cells
            )
        )
    records: List[Dict[str, Any]] = []
    details: List[Dict[str, Any]] = []
    for (witness_id, n_value), modes in sorted(by_cell.items()):
        exemplar = next(iter(modes.values()))
        fixed_mode = exemplar["param_fixed_mode_under_test"]
        fixed = modes.get(fixed_mode)
        if fixed is None or not _is_pass_row(fixed, source):
            _fail(
                "E5 witness {} N={} lacks its fixed mode {}".format(
                    witness_id, n_value, fixed_mode
                )
            )
        _validate_repeated_row(fixed, source, expectations)
        fixed_effective_ms = _as_float(
            fixed["e5_effective_latency_ms_median"], "E5 fixed effective latency"
        )
        best_effective_ms = _as_float(
            fixed["e5_best_effective_latency_ms_median"], "E5 best effective latency"
        )
        if best_effective_ms <= 0.0:
            _fail("E5 best effective latency must be positive")
        fixed_regret = fixed_effective_ms / best_effective_ms
        item = {
            "cell_id": "{}:N={}".format(witness_id, n_value),
            "witness_id": witness_id,
            "N": _as_int(n_value, "E5 N"),
            "witness_kind": fixed["param_witness_kind"],
            "baseline_mode": fixed_mode,
            "fixed_mode_regret": fixed_regret,
            "fixed_effective_latency_ms": fixed_effective_ms,
            "best_effective_latency_ms": best_effective_ms,
            "ratio": fixed_regret,
        }
        records.append(item)
        details.append(dict(item))
    regret_records = [record for record in records if record["witness_kind"] == "regret_witness"]
    regret_only = _ratio_summary(
        regret_records,
        "fixed_mode_effective_latency / BestEnumeratedAdmissible_effective_latency",
        True,
    )
    regret_only["comparison"] = "fixed-representation regret on declared W1-W5 cells"
    control_records = [
        record for record in records if record["witness_kind"] == "positive_control"
    ]
    positive_control = _ratio_summary(
        control_records,
        "fixed_mode_effective_latency / BestEnumeratedAdmissible_effective_latency",
        True,
    )
    positive_control["comparison"] = "MAV positive control"
    witness_maxima = {
        witness_id: max(
            record["fixed_mode_regret"]
            for record in regret_records
            if record["witness_id"] == witness_id
        )
        for witness_id in sorted(
            {record["witness_id"] for record in regret_records}
        )
    }
    return {
        "source": {
            **_source_fields(provenance),
            "metric_source": "results/summarized/E5_PROTOCOL/cell_stats.csv",
        },
        "witness_count": expectations.e5_witnesses,
        "witness_N_cell_count": len(records),
        "declared_regret_witnesses": regret_only,
        "positive_control": positive_control,
        "per_witness_max_regret": witness_maxima,
        "cells": details,
        "evidence_grade": "repeated_protocol",
        "limitation": (
            "E5 is a fixed-representation regret witness against measured "
            "BestEnumeratedAdmissible. It is not evidence for a prospective "
            "AdmissionFirst selector; the MAV positive control is reported separately."
        ),
    }


def _aggregate_e8(
    repo_root: Path,
    provenance: Mapping[str, Any],
    expectations: Expectations,
) -> Dict[str, Any]:
    source = repo_root / "results" / "summarized" / "E8_COST_1E6" / "cell_stats.csv"
    rows = _read_csv(
        source,
        {
            "run_kind",
            "query_id",
            "mode",
            "baseline_class",
            "protocol_status",
            "sample_count",
            "warmup_count",
            "status_counts",
            "artifact_amortized_declared_q_u_ms_median",
            "param_expected_action",
            "param_expected_effect",
            "manifest_hashes",
        },
    )
    normal = [row for row in rows if row["run_kind"] == "normal_mode"]
    _validate_manifest_rows(normal, provenance, source)
    by_scenario: Dict[str, Dict[str, Dict[str, str]]] = defaultdict(dict)
    for row in normal:
        if row["mode"] in by_scenario[row["query_id"]]:
            _fail("{} contains a duplicate E8 scenario/mode".format(source))
        by_scenario[row["query_id"]][row["mode"]] = row
    if len(by_scenario) != expectations.e8_scenarios:
        _fail("{} has {} E8 scenarios; expected {}".format(source, len(by_scenario), expectations.e8_scenarios))

    conservative_records = []
    native_records = []
    fastest_records = []
    details = []
    for scenario, modes in sorted(by_scenario.items()):
        if len(modes) != expectations.e8_modes_per_scenario:
            _fail("E8 scenario {} has {} modes".format(scenario, len(modes)))
        admission_first = modes.get(ADMISSION_FIRST_MODE)
        conservative = modes.get("conservative-barrier")
        native = modes.get("native-pg-rls-physical-design")
        if admission_first is None or conservative is None or native is None:
            _fail("E8 scenario {} lacks a required comparison mode".format(scenario))
        for required in (admission_first, conservative, native):
            _validate_repeated_row(required, source, expectations)
        admission_first_ms = _as_float(
            admission_first["artifact_amortized_declared_q_u_ms_median"], "E8 AdmissionFirst declared cost"
        )
        conservative_ms = _as_float(
            conservative["artifact_amortized_declared_q_u_ms_median"],
            "E8 conservative declared cost",
        )
        native_ms = _as_float(
            native["artifact_amortized_declared_q_u_ms_median"], "E8 native declared cost"
        )
        policy_enforcement = [
            row
            for row in modes.values()
            if row["evaluation_role"] == EvaluationRole.POLICY_ENFORCEMENT.value
            and _is_pass_row(row, source)
            and row["artifact_amortized_declared_q_u_ms_median"]
            and _as_float(
                row["artifact_amortized_declared_q_u_ms_median"], "E8 policy-enforcement cost"
            )
            > 0.0
        ]
        if not policy_enforcement:
            _fail("E8 scenario {} has no policy-enforcement mode".format(scenario))
        for candidate in policy_enforcement:
            _validate_repeated_row(candidate, source, expectations)
        best = min(
            policy_enforcement,
            key=lambda row: (
                _as_float(
                    row["artifact_amortized_declared_q_u_ms_median"],
                    "E8 policy-enforcement cost",
                ),
                mode_execution_order_key(row["mode"]),
            ),
        )
        best_ms = _as_float(
            best["artifact_amortized_declared_q_u_ms_median"], "E8 best declared cost"
        )
        common = {
            "cell_id": scenario,
            "scenario": scenario,
            "expected_action": admission_first["param_expected_action"],
            "expected_effect": admission_first["param_expected_effect"],
            "admission_first_amortized_declared_ms": admission_first_ms,
        }
        conservative_records.append(
            {
                **common,
                "baseline_mode": "conservative-barrier",
                "baseline_amortized_declared_ms": conservative_ms,
                "ratio": conservative_ms / admission_first_ms,
            }
        )
        native_records.append(
            {
                **common,
                "baseline_mode": "native-pg-rls-physical-design",
                "baseline_amortized_declared_ms": native_ms,
                "ratio": native_ms / admission_first_ms,
            }
        )
        fastest_records.append(
            {
                **common,
                "baseline_mode": best["mode"],
                "baseline_amortized_declared_ms": best_ms,
                "ratio": admission_first_ms / best_ms,
            }
        )
        details.append(
            {
                **common,
                "conservative_barrier_ms": conservative_ms,
                "native_pg_rls_pd_ms": native_ms,
                "fastest_policy_enforcement_mode": best["mode"],
                "fastest_policy_enforcement_ms": best_ms,
                "admission_first_slowdown_vs_fastest": admission_first_ms / best_ms,
            }
        )
    conservative_summary = _ratio_summary(
        conservative_records,
        "conservative_barrier_amortized_declared_ms / admission_first_amortized_declared_ms",
        True,
    )
    conservative_summary["comparison"] = "ConservativeBarrier"
    native_summary = _ratio_summary(
        native_records,
        "native_pg_rls_pd_amortized_declared_ms / admission_first_amortized_declared_ms",
        True,
    )
    native_summary["comparison"] = "NativePG-RLS+PD"
    fastest_summary = _ratio_summary(
        fastest_records,
        "admission_first_amortized_declared_ms / fastest_policy_enforcement_amortized_declared_ms",
        False,
        inclusive_fastest=True,
    )
    fastest_summary["comparison"] = "fastest-policy-enforcement"
    artifact = provenance["summary"].get("artifact_cost_analysis")
    if not isinstance(artifact, Mapping):
        _fail("E8 summary lacks artifact_cost_analysis")
    if _as_int(artifact.get("scenario_count"), "E8 scenario_count") != expectations.e8_scenarios:
        _fail("E8 artifact summary has the wrong scenario count")
    return {
        "source": {
            **_source_fields(provenance),
            "metric_source": "results/summarized/E8_COST_1E6/cell_stats.csv",
            "artifact_summary_source": "results/summarized/E8_COST_1E6/artifact_cost_summary.json",
        },
        "scenario_count": expectations.e8_scenarios,
        "cost_metric": "artifact_amortized_declared_q_u_ms_median",
        "comparisons": [conservative_summary, native_summary, fastest_summary],
        "correctness_and_actions": {
            "measured_record_count": artifact.get("measured_record_count"),
            "admission_first_wrong_results": artifact.get("admission_first_wrong_results"),
            "diagnostic_wrong_results": artifact.get("diagnostic_wrong_results"),
            "admission_first_actions": artifact.get("admission_first_actions", {}),
            "admission_first_templates": artifact.get("admission_first_templates", {}),
        },
        "scenarios": details,
        "note": "All 48 declared-Q/U scenarios are included. Every non-policy-enforcement role, including contract-violation and conservative controls, is excluded from fastest policy-enforcement latency.",
    }


def _aggregate_e9(
    repo_root: Path,
    provenance: Mapping[str, Any],
    expectations: Expectations,
) -> Dict[str, Any]:
    manifest_path = repo_root / str(provenance["manifest_path"])
    manifest = _read_yaml(manifest_path)
    raw_modes = manifest.get("modes")
    repetitions = manifest.get("repetitions")
    if not isinstance(raw_modes, Sequence) or isinstance(raw_modes, (str, bytes)):
        _fail("{} does not declare E9 modes".format(manifest_path))
    try:
        modes = tuple(normalize_mode_id(str(mode)) for mode in raw_modes if str(mode))
    except ValueError as exc:
        raise PerformancePreviewError(f"{manifest_path}: {exc}") from exc
    if not modes or len(modes) != len(raw_modes) or len(set(modes)) != len(modes):
        _fail("{} contains empty or duplicate E9 modes".format(manifest_path))
    if ADMISSION_FIRST_MODE not in modes:
        _fail("{} does not declare the AdmissionFirst E9 mode".format(manifest_path))
    if not isinstance(repetitions, Mapping):
        _fail("{} does not declare E9 repetitions".format(manifest_path))
    warmup_repetitions = _as_int(repetitions.get("warmup"), "E9 manifest warmups")
    measured_repetitions = _as_int(repetitions.get("measured"), "E9 manifest measurements")
    if warmup_repetitions != expectations.repeated_warmups:
        _fail("{} has the wrong E9 warmup count".format(manifest_path))
    if measured_repetitions != expectations.repeated_measurements:
        _fail("{} has the wrong E9 measured count".format(manifest_path))

    summary = provenance["summary"]
    protocol = summary.get("measurement_protocol")
    if not isinstance(protocol, Mapping):
        _fail("E9 summary lacks measurement_protocol")
    mode_cell_count = _as_int(protocol.get("cell_count"), "E9 protocol cell_count")
    if mode_cell_count != expectations.e9_mode_cells:
        _fail(
            "E9 summary has {} mode-cells; expected {}".format(
                mode_cell_count, expectations.e9_mode_cells
            )
        )
    if mode_cell_count % len(modes):
        _fail("E9 mode-cell denominator is not balanced across manifest modes")
    cells_per_mode = mode_cell_count // len(modes)
    expected_records_per_mode = cells_per_mode * (
        warmup_repetitions + measured_repetitions
    )
    expected_record_count = mode_cell_count * (
        warmup_repetitions + measured_repetitions
    )
    expected_admission_first_measurements = cells_per_mode * measured_repetitions
    expected_protocol = {
        "cells_meeting_required_repetitions": mode_cell_count,
        "required_warmup_repetitions": warmup_repetitions,
        "required_measured_repetitions": measured_repetitions,
    }
    for field, expected in expected_protocol.items():
        if _as_int(protocol.get(field), "E9 protocol {}".format(field)) != expected:
            _fail("E9 summary disagrees with the manifest-derived {}".format(field))
    if _as_int(summary.get("record_count"), "E9 record_count") != expected_record_count:
        _fail("E9 summary does not contain the manifest-derived record denominator")
    summary_mode_counts = summary.get("mode_counts")
    if not isinstance(summary_mode_counts, Mapping):
        _fail("E9 summary lacks mode_counts")
    if {
        normalize_mode_id(str(mode)): _as_int(count, "E9 summary mode count")
        for mode, count in summary_mode_counts.items()
    } != {mode: expected_records_per_mode for mode in modes}:
        _fail("E9 summary mode counts do not match the complete manifest denominator")

    summary_dir = repo_root / "results" / "summarized" / "SIGMOD_CURRENT_E9"
    cells_path = summary_dir / "cell_stats.csv"
    cell_rows = _read_csv(
        cells_path,
        {
            "run_kind",
            "mode",
            "sample_count",
            "warmup_count",
            "total_record_count",
            "protocol_status",
            "status_counts",
            "manifest_hashes",
        },
    )
    if len(cell_rows) != mode_cell_count:
        _fail("{} has {} mode-cells; expected {}".format(cells_path, len(cell_rows), mode_cell_count))
    if any(row["run_kind"] != "normal_mode" for row in cell_rows):
        _fail("{} contains a non-normal E9 mode-cell".format(cells_path))
    _validate_manifest_rows(cell_rows, provenance, cells_path)
    cell_mode_counts = Counter(row["mode"] for row in cell_rows)
    if cell_mode_counts != Counter({mode: cells_per_mode for mode in modes}):
        _fail("{} is not balanced across the manifest modes".format(cells_path))
    for row in cell_rows:
        _validate_repeated_row(row, cells_path, expectations)
        if _as_int(row["total_record_count"], "E9 total_record_count") != (
            warmup_repetitions + measured_repetitions
        ):
            _fail("{} contains an incomplete E9 mode-cell".format(cells_path))

    runs_path = summary_dir / "runs.csv"
    run_rows = _read_csv(
        runs_path,
        {
            "mode",
            "status",
            "manifest_hash",
            "measurement_phase",
            "planning_ms",
            "postgres_planning_ms",
            "total_ms",
            "planning_total_ratio",
        },
    )
    if len(run_rows) != expected_record_count:
        _fail("{} has {} records; expected {}".format(runs_path, len(run_rows), expected_record_count))
    _validate_manifest_rows(
        [{"manifest_hashes": row["manifest_hash"]} for row in run_rows],
        provenance,
        runs_path,
    )
    if Counter(row["mode"] for row in run_rows) != Counter(
        {mode: expected_records_per_mode for mode in modes}
    ):
        _fail("{} mode counts do not match the complete manifest denominator".format(runs_path))
    if Counter(row["status"] for row in run_rows) != Counter({"pass": expected_record_count}):
        _fail("{} contains a non-pass E9 record".format(runs_path))

    admission_first_rows = [
        row
        for row in run_rows
        if row["mode"] == ADMISSION_FIRST_MODE and row["measurement_phase"] == "measured"
    ]
    if len(admission_first_rows) != expected_admission_first_measurements:
        _fail(
            "{} has {} measured AdmissionFirst executions; expected {}".format(
                runs_path,
                len(admission_first_rows),
                expected_admission_first_measurements,
            )
        )
    planning_values: List[float] = []
    postgres_planning_values: List[float] = []
    recorded_planner_plus_execution_values: List[float] = []
    derived_three_part_values: List[float] = []
    planning_fractions: List[float] = []
    for row in admission_first_rows:
        planning_ms = _as_float(row["planning_ms"], "E9 AdmissionFirst planning_ms")
        postgres_planning_ms = _as_float(
            row["postgres_planning_ms"], "E9 AdmissionFirst postgres_planning_ms"
        )
        recorded_total_ms = _as_float(
            row["total_ms"], "E9 AdmissionFirst recorded total_ms"
        )
        recorded_fraction = _as_float(
            row["planning_total_ratio"], "E9 AdmissionFirst planning_total_ratio"
        )
        if planning_ms < 0.0 or postgres_planning_ms < 0.0 or recorded_total_ms <= 0.0:
            _fail(
                "{} contains a negative planning time or non-positive recorded total_ms".format(
                    runs_path
                )
            )
        computed_fraction = planning_ms / recorded_total_ms
        if not math.isclose(
            recorded_fraction, computed_fraction, rel_tol=1e-9, abs_tol=1e-12
        ):
            _fail("{} contains an inconsistent planning_total_ratio".format(runs_path))
        planning_values.append(planning_ms)
        postgres_planning_values.append(postgres_planning_ms)
        recorded_planner_plus_execution_values.append(recorded_total_ms)
        derived_three_part_values.append(recorded_total_ms + postgres_planning_ms)
        planning_fractions.append(computed_fraction)

    return {
        "source": {
            **_source_fields(provenance),
            "runs_source": "results/summarized/SIGMOD_CURRENT_E9/runs.csv",
            "metric_source": "results/summarized/SIGMOD_CURRENT_E9/cell_stats.csv",
        },
        "record_count": expected_record_count,
        "mode_cell_count": mode_cell_count,
        "cells_per_mode": cells_per_mode,
        "mode_record_counts": {mode: expected_records_per_mode for mode in modes},
        "warmup_repetitions_per_mode_cell": warmup_repetitions,
        "measured_repetitions_per_mode_cell": measured_repetitions,
        "admission_first_measured_observation_count": len(admission_first_rows),
        "admission_first_planning_ms": _distribution_summary(planning_values, "ms"),
        "admission_first_postgres_planning_ms": _distribution_summary(
            postgres_planning_values, "ms"
        ),
        "admission_first_recorded_planner_plus_pg_execution_ms": _distribution_summary(
            recorded_planner_plus_execution_values, "ms"
        ),
        "admission_first_derived_planner_plus_pg_planning_plus_execution_ms": (
            _distribution_summary(derived_three_part_values, "ms")
        ),
        "admission_first_planning_fraction": _distribution_summary(
            planning_fractions, "fraction"
        ),
        "note": (
            "All {} E9 run records and all {} manifest case--mode pairs are validated. "
            "Latency distributions use all {} measured AdmissionFirst executions; "
            "recorded total_ms is CAPRLS planning_ms plus PostgreSQL execution_ms and "
            "excludes PostgreSQL Planning Time. The derived three-part latency adds the "
            "separately recorded postgres_planning_ms; no overhead threshold or E9 "
            "hard gate is applied."
        ).format(expected_record_count, mode_cell_count, len(admission_first_rows)),
    }


def _validate_e10_run_evidence(
    repo_root: Path,
    provenance: Mapping[str, Any],
    expectations: Expectations,
) -> Dict[str, Any]:
    source = repo_root / "results" / "summarized" / "SIGMOD_CURRENT_E10" / "runs.csv"
    rows = _read_csv(
        source,
        {
            "raw_path",
            "run_id",
            "manifest_hash",
            "run_kind",
            "query_id",
            "policy_id",
            "context_id",
            "mode",
            "template_id",
            "baseline_class",
            "status",
            "oracle_status",
            "known_invalid_accepted",
            "known_valid_rejected",
            "runtime_audit_status",
            "unauthorized_observations",
            "result_hash",
            "measurement_phase",
            "measurement_iteration",
            "measurement_warmup_repetitions",
            "measurement_measured_repetitions",
        },
    )
    if len(rows) != expectations.e10_records:
        _fail("{} has {} records; expected {}".format(source, len(rows), expectations.e10_records))
    if _as_int(provenance["summary"].get("record_count"), "E10 record_count") != len(rows):
        _fail("{} record count disagrees with summary.json".format(source))
    _validate_manifest_rows(
        [{"manifest_hashes": row["manifest_hash"]} for row in rows], provenance, source
    )

    units: Dict[Tuple[str, ...], List[Dict[str, str]]] = defaultdict(list)
    for row in rows:
        unit_template = "" if row["run_kind"] == "template_oracle_summary" else row["template_id"]
        unit = (
            row["run_kind"],
            row["query_id"],
            row["policy_id"],
            row["context_id"],
            row["mode"],
            unit_template,
        )
        units[unit].append(row)
        if _as_int(row["measurement_warmup_repetitions"], "E10 warmup repetitions") != expectations.repeated_warmups:
            _fail("{} contains a row with the wrong E10 warmup declaration".format(source))
        if _as_int(row["measurement_measured_repetitions"], "E10 measured repetitions") != expectations.repeated_measurements:
            _fail("{} contains a row with the wrong E10 measured declaration".format(source))
        if _is_true(row["known_invalid_accepted"]) or _is_true(row["known_valid_rejected"]):
            _fail("{} contains an oracle classification error".format(source))
    if len(units) != expectations.e10_run_units:
        _fail("{} has {} execution units; expected {}".format(source, len(units), expectations.e10_run_units))
    for unit, unit_rows in units.items():
        phases = Counter(row["measurement_phase"] for row in unit_rows)
        expected_phases = Counter(
            {"warmup": expectations.repeated_warmups, "measured": expectations.repeated_measurements}
        )
        if phases != expected_phases:
            _fail("E10 execution unit {} does not contain 5+10 repetitions".format(unit))
        for phase, expected_count in expected_phases.items():
            iterations = sorted(
                _as_int(row["measurement_iteration"], "E10 measurement iteration")
                for row in unit_rows
                if row["measurement_phase"] == phase
            )
            if iterations != list(range(1, expected_count + 1)):
                _fail("E10 execution unit {} has invalid {} iteration numbers".format(unit, phase))

    status_counts = Counter(row["status"] for row in rows)
    summary_status = {
        str(key): _as_int(value, "E10 summary status count")
        for key, value in provenance["summary"].get("status_counts", {}).items()
    }
    if dict(status_counts) != summary_status:
        _fail("{} status counts disagree with summary.json".format(source))
    expected_status_counts = {
        "pass": expectations.e10_pass_records,
        "expected_reject": expectations.e10_expected_reject_records,
        "unsafe_observation": expectations.e10_unsafe_control_records,
    }
    if status_counts != Counter(
        {status: count for status, count in expected_status_counts.items() if count}
    ):
        _fail("{} has unexpected E10 status counts".format(source))

    raw_directory = repo_root / str(provenance["raw_directory"])
    actual_raw_paths = {
        path.relative_to(repo_root).as_posix()
        for path in raw_directory.glob("*.json")
        if not path.name.startswith("._")
    }
    listed_raw_paths = {row["raw_path"] for row in rows}
    if len(listed_raw_paths) != len(rows) or listed_raw_paths != actual_raw_paths:
        _fail("{} does not bind one distinct raw JSON file per record".format(source))

    executed_pass = 0
    expected_reject = 0
    unsafe_control = 0
    for row in rows:
        raw = _read_json(repo_root / row["raw_path"])
        oracle = raw.get("oracle_check")
        runtime = raw.get("runtime_audit")
        measurement = raw.get("measurement")
        result = raw.get("result")
        if not all(isinstance(value, Mapping) for value in (oracle, runtime, measurement, result)):
            _fail("{} lacks required E10 execution evidence".format(row["raw_path"]))
        assert isinstance(oracle, Mapping)
        assert isinstance(runtime, Mapping)
        assert isinstance(measurement, Mapping)
        assert isinstance(result, Mapping)
        if raw.get("run_id") != row["run_id"] or raw.get("status") != row["status"]:
            _fail("{} disagrees with runs.csv identity/status".format(row["raw_path"]))
        if oracle.get("status") != row["oracle_status"] or runtime.get("status") != row["runtime_audit_status"]:
            _fail("{} disagrees with runs.csv oracle/runtime status".format(row["raw_path"]))
        if _as_int(runtime.get("unauthorized_observations"), "E10 raw unauthorized observations") != _as_int(
            row["unauthorized_observations"], "E10 unauthorized observations"
        ):
            _fail("{} disagrees on unauthorized observations".format(row["raw_path"]))
        if (
            measurement.get("phase") != row["measurement_phase"]
            or _as_int(measurement.get("iteration"), "E10 raw iteration")
            != _as_int(row["measurement_iteration"], "E10 CSV iteration")
        ):
            _fail("{} disagrees with runs.csv measurement identity".format(row["raw_path"]))

        if row["status"] == "pass":
            executed_pass += 1
            if (
                row["oracle_status"] != "match"
                or _as_int(oracle.get("set_diff_left"), "E10 reference left diff") != 0
                or _as_int(oracle.get("set_diff_right"), "E10 reference right diff") != 0
                or row["runtime_audit_status"] != "pass"
                or _as_int(row["unauthorized_observations"], "E10 unauthorized observations") != 0
                or not row["result_hash"].startswith("sha256:")
                or result.get("result_hash") != row["result_hash"]
            ):
                _fail("{} is not a clean actual/reference execution".format(row["raw_path"]))
        elif row["status"] == "expected_reject":
            expected_reject += 1
            if (
                row["oracle_status"] != "not_applicable"
                or row["runtime_audit_status"] != "pass"
                or _as_int(row["unauthorized_observations"], "E10 rejected unauthorized observations") != 0
            ):
                _fail("{} is not a clean expected reject".format(row["raw_path"]))
        else:
            unsafe_control += 1
            if (
                row["evaluation_role"] != EvaluationRole.CONTRACT_VIOLATION_CONTROL.value
                or row["oracle_status"] != "match"
                or _as_int(oracle.get("set_diff_left"), "E10 unsafe-control left diff") != 0
                or _as_int(oracle.get("set_diff_right"), "E10 unsafe-control right diff") != 0
                or row["runtime_audit_status"] != "fail"
                or _as_int(row["unauthorized_observations"], "E10 unsafe-control observations") <= 0
            ):
                _fail("{} is not the declared unsafe positive control".format(row["raw_path"]))

    return {
        "record_count": len(rows),
        "execution_unit_count": len(units),
        "warmup_repetitions_per_unit": expectations.repeated_warmups,
        "measured_repetitions_per_unit": expectations.repeated_measurements,
        "status_counts": dict(sorted(status_counts.items())),
        "clean_actual_reference_executions": executed_pass,
        "clean_expected_reject_records": expected_reject,
        "declared_unsafe_positive_control_records": unsafe_control,
        "actual_reference_set_differences": 0,
        "actual_runtime_audit_failures": 0,
        "actual_unauthorized_observations": 0,
        "raw_file_bijection": True,
    }


def _aggregate_e10(
    repo_root: Path,
    provenance: Mapping[str, Any],
    expectations: Expectations,
) -> Dict[str, Any]:
    summary_dir = repo_root / "results" / "summarized" / "SIGMOD_CURRENT_E10"
    run_evidence = _validate_e10_run_evidence(repo_root, provenance, expectations)
    source = summary_dir / "template_oracle_analysis.csv"
    rows = _read_csv(
        source,
        {
            "experiment",
            "stage",
            "dataset_name",
            "dataset_scale",
            "dataset_seed",
            "query_id",
            "policy_id",
            "context_id",
            "best_template_id",
            "chosen_template_id",
            "oracle_gap",
            "estimated_rank",
            "chosen_is_measured_best",
        },
    )
    identity = (
        "experiment",
        "stage",
        "dataset_name",
        "dataset_scale",
        "dataset_seed",
        "query_id",
        "policy_id",
        "context_id",
    )
    groups: Dict[Tuple[str, ...], List[Dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[tuple(row[field] for field in identity)].append(row)
    if len(groups) != expectations.e10_cells:
        _fail("{} has {} E10 cells; expected {}".format(source, len(groups), expectations.e10_cells))
    cells = []
    for key, observations in sorted(groups.items()):
        if len(observations) != expectations.e10_observations_per_cell:
            _fail("E10 case {} has {} oracle repetitions".format(key, len(observations)))
        gaps = [_as_float(row["oracle_gap"], "E10 oracle_gap") for row in observations]
        choice_estimated_ranks = [
            _as_float(row["estimated_rank"], "E10 AdmissionFirst choice estimated_rank")
            for row in observations
        ]
        chosen_hit_observations = sum(_is_true(row["chosen_is_measured_best"]) for row in observations)
        chosen_hit_rate = chosen_hit_observations / len(observations)
        cell_median_gap = _median(gaps)
        chosen_counts = Counter(row["chosen_template_id"] for row in observations)
        best_counts = Counter(row["best_template_id"] for row in observations)
        if len(chosen_counts) != 1:
            _fail("E10 case {} changes the AdmissionFirst choice across repetitions".format(key))
        chosen_template = next(iter(chosen_counts))
        best_template = sorted(best_counts, key=lambda value: (-best_counts[value], value))[0]
        best_template_modal_count = best_counts[best_template]
        cells.append(
            {
                "cell_id": "{}/{}/{}".format(key[5], key[6], key[7]),
                "query_id": key[5],
                "policy_id": key[6],
                "context_id": key[7],
                "chosen_template_id": chosen_template,
                "modal_measured_best_template_id": best_template,
                "modal_measured_best_template_count": best_template_modal_count,
                "modal_measured_best_template_tied": sum(
                    count == best_template_modal_count for count in best_counts.values()
                )
                > 1,
                "measured_best_template_counts": dict(sorted(best_counts.items())),
                # Keep the cell-level definition identical to the ordinary
                # summary: the median chosen/oracle gap must be exactly one.
                # A 5/10 observation split with losses in the other half is
                # therefore disclosed as a miss instead of being rounded up.
                "chosen_is_measured_best": math.isclose(
                    cell_median_gap, 1.0, rel_tol=1e-12, abs_tol=1e-12
                ),
                "chosen_measured_best_observation_count": chosen_hit_observations,
                "chosen_measured_best_observation_rate": chosen_hit_rate,
                "cell_median_oracle_gap": cell_median_gap,
                "admission_first_choice_estimated_rank_median": _median(choice_estimated_ranks),
            }
        )
    gap_values = [float(cell["cell_median_oracle_gap"]) for cell in cells]
    observation_gap_values = [
        _as_float(row["oracle_gap"], "E10 observation oracle_gap") for row in rows
    ]
    chosen_best_count = sum(bool(cell["chosen_is_measured_best"]) for cell in cells)
    chosen_best_observation_count = sum(
        int(cell["chosen_measured_best_observation_count"]) for cell in cells
    )
    choice_estimated_top1 = sum(
        float(cell["admission_first_choice_estimated_rank_median"]) <= 1.0 for cell in cells
    )
    choice_estimated_top3 = sum(
        float(cell["admission_first_choice_estimated_rank_median"]) <= 3.0 for cell in cells
    )
    observation_estimated_top1 = sum(
        _as_float(row["estimated_rank"], "E10 observation estimated_rank") <= 1.0
        for row in rows
    )
    observation_estimated_top3 = sum(
        _as_float(row["estimated_rank"], "E10 observation estimated_rank") <= 3.0
        for row in rows
    )
    gap_summary = {
        "ratio_definition": "chosen_execution_ms / fastest_eligible_admissible_execution_ms",
        "cell_count": len(cells),
        "median": _median(gap_values),
        "geometric_mean": _geometric_mean(gap_values),
        "p90_linear": _percentile_linear(gap_values, 0.9),
        "max": max(gap_values),
        "min": min(gap_values),
    }

    template_summary_path = summary_dir / "template_oracle_summary.json"
    template_summary = _read_json(template_summary_path)
    expected_pairs = {
        "oracle_cell_count": len(cells),
        "oracle_observation_count": len(rows),
        "chosen_is_measured_best_count": chosen_best_count,
        "observation_chosen_is_measured_best_count": chosen_best_observation_count,
        "top1_estimated_rank_count": choice_estimated_top1,
        "top3_estimated_rank_count": choice_estimated_top3,
        "observation_top1_estimated_rank_count": observation_estimated_top1,
        "observation_top3_estimated_rank_count": observation_estimated_top3,
    }
    for field, expected in expected_pairs.items():
        if _as_int(template_summary.get(field), "E10 {}".format(field)) != expected:
            _fail("{} disagrees on {}".format(template_summary_path, field))
    for field, expected in {
        "median_oracle_gap": gap_summary["median"],
        "p90_oracle_gap": gap_summary["p90_linear"],
        "max_oracle_gap": gap_summary["max"],
        "observation_median_oracle_gap": _median(observation_gap_values),
        "observation_p90_oracle_gap": _percentile_linear(observation_gap_values, 0.9),
        "observation_max_oracle_gap": max(observation_gap_values),
    }.items():
        if not math.isclose(
            _as_float(template_summary.get(field), "E10 {}".format(field)),
            expected,
            rel_tol=1e-12,
            abs_tol=1e-12,
        ):
            _fail("{} disagrees on {}".format(template_summary_path, field))

    ranker_path = summary_dir / "ranker_audit_summary.json"
    ranker = _read_json(ranker_path)
    overall = ranker.get("overall")
    if not isinstance(overall, Mapping):
        _fail("{} lacks overall ranker metrics".format(ranker_path))
    _validate_manifest_rows([overall], provenance, ranker_path)
    if _as_int(overall.get("cell_count"), "E10 ranker cell_count") != expectations.e10_cells:
        _fail("{} has the wrong ranker denominator".format(ranker_path))
    raw_top1 = _as_int(overall.get("raw_pg_top1_measured_best_count"), "E10 raw PG top1")
    raw_top3 = _as_int(overall.get("raw_pg_top3_measured_best_count"), "E10 raw PG top3")

    latency_path = summary_dir / "cell_stats.csv"
    latency_rows = _read_csv(
        latency_path,
        {
            "run_kind",
            "query_id",
            "policy_id",
            "context_id",
            "mode",
            "baseline_class",
            "sample_count",
            "warmup_count",
            "protocol_status",
            "status_counts",
            "total_ms_median",
            "manifest_hashes",
        },
    )
    normal = [row for row in latency_rows if row["run_kind"] == "normal_mode"]
    _validate_manifest_rows(normal, provenance, latency_path)
    by_cell: Dict[Tuple[str, str, str], Dict[str, Dict[str, str]]] = defaultdict(dict)
    for row in normal:
        key = (row["query_id"], row["policy_id"], row["context_id"])
        if row["mode"] in by_cell[key]:
            _fail("{} contains a duplicate E10 cell/mode".format(latency_path))
        by_cell[key][row["mode"]] = row
    if len(by_cell) != expectations.e10_cells:
        _fail("{} has {} E10 latency cells; expected {}".format(latency_path, len(by_cell), expectations.e10_cells))

    comparisons = []
    for baseline_mode, label in (
        ("native-pg-rls", "NativePG-RLS"),
        ("native-pg-rls-physical-design", "NativePG-RLS+PD"),
    ):
        records = []
        for key, modes in sorted(by_cell.items()):
            admission_first = modes.get(ADMISSION_FIRST_MODE)
            baseline = modes.get(baseline_mode)
            if admission_first is None or baseline is None:
                _fail("E10 cell {} lacks AdmissionFirst or {}".format(key, baseline_mode))
            if admission_first["evaluation_role"] != EvaluationRole.POLICY_ENFORCEMENT.value or baseline["evaluation_role"] != EvaluationRole.POLICY_ENFORCEMENT.value:
                _fail("E10 cell {} contains a non-policy-enforcement headline mode".format(key))
            _validate_repeated_row(admission_first, latency_path, expectations)
            _validate_repeated_row(baseline, latency_path, expectations)
            admission_first_ms = _as_float(admission_first["total_ms_median"], "E10 AdmissionFirst total latency")
            baseline_ms = _as_float(baseline["total_ms_median"], "E10 native total latency")
            records.append(
                {
                    "cell_id": "{}/{}/{}".format(*key),
                    "query_id": key[0],
                    "policy_id": key[1],
                    "context_id": key[2],
                    "baseline_mode": baseline_mode,
                    "admission_first_total_ms_median": admission_first_ms,
                    "baseline_total_ms_median": baseline_ms,
                    "ratio": baseline_ms / admission_first_ms,
                }
            )
        comparison = _ratio_summary(
            records,
            "{}_total_ms_median / admission_first_total_ms_median".format(baseline_mode.replace("-", "_")),
            True,
        )
        comparison["comparison"] = label
        comparisons.append(comparison)

    return {
        "source": {
            **_source_fields(provenance),
            "runs_source": "results/summarized/SIGMOD_CURRENT_E10/runs.csv",
            "metric_source": "results/summarized/SIGMOD_CURRENT_E10/template_oracle_analysis.csv",
            "latency_source": "results/summarized/SIGMOD_CURRENT_E10/cell_stats.csv",
            "template_oracle_summary": "results/summarized/SIGMOD_CURRENT_E10/template_oracle_summary.json",
            "ranker_summary": "results/summarized/SIGMOD_CURRENT_E10/ranker_audit_summary.json",
        },
        "denominator_cells": expectations.e10_cells,
        "oracle_observations": len(rows),
        "run_evidence": run_evidence,
        "latency_metric": "total_ms_median",
        "native_comparisons": comparisons,
        "admission_first_chosen_measured_best": {
            "count": chosen_best_count,
            "rate": chosen_best_count / len(cells),
            "cell_classification_rule": "The median chosen/oracle gap across the case's measured repetitions equals 1.0.",
            "miss_count": len(cells) - chosen_best_count,
            "miss_cells": [cell for cell in cells if not cell["chosen_is_measured_best"]],
            "observation_count": len(rows),
            "observation_hit_count": chosen_best_observation_count,
            "observation_hit_rate": chosen_best_observation_count / len(rows),
            "exactly_half_hit_cell_count": sum(
                math.isclose(float(cell["chosen_measured_best_observation_rate"]), 0.5, rel_tol=0.0, abs_tol=1e-12)
                for cell in cells
            ),
        },
        "raw_pg_rank_of_measured_best": {
            "top1_count": raw_top1,
            "top1_rate": raw_top1 / len(cells),
            "top3_count": raw_top3,
            "top3_rate": raw_top3 / len(cells),
        },
        "admission_first_choice_estimated_rank": {
            "top1_count": choice_estimated_top1,
            "top1_rate": choice_estimated_top1 / len(cells),
            "top3_count": choice_estimated_top3,
            "top3_rate": choice_estimated_top3 / len(cells),
            "observation_count": len(rows),
            "observation_top1_count": observation_estimated_top1,
            "observation_top1_rate": observation_estimated_top1 / len(rows),
            "observation_top3_count": observation_estimated_top3,
            "observation_top3_rate": observation_estimated_top3 / len(rows),
        },
        "cell_median_oracle_gap": gap_summary,
        "observation_oracle_gap": {
            "ratio_definition": gap_summary["ratio_definition"],
            "observation_count": len(observation_gap_values),
            "median": _median(observation_gap_values),
            "geometric_mean": _geometric_mean(observation_gap_values),
            "p90_linear": _percentile_linear(observation_gap_values, 0.9),
            "max": max(observation_gap_values),
            "min": min(observation_gap_values),
        },
        "measurement_resolution": {
            "floor_ms": template_summary.get("measurement_resolution_floor_ms"),
            "below_floor_cell_count": template_summary.get("below_resolution_cell_count"),
            "pool_size_1_cell_count": template_summary.get("pool_size_1_cell_count"),
        },
        "cells": cells,
        "note": "Fresh corrected 11-cell E10 only. Chosen measured-best accuracy, estimated-rank coverage, raw-PG ranker coverage, and native latency comparisons remain distinct; all losses are retained.",
    }


def _comparison_csv_row(
    section: str,
    comparison: Mapping[str, Any],
    source: Mapping[str, Any],
    source_path: str,
    notes: str = "",
    metric_scope: str = "",
) -> Dict[str, Any]:
    return {
        "section": section,
        "comparison": comparison.get("comparison", ""),
        "metric_kind": "ratio_distribution",
        "metric_scope": metric_scope,
        "ratio_definition": comparison.get("ratio_definition", ""),
        "cell_count": comparison.get("cell_count", ""),
        "observation_count": "",
        "median": comparison.get("median", ""),
        "geometric_mean": comparison.get("geometric_mean", ""),
        "p90_linear": comparison.get("p90_linear", ""),
        "max": comparison.get("max", ""),
        "min": comparison.get("min", ""),
        "wins": comparison.get("wins", ""),
        "ties": comparison.get("ties", ""),
        "losses": comparison.get("losses", ""),
        "top1_count": "",
        "top1_rate": "",
        "top3_count": "",
        "top3_rate": "",
        "source_path": source_path,
        "manifest_id": source["manifest_id"],
        "manifest_hashes": ";".join(source["manifest_hashes"]),
        "git_commits": ";".join(source["git_commits"]),
        "protocol_status": source["protocol_status"],
        "notes": notes,
    }


def _distribution_csv_row(
    section: str,
    comparison: str,
    metric_kind: str,
    distribution: Mapping[str, Any],
    source: Mapping[str, Any],
    source_path: str,
    cell_count: int,
    ratio_definition: str = "",
    notes: str = "",
    metric_scope: str = "",
) -> Dict[str, Any]:
    return {
        "section": section,
        "comparison": comparison,
        "metric_kind": metric_kind,
        "metric_scope": metric_scope,
        "ratio_definition": ratio_definition,
        "cell_count": cell_count,
        "observation_count": distribution["observation_count"],
        "median": distribution["median"],
        "geometric_mean": "",
        "p90_linear": distribution["p90_linear"],
        "max": distribution["max"],
        "min": distribution["min"],
        "wins": "",
        "ties": "",
        "losses": "",
        "top1_count": "",
        "top1_rate": "",
        "top3_count": "",
        "top3_rate": "",
        "source_path": source_path,
        "manifest_id": source["manifest_id"],
        "manifest_hashes": ";".join(source["manifest_hashes"]),
        "git_commits": ";".join(source["git_commits"]),
        "protocol_status": source["protocol_status"],
        "notes": notes,
    }


def _accuracy_csv_row(
    section: str,
    comparison: str,
    source: Mapping[str, Any],
    source_path: str,
    cell_count: int,
    top1_count: int,
    top3_count: Optional[int] = None,
    notes: str = "",
) -> Dict[str, Any]:
    return {
        "section": section,
        "comparison": comparison,
        "metric_kind": "top_k_accuracy",
        "metric_scope": "",
        "ratio_definition": "",
        "cell_count": cell_count,
        "observation_count": "",
        "median": "",
        "geometric_mean": "",
        "p90_linear": "",
        "max": "",
        "min": "",
        "wins": "",
        "ties": "",
        "losses": cell_count - top1_count,
        "top1_count": top1_count,
        "top1_rate": top1_count / cell_count,
        "top3_count": "" if top3_count is None else top3_count,
        "top3_rate": "" if top3_count is None else top3_count / cell_count,
        "source_path": source_path,
        "manifest_id": source["manifest_id"],
        "manifest_hashes": ";".join(source["manifest_hashes"]),
        "git_commits": ";".join(source["git_commits"]),
        "protocol_status": source["protocol_status"],
        "notes": notes,
    }


def _e2_selector_csv_rows(e2: Mapping[str, Any]) -> List[Dict[str, Any]]:
    selector = e2["admission_first_prospective_selection"]
    source = e2["source"]
    note = str(selector["note"])
    return [
        _distribution_csv_row(
            "E2",
            "AdmissionFirst prospective full-selection client wall latency",
            "selector_wall_distribution_ms",
            selector["prospective_selection_wall_ms_median"],
            source,
            source["metric_source"],
            selector["cell_count"],
            notes=note,
            metric_scope=selector["selection_timing_scope"],
        ),
        _distribution_csv_row(
            "E2",
            "AdmissionFirst prospective EXPLAIN client wall latency",
            "selector_explain_wall_distribution_ms",
            selector["prospective_explain_wall_ms_median"],
            source,
            source["metric_source"],
            selector["cell_count"],
            notes=note,
            metric_scope=selector["selection_timing_scope"],
        ),
    ]


def generate_performance_preview(
    repo_root: Path = Path("."),
    output_dir: Optional[Path] = None,
    expectations: Expectations = DEFAULT_EXPECTATIONS,
    source_specs: Sequence[SourceSpec] = SOURCE_SPECS,
) -> PerformancePreviewResult:
    root = Path(repo_root)
    destination = (
        root / DEFAULT_OUTPUT_DIR
        if output_dir is None
        else (output_dir if output_dir.is_absolute() else root / output_dir)
    )
    metrics_csv = destination / "performance_metrics.csv"
    summary_json = destination / "performance_summary.json"
    specs = {spec.family: spec for spec in source_specs}
    required_families = {spec.family for spec in SOURCE_SPECS}
    if set(specs) != required_families:
        _fail("source specs must cover exactly {}".format(sorted(required_families)))
    provenance = {
        family: _load_provenance(root, specs[family]) for family in sorted(specs)
    }

    e2 = _aggregate_e2(root, provenance["E2_PROTOCOL"], expectations)
    e3 = _aggregate_e3(root, provenance["E3_SF1_RAWPG_V1"], expectations)
    e4 = _aggregate_e4(root, provenance["E4_PROTOCOL"], expectations)
    e5 = _aggregate_e5(root, provenance["E5_PROTOCOL"], expectations)
    e9 = _aggregate_e9(root, provenance["SIGMOD_CURRENT_E9"], expectations)
    e10 = _aggregate_e10(root, provenance["SIGMOD_CURRENT_E10"], expectations)

    csv_rows: List[Dict[str, Any]] = []
    csv_rows.append(
        _accuracy_csv_row(
            "E2",
            "AdmissionFirst chosen measured-best",
            e2["source"],
            e2["source"]["oracle_source"],
            e2["denominator_cells"],
            e2["admission_first_measured_best"]["count"],
            notes="E2 contains no NativePG baseline.",
        )
    )
    csv_rows.extend(_e2_selector_csv_rows(e2))
    csv_rows.append(
        _comparison_csv_row(
            "E2",
            e2["fastest_applicable_fixed"],
            e2["source"],
            e2["source"]["metric_source"],
            notes=E2_STEADY_STATE_LATENCY_NOTE,
            metric_scope=e2["latency_metric"],
        )
    )
    csv_rows.extend(
        _comparison_csv_row(
            "E2",
            comparison,
            e2["source"],
            e2["source"]["metric_source"],
            notes=E2_STEADY_STATE_LATENCY_NOTE,
            metric_scope=e2["latency_metric"],
        )
        for comparison in e2["fixed_mode_comparisons"]
    )
    csv_rows.extend(
        _comparison_csv_row("E3", comparison, e3["source"], e3["source"]["metric_source"])
        for comparison in e3["comparisons"]
    )
    csv_rows.append(
        _comparison_csv_row(
            "E4",
            e4["stress_comparison"],
            e4["source"],
            e4["source"]["metric_source"],
            notes=e4["limitation"],
        )
    )
    csv_rows.append(
        _comparison_csv_row(
            "E5",
            e5["declared_regret_witnesses"],
            e5["source"],
            e5["source"]["metric_source"],
            notes=e5["limitation"],
        )
    )
    e9_observation_note = "Distribution over all {} measured AdmissionFirst executions.".format(
        e9["admission_first_measured_observation_count"]
    )
    csv_rows.extend(
        (
            _distribution_csv_row(
                "E9",
                "AdmissionFirst CAPRLS planning latency",
                "latency_distribution_ms",
                e9["admission_first_planning_ms"],
                e9["source"],
                e9["source"]["runs_source"],
                e9["cells_per_mode"],
                notes=e9_observation_note,
            ),
            _distribution_csv_row(
                "E9",
                "AdmissionFirst PostgreSQL planning latency",
                "latency_distribution_ms",
                e9["admission_first_postgres_planning_ms"],
                e9["source"],
                e9["source"]["runs_source"],
                e9["cells_per_mode"],
                notes=(
                    e9_observation_note
                    + " PostgreSQL Planning Time is recorded separately and is not included in raw total_ms."
                ),
            ),
            _distribution_csv_row(
                "E9",
                "AdmissionFirst recorded CAPRLS planning + PG execution latency",
                "latency_distribution_ms",
                e9["admission_first_recorded_planner_plus_pg_execution_ms"],
                e9["source"],
                e9["source"]["runs_source"],
                e9["cells_per_mode"],
                notes=e9_observation_note + " Raw total_ms excludes PostgreSQL Planning Time.",
            ),
            _distribution_csv_row(
                "E9",
                "AdmissionFirst derived CAPRLS planning + PG planning + execution latency",
                "latency_distribution_ms",
                e9["admission_first_derived_planner_plus_pg_planning_plus_execution_ms"],
                e9["source"],
                e9["source"]["runs_source"],
                e9["cells_per_mode"],
                notes=e9_observation_note + " Derived as total_ms + postgres_planning_ms.",
            ),
            _distribution_csv_row(
                "E9",
                "AdmissionFirst CAPRLS-planning fraction of recorded total_ms",
                "overhead",
                e9["admission_first_planning_fraction"],
                e9["source"],
                e9["source"]["runs_source"],
                e9["cells_per_mode"],
                ratio_definition="CAPRLS planning_ms / recorded (CAPRLS planning_ms + PG execution_ms)",
                notes=(
                    "Per-execution fraction over all {} measured AdmissionFirst "
                    "executions; PostgreSQL Planning Time is excluded from this "
                    "recorded-total denominator; descriptive only, with no threshold "
                    "or hard gate."
                ).format(e9["admission_first_measured_observation_count"]),
            ),
        )
    )
    csv_rows.extend(
        _comparison_csv_row(
            "E10", comparison, e10["source"], e10["source"]["latency_source"]
        )
        for comparison in e10["native_comparisons"]
    )
    csv_rows.append(
        _accuracy_csv_row(
            "E10",
            "AdmissionFirst chosen measured-best",
            e10["source"],
            e10["source"]["metric_source"],
            e10["denominator_cells"],
            e10["admission_first_chosen_measured_best"]["count"],
            notes="This is selected-plan measured-best accuracy under the documented cell-median oracle-gap rule; it is not a measured top-3 claim.",
        )
    )
    choice_rank = e10["admission_first_choice_estimated_rank"]
    csv_rows.append(
        _accuracy_csv_row(
            "E10",
            "AdmissionFirst choice estimated-rank coverage",
            e10["source"],
            e10["source"]["template_oracle_summary"],
            e10["denominator_cells"],
            choice_rank["top1_count"],
            choice_rank["top3_count"],
            notes="This ranks the AdmissionFirst choice by estimated cost; it is not measured-best accuracy.",
        )
    )
    raw_rank = e10["raw_pg_rank_of_measured_best"]
    csv_rows.append(
        _accuracy_csv_row(
            "E10",
            "Raw PG estimated rank of measured-best",
            e10["source"],
            e10["source"]["ranker_summary"],
            e10["denominator_cells"],
            raw_rank["top1_count"],
            raw_rank["top3_count"],
            notes="This top-k metric is ranker coverage, not AdmissionFirst selected-plan top-k.",
        )
    )
    gap = dict(e10["cell_median_oracle_gap"])
    gap["comparison"] = "AdmissionFirst chosen-to-best oracle gap"
    gap.update({"wins": "", "ties": "", "losses": e10["admission_first_chosen_measured_best"]["miss_count"]})
    csv_rows.append(
        _comparison_csv_row(
            "E10", gap, e10["source"], e10["source"]["metric_source"]
        )
    )

    distinct_commits = sorted(
        {
            commit
            for source in provenance.values()
            for commit in source["git_commits"]
        }
    )
    summary: Dict[str, Any] = {
        "schema_version": "caprls-sigmod-performance-preview-v3",
        "authority": "paper_performance",
        "status": "pass",
        "scope": "Existing E2/E3/E4/E5/E9/E10 performance evidence; no raw data changed",
        "methods": {
            "aggregation": "Per-case medians are compared without workload weighting. E2 selector distributions use one case-level value per AdmissionFirst case rather than repeated query executions. E9 descriptive distributions use every measured AdmissionFirst execution and report both case and execution denominators.",
            "e2_timing": E2_STEADY_STATE_LATENCY_NOTE,
            "e9_timing": "E9 raw total_ms is CAPRLS planning_ms plus PostgreSQL execution_ms; postgres_planning_ms is separate. The explicitly derived three-part latency is total_ms + postgres_planning_ms.",
            "geometric_mean": "exp(mean(log(positive per-cell ratios)))",
            "p90": "linear interpolation at rank 0.9*(n-1)",
            "win_tie_loss": "Ratios within [0.99,1.01] are ties, except fastest-inclusive comparisons where exact fastest is win, within 1% is tie, and >1% slower is loss.",
            "tie_tolerance": TIE_TOLERANCE,
        },
        "snapshot_policy": {
            "single_combined_snapshot_claimed": False,
            "distinct_git_commits": distinct_commits,
            "note": "Every section retains its own manifest and Git commit; no cross-family aggregate speedup is reported.",
        },
        "sources": {family: _source_fields(source) for family, source in sorted(provenance.items())},
        "sections": {
            "E2": e2,
            "E3": e3,
            "E4": e4,
            "E5": e5,
            "E9": e9,
            "E10": e10,
        },
        "loss_disclosure": {
            "E3": {
                comparison["comparison"]: {
                    "wins": comparison["wins"],
                    "ties": comparison["ties"],
                    "losses": comparison["losses"],
                    "loss_cells": comparison["loss_cells"],
                }
                for comparison in e3["comparisons"]
            },
            "E10": {
                comparison["comparison"]: {
                    "wins": comparison["wins"],
                    "ties": comparison["ties"],
                    "losses": comparison["losses"],
                    "loss_cells": comparison["loss_cells"],
                }
                for comparison in e10["native_comparisons"]
            },
            "E10_chosen_misses": e10["admission_first_chosen_measured_best"]["miss_cells"],
            "E4_E5_scope": (
                "E4 is a declared-template parent-continuation study; E5 is a "
                "fixed-representation regret witness against measured "
                "BestEnumeratedAdmissible. Both use their tracked 5+10 packages."
            ),
        },
        "outputs": {
            "metrics_csv": _output_reference(root, metrics_csv),
            "summary_json": _output_reference(root, summary_json),
        },
    }

    destination.mkdir(parents=True, exist_ok=True)
    with metrics_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(csv_rows)
    summary_json.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return PerformancePreviewResult(metrics_csv=metrics_csv, summary_json=summary_json, summary=summary)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the transparent SIGMOD performance preview")
    parser.add_argument("--root", type=Path, default=Path("."), help="repository root")
    parser.add_argument("--output-dir", type=Path, default=None, help="optional output directory")
    args = parser.parse_args(argv)
    try:
        result = generate_performance_preview(args.root, args.output_dir)
    except PerformancePreviewError as exc:
        parser.exit(2, "sigmod-performance-preview: error: {}\n".format(exc))
    print("wrote {} and {}".format(result.metrics_csv, result.summary_json))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
