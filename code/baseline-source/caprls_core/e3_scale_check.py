"""Validate and summarize the standalone E3 TPC-H SF10 scale check."""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
    normalize_mode_id,
)

import argparse
import csv
import hashlib
import json
import math
import re
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple


class E3ScaleCheckError(ValueError):
    """The input cannot support the fixed SF10 scale-check claim."""


EXPECTED_QUERIES = ("Q3", "Q5", "Q7", "Q10", "Q12")
EXPECTED_POLICIES = (
    "cheap_tenant_sargable",
    "group_acl_expensive",
    "hybrid_selective_key",
)
COMPARATOR_MODES = ("native-pg-rls", "barrier-only", "local-greedy")
EXPECTED_MODES = COMPARATOR_MODES + (ADMISSION_FIRST_MODE,)
OPTIONAL_DIAGNOSTIC_MODES = ("injection-only",)
PRIMARY_METRIC = "median_end_to_end_ms_including_validation_and_client"
EXPECTED_CELLS = 15
TIE_LOWER_BOUND, TIE_FACTOR = 0.99, 1.01

_HEX40 = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_REQUIRED_FIELDS = {
    "manifest_id", "manifest_sha256", "git_commit", "query_id", "workload",
    "dataset_scale", "seed", "policy_id", "mode", "template_id", "status",
    "failure_reason", "row_count", "reference_row_count", "result_digest",
    "reference_digest", "actual_only_rows", "reference_only_rows",
    "sql_digest", "measurement_protocol", "warmup_repetitions",
    "measured_repetitions", PRIMARY_METRIC,
}
_CELL_FIELDS = (
    "query_id", "policy_id", "workload", "dataset_scale", "seed",
    "manifest_id", "manifest_sha256", "git_commit", "comparator_mode",
    "comparator_template_id", "admission_first_template_id",
    "comparator_sql_digest", "admission_first_sql_digest",
    "shared_execution_identity", "ratio_source", "primary_metric",
    "comparator_median_ms", "admission_first_median_ms",
    "ratio_comparator_over_admission_first", "outcome_for_admission_first",
    "tie_factor",
)
_EXPECTED_IDENTITIES = {
    (query, policy, mode)
    for query in EXPECTED_QUERIES
    for policy in EXPECTED_POLICIES
    for mode in EXPECTED_MODES
}
_EXPECTED_IDENTITIES_WITH_DIAGNOSTICS = _EXPECTED_IDENTITIES | {
    (query, policy, mode)
    for query in EXPECTED_QUERIES
    for policy in EXPECTED_POLICIES
    for mode in OPTIONAL_DIAGNOSTIC_MODES
}


@dataclass(frozen=True)
class E3ScaleCheckResult:
    summary_json: Path
    cells_csv: Path
    summary: Mapping[str, Any]


def _integer(value: str, label: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise E3ScaleCheckError("invalid {}={!r}".format(label, value)) from exc


def _positive(value: str, label: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise E3ScaleCheckError("invalid {}={!r}".format(label, value)) from exc
    if not math.isfinite(number) or number <= 0:
        raise E3ScaleCheckError("{} must be finite and positive".format(label))
    return number


def _p90(values: Sequence[float]) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * 0.9
    lower = math.floor(position)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[math.ceil(position)] * weight


def _outcome(ratio: float) -> str:
    return "win" if ratio > TIE_FACTOR else (
        "loss" if ratio < TIE_LOWER_BOUND else "tie"
    )


def _read_source(
    path: Path,
) -> Tuple[
    Dict[Tuple[str, str, str], Dict[str, str]],
    Tuple[str, str, str, int],
    Tuple[str, ...],
]:
    if not path.is_file():
        raise E3ScaleCheckError("source summary does not exist: {}".format(path))
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = _REQUIRED_FIELDS - set(reader.fieldnames or ())
        if missing:
            raise E3ScaleCheckError(
                "source summary is missing: {}".format(", ".join(sorted(missing)))
            )
        rows = list(reader)
    identities = [
        (
            row["query_id"],
            row["policy_id"],
            normalize_mode_id(str(row["mode"])),
        )
        for row in rows
    ]
    identity_set = set(identities)
    if identity_set == _EXPECTED_IDENTITIES:
        source_modes = EXPECTED_MODES
    elif identity_set == _EXPECTED_IDENTITIES_WITH_DIAGNOSTICS:
        source_modes = EXPECTED_MODES + OPTIONAL_DIAGNOSTIC_MODES
    else:
        raise E3ScaleCheckError(
            "source must contain the exact 60 core identities, optionally "
            "plus all 15 injection-only identities"
        )
    if len(rows) != len(identity_set):
        raise E3ScaleCheckError("source identities must be unique")

    indexed = {}
    snapshots = set()
    for number, (identity, row) in enumerate(zip(identities, rows), start=2):
        prefix = "row {}".format(number)
        row_count = _integer(row["row_count"], prefix + " row_count")
        reference_count = _integer(
            row["reference_row_count"], prefix + " reference_row_count"
        )
        bag = (
            _integer(row["actual_only_rows"], prefix + " actual_only_rows"),
            _integer(row["reference_only_rows"], prefix + " reference_only_rows"),
        )
        valid = (
            row["workload"] == "tpch"
            and row["dataset_scale"] == "SF10"
            and row["status"] == "pass"
            and not row["failure_reason"].strip()
            and row["measurement_protocol"] == "warm_cache_repetitions"
            and _integer(row["warmup_repetitions"], prefix + " warmups") == 5
            and _integer(row["measured_repetitions"], prefix + " measurements") == 10
            and row_count >= 0
            and row_count == reference_count
            and bool(_SHA256.fullmatch(row["result_digest"]))
            and row["result_digest"] == row["reference_digest"]
            and bag == (0, 0)
            and bool(row["template_id"].strip())
            and bool(_SHA256.fullmatch(row["sql_digest"]))
        )
        _positive(row[PRIMARY_METRIC], prefix + " " + PRIMARY_METRIC)
        seed = _integer(row["seed"], prefix + " seed")
        manifest = row["manifest_id"]
        manifest_hash = row["manifest_sha256"]
        commit = row["git_commit"]
        valid = valid and (
            seed >= 0
            and bool(manifest.strip())
            and bool(_SHA256.fullmatch(manifest_hash))
            and bool(_HEX40.fullmatch(commit))
        )
        if not valid:
            raise E3ScaleCheckError(prefix + " violates the SF10 protocol")
        snapshots.add((manifest, manifest_hash, commit, seed))
        indexed[identity] = dict(row)
    if len(snapshots) != 1:
        raise E3ScaleCheckError(
            "all source rows must use one snapshot and manifest"
        )
    return indexed, next(iter(snapshots)), source_modes


def generate_e3_scale_check(
    input_csv: Path, output_dir: Path
) -> E3ScaleCheckResult:
    """Generate the static standalone scale-check package."""

    input_csv, output_dir = Path(input_csv), Path(output_dir)
    rows, (manifest_id, manifest_hash, commit, seed), source_modes = (
        _read_source(input_csv)
    )
    cells = []
    comparisons = {}
    comparison_modes = COMPARATOR_MODES + tuple(
        mode for mode in OPTIONAL_DIAGNOSTIC_MODES if mode in source_modes
    )
    for mode in comparison_modes:
        ratios, comparator_ms_values, af_ms_values = [], [], []
        outcomes = {"win": 0, "tie": 0, "loss": 0}
        shared_count = 0
        for query in EXPECTED_QUERIES:
            for policy in EXPECTED_POLICIES:
                comparator = rows[(query, policy, mode)]
                af = rows[(query, policy, ADMISSION_FIRST_MODE)]
                comparator_ms = float(comparator[PRIMARY_METRIC])
                af_ms = float(af[PRIMARY_METRIC])
                shared = (
                    comparator["template_id"] == af["template_id"]
                    and comparator["sql_digest"] == af["sql_digest"]
                )
                ratio = 1.0 if shared else comparator_ms / af_ms
                source = "identity_collapsed" if shared else "measured"
                outcome = _outcome(ratio)
                shared_count += int(shared)
                outcomes[outcome] += 1
                ratios.append(ratio)
                comparator_ms_values.append(comparator_ms)
                af_ms_values.append(af_ms)
                cells.append({
                    "query_id": query, "policy_id": policy, "workload": "tpch",
                    "dataset_scale": "SF10", "seed": seed,
                    "manifest_id": manifest_id, "manifest_sha256": manifest_hash,
                    "git_commit": commit, "comparator_mode": mode,
                    "comparator_template_id": comparator["template_id"],
                    "admission_first_template_id": af["template_id"],
                    "comparator_sql_digest": comparator["sql_digest"],
                    "admission_first_sql_digest": af["sql_digest"],
                    "shared_execution_identity": str(shared).lower(),
                    "ratio_source": source, "primary_metric": PRIMARY_METRIC,
                    "comparator_median_ms": "{:.9f}".format(comparator_ms),
                    "admission_first_median_ms": "{:.9f}".format(af_ms),
                    "ratio_comparator_over_admission_first": "{:.12f}".format(ratio),
                    "outcome_for_admission_first": outcome,
                    "tie_factor": "{:.6f}".format(TIE_FACTOR),
                })
        comparisons[mode] = {
            "comparator_mode": mode, "cell_count": EXPECTED_CELLS,
            "ratio_definition": "comparator_median_ms / admission_first_median_ms",
            "ratio_median": statistics.median(ratios),
            "ratio_geometric_mean": statistics.geometric_mean(ratios),
            "ratio_p90_linear": _p90(ratios),
            "wins": outcomes["win"], "ties": outcomes["tie"],
            "losses": outcomes["loss"],
            "shared_execution_identity_cells": shared_count,
            "comparator_latency_median_ms": statistics.median(comparator_ms_values),
            "admission_first_latency_median_ms": statistics.median(af_ms_values),
        }

    summary = {
        "schema": "e3_sf10_standalone_scale_check_v1", "schema_version": 1,
        "authority": "standalone_e3_sf10_scale_check", "status": "pass",
        "experiment": "E3", "scope": "standalone_tpch_sf10_scale_check",
        "paper_authority_integration": {
            "included_in_existing_52_cell_correctness_authority": False,
            "included_in_existing_780_record_correctness_total": False,
            "included_in_existing_performance_authority": False,
            "no_cross_sf1_aggregate": True,
            "claim": "Standalone; does not alter existing correctness or SF1 performance authority.",
        },
        "selection_claims": {"oracle_claimed": False, "measured_best_claimed": False},
        "source": {
            "summary_csv": str(input_csv),
            "summary_csv_sha256": "sha256:" + hashlib.sha256(
                input_csv.read_bytes()
            ).hexdigest(),
            "manifest_id": manifest_id, "manifest_sha256": manifest_hash,
            "git_commit": commit,
        },
        "denominator": {
            "queries": list(EXPECTED_QUERIES), "policies": list(EXPECTED_POLICIES),
            "modes": list(source_modes), "logical_cells": EXPECTED_CELLS,
            "source_rows": len(rows), "dataset": "tpch",
            "dataset_scale": "SF10", "seed": seed,
        },
        "measurement": {
            "protocol": "warm_cache_repetitions", "warmup_repetitions": 5,
            "measured_repetitions": 10, "primary_metric": PRIMARY_METRIC,
            "ratio_definition": "comparator / AdmissionFirst",
            "tie_rule": {"factor": 1.01, "win": "ratio > 1.01",
                         "tie": "0.99 <= ratio <= 1.01", "loss": "ratio < 0.99"},
        },
        "correctness": {
            "logical_cells_passed": 15, "logical_cells_total": 15,
            "mode_cells_passed": len(rows), "mode_cells_total": len(rows),
            "source_rows_passed": len(rows), "source_rows_failed": 0,
            "check": "row count, canonical digest, and zero bag difference",
        },
        "comparisons": comparisons,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    cells_csv, summary_json = output_dir / "cells.csv", output_dir / "summary.json"
    with cells_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=_CELL_FIELDS)
        writer.writeheader()
        writer.writerows(cells)
    summary_json.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return E3ScaleCheckResult(summary_json, cells_csv, summary)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize the E3 SF10 scale check")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = generate_e3_scale_check(args.input, args.output_dir)
    except E3ScaleCheckError as exc:
        parser.exit(2, "e3-scale-check: error: {}\n".format(exc))
    print("wrote {} and {}".format(result.summary_json, result.cells_csv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
