"""Offline reduction of selection-only, sparse-timer diagnostics.

This module never connects to PostgreSQL and does not alter paper results.
The optional historical allocation is explicitly an estimate: fractions from
the new six-case diagnostic cohort are applied to an old 33-case total median.
It is not a recovery of unrecorded component times from that old experiment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ARMS = ("plain_sparse", "legacy_profile_sparse")
QUERIES = ("Q10", "JOB_10a")
POLICIES = (
    "cheap_tenant_sargable", "group_acl_expensive", "hybrid_selective_key",
)
EXPECTED_CASES = tuple(f"E3_{query}_{policy}" for query in QUERIES for policy in POLICIES)
HISTORICAL_TOTAL_SECONDS = 17.458591624999826
HISTORICAL_CAMPAIGN = "ORIGINAL_TABLE3_COST_NOISE_20261006_V1"
DEFAULT_SEED = 102026


class BreakdownAnalysisError(ValueError):
    """Malformed or incompatible diagnostic input."""


def _mean(values: Sequence[float]) -> float:
    return statistics.fmean(values)


def _quantile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise BreakdownAnalysisError("cannot summarize an empty sequence")
    position = probability * (len(ordered) - 1)
    left = int(position)
    right = min(left + 1, len(ordered) - 1)
    return ordered[left] + (ordered[right] - ordered[left]) * (position - left)


def _finite_number(value: Any, name: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BreakdownAnalysisError(f"{name}: expected a number")
    result = float(value)
    if not math.isfinite(result) or (result <= 0 if positive else result < 0):
        raise BreakdownAnalysisError(f"{name}: expected a finite {'positive' if positive else 'nonnegative'} number")
    return result


def _record_values(record: Mapping[str, Any]) -> tuple[float, dict[str, float]]:
    breakdown = record.get("breakdown")
    if not isinstance(breakdown, Mapping):
        raise BreakdownAnalysisError("selection record has no breakdown mapping")
    wall = _finite_number(breakdown.get("total_wall_ms"), "total_wall_ms", positive=True)
    exclusive = breakdown.get("exclusive_ms")
    if not isinstance(exclusive, Mapping) or not exclusive:
        raise BreakdownAnalysisError("exclusive_ms must be a nonempty mapping")
    values = {str(key): _finite_number(value, f"exclusive_ms/{key}")
              for key, value in exclusive.items()}
    if not math.isclose(sum(values.values()), wall, rel_tol=1e-7, abs_tol=1e-5):
        raise BreakdownAnalysisError(
            f"exclusive components do not conserve the total: {sum(values.values())} != {wall}"
        )
    return wall, values


def _bootstrap_equal_case_means(
    case_vectors: Sequence[Sequence[Sequence[float]]], *, draws: int, seed: int,
) -> list[list[float]]:
    """Resample observations inside each *fixed* case, preserving vector sums.

    Cases are equally weighted, not pooled by sample count or elapsed time.
    Intervals therefore describe this fixed diagnostic cohort only; they do
    not establish representativeness for the historic 33-case workload.
    """
    rng = random.Random(seed)
    width = len(case_vectors[0][0])
    distributions = [[] for _ in range(width)]
    for _ in range(draws):
        draw_vector = [0.0] * width
        for observations in case_vectors:
            totals = [0.0] * width
            for _sample in observations:
                selected = observations[rng.randrange(len(observations))]
                for index, value in enumerate(selected):
                    totals[index] += value
            for index, total in enumerate(totals):
                draw_vector[index] += total / len(observations) / len(case_vectors)
        for index, value in enumerate(draw_vector):
            distributions[index].append(value)
    return distributions


def _interval(values: Sequence[float]) -> dict[str, float]:
    return {"lower": _quantile(values, 0.025), "upper": _quantile(values, 0.975)}


def _identity(record: Mapping[str, Any]) -> tuple[Any, Any]:
    selection = record.get("selection", {})
    if not isinstance(selection, Mapping):
        return None, None
    return selection.get("selected_template_id"), selection.get("runner_sql_digest")


def analyze_records(
    records: Iterable[Mapping[str, Any]], *,
    expected_cases: Sequence[str] = EXPECTED_CASES,
    expected_warmup: int = 5, expected_measured: int = 30,
    bootstrap_draws: int = 2000, seed: int = DEFAULT_SEED,
    stability_tolerance_percentage_points: float = 5.0,
    historical_total_seconds: float = HISTORICAL_TOTAL_SECONDS,
) -> dict[str, Any]:
    """Validate and summarize an entire declared diagnostic cohort.

    Failed, incomplete or identity-changing inputs are not selectively
    removed to produce an allocation. A complete but unstable cohort retains
    its observations and receives an ``exploratory_unstable`` estimate label.
    """
    if expected_warmup < 0 or expected_measured < 2 or bootstrap_draws < 1:
        raise BreakdownAnalysisError("invalid declared repetition/bootstrap count")
    if len(set(expected_cases)) != len(expected_cases) or not expected_cases:
        raise BreakdownAnalysisError("expected case inventory is empty or duplicated")
    if not math.isfinite(stability_tolerance_percentage_points) or stability_tolerance_percentage_points < 0:
        raise BreakdownAnalysisError("invalid stability tolerance")
    _finite_number(historical_total_seconds, "historical_total_seconds", positive=True)
    grouped: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    blockers: list[str] = []
    observed_cases: set[str] = set()
    categories: set[str] = set()
    record_count = pair_records = metadata_records = 0
    for record in records:
        if record.get("kind") == "pair_summary":
            pair_records += 1
            if record.get("selection_and_sql_match") is False:
                blockers.append(f"{record.get('case_id')}/{record.get('phase')}/{record.get('iteration')}: pair summary reports an identity mismatch")
            continue
        if record.get("kind") == "database_setup_started":
            metadata_records += 1
            continue
        record_count += 1
        case, arm, phase = record.get("case_id"), record.get("arm"), record.get("phase")
        if not isinstance(case, str) or arm not in ARMS or phase not in ("warmup", "measured"):
            blockers.append(f"record {record_count}: invalid case/arm/phase")
            continue
        observed_cases.add(case)
        if record.get("family") != "E3":
            blockers.append(f"{case}/{arm}/{phase}: family is not E3")
        if record.get("status") != "pass":
            blockers.append(f"{case}/{arm}/{phase}: status is {record.get('status')!r}")
        iteration = record.get("iteration")
        if isinstance(iteration, bool) or not isinstance(iteration, int) or iteration < 0:
            blockers.append(f"{case}/{arm}/{phase}: invalid iteration")
        try:
            _wall, exclusive = _record_values(record)
            categories.update(exclusive)
            if record["breakdown"].get("sql_call_counts", {}).get("explain_analyze", 0):
                blockers.append(f"{case}/{arm}/{phase}/{iteration}: selection diagnosis executed EXPLAIN ANALYZE")
        except BreakdownAnalysisError as exc:
            blockers.append(f"{case}/{arm}/{phase}/{iteration}: {exc}")
        if not all(_identity(record)):
            blockers.append(f"{case}/{arm}/{phase}/{iteration}: missing selected template or SQL identity")
        grouped[(case, arm, phase)].append(record)
    if observed_cases != set(expected_cases):
        blockers.append(f"case inventory differs: missing={sorted(set(expected_cases) - observed_cases)}, unexpected={sorted(observed_cases - set(expected_cases))}")
    for case in expected_cases:
        for arm in ARMS:
            for phase, count in (("warmup", expected_warmup), ("measured", expected_measured)):
                rows = grouped[(case, arm, phase)]
                iterations = [row.get("iteration") for row in rows]
                if len(rows) != count or sorted(iterations, key=repr) != sorted(range(count), key=repr):
                    blockers.append(f"{case}/{arm}/{phase}: expected unique iterations 0..{count - 1}, found {iterations}")
        for phase in ("warmup", "measured"):
            plain = {row.get("iteration"): row for row in grouped[(case, ARMS[0], phase)]}
            legacy = {row.get("iteration"): row for row in grouped[(case, ARMS[1], phase)]}
            for iteration in sorted(plain.keys() & legacy.keys(), key=repr):
                if _identity(plain[iteration]) != _identity(legacy[iteration]):
                    blockers.append(f"{case}/{phase}/{iteration}: paired arms selected different template/SQL")
        identities = {_identity(row) for arm in ARMS for phase in ("warmup", "measured")
                      for row in grouped[(case, arm, phase)]}
        if len(identities) > 1:
            blockers.append(f"{case}: selected template/SQL changed across diagnostic observations")

    metadata: dict[str, Any] = {
        "schema": "caprls-selection-cost-breakdown-analysis-v1",
        "scope": "new selection-only six-case diagnostic; no query performance rerun",
        "expected_cases": list(expected_cases), "observed_cases": sorted(observed_cases),
        "selection_records": record_count, "ignored_pair_summary_records": pair_records,
        "ignored_setup_metadata_records": metadata_records,
        "declared_warmup_per_case_arm": expected_warmup,
        "declared_measured_per_case_arm": expected_measured,
        "warmup_in_aggregates": False,
        "bootstrap": {"draws": bootstrap_draws, "seed": seed, "confidence": 0.95,
                      "unit": "paired selection observation, not inner calls",
                      "scope": "observations resampled within fixed cases; equal case weighting"},
        "stability_rule": {"criterion": "first-half versus second-half component-share mean absolute difference",
                           "maximum_percentage_points": stability_tolerance_percentage_points,
                           "all_case_arm_components_must_pass": True,
                           "unstable_cases_are_not_removed": True},
        "inclusive_timings_are_not_additive": True,
        "sparse_timer_overhead_is_included": True,
        "historical_original_records_modified": False,
        "manuscript_modified": False,
        "blockers": blockers,
    }
    if blockers:
        return {**metadata, "status": "needs_review", "actual_diagnostic": None,
                "provisional_allocation": None, "profiler_comparison": None}

    ordered_categories = sorted(categories)
    by_arm: dict[str, Any] = {}
    all_stable = True
    arm_case_vectors: dict[str, list[list[list[float]]]] = {}
    for arm_index, arm in enumerate(ARMS):
        case_summaries = []
        vectors_by_case = []
        for case in expected_cases:
            rows = sorted(grouped[(case, arm, "measured")], key=lambda row: row["iteration"])
            walls, components = zip(*(_record_values(row) for row in rows))
            vectors = [[component.get(category, 0.0) / wall for category in ordered_categories]
                       for wall, component in zip(walls, components)]
            vectors_by_case.append(vectors)
            case_distributions = _bootstrap_equal_case_means(
                [vectors], draws=bootstrap_draws, seed=seed + 1000 * arm_index + len(case_summaries),
            )
            split = len(vectors) // 2
            phase_summary = {}
            for index, category in enumerate(ordered_categories):
                fractions = [vector[index] for vector in vectors]
                first = _mean(fractions[:split])
                second = _mean(fractions[split:])
                delta_pp = (second - first) * 100
                stable = abs(delta_pp) <= stability_tolerance_percentage_points
                all_stable = all_stable and stable
                phase_summary[category] = {
                    "mean_fraction": _mean(fractions), "fraction_ci95": _interval(case_distributions[index]),
                    "first_half_mean_fraction": first, "second_half_mean_fraction": second,
                    "second_minus_first_percentage_points": delta_pp,
                    "stable_by_predeclared_rule": stable,
                    "exclusive_ms_mean": _mean([value.get(category, 0.0) for value in components]),
                    "exclusive_ms_median": statistics.median([value.get(category, 0.0) for value in components]),
                }
            case_summaries.append({
                "case_id": case, "formal_observations": len(rows),
                "selected_template_id": _identity(rows[0])[0], "runner_sql_digest": _identity(rows[0])[1],
                "total_wall_ms_mean": _mean(walls), "total_wall_ms_median": statistics.median(walls),
                "phases": phase_summary,
                "inclusive_phase_ms_diagnostic": {
                    category: {
                        "mean": _mean([float(row["breakdown"].get("inclusive_ms", {}).get(category, 0)) for row in rows]),
                        "median": statistics.median([float(row["breakdown"].get("inclusive_ms", {}).get(category, 0)) for row in rows]),
                        "additive": False,
                    } for category in ordered_categories
                },
                "phase_call_counts": {
                    category: {
                        "median": statistics.median([float(row["breakdown"].get("call_counts", row["breakdown"].get("counts", {})).get(category, 0)) for row in rows]),
                        "min": min([float(row["breakdown"].get("call_counts", row["breakdown"].get("counts", {})).get(category, 0)) for row in rows]),
                        "max": max([float(row["breakdown"].get("call_counts", row["breakdown"].get("counts", {})).get(category, 0)) for row in rows]),
                    } for category in ordered_categories
                },
                "sql_call_counts": {
                    kind: {
                        "median": statistics.median([float(row["breakdown"].get("sql_call_counts", {}).get(kind, 0)) for row in rows]),
                        "min": min([float(row["breakdown"].get("sql_call_counts", {}).get(kind, 0)) for row in rows]),
                        "max": max([float(row["breakdown"].get("sql_call_counts", {}).get(kind, 0)) for row in rows]),
                    } for kind in ("plain_explain", "explain_analyze", "other")
                },
            })
        arm_case_vectors[arm] = vectors_by_case
        draws = _bootstrap_equal_case_means(vectors_by_case, draws=bootstrap_draws, seed=seed + 10000 + arm_index)
        cohort = {}
        for index, category in enumerate(ordered_categories):
            case_means = [case["phases"][category]["mean_fraction"] for case in case_summaries]
            cohort[category] = {
                "mean_fraction": _mean(case_means), "fraction_ci95": _interval(draws[index]),
                "case_mean_fraction_min": min(case_means), "case_mean_fraction_max": max(case_means),
                "between_case_range_percentage_points": (max(case_means) - min(case_means)) * 100,
            }
        by_arm[arm] = {
            "cases": case_summaries, "cohort_phases": cohort,
            "weighting": "equal case weights; within each case arithmetic mean of formal-observation fractions",
            "mean_fraction_sum": sum(value["mean_fraction"] for value in cohort.values()),
            "total_wall_ms_equal_case_mean": _mean([case["total_wall_ms_mean"] for case in case_summaries]),
        }

    paired_vectors, paired_cases = [], []
    for case in expected_cases:
        plain = {row["iteration"]: row for row in grouped[(case, ARMS[0], "measured")]}
        legacy = {row["iteration"]: row for row in grouped[(case, ARMS[1], "measured")]}
        observations = []
        for iteration in range(expected_measured):
            plain_wall = _record_values(plain[iteration])[0]
            legacy_wall = _record_values(legacy[iteration])[0]
            observations.append([legacy_wall - plain_wall, (legacy_wall - plain_wall) / plain_wall])
        paired_vectors.append(observations)
        case_draws = _bootstrap_equal_case_means([observations], draws=bootstrap_draws, seed=seed + 20000 + len(paired_cases))
        paired_cases.append({"case_id": case,
                             "legacy_minus_plain_ms_mean": _mean([row[0] for row in observations]),
                             "difference_ms_ci95": _interval(case_draws[0]),
                             "relative_difference_mean": _mean([row[1] for row in observations]),
                             "relative_difference_ci95": _interval(case_draws[1])})
    delta_draws = _bootstrap_equal_case_means(paired_vectors, draws=bootstrap_draws, seed=seed + 30000)
    delta_interval = _interval(delta_draws[0])
    profiler_comparison = {
        "kind": "paired_diagnostic_comparison_not_an_exclusive_measured_component",
        "scope": "legacy global profiling enabled versus disabled; both arms use sparse hooks",
        "interpretation": "includes profiling effects and remaining execution-context variation; not a direct historical profiler cost",
        "legacy_minus_plain_ms_equal_case_mean": _mean([case["legacy_minus_plain_ms_mean"] for case in paired_cases]),
        "difference_ms_ci95": delta_interval,
        "relative_difference_equal_case_mean": _mean([case["relative_difference_mean"] for case in paired_cases]),
        "relative_difference_ci95": _interval(delta_draws[1]),
        "difference_resolved_positive": delta_interval["lower"] > 0,
        "difference_resolved_negative": delta_interval["upper"] < 0,
        "negative_differences_clamped": False, "subtracted_from_historical_total": False,
        "cases": paired_cases,
    }
    source_phases = by_arm["legacy_profile_sparse"]["cohort_phases"]
    allocation = {
        "kind": "PROVISIONAL_ESTIMATED_ALLOCATION",
        "status": "provisional_stable_diagnostic" if all_stable else "exploratory_unstable",
        "directly_measured_in_historical_campaign": False,
        "replace_paper_numbers": False,
        "historical_campaign": HISTORICAL_CAMPAIGN,
        "historical_total_seconds": historical_total_seconds,
        "historical_total_scope": "median of 33 original mixed-workload whole-selection measurements; inputs excluded",
        "diagnostic_arm": "legacy_profile_sparse", "diagnostic_cases": list(expected_cases),
        "method": "historical total multiplied by equal-case mean new-diagnostic exclusive fractions",
        "limitations": [
            "These are estimated allocations, not reconstructed old component measurements.",
            "Six representative cases are not the full 33-case historic cohort.",
            "Fractions are warm diagnostic observations; the original total used one choice per case.",
            "Bootstrap intervals quantify diagnostic observation fluctuation, not transfer uncertainty to the historic cohort.",
            "Legacy-arm exclusive phases include profiling overhead incurred inside them; the separate paired delta is not added again.",
        ],
        "phases": {category: {
            "estimated_fraction": stats["mean_fraction"],
            "estimated_seconds": historical_total_seconds * stats["mean_fraction"],
            "scaled_diagnostic_ci95_seconds": {
                "lower": historical_total_seconds * stats["fraction_ci95"]["lower"],
                "upper": historical_total_seconds * stats["fraction_ci95"]["upper"],
            },
        } for category, stats in source_phases.items()},
    }
    allocation["estimated_seconds_sum"] = sum(value["estimated_seconds"] for value in allocation["phases"].values())
    return {**metadata, "status": "pass" if all_stable else "exploratory_unstable",
            "all_components_stable_by_predeclared_rule": all_stable,
            "actual_diagnostic": by_arm, "profiler_comparison": profiler_comparison,
            "provisional_allocation": allocation}


def read_records(path: Path) -> list[Mapping[str, Any]]:
    records = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise BreakdownAnalysisError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(record, Mapping):
                raise BreakdownAnalysisError(f"{path}:{line_number}: JSON record is not an object")
            records.append(record)
    return records


def write_analysis(path: Path, analysis: Mapping[str, Any], *, input_path: Path) -> None:
    """Generate a new receipt directory. Existing directories are never reused."""
    path.mkdir(parents=True, exist_ok=False)
    payload = dict(analysis)
    payload["input_path"] = str(input_path.resolve())
    payload["input_sha256"] = hashlib.sha256(input_path.read_bytes()).hexdigest()
    (path / "analysis.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    allocation = payload.get("provisional_allocation")
    (path / "provisional_allocation_17_459.json").write_text(
        json.dumps(allocation, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    lines = ["# Selection-cost diagnostic reduction", "", f"Status: {payload['status']}", "",
             "This is new selection-only diagnosis, not a query-performance rerun.",
             "The historical 17.459-second decomposition is a provisional proportional estimate,",
             "not a direct measurement from the historical 33-case campaign.", ""]
    if allocation:
        lines += ["| Exclusive phase | Diagnostic mean share | Estimated allocation (s) |", "|---|---:|---:|"]
        for category, value in allocation["phases"].items():
            lines.append(f"| {category} | {value['estimated_fraction']:.2%} | {value['estimated_seconds']:.6f} |")
        lines += ["", "The profile-on/off difference is reported separately and is not added to this table.",
                  "All cases, including unstable cases, are retained. See analysis.json for intervals and half-run checks."]
    else:
        lines += ["No allocation was generated because the declared activity is incomplete or invalid.", ""]
        lines += [f"- {blocker}" for blocker in payload["blockers"]]
    (path / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="diagnosis.jsonl selection records")
    parser.add_argument("--output-dir", type=Path, required=True, help="new output directory (must not exist)")
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--measured", type=int, default=30)
    parser.add_argument("--bootstrap-draws", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args(argv)
    if args.output_dir.exists():
        parser.error(f"refusing to overwrite existing output directory: {args.output_dir}")
    analysis = analyze_records(read_records(args.input), expected_warmup=args.warmup,
                               expected_measured=args.measured, bootstrap_draws=args.bootstrap_draws,
                               seed=args.seed)
    write_analysis(args.output_dir, analysis, input_path=args.input)
    print(json.dumps({"status": analysis["status"], "output_dir": str(args.output_dir),
                      "blockers": analysis["blockers"],
                      "allocation_kind": (analysis.get("provisional_allocation") or {}).get("kind")}))
    return 2 if analysis["blockers"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
