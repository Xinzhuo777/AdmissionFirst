"""Separate offline, post-hoc explanatory allocation of historical choice cost.

The active diagnostic sampler and its frozen reducer do not import this file.
For matched observations L=legacy-profile wall, P=plain sparse wall, and x_k
the plain sparse exclusive components, allocate x_k/L to processing phase k
and (L-P)/L to the estimated extra global-profile effect. These add to one.
No negative differences are clamped. All attribution and historical transfer
are estimates; neither the original total nor paper C/K values are changed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from caprls_core import selection_cost_breakdown_analyze as diagnostic


PROFILE_COMPONENT = "estimated_extra_legacy_global_profile_effect"
DEFAULT_SEED = 102027


def allocate_records(
    records: Iterable[Mapping[str, Any]], *,
    expected_cases: Sequence[str] = diagnostic.EXPECTED_CASES,
    expected_warmup: int = 5, expected_measured: int = 30,
    bootstrap_draws: int = 2000, seed: int = DEFAULT_SEED,
    historical_total_seconds: float = diagnostic.HISTORICAL_TOTAL_SECONDS,
) -> dict[str, Any]:
    """Estimate a conserved partition, retaining all declared observations."""
    rows = list(records)
    checked = diagnostic.analyze_records(
        rows, expected_cases=expected_cases, expected_warmup=expected_warmup,
        expected_measured=expected_measured, bootstrap_draws=bootstrap_draws,
        seed=seed, historical_total_seconds=historical_total_seconds,
    )
    base: dict[str, Any] = {
        "schema": "caprls-selection-cost-profile-transfer-estimate-v1",
        "kind": "POSTHOC_EXPLANATORY_ESTIMATE",
        "model": "processing share x_k/L; extra legacy-profile share (L-P)/L; equal case mean of paired observation shares",
        "posthoc_model_not_original_predeclaration": True,
        "direct_historical_component_measurement": False,
        "historical_campaign": diagnostic.HISTORICAL_CAMPAIGN,
        "historical_total_seconds": historical_total_seconds,
        "historical_total_remains_a_measurement": True,
        "paper_performance_or_C_or_K_replaced": False,
        "diagnostic_cases": list(expected_cases),
        "all_cases_retained": True, "warmup_used_for_estimate": False,
        "negative_effects_clamped": False,
        "sparse_hook_overhead_still_in_processing_components": True,
        "all_measurement_overhead_isolated": False,
        "interpretation": "estimated transfer of a profiled historical total to sparse-instrumented processing phases plus the extra legacy global-profile effect",
        "limitations": [
            "New six-case warm diagnostics do not directly measure old 33-case component medians.",
            "The profile-on/off contrast includes remaining execution-context variation as well as the enabled global-profile effect.",
            "Sparse-hook overhead remains in processing phases; this does not isolate every measurement overhead.",
            "Bootstrap intervals describe the fixed diagnostic cohort, not uncertainty in transferring its fractions to the old workload.",
            "A negative profile increment is retained mathematically and cannot be presented as positive overhead.",
        ],
        "bootstrap": {"draws": bootstrap_draws, "seed": seed, "confidence": 0.95,
                      "unit": "matched formal selection observation; resample paired vectors within fixed cases"},
        "validation_status": checked["status"], "blockers": checked["blockers"],
    }
    if checked["blockers"]:
        return {**base, "status": "needs_review", "estimated_components": None,
                "clean_positive_overhead_attribution_supported": False}
    selected = [row for row in rows if row.get("kind", "selection") == "selection"
                and row.get("phase") == "measured"]
    indexed = {(row["case_id"], row["iteration"], row["arm"]): row for row in selected}
    categories = sorted({category for row in selected
                         for category in row["breakdown"]["exclusive_ms"]})
    if PROFILE_COMPONENT in categories:
        raise diagnostic.BreakdownAnalysisError("processing category collides with estimated profile-effect name")
    components = categories + [PROFILE_COMPONENT]
    case_vectors: list[list[list[float]]] = []
    case_summaries = []
    all_resolved_positive = True
    all_shares_stable = True
    for case_index, case in enumerate(expected_cases):
        vectors, delta_vectors = [], []
        for iteration in range(expected_measured):
            plain = indexed[(case, iteration, "plain_sparse")]
            legacy = indexed[(case, iteration, "legacy_profile_sparse")]
            plain_wall, plain_exclusive = diagnostic._record_values(plain)
            legacy_wall, _legacy_exclusive = diagnostic._record_values(legacy)
            vector = [plain_exclusive.get(category, 0.0) / legacy_wall for category in categories]
            vector.append((legacy_wall - plain_wall) / legacy_wall)
            vectors.append(vector)
            delta_vectors.append([legacy_wall - plain_wall])
        case_vectors.append(vectors)
        vector_draws = diagnostic._bootstrap_equal_case_means(
            [vectors], draws=bootstrap_draws, seed=seed + case_index,
        )
        delta_draws = diagnostic._bootstrap_equal_case_means(
            [delta_vectors], draws=bootstrap_draws, seed=seed + 1000 + case_index,
        )
        delta_interval = diagnostic._interval(delta_draws[0])
        resolved = delta_interval["lower"] > 0
        all_resolved_positive = all_resolved_positive and resolved
        split = len(vectors) // 2
        per_component = {}
        for index, component in enumerate(components):
            fractions = [vector[index] for vector in vectors]
            half_delta_pp = (statistics.fmean(fractions[split:]) - statistics.fmean(fractions[:split])) * 100
            stable = abs(half_delta_pp) <= 5.0
            all_shares_stable = all_shares_stable and stable
            per_component[component] = {
                "estimated_fraction_mean": statistics.fmean(fractions),
                "diagnostic_fraction_ci95": diagnostic._interval(vector_draws[index]),
                "second_minus_first_half_percentage_points": half_delta_pp,
                "stable_within_five_percentage_points": stable,
                "negative_observation_fractions": sum(value < 0 for value in fractions),
            }
        case_summaries.append({
            "case_id": case, "formal_pairs": len(vectors),
            "legacy_minus_plain_wall_ms_mean": statistics.fmean([row[0] for row in delta_vectors]),
            "legacy_minus_plain_wall_ms_ci95": delta_interval,
            "positive_extra_profile_effect_resolved": resolved,
            "attribution_status": "positive_diagnostic_contrast" if resolved else "cannot_resolve_positive_profile_effect",
            "estimated_components": per_component,
            "mean_fraction_sum": sum(value["estimated_fraction_mean"] for value in per_component.values()),
        })
    draws = diagnostic._bootstrap_equal_case_means(case_vectors, draws=bootstrap_draws, seed=seed + 10000)
    estimated = {}
    for index, component in enumerate(components):
        case_means = [case["estimated_components"][component]["estimated_fraction_mean"] for case in case_summaries]
        mean_fraction = statistics.fmean(case_means)
        interval = diagnostic._interval(draws[index])
        estimated[component] = {
            "kind": "estimated_processing_transfer" if component != PROFILE_COMPONENT else "estimated_extra_profile_transfer",
            "estimated_fraction": mean_fraction,
            "estimated_seconds": historical_total_seconds * mean_fraction,
            "diagnostic_fraction_ci95": interval,
            "scaled_diagnostic_ci95_seconds": {key: historical_total_seconds * value for key, value in interval.items()},
            "negative_mean_fraction": mean_fraction < 0,
            "between_case_fraction_min": min(case_means), "between_case_fraction_max": max(case_means),
        }
    negative_groups = [component for component, value in estimated.items() if value["negative_mean_fraction"]]
    clean = all_resolved_positive and not negative_groups
    if not clean:
        status = "diagnostic_only_unresolved_or_negative_profile_attribution"
    elif not all_shares_stable:
        status = "exploratory_unstable_posthoc_estimate"
    else:
        status = "posthoc_explanatory_estimate"
    return {
        **base, "status": status,
        "clean_positive_overhead_attribution_supported": clean,
        "positive_profile_difference_resolved_in_every_case": all_resolved_positive,
        "all_estimated_shares_stable_within_five_percentage_points": all_shares_stable,
        "negative_group_mean_components": negative_groups,
        "estimated_components": estimated, "cases": case_summaries,
        "estimated_fraction_sum": sum(value["estimated_fraction"] for value in estimated.values()),
        "estimated_seconds_sum": sum(value["estimated_seconds"] for value in estimated.values()),
    }


def write_estimate(output_dir: Path, result: Mapping[str, Any], input_path: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=False)
    payload = dict(result)
    payload["input_path"] = str(input_path.resolve())
    payload["input_sha256"] = hashlib.sha256(input_path.read_bytes()).hexdigest()
    (output_dir / "estimated_allocation_with_legacy_profile_effect.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    lines = ["# Post-hoc explanatory estimate: selection cost and legacy profiling", "",
             f"Status: {payload['status']}", "",
             "This is a provisional proportional allocation, not historical component measurement.",
             "The historical total and manuscript performance, selection cost and recovery remain unchanged.", ""]
    if payload.get("estimated_components"):
        lines += ["| Component | Estimated share | Estimated allocation (s) |", "|---|---:|---:|"]
        for component, value in payload["estimated_components"].items():
            lines.append(f"| {component} | {value['estimated_fraction']:.2%} | {value['estimated_seconds']:.6f} |")
        lines += ["", "Sparse-hook overhead remains within processing components.",
                  "Negative differences are retained; unresolved profiling effects cannot be claimed as positive overhead.",
                  "Intervals and each case's profile contrast are in the JSON receipt."]
    else:
        lines += ["No allocation was generated because validation failed.", ""]
        lines += [f"- {blocker}" for blocker in payload["blockers"]]
    (output_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True, help="new directory; existing output is never overwritten")
    parser.add_argument("--bootstrap-draws", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args(argv)
    if args.output_dir.exists():
        parser.error(f"refusing to overwrite {args.output_dir}")
    result = allocate_records(diagnostic.read_records(args.input), bootstrap_draws=args.bootstrap_draws, seed=args.seed)
    write_estimate(args.output_dir, result, args.input)
    print(json.dumps({"status": result["status"], "kind": result["kind"],
                      "output_dir": str(args.output_dir), "blockers": result["blockers"]}))
    return 2 if result["blockers"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
