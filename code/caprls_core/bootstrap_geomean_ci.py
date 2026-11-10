"""Paired bootstrap intervals for the paper's NativePG/AdmissionFirst ratios.

This module is reporting-only.  It reads the checked-in E3 and E10 summary
records and never launches PostgreSQL or an experiment campaign.
"""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
    mode_execution_order_key,
    normalize_mode_id,
)

import argparse
import csv
import hashlib
import json
import math
import random
import statistics
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence


DEFAULT_SEED = 20260904
DEFAULT_REPLICATES = 10_000
NATIVE_MODE = "native-pg-rls"
MODE_ORDER = (NATIVE_MODE, ADMISSION_FIRST_MODE)
E3_POLICY_ENFORCEMENT_MODES = (
    "auth-index-enum-only",
    "barrier-only",
    ADMISSION_FIRST_MODE,
    "injection-only",
    "local-greedy",
    NATIVE_MODE,
    "native-pg-rls-physical-design",
    "security-barrier",
    "strong-auth-index",
)
E3_EXPECTED_POINT = 1.4858508306204965
E10_EXPECTED_POINT = 1.1087697981627656


class BootstrapAnalysisError(ValueError):
    """Raised when a frozen input does not satisfy the analysis contract."""


@dataclass(frozen=True)
class Sample:
    iteration: int
    total_ms: float
    runner_sql_hash: str


@dataclass(frozen=True)
class Cell:
    key: tuple[str, str]
    samples_by_mode: Mapping[str, tuple[Sample, ...]]

    @property
    def iterations(self) -> tuple[int, ...]:
        return tuple(sample.iteration for sample in self.samples_by_mode[MODE_ORDER[0]])


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _cell_key(row: Mapping[str, str], policy_field: str) -> tuple[str, str]:
    return (str(row.get("query_id") or ""), str(row.get(policy_field) or ""))


def _load_cells(
    path: Path,
    *,
    policy_field: str,
    included_modes: Sequence[str],
    required_modes: Sequence[str],
    expected_cells: int,
    expected_iterations: int = 10,
    require_runner_sql_hash: bool,
) -> tuple[Cell, ...]:
    rows = [
        row
        for row in _read_csv(path)
        if row.get("run_kind") == "normal_mode"
        and row.get("measurement_phase") == "measured"
        and row.get("status") == "pass"
        and normalize_mode_id(str(row.get("mode", ""))) in included_modes
    ]
    grouped: defaultdict[tuple[str, str], defaultdict[str, list[Sample]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in rows:
        try:
            iteration = int(row["measurement_iteration"])
            total_ms = float(row["total_ms"])
        except (KeyError, TypeError, ValueError) as exc:
            raise BootstrapAnalysisError(f"invalid measured row in {path}") from exc
        if total_ms <= 0.0:
            raise BootstrapAnalysisError(f"non-positive total_ms in {path}")
        runner_sql_hash = str(row.get("runner_sql_hash") or "")
        if require_runner_sql_hash and not runner_sql_hash:
            raise BootstrapAnalysisError(f"missing runner_sql_hash in {path}")
        grouped[_cell_key(row, policy_field)][
            normalize_mode_id(str(row["mode"]))
        ].append(
            Sample(iteration, total_ms, runner_sql_hash)
        )

    if len(grouped) != expected_cells:
        raise BootstrapAnalysisError(
            f"{path} has {len(grouped)} cells; expected {expected_cells}"
        )

    required_mode_set = set(required_modes)
    expected_iteration_set = set(range(1, expected_iterations + 1))
    cells: list[Cell] = []
    for key in sorted(grouped):
        by_mode = grouped[key]
        if not required_mode_set.issubset(by_mode):
            missing = sorted(required_mode_set - set(by_mode), key=mode_execution_order_key)
            extra: list[str] = []
            raise BootstrapAnalysisError(
                f"{path} cell {key} has wrong modes; missing={missing}, extra={extra}"
            )
        normalized: dict[str, tuple[Sample, ...]] = {}
        for mode in sorted(by_mode, key=mode_execution_order_key):
            samples = tuple(sorted(by_mode[mode], key=lambda sample: sample.iteration))
            iterations = [sample.iteration for sample in samples]
            if len(iterations) != expected_iterations or set(iterations) != expected_iteration_set:
                raise BootstrapAnalysisError(
                    f"{path} cell {key}, mode {mode} has iterations {iterations}"
                )
            if require_runner_sql_hash and len({sample.runner_sql_hash for sample in samples}) != 1:
                raise BootstrapAnalysisError(
                    f"{path} cell {key}, mode {mode} has an unstable runner_sql_hash"
                )
            normalized[mode] = samples
        cells.append(Cell(key, normalized))
    return tuple(cells)


def load_e3_cells(path: Path) -> tuple[Cell, ...]:
    return _load_cells(
        path,
        policy_field="param_policy_config_id",
        included_modes=E3_POLICY_ENFORCEMENT_MODES,
        required_modes=MODE_ORDER,
        expected_cells=33,
        require_runner_sql_hash=True,
    )


def load_e10_cells(path: Path) -> tuple[Cell, ...]:
    return _load_cells(
        path,
        policy_field="policy_id",
        included_modes=MODE_ORDER,
        required_modes=MODE_ORDER,
        expected_cells=11,
        require_runner_sql_hash=False,
    )


def _geometric_mean(values: Iterable[float]) -> float:
    materialized = tuple(values)
    if not materialized or any(value <= 0.0 for value in materialized):
        raise BootstrapAnalysisError("geometric mean requires positive values")
    return math.exp(math.fsum(math.log(value) for value in materialized) / len(materialized))


def _e3_ratio(cell: Cell, sampled_iterations: Sequence[int]) -> float:
    """Rebuild exact-runner-SQL pooling for one E3 bootstrap draw."""

    by_hash: defaultdict[str, list[float]] = defaultdict(list)
    mode_hashes: dict[str, str] = {}
    for mode in sorted(cell.samples_by_mode, key=mode_execution_order_key):
        by_iteration = {sample.iteration: sample for sample in cell.samples_by_mode[mode]}
        stable_hashes = {sample.runner_sql_hash for sample in cell.samples_by_mode[mode]}
        if len(stable_hashes) != 1:
            raise BootstrapAnalysisError(f"E3 cell {cell.key}, mode {mode} has unstable SQL")
        mode_hash = next(iter(stable_hashes))
        mode_hashes[mode] = mode_hash
        by_hash[mode_hash].extend(
            by_iteration[iteration].total_ms for iteration in sampled_iterations
        )
    native_ms = statistics.median(by_hash[mode_hashes[NATIVE_MODE]])
    admission_first_ms = statistics.median(by_hash[mode_hashes[ADMISSION_FIRST_MODE]])
    return native_ms / admission_first_ms


def _e10_ratio(cell: Cell, sampled_iterations: Sequence[int]) -> float:
    """Apply E10's mode-local median estimator to one paired draw."""

    medians: dict[str, float] = {}
    for mode in MODE_ORDER:
        by_iteration = {sample.iteration: sample for sample in cell.samples_by_mode[mode]}
        medians[mode] = statistics.median(
            by_iteration[iteration].total_ms for iteration in sampled_iterations
        )
    return medians[NATIVE_MODE] / medians[ADMISSION_FIRST_MODE]


def _ratio_function(estimator: str):
    if estimator == "e3_exact_runner_sql_pooling":
        return _e3_ratio
    if estimator == "e10_mode_local":
        return _e10_ratio
    raise BootstrapAnalysisError(f"unknown estimator: {estimator}")


def point_estimate(cells: Sequence[Cell], *, estimator: str) -> float:
    ratio_fn = _ratio_function(estimator)
    return _geometric_mean(ratio_fn(cell, cell.iterations) for cell in cells)


def bootstrap_distribution(
    cells: Sequence[Cell],
    *,
    estimator: str,
    seed: int,
    replicates: int,
) -> list[float]:
    if replicates <= 0:
        raise BootstrapAnalysisError("replicates must be positive")
    ratio_fn = _ratio_function(estimator)
    rng = random.Random(seed)
    estimates: list[float] = []
    for _ in range(replicates):
        ratios: list[float] = []
        for cell in cells:
            iterations = cell.iterations
            draw = tuple(iterations[rng.randrange(len(iterations))] for _ in iterations)
            ratios.append(ratio_fn(cell, draw))
        estimates.append(_geometric_mean(ratios))
    return estimates


def _linear_percentile(sorted_values: Sequence[float], probability: float) -> float:
    if not sorted_values:
        raise BootstrapAnalysisError("percentile requires observations")
    position = (len(sorted_values) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    fraction = position - lower
    return sorted_values[lower] * (1.0 - fraction) + sorted_values[upper] * fraction


def percentile_interval(values: Sequence[float]) -> tuple[float, float]:
    ordered = sorted(values)
    return (_linear_percentile(ordered, 0.025), _linear_percentile(ordered, 0.975))


def analyze(
    *,
    repo_root: Path,
    seed: int = DEFAULT_SEED,
    replicates: int = DEFAULT_REPLICATES,
) -> dict[str, object]:
    e3_path = repo_root / "results/summarized/E3_SF1_RAWPG_V1/runs.csv"
    e10_path = repo_root / "results/summarized/SIGMOD_CURRENT_E10/runs.csv"
    e3_cells = load_e3_cells(e3_path)
    e10_cells = load_e10_cells(e10_path)

    e3_point = point_estimate(e3_cells, estimator="e3_exact_runner_sql_pooling")
    e10_point = point_estimate(e10_cells, estimator="e10_mode_local")
    if not math.isclose(e3_point, E3_EXPECTED_POINT, rel_tol=1e-12, abs_tol=1e-12):
        raise BootstrapAnalysisError(
            f"E3 point estimate {e3_point} does not reproduce {E3_EXPECTED_POINT}"
        )
    if not math.isclose(e10_point, E10_EXPECTED_POINT, rel_tol=1e-12, abs_tol=1e-12):
        raise BootstrapAnalysisError(
            f"E10 point estimate {e10_point} does not reproduce {E10_EXPECTED_POINT}"
        )

    e3_draws = bootstrap_distribution(
        e3_cells,
        estimator="e3_exact_runner_sql_pooling",
        seed=seed,
        replicates=replicates,
    )
    # A separate, derived seed keeps each result reproducible if the other
    # family is later removed from this reporting command.
    e10_seed = seed + 1
    e10_draws = bootstrap_distribution(
        e10_cells,
        estimator="e10_mode_local",
        seed=e10_seed,
        replicates=replicates,
    )
    e3_low, e3_high = percentile_interval(e3_draws)
    e10_low, e10_high = percentile_interval(e10_draws)

    common = {
        "ratio_definition": "NativePG-RLS median total_ms / AdmissionFirst median total_ms",
        "pre_specified_modes": list(MODE_ORDER),
        "measured_iterations_per_cell": 10,
        "bootstrap_unit": (
            "measurement_iteration block within each cell; the same sampled "
            "iteration indices are used for both modes"
        ),
        "confidence_interval": "95% percentile interval with linear interpolation",
        "fixed_cell_set": True,
    }
    return {
        "schema_version": "caprls_native_admission_first_bootstrap_v1",
        "replicates": replicates,
        "base_seed": seed,
        "scope_note": (
            "Intervals describe repeated-measurement uncertainty conditional on "
            "the fixed workload cells. They do not cover the post-hoc "
            "fastest policy-enforcement comparison."
        ),
        "mixed_workload": {
            **common,
            "family": "E3_SF1_RAWPG_V1",
            "source": str(e3_path.relative_to(repo_root)),
            "source_sha256": _sha256(e3_path),
            "cell_count": len(e3_cells),
            "seed": seed,
            "estimator": (
                "within every bootstrap replicate, pool measured total_ms by exact "
                "runner_sql_hash across all policy-enforcement modes, take each target "
                "mode's pooled median, then geometrically average cell ratios"
            ),
            "point_estimate": e3_point,
            "ci95_low": e3_low,
            "ci95_high": e3_high,
        },
        "case_study": {
            **common,
            "family": "SIGMOD_CURRENT_E10",
            "source": str(e10_path.relative_to(repo_root)),
            "source_sha256": _sha256(e10_path),
            "cell_count": len(e10_cells),
            "seed": e10_seed,
            "execution_order": "fixed per-cell mode order in the E10 runner",
            "execution_order_note": (
                "paired bootstrap preserves measurement_iteration blocks but does "
                "not remove a systematic effect of the runner's fixed mode order"
            ),
            "estimator": (
                "within every bootstrap replicate, take separate NativePG-RLS and "
                "AdmissionFirst medians, then geometrically average cell ratios"
            ),
            "point_estimate": e10_point,
            "ci95_low": e10_low,
            "ci95_high": e10_high,
        },
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--replicates", type=int, default=DEFAULT_REPLICATES)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/analysis/native_admission_first_bootstrap_ci.json"),
    )
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    result = analyze(repo_root=repo_root, seed=args.seed, replicates=args.replicates)
    output = args.output if args.output.is_absolute() else repo_root / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
