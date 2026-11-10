"""Run the existing paper's non-E3 families with the frozen current AF code.

Each invocation owns a fresh output directory and one temporary cluster.  No
historical result is resumed and no baseline renderer is changed.  E3/SF10
execution belongs to ``final_af_e3_study`` because it must execute the selected
bound SQL rather than the historical count-query adapter.

Examples::

    python -m caprls_core.final_af_auxiliary_study --stage E1 --output results/raw/FINAL_AF/E1
    python -m caprls_core.final_af_auxiliary_study --stage E10 --output results/raw/FINAL_AF/E10

``--describe`` reads configuration without creating outputs or accessing a DB.
The content stage checks only the 19 E2/E10 protected-position cells; it never
represents those receipts as the legacy package's 52-cell completion.
"""

from __future__ import annotations

import argparse
from dataclasses import fields, is_dataclass
from datetime import datetime, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path
import shlex
import time
import traceback
from typing import Any, Mapping

import yaml

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = {
    "E1": "manifests/experiments/e1_smoke.yaml",
    "E7": "manifests/experiments/e7_runtime_audit_smoke.yaml",
    "E2": "manifests/experiments/e2_alternative_matrix_reduced.yaml",
    "E4": "manifests/experiments/e4_pairs_reduced.yaml",
    "E5": "manifests/experiments/e5_regret_reduced.yaml",
    "E10": "manifests/experiments/e10_case_study.yaml",
    "E6": "manifests/experiments/e6a_sigma_gate.yaml",
}
STAGES = tuple(MANIFESTS) + ("content-e2-e10",)
DATABASE_PROFILES = {
    "legacy_16mb": {"shared_buffers": "16MB"},
    "shared_host_2gb": {
        "shared_buffers": "2GB", "work_mem": "16MB",
        "effective_cache_size": "8GB", "max_wal_size": "4GB",
    },
}
PROTECTED = (
    "reference-manuscript.tex", "reference-manuscript.pdf", "main.tex", "main.pdf",
    "supplement.tex", "supplement.pdf", "AGENTS.md",
    "reference/notes.md",
    "submission-review-appendix/review_appendix.tex",
)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, default=str)
        handle.write("\n")


def _source_inventory(root: Path) -> dict[str, str]:
    paths = [p for directory in ("caprls_core", "planner", "sql", "manifests", "configs", "specs")
             for p in (root / directory).rglob("*")
             if p.is_file() and p.suffix in {".py", ".sql", ".yaml", ".yml"}
             and not p.name.startswith("._")]
    return {str(p.relative_to(root)): _sha(p) for p in sorted(paths)}


def _snapshot(root: Path, *, driver_files: tuple[str, ...] = (
        "caprls_core/final_af_auxiliary_study.py",)) -> dict[str, str]:
    # An analysis or experiment tool that is not invoked in this stage is
    # provenance inventory, not an execution dependency. The actual algorithms,
    # shared helpers, SQL/configuration and explicitly invoked drivers stay gated.
    return {name: digest for name, digest in _source_inventory(root).items()
            if not Path(name).name.startswith("final_af_") or name in driver_files}


def _freeze_driver_files(root: Path, output: Path, driver_files: tuple[str, ...]) -> None:
    for name in driver_files:
        source = root / name
        target = output / "driver-source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as handle:
            handle.write(source.read_bytes())


def _drift(root: Path, snapshot: Mapping[str, str]) -> list[str]:
    return [name for name, digest in snapshot.items()
            if not (root / name).is_file() or _sha(root / name) != digest]


def describe_stage(root: Path, stage: str, warmup: int | None = None,
                   measured: int | None = None, *,
                   database_profile: str = "legacy_16mb") -> dict[str, Any]:
    if stage not in STAGES:
        raise ValueError(f"unknown stage: {stage}")
    if database_profile not in DATABASE_PROFILES:
        raise ValueError(f"unknown database profile: {database_profile}")
    if stage == "content-e2-e10":
        if warmup is not None or measured is not None:
            raise ValueError("content checks have no timing repetitions")
        return {"stage": stage, "families": ["E2", "E10"], "expected_cells": 19,
                "timing": False, "e3_covered": False,
                "preflight": "current explicit-template content audit must pass before DB startup"}
    source = root / MANIFESTS[stage]
    manifest = yaml.safe_load(source.read_text())
    repetitions = dict(manifest["repetitions"])
    if stage == "E10":
        repetitions = {"warmup": 5, "measured": 30}
    if warmup is not None:
        repetitions["warmup"] = warmup
    if measured is not None:
        repetitions["measured"] = measured
    if repetitions["warmup"] < 0 or repetitions["measured"] < 1:
        raise ValueError("warmup must be nonnegative and measured must be positive")
    manifest["repetitions"] = repetitions
    return {"stage": stage, "database_profile": database_profile,
            "expected_database_settings": dict(DATABASE_PROFILES[database_profile]),
            "manifest_source": str(source),
            "manifest_source_sha256": _sha(source), "manifest": manifest,
            "selection_observer": "SparseSelectionObserver" if stage == "E10" else None,
            "baseline_algorithm_changes": False}


def _install_database_profile(name: str) -> dict[str, str]:
    profile = dict(DATABASE_PROFILES[name])
    os.environ.update(CAPRLS_PG_SHARED_BUFFERS=profile["shared_buffers"],
                      CAPRLS_PG_INITDB_SHARED_BUFFERS="400kB",
                      CAPRLS_PG_INITDB_MAX_CONNECTIONS="20")
    if name == "legacy_16mb":
        os.environ.pop("CAPRLS_PG_EXTRA_OPTS", None)
    else:
        extra = [part for key, value in profile.items() if key != "shared_buffers"
                 for part in ("-c", f"{key}={value}")]
        extra += ["-c", "hash_mem_multiplier=2.0", "-c", "plan_cache_mode=force_custom_plan"]
        os.environ["CAPRLS_PG_EXTRA_OPTS"] = shlex.join(extra)
    return profile


def _observed_database_settings(pg: Any, expected: Mapping[str, str]) -> dict[str, str]:
    from .postgres_runner import run_psql_command
    pairs = ",".join(f"'{key}',current_setting('{key}')" for key in expected)
    observed = json.loads(run_psql_command(f"SELECT json_build_object({pairs})::text;", pg).strip())
    if observed != dict(expected):
        raise RuntimeError(f"unexpected database profile: {observed}; expected {dict(expected)}")
    return observed


def _result_counts(result: Any) -> dict[str, Any]:
    if not is_dataclass(result):
        return {"result": str(result)}
    return {field.name: getattr(result, field.name) for field in fields(result)
            if field.name not in {"raw_result_paths", "correctness_result_paths"}}


def _run_family(root: Path, output: Path, stage: str, manifest_path: Path,
                pg: Any) -> dict[str, Any]:
    modules = {"E1": "e1_smoke", "E7": "e7_smoke", "E2": "e2_main",
               "E4": "e4_main", "E5": "e5_main", "E10": "e10_study", "E6": "e6a_smoke"}
    module = importlib.import_module("caprls_core." + modules[stage])
    function = getattr(module, "run_e10_case_study" if stage == "E10"
                       else "run_" + modules[stage])
    arguments = {"root": root, "manifest_path": manifest_path,
                 "output_dir": output / "raw"}
    if stage not in {"E1", "E6"}:
        arguments["pg_env"] = pg
    if stage != "E10":
        return _result_counts(function(**arguments))
    from .selection_cost_observer import SparseSelectionObserver
    with (output / "choice_costs.jsonl").open("x", encoding="utf-8") as sidecar:
        with SparseSelectionObserver(sidecar, e10=module) as observer:
            result = function(**arguments)
    if observer.errors:
        _write(output / "observer-errors.json", observer.errors)
        raise RuntimeError("E10 choice observation failed; retained observer-errors.json")
    manifest = yaml.safe_load(manifest_path.read_text())
    repetitions = manifest["repetitions"]
    expected_choices = (len(manifest["queries"]) * len(module._context_ids_from_manifest(manifest))
                        * (repetitions["warmup"] + repetitions["measured"]))
    if observer.choice_records != expected_choices:
        raise RuntimeError(f"E10 choice coverage is {observer.choice_records}, expected {expected_choices}")
    return {**_result_counts(result), "choice_records": observer.choice_records,
            "expected_choice_records": expected_choices,
            "choice_cost_scope": "including planning-input collection",
            "choice_sidecar": "choice_costs.jsonl"}


def _run_content(root: Path, output: Path, pg: Any) -> dict[str, Any]:
    from .content_verify import load_spec, ordered_cells
    from .final_af_content_study import run_content_study
    spec = load_spec(root / "specs/content_cells.yaml")
    cells = [cell for cell in ordered_cells(spec) if cell["family"] in {"E2", "E10"}]
    if len(cells) != 19:
        raise RuntimeError("protected-position E2/E10 cell inventory differs from 19")
    result = run_content_study(root, output / "content-package", only=[cell["short_id"] for cell in cells])
    if result["status"] != "pass" or result["passed"] != 19:
        raise RuntimeError("E2/E10 protected-position subset did not pass all 19 cells")
    return result


def run_stage(root: Path, output: Path, stage: str, *, warmup: int | None = None,
              measured: int | None = None,
              database_profile: str = "legacy_16mb") -> dict[str, Any]:
    root, output = root.resolve(), output.resolve()
    allowed = (root / "results/raw", root / "AF-wiki/raw/experiments")
    if not any(output != base and output.is_relative_to(base) for base in allowed):
        raise ValueError("output must be a fresh experiment directory below results/raw or AF-wiki/raw/experiments")
    configuration = describe_stage(root, stage, warmup, measured,
                                   database_profile=database_profile)
    output.mkdir(parents=True, exist_ok=False)
    driver_files = ("caprls_core/final_af_auxiliary_study.py",)
    if stage == "content-e2-e10":
        driver_files += ("caprls_core/final_af_content_study.py", "specs/content_compatibility.yaml")
    source = _snapshot(root, driver_files=driver_files)
    protected = {name: _sha(root / name) for name in PROTECTED if (root / name).is_file()}
    _write(output / "source-snapshot.json", source)
    _write(output / "source-inventory.json", _source_inventory(root))
    _freeze_driver_files(root, output, driver_files)
    _write(output / "protected-snapshot.json", protected)
    started = time.perf_counter()
    protocol = {"schema": "caprls-final-af-auxiliary-v1", "started_at": _utc(),
                "pid": os.getpid(), "configuration": configuration,
                "af_implementation": "current frozen source-snapshot.json",
                "baseline_implementation": "existing ordinary modes, unchanged",
                "formal_manuscript_writes": False, "resume_or_overwrite": False,
                "database_profile": database_profile,
                "expected_database_settings": dict(DATABASE_PROFILES[database_profile]),
                "shared_buffers": DATABASE_PROFILES[database_profile]["shared_buffers"]}
    _write(output / "protocol.json", protocol)
    manifest_path = output / "manifest.yaml"
    if "manifest" in configuration:
        manifest_path.write_text(yaml.safe_dump(configuration["manifest"], sort_keys=False))
    expected_settings = _install_database_profile(database_profile)
    from .postgres_runner import temporary_cluster, run_psql_command
    failure, result = None, None
    try:
        if stage == "content-e2-e10":
            from .final_af_content_study import current_audit
            if current_audit(root)["status"] != "pass":
                raise RuntimeError("current content compatibility audit failed")
            result = _run_content(root, output, None)
        elif stage in {"E1", "E6"}:
            result = _run_family(root, output, stage, manifest_path, None)
        else:
            with temporary_cluster(database="caprls_smoke") as pg:
                observed = _observed_database_settings(pg, expected_settings)
                _write(output / "settings-before.json", observed)
                _write(output / "database.json", {"host": pg.host, "port": pg.port,
                                                 "database": pg.database, "user": pg.user,
                                                 "shared_buffers": observed["shared_buffers"],
                                                 "database_profile": database_profile,
                                                 "observed_settings": observed})
                result = (_run_content(root, output, pg) if stage == "content-e2-e10"
                          else _run_family(root, output, stage, manifest_path, pg))
                _write(output / "settings-after.json", _observed_database_settings(pg, expected_settings))
    except Exception as exc:
        failure = {"error": str(exc), "traceback": traceback.format_exc()}
    source_drift, protected_drift = _drift(root, source), _drift(root, protected)
    completion = {"finished_at": _utc(), "stage": stage,
                  "status": "completed" if failure is None and not source_drift and not protected_drift else "failed",
                  "elapsed_seconds": time.perf_counter() - started, "result": result,
                  "failure": failure, "source_drift": source_drift,
                  "protected_drift": protected_drift,
                  "scientific_claims": "requires analysis of retained raw records"}
    _write(output / "completion.json", completion)
    return completion


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=STAGES, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--warmup", type=int)
    parser.add_argument("--measured", type=int)
    parser.add_argument("--database-profile", choices=tuple(DATABASE_PROFILES), default="legacy_16mb")
    parser.add_argument("--describe", action="store_true")
    args = parser.parse_args(argv)
    if args.describe:
        print(json.dumps(describe_stage(args.root, args.stage, args.warmup, args.measured,
                                       database_profile=args.database_profile), indent=2))
        return 0
    if args.output is None:
        parser.error("--output is required unless --describe is used")
    completion = run_stage(args.root, args.output, args.stage,
                           warmup=args.warmup, measured=args.measured,
                           database_profile=args.database_profile)
    print(json.dumps(completion, indent=2, default=str), flush=True)
    return 0 if completion["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
