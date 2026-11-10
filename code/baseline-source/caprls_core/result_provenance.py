"""Result-level provenance checks for generated CAPRLS artifacts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

import yaml

from .baselines import (
    ADMISSION_FIRST_MODE,
    load_mode_registry,
    normalize_mode_id,
)
from .manifest_validator import (
    REDUCED_JOB_SCALE,
    REDUCED_TPCH_SCALE,
    load_yaml,
    scientific_manifest_hash,
)
from .result_schema import (
    PREVIOUS_RAW_SCHEMA_VERSION,
    RAW_SCHEMA_VERSION,
    validate_raw_run_record,
)


RESULT_SCALE_EXPECTATIONS = {
    "e3_smoke_v1": {"tpch": REDUCED_TPCH_SCALE},
    "e3_to_main_oracle_smoke_v1": {"job": REDUCED_JOB_SCALE, "tpch": REDUCED_TPCH_SCALE},
    "e3_standard_reduced_v1": {"tpch": REDUCED_TPCH_SCALE, "job": REDUCED_JOB_SCALE},
    "e3_standard_sf1_v1": {"tpch": "SF1", "job": "full"},
    "e3_standard_sf1_rawpg_v1": {"tpch": "SF1", "job": "full"},
    "e3_standard_sf10_v1": {"tpch": "SF10", "job": "full"},
    "e6b_sigma_full_v1": {"tpch": "SF10", "job": "full"},
}

SOURCE_AUDITED_MANIFESTS = {
    "e1_smoke_v1",
    "e6a_sigma_gate_v1",
    "e6b_sigma_full_v1",
    "e8a_artifact_validity_gate_v1",
    "e8b_freshness_maintenance_v1",
}

ALLOWED_EXECUTION_SQL_SOURCES = {
    "artifact_validation_gate_sql",
    "benchmark_probe_sql",
    "native_baseline_sql",
    "not_executed",
    "planner_ir_emitted",
}

E6B_BENCHMARK_PROBE_COMPONENTS = {
    "NoBranchLineage",
    "NoPhysProps",
    "NoRIDMatProps",
    "NoResidual",
}


@dataclass(frozen=True)
class ResultProvenanceIssue:
    path: Path
    message: str


@lru_cache(maxsize=4)
def _successor_manifest_predecessors(repo_root: Path) -> Mapping[str, str]:
    """Return v3 successor-to-predecessor ids from sealed manifest lineage."""

    repo_root = repo_root.resolve()
    v3_dir = repo_root / "manifests" / "experiments" / "v3"
    predecessors: dict[str, str] = {}
    for successor_path in sorted(v3_dir.glob("*.yaml")):
        if successor_path.name.startswith("._"):
            continue
        successor = load_yaml(successor_path)
        if not isinstance(successor, Mapping):
            raise ValueError(f"{successor_path}: successor manifest must be a mapping")
        if successor.get("manifest_schema") != "caprls-experiment-manifest-v3":
            raise ValueError(f"{successor_path}: successor manifest schema is invalid")
        # This call verifies the predecessor path and hash before the successor
        # inherits any of the predecessor's scientific provenance gates.
        scientific_manifest_hash(successor_path)
        successor_id = successor.get("manifest_id")
        lineage = successor.get("lineage")
        if not isinstance(successor_id, str) or not successor_id:
            raise ValueError(f"{successor_path}: successor manifest_id is missing")
        if not isinstance(lineage, Mapping):
            raise ValueError(f"{successor_path}: successor lineage is missing")
        predecessor_relpath = lineage.get("predecessor_path")
        if not isinstance(predecessor_relpath, str) or not predecessor_relpath:
            raise ValueError(f"{successor_path}: lineage.predecessor_path is missing")
        predecessor_path = (repo_root / predecessor_relpath).resolve()
        try:
            predecessor_path.relative_to(repo_root)
        except ValueError as exc:
            raise ValueError(
                f"{successor_path}: lineage predecessor escapes the repository"
            ) from exc
        predecessor = load_yaml(predecessor_path)
        if not isinstance(predecessor, Mapping):
            raise ValueError(f"{predecessor_path}: predecessor manifest must be a mapping")
        predecessor_id = predecessor.get("manifest_id")
        if not isinstance(predecessor_id, str) or not predecessor_id:
            raise ValueError(f"{predecessor_path}: predecessor manifest_id is missing")
        prior = predecessors.setdefault(successor_id, predecessor_id)
        if prior != predecessor_id:
            raise ValueError(
                f"{successor_path}: successor {successor_id!r} has conflicting predecessors"
            )
    return predecessors


def _scientific_manifest_id(
    manifest_id: str,
    successor_predecessors: Mapping[str, str],
) -> str:
    return successor_predecessors.get(manifest_id, manifest_id)


def _record_dataset(record: Mapping[str, Any]) -> tuple[str, str]:
    dataset = record.get("dataset")
    if not isinstance(dataset, Mapping):
        return "", ""
    return str(dataset.get("name", "")), str(dataset.get("scale", ""))


def _is_auxiliary_json_path(path: Path) -> bool:
    return path.name.startswith(".") or "explain" in path.parts


def _raw_record_paths(
    raw_dir: Path,
) -> tuple[tuple[Path, ...], list[ResultProvenanceIssue]]:
    """Return raw records, honoring the sealed legacy artifact boundary."""

    artifact_manifest = raw_dir.parent / "artifact_manifest.json"
    if raw_dir.name != "raw" or not artifact_manifest.is_file():
        paths = tuple(
            sorted(
                item
                for item in raw_dir.rglob("*.json")
                if not _is_auxiliary_json_path(item)
            )
        )
        return paths, []

    try:
        manifest = json.loads(artifact_manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return (), [
            ResultProvenanceIssue(
                artifact_manifest,
                f"cannot load raw-result authority boundary: {exc}",
            )
        ]
    if not isinstance(manifest, Mapping):
        return (), [
            ResultProvenanceIssue(
                artifact_manifest,
                "raw-result authority boundary must be a JSON object",
            )
        ]
    included = manifest.get("included_top_level_directories")
    included_raw = included.get("raw") if isinstance(included, Mapping) else None
    if (
        not isinstance(included_raw, list)
        or isinstance(included_raw, (str, bytes))
        or not all(isinstance(item, str) and item for item in included_raw)
    ):
        return (), [
            ResultProvenanceIssue(
                artifact_manifest,
                "included_top_level_directories.raw must be a list of directory names",
            )
        ]

    issues: list[ResultProvenanceIssue] = []
    paths: list[Path] = []
    raw_root = raw_dir.resolve()
    for name in included_raw:
        relative = Path(name)
        if relative.name != name or name in {".", ".."}:
            issues.append(
                ResultProvenanceIssue(
                    artifact_manifest,
                    f"raw authority entry must name one top-level directory: {name!r}",
                )
            )
            continue
        directory = raw_dir / relative
        try:
            directory.resolve().relative_to(raw_root)
        except ValueError:
            issues.append(
                ResultProvenanceIssue(
                    artifact_manifest,
                    f"raw authority entry escapes results/raw: {name!r}",
                )
            )
            continue
        if not directory.is_dir():
            issues.append(
                ResultProvenanceIssue(
                    artifact_manifest,
                    f"included raw-result directory is missing: {name!r}",
                )
            )
            continue
        paths.extend(
            item
            for item in directory.rglob("*.json")
            if not _is_auxiliary_json_path(item)
        )
    return tuple(sorted(paths)), issues


def _execution_sql_source(record: Mapping[str, Any]) -> str:
    sql = record.get("sql")
    if not isinstance(sql, Mapping):
        return ""
    return str(sql.get("execution_sql_source", ""))


def _validate_e1_planner_status(
    path: Path,
    record: Mapping[str, Any],
    scientific_manifest_id: str,
) -> list[ResultProvenanceIssue]:
    if str(record.get("schema_version", "")) not in {
        PREVIOUS_RAW_SCHEMA_VERSION,
        RAW_SCHEMA_VERSION,
    }:
        return []
    if scientific_manifest_id != "e1_smoke_v1":
        return []
    try:
        mode = normalize_mode_id(str(record.get("mode", "")))
    except ValueError:
        return []
    if mode != ADMISSION_FIRST_MODE:
        return []

    issues: list[ResultProvenanceIssue] = []
    e1_case = record.get("e1_contract_case")
    if not isinstance(e1_case, Mapping):
        issues.append(ResultProvenanceIssue(path, "E1 v2 records must include e1_contract_case"))
        return issues
    if str(e1_case.get("status_source", "")) != "planner_query":
        issues.append(
            ResultProvenanceIssue(
                path,
                "E1 AdmissionFirst status must be derived from planner_query",
            )
        )

    planner = record.get("planner")
    query_plan = planner.get("query_plan") if isinstance(planner, Mapping) else None
    if not isinstance(query_plan, Mapping):
        issues.append(ResultProvenanceIssue(path, "E1 AdmissionFirst records must include planner.query_plan"))
        return issues
    planner_status = "pass" if bool(query_plan.get("ok")) else "expected_reject"
    if str(record.get("status", "")) != planner_status:
        issues.append(
            ResultProvenanceIssue(
                path,
                f"E1 top-level status must match planner.query_plan.ok: expected {planner_status!r}",
            )
        )
    if str(e1_case.get("status", "")) != planner_status:
        issues.append(
            ResultProvenanceIssue(
                path,
                f"E1 contract-case status must match planner.query_plan.ok: expected {planner_status!r}",
            )
        )
    return issues


def _validate_benchmark_probe_source(
    path: Path,
    record: Mapping[str, Any],
    scientific_manifest_id: str,
) -> list[ResultProvenanceIssue]:
    if _execution_sql_source(record) != "benchmark_probe_sql":
        return []
    if scientific_manifest_id != "e6b_sigma_full_v1":
        return [
            ResultProvenanceIssue(
                path,
                "benchmark_probe_sql is only allowed for bounded E6B probes without equivalent IR emission",
            )
        ]
    e6b_case = record.get("e6b_study_case")
    if not isinstance(e6b_case, Mapping):
        return [
            ResultProvenanceIssue(
                path,
                "E6B benchmark_probe_sql records must identify e6b_study_case.component",
            )
        ]
    component = str(e6b_case.get("component", ""))
    if component not in E6B_BENCHMARK_PROBE_COMPONENTS:
        return [
            ResultProvenanceIssue(
                path,
                f"E6B benchmark_probe_sql is not allowed for component {component!r}",
            )
        ]
    return []


def _is_live_e1_e6_e8_path(path: Path) -> bool:
    parts = path.parts
    for index, part in enumerate(parts[:-1]):
        if part == "raw":
            return index + 1 < len(parts) and parts[index + 1] in {"E1", "E6", "E8"}
    return True


def validate_result_provenance(raw_dir: Path) -> list[ResultProvenanceIssue]:
    issues: list[ResultProvenanceIssue] = []
    if not raw_dir.exists():
        issues.append(ResultProvenanceIssue(raw_dir, "raw result directory does not exist"))
        return issues

    repo_root = Path(__file__).resolve().parents[1]
    mode_registry = load_mode_registry(repo_root)
    try:
        successor_predecessors = _successor_manifest_predecessors(repo_root)
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as exc:
        issues.append(
            ResultProvenanceIssue(
                repo_root / "manifests" / "experiments" / "v3",
                f"cannot load successor manifest lineage: {exc}",
            )
        )
        return issues
    record_paths, authority_issues = _raw_record_paths(raw_dir)
    issues.extend(authority_issues)
    for path in record_paths:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            issues.append(ResultProvenanceIssue(path, f"invalid JSON: {exc}"))
            continue
        if not isinstance(record, Mapping):
            issues.append(ResultProvenanceIssue(path, "raw result must be a JSON object"))
            continue
        for issue in validate_raw_run_record(record, mode_registry=mode_registry):
            issues.append(
                ResultProvenanceIssue(path, f"schema {issue.path}: {issue.message}")
            )
        manifest_id = str(record.get("manifest_id", ""))
        scientific_manifest_id = _scientific_manifest_id(
            manifest_id,
            successor_predecessors,
        )
        issues.extend(
            _validate_e1_planner_status(path, record, scientific_manifest_id)
        )
        if scientific_manifest_id in SOURCE_AUDITED_MANIFESTS and _is_live_e1_e6_e8_path(path):
            execution_sql_source = _execution_sql_source(record)
            if not execution_sql_source:
                issues.append(
                    ResultProvenanceIssue(
                        path,
                        f"{manifest_id} must record sql.execution_sql_source",
                    )
                )
            elif execution_sql_source == "legacy_runner_sql":
                issues.append(
                    ResultProvenanceIssue(
                        path,
                        f"{manifest_id} must not use legacy_runner_sql execution provenance",
                    )
                )
            elif execution_sql_source not in ALLOWED_EXECUTION_SQL_SOURCES:
                issues.append(
                    ResultProvenanceIssue(
                        path,
                        f"{manifest_id} has unknown sql.execution_sql_source {execution_sql_source!r}",
                    )
                )
            issues.extend(
                _validate_benchmark_probe_source(
                    path,
                    record,
                    scientific_manifest_id,
                )
            )
            if execution_sql_source == "planner_ir_emitted":
                sql = record.get("sql")
                emitted_sql_path = str(sql.get("emitted_sql_path", "")) if isinstance(sql, Mapping) else ""
                if not emitted_sql_path.startswith("generated:"):
                    issues.append(
                        ResultProvenanceIssue(
                            path,
                            "planner_ir_emitted rows must use generated: emitted_sql_path",
                        )
                    )
        expected_by_dataset = RESULT_SCALE_EXPECTATIONS.get(scientific_manifest_id)
        if not expected_by_dataset:
            continue
        dataset_name, dataset_scale = _record_dataset(record)
        expected_scale = expected_by_dataset.get(dataset_name)
        if expected_scale is not None and dataset_scale != expected_scale:
            issues.append(
                ResultProvenanceIssue(
                    path,
                    f"{manifest_id} dataset {dataset_name} must use scale "
                    f"{expected_scale!r}, got {dataset_scale!r}",
                )
            )
    return issues
