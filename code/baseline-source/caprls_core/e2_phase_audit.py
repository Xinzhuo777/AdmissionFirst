"""Validation for the E2 phase-diagram evidence package."""

from __future__ import annotations

import csv
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from itertools import product
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from .manifest_validator import file_sha256


FIG3_DIR = "fig3_e2_phase_diagram"
FIG3_SOURCE = "fig3_e2_phase_diagram_source.csv"
FIG3_WITNESS_SOURCE = "fig3_e2_phase_witness_audit.csv"
RAW_SUBDIR = "E2_PROTOCOL"
SUMMARY_SUBDIR = "E2_PROTOCOL"

EXPECTED_MANIFEST_ID = "e2_alternative_matrix_reduced_v2"
EXPECTED_MANIFEST_IDS = frozenset(
    {
        EXPECTED_MANIFEST_ID,
        "e2_alternative_matrix_reduced_v2_taxonomy_v3",
    }
)
EXPECTED_EXPERIMENT = "E2"
EXPECTED_STAGE = "alternative_matrix_reduced"
EXPECTED_QUERY_ID = "E2_range_count"


def _is_sidecar_path(path: Path) -> bool:
    return path.name.startswith("._") or path.name.startswith(".") or "explain" in path.parts


EXPECTED_POLICY_ID = "tenant_group"
EXPECTED_DATASET = ("synthetic_saas", "1e5", "42")
EXPECTED_RANKING_METRIC = "execution_time_ms"
DEFAULT_MIN_WINNING_FAMILIES = 0

EXPECTED_TEMPLATE_CANDIDATES = (
    "barrier_filter_v1",
    "safe_predicate_injection_v1",
    "auth_view_scan_v1",
    "auth_index_enum_v1",
    "strong_auth_index_keyed_v1",
    "mav_scan_v1",
    "guard_candidate_plus_residual_v1",
    "hybrid_intersect_v1",
)

DEFAULT_REQUIRED_WINNING_FAMILIES: tuple[str, ...] = ()

TEMPLATE_FAMILIES = {
    "auth_index_enum_v1": "auth-index",
    "strong_auth_index_keyed_v1": "auth-index",
    "auth_view_scan_v1": "auth-view",
    "barrier_filter_v1": "barrier",
    "guard_candidate_plus_residual_v1": "guard",
    "hybrid_intersect_v1": "hybrid",
    "mav_scan_v1": "mav",
    "safe_predicate_injection_v1": "safe-injection",
}

FIG3_FAMILY_WITNESS_DIRECTIONS = {
    "auth-index": {
        "theory_witnesses": ("W1", "W4", "W5"),
        "witness_role": "expected-best-auth-artifact",
    },
    "hybrid": {
        "theory_witnesses": ("W1", "W4", "W5"),
        "witness_role": "expected-best-auth-artifact-plus-residual",
    },
    "safe-injection": {
        "theory_witnesses": ("W2", "W3"),
        "witness_role": "expected-best-exact-filter",
    },
    "auth-view": {
        "theory_witnesses": ("W2", "W3"),
        "witness_role": "expected-best-exact-filter-view",
    },
    "mav": {
        "theory_witnesses": ("W3", "W5"),
        "witness_role": "fresh-materialized-artifact-region",
    },
}

T5_WITNESS_COVERAGE = {
    "W1": {
        "fixed_mode_under_test": "barrier-only",
        "expected_best_direction": "auth-index-or-hybrid",
        "e5_witness_id": "barrier_bad_auth_singleton",
    },
    "W2": {
        "fixed_mode_under_test": "auth-index-enum-only",
        "expected_best_direction": "exact-filter",
        "e5_witness_id": "auth_enum_bad_point_query",
    },
    "W3": {
        "fixed_mode_under_test": "mav-only",
        "expected_best_direction": "exact-filter-or-fresh-mav-boundary",
        "e5_witness_id": "mav_bad_single_use_refresh",
    },
    "W4": {
        "fixed_mode_under_test": "guard-mandatory-discharge",
        "expected_best_direction": "auth-index-or-hybrid",
        "e5_witness_id": "guard_bad_unselective_residual",
    },
    "W5": {
        "fixed_mode_under_test": "injection-only",
        "expected_best_direction": "auth-index-hybrid-or-mav",
        "e5_witness_id": "injection_bad_expensive_singleton",
    },
}

GOOD_REJECT_STATUSES = {"expected_reject", "static_verifier_fail"}


@dataclass(frozen=True)
class E2PhaseAuditIssue:
    path: str
    message: str


@dataclass(frozen=True)
class E2PhaseAuditReport:
    issues: tuple[E2PhaseAuditIssue, ...]
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
    if not math.isfinite(parsed):
        return None
    return parsed


def _maybe_int(value: Any) -> int | None:
    parsed = _maybe_float(value)
    if parsed is None:
        return None
    return int(parsed)


def _maybe_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no"}:
            return False
    return None


def _median(values: Sequence[float]) -> float:
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[midpoint]
    return (ordered[midpoint - 1] + ordered[midpoint]) / 2.0


def _percentile(values: Sequence[float], q: float) -> float:
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


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _slug_float(value: float) -> str:
    return str(value).replace(".", "p").replace("-", "m")


def _template_family(template_id: str) -> str:
    return TEMPLATE_FAMILIES.get(template_id, "unknown")


def _parse_required_families(required_winning_families: Sequence[str] | str | None) -> set[str]:
    if required_winning_families is None:
        return set(DEFAULT_REQUIRED_WINNING_FAMILIES)
    if isinstance(required_winning_families, str):
        return {item.strip() for item in required_winning_families.split(",") if item.strip()}
    return {str(item).strip() for item in required_winning_families if str(item).strip()}


def _load_manifest(
    manifest_path: Path | None,
    issues: list[E2PhaseAuditIssue],
    details: dict[str, Any],
) -> tuple[Mapping[str, Any] | None, set[str], set[str], str | None, int, int]:
    if manifest_path is None:
        details["manifest_validation"] = "skipped"
        return None, set(), set(EXPECTED_TEMPLATE_CANDIDATES), None, 0, 0
    if not manifest_path.exists():
        issues.append(E2PhaseAuditIssue(str(manifest_path), "missing E2 manifest"))
        return None, set(), set(EXPECTED_TEMPLATE_CANDIDATES), None, 0, 0

    try:
        with manifest_path.open("r", encoding="utf-8") as fh:
            manifest = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        issues.append(E2PhaseAuditIssue(str(manifest_path), f"invalid YAML: {exc}"))
        return None, set(), set(EXPECTED_TEMPLATE_CANDIDATES), None, 0, 0

    if not isinstance(manifest, Mapping):
        issues.append(E2PhaseAuditIssue(str(manifest_path), "manifest must be a YAML mapping"))
        return None, set(), set(EXPECTED_TEMPLATE_CANDIDATES), None, 0, 0

    manifest_hash = file_sha256(manifest_path)
    variables = manifest.get("variables") if isinstance(manifest.get("variables"), Mapping) else {}
    s_auth_values = [float(item) for item in variables.get("s_auth", [])]
    s_q_values = [float(item) for item in variables.get("s_q", [])]
    policy_costs = [str(item) for item in variables.get("policy_cost", [])]
    artifact_availability = [str(item) for item in variables.get("artifact_availability", [])]
    grid_points = {
        f"sq{_slug_float(s_q)}_sa{_slug_float(s_auth)}_{policy_cost}_{availability}"
        for s_auth, s_q, policy_cost, availability in product(
            s_auth_values,
            s_q_values,
            policy_costs,
            artifact_availability,
        )
    }
    templates = {str(item) for item in manifest.get("template_candidates", [])}
    repetitions = manifest.get("repetitions") if isinstance(manifest.get("repetitions"), Mapping) else {}
    manifest_warmup = int(_maybe_int(repetitions.get("warmup")) or 0)
    manifest_measured = int(_maybe_int(repetitions.get("measured")) or 0)

    details["manifest"] = {
        "path": str(manifest_path),
        "hash": manifest_hash,
        "manifest_id": manifest.get("manifest_id"),
        "experiment": manifest.get("experiment"),
        "stage": manifest.get("stage"),
        "ranking_metric": manifest.get("ranking_metric"),
        "grid_points": sorted(grid_points),
        "template_candidates": sorted(templates),
        "repetitions": {"warmup": manifest_warmup, "measured": manifest_measured},
    }

    if manifest.get("manifest_id") != EXPECTED_MANIFEST_ID:
        issues.append(E2PhaseAuditIssue(str(manifest_path), "manifest_id is not the frozen E2 reduced manifest"))
    if manifest.get("experiment") != EXPECTED_EXPERIMENT or manifest.get("stage") != EXPECTED_STAGE:
        issues.append(E2PhaseAuditIssue(str(manifest_path), "manifest is not E2 alternative_matrix_reduced"))
    if manifest.get("ranking_metric") != EXPECTED_RANKING_METRIC:
        issues.append(E2PhaseAuditIssue(str(manifest_path), "E2 ranking_metric is not measured execution_time_ms"))
    if templates != set(EXPECTED_TEMPLATE_CANDIDATES):
        issues.append(E2PhaseAuditIssue(str(manifest_path), "E2 template candidate set differs from the frozen eight-template pool"))
    if not grid_points:
        issues.append(E2PhaseAuditIssue(str(manifest_path), "manifest produces no E2 grid points"))
    queries = manifest.get("queries") if isinstance(manifest.get("queries"), Sequence) else []
    query_ids = {
        str(item.get("query_id"))
        for item in queries
        if isinstance(item, Mapping) and item.get("query_id")
    }
    if query_ids != {EXPECTED_QUERY_ID}:
        issues.append(E2PhaseAuditIssue(str(manifest_path), f"E2 query set {sorted(query_ids)} is not the frozen range-count query"))

    return manifest, grid_points, templates, manifest_hash, manifest_warmup, manifest_measured


def _load_raw_records(raw_dir: Path, issues: list[E2PhaseAuditIssue]) -> list[_RawRecord]:
    e2_dir = raw_dir / RAW_SUBDIR
    if not e2_dir.exists():
        issues.append(E2PhaseAuditIssue(str(e2_dir), "missing E2 protocol raw directory"))
        return []
    records: list[_RawRecord] = []
    for path in sorted(item for item in e2_dir.rglob("*.json") if not _is_sidecar_path(item)):
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            issues.append(E2PhaseAuditIssue(str(path), f"invalid JSON: {exc}"))
            continue
        if not isinstance(parsed, Mapping):
            issues.append(E2PhaseAuditIssue(str(path), "raw result must be a JSON object"))
            continue
        records.append(_RawRecord(path=path, record=parsed))
    if not records:
        issues.append(E2PhaseAuditIssue(str(e2_dir), "E2 protocol raw directory has no JSON records"))
    return records


def _record_grid_point(item: _RawRecord) -> str:
    return str(_get(item.record, "query.params.grid_point"))


def _record_template_id(item: _RawRecord) -> str:
    return str(_get(item.record, "template.template_id"))


def _measurement_phase(item: _RawRecord) -> str:
    return str(_get(item.record, "measurement.phase"))


def _measurement_iteration(item: _RawRecord) -> int | None:
    return _maybe_int(_get(item.record, "measurement.iteration"))


def _validate_protocol(
    items: Sequence[_RawRecord],
    *,
    path_label: str,
    expected_warmup: int,
    expected_measured: int,
    issues: list[E2PhaseAuditIssue],
) -> dict[str, Any]:
    phase_iterations: dict[str, list[int]] = defaultdict(list)
    for item in items:
        phase = _measurement_phase(item)
        iteration = _measurement_iteration(item)
        warmup = _maybe_int(_get(item.record, "measurement.warmup_repetitions", None))
        measured = _maybe_int(_get(item.record, "measurement.measured_repetitions", None))
        if phase not in {"warmup", "measured"} or iteration is None:
            issues.append(E2PhaseAuditIssue(str(item.path), f"{path_label} lacks measurement phase/iteration"))
            continue
        if warmup != expected_warmup or measured != expected_measured:
            issues.append(
                E2PhaseAuditIssue(
                    str(item.path),
                    f"{path_label} declares warmup/measured {warmup}/{measured}, "
                    f"expected {expected_warmup}/{expected_measured}",
                )
            )
        phase_iterations[phase].append(iteration)

    observed: dict[str, Any] = {}
    for phase, expected_count in (("warmup", expected_warmup), ("measured", expected_measured)):
        iterations = phase_iterations.get(phase, [])
        unique = sorted(set(iterations))
        observed[phase] = {"count": len(iterations), "unique_iterations": unique}
        if len(iterations) != expected_count or unique != list(range(1, expected_count + 1)):
            issues.append(
                E2PhaseAuditIssue(
                    path_label,
                    f"{phase} repetitions {unique} with count {len(iterations)} "
                    f"do not match expected 1..{expected_count}",
                )
            )
        if len(iterations) != len(unique):
            issues.append(E2PhaseAuditIssue(path_label, f"{phase} repetitions contain duplicate iterations"))
    return observed


def _validate_raw_candidate_pool(
    records: Sequence[_RawRecord],
    *,
    expected_grid_points: set[str],
    expected_templates: set[str],
    expected_manifest_hash: str | None,
    expected_warmup: int,
    expected_measured: int,
    issues: list[E2PhaseAuditIssue],
    details: dict[str, Any],
) -> dict[str, int]:
    candidate_records = [item for item in records if str(item.record.get("run_kind", "")) == "template_candidate"]
    measured_candidates = [item for item in candidate_records if _measurement_phase(item) == "measured"]
    warmup_candidates = [item for item in candidate_records if _measurement_phase(item) == "warmup"]
    details["raw_candidate_pool"] = {
        "record_count": len(candidate_records),
        "measured_record_count": len(measured_candidates),
        "warmup_record_count": len(warmup_candidates),
        "status_counts": dict(sorted(Counter(str(item.record.get("status", "")) for item in candidate_records).items())),
        "template_counts": dict(sorted(Counter(_record_template_id(item) for item in candidate_records).items())),
        "grid_point_counts": dict(sorted(Counter(_record_grid_point(item) for item in candidate_records).items())),
    }
    if not candidate_records:
        issues.append(E2PhaseAuditIssue(f"{RAW_SUBDIR}:template_candidate", "missing E2 template_candidate raw records"))
        return {}

    for item in candidate_records:
        record = item.record
        grid_point = _record_grid_point(item)
        template_id = _record_template_id(item)
        status = str(record.get("status", ""))
        eligibility = _truth(_get(record, "template_oracle.eligible_for_template_oracle", False))
        execution_ms = _maybe_float(_get(record, "timing_ms.execution"))
        if record.get("experiment") != EXPECTED_EXPERIMENT:
            issues.append(E2PhaseAuditIssue(str(item.path), "E2 raw candidate has wrong experiment"))
        if record.get("stage") != EXPECTED_STAGE:
            issues.append(E2PhaseAuditIssue(str(item.path), "E2 raw candidate has wrong stage"))
        if record.get("manifest_id") not in EXPECTED_MANIFEST_IDS:
            issues.append(E2PhaseAuditIssue(str(item.path), "E2 raw candidate has wrong manifest_id"))
        if expected_manifest_hash and record.get("manifest_hash") != expected_manifest_hash:
            issues.append(E2PhaseAuditIssue(str(item.path), "E2 raw candidate manifest_hash differs from manifest file"))
        if str(_get(record, "query.query_id")) != EXPECTED_QUERY_ID:
            issues.append(E2PhaseAuditIssue(str(item.path), "E2 raw candidate has wrong query_id"))
        if str(_get(record, "policy.policy_id")) != EXPECTED_POLICY_ID:
            issues.append(E2PhaseAuditIssue(str(item.path), "E2 raw candidate has wrong policy_id"))
        dataset = (
            str(_get(record, "dataset.name")),
            str(_get(record, "dataset.scale")),
            str(_get(record, "dataset.seed")),
        )
        if dataset != EXPECTED_DATASET:
            issues.append(E2PhaseAuditIssue(str(item.path), f"E2 raw candidate dataset {dataset} differs from frozen dataset"))
        if expected_grid_points and grid_point not in expected_grid_points:
            issues.append(E2PhaseAuditIssue(str(item.path), f"unexpected E2 grid point {grid_point!r}"))
        if template_id not in expected_templates:
            issues.append(E2PhaseAuditIssue(str(item.path), f"unexpected E2 template candidate {template_id!r}"))
        if status == "pass":
            if not eligibility:
                issues.append(E2PhaseAuditIssue(str(item.path), "pass template candidate is not template-oracle eligible"))
            if execution_ms is None or execution_ms <= 0:
                issues.append(E2PhaseAuditIssue(str(item.path), "pass template candidate lacks positive measured execution time"))
        elif status in GOOD_REJECT_STATUSES:
            if eligibility:
                issues.append(E2PhaseAuditIssue(str(item.path), "rejected template candidate is marked template-oracle eligible"))
            reason = str(_get(record, "template_applicability.reason", "") or _get(record, "failure.reason", ""))
            if not reason:
                issues.append(E2PhaseAuditIssue(str(item.path), "rejected template candidate lacks structured exclusion reason"))
        else:
            issues.append(E2PhaseAuditIssue(str(item.path), f"unexpected template-candidate status {status!r}"))
        if _truth(_get(record, "oracle_check.known_invalid_accepted", False)):
            issues.append(E2PhaseAuditIssue(str(item.path), "template candidate accepted a known-invalid result"))
        if str(_get(record, "oracle_check.status", "match")) not in {"", "match"}:
            issues.append(E2PhaseAuditIssue(str(item.path), "template candidate oracle check is not match"))

    protocols: dict[str, Any] = {}
    by_cell_template: dict[tuple[str, str], list[_RawRecord]] = defaultdict(list)
    for item in candidate_records:
        by_cell_template[(_record_grid_point(item), _record_template_id(item))].append(item)
    for grid_point in sorted(expected_grid_points):
        for template_id in sorted(expected_templates):
            items = by_cell_template.get((grid_point, template_id), [])
            if not items:
                issues.append(E2PhaseAuditIssue(f"{RAW_SUBDIR}:{grid_point}:{template_id}", "missing measured-candidate cell"))
                continue
            protocols[f"{grid_point}:{template_id}"] = _validate_protocol(
                items,
                path_label=f"{RAW_SUBDIR}:{grid_point}:{template_id}",
                expected_warmup=expected_warmup,
                expected_measured=expected_measured,
                issues=issues,
            )
    details["raw_candidate_protocol_checked_cells"] = len(protocols)
    eligible_denominators: dict[str, int] = {}
    for grid_point in expected_grid_points:
        eligible_denominators[grid_point] = len(
            {
                _record_template_id(item)
                for item in measured_candidates
                if _record_grid_point(item) == grid_point
                and str(item.record.get("status", "")) == "pass"
                and _truth(
                    _get(
                        item.record,
                        "template_oracle.eligible_for_template_oracle",
                        False,
                    )
                )
            }
        )
    details["raw_eligible_template_denominators"] = dict(
        sorted(eligible_denominators.items())
    )
    return eligible_denominators


def _validate_summary(
    summary_dir: Path | None,
    *,
    expected_grid_points: set[str],
    expected_templates: set[str],
    expected_warmup: int,
    expected_measured: int,
    eligible_denominators: Mapping[str, int],
    min_winning_families: int,
    required_winning_families: set[str],
    issues: list[E2PhaseAuditIssue],
    details: dict[str, Any],
) -> set[str]:
    if summary_dir is None:
        details["summary_validation"] = "skipped"
        return set()
    summary_path = summary_dir / SUMMARY_SUBDIR / "summary.json"
    analysis_path = summary_dir / SUMMARY_SUBDIR / "template_oracle_analysis.csv"
    observed_winning_families: set[str] = set()
    summary_oracle: Mapping[str, Any] = {}
    if not summary_path.exists():
        issues.append(E2PhaseAuditIssue(str(summary_path), "missing E2 protocol summary.json"))
    else:
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            issues.append(E2PhaseAuditIssue(str(summary_path), f"invalid summary JSON: {exc}"))
            summary = {}
        if isinstance(summary, Mapping):
            protocol = summary.get("measurement_protocol", {})
            oracle = summary.get("template_oracle_analysis", {})
            if isinstance(oracle, Mapping):
                summary_oracle = oracle
            details["summary"] = {
                "record_count": summary.get("record_count"),
                "run_kind_counts": summary.get("run_kind_counts"),
                "mode_counts": summary.get("mode_counts"),
                "measurement_protocol": protocol,
                "template_oracle_analysis": oracle,
            }
            run_kind_counts = summary.get("run_kind_counts", {})
            if isinstance(run_kind_counts, Mapping):
                expected_candidate_records = (
                    len(expected_grid_points)
                    * len(expected_templates)
                    * (expected_warmup + expected_measured)
                )
                expected_summary_records = len(expected_grid_points) * (expected_warmup + expected_measured)
                if _maybe_int(run_kind_counts.get("template_candidate")) != expected_candidate_records:
                    issues.append(E2PhaseAuditIssue(str(summary_path), "E2 template_candidate count does not match grid x template x repetitions"))
                if _maybe_int(run_kind_counts.get("template_oracle_summary")) != expected_summary_records:
                    issues.append(E2PhaseAuditIssue(str(summary_path), "E2 template_oracle_summary count does not match grid x repetitions"))
            if isinstance(protocol, Mapping):
                if protocol.get("status") != "ok":
                    issues.append(E2PhaseAuditIssue(str(summary_path), "E2 measurement protocol status is not ok"))
                if (_maybe_int(protocol.get("cell_count")) or 0) < len(expected_grid_points):
                    issues.append(E2PhaseAuditIssue(str(summary_path), "E2 measurement cell_count is smaller than the frozen grid"))
                if _maybe_int(protocol.get("cells_meeting_required_repetitions")) != _maybe_int(protocol.get("cell_count")):
                    issues.append(E2PhaseAuditIssue(str(summary_path), "not all E2 cells meet required repetitions"))
                if _maybe_int(protocol.get("required_warmup_repetitions")) != expected_warmup:
                    issues.append(E2PhaseAuditIssue(str(summary_path), "E2 summary has wrong warmup requirement"))
                if _maybe_int(protocol.get("required_measured_repetitions")) != expected_measured:
                    issues.append(E2PhaseAuditIssue(str(summary_path), "E2 summary has wrong measured requirement"))
            if isinstance(oracle, Mapping):
                if _maybe_int(oracle.get("oracle_cell_count")) != len(expected_grid_points):
                    issues.append(E2PhaseAuditIssue(str(summary_path), "E2 oracle_cell_count does not match frozen grid count"))
                if _maybe_int(oracle.get("oracle_observation_count")) != len(expected_grid_points) * expected_measured:
                    issues.append(E2PhaseAuditIssue(str(summary_path), "E2 oracle observation count does not match grid x measured repetitions"))

    if not analysis_path.exists():
        issues.append(E2PhaseAuditIssue(str(analysis_path), "missing E2 template_oracle_analysis.csv"))
        return observed_winning_families

    rows = _read_csv(analysis_path)
    details["template_oracle_analysis_csv"] = {
        "row_count": len(rows),
        "grid_point_counts": dict(sorted(Counter(row.get("param_grid_point", "") for row in rows).items())),
    }
    if len(rows) != len(expected_grid_points) * expected_measured:
        issues.append(E2PhaseAuditIssue(str(analysis_path), "E2 template_oracle_analysis row count does not match grid x measured repetitions"))
    by_grid: dict[str, list[dict[str, str]]] = defaultdict(list)
    best_templates_by_grid: defaultdict[str, set[str]] = defaultdict(set)
    observed_gaps: list[float] = []
    observed_hits = 0
    for row in rows:
        grid_point = str(row.get("param_grid_point", ""))
        by_grid[grid_point].append(row)
        best_template = str(row.get("best_template_id", ""))
        chosen_template = str(row.get("chosen_template_id", ""))
        best_templates_by_grid[grid_point].add(best_template)
        observed_winning_families.add(_template_family(best_template))
        if grid_point not in expected_grid_points:
            issues.append(E2PhaseAuditIssue(str(analysis_path), f"unexpected oracle-analysis grid point {grid_point!r}"))
        if best_template not in expected_templates:
            issues.append(E2PhaseAuditIssue(str(analysis_path), f"unexpected best template {best_template!r}"))
        if chosen_template not in expected_templates:
            issues.append(E2PhaseAuditIssue(str(analysis_path), f"unexpected chosen template {chosen_template!r}"))
        best_ms = _maybe_float(row.get("best_execution_ms"))
        chosen_ms = _maybe_float(row.get("chosen_execution_ms"))
        gap = _maybe_float(row.get("oracle_gap"))
        if best_ms is None or best_ms <= 0:
            issues.append(E2PhaseAuditIssue(str(analysis_path), f"{grid_point} lacks positive measured best execution time"))
        if chosen_ms is None or chosen_ms <= 0:
            issues.append(E2PhaseAuditIssue(str(analysis_path), f"{grid_point} lacks positive chosen execution time"))
        if gap is None or gap < 1.0:
            issues.append(E2PhaseAuditIssue(str(analysis_path), f"{grid_point} lacks a valid oracle regret ratio"))
        elif best_ms is not None and best_ms > 0 and chosen_ms is not None:
            expected_gap = chosen_ms / best_ms
            if not math.isclose(gap, expected_gap, rel_tol=1e-9, abs_tol=1e-9):
                issues.append(E2PhaseAuditIssue(str(analysis_path), f"{grid_point} oracle_gap does not match chosen/best timing"))
            observed_gaps.append(gap)
        declared_hit = _maybe_bool(row.get("chosen_is_measured_best"))
        expected_hit = gap is not None and math.isclose(gap, 1.0, rel_tol=1e-9, abs_tol=1e-9)
        if declared_hit is None or declared_hit != expected_hit:
            issues.append(E2PhaseAuditIssue(str(analysis_path), f"{grid_point} chosen_is_measured_best disagrees with measured timing"))
        elif declared_hit:
            observed_hits += 1
        eligible = _maybe_float(row.get("eligible_templates"))
        expected_eligible = eligible_denominators.get(grid_point)
        if (
            eligible is None
            or not eligible.is_integer()
            or expected_eligible is None
            or int(eligible) != expected_eligible
        ):
            issues.append(E2PhaseAuditIssue(str(analysis_path), f"{grid_point} eligible template denominator is incomplete or inconsistent"))

    missing_grids = sorted(expected_grid_points - set(by_grid))
    extra_grids = sorted(set(by_grid) - expected_grid_points)
    if missing_grids:
        issues.append(E2PhaseAuditIssue(str(analysis_path), f"missing oracle-analysis grid points: {', '.join(missing_grids)}"))
    if extra_grids:
        issues.append(E2PhaseAuditIssue(str(analysis_path), f"extra oracle-analysis grid points: {', '.join(extra_grids)}"))
    for grid_point, grid_rows in sorted(by_grid.items()):
        if grid_point in expected_grid_points and len(grid_rows) != expected_measured:
            issues.append(E2PhaseAuditIssue(str(analysis_path), f"{grid_point} has {len(grid_rows)} oracle observations, expected {expected_measured}"))

    observation_count = len(rows)
    expected_rate = observed_hits / observation_count if observation_count else 0.0
    aggregate_checks = {
        "observation_chosen_is_measured_best_count": float(observed_hits),
        "observation_chosen_is_measured_best_rate": expected_rate,
        "observation_median_oracle_gap": _median(observed_gaps) if observed_gaps else None,
        "observation_p90_oracle_gap": _percentile(observed_gaps, 0.9) if observed_gaps else None,
        "observation_max_oracle_gap": max(observed_gaps) if observed_gaps else None,
    }
    for field, expected in aggregate_checks.items():
        actual = _maybe_float(summary_oracle.get(field))
        if expected is None or actual is None or not math.isclose(
            actual,
            expected,
            rel_tol=1e-9,
            abs_tol=1e-9,
        ):
            issues.append(E2PhaseAuditIssue(str(summary_path), f"E2 oracle summary {field} does not match the complete observation denominator"))
    details["oracle_outcome"] = {
        "observation_count": observation_count,
        "measured_best_hit_count": observed_hits,
        "measured_best_hit_rate": expected_rate,
        "median_regret": _median(observed_gaps) if observed_gaps else None,
        "p90_regret": _percentile(observed_gaps, 0.9) if observed_gaps else None,
        "max_regret": max(observed_gaps) if observed_gaps else None,
    }
    details["oracle_best_templates_by_grid"] = {
        grid_point: sorted(template_ids)
        for grid_point, template_ids in sorted(best_templates_by_grid.items())
    }

    observed_winning_families.discard("unknown")
    details["winning_family_counts"] = dict(
        sorted(
            Counter(
                _template_family(str(row.get("best_template_id", "")))
                for row in rows
                if _template_family(str(row.get("best_template_id", ""))) != "unknown"
            ).items()
        )
    )
    details["winning_family_expectation_report"] = {
        "observed": sorted(observed_winning_families),
        "requested_minimum": min_winning_families,
        "requested_families": sorted(required_winning_families),
        "missing_requested_families": sorted(
            required_winning_families - observed_winning_families
        ),
        "enforced": False,
    }
    return observed_winning_families


def _families_from_observed_template_ids(value: str) -> set[str]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        parsed = []
    if not isinstance(parsed, list):
        return set()
    return {_template_family(str(item)) for item in parsed if _template_family(str(item)) != "unknown"}


def _list_cell(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if value in (None, ""):
        return []
    text = str(value).strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, list):
        return [str(item) for item in parsed if str(item)]
    for delimiter in ("|", ","):
        if delimiter in text:
            return [part.strip() for part in text.split(delimiter) if part.strip()]
    return [text]


def _templates_from_observed_template_ids(value: str) -> list[str]:
    return [
        template_id
        for template_id in _list_cell(value)
        if template_id in TEMPLATE_FAMILIES
    ]


def _validate_fig3_witness_audit(
    figure_dir: Path,
    *,
    summary_rows: Sequence[dict[str, str]],
    source_path: Path,
    issues: list[E2PhaseAuditIssue],
    details: dict[str, Any],
) -> None:
    witness_path = figure_dir / FIG3_DIR / FIG3_WITNESS_SOURCE
    if not witness_path.exists():
        issues.append(E2PhaseAuditIssue(str(witness_path), "missing Fig3 E2 witness audit CSV"))
        return

    rows = _read_csv(witness_path)
    region_rows = [row for row in rows if row.get("row_type") == "region_winner"]
    coverage_rows = [row for row in rows if row.get("row_type") == "witness_coverage"]
    details["fig3_witness_audit"] = {
        "source": str(witness_path),
        "row_count": len(rows),
        "region_row_count": len(region_rows),
        "coverage_row_count": len(coverage_rows),
        "covered_witnesses": sorted({row.get("theory_witness", "") for row in coverage_rows}),
    }
    if not rows:
        issues.append(E2PhaseAuditIssue(str(witness_path), "Fig3 witness audit CSV is empty"))
        return

    required_columns = {
        "row_type",
        "consistency_status",
        "evidence_anchor",
        "theory_witnesses",
        "theory_witness",
        "param_grid_point",
        "observed_template_id",
        "observed_family",
    }
    missing_columns = sorted(required_columns - set(rows[0]))
    if missing_columns:
        issues.append(E2PhaseAuditIssue(str(witness_path), f"Fig3 witness audit lacks columns: {', '.join(missing_columns)}"))

    expected_region_keys: set[tuple[str, str, str]] = set()
    expected_grid_params: dict[str, dict[str, str]] = {}
    ignored_region_templates: list[tuple[str, str, str]] = []
    for row in summary_rows:
        grid_point = str(row.get("param_grid_point", ""))
        expected_grid_params[grid_point] = {
            "param_s_q": str(row.get("param_s_q", "")),
            "param_s_auth": str(row.get("param_s_auth", "")),
            "artifact_availability": str(row.get("artifact_availability", "")),
        }
        for template_id in _templates_from_observed_template_ids(str(row.get("observed_template_ids", ""))):
            family = _template_family(template_id)
            if family not in FIG3_FAMILY_WITNESS_DIRECTIONS:
                ignored_region_templates.append((grid_point, template_id, family))
                continue
            expected_region_keys.add((grid_point, template_id, family))
    if ignored_region_templates:
        details["fig3_witness_audit"]["ignored_undeclared_region_templates"] = ignored_region_templates

    observed_region_keys = {
        (
            str(row.get("param_grid_point", "")),
            str(row.get("observed_template_id", "")),
            str(row.get("observed_family", "")),
        )
        for row in region_rows
    }
    missing_region_keys = sorted(expected_region_keys - observed_region_keys)
    extra_region_keys = sorted(observed_region_keys - expected_region_keys)
    if missing_region_keys:
        issues.append(E2PhaseAuditIssue(str(witness_path), f"Fig3 witness audit missing region winners: {missing_region_keys}"))
    if extra_region_keys:
        issues.append(E2PhaseAuditIssue(str(witness_path), f"Fig3 witness audit has extra region winners: {extra_region_keys}"))

    witness_to_region_keys: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
    for row in region_rows:
        grid_point = str(row.get("param_grid_point", ""))
        template_id = str(row.get("observed_template_id", ""))
        family = str(row.get("observed_family", ""))
        key = (grid_point, template_id, family)
        expected_family = _template_family(template_id)
        spec = FIG3_FAMILY_WITNESS_DIRECTIONS.get(family)
        if row.get("consistency_status") != "consistent":
            issues.append(E2PhaseAuditIssue(str(witness_path), f"{grid_point}/{template_id} witness status is not consistent"))
        if not row.get("evidence_anchor") or not row.get("direction"):
            issues.append(E2PhaseAuditIssue(str(witness_path), f"{grid_point}/{template_id} lacks witness direction or evidence anchor"))
        if expected_family != family:
            issues.append(E2PhaseAuditIssue(str(witness_path), f"{template_id} is labeled as family {family}, expected {expected_family}"))
        if spec is None:
            issues.append(E2PhaseAuditIssue(str(witness_path), f"{family} has no declared T5 witness direction"))
            continue
        witnesses = set(_list_cell(row.get("theory_witnesses", "")))
        expected_witnesses = set(spec["theory_witnesses"])
        if witnesses != expected_witnesses:
            issues.append(
                E2PhaseAuditIssue(
                    str(witness_path),
                    f"{grid_point}/{template_id} carries witnesses {sorted(witnesses)}, expected {sorted(expected_witnesses)}",
                )
            )
        if row.get("witness_role") != spec["witness_role"]:
            issues.append(E2PhaseAuditIssue(str(witness_path), f"{grid_point}/{template_id} witness_role changed"))
        expected_params = expected_grid_params.get(grid_point, {})
        for field in ("param_s_q", "param_s_auth", "artifact_availability"):
            if expected_params and str(row.get(field, "")) != expected_params.get(field, ""):
                issues.append(E2PhaseAuditIssue(str(witness_path), f"{grid_point}/{template_id} {field} differs from Fig3 source"))
        for witness in witnesses:
            witness_to_region_keys[witness].add(key)

    coverage_by_witness: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in coverage_rows:
        coverage_by_witness[str(row.get("theory_witness", ""))].append(row)

    coverage_summaries: dict[str, Any] = {}
    for theory_witness, spec in T5_WITNESS_COVERAGE.items():
        group = coverage_by_witness.get(theory_witness, [])
        if len(group) != 1:
            issues.append(E2PhaseAuditIssue(str(witness_path), f"Fig3 witness audit must have exactly one {theory_witness} coverage row"))
            continue
        row = group[0]
        for field, expected in spec.items():
            if row.get(field) != expected:
                issues.append(E2PhaseAuditIssue(str(witness_path), f"{theory_witness} {field} changed"))
        matching_grids = set(_list_cell(row.get("e2_matching_grid_points", "")))
        matching_families = set(_list_cell(row.get("e2_matching_families", "")))
        actual_keys = witness_to_region_keys.get(theory_witness, set())
        actual_grids = {key[0] for key in actual_keys}
        actual_families = {key[2] for key in actual_keys}
        if matching_grids != actual_grids:
            issues.append(E2PhaseAuditIssue(str(witness_path), f"{theory_witness} coverage grids differ from region rows"))
        if matching_families != actual_families:
            issues.append(E2PhaseAuditIssue(str(witness_path), f"{theory_witness} coverage families differ from region rows"))
        coverage_summaries[theory_witness] = {
            "fixed_mode_under_test": row.get("fixed_mode_under_test", ""),
            "expected_best_direction": row.get("expected_best_direction", ""),
            "e5_witness_id": row.get("e5_witness_id", ""),
            "e2_matching_families": sorted(actual_families),
            "e2_matching_grid_count": len(actual_grids),
            "reported_status": row.get("consistency_status", ""),
            "coverage_enforced": False,
        }

    extra_coverage = sorted(set(coverage_by_witness) - set(T5_WITNESS_COVERAGE))
    if extra_coverage:
        issues.append(E2PhaseAuditIssue(str(witness_path), f"Fig3 witness audit has extra coverage witnesses: {', '.join(extra_coverage)}"))
    details["fig3_witness_coverage"] = coverage_summaries


def _validate_fig3_source(
    figure_dir: Path | None,
    *,
    expected_grid_points: set[str],
    expected_manifest_hash: str | None,
    min_winning_families: int,
    required_winning_families: set[str],
    issues: list[E2PhaseAuditIssue],
    details: dict[str, Any],
) -> None:
    if figure_dir is None:
        details["figure_validation"] = "skipped"
        return
    source_path = figure_dir / FIG3_DIR / FIG3_SOURCE
    config_path = figure_dir / FIG3_DIR / f"{FIG3_DIR}_config.json"
    if not source_path.exists():
        issues.append(E2PhaseAuditIssue(str(source_path), "missing Fig3 E2 phase source CSV"))
        return
    rows = _read_csv(source_path)
    summary_rows = [row for row in rows if row.get("run_kind") == "template_oracle_summary"]
    normal_rows = [row for row in rows if row.get("run_kind") == "normal_mode"]
    template_candidate_rows = [row for row in rows if row.get("run_kind") == "template_candidate"]
    details["fig3_source"] = {
        "row_count": len(rows),
        "summary_row_count": len(summary_rows),
        "normal_row_count": len(normal_rows),
        "template_candidate_row_count": len(template_candidate_rows),
        "grid_points": sorted({row.get("param_grid_point", "") for row in rows if row.get("param_grid_point")}),
    }
    if not rows:
        issues.append(E2PhaseAuditIssue(str(source_path), "Fig3 E2 phase source CSV is empty"))
        return
    missing_columns = [
        column
        for column in (
            "param_grid_point",
            "param_s_q",
            "param_s_auth",
            "param_policy_cost",
            "artifact_availability",
            "oracle_gap_median",
            "oracle_best_execution_ms_median",
            "oracle_chosen_execution_ms_median",
        )
        if column not in rows[0]
    ]
    if missing_columns:
        issues.append(E2PhaseAuditIssue(str(source_path), f"Fig3 source lacks phase/oracle columns: {', '.join(missing_columns)}"))
    source_grids = {row.get("param_grid_point", "") for row in rows if row.get("param_grid_point")}
    if expected_grid_points and source_grids != expected_grid_points:
        issues.append(E2PhaseAuditIssue(str(source_path), "Fig3 source grid points differ from frozen manifest grid"))
    if len(summary_rows) != len(expected_grid_points):
        issues.append(E2PhaseAuditIssue(str(source_path), "Fig3 source does not have one template_oracle_summary row per grid point"))

    fig_winning_families: set[str] = set()
    expected_best_by_grid = details.get("oracle_best_templates_by_grid", {})
    for row in summary_rows:
        grid_point = str(row.get("param_grid_point", ""))
        observed_templates = set(
            _templates_from_observed_template_ids(
                str(row.get("observed_template_ids", ""))
            )
        )
        fig_winning_families.update(
            _families_from_observed_template_ids(
                str(row.get("observed_template_ids", ""))
            )
        )
        if grid_point not in expected_grid_points:
            issues.append(E2PhaseAuditIssue(str(source_path), f"unexpected Fig3 summary grid point {grid_point!r}"))
        expected_best = set(expected_best_by_grid.get(grid_point, []))
        region_templates = observed_templates - {"guard_candidate_plus_residual_v1"}
        if expected_best and region_templates != expected_best:
            issues.append(E2PhaseAuditIssue(str(source_path), f"{grid_point} Fig3 top-level winners differ from measured best templates"))
        gap = _maybe_float(row.get("oracle_gap_median"))
        if gap is None or gap < 1.0:
            issues.append(E2PhaseAuditIssue(str(source_path), f"{grid_point} Fig3 summary lacks a valid regret ratio"))
        if _maybe_float(row.get("oracle_best_execution_ms_median")) is None or _maybe_float(row.get("oracle_best_execution_ms_median")) <= 0:
            issues.append(E2PhaseAuditIssue(str(source_path), f"{grid_point} Fig3 source lacks positive oracle best runtime"))
        if _maybe_float(row.get("oracle_chosen_execution_ms_median")) is None or _maybe_float(row.get("oracle_chosen_execution_ms_median")) <= 0:
            issues.append(E2PhaseAuditIssue(str(source_path), f"{grid_point} Fig3 source lacks positive chosen runtime"))

    details["fig3_winning_families"] = sorted(fig_winning_families)
    details["fig3_winning_family_expectation_report"] = {
        "observed": sorted(fig_winning_families),
        "requested_minimum": min_winning_families,
        "requested_families": sorted(required_winning_families),
        "missing_requested_families": sorted(
            required_winning_families - fig_winning_families
        ),
        "enforced": False,
    }

    _validate_fig3_witness_audit(
        figure_dir,
        summary_rows=summary_rows,
        source_path=source_path,
        issues=issues,
        details=details,
    )

    if not config_path.exists():
        issues.append(E2PhaseAuditIssue(str(config_path), "missing Fig3 config JSON"))
    else:
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            issues.append(E2PhaseAuditIssue(str(config_path), f"invalid Fig3 config JSON: {exc}"))
            config = {}
        if isinstance(config, Mapping):
            details["fig3_config"] = {
                "source_file": config.get("source_file"),
                "uses_protocol_cell_stats": config.get("uses_protocol_cell_stats"),
                "manifest_hashes": config.get("manifest_hashes"),
                "record_count": config.get("record_count"),
                "companion_sources": config.get("companion_sources"),
                "witness_audit_csv": config.get("witness_audit_csv"),
            }
            if config.get("source_file") != "cell_stats.csv":
                issues.append(E2PhaseAuditIssue(str(config_path), "Fig3 source_file is not cell_stats.csv"))
            if config.get("uses_protocol_cell_stats") is not True:
                issues.append(E2PhaseAuditIssue(str(config_path), "Fig3 does not declare protocol cell_stats source"))
            companion_sources = config.get("companion_sources")
            witness_audit_csv = str(config.get("witness_audit_csv", ""))
            companion_names = [str(item) for item in companion_sources] if isinstance(companion_sources, list) else []
            if not witness_audit_csv.endswith(FIG3_WITNESS_SOURCE):
                issues.append(E2PhaseAuditIssue(str(config_path), "Fig3 config does not declare witness_audit_csv"))
            if not any(item.endswith(FIG3_WITNESS_SOURCE) for item in companion_names):
                issues.append(E2PhaseAuditIssue(str(config_path), "Fig3 config companion_sources lacks witness audit CSV"))
            manifest_hashes = config.get("manifest_hashes")
            if expected_manifest_hash and (
                not isinstance(manifest_hashes, list) or expected_manifest_hash not in manifest_hashes
            ):
                issues.append(E2PhaseAuditIssue(str(config_path), "Fig3 config lacks frozen E2 manifest hash"))


def validate_e2_phase_diagram(
    raw_dir: Path,
    summary_dir: Path | None = None,
    figure_dir: Path | None = None,
    manifest_path: Path | None = None,
    *,
    expected_warmup: int = 5,
    expected_measured: int = 10,
    min_winning_families: int = DEFAULT_MIN_WINNING_FAMILIES,
    required_winning_families: Sequence[str] | str | None = None,
) -> E2PhaseAuditReport:
    issues: list[E2PhaseAuditIssue] = []
    details: dict[str, Any] = {
        "expected_protocol": {"warmup": expected_warmup, "measured": expected_measured},
        "min_winning_families": min_winning_families,
    }
    required_families = _parse_required_families(required_winning_families)
    details["required_winning_families"] = sorted(required_families)

    (
        _manifest,
        expected_grid_points,
        expected_templates,
        expected_manifest_hash,
        manifest_warmup,
        manifest_measured,
    ) = _load_manifest(manifest_path, issues, details)
    if manifest_warmup and manifest_warmup != expected_warmup:
        issues.append(E2PhaseAuditIssue(str(manifest_path), "manifest warmup repetitions differ from validator expectation"))
    if manifest_measured and manifest_measured != expected_measured:
        issues.append(E2PhaseAuditIssue(str(manifest_path), "manifest measured repetitions differ from validator expectation"))

    records = _load_raw_records(raw_dir, issues)
    details["raw_record_count"] = len(records)
    eligible_denominators = _validate_raw_candidate_pool(
        records,
        expected_grid_points=expected_grid_points,
        expected_templates=expected_templates,
        expected_manifest_hash=expected_manifest_hash,
        expected_warmup=expected_warmup,
        expected_measured=expected_measured,
        issues=issues,
        details=details,
    )
    summary_families = _validate_summary(
        summary_dir,
        expected_grid_points=expected_grid_points,
        expected_templates=expected_templates,
        expected_warmup=expected_warmup,
        expected_measured=expected_measured,
        eligible_denominators=eligible_denominators,
        min_winning_families=min_winning_families,
        required_winning_families=required_families,
        issues=issues,
        details=details,
    )
    details["summary_winning_families"] = sorted(summary_families)
    _validate_fig3_source(
        figure_dir,
        expected_grid_points=expected_grid_points,
        expected_manifest_hash=expected_manifest_hash,
        min_winning_families=min_winning_families,
        required_winning_families=required_families,
        issues=issues,
        details=details,
    )

    return E2PhaseAuditReport(issues=tuple(issues), details=details)
