"""Validation for the E10 representation-diversity case-study evidence."""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
    normalize_mode_id,
)

import csv
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

TAB2_DIR = "tab2_e10_diversity"
TAB2_SOURCE = "tab2_e10_diversity_source.csv"
RAW_SUBDIR = "SIGMOD_CURRENT_E10"
SUMMARY_SUBDIR = "SIGMOD_CURRENT_E10"

DIAGNOSTIC_UNSAFE_PUSHDOWN = "unsafe-pushdown-positive-control"
E10_BARRIER_QUERY_ID = "E10_Q4_shared_document_search_audit"
BAD_CONTRACT_STATUSES = {"wrong_result", "unsafe_observation"}
REQUIRED_NON_MAV_FAMILIES = {"auth-index", "barrier", "guard", "hybrid", "safe-injection"}
MAV_ALLOWED_BEST_CASES = {"E10_Q2_tenant_dashboard", "E10_Q7_ordered_export"}
EXPECTED_CASE_COUNT = 11
DEFAULT_NEAR_MISS_GAP_MAX = 1.10
DEFAULT_NEAR_MISS_ABS_MS_MAX = 0.050

MAIN_ARCHETYPES = {
    "HYB": ("E10_Q1_support_ticket_lookup", "hybrid"),
    "GUARD": ("E10_Q5_invoice_region_purpose_join", "guard"),
    "INJ": ("E10_Q11_ticket_exact_injection", "safe-injection"),
    "BARRIER": ("E10_Q4_shared_document_search_audit", "barrier"),
    "AUTHIDX": ("E10_Q3_cross_tenant_admin_audit", "auth-index"),
}

CONTROL_CASES = {
    "E10_Q2_tenant_dashboard",
    "E10_Q6_own_plus_group_shared_union",
    "E10_Q7_ordered_export",
    "E10_Q8_stale_dashboard_mav",
    "E10_Q9_wrong_context_mav",
    "E10_Q10_revoked_membership_mav",
}

MAV_REJECTION_CONTROLS = {
    "E10_Q8_stale_dashboard_mav": "stale",
    "E10_Q9_wrong_context_mav": "wrong_context",
    "E10_Q10_revoked_membership_mav": "stale",
}

PAPER_WATERFALL_LABEL = r"\label{tab:e10-candidate-waterfall}"
PAPER_WATERFALL_CASE_TOKENS = tuple(f"Q{index}" for index in range(1, 12))
PAPER_WATERFALL_REASON_TOKENS = (
    "incomplete guard",
    "unsafe exact policy",
    "unavailable",
    "stale",
    "wrong-context",
    "unsafe/nontransparent boundary",
)


@dataclass(frozen=True)
class E10DiversityAuditIssue:
    path: str
    message: str


@dataclass(frozen=True)
class E10DiversityAuditReport:
    issues: tuple[E10DiversityAuditIssue, ...]
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


def _query_id(item: _RawRecord) -> str:
    return str(_get(item.record, "query.query_id"))


def _mode(item: _RawRecord) -> str:
    return normalize_mode_id(str(item.record.get("mode", "")))


def _status(item: _RawRecord) -> str:
    return str(item.record.get("status", ""))


def _unauthorized_observations(item: _RawRecord) -> int:
    return int(_maybe_int(_get(item.record, "runtime_audit.unauthorized_observations", 0)) or 0)


def _context_id(item: _RawRecord) -> str:
    return str(_get(item.record, "context.context_id", ""))


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _is_sidecar_path(path: Path) -> bool:
    return path.name.startswith(".") or "explain" in path.parts


def _load_raw_records(
    raw_dir: Path,
    issues: list[E10DiversityAuditIssue],
    *,
    raw_subdir: str = RAW_SUBDIR,
) -> list[_RawRecord]:
    e10_dir = raw_dir / raw_subdir
    if not e10_dir.exists():
        issues.append(E10DiversityAuditIssue(str(e10_dir), "missing E10 protocol raw directory"))
        return []
    records: list[_RawRecord] = []
    for path in sorted(item for item in e10_dir.rglob("*.json") if not _is_sidecar_path(item)):
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            issues.append(E10DiversityAuditIssue(str(path), f"invalid JSON: {exc}"))
            continue
        if not isinstance(parsed, Mapping):
            issues.append(E10DiversityAuditIssue(str(path), "raw result must be a JSON object"))
            continue
        records.append(_RawRecord(path=path, record=parsed))
    if not records:
        issues.append(E10DiversityAuditIssue(str(e10_dir), "E10 protocol raw directory has no JSON records"))
    return records


def _validate_summary(
    summary_dir: Path | None,
    issues: list[E10DiversityAuditIssue],
    details: dict[str, Any],
    *,
    summary_subdir: str = SUMMARY_SUBDIR,
    expected_oracle_cell_count: int | None = EXPECTED_CASE_COUNT,
) -> None:
    if summary_dir is None:
        details["summary_validation"] = "skipped"
        return
    summary_path = summary_dir / summary_subdir / "summary.json"
    if not summary_path.exists():
        issues.append(E10DiversityAuditIssue(str(summary_path), "missing E10 protocol summary.json"))
        return
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        issues.append(E10DiversityAuditIssue(str(summary_path), f"invalid summary JSON: {exc}"))
        return
    if not isinstance(summary, Mapping):
        issues.append(E10DiversityAuditIssue(str(summary_path), "summary must be a JSON object"))
        return
    protocol = summary.get("measurement_protocol", {})
    oracle = summary.get("template_oracle_analysis", {})
    details["summary"] = {
        "record_count": summary.get("record_count"),
        "measurement_protocol": protocol,
        "oracle_cell_count": oracle.get("oracle_cell_count") if isinstance(oracle, Mapping) else None,
        "median_oracle_gap": oracle.get("median_oracle_gap") if isinstance(oracle, Mapping) else None,
        "p90_oracle_gap": oracle.get("p90_oracle_gap") if isinstance(oracle, Mapping) else None,
        "max_oracle_gap": oracle.get("max_oracle_gap") if isinstance(oracle, Mapping) else None,
    }
    if isinstance(protocol, Mapping):
        if protocol.get("status") != "ok":
            issues.append(E10DiversityAuditIssue(str(summary_path), "E10 measurement protocol status is not ok"))
        if _maybe_int(protocol.get("cells_meeting_required_repetitions")) != _maybe_int(protocol.get("cell_count")):
            issues.append(E10DiversityAuditIssue(str(summary_path), "not all E10 cells meet required repetitions"))
    if isinstance(oracle, Mapping) and expected_oracle_cell_count is not None:
        observed_oracle_cell_count = _maybe_int(oracle.get("oracle_cell_count"))
        if observed_oracle_cell_count != expected_oracle_cell_count:
            issues.append(
                E10DiversityAuditIssue(
                    str(summary_path),
                    "E10 oracle_cell_count "
                    f"{observed_oracle_cell_count} does not match expected "
                    f"{expected_oracle_cell_count} query-context cell(s)",
                )
            )


def _validate_protocol(
    items: Sequence[_RawRecord],
    *,
    path_label: str,
    expected_warmup: int,
    expected_measured: int,
    issues: list[E10DiversityAuditIssue],
) -> dict[str, Any]:
    phase_iterations: dict[str, list[int]] = defaultdict(list)
    for item in items:
        phase = str(_get(item.record, "measurement.phase", ""))
        iteration = _maybe_int(_get(item.record, "measurement.iteration", None))
        warmup = _maybe_int(_get(item.record, "measurement.warmup_repetitions", None))
        measured = _maybe_int(_get(item.record, "measurement.measured_repetitions", None))
        if phase not in {"warmup", "measured"} or iteration is None:
            issues.append(E10DiversityAuditIssue(str(item.path), f"{path_label} lacks measurement phase/iteration"))
            continue
        if warmup != expected_warmup or measured != expected_measured:
            issues.append(
                E10DiversityAuditIssue(
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
                E10DiversityAuditIssue(
                    path_label,
                    f"{phase} repetitions {unique} with count {len(iterations)} "
                    f"do not match expected 1..{expected_count}",
                )
            )
        if len(iterations) != len(unique):
            issues.append(E10DiversityAuditIssue(path_label, f"{phase} repetitions contain duplicate iterations"))
    return observed


def _validate_admission_first_raw(
    records: Sequence[_RawRecord],
    *,
    expected_warmup: int,
    expected_measured: int,
    issues: list[E10DiversityAuditIssue],
    details: dict[str, Any],
) -> None:
    expected_queries = {case_id for case_id, _family in MAIN_ARCHETYPES.values()} | CONTROL_CASES
    contract_records = [item for item in records if _mode(item) == ADMISSION_FIRST_MODE and _query_id(item) in expected_queries]
    by_query: dict[str, list[_RawRecord]] = defaultdict(list)
    for item in contract_records:
        by_query[_query_id(item)].append(item)
        if _status(item) in BAD_CONTRACT_STATUSES:
            issues.append(E10DiversityAuditIssue(str(item.path), f"AdmissionFirst produced {_status(item)}"))
        if _unauthorized_observations(item) != 0:
            issues.append(E10DiversityAuditIssue(str(item.path), "AdmissionFirst recorded unauthorized observations"))
        if _get(item.record, "oracle_check.known_invalid_accepted", False) is True:
            issues.append(E10DiversityAuditIssue(str(item.path), "AdmissionFirst accepted a known-invalid candidate"))
    details["admission_first_status_counts"] = dict(sorted(Counter(_status(item) for item in contract_records).items()))
    details["admission_first_query_count"] = len(by_query)

    for query_id in sorted(expected_queries):
        items = by_query.get(query_id, [])
        if not items:
            issues.append(E10DiversityAuditIssue(f"E10:{query_id}:{ADMISSION_FIRST_MODE}", "missing AdmissionFirst records"))
            continue
        by_context: dict[str, list[_RawRecord]] = defaultdict(list)
        for item in items:
            by_context[_context_id(item) or "unknown"].append(item)
        protocol_by_context: dict[str, Any] = {}
        for context_id, context_items in sorted(by_context.items()):
            protocol_by_context[context_id] = _validate_protocol(
                context_items,
                path_label=f"E10:{query_id}:{ADMISSION_FIRST_MODE}:{context_id}",
                expected_warmup=expected_warmup,
                expected_measured=expected_measured,
                issues=issues,
            )
        details.setdefault("admission_first_protocol", {})[query_id] = protocol_by_context


def _validate_barrier_positive_control(
    records: Sequence[_RawRecord],
    *,
    expected_warmup: int,
    expected_measured: int,
    issues: list[E10DiversityAuditIssue],
    details: dict[str, Any],
) -> None:
    items = [
        item
        for item in records
        if _query_id(item) == E10_BARRIER_QUERY_ID
        and _mode(item) == DIAGNOSTIC_UNSAFE_PUSHDOWN
    ]
    details["barrier_positive_control"] = {
        "query_id": E10_BARRIER_QUERY_ID,
        "mode": DIAGNOSTIC_UNSAFE_PUSHDOWN,
        "record_count": len(items),
        "status_counts": dict(sorted(Counter(_status(item) for item in items).items())),
        "unauthorized_observations_total": sum(_unauthorized_observations(item) for item in items),
    }
    if not items:
        issues.append(
            E10DiversityAuditIssue(
                f"E10:{E10_BARRIER_QUERY_ID}:{DIAGNOSTIC_UNSAFE_PUSHDOWN}",
                "missing E10-BARRIER unsafe-pushdown positive-control records",
            )
        )
        return
    by_context: dict[str, list[_RawRecord]] = defaultdict(list)
    for item in items:
        by_context[_context_id(item) or "unknown"].append(item)
    details["barrier_positive_control"]["protocol_by_context"] = {
        context_id: _validate_protocol(
            context_items,
            path_label=f"E10:{E10_BARRIER_QUERY_ID}:{DIAGNOSTIC_UNSAFE_PUSHDOWN}:{context_id}",
            expected_warmup=expected_warmup,
            expected_measured=expected_measured,
            issues=issues,
        )
        for context_id, context_items in sorted(by_context.items())
    }
    bad_status = [item for item in items if _status(item) != "unsafe_observation"]
    if bad_status:
        issues.append(
            E10DiversityAuditIssue(
                f"E10:{E10_BARRIER_QUERY_ID}:{DIAGNOSTIC_UNSAFE_PUSHDOWN}",
                f"positive control has {len(bad_status)} record(s) without unsafe_observation status",
            )
        )
    missing_observation = [item for item in items if _unauthorized_observations(item) <= 0]
    if missing_observation:
        issues.append(
            E10DiversityAuditIssue(
                f"E10:{E10_BARRIER_QUERY_ID}:{DIAGNOSTIC_UNSAFE_PUSHDOWN}",
                f"positive control has {len(missing_observation)} record(s) without unauthorized observations",
            )
        )
    eligible = [
        item
        for item in items
        if _get(item.record, "template_oracle.eligible_for_template_oracle", False) is True
    ]
    if eligible:
        issues.append(
            E10DiversityAuditIssue(
                f"E10:{E10_BARRIER_QUERY_ID}:{DIAGNOSTIC_UNSAFE_PUSHDOWN}",
                "positive control must be excluded from the measured template-oracle pool",
            )
        )


def _validate_dataset_context(
    records: Sequence[_RawRecord],
    *,
    expected_dataset_scale: str | None,
    expected_dataset_seed: int | None,
    min_contexts_per_case: int | None,
    issues: list[E10DiversityAuditIssue],
    details: dict[str, Any],
) -> None:
    dataset_counts: Counter[str] = Counter()
    scale_counts: Counter[str] = Counter()
    seed_counts: Counter[str] = Counter()
    context_by_case: defaultdict[str, set[str]] = defaultdict(set)
    expected_queries = {case_id for case_id, _family in MAIN_ARCHETYPES.values()} | CONTROL_CASES
    for item in records:
        dataset_name = str(_get(item.record, "dataset.name", ""))
        dataset_scale = str(_get(item.record, "dataset.scale", ""))
        dataset_seed = str(_get(item.record, "dataset.seed", ""))
        if dataset_name or dataset_scale or dataset_seed:
            dataset_counts[f"{dataset_name}:{dataset_scale}:seed{dataset_seed}"] += 1
        scale_counts[dataset_scale] += 1
        seed_counts[dataset_seed] += 1
        query_id = _query_id(item)
        context_id = str(_get(item.record, "context.context_id", ""))
        if query_id in expected_queries and context_id:
            context_by_case[query_id].add(context_id)

    context_counts = {query_id: len(context_by_case.get(query_id, set())) for query_id in sorted(expected_queries)}
    details["raw_dataset_counts"] = dict(sorted(dataset_counts.items()))
    details["raw_dataset_scale_counts"] = dict(sorted(scale_counts.items()))
    details["raw_dataset_seed_counts"] = dict(sorted(seed_counts.items()))
    details["context_counts_by_case"] = context_counts

    if expected_dataset_scale is not None and (
        set(scale_counts) != {expected_dataset_scale}
    ):
        issues.append(
            E10DiversityAuditIssue(
                "E10:dataset",
                f"dataset.scale distribution {dict(sorted(scale_counts.items()))} "
                f"does not match expected {expected_dataset_scale!r}",
            )
        )
    if expected_dataset_seed is not None and set(seed_counts) != {str(expected_dataset_seed)}:
        issues.append(
            E10DiversityAuditIssue(
                "E10:dataset",
                f"dataset.seed distribution {dict(sorted(seed_counts.items()))} "
                f"does not match expected {expected_dataset_seed}",
            )
        )

    if min_contexts_per_case is not None:
        for query_id, count in context_counts.items():
            if count < min_contexts_per_case:
                issues.append(
                    E10DiversityAuditIssue(
                        f"E10:{query_id}",
                        f"context count {count} below required {min_contexts_per_case}",
                    )
                )


def _parse_source(
    figure_dir: Path,
    issues: list[E10DiversityAuditIssue],
    *,
    figure_subdir: str = TAB2_DIR,
    figure_source: str | None = None,
) -> tuple[Path, list[dict[str, str]]]:
    source_name = figure_source or f"{figure_subdir}_source.csv"
    source_path = figure_dir / figure_subdir / source_name
    if not source_path.exists():
        issues.append(E10DiversityAuditIssue(str(source_path), "missing E10 diversity source CSV"))
        return source_path, []
    return source_path, _read_csv(source_path)


def _family_counts(rows: Iterable[Mapping[str, str]], field: str) -> dict[str, int]:
    return dict(sorted(Counter(str(row.get(field, "")) for row in rows if row.get(field)).items()))


def _is_near_miss_witness(
    row: Mapping[str, str],
    *,
    near_miss_gap_max: float,
    near_miss_abs_ms_max: float,
) -> bool:
    gap = _maybe_float(row.get("oracle_gap_median"))
    if gap is not None and gap <= near_miss_gap_max:
        return True
    measured_best = _maybe_float(row.get("measured_best_ms_median"))
    contract_chosen = _maybe_float(row.get("contract_chosen_ms_median"))
    if measured_best is None or contract_chosen is None:
        return False
    return abs(contract_chosen - measured_best) <= near_miss_abs_ms_max


def _non_mav_witness_families(
    case_rows: Sequence[Mapping[str, str]],
    *,
    near_miss_gap_max: float,
    near_miss_abs_ms_max: float,
) -> set[str]:
    families: set[str] = set()
    for row in case_rows:
        measured_family = str(row.get("measured_best_family", ""))
        if measured_family and measured_family != "mav":
            families.add(measured_family)
        contract_family = str(row.get("contract_chosen_family", ""))
        if (
            contract_family
            and contract_family != "mav"
            and _is_near_miss_witness(
                row,
                near_miss_gap_max=near_miss_gap_max,
                near_miss_abs_ms_max=near_miss_abs_ms_max,
            )
        ):
            families.add(contract_family)
    return families


def _accepted_candidate_witness_families(rows: Sequence[Mapping[str, str]]) -> dict[str, set[str]]:
    by_case: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        if row.get("row_type") != "candidate_waterfall":
            continue
        if "accepted" not in str(row.get("candidate_role", "")):
            continue
        family = str(row.get("template_family", ""))
        if family and family != "mav":
            by_case[str(row.get("query_id", ""))].add(family)
    return by_case


def _validate_case_summaries(
    source_path: Path,
    rows: Sequence[dict[str, str]],
    *,
    near_miss_gap_max: float,
    near_miss_abs_ms_max: float,
    issues: list[E10DiversityAuditIssue],
    details: dict[str, Any],
) -> None:
    case_rows = [row for row in rows if row.get("row_type") == "case_summary"]
    by_case = {str(row.get("query_id", "")): row for row in case_rows}
    details["case_count"] = len(case_rows)
    details["measured_best_family_counts"] = _family_counts(case_rows, "measured_best_family")
    details["contract_chosen_family_counts"] = _family_counts(case_rows, "contract_chosen_family")
    details["dataset_scale_counts"] = _family_counts(case_rows, "dataset_scale")
    accepted_families_by_case = _accepted_candidate_witness_families(rows)

    if len(case_rows) != EXPECTED_CASE_COUNT:
        issues.append(E10DiversityAuditIssue(str(source_path), f"E10 diversity source has {len(case_rows)} case summaries, expected {EXPECTED_CASE_COUNT}"))

    expected_cases = {case_id for case_id, _family in MAIN_ARCHETYPES.values()} | CONTROL_CASES
    missing_cases = sorted(expected_cases - set(by_case))
    extra_cases = sorted(set(by_case) - expected_cases)
    if missing_cases:
        issues.append(E10DiversityAuditIssue(str(source_path), f"missing E10 case summary rows: {', '.join(missing_cases)}"))
    if extra_cases:
        issues.append(E10DiversityAuditIssue(str(source_path), f"unexpected E10 case summary rows: {', '.join(extra_cases)}"))

    observed_non_mav = _non_mav_witness_families(
        case_rows,
        near_miss_gap_max=near_miss_gap_max,
        near_miss_abs_ms_max=near_miss_abs_ms_max,
    )
    accepted_non_mav = set().union(*accepted_families_by_case.values()) if accepted_families_by_case else set()
    observed_non_mav |= accepted_non_mav
    details["non_mav_witness_families"] = sorted(observed_non_mav)
    details["accepted_candidate_witness_families"] = {
        query_id: sorted(families)
        for query_id, families in sorted(accepted_families_by_case.items())
    }
    missing_families = sorted(REQUIRED_NON_MAV_FAMILIES - observed_non_mav)
    if missing_families:
        issues.append(E10DiversityAuditIssue(str(source_path), f"missing non-MAV witness family/families: {', '.join(missing_families)}"))

    mav_best_cases = {str(row.get("query_id", "")) for row in case_rows if row.get("measured_best_family") == "mav"}
    disallowed_mav = sorted(mav_best_cases - MAV_ALLOWED_BEST_CASES)
    if disallowed_mav:
        issues.append(E10DiversityAuditIssue(str(source_path), f"MAV measured-best appears outside allowed controls: {', '.join(disallowed_mav)}"))
    details["mav_measured_best_cases"] = sorted(mav_best_cases)

    archetype_details: dict[str, Any] = {}
    for archetype, (query_id, expected_family) in MAIN_ARCHETYPES.items():
        row = by_case.get(query_id)
        if row is None:
            continue
        chosen_family = str(row.get("contract_chosen_family", ""))
        measured_family = str(row.get("measured_best_family", ""))
        gap = _maybe_float(row.get("oracle_gap_median"))
        measured_best = _maybe_float(row.get("measured_best_ms_median"))
        contract_chosen = _maybe_float(row.get("contract_chosen_ms_median"))
        archetype_details[archetype] = {
            "query_id": query_id,
            "expected_witness_family": expected_family,
            "contract_chosen_family": chosen_family,
            "measured_best_family": measured_family,
            "accepted_candidate_families": sorted(accepted_families_by_case.get(query_id, set())),
            "oracle_gap_median": gap,
            "contract_chosen_minus_measured_best_ms": (
                None if measured_best is None or contract_chosen is None else contract_chosen - measured_best
            ),
        }
        if expected_family not in accepted_families_by_case.get(query_id, set()):
            issues.append(
                E10DiversityAuditIssue(
                    str(source_path),
                    f"{archetype} lacks accepted candidate witness family {expected_family!r}",
                )
            )
        if measured_family == "mav":
            issues.append(E10DiversityAuditIssue(str(source_path), f"{archetype} measured-best is MAV, not a non-MAV diversity witness"))
        if measured_family != expected_family and not _is_near_miss_witness(
            row,
            near_miss_gap_max=near_miss_gap_max,
            near_miss_abs_ms_max=near_miss_abs_ms_max,
        ):
            issues.append(
                E10DiversityAuditIssue(
                    str(source_path),
                    f"{archetype} measured-best crossover gap {gap} exceeds near-miss bound "
                    f"{near_miss_gap_max} and absolute delta bound {near_miss_abs_ms_max} ms",
                )
            )
    details["main_archetypes"] = archetype_details

    for row in case_rows:
        accepted = _maybe_int(row.get("accepted_template_count"))
        rejected = _maybe_int(row.get("rejected_template_count"))
        if accepted is None or accepted <= 0:
            issues.append(E10DiversityAuditIssue(str(source_path), f"{row.get('query_id')} has no accepted template count"))
        if rejected is None or rejected <= 0:
            issues.append(E10DiversityAuditIssue(str(source_path), f"{row.get('query_id')} has no rejected template count"))
        if _maybe_int(row.get("unauthorized_observations")) not in (0, None):
            issues.append(E10DiversityAuditIssue(str(source_path), f"{row.get('query_id')} reports unauthorized observations"))


def _validate_waterfall(
    source_path: Path,
    rows: Sequence[dict[str, str]],
    *,
    expected_measured: int,
    context_counts_by_case: Mapping[str, int],
    issues: list[E10DiversityAuditIssue],
    details: dict[str, Any],
) -> None:
    waterfall = [row for row in rows if row.get("row_type") == "candidate_waterfall"]
    by_case: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in waterfall:
        by_case[str(row.get("query_id", ""))].append(row)

    rejected_reason_counts: Counter[str] = Counter()
    for query_id, group in sorted(by_case.items()):
        expected_sample_count = expected_measured * max(1, int(context_counts_by_case.get(query_id, 1)))
        accepted = [row for row in group if "accepted" in str(row.get("candidate_role", ""))]
        rejected = [row for row in group if row.get("candidate_role") == "rejected"]
        if not accepted:
            issues.append(E10DiversityAuditIssue(str(source_path), f"{query_id} has no accepted candidate-waterfall rows"))
        if not rejected:
            issues.append(E10DiversityAuditIssue(str(source_path), f"{query_id} has no rejected candidate-waterfall rows"))
        for row in accepted:
            sample_count = _maybe_int(row.get("sample_count"))
            if sample_count != expected_sample_count:
                issues.append(
                    E10DiversityAuditIssue(
                        str(source_path),
                        f"{query_id}/{row.get('template_id')} accepted sample_count "
                        f"{sample_count} != {expected_sample_count}",
                    )
                )
        for row in rejected:
            status = str(row.get("template_applicability_status", ""))
            reason = str(row.get("template_applicability_reason", ""))
            sample_count = _maybe_int(row.get("sample_count"))
            if sample_count != expected_sample_count:
                issues.append(
                    E10DiversityAuditIssue(
                        str(source_path),
                        f"{query_id}/{row.get('template_id')} rejected sample_count "
                        f"{sample_count} != {expected_sample_count}",
                    )
                )
            if not status or status == "applicable":
                issues.append(E10DiversityAuditIssue(str(source_path), f"{query_id}/{row.get('template_id')} rejected row lacks structured status"))
            if not reason or not reason.startswith(f"{status}:"):
                issues.append(E10DiversityAuditIssue(str(source_path), f"{query_id}/{row.get('template_id')} rejected row lacks status-prefixed reason"))
            if reason:
                rejected_reason_counts[reason] += 1

    for query_id, expected_reason_fragment in MAV_REJECTION_CONTROLS.items():
        mav_rows = [
            row
            for row in by_case.get(query_id, [])
            if row.get("template_id") == "mav_scan_v1" and row.get("candidate_role") == "rejected"
        ]
        if not mav_rows:
            issues.append(E10DiversityAuditIssue(str(source_path), f"{query_id} lacks rejected stale/wrong-context MAV candidate"))
            continue
        reason = str(mav_rows[0].get("template_applicability_reason", ""))
        if "metadata_invalid:mav" not in reason or expected_reason_fragment not in reason:
            issues.append(E10DiversityAuditIssue(str(source_path), f"{query_id} MAV rejection reason {reason!r} lacks {expected_reason_fragment!r}"))

    q4_guard_rows = [
        row
        for row in by_case.get("E10_Q4_shared_document_search_audit", [])
        if row.get("template_id") == "guard_candidate_plus_residual_v1" and row.get("candidate_role") == "rejected"
    ]
    if not q4_guard_rows:
        issues.append(E10DiversityAuditIssue(str(source_path), "E10_Q4 lacks rejected guard residual candidate"))
    elif "residual_crosses_unsafe_boundary" not in str(q4_guard_rows[0].get("template_applicability_reason", "")):
        issues.append(E10DiversityAuditIssue(str(source_path), "E10_Q4 guard rejection lacks unsafe-boundary reason"))

    details["waterfall"] = {
        "row_count": len(waterfall),
        "case_count": len(by_case),
        "rejected_reason_top": dict(rejected_reason_counts.most_common(10)),
    }


def _paper_table_block(text: str, label: str) -> str | None:
    label_index = text.find(label)
    if label_index < 0:
        return None
    begin_index = text.rfind(r"\begin{table", 0, label_index)
    end_index = text.find(r"\end{table", label_index)
    if begin_index < 0 or end_index < 0:
        return None
    end_line = text.find("\n", end_index)
    if end_line < 0:
        end_line = len(text)
    return text[begin_index:end_line]


def _validate_paper_waterfall(
    paper_path: Path,
    issues: list[E10DiversityAuditIssue],
    details: dict[str, Any],
) -> None:
    if not paper_path.exists():
        issues.append(E10DiversityAuditIssue(str(paper_path), "paper file does not exist"))
        return
    text = paper_path.read_text(encoding="utf-8")
    block = _paper_table_block(text, PAPER_WATERFALL_LABEL)
    if block is None:
        issues.append(
            E10DiversityAuditIssue(
                str(paper_path),
                "missing visible E10 candidate-cost waterfall table "
                f"{PAPER_WATERFALL_LABEL}",
            )
        )
        return
    missing_cases = [token for token in PAPER_WATERFALL_CASE_TOKENS if token not in block]
    missing_reasons = [token for token in PAPER_WATERFALL_REASON_TOKENS if token not in block]
    if missing_cases:
        issues.append(
            E10DiversityAuditIssue(
                str(paper_path),
                "E10 waterfall table is missing case token(s): "
                + ", ".join(missing_cases),
            )
        )
    if missing_reasons:
        issues.append(
            E10DiversityAuditIssue(
                str(paper_path),
                "E10 waterfall table is missing rejection reason token(s): "
                + ", ".join(missing_reasons),
            )
        )
    details["paper_waterfall"] = {
        "label": "tab:e10-candidate-waterfall",
        "case_tokens": len(PAPER_WATERFALL_CASE_TOKENS) - len(missing_cases),
        "reason_tokens": len(PAPER_WATERFALL_REASON_TOKENS) - len(missing_reasons),
    }


def validate_e10_diversity(
    raw_dir: Path,
    summary_dir: Path | None = None,
    figure_dir: Path | None = None,
    paper_path: Path | None = None,
    *,
    raw_subdir: str = RAW_SUBDIR,
    summary_subdir: str = SUMMARY_SUBDIR,
    figure_subdir: str = TAB2_DIR,
    figure_source: str | None = None,
    expected_warmup: int = 5,
    expected_measured: int = 10,
    near_miss_gap_max: float = DEFAULT_NEAR_MISS_GAP_MAX,
    near_miss_abs_ms_max: float = DEFAULT_NEAR_MISS_ABS_MS_MAX,
    expected_dataset_scale: str | None = None,
    expected_dataset_seed: int | None = None,
    min_contexts_per_case: int | None = None,
) -> E10DiversityAuditReport:
    issues: list[E10DiversityAuditIssue] = []
    details: dict[str, Any] = {
        "expected_protocol": {"warmup": expected_warmup, "measured": expected_measured},
        "near_miss_gap_max": near_miss_gap_max,
        "near_miss_abs_ms_max": near_miss_abs_ms_max,
        "raw_subdir": raw_subdir,
        "summary_subdir": summary_subdir,
        "figure_subdir": figure_subdir,
        "figure_source": figure_source or f"{figure_subdir}_source.csv",
    }

    records = _load_raw_records(raw_dir, issues, raw_subdir=raw_subdir)
    details["raw_record_count"] = len(records)
    _validate_dataset_context(
        records,
        expected_dataset_scale=expected_dataset_scale,
        expected_dataset_seed=expected_dataset_seed,
        min_contexts_per_case=min_contexts_per_case,
        issues=issues,
        details=details,
    )
    context_counts_by_case = details.get("context_counts_by_case", {})
    expected_oracle_cell_count = (
        sum(int(value) for value in context_counts_by_case.values())
        if context_counts_by_case
        else EXPECTED_CASE_COUNT
    )
    _validate_summary(
        summary_dir,
        issues,
        details,
        summary_subdir=summary_subdir,
        expected_oracle_cell_count=expected_oracle_cell_count,
    )
    _validate_admission_first_raw(
        records,
        expected_warmup=expected_warmup,
        expected_measured=expected_measured,
        issues=issues,
        details=details,
    )
    _validate_barrier_positive_control(
        records,
        expected_warmup=expected_warmup,
        expected_measured=expected_measured,
        issues=issues,
        details=details,
    )

    if figure_dir is None:
        details["figure_validation"] = "skipped"
    else:
        source_path, rows = _parse_source(
            figure_dir,
            issues,
            figure_subdir=figure_subdir,
            figure_source=figure_source,
        )
        if rows:
            _validate_case_summaries(
                source_path,
                rows,
                near_miss_gap_max=near_miss_gap_max,
                near_miss_abs_ms_max=near_miss_abs_ms_max,
                issues=issues,
                details=details,
            )
            _validate_waterfall(
                source_path,
                rows,
                expected_measured=expected_measured,
                context_counts_by_case=details.get("context_counts_by_case", {}),
                issues=issues,
                details=details,
            )

    if paper_path is None:
        details["paper_waterfall_validation"] = "skipped"
    else:
        _validate_paper_waterfall(paper_path, issues, details)

    return E10DiversityAuditReport(issues=tuple(issues), details=details)
