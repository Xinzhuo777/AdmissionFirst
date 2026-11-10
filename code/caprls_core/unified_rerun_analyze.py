"""Independent, read-only reduction of a unified query/choice campaign.

The reducer never connects to PostgreSQL and never pools observations merely
because two modes share SQL.  Primary query latency and reuse use the same
mode-local wall-clock samples.  Actual no-cache request latency is a distinct
outer wall-clock observation, not the sum of separately aggregated medians.

The canonical record has campaign_id, family, case_id, mode, phase, iteration,
status, query_wall_ms, executed_sql_hash and (for AF) choice_total_wall_ms,
request_wall_ms, selected_candidate_id, costed_sql_hash, admitted_sql_hash,
state_id. Candidate execution diagnostics may be separate record_kind=candidate
records with admitted, selected and pg_execution_ms. Missing diagnostics never
silently become measurements. JSON reports are created exclusively, not replaced.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


AF = "admission-first"
NATIVE = "native-pg-rls"
SUCCESS = frozenset(("pass", "success", "ok"))
INAPPLICABLE = frozenset(("rejected", "not_applicable", "not-applicable", "na"))
SCHEMA = "caprls-unified-rerun-analysis-v1"


def _mode(value: Any) -> str:
    return AF if str(value) in ("contract-aware", "af", "AF") else str(value)


def percentile(values: Sequence[float], q: float) -> float | None:
    """Linearly interpolated quantile, including endpoints."""
    if not values:
        return None
    ordered = sorted(values)
    index = (len(ordered) - 1) * q
    lo, hi = math.floor(index), math.ceil(index)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (index - lo)


def ratio_statistics(ratios: Sequence[float], *, higher_is_better: bool = True) -> dict[str, Any]:
    """Case-level ratios; the tie band is descriptive and fixed at 1%."""
    if any(not math.isfinite(x) or x <= 0 for x in ratios):
        raise ValueError("ratios must be finite and positive")
    return {
        "cases": len(ratios),
        "median": statistics.median(ratios) if ratios else None,
        "geometric_mean": math.exp(statistics.mean(math.log(x) for x in ratios))
        if ratios else None,
        "p90": percentile(ratios, 0.90),
        "wins": sum((x > 1.01 if higher_is_better else x < 0.99) for x in ratios),
        "ties": sum(0.99 <= x <= 1.01 for x in ratios),
        "losses": sum((x < 0.99 if higher_is_better else x > 1.01) for x in ratios),
        "tie_band": [0.99, 1.01],
        "higher_is_better": higher_is_better,
    }


def _number(row: Mapping[str, Any], field: str, *, positive: bool = False) -> float:
    number = float(row[field])
    if not math.isfinite(number) or number < 0 or (positive and number == 0):
        raise ValueError(f"invalid {field}: {row[field]!r}")
    return number


def _identity(row: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return tuple(str(row.get(key) or "") for key in
                 ("campaign_id", "family", "case_id", "state_id"))  # type: ignore[return-value]


def _median_field(rows: Sequence[Mapping[str, Any]], field: str) -> float | None:
    if not rows or any(field not in row or row[field] in (None, "") for row in rows):
        return None
    try:
        return statistics.median(_number(row, field) for row in rows)
    except (TypeError, ValueError):
        return None


def summarize_records(
    records: Iterable[Mapping[str, Any]],
    *,
    expected_cases: Mapping[str, Sequence[str]] | None = None,
    expected_modes: Mapping[str, Sequence[str]] | None = None,
    fastest_modes: Mapping[str, Sequence[str]] | None = None,
    measured_count: int = 10,
    warmup_count: int = 5,
    require_identity: bool = True,
    require_choice: bool = True,
) -> dict[str, Any]:
    """Reduce records and expose incomplete/failed cases, including partial runs.

    expected_cases and expected_modes must come from the predeclared campaign,
    not from whichever records happened to complete. Without them a partial
    report can be inspected but is explicitly not publication-ready.
    """
    if measured_count < 1 or warmup_count < 0:
        raise ValueError("invalid repetition counts")
    source = [dict(row) for row in records]
    blockers: list[str] = []
    warnings: list[str] = []
    groups: dict[tuple[str, str], dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    candidate_rows: dict[tuple[str, str, int], list[dict[str, Any]]] = defaultdict(list)
    campaigns: set[str] = set()
    observed_cases: dict[str, set[str]] = defaultdict(set)
    failure_counts: dict[str, int] = defaultdict(int)
    availability: dict[tuple[str, str], dict[str, str]] = defaultdict(dict)
    candidate_inventories: dict[tuple[str, str], set[str]] = {}
    for index, row in enumerate(source):
        kind = str(row.get("record_kind", "query"))
        if kind not in ("query", "normal_mode", "request", "candidate", "candidate_diagnostic"):
            if kind == "failure":
                status = str(row.get("status", "failed"))
                failure_counts[status] += 1
                blockers.append(f"{row.get('family')}/{row.get('case_id')}: {row.get('error', status)}")
            elif kind == "case_preflight":
                key = (str(row.get("family", "")), str(row.get("case_id", "")))
                for unavailable in row.get("unavailable_modes", []):
                    availability[key][_mode(unavailable.get("mode", ""))] = str(unavailable.get("reason") or "preflight unavailable")
                if "admitted_candidate_ids" in row:
                    candidate_inventories[key] = set(map(str, row["admitted_candidate_ids"]))
            continue
        if "event" in row and "record_kind" not in row:
            continue  # Environment/restoration metadata is not a query sample.
        campaign, family, case, _ = _identity(row)
        if not all((campaign, family, case)):
            blockers.append(f"record {index}: missing campaign/family/case identity")
            continue
        campaigns.add(campaign)
        observed_cases[family].add(case)
        try:
            iteration = int(row["iteration"])
        except (KeyError, TypeError, ValueError):
            blockers.append(f"record {index}: missing or invalid iteration")
            continue
        if kind in ("candidate", "candidate_diagnostic"):
            if row.get("phase") == "measured":
                candidate_rows[(family, case, iteration)].append(row)
            continue
        if kind not in ("query", "normal_mode", "request"):
            warnings.append(f"record {index}: ignored non-query record kind {kind}")
            continue
        mode = _mode(row.get("mode", ""))
        if not mode:
            blockers.append(f"record {index}: missing mode")
            continue
        phase = str(row.get("phase", ""))
        if phase not in ("warmup", "measured"):
            blockers.append(f"record {index}: unknown phase {phase!r}")
            continue
        status = str(row.get("status", "")).lower()
        if status not in SUCCESS | INAPPLICABLE:
            failure_counts[status or "missing_status"] += 1
            blockers.append(f"{family}/{case}/{mode}/{phase}/{iteration}: {status or 'missing status'}")
        row["mode"] = mode
        row["iteration"] = iteration
        row["status"] = status
        groups[(family, case)][mode].append(row)
    if len(campaigns) != 1:
        blockers.append(f"expected one campaign; observed {sorted(campaigns)}")
    if expected_cases is None or expected_modes is None:
        warnings.append("No predeclared full case/mode inventory: partial audit only")
    if expected_cases is not None:
        for family in sorted(set(observed_cases) | set(expected_cases)):
            expected = set(map(str, expected_cases.get(family, ())))
            observed = observed_cases.get(family, set())
            missing, unexpected = sorted(expected - observed), sorted(observed - expected)
            if missing or unexpected:
                blockers.append(f"{family}: missing cases={missing}, unexpected cases={unexpected}")

    case_reports: list[dict[str, Any]] = []
    for (family, case), by_mode in sorted(groups.items()):
        start_blockers = len(blockers)
        declared_modes = set(map(_mode, expected_modes.get(family, ()))) if expected_modes else set(by_mode)
        unavailable_modes = availability.get((family, case), {})
        for mode in sorted(declared_modes - set(by_mode) - set(unavailable_modes)):
            blockers.append(f"{family}/{case}: missing mode {mode}")
        mode_reports: dict[str, dict[str, Any]] = {}
        for mode in sorted(declared_modes & set(unavailable_modes) - set(by_mode)):
            mode_reports[mode] = {"status": "not_applicable", "measured_samples": 0,
                                  "reason": unavailable_modes[mode], "source": "case_preflight"}
        measured_by_mode: dict[str, list[dict[str, Any]]] = {}
        measured_states: set[str] = set()
        measured_iteration_sets: set[tuple[int, ...]] = set()
        for mode, rows in sorted(by_mode.items()):
            mode_blockers = len(blockers)
            for phase, expected_count in (("warmup", warmup_count), ("measured", measured_count)):
                phase_rows = [row for row in rows if row["phase"] == phase]
                iterations = [row["iteration"] for row in phase_rows]
                # Iterations can be zero- or one-based; the declaration is count
                # plus contiguity, not a silently imposed legacy numbering scheme.
                if len(iterations) != expected_count or len(set(iterations)) != expected_count:
                    blockers.append(f"{family}/{case}/{mode}: {phase} count {len(iterations)}; expected {expected_count}, no duplicates")
                elif iterations and max(iterations) - min(iterations) + 1 != expected_count:
                    blockers.append(f"{family}/{case}/{mode}: non-contiguous {phase} iterations")
            measured = sorted((row for row in rows if row["phase"] == "measured"), key=lambda row: row["iteration"])
            measured_by_mode[mode] = measured
            measured_iteration_sets.add(tuple(row["iteration"] for row in measured))
            statuses = {row["status"] for row in measured}
            if statuses and statuses <= INAPPLICABLE:
                mode_reports[mode] = {"status": "not_applicable", "measured_samples": len(measured)}
                continue
            if not measured or statuses - SUCCESS:
                blockers.append(f"{family}/{case}/{mode}: mixed/missing execution status {sorted(statuses)}")
                mode_reports[mode] = {"status": "invalid", "measured_samples": len(measured)}
                continue
            latencies: list[float] = []
            for row in measured:
                try:
                    latencies.append(_number(row, "query_wall_ms", positive=True))
                    if "ordinary_query_executions" in row and row["ordinary_query_executions"] != 1:
                        raise ValueError("ordinary request did not execute exactly one query")
                    if "diagnostic_query_executions" in row and row["diagnostic_query_executions"] != 0:
                        raise ValueError("diagnostic execution inside primary request interval")
                    sql_hash = str(row.get("executed_sql_hash") or "")
                    if not sql_hash:
                        raise ValueError("missing executed_sql_hash")
                    state = str(row.get("state_id") or "")
                    if not state:
                        raise ValueError("missing state_id")
                    measured_states.add(state)
                    if mode == AF and require_identity:
                        for field in ("costed_sql_hash", "admitted_sql_hash"):
                            if row.get(field) != sql_hash:
                                raise ValueError(f"{field} != executed_sql_hash")
                    if mode == AF and require_choice:
                        _number(row, "choice_total_wall_ms")
                        outer = _number(row, "request_wall_ms", positive=True)
                        if outer + 1e-6 < _number(row, "query_wall_ms"):
                            raise ValueError("request wall shorter than query wall")
                        if not row.get("selected_candidate_id"):
                            raise ValueError("missing selected_candidate_id")
                    if mode == NATIVE and require_choice:
                        _number(row, "request_wall_ms", positive=True)
                except (KeyError, TypeError, ValueError) as exc:
                    blockers.append(f"{family}/{case}/{mode}/{row['iteration']}: {exc}")
            mode_reports[mode] = {
                "status": "pass" if len(blockers) == mode_blockers else "invalid",
                "measured_samples": len(measured),
                "query_wall_ms_median": statistics.median(latencies) if len(latencies) == len(measured) else None,
                "request_wall_ms_median": _median_field(measured, "request_wall_ms"),
                "choice_total_wall_ms_median": _median_field(measured, "choice_total_wall_ms"),
                "pg_execution_ms_median": _median_field(measured, "pg_execution_ms"),
            }
        if len(measured_states) != 1:
            blockers.append(f"{family}/{case}: measured modes do not share one state_id: {sorted(measured_states)}")
        if len(measured_iteration_sets) != 1:
            blockers.append(f"{family}/{case}: modes do not share measured repetition identities")
        # Any prior ingestion failure for this case must also prevent adoption.
        case_prefix = f"{family}/{case}/"
        case_valid = len(blockers) == start_blockers and not any(
            item.startswith(case_prefix) for item in blockers[:start_blockers]
        )
        result: dict[str, Any] = {
            "family": family, "case_id": case, "valid": case_valid,
            "modes": mode_reports,
            "native_over_af_query_wall": None,
            "native_over_af_request_wall": None,
            "af_over_fastest_mode_query_wall": None,
            "stable_choice": False,
            "positive_savings": None,
            "estimated_reuse_executions": None,
        }
        if AF not in mode_reports or NATIVE not in mode_reports or any(
            mode_reports[mode]["status"] != "pass" for mode in (AF, NATIVE) if mode in mode_reports
        ):
            blockers.append(f"{family}/{case}: valid AF and Native records required")
            result["valid"] = False
            case_reports.append(result)
            continue
        if not case_valid:
            case_reports.append(result)
            continue
        af, native = mode_reports[AF], mode_reports[NATIVE]
        af_query, native_query = af["query_wall_ms_median"], native["query_wall_ms_median"]
        result["native_over_af_query_wall"] = native_query / af_query
        if af["request_wall_ms_median"] is not None and native["request_wall_ms_median"] is not None:
            result["native_over_af_request_wall"] = native["request_wall_ms_median"] / af["request_wall_ms_median"]
        pool = set(map(_mode, fastest_modes.get(family, ()))) if fastest_modes else declared_modes
        possible = {mode: item["query_wall_ms_median"] for mode, item in mode_reports.items()
                    if mode in pool and item["status"] == "pass"}
        if possible:
            fastest_value = min(possible.values())
            result["af_over_fastest_mode_query_wall"] = af_query / fastest_value
            result["fastest_modes"] = sorted(mode for mode, value in possible.items() if value == fastest_value)
        choices = {(row.get("selected_candidate_id"), row.get("executed_sql_hash"), row.get("state_id"))
                   for row in measured_by_mode[AF]}
        stable = len(choices) == 1 and all(all(value for value in choice) for choice in choices)
        result["stable_choice"] = stable
        if stable and af["choice_total_wall_ms_median"] is not None:
            delta = native_query - af_query
            result["savings_per_execution_wall_ms"] = delta
            result["positive_savings"] = delta > 0
            if delta > 0:
                result["estimated_reuse_executions"] = math.ceil(af["choice_total_wall_ms_median"] / delta)
        quality = []
        wall_quality: list[float] = []
        wall_by_candidate: dict[str, list[float]] = defaultdict(list)
        observed_candidate_inventories: list[set[str]] = []
        candidate_errors: list[str] = []
        for row in measured_by_mode[AF]:
            candidates = candidate_rows.get((family, case, row["iteration"]), [])
            wall_usable = []
            for candidate in candidates:
                if candidate.get("admitted") is not True or str(candidate.get("status", "pass")).lower() not in SUCCESS:
                    continue
                candidate_id = str(candidate.get("selected_candidate_id") or candidate.get("candidate_id") or "")
                try:
                    wall = _number(candidate, "query_wall_ms", positive=True)
                    if not candidate_id or not candidate.get("executed_sql_hash"):
                        raise ValueError("missing candidate identity")
                    if require_identity and any(candidate.get(field) != candidate.get("executed_sql_hash")
                                                for field in ("costed_sql_hash", "admitted_sql_hash")):
                        raise ValueError("candidate SQL identity mismatch")
                    wall_usable.append((candidate_id, candidate, wall))
                    wall_by_candidate[candidate_id].append(wall)
                except (KeyError, TypeError, ValueError) as exc:
                    if candidate_inventories.get((family, case)):
                        candidate_errors.append(f"candidate {candidate_id}/{row['iteration']}: {exc}")
            observed_candidate_inventories.append({item[0] for item in wall_usable})
            selected_wall = [wall for candidate_id, candidate, wall in wall_usable
                             if candidate_id == row.get("selected_candidate_id")
                             and candidate.get("executed_sql_hash") == row.get("executed_sql_hash")]
            if wall_usable and len(selected_wall) == 1:
                wall_quality.append(selected_wall[0] / min(item[2] for item in wall_usable))
            admitted = [candidate for candidate in candidates
                        if candidate.get("admitted") is True
                        and str(candidate.get("status", "pass")).lower() in SUCCESS
                        and candidate.get("pg_execution_ms") not in (None, "")]
            usable = []
            for candidate in admitted:
                try:
                    usable.append((candidate, _number(candidate, "pg_execution_ms", positive=True)))
                except (KeyError, TypeError, ValueError):
                    pass  # Failed/missing diagnostics are not fastest candidates.
            chosen = [timing for candidate, timing in usable
                      if candidate.get("executed_sql_hash") == row.get("executed_sql_hash")]
            if usable and len(chosen) == 1:
                quality.append(chosen[0] / min(timing for _, timing in usable))
        declared_candidates = candidate_inventories.get((family, case))
        if declared_candidates is not None:
            for iteration, observed in zip((row["iteration"] for row in measured_by_mode[AF]), observed_candidate_inventories):
                if observed != declared_candidates:
                    candidate_errors.append(f"candidate inventory at {iteration}: expected {sorted(declared_candidates)}, observed {sorted(observed)}")
        if candidate_errors:
            blockers.extend(f"{family}/{case}: {message}" for message in candidate_errors)
            result["valid"] = False
        candidate_medians = {candidate: statistics.median(timings)
                             for candidate, timings in wall_by_candidate.items()
                             if len(timings) == measured_count}
        result["candidate_wall_quality"] = {
            "available_repetitions": len(wall_quality),
            "expected_repetitions": measured_count,
            "ratios": wall_quality,
            "median_selected_over_fastest_admitted": statistics.median(wall_quality) if wall_quality else None,
            "matches_exact": sum(value == 1.0 for value in wall_quality),
            "matches_within_one_percent": sum(value <= 1.01 for value in wall_quality),
            "candidate_query_wall_ms_medians": candidate_medians,
            "af_over_fastest_admitted_query_wall": af_query / min(candidate_medians.values()) if candidate_medians else None,
            "inventory_declared": declared_candidates is not None,
            "metric": "ordinary selected-query wall probes of admitted candidates; distinct from PG execution diagnostics",
        }
        result["candidate_execution_quality"] = {
            "available_repetitions": len(quality),
            "expected_repetitions": measured_count,
            "ratios": quality,
            "median_af_over_fastest_admitted": statistics.median(quality) if quality else None,
            "matches_within_one_percent": sum(value <= 1.01 for value in quality),
            "metric": "diagnostic PG execution time only; not primary query wall latency",
        }
        case_reports.append(result)

    families: dict[str, Any] = {}
    for family in sorted(observed_cases):
        valid = [case for case in case_reports if case["family"] == family and case["valid"]]
        stable = [case for case in valid if case["stable_choice"] and case["positive_savings"] is not None]
        positive = [case for case in stable if case["positive_savings"]]
        stable_ratios = [case["native_over_af_query_wall"] for case in stable]
        stable_stats = ratio_statistics(stable_ratios)
        if not stable_stats["wins"] <= len(positive) <= stable_stats["wins"] + stable_stats["ties"]:
            blockers.append(f"{family}: wins/positive savings invariant failed on stable-choice subset")
        choices = [case["modes"][AF]["choice_total_wall_ms_median"] for case in valid
                   if case["modes"][AF]["choice_total_wall_ms_median"] is not None]
        families[family] = {
            "observed_cases": len(observed_cases[family]),
            "valid_cases": len(valid),
            "query_wall_native_over_af": ratio_statistics([case["native_over_af_query_wall"] for case in valid]),
            "actual_request_wall_native_over_af": ratio_statistics([case["native_over_af_request_wall"] for case in valid
                                                                    if case["native_over_af_request_wall"] is not None]),
            "af_over_fastest_mode_query_wall": ratio_statistics([case["af_over_fastest_mode_query_wall"] for case in valid
                                                                if case["af_over_fastest_mode_query_wall"] is not None],
                                                                higher_is_better=False),
            "af_over_fastest_admitted_query_wall": ratio_statistics([
                case["candidate_wall_quality"]["af_over_fastest_admitted_query_wall"] for case in valid
                if case.get("candidate_wall_quality", {}).get("af_over_fastest_admitted_query_wall") is not None
            ], higher_is_better=False),
            "candidate_choice_wall_quality": {
                "case_ratios": ratio_statistics([
                    case["candidate_wall_quality"]["median_selected_over_fastest_admitted"] for case in valid
                    if case.get("candidate_wall_quality", {}).get("median_selected_over_fastest_admitted") is not None
                ], higher_is_better=False),
                "available_repetitions": sum(case.get("candidate_wall_quality", {}).get("available_repetitions", 0)
                                             for case in valid),
                "matches_exact": sum(case.get("candidate_wall_quality", {}).get("matches_exact", 0)
                                     for case in valid),
                "matches_within_one_percent": sum(case.get("candidate_wall_quality", {}).get("matches_within_one_percent", 0)
                                                  for case in valid),
            },
            "choice_total_wall_ms_median_of_case_medians": statistics.median(choices) if choices else None,
            "reuse": {
                "stable_choice_cases": len(stable),
                "choice_changed_or_unavailable_cases": len(valid) - len(stable),
                "positive_savings_cases": len(positive),
                "nonpositive_savings_cases": len(stable) - len(positive),
                "median_estimated_executions_positive_subset": statistics.median(
                    case["estimated_reuse_executions"] for case in positive
                ) if positive else None,
                "stable_choice_native_over_af": stable_stats,
                "scope": "conditional estimate for a reusable unchanged chosen SQL/state; no cache implemented",
            },
        }
    return {
        "schema": SCHEMA,
        "campaign_ids": sorted(campaigns),
        "ready": not blockers and expected_cases is not None and expected_modes is not None,
        "blockers": blockers,
        "warnings": warnings,
        "failure_counts": dict(sorted(failure_counts.items())),
        "families": families,
        "cases": case_reports,
        "metric_contract": {
            "primary": "mode-local median selected-query wall time; same samples used for savings",
            "request": "mode-local median of actual no-cache outer request wall observations",
            "reuse": "ceil(median choice_total_wall_ms / (Native median query wall - AF median query wall))",
            "cross_family_aggregation": "not performed",
            "sql_pooling": "not performed",
            "candidate_quality": "optional separately labelled PG execution diagnostics",
        },
    }


def _parse_records(data: bytes, suffix: str) -> list[dict[str, Any]]:
    text = data.decode("utf-8")
    if suffix.lower() == ".csv":
        return list(csv.DictReader(io.StringIO(text)))
    if suffix.lower() in (".jsonl", ".ndjson"):
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    document = json.loads(text)
    if isinstance(document, list):
        return document
    if isinstance(document, dict) and isinstance(document.get("records"), list):
        return document["records"]
    raise ValueError("expected a records list or JSONL")


def read_records(path: Path) -> list[dict[str, Any]]:
    return _parse_records(path.read_bytes(), path.suffix)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Canonical records JSONL/JSON/CSV")
    parser.add_argument("--declaration", type=Path, help="JSON with expected_cases, expected_modes, fastest_modes and repetition counts")
    parser.add_argument("--output", type=Path, help="New JSON report; existing paths are never overwritten")
    args = parser.parse_args(argv)
    declaration_bytes = args.declaration.read_bytes() if args.declaration else None
    declaration = json.loads(declaration_bytes) if declaration_bytes else {}
    # A live producer may append while an independent audit runs. Hash exactly
    # the single byte snapshot reduced here, never a second read of the file.
    input_bytes = args.input.read_bytes()
    report = summarize_records(_parse_records(input_bytes, args.input.suffix), **{
        key: declaration[key] for key in ("expected_cases", "expected_modes", "fastest_modes",
                                         "measured_count", "warmup_count") if key in declaration
    })
    report["input_sha256"] = hashlib.sha256(input_bytes).hexdigest()
    report["input_bytes"] = len(input_bytes)
    report["declaration_sha256"] = hashlib.sha256(declaration_bytes).hexdigest() if declaration_bytes else None
    report["analyzer_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    rendered = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(rendered)
    else:
        print(rendered, end="")
    return 0 if report["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
