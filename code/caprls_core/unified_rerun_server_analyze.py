"""Read-only V2 server-time reduction, including identical-SQL noise controls.

The primary latency is PostgreSQL planning + execution + applicable validation
time for the actual admitted SQL.  Instrumented EXPLAIN wall time is not an
ordinary request, and no ordinary-request result is synthesized here. Choice
cost remains separately measured wall time. All case medians are mode-local.
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

from caprls_core.unified_rerun_analyze import AF, NATIVE, INAPPLICABLE, SUCCESS, percentile


PD = "native-pg-rls-physical-design"
SCHEMA = "caprls-unified-rerun-server-analysis-v2"
PRACTICAL_LOG_BAND = math.log(1.05)
CONTROL_P90_LOG_LIMIT = math.log(1.10)


def number(row: Mapping[str, Any], field: str, *, positive: bool = False) -> float:
    value = float(row[field])
    if not math.isfinite(value) or value < 0 or (positive and value == 0):
        raise ValueError(f"invalid {field}: {row[field]!r}")
    return value


def server_time(row: Mapping[str, Any], *, expected_batch_count: int | None = None) -> float:
    primary = number(row, "query_server_ms", positive=True)
    total = sum(number(row, field) for field in (
        "server_planning_ms", "server_execution_ms", "validation_server_ms"))
    if not math.isclose(primary, total, rel_tol=1e-8, abs_tol=1e-6):
        raise ValueError("query_server_ms != planning + execution + validation")
    count = row.get("measurement_batch_count", 1)
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ValueError("invalid measurement_batch_count")
    if expected_batch_count is not None and count != expected_batch_count:
        raise ValueError(f"measurement_batch_count {count} != predeclared {expected_batch_count}")
    if row.get("query_executions", 1) != count:
        raise ValueError("instrumented execution count differs from declared batch count")
    if row.get("explain_analyze_query_executions", 1) != count:
        raise ValueError("EXPLAIN ANALYZE execution count differs from declared batch count")
    if row.get("ordinary_query_executions", 0) != 0:
        raise ValueError("ordinary execution mixed into instrumented sample")
    if row.get("diagnostic_query_executions", 0) != 0:
        raise ValueError("extra diagnostic execution mixed into sample")
    members = row.get("raw_server_measurements")
    if count > 1 or members is not None:
        if not isinstance(members, list) or len(members) != count:
            raise ValueError("raw batch member count differs from declared batch count")
        for member in members:
            if member.get("measurement_batch_count", 1) != 1:
                raise ValueError("a raw batch member is not one complete query execution")
            server_time(member, expected_batch_count=1)
            for field in ("executed_sql_hash", "role", "row_security", "read_only"):
                if field in row and member.get(field) != row[field]:
                    raise ValueError(f"batch member differs in {field}")
        for field in ("query_server_ms", "server_planning_ms", "server_execution_ms", "validation_server_ms"):
            if not math.isclose(number(row, field), statistics.mean(number(member, field) for member in members),
                                rel_tol=1e-8, abs_tol=1e-6):
                raise ValueError(f"{field} is not the mean of every raw batch member")
        if "validation_query_executions" in row and row["validation_query_executions"] != sum(
                member.get("validation_query_executions", 0) for member in members):
            raise ValueError("batch validation execution count does not match raw members")
    return primary


def declared_batch_count(row: Mapping[str, Any], counts: Mapping[str, int] | None) -> int:
    count = 1
    if counts is not None:
        found = False
        for key in (str(row.get("case_id", "")), f"{row.get('family')}/{row.get('case_id')}",
                    str(row.get("control_group_id", ""))):
            if key in counts:
                count = counts[key]
                found = True
                break
        if not found:
            raise ValueError(f"case {row.get('case_id')} missing from predeclared batch-count map")
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ValueError("predeclared measurement batch count must be a positive integer")
    return count


def declared_repetition_count(row: Mapping[str, Any], counts: Mapping[str, int] | None,
                              default: int) -> int:
    count = default
    if counts is not None:
        found = False
        for key in (str(row.get("case_id", "")), f"{row.get('family')}/{row.get('case_id')}",
                    str(row.get("control_group_id", ""))):
            if key in counts:
                count = counts[key]
                found = True
                break
        if not found:
            raise ValueError(f"case {row.get('case_id')} missing from predeclared repetition-count map")
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ValueError("predeclared measured repetition count must be a positive integer")
    return count


def descriptive_ratios(values: Sequence[float]) -> dict[str, Any]:
    if any(not math.isfinite(value) or value <= 0 for value in values):
        raise ValueError("ratio must be finite and positive")
    return {"cases": len(values),
            "geometric_mean": math.exp(statistics.mean(map(math.log, values))) if values else None,
            "median": statistics.median(values) if values else None,
            "p10": percentile(values, .10), "p90": percentile(values, .90),
            "scope": "descriptive case-median ratios; not a precision guarantee"}


def _phase_check(rows: Sequence[Mapping[str, Any]], warmup_count: int,
                 measured_count: int, label: str) -> list[str]:
    errors = []
    for phase, count in (("warmup", warmup_count), ("measured", measured_count)):
        members = [row for row in rows if row.get("phase") == phase]
        ids = [row.get("iteration") for row in members]
        if len(ids) != count or len(set(ids)) != count:
            errors.append(f"{label}: {phase} count {len(ids)}; expected {count}, no duplicates")
        elif any(not isinstance(value, int) for value in ids) or (
                ids and max(ids) - min(ids) + 1 != count):
            errors.append(f"{label}: non-contiguous {phase} iterations")
    if any(row.get("phase") not in ("warmup", "measured") for row in rows):
        errors.append(f"{label}: unknown phase")
    return errors


def _identity(row: Mapping[str, Any], *, af: bool = False) -> None:
    for field in ("campaign_id", "family", "case_id", "state_id", "executed_sql_hash"):
        if not row.get(field):
            raise ValueError(f"missing {field}")
    if af:
        for field in ("costed_sql_hash", "admitted_sql_hash"):
            if row.get(field) != row["executed_sql_hash"]:
                raise ValueError(f"{field} != executed_sql_hash")
        if not row.get("selected_candidate_id"):
            raise ValueError("missing selected_candidate_id")


def _sample_spread(values: Sequence[float]) -> dict[str, Any]:
    median = statistics.median(values)
    return {"median_ms": median, "p10_ms": percentile(values, .10),
            "p90_ms": percentile(values, .90), "min_ms": min(values), "max_ms": max(values),
            "p90_abs_log_deviation": percentile([abs(math.log(value / median)) for value in values], .90)}


def paired_ratio_interval(native: Sequence[Mapping[str, Any]], af: Sequence[Mapping[str, Any]],
                          *, seed: int = 62026, draws: int = 2000) -> dict[str, Any]:
    """Paired resampling of repetition IDs, with predeclared deterministic seed."""
    left = {row["iteration"]: server_time(row) for row in native}
    right = {row["iteration"]: server_time(row) for row in af}
    if not left or set(left) != set(right):
        raise ValueError("AF and Native interval samples do not share repetition IDs")
    pairs = [(left[index], right[index]) for index in sorted(left)]
    rng = random.Random(seed)
    ratios, differences = [], []
    for _ in range(draws):
        sampled = [pairs[rng.randrange(len(pairs))] for _ in pairs]
        native_median = statistics.median(pair[0] for pair in sampled)
        af_median = statistics.median(pair[1] for pair in sampled)
        ratios.append(native_median / af_median)
        differences.append(native_median - af_median)
    return {"lower": percentile(ratios, .025), "upper": percentile(ratios, .975),
            "native_minus_af_ms_lower": percentile(differences, .025),
            "native_minus_af_ms_upper": percentile(differences, .975),
            "native_minus_af_us_lower": 1000 * percentile(differences, .025),
            "native_minus_af_us_upper": 1000 * percentile(differences, .975),
            "confidence": .95, "draws": draws, "seed": seed,
            "method": "paired repetition bootstrap of Native-median / AF-median"}


def compare_controls(a: Sequence[Mapping[str, Any]], b: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Controls are paired by repetition, without SQL pooling or outlier removal."""
    errors = []
    by_a = {row.get("iteration"): row for row in a}
    by_b = {row.get("iteration"): row for row in b}
    if (len(by_a) != len(a) or len(by_b) != len(b) or
            any(not isinstance(index, int) for index in set(by_a) | set(by_b))):
        return {"passed": False, "integrity_passed": False,
                "errors": ["control repetition identity is missing or duplicated"],
                "median_ratio": None, "paired_abs_log_ratio_p90": None}
    if set(by_a) != set(by_b) or not by_a:
        errors.append("control arms do not share repetition identities")
    ratios = []
    sqls, states, roles, campaigns, cases = set(), set(), set(), set(), set()
    for iteration in sorted(set(by_a) & set(by_b)):
        left, right = by_a[iteration], by_b[iteration]
        try:
            for row in (left, right):
                _identity(row)
                sqls.add(row["executed_sql_hash"])
                states.add(row["state_id"])
                campaigns.add(row["campaign_id"])
                cases.add((row["family"], row["case_id"]))
                if "role" in row:
                    roles.add(row["role"])
            if left.get("status") not in SUCCESS or right.get("status") not in SUCCESS:
                raise ValueError("control is not a successful execution")
            ratios.append(server_time(left) / server_time(right))
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(f"control repetition {iteration}: {exc}")
    if len(sqls) != 1 or len(states) != 1 or len(roles) > 1 or len(campaigns) != 1 or len(cases) != 1:
        errors.append("control SQL/state/role identity differs")
    if not ratios or errors:
        return {"passed": False, "integrity_passed": False, "errors": errors,
                "median_ratio": None, "paired_abs_log_ratio_p90": None}
    left_values = [server_time(by_a[index]) for index in sorted(by_a)]
    right_values = [server_time(by_b[index]) for index in sorted(by_b)]
    median_ratio = statistics.median(left_values) / statistics.median(right_values)
    p90 = percentile([abs(math.log(value)) for value in ratios], .90)
    passed = abs(math.log(median_ratio)) <= PRACTICAL_LOG_BAND and p90 <= CONTROL_P90_LOG_LIMIT
    return {"passed": passed, "integrity_passed": True, "errors": [],
            "median_ratio": median_ratio, "paired_abs_log_ratio_p90": p90,
            "paired_relative_noise_p90": math.expm1(p90), "pairs": len(ratios),
            "sql_hash": next(iter(sqls)), "state_id": next(iter(states)),
            "a_spread": _sample_spread(left_values), "b_spread": _sample_spread(right_values),
            "gate": {"median_ratio_band": [1 / 1.05, 1.05], "paired_noise_p90_limit": .10}}


def summarize_controls(records: Iterable[Mapping[str, Any]], *,
                       expected_groups: Sequence[str] | None = None,
                       warmup_count: int = 5, measured_count: int = 20,
                       measurement_batch_counts: Mapping[str, int] | None = None,
                       measurement_repetition_counts: Mapping[str, int] | None = None) -> dict[str, Any]:
    groups: dict[str, dict[str, list[Mapping[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    errors = []
    for row in records:
        if row.get("record_kind") != "control":
            continue
        group = str(row.get("control_group_id") or "")
        arm = str(row.get("control_arm") or "")
        if not group or arm not in ("A", "B"):
            errors.append("control missing group or A/B arm")
            continue
        groups[group][arm].append(row)
    if expected_groups is None:
        errors.append("control groups were not predeclared")
    elif set(groups) != set(expected_groups):
        errors.append(f"control group inventory differs: observed {sorted(groups)}, expected {sorted(expected_groups)}")
    reports = []
    for group, arms in sorted(groups.items()):
        local = []
        for arm in ("A", "B"):
            members = arms.get(arm, [])
            count = declared_repetition_count(members[0] if members else {"control_group_id": group},
                                              measurement_repetition_counts, measured_count)
            local.extend(_phase_check(members, warmup_count, count, f"{group}/{arm}"))
            for row in arms.get(arm, []):
                try:
                    _identity(row)
                    server_time(row, expected_batch_count=declared_batch_count(row, measurement_batch_counts))
                    if row.get("status") not in SUCCESS:
                        raise ValueError("control warmup/execution not successful")
                except (KeyError, TypeError, ValueError) as exc:
                    local.append(f"{group}/{arm}/{row.get('phase')}/{row.get('iteration')}: {exc}")
        report = compare_controls([row for row in arms.get("A", []) if row.get("phase") == "measured"],
                                  [row for row in arms.get("B", []) if row.get("phase") == "measured"])
        report.update({"control_group_id": group})
        if local:
            report["passed"] = report["integrity_passed"] = False
            report["errors"].extend(local)
        reports.append(report)
        errors.extend(f"{group}: {error}" for error in report["errors"])
    return {"schema": SCHEMA, "control_only": True,
            "ready": not errors and bool(reports) and all(report["passed"] for report in reports),
            "integrity_ready": not errors and bool(reports),
            "gate_failures": [report["control_group_id"] for report in reports if not report["passed"]],
            "blockers": errors, "controls": reports,
            "scope": "identical-SQL instrument gate; no AF gain inspected; no 1% precision claim"}


def summarize_records(records: Iterable[Mapping[str, Any]], *,
                      expected_cases: Mapping[str, Sequence[str]] | None = None,
                      expected_modes: Mapping[str, Sequence[str]] | None = None,
                      fastest_modes: Mapping[str, Sequence[str]] | None = None,
                      measured_count: int = 10, warmup_count: int = 5,
                      require_noise_control: bool = True,
                      measurement_batch_counts: Mapping[str, int] | None = None,
                      measurement_repetition_counts: Mapping[str, int] | None = None) -> dict[str, Any]:
    source = [dict(row) for row in records]
    blockers, warnings = [], []
    groups: dict[tuple[str, str], dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    candidate_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    availability: dict[tuple[str, str], dict[str, str]] = defaultdict(dict)
    candidate_inventory: dict[tuple[str, str], set[str]] = {}
    campaigns = set()
    for row in source:
        kind = row.get("record_kind", "query")
        key = (str(row.get("family", "")), str(row.get("case_id", "")))
        if kind == "failure":
            blockers.append(f"{key[0]}/{key[1]}: {row.get('error', 'failure')}")
        elif kind == "case_preflight":
            for item in row.get("unavailable_modes", []):
                availability[key][str(item["mode"])] = str(item.get("reason", "not applicable"))
            if "admitted_candidate_ids" in row:
                candidate_inventory[key] = set(map(str, row["admitted_candidate_ids"]))
        elif kind in ("candidate", "candidate_diagnostic"):
            candidate_groups[key].append(row)
        elif kind in ("query", "normal_mode") and not ("event" in row and "record_kind" not in row):
            if not all(key) or not row.get("mode") or not row.get("campaign_id"):
                blockers.append("query missing campaign/family/case/mode")
                continue
            campaigns.add(row["campaign_id"])
            groups[key][str(row["mode"])].append(row)
    if len(campaigns) != 1:
        blockers.append(f"expected one campaign, observed {sorted(campaigns)}")
    if expected_cases is None or expected_modes is None:
        blockers.append("full case and mode inventories were not predeclared")
    if expected_cases is not None:
        expected = {(family, str(case)) for family, cases in expected_cases.items() for case in cases}
        if set(groups) != expected:
            blockers.append(f"case inventory differs: missing={sorted(expected - set(groups))}, unexpected={sorted(set(groups) - expected)}")
    cases = []
    for key, mode_rows in sorted(groups.items()):
        family, case_id = key
        start = len(blockers)
        prefix = f"{family}/{case_id}"
        try:
            case_measured_count = declared_repetition_count({"family": family, "case_id": case_id},
                                                           measurement_repetition_counts, measured_count)
        except ValueError as exc:
            blockers.append(f"{prefix}: {exc}")
            cases.append({"family": family, "case_id": case_id, "valid": False, "modes": {},
                          "classification": "unresolved",
                          "classification_label": "unresolved_difference_not_beyond_measurement_fluctuation"})
            continue
        declared = set(expected_modes.get(family, [])) if expected_modes is not None else set(mode_rows)
        missing = declared - set(mode_rows) - set(availability[key])
        if missing or set(mode_rows) - declared:
            blockers.append(f"{prefix}: mode inventory missing={sorted(missing)}, unexpected={sorted(set(mode_rows) - declared)}")
        modes, measured_by_mode, states, repetition_sets = {}, {}, set(), set()
        for mode in sorted(declared):
            rows = mode_rows.get(mode, [])
            if not rows and mode in availability[key]:
                modes[mode] = {"status": "not_applicable", "reason": availability[key][mode]}
                continue
            local = _phase_check(rows, warmup_count, case_measured_count, f"{prefix}/{mode}")
            measured = sorted((row for row in rows if row.get("phase") == "measured"), key=lambda row: row["iteration"] if isinstance(row.get("iteration"), int) else -1)
            measured_by_mode[mode] = measured
            statuses = {row.get("status") for row in measured}
            if statuses and statuses <= INAPPLICABLE:
                modes[mode] = {"status": "not_applicable", "measured_samples": len(measured)}
                blockers.extend(local)
                continue
            for row in rows:
                if row.get("phase") != "warmup":
                    continue
                try:
                    if row.get("status") not in SUCCESS:
                        raise ValueError(f"warmup status {row.get('status')}")
                    _identity(row, af=mode == AF)
                    server_time(row, expected_batch_count=declared_batch_count(row, measurement_batch_counts))
                    if mode == AF:
                        number(row, "choice_total_wall_ms")
                except (KeyError, TypeError, ValueError) as exc:
                    local.append(f"{prefix}/{mode}/warmup/{row.get('iteration')}: {exc}")
            times, costs = [], []
            for row in measured:
                try:
                    if row.get("status") not in SUCCESS:
                        raise ValueError(f"execution status {row.get('status')}")
                    _identity(row, af=mode == AF)
                    times.append(server_time(row, expected_batch_count=declared_batch_count(row, measurement_batch_counts)))
                    states.add(row["state_id"])
                    if mode == AF:
                        costs.append(number(row, "choice_total_wall_ms"))
                except (KeyError, TypeError, ValueError) as exc:
                    local.append(f"{prefix}/{mode}/{row.get('iteration')}: {exc}")
            repetition_sets.add(tuple(row.get("iteration") for row in measured))
            blockers.extend(local)
            modes[mode] = {"status": "invalid" if local else "pass", "measured_samples": len(measured),
                           "query_server_ms_median": statistics.median(times) if times else None,
                           "server_spread": _sample_spread(times) if times else None,
                           "choice_total_wall_ms_median": statistics.median(costs) if costs else None}
        if len(states) != 1 or len(repetition_sets) != 1:
            blockers.append(f"{prefix}: cross-mode state or repetition identities differ")
        valid = len(blockers) == start and not any(item.startswith(prefix + ":") or item.startswith(prefix + "/") for item in blockers[:start])
        result = {"family": family, "case_id": case_id, "valid": valid, "modes": modes,
                  "predeclared_measured_blocks": case_measured_count,
                  "native_over_af_query_server": None, "classification": "unresolved",
                  "stable_choice": False, "resolved_positive_savings": False,
                  "estimated_reuse_executions": None}
        if not valid or any(modes.get(mode, {}).get("status") != "pass" for mode in (AF, NATIVE)):
            if valid:
                blockers.append(f"{prefix}: AF and Native successful samples required")
                result["valid"] = False
            cases.append(result)
            continue
        af_ms = modes[AF]["query_server_ms_median"]
        native_ms = modes[NATIVE]["query_server_ms_median"]
        ratio = native_ms / af_ms
        result["native_over_af_query_server"] = ratio
        aa = compare_controls(measured_by_mode[NATIVE], measured_by_mode[PD]) if modes.get(PD, {}).get("status") == "pass" else {
            "passed": False, "integrity_passed": False, "errors": ["Native+PD control unavailable"],
            "paired_abs_log_ratio_p90": None}
        result["identical_sql_control"] = {name: value for name, value in aa.items() if name not in ("passed", "gate")}
        result["identical_sql_control"]["scope"] = "per-case noise envelope; no global precision/adoption gate"
        if require_noise_control and not aa["integrity_passed"]:
            blockers.extend(f"{prefix}: {error}" for error in aa["errors"])
            result["valid"] = False
        resolution = aa.get("paired_abs_log_ratio_p90") or 0
        result["resolution_relative"] = math.expm1(resolution)
        interval = paired_ratio_interval(measured_by_mode[NATIVE], measured_by_mode[AF])
        result["native_over_af_ratio_interval"] = interval
        if aa["integrity_passed"] or not require_noise_control:
            if interval["lower"] > math.exp(resolution):
                result["classification"] = "win"
            elif interval["upper"] < math.exp(-resolution):
                result["classification"] = "loss"
        result["classification_label"] = "unresolved_difference_not_beyond_measurement_fluctuation" if result["classification"] == "unresolved" else result["classification"]
        choices = {(row["selected_candidate_id"], row["executed_sql_hash"], row["state_id"]) for row in measured_by_mode[AF]}
        stable = len(choices) == 1
        result["stable_choice"] = stable
        result["savings_per_execution_server_ms"] = native_ms - af_ms
        result["native_minus_af_server_ms"] = native_ms - af_ms
        result["native_minus_af_server_us"] = 1000 * (native_ms - af_ms)
        result["absolute_server_difference_ms"] = abs(native_ms - af_ms)
        result["absolute_server_difference_us"] = 1000 * abs(native_ms - af_ms)
        result["raw_positive_difference"] = native_ms > af_ms
        if stable and result["valid"] and result["classification"] == "win":
            result["resolved_positive_savings"] = True
            result["estimated_reuse_executions"] = math.ceil(modes[AF]["choice_total_wall_ms_median"] / (native_ms - af_ms))
        pool = set(fastest_modes.get(family, [])) if fastest_modes is not None else declared - {AF}
        available = {mode: value["query_server_ms_median"] for mode, value in modes.items()
                     if mode in pool and value["status"] == "pass"}
        result["af_over_fastest_fixed_query_server"] = af_ms / min(available.values()) if available else None
        result["fastest_fixed_modes"] = sorted(mode for mode, value in available.items() if value == min(available.values())) if available else []
        candidate_times: dict[str, list[float]] = defaultdict(list)
        all_candidate_rows: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        per_iteration: dict[int, dict[str, Mapping[str, Any]]] = defaultdict(dict)
        candidate_errors = []
        for row in candidate_groups[key]:
            if row.get("admitted") is not True:
                continue
            candidate_id = str(row.get("selected_candidate_id") or row.get("candidate_id") or "")
            all_candidate_rows[candidate_id].append(row)
            try:
                _identity(row, af=True)
                if row.get("status") not in SUCCESS:
                    raise ValueError("candidate not successful")
                if row["state_id"] not in states or row["campaign_id"] not in campaigns:
                    raise ValueError("candidate SQL probe has a different state/campaign")
                server_time(row, expected_batch_count=declared_batch_count(row, measurement_batch_counts))
                if row.get("phase") != "measured":
                    continue
                iteration = int(row["iteration"])
                if candidate_id in per_iteration[iteration]:
                    raise ValueError("duplicate candidate/repetition")
                per_iteration[iteration][candidate_id] = row
                candidate_times[candidate_id].append(server_time(row))
            except (KeyError, TypeError, ValueError) as exc:
                candidate_errors.append(f"candidate {candidate_id}: {exc}")
        inventory = candidate_inventory.get(key)
        if inventory is not None:
            for candidate_id in sorted(inventory):
                candidate_errors.extend(_phase_check(all_candidate_rows[candidate_id], warmup_count,
                                                    case_measured_count, f"candidate {candidate_id}"))
        quality = []
        for selected in measured_by_mode[AF]:
            candidates = per_iteration.get(selected["iteration"], {})
            if inventory is not None and set(candidates) != inventory:
                candidate_errors.append(f"candidate inventory at {selected['iteration']}: expected {sorted(inventory)}, observed {sorted(candidates)}")
            chosen = candidates.get(selected["selected_candidate_id"])
            if chosen is not None:
                if chosen["executed_sql_hash"] != selected["executed_sql_hash"] or chosen["state_id"] != selected["state_id"]:
                    candidate_errors.append("candidate probe differs from selected SQL/state")
                else:
                    quality.append(server_time(chosen) / min(server_time(row) for row in candidates.values()))
        if candidate_errors:
            blockers.extend(f"{prefix}: {error}" for error in candidate_errors)
            result["valid"] = False
            result["resolved_positive_savings"] = False
            result["estimated_reuse_executions"] = None
        medians = {candidate: statistics.median(times) for candidate, times in candidate_times.items() if len(times) == case_measured_count}
        result["candidate_server_quality"] = {
            "available_repetitions": len(quality), "expected_repetitions": case_measured_count,
            "selected_over_fastest_admitted_ratios": quality,
            "candidate_server_ms_medians": medians,
            "matches_exact": sum(value == 1 for value in quality),
            "selected_over_fastest_admitted_descriptive": descriptive_ratios(quality),
            "af_over_fastest_admitted_query_server": af_ms / min(medians.values()) if medians else None,
            "scope": "same-repetition admitted-candidate server probes; no pooling"}
        cases.append(result)
    families = {}
    for family in sorted({case["family"] for case in cases}):
        valid = [case for case in cases if case["family"] == family and case["valid"]]
        positive = [case for case in valid if case["resolved_positive_savings"]]
        choices = [case["modes"][AF]["choice_total_wall_ms_median"] for case in valid]
        families[family] = {
            "observed_cases": sum(case["family"] == family for case in cases), "valid_cases": len(valid),
            "query_server_native_over_af": descriptive_ratios([case["native_over_af_query_server"] for case in valid]),
            "classification": {"wins": sum(case["classification"] == "win" for case in valid),
                               "ties_inconclusive": sum(case["classification"] == "unresolved" for case in valid),
                               "losses": sum(case["classification"] == "loss" for case in valid)},
            "unresolved_difference_not_beyond_measurement_fluctuation_cases": sum(case["classification"] == "unresolved" for case in valid),
            "af_over_fastest_fixed_query_server": descriptive_ratios([case["af_over_fastest_fixed_query_server"] for case in valid if case["af_over_fastest_fixed_query_server"] is not None]),
            "af_over_fastest_admitted_query_server": descriptive_ratios([case["candidate_server_quality"]["af_over_fastest_admitted_query_server"] for case in valid if case["candidate_server_quality"]["af_over_fastest_admitted_query_server"] is not None]),
            "choice_total_wall_ms_median_of_case_medians": statistics.median(choices) if choices else None,
            "reuse": {"stable_choice_cases": sum(case["stable_choice"] for case in valid),
                      "resolved_positive_savings_cases": len(positive),
                      "observed_positive_difference_cases_diagnostic": sum(case["raw_positive_difference"] for case in valid),
                      "resolved_no_positive_savings_cases": sum(case["classification"] == "loss" for case in valid),
                      "unresolved_cases": sum(case["classification"] == "unresolved" for case in valid),
                      "median_estimated_executions_resolved_positive_subset": statistics.median([case["estimated_reuse_executions"] for case in positive]) if positive else None,
                      "scope": "conditional server-work-equivalent recovery estimate; no ordinary-request or implemented-cache claim"}}
    return {"schema": SCHEMA, "ready": not blockers and expected_cases is not None and expected_modes is not None,
            "blockers": blockers, "warnings": warnings, "campaign_ids": sorted(campaigns),
            "families": families, "cases": cases,
            "metric_contract": {"primary": "actual SQL server planning + execution + applicable validation",
                                "sample_unit": "one predeclared K-query batch mean; case-specific predeclared repetition count is batches, never K-times-batches",
                                "choice": "same-campaign choice_total_wall_ms measured separately",
                                "request": "not measured: EXPLAIN wall is not ordinary-request wall",
                                "resolution": "same-case paired A/A p90 absolute log ratio; no fixed percentage tie band",
                                "classification": "win if paired bootstrap 95% ratio CI lower exceeds exp(A/A envelope); loss if upper below exp(-envelope); otherwise unresolved_difference_not_beyond_measurement_fluctuation",
                                "reuse": "ceil(choice-wall median / server Native-minus-AF median), only stable resolved-positive cases",
                                "sql_pooling": "none", "cross_family_aggregation": "none"}}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--declaration", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--control-only", action="store_true")
    args = parser.parse_args(argv)
    input_bytes, declaration_bytes = args.input.read_bytes(), args.declaration.read_bytes()
    records = [json.loads(line) for line in input_bytes.decode().splitlines() if line.strip()]
    declaration = json.loads(declaration_bytes)
    if args.control_only:
        report = summarize_controls(records, **{key: declaration[key] for key in
            ("expected_groups", "warmup_count", "measured_count", "measurement_batch_counts", "measurement_repetition_counts") if key in declaration})
    else:
        report = summarize_records(records, **{key: declaration[key] for key in
            ("expected_cases", "expected_modes", "fastest_modes", "warmup_count", "measured_count", "require_noise_control", "measurement_batch_counts", "measurement_repetition_counts") if key in declaration})
    report.update({"input_sha256": hashlib.sha256(input_bytes).hexdigest(), "input_bytes": len(input_bytes),
                   "declaration_sha256": hashlib.sha256(declaration_bytes).hexdigest(),
                   "analyzer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    rendered = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(rendered)
    else:
        print(rendered, end="")
    return 0 if report["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
