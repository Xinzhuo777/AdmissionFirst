"""Offline reduction of the original protocol with complete sparse choice timing.

Original performance estimators, SQL pooling and W/U/L rules are reused from
the frozen original pure reducer. Component statistics use the new sidecar's
direct measurements only. No proportional allocation of historical cost,
database access, sampling, or manuscript adoption occurs here.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import statistics
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
ACTIVITY = "ORIGINAL_PROTOCOL_OBSERVED_20261010_V1"
PURE_REDUCER = ROOT / "output/section65_original_protocol_execution_2026-10-06/independent_analysis/analyze_original.py"
PURE_REDUCER_SHA256 = "4d1b4a368fc154585fed8dce5cba5229c95248de6c59f7720993bd3d1fc40905"
CATEGORIES = (
    "admission", "certificate_checker", "candidate_construction",
    "postgres_explain", "database_other", "selection_other",
)
WARMUP = 5
MEASURED = 30
REQUIRED_HOOKS = {
    "planner.query.plan_query", "planner.strict_planning.strict_plan_forced_alternative",
    "planner.core._typed_target_admission", "ContractChecker.check",
    "planner.certificate_envelope.replay_certificate_envelope",
    "planner.verifier.cert_checker.check_certificate",
    "planner.root_selection.select_completed_roots", "PostgresTransactionSession.execute",
    "_PsqlInteractiveChannel.execute",
}
ROOT_SELECTOR = "planner.root_selection.select_completed_roots"
# The sparse collector records class bindings as Class.method in its
# installed-binding inventory, while its category coverage uses Module.Class.method.
# These exact aliases identify the same three installed class boundaries.
# Never use a suffix/short-name heuristic: unknown modules must still fail.
EXACT_CLASS_HOOK_ALIASES = {
    "ContractChecker.check": "planner.core.ContractChecker.check",
    "PostgresTransactionSession.__init__": "caprls_core.postgres_runner.PostgresTransactionSession.__init__",
    "PostgresTransactionSession.execute": "caprls_core.postgres_runner.PostgresTransactionSession.execute",
    "_PsqlInteractiveChannel.execute": "caprls_core.postgres_runner._PsqlInteractiveChannel.execute",
}


def _canonical_hook(label: str) -> str:
    return EXACT_CLASS_HOOK_ALIASES.get(label, label)


def _validate_coverage(breakdown: Mapping[str, Any], family: str) -> None:
    inventory = breakdown.get("hook_inventory")
    if not isinstance(inventory, list) or any(not isinstance(hook, str) for hook in inventory):
        raise ValueError("installed named hook inventory missing")
    owner_hook = f"caprls_core.{ 'e3_main' if family == 'E3' else 'e10_study' }._require_{family.lower()}_production_planning_owner"
    installed = {_canonical_hook(hook) for hook in inventory}
    missing = {_canonical_hook(hook) for hook in REQUIRED_HOOKS | {owner_hook}} - installed
    if missing:
        raise ValueError(f"required named hooks missing: {sorted(missing)}")
    counts, coverage = breakdown.get("call_counts"), breakdown.get("coverage")
    if not isinstance(counts, Mapping) or set(counts) != set(CATEGORIES):
        raise ValueError("complete six-category call counts missing")
    if not isinstance(coverage, Mapping) or set(coverage) != set(CATEGORIES):
        raise ValueError("explicit component coverage/not-applicable declarations missing")
    for category in CATEGORIES:
        count = counts[category]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError(f"{category}: invalid boundary call count")
        entry = coverage[category]
        if not isinstance(entry, Mapping) or entry.get("calls") != count:
            raise ValueError(f"{category}: coverage count does not match observed calls")
        hooks = entry.get("hooks_installed")
        if not isinstance(hooks, list) or not hooks or any(not isinstance(hook, str) for hook in hooks) or not {_canonical_hook(hook) for hook in hooks}.issubset(installed):
            raise ValueError(f"{category}: installed coverage hooks missing or not bound to inventory")
        if count > 0 and entry.get("status") != "observed":
            raise ValueError(f"{category}: positive calls lack observed coverage")
        external_remainder = category == "selection_other" and entry.get("status") == "observed" and bool(entry.get("reason"))
        if count == 0 and not external_remainder and (entry.get("status") != "not_applicable" or not entry.get("reason")):
            raise ValueError(f"{category}: zero calls require explicit not-applicable reason")
        if category != "selection_other" and breakdown["exclusive_ms"][category] > 0 and count == 0:
            raise ValueError(f"{category}: positive exclusive work has no observed boundary call")
    if counts["candidate_construction"] == 0:
        raise ValueError("original candidate construction was not observed; cannot accept all work as residual")
    sql_counts, sql_coverage = breakdown.get("sql_call_counts"), breakdown.get("sql_coverage")
    kinds = {"plain_explain", "explain_analyze", "other"}
    if not isinstance(sql_counts, Mapping) or set(sql_counts) != kinds or not isinstance(sql_coverage, Mapping) or set(sql_coverage) != kinds:
        raise ValueError("complete SQL-call counts and explicit coverage missing")
    for kind in kinds:
        count, entry = sql_counts[kind], sql_coverage[kind]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0 or not isinstance(entry, Mapping) or entry.get("calls") != count:
            raise ValueError(f"{kind}: SQL coverage count invalid")
        if count > 0 and entry.get("status") != "observed":
            raise ValueError(f"{kind}: SQL calls lack observed status")
        if count == 0 and (entry.get("status") != "not_applicable" or not entry.get("reason")):
            raise ValueError(f"{kind}: zero SQL calls require a not-applicable explanation")
    if sql_counts["explain_analyze"]:
        raise ValueError("selection window unexpectedly contains EXPLAIN ANALYZE")
    functions = breakdown.get("functions")
    if not isinstance(functions, Mapping) or not functions:
        raise ValueError("direct named function observations missing")
    if not any(label in functions and functions[label].get("calls", 0) > 0
               for label in coverage["candidate_construction"]["hooks_installed"]):
        raise ValueError("no named candidate-construction execution was captured")


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            digest.update(block)
    return digest.hexdigest()


def write_new(path: Path, payload: Any) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(payload, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{number}: sidecar record is not an object")
            rows.append(row)
    return rows


def _numeric(value: Any, name: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name}: nonnumeric")
    result = float(value)
    if not math.isfinite(result) or (result <= 0 if positive else result < 0):
        raise ValueError(f"{name}: invalid value")
    return result


def validate_gate(run: Path, *, root: Path = ROOT) -> dict[str, Any]:
    """Check completion, protocol and frozen source identities before raw IO."""
    completion = json.loads((run / "completion.json").read_text())
    if completion.get("status") != "pass":
        raise ValueError("sampling completion is not pass")
    if completion.get("failures") or completion.get("observer_errors"):
        raise ValueError("sampling or observer failures are present")
    family_statuses = {entry["family"]: entry["status"] for entry in completion.get("families", [])}
    if family_statuses != {"E3": "pass", "E10": "pass"}:
        raise ValueError("both original driver families must complete with pass")
    protocol = json.loads((run / "protocol.json").read_text())
    if protocol.get("activity") != ACTIVITY or protocol.get("warmup") != WARMUP or protocol.get("measured") != MEASURED:
        raise ValueError("activity or frozen original 5/30 protocol identity differs")
    snapshot_path = run / "original_source_snapshot.json"
    snapshot = json.loads(snapshot_path.read_text())
    if not isinstance(snapshot, dict) or not snapshot:
        raise ValueError("frozen source snapshot is missing or empty")
    current = {}
    for name, expected in snapshot.items():
        path = root / name
        if not path.resolve().is_relative_to(root.resolve()):
            raise ValueError(f"snapshot source escapes repository: {name}")
        current[name] = sha(path)
    changed = [name for name in snapshot if current[name] != snapshot[name]]
    if changed:
        raise ValueError(f"frozen sampling/observation sources changed: {changed}")
    if sha(PURE_REDUCER) != PURE_REDUCER_SHA256:
        raise ValueError("frozen original pure reducer hash differs")
    return {"completion": completion, "protocol": protocol, "snapshot": snapshot,
            "source_hashes_before_reduction": current,
            "source_snapshot_sha256": sha(snapshot_path), "protocol_sha256": sha(run / "protocol.json")}


def load_pure_reducer():
    specification = importlib.util.spec_from_file_location("caprls_original_performance_pure_frozen", PURE_REDUCER)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _cost_key(record: Mapping[str, Any]) -> tuple[str, str, str]:
    family = str(record.get("family") or "")
    query = str(record.get("query_id") or record.get("case_id") or "")
    policy = str(record.get("policy_id") or "") if family == "E3" else ""
    return family, query, policy


def validate_and_summarize_components(
    records: Iterable[Mapping[str, Any]], expected_keys: Sequence[tuple[str, str, str]],
    *, warmup: int = WARMUP, measured: int = MEASURED,
) -> dict[str, Any]:
    """Audit every choice, including warmup, and summarize direct observations."""
    groups: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    blockers = []
    choice_count = 0
    for record in records:
        if record.get("record_kind") != "choice":
            continue
        choice_count += 1
        key = _cost_key(record)
        groups[key].append(record)
        label = f"{key}/{record.get('phase')}/{record.get('iteration')}"
        if record.get("profile_state") != "disabled":
            blockers.append(f"{label}: global-profile-disabled identity missing")
        if record.get("status") not in (None, "pass"):
            blockers.append(f"{label}: observation status is not pass")
        if not isinstance(record.get("selected_template_id"), str) or not record["selected_template_id"]:
            blockers.append(f"{label}: selected template identity missing")
        binding_field = "original_timed_runner_sql_hash" if key[0] == "E3" else "original_runner_sql_hash_if_available"
        if not isinstance(record.get(binding_field), str) or not record[binding_field]:
            blockers.append(f"{label}: original timed SQL binding hash missing")
        breakdown = record.get("breakdown")
        if not isinstance(breakdown, Mapping):
            blockers.append(f"{label}: complete breakdown missing")
            continue
        try:
            total = _numeric(breakdown.get("total_wall_ms"), "total_wall_ms", positive=True)
            choice = _numeric(record.get("choice_cost_ms"), "choice_cost_ms", positive=True)
            exclusive = breakdown.get("exclusive_ms")
            if not isinstance(exclusive, Mapping) or set(exclusive) != set(CATEGORIES):
                raise ValueError("exactly six exclusive component categories are required")
            values = [_numeric(exclusive[category], category) for category in CATEGORIES]
            if not math.isclose(sum(values), total, rel_tol=1e-7, abs_tol=1e-5):
                raise ValueError("exclusive components do not sum to observed total")
            if not math.isclose(choice, total, rel_tol=1e-7, abs_tol=1e-5):
                raise ValueError("choice_cost_ms differs from breakdown total")
            if breakdown.get("global_profile_modified") is not False:
                raise ValueError("sparse collector profiler identity missing")
            _validate_coverage(breakdown, key[0])
        except (TypeError, ValueError) as exc:
            blockers.append(f"{label}: {exc}")
    expected = set(expected_keys)
    if set(groups) != expected:
        blockers.append(f"choice case inventory differs: missing={sorted(expected - set(groups))}, unexpected={sorted(set(groups) - expected)}")
    for key in expected_keys:
        rows = groups[key]
        if key[0] == "E3":
            if len(rows) != 1 or any(row.get("phase") != "case_once" or row.get("iteration") is not None for row in rows):
                blockers.append(f"{key}: E3 requires exactly one case_once observation with iteration null")
        elif key[0] == "E10":
            if len(rows) != warmup + measured:
                blockers.append(f"{key}: E10 requires {warmup + measured} original choice observations")
            for phase, count in (("warmup", warmup), ("measured", measured)):
                ids = [row.get("iteration") for row in rows if row.get("phase") == phase]
                if len(ids) != count or sorted(ids, key=repr) != sorted(range(1, count + 1), key=repr):
                    blockers.append(f"{key}: incomplete or duplicate {phase} choices, expected 1..{count}")
        else:
            blockers.append(f"{key}: unexpected experiment family")
    base = {"direct_new_measurements_only": True, "historical_17_459_scaled": False,
            "choice_records": choice_count, "declared_cases": len(expected_keys),
            "warmup_audited_but_not_aggregated": True,
            "component_medians_are_not_additive": True, "exclusive_observation_totals_are_additive": True,
            "inclusive_timings_are_not_additive": True,
            "sparse_observer_overhead_is_included": True, "blockers": blockers}
    if blockers:
        return {**base, "ready": False, "families": {}, "cases": []}
    cases = []
    for key in sorted(expected_keys):
        active = groups[key] if key[0] == "E3" else [row for row in groups[key] if row["phase"] == "measured"]
        totals = [float(row["choice_cost_ms"]) for row in active]
        components = {}
        for category in CATEGORIES:
            values = [float(row["breakdown"]["exclusive_ms"][category]) for row in active]
            shares = [value / total for value, total in zip(values, totals)]
            components[category] = {
                "direct_component_ms_median": statistics.median(values),
                "direct_component_ms_mean": statistics.fmean(values),
                "mean_observation_fraction": statistics.fmean(shares),
            }
        function_labels = sorted({label for row in active for label in row["breakdown"]["functions"]} | {
            ROOT_SELECTOR, f"caprls_core.{ 'e3_main' if key[0] == 'E3' else 'e10_study' }._require_{key[0].lower()}_production_planning_owner",
        })
        function_stats = {}
        for label in function_labels:
            observations = [row["breakdown"]["functions"].get(label, {}) for row in active]
            function_stats[label] = {
                "calls_median": statistics.median(value.get("calls", 0) for value in observations),
                "calls_mean": statistics.fmean(value.get("calls", 0) for value in observations),
                "inclusive_ms_median": statistics.median(value.get("inclusive_ms", 0) for value in observations),
                "exclusive_ms_median": statistics.median(value.get("exclusive_ms", 0) for value in observations),
                "inclusive_ms_mean": statistics.fmean(value.get("inclusive_ms", 0) for value in observations),
                "exclusive_ms_mean": statistics.fmean(value.get("exclusive_ms", 0) for value in observations),
                "observations_with_no_call": sum(not value.get("calls", 0) for value in observations),
                "inclusive_timings_are_not_additive": True,
            }
        cases.append({"family": key[0], "query_id": key[1], "policy_id": key[2],
                      "formal_choice_observations": len(active),
                      "direct_choice_total_ms_median": statistics.median(totals),
                      "direct_choice_total_ms_mean": statistics.fmean(totals),
                      "components": components,
                      "named_functions_direct": function_stats,
                      "root_functions_direct": {label: value for label, value in function_stats.items()
                                                if label == ROOT_SELECTOR or "production_planning_owner" in label},
                      "mean_fraction_sum": sum(value["mean_observation_fraction"] for value in components.values())})
    families = {}
    for family in ("E3", "E10"):
        selected = [case for case in cases if case["family"] == family]
        if not selected:
            continue
        families[family] = {
            "cases": len(selected), "formal_choice_observations": sum(case["formal_choice_observations"] for case in selected),
            "total_cost_ms_median_of_case_medians": statistics.median(case["direct_choice_total_ms_median"] for case in selected),
            "components": {category: {
                "component_ms_median_of_case_medians": statistics.median(case["components"][category]["direct_component_ms_median"] for case in selected),
                "component_ms_mean_of_case_means": statistics.fmean(case["components"][category]["direct_component_ms_mean"] for case in selected),
                "equal_case_mean_observation_fraction": statistics.fmean(case["components"][category]["mean_observation_fraction"] for case in selected),
            } for category in CATEGORIES},
            "aggregation_semantics": "one measured choice per case, then across-33-case statistics" if family == "E3" else "30 formal observations per case; case medians then across-11-case median",
            "component_medians_are_not_additive": True,
        }
        root_labels = sorted({label for case in selected for label in case["root_functions_direct"]})
        families[family]["root_functions_direct"] = {
            label: {metric + "_of_case_medians": statistics.median(case["root_functions_direct"].get(label, {}).get(metric, 0) for case in selected)
                    for metric in ("inclusive_ms_median", "exclusive_ms_median", "calls_median")}
            for label in root_labels
        }
        families[family]["equal_case_mean_fraction_sum"] = sum(value["equal_case_mean_observation_fraction"] for value in families[family]["components"].values())
    return {**base, "ready": True, "families": families, "cases": cases}


def analyze(run: Path, output: Path, *, root: Path = ROOT) -> int:
    """Use the frozen pure estimators and issue a single combined receipt."""
    run, output = run.resolve(), output.resolve()
    if output.exists():
        raise FileExistsError(f"refusing to overwrite output: {output}")
    try:
        gate = validate_gate(run, root=root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        output.mkdir(parents=True, exist_ok=False)
        receipt = {"schema": "caprls-observed-original-independent-receipt-v1", "status": "needs_review", "ready": False,
                   "blockers": [str(exc)], "raw_not_parsed": True, "no_sampling_database_or_manuscript_write": True}
        write_new(output / "receipt.json", receipt)
        print(json.dumps(receipt), flush=True)
        return 2
    pure = load_pure_reducer()
    output.mkdir(parents=True, exist_ok=False)
    costs = read_jsonl(run / "choice_costs.jsonl")
    observed_choice_keys = sorted({_cost_key(record) for record in costs if record.get("record_kind") == "choice"})
    preliminary = validate_and_summarize_components(costs, observed_choice_keys)
    for family, wanted in (("E3", 33), ("E10", 11)):
        actual = sum(key[0] == family for key in observed_choice_keys)
        if actual != wanted:
            preliminary["blockers"].append(f"{family}: complete choice sidecar requires {wanted} cases, observed {actual}")
    if preliminary["blockers"]:
        report = {"schema": "caprls-observed-original-independent-analysis-v1", "ready": False,
                  "activity": ACTIVITY, "source_activity": str(run), "blockers": preliminary["blockers"],
                  "choice_components": preliminary, "raw_not_parsed": True,
                  "protocol_sha256": gate["protocol_sha256"], "source_snapshot_sha256": gate["source_snapshot_sha256"],
                  "choice_sidecar_sha256": sha(run / "choice_costs.jsonl"),
                  "historical_cost_scaling": False, "no_sampling_database_or_manuscript_write": True}
        write_new(output / "analysis.json", report)
        receipt = {"schema": "caprls-observed-original-independent-receipt-v1", "status": "needs_review", "ready": False,
                   "blockers": preliminary["blockers"], "choice_component_inventory_pass": False,
                   "analysis_path": str(output / "analysis.json"), "analysis_sha256": sha(output / "analysis.json"),
                   "raw_not_parsed": True, "no_sampling_database_or_manuscript_write": True}
        write_new(output / "receipt.json", receipt)
        print(json.dumps(receipt), flush=True)
        return 2
    blockers, warnings, cases, families, inventories, hashes, expected_keys = [], [], [], {}, {}, {}, []
    for family in ("E3", "E10"):
        raw = pure.rep._load_raw_records(run / family, family)
        rows = []
        for record in raw:
            row = pure.rep._flatten_record(record)
            text = record.get("sql", {}).get("runner_sql")
            row["_runner_sql_plain_text_sha256"] = hashlib.sha256(text.encode()).hexdigest() if isinstance(text, str) else None
            rows.append(row)
        hashes[family] = {str(Path(record["_raw_path"]).relative_to(run)): sha(Path(record["_raw_path"])) for record in raw}
        del raw
        inventories[family] = pure.validate_inventory(rows, family, blockers)
        expected_keys.extend(sorted({(family, pure.case_key(row, family)[0], pure.case_key(row, family)[1] if family == "E3" else "")
                                    for row in rows if row["run_kind"] == "normal_mode"}))
        cells = pure.cells_from_rows(rows, family, blockers)
        cell_rows = pure.rep._cell_stats(rows)
        if family == "E3":
            pure.rep._annotate_e3_runner_sql_canonical_latencies(rows, cell_rows)
        loss_rows = pure.rep._e3_loss_table(cell_rows)[0] if family == "E3" else []
        oracle_rows = pure.rep._template_oracle_analysis(rows)[0] if family == "E10" else []
        if family == "E10" and len(oracle_rows) != 11 * MEASURED:
            blockers.append(f"E10 original oracle inventory {len(oracle_rows)} differs from {11 * MEASURED}")
        pure.write_csv_new(output / f"{family}_runs.csv", rows)
        pure.write_csv_new(output / f"{family}_cell_stats.csv", cell_rows)
        pure.write_csv_new(output / (f"{family}_loss_table.csv" if family == "E3" else f"{family}_template_oracle_analysis.csv"),
                           loss_rows if family == "E3" else oracle_rows)
        chosen_cases = []
        for key, cell in cells:
            try:
                stats = pure.case_statistics(cell, family)
                cost = pure.match_choice(key, family, rows, costs, blockers)
            except (ValueError, KeyError, TypeError) as exc:
                blockers.append(f"{family}/{key}: {exc}")
                continue
            stats.update({"family": family, "query_id": key[0], "policy_id": key[1], "context_id": key[2], **cost})
            eligible = stats["classification"] == "win" and cost["choice_stable"] and cost["choice_cost_ms"] is not None and stats["native_minus_af_ms"] > 0
            stats["eligible_for_recovery"] = eligible
            stats["recovery_executions"] = math.ceil(cost["choice_cost_ms"] / stats["native_minus_af_ms"]) if eligible else None
            if not cost["choice_stable"]:
                warnings.append(f"{family}/{key}: changing selected SQL/state; no single-choice recovery estimate")
            chosen_cases.append(stats)
        cases.extend(chosen_cases)
        if any(case["choice_cost_ms"] is None for case in chosen_cases):
            families[family] = {"cases": len(chosen_cases), "analysis_valid": False,
                                "reason": "choice binding/cost missing; no partial family cost or recovery aggregate"}
        else:
            families[family] = pure.family_report(family, chosen_cases, cells, loss_rows, oracle_rows)
        print(json.dumps({"event": "family_original_reduction_complete", "family": family, "families": {family: families[family]}, "blockers_so_far": blockers}), flush=True)
        del rows, cell_rows
    components = validate_and_summarize_components(costs, expected_keys)
    blockers.extend(components["blockers"])
    for family, summary in components["families"].items():
        primary_cost = families[family].get("choice_cost_ms_median")
        if primary_cost is None or not math.isclose(summary["total_cost_ms_median_of_case_medians"], primary_cost, rel_tol=1e-7, abs_tol=1e-5):
            blockers.append(f"{family}: component audit total median does not match recovery/primary cost median")
    changed_after = [name for name, expected in gate["snapshot"].items() if sha(root / name) != expected]
    if changed_after:
        blockers.append(f"frozen sources changed during offline reduction: {changed_after}")
    ready = not blockers and len(cases) == 44 and components["ready"]
    report = {
        "schema": "caprls-observed-original-independent-analysis-v1", "ready": ready,
        "completed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_activity": str(run), "activity": ACTIVITY, "blockers": blockers, "warnings": warnings,
        "families": families, "cases": cases, "choice_components": components, "inventory": inventories,
        "raw_file_sha256": hashes, "choice_sidecar_sha256": sha(run / "choice_costs.jsonl"),
        "completion_sha256": sha(run / "completion.json"), "protocol_sha256": gate["protocol_sha256"],
        "source_snapshot_sha256": gate["source_snapshot_sha256"], "source_snapshot_changed": changed_after,
        "frozen_original_pure_reducer_sha256": PURE_REDUCER_SHA256, "analyzer_sha256": sha(Path(__file__)),
        "implementation_config_change": gate["protocol"].get("implementation_config_change"),
        "contract": {"performance": "unchanged original Table 3 estimators and ranges",
                     "E3": "exact original timed-SQL pooling for point estimates and bootstrap draws",
                     "E10": "mode-local total medians; candidate quality uses original execution-only oracle ratios",
                     "noise": "same-SQL Native/PD unpooled p90 absolute log envelope; paired 95% ratio CI beyond it",
                     "classification_seed": pure.SEED, "classification_draws": pure.DRAWS,
                     "warmup": WARMUP, "measured": MEASURED,
                     "cost": "direct same-activity sparse observed choice; E3 inputs excluded; E10 original START/STOP inputs included",
                     "recovery": "direct same-activity choice cost / original-estimator saving; stable resolved wins only",
                     "historical_cost_scaling": False, "global_profile_enabled": False,
                     "database_access": False, "manuscript_adoption": False},
    }
    write_new(output / "analysis.json", report)
    receipt = {"schema": "caprls-observed-original-independent-receipt-v1", "status": "pass" if ready else "needs_review", "ready": ready,
               "completed_at": report["completed_at"], "cases": len(cases), "families": families,
               "choice_component_inventory_pass": components["ready"], "blockers": blockers, "warnings": warnings,
               "source_hashes_match": not changed_after, "protocol_sha256": report["protocol_sha256"],
               "analysis_sha256": sha(output / "analysis.json"), "analysis_path": str(output / "analysis.json"),
               "costs_are_direct_measurements": True, "historical_cost_scaling": False,
               "no_sampling_database_or_manuscript_write": True}
    write_new(output / "receipt.json", receipt)
    print(json.dumps(receipt), flush=True)
    return 0 if ready else 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    return analyze(args.run, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
