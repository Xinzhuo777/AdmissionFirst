"""Measure repeated actual AF catalog/choice calls from two isolated sources.

Run this stdlib-only harness as a script (``python -m`` reexecs that script
before source activation). It reuses af_pareto_study's fresh workers, shared
preparation, statistics observations, and global full-bag correctness gate.
No PostgreSQL work occurs merely by importing this module or requesting help.
"""

from __future__ import annotations

import argparse
from contextlib import nullcontext
import csv
from dataclasses import asdict
import importlib.util
import json
import math
from pathlib import Path
import statistics
import sys
import time
import traceback
from typing import Any, Callable, Mapping, Sequence


VARIANTS = ("af-old", "af-new")
COMPONENTS = ("catalog_receipt_wall_ms", "selection_wall_ms", "catalog_plus_selection_wall_ms",
              "worker_request_wall_ms", "worker_residual_wall_ms")


def load_study_tools(path: Path | None = None) -> Any:
    """Load the stdlib harness without claiming a caprls_core source package."""
    path = (path or Path(__file__).with_name("af_pareto_study.py")).resolve()
    name = "_af_choice_pareto_harness_tools"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load retained AF study harness tools")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def harness_identity(tools: Any) -> dict[str, Any]:
    paths = {"choice_harness": Path(__file__).resolve(), "reused_study_harness": Path(tools.__file__).resolve()}
    return {name: {"path": str(path), "sha256": tools.digest_bytes(path.read_bytes())}
            for name, path in paths.items()}


def selected_identity(worker: Mapping[str, Any], tools: Any) -> dict[str, Any]:
    """Freeze executable semantics while allowing fresh receipt/snapshot IDs."""
    spec, selection = worker.get("spec"), worker.get("selection")
    if not isinstance(spec, dict) or not isinstance(selection, dict):
        raise ValueError("choice worker lacks its exact executable spec/selection")
    bound = selection.get("bound_runner")
    if not isinstance(bound, dict) or type(spec.get("sql")) is not str or not spec["sql"]:
        raise ValueError("choice worker lacks its exact bound SQL")
    sql_digest = tools.digest_json({"exact_runner_sql": spec["sql"]})
    if (bound.get("runner_sql") != spec["sql"]
        or bound.get("runner_sql_digest") != sql_digest
        or selection.get("selected_runner_digest") != sql_digest
        or selection.get("selected_template_id") != bound.get("template_id")
        or bound.get("template_id") != spec.get("template_id")
        or type(spec.get("template_id")) is not str or not spec["template_id"]
        or selection.get("selected_plan_id") != bound.get("plan_id")
        or type(bound.get("plan_id")) is not str or not bound["plan_id"]
        or selection.get("measured_runtime_used_for_selection") is not False):
        raise ValueError("choice worker's selected SQL/template/plan binding is inconsistent")
    profile = spec.get("execution_profile")
    if profile is not None:
        if (not isinstance(profile, dict) or profile.get("name") != "trusted_explicit"
            or not isinstance(spec.get("session_contract"), dict)
            or selection.get("execution_profile") != "trusted_explicit"
            or spec.get("session_contract") != bound.get("session_contract")
            or profile != bound.get("execution_profile")
            or spec["session_contract"].get("digest") != bound.get("session_contract_digest")
            or profile.get("session_contract_digest") != bound.get("session_contract_digest")
            or spec.get("role") != spec["session_contract"].get("role")):
            raise ValueError("choice worker execution profile is detached from its bound runner")
        # Receipt IDs legitimately change with a new worker's catalog snapshot.
        profile = {key: value for key, value in profile.items()
                   if key not in {"receipt_digest", "profile_digest"}}
    elif (selection.get("execution_profile") == "trusted_explicit" or bound.get("execution_profile") is not None
          or spec.get("session_contract") is not None or bound.get("session_contract") is not None):
        raise ValueError("choice worker silently lost its trusted execution profile")
    return {
        "sql_sha256": tools.digest_bytes(spec["sql"].encode()),
        "selected_runner_digest": sql_digest, "template_id": spec["template_id"],
        "executable_spec_digest": tools.digest_json({
            **{key: spec.get(key) for key in ("sql", "template_id", "sql_source", "role", "result_columns",
                                             "artifact_ids", "expected_artifact_json", "session_contract")},
            "execution_profile": profile,
        }),
    }


def worker_components(worker: Mapping[str, Any]) -> dict[str, float]:
    selection = worker["selection"]
    values = {"catalog_receipt_wall_ms": selection.get("catalog_receipt_wall_ms"),
              "selection_wall_ms": selection.get("selection_wall_ms"),
              "worker_request_wall_ms": worker.get("worker_request_wall_ms")}
    for name, value in values.items():
        if type(value) not in {int, float} or not math.isfinite(value) or value < 0:
            raise ValueError("invalid choice timing component: " + name)
    total = values["catalog_receipt_wall_ms"] + values["selection_wall_ms"]
    if values["worker_request_wall_ms"] + 1e-6 < total:
        raise ValueError("worker wall time is shorter than its nested measured calls")
    return {**values, "catalog_plus_selection_wall_ms": total,
            "worker_residual_wall_ms": max(0., values["worker_request_wall_ms"]-total)}


def validate_worker(worker: Mapping[str, Any], *, variant: str, cell: Mapping[str, Any],
                    identity: Mapping[str, Any], manifest_digest: str,
                    required_profile: str | None, tools: Any) -> dict[str, Any]:
    if (worker.get("schema") != "af_pareto_worker_v1" or worker.get("status") != "pass"
        or worker.get("variant") != variant
        or (worker.get("query_id"), worker.get("policy_id")) != (cell["query_id"], cell["policy_id"])
        or worker.get("source_identity") != identity or worker.get("manifest_sha256") != manifest_digest):
        raise ValueError("choice worker source/manifest/case identity changed: " + cell["case_id"]+":"+variant)
    if worker.get("spec", {}).get("mode") != variant:
        raise ValueError("choice worker mode changed")
    bound = worker.get("selection", {}).get("bound_runner", {})
    if (bound.get("query_id"), bound.get("policy_id")) != (cell["query_id"], cell["policy_id"]):
        raise ValueError("choice worker bound runner belongs to another case")
    if required_profile is not None and worker.get("selection", {}).get("execution_profile") != required_profile:
        raise ValueError("choice worker did not provide required new execution profile")
    selected = selected_identity(worker, tools)
    worker_components(worker)
    return selected


def sample_choices(cells: Sequence[Mapping[str, Any]], *, output_dir: Path, warmup: int, measured: int,
                   choose: Callable[[Mapping[str, Any], str], Mapping[str, Any]],
                   restore_cell: Callable[[Mapping[str, Any]], None], check_frozen: Callable[[], None],
                   tools: Any, identities: Mapping[str, Any], manifest_digest: str,
                   statistics_digest: str, require_same_selected_sql: bool = False,
                   required_new_profile: str | None = None) -> dict[str, Any]:
    """Run only after the caller has passed the global full-bag gate."""
    if type(warmup) is not int or warmup < 0 or type(measured) is not int or measured < 1:
        raise ValueError("explicit warmup >= 0 and measured >= 1 are required")
    summary, comparisons = [], []
    all_pilot_ids = {}
    for cell in cells:
        if cell.get("full_bag_gate_passed") is not True:
            raise ValueError("every declared case must pass full-bag correctness before choice sampling")
        pilot_ids = {variant: selected_identity(cell["pilot"][variant], tools) for variant in VARIANTS}
        all_pilot_ids[cell["case_id"]] = pilot_ids
        if require_same_selected_sql and any(
            pilot_ids["af-old"][key] != pilot_ids["af-new"][key] for key in ("sql_sha256", "template_id")
        ):
            raise ValueError("old/new selected SQL or template differs from requested identity ablation: " + cell["case_id"])
    for cell in cells:
        case = cell["case_id"]
        pilot_ids = all_pilot_ids[case]
        same_sql = all(pilot_ids["af-old"][key] == pilot_ids["af-new"][key]
                       for key in ("sql_sha256", "template_id"))
        same_executable = pilot_ids["af-old"]["executable_spec_digest"] == pilot_ids["af-new"]["executable_spec_digest"]
        restore_cell(cell)
        check_frozen()
        values = {variant: [] for variant in VARIANTS}
        for round_index in range(warmup+measured):
            phase = "warmup" if round_index < warmup else "measured"
            iteration = round_index+1 if phase == "warmup" else round_index-warmup+1
            order = VARIANTS[round_index % 2:] + VARIANTS[:round_index % 2]
            for order_index, variant in enumerate(order):
                check_frozen()
                worker = dict(choose(cell, variant))
                relative = f"samples/{case}__{variant}__{phase}{iteration:02d}.json"
                # Retain the returned evidence before validating drift. A
                # changed SQL/template is never silently dropped or timed as
                # though it were the full-bag-checked pilot.
                record = {"case_id": case, "mode": variant, "phase": phase, "iteration": iteration,
                          "round_index": round_index, "order_index": order_index,
                          "manifest_sha256": manifest_digest, "statistics_digest": statistics_digest,
                          "worker": worker}
                tools.write_once(output_dir/relative, record)
                actual = validate_worker(worker, variant=variant, cell=cell, identity=identities[variant],
                    manifest_digest=manifest_digest, required_profile=required_new_profile if variant == "af-new" else None,
                    tools=tools)
                if actual != pilot_ids[variant]:
                    tools.write_once(output_dir/"identity_drift"/(Path(relative).name), {
                        "status": "not_promotable_selected_identity_changed", "input_sample": relative,
                        "pilot_identity": pilot_ids[variant], "actual_identity": actual,
                    })
                    raise ValueError("repeated choice changed its full-bag-checked SQL/template/executable identity: " + case+":"+variant)
                check_frozen()
                if phase == "measured":
                    values[variant].append(worker_components(worker))
        for variant in VARIANTS:
            summary.append({"case_id": case, "query_id": cell["query_id"], "policy_id": cell["policy_id"],
                "mode": variant, "measured_repetitions": measured, "warmup_repetitions": warmup,
                "source_digest": identities[variant]["digest"], **pilot_ids[variant],
                **{"median_"+component: statistics.median(row[component] for row in values[variant])
                   for component in COMPONENTS}})
        comparisons.append({"case_id": case, "same_selected_sql_and_template": same_sql,
            "same_executable_semantics_including_session_profile": same_executable,
            "comparison_scope": "same_executable_identity_choice_comparison" if same_sql and same_executable
                                else "different_system_execution_profiles_or_SQL_not_pure_identity_ablation",
            "paired_measured_rounds": measured,
            **{"old_over_new_median_"+component: (
                    statistics.median(row[component] for row in values["af-old"]) /
                    statistics.median(row[component] for row in values["af-new"])
                    if statistics.median(row[component] for row in values["af-new"]) > 0 else None)
                for component in COMPONENTS}})
    return {"summary": summary, "comparisons": comparisons}


def run_study(args: argparse.Namespace) -> dict[str, Any]:
    tools = load_study_tools()
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=False)
    root = Path(args.root).resolve()
    source, baseline = Path(args.source_root).resolve(), Path(args.baseline_source).resolve()
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = root/manifest_path
    identities = {"af-old": tools.source_identity(baseline), "af-new": tools.source_identity(source)}
    harness = harness_identity(tools)
    manifest_digest = tools.digest_bytes(manifest_path.read_bytes())
    e3, preview, postgres = tools.activate_source(source)
    manifest = e3._load_manifest(manifest_path)
    e3._validate_manifest(manifest_path, manifest)
    e3.require_e3_manifest_data(root, manifest_path, manifest)
    queries = preview._select_items(e3._queries_for_manifest(manifest_path, manifest), args.query,
                                   key=lambda item: item.query_id, label="query")
    policies = preview._select_items(e3._policies_for_manifest(manifest_path, manifest), args.policy,
                                    key=lambda item: item.config_id, label="policy")
    if args.warmup < 0 or args.measured < 1 or args.worker_timeout <= 0:
        raise ValueError("invalid explicit repetitions or worker timeout")
    wrapper = (manifest.get("scale_check") or {}).get("bound_runner_wrapper", "materialized")
    if wrapper not in {"materialized", "not_materialized_single_reference"}:
        raise ValueError("unsupported access-root wrapper")
    scales = {item["name"]: item["scale"] for item in manifest["datasets"]}
    tools.write_once(output/"protocol.json", {
        "schema": "af_choice_study_v1", "started_at": tools.now(), "manifest": str(manifest_path),
        "manifest_sha256": manifest_digest, "sources": identities, "harness": harness,
        "queries": [query.query_id for query in queries], "policies": [policy.config_id for policy in policies],
        "variants": list(VARIANTS), "warmup": args.warmup, "measured": args.measured,
        "require_same_selected_sql": args.require_same_selected_sql,
        "required_new_execution_profile": args.require_new_execution_profile,
        "schedule": "casewise_rotating_old_new_order_continues_across_explicit_warmup_and_measured",
        "fresh_process": "one independent worker subprocess per pilot/variant/round; no cProfile/call-count instrumentation",
        "correctness_gate": "all declared pilot SQL full-JSONB-multiset checks precede every warmup/measured choice",
        "identity_policy": "retain raw worker then fail closed on repeat SQL/template/executable-semantics drift",
        "primary_choice_scope": "catalog_receipt_wall_ms + selection_wall_ms, separate nested observations from actual worker",
        "worker_wall_scope": "actual complete worker request including process startup, source hashing, imports, ranker loading, spec generation and serialization",
        "worker_residual_scope": "worker wall minus receipt/selection; mixed harness and uninstrumented work, not a product-overhead estimate",
        "harness_excluded_from_choice": ["process startup", "source/manifest/statistics identity probes", "global correctness", "data/artifact setup"],
        "artifact_setup": "all unique recipes and final VACUUM ANALYZE before pilot; no builds or ANALYZE inside rounds",
        "rls_configuration": "restore active case policy outside each case's round block; no mutation inside paired rounds",
        "diagnostics": "none in primary campaign; any cProfile study must be separate",
        "statistical_scope": "per-case measured medians/paired-round raw calls; no confidence interval or numerical acceptance threshold is imposed by this driver",
        "baseline_scope": "actual previous AF source; no ordinary comparator implementation is changed",
    })
    context = postgres.temporary_cluster(database=args.database) if args.host is None else nullcontext(
        postgres.PostgresEnv(args.host, args.port, args.user, args.database))
    with context as pg_env:
        setup_started = time.perf_counter()
        version = e3._prepare_database(root, pg_env, tpch_scale=scales.get("tpch", ""), job_scale=scales.get("job", ""))
        tools.write_once(output/"database.json", {"postgres_version": version, "pg_env": asdict(pg_env),
            "data_scales": scales, "setup_wall_ms": (time.perf_counter()-setup_started)*1000})
        artifact_started = time.perf_counter()
        artifacts = tools.prepare_artifacts(e3, postgres, queries, policies, pg_env)
        tools.write_once(output/"shared_artifacts.json", artifacts)
        tools.write_once(output/"artifact_preparation.json", {
            "wall_ms_including_final_VACUUM_ANALYZE": (time.perf_counter()-artifact_started)*1000,
            "sum_recorded_build_ms": sum(item["artifact_build_ms"] for item in artifacts.values()),
            "scope": "one shared preparation before pilot, separate from every choice call",
        })
        frozen_stats = tools.statistics_identity(postgres, pg_env)
        tools.write_once(output/"statistics_before_selection.json", frozen_stats)

        def check_frozen() -> None:
            if (tools.source_identity(source) != identities["af-new"]
                or tools.source_identity(baseline) != identities["af-old"]
                or tools.digest_bytes(manifest_path.read_bytes()) != manifest_digest
                or harness_identity(tools) != harness):
                raise RuntimeError("choice source/manifest/harness changed; campaign is not promotable")
            if tools.statistics_identity(postgres, pg_env) != frozen_stats:
                raise RuntimeError("planner statistics changed; choice campaign is not promotable")

        by_query = {query.query_id: query for query in queries}
        by_policy = {policy.config_id: policy for policy in policies}

        def restore(cell: Mapping[str, Any]) -> None:
            check_frozen()
            e3._configure_native_rls(by_query[cell["query_id"]], by_policy[cell["policy_id"]], pg_env)
            check_frozen()

        def choose(cell: Mapping[str, Any], variant: str) -> Mapping[str, Any]:
            request = {"project_root": str(root), "manifest": str(manifest_path),
                "query_id": cell["query_id"], "policy_id": cell["policy_id"], "stats": cell["stats"],
                "pg_env": asdict(pg_env), "access_root_materialized": wrapper == "materialized",
                "variant": variant, "collect_fixed": False,
                "required_execution_profile": args.require_new_execution_profile if variant == "af-new" else None}
            return tools.run_worker(baseline if variant == "af-old" else source, request, timeout_s=args.worker_timeout)

        cells = []
        for query in queries:
            for policy in policies:
                cell = {"case_id": query.query_id+"__"+policy.config_id,
                        "query_id": query.query_id, "policy_id": policy.config_id}
                restore(cell)
                started = time.perf_counter()
                artifact = artifacts[e3._artifact_id(query, policy)]
                protected = e3._protected_count(query, pg_env)
                local = int(postgres.run_psql_command(
                    f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} WHERE {e3._query_local_predicate(query)}", pg_env))
                authorized = int(postgres.run_psql_command(
                    f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} WHERE {e3._policy_predicate(query, policy)}", pg_env))
                cell["stats"] = {"protected_rows": protected, "query_local_rows": local,
                    "authorized_rows": artifact["artifact_rows"] or authorized,
                    "keyed_artifact_rows": artifact["keyed_artifact_rows"],
                    "artifact_build_ms": artifact["artifact_build_ms"],
                    "input_collection_wall_ms": (time.perf_counter()-started)*1000}
                pilot = {}
                order = VARIANTS[len(cells) % 2:] + VARIANTS[:len(cells) % 2]
                for order_index, variant in enumerate(order):
                    print("pilot " + cell["case_id"] + " " + variant, flush=True)
                    check_frozen()
                    worker = dict(choose(cell, variant))
                    tools.write_once(output/"pilot"/cell["case_id"]/(variant+".json"), {
                        "phase": "pilot_not_warmup_or_primary", "order_index": order_index,
                        "statistics_digest": frozen_stats["digest"], "stats": cell["stats"], "worker": worker})
                    validate_worker(worker, variant=variant, cell=cell, identity=identities[variant],
                        manifest_digest=manifest_digest, required_profile=args.require_new_execution_profile if variant == "af-new" else None,
                        tools=tools)
                    check_frozen()
                    pilot[variant] = worker
                cell.update(pilot=pilot, reference=pilot["af-old"]["reference"],
                    modes=[{"mode": variant, "spec": pilot[variant]["spec"], "selection": pilot[variant]["selection"],
                            "source_digest": identities[variant]["digest"],
                            "worker_request_wall_ms": pilot[variant]["worker_request_wall_ms"]}
                           for variant in VARIANTS])
                tools.write_once(output/"prepared"/(cell["case_id"]+".json"), cell)
                cells.append(cell)
        # Reuse the established all-cases-before-timing multiset gate. Its
        # zero-repetition summary is intentionally not a choice measurement.
        print("full-bag correctness for all " + str(len(cells)) + " declared cases", flush=True)
        tools.evaluate_cells(cells, output_dir=output, warmup=0, measured=0,
            canonicalize=lambda payload: asdict(preview._canonicalize_live(tools._spec_from_dict(preview, payload), pg_env)),
            measure=lambda _payload: (_ for _ in ()).throw(RuntimeError("unexpected query timing")),
            diagnostic=None, restore_cell=restore, correctness_only=True)
        for cell in cells:
            cell["full_bag_gate_passed"] = True
        tools.write_once(output/"correctness_complete.json", {"status": "pass", "at": tools.now(),
            "declared_cases": len(cells), "case_variant_results": len(cells)*2,
            "method": "full_row_jsonb_multiset_equality", "pilot_only_not_choice_timing": True})
        print("full-bag gate passed; begin explicitly declared choice rounds", flush=True)
        result = sample_choices(cells, output_dir=output, warmup=args.warmup, measured=args.measured,
            choose=choose, restore_cell=restore, check_frozen=check_frozen, tools=tools,
            identities=identities, manifest_digest=manifest_digest, statistics_digest=frozen_stats["digest"],
            require_same_selected_sql=args.require_same_selected_sql,
            required_new_profile=args.require_new_execution_profile)
        check_frozen()
        tools.write_once(output/"statistics_after_sampling.json", tools.statistics_identity(postgres, pg_env))
        for name in ("summary", "comparisons"):
            with (output/(name+".csv")).open("x", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(result[name][0]) if result[name] else [])
                writer.writeheader()
                writer.writerows(result[name])
        terminal = {"schema": "af_choice_study_result_v1", "status": "completed", "finished_at": tools.now(),
                    "cells": len(cells), "measured_worker_calls": len(cells)*2*args.measured,
                    "warmup_worker_calls": len(cells)*2*args.warmup, "pilot_worker_calls": len(cells)*2,
                    "harness": harness, **result}
        tools.write_once(output/"summary.json", terminal)
        return terminal


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--baseline-source", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--query", action="append")
    parser.add_argument("--policy", action="append")
    parser.add_argument("--warmup", type=int, required=True)
    parser.add_argument("--measured", type=int, required=True)
    parser.add_argument("--require-same-selected-sql", action="store_true")
    parser.add_argument("--require-new-execution-profile", choices=("trusted_explicit",))
    parser.add_argument("--worker-timeout", type=float, default=1800)
    parser.add_argument("--host")
    parser.add_argument("--port", type=int, default=5432)
    parser.add_argument("--user", default="postgres")
    parser.add_argument("--database", default="caprls_af_choice")
    args = parser.parse_args(argv)
    existed = Path(args.output_dir).exists()
    try:
        result = run_study(args)
        print(json.dumps({key: value for key, value in result.items() if key not in {"summary", "comparisons"}}))
        return 0
    except Exception as exc:
        output = Path(args.output_dir)
        if not existed and output.is_dir() and not (output/"failure.json").exists():
            tools = load_study_tools()
            tools.write_once(output/"failure.json", {"status": "failed", "at": tools.now(),
                "error": str(exc), "traceback": traceback.format_exc()})
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    if __package__:
        # -m initially imports the launcher package from the invoking tree.
        # Start a clean stdlib script before activating a different snapshot.
        import os
        os.execv(sys.executable, [sys.executable, "-B", str(Path(__file__).resolve()), *sys.argv[1:]])
    raise SystemExit(main())
