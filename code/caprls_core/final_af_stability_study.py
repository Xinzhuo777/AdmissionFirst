"""Rebuild-and-select observations for the one final AF implementation.

This reproduces the existing eleven membership queries over ten successive
artifact rebuild/ANALYZE rounds. It does not time query execution or compare AF
versions. Selection uses the same isolated trusted-profile worker as the final
E3 timing study; the algorithm source remains frozen.
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import nullcontext
from dataclasses import asdict
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import traceback
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
POLICY_ID = "group_acl_expensive"
DEFAULT_MANIFEST = "manifests/experiments/e3_standard_sf1_rawpg.yaml"
DEFAULT_SOURCE = "."
PROTECTED = (
    "reference-manuscript.tex", "reference-manuscript.pdf", "main.tex", "main.pdf",
    "supplement.tex", "supplement.pdf", "submission-review-appendix/review_appendix.tex",
    "AGENTS.md", "reference/notes.md",
)


def load_driver() -> Any:
    # Load experiment orchestration without claiming it is algorithm source.
    path = Path(__file__).with_name("final_af_e3_study.py")
    spec = importlib.util.spec_from_file_location("_final_af_e3_stability_driver", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("final E3 experiment driver is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def rotate_queries(queries: Sequence[Any], round_index: int) -> list[Any]:
    if round_index < 1:
        raise ValueError("round indices start at one")
    ordered = list(queries)
    offset = (round_index-1) % len(ordered) if ordered else 0
    return ordered[offset:] + ordered[:offset]


def protected_identity(root: Path) -> dict[str, str]:
    return {name: hashlib.sha256((root/name).read_bytes()).hexdigest()
            for name in PROTECTED if (root/name).is_file()}


def artifact_state(postgres: Any, pg_env: Any, driver: Any) -> dict[str, Any]:
    raw = postgres.run_psql_command("""
SELECT coalesce(json_agg(json_build_object(
  'relation',c.relname,'relpages',c.relpages,'reltuples',c.reltuples,
  'relation_size_bytes',pg_relation_size(c.oid),
  'n_live_tup',s.n_live_tup,'n_dead_tup',s.n_dead_tup) ORDER BY c.relname),'[]'::json)::text
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
LEFT JOIN pg_catalog.pg_stat_user_tables s ON s.relid=c.oid
WHERE n.nspname='public' AND c.relname IN ('auth_idx','auth_idx_keyed') AND c.relkind='r'
""", pg_env)
    relations = json.loads(raw)
    return {"relations": relations, "fingerprint": driver.digest_json(relations)}


def run_round(*, driver: Any, e3: Any, postgres: Any, root: Path,
              source: Path, source_identity: Mapping[str, Any], manifest: Path,
              manifest_sha256: str, query: Any, policy: Any, pg_env: Any,
              round_index: int, position: int, access_root_materialized: bool,
              worker_timeout: float,
              access_root_materialized_by_template: Mapping[str, bool] | None = None) -> dict[str, Any]:
    layouts = driver.validate_access_root_materialized_by_template(access_root_materialized_by_template)
    before = artifact_state(postgres, pg_env, driver)
    predicate = e3._policy_predicate(query, policy)
    build_ms, artifact_rows, keyed_rows = e3._build_artifact(query, policy, predicate, pg_env)
    # _build_artifact finishes the existing rebuild transaction and ANALYZE.
    e3._configure_native_rls(query, policy, pg_env)
    started = time.perf_counter()
    protected = e3._protected_count(query, pg_env)
    local = int(postgres.run_psql_command(
        f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} "
        f"WHERE {e3._query_local_predicate(query)}", pg_env))
    authorized = int(postgres.run_psql_command(
        f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} WHERE {predicate}", pg_env))
    stats = {"protected_rows": protected, "query_local_rows": local,
             "authorized_rows": artifact_rows or authorized,
             "keyed_artifact_rows": keyed_rows, "artifact_build_ms": build_ms,
             "input_collection_wall_ms": (time.perf_counter()-started)*1000}
    statistics_before = driver.statistics_identity(postgres, pg_env)
    request = {"project_root": str(root), "manifest": str(manifest),
               "query_id": query.query_id, "policy_id": policy.config_id,
               "stats": stats, "pg_env": asdict(pg_env), "variant": "af",
               "worker_kind": "af", "required_execution_profile": "trusted_explicit",
               "access_root_materialized": access_root_materialized,
               "access_root_materialized_by_template": layouts}
    worker = driver.run_worker(source, request, timeout_s=worker_timeout)
    if worker["source_identity"] != source_identity:
        raise RuntimeError("AF source changed during rebuild campaign")
    if worker["manifest_sha256"] != manifest_sha256:
        raise RuntimeError("manifest changed during rebuild campaign")
    driver.validate_af_bound_spec(worker)
    selection = worker["selection"]
    if selection.get("execution_profile") != "trusted_explicit":
        raise RuntimeError("rebuild selection did not use final AF trusted execution profile")
    if selection.get("access_root_materialized_by_template", {}) != layouts:
        raise RuntimeError("worker per-template layout record differs from the resolved policy")
    template = selection["selected_template_id"]
    expected_materialized = layouts.get(template, access_root_materialized)
    wrapper = re.match(r"\AWITH caprls_access_root AS (NOT )?MATERIALIZED \(",
                       selection["bound_runner"]["runner_sql"])
    if wrapper is None or (wrapper.group(1) is None) != expected_materialized:
        raise RuntimeError("selected bound access-root wrapper differs from resolved layout policy")
    statistics_after = driver.statistics_identity(postgres, pg_env)
    if statistics_before != statistics_after:
        raise RuntimeError("statistics changed within one prospective selection")
    return {"schema": "final_af_stability_round_v1", "status": "pass",
            "recorded_at": driver.now(), "round": round_index, "position": position,
            "query_id": query.query_id, "policy_id": policy.config_id,
            "selected_template_id": selection["selected_template_id"],
            "selected_plan_id": selection["selected_plan_id"],
            "base_access_root_materialized": access_root_materialized,
            "access_root_materialized_by_template": layouts,
            "actual_access_root_materialized": expected_materialized,
            "bound_runner": selection["bound_runner"],
            "prospective_total_cost": selection["prospective_total_cost"],
            "candidate_cost_vector": selection.get("candidate_cost_vector"),
            "candidate_cost_vector_available": "candidate_cost_vector" in selection,
            "execution_profile": selection["execution_profile"],
            "selection_wall_ms": selection["selection_wall_ms"],
            "catalog_receipt_wall_ms": selection["catalog_receipt_wall_ms"],
            "selection_breakdown": selection.get("selection_breakdown"),
            "stats": stats, "statistics_before": statistics_before,
            "statistics_after": statistics_after, "artifact_before_rebuild": before,
            "artifact_after_selection": artifact_state(postgres, pg_env, driver),
            "worker": worker, "query_latency_measured": False}


def summarize(queries: Sequence[Any], records: Sequence[Mapping[str, Any]],
              failures: Sequence[Mapping[str, Any]], rounds: int) -> dict[str, Any]:
    cells = []
    for query in queries:
        observed = [row for row in records if row["query_id"] == query.query_id]
        failed = [row for row in failures if row["query_id"] == query.query_id]
        counts = Counter(row["selected_template_id"] for row in observed)
        cells.append({"query_id": query.query_id, "policy_id": POLICY_ID,
                      "selected_template_counts": dict(sorted(counts.items())),
                      "completed_rounds": len(observed), "declared_rounds": rounds,
                      "failed_rounds": [{"round": row["round"], "error": row["error"]} for row in failed],
                      "switches_template": len(counts) > 1,
                      "selection_frequencies_are_ordered_observations_not_probabilities": True})
    expected = len(queries)*rounds
    return {"schema": "final_af_stability_summary_v1",
            "status": "pass" if len(records) == expected and not failures else "incomplete",
            "expected_observations": expected, "completed_observations": len(records),
            "failed_observations": len(failures), "cells": cells,
            "query_latency_measured": False,
            "scope": "successive rebuild-and-ANALYZE states with deterministic query-order rotation"}


def run_study(args: argparse.Namespace) -> dict[str, Any]:
    driver = load_driver()
    root = Path(args.root).resolve()
    source = Path(args.source_root)
    source = (root/source).resolve() if not source.is_absolute() else source.resolve()
    manifest = Path(args.manifest)
    manifest = (root/manifest).resolve() if not manifest.is_absolute() else manifest.resolve()
    output = Path(args.output_dir).resolve()
    if args.rounds < 1:
        raise ValueError("rounds must be positive")
    allowed = (root/"AF-wiki/raw/experiments", root/"AF-wiki/raw/attempts", root/"results/raw")
    if not any(output != path and output.is_relative_to(path) for path in allowed):
        raise ValueError("output must be a fresh experiment directory under retained raw artifacts")
    output.mkdir(parents=True, exist_ok=False)
    identity = driver.source_identity(source)
    protected = protected_identity(root)
    driver_hash = driver.digest_bytes(Path(driver.__file__).read_bytes())
    self_hash = driver.digest_bytes(Path(__file__).read_bytes())
    (output/"driver-source").mkdir()
    for path in (Path(__file__), Path(driver.__file__)):
        with (output/"driver-source"/path.name).open("xb") as handle:
            handle.write(path.read_bytes())
    with (output/"input-manifest.yaml").open("xb") as handle:
        handle.write(manifest.read_bytes())
    e3, _preview, postgres = driver.activate_source(source)
    document = e3._load_manifest(manifest)
    e3._validate_manifest(manifest, document)
    e3.require_e3_manifest_data(root, manifest, document)
    all_queries = e3._queries_for_manifest(manifest, document)
    requested = args.query
    queries = [q for q in all_queries if not requested or q.query_id in requested]
    if requested and (len(requested) != len(set(requested)) or set(requested) != {q.query_id for q in queries}):
        raise ValueError("unknown or duplicate requested query")
    if not queries or (not requested and len(queries) != 11):
        raise ValueError("default stability workload must contain eleven queries")
    policies = [p for p in e3._policies_for_manifest(manifest, document) if p.config_id == POLICY_ID]
    if len(policies) != 1:
        raise ValueError("membership policy is absent or ambiguous")
    policy = policies[0]
    wrapper_override = getattr(args, "access_root_wrapper", None)
    wrapper = wrapper_override or (document.get("scale_check") or {}).get("bound_runner_wrapper", "materialized")
    if wrapper not in {"materialized", "not_materialized_single_reference"}:
        raise ValueError("unsupported access-root wrapper")
    layout_override = driver.template_materialization_override(getattr(args, "materialize_template", None))
    layouts = driver.resolve_access_root_materialized_by_template(source, layout_override)
    manifest_hash = driver.digest_bytes(manifest.read_bytes())
    protocol = {"schema": "final_af_stability_protocol_v1", "started_at": driver.now(),
                "source": identity, "manifest": str(manifest), "manifest_sha256": manifest_hash,
                "driver_sha256": self_hash, "e3_worker_driver_sha256": driver_hash,
                "queries": [q.query_id for q in queries], "policy_id": POLICY_ID,
                "rounds": args.rounds, "expected_observations": len(queries)*args.rounds,
                "query_order": "rotate manifest query order by round_index-1",
                "execution_profile": "trusted_explicit", "methods": ["af"],
                "access_root_wrapper": wrapper,
                "access_root_wrapper_override": wrapper_override,
                "access_root_materialized_by_template": layouts,
                "access_root_materialized_by_template_override": layout_override,
                "query_latency_measured": False, "protected_before": protected,
                "rebuild": "existing _build_artifact clear/build transaction plus ANALYZE, no vacuum between rounds",
                "interpretation": "ordered successive artifact states; no IID probability or confidence interval"}
    driver.write_once(output/"protocol.json", protocol)
    context = (postgres.temporary_cluster(database=args.database) if args.host is None else
               nullcontext(postgres.PostgresEnv(args.host, args.port, args.user, args.database)))
    records, failures = [], []
    with context as pg_env:
        setup_started = time.perf_counter()
        scales = {item["name"]: item["scale"] for item in document["datasets"]}
        version = e3._prepare_database(root, pg_env, tpch_scale=scales.get("tpch", ""),
                                       job_scale=scales.get("job", ""))
        autovacuum = postgres.run_psql_command("SHOW autovacuum", pg_env).strip().lower()
        if autovacuum != "off":
            raise RuntimeError("successive rebuild experiment requires autovacuum off")
        driver.write_once(output/"database.json", {"pg_env": asdict(pg_env), "postgres_version": version,
                          "setup_wall_ms": (time.perf_counter()-setup_started)*1000,
                          "autovacuum": autovacuum, "data_scales": scales,
                          "settings": postgres.run_psql_command("""
SELECT json_build_object('shared_buffers',current_setting('shared_buffers'),
  'work_mem',current_setting('work_mem'),'autovacuum',current_setting('autovacuum'),
  'jit',current_setting('jit'),'max_parallel_workers_per_gather',current_setting('max_parallel_workers_per_gather'),
  'plan_cache_mode',current_setting('plan_cache_mode'))::text
""", pg_env),
                          "initial_artifact_state": artifact_state(postgres, pg_env, driver)})
        for round_index in range(1, args.rounds+1):
            for position, query in enumerate(rotate_queries(queries, round_index), 1):
                try:
                    record = run_round(driver=driver, e3=e3, postgres=postgres, root=root,
                        source=source, source_identity=identity, manifest=manifest,
                        manifest_sha256=manifest_hash, query=query, policy=policy, pg_env=pg_env,
                        round_index=round_index, position=position,
                        access_root_materialized=wrapper == "materialized", worker_timeout=args.worker_timeout,
                        access_root_materialized_by_template=layouts)
                    records.append(record)
                    driver.write_once(output/"rounds"/f"{query.query_id}__round{round_index:02d}.json", record)
                except Exception as exc:
                    failure = {"query_id": query.query_id, "policy_id": POLICY_ID,
                               "round": round_index, "position": position, "error": str(exc),
                               "traceback": traceback.format_exc(), "recorded_at": driver.now()}
                    failures.append(failure)
                    driver.write_once(output/"failures"/f"{query.query_id}__round{round_index:02d}.json", failure)
                print(json.dumps({"stage": "final-af-stability", "query": query.query_id,
                                  "round": round_index, "completed": len(records), "failures": len(failures)}), flush=True)
                if driver.source_identity(source) != identity or protected_identity(root) != protected:
                    raise RuntimeError("source or protected original changed during stability campaign")
                if driver.digest_bytes(Path(driver.__file__).read_bytes()) != driver_hash:
                    raise RuntimeError("E3 worker driver changed during stability campaign")
        autovacuum_after = postgres.run_psql_command("SHOW autovacuum", pg_env).strip().lower()
        if autovacuum_after != autovacuum:
            raise RuntimeError("autovacuum setting changed during stability campaign")
        final_artifact = artifact_state(postgres, pg_env, driver)
    if (driver.source_identity(source) != identity or protected_identity(root) != protected or
        driver.digest_bytes(Path(driver.__file__).read_bytes()) != driver_hash or
        driver.digest_bytes(Path(__file__).read_bytes()) != self_hash):
        raise RuntimeError("source, experiment driver or protected original changed before completion")
    result = {**summarize(queries, records, failures, args.rounds), "completed_at": driver.now(),
              "source_unchanged": True, "protected_unchanged": True,
              "final_artifact_state": final_artifact}
    driver.write_once(output/"summary.json", result)
    driver.write_once(output/"completion.json", result)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # A script entry leaves the caprls_core package unimported until the frozen
    # source is activated. Module invocation re-execs that clean script entry.
    if __package__:
        return subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), *argv],
                              cwd=ROOT, env=os.environ.copy()).returncode
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--source-root", default=DEFAULT_SOURCE)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--query", action="append")
    parser.add_argument("--worker-timeout", type=float, default=1800)
    parser.add_argument("--access-root-wrapper", choices=("materialized", "not_materialized_single_reference"),
                        help="AF-only bound runner composition; default uses the manifest wrapper, with admission and exact SQL binding retained")
    parser.add_argument("--materialize-template", action="append",
                        help="repeat to replace the source-default per-template handoff map with these materialized template IDs")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int, default=5432)
    parser.add_argument("--user", default="postgres")
    parser.add_argument("--database", default="caprls_final_af_stability")
    args = parser.parse_args(argv)
    existed = Path(args.output_dir).exists()
    try:
        result = run_study(args)
        print(json.dumps(result))
        return 0 if result["status"] == "pass" else 1
    except Exception as exc:
        if not existed and Path(args.output_dir).is_dir():
            driver = load_driver()
            driver.write_once(Path(args.output_dir)/"failure.json", {
                "status": "failed", "error": str(exc), "at": driver.now(),
                "traceback": traceback.format_exc()})
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
