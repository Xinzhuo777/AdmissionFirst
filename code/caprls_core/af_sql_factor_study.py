"""Exploratory, paired SQL-factor study using admitted production AF runners.

Four internal AF ablations cross before/current source with materialized/inline
single-reference access roots. Ordinary IndexPriority comes only from its frozen
baseline tree. This screen does not establish complete-workload acceptance.
"""
from __future__ import annotations

import argparse
from contextlib import nullcontext
import csv
from dataclasses import asdict
import json
from pathlib import Path
import re
import sys
import time
import traceback
from typing import Any, Mapping, Sequence

from caprls_core import e3_main as e3
from caprls_core import e3_sigmod_preview as preview
from caprls_core import final_af_e3_study as study
from caprls_core import postgres_runner as postgres


FACTORS = (
    ("af-before-mat", "before", True),
    ("af-before-inline", "before", False),
    ("af-local-mat", "current", True),
    ("af-local-inline", "current", False),
)
MODES = tuple(item[0] for item in FACTORS) + ("local-greedy",)


def prepare_workers(*, sources: Mapping[str, Path], identities: Mapping[str, Any],
                    request: Mapping[str, Any], manifest_digest: str,
                    output: Path, timeout_s: float, check_statistics: Any,
                    run_worker: Any = study.run_worker) -> tuple[list[dict[str, Any]], Mapping[str, Any]]:
    """Choose each factor prospectively; never edit a returned SQL string."""
    entries = []
    for mode, source_key, materialized in FACTORS:
        check_statistics()
        worker = run_worker(sources[source_key], {
            **request, "variant": "af", "worker_kind": "af",
            "access_root_materialized": materialized,
            "required_execution_profile": "trusted_explicit",
        }, timeout_s=timeout_s)
        if (worker["source_identity"] != identities[source_key]
                or worker["manifest_sha256"] != manifest_digest):
            raise RuntimeError("AF worker source/manifest changed: " + mode)
        study.validate_af_bound_spec(worker)
        actual_inline = bool(re.match(
            r"\A\s*WITH\s+caprls_access_root\s+AS\s+NOT\s+MATERIALIZED\b",
            worker["spec"]["sql"], re.IGNORECASE))
        if actual_inline == materialized:
            raise RuntimeError("AF worker bound wrapper disagrees with requested factor: " + mode)
        check_statistics()
        study.write_once(output/(mode+".json"), worker)
        entries.append({"mode": mode, "spec": worker["spec"],
                        "selection": worker["selection"],
                        "execution_source_key": source_key,
                        "source_digest": identities[source_key]["digest"],
                        "worker_request_wall_ms": worker["worker_request_wall_ms"]})
    check_statistics()
    fixed = run_worker(sources["baseline"], {
        **request, "variant": "af", "worker_kind": "fixed",
        "fixed_modes": ["local-greedy"],
    }, timeout_s=timeout_s)
    if (fixed["source_identity"] != identities["baseline"]
            or fixed["manifest_sha256"] != manifest_digest):
        raise RuntimeError("ordinary baseline source/manifest changed")
    check_statistics()
    study.write_once(output/"fixed.json", fixed)
    comparator = next(item for item in fixed["fixed_modes"] if item["mode"] == "local-greedy")
    if comparator["spec"] is None:
        raise ValueError("ordinary IndexPriority unavailable: " + comparator["unavailable_reason"])
    entries.append({**comparator, "source_digest": identities["baseline"]["digest"],
                    "execution_source_key": "baseline"})
    return entries, fixed["reference"]


def execution_routes(cells: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """Route complete, unchanged specs to a matching implementation tree.

    An exactly identical complete spec can be shared by two trees. The first
    declared source is then used, with every compatible source retained in the
    route record. No profile, contract or SQL field is rewritten to make a
    source accept another source's spec.
    """
    routes: dict[str, dict[str, Any]] = {}
    for cell in cells:
        entries = [{"spec": cell["reference"], "execution_source_key": "baseline"},
                   *cell["modes"]]
        for entry in entries:
            spec = entry["spec"]
            source_key = entry["execution_source_key"]
            key = study.digest_json(spec)
            if key not in routes:
                routes[key] = {"spec": spec, "source_key": source_key,
                               "compatible_source_keys": [source_key]}
            elif routes[key]["spec"] != spec:
                raise ValueError("complete execution spec digest collision")
            elif source_key not in routes[key]["compatible_source_keys"]:
                routes[key]["compatible_source_keys"].append(source_key)
    return routes


class SourceExecutor:
    def __init__(self, *, routes: Mapping[str, Any], sources: Mapping[str, Path],
                 identities: Mapping[str, Any], pg_env: Mapping[str, Any],
                 timeout_s: float, run_worker: Any = study.run_worker):
        self.routes, self.sources, self.identities = routes, sources, identities
        self.pg_env, self.timeout_s, self.run_worker = pg_env, timeout_s, run_worker

    def call(self, operation: str, spec: Mapping[str, Any]) -> Mapping[str, Any]:
        key = study.digest_json(spec)
        route = self.routes.get(key)
        if route is None or route["spec"] != spec:
            raise ValueError("execution spec has no exact source route")
        source_key = route["source_key"]
        worker = self.run_worker(self.sources[source_key], {
            "operation": operation, "spec": spec, "pg_env": self.pg_env,
        }, timeout_s=self.timeout_s)
        if worker.get("source_identity") != self.identities[source_key]:
            raise ValueError("execution worker source identity changed")
        if worker.get("operation") != operation:
            raise ValueError("execution worker operation mismatch")
        result = worker.get("result")
        if not isinstance(result, Mapping):
            raise ValueError("execution worker result is malformed")
        if operation == "measure":
            result = {**result, "execution_worker_wall_ms_infrastructure_only": worker["worker_request_wall_ms"],
                      "execution_source_digest": self.identities[source_key]["digest"],
                      "execution_spec_digest": key}
        return result


def adjust_summary(rows: list[dict[str, Any]], cells: Sequence[Mapping[str, Any]]) -> None:
    """Account for shared AF inputs under internal ablation labels."""
    stats = {cell["case_id"]: cell["stats"] for cell in cells}
    for row in rows:
        if row["mode"] not in MODES[:-1]:
            continue
        data = stats[row["case_id"]]
        input_ms = data["input_collection_wall_ms"]
        row["input_collection_wall_ms"] = input_ms
        request = row["median_end_to_end_ms_including_validation_and_client"]
        first = None if request is None else request + input_ms + (
            row["selection_wall_ms"] or 0) + (row["catalog_receipt_wall_ms"] or 0)
        row["first_use_estimate_ms_excluding_artifact_build"] = first
        row["first_use_estimate_with_artifact_build_ms"] = (
            None if first is None else first + data["artifact_build_ms"])


def run_study(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.root).resolve()
    sources = {"before": Path(args.before_source).resolve(),
               "current": Path(args.source_root or root).resolve(),
               "baseline": Path(args.baseline_source).resolve()}
    identities = {name: study.source_identity(path) for name, path in sources.items()}
    setup_root = Path(e3.__file__).resolve().parent.parent
    setup_identity = study.source_identity(setup_root)
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = root/manifest_path
    manifest_digest = study.digest_bytes(manifest_path.read_bytes())
    manifest = e3._load_manifest(manifest_path)
    e3._validate_manifest(manifest_path, manifest)
    e3.require_e3_manifest_data(root, manifest_path, manifest)
    queries = preview._select_items(e3._queries_for_manifest(manifest_path, manifest), args.query,
                                   key=lambda item: item.query_id, label="query")
    policies = preview._select_items(e3._policies_for_manifest(manifest_path, manifest), args.policy,
                                    key=lambda item: item.config_id, label="policy")
    measured = 0 if args.correctness_only else args.measured
    if measured < 0 or (not args.correctness_only and measured < 1):
        raise ValueError("invalid measured repetitions")
    scales = {item["name"]: item["scale"] for item in manifest["datasets"]}
    study.write_once(output/"protocol.json", {
        "schema": "af_sql_factor_study_v1", "started_at": study.now(),
        "purpose": "exploratory AF-internal factor screen, not complete-workload acceptance",
        "manifest": str(manifest_path), "manifest_sha256": manifest_digest,
        "sources": identities, "setup_source": setup_identity,
        "driver_sha256": study.digest_bytes(Path(__file__).read_bytes()),
        "shared_measurement_driver_sha256": study.digest_bytes(Path(study.__file__).read_bytes()),
        "factors": FACTORS, "modes": MODES,
        "queries": [q.query_id for q in queries], "policies": [p.config_id for p in policies],
        "minimum_measured": measured, "correctness_only": args.correctness_only,
        "primary_metric": "median_postgres_query_execution_ms",
        "primary_scope": "actual admitted bound query Execution Time, TIMING OFF EXPLAIN ANALYZE",
        "schedule": "balanced_available_modes_v1",
        "repetition_policy": "one complete 10-round warmup cycle, measured rounded upward to complete 10-round cycles",
        "balanced_round_order_indices": study.balanced_round_orders(5),
        "baseline_implementation": "ordinary local-greedy from unchanged baseline source",
        "af_execution_profile": "trusted_explicit with exact bound SQL and unchanged validation",
        "execution_dispatch": "script, canonicalize, measure and diagnostic in isolated matching-source workers; complete spec digest routing; first declared source for exactly identical complete specs",
        "statistics_policy": "all artifacts built and VACUUM ANALYZE completed before selection; catalog statistics frozen through sampling",
        "correctness_policy": "all complete result multisets checked against independent baseline reference before any timing",
        "companion_costs": "planning, required validation, client request, prospective choice and shared setup separately retained",
    })
    context = (postgres.temporary_cluster(database=args.database) if args.host is None
               else nullcontext(postgres.PostgresEnv(args.host, args.port, args.user, args.database)))
    with context as pg_env:
        started = time.perf_counter()
        version = e3._prepare_database(root, pg_env, tpch_scale=scales.get("tpch", ""),
                                       job_scale=scales.get("job", ""))
        study.write_once(output/"database.json", {
            "postgres_version": version, "pg_env": asdict(pg_env), "data_scales": scales,
            "setup_wall_ms": (time.perf_counter()-started)*1000,
            "settings": postgres.run_psql_command(
                "SELECT json_build_object('work_mem',current_setting('work_mem'),'shared_buffers',current_setting('shared_buffers'),'autovacuum',current_setting('autovacuum'))::text", pg_env)})
        artifacts = study.prepare_artifacts(e3, postgres, queries, policies, pg_env)
        study.write_once(output/"shared_artifacts.json", artifacts)
        frozen_statistics = study.statistics_identity(postgres, pg_env)
        study.write_once(output/"statistics_before_selection.json", frozen_statistics)

        def check_statistics() -> None:
            if study.statistics_identity(postgres, pg_env) != frozen_statistics:
                raise RuntimeError("catalog statistics changed during factor study")

        cells = []
        for query in queries:
            for policy in policies:
                case_id = query.query_id+"__"+policy.config_id
                print("prepare "+case_id, flush=True)
                started = time.perf_counter()
                protected = e3._protected_count(query, pg_env)
                local = int(postgres.run_psql_command(
                    f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} WHERE {e3._query_local_predicate(query)}", pg_env))
                e3._configure_native_rls(query, policy, pg_env)
                authorized = int(postgres.run_psql_command(
                    f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} WHERE {e3._policy_predicate(query, policy)}", pg_env))
                artifact = artifacts[e3._artifact_id(query, policy)]
                stats = {"protected_rows": protected, "query_local_rows": local,
                         "authorized_rows": artifact["artifact_rows"] or authorized,
                         "keyed_artifact_rows": artifact["keyed_artifact_rows"],
                         "artifact_build_ms": artifact["artifact_build_ms"],
                         "input_collection_wall_ms": (time.perf_counter()-started)*1000}
                request = {"project_root": str(root), "manifest": str(manifest_path),
                           "query_id": query.query_id, "policy_id": policy.config_id,
                           "stats": stats, "pg_env": asdict(pg_env)}
                entries, reference = prepare_workers(
                    sources=sources, identities=identities, request=request,
                    manifest_digest=manifest_digest, output=output/"prepared"/case_id,
                    timeout_s=args.worker_timeout, check_statistics=check_statistics)
                cell = {"case_id": case_id, "query_id": query.query_id, "policy_id": policy.config_id,
                        "dataset_scale": scales[query.workload], "stats": stats,
                        "reference": reference, "reference_source_key": "baseline", "modes": entries}
                study.write_once(output/"prepared"/case_id/"shared.json", cell)
                cells.append(cell)
        routes = execution_routes(cells)
        study.write_once(output/"execution-routes.json", routes)
        executor = SourceExecutor(routes=routes, sources=sources, identities=identities,
                                  pg_env=asdict(pg_env), timeout_s=args.worker_timeout)
        for cell in cells:
            for entry in cell["modes"]:
                path = output/"measurement-scripts"/cell["case_id"]/(entry["mode"]+".sql")
                path.parent.mkdir(parents=True, exist_ok=True)
                generated = executor.call("script", entry["spec"])
                if type(generated.get("script")) is not str:
                    raise ValueError("source script worker returned no script")
                with path.open("x", encoding="utf-8") as handle:
                    handle.write(generated["script"])
        by_query = {q.query_id: q for q in queries}
        by_policy = {p.config_id: p for p in policies}

        def restore(cell: Mapping[str, Any]) -> None:
            check_statistics()
            e3._configure_native_rls(by_query[cell["query_id"]], by_policy[cell["policy_id"]], pg_env)

        def canonicalize(payload: Mapping[str, Any]) -> Mapping[str, Any]:
            return executor.call("canonicalize", payload)

        def measure(payload: Mapping[str, Any]) -> Mapping[str, Any]:
            return executor.call("measure", payload)

        def diagnostic(payload: Mapping[str, Any]) -> Mapping[str, Any]:
            return executor.call("diagnostic", payload)

        summary = study.evaluate_cells(cells, output_dir=output, measured=measured,
            canonicalize=canonicalize, measure=measure, restore_cell=restore,
            diagnostic=None if args.skip_diagnostics or args.correctness_only else diagnostic,
            correctness_only=args.correctness_only)
        adjust_summary(summary, cells)
        for name, path in sources.items():
            if study.source_identity(path) != identities[name]:
                raise RuntimeError("source changed during factor study: "+name)
        if study.source_identity(setup_root) != setup_identity:
            raise RuntimeError("common setup/measurement source changed during factor study")
        if study.digest_bytes(manifest_path.read_bytes()) != manifest_digest:
            raise RuntimeError("manifest changed during factor study")
        final_statistics = study.statistics_identity(postgres, pg_env)
        study.write_once(output/"statistics_after_sampling.json", final_statistics)
        if final_statistics != frozen_statistics:
            raise RuntimeError("catalog statistics changed during factor study")
        with (output/"summary.csv").open("x", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(summary[0]) if summary else [])
            writer.writeheader(); writer.writerows(summary)
        result = {"status": "completed", "finished_at": study.now(), "cells": len(cells),
                  "mode_results": len(summary), "summary": summary}
        study.write_once(output/"summary.json", result)
        return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--source-root")
    parser.add_argument("--before-source", required=True)
    parser.add_argument("--baseline-source", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--query", action="append")
    parser.add_argument("--policy", action="append")
    parser.add_argument("--measured", type=int, default=10)
    parser.add_argument("--correctness-only", action="store_true")
    parser.add_argument("--skip-diagnostics", action="store_true")
    parser.add_argument("--worker-timeout", type=float, default=1800)
    parser.add_argument("--host")
    parser.add_argument("--port", type=int, default=5432)
    parser.add_argument("--user", default="postgres")
    parser.add_argument("--database", default="caprls_final_af_e3")
    args = parser.parse_args(argv)
    existed = Path(args.output_dir).exists()
    try:
        result = run_study(args)
        print(json.dumps({k: v for k, v in result.items() if k != "summary"}))
        return 0
    except Exception as exc:
        if not existed and Path(args.output_dir).is_dir() and not (Path(args.output_dir)/"failure.json").exists():
            study.write_once(Path(args.output_dir)/"failure.json", {
                "status": "failed", "at": study.now(), "error": str(exc), "traceback": traceback.format_exc()})
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
