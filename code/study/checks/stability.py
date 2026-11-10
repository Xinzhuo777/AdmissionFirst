"""External R08 stability interface adapter; importing this file issues no SQL.

The frozen eleven-query/ten-round driver still owns setup, rebuild order,
statistics and source guards, raw records and summary. Only the normal-worker
declaration/effective-layout interface is adapted. Every round additionally
checks one guarded normal body, without a query-latency benchmark.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import importlib.util
import json
from pathlib import Path
import re
import sys
import time
import traceback
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = "."
DEFAULT_MANIFEST = "study/inputs/mixed-input-manifest.yaml"
QUERIES = ("Q3", "Q5", "Q7", "Q10", "Q12", "JOB_1a", "JOB_2a", "JOB_3c", "JOB_6d", "JOB_10a", "JOB_16b")
POLICY = "group_acl_expensive"
ROUNDS = 10


def load_legacy(source: Path) -> Any:
    path = source / "caprls_core/final_af_stability_study.py"
    spec = importlib.util.spec_from_file_location("_stability_r08_frozen_driver", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("frozen stability driver is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def paired_protocol(original: Mapping[str, Any], support: Any) -> dict[str, Any]:
    """Keep the original full grid; resolve layout from the source declaration."""
    if (original.get("rounds") != ROUNDS
            or original.get("expected_observations") != len(QUERIES) * ROUNDS
            or original.get("queries") != list(QUERIES)
            or original.get("policy_id") != POLICY
            or original.get("source") != support.identity
            or original.get("query_latency_measured") is not False
            or original.get("access_root_wrapper") != support.declared["access_root_wrapper"]
            or original.get("access_root_materialized_by_template")
               != support.declared["access_root_materialized_by_template"]
            or original.get("access_root_materialized_by_template_override") is not None):
        raise ValueError("paired stability requires the complete unchanged eleven-by-ten declaration")
    return {
        **original,
        **support.protocol_fields(),
        "access_root_wrapper_override": None,
        "user_access_root_wrapper_override": None,
        "legacy_bridge_access_root_wrapper_argument": support.declared["access_root_wrapper"],
        "access_root_wrapper_resolution": "source_normal_physical_recipe_strategy",
        "normal_body_check_scope": "one extra exact admitted body per round; not query-latency timing or independent result correctness",
        "support_adapter_scope": "external paired interface only; original rebuild/order/statistics/source guards retained",
    }


def run_round(*, support: Any, legacy: Any, driver: Any, e3: Any,
              postgres: Any, root: Path, source: Path,
              source_identity: Mapping[str, Any], manifest: Path,
              manifest_sha256: str, query: Any, policy: Any, pg_env: Any,
              round_index: int, position: int, access_root_materialized: bool,
              worker_timeout: float,
              access_root_materialized_by_template: Mapping[str, bool] | None = None) -> dict[str, Any]:
    """Original rebuild-and-select round with a validated effective-layout gate."""
    support.guard()
    declared_layouts = driver.validate_access_root_materialized_by_template(
        access_root_materialized_by_template)
    if (driver is not support.study or source_identity != support.identity
            or access_root_materialized is not False
            or declared_layouts != support.declared["access_root_materialized_by_template"]
            or policy.config_id != POLICY):
        raise ValueError("paired stability source/default declaration differs")
    before = legacy.artifact_state(postgres, pg_env, driver)
    predicate = e3._policy_predicate(query, policy)
    build_ms, artifact_rows, keyed_rows = e3._build_artifact(query, policy, predicate, pg_env)
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
             "input_collection_wall_ms": (time.perf_counter() - started) * 1000}
    statistics_before = driver.statistics_identity(postgres, pg_env)
    request = {
        "project_root": str(root), "manifest": str(manifest),
        "query_id": query.query_id, "policy_id": policy.config_id,
        "stats": stats, "pg_env": asdict(pg_env), "variant": "af",
        "worker_kind": "af", "required_execution_profile": "trusted_explicit",
        "access_root_materialized": False,
        "access_root_materialized_by_template": declared_layouts,
        "verify_normal_execution": True,
    }
    worker, checked = support.run_worker(request, timeout_s=worker_timeout)
    if worker["source_identity"] != source_identity:
        raise RuntimeError("AF source changed during rebuild campaign")
    if worker["manifest_sha256"] != manifest_sha256:
        raise RuntimeError("manifest changed during rebuild campaign")
    driver.validate_af_bound_spec(worker)
    selection = worker["selection"]
    if (selection.get("execution_profile") != "trusted_explicit"
            or checked["physical_recipe"].get("status") != "verified"
            or checked["normal"].get("normal_execution_verified") is not True
            or checked["effective_base_materialized"] is not False):
        raise RuntimeError("paired stability lacks verified physical/normal evidence")
    effective = driver.validate_access_root_materialized_by_template(
        checked["effective_materialized_by_template"])
    if selection.get("access_root_materialized_by_template") != effective:
        raise RuntimeError("worker effective map differs from its validated physical decision")
    template = selection["selected_template_id"]
    expected_materialized = effective.get(template, False)
    actual_materialized = support.root_materialized(selection["bound_runner"]["runner_sql"])
    if actual_materialized != expected_materialized:
        raise RuntimeError("selected bound access-root wrapper differs from validated effective policy")
    statistics_after = driver.statistics_identity(postgres, pg_env)
    if statistics_before != statistics_after:
        raise RuntimeError("statistics changed within one prospective selection")
    support.guard()
    return {
        "schema": "final_af_stability_round_v1", "status": "pass",
        "recorded_at": driver.now(), "round": round_index, "position": position,
        "query_id": query.query_id, "policy_id": policy.config_id,
        "selected_template_id": template, "selected_plan_id": selection["selected_plan_id"],
        "base_access_root_materialized": False,
        "declared_access_root_materialized_by_template": declared_layouts,
        "access_root_materialized_by_template": effective,
        "actual_access_root_materialized": expected_materialized,
        "bound_runner": selection["bound_runner"],
        "prospective_total_cost": selection["prospective_total_cost"],
        "candidate_cost_vector": selection.get("candidate_cost_vector"),
        "candidate_cost_vector_available": "candidate_cost_vector" in selection,
        "execution_profile": selection["execution_profile"],
        "selection_wall_ms": selection["selection_wall_ms"],
        "catalog_receipt_wall_ms": selection["catalog_receipt_wall_ms"],
        "selection_breakdown": selection.get("selection_breakdown"),
        "physical_recipe_validation": checked["physical_recipe"],
        "normal_entry_validation": checked["normal"],
        "support_r08_validation": checked,
        "normal_body_execution_verified": True,
        "stats": stats, "statistics_before": statistics_before,
        "statistics_after": statistics_after, "artifact_before_rebuild": before,
        "artifact_after_selection": legacy.artifact_state(postgres, pg_env, driver),
        "worker": worker, "query_latency_measured": False,
    }


def run_study(args: argparse.Namespace) -> dict[str, Any]:
    # Import only the stdlib-based adapter support before the frozen original
    # driver activates its issuer. Do not import root caprls_core here.
    from support import PairedSupport

    root = Path(args.root).resolve()
    source = Path(args.source_root)
    source = (root / source).resolve() if not source.is_absolute() else source.resolve()
    manifest = Path(args.manifest)
    manifest = (root / manifest).resolve() if not manifest.is_absolute() else manifest.resolve()
    output = Path(args.output_dir)
    output = (root / output).resolve() if not output.is_absolute() else output.resolve()
    if output.exists():
        raise ValueError("paired stability output must be fresh")
    legacy_path = source / "caprls_core/final_af_stability_study.py"
    support = PairedSupport(root, source, extra_files=(Path(__file__).resolve(), legacy_path, manifest))
    legacy = load_legacy(source)
    driver = support.study
    original_load, original_round, original_write = legacy.load_driver, legacy.run_round, driver.write_once
    records = []
    protocol_written = False

    def write(path, value):
        nonlocal protocol_written
        if Path(path) == output / "protocol.json":
            value = paired_protocol(value, support)
            original_write(path, value)
            support.archive(output, original_write)
            protocol_written = True
        else:
            if Path(path) in (output / "summary.json", output / "completion.json"):
                support.guard()
            original_write(path, value)

    def paired_round(**values):
        record = run_round(support=support, legacy=legacy, **values)
        records.append(record)
        return record

    frozen_args = argparse.Namespace(
        root=str(root), source_root=str(source), manifest=str(manifest), output_dir=str(output),
        rounds=ROUNDS, query=None, worker_timeout=args.worker_timeout,
        access_root_wrapper=support.declared["access_root_wrapper"], materialize_template=None,
        host=None, port=5432, user="postgres", database="caprls_paired_af_stability",
    )
    legacy.load_driver = lambda: driver
    legacy.run_round = paired_round
    driver.write_once = write
    try:
        result = legacy.run_study(frozen_args)
    finally:
        driver.write_once = original_write
        legacy.run_round = original_round
        legacy.load_driver = original_load
    support.guard()
    expected = {(query, round_index) for query in QUERIES for round_index in range(1, ROUNDS + 1)}
    observed = {(record["query_id"], record["round"]) for record in records}
    complete = (protocol_written and result.get("status") == "pass"
                and result.get("expected_observations") == result.get("completed_observations") == 110
                and result.get("failed_observations") == 0 and len(records) == len(observed) == 110
                and observed == expected
                and all(record["normal_body_execution_verified"] is True
                        and record["normal_entry_validation"]["normal_execution_verified"] is True
                        and record["physical_recipe_validation"]["status"] == "verified"
                        for record in records))
    original_write(output / "paired-support-completion.json", {
        "schema": "stability_r02_support_completion_v1",
        "status": "pass" if complete else "incomplete",
        "expected_observations": 110, "observed_records": len(records),
        "normal_entry_checks_verified": sum(record["normal_entry_validation"]["normal_execution_verified"] for record in records),
        "physical_recipe_checks_verified": sum(record["physical_recipe_validation"]["status"] == "verified" for record in records),
        "complete_110_grid": complete, "source_and_adapter_inputs_unchanged": True,
        "query_latency_measured": False,
        "scope": "existing eleven-by-ten stability grid with paired normal/effective-layout interface checks",
    })
    if not complete:
        raise RuntimeError("paired stability did not complete its full 110-observation support grid")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--source-root", default=DEFAULT_SOURCE)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--worker-timeout", type=float, default=1800)
    args = parser.parse_args(argv)
    output = Path(args.output_dir)
    output = (Path(args.root).resolve() / output).resolve() if not output.is_absolute() else output.resolve()
    existed = output.exists()
    try:
        result = run_study(args)
        print(json.dumps({"status": result["status"], "completed_observations": result["completed_observations"],
                          "query_latency_measured": False}), flush=True)
        return 0
    except Exception as exc:
        if not existed and output.is_dir():
            with (output / "paired-support-failure.json").open("x") as handle:
                json.dump({"status": "failed", "error": str(exc), "traceback": traceback.format_exc()}, handle, indent=2)
                handle.write("\n")
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
