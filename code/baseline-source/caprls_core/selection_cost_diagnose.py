"""Selection-only E3 cost diagnosis; never rerun or replace query latency.

Run ``python -m caprls_core.selection_cost_diagnose --dry-run`` to inspect the
six declared cells without database access.  A real run creates a fresh private
16 MB temporary cluster, uses the original selection callable and SQL settings,
and refuses to overwrite an existing result directory.
"""

from __future__ import annotations

import argparse
from contextlib import nullcontext
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
from typing import Any, Mapping


ACTIVITY = "SELECTION_COST_BREAKDOWN_20261010_V1"
QUERIES = ("Q10", "JOB_10a")
POLICIES = (
    "cheap_tenant_sargable", "group_acl_expensive", "hybrid_selective_key",
)
ARMS = ("plain_sparse", "legacy_profile_sparse")
WARMUP = 5
MEASURED = 30
MANIFEST = "manifests/experiments/e3_standard_sf1_rawpg.yaml"
LEGACY_OBSERVER = (
    "output/section65_original_protocol_execution_2026-10-06/"
    "run_original_protocol.py"
)
PROTECTED = (
    "main.tex", "reference-manuscript.tex", "main.pdf", "reference-manuscript.pdf",
    "results/raw/ORIGINAL_TABLE3_COST_NOISE_20261006_V1/choice_costs.jsonl",
    "output/section65_original_protocol_execution_2026-10-06/"
    "independent_analysis/adjudicated_reduction_v1/analysis.json",
)


def utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_once(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, default=str)
        handle.write("\n")


def append_record(handle: Any, record: Mapping[str, Any]) -> None:
    handle.write(json.dumps(dict(record), default=str) + "\n")
    handle.flush()


def process_snapshot() -> dict[str, Any]:
    result: dict[str, Any] = {"at": utc(), "pid": os.getpid(),
                              "load_average": list(os.getloadavg())}
    try:
        proc = subprocess.run(
            ["ps", "-axo", "pid,ppid,stat,pcpu,comm"],
            check=True, capture_output=True, text=True, timeout=10,
        )
        rows = []
        for line in proc.stdout.splitlines()[1:]:
            fields = line.strip().split(None, 4)
            if len(fields) == 5:
                rows.append({"pid": int(fields[0]), "ppid": int(fields[1]),
                             "stat": fields[2], "cpu_percent": float(fields[3]),
                             "command_name": fields[4]})
        result["top_processes_by_ps_cpu"] = sorted(
            rows, key=lambda item: item["cpu_percent"], reverse=True,
        )[:15]
        result["scope"] = "ps accumulated CPU percentage; not instantaneous idle"
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result["process_observation_error"] = str(exc)
    return result


def source_paths(root: Path, loaded: Mapping[str, Any]) -> list[Path]:
    paths = {
        root / "caprls_core/selection_cost_diagnose.py",
        root / "caprls_core/selection_cost_breakdown.py",
        root / "caprls_core/selection_cost_breakdown_analyze.py",
        root / "caprls_core/e3_main.py", root / "caprls_core/e10_study.py",
        root / "caprls_core/postgres_runner.py",
        root / "caprls_core/selection_cost_e3.py",
        root / MANIFEST, root / "configs/pg_smoke.yaml", root / LEGACY_OBSERVER,
    }
    paths.update(root.joinpath("planner").rglob("*.py"))
    paths.update(root.joinpath("sql").rglob("*.sql"))
    # Record loaded measurement dependencies, not unrelated paper rendering code.
    excluded = {"paper_figures.py", "sigmod_release.py"}
    for module in tuple(sys.modules.values()):
        filename = getattr(module, "__file__", None)
        if filename:
            path = Path(filename).resolve()
            if path.parent == root / "caprls_core" and path.suffix == ".py":
                if path.name not in excluded:
                    paths.add(path)
    paths.update(root / query.path for query in loaded["queries"])
    return sorted(path for path in paths if not path.name.startswith("._"))


def snapshot_hashes(root: Path, paths: list[Path]) -> dict[str, str]:
    return {str(path.relative_to(root)): file_hash(path) for path in paths}


def changed_hashes(root: Path, before: Mapping[str, str]) -> list[str]:
    return [name for name, digest in before.items()
            if not (root / name).exists() or file_hash(root / name) != digest]


def load_observer(root: Path) -> type:
    path = root / LEGACY_OBSERVER
    spec = importlib.util.spec_from_file_location("caprls_legacy_cost_observer", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the preserved legacy observer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.OriginalObserver


def prepare_case(e3: Any, query: Any, policy: Any, pg_env: Any,
                 ranker: Any, registry: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Use the original builder and original pre-collected input boundary."""
    from caprls_core.postgres_runner import run_psql_command

    started = time.perf_counter()
    protected_rows = e3._protected_count(query, pg_env)
    query_local_rows = int(run_psql_command(
        f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} "
        f"WHERE {e3._query_local_predicate(query)};", pg_env,
    ))
    predicate = e3._policy_predicate(query, policy)
    build_ms, artifact_rows, keyed_rows = e3._build_artifact(
        query, policy, predicate, pg_env,
    )
    e3._configure_native_rls(query, policy, pg_env)
    receipt = e3._collect_e3_planning_catalog_receipt(query, policy, pg_env)
    authorized_rows = int(run_psql_command(
        f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} "
        f"WHERE {predicate};", pg_env,
    ))
    if artifact_rows:
        authorized_rows = artifact_rows
    kwargs = dict(
        query=query, policy=policy, predicate=predicate, pg_env=pg_env,
        protected_rows=protected_rows, query_local_rows=query_local_rows,
        authorized_rows=authorized_rows, build_ms=build_ms, ranker=ranker,
        registry=registry, keyed_artifact_rows=keyed_rows,
        planning_catalog_receipt=receipt, access_root_materialized=True,
    )
    metadata = {
        "excluded_setup_wall_ms": (time.perf_counter() - started) * 1000,
        "protected_rows": protected_rows, "query_local_rows": query_local_rows,
        "authorized_rows": authorized_rows, "artifact_rows": artifact_rows,
        "keyed_artifact_rows": keyed_rows, "artifact_build_ms": build_ms,
        "predicate_hash": sha256_text(predicate), "access_root_materialized": True,
        "receipt_type": type(receipt).__name__,
        "scope": "pre-collected inputs and provisioning excluded from selection",
    }
    return kwargs, metadata


def selection_identity(e3: Any, result: Any, query: Any, policy: Any) -> dict[str, Any]:
    from caprls_core.selection_cost_e3 import measurement_sql

    plan, query_plan, _problem = result
    bound = query_plan.get("production_bound_runner")
    if not isinstance(bound, Mapping) or not isinstance(bound.get("runner_sql"), str):
        raise RuntimeError("selection did not produce its original bound runner SQL")
    selected = e3._require_e3_selected_root_template(query_plan)
    timed = measurement_sql(e3, query, policy, selected)
    return {
        "selected_template_id": selected, "selected_plan_id": bound.get("plan_id"),
        "runner_sql_digest": sha256_text(bound["runner_sql"]),
        "bound_runner_sql_digest": bound.get("runner_sql_digest"),
        "runner_sql": bound["runner_sql"],
        "timed_shared_runner_sql_hash": sha256_text(timed["sql"]),
        "timed_shared_sql_executed_in_diagnosis": False,
        "chosen_cost": query_plan.get("production_chosen_cost"),
        "root_selection_audit": query_plan.get("production_root_selection"),
        "candidate_costs": [
            {"template_id": candidate.template_id,
             "accepted": candidate.accepted,
             "diagnostic_heuristic_estimated_cost": candidate.estimated_cost}
            for candidate in plan.candidates
        ],
        "candidate_costs_scope": "heuristic fields; production chosen cost separately recorded",
    }


def pair_order(case_index: int, phase: str, iteration: int) -> tuple[str, str]:
    offset = WARMUP if phase == "measured" else 0
    return ARMS if (case_index + offset + iteration) % 2 == 0 else ARMS[::-1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path,
                        help="new directory; defaults to results/raw/" + ACTIVITY)
    parser.add_argument("--dry-run", action="store_true",
                        help="inventory and data-path checks only; no DB or file writes")
    parser.add_argument("--skip-analysis", action="store_true",
                        help="retain samples and completion, without automatic offline reduction")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    output = (args.output if args.output is not None
              else root / "results/raw" / ACTIVITY).resolve()
    from caprls_core import e3_main as e3
    from caprls_core.selection_cost_e3 import load_family

    loaded = load_family(root, root / MANIFEST)
    queries = {query.query_id: query for query in loaded["queries"]}
    policies = {policy.config_id: policy for policy in loaded["policies"]}
    pairs = [(queries[qid], policies[pid]) for qid in QUERIES for pid in POLICIES]
    missing_data = [str(item.path) for item in e3.e3_manifest_data_requirements(
        root, loaded["manifest"],
    ) if not item.path.exists()]
    protocol = {
        "schema": "caprls-selection-only-cost-diagnosis-v1", "activity": ACTIVITY,
        "started_at": utc(), "pid": os.getpid(), "root": str(root),
        "output": str(output), "family": "E3", "cases": [
            {"case_id": f"E3_{q.query_id}_{p.config_id}",
             "query_id": q.query_id, "policy_id": p.config_id} for q, p in pairs
        ],
        "warmup_per_arm": WARMUP, "measured_per_arm": MEASURED, "arms": ARMS,
        "expected_selection_calls": len(pairs) * (WARMUP + MEASURED) * len(ARMS),
        "order": "alternate paired arm order by case_index+phase_offset+iteration",
        "temporary_cluster": "new private cluster; shared_buffers 16MB",
        "selection_callable": "caprls_core.e3_main._plan_e3_admission_first",
        "precollected_inputs_excluded": True, "access_root_materialized": True,
        "query_latency_measurement": False, "explain_analyze_benchmark": False,
        "legacy_observer": LEGACY_OBSERVER,
        "legacy_direct_caller_difference": (
            "legacy callback retained unchanged; selection invoked by collector.run "
            "rather than run_e3_main; historical direct-caller filter thus emits no "
            "legacy choice receipt. Python global profiling dispatch remains enabled."
        ),
        "no_automatic_retry": True, "no_manuscript_adoption": True,
        "old_result_replacement": False, "missing_data": missing_data,
        "new_output_already_exists": output.exists(),
        "automatic_offline_reduction": not args.skip_analysis,
    }
    if args.dry_run:
        print(json.dumps(protocol, indent=2))
        return 0 if not missing_data and not output.exists() else 1
    if output.exists():
        raise FileExistsError(f"refusing existing result directory: {output}")
    if missing_data:
        raise FileNotFoundError("required original benchmark inputs missing: " + str(missing_data))
    if sys.getprofile() is not None:
        raise RuntimeError("a pre-existing global profiler would invalidate the plain_sparse arm")
    from caprls_core.postgres_runner import temporary_cluster, run_psql_command
    from caprls_core.selection_cost_breakdown import SelectionCostBreakdown

    observer_type = load_observer(root)
    ranker = e3._ranker_from_manifest(root, loaded["manifest"])
    registry = e3._e3_registry_from_manifest(loaded["manifest"])
    sources = snapshot_hashes(root, source_paths(root, loaded))
    protected = snapshot_hashes(root, [root / name for name in PROTECTED])
    output.mkdir(parents=True, exist_ok=False)
    write_once(output / "protocol.json", protocol)
    write_once(output / "source_hashes_before.json", sources)
    write_once(output / "protected_hashes_before.json", protected)
    write_once(output / "processes_before.json", process_snapshot())
    failures: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []
    completed_cases: list[str] = []
    completed_selections = 0
    original_buffers = os.environ.get("CAPRLS_PG_SHARED_BUFFERS")
    os.environ["CAPRLS_PG_SHARED_BUFFERS"] = "16MB"
    try:
        with (output / "diagnosis.jsonl").open("x", encoding="utf-8") as records:
            with temporary_cluster(database="caprls_selection_diagnosis") as pg_env:
                observed_buffers = run_psql_command("SHOW shared_buffers;", pg_env).strip()
                if observed_buffers != "16MB":
                    raise RuntimeError(f"private cluster buffer setting differs: {observed_buffers}")
                append_record(records, {"kind": "database_setup_started", "at": utc()})
                print(json.dumps({"event": "database_setup_started", "at": utc()}), flush=True)
                setup_started = time.perf_counter()
                version = e3._prepare_database(root, pg_env, tpch_scale="SF1", job_scale="full")
                write_once(output / "environment.json", {
                    "server_version": version, "shared_buffers": observed_buffers,
                    "host": pg_env.host, "port": pg_env.port, "database": pg_env.database,
                    "setup_wall_ms": (time.perf_counter() - setup_started) * 1000,
                    "private_temporary_database": True,
                })
                for case_index, (query, policy) in enumerate(pairs):
                    case_id = f"E3_{query.query_id}_{policy.config_id}"
                    print(json.dumps({"event": "case_setup_started", "case_id": case_id,
                                      "at": utc()}), flush=True)
                    kwargs, setup = prepare_case(e3, query, policy, pg_env, ranker, registry)
                    write_once(output / f"{case_id}_setup.json", setup)
                    for phase, count in (("warmup", WARMUP), ("measured", MEASURED)):
                        for iteration in range(count):
                            order = pair_order(case_index, phase, iteration)
                            observations: dict[str, dict[str, Any]] = {}
                            for arm in order:
                                # Capture original target code objects before collector patches.
                                legacy_stream = io.StringIO()
                                legacy = observer_type(legacy_stream, e3=e3)
                                scope = legacy if arm == "legacy_profile_sparse" else nullcontext()
                                record: dict[str, Any] = {
                                    "kind": "selection", "at": utc(), "family": "E3",
                                    "case_id": case_id, "query_id": query.query_id,
                                    "policy_id": policy.config_id, "phase": phase,
                                    "iteration": iteration, "arm": arm, "pair_order": order,
                                    "access_root_materialized": True,
                                }
                                try:
                                    collector = SelectionCostBreakdown(family="E3")
                                    with scope:
                                        result, breakdown = collector.run(
                                            e3._plan_e3_admission_first, **kwargs,
                                        )
                                    record.update({"status": "pass", "breakdown": breakdown,
                                                   "selection": selection_identity(e3, result, query, policy),
                                                   "legacy_observer_errors": legacy.errors,
                                                   "legacy_emitted_records": legacy_stream.getvalue()})
                                    if legacy.errors:
                                        raise RuntimeError("legacy observation callback error: " + str(legacy.errors))
                                    if breakdown.get("sql_call_counts", {}).get("explain_analyze", 0):
                                        raise RuntimeError("selection diagnosis unexpectedly executed EXPLAIN ANALYZE")
                                except BaseException as exc:
                                    record.update({"status": "failed", "error": str(exc),
                                                   "traceback": traceback.format_exc()})
                                    failures.append({key: record[key] for key in
                                                     ("case_id", "phase", "iteration", "arm", "error")})
                                    append_record(records, record)
                                    raise
                                append_record(records, record)
                                observations[arm] = record
                                completed_selections += 1
                                print(json.dumps({"event": "selection_complete", "at": utc(),
                                                  "case_id": case_id, "phase": phase,
                                                  "iteration": iteration, "arm": arm,
                                                  "total_wall_ms": breakdown["total_wall_ms"],
                                                  "selected_template_id": record["selection"]["selected_template_id"]}),
                                      flush=True)
                            left = observations[ARMS[0]]["selection"]
                            right = observations[ARMS[1]]["selection"]
                            same = all(left[field] == right[field] for field in
                                       ("selected_template_id", "runner_sql_digest", "timed_shared_runner_sql_hash"))
                            pair = {"kind": "pair_summary", "at": utc(), "case_id": case_id,
                                    "phase": phase, "iteration": iteration,
                                    "selection_and_sql_match": same,
                                    "selection_identities": {arm: observations[arm]["selection"]["runner_sql_digest"]
                                                             for arm in ARMS}}
                            append_record(records, pair)
                            if not same:
                                mismatches.append(pair)
                    completed_cases.append(case_id)
                    print(json.dumps({"event": "case_complete", "case_id": case_id,
                                      "completed_cases": len(completed_cases), "at": utc()}), flush=True)
    except BaseException as exc:
        if not failures:
            failures.append({"stage": "setup_or_activity", "error": str(exc),
                             "traceback": traceback.format_exc()})
    finally:
        if original_buffers is None:
            os.environ.pop("CAPRLS_PG_SHARED_BUFFERS", None)
        else:
            os.environ["CAPRLS_PG_SHARED_BUFFERS"] = original_buffers
        source_changes = changed_hashes(root, sources)
        protected_changes = changed_hashes(root, protected)
        write_once(output / "processes_after.json", process_snapshot())
        completion = {
            "activity": ACTIVITY, "completed_at": utc(),
            "status": "pass" if (not failures and not source_changes and not protected_changes
                                   and not mismatches and len(completed_cases) == len(pairs)) else "needs_review",
            "completed_cases": completed_cases, "expected_cases": len(pairs),
            "completed_selection_calls": completed_selections,
            "expected_selection_calls": protocol["expected_selection_calls"],
            "failures": failures, "paired_selection_or_sql_mismatches": mismatches,
            "changed_measurement_sources": source_changes,
            "changed_protected_files": protected_changes,
            "no_retry": True, "no_query_latency_measurements": True,
            "no_manuscript_changes": True,
        }
        write_once(output / "completion.json", completion)
        print(json.dumps(completion, default=str), flush=True)
    analysis_receipt = None
    if not args.skip_analysis:
        # This runs only after the private cluster is closed.  Reduction never
        # connects to PostgreSQL, changes sampling, or replaces manuscript data.
        from caprls_core.selection_cost_breakdown_analyze import main as analyze_main
        reduction = output / "auto_reduction"
        analysis_receipt = {
            "activity": ACTIVITY, "started_at": utc(),
            "database_access": False, "sampling_retry": False,
            "input": str(output / "diagnosis.jsonl"), "output": str(reduction),
        }
        try:
            exit_code = analyze_main(["--input", str(output / "diagnosis.jsonl"),
                                      "--output-dir", str(reduction)])
            analysis_receipt["analyzer_exit_code"] = exit_code
            analysis_path = reduction / "analysis.json"
            if analysis_path.exists():
                analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
                analysis_receipt["analysis_status"] = analysis.get("status")
                analysis_receipt["analysis_sha256"] = file_hash(analysis_path)
            analysis_receipt["status"] = "complete" if exit_code == 0 else "needs_review"
        except BaseException as exc:
            analysis_receipt.update({"status": "needs_review", "error": str(exc),
                                     "traceback": traceback.format_exc()})
        analysis_receipt["completed_at"] = utc()
        write_once(output / "analysis_receipt.json", analysis_receipt)
        print(json.dumps(analysis_receipt, default=str), flush=True)
    if completion["status"] != "pass":
        return 1
    if analysis_receipt is not None and analysis_receipt["status"] != "complete":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
