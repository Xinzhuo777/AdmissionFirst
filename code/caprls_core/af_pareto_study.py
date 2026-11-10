"""Compare actual old/new AF sources on one loaded PostgreSQL dataset.

The selection workers import only their declared source tree.  Normal fixed
comparators come from the baseline source, without transplanting AF changes.
Selection is prospective; full-result checks precede all timing.  The primary
timing boundary is the existing E3 preview's client/transaction/validation/
EXPLAIN ANALYZE boundary.  Choice and first-use costs are reported separately.
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import nullcontext
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time
import traceback
from typing import Any, Callable, Mapping, Sequence


FRAME = "AF_PARETO_WORKER_V1 "
FIXED_MODES = ("native-pg-rls", "local-greedy", "barrier-only", "injection-only")
DEFAULT_MODES = ("af-old", "af-new", *FIXED_MODES)

# All six orders, arranged so the circular boundaries also balance each
# predecessor pair, including repeats. Every mode occupies each position
# twice and follows every mode twice per cycle. Rotation alone
# preserves most predecessor pairs and can confound cache carryover.
BALANCED_THREE_MODE_ORDERS = (
    (0, 1, 2), (2, 0, 1), (1, 0, 2),
    (2, 1, 0), (0, 2, 1), (1, 2, 0),
)


def measurement_order(entries: Sequence[Any], round_index: int, schedule: str) -> list[Any]:
    if schedule == "balanced_three_mode_v2":
        if len(entries) != 3:
            raise ValueError("balanced schedule requires exactly three available modes")
        return [entries[index] for index in BALANCED_THREE_MODE_ORDERS[round_index % 6]]
    if schedule != "rotating":
        raise ValueError("unknown measurement schedule")
    offset = round_index % len(entries) if entries else 0
    return list(entries[offset:]) + list(entries[:offset])


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_json(value: Any) -> str:
    return digest_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_once(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def source_identity(source: Path) -> dict[str, Any]:
    """Freeze code/configuration, excluding manuscripts and wiki documents."""
    paths = []
    for directory in ("caprls_core", "planner"):
        paths.extend((source / directory).rglob("*.py"))
    paths.extend((source / "configs").rglob("*.yaml"))
    # SQL is executable input and A004 also reads the controlled validator
    # body from its source tree during issuance/replay.
    for directory in ("sql", "workloads", "specs"):
        for suffix in ("*.sql", "*.yaml", "*.json"):
            paths.extend((source / directory).rglob(suffix))
    files = {str(path.relative_to(source)): digest_bytes(path.read_bytes())
             for path in sorted(paths) if "__pycache__" not in path.parts}
    if "caprls_core/e3_main.py" not in files or "planner/contracts.py" not in files:
        raise ValueError("source root lacks the E3/planner implementation")
    return {"root": str(source.resolve()), "digest": digest_json(files), "files": files}


def activate_source(source: Path) -> tuple[Any, Any, Any]:
    source = source.resolve()
    sys.path.insert(0, str(source))
    e3 = importlib.import_module("caprls_core.e3_main")
    preview = importlib.import_module("caprls_core.e3_sigmod_preview")
    postgres = importlib.import_module("caprls_core.postgres_runner")
    for name, module in tuple(sys.modules.items()):
        if name in {"planner", "caprls_core"} or name.startswith(("planner.", "caprls_core.")):
            filename = getattr(module, "__file__", None)
            if filename and name != __name__:
                try:
                    Path(filename).resolve().relative_to(source)
                except ValueError as exc:
                    raise RuntimeError("mixed source imports: " + name) from exc
    return e3, preview, postgres


def worker_execution_profile_options(e3: Any, registry: Any, required: str | None = None) -> dict[str, str]:
    options = {}
    if (hasattr(e3, "_validate_e3_execution_profile_payload")
        and "native_pg_rls_v1" not in e3._e3_registry_template_ids(registry)):
        options["execution_profile"] = "trusted_explicit"
    if required is not None and options.get("execution_profile") != required:
        raise ValueError("worker source/portfolio cannot provide the required execution profile: " + required)
    return options


def worker_payload(source: Path, request: Mapping[str, Any]) -> dict[str, Any]:
    before = source_identity(source)
    e3, preview, postgres = activate_source(source)
    manifest_path = Path(request["manifest"])
    manifest = e3._load_manifest(manifest_path)
    query = next(item for item in e3._queries_for_manifest(manifest_path, manifest)
                 if item.query_id == request["query_id"])
    policy = next(item for item in e3._policies_for_manifest(manifest_path, manifest)
                  if item.config_id == request["policy_id"])
    pg_env = postgres.PostgresEnv(**request["pg_env"])
    stats = request["stats"]
    predicate = e3._policy_predicate(query, policy)
    registry = e3._e3_registry_from_manifest(manifest)
    # Each source uses its implemented AF profile. The legacy source has no
    # trusted-profile issuer; its catalog/cost/execution behavior stays intact.
    profile_kwargs = worker_execution_profile_options(e3, registry, request.get("required_execution_profile"))
    started = time.perf_counter()
    receipt = e3._collect_e3_planning_catalog_receipt(query, policy, pg_env, **profile_kwargs)
    receipt_ms = (time.perf_counter() - started) * 1000
    # Calibration belongs to the algorithm source, while the manifest and
    # database population are the shared study inputs.
    ranker = e3._ranker_from_manifest(source, manifest)
    started = time.perf_counter()
    result, plan, _ = e3._plan_e3_admission_first(
        query=query, policy=policy, predicate=predicate, pg_env=pg_env,
        protected_rows=stats["protected_rows"], query_local_rows=stats["query_local_rows"],
        authorized_rows=stats["authorized_rows"], build_ms=stats["artifact_build_ms"],
        keyed_artifact_rows=stats["keyed_artifact_rows"], ranker=ranker, registry=registry,
        planning_catalog_receipt=receipt,
        access_root_materialized=request["access_root_materialized"],
        **profile_kwargs,
    )
    selection_ms = (time.perf_counter() - started) * 1000
    template = e3._require_e3_selected_root_template(plan)
    bound = plan["production_bound_runner"]
    sql = bound["runner_sql"]
    if bound["template_id"] != template or bound["runner_sql_digest"] != e3._canonical_sha256(
            {"exact_runner_sql": sql}):
        raise ValueError("worker selected SQL identity mismatch")
    if result.chosen_template is None:
        raise ValueError("worker has no chosen AF template")
    sql_source = e3._source_for_template(template)
    artifact_ids, expected_json = preview._artifact_validation_for(query, policy, sql_source)
    contract_kwargs = {}
    if profile_kwargs:
        contract_kwargs = {
            "session_contract": bound.get("session_contract"),
            "execution_profile": bound.get("execution_profile"),
        }
        if any(not isinstance(value, Mapping) for value in contract_kwargs.values()):
            raise ValueError("trusted AF worker lacks its actual execution contract")
    spec = preview.ExecutionSpec(
        mode=request["variant"], template_id=template,
        alternative=result.chosen_template.alternative, sql=sql, sql_source=sql_source,
        result_columns=preview._result_columns_for(query),
        role=(contract_kwargs["session_contract"]["role"] if contract_kwargs
              else e3.E3_RLS_ROLE if sql_source == "rls" else None),
        artifact_ids=artifact_ids, expected_artifact_json=expected_json,
        **contract_kwargs,
    )
    if contract_kwargs:
        preview._execution_contract(spec)
    fixed = []
    if request.get("collect_fixed"):
        for mode in FIXED_MODES:
            mode_started = time.perf_counter()
            prepared = preview._fixed_mode(query, policy, mode)
            fixed.append({
                "mode": mode,
                "spec": None if prepared.spec is None else asdict(prepared.spec),
                "unavailable_reason": prepared.unavailable_reason,
                "generation_wall_ms": (time.perf_counter() - mode_started) * 1000,
            })
    reference = preview.ExecutionSpec(
        mode="independent-reference", template_id="direct_independent_reference_v1",
        alternative="IndependentReference", sql=e3._e3_independent_result_reference_sql(query, policy),
        sql_source="direct-independent-reference", result_columns=preview._result_columns_for(query),
    )
    after = source_identity(source)
    if before != after:
        raise RuntimeError("worker source changed during prospective selection")
    return {
        "schema": "af_pareto_worker_v1", "status": "pass", "variant": request["variant"],
        "query_id": query.query_id, "policy_id": policy.config_id,
        "source_identity": before, "manifest_sha256": digest_bytes(manifest_path.read_bytes()),
        "spec": asdict(spec), "fixed_modes": fixed, "reference": asdict(reference),
        "selection": {
            "selected_template_id": template, "selected_plan_id": bound["plan_id"],
            "selected_runner_digest": bound["runner_sql_digest"],
            "prospective_total_cost": plan["production_chosen_cost"]["prospective_total_cost"],
            "selection_wall_ms": selection_ms, "catalog_receipt_wall_ms": receipt_ms,
            "execution_profile": profile_kwargs.get("execution_profile", "legacy_native_cost_trusted_explicit_execution"),
            "measured_runtime_used_for_selection": False,
            "bound_runner": bound,
        },
    }


def parse_worker_frame(stdout: str) -> dict[str, Any]:
    frames = [line[len(FRAME):] for line in stdout.splitlines() if line.startswith(FRAME)]
    if len(frames) != 1:
        raise ValueError("worker must return exactly one framed response")
    result = json.loads(frames[0])
    if not isinstance(result, dict) or result.get("schema") != "af_pareto_worker_v1":
        raise ValueError("invalid worker response schema")
    return result


def run_worker(source: Path, request: Mapping[str, Any], *, timeout_s: float = 1800) -> dict[str, Any]:
    started = time.perf_counter()
    proc = subprocess.run(
        [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", str(source.resolve())],
        input=json.dumps(request), text=True, capture_output=True, cwd=source, timeout=timeout_s,
        env={**os.environ, "PYTHONPATH": str(source.resolve())},
    )
    try:
        result = parse_worker_frame(proc.stdout)
    except (ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("malformed selection worker response: " + json.dumps({
            "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr,
        }, ensure_ascii=False)) from exc
    result["worker_request_wall_ms"] = (time.perf_counter() - started) * 1000
    if proc.returncode or result.get("status") != "pass":
        raise RuntimeError("selection worker failed: " + json.dumps({
            "returncode": proc.returncode, "response": result, "stderr": proc.stderr,
        }, ensure_ascii=False))
    return result


def prepare_artifacts(e3: Any, postgres: Any, queries: Sequence[Any],
                      policies: Sequence[Any], pg_env: Any) -> dict[str, Any]:
    """Finish all shared artifact writes before any prospective selection.

    E3 artifact IDs are shared by queries in the same workload/policy. Reusing
    an ID with a different recipe is rejected instead of silently replacing
    the artifact that an earlier selection assumed.
    """
    recipes: dict[str, tuple[str, Any, Any]] = {}
    for query in queries:
        for policy in policies:
            artifact_id = e3._artifact_id(query, policy)
            predicate = e3._policy_predicate(query, policy)
            recipe = {
                "sql": None if policy.artifacts == "none" else e3._build_artifact_sql(query, policy, predicate),
                "protected_rel": query.protected_rel, "rid_col": query.rid_col,
                "key_name": query.key_name, "key_value": query.key_value,
            }
            signature = digest_json(recipe)
            if artifact_id in recipes and recipes[artifact_id][0] != signature:
                raise ValueError("shared artifact ID has incompatible query recipes: " + artifact_id)
            recipes.setdefault(artifact_id, (signature, query, policy))
    built = {}
    for artifact_id, (signature, query, policy) in recipes.items():
        build_ms, rows, keyed_rows = e3._build_artifact(
            query, policy, e3._policy_predicate(query, policy), pg_env)
        built[artifact_id] = {
            "recipe_digest": signature, "representative_query": query.query_id,
            "policy_id": policy.config_id, "artifact_build_ms": build_ms,
            "artifact_rows": rows, "keyed_artifact_rows": keyed_rows,
        }
    # One final common maintenance step prevents early cells from seeing an
    # incomplete artifact population or statistics that later builds replace.
    for table in ("auth_idx", "auth_idx_keyed", "artifact_dependencies"):
        postgres.run_psql_command("VACUUM (ANALYZE) public." + table, pg_env)
    return built


def statistics_identity(postgres: Any, pg_env: Any) -> dict[str, Any]:
    """Record the catalog statistics used by normal PostgreSQL planning."""
    raw = postgres.run_psql_command("""
SELECT json_build_object(
  'relations', (
    SELECT json_agg(json_build_array(c.relname, c.relpages, c.reltuples, c.relallvisible)
                    ORDER BY c.relname)
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'm')
  ),
  'statistics', (
    SELECT json_agg(json_build_array(tablename, attname, inherited, null_frac,
                    avg_width, n_distinct, most_common_vals::text,
                    most_common_freqs::text, histogram_bounds::text, correlation,
                    most_common_elems::text, most_common_elem_freqs::text,
                    elem_count_histogram::text)
                    ORDER BY tablename, attname, inherited)
    FROM pg_catalog.pg_stats WHERE schemaname = 'public'
  )
)::text
""", pg_env)
    payload = json.loads(raw)
    return {"digest": digest_json(payload), "catalog_statistics": payload}


def evaluate_cells(
    cells: Sequence[Mapping[str, Any]], *, output_dir: Path, warmup: int, measured: int,
    canonicalize: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    measure: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    diagnostic: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None,
    restore_cell: Callable[[Mapping[str, Any]], None], correctness_only: bool = False,
    schedule: str = "rotating",
) -> list[dict[str, Any]]:
    """Check every case/mode before timing, then use the declared schedule."""
    if warmup < 0 or measured < 0 or (not correctness_only and measured < 1):
        raise ValueError("invalid warmup/measured repetitions")
    if correctness_only and (warmup or measured):
        raise ValueError("correctness-only requires zero repetitions")
    if schedule not in {"rotating", "balanced_three_mode_v2"}:
        raise ValueError("unknown measurement schedule")
    if schedule == "balanced_three_mode_v2" and not correctness_only:
        if warmup < 6 or measured < 6 or warmup % 6 or measured % 6:
            raise ValueError("balanced schedule requires complete six-round warmup/measured cycles")
        if any(sum(entry["spec"] is not None for entry in cell["modes"]) != 3 for cell in cells):
            raise ValueError("balanced schedule requires exactly three available modes")
    checked = []
    failures = []
    for cell in cells:
        restore_cell(cell)
        reference = dict(canonicalize(cell["reference"]))
        correctness = {}
        for entry in cell["modes"]:
            mode, spec = entry["mode"], entry["spec"]
            if spec is None:
                correctness[mode] = {"status": "unavailable", "reason": entry["unavailable_reason"]}
                continue
            actual = dict(canonicalize(spec))
            a, r = Counter(actual["canonical_rows"]), Counter(reference["canonical_rows"])
            excess, missing = sum((a-r).values()), sum((r-a).values())
            status = "pass" if not excess and not missing else "correctness_fail"
            correctness[mode] = {
                "status": status, "actual": actual, "actual_only_rows": excess,
                "reference_only_rows": missing,
                "ordered_sequence_match_diagnostic": actual["canonical_rows"] == reference["canonical_rows"],
            }
            if status != "pass":
                failures.append(cell["case_id"] + ":" + mode)
        write_once(output_dir/"correctness"/(cell["case_id"]+".json"), {
            "method": "full_row_jsonb_multiset_equality", "reference": reference,
            "modes": correctness,
        })
        checked.append((cell, correctness))
    if failures:
        raise ValueError("correctness failed before any timing: " + ", ".join(failures))

    summary = []
    for cell, correctness in checked:
        restore_cell(cell)
        eligible = [entry for entry in cell["modes"] if entry["spec"] is not None]
        collected: dict[str, list[Mapping[str, Any]]] = {entry["mode"]: [] for entry in eligible}
        preceding_mode = None
        if not correctness_only:
            for round_index in range(warmup + measured):
                phase = "warmup" if round_index < warmup else "measured"
                iteration = round_index+1 if phase == "warmup" else round_index-warmup+1
                order = measurement_order(eligible, round_index, schedule)
                for order_index, entry in enumerate(order):
                    sample = dict(measure(entry["spec"]))
                    write_once(output_dir/"samples"/(
                        f"{cell['case_id']}__{entry['mode']}__{phase}{iteration:02d}.json"), {
                        "case_id": cell["case_id"], "mode": entry["mode"], "phase": phase,
                        "iteration": iteration, "round_index": round_index,
                        "order_index": order_index, "sql_sha256": digest_bytes(entry["spec"]["sql"].encode()),
                        **({"preceding_mode": preceding_mode} if schedule == "balanced_three_mode_v2" else {}),
                        "source_identity": entry.get("source_digest"),
                        "selection": entry.get("selection"), "measurement": sample,
                    })
                    preceding_mode = entry["mode"]
                    if phase == "measured":
                        collected[entry["mode"]].append(sample)
        for entry in cell["modes"]:
            mode = entry["mode"]
            samples = collected.get(mode, [])
            median = lambda key: statistics.median(sample[key] for sample in samples) if samples else None
            request_ms = median("database_total_ms")
            selection = entry.get("selection") or {}
            choice_ms = selection.get("selection_wall_ms", 0) + selection.get("catalog_receipt_wall_ms", 0)
            input_ms = cell["stats"]["input_collection_wall_ms"] if mode.startswith("af-") else 0
            first_use = None if request_ms is None else request_ms + choice_ms + input_ms + entry.get("generation_wall_ms", 0)
            row = {
                "case_id": cell["case_id"], "query_id": cell["query_id"], "policy_id": cell["policy_id"],
                "mode": mode, "status": correctness[mode]["status"],
                "template_id": None if entry["spec"] is None else entry["spec"]["template_id"],
                "source_digest": entry.get("source_digest"),
                "measured_repetitions": len(samples),
                "median_end_to_end_ms_including_validation_and_client": request_ms,
                "median_postgres_planning_ms": median("postgres_planning_ms"),
                "median_postgres_query_execution_ms": median("execution_ms"),
                "selection_wall_ms": selection.get("selection_wall_ms"),
                "catalog_receipt_wall_ms": selection.get("catalog_receipt_wall_ms"),
                "input_collection_wall_ms": input_ms,
                "worker_request_wall_ms_infrastructure_only": entry.get("worker_request_wall_ms"),
                "first_use_estimate_ms_excluding_artifact_build": first_use,
                "artifact_build_ms_shared_setup": cell["stats"]["artifact_build_ms"],
                "first_use_estimate_with_artifact_build_ms": None if first_use is None else first_use + (
                    cell["stats"]["artifact_build_ms"] if mode.startswith("af-") or (
                        entry["spec"] and entry["spec"].get("artifact_ids")) else 0),
            }
            summary.append(row)
        # Diagnostic executions occur after primary samples and are not timed samples.
        if diagnostic is not None:
            for entry in eligible:
                write_once(output_dir/"diagnostics"/(cell["case_id"]+"__"+entry["mode"]+".json"),
                           diagnostic(entry["spec"]))
    return summary


def _spec_from_dict(preview: Any, payload: Mapping[str, Any]) -> Any:
    data = dict(payload)
    data["result_columns"] = tuple(tuple(column) for column in data.get("result_columns", ()))
    data["artifact_ids"] = tuple(data.get("artifact_ids", ()))
    return preview.ExecutionSpec(**data)


def run_study(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.root).resolve()
    source = Path(args.source_root or root).resolve()
    baseline = Path(args.baseline_source).resolve()
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = root/manifest_path
    current_identity, baseline_identity = source_identity(source), source_identity(baseline)
    manifest_digest = digest_bytes(manifest_path.read_bytes())
    e3, preview, postgres = activate_source(source)
    manifest = e3._load_manifest(manifest_path)
    e3._validate_manifest(manifest_path, manifest)
    e3.require_e3_manifest_data(root, manifest_path, manifest)
    queries = preview._select_items(e3._queries_for_manifest(manifest_path, manifest), args.query,
                                   key=lambda item: item.query_id, label="query")
    policies = preview._select_items(e3._policies_for_manifest(manifest_path, manifest), args.policy,
                                    key=lambda item: item.config_id, label="policy")
    modes = tuple(args.mode or DEFAULT_MODES)
    if len(set(modes)) != len(modes) or any(mode not in DEFAULT_MODES for mode in modes):
        raise ValueError("unknown or duplicate study mode")
    warmup, measured = (0, 0) if args.correctness_only else (args.warmup, args.measured)
    schedule = getattr(args, "schedule", "rotating")
    if warmup < 0 or measured < 0 or (not args.correctness_only and measured < 1):
        raise ValueError("invalid repetitions")
    if schedule == "balanced_three_mode_v2" and (len(modes) != 3 or (not args.correctness_only and (
            warmup < 6 or measured < 6 or warmup % 6 or measured % 6))):
        raise ValueError("balanced schedule needs three modes and complete six-round phase cycles")
    scales = {item["name"]: item["scale"] for item in manifest["datasets"]}
    wrapper = (manifest.get("scale_check") or {}).get("bound_runner_wrapper", "materialized")
    if wrapper not in {"materialized", "not_materialized_single_reference"}:
        raise ValueError("unsupported access-root wrapper")
    write_once(output/"protocol.json", {
        "schema": "af_pareto_study_v1", "started_at": now(), "manifest": str(manifest_path),
        "manifest_sha256": manifest_digest, "modes": modes,
        "queries": [query.query_id for query in queries], "policies": [policy.config_id for policy in policies],
        "warmup": warmup, "measured": measured, "correctness_only": args.correctness_only,
        "driver_sha256": digest_bytes(Path(__file__).read_bytes()),
        "current_source": current_identity, "baseline_source": baseline_identity,
        "primary_scope": "psql_connection_RR_transaction_required_validation_PG_explain_planning_execution_commit",
        "choice_scope": "catalog_receipt_and_prospective_admission_choice_separately_reported",
        "af_execution_profile_rule": "Use the source's trusted_explicit issuer for explicit-only registries when implemented; otherwise retain that source's legacy behavior. Fixed baselines always come from baseline_source.",
        "required_new_execution_profile": args.require_new_execution_profile,
        "first_use_scope": "input_counts_catalog_receipt_choice_SQL_generation_primary_request_excluding_artifact_build",
        "first_use_is_estimate_not_complete_cold_request": True,
        "first_use_excludes": ["database_and_data_initialization", "native_RLS_policy_installation",
                               "experimental_statistics_probes", "worker_process_startup"],
        "artifact_build_scope": "shared_setup_separate; with_build_scenario_charges_AF_candidate_pool_build_or_fixed_mode_required_artifact_build",
        "worker_process_overhead": "infrastructure_only_separately_recorded_not_algorithm_choice_time",
        "diagnostics_scope": "separate_post_sampling_EXPLAIN_ANALYZE_BUFFERS_not_primary_samples",
        "baseline_implementation": "normal_fixed_specs_from_unchanged_baseline_source",
        "schedule": ("casewise_balanced_three_mode_rounds_v2" if schedule == "balanced_three_mode_v2"
                     else "casewise_deterministic_rotating_rounds"),
        "balanced_round_order_indices": (BALANCED_THREE_MODE_ORDERS if schedule == "balanced_three_mode_v2" else None),
        "artifact_preparation": "all_unique_recipes_built_once_then_common_VACUUM_ANALYZE_before_all_selection",
        "statistics_policy": "catalog_statistics_and_relation_estimates_frozen_across_selection_correctness_timing",
    })
    context = postgres.temporary_cluster(database=args.database) if args.host is None else nullcontext(
        postgres.PostgresEnv(args.host, args.port, args.user, args.database))
    with context as pg_env:
        setup_started = time.perf_counter()
        pg_version = e3._prepare_database(root, pg_env, tpch_scale=scales.get("tpch", ""), job_scale=scales.get("job", ""))
        write_once(output/"database.json", {"postgres_version": pg_version,
                   "setup_wall_ms": (time.perf_counter()-setup_started)*1000,
                   "pg_env": asdict(pg_env), "data_scales": scales,
                   "settings": postgres.run_psql_command(
                       "SELECT json_build_object('work_mem',current_setting('work_mem'),'shared_buffers',current_setting('shared_buffers'),'autovacuum',current_setting('autovacuum'))::text", pg_env)})
        artifacts = prepare_artifacts(e3, postgres, queries, policies, pg_env)
        write_once(output/"shared_artifacts.json", artifacts)
        frozen_statistics = statistics_identity(postgres, pg_env)
        write_once(output/"statistics_before_selection.json", frozen_statistics)
        cells = []
        for query in queries:
            for policy in policies:
                case_id = query.query_id + "__" + policy.config_id
                print("prepare " + case_id, flush=True)
                shared_started = time.perf_counter()
                count_started = time.perf_counter()
                protected = e3._protected_count(query, pg_env)
                local = int(postgres.run_psql_command(
                    f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} WHERE {e3._query_local_predicate(query)}", pg_env))
                count_ms = (time.perf_counter()-count_started)*1000
                predicate = e3._policy_predicate(query, policy)
                artifact = artifacts[e3._artifact_id(query, policy)]
                e3._configure_native_rls(query, policy, pg_env)
                count_started = time.perf_counter()
                authorized = int(postgres.run_psql_command(
                    f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} WHERE {predicate}", pg_env))
                count_ms += (time.perf_counter()-count_started)*1000
                stats = {"protected_rows": protected, "query_local_rows": local,
                         "authorized_rows": artifact["artifact_rows"] or authorized,
                         "keyed_artifact_rows": artifact["keyed_artifact_rows"],
                         "artifact_build_ms": artifact["artifact_build_ms"], "input_collection_wall_ms": count_ms,
                         "shared_preparation_wall_ms": (time.perf_counter()-shared_started)*1000}
                request = {"project_root": str(root), "manifest": str(manifest_path),
                           "query_id": query.query_id, "policy_id": policy.config_id,
                           "stats": stats, "pg_env": asdict(pg_env),
                           "access_root_materialized": wrapper == "materialized"}
                variants = {}
                for variant, tree in (("af-old", baseline), ("af-new", source)):
                    if statistics_identity(postgres, pg_env) != frozen_statistics:
                        raise RuntimeError("planner statistics changed before prospective selection")
                    worker = run_worker(tree, {**request, "variant": variant, "collect_fixed": variant == "af-old",
                                        "required_execution_profile": args.require_new_execution_profile if variant == "af-new" else None},
                                        timeout_s=args.worker_timeout)
                    expected = baseline_identity if variant == "af-old" else current_identity
                    if worker["source_identity"] != expected:
                        raise RuntimeError("source changed since campaign start: " + variant)
                    if worker["manifest_sha256"] != manifest_digest:
                        raise RuntimeError("manifest changed since campaign start")
                    if statistics_identity(postgres, pg_env) != frozen_statistics:
                        raise RuntimeError("planner statistics changed during prospective selection")
                    variants[variant] = worker
                    write_once(output/"prepared"/case_id/(variant+".json"), worker)
                entries = []
                for mode in modes:
                    if mode.startswith("af-"):
                        worker = variants[mode]
                        entries.append({"mode": mode, "spec": worker["spec"], "selection": worker["selection"],
                                        "source_digest": worker["source_identity"]["digest"],
                                        "worker_request_wall_ms": worker["worker_request_wall_ms"]})
                    else:
                        fixed = next(item for item in variants["af-old"]["fixed_modes"] if item["mode"] == mode)
                        entries.append({**fixed, "source_digest": baseline_identity["digest"]})
                cell = {"case_id": case_id, "query_id": query.query_id, "policy_id": policy.config_id,
                        "dataset_scale": scales[query.workload], "stats": stats,
                        "reference": variants["af-old"]["reference"], "modes": entries}
                cells.append(cell)
                write_once(output/"prepared"/case_id/"shared.json", cell)
        by_query = {query.query_id: query for query in queries}
        by_policy = {policy.config_id: policy for policy in policies}

        def restore(cell: Mapping[str, Any]) -> None:
            if statistics_identity(postgres, pg_env) != frozen_statistics:
                raise RuntimeError("planner statistics changed after campaign preparation")
            e3._configure_native_rls(by_query[cell["query_id"]], by_policy[cell["policy_id"]], pg_env)

        def canonicalize(payload: Mapping[str, Any]) -> Mapping[str, Any]:
            return asdict(preview._canonicalize_live(_spec_from_dict(preview, payload), pg_env))

        def measure(payload: Mapping[str, Any]) -> Mapping[str, Any]:
            return asdict(preview._measure_live(_spec_from_dict(preview, payload), pg_env))

        def diagnostic(payload: Mapping[str, Any]) -> Mapping[str, Any]:
            spec = _spec_from_dict(preview, payload)
            statement = preview._single_query(spec.sql)
            raw = postgres.run_psql_command(preview._transaction_script(spec,
                "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON, TIMING OFF, SUMMARY ON) " + statement), pg_env)
            observe_environment = getattr(preview, "_observed_execution_environment", None)
            query_output = getattr(preview, "_execution_query_output", lambda value: value)(raw)
            return {"sql": spec.sql, "sql_sha256": digest_bytes(spec.sql.encode()),
                    "role": spec.role, "artifact_validation_required": bool(spec.artifact_ids),
                    "execution_environment": (observe_environment(spec, raw)
                                              if observe_environment is not None else None),
                    "explain": e3._parse_explain_json(query_output)}

        summary = evaluate_cells(cells, output_dir=output, warmup=warmup, measured=measured,
                                 canonicalize=canonicalize, measure=measure,
                                 diagnostic=None if args.skip_diagnostics or args.correctness_only else diagnostic,
                                 restore_cell=restore, correctness_only=args.correctness_only,
                                 schedule=schedule)
        if source_identity(source) != current_identity or source_identity(baseline) != baseline_identity:
            raise RuntimeError("source changed during the campaign; results not promotable")
        if digest_bytes(manifest_path.read_bytes()) != manifest_digest:
            raise RuntimeError("manifest changed during the campaign; results not promotable")
        final_statistics = statistics_identity(postgres, pg_env)
        write_once(output/"statistics_after_sampling.json", final_statistics)
        if final_statistics != frozen_statistics:
            raise RuntimeError("planner statistics changed during the campaign; results not promotable")
        import csv
        with (output/"summary.csv").open("x", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(summary[0]) if summary else [])
            writer.writeheader()
            writer.writerows(summary)
        result = {"status": "completed", "finished_at": now(), "cells": len(cells),
                  "mode_results": len(summary), "summary": summary}
        write_once(output/"summary.json", result)
        return result


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "--worker":
        try:
            if len(argv) != 2:
                raise ValueError("worker requires exactly one source root")
            result = worker_payload(Path(argv[1]).resolve(), json.load(sys.stdin))
            code = 0
        except Exception as exc:
            result = {"schema": "af_pareto_worker_v1", "status": "error",
                      "error": str(exc), "traceback": traceback.format_exc()}
            code = 1
        print(FRAME + json.dumps(result, ensure_ascii=False), flush=True)
        return code
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--source-root")
    parser.add_argument("--baseline-source", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--query", action="append")
    parser.add_argument("--policy", action="append")
    parser.add_argument("--mode", action="append", choices=DEFAULT_MODES)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--measured", type=int, default=10)
    parser.add_argument("--schedule", choices=("rotating", "balanced_three_mode_v2"), default="rotating")
    parser.add_argument("--correctness-only", action="store_true")
    parser.add_argument("--skip-diagnostics", action="store_true")
    parser.add_argument("--require-new-execution-profile", choices=("trusted_explicit",),
                        help="fail before timing unless af-new actually implements this profile")
    parser.add_argument("--worker-timeout", type=float, default=1800)
    parser.add_argument("--host", help="reuse an explicitly supplied experiment cluster; otherwise create one temporary cluster")
    parser.add_argument("--port", type=int, default=5432)
    parser.add_argument("--user", default="postgres")
    parser.add_argument("--database", default="caprls_af_pareto")
    args = parser.parse_args(argv)
    existed = Path(args.output_dir).exists()
    try:
        result = run_study(args)
        print(json.dumps({key: value for key, value in result.items() if key != "summary"}))
        return 0
    except Exception as exc:
        if not existed and Path(args.output_dir).is_dir():
            failure = Path(args.output_dir)/"failure.json"
            if not failure.exists():
                write_once(failure, {"status": "failed", "at": now(), "error": str(exc),
                                     "traceback": traceback.format_exc()})
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
