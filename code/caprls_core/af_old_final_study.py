"""Independent complete-grid A007/final AF control; ordinary main results stay separate.

Clean script workers import each issuer from its declared tree. Execution routes
include the source key even for byte-identical specs. No SQL/profile is rewritten.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import time
import traceback
from typing import Any, Mapping, Sequence


FRAME = "AF_OLD_FINAL_WORKER_V1 "
OLD_DIGEST = "sha256:1cb4d8af928bb978f84291e15dd4af6647b4fa95018f955bbfde559a2c6e97e9"
TPCH = ("Q3", "Q5", "Q7", "Q10", "Q12")
JOB = ("JOB_1a", "JOB_2a", "JOB_3c", "JOB_6d", "JOB_10a", "JOB_16b")
POLICIES = ("cheap_tenant_sargable", "group_acl_expensive", "hybrid_selective_key")
MODES = ("old", "final")


def load_shared() -> Any:
    path = Path(__file__).with_name("final_af_e3_study.py")
    spec = importlib.util.spec_from_file_location("_af_old_final_shared", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def sha(data: bytes) -> str:
    return "sha256:"+hashlib.sha256(data).hexdigest()


def digest(value: Any) -> str:
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def dual_schedule(shared: Any) -> tuple[tuple[int, ...], ...]:
    rows = tuple(tuple(row) for row in shared.balanced_round_orders(2))
    flat = [mode for row in rows for mode in row]
    if (len(rows) != 4 or any(sorted(row) != [0,1] for row in rows)
            or Counter((m,p) for row in rows for p,m in enumerate(row)) != Counter({(m,p):2 for m in range(2) for p in range(2)})
            or Counter(zip([flat[-1]]+flat[:-1],flat)) != Counter({(a,b):2 for a in range(2) for b in range(2)})):
        raise ValueError("two-method cycle must balance positions and all predecessors in four rounds")
    return rows


def failure_details(exc: Exception) -> dict[str, Any]:
    def decoded(value):
        return value.decode(errors="replace") if isinstance(value,bytes) else value
    return {"error":str(exc), "traceback":traceback.format_exc(),
            "captured_stdout":decoded(getattr(exc,"stdout",None)),
            "captured_stderr":decoded(getattr(exc,"stderr",None))}


def workload_scope(manifest: Mapping[str, Any]) -> tuple[str, bool]:
    """Pin complete original grids and the actual archived A007 compositions."""
    queries = [row["query_id"] for row in manifest["queries"]]
    policies = [row["id"] for row in manifest["policy_configs"]]
    scales = {row["name"]: row["scale"] for row in manifest["datasets"]}
    if len(queries) != len(set(queries)) or len(policies) != 3 or set(policies) != set(POLICIES):
        raise ValueError("old/final comparison requires the complete original policy grid")
    if set(queries) == set(TPCH+JOB) and len(queries) == 11 and scales.get("tpch") == "SF1" and scales.get("job") == "full" and not manifest.get("scale_check"):
        family, old_materialized = "mixed", True
    elif set(queries) == set(TPCH) and len(queries) == 5 and scales.get("tpch") == "SF10" and scales.get("job") == "reduced_1500_title_4000_companies_8000_cast" and manifest.get("scale_check"):
        family, old_materialized = "sf10", False
    else:
        raise ValueError("manifest is not the complete original mixed33 or SF10 15 grid")
    declared = (manifest.get("scale_check") or {}).get("bound_runner_wrapper", "materialized")
    if declared != ("materialized" if old_materialized else "not_materialized_single_reference"):
        raise ValueError("manifest composition disagrees with archived A007 workload configuration")
    return family, old_materialized


def worker_payload(source: Path, request: Mapping[str, Any]) -> dict[str, Any]:
    shared = load_shared()
    before = shared.source_identity(source)
    operation = request["operation"]
    if operation == "execute":
        # This child-only default also makes independent references read-only;
        # matching-source scripts, profiles and guards themselves stay intact.
        os.environ["PGOPTIONS"] = os.environ.get("PGOPTIONS", "")+" -c default_transaction_read_only=on"
        nested = shared.execution_worker_payload(source, {
            "operation": request["execution_operation"], "spec": request["spec"], "pg_env": request["pg_env"]})
        if nested["source_identity"] != before or shared.source_identity(source) != before:
            raise ValueError("execution source identity changed")
        return {"schema":"af_old_final_worker_v1", "status":"pass", "source_identity":before,
                "operation":"execute", "execution_operation":request["execution_operation"],
                "read_only_session_default":True, "result":nested["result"]}
    e3, preview, _postgres = shared.activate_source(source)
    manifest_path = Path(request["manifest"])
    manifest = e3._load_manifest(manifest_path)
    e3._validate_manifest(manifest_path, manifest)
    workload_scope(manifest)
    queries = e3._queries_for_manifest(manifest_path, manifest)
    policies = e3._policies_for_manifest(manifest_path, manifest)
    if operation == "recipes":
        recipes = {}
        for query in queries:
            for policy in policies:
                predicate = e3._policy_predicate(query, policy)
                recipes[query.query_id+"__"+policy.config_id] = {
                    "artifact_id": e3._artifact_id(query, policy), "artifacts": policy.artifacts,
                    "protected_rel": query.protected_rel, "rid_col": query.rid_col,
                    "alias": query.alias, "key_name": query.key_name, "key_value": query.key_value,
                    "principal": e3.E3_PRINCIPAL_ID, "context_token": e3.E3_CONTEXT_TOKEN,
                    "predicate": predicate, "clear_sql": e3._clear_artifact_sql(e3._artifact_id(query, policy)),
                    "build_sql": None if policy.artifacts == "none" else e3._build_artifact_sql(query, policy, predicate),
                    "dependencies": e3._artifact_dependency_records(query, policy),
                    "expected_validator_input": e3._expected_artifact_json(query, policy),
                    "validator_body_sha256": sha(e3._e3_trusted_validator_body().encode()),
                }
        result = {"recipes": recipes, "queries": [q.query_id for q in queries],
                  "policies": [p.config_id for p in policies]}
    elif operation == "prepare_final":
        normal = importlib.import_module("caprls_core.normal_e3_af")
        Path(normal.__file__).resolve().relative_to(source)
        pg_env = _postgres.PostgresEnv(**request["pg_env"])
        prepared = normal.prepare_normal_e3_af(query_id=request["query_id"], policy_id=request["policy_id"],
            manifest_path=manifest_path, project_root=request["project_root"], pg_env=pg_env, stats=request["stats"])
        report = normal.prepared_report(prepared)
        executed = normal.execute_normal_e3_af(prepared)
        spec, bound = report["spec"], report["bound_runner"]
        if (executed.get("schema") != "normal_e3_af_execution_v1" or executed.get("status") != "executed"
                or executed.get("exact_bound_sql_sha256") != sha(spec["sql"].encode())
                or type(executed.get("query_body_executions")) is not int or executed["query_body_executions"] != 1
                or executed.get("independent_result_correctness_checked") is not False
                or report["metadata"].get("source_identity") != before):
            raise ValueError("normal final entry did not execute its exact admitted body")
        query = next(q for q in queries if q.query_id == request["query_id"])
        policy = next(p for p in policies if p.config_id == request["policy_id"])
        reference = preview.ExecutionSpec(mode="independent-reference", template_id="direct_independent_reference_v1",
            alternative="IndependentReference", sql=e3._e3_independent_result_reference_sql(query, policy),
            sql_source="direct-independent-reference", result_columns=preview._result_columns_for(query))
        plan = prepared.query_plan
        result = {"schema": "final_af_e3_worker_v1", "status": "pass", "spec": spec,
            "source_identity": before, "manifest_sha256": sha(manifest_path.read_bytes()),
            "reference": asdict(reference), "selection": {
                "selected_template_id": spec["template_id"], "selected_plan_id": bound["plan_id"],
                "selected_runner_digest": bound["runner_sql_digest"], "bound_runner": bound,
                "execution_profile": "trusted_explicit", "measured_runtime_used_for_selection": False,
                "normal_entry_used": True, "normal_entry_metadata": report["metadata"],
                "access_root_materialized_by_template": report["metadata"]["resolved_runtime_config"].get("access_root_materialized_by_template",{}),
                "normal_execution_check": executed, "selection_wall_ms": report["metadata"]["selection_wall_ms"],
                "catalog_receipt_wall_ms": report["metadata"]["catalog_receipt_wall_ms"],
                "complete_runner_costs": plan.get("production_candidate_costs", []),
                "root_selection_audit": plan["production_root_selection"],
                "access_root_layout_policy": plan.get("production_access_root_layout_policy"),
                "access_root_layouts": plan.get("production_access_root_layouts", []),
                "prospective_total_cost": plan["production_chosen_cost"]["prospective_total_cost"]}}
        shared.validate_af_bound_spec(result)
    else:
        raise ValueError("unsupported isolated old/final worker operation")
    if shared.source_identity(source) != before:
        raise RuntimeError("source changed during isolated old/final operation")
    return {"schema": "af_old_final_worker_v1", "status": "pass", "source_identity": before,
            "operation": operation, "execution_operation": request.get("execution_operation"),
            "read_only_session_default": operation == "execute", "result": result}


def run_owned_worker(source: Path, request: Mapping[str, Any], *, timeout_s: float) -> dict[str, Any]:
    started = time.perf_counter()
    proc = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", str(source)],
        input=json.dumps(request), text=True, capture_output=True, cwd=source, timeout=timeout_s)
    frames = [line[len(FRAME):] for line in proc.stdout.splitlines() if line.startswith(FRAME)]
    if len(frames) != 1:
        raise RuntimeError("invalid isolated worker frame: "+json.dumps({"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}))
    result = json.loads(frames[0])
    if (not isinstance(result, dict) or result.get("schema") != "af_old_final_worker_v1"
            or proc.returncode or result.get("status") != "pass" or result.get("operation") != request["operation"]):
        raise RuntimeError("isolated worker failed: "+json.dumps(result))
    result["worker_request_wall_ms"] = (time.perf_counter()-started)*1000
    return result


def artifact_build_signature(recipe: Mapping[str, Any]) -> dict[str, Any]:
    # alias/key_value describe a query's lookup, not the shared artifact build.
    fields = ("artifact_id", "artifacts", "protected_rel", "rid_col", "key_name", "principal", "context_token",
              "clear_sql", "build_sql", "dependencies", "expected_validator_input", "validator_body_sha256")
    return {key:recipe[key] for key in fields}


def compatible_recipes(old: Mapping[str, Any], final: Mapping[str, Any]) -> dict[str, Any]:
    if old != final:
        raise ValueError("old/final artifact recipes, namespaces or validator inputs differ; no shared build permitted")
    by_id = {}
    for case, recipe in old.items():
        key = recipe["artifact_id"]
        actual = artifact_build_signature(recipe)
        if key in by_id and by_id[key]["recipe"] != actual:
            raise ValueError("shared artifact ID has different within-source recipes: "+key)
        by_id.setdefault(key, {"recipe": actual, "representative_case": case, "cases": []})["cases"].append(case)
    return by_id


class Executor:
    """Explicit source+spec routes; identical specs never select another issuer."""
    def __init__(self, shared: Any, sources: Mapping[str, Path], identities: Mapping[str, Any],
                 pg_env: Mapping[str, Any], timeout_s: float, run_worker: Any = None):
        self.shared, self.sources, self.identities = shared, sources, identities
        self.pg_env, self.timeout_s, self.routes = pg_env, timeout_s, {}
        self.run_worker = run_owned_worker if run_worker is None else run_worker

    def register(self, source_key: str, spec: Mapping[str, Any]) -> None:
        key = (source_key, digest(spec))
        if source_key not in self.sources or (key in self.routes and self.routes[key] != spec):
            raise ValueError("invalid or conflicting source-specific execution route")
        self.routes[key] = json.loads(json.dumps(spec))

    def call(self, source_key: str, spec: Mapping[str, Any], operation: str) -> dict[str, Any]:
        key = (source_key, digest(spec))
        if key not in self.routes or self.routes[key] != spec:
            raise ValueError("unregistered exact source/spec route")
        worker = self.run_worker(self.sources[source_key], {
            "operation": "execute", "execution_operation": operation, "spec": spec, "pg_env": self.pg_env}, timeout_s=self.timeout_s)
        if (worker.get("source_identity") != self.identities[source_key] or worker.get("operation") != "execute"
                or worker.get("execution_operation") != operation or worker.get("read_only_session_default") is not True):
            raise ValueError("execution worker source/operation differs from explicit route")
        if not isinstance(worker.get("result"), Mapping):
            raise ValueError("invalid execution worker result")
        return {"result": worker["result"], "execution": {"source_key": source_key,
            "source_digest": self.identities[source_key]["digest"], "spec_digest": key[1],
            "operation": operation, "read_only_session_default": True,
            "execution_worker_wall_ms": worker["worker_request_wall_ms"]}}


def evaluate(cells: Sequence[Mapping[str, Any]], *, shared: Any, executor: Executor,
             output: Path, restore: Any, check_statistics: Any) -> list[dict[str, Any]]:
    """All complete result gates precede every warmup and formal sample."""
    write = shared.write_once
    orders = dual_schedule(shared)
    failed, reference_counts = [], {}
    for cell in cells:
        restore(cell)
        checks = {}
        for key in MODES:
            entry = cell["methods"][key]
            try:
                ref = executor.call(key, entry["reference"], "canonicalize")
                actual = executor.call(key, entry["spec"], "canonicalize")
                checks[key] = {"reference": ref, "actual": actual,
                    "status": "pass" if Counter(ref["result"]["canonical_rows"]) == Counter(actual["result"]["canonical_rows"]) else "mismatch"}
            except Exception as exc:
                checks[key] = {"status": "error", **failure_details(exc)}
        if all(checks[key]["status"] == "pass" for key in MODES):
            same = Counter(checks["old"]["reference"]["result"]["canonical_rows"]) == Counter(checks["final"]["reference"]["result"]["canonical_rows"])
            reference_counts[cell["case_id"]] = len(checks["old"]["reference"]["result"]["canonical_rows"])
        else:
            same = False
        if not same: failed.append(cell["case_id"])
        write(output/"correctness"/(cell["case_id"]+".json"), {"methods": checks, "references_equal": same})
        check_statistics()
    if failed:
        raise ValueError("full-result gate failed before any timing: "+", ".join(failed))
    summary = []
    for cell in cells:
        restore(cell)
        collected = {key: [] for key in MODES}; worker_walls = {key: [] for key in MODES}
        previous = None
        for round_index in range(36):
            check_statistics()
            phase = "warmup" if round_index < 4 else "measured"
            iteration = round_index+1 if phase == "warmup" else round_index-3
            for position, mode_index in enumerate(orders[round_index % 4]):
                key = MODES[mode_index]; entry = cell["methods"][key]
                metadata = {"case_id": cell["case_id"], "mode": key, "phase": phase,
                    "iteration": iteration, "round_index": round_index, "order_index": position,
                    "preceding_mode": previous, "sql_sha256": sha(entry["spec"]["sql"].encode()),
                    "source_digest": entry["source_digest"], "spec_digest": digest(entry["spec"])}
                path = output/"samples"/(cell["case_id"]+"__"+key+"__"+phase+f"{iteration:02d}.json")
                try:
                    observed = executor.call(key, entry["spec"], "measure")
                except Exception as exc:
                    write(path, {**metadata, "status": "error", "spec": entry["spec"], **failure_details(exc)})
                    raise
                write(path, {**metadata, "status": "pass", "measurement": observed["result"], "execution": observed["execution"]})
                previous = key
                if phase == "measured":
                    collected[key].append(observed["result"])
                    worker_walls[key].append(observed["execution"]["execution_worker_wall_ms"])
            check_statistics()
        for key in MODES:
            entry = cell["methods"][key]; values = collected[key]
            fields = ("execution_ms", "postgres_planning_ms", "server_validation_ms", "server_guard_body_execution_ms",
                      "server_query_plus_required_validation_observed_ms", "database_total_ms")
            summary.append({"case_id": cell["case_id"], "mode": key, "status": "pass",
                "reference_rows": reference_counts[cell["case_id"]], "warmup": 4, "measured": len(values),
                "template_id": entry["spec"]["template_id"], "source_digest": entry["source_digest"],
                "medians_ms": {field: statistics.median(row[field] for row in values) for field in fields},
                "median_execution_worker_wall_ms": statistics.median(worker_walls[key]),
                "selection_wall_ms": entry["selection"].get("selection_wall_ms"),
                "catalog_receipt_wall_ms": entry["selection"].get("catalog_receipt_wall_ms"),
                "input_collection_wall_ms_shared": cell["stats"]["input_collection_wall_ms"],
                "choice_scope": "source-native prospective stage; final normal API metadata and old collector scopes retained separately",
                "artifact_build_ms_shared": cell["stats"]["artifact_build_ms"]})
            write(output/"diagnostics"/(cell["case_id"]+"__"+key+".json"), executor.call(key, entry["spec"], "diagnostic"))
        check_statistics()
    return summary


def run_study(args: argparse.Namespace) -> dict[str, Any]:
    shared = load_shared()
    root, output = Path(args.root).resolve(), Path(args.output_dir).resolve()
    if not any(output != base and output.is_relative_to(base) for base in (root/"AF-wiki/raw/experiments", root/"results/raw")):
        raise ValueError("comparison output must be a new retained experiment directory")
    output.mkdir(parents=True, exist_ok=False)
    sources = {"old": Path(args.old_source).resolve(), "final": Path(args.final_source).resolve()}
    identities = {key: shared.source_identity(path) for key, path in sources.items()}
    if identities["old"]["digest"] != OLD_DIGEST:
        raise ValueError("old source is not the preserved A007 anchor")
    if not (sources["final"]/"caprls_core/normal_e3_af.py").is_file():
        raise ValueError("final source lacks its normal AF API")
    manifest_path = Path(args.manifest)
    manifest_path = (root/manifest_path).resolve() if not manifest_path.is_absolute() else manifest_path.resolve()
    manifest_raw = manifest_path.read_bytes(); manifest_hash = sha(manifest_raw)
    e3, _preview, postgres = shared.activate_source(sources["final"])
    normal = importlib.import_module("caprls_core.normal_e3_af")
    config = normal.load_runtime_config()
    final_layouts = shared.validate_access_root_materialized_by_template(config.get("access_root_materialized_by_template"))
    manifest = e3._load_manifest(manifest_path); e3._validate_manifest(manifest_path, manifest)
    family, old_materialized = workload_scope(manifest)
    e3.require_e3_manifest_data(root, manifest_path, manifest)
    queries, policies = e3._queries_for_manifest(manifest_path, manifest), e3._policies_for_manifest(manifest_path, manifest)
    driver_paths = (Path(__file__).resolve(), Path(shared.__file__).resolve())
    driver_hashes = {str(path): sha(path.read_bytes()) for path in driver_paths}
    protocol = {"schema": "af_old_final_study_v1", "started_at": shared.now(), "family": family,
        "manifest": str(manifest_path), "manifest_sha256": manifest_hash,
        "sources": identities, "queries": [q.query_id for q in queries], "policies": [p.config_id for p in policies],
        "methods": MODES, "old_runtime": {"access_root_materialized": old_materialized,
            "access_root_materialized_by_template": {}, "profile": "trusted_explicit", "normal_api": "not_available"},
        "final_runtime_config": config, "final_normal_exact_body_check": True,
        "cycle_rounds": 4, "warmup_cycles": 1, "formal_cycles": 8, "warmup_rounds": 4, "formal_rounds": 32,
        "bootstrap_draws":10000, "bootstrap_seed":20261028,
        "orders": dual_schedule(shared), "driver_hashes": driver_hashes,
        "primary_metric": "median PostgreSQL query Execution Time; old/final, fixed-grid equal-case-weight GM",
        "normal_check_scope": "final one extra exact-body execution after choice, not formal timing or independent correctness; old does not acquire normal API coverage",
        "execution_session_default": "default_transaction_read_only=on inside each execution child; source profile/guards unchanged",
        "companion_cost_scope": {"database_total_ms":"historical raw name for complete psql client wall time; includes server work",
            "execution_worker_wall_ms":"whole isolated worker request including import, source checks, psql/client/server work; infrastructure-inclusive, never added to SQL metric"},
        "comparison_scope": "internal old AF anchor; does not replace ordinary baseline main results or their independent confirmation"}
    shared.write_once(output/"protocol.json", protocol)
    (output/"input-manifest.yaml").write_bytes(manifest_raw)
    for path in driver_paths:
        target = output/"driver-source"/path.name; target.parent.mkdir(exist_ok=True)
        with target.open("xb") as handle: handle.write(path.read_bytes())
    recipe_reports = {}
    for key in MODES:
        report = run_owned_worker(sources[key], {"operation": "recipes", "manifest": str(manifest_path)}, timeout_s=args.worker_timeout)
        if report["source_identity"] != identities[key]: raise ValueError("recipe worker source identity differs")
        recipe_reports[key] = report
        shared.write_once(output/"recipes"/(key+".json"), report)
    for key in MODES:
        if recipe_reports[key]["result"]["queries"] != protocol["queries"] or recipe_reports[key]["result"]["policies"] != protocol["policies"]:
            raise ValueError("source query/policy order differs from declared complete grid: "+key)
    compatible = compatible_recipes(recipe_reports["old"]["result"]["recipes"], recipe_reports["final"]["result"]["recipes"])
    shared.write_once(output/"artifact-compatibility.json", {"status": "pass", "recipes": compatible})
    scales = {row["name"]: row["scale"] for row in manifest["datasets"]}
    with postgres.temporary_cluster(database="caprls_old_final") as pg_env:
        started = time.perf_counter()
        version = e3._prepare_database(root, pg_env, tpch_scale=scales["tpch"], job_scale=scales["job"])
        shared.write_once(output/"database.json", {"pg_env": asdict(pg_env), "version": version,
            "setup_wall_ms": (time.perf_counter()-started)*1000, "scales": scales})
        artifacts = shared.prepare_artifacts(e3, postgres, queries, policies, pg_env)
        shared.write_once(output/"shared_artifacts.json", artifacts)
        frozen_stats = shared.statistics_identity(postgres, pg_env)
        shared.write_once(output/"statistics_before_selection.json", frozen_stats)
        def check_statistics():
            if shared.statistics_identity(postgres, pg_env) != frozen_stats:
                raise RuntimeError("common catalog statistics drifted; no rebuild or retry is allowed")
            if any(shared.source_identity(path) != identities[key] for key,path in sources.items()):
                raise RuntimeError("old/final source identity drifted; no source substitution is allowed")
        cells = []
        executor = Executor(shared, sources, identities, asdict(pg_env), args.worker_timeout)
        for query in queries:
            for policy in policies:
                case = query.query_id+"__"+policy.config_id
                print("prepare "+case, flush=True); check_statistics()
                e3._configure_native_rls(query, policy, pg_env)
                artifact = artifacts[e3._artifact_id(query, policy)]
                counts_started = time.perf_counter()
                stats = {"protected_rows": e3._protected_count(query, pg_env),
                    "query_local_rows": int(postgres.run_psql_command(f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} WHERE {e3._query_local_predicate(query)}", pg_env)),
                    "authorized_rows": int(postgres.run_psql_command(f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} WHERE {e3._policy_predicate(query, policy)}", pg_env)),
                    "keyed_artifact_rows": artifact["keyed_artifact_rows"], "artifact_build_ms": artifact["artifact_build_ms"]}
                stats["input_collection_wall_ms"] = (time.perf_counter()-counts_started)*1000
                request = {"project_root": str(root), "manifest": str(manifest_path), "query_id": query.query_id,
                    "policy_id": policy.config_id, "stats": stats, "pg_env": asdict(pg_env)}
                try:
                    old = shared.run_worker(sources["old"], {**request, "variant": "af", "worker_kind": "af",
                        "required_execution_profile": "trusted_explicit", "access_root_materialized": old_materialized,
                        "access_root_materialized_by_template": {}, "verify_normal_execution": False}, timeout_s=args.worker_timeout)
                except Exception as exc:
                    shared.write_once(output/"prepared"/case/"old-error.json", {"source":identities["old"], "request":request, **failure_details(exc)})
                    raise
                try:
                    final_report = run_owned_worker(sources["final"], {**request, "operation": "prepare_final"}, timeout_s=args.worker_timeout)
                except Exception as exc:
                    shared.write_once(output/"prepared"/case/"final-error.json", {"source":identities["final"], "request":request, **failure_details(exc)})
                    raise
                if final_report["source_identity"] != identities["final"]: raise ValueError("final prepare source drifted")
                payloads = {"old": old, "final": final_report["result"]}; methods = {}
                columns = old["reference"]["result_columns"]
                if not columns or any(payload[part]["result_columns"] != columns for payload in payloads.values() for part in ("spec","reference")):
                    raise ValueError("old/final result contracts differ")
                for key, payload in payloads.items():
                    if payload["source_identity"] != identities[key] or payload["manifest_sha256"] != manifest_hash:
                        raise ValueError("prepared source/manifest differs")
                    shared.validate_af_bound_spec(payload)
                    template = payload["spec"]["template_id"]
                    expected_mat = old_materialized if key == "old" else final_layouts.get(template, config["access_root_wrapper"] == "materialized")
                    match = re.match(r"\AWITH caprls_access_root AS (NOT )?MATERIALIZED \(", payload["spec"]["sql"])
                    if match is None or (match.group(1) is None) != expected_mat: raise ValueError("actual selected wrapper differs from its source configuration")
                    if key == "old" and payload["selection"].get("normal_entry_used", False): raise ValueError("A007 must not acquire a transplanted normal API")
                    if key == "final" and payload["selection"]["normal_entry_metadata"]["resolved_runtime_config"] != config:
                        raise ValueError("final worker did not use its unchanged source preset")
                    shared.write_once(output/"prepared"/case/(key+".json"), payload)
                    entry = {"spec": payload["spec"], "reference": payload["reference"], "selection": payload["selection"],
                             "source_digest": identities[key]["digest"], "source_key": key}
                    for spec in (entry["spec"], entry["reference"]): executor.register(key, spec)
                    generated = executor.call(key, entry["spec"], "script")
                    path = output/"measurement-scripts"/case/(key+".sql"); path.parent.mkdir(parents=True, exist_ok=True)
                    with path.open("x") as handle: handle.write(generated["result"]["script"])
                    entry["measurement_script_sha256"] = sha(path.read_bytes())
                    entry["script_execution_route"] = generated["execution"]
                    methods[key] = entry
                    check_statistics()
                cell = {"case_id": case, "query_id": query.query_id, "policy_id": policy.config_id, "stats": stats, "methods": methods}
                shared.write_once(output/"prepared"/case/"shared.json", cell); cells.append(cell)
        by_query, by_policy = {q.query_id:q for q in queries}, {p.config_id:p for p in policies}
        def restore(cell):
            check_statistics(); e3._configure_native_rls(by_query[cell["query_id"]], by_policy[cell["policy_id"]], pg_env)
        summary = evaluate(cells, shared=shared, executor=executor, output=output, restore=restore, check_statistics=check_statistics)
        check_statistics(); shared.write_once(output/"statistics_after_sampling.json", shared.statistics_identity(postgres, pg_env))
    after = {key:shared.source_identity(path) for key,path in sources.items()}
    if after != identities or sha(manifest_path.read_bytes()) != manifest_hash or any(sha(Path(path).read_bytes()) != value for path,value in driver_hashes.items()):
        raise RuntimeError("source, manifest or driver changed; comparison is not promotable")
    shared.write_once(output/"sources_after.json", after)
    result = {"schema": "af_old_final_summary_v1", "status": "completed", "finished_at": shared.now(),
              "family": family, "cases": len(cells), "summary": summary}
    shared.write_once(output/"summary.json", result)
    return result


def analyze_run(input_dir: Path, *, draws: int = 10000, seed: int = 20261028) -> dict[str, Any]:
    """Audit retained exact sources/specs/samples before paired fixed-grid analysis."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from caprls_core import final_af_e3_analyze as analysis
    from caprls_core.af_pareto_analyze import canonical_bag, execution_profile_audit, inventory, require, source_digest
    shared = load_shared()
    root = input_dir.resolve(); initial = inventory(root)
    read = lambda name: json.loads((root/name).read_text())
    require(not (root/"failure.json").exists(), "comparison has a failure receipt")
    protocol, terminal = read("protocol.json"), read("summary.json")
    require(protocol["schema"] == "af_old_final_study_v1" and terminal["schema"] == "af_old_final_summary_v1"
            and terminal["status"] == "completed" and protocol["methods"] == list(MODES), "comparison is not completed or has different methods")
    require(protocol["final_normal_exact_body_check"] is True, "final normal exact-body check was not declared")
    require(draws == protocol["bootstrap_draws"] == 10000 and seed == protocol["bootstrap_seed"], "analysis differs from predeclared bootstrap settings")
    require(protocol["cycle_rounds"] == 4 and protocol["warmup_rounds"] == 4 and protocol["formal_rounds"] == 32 and protocol["formal_cycles"] == 8, "declared budget differs")
    orders = protocol["orders"]
    require(len(orders) == 4 and all(sorted(row) == [0,1] for row in orders), "invalid two-method cycle")
    flat = [i for row in orders for i in row]
    require(Counter(zip([flat[-1]]+flat[:-1],flat)) == Counter({(a,b):2 for a in range(2) for b in range(2)}) and
            Counter((m,p) for row in orders for p,m in enumerate(row)) == Counter({(m,p):2 for m in range(2) for p in range(2)}), "unbalanced complete cycle")
    sources = protocol["sources"]
    require(set(sources) == set(MODES), "source declarations differ")
    for key in MODES: source_digest(sources[key], key)
    require(sources["old"]["digest"] == OLD_DIGEST and read("sources_after.json") == sources, "source identity drift")
    require(sha((root/"input-manifest.yaml").read_bytes()) == protocol["manifest_sha256"], "input manifest changed")
    archived_drivers = {Path(path).name:value for path,value in protocol["driver_hashes"].items()}
    require(len(protocol["driver_hashes"]) == len(archived_drivers) == 2 and set(archived_drivers) == {"af_old_final_study.py","final_af_e3_study.py"}, "driver declarations differ")
    for name,value in archived_drivers.items():
        require(sha((root/"driver-source"/name).read_bytes()) == value, "archived driver differs: "+name)
    manifest = shared.yaml.safe_load((root/"input-manifest.yaml").read_text())
    family, old_materialized = workload_scope(manifest)
    require(family == protocol["family"] and [q["query_id"] for q in manifest["queries"]] == protocol["queries"]
            and [p["id"] for p in manifest["policy_configs"]] == protocol["policies"], "archived input grid differs from protocol")
    require(protocol["old_runtime"] == {"access_root_materialized":old_materialized,
        "access_root_materialized_by_template":{}, "profile":"trusted_explicit", "normal_api":"not_available"}, "A007 runtime differs from actual workload configuration")
    before, after = read("statistics_before_selection.json"), read("statistics_after_sampling.json")
    require(before == after and before["digest"] == digest(before["catalog_statistics"]), "statistics changed")
    require(read("artifact-compatibility.json")["status"] == "pass", "shared recipes not verified")
    recipes = {key:read("recipes/"+key+".json") for key in MODES}
    for key in MODES:
        require(recipes[key]["source_identity"] == sources[key] and recipes[key]["operation"] == "recipes"
                and recipes[key]["result"]["queries"] == protocol["queries"] and recipes[key]["result"]["policies"] == protocol["policies"], "recipe source/operation/grid differs")
    compatible = compatible_recipes(recipes["old"]["result"]["recipes"], recipes["final"]["result"]["recipes"])
    require(read("artifact-compatibility.json")["recipes"] == compatible, "retained compatibility report differs from recipes")
    cases = [q+"__"+p for q in protocol["queries"] for p in protocol["policies"]]
    require(len(cases) == (33 if protocol["family"] == "mixed" else 15) and terminal["cases"] == len(cases), "incomplete declared grid")
    pg_env = read("database.json")["pg_env"]
    expected_samples, expected_diagnostics, vectors, normal_checks = set(), set(), {}, []
    expected_rows = {(case,key) for case in cases for key in MODES}
    rows = {(row["case_id"],row["mode"]):row for row in terminal["summary"]}
    require(set(rows) == expected_rows and len(terminal["summary"]) == len(expected_rows), "terminal summary grid differs")
    for case in cases:
        cell = read("prepared/"+case+"/shared.json"); checked = read("correctness/"+case+".json")
        require(cell["case_id"] == case and cell["query_id"]+"__"+cell["policy_id"] == case
                and set(cell["methods"]) == set(MODES) and set(checked["methods"]) == set(MODES)
                and checked["references_equal"] is True, "prepared grid or independent references differ")
        row_count = None; profiles = {}
        columns = cell["methods"]["old"]["reference"]["result_columns"]
        require(bool(columns) and all(entry[part]["result_columns"] == columns for entry in cell["methods"].values() for part in ("spec","reference")), "source result contracts differ")
        for key in MODES:
            entry = cell["methods"][key]; prepared = read("prepared/"+case+"/"+key+".json")
            require(prepared["source_identity"] == sources[key] and prepared["manifest_sha256"] == protocol["manifest_sha256"]
                    and prepared["spec"] == entry["spec"] and prepared["reference"] == entry["reference"] and prepared["selection"] == entry["selection"]
                    and entry["source_key"] == key and entry["source_digest"] == sources[key]["digest"], "prepared identities differ")
            shared.validate_af_bound_spec(prepared)
            profiles[key] = execution_profile_audit(entry["spec"], entry["selection"], query=cell["query_id"], policy=cell["policy_id"], pg_env=pg_env, required_profile="trusted_explicit", label=case+":"+key)
            if key == "old":
                require(entry["selection"].get("normal_entry_used",False) is False and entry["selection"].get("normal_execution_check") is None, "old AF acquired normal API coverage")
                layout_protocol = {"access_root_wrapper":"materialized" if old_materialized else "not_materialized_single_reference"}
            else:
                config = protocol["final_runtime_config"]
                require(entry["selection"]["normal_entry_metadata"]["resolved_runtime_config"] == config, "final resolved preset differs")
                layout_protocol = {"current_source":sources[key], "manifest":protocol["manifest"], "manifest_sha256":protocol["manifest_sha256"],
                    "access_root_wrapper":config["access_root_wrapper"], "access_root_materialized_by_template":config.get("access_root_materialized_by_template",{}),
                    "normal_entry_execution_check":True}
                normal_checks.append(analysis.normal_entry_audit(layout_protocol,entry["spec"],entry["selection"],profiles[key],query=cell["query_id"],policy=cell["policy_id"],label=case))
            wrapper = analysis.access_root_wrapper_audit(layout_protocol,entry["spec"]["sql"],case,template_id=entry["spec"]["template_id"])
            if key == "final": analysis.access_root_layout_policy_audit(layout_protocol,entry["selection"],wrapper,case)
            item = checked["methods"][key]
            require(item["status"] == "pass", "full result check not passed")
            for label in ("reference", "actual"):
                envelope = item[label]; route = envelope["execution"]
                spec = entry["reference"] if label == "reference" else entry["spec"]
                require(route["source_key"] == key and route["source_digest"] == sources[key]["digest"] and route["spec_digest"] == digest(spec)
                        and route["operation"] == "canonicalize" and route["read_only_session_default"] is True, "canonical result crossed source route")
            reference = canonical_bag(item["reference"]["result"], case+key+" reference")
            require(reference == canonical_bag(item["actual"]["result"], case+key+" actual"), "full result mismatch")
            require(row_count is None or row_count == sum(reference.values()), "reference cardinality differs")
            row_count = sum(reference.values())
            script = root/"measurement-scripts"/case/(key+".sql")
            require(sha(script.read_bytes()) == entry["measurement_script_sha256"] and entry["spec"]["sql"] in script.read_text(), "measurement script differs")
            route = entry["script_execution_route"]
            require(route["source_key"] == key and route["source_digest"] == sources[key]["digest"] and route["spec_digest"] == digest(entry["spec"])
                    and route["operation"] == "script" and route["read_only_session_default"] is True, "script crossed source route")
        old_ref = checked["methods"]["old"]["reference"]["result"]
        final_ref = checked["methods"]["final"]["reference"]["result"]
        require(canonical_bag(old_ref,case) == canonical_bag(final_ref,case), "source reference bags differ")
        values, companions, worker_walls, counts = {key:[] for key in MODES}, {key:[] for key in MODES}, {key:[] for key in MODES}, Counter()
        previous = None
        for round_index in range(36):
            phase = "warmup" if round_index < 4 else "measured"; iteration = round_index+1 if phase == "warmup" else round_index-3
            for position, index in enumerate(orders[round_index % 4]):
                key = MODES[index]; entry = cell["methods"][key]
                path = "samples/"+case+"__"+key+"__"+phase+f"{iteration:02d}.json"; expected_samples.add(path); sample = read(path)
                require((sample["status"],sample["case_id"],sample["mode"],sample["phase"],sample["iteration"],sample["round_index"],sample["order_index"],sample["preceding_mode"]) == ("pass",case,key,phase,iteration,round_index,position,previous), "sample status/order differs")
                require(sample["sql_sha256"] == sha(entry["spec"]["sql"].encode()) and sample["source_digest"] == sources[key]["digest"] and sample["spec_digest"] == digest(entry["spec"]), "sample source/SQL differs")
                route = sample["execution"]
                require(route["source_key"] == key and route["source_digest"] == sources[key]["digest"] and route["spec_digest"] == digest(entry["spec"])
                        and route["operation"] == "measure" and route["read_only_session_default"] is True, "measurement crossed source route")
                analysis.audit_measurement(sample["measurement"], entry["spec"], entry["measurement_script_sha256"], profiles[key], path, reference_rows=row_count)
                counts[(key,phase)] += 1
                if phase == "measured":
                    values[key].append(sample["measurement"]["execution_ms"]); companions[key].append(sample["measurement"])
                    worker_walls[key].append(route["execution_worker_wall_ms"])
                previous = key
        for key in MODES:
            entry, row = cell["methods"][key], rows[(case,key)]
            require(counts[(key,"warmup")] == row["warmup"] == 4 and counts[(key,"measured")] == row["measured"] == 32
                    and row["status"] == "pass" and row["reference_rows"] == row_count
                    and row["template_id"] == entry["spec"]["template_id"] and row["source_digest"] == sources[key]["digest"], "summary identity/counts differ")
            expected_medians = {field:statistics.median(sample[field] for sample in companions[key]) for field in
                ("execution_ms","postgres_planning_ms","server_validation_ms","server_guard_body_execution_ms","server_query_plus_required_validation_observed_ms","database_total_ms")}
            require(row["medians_ms"] == expected_medians and row["selection_wall_ms"] == entry["selection"].get("selection_wall_ms")
                    and row["median_execution_worker_wall_ms"] == statistics.median(worker_walls[key])
                    and row["catalog_receipt_wall_ms"] == entry["selection"].get("catalog_receipt_wall_ms")
                    and row["input_collection_wall_ms_shared"] == cell["stats"]["input_collection_wall_ms"]
                    and row["artifact_build_ms_shared"] == cell["stats"]["artifact_build_ms"], "summary companion medians/stages differ from raw records")
            path = "diagnostics/"+case+"__"+key+".json"; expected_diagnostics.add(path)
            diagnostic = read(path); route = diagnostic["execution"]; result = diagnostic["result"]
            require(route["source_key"] == key and route["source_digest"] == sources[key]["digest"] and route["spec_digest"] == digest(entry["spec"])
                    and route["operation"] == "diagnostic" and route["read_only_session_default"] is True
                    and result["sql"] == entry["spec"]["sql"] and result["sql_sha256"] == sha(entry["spec"]["sql"].encode())
                    and result["role"] == entry["spec"]["role"], "diagnostic source/SQL/role differs")
            analysis.execution_environment_audit(result["execution_environment"], profiles[key], path)
            require(result["artifact_validation_required"] is bool(entry["spec"].get("artifact_ids"))
                    and isinstance(result["explain"], list) and len(result["explain"]) == 1
                    and isinstance(result["explain"][0].get("Plan"), dict), "diagnostic plan or validation declaration differs")
        vectors[case] = (values["final"], values["old"])
    actual_samples = {str(p.relative_to(root)) for p in (root/"samples").glob("*.json")}
    require(actual_samples == expected_samples, "missing or extra samples")
    require({str(p.relative_to(root)) for p in (root/"diagnostics").glob("*.json")} == expected_diagnostics, "missing or extra diagnostics")
    analysis._expected_paths(root, "prepared", {"prepared/"+case+"/"+name+".json" for case in cases for name in ("old","final","shared")})
    analysis._expected_paths(root, "correctness", {"correctness/"+case+".json" for case in cases})
    analysis._expected_paths(root, "measurement-scripts", {"measurement-scripts/"+case+"/"+key+".sql" for case in cases for key in MODES})
    comparison = analysis.compare_vectors(vectors, draws=draws, seed=seed, label="old_over_final", cycles={case:4 for case in cases})
    require(len(comparison["cycle_sensitivity"]) == 8 and all(row["case_count"] == len(cases) for row in comparison["cycle_sensitivity"]), "incomplete cycle sensitivity grid")
    require(inventory(root) == initial, "comparison input changed during analysis")
    return {"schema":"af_old_final_analysis_v1", "analysis_ready":True, "family":protocol["family"],
        "protocol":protocol, "input_inventory":initial, "input_inventory_digest":digest(initial),
        "metric":"PostgreSQL query Execution Time; old/final >1 favors final", "comparison":comparison,
        "comparison_helper_roles":{"af":"final", "baseline":"old", "ratio":"old/final"},
        "classification_meanings":{"W":"interval strictly above one", "L":"interval strictly below one", "N":"interval includes one; no equivalence or non-degradation conclusion"},
        "summary_rows":terminal["summary"], "analysis_helper_sha256":sha(Path(analysis.__file__).read_bytes()),
        "final_normal_entry_checks":normal_checks, "old_normal_entry_coverage":"not_available; not claimed",
        "limitations":["Internal old AF control does not replace ordinary baseline main results or independent confirmation.",
            "Paired-round bootstrap does not preserve cross-round dependence; eight cycles are descriptive sensitivity, not independent rebuilds.",
            "A confidence interval covering one is not evidence of non-degradation; no margin or stopping rule is changed."]}


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if __package__:
        return subprocess.run([sys.executable,"-B",str(Path(__file__).resolve()),*argv], cwd=Path(__file__).resolve().parents[1]).returncode
    if argv and argv[0] == "--worker":
        try:
            result = worker_payload(Path(argv[1]).resolve(), json.load(sys.stdin)); code = 0
        except Exception as exc:
            result = {"status":"error","error":str(exc),"traceback":traceback.format_exc()}; code = 1
        print(FRAME+json.dumps(result)); return code
    parser = argparse.ArgumentParser(description=__doc__); sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--root", default="."); run.add_argument("--old-source", required=True)
    run.add_argument("--final-source", required=True); run.add_argument("--manifest", required=True)
    run.add_argument("--output-dir", required=True); run.add_argument("--worker-timeout",type=float,default=1800)
    audit = sub.add_parser("analyze"); audit.add_argument("--input-dir",required=True)
    audit.add_argument("--output-dir",required=True); audit.add_argument("--bootstrap-draws",type=int,default=10000)
    audit.add_argument("--seed",type=int,default=20261028)
    args = parser.parse_args(argv); output = Path(args.output_dir).resolve(); existed = output.exists()
    try:
        if args.command == "run": result = run_study(args)
        else:
            source = Path(args.input_dir).resolve()
            if output == source or source in output.parents or output.exists(): raise ValueError("analysis output must be fresh and outside immutable input")
            result = analyze_run(source, draws=args.bootstrap_draws, seed=args.seed)
            output.mkdir(parents=True,exist_ok=False)
            (output/"analysis.json").write_text(json.dumps(result,indent=2)+"\n")
            (output/"report.md").write_text("# Internal old/final AF comparison\n\n"+json.dumps(result["comparison"],indent=2)+"\n\n"+"\n".join(result["limitations"])+"\n")
        print(json.dumps({k:v for k,v in result.items() if k in ("schema","status","analysis_ready","family","cases")})); return 0
    except Exception as exc:
        if args.command == "run" and not existed and output.is_dir():
            load_shared().write_once(output/"failure.json", {"status":"failed",**failure_details(exc)})
        elif args.command == "analyze" and not existed and output != Path(args.input_dir).resolve() and Path(args.input_dir).resolve() not in output.parents:
            output.mkdir(parents=True,exist_ok=False)
            (output/"analysis.json").write_text(json.dumps({"schema":"af_old_final_analysis_v1","analysis_ready":False,
                "performance_statistics":None,**failure_details(exc)},indent=2)+"\n")
        print(str(exc),file=sys.stderr); return 1


if __name__ == "__main__": raise SystemExit(main())
