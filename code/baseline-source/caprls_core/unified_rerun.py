"""Write-once unified evaluation runner, October 2026.

This module does not change frozen drivers. Ordinary request measurements run
the admitted/costed SQL once; EXPLAIN ANALYZE and reference checks are outside
that interval. One process owns all database sampling.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

from .postgres_runner import PostgresEnv, PostgresTransactionSession, run_psql_command


def digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def write_once(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, default=str)
        handle.write("\n")


def run_once_sql(sql: str, pg_env: PostgresEnv, *, role: Optional[str] = None,
                 validation_sql: Optional[str] = None,
                 timeout_s: float = 7200) -> dict[str, Any]:
    """One ordinary SQL/fetch, with validation in the same RR transaction.

    Primary query wall starts after the persistent psql backend/transaction is
    ready and ends at commit; every comparator uses this boundary. Separate
    request wall includes opening/closing this backend. No query wrapper,
    result reference, or EXPLAIN ANALYZE is present in the primary interval.
    """
    outer = time.perf_counter()
    session = PostgresTransactionSession(pg_env, read_only=False,
                                         statement_timeout_s=timeout_s)
    opened = time.perf_counter()
    try:
        for statement in (
            "SET LOCAL search_path TO pg_catalog, public",
            "SET LOCAL jit = off",
            "SET LOCAL max_parallel_workers_per_gather = 0",
            "SET LOCAL plan_cache_mode = force_custom_plan",
            "SET LOCAL row_security = on",
        ):
            session.execute(statement)
        validation_started = time.perf_counter()
        if validation_sql:
            # Existing validation helper returns only semicolon-terminated
            # caprls_assert_artifact_valid SELECT statements, no bodies.
            for statement in validation_sql.split(";\n"):
                if statement.strip():
                    session.execute(statement.strip().rstrip(";"))
        validation_wall_ms = (time.perf_counter() - validation_started) * 1000
        if role:
            if not role.replace("_", "").isalnum():
                raise ValueError("invalid benchmark role")
            session.execute("SET LOCAL ROLE " + role)
        body_started = time.perf_counter()
        rows = session.execute(sql)
        body_wall_ms = (time.perf_counter() - body_started) * 1000
        identity = session.identity.to_dict()
        # commit() also closes the underlying persistent psql channel before
        # it returns; the final close() below is an idempotent safety cleanup.
        session.commit()
        finished = time.perf_counter()
        return {
            "wall_ms": (finished - opened) * 1000,
            "query_wall_ms": (finished - opened) * 1000,
            "request_wall_ms": (finished - outer) * 1000,
            "connection_open_wall_ms": (opened - outer) * 1000,
            "body_fetch_wall_ms": body_wall_ms,
            "validation_wall_ms": validation_wall_ms if validation_sql else 0.0,
            "rows_text": rows,
            "row_count": len(rows.splitlines()) if rows else 0,
            "result_digest": digest(rows),
            "sql_hash": digest(sql),
            "executed_sql_hash": digest(sql),
            "ordinary_query_executions": 1,
            "diagnostic_query_executions": 0,
            "transaction_identity": identity,
            "query_wall_scope": "ready_backend_setup_validation_query_fetch_commit",
        }
    finally:
        session.close()


class Context:
    def __init__(self, root: Path, run_dir: Path, pg_env: PostgresEnv):
        self.root, self.run_dir, self.pg_env = root, run_dir, pg_env
        self.campaign_id = run_dir.name

    def run_once_sql(self, sql: str, pg_env: Optional[PostgresEnv] = None,
                     **kwargs: Any) -> dict[str, Any]:
        return run_once_sql(sql, pg_env or self.pg_env, **kwargs)

    def append_event(self, event: Mapping[str, Any]) -> None:
        payload = {"campaign_id": self.campaign_id, "timestamp": now(), **event}
        with (self.run_dir / "records.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, default=str) + "\n")
            handle.flush()
            os.fsync(handle.fileno())


class CaptureBoundRunners:
    """Read-only observer of the existing per-bound-runner static verifier."""
    def __init__(self, e3: Any):
        self.e3, self.entries = e3, []

    def __enter__(self):
        self.original = self.e3._verify_e3_static
        def observe(template_id, sql, explain, *args, **kwargs):
            result = self.original(template_id, sql, explain, *args, **kwargs)
            self.entries.append({"template_id": template_id, "sql": sql,
                                 "sql_hash": digest(sql),
                                 "cost": explain[0]["Plan"]["Total Cost"],
                                 "static_status": result.status})
            return result
        self.e3._verify_e3_static = observe
        return self

    def __exit__(self, *args):
        self.e3._verify_e3_static = self.original


def vacuum_artifacts(pg_env: PostgresEnv) -> dict[str, Any]:
    names = [line for line in run_psql_command(
        "SELECT tablename FROM pg_tables WHERE schemaname='public' AND "
        "tablename IN ('auth_idx','auth_idx_keyed','artifact_dependencies') "
        "ORDER BY tablename", pg_env).splitlines() if line]
    for name in names:
        run_psql_command("VACUUM (ANALYZE) public." + name, pg_env)
    raw = run_psql_command(
        "SELECT coalesce(json_agg(row_to_json(x)),'[]'::json)::text FROM "
        "(SELECT relname,n_live_tup,n_dead_tup,pg_total_relation_size(relid) "
        "AS total_bytes FROM pg_stat_user_tables WHERE relname IN "
        "('auth_idx','auth_idx_keyed','artifact_dependencies') ORDER BY relname) x",
        pg_env)
    return {"maintenance": "untimed_vacuum_analyze_before_cell",
            "artifact_table_state": json.loads(raw)}


def prepare_sampling_environment(pg_env: PostgresEnv) -> None:
    """Scoped maintenance policy: never change the user's general databases."""
    if pg_env.database not in {"caprls_unified_e3", "caprls_unified_e10"}:
        raise ValueError("sampling preparation requires a dedicated unified experiment DB")
    run_psql_command(
        "SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE "
        "datname=current_database() AND backend_type='autovacuum worker'",
        pg_env)
    names = run_psql_command(
        "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename",
        pg_env).splitlines()
    for name in names:
        quoted = '"' + name.replace('"', '""') + '"'
        run_psql_command("ALTER TABLE public." + quoted +
                         " SET (autovacuum_enabled=false)", pg_env)


def _e3_select(context: Context, query: Any, policy: Any, build: tuple,
               manifest: Mapping[str, Any]) -> dict[str, Any]:
    from . import e3_main as e3
    from . import e3_sigmod_preview as preview
    started = time.perf_counter()
    protected = e3._protected_count(query, context.pg_env)
    local = int(run_psql_command(
        f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} "
        f"WHERE {e3._query_local_predicate(query)}", context.pg_env))
    predicate = e3._policy_predicate(query, policy)
    receipt = e3._collect_e3_planning_catalog_receipt(query, policy, context.pg_env)
    authorized = int(run_psql_command(
        f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} "
        f"WHERE {predicate}", context.pg_env))
    inputs_finished = time.perf_counter()
    with CaptureBoundRunners(e3) as capture:
        result, plan, _ = e3._plan_e3_admission_first(
            query=query, policy=policy, predicate=predicate, pg_env=context.pg_env,
            protected_rows=protected, query_local_rows=local,
            authorized_rows=build[1] or authorized, build_ms=build[0],
            keyed_artifact_rows=build[2],
            ranker=e3._ranker_from_manifest(context.root, manifest),
            registry=e3._e3_registry_from_manifest(manifest),
            planning_catalog_receipt=receipt)
    stopped = time.perf_counter()
    bound = plan["production_bound_runner"]
    template = e3._require_e3_selected_root_template(plan)
    sql = bound["runner_sql"]
    if bound["runner_sql_digest"] != e3._canonical_sha256({"exact_runner_sql": sql}):
        raise ValueError("selected SQL binding identity mismatch")
    if not any(item["sql"] == sql for item in capture.entries):
        raise ValueError("selected SQL was not observed in costed runners")
    source = e3._source_for_template(template)
    artifact_ids, expected = preview._artifact_validation_for(query, policy, source)
    spec = preview.ExecutionSpec(
        mode="admission-first", template_id=template,
        alternative=result.chosen_template.alternative, sql=sql, sql_source=source,
        result_columns=preview._result_columns_for(query),
        role=e3.E3_RLS_ROLE if source == "rls" else None,
        artifact_ids=artifact_ids, expected_artifact_json=expected)
    eligible = {item["template_id"] for item in
                plan["production_completed_root_eligibility"]["completed_roots"]}
    return {"spec": spec, "plan": plan, "result": result,
            "bound": dict(bound), "input_collection_wall_ms":
            (inputs_finished-started)*1000,
            "choice_core_wall_ms": (stopped-inputs_finished)*1000,
            "choice_total_wall_ms": (stopped-started)*1000,
            "candidates": [item for item in capture.entries
                           if item["template_id"] in eligible],
            "request_started": started}


def measure_e3_spec(context: Context, spec: Any) -> dict[str, Any]:
    from .e8b_study import _validation_statements
    validation = (_validation_statements(spec.artifact_ids, spec.expected_artifact_json)
                  if spec.artifact_ids else None)
    return context.run_once_sql(spec.sql, role=spec.role, validation_sql=validation)


def run_e3_case(context: Context, query: Any, policy: Any, manifest: Mapping[str, Any],
                *, warmup: int = 5, measured: int = 10) -> dict[str, Any]:
    from . import e3_main as e3
    from . import e3_sigmod_preview as preview
    from .baselines import normalize_mode_id
    case_id = f"E3_{query.query_id}_{policy.config_id}"
    predicate = e3._policy_predicate(query, policy)
    build = e3._build_artifact(query, policy, predicate, context.pg_env)
    e3._configure_native_rls(query, policy, context.pg_env)
    state = vacuum_artifacts(context.pg_env)
    state_id = digest(json.dumps(state, sort_keys=True))
    selected = _e3_select(context, query, policy, build, manifest)
    fixed = [preview._fixed_mode(query, policy, normalize_mode_id(mode))
             for mode in manifest["modes"] if normalize_mode_id(mode) != "admission-first"]
    specs = {item.mode: item.spec for item in fixed if item.spec is not None}
    reference_spec = preview.ExecutionSpec(
        mode="reference", template_id="independent", alternative="reference",
        sql=e3._e3_independent_result_reference_sql(query, policy),
        sql_source="direct", result_columns=preview._result_columns_for(query))
    reference = preview._canonicalize_live(reference_spec, context.pg_env)
    candidate_specs = {}
    for item in selected["candidates"]:
        source = e3._source_for_template(item["template_id"])
        ids, expected = preview._artifact_validation_for(query, policy, source)
        candidate_specs[item["template_id"]] = preview.ExecutionSpec(
            mode="candidate:"+item["template_id"], template_id=item["template_id"],
            alternative="admitted-candidate", sql=item["sql"], sql_source=source,
            result_columns=preview._result_columns_for(query),
            role=e3.E3_RLS_ROLE if source == "rls" else None,
            artifact_ids=ids, expected_artifact_json=expected)
    checked = set()
    for spec in [selected["spec"], *specs.values(), *candidate_specs.values()]:
        if digest(spec.sql) in checked:
            continue
        actual = preview._canonicalize_live(spec, context.pg_env)
        if actual.canonical_rows != reference.canonical_rows:
            raise ValueError(f"full result mismatch: {case_id}/{spec.mode}")
        checked.add(digest(spec.sql))
    context.append_event({"record_kind": "case_preflight", "family": "E3",
                          "case_id": case_id, "status": "pass", "state_id": state_id,
                          "state": state, "reference_digest": reference.result_digest,
                          "distinct_sql_correctness_checked": len(checked),
                          "admitted_candidate_ids": list(candidate_specs),
                          "unavailable_modes": [{"mode": item.mode,
                              "reason": item.unavailable_reason} for item in fixed
                              if item.spec is None]})
    modes = ["admission-first", *specs]
    sampled = 0
    for iteration in range(warmup + measured):
        phase = "warmup" if iteration < warmup else "measured"
        order = modes[iteration % len(modes):] + modes[:iteration % len(modes)]
        for mode in order:
            choice = None
            if mode == "admission-first":
                choice = _e3_select(context, query, policy, build, manifest)
                spec = choice["spec"]
            else:
                spec = specs[mode]
            observation = measure_e3_spec(context, spec)
            outer = ((time.perf_counter()-choice["request_started"])*1000
                     if choice else observation["request_wall_ms"])
            event = {"record_kind": "query", "family": "E3", "case_id": case_id,
                     "query_id": query.query_id, "policy_id": policy.config_id,
                     "mode": mode, "phase": phase, "iteration": iteration,
                     "status": "pass", "state_id": state_id,
                     "selected_candidate_id": spec.template_id,
                     "admitted_sql_hash": digest(spec.sql),
                     "costed_sql_hash": digest(spec.sql) if choice else None,
                     **observation, "request_wall_ms": outer}
            if choice:
                event.update({key: choice[key] for key in
                              ("choice_total_wall_ms", "choice_core_wall_ms",
                               "input_collection_wall_ms", "bound")})
                event["choice_sql_identity"] = "actual_costed_bound_runner"
            event.pop("rows_text", None)
            context.append_event(event)
            sampled += 1
        # Candidate pool uses costed bound runners, not template re-rendering.
        candidate_items = list(candidate_specs.items())
        offset = iteration % max(1, len(candidate_items))
        for template, spec in candidate_items[offset:] + candidate_items[:offset]:
            observation = measure_e3_spec(context, spec)
            observation.pop("rows_text", None)
            context.append_event({"record_kind": "candidate", "family": "E3",
                "case_id": case_id, "query_id": query.query_id,
                "policy_id": policy.config_id, "mode": spec.mode,
                "selected_candidate_id": template, "phase": phase,
                "iteration": iteration, "status": "pass", "admitted": True,
                "state_id": state_id, "admitted_sql_hash": digest(spec.sql),
                "costed_sql_hash": digest(spec.sql), **observation})
            sampled += 1
        print(json.dumps({"time": now(), "case": case_id, "iteration": iteration,
                          "phase": phase, "samples": sampled}), flush=True)
    result = {"family": "E3", "case_id": case_id, "status": "pass",
              "samples": sampled, "warmup": warmup, "measured": measured,
              "state": state, "reference_digest": reference.result_digest}
    write_once(context.run_dir / "receipts" / (case_id + ".json"), result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--e3-db", default="caprls_unified_e3")
    parser.add_argument("--e10-db", default="caprls_unified_e10")
    parser.add_argument("--pg-host", default="127.0.0.1")
    parser.add_argument("--pg-port", type=int, default=5432)
    parser.add_argument("--pg-user", default=os.environ.get("USER", "postgres"))
    parser.add_argument("--family", choices=["E3", "E10", "both"], default="both")
    parser.add_argument("--cases", nargs="*")
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--measured", type=int, default=10)
    parser.add_argument("--provision", action="store_true")
    parser.add_argument("--sampling-preparation", action="store_true")
    parser.add_argument("--detach", action="store_true",
                        help="launch independently with caffeinate, PID receipt, and log")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    run_dir = Path(args.output).resolve()
    if args.detach:
        launch_dir = root / "output/section65_unified_rerun_execution_2026-10-05/runner"
        launch_dir.mkdir(parents=True, exist_ok=True)
        log_path = launch_dir / (run_dir.name + ".log")
        command = ["/usr/bin/caffeinate", "-i", sys.executable, "-u", "-m",
                   "caprls_core.unified_rerun", *[arg for arg in sys.argv[1:]
                                                   if arg != "--detach"]]
        with log_path.open("x", encoding="utf-8") as log:
            child = subprocess.Popen(command, cwd=str(root), stdout=log,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        receipt = {"started_at": now(), "launcher_pid": child.pid,
                   "command": command, "output": str(run_dir), "log": str(log_path)}
        write_once(launch_dir / (run_dir.name + "_launch.json"), receipt)
        print(json.dumps(receipt), flush=True)
        return 0
    run_dir.mkdir(parents=True, exist_ok=False)
    from .selection_cost_e3 import load_family
    from .selection_cost_common import E3_MANIFEST
    from .baselines import normalize_mode_id
    from . import e10_study
    e3_inventory = load_family(root, root / E3_MANIFEST)
    expected_cases = {
        "E3": [f"E3_{q.query_id}_{p.config_id}" for q in e3_inventory["queries"]
               for p in e3_inventory["policies"]],
        "E10": [case.query_id for case in e10_study.CASES],
    }
    if args.family != "both":
        expected_cases = {args.family: expected_cases[args.family]}
    if args.cases:
        expected_cases = {family: [case for case in cases if case in args.cases]
                          for family, cases in expected_cases.items()}
    write_once(run_dir / "declaration.json", {
        "expected_cases": expected_cases,
        "expected_modes": {
            "E3": [normalize_mode_id(mode) for mode in e3_inventory["manifest"]["modes"]],
            "E10": sorted(e10_study.REQUIRED_MODES),
        }, "warmup_count": args.warmup, "measured_count": args.measured})
    write_once(run_dir / "protocol.json", {"schema": "unified-rerun-v1",
        "created_at": now(), "args": vars(args), "pid": os.getpid(),
        "query_scope": "ready_backend_setup_validation_query_fetch_commit",
        "request_scope": "AF inputs_choice_new_backend_validation_query_fetch_commit",
        "single_activity": True, "tie_band": [0.99, 1.01],
        "stable_choice_required_for_break_even": True,
        "sql_identity": "AF actual costed bound SQL; no count transform",
        "ordinary_executions_per_query_sample": 1})
    failures, completed = [], []
    families = ["E3", "E10"] if args.family == "both" else [args.family]
    for family in families:
        db = args.e3_db if family == "E3" else args.e10_db
        pg_env = PostgresEnv(args.pg_host, args.pg_port, args.pg_user, db)
        context = Context(root, run_dir, pg_env)
        if args.provision:
            from .content_psql import ContentPostgresEnv
            from .content_verify import provision_family
            detail = provision_family(root, family,
                ContentPostgresEnv(args.pg_host, args.pg_port, args.pg_user, db))
            write_once(run_dir / (family + "_provision.json"), detail)
        if args.sampling_preparation:
            prepare_sampling_environment(pg_env)
        config = run_psql_command(
            "SELECT json_build_object('server_version',version(),"
            "'shared_buffers',current_setting('shared_buffers'),"
            "'work_mem',current_setting('work_mem'),"
            "'autovacuum',current_setting('autovacuum'),"
            "'effective_cache_size',current_setting('effective_cache_size'),"
            "'database',current_database(), 'session_user',session_user)::text",
            pg_env)
        write_once(run_dir / (family + "_environment.json"), {
            "observed_at": now(), "postgres": json.loads(config),
            "driver_sha256": digest(Path(__file__).read_text()),
            "frozen_e3_sha256": digest((root / "caprls_core/e3_main.py").read_text()),
            "frozen_e10_sha256": digest((root / "caprls_core/e10_study.py").read_text())})
        if family == "E3":
            from .selection_cost_e3 import load_family
            from .selection_cost_common import E3_MANIFEST
            loaded = load_family(root, root / E3_MANIFEST)
            cases = [(q,p) for q in loaded["queries"] for p in loaded["policies"]]
            for query, policy in cases:
                sid = f"E3_{query.query_id}_{policy.config_id}"
                if args.cases and sid not in args.cases:
                    continue
                try:
                    completed.append(run_e3_case(context, query, policy,
                        loaded["manifest"], warmup=args.warmup, measured=args.measured))
                except Exception as exc:
                    failure = {"family": family, "case_id": sid, "status": "failed",
                               "error": str(exc), "traceback": traceback.format_exc()}
                    context.append_event({"record_kind": "failure", **failure})
                    failures.append(failure)
                    print(json.dumps(failure), flush=True)
                    # Identity/correctness errors stop before collecting an
                    # entire invalid cohort. Existing successful blocks persist.
                    if len(failures) >= 2:
                        break
        else:
            from . import unified_rerun_e10 as e10
            import yaml
            with (root / "manifests/experiments/e10_case_study.yaml").open() as handle:
                manifest = yaml.safe_load(handle)
            state = e10.prepare_e10(context, manifest)
            for case in e10.e10.CASES:
                sid = case.query_id
                if args.cases and sid not in args.cases:
                    continue
                try:
                    case_receipts = []
                    for iteration in range(args.warmup + args.measured):
                        phase = "warmup" if iteration < args.warmup else "measured"
                        block = e10.run_e10_case(context, state, case,
                            repetition=iteration, phase=phase)
                        state_id = digest(json.dumps({"context": dict(state.context),
                            "case": sid, "policy": block.get("planning_receipt")},
                            sort_keys=True, default=str))
                        if iteration == 0:
                            context.append_event({"record_kind": "case_preflight",
                                "family": "E10", "case_id": sid,
                                "status": "pass", "state_id": state_id,
                                "admitted_candidate_ids": [arm["template_id"]
                                    for arm in block["candidates"]],
                                "unavailable_modes": block["unavailable"],
                                "correctness": block["correctness"]})
                        # State id names the stable logical case state rather
                        # than volatile receipt/connection nonce identities.
                        state_id = digest(json.dumps({"context": dict(state.context),
                            "case": sid, "negative_kind":
                            e10.e10.E10_NEGATIVE_STATE_KIND_BY_QUERY.get(case.query_id)},
                            sort_keys=True, default=str))
                        for kind, arms in (("query", block["arms"]),
                                           ("candidate", block["candidates"])):
                            for arm in arms:
                                payload = {k:v for k,v in arm.items()
                                    if k not in ("rows_text", "sql")}
                                sql_hash = digest(arm["sql"])
                                payload.update({"record_kind": kind, "family": "E10",
                                    "case_id": sid, "query_id": case.query_id,
                                    "status": "pass", "phase": phase,
                                    "iteration": iteration, "state_id": state_id,
                                    "selected_candidate_id": arm["template_id"],
                                    "admitted_sql_hash": sql_hash,
                                    "costed_sql_hash": sql_hash if
                                    arm["template_id"] in block["cost_bindings"] else None,
                                    "executed_sql_hash": sql_hash,
                                    "admitted": True})
                                if arm.get("request_total_wall_ms") is not None:
                                    payload["request_wall_ms"] = arm["request_total_wall_ms"]
                                context.append_event(payload)
                        for arm in block["unavailable"]:
                            context.append_event({"record_kind": "query",
                                "family": "E10", "case_id": sid,
                                "phase": phase, "iteration": iteration,
                                "state_id": state_id, **arm,
                                "status": "not_applicable"})
                        block.pop("reference", None)
                        write_once(run_dir / "e10_blocks" /
                                   f"{sid}_{iteration:02d}.json", block)
                        case_receipts.append({"iteration": iteration,
                            "phase": phase, "choice": block["selected_template"],
                            "sql": block["selected_sql_sha256"]})
                        print(json.dumps({"time": now(), "case": sid,
                            "iteration": iteration, "phase": phase}), flush=True)
                    receipt = {"family": "E10", "case_id": sid,
                        "status": "pass", "iterations": case_receipts}
                    write_once(run_dir / "receipts" / (sid+".json"), receipt)
                    completed.append(receipt)
                except Exception as exc:
                    failure = {"family": family, "case_id": sid, "status": "failed",
                               "error": str(exc), "traceback": traceback.format_exc()}
                    context.append_event({"record_kind": "failure", **failure})
                    failures.append(failure)
                    print(json.dumps(failure), flush=True)
                    if len(failures) >= 2:
                        break
    write_once(run_dir / "completion.json", {"completed_at": now(),
               "completed": completed, "failures": failures,
               "status": "pass" if not failures else "incomplete"})
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
