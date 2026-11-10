"""V2 write-once server-time campaign; V1 and frozen drivers stay unchanged.

Primary samples execute the actual SQL through one TIMING OFF EXPLAIN ANALYZE.
Correctness fetches are separate, untimed observations.  Formal sampling uses
an explicit author-approved casewise resolution declaration. Historical pilot
gate failures are retained; they are not relabeled as passing.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import traceback
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

from .postgres_runner import PostgresEnv, run_psql_command
from .unified_rerun import (
    CaptureBoundRunners, Context as OrdinaryContext, _e3_select, digest, now,
    prepare_sampling_environment, vacuum_artifacts, write_once,
)


class Context(OrdinaryContext):
    """Explicitly separate correctness fetch from instrumented server sample."""

    def __init__(self, root, run_dir, pg_env, sampling_declaration=None):
        super().__init__(root, run_dir, pg_env)
        self.server_batch_count = 1
        self.server_timing_backend = None
        self.sampling_declaration = sampling_declaration
        self.e3_access_root_materialized = (
            True if sampling_declaration is None
            else sampling_declaration.get("e3_access_root_materialized", True))

    def set_case(self, case_id, family):
        self.close_timing_backend()
        self.server_batch_count = (
            batch_count_for_case(case_id, family) if self.sampling_declaration is None
            else self.sampling_declaration["measurement_batch_counts"][case_id])

    def close_timing_backend(self):
        if self.server_timing_backend is not None:
            self.server_timing_backend.close()
            self.server_timing_backend = None

    def run_server_timed_sql(self, sql: str, pg_env=None, **kwargs):
        from .unified_rerun_server_timing import (
            PersistentServerTimingBackend, run_server_timing_block,
        )
        target = pg_env or self.pg_env
        if target != self.pg_env:
            raise ValueError("persistent timing backend must remain in its declared case DB")
        if self.server_timing_backend is None:
            self.server_timing_backend = PersistentServerTimingBackend(target)
        return run_server_timing_block(sql, target, backend=self.server_timing_backend,
            batch_count=self.server_batch_count, **kwargs)

    def run_correctness_sql(self, sql: str, pg_env=None, **kwargs):
        return super().run_once_sql(sql, pg_env, **kwargs)


def batch_count_for_case(case_id, family):
    if family == "E10":
        return 10
    if family == "E3":
        return 1 if case_id.startswith("E3_JOB_") else 10
    raise ValueError("unknown measurement family")


def select_e3(context, query, policy, build, manifest):
    """Preserve the actual bound runner and its production cost role."""
    from . import e3_main as e3
    materialized = getattr(context, "e3_access_root_materialized", True)
    result = (_e3_select(context, query, policy, build, manifest) if materialized
              else select_e3_prospective_not_materialized(context, query, policy,
                                                         build, manifest))
    result["spec"] = replace(result["spec"], role=e3.E3_RLS_ROLE)
    result["cost_role"] = e3.E3_RLS_ROLE
    result["execution_role"] = e3.E3_RLS_ROLE
    result["access_root_materialized"] = materialized
    return result


def select_e3_prospective_not_materialized(context, query, policy, build, manifest):
    """Generate the existing single-use root variant before admission/costing.

    Only the existing production planner's access_root_materialized switch is
    different from V1's selector adapter. No selected SQL is edited afterwards.
    The production wrapper's single-use assertion, physical/static verification,
    eligible-root inventory and actual bound-SQL identity remain in force.
    """
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
    input_done = time.perf_counter()
    with CaptureBoundRunners(e3) as capture:
        result, plan, _ = e3._plan_e3_admission_first(
            query=query, policy=policy, predicate=predicate, pg_env=context.pg_env,
            protected_rows=protected, query_local_rows=local,
            authorized_rows=build[1] or authorized, build_ms=build[0],
            keyed_artifact_rows=build[2],
            ranker=e3._ranker_from_manifest(context.root, manifest),
            registry=e3._e3_registry_from_manifest(manifest),
            planning_catalog_receipt=receipt, access_root_materialized=False)
    stopped = time.perf_counter()
    bound = plan["production_bound_runner"]
    template = e3._require_e3_selected_root_template(plan)
    sql = bound["runner_sql"]
    if bound["runner_sql_digest"] != e3._canonical_sha256({"exact_runner_sql": sql}):
        raise ValueError("selected NOT MATERIALIZED SQL binding identity mismatch")
    if not any(item["sql"] == sql for item in capture.entries):
        raise ValueError("selected NOT MATERIALIZED SQL was not observed in costed runners")
    source = e3._source_for_template(template)
    artifact_ids, expected = preview._artifact_validation_for(query, policy, source)
    spec = preview.ExecutionSpec(mode="admission-first", template_id=template,
        alternative=result.chosen_template.alternative, sql=sql, sql_source=source,
        result_columns=preview._result_columns_for(query), role=e3.E3_RLS_ROLE,
        artifact_ids=artifact_ids, expected_artifact_json=expected)
    eligible = {item["template_id"] for item in
                plan["production_completed_root_eligibility"]["completed_roots"]}
    return {"spec": spec, "plan": plan, "result": result, "bound": dict(bound),
        "input_collection_wall_ms": (input_done-started)*1000,
        "choice_core_wall_ms": (stopped-input_done)*1000,
        "choice_total_wall_ms": (stopped-started)*1000,
        "candidates": [item for item in capture.entries if item["template_id"] in eligible],
        "request_started": started}


def measure_e3_spec(context, spec):
    from .e8b_study import _validation_statements
    validation = (_validation_statements(spec.artifact_ids,
                  spec.expected_artifact_json) if spec.artifact_ids else None)
    return context.run_server_timed_sql(spec.sql, role=spec.role,
                                       validation_sql=validation, read_only=True)


def prepare_e3_case(context, query, policy):
    from . import e3_main as e3
    predicate = e3._policy_predicate(query, policy)
    build = e3._build_artifact(query, policy, predicate, context.pg_env)
    e3._configure_native_rls(query, policy, context.pg_env)
    state = vacuum_artifacts(context.pg_env)
    return build, state, digest(json.dumps(state, sort_keys=True))


def run_e3_control_case(context, query, policy, *, warmup=5, measured=20):
    from . import e3_sigmod_preview as preview
    case_id = f"E3_{query.query_id}_{policy.config_id}"
    _, state, state_id = prepare_e3_case(context, query, policy)
    spec = preview._fixed_mode(query, policy, "native-pg-rls").spec
    if spec is None:
        raise ValueError("Native control unexpectedly unavailable")
    actual = preview._canonicalize_live(spec, context.pg_env)
    group = case_id + ":identical-native-SQL"
    for iteration in range(warmup + measured):
        phase = "warmup" if iteration < warmup else "measured"
        order = ("A", "B") if iteration % 2 == 0 else ("B", "A")
        for arm in order:
            observation = measure_e3_spec(context, spec)
            context.append_event({"record_kind": "control", "family": "E3",
                "case_id": case_id, "control_group_id": group,
                "control_arm": arm, "phase": phase, "iteration": iteration,
                "status": "pass", "state_id": state_id,
                "admitted_sql_hash": digest(spec.sql),
                "reference_digest": actual.result_digest, **observation})
        print(json.dumps({"time": now(), "control": case_id,
                          "iteration": iteration, "phase": phase}), flush=True)
    receipt = {"family": "E3", "case_id": case_id, "status": "pass",
               "control_group_id": group, "warmup": warmup,
               "measured": measured, "state": state}
    write_once(context.run_dir / "receipts" / (case_id + ".json"), receipt)
    return receipt


def run_e3_case(context, query, policy, manifest, *, warmup=5, measured=10):
    from . import e3_main as e3
    from . import e3_sigmod_preview as preview
    from .baselines import normalize_mode_id
    case_id = f"E3_{query.query_id}_{policy.config_id}"
    build, state, state_id = prepare_e3_case(context, query, policy)
    selected = select_e3(context, query, policy, build, manifest)
    fixed = [preview._fixed_mode(query, policy, normalize_mode_id(mode))
             for mode in manifest["modes"]
             if normalize_mode_id(mode) != "admission-first"]
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
            mode="candidate:" + item["template_id"],
            template_id=item["template_id"], alternative="admitted-candidate",
            sql=item["sql"], sql_source=source,
            result_columns=preview._result_columns_for(query),
            role=e3.E3_RLS_ROLE, artifact_ids=ids, expected_artifact_json=expected)
    checked = set()
    for spec in [selected["spec"], *specs.values(), *candidate_specs.values()]:
        identity = (digest(spec.sql), spec.role)
        if identity in checked:
            continue
        actual = preview._canonicalize_live(spec, context.pg_env)
        if actual.canonical_rows != reference.canonical_rows:
            raise ValueError(f"full result mismatch: {case_id}/{spec.mode}")
        checked.add(identity)
    context.append_event({"record_kind": "case_preflight", "family": "E3",
        "case_id": case_id, "status": "pass", "state_id": state_id,
        "state": state, "reference_digest": reference.result_digest,
        "distinct_sql_role_correctness_checked": len(checked),
        "cost_role": e3.E3_RLS_ROLE, "bound_execution_role": e3.E3_RLS_ROLE,
        "admitted_candidate_ids": list(candidate_specs),
        "unavailable_modes": [{"mode": item.mode,
            "reason": item.unavailable_reason} for item in fixed if item.spec is None]})
    modes = ["admission-first", *specs]
    samples = 0
    for iteration in range(warmup + measured):
        phase = "warmup" if iteration < warmup else "measured"
        offset = iteration % len(modes)
        for mode in modes[offset:] + modes[:offset]:
            choice = None
            if mode == "admission-first":
                choice = select_e3(context, query, policy, build, manifest)
                spec = choice["spec"]
            else:
                spec = specs[mode]
            observation = measure_e3_spec(context, spec)
            event = {"record_kind": "query", "family": "E3",
                "case_id": case_id, "query_id": query.query_id,
                "policy_id": policy.config_id, "mode": mode, "phase": phase,
                "iteration": iteration, "status": "pass", "state_id": state_id,
                "selected_candidate_id": spec.template_id,
                "admitted_sql_hash": digest(spec.sql),
                "costed_sql_hash": digest(spec.sql) if choice else None,
                "execution_role": spec.role or context.pg_env.user, **observation}
            if choice:
                event.update({key: choice[key] for key in (
                    "choice_total_wall_ms", "choice_core_wall_ms",
                    "input_collection_wall_ms", "bound", "cost_role")})
                event["access_root_materialized"] = choice["access_root_materialized"]
                event["instrumented_choice_and_measurement_wall_ms"] = (
                    time.perf_counter() - choice["request_started"]) * 1000
                event["choice_sql_identity"] = "actual_costed_bound_runner"
            context.append_event(event)
            samples += 1
        candidate_items = list(candidate_specs.items())
        offset = iteration % max(1, len(candidate_items))
        for template, spec in candidate_items[offset:] + candidate_items[:offset]:
            observation = measure_e3_spec(context, spec)
            context.append_event({"record_kind": "candidate", "family": "E3",
                "case_id": case_id, "query_id": query.query_id,
                "policy_id": policy.config_id, "mode": spec.mode,
                "selected_candidate_id": template, "phase": phase,
                "iteration": iteration, "status": "pass", "admitted": True,
                "state_id": state_id, "admitted_sql_hash": digest(spec.sql),
                "costed_sql_hash": digest(spec.sql), "cost_role": e3.E3_RLS_ROLE,
                "execution_role": e3.E3_RLS_ROLE, **observation})
            samples += 1
        print(json.dumps({"time": now(), "case": case_id, "iteration": iteration,
                          "phase": phase, "samples": samples}), flush=True)
    receipt = {"family": "E3", "case_id": case_id, "status": "pass",
        "samples": samples, "warmup": warmup, "measured": measured,
        "state": state, "reference_digest": reference.result_digest}
    write_once(context.run_dir / "receipts" / (case_id + ".json"), receipt)
    return receipt


def e10_formal(context, state, case, *, warmup, measured):
    from . import unified_rerun_e10_server as e10
    iterations = []
    for iteration in range(warmup + measured):
        phase = "warmup" if iteration < warmup else "measured"
        block = e10.run_e10_case(context, state, case,
                                 repetition=iteration, phase=phase)
        state_id = digest(json.dumps({"context": dict(state.context),
            "case": case.query_id, "negative_kind":
            e10.e10.E10_NEGATIVE_STATE_KIND_BY_QUERY.get(case.query_id)},
            sort_keys=True, default=str))
        if iteration == 0:
            context.append_event({"record_kind": "case_preflight", "family": "E10",
                "case_id": case.query_id, "status": "pass", "state_id": state_id,
                "admitted_candidate_ids": [arm["template_id"]
                    for arm in block["candidates"]],
                "unavailable_modes": block["unavailable"],
                "correctness": block["correctness"]})
        for kind, arms in (("query", block["arms"]), ("candidate", block["candidates"])):
            for arm in arms:
                payload = {k: v for k, v in arm.items() if k not in ("rows_text", "sql")}
                sql_hash = digest(arm["sql"])
                payload.update({"record_kind": kind, "family": "E10",
                    "case_id": case.query_id, "query_id": case.query_id,
                    "status": "pass", "phase": phase, "iteration": iteration,
                    "state_id": state_id, "selected_candidate_id": arm["template_id"],
                    "admitted_sql_hash": sql_hash,
                    "costed_sql_hash": sql_hash if arm["template_id"]
                        in block["cost_bindings"] else None,
                    "executed_sql_hash": sql_hash, "admitted": True})
                context.append_event(payload)
        for arm in block["unavailable"]:
            context.append_event({"record_kind": "query", "family": "E10",
                "case_id": case.query_id, "phase": phase, "iteration": iteration,
                "state_id": state_id, **arm, "status": "not_applicable"})
        block.pop("reference", None)
        write_once(context.run_dir / "e10_blocks" /
                   f"{case.query_id}_{iteration:02d}.json", block)
        iterations.append({"iteration": iteration, "phase": phase,
            "choice": block["selected_template"], "sql": block["selected_sql_sha256"]})
        print(json.dumps({"time": now(), "case": case.query_id,
                          "iteration": iteration, "phase": phase}), flush=True)
    receipt = {"family": "E10", "case_id": case.query_id, "status": "pass",
               "warmup": warmup, "measured": measured, "iterations": iterations}
    write_once(context.run_dir / "receipts" / (case.query_id + ".json"), receipt)
    return receipt


def require_gate(path):
    if not path:
        raise ValueError("--gate-receipt is required before formal sampling")
    payload = json.loads(Path(path).read_text())
    if payload.get("status") != "pass":
        raise ValueError("independent same-SQL gate must pass before formal sampling")
    return {"path": str(Path(path).resolve()), "sha256": digest(Path(path).read_text()),
            "payload": payload}


def _structured_file(path):
    source = Path(path)
    text = source.read_text()
    if source.suffix.lower() in {".yaml", ".yml"}:
        import yaml
        payload = yaml.safe_load(text)
    else:
        payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("sampling declaration/approval must be a mapping")
    return payload, digest(text)


def require_casewise_scope(approval_path, declaration_path):
    """Read the explicit new authority, never relabel an old failed gate."""
    if not approval_path or not declaration_path:
        raise ValueError("formal sampling requires --scope-approval and --sampling-declaration")
    declaration, declaration_hash = _structured_file(declaration_path)
    approval, approval_hash = _structured_file(approval_path)
    if (approval.get("status") != "accepted_casewise_resolution"
            or approval.get("formal_sampling_authorized") is not True):
        raise ValueError("formal sampling needs explicit accepted_casewise_resolution authority")
    approved_hash = approval.get("sampling_declaration_sha256", "")
    if not isinstance(approved_hash, str) or approved_hash.removeprefix("sha256:") != declaration_hash.removeprefix("sha256:"):
        raise ValueError("scope approval is not bound to this sampling declaration")
    expected = declaration.get("expected_cases")
    if not isinstance(expected, dict) or set(expected) != {"E3", "E10"}:
        raise ValueError("formal declaration must give both E3 and E10 case inventories")
    if any(not isinstance(items, list) or any(not isinstance(case, str) or not case for case in items)
           for items in expected.values()):
        raise ValueError("formal case inventories must be lists of nonempty strings")
    cases = [case for family in expected.values() for case in family]
    if len(cases) != len(set(cases)):
        raise ValueError("duplicate case in formal sampling declaration")
    for field in ("measurement_batch_counts", "measurement_repetition_counts"):
        values = declaration.get(field)
        if not isinstance(values, dict) or set(values) != set(cases):
            raise ValueError(field + " must cover exactly the declared cases")
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 1
               for value in values.values()):
            raise ValueError(field + " values must be positive integers")
    if any(value < 2 for value in declaration["measurement_repetition_counts"].values()):
        raise ValueError("formal measured repetitions must be at least two")
    warmup = declaration.get("warmup_count")
    if isinstance(warmup, bool) or not isinstance(warmup, int) or warmup < 1:
        raise ValueError("formal declaration requires a positive warmup_count")
    if declaration.get("e3_access_root_materialized", True).__class__ is not bool:
        raise ValueError("materialization declaration must be Boolean")
    return declaration, {"path": str(Path(approval_path).resolve()),
        "sha256": approval_hash, "payload": approval,
        "sampling_declaration_path": str(Path(declaration_path).resolve()),
        "sampling_declaration_sha256": declaration_hash}


def main():
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
    parser.add_argument("--pilot-controls", action="store_true")
    parser.add_argument("--gate-receipt")
    parser.add_argument("--sampling-declaration")
    parser.add_argument("--scope-approval")
    parser.add_argument("--sampling-preparation", action="store_true")
    parser.add_argument("--detach", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    run_dir = Path(args.output).resolve()
    sampling_declaration = None
    scope_approval = None
    if not args.pilot_controls:
        sampling_declaration, scope_approval = require_casewise_scope(
            args.scope_approval, args.sampling_declaration)
    if args.warmup < 1 or args.measured < 2:
        parser.error("warmup >= 1 and measured >= 2 are required")
    if args.detach:
        launch_dir = root / "output/section65_server_rerun_execution_2026-10-06/runner"
        launch_dir.mkdir(parents=True, exist_ok=True)
        log_path = launch_dir / (run_dir.name + ".log")
        command = ["/usr/bin/caffeinate", "-i", sys.executable, "-u", "-m",
            "caprls_core.unified_rerun_server", *[arg for arg in sys.argv[1:] if arg != "--detach"]]
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
    from . import e10_study
    from .baselines import normalize_mode_id
    loaded = load_family(root, root / E3_MANIFEST)
    all_cases = {"E3": [f"E3_{q.query_id}_{p.config_id}" for q in loaded["queries"]
                        for p in loaded["policies"]],
                 "E10": [case.query_id for case in e10_study.CASES]}
    families = ["E3", "E10"] if args.family == "both" else [args.family]
    expected = {family: [sid for sid in all_cases[family]
        if not args.cases or sid in args.cases] for family in families}
    if args.cases and set(args.cases) - {sid for items in expected.values() for sid in items}:
        raise ValueError("unknown or out-of-family case identifiers")
    if not any(expected.values()):
        raise ValueError("no known cases selected")
    if sampling_declaration is not None:
        declared_cases = sampling_declaration["expected_cases"]
        if set(expected) != set(declared_cases) or any(
                set(expected[family]) != set(declared_cases[family]) for family in expected):
            raise ValueError("formal declared case inventory differs from the actual selected inventory")
        # The root's frozen declaration owns case order as well as coverage.
        expected = {family: list(declared_cases[family]) for family in families}
    batch_counts = ({sid: batch_count_for_case(sid, family)
        for family, items in expected.items() for sid in items}
        if sampling_declaration is None else sampling_declaration["measurement_batch_counts"])
    repetition_counts = ({sid: args.measured for items in expected.values() for sid in items}
        if sampling_declaration is None else sampling_declaration["measurement_repetition_counts"])
    warmup_count = (args.warmup if sampling_declaration is None
                    else sampling_declaration["warmup_count"])
    code_paths = ["caprls_core/unified_rerun_server.py",
        "caprls_core/unified_rerun_server_timing.py", "caprls_core/unified_rerun_e10_server.py",
        "caprls_core/unified_rerun.py", "caprls_core/unified_rerun_e10.py",
        "caprls_core/e3_main.py", "caprls_core/e10_study.py"]
    snapshot = {path: digest((root / path).read_text()) for path in code_paths}
    write_once(run_dir / "code_snapshot.json", snapshot)
    write_once(run_dir / "declaration.json", {"expected_cases": expected,
        "expected_modes": {"E3": [normalize_mode_id(mode) for mode in loaded["manifest"]["modes"]],
                           "E10": sorted(e10_study.REQUIRED_MODES)},
        "measurement_batch_counts": batch_counts,
        "measurement_repetition_counts": repetition_counts,
        "warmup_count": warmup_count, "measured_count": args.measured,
        "source_sampling_declaration": sampling_declaration,
        "pilot_controls": args.pilot_controls})
    write_once(run_dir / "protocol.json", {"schema": "unified-server-rerun-v2",
        "created_at": now(), "args": vars(args), "pid": os.getpid(),
        "query_scope": "PostgreSQL planning+execution+required_validation_TIMING_OFF",
        "correctness_scope": "independent ordinary fetch outside performance samples",
        "choice_scope": "full observed input_collection+admission+plain_EXPLAIN_choice",
        "uncached_request_scope": "not_measured_by_instrumented_performance_samples",
        "e3_bound_cost_and_execution_role": "caprls_e3_rls_user",
        "e3_cost_and_execution_transaction_read_only": True,
        "e3_role_change_from_v1": "V1 source-based owner execution corrected to production contract",
        "sql_identity": "actual costed bound SQL; no extra count transform",
        "classification": "same_SQL_noise_envelope_and_paired_bootstrap95_no_fixed_tie_band",
        "timing_backend_lifecycle": "one persistent PostgreSQL backend per case; independent RR transaction per execution",
        "batch_rule": "frozen_per_case_K_and_outer_repetitions; all raw members retained",
        "measurement_batch_counts": batch_counts,
        "measurement_repetition_counts": repetition_counts,
        "e3_access_root_materialized": (True if sampling_declaration is None
            else sampling_declaration.get("e3_access_root_materialized", True)),
        "e3_render_variant_scope": "single-use outer root generated before admission and costing; inner CTEs unchanged",
        "single_activity": True, "stable_choice_required_for_break_even": True,
        "scope_approval": scope_approval,
        "original_global_precision_gate": "retained_failed_not_used_as_casewise_sampling_authority"})
    completed, failures = [], []
    for family in families:
        db = args.e3_db if family == "E3" else args.e10_db
        pg = PostgresEnv(args.pg_host, args.pg_port, args.pg_user, db)
        context = Context(root, run_dir, pg, sampling_declaration)
        if args.sampling_preparation:
            prepare_sampling_environment(pg)
        raw = run_psql_command("SELECT json_build_object('server_version',version(),"
            "'shared_buffers',current_setting('shared_buffers'),'work_mem',current_setting('work_mem'),"
            "'database',current_database(),'session_user',session_user)::text", pg)
        write_once(run_dir / (family + "_environment.json"),
                   {"observed_at": now(), "postgres": json.loads(raw)})
        if family == "E3":
            case_by_id = {f"E3_{q.query_id}_{p.config_id}": (q, p)
                          for q in loaded["queries"] for p in loaded["policies"]}
            cases = [case_by_id[sid] for sid in expected[family]]
        else:
            from . import unified_rerun_e10_server as e10
            import yaml
            with (root / "manifests/experiments/e10_case_study.yaml").open() as handle:
                state = e10.prepare_e10(context, yaml.safe_load(handle))
            case_by_id = {case.query_id: case for case in e10.e10.CASES}
            cases = [case_by_id[sid] for sid in expected[family]]
        for item in cases:
            sid = (f"E3_{item[0].query_id}_{item[1].config_id}"
                   if family == "E3" else item.query_id)
            try:
                context.set_case(sid, family)
                for path, code_hash in snapshot.items():
                    if digest((root / path).read_text()) != code_hash:
                        raise RuntimeError("sampling code changed after campaign freeze: " + path)
                if family == "E3":
                    if args.pilot_controls:
                        result = run_e3_control_case(context, *item,
                            warmup=warmup_count, measured=repetition_counts[sid])
                    else:
                        result = run_e3_case(context, *item, loaded["manifest"],
                            warmup=warmup_count, measured=repetition_counts[sid])
                elif args.pilot_controls:
                    block = e10.run_e10_control_case(context, state, item,
                        warmup=warmup_count, measured=repetition_counts[sid])
                    state_id = digest(json.dumps({"context": dict(state.context),
                        "case": sid}, sort_keys=True, default=str))
                    for arm in block["samples"]:
                        payload = {key: value for key, value in arm.items() if key != "sql"}
                        payload.update({"record_kind": "control", "family": "E10",
                            "case_id": sid, "control_group_id": sid + ":identical-native-SQL",
                            "control_arm": arm["mode"].rsplit("-", 1)[-1].upper(),
                            "status": "pass", "state_id": state_id})
                        context.append_event(payload)
                    result = {key: value for key, value in block.items() if key != "samples"}
                    result.update({"status": "pass", "sample_count": len(block["samples"])})
                    write_once(run_dir / "receipts" / (sid + ".json"), result)
                else:
                    result = e10_formal(context, state, item,
                        warmup=warmup_count, measured=repetition_counts[sid])
                completed.append(result)
            except Exception as exc:
                failure = {"family": family, "case_id": sid, "status": "failed",
                    "error": str(exc), "traceback": traceback.format_exc()}
                context.append_event({"record_kind": "failure", **failure})
                failures.append(failure)
                print(json.dumps(failure), flush=True)
                break
            finally:
                context.close_timing_backend()
        if failures:
            break
    write_once(run_dir / "completion.json", {"completed_at": now(),
        "completed": completed, "failures": failures,
        "status": "pass" if not failures and len(completed) == sum(map(len, expected.values()))
                  else "incomplete"})
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
