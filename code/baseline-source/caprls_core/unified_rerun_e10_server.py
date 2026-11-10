"""E10 adapter for the server-timed second unified campaign.

The V1 adapters and the frozen E10 study are not modified.  Each measured arm
uses the predeclared fixed-size server timing block, whose members execute its
actual SQL once through EXPLAIN ANALYZE (TIMING OFF); the primary
metric is PostgreSQL planning + execution + same-transaction validation time.
Ordinary full-result correctness checks are independent and untimed.  No
EXPLAIN row count is represented as a fetched benchmark result.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping

from . import e10_study as e10
from . import unified_rerun_e10 as v1
from .baselines import ADMISSION_FIRST_MODE, mode_execution_order_key

E10State = v1.E10State
prepare_e10 = v1.prepare_e10


def _digest(sql: str) -> str:
    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


def _event(context: Any, payload: Mapping[str, Any]) -> None:
    v1._event(context, payload)


def _query_sql(state: E10State, case: Any, relation: str, rid: str,
               alias: str, exact: str, template: str, rendered: str) -> str:
    # Native SQL's renderer decorates the body with SET/RESET ROLE.  The timer
    # receives the body and role separately, and prospective EXPLAIN uses the
    # same body under that same role.
    if e10._is_native_rls_template(template):
        return e10._native_rls_query(case, relation, rid, alias,
                                    policy_predicate=exact,
                                    principal_id=state.user_id)
    return rendered


def plan_e10_case(context: Any, state: E10State, case: Any,
                  negative_handle: Any = None) -> dict[str, Any]:
    """Observe inputs, replay admission and cost the exact execution body.

    This small copy of V1's planner adapter keeps its accounting boundary while
    fixing Native's prospective EXPLAIN role and normalizing only its session
    decoration.  No template, admission decision or SQL rendering is redesigned.
    """
    root, pg = Path(context.root), context.pg_env
    started = time.perf_counter()
    relation, rid, policy, alias = e10._target_for_case(case)
    exact = state.exact[(relation, alias)]
    guard = (e10._complete_guard_predicate(case, alias, rid, state.context, relation)
             if case.complete_guard_sql_template is not None else None)
    query_predicate = e10._e10_planning_query_predicate(case, alias, rid)
    ids = dict(state.artifact_ids[relation])
    mav_relation = f"public.{e10._mav_table(relation, state.context_id)}"
    dependency_profile = "legacy5"
    if negative_handle is not None:
        if negative_handle.spec.case_query_id != case.query_id:
            raise e10.PostgresError("server E10 negative handle case mismatch")
        ids["mav"] = negative_handle.spec.artifact_id
        mav_relation = negative_handle.spec.physical_relation
        dependency_profile = "state9"
    expectation = e10._e10_planning_expectation(
        root=root, case=case, context_id=state.context_id, context=state.context,
        context_hash=state.ctx_hash, context_version=state.context_version,
        policy=state.policies[policy], exact_predicate=exact, guard_predicate=guard,
        query_predicate=query_predicate, artifact_ids=ids,
        mav_physical_relation=mav_relation, mav_dependency_profile=dependency_profile,
        scope="fixture")
    observation, collector_digest = e10._collect_e10_planning_catalog_observation(
        expectation, pg)
    receipt = e10._issue_e10_planning_receipt(
        expectation, observation, collector_sql_digest=collector_digest)
    replay = e10._replay_e10_planning_receipt(receipt, expectation,
                                           require_production=False)
    if not replay.valid:
        raise e10.PostgresError("server E10 catalog replay failed: " + ";".join(replay.reasons))
    bundle = e10._issue_e10_admission_bundle(
        root=root, case=case, receipt=receipt, expectation=expectation,
        require_production=False)
    admission = e10._replay_e10_admission_bundle(
        bundle, root=root, case=case, receipt=receipt, expectation=expectation,
        require_production=False)
    if not admission.valid:
        raise e10.PostgresError("server E10 admission replay failed: " + ";".join(admission.reasons))
    base_rows = e10._run_count(f"SELECT count(*) FROM public.{relation};", pg)
    filtered_rows = e10._run_count(
        f"SELECT count(*) FROM public.{relation} {alias} WHERE {query_predicate};", pg)
    artifact_rows = dict(state.artifact_rows[relation])
    builds, storage = dict(state.build_ms[relation]), dict(state.storage_bytes[relation])
    if negative_handle is not None:
        artifact_rows["mav"] = e10._run_count(f"SELECT count(*) FROM {mav_relation};", pg)
        builds["mav"] = 0.0
        storage["mav"] = e10._relation_size_bytes(mav_relation, pg)
    artifacts = e10._artifact_metadata_for_case(
        case, relation, rid, ids, artifact_rows, builds, storage,
        planning_receipt=receipt, planning_expectation=expectation,
        require_production_receipt=False)
    assessments = {item.kind: item for item in receipt.artifact_assessments}

    def allowed(template: str) -> bool:
        required = e10._required_artifact_for_template(template)
        return (e10._template_unavailable_reason(case, template) is None
                and (required is None or bool(assessments.get(required)
                                             and assessments[required].usable)))

    def sql_for(template: str) -> str:
        rendered = e10._sql_for_template(
            case, template, relation, rid, alias, exact, ids, policy,
            state.user_id, state.ctx_hash, state.context_id,
            complete_guard_predicate=guard, mav_physical_relation=mav_relation)
        return _query_sql(state, case, relation, rid, alias, exact, template, rendered)

    input_done = time.perf_counter()
    bindings: dict[str, dict[str, Any]] = {}

    def explain_cost(template: str) -> Any:
        if not allowed(template):
            return None
        sql = sql_for(template)
        native = e10._is_native_rls_template(template)
        checked = e10._run_e10_static_preflight(template, sql, pg, native_rls=native)
        plan = checked.explain_json[0].get("Plan", {})
        if not isinstance(plan, Mapping) or "Total Cost" not in plan:
            raise e10.PostgresError("server E10 prospective plan has no Total Cost")
        evidence = {"pg_plan_rows": plan.get("Plan Rows"),
                    "plan_hash": e10._explain_plan_hash(list(checked.explain_json)),
                    "explain_prospective": True,
                    "role": e10.E10_NATIVE_RLS_ROLE if native else None}
        total_cost = float(plan["Total Cost"])
        bindings[template] = {"sql": sql, "sql_sha256": _digest(sql),
                              "pg_total_cost": total_cost, "plan_evidence": evidence,
                              "explain_json": list(checked.explain_json),
                              "static_verification": {
                                  "status": checked.verification.status,
                                  "plan_hash": checked.verification.plan_hash}}
        return total_cost, evidence

    invocation = e10._planner_invocation_for_case(
        case, ADMISSION_FIRST_MODE, relname=relation, rid_col=rid,
        policy_id=policy, artifacts=artifacts, base_rows=base_rows,
        filtered_rows=filtered_rows, alias=alias, exact_predicate=exact,
        complete_guard_predicate=guard, query_predicate=query_predicate,
        planning_receipt=receipt, planning_expectation=expectation,
        planning_admission_bundle=bundle, require_production_receipt=False,
        root=root, artifact_relations={"mav": mav_relation}, explain_cost_fn=explain_cost)
    chosen = invocation.occurrence_result.chosen_template
    if chosen is None:
        raise e10.PostgresError("server E10 AF selected no admitted candidate")
    selected_sql = sql_for(chosen.template_id)
    binding = bindings.get(chosen.template_id)
    if binding is None or binding["sql_sha256"] != _digest(selected_sql):
        raise e10.PostgresError("server E10 chosen SQL differs from costed SQL")
    stopped = time.perf_counter()
    return {"case": case, "relation": relation, "rid_col": rid, "policy_id": policy,
            "alias": alias, "exact_predicate": exact, "artifact_ids": ids,
            "receipt": receipt, "expectation": expectation, "bundle": bundle,
            "invocation": invocation, "sql_for": sql_for, "allowed": allowed,
            "selected_template": chosen.template_id, "selected_sql": selected_sql,
            "cost_bindings": bindings,
            "input_collection_wall_ms": (input_done - started) * 1000,
            "choice_core_wall_ms": (stopped - input_done) * 1000,
            "choice_total_wall_ms": (stopped - started) * 1000}


def _validation_sql(state: E10State, planned: Mapping[str, Any], template: str) -> str | None:
    kind = e10._artifact_kind_for_template(template)
    if kind is None:
        return None
    expected = e10._artifact_dependency_expected_json(
        planned["policy_id"], state.ctx_hash, planned["relation"], planned["rid_col"])
    return ("SELECT public.caprls_assert_artifact_valid("
            f"{e10._quote(planned['artifact_ids'][kind])},"
            f"{e10._quote(expected)}::jsonb);")


def _correctness(context: Any, state: E10State, planned: Mapping[str, Any],
                 sql: str, role: str | None, validation: str | None) -> dict[str, Any]:
    """Independently fetch and compare the full defined benchmark result.

    The campaign holds its logical case state fixed; negative-fixture restoration
    is checked at every repetition.  Checks are cached by case/context/body/role,
    never by an EXPLAIN row count.  Any new SQL receives its own full-result check.
    """
    cache = getattr(context, "e10_server_correctness_cache", None)
    if cache is None:
        cache = {}
        setattr(context, "e10_server_correctness_cache", cache)
    reference_sql = e10._base_query(
        planned["case"], planned["relation"], planned["rid_col"], planned["alias"],
        planned["exact_predicate"], principal_id=state.user_id)
    key = (planned["case"].query_id, state.context_id, state.ctx_hash,
           state.context_version, _digest(reference_sql), _digest(sql), role, validation)
    if key in cache:
        return {**cache[key], "correctness_preflight_reused": True}
    ordinary = getattr(context, "run_correctness_sql", None)
    if ordinary is None:
        from .unified_rerun import run_once_sql
        ordinary = run_once_sql
    reference = ordinary(reference_sql, context.pg_env, role=None, validation_sql=None)
    fetched = ordinary(sql, context.pg_env, role=role, validation_sql=validation)
    v1._check_results([{"mode": "untimed-preflight", **fetched}], reference)
    evidence = {"correctness_source": "separate_untimed_full_result_check",
                "correctness_preflight_result_digest": fetched["result_digest"],
                "reference_result_digest": reference["result_digest"],
                "correctness_preflight_sql_sha256": _digest(sql),
                "correctness_preflight_role": role,
                "correctness_preflight_row_count": fetched.get("row_count")}
    cache[key] = evidence
    return {**evidence, "correctness_preflight_reused": False}


def measure_e10_arm(context: Any, state: E10State, planned: Mapping[str, Any],
                    template: str, *, mode: str, preflight: bool = True) -> dict[str, Any]:
    """A declared server timing block; setup/fetch/commit wall is not latency."""
    sql = planned["sql_for"](template)
    native = e10._is_native_rls_template(template)
    sql = _query_sql(state, planned["case"], planned["relation"], planned["rid_col"],
                     planned["alias"], planned["exact_predicate"], template, sql)
    role = e10.E10_NATIVE_RLS_ROLE if native else None
    binding = planned["cost_bindings"].get(template)
    verification = None if binding is None else binding.get("static_verification")
    if binding is not None and binding["sql_sha256"] != _digest(sql):
        raise e10.PostgresError("server E10 executed SQL differs from costed SQL")
    if preflight:
        checked = e10._run_e10_static_preflight(template, sql, context.pg_env,
                                                native_rls=native)
        verification = {"status": checked.verification.status,
                        "plan_hash": checked.verification.plan_hash}
    validation = _validation_sql(state, planned, template)
    correctness = _correctness(context, state, planned, sql, role, validation)
    result = dict(context.run_server_timed_sql(sql, context.pg_env, role=role,
                                               validation_sql=validation))
    if "query_server_ms" not in result:
        raise e10.PostgresError("server E10 timer did not return query_server_ms")
    declared_count = int(getattr(context, "server_batch_count", 1))
    if int(result.get("query_executions", 1)) != declared_count:
        raise e10.PostgresError("server E10 timer execution count differs from declared block")
    if result.get("executed_sql_hash") != "sha256:" + _digest(sql):
        raise e10.PostgresError("server E10 timer SQL identity mismatch")
    result.update({"family": "E10", "case_id": planned["case"].query_id,
                   "mode": mode, "template_id": template, "sql": sql,
                   "sql_sha256": _digest(sql), "validation_required": validation is not None,
                   "static_verification": verification, **correctness})
    return result


def _rotated(values: list[Any], repetition: int) -> list[Any]:
    if not values:
        return []
    offset = repetition % len(values)
    return values[offset:] + values[:offset]


def run_e10_case(context: Any, state: E10State, case: Any, *,
                 repetition: int = 0, phase: str = "measured") -> dict[str, Any]:
    """Rotate every applicable mode, including AF, and retain negative restoration."""
    handle = None
    if case.query_id in e10.E10_NEGATIVE_STATE_KIND_BY_QUERY:
        handle = e10._materialize_e10_negative_state(
            Path(context.root), case, state.context_id, context.pg_env)
    try:
        planned = plan_e10_case(context, state, case, handle)
        modes = _rotated(sorted(e10.REQUIRED_MODES, key=mode_execution_order_key), repetition)
        arms, unavailable = [], []
        for mode in modes:
            template = (planned["selected_template"] if mode == ADMISSION_FIRST_MODE
                        else e10._mode_template(case, mode)[0])
            if not planned["allowed"](template):
                unavailable.append({"mode": mode, "template_id": template,
                                    "status": "not_applicable_or_not_admitted"})
                continue
            arm = measure_e10_arm(context, state, planned, template, mode=mode,
                                   preflight=mode != ADMISSION_FIRST_MODE)
            if mode == ADMISSION_FIRST_MODE:
                for key in ("input_collection_wall_ms", "choice_core_wall_ms",
                            "choice_total_wall_ms"):
                    arm[key] = planned[key]
            arms.append(arm)
        candidates = []
        accepted = [candidate for candidate in planned["invocation"].occurrence_result.candidates
                    if candidate.accepted and planned["allowed"](candidate.template_id)]
        for candidate in _rotated(accepted, repetition):
            candidates.append(measure_e10_arm(context, state, planned,
                              candidate.template_id, mode="template-candidate", preflight=False))
        return {"family": "E10", "case_id": case.query_id, "phase": phase,
                "repetition": repetition, "selected_template": planned["selected_template"],
                "selected_sql_sha256": _digest(planned["selected_sql"]),
                "arms": arms, "candidates": candidates, "unavailable": unavailable,
                "plan_result": planned["invocation"].occurrence_result.to_dict(),
                "planning_receipt": planned["receipt"].to_dict(),
                "cost_bindings": planned["cost_bindings"],
                "mode_order": [arm["mode"] for arm in arms],
                "server_instrumented_query_executions_per_arm": int(
                    getattr(context, "server_batch_count", 1)),
                "ordinary_query_executions_in_primary_measurement": 0,
                "benchmark_result_kind": "count_aggregate_as_defined_by_e10",
                "correctness": "separate_untimed_full_result_check",
                "primary_metric": "server_planning_execution_and_required_validation_ms",
                "sql_identity": "prospectively_costed_statement_executed_unchanged"}
    finally:
        if handle is not None:
            restoration = e10._restore_e10_negative_state(handle, context.pg_env)
            _event(context, {"event": "e10_negative_state_restored", "case_id": case.query_id,
                             "repetition": repetition, "restoration": asdict(restoration)})


def run_e10_control_case(context: Any, state: E10State, case: Any, *,
                         warmup: int = 5, measured: int = 20) -> dict[str, Any]:
    """Small blind A/A Native control: identical SQL and role, alternating order."""
    if case.query_id in e10.E10_NEGATIVE_STATE_KIND_BY_QUERY:
        raise e10.PostgresError("A/A control must use a non-intervention E10 case")
    planned = plan_e10_case(context, state, case)
    template = "native_pg_rls_v1"
    samples = []
    for repetition in range(warmup + measured):
        order = ["control-a", "control-b"]
        if repetition % 2:
            order.reverse()
        for label in order:
            result = measure_e10_arm(context, state, planned, template,
                                       mode=label, preflight=repetition == 0)
            result.update({"phase": "warmup" if repetition < warmup else "measured",
                           "iteration": repetition, "record_kind": "control",
                           "control_order": order})
            samples.append(result)
    return {"family": "E10", "case_id": case.query_id, "samples": samples,
            "control": "same_sql_same_role_alternating_ab_ba",
            "warmup": warmup, "measured": measured}
