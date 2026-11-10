"""Small E10 adapter for the unified evaluation campaign.

The frozen E10 query/planning functions remain untouched.  Unlike its old
measurement driver, this module executes each ordinary request once and fetches
its result.  EXPLAIN ANALYZE and correctness references are separate diagnostics,
never part of the AF request timer.  The E10 benchmark queries are count-valued
queries already; this adapter does not introduce an extra count wrapper.

Only the campaign's sole runner should call the live functions.  ``context`` has
``root``, ``pg_env``, ``run_once_sql(sql, pg_env, role=None, validation_sql=None)``
and an optional ``append_event(dict)`` callback.  No result files are opened here.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from . import e10_study as e10
from .baselines import ADMISSION_FIRST_MODE, mode_execution_order_key


def _digest(sql: str) -> str:
    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


def _event(context: Any, payload: Mapping[str, Any]) -> None:
    callback = getattr(context, "append_event", None)
    if callback is not None:
        callback(dict(payload))


def _check_results(arms: list[dict[str, Any]], reference: Mapping[str, Any]) -> None:
    """Compare fetched benchmark results, never just the number of output rows."""
    expected = reference.get("result_digest")
    if not expected:
        raise e10.PostgresError("unified E10 reference result digest missing")
    for arm in arms:
        if arm.get("result_digest") != expected:
            raise e10.PostgresError(
                "unified E10 result mismatch: "
                f"{arm.get('mode')}/{arm.get('template_id')}")


@dataclass
class E10State:
    context_id: str
    context: Mapping[str, Any]
    context_version: int
    user_id: str
    ctx_hash: str
    policies: Mapping[str, Mapping[str, Any]]
    exact: Mapping[tuple[str, str], str]
    artifact_ids: Mapping[str, Mapping[str, str]]
    artifact_rows: Mapping[str, Mapping[str, int]]
    build_ms: Mapping[str, Mapping[str, float]]
    storage_bytes: Mapping[str, Mapping[str, int]]
    base_rows: Mapping[str, int]


def prepare_e10(context: Any, manifest: Mapping[str, Any], *,
                context_id: str = "ctx_000001", prepare_dataset: bool = False) -> E10State:
    """Prepare reusable artifacts once, not once per timed repetition.

    Artifact construction is environment preparation, recorded separately from
    choice cost.  VACUUM follows the delete/rebuild cycle outside all timers.
    """
    root, pg = Path(context.root), context.pg_env
    if prepare_dataset:
        dataset = manifest.get("dataset") or {}
        e10.generate_synthetic_saas(root, pg, scale=str(dataset.get("scale", "1e5")),
                                    seed=int(dataset.get("seed", 52)), verify=True,
                                    output_dir=None)
    ctx = e10._load_context(context_id, pg)
    target, _ = e10._load_e10_state_contexts(context_id, pg)
    if (target["context_id"] != context_id
            or target["canonical_context"] != dict(ctx)
            or str(target["principal_id"]) != str(ctx["user_id"])
            or e10._canonical_digest(ctx) != str(target["ctx_hash"])):
        raise e10.PostgresError("unified E10 context identity mismatch")
    user, ctx_hash = str(ctx["user_id"]), str(target["ctx_hash"])
    targets = sorted({e10._target_for_case(case) for case in e10.CASES})
    policies = {policy: e10._load_policy(root, policy)
                for _, _, policy, _ in targets}
    exact, ids, rows, builds, sizes, bases = {}, {}, {}, {}, {}, {}
    for relation, rid, policy, alias in targets:
        predicate = e10._render_policy_predicate(
            str(policies[policy]["exact_sql_template"]), alias, rid, ctx, relation)
        exact[(relation, alias)] = predicate
        e10.configure_native_rls(
            rel=f"public.{relation}", policy_name=f"caprls_e10_policy_{relation}",
            predicate=e10._native_rls_policy_predicate(predicate, alias),
            role_name=e10.E10_NATIVE_RLS_ROLE, pg_env=pg)
        ids[relation] = e10._artifact_ids_for_context(relation, context_id)
        scripts = {
            "auth": e10._build_auth_idx_sql(ids[relation]["auth"], policy, user,
                                           ctx_hash, relation, rid, alias, predicate),
            "keyed": e10._build_keyed_sql(ids[relation]["keyed"], policy, user,
                                         ctx_hash, relation, rid, alias, predicate),
            "mav": e10._build_mav_sql(ids[relation]["mav"], policy, ctx_hash,
                                     relation, rid, alias, predicate, context_id),
        }
        builds[relation] = {kind: e10._timed_sql_script(sql, pg)
                            for kind, sql in scripts.items()}
        physical = {"auth": "public.auth_idx", "keyed": "public.auth_idx_keyed",
                    "mav": f"public.{e10._mav_table(relation, context_id)}"}
        sizes[relation] = {kind: e10._relation_size_bytes(table, pg)
                           for kind, table in physical.items()}
        rows[relation] = {
            "auth": e10._run_count("SELECT count(*) FROM public.auth_idx WHERE "
                                   f"artifact_id={e10._quote(ids[relation]['auth'])};", pg),
            "keyed": e10._run_count("SELECT count(*) FROM public.auth_idx_keyed WHERE "
                                    f"artifact_id={e10._quote(ids[relation]['keyed'])};", pg),
            "mav": e10._run_count(f"SELECT count(*) FROM {physical['mav']};", pg),
        }
        bases[relation] = e10._run_count(f"SELECT count(*) FROM public.{relation};", pg)
    # psql -c runs a multi-statement string in an implicit transaction; VACUUM
    # must therefore be sent as separate commands.
    e10.run_psql_command("VACUUM ANALYZE public.auth_idx;", pg)
    e10.run_psql_command("VACUUM ANALYZE public.auth_idx_keyed;", pg)
    _event(context, {"event": "e10_prepared", "context_id": context_id,
                     "artifact_build_ms": builds,
                     "artifact_rebuild_policy": "once_before_sampling",
                     "vacuum_after_artifact_rebuild": True})
    return E10State(context_id, ctx, int(target["version"]), user, ctx_hash,
                    policies, exact, ids, rows, builds, sizes, bases)


def plan_e10_case(context: Any, state: E10State, case: Any,
                  negative_handle: Any = None) -> dict[str, Any]:
    """Observe inputs, replay admission, cost the exact SQL, and choose once."""
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
            raise e10.PostgresError("unified E10 negative handle case mismatch")
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
        raise e10.PostgresError("unified E10 catalog replay failed: " + ";".join(replay.reasons))
    bundle = e10._issue_e10_admission_bundle(
        root=root, case=case, receipt=receipt, expectation=expectation,
        require_production=False)
    admission = e10._replay_e10_admission_bundle(
        bundle, root=root, case=case, receipt=receipt, expectation=expectation,
        require_production=False)
    if not admission.valid:
        raise e10.PostgresError("unified E10 admission replay failed: " + ";".join(admission.reasons))
    base_rows = e10._run_count(f"SELECT count(*) FROM public.{relation};", pg)
    filtered_rows = e10._run_count(
        f"SELECT count(*) FROM public.{relation} {alias} WHERE {query_predicate};", pg)
    artifact_rows, build_ms, storage = (dict(state.artifact_rows[relation]),
                                       dict(state.build_ms[relation]),
                                       dict(state.storage_bytes[relation]))
    if negative_handle is not None:
        artifact_rows["mav"] = e10._run_count(f"SELECT count(*) FROM {mav_relation};", pg)
        build_ms["mav"] = 0.0
        storage["mav"] = e10._relation_size_bytes(mav_relation, pg)
    artifacts = e10._artifact_metadata_for_case(
        case, relation, rid, ids, artifact_rows, build_ms, storage,
        planning_receipt=receipt, planning_expectation=expectation,
        require_production_receipt=False)
    assessments = {item.kind: item for item in receipt.artifact_assessments}

    def allowed(template: str) -> bool:
        required = e10._required_artifact_for_template(template)
        return (e10._template_unavailable_reason(case, template) is None
                and (required is None or bool(assessments.get(required)
                                             and assessments[required].usable)))

    def sql_for(template: str) -> str:
        return e10._sql_for_template(
            case, template, relation, rid, alias, exact, ids, policy,
            state.user_id, state.ctx_hash, state.context_id,
            complete_guard_predicate=guard, mav_physical_relation=mav_relation)

    input_done = time.perf_counter()
    cost_bindings: dict[str, dict[str, Any]] = {}

    def explain_cost(template: str) -> Any:
        if not allowed(template):
            return None
        sql = sql_for(template)
        # One plain EXPLAIN serves both static-plan verification and prospective
        # costing.  It never executes the query and precedes the selected request.
        checked = e10._run_e10_static_preflight(template, sql, pg, native_rls=False)
        plan = checked.explain_json[0].get("Plan", {})
        if not isinstance(plan, Mapping) or "Total Cost" not in plan:
            raise e10.PostgresError("unified E10 prospective plan has no Total Cost")
        prospective = (float(plan["Total Cost"]), {
            "pg_plan_rows": plan.get("Plan Rows"),
            "plan_hash": e10._explain_plan_hash(list(checked.explain_json)),
            "explain_prospective": True})
        cost_bindings[template] = {"sql": sql, "sql_sha256": _digest(sql),
                                   "pg_total_cost": prospective[0],
                                   "plan_evidence": prospective[1],
                                   "explain_json": list(checked.explain_json),
                                   "static_verification": {
                                       "status": checked.verification.status,
                                       "plan_hash": checked.verification.plan_hash}}
        return prospective

    invocation = e10._planner_invocation_for_case(
        case, ADMISSION_FIRST_MODE, relname=relation, rid_col=rid,
        policy_id=policy, artifacts=artifacts, base_rows=base_rows,
        filtered_rows=filtered_rows, alias=alias, exact_predicate=exact,
        complete_guard_predicate=guard, query_predicate=query_predicate,
        planning_receipt=receipt, planning_expectation=expectation,
        planning_admission_bundle=bundle, require_production_receipt=False,
        root=root, artifact_relations={"mav": mav_relation},
        explain_cost_fn=explain_cost)
    chosen = invocation.occurrence_result.chosen_template
    if chosen is None:
        raise e10.PostgresError("unified E10 AF selected no admitted candidate")
    selected_sql = sql_for(chosen.template_id)
    binding = cost_bindings.get(chosen.template_id)
    if binding is None or binding["sql_sha256"] != _digest(selected_sql):
        raise e10.PostgresError("unified E10 chosen SQL differs from costed SQL")
    stopped = time.perf_counter()
    return {"case": case, "relation": relation, "rid_col": rid, "policy_id": policy,
            "alias": alias, "exact_predicate": exact, "artifact_ids": ids,
            "receipt": receipt, "expectation": expectation, "bundle": bundle,
            "invocation": invocation, "sql_for": sql_for, "allowed": allowed,
            "selected_template": chosen.template_id, "selected_sql": selected_sql,
            "cost_bindings": cost_bindings,
            "input_collection_wall_ms": (input_done - started) * 1000,
            "choice_core_wall_ms": (stopped - input_done) * 1000,
            "choice_total_wall_ms": (stopped - started) * 1000}


def measure_e10_arm(context: Any, state: E10State, planned: Mapping[str, Any],
                    template: str, *, mode: str, preflight: bool = True) -> dict[str, Any]:
    """Execute one ordinary complete SQL, with applicable validation in its transaction."""
    sql = planned["sql_for"](template)
    native = e10._is_native_rls_template(template)
    # The native renderer includes SET/RESET ROLE; request execution receives the
    # query body plus an explicit role, so its timer has the same session boundary.
    if native:
        sql = e10._native_rls_query(
            planned["case"], planned["relation"], planned["rid_col"],
            planned["alias"], policy_predicate=planned["exact_predicate"],
            principal_id=state.user_id)
    binding = planned["cost_bindings"].get(template)
    verification = None if binding is None else binding.get("static_verification")
    if preflight:
        checked = e10._run_e10_static_preflight(template, sql, context.pg_env,
                                                native_rls=native)
        verification = {"status": checked.verification.status,
                        "plan_hash": checked.verification.plan_hash}
    validation = None
    kind = e10._artifact_kind_for_template(template)
    if kind is not None:
        expected = e10._artifact_dependency_expected_json(
            planned["policy_id"], state.ctx_hash, planned["relation"], planned["rid_col"])
        validation = ("SELECT public.caprls_assert_artifact_valid("
                      f"{e10._quote(planned['artifact_ids'][kind])},"
                      f"{e10._quote(expected)}::jsonb);")
    if not native and binding is not None and binding["sql_sha256"] != _digest(sql):
        raise e10.PostgresError("unified E10 executed SQL differs from costed SQL")
    result = dict(context.run_once_sql(
        sql, context.pg_env, role=e10.E10_NATIVE_RLS_ROLE if native else None,
        validation_sql=validation))
    result.update({"family": "E10", "case_id": planned["case"].query_id,
                   "mode": mode, "template_id": template, "sql": sql,
                   "sql_sha256": _digest(sql), "validation_required": kind is not None,
                   "static_verification": verification})
    return result


def run_e10_case(context: Any, state: E10State, case: Any, *,
                 repetition: int = 0, phase: str = "measured") -> dict[str, Any]:
    """One complete case block; failed attempts and restoration are caller logged.

    AF's actual request comes first so choice and its single query are contiguous.
    Other fixed modes rotate; candidate-oracle probes and reference run afterwards.
    The AF query from this request is also the performance/reuse sample.
    """
    handle = None
    if case.query_id in e10.E10_NEGATIVE_STATE_KIND_BY_QUERY:
        handle = e10._materialize_e10_negative_state(
            Path(context.root), case, state.context_id, context.pg_env)
    restoration = None
    try:
        request_start = time.perf_counter()
        planned = plan_e10_case(context, state, case, handle)
        # Plain prospective EXPLAIN/admission took place during choice.  Any
        # extra static-plan diagnostic goes after the actual AF request window.
        af = measure_e10_arm(context, state, planned, planned["selected_template"],
                              mode=ADMISSION_FIRST_MODE, preflight=False)
        af["request_total_wall_ms"] = (time.perf_counter() - request_start) * 1000
        for key in ("input_collection_wall_ms", "choice_core_wall_ms", "choice_total_wall_ms"):
            af[key] = planned[key]
        modes = sorted(e10.REQUIRED_MODES - {ADMISSION_FIRST_MODE},
                       key=mode_execution_order_key)
        offset = repetition % len(modes)
        modes = modes[offset:] + modes[:offset]
        arms, unavailable = [af], []
        for mode in modes:
            template = e10._mode_template(case, mode)[0]
            if not planned["allowed"](template):
                unavailable.append({"mode": mode, "template_id": template,
                                    "status": "not_applicable_or_not_admitted"})
                continue
            arms.append(measure_e10_arm(context, state, planned, template, mode=mode))
        candidates = []
        for candidate in planned["invocation"].occurrence_result.candidates:
            if candidate.accepted and planned["allowed"](candidate.template_id):
                candidates.append(measure_e10_arm(
                    context, state, planned, candidate.template_id,
                    mode="template-candidate"))
        reference_sql = e10._base_query(
            case, planned["relation"], planned["rid_col"], planned["alias"],
            planned["exact_predicate"], principal_id=state.user_id)
        reference = dict(context.run_once_sql(reference_sql, context.pg_env,
                                              role=None, validation_sql=None))
        _check_results(arms + candidates, reference)
        result = {"family": "E10", "case_id": case.query_id, "phase": phase,
                  "repetition": repetition, "selected_template": planned["selected_template"],
                  "selected_sql_sha256": _digest(planned["selected_sql"]),
                  "arms": arms, "candidates": candidates, "unavailable": unavailable,
                  "reference": reference,
                  "plan_result": planned["invocation"].occurrence_result.to_dict(),
                  "planning_receipt": planned["receipt"].to_dict(),
                  "cost_bindings": planned["cost_bindings"],
                  "mode_order": [arm["mode"] for arm in arms],
                  "ordinary_query_executions_per_arm": 1,
                  "diagnostic_executions_in_request": 0,
                  "benchmark_result_kind": "count_aggregate_as_defined_by_e10",
                  "correctness": "fetched_benchmark_result_matches_reference",
                  "sql_identity": "prospectively_costed_statement_executed_unchanged"}
        return result
    finally:
        if handle is not None:
            restoration = e10._restore_e10_negative_state(handle, context.pg_env)
            _event(context, {"event": "e10_negative_state_restored",
                             "case_id": case.query_id, "repetition": repetition,
                             "restoration": asdict(restoration)})
