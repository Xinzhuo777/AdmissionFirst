"""Opt-in original-driver selection observation without global profiling.

Only measurement adapters are installed. The original functions receive their
original arguments and their result objects are returned unchanged. Sparse
phase hooks exist only inside selection windows, not during query sampling.
E3 selects once per cell, excluding pre-collected inputs; E10 preserves the
original expectation-START / invocation-STOP span, including planning inputs.
"""
from __future__ import annotations

from datetime import datetime, timezone
from functools import wraps
import hashlib
import inspect
import json
import sys
import time
from typing import Any, Callable

from caprls_core.selection_cost_breakdown import SelectionCostBreakdown


def _hash(text: Any) -> str | None:
    return hashlib.sha256(text.encode()).hexdigest() if isinstance(text, str) else None


def _arg(fn: Callable[..., Any], args: tuple, kwargs: dict, name: str) -> Any:
    if name in kwargs:
        return kwargs[name]
    return inspect.signature(fn).bind_partial(*args, **kwargs).arguments.get(name)


class SparseSelectionObserver:
    """Use around one unchanged E3 or E10 original driver.

    ``with SparseSelectionObserver(sidecar, e3=e3): e3.run_e3_main(...)``
    ``with SparseSelectionObserver(sidecar, e10=e10): e10.run_e10_case_study(...)``

    Do not combine with OriginalObserver or E10SelectionAnchors. Existing
    sys.getprofile() is refused, not disabled behind the caller's back.
    Observation errors are retained in ``errors``; they never replace an
    original result or an original function exception.
    """
    def __init__(self, sidecar: Any, *, e3: Any = None, e10: Any = None,
                 collector_factory: Callable[..., Any] = SelectionCostBreakdown):
        if (e3 is None) == (e10 is None):
            raise ValueError("specify exactly one of e3 or e10")
        self.sidecar, self.e3, self.e10 = sidecar, e3, e10
        self.family = "E3" if e3 is not None else "E10"
        self.collector_factory = collector_factory
        self.errors: list[dict[str, Any]] = []
        self.inputs: dict[tuple, float] = {}
        self.choice_records = 0
        self._patches: list[tuple[Any, str, Any]] = []
        self._open: dict[str, Any] | None = None
        self._pending: list[dict[str, Any]] = []
        self._repetition: Any = None
        self._entered = False

    def _error(self, where: str, exc: BaseException) -> None:
        self.errors.append({"where": where, "error": str(exc), "family": self.family})

    def _emit(self, record: dict[str, Any]) -> None:
        if self._open is not None:
            raise RuntimeError("record serialization must be outside selection windows")
        payload = {"observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                   "observer": "sparse_original_boundary_v1", "global_profile_enabled": False,
                   "profile_state": "disabled",
                   "serialization_outside_window": True, **record}
        self.sidecar.write(json.dumps(payload, default=str) + "\n")
        self.sidecar.flush()

    def _patch(self, module: Any, name: str, fn: Any) -> None:
        self._patches.append((module, name, getattr(module, name)))
        setattr(module, name, fn)

    def __enter__(self) -> "SparseSelectionObserver":
        if self._entered:
            raise RuntimeError("observer cannot be entered twice")
        if sys.getprofile() is not None:
            raise RuntimeError("existing global profiler is incompatible with sparse observation")
        try:
            if self.e3 is not None:
                self._install_e3()
            else:
                self._install_e10()
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise
        self._entered = True
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._open is not None:
            self._finish_open("unclosed_window", success=False)
        for module, name, original in reversed(self._patches):
            setattr(module, name, original)
        self._patches.clear()
        self._entered = False

    def _install_e3(self) -> None:
        e3 = self.e3
        original = e3._plan_e3_admission_first
        driver_code = e3.run_e3_main.__code__
        observer = self

        @wraps(original)
        def choose(*args: Any, **kwargs: Any) -> Any:
            if sys._getframe(1).f_code is not driver_code:
                return original(*args, **kwargs)
            query, policy = _arg(original, args, kwargs, "query"), _arg(original, args, kwargs, "policy")
            collector = observer.collector_factory(family="E3")
            # Hook setup, output metadata and JSON are outside the external
            # original selection-function window. No wrapper changes the body.
            with collector:
                result, breakdown = collector.run(original, *args, **kwargs)
            try:
                from caprls_core.selection_cost_e3 import measurement_sql
                plan, query_plan, _ = result
                chosen = plan.chosen_template.template_id
                measured = measurement_sql(e3, query, policy, chosen)
                qid, pid = query.query_id, policy.config_id
                shared = sum(observer.inputs.get((qid, name), 0.0) for name in ("protected", "query_local"))
                cell = sum(observer.inputs.get((qid, pid, name), 0.0) for name in ("catalog", "authorized"))
                observer._emit({
                    "record_kind": "choice", "family": "E3", "case_id": f"E3_{qid}_{pid}",
                    "query_id": qid, "policy_id": pid, "phase": "case_once", "iteration": None,
                    "choice_frequency": "once_per_cell_before_original_repetition_loop",
                    "choice_cost_scope": "original_planner_call_excludes_precollected_inputs",
                    "choice_cost_ms": breakdown["total_wall_ms"], "choice_core_wall_ms": breakdown["total_wall_ms"],
                    "breakdown": breakdown, "cell_specific_input_wall_ms": cell,
                    "query_shared_input_wall_ms": shared,
                    "query_shared_input_scope": "observed_once_per_query_and_reused_by_three_policy_cases",
                    "selected_template_id": chosen, "selection_source": measured["source"],
                    "prospective_runner_sql_hash": query_plan.get("production_bound_runner", {}).get("runner_sql_digest"),
                    "original_timed_runner_binding_digest": measured["sql_digest"],
                    "original_timed_runner_sql_hash": _hash(measured["sql"]),
                    "original_timed_runner_sql": measured["sql"],
                    "old_execution_role_rule": "native_rls_role_for_rls_source; original_owner_for_other_sources",
                    "no_extra_selection_or_query": True,
                })
                observer.choice_records += 1
            except Exception as exc:
                observer._error("e3_choice_metadata", exc)
            return result

        self._patch(e3, "_plan_e3_admission_first", choose)
        for name, kind in (("_protected_count", "protected"),
                           ("_collect_e3_planning_catalog_receipt", "catalog"),
                           ("run_psql_command", "count")):
            if not hasattr(e3, name):
                continue
            self._install_e3_input(name, kind, driver_code)

    def _install_e3_input(self, name: str, kind: str, driver_code: Any) -> None:
        e3, observer = self.e3, self
        original = getattr(e3, name)
        @wraps(original)
        def observed(*args: Any, **kwargs: Any) -> Any:
            caller = sys._getframe(1)
            if caller.f_code is not driver_code:
                return original(*args, **kwargs)
            started = time.perf_counter_ns()
            result = original(*args, **kwargs)
            elapsed = (time.perf_counter_ns() - started) / 1e6
            try:
                query, policy = caller.f_locals["query"], caller.f_locals.get("policy")
                qid, pid = query.query_id, getattr(policy, "config_id", None)
                scope = kind
                if kind == "count":
                    sql = _arg(original, args, kwargs, "sql")
                    local = (f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} "
                             f"WHERE {e3._query_local_predicate(query)};")
                    authorized = (f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} "
                                  f"WHERE {caller.f_locals.get('predicate')};")
                    scope = "query_local" if sql == local else "authorized" if sql == authorized else None
                if scope is not None:
                    key = (qid, pid, scope) if scope in ("catalog", "authorized") else (qid, scope)
                    observer.inputs[key] = elapsed
                    label = {"protected": "query_shared_protected_count", "query_local": "query_shared_local_count",
                             "catalog": "cell_catalog_receipt", "authorized": "cell_authorized_count"}[scope]
                    observer._emit({"record_kind": "planning_input", "family": "E3", "query_id": qid,
                                    "policy_id": pid if scope in ("catalog", "authorized") else None,
                                    "scope": label, "wall_ms": elapsed, "reexecuted": False})
            except Exception as exc:
                observer._error("e3_input_metadata", exc)
            return result
        self._patch(e3, name, observed)

    def _finish_open(self, where: str, *, success: bool) -> None:
        window, self._open = self._open, None
        if window is None:
            self._error(where, RuntimeError("STOP has no matching START"))
            return
        collector = window["collector"]
        try:
            breakdown = collector.stop_window()
            self._pending.append({"query_id": window["query_id"], "breakdown": breakdown,
                                  "success": success, "observed_start_line": window["start_line"],
                                  "observed_stop_line": window.get("stop_line")})
        except Exception as exc:
            self._error(where, exc)
        finally:
            collector.__exit__(None, None, None)
        if not success:
            self._error(where, RuntimeError("original selection did not return successfully"))

    def _install_e10(self) -> None:
        e10, observer = self.e10, self
        start_original = e10._e10_planning_expectation
        stop_original = e10._planner_invocation_for_case
        prepare_original = e10._prepare_postgres_measurements
        case_code = e10._prepare_e10_case_postgres_measurements.__code__
        driver_code = e10.run_e10_case_study.__code__

        @wraps(start_original)
        def start(*args: Any, **kwargs: Any) -> Any:
            caller = sys._getframe(1)
            if caller.f_code is not case_code:
                return start_original(*args, **kwargs)
            if observer._open is not None:
                observer._error("e10_start", RuntimeError("duplicate START"))
                return start_original(*args, **kwargs)
            case = _arg(start_original, args, kwargs, "case")
            collector = observer.collector_factory(family="E10")
            collector.__enter__()
            observer._open = {"collector": collector, "query_id": case.query_id, "start_line": caller.f_lineno}
            collector.start_window()
            try:
                return start_original(*args, **kwargs)
            except BaseException:
                observer._finish_open("e10_start_original_exception", success=False)
                raise

        @wraps(stop_original)
        def stop(*args: Any, **kwargs: Any) -> Any:
            caller = sys._getframe(1)
            if caller.f_code is not case_code:
                return stop_original(*args, **kwargs)
            try:
                result = stop_original(*args, **kwargs)
            except BaseException:
                observer._finish_open("e10_stop_original_exception", success=False)
                raise
            if observer._open is not None:
                observer._open["stop_line"] = caller.f_lineno
            observer._finish_open("e10_stop", success=True)
            return result

        @wraps(prepare_original)
        def prepare(*args: Any, **kwargs: Any) -> Any:
            caller = sys._getframe(1)
            if caller.f_code is not driver_code:
                return prepare_original(*args, **kwargs)
            observer._repetition = caller.f_locals.get("repetition")
            observer._pending = []
            try:
                result = prepare_original(*args, **kwargs)
            finally:
                if observer._open is not None:
                    observer._finish_open("e10_prepare_open_window", success=False)
            try:
                observer._emit_e10_pending(result)
            except Exception as exc:
                observer._error("e10_prepare_metadata", exc)
            return result

        self._patch(e10, "_e10_planning_expectation", start)
        self._patch(e10, "_planner_invocation_for_case", stop)
        self._patch(e10, "_prepare_postgres_measurements", prepare)

    def _emit_e10_pending(self, result: Any) -> None:
        from caprls_core.baselines import ADMISSION_FIRST_MODE
        repetition = self._repetition
        if repetition is None:
            raise RuntimeError("original repetition identity missing")
        seen = [item["query_id"] for item in self._pending]
        expected = len(self.e10.CASES)
        if len(seen) != expected or len(set(seen)) != expected:
            raise RuntimeError(f"expected one selection window for each of {expected} cases: {seen}")
        for item in self._pending:
            qid = item["query_id"]
            if not item["success"]:
                raise RuntimeError(f"selection window did not complete: {qid}")
            plan = result.plan_results[(qid, ADMISSION_FIRST_MODE)]
            measurement = result.measurements[(qid, ADMISSION_FIRST_MODE)]
            breakdown = item["breakdown"]
            self._emit({
                "record_kind": "choice", "family": "E10", "case_id": qid,
                "query_id": qid, "context_id": result.context_id,
                "phase": repetition.phase, "iteration": repetition.iteration,
                "choice_frequency": "original_once_per_case_per_original_repetition",
                "choice_cost_scope": "original_E10_START_STOP_anchor_includes_case_planning_inputs",
                "choice_cost_ms": breakdown["total_wall_ms"], "breakdown": breakdown,
                "selected_template_id": plan.chosen_template.template_id,
                "original_runner_sql_hash_if_available": _hash(getattr(measurement, "runner_sql", None)),
                "original_sql_identity_source": "unchanged_raw_normal_mode_record",
                "state_context_hash": result.ctx_hash,
                "anchor": {"query_id": qid, "selection_wall_ms": breakdown["total_wall_ms"],
                           "observed_start_line": item["observed_start_line"],
                           "observed_stop_line": item["observed_stop_line"],
                           "candidate_explain_count": breakdown["sql_call_counts"]["plain_explain"]},
                "no_extra_selection_or_query": True,
            })
            self.choice_records += 1
        self._pending = []


OriginalBoundaryObserver = SparseSelectionObserver
