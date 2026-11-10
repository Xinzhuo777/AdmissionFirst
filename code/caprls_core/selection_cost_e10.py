"""Campaign B, E10 arm: 11 case-study cells.

Anchor (memo section 1.3, Gate ruling (b) - ACCEPTED as proven): E10's selection
region is a contiguous span *inside*
``e10_study._prepare_e10_case_postgres_measurements`` and cannot be bracketed
from outside that function, so it is bracketed by pass-through wrappers on its
two boundary functions:

* START ``e10_study._e10_planning_expectation`` - **exactly one call site in the
  module** (``:11980``), so "exactly one START per (case, repetition)" is
  structurally guaranteed;
* STOP ``e10_study._planner_invocation_for_case`` - three call sites, correctly
  discriminated by the caller-code-object assertion
  ``co_name == "_prepare_e10_case_postgres_measurements"``.

Both wrappers delegate unchanged, are exception-proof, and are restored in
``finally``.  ``e10_study.py`` stays byte-identical on disk.

Latency comes from the same call: driving the frozen
``_prepare_postgres_measurements`` per repetition yields every mode's timing
through the frozen ``_measure_query`` / ``_measure_validated_query`` window.
"""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
)

import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from caprls_core import selection_cost_common as scc
from caprls_core.selection_cost_common import SelectionCostError

FAMILY = "E10"
CONTEXT_ID = "ctx_000001"
MODE_AF = ADMISSION_FIRST_MODE
MODE_NATIVE = "native-pg-rls"
MODE_PD = "native-pg-rls-physical-design"

ANCHOR_CALLER = "_prepare_e10_case_postgres_measurements"
START_FUNCTION = "_e10_planning_expectation"
STOP_FUNCTION = "_planner_invocation_for_case"
COST_FUNCTION = "_prospective_pg_cost"

SELECTION_WALL_SCOPE = (
    "case_level_full_selection_client_wall_ms_including_planning_inputs"
)


def short_id(query_id: str) -> str:
    return f"E10_{query_id}"


def cell_id(query_id: str) -> str:
    return f"{scc.CAMPAIGN_B}|family=E10|query={query_id}|context={CONTEXT_ID}"


class E10SelectionAnchors:
    """Install the START/STOP/cost wrappers; collect per-case observations.

    Refusals (memo section 1.3, clauses 3-4; stop rule section 10.2):

    * an observation whose immediate caller is not
      :data:`ANCHOR_CALLER` is ignored, not counted;
    * any (case, repetition) that does not see exactly one START and exactly
      one STOP raises - "any other count is a refusal, not a repair".
    """

    def __init__(self, e10: Any) -> None:
        self._e10 = e10
        self._originals: Dict[str, Any] = {}
        self._open: Optional[Dict[str, Any]] = None
        self.observations: List[Dict[str, Any]] = []
        self.ignored_calls: Dict[str, int] = {STOP_FUNCTION: 0, COST_FUNCTION: 0}

    # -- context management -------------------------------------------------

    def __enter__(self) -> "E10SelectionAnchors":
        e10 = self._e10
        for name in (START_FUNCTION, STOP_FUNCTION, COST_FUNCTION):
            self._originals[name] = getattr(e10, name)

        start_original = self._originals[START_FUNCTION]
        stop_original = self._originals[STOP_FUNCTION]
        cost_original = self._originals[COST_FUNCTION]
        anchors = self

        def _start_wrapper(*args: Any, **kwargs: Any) -> Any:
            frame = sys._getframe(1)
            if scc.caller_name(frame) == ANCHOR_CALLER:
                try:
                    anchors._open_window(kwargs.get("case") or (args[1] if len(args) > 1 else None),
                                         frame.f_lineno)
                except Exception:  # noqa: BLE001 - observation must never perturb
                    pass
            return start_original(*args, **kwargs)

        def _stop_wrapper(*args: Any, **kwargs: Any) -> Any:
            frame = sys._getframe(1)
            anchored = scc.caller_name(frame) == ANCHOR_CALLER
            if not anchored:
                anchors.ignored_calls[STOP_FUNCTION] += 1
                return stop_original(*args, **kwargs)
            lineno = frame.f_lineno
            result = stop_original(*args, **kwargs)
            try:
                anchors._close_window(lineno)
            except Exception:  # noqa: BLE001
                pass
            return result

        def _cost_wrapper(*args: Any, **kwargs: Any) -> Any:
            started = time.perf_counter()
            result = cost_original(*args, **kwargs)
            try:
                anchors._record_cost((time.perf_counter() - started) * 1000.0)
            except Exception:  # noqa: BLE001
                pass
            return result

        setattr(e10, START_FUNCTION, _start_wrapper)
        setattr(e10, STOP_FUNCTION, _stop_wrapper)
        setattr(e10, COST_FUNCTION, _cost_wrapper)
        return self

    def __exit__(self, *exc_info: Any) -> None:
        for name, original in self._originals.items():
            setattr(self._e10, name, original)

    # -- window bookkeeping -------------------------------------------------

    def _open_window(self, case: Any, lineno: int) -> None:
        query_id = getattr(case, "query_id", None)
        if self._open is not None:
            raise SelectionCostError(
                "E10 anchor refusal: a second START observed before the "
                f"previous window for {self._open.get('query_id')} closed"
            )
        self._open = {
            "query_id": query_id,
            "started": time.perf_counter(),
            "start_line": int(lineno),
            "explain_calls": 0,
            "explain_wall_ms": 0.0,
        }

    def _record_cost(self, elapsed_ms: float) -> None:
        if self._open is None:
            self.ignored_calls[COST_FUNCTION] += 1
            return
        self._open["explain_calls"] += 1
        self._open["explain_wall_ms"] += elapsed_ms

    def _close_window(self, lineno: int) -> None:
        if self._open is None:
            raise SelectionCostError(
                "E10 anchor refusal: STOP observed with no open START window"
            )
        window = self._open
        self._open = None
        wall_ms = (time.perf_counter() - window["started"]) * 1000.0
        self.observations.append(
            {
                "query_id": window["query_id"],
                "selection_wall_ms": wall_ms,
                "candidate_explain_count": window["explain_calls"],
                "candidate_explain_wall_ms": window["explain_wall_ms"],
                "selection_residual_ms": wall_ms - window["explain_wall_ms"],
                "observed_start_line": window["start_line"],
                "observed_stop_line": int(lineno),
            }
        )

    def drain(self, *, expected_cases: int) -> List[Dict[str, Any]]:
        """Return this repetition's observations and assert one per case."""

        if self._open is not None:
            raise SelectionCostError(
                "E10 anchor refusal: repetition ended with an open selection window"
            )
        observations = list(self.observations)
        self.observations = []
        seen = [o["query_id"] for o in observations]
        if len(seen) != expected_cases or len(set(seen)) != expected_cases:
            raise SelectionCostError(
                "E10 anchor refusal: expected exactly one selection window per "
                f"case ({expected_cases}); observed {len(seen)} for "
                f"{len(set(seen))} distinct cases"
            )
        return observations


def _total_ms(measurement: Any) -> float:
    """Frozen composition ``e10_study.py:13162-13163``."""

    return float(measurement.timing.total_ms) + float(measurement.validation_ms)


def _arm(measurement: Any, e10: Any) -> Dict[str, Any]:
    runner_sql = getattr(measurement, "runner_sql", None)
    return {
        "planning_ms": float(measurement.timing.planning_ms),
        "execution_ms": float(measurement.timing.execution_ms),
        "validation_ms": float(measurement.validation_ms),
        "total_ms": _total_ms(measurement),
        "row_count": int(measurement.row_count),
        "validation_same_snapshot": bool(measurement.same_snapshot),
        "static_plan_hash": measurement.static_verifier_plan_hash,
        "runner_sql_digest": (
            scc.sha256_text(runner_sql) if isinstance(runner_sql, str) else None
        ),
    }


def pd_discriminant_from_measurements(
    native: Mapping[str, Any],
    pd: Optional[Mapping[str, Any]],
    *,
    native_template_id: str,
    pd_template_id: Optional[str],
) -> Dict[str, Any]:
    """Triple discriminant, evaluated on the frozen path's own emitted SQL."""

    if pd is None:
        return {
            "pd_identity": "undetermined",
            "reason": "+PD mode not present in the driven measurements",
        }
    template_equal = native_template_id == pd_template_id
    digest_equal = native.get("runner_sql_digest") == pd.get("runner_sql_digest")
    plan_equal = native.get("static_plan_hash") == pd.get("static_plan_hash")
    collapsed = bool(template_equal and digest_equal and plan_equal)
    return {
        "pd_identity": "collapsed_to_native" if collapsed else "independent",
        "template_id_equal": template_equal,
        "sql_digest_equal": digest_equal,
        "static_plan_hash_equal": plan_equal,
        "native_template_id": native_template_id,
        "pd_template_id": pd_template_id,
        "native_sql_digest": native.get("runner_sql_digest"),
        "pd_sql_digest": pd.get("runner_sql_digest"),
        "native_static_plan_hash": native.get("static_plan_hash"),
        "pd_static_plan_hash": pd.get("static_plan_hash"),
        "conjunction": "template_id AND sql_digest AND static_plan_hash",
        "action": (
            "report_native_only_and_record"
            if collapsed
            else "measure_and_report_as_own_comparator"
        ),
    }


def run_family(
    *,
    root: Path,
    pg_env: Any,
    manifest_path: Path,
    identity: Mapping[str, Any],
    context_id: str = CONTEXT_ID,
    warmup: int = scc.E10_SELECTION_WARMUP,
    measured: int = scc.E10_SELECTION_MEASURED,
    prepare_dataset: bool = False,
    case_ids: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Drive the frozen E10 preparation ``warmup + measured`` times.

    Both the selection wall and the query latency come out of the same frozen
    call, so ``Q_CA``/``Q_N`` are produced by the frozen measurement code rather
    than by a re-implementation.
    """

    from caprls_core import e10_study as e10
    from caprls_core.e3_smoke import _load_manifest

    manifest = _load_manifest(manifest_path)
    # The frozen driver always runs every case in `e10.CASES`
    # (`_prepare_postgres_measurements` loops `for case in CASES`), so the
    # anchor's expectation must follow the DRIVER, not the request.  Deriving
    # it from a requested subset made any proper subset refuse with
    # "observed 11 for 11 distinct cases".
    driver_cases = list(e10.CASES)
    expected = len(driver_cases)
    if case_ids:
        wanted = set(case_ids)
        unknown = wanted - {case.query_id for case in driver_cases}
        if unknown:
            raise SelectionCostError(
                f"unknown E10 case id(s): {sorted(unknown)}"
            )
        cases = [case for case in driver_cases if case.query_id in wanted]
    else:
        cases = driver_cases

    excluded_tail = scc.measure_e10_excluded_tail()

    # Collect for every driven case; report only the requested subset.
    selection_samples: Dict[str, List[Dict[str, Any]]] = {
        case.query_id: [] for case in driver_cases
    }
    latency_samples: Dict[str, Dict[str, List[Dict[str, Any]]]] = {
        case.query_id: {} for case in driver_cases
    }
    templates: Dict[str, Dict[str, str]] = {case.query_id: {} for case in driver_cases}
    ignored_summary: Dict[str, int] = {}

    anchors = E10SelectionAnchors(e10)
    dataset_prepared = not prepare_dataset
    with anchors:
        for rep in range(warmup + measured):
            measurements = e10._prepare_postgres_measurements(
                root,
                manifest,
                pg_env,
                context_id=context_id,
                prepare_dataset=not dataset_prepared,
            )
            dataset_prepared = True
            observations = anchors.drain(expected_cases=expected)
            if rep < warmup:
                continue
            for observation in observations:
                selection_samples[observation["query_id"]].append(observation)
            for (query_id, mode), measurement in measurements.measurements.items():
                if query_id not in latency_samples:
                    continue
                if mode not in (MODE_AF, MODE_NATIVE, MODE_PD):
                    continue
                arm = _arm(measurement, e10)
                latency_samples[query_id].setdefault(mode, []).append(arm)
                plan_result = measurements.plan_results.get((query_id, mode))
                chosen = getattr(plan_result, "chosen_template", None)
                templates[query_id][mode] = (
                    getattr(chosen, "template_id", None) or str(chosen)
                    if chosen is not None
                    else templates[query_id].get(mode, "")
                )
        ignored_summary = dict(anchors.ignored_calls)

    receipts = [
        _build_receipt(
            case=case,
            identity=identity,
            selection=selection_samples[case.query_id],
            latency=latency_samples[case.query_id],
            templates=templates[case.query_id],
            excluded_tail=excluded_tail,
            warmup=warmup,
            measured=measured,
            ignored_calls=ignored_summary,
        )
        for case in cases
    ]
    return {
        "receipts": receipts,
        "excluded_tail": excluded_tail,
        "driver_case_count": expected,
        "reported_case_count": len(cases),
        "case_filter_is_reporting_only": bool(case_ids),
        "case_filter_note": (
            "--cases selects which receipts are written; the frozen driver "
            "always runs all 11 cases, so it saves no machine time"
        ),
    }


def _build_receipt(
    *,
    case: Any,
    identity: Mapping[str, Any],
    selection: Sequence[Mapping[str, Any]],
    latency: Mapping[str, Sequence[Mapping[str, Any]]],
    templates: Mapping[str, str],
    excluded_tail: Mapping[str, Any],
    warmup: int,
    measured: int,
    ignored_calls: Mapping[str, int],
) -> Dict[str, Any]:
    walls = [float(o["selection_wall_ms"]) for o in selection]
    explain_walls = [float(o["candidate_explain_wall_ms"]) for o in selection]
    wall_dist = scc.distribution(walls)

    selection_block = {
        "anchor": {
            "kind": "pass_through_wrapper_pair",
            "start": f"caprls_core/e10_study.py {START_FUNCTION} (entry)",
            "stop": f"caprls_core/e10_study.py {STOP_FUNCTION} (return)",
            "caller_assertion": ANCHOR_CALLER,
            "precedent": "caprls_core/content_verify.py:852-899",
            "restore_guarantee": scc.REBIND_RESTORE_GUARANTEE,
            "observed_start_lines": sorted({o["observed_start_line"] for o in selection}),
            "observed_stop_lines": sorted({o["observed_stop_line"] for o in selection}),
            "ignored_non_anchor_calls": dict(ignored_calls),
            "excluded_tail": dict(excluded_tail),
        },
        "selection_wall_scope": SELECTION_WALL_SCOPE,
        "selection_repeat_semantics": "per_repetition_artifact_rebuild",
        "selection_repeat_semantics_reason": (
            "the frozen path rebuilds artifacts once per repetition; changing "
            "it would require editing e10_study.py, which is forbidden"
        ),
        "selection_warmup": warmup,
        "selection_measured": measured,
        "selection_wall_ms_median": wall_dist["median"],
        "selection_wall_ms_distribution": wall_dist,
        # E10's bracket already contains the planning inputs E3 excludes.
        "selection_inputs_ms": None,
        "selection_inputs_included_in_wall": True,
        "candidate_explain_count": (
            selection[0]["candidate_explain_count"] if selection else 0
        ),
        "candidate_explain_wall_ms_median": scc._median(explain_walls),
        "selection_residual_ms_median": (
            scc._median([float(o["selection_residual_ms"]) for o in selection])
        ),
        "selected_template_id": templates.get(MODE_AF),
    }

    latency_block: Dict[str, Any] = {}
    for mode, rows in latency.items():
        latency_block[mode] = {
            "template_id": templates.get(mode),
            "planning_ms_median": scc._median([r["planning_ms"] for r in rows]),
            "execution_ms_median": scc._median([r["execution_ms"] for r in rows]),
            "validation_ms_median": scc._median([r["validation_ms"] for r in rows]),
            "total_ms_median": scc._median([r["total_ms"] for r in rows]),
            "row_count_median": scc._median([float(r["row_count"]) for r in rows]),
            "runner_sql_digest": rows[0]["runner_sql_digest"] if rows else None,
            "static_plan_hash": rows[0]["static_plan_hash"] if rows else None,
            "samples": list(rows),
        }

    native = latency_block.get(MODE_NATIVE, {})
    pd_arm = latency_block.get(MODE_PD)
    pd = pd_discriminant_from_measurements(
        native,
        pd_arm,
        native_template_id=templates.get(MODE_NATIVE, ""),
        pd_template_id=templates.get(MODE_PD),
    )
    if pd.get("pd_identity") == "collapsed_to_native" and pd_arm is not None:
        pd_arm["ratio_source"] = "identity_collapsed"
        pd_arm["collapsed_to"] = MODE_NATIVE
        pd_arm["reported_total_ms_median"] = None
        pd_arm["note"] = (
            "template id, runner-SQL digest and static plan hash all equal "
            "Native's; +PD is reported as Native and is not an independent "
            "comparator in this campaign"
        )

    q_af = latency_block.get(MODE_AF, {}).get("total_ms_median")
    q_native = native.get("total_ms_median")
    derived = _derive(selection_block, q_af, q_native)

    return {
        "schema": scc.RECEIPT_SCHEMA_B,
        "short_id": short_id(case.query_id),
        "cell_id": cell_id(case.query_id),
        "family": FAMILY,
        "query_id": case.query_id,
        "policy_id": getattr(case, "policy_mix", None),
        "context_id": CONTEXT_ID,
        "status": "pass" if q_af is not None and q_native is not None else "incomplete",
        "failure_reason": None,
        "identity": dict(identity),
        "protocol": {
            "selection_warmup": warmup,
            "selection_measured": measured,
            "latency_warmup": warmup,
            "latency_measured": measured,
            "serial": True,
            "measurement_window": (
                "postgres_planning_plus_execution_plus_validation_ms"
            ),
            "driver": "caprls_core.e10_study._prepare_postgres_measurements",
            "modes_reported": sorted(latency_block),
        },
        "selection": selection_block,
        "pd_discriminant": pd,
        "latency": latency_block,
        "derived": derived,
        "provenance": {
            "campaign": scc.CAMPAIGN_B,
            "relationship_to_frozen": (
                "new_measurement_this_machine_this_state; does_not_restate_"
                "correct_or_replace_any_frozen_number"
            ),
            "frozen_packages_read": [],
        },
    }


def _derive(
    selection_block: Mapping[str, Any],
    q_af: Optional[float],
    q_native: Optional[float],
) -> Dict[str, Any]:
    wall = selection_block["selection_wall_ms_median"]
    if q_af is None or q_native is None or wall is None:
        return {"status": "incomplete"}
    be = scc.break_even(wall, q_af, q_native)
    scc.assert_break_even_paired(be)
    amort = scc.amortization(wall, q_af, q_native)
    return {
        "Q_CA_ms": q_af,
        "Q_N_ms": q_native,
        "selection_wall_ms": wall,
        # C3: E10's wall already includes the planning inputs, so it IS the
        # commensurable quantity for pooling against E3's wall+inputs.
        "pooled_commensurable_wall_ms": wall,
        "primary": be,
        "sensitivity_inputs_included": None,
        "amortization": amort,
        "k_star_grid": scc.k_star_grid(amort),
    }
