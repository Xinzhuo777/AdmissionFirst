"""Campaign B, E3 arm: 33 SF1 cells (11 queries x 3 policy configs).

Anchor (memo section 1.2): the selection wall is the EXTERNAL bracket around
``e3_main._plan_e3_admission_first`` - the anchor the repository already uses at
``e3_sigmod_preview.py:466``/``:482``.  ``e3_main.py`` is never edited and the
selection function is never wrapped.

Per-cell order, mirroring ``e3_sigmod_preview._prepare_cell_live`` and
``e3_main.run_e3_main``:

1. planning-input probes and the planning catalog receipt  -> ``selection_inputs_ms``
2. artifact build + native-RLS DDL                          -> EXCLUDED (provisioning)
3. 1 warmup + 5 measured selections, same artifact state    -> ``selection_wall_ms``
4. ``+PD`` triple discriminant, untimed
5. 5 warmup + 10 measured latency reps per admitted mode via the frozen
   ``e3_main._measure_e3_query`` -> ``Q_CA`` / ``Q_N``
"""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
)

import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from caprls_core import selection_cost_common as scc
from caprls_core.selection_cost_common import SelectionCostError

FAMILY = "E3"
CONTEXT_ID = "e3_main_ctx"
MODE_AF = ADMISSION_FIRST_MODE
MODE_NATIVE = "native-pg-rls"
MODE_PD = "native-pg-rls-physical-design"
MODES = (MODE_AF, MODE_NATIVE, MODE_PD)

SELECTION_WALL_SCOPE = (
    "cell_level_full_selection_client_wall_ms_including_session_open"
)


class _E3CostVectorAndExplainWall:
    """Observe per-candidate prospective cost and EXPLAIN wall time.

    Pass-through wrapper on ``e3_main._verify_e3_static``, the same read-only
    hook ``content_verify._E3CostVectorCapture`` (``:852-899``) uses and the
    same one the Cell-10 attribution used.  ``e3_main.py`` stays byte-identical;
    the original is restored in ``finally``.

    ``_verify_e3_static`` is called once per costed candidate, immediately after
    ``costs[plan_id] = plan_root["Total Cost"]`` (``e3_main.py:6264-6265``), so
    the inter-call delta is a faithful per-candidate EXPLAIN accounting.
    """

    def __init__(self, e3: Any) -> None:
        self._e3 = e3
        self._original: Any = None
        self.observations: List[Dict[str, Any]] = []
        self._last_exit: Optional[float] = None

    def reset(self) -> None:
        self.observations = []
        self._last_exit = None

    def __enter__(self) -> "_E3CostVectorAndExplainWall":
        self._original = getattr(self._e3, "_verify_e3_static")
        original = self._original
        capture = self

        def _wrapper(template_id, runner_body, explain_json, *args, **kwargs):
            try:
                now = time.perf_counter()
                cost = explain_json[0]["Plan"]["Total Cost"]
                capture.observations.append(
                    {
                        "template_id": str(template_id),
                        "prospective_total_cost": float(cost),
                        "runner_sql_digest": scc.sha256_text(str(runner_body)),
                        "observed_at_perf_counter": now,
                    }
                )
            except Exception:  # noqa: BLE001 - observation must never perturb
                pass
            return original(template_id, runner_body, explain_json, *args, **kwargs)

        setattr(self._e3, "_verify_e3_static", _wrapper)
        return self

    def __exit__(self, *exc_info: Any) -> None:
        setattr(self._e3, "_verify_e3_static", self._original)

    def summary(self, selection_started: float) -> Dict[str, Any]:
        obs = self.observations
        if not obs:
            return {
                "candidate_explain_count": 0,
                "candidate_explain_wall_ms": None,
                "candidate_cost_vector": [],
            }
        span_ms = (obs[-1]["observed_at_perf_counter"] - selection_started) * 1000.0
        return {
            "candidate_explain_count": len(obs),
            "candidate_explain_wall_ms": span_ms,
            "candidate_explain_wall_definition": (
                "perf_counter span from the selection bracket start to the last "
                "per-candidate EXPLAIN observation; an upper bound on the "
                "prospective-EXPLAIN phase, not a sum of isolated calls"
            ),
            "candidate_cost_vector": [
                {
                    "template_id": item["template_id"],
                    "prospective_total_cost": item["prospective_total_cost"],
                    "runner_sql_digest": item["runner_sql_digest"],
                }
                for item in obs
            ],
        }


def _timed(fn, *args, **kwargs) -> Tuple[Any, float]:
    started = time.perf_counter()
    value = fn(*args, **kwargs)
    return value, (time.perf_counter() - started) * 1000.0


def short_id(query_id: str, policy_id: str) -> str:
    return f"E3_{query_id}_{policy_id}"


def cell_id(query_id: str, policy_id: str) -> str:
    return (
        f"{scc.CAMPAIGN_B}|family=E3|query={query_id}"
        f"|policy={policy_id}|context={CONTEXT_ID}"
    )


def measurement_sql(e3: Any, query: Any, policy: Any, template_id: str) -> Dict[str, Any]:
    """Build the statement the frozen E3 window actually times.

    ``_measure_e3_query`` opens with ``_require_e3_measurement_identity``
    (``e3_main.py:7284-7316``), which reconstructs the expected statement from
    ``(query, policy, source)`` and refuses anything that is not **byte-identical**:

    .. code-block:: python

        expected_sql = (_native_rls_count_sql(query, policy) if native_rls
                        else _query_count_sql(query, policy, source,
                                              _policy_predicate(query, policy)))

    So the measured object is the frozen **count-wrapped** query
    (``SELECT count(*) FROM ( <semantic sql> ) AS q`` behind the frozen GUC
    preamble), not the planner's runner SQL and not the bare semantic SQL.
    ``run_e3_main`` builds it exactly this way at ``e3_main.py:7534-7537`` and
    records it as the mode's ``runner_sql``, which is why the frozen
    ``runner_sql_hash`` is a hash of the count query.

    This function reproduces that construction and nothing else.  The guard is
    never bypassed or weakened; the harness is what changed.
    """

    source = e3._source_for_template(template_id)
    if source == "rls":
        sql = e3._native_rls_count_sql(query, policy)
    else:
        sql = e3._query_count_sql(
            query, policy, source, e3._policy_predicate(query, policy)
        )
    return {
        "template_id": template_id,
        "source": source,
        "native_rls": source == "rls",
        "sql": sql,
        "sql_digest": e3._canonical_sha256({"exact_runner_sql": sql}),
        "construction": (
            "_native_rls_count_sql(query, policy)"
            if source == "rls"
            else "_query_count_sql(query, policy, source, _policy_predicate(query, policy))"
        ),
    }


def assert_measurement_identity(e3: Any, query: Any, policy: Any, template_id: str) -> str:
    """Offline proof that our statement satisfies the frozen guard.

    Calls the frozen guard directly.  It performs no I/O, so this is a pure
    function check: it can run in the offline suite for all 33 cells and every
    arm, before a database exists.  Defect 1 of the first run was invisible to a
    13/13 offline suite precisely because nothing exercised this.
    """

    built = measurement_sql(e3, query, policy, template_id)
    e3._require_e3_measurement_identity(
        template_id, built["sql"], query, policy, built["source"]
    )
    return built["sql_digest"]


def _mode_template(e3: Any, policy: Any, mode: str) -> Optional[Dict[str, Any]]:
    """Resolve a fixed mode to its template, or explain why it is unavailable."""

    template_id, alternative = e3._template_for_mode(policy, mode)
    unavailable = e3._artifact_unavailable_reason(policy, template_id, mode)
    if mode == "injection-only" and not policy.injection_safe:
        unavailable = "mode requires an injection-safe exact policy predicate"
    if unavailable is not None:
        return {"unavailable_reason": unavailable, "template_id": template_id}
    return {"template_id": template_id, "alternative": alternative}


def _static_plan_hash(e3: Any, sql: str, pg_env: Any, *, native_rls: bool) -> str:
    """Untimed plain EXPLAIN plan hash, for the ``+PD`` discriminant.

    ``_explain_json`` strips psql directives itself (``e3_main.py:4340``), so
    the frozen count-wrapped statement can be passed in verbatim.
    """

    explain_json = e3._explain_json(sql, pg_env, native_rls=native_rls, analyze=False)
    return e3._explain_plan_hash(explain_json)


def pd_discriminant(
    e3: Any,
    query: Any,
    policy: Any,
    pg_env: Any,
) -> Dict[str, Any]:
    """C-memo section 2.5 triple discriminant, run before any timed work.

    ``+PD`` is measured as an independent comparator only when its template id,
    its runner-SQL digest OR its static plan hash differs from Native.  All
    three comparisons are recorded regardless of outcome, so the decision is
    auditable from the package alone.
    """

    native_mode = _mode_template(e3, policy, MODE_NATIVE)
    pd_mode = _mode_template(e3, policy, MODE_PD)
    if "unavailable_reason" in native_mode or "unavailable_reason" in pd_mode:
        return {
            "pd_identity": "undetermined",
            "reason": "native or +PD template unavailable for this policy",
            "native": native_mode,
            "pd": pd_mode,
        }
    native = measurement_sql(e3, query, policy, native_mode["template_id"])
    pd = measurement_sql(e3, query, policy, pd_mode["template_id"])
    native_hash = _static_plan_hash(
        e3, native["sql"], pg_env, native_rls=native["native_rls"]
    )
    pd_hash = _static_plan_hash(e3, pd["sql"], pg_env, native_rls=pd["native_rls"])
    template_equal = native["template_id"] == pd["template_id"]
    digest_equal = native["sql_digest"] == pd["sql_digest"]
    plan_equal = native_hash == pd_hash
    collapsed = template_equal and digest_equal and plan_equal
    return {
        "pd_identity": "collapsed_to_native" if collapsed else "independent",
        "template_id_equal": template_equal,
        "sql_digest_equal": digest_equal,
        "static_plan_hash_equal": plan_equal,
        "native_template_id": native["template_id"],
        "pd_template_id": pd["template_id"],
        "native_sql_digest": native["sql_digest"],
        "pd_sql_digest": pd["sql_digest"],
        "native_static_plan_hash": native_hash,
        "pd_static_plan_hash": pd_hash,
        "conjunction": "template_id AND sql_digest AND static_plan_hash",
        "precedent": "caprls_core/e3_scale_check.py:214-219 (strengthened)",
        "action": (
            "report_native_only_and_record"
            if collapsed
            else "measure_and_report_as_own_comparator"
        ),
    }


def measure_latency(
    e3: Any,
    *,
    template_id: str,
    sql: str,
    query: Any,
    policy: Any,
    source: str,
    pg_env: Any,
) -> Dict[str, Any]:
    """One latency observation through the FROZEN window.

    ``total = PostgreSQL planning + PostgreSQL execution + same-snapshot
    artifact validation``, composed with the frozen formula
    (``e3_main.py:8083-8090``).  No client wall clock, no selection.
    """

    (
        row_count,
        planning_ms,
        execution_ms,
        validation_ms,
        same_snapshot,
        isolation_level,
        verification,
        _explain_json,
    ) = e3._measure_e3_query(template_id, sql, query, policy, source, pg_env)
    return {
        "planning_ms": float(planning_ms),
        "execution_ms": float(execution_ms),
        "validation_ms": float(validation_ms),
        "total_ms": float(planning_ms) + float(execution_ms) + float(validation_ms),
        "row_count": int(row_count),
        "validation_same_snapshot": bool(same_snapshot),
        "isolation_level": isolation_level,
        "static_verification_status": getattr(verification, "status", None),
    }


def _rotated(items: Sequence[Any], index: int) -> Tuple[Any, ...]:
    """Deterministic counterbalancing, derived only from the repetition index.

    Same discipline as ``e3_main._rotated_e3_sequence:8379-8391``: no
    randomness, no outcome feedback.
    """

    ordered = tuple(items)
    if not ordered:
        return ()
    offset = index % len(ordered)
    return ordered[offset:] + ordered[:offset]


def run_cell(
    *,
    root: Path,
    pg_env: Any,
    manifest: Mapping[str, Any],
    query: Any,
    policy: Any,
    ranker: Any,
    registry: Any,
    identity: Mapping[str, Any],
    selection_warmup: int = scc.E3_SELECTION_WARMUP,
    selection_measured: int = scc.E3_SELECTION_MEASURED,
    latency_warmup: int = scc.LATENCY_WARMUP,
    latency_measured: int = scc.LATENCY_MEASURED,
    access_root_materialized: bool = True,
    run_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Measure one E3 cell end to end and return its receipt."""

    from caprls_core import e3_main as e3
    from caprls_core.postgres_runner import run_psql_command

    sid = short_id(query.query_id, policy.config_id)

    # --- C1: post-anchor steps must be no-ops --------------------------------
    topk = scc.assert_adaptive_topk_disabled(root, manifest)

    # --- planning inputs (E10 counts these inside its bracket; E3 does not) --
    protected_rows, t_protected = _timed(e3._protected_count, query, pg_env)
    query_local_rows_raw, t_local = _timed(
        run_psql_command,
        f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} "
        f"WHERE {e3._query_local_predicate(query)};",
        pg_env,
    )
    query_local_rows = int(query_local_rows_raw)
    predicate = e3._policy_predicate(query, policy)

    # --- provisioning: EXCLUDED from every selection quantity ----------------
    build_ms, artifact_rows, keyed_artifact_rows = e3._build_artifact(
        query, policy, predicate, pg_env
    )
    e3._configure_native_rls(query, policy, pg_env)

    receipt, t_receipt = _timed(
        e3._collect_e3_planning_catalog_receipt, query, policy, pg_env
    )
    authorized_raw, t_authorized = _timed(
        run_psql_command,
        f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} "
        f"WHERE {predicate};",
        pg_env,
    )
    authorized_rows = int(authorized_raw)
    if artifact_rows:
        authorized_rows = artifact_rows

    selection_inputs_ms = t_protected + t_local + t_receipt + t_authorized

    # --- selection: 1 warmup + 5 measured, same artifact state ---------------
    capture = _E3CostVectorAndExplainWall(e3)
    walls: List[float] = []
    explain_summaries: List[Dict[str, Any]] = []
    selected: Optional[Dict[str, Any]] = None
    plan_identities: List[Tuple[str, Any]] = []

    with capture:
        for index in range(selection_warmup + selection_measured):
            capture.reset()
            started = time.perf_counter()
            plan_result, query_plan, _problem = e3._plan_e3_admission_first(
                query=query,
                policy=policy,
                predicate=predicate,
                pg_env=pg_env,
                protected_rows=protected_rows,
                query_local_rows=query_local_rows,
                authorized_rows=authorized_rows,
                build_ms=build_ms,
                ranker=ranker,
                registry=registry,
                keyed_artifact_rows=keyed_artifact_rows,
                planning_catalog_receipt=receipt,
                access_root_materialized=access_root_materialized,
            )
            wall_ms = (time.perf_counter() - started) * 1000.0
            summary = capture.summary(started)
            if index < selection_warmup:
                continue
            walls.append(wall_ms)
            explain_summaries.append(summary)
            bound = query_plan.get("production_bound_runner")
            chosen_cost = query_plan.get("production_chosen_cost")
            if not isinstance(bound, Mapping):
                raise SelectionCostError("E3 selection lacks its bound runner")
            selected = {
                "selected_template_id": e3._require_e3_selected_root_template(query_plan),
                "selected_plan_id": bound.get("plan_id"),
                "selected_runner_sql": bound.get("runner_sql"),
                "selected_runner_sql_digest": bound.get("runner_sql_digest"),
                "prospective_total_cost": (
                    dict(chosen_cost) if isinstance(chosen_cost, Mapping) else None
                ),
                "candidate_cost_vector": summary["candidate_cost_vector"],
            }
            plan_identities.append(
                (str(bound.get("plan_id")), summary["candidate_explain_count"])
            )

    if selected is None:
        raise SelectionCostError("E3 selection produced no measured repetition")

    stable_within_cell = len({pid for pid, _ in plan_identities}) == 1
    wall_dist = scc.distribution(walls)
    explain_walls = [
        s["candidate_explain_wall_ms"]
        for s in explain_summaries
        if s.get("candidate_explain_wall_ms") is not None
    ]

    selection_block: Dict[str, Any] = {
        "anchor": {
            "kind": "external_bracket",
            "call": "caprls_core/e3_main.py:6007 _plan_e3_admission_first",
            "precedent": "caprls_core/e3_sigmod_preview.py:466,482",
            "wrapped": False,
            "excludes": [
                "_build_artifact (provisioning)",
                "_configure_native_rls (baseline DDL)",
                "_collect_e3_planning_catalog_receipt (counted in selection_inputs_ms)",
                "row-count probes (counted in selection_inputs_ms)",
            ],
        },
        "selection_wall_scope": SELECTION_WALL_SCOPE,
        "selection_repeat_semantics": "same_artifact_state",
        "selection_repeats_beyond_frozen_path": selection_measured
        + selection_warmup
        - 1,
        "selection_warmup": selection_warmup,
        "selection_measured": selection_measured,
        "selection_wall_ms_median": wall_dist["median"],
        "selection_wall_ms_distribution": wall_dist,
        "selection_inputs_ms": selection_inputs_ms,
        "selection_inputs_breakdown_ms": {
            "protected_count": t_protected,
            "query_local_count": t_local,
            "planning_catalog_receipt": t_receipt,
            "authorized_count": t_authorized,
        },
        "selection_wall_plus_inputs_ms": (
            (wall_dist["median"] or 0.0) + selection_inputs_ms
        ),
        "candidate_explain_count": explain_summaries[0]["candidate_explain_count"],
        "candidate_explain_wall_ms_median": scc._median(explain_walls),
        "selection_residual_ms_median": (
            (wall_dist["median"] - scc._median(explain_walls))
            if wall_dist["median"] is not None and explain_walls
            else None
        ),
        "selection_stable_within_cell": stable_within_cell,
        "observed_plan_ids": sorted({pid for pid, _ in plan_identities}),
        **{k: v for k, v in selected.items()},
        **topk,
    }

    # --- +PD discriminant (untimed) -----------------------------------------
    pd = pd_discriminant(e3, query, policy, pg_env)

    # --- latency -------------------------------------------------------------
    # Every arm's statement goes through the SAME construction the frozen
    # runner uses (e3_main.py:7534-7537), so `_require_e3_measurement_identity`
    # accepts it byte-for-byte.  The guard is never bypassed or weakened.
    # Note what this means: the timed object is the frozen count-wrapped query,
    # NOT the planner's runner SQL.  That is the frozen E3 SF1 window, and the
    # planner's runner SQL is kept separately in `selection.selected_runner_sql_digest`.
    arms: List[Dict[str, Any]] = []
    af_built = measurement_sql(e3, query, policy, selection_block["selected_template_id"])
    arms.append({"mode": MODE_AF, **af_built})

    native_mode = _mode_template(e3, policy, MODE_NATIVE)
    if "unavailable_reason" in native_mode:
        raise SelectionCostError(
            "E3 native comparator unavailable for "
            f"{query.query_id}/{policy.config_id}: {native_mode['unavailable_reason']}"
        )
    arms.append({"mode": MODE_NATIVE, **measurement_sql(e3, query, policy, native_mode["template_id"])})

    if pd.get("pd_identity") == "independent":
        pd_mode = _mode_template(e3, policy, MODE_PD)
        arms.append(
            {"mode": MODE_PD, **measurement_sql(e3, query, policy, pd_mode["template_id"])}
        )

    # Fail fast and offline-checkably: prove every arm satisfies the frozen
    # identity guard before a single statement is timed.
    for arm in arms:
        e3._require_e3_measurement_identity(
            arm["template_id"], arm["sql"], query, policy, arm["source"]
        )

    samples: Dict[str, List[Dict[str, Any]]] = {arm["mode"]: [] for arm in arms}
    for rep in range(latency_warmup + latency_measured):
        for arm in _rotated(arms, rep):
            observation = measure_latency(
                e3,
                template_id=arm["template_id"],
                sql=arm["sql"],
                query=query,
                policy=policy,
                source=arm["source"],
                pg_env=pg_env,
            )
            if rep >= latency_warmup:
                samples[arm["mode"]].append(observation)

    latency: Dict[str, Any] = {}
    for arm in arms:
        rows = samples[arm["mode"]]
        latency[arm["mode"]] = {
            "template_id": arm["template_id"],
            "source": arm["source"],
            "measured_statement": "frozen_count_wrapped_query",
            "measured_statement_construction": arm["construction"],
            "runner_sql_digest": arm["sql_digest"],
            "planning_ms_median": scc._median([r["planning_ms"] for r in rows]),
            "execution_ms_median": scc._median([r["execution_ms"] for r in rows]),
            "validation_ms_median": scc._median([r["validation_ms"] for r in rows]),
            "total_ms_median": scc._median([r["total_ms"] for r in rows]),
            "row_count_median": scc._median([float(r["row_count"]) for r in rows]),
            "samples": rows,
        }
    if pd.get("pd_identity") == "collapsed_to_native":
        latency[MODE_PD] = {
            "template_id": pd.get("pd_template_id"),
            "total_ms_median": None,
            "ratio_source": "identity_collapsed",
            "collapsed_to": MODE_NATIVE,
            "note": (
                "template id, runner-SQL digest and static plan hash all equal "
                "Native's; +PD was not measured and is reported as Native"
            ),
        }

    q_af = latency[MODE_AF]["total_ms_median"]
    q_native = latency[MODE_NATIVE]["total_ms_median"]
    derived = _derive(selection_block, q_af, q_native)

    return {
        "schema": scc.RECEIPT_SCHEMA_B,
        "short_id": sid,
        "cell_id": cell_id(query.query_id, policy.config_id),
        "family": FAMILY,
        "query_id": query.query_id,
        "policy_id": policy.config_id,
        "context_id": CONTEXT_ID,
        "status": "pass",
        "failure_reason": None,
        "identity": dict(identity),
        "dataset": {
            "protected_relation": query.protected_rel,
            "protected_rows": protected_rows,
            "query_local_rows": query_local_rows,
            "authorized_rows": authorized_rows,
            "artifact_rows": artifact_rows,
            "keyed_artifact_rows": keyed_artifact_rows,
            "artifact_build_ms": build_ms,
        },
        "protocol": {
            "selection_warmup": selection_warmup,
            "selection_measured": selection_measured,
            "latency_warmup": latency_warmup,
            "latency_measured": latency_measured,
            "mode_rotation": "deterministic_by_repetition_index",
            "serial": True,
            "measurement_window": (
                "postgres_planning_plus_execution_plus_validation_ms"
            ),
            "measurement_gucs": dict(
                getattr(__import__("caprls_core.e3_main", fromlist=["x"]), "E3_PSQL_GUCS")
            ),
            "modes_measured": [arm["mode"] for arm in arms],
        },
        "selection": selection_block,
        "pd_discriminant": pd,
        "latency": latency,
        "derived": derived,
        "provenance": _provenance(),
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
    sensitivity_wall = selection_block.get("selection_wall_plus_inputs_ms")
    be_inputs = (
        scc.break_even(sensitivity_wall, q_af, q_native)
        if sensitivity_wall is not None
        else None
    )
    if be_inputs is not None:
        scc.assert_break_even_paired(be_inputs)
    return {
        "Q_CA_ms": q_af,
        "Q_N_ms": q_native,
        "selection_wall_ms": wall,
        # C3: E3's contribution to any pooled figure is the commensurable one.
        "pooled_commensurable_wall_ms": sensitivity_wall,
        "primary": be,
        "sensitivity_inputs_included": be_inputs,
        "amortization": amort,
        "k_star_grid": scc.k_star_grid(amort),
    }


def _provenance() -> Dict[str, Any]:
    return {
        "campaign": scc.CAMPAIGN_B,
        "relationship_to_frozen": (
            "new_measurement_this_machine_this_state; does_not_restate_correct_"
            "or_replace_any_frozen_number"
        ),
        "frozen_packages_read": [],
    }


def load_family(root: Path, manifest_path: Path) -> Dict[str, Any]:
    """Load the E3 manifest, queries and policies without touching the DB."""

    from caprls_core import e3_main as e3
    from caprls_core.e3_smoke import _load_manifest

    manifest = _load_manifest(manifest_path)
    e3._validate_manifest(manifest_path, manifest)
    queries = tuple(e3._queries_for_manifest(manifest_path, manifest))
    policies = tuple(e3._policies_for_manifest(manifest_path, manifest))
    return {"manifest": manifest, "queries": queries, "policies": policies}
