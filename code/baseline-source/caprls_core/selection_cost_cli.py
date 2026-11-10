"""Standalone CLI for the R4A selection-cost campaigns.

    python -m caprls_core.selection_cost_cli <subcommand>

``caprls_core/cli.py`` is a measurement-path file and is NOT touched; this
module is the campaigns' own entry point, exactly as R3 shipped
``content_cli.py`` rather than extending the shared CLI.

Subcommands
-----------
``predeclare``      write the write-once signed pre-registration
``offline-checks``  every check that needs no database
``provision``       build the campaign databases from each family's own builder
``run-b``           SELECTION_COST_V1 (44 cells), then seal
``run-c``           STABILITY_WITNESS_V1 (11 cells x 10 rounds), then seal
``analyze``         re-derive summary artifacts from an existing package
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from caprls_core import selection_cost_analyze as analyze
from caprls_core import selection_cost_common as scc
from caprls_core import selection_cost_e3 as e3arm
from caprls_core import selection_cost_e10 as e10arm
from caprls_core import selection_cost_predeclare as predeclare
from caprls_core import stability_witness_e3 as witness
from caprls_core.selection_cost_common import SelectionCostError

DEFAULT_DB_PREFIX = "caprls_selcost"


def _repo_root() -> Path:
    return scc.repo_root()


def _pg_env(args: argparse.Namespace, database: str):
    from caprls_core.postgres_runner import PostgresEnv

    return PostgresEnv(
        host=args.pg_host, port=args.pg_port, user=args.pg_user, database=database
    )


def _content_pg_env(args: argparse.Namespace, database: str):
    from caprls_core.content_psql import ContentPostgresEnv

    return ContentPostgresEnv(
        host=args.pg_host, port=args.pg_port, user=args.pg_user, database=database
    )


def _database_for(args: argparse.Namespace, family: str) -> str:
    return f"{args.pg_database_prefix}_{family.lower()}"


def _campaign_dir(root: Path, args: argparse.Namespace, default: str) -> Path:
    """Package directory for this attempt.

    The directory is the RUN id; the pre-registered campaign identity that
    appears in every ``cell_id`` comes from the signed spec and does not move
    with it.  So a repaired full rerun can write ``SELECTION_COST_V2`` while
    ``specs/selection_cost_cells.yaml`` and the memo keep their digests - the
    signed artefacts are not reopened just to change a folder name.
    """

    name = getattr(args, "campaign_dir", None) or default
    return root / "results" / "raw" / name


# ---------------------------------------------------------------------------
# predeclare
# ---------------------------------------------------------------------------


def cmd_predeclare(args: argparse.Namespace) -> int:
    root = _repo_root()
    run_dir = _campaign_dir(root, args, scc.CAMPAIGN_B)
    spec_path = root / scc.SPEC_PATH
    if not spec_path.exists():
        raise SelectionCostError(f"campaign spec missing: {scc.SPEC_PATH}")
    result = predeclare.write_predeclaration(
        root, run_dir=run_dir, spec_path=spec_path, overwrite=args.overwrite
    )
    print(json.dumps(result, indent=2))
    return 0


# ---------------------------------------------------------------------------
# offline checks
# ---------------------------------------------------------------------------


def cmd_offline_checks(args: argparse.Namespace) -> int:
    root = _repo_root()
    report = run_offline_checks(root)
    print(json.dumps(report, indent=2, default=str))
    return 0 if report["ok"] else 1


def run_offline_checks(root: Path) -> Dict[str, Any]:
    """Every pre-run check that needs no database (memo section 10.3, 1-8)."""

    checks: List[Dict[str, Any]] = []

    def record(name: str, fn) -> None:
        try:
            detail = fn()
            checks.append({"check": name, "ok": True, "detail": detail})
        except Exception as exc:  # noqa: BLE001 - report, do not abort the suite
            checks.append(
                {
                    "check": name,
                    "ok": False,
                    "error": f"{exc.__class__.__name__}: {exc}",
                    "traceback": traceback.format_exc(limit=4),
                }
            )

    record("anchor_symbols_resolve", lambda: _check_anchor_symbols())
    record("e10_excluded_tail_measured", scc.measure_e10_excluded_tail)
    record("e10_call_site_uniqueness", _check_call_sites)
    record("wrapper_neutrality_dry_run", _check_wrapper_neutrality)
    record("adaptive_topk_disabled", lambda: _check_adaptive_topk(root))
    record("e3_measurement_identity_all_cells", lambda: _check_e3_measurement_identity(root))
    record("c3_pooled_requires_both_families", _check_pooled_family_representation)
    record("per_cell_setup_matches_frozen_order", _check_per_cell_setup_order)
    record("formula_unit_vectors", _check_formulas)
    record("pd_discriminant_truth_table", _check_pd_truth_table)
    record("c6_break_even_pairing", _check_c6)
    record("c3_c4_pooled_labels", _check_pooled)
    record("c8_denominator_always_ten", lambda: _check_c8())
    record("frozen_files_byte_intact", lambda: scc.frozen_files_unchanged(root))
    record(
        "reused_latency_function_digests",
        lambda: [scc.function_digest(m, a) for m, a in scc.LATENCY_FUNCTIONS],
    )
    record("classification_spec_loads", lambda: _check_classification(root))

    ok = all(item["ok"] for item in checks)
    return {
        "ok": ok,
        "checked_at": scc.utc_now(),
        "check_count": len(checks),
        "failed": [item["check"] for item in checks if not item["ok"]],
        "checks": checks,
    }


def _check_anchor_symbols() -> Dict[str, Any]:
    import inspect

    from caprls_core import e10_study, e3_main

    required = {
        "e3_main._plan_e3_admission_first": e3_main._plan_e3_admission_first,
        "e3_main._verify_e3_static": e3_main._verify_e3_static,
        "e3_main._measure_e3_query": e3_main._measure_e3_query,
        "e3_main._build_artifact": e3_main._build_artifact,
        "e10_study._e10_planning_expectation": e10_study._e10_planning_expectation,
        "e10_study._planner_invocation_for_case": e10_study._planner_invocation_for_case,
        "e10_study._prospective_pg_cost": e10_study._prospective_pg_cost,
        "e10_study._prepare_postgres_measurements": (
            e10_study._prepare_postgres_measurements
        ),
        "e10_study._prepare_e10_case_postgres_measurements": (
            e10_study._prepare_e10_case_postgres_measurements
        ),
    }
    return {
        name: {
            "first_line": inspect.getsourcelines(fn)[1],
            "signature": str(inspect.signature(fn)),
        }
        for name, fn in required.items()
    }


def _check_call_sites() -> Dict[str, Any]:
    """Re-derive the call-site census the Gate relied on for ruling (b)."""

    import inspect
    import re

    from caprls_core import e10_study

    source = Path(inspect.getfile(e10_study)).read_text(encoding="utf-8").splitlines()
    sites: Dict[str, List[int]] = {}
    for name in (
        e10arm.START_FUNCTION,
        e10arm.STOP_FUNCTION,
        e10arm.ANCHOR_CALLER,
    ):
        pattern = re.compile(rf"(?<![\w.]){re.escape(name)}\(")
        hits = [
            index
            for index, line in enumerate(source, 1)
            if pattern.search(line) and not line.lstrip().startswith("def ")
        ]
        sites[name] = hits
    if len(sites[e10arm.START_FUNCTION]) != 1:
        raise SelectionCostError(
            "START anchor is no longer a single call site: "
            f"{sites[e10arm.START_FUNCTION]}"
        )
    if len(sites[e10arm.ANCHOR_CALLER]) != 1:
        raise SelectionCostError(
            "anchor caller is no longer single-entry: "
            f"{sites[e10arm.ANCHOR_CALLER]}"
        )
    return {
        "call_sites": sites,
        "start_anchor_unique": True,
        "caller_single_entry": True,
        "stop_anchor_discriminated_by": "caller code object assertion",
    }


def _check_wrapper_neutrality() -> Dict[str, Any]:
    """Prove the wrapper machinery is transparent, without touching a database."""

    import types

    module = types.ModuleType("neutrality_probe")

    def target(a: int, b: int = 2) -> int:
        return a * b + 1

    module.target = target  # type: ignore[attr-defined]
    baseline = [target(3), target(3, 5), target(a=4, b=7)]

    seen: List[str] = []

    wrapper = scc.PassThroughWrapper(
        module, "target", lambda phase, frame, ts, result, args, kwargs: seen.append(phase)
    )
    with wrapper:
        wrapped = [module.target(3), module.target(3, 5), module.target(a=4, b=7)]
    restored = module.target is target

    if wrapped != baseline:
        raise SelectionCostError("wrapper altered the wrapped function's result")
    if not restored:
        raise SelectionCostError("wrapper did not restore the original binding")

    # An observer that raises must not propagate.
    def exploding(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("observation failure")

    with scc.PassThroughWrapper(module, "target", exploding):
        if module.target(3) != baseline[0]:
            raise SelectionCostError("exploding observer perturbed the result")
    if module.target is not target:
        raise SelectionCostError("wrapper did not restore after an observer error")

    # And it must restore even when the wrapped call itself raises.
    def boom(*_args: Any, **_kwargs: Any) -> int:
        raise ValueError("wrapped call failure")

    module.boom = boom  # type: ignore[attr-defined]
    try:
        with scc.PassThroughWrapper(module, "boom", lambda *a, **k: None):
            module.boom()
    except ValueError:
        pass
    if module.boom is not boom:
        raise SelectionCostError("wrapper did not restore after a wrapped-call error")

    return {
        "baseline": baseline,
        "wrapped": wrapped,
        "observer_phases": seen,
        "restored_after_success": True,
        "restored_after_observer_error": True,
        "restored_after_wrapped_error": True,
    }


def _check_adaptive_topk(root: Path) -> Dict[str, Any]:
    from caprls_core.e3_smoke import _load_manifest

    manifest = _load_manifest(root / scc.E3_MANIFEST)
    return scc.assert_adaptive_topk_disabled(root, manifest)


def _check_per_cell_setup_order() -> Dict[str, Any]:
    """Both campaigns must reproduce the frozen per-cell setup sequence.

    Campaign C originally skipped ``_configure_native_rls``, so it inherited the
    RLS policy expression left by the previous campaign's last cell and every
    planning-catalog replay failed.  The frozen runner's order is the reference,
    read from ``e3_main.run_e3_main`` rather than restated here.
    """

    from caprls_core import e3_main as e3

    frozen = scc.call_order(e3.run_e3_main, scc.E3_PER_CELL_SETUP_ORDER)
    expected = [n for n in scc.E3_PER_CELL_SETUP_ORDER if n in frozen]
    if expected != list(scc.E3_PER_CELL_SETUP_ORDER):
        raise SelectionCostError(
            f"frozen run_e3_main no longer performs the reference order: {frozen}"
        )
    b_order = scc.assert_per_cell_setup_order(
        e3arm.run_cell, label="campaign B selection_cost_e3.run_cell"
    )
    c_order = scc.assert_per_cell_setup_order(
        witness.run_round, label="campaign C stability_witness_e3.run_round"
    )
    if b_order != c_order:
        raise SelectionCostError(
            f"B and C disagree on per-cell setup order: {b_order} != {c_order}"
        )
    return {
        "frozen_reference": frozen,
        "campaign_b": b_order,
        "campaign_c": c_order,
        "reference_source": "caprls_core.e3_main.run_e3_main",
        "method": "ast_call_order; no database required",
    }


def _check_e3_measurement_identity(root: Path) -> Dict[str, Any]:
    """Regression for the defect that blocked all 33 E3 cells.

    ``_require_e3_measurement_identity`` performs no I/O, so every cell and
    every arm can be proved offline, before a database exists.  The first run
    passed 13/13 offline checks while all 33 E3 cells were guaranteed to fail on
    their first latency observation, because nothing exercised this guard.
    """

    from caprls_core import e3_main as e3

    family = e3arm.load_family(root, root / scc.E3_MANIFEST)
    checked = 0
    per_policy: Dict[str, Any] = {}
    for query in family["queries"]:
        for policy in family["policies"]:
            arms = {}
            # Every template a cell can be measured under: the fixed comparator
            # modes plus every planner template that could be selected for AF.
            template_ids = set()
            for mode in (e3arm.MODE_NATIVE, e3arm.MODE_PD):
                resolved = e3arm._mode_template(e3, policy, mode)
                if "unavailable_reason" not in resolved:
                    template_ids.add(resolved["template_id"])
            template_ids.update(e3.E3_PLANNER_TEMPLATE_IDS)
            for template_id in sorted(template_ids):
                try:
                    e3._source_for_template(template_id)
                except Exception:  # noqa: BLE001 - template not measurable here
                    continue
                digest = e3arm.assert_measurement_identity(
                    e3, query, policy, template_id
                )
                arms[template_id] = digest
                checked += 1
            per_policy.setdefault(policy.config_id, len(arms))
    if checked == 0:
        raise SelectionCostError("no E3 measurement identity was checked")
    return {
        "cells": len(family["queries"]) * len(family["policies"]),
        "statements_verified": checked,
        "templates_per_policy": per_policy,
        "guard": "e3_main._require_e3_measurement_identity",
        "note": "pure-function check; no database required",
    }


def _check_pooled_family_representation() -> Dict[str, Any]:
    """C3 regression: an E10-only run must not emit a pooled row."""

    def cell(short_id: str, family: str) -> Dict[str, Any]:
        return {
            "short_id": short_id,
            "cell_id": f"SELECTION_COST_V1|family={family}|query={short_id}",
            "family": family,
            "status": "pass",
            "selection": {},
            "pd_discriminant": {},
            "derived": {
                "Q_CA_ms": 10.0,
                "Q_N_ms": 20.0,
                "pooled_commensurable_wall_ms": 100.0,
                "primary": scc.break_even(100.0, 10.0, 20.0),
                "sensitivity_inputs_included": None,
                "amortization": scc.amortization(100.0, 10.0, 20.0),
                "k_star_grid": None,
            },
        }

    e10_only = [cell("E10_Q1", "E10")]
    if scc.pooled_aggregate([], e10_only, k=10) is not None:
        raise SelectionCostError("C3: pooled row produced from zero E3 cells")
    if scc.pooled_aggregate([cell("E3_a", "E3")], [], k=10) is not None:
        raise SelectionCostError("C3: pooled row produced from zero E10 cells")

    summary = analyze.build_summary(
        receipts=e10_only,
        failures=[],
        identity={},
        denominators={"B_cells": 44},
        status="incomplete_stopped",
    )
    if summary["aggregates"]["pooled"]:
        raise SelectionCostError("C3: E10-only summary still published a pooled row")
    reason = summary["aggregates"]["pooled_omitted_reason"]
    if not reason or "E3" not in reason:
        raise SelectionCostError(f"C3: omission reason does not name the gap: {reason}")

    both = analyze.build_summary(
        receipts=[cell("E3_a", "E3"), cell("E10_Q1", "E10")],
        failures=[],
        identity={},
        denominators={"B_cells": 44},
        status="complete",
    )
    pooled = both["aggregates"]["pooled"]
    if len(pooled) != len(scc.K_GRID):
        raise SelectionCostError("C3: pooled rows missing when both families present")
    for row in pooled:
        if row["pooled_family_cell_counts"] != {"E3": 1, "E10": 1}:
            raise SelectionCostError("C3: pooled row misreports family contribution")
    return {
        "e10_only_omitted": True,
        "e3_only_omitted": True,
        "omission_reason": reason,
        "both_families_pooled": len(pooled),
    }


def _check_formulas() -> Dict[str, Any]:
    cases = []

    # Native slower than AF -> finite break-even.
    be = scc.break_even(1000.0, 10.0, 20.0)
    assert be["break_even_k"] == 100, be
    assert be["break_even_class"] == "finite"
    cases.append(be)

    # Native faster -> no finite break-even.
    be2 = scc.break_even(1000.0, 20.0, 10.0)
    assert be2["break_even_k"] is None and be2["break_even_class"] == "no_finite_break_even"
    cases.append(be2)

    # Exactly equal -> no finite break-even (delta == 0).
    be3 = scc.break_even(1000.0, 10.0, 10.0)
    assert be3["break_even_k"] is None, be3
    assert be3["within_tie_band"] is True, be3
    cases.append(be3)

    # Inside the 1 % band but positive -> finite AND flagged.
    be4 = scc.break_even(1000.0, 100.0, 100.5)
    assert be4["break_even_k"] == 2000, be4
    assert be4["within_tie_band"] is True, be4
    cases.append(be4)

    # Rounding is a ceiling, never a floor.
    assert scc.break_even(10.0, 1.0, 4.0)["break_even_k"] == 4

    amort = scc.amortization(1000.0, 10.0, 20.0)
    assert [row["k"] for row in amort] == list(scc.K_GRID)
    assert abs(amort[0]["amortized_ca_ms"] - 1010.0) < 1e-9
    assert abs(amort[-1]["amortized_ca_ms"] - 20.0) < 1e-9
    assert scc.k_star_grid(amort) is None

    # k* is the first grid point that WINS, not the first that ties.  With a
    # 10 ms wall, k=1 gives 10 + 10 = 20 ms against a 20 ms native: ratio 1.0,
    # inside the tie band, so k* is 2.
    amort2 = scc.amortization(10.0, 10.0, 20.0)
    assert [row["outcome_k"] for row in amort2][0] == "tie", amort2
    assert scc.k_star_grid(amort2) == 2, amort2
    # A wall small enough to win outright at k=1.
    amort3 = scc.amortization(1.0, 10.0, 20.0)
    assert scc.k_star_grid(amort3) == 1, amort3

    assert scc.outcome(1.02) == "win"
    assert scc.outcome(1.0) == "tie"
    assert scc.outcome(0.5) == "loss"
    return {"break_even_vectors": cases, "k_grid": list(scc.K_GRID)}


def _check_pd_truth_table() -> Dict[str, Any]:
    rows = []
    for template_equal in (True, False):
        for digest_equal in (True, False):
            for plan_equal in (True, False):
                native = {"runner_sql_digest": "a", "static_plan_hash": "p"}
                pd = {
                    "runner_sql_digest": "a" if digest_equal else "b",
                    "static_plan_hash": "p" if plan_equal else "q",
                }
                result = e10arm.pd_discriminant_from_measurements(
                    native,
                    pd,
                    native_template_id="t",
                    pd_template_id="t" if template_equal else "u",
                )
                expected = (
                    "collapsed_to_native"
                    if (template_equal and digest_equal and plan_equal)
                    else "independent"
                )
                if result["pd_identity"] != expected:
                    raise SelectionCostError(
                        f"+PD truth table wrong for {(template_equal, digest_equal, plan_equal)}"
                    )
                rows.append(
                    {
                        "template_equal": template_equal,
                        "digest_equal": digest_equal,
                        "plan_equal": plan_equal,
                        "pd_identity": result["pd_identity"],
                    }
                )
    if sum(1 for row in rows if row["pd_identity"] == "collapsed_to_native") != 1:
        raise SelectionCostError("+PD collapse must require all three equalities")
    return {"rows": rows}


def _check_c6() -> Dict[str, Any]:
    good = scc.break_even(1.0, 1.0, 2.0)
    scc.assert_break_even_paired(good)
    try:
        scc.assert_break_even_paired({"break_even_k": 3})
    except SelectionCostError:
        pass
    else:
        raise SelectionCostError("C6 guard did not reject an unpaired break_even_k")
    if "within_tie_band" not in analyze.SUMMARY_COLUMNS:
        raise SelectionCostError("C6: summary CSV lacks within_tie_band")
    if analyze.SUMMARY_COLUMNS.index("within_tie_band") != (
        analyze.SUMMARY_COLUMNS.index("break_even_k") + 1
    ):
        raise SelectionCostError("C6: within_tie_band must be adjacent to break_even_k")
    return {"paired": True, "csv_adjacent": True}


def _check_pooled() -> Dict[str, Any]:
    def cell(short_id: str, wall: Optional[float]) -> Dict[str, Any]:
        return {
            "short_id": short_id,
            "derived": {
                "Q_CA_ms": 10.0,
                "Q_N_ms": 20.0,
                "pooled_commensurable_wall_ms": wall,
                "amortization": scc.amortization(100.0, 10.0, 20.0),
            },
        }

    complete = scc.pooled_aggregate([cell("a", 100.0)], [cell("b", 50.0)], k=10)
    scc.assert_pooled_labels_present(complete)
    missing = scc.pooled_aggregate([cell("a", None)], [cell("b", 50.0)], k=10)
    if missing is not None:
        raise SelectionCostError("C3: pooled row produced from an incommensurable set")
    try:
        scc.assert_pooled_labels_present({"aggregation_scope": "x"})
    except SelectionCostError:
        pass
    else:
        raise SelectionCostError("C4 guard did not reject a partly labelled pooled row")
    return {
        "pooled_with_labels": {
            key: complete[key]
            for key in (
                "aggregation_scope",
                "pooled_measurand_scope_mismatch",
                "pooled_commensurable_pairing",
            )
        },
        "omitted_when_incommensurable": True,
    }


def _check_c8() -> Dict[str, Any]:
    rounds = [
        {
            "round": index,
            "selected_template_id": "auth_index_enum_v1" if index % 3 else "barrier_filter_v1",
            "candidate_cost_vector": [
                {"template_id": "auth_index_enum_v1", "prospective_total_cost": 100.0 + index},
                {"template_id": "barrier_filter_v1", "prospective_total_cost": 150.0},
            ],
            "cell_position_in_round": index,
            "artifact_state": {"auth_idx": {"relpages": index}},
            "content": {"content_state": "same"},
            "latency_object_id": "sha256:x",
        }
        for index in range(1, 9)
    ]
    failures = [
        {"round": 9, "failure_reason": "psql timeout"},
        {"round": 10, "failure_reason": "psql timeout"},
    ]
    receipt = witness.build_cell_receipt("E3_Q3_group_acl_expensive", rounds, failures)
    if receipt["rounds_denominator"] != scc.C_ROUNDS:
        raise SelectionCostError("C8: denominator is not 10")
    for printed in receipt["selection_frequency_printed"].values():
        if not printed.endswith(f"/{scc.C_ROUNDS}"):
            raise SelectionCostError(f"C8: distribution not printed as n/10: {printed}")
    if len(receipt["failed_rounds"]) != 2:
        raise SelectionCostError("C8: failed rounds not enumerated")
    witness.assert_no_banned_vocabulary(receipt["witness_sentence"])
    return {
        "printed": receipt["selection_frequency_printed"],
        "failed_rounds": receipt["failed_rounds"],
        "witness_sentence": receipt["witness_sentence"],
    }


def _check_classification(root: Path) -> Dict[str, Any]:
    classification = witness.load_classification(root)
    if len(classification["entries"]) != 11:
        raise SelectionCostError(
            f"classification spec has {len(classification['entries'])} entries, expected 11"
        )
    order = classification["canonical_order"]
    rotations = {tuple(witness.rotated_cells(order, r)) for r in range(1, scc.C_ROUNDS + 1)}
    if len(rotations) != scc.C_ROUNDS:
        raise SelectionCostError("C rotation is not distinct across the ten rounds")
    return {
        "entries": len(classification["entries"]),
        "digest": classification["digest"],
        "distinct_round_orders": len(rotations),
    }


# ---------------------------------------------------------------------------
# provision
# ---------------------------------------------------------------------------


def cmd_provision(args: argparse.Namespace) -> int:
    from caprls_core import content_verify as cv

    root = _repo_root()
    results = {}
    target = {
        "pg_host": args.pg_host,
        "pg_port": args.pg_port,
        "pg_user": args.pg_user,
        "database_prefix": args.pg_database_prefix,
    }
    for family in args.family:
        database = _database_for(args, family)
        pg_env = _content_pg_env(args, database)
        manifest = root / (scc.E3_MANIFEST if family == "E3" else scc.E10_MANIFEST)
        results[family] = cv.provision_family(
            root, family, pg_env, manifest_path=manifest, create_database=True
        )
        # Record the vacuum regime at provisioning time.  Campaign C refuses to
        # start unless it is off, and B's numbers are only comparable to C's
        # under the same regime, so a silently-wrong connection target must be
        # caught here rather than three hours later.
        autovacuum = witness.show_autovacuum(_pg_env(args, database))
        results[family]["autovacuum"] = autovacuum
        results[family]["connection_target"] = dict(target, database=database)
        if autovacuum.lower() != "off" and not args.allow_autovacuum_on:
            raise SelectionCostError(
                f"{database} on {args.pg_host}:{args.pg_port} has "
                f"autovacuum = {autovacuum!r}, not 'off'. Campaign C will "
                "refuse to start against this cluster and B would not be "
                "comparable to it. Point --pg-host/--pg-port at the dedicated "
                "campaign cluster, or pass --allow-autovacuum-on to override."
            )
    print(json.dumps(results, indent=2, default=str))
    return 0


# ---------------------------------------------------------------------------
# run-b
# ---------------------------------------------------------------------------


def cmd_run_b(args: argparse.Namespace) -> int:
    root = _repo_root()
    run_dir = _campaign_dir(root, args, scc.CAMPAIGN_B)
    signed = predeclare.require_predeclaration(run_dir)

    if scc.package_is_sealed(run_dir):
        raise SelectionCostError(
            f"{run_dir} is already sealed; a new attempt takes a V2 directory"
        )

    identity = scc.identity_block(
        root,
        campaign=scc.CAMPAIGN_B,
        spec_path=root / scc.SPEC_PATH,
        predeclaration_path=run_dir / scc.PREDECLARATION_NAME,
        manifest_paths=[root / scc.E3_MANIFEST, root / scc.E10_MANIFEST],
    )
    identity["predeclaration_verified_digest"] = signed["digest"]
    identity["package_dir"] = run_dir.name
    identity["preregistered_campaign_identity"] = scc.CAMPAIGN_B
    identity["cell_id_namespace"] = scc.CAMPAIGN_B
    identity["cell_id_namespace_note"] = (
        "cell_id carries the pre-registered campaign identity from the signed "
        "spec; the package directory is the run id and may differ on a repaired "
        "rerun without reopening any signed artefact"
    )
    if not identity["frozen_measurement_files"]["all_byte_identical_to_head"]:
        raise SelectionCostError(
            "refusing to run: a frozen measurement-path file is modified: "
            + str(identity["frozen_measurement_files"]["modified"])
        )

    receipts: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    status = "complete"

    if "E3" in args.family:
        try:
            new_receipts, new_failures = _run_b_e3(root, args, identity, run_dir)
            receipts.extend(new_receipts)
            failures.extend(new_failures)
        except scc.SystematicStop as exc:
            # Evidence is already on disk (see _persist_*); the payload is here
            # so the summary can count what actually happened rather than
            # reporting only the stop reason.  R3 F8, third occurrence.
            status = "incomplete_stopped"
            receipts.extend(exc.receipts)
            failures.extend(exc.failures)
            failures.append(
                scc.failure_record(
                    "E3_FAMILY", phase="e3_family", exc=exc, failure_class="systematic",
                    partial={
                        "cells_measured_before_stop": len(exc.receipts),
                        "cells_failed_before_stop": len(exc.failures),
                        "per_cell_failure_ids": [f["short_id"] for f in exc.failures],
                    },
                )
            )
            _persist_failure(run_dir, failures[-1])
        except SelectionCostError as exc:
            status = "incomplete_stopped"
            failures.append(
                scc.failure_record(
                    "E3_FAMILY", phase="e3_family", exc=exc, failure_class="systematic"
                )
            )
            _persist_failure(run_dir, failures[-1])
    if "E10" in args.family and status == "complete":
        try:
            new_receipts = _run_b_e10(root, args, identity)
            receipts.extend(new_receipts)
            for receipt in new_receipts:
                _persist_receipt(run_dir, receipt)
        except SelectionCostError as exc:
            status = "incomplete_stopped"
            failures.append(
                scc.failure_record(
                    "E10_FAMILY", phase="e10_family", exc=exc, failure_class="systematic"
                )
            )
            _persist_failure(run_dir, failures[-1])

    denominators = {"B_cells": 44, "B_e3_cells": 33, "B_e10_cells": 11}
    summary = analyze.build_summary(
        receipts=receipts,
        failures=failures,
        identity=identity,
        denominators=denominators,
        status=status,
    )
    outputs = analyze.write_outputs(
        run_dir, receipts=receipts, failures=failures, summary=summary
    )
    _copy_inputs(root, run_dir)
    sealed = scc.seal_package(
        run_dir,
        summary=summary,
        summary_rows=outputs["summary_rows"],
        summary_columns=outputs["summary_columns"],
        status=status,
    )
    print(json.dumps({"status": status, "sealed": sealed}, indent=2, default=str))
    return 0 if status == "complete" else 1


def _persist_receipt(run_dir: Path, receipt: Mapping[str, Any]) -> None:
    """Write one receipt the moment it exists, before anything can discard it."""

    scc.write_json(run_dir / "receipts" / f"{receipt['short_id']}.json", receipt)


def _persist_failure(run_dir: Path, failure: Mapping[str, Any]) -> None:
    """Write one failure the moment it happens, before the stop rule decides."""

    scc.write_json(run_dir / "failures" / f"{failure['short_id']}.json", failure)


def _run_b_e3(
    root: Path,
    args: argparse.Namespace,
    identity: Mapping[str, Any],
    run_dir: Path,
):
    from caprls_core import e3_main as e3

    manifest_path = root / scc.E3_MANIFEST
    family = e3arm.load_family(root, manifest_path)
    manifest = family["manifest"]
    queries = family["queries"]
    policies = family["policies"]
    if args.cells:
        wanted = set(args.cells)
        pairs = [
            (q, p)
            for q in queries
            for p in policies
            if e3arm.short_id(q.query_id, p.config_id) in wanted
        ]
    else:
        pairs = [(q, p) for q in queries for p in policies]

    pg_env = _pg_env(args, _database_for(args, "E3"))
    ranker = e3._ranker_from_manifest(root, manifest)
    registry = e3._e3_registry_from_manifest(manifest)

    receipts: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    rule = scc.StopRule(family_cell_count=len(pairs))
    for query, policy in pairs:
        sid = e3arm.short_id(query.query_id, policy.config_id)
        try:
            receipt = e3arm.run_cell(
                root=root,
                pg_env=pg_env,
                manifest=manifest,
                query=query,
                policy=policy,
                ranker=ranker,
                registry=registry,
                identity=identity,
            )
            # Persist FIRST, then account.  The stop rule only decides whether
            # to continue; it can never unwrite what already happened.
            _persist_receipt(run_dir, receipt)
            receipts.append(receipt)
            rule.record_success()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:  # noqa: BLE001 - record and continue
            failure = scc.failure_record(sid, phase="e3_cell", exc=exc)
            failure["traceback"] = traceback.format_exc(limit=12)
            _persist_failure(run_dir, failure)
            failures.append(failure)
            rule.record_failure()
            reason = rule.should_stop()
            if reason:
                raise scc.SystematicStop(
                    f"E3 systematic failure: {reason}",
                    receipts=receipts,
                    failures=failures,
                ) from exc
    return receipts, failures


def _run_b_e10(root: Path, args: argparse.Namespace, identity: Mapping[str, Any]):
    pg_env = _pg_env(args, _database_for(args, "E10"))
    result = e10arm.run_family(
        root=root,
        pg_env=pg_env,
        manifest_path=root / scc.E10_MANIFEST,
        identity=identity,
        case_ids=args.cases or None,
    )
    if result.get("case_filter_is_reporting_only"):
        for receipt in result["receipts"]:
            receipt["protocol"]["case_filter_is_reporting_only"] = True
            receipt["protocol"]["driver_case_count"] = result["driver_case_count"]
            receipt["protocol"]["case_filter_note"] = result["case_filter_note"]
    return result["receipts"]


# ---------------------------------------------------------------------------
# run-c
# ---------------------------------------------------------------------------


def cmd_run_c(args: argparse.Namespace) -> int:
    from caprls_core import e3_main as e3

    root = _repo_root()
    run_dir = _campaign_dir(root, args, scc.CAMPAIGN_C)
    b_dir = (
        root / "results" / "raw" / args.b_package
        if getattr(args, "b_package", None)
        else root / "results" / "raw" / scc.CAMPAIGN_B
    )
    if scc.package_is_sealed(run_dir):
        raise SelectionCostError(f"{run_dir} is already sealed")

    # C7 - B must be sealed first, and C must name what it inherited.
    inherited = witness.require_sealed_b_package(root, b_dir)

    # C signs its OWN pre-registration in its own package directory, so its
    # identity binds the memo under which C actually runs.  Binding only B's
    # would leave a rerun bound to a pre-amendment memo digest.
    signed_c = predeclare.require_predeclaration(run_dir)

    pg_env = _pg_env(args, _database_for(args, "E3"))
    autovacuum_start = witness.show_autovacuum(pg_env)
    if autovacuum_start.lower() != "off":
        raise SelectionCostError(
            "C refusal: autovacuum must be 'off' for the whole run; observed "
            f"'{autovacuum_start}'"
        )

    classification = witness.load_classification(root)
    manifest_path = root / scc.E3_MANIFEST
    family = e3arm.load_family(root, manifest_path)
    manifest = family["manifest"]
    queries = {q.query_id: q for q in family["queries"]}
    policies = {p.config_id: p for p in family["policies"]}
    ranker = e3._ranker_from_manifest(root, manifest)
    registry = e3._e3_registry_from_manifest(manifest)

    identity = scc.identity_block(
        root,
        campaign=scc.CAMPAIGN_C,
        spec_path=root / scc.SPEC_PATH,
        predeclaration_path=run_dir / scc.PREDECLARATION_NAME,
        manifest_paths=[manifest_path],
    )
    identity["predeclaration_verified_digest"] = signed_c["digest"]
    identity["package_dir"] = run_dir.name
    identity["preregistered_campaign_identity"] = scc.CAMPAIGN_C
    identity["inherited_b_predeclaration_digest"] = inherited.get(
        "b_predeclaration_digest"
    )

    round_zero = {
        "round": 0,
        "purpose": "record the state C inherits, before any C perturbation",
        "inherited_from_campaign_b": inherited,
        "inherited_artifact_state": witness.artifact_state(pg_env),
        "autovacuum_at_start": autovacuum_start,
        "recorded_at": scc.utc_now(),
    }
    scc.write_json(run_dir / "rounds" / "round00_inherited_state.json", round_zero)

    canonical = classification["canonical_order"]
    by_cell: Dict[str, List[Dict[str, Any]]] = {sid: [] for sid in canonical}
    failures_by_cell: Dict[str, List[Dict[str, Any]]] = {sid: [] for sid in canonical}
    all_rounds: List[Dict[str, Any]] = []
    all_failures: List[Dict[str, Any]] = []
    status = "complete"
    rule = scc.StopRule(family_cell_count=len(canonical))

    for round_index in range(1, scc.C_ROUNDS + 1):
        order = witness.rotated_cells(canonical, round_index)
        for position, sid in enumerate(order, start=1):
            entry = classification["entries"].get(sid)
            query_id = _query_of(sid)
            query = queries.get(query_id)
            policy = policies.get(witness.POLICY_ID)
            if query is None or policy is None:
                record = {"round": round_index, "short_id": sid,
                          "failure_reason": f"unknown cell {sid}"}
                failures_by_cell.setdefault(sid, []).append(record)
                all_failures.append(record)
                continue
            try:
                observation = witness.run_round(
                    root=root,
                    pg_env=pg_env,
                    round_index=round_index,
                    short_id=sid,
                    position=position,
                    query=query,
                    policy=policy,
                    ranker=ranker,
                    registry=registry,
                    entry=entry,
                    identity=identity,
                )
                by_cell[sid].append(observation)
                all_rounds.append(observation)
                scc.write_json(
                    run_dir / "rounds" / f"{sid}_round{round_index:02d}.json",
                    observation,
                )
                rule.record_success()
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:  # noqa: BLE001 - record and continue
                record = scc.failure_record(
                    sid, phase=f"c_round_{round_index}", exc=exc
                )
                record["round"] = round_index
                record["failure_reason"] = f"{exc.__class__.__name__}: {exc}"
                failures_by_cell.setdefault(sid, []).append(record)
                all_failures.append(record)
                rule.record_failure()
                if rule.should_stop():
                    status = "incomplete_stopped"
                    break
        if status != "complete":
            break

    autovacuum_end = witness.show_autovacuum(pg_env)
    if autovacuum_end != autovacuum_start:
        status = "incomplete_stopped"

    receipts = [
        witness.build_cell_receipt(sid, by_cell[sid], failures_by_cell.get(sid, []))
        for sid in canonical
    ]
    for receipt in receipts:
        scc.write_json(run_dir / "receipts" / f"{receipt['short_id']}.json", receipt)
    for index, failure in enumerate(all_failures):
        scc.write_json(
            run_dir / "failures" / f"{failure.get('short_id', 'unknown')}_{index:03d}.json",
            failure,
        )

    summary = witness.build_summary(
        receipts=receipts,
        round_records=all_rounds,
        failures=all_failures,
        identity=identity,
        round_zero=round_zero,
        autovacuum={
            "at_start": autovacuum_start,
            "at_end": autovacuum_end,
            "unchanged": autovacuum_end == autovacuum_start,
            "verified_not_assumed": True,
        },
        classification=classification,
        status=status,
    )
    _copy_inputs(root, run_dir, include_classification=True)
    sealed = scc.seal_package(
        run_dir,
        summary=summary,
        summary_rows=witness.summary_rows(receipts),
        summary_columns=witness.SUMMARY_COLUMNS_C,
        status=status,
    )
    print(json.dumps({"status": status, "sealed": sealed}, indent=2, default=str))
    return 0 if status == "complete" else 1


def _query_of(short_id: str) -> str:
    # ``E3_<query_id>_group_acl_expensive``
    body = short_id[len("E3_") :]
    return body[: -len("_group_acl_expensive")]


def _copy_inputs(root: Path, run_dir: Path, *, include_classification: bool = False) -> None:
    import shutil

    spec = root / scc.SPEC_PATH
    if spec.exists():
        shutil.copyfile(spec, run_dir / "selection_cost_cells.yaml")
    predeclaration = run_dir / scc.PREDECLARATION_NAME
    if not predeclaration.exists():
        predeclaration = root / "results" / "raw" / scc.CAMPAIGN_B / scc.PREDECLARATION_NAME
    if predeclaration.exists() and predeclaration.parent != run_dir:
        shutil.copyfile(
            predeclaration, run_dir / "predeclared_selection_cost.copy.yaml"
        )
    if include_classification:
        classification = root / scc.CLASSIFICATION_SPEC
        if classification.exists():
            shutil.copyfile(
                classification,
                run_dir / "selection_difference_classification.copy.yaml",
            )


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------


def cmd_analyze(args: argparse.Namespace) -> int:
    root = _repo_root()
    run_dir = Path(args.run_dir) if args.run_dir else root / "results" / "raw" / scc.CAMPAIGN_B
    receipts = analyze.load_receipts(run_dir)
    summary = analyze.build_summary(
        receipts=receipts,
        failures=[],
        identity={"campaign": scc.CAMPAIGN_B, "re_derived": True},
        denominators={"B_cells": 44, "B_e3_cells": 33, "B_e10_cells": 11},
        status="re_derived",
    )
    print(json.dumps(summary, indent=2, default=str))
    return 0


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def _add_pg_args(parser: argparse.ArgumentParser, *, suppress: bool) -> None:
    """Connection flags.

    Added to the top-level parser AND to every subcommand.  In the first run the
    flags existed only at the top level, so the documented
    ``... selection_cost_cli provision --family E3 E10`` silently fell back to
    ``127.0.0.1:5432`` - a server with ``autovacuum = on``, the regime under
    which campaign C refuses to start.  On the subcommands the defaults are
    ``SUPPRESS`` so a value given before the subcommand is not overwritten by a
    subparser default.
    """

    kwargs = {"default": argparse.SUPPRESS} if suppress else {}
    parser.add_argument("--pg-host", **({"default": "127.0.0.1"} if not suppress else kwargs))
    parser.add_argument("--pg-port", type=int, **({"default": 5432} if not suppress else kwargs))
    parser.add_argument("--pg-user", **({"default": "postgres"} if not suppress else kwargs))
    parser.add_argument(
        "--pg-database-prefix",
        **({"default": DEFAULT_DB_PREFIX} if not suppress else kwargs),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m caprls_core.selection_cost_cli",
        description="R4A selection-cost and stability-witness campaigns",
        epilog=(
            "Connection flags may be given before OR after the subcommand. "
            "Point them at the dedicated cluster; the defaults "
            "(127.0.0.1:5432) are NOT the campaign cluster."
        ),
    )
    _add_pg_args(parser, suppress=False)
    sub = parser.add_subparsers(dest="command", required=True)

    pre = sub.add_parser("predeclare", help="write the signed pre-registration")
    pre.add_argument("--overwrite", action="store_true")
    pre.set_defaults(func=cmd_predeclare)

    offline = sub.add_parser("offline-checks", help="run every database-free check")
    offline.set_defaults(func=cmd_offline_checks)

    provision = sub.add_parser("provision", help="build the campaign databases")
    provision.add_argument("--family", nargs="+", default=["E3", "E10"])
    provision.add_argument(
        "--allow-autovacuum-on",
        action="store_true",
        help=(
            "proceed even if the target cluster has autovacuum on; campaign C "
            "will still refuse, so this is for diagnostics only"
        ),
    )
    provision.set_defaults(func=cmd_provision)

    run_b = sub.add_parser("run-b", help="run SELECTION_COST_V1 and seal")
    run_b.add_argument("--family", nargs="+", default=["E3", "E10"])
    run_b.add_argument("--cells", nargs="*", default=None, help="E3 short ids")
    run_b.add_argument(
        "--cases",
        nargs="*",
        default=None,
        help=(
            "E10 query ids to REPORT; the frozen driver always runs all 11 "
            "cases, so this saves no machine time"
        ),
    )
    run_b.set_defaults(func=cmd_run_b)

    run_c = sub.add_parser("run-c", help="run STABILITY_WITNESS_V1 and seal")
    run_c.set_defaults(func=cmd_run_c)

    an = sub.add_parser("analyze", help="re-derive summary artifacts")
    an.add_argument("--run-dir", default=None)
    an.set_defaults(func=cmd_analyze)

    for subparser in (pre, run_b, run_c):
        subparser.add_argument(
            "--campaign-dir",
            default=None,
            help=(
                "package directory under results/raw/ (default: the campaign "
                "constant). The signed spec's cell_id namespace does not move "
                "with it, so a repaired rerun needs no re-signed spec."
            ),
        )
    run_c.add_argument(
        "--b-package",
        default=None,
        help="directory name of the sealed B package C must inherit from (C7)",
    )
    for subparser in (pre, offline, provision, run_b, run_c, an):
        _add_pg_args(subparser, suppress=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except SelectionCostError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
