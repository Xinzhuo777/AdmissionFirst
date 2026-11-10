"""Campaign B analysis: break-even, amortization, summary and CSV emission.

Claim-shaping conditions enforced here:

* **C3** - the pooled 44-cell aggregate is computed **only** on the
  commensurable pairing (E3 ``selection_wall_plus_inputs_ms`` vs E10
  ``selection_wall_ms``).  If any cell cannot supply it, no pooled row is
  produced at all.
* **C4** - ``aggregation_scope`` and ``pooled_measurand_scope_mismatch`` travel
  with every pooled figure; :func:`validate_summary` refuses otherwise.
* **C6** - a tie-band ``break_even_k`` never appears without
  ``within_tie_band`` beside it, in JSON or CSV.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from caprls_core import selection_cost_common as scc
from caprls_core.selection_cost_common import SelectionCostError

SUMMARY_COLUMNS = (
    "short_id",
    "cell_id",
    "family",
    "query_id",
    "policy_id",
    "status",
    "selected_template_id",
    "selection_wall_ms_median",
    "selection_inputs_ms",
    "selection_wall_plus_inputs_ms",
    "candidate_explain_count",
    "candidate_explain_wall_ms_median",
    "selection_repeat_semantics",
    "pd_identity",
    "Q_CA_ms",
    "Q_N_ms",
    "delta_ms",
    "ratio_native_over_ca",
    "tie_class",
    "break_even_k",
    "within_tie_band",
    "break_even_class",
    "break_even_k_inputs_included",
    "within_tie_band_inputs_included",
    "k_star_grid",
)

AMORTIZATION_COLUMNS = (
    "short_id",
    "family",
    "k",
    "Q_CA_ms",
    "selection_wall_ms_median",
    "amortized_ca_ms",
    "Q_N_ms",
    "ratio_k",
    "outcome_k",
)


def _cell_row(receipt: Mapping[str, Any]) -> Dict[str, Any]:
    selection = receipt.get("selection", {})
    derived = receipt.get("derived", {})
    primary = derived.get("primary") or {}
    sensitivity = derived.get("sensitivity_inputs_included") or {}
    scc.assert_break_even_paired(primary)
    if sensitivity:
        scc.assert_break_even_paired(sensitivity)
    return {
        "short_id": receipt["short_id"],
        "cell_id": receipt["cell_id"],
        "family": receipt["family"],
        "query_id": receipt.get("query_id"),
        "policy_id": receipt.get("policy_id"),
        "status": receipt.get("status"),
        "selected_template_id": selection.get("selected_template_id"),
        "selection_wall_ms_median": selection.get("selection_wall_ms_median"),
        "selection_inputs_ms": selection.get("selection_inputs_ms"),
        "selection_wall_plus_inputs_ms": selection.get(
            "selection_wall_plus_inputs_ms"
        ),
        "candidate_explain_count": selection.get("candidate_explain_count"),
        "candidate_explain_wall_ms_median": selection.get(
            "candidate_explain_wall_ms_median"
        ),
        "selection_repeat_semantics": selection.get("selection_repeat_semantics"),
        "pd_identity": (receipt.get("pd_discriminant") or {}).get("pd_identity"),
        "Q_CA_ms": derived.get("Q_CA_ms"),
        "Q_N_ms": derived.get("Q_N_ms"),
        "delta_ms": primary.get("delta_ms"),
        "ratio_native_over_ca": primary.get("ratio_native_over_ca"),
        "tie_class": primary.get("tie_class"),
        "break_even_k": primary.get("break_even_k"),
        # C6 - emitted in the adjacent column, always, never optional.
        "within_tie_band": primary.get("within_tie_band"),
        "break_even_class": primary.get("break_even_class"),
        "break_even_k_inputs_included": sensitivity.get("break_even_k"),
        "within_tie_band_inputs_included": sensitivity.get("within_tie_band"),
        "k_star_grid": derived.get("k_star_grid"),
    }


def _amortization_rows(receipt: Mapping[str, Any]) -> List[Dict[str, Any]]:
    derived = receipt.get("derived", {})
    rows: List[Dict[str, Any]] = []
    for row in derived.get("amortization", []):
        rows.append(
            {
                "short_id": receipt["short_id"],
                "family": receipt["family"],
                "k": row["k"],
                "Q_CA_ms": derived.get("Q_CA_ms"),
                "selection_wall_ms_median": derived.get("selection_wall_ms"),
                "amortized_ca_ms": row["amortized_ca_ms"],
                "Q_N_ms": derived.get("Q_N_ms"),
                "ratio_k": row["ratio_k"],
                "outcome_k": row["outcome_k"],
            }
        )
    return rows


def build_summary(
    *,
    receipts: Sequence[Mapping[str, Any]],
    failures: Sequence[Mapping[str, Any]],
    identity: Mapping[str, Any],
    denominators: Mapping[str, int],
    status: str,
) -> Dict[str, Any]:
    measured = [r for r in receipts if r.get("status") == "pass"]
    e3_cells = [r for r in measured if r["family"] == "E3" and r["derived"].get("Q_CA_ms")]
    e10_cells = [
        r for r in measured if r["family"] == "E10" and r["derived"].get("Q_CA_ms")
    ]

    per_family: Dict[str, Any] = {"E3": [], "E10": []}
    for k in scc.K_GRID:
        per_family["E3"].append(scc.family_aggregate(e3_cells, k=k))
        per_family["E10"].append(scc.family_aggregate(e10_cells, k=k))

    # C3 - decided once, before any pooled arithmetic, on family representation
    # AND commensurability.  An E10-only partial run must not emit a row
    # labelled "pooled across two dissimilar families".
    pooled: List[Dict[str, Any]] = []
    pooled_omitted_reason: Optional[str] = scc.pooled_omission_reason(
        e3_cells, e10_cells
    )
    if pooled_omitted_reason is None:
        for k in scc.K_GRID:
            aggregate = scc.pooled_aggregate(e3_cells, e10_cells, k=k)
            if aggregate is None:  # defensive; the reason check already passed
                pooled = []
                pooled_omitted_reason = "C3: pooled aggregate refused at k=%s" % k
                break
            scc.assert_pooled_labels_present(aggregate)
            pooled.append(aggregate)
    if pooled_omitted_reason is not None and pooled:
        raise SelectionCostError("C3 violation: pooled rows emitted despite an omission reason")

    finite = [
        r for r in measured if (r["derived"].get("primary") or {}).get("break_even_k")
    ]
    infinite = [
        r
        for r in measured
        if (r["derived"].get("primary") or {}).get("break_even_class")
        == "no_finite_break_even"
    ]
    tie_band = [
        r for r in measured if (r["derived"].get("primary") or {}).get("within_tie_band")
    ]

    summary: Dict[str, Any] = {
        "schema": scc.SUMMARY_SCHEMA_B,
        "campaign": scc.CAMPAIGN_B,
        "status": status,
        "generated_at": scc.utc_now(),
        "identity": dict(identity),
        "denominators": dict(denominators),
        "counts": {
            "receipts": len(receipts),
            "measured_cells": len(measured),
            "failed_cells": len(failures),
            "finite_break_even_cells": len(finite),
            "no_finite_break_even_cells": len(infinite),
            "within_tie_band_cells": len(tie_band),
        },
        "no_finite_break_even_cell_ids": sorted(r["short_id"] for r in infinite),
        "within_tie_band_cell_ids": sorted(r["short_id"] for r in tie_band),
        "failed_cell_ids": sorted(f["short_id"] for f in failures),
        "selection_wall_ms": {
            "E3": scc.distribution(
                [
                    r["selection"]["selection_wall_ms_median"]
                    for r in e3_cells
                    if r["selection"].get("selection_wall_ms_median") is not None
                ]
            ),
            "E10": scc.distribution(
                [
                    r["selection"]["selection_wall_ms_median"]
                    for r in e10_cells
                    if r["selection"].get("selection_wall_ms_median") is not None
                ]
            ),
        },
        "pd_discriminant_outcomes": _pd_outcomes(measured),
        "aggregates": {
            "per_family": per_family,
            "pooled": pooled,
            "pooled_omitted_reason": pooled_omitted_reason,
            "reporting_order": (
                "per-family aggregates are reported first; the pooled row is a "
                "presentational object, not a measurement"
            ),
        },
        "declaration": DECLARATION,
        "amortization_k_grid": list(scc.K_GRID),
        "tie_band": {"lower": scc.TIE_LOWER_BOUND, "upper": scc.TIE_FACTOR},
    }
    validate_summary(summary)
    return summary


def _pd_outcomes(receipts: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    outcomes: Dict[str, int] = {}
    independent: List[str] = []
    for receipt in receipts:
        pd = receipt.get("pd_discriminant") or {}
        identity = str(pd.get("pd_identity"))
        outcomes[identity] = outcomes.get(identity, 0) + 1
        if identity == "independent":
            independent.append(receipt["short_id"])
    return {
        "counts": outcomes,
        "independent_cells": sorted(independent),
        "rule": "template_id AND sql_digest AND static_plan_hash",
    }


DECLARATION = (
    "SELECTION_COST_V1 is a new measurement taken on this machine, on freshly "
    "provisioned databases, in this dataset state, at the recorded git HEAD. "
    "Its Q_CA and Q_N medians are the denominators of its own break-even and "
    "amortization arithmetic and of nothing else. They do not restate, correct, "
    "adjust, supersede or replace any number in "
    "results/summarized/E3_SF1_RAWPG_V1/, "
    "results/summarized/SIGMOD_CURRENT_E10/, "
    "results/raw/P1_E3_TPCH_SF10_RAWPG_RLSFIX_ROTATE_V3/, "
    "results/raw/E3_CANONICAL_CORRECTNESS_V1/, results/raw/E2_PROTOCOL/ or any "
    "other frozen package, and they may not be substituted for a frozen number "
    "in any table, figure or sentence. Break-even and amortization hold inside "
    "this campaign only."
)


def validate_summary(summary: Mapping[str, Any]) -> None:
    """C4 + C6 guards, applied before anything is written."""

    aggregates = summary.get("aggregates", {})
    pooled = aggregates.get("pooled", [])
    for aggregate in pooled:
        scc.assert_pooled_labels_present(aggregate)
        # C3 - a pooled figure must be pooled over both declared families.
        counts = aggregate.get("pooled_family_cell_counts") or {}
        if not counts.get("E3") or not counts.get("E10"):
            raise SelectionCostError(
                "C3 violation: pooled figure published without both families "
                f"represented: {counts}"
            )
    if pooled and aggregates.get("pooled_omitted_reason"):
        raise SelectionCostError(
            "C3 violation: pooled rows present alongside an omission reason"
        )
    if not pooled and not aggregates.get("pooled_omitted_reason"):
        raise SelectionCostError(
            "C3 violation: pooled row omitted without a recorded reason"
        )
    for key in ("within_tie_band_cell_ids", "no_finite_break_even_cell_ids"):
        if key not in summary:
            raise SelectionCostError(f"summary missing required disclosure: {key}")


def write_outputs(
    run_dir: Path,
    *,
    receipts: Sequence[Mapping[str, Any]],
    failures: Sequence[Mapping[str, Any]],
    summary: Mapping[str, Any],
) -> Dict[str, Any]:
    for receipt in receipts:
        scc.write_json(run_dir / "receipts" / f"{receipt['short_id']}.json", receipt)
    for failure in failures:
        scc.write_json(run_dir / "failures" / f"{failure['short_id']}.json", failure)

    rows = [_cell_row(r) for r in receipts]
    amortization_rows: List[Dict[str, Any]] = []
    for receipt in receipts:
        amortization_rows.extend(_amortization_rows(receipt))
    scc.write_csv(run_dir / "amortization.csv", amortization_rows, AMORTIZATION_COLUMNS)
    return {"summary_rows": rows, "summary_columns": list(SUMMARY_COLUMNS)}


def load_receipts(run_dir: Path) -> List[Dict[str, Any]]:
    receipts = []
    directory = run_dir / "receipts"
    if not directory.exists():
        return receipts
    for path in sorted(directory.glob("*.json")):
        receipts.append(json.loads(path.read_text(encoding="utf-8")))
    return receipts
