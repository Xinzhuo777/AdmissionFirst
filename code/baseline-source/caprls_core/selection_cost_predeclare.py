"""Write-once pre-registration for the R4A selection-cost campaigns.

Role, unchanged from R3 (``content_predeclare.py:8-17``): **tamper evidence,
not acceptance.**  Nothing in this file is a pass criterion.  A deviation
between a recorded expectation and an observation sets
``predeclaration.expectation_deviation`` and is *reported, never repaired*.

Condition **C9** (load-bearing): the scoping predictions P1-P6 live in the
design memo, **not** here - but this file carries a pointer plus the digest of
the memo as signed, so "recorded before the run" stays a cryptographic property
rather than an editorial one.  Without the digest, moving P5 out of the signed
file would convert "fixed before the numbers existed" into "asserted after".
"""

from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

import yaml

from caprls_core import selection_cost_common as scc
from caprls_core.selection_cost_common import SelectionCostError

PREDECLARATION_SCHEMA = "caprls-selection-cost-predeclaration-v1"


def build_document(root: Path, *, spec_path: Path) -> Dict[str, Any]:
    memo_path = root / scc.DESIGN_MEMO
    if not memo_path.exists():
        raise SelectionCostError(f"design memo missing: {scc.DESIGN_MEMO}")

    doc: Dict[str, Any] = OrderedDict()
    doc["schema"] = PREDECLARATION_SCHEMA
    doc["written_at"] = scc.utc_now()
    doc["role"] = "tamper_anchor"
    doc["never"] = "acceptance_criterion"
    doc["pass_criteria_are_elsewhere"] = True
    doc["campaigns"] = {
        "B": scc.CAMPAIGN_B,
        "C": scc.CAMPAIGN_C,
    }
    doc["design_memo"] = scc.DESIGN_MEMO
    doc["design_memo_digest"] = scc.sha256_file(memo_path)
    doc["spec_path"] = _relative(spec_path, root)
    doc["spec_digest"] = scc.sha256_file(spec_path)
    doc["gate"] = {
        "decision": (
            "reference/"
            "gate_decision_r4a.md"
        ),
        "audit_section": "classification-metadata 'R4A Measurement Gate'",
        "conditions": ["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9"],
    }

    # --- C9 --------------------------------------------------------------
    doc["scoping_predictions_ref"] = "selection_cost_protocol.md#11"
    doc["scoping_predictions_digest"] = scc.sha256_file(memo_path)
    doc["scoping_predictions_note"] = (
        "P1-P6 are recorded in the design memo, not in this signed file, so "
        "they cannot be read as predeclared targets (ID-09). The digest above "
        "binds the memo as signed, so the fixed-before-the-numbers property "
        "remains cryptographic."
    )

    doc["anchors"] = {
        "e3_selection_wall": {
            "kind": "external_bracket",
            "call": "caprls_core/e3_main.py:6007 _plan_e3_admission_first",
            "precedent": "caprls_core/e3_sigmod_preview.py:466,482",
            "wrapped": False,
            "excludes": [
                "caprls_core/e3_main.py _build_artifact (provisioning)",
                "caprls_core/e3_main.py _configure_native_rls (baseline DDL)",
                "_collect_e3_planning_catalog_receipt (selection_inputs_ms)",
                "row-count probes (selection_inputs_ms)",
            ],
        },
        "e3_selection_inputs": {
            "kind": "external_bracket",
            "calls": [
                "_protected_count",
                "query_local_rows count",
                "_collect_e3_planning_catalog_receipt",
                "authorized_rows count",
            ],
        },
        "e10_selection_wall": {
            "kind": "pass_through_wrapper_pair",
            "start": "caprls_core/e10_study.py _e10_planning_expectation (entry)",
            "stop": "caprls_core/e10_study.py _planner_invocation_for_case (return)",
            "caller_assertion": "_prepare_e10_case_postgres_measurements",
            "precedent": "caprls_core/content_verify.py:852-899",
            "excluded_tail_method": (
                "measured from the frozen source at run time by content match "
                "(C2); line numbers are never transcribed"
            ),
        },
    }
    # Gate ruling (a): name the runtime rebinding explicitly.
    doc["runtime_rebound_frozen_functions"] = {
        "restore_guarantee": scc.REBIND_RESTORE_GUARANTEE,
        "externally_bracketed_never_wrapped": (
            "caprls_core.e3_main._plan_e3_admission_first"
        ),
        "functions": [dict(entry) for entry in scc.REBOUND_FUNCTIONS],
    }

    doc["repetitions"] = {
        "e3_selection": {
            "warmup": scc.E3_SELECTION_WARMUP,
            "measured": scc.E3_SELECTION_MEASURED,
            "semantics": "same_artifact_state",
        },
        "e10_selection": {
            "warmup": scc.E10_SELECTION_WARMUP,
            "measured": scc.E10_SELECTION_MEASURED,
            "semantics": "per_repetition_artifact_rebuild",
        },
        "query_latency": {
            "warmup": scc.LATENCY_WARMUP,
            "measured": scc.LATENCY_MEASURED,
        },
        "c_rounds": scc.C_ROUNDS,
    }

    doc["formulas"] = {
        "latency_total_ms": "planning_ms + execution_ms + validation_ms",
        "break_even_k": (
            "ceil(selection_wall_ms / (Q_N - Q_CA)) if Q_N - Q_CA > 0 else null"
        ),
        "amortized_ca_k": "Q_CA + selection_wall_ms / k",
        "ratio_k": "Q_N / amortized_ca_k",
        "k_grid": list(scc.K_GRID),
        "tie_band": {
            "lower": scc.TIE_LOWER_BOUND,
            "upper": scc.TIE_FACTOR,
            "source": "caprls_core/e3_scale_check.py:33",
        },
    }

    doc["pd_discriminant"] = {
        "conjunction": ["template_id", "sql_digest", "static_plan_hash"],
        "collapsed_action": "report_native_only_and_record",
        "independent_action": "measure_and_report_as_own_comparator",
        "precedent": "caprls_core/e3_scale_check.py:214-219",
    }

    doc["conditions_bound_here"] = {
        "C1": "assert and record adaptive_topk_enabled false per E3 receipt",
        "C2": "excluded-tail citation measured at run time, never transcribed",
        "C3": (
            "pooled 44-cell aggregate computed only on "
            + scc.POOLED_COMMENSURABLE_PAIRING
            + "; otherwise no pooled row"
        ),
        "C4": (
            "pooled figures always carry aggregation_scope and "
            "pooled_measurand_scope_mismatch"
        ),
        "C5": "identity block records reused latency-measurement function digests",
        "C6": "break_even_k never emitted without within_tie_band",
        "C7": (
            "B is sealed before C round 1; C round 0 records the inherited "
            "artifact-state fingerprint and B's campaign identity"
        ),
        "C8": (
            "C distributions always printed as n/10 with failed rounds "
            "enumerated by index and cause"
        ),
        "C9": "this file carries scoping_predictions_ref + memo digest",
    }

    doc["failure_policy"] = {
        "single_cell": "record a failure receipt and continue",
        "stop_on": [
            "any identity/provenance/GUC/fingerprint refusal",
            "any anchor refusal (start/stop count or caller mismatch)",
            "three consecutive cell failures",
            "more than 20 percent of a family's cells failed",
            "KeyboardInterrupt or SystemExit (re-raised, never swallowed)",
        ],
        "on_stop": "seal and report; no retry, no partial re-issue; next attempt is V2",
    }

    doc["c_forbidden"] = [
        "no VACUUM in any form (plain, FULL, FREEZE, ANALYZE-variant)",
        "no re-enabling autovacuum; regime verified at start and end",
        "no ANALYZE beyond the two inside _build_artifact_sql",
        "no statistics pinning (SET STATISTICS, pg_class/pg_statistic writes)",
        "no GUC change between rounds",
        "no index creation or drop",
        "no re-running, discarding or extending rounds",
        "no protocol change after observing any round's result",
    ]
    doc["c_banned_vocabulary"] = [
        "probability",
        "chance",
        "percent of the time",
        "expected rate",
        "flaky",
        "converges",
        "in practice",
        "any confidence interval",
        "any extrapolation beyond the ten observed rounds",
        "any is-or-is-not-a-defect statement",
    ]

    doc["relationship_to_frozen_evidence"] = {
        "declaration": "selection_cost_protocol.md#7.1",
        "prohibited": [
            "any ratio/delta/speedup between a campaign number and a frozen number",
            "using a campaign Q_CA/Q_N to update or re-derive a frozen aggregate",
            "amortizing a frozen headline by a campaign selection_wall_ms",
            "extrapolating E2's prospective_selection_wall_ms to E3 or E10",
            "describing C's frequency counts as probabilities",
        ],
    }
    return doc


def write_predeclaration(
    root: Path,
    *,
    run_dir: Path,
    spec_path: Path,
    overwrite: bool = False,
) -> Dict[str, Any]:
    """Write the pre-registration once and return its path and digest."""

    run_dir.mkdir(parents=True, exist_ok=True)
    target = run_dir / scc.PREDECLARATION_NAME
    if target.exists() and not overwrite:
        raise SelectionCostError(
            f"pre-registration already exists and is write-once: {target}"
        )
    document = build_document(root, spec_path=spec_path)
    target.write_text(
        yaml.safe_dump(_plain(document), sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return {
        "path": _relative(target, root),
        "digest": scc.sha256_file(target),
        "design_memo_digest": document["design_memo_digest"],
        "spec_digest": document["spec_digest"],
        "written_at": document["written_at"],
    }


def require_predeclaration(run_dir: Path) -> Dict[str, Any]:
    """Refuse to start a run without a signed pre-registration."""

    target = run_dir / scc.PREDECLARATION_NAME
    if not target.exists():
        raise SelectionCostError(
            "refusing to run: no signed pre-registration at " f"{target}"
        )
    document = yaml.safe_load(target.read_text(encoding="utf-8"))
    if document.get("schema") != PREDECLARATION_SCHEMA:
        raise SelectionCostError("pre-registration schema mismatch")
    for key in ("scoping_predictions_ref", "scoping_predictions_digest"):
        if not document.get(key):
            raise SelectionCostError(f"C9 violation: pre-registration lacks {key}")
    return {
        "path": str(target),
        "digest": scc.sha256_file(target),
        "document": document,
    }


def _relative(path: Path, root: Path) -> str:
    """Repo-relative when possible; absolute otherwise (tests use tmp dirs)."""

    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _plain(value: Any) -> Any:
    if isinstance(value, OrderedDict):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value
