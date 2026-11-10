"""Campaign C: bounded stability witness over the 11 E3 group_acl cells.

Ten pre-fixed rounds, each round rebuilding the artifact exactly as the frozen
path does (``e3_main._build_artifact`` -> DELETE + INSERT + ``ANALYZE
public.auth_idx`` / ``auth_idx_keyed``) and then re-running the selection under
the same external bracket campaign B uses.

What C is, and is not
---------------------
``auth_idx`` is a single shared table rewritten per cell in a cluster with
autovacuum off, so dead tuples are never reclaimed and the table bloats
monotonically within a run.  The ten rounds are therefore **ten successive
states of a bloating table, not ten i.i.d. draws**.  C reports a frequency
count under a declared, ordered perturbation schedule.  It never reports a
probability, a rate, a confidence interval, or any extrapolation - see
:data:`BANNED_VOCABULARY` and :func:`witness_sentence`.

Conditions bound here: **C7** (B sealed first; round 0 records the inherited
artifact-state fingerprint and B's identity) and **C8** (every distribution is
printed as ``n/10`` with failed rounds enumerated by index and cause).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import yaml

from caprls_core import selection_cost_common as scc
from caprls_core.selection_cost_common import SelectionCostError

ARTIFACT_RELATIONS = ("auth_idx", "auth_idx_keyed")
POLICY_ID = "group_acl_expensive"

BANNED_VOCABULARY = (
    "probability",
    "chance",
    "% of the time",
    "expected rate",
    "flaky",
    "converges",
    "in practice",
)

WITNESS_TEMPLATE = (
    "Under ten successive artifact rebuild-and-ANALYZE cycles on a cluster with "
    "autovacuum disabled, with no other change to data, code, query, policy or "
    "session settings, cell {cell} selected {selections} across {n}/10 rounds; "
    "the competing candidates' prospective costs spanned {cost_span} across "
    "those rounds while the non-artifact candidates were bit-stable."
)


def load_classification(root: Path) -> Dict[str, Any]:
    path = root / scc.CLASSIFICATION_SPEC
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    entries = {entry["short_id"]: entry for entry in document.get("entries", [])}
    return {
        "path": str(path.relative_to(root)),
        "digest": scc.sha256_file(path),
        "document": document,
        "entries": entries,
        "canonical_order": [entry["short_id"] for entry in document.get("entries", [])],
    }


def rotated_cells(canonical: Sequence[str], round_index: int) -> List[str]:
    """Deterministic rotation, derived only from the round index.

    Each cell's rebuild leaves bloat that the next cell's selection observes, so
    holding one order fixed would confound cell with position.  Same discipline
    as ``e3_main._rotated_e3_sequence:8379-8391``: no randomness, no outcome
    feedback.
    """

    ordered = list(canonical)
    if not ordered:
        return []
    offset = (round_index - 1) % len(ordered)
    return ordered[offset:] + ordered[:offset]


def show_autovacuum(pg_env: Any) -> str:
    from caprls_core.postgres_runner import run_psql_command

    return run_psql_command("SHOW autovacuum;", pg_env).strip()


def artifact_state(pg_env: Any) -> Dict[str, Any]:
    """Record the bloat trajectory the witness must disclose."""

    from caprls_core.postgres_runner import run_psql_command

    state: Dict[str, Any] = {}
    for relname in ARTIFACT_RELATIONS:
        raw = run_psql_command(
            "SELECT c.relpages || '|' || c.reltuples || '|' || "
            "coalesce(s.n_live_tup, -1) || '|' || coalesce(s.n_dead_tup, -1) "
            "|| '|' || pg_relation_size(c.oid) "
            "FROM pg_class c LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid "
            f"WHERE c.relname = '{relname}' AND c.relkind = 'r';",
            pg_env,
        ).strip()
        if not raw:
            state[relname] = None
            continue
        relpages, reltuples, live, dead, size = raw.split("|")
        state[relname] = {
            "relpages": int(float(relpages)),
            "reltuples": float(reltuples),
            "n_live_tup": int(live),
            "n_dead_tup": int(dead),
            "relation_size_bytes": int(size),
        }
    state["fingerprint"] = scc.sha256_canonical(
        {k: v for k, v in sorted(state.items()) if k != "fingerprint"}
    )
    return state


def content_state(
    entry: Optional[Mapping[str, Any]],
    observed_template_id: str,
) -> Dict[str, Any]:
    """Classify against the pre-signed table; the harness never self-classifies.

    An observed template outside the declared admissible set sets
    ``unknown_refuse`` - the binding rule of
    ``specs/selection_difference_classification.yaml``.
    """

    if entry is None:
        return {
            "content_state": "unknown_refuse",
            "reason": "cell is not in the pre-signed classification table",
        }
    frozen = entry.get("frozen_selected_template_id")
    admissible = list(entry.get("admissible_observed_templates", []))
    if observed_template_id == frozen:
        state = "same"
    elif observed_template_id in admissible:
        state = "differs"
    else:
        state = "unknown_refuse"
    return {
        "content_state": state,
        "frozen_selected_template_id": frozen,
        "admissible_observed_templates": admissible,
        "declared_selection_stability": entry.get("selection_stability"),
        "declared_cause": entry.get("cause") if state != "unknown_refuse" else None,
        "classification_is_pre_signed": True,
        "harness_self_classified": False,
    }


def require_sealed_b_package(root: Path, b_dir: Path) -> Dict[str, Any]:
    """C7: C may not start until B is sealed, and must name what it inherited."""

    if not scc.package_is_sealed(b_dir):
        raise SelectionCostError(
            "C7 refusal: campaign B must be sealed (IMMUTABLE + INTEGRITY.json) "
            f"before campaign C starts; not sealed at {b_dir}"
        )
    import json

    integrity = json.loads((b_dir / "INTEGRITY.json").read_text(encoding="utf-8"))
    summary = json.loads((b_dir / "summary.json").read_text(encoding="utf-8"))
    return {
        "b_package_path": str(b_dir.relative_to(root)),
        "b_campaign": summary.get("campaign"),
        "b_status": summary.get("status"),
        "b_package_merkle_root": integrity.get("package_merkle_root"),
        "b_generated_at": summary.get("generated_at"),
        "b_identity_git_head": (summary.get("identity") or {}).get("git"),
        "b_predeclaration_digest": (summary.get("identity") or {}).get(
            "predeclaration_digest"
        ),
    }


def run_round(
    *,
    root: Path,
    pg_env: Any,
    round_index: int,
    short_id: str,
    position: int,
    query: Any,
    policy: Any,
    ranker: Any,
    registry: Any,
    entry: Optional[Mapping[str, Any]],
    identity: Mapping[str, Any],
    access_root_materialized: bool = True,
) -> Dict[str, Any]:
    """One (round, cell) observation: rebuild, re-select, record."""

    from caprls_core import e3_main as e3
    from caprls_core.postgres_runner import run_psql_command
    from caprls_core.selection_cost_e3 import _E3CostVectorAndExplainWall

    protected_rows = e3._protected_count(query, pg_env)
    query_local_rows = int(
        run_psql_command(
            f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} "
            f"WHERE {e3._query_local_predicate(query)};",
            pg_env,
        )
    )
    predicate = e3._policy_predicate(query, policy)

    build_ms, artifact_rows, keyed_artifact_rows = e3._build_artifact(
        query, policy, predicate, pg_env
    )
    # Per-cell RLS policy setup, in the frozen path's own position.
    #
    # `caprls_e3_policy_<rel>` is a GLOBAL policy on the protected relation: one
    # policy per relation, rewritten per cell.  The frozen runner therefore
    # re-establishes it for every cell, between the artifact build and the
    # planning-catalog receipt (`e3_main.py:8453` -> `:8456` -> `:8457`), and so
    # does campaign B (`selection_cost_e3.run_cell`).  Campaign C did not, so it
    # inherited whatever the previous campaign's LAST cell had left behind: after
    # B's final cell (`JOB_16b/hybrid_selective_key`) the live policy carried the
    # `hybrid_selective_key` expression, while C's rotation opens on
    # `group_acl_expensive` cells whose planning-catalog receipt expects that
    # policy's expression.  Replay returned `rls_policy_expression_mismatch` on
    # every one of them.
    #
    # This is setup ordering, not a planner intervention.  It is NOT one of the
    # actions section 5.4 forbids: it neither stabilises a planner input nor
    # touches the artifact state C measures (`auth_idx` / `auth_idx_keyed` are
    # not read, written, vacuumed or re-ANALYZEd here) - see protocol section
    # 5.4.1.
    e3._configure_native_rls(query, policy, pg_env)
    receipt = e3._collect_e3_planning_catalog_receipt(query, policy, pg_env)
    authorized_rows = int(
        run_psql_command(
            f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} "
            f"WHERE {predicate};",
            pg_env,
        )
    )
    if artifact_rows:
        authorized_rows = artifact_rows

    capture = _E3CostVectorAndExplainWall(e3)
    with capture:
        capture.reset()
        started = time.perf_counter()
        _plan_result, query_plan, _problem = e3._plan_e3_admission_first(
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

    bound = query_plan.get("production_bound_runner")
    if not isinstance(bound, Mapping):
        raise SelectionCostError("C round selection lacks its bound runner")
    template_id = e3._require_e3_selected_root_template(query_plan)
    runner_sql = bound.get("runner_sql")

    return {
        "schema": scc.ROUND_SCHEMA_C,
        "round": round_index,
        "cell_position_in_round": position,
        "short_id": short_id,
        "query_id": query.query_id,
        "policy_id": policy.config_id,
        "status": "pass",
        "selected_template_id": template_id,
        "selected_plan_id": bound.get("plan_id"),
        "prospective_total_cost": query_plan.get("production_chosen_cost"),
        "candidate_cost_vector": summary["candidate_cost_vector"],
        "candidate_explain_count": summary["candidate_explain_count"],
        "selection_wall_ms": wall_ms,
        # The latency STATE IDENTIFIER: two rounds selecting different templates
        # denote different measured objects.  C does not re-measure latency.
        "latency_object_id": (
            scc.sha256_text(runner_sql) if isinstance(runner_sql, str) else None
        ),
        "selected_runner_sql_digest": bound.get("runner_sql_digest"),
        "content": content_state(entry, template_id),
        "artifact_state": artifact_state(pg_env),
        "artifact_build_ms": build_ms,
        "artifact_rows": artifact_rows,
        "keyed_artifact_rows": keyed_artifact_rows,
        "identity": dict(identity),
        "recorded_at": scc.utc_now(),
    }


def build_cell_receipt(
    short_id: str,
    rounds: Sequence[Mapping[str, Any]],
    failures: Sequence[Mapping[str, Any]],
    *,
    total_rounds: int = scc.C_ROUNDS,
) -> Dict[str, Any]:
    """C8: the denominator is always ``total_rounds``; failures are enumerated."""

    counts: Dict[str, int] = {}
    for record in rounds:
        template = record["selected_template_id"]
        counts[template] = counts.get(template, 0) + 1

    cost_by_template: Dict[str, List[float]] = {}
    for record in rounds:
        for candidate in record.get("candidate_cost_vector", []):
            cost_by_template.setdefault(candidate["template_id"], []).append(
                float(candidate["prospective_total_cost"])
            )

    failed = [
        {"round": f["round"], "cause": f.get("failure_reason") or f.get("exception_message")}
        for f in failures
    ]
    distribution = {
        template: f"{count}/{total_rounds}" for template, count in sorted(counts.items())
    }
    return {
        "schema": scc.RECEIPT_SCHEMA_C,
        "short_id": short_id,
        "rounds_denominator": total_rounds,
        "rounds_observed": len(rounds),
        "rounds_failed": len(failed),
        "failed_rounds": failed,
        "selection_frequency": {
            template: {"n": count, "of": total_rounds, "printed": f"{count}/{total_rounds}"}
            for template, count in sorted(counts.items())
        },
        "selection_frequency_printed": distribution,
        "distinct_selections": len(counts),
        "unique_selection_across_all_rounds": len(counts) == 1 and not failed,
        "candidate_cost_range": {
            template: {
                "min": min(values),
                "max": max(values),
                "observations": len(values),
                "bit_stable": len(set(values)) == 1,
            }
            for template, values in sorted(cost_by_template.items())
        },
        "artifact_state_trajectory": [
            {
                "round": record["round"],
                "position": record["cell_position_in_round"],
                "auth_idx": (record.get("artifact_state") or {}).get("auth_idx"),
                "auth_idx_keyed": (record.get("artifact_state") or {}).get(
                    "auth_idx_keyed"
                ),
            }
            for record in rounds
        ],
        "content_states": sorted(
            {record["content"]["content_state"] for record in rounds}
        ),
        "latency_object_ids": sorted(
            {record["latency_object_id"] for record in rounds if record.get("latency_object_id")}
        ),
        "witness_sentence": witness_sentence(short_id, counts, cost_by_template, total_rounds),
        "denominator_rule": (
            "C8: distributions are always printed as n/10; a denominator that "
            "shrinks on failure would be a soft repair channel"
        ),
    }


def witness_sentence(
    short_id: str,
    counts: Mapping[str, int],
    cost_by_template: Mapping[str, Sequence[float]],
    total_rounds: int,
) -> str:
    """The only permitted claim shape."""

    if not counts:
        return (
            f"Cell {short_id} produced no successful round out of {total_rounds}; "
            "no selection frequency is reported."
        )
    selections = "; ".join(
        f"{template} in {count}/{total_rounds} rounds"
        for template, count in sorted(counts.items(), key=lambda item: -item[1])
    )
    moving = {
        template: values
        for template, values in cost_by_template.items()
        if len(set(values)) > 1
    }
    if moving:
        span = "; ".join(
            f"{template} {min(values):.2f}-{max(values):.2f}"
            for template, values in sorted(moving.items())
        )
    else:
        span = "no candidate cost moved"
    sentence = WITNESS_TEMPLATE.format(
        cell=short_id,
        selections=selections,
        n=sum(counts.values()),
        cost_span=span,
    )
    assert_no_banned_vocabulary(sentence)
    return sentence


def assert_no_banned_vocabulary(text: str) -> None:
    lowered = text.lower()
    for banned in BANNED_VOCABULARY:
        if banned in lowered:
            raise SelectionCostError(
                f"C witness vocabulary violation: '{banned}' in rendered output"
            )


def build_summary(
    *,
    receipts: Sequence[Mapping[str, Any]],
    round_records: Sequence[Mapping[str, Any]],
    failures: Sequence[Mapping[str, Any]],
    identity: Mapping[str, Any],
    round_zero: Mapping[str, Any],
    autovacuum: Mapping[str, Any],
    classification: Mapping[str, Any],
    status: str,
) -> Dict[str, Any]:
    unique = [r for r in receipts if r["unique_selection_across_all_rounds"]]
    multiple = [r for r in receipts if r["distinct_selections"] > 1]
    return {
        "schema": scc.SUMMARY_SCHEMA_C,
        "campaign": scc.CAMPAIGN_C,
        "status": status,
        "generated_at": scc.utc_now(),
        "identity": dict(identity),
        # C7
        "round_zero": dict(round_zero),
        "autovacuum_regime": dict(autovacuum),
        "classification_spec": {
            "path": classification["path"],
            "digest": classification["digest"],
        },
        "denominators": {
            "cells": len(receipts),
            "rounds_per_cell": scc.C_ROUNDS,
            "round_records": len(round_records),
            "expected_round_records": len(receipts) * scc.C_ROUNDS,
        },
        "counts": {
            "cells_with_unique_selection": len(unique),
            "cells_with_two_or_more_distinct_selections": len(multiple),
            "failed_round_records": len(failures),
        },
        "cells_with_unique_selection": sorted(r["short_id"] for r in unique),
        "cells_with_multiple_selections": sorted(r["short_id"] for r in multiple),
        "confound_disclosure": (
            "auth_idx is a single shared table rewritten per cell on a cluster "
            "with autovacuum off, so the ten rounds are ten successive states "
            "of a monotonically bloating table, not ten independent draws. "
            "These are frequency counts under a declared ordered perturbation "
            "schedule; they are not probabilities and support no extrapolation "
            "beyond the ten observed rounds."
        ),
        "banned_vocabulary": list(BANNED_VOCABULARY),
        "witness_sentences": [r["witness_sentence"] for r in receipts],
        "relationship_to_frozen_evidence": (
            "STABILITY_WITNESS_V1 records selections observed on this machine "
            "under a declared perturbation schedule. It does not restate, "
            "correct or replace any frozen selection, and it makes no claim "
            "that any frozen selection was right or wrong."
        ),
    }


SUMMARY_COLUMNS_C = (
    "short_id",
    "rounds_denominator",
    "rounds_observed",
    "rounds_failed",
    "distinct_selections",
    "unique_selection_across_all_rounds",
    "selection_frequency_printed",
    "content_states",
    "witness_sentence",
)


def summary_rows(receipts: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    for receipt in receipts:
        rows.append(
            {
                "short_id": receipt["short_id"],
                "rounds_denominator": receipt["rounds_denominator"],
                "rounds_observed": receipt["rounds_observed"],
                "rounds_failed": receipt["rounds_failed"],
                "distinct_selections": receipt["distinct_selections"],
                "unique_selection_across_all_rounds": receipt[
                    "unique_selection_across_all_rounds"
                ],
                "selection_frequency_printed": "; ".join(
                    f"{template}={printed}"
                    for template, printed in receipt[
                        "selection_frequency_printed"
                    ].items()
                ),
                "content_states": "; ".join(receipt["content_states"]),
                "witness_sentence": receipt["witness_sentence"],
            }
        )
    return rows
