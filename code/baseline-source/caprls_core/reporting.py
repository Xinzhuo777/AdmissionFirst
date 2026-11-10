"""Summarization and lightweight figure artifacts for CAPRLS smoke results."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import textwrap
from collections import Counter, defaultdict
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

# BEGIN PHASE_B2A_E8COST_REPORTING_IMPORTS
from .e8_cost_evidence import (
    E8COST_ACCOUNTING_PROJECTION,
    E8COST_EVIDENCE_CLASSES,
    E8COST_GATE_REJECT,
    E8COST_RESULT_EXECUTION,
    classify_e8_cost_evidence,
)
# END PHASE_B2A_E8COST_REPORTING_IMPORTS
from .result_schema import normalize_run_identity, validate_raw_run_record
from .baselines import (
    ADMISSION_FIRST_MODE,
    ADMISSION_FIRST_NO_DOMINANCE_MODE,
    EvaluationRole,
    load_mode_registry,
    mode_execution_order_key,
    normalize_evaluation_role,
    normalize_mode_id,
)


ROOT = Path(__file__).resolve().parents[1]


@lru_cache(maxsize=1)
def _mode_registry() -> dict[str, Any]:
    return load_mode_registry(ROOT)


def _paper_label(mode: Any) -> str:
    value = str(mode or "")
    try:
        canonical = normalize_mode_id(value)
        return _mode_registry()[canonical].paper_label
    except (KeyError, ValueError):
        return value


def _mode_order(mode: Any) -> int:
    return mode_execution_order_key(str(mode or ""))


FIGURE_EXPERIMENTS = {
    "fig2_contract_matrix": ("E1", "E6"),
    "fig3_e2_phase_diagram": ("E2",),
    "fig4_e3_speedup": ("E3",),
    "fig5_e5_template_regret": ("E5",),
    "fig6_e4_local_greedy": ("E4",),
    "fig7_sigma_ablation": ("E6",),
    "fig8_e9_overhead": ("E9",),
    "fig9_template_oracle_audit": ("E2", "E3", "E10"),
    "tab3_ranker_audit": ("E3",),
    "tab2_e10_diversity": ("E10",),
}

PROTOCOL_SUMMARY_EXPERIMENTS = {
    "E2_PROTOCOL": "E2",
    "E3_MINIPLUS_REDUCED": "E3",
    "E3_MINIPLUS_RANKER": "E3",
    "E3_MINIPLUS_RANKER_V2": "E3",
    "E3_MINIPLUS_RAWPG_V1": "E3",
    "E3_MINIPLUS_NATIVE_PORTFOLIO": "E3",
    "E3_MINIPLUS_PORTFOLIO": "E3",
    "E3_MINIPLUS_ADAPTIVE_TOPK": "E3",
    "E3_MINIPLUS_PORTFOLIO_GATED": "E3",
    "E3_SF1": "E3",
    "E3_SF1_RAWPG_V1": "E3",
    "E3_SF10": "E3",
    "E3_TO_MAIN_ORACLE_SMOKE": "E3",
    "E3_SELECTED_SF10": "E3",
    "E3_OUTLIER_SF10": "E3",
    "E4_PROTOCOL": "E4",
    "E5_PROTOCOL": "E5",
    "E6B_PROTOCOL": "E6",
    "E8B_PROTOCOL": "E8",
    "E8_COST_1E6": "E8",
    "SIGMOD_CURRENT_E9": "E9",
    "SIGMOD_CURRENT_E10": "E10",
}

RESULTS_MANIFEST_INCLUDED_RAW_DIRS = (
    "E1",
    "E2",
    "E2_PROTOCOL",
    "E3",
    "E3_SF1_RAWPG_V1",
    "E4",
    "E4_PROTOCOL",
    "E5",
    "E5_PROTOCOL",
    "E6",
    "E6B_PROTOCOL",
    "E7",
    "E8",
    "E9",
    "SIGMOD_CURRENT_E9",
    "SIGMOD_CURRENT_E10",
    "E10_GUARD_UNSAFE_STATIC_WITNESS",
    "STATIC_VERIFIER_TEMPLATE_WITNESS",
)
RESULTS_MANIFEST_INCLUDED_SUMMARY_DIRS = (
    "CLAIM_SUPPORT",
    "E1",
    "E2",
    "E2_PROTOCOL",
    "E3",
    "E3_SF1_RAWPG_V1",
    "E4",
    "E4_PROTOCOL",
    "E5",
    "E5_PROTOCOL",
    "E6",
    "E6B_PROTOCOL",
    "E7",
    "E8",
    "E9",
    "SIGMOD_CURRENT_E9",
    "SIGMOD_CURRENT_E10",
)
RESULTS_MANIFEST_EXCLUDED_TOP_LEVEL_DIRS = ("E10",)

FIGURES_SMALL_REQUIRED_SUMMARY_INPUTS = (
    ("E1", "E1"),
    ("E2", "E2"),
    ("E2_PROTOCOL", "E2"),
    ("E3", "E3"),
    ("E3_SF1_RAWPG_V1", "E3"),
    ("E4", "E4"),
    ("E4_PROTOCOL", "E4"),
    ("E5", "E5"),
    ("E5_PROTOCOL", "E5"),
    ("E6", "E6"),
    ("E6B_PROTOCOL", "E6"),
    ("E7", "E7"),
    ("E8", "E8"),
    ("E9", "E9"),
    ("SIGMOD_CURRENT_E9", "E9"),
    ("SIGMOD_CURRENT_E10", "E10"),
)

FIGURE_SUMMARY_DIRECTORIES = {
    "fig3_e2_phase_diagram": ("E2_PROTOCOL",),
    "fig4_e3_speedup": ("E3_SF1_RAWPG_V1",),
    "fig5_e5_template_regret": ("E5_PROTOCOL",),
    "fig6_e4_local_greedy": ("E4_PROTOCOL",),
    "fig7_sigma_ablation": ("E6B_PROTOCOL",),
    "fig8_e9_overhead": ("SIGMOD_CURRENT_E9",),
    "fig9_template_oracle_audit": ("E2_PROTOCOL", "E3_SF1_RAWPG_V1", "SIGMOD_CURRENT_E10"),
    "tab3_ranker_audit": ("E3_SF1_RAWPG_V1",),
    "tab2_e10_diversity": ("SIGMOD_CURRENT_E10",),
}

FIGURE_SOURCE_FILES = {
    "fig3_e2_phase_diagram": "cell_stats.csv",
    "fig4_e3_speedup": "cell_stats.csv",
    "fig5_e5_template_regret": "cell_stats.csv",
    "fig6_e4_local_greedy": "cell_stats.csv",
    "fig7_sigma_ablation": "cell_stats.csv",
    "fig8_e9_overhead": "cell_stats.csv",
    "fig9_template_oracle_audit": "runs.csv",
    "tab3_ranker_audit": "ranker_audit_analysis.csv",
    "tab2_e10_diversity": "runs.csv",
}

FIG3_WITNESS_SOURCE = "fig3_e2_phase_witness_audit.csv"
FIG4_HONESTY_SOURCE = "fig4_e3_honesty_audit.csv"

FIG3_FAMILY_WITNESS_DIRECTIONS = {
    "auth-index": {
        "theory_witnesses": ("W1", "W4", "W5"),
        "witness_role": "expected-best-auth-artifact",
        "direction": (
            "Auth-index is the expected-best direction in W1, W4, and W5 when "
            "barrier, mandatory guard, or exact-injection-only fixed modes lose."
        ),
    },
    "hybrid": {
        "theory_witnesses": ("W1", "W4", "W5"),
        "witness_role": "expected-best-auth-artifact-plus-residual",
        "direction": (
            "Hybrid intersection keeps the auth-artifact direction while adding "
            "the exact residual side needed by mixed continuations."
        ),
    },
    "safe-injection": {
        "theory_witnesses": ("W2", "W3"),
        "witness_role": "expected-best-exact-filter",
        "direction": (
            "Exact predicate injection is the expected-best direction in W2 and "
            "W3 when fixed auth-index enumeration or single-use MAV materialization loses."
        ),
    },
    "auth-view": {
        "theory_witnesses": ("W2", "W3"),
        "witness_role": "expected-best-exact-filter-view",
        "direction": (
            "Authorization views are the exact-filter side of the same W2/W3 "
            "continuation direction; the companion audit keeps them separate from injection."
        ),
    },
    "mav": {
        "theory_witnesses": ("W3", "W5"),
        "witness_role": "fresh-materialized-artifact-region",
        "direction": (
            "MAV wins only in fresh materialized-artifact regions; E5's W3 bad "
            "single-use witness and MAV positive control separate the bad and good sides."
        ),
    },
}

FIG3_T5_WITNESS_COVERAGE = {
    "W1": {
        "fixed_mode_under_test": "barrier-only",
        "expected_best_direction": "auth-index-or-hybrid",
        "e5_witness_id": "barrier_bad_auth_singleton",
    },
    "W2": {
        "fixed_mode_under_test": "auth-index-enum-only",
        "expected_best_direction": "exact-filter",
        "e5_witness_id": "auth_enum_bad_point_query",
    },
    "W3": {
        "fixed_mode_under_test": "mav-only",
        "expected_best_direction": "exact-filter-or-fresh-mav-boundary",
        "e5_witness_id": "mav_bad_single_use_refresh",
    },
    "W4": {
        "fixed_mode_under_test": "guard-mandatory-discharge",
        "expected_best_direction": "auth-index-or-hybrid",
        "e5_witness_id": "guard_bad_unselective_residual",
    },
    "W5": {
        "fixed_mode_under_test": "injection-only",
        "expected_best_direction": "auth-index-hybrid-or-mav",
        "e5_witness_id": "injection_bad_expensive_singleton",
    },
}

FIG4_CDF_COMPARISONS = (
    "native-pg-rls-physical-design",
    "best-single-fixed-mode",
    "local-greedy",
)

FIGURES_SMALL = (
    "fig2_contract_matrix",
    "fig3_e2_phase_diagram",
    "fig4_e3_speedup",
    "fig5_e5_template_regret",
    "fig6_e4_local_greedy",
    "fig7_sigma_ablation",
    "fig8_e9_overhead",
    "fig9_template_oracle_audit",
    "tab3_ranker_audit",
    "tab2_e10_diversity",
)

E3_LOSS_TIE_TOLERANCE = 0.01
E3_POLICY_ENFORCEMENT_MODES = {
    "auth-index-enum-only",
    "barrier-only",
    ADMISSION_FIRST_MODE,
    "injection-only",
    "local-greedy",
    "native-pg-rls",
    "native-pg-rls-physical-design",
    "security-barrier",
    "strong-auth-index",
}

DATA_BOUNDARY_FILES = (
    {
        "role": "excluded_query_manifest",
        "boundary": "excluded_queries",
        "path": "workloads/e3/excluded_queries_mini_plus.yaml",
        "description": "Frozen E3-MINI+ included query set, adapter boundary, and excluded-query reasons.",
    },
    {
        "role": "reduced_adapter_manifest",
        "boundary": "deterministic_reduced_adapter",
        "path": "manifests/experiments/e3_standard_reduced.yaml",
        "description": "TPC-H/JOB reduced adapter used by the main AE-scale E3 package.",
    },
    {
        "role": "rawpg_sf1_manifest",
        "boundary": "zero_calibration_pg_explain_raw",
        "path": "manifests/experiments/e3_standard_sf1_rawpg.yaml",
        "description": "Prospective zero-calibration RawPG SF1/full rerun used by the main E3/X1 package.",
    },
    {
        "role": "real_scale_manifest",
        "boundary": "real_tpch_job_scale",
        "path": "manifests/experiments/e3_standard_sf10.yaml",
        "description": "Full TPC-H SF10 and JOB/full E3 manifest; not AE-required.",
    },
    {
        "role": "real_scale_oracle_manifest",
        "boundary": "real_tpch_job_scale",
        "path": "manifests/experiments/e3_selected_oracle_sf10.yaml",
        "description": "Predeclared selected SF10/JOB measured-oracle validation cases.",
    },
    {
        "role": "real_scale_oracle_manifest",
        "boundary": "real_tpch_job_scale",
        "path": "manifests/experiments/e3_outlier_oracle_sf10.yaml",
        "description": "Predeclared SF10/JOB outlier-validation measured-oracle cases.",
    },
    {
        "role": "synthetic_saas_manifest",
        "boundary": "synthetic_saas",
        "path": "manifests/experiments/e10_case_study.yaml",
        "description": "Synthetic SaaS diversity case-study manifest.",
    },
)

REQUIRED_WARMUP_REPETITIONS = 5
REQUIRED_MEASURED_REPETITIONS = 10

BASE_CELL_KEY_FIELDS = (
    "experiment",
    "stage",
    "run_kind",
    "dataset_name",
    "dataset_scale",
    "dataset_seed",
    "query_id",
    "policy_id",
    "context_id",
    "mode",
    "template_id",
    "evaluation_role",
)

STABLE_CELL_FIELDS = (
    "planner_choice_reason",
    "planner_level",
    "planner_local_feature_vector",
    "planner_parent_requirement_vector",
    "prospective_selection_timing_scope",
    "query_timing_scope",
    "result_hash",
    "static_plan_hash",
    "emitted_sql_hash",
    "runner_sql_hash",
    "e5_theory_witness",
    "e5_fixed_mode_under_test",
    "e5_expected_best_mode",
)

MULTI_VALUE_CELL_FIELDS = (
    "result_hash",
    "static_plan_hash",
    "emitted_sql_hash",
    "runner_sql_hash",
)

ADAPTIVE_TEMPLATE_CELL_MODES = {
    ADMISSION_FIRST_MODE,
    "template-oracle",
}

NUMERIC_STAT_FIELDS = (
    "planning_ms",
    "execution_ms",
    "verification_ms",
    "total_ms",
    "query_only_ms",
    "artifact_build_ms",
    "artifact_refresh_ms",
    "artifact_storage_bytes",
    "row_count",
    "policy_evals",
    "residual_checks",
    "candidate_rows",
    "authorized_rows",
    "artifact_lookups",
    "base_fetches",
    "generated_templates",
    "rejected_templates",
    "dominance_pruned",
    "costed_templates",
    "dominance_checks",
    "memo_groups",
    "peak_memory_bytes",
    "serialized_state_bytes",
    "pruning_ratio",
    "planning_total_ratio",
    "postgres_planning_ms",
    "prospective_selection_wall_ms",
    "prospective_explain_wall_ms",
    "prospective_selection_explain_count",
    "chosen_rank_vs_template_oracle",
    "chosen_estimated_cost",
    "chosen_pg_total_cost",
    "candidate_estimated_cost",
    "candidate_pg_total_cost",
    "candidate_heuristic_cost",
    "oracle_gap",
    "oracle_best_execution_ms",
    "oracle_chosen_execution_ms",
    "oracle_eligible_templates",
    "oracle_eligible_plan_shapes",
    "oracle_chosen_measured_rank",
    "oracle_measured_best_estimated_rank",
    "artifact_cost_q",
    "artifact_cost_u",
    "artifact_update_rate",
    "artifact_invalidated_rows",
    "artifact_table_pages",
    "artifact_index_pages",
    "artifact_validation_ms",
    "artifact_maintenance_ms_total",
    "artifact_fallback_ms",
    "artifact_amortized_query_only_ms",
    "artifact_amortized_build_plus_single_query_ms",
    "artifact_amortized_q100_u1pct_ms",
    "artifact_amortized_q1000_u0pct_ms",
    "artifact_amortized_declared_q_u_ms",
    "e5_effective_latency_ms",
    "e5_best_effective_latency_ms",
    "e5_regret_ratio",
)
# BEGIN PHASE_B2A_E8COST_ACCOUNTING_STAT_FIELDS
E8COST_ACCOUNTING_NUMERIC_STAT_FIELDS = (
    "projected_declared_q",
    "projected_declared_u",
    "projected_declared_ttl_s",
    "projected_declared_contexts",
    "projected_case_validation_elapsed_ms",
    "projected_alternative_count",
    "observed_accounting_minimum_amortized_latency_ms",
    "gate_accounting_q",
    "gate_accounting_u",
    "gate_accounting_query_only_ms",
    "gate_accounting_build_ms",
    "gate_accounting_refresh_ms",
    "gate_accounting_validation_ms",
    "gate_accounting_maintenance_ms_total",
    "gate_accounting_fallback_ms",
    "gate_accounting_storage_bytes",
)
# END PHASE_B2A_E8COST_ACCOUNTING_STAT_FIELDS

FIGURE_TITLES = {
    "fig2_contract_matrix": "Fig2 Contract Matrix",
    "fig3_e2_phase_diagram": "Fig3 E2 Phase Diagram",
    "fig4_e3_speedup": "Fig4 E3 Speedup",
    "fig5_e5_template_regret": "Fig5 E5 Template Regret",
    "fig6_e4_local_greedy": "Fig6 E4 Local Greedy",
    "fig7_sigma_ablation": "Fig7 Sigma Ablation",
    "fig8_e9_overhead": "Fig8 E9 Overhead",
    "fig9_template_oracle_audit": "Fig9 Template Oracle Audit",
    "tab3_ranker_audit": "Table3 Ranker Audit",
    "tab2_e10_diversity": "Table2 E10 Diversity",
}

CLAIM_SUPPORT_ROWS: tuple[dict[str, str], ...] = (
    {
        "claim_id": "admissibility_gates",
        "claim": "Contracts are admissibility gates, not decorations.",
        "formal_object": "Contract-soundness theorem; H0-H7 obligations.",
        "experimental_witness": "E1, E6, E7, and E8 gate suites.",
        "current_evidence": (
            "AdmissionFirst has no wrong-result or unsafe-observation status in reported "
            "policy-enforcement gate rows; contract-violation controls expose wrong results or unsafe "
            "observations when the corresponding gate is removed."
        ),
        "paper_anchor": "main.tex Table tab:claim-support; gate evidence figure.",
        "status": "supported_current_package",
    },
    {
        "claim_id": "sigma_components",
        "claim": "Each Sigma component is needed.",
        "formal_object": "Ordinary-state insufficiency proposition.",
        "experimental_witness": "E6 Sigma-ablation matrix and E1 sanity gates.",
        "current_evidence": (
            "Targeted ablations cover domain, residual, residual carrier, safety, "
            "freshness, context scope, RID/materialization, branch lineage, and "
            "ordinary physical properties."
        ),
        "paper_anchor": "main.tex Table tab:sigma-counterexamples; Fig. gate evidence.",
        "status": "supported_current_package",
    },
    {
        "claim_id": "fixed_representation_regret",
        "claim": "Fixed enforcement representations do not dominate.",
        "formal_object": "Fixed-representation lower-bound proposition.",
        "experimental_witness": "E2 phase diagram, E10 diversity, and E5 fixed-regret witnesses.",
        "current_evidence": (
            "E2 exercises five winning template families; E5 reports measured "
            "W1-W5 fixed-representation regret against BestEnumeratedAdmissible; "
            "the separate MAV case is a positive control. E10 has five non-MAV "
            "measured-best families "
            "across declared cases."
        ),
        "paper_anchor": "main.tex Table tab:claim-support; Fig. performance evidence; Table tab:e10-diversity.",
        "status": "supported_current_package",
    },
    {
        "claim_id": "parent_requirements",
        "claim": "Local enforcement choice needs parent requirements.",
        "formal_object": "Local-greedy regret proposition.",
        "experimental_witness": "E4 paired continuations.",
        "current_evidence": (
            "Identical local views differ under high-fanout, required-order, and "
            "key-predicate parents; AdmissionFirst carries the parent requirement "
            "that LocalGreedy omits. The E4 local-greedy validator checks the "
            "four-pair package, neutral ties, stress regret/reject evidence, "
            "local vectors, parent continuation IDs, and hash provenance."
        ),
        "paper_anchor": "main.tex Tables tab:claim-support and tab:e4-local-greedy-witness.",
        "status": "supported_current_package",
    },
    {
        "claim_id": "measured_oracle_tracking",
        "claim": "Cost ranking is useful but not perfect.",
        "formal_object": "Planner algorithm and admissible finite-template candidate set.",
        "experimental_witness": "E2, E3, and E10 measured BestEnumeratedAdmissible audit.",
        "current_evidence": (
            "Fig9 evidence is generated from the current measured-oracle source; "
            "case counts, gap summaries, ranks, near-best coverage, and diagnosed "
            "misses must not be hard-coded when that source is unavailable."
        ),
        "paper_anchor": "main.tex Fig. template-oracle-audit; Table tab:claim-support.",
        "status": "supported_current_package",
    },
    {
        "claim_id": "artifact_practicality",
        "claim": "Artifacts and contract state are practical.",
        "formal_object": "Freshness, context scope, RID/materialization, and planning overhead.",
        "experimental_witness": "E8 artifact gates and E9 overhead.",
        "current_evidence": (
            "E8A/E8B exercise freshness, context, RID, execute, fallback, "
            "refresh, reject, and replan gates. No E8-COST payoff or speedup "
            "claim is retained. E9 Fig8 and measured-row planning statistics "
            "are loaded from the current generated sources."
        ),
        "paper_anchor": "main.tex Table tab:claim-support; Fig. gate/performance evidence.",
        "status": "supported_current_package",
    },
)


def _format_claim_count(row: Mapping[str, str], field: str) -> str:
    parsed = _maybe_float(row.get(field, ""))
    if parsed is None:
        return str(row.get(field, ""))
    return str(int(parsed))


def _format_claim_gap(row: Mapping[str, str], field: str) -> str:
    parsed = _maybe_float(row.get(field, ""))
    return "nan" if parsed is None else f"{parsed:.3f}"


def _current_fig9_claim_evidence(output_dir: Path) -> str | None:
    fig9_source = (
        output_dir.parent.parent
        / "figures"
        / "fig9_template_oracle_audit"
        / "fig9_template_oracle_audit_source.csv"
    )
    if not fig9_source.exists():
        return None
    with fig9_source.open("r", encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    combined = next(
        (
            row
            for row in rows
            if row.get("row_type") == "summary" and row.get("experiment") == "combined"
        ),
        None,
    )
    if combined is None:
        return None
    cells = _format_claim_count(combined, "oracle_cell_count")
    worst_rows = [row for row in rows if row.get("row_type") == "worst_miss"]
    worst_phrase = (
        (
            "1 worst miss row is diagnosed in source rows"
            if len(worst_rows) == 1
            else f"{len(worst_rows)} worst miss rows are diagnosed in source rows"
        )
        if worst_rows
        else "no worst-miss rows are emitted because every case is measured-best"
    )
    bounded_phrase = ""
    if _maybe_float(combined.get("bounded_max_oracle_gap")) is not None:
        floor = _maybe_float(combined.get("measurement_resolution_floor_ms"))
        floor_text = f"{floor:g}" if floor is not None else "1"
        bounded_phrase = (
            f" {_format_claim_count(combined, 'below_resolution_cell_count')}/{cells} cases are "
            f"below the {floor_text}ms measurement floor; the "
            f"{_format_claim_count(combined, 'bounded_cell_count')} bounded cases have "
            f"median/p90/max gaps {_format_claim_gap(combined, 'bounded_median_oracle_gap')}/"
            f"{_format_claim_gap(combined, 'bounded_p90_oracle_gap')}/"
            f"{_format_claim_gap(combined, 'bounded_max_oracle_gap')}."
        )
    return (
        f"Fig9 reports {cells} cases with combined median/p90/max per-case gaps "
        f"{_format_claim_gap(combined, 'median_oracle_gap')}/"
        f"{_format_claim_gap(combined, 'p90_oracle_gap')}/"
        f"{_format_claim_gap(combined, 'max_oracle_gap')}, measured-best hits "
        f"{_format_claim_count(combined, 'top1_measured_best_count')}/{cells}, "
        f"top-2 rank {_format_claim_count(combined, 'top2_measured_rank_count')}/{cells}, "
        f"top-3 rank {_format_claim_count(combined, 'top3_measured_rank_count')}/{cells}, "
        f"and fixed near-best tolerances "
        f"{_format_claim_count(combined, 'near_best_3pct_count')}/{cells} within 3% "
        f"and {_format_claim_count(combined, 'near_best_5pct_count')}/{cells} within 5%; "
        f"{worst_phrase}.{bounded_phrase}"
    )


def _current_fig8_claim_evidence(output_dir: Path) -> str | None:
    fig8_source = (
        output_dir.parent.parent
        / "figures"
        / "fig8_e9_overhead"
        / "fig8_e9_overhead_source.csv"
    )
    runs_source = output_dir.parent / "SIGMOD_CURRENT_E9" / "runs.csv"
    if not fig8_source.exists() or not runs_source.exists():
        return None
    with fig8_source.open("r", encoding="utf-8", newline="") as fh:
        cells = [
            row
            for row in csv.DictReader(fh)
            if normalize_mode_id(str(row.get("mode") or "")) == ADMISSION_FIRST_MODE
        ]
    with runs_source.open("r", encoding="utf-8", newline="") as fh:
        observations = [
            row
            for row in csv.DictReader(fh)
            if normalize_mode_id(str(row.get("mode") or "")) == ADMISSION_FIRST_MODE
            and row.get("measurement_phase") == "measured"
        ]
    cell_planning = sorted(
        value
        for row in cells
        if (value := _maybe_float(row.get("planning_ms_median", ""))) is not None
    )
    cell_ratio = sorted(
        value
        for row in cells
        if (value := _maybe_float(row.get("planning_total_ratio", ""))) is not None
    )
    cell_memory = sorted(
        value
        for row in cells
        if (value := _maybe_float(row.get("peak_memory_bytes_median", ""))) is not None
    )
    measured_planning = sorted(
        value
        for row in observations
        if (value := _maybe_float(row.get("planning_ms", ""))) is not None
    )
    if not cell_planning or not cell_ratio or not cell_memory or not measured_planning:
        return None
    return (
        "E8A/E8B exercise freshness, context, RID, execute, fallback, refresh, "
        "reject, and replan gates. No E8-COST payoff or speedup claim is "
        "retained. E9 Fig8 reports "
        f"{_median(cell_planning):.3f}/{max(cell_planning):.3f} ms median/max "
        "across AdmissionFirst per-case planning medians, "
        f"{_median(cell_ratio):.3f}/{max(cell_ratio):.3f} median/max "
        "planning-to-total ratio, and "
        f"{max(cell_memory) / (1024 * 1024):.2f} MiB maximum median planner "
        "memory. Across measured AdmissionFirst rows, planning median/P90/max is "
        f"{_median(measured_planning):.3f}/"
        f"{_percentile(measured_planning, 0.9):.3f}/"
        f"{max(measured_planning):.3f} ms."
    )


def _claim_support_rows(output_dir: Path) -> list[dict[str, str]]:
    rows = [dict(row) for row in CLAIM_SUPPORT_ROWS]
    fig9_evidence = _current_fig9_claim_evidence(output_dir)
    if fig9_evidence is not None:
        for row in rows:
            if row.get("claim_id") == "measured_oracle_tracking":
                row["current_evidence"] = fig9_evidence
                break
    fig8_evidence = _current_fig8_claim_evidence(output_dir)
    if fig8_evidence is not None:
        for row in rows:
            if row.get("claim_id") == "artifact_practicality":
                row["current_evidence"] = fig8_evidence
                break
    return rows


@dataclass(frozen=True)
class SummaryResult:
    experiment: str
    record_count: int
    output_dir: Path
    runs_csv: Path
    cell_stats_csv: Path
    summary_json: Path
    manifest_hashes_txt: Path
    script_version_txt: Path
    template_oracle_csv: Path
    template_oracle_summary_json: Path
    artifact_cost_csv: Path
    artifact_cost_summary_json: Path
    ranker_audit_csv: Path
    ranker_audit_summary_json: Path


@dataclass(frozen=True)
class PlotResult:
    figure: str
    record_count: int
    output_dir: Path
    figure_file: Path
    source_csv: Path
    config_json: Path
    manifest_hashes_txt: Path
    script_version_txt: Path


@dataclass(frozen=True)
class FiguresSmallResult:
    summaries: list[SummaryResult]
    plots: list[PlotResult]


@dataclass(frozen=True)
class ClaimSupportResult:
    output_dir: Path
    source_csv: Path
    summary_json: Path
    script_version_txt: Path
    row_count: int


@dataclass(frozen=True)
class ResultsManifestResult:
    output_path: Path
    raw_file_count: int
    summary_file_count: int
    figure_file_count: int
    raw_record_count: int
    aggregate_digest: str


def _script_version_hash() -> str:
    return "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _as_scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, str)):
        return str(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _float(value: Any, default: float = 0.0) -> float:
    try:
        if value == "" or value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _int(value: Any, default: int = 0) -> int:
    try:
        if value == "" or value is None:
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _maybe_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None or value == "":
        return None
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
    return None


def _json_mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, Mapping) else {}


def _json_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if not value:
        return []
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def _row_status(row: Mapping[str, Any]) -> str:
    if row.get("status"):
        return str(row["status"])
    counts = _json_mapping(row.get("status_counts"))
    if len(counts) == 1:
        return next(iter(counts))
    if not counts:
        return ""
    return "mixed"


def _metric(row: Mapping[str, Any], field: str) -> float:
    median_key = f"{field}_median"
    return _float(row.get(median_key) if median_key in row else row.get(field))


def _metric_ci(row: Mapping[str, Any], field: str) -> tuple[float, float]:
    value = _metric(row, field)
    low_key = f"{field}_ci95_low"
    high_key = f"{field}_ci95_high"
    if low_key in row and high_key in row:
        return (_float(row.get(low_key), value), _float(row.get(high_key), value))
    return (value, value)


def _bar(label: str, value: float, ci95_low: float | None = None, ci95_high: float | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {"label": label, "value": value}
    if ci95_low is not None and ci95_high is not None:
        row["ci95_low"] = ci95_low
        row["ci95_high"] = ci95_high
    return row


def _bar_label(item: Any) -> str:
    if isinstance(item, Mapping):
        return str(item.get("label", ""))
    return str(item[0])


def _bar_value(item: Any) -> float:
    if isinstance(item, Mapping):
        return _float(item.get("value"))
    return _float(item[1])


def _bar_ci(item: Any) -> tuple[float, float]:
    value = _bar_value(item)
    if isinstance(item, Mapping):
        return (_float(item.get("ci95_low"), value), _float(item.get("ci95_high"), value))
    return (value, value)


def _get(record: Mapping[str, Any], path: str, default: Any = None) -> Any:
    current: Any = record
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return default
        current = current[part]
    return current


def _planner_candidate_for_template(
    record: Mapping[str, Any],
    template_id: str,
) -> Mapping[str, Any]:
    candidates = _get(record, "planner.candidates", [])
    if not isinstance(candidates, list):
        return {}
    for candidate in candidates:
        if (
            isinstance(candidate, Mapping)
            and str(candidate.get("template_id") or "") == template_id
        ):
            return candidate
    return {}


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key not in seen:
                fieldnames.append(key)
                seen.add(key)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _as_scalar(row.get(key)) for key in fieldnames})


def _canonical_taxonomy_key(key: str) -> str:
    for legacy, current in (
        ("contractaware", "admission_first"),
        ("best_production_safe", "fastest_policy_enforcement"),
        ("fastest_production_safe", "fastest_policy_enforcement"),
        ("production_safe_mode_count", "policy_enforcement_mode_count"),
    ):
        if legacy in key:
            return key.replace(legacy, current)
    return key


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        rows = [dict(row) for row in csv.DictReader(fh)]
    for row in rows:
        for key in list(row):
            canonical_key = _canonical_taxonomy_key(key)
            if canonical_key != key and canonical_key not in row:
                row[canonical_key] = row[key]
        if row.get("mode"):
            row["mode"] = normalize_mode_id(row["mode"])
        role = row.get("evaluation_role") or row.get("baseline_class")
        if role:
            row["evaluation_role"] = normalize_evaluation_role(role)
    return rows


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")


def _write_lines(path: Path, lines: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for line in lines:
            fh.write(f"{line}\n")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _is_sidecar_path(path: Path) -> bool:
    return path.name.startswith("._") or path.name.startswith(".")


def _visible_json_paths(root: Path, *, recursive: bool = False) -> list[Path]:
    if not root.exists():
        return []
    iterator = root.rglob("*.json") if recursive else root.glob("*.json")
    return sorted(
        path
        for path in iterator
        if path.is_file() and not _is_sidecar_path(path)
    )


def _load_raw_records(input_dir: Path, experiment: str) -> list[dict[str, Any]]:
    if not input_dir.exists():
        raise ValueError(f"missing raw input directory: {input_dir}")
    records: list[dict[str, Any]] = []
    for path in _visible_json_paths(input_dir):
        with path.open("r", encoding="utf-8") as fh:
            record = json.load(fh)
        if record.get("experiment") != experiment:
            continue
        issues = validate_raw_run_record(record, mode_registry=_mode_registry())
        if issues:
            first = issues[0]
            raise ValueError(f"{path}: raw schema issue at {first.path}: {first.message}")
        record["_raw_path"] = str(path)
        records.append(record)
    if not records:
        raise ValueError(f"no raw {experiment} result JSON files found in {input_dir}")
    return records


def _flatten_record(record: Mapping[str, Any]) -> dict[str, Any]:
# BEGIN PHASE_B2A_E8COST_FLATTEN_CLASSIFICATION
    e8cost_evidence_class = classify_e8_cost_evidence(record)
# END PHASE_B2A_E8COST_FLATTEN_CLASSIFICATION
    oracle_summary = _json_mapping(record.get("template_oracle_summary"))
    template_id = str(_get(record, "template.template_id") or "")
    planner_candidate = _planner_candidate_for_template(record, template_id)
    planner_candidate_diagnostics = planner_candidate.get("diagnostics", {})
    if not isinstance(planner_candidate_diagnostics, Mapping):
        planner_candidate_diagnostics = {}
    identity = normalize_run_identity(record, mode_registry=_mode_registry())
    mode = identity.mode
    evaluation_role = identity.evaluation_role
    row = {
        "raw_path": record.get("_raw_path", ""),
        "run_id": record.get("run_id"),
        "manifest_id": record.get("manifest_id"),
        "manifest_hash": record.get("manifest_hash"),
        "experiment": record.get("experiment"),
        "stage": record.get("stage"),
        "run_kind": record.get("run_kind"),
        "dataset_name": _get(record, "dataset.name"),
        "dataset_scale": _get(record, "dataset.scale"),
        "dataset_seed": _get(record, "dataset.seed"),
        "query_id": _get(record, "query.query_id"),
        "query_path": _get(record, "query.path"),
        "policy_id": _get(record, "policy.policy_id"),
        "context_id": _get(record, "context.context_id"),
        "mode": mode,
        "paper_label": _paper_label(mode),
        "evaluation_role": evaluation_role,
        "template_id": template_id,
        "alternative": _get(record, "template.alternative"),
        "template_applicability_status": _get(record, "template_applicability.status"),
        "template_applicability_reason": _get(record, "template_applicability.reason"),
        "template_oracle_eligible": _get(record, "template_oracle.eligible_for_template_oracle"),
        "status": record.get("status"),
        "failure_reason": _get(record, "failure.reason", ""),
        "oracle_status": _get(record, "oracle_check.status"),
        "known_invalid_accepted": _get(record, "oracle_check.known_invalid_accepted"),
        "known_valid_rejected": _get(record, "oracle_check.known_valid_rejected"),
        "artifact_validation_status": _get(record, "artifact_validation.status"),
        "artifact_action": _get(record, "artifact_validation.action"),
        "artifact_expected_action": _get(record, "artifact_validation.expected_action"),
        "artifact_validation_same_snapshot": _get(record, "artifact_validation.same_snapshot"),
        "artifact_validation_isolation_level": _get(record, "artifact_validation.isolation_level"),
        "failure_sqlstate": _get(record, "artifact_validation.failure_sqlstate"),
        "failure_symbol": _get(record, "artifact_validation.failure_symbol"),
        "runtime_audit_status": _get(record, "runtime_audit.status"),
        "unauthorized_observations": _get(record, "runtime_audit.unauthorized_observations"),
        "udf_calls": _get(record, "runtime_audit.udf_calls"),
        "planning_ms": _get(record, "timing_ms.planning"),
        "execution_ms": _get(record, "timing_ms.execution"),
        "verification_ms": _get(record, "timing_ms.verification"),
        "total_ms": _get(record, "timing_ms.total"),
        "row_count": _get(record, "result.row_count"),
        "policy_evals": _get(record, "counts.policy_evals"),
        "residual_checks": _get(record, "counts.residual_checks"),
        "candidate_rows": _get(record, "counts.candidate_rows"),
        "authorized_rows": _get(record, "counts.authorized_rows"),
        "artifact_lookups": _get(record, "counts.artifact_lookups"),
        "base_fetches": _get(record, "counts.base_fetches"),
        "generated_templates": _get(record, "planner.generated_templates"),
        "rejected_templates": _get(record, "planner.rejected_templates"),
        "dominance_pruned": _get(record, "planner.dominance_pruned"),
        "costed_templates": _get(record, "planner.costed_templates"),
        "dominance_checks": _get(record, "counts.dominance_checks"),
        "memo_groups": _get(record, "counts.memo_groups"),
        "peak_memory_bytes": _get(record, "counts.peak_memory_bytes"),
        "serialized_state_bytes": _get(record, "counts.serialized_state_bytes"),
        "pruning_ratio": _get(record, "counts.pruning_ratio"),
        "postgres_planning_ms": _get(record, "pg_metrics.postgres_planning_ms"),
        "prospective_selection_wall_ms": _get(
            record, "planner.prospective_selection_wall_ms"
        ),
        "prospective_explain_wall_ms": _get(
            record, "planner.prospective_explain_wall_ms"
        ),
        "prospective_selection_explain_count": _get(
            record, "planner.prospective_selection_explain_count"
        ),
        "prospective_selection_timing_scope": _get(
            record, "planner.prospective_selection_timing_scope"
        ),
        "query_timing_scope": _get(record, "planner.query_timing_scope"),
        "chosen_rank_vs_template_oracle": _get(record, "planner.chosen_rank_vs_template_oracle"),
        "chosen_estimated_cost": _get(record, "planner.chosen_estimated_cost"),
        "chosen_pg_total_cost": _get(record, "planner.chosen_pg_total_cost"),
        "candidate_estimated_cost": planner_candidate.get("estimated_cost"),
        "candidate_pg_total_cost": planner_candidate_diagnostics.get("pg_total_cost"),
        "candidate_heuristic_cost": planner_candidate_diagnostics.get("heuristic_cost"),
        "candidate_cost_model_version": planner_candidate_diagnostics.get("cost_model_version"),
        "cost_model_version": _get(record, "planner.cost_model_version"),
        "calibration_path": _get(record, "planner.calibration_path"),
        "calibration_hash": _get(record, "planner.calibration_hash"),
        "planner_choice_reason": _get(record, "planner.choice_reason"),
        "planner_level": _get(record, "planner.level"),
        "planner_local_feature_vector": _get(record, "planner.local_feature_vector"),
        "planner_parent_requirement_vector": _get(record, "planner.parent_requirement_vector"),
        "result_hash": _get(record, "result.result_hash"),
        "static_plan_hash": _get(record, "static_verifier.plan_hash"),
        "emitted_sql_hash": _get(record, "sql.emitted_sql_hash"),
        "runner_sql_hash": _get(record, "sql.runner_sql_hash"),
        "query_only_ms": _get(record, "artifact_cost.query_only_ms"),
        "artifact_build_ms": _get(record, "artifact_cost.build_ms"),
        "artifact_refresh_ms": _get(record, "artifact_cost.refresh_ms"),
        "artifact_storage_bytes": _get(record, "artifact_cost.storage_bytes"),
        "artifact_amortization_model": _get(record, "artifact_cost.amortization_model"),
        "artifact_cost_q": _get(record, "artifact_cost.Q"),
        "artifact_cost_u": _get(record, "artifact_cost.U"),
        "artifact_update_rate": _get(record, "artifact_cost.update_rate"),
        "artifact_invalidated_rows": _get(record, "artifact_cost.invalidated_rows"),
        "artifact_table_pages": _get(record, "artifact_cost.table_pages"),
        "artifact_index_pages": _get(record, "artifact_cost.index_pages"),
        "artifact_validation_ms": _get(record, "artifact_cost.validation_ms"),
        "artifact_maintenance_ms_total": _get(record, "artifact_cost.maintenance_ms_total"),
        "artifact_fallback_ms": _get(record, "artifact_cost.fallback_ms"),
        "artifact_refresh_policy": _get(record, "artifact_cost.refresh_policy"),
        "artifact_amortized_query_only_ms": _get(record, "artifact_cost.amortized_latency_ms.query_only"),
        "artifact_amortized_build_plus_single_query_ms": _get(record, "artifact_cost.amortized_latency_ms.build_plus_single_query"),
        "artifact_amortized_q100_u1pct_ms": _get(record, "artifact_cost.amortized_latency_ms.amortized_Q100_U1pct"),
        "artifact_amortized_q1000_u0pct_ms": _get(record, "artifact_cost.amortized_latency_ms.amortized_Q1000_U0pct"),
        "artifact_amortized_declared_q_u_ms": _get(record, "artifact_cost.amortized_latency_ms.declared_Q_U"),
        "e5_effective_latency_ms": _get(record, "e5_witness.effective_latency_ms"),
        "e5_best_effective_latency_ms": _get(record, "e5_witness.best_effective_ms"),
        "e5_regret_ratio": _get(record, "e5_witness.regret_ratio"),
        "e5_theory_witness": _get(record, "e5_witness.theory_witness"),
        "e5_fixed_mode_under_test": _get(record, "e5_witness.fixed_mode_under_test"),
        "e5_expected_best_mode": _get(record, "e5_witness.expected_best_mode"),
        "git_commit": _get(record, "implementation.git_commit"),
        "measurement_phase": _get(record, "measurement.phase", "measured"),
        "measurement_iteration": _get(record, "measurement.iteration"),
        "measurement_warmup_repetitions": _get(record, "measurement.warmup_repetitions"),
        "measurement_measured_repetitions": _get(record, "measurement.measured_repetitions"),
        "oracle_gap": oracle_summary.get("gap"),
        "oracle_best_template_id": oracle_summary.get("best_template_id"),
        "oracle_best_execution_ms": oracle_summary.get("best_execution_ms"),
        "oracle_chosen_template_id": oracle_summary.get("chosen_template_id"),
        "oracle_chosen_execution_ms": oracle_summary.get("chosen_execution_ms"),
        "oracle_eligible_templates": oracle_summary.get("eligible_templates"),
        "oracle_eligible_plan_shapes": oracle_summary.get("eligible_plan_shapes"),
        "oracle_chosen_is_measured_best": oracle_summary.get("chosen_is_measured_best"),
        "oracle_chosen_measured_rank": oracle_summary.get("chosen_measured_rank"),
        "oracle_measured_best_estimated_rank": oracle_summary.get("measured_best_estimated_rank"),
        "oracle_excluded_templates": oracle_summary.get("excluded_templates"),
        "oracle_ranking_metric": oracle_summary.get("ranking_metric"),
    }
    params = _get(record, "query.params", {})
    if isinstance(params, Mapping):
        for key, value in sorted(params.items()):
            row[f"param_{key}"] = value
    planning_ms = _maybe_float(row.get("planning_ms"))
    total_ms = _maybe_float(row.get("total_ms"))
    if planning_ms is not None and total_ms is not None and total_ms > 0:
        row["planning_total_ratio"] = planning_ms / total_ms
# BEGIN PHASE_B2A_E8COST_FLATTEN_ACCOUNTING
    if e8cost_evidence_class is not None:
        evidence = _json_mapping(record.get("evidence"))
        result_body_observed = (
            e8cost_evidence_class == E8COST_RESULT_EXECUTION
        )
        row.update(
            {
                "e8cost_evidence_class": e8cost_evidence_class,
                "e8cost_evidence_authority": (
                    "executed_result_evidence"
                    if result_body_observed
                    else (
                        "accounting_projection_integrity_only"
                        if e8cost_evidence_class
                        == E8COST_ACCOUNTING_PROJECTION
                        else "gate_reject_no_selected_body"
                    )
                ),
                "e8cost_result_body_observed": result_body_observed,
                "e8cost_integrity_only": not result_body_observed,
                "e8cost_production_planner_authority": False,
                "e8cost_selection_authority": False,
                "e8cost_execution_authority": result_body_observed,
                "e8cost_result_evidence": result_body_observed,
                "e8cost_f3_selection_authority": False,
            }
        )
        if e8cost_evidence_class == E8COST_ACCOUNTING_PROJECTION:
            accounting = _json_mapping(
                _get(record, "artifact_cost.accounting_probe", {})
            )
            declared = _json_mapping(accounting.get("declared_inputs"))
            case_validation = _json_mapping(
                accounting.get("case_validation_observation")
            )
            alternatives = _json_list(accounting.get("accounting_alternatives"))
            minimum = _json_mapping(
                accounting.get("observed_accounting_minimum")
            )
            row.update(
                {
                    "projected_declared_family": declared.get("family"),
                    "projected_declared_q": declared.get("Q"),
                    "projected_declared_u": declared.get("U"),
                    "projected_declared_query_shape": declared.get(
                        "query_shape"
                    ),
                    "projected_declared_artifact_type": declared.get(
                        "artifact_type"
                    ),
                    "projected_declared_ttl_s": declared.get("ttl_s"),
                    "projected_declared_contexts": declared.get("contexts"),
                    "projected_declared_artifact_status": declared.get(
                        "artifact_status"
                    ),
                    "projected_declared_contract_action": declared.get(
                        "contract_action"
                    ),
                    "projected_declared_expected_effect": declared.get(
                        "expected_effect"
                    ),
                    "projected_case_validation_status": case_validation.get(
                        "status"
                    ),
                    "projected_case_validation_failure_sqlstate": (
                        case_validation.get("failure_sqlstate")
                    ),
                    "projected_case_validation_failure_symbol": (
                        case_validation.get("failure_symbol")
                    ),
                    "projected_case_validation_elapsed_ms": (
                        case_validation.get("elapsed_ms")
                    ),
                    "projected_case_validation_same_snapshot": (
                        case_validation.get("same_snapshot")
                    ),
                    "projected_case_validation_isolation_level": (
                        case_validation.get("isolation_level")
                    ),
                    "projected_alternatives": alternatives,
                    "projected_alternative_count": len(alternatives),
                    "observed_accounting_minimum": minimum,
                    "observed_accounting_minimum_template_id": minimum.get(
                        "projected_template_id"
                    ),
                    "observed_accounting_minimum_alternative": minimum.get(
                        "projected_alternative"
                    ),
                    "observed_accounting_minimum_action": minimum.get(
                        "projected_action"
                    ),
                    "observed_accounting_minimum_reason": minimum.get(
                        "projection_reason"
                    ),
                    "observed_accounting_minimum_amortized_latency_ms": (
                        minimum.get("amortized_latency_ms")
                    ),
                    "projected_shared_probe_owner_digest": evidence.get(
                        "shared_probe_owner_digest"
                    ),
                    "projected_projection_owner_digest": evidence.get(
                        "projection_owner_digest"
                    ),
                    "projected_projection_integrity_digest": evidence.get(
                        "projection_integrity_digest"
                    ),
                }
            )
        elif e8cost_evidence_class == E8COST_GATE_REJECT:
            row.update(
                {
                    "gate_reject_template_id": row.get("template_id"),
                    "gate_reject_alternative": row.get("alternative"),
                    "gate_accounting_q": row.get("artifact_cost_q"),
                    "gate_accounting_u": row.get("artifact_cost_u"),
                    "gate_accounting_query_only_ms": row.get("query_only_ms"),
                    "gate_accounting_build_ms": row.get("artifact_build_ms"),
                    "gate_accounting_refresh_ms": row.get(
                        "artifact_refresh_ms"
                    ),
                    "gate_accounting_validation_ms": row.get(
                        "artifact_validation_ms"
                    ),
                    "gate_accounting_maintenance_ms_total": row.get(
                        "artifact_maintenance_ms_total"
                    ),
                    "gate_accounting_fallback_ms": row.get(
                        "artifact_fallback_ms"
                    ),
                    "gate_accounting_storage_bytes": row.get(
                        "artifact_storage_bytes"
                    ),
                }
            )
        if e8cost_evidence_class != E8COST_RESULT_EXECUTION:
            for field in (
                "planning_ms",
                "execution_ms",
                "verification_ms",
                "total_ms",
                "planning_total_ratio",
                "row_count",
                "result_hash",
                "query_only_ms",
                "artifact_build_ms",
                "artifact_refresh_ms",
                "artifact_storage_bytes",
                "artifact_cost_q",
                "artifact_cost_u",
                "artifact_update_rate",
                "artifact_invalidated_rows",
                "artifact_table_pages",
                "artifact_index_pages",
                "artifact_validation_ms",
                "artifact_maintenance_ms_total",
                "artifact_fallback_ms",
                "artifact_amortized_query_only_ms",
                "artifact_amortized_build_plus_single_query_ms",
                "artifact_amortized_q100_u1pct_ms",
                "artifact_amortized_q1000_u0pct_ms",
                "artifact_amortized_declared_q_u_ms",
                "chosen_rank_vs_template_oracle",
                "chosen_estimated_cost",
                "chosen_pg_total_cost",
                "candidate_estimated_cost",
                "candidate_pg_total_cost",
                "candidate_heuristic_cost",
                "oracle_gap",
                "oracle_best_execution_ms",
                "oracle_chosen_execution_ms",
                "oracle_chosen_measured_rank",
            ):
                row[field] = None
            if e8cost_evidence_class == E8COST_GATE_REJECT:
                row["template_id"] = ""
                row["alternative"] = None
            row["planner_choice_reason"] = None
# END PHASE_B2A_E8COST_FLATTEN_ACCOUNTING
    return row


def _template_oracle_analysis(rows: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    candidate_template_sets: defaultdict[tuple[str, ...], set[str]] = defaultdict(set)
    candidate_plan_shape_sets: defaultdict[tuple[str, ...], set[str]] = defaultdict(set)
    for row in rows:
        if row.get("run_kind") != "template_candidate":
            continue
        if str(row.get("measurement_phase") or "measured") != "measured":
            continue
        if _maybe_bool(row.get("template_oracle_eligible")) is not True:
            continue
        if _row_status(row) != "pass":
            continue
        cell_key = _oracle_audit_cell_key(row)
        template_id = str(row.get("template_id", ""))
        if template_id:
            candidate_template_sets[cell_key].add(template_id)
        plan_shape_key = str(
            row.get("static_plan_hash")
            or row.get("emitted_sql_hash")
            or template_id
        )
        if plan_shape_key:
            candidate_plan_shape_sets[cell_key].add(plan_shape_key)

    oracle_rows = [
        row
        for row in rows
        if row.get("run_kind") == "template_oracle_summary"
        and str(row.get("measurement_phase") or "measured") == "measured"
        and _maybe_float(row.get("oracle_gap")) is not None
    ]
    analysis_rows: list[dict[str, Any]] = []
    gaps: list[float] = []
    cell_groups: defaultdict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    below_resolution_cells: set[tuple[str, ...]] = set()
    top1 = 0
    top3 = 0
    measured_best_hits = 0
    measured_best_estimated_ranks: list[float] = []
    chosen_measured_ranks: list[float] = []
    for row in oracle_rows:
        gap = float(row["oracle_gap"])
        gaps.append(gap)
        estimated_rank = _maybe_float(row.get("chosen_rank_vs_template_oracle"))
        if estimated_rank is not None and estimated_rank <= 1:
            top1 += 1
        if estimated_rank is not None and estimated_rank <= 3:
            top3 += 1
        measured_best_estimated_rank = _maybe_float(row.get("oracle_measured_best_estimated_rank"))
        chosen_measured_rank = _maybe_float(row.get("oracle_chosen_measured_rank"))
        declared_hit = _maybe_bool(row.get("oracle_chosen_is_measured_best"))
        if declared_hit is None:
            best_template_id = str(row.get("oracle_best_template_id") or "")
            chosen_template_id = str(row.get("oracle_chosen_template_id") or "")
            same_template = bool(
                best_template_id and chosen_template_id and best_template_id == chosen_template_id
            )
            same_runtime = math.isclose(gap, 1.0, rel_tol=1e-12, abs_tol=1e-12)
            chosen_is_measured_best = same_template or same_runtime
        else:
            chosen_is_measured_best = declared_hit
        if chosen_is_measured_best:
            measured_best_hits += 1
            if chosen_measured_rank is None:
                chosen_measured_rank = 1.0
            if measured_best_estimated_rank is None:
                measured_best_estimated_rank = estimated_rank
        if measured_best_estimated_rank is not None:
            measured_best_estimated_ranks.append(measured_best_estimated_rank)
        if chosen_measured_rank is not None:
            chosen_measured_ranks.append(chosen_measured_rank)
        cell_key = _oracle_audit_cell_key(row)
        eligible_templates = _maybe_float(row.get("oracle_eligible_templates"))
        if eligible_templates is None and candidate_template_sets.get(cell_key):
            eligible_templates = float(len(candidate_template_sets[cell_key]))
        eligible_plan_shapes = _maybe_float(row.get("oracle_eligible_plan_shapes"))
        if eligible_plan_shapes is None and candidate_plan_shape_sets.get(cell_key):
            eligible_plan_shapes = float(len(candidate_plan_shape_sets[cell_key]))
        best_execution_ms = _maybe_float(row.get("oracle_best_execution_ms"))
        below_resolution = (
            best_execution_ms is not None
            and best_execution_ms < ORACLE_MEASUREMENT_RESOLUTION_FLOOR_MS
        )
        if below_resolution:
            below_resolution_cells.add(cell_key)
        cell_groups[cell_key].append(
            {
                "gap": gap,
                "estimated_rank": estimated_rank,
                "chosen_is_measured_best": chosen_is_measured_best,
                "measured_best_estimated_rank": measured_best_estimated_rank,
                "chosen_measured_rank": chosen_measured_rank,
                "eligible_templates": eligible_templates,
                "eligible_plan_shapes": eligible_plan_shapes,
            }
        )
        extra_cell_fields = {
            field: row.get(field, "")
            for field in ORACLE_AUDIT_E2_CELL_FIELDS
            if str(row.get("experiment", "")) == "E2"
        }
        analysis_rows.append(
            {
                "experiment": row.get("experiment", ""),
                "stage": row.get("stage", ""),
                "dataset_name": row.get("dataset_name", ""),
                "dataset_scale": row.get("dataset_scale", ""),
                "dataset_seed": row.get("dataset_seed", ""),
                "query_id": row.get("query_id", ""),
                "policy_id": row.get("policy_id", ""),
                "context_id": row.get("context_id", ""),
                **extra_cell_fields,
                "best_template_id": row.get("oracle_best_template_id", ""),
                "chosen_template_id": row.get("oracle_chosen_template_id", ""),
                "oracle_gap": gap,
                "best_execution_ms": row.get("oracle_best_execution_ms", ""),
                "chosen_execution_ms": row.get("oracle_chosen_execution_ms", ""),
                "eligible_templates": eligible_templates if eligible_templates is not None else "",
                "eligible_plan_shapes": eligible_plan_shapes if eligible_plan_shapes is not None else "",
                "excluded_templates": row.get("oracle_excluded_templates", ""),
                "estimated_rank": row.get("chosen_rank_vs_template_oracle", ""),
                "chosen_is_measured_best": chosen_is_measured_best,
                "below_measurement_resolution": below_resolution,
                "chosen_measured_rank": chosen_measured_rank if chosen_measured_rank is not None else "",
                "measured_best_estimated_rank": (
                    measured_best_estimated_rank if measured_best_estimated_rank is not None else ""
                ),
                "ranking_metric": row.get("oracle_ranking_metric", ""),
            }
        )
    ordered = sorted(gaps)
    observation_count = len(ordered)
    cell_gap_values: list[float] = []
    cell_top1 = 0
    cell_top3 = 0
    cell_measured_best_hits = 0
    cell_measured_best_estimated_rank_values: list[float] = []
    cell_chosen_measured_rank_values: list[float] = []
    cell_eligible_template_values: list[float] = []
    cell_eligible_plan_shape_values: list[float] = []
    for group in cell_groups.values():
        group_gaps = [float(item["gap"]) for item in group]
        group_ranks = [item["estimated_rank"] for item in group if item["estimated_rank"] is not None]
        group_eligible_templates = [
            item["eligible_templates"]
            for item in group
            if item["eligible_templates"] is not None
        ]
        group_eligible_plan_shapes = [
            item["eligible_plan_shapes"]
            for item in group
            if item["eligible_plan_shapes"] is not None
        ]
        cell_gap = _median(group_gaps)
        cell_gap_values.append(cell_gap)
        if group_eligible_templates:
            cell_eligible_template_values.append(_median(group_eligible_templates))
        if group_eligible_plan_shapes:
            cell_eligible_plan_shape_values.append(_median(group_eligible_plan_shapes))
        if group_ranks and _median(group_ranks) <= 1:
            cell_top1 += 1
        if group_ranks and _median(group_ranks) <= 3:
            cell_top3 += 1
        if math.isclose(cell_gap, 1.0, rel_tol=1e-12, abs_tol=1e-12):
            cell_measured_best_hits += 1
        measured_best_rank_group = [
            item["measured_best_estimated_rank"]
            for item in group
            if item["measured_best_estimated_rank"] is not None
        ]
        chosen_measured_rank_group = [
            item["chosen_measured_rank"]
            for item in group
            if item["chosen_measured_rank"] is not None
        ]
        if measured_best_rank_group:
            cell_measured_best_estimated_rank_values.append(_median(measured_best_rank_group))
        if chosen_measured_rank_group:
            cell_chosen_measured_rank_values.append(_median(chosen_measured_rank_group))
    ordered_cell_gaps = sorted(cell_gap_values)
    cell_count = len(ordered_cell_gaps)
    summary = {
        "oracle_cell_count": cell_count,
        "oracle_observation_count": observation_count,
        "below_resolution_cell_count": len(below_resolution_cells),
        "measurement_resolution_floor_ms": ORACLE_MEASUREMENT_RESOLUTION_FLOOR_MS,
        "eligible_templates_min": min(cell_eligible_template_values)
        if cell_eligible_template_values
        else None,
        "eligible_templates_median": _median(cell_eligible_template_values)
        if cell_eligible_template_values
        else None,
        "eligible_templates_max": max(cell_eligible_template_values)
        if cell_eligible_template_values
        else None,
        "eligible_plan_shapes_min": min(cell_eligible_plan_shape_values)
        if cell_eligible_plan_shape_values
        else None,
        "eligible_plan_shapes_median": _median(cell_eligible_plan_shape_values)
        if cell_eligible_plan_shape_values
        else None,
        "eligible_plan_shapes_max": max(cell_eligible_plan_shape_values)
        if cell_eligible_plan_shape_values
        else None,
        "pool_size_1_cell_count": sum(
            1 for value in cell_eligible_plan_shape_values if math.isclose(value, 1.0)
        ),
        "median_oracle_gap": _median(ordered_cell_gaps) if ordered_cell_gaps else None,
        "p90_oracle_gap": _percentile(ordered_cell_gaps, 0.9) if ordered_cell_gaps else None,
        "max_oracle_gap": max(ordered_cell_gaps) if ordered_cell_gaps else None,
        "observation_median_oracle_gap": _median(ordered) if ordered else None,
        "observation_p90_oracle_gap": _percentile(ordered, 0.9) if ordered else None,
        "observation_max_oracle_gap": max(ordered) if ordered else None,
        "top1_estimated_rank_count": cell_top1,
        "top3_estimated_rank_count": cell_top3,
        "top1_estimated_rank_rate": (cell_top1 / cell_count) if cell_count else None,
        "top3_estimated_rank_rate": (cell_top3 / cell_count) if cell_count else None,
        "observation_top1_estimated_rank_count": top1,
        "observation_top3_estimated_rank_count": top3,
        "chosen_is_measured_best_count": cell_measured_best_hits,
        "chosen_is_measured_best_rate": (cell_measured_best_hits / cell_count) if cell_count else None,
        "observation_chosen_is_measured_best_count": measured_best_hits,
        "observation_chosen_is_measured_best_rate": (
            measured_best_hits / observation_count
        ) if observation_count else None,
        "measured_best_estimated_rank_median": _median(cell_measured_best_estimated_rank_values)
        if cell_measured_best_estimated_rank_values
        else None,
        "chosen_measured_rank_median": _median(cell_chosen_measured_rank_values)
        if cell_chosen_measured_rank_values
        else None,
        "observation_measured_best_estimated_rank_median": _median(measured_best_estimated_ranks)
        if measured_best_estimated_ranks
        else None,
        "observation_chosen_measured_rank_median": _median(chosen_measured_ranks)
        if chosen_measured_ranks
        else None,
    }
    return analysis_rows, summary


def _median_field(rows: Sequence[Mapping[str, Any]], field: str) -> float | None:
    values = [
        parsed
        for parsed in (_maybe_float(row.get(field)) for row in rows)
        if parsed is not None
    ]
    return _median(values) if values else None


def _rank_keyed_values(values: Mapping[str, float]) -> dict[str, int]:
    ranked = sorted(values.items(), key=lambda item: (item[1], item[0]))
    return {key: index for index, (key, _) in enumerate(ranked, start=1)}


# BEGIN PHASE_B2A_E8COST_ARTIFACT_ACCOUNTING_ANALYSIS
def _e8cost_family(query_id: str) -> str:
    if query_id.startswith("E8cost_mav_dash_"):
        return "MAV-DASH"
    if query_id.startswith("E8cost_authidx_sparse_"):
        return "AUTHIDX-SPARSE"
    if query_id.startswith("E8cost_stale_fallback_"):
        return "STALE-FALLBACK"
    raise ValueError(f"unknown E8-COST query identity: {query_id}")


def _e8cost_invalid_gate_admission(row: Mapping[str, Any]) -> bool:
    if row.get("e8cost_evidence_class") != E8COST_ACCOUNTING_PROJECTION:
        return False
    if row.get("projected_case_validation_status") == "pass":
        return False
    return any(
        isinstance(alternative, Mapping)
        and alternative.get("projected_action") == "execute"
        for alternative in _json_list(row.get("projected_alternatives"))
    )


def _e8cost_artifact_cost_analysis(
    rows: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    e8_rows = [
        row
        for row in rows
        if row.get("experiment") == "E8"
        and row.get("stage") == "artifact_cost_update_rate"
        and row.get("run_kind") == "normal_mode"
    ]
    if any(
        row.get("e8cost_evidence_class") not in E8COST_EVIDENCE_CLASSES
        for row in e8_rows
    ):
        raise ValueError("E8-COST accounting analysis received unclassified rows")

    groups: defaultdict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(
        list
    )
    for row in e8_rows:
        groups[(str(row.get("query_id") or ""), str(row.get("mode") or ""))].append(
            row
        )

    cost_rows: list[dict[str, Any]] = []
    raw_class_counts: Counter[str] = Counter()
    measured_class_counts: Counter[str] = Counter()
    warmup_class_counts: Counter[str] = Counter()
    class_cell_counts: Counter[str] = Counter()
    projected_action_record_counts: Counter[str] = Counter()
    projected_action_cell_counts: Counter[str] = Counter()
    projected_template_record_counts: Counter[str] = Counter()
    projected_template_cell_counts: Counter[str] = Counter()
    minimum_action_record_counts: Counter[str] = Counter()
    minimum_template_record_counts: Counter[str] = Counter()
    invalid_gate_admission_count = 0
    measured_invalid_gate_admission_count = 0
    executed_pass_count = 0
    executed_wrong_count = 0

    for (query_id, mode), group in sorted(
        groups.items(), key=lambda item: (item[0][0], _mode_order(item[0][1]))
    ):
        classes = {str(row.get("e8cost_evidence_class")) for row in group}
        if len(classes) != 1:
            raise ValueError(
                f"E8-COST cell {query_id}/{mode} mixes evidence populations"
            )
        evidence_class = next(iter(classes))
        class_cell_counts[evidence_class] += 1
        measured = [
            row
            for row in group
            if str(row.get("measurement_phase") or "measured") == "measured"
        ]
        warmup = [
            row
            for row in group
            if str(row.get("measurement_phase")) == "warmup"
        ]
        raw_class_counts[evidence_class] += len(group)
        measured_class_counts[evidence_class] += len(measured)
        warmup_class_counts[evidence_class] += len(warmup)

        family = _e8cost_family(query_id)
        first = group[0]
        accounting_q = (
            first.get("projected_declared_q")
            if evidence_class == E8COST_ACCOUNTING_PROJECTION
            else first.get("param_amortization_q")
        )
        accounting_u = (
            first.get("projected_declared_u")
            if evidence_class == E8COST_ACCOUNTING_PROJECTION
            else first.get("param_update_rate_per_hour")
        )
        artifact_type = (
            first.get("projected_declared_artifact_type")
            if evidence_class == E8COST_ACCOUNTING_PROJECTION
            else first.get("param_artifact_type")
        )
        query_shape = (
            first.get("projected_declared_query_shape")
            if evidence_class == E8COST_ACCOUNTING_PROJECTION
            else first.get("param_query_shape")
        )

        status_counts = Counter(str(row.get("status")) for row in measured)
        cell_projected_actions: set[str] = set()
        cell_projected_templates: set[str] = set()
        if evidence_class == E8COST_ACCOUNTING_PROJECTION:
            for row in group:
                invalid = _e8cost_invalid_gate_admission(row)
                invalid_gate_admission_count += int(invalid)
                if str(row.get("measurement_phase") or "measured") == "measured":
                    measured_invalid_gate_admission_count += int(invalid)
            for row in measured:
                observed_action = str(
                    row.get("observed_accounting_minimum_action") or ""
                )
                observed_template = str(
                    row.get("observed_accounting_minimum_template_id") or ""
                )
                if not observed_action or not observed_template:
                    raise ValueError(
                        "observed accounting minimum identity is incomplete"
                    )
                projected_action_record_counts[observed_action] += 1
                projected_template_record_counts[observed_template] += 1
                cell_projected_actions.add(observed_action)
                cell_projected_templates.add(observed_template)
                for alternative in _json_list(row.get("projected_alternatives")):
                    if not isinstance(alternative, Mapping):
                        raise ValueError(
                            "projected accounting alternatives must remain mappings"
                        )
                    action = str(alternative.get("projected_action") or "")
                    template = str(
                        alternative.get("projected_template_id") or ""
                    )
                    if not action or not template:
                        raise ValueError(
                            "projected accounting alternative identity is incomplete"
                        )
                minimum_action_record_counts[
                    str(row.get("observed_accounting_minimum_action") or "")
                ] += 1
                minimum_template_record_counts[
                    str(
                        row.get("observed_accounting_minimum_template_id") or ""
                    )
                ] += 1
            projected_action_cell_counts.update(cell_projected_actions)
            projected_template_cell_counts.update(cell_projected_templates)

        executed_rows = (
            measured
            if evidence_class == E8COST_RESULT_EXECUTION
            else []
        )
        cell_executed_pass = sum(
            1 for row in executed_rows if row.get("status") == "pass"
        )
        cell_executed_wrong = sum(
            1 for row in executed_rows if row.get("status") == "wrong_result"
        )
        cell_executed_denominator = len(executed_rows)
        executed_pass_count += cell_executed_pass
        executed_wrong_count += cell_executed_wrong

        cost_rows.append(
            {
                "query_id": query_id,
                "mode": mode,
                "paper_label": first.get("paper_label", ""),
                "evaluation_role": first.get("evaluation_role", ""),
                "e8cost_evidence_class": evidence_class,
                "accounting_family": family,
                "accounting_q": accounting_q,
                "accounting_u": accounting_u,
                "accounting_artifact_type": artifact_type,
                "accounting_query_shape": query_shape,
                "sample_count": len(measured),
                "warmup_count": len(warmup),
                "total_record_count": len(group),
                "accounting_projection_record_count": (
                    len(measured)
                    if evidence_class == E8COST_ACCOUNTING_PROJECTION
                    else 0
                ),
                "gate_reject_record_count": (
                    len(measured)
                    if evidence_class == E8COST_GATE_REJECT
                    else 0
                ),
                "result_execution_record_count": len(executed_rows),
                "executed_pass_count": cell_executed_pass,
                "executed_wrong_result_count": cell_executed_wrong,
                "executed_result_denominator": cell_executed_denominator,
                "executed_wrong_result_rate": (
                    cell_executed_wrong / cell_executed_denominator
                    if cell_executed_denominator
                    else None
                ),
                "invalid_gate_admission_count": sum(
                    1 for row in measured if _e8cost_invalid_gate_admission(row)
                ),
                "status_counts": dict(sorted(status_counts.items())),
                "projected_action_accounting_counts": dict(
                    sorted(
                        Counter(
                            str(row.get("observed_accounting_minimum_action"))
                            for row in measured
                            if row.get("observed_accounting_minimum_action")
                        ).items()
                    )
                ),
                "projected_template_accounting_counts": dict(
                    sorted(
                        Counter(
                            str(
                                row.get(
                                    "observed_accounting_minimum_template_id"
                                )
                            )
                            for row in measured
                            if row.get(
                                "observed_accounting_minimum_template_id"
                            )
                        ).items()
                    )
                ),
                "observed_accounting_minimum_template_counts": dict(
                    sorted(
                        Counter(
                            str(
                                row.get(
                                    "observed_accounting_minimum_template_id"
                                )
                            )
                            for row in measured
                            if row.get(
                                "observed_accounting_minimum_template_id"
                            )
                        ).items()
                    )
                ),
                "observed_accounting_minimum_action_counts": dict(
                    sorted(
                        Counter(
                            str(
                                row.get(
                                    "observed_accounting_minimum_action"
                                )
                            )
                            for row in measured
                            if row.get("observed_accounting_minimum_action")
                        ).items()
                    )
                ),
                "observed_accounting_minimum_amortized_latency_ms_median": (
                    _median_field(
                        measured,
                        "observed_accounting_minimum_amortized_latency_ms",
                    )
                ),
                "projected_case_validation_ms_median": _median_field(
                    measured, "projected_case_validation_elapsed_ms"
                ),
                "gate_accounting_validation_ms_median": _median_field(
                    measured, "gate_accounting_validation_ms"
                ),
                "gate_accounting_query_only_ms_median": _median_field(
                    measured, "gate_accounting_query_only_ms"
                ),
                "executed_query_only_ms_median": _median_field(
                    executed_rows, "query_only_ms"
                ),
                "executed_execution_ms_median": _median_field(
                    executed_rows, "execution_ms"
                ),
                "executed_total_ms_median": _median_field(
                    executed_rows, "total_ms"
                ),
                "observed_accounting_declared_q_u_ms_median": _median_field(
                    executed_rows, "artifact_amortized_declared_q_u_ms"
                ),
            }
        )

    executed_denominator = executed_pass_count + executed_wrong_count
    summary = {
        "artifact_cost_cell_count": len(cost_rows),
        "scenario_count": len({row.get("query_id") for row in e8_rows}),
        "raw_record_count": len(e8_rows),
        "measured_record_count": sum(
            1
            for row in e8_rows
            if str(row.get("measurement_phase") or "measured") == "measured"
        ),
        "warmup_record_count": sum(
            1
            for row in e8_rows
            if str(row.get("measurement_phase")) == "warmup"
        ),
        "evidence_class_raw_record_counts": {
            key: raw_class_counts.get(key, 0) for key in E8COST_EVIDENCE_CLASSES
        },
        "evidence_class_measured_record_counts": {
            key: measured_class_counts.get(key, 0)
            for key in E8COST_EVIDENCE_CLASSES
        },
        "evidence_class_warmup_record_counts": {
            key: warmup_class_counts.get(key, 0)
            for key in E8COST_EVIDENCE_CLASSES
        },
        "evidence_class_cell_counts": {
            key: class_cell_counts.get(key, 0)
            for key in E8COST_EVIDENCE_CLASSES
        },
        "accounting_projection_record_count": raw_class_counts.get(
            E8COST_ACCOUNTING_PROJECTION, 0
        ),
        "accounting_projection_measured_record_count": measured_class_counts.get(
            E8COST_ACCOUNTING_PROJECTION, 0
        ),
        "accounting_projection_warmup_record_count": warmup_class_counts.get(
            E8COST_ACCOUNTING_PROJECTION, 0
        ),
        "accounting_projection_cell_count": class_cell_counts.get(
            E8COST_ACCOUNTING_PROJECTION, 0
        ),
        "gate_reject_record_count": raw_class_counts.get(E8COST_GATE_REJECT, 0),
        "gate_reject_measured_record_count": measured_class_counts.get(
            E8COST_GATE_REJECT, 0
        ),
        "gate_reject_warmup_record_count": warmup_class_counts.get(
            E8COST_GATE_REJECT, 0
        ),
        "gate_reject_cell_count": class_cell_counts.get(E8COST_GATE_REJECT, 0),
        "result_execution_record_count": raw_class_counts.get(
            E8COST_RESULT_EXECUTION, 0
        ),
        "result_execution_measured_record_count": measured_class_counts.get(
            E8COST_RESULT_EXECUTION, 0
        ),
        "result_execution_warmup_record_count": warmup_class_counts.get(
            E8COST_RESULT_EXECUTION, 0
        ),
        "result_execution_cell_count": class_cell_counts.get(
            E8COST_RESULT_EXECUTION, 0
        ),
        "executed_pass_count": executed_pass_count,
        "executed_wrong_result_count": executed_wrong_count,
        "executed_result_denominator": executed_denominator,
        "executed_wrong_result_rate": (
            executed_wrong_count / executed_denominator
            if executed_denominator
            else None
        ),
        "invalid_gate_admission_count": invalid_gate_admission_count,
        "measured_invalid_gate_admission_count": (
            measured_invalid_gate_admission_count
        ),
        "projected_action_accounting_record_counts": dict(
            sorted(projected_action_record_counts.items())
        ),
        "projected_action_accounting_cell_counts": dict(
            sorted(projected_action_cell_counts.items())
        ),
        "projected_template_accounting_record_counts": dict(
            sorted(projected_template_record_counts.items())
        ),
        "projected_template_accounting_cell_counts": dict(
            sorted(projected_template_cell_counts.items())
        ),
        "observed_accounting_minimum_action_record_counts": dict(
            sorted(minimum_action_record_counts.items())
        ),
        "observed_accounting_minimum_template_record_counts": dict(
            sorted(minimum_template_record_counts.items())
        ),
        "performance_ranking_eligible": False,
        "planner_choice_authority": False,
    }
    return cost_rows, summary
# END PHASE_B2A_E8COST_ARTIFACT_ACCOUNTING_ANALYSIS
def _artifact_cost_analysis(rows: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
# BEGIN PHASE_B2A_E8COST_ARTIFACT_ACCOUNTING_ROUTE
    if any(
        row.get("experiment") == "E8"
        and row.get("stage") == "artifact_cost_update_rate"
        for row in rows
    ):
        return _e8cost_artifact_cost_analysis(rows)
# END PHASE_B2A_E8COST_ARTIFACT_ACCOUNTING_ROUTE
    e8_rows = [
        row
        for row in rows
        if row.get("experiment") == "E8"
        and row.get("run_kind") == "normal_mode"
        and str(row.get("measurement_phase") or "measured") == "measured"
    ]
    groups: defaultdict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in e8_rows:
        groups[(str(row.get("query_id") or ""), str(row.get("mode") or ""))].append(row)

    cost_rows: list[dict[str, Any]] = []
    for (query_id, mode), group in sorted(
        groups.items(), key=lambda item: (item[0][0], _mode_order(item[0][1]))
    ):
        status_counts = Counter(str(row.get("status")) for row in group)
        action_counts = Counter(str(row.get("artifact_action")) for row in group)
        template_counts = Counter(str(row.get("template_id")) for row in group)
        choice_reason_counts = Counter(
            str(row.get("planner_choice_reason") or "") for row in group
        )
        known_invalid_accepted_count = sum(
            1
            for row in group
            if str(row.get("known_invalid_accepted", "")).strip().lower()
            in {"1", "true", "yes"}
        )
        first = group[0]
        cost_rows.append(
            {
                "query_id": query_id,
                "mode": mode,
                "paper_label": first.get("paper_label", ""),
                "evaluation_role": first.get("evaluation_role", ""),
                "artifact_type": first.get("param_artifact_type", ""),
                "query_shape": first.get("param_query_shape", ""),
                "expected_action": first.get("param_expected_action", ""),
                "update_rate_per_hour": first.get("param_update_rate_per_hour", ""),
                "ttl_s": first.get("param_ttl_s", ""),
                "contexts": first.get("param_contexts", ""),
                "dominant_status": status_counts.most_common(1)[0][0] if status_counts else "",
                "dominant_action": action_counts.most_common(1)[0][0] if action_counts else "",
                "dominant_template_id": template_counts.most_common(1)[0][0] if template_counts else "",
                "choice_reason_counts": dict(sorted(choice_reason_counts.items())),
                "status_counts": dict(sorted(status_counts.items())),
                "wrong_result_count": status_counts.get("wrong_result", 0),
                "known_invalid_accepted_count": known_invalid_accepted_count,
                "sample_count": len(group),
                "query_only_ms_median": _median_field(group, "query_only_ms"),
                "total_ms_median": _median_field(group, "total_ms"),
                "build_ms_median": _median_field(group, "artifact_build_ms"),
                "refresh_ms_median": _median_field(group, "artifact_refresh_ms"),
                "validation_ms_median": _median_field(group, "artifact_validation_ms"),
                "maintenance_ms_total_median": _median_field(group, "artifact_maintenance_ms_total"),
                "fallback_ms_median": _median_field(group, "artifact_fallback_ms"),
                "storage_bytes_median": _median_field(group, "artifact_storage_bytes"),
                "table_pages_median": _median_field(group, "artifact_table_pages"),
                "index_pages_median": _median_field(group, "artifact_index_pages"),
                "invalidated_rows_median": _median_field(group, "artifact_invalidated_rows"),
                "amortized_query_only_ms_median": _median_field(group, "artifact_amortized_query_only_ms"),
                "amortized_build_plus_single_query_ms_median": _median_field(
                    group,
                    "artifact_amortized_build_plus_single_query_ms",
                ),
                "amortized_q100_u1pct_ms_median": _median_field(group, "artifact_amortized_q100_u1pct_ms"),
                "amortized_q1000_u0pct_ms_median": _median_field(group, "artifact_amortized_q1000_u0pct_ms"),
                "amortized_declared_q_u_ms_median": _median_field(
                    group,
                    "artifact_amortized_declared_q_u_ms",
                ),
            }
        )

    policy_enforcement_modes = {
        ADMISSION_FIRST_MODE,
        "conservative-barrier",
        "native-pg-rls",
        "native-pg-rls-physical-design",
    }
    best_query_only: dict[str, Any] = {}
    best_amortized_q100: dict[str, Any] = {}
    best_declared_q_u: dict[str, Any] = {}
    by_query: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in cost_rows:
        if row["mode"] in policy_enforcement_modes and row["dominant_status"] == "pass":
            by_query[str(row["query_id"])].append(row)
    for query_id, group in sorted(by_query.items()):
        query_candidates = [
            row for row in group if _maybe_float(row.get("query_only_ms_median")) is not None
        ]
        amortized_candidates = [
            row for row in group if _maybe_float(row.get("amortized_q100_u1pct_ms_median")) is not None
        ]
        declared_candidates = [
            row for row in group if _maybe_float(row.get("amortized_declared_q_u_ms_median")) is not None
        ]
        if query_candidates:
            best = min(
                query_candidates,
                key=lambda row: (float(row["query_only_ms_median"]), _mode_order(row["mode"])),
            )
            best_query_only[query_id] = {
                "mode": best["mode"],
                "query_only_ms_median": best["query_only_ms_median"],
            }
        if amortized_candidates:
            best = min(
                amortized_candidates,
                key=lambda row: (float(row["amortized_q100_u1pct_ms_median"]), _mode_order(row["mode"])),
            )
            best_amortized_q100[query_id] = {
                "mode": best["mode"],
                "amortized_q100_u1pct_ms_median": best["amortized_q100_u1pct_ms_median"],
            }
        if declared_candidates:
            best = min(
                declared_candidates,
                key=lambda row: (float(row["amortized_declared_q_u_ms_median"]), _mode_order(row["mode"])),
            )
            best_declared_q_u[query_id] = {
                "mode": best["mode"],
                "amortized_declared_q_u_ms_median": best["amortized_declared_q_u_ms_median"],
            }

    contract_rows = [row for row in e8_rows if row.get("mode") == ADMISSION_FIRST_MODE]
    summary = {
        "artifact_cost_cell_count": len(cost_rows),
        "scenario_count": len({row.get("query_id") for row in e8_rows}),
        "measured_record_count": len(e8_rows),
        "admission_first_wrong_results": sum(1 for row in contract_rows if row.get("status") == "wrong_result"),
        "admission_first_expected_rejects": sum(1 for row in contract_rows if row.get("status") == "expected_reject"),
        "diagnostic_wrong_results": sum(
            1
            for row in e8_rows
            if row.get("mode") != ADMISSION_FIRST_MODE and row.get("status") == "wrong_result"
        ),
        "admission_first_actions": dict(sorted(Counter(str(row.get("artifact_action")) for row in contract_rows).items())),
        "admission_first_choice_reasons": dict(
            sorted(Counter(str(row.get("planner_choice_reason") or "") for row in contract_rows).items())
        ),
        "admission_first_templates": dict(
            sorted(Counter(str(row.get("template_id")) for row in contract_rows).items())
        ),
        "best_query_only_by_scenario": best_query_only,
        "best_amortized_q100_u1pct_by_scenario": best_amortized_q100,
        "best_amortized_declared_q_u_by_scenario": best_declared_q_u,
        "diagnostic_modes_excluded_from_best_tables": [
            "mav-no-version",
            "naive-artifact-only",
            "naive-auth-index-no-scope",
        ],
    }
    return cost_rows, summary


RANKER_AUDIT_CELL_FIELDS = (
    "experiment",
    "stage",
    "dataset_name",
    "dataset_scale",
    "dataset_seed",
    "query_id",
    "policy_id",
    "context_id",
)


def _query_family(query_id: str) -> str:
    if query_id.startswith("JOB_"):
        return "JOB"
    if query_id.startswith("Q"):
        return "TPC-H"
    return "other"


def _candidate_diagnostics(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    def normalized_candidate(
        item: Mapping[str, Any],
        *,
        template_id: str,
        alternative: Any = "",
    ) -> dict[str, Any] | None:
        pg_total_cost = _maybe_float(item.get("pg_total_cost"))
        adjusted_cost = _maybe_float(item.get("adjusted_cost"))
        ranker = str(item.get("ranker") or "")
        cost_model_version = str(item.get("cost_model_version") or "")
        if adjusted_cost is None and ranker == "pg-explain-raw" and cost_model_version == "pg_explain_raw_v1":
            adjusted_cost = pg_total_cost
        if not template_id or pg_total_cost is None or adjusted_cost is None:
            return None
        return {
            "template_id": template_id,
            "template_family": _template_family(template_id),
            "pg_total_cost": pg_total_cost,
            "adjusted_cost": adjusted_cost,
            "ranker": ranker,
            "cost_model_version": cost_model_version,
            "calibration_path": item.get("calibration_path", ""),
            "calibration_hash": item.get("calibration_hash", ""),
            "heuristic_cost": item.get("heuristic_cost", ""),
            "plan_hash": item.get("plan_hash", ""),
            "source": item.get("source", alternative),
        }

    raw = _get(record, "planner.candidate_diagnostics", [])
    candidates: list[dict[str, Any]] = []
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, Mapping):
                continue
            candidate = normalized_candidate(item, template_id=str(item.get("template_id") or ""))
            if candidate is not None:
                candidates.append(candidate)
    if candidates:
        return candidates

    planner_candidates = _get(record, "planner.candidates", [])
    if not isinstance(planner_candidates, list):
        return []
    for item in planner_candidates:
        if not isinstance(item, Mapping):
            continue
        diagnostics = item.get("diagnostics")
        if not isinstance(diagnostics, Mapping):
            continue
        candidate = normalized_candidate(
            diagnostics,
            template_id=str(item.get("template_id") or diagnostics.get("template_id") or ""),
            alternative=item.get("alternative", ""),
        )
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def _ranker_choice_and_ranks(
    candidates: Sequence[Mapping[str, Any]],
    cost_field: str,
) -> tuple[str, str, dict[str, int], dict[str, int]]:
    best_by_template: dict[str, Mapping[str, Any]] = {}
    for candidate in candidates:
        template_id = str(candidate.get("template_id") or "")
        cost = _maybe_float(candidate.get(cost_field))
        if not template_id or cost is None:
            continue
        current = best_by_template.get(template_id)
        if current is None or cost < float(current[cost_field]):
            best_by_template[template_id] = candidate
    ordered = sorted(
        best_by_template.values(),
        key=lambda item: (float(item[cost_field]), str(item.get("template_id") or "")),
    )
    ranks = {
        str(item.get("template_id")): index
        for index, item in enumerate(ordered, start=1)
    }
    equivalence_ranks: dict[str, int] = {}
    for index, item in enumerate(ordered, start=1):
        equivalence_key = str(item.get("plan_hash") or item.get("template_id") or "")
        if equivalence_key and equivalence_key not in equivalence_ranks:
            equivalence_ranks[equivalence_key] = index
    if not ordered:
        return "", "", ranks, equivalence_ranks
    choice = ordered[0]
    return (
        str(choice.get("template_id") or ""),
        str(choice.get("plan_hash") or choice.get("template_id") or ""),
        ranks,
        equivalence_ranks,
    )


def _record_ranker_cell_base(record: Mapping[str, Any]) -> dict[str, Any]:
    query_id = str(_get(record, "query.query_id", ""))
    return {
        "experiment": record.get("experiment", ""),
        "stage": record.get("stage", ""),
        "dataset_name": _get(record, "dataset.name", ""),
        "dataset_scale": _get(record, "dataset.scale", ""),
        "dataset_seed": _get(record, "dataset.seed", ""),
        "query_id": query_id,
        "query_family": _query_family(query_id),
        "policy_id": _get(record, "policy.policy_id", ""),
        "context_id": _get(record, "context.context_id", ""),
    }


def _ranker_cell_key(row: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(str(row.get(field, "")) for field in RANKER_AUDIT_CELL_FIELDS)


def _workspace_calibration_hashes(paths: Iterable[str]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for raw_path in sorted({path for path in paths if path}):
        path = Path(raw_path)
        if path.exists() and path.is_file():
            hashes[raw_path] = _file_sha256(path)
    return hashes


def _calibration_scope_audit(
    *,
    observations: Sequence[Mapping[str, Any]],
    calibration_paths: Sequence[str],
) -> dict[str, Any]:
    texts: dict[str, str] = {}
    for raw_path in calibration_paths:
        path = Path(raw_path)
        if path.exists() and path.is_file():
            texts[raw_path] = path.read_text(encoding="utf-8")
    joined = "\n".join(texts.values())
    query_ids = sorted({str(row.get("query_id") or "") for row in observations if row.get("query_id")})
    query_families = sorted(
        {str(row.get("query_family") or "") for row in observations if row.get("query_family")}
    )
    policy_ids = sorted({str(row.get("policy_id") or "") for row in observations if row.get("policy_id")})
    query_tokens = [*query_ids, *query_families, "query_multipliers:", "workload_multipliers:"]
    policy_tokens = [*policy_ids, "policy_multipliers:"]
    query_specific = any(token and token in joined for token in query_tokens)
    policy_specific = any(token and token in joined for token in policy_tokens)
    return {
        "calibration_scope_available": bool(texts),
        "calibration_query_specific_terms_present": query_specific,
        "calibration_policy_specific_terms_present": policy_specific,
        "observed_query_ids": query_ids,
        "observed_query_families": query_families,
        "observed_policy_ids": policy_ids,
    }


def _heldout_fields_for_split(
    *,
    split_id: str,
    split_role: str,
    calibration_scope: Mapping[str, Any],
) -> dict[str, Any]:
    available = _maybe_bool(calibration_scope.get("calibration_scope_available"))
    query_specific = _maybe_bool(calibration_scope.get("calibration_query_specific_terms_present"))
    policy_specific = _maybe_bool(calibration_scope.get("calibration_policy_specific_terms_present"))
    if available is not True:
        return {
            "heldout_from_direct_calibration": "",
            "heldout_status": "unknown_calibration_file_unavailable",
            "heldout_basis": "calibration file unavailable to audit split membership",
        }
    if split_id.startswith("query_family:"):
        is_heldout = query_specific is not True
        return {
            "heldout_from_direct_calibration": is_heldout,
            "heldout_status": "parameter_heldout" if is_heldout else "not_heldout",
            "heldout_basis": (
                "calibration file has no query_multipliers/workload_multipliers "
                "or observed query-family/query-id tokens"
                if is_heldout
                else "calibration file contains query-family, query-id, or workload terms"
            ),
        }
    if split_id.startswith("policy:"):
        return {
            "heldout_from_direct_calibration": False,
            "heldout_status": "not_heldout_policy_parameterized"
            if policy_specific is True
            else "not_heldout_policy_split",
            "heldout_basis": (
                "calibration file contains policy_multipliers or observed policy ids"
                if policy_specific is True
                else "policy split is reported diagnostically, not as the held-out split"
            ),
        }
    return {
        "heldout_from_direct_calibration": False,
        "heldout_status": split_role,
        "heldout_basis": "aggregate reported cases, not a held-out split",
    }


def _ranker_observation_rows(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for record in records:
        if record.get("run_kind") != "template_oracle_summary":
            continue
        if str(_get(record, "measurement.phase", "measured") or "measured") != "measured":
            continue
        oracle_summary = _json_mapping(record.get("template_oracle_summary"))
        gap = _maybe_float(oracle_summary.get("gap"))
        if gap is None:
            continue
        candidates = _candidate_diagnostics(record)
        if not candidates:
            continue
        raw_choice, raw_choice_equivalence_key, raw_ranks, raw_equivalence_ranks = _ranker_choice_and_ranks(
            candidates,
            "pg_total_cost",
        )
        (
            calibrated_choice,
            calibrated_choice_equivalence_key,
            calibrated_ranks,
            calibrated_equivalence_ranks,
        ) = _ranker_choice_and_ranks(candidates, "adjusted_cost")
        best_template = str(oracle_summary.get("best_template_id") or "")
        best_equivalence_key = str(oracle_summary.get("best_equivalence_key") or best_template)
        contract_choice = str(oracle_summary.get("chosen_template_id") or "")
        chosen_is_measured_best = _maybe_bool(oracle_summary.get("chosen_is_measured_best"))
        first = candidates[0]
        row = {
            "row_type": "ranker_observation",
            **_record_ranker_cell_base(record),
            "run_id": record.get("run_id", ""),
            "manifest_hash": record.get("manifest_hash", ""),
            "measurement_iteration": _get(record, "measurement.iteration", ""),
            "ranker": first.get("ranker", ""),
            "cost_model_version": first.get("cost_model_version", ""),
            "calibration_path": first.get("calibration_path", ""),
            "calibration_hash": first.get("calibration_hash", ""),
            "candidate_count": len(candidates),
            "raw_pg_ranker_choice_template_id": raw_choice,
            "raw_pg_ranker_choice_family": _template_family(raw_choice),
            "calibrated_ranker_choice_template_id": calibrated_choice,
            "calibrated_ranker_choice_equivalence_key": calibrated_choice_equivalence_key,
            "calibrated_ranker_choice_family": _template_family(calibrated_choice),
            "admission_first_chosen_template_id": contract_choice,
            "admission_first_chosen_family": _template_family(contract_choice),
            "measured_best_template_id": best_template,
            "measured_best_equivalence_key": best_equivalence_key,
            "measured_best_family": _template_family(best_template),
            "raw_pg_ranker_choice_equivalence_key": raw_choice_equivalence_key,
            "raw_pg_rank_of_measured_best": raw_equivalence_ranks.get(
                best_equivalence_key,
                raw_ranks.get(best_template, ""),
            ),
            "calibrated_rank_of_measured_best": calibrated_equivalence_ranks.get(
                best_equivalence_key,
                calibrated_ranks.get(best_template, ""),
            ),
            "admission_first_chosen_measured_rank": oracle_summary.get("chosen_measured_rank", ""),
            "raw_pg_matches_measured_best": (
                raw_choice == best_template
                or bool(best_equivalence_key and raw_choice_equivalence_key == best_equivalence_key)
            ),
            "calibrated_matches_measured_best": (
                calibrated_choice == best_template
                or bool(
                    best_equivalence_key
                    and calibrated_choice_equivalence_key == best_equivalence_key
                )
            ),
            "admission_first_matches_measured_best": (
                bool(chosen_is_measured_best)
                if chosen_is_measured_best is not None
                else contract_choice == best_template
            ),
            "calibrated_matches_admission_first": calibrated_choice == contract_choice,
            "oracle_gap": gap,
            "best_execution_ms": oracle_summary.get("best_execution_ms", ""),
            "chosen_execution_ms": oracle_summary.get("chosen_execution_ms", ""),
            "eligible_templates": oracle_summary.get("eligible_templates", ""),
            "eligible_plan_shapes": oracle_summary.get("eligible_plan_shapes", ""),
            "excluded_templates": oracle_summary.get("excluded_templates", ""),
        }
        observations.append(row)
    return observations


def _ranker_split_summary(
    *,
    experiment: str,
    split_id: str,
    split_role: str,
    observations: Sequence[Mapping[str, Any]],
    extra_fields: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    cell_groups: defaultdict[tuple[str, ...], list[Mapping[str, Any]]] = defaultdict(list)
    for row in observations:
        cell_groups[_ranker_cell_key(row)].append(row)
    cell_rows: list[dict[str, Any]] = []
    for group in cell_groups.values():
        first = group[0]
        gap_values = [
            parsed for parsed in (_maybe_float(row.get("oracle_gap")) for row in group)
            if parsed is not None
        ]
        raw_ranks = [
            parsed
            for parsed in (_maybe_float(row.get("raw_pg_rank_of_measured_best")) for row in group)
            if parsed is not None
        ]
        calibrated_ranks = [
            parsed
            for parsed in (_maybe_float(row.get("calibrated_rank_of_measured_best")) for row in group)
            if parsed is not None
        ]
        contract_ranks = [
            parsed
            for parsed in (_maybe_float(row.get("admission_first_chosen_measured_rank")) for row in group)
            if parsed is not None
        ]
        cell_rows.append(
            {
                **{field: first.get(field, "") for field in RANKER_AUDIT_CELL_FIELDS},
                "query_family": first.get("query_family", ""),
                "oracle_gap_median": _median(gap_values) if gap_values else "",
                "raw_pg_rank_of_measured_best_median": _median(raw_ranks) if raw_ranks else "",
                "calibrated_rank_of_measured_best_median": _median(calibrated_ranks)
                if calibrated_ranks
                else "",
                "admission_first_chosen_measured_rank_median": _median(contract_ranks)
                if contract_ranks
                else "",
                "raw_pg_matches_measured_best": (
                    sum(1 for row in group if _maybe_bool(row.get("raw_pg_matches_measured_best")) is True)
                    >= len(group) / 2
                ),
                "calibrated_matches_measured_best": (
                    sum(
                        1
                        for row in group
                        if _maybe_bool(row.get("calibrated_matches_measured_best")) is True
                    )
                    >= len(group) / 2
                ),
                "admission_first_matches_measured_best": (
                    sum(
                        1
                        for row in group
                        if _maybe_bool(row.get("admission_first_matches_measured_best")) is True
                    )
                    >= len(group) / 2
                ),
                "calibrated_matches_admission_first": (
                    sum(
                        1
                        for row in group
                        if _maybe_bool(row.get("calibrated_matches_admission_first")) is True
                    )
                    >= len(group) / 2
                ),
                "raw_pg_ranker_choice_template_id": _dominant_string(
                    group,
                    "raw_pg_ranker_choice_template_id",
                ),
                "calibrated_ranker_choice_template_id": _dominant_string(
                    group,
                    "calibrated_ranker_choice_template_id",
                ),
                "admission_first_chosen_template_id": _dominant_string(
                    group,
                    "admission_first_chosen_template_id",
                ),
                "measured_best_template_id": _dominant_string(group, "measured_best_template_id"),
                "observation_count": len(group),
            }
        )

    gaps = [
        parsed
        for parsed in (_maybe_float(row.get("oracle_gap_median")) for row in cell_rows)
        if parsed is not None
    ]
    raw_rank_values = [
        parsed
        for parsed in (_maybe_float(row.get("raw_pg_rank_of_measured_best_median")) for row in cell_rows)
        if parsed is not None
    ]
    calibrated_rank_values = [
        parsed
        for parsed in (
            _maybe_float(row.get("calibrated_rank_of_measured_best_median"))
            for row in cell_rows
        )
        if parsed is not None
    ]
    contract_rank_values = [
        parsed
        for parsed in (
            _maybe_float(row.get("admission_first_chosen_measured_rank_median"))
            for row in cell_rows
        )
        if parsed is not None
    ]
    cell_count = len(cell_rows)

    def rate(count: int, denominator: int = cell_count) -> float | str:
        return (count / denominator) if denominator else ""

    raw_top1 = sum(1 for row in cell_rows if row["raw_pg_matches_measured_best"])
    calibrated_top1 = sum(1 for row in cell_rows if row["calibrated_matches_measured_best"])
    contract_top1 = sum(1 for row in cell_rows if row["admission_first_matches_measured_best"])
    raw_top3 = sum(1 for value in raw_rank_values if value <= 3)
    calibrated_top3 = sum(1 for value in calibrated_rank_values if value <= 3)
    contract_top3 = sum(1 for value in contract_rank_values if value <= 3)
    row = {
        "row_type": "split_summary",
        "experiment": experiment,
        "split_id": split_id,
        "split_role": split_role,
        "manifest_hashes": ";".join(_manifest_hashes_from_rows(observations)),
        "cell_count": cell_count,
        "observation_count": sum(int(row["observation_count"]) for row in cell_rows),
        "median_oracle_gap": _median(gaps) if gaps else "",
        "p90_oracle_gap": _percentile(sorted(gaps), 0.9) if gaps else "",
        "max_oracle_gap": max(gaps) if gaps else "",
        "raw_pg_top1_measured_best_count": raw_top1,
        "raw_pg_top1_measured_best_rate": rate(raw_top1),
        "raw_pg_top3_measured_best_count": raw_top3,
        "raw_pg_top3_measured_best_rate": rate(raw_top3, len(raw_rank_values)),
        "calibrated_top1_measured_best_count": calibrated_top1,
        "calibrated_top1_measured_best_rate": rate(calibrated_top1),
        "calibrated_top3_measured_best_count": calibrated_top3,
        "calibrated_top3_measured_best_rate": rate(calibrated_top3, len(calibrated_rank_values)),
        "admission_first_top1_measured_best_count": contract_top1,
        "admission_first_top1_measured_best_rate": rate(contract_top1),
        "admission_first_top3_measured_rank_count": contract_top3,
        "admission_first_top3_measured_rank_rate": rate(contract_top3, len(contract_rank_values)),
        "calibrated_admission_first_match_count": sum(
            1 for row in cell_rows if row["calibrated_matches_admission_first"]
        ),
        "calibrated_admission_first_match_rate": rate(
            sum(1 for row in cell_rows if row["calibrated_matches_admission_first"])
        ),
    }
    if extra_fields:
        row.update(extra_fields)
    return row


def _ranker_cell_summary_rows(observations: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    groups: defaultdict[tuple[str, ...], list[Mapping[str, Any]]] = defaultdict(list)
    for row in observations:
        groups[_ranker_cell_key(row)].append(row)
    rows: list[dict[str, Any]] = []
    for group in groups.values():
        first = group[0]
        summary = _ranker_split_summary(
            experiment=str(first.get("experiment") or ""),
            split_id="single_cell",
            split_role="cell",
            observations=group,
        )
        row = {
            "row_type": "ranker_cell_summary",
            **{field: first.get(field, "") for field in RANKER_AUDIT_CELL_FIELDS},
            "query_family": first.get("query_family", ""),
            "raw_pg_ranker_choice_template_id": _dominant_string(
                group,
                "raw_pg_ranker_choice_template_id",
            ),
            "calibrated_ranker_choice_template_id": _dominant_string(
                group,
                "calibrated_ranker_choice_template_id",
            ),
            "admission_first_chosen_template_id": _dominant_string(
                group,
                "admission_first_chosen_template_id",
            ),
            "measured_best_template_id": _dominant_string(group, "measured_best_template_id"),
            "ranker_diagnosis": _oracle_miss_diagnosis(
                _dominant_string(group, "admission_first_chosen_template_id"),
                _dominant_string(group, "measured_best_template_id"),
                str(first.get("query_id", "")),
                str(first.get("policy_id", "")),
            ),
            "claim_action": _oracle_claim_action(float(summary["median_oracle_gap"] or 1.0)),
            **{
                key: value
                for key, value in summary.items()
                if key
                not in {
                    "row_type",
                    "experiment",
                    "split_id",
                    "split_role",
                }
            },
        }
        rows.append(row)
    return sorted(rows, key=lambda row: tuple(str(row.get(field, "")) for field in RANKER_AUDIT_CELL_FIELDS))


def _ranker_audit_analysis(
    records: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    observations = _ranker_observation_rows(records)
    experiment_values = sorted(
        {
            str(row.get("experiment") or "")
            for row in observations
            if str(row.get("experiment") or "")
        }
        or {
            str(record.get("experiment") or "")
            for record in records
            if str(record.get("experiment") or "")
        }
    )
    audit_experiment = experiment_values[0] if len(experiment_values) == 1 else "mixed"
    all_cells_split_id = f"all_{audit_experiment.lower()}_cells" if audit_experiment else "all_cells"
    calibration_paths = sorted({str(row.get("calibration_path") or "") for row in observations if row.get("calibration_path")})
    calibration_hashes = sorted({str(row.get("calibration_hash") or "") for row in observations if row.get("calibration_hash")})
    cost_model_versions = sorted({str(row.get("cost_model_version") or "") for row in observations if row.get("cost_model_version")})
    rankers = sorted({str(row.get("ranker") or "") for row in observations if row.get("ranker")})
    workspace_hashes = _workspace_calibration_hashes(calibration_paths)
    workspace_matches_raw = all(
        workspace_hashes.get(path) in set(calibration_hashes)
        for path in calibration_paths
        if path in workspace_hashes
    ) if calibration_hashes else None
    calibration_scope = _calibration_scope_audit(
        observations=observations,
        calibration_paths=calibration_paths,
    )

    source: list[dict[str, Any]] = []
    for path in calibration_paths or [""]:
        source.append(
            {
                "row_type": "calibration_provenance",
                "experiment": audit_experiment,
                "calibration_path": path,
                "calibration_hash": ",".join(calibration_hashes),
                "workspace_calibration_hash": workspace_hashes.get(path, ""),
                "workspace_hash_matches_raw": workspace_matches_raw
                if workspace_matches_raw is not None
                else "",
                "manifest_hashes": ";".join(_manifest_hashes_from_rows(observations)),
                "rankers": ",".join(rankers),
                "cost_model_versions": ",".join(cost_model_versions),
                "observation_count": len(observations),
                "calibration_scope_available": calibration_scope["calibration_scope_available"],
                "calibration_query_specific_terms_present": calibration_scope[
                    "calibration_query_specific_terms_present"
                ],
                "calibration_policy_specific_terms_present": calibration_scope[
                    "calibration_policy_specific_terms_present"
                ],
                "note": (
                    "Observed hashes come from raw records; workspace hash is "
                    "diagnostic and identifies the code used for the reported run."
                ),
            }
        )

    cell_rows = _ranker_cell_summary_rows(observations)
    split_rows = [
        _ranker_split_summary(
            experiment=audit_experiment,
            split_id=all_cells_split_id,
            split_role="reported_cells",
            observations=observations,
            extra_fields=_heldout_fields_for_split(
                split_id=all_cells_split_id,
                split_role="reported_cells",
                calibration_scope=calibration_scope,
            ),
        )
    ] if observations else []
    for family in sorted({str(row.get("query_family") or "") for row in observations if row.get("query_family")}):
        split_id = f"query_family:{family}"
        split_rows.append(
            _ranker_split_summary(
                experiment=audit_experiment,
                split_id=split_id,
                split_role="query_family_audit",
                observations=[row for row in observations if row.get("query_family") == family],
                extra_fields=_heldout_fields_for_split(
                    split_id=split_id,
                    split_role="query_family_audit",
                    calibration_scope=calibration_scope,
                ),
            )
        )
    for policy_id in sorted({str(row.get("policy_id") or "") for row in observations if row.get("policy_id")}):
        split_id = f"policy:{policy_id}"
        split_rows.append(
            _ranker_split_summary(
                experiment=audit_experiment,
                split_id=split_id,
                split_role="policy_config_audit",
                observations=[row for row in observations if row.get("policy_id") == policy_id],
                extra_fields=_heldout_fields_for_split(
                    split_id=split_id,
                    split_role="policy_config_audit",
                    calibration_scope=calibration_scope,
                ),
            )
        )

    source.extend(split_rows)
    heldout_rows = [
        {**row, "row_type": "heldout_audit"}
        for row in split_rows
        if _maybe_bool(row.get("heldout_from_direct_calibration")) is True
    ]
    source.extend(heldout_rows)
    source.extend(cell_rows)
    source.extend(observations)

    worst_cells = sorted(
        [
            row for row in cell_rows
            if _maybe_float(row.get("median_oracle_gap")) is not None
            and float(row["median_oracle_gap"]) > 1.0
        ],
        key=lambda row: (
            float(row["median_oracle_gap"]),
            float(row.get("max_oracle_gap") or row["median_oracle_gap"]),
            str(row.get("query_id", "")),
            str(row.get("policy_id", "")),
        ),
        reverse=True,
    )
    for rank, row in enumerate(worst_cells[:5], start=1):
        source.append({**row, "row_type": "worst_miss", "worst_rank": rank})

    all_summary = next((row for row in split_rows if row["split_id"] == all_cells_split_id), {})
    summary = {
        "ranker_audit_observation_count": len(observations),
        "ranker_audit_cell_count": len(cell_rows),
        "rankers": rankers,
        "cost_model_versions": cost_model_versions,
        "calibration_paths": calibration_paths,
        "calibration_hashes": calibration_hashes,
        "workspace_calibration_hashes": workspace_hashes,
        "workspace_hash_matches_raw": workspace_matches_raw,
        "calibration_scope": calibration_scope,
        "heldout_summaries": {
            str(row["split_id"]): {
                key: value
                for key, value in row.items()
                if key not in {"row_type", "experiment", "split_id", "split_role"}
            }
            for row in heldout_rows
        },
        "split_summaries": {
            str(row["split_id"]): {
                key: value
                for key, value in row.items()
                if key not in {"row_type", "experiment", "split_id", "split_role"}
            }
            for row in split_rows
        },
        "overall": {
            key: value
            for key, value in all_summary.items()
            if key not in {"row_type", "experiment", "split_id", "split_role"}
        },
        "worst_miss_count": len(worst_cells[:5]),
    }
    return source, summary


def _median(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[midpoint]
    return (ordered[midpoint - 1] + ordered[midpoint]) / 2.0


def _percentile(sorted_values: Sequence[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = q * (len(sorted_values) - 1)
    lower = int(math.floor(rank))
    upper = int(math.ceil(rank))
    if lower == upper:
        return sorted_values[lower]
    weight = rank - lower
    return sorted_values[lower] * (1.0 - weight) + sorted_values[upper] * weight


def _median_order_stat_ci(values: Sequence[float], alpha: float = 0.05) -> tuple[float, float]:
    if not values:
        return (0.0, 0.0)
    ordered = sorted(values)
    n = len(ordered)
    if n == 1 or ordered[0] == ordered[-1]:
        return (ordered[0], ordered[-1])

    tail = alpha / 2.0
    if n <= 200:
        # Exact binomial order-statistic interval for the sample median.
        cumulative = 0.0
        probability = 0.5**n
        k = 0
        while k < n // 2 and cumulative + probability <= tail:
            cumulative += probability
            k += 1
            probability *= (n - k + 1) / k
        lower_index = max(0, k - 1)
    else:
        z_975 = 1.959963984540054
        lower_index = max(0, int(math.floor((n - z_975 * math.sqrt(n)) / 2.0)))
    upper_index = min(n - 1, n - lower_index - 1)
    return (ordered[lower_index], ordered[upper_index])


def _maybe_float(value: Any) -> float | None:
    if value == "" or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _split_manifest_hashes(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    if not text:
        return []
    for separator in (";", ",", "|"):
        text = text.replace(separator, "\n")
    return [item.strip() for item in text.splitlines() if item.strip()]


def _manifest_hashes_from_rows(rows: Sequence[Mapping[str, Any]]) -> list[str]:
    manifest_hashes: set[str] = set()
    for row in rows:
        manifest_hashes.update(_split_manifest_hashes(row.get("manifest_hash")))
        manifest_hashes.update(_split_manifest_hashes(row.get("manifest_hashes")))
    return sorted(manifest_hashes)


def _cell_key_fields(rows: Sequence[Mapping[str, Any]]) -> list[str]:
    param_fields = sorted({key for row in rows for key in row if key.startswith("param_")})
    return list(BASE_CELL_KEY_FIELDS) + [field for field in param_fields if field not in BASE_CELL_KEY_FIELDS]


def _cell_stats(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    key_fields = _cell_key_fields(rows)
    groups: defaultdict[tuple[str, ...], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[tuple(_cell_key_value(row, field) for field in key_fields)].append(row)

    cell_rows: list[dict[str, Any]] = []
    mode_index = key_fields.index("mode")

    def group_order(item: tuple[tuple[str, ...], list[Mapping[str, Any]]]) -> tuple[Any, ...]:
        key = item[0]
        return (*key[:mode_index], _mode_order(key[mode_index]), *key[mode_index + 1 :])

    for key, group in sorted(groups.items(), key=group_order):
        measured_group = [
            item for item in group if str(item.get("measurement_phase") or "measured") == "measured"
        ]
        warmup_group = [item for item in group if str(item.get("measurement_phase")) == "warmup"]
# BEGIN PHASE_B2A_E8COST_CELL_POPULATIONS
        is_e8cost_group = all(
            item.get("experiment") == "E8"
            and item.get("stage") == "artifact_cost_update_rate"
            for item in group
        )
        numeric_measured_group = measured_group
        if is_e8cost_group:
            if any(
                item.get("e8cost_evidence_class") not in E8COST_EVIDENCE_CLASSES
                for item in group
            ):
                raise ValueError(
                    "E8-COST cell contains an unclassified evidence row"
                )
            numeric_measured_group = [
                item
                for item in measured_group
                if item.get("e8cost_evidence_class")
                == E8COST_RESULT_EXECUTION
            ]
# END PHASE_B2A_E8COST_CELL_POPULATIONS
        row: dict[str, Any] = {field: value for field, value in zip(key_fields, key)}
        row["sample_count"] = len(measured_group)
        row["warmup_count"] = len(warmup_group)
        row["total_record_count"] = len(group)
        row["manifest_hashes"] = ";".join(_manifest_hashes_from_rows(group))
        row["required_warmup_repetitions"] = REQUIRED_WARMUP_REPETITIONS
        row["required_measured_repetitions"] = REQUIRED_MEASURED_REPETITIONS
        row["protocol_status"] = (
            "ok"
            if (
                len(measured_group) >= REQUIRED_MEASURED_REPETITIONS
                and len(warmup_group) >= REQUIRED_WARMUP_REPETITIONS
            )
            else "insufficient_repetitions"
        )
        row["status_counts"] = dict(sorted(Counter(str(item.get("status")) for item in group).items()))
# BEGIN PHASE_B2A_E8COST_CELL_CLASS_COUNTS
        if is_e8cost_group:
            class_counts = Counter(
                str(item.get("e8cost_evidence_class")) for item in group
            )
            measured_class_counts = Counter(
                str(item.get("e8cost_evidence_class"))
                for item in measured_group
            )
            warmup_class_counts = Counter(
                str(item.get("e8cost_evidence_class"))
                for item in warmup_group
            )
            observed_classes = sorted(class_counts)
            if len(observed_classes) != 1:
                raise ValueError(
                    "E8-COST cell mixes accounting, gate, and result populations"
                )
            row["e8cost_evidence_class"] = observed_classes[0]
            row["e8cost_evidence_class_counts"] = dict(
                sorted(class_counts.items())
            )
            executed_pass = sum(
                1
                for item in numeric_measured_group
                if item.get("status") == "pass"
            )
            executed_wrong = sum(
                1
                for item in numeric_measured_group
                if item.get("status") == "wrong_result"
            )
            executed_denominator = len(numeric_measured_group)
            row.update(
                {
                    "accounting_projection_record_count": class_counts.get(
                        E8COST_ACCOUNTING_PROJECTION, 0
                    ),
                    "accounting_projection_measured_count": (
                        measured_class_counts.get(
                            E8COST_ACCOUNTING_PROJECTION, 0
                        )
                    ),
                    "accounting_projection_warmup_count": (
                        warmup_class_counts.get(
                            E8COST_ACCOUNTING_PROJECTION, 0
                        )
                    ),
                    "gate_reject_record_count": class_counts.get(
                        E8COST_GATE_REJECT, 0
                    ),
                    "gate_reject_measured_count": measured_class_counts.get(
                        E8COST_GATE_REJECT, 0
                    ),
                    "gate_reject_warmup_count": warmup_class_counts.get(
                        E8COST_GATE_REJECT, 0
                    ),
                    "result_execution_record_count": class_counts.get(
                        E8COST_RESULT_EXECUTION, 0
                    ),
                    "result_execution_measured_count": (
                        measured_class_counts.get(E8COST_RESULT_EXECUTION, 0)
                    ),
                    "result_execution_warmup_count": warmup_class_counts.get(
                        E8COST_RESULT_EXECUTION, 0
                    ),
                    "executed_pass_count": executed_pass,
                    "executed_wrong_result_count": executed_wrong,
                    "executed_result_denominator": executed_denominator,
                    "executed_wrong_result_rate": (
                        executed_wrong / executed_denominator
                        if executed_denominator
                        else None
                    ),
                }
            )
# END PHASE_B2A_E8COST_CELL_CLASS_COUNTS
        row["observed_template_ids"] = sorted(
            {str(item.get("template_id")) for item in group if item.get("template_id")}
        )
        row["observed_alternatives"] = sorted(
            {str(item.get("alternative")) for item in group if item.get("alternative")}
        )
        for field in STABLE_CELL_FIELDS:
            values = sorted({str(item.get(field)) for item in group if item.get(field)})
            if len(values) == 1:
                row[field] = values[0]
        for field in MULTI_VALUE_CELL_FIELDS:
            values = sorted({str(item.get(field)) for item in group if item.get(field)})
            if values:
                row[f"{field}es"] = ";".join(values)
# BEGIN PHASE_B2A_E8COST_SCOPED_LINT_COMPATIBILITY
        _seed_key = "|".join(key)
# END PHASE_B2A_E8COST_SCOPED_LINT_COMPATIBILITY
        for field in NUMERIC_STAT_FIELDS:
            values = [
                parsed
# BEGIN PHASE_B2A_E8COST_RESULT_ONLY_NUMERIC_STATS
                for parsed in (
                    _maybe_float(item.get(field))
                    for item in numeric_measured_group
                )
# END PHASE_B2A_E8COST_RESULT_ONLY_NUMERIC_STATS
                if parsed is not None
            ]
            if not values:
                continue
            low, high = _median_order_stat_ci(values)
            row[f"{field}_median"] = _median(values)
            row[f"{field}_ci95_low"] = low
            row[f"{field}_ci95_high"] = high
# BEGIN PHASE_B2A_E8COST_ACCOUNTING_CELL_STATS
        if is_e8cost_group:
            for field in E8COST_ACCOUNTING_NUMERIC_STAT_FIELDS:
                values = [
                    parsed
                    for parsed in (
                        _maybe_float(item.get(field))
                        for item in measured_group
                    )
                    if parsed is not None
                ]
                if not values:
                    continue
                low, high = _median_order_stat_ci(values)
                row[f"{field}_median"] = _median(values)
                row[f"{field}_ci95_low"] = low
                row[f"{field}_ci95_high"] = high
# END PHASE_B2A_E8COST_ACCOUNTING_CELL_STATS
        cell_rows.append(row)
    return cell_rows


E3_RUNNER_SQL_CANONICALIZATION_METHOD = (
    "pooled_measured_samples_by_exact_runner_sql_hash_v1"
)


def _annotate_e3_runner_sql_canonical_latencies(
    raw_rows: Sequence[Mapping[str, Any]],
    cell_rows: Sequence[dict[str, Any]],
) -> None:
    """Share measured samples among modes that execute byte-identical SQL.

    E3 exposes several policy-enforcement labels that can resolve to the exact
    same runner SQL in a cell.  Treating those labels as independent draws and
    then selecting their minimum median gives the duplicated SQL more chances
    to win.  This reporting-only annotation pools all measured samples with an
    exact ``runner_sql_hash`` and assigns the pooled median/CI to every member
    mode.  Original mode rows and their mode-local statistics remain intact.

    Missing or unstable hashes are deliberately kept mode-local; they are
    never merged by label or by an approximate SQL comparison.
    """

    samples_by_group: defaultdict[tuple[str, str, str], list[float]] = defaultdict(list)
    modes_by_group: defaultdict[tuple[str, str, str], set[str]] = defaultdict(set)
    for row in raw_rows:
        mode = normalize_mode_id(str(row.get("mode") or ""))
        runner_hash = str(row.get("runner_sql_hash") or "")
        if (
            row.get("run_kind") != "normal_mode"
            or mode not in E3_POLICY_ENFORCEMENT_MODES
            or _row_status(row) != "pass"
            or str(row.get("measurement_phase") or "measured") != "measured"
            or not runner_hash
        ):
            continue
        total_ms = _maybe_float(row.get("total_ms"))
        if total_ms is None or total_ms <= 0.0:
            continue
        key = (
            str(row.get("query_id") or ""),
            str(row.get("param_policy_config_id") or ""),
            runner_hash,
        )
        samples_by_group[key].append(total_ms)
        modes_by_group[key].add(mode)

    for row in cell_rows:
        mode = normalize_mode_id(str(row.get("mode") or ""))
        if (
            row.get("run_kind") != "normal_mode"
            or mode not in E3_POLICY_ENFORCEMENT_MODES
        ):
            continue
        mode_median = _metric(row, "total_ms")
        mode_low, mode_high = _metric_ci(row, "total_ms")
        runner_hash = str(row.get("runner_sql_hash") or "")
        key = (
            str(row.get("query_id") or ""),
            str(row.get("param_policy_config_id") or ""),
            runner_hash,
        )
        pooled = samples_by_group.get(key) if runner_hash else None
        if pooled:
            canonical_median = _median(pooled)
            canonical_low, canonical_high = _median_order_stat_ci(pooled)
            equivalent_modes = sorted(modes_by_group[key], key=_mode_order)
            canonical_sample_count = len(pooled)
            method = E3_RUNNER_SQL_CANONICALIZATION_METHOD
            group_id = runner_hash
        else:
            canonical_median = mode_median
            canonical_low, canonical_high = mode_low, mode_high
            equivalent_modes = [mode]
            canonical_sample_count = int(_float(row.get("sample_count"), 0.0))
            method = "mode_local_runner_sql_hash_missing_or_unstable"
            group_id = "mode-local:{}".format(mode)

        row.update(
            {
                "mode_total_ms_median": mode_median,
                "mode_total_ms_ci95_low": mode_low,
                "mode_total_ms_ci95_high": mode_high,
                "runner_sql_canonical_group_id": group_id,
                "runner_sql_canonicalization_method": method,
                "runner_sql_equivalent_modes": equivalent_modes,
                "runner_sql_equivalent_mode_count": len(equivalent_modes),
                "runner_sql_canonical_sample_count": canonical_sample_count,
                "runner_sql_canonical_total_ms_median": canonical_median,
                "runner_sql_canonical_total_ms_ci95_low": canonical_low,
                "runner_sql_canonical_total_ms_ci95_high": canonical_high,
            }
        )


def _e3_canonical_latency(row: Mapping[str, Any]) -> float:
    value = _maybe_float(row.get("runner_sql_canonical_total_ms_median"))
    return value if value is not None and value > 0.0 else _metric(row, "total_ms")


def _e3_canonical_latency_ci(row: Mapping[str, Any]) -> tuple[float, float]:
    value = _e3_canonical_latency(row)
    low = _maybe_float(row.get("runner_sql_canonical_total_ms_ci95_low"))
    high = _maybe_float(row.get("runner_sql_canonical_total_ms_ci95_high"))
    return (
        low if low is not None and low > 0.0 else value,
        high if high is not None and high > 0.0 else value,
    )


def _cell_key_value(row: Mapping[str, Any], field: str) -> str:
    if field == "template_id" and str(row.get("mode")) in ADAPTIVE_TEMPLATE_CELL_MODES:
        return "adaptive_choice"
    return _as_scalar(row.get(field))


def summarize_experiment(experiment: str, input_dir: Path, output_dir: Path) -> SummaryResult:
    records = _load_raw_records(input_dir, experiment)
    rows = [_flatten_record(record) for record in records]
    cell_rows = _cell_stats(rows)
    if experiment == "E3":
        _annotate_e3_runner_sql_canonical_latencies(rows, cell_rows)
    manifest_hashes = sorted({str(row["manifest_hash"]) for row in rows})
    script_hash = _script_version_hash()

    runs_csv = output_dir / "runs.csv"
    cell_stats_csv = output_dir / "cell_stats.csv"
    template_oracle_csv = output_dir / "template_oracle_analysis.csv"
    template_oracle_summary_json = output_dir / "template_oracle_summary.json"
    artifact_cost_csv = output_dir / "artifact_cost_analysis.csv"
    artifact_cost_summary_json = output_dir / "artifact_cost_summary.json"
    ranker_audit_csv = output_dir / "ranker_audit_analysis.csv"
    ranker_audit_summary_json = output_dir / "ranker_audit_summary.json"
    e3_loss_table_csv = output_dir / "e3_loss_table.csv"
    e3_loss_table_summary_json = output_dir / "e3_loss_table_summary.json"
    summary_json = output_dir / "summary.json"
    manifest_hashes_txt = output_dir / "manifest_hashes.txt"
    script_version_txt = output_dir / "script_version.txt"
    insufficient_cells = sum(1 for row in cell_rows if row["protocol_status"] != "ok")
    oracle_rows, oracle_summary = _template_oracle_analysis(rows)
    artifact_cost_rows, artifact_cost_summary = _artifact_cost_analysis(rows)
    ranker_audit_rows, ranker_audit_summary = _ranker_audit_analysis(records)
    e3_loss_table_rows, e3_loss_table_summary = (
        _e3_loss_table(cell_rows) if experiment == "E3" else ([], {})
    )

    _write_csv(runs_csv, rows)
    _write_csv(cell_stats_csv, cell_rows)
    _write_csv(template_oracle_csv, oracle_rows)
    _write_json(template_oracle_summary_json, oracle_summary)
    _write_csv(artifact_cost_csv, artifact_cost_rows)
    _write_json(artifact_cost_summary_json, artifact_cost_summary)
    _write_csv(ranker_audit_csv, ranker_audit_rows)
    _write_json(ranker_audit_summary_json, ranker_audit_summary)
    if experiment == "E3":
        _write_csv(e3_loss_table_csv, e3_loss_table_rows)
        _write_json(e3_loss_table_summary_json, e3_loss_table_summary)
    _write_json(
        summary_json,
        {
            "experiment": experiment,
            "record_count": len(rows),
            "input_dir": str(input_dir),
            "runs_csv": str(runs_csv),
            "cell_stats_csv": str(cell_stats_csv),
            "template_oracle_analysis_csv": str(template_oracle_csv),
            "template_oracle_summary_json": str(template_oracle_summary_json),
            "template_oracle_analysis": oracle_summary,
            "artifact_cost_analysis_csv": str(artifact_cost_csv),
            "artifact_cost_summary_json": str(artifact_cost_summary_json),
            "artifact_cost_analysis": artifact_cost_summary,
            "ranker_audit_analysis_csv": str(ranker_audit_csv),
            "ranker_audit_summary_json": str(ranker_audit_summary_json),
            "ranker_audit_analysis": ranker_audit_summary,
            "e3_loss_table_csv": str(e3_loss_table_csv) if experiment == "E3" else None,
            "e3_loss_table_summary_json": str(e3_loss_table_summary_json) if experiment == "E3" else None,
            "e3_loss_table_summary": e3_loss_table_summary if experiment == "E3" else {},
            "manifest_hashes": manifest_hashes,
            "git_commits": sorted({str(row["git_commit"]) for row in rows}),
            "status_counts": dict(sorted(Counter(str(row["status"]) for row in rows).items())),
            "mode_counts": dict(sorted(Counter(str(row["mode"]) for row in rows).items())),
            "run_kind_counts": dict(sorted(Counter(str(row["run_kind"]) for row in rows).items())),
            "measurement_protocol": {
                "required_warmup_repetitions": REQUIRED_WARMUP_REPETITIONS,
                "required_measured_repetitions": REQUIRED_MEASURED_REPETITIONS,
                "cell_count": len(cell_rows),
                "cells_meeting_required_repetitions": len(cell_rows) - insufficient_cells,
                "insufficient_repetition_cells": insufficient_cells,
                "status": "ok" if insufficient_cells == 0 else "insufficient_repetitions",
                "note": (
                    "Median and 95% nonparametric median CI are computed when repeated measured "
                    "records exist for the same experiment cell. Current reduced/probe "
                    "runs may remain below the VLDB protocol of 5 warmup + 10 measured "
                    "repetitions."
                ),
            },
            "script_version_hash": script_hash,
        },
    )
    _write_lines(manifest_hashes_txt, manifest_hashes)
    _write_lines(script_version_txt, [script_hash])
    return SummaryResult(
        experiment=experiment,
        record_count=len(rows),
        output_dir=output_dir,
        runs_csv=runs_csv,
        cell_stats_csv=cell_stats_csv,
        summary_json=summary_json,
        manifest_hashes_txt=manifest_hashes_txt,
        script_version_txt=script_version_txt,
        template_oracle_csv=template_oracle_csv,
        template_oracle_summary_json=template_oracle_summary_json,
        artifact_cost_csv=artifact_cost_csv,
        artifact_cost_summary_json=artifact_cost_summary_json,
        ranker_audit_csv=ranker_audit_csv,
        ranker_audit_summary_json=ranker_audit_summary_json,
    )


def _summary_csv_paths(input_path: Path, figure: str) -> list[Path]:
    wanted = set(FIGURE_EXPERIMENTS[figure])
    source_file = FIGURE_SOURCE_FILES.get(figure, "runs.csv")
    if (input_path / source_file).exists():
        paths = [input_path / source_file]
        parent = input_path.parent
        for directory in FIGURE_SUMMARY_DIRECTORIES.get(figure, FIGURE_EXPERIMENTS[figure]):
            sibling = parent / directory / source_file
            if sibling.exists() and sibling not in paths:
                paths.append(sibling)
        return paths
    paths = []
    for directory in FIGURE_SUMMARY_DIRECTORIES.get(figure, FIGURE_EXPERIMENTS[figure]):
        path = input_path / directory / source_file
        if path.exists():
            paths.append(path)
    if paths:
        return paths
    if source_file != "runs.csv":
        for experiment in wanted:
            path = input_path / experiment / source_file
            if path.exists():
                paths.append(path)
        if paths:
            return paths
    return sorted(input_path.glob(f"*/{source_file}"))


def _load_summary_rows(input_path: Path, figure: str) -> list[dict[str, str]]:
    wanted = set(FIGURE_EXPERIMENTS[figure])
    rows: list[dict[str, str]] = []
    for path in _summary_csv_paths(input_path, figure):
        for row in _read_csv(path):
            if row.get("experiment") in wanted:
                rows.append(row)
    if not rows:
        raise ValueError(
            f"no summarized rows for {figure}; expected experiments {sorted(wanted)} under {input_path}"
        )
    return rows


def _geom_mean(values: Sequence[float]) -> float:
    positive = [value for value in values if value > 0]
    if not positive:
        return 0.0
    return math.exp(sum(math.log(value) for value in positive) / len(positive))


def _status_bar_rows(rows: Sequence[Mapping[str, str]]) -> list[dict[str, Any]]:
    counts = Counter(_row_status(row) for row in rows)
    return [_bar(status, float(count)) for status, count in sorted(counts.items())]


def _source_fig2(rows: Sequence[dict[str, str]]) -> tuple[list[dict[str, Any]], list[str], list[tuple[str, float]]]:
    source = [
        {
            "experiment": row["experiment"],
            "query_id": row["query_id"],
            "mode": row["mode"],
            "status": row["status"],
            "known_invalid_accepted": row["known_invalid_accepted"],
            "known_valid_rejected": row["known_valid_rejected"],
            "unauthorized_observations": row["unauthorized_observations"],
        }
        for row in rows
        if row["run_kind"] == "normal_mode"
    ]
    contract_rows = [row for row in source if row["mode"] == ADMISSION_FIRST_MODE]
    wrong = sum(1 for row in contract_rows if row["status"] == "wrong_result")
    unsafe = sum(_int(row["unauthorized_observations"]) for row in contract_rows)
    diagnostic_failures = sum(
        1
        for row in source
        if row["mode"] != ADMISSION_FIRST_MODE and row["status"] in {"wrong_result", "unsafe_observation"}
    )
    lines = [
        f"AdmissionFirst records: {len(contract_rows)}",
        f"AdmissionFirst wrong-result records: {wrong}",
        f"AdmissionFirst unauthorized observations: {unsafe}",
        f"Diagnostic wrong/unsafe records: {diagnostic_failures}",
    ]
    return source, lines, _status_bar_rows(source)


def _fig3_witness_audit_rows(source_rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_region_keys: set[tuple[str, str, str]] = set()
    witness_matches: defaultdict[str, dict[str, set[str]]] = defaultdict(lambda: {"families": set(), "grid_points": set()})

    summary_rows = [row for row in source_rows if row.get("run_kind") == "template_oracle_summary"]
    for row in summary_rows:
        grid_point = str(row.get("param_grid_point", ""))
        template_ids = [str(item) for item in _json_list(row.get("observed_template_ids")) if str(item)]
        for template_id in sorted(template_ids):
            family = _template_family(template_id)
            spec = FIG3_FAMILY_WITNESS_DIRECTIONS.get(family)
            if spec is None:
                continue
            key = (grid_point, template_id, family)
            if key in seen_region_keys:
                continue
            seen_region_keys.add(key)
            witnesses = list(spec["theory_witnesses"])
            for witness in witnesses:
                witness_matches[witness]["families"].add(family)
                witness_matches[witness]["grid_points"].add(grid_point)
            rows.append(
                {
                    "row_type": "region_winner",
                    "param_grid_point": grid_point,
                    "param_s_q": row.get("param_s_q", ""),
                    "param_s_auth": row.get("param_s_auth", ""),
                    "artifact_availability": row.get("artifact_availability", ""),
                    "observed_template_id": template_id,
                    "observed_family": family,
                    "theory_witnesses": witnesses,
                    "theory_witness": "",
                    "witness_role": spec["witness_role"],
                    "direction": spec["direction"],
                    "evidence_anchor": "Fig3 measured-best region; Fig5 W1-W5 controlled-regret source",
                    "consistency_status": "consistent",
                }
            )

    for theory_witness, spec in FIG3_T5_WITNESS_COVERAGE.items():
        matches = witness_matches[theory_witness]
        rows.append(
            {
                "row_type": "witness_coverage",
                "param_grid_point": "",
                "param_s_q": "",
                "param_s_auth": "",
                "artifact_availability": "",
                "observed_template_id": "",
                "observed_family": "",
                "theory_witnesses": "",
                "theory_witness": theory_witness,
                "witness_role": "T5-witness-coverage",
                "direction": spec["expected_best_direction"],
                "fixed_mode_under_test": spec["fixed_mode_under_test"],
                "expected_best_direction": spec["expected_best_direction"],
                "e5_witness_id": spec["e5_witness_id"],
                "e2_matching_families": sorted(matches["families"]),
                "e2_matching_grid_points": sorted(matches["grid_points"]),
                "evidence_anchor": "Fig3 region winners plus Fig5 fixed-regret witness",
                "consistency_status": "covered" if matches["grid_points"] else "missing",
            }
        )
    return rows


def _source_fig3(rows: Sequence[dict[str, str]]) -> tuple[list[dict[str, Any]], list[str], list[tuple[str, float]]]:
    source: list[dict[str, Any]] = []
    for row in rows:
        if row["run_kind"] not in {"normal_mode", "template_candidate", "template_oracle_summary"}:
            continue
        total_ms = _metric(row, "total_ms")
        total_low, total_high = _metric_ci(row, "total_ms")
        status = _row_status(row)
        source.append(
            {
                "experiment": row.get("experiment", ""),
                "stage": row.get("stage", ""),
                "dataset_name": row.get("dataset_name", ""),
                "dataset_scale": row.get("dataset_scale", ""),
                "dataset_seed": row.get("dataset_seed", ""),
                "query_id": row.get("query_id", ""),
                "policy_id": row.get("policy_id", ""),
                "context_id": row.get("context_id", ""),
                "param_grid_point": row.get("param_grid_point", ""),
                "param_policy_cost": row.get("param_policy_cost", ""),
                "param_s_auth": row.get("param_s_auth", ""),
                "param_s_q": row.get("param_s_q", ""),
                "artifact_availability": row.get("param_artifact_availability", ""),
                "mode": row["mode"],
                "run_kind": row["run_kind"],
                "template_id": row["template_id"],
                "evaluation_role": row.get("evaluation_role", ""),
                "observed_template_ids": row.get("observed_template_ids", ""),
                "observed_alternatives": row.get("observed_alternatives", ""),
                "applicability": row.get("template_applicability_status", ""),
                "total_ms_median": total_ms,
                "total_ms_ci95_low": total_low,
                "total_ms_ci95_high": total_high,
                "execution_ms_median": _metric(row, "execution_ms"),
                "oracle_gap_median": row.get("oracle_gap_median", ""),
                "oracle_best_execution_ms_median": row.get("oracle_best_execution_ms_median", ""),
                "oracle_chosen_execution_ms_median": row.get("oracle_chosen_execution_ms_median", ""),
                "oracle_eligible_templates_median": row.get("oracle_eligible_templates_median", ""),
                "sample_count": row.get("sample_count", ""),
                "warmup_count": row.get("warmup_count", ""),
                "protocol_status": row.get("protocol_status", ""),
                "status": status,
            }
        )
    normal = [row for row in source if row["run_kind"] == "normal_mode" and row["status"] == "pass"]
    unavailable = sum(
        1
        for row in source
        if row["applicability"] == "artifact_unavailable" or row["status"] == "expected_reject"
    )
    best_by_availability: dict[str, tuple[str, float]] = {}
    for row in normal:
        key = row["artifact_availability"]
        value = _float(row["total_ms_median"])
        if (
            key not in best_by_availability
            or (value, _mode_order(row["mode"]))
            < (best_by_availability[key][1], _mode_order(best_by_availability[key][0]))
        ):
            best_by_availability[key] = (row["mode"], value)
    lines = [f"Artifact-unavailable template cases: {unavailable}"]
    lines.extend(
        f"{key or 'unspecified'} best normal mode: {mode} ({value:.3f} ms)"
        for key, (mode, value) in sorted(best_by_availability.items())
    )
    bars = [
        _bar(
            f"{row['artifact_availability']}:{_paper_label(row['mode'])}",
            _float(row["total_ms_median"]),
            _float(row["total_ms_ci95_low"]),
            _float(row["total_ms_ci95_high"]),
        )
        for row in normal
    ]
    return source, lines, bars


def _fig4_honesty_audit_rows(source_rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    pass_rows = [
        row
        for row in source_rows
        if row.get("status") == "pass"
        and str(row.get("mode")) in E3_POLICY_ENFORCEMENT_MODES
        and _float(row.get("total_ms_median")) > 0.0
    ]
    grouped: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in pass_rows:
        grouped[(str(row.get("query_id", "")), str(row.get("policy_config_id", "")))].append(row)

    rows: list[dict[str, Any]] = []
    cdf_points: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    plan_choice_counts: Counter[tuple[str, str]] = Counter()
    plan_choice_templates: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    heatmap_slowdowns: list[float] = []
    winner_counts: Counter[str] = Counter()

    fixed_mode_exclusions = {
        ADMISSION_FIRST_MODE,
        "local-greedy",
        "native-pg-rls",
        "native-pg-rls-physical-design",
    }
    for (query_id, policy_config_id), cell_rows in sorted(grouped.items()):
        by_mode = {str(row.get("mode", "")): row for row in cell_rows}
        contract = by_mode.get(ADMISSION_FIRST_MODE)
        if contract is None:
            continue
        contract_ms = _float(contract.get("total_ms_median"))
        if contract_ms <= 0.0:
            continue

        best = min(
            cell_rows,
            key=lambda row: (
                _float(row.get("total_ms_median"), math.inf),
                _mode_order(row.get("mode")),
            ),
        )
        best_ms = _float(best.get("total_ms_median"))
        slowdown = contract_ms / best_ms if best_ms > 0.0 else 0.0
        outcome = "admission_first_win_or_tie" if str(best.get("mode", "")) == ADMISSION_FIRST_MODE or slowdown <= 1.0 + E3_LOSS_TIE_TOLERANCE else "admission_first_loss"
        bucket = _e3_winner_bucket(str(best.get("mode", "")) if outcome == "admission_first_loss" else ADMISSION_FIRST_MODE)
        winner_counts[bucket] += 1
        heatmap_slowdowns.append(slowdown)

        fixed_rows = [
            row
            for row in cell_rows
            if str(row.get("mode", "")) not in fixed_mode_exclusions
        ]
        best_fixed = min(
            fixed_rows,
            key=lambda row: (
                _float(row.get("total_ms_median"), math.inf),
                _mode_order(row.get("mode")),
            ),
        ) if fixed_rows else {}
        native_pd = by_mode.get("native-pg-rls-physical-design", {})
        local = by_mode.get("local-greedy", {})

        rows.append(
            {
                "row_type": "heatmap_cell",
                "query_id": query_id,
                "policy_config_id": policy_config_id,
                "fastest_policy_enforcement_mode": best.get("mode", ""),
                "best_winner_bucket": bucket,
                "best_total_ms_median": best_ms,
                "admission_first_total_ms_median": contract_ms,
                "admission_first_slowdown_vs_fastest": slowdown,
                "native_pg_rls_physical_design_total_ms_median": _float(native_pd.get("total_ms_median")),
                "best_single_fixed_mode": best_fixed.get("mode", ""),
                "best_single_fixed_total_ms_median": _float(best_fixed.get("total_ms_median")),
                "local_greedy_total_ms_median": _float(local.get("total_ms_median")),
                "sample_count": contract.get("sample_count", ""),
                "warmup_count": contract.get("warmup_count", ""),
                "protocol_status": contract.get("protocol_status", ""),
            }
        )

        comparisons = {
            "native-pg-rls-physical-design": native_pd,
            "best-single-fixed-mode": best_fixed,
            "local-greedy": local,
        }
        for comparison, comparator in comparisons.items():
            comparator_ms = _float(comparator.get("total_ms_median"))
            if comparator_ms <= 0.0:
                continue
            cdf_points[comparison].append(
                {
                    "row_type": "cdf_point",
                    "comparison": comparison,
                    "query_id": query_id,
                    "policy_config_id": policy_config_id,
                    "comparator_mode": comparator.get("mode", comparison),
                    "comparator_total_ms_median": comparator_ms,
                    "admission_first_total_ms_median": contract_ms,
                    "admission_first_speedup_vs_comparator": comparator_ms / contract_ms,
                    "admission_first_slowdown_vs_comparator": contract_ms / comparator_ms,
                }
            )

        observed_templates = [str(item) for item in _json_list(contract.get("observed_template_ids")) if str(item)]
        chosen_template = observed_templates[0] if observed_templates else str(contract.get("template_id", ""))
        chosen_family = _template_family(chosen_template)
        plan_key = (policy_config_id, chosen_family)
        plan_choice_counts[plan_key] += 1
        if chosen_template:
            plan_choice_templates[plan_key].add(chosen_template)

    for comparison, points in sorted(cdf_points.items()):
        ordered = sorted(points, key=lambda row: float(row["admission_first_speedup_vs_comparator"]))
        for rank, row in enumerate(ordered, start=1):
            row["cdf_rank"] = rank
            row["cdf_fraction"] = rank / len(ordered)
            rows.append(row)
        values = [float(row["admission_first_speedup_vs_comparator"]) for row in ordered]
        rows.append(
            {
                "row_type": "cdf_summary",
                "comparison": comparison,
                "cell_count": len(values),
                "speedup_median": _median(values),
                "speedup_p10": _percentile(sorted(values), 0.1),
                "speedup_p90": _percentile(sorted(values), 0.9),
                "speedup_min": min(values) if values else "",
                "speedup_max": max(values) if values else "",
            }
        )

    for (policy_config_id, chosen_family), count in sorted(plan_choice_counts.items()):
        rows.append(
            {
                "row_type": "plan_choice_stack",
                "policy_config_id": policy_config_id,
                "chosen_template_id": json.dumps(
                    sorted(plan_choice_templates[(policy_config_id, chosen_family)]),
                    separators=(",", ":"),
                ),
                "chosen_family": chosen_family,
                "cell_count": count,
            }
        )

    rows.append(
        {
            "row_type": "summary",
            "heatmap_cell_count": len(heatmap_slowdowns),
            "cdf_comparisons": list(FIG4_CDF_COMPARISONS),
            "plan_choice_cell_count": sum(plan_choice_counts.values()),
            "winner_bucket_counts": dict(sorted(winner_counts.items())),
            "admission_first_slowdown_median": _median(heatmap_slowdowns),
            "admission_first_slowdown_p90": _percentile(sorted(heatmap_slowdowns), 0.9),
            "admission_first_slowdown_max": max(heatmap_slowdowns) if heatmap_slowdowns else "",
        }
    )
    return rows


def _source_fig4(rows: Sequence[dict[str, str]]) -> tuple[list[dict[str, Any]], list[str], list[tuple[str, float]]]:
    pass_rows = [row for row in rows if row["run_kind"] == "normal_mode" and _row_status(row) == "pass"]
    baseline_by_query: dict[tuple[str, str], tuple[float, float, float]] = {}
    for row in pass_rows:
        if row["mode"] == "native-pg-rls":
            value = _e3_canonical_latency(row)
            low, high = _e3_canonical_latency_ci(row)
            baseline_by_query[(row["query_id"], row.get("param_policy_config_id", ""))] = (value, low, high)
    source: list[dict[str, Any]] = []
    speedups_by_mode: defaultdict[str, list[float]] = defaultdict(list)
    for row in pass_rows:
        key = (row["query_id"], row.get("param_policy_config_id", ""))
        baseline, baseline_low, baseline_high = baseline_by_query.get(key, (0.0, 0.0, 0.0))
        mode_total_ms = _metric(row, "total_ms")
        total_ms = _e3_canonical_latency(row)
        total_low, total_high = _e3_canonical_latency_ci(row)
        speedup = baseline / total_ms if baseline and total_ms else 0.0
        speedup_low = baseline_low / total_high if baseline_low and total_high else speedup
        speedup_high = baseline_high / total_low if baseline_high and total_low else speedup
        source.append(
            {
                "query_id": row["query_id"],
                "policy_config_id": row.get("param_policy_config_id", ""),
                "mode": row["mode"],
                "template_id": row.get("template_id", ""),
                "observed_template_ids": row.get("observed_template_ids", ""),
                "observed_alternatives": row.get("observed_alternatives", ""),
                "runner_sql_hash": row.get("runner_sql_hash", ""),
                "runner_sql_canonicalization_method": row.get(
                    "runner_sql_canonicalization_method", ""
                ),
                "runner_sql_equivalent_modes": row.get(
                    "runner_sql_equivalent_modes", ""
                ),
                "runner_sql_equivalent_mode_count": row.get(
                    "runner_sql_equivalent_mode_count", ""
                ),
                "runner_sql_canonical_sample_count": row.get(
                    "runner_sql_canonical_sample_count", ""
                ),
                "mode_total_ms_median": mode_total_ms,
                "total_ms_median": total_ms,
                "total_ms_ci95_low": total_low,
                "total_ms_ci95_high": total_high,
                "speedup_vs_native_pg_rls": speedup,
                "speedup_ci95_low": speedup_low,
                "speedup_ci95_high": speedup_high,
                "sample_count": row.get("sample_count", ""),
                "warmup_count": row.get("warmup_count", ""),
                "protocol_status": row.get("protocol_status", ""),
                "status": _row_status(row),
            }
        )
        if speedup:
            speedups_by_mode[row["mode"]].append(speedup)
    presentation_rows = _fig4_honesty_audit_rows(source)
    heatmap_rows = [row for row in presentation_rows if row.get("row_type") == "heatmap_cell"]
    cdf_summary_rows = [row for row in presentation_rows if row.get("row_type") == "cdf_summary"]
    plan_choice_rows = [row for row in presentation_rows if row.get("row_type") == "plan_choice_stack"]
    summary_row = next((row for row in presentation_rows if row.get("row_type") == "summary"), {})
    lines = [
        f"{_paper_label(mode)} geomean speedup: {_geom_mean(values):.3f}x"
        for mode, values in sorted(speedups_by_mode.items(), key=lambda item: _mode_order(item[0]))
    ]
    if summary_row:
        lines.append(
            "E3 honesty audit: "
            f"{summary_row.get('heatmap_cell_count', 0)} heatmap cells, "
            f"slowdown med/p90/max="
            f"{_float(summary_row.get('admission_first_slowdown_median')):.3f}/"
            f"{_float(summary_row.get('admission_first_slowdown_p90')):.3f}/"
            f"{_float(summary_row.get('admission_first_slowdown_max')):.3f}"
        )
    lines.extend(
        f"CDF {row['comparison']}: AF speedup median/p90="
        f"{_float(row.get('speedup_median')):.3f}/{_float(row.get('speedup_p90')):.3f}"
        for row in cdf_summary_rows
    )
    bars = [
        _bar(
            f"heatmap:{row['query_id']}/{row['policy_config_id']}",
            _float(row["admission_first_slowdown_vs_fastest"]),
        )
        for row in heatmap_rows
    ]
    bars.extend(
        _bar(f"cdf:{row['comparison']}:median", _float(row.get("speedup_median")))
        for row in cdf_summary_rows
    )
    bars.extend(
        _bar(
            f"plan:{row['policy_config_id']}:{row['chosen_family']}",
            _float(row.get("cell_count")),
        )
        for row in plan_choice_rows
    )
    return source, lines, bars


def _e3_winner_bucket(mode: str) -> str:
    if mode == ADMISSION_FIRST_MODE:
        return ADMISSION_FIRST_MODE
    if mode.startswith("native-pg-rls"):
        return "native-pg-rls"
    if mode == "local-greedy":
        return "local-greedy"
    return "fixed-mode"


def _e3_loss_table(cell_rows: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    cell_rows = [
        {**row, "mode": normalize_mode_id(str(row.get("mode") or ""))}
        for row in cell_rows
    ]
    pass_rows = [
        row
        for row in cell_rows
        if row.get("run_kind") == "normal_mode"
        and str(row.get("mode")) in E3_POLICY_ENFORCEMENT_MODES
        and _row_status(row) == "pass"
        and _metric(row, "total_ms") > 0.0
    ]
    grouped: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in pass_rows:
        grouped[(str(row.get("query_id", "")), str(row.get("param_policy_config_id", "")))].append(row)

    table_rows: list[dict[str, Any]] = []
    slowdowns: list[float] = []
    winner_counts: Counter[str] = Counter()
    outcome_counts: Counter[str] = Counter()
    total_mode_rows = 0
    total_canonical_groups = 0
    shared_runner_sql_groups = 0
    missing_or_unstable_hash_mode_rows = 0
    for (query_id, policy_config_id), rows in sorted(grouped.items()):
        by_mode = {str(row.get("mode")): row for row in rows}
        contract_row = by_mode.get(ADMISSION_FIRST_MODE)
        if contract_row is None:
            continue
        contract_ms = _e3_canonical_latency(contract_row)
        if contract_ms <= 0.0:
            continue

        canonical_groups: defaultdict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for row in rows:
            runner_hash = str(row.get("runner_sql_hash") or "")
            group_id = str(row.get("runner_sql_canonical_group_id") or "")
            if not group_id:
                # Never merge missing/unstable hashes by mode name alone.
                group_id = runner_hash or "mode-local:{}".format(row.get("mode", ""))
            canonical_groups[group_id].append(row)
            if not runner_hash:
                missing_or_unstable_hash_mode_rows += 1

        def representative(group_rows: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
            contract = next(
                (row for row in group_rows if str(row.get("mode")) == ADMISSION_FIRST_MODE),
                None,
            )
            if contract is not None:
                return contract
            return min(group_rows, key=lambda row: _mode_order(row.get("mode")))

        group_candidates: list[tuple[float, Mapping[str, Any], list[Mapping[str, Any]]]] = []
        for group_rows in canonical_groups.values():
            canonical_ms = _e3_canonical_latency(group_rows[0])
            group_candidates.append((canonical_ms, representative(group_rows), group_rows))
        best_ms, best_row, best_group_rows = min(
            group_candidates,
            key=lambda item: (item[0], _mode_order(item[1].get("mode"))),
        )
        best_mode = str(best_row.get("mode"))
        best_modes = sorted(
            (str(row.get("mode") or "") for row in best_group_rows),
            key=_mode_order,
        )
        if best_ms <= 0.0:
            continue
        slowdown = contract_ms / best_ms
        if ADMISSION_FIRST_MODE in best_modes or slowdown <= 1.0 + E3_LOSS_TIE_TOLERANCE:
            outcome = "admission_first_win_or_tie"
        else:
            outcome = "admission_first_loss"
        bucket = _e3_winner_bucket(best_mode if outcome == "admission_first_loss" else ADMISSION_FIRST_MODE)
        winner_counts[bucket] += 1
        outcome_counts[outcome] += 1
        slowdowns.append(slowdown)
        total_mode_rows += len(rows)
        total_canonical_groups += len(canonical_groups)
        cell_shared_groups = sum(
            1 for group_rows in canonical_groups.values() if len(group_rows) > 1
        )
        shared_runner_sql_groups += cell_shared_groups
        table_rows.append(
            {
                "query_id": query_id,
                "policy_config_id": policy_config_id,
                "fastest_policy_enforcement_mode": best_mode,
                "fastest_policy_enforcement_modes": best_modes,
                "best_winner_bucket": bucket,
                "best_total_ms_median": best_ms,
                "best_runner_sql_hash": best_row.get("runner_sql_hash", ""),
                "best_canonical_sample_count": best_row.get(
                    "runner_sql_canonical_sample_count", best_row.get("sample_count", "")
                ),
                "admission_first_total_ms_median": contract_ms,
                "admission_first_mode_total_ms_median": _metric(contract_row, "total_ms"),
                "admission_first_runner_sql_hash": contract_row.get("runner_sql_hash", ""),
                "admission_first_canonical_sample_count": contract_row.get(
                    "runner_sql_canonical_sample_count", contract_row.get("sample_count", "")
                ),
                "admission_first_slowdown_vs_fastest": slowdown,
                "admission_first_outcome": outcome,
                "native_pg_rls_total_ms_median": _e3_canonical_latency(
                    by_mode.get("native-pg-rls", {})
                ),
                "native_pg_rls_mode_total_ms_median": _metric(
                    by_mode.get("native-pg-rls", {}), "total_ms"
                ),
                "native_pg_rls_physical_design_total_ms_median": _e3_canonical_latency(
                    by_mode.get("native-pg-rls-physical-design", {})
                ),
                "native_pg_rls_physical_design_mode_total_ms_median": _metric(
                    by_mode.get("native-pg-rls-physical-design", {}),
                    "total_ms",
                ),
                "security_barrier_total_ms_median": _e3_canonical_latency(
                    by_mode.get("security-barrier", {})
                ),
                "security_barrier_mode_total_ms_median": _metric(
                    by_mode.get("security-barrier", {}), "total_ms"
                ),
                "local_greedy_total_ms_median": _e3_canonical_latency(
                    by_mode.get("local-greedy", {})
                ),
                "local_greedy_mode_total_ms_median": _metric(
                    by_mode.get("local-greedy", {}), "total_ms"
                ),
                "policy_enforcement_mode_count": len(rows),
                "canonical_runner_sql_group_count": len(canonical_groups),
                "shared_runner_sql_group_count": cell_shared_groups,
                "runner_sql_canonicalization_method": (
                    E3_RUNNER_SQL_CANONICALIZATION_METHOD
                ),
                "sample_count": contract_row.get("sample_count", ""),
                "warmup_count": contract_row.get("warmup_count", ""),
                "protocol_status": contract_row.get("protocol_status", ""),
                "manifest_hashes": contract_row.get("manifest_hashes", ""),
            }
        )

    summary: dict[str, Any] = {
        "cell_count": len(table_rows),
        "tie_tolerance": E3_LOSS_TIE_TOLERANCE,
        "winner_bucket_counts": dict(sorted(winner_counts.items())),
        "admission_first_outcome_counts": dict(sorted(outcome_counts.items())),
        "runner_sql_canonicalization": {
            "method": E3_RUNNER_SQL_CANONICALIZATION_METHOD,
            "equivalence_key": "exact runner_sql_hash within query/policy case",
            "latency_estimator": "median of pooled measured samples",
            "mode_rows_retained": total_mode_rows,
            "canonical_runner_sql_groups": total_canonical_groups,
            "shared_runner_sql_groups": shared_runner_sql_groups,
            "duplicate_mode_draws_removed_from_fastest_selection": (
                total_mode_rows - total_canonical_groups
            ),
            "missing_or_unstable_hash_mode_rows_kept_local": (
                missing_or_unstable_hash_mode_rows
            ),
            "selector_changed": False,
        },
    }
    if slowdowns:
        sorted_slowdowns = sorted(slowdowns)
        p90_index = max(0, math.ceil(0.9 * len(sorted_slowdowns)) - 1)
        worst = max(table_rows, key=lambda row: _float(row["admission_first_slowdown_vs_fastest"]))
        summary.update(
            {
                "admission_first_slowdown_median": _median(slowdowns),
                "admission_first_slowdown_p90": sorted_slowdowns[p90_index],
                "admission_first_slowdown_max": sorted_slowdowns[-1],
                "worst_admission_first_loss": {
                    "query_id": worst["query_id"],
                    "policy_config_id": worst["policy_config_id"],
                    "fastest_policy_enforcement_mode": worst["fastest_policy_enforcement_mode"],
                    "admission_first_slowdown_vs_fastest": worst["admission_first_slowdown_vs_fastest"],
                },
            }
        )
    return table_rows, summary


def _source_fig5(rows: Sequence[dict[str, str]]) -> tuple[list[dict[str, Any]], list[str], list[tuple[str, float]]]:
    def witness_key(row: Mapping[str, str]) -> tuple[str, str, str, str, str]:
        return (
            row.get("param_witness_id", ""),
            row.get("param_N", ""),
            row.get("param_artifact_config", ""),
            row.get("param_amortization_q", ""),
            row.get("param_amortization_u", ""),
        )

    summaries = {
        witness_key(row): (
            _metric(row, "e5_effective_latency_ms") or _metric(row, "total_ms"),
            *_metric_ci(row, "e5_effective_latency_ms"),
        )
        for row in rows
        if row["run_kind"] == "template_oracle_summary" and _row_status(row) == "pass"
    }
    source: list[dict[str, Any]] = []
    regret_by_mode: defaultdict[str, list[float]] = defaultdict(list)
    for row in rows:
        if row["run_kind"] != "normal_mode":
            continue
        witness = row.get("param_witness_id", "")
        oracle_ms, oracle_low, oracle_high = summaries.get(witness_key(row), (0.0, 0.0, 0.0))
        query_ms = _metric(row, "total_ms")
        query_low, query_high = _metric_ci(row, "total_ms")
        effective_ms = _metric(row, "e5_effective_latency_ms") or query_ms
        effective_low, effective_high = _metric_ci(row, "e5_effective_latency_ms")
        if not effective_low and query_low:
            effective_low = query_low
        if not effective_high and query_high:
            effective_high = query_high
        regret = effective_ms / oracle_ms if oracle_ms and effective_ms else 0.0
        regret_low = effective_low / oracle_high if effective_low and oracle_high else regret
        regret_high = effective_high / oracle_low if effective_high and oracle_low else regret
        witness_kind = row.get("param_witness_kind", "")
        source.append(
            {
                "witness_id": witness,
                "witness_kind": witness_kind,
                "theory_witness": row.get("param_theory_witness", "") or row.get("e5_theory_witness", ""),
                "fixed_mode_under_test": row.get("param_fixed_mode_under_test", "") or row.get("e5_fixed_mode_under_test", ""),
                "expected_best_mode": row.get("param_expected_best_mode", "") or row.get("e5_expected_best_mode", ""),
                "N": row.get("param_N", ""),
                "artifact_config": row.get("param_artifact_config", ""),
                "mode": row["mode"],
                "template_id": row["template_id"],
                "observed_template_ids": row.get("observed_template_ids", ""),
                "query_only_ms_median": query_ms,
                "query_only_ms_ci95_low": query_low,
                "query_only_ms_ci95_high": query_high,
                "effective_ms_median": effective_ms,
                "effective_ms_ci95_low": effective_low,
                "effective_ms_ci95_high": effective_high,
                "oracle_effective_ms_median": oracle_ms,
                "oracle_effective_ms_ci95_low": oracle_low,
                "oracle_effective_ms_ci95_high": oracle_high,
                "template_regret": regret,
                "template_regret_ci95_low": regret_low,
                "template_regret_ci95_high": regret_high,
                "sample_count": row.get("sample_count", ""),
                "warmup_count": row.get("warmup_count", ""),
                "protocol_status": row.get("protocol_status", ""),
                "status": _row_status(row),
            }
        )
        if regret and witness_kind != "positive_control":
            regret_by_mode[row["mode"]].append(regret)
    lines = [
        f"{_paper_label(mode)} geomean regret: {_geom_mean(values):.3f}x"
        for mode, values in sorted(regret_by_mode.items(), key=lambda item: _mode_order(item[0]))
    ]
    bars = [
        _bar(
            f"{row['witness_id']}:{_paper_label(row['mode'])}",
            _float(row["template_regret"]),
            _float(row["template_regret_ci95_low"]),
            _float(row["template_regret_ci95_high"]),
        )
        for row in source
        if row["template_regret"]
    ]
    return source, lines, bars


def _source_fig6(rows: Sequence[dict[str, str]]) -> tuple[list[dict[str, Any]], list[str], list[tuple[str, float]]]:
    normal = [row for row in rows if row["run_kind"] == "normal_mode"]
    contract_ms_by_pair_parent = {
        (row.get("param_pair_id", ""), row.get("param_parent", "")): _metric(row, "total_ms")
        for row in normal
        if row.get("mode") == ADMISSION_FIRST_MODE and _row_status(row) == "pass"
    }
    source = []
    for row in normal:
        total_ms = _metric(row, "total_ms")
        total_low, total_high = _metric_ci(row, "total_ms")
        observed_templates = _json_list(row.get("observed_template_ids"))
        if not observed_templates and row.get("template_id"):
            observed_templates = [row["template_id"]]
        contract_ms = contract_ms_by_pair_parent.get((row.get("param_pair_id", ""), row.get("param_parent", "")), 0.0)
        regret_vs_contract = total_ms / contract_ms if contract_ms and total_ms else 0.0
        source.append(
            {
                "pair_id": row.get("param_pair_id", ""),
                "query_id": row["query_id"],
                "parent": row.get("param_parent", ""),
                "parent_continuation_id": row.get("param_parent", ""),
                "mode": row["mode"],
                "template_id": row["template_id"],
                "observed_template_ids": observed_templates,
                "alternative": row.get("alternative", ""),
                "observed_alternatives": row.get("observed_alternatives", ""),
                "total_ms_median": total_ms,
                "total_ms_ci95_low": total_low,
                "total_ms_ci95_high": total_high,
                "admission_first_total_ms_median": contract_ms,
                "regret_vs_contract": regret_vs_contract,
                "sample_count": row.get("sample_count", ""),
                "warmup_count": row.get("warmup_count", ""),
                "protocol_status": row.get("protocol_status", ""),
                "local_feature_vector": row.get("planner_local_feature_vector", ""),
                "parent_requirement_vector": row.get("planner_parent_requirement_vector", ""),
                "result_hash": row.get("result_hash", "") or row.get("result_hashes", ""),
                "static_plan_hash": row.get("static_plan_hash", "") or row.get("static_plan_hashes", ""),
                "emitted_sql_hash": row.get("emitted_sql_hash", "") or row.get("emitted_sql_hashes", ""),
                "result_hashes": row.get("result_hashes", ""),
                "static_plan_hashes": row.get("static_plan_hashes", ""),
                "emitted_sql_hashes": row.get("emitted_sql_hashes", ""),
                "status": _row_status(row),
            }
        )
    by_pair_mode: defaultdict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in source:
        by_pair_mode[(row["pair_id"], row["mode"])].append(row)
    differing = 0
    identical_local = 0
    for (_pair, _mode), group in by_pair_mode.items():
        if len(group) < 2:
            continue
        local_vectors = {item["local_feature_vector"] for item in group}
        choices = {
            template_id
            for item in group
            for template_id in (item["observed_template_ids"] or [item["template_id"]])
        }
        if len(local_vectors) == 1:
            identical_local += 1
        if len(choices) > 1:
            differing += 1
    lines = [
        f"Pair/mode groups with identical local vectors: {identical_local}",
        f"Pair/mode groups with different selected templates: {differing}",
    ]
    bars = [
        _bar(
            f"{row['pair_id']}:{_paper_label(row['mode'])}",
            _float(row["total_ms_median"]),
            _float(row["total_ms_ci95_low"]),
            _float(row["total_ms_ci95_high"]),
        )
        for row in source
    ]
    return source, lines, bars


def _source_fig7(rows: Sequence[dict[str, str]]) -> tuple[list[dict[str, Any]], list[str], list[tuple[str, float]]]:
    def component_for(row: Mapping[str, str]) -> str:
        if row.get("param_component"):
            return str(row["param_component"])
        query_id = row.get("query_id", "")
        for marker, component in (
            ("domain", "NoDomain"),
            ("residual", "NoResidual"),
            ("freshness", "NoFreshness"),
            ("context", "NoContextScope"),
            ("rid", "NoRIDMatProps"),
            ("safety", "NoSafetyLevel"),
            ("branch", "NoBranchLineage"),
            ("phys", "NoPhysProps"),
        ):
            if marker in query_id:
                return component
        return "unknown"

    normal = [row for row in rows if row["run_kind"] == "normal_mode"]
    source = [
        {
            "component": component_for(row),
            "case_id": row["query_id"],
            "mode": row["mode"],
            "status": _row_status(row),
            "status_counts": row.get("status_counts", ""),
            "sample_count": row.get("sample_count", ""),
            "warmup_count": row.get("warmup_count", ""),
            "protocol_status": row.get("protocol_status", ""),
            "artifact_validation_status": row.get("artifact_validation_status", ""),
            "artifact_action": row.get("artifact_action", ""),
            "unauthorized_observations": row.get("unauthorized_observations", ""),
            "known_invalid_accepted": row.get("known_invalid_accepted", ""),
        }
        for row in normal
    ]
    ablations = [row for row in source if row["mode"] != ADMISSION_FIRST_MODE]
    wrong = sum(1 for row in ablations if row["status"] == "wrong_result")
    unsafe = sum(1 for row in ablations if row["status"] == "unsafe_observation")
    conservative = sum(1 for row in ablations if row["mode"] == "no-phys-props" and row["status"] == "pass")
    lines = [
        f"Ablation wrong-result cases: {wrong}",
        f"Ablation unsafe-observation cases: {unsafe}",
        f"Safe conservative/performance cases: {conservative}",
    ]
    bars = _status_bar_rows(source)
    return source, lines, bars


def _source_fig8(rows: Sequence[dict[str, str]]) -> tuple[list[dict[str, Any]], list[str], list[tuple[str, float]]]:
    normal = [row for row in rows if row["run_kind"] == "normal_mode" and _row_status(row) == "pass"]
    source = []
    for row in normal:
        planning_ms = _metric(row, "planning_ms")
        planning_low, planning_high = _metric_ci(row, "planning_ms")
        execution_ms = _metric(row, "execution_ms")
        total_ms = _metric(row, "total_ms")
        planning_total_ratio = _metric(row, "planning_total_ratio")
        generated_templates = _metric(row, "generated_templates")
        rejected_templates = _metric(row, "rejected_templates")
        dominance_pruned = _metric(row, "dominance_pruned")
        pruning_ratio = _metric(row, "pruning_ratio")
        source.append(
            {
                "tier": row.get("param_tier", ""),
                "protected_occurrences": row.get("param_protected_occurrences", ""),
                "alternatives_per_occurrence": row.get("param_alternatives_per_occurrence", ""),
                "joins": row.get("param_joins", ""),
                "residuals": row.get("param_residuals", ""),
                "rows_per_relation": row.get("param_rows_per_relation", ""),
                "mode": row["mode"],
                "planning_ms_median": planning_ms,
                "planning_ms_ci95_low": planning_low,
                "planning_ms_ci95_high": planning_high,
                "execution_ms_median": execution_ms,
                "execution_ms_ci95_low": _metric_ci(row, "execution_ms")[0],
                "execution_ms_ci95_high": _metric_ci(row, "execution_ms")[1],
                "total_ms_median": total_ms,
                "total_ms_ci95_low": _metric_ci(row, "total_ms")[0],
                "total_ms_ci95_high": _metric_ci(row, "total_ms")[1],
                "planning_total_ratio": planning_total_ratio,
                "planning_total_ratio_ci95_low": _metric_ci(row, "planning_total_ratio")[0],
                "planning_total_ratio_ci95_high": _metric_ci(row, "planning_total_ratio")[1],
                "postgres_planning_ms_median": _metric(row, "postgres_planning_ms"),
                "generated_templates_median": generated_templates,
                "rejected_templates_median": rejected_templates,
                "dominance_pruned_median": dominance_pruned,
                "costed_templates_median": _metric(row, "costed_templates"),
                "dominance_checks_median": _metric(row, "dominance_checks"),
                "memo_groups_median": _metric(row, "memo_groups"),
                "peak_memory_bytes_median": _metric(row, "peak_memory_bytes"),
                "serialized_state_bytes_median": _metric(row, "serialized_state_bytes"),
                "sample_count": row.get("sample_count", ""),
                "warmup_count": row.get("warmup_count", ""),
                "protocol_status": row.get("protocol_status", ""),
                "pruning_ratio": pruning_ratio,
                "planner_level": row.get("planner_level", ""),
                "local_feature_vector": row.get("planner_local_feature_vector", ""),
                "parent_requirement_vector": row.get("planner_parent_requirement_vector", ""),
                "result_hash": row.get("result_hash", "") or row.get("result_hashes", ""),
                "static_plan_hash": row.get("static_plan_hash", "") or row.get("static_plan_hashes", ""),
                "emitted_sql_hash": row.get("emitted_sql_hash", "") or row.get("emitted_sql_hashes", ""),
            }
        )
    max_planning = max((_float(row["planning_ms_median"]) for row in source), default=0.0)
    max_ratio = max((_float(row["planning_total_ratio"]) for row in source), default=0.0)
    max_memory_kib = max((_float(row["peak_memory_bytes_median"]) / 1024.0 for row in source), default=0.0)
    max_generated = max((_int(row["generated_templates_median"]) for row in source), default=0)
    lines = [
        f"Max planning time: {max_planning:.3f} ms",
        f"Max planning/total ratio: {max_ratio:.3f}",
        f"Max median planner memory: {max_memory_kib:.1f} KiB",
        f"Max generated templates: {max_generated}",
    ]
    bars = [
        _bar(
            f"occ{row['protected_occurrences']}:{_paper_label(row['mode'])}",
            _float(row["planning_ms_median"]),
            _float(row["planning_ms_ci95_low"]),
            _float(row["planning_ms_ci95_high"]),
        )
        for row in source
    ]
    return source, lines, bars


ORACLE_AUDIT_CELL_FIELDS = (
    "experiment",
    "stage",
    "dataset_name",
    "dataset_scale",
    "dataset_seed",
    "query_id",
    "policy_id",
    "context_id",
)

ORACLE_AUDIT_E2_CELL_FIELDS = ("param_grid_point",)

# Comparative gap ratios below this best-runtime floor are dominated by
# client/timer noise (sub-millisecond executions); such cells are disclosed
# with below_measurement_resolution=True rather than silently reinterpreted.
ORACLE_MEASUREMENT_RESOLUTION_FLOOR_MS = 1.0


def _oracle_audit_cell_key(row: Mapping[str, Any]) -> tuple[str, ...]:
    fields: tuple[str, ...] = ORACLE_AUDIT_CELL_FIELDS
    if str(row.get("experiment", "")) == "E2":
        fields = fields + ORACLE_AUDIT_E2_CELL_FIELDS
    return tuple(str(row.get(field, "")) for field in fields)


def _oracle_audit_cell_dict(key: Sequence[str]) -> dict[str, str]:
    row = {
        field: str(key[index])
        for index, field in enumerate(ORACLE_AUDIT_CELL_FIELDS)
        if index < len(key)
    }
    if row.get("experiment") == "E2":
        offset = len(ORACLE_AUDIT_CELL_FIELDS)
        for index, field in enumerate(ORACLE_AUDIT_E2_CELL_FIELDS, start=offset):
            if index < len(key):
                row[field] = str(key[index])
    return row


def _oracle_audit_iteration_key(row: Mapping[str, Any]) -> tuple[str, ...]:
    return _oracle_audit_cell_key(row) + (str(row.get("measurement_iteration", "")),)


def _dominant_string(rows: Sequence[Mapping[str, Any]], field: str) -> str:
    values = [str(row.get(field, "")) for row in rows if str(row.get(field, ""))]
    return Counter(values).most_common(1)[0][0] if values else ""


def _template_family(template_id: str) -> str:
    lowered = template_id.lower()
    if "mav" in lowered:
        return "mav"
    if "hybrid" in lowered:
        return "hybrid"
    if "auth_view" in lowered:
        return "auth-view"
    if "strong_auth_index" in lowered or "auth_index" in lowered:
        return "auth-index"
    if "injection" in lowered:
        return "safe-injection"
    if "barrier" in lowered:
        return "barrier"
    if "ordinary" in lowered:
        return "ordinary-sql"
    if "guard" in lowered:
        return "guard"
    return "other"


def _oracle_miss_diagnosis(chosen_template: str, best_template: str, query_id: str, policy_id: str) -> str:
    joined = " ".join([chosen_template, best_template, query_id, policy_id]).lower()
    best_family = _template_family(best_template)
    chosen_family = _template_family(chosen_template)
    if "mav" in joined:
        return "artifact cardinality/freshness boundary"
    if "hybrid" in joined:
        return "hybrid selectivity/cardinality miss"
    if best_family == "auth-index" and chosen_family != "auth-index":
        return "auth-index selectivity/random-fetch miss"
    if chosen_family == "auth-index" and best_family != "auth-index":
        return "auth-index random-fetch overestimate"
    if best_family == "safe-injection" or chosen_family == "safe-injection":
        return "safe-injection selectivity/cardinality miss"
    if best_family == "barrier" and chosen_family == "ordinary-sql":
        return "cheap sargable native-style predicate faster"
    if {best_family, chosen_family} == {"barrier", "guard"}:
        return "barrier-vs-guard residual/materialization cost miss"
    if best_family == "barrier" or chosen_family == "barrier":
        return "barrier-vs-index access-path/cardinality miss"
    return "residual access-path/cardinality miss"


def _oracle_claim_action(gap: float) -> str:
    if gap <= 1.10:
        return "no claim change; near-best finite-template miss"
    if gap <= 1.25:
        return "report as bounded miss; avoid fastest-template wording"
    return "keep claim at near-best/headroom, not fastest-template"


def _source_fig9(rows: Sequence[dict[str, str]]) -> tuple[list[dict[str, Any]], list[str], list[tuple[str, float]]]:
    def candidate_estimated_cost(row: Mapping[str, Any]) -> float | None:
        candidate_cost = _maybe_float(row.get("candidate_estimated_cost"))
        if candidate_cost is not None:
            return candidate_cost
        return _maybe_float(row.get("chosen_estimated_cost"))

    near_best_tolerances = {"near_best_3pct": 1.03, "near_best_5pct": 1.05}
    candidate_template_groups: defaultdict[tuple[tuple[str, ...], str], list[dict[str, str]]] = defaultdict(list)
    eligible_iteration_groups: defaultdict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    scatter_groups: defaultdict[tuple[tuple[str, ...], str], list[dict[str, str]]] = defaultdict(list)

    for row in rows:
        if row.get("run_kind") != "template_candidate":
            continue
        if str(row.get("measurement_phase") or "measured") != "measured":
            continue
        if _maybe_bool(row.get("template_oracle_eligible")) is not True:
            continue
        if _row_status(row) != "pass":
            continue
        execution_ms = _maybe_float(row.get("execution_ms"))
        if execution_ms is None or execution_ms <= 0:
            continue
        cell_key = _oracle_audit_cell_key(row)
        template_id = str(row.get("template_id", ""))
        candidate_template_groups[(cell_key, template_id)].append(row)
        eligible_iteration_groups[_oracle_audit_iteration_key(row)].append(row)
        if candidate_estimated_cost(row) is not None:
            scatter_groups[(cell_key, template_id)].append(row)

    summary_groups: defaultdict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        if row.get("run_kind") != "template_oracle_summary":
            continue
        if str(row.get("measurement_phase") or "measured") != "measured":
            continue
        summary_groups[_oracle_audit_cell_key(row)].append(row)

    cells: list[dict[str, Any]] = []
    cell_keys = sorted({cell_key for cell_key, _ in candidate_template_groups} | set(summary_groups))
    for key in cell_keys:
        template_execution: dict[str, float] = {}
        template_estimated: dict[str, float] = {}
        template_counts: dict[str, int] = {}
        for (cell_key, template_id), group in candidate_template_groups.items():
            if cell_key != key:
                continue
            execution_values = [
                parsed
                for parsed in (_maybe_float(row.get("execution_ms")) for row in group)
                if parsed is not None and parsed > 0
            ]
            estimated_values = [
                parsed
                for parsed in (candidate_estimated_cost(row) for row in group)
                if parsed is not None
            ]
            if not execution_values:
                continue
            template_execution[template_id] = _median(execution_values)
            template_counts[template_id] = len(execution_values)
            if estimated_values:
                template_estimated[template_id] = _median(estimated_values)
        if not template_execution:
            continue

        summary_group = summary_groups.get(key, [])
        best_template = min(template_execution, key=lambda item: (template_execution[item], item))
        chosen_template = _dominant_string(summary_group, "oracle_chosen_template_id")
        if not chosen_template:
            chosen_template = min(
                template_estimated or template_execution,
                key=lambda item: ((template_estimated or template_execution)[item], item),
            )
        if chosen_template not in template_execution:
            continue
        best_execution = template_execution[best_template]
        chosen_execution = template_execution[chosen_template]
        gap = chosen_execution / best_execution if best_execution > 0 else float("inf")
        measured_ranks = _rank_keyed_values(template_execution)
        chosen_rank = measured_ranks.get(chosen_template)
        chosen_is_measured_best = chosen_template == best_template or math.isclose(
            gap,
            1.0,
            rel_tol=1e-12,
            abs_tol=1e-12,
        )
        eligible_counts = [
            len(group)
            for iter_key, group in eligible_iteration_groups.items()
            if iter_key[:-1] == key
        ]
        eligible_plan_shapes = [
            parsed
            for parsed in (_maybe_float(row.get("oracle_eligible_plan_shapes")) for row in summary_group)
            if parsed is not None
        ]
        cell = {
            **_oracle_audit_cell_dict(key),
            "oracle_gap_median": gap,
            "oracle_gap_p90": gap,
            "oracle_gap_max": gap,
            "oracle_observation_count": max(template_counts.values()) if template_counts else 0,
            "best_template_id": best_template,
            "chosen_template_id": chosen_template,
            "best_template_family": _template_family(best_template),
            "chosen_template_family": _template_family(chosen_template),
            "best_execution_ms_median": best_execution,
            "chosen_execution_ms_median": chosen_execution,
            "below_measurement_resolution": best_execution < ORACLE_MEASUREMENT_RESOLUTION_FLOOR_MS,
            "eligible_templates_median": _median(eligible_counts) if eligible_counts else len(template_execution),
            "eligible_plan_shapes_median": _median(eligible_plan_shapes) if eligible_plan_shapes else len(template_execution),
            "excluded_templates": _dominant_string(summary_group, "oracle_excluded_templates"),
            "chosen_is_measured_best": chosen_is_measured_best,
            "chosen_is_measured_best_observation_rate": 1.0 if chosen_is_measured_best else 0.0,
            "chosen_measured_rank_median": chosen_rank if chosen_rank is not None else "",
            "chosen_measured_rank_observations": 1 if chosen_rank is not None else 0,
            "ranker_diagnosis": _oracle_miss_diagnosis(chosen_template, best_template, key[5], key[6]),
            "claim_action": _oracle_claim_action(gap),
        }
        cells.append(cell)

    def summary_row(label: str, label_cells: Sequence[dict[str, Any]]) -> dict[str, Any]:
        gaps = [float(cell["oracle_gap_median"]) for cell in label_cells]
        ranked = [
            float(cell["chosen_measured_rank_median"])
            for cell in label_cells
            if cell["chosen_measured_rank_median"] != ""
        ]
        eligible_templates = [
            float(cell["eligible_templates_median"])
            for cell in label_cells
            if cell["eligible_templates_median"] != ""
        ]
        eligible_plan_shapes = [
            float(cell["eligible_plan_shapes_median"])
            for cell in label_cells
            if cell["eligible_plan_shapes_median"] != ""
        ]
        cell_count = len(label_cells)
        rank_count = len(ranked)
        hit_count = sum(1 for cell in label_cells if cell["chosen_is_measured_best"])
        bounded_gaps = [
            float(cell["oracle_gap_median"])
            for cell in label_cells
            if not cell["below_measurement_resolution"]
        ]
        result = {
            "row_type": "summary",
            "experiment": label,
            "oracle_cell_count": cell_count,
            "oracle_observation_count": sum(int(cell["oracle_observation_count"]) for cell in label_cells),
            "rank_observed_cells": rank_count,
            "rank_observed_rate": (rank_count / cell_count) if cell_count else "",
            "median_oracle_gap": _median(gaps) if gaps else "",
            "p90_oracle_gap": _percentile(sorted(gaps), 0.9) if gaps else "",
            "max_oracle_gap": max(gaps) if gaps else "",
            "below_resolution_cell_count": cell_count - len(bounded_gaps),
            "measurement_resolution_floor_ms": ORACLE_MEASUREMENT_RESOLUTION_FLOOR_MS,
            "bounded_cell_count": len(bounded_gaps),
            "bounded_median_oracle_gap": _median(bounded_gaps) if bounded_gaps else "",
            "bounded_p90_oracle_gap": _percentile(sorted(bounded_gaps), 0.9) if bounded_gaps else "",
            "bounded_max_oracle_gap": max(bounded_gaps) if bounded_gaps else "",
            "chosen_is_measured_best_count": hit_count,
            "chosen_is_measured_best_rate": (hit_count / cell_count) if cell_count else "",
            "top1_measured_best_count": hit_count,
            "top1_measured_best_rate": (hit_count / cell_count) if cell_count else "",
            "top1_measured_rank_count": sum(1 for rank in ranked if rank <= 1),
            "top2_measured_rank_count": sum(1 for rank in ranked if rank <= 2),
            "top3_measured_rank_count": sum(1 for rank in ranked if rank <= 3),
            "top1_measured_rank_rate": (sum(1 for rank in ranked if rank <= 1) / rank_count) if rank_count else "",
            "top2_measured_rank_rate": (sum(1 for rank in ranked if rank <= 2) / rank_count) if rank_count else "",
            "top3_measured_rank_rate": (sum(1 for rank in ranked if rank <= 3) / rank_count) if rank_count else "",
            "eligible_templates_median": _median(eligible_templates) if eligible_templates else "",
            "eligible_plan_shapes_median": _median(eligible_plan_shapes) if eligible_plan_shapes else "",
        }
        for field, threshold in near_best_tolerances.items():
            count = sum(1 for gap in gaps if gap <= threshold)
            result[f"{field}_count"] = count
            result[f"{field}_rate"] = (count / cell_count) if cell_count else ""
        return result

    source: list[dict[str, Any]] = []
    experiments = sorted({cell["experiment"] for cell in cells})
    summary_rows = [summary_row(experiment, [cell for cell in cells if cell["experiment"] == experiment]) for experiment in experiments]
    if cells:
        summary_rows.append(summary_row("combined", cells))
    source.extend(summary_rows)
    cells_by_key = {_oracle_audit_cell_key(cell): cell for cell in cells}

    for label in [*experiments, "combined"]:
        label_cells = cells if label == "combined" else [cell for cell in cells if cell["experiment"] == label]
        ordered_cells = sorted(
            label_cells,
            key=lambda cell: (
                float(cell["oracle_gap_median"]),
                cell["query_id"],
                cell["policy_id"],
                cell.get("param_grid_point", ""),
            ),
        )
        for index, cell in enumerate(ordered_cells, start=1):
            source.append(
                {
                    "row_type": "cdf_point",
                    "cdf_scope": label,
                    "cdf_rank": index,
                    "cdf_fraction": index / len(ordered_cells) if ordered_cells else "",
                    **cell,
                }
            )

    for (cell_key, template_id), group in sorted(scatter_groups.items()):
        execution_values = [
            parsed
            for parsed in (_maybe_float(row.get("execution_ms")) for row in group)
            if parsed is not None
        ]
        estimated_values = [
            parsed
            for parsed in (candidate_estimated_cost(row) for row in group)
            if parsed is not None
        ]
        if not execution_values or not estimated_values:
            continue
        cell = cells_by_key.get(cell_key, {})
        source.append(
            {
                "row_type": "estimated_vs_measured",
                **_oracle_audit_cell_dict(cell_key),
                "template_id": template_id,
                "template_family": _template_family(template_id),
                "estimated_cost_median": _median(estimated_values),
                "measured_runtime_ms_median": _median(execution_values),
                "sample_count": len(execution_values),
                "eligible_templates_median": cell.get("eligible_templates_median", ""),
                "eligible_plan_shapes_median": cell.get("eligible_plan_shapes_median", ""),
            }
        )

    worst_cells = sorted(
        [cell for cell in cells if float(cell["oracle_gap_median"]) > 1.0],
        key=lambda cell: (
            float(cell["oracle_gap_median"]),
            float(cell["oracle_gap_max"]),
            cell["experiment"],
            cell["query_id"],
            cell["policy_id"],
        ),
        reverse=True,
    )
    for rank, cell in enumerate(worst_cells[:5], start=1):
        source.append({"row_type": "worst_miss", "worst_rank": rank, **cell})

    def pct(value: Any) -> str:
        parsed = _maybe_float(value)
        return "n/a" if parsed is None else f"{100.0 * parsed:.1f}%"

    def num(value: Any) -> str:
        parsed = _maybe_float(value)
        return "n/a" if parsed is None else f"{parsed:.3f}"

    combined_summary = next((row for row in summary_rows if row["experiment"] == "combined"), None)
    lines = [
        f"Measured oracle cases: {combined_summary['oracle_cell_count'] if combined_summary else 0}",
        "Top-k rates use cases with observed or candidate-inferred measured rank.",
    ]
    for row in summary_rows:
        lines.append(
            f"{row['experiment']}: gap med/p90/max "
            f"{num(row['median_oracle_gap'])}/{num(row['p90_oracle_gap'])}/{num(row['max_oracle_gap'])}; "
            f"top1/top2/top3 {pct(row['top1_measured_rank_rate'])}/"
            f"{pct(row['top2_measured_rank_rate'])}/{pct(row['top3_measured_rank_rate'])}; "
            f"within 3%/5% {pct(row['near_best_3pct_rate'])}/"
            f"{pct(row['near_best_5pct_rate'])}; "
            f"best-hit {pct(row['chosen_is_measured_best_rate'])} "
            f"({row['rank_observed_cells']}/{row['oracle_cell_count']} ranks)"
        )
    if combined_summary is not None and combined_summary.get("bounded_max_oracle_gap") != "":
        lines.append(
            f"Below-resolution cases: {combined_summary['below_resolution_cell_count']}/"
            f"{combined_summary['oracle_cell_count']} with best execution < "
            f"{float(combined_summary['measurement_resolution_floor_ms']):g}ms; "
            f"bounded-case gap med/p90/max "
            f"{num(combined_summary['bounded_median_oracle_gap'])}/"
            f"{num(combined_summary['bounded_p90_oracle_gap'])}/"
            f"{num(combined_summary['bounded_max_oracle_gap'])}"
        )
    for rank, cell in enumerate(worst_cells[:5], start=1):
        lines.append(
            f"Worst {rank}: {cell['experiment']} {cell['query_id']}/{cell['policy_id']} "
            f"gap {float(cell['oracle_gap_median']):.3f}, chosen {cell['chosen_template_id']}, "
            f"best {cell['best_template_id']}; {cell['ranker_diagnosis']}"
        )

    bars = [
        _bar(f"{row['experiment']} p90 gap", _float(row["p90_oracle_gap"]))
        for row in summary_rows
        if row.get("p90_oracle_gap") != ""
    ]
    bars.extend(
        _bar(f"worst {idx + 1}: {cell['experiment']} {cell['query_id']}", _float(cell["oracle_gap_median"]))
        for idx, cell in enumerate(worst_cells[:5])
    )
    return source, lines, bars


def _source_tab2_e10_diversity(rows: Sequence[dict[str, str]]) -> tuple[list[dict[str, Any]], list[str], list[tuple[str, float]]]:
    def candidate_estimated_cost(row: Mapping[str, Any]) -> float | None:
        candidate_cost = _maybe_float(row.get("candidate_estimated_cost"))
        if candidate_cost is not None:
            return candidate_cost
        return _maybe_float(row.get("chosen_estimated_cost"))

    def reject_reason(row: Mapping[str, str]) -> str:
        status = str(row.get("template_applicability_status", ""))
        reason = str(row.get("template_applicability_reason", ""))
        if not reason:
            return status
        if status and reason.startswith(f"{status}:"):
            return reason
        return f"{status}:{reason}" if status else reason

    candidate_groups: defaultdict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    oracle_groups: defaultdict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    normal_groups: defaultdict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        if row.get("experiment") != "E10":
            continue
        if str(row.get("measurement_phase") or "measured") != "measured":
            continue
        key = (str(row.get("query_id", "")), str(row.get("policy_id", "")))
        if row.get("run_kind") == "template_candidate":
            candidate_groups[key].append(row)
        elif row.get("run_kind") == "template_oracle_summary":
            oracle_groups[key].append(row)
        elif row.get("run_kind") == "normal_mode" and row.get("evaluation_role") != EvaluationRole.CONTRACT_VIOLATION_CONTROL.value:
            normal_groups[key].append(row)

    source: list[dict[str, Any]] = []
    bars: list[dict[str, Any]] = []
    family_counts: Counter[str] = Counter()
    chosen_family_counts: Counter[str] = Counter()
    non_mav_best_cases = 0

    for key in sorted(set(candidate_groups) | set(oracle_groups)):
        query_id, policy_id = key
        candidates = candidate_groups.get(key, [])
        oracle_rows = oracle_groups.get(key, [])
        normal_rows = normal_groups.get(key, [])
        if not candidates and not oracle_rows:
            continue

        eligible_by_template: defaultdict[str, list[dict[str, str]]] = defaultdict(list)
        rejected_by_template: defaultdict[str, list[dict[str, str]]] = defaultdict(list)
        for row in candidates:
            if _maybe_bool(row.get("template_oracle_eligible")) is True and _row_status(row) == "pass":
                eligible_by_template[str(row.get("template_id", ""))].append(row)
            else:
                rejected_by_template[str(row.get("template_id", ""))].append(row)

        measured_candidates: list[dict[str, Any]] = []
        for template_id, group in sorted(eligible_by_template.items()):
            execution_values = [
                parsed
                for parsed in (_maybe_float(row.get("execution_ms")) for row in group)
                if parsed is not None and parsed > 0
            ]
            estimated_values = [
                parsed
                for parsed in (candidate_estimated_cost(row) for row in group)
                if parsed is not None
            ]
            if not execution_values:
                continue
            measured_candidates.append(
                {
                    "template_id": template_id,
                    "template_family": _template_family(template_id),
                    "median_execution_ms": _median(execution_values),
                    "median_estimated_cost": _median(estimated_values) if estimated_values else "",
                    "sample_count": len(execution_values),
                }
            )

        measured_candidates.sort(
            key=lambda item: (
                float(item["median_execution_ms"]),
                str(item["template_id"]),
            )
        )
        measured_best = measured_candidates[0] if measured_candidates else {}
        measured_best_template = str(measured_best.get("template_id", ""))
        measured_best_family = str(measured_best.get("template_family", ""))
        measured_best_ms = measured_best.get("median_execution_ms", "")
        if measured_best_family:
            family_counts[measured_best_family] += 1
            if measured_best_family != "mav":
                non_mav_best_cases += 1

        chosen_template = _dominant_string(oracle_rows, "oracle_chosen_template_id")
        if not chosen_template:
            chosen_template = _dominant_string(
                [row for row in normal_rows if row.get("mode") == ADMISSION_FIRST_MODE],
                "template_id",
            )
        chosen_family = _template_family(chosen_template) if chosen_template else ""
        if chosen_family:
            chosen_family_counts[chosen_family] += 1
        chosen_candidate = next(
            (candidate for candidate in measured_candidates if candidate["template_id"] == chosen_template),
            {},
        )
        chosen_ms = chosen_candidate.get("median_execution_ms", "")

        gap_values = [
            parsed
            for parsed in (_maybe_float(row.get("oracle_gap")) for row in oracle_rows)
            if parsed is not None
        ]
        context_gap_values: list[float] = []
        context_ids = sorted(
            {
                str(row.get("context_id", ""))
                for row in candidates + oracle_rows
                if str(row.get("context_id", ""))
            }
        )
        for context_id in context_ids:
            context_templates: dict[str, float] = {}
            for template_id, group in eligible_by_template.items():
                values = [
                    parsed
                    for parsed in (
                        _maybe_float(row.get("execution_ms"))
                        for row in group
                        if str(row.get("context_id", "")) == context_id
                    )
                    if parsed is not None and parsed > 0
                ]
                if values:
                    context_templates[template_id] = _median(values)
            if not context_templates:
                continue
            context_oracle_rows = [
                row
                for row in oracle_rows
                if str(row.get("context_id", "")) == context_id
            ]
            context_chosen = _dominant_string(
                context_oracle_rows,
                "oracle_chosen_template_id",
            )
            if context_chosen not in context_templates:
                continue
            context_best_ms = min(context_templates.values())
            if context_best_ms > 0:
                context_gap_values.append(
                    context_templates[context_chosen] / context_best_ms
                )
        eligible_values = [
            parsed
            for parsed in (_maybe_float(row.get("oracle_eligible_templates")) for row in oracle_rows)
            if parsed is not None
        ]
        excluded_templates = _dominant_string(oracle_rows, "oracle_excluded_templates")
        if not excluded_templates:
            excluded_templates = json.dumps(
                {
                    str(reason): count
                    for reason, count in sorted(
                        Counter(
                            reject_reason(row)
                            for group in rejected_by_template.values()
                            for row in group
                        ).items()
                    )
                    if reason
                },
                sort_keys=True,
                separators=(",", ":"),
            )

        case_label = _dominant_string(candidates or oracle_rows or normal_rows, "param_label")
        query_shape = _dominant_string(candidates or oracle_rows or normal_rows, "param_query_shape")
        dataset_scale = _dominant_string(candidates or oracle_rows or normal_rows, "dataset_scale")
        row_count_values = [
            parsed
            for parsed in (
                _maybe_float(row.get("row_count"))
                for group in eligible_by_template.values()
                for row in group
            )
            if parsed is not None
        ]
        unauthorized = sum(_int(row.get("unauthorized_observations")) for row in normal_rows)
        source.append(
            {
                "row_type": "case_summary",
                "query_id": query_id,
                "case_label": case_label,
                "policy_id": policy_id,
                "query_shape": query_shape,
                "dataset_scale": dataset_scale,
                "measured_best_template_id": measured_best_template,
                "measured_best_family": measured_best_family,
                "measured_best_ms_median": measured_best_ms,
                "contract_chosen_template_id": chosen_template,
                "contract_chosen_family": chosen_family,
                "contract_chosen_ms_median": chosen_ms,
                "oracle_gap_median": _median(context_gap_values)
                if context_gap_values
                else (_median(gap_values) if gap_values else ""),
                "oracle_gap_p90": _percentile(sorted(context_gap_values), 0.9)
                if context_gap_values
                else (_percentile(sorted(gap_values), 0.9) if gap_values else ""),
                "oracle_gap_definition": "per-context ratio of template execution medians",
                "eligible_templates_median": _median(eligible_values) if eligible_values else "",
                "accepted_template_count": len(measured_candidates),
                "rejected_template_count": len(rejected_by_template),
                "excluded_templates": excluded_templates,
                "row_count_median": _median(row_count_values) if row_count_values else "",
                "unauthorized_observations": unauthorized,
            }
        )
        if measured_best_ms != "":
            bars.append(_bar(f"{query_id}:{measured_best_family}", float(measured_best_ms)))

        for rank, candidate in enumerate(measured_candidates, start=1):
            role_parts = ["accepted"]
            if candidate["template_id"] == measured_best_template:
                role_parts.append("measured_best")
            if candidate["template_id"] == chosen_template:
                role_parts.append("contract_chosen")
            source.append(
                {
                    "row_type": "candidate_waterfall",
                    "query_id": query_id,
                    "policy_id": policy_id,
                    "template_rank_by_measured_ms": rank,
                    "template_id": candidate["template_id"],
                    "template_family": candidate["template_family"],
                    "candidate_role": "+".join(role_parts),
                    "template_applicability_status": "applicable",
                    "template_applicability_reason": "",
                    "median_execution_ms": candidate["median_execution_ms"],
                    "median_estimated_cost": candidate["median_estimated_cost"],
                    "sample_count": candidate["sample_count"],
                }
            )
        for template_id, group in sorted(rejected_by_template.items()):
            reason_counts = Counter(reject_reason(row) for row in group)
            status = _dominant_string(group, "template_applicability_status")
            source.append(
                {
                    "row_type": "candidate_waterfall",
                    "query_id": query_id,
                    "policy_id": policy_id,
                    "template_id": template_id,
                    "template_family": _template_family(template_id),
                    "candidate_role": "rejected",
                    "template_applicability_status": status,
                    "template_applicability_reason": reason_counts.most_common(1)[0][0] if reason_counts else "",
                    "sample_count": len(group),
                    "reason_counts": dict(sorted(reason_counts.items())),
                }
            )

    family_summary = ", ".join(f"{family}:{count}" for family, count in sorted(family_counts.items()))
    chosen_summary = ", ".join(f"{family}:{count}" for family, count in sorted(chosen_family_counts.items()))
    case_count = sum(family_counts.values())
    lines = [
        f"E10 measured-best families across {case_count} cases: {family_summary}",
        f"AdmissionFirst chosen families: {chosen_summary}",
        f"Non-MAV measured-best cases: {non_mav_best_cases}/{case_count}",
    ]
    return source, lines, bars


def _source_tab3_ranker_audit(rows: Sequence[dict[str, str]]) -> tuple[list[dict[str, Any]], list[str], list[tuple[str, float]]]:
    source = [dict(row) for row in rows]
    split_rows = [row for row in rows if row.get("row_type") == "split_summary"]
    provenance_rows = [row for row in rows if row.get("row_type") == "calibration_provenance"]
    worst_rows = [row for row in rows if row.get("row_type") == "worst_miss"]

    def pct(value: Any) -> str:
        parsed = _maybe_float(value)
        return "n/a" if parsed is None else f"{100.0 * parsed:.1f}%"

    def num(value: Any) -> str:
        parsed = _maybe_float(value)
        return "n/a" if parsed is None else f"{parsed:.3f}"

    lines: list[str] = []
    if provenance_rows:
        first = provenance_rows[0]
        lines.append(
            "Observed calibration hash: "
            f"{first.get('calibration_hash', 'n/a') or 'n/a'}"
        )
        workspace_hash = first.get("workspace_calibration_hash")
        if workspace_hash:
            lines.append(
                "Workspace calibration hash: "
                f"{workspace_hash} (matches raw: {first.get('workspace_hash_matches_raw')})"
            )
        lines.append(
            f"Ranker/version: {first.get('rankers', 'n/a')}/"
            f"{first.get('cost_model_versions', 'n/a')}"
        )
    for row in split_rows:
        lines.append(
            f"{row.get('split_id')}: cases {row.get('cell_count')}, "
            f"gap med/p90/max {num(row.get('median_oracle_gap'))}/"
            f"{num(row.get('p90_oracle_gap'))}/{num(row.get('max_oracle_gap'))}; "
            f"RawPG top1/top3 {pct(row.get('raw_pg_top1_measured_best_rate'))}/"
            f"{pct(row.get('raw_pg_top3_measured_best_rate'))}; "
            f"calibrated top1/top3 {pct(row.get('calibrated_top1_measured_best_rate'))}/"
            f"{pct(row.get('calibrated_top3_measured_best_rate'))}; "
            f"AdmissionFirst top1/top3 {pct(row.get('admission_first_top1_measured_best_rate'))}/"
            f"{pct(row.get('admission_first_top3_measured_rank_rate'))}"
        )
    for row in worst_rows[:5]:
        lines.append(
            f"Worst {row.get('worst_rank')}: {row.get('query_id')}/{row.get('policy_id')} "
            f"gap {num(row.get('median_oracle_gap'))}; raw {row.get('raw_pg_ranker_choice_template_id')}, "
            f"cal {row.get('calibrated_ranker_choice_template_id')}, "
            f"chosen {row.get('admission_first_chosen_template_id')}, "
            f"best {row.get('measured_best_template_id')}; {row.get('ranker_diagnosis')}"
        )

    bars: list[dict[str, Any]] = []
    for row in split_rows:
        split_id = str(row.get("split_id", ""))
        if split_id not in {"all_e3_cells", "query_family:JOB", "query_family:TPC-H"}:
            continue
        raw_top3 = _maybe_float(row.get("raw_pg_top3_measured_best_rate"))
        calibrated_top3 = _maybe_float(row.get("calibrated_top3_measured_best_rate"))
        contract_top3 = _maybe_float(row.get("admission_first_top3_measured_rank_rate"))
        if raw_top3 is not None:
            bars.append(_bar(f"{split_id} RawPG top3", raw_top3))
        if calibrated_top3 is not None:
            bars.append(_bar(f"{split_id} calibrated top3", calibrated_top3))
        if contract_top3 is not None:
            bars.append(_bar(f"{split_id} AdmissionFirst top3", contract_top3))
    return source, lines, bars


def _figure_source(rows: Sequence[dict[str, str]], figure: str) -> tuple[list[dict[str, Any]], list[str], list[tuple[str, float]]]:
    if figure == "fig2_contract_matrix":
        return _source_fig2(rows)
    if figure == "fig3_e2_phase_diagram":
        return _source_fig3(rows)
    if figure == "fig4_e3_speedup":
        return _source_fig4(rows)
    if figure == "fig5_e5_template_regret":
        return _source_fig5(rows)
    if figure == "fig6_e4_local_greedy":
        return _source_fig6(rows)
    if figure == "fig7_sigma_ablation":
        return _source_fig7(rows)
    if figure == "fig8_e9_overhead":
        return _source_fig8(rows)
    if figure == "fig9_template_oracle_audit":
        return _source_fig9(rows)
    if figure == "tab3_ranker_audit":
        return _source_tab3_ranker_audit(rows)
    if figure == "tab2_e10_diversity":
        return _source_tab2_e10_diversity(rows)
    raise ValueError(f"unknown figure: {figure}")


def _pdf_escape(text: str) -> str:
    return text.encode("ascii", "replace").decode("ascii").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _write_text_pdf(
    path: Path,
    title: str,
    lines: Sequence[str],
    bars: Sequence[Any],
    *,
    taxonomy_layout: bool = False,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    width = 612
    height = 792
    commands: list[str] = []
    commands.append("BT /F1 16 Tf 50 750 Td (" + _pdf_escape(title) + ") Tj ET")
    y = 720
    summary_lines: list[str] = []
    for line in lines:
        if taxonomy_layout:
            summary_lines.extend(
                textwrap.wrap(
                    line,
                    width=86,
                    break_long_words=False,
                    break_on_hyphens=False,
                )
                or [""]
            )
        else:
            summary_lines.append(line[:110])
    for line in summary_lines[:18]:
        commands.append(f"BT /F1 10 Tf 50 {y} Td ({_pdf_escape(line)}) Tj ET")
        y -= 16
    if bars:
        y -= 10
        valid_bars = [item for item in bars if _bar_value(item) >= 0]
        max_value = max(max(_bar_value(item), _bar_ci(item)[1]) for item in valid_bars) or 1.0
        row_height = 13 if taxonomy_layout else 14
        column_gap = 280
        bar_max_width = 60.0 if taxonomy_layout else 220.0
        rows_per_column = max(1, int((y - 40) / row_height))
        max_bars = rows_per_column * 2
        for index, item in enumerate(valid_bars[:max_bars]):
            column = index // rows_per_column
            row = index % rows_per_column
            x = 50 + column * column_gap
            row_y = y - row * row_height
            label = _bar_label(item)
            value = _bar_value(item)
            ci_low, ci_high = _bar_ci(item)
            bar_x = x + 82 if taxonomy_layout else x
            bar_width = max(1.0, min(bar_max_width, bar_max_width * max(value, 0.0) / max_value))
            commands.append(f"0.18 0.35 0.62 rg {bar_x} {row_y - 3} {bar_width:.2f} 9 re f")
            if ci_low != value or ci_high != value:
                low_x = bar_x + min(bar_max_width, bar_max_width * max(ci_low, 0.0) / max_value)
                high_x = bar_x + min(bar_max_width, bar_max_width * max(ci_high, 0.0) / max_value)
                mid_y = row_y + 1
                commands.append(f"0.05 0.05 0.05 RG 0.7 w {low_x:.2f} {mid_y:.2f} m {high_x:.2f} {mid_y:.2f} l S")
                commands.append(f"{low_x:.2f} {mid_y - 3:.2f} m {low_x:.2f} {mid_y + 3:.2f} l S")
                commands.append(f"{high_x:.2f} {mid_y - 3:.2f} m {high_x:.2f} {mid_y + 3:.2f} l S")
            commands.append("0 0 0 rg")
            label_limit = 23 if taxonomy_layout else 32
            label_text = (
                label
                if len(label) <= label_limit
                else label[: label_limit - 3] + "..."
            )
            value_text = f"{value:.3f}"
            if ci_low != value or ci_high != value:
                value_text += f" [{ci_low:.3f}, {ci_high:.3f}]"
            if taxonomy_layout:
                commands.append(
                    f"BT /F1 6 Tf {x} {row_y - 1} Td ({_pdf_escape(label_text)}) Tj ET"
                )
                commands.append(
                    f"BT /F1 6 Tf {x + 148} {row_y - 1} Td ({_pdf_escape(value_text)}) Tj ET"
                )
            else:
                text = f"{label_text}  {value_text}"
                commands.append(f"BT /F1 7 Tf {x + 5} {row_y - 1} Td ({_pdf_escape(text)}) Tj ET")
    content = "\n".join(commands).encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width} {height}] "
            f"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ).encode("ascii"),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"\nendstream",
    ]
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{number} 0 obj\n".encode("ascii"))
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")
    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )
    path.write_bytes(bytes(pdf))


def plot_figure(figure: str, input_path: Path, output_dir: Path) -> PlotResult:
    if figure not in FIGURE_EXPERIMENTS:
        raise ValueError(f"unknown figure: {figure}")
    rows = _load_summary_rows(input_path, figure)
    source_rows, lines, bars = _figure_source(rows, figure)
    if not source_rows:
        raise ValueError(f"{figure} has no source rows after filtering")

    figure_dir = output_dir / figure
    figure_file = figure_dir / f"{figure}.pdf"
    source_csv = figure_dir / f"{figure}_source.csv"
    config_json = figure_dir / f"{figure}_config.json"
    manifest_hashes_txt = figure_dir / f"{figure}_manifest_hashes.txt"
    script_version_txt = figure_dir / f"{figure}_script_version.txt"
    companion_sources: list[str] = []
    witness_audit_csv = figure_dir / FIG3_WITNESS_SOURCE if figure == "fig3_e2_phase_diagram" else None
    witness_audit_rows = _fig3_witness_audit_rows(source_rows) if figure == "fig3_e2_phase_diagram" else []
    honesty_audit_csv = figure_dir / FIG4_HONESTY_SOURCE if figure == "fig4_e3_speedup" else None
    honesty_audit_rows = _fig4_honesty_audit_rows(source_rows) if figure == "fig4_e3_speedup" else []
    if witness_audit_csv is not None and witness_audit_rows:
        companion_sources.append(str(witness_audit_csv))
    if honesty_audit_csv is not None and honesty_audit_rows:
        companion_sources.append(str(honesty_audit_csv))
    manifest_hashes = _manifest_hashes_from_rows(rows)
    calibration_hashes = sorted({row["calibration_hash"] for row in rows if row.get("calibration_hash")})
    calibration_paths = sorted({row["calibration_path"] for row in rows if row.get("calibration_path")})
    cost_model_versions = sorted({row["cost_model_version"] for row in rows if row.get("cost_model_version")})
    rankers = sorted({row["ranker"] for row in rows if row.get("ranker")})
    workspace_calibration_hashes = {
        row["calibration_path"]: row["workspace_calibration_hash"]
        for row in rows
        if row.get("calibration_path") and row.get("workspace_calibration_hash")
    }
    script_hash = _script_version_hash()

    _write_csv(source_csv, source_rows)
    if witness_audit_csv is not None and witness_audit_rows:
        _write_csv(witness_audit_csv, witness_audit_rows)
    if honesty_audit_csv is not None and honesty_audit_rows:
        _write_csv(honesty_audit_csv, honesty_audit_rows)
    _write_json(
        config_json,
        {
            "figure": figure,
            "title": FIGURE_TITLES[figure],
            "input": str(input_path),
            "record_count": len(source_rows),
            "experiments": list(FIGURE_EXPERIMENTS[figure]),
            "summary_directories": list(FIGURE_SUMMARY_DIRECTORIES.get(figure, FIGURE_EXPERIMENTS[figure])),
            "source_file": FIGURE_SOURCE_FILES.get(figure, "runs.csv"),
            "uses_protocol_cell_stats": FIGURE_SOURCE_FILES.get(figure) == "cell_stats.csv",
            "output_pdf": str(figure_file),
            "source_csv": str(source_csv),
            "companion_sources": companion_sources,
            "witness_audit_csv": str(witness_audit_csv) if witness_audit_csv is not None and witness_audit_rows else "",
            "honesty_audit_csv": str(honesty_audit_csv) if honesty_audit_csv is not None and honesty_audit_rows else "",
            "manifest_hashes": manifest_hashes,
            "calibration_paths": calibration_paths,
            "calibration_hashes": calibration_hashes,
            "workspace_calibration_hashes": workspace_calibration_hashes,
            "cost_model_versions": cost_model_versions,
            "rankers": rankers,
            "script_version_hash": script_hash,
        },
    )
    _write_lines(manifest_hashes_txt, manifest_hashes)
    _write_lines(script_version_txt, [script_hash])
    _write_text_pdf(figure_file, FIGURE_TITLES[figure], lines, bars)
    return PlotResult(
        figure=figure,
        record_count=len(source_rows),
        output_dir=figure_dir,
        figure_file=figure_file,
        source_csv=source_csv,
        config_json=config_json,
        manifest_hashes_txt=manifest_hashes_txt,
        script_version_txt=script_version_txt,
    )


def _retained_figure_presentation(
    figure: str,
    rows: Sequence[Mapping[str, Any]],
) -> tuple[list[str], list[dict[str, Any]]]:
    """Build presentation text from an already-retained source CSV.

    Taxonomy-only releases must not rewrite the frozen source CSV.  This
    presentation path therefore derives only labels and PDF text from that
    retained numeric projection.
    """

    def compact_mode_label(value: Any) -> str:
        raw_mode = str(value or "")
        try:
            mode = normalize_mode_id(raw_mode)
        except ValueError:
            mode = raw_mode
        if mode == ADMISSION_FIRST_MODE:
            return "AF"
        if mode == ADMISSION_FIRST_NO_DOMINANCE_MODE:
            return "AF-NoDom"
        compact_labels = {
            "auth-index-enum-only": "AuthIndex",
            "barrier-only": "Barrier",
            "guard-mandatory-discharge": "Guard",
            "injection-only": "Injection",
            "mav-only": "MAV",
            "strong-auth-index": "StrongIndex",
        }
        return compact_labels.get(mode, _paper_label(mode))

    if figure == "fig5_e5_template_regret":
        by_mode: defaultdict[str, list[float]] = defaultdict(list)
        bars: list[dict[str, Any]] = []
        for row in rows:
            regret = _float(row.get("template_regret"))
            mode = str(row.get("mode") or "")
            if regret and str(row.get("witness_kind") or "") != "positive_control":
                by_mode[mode].append(regret)
            if regret:
                bars.append(
                    _bar(
                        f"{compact_mode_label(mode)}: {row.get('witness_id', '')}",
                        regret,
                        _float(row.get("template_regret_ci95_low")),
                        _float(row.get("template_regret_ci95_high")),
                    )
                )
        lines = [
            f"{_paper_label(mode)} geomean regret: {_geom_mean(values):.3f}x"
            for mode, values in sorted(by_mode.items(), key=lambda item: _mode_order(item[0]))
        ]
        return lines, bars

    if figure == "fig6_e4_local_greedy":
        bars = [
            _bar(
                f"{compact_mode_label(row.get('mode'))}: {row.get('pair_id', '')}",
                _float(row.get("total_ms_median")),
                _float(row.get("total_ms_ci95_low")),
                _float(row.get("total_ms_ci95_high")),
            )
            for row in rows
        ]
        pair_modes = {
            (str(row.get("pair_id") or ""), str(row.get("mode") or ""))
            for row in rows
        }
        return [f"Retained pair/mode groups: {len(pair_modes)}"], bars

    if figure == "fig8_e9_overhead":
        bars = [
            _bar(
                f"{compact_mode_label(row.get('mode'))}: occ{row.get('protected_occurrences', '')}",
                _float(row.get("planning_ms_median")),
                _float(row.get("planning_ms_ci95_low")),
                _float(row.get("planning_ms_ci95_high")),
            )
            for row in rows
        ]
        lines = [
            f"Max planning time: {max((_float(row.get('planning_ms_median')) for row in rows), default=0.0):.3f} ms",
            f"Max planning/total ratio: {max((_float(row.get('planning_total_ratio')) for row in rows), default=0.0):.3f}",
            f"Max median planner memory: {max((_float(row.get('peak_memory_bytes_median')) / 1024.0 for row in rows), default=0.0):.1f} KiB",
            f"Max generated templates: {max((_int(row.get('generated_templates_median')) for row in rows), default=0)}",
        ]
        return lines, bars

    if figure in {"tab2_e10_diversity", "tab2_e10_diversity_full_seed42"}:
        cases = [row for row in rows if row.get("row_type") == "case_summary"]
        measured = Counter(str(row.get("measured_best_family") or "") for row in cases)
        chosen = Counter(str(row.get("contract_chosen_family") or "") for row in cases)
        measured.pop("", None)
        chosen.pop("", None)
        measured_text = ", ".join(f"{family}:{count}" for family, count in sorted(measured.items()))
        chosen_text = ", ".join(f"{family}:{count}" for family, count in sorted(chosen.items()))
        lines = [
            f"E10 measured-best families across {len(cases)} cases: {measured_text}",
            f"AdmissionFirst chosen families: {chosen_text}",
            f"Non-MAV measured-best cases: {sum(count for family, count in measured.items() if family != 'mav')}/{len(cases)}",
        ]
        bars = [
            _bar(
                "{}: {}".format(
                    row.get("measured_best_family", ""),
                    str(row.get("query_id", "")).replace("E10_", "").split("_", 1)[0],
                ),
                _float(row.get("measured_best_ms_median")),
            )
            for row in cases
            if row.get("measured_best_ms_median") not in {"", None}
        ]
        return lines, bars

    raise ValueError(f"{figure} is not a retained taxonomy figure")


def rerender_retained_figure_pdf(figure: str, figure_root: Path) -> Path:
    """Refresh one label-bearing PDF without mutating its retained source CSV."""

    figure_dir = figure_root / figure
    source = figure_dir / f"{figure}_source.csv"
    if not source.is_file():
        raise FileNotFoundError(f"missing retained figure source: {source}")
    before = source.read_bytes()
    rows = _read_csv(source)
    lines, bars = _retained_figure_presentation(figure, rows)
    output = figure_dir / f"{figure}.pdf"
    title = FIGURE_TITLES.get(figure, "Table2 E10 Diversity (Full Seed42)")
    _write_text_pdf(output, title, lines, bars, taxonomy_layout=True)
    if source.read_bytes() != before:
        raise RuntimeError(f"taxonomy rendering modified retained source: {source}")
    return output


def _artifact_entries(
    root: Path,
    *,
    include_top_level_dirs: Sequence[str] = (),
    exclude_top_level_dirs: Sequence[str] = (),
) -> list[dict[str, Any]]:
    if not root.exists():
        return []
    entries: list[dict[str, Any]] = []
    included = set(include_top_level_dirs)
    excluded = set(exclude_top_level_dirs)
    for path in sorted(
        item for item in root.rglob("*") if item.is_file() and not _is_sidecar_path(item)
    ):
        rel_path = path.relative_to(root).as_posix()
        rel_parts = Path(rel_path).parts
        if included and (not rel_parts or rel_parts[0] not in included):
            continue
        if rel_parts and rel_parts[0] in excluded:
            continue
        entries.append(
            {
                "path": rel_path,
                "bytes": path.stat().st_size,
                "sha256": _file_sha256(path),
            }
        )
    return entries


def _entries_digest(entries: Sequence[Mapping[str, Any]]) -> str:
    digest = hashlib.sha256()
    for entry in entries:
        digest.update(str(entry["path"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(entry["bytes"]).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(entry["sha256"]).encode("ascii"))
        digest.update(b"\n")
    return "sha256:" + digest.hexdigest()


def _artifact_summary(entries: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "file_count": len(entries),
        "total_bytes": sum(int(entry["bytes"]) for entry in entries),
        "digest": _entries_digest(entries),
    }


def _section_entries(section: str, entries: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            **dict(entry),
            "path": f"{section}/{entry['path']}",
        }
        for entry in entries
    ]


def _results_manifest_project_root(raw_dir: Path, output_path: Path) -> Path:
    raw_resolved = raw_dir.resolve()
    if raw_resolved.name == "raw" and raw_resolved.parent.name == "results":
        return raw_resolved.parent.parent
    output_resolved = output_path.resolve()
    if output_resolved.parent.name == "results":
        return output_resolved.parent.parent
    return output_resolved.parent


def _data_boundary_inventory(project_root: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for spec in DATA_BOUNDARY_FILES:
        rel_path = str(spec["path"])
        path = project_root / rel_path
        entry = {
            "role": spec["role"],
            "boundary": spec["boundary"],
            "path": rel_path,
            "description": spec["description"],
        }
        if path.exists():
            entry.update(
                {
                    "bytes": path.stat().st_size,
                    "sha256": _file_sha256(path),
                    "missing": False,
                }
            )
        else:
            entry.update({"bytes": 0, "sha256": "", "missing": True})
        entries.append(entry)
    present_entries = [entry for entry in entries if not entry["missing"]]
    return {
        "schema_version": "caprls-data-boundary-v1",
        "project_root": str(project_root),
        "entries": entries,
        "file_count": len(present_entries),
        "missing_file_count": len(entries) - len(present_entries),
        "digest": _entries_digest(present_entries),
    }


def _read_lines_if_present(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _read_json_if_present(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        loaded = json.load(fh)
    return loaded if isinstance(loaded, dict) else {}


def _figure_artifact_inventory(figure_dir: Path) -> list[dict[str, Any]]:
    """Group generated plot/table sidecars for reviewer traceability."""
    if not figure_dir.exists():
        return []
    artifacts: list[dict[str, Any]] = []
    for artifact_dir in sorted(path for path in figure_dir.iterdir() if path.is_dir()):
        artifact_id = artifact_dir.name
        expected_files = {
            "figure_pdf": artifact_dir / f"{artifact_id}.pdf",
            "source_csv": artifact_dir / f"{artifact_id}_source.csv",
            "config_json": artifact_dir / f"{artifact_id}_config.json",
            "manifest_hashes_txt": artifact_dir / f"{artifact_id}_manifest_hashes.txt",
            "script_version_txt": artifact_dir / f"{artifact_id}_script_version.txt",
        }
        files: dict[str, str] = {}
        file_sha256: dict[str, str] = {}
        file_bytes: dict[str, int] = {}
        missing: list[str] = []
        for role, path in expected_files.items():
            if path.exists():
                files[role] = path.as_posix()
                file_sha256[role] = _file_sha256(path)
                file_bytes[role] = path.stat().st_size
            else:
                missing.append(role)

        config = _read_json_if_present(expected_files["config_json"])
        manifest_hashes = _read_lines_if_present(expected_files["manifest_hashes_txt"])
        script_versions = _read_lines_if_present(expected_files["script_version_txt"])
        companion_sources = [
            str(item)
            for item in config.get("companion_sources", [])
            if str(item)
        ]
        companion_sha256: dict[str, str] = {}
        companion_bytes: dict[str, int] = {}
        missing_companion_sources: list[str] = []
        for companion_source in companion_sources:
            companion_path = Path(companion_source)
            if not companion_path.exists():
                companion_path = artifact_dir / Path(companion_source).name
            if companion_path.exists():
                companion_sha256[companion_source] = _file_sha256(companion_path)
                companion_bytes[companion_source] = companion_path.stat().st_size
            else:
                missing_companion_sources.append(companion_source)
        artifacts.append(
            {
                "artifact_id": artifact_id,
                "directory": artifact_dir.as_posix(),
                "artifact_digest": _entries_digest(_artifact_entries(artifact_dir)),
                "files": files,
                "file_sha256": file_sha256,
                "file_bytes": file_bytes,
                "missing_required_files": missing,
                "companion_sources": companion_sources,
                "companion_source_sha256": companion_sha256,
                "companion_source_bytes": companion_bytes,
                "missing_companion_sources": missing_companion_sources,
                "manifest_hashes": manifest_hashes,
                "script_version_hash": script_versions[0] if script_versions else "",
                "config_script_version_hash": str(config.get("script_version_hash", "")),
                "source_file": str(config.get("source_file", "")),
                "summary_directories": list(config.get("summary_directories", [])),
                "experiments": list(config.get("experiments", [])),
                "record_count": int(config.get("record_count", 0) or 0),
            }
        )
    return artifacts


def _raw_inventory(
    raw_dir: Path,
    *,
    include_top_level_dirs: Sequence[str] = (),
    exclude_top_level_dirs: Sequence[str] = (),
) -> dict[str, Any]:
    by_directory: Counter[str] = Counter()
    by_experiment: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    git_commits: set[str] = set()
    json_count = 0
    included = set(include_top_level_dirs)
    excluded = set(exclude_top_level_dirs)
    raw_paths = _visible_json_paths(raw_dir, recursive=True)
    for path in raw_paths:
        parts = path.relative_to(raw_dir).parts
        if included and (not parts or parts[0] not in included):
            continue
        if parts and parts[0] in excluded:
            continue
        if "explain" in parts:
            continue
        json_count += 1
        try:
            with path.open("r", encoding="utf-8") as fh:
                record = json.load(fh)
        except json.JSONDecodeError:
            by_directory[path.relative_to(raw_dir).parts[0]] += 1
            status_counts["json_decode_error"] += 1
            continue
        directory = parts[0] if parts else "."
        if not isinstance(record, dict):
            status_counts["non_record_json"] += 1
            by_directory[directory] += 1
            continue
        experiment = str(record.get("experiment") or directory)
        by_directory[directory] += 1
        by_experiment[experiment] += 1
        status_counts[str(record.get("status", ""))] += 1
        git_commit = _get(record, "implementation.git_commit")
        if git_commit:
            git_commits.add(str(git_commit))
    return {
        "json_count": json_count,
        "record_count": sum(by_experiment.values()),
        "by_directory": dict(sorted(by_directory.items())),
        "by_experiment": dict(sorted(by_experiment.items())),
        "status_counts": dict(sorted(status_counts.items())),
        "git_commits": sorted(git_commits),
    }


def write_claim_support_matrix(output_dir: Path) -> ClaimSupportResult:
    rows = _claim_support_rows(output_dir)
    source_csv = output_dir / "claim_support_matrix.csv"
    summary_json = output_dir / "claim_support_matrix_summary.json"
    script_version_txt = output_dir / "script_version.txt"
    script_hash = _script_version_hash()

    _write_csv(source_csv, rows)
    _write_json(
        summary_json,
        {
            "schema_version": "caprls-claim-support-matrix-v1",
            "row_count": len(rows),
            "claim_ids": [row["claim_id"] for row in rows],
            "paper_anchor": "main.tex Table tab:claim-support",
            "script_version_hash": script_hash,
            "rows": rows,
        },
    )
    _write_lines(script_version_txt, [script_hash])
    return ClaimSupportResult(
        output_dir=output_dir,
        source_csv=source_csv,
        summary_json=summary_json,
        script_version_txt=script_version_txt,
        row_count=len(rows),
    )


def write_results_manifest(
    raw_dir: Path,
    summary_dir: Path,
    figure_dir: Path,
    output_path: Path,
) -> ResultsManifestResult:
    raw_entries = _artifact_entries(
        raw_dir,
        include_top_level_dirs=RESULTS_MANIFEST_INCLUDED_RAW_DIRS,
        exclude_top_level_dirs=RESULTS_MANIFEST_EXCLUDED_TOP_LEVEL_DIRS,
    )
    summary_entries = _artifact_entries(
        summary_dir,
        include_top_level_dirs=RESULTS_MANIFEST_INCLUDED_SUMMARY_DIRS,
        exclude_top_level_dirs=RESULTS_MANIFEST_EXCLUDED_TOP_LEVEL_DIRS,
    )
    figure_entries = _artifact_entries(figure_dir)
    project_root = _results_manifest_project_root(raw_dir, output_path)
    data_boundary = _data_boundary_inventory(project_root)
    boundary_entries = [
        entry for entry in data_boundary["entries"] if not entry["missing"]
    ]
    raw_summary = _artifact_summary(raw_entries)
    summary_summary = _artifact_summary(summary_entries)
    figure_summary = _artifact_summary(figure_entries)
    figure_artifacts = _figure_artifact_inventory(figure_dir)
    aggregate_digest = _entries_digest(
        [
            *_section_entries("raw", raw_entries),
            *_section_entries("summarized", summary_entries),
            *_section_entries("figures", figure_entries),
            *_section_entries("data_boundary", boundary_entries),
        ]
    )
    raw_inventory = _raw_inventory(
        raw_dir,
        include_top_level_dirs=RESULTS_MANIFEST_INCLUDED_RAW_DIRS,
        exclude_top_level_dirs=RESULTS_MANIFEST_EXCLUDED_TOP_LEVEL_DIRS,
    )
    payload = {
        "schema_version": "caprls-results-artifact-manifest-v2",
        "note": (
            "Raw results and generated summaries/figures are ignored by git by default; "
            "this tracked manifest records their local inventory, per-figure sidecars, "
            "and aggregate hashes."
        ),
        "paths": {
            "raw_dir": str(raw_dir),
            "summary_dir": str(summary_dir),
            "figure_dir": str(figure_dir),
        },
        "excluded_top_level_directories": {
            "raw": list(RESULTS_MANIFEST_EXCLUDED_TOP_LEVEL_DIRS),
            "summarized": list(RESULTS_MANIFEST_EXCLUDED_TOP_LEVEL_DIRS),
            "figures": [],
        },
        "included_top_level_directories": {
            "raw": list(RESULTS_MANIFEST_INCLUDED_RAW_DIRS),
            "summarized": list(RESULTS_MANIFEST_INCLUDED_SUMMARY_DIRS),
            "figures": [],
        },
        "raw": {**raw_summary, **raw_inventory},
        "summarized": summary_summary,
        "figures": {
            **figure_summary,
            "artifact_count": len(figure_artifacts),
            "artifacts": figure_artifacts,
            "missing_required_sidecar_count": sum(
                len(artifact["missing_required_files"]) for artifact in figure_artifacts
            ),
        },
        "data_boundary": data_boundary,
        "total_file_count": (
            len(raw_entries) + len(summary_entries) + len(figure_entries) + len(boundary_entries)
        ),
        "total_bytes": (
            raw_summary["total_bytes"]
            + summary_summary["total_bytes"]
            + figure_summary["total_bytes"]
            + sum(int(entry["bytes"]) for entry in boundary_entries)
        ),
        "aggregate_digest": aggregate_digest,
        "generated_by": "caprls results-manifest",
        "reporting_script_version_hash": _script_version_hash(),
    }
    _write_json(output_path, payload)
    return ResultsManifestResult(
        output_path=output_path,
        raw_file_count=len(raw_entries),
        summary_file_count=len(summary_entries),
        figure_file_count=len(figure_entries),
        raw_record_count=int(raw_inventory["record_count"]),
        aggregate_digest=aggregate_digest,
    )


def run_figures_small(raw_dir: Path, summary_dir: Path, figure_dir: Path) -> FiguresSmallResult:
    required_inputs = FIGURES_SMALL_REQUIRED_SUMMARY_INPUTS
    missing = [
        directory
        for directory, _experiment in required_inputs
        if not _visible_json_paths(raw_dir / directory)
    ]
    if missing:
        raise ValueError(
            "figures-small needs smoke/raw results for "
            + ", ".join(missing)
            + f" under {raw_dir}"
        )
    summaries = [
        summarize_experiment(experiment, raw_dir / directory, summary_dir / directory)
        for directory, experiment in required_inputs
    ]
    plots = [plot_figure(figure, summary_dir, figure_dir) for figure in FIGURES_SMALL]
    return FiguresSmallResult(summaries=summaries, plots=plots)
