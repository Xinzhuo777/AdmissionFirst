"""Audit and analyze one final-AF campaign without executing SQL.

All declared cases and ordinary baselines remain in the denominator. Ratios are
baseline / AF; W means that the paired-round percentile interval lies above 1.
The bootstrap conditions on the declared case grid and resamples rounds within
each case. Identical SQL is described separately without pooling observations.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import random
import re
import statistics
from typing import Any, Mapping, Sequence

from planner.pc_scope import decode_access_root_materialized

from caprls_core.af_pareto_analyze import (
    AnalysisError, canonical_bag, close, csv_matches_json, digest_field,
    execution_environment_audit, execution_profile_audit, indexed_rows, integer,
    inventory, json_digest, number, percentile, read_json, require, sha,
    source_digest, unique_strings,
)

SCHEMA = "final_af_e3_analysis_v1"
FIXED_MODES = ("native-pg-rls", "local-greedy", "barrier-only", "injection-only",
               "auth-index-enum-only", "strong-auth-index")
PRIMARY_MODES = ("af", *FIXED_MODES[:4])
ALL_MODES = ("af", *FIXED_MODES)
MEASURES = {
    "median_postgres_query_execution_ms": "execution_ms",
    "median_server_query_plus_required_validation_observed_ms": "server_query_plus_required_validation_observed_ms",
    "median_end_to_end_ms_including_validation_and_client": "database_total_ms",
    "median_postgres_planning_ms": "postgres_planning_ms",
    "median_server_validation_ms": "server_validation_ms",
    "median_server_guard_body_execution_ms": "server_guard_body_execution_ms",
    "median_server_body_planning_execution_ms": "server_body_planning_execution_ms",
}
METRICS = {
    "sql_execution": "execution_ms",
    "observed_server_query_plus_validation": "server_query_plus_required_validation_observed_ms",
    "client_request": "database_total_ms",
}
LEGACY_PROTOCOL_SCHEDULE = "casewise_balanced_available_modes_rounds_v1"
ADJACENT_SAMPLING_SCHEDULE = "af_ip_adjacent_block_v1"
# Independently transcribed expanded rows from the preregistered finite check.
# Do not call the producer's schedule generator to create audit expectations.
_ADJACENT_ORDERS = {
    5: ((0,2,3,1,4),(4,1,3,0,2),(2,0,1,4,3),(3,4,0,2,1),
        (1,3,2,0,4),(4,2,0,3,1),(1,0,2,4,3),(3,4,1,2,0)),
    6: ((0,2,1,5,3,4),(4,5,3,2,0,1),(1,3,0,2,4,5),(5,2,0,4,1,3),
        (3,4,1,5,0,2),(2,0,5,1,4,3),(3,1,4,0,2,5),(5,4,2,0,3,1),
        (1,0,2,3,5,4),(4,3,5,1,2,0)),
    7: ((0,2,4,3,5,1,6),(6,1,5,3,4,0,2),(2,0,1,6,3,5,4),(4,5,0,2,6,3,1),
        (1,3,2,0,4,6,5),(5,6,4,1,0,2,3),(3,4,1,5,2,0,6),(6,2,0,5,1,4,3),
        (3,0,2,1,4,6,5),(5,6,4,2,0,3,1),(1,3,6,0,2,5,4),(4,5,3,6,1,2,0)),
}
_ADJACENT_REASON = "one complete AF/IP-adjacent role-symmetric warmup cycle; measured rounds rounded up to its complete cycle"
_ADJACENT_REPETITION_POLICY = "per cell: one complete 2(n-1)-round AF/IP-adjacent role-symmetric warmup cycle; at least requested measured rounds rounded upward to its complete cycle; n=available modes"


def _adjacent_mode_map(eligible: Sequence[str]) -> dict[str, Any]:
    modes = list(eligible)
    require(len(modes) in _ADJACENT_ORDERS and len(set(modes)) == len(modes)
            and modes[0] == "af" and modes[2] == "local-greedy"
            and modes == [mode for mode in ALL_MODES if mode in modes],
            "adjacent schedule requires AF index 0 and ordinary IP index 2 in unchanged mode order")
    return {"pair_indices": [0, 2], "pair_modes": ["af", "local-greedy"],
            "eligible_mode_order": modes,
            "macro_units": [["af", "local-greedy"]] + [[mode] for i, mode in enumerate(modes) if i not in (0, 2)]}


def _adjacent_contract() -> dict[str, Any]:
    return {
        "schema": "af_ip_adjacent_block_sampling_v1", "pair_indices": [0, 2],
        "pair_modes": ["af", "local-greedy"],
        "macro_index_maps": {str(n): [[0, 2]] + [[i] for i in range(n) if i not in (0, 2)] for n in (5, 6, 7)},
        "direction_bits_0_AB_1_BA": {"5": "00101101", "6": "0101010101", "7": "001010110101"},
        "outer_orders_sha256": {
            "5": "sha256:ca68b2c5b9313b0097300f3f80f5a7861907d065b4dca969fa9d20e23c53bb44",
            "6": "sha256:36f6c501bc1e6340586d7c2f9f0926f16a22fb2fc88846b9a1955e3bd4f58ce8",
            "7": "sha256:2e8d492816463eecb0ba741649d190fb762226e6053a3d417d82ec606d1ef5e3"},
        "balance_scope": "AF/IP raw positions equal; ordinary external predecessor/successor labels equal by orientation; actual AF/IP carryover and transition matrix symmetric under AF<->IP relabeling",
        "all_method_raw_positions_uniform": False,
        "full_literal_external_labels_balanced": False,
        "warmup_boundary": "one identical complete warmup cycle supplies the first formal predecessor",
        "cache_scope": "adjacency changes immediate predecessor/cache conditions; keep separate from legacy samples; no pooling or correction",
        "cycle_sensitivity_scope": "cycle indices are per case; at minimum30 n5 has four cycles and n6/n7 three; an extra mixed cycle may be a subset, identified by case_count; primary GM retains the full case grid",
    }


def sampling_protocol_audit(protocol: Mapping[str, Any]) -> str:
    schedule = protocol.get("schedule")
    if schedule == LEGACY_PROTOCOL_SCHEDULE:
        require("sampling_schedule_contract" not in protocol, "adjacent contract under legacy schedule")
        return schedule
    require(schedule == ADJACENT_SAMPLING_SCHEDULE, "unknown sampling schedule")
    require(json_digest(protocol.get("sampling_schedule_contract")) == json_digest(_adjacent_contract()),
            "adjacent sampling contract differs from preregistration")
    expected = {str(n): [list(row) for row in _ADJACENT_ORDERS[n]] for n in (5, 6, 7)}
    require(json_digest(protocol.get("balanced_round_order_indices")) == json_digest(expected),
            "adjacent protocol rows differ from preregistration")
    require(protocol.get("repetition_policy") == _ADJACENT_REPETITION_POLICY,
            "adjacent repetition declaration differs from preregistration")
    return schedule


def _materialization_layouts(value: Any, label: str) -> dict[str, bool]:
    require(isinstance(value, Mapping) and all(type(key) is str and bool(key)
            and type(flag) is bool for key, flag in value.items()),
            "invalid per-template access-root layout policy: "+label)
    return dict(value)


PHYSICAL_RECIPE_STRATEGY = "strong_handoff_min_full_cost_v1"
_VALIDATED_PHYSICAL_RECIPE = object()
_RECIPE_ORDER = ("inline_strong", "materialized_strong")


def physical_recipe_protocol_audit(protocol: Mapping[str, Any], spec: Mapping[str, Any],
                                   selection: Mapping[str, Any], *, query: str,
                                   policy: str, label: str) -> tuple[Mapping[str, Any], dict[str, Any]]:
    """Validate detached physical evidence before deriving one effective layout.

    This checks retained commitments and cost selection. It does not recreate
    the source's opaque owned decision, query plan, or planning batch.
    """
    metadata = selection.get("normal_entry_metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    strategy = protocol.get("physical_recipe_strategy")
    if strategy is None:
        declared_metadata = metadata.get("declared_runtime_config")
        require(selection.get("physical_recipe_selection") is None and metadata.get("physical_recipe_selection") is None
                and not (isinstance(declared_metadata, Mapping) and declared_metadata.get("physical_recipe_strategy")),
                "undeclared physical recipe strategy: "+label)
        return protocol, {"case_id":label,"status":"not_declared","strategy":None}
    require(strategy == PHYSICAL_RECIPE_STRATEGY and protocol.get("normal_entry_execution_check") is True,
            "unsupported physical recipe strategy or missing exact-body check: "+label)
    declared = protocol.get("declared_runtime_config")
    keys = {"schema","name","configuration_status","execution_profile","access_root_wrapper","access_root_materialized_by_template","physical_recipe_strategy"}
    require(type(declared) is dict and set(declared)==keys and declared.get("physical_recipe_strategy")==strategy
            and declared.get("schema")=="normal_e3_af_runtime_v1" and declared.get("configuration_status")=="candidate_not_accepted"
            and declared.get("execution_profile")=="trusted_explicit" and type(declared.get("name")) is str and bool(declared["name"])
            and declared.get("access_root_wrapper")=="not_materialized_single_reference"
            and _materialization_layouts(declared.get("access_root_materialized_by_template"),label)=={"auth_index_enum_v1":True},
            "invalid physical recipe declaration: "+label)
    declaration_digest = json_digest(declared)
    require(protocol.get("declared_runtime_config_sha256")==metadata.get("declared_runtime_config_sha256")==declaration_digest
            and metadata.get("declared_runtime_config")==declared
            and protocol.get("access_root_wrapper")==declared["access_root_wrapper"]
            and protocol.get("access_root_materialized_by_template")==declared["access_root_materialized_by_template"]
            and protocol.get("access_root_materialized_by_template_override") is None,
            "physical declaration/default-map binding differs: "+label)
    physical = metadata.get("physical_recipe_selection")
    require(type(physical) is dict and selection.get("physical_recipe_strategy")==strategy
            and selection.get("physical_recipe_selection")==physical
            and physical.get("schema")=="e3_physical_recipe_selection_v1" and physical.get("strategy")==strategy
            and physical.get("declared_config_digest")==declaration_digest and physical.get("recipe_order")==list(_RECIPE_ORDER)
            and physical.get("comparison")=="minimum_owned_selected_prospective_total_cost"
            and physical.get("tie_break")=="recipe_order_on_exact_cost"
            and physical.get("decision_digest")==json_digest({key:value for key,value in physical.items() if key!="decision_digest"}),
            "physical recipe decision commitment differs: "+label)
    branches=physical.get("branches");identity=physical.get("shared_planning_identity")
    identity_keys={"batch_id","snapshot_digest","database_identity_digest","session_contract_digest","guc_digest","cost_model_version",
        "catalog_digest","gamma_digest","registry_digest","registry_scope_identity","registry_manifest_digest","admitted_candidate_inventory_digest",
        "target_digest","logical_target_id","rho_digest","emit_context_digest","obligation_graph_digest","evidence_role"}
    require(type(identity) is dict and set(identity)==identity_keys and identity.get("evidence_role")=="production_validator"
            and type(identity.get("batch_id")) is str and bool(identity["batch_id"])
            and type(identity.get("cost_model_version")) is str and bool(identity["cost_model_version"]),"physical common planning identity differs: "+label)
    for key in identity_keys-{"batch_id","cost_model_version","evidence_role"}:digest_field(identity[key],label+" "+key)
    require(isinstance(branches,list) and len(branches)==2 and [b.get("recipe_id") for b in branches]==list(_RECIPE_ORDER),"fixed physical recipe inventory differs: "+label)
    bound_fields={"strict_result_identity_seal","plan_id","template_id","query_id","policy_id","case_owner_identity_digest",
        "strict_complete_root_plan_digest","strict_exact_sql_digest","strict_sql_ast_digest","renderer_id","renderer_version","ordered_keys","row_limit",
        "strict_core_sql_digest","continuation_sql_digest","continuation_digest","result_contract_digest","runner_sql_digest","session_contract_digest",
        "registry_digest","snapshot_digest","database_identity_digest","catalog_digest"}
    for index,branch in enumerate(branches):
        layouts={"auth_index_enum_v1":True}
        if index:layouts["strong_auth_index_keyed_v1"]=True
        expected_layout={"schema":"e3_access_root_layout_policy_v1","base_materialized":False,"materialized_by_template":layouts}
        require(branch.get("layout_policy")==expected_layout and branch.get("planning_batch_identity")==identity,"physical branch layout/common snapshot differs: "+label)
        for field in ("planning_batch_digest","query_plan_digest","selected_runner_digest","selected_bound_runner_identity_digest"):digest_field(branch.get(field),label+" "+field)
        bound=branch.get("selected_bound_runner")
        require(type(bound) is dict and bound.get("query_id")==query and bound.get("policy_id")==policy
                and bound.get("plan_id")==branch.get("selected_plan_id") and bound.get("template_id")==branch.get("selected_template_id")
                and bound.get("runner_sql_digest")==branch["selected_runner_digest"]==json_digest({"exact_runner_sql":bound.get("runner_sql")})
                and bound.get("identity_digest")==branch["selected_bound_runner_identity_digest"]==json_digest({key:bound[key] for key in bound_fields}),
                "physical branch original bound identity differs: "+label)
        require(all(bound.get(key)==identity[key] for key in ("snapshot_digest","database_identity_digest","session_contract_digest","registry_digest","catalog_digest"))
                and bound.get("session_contract")==spec.get("session_contract") and bound.get("execution_profile")==spec.get("execution_profile")
                and identity["guc_digest"]==json_digest(spec["session_contract"]["gucs"])
                and bound.get("continuation")==selection["bound_runner"].get("continuation")
                and bound.get("continuation_digest")==json_digest(bound.get("continuation")),"physical branch target/environment/continuation differs: "+label)
        access_root_wrapper_audit({"access_root_wrapper":"not_materialized_single_reference","access_root_materialized_by_template":layouts},bound["runner_sql"],label+" "+branch["recipe_id"],template_id=bound["template_id"])
        costs=branch.get("complete_runner_costs");eligibility=branch.get("completed_root_eligibility");root_audit=branch.get("root_selection_audit")
        require(isinstance(costs,list) and bool(costs) and type(eligibility) is dict and type(root_audit) is dict,"physical branch completed evidence missing: "+label)
        by_plan={row["plan_id"]:row for row in costs}
        require(len(by_plan)==len(costs) and eligibility.get("schema")=="e3_production_completed_root_eligibility_v1"
                and eligibility.get("planning_batch_digest")==branch["planning_batch_digest"]
                and eligibility.get("eligibility_digest")==json_digest({key:value for key,value in eligibility.items() if key!="eligibility_digest"})
                and sorted((row["template_id"],row["plan_id"]) for row in eligibility.get("completed_roots",[]))==sorted((row["template_id"],row["plan_id"]) for row in costs)
                and eligibility.get("evidence_failures")==[],"physical branch eligibility/batch commitment differs: "+label)
        for row in costs:
            number(row.get("prospective_total_cost"),label+" completed cost")
            digest_field(row.get("runner_sql_digest"),label+" completed SQL");digest_field(row.get("explain_plan_digest"),label+" completed EXPLAIN")
            require(row.get("access_root_materialized") is layouts.get(row["template_id"],False),"physical completed-root layout differs: "+label)
        survivors=root_audit.get("survivor_plan_ids")
        require(isinstance(survivors,list) and bool(survivors) and len(survivors)==len(set(survivors)) and set(survivors)<=set(by_plan)
                and root_audit.get("status") in {"selected","singleton_no_comparison"}
                and root_audit.get("frontier_complete") is True and root_audit.get("cost_evidence_complete") is True
                and root_audit.get("completed_root_count")==len(costs) and root_audit.get("chosen_plan_id")==branch["selected_plan_id"]
                and root_audit.get("tie_break")=="final_prospective_cost_then_plan_id"
                and root_audit.get("cost_evidence",{}).get("ok") is True
                and root_audit["cost_evidence"].get("cost_model_version")==identity["cost_model_version"]
                and root_audit["cost_evidence"].get("planning_environment_digest")==json_digest(identity),"physical original root selection differs: "+label)
        chosen=min((by_plan[plan] for plan in survivors),key=lambda row:(row["prospective_total_cost"],row["plan_id"]))
        minimum=chosen["prospective_total_cost"]
        require(chosen["plan_id"]==branch["selected_plan_id"] and chosen["template_id"]==branch["selected_template_id"]
                and chosen["runner_sql_digest"]==branch["selected_runner_digest"] and branch.get("prospective_total_cost")==minimum
                and root_audit.get("tied_minimum_plan_ids")==sorted(plan for plan in survivors if by_plan[plan]["prospective_total_cost"]==minimum),"physical selected full cost/minimum differs: "+label)
    winner=min(enumerate(branches),key=lambda item:(item[1]["prospective_total_cost"],item[0]))[1]
    require(physical.get("selected_recipe_id")==winner["recipe_id"] and physical.get("selected_plan_id")==winner["selected_plan_id"]
            and physical.get("selected_runner_digest")==winner["selected_runner_digest"] and physical.get("effective_layout_policy")==winner["layout_policy"]
            and selection.get("bound_runner")==winner["selected_bound_runner"] and spec.get("sql")==winner["selected_bound_runner"]["runner_sql"]
            and selection.get("selected_plan_id")==winner["selected_plan_id"] and selection.get("selected_runner_digest")==winner["selected_runner_digest"]
            and selection.get("selected_template_id")==winner["selected_template_id"] and selection.get("prospective_total_cost")==winner["prospective_total_cost"]
            and selection.get("complete_runner_costs")==winner["complete_runner_costs"]
            and selection.get("completed_root_eligibility")==winner["completed_root_eligibility"]
            and selection.get("root_selection_audit")==winner["root_selection_audit"],"physical minimum/tie rule or original winner handoff differs: "+label)
    effective={key:value for key,value in declared.items() if key!="physical_recipe_strategy"}
    effective["access_root_materialized_by_template"]=winner["layout_policy"]["materialized_by_template"]
    require(metadata.get("resolved_runtime_config")==effective and metadata.get("runtime_config_sha256")==json_digest(effective)
            and selection.get("access_root_materialized_by_template")==effective["access_root_materialized_by_template"]
            and selection.get("access_root_layout_policy")==winner["layout_policy"],"physical effective runtime/layout differs: "+label)
    resolved={**protocol,"access_root_materialized_by_template":effective["access_root_materialized_by_template"],
              "_physical_recipe_validated":_VALIDATED_PHYSICAL_RECIPE,"_physical_recipe_runner_digest":winner["selected_runner_digest"]}
    return resolved,{"case_id":label,"status":"verified","strategy":strategy,"selected_recipe_id":winner["recipe_id"],
        "decision_digest":physical["decision_digest"],"recipe_costs":[{"recipe_id":b["recipe_id"],"prospective_total_cost":b["prospective_total_cost"]} for b in branches],
        "effective_materialized_by_template":effective["access_root_materialized_by_template"],"query_plan_digests_recomputed":False,"planning_batch_digests_recomputed":False}


def access_root_wrapper_audit(protocol: Mapping[str, Any], sql: str,
                              label: str, *, template_id: str | None = None) -> dict[str, Any]:
    """Check the retained resolved composition, without rerendering a manifest.

    Older campaigns did not serialize these protocol fields. Their existing
    exact SQL/profile audits remain applicable; new declarations must agree
    with both the explicit override and the actual bound query.
    """
    if protocol.get("physical_recipe_strategy") is not None:
        require(protocol.get("_physical_recipe_validated") is _VALIDATED_PHYSICAL_RECIPE and
                protocol.get("_physical_recipe_runner_digest")==json_digest({"exact_runner_sql":sql}),"physical recipe must be validated before wrapper audit: "+label)
    declared = protocol.get("access_root_wrapper")
    override = protocol.get("access_root_wrapper_override")
    layouts = _materialization_layouts(protocol.get("access_root_materialized_by_template", {}), label)
    layout_override = protocol.get("access_root_materialized_by_template_override")
    if layout_override is not None:
        require(_materialization_layouts(layout_override, label) == layouts,
                "resolved per-template layout disagrees with explicit override: "+label)
    if layouts:
        require(type(template_id) is str and bool(template_id),
                "per-template layout lacks selected template identity: "+label)
    decoded = decode_access_root_materialized(sql)
    actual = (None if decoded is None else
              "materialized" if decoded else "not_materialized_single_reference")
    expected = declared
    if ("access_root_wrapper" in protocol or "access_root_wrapper_override" in protocol
            or "access_root_materialized_by_template" in protocol):
        supported = {"materialized", "not_materialized_single_reference"}
        require(type(declared) is str and declared in supported,
                "invalid resolved access-root wrapper: "+label)
        require(override is None or (type(override) is str and override in supported),
                "invalid access-root wrapper override: "+label)
        require(override is None or override == declared,
                "resolved access-root wrapper disagrees with explicit override: "+label)
        expected = ("materialized" if layouts.get(template_id, declared == "materialized")
                    else "not_materialized_single_reference")
        require(actual == expected,
                "bound SQL access-root wrapper disagrees with resolved protocol: "+label)
    return {"case_id": label, "declared_wrapper": declared,
            "explicit_override": override, "observed_bound_sql_wrapper": actual,
            "selected_template_id": template_id, "expected_selected_wrapper": expected,
            "materialized_by_template": layouts, "materialized_by_template_override": layout_override,
            "declaration_recorded": "access_root_wrapper" in protocol}


def access_root_layout_policy_audit(protocol: Mapping[str, Any], selection: Mapping[str, Any],
                                   wrapper: Mapping[str, Any], label: str) -> dict[str, Any]:
    if protocol.get("physical_recipe_strategy") is not None:
        require(protocol.get("_physical_recipe_validated") is _VALIDATED_PHYSICAL_RECIPE and
                protocol.get("_physical_recipe_runner_digest")==selection.get("selected_runner_digest"),
                "physical recipe must be validated before layout audit: "+label)
    layouts = wrapper["materialized_by_template"]
    recorded = "access_root_materialized_by_template" in protocol
    if recorded:
        require(selection.get("access_root_materialized_by_template") == layouts,
                "selected worker per-template layout differs from protocol: "+label)
    policy = selection.get("access_root_layout_policy")
    rows = selection.get("access_root_layouts", [])
    if layouts or policy is not None:
        require(isinstance(policy, dict) and policy.get("schema") == "e3_access_root_layout_policy_v1"
                and policy.get("base_materialized") is (wrapper["declared_wrapper"] == "materialized")
                and policy.get("materialized_by_template") == layouts,
                "production layout policy differs from resolved protocol: "+label)
        require(isinstance(rows, list) and rows, "production layout observations are missing: "+label)
        by_plan = {}
        for row in rows:
            require(isinstance(row, dict) and type(row.get("plan_id")) is str and row["plan_id"]
                    and type(row.get("template_id")) is str and row["template_id"]
                    and row["plan_id"] not in by_plan,
                    "production layout observation identity is invalid: "+label)
            expected = layouts.get(row["template_id"], policy["base_materialized"])
            require(row.get("access_root_materialized") is expected,
                    "completed root layout differs from template policy: "+label)
            digest_field(row.get("runner_sql_digest"), label+" completed root layout")
            by_plan[row["plan_id"]] = row
        for cost in selection.get("complete_runner_costs", []):
            row = by_plan.get(cost.get("plan_id"))
            require(row is not None and cost.get("template_id") == row["template_id"]
                    and cost.get("runner_sql_digest") == row["runner_sql_digest"]
                    and cost.get("access_root_materialized") is row["access_root_materialized"],
                    "complete-runner cost/layout binding differs: "+label)
        chosen = [row for row in rows if row.get("plan_id") == selection.get("selected_plan_id")]
        require(len(chosen) == 1 and chosen[0].get("template_id") == selection.get("selected_template_id")
                and chosen[0].get("access_root_materialized") is (wrapper["observed_bound_sql_wrapper"] == "materialized")
                and chosen[0].get("runner_sql_digest") == selection.get("selected_runner_digest"),
                "selected production layout does not match its bound runner: "+label)
    return {"case_id": label, "declaration_recorded": recorded,
            "production_policy": policy, "completed_root_layouts": rows}


def normal_entry_audit(protocol: Mapping[str, Any], spec: Mapping[str, Any],
                       selection: Mapping[str, Any], profile: Mapping[str, Any], *,
                       query: str, policy: str, label: str) -> dict[str, Any]:
    """Audit an extra normal body execution, separately from full-result checks."""
    if protocol.get("_physical_recipe_validated") is not _VALIDATED_PHYSICAL_RECIPE:
        protocol, _physical = physical_recipe_protocol_audit(protocol,spec,selection,query=query,policy=policy,label=label)
    requested = protocol.get("normal_entry_execution_check", False)
    require(type(requested) is bool, "invalid normal-entry execution declaration: "+label)
    if not requested:
        return {"case_id": label, "status": "not_requested", "requested": False,
                "preparation_marker_recorded": selection.get("normal_entry_used") is True,
                "normal_execution_verified": False,
                "independent_result_correctness_checked_by_normal_api": None}
    require(selection.get("normal_entry_used") is True,
            "required normal AF entry was not used: "+label)
    metadata, executed = selection.get("normal_entry_metadata"), selection.get("normal_execution_check")
    require(type(metadata) is dict and metadata.get("schema") == "normal_e3_af_prepared_v1",
            "missing normal-entry prepared metadata: "+label)
    require(metadata.get("source_identity") == protocol.get("current_source") and
            {"caprls_core/normal_e3_af.py", "configs/normal_e3_af_candidate.yaml"}
            <= set(protocol["current_source"]["files"]),
            "normal-entry source identity differs or lacks its API/configuration: "+label)
    require((metadata.get("query_id"), metadata.get("policy_id")) == (query, policy) and
            metadata.get("algorithm_mode") == "admission-first" and
            metadata.get("configuration_status") == "candidate_not_accepted" and
            metadata.get("database_or_artifact_maintenance_performed") is False,
            "normal-entry case/mode/configuration metadata differs: "+label)
    require(metadata.get("manifest_sha256") == protocol.get("manifest_sha256") and
            type(metadata.get("manifest")) is str and type(protocol.get("manifest")) is str and
            Path(metadata["manifest"]).resolve() == Path(protocol["manifest"]).resolve(),
            "normal-entry manifest identity differs: "+label)
    config = metadata.get("resolved_runtime_config")
    config_keys = {"schema", "name", "configuration_status", "execution_profile", "access_root_wrapper"}
    require(type(config) is dict and config_keys <= set(config) <= config_keys | {"access_root_materialized_by_template"} and
            config.get("schema") == "normal_e3_af_runtime_v1" and
            type(config.get("name")) is str and bool(config["name"]) and
            config.get("configuration_status") == "candidate_not_accepted" and
            config.get("execution_profile") == "trusted_explicit" and
            metadata.get("runtime_config_sha256") == json_digest(config),
            "normal-entry resolved configuration or digest differs: "+label)
    wrapper = access_root_wrapper_audit(protocol, spec["sql"], label, template_id=spec.get("template_id"))
    config_layouts = _materialization_layouts(config.get("access_root_materialized_by_template", {}), label)
    config_expected = ("materialized" if config_layouts.get(spec.get("template_id"), config.get("access_root_wrapper") == "materialized")
                       else "not_materialized_single_reference")
    require(wrapper["observed_bound_sql_wrapper"] is not None and
            config.get("access_root_wrapper") in {"materialized", "not_materialized_single_reference"} and
            (wrapper["declared_wrapper"] is None or config.get("access_root_wrapper") == wrapper["declared_wrapper"]) and
            config_layouts == wrapper["materialized_by_template"] and
            config_expected == wrapper["observed_bound_sql_wrapper"],
            "normal-entry configuration differs from actual bound wrapper: "+label)
    require(type(executed) is dict and executed.get("schema") == "normal_e3_af_execution_v1" and
            executed.get("status") == "executed" and
            executed.get("configuration_status") == "candidate_not_accepted",
            "missing normal-entry executed receipt: "+label)
    require(executed.get("exact_bound_sql_sha256") == sha(spec["sql"].encode()) and
            type(executed.get("query_body_executions")) is int and executed["query_body_executions"] == 1,
            "normal-entry executed body identity/count differs: "+label)
    digest_field(executed.get("transaction_script_sha256"), label+" normal transaction script")
    require(executed.get("independent_result_correctness_checked") is False,
            "normal-entry execution was relabeled as independent correctness: "+label)
    number(executed.get("client_execution_wall_ms"), label+" normal execution client time")
    raw = executed.get("raw_output")
    require(type(raw) is str and bool(raw), "normal-entry raw output is missing: "+label)
    prefix = "CAPRLS_E3_EXECUTION_ENV_V1:"
    observations = [line[len(prefix):] for line in raw.splitlines() if line.startswith(prefix)]
    require(len(observations) == 1, "normal-entry raw environment observation count differs: "+label)
    try:
        observed = json.loads(observations[0])
    except ValueError as exc:
        raise AnalysisError("invalid normal-entry raw environment: "+label) from exc
    require(observed == executed.get("execution_environment"),
            "normal-entry raw/parsed execution environment differs: "+label)
    execution_environment_audit(observed, profile, label+" normal execution")
    return {"case_id": label, "status": "verified", "requested": True,
            "normal_execution_verified": True, "metadata_schema": metadata["schema"],
            "runtime_config_sha256": metadata["runtime_config_sha256"],
            "exact_bound_sql_sha256": executed["exact_bound_sql_sha256"],
            "transaction_script_sha256": executed["transaction_script_sha256"],
            "raw_output_sha256": sha(raw.encode()), "query_body_executions": 1,
            "independent_result_correctness_checked_by_normal_api": False,
            "execution_environment": observed,
            "client_execution_wall_ms": executed["client_execution_wall_ms"]}


def validated_schedule(record: Mapping[str, Any], eligible: Sequence[str],
                       minimum: int, *, protocol_schedule: str = LEGACY_PROTOCOL_SCHEDULE
                       ) -> tuple[int, int, list[list[int]]]:
    """Keep legacy balance checks; independently reconstruct the optional pair schedule."""
    require(protocol_schedule in (LEGACY_PROTOCOL_SCHEDULE, ADJACENT_SAMPLING_SCHEDULE),
            "unknown sampling schedule")
    adjacent = protocol_schedule == ADJACENT_SAMPLING_SCHEDULE
    require(record.get("correctness_only") is False, "correctness-only sampling")
    require(record.get("modes") == list(eligible), "sampling applicable-mode inventory/order mismatch")
    rep = record.get("repetitions")
    require(isinstance(rep, dict), "missing actual repetitions")
    n = len(eligible)
    require(n in (5, 6, 7), "unsupported applicable mode count")
    cycle = 2*(n-1) if adjacent else 2*n
    if adjacent:
        mode_map = _adjacent_mode_map(eligible)
        require(record.get("sampling_schedule") == ADJACENT_SAMPLING_SCHEDULE and
                json_digest(record.get("sampling_mode_map")) == json_digest(mode_map),
                "adjacent sampling mode map differs from applicable inventory")
        require(all(type(rep.get(key)) is int for key in (
            "available_modes", "cycle_rounds", "warmup", "measured", "minimum_measured")),
            "invalid adjacent repetition integer")
    else:
        require("sampling_schedule" not in record and "sampling_mode_map" not in record,
                "adjacent sampling declaration under legacy schedule")
    require(rep.get("available_modes") == n and rep.get("cycle_rounds") == cycle,
            "sampling cycle metadata mismatch")
    warm = integer(rep.get("warmup"), "warmup", minimum=1)
    measured = integer(rep.get("measured"), "measured", minimum=1)
    require(rep.get("minimum_measured") == minimum and warm == cycle and
            measured == math.ceil(minimum/cycle)*cycle, "repetition policy differs from declaration")
    rows = rep.get("round_order_indices")
    require(isinstance(rows, list) and len(rows) == cycle, "missing complete schedule period")
    for row in rows:
        require(isinstance(row, list) and len(row) == n and
                all(type(i) is int for i in row) and sorted(row) == list(range(n)),
                "invalid schedule permutation")
    if adjacent:
        expected_rows = [list(row) for row in _ADJACENT_ORDERS[n]]
        expected_rep = {"available_modes": n, "cycle_rounds": cycle, "warmup": cycle,
            "measured": math.ceil(minimum/cycle)*cycle, "minimum_measured": minimum,
            "reason": _ADJACENT_REASON, "round_order_indices": expected_rows}
        require(json_digest(rep) == json_digest(expected_rep),
                "adjacent repetitions or fixed rows differ from preregistration")
        positions = Counter((m, p) for row in rows for p, m in enumerate(row))
        require(all(positions[(0,p)] == positions[(2,p)] for p in range(n)),
                "adjacent AF/IP raw positions differ")
        flat = [m for row in rows for m in row]
        transitions = Counter(zip([flat[-1]]+flat[:-1], flat))
        swap = lambda i: 2 if i == 0 else 0 if i == 2 else i
        require(all(transitions[(a,b)] == transitions[(swap(a),swap(b))]
                    for a in range(n) for b in range(n)),
                "adjacent actual carryover lacks AF/IP role symmetry")
    else:
        require(Counter((m, p) for row in rows for p, m in enumerate(row)) ==
                Counter({(m, p): 2 for m in range(n) for p in range(n)}), "unbalanced schedule positions")
        flat = [m for row in rows for m in row]
        require(Counter(zip([flat[-1]]+flat[:-1], flat)) ==
                Counter({(a, b): 2 for a in range(n) for b in range(n)}),
                "unbalanced schedule predecessors, including self")
    return warm, measured, rows


def audit_measurement(value: Any, spec: Mapping[str, Any], script_digest: str,
                      profile: Mapping[str, Any] | None, label: str,
                      reference_rows: int | None = None) -> dict[str, Any]:
    require(isinstance(value, dict), "missing measurement: "+label)
    for field in MEASURES.values():
        number(value.get(field), label+":"+field, positive=field in METRICS.values())
    require(value.get("measurement_script_sha256") == script_digest, "measurement script digest mismatch: "+label)
    require(value.get("query_executions") == 1, "query was not executed exactly once: "+label)
    explain = value.get("query_explain")
    require(isinstance(explain, dict) and isinstance(explain.get("Plan"), dict), "missing query EXPLAIN: "+label)
    close(explain.get("Execution Time"), value["execution_ms"], "EXPLAIN execution time")
    close(explain.get("Planning Time"), value["postgres_planning_ms"], "EXPLAIN planning time")
    close(value["server_body_planning_execution_ms"], value["execution_ms"]+value["postgres_planning_ms"], "query body time")
    validations = value.get("validation_observations")
    require(isinstance(validations, list) and len(validations) == len(spec.get("artifact_ids", [])) and
            value.get("artifact_validation_executions") == len(validations), "artifact validation count mismatch: "+label)
    total = 0.0
    for index, item in enumerate(validations):
        require(item.get("index") == index, "artifact validation order mismatch: "+label)
        exp = item.get("explain")
        require(isinstance(exp, dict) and isinstance(exp.get("Plan"), dict), "missing artifact EXPLAIN: "+label)
        total += number(exp.get("Execution Time"), label+" validation execution") + number(exp.get("Planning Time"), label+" validation planning")
    close(total, value["server_validation_ms"], "artifact validation total")
    close(value["server_query_plus_required_validation_observed_ms"],
          value["server_body_planning_execution_ms"]+total+value["server_guard_body_execution_ms"], "observed server total")
    require(isinstance(value.get("raw_output"), str) and value["raw_output"], "missing raw measurement output: "+label)
    lines = value["raw_output"].splitlines()
    def raw_section(begin: str, end: str) -> tuple[Any, str]:
        require(lines.count(begin) == lines.count(end) == 1, "missing or duplicate raw timing frame: "+label)
        left, right = lines.index(begin), lines.index(end)
        require(left < right, "reversed raw timing frame: "+label)
        content = "\n".join(lines[left+1:right])
        try:
            parsed = json.loads(content)
        except ValueError as exc:
            raise AnalysisError("invalid raw EXPLAIN JSON: "+label) from exc
        require(isinstance(parsed, list) and len(parsed) == 1, "raw EXPLAIN document count mismatch: "+label)
        return parsed[0], content
    raw_query, _ = raw_section("FINAL_AF_QUERY_BEGIN", "FINAL_AF_QUERY_END")
    require(raw_query == explain, "raw/parsed query EXPLAIN differs: "+label)
    raw_indices = [int(match.group(1)) for line in lines
                   if (match := re.fullmatch(r"FINAL_AF_VALIDATION_BEGIN_([0-9]+)", line))]
    require(raw_indices == list(range(len(validations))), "raw artifact validation inventory differs: "+label)
    for index, item in enumerate(validations):
        raw_validation, raw_text = raw_section(f"FINAL_AF_VALIDATION_BEGIN_{index}", f"FINAL_AF_VALIDATION_END_{index}")
        require(raw_validation == item["explain"] and raw_text == item.get("explain_raw"), "raw/parsed artifact EXPLAIN differs: "+label)
    guards = [line[len("FINAL_AF_GUARD_BODY_MS "):] for line in lines if line.startswith("FINAL_AF_GUARD_BODY_MS ")]
    raw_environments = [line[len("CAPRLS_E3_EXECUTION_ENV_V1:"):] for line in lines if line.startswith("CAPRLS_E3_EXECUTION_ENV_V1:")]
    if profile is not None:
        require(len(guards) == len(raw_environments) == 1, "AF guard/environment raw observation count differs: "+label)
        try:
            guard = float(guards[0])
            environment = json.loads(raw_environments[0])
        except ValueError as exc:
            raise AnalysisError("invalid raw AF observation: "+label) from exc
        close(guard, value["server_guard_body_execution_ms"], "raw AF guard time")
        require(environment == value.get("execution_environment"), "raw/parsed execution environment differs: "+label)
        execution_environment_audit(value.get("execution_environment"), profile, label)
    else:
        require(not guards and not raw_environments and value.get("execution_environment") is None and value["server_guard_body_execution_ms"] == 0,
                "ordinary baseline carries AF execution instrumentation: "+label)
    root_plan = raw_query["Plan"]
    result_count = {"status": "not_requested", "reference_rows": reference_rows,
                    "root_actual_rows": root_plan.get("Actual Rows"),
                    "root_actual_loops": root_plan.get("Actual Loops")}
    if reference_rows is not None:
        if "Actual Rows" not in root_plan or "Actual Loops" not in root_plan:
            result_count["status"] = "root_output_count_not_available"
        else:
            def has_parallel(node: Mapping[str, Any]) -> bool:
                return (node.get("Parallel Aware") is True or node.get("Node Type") in ("Gather", "Gather Merge") or
                        number(node.get("Workers Launched", 0), "workers launched") > 0 or
                        any(has_parallel(child) for child in node.get("Plans", [])))
            require(root_plan["Actual Loops"] == 1 and not has_parallel(root_plan),
                    "root output count requires one loop and nonparallel execution: "+label)
            actual_rows = number(root_plan["Actual Rows"], "root actual rows")
            require(actual_rows == reference_rows,
                    f"root result row count {actual_rows} differs from full reference {reference_rows}: "+label)
            result_count["status"] = "verified_against_full_reference"
    return result_count


def _seed(seed: int, label: str) -> int:
    return int.from_bytes(hashlib.sha256((str(seed)+":"+label).encode()).digest()[:8], "big")


def _interval(values: Sequence[float]) -> dict[str, Any]:
    ordered = sorted(values)
    low, high = percentile(ordered, .025), percentile(ordered, .975)
    return {"ci95_lower": low, "ci95_upper": high,
            "classification": "W" if low > 1 else "L" if high < 1 else "N"}


def compare_vectors(vectors: Mapping[str, tuple[Sequence[float], Sequence[float]]], *,
                    draws: int, seed: int, label: str,
                    cycles: Mapping[str, int]) -> dict[str, Any]:
    """Paired rounds per case; each bootstrap draw preserves the fixed case grid."""
    require(bool(vectors), "empty comparison grid")
    integer(draws, "bootstrap draws", minimum=1)
    per_case, boot_logs = [], [0.0]*draws
    for case, (af, baseline) in vectors.items():
        require(len(af) == len(baseline) and bool(af), "unequal paired vectors")
        af = [number(v, "AF timing", positive=True) for v in af]
        baseline = [number(v, "baseline timing", positive=True) for v in baseline]
        rng = random.Random(_seed(seed, label+":"+case))
        ratios = []
        n = len(af)
        for draw in range(draws):
            idx = [rng.randrange(n) for _ in range(n)]
            ratio = statistics.median(baseline[i] for i in idx)/statistics.median(af[i] for i in idx)
            ratios.append(ratio)
            boot_logs[draw] += math.log(ratio)
        per_case.append({"case_id": case, "af_median_ms": statistics.median(af),
                         "baseline_median_ms": statistics.median(baseline),
                         "ratio": statistics.median(baseline)/statistics.median(af),
                         "paired_rounds": n, "bootstrap_seed": _seed(seed, label+":"+case),
                         **_interval(ratios)})
    wnl = Counter(item["classification"] for item in per_case)
    gm = math.exp(statistics.mean(math.log(item["ratio"]) for item in per_case))
    cycle_results = []
    count = max(len(a)//cycles[c] for c, (a, _) in vectors.items())
    for index in range(count):
        members = []
        for case, (af, baseline) in vectors.items():
            step = cycles[case]
            if (index+1)*step <= len(af):
                aa, bb = af[index*step:(index+1)*step], baseline[index*step:(index+1)*step]
                members.append({"case_id": case, "paired_rounds": step,
                                "ratio": statistics.median(bb)/statistics.median(aa)})
        cycle_results.append({"cycle_index": index, "case_count": len(members), "cases": members,
            "geometric_mean_ratio": math.exp(statistics.mean(math.log(v["ratio"]) for v in members))})
    return {"case_count": len(per_case), "cases": per_case,
            "geometric_mean_ratio": gm, **_interval([math.exp(v/len(per_case)) for v in boot_logs]),
            "W": wnl["W"], "N": wnl["N"], "L": wnl["L"], "bootstrap_draws": draws,
            "cycle_sensitivity": cycle_results}


def _expected_paths(root: Path, folder: str, expected: set[str]) -> None:
    actual = {p.relative_to(root).as_posix() for p in (root/folder).rglob("*") if p.is_file()}
    require(actual == expected, "missing or unexpected files under "+folder)


def _choice(selection: Mapping[str, Any], shared: Mapping[str, Any], label: str) -> dict[str, Any]:
    breakdown = selection.get("selection_breakdown")
    require(isinstance(breakdown, dict) and breakdown.get("schema") == "caprls-selection-cost-breakdown-v1",
            "missing observed selection breakdown: "+label)
    exclusive = breakdown.get("exclusive_ms")
    require(isinstance(exclusive, dict) and exclusive, "missing exclusive choice categories")
    for category, value in exclusive.items():
        number(value, label+":"+category)
    # Breakdown rounds individual categories to six decimals.
    total = number(breakdown.get("total_wall_ms"), label+" selection total")
    require(math.isclose(sum(exclusive.values()), total, abs_tol=1e-4), "choice categories do not conserve total")
    close(selection.get("selection_wall_ms"), total, "choice measured total")
    vector = selection.get("candidate_cost_vector")
    require(isinstance(vector, list) and vector, "missing prospective candidate costs")
    for item in vector:
        require(type(item.get("accepted")) is bool and isinstance(item.get("rejection_reasons"), list), "invalid prospective candidate")
        if item.get("estimated_cost") is not None:
            number(item["estimated_cost"], "candidate estimated cost")
    require(any(item.get("accepted") and item.get("template_id") == selection.get("selected_template_id") for item in vector),
            "selected template absent from admitted candidate vector")
    return {"case_id": label, "selection_wall_ms": total,
            "catalog_receipt_wall_ms": number(selection.get("catalog_receipt_wall_ms"), "catalog receipt"),
            "input_collection_wall_ms": number(shared["stats"].get("input_collection_wall_ms"), "input collection"),
            "exclusive_ms": exclusive, "inclusive_ms": breakdown.get("inclusive_ms"),
            "coverage": breakdown.get("coverage"), "sql_call_counts": breakdown.get("sql_call_counts"),
            "candidate_cost_vector": vector}


def analyze_run(input_dir: Path, *, draws: int = 10000, seed: int = 20261028) -> dict[str, Any]:
    root = input_dir.resolve()
    require(root.is_dir(), "input directory does not exist")
    initial = inventory(root)
    require("failure.json" not in initial, "campaign has a failure receipt")
    protocol = read_json(root, "protocol.json")
    require(protocol.get("schema") == "final_af_e3_study_v1", "unsupported protocol schema")
    require(protocol.get("correctness_only") is False, "correctness-only run has no formal timing results")
    modes = unique_strings(protocol.get("modes"), "modes")
    require(tuple(modes) in (PRIMARY_MODES, ALL_MODES), "ordinary baseline set/order differs from protocol family")
    protocol_schedule = sampling_protocol_audit(protocol)
    require(protocol.get("primary_metric") == "median_postgres_query_execution_ms" and
            protocol.get("primary_scope") == "postgresql_generated_query_Execution_Time_TIMING_OFF" and
            protocol.get("existing_paper_server_metric") == "median_server_query_plus_required_validation_observed_ms" and
            protocol.get("required_af_execution_profile") == "trusted_explicit", "measurement/profile scope differs")
    require(protocol.get("baseline_implementation") == "normal_fixed_specs_from_unchanged_baseline_source", "unsupported baseline implementation")
    minimum = integer(protocol.get("minimum_measured"), "minimum measured", minimum=1)
    for field in ("manifest_sha256", "driver_sha256"):
        digest_field(protocol.get(field), field)
    sources = {"af": source_digest(protocol.get("current_source"), "AF source"),
               "fixed": source_digest(protocol.get("baseline_source"), "baseline source")}
    queries = unique_strings(protocol.get("queries"), "queries")
    policies = unique_strings(protocol.get("policies"), "policies")
    require(all("/" not in v and "\\" not in v and v not in (".", "..") for v in queries+policies), "unsafe case identifier")
    labels = {q+"__"+p: (q, p) for q in queries for p in policies}
    require(len(labels) == len(queries)*len(policies), "ambiguous case identifiers")
    expected = {(c, m) for c in labels for m in modes}
    terminal = read_json(root, "summary.json")
    require(terminal.get("status") == "completed" and terminal.get("cells") == len(labels) and
            terminal.get("mode_results") == len(expected), "campaign lacks complete terminal summary")
    try:
        require(datetime.fromisoformat(terminal["finished_at"]) >= datetime.fromisoformat(protocol["started_at"]), "terminal precedes start")
    except (KeyError, TypeError, ValueError) as exc:
        raise AnalysisError("invalid campaign timestamps") from exc
    rows = indexed_rows(terminal.get("summary"), expected, "summary")
    with (root/"summary.csv").open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        require(reader.fieldnames and len(reader.fieldnames) == len(set(reader.fieldnames)), "invalid summary CSV headers")
        csvrows = indexed_rows(list(reader), expected, "summary CSV")
    for key in expected:
        csv_matches_json(csvrows[key], rows[key], str(key))
    before, after = (read_json(root, name) for name in ("statistics_before_selection.json", "statistics_after_sampling.json"))
    require(before == after and isinstance(before.get("catalog_statistics"), dict) and
            isinstance(before["catalog_statistics"].get("relations"), list) and
            isinstance(before["catalog_statistics"].get("statistics"), list) and
            before.get("digest") == json_digest(before["catalog_statistics"]), "planner statistics changed or digest invalid")
    database = read_json(root, "database.json")
    require(isinstance(database.get("pg_env"), dict), "missing database identity")
    artifacts = read_json(root, "shared_artifacts.json")
    require(isinstance(artifacts, dict) and artifacts, "missing shared artifacts")
    for item in artifacts.values():
        number(item.get("artifact_build_ms"), "artifact build")
        integer(item.get("artifact_rows"), "artifact rows")
        integer(item.get("keyed_artifact_rows"), "keyed artifact rows")
    cells, choices, availability, sql_groups, profiles, observations, execution_counts = {}, [], [], [], [], [], []
    wrappers, normal_entries, layout_policies, physical_recipes = [], [], [], []
    allowed_prepared, allowed_scripts, allowed_samples, allowed_diagnostics = set(), set(), set(), set()
    for case, (query, policy) in labels.items():
        shared = read_json(root, "prepared/"+case+"/shared.json")
        require((shared.get("case_id"), shared.get("query_id"), shared.get("policy_id")) == (case, query, policy), "prepared identity mismatch")
        entries = shared.get("modes")
        require(isinstance(entries, list) and [e.get("mode") for e in entries] == modes, "prepared mode inventory mismatch")
        entries = {e["mode"]: e for e in entries}
        workers = {}
        for kind in ("af", "fixed"):
            path = "prepared/"+case+"/"+kind+".json"
            allowed_prepared.add(path)
            worker = read_json(root, path)
            require(worker.get("schema") == "final_af_e3_worker_v1" and worker.get("status") == "pass", "failed preparation worker: "+path)
            require(worker.get("source_identity") == protocol["current_source" if kind == "af" else "baseline_source"] and
                    worker.get("manifest_sha256") == protocol["manifest_sha256"], "worker source/manifest mismatch")
            workers[kind] = worker
        allowed_prepared.add("prepared/"+case+"/shared.json")
        af, fixed = workers["af"], workers["fixed"]
        require((af.get("variant"), af.get("query_id"), af.get("policy_id")) == ("af", query, policy) and
                fixed.get("worker_kind") == "fixed", "worker identity mismatch")
        require(shared.get("reference") == fixed.get("reference"), "baseline reference changed")
        require(isinstance(fixed.get("fixed_modes"), list) and [e.get("mode") for e in fixed["fixed_modes"]] == modes[1:], "fixed baseline inventory mismatch")
        fixed_entries = {e["mode"]: e for e in fixed["fixed_modes"]}
        spec, selection = af.get("spec"), af.get("selection")
        require(isinstance(spec, dict) and isinstance(selection, dict), "missing AF selected spec")
        bound = selection.get("bound_runner")
        require(isinstance(bound, dict) and isinstance(spec.get("sql"), str) and spec["sql"] and
                bound.get("runner_sql") == spec["sql"], "AF bound/executed SQL mismatch")
        require(selection.get("selected_runner_digest") == bound.get("runner_sql_digest") == json_digest({"exact_runner_sql": spec["sql"]}), "AF runner digest mismatch")
        require(selection.get("selected_template_id") == bound.get("template_id") == spec.get("template_id") and
                selection.get("selected_plan_id") == bound.get("plan_id") and
                (bound.get("query_id"), bound.get("policy_id")) == (query, policy), "AF plan/template/case binding mismatch")
        require(selection.get("measured_runtime_used_for_selection") is False, "selection used measured runtime")
        require(entries["af"].get("spec") == spec and entries["af"].get("selection") == selection, "prepared AF changed")
        case_protocol, physical = physical_recipe_protocol_audit(protocol,spec,selection,query=query,policy=policy,label=case)
        physical_recipes.append(physical)
        wrappers.append(access_root_wrapper_audit(case_protocol, spec["sql"], case, template_id=spec.get("template_id")))
        layout_policies.append(access_root_layout_policy_audit(case_protocol, selection, wrappers[-1], case))
        profile = execution_profile_audit(spec, selection, query=query, policy=policy,
            pg_env=database["pg_env"], required_profile="trusted_explicit", label=case+":af")
        normal_entries.append(normal_entry_audit(case_protocol, spec, selection, profile,
            query=query, policy=policy, label=case))
        choices.append(_choice(selection, shared, case))
        eligible = [m for m in modes if entries[m].get("spec") is not None]
        require("af" in eligible, "AF unavailable; campaign cannot produce complete performance comparisons")
        sampledecl = read_json(root, "sampling/"+case+".json")
        require(sampledecl.get("case_id") == case, "sampling case mismatch")
        warm, measured, orders = validated_schedule(sampledecl, eligible, minimum,
                                                   protocol_schedule=protocol_schedule)
        require(protocol.get("balanced_round_order_indices", {}).get(str(len(eligible))) == orders, "case/protocol schedules differ")
        correctness = read_json(root, "correctness/"+case+".json")
        require(correctness.get("method") == "full_row_jsonb_multiset_equality" and
                set(correctness.get("modes", {})) == set(modes), "correctness denominator/method mismatch")
        reference = canonical_bag(correctness.get("reference"), case+" reference")
        scripts, groups = {}, defaultdict(list)
        cell = {"entries": entries, "vectors": {m: {metric: [] for metric in METRICS} for m in eligible},
                "cycle": len(orders), "measured": measured, "shared": shared}
        for mode in modes:
            entry, row, check = entries[mode], rows[(case, mode)], correctness["modes"][mode]
            mspec = entry.get("spec")
            require((row.get("query_id"), row.get("policy_id")) == (query, policy), "summary case label mismatch")
            require(row.get("source_digest") == entry.get("source_digest") == sources["af" if mode == "af" else "fixed"], "mode source identity mismatch")
            require(row.get("warmup_repetitions") == warm and row.get("measured_repetitions") == (measured if mspec is not None else 0), "summary repetitions mismatch")
            if mode != "af":
                require({k: v for k, v in entry.items() if k != "source_digest"} == fixed_entries[mode], "ordinary baseline was changed after preparation")
                require(row.get("selection_wall_ms") is None and row.get("catalog_receipt_wall_ms") is None, "AF choice charged to baseline")
            else:
                for field in ("selection_wall_ms", "catalog_receipt_wall_ms"):
                    close(row.get(field), selection.get(field), "AF "+field)
                close(entry.get("worker_request_wall_ms"), af.get("worker_request_wall_ms"), "AF worker time")
                close(row.get("worker_request_wall_ms_infrastructure_only"), af.get("worker_request_wall_ms"), "summary AF worker time")
            close(row.get("input_collection_wall_ms"), shared["stats"]["input_collection_wall_ms"] if mode == "af" else 0, "input cost")
            close(row.get("artifact_build_ms_shared_setup"), shared["stats"]["artifact_build_ms"], "build cost")
            availability.append({"case_id": case, "mode": mode, "status": row.get("status"),
                "unavailable_reason": entry.get("unavailable_reason"), "measured_rounds": row["measured_repetitions"]})
            if mspec is None:
                require(mode != "af" and isinstance(entry.get("unavailable_reason"), str) and entry["unavailable_reason"] and
                        check == {"status": "unavailable", "reason": entry["unavailable_reason"]} and row.get("status") == "unavailable" and
                        row.get("template_id") is None and all(row.get(k) is None for k in MEASURES) and
                        row.get("first_use_estimate_ms_excluding_artifact_build") is None and row.get("first_use_estimate_with_artifact_build_ms") is None,
                        "unavailable mode not faithfully retained")
                continue
            require(mspec.get("mode") == mode and isinstance(mspec.get("sql"), str) and mspec["sql"] and
                    row.get("template_id") == mspec.get("template_id") and row.get("status") == "pass", "invalid available mode spec/summary")
            require(mspec.get("result_columns") == shared["reference"].get("result_columns") and mspec.get("result_columns"), "result contract differs")
            require(all(a in artifacts for a in mspec.get("artifact_ids", [])), "required artifact was not prepared")
            if mode != "af":
                require(mspec.get("session_contract") is None and mspec.get("execution_profile") is None, "ordinary baseline has AF profile")
                number(entry.get("generation_wall_ms"), "baseline generation time")
            require(check.get("status") == "pass" and check.get("actual_only_rows") == check.get("reference_only_rows") == 0 and
                    canonical_bag(check.get("actual"), case+":"+mode) == reference, "full reference result check failed")
            script_path = "measurement-scripts/"+case+"/"+mode+".sql"
            allowed_scripts.add(script_path)
            script = (root/script_path).read_bytes()
            require(mspec["sql"] in script.decode(), "measurement script does not contain exact bound query")
            scripts[mode] = sha(script)
            groups[sha(mspec["sql"].encode())].append(mode)
        sql_groups.extend({"case_id": case, "sql_sha256": digest, "modes": members,
                           "contains_af": "af" in members} for digest, members in groups.items() if len(members) > 1)
        previous = None
        collected = {m: [] for m in eligible}
        case_counts = {m: {"case_id": case, "mode": m, "reference_rows": sum(reference.values()),
            "warmup_query_executions": 0, "measured_query_executions": 0,
            "warmup_root_output_counts_verified": 0, "measured_root_output_counts_verified": 0,
            "root_output_count_unavailable": 0} for m in eligible}
        for round_index in range(warm+measured):
            phase = "warmup" if round_index < warm else "measured"
            iteration = round_index+1 if phase == "warmup" else round_index-warm+1
            for order_index, mode_index in enumerate(orders[round_index % len(orders)]):
                mode = eligible[mode_index]
                path = f"samples/{case}__{mode}__{phase}{iteration:02d}.json"
                allowed_samples.add(path)
                sample = read_json(root, path)
                require((sample.get("case_id"), sample.get("mode"), sample.get("phase"), sample.get("iteration"),
                         sample.get("round_index"), sample.get("order_index"), sample.get("preceding_mode")) ==
                        (case, mode, phase, iteration, round_index, order_index, previous), "sample schedule/identity mismatch: "+path)
                entry = entries[mode]
                require(sample.get("status") == "pass" and sample.get("sql_sha256") == sha(entry["spec"]["sql"].encode()) and
                        sample.get("source_identity") == entry["source_digest"] and sample.get("selection") == entry.get("selection"), "sample source/SQL/selection/status mismatch: "+path)
                measure = sample.get("measurement")
                count_check = audit_measurement(measure, entry["spec"], scripts[mode],
                    profile if mode == "af" else None, path, reference_rows=sum(reference.values()))
                case_counts[mode][phase+"_query_executions"] += 1
                if count_check["status"] == "verified_against_full_reference":
                    case_counts[mode][phase+"_root_output_counts_verified"] += 1
                else:
                    case_counts[mode]["root_output_count_unavailable"] += 1
                if mode == "af":
                    observations.append({"case_id": case, "phase": phase, "iteration": iteration,
                        "execution_environment": measure["execution_environment"]})
                if phase == "measured":
                    collected[mode].append(measure)
                    for metric, field in METRICS.items():
                        cell["vectors"][mode][metric].append(measure[field])
                previous = mode
        execution_counts.extend(case_counts.values())
        for mode in eligible:
            row, entry = rows[(case, mode)], entries[mode]
            for median_field, sample_field in MEASURES.items():
                close(row.get(median_field), statistics.median(s[sample_field] for s in collected[mode]), "summary median "+case+":"+mode+":"+median_field)
            sel = entry.get("selection") or {}
            first = row["median_end_to_end_ms_including_validation_and_client"] + sel.get("selection_wall_ms", 0) + sel.get("catalog_receipt_wall_ms", 0) + row["input_collection_wall_ms"] + entry.get("generation_wall_ms", 0)
            close(row.get("first_use_estimate_ms_excluding_artifact_build"), first, "first use estimate")
            close(row.get("first_use_estimate_with_artifact_build_ms"), first+(shared["stats"]["artifact_build_ms"] if mode == "af" or entry["spec"].get("artifact_ids") else 0), "first use with build")
            dpath = "diagnostics/"+case+"__"+mode+".json"
            if (root/dpath).is_file():
                allowed_diagnostics.add(dpath)
                diag = read_json(root, dpath)
                require(diag.get("sql") == entry["spec"]["sql"] and diag.get("sql_sha256") == sha(entry["spec"]["sql"].encode()) and
                        diag.get("role") == entry["spec"].get("role"), "diagnostic SQL/role mismatch")
                require(isinstance(diag.get("explain"), list) and len(diag["explain"]) == 1 and isinstance(diag["explain"][0].get("Plan"), dict), "invalid diagnostic EXPLAIN")
                if mode == "af":
                    execution_environment_audit(diag.get("execution_environment"), profile, dpath)
        profiles.append({"case_id": case, "profile_digest": profile["profile"]["profile_digest"],
                         "session_contract_digest": profile["contract"]["digest"],
                         "warmup_observations": warm, "measured_observations": measured,
                         "diagnostic_observed": "diagnostics/"+case+"__af.json" in allowed_diagnostics})
        cells[case] = cell
    for folder, expected_paths in (("prepared", allowed_prepared), ("measurement-scripts", allowed_scripts),
            ("samples", allowed_samples), ("diagnostics", allowed_diagnostics),
            ("correctness", {"correctness/"+c+".json" for c in labels}),
            ("sampling", {"sampling/"+c+".json" for c in labels})):
        _expected_paths(root, folder, expected_paths)
    require(not (root/"smoke-measurements").exists(), "instrumentation smoke output is not a formal performance campaign")
    comparisons, fastest, recovery = {}, {}, []
    cycles = {case: cell["cycle"] for case, cell in cells.items()}
    for metric, field in METRICS.items():
        comparisons[metric] = {}
        fastest[metric] = []
        for mode in modes[1:]:
            vectors = {case: (cell["vectors"]["af"][metric], cell["vectors"][mode][metric])
                       for case, cell in cells.items() if mode in cell["vectors"]}
            comparisons[metric][mode] = ({"applicable_cases": list(vectors),
                "unavailable_cases": [c for c in cells if c not in vectors],
                **compare_vectors(vectors, draws=draws, seed=seed, label=metric+":"+mode, cycles=cycles)}
                if vectors else {"case_count": 0, "applicable_cases": [], "unavailable_cases": list(cells), "status": "unavailable_on_entire_grid"})
        for case, cell in cells.items():
            medians = {mode: statistics.median(v[metric]) for mode, v in cell["vectors"].items()}
            best = min(medians.values())
            baseline_best = min(v for m, v in medians.items() if m != "af")
            fastest[metric].append({"case_id": case, "available_mode_medians_ms": medians,
                "minimum_mode_median_ms": best, "minimum_modes": [m for m, v in medians.items() if v == best],
                "af_over_fastest_applicable": medians["af"]/best,
                "minimum_ordinary_baseline_median_ms": baseline_best,
                "minimum_ordinary_baselines": [m for m, v in medians.items() if m != "af" and v == baseline_best],
                "af_over_fastest_ordinary_baseline": medians["af"]/baseline_best})
    fastest_summary = {}
    for metric, members in fastest.items():
        ratios = sorted(item["af_over_fastest_applicable"] for item in members)
        fastest_summary[metric] = {"case_count": len(members), "median_af_over_fastest": statistics.median(ratios),
            "p95_af_over_fastest": percentile(ratios, .95), "maximum_af_over_fastest": max(ratios),
            "af_matches_minimum_count": sum("af" in item["minimum_modes"] for item in members)}
    for case, cell in cells.items():
        arow = rows[(case, "af")]
        for mode in modes[1:]:
            if mode not in cell["vectors"]:
                continue
            brow = rows[(case, mode)]
            cost = arow["first_use_estimate_ms_excluding_artifact_build"]-arow["median_end_to_end_ms_including_validation_and_client"]-(brow["first_use_estimate_ms_excluding_artifact_build"]-brow["median_end_to_end_ms_including_validation_and_client"])
            with_build = arow["first_use_estimate_with_artifact_build_ms"]-arow["median_end_to_end_ms_including_validation_and_client"]-(brow["first_use_estimate_with_artifact_build_ms"]-brow["median_end_to_end_ms_including_validation_and_client"])
            for metric, field in METRICS.items():
                median_field = next(k for k, v in MEASURES.items() if v == field)
                saved = brow[median_field]-arow[median_field]
                recovery.append({"case_id": case, "baseline": mode, "metric": metric,
                    "observed_saving_per_reuse_ms": saved,
                    "incremental_one_time_estimate_ms": cost, "incremental_one_time_with_build_estimate_ms": with_build,
                    "estimated_reuses_to_recover": math.ceil(max(0, cost)/saved) if saved > 0 else None,
                    "estimated_reuses_to_recover_with_build": math.ceil(max(0, with_build)/saved) if saved > 0 else None,
                    "status": "positive_observed_saving" if saved > 0 else "no_positive_observed_saving"})
    choice_summary = {field: statistics.median(row[field] for row in choices)
                      for field in ("selection_wall_ms", "catalog_receipt_wall_ms", "input_collection_wall_ms")}
    categories = sorted(set(k for row in choices for k in row["exclusive_ms"]))
    choice_summary["exclusive_category_medians_ms"] = {k: statistics.median(row["exclusive_ms"][k] for row in choices if k in row["exclusive_ms"]) for k in categories}
    choice_summary["category_case_counts"] = {k: sum(k in row["exclusive_ms"] for row in choices) for k in categories}
    require(inventory(root) == initial, "input files changed during analysis")
    return {"schema": SCHEMA, "analysis_ready": True, "input_dir": str(root), "protocol": protocol,
        "input_inventory": initial, "input_inventory_digest": json_digest(initial),
        "case_grid": list(labels), "declared_modes": modes, "case_mode_statuses": availability,
        "denominators": {"cases": len(cells), "declared_case_modes": len(expected),
                         "passing_case_modes": sum(r["status"] == "pass" for r in availability),
                         "unavailable_case_modes": sum(r["status"] == "unavailable" for r in availability),
                         "af_passing_cases": len(cells), "af_failed_or_unavailable_cases": 0,
                         "normal_entry_execution_checks_verified": sum(v["normal_execution_verified"] for v in normal_entries),
                         "af_warmup_query_executions": sum(v["warmup_query_executions"] for v in execution_counts if v["mode"] == "af"),
                         "af_measured_query_executions": sum(v["measured_query_executions"] for v in execution_counts if v["mode"] == "af"),
                         "af_query_executions_total": sum(v["warmup_query_executions"]+v["measured_query_executions"] for v in execution_counts if v["mode"] == "af"),
                         "af_root_output_counts_verified": sum(v["warmup_root_output_counts_verified"]+v["measured_root_output_counts_verified"] for v in execution_counts if v["mode"] == "af")},
        "statistics_digest": before["digest"], "source_digests": sources,
        "execution_profiles": profiles, "af_execution_observations": observations,
        "access_root_wrappers": wrappers,
        "access_root_layout_policies": layout_policies,
        "normal_entry_checks": normal_entries,
        "physical_recipe_checks": physical_recipes,
        "timed_query_result_count_checks": execution_counts,
        "scope": {"ratio_direction": "baseline / AF; >1 favors AF", "primary_metric": "sql_execution",
            "bootstrap": "paired round indices within each case; fixed case grid geometric mean; percentile 95%; no case resampling",
            "draws": draws, "seed": seed, "unfavorable_case_filtering": False,
            "server_validation": protocol.get("server_validation_scope"),
            "profile_audit": "bound SQL, intrinsic profile/contract identities and actual execution environments checked; upstream issuer preimages and general concurrent authorization not independently certified",
            "wrapper_audit": "new resolved protocol wrapper and explicit override checked against exact bound SQL; no manifest rerendering or issuer substitution; legacy absent declarations retained as unrecorded",
            "normal_entry_check": "only explicitly requested guarded normal executions are audited; each is separate from formal samples and independent canonical correctness; recorded script hash has no retained script preimage and is not reconstructed from today's issuer",
            "identical_sql": "exact text groups are descriptive; all ordinary baseline comparisons retain their own unpooled samples",
            "timed_result_count": "raw query EXPLAIN root Actual Rows, one loop and no parallel plan; compared with full reference row count; unavailable root counters recorded separately; no internal aggregate or child rows substituted",
            "fastest_applicable": "post hoc minimum mode median over AF and all available ordinary baselines; descriptive, not an implemented selector",
            "choice_breakdown": "exclusive category medians are separate observations and need not sum to the median total; inclusive categories are not additive",
            "recovery": "separate SQL, observed-server and client point estimates using same-metric measured saving and recorded preparation costs; requires reuse; no confidence guarantee or unimplemented caching assumed; initialization exclusions remain as declared",
            **({"sampling_schedule": ADJACENT_SAMPLING_SCHEDULE,
                "sampling_balance": protocol["sampling_schedule_contract"]["balance_scope"],
                "sampling_cache_conditions": protocol["sampling_schedule_contract"]["cache_scope"],
                "cycle_sensitivity": protocol["sampling_schedule_contract"]["cycle_sensitivity_scope"]}
               if protocol_schedule == ADJACENT_SAMPLING_SCHEDULE else {})},
        "comparisons": comparisons, "fastest_applicable": fastest, "fastest_applicable_summary": fastest_summary,
        "identical_sql_groups": sql_groups,
        "choice_cost": {"cases": choices, "medians": choice_summary, "recovery": recovery},
        "summary_rows": [rows[(case, mode)] for case in labels for mode in modes],
        "diagnostic_count": len(allowed_diagnostics)}


def rejection_report(root: Path, error: Exception) -> dict[str, Any]:
    """Retain non-success evidence without promoting a favorable partial subset."""
    evidence = []
    for path in sorted(root.rglob("*.json")) if root.is_dir() else []:
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            evidence.append({"input_path": relative, "status": "symlink_rejected"})
            continue
        if relative == "failure.json" or relative.startswith(("correctness/", "prepared/", "samples/")):
            try:
                value = json.loads(path.read_text())
            except (OSError, ValueError) as exc:
                evidence.append({"input_path": relative, "status": "unreadable", "error": str(exc)})
                continue
            if not isinstance(value, dict):
                evidence.append({"input_path": relative, "status": "malformed_non_object"})
                continue
            if relative == "failure.json" or value.get("status") not in (None, "pass"):
                evidence.append({"input_path": relative, "record": value})
            elif relative.startswith("correctness/"):
                for mode, record in value.get("modes", {}).items():
                    if record.get("status") != "pass":
                        evidence.append({"input_path": relative, "mode": mode, "record": record})
            elif relative.endswith("/shared.json"):
                for entry in value.get("modes", []):
                    if entry.get("spec") is None:
                        evidence.append({"input_path": relative, "mode": entry.get("mode"),
                                         "status": "unavailable", "reason": entry.get("unavailable_reason")})
    return {"schema": SCHEMA, "analysis_ready": False, "input_dir": str(root.resolve()),
            "error": str(error), "non_success_evidence": evidence,
            "performance_statistics": None, "partial_case_filtering": False}


def render_report(result: Mapping[str, Any]) -> str:
    if not result["analysis_ready"]:
        return "# Final AF campaign analysis\n\nAnalysis rejected: "+result["error"]+"\n\nNo partial performance statistics were promoted. Non-success records are retained in analysis.json.\n"
    lines = ["# Final AF campaign analysis", "", "All declared cases and ordinary baselines are retained. Ratios are baseline / AF; values above 1 favor AF. W/N/L use paired-round 95% intervals.", "",
             "| Metric | Baseline | Applicable cases | GM ratio [95% interval] | W/N/L |", "| --- | --- | ---: | --- | --- |"]
    for metric, comparators in result["comparisons"].items():
        for mode, value in comparators.items():
            if value["case_count"]:
                lines.append(f"| {metric} | {mode} | {value['case_count']} | {value['geometric_mean_ratio']:.4f} [{value['ci95_lower']:.4f}, {value['ci95_upper']:.4f}] | {value['W']}/{value['N']}/{value['L']} |")
            else:
                lines.append(f"| {metric} | {mode} | 0 | unavailable | — |")
    cycle_label = ("per-case cycle sensitivity with each item's case_count"
                   if result["protocol"].get("schedule") == ADJACENT_SAMPLING_SCHEDULE else "full-cycle sensitivity")
    lines += ["", "The JSON contains every case median and interval, "+cycle_label+", unavailable records, exact SQL groups, and the descriptive fastest applicable comparison. Identical SQL groups do not pool samples.", "", result["scope"]["server_validation"], "", "Choice costs and recovery are estimates from this campaign's retained observations. Recovery assumes reuse; it does not establish a caching implementation.", ""]
    if result["protocol"].get("schedule") == ADJACENT_SAMPLING_SCHEDULE:
        lines += ["AF/IP adjacent-block sampling uses role symmetry, not uniform raw positions for every method or literal equality of all external labels. Cache/predecessor conditions differ from legacy; samples are not pooled.", "",
                  result["scope"]["cycle_sensitivity"], ""]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--bootstrap-draws", "--draws", dest="draws", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=20261028)
    args = parser.parse_args(argv)
    root, output = Path(args.input_dir).resolve(), Path(args.output_dir).resolve()
    require(output != root and root not in output.parents, "analysis output must be outside immutable campaign input")
    require(not output.exists(), "analysis output directory already exists")
    try:
        result = analyze_run(root, draws=args.draws, seed=args.seed)
    except (AnalysisError, OSError, KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
        result = rejection_report(root, exc)
    output.mkdir(parents=True, exist_ok=False)
    (output/"analysis.json").write_text(json.dumps(result, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    (output/"report.md").write_text(render_report(result), encoding="utf-8")
    print(json.dumps({"analysis_ready": result["analysis_ready"], "output_dir": str(output), "error": result.get("error")}))
    return 0 if result["analysis_ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
