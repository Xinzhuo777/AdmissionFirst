"""Measure one final AF against unchanged ordinary E3 baselines.

AF uses its actual admitted bound SQL and execution contract. Fixed comparators
are generated in an isolated worker from the declared initial baseline source.
Every full-result check precedes timing. SQL execution is primary; PostgreSQL
planning, complete client requests and prospective choice costs remain separate.
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import nullcontext
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import importlib
import json
import math
import os
import re
from pathlib import Path
import statistics
import subprocess
import sys
import time
import traceback
from typing import Any, Callable, Mapping, Sequence

import yaml


FRAME = "FINAL_AF_E3_WORKER_V1 "
PRIMARY_FIXED_MODES = ("native-pg-rls", "local-greedy", "barrier-only", "injection-only")
FIXED_MODES = (*PRIMARY_FIXED_MODES, "auth-index-enum-only", "strong-auth-index")
DEFAULT_MODES = ("af", *FIXED_MODES)
PRIMARY_MODES = ("af", *PRIMARY_FIXED_MODES)
LEGACY_SAMPLING_SCHEDULE = "balanced_available_modes_v1"
ADJACENT_SAMPLING_SCHEDULE = "af_ip_adjacent_block_v1"
ADJACENT_DIRECTION_BITS = {5: "00101101", 6: "0101010101", 7: "001010110101"}
ADJACENT_OUTER_DIGESTS = {
    5: "sha256:ca68b2c5b9313b0097300f3f80f5a7861907d065b4dca969fa9d20e23c53bb44",
    6: "sha256:36f6c501bc1e6340586d7c2f9f0926f16a22fb2fc88846b9a1955e3bd4f58ce8",
    7: "sha256:2e8d492816463eecb0ba741649d190fb762226e6053a3d417d82ec606d1ef5e3",
}
ADJACENT_REPETITION_REASON = "one complete AF/IP-adjacent role-symmetric warmup cycle; measured rounds rounded up to its complete cycle"
ADJACENT_REPETITION_POLICY = "per cell: one complete 2(n-1)-round AF/IP-adjacent role-symmetric warmup cycle; at least requested measured rounds rounded upward to its complete cycle; n=available modes"

# Ten permutations balance all positions and all 25 predecessor pairs,
# including self transitions at circular round boundaries. A full warmup cycle
# supplies the predecessor for the first formal sample.
BALANCED_FIVE_MODE_ORDERS = (
    (0, 1, 4, 2, 3), (3, 4, 2, 0, 1), (1, 2, 0, 3, 4),
    (4, 0, 3, 1, 2), (2, 3, 1, 4, 0), (0, 4, 1, 3, 2),
    (2, 1, 3, 0, 4), (4, 3, 0, 2, 1), (1, 0, 2, 4, 3),
    (3, 2, 4, 1, 0),
)


def balanced_round_orders(n: int) -> tuple[tuple[int, ...], ...]:
    """Two Williams families, with Euler-ordered self-carryover boundaries.

    Each family covers every nonself adjacent ordered pair once. Odd n uses
    its reverse family. For even n a second label permutation joins the two
    endpoint matchings into one cycle, permitting an Euler tour of all rows.
    Every circular row boundary then contributes a self pair, twice per mode.
    """
    if type(n) is not int or n < 2:
        raise ValueError("at least two available modes are required")
    if n == 5:
        return BALANCED_FIVE_MODE_ORDERS
    base = [0]
    for low in range(1, n//2+1):
        base.append(low)
        if n-low != low:
            base.append(n-low)
    family = [tuple((value+shift) % n for value in base) for shift in range(n)]
    if n % 2:
        rows = family + [tuple(reversed(row)) for row in family]
    else:
        half = n//2
        relabel = {**{i: half+i for i in range(half)},
                   **{half+i: (i+1) % half for i in range(half)}}
        rows = family + [tuple(relabel[value] for value in row) for row in family]
    outgoing = {mode: [] for mode in range(n)}
    for index, row in enumerate(rows):
        outgoing[row[0]].append(index)
    stack = [(0, None)]
    tour = []
    while stack:
        node, incoming = stack[-1]
        if outgoing[node]:
            index = outgoing[node].pop()
            stack.append((rows[index][-1], index))
        else:
            stack.pop()
            if incoming is not None:
                tour.append(incoming)
    ordered = tuple(rows[index] for index in reversed(tour))
    if len(ordered) != 2*n:
        raise ValueError("balanced row graph is disconnected")
    flat = [mode for row in ordered for mode in row]
    if (Counter((mode, position) for row in ordered for position, mode in enumerate(row))
        != Counter({(mode, position): 2 for mode in range(n) for position in range(n)})
        or Counter(zip([flat[-1]]+flat[:-1], flat))
        != Counter({(a, b): 2 for a in range(n) for b in range(n)})):
        raise ValueError("invalid balanced positions or predecessor pairs")
    return ordered


def _sampling_schedule_key(schedule: str) -> str:
    if schedule in ("legacy", LEGACY_SAMPLING_SCHEDULE):
        return LEGACY_SAMPLING_SCHEDULE
    if schedule == ADJACENT_SAMPLING_SCHEDULE:
        return schedule
    raise ValueError("unknown measurement schedule")


def sampling_round_orders(available_modes: int,
                          schedule: str = LEGACY_SAMPLING_SCHEDULE) -> tuple[tuple[int, ...], ...]:
    if _sampling_schedule_key(schedule) == LEGACY_SAMPLING_SCHEDULE:
        return balanced_round_orders(available_modes)
    if type(available_modes) is not int or available_modes not in ADJACENT_DIRECTION_BITS:
        raise ValueError("adjacent schedule requires 5, 6 or 7 applicable modes")
    outer = balanced_round_orders(available_modes-1)
    if digest_json(outer) != ADJACENT_OUTER_DIGESTS[available_modes]:
        raise ValueError("adjacent schedule outer Williams rows changed")
    units = ((0, 2),) + tuple((i,) for i in range(available_modes) if i not in (0, 2))
    return tuple(tuple(index for unit in row for index in (
        tuple(reversed(units[unit])) if unit == 0 and bit == "1" else units[unit]))
        for row, bit in zip(outer, ADJACENT_DIRECTION_BITS[available_modes]))


def adjacent_mode_map(eligible: Sequence[str]) -> dict[str, Any]:
    modes = list(eligible)
    if (len(modes) not in ADJACENT_DIRECTION_BITS or len(set(modes)) != len(modes)
            or modes[0] != "af" or modes[2] != "local-greedy"
            or modes != [mode for mode in DEFAULT_MODES if mode in modes]):
        raise ValueError("adjacent schedule requires AF index 0 and ordinary IP index 2 in unchanged mode order")
    return {"pair_indices": [0, 2], "pair_modes": ["af", "local-greedy"],
            "eligible_mode_order": modes,
            "macro_units": [["af", "local-greedy"]] + [[mode] for i, mode in enumerate(modes) if i not in (0, 2)]}


def sampling_schedule_protocol_fields(schedule: str = LEGACY_SAMPLING_SCHEDULE) -> dict[str, Any]:
    schedule = _sampling_schedule_key(schedule)
    if schedule == LEGACY_SAMPLING_SCHEDULE:
        return {"schedule": "casewise_balanced_available_modes_rounds_v1",
                "balanced_round_order_indices": {str(n): balanced_round_orders(n) for n in (5, 6, 7)}}
    return {"schedule": schedule,
        "repetition_policy": ADJACENT_REPETITION_POLICY,
        "balanced_round_order_indices": {str(n): sampling_round_orders(n, schedule) for n in (5, 6, 7)},
        "sampling_schedule_contract": {
            "schema": "af_ip_adjacent_block_sampling_v1", "pair_indices": [0, 2],
            "pair_modes": ["af", "local-greedy"],
            "macro_index_maps": {str(n): [[0, 2]] + [[i] for i in range(n) if i not in (0, 2)] for n in (5, 6, 7)},
            "direction_bits_0_AB_1_BA": {str(n): ADJACENT_DIRECTION_BITS[n] for n in (5, 6, 7)},
            "outer_orders_sha256": {str(n): ADJACENT_OUTER_DIGESTS[n] for n in (5, 6, 7)},
            "balance_scope": "AF/IP raw positions equal; ordinary external predecessor/successor labels equal by orientation; actual AF/IP carryover and transition matrix symmetric under AF<->IP relabeling",
            "all_method_raw_positions_uniform": False,
            "full_literal_external_labels_balanced": False,
            "warmup_boundary": "one identical complete warmup cycle supplies the first formal predecessor",
            "cache_scope": "adjacency changes immediate predecessor/cache conditions; keep separate from legacy samples; no pooling or correction",
            "cycle_sensitivity_scope": "cycle indices are per case; at minimum30 n5 has four cycles and n6/n7 three; an extra mixed cycle may be a subset, identified by case_count; primary GM retains the full case grid",
        }}


def measurement_order(entries: Sequence[Any], round_index: int,
                      schedule: str = LEGACY_SAMPLING_SCHEDULE) -> list[Any]:
    if _sampling_schedule_key(schedule) == ADJACENT_SAMPLING_SCHEDULE:
        adjacent_mode_map([entry["mode"] for entry in entries])
    orders = sampling_round_orders(len(entries), schedule)
    return [entries[index] for index in orders[round_index % len(orders)]]


def sampling_repetitions(available_modes: int, minimum_measured: int = 30, *,
                         schedule: str = LEGACY_SAMPLING_SCHEDULE) -> dict[str, Any]:
    if type(minimum_measured) is not int or minimum_measured < 1:
        raise ValueError("minimum measured repetitions must be positive")
    orders = sampling_round_orders(available_modes, schedule)
    cycle = len(orders)
    return {"available_modes": available_modes, "cycle_rounds": cycle, "warmup": cycle,
            "measured": math.ceil(minimum_measured/cycle)*cycle,
            "minimum_measured": minimum_measured,
            "reason": (ADJACENT_REPETITION_REASON if _sampling_schedule_key(schedule) == ADJACENT_SAMPLING_SCHEDULE else
                       "one warmup cycle and measured rounds rounded up to complete position/predecessor-balanced cycles"),
            "round_order_indices": orders}


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_json(value: Any) -> str:
    return digest_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_once(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def source_identity(source: Path) -> dict[str, Any]:
    """Freeze code/configuration, excluding manuscripts and wiki documents."""
    paths = []
    for directory in ("caprls_core", "planner"):
        paths.extend((source / directory).rglob("*.py"))
    paths.extend((source / "configs").rglob("*.yaml"))
    # SQL is executable input and A004 also reads the controlled validator
    # body from its source tree during issuance/replay.
    for directory in ("sql", "workloads", "specs"):
        for suffix in ("*.sql", "*.yaml", "*.json"):
            paths.extend((source / directory).rglob(suffix))
    files = {str(path.relative_to(source)): digest_bytes(path.read_bytes())
             for path in sorted(paths)
             if "__pycache__" not in path.parts
             and not any(part.startswith("._") for part in path.relative_to(source).parts)}
    if "caprls_core/e3_main.py" not in files or "planner/contracts.py" not in files:
        raise ValueError("source root lacks the E3/planner implementation")
    return {"root": str(source.resolve()), "digest": digest_json(files), "files": files}


def activate_source(source: Path) -> tuple[Any, Any, Any]:
    source = source.resolve()
    sys.path.insert(0, str(source))
    e3 = importlib.import_module("caprls_core.e3_main")
    preview = importlib.import_module("caprls_core.e3_sigmod_preview")
    postgres = importlib.import_module("caprls_core.postgres_runner")
    for name, module in tuple(sys.modules.items()):
        if name in {"planner", "caprls_core"} or name.startswith(("planner.", "caprls_core.")):
            filename = getattr(module, "__file__", None)
            if filename and name != __name__:
                try:
                    Path(filename).resolve().relative_to(source)
                except ValueError as exc:
                    raise RuntimeError("mixed source imports: " + name) from exc
    return e3, preview, postgres


def worker_execution_profile_options(e3: Any, registry: Any, required: str | None = None) -> dict[str, str]:
    options = {}
    if (hasattr(e3, "_validate_e3_execution_profile_payload")
        and "native_pg_rls_v1" not in e3._e3_registry_template_ids(registry)):
        options["execution_profile"] = "trusted_explicit"
    if required is not None and options.get("execution_profile") != required:
        raise ValueError("worker source/portfolio cannot provide the required execution profile: " + required)
    return options


def validate_access_root_materialized_by_template(value: Any) -> dict[str, bool]:
    if value is None:
        return {}
    if (not isinstance(value, Mapping) or any(type(key) is not str or not key
            or type(flag) is not bool for key, flag in value.items())):
        raise ValueError("invalid per-template access-root materialization policy")
    return dict(sorted(value.items()))


def template_materialization_override(templates: Sequence[str] | None) -> dict[str, bool] | None:
    if templates is None:
        return None
    if isinstance(templates, (str, bytes)) or any(type(key) is not str or not key for key in templates):
        raise ValueError("invalid explicit materialized template list")
    return validate_access_root_materialized_by_template({key: True for key in templates})


def resolve_access_root_materialized_by_template(source: Path,
                                                override: Mapping[str, bool] | None = None) -> dict[str, bool]:
    if override is not None:
        return validate_access_root_materialized_by_template(override)
    path = source / "configs/normal_e3_af_candidate.yaml"
    if not path.is_file():
        return {}
    config = yaml.safe_load(path.read_text())
    if not isinstance(config, Mapping):
        raise ValueError("source normal AF configuration is not a mapping")
    return validate_access_root_materialized_by_template(config.get("access_root_materialized_by_template"))


PHYSICAL_RECIPE_STRATEGY = "strong_handoff_min_full_cost_v1"


def source_physical_recipe_declaration(source: Path) -> dict[str, Any] | None:
    path = source / "configs/normal_e3_af_candidate.yaml"
    if not path.is_file():
        return None
    config = yaml.safe_load(path.read_text())
    if not isinstance(config, Mapping):
        raise ValueError("source normal AF configuration is not a mapping")
    strategy = config.get("physical_recipe_strategy")
    if strategy is None:
        return None
    if (strategy != PHYSICAL_RECIPE_STRATEGY
            or config.get("access_root_wrapper") != "not_materialized_single_reference"
            or validate_access_root_materialized_by_template(config.get("access_root_materialized_by_template"))
            != {"auth_index_enum_v1": True}):
        raise ValueError("unsupported physical recipe declaration or fixed recipe baseline")
    return dict(config)


def resolve_study_materialization(source: Path, manifest: Mapping[str, Any], *,
                                  wrapper_override: str | None = None,
                                  layout_override: Mapping[str, bool] | None = None
                                  ) -> tuple[str, dict[str, bool], dict[str, Any] | None]:
    declared = source_physical_recipe_declaration(source)
    wrapper = wrapper_override or (declared["access_root_wrapper"] if declared is not None
                                   else (manifest.get("scale_check") or {}).get("bound_runner_wrapper", "materialized"))
    if wrapper not in {"materialized", "not_materialized_single_reference"}:
        raise ValueError("unsupported access-root wrapper")
    layouts = resolve_access_root_materialized_by_template(source, layout_override)
    if declared is not None and (wrapper != declared["access_root_wrapper"] or layout_override is not None):
        raise ValueError("physical recipe strategy does not accept wrapper changes or template-map overrides")
    return wrapper, layouts, declared


def worker_payload(source: Path, request: Mapping[str, Any]) -> dict[str, Any]:
    if "operation" in request:
        return execution_worker_payload(source, request)
    before = source_identity(source)
    e3, preview, postgres = activate_source(source)
    if request.get("worker_kind") == "fixed":
        return fixed_worker_payload(source, request, e3=e3, preview=preview, before=before)
    layouts = resolve_access_root_materialized_by_template(
        source, request.get("access_root_materialized_by_template"))
    manifest_path = Path(request["manifest"])
    manifest = e3._load_manifest(manifest_path)
    query = next(item for item in e3._queries_for_manifest(manifest_path, manifest)
                 if item.query_id == request["query_id"])
    policy = next(item for item in e3._policies_for_manifest(manifest_path, manifest)
                  if item.config_id == request["policy_id"])
    pg_env = postgres.PostgresEnv(**request["pg_env"])
    stats = request["stats"]
    predicate = e3._policy_predicate(query, policy)
    registry = e3._e3_registry_from_manifest(manifest)
    profile_kwargs = worker_execution_profile_options(e3, registry, request.get("required_execution_profile"))
    started = time.perf_counter()
    receipt = e3._collect_e3_planning_catalog_receipt(query, policy, pg_env, **profile_kwargs)
    receipt_ms = (time.perf_counter() - started) * 1000
    # Calibration belongs to the algorithm source, while the manifest and
    # database population are the shared study inputs.
    collector_cls = importlib.import_module("caprls_core.selection_cost_breakdown").SelectionCostBreakdown
    collector = collector_cls(family="E3")
    started = time.perf_counter()
    normal_metadata = None
    normal_prepared = None
    physical_strategy = None
    spec = None
    if ((source / "caprls_core/normal_e3_af.py").is_file()
            and profile_kwargs.get("execution_profile") == "trusted_explicit"):
        normal = importlib.import_module("caprls_core.normal_e3_af")
        Path(normal.__file__).resolve().relative_to(source.resolve())
        config = normal.load_runtime_config()
        physical_strategy = config.get("physical_recipe_strategy")
        if physical_strategy is not None:
            if (source_physical_recipe_declaration(source) != config
                    or request["access_root_materialized"] is not False
                    or layouts != {"auth_index_enum_v1": True}):
                raise ValueError("physical recipe strategy requires its unchanged source declaration")
        elif request["access_root_materialized"]:
            config.update(name="af-study-materialized-ablation", access_root_wrapper="materialized")
        else:
            config["access_root_wrapper"] = "not_materialized_single_reference"
        if physical_strategy is None and ("access_root_materialized_by_template" in config or layouts):
            config["access_root_materialized_by_template"] = layouts
        prepared, breakdown = collector.run(normal.prepare_normal_e3_af,
            query_id=query.query_id, policy_id=policy.config_id,
            manifest_path=manifest_path, project_root=Path(request["project_root"]),
            pg_env=pg_env, stats=stats, runtime_config=config,
            planning_catalog_receipt=receipt)
        result, plan, spec = prepared.plan_result, prepared.query_plan, prepared.spec
        normal_prepared = prepared
        normal_metadata = dict(prepared.metadata)
        if physical_strategy is not None:
            # Replay the original two owned branches before exporting a winner.
            review = normal.prepared_report(prepared)
            if (review["metadata"] != normal_metadata or review["spec"] != asdict(spec)
                    or normal_metadata.get("declared_runtime_config") != config
                    or normal_metadata.get("declared_runtime_config_sha256") != digest_json(config)):
                raise ValueError("normal physical recipe declaration or owned review changed")
            physical = normal_metadata.get("physical_recipe_selection")
            effective = normal_metadata.get("resolved_runtime_config")
            if (not isinstance(physical, Mapping) or not isinstance(effective, Mapping)
                    or physical.get("strategy") != physical_strategy
                    or physical.get("declared_config_digest") != digest_json(config)
                    or normal_metadata.get("runtime_config_sha256") != digest_json(effective)):
                raise ValueError("normal physical recipe decision or effective configuration changed")
            layouts = validate_access_root_materialized_by_template(effective.get("access_root_materialized_by_template"))
            expected_effective = {key: value for key, value in config.items() if key != "physical_recipe_strategy"}
            expected_effective["access_root_materialized_by_template"] = physical["effective_layout_policy"]["materialized_by_template"]
            if effective != expected_effective:
                raise ValueError("physical winner changed non-layout runtime configuration")
        if (normal_metadata.get("source_identity") != before
                or (physical_strategy is None and normal_metadata.get("resolved_runtime_config") != config)):
            raise ValueError("normal AF entry source or runtime configuration changed")
    else:
        # Historical source trees lack the normal adapter. Keep that exact
        # research path for before-source ablations, without transplanting it.
        ranker = e3._ranker_from_manifest(source, manifest)
        layout_kwargs = {"access_root_materialized_by_template": layouts} if layouts else {}
        (result, plan, _), breakdown = collector.run(e3._plan_e3_admission_first,
            query=query, policy=policy, predicate=predicate, pg_env=pg_env,
            protected_rows=stats["protected_rows"], query_local_rows=stats["query_local_rows"],
            authorized_rows=stats["authorized_rows"], build_ms=stats["artifact_build_ms"],
            keyed_artifact_rows=stats["keyed_artifact_rows"], ranker=ranker, registry=registry,
            planning_catalog_receipt=receipt,
            access_root_materialized=request["access_root_materialized"],
            **profile_kwargs,
            **layout_kwargs,
        )
    selection_ms = (time.perf_counter() - started) * 1000
    template = e3._require_e3_selected_root_template(plan)
    bound = plan["production_bound_runner"]
    layout_policy = plan.get("production_access_root_layout_policy")
    if layouts and (not isinstance(layout_policy, Mapping)
            or layout_policy.get("materialized_by_template") != layouts
            or layout_policy.get("base_materialized") != request["access_root_materialized"]):
        raise ValueError("worker source did not bind its requested template handoff policy")
    sql = bound["runner_sql"]
    if bound["template_id"] != template or bound["runner_sql_digest"] != e3._canonical_sha256(
            {"exact_runner_sql": sql}):
        raise ValueError("worker selected SQL identity mismatch")
    if result.chosen_template is None:
        raise ValueError("worker has no chosen AF template")
    sql_source = e3._source_for_template(template)
    artifact_ids, expected_json = preview._artifact_validation_for(query, policy, sql_source)
    contract_kwargs = {}
    if profile_kwargs:
        contract_kwargs = {
            "session_contract": bound.get("session_contract"),
            "execution_profile": bound.get("execution_profile"),
        }
        if any(not isinstance(value, Mapping) for value in contract_kwargs.values()):
            raise ValueError("trusted AF worker lacks its actual execution contract")
    expected_spec = preview.ExecutionSpec(
        mode=request["variant"], template_id=template,
        alternative=result.chosen_template.alternative, sql=sql, sql_source=sql_source,
        result_columns=preview._result_columns_for(query),
        role=(contract_kwargs["session_contract"]["role"] if contract_kwargs
              else e3.E3_RLS_ROLE if sql_source == "rls" else None),
        artifact_ids=artifact_ids, expected_artifact_json=expected_json,
        **contract_kwargs,
    )
    if spec is None:
        spec = expected_spec
    elif asdict(spec) != asdict(expected_spec):
        raise ValueError("normal AF entry differs from its actual bound worker handoff")
    if contract_kwargs:
        preview._execution_contract(spec)
    normal_execution_check = None
    normal_api_execution_total_ms = None
    if request.get("verify_normal_execution", False):
        if normal_prepared is None:
            raise ValueError("normal-entry execution check requires the normal AF source adapter")
        # A separate correctness-path execution after prospective selection;
        # it is not a timing sample and cannot feed back into the choice.
        api_started = time.perf_counter()
        normal_execution_check = normal.execute_normal_e3_af(normal_prepared)
        normal_api_execution_total_ms = (time.perf_counter()-api_started)*1000
        if (normal_execution_check.get("status") != "executed"
                or normal_execution_check.get("exact_bound_sql_sha256") != digest_bytes(spec.sql.encode())
                or normal_execution_check.get("query_body_executions") != 1):
            raise ValueError("normal entry did not execute the admitted query body exactly once")
    reference = preview.ExecutionSpec(
        mode="independent-reference", template_id="direct_independent_reference_v1",
        alternative="IndependentReference", sql=e3._e3_independent_result_reference_sql(query, policy),
        sql_source="direct-independent-reference", result_columns=preview._result_columns_for(query),
    )
    after = source_identity(source)
    if before != after:
        raise RuntimeError("worker source changed during prospective selection")
    return {
        "schema": "final_af_e3_worker_v1", "status": "pass", "variant": request["variant"],
        "query_id": query.query_id, "policy_id": policy.config_id,
        "source_identity": before, "manifest_sha256": digest_bytes(manifest_path.read_bytes()),
        "spec": asdict(spec), "reference": asdict(reference),
        "selection": {
            "selected_template_id": template, "selected_plan_id": bound["plan_id"],
            "selected_runner_digest": bound["runner_sql_digest"],
            "access_root_materialized_by_template": layouts,
            "access_root_layout_policy": layout_policy,
            "access_root_layouts": plan.get("production_access_root_layouts", []),
            "candidate_cost_vector": [{"template_id": candidate.template_id,
                "accepted": candidate.accepted, "estimated_cost": candidate.estimated_cost,
                "rejection_reasons": list(candidate.rejection_reasons)} for candidate in result.candidates],
            "complete_runner_costs": plan.get("production_candidate_costs", []),
            "completed_root_eligibility": plan["production_completed_root_eligibility"],
            "root_selection_audit": plan["production_root_selection"],
            "prospective_total_cost": plan["production_chosen_cost"]["prospective_total_cost"],
            "selection_wall_ms": breakdown["total_wall_ms"],
            "selection_observer_total_with_hook_setup_ms": selection_ms,
            "selection_breakdown": breakdown,
            "selection_breakdown_scope": (
                "one_normal_AF_prepare_invocation_with_external_receipt_excluding_input_collection_and_catalog_receipt"
                if normal_metadata is not None else
                "one_actual_plan_e3_admission_first_invocation_excluding_input_collection_and_catalog_receipt"),
            "normal_entry_used": normal_metadata is not None,
            "normal_entry_metadata": normal_metadata,
            "normal_execution_check": normal_execution_check,
            "normal_api_execution_total_wall_ms_including_python_revalidation": normal_api_execution_total_ms,
            **({"physical_recipe_strategy": physical_strategy,
                "physical_recipe_selection": normal_metadata["physical_recipe_selection"]}
               if physical_strategy is not None else {}),
            "catalog_receipt_wall_ms": receipt_ms,
            "execution_profile": profile_kwargs.get("execution_profile"),
            "measured_runtime_used_for_selection": False,
            "bound_runner": bound,
        },
    }



def fixed_worker_payload(source: Path, request: Mapping[str, Any], *, e3: Any,
                         preview: Any, before: Mapping[str, Any]) -> dict[str, Any]:
    manifest_path = Path(request["manifest"])
    manifest = e3._load_manifest(manifest_path)
    query = next(item for item in e3._queries_for_manifest(manifest_path, manifest)
                 if item.query_id == request["query_id"])
    policy = next(item for item in e3._policies_for_manifest(manifest_path, manifest)
                  if item.config_id == request["policy_id"])
    fixed = []
    for mode in request["fixed_modes"]:
        if mode not in FIXED_MODES:
            raise ValueError("unsupported ordinary baseline")
        started = time.perf_counter()
        prepared = preview._fixed_mode(query, policy, mode)
        fixed.append({"mode": mode, "spec": None if prepared.spec is None else asdict(prepared.spec),
                      "unavailable_reason": prepared.unavailable_reason,
                      "generation_wall_ms": (time.perf_counter()-started)*1000})
    reference = preview.ExecutionSpec(
        mode="independent-reference", template_id="direct_independent_reference_v1",
        alternative="IndependentReference", sql=e3._e3_independent_result_reference_sql(query, policy),
        sql_source="direct-independent-reference", result_columns=preview._result_columns_for(query))
    if source_identity(source) != before:
        raise RuntimeError("fixed baseline source changed during generation")
    return {"schema": "final_af_e3_worker_v1", "status": "pass", "worker_kind": "fixed",
            "source_identity": before, "manifest_sha256": digest_bytes(manifest_path.read_bytes()),
            "fixed_modes": fixed, "reference": asdict(reference)}


def validate_af_bound_spec(payload: Mapping[str, Any]) -> None:
    spec, selection = payload["spec"], payload["selection"]
    bound = selection["bound_runner"]
    if (spec["mode"] != "af" or spec["sql"] != bound["runner_sql"]
        or spec["template_id"] != bound["template_id"]
        or digest_json({"exact_runner_sql": spec["sql"]}) != bound["runner_sql_digest"]
        or selection["selected_runner_digest"] != bound["runner_sql_digest"]):
        raise ValueError("AF timed SQL differs from its actual admitted bound runner")
    for key in ("session_contract", "execution_profile"):
        if not isinstance(spec.get(key), Mapping) or spec[key] != bound.get(key):
            raise ValueError("AF execution contract differs from its bound runner: " + key)
    if (spec["execution_profile"].get("name") != "trusted_explicit"
        or spec["role"] != spec["session_contract"].get("role")):
        raise ValueError("AF requires its actual trusted explicit execution role/profile")

def parse_worker_frame(stdout: str) -> dict[str, Any]:
    frames = [line[len(FRAME):] for line in stdout.splitlines() if line.startswith(FRAME)]
    if len(frames) != 1:
        raise ValueError("worker must return exactly one framed response")
    result = json.loads(frames[0])
    if not isinstance(result, dict) or result.get("schema") != "final_af_e3_worker_v1":
        raise ValueError("invalid worker response schema")
    return result


def run_worker(source: Path, request: Mapping[str, Any], *, timeout_s: float = 1800) -> dict[str, Any]:
    started = time.perf_counter()
    proc = subprocess.run(
        [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", str(source.resolve())],
        input=json.dumps(request), text=True, capture_output=True, cwd=source, timeout=timeout_s,
        env={**os.environ, "PYTHONPATH": str(source.resolve())},
    )
    try:
        result = parse_worker_frame(proc.stdout)
    except (ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("malformed selection worker response: " + json.dumps({
            "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr,
        }, ensure_ascii=False)) from exc
    result["worker_request_wall_ms"] = (time.perf_counter() - started) * 1000
    if proc.returncode or result.get("status") != "pass":
        raise RuntimeError("selection worker failed: " + json.dumps({
            "returncode": proc.returncode, "response": result, "stderr": proc.stderr,
        }, ensure_ascii=False))
    return result


def prepare_artifacts(e3: Any, postgres: Any, queries: Sequence[Any],
                      policies: Sequence[Any], pg_env: Any) -> dict[str, Any]:
    """Finish all shared artifact writes before any prospective selection.

    E3 artifact IDs are shared by queries in the same workload/policy. Reusing
    an ID with a different recipe is rejected instead of silently replacing
    the artifact that an earlier selection assumed.
    """
    recipes: dict[str, tuple[str, Any, Any]] = {}
    for query in queries:
        for policy in policies:
            artifact_id = e3._artifact_id(query, policy)
            predicate = e3._policy_predicate(query, policy)
            recipe = {
                "sql": None if policy.artifacts == "none" else e3._build_artifact_sql(query, policy, predicate),
                "protected_rel": query.protected_rel, "rid_col": query.rid_col,
                "key_name": query.key_name, "key_value": query.key_value,
            }
            signature = digest_json(recipe)
            if artifact_id in recipes and recipes[artifact_id][0] != signature:
                raise ValueError("shared artifact ID has incompatible query recipes: " + artifact_id)
            recipes.setdefault(artifact_id, (signature, query, policy))
    built = {}
    for artifact_id, (signature, query, policy) in recipes.items():
        build_ms, rows, keyed_rows = e3._build_artifact(
            query, policy, e3._policy_predicate(query, policy), pg_env)
        built[artifact_id] = {
            "recipe_digest": signature, "representative_query": query.query_id,
            "policy_id": policy.config_id, "artifact_build_ms": build_ms,
            "artifact_rows": rows, "keyed_artifact_rows": keyed_rows,
        }
    # One final common maintenance step prevents early cells from seeing an
    # incomplete artifact population or statistics that later builds replace.
    for table in ("auth_idx", "auth_idx_keyed", "artifact_dependencies"):
        postgres.run_psql_command("VACUUM (ANALYZE) public." + table, pg_env)
    return built


def statistics_identity(postgres: Any, pg_env: Any) -> dict[str, Any]:
    """Record the catalog statistics used by normal PostgreSQL planning."""
    raw = postgres.run_psql_command("""
SELECT json_build_object(
  'relations', (
    SELECT json_agg(json_build_array(c.relname, c.relpages, c.reltuples, c.relallvisible)
                    ORDER BY c.relname)
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'm')
  ),
  'statistics', (
    SELECT json_agg(json_build_array(tablename, attname, inherited, null_frac,
                    avg_width, n_distinct, most_common_vals::text,
                    most_common_freqs::text, histogram_bounds::text, correlation,
                    most_common_elems::text, most_common_elem_freqs::text,
                    elem_count_histogram::text)
                    ORDER BY tablename, attname, inherited)
    FROM pg_catalog.pg_stats WHERE schemaname = 'public'
  )
)::text
""", pg_env)
    payload = json.loads(raw)
    return {"digest": digest_json(payload), "catalog_statistics": payload}


def evaluate_cells(
    cells: Sequence[Mapping[str, Any]], *, output_dir: Path, measured: int,
    canonicalize: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    measure: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    diagnostic: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None,
    restore_cell: Callable[[Mapping[str, Any]], None], correctness_only: bool = False,
    schedule: str = "balanced_available_modes_v1",
) -> list[dict[str, Any]]:
    """Check every case/mode before timing, then use the declared schedule."""
    if measured < 0 or (not correctness_only and measured < 1):
        raise ValueError("invalid measured repetitions")
    if correctness_only and measured:
        raise ValueError("correctness-only requires zero repetitions")
    schedule = _sampling_schedule_key(schedule)
    checked = []
    failures = []
    for cell in cells:
        restore_cell(cell)
        reference = dict(canonicalize(cell["reference"]))
        correctness = {}
        for entry in cell["modes"]:
            mode, spec = entry["mode"], entry["spec"]
            if spec is None:
                correctness[mode] = {"status": "unavailable", "reason": entry["unavailable_reason"]}
                continue
            actual = dict(canonicalize(spec))
            a, r = Counter(actual["canonical_rows"]), Counter(reference["canonical_rows"])
            excess, missing = sum((a-r).values()), sum((r-a).values())
            status = "pass" if not excess and not missing else "correctness_fail"
            correctness[mode] = {
                "status": status, "actual": actual, "actual_only_rows": excess,
                "reference_only_rows": missing,
                "ordered_sequence_match_diagnostic": actual["canonical_rows"] == reference["canonical_rows"],
            }
            if status != "pass":
                failures.append(cell["case_id"] + ":" + mode)
        write_once(output_dir/"correctness"/(cell["case_id"]+".json"), {
            "method": "full_row_jsonb_multiset_equality", "reference": reference,
            "modes": correctness,
        })
        eligible_modes = [entry["mode"] for entry in cell["modes"] if entry["spec"] is not None]
        mode_map = adjacent_mode_map(eligible_modes) if schedule == ADJACENT_SAMPLING_SCHEDULE else None
        repetitions = (None if correctness_only else sampling_repetitions(
            len(eligible_modes), measured, schedule=schedule))
        write_once(output_dir/"sampling"/(cell["case_id"]+".json"),
                   {"case_id": cell["case_id"], "modes": eligible_modes,
                    "repetitions": repetitions, "correctness_only": correctness_only,
                    **({"sampling_schedule": schedule, "sampling_mode_map": mode_map} if mode_map is not None else {})})
        checked.append((cell, correctness, repetitions))
    if failures:
        raise ValueError("correctness failed before any timing: " + ", ".join(failures))

    summary = []
    for cell, correctness, repetitions in checked:
        restore_cell(cell)
        eligible = [entry for entry in cell["modes"] if entry["spec"] is not None]
        collected: dict[str, list[Mapping[str, Any]]] = {entry["mode"]: [] for entry in eligible}
        preceding_mode = None
        if not correctness_only:
            warmup, measured_rounds = repetitions["warmup"], repetitions["measured"]
            for round_index in range(warmup + measured_rounds):
                phase = "warmup" if round_index < warmup else "measured"
                iteration = round_index+1 if phase == "warmup" else round_index-warmup+1
                order = measurement_order(eligible, round_index, schedule)
                for order_index, entry in enumerate(order):
                    path = output_dir/"samples"/(
                        f"{cell['case_id']}__{entry['mode']}__{phase}{iteration:02d}.json")
                    metadata = {
                        "case_id": cell["case_id"], "mode": entry["mode"], "phase": phase,
                        "iteration": iteration, "round_index": round_index,
                        "order_index": order_index, "sql_sha256": digest_bytes(entry["spec"]["sql"].encode()),
                        "preceding_mode": preceding_mode, "source_identity": entry.get("source_digest"),
                        "selection": entry.get("selection")}
                    try:
                        sample = dict(measure(entry["spec"]))
                    except Exception as exc:
                        write_once(path, {**metadata, "status": "error", "spec": entry["spec"],
                                          "error": str(exc), "traceback": traceback.format_exc()})
                        raise
                    write_once(path, {**metadata, "status": "pass", "measurement": sample})
                    preceding_mode = entry["mode"]
                    if phase == "measured":
                        collected[entry["mode"]].append(sample)
        for entry in cell["modes"]:
            mode = entry["mode"]
            samples = collected.get(mode, [])
            median = lambda key: statistics.median(sample[key] for sample in samples) if samples else None
            request_ms = median("database_total_ms")
            selection = entry.get("selection") or {}
            choice_ms = selection.get("selection_wall_ms", 0) + selection.get("catalog_receipt_wall_ms", 0)
            input_ms = cell["stats"]["input_collection_wall_ms"] if mode == "af" else 0
            first_use = None if request_ms is None else request_ms + choice_ms + input_ms + entry.get("generation_wall_ms", 0)
            row = {
                "case_id": cell["case_id"], "query_id": cell["query_id"], "policy_id": cell["policy_id"],
                "mode": mode, "status": correctness[mode]["status"],
                "template_id": None if entry["spec"] is None else entry["spec"]["template_id"],
                "source_digest": entry.get("source_digest"),
                "warmup_repetitions": 0 if repetitions is None else repetitions["warmup"],
                "measured_repetitions": len(samples),
                "median_end_to_end_ms_including_validation_and_client": request_ms,
                "median_postgres_planning_ms": median("postgres_planning_ms"),
                "median_postgres_query_execution_ms": median("execution_ms"),
                "median_server_validation_ms": median("server_validation_ms"),
                "median_server_guard_body_execution_ms": median("server_guard_body_execution_ms"),
                "median_server_body_planning_execution_ms": median("server_body_planning_execution_ms"),
                "median_server_query_plus_required_validation_observed_ms": median("server_query_plus_required_validation_observed_ms"),
                "selection_wall_ms": selection.get("selection_wall_ms"),
                "catalog_receipt_wall_ms": selection.get("catalog_receipt_wall_ms"),
                "input_collection_wall_ms": input_ms,
                "worker_request_wall_ms_infrastructure_only": entry.get("worker_request_wall_ms"),
                "first_use_estimate_ms_excluding_artifact_build": first_use,
                "artifact_build_ms_shared_setup": cell["stats"]["artifact_build_ms"],
                "first_use_estimate_with_artifact_build_ms": None if first_use is None else first_use + (
                    cell["stats"]["artifact_build_ms"] if mode == "af" or (
                        entry["spec"] and entry["spec"].get("artifact_ids")) else 0),
            }
            summary.append(row)
        # Diagnostic executions occur after primary samples and are not timed samples.
        if diagnostic is not None:
            for entry in eligible:
                write_once(output_dir/"diagnostics"/(cell["case_id"]+"__"+entry["mode"]+".json"),
                           diagnostic(entry["spec"]))
    return summary


def _spec_from_dict(preview: Any, payload: Mapping[str, Any]) -> Any:
    data = dict(payload)
    data["result_columns"] = tuple(tuple(column) for column in data.get("result_columns", ()))
    data["artifact_ids"] = tuple(data.get("artifact_ids", ()))
    return preview.ExecutionSpec(**data)



EXPLAIN_PREFIX = "EXPLAIN (ANALYZE, FORMAT JSON, TIMING OFF, SUMMARY ON) "
QUERY_BEGIN = "FINAL_AF_QUERY_BEGIN"
QUERY_END = "FINAL_AF_QUERY_END"
GUARD_TIME_PREFIX = "FINAL_AF_GUARD_BODY_MS "


def measurement_script(preview: Any, spec: Any) -> str:
    """Observe the existing transaction's checks; never rewrite its query.

    Artifact assertions are each executed once under EXPLAIN ANALYZE. Their
    existing raised exceptions still abort the transaction. The trusted AF DO
    guard retains every original check; two clock observations expose its body
    execution, excluding DO compilation and statement overhead.
    """
    body = EXPLAIN_PREFIX + preview._single_query(spec.sql)
    script = preview._transaction_script(spec, body)
    if spec.artifact_ids:
        validations = preview._validation_statements(spec.artifact_ids, spec.expected_artifact_json)
        framed = []
        for index, statement in enumerate(validations.split(";\n")):
            if statement.strip():
                statement = statement.strip().rstrip(";")
                framed.append(f"SELECT 'FINAL_AF_VALIDATION_BEGIN_{index}';\n"
                              + EXPLAIN_PREFIX + statement + ";\n"
                              + f"SELECT 'FINAL_AF_VALIDATION_END_{index}';")
        if script.count(validations) != 1:
            raise ValueError("artifact validation block is not unique in transaction script")
        script = script.replace(validations, "\n".join(framed), 1)
    if getattr(spec, "session_contract", None) is not None:
        pattern = re.compile(r"DO (?P<tag>\$[^$]*\$)\nBEGIN(?P<body>.*?)\nEND\n(?P=tag);", re.S)
        matches = list(pattern.finditer(script))
        if len(matches) != 1:
            raise ValueError("expected one trusted AF environment DO guard")
        match = matches[0]
        tag = match.group("tag")
        instrumented = (
            f"DO {tag}\nDECLARE final_af_guard_started timestamptz := pg_catalog.clock_timestamp();\nBEGIN"
            + match.group("body")
            + "\n  PERFORM pg_catalog.set_config('caprls.final_af_guard_body_ms',"
              " (EXTRACT(EPOCH FROM (pg_catalog.clock_timestamp()-final_af_guard_started))*1000)::text, true);"
            + f"\nEND\n{tag};\n"
            + f"SELECT '{GUARD_TIME_PREFIX}' || pg_catalog.current_setting('caprls.final_af_guard_body_ms');")
        script = script[:match.start()] + instrumented + script[match.end():]
    if script.count(body) != 1:
        raise ValueError("query body is not unique in measurement script")
    script = script.replace(body+";", f"SELECT '{QUERY_BEGIN}';\n"+body+f";\nSELECT '{QUERY_END}';", 1)
    return script


def parse_measurement_output(e3: Any, preview: Any, spec: Any, raw: str,
                             client_ms: float) -> dict[str, Any]:
    lines = raw.splitlines()
    def section(begin: str, end: str) -> str:
        if lines.count(begin) != 1 or lines.count(end) != 1:
            raise ValueError("missing or duplicate measurement output frame: " + begin)
        left, right = lines.index(begin), lines.index(end)
        if left >= right:
            raise ValueError("reversed measurement output frame")
        return "\n".join(lines[left+1:right])
    def parsed_explain(value: str) -> Mapping[str, Any]:
        documents = e3._parse_explain_json(value)
        if len(documents) != 1 or not isinstance(documents[0], Mapping):
            raise ValueError("expected one EXPLAIN ANALYZE document")
        for field in ("Planning Time", "Execution Time"):
            number = documents[0].get(field)
            if type(number) not in (int, float) or not math.isfinite(number) or number < 0:
                raise ValueError("missing or invalid EXPLAIN time: " + field)
        return documents[0]
    query_raw = section(QUERY_BEGIN, QUERY_END)
    query = parsed_explain(query_raw)
    validation_observations = []
    for line in lines:
        match = re.fullmatch(r"FINAL_AF_VALIDATION_BEGIN_([0-9]+)", line)
        if match is not None:
            number = match.group(1)
            content = section(line, "FINAL_AF_VALIDATION_END_"+number)
            validation = parsed_explain(content)
            validation_observations.append({"index": int(number), "explain": validation,
                                            "explain_raw": content})
    validation_ms = sum(row["explain"]["Planning Time"]+row["explain"]["Execution Time"]
                        for row in validation_observations)
    if len(validation_observations) != len(spec.artifact_ids):
        raise ValueError("missing or extra artifact validation observation")
    guard_lines = [line[len(GUARD_TIME_PREFIX):] for line in lines if line.startswith(GUARD_TIME_PREFIX)]
    if len(guard_lines) != (1 if getattr(spec, "session_contract", None) is not None else 0):
        raise ValueError("missing or unexpected AF guard body timing")
    guard_ms = float(guard_lines[0]) if guard_lines else 0.0
    if not math.isfinite(guard_ms) or guard_ms < 0:
        raise ValueError("invalid AF guard body time")
    body_ms = query["Planning Time"]+query["Execution Time"]
    return {"execution_ms": query["Execution Time"], "postgres_planning_ms": query["Planning Time"],
            "database_total_ms": client_ms, "server_validation_ms": validation_ms,
            "server_guard_body_execution_ms": guard_ms,
            "server_body_planning_execution_ms": body_ms,
            "server_query_plus_required_validation_observed_ms": body_ms+validation_ms+guard_ms,
            "guard_scope": "DO body execution only; DO compilation and statement overhead unobserved",
            "execution_environment": (preview._observed_execution_environment(spec, raw)
                                      if hasattr(preview, "_observed_execution_environment") else None),
            "query_explain": query, "validation_observations": validation_observations,
            "query_executions": 1, "artifact_validation_executions": len(validation_observations),
            "raw_output": raw}


def execution_worker_payload(source: Path, request: Mapping[str, Any]) -> dict[str, Any]:
    """Replay a spec under its own frozen issuer and validator implementation.

    Old and new finite profiles can legitimately have different digests. Their
    validation must stay isolated; no cross-version digest is rewritten or
    accepted by relaxing the production execution contract.
    """
    before = source_identity(source)
    e3, preview, postgres = activate_source(source)
    spec = _spec_from_dict(preview, request["spec"])
    operation = request["operation"]
    if operation == "script":
        result = {"script": measurement_script(preview, spec)}
    elif operation in {"canonicalize", "measure", "diagnostic"}:
        pg_env = postgres.PostgresEnv(**request["pg_env"])
        if operation == "canonicalize":
            result = asdict(preview._canonicalize_live(spec, pg_env))
        elif operation == "measure":
            script = measurement_script(preview, spec)
            started = time.perf_counter()
            raw = postgres.run_psql_command(script, pg_env)
            result = parse_measurement_output(e3, preview, spec, raw,
                                              (time.perf_counter()-started)*1000)
            result["measurement_script_sha256"] = digest_bytes(script.encode())
        else:
            # The matching source checks the complete contract before running
            # EXPLAIN, just as it does for correctness and primary timing.
            script = preview._transaction_script(spec,
                "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON, TIMING OFF, SUMMARY ON) "
                + preview._single_query(spec.sql))
            raw = postgres.run_psql_command(script, pg_env)
            query_output = getattr(preview, "_execution_query_output", lambda value: value)(raw)
            observer = getattr(preview, "_observed_execution_environment", None)
            result = {"sql": spec.sql, "sql_sha256": digest_bytes(spec.sql.encode()),
                      "role": spec.role, "artifact_validation_required": bool(spec.artifact_ids),
                      "execution_environment": observer(spec, raw) if observer is not None else None,
                      "explain": e3._parse_explain_json(query_output)}
    else:
        raise ValueError("unknown frozen-source execution operation: " + str(operation))
    if source_identity(source) != before:
        raise RuntimeError("source changed during frozen-source execution")
    return {"schema": "final_af_e3_worker_v1", "status": "pass",
            "source_identity": before, "operation": operation, "result": result}


def load_shared_preparation(directory: Path, *, postgres: Any, pg_env: Any,
                            manifest_digest: str, queries: Sequence[Any],
                            policies: Sequence[Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify unchanged common data; never supplies an admission or a choice."""
    directory = Path(directory).resolve()
    record = json.loads((directory/"protocol.json").read_text())
    if (record.get("schema") != "a016_shared_database_preparation_v1"
            or record.get("manifest_sha256") != manifest_digest
            or record.get("pg_env") != asdict(pg_env)
            or record.get("queries") != [q.query_id for q in queries]
            or record.get("policies") != [p.config_id for p in policies]):
        raise ValueError("shared data/manifest/case/database identity differs")
    actual = postgres.run_psql_command("SELECT system_identifier::text FROM pg_control_system()",pg_env)
    if actual != record["database_system_identifier"]:
        raise ValueError("shared PostgreSQL cluster identity changed")
    expected = json.loads((directory/"statistics.json").read_text())
    if statistics_identity(postgres,pg_env) != expected:
        raise ValueError("shared data statistics changed")
    artifacts = json.loads((directory/"artifacts.json").read_text())
    if digest_bytes((directory/"artifacts.json").read_bytes()) != record["artifacts_file_sha256"]:
        raise ValueError("shared artifact preparation record changed")
    return record, artifacts


def run_study(args: argparse.Namespace) -> dict[str, Any]:
    root = Path(args.root).resolve()
    source = Path(args.source_root or root).resolve()
    baseline = Path(args.baseline_source).resolve()
    output = Path(args.output_dir).resolve()
    if (getattr(args, "normal_entry_check", False)
            and not (source / "caprls_core/normal_e3_af.py").is_file()):
        raise ValueError("normal-entry check requires a source with the normal AF adapter")
    if args.smoke_measurement_checks and not args.correctness_only:
        raise ValueError("smoke measurement checks require correctness-only mode")
    output.mkdir(parents=True, exist_ok=False)
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = root/manifest_path
    current_identity, baseline_identity = source_identity(source), source_identity(baseline)
    manifest_digest = digest_bytes(manifest_path.read_bytes())
    e3, preview, postgres = activate_source(source)
    manifest = e3._load_manifest(manifest_path)
    e3._validate_manifest(manifest_path, manifest)
    e3.require_e3_manifest_data(root, manifest_path, manifest)
    queries = preview._select_items(e3._queries_for_manifest(manifest_path, manifest), args.query,
                                   key=lambda item: item.query_id, label="query")
    policies = preview._select_items(e3._policies_for_manifest(manifest_path, manifest), args.policy,
                                    key=lambda item: item.config_id, label="policy")
    expected_modes = PRIMARY_MODES if manifest.get("scale_check") else DEFAULT_MODES
    modes = tuple(args.mode or expected_modes)
    if modes != expected_modes:
        raise ValueError("study requires AF and its declared ordinary baseline set in fixed order")
    measured = 0 if args.correctness_only else args.measured
    schedule = _sampling_schedule_key(getattr(args, "sampling_schedule", "legacy"))
    if measured < 0 or (not args.correctness_only and measured < 1):
        raise ValueError("invalid repetitions")
    scales = {item["name"]: item["scale"] for item in manifest["datasets"]}
    layout_override = template_materialization_override(getattr(args, "materialize_template", None))
    wrapper, layouts, declared_runtime = resolve_study_materialization(source,manifest,
        wrapper_override=getattr(args,"access_root_wrapper",None),layout_override=layout_override)
    if declared_runtime is not None and not getattr(args, "normal_entry_check", False):
        raise ValueError("physical recipe campaigns require --normal-entry-check")
    write_once(output/"protocol.json", {
        "schema": "final_af_e3_study_v1", "started_at": now(), "manifest": str(manifest_path),
        "manifest_sha256": manifest_digest, "modes": modes,
        "queries": [query.query_id for query in queries], "policies": [policy.config_id for policy in policies],
        "minimum_measured": measured, "correctness_only": args.correctness_only,
        "access_root_wrapper": wrapper,
        "access_root_wrapper_override": getattr(args, "access_root_wrapper", None),
        "access_root_materialized_by_template": layouts,
        "access_root_materialized_by_template_override": layout_override,
        **({"physical_recipe_strategy": declared_runtime["physical_recipe_strategy"],
            "declared_runtime_config": declared_runtime,
            "declared_runtime_config_sha256": digest_json(declared_runtime),
            "access_root_materialization_scope": "declared recipe baseline; effective layout is validated per case from the owned physical decision",
            "access_root_wrapper_resolution": "source_normal_physical_recipe_strategy"}
           if declared_runtime is not None else {}),
        "normal_entry_execution_check": getattr(args, "normal_entry_check", False),
        "normal_entry_execution_scope": "one separate exact-body guarded execution per AF case after prospective selection; not a formal timing sample",
        "repetition_policy": "per cell: one complete 2n-round warmup cycle; at least requested measured rounds rounded upward to a complete 2n cycle; n=available modes",
        "actual_case_repetitions": "sampling/<case_id>.json",
        "driver_sha256": digest_bytes(Path(__file__).read_bytes()),
        "current_source": current_identity, "baseline_source": baseline_identity,
        "primary_scope": "postgresql_generated_query_Execution_Time_TIMING_OFF",
        "primary_metric": "median_postgres_query_execution_ms",
        "existing_paper_server_metric": "median_server_query_plus_required_validation_observed_ms",
        "server_validation_scope": "EXPLAIN planning+execution for existing artifact assertions, plus separately observed AF guard DO body execution; DO compilation/statement overhead unobserved",
        "query_instrumentation": "actual bound query executed once by TIMING OFF EXPLAIN ANALYZE; full-result checks separate before timing",
        "artifact_assertion_semantics": "original caprls_assert_artifact_valid raises on mismatch; EXPLAIN ANALYZE executes assertion once and preserves failure abort",
        "companion_client_scope": "psql_connection_RR_transaction_required_validation_PG_explain_planning_execution_commit",
        "choice_scope": "catalog_receipt_and_prospective_admission_choice_separately_reported",
        "af_execution_profile_rule": "Final AF admitted bound SQL with its trusted_explicit execution contract; fixed baselines solely from unchanged baseline_source.",
        "required_af_execution_profile": "trusted_explicit",
        "first_use_scope": "input_counts_catalog_receipt_choice_SQL_generation_primary_request_excluding_artifact_build",
        "first_use_is_estimate_not_complete_cold_request": True,
        "first_use_excludes": ["database_and_data_initialization", "native_RLS_policy_installation",
                               "experimental_statistics_probes", "worker_process_startup"],
        "artifact_build_scope": "shared_setup_separate; with_build_scenario_charges_AF_candidate_pool_build_or_fixed_mode_required_artifact_build",
        "worker_process_overhead": "infrastructure_only_separately_recorded_not_algorithm_choice_time",
        "diagnostics_scope": "separate_post_sampling_EXPLAIN_ANALYZE_BUFFERS_not_primary_samples",
        "baseline_implementation": "normal_fixed_specs_from_unchanged_baseline_source",
        **sampling_schedule_protocol_fields(schedule),
        "artifact_preparation": "all_unique_recipes_built_once_then_common_VACUUM_ANALYZE_before_all_selection",
        "statistics_policy": "catalog_statistics_and_relation_estimates_frozen_across_selection_correctness_timing",
    })
    context = postgres.temporary_cluster(database=args.database) if args.host is None else nullcontext(
        postgres.PostgresEnv(args.host, args.port, args.user, args.database))
    with context as pg_env:
        setup_started = time.perf_counter()
        shared_dir = getattr(args, "shared_preparation", None)
        shared_receipt = None
        if shared_dir is None:
            pg_version = e3._prepare_database(root, pg_env, tpch_scale=scales.get("tpch", ""), job_scale=scales.get("job", ""))
        else:
            # Share data/artifact maintenance, never a selection or verdict.
            if args.host is None:
                raise ValueError("shared preparation requires its explicit existing private database")
            shared_dir = Path(shared_dir).resolve()
            shared_receipt, shared_artifacts = load_shared_preparation(
                shared_dir,postgres=postgres,pg_env=pg_env,manifest_digest=manifest_digest,
                queries=queries,policies=policies)
            pg_version = postgres.run_psql_command("SHOW server_version",pg_env)
        write_once(output/"database.json", {"postgres_version": pg_version,
                   "setup_wall_ms": (time.perf_counter()-setup_started)*1000,
                   "pg_env": asdict(pg_env), "data_scales": scales,
                   "settings": postgres.run_psql_command(
                       "SELECT json_build_object('work_mem',current_setting('work_mem'),'shared_buffers',current_setting('shared_buffers'),'autovacuum',current_setting('autovacuum'))::text", pg_env)})
        if shared_dir is None:
            artifacts = prepare_artifacts(e3, postgres, queries, policies, pg_env)
        else:
            artifacts = shared_artifacts
            write_once(output/"shared_preparation_reuse.json",{
                "schema":"a016_shared_preparation_reuse_v1","path":str(shared_dir),
                "protocol_sha256":digest_bytes((shared_dir/"protocol.json").read_bytes()),
                "artifacts_sha256":digest_bytes((shared_dir/"artifacts.json").read_bytes()),
                "original_setup":shared_receipt,
                "scope":"Reuse unchanged data/artifact maintenance only; normal selection, admission, receipts and validation remain live. Shared build costs belong to initial preparation, not each profile."})
        write_once(output/"shared_artifacts.json", artifacts)
        actual_settings = json.loads(postgres.run_psql_command("""
SELECT json_object_agg(name,json_build_object('setting',setting,'unit',unit,'source',source))::text
FROM pg_settings WHERE name IN ('shared_buffers','work_mem','effective_cache_size','max_wal_size',
 'hash_mem_multiplier','max_connections','autovacuum','jit','max_parallel_workers',
 'max_parallel_workers_per_gather','plan_cache_mode','shared_memory_type','max_worker_processes');
""",pg_env))
        write_once(output/"actual-postgres-settings.json",actual_settings)
        frozen_statistics = statistics_identity(postgres, pg_env)
        write_once(output/"statistics_before_selection.json", frozen_statistics)
        cells = []
        for query in queries:
            for policy in policies:
                case_id = query.query_id + "__" + policy.config_id
                print("prepare " + case_id, flush=True)
                shared_started = time.perf_counter()
                count_started = time.perf_counter()
                protected = e3._protected_count(query, pg_env)
                local = int(postgres.run_psql_command(
                    f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} WHERE {e3._query_local_predicate(query)}", pg_env))
                count_ms = (time.perf_counter()-count_started)*1000
                predicate = e3._policy_predicate(query, policy)
                artifact = artifacts[e3._artifact_id(query, policy)]
                e3._configure_native_rls(query, policy, pg_env)
                count_started = time.perf_counter()
                authorized = int(postgres.run_psql_command(
                    f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} WHERE {predicate}", pg_env))
                count_ms += (time.perf_counter()-count_started)*1000
                stats = {"protected_rows": protected, "query_local_rows": local,
                         "authorized_rows": artifact["artifact_rows"] or authorized,
                         "keyed_artifact_rows": artifact["keyed_artifact_rows"],
                         "artifact_build_ms": artifact["artifact_build_ms"], "input_collection_wall_ms": count_ms,
                         "shared_preparation_wall_ms": (time.perf_counter()-shared_started)*1000}
                request = {"project_root": str(root), "manifest": str(manifest_path),
                           "query_id": query.query_id, "policy_id": policy.config_id,
                           "stats": stats, "pg_env": asdict(pg_env),
                           "access_root_materialized": wrapper == "materialized",
                           "access_root_materialized_by_template": layouts,
                           "verify_normal_execution": getattr(args, "normal_entry_check", False),
                           "fixed_modes": [mode for mode in modes if mode != "af"]}
                workers = {}
                for kind, tree in (("af", source), ("fixed", baseline)):
                    if statistics_identity(postgres, pg_env) != frozen_statistics:
                        raise RuntimeError("planner statistics changed before prospective selection")
                    worker = run_worker(tree, {**request, "variant": "af", "worker_kind": kind,
                                        "required_execution_profile": "trusted_explicit" if kind == "af" else None},
                                        timeout_s=args.worker_timeout)
                    expected = current_identity if kind == "af" else baseline_identity
                    if worker["source_identity"] != expected or worker["manifest_sha256"] != manifest_digest:
                        raise RuntimeError("worker source/manifest changed since campaign start")
                    if statistics_identity(postgres, pg_env) != frozen_statistics:
                        raise RuntimeError("planner statistics changed during prospective selection")
                    if kind == "af":
                        validate_af_bound_spec(worker)
                    workers[kind] = worker
                    write_once(output/"prepared"/case_id/(kind+".json"), worker)
                af = workers["af"]
                entries = [{"mode": "af", "spec": af["spec"], "selection": af["selection"],
                            "source_digest": current_identity["digest"],
                            "worker_request_wall_ms": af["worker_request_wall_ms"]}]
                for mode in modes[1:]:
                    fixed = next(item for item in workers["fixed"]["fixed_modes"] if item["mode"] == mode)
                    entries.append({**fixed, "source_digest": baseline_identity["digest"]})
                cell = {"case_id": case_id, "query_id": query.query_id, "policy_id": policy.config_id,
                        "dataset_scale": scales[query.workload], "stats": stats,
                        "reference": workers["fixed"]["reference"], "modes": entries}
                for entry in entries:
                    if entry["spec"] is not None:
                        script_path = output/"measurement-scripts"/case_id/(entry["mode"]+".sql")
                        script_path.parent.mkdir(parents=True, exist_ok=True)
                        with script_path.open("x", encoding="utf-8") as handle:
                            handle.write(measurement_script(preview, _spec_from_dict(preview, entry["spec"])))
                cells.append(cell)
                write_once(output/"prepared"/case_id/"shared.json", cell)
        by_query = {query.query_id: query for query in queries}
        by_policy = {policy.config_id: policy for policy in policies}

        def restore(cell: Mapping[str, Any]) -> None:
            if statistics_identity(postgres, pg_env) != frozen_statistics:
                raise RuntimeError("planner statistics changed after campaign preparation")
            e3._configure_native_rls(by_query[cell["query_id"]], by_policy[cell["policy_id"]], pg_env)

        def canonicalize(payload: Mapping[str, Any]) -> Mapping[str, Any]:
            return asdict(preview._canonicalize_live(_spec_from_dict(preview, payload), pg_env))

        def measure(payload: Mapping[str, Any]) -> Mapping[str, Any]:
            spec = _spec_from_dict(preview, payload)
            script = measurement_script(preview, spec)
            started = time.perf_counter()
            raw = postgres.run_psql_command(script, pg_env)
            measurement = parse_measurement_output(e3, preview, spec, raw,
                                                  (time.perf_counter()-started)*1000)
            measurement["measurement_script_sha256"] = digest_bytes(script.encode())
            return measurement

        def diagnostic(payload: Mapping[str, Any]) -> Mapping[str, Any]:
            spec = _spec_from_dict(preview, payload)
            statement = preview._single_query(spec.sql)
            raw = postgres.run_psql_command(preview._transaction_script(spec,
                "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON, TIMING OFF, SUMMARY ON) " + statement), pg_env)
            observe_environment = getattr(preview, "_observed_execution_environment", None)
            query_output = getattr(preview, "_execution_query_output", lambda value: value)(raw)
            return {"sql": spec.sql, "sql_sha256": digest_bytes(spec.sql.encode()),
                    "role": spec.role, "artifact_validation_required": bool(spec.artifact_ids),
                    "execution_environment": (observe_environment(spec, raw)
                                              if observe_environment is not None else None),
                    "explain": e3._parse_explain_json(query_output)}

        summary = evaluate_cells(cells, output_dir=output, measured=measured,
                                 canonicalize=canonicalize, measure=measure,
                                 diagnostic=None if args.skip_diagnostics or args.correctness_only else diagnostic,
                                 restore_cell=restore, correctness_only=args.correctness_only,
                                 schedule=schedule)
        if args.smoke_measurement_checks:
            if not args.correctness_only:
                raise ValueError("smoke measurement checks require correctness-only mode")
            for cell in cells:
                restore(cell)
                for entry in cell["modes"]:
                    if entry["spec"] is not None:
                        path = output/"smoke-measurements"/(cell["case_id"]+"__"+entry["mode"]+".json")
                        try:
                            observed = measure(entry["spec"])
                        except Exception as exc:
                            write_once(path, {"status": "error", "case_id": cell["case_id"],
                                "mode": entry["mode"], "spec": entry["spec"],
                                "error": str(exc), "traceback": traceback.format_exc()})
                            raise
                        write_once(path, {"status": "pass", "case_id": cell["case_id"],
                            "mode": entry["mode"], "scope": "single instrumentation smoke check; not statistical or formal timing samples",
                            "measurement": observed})
        if source_identity(source) != current_identity or source_identity(baseline) != baseline_identity:
            raise RuntimeError("source changed during the campaign; results not promotable")
        if digest_bytes(manifest_path.read_bytes()) != manifest_digest:
            raise RuntimeError("manifest changed during the campaign; results not promotable")
        final_statistics = statistics_identity(postgres, pg_env)
        write_once(output/"statistics_after_sampling.json", final_statistics)
        if final_statistics != frozen_statistics:
            raise RuntimeError("planner statistics changed during the campaign; results not promotable")
        import csv
        with (output/"summary.csv").open("x", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(summary[0]) if summary else [])
            writer.writeheader()
            writer.writerows(summary)
        result = {"status": "completed", "finished_at": now(), "cells": len(cells),
                  "mode_results": len(summary), "summary": summary}
        write_once(output/"summary.json", result)
        return result


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "--worker":
        try:
            if len(argv) != 2:
                raise ValueError("worker requires exactly one source root")
            result = worker_payload(Path(argv[1]).resolve(), json.load(sys.stdin))
            code = 0
        except Exception as exc:
            result = {"schema": "final_af_e3_worker_v1", "status": "error",
                      "error": str(exc), "traceback": traceback.format_exc()}
            code = 1
        print(FRAME + json.dumps(result, ensure_ascii=False), flush=True)
        return code
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--source-root")
    parser.add_argument("--baseline-source", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--query", action="append")
    parser.add_argument("--policy", action="append")
    parser.add_argument("--mode", action="append", choices=DEFAULT_MODES)
    parser.add_argument("--measured", type=int, default=30)
    parser.add_argument("--sampling-schedule", choices=("legacy", ADJACENT_SAMPLING_SCHEDULE), default="legacy",
                        help="legacy preserves the original schedule; adjacent pairs AF/IP under declared role symmetry and changed cache conditions")
    parser.add_argument("--correctness-only", action="store_true")
    parser.add_argument("--smoke-measurement-checks", action="store_true",
                        help="correctness-only: one untimed-for-statistics instrumentation check per available case/method")
    parser.add_argument("--skip-diagnostics", action="store_true")
    parser.add_argument("--worker-timeout", type=float, default=1800)
    parser.add_argument("--access-root-wrapper", choices=("materialized", "not_materialized_single_reference"),
                        help="AF-only bound runner composition; admission, exact SQL binding and checks remain required")
    parser.add_argument("--materialize-template", action="append",
                        help="repeat template IDs to override the source default materialized handoffs; omitted uses the source preset")
    parser.add_argument("--normal-entry-check", action="store_true",
                        help="verify one exact full-query execution through the same-process normal AF API before formal timing")
    parser.add_argument("--host", help="reuse an explicitly supplied experiment cluster; otherwise create one temporary cluster")
    parser.add_argument("--shared-preparation",type=Path,
        help="Verified common data/artifact preparation in an existing private cluster; does not reuse choices")
    parser.add_argument("--port", type=int, default=5432)
    parser.add_argument("--user", default="postgres")
    parser.add_argument("--database", default="caprls_final_af_e3")
    args = parser.parse_args(argv)
    existed = Path(args.output_dir).exists()
    try:
        result = run_study(args)
        print(json.dumps({key: value for key, value in result.items() if key != "summary"}))
        return 0
    except Exception as exc:
        if not existed and Path(args.output_dir).is_dir():
            failure = Path(args.output_dir)/"failure.json"
            if not failure.exists():
                write_once(failure, {"status": "failed", "at": now(), "error": str(exc),
                                     "traceback": traceback.format_exc()})
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
