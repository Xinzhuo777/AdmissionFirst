"""Prepare and execute the AdmissionFirst E3 workload."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path
import time
from typing import Any, Mapping

import yaml

from . import e3_main as e3
from . import e3_sigmod_preview as preview
from .postgres_runner import PostgresEnv, PostgresError, run_psql_command
from planner.identity_observation import backend_info as identity_observation_backend_info


ALGORITHM_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNTIME_CONFIG = ALGORITHM_ROOT / "configs/normal_e3_af_candidate.yaml"
_CONFIG_KEYS = {"schema", "name", "configuration_status", "execution_profile", "access_root_wrapper"}
_LAYOUT_KEY = "access_root_materialized_by_template"
_STRATEGY_KEY = "physical_recipe_strategy"
_STAT_DEFAULTS = {"protected_rows": 1, "query_local_rows": 1, "authorized_rows": 1,
                  "artifact_build_ms": 0.0, "keyed_artifact_rows": 0}


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def load_runtime_config(config: Mapping[str, Any] | Path | str | None = None) -> dict[str, Any]:
    if isinstance(config, Mapping):
        value = dict(config)
    else:
        path = DEFAULT_RUNTIME_CONFIG if config is None else Path(config)
        value = yaml.safe_load(path.read_text())
    if not isinstance(value, dict) or not (_CONFIG_KEYS <= set(value) <= _CONFIG_KEYS | {_LAYOUT_KEY, _STRATEGY_KEY}):
        raise ValueError("normal AF runtime configuration shape is unsupported")
    if (value["schema"] != "normal_e3_af_runtime_v1"
            or not isinstance(value["name"], str) or not value["name"]
            or value["configuration_status"] != "candidate_not_accepted"
            or value["execution_profile"] != "trusted_explicit"
            or value["access_root_wrapper"] not in {"materialized", "not_materialized_single_reference"}):
        raise ValueError("normal AF requires an explicit supported candidate execution configuration")
    if _LAYOUT_KEY in value:
        layouts = value[_LAYOUT_KEY]
        if (not isinstance(layouts, Mapping) or any(type(key) is not str or not key
                or type(flag) is not bool for key, flag in layouts.items())):
            raise ValueError("normal AF template handoff configuration is invalid")
        value[_LAYOUT_KEY] = dict(layouts)
    if _STRATEGY_KEY in value and (
            value[_STRATEGY_KEY] != e3.E3_PHYSICAL_RECIPE_STRATEGY
            or value["access_root_wrapper"] != "not_materialized_single_reference"
            or value.get(_LAYOUT_KEY) != {"auth_index_enum_v1": True}):
        raise ValueError("normal AF physical recipe strategy requires the fixed inline/strong-MAT policy")
    return value


def _implementation_identity() -> dict[str, Any]:
    paths = []
    for directory, suffixes in (("caprls_core", ("*.py",)), ("planner", ("*.py",)),
                                ("configs", ("*.yaml",)), ("sql", ("*.sql", "*.yaml", "*.json")),
                                ("workloads", ("*.sql", "*.yaml", "*.json")),
                                ("specs", ("*.sql", "*.yaml", "*.json"))):
        for suffix in suffixes:
            paths.extend((ALGORITHM_ROOT/directory).rglob(suffix))
    files = {str(path.relative_to(ALGORITHM_ROOT)): _digest(path.read_bytes())
             for path in sorted(paths) if "__pycache__" not in path.parts}
    return {"root": str(ALGORITHM_ROOT), "digest": _digest(json.dumps(
        files, sort_keys=True, separators=(",", ":")).encode()), "files": files}


@dataclass(frozen=True)
class PreparedNormalE3AF:
    """Same-process result container; execution still replays existing seals."""
    plan_result: Any
    query_plan: Mapping[str, Any]
    spec: preview.ExecutionSpec
    pg_env: PostgresEnv
    planning_catalog_receipt: Any
    metadata: Mapping[str, Any]
    physical_recipe_decision: Any = None


def _bound_spec(query: Any, policy: Any, plan_result: Any,
                query_plan: Mapping[str, Any]) -> preview.ExecutionSpec:
    e3._require_e3_production_plan_lineage(plan_result, query_plan)
    template = e3._require_e3_selected_root_template(query_plan)
    bound = query_plan["production_bound_runner"]
    if (bound["query_id"] != query.query_id or bound["policy_id"] != policy.config_id
            or bound["template_id"] != template or plan_result.chosen_template is None
            or plan_result.chosen_template.template_id != template
            or bound["runner_sql_digest"] != e3._canonical_sha256({"exact_runner_sql": bound["runner_sql"]})):
        raise PostgresError("normal AF selected bound runner identity differs")
    source = e3._source_for_template(template)
    if source == "rls":
        raise PostgresError("normal AF explicit configuration cannot delegate native RLS")
    artifact_ids, expected = preview._artifact_validation_for(query, policy, source)
    spec = preview.ExecutionSpec(
        mode="af", template_id=template,
        alternative=plan_result.chosen_template.alternative,
        sql=bound["runner_sql"], sql_source=source,
        result_columns=preview._result_columns_for(query),
        role=bound["session_contract"]["role"], artifact_ids=artifact_ids,
        expected_artifact_json=expected, session_contract=bound["session_contract"],
        execution_profile=bound["execution_profile"],
    )
    preview._execution_contract(spec)
    return spec


def prepare_normal_e3_af(*, query_id: str, policy_id: str, manifest_path: Path | str,
                         project_root: Path | str, pg_env: PostgresEnv,
                         stats: Mapping[str, Any] | None = None,
                         runtime_config: Mapping[str, Any] | Path | str | None = None,
                         planning_catalog_receipt: Any = None) -> PreparedNormalE3AF:
    """Prepare the actual bound query without database/artifact maintenance.

    ``stats`` are diagnostic setup metadata, not measured-runtime selection
    evidence. With no metadata supplied, explicit conservative placeholders
    avoid count queries. A supplied receipt is revalidated by the existing
    production factory; its external collection time is recorded as None.
    """
    started = time.perf_counter()
    config = load_runtime_config(runtime_config)
    root = Path(project_root).resolve()
    manifest_path = Path(manifest_path)
    manifest_path = (root/manifest_path).resolve() if not manifest_path.is_absolute() else manifest_path.resolve()
    manifest = e3._load_manifest(manifest_path)
    e3._validate_manifest(manifest_path, manifest)
    queries = [q for q in e3._queries_for_manifest(manifest_path, manifest) if q.query_id == query_id]
    policies = [p for p in e3._policies_for_manifest(manifest_path, manifest) if p.config_id == policy_id]
    if len(queries) != 1 or len(policies) != 1:
        raise ValueError("normal AF requires one canonical query/policy declared by the manifest")
    query, policy = queries[0], policies[0]
    e3._require_e3_canonical_query_policy_sources(query, policy)
    registry = e3._e3_registry_from_manifest(manifest)
    if "native_pg_rls_v1" in e3._e3_registry_template_ids(registry):
        raise PostgresError("normal AF trusted explicit preset rejects a native-RLS portfolio")
    layouts = config.get(_LAYOUT_KEY, {})
    if set(layouts) - set(e3._e3_registry_template_ids(registry)):
        raise ValueError("normal AF template handoff configuration names an unavailable template")
    diagnostic = dict(_STAT_DEFAULTS) if stats is None else dict(stats)
    for name in _STAT_DEFAULTS:
        value = diagnostic.get(name)
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError("normal AF diagnostic statistics are invalid: " + name)
    diagnostic = json.loads(json.dumps(diagnostic, allow_nan=False))
    predicate = e3._policy_predicate(query, policy)
    receipt = planning_catalog_receipt
    receipt_ms = None
    if receipt is None:
        receipt_started = time.perf_counter()
        receipt = e3._collect_e3_planning_catalog_receipt(
            query, policy, pg_env, execution_profile=config["execution_profile"])
        receipt_ms = (time.perf_counter()-receipt_started)*1000
    # Calibration follows the algorithm package, independently of the data
    # project root. It remains legacy diagnostic input to full-root selection.
    ranker = e3._ranker_from_manifest(ALGORITHM_ROOT, manifest)
    selection_started = time.perf_counter()
    common = dict(
        query=query, policy=policy, predicate=predicate, pg_env=pg_env,
        protected_rows=diagnostic["protected_rows"], query_local_rows=diagnostic["query_local_rows"],
        authorized_rows=diagnostic["authorized_rows"], build_ms=diagnostic["artifact_build_ms"],
        keyed_artifact_rows=diagnostic["keyed_artifact_rows"], ranker=ranker, registry=registry,
        planning_catalog_receipt=receipt, execution_profile=config["execution_profile"],
    )
    decision = None
    selection_audit = None
    declared_digest = _digest(json.dumps(config, sort_keys=True, separators=(",", ":")).encode())
    effective = dict(config)
    if _STRATEGY_KEY in config:
        result, plan, _problem, decision = e3._plan_e3_admission_first_physical_recipes(
            **common, declared_config_digest=declared_digest)
        selection_audit = e3._require_e3_physical_recipe_decision(
            decision, plan_result=result, query_plan=plan,
            declared_config_digest=declared_digest)
        effective.pop(_STRATEGY_KEY)
        effective[_LAYOUT_KEY] = dict(selection_audit["effective_layout_policy"]["materialized_by_template"])
    else:
        result, plan, _problem = e3._plan_e3_admission_first(
            **common, access_root_materialized=config["access_root_wrapper"] == "materialized",
            access_root_materialized_by_template=layouts)
    selection_ms = (time.perf_counter()-selection_started)*1000
    spec = _bound_spec(query, policy, result, plan)
    metadata = {
        "schema": "normal_e3_af_prepared_v1", "query_id": query_id, "policy_id": policy_id,
        "algorithm_mode": e3.ADMISSION_FIRST_MODE,
        "configuration_status": "candidate_not_accepted", "resolved_runtime_config": effective,
        "runtime_config_sha256": _digest(json.dumps(effective, sort_keys=True, separators=(",", ":")).encode()),
        "manifest": str(manifest_path), "manifest_sha256": _digest(manifest_path.read_bytes()),
        "project_root": str(root), "source_identity": _implementation_identity(),
        "diagnostic_stats": diagnostic,
        "stats_source": "diagnostic_placeholders" if stats is None else "caller_setup_diagnostics",
        "production_selection_evidence": "same-transaction plain EXPLAIN of admitted complete bound roots",
        "catalog_receipt_wall_ms": receipt_ms,
        "receipt_source": "internally_collected" if planning_catalog_receipt is None else "externally_collected_revalidated_by_production_factory",
        "selection_wall_ms": selection_ms,
        "identity_observation_backend": identity_observation_backend_info(),
        "stage_scope": "receipt time is None when externally collected, not zero cost; selection time encloses only the production factory",
        "database_or_artifact_maintenance_performed": False,
        "prepare_wall_ms": (time.perf_counter()-started)*1000,
    }
    if decision is not None:
        metadata.update(declared_runtime_config=config,
                        declared_runtime_config_sha256=declared_digest,
                        physical_recipe_selection=selection_audit)
    return PreparedNormalE3AF(result, plan, spec, pg_env, receipt, metadata, decision)


def _validate_prepared(prepared: PreparedNormalE3AF) -> preview.ExecutionSpec:
    if type(prepared) is not PreparedNormalE3AF:
        raise PostgresError("normal AF execution requires its same-process prepared container")
    # This existing accessor replays the original strong plan and query-plan
    # registrations. The owner retains the actual compile connection target.
    query_row, _lineage_row = e3._e3_owned_production_plan_rows(prepared.plan_result, prepared.query_plan)
    owner = query_row[2]
    if e3._e3_connection_target_payload(prepared.pg_env) != e3._e3_connection_target_payload(owner.pg_env):
        raise PostgresError("normal AF execution target differs from the sealed planning target")
    receipt = e3._require_e3_production_catalog_receipt(
        prepared.planning_catalog_receipt, query=owner.query, policy=owner.policy,
        predicate=e3._policy_predicate(owner.query, owner.policy), pg_env=prepared.pg_env,
        execution_profile="trusted_explicit")
    e3._require_e3_query_plan_catalog_receipt(prepared.query_plan, receipt)
    declared = prepared.metadata.get("declared_runtime_config")
    declared_digest = None
    if declared is not None:
        if type(declared) is not dict:
            raise PostgresError("normal AF declared recipe configuration must be an issued object")
        try:
            declared = load_runtime_config(declared)
        except (TypeError, ValueError) as exc:
            raise PostgresError("normal AF declared recipe configuration changed") from exc
        if _STRATEGY_KEY not in declared:
            raise PostgresError("normal AF declared physical recipe strategy is missing")
        declared_digest = _digest(json.dumps(declared, sort_keys=True, separators=(",", ":")).encode())
    audit = e3._require_e3_physical_recipe_handoff(
        prepared.plan_result, prepared.query_plan, prepared.physical_recipe_decision,
        declared_config_digest=declared_digest)
    if audit is not None:
        effective = {k: v for k, v in declared.items() if k != _STRATEGY_KEY}
        effective[_LAYOUT_KEY] = dict(audit["effective_layout_policy"]["materialized_by_template"])
        effective_digest = _digest(json.dumps(effective, sort_keys=True, separators=(",", ":")).encode())
        if (prepared.metadata.get("declared_runtime_config_sha256") != declared_digest
                or prepared.metadata.get("physical_recipe_selection") != audit
                or prepared.metadata.get("resolved_runtime_config") != effective
                or prepared.metadata.get("runtime_config_sha256") != effective_digest):
            raise PostgresError("normal AF physical recipe metadata differs from its owned decision")
    elif prepared.metadata.get("physical_recipe_selection") is not None:
        raise PostgresError("normal AF has an unissued physical recipe audit")
    expected = _bound_spec(owner.query, owner.policy, prepared.plan_result, prepared.query_plan)
    if type(prepared.spec) is not preview.ExecutionSpec or asdict(prepared.spec) != asdict(expected):
        raise PostgresError("normal AF execution spec differs from its exact admitted bound query")
    return expected


def prepared_report(prepared: PreparedNormalE3AF) -> dict[str, Any]:
    """Review export; serialized output is not an executable authorization."""
    spec = _validate_prepared(prepared)
    return {"metadata": dict(prepared.metadata), "spec": asdict(spec),
            "bound_runner": prepared.query_plan["production_bound_runner"],
            "selected_template_id": spec.template_id,
            "selected_plan_id": prepared.query_plan["production_bound_runner"]["plan_id"]}


def execute_normal_e3_af(prepared: PreparedNormalE3AF) -> dict[str, Any]:
    """Execute the admitted full query body once, retaining all existing guards."""
    spec = _validate_prepared(prepared)
    statement = preview._single_query(spec.sql)
    script = preview._transaction_script(spec, statement)
    if script.count(statement) != 1:
        raise PostgresError("normal AF bound query body is not unique in its transaction script")
    started = time.perf_counter()
    raw = run_psql_command(script, prepared.pg_env)
    wall_ms = (time.perf_counter()-started)*1000
    observed = preview._observed_execution_environment(spec, raw)
    return {"schema": "normal_e3_af_execution_v1", "status": "executed",
            "configuration_status": "candidate_not_accepted", "raw_output": raw,
            "execution_environment": observed, "client_execution_wall_ms": wall_ms,
            "exact_bound_sql_sha256": _digest(spec.sql.encode()),
            "transaction_script_sha256": _digest(script.encode()),
            "query_body_executions": 1, "independent_result_correctness_checked": False,
            "scope": "one admitted complete query with existing receipt, environment and artifact checks; no EXPLAIN/count/canonicalize replacement"}
