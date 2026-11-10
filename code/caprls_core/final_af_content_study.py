"""Fresh protected-position verification for final AF's 52 E2/E3/E10 cases.

The current template declaration replaces the old 14-template compatibility
assumption. All other implementation-fidelity checks and the existing
same-snapshot, values/NULLs/duplicates comparison remain in force. Historical
template identity is recorded; it does not substitute for a fresh semantic
comparison of the actual selected boundary.
"""

from __future__ import annotations

import argparse
import ast
from contextlib import contextmanager, nullcontext
import inspect
import json
import os
from pathlib import Path
import re
import time
import traceback
from typing import Any, Mapping, Sequence

import yaml

from . import content_spec_audit as audit
from . import content_verify as content
from .final_af_auxiliary_study import ROOT, PROTECTED, _sha, _snapshot, _source_inventory, _freeze_driver_files, _drift, _utc, _write

COMPATIBILITY = "specs/final_af_content_compatibility_2026_10_28.yaml"
FINAL_AF_SOURCE = "AF-wiki/raw/checkpoints/af-a007-canonical-policy-check-2026-10-26/source"
E3_MANIFEST = "output/section65_original_protocol_execution_2026-10-06/e3_original_30.yaml"
ARTIFACT_VALIDATION_TAG_PREFIX = "artifact_validation_"


def content_access_root_wrapper(manifest: Mapping[str, Any], override: str | None = None) -> str:
    wrapper = (override if override is not None else
               (manifest.get("scale_check") or {}).get("bound_runner_wrapper", "materialized"))
    if type(wrapper) is not str or wrapper not in {"materialized", "not_materialized_single_reference"}:
        raise ValueError("unsupported access-root wrapper")
    return wrapper


def content_artifact_validation_sql(spec: Any) -> str:
    """Execute the production validator with tagged Boolean output per artifact."""
    if not spec.artifact_ids:
        return ""
    if not spec.expected_artifact_json:
        raise ValueError("artifact-backed content check lacks expected dependencies")
    return "\n".join(content._tagged(ARTIFACT_VALIDATION_TAG_PREFIX + str(index),
        "public.caprls_assert_artifact_valid("
        + content.quote_literal(artifact_id) + ", "
        + content.quote_literal(spec.expected_artifact_json) + "::jsonb)::text")
        for index, artifact_id in enumerate(spec.artifact_ids))


def validate_content_artifact_tags(values: Mapping[str, str], artifact_ids: Sequence[str]) -> dict[str, Any]:
    expected = {ARTIFACT_VALIDATION_TAG_PREFIX + str(index) for index in range(len(artifact_ids))}
    observed = {key: value for key, value in values.items() if key.startswith(ARTIFACT_VALIDATION_TAG_PREFIX)}
    if set(observed) != expected or any(value != "true" for value in observed.values()):
        raise content.ContentRefusal("artifact validation output is missing, unexpected, or not true",
             partial={"refusal_operands": {"expected_artifact_validation_tags": sorted(expected),
                      "observed_artifact_validation_tags": observed, "artifact_ids": list(artifact_ids)}})
    return {"artifact_ids": list(artifact_ids), "tagged_results": observed,
            "all_artifacts_validated": True}


def split_current_access_root(sql: str) -> tuple[str, str, str]:
    """Extract the exact CTE body while retaining byte-recomposition operands."""
    match = re.match(r"\AWITH caprls_access_root AS (?:NOT )?MATERIALIZED \(", sql)
    if match is None:
        raise ValueError("bound SQL lacks its exact caprls_access_root wrapper")
    start, depth, quote, dollar, index = match.end(), 1, None, None, match.end()
    while index < len(sql):
        char = sql[index]
        if dollar is not None:
            if sql.startswith(dollar, index):
                index += len(dollar)
                dollar = None
                continue
        elif quote is not None:
            if char == quote:
                if index + 1 < len(sql) and sql[index + 1] == quote:
                    index += 2
                    continue
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "$":
            tag = re.match(r"\$[A-Za-z_0-9]*\$", sql[index:])
            if tag is not None:
                dollar = tag.group()
                index += len(dollar)
                continue
        elif sql.startswith("--", index):
            newline = sql.find("\n", index)
            index = len(sql) if newline < 0 else newline
            continue
        elif sql.startswith("/*", index):
            closing = sql.find("*/", index + 2)
            if closing < 0:
                raise ValueError("unclosed SQL comment in access root")
            index = closing + 2
            continue
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                prefix, body, suffix = sql[:start], sql[start:index], sql[index:]
                if prefix + body + suffix != sql:
                    raise ValueError("access-root extraction is not byte reversible")
                return prefix, body, suffix
        index += 1
    raise ValueError("unbalanced access-root wrapper")


class FinalE3Session:
    """Select through the same isolated final-AF worker as the timing study."""
    def __init__(self, root: Path, pg_env: Any, manifest_path: Path,
                 source: Path, output: Path, *, access_root_wrapper: str | None = None,
                 access_root_materialized_by_template: Mapping[str, bool] | None = None):
        from . import e3_main as e3
        from . import final_af_e3_study as study
        self.root, self.pg_env, self.source, self.output = root, pg_env, source, output
        self.manifest_path = manifest_path
        self.manifest = yaml.safe_load(manifest_path.read_text())
        self.access_root_wrapper_override = access_root_wrapper
        self.access_root_wrapper = content_access_root_wrapper(self.manifest, access_root_wrapper)
        self.access_root_materialized = self.access_root_wrapper == "materialized"
        self.access_root_materialized_by_template_override = (
            None if access_root_materialized_by_template is None else
            study.validate_access_root_materialized_by_template(access_root_materialized_by_template))
        self.access_root_materialized_by_template = study.resolve_access_root_materialized_by_template(
            source, self.access_root_materialized_by_template_override)
        self.queries = {query.query_id: query for query in e3._queries_for_manifest(manifest_path, self.manifest)}
        self.policies = {policy.config_id: policy for policy in e3._policies_for_manifest(manifest_path, self.manifest)}
        scales = {item["name"]: str(item["scale"]) for item in self.manifest["datasets"]}
        self.tpch_scale, self.job_scale = scales.get("tpch", ""), scales.get("job", "")
        # run_content_study has already provisioned this isolated family DB
        # through the original builder. Selection must use that same data state.
        self.worker = None

    def candidate(self, cell: Mapping[str, Any]) -> content.CandidateBoundary:
        from dataclasses import asdict
        from . import e3_main as e3
        from . import final_af_e3_study as study
        from .postgres_runner import run_psql_command
        query, policy = self.queries[cell["query_id"]], self.policies[cell["policy_id"]]
        predicate = e3._policy_predicate(query, policy)
        build_ms, artifact_rows, keyed_rows = e3._build_artifact(query, policy, predicate, self.pg_env)
        e3._configure_native_rls(query, policy, self.pg_env)
        local_rows = int(run_psql_command(f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} WHERE {e3._query_local_predicate(query)};", self.pg_env))
        authorized = int(run_psql_command(f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} WHERE {predicate};", self.pg_env))
        request = {"worker_kind": "af", "variant": "af", "query_id": query.query_id,
                   "project_root": str(self.root),
                   "policy_id": policy.config_id, "manifest": str(self.manifest_path),
                   "pg_env": asdict(self.pg_env), "access_root_materialized": self.access_root_materialized,
                   "access_root_materialized_by_template": self.access_root_materialized_by_template,
                   "required_execution_profile": "trusted_explicit",
                   "stats": {"protected_rows": e3._protected_count(query, self.pg_env),
                             "query_local_rows": local_rows, "authorized_rows": artifact_rows or authorized,
                             "artifact_build_ms": build_ms, "keyed_artifact_rows": keyed_rows}}
        self.worker = study.run_worker(self.source, request)
        study.validate_af_bound_spec(self.worker)
        _write(self.output / "workers" / (cell["short_id"] + ".json"), self.worker)
        spec, selection = self.worker["spec"], self.worker["selection"]
        if selection.get("access_root_materialized_by_template", {}) != self.access_root_materialized_by_template:
            raise ValueError("worker per-template layout record differs from the resolved policy")
        prefix, body, suffix = split_current_access_root(spec["sql"])
        actual_materialized = prefix.startswith("WITH caprls_access_root AS MATERIALIZED (")
        selected_materialized = self.access_root_materialized_by_template.get(
            spec["template_id"], self.access_root_materialized)
        if actual_materialized != selected_materialized:
            raise ValueError("actual bound access-root wrapper differs from the resolved experiment configuration")
        proof = {"fidelity": "verbatim_subplan_planner_anchored", "extraction": "actual_bound_access_root",
                 "recomposition_byte_identical": prefix + body + suffix == spec["sql"],
                 "wrapper_prefix": prefix, "continuation_suffix": suffix,
                 "manifest_access_root_wrapper": (self.manifest.get("scale_check") or {}).get("bound_runner_wrapper", "materialized"),
                 "resolved_access_root_wrapper": self.access_root_wrapper,
                 "access_root_wrapper_override": self.access_root_wrapper_override,
                 "access_root_materialized_by_template": self.access_root_materialized_by_template,
                 "access_root_materialized_by_template_override": self.access_root_materialized_by_template_override,
                 "resolved_selected_access_root_materialized": selected_materialized,
                 "actual_access_root_materialized": actual_materialized,
                 "selected_runner_digest_recomputed": study.digest_json({"exact_runner_sql": spec["sql"]}),
                 "selected_plan_id": selection["selected_plan_id"],
                 "actual_execution_profile": spec["execution_profile"], "actual_session_contract": spec["session_contract"],
                 "actual_bound_runner": selection["bound_runner"], "worker_source_identity": self.worker["source_identity"]}
        proof.update(content.evaluate_r_c_containment(cell, body,
                     "same" if spec["template_id"] == cell["frozen"]["selected_template_id"] else "differs"))
        if proof.get("r_c_containment") == "failed":
            raise content.ContentRefusal("actual bound access root lacks the declared query target", partial={"extraction_proof": proof})
        return content.CandidateBoundary(selected_template_id=spec["template_id"],
                    selected_plan_id=selection["selected_plan_id"], selected_runner_digest=selection["selected_runner_digest"],
                    runner_sql=spec["sql"], boundary_sql=body, prospective_total_cost=selection["prospective_total_cost"],
                    predicate_text=predicate, extraction_proof=proof, candidate_cost_vector=selection["candidate_cost_vector"],
                    cost_vector_source="actual final-AF worker prospective selection")


@contextmanager
def final_e3_transaction_adapter(session: FinalE3Session):
    """Keep the actual read-only execution contract during the bag check.

    Typed TEMP tables are created WITH NO DATA before the read-only transaction.
    INSERT into those temporary tables is allowed in READ ONLY mode; both
    protected reads and reference reads occur after the production guard and
    artifact validation, inside that one repeatable-read transaction.
    """
    original = content.build_transaction_script
    original_parser = content.parse_tagged_output
    def build(cell, candidate_sql, reference_sql, policy_cardinality_sql, *, crossvalidate):
        from . import e3_sigmod_preview as preview
        from . import final_af_e3_study as study
        script = original(cell, candidate_sql, reference_sql, policy_cardinality_sql, crossvalidate=crossvalidate)
        spec = study._spec_from_dict(preview, session.worker["spec"])
        guard = preview._execution_environment_guard(spec)
        environment_sql = preview._execution_environment_sql()
        if environment_sql not in guard:
            raise ValueError("production guard no longer exposes its environment reporting tail")
        guard = guard[:guard.rindex(environment_sql)]
        validation = content_artifact_validation_sql(spec)
        declarations = []
        for name, query in ((content.ACTUAL_TABLE, candidate_sql), (content.REFERENCE_TABLE, reference_sql)):
            create = f"CREATE TEMP TABLE {name} ON COMMIT DROP AS\n{query.rstrip().rstrip(';')};"
            if create not in script:
                raise ValueError("protected-position table materialization changed unexpectedly")
            declarations.append(f"CREATE TEMP TABLE {name} AS\n{query.rstrip().rstrip(';')} WITH NO DATA;")
            script = script.replace(create, f"INSERT INTO {name}\n{query.rstrip().rstrip(';')};", 1)
        script = script.replace("BEGIN ISOLATION LEVEL REPEATABLE READ;", "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;", 1)
        before_snapshot = "\n" + content._tagged("snapshot", "jsonb_build_object("
            "'snapshot_token', pg_current_snapshot()::text, 'current_user', current_user, "
            "'pg_version', current_setting('server_version'), 'isolation', current_setting('transaction_isolation'))::text")
        if before_snapshot not in script:
            raise ValueError("cannot locate same-snapshot guard insertion point")
        role = 'SET LOCAL ROLE "' + spec.role.replace('"', '""') + '";'
        script = script.replace(before_snapshot, "\n" + role + "\n" + guard + "\n" + validation + before_snapshot, 1)
        return "SET search_path TO pg_catalog, public;\n" + "\n".join(declarations) + "\n" + script
    def parse(raw):
        values = original_parser(raw)
        session.artifact_validation_observed = validate_content_artifact_tags(
            values, session.worker["spec"].get("artifact_ids", ()))
        return values
    content.build_transaction_script = build
    content.parse_tagged_output = parse
    try:
        yield
    finally:
        content.build_transaction_script = original
        content.parse_tagged_output = original_parser


def _compatibility_path(root: Path, compatibility: Path | None = None) -> Path:
    path = Path(compatibility) if compatibility is not None else Path(COMPATIBILITY)
    path = (path if path.is_absolute() else root / path).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("compatibility declaration must be inside the project root")
    return path


def load_compatibility(root: Path, compatibility: Path | None = None) -> dict[str, Any]:
    declaration = yaml.safe_load(_compatibility_path(root, compatibility).read_text())
    if declaration.get("schema") != "caprls-final-af-content-compatibility-v1":
        raise ValueError("unrecognized current content compatibility declaration")
    return declaration


def audit_current_templates(declaration: Mapping[str, Any]) -> dict[str, Any]:
    """Check every explicit current emitter and its registry membership."""
    from planner import contracts, emit
    from planner.core import DEFAULT_TEMPLATE_REGISTRY
    definitions = list(contracts.TEMPLATE_DEFINITIONS)
    rows = declaration["templates"]
    errors, checks = [], []
    declared_ids = [row["template_id"] for row in rows]
    actual_ids = [definition.template_id for definition in definitions]
    if declared_ids != actual_ids:
        errors.append("explicit template list/order differs from current canonical definitions")
    actual_default = {template.template_id for template in DEFAULT_TEMPLATE_REGISTRY.template_specs()}
    declared_default = {row["template_id"] for row in rows if row["in_default_registry"]}
    if actual_default != declared_default:
        errors.append("explicit default-registry set differs from actual default registry")
    by_id = {definition.template_id: definition for definition in definitions}
    for row in rows:
        template = row["template_id"]
        definition = by_id.get(template)
        emitter = getattr(emit, row["emitter"], None)
        failures = []
        if definition is None or emitter is None:
            failures.append("canonical definition or declared emitter missing")
        else:
            calls = [node.func for node in ast.walk(ast.parse(inspect.getsource(emitter)))
                     if isinstance(node, ast.Call)]
            direct = any(isinstance(fn, ast.Attribute) and fn.attr == "query_predicate_for" for fn in calls)
            delegated = any(isinstance(fn, ast.Name) and fn.id == "_lower_safe_predicate_injection" for fn in calls)
            observed = direct or delegated
            declared = row["carries_query_predicate"]
            if declared not in {"yes", "no", "conditional"}:
                failures.append("unknown query-predicate declaration")
            elif observed != (declared != "no"):
                failures.append("query-predicate use differs from explicit declaration")
            if bool(definition.include_in_default_registry) != row["in_default_registry"]:
                failures.append("default registry membership differs")
            routed = emit.PROTECTED_SCAN_LOWERERS.get(template)
            if template != "raw_pushdown_positive_control_v1" and routed is not emitter:
                failures.append("actual protected-scan lowerer differs from declared emitter")
        checks.append({**row, "status": "fail" if failures else "pass", "errors": failures})
        errors.extend(template + ": " + failure for failure in failures)
    return {"schema": "caprls-final-af-content-template-audit-v1", "status": "fail" if errors else "pass",
            "checked_templates": len(checks), "checks": checks, "errors": errors}


def current_audit(root: Path, spec_path: Path | None = None, *,
                  compatibility: Path | None = None) -> dict[str, Any]:
    compatibility_path = _compatibility_path(root, compatibility)
    declaration = load_compatibility(root, compatibility_path)
    declared_spec = root / declaration["base_spec"]
    if spec_path is not None and _sha(spec_path) != _sha(declared_spec):
        raise ValueError("provided content spec differs from its compatibility declaration")
    spec_path = spec_path or declared_spec
    # Every old semantic/fidelity item still runs. Only its obsolete fixed-size
    # template table check is replaced by the complete current-version check.
    legacy = audit.run_audit(root, spec_path)
    current = audit_current_templates(declaration)
    retained = [item.to_dict() for item in legacy.items if item.item != "carries_query_predicate"]
    for item in retained:
        if item["item"] == "selection_classification":
            item["scope"] = "historical classification table fidelity only; current validation policy independently checks actual selected boundaries"
    return {"schema": "caprls-final-af-content-audit-v1", "status": "pass" if
            current["status"] == "pass" and all(item["status"] == "pass" for item in retained) else "fail",
            "compatibility": str(compatibility_path), "compatibility_sha256": _sha(compatibility_path),
            "source_spec": str(spec_path), "source_spec_sha256": _sha(spec_path), "template_audit": current,
            "retained_fidelity_items": retained,
            "replaced_check": "14-template count/order/tally replaced by explicit current template list and per-emitter checks"}


def current_validation_policy(cells: Sequence[Mapping[str, Any]],
                              declaration: Mapping[str, Any]) -> dict[str, Any]:
    # This declares the scope of a fresh correctness check, not a cause for a
    # historical template difference. Native/diagnostic modes cannot enter it.
    allowed = [row["template_id"] for row in declaration["templates"]
               if row["template_id"] not in {"native_pg_rls_v1", "raw_pushdown_positive_control_v1"}]
    return {"schema": "caprls-final-af-content-selection-policy-v1", "entries": [
        {"short_id": cell["short_id"], "cell_id": cell["cell_id"],
         "frozen_selected_template_id": cell["frozen"]["selected_template_id"],
         "admissible_observed_templates": allowed,
         "cause": "not_attributed_current_implementation_requires_fresh_semantic_validation",
         "selection_stability": None,
         "evidence_ref": "current-validation-policy.json; receipt contains actual selected SQL and full boundary comparison"}
        for cell in cells],
        "acceptance": "actual admitted boundary equals independently generated reference as a multiset in the same snapshot",
        "historical_identity": "diagnostic provenance; no historical performance is imported"}


def run_content_study(root: Path, output: Path, *, only: Sequence[str] | None = None,
                      source: Path | None = None, manifest: Path | None = None,
                      access_root_wrapper: str | None = None,
                      compatibility: Path | None = None,
                      access_root_materialized_by_template: Mapping[str, bool] | None = None) -> dict[str, Any]:
    root, output = root.resolve(), output.resolve()
    allowed = (root / "results/raw", root / "AF-wiki/raw/experiments")
    if not any(output != base and output.is_relative_to(base) for base in allowed):
        raise ValueError("output must be a fresh experiment directory")
    output.mkdir(parents=True, exist_ok=False)
    compatibility_path = _compatibility_path(root, compatibility)
    drivers = ("caprls_core/final_af_auxiliary_study.py", "caprls_core/final_af_content_study.py",
               "caprls_core/final_af_e3_study.py", str(compatibility_path.relative_to(root)))
    source_snapshot = _snapshot(root, driver_files=drivers)
    protected = {name: _sha(root / name) for name in PROTECTED if (root / name).is_file()}
    _write(output / "source-snapshot.json", source_snapshot)
    _write(output / "source-inventory.json", _source_inventory(root))
    _freeze_driver_files(root, output, drivers)
    _write(output / "protected-snapshot.json", protected)
    declaration = load_compatibility(root, compatibility_path)
    source = (source or root / FINAL_AF_SOURCE).resolve()
    manifest = (manifest or root / E3_MANIFEST).resolve()
    resolved_wrapper = content_access_root_wrapper(yaml.safe_load(manifest.read_text()), access_root_wrapper)
    from . import final_af_e3_study as driver
    layout_override = (None if access_root_materialized_by_template is None else
                       driver.validate_access_root_materialized_by_template(access_root_materialized_by_template))
    layouts = driver.resolve_access_root_materialized_by_template(source, layout_override)
    base_spec_path = root / declaration["base_spec"]
    spec = content.load_spec(base_spec_path)
    all_cells = [cell for cell in content.ordered_cells(spec) if cell["family"] in declaration["execution_families"]]
    if len(all_cells) != declaration["expected_cells"]:
        raise RuntimeError("declared protected-position cell count differs")
    cells = all_cells
    if only:
        wanted = set(only)
        cells = [cell for cell in all_cells if cell["short_id"] in wanted]
        if {cell["short_id"] for cell in cells} != wanted:
            raise ValueError("--only contains a cell outside the declared protected-position scope")
    # Preserve the base contract, including independently transcribed policy,
    # row columns and refinement. The compatibility declaration is separate.
    spec_path = output / "content-cells.copy.yaml"
    spec_path.write_bytes(base_spec_path.read_bytes())
    (output / "compatibility.copy.yaml").write_bytes(compatibility_path.read_bytes())
    policy = current_validation_policy(cells, declaration)
    _write(output / "current-validation-policy.json", policy)
    started = time.perf_counter()
    _write(output / "protocol.json", {"schema": "caprls-final-af-content-study-v1", "started_at": _utc(),
             "families": declaration["execution_families"], "declared_full_cells": len(all_cells),
             "requested_cells": [cell["short_id"] for cell in cells], "timing": False,
             "selection": "prospective AF selection with no measured outcome feedback",
             "reference": "independent content_reference process; same-snapshot bag comparison",
             "final_af_source": str(source), "e3_manifest": str(manifest), "e3_manifest_sha256": _sha(manifest),
             "access_root_wrapper": resolved_wrapper, "access_root_wrapper_override": access_root_wrapper,
             "access_root_materialized_by_template": layouts,
             "access_root_materialized_by_template_override": layout_override,
             "source_spec_sha256": _sha(base_spec_path), "compatibility": str(compatibility_path),
             "compatibility_sha256": _sha(compatibility_path)})
    receipts, failure, identity = [], None, None
    try:
        compatibility_audit = current_audit(root, spec_path, compatibility=compatibility_path)
        _write(output / "implementation-fidelity-audit.json", compatibility_audit)
        if compatibility_audit["status"] != "pass":
            raise RuntimeError("current content compatibility audit failed")
        from .content_predeclare import write_predeclaration
        predeclared_path = output / "predeclared-expectations.yaml"
        write_predeclaration(root, predeclared_path, spec_path)
        predeclared = yaml.safe_load(predeclared_path.read_text())
        identity = {"source": content.source_identity(root), "harness": content.harness_identity(root),
                    "git": content.git_identity(root), "spec_digest": content._sha256_file(spec_path),
                    "predeclared_digest": content._sha256_file(predeclared_path),
                    "policy_manifest_digest": content._sha256_file(root / "manifests/policies/synthetic_saas_policies.yaml"),
                    "implementation_fidelity_audit": compatibility_audit,
                    "dataset_fingerprint_by_family": {}, "statistics_digest_by_family": {}}
        os.environ.update(CAPRLS_PG_SHARED_BUFFERS="16MB", CAPRLS_PG_INITDB_SHARED_BUFFERS="400kB",
                          CAPRLS_PG_INITDB_MAX_CONNECTIONS="20")
        os.environ.pop("CAPRLS_PG_EXTRA_OPTS", None)
        from .postgres_runner import PostgresEnv, temporary_cluster
        from .content_psql import ContentPostgresEnv
        with temporary_cluster(database="caprls_smoke") as pg:
            families = sorted({cell["family"] for cell in cells})
            environments = {family: ContentPostgresEnv(host=pg.host, port=pg.port, user=pg.user,
                              database="final_af_content_" + family.lower()) for family in families}
            for family, environment in environments.items():
                print(json.dumps({"event": "provision_family", "family": family}), flush=True)
                content.provision_family(root, family, environment,
                     manifest_path=manifest if family == "E3" else None, create_database=True)
            context = content.RunContext(root=root, run_dir=output, spec_path=spec_path,
                    predeclared_path=predeclared_path, spec=spec, predeclared=predeclared,
                    classification=policy, identity=identity, pg_env_by_family=environments,
                    legacy_pg_env_by_family={family: PostgresEnv(host=env.host, port=env.port, user=env.user,
                                                database=env.database) for family, env in environments.items()})
            sessions = {}
            factories = {"E2": content._E2Session, "E10": content._E10Session,
                         "E3": lambda root, pg_env, manifest_path: FinalE3Session(root, pg_env, manifest_path, source, output,
                                      access_root_wrapper=access_root_wrapper,
                                      access_root_materialized_by_template=layout_override)}
            manifests = {"E2": "manifests/experiments/e2_alternative_matrix_reduced.yaml",
                         "E10": "manifests/experiments/e10_case_study.yaml", "E3": str(manifest)}
            for cell in cells:
                family = cell["family"]
                try:
                    if family not in sessions:
                        sessions[family] = factories[family](root, context.legacy_pg_env(family), root / manifests[family])
                        session = sessions[family]
                        identity["dataset_fingerprint_by_family"][family] = content.dataset_fingerprint(root, context.pg_env(family), family,
                              tpch_scale=getattr(session, "tpch_scale", ""), job_scale=getattr(session, "job_scale", ""))
                        identity["statistics_digest_by_family"][family] = content.statistics_digest(context.pg_env(family), family)
                    with final_e3_transaction_adapter(sessions[family]) if family == "E3" else nullcontext():
                        receipt = content.verify_cell(cell, context, sessions[family])
                    if receipt.get("candidate", {}).get("selection_identity") == "differs":
                        receipt["candidate"]["selection_classified_by"] = "declared_current_validation_scope"
                        receipt["candidate"]["selection_difference_cause"] = "not attributed; actual boundary independently revalidated"
                    receipt["current_validation"] = {"historical_template_identity_is_acceptance_condition": False,
                              "actual_selected_boundary_is_compared": True,
                              "e3_actual_contract_checked_inside_comparison_transaction": family == "E3"}
                    if family == "E3":
                        receipt["current_validation"]["artifact_validation"] = sessions[family].artifact_validation_observed
                    content._recheck_fingerprint_after_negative_states(cell, context, sessions[family], root, identity)
                except Exception as exc:
                    receipt = content._receipt_skeleton(cell, context)
                    if getattr(exc, "partial", None):
                        receipt.update(exc.partial)
                    receipt.update(status="refused", failure_reason=str(exc), traceback=traceback.format_exc())
                receipts.append(receipt)
                _write(output / "receipts" / (cell["short_id"] + ".json"), receipt)
                print(json.dumps({"event": "protected_cell", "cell": cell["short_id"], "status": receipt["status"]}), flush=True)
                if receipt["status"] not in {"pass", "pass_after_spec_revision"}:
                    raise RuntimeError(cell["short_id"] + ": " + str(receipt.get("failure_reason")))
    except Exception as exc:
        failure = {"error": str(exc), "traceback": traceback.format_exc()}
    if identity is not None:
        _write(output / "data-identity.json", identity)
    source_drift, protected_drift = _drift(root, source_snapshot), _drift(root, protected)
    summary = {"schema": "caprls-final-af-content-summary-v1", "finished_at": _utc(),
               "status": "pass" if failure is None and not source_drift and not protected_drift and len(receipts) == len(cells) else "fail",
               "declared_full_cells": len(all_cells), "requested_cells": len(cells), "receipts": len(receipts),
               "passed": sum(r["status"] in {"pass", "pass_after_spec_revision"} for r in receipts),
               "full_52_cell_coverage": len(cells) == 52 and len(receipts) == 52 and failure is None
                     and not source_drift and not protected_drift
                     and all(r["status"] in {"pass", "pass_after_spec_revision"} for r in receipts),
               "families_requested": sorted({cell["family"] for cell in cells}),
               "elapsed_seconds": time.perf_counter() - started, "failure": failure,
               "source_drift": source_drift, "protected_drift": protected_drift}
    _write(output / "summary.json", summary)
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--only", action="append")
    parser.add_argument("--source", type=Path, help="same frozen final-AF algorithm source as the timing campaign")
    parser.add_argument("--manifest", type=Path, help="same full SF1/JOB manifest as the E3 timing campaign")
    parser.add_argument("--compatibility", type=Path,
                        help="versioned content compatibility declaration inside the project; default retains the legacy specification")
    parser.add_argument("--access-root-wrapper", choices=("materialized", "not_materialized_single_reference"),
                        help="same explicit AF E3 wrapper override as the timing campaign; default follows its manifest")
    parser.add_argument("--materialize-template", action="append",
                        help="repeat to replace the source-default per-template handoff map with these materialized template IDs")
    parser.add_argument("--offline-check", action="store_true")
    args = parser.parse_args(argv)
    if args.offline_check:
        result = current_audit(args.root, compatibility=args.compatibility)
    else:
        if args.output is None:
            parser.error("--output is required")
        from . import final_af_e3_study as driver
        layout_override = driver.template_materialization_override(args.materialize_template)
        result = run_content_study(args.root, args.output, only=args.only, source=args.source, manifest=args.manifest,
                                   access_root_wrapper=args.access_root_wrapper, compatibility=args.compatibility,
                                   access_root_materialized_by_template=layout_override)
    print(json.dumps(result, indent=2, default=str), flush=True)
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
