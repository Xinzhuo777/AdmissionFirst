"""Audit the promoted E3 RawPG path for zero-calibration discipline."""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
    normalize_mode_id,
)

import inspect
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml

from .e3_main import POLICY_CONFIGS, _e3_planning_problem, _rawpg_dominance_cost_inputs


EXPECTED_RANKER = {"name": "pg-explain-raw"}
EXPECTED_COST_MODEL_VERSION = "pg_explain_raw_v1"
EXPECTED_STAGE = "standard_workloads_sf1_rawpg"
EXPECTED_RAW_SUBDIR = "E3_SF1_RAWPG_V1"
PROMOTED_INJECTION_POLICIES = ("group_acl_expensive", "hybrid_selective_key")
REQUIRED_INJECTION_SAFE_POLICIES = (
    "cheap_tenant_sargable",
    "group_acl_expensive",
    "hybrid_selective_key",
)
REQUIRED_PROMOTED_INJECTION_TEMPLATES = (
    "safe_predicate_injection_v1",
    "ordinary_first_exact_check_v1",
)
FORBIDDEN_INJECTION_GATE_SNIPPETS = (
    'config_id == "cheap_tenant_sargable"',
    "config_id == 'cheap_tenant_sargable'",
    "exact_policy_safe = policy.config_id",
)
ZERO_CALIBRATION_FIELDS = (
    "estimated_rows",
    "query_selectivity",
    "auth_selectivity",
    "policy_eval_cost",
    "residual_eval_cost",
    "scan_cost_per_row",
    "base_fetch_cost",
    "artifact_lookup_cost",
    "guard_selectivity",
    "residual_check_cost",
    "validation_gate_cost",
    "materialize_cost",
    "declared_update_rate_per_hour",
    "declared_ttl_s",
    "declared_contexts",
)


@dataclass(frozen=True)
class E3RawPGAuditIssue:
    path: str
    message: str


@dataclass(frozen=True)
class E3RawPGAuditReport:
    issues: tuple[E3RawPGAuditIssue, ...]
    details: Mapping[str, Any]

    @property
    def ok(self) -> bool:
        return not self.issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "details": dict(self.details),
            "issues": [issue.__dict__ for issue in self.issues],
        }


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _maybe_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def _validate_manifest(path: Path, issues: list[E3RawPGAuditIssue], details: dict[str, Any]) -> None:
    try:
        manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        issues.append(E3RawPGAuditIssue(str(path), f"invalid manifest YAML: {exc}"))
        return
    if not isinstance(manifest, Mapping):
        issues.append(E3RawPGAuditIssue(str(path), "manifest must be a YAML object"))
        return

    ranker = manifest.get("ranker")
    outputs = manifest.get("outputs", {})
    details["manifest"] = {
        "manifest_id": manifest.get("manifest_id"),
        "stage": manifest.get("stage"),
        "ranker": ranker,
        "raw_dir": outputs.get("raw_dir") if isinstance(outputs, Mapping) else None,
        "summary_dir": outputs.get("summary_dir") if isinstance(outputs, Mapping) else None,
    }
    if manifest.get("stage") != EXPECTED_STAGE:
        issues.append(E3RawPGAuditIssue(str(path), f"manifest stage is not {EXPECTED_STAGE}"))
    if ranker != EXPECTED_RANKER:
        issues.append(E3RawPGAuditIssue(str(path), "manifest ranker must be exactly {name: pg-explain-raw}"))
    if isinstance(ranker, Mapping):
        for forbidden in ("calibration_path", "calibration_hash", "calibration"):
            if forbidden in ranker:
                issues.append(E3RawPGAuditIssue(str(path), f"manifest ranker carries forbidden {forbidden}"))
    if isinstance(outputs, Mapping):
        raw_dir = str(outputs.get("raw_dir", ""))
        if EXPECTED_RAW_SUBDIR not in raw_dir:
            issues.append(E3RawPGAuditIssue(str(path), f"manifest raw_dir does not point at {EXPECTED_RAW_SUBDIR}"))


def _validate_rawpg_cost_inputs(issues: list[E3RawPGAuditIssue], details: dict[str, Any]) -> None:
    inputs = _rawpg_dominance_cost_inputs(sort_enforcer_cost=7.5)
    payload = inputs.__dict__
    details["rawpg_dominance_cost_inputs_probe"] = dict(payload)
    for field in ZERO_CALIBRATION_FIELDS:
        value = payload.get(field)
        if value != 0 and value != 0.0:
            issues.append(E3RawPGAuditIssue("caprls_core/e3_main.py", f"RawPG CostInputs field {field} is not zero"))
    if payload.get("sort_cost") != 7.5:
        issues.append(E3RawPGAuditIssue("caprls_core/e3_main.py", "RawPG CostInputs did not preserve sort enforcer cost"))
    if payload.get("declared_reuse") is not None:
        issues.append(E3RawPGAuditIssue("caprls_core/e3_main.py", "RawPG CostInputs must keep declared_reuse unset"))


def _validate_injection_safety_source(issues: list[E3RawPGAuditIssue], details: dict[str, Any]) -> None:
    by_policy = {policy.config_id: policy for policy in POLICY_CONFIGS}
    policy_details: dict[str, bool | None] = {}
    for policy_id in REQUIRED_INJECTION_SAFE_POLICIES:
        policy = by_policy.get(policy_id)
        policy_details[policy_id] = None if policy is None else bool(policy.injection_safe)
        if policy is None:
            issues.append(E3RawPGAuditIssue("caprls_core/e3_main.py", f"E3 policy config missing: {policy_id}"))
            continue
        if policy.injection_safe is not True:
            issues.append(
                E3RawPGAuditIssue(
                    "caprls_core/e3_main.py",
                    f"E3 policy {policy_id} must declare injection_safe=True",
                )
            )
    try:
        source = inspect.getsource(_e3_planning_problem)
    except OSError as exc:
        issues.append(E3RawPGAuditIssue("caprls_core/e3_main.py", f"cannot inspect _e3_planning_problem: {exc}"))
        source = ""
    details["injection_safety_source"] = {
        "policy_injection_safe": policy_details,
        "uses_injection_safe_field": "exact_policy_safe = policy.injection_safe" in source,
        "forbidden_snippets_present": [
            snippet for snippet in FORBIDDEN_INJECTION_GATE_SNIPPETS if snippet in source
        ],
    }
    if "exact_policy_safe = policy.injection_safe" not in source:
        issues.append(
            E3RawPGAuditIssue(
                "caprls_core/e3_main.py",
                "_e3_planning_problem must drive exact_policy_safe from policy.injection_safe",
            )
        )
    for snippet in FORBIDDEN_INJECTION_GATE_SNIPPETS:
        if snippet in source:
            issues.append(
                E3RawPGAuditIssue(
                    "caprls_core/e3_main.py",
                    f"_e3_planning_problem contains forbidden injection gate snippet: {snippet}",
                )
            )


def _iter_raw_records(raw_dir: Path) -> list[Path]:
    return [
        path
        for path in sorted(raw_dir.glob("*.json"))
        if path.is_file() and not path.name.startswith(".")
    ]


def _validate_contract_query_plan(
    path: Path,
    query_plan: Any,
    issues: list[E3RawPGAuditIssue],
) -> bool:
    if not isinstance(query_plan, Mapping):
        issues.append(
            E3RawPGAuditIssue(
                str(path),
                "AdmissionFirst record is missing planner.query_plan from the IR/root-closure writer",
            )
        )
        return False

    ok = True
    if query_plan.get("ok") is not True:
        issues.append(E3RawPGAuditIssue(str(path), "AdmissionFirst planner.query_plan.ok is not true"))
        ok = False

    root_closure = query_plan.get("root_closure")
    if not isinstance(root_closure, Mapping) or root_closure.get("ok") is not True:
        issues.append(E3RawPGAuditIssue(str(path), "AdmissionFirst planner.query_plan.root_closure is not ok"))
        ok = False

    certificate = query_plan.get("certificate")
    if not isinstance(certificate, list) or not certificate:
        issues.append(E3RawPGAuditIssue(str(path), "AdmissionFirst planner.query_plan lacks certificate steps"))
        ok = False

    certificate_check = query_plan.get("certificate_check")
    if not isinstance(certificate_check, Mapping) or certificate_check.get("status") != "pass":
        issues.append(E3RawPGAuditIssue(str(path), "AdmissionFirst planner.query_plan.certificate_check is not pass"))
        ok = False

    return ok


def _record_policy_id(record: Mapping[str, Any]) -> str:
    policy = record.get("policy")
    if isinstance(policy, Mapping):
        policy_id = policy.get("policy_id")
        if isinstance(policy_id, str) and policy_id:
            return policy_id
    query = record.get("query")
    if isinstance(query, Mapping):
        params = query.get("params")
        if isinstance(params, Mapping):
            policy_config_id = params.get("policy_config_id")
            if isinstance(policy_config_id, str) and policy_config_id:
                return policy_config_id
    return ""


def _accepted_candidate_templates(planner: Mapping[str, Any]) -> set[str]:
    candidates = planner.get("candidates")
    if not isinstance(candidates, list):
        return set()
    return {
        str(candidate.get("template_id"))
        for candidate in candidates
        if isinstance(candidate, Mapping) and candidate.get("accepted") is True
    }


def _chosen_template_id(record: Mapping[str, Any], planner: Mapping[str, Any]) -> str:
    for dotted in ("template.template_id", "planner.chosen_template.template_id"):
        value = _get(record, dotted) if dotted.startswith("template") else _get({"planner": planner}, dotted)
        if isinstance(value, str) and value:
            return value
    value = planner.get("chosen_template")
    if isinstance(value, str) and value:
        return value
    return ""


def _get(mapping: Mapping[str, Any], dotted: str) -> Any:
    current: Any = mapping
    for part in dotted.split("."):
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current


def _validate_dominance_invariants(
    path: Path,
    record: Mapping[str, Any],
    planner: Mapping[str, Any],
    issues: list[E3RawPGAuditIssue],
) -> tuple[int, int, int]:
    candidates = planner.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return 0, 0, 0
    by_template = {
        str(candidate.get("template_id")): candidate
        for candidate in candidates
        if isinstance(candidate, Mapping) and candidate.get("template_id") not in (None, "")
    }
    checked = 1
    pruned_count = 0
    violation_count = 0
    if normalize_mode_id(str(record.get("mode", ""))) == ADMISSION_FIRST_MODE:
        chosen_id = _chosen_template_id(record, planner)
        chosen = by_template.get(chosen_id)
        if chosen is not None and chosen.get("pruned_by_dominance"):
            violation_count += 1
            issues.append(
                E3RawPGAuditIssue(
                    str(path),
                    "chosen template is marked pruned_by_dominance: "
                    f"chosen={chosen_id}, dominator={chosen.get('pruned_by_dominance')}",
                )
            )
    for candidate in by_template.values():
        dominator_id = candidate.get("pruned_by_dominance")
        if not candidate.get("accepted") or not dominator_id:
            continue
        pruned_count += 1
        dominator = by_template.get(str(dominator_id))
        if dominator is None:
            violation_count += 1
            issues.append(
                E3RawPGAuditIssue(
                    str(path),
                    "dominance-pruned candidate references missing dominator: "
                    f"candidate={candidate.get('template_id')}, dominator={dominator_id}",
                )
            )
            continue
        if dominator.get("pruned_by_dominance"):
            violation_count += 1
            issues.append(
                E3RawPGAuditIssue(
                    str(path),
                    "dominance dominator is itself pruned: "
                    f"candidate={candidate.get('template_id')}, dominator={dominator_id}",
                )
            )
        if dominator.get("accepted") is not True:
            violation_count += 1
            issues.append(
                E3RawPGAuditIssue(
                    str(path),
                    "dominance dominator is not an accepted candidate: "
                    f"candidate={candidate.get('template_id')}, dominator={dominator_id}",
                )
            )
        candidate_cost = _maybe_float(candidate.get("estimated_cost"))
        dominator_cost = _maybe_float(dominator.get("estimated_cost"))
        if candidate_cost is None or dominator_cost is None:
            violation_count += 1
            issues.append(
                E3RawPGAuditIssue(
                    str(path),
                    "dominance-pruned candidate or dominator lacks numeric estimated_cost: "
                    f"candidate={candidate.get('template_id')}, dominator={dominator_id}",
                )
            )
        elif dominator_cost > candidate_cost + 1e-12:
            violation_count += 1
            issues.append(
                E3RawPGAuditIssue(
                    str(path),
                    "dominance dominator cost exceeds pruned candidate cost: "
                    f"candidate={candidate.get('template_id')} cost={candidate_cost}, "
                    f"dominator={dominator_id} cost={dominator_cost}",
                )
            )
    return checked, pruned_count, violation_count


def _validate_raw_records(
    raw_dir: Path,
    issues: list[E3RawPGAuditIssue],
    details: dict[str, Any],
    *,
    require_promoted_injection_candidates: bool = False,
) -> None:
    if not raw_dir.exists():
        issues.append(E3RawPGAuditIssue(str(raw_dir), "promoted E3 RawPG raw directory is missing"))
        return
    record_paths = _iter_raw_records(raw_dir)
    diagnostic_count = 0
    record_count = 0
    checked_record_count = 0
    contract_query_plan_count = 0
    stage_counts: dict[str, int] = {}
    mode_counts: dict[str, int] = {}
    dominance_checked_record_count = 0
    dominance_pruned_candidate_count = 0
    dominance_violation_count = 0
    promoted_policy_rows: dict[str, int] = {policy: 0 for policy in PROMOTED_INJECTION_POLICIES}
    promoted_policy_accepted_template_counts: dict[str, dict[str, int]] = {
        policy: {template_id: 0 for template_id in REQUIRED_PROMOTED_INJECTION_TEMPLATES}
        for policy in PROMOTED_INJECTION_POLICIES
    }
    for path in record_paths:
        record_count += 1
        try:
            record = _read_json(path)
        except json.JSONDecodeError as exc:
            issues.append(E3RawPGAuditIssue(str(path), f"invalid raw JSON: {exc}"))
            continue
        stage = str(record.get("stage", ""))
        mode = normalize_mode_id(str(record.get("mode", "")))
        stage_counts[stage] = stage_counts.get(stage, 0) + 1
        mode_counts[mode] = mode_counts.get(mode, 0) + 1
        if record.get("experiment") != "E3":
            issues.append(E3RawPGAuditIssue(str(path), "record is not an E3 raw record"))
        if stage != EXPECTED_STAGE:
            issues.append(E3RawPGAuditIssue(str(path), f"record stage is not {EXPECTED_STAGE}"))
        planner = record.get("planner", {})
        if not isinstance(planner, Mapping):
            issues.append(E3RawPGAuditIssue(str(path), "planner payload must be an object"))
            continue
        if planner.get("calibration_path") is not None:
            issues.append(E3RawPGAuditIssue(str(path), "planner.calibration_path is not null"))
        if planner.get("calibration_hash") is not None:
            issues.append(E3RawPGAuditIssue(str(path), "planner.calibration_hash is not null"))
        dominance_checked, dominance_pruned, dominance_violations = _validate_dominance_invariants(
            path,
            record,
            planner,
            issues,
        )
        dominance_checked_record_count += dominance_checked
        dominance_pruned_candidate_count += dominance_pruned
        dominance_violation_count += dominance_violations
        if mode == ADMISSION_FIRST_MODE and _validate_contract_query_plan(path, planner.get("query_plan"), issues):
            contract_query_plan_count += 1
        policy_id = _record_policy_id(record)
        if mode == ADMISSION_FIRST_MODE and policy_id in PROMOTED_INJECTION_POLICIES:
            promoted_policy_rows[policy_id] += 1
            accepted_templates = _accepted_candidate_templates(planner)
            missing_templates = [
                template_id
                for template_id in REQUIRED_PROMOTED_INJECTION_TEMPLATES
                if template_id not in accepted_templates
            ]
            for template_id in REQUIRED_PROMOTED_INJECTION_TEMPLATES:
                if template_id in accepted_templates:
                    promoted_policy_accepted_template_counts[policy_id][template_id] += 1
            if require_promoted_injection_candidates and missing_templates:
                issues.append(
                    E3RawPGAuditIssue(
                        str(path),
                        "promoted E3 policy lacks accepted injection candidates: "
                        f"policy_id={policy_id}, missing={','.join(missing_templates)}",
                    )
                )
        diagnostics = planner.get("candidate_diagnostics") or ()
        if diagnostics:
            checked_record_count += 1
        for diagnostic in diagnostics:
            if not isinstance(diagnostic, Mapping):
                issues.append(E3RawPGAuditIssue(str(path), "candidate diagnostic must be an object"))
                continue
            if diagnostic.get("diagnostic_kind") != "e3_candidate_cost":
                continue
            diagnostic_count += 1
            template_id = diagnostic.get("template_id", "<unknown>")
            if diagnostic.get("ranker") != EXPECTED_RANKER["name"]:
                issues.append(E3RawPGAuditIssue(str(path), f"{template_id}: diagnostic ranker is not pg-explain-raw"))
            if diagnostic.get("cost_model_version") != EXPECTED_COST_MODEL_VERSION:
                issues.append(E3RawPGAuditIssue(str(path), f"{template_id}: diagnostic cost_model_version is not RawPG"))
            if diagnostic.get("calibration_path") is not None:
                issues.append(E3RawPGAuditIssue(str(path), f"{template_id}: diagnostic calibration_path is not null"))
            if diagnostic.get("calibration_hash") is not None:
                issues.append(E3RawPGAuditIssue(str(path), f"{template_id}: diagnostic calibration_hash is not null"))
            adjusted = _maybe_float(diagnostic.get("adjusted_cost"))
            pg_total = _maybe_float(diagnostic.get("pg_total_cost"))
            if adjusted is None or pg_total is None:
                issues.append(E3RawPGAuditIssue(str(path), f"{template_id}: diagnostic lacks numeric RawPG cost"))
            elif not math.isclose(adjusted, pg_total, rel_tol=0.0, abs_tol=1e-9):
                issues.append(E3RawPGAuditIssue(str(path), f"{template_id}: adjusted_cost differs from pg_total_cost"))
        chosen = _maybe_float(planner.get("chosen_estimated_cost"))
        chosen_pg = _maybe_float(planner.get("chosen_pg_total_cost"))
        if chosen is not None and chosen_pg is not None and not math.isclose(chosen, chosen_pg, rel_tol=0.0, abs_tol=1e-9):
            issues.append(E3RawPGAuditIssue(str(path), "chosen_estimated_cost differs from chosen_pg_total_cost"))
    if not record_paths:
        issues.append(E3RawPGAuditIssue(str(raw_dir), "promoted E3 RawPG raw directory is empty"))
    if diagnostic_count == 0:
        issues.append(E3RawPGAuditIssue(str(raw_dir), "no E3 RawPG candidate diagnostics were found"))
    if require_promoted_injection_candidates:
        for policy_id, count in promoted_policy_rows.items():
            if count == 0:
                issues.append(
                    E3RawPGAuditIssue(
                        str(raw_dir),
                        f"promoted E3 policy has no AdmissionFirst rows: policy_id={policy_id}",
                    )
                )
    details["raw_records"] = {
        "record_count": record_count,
        "records_with_candidate_diagnostics": checked_record_count,
        "candidate_diagnostic_count": diagnostic_count,
        "contract_query_plan_count": contract_query_plan_count,
        "dominance_checked_record_count": dominance_checked_record_count,
        "dominance_pruned_candidate_count": dominance_pruned_candidate_count,
        "dominance_violation_count": dominance_violation_count,
        "promoted_injection_candidate_requirement": require_promoted_injection_candidates,
        "promoted_policy_rows": dict(sorted(promoted_policy_rows.items())),
        "promoted_policy_accepted_template_counts": {
            policy: dict(sorted(counts.items()))
            for policy, counts in sorted(promoted_policy_accepted_template_counts.items())
        },
        "stage_counts": dict(sorted(stage_counts.items())),
        "mode_counts": dict(sorted(mode_counts.items())),
    }


def validate_e3_rawpg_zero_calibration(
    *,
    manifest_path: Path,
    raw_dir: Path | None = None,
    require_promoted_injection_candidates: bool = False,
) -> E3RawPGAuditReport:
    issues: list[E3RawPGAuditIssue] = []
    details: dict[str, Any] = {}
    _validate_manifest(manifest_path, issues, details)
    _validate_rawpg_cost_inputs(issues, details)
    _validate_injection_safety_source(issues, details)
    if raw_dir is not None:
        _validate_raw_records(
            raw_dir,
            issues,
            details,
            require_promoted_injection_candidates=require_promoted_injection_candidates,
        )
    return E3RawPGAuditReport(tuple(issues), details)
