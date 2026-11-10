"""Static-verifier coverage witnesses for templates not selected by main runs."""

from __future__ import annotations

from .baselines import (
    POLICY_ENFORCEMENT_ROLE,
)

import hashlib
import json
import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from planner.verifier.static import verify_template_static

from .result_schema import (
    RAW_SCHEMA_VERSION,
    STATIC_VERIFIER_TEMPLATE_WITNESS_MANIFEST_ID,
    STATIC_VERIFIER_TEMPLATE_WITNESS_MODE,
    validate_raw_run_record,
)


PACKAGE_NAME = "STATIC_VERIFIER_TEMPLATE_WITNESS"
MANIFEST_ID = STATIC_VERIFIER_TEMPLATE_WITNESS_MANIFEST_ID
WITNESS_TEMPLATE_IDS = (
    "barrier_filter_inline_v1",
    "auth_index_semijoin_v1",
    "auth_index_keyed_semijoin_v1",
)

AUTH_SCOPE_FILTER = (
    "((artifact_id = 'auth'::text) AND (ctx_hash = 'ctx'::text) "
    "AND (rid_domain_id = 'document.doc_id'::text))"
)
KEYED_SCOPE_FILTER = (
    "((artifact_id = 'auth_keyed'::text) AND (ctx_hash = 'ctx'::text) "
    "AND (rid_domain_id = 'document.doc_id'::text) "
    "AND (key_name = 'tenant_id'::text) AND (key_value = '1'::text))"
)


@dataclass(frozen=True)
class StaticVerifierTemplateWitnessResult:
    output_dir: Path
    raw_result_paths: tuple[Path, ...]
    witness_records: int


def _scan(relation: str, node_type: str = "Seq Scan", **conditions: str) -> dict[str, Any]:
    payload: dict[str, Any] = {"Node Type": node_type, "Relation Name": relation}
    payload.update(conditions)
    return payload


def _join(*plans: dict[str, Any], condition: str = "(d.doc_id = a.rid)") -> dict[str, Any]:
    return {"Node Type": "Hash Join", "Hash Cond": condition, "Plans": list(plans)}


def _explain(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"Plan": plan}]


def _sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_json(payload: Any) -> str:
    rendered = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return _sha256_text(rendered)


def _git_commit(root: Path) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(root),
        text=True,
        capture_output=True,
    )
    return proc.stdout.strip() if proc.returncode == 0 and proc.stdout.strip() else "unknown"


def _witness_cases() -> dict[str, tuple[str, list[dict[str, Any]], str]]:
    return {
        "barrier_filter_inline_v1": (
            """WITH auth AS NOT MATERIALIZED (
  SELECT d.doc_id, d.tenant_id, d.owner_id, d.public, d.doc_id AS __rid
  FROM public.document d
  WHERE d.tenant_id = 1
)
SELECT auth.doc_id FROM auth;""",
            _explain(_scan("document")),
            "InlineBarrierFilter",
        ),
        "auth_index_semijoin_v1": (
            """SELECT *
FROM public.document d
WHERE d.owner_id = 7
  AND EXISTS (
    SELECT 1
    FROM public.auth_idx a
    WHERE a.rid = d.doc_id
      AND a.artifact_id = 'auth'
      AND a.policy_id = 'tenant_group'
      AND a.user_id = 'u1'
      AND a.ctx_hash = 'ctx'
      AND a.rid_domain_id = 'document.doc_id'
      AND a.base_rel_oid = 'public.document'::regclass::oid
  );""",
            _explain(_join(_scan("document"), _scan("auth_idx", Filter=AUTH_SCOPE_FILTER))),
            "AuthorizationIndexSemiJoin",
        ),
        "auth_index_keyed_semijoin_v1": (
            """SELECT *
FROM public.document d
WHERE EXISTS (
  SELECT 1
  FROM public.auth_idx_keyed a
  WHERE a.rid = d.doc_id
    AND a.artifact_id = 'auth_keyed'
    AND a.policy_id = 'tenant_group'
    AND a.user_id = 'u1'
    AND a.ctx_hash = 'ctx'
    AND a.key_name = 'tenant_id'
    AND a.key_value = '1'
    AND a.rid_domain_id = 'document.doc_id'
    AND a.base_rel_oid = 'public.document'::regclass::oid
);""",
            _explain(_join(_scan("document"), _scan("auth_idx_keyed", Filter=KEYED_SCOPE_FILTER))),
            "AuthorizationIndexKeyedSemiJoin",
        ),
    }


def _record(
    *,
    root: Path,
    template_id: str,
    alternative: str,
    sql: str,
    explain_json: list[dict[str, Any]],
    plan_hash: str,
) -> dict[str, Any]:
    sql_hash = _sha256_text(sql)
    explain_ref = f"explain/{template_id}.explain.json"
    manifest_hash = _sha256_json(
        {
            "manifest_id": MANIFEST_ID,
            "templates": WITNESS_TEMPLATE_IDS,
            "purpose": "static_verifier_registered_template_coverage",
        }
    )
    return {
        "schema_version": RAW_SCHEMA_VERSION,
        "run_id": f"STATIC_VERIFIER_{template_id}",
        "manifest_id": MANIFEST_ID,
        "manifest_hash": manifest_hash,
        "experiment": "STATIC_VERIFIER",
        "stage": "template_witness",
        "run_kind": "normal_mode",
        "dataset": {"name": "static_verifier_fixture", "scale": "not_applicable", "seed": 0},
        "query": {
            "query_id": f"static_verifier_{template_id}",
            "path": f"generated:static_verifier_witness/{template_id}.sql",
            "params": {"template_id": template_id},
        },
        "policy": {
            "policy_id": "tenant_group",
            "policy_version": 0,
            "policy_sql_manifest_hash": manifest_hash,
        },
        "context": {"context_id": "ctx_static_verifier", "ctx_hash": "ctx"},
        "mode": STATIC_VERIFIER_TEMPLATE_WITNESS_MODE,
        "template": {"template_id": template_id, "alternative": alternative},
        "template_applicability": {"status": "applicable", "reason": None},
        "template_oracle": {
            "eligible_for_template_oracle": False,
            "template_oracle_exclusion_reason": "static_verifier_witness_not_ranked",
        },
        "evaluation_role": POLICY_ENFORCEMENT_ROLE,
        "pg": {
            "version": "static-verifier-fixture",
            "gucs": {"jit": "off", "max_parallel_workers_per_gather": "0"},
        },
        "versions": {
            "policy": {"tenant_group": 0},
            "membership": {},
            "context": {"ctx_static_verifier": 0},
            "trusted_state": {"static_verifier_fixture": 1},
            "base": {"document": 0},
            "artifacts": {},
        },
        "planner": {
            "level": "A",
            "planning_time_ms": 0.0,
            "generated_templates": 1,
            "rejected_templates": 0,
            "costed_templates": 1,
            "rejection_reasons": {},
            "chosen_estimated_cost": 0.0,
            "chosen_rank_vs_template_oracle": None,
            "local_feature_vector": None,
            "parent_requirement_vector": None,
            "candidates": [],
            "disabled_components": [],
            "delivered_sigma": {},
        },
        "static_verifier": {
            "status": "pass",
            "plan_hash": plan_hash,
            "explain_path": explain_ref,
            "reasons": [],
        },
        "artifact_validation": {
            "status": "not_applicable",
            "action": "execute",
            "expected_action": "execute",
            "failure_sqlstate": None,
            "failure_symbol": None,
            "same_snapshot": False,
            "isolation_level": None,
        },
        "runtime_audit": {
            "status": "pass",
            "audit_path": None,
            "udf_calls": 0,
            "unauthorized_observations": 0,
            "client_errors": 0,
            "client_notices": 0,
        },
        "sql": {
            "emitted_sql_path": f"generated:static_verifier_witness/{template_id}.sql",
            "emitted_sql_hash": sql_hash,
            "normalized_sql_hash": sql_hash,
        },
        "oracle_check": {
            "status": "not_applicable",
            "oracle_kind": "static_verifier_shape_witness",
            "set_diff_left": 0,
            "set_diff_right": 0,
            "known_invalid_accepted": False,
            "known_valid_rejected": False,
        },
        "timing_ms": {"planning": 0.0, "execution": 0.0, "verification": 0.0, "total": 0.0},
        "result": {"row_count": 0, "result_hash": _sha256_json({"template_id": template_id})},
        "pg_metrics": {
            "shared_read_blocks": 0,
            "shared_hit_blocks": 0,
            "temp_read_blocks": 0,
            "temp_written_blocks": 0,
        },
        "counts": {
            "policy_evals": None,
            "residual_checks": None,
            "candidate_rows": None,
            "authorized_rows": None,
            "artifact_lookups": None,
            "base_fetches": None,
        },
        "artifact_cost": {
            "query_only_ms": 0.0,
            "build_ms": 0.0,
            "refresh_ms": 0.0,
            "storage_bytes": 0,
            "indexes_built": [],
            "artifact_key_encoding_version": "artifact_key_encoding_v1",
            "amortization_model": "not_applicable",
        },
        "implementation": {
            "git_commit": _git_commit(root),
            "docker_image_digest": "not_containerized",
            "python_version": platform.python_version(),
            "planner_language": "python",
        },
        "status": "pass",
        "failure": None,
    }


def write_static_verifier_template_witnesses(
    *,
    root: Path,
    output_dir: Path,
) -> StaticVerifierTemplateWitnessResult:
    output_dir.mkdir(parents=True, exist_ok=True)
    explain_dir = output_dir / "explain"
    explain_dir.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    for template_id, (sql, explain_json, alternative) in _witness_cases().items():
        plan_hash = _sha256_json(explain_json)
        verification = verify_template_static(template_id, sql, explain_json, plan_hash)
        if verification.status != "pass":
            rendered = ", ".join(verification.reasons)
            raise ValueError(f"{template_id} static verifier witness failed: {rendered}")
        explain_path = explain_dir / f"{template_id}.explain.json"
        explain_path.write_text(
            json.dumps(explain_json, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        record = _record(
            root=root,
            template_id=template_id,
            alternative=alternative,
            sql=sql,
            explain_json=explain_json,
            plan_hash=plan_hash,
        )
        issues = validate_raw_run_record(record)
        if issues:
            rendered = ", ".join(f"{issue.path}: {issue.message}" for issue in issues)
            raise ValueError(f"{template_id} static verifier witness failed schema validation: {rendered}")
        raw_path = output_dir / f"{template_id}.json"
        raw_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(raw_path)

    return StaticVerifierTemplateWitnessResult(
        output_dir=output_dir,
        raw_result_paths=tuple(written),
        witness_records=len(written),
    )
