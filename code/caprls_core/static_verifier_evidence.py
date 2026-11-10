"""Audit static verifier evidence attached to raw run records."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from planner.verifier.static import TEMPLATE_STATIC_VERIFIERS


PLAN_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
EXPLAIN_OPTIONAL_MANIFESTS = frozenset(
    {
        "e3_smoke_v1",
        "e3_smoke_v1_taxonomy_v3",
        "e8a_artifact_validity_gate_v1",
        "e8a_artifact_validity_gate_v1_taxonomy_v3",
    }
)
PLAN_CONDITION_FIELDS = (
    "Filter",
    "Index Cond",
    "Recheck Cond",
    "Hash Cond",
    "Merge Cond",
    "Join Filter",
)
GUARD_TEMPLATE_ID = "guard_candidate_plus_residual_v1"


@dataclass(frozen=True)
class StaticVerifierEvidenceIssue:
    path: str
    message: str


@dataclass(frozen=True)
class StaticVerifierEvidenceReport:
    issues: tuple[StaticVerifierEvidenceIssue, ...]
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


def _is_raw_record_path(path: Path) -> bool:
    return (
        path.suffix == ".json"
        and not path.name.startswith(".")
        and "explain" not in path.parts
    )


def _raw_record_paths(path: Path) -> tuple[Path, ...]:
    if path.is_file():
        return (path,)
    if not path.exists():
        return ()
    return tuple(sorted(item for item in path.rglob("*.json") if _is_raw_record_path(item)))


def _read_json(path: Path) -> Mapping[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, Mapping) else None


def _resolve_explain_path(raw_record_path: Path, explain_path: str) -> Path:
    path = Path(explain_path)
    if path.is_absolute():
        return path
    return raw_record_path.parent / path


def _load_explain_json(path: Path) -> Sequence[Mapping[str, Any]] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, list):
        return None
    rendered = tuple(item for item in payload if isinstance(item, Mapping))
    return rendered or None


def _walk_explain_nodes(node: Any) -> Sequence[Mapping[str, Any]]:
    nodes: list[Mapping[str, Any]] = []
    if isinstance(node, Mapping):
        if "Node Type" in node:
            nodes.append(node)
        for value in node.values():
            nodes.extend(_walk_explain_nodes(value))
    elif isinstance(node, list):
        for item in node:
            nodes.extend(_walk_explain_nodes(item))
    return tuple(nodes)


def _explain_conditions(explain_json: Sequence[Mapping[str, Any]]) -> str:
    fragments: list[str] = []
    for item in explain_json:
        for node in _walk_explain_nodes(item):
            for field in PLAN_CONDITION_FIELDS:
                value = node.get(field)
                if value:
                    fragments.append(str(value).lower())
    return " ".join(fragments)


def _is_summary_record(record: Mapping[str, Any]) -> bool:
    run_kind = str(record.get("run_kind", ""))
    return run_kind.endswith("_summary") or isinstance(
        record.get("template_oracle_summary"),
        Mapping,
    )


def _is_explain_optional_record(record: Mapping[str, Any]) -> bool:
    return str(record.get("manifest_id", "")) in EXPLAIN_OPTIONAL_MANIFESTS


def _template_id(record: Mapping[str, Any]) -> str:
    template = record.get("template")
    if isinstance(template, Mapping):
        return str(template.get("template_id", ""))
    return str(record.get("template_id", ""))


def validate_static_verifier_evidence(
    paths: Sequence[Path],
    *,
    require_explain_path: bool = True,
    require_guard_unsafe_witness: bool = False,
    required_template_ids: Sequence[str] = (),
) -> StaticVerifierEvidenceReport:
    issues: list[StaticVerifierEvidenceIssue] = []
    required_templates = tuple(dict.fromkeys(str(item) for item in required_template_ids if str(item)))
    unknown_required_templates = tuple(
        template_id for template_id in required_templates if template_id not in TEMPLATE_STATIC_VERIFIERS
    )
    template_evidence_counts: dict[str, int] = {}
    details: dict[str, Any] = {
        "input_count": len(paths),
        "record_count": 0,
        "pass_record_count": 0,
        "checked_static_verifier_count": 0,
        "checked_explain_artifact_count": 0,
        "guard_template_pass_record_count": 0,
        "guard_unsafe_witness_count": 0,
        "skipped_non_pass_record_count": 0,
        "skipped_summary_record_count": 0,
        "skipped_explain_optional_record_count": 0,
        "required_template_ids": list(required_templates),
        "unknown_required_template_ids": list(unknown_required_templates),
        "missing_required_template_ids": [],
        "template_evidence_counts": {},
    }
    for template_id in unknown_required_templates:
        issues.append(
            StaticVerifierEvidenceIssue(
                ",".join(str(path) for path in paths),
                f"required template has no registered static verifier: {template_id}",
            )
        )

    for root in paths:
        record_paths = _raw_record_paths(root)
        if not record_paths:
            issues.append(
                StaticVerifierEvidenceIssue(
                    str(root),
                    "no raw JSON records found",
                )
            )
            continue
        for path in record_paths:
            details["record_count"] += 1
            record = _read_json(path)
            if record is None:
                issues.append(
                    StaticVerifierEvidenceIssue(
                        str(path),
                        "raw record must be a JSON object",
                    )
                )
                continue
            if record.get("status") != "pass":
                details["skipped_non_pass_record_count"] += 1
                continue
            if _is_summary_record(record):
                details["skipped_summary_record_count"] += 1
                continue
            if require_explain_path and _is_explain_optional_record(record):
                details["skipped_explain_optional_record_count"] += 1
                continue
            details["pass_record_count"] += 1
            static_verifier = record.get("static_verifier")
            if not isinstance(static_verifier, Mapping):
                issues.append(
                    StaticVerifierEvidenceIssue(
                        str(path),
                        "pass record lacks static_verifier object",
                    )
                )
                continue
            details["checked_static_verifier_count"] += 1
            is_guard_template = _template_id(record) == GUARD_TEMPLATE_ID
            if is_guard_template:
                details["guard_template_pass_record_count"] += 1
            if static_verifier.get("status") != "pass":
                issues.append(
                    StaticVerifierEvidenceIssue(
                        str(path),
                        "pass record static_verifier.status is not pass",
                    )
                )
            plan_hash = static_verifier.get("plan_hash")
            if not isinstance(plan_hash, str) or not PLAN_HASH_RE.fullmatch(plan_hash):
                issues.append(
                    StaticVerifierEvidenceIssue(
                        str(path),
                        "pass record lacks valid static_verifier.plan_hash",
                    )
                )
            reasons = static_verifier.get("reasons")
            if isinstance(reasons, Sequence) and not isinstance(reasons, (str, bytes)):
                if reasons:
                    issues.append(
                        StaticVerifierEvidenceIssue(
                            str(path),
                            "pass record static_verifier.reasons is nonempty",
                        )
                    )
            elif reasons is not None:
                issues.append(
                    StaticVerifierEvidenceIssue(
                        str(path),
                        "pass record static_verifier.reasons must be a list",
                    )
                )

            explain_path = static_verifier.get("explain_path")
            if explain_path in (None, ""):
                if require_explain_path:
                    issues.append(
                        StaticVerifierEvidenceIssue(
                            str(path),
                            "pass record lacks static_verifier.explain_path",
                        )
                    )
                continue
            if not isinstance(explain_path, str):
                issues.append(
                    StaticVerifierEvidenceIssue(
                        str(path),
                        "static_verifier.explain_path must be a string",
                    )
                )
                continue
            resolved = _resolve_explain_path(path, explain_path)
            explain_json = _load_explain_json(resolved)
            if explain_json is None:
                issues.append(
                    StaticVerifierEvidenceIssue(
                        str(path),
                        f"cannot read EXPLAIN artifact: {explain_path}",
                    )
                )
                continue
            details["checked_explain_artifact_count"] += 1
            template_id = _template_id(record)
            if template_id:
                template_evidence_counts[template_id] = template_evidence_counts.get(template_id, 0) + 1
            if is_guard_template and "unsafe_log" in _explain_conditions(explain_json):
                details["guard_unsafe_witness_count"] += 1

    details["template_evidence_counts"] = dict(sorted(template_evidence_counts.items()))
    missing_required_templates = tuple(
        template_id for template_id in required_templates if template_evidence_counts.get(template_id, 0) == 0
    )
    details["missing_required_template_ids"] = list(missing_required_templates)
    for template_id in missing_required_templates:
        issues.append(
            StaticVerifierEvidenceIssue(
                ",".join(str(path) for path in paths),
                f"no pass static-verifier EXPLAIN evidence found for required template: {template_id}",
            )
        )
    if details["record_count"] == 0:
        issues.append(
            StaticVerifierEvidenceIssue(
                ",".join(str(path) for path in paths),
                "no raw JSON records found",
            )
        )
    if details["pass_record_count"] == 0:
        issues.append(
            StaticVerifierEvidenceIssue(
                ",".join(str(path) for path in paths),
                "no pass raw records checked",
            )
        )
    if require_guard_unsafe_witness and details["guard_unsafe_witness_count"] == 0:
        issues.append(
            StaticVerifierEvidenceIssue(
                ",".join(str(path) for path in paths),
                "no pass guard+unsafe static-verifier witness found",
            )
        )
    return StaticVerifierEvidenceReport(issues=tuple(issues), details=details)
