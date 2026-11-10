"""Replay planner certificate checks from raw run records."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from planner.verifier.cert_checker import check_certificate


@dataclass(frozen=True)
class CertificateReplayIssue:
    path: str
    message: str


@dataclass(frozen=True)
class CertificateReplayReport:
    issues: tuple[CertificateReplayIssue, ...]
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


def _read_json(path: Path) -> Mapping[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        parsed = json.load(fh)
    return parsed if isinstance(parsed, Mapping) else {}


def is_diagnostic_certificate_suppressed(candidate: Mapping[str, Any]) -> bool:
    diagnostics = candidate.get("diagnostics")
    if not isinstance(diagnostics, Mapping):
        return False
    disabled_components = diagnostics.get("disabled_components")
    return (
        diagnostics.get("diagnostic_ablation") is True
        and diagnostics.get("certificate_suppressed") is True
        and isinstance(disabled_components, list)
        and bool(disabled_components)
    )


def _stored_check_matches(
    *,
    prefix: str,
    stored: Any,
    checked: Any,
) -> list[CertificateReplayIssue]:
    issues: list[CertificateReplayIssue] = []
    if not isinstance(stored, Mapping):
        issues.append(CertificateReplayIssue(f"{prefix}.certificate_check", "missing certificate_check"))
        return issues
    if stored.get("status") != checked.status:
        issues.append(CertificateReplayIssue(f"{prefix}.certificate_check.status", "stored status disagrees with replay"))
    if dict(stored.get("delivered_sigma", {})) != dict(checked.delivered_sigma):
        issues.append(CertificateReplayIssue(f"{prefix}.certificate_check.delivered_sigma", "stored delivered_sigma disagrees with replay"))
    if list(stored.get("h_obligations", [])) != list(checked.h_obligations):
        issues.append(CertificateReplayIssue(f"{prefix}.certificate_check.h_obligations", "stored h_obligations disagree with replay"))
    return issues


def _recorded_sigma_matches_replay(
    *,
    prefix: str,
    field_name: str,
    recorded_sigma: Mapping[str, Any],
    checked: Any,
) -> list[CertificateReplayIssue]:
    if dict(recorded_sigma) == dict(checked.delivered_sigma):
        return []
    return [
        CertificateReplayIssue(
            f"{prefix}.{field_name}",
            f"recorded {field_name} disagrees with replayed certificate Sigma",
        )
    ]


def _with_legacy_ir_transfer_operators(
    certificate: list[Any],
) -> tuple[list[Any], int]:
    normalized: list[Any] = []
    inferred = 0
    for step in certificate:
        if not isinstance(step, Mapping):
            normalized.append(step)
            continue
        rendered = dict(step)
        rule = rendered.get("rule")
        if (
            rendered.get("constructor") == "Transfer"
            and isinstance(rule, str)
            and rule.startswith("ir:")
            and not rendered.get("operator")
        ):
            rendered["operator"] = rule[3:].split(":", 1)[0]
            inferred += 1
        normalized.append(rendered)
    return normalized, inferred


def _replay_query_certificate(
    *,
    container: Mapping[str, Any],
    prefix: str,
    expected_sigma_field: str,
    suppressible: bool,
    details: dict[str, Any],
) -> list[CertificateReplayIssue]:
    issues: list[CertificateReplayIssue] = []
    certificate = container.get("certificate")
    certificate_check = container.get("certificate_check")
    if suppressible and container.get("certificate_suppressed") is True:
        if certificate is not None:
            issues.append(
                CertificateReplayIssue(
                    f"{prefix}.certificate",
                    "certificate-suppressed query plan must not carry a certificate",
                )
            )
        if certificate_check is not None:
            issues.append(
                CertificateReplayIssue(
                    f"{prefix}.certificate_check",
                    "certificate-suppressed query plan must not carry certificate_check",
                )
            )
        details["suppressed_certificate_count"] += 1
        details["suppressed_query_certificate_count"] += 1
        return issues

    if certificate is None and certificate_check is None:
        return issues
    if not isinstance(certificate, list) or not certificate:
        issues.append(CertificateReplayIssue(f"{prefix}.certificate", "query plan missing certificate"))
        return issues
    expected_sigma = container.get(expected_sigma_field)
    if not isinstance(expected_sigma, Mapping):
        issues.append(
            CertificateReplayIssue(
                f"{prefix}.{expected_sigma_field}",
                f"missing {expected_sigma_field} mapping",
            )
        )
        return issues
    replay_certificate, inferred_legacy = _with_legacy_ir_transfer_operators(certificate)
    details["legacy_inferred_ir_transfer_operator_count"] += inferred_legacy
    checked = check_certificate(
        replay_certificate,
        expected_sigma=expected_sigma,
        template_id="query_plan",
    )
    details["checked_certificate_count"] += 1
    details["checked_query_certificate_count"] += 1
    sigma_mismatch_issues = _recorded_sigma_matches_replay(
        prefix=prefix,
        field_name=expected_sigma_field,
        recorded_sigma=expected_sigma,
        checked=checked,
    )
    details["recorded_sigma_mismatch_count"] += len(sigma_mismatch_issues)
    issues.extend(sigma_mismatch_issues)
    if not checked.ok:
        reasons = ", ".join(reject.reason for reject in checked.rejects)
        issues.append(CertificateReplayIssue(f"{prefix}.certificate", reasons))
    issues.extend(
        _stored_check_matches(
            prefix=prefix,
            stored=certificate_check,
            checked=checked,
        )
    )
    return issues


def _has_query_certificate_evidence(planner: Any) -> bool:
    if not isinstance(planner, Mapping):
        return False
    if planner.get("certificate") is not None or planner.get("certificate_check") is not None:
        return True
    return isinstance(planner.get("query_plan"), Mapping)


def check_run_record_certificates(record: Mapping[str, Any]) -> CertificateReplayReport:
    issues: list[CertificateReplayIssue] = []
    planner = record.get("planner")
    candidates = planner.get("candidates") if isinstance(planner, Mapping) else None
    details = {
        "run_id": str(record.get("run_id", "")),
        "candidate_count": 0,
        "accepted_candidate_count": 0,
        "rejected_candidate_count": 0,
        "checked_certificate_count": 0,
        "checked_query_certificate_count": 0,
        "suppressed_certificate_count": 0,
        "suppressed_query_certificate_count": 0,
        "legacy_inferred_ir_transfer_operator_count": 0,
        "recorded_sigma_mismatch_count": 0,
    }
    if not isinstance(candidates, list):
        if not _has_query_certificate_evidence(planner):
            return CertificateReplayReport(
                issues=(CertificateReplayIssue("planner.candidates", "missing candidate list"),),
                details=details,
            )
        candidates = []

    details["candidate_count"] = len(candidates)
    for index, candidate in enumerate(candidates):
        prefix = f"planner.candidates[{index}]"
        if not isinstance(candidate, Mapping):
            issues.append(CertificateReplayIssue(prefix, "candidate must be an object"))
            continue
        accepted = bool(candidate.get("accepted"))
        if accepted:
            details["accepted_candidate_count"] += 1
            if is_diagnostic_certificate_suppressed(candidate):
                if candidate.get("certificate") is not None:
                    issues.append(
                        CertificateReplayIssue(
                            f"{prefix}.certificate",
                            "certificate-suppressed diagnostic candidate must not carry a certificate",
                        )
                    )
                if candidate.get("certificate_check") is not None:
                    issues.append(
                        CertificateReplayIssue(
                            f"{prefix}.certificate_check",
                            "certificate-suppressed diagnostic candidate must not carry certificate_check",
                        )
                    )
                details["suppressed_certificate_count"] += 1
                continue
            certificate = candidate.get("certificate")
            if not isinstance(certificate, list) or not certificate:
                issues.append(CertificateReplayIssue(f"{prefix}.certificate", "accepted candidate missing certificate"))
                continue
            delivered_sigma = candidate.get("delivered_sigma")
            if not isinstance(delivered_sigma, Mapping):
                issues.append(CertificateReplayIssue(f"{prefix}.delivered_sigma", "missing delivered_sigma mapping"))
                continue
            checked = check_certificate(
                certificate,
                expected_sigma=delivered_sigma,
                template_id=str(candidate.get("template_id", "")),
            )
            details["checked_certificate_count"] += 1
            sigma_mismatch_issues = _recorded_sigma_matches_replay(
                prefix=prefix,
                field_name="delivered_sigma",
                recorded_sigma=delivered_sigma,
                checked=checked,
            )
            details["recorded_sigma_mismatch_count"] += len(sigma_mismatch_issues)
            issues.extend(sigma_mismatch_issues)
            if not checked.ok:
                reasons = ", ".join(reject.reason for reject in checked.rejects)
                issues.append(CertificateReplayIssue(f"{prefix}.certificate", reasons))
            stored = candidate.get("certificate_check")
            issues.extend(
                _stored_check_matches(
                    prefix=prefix,
                    stored=stored,
                    checked=checked,
                )
            )
        else:
            details["rejected_candidate_count"] += 1
            if candidate.get("certificate") is not None:
                issues.append(CertificateReplayIssue(f"{prefix}.certificate", "rejected candidate must not carry a certificate"))
            if candidate.get("certificate_check") is not None:
                issues.append(CertificateReplayIssue(f"{prefix}.certificate_check", "rejected candidate must not carry certificate_check"))

    if isinstance(planner, Mapping):
        issues.extend(
            _replay_query_certificate(
                container=planner,
                prefix="planner",
                expected_sigma_field="delivered_sigma",
                suppressible=False,
                details=details,
            )
        )
        query_plan = planner.get("query_plan")
        if isinstance(query_plan, Mapping):
            issues.extend(
                _replay_query_certificate(
                    container=query_plan,
                    prefix="planner.query_plan",
                    expected_sigma_field="root_sigma",
                    suppressible=True,
                    details=details,
                )
            )

    return CertificateReplayReport(issues=tuple(issues), details=details)


def check_run_record_certificates_path(path: Path) -> CertificateReplayReport:
    return check_run_record_certificates(_read_json(path))


def _is_sidecar_path(path: Path) -> bool:
    return path.name.startswith(".") or "explain" in path.parts


def _merge_details(aggregate: dict[str, Any], details: Mapping[str, Any]) -> None:
    for key in (
        "candidate_count",
        "accepted_candidate_count",
        "rejected_candidate_count",
        "checked_certificate_count",
        "checked_query_certificate_count",
        "suppressed_certificate_count",
        "suppressed_query_certificate_count",
        "legacy_inferred_ir_transfer_operator_count",
        "recorded_sigma_mismatch_count",
    ):
        aggregate[key] += int(details.get(key, 0) or 0)


def check_run_record_certificates_package(
    root: Path,
    *,
    require_planner_candidates: bool = False,
) -> CertificateReplayReport:
    if root.is_file():
        report = check_run_record_certificates_path(root)
        if (
            require_planner_candidates
            and not report.issues
            and int(report.details.get("candidate_count", 0) or 0) == 0
        ):
            return CertificateReplayReport(
                issues=(
                    CertificateReplayIssue(
                        str(root),
                        "no planner candidates found",
                    ),
                ),
                details=report.details,
            )
        return report

    issues: list[CertificateReplayIssue] = []
    details: dict[str, Any] = {
        "root": str(root),
        "record_count": 0,
        "checked_record_count": 0,
        "skipped_no_candidate_list_count": 0,
        "candidate_count": 0,
        "accepted_candidate_count": 0,
        "rejected_candidate_count": 0,
        "checked_certificate_count": 0,
        "checked_query_certificate_count": 0,
        "suppressed_certificate_count": 0,
        "suppressed_query_certificate_count": 0,
        "legacy_inferred_ir_transfer_operator_count": 0,
        "recorded_sigma_mismatch_count": 0,
    }
    if not root.exists():
        return CertificateReplayReport(
            issues=(CertificateReplayIssue(str(root), "certificate replay root does not exist"),),
            details=details,
        )

    for path in sorted(item for item in root.rglob("*.json") if not _is_sidecar_path(item)):
        details["record_count"] += 1
        try:
            record = _read_json(path)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            issues.append(CertificateReplayIssue(str(path), f"invalid JSON: {exc}"))
            continue
        planner = record.get("planner")
        candidates = planner.get("candidates") if isinstance(planner, Mapping) else None
        if not isinstance(candidates, list) and not _has_query_certificate_evidence(planner):
            details["skipped_no_candidate_list_count"] += 1
            if require_planner_candidates:
                issues.append(CertificateReplayIssue(str(path), "missing planner.candidates"))
            continue
        report = check_run_record_certificates(record)
        details["checked_record_count"] += 1
        _merge_details(details, report.details)
        for issue in report.issues:
            issues.append(CertificateReplayIssue(f"{path}:{issue.path}", issue.message))

    if details["record_count"] == 0:
        issues.append(CertificateReplayIssue(str(root), "certificate replay root has no JSON records"))
    if require_planner_candidates and details["candidate_count"] == 0:
        issues.append(CertificateReplayIssue(str(root), "no planner candidates found"))
    return CertificateReplayReport(issues=tuple(issues), details=details)


def check_run_record_certificates_package_path(
    path: Path,
    *,
    require_planner_candidates: bool = False,
) -> CertificateReplayReport:
    return check_run_record_certificates_package(
        path,
        require_planner_candidates=require_planner_candidates,
    )
