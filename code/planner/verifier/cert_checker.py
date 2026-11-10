"""Linear checker for CAPRLS flat-template certificates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence

from planner.certificates import ARTIFACT_TEMPLATE_IDS, CONSTRUCTOR_H_OBLIGATIONS


IR_TRANSFER_OPERATORS = {
    "BarrierEnforce",
    "Boundary",
    "DuplicateCollapse",
    "InnerJoin",
    "Materialize",
    "Project",
    "RCheck",
    "Root",
    "Select",
    "SortEnforce",
    "UnionTagged",
    "UnsafeExpr",
    "ValidationGate",
}


@dataclass(frozen=True)
class CertReject:
    constructor_index: Optional[int]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "constructor_index": self.constructor_index,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CertificateCheckResult:
    status: str
    delivered_sigma: Mapping[str, Any]
    h_obligations: tuple[str, ...]
    rejects: tuple[CertReject, ...] = ()

    @property
    def ok(self) -> bool:
        return self.status == "pass"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "delivered_sigma": dict(self.delivered_sigma),
            "h_obligations": list(self.h_obligations),
            "rejects": [reject.to_dict() for reject in self.rejects],
        }


def _as_step_dict(step: Any) -> Mapping[str, Any]:
    if isinstance(step, Mapping):
        return step
    if hasattr(step, "to_dict"):
        rendered = step.to_dict()
        if isinstance(rendered, Mapping):
            return rendered
    return {}


def _constructors(certificate: Sequence[Any]) -> tuple[str, ...]:
    return tuple(str(_as_step_dict(step).get("constructor", "")) for step in certificate)


def _record_reject(rejects: list[CertReject], index: Optional[int], reason: str) -> None:
    rejects.append(CertReject(constructor_index=index, reason=reason))


def _is_json_sequence(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def _has_only_nonempty_strings(value: Sequence[Any]) -> bool:
    return all(isinstance(item, str) and bool(item) for item in value)


def _is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _sigma_equal(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return dict(left) == dict(right)


def check_certificate(
    certificate: Sequence[Any],
    *,
    expected_sigma: Optional[Mapping[str, Any]] = None,
    template_id: Optional[str] = None,
) -> CertificateCheckResult:
    """Check one constructor sequence in a single pass.

    The checker combines recorded evidence; it does not re-run PostgreSQL,
    re-evaluate policy predicates, or recompute semantic facts.
    """

    rejects: list[CertReject] = []
    h_obligations: set[str] = set()
    delivered_sigma: Mapping[str, Any] = {}
    artifact_valid = False
    exact_leaf = False
    candidate_leaf = False
    transfer_seen = False
    boundary_seen = False
    enforce_seen = False
    safety_seen = False
    ordinary_seen = False
    root_seen = False
    pending_boundary_residual_ids: set[str] = set()

    if not certificate:
        _record_reject(rejects, None, "empty_certificate")

    for index, raw_step in enumerate(certificate):
        step = _as_step_dict(raw_step)
        constructor = str(step.get("constructor", ""))
        if not constructor:
            _record_reject(rejects, index, "missing_constructor")
            continue
        h_obligations.update(CONSTRUCTOR_H_OBLIGATIONS.get(constructor, ()))

        if constructor == "ArtifactValid":
            artifact_valid = True
            for field in ("freshness", "context_scope", "snapshot", "trusted_read", "rid_domain"):
                if not bool(step.get(field)):
                    _record_reject(rejects, index, f"artifact_valid_missing:{field}")
            artifact_ids = step.get("artifact_ids")
            if not isinstance(artifact_ids, Mapping) or not artifact_ids:
                _record_reject(rejects, index, "artifact_valid_missing:artifact_ids")
        elif constructor == "ExactLeaf":
            exact_leaf = True
            if not step.get("basis_id"):
                _record_reject(rejects, index, "exact_leaf_missing:basis_id")
            if not step.get("omega_id"):
                _record_reject(rejects, index, "exact_leaf_missing:omega_id")
            evidence = step.get("evidence")
            if not _is_json_sequence(evidence):
                _record_reject(rejects, index, "exact_leaf_invalid:evidence")
            elif not evidence:
                _record_reject(rejects, index, "exact_leaf_missing:evidence")
            elif not _has_only_nonempty_strings(evidence):
                _record_reject(rejects, index, "exact_leaf_invalid:evidence")
        elif constructor == "CandidateLeaf":
            candidate_leaf = True
            residual_ids = step.get("residual_ids")
            if not _is_json_sequence(residual_ids):
                _record_reject(rejects, index, "candidate_leaf_invalid:residual_ids")
            elif not residual_ids:
                _record_reject(rejects, index, "candidate_leaf_missing:residual_ids")
            elif not _has_only_nonempty_strings(residual_ids):
                _record_reject(rejects, index, "candidate_leaf_invalid:residual_ids")
            if not step.get("deadline"):
                _record_reject(rejects, index, "candidate_leaf_missing:deadline")
            need = step.get("need")
            if need is not None and not isinstance(need, Mapping):
                _record_reject(rejects, index, "candidate_leaf_need_not_mapping")
            elif isinstance(need, Mapping) and need:
                for field in (
                    "attrs",
                    "rids",
                    "ctx_keys",
                    "trusted_reads",
                    "freshness_evidence",
                    "lineage_carriers",
                ):
                    value = need.get(field)
                    if field not in need:
                        _record_reject(rejects, index, f"candidate_leaf_need_missing:{field}")
                    elif not _is_json_sequence(value) or not _has_only_nonempty_strings(value):
                        _record_reject(rejects, index, f"candidate_leaf_need_invalid:{field}")
        elif constructor == "Transfer":
            transfer_seen = True
            rule = step.get("rule")
            if not _is_nonempty_string(rule):
                _record_reject(rejects, index, "transfer_missing:rule")
            elif rule.startswith("ir:"):
                expected_operator = rule[3:].split(":", 1)[0]
                operator = step.get("operator")
                if not _is_nonempty_string(operator):
                    _record_reject(rejects, index, "transfer_missing:operator")
                elif operator != expected_operator:
                    _record_reject(rejects, index, "transfer_operator_mismatch")
                elif operator not in IR_TRANSFER_OPERATORS:
                    _record_reject(rejects, index, "transfer_unknown_operator")
                if step.get("ir_traversal_version") == "ir_transfer_path_v1":
                    node_path = step.get("node_path")
                    if (
                        not _is_json_sequence(node_path)
                        or not node_path
                        or not _has_only_nonempty_strings(node_path)
                    ):
                        _record_reject(rejects, index, "transfer_invalid:node_path")
                    occurrence_ids = step.get("occurrence_ids")
                    if occurrence_ids is not None and (
                        not _is_json_sequence(occurrence_ids)
                        or not _has_only_nonempty_strings(occurrence_ids)
                    ):
                        _record_reject(rejects, index, "transfer_invalid:occurrence_ids")
                    if not isinstance(step.get("traversal_index"), int):
                        _record_reject(rejects, index, "transfer_invalid:traversal_index")
            if not bool(step.get("preserves_live")):
                _record_reject(rejects, index, "transfer_drops_live_obligations")
            if not bool(step.get("preserves_coverage")):
                _record_reject(rejects, index, "transfer_drops_coverage")
        elif constructor == "Boundary":
            boundary_seen = True
            residual_ids = step.get("residual_ids")
            residual_id_set: set[str] = set()
            if residual_ids is not None:
                if not _is_json_sequence(residual_ids) or not _has_only_nonempty_strings(
                    residual_ids
                ):
                    _record_reject(rejects, index, "boundary_invalid:residual_ids")
                else:
                    residual_id_set = set(residual_ids)
            if not bool(step.get("transparent")) and residual_id_set:
                pending_boundary_residual_ids.update(residual_id_set)
        elif constructor == "Enforce":
            enforce_seen = True
            if not bool(step.get("allowed_by_rho")):
                _record_reject(rejects, index, "enforcer_not_allowed_by_rho")
            target_ids = step.get("target_ids")
            if target_ids is not None:
                if not _is_json_sequence(target_ids) or not _has_only_nonempty_strings(
                    target_ids
                ):
                    _record_reject(rejects, index, "enforcer_invalid:target_ids")
            residual_ids = step.get("residual_ids")
            if residual_ids is not None:
                if not _is_json_sequence(residual_ids) or not _has_only_nonempty_strings(
                    residual_ids
                ):
                    _record_reject(rejects, index, "enforcer_invalid:residual_ids")
            if step.get("enforcer") == "RCheck" and step.get("residual_ids"):
                if not boundary_seen:
                    _record_reject(rejects, index, "rcheck_without_prior_boundary")
                elif _is_json_sequence(residual_ids) and _has_only_nonempty_strings(residual_ids):
                    pending_boundary_residual_ids.difference_update(set(residual_ids))
        elif constructor == "Merge":
            lifted_equivalence = bool(step.get("lifted_equivalence"))
            trusted_surrogate = bool(step.get("trusted_surrogate"))
            merge_kind = str(step.get("merge_kind") or "")
            if not (lifted_equivalence or trusted_surrogate):
                _record_reject(rejects, index, "merge_missing_equivalence_witness")
            if lifted_equivalence and trusted_surrogate:
                _record_reject(rejects, index, "merge_ambiguous_equivalence_witness")
            if merge_kind.startswith("duplicate_collapse"):
                if merge_kind == "duplicate_collapse:lifted_equivalence":
                    if not lifted_equivalence or trusted_surrogate:
                        _record_reject(rejects, index, "merge_kind_witness_mismatch")
                elif merge_kind == "duplicate_collapse:trusted_surrogate":
                    if not trusted_surrogate or lifted_equivalence:
                        _record_reject(rejects, index, "merge_kind_witness_mismatch")
                if not str(step.get("gamma_fact") or ""):
                    _record_reject(rejects, index, "merge_missing_gamma_fact")
        elif constructor == "SafetyCheck":
            safety_seen = True
            if bool(step.get("observes_candidate_basis")):
                _record_reject(rejects, index, "unsafe_expression_observes_candidate_basis")
        elif constructor == "OrdinaryOp":
            ordinary_seen = True
            if not bool(step.get("preserves_sigma")):
                _record_reject(rejects, index, "ordinary_op_does_not_preserve_sigma")
        elif constructor == "RootClosed":
            root_seen = True
            delivered = step.get("delivered_sigma")
            if not isinstance(delivered, Mapping):
                _record_reject(rejects, index, "root_closed_missing:delivered_sigma")
                delivered_sigma = {}
            else:
                delivered_sigma = delivered
            if not bool(step.get("domain_covering")):
                _record_reject(rejects, index, "root_not_domain_covering")
            if not bool(step.get("live_pairs_certified")):
                _record_reject(rejects, index, "root_live_pairs_not_certified")
            if not bool(step.get("residuals_recorded_or_discharged")):
                _record_reject(rejects, index, "root_residuals_not_closed")
        else:
            _record_reject(rejects, index, f"unknown_constructor:{constructor}")

    constructors = _constructors(certificate)
    if root_seen and constructors[-1] != "RootClosed":
        _record_reject(rejects, len(certificate) - 1, "root_closed_not_last")
    if not root_seen:
        _record_reject(rejects, None, "missing_root_closed")
    if pending_boundary_residual_ids:
        _record_reject(rejects, None, "boundary_residuals_not_discharged")
    if template_id in ARTIFACT_TEMPLATE_IDS and not artifact_valid:
        _record_reject(rejects, None, "artifact_template_without_artifact_valid")
    if template_id in ARTIFACT_TEMPLATE_IDS and "ArtifactValid" in constructors and "ExactLeaf" in constructors:
        if constructors.index("ArtifactValid") > constructors.index("ExactLeaf"):
            _record_reject(rejects, None, "artifact_valid_after_exact_leaf")
    if template_id == "query_plan":
        if not (exact_leaf or candidate_leaf):
            _record_reject(rejects, None, "query_certificate_missing_leaf")
        if not transfer_seen:
            _record_reject(rejects, None, "query_certificate_missing_transfer")
    elif template_id == "guard_candidate_plus_residual_v1":
        expected = (
            "CandidateLeaf",
            "Transfer",
            "Boundary",
            "Enforce",
            "SafetyCheck",
            "RootClosed",
        )
        if constructors != expected:
            _record_reject(rejects, None, "guard_certificate_constructor_sequence_mismatch")
        if not (candidate_leaf and transfer_seen and boundary_seen and enforce_seen and safety_seen):
            _record_reject(rejects, None, "guard_certificate_missing_required_constructor")
    elif not (exact_leaf and ordinary_seen):
        _record_reject(rejects, None, "exact_template_missing_leaf_or_ordinary_op")

    if expected_sigma is not None:
        if not isinstance(expected_sigma, Mapping):
            _record_reject(rejects, None, "expected_sigma_not_mapping")
        elif not _sigma_equal(delivered_sigma, expected_sigma):
            _record_reject(rejects, None, "delivered_sigma_mismatch")

    status = "fail" if rejects else "pass"
    return CertificateCheckResult(
        status=status,
        delivered_sigma=delivered_sigma,
        h_obligations=tuple(sorted(h_obligations)),
        rejects=tuple(rejects),
    )
