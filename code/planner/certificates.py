"""Flat certificate syntax and emitter for the finite CAPRLS planner fragment.

The full theory has an IR-derived certificate tree.  This module covers the
current finite-template layer: each admitted template emits a constructor
sequence that records the checked evidence used by the flat planner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence, Union


def _with_constructor(name: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    rendered = dict(payload)
    rendered["constructor"] = name
    return rendered


@dataclass(frozen=True)
class ExactLeaf:
    target_kind: str
    basis_id: str
    omega_id: str
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return _with_constructor(
            "ExactLeaf",
            {
                "target_kind": self.target_kind,
                "basis_id": self.basis_id,
                "omega_id": self.omega_id,
                "evidence": list(self.evidence),
            },
        )


@dataclass(frozen=True)
class CandidateLeaf:
    target_kind: str
    basis_id: str
    omega_id: str
    residual_ids: tuple[str, ...]
    deadline: str
    need: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return _with_constructor(
            "CandidateLeaf",
            {
                "target_kind": self.target_kind,
                "basis_id": self.basis_id,
                "omega_id": self.omega_id,
                "residual_ids": list(self.residual_ids),
                "deadline": self.deadline,
                "need": dict(self.need),
            },
        )


@dataclass(frozen=True)
class ArtifactValid:
    artifact_ids: Mapping[str, str]
    freshness: bool
    context_scope: bool
    snapshot: bool
    trusted_read: bool
    rid_domain: bool

    def to_dict(self) -> dict[str, Any]:
        return _with_constructor(
            "ArtifactValid",
            {
                "artifact_ids": dict(self.artifact_ids),
                "freshness": self.freshness,
                "context_scope": self.context_scope,
                "snapshot": self.snapshot,
                "trusted_read": self.trusted_read,
                "rid_domain": self.rid_domain,
            },
        )


@dataclass(frozen=True)
class Transfer:
    rule: str
    preserves_live: bool = True
    preserves_coverage: bool = True
    operator: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _with_constructor(
            "Transfer",
            {
                "rule": self.rule,
                "preserves_live": self.preserves_live,
                "preserves_coverage": self.preserves_coverage,
                "operator": self.operator,
            },
        )


@dataclass(frozen=True)
class Boundary:
    boundary_kind: str
    transparent: bool
    residual_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return _with_constructor(
            "Boundary",
            {
                "boundary_kind": self.boundary_kind,
                "transparent": self.transparent,
                "residual_ids": list(self.residual_ids),
            },
        )


@dataclass(frozen=True)
class Enforce:
    enforcer: str
    residual_ids: tuple[str, ...] = ()
    target_ids: tuple[str, ...] = ()
    allowed_by_rho: bool = True

    def to_dict(self) -> dict[str, Any]:
        return _with_constructor(
            "Enforce",
            {
                "enforcer": self.enforcer,
                "residual_ids": list(self.residual_ids),
                "target_ids": list(self.target_ids),
                "allowed_by_rho": self.allowed_by_rho,
            },
        )


@dataclass(frozen=True)
class Merge:
    merge_kind: str
    lifted_equivalence: bool
    trusted_surrogate: bool = False
    gamma_fact: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _with_constructor(
            "Merge",
            {
                "merge_kind": self.merge_kind,
                "lifted_equivalence": self.lifted_equivalence,
                "trusted_surrogate": self.trusted_surrogate,
                "gamma_fact": self.gamma_fact,
            },
        )


@dataclass(frozen=True)
class SafetyCheck:
    expression_label: str
    observes_candidate_basis: bool = False
    required_safety: str = "exact_authorized"

    def to_dict(self) -> dict[str, Any]:
        return _with_constructor(
            "SafetyCheck",
            {
                "expression_label": self.expression_label,
                "observes_candidate_basis": self.observes_candidate_basis,
                "required_safety": self.required_safety,
            },
        )


@dataclass(frozen=True)
class OrdinaryOp:
    operator: str
    preserves_sigma: bool = True

    def to_dict(self) -> dict[str, Any]:
        return _with_constructor(
            "OrdinaryOp",
            {
                "operator": self.operator,
                "preserves_sigma": self.preserves_sigma,
            },
        )


@dataclass(frozen=True)
class RootClosed:
    delivered_sigma: Mapping[str, Any]
    live_pairs_certified: bool
    residuals_recorded_or_discharged: bool
    domain_covering: bool = True

    def to_dict(self) -> dict[str, Any]:
        return _with_constructor(
            "RootClosed",
            {
                "delivered_sigma": dict(self.delivered_sigma),
                "live_pairs_certified": self.live_pairs_certified,
                "residuals_recorded_or_discharged": self.residuals_recorded_or_discharged,
                "domain_covering": self.domain_covering,
            },
        )


CertificateStep = Union[
    ExactLeaf,
    CandidateLeaf,
    ArtifactValid,
    Transfer,
    Boundary,
    Enforce,
    Merge,
    SafetyCheck,
    OrdinaryOp,
    RootClosed,
]


CERTIFICATE_CONSTRUCTOR_NAMES = (
    "ExactLeaf",
    "CandidateLeaf",
    "ArtifactValid",
    "Transfer",
    "Boundary",
    "Enforce",
    "Merge",
    "SafetyCheck",
    "OrdinaryOp",
    "RootClosed",
)


@dataclass(frozen=True)
class CertificateConstructorSpec:
    """Executable anchor for one certificate checker-transition row."""

    constructor: str
    transition_row: str
    checked_fields: tuple[str, ...]
    delivered_transition: str
    h_obligations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "constructor": self.constructor,
            "transition_row": self.transition_row,
            "checked_fields": list(self.checked_fields),
            "delivered_transition": self.delivered_transition,
            "h_obligations": list(self.h_obligations),
        }


# Single executable copy of the certificate-constructor to H-obligation table.
# Keep the mapping in this syntax module so certificate checking has one source
# of truth.
CONSTRUCTOR_H_OBLIGATIONS: Mapping[str, tuple[str, ...]] = {
    "ExactLeaf": ("H0", "H1", "H4"),
    "CandidateLeaf": ("H0", "H1"),
    "ArtifactValid": ("H2",),
    "Transfer": ("H7",),
    "Boundary": ("H3",),
    "Enforce": ("H3",),
    "Merge": ("H7",),
    "SafetyCheck": ("H4",),
    "OrdinaryOp": ("H6",),
    "RootClosed": ("H5", "H7"),
}


CERTIFICATE_CONSTRUCTOR_SPECS: tuple[CertificateConstructorSpec, ...] = (
    CertificateConstructorSpec(
        constructor="ExactLeaf",
        transition_row="ExactLeaf target and exact omega introduction",
        checked_fields=("target_kind", "basis_id", "omega_id", "evidence"),
        delivered_transition="introduce exact authorized basis pair",
        h_obligations=CONSTRUCTOR_H_OBLIGATIONS["ExactLeaf"],
    ),
    CertificateConstructorSpec(
        constructor="CandidateLeaf",
        transition_row="CandidateLeaf complete-candidate residual introduction",
        checked_fields=(
            "target_kind",
            "basis_id",
            "omega_id",
            "residual_ids",
            "deadline",
            "need",
        ),
        delivered_transition="introduce candidate basis and residual need/deadline",
        h_obligations=CONSTRUCTOR_H_OBLIGATIONS["CandidateLeaf"],
    ),
    CertificateConstructorSpec(
        constructor="ArtifactValid",
        transition_row="ArtifactValid freshness context snapshot trusted-read RID checks",
        checked_fields=(
            "artifact_ids",
            "freshness",
            "context_scope",
            "snapshot",
            "trusted_read",
            "rid_domain",
        ),
        delivered_transition="license artifact-backed exact leaf evidence",
        h_obligations=CONSTRUCTOR_H_OBLIGATIONS["ArtifactValid"],
    ),
    CertificateConstructorSpec(
        constructor="Transfer",
        transition_row="Transfer coverage-preserving ordinary IR operator",
        checked_fields=("rule", "preserves_live", "preserves_coverage", "operator"),
        delivered_transition="transport Sigma across a transparent operator",
        h_obligations=CONSTRUCTOR_H_OBLIGATIONS["Transfer"],
    ),
    CertificateConstructorSpec(
        constructor="Boundary",
        transition_row="Boundary transparency or pre-discharge witness",
        checked_fields=("boundary_kind", "transparent", "residual_ids"),
        delivered_transition="record boundary transparency side condition",
        h_obligations=CONSTRUCTOR_H_OBLIGATIONS["Boundary"],
    ),
    CertificateConstructorSpec(
        constructor="Enforce",
        transition_row="Enforce rho-allowed residual or physical enforcer",
        checked_fields=("enforcer", "residual_ids", "target_ids", "allowed_by_rho"),
        delivered_transition="discharge residual or deliver required physprop",
        h_obligations=CONSTRUCTOR_H_OBLIGATIONS["Enforce"],
    ),
    CertificateConstructorSpec(
        constructor="Merge",
        transition_row="Merge lifted-equivalence or trusted-surrogate witness",
        checked_fields=("merge_kind", "lifted_equivalence", "trusted_surrogate", "gamma_fact"),
        delivered_transition="justify duplicate-collapse or branch merge",
        h_obligations=CONSTRUCTOR_H_OBLIGATIONS["Merge"],
    ),
    CertificateConstructorSpec(
        constructor="SafetyCheck",
        transition_row="SafetyCheck expression observation boundary",
        checked_fields=("expression_label", "observes_candidate_basis", "required_safety"),
        delivered_transition="prove unsafe expression observes only exact basis",
        h_obligations=CONSTRUCTOR_H_OBLIGATIONS["SafetyCheck"],
    ),
    CertificateConstructorSpec(
        constructor="OrdinaryOp",
        transition_row="OrdinaryOp Sigma-preserving physical SQL operator",
        checked_fields=("operator", "preserves_sigma"),
        delivered_transition="record ordinary operator preservation evidence",
        h_obligations=CONSTRUCTOR_H_OBLIGATIONS["OrdinaryOp"],
    ),
    CertificateConstructorSpec(
        constructor="RootClosed",
        transition_row="RootClosed domain live-pair residual closure",
        checked_fields=(
            "delivered_sigma",
            "live_pairs_certified",
            "residuals_recorded_or_discharged",
            "domain_covering",
        ),
        delivered_transition="close root with certified live pairs and no open residuals",
        h_obligations=CONSTRUCTOR_H_OBLIGATIONS["RootClosed"],
    ),
)


def certificate_constructor_table() -> tuple[Mapping[str, Any], ...]:
    """Return the executable certificate checker-transition mapping."""

    return tuple(spec.to_dict() for spec in CERTIFICATE_CONSTRUCTOR_SPECS)


ARTIFACT_TEMPLATE_IDS = {
    "auth_index_enum_v1",
    "auth_index_semijoin_v1",
    "strong_auth_index_keyed_v1",
    "auth_index_keyed_semijoin_v1",
    "mav_scan_v1",
    "hybrid_intersect_v1",
}


def certificate_to_dicts(certificate: Sequence[CertificateStep]) -> list[dict[str, Any]]:
    return [step.to_dict() for step in certificate]


def emit_query_certificate(
    *,
    occurrence_certificates: Mapping[str, Sequence[Mapping[str, Any]]],
    operator_transfers: Sequence[str | Mapping[str, Any]] = (),
    delivered_sigma: Mapping[str, Any],
    domain_covering: bool,
    live_pairs_certified: bool,
    residuals_closed: bool,
) -> tuple[Mapping[str, Any], ...]:
    """Emit a query-level certificate from occurrence certificates and root facts."""

    steps: list[Mapping[str, Any]] = []
    for occurrence_id, certificate in sorted(occurrence_certificates.items()):
        for raw_step in certificate:
            step = dict(raw_step)
            if step.get("constructor") == "RootClosed":
                continue
            if step.get("constructor") == "Enforce" and step.get("enforcer") == "RCheck":
                continue
            steps.append(step)
        steps.append(Transfer(rule=f"occurrence_admitted:{occurrence_id}").to_dict())

    for transfer in operator_transfers:
        steps.extend(_ir_operator_certificate_steps(transfer))

    steps.append(Transfer(rule="query_root_closure").to_dict())
    steps.append(
        RootClosed(
            delivered_sigma=delivered_sigma,
            domain_covering=domain_covering,
            live_pairs_certified=live_pairs_certified,
            residuals_recorded_or_discharged=residuals_closed,
        ).to_dict()
    )
    return tuple(steps)


def _ir_operator_certificate_steps(transfer: str | Mapping[str, Any]) -> list[Mapping[str, Any]]:
    if isinstance(transfer, Mapping):
        rule = str(transfer.get("rule", ""))
        operator = str(transfer.get("operator") or rule.split(":", 1)[0])
    else:
        rule = str(transfer)
        operator = rule.split(":", 1)[0]
        transfer = {}
    marker = Transfer(rule=f"ir:{rule}", operator=operator).to_dict()
    _attach_ir_transfer_evidence(marker, transfer)
    if rule.startswith("Boundary:"):
        return [
            Boundary(boundary_kind=rule.split(":", 1)[1], transparent=False).to_dict(),
            marker,
        ]
    if rule.startswith("UnsafeExpr:"):
        return [
            SafetyCheck(expression_label=rule.split(":", 1)[1]).to_dict(),
            marker,
        ]
    if rule.startswith("Select:unsafe"):
        payload = rule.split(":", 2)
        expression_label = payload[2] if len(payload) > 2 else "unsafe_predicate"
        return [
            SafetyCheck(expression_label=expression_label).to_dict(),
            marker,
        ]
    if rule.startswith("RCheck"):
        target_ids = _rule_payload(rule)
        return [
            Enforce(
                enforcer="RCheck",
                residual_ids=target_ids,
                target_ids=target_ids,
                allowed_by_rho=True,
            ).to_dict(),
            marker,
        ]
    if rule.startswith("ValidationGate"):
        target_ids = _rule_payload(rule)
        return [
            Enforce(
                enforcer="ValidationGate",
                target_ids=target_ids,
                allowed_by_rho=True,
            ).to_dict(),
            marker,
        ]
    if rule.startswith("SortEnforce"):
        target_ids = _rule_payload(rule)
        return [
            Enforce(
                enforcer="SortEnforce",
                target_ids=target_ids,
                allowed_by_rho=True,
            ).to_dict(),
            marker,
        ]
    if rule == "Materialize":
        return [
            Enforce(enforcer="Materialize", allowed_by_rho=True).to_dict(),
            marker,
        ]
    if rule == "BarrierEnforce":
        return [
            Enforce(enforcer="BarrierEnforce", allowed_by_rho=True).to_dict(),
            marker,
        ]
    if rule.startswith("DuplicateCollapse:"):
        parts = rule.split(":", 2)
        fact = parts[1]
        gamma_fact = parts[2] if len(parts) > 2 else ""
        return [
            Merge(
                merge_kind=f"duplicate_collapse:{fact}",
                lifted_equivalence=fact == "lifted_equivalence",
                trusted_surrogate=fact == "trusted_surrogate",
                gamma_fact=gamma_fact,
            ).to_dict(),
            marker,
        ]
    if rule == "DuplicateCollapse":
        return [
            Boundary(boundary_kind="duplicate_collapse", transparent=False).to_dict(),
            marker,
        ]
    return [marker]


def _attach_ir_transfer_evidence(marker: dict[str, Any], transfer: Mapping[str, Any]) -> None:
    version = transfer.get("ir_traversal_version")
    if version:
        marker["ir_traversal_version"] = str(version)
    node_path = transfer.get("node_path")
    if isinstance(node_path, Sequence) and not isinstance(node_path, (str, bytes, bytearray)):
        marker["node_path"] = [str(item) for item in node_path]
    occurrence_ids = transfer.get("occurrence_ids")
    if isinstance(occurrence_ids, Sequence) and not isinstance(occurrence_ids, (str, bytes, bytearray)):
        marker["occurrence_ids"] = [str(item) for item in occurrence_ids]
    traversal_index = transfer.get("traversal_index")
    if isinstance(traversal_index, int):
        marker["traversal_index"] = traversal_index


def _rule_payload(rule: str) -> tuple[str, ...]:
    if ":" not in rule:
        return ()
    payload = rule.split(":", 1)[1]
    return tuple(item for item in (part.strip() for part in payload.split(",")) if item)


def _first_basis_id(sigma: Mapping[str, Any]) -> str:
    dom = sigma.get("Dom")
    if isinstance(dom, Sequence) and dom and isinstance(dom[0], Mapping):
        first = dom[0]
        basis = str(first.get("basis_id", ""))
        if basis:
            return basis
        relation = str(first.get("relation", ""))
        occurrence = str(first.get("occurrence_id", ""))
        if relation or occurrence:
            return f"{relation}:{occurrence}".strip(":")
    if isinstance(dom, Mapping):
        basis = str(dom.get("basis_id", ""))
        if basis:
            return basis
        relation = str(dom.get("relation", ""))
        occurrence = str(dom.get("occurrence_id", ""))
        if relation or occurrence:
            return f"{relation}:{occurrence}".strip(":")
    return ""


def _first_auth_pair(sigma: Mapping[str, Any]) -> tuple[str, str]:
    auth_set = sigma.get("AuthSet")
    basis_id = _first_basis_id(sigma)
    if isinstance(auth_set, Mapping):
        pairs = auth_set.get("pairs")
        if isinstance(pairs, Sequence) and pairs and isinstance(pairs[0], Mapping):
            return (
                str(pairs[0].get("basis_id", "")),
                str(pairs[0].get("omega_id", "")),
            )
    if isinstance(auth_set, str) and auth_set not in {"", "unknown"}:
        return (basis_id, auth_set)
    return (basis_id, "")


def _residual_ids(sigma: Mapping[str, Any]) -> tuple[str, ...]:
    residuals = sigma.get("Residual") or []
    ids: list[str] = []
    if isinstance(residuals, Sequence):
        for residual in residuals:
            if isinstance(residual, Mapping):
                ids.append(
                    str(
                        residual.get(
                            "check_id",
                            residual.get(
                                "omega_id",
                                ":".join(
                                    str(residual.get(part, ""))
                                    for part in ("policy_id", "occurrence_id")
                                    if residual.get(part)
                                ),
                            ),
                        )
                    )
                )
    return tuple(item for item in ids if item)


def _first_residual_need(sigma: Mapping[str, Any]) -> Mapping[str, Any]:
    residuals = sigma.get("Residual") or []
    if isinstance(residuals, Sequence) and residuals and isinstance(residuals[0], Mapping):
        need = residuals[0].get("need")
        if isinstance(need, Mapping):
            return need
    return {}


def _first_residual_deadline(sigma: Mapping[str, Any], default: str) -> str:
    residuals = sigma.get("Residual") or []
    if isinstance(residuals, Sequence) and residuals and isinstance(residuals[0], Mapping):
        return str(residuals[0].get("deadline", default))
    return default


def _target_kind(kappa_sem: Mapping[str, Any]) -> str:
    target = kappa_sem.get("target")
    if isinstance(target, Mapping):
        return str(target.get("kind", "bare_occurrence"))
    return "bare_occurrence"


def _leaf_evidence(template_id: str, kappa_sem: Mapping[str, Any]) -> tuple[str, ...]:
    pre = kappa_sem.get("pre")
    evidence = tuple(str(item) for item in pre) if isinstance(pre, Sequence) else ()
    if template_id in ARTIFACT_TEMPLATE_IDS:
        return ("ArtifactValid",) + evidence
    return evidence or ("trusted_exact_policy_executable",)


def emit_flat_certificate(
    *,
    template_id: str,
    kappa_sem: Mapping[str, Any],
    delivered_sigma: Mapping[str, Any],
    artifact_ids: Optional[Mapping[str, str]] = None,
) -> tuple[CertificateStep, ...]:
    """Emit a certificate skeleton for one accepted flat-template candidate."""

    basis_id, omega_id = _first_auth_pair(delivered_sigma)
    basis_id = basis_id or _first_basis_id(delivered_sigma)
    target_kind = _target_kind(kappa_sem)
    residual_ids = _residual_ids(delivered_sigma)
    steps: list[CertificateStep] = []
    if template_id in ARTIFACT_TEMPLATE_IDS:
        steps.append(
            ArtifactValid(
                artifact_ids=dict(artifact_ids or {}),
                freshness=True,
                context_scope=True,
                snapshot=True,
                trusted_read=True,
                rid_domain=True,
            )
        )
    if template_id == "guard_candidate_plus_residual_v1":
        deadline = _first_residual_deadline(
            delivered_sigma,
            "parent_transparent_boundary",
        )
        steps.extend(
            [
                CandidateLeaf(
                    target_kind=target_kind,
                    basis_id=basis_id,
                    omega_id=omega_id or "complete_candidate",
                    residual_ids=residual_ids,
                    deadline=deadline,
                    need=_first_residual_need(delivered_sigma),
                ),
                Transfer(rule="candidate_residual_transport"),
                Boundary(
                    boundary_kind=deadline,
                    transparent=False,
                    residual_ids=residual_ids,
                ),
                Enforce(enforcer="RCheck", residual_ids=residual_ids),
                SafetyCheck(expression_label="exact_residual_after_guard"),
            ]
        )
    else:
        steps.extend(
            [
                ExactLeaf(
                    target_kind=target_kind,
                    basis_id=basis_id,
                    omega_id=omega_id,
                    evidence=_leaf_evidence(template_id, kappa_sem),
                ),
                OrdinaryOp(operator=template_id),
            ]
        )
    steps.append(
        RootClosed(
            delivered_sigma=delivered_sigma,
            live_pairs_certified=True,
            residuals_recorded_or_discharged=True,
        )
    )
    return tuple(steps)
