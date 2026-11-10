"""Structured delivered-state objects for the finite CAPRLS planner."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional


def _json_value(value: Any) -> Any:
    """Recursively normalize finite state into canonical JSON containers."""

    if isinstance(value, Mapping):
        return {str(key): _json_value(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(child) for child in value]
    if isinstance(value, (set, frozenset)):
        return [_json_value(child) for child in sorted(value, key=str)]
    return value


_SCHEMA_CARRIER_PHYS_FIELDS = ("visible_attrs", "hidden_attrs")


def _canonical_phys_props(value: Any) -> dict[str, Any]:
    """Restore JSON-shaped physical properties without inventing carriers."""

    if not isinstance(value, Mapping):
        raise ValueError("Sigma.PhysProps must be a mapping")
    normalized = _json_value(value)
    assert isinstance(normalized, dict)
    for field_name in _SCHEMA_CARRIER_PHYS_FIELDS:
        if field_name not in normalized:
            continue
        carriers = normalized[field_name]
        if not isinstance(carriers, list):
            raise ValueError(f"Sigma.PhysProps.{field_name} must be a JSON list")
        if any(not isinstance(carrier, str) or not carrier for carrier in carriers):
            raise ValueError(
                f"Sigma.PhysProps.{field_name} must contain non-empty strings"
            )
    return normalized


@dataclass(frozen=True)
class BasisElement:
    basis_id: str
    kind: str
    occurrence_id: str
    relation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "basis_id": self.basis_id,
            "kind": self.kind,
            "occurrence_id": self.occurrence_id,
            "relation": self.relation,
        }


@dataclass(frozen=True)
class Need:
    attrs: tuple[str, ...] = ()
    rids: tuple[str, ...] = ()
    ctx_keys: tuple[str, ...] = ()
    trusted_reads: tuple[str, ...] = ()
    freshness_evidence: tuple[str, ...] = ()
    lineage_carriers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "attrs",
            "rids",
            "ctx_keys",
            "trusted_reads",
            "freshness_evidence",
            "lineage_carriers",
        ):
            ordered: list[str] = []
            for value in getattr(self, name):
                if not isinstance(value, str) or not value:
                    raise ValueError(f"Need.{name} must contain non-empty strings")
                if value not in ordered:
                    ordered.append(value)
            object.__setattr__(
                self,
                name,
                tuple(ordered),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "attrs": list(self.attrs),
            "rids": list(self.rids),
            "ctx_keys": list(self.ctx_keys),
            "trusted_reads": list(self.trusted_reads),
            "freshness_evidence": list(self.freshness_evidence),
            "lineage_carriers": list(self.lineage_carriers),
        }


@dataclass(frozen=True, order=True)
class RIDCarrierBinding:
    """Declared correspondence between one logical RID and an output carrier."""

    logical_rid: str
    physical_carrier: str
    rid_domain_id: str

    def __post_init__(self) -> None:
        if not self.logical_rid or not self.physical_carrier or not self.rid_domain_id:
            raise ValueError("RID carrier binding requires complete identity")

    def to_dict(self) -> dict[str, str]:
        return {
            "logical_rid": self.logical_rid,
            "physical_carrier": self.physical_carrier,
            "rid_domain_id": self.rid_domain_id,
        }


@dataclass(frozen=True, order=True)
class LineageCarrierBinding:
    """Declared correspondence between logical lineage and a physical column."""

    logical_carrier: str
    physical_carrier: str

    def __post_init__(self) -> None:
        if not self.logical_carrier or not self.physical_carrier:
            raise ValueError("lineage carrier binding requires complete identity")

    def to_dict(self) -> dict[str, str]:
        return {
            "logical_carrier": self.logical_carrier,
            "physical_carrier": self.physical_carrier,
        }


RECOVERABILITY_EVIDENCE_MODES = frozenset(
    {
        "production_typed",
        "legacy_diagnostic",
        "planning_rejected",
    }
)


@dataclass(frozen=True)
class RecoverabilityContext:
    """All evidence classes that a residual Need must recover at a boundary."""

    visible_attrs: frozenset[str] = frozenset()
    hidden_carriers: frozenset[str] = frozenset()
    rid_carriers: tuple[RIDCarrierBinding, ...] = ()
    lineage_carriers: tuple[LineageCarrierBinding, ...] = ()
    available_context_keys: frozenset[str] = frozenset()
    trusted_read_facts: frozenset[str] = frozenset()
    freshness_facts: frozenset[str] = frozenset()
    gamma_snapshot_id: str = ""
    # Provenance label only.  Promotion remains bound to the external G2
    # planning-execution/receipt identity and never follows from this value.
    evidence_mode: str = "legacy_diagnostic"

    def __post_init__(self) -> None:
        for name in (
            "visible_attrs",
            "hidden_carriers",
            "available_context_keys",
            "trusted_read_facts",
            "freshness_facts",
        ):
            values = tuple(getattr(self, name))
            if any(not isinstance(value, str) or not value for value in values):
                raise ValueError(
                    f"recoverability context {name} must contain non-empty strings"
                )
            object.__setattr__(
                self,
                name,
                frozenset(values),
            )
        if any(
            not isinstance(item, RIDCarrierBinding)
            for item in self.rid_carriers
        ):
            raise TypeError("recoverability RID carriers must be typed bindings")
        if any(
            not isinstance(item, LineageCarrierBinding)
            for item in self.lineage_carriers
        ):
            raise TypeError("recoverability lineage carriers must be typed bindings")
        rid_carriers = tuple(sorted(set(self.rid_carriers)))
        lineage_carriers = tuple(sorted(set(self.lineage_carriers)))
        object.__setattr__(self, "rid_carriers", rid_carriers)
        object.__setattr__(self, "lineage_carriers", lineage_carriers)
        if self.evidence_mode not in RECOVERABILITY_EVIDENCE_MODES:
            raise ValueError("recoverability evidence mode is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "visible_attrs": sorted(self.visible_attrs),
            "hidden_carriers": sorted(self.hidden_carriers),
            "rid_carriers": [item.to_dict() for item in self.rid_carriers],
            "lineage_carriers": [
                item.to_dict() for item in self.lineage_carriers
            ],
            "available_context_keys": sorted(self.available_context_keys),
            "trusted_read_facts": sorted(self.trusted_read_facts),
            "freshness_facts": sorted(self.freshness_facts),
            "gamma_snapshot_id": self.gamma_snapshot_id,
            "evidence_mode": self.evidence_mode,
        }

    def missing_for(
        self,
        need: Need,
        *,
        expected_rid_domain_id: str,
        expected_gamma_snapshot_id: str,
    ) -> tuple[str, ...]:
        available_attrs = self.visible_attrs | self.hidden_carriers
        missing: list[str] = []
        checks = (
            ("attrs", set(need.attrs), available_attrs),
            ("ctx_keys", set(need.ctx_keys), self.available_context_keys),
            ("trusted_reads", set(need.trusted_reads), self.trusted_read_facts),
            ("freshness_evidence", set(need.freshness_evidence), self.freshness_facts),
        )
        for label, required, available in checks:
            for value in sorted(required - available):
                missing.append(f"{label}:{value}")
        for logical_rid in need.rids:
            if not any(
                binding.logical_rid == logical_rid
                and binding.rid_domain_id == expected_rid_domain_id
                and binding.physical_carrier in available_attrs
                for binding in self.rid_carriers
            ):
                missing.append(f"rids:{logical_rid}")
        for logical_carrier in need.lineage_carriers:
            if not any(
                binding.logical_carrier == logical_carrier
                and binding.physical_carrier in available_attrs
                for binding in self.lineage_carriers
            ):
                missing.append(f"lineage_carriers:{logical_carrier}")
        if need.trusted_reads or need.freshness_evidence:
            if (
                not expected_gamma_snapshot_id
                or self.gamma_snapshot_id != expected_gamma_snapshot_id
            ):
                missing.append(
                    "gamma_snapshot:"
                    + (expected_gamma_snapshot_id or "missing")
                )
        return tuple(missing)


@dataclass(frozen=True)
class RecoverabilityWitness:
    """Basis-local recoverability evidence derived by leaf/transfer rules."""

    witness_id: str
    basis_id: str
    source_basis_id: str
    transport_path: tuple[str, ...]
    context: RecoverabilityContext

    def __post_init__(self) -> None:
        if not self.witness_id or not self.basis_id or not self.source_basis_id:
            raise ValueError("recoverability witness requires complete basis identity")
        if not self.transport_path or any(
            not isinstance(item, str) or not item
            for item in self.transport_path
        ):
            raise ValueError("recoverability witness transport path is invalid")
        if not isinstance(self.context, RecoverabilityContext):
            raise TypeError("recoverability witness context must be typed")
        expected_id = self.derived_id(
            basis_id=self.basis_id,
            source_basis_id=self.source_basis_id,
            transport_path=self.transport_path,
            context=self.context,
        )
        if self.witness_id != expected_id:
            raise ValueError("recoverability witness identity is not canonical")

    @classmethod
    def derive(
        cls,
        *,
        basis_id: str,
        source_basis_id: str,
        transport_path: tuple[str, ...],
        context: RecoverabilityContext,
    ) -> "RecoverabilityWitness":
        return cls(
            witness_id=cls.derived_id(
                basis_id=basis_id,
                source_basis_id=source_basis_id,
                transport_path=transport_path,
                context=context,
            ),
            basis_id=basis_id,
            source_basis_id=source_basis_id,
            transport_path=transport_path,
            context=context,
        )

    @staticmethod
    def derived_id(
        *,
        basis_id: str,
        source_basis_id: str,
        transport_path: tuple[str, ...],
        context: RecoverabilityContext,
    ) -> str:
        payload = {
            "basis_id": basis_id,
            "source_basis_id": source_basis_id,
            "transport_path": list(transport_path),
            "context": context.to_dict(),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "witness_id": self.witness_id,
            "basis_id": self.basis_id,
            "source_basis_id": self.source_basis_id,
            "transport_path": list(self.transport_path),
            "context": self.context.to_dict(),
        }

    @property
    def digest(self) -> str:
        canonical = json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ResidualRecord:
    basis_id: str
    omega_id: str
    check_id: str
    need: Need
    deadline: str
    recoverability_witness_id: str
    gamma_snapshot_id: str
    rid_domain_id: str

    def __post_init__(self) -> None:
        for name in (
            "basis_id",
            "omega_id",
            "check_id",
            "deadline",
            "recoverability_witness_id",
            "gamma_snapshot_id",
            "rid_domain_id",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"ResidualRecord.{name} must be non-empty")
        if not isinstance(self.need, Need):
            raise TypeError("ResidualRecord.need must be typed")

    def to_dict(self) -> dict[str, Any]:
        return {
            "basis_id": self.basis_id,
            "omega_id": self.omega_id,
            "check_id": self.check_id,
            "need": self.need.to_dict(),
            "deadline": self.deadline,
            "recoverability_witness_id": self.recoverability_witness_id,
            "gamma_snapshot_id": self.gamma_snapshot_id,
            "rid_domain_id": self.rid_domain_id,
        }


@dataclass(frozen=True)
class Sigma:
    dom: tuple[BasisElement, ...]
    live: Mapping[str, tuple[str, ...]]
    auth_set: tuple[tuple[str, str], ...]
    auth_summary: str
    residuals: tuple[ResidualRecord, ...]
    safety: Mapping[str, str]
    freshness: str
    context_scope: str
    rid_mat_props: Mapping[str, Any]
    recoverability: tuple[RecoverabilityWitness, ...]
    phys_props: Mapping[str, Any] = field(default_factory=dict)
    branch_lineage: str = "preserved"

    def __post_init__(self) -> None:
        if any(
            not isinstance(item, RecoverabilityWitness)
            for item in self.recoverability
        ):
            raise TypeError("Sigma recoverability entries must be typed witnesses")
        recoverability = tuple(
            sorted(
                self.recoverability,
                key=lambda item: (item.basis_id, item.witness_id),
            )
        )
        if len({item.witness_id for item in recoverability}) != len(
            recoverability
        ):
            raise ValueError("Sigma recoverability witness identifiers must be unique")
        object.__setattr__(self, "recoverability", recoverability)

    def to_dict(self) -> dict[str, Any]:
        return {
            "Dom": [basis.to_dict() for basis in self.dom],
            "Live": {key: list(value) for key, value in self.live.items()},
            "AuthSet": {
                "summary": self.auth_summary,
                "pairs": [
                    {"basis_id": basis_id, "omega_id": omega_id}
                    for basis_id, omega_id in self.auth_set
                ],
            },
            "Residual": [residual.to_dict() for residual in self.residuals],
            "SafetyLevel": dict(self.safety),
            "Freshness": self.freshness,
            "ContextScope": self.context_scope,
            "RIDMatProps": _json_value(self.rid_mat_props),
            "Recoverability": [
                witness.to_dict() for witness in self.recoverability
            ],
            "BranchLineage": self.branch_lineage,
            "PhysProps": _json_value(self.phys_props),
        }


def _tuple_of_str(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)):
        return (str(value),)
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    return (str(value),)


def _strict_keys(
    payload: Mapping[str, Any],
    expected: set[str],
    *,
    label: str,
) -> None:
    actual = set(payload)
    if actual != expected:
        raise ValueError(
            f"{label} schema mismatch; "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )


def _strict_non_empty_string(
    payload: Mapping[str, Any],
    key: str,
    *,
    label: str,
) -> str:
    value = payload[key]
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label}.{key} must be a non-empty string")
    return value


def _strict_string_list(
    payload: Mapping[str, Any],
    key: str,
    *,
    label: str,
    canonical_set: bool,
) -> tuple[str, ...]:
    value = payload[key]
    if not isinstance(value, list):
        raise ValueError(f"{label}.{key} must be a JSON list")
    if any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{label}.{key} must contain non-empty strings")
    items = tuple(value)
    if len(set(items)) != len(items):
        raise ValueError(f"{label}.{key} contains duplicate entries")
    if canonical_set and items != tuple(sorted(items)):
        raise ValueError(f"{label}.{key} is not in canonical order")
    return items


def need_from_dict(payload: Mapping[str, Any] | None) -> Need:
    if not isinstance(payload, Mapping):
        raise ValueError("Residual.need must be a mapping")
    data = payload
    fields = {
        "attrs",
        "rids",
        "ctx_keys",
        "trusted_reads",
        "freshness_evidence",
        "lineage_carriers",
    }
    _strict_keys(data, fields, label="Residual.need")
    return Need(
        attrs=_strict_string_list(
            data, "attrs", label="Residual.need", canonical_set=False
        ),
        rids=_strict_string_list(
            data, "rids", label="Residual.need", canonical_set=False
        ),
        ctx_keys=_strict_string_list(
            data, "ctx_keys", label="Residual.need", canonical_set=False
        ),
        trusted_reads=_strict_string_list(
            data, "trusted_reads", label="Residual.need", canonical_set=False
        ),
        freshness_evidence=_strict_string_list(
            data,
            "freshness_evidence",
            label="Residual.need",
            canonical_set=False,
        ),
        lineage_carriers=_strict_string_list(
            data,
            "lineage_carriers",
            label="Residual.need",
            canonical_set=False,
        ),
    )


def _rid_carrier_binding_from_dict(payload: Any) -> RIDCarrierBinding:
    label = "Recoverability.context.rid_carrier"
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be a mapping")
    _strict_keys(
        payload,
        {"logical_rid", "physical_carrier", "rid_domain_id"},
        label=label,
    )
    return RIDCarrierBinding(
        logical_rid=_strict_non_empty_string(
            payload, "logical_rid", label=label
        ),
        physical_carrier=_strict_non_empty_string(
            payload, "physical_carrier", label=label
        ),
        rid_domain_id=_strict_non_empty_string(
            payload, "rid_domain_id", label=label
        ),
    )


def _lineage_carrier_binding_from_dict(
    payload: Any,
) -> LineageCarrierBinding:
    label = "Recoverability.context.lineage_carrier"
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be a mapping")
    _strict_keys(
        payload,
        {"logical_carrier", "physical_carrier"},
        label=label,
    )
    return LineageCarrierBinding(
        logical_carrier=_strict_non_empty_string(
            payload, "logical_carrier", label=label
        ),
        physical_carrier=_strict_non_empty_string(
            payload, "physical_carrier", label=label
        ),
    )


def recoverability_context_from_dict(
    payload: Any,
) -> RecoverabilityContext:
    label = "Recoverability.context"
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be a mapping")
    fields = {
        "visible_attrs",
        "hidden_carriers",
        "rid_carriers",
        "lineage_carriers",
        "available_context_keys",
        "trusted_read_facts",
        "freshness_facts",
        "gamma_snapshot_id",
        "evidence_mode",
    }
    _strict_keys(payload, fields, label=label)
    raw_rids = payload["rid_carriers"]
    raw_lineage = payload["lineage_carriers"]
    if not isinstance(raw_rids, list) or not isinstance(raw_lineage, list):
        raise ValueError(f"{label} carrier bindings must be JSON lists")
    rid_carriers = tuple(_rid_carrier_binding_from_dict(item) for item in raw_rids)
    lineage_carriers = tuple(
        _lineage_carrier_binding_from_dict(item) for item in raw_lineage
    )
    if rid_carriers != tuple(sorted(set(rid_carriers))):
        raise ValueError(f"{label}.rid_carriers is not canonical")
    if lineage_carriers != tuple(sorted(set(lineage_carriers))):
        raise ValueError(f"{label}.lineage_carriers is not canonical")
    return RecoverabilityContext(
        visible_attrs=frozenset(
            _strict_string_list(
                payload,
                "visible_attrs",
                label=label,
                canonical_set=True,
            )
        ),
        hidden_carriers=frozenset(
            _strict_string_list(
                payload,
                "hidden_carriers",
                label=label,
                canonical_set=True,
            )
        ),
        rid_carriers=rid_carriers,
        lineage_carriers=lineage_carriers,
        available_context_keys=frozenset(
            _strict_string_list(
                payload,
                "available_context_keys",
                label=label,
                canonical_set=True,
            )
        ),
        trusted_read_facts=frozenset(
            _strict_string_list(
                payload,
                "trusted_read_facts",
                label=label,
                canonical_set=True,
            )
        ),
        freshness_facts=frozenset(
            _strict_string_list(
                payload,
                "freshness_facts",
                label=label,
                canonical_set=True,
            )
        ),
        gamma_snapshot_id=_strict_non_empty_string(
            payload,
            "gamma_snapshot_id",
            label=label,
        ),
        evidence_mode=_strict_non_empty_string(
            payload,
            "evidence_mode",
            label=label,
        ),
    )


def recoverability_witness_from_dict(payload: Any) -> RecoverabilityWitness:
    label = "Recoverability.witness"
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must be a mapping")
    _strict_keys(
        payload,
        {
            "witness_id",
            "basis_id",
            "source_basis_id",
            "transport_path",
            "context",
        },
        label=label,
    )
    return RecoverabilityWitness(
        witness_id=_strict_non_empty_string(
            payload, "witness_id", label=label
        ),
        basis_id=_strict_non_empty_string(payload, "basis_id", label=label),
        source_basis_id=_strict_non_empty_string(
            payload, "source_basis_id", label=label
        ),
        transport_path=_strict_string_list(
            payload,
            "transport_path",
            label=label,
            canonical_set=False,
        ),
        context=recoverability_context_from_dict(payload["context"]),
    )


def basis_from_dict(payload: Mapping[str, Any]) -> BasisElement:
    basis_id = str(payload.get("basis_id") or "")
    occurrence_id = str(payload.get("occurrence_id") or "")
    relation = str(payload.get("relation") or "")
    if not basis_id:
        basis_id = f"{occurrence_id}:out" if occurrence_id else f"{relation}:out"
    return BasisElement(
        basis_id=basis_id,
        kind=str(payload.get("kind") or "output_tuples"),
        occurrence_id=occurrence_id,
        relation=relation,
    )


def residual_from_dict(payload: Mapping[str, Any]) -> ResidualRecord:
    label = "Residual"
    _strict_keys(
        payload,
        {
            "basis_id",
            "omega_id",
            "check_id",
            "need",
            "deadline",
            "recoverability_witness_id",
            "gamma_snapshot_id",
            "rid_domain_id",
        },
        label=label,
    )
    return ResidualRecord(
        basis_id=_strict_non_empty_string(payload, "basis_id", label=label),
        omega_id=_strict_non_empty_string(payload, "omega_id", label=label),
        check_id=_strict_non_empty_string(payload, "check_id", label=label),
        need=need_from_dict(payload["need"]),
        deadline=_strict_non_empty_string(payload, "deadline", label=label),
        recoverability_witness_id=_strict_non_empty_string(
            payload,
            "recoverability_witness_id",
            label=label,
        ),
        gamma_snapshot_id=_strict_non_empty_string(
            payload,
            "gamma_snapshot_id",
            label=label,
        ),
        rid_domain_id=_strict_non_empty_string(
            payload,
            "rid_domain_id",
            label=label,
        ),
    )


def sigma_from_dict(payload: Mapping[str, Any]) -> Sigma:
    dom_raw = payload.get("Dom") or []
    if isinstance(dom_raw, Mapping):
        dom = (basis_from_dict(dom_raw),)
    elif isinstance(dom_raw, (list, tuple)):
        dom = tuple(
            basis_from_dict(item)
            for item in dom_raw
            if isinstance(item, Mapping)
        )
    else:
        dom = ()

    auth_raw = payload.get("AuthSet")
    auth_summary = "unknown"
    auth_pairs: tuple[tuple[str, str], ...] = ()
    if isinstance(auth_raw, Mapping):
        auth_summary = str(auth_raw.get("summary") or "unknown")
        pairs = auth_raw.get("pairs") or []
        if isinstance(pairs, (list, tuple)):
            auth_pairs = tuple(
                (
                    str(pair.get("basis_id") or ""),
                    str(pair.get("omega_id") or ""),
                )
                for pair in pairs
                if isinstance(pair, Mapping)
            )
    elif isinstance(auth_raw, str):
        auth_summary = auth_raw
        if dom and auth_raw:
            auth_pairs = ((dom[0].basis_id, auth_raw),)

    live_raw = payload.get("Live") or {}
    live: Mapping[str, tuple[str, ...]]
    if isinstance(live_raw, Mapping):
        live = {str(key): _tuple_of_str(value) for key, value in live_raw.items()}
    elif auth_pairs:
        grouped: dict[str, list[str]] = {}
        for basis_id, omega_id in auth_pairs:
            grouped.setdefault(basis_id, []).append(omega_id)
        live = {basis_id: tuple(omega_ids) for basis_id, omega_ids in grouped.items()}
    else:
        live = {}

    residuals_raw = payload.get("Residual")
    if not isinstance(residuals_raw, list):
        raise ValueError("Sigma.Residual must be a JSON list")
    if any(not isinstance(item, Mapping) for item in residuals_raw):
        raise ValueError("Sigma.Residual entries must be mappings")
    residuals = tuple(residual_from_dict(item) for item in residuals_raw)

    safety_raw = payload.get("SafetyLevel") or {}
    if isinstance(safety_raw, Mapping):
        safety = {str(key): str(value) for key, value in safety_raw.items()}
    elif dom:
        safety = {basis.basis_id: str(safety_raw) for basis in dom}
    else:
        safety = {}

    rid_mat_props = payload.get("RIDMatProps") or {}
    recoverability_raw = payload.get("Recoverability")
    if not isinstance(recoverability_raw, list):
        raise ValueError("Sigma.Recoverability must be a JSON list")
    recoverability = tuple(
        recoverability_witness_from_dict(item)
        for item in recoverability_raw
    )
    canonical_recoverability = tuple(
        sorted(
            recoverability,
            key=lambda item: (item.basis_id, item.witness_id),
        )
    )
    if recoverability != canonical_recoverability:
        raise ValueError("Sigma.Recoverability is not in canonical order")
    if len({item.witness_id for item in recoverability}) != len(recoverability):
        raise ValueError("Sigma.Recoverability has duplicate witness identities")
    basis_ids = {basis.basis_id for basis in dom}
    if any(item.basis_id not in basis_ids for item in recoverability):
        raise ValueError("Sigma.Recoverability references an unknown basis")
    witness_by_id = {item.witness_id: item for item in recoverability}
    for residual in residuals:
        witness = witness_by_id.get(residual.recoverability_witness_id)
        if witness is None or witness.basis_id != residual.basis_id:
            raise ValueError(
                "Sigma residual recoverability witness reference is invalid"
            )
    referenced_witness_ids = {
        residual.recoverability_witness_id for residual in residuals
    }
    if any(
        witness.witness_id not in referenced_witness_ids
        for witness in recoverability
    ):
        raise ValueError("Sigma.Recoverability contains an unreferenced witness")
    phys_props = _canonical_phys_props(payload.get("PhysProps", {}))
    return Sigma(
        dom=dom,
        live=live,
        auth_set=auth_pairs,
        auth_summary=auth_summary,
        residuals=residuals,
        safety=safety,
        freshness=str(payload.get("Freshness") or "unknown"),
        context_scope=str(payload.get("ContextScope") or "unknown"),
        rid_mat_props=dict(rid_mat_props) if isinstance(rid_mat_props, Mapping) else {},
        recoverability=recoverability,
        # PhysProps is deliberately JSON-like.  Typed transfer consumers read
        # its finite sequences without imposing a Python tuple/list identity.
        phys_props=phys_props,
        branch_lineage=str(payload.get("BranchLineage") or "unknown"),
    )


def structured_sigma(
    *,
    relation: str,
    occurrence_id: str,
    rid_col: str,
    policy_id: str,
    template_id: str,
    auth_summary: str,
    freshness: str,
    context_scope: str,
    safety_level: str,
    required_attrs: tuple[str, ...] = (),
    required_ctx: tuple[str, ...] = (),
    required_lineage: tuple[str, ...] = (),
    residual_deadline: Optional[str] = None,
    branch_lineage: str = "preserved",
    required_order: tuple[str, ...] = (),
    delivered_order: tuple[str, ...] = (),
    trusted_reads: tuple[str, ...] | None = None,
    freshness_evidence: tuple[str, ...] | None = None,
    gamma_snapshot_id: str = "legacy-diagnostic:unbound",
    recoverability_evidence_mode: str = "legacy_diagnostic",
) -> Sigma:
    basis = BasisElement(
        basis_id=f"{occurrence_id}:out",
        kind="output_tuples",
        occurrence_id=occurrence_id,
        relation=relation,
    )
    auth_pairs: tuple[tuple[str, str], ...] = ()
    if auth_summary in {"exact", "artifact_exact", "engine_exact"}:
        auth_pairs = ((basis.basis_id, f"{policy_id}:exact"),)
    elif auth_summary == "candidate":
        auth_pairs = ((basis.basis_id, f"{policy_id}:complete_candidate"),)

    actual_trusted_reads = (
        (policy_id,) if trusted_reads is None else tuple(trusted_reads)
    )
    actual_freshness_evidence = (
        (() if freshness.startswith("non_artifact") else (freshness,))
        if freshness_evidence is None
        else tuple(freshness_evidence)
    )
    residuals: tuple[ResidualRecord, ...] = ()
    recoverability: tuple[RecoverabilityWitness, ...] = ()
    if residual_deadline is not None:
        rid_domain_id = f"{relation}.{rid_col}"
        context = RecoverabilityContext(
            visible_attrs=frozenset((*required_attrs, rid_col)),
            hidden_carriers=frozenset({"__rid"}),
            rid_carriers=(
                RIDCarrierBinding(rid_col, rid_col, rid_domain_id),
                RIDCarrierBinding(rid_col, "__rid", rid_domain_id),
            ),
            # A leaf does not invent a physical branch tag.  Controlled union
            # transfer is the constructor that may add that binding.
            lineage_carriers=(),
            available_context_keys=frozenset(required_ctx),
            trusted_read_facts=frozenset(actual_trusted_reads),
            freshness_facts=frozenset(actual_freshness_evidence),
            gamma_snapshot_id=gamma_snapshot_id,
            evidence_mode=recoverability_evidence_mode,
        )
        witness = RecoverabilityWitness.derive(
            basis_id=basis.basis_id,
            source_basis_id=basis.basis_id,
            transport_path=("leaf",),
            context=context,
        )
        recoverability = (witness,)
        residuals = (
            ResidualRecord(
                basis_id=basis.basis_id,
                omega_id=f"{policy_id}:exact_residual",
                check_id=f"{policy_id}:exact_residual",
                need=Need(
                    attrs=required_attrs,
                    rids=(rid_col,),
                    ctx_keys=required_ctx,
                    trusted_reads=actual_trusted_reads,
                    freshness_evidence=actual_freshness_evidence,
                    lineage_carriers=required_lineage,
                ),
                deadline=residual_deadline,
                recoverability_witness_id=witness.witness_id,
                gamma_snapshot_id=gamma_snapshot_id,
                rid_domain_id=rid_domain_id,
            ),
        )

    return Sigma(
        dom=(basis,),
        live={basis.basis_id: tuple(omega_id for _basis, omega_id in auth_pairs)},
        auth_set=auth_pairs,
        auth_summary=auth_summary,
        residuals=residuals,
        safety={basis.basis_id: safety_level},
        freshness=freshness,
        context_scope=context_scope,
        rid_mat_props={
            "rid_domain": f"{relation}.{rid_col}",
            "surrogate_col": rid_col,
            "carrier": "__rid",
        },
        recoverability=recoverability,
        phys_props={
            "template_id": template_id,
            # ``required_attrs`` is the typed output demand propagated from
            # root rho.  A leaf promises only this explicit set; callers must
            # not infer arbitrary base-table columns after a projection.
            "visible_attrs": list(required_attrs),
            "hidden_attrs": [],
            "required_order": list(required_order),
            "delivered_order": list(delivered_order),
            "context_keys": list(required_ctx),
            "trusted_reads": list(actual_trusted_reads),
            "freshness_evidence": list(actual_freshness_evidence),
            "gamma_snapshot_id": gamma_snapshot_id,
            "recoverability_evidence_mode": recoverability_evidence_mode,
        },
        branch_lineage=branch_lineage,
    )
