"""Template semantic contracts for the finite CAPRLS planner fragment.

The actual catalog lives in :mod:`planner.contracts`.  This module preserves
the small κ API used by the planner and tests while preventing semantic drift
between the planner registry and the theorem-facing contract table.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from .contracts import template_definition, template_kappa_contracts


@dataclass(frozen=True)
class TargetSpec:
    kind: str
    occurrence_id: str
    relation: str
    policy_id: str
    refinement_predicate: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "occurrence_id": self.occurrence_id,
            "relation": self.relation,
            "policy_id": self.policy_id,
            "refinement_predicate": self.refinement_predicate,
        }


@dataclass(frozen=True)
class ResidualSpec:
    kind: str
    check_id: str
    required_attrs: tuple[str, ...] = ()
    required_ctx: tuple[str, ...] = ()
    deadline: str = "parent_transparent_boundary"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "check_id": self.check_id,
            "required_attrs": list(self.required_attrs),
            "required_ctx": list(self.required_ctx),
            "deadline": self.deadline,
        }


@dataclass(frozen=True)
class KappaSem:
    target: TargetSpec
    pre: tuple[str, ...]
    guarantee: str
    residual: Optional[ResidualSpec]
    safety: str
    freshness: str
    physprops: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "pre": list(self.pre),
            "guarantee": self.guarantee,
            "residual": None if self.residual is None else self.residual.to_dict(),
            "safety": self.safety,
            "freshness": self.freshness,
            "physprops": dict(self.physprops),
        }


def kappa_sem_for_template(
    template_id: str,
    *,
    relation: str,
    policy_id: str,
    occurrence_id: str,
    required_attrs: tuple[str, ...] = (),
    required_ctx: tuple[str, ...] = (),
    residual_deadline: str = "parent_transparent_boundary",
) -> KappaSem:
    try:
        definition = template_definition(template_id)
    except KeyError as exc:
        raise KeyError(f"unknown template semantic contract: {template_id}") from exc

    residual = None
    if definition.residual_kind:
        residual = ResidualSpec(
            kind=definition.residual_kind,
            check_id=f"{policy_id}:exact_residual",
            required_attrs=required_attrs,
            required_ctx=required_ctx,
            deadline=residual_deadline,
        )
    return KappaSem(
        target=TargetSpec(
            kind=definition.target_kind,
            occurrence_id=occurrence_id,
            relation=relation,
            policy_id=policy_id,
            refinement_predicate=definition.refinement_predicate,
        ),
        pre=tuple(definition.pre),
        guarantee=definition.guarantee,
        residual=residual,
        safety=definition.safety,
        freshness=definition.freshness,
        physprops=dict(definition.physprops),
    )


def template_kappa_table() -> Mapping[str, Mapping[str, Any]]:
    return template_kappa_contracts()
