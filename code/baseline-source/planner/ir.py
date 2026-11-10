"""Plan-tree IR nodes for the finite CAPRLS planning fragment."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal, Mapping, Union


SelectKind = Literal[
    "logical_target",
    "necessary_safe_reducer",
    "leakproof_only",
    "unsafe",
]

BoundaryKind = Literal[
    "aggregation",
    "distinct",
    "limit",
    "window",
    "final_projection",
    "unsafe",
    "duplicate_collapse",
]


@dataclass(frozen=True)
class ScanProtected:
    occurrence_id: str
    template_slot: str

    def children(self) -> tuple["PlanNode", ...]:
        return ()

    def to_dict(self) -> dict[str, Any]:
        return {"node": "ScanProtected", **asdict(self)}


@dataclass(frozen=True)
class ScanOrdinary:
    rel: str

    def children(self) -> tuple["PlanNode", ...]:
        return ()

    def to_dict(self) -> dict[str, Any]:
        return {"node": "ScanOrdinary", **asdict(self)}


@dataclass(frozen=True)
class Select:
    source: "PlanNode"
    pred: str
    pred_kind: SelectKind
    expr_label: str = ""

    def children(self) -> tuple["PlanNode", ...]:
        return (self.source,)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node": "Select",
            "pred": self.pred,
            "pred_kind": self.pred_kind,
            "expr_label": self.expr_label,
            "source": self.source.to_dict(),
        }


@dataclass(frozen=True)
class Project:
    source: "PlanNode"
    visible_A: tuple[str, ...] = ()
    hidden_H: tuple[str, ...] = ()

    def children(self) -> tuple["PlanNode", ...]:
        return (self.source,)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node": "Project",
            "visible_A": list(self.visible_A),
            "hidden_H": list(self.hidden_H),
            "source": self.source.to_dict(),
        }


@dataclass(frozen=True)
class InnerJoin:
    left: "PlanNode"
    right: "PlanNode"
    theta: str = ""
    theta_label: str = ""

    def children(self) -> tuple["PlanNode", ...]:
        return (self.left, self.right)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node": "InnerJoin",
            "theta": self.theta,
            "theta_label": self.theta_label,
            "left": self.left.to_dict(),
            "right": self.right.to_dict(),
        }


@dataclass(frozen=True)
class UnionTagged:
    branches: tuple["PlanNode", ...]
    branch_tag: str

    def children(self) -> tuple["PlanNode", ...]:
        return self.branches

    def to_dict(self) -> dict[str, Any]:
        return {
            "node": "UnionTagged",
            "branch_tag": self.branch_tag,
            "branches": [branch.to_dict() for branch in self.branches],
        }


@dataclass(frozen=True)
class DuplicateCollapse:
    source: "PlanNode"
    trusted_surrogate: bool = False
    lifted_equivalence: bool = False
    gamma_fact: str = ""

    def children(self) -> tuple["PlanNode", ...]:
        return (self.source,)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node": "DuplicateCollapse",
            "trusted_surrogate": self.trusted_surrogate,
            "lifted_equivalence": self.lifted_equivalence,
            "gamma_fact": self.gamma_fact,
            "source": self.source.to_dict(),
        }


@dataclass(frozen=True)
class UnsafeExpr:
    source: "PlanNode"
    expr_label: str

    def children(self) -> tuple["PlanNode", ...]:
        return (self.source,)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node": "UnsafeExpr",
            "expr_label": self.expr_label,
            "source": self.source.to_dict(),
        }


@dataclass(frozen=True)
class Boundary:
    source: "PlanNode"
    kind: BoundaryKind

    def children(self) -> tuple["PlanNode", ...]:
        return (self.source,)

    def to_dict(self) -> dict[str, Any]:
        return {"node": "Boundary", "kind": self.kind, "source": self.source.to_dict()}


@dataclass(frozen=True)
class RCheck:
    source: "PlanNode"
    residual_id: str

    def children(self) -> tuple["PlanNode", ...]:
        return (self.source,)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node": "RCheck",
            "residual_id": self.residual_id,
            "source": self.source.to_dict(),
        }


@dataclass(frozen=True)
class BarrierEnforce:
    source: "PlanNode"

    def children(self) -> tuple["PlanNode", ...]:
        return (self.source,)

    def to_dict(self) -> dict[str, Any]:
        return {"node": "BarrierEnforce", "source": self.source.to_dict()}


@dataclass(frozen=True)
class ValidationGate:
    source: "PlanNode"
    artifact_id: str

    def children(self) -> tuple["PlanNode", ...]:
        return (self.source,)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node": "ValidationGate",
            "artifact_id": self.artifact_id,
            "source": self.source.to_dict(),
        }


@dataclass(frozen=True)
class SortEnforce:
    source: "PlanNode"
    keys: tuple[str, ...]

    def children(self) -> tuple["PlanNode", ...]:
        return (self.source,)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node": "SortEnforce",
            "keys": list(self.keys),
            "source": self.source.to_dict(),
        }


@dataclass(frozen=True)
class Materialize:
    source: "PlanNode"

    def children(self) -> tuple["PlanNode", ...]:
        return (self.source,)

    def to_dict(self) -> dict[str, Any]:
        return {"node": "Materialize", "source": self.source.to_dict()}


@dataclass(frozen=True)
class Root:
    source: "PlanNode"
    rho_root: Mapping[str, Any] = field(default_factory=dict)

    def children(self) -> tuple["PlanNode", ...]:
        return (self.source,)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node": "Root",
            "rho_root": dict(self.rho_root),
            "source": self.source.to_dict(),
        }


PlanNode = Union[
    ScanProtected,
    ScanOrdinary,
    Select,
    Project,
    InnerJoin,
    UnionTagged,
    DuplicateCollapse,
    UnsafeExpr,
    Boundary,
    RCheck,
    BarrierEnforce,
    ValidationGate,
    SortEnforce,
    Materialize,
    Root,
]


def walk(node: PlanNode) -> tuple[PlanNode, ...]:
    """Return a preorder traversal for tests, memo accounting, and emitters."""

    nodes: list[PlanNode] = [node]
    for child in node.children():
        nodes.extend(walk(child))
    return tuple(nodes)
