"""Immutable, pre-candidate root obligations for the finite CAPRLS IR.

The graph is built from logical occurrences before leaf alternatives and
transfer run.  Root closure therefore cannot recover its requirements from a
candidate's final ``Sigma`` after a buggy transfer erased both evidence and
the apparent requirement.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from .ir import InnerJoin, PlanNode, ScanProtected, UnionTagged


_ROOT_SEQUENCE_FIELDS = frozenset(
    {
        "visible_columns",
        "required_order",
        "licensed_refinements",
        "allowed_enforcers",
        "observable_coverage",
        "required_ctx",
    }
)
_ROOT_BOOL_FIELDS = frozenset(
    {
        "residual_allowed",
        "transparent",
        "unsafe_expression_boundary",
        "needs_branch_lineage",
        "future_rid_intersection",
    }
)
_ROOT_OPTIONAL_STRING_FIELDS = frozenset(
    {
        "logical_group_id",
        "freshness_predicate",
        "context_predicate",
    }
)
_ROOT_STRING_FIELDS = frozenset({"residual_deadline", "min_safety_level"})
_ROOT_RHO_FIELDS = (
    _ROOT_SEQUENCE_FIELDS
    | _ROOT_BOOL_FIELDS
    | _ROOT_OPTIONAL_STRING_FIELDS
    | _ROOT_STRING_FIELDS
)
_FINITE_ENFORCERS = frozenset(
    {"residual_check", "validation_gate", "sort", "materialize"}
)
_FINITE_SAFETY_LEVELS = frozenset(
    {
        "unsafe_before_authorization",
        "candidate",
        "candidate_authorized",
        "candidate_until_residual_discharge",
        "engine_authorized",
        "exact_authorized",
    }
)


def canonical_root_observables(
    root_observables: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Copy and validate the finite root-rho JSON-like schema.

    Lists and tuples are equivalent input spellings and are frozen to tuples.
    No nested or open-ended obligation language is inferred here; a future
    richer model must add an explicit typed field instead of passing through
    an unknown value.
    """

    if root_observables is None:
        return {}
    if not isinstance(root_observables, Mapping):
        raise TypeError("root observables must be a mapping")
    raw_keys = tuple(root_observables.keys())
    if any(not isinstance(key, str) or not key for key in raw_keys):
        raise ValueError("root observable field names must be nonempty strings")
    if len(raw_keys) != len(set(raw_keys)):
        raise ValueError("duplicate root observable field identity")
    unknown = set(raw_keys) - _ROOT_RHO_FIELDS
    if unknown:
        raise ValueError(
            "unsupported finite root observable fields: "
            + ",".join(sorted(unknown))
        )

    canonical: dict[str, Any] = {}
    for key in sorted(raw_keys):
        value = root_observables[key]
        if key in _ROOT_SEQUENCE_FIELDS:
            if not isinstance(value, (list, tuple)):
                raise TypeError(f"root observable {key} must be a list/tuple of strings")
            items = tuple(value)
            if any(not isinstance(item, str) or not item for item in items):
                raise ValueError(
                    f"root observable {key} must contain nonempty strings"
                )
            if len(items) != len(set(items)):
                raise ValueError(f"root observable {key} contains duplicate identity")
            if key == "allowed_enforcers" and set(items) - _FINITE_ENFORCERS:
                raise ValueError("root observable allowed_enforcers is unsupported")
            if key == "observable_coverage":
                for item in items:
                    if item == "materialized":
                        continue
                    if item.startswith("hidden_carrier:") and item.split(":", 1)[1]:
                        continue
                    if item.startswith("branch_tag:") and re.fullmatch(
                        r"[a-z_][a-z0-9_]*", item.split(":", 1)[1]
                    ):
                        continue
                    raise ValueError(
                        "root observable coverage is outside the finite model"
                    )
            canonical[key] = items
            continue
        if key in _ROOT_BOOL_FIELDS:
            if not isinstance(value, bool):
                raise TypeError(f"root observable {key} must be bool")
            canonical[key] = value
            continue
        if key in _ROOT_OPTIONAL_STRING_FIELDS:
            if value is not None and (
                not isinstance(value, str) or not value
            ):
                raise ValueError(
                    f"root observable {key} must be null or a nonempty string"
                )
            canonical[key] = value
            continue
        if not isinstance(value, str) or not value:
            raise ValueError(f"root observable {key} must be a nonempty string")
        if key == "min_safety_level" and value not in _FINITE_SAFETY_LEVELS:
            raise ValueError("root observable min_safety_level is unsupported")
        canonical[key] = value
    return canonical


def _digest(payload: Any) -> str:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class LogicalBasis:
    occurrence_id: str
    basis_id: str
    relation: str
    policy_id: str


@dataclass(frozen=True)
class LogicalObligation:
    basis_id: str
    omega_id: str
    source_occurrence_id: str


@dataclass(frozen=True)
class ResidualDeadline:
    occurrence_id: str
    policy_id: str
    deadline: str
    allowed_enforcers: tuple[str, ...]

    def __post_init__(self) -> None:
        if any(
            not isinstance(value, str) or not value
            for value in (self.occurrence_id, self.policy_id, self.deadline)
        ):
            raise ValueError("ResidualDeadline requires complete string identity")
        if not isinstance(self.allowed_enforcers, (list, tuple)):
            raise TypeError("ResidualDeadline enforcers must be a list/tuple")
        values = tuple(self.allowed_enforcers)
        if any(not isinstance(value, str) or not value for value in values):
            raise ValueError("ResidualDeadline enforcers must be nonempty strings")
        if len(values) != len(set(values)):
            raise ValueError("ResidualDeadline contains duplicate enforcers")
        if set(values) - _FINITE_ENFORCERS:
            raise ValueError("ResidualDeadline contains an unsupported enforcer")
        object.__setattr__(
            self, "allowed_enforcers", tuple(sorted(values))
        )


@dataclass(frozen=True)
class LineageTransform:
    """One pre-candidate transform authorized for one logical occurrence.

    A tag/product-looking string cannot authorize itself: it must map to the
    exact protected occurrence, operator path and (for a union) branch index
    discovered from the logical IR before alternative enumeration.
    """

    occurrence_id: str
    logical_basis_id: str
    kind: str
    operator_path: tuple[str, ...]
    join_side: str = ""
    branch_tag: str = ""
    branch_index: int | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.occurrence_id, str)
            or not self.occurrence_id
            or not isinstance(self.logical_basis_id, str)
            or not self.logical_basis_id
        ):
            raise ValueError("LineageTransform requires occurrence and logical basis identity")
        if self.kind not in {"join_product", "union_tag"}:
            raise ValueError("LineageTransform kind is unsupported")
        if not isinstance(self.operator_path, (list, tuple)):
            raise TypeError("LineageTransform operator path must be a list/tuple")
        path = tuple(self.operator_path)
        if (
            not path
            or path[0] != "root"
            or any(
                not isinstance(item, str)
                or not item
                or (
                    item not in (
                        {"root"} if index == 0 else {"source", "left", "right"}
                    )
                    and re.fullmatch(r"branches\[[0-9]+\]", item) is None
                )
                for index, item in enumerate(path)
            )
        ):
            raise ValueError("LineageTransform requires a nonempty operator path")
        object.__setattr__(self, "operator_path", path)
        if self.kind == "union_tag":
            if self.join_side:
                raise ValueError("union LineageTransform cannot carry a join side")
            if (
                not isinstance(self.branch_tag, str)
                or re.fullmatch(r"[a-z_][a-z0-9_]*", self.branch_tag) is None
                or not isinstance(self.branch_index, int)
                or isinstance(self.branch_index, bool)
                or self.branch_index < 0
            ):
                raise ValueError("union LineageTransform requires tag and nonnegative branch index")
        else:
            if self.join_side not in {"left", "right"}:
                raise ValueError("join LineageTransform requires an exact left/right side")
            if self.branch_tag or self.branch_index is not None:
                raise ValueError("join LineageTransform cannot carry a union branch")

    @property
    def token(self) -> str:
        if self.kind == "join_product":
            return f"join:{self.join_side}"
        return f"union:{self.branch_tag}:{self.branch_index}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "occurrence_id": self.occurrence_id,
            "logical_basis_id": self.logical_basis_id,
            "kind": self.kind,
            "operator_path": list(self.operator_path),
            "join_side": self.join_side,
            "branch_tag": self.branch_tag,
            "branch_index": self.branch_index,
        }


@dataclass(frozen=True)
class ObligationGraph:
    logical_basis: tuple[LogicalBasis, ...]
    required_live_pairs: tuple[LogicalObligation, ...]
    residual_deadlines: tuple[ResidualDeadline, ...] = ()
    lineage_transforms: tuple[LineageTransform, ...] = ()
    root_observables: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "logical_basis", tuple(self.logical_basis))
        object.__setattr__(self, "required_live_pairs", tuple(self.required_live_pairs))
        object.__setattr__(self, "residual_deadlines", tuple(self.residual_deadlines))
        object.__setattr__(self, "lineage_transforms", tuple(self.lineage_transforms))
        canonical_root = canonical_root_observables(self.root_observables)
        object.__setattr__(
            self,
            "root_observables",
            MappingProxyType(canonical_root),
        )
        if any(not isinstance(item, LogicalBasis) for item in self.logical_basis):
            raise TypeError("ObligationGraph logical basis entries must be LogicalBasis values")
        for basis in self.logical_basis:
            if any(
                not isinstance(value, str) or not value
                for value in (
                    basis.occurrence_id,
                    basis.basis_id,
                    basis.relation,
                    basis.policy_id,
                )
            ):
                raise ValueError("ObligationGraph logical basis identity is incomplete")
        occurrence_ids = [basis.occurrence_id for basis in self.logical_basis]
        if not occurrence_ids:
            raise ValueError("ObligationGraph requires a logical basis")
        if len(occurrence_ids) != len(set(occurrence_ids)):
            raise ValueError("ObligationGraph requires unique logical occurrence IDs")
        basis_ids = [basis.basis_id for basis in self.logical_basis]
        if len(basis_ids) != len(set(basis_ids)):
            raise ValueError("ObligationGraph requires unique logical basis IDs")
        if any(
            basis.basis_id != f"{basis.occurrence_id}:out"
            for basis in self.logical_basis
        ):
            raise ValueError(
                "ObligationGraph logical basis is not the finite canonical occurrence output"
            )
        if any(
            not isinstance(item, LogicalObligation)
            for item in self.required_live_pairs
        ):
            raise TypeError(
                "ObligationGraph live obligations must be LogicalObligation values"
            )
        for item in self.required_live_pairs:
            if any(
                not isinstance(value, str) or not value
                for value in (
                    item.basis_id,
                    item.omega_id,
                    item.source_occurrence_id,
                )
            ):
                raise ValueError("ObligationGraph live obligation identity is incomplete")
        pairs = [(item.basis_id, item.omega_id) for item in self.required_live_pairs]
        if len(pairs) != len(set(pairs)):
            raise ValueError("ObligationGraph contains duplicate required live pairs")
        obligations_by_basis: dict[str, list[LogicalObligation]] = {}
        for item in self.required_live_pairs:
            obligations_by_basis.setdefault(item.basis_id, []).append(item)
        unknown_obligation_basis = set(obligations_by_basis) - set(basis_ids)
        if unknown_obligation_basis:
            raise ValueError("ObligationGraph live obligation references an unknown logical basis")
        missing_obligation_basis = set(basis_ids) - set(obligations_by_basis)
        if missing_obligation_basis:
            raise ValueError(
                "ObligationGraph is missing a required live obligation"
            )
        if any(len(items) != 1 for items in obligations_by_basis.values()):
            raise ValueError(
                "ObligationGraph requires exactly one finite live obligation per basis"
            )
        basis_by_id = {basis.basis_id: basis for basis in self.logical_basis}
        for basis_id, items in obligations_by_basis.items():
            basis = basis_by_id[basis_id]
            obligation = items[0]
            if obligation.source_occurrence_id != basis.occurrence_id:
                raise ValueError(
                    "ObligationGraph live obligation source occurrence mismatch"
                )
            if obligation.omega_id != f"{basis.policy_id}:exact":
                raise ValueError(
                    "ObligationGraph live obligation is not the finite exact omega"
                )
        if any(
            not isinstance(item, ResidualDeadline)
            for item in self.residual_deadlines
        ):
            raise TypeError(
                "ObligationGraph residual deadlines must be ResidualDeadline values"
            )
        deadline_occurrences = [
            item.occurrence_id for item in self.residual_deadlines
        ]
        if len(deadline_occurrences) != len(set(deadline_occurrences)):
            raise ValueError("ObligationGraph contains duplicate residual deadlines")
        basis_by_occurrence = {
            basis.occurrence_id: basis for basis in self.logical_basis
        }
        for item in self.residual_deadlines:
            basis = basis_by_occurrence.get(item.occurrence_id)
            if basis is None or basis.policy_id != item.policy_id:
                raise ValueError(
                    "ObligationGraph residual deadline identity mismatch"
                )
        if any(not isinstance(item, LineageTransform) for item in self.lineage_transforms):
            raise TypeError("ObligationGraph lineage transforms must be LineageTransform values")
        transform_identities = [
            (
                item.occurrence_id,
                item.logical_basis_id,
                item.kind,
                item.operator_path,
                item.join_side,
                item.branch_tag,
                item.branch_index,
            )
            for item in self.lineage_transforms
        ]
        if len(transform_identities) != len(set(transform_identities)):
            raise ValueError("ObligationGraph contains duplicate lineage transforms")
        paths_by_basis: dict[str, set[tuple[str, ...]]] = {}
        for transform in self.lineage_transforms:
            if transform.logical_basis_id not in set(basis_ids):
                raise ValueError("LineageTransform references an unknown logical basis")
            matching_basis = next(
                basis for basis in self.logical_basis if basis.basis_id == transform.logical_basis_id
            )
            if matching_basis.occurrence_id != transform.occurrence_id:
                raise ValueError("LineageTransform occurrence does not match logical basis")
            paths = paths_by_basis.setdefault(transform.logical_basis_id, set())
            if transform.operator_path in paths:
                raise ValueError(
                    "ObligationGraph has ambiguous transforms at one operator path"
                )
            paths.add(transform.operator_path)
        # A branch can contain multiple protected scans, but reusing the same
        # tag name for distinct union operators would make SQL's tagged basis
        # spelling ambiguous.  Preserve the operator path in every record and
        # reject that ambiguous IR at graph construction time.
        tag_paths: dict[str, tuple[str, ...]] = {}
        for item in self.lineage_transforms:
            if item.kind != "union_tag":
                continue
            prior = tag_paths.setdefault(item.branch_tag, item.operator_path)
            if prior != item.operator_path:
                raise ValueError("union tags must be unique across logical IR paths")

    @property
    def digest(self) -> str:
        return _digest(self.to_dict())

    def transforms_for_basis(self, basis_id: str) -> tuple[LineageTransform, ...]:
        """Return the exact root-to-leaf transform chain for one basis."""

        return tuple(
            sorted(
                (
                    transform
                    for transform in self.lineage_transforms
                    if transform.logical_basis_id == basis_id
                ),
                key=lambda transform: (len(transform.operator_path), transform.operator_path),
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "logical_basis": [asdict(item) for item in self.logical_basis],
            "required_live_pairs": [asdict(item) for item in self.required_live_pairs],
            "residual_deadlines": [
                {
                    **asdict(item),
                    "allowed_enforcers": list(item.allowed_enforcers),
                }
                for item in self.residual_deadlines
            ],
            "lineage_transforms": [item.to_dict() for item in self.lineage_transforms],
            "root_observables": dict(self.root_observables),
        }


def build_obligation_graph(
    ir: PlanNode,
    occurrence_goals: Mapping[str, Any],
    *,
    root_observables: Mapping[str, Any] | None = None,
) -> ObligationGraph:
    """Build requirements from logical IR/goals before candidate enumeration."""

    occurrence_ids: list[str] = []
    occurrence_id_set: set[str] = set()
    transform_specs: list[tuple[str, str, tuple[str, ...], str, str, int | None]] = []
    protected_presence: dict[int, bool] = {}

    def contains_protected(node: PlanNode) -> bool:
        cached = protected_presence.get(id(node))
        if cached is not None:
            return cached
        present = isinstance(node, ScanProtected) or any(
            contains_protected(child) for child in node.children()
        )
        protected_presence[id(node)] = present
        return present

    def visit(
        node: PlanNode,
        *,
        path: tuple[str, ...],
        inherited: tuple[tuple[str, tuple[str, ...], str, str, int | None], ...],
    ) -> None:
        if isinstance(node, ScanProtected):
            if not isinstance(node.occurrence_id, str) or not node.occurrence_id:
                raise ValueError("protected scan occurrence identity is empty")
            if node.occurrence_id in occurrence_id_set:
                raise ValueError(
                    f"duplicate protected occurrence identity: {node.occurrence_id}"
                )
            occurrence_ids.append(node.occurrence_id)
            occurrence_id_set.add(node.occurrence_id)
            for kind, operator_path, join_side, branch_tag, branch_index in inherited:
                transform_specs.append(
                    (node.occurrence_id, kind, operator_path, join_side, branch_tag, branch_index)
                )
            return
        if isinstance(node, InnerJoin):
            both_protected = contains_protected(node.left) and contains_protected(
                node.right
            )
            left_inherited = inherited
            right_inherited = inherited
            if both_protected:
                left_inherited = (
                    *inherited,
                    ("join_product", path, "left", "", None),
                )
                right_inherited = (
                    *inherited,
                    ("join_product", path, "right", "", None),
                )
            visit(node.left, path=(*path, "left"), inherited=left_inherited)
            visit(node.right, path=(*path, "right"), inherited=right_inherited)
            return
        if isinstance(node, UnionTagged):
            protected_branches = tuple(
                contains_protected(branch) for branch in node.branches
            )
            if any(protected_branches) and not all(protected_branches):
                raise ValueError(
                    "mixed protected/ordinary union is outside the finite obligation model"
                )
            for index, branch in enumerate(node.branches):
                transform = ("union_tag", path, "", node.branch_tag, index)
                visit(
                    branch,
                    path=(*path, f"branches[{index}]"),
                    inherited=(
                        (*inherited, transform)
                        if protected_branches[index]
                        else inherited
                    ),
                )
            return
        children = node.children()
        if len(children) == 1:
            visit(children[0], path=(*path, "source"), inherited=inherited)
            return
        if len(children) == 0:
            return
        # The finite IR's only multi-child nodes are InnerJoin/UnionTagged;
        # reject silent traversal if a new shape is introduced.
        raise ValueError(f"unsupported logical IR shape in obligation graph: {node!r}")

    visit(ir, path=("root",), inherited=())
    if not occurrence_ids:
        raise ValueError("obligation graph requires a protected occurrence")
    if not isinstance(occurrence_goals, Mapping):
        raise TypeError("logical occurrence goals must be a mapping")
    goal_ids = tuple(occurrence_goals.keys())
    if any(not isinstance(item, str) or not item for item in goal_ids):
        raise ValueError("logical occurrence goal identity is invalid")
    if len(goal_ids) != len(set(goal_ids)):
        raise ValueError("duplicate logical occurrence goal identity")
    missing_goals = occurrence_id_set - set(goal_ids)
    extra_goals = set(goal_ids) - occurrence_id_set
    if missing_goals:
        raise ValueError(
            "missing logical occurrence goals: " + ",".join(sorted(missing_goals))
        )
    if extra_goals:
        raise ValueError(
            "extra logical occurrence goals: " + ",".join(sorted(extra_goals))
        )
    bases: list[LogicalBasis] = []
    live: list[LogicalObligation] = []
    deadlines: list[ResidualDeadline] = []
    for occurrence_id in occurrence_ids:
        goal = occurrence_goals.get(occurrence_id)
        if goal is None or not hasattr(goal, "problem"):
            raise ValueError(f"missing logical occurrence goal for {occurrence_id}")
        problem = goal.problem
        if getattr(problem, "occurrence_id", None) != occurrence_id:
            raise ValueError(
                f"logical occurrence goal identity mismatch for {occurrence_id}"
            )
        if any(
            not isinstance(value, str) or not value
            for value in (
                getattr(problem, "relation", None),
                getattr(problem, "policy_id", None),
            )
        ):
            raise ValueError(
                f"logical occurrence goal metadata incomplete for {occurrence_id}"
            )
        basis_id = f"{occurrence_id}:out"
        omega_id = f"{problem.policy_id}:exact"
        bases.append(
            LogicalBasis(
                occurrence_id=occurrence_id,
                basis_id=basis_id,
                relation=problem.relation,
                policy_id=problem.policy_id,
            )
        )
        live.append(
            LogicalObligation(
                basis_id=basis_id,
                omega_id=omega_id,
                source_occurrence_id=occurrence_id,
            )
        )
        deadlines.append(
            ResidualDeadline(
                occurrence_id=occurrence_id,
                policy_id=problem.policy_id,
                deadline=problem.parent_requirement.residual_deadline,
                allowed_enforcers=problem.parent_requirement.allowed_enforcers,
            )
        )
    transforms = tuple(
        LineageTransform(
            occurrence_id=occurrence_id,
            logical_basis_id=f"{occurrence_id}:out",
            kind=kind,
            operator_path=operator_path,
            join_side=join_side,
            branch_tag=branch_tag,
            branch_index=branch_index,
        )
        for occurrence_id, kind, operator_path, join_side, branch_tag, branch_index in transform_specs
    )
    return ObligationGraph(
        logical_basis=tuple(bases),
        required_live_pairs=tuple(live),
        residual_deadlines=tuple(deadlines),
        lineage_transforms=transforms,
        root_observables=dict(root_observables or {}),
    )


def actual_basis_covers_logical(
    actual_basis_id: str,
    logical_basis_id: str,
    *,
    allowed_transforms: Iterable[LineageTransform] = (),
) -> bool:
    """Recognize the finite IR's tagged/product lineage transforms.

    The logical basis is frozen before transfer.  This matcher only follows
    explicit string encodings produced by the finite transfer operators; it
    never creates a requirement from the final candidate state.
    """

    return _finite_lineage_covers(
        actual_basis_id,
        logical_basis_id,
        transforms=tuple(allowed_transforms),
        basis_mode=True,
    )


def actual_omega_covers_logical(
    actual_omega_id: str,
    logical_omega_id: str,
    *,
    allowed_transforms: Iterable[LineageTransform] = (),
) -> bool:
    """Follow explicit tagged-union/product omega encodings from transfer."""

    return _finite_lineage_covers(
        actual_omega_id,
        logical_omega_id,
        transforms=tuple(allowed_transforms),
        basis_mode=False,
    )


def _finite_lineage_covers(
    actual_id: str,
    logical_id: str,
    *,
    transforms: tuple[LineageTransform, ...],
    basis_mode: bool,
    _index: int = 0,
) -> bool:
    """Recognize only the finite transfer encodings, never substrings.

    The transfer implementation has two relevant encodings: a product ``a*b``
    from ``InnerJoin`` and a tagged ``tag:index:a``/``tagindex:a`` from
    ``UnionTagged``.  Parsing those exact shapes avoids accepting a forged
    prefix/suffix such as ``evil:o:out:extra`` as evidence for ``o:out``.
    """

    if _index > 32 or not actual_id or not logical_id:
        return False
    if _index == len(transforms):
        return actual_id == logical_id
    transform = transforms[_index]
    if transform.kind == "join_product":
        # Products are emitted in a canonical binary form ``(left*right)``.
        # The graph records the protected occurrence's side at every join, so
        # a commuted or flattened product cannot impersonate the component
        # that actually carried its authorization evidence.
        product = _parse_canonical_product(actual_id)
        if product is None:
            return False
        side = product[0] if transform.join_side == "left" else product[1]
        return _finite_lineage_covers(
            side,
            logical_id,
            transforms=transforms,
            basis_mode=basis_mode,
            _index=_index + 1,
        )
    if transform.kind != "union_tag":  # pragma: no cover - constructor invariant
        return False
    tag = re.escape(transform.branch_tag)
    index = transform.branch_index
    assert index is not None
    pattern = (
        rf"^{tag}:{index}:(.+)$"
        if basis_mode
        else rf"^{tag}{index}:(.+)$"
    )
    tagged = re.fullmatch(pattern, actual_id)
    if tagged is None:
        return False
    return _finite_lineage_covers(
        tagged.group(1),
        logical_id,
        transforms=transforms,
        basis_mode=basis_mode,
        _index=_index + 1,
    )


def _parse_canonical_product(value: str) -> tuple[str, str] | None:
    """Parse only transfer-generated binary products, never a flat string.

    Parentheses preserve the finite IR's join tree.  A raw ``a*b`` may look
    compatible to a human but loses associativity and left/right component
    identity, so root replay rejects it rather than guessing a lineage.
    """

    if len(value) < 5 or not value.startswith("(") or not value.endswith(")"):
        return None
    depth = 0
    separator_index: int | None = None
    for index, char in enumerate(value[1:-1], start=1):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return None
        elif char == "*" and depth == 0:
            if separator_index is not None:
                return None
            separator_index = index
    if depth != 0 or separator_index is None:
        return None
    left = value[1:separator_index]
    right = value[separator_index + 1:-1]
    if not left or not right:
        return None
    return left, right
