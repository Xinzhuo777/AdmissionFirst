"""Sigma transfer functions for the finite CAPRLS plan-tree fragment."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping, Sequence

from .state import (
    RECOVERABILITY_EVIDENCE_MODES,
    BasisElement,
    LineageCarrierBinding,
    RecoverabilityContext,
    RecoverabilityWitness,
    ResidualRecord,
    Sigma,
)
from .obligations import (
    ObligationGraph,
    actual_basis_covers_logical,
    actual_omega_covers_logical,
    canonical_root_observables,
)


EXACT_AUTH_SUMMARIES = frozenset({"exact", "artifact_exact", "engine_exact"})
BOUNDARY_KINDS = frozenset(
    {"aggregation", "distinct", "limit", "window", "final_projection", "unsafe"}
)


@dataclass(frozen=True)
class EnforcerInsertion:
    enforcer: str
    target_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "enforcer": self.enforcer,
            "target_ids": list(self.target_ids),
        }
        if self.metadata is not None:
            payload["metadata"] = dict(self.metadata)
        return payload


@dataclass(frozen=True)
class TransferResult:
    ok: bool
    sigma: Sigma | None = None
    reason: str = ""
    inserted_enforcers: tuple[EnforcerInsertion, ...] = ()
    evidence_refs: tuple[str, ...] = ()

    @classmethod
    def accept(
        cls,
        sigma: Sigma,
        *,
        inserted_enforcers: Iterable[EnforcerInsertion] = (),
        evidence_refs: Iterable[str] = (),
    ) -> "TransferResult":
        return cls(
            ok=True,
            sigma=sigma,
            inserted_enforcers=tuple(inserted_enforcers),
            evidence_refs=tuple(sorted(set(str(ref) for ref in evidence_refs))),
        )

    @classmethod
    def reject(cls, reason: str) -> "TransferResult":
        return cls(ok=False, reason=reason)


@dataclass(frozen=True)
class RootClosure:
    ok: bool
    reason: str = ""
    domain_covering: bool = False
    live_pairs_certified: bool = False
    residuals_closed: bool = False
    live_pairs: tuple[tuple[str, str], ...] = ()
    obligation_graph_digest: str = ""


@dataclass(frozen=True)
class TransferRuleSpec:
    """Executable anchor for one Table 3 / supplement A.2 transfer row."""

    theory_row: str
    function_name: str
    ir_nodes: tuple[str, ...]
    obligation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "theory_row": self.theory_row,
            "function_name": self.function_name,
            "ir_nodes": list(self.ir_nodes),
            "obligation": self.obligation,
        }


TRANSFER_RULE_SPECS: tuple[TransferRuleSpec, ...] = (
    TransferRuleSpec(
        theory_row="logical-target selection functional transfer",
        function_name="transfer_select_logical_target",
        ir_nodes=("Select[pred_kind=logical_target]",),
        obligation="preserve live pairs and auth basis",
    ),
    TransferRuleSpec(
        theory_row="necessary safe reducer requires Gamma necessity",
        function_name="transfer_select_necessary_safe_reducer",
        ir_nodes=("Select[pred_kind=necessary_safe_reducer]",),
        obligation="reject without gamma:necessary fact",
    ),
    TransferRuleSpec(
        theory_row="merely leakproof predicate is not a reducer",
        function_name="transfer_select_leakproof_only",
        ir_nodes=("Select[pred_kind=leakproof_only]",),
        obligation="preserve Sigma without residual transport claims",
    ),
    TransferRuleSpec(
        theory_row="unsafe expression observes only exact authorized basis",
        function_name="transfer_select_unsafe",
        ir_nodes=("Select[pred_kind=unsafe]", "UnsafeExpr"),
        obligation="H4 expression safety",
    ),
    TransferRuleSpec(
        theory_row="carrier-preserving projection recoverability",
        function_name="transfer_project",
        ir_nodes=("Project",),
        obligation="Recoverable_Gamma(Need, visible+hidden carriers)",
    ),
    TransferRuleSpec(
        theory_row="side-local inner join product basis",
        function_name="transfer_inner_join",
        ir_nodes=("InnerJoin",),
        obligation="product basis and side-local residual transport",
    ),
    TransferRuleSpec(
        theory_row="branch-tagged union tagged sum",
        function_name="transfer_union_tagged",
        ir_nodes=("UnionTagged",),
        obligation="branch-local basis and lineage preservation",
    ),
    TransferRuleSpec(
        theory_row="duplicate collapse non-transparency",
        function_name="transfer_duplicate_collapse",
        ir_nodes=("DuplicateCollapse",),
        obligation="require discharge or trusted-surrogate/lifted-equivalence Gamma",
    ),
    TransferRuleSpec(
        theory_row="opaque boundary requires residual discharge",
        function_name="transfer_boundary",
        ir_nodes=("Boundary",),
        obligation="reject or insert RCheck before non-transparent boundary",
    ),
    TransferRuleSpec(
        theory_row="residual-check enforcer discharges residual obligations",
        function_name="enforce_residual_check",
        ir_nodes=("RCheck",),
        obligation="H3 residual transparency via allowed enforcer",
    ),
    TransferRuleSpec(
        theory_row="artifact validation gate enforcer",
        function_name="enforce_validation_gate",
        ir_nodes=("ValidationGate",),
        obligation="H2 snapshot/freshness gate under rho",
    ),
    TransferRuleSpec(
        theory_row="sort enforcer for required order",
        function_name="enforce_sort",
        ir_nodes=("SortEnforce",),
        obligation="ordinary physprop delivered when rho allows sort",
    ),
    TransferRuleSpec(
        theory_row="materialize enforcer for observable coverage",
        function_name="enforce_materialize",
        ir_nodes=("Materialize",),
        obligation="coverage/materialization property delivered when rho allows it",
    ),
    TransferRuleSpec(
        theory_row="root closure over domain, live pairs, and residuals",
        function_name="root_close",
        ir_nodes=("Root",),
        obligation="DomainCovering and LivePairs_root subset AuthSet and no residuals",
    ),
)


def transfer_rule_table() -> tuple[Mapping[str, Any], ...]:
    """Return the executable Table 3 / supplement A.2 mapping."""

    return tuple(spec.to_dict() for spec in TRANSFER_RULE_SPECS)


def _auth_summary(sigma: Sigma) -> str:
    return str(sigma.auth_summary or "")


@dataclass(frozen=True)
class _RootActualInventory:
    basis_ids: tuple[str, ...]
    live_pairs: tuple[tuple[str, str], ...]
    auth_pairs: tuple[tuple[str, str], ...]
    residual_count: int
    domain_identities_valid: bool
    pair_identities_valid: bool
    pair_bases_in_domain: bool
    residual_inventory_valid: bool


def _root_actual_inventory(sigmas: Sequence[Sigma]) -> _RootActualInventory:
    """Retain multiplicity while validating the finite actual root sets."""

    basis_ids: list[str] = []
    live_pairs: list[tuple[str, str]] = []
    auth_pairs: list[tuple[str, str]] = []
    residual_count = 0
    domain_valid = True
    pairs_valid = True
    residual_valid = True
    for sigma in sigmas:
        if not isinstance(sigma, Sigma):
            domain_valid = False
            pairs_valid = False
            residual_valid = False
            continue
        if not isinstance(sigma.dom, (list, tuple)):
            domain_valid = False
        else:
            for basis in sigma.dom:
                if not isinstance(basis, BasisElement) or any(
                    not isinstance(value, str) or not value
                    for value in (
                        getattr(basis, "basis_id", None),
                        getattr(basis, "kind", None),
                        getattr(basis, "occurrence_id", None),
                        getattr(basis, "relation", None),
                    )
                ):
                    domain_valid = False
                    continue
                basis_ids.append(basis.basis_id)
        if not isinstance(sigma.live, Mapping):
            pairs_valid = False
        else:
            for basis_id, omega_ids in sigma.live.items():
                if (
                    not isinstance(basis_id, str)
                    or not basis_id
                    or not isinstance(omega_ids, (list, tuple))
                ):
                    pairs_valid = False
                    continue
                for omega_id in omega_ids:
                    if not isinstance(omega_id, str) or not omega_id:
                        pairs_valid = False
                        continue
                    live_pairs.append((basis_id, omega_id))
        if not isinstance(sigma.auth_set, (list, tuple)):
            pairs_valid = False
        else:
            for pair in sigma.auth_set:
                if (
                    not isinstance(pair, (list, tuple))
                    or len(pair) != 2
                    or any(not isinstance(value, str) or not value for value in pair)
                ):
                    pairs_valid = False
                    continue
                auth_pairs.append((pair[0], pair[1]))
        if not isinstance(sigma.residuals, (list, tuple)):
            residual_valid = False
        else:
            residual_count += len(sigma.residuals)

    if len(basis_ids) != len(set(basis_ids)):
        domain_valid = False
    if len(live_pairs) != len(set(live_pairs)) or len(auth_pairs) != len(
        set(auth_pairs)
    ):
        pairs_valid = False
    basis_id_set = set(basis_ids)
    pair_bases_in_domain = all(
        basis_id in basis_id_set
        for basis_id, _omega_id in (*live_pairs, *auth_pairs)
    )
    return _RootActualInventory(
        basis_ids=tuple(basis_ids),
        live_pairs=tuple(live_pairs),
        auth_pairs=tuple(auth_pairs),
        residual_count=residual_count,
        domain_identities_valid=domain_valid,
        pair_identities_valid=pairs_valid,
        pair_bases_in_domain=pair_bases_in_domain,
        residual_inventory_valid=residual_valid,
    )


def _residual_id(residual: ResidualRecord) -> str:
    return residual.check_id or residual.omega_id


def _residual_ids(residuals: Sequence[ResidualRecord]) -> tuple[str, ...]:
    return tuple(_residual_id(residual) for residual in residuals)


def _replace_residual_basis(residual: ResidualRecord, basis_id: str) -> ResidualRecord:
    return replace(residual, basis_id=basis_id)


def _without_residuals(
    sigma: Sigma,
    residual_ids: Iterable[str] | None = None,
) -> Sigma:
    targets = (
        {_residual_id(residual) for residual in sigma.residuals}
        if residual_ids is None
        else set(residual_ids)
    )
    remaining = tuple(
        residual
        for residual in sigma.residuals
        if _residual_id(residual) not in targets
    )
    active_witness_ids = {
        residual.recoverability_witness_id for residual in remaining
    }
    return _promote_candidate_if_residuals_closed(replace(
        sigma,
        residuals=remaining,
        recoverability=tuple(
            witness
            for witness in sigma.recoverability
            if witness.witness_id in active_witness_ids
        ),
    ))


def _promoted_omega(omega_id: str) -> str:
    if "complete_candidate" in omega_id:
        return omega_id.replace("complete_candidate", "exact")
    if "candidate" in omega_id:
        return omega_id.replace("candidate", "exact")
    return omega_id


def _promote_candidate_if_residuals_closed(sigma: Sigma) -> Sigma:
    if sigma.residuals or sigma.auth_summary != "candidate":
        return sigma
    auth_set = tuple((basis_id, _promoted_omega(omega_id)) for basis_id, omega_id in sigma.auth_set)
    live = {
        basis_id: tuple(_promoted_omega(omega_id) for omega_id in omega_ids)
        for basis_id, omega_ids in sigma.live.items()
    }
    safety = {
        basis_id: "exact_authorized"
        if safety_level in {"candidate", "candidate_authorized"}
        else safety_level
        for basis_id, safety_level in sigma.safety.items()
    }
    return replace(
        sigma,
        auth_set=auth_set,
        auth_summary="exact",
        live=live,
        safety=safety,
    )


def _with_phys_props(sigma: Sigma, **updates: Any) -> Sigma:
    phys = dict(sigma.phys_props)
    phys.update(updates)
    return replace(sigma, phys_props=phys)


def _project_recoverability_context(
    context: RecoverabilityContext,
    *,
    visible_attrs: Iterable[str],
    hidden_attrs: Iterable[str],
) -> RecoverabilityContext:
    requested_visible = frozenset(str(value) for value in visible_attrs)
    requested_hidden = frozenset(str(value) for value in hidden_attrs)
    input_carriers = context.visible_attrs | context.hidden_carriers
    output_visible = requested_visible & input_carriers
    output_hidden = requested_hidden & input_carriers
    output_carriers = output_visible | output_hidden
    return RecoverabilityContext(
        visible_attrs=output_visible,
        hidden_carriers=output_hidden,
        rid_carriers=tuple(
            binding
            for binding in context.rid_carriers
            if binding.physical_carrier in output_carriers
        ),
        lineage_carriers=tuple(
            binding
            for binding in context.lineage_carriers
            if binding.physical_carrier in output_carriers
        ),
        available_context_keys=context.available_context_keys,
        trusted_read_facts=context.trusted_read_facts,
        freshness_facts=context.freshness_facts,
        gamma_snapshot_id=context.gamma_snapshot_id,
        evidence_mode=context.evidence_mode,
    )


def _transport_recoverability_witness(
    witness: RecoverabilityWitness,
    *,
    basis_id: str,
    transport_step: str,
    context: RecoverabilityContext | None = None,
) -> RecoverabilityWitness:
    return RecoverabilityWitness.derive(
        basis_id=basis_id,
        source_basis_id=witness.source_basis_id,
        transport_path=(*witness.transport_path, transport_step),
        context=witness.context if context is None else context,
    )


def _recoverability_witness_for_residual(
    sigma: Sigma,
    residual: ResidualRecord,
) -> RecoverabilityWitness | None:
    matches = tuple(
        witness
        for witness in sigma.recoverability
        if witness.witness_id == residual.recoverability_witness_id
        and witness.basis_id == residual.basis_id
    )
    return matches[0] if len(matches) == 1 else None


def _recoverability_missing_for_residual(
    sigma: Sigma,
    residual: ResidualRecord,
) -> tuple[str, ...]:
    witness = _recoverability_witness_for_residual(sigma, residual)
    if witness is None:
        return ("recoverability_witness:missing_or_ambiguous",)
    return witness.context.missing_for(
        residual.need,
        expected_rid_domain_id=residual.rid_domain_id,
        expected_gamma_snapshot_id=residual.gamma_snapshot_id,
    )


def _exact_authorized_basis_ids(sigma: Sigma) -> set[str]:
    if _auth_summary(sigma) not in EXACT_AUTH_SUMMARIES:
        return set()
    return {basis_id for basis_id, _omega_id in sigma.auth_set}


def _safety_disabled_basis_ids(sigma: Sigma) -> set[str]:
    return {
        basis_id
        for basis_id, safety_level in sigma.safety.items()
        if safety_level == "disabled_safety_level"
    }


def _min_safety(left: str, right: str) -> str:
    order = {
        "unknown": 0,
        "candidate_authorized": 1,
        "exact_authorized": 2,
    }
    return left if order.get(left, 0) <= order.get(right, 0) else right


def _combined_freshness(left: str, right: str) -> str:
    if left == right:
        return left
    if "stale" in {left, right}:
        return "stale"
    if "unknown" in {left, right}:
        return "unknown"
    return f"{left}+{right}"


def _combined_context_scope(left: str, right: str) -> str:
    if left == right:
        return left
    if "mismatch" in {left, right}:
        return "mismatch"
    if "unknown" in {left, right}:
        return "unknown"
    return f"{left}+{right}"


def _basis_product(left: BasisElement, right: BasisElement) -> BasisElement:
    return BasisElement(
        basis_id=_canonical_product_id(left.basis_id, right.basis_id),
        kind="join_product",
        occurrence_id=f"{left.occurrence_id}*{right.occurrence_id}",
        relation=f"{left.relation}*{right.relation}",
    )


def _canonical_product_id(left: str, right: str) -> str:
    """Return the only join-product encoding accepted by root replay.

    Parenthesized binary form retains both associativity and operand position;
    a flat ``a*b*c`` representation cannot prove which component carried a
    protected occurrence's authorization evidence.
    """

    if not left or not right:
        raise ValueError("join product operands must be nonempty")
    return f"({left}*{right})"


def _tagged_basis(basis: BasisElement, branch_index: int, branch_tag: str) -> BasisElement:
    return BasisElement(
        basis_id=f"{branch_tag}:{branch_index}:{basis.basis_id}",
        kind="tagged_union",
        occurrence_id=basis.occurrence_id,
        relation=basis.relation,
    )


def _union_branch_carrier_inventory(
    sigma: Sigma,
) -> tuple[tuple[str, ...], tuple[str, ...], frozenset[str]] | None:
    """Return only carriers explicitly present in a branch output contract."""

    schemas: dict[str, tuple[str, ...]] = {}
    for field_name in ("visible_attrs", "hidden_attrs"):
        raw = sigma.phys_props.get(field_name)
        if not isinstance(raw, (list, tuple)):
            return None
        values = tuple(raw)
        if (
            any(not isinstance(value, str) or not value for value in values)
            or len(set(values)) != len(values)
        ):
            return None
        schemas[field_name] = values
    visible = schemas["visible_attrs"]
    hidden = schemas["hidden_attrs"]
    if set(visible) & set(hidden):
        return None
    carriers = set(visible) | set(hidden)
    for witness in sigma.recoverability:
        context_carriers = (
            witness.context.visible_attrs | witness.context.hidden_carriers
        )
        if any(
            binding.physical_carrier not in context_carriers
            for binding in (
                *witness.context.rid_carriers,
                *witness.context.lineage_carriers,
            )
        ):
            return None
        carriers.update(context_carriers)
    return visible, hidden, frozenset(carriers)


# Table 3 / supplement A.2: Select(logical_target) is a functional transfer.
def transfer_select_logical_target(sigma: Sigma) -> TransferResult:
    return TransferResult.accept(sigma)


# Table 3 / supplement A.2: necessary safe reducers require a Gamma necessity fact.
def transfer_select_necessary_safe_reducer(
    sigma: Sigma,
    *,
    gamma_necessity_fact: bool,
) -> TransferResult:
    if not gamma_necessity_fact:
        return TransferResult.reject("missing_necessity_fact_for_safe_reducer")
    return TransferResult.accept(sigma)


# Table 3 / supplement A.2: merely leakproof predicates do not become reducers.
def transfer_select_leakproof_only(sigma: Sigma) -> TransferResult:
    # Leakproofness limits observations; it is not a completeness theorem.
    # A SQL WHERE at this point would be a reducer, so it is legal only after
    # the child is already exact-authorized and any residual is discharged.
    if sigma.residuals or _auth_summary(sigma) not in EXACT_AUTH_SUMMARIES:
        return TransferResult.reject("leakproof_predicate_not_authorized_reducer")
    return TransferResult.accept(sigma)


# Table 3 / supplement A.2: unsafe predicates may observe only exact auth basis.
def transfer_select_unsafe(
    sigma: Sigma,
    *,
    observed_basis_ids: Iterable[str],
) -> TransferResult:
    observed = set(observed_basis_ids)
    allowed = _exact_authorized_basis_ids(sigma) | _safety_disabled_basis_ids(sigma)
    if not observed.issubset(allowed):
        return TransferResult.reject("unsafe_expression_observes_candidate_basis")
    return TransferResult.accept(sigma)


# Table 3 / supplement A.2: projection must retain recoverable residual carriers.
def transfer_project(
    sigma: Sigma,
    *,
    visible_attrs: Iterable[str],
    hidden_attrs: Iterable[str],
) -> TransferResult:
    visible = set(visible_attrs)
    hidden = set(hidden_attrs)
    projected_by_input_id: dict[str, RecoverabilityWitness] = {}
    for witness in sigma.recoverability:
        projected_context = _project_recoverability_context(
            witness.context,
            visible_attrs=visible,
            hidden_attrs=hidden,
        )
        projected_by_input_id[witness.witness_id] = (
            _transport_recoverability_witness(
                witness,
                basis_id=witness.basis_id,
                transport_step="project",
                context=projected_context,
            )
        )
    projected_residuals: list[ResidualRecord] = []
    for residual in sigma.residuals:
        witness = projected_by_input_id.get(
            residual.recoverability_witness_id
        )
        if witness is None or witness.basis_id != residual.basis_id:
            return TransferResult.reject("project_recoverability_witness_missing")
        projected_residuals.append(
            replace(
                residual,
                recoverability_witness_id=witness.witness_id,
            )
        )
    projected_sigma = replace(
        sigma,
        residuals=tuple(projected_residuals),
        recoverability=tuple(projected_by_input_id.values()),
    )
    for residual in projected_sigma.residuals:
        if _recoverability_missing_for_residual(projected_sigma, residual):
            return TransferResult.reject("project_drops_residual_carrier")
    return TransferResult.accept(
        _with_phys_props(
            projected_sigma,
            visible_attrs=tuple(sorted(visible)),
            hidden_attrs=tuple(sorted(hidden)),
        ),
        evidence_refs=tuple(
            f"recoverability:witness:{witness.witness_id}"
            for witness in projected_sigma.recoverability
        ),
    )


# Table 3 / supplement A.2: inner join uses product bases and side-local residual transport.
def transfer_inner_join(
    left: Sigma,
    right: Sigma,
    *,
    theta_safe: bool = True,
) -> TransferResult:
    if not theta_safe:
        return TransferResult.reject("unsafe_join_theta")
    products: list[BasisElement] = []
    live: dict[str, tuple[str, ...]] = {}
    auth_pairs: list[tuple[str, str]] = []
    residuals: list[ResidualRecord] = []
    recoverability: list[RecoverabilityWitness] = []
    safety: dict[str, str] = {}

    for left_basis in left.dom:
        for right_basis in right.dom:
            product = _basis_product(left_basis, right_basis)
            products.append(product)
            left_live = tuple(left.live.get(left_basis.basis_id, ()))
            right_live = tuple(right.live.get(right_basis.basis_id, ()))
            live[product.basis_id] = tuple(
                _canonical_product_id(left_omega, right_omega)
                for left_omega in left_live
                for right_omega in right_live
            )
            safety[product.basis_id] = _min_safety(
                left.safety.get(left_basis.basis_id, "unknown"),
                right.safety.get(right_basis.basis_id, "unknown"),
            )
            left_witnesses = {
                witness.witness_id: _transport_recoverability_witness(
                    witness,
                    basis_id=product.basis_id,
                    transport_step="join:left",
                )
                for witness in left.recoverability
                if witness.basis_id == left_basis.basis_id
            }
            right_witnesses = {
                witness.witness_id: _transport_recoverability_witness(
                    witness,
                    basis_id=product.basis_id,
                    transport_step="join:right",
                )
                for witness in right.recoverability
                if witness.basis_id == right_basis.basis_id
            }
            recoverability.extend(left_witnesses.values())
            recoverability.extend(right_witnesses.values())
            for basis_id, omega_id in left.auth_set:
                if basis_id == left_basis.basis_id:
                    for right_basis_id, right_omega_id in right.auth_set:
                        if right_basis_id == right_basis.basis_id:
                            auth_pairs.append(
                                (
                                    product.basis_id,
                                    _canonical_product_id(omega_id, right_omega_id),
                                )
                            )
            for residual in left.residuals:
                if residual.basis_id != left_basis.basis_id:
                    continue
                witness = left_witnesses.get(
                    residual.recoverability_witness_id
                )
                if witness is None:
                    return TransferResult.reject(
                        "join_left_recoverability_witness_missing"
                    )
                residuals.append(
                    replace(
                        residual,
                        basis_id=product.basis_id,
                        recoverability_witness_id=witness.witness_id,
                    )
                )
            for residual in right.residuals:
                if residual.basis_id != right_basis.basis_id:
                    continue
                witness = right_witnesses.get(
                    residual.recoverability_witness_id
                )
                if witness is None:
                    return TransferResult.reject(
                        "join_right_recoverability_witness_missing"
                    )
                residuals.append(
                    replace(
                        residual,
                        basis_id=product.basis_id,
                        recoverability_witness_id=witness.witness_id,
                    )
                )

    joined = Sigma(
        dom=tuple(products),
        live=live,
        auth_set=tuple(auth_pairs),
        auth_summary="exact"
        if left.auth_summary in EXACT_AUTH_SUMMARIES
        and right.auth_summary in EXACT_AUTH_SUMMARIES
        else "candidate",
        residuals=tuple(residuals),
        safety=safety,
        freshness=_combined_freshness(left.freshness, right.freshness),
        context_scope=_combined_context_scope(
            left.context_scope,
            right.context_scope,
        ),
        rid_mat_props={
            "join": [
                dict(left.rid_mat_props),
                dict(right.rid_mat_props),
            ]
        },
        recoverability=tuple(recoverability),
        phys_props={
            "operator": "inner_join",
            "left": dict(left.phys_props),
            "right": dict(right.phys_props),
        },
        branch_lineage="preserved"
        if left.branch_lineage == "preserved"
        and right.branch_lineage == "preserved"
        else "lost",
    )
    if any(
        _recoverability_missing_for_residual(joined, residual)
        for residual in joined.residuals
    ):
        return TransferResult.reject("join_residual_not_recoverable")
    return TransferResult.accept(joined)


# Table 3 / supplement A.2: branch-tagged union is a tagged sum.
def transfer_union_tagged(
    branches: Sequence[Sigma],
    *,
    branch_tag: str,
) -> TransferResult:
    if not branches:
        return TransferResult.reject("union_requires_branch")
    if (
        not isinstance(branch_tag, str)
        or re.fullmatch(r"[a-z_][a-z0-9_]*", branch_tag) is None
    ):
        return TransferResult.reject("union_branch_tag_invalid")
    inventories: list[
        tuple[tuple[str, ...], tuple[str, ...], frozenset[str]]
    ] = []
    for sigma in branches:
        inventory = _union_branch_carrier_inventory(sigma)
        if inventory is None:
            return TransferResult.reject(
                "union_branch_carrier_inventory_unknown"
            )
        if branch_tag in inventory[2]:
            return TransferResult.reject(
                "union_branch_tag_carrier_collision"
            )
        inventories.append(inventory)
    if len({(visible, hidden) for visible, hidden, _all in inventories}) != 1:
        return TransferResult.reject("union_branch_schema_mismatch")
    visible_attrs, input_hidden_attrs, _inventory = inventories[0]
    logical_lineage_id = f"branch_tag:{branch_tag}"
    dom: list[BasisElement] = []
    live: dict[str, tuple[str, ...]] = {}
    auth_pairs: list[tuple[str, str]] = []
    residuals: list[ResidualRecord] = []
    recoverability: list[RecoverabilityWitness] = []
    safety: dict[str, str] = {}
    freshness_values: set[str] = set()
    context_values: set[str] = set()

    for index, sigma in enumerate(branches):
        freshness_values.add(sigma.freshness)
        context_values.add(sigma.context_scope)
        basis_map: dict[str, str] = {}
        for basis in sigma.dom:
            tagged = _tagged_basis(basis, index, branch_tag)
            dom.append(tagged)
            basis_map[basis.basis_id] = tagged.basis_id
            live[tagged.basis_id] = tuple(
                f"{branch_tag}{index}:{omega_id}"
                for omega_id in sigma.live.get(basis.basis_id, ())
            )
            safety[tagged.basis_id] = sigma.safety.get(basis.basis_id, "unknown")
            witness_map: dict[str, RecoverabilityWitness] = {}
            for witness in sigma.recoverability:
                if witness.basis_id != basis.basis_id:
                    continue
                context = replace(
                    witness.context,
                    hidden_carriers=(
                        witness.context.hidden_carriers | {branch_tag}
                    ),
                    lineage_carriers=(
                        *witness.context.lineage_carriers,
                        LineageCarrierBinding(
                            logical_lineage_id,
                            branch_tag,
                        ),
                    ),
                )
                transported = _transport_recoverability_witness(
                    witness,
                    basis_id=tagged.basis_id,
                    transport_step=f"union:{branch_tag}:{index}",
                    context=context,
                )
                witness_map[witness.witness_id] = transported
                recoverability.append(transported)
            for residual in sigma.residuals:
                if residual.basis_id != basis.basis_id:
                    continue
                witness = witness_map.get(
                    residual.recoverability_witness_id
                )
                if witness is None:
                    return TransferResult.reject(
                        "union_recoverability_witness_missing"
                    )
                residuals.append(
                    replace(
                        residual,
                        basis_id=tagged.basis_id,
                        need=replace(
                            residual.need,
                            lineage_carriers=(
                                *residual.need.lineage_carriers,
                                logical_lineage_id,
                            ),
                        ),
                        recoverability_witness_id=witness.witness_id,
                    )
                )
        for basis_id, omega_id in sigma.auth_set:
            if basis_id in basis_map:
                auth_pairs.append((basis_map[basis_id], f"{branch_tag}{index}:{omega_id}"))

    tagged = Sigma(
        dom=tuple(dom),
        live=live,
        auth_set=tuple(auth_pairs),
        auth_summary="exact"
        if all(
            branch.auth_summary in EXACT_AUTH_SUMMARIES
            for branch in branches
        )
        else "candidate",
        residuals=tuple(residuals),
        safety=safety,
        freshness=next(iter(freshness_values))
        if len(freshness_values) == 1
        else "mixed",
        context_scope=next(iter(context_values))
        if len(context_values) == 1
        else "mixed",
        rid_mat_props={"union_tag": branch_tag},
        recoverability=tuple(recoverability),
        phys_props={
            "operator": "union_tagged",
            "branch_tag": branch_tag,
            "visible_attrs": visible_attrs,
            "hidden_attrs": (*input_hidden_attrs, branch_tag),
        },
        branch_lineage="preserved",
    )
    if any(
        _recoverability_missing_for_residual(tagged, residual)
        for residual in tagged.residuals
    ):
        return TransferResult.reject("union_residual_not_recoverable")
    return TransferResult.accept(tagged)


# Table 3 / supplement A.2: duplicate collapse is non-transparent without Gamma facts.
def transfer_duplicate_collapse(
    sigma: Sigma,
    *,
    trusted_surrogate: bool = False,
    lifted_equivalence: bool = False,
    gamma_fact: str = "",
) -> TransferResult:
    if (trusted_surrogate or lifted_equivalence) and not gamma_fact:
        return TransferResult.reject("duplicate_collapse_missing_gamma_fact")
    if sigma.residuals and not (trusted_surrogate or lifted_equivalence):
        return TransferResult.reject("duplicate_collapse_requires_discharge")
    lineage = "preserved" if trusted_surrogate or lifted_equivalence else "collapsed"
    return TransferResult.accept(replace(sigma, branch_lineage=lineage))


# Table 3 / supplement A.2: opaque boundaries require residual discharge first.
def transfer_boundary(
    sigma: Sigma,
    *,
    kind: str,
    allowed_enforcers: Iterable[str] = (),
) -> TransferResult:
    if kind not in BOUNDARY_KINDS:
        return TransferResult.reject(f"unknown_boundary:{kind}")
    if not sigma.residuals:
        return TransferResult.accept(sigma)
    if "residual_check" not in set(allowed_enforcers):
        return TransferResult.reject("residual_crosses_opaque_boundary")
    residual_ids = _residual_ids(sigma.residuals)
    # The enforcer is only a placement requirement here; it is not evidence
    # that an RCheck was bound into the actual IR.  Keeping the residual live
    # prevents a caller from promoting a candidate to exact merely by asking
    # for an insertion and then passing the resulting Sigma to root_close.
    return TransferResult.accept(
        _with_phys_props(
            sigma,
            pending_residual_enforcer=tuple(residual_ids),
        ),
        inserted_enforcers=(
            EnforcerInsertion(enforcer="RCheck", target_ids=residual_ids),
        ),
    )


def enforce_residual_check(
    sigma: Sigma,
    *,
    residual_ids: Iterable[str] | None = None,
) -> TransferResult:
    target_ids = tuple(
        dict.fromkeys(
            str(item)
            for item in (
                residual_ids
                if residual_ids is not None
                else _residual_ids(sigma.residuals)
            )
        )
    )
    if not target_ids:
        return TransferResult.reject("residual_check_requires_target")
    available_ids = set(_residual_ids(sigma.residuals))
    if not set(target_ids).issubset(available_ids):
        return TransferResult.reject("residual_check_target_missing")
    target_id_set = set(target_ids)
    targeted = tuple(
        residual
        for residual in sigma.residuals
        if _residual_id(residual) in target_id_set
    )
    recovered: list[tuple[ResidualRecord, RecoverabilityWitness]] = []
    for residual in targeted:
        witness = _recoverability_witness_for_residual(sigma, residual)
        if witness is None:
            return TransferResult.reject(
                "residual_recoverability_witness_missing"
            )
        missing = _recoverability_missing_for_residual(sigma, residual)
        if missing:
            return TransferResult.reject(
                "residual_need_not_recoverable:" + ",".join(missing)
            )
        recovered.append((residual, witness))

    raw_discharged = sigma.phys_props.get("discharged_residuals", ())
    if not isinstance(raw_discharged, (list, tuple)) or any(
        not isinstance(item, Mapping) for item in raw_discharged
    ):
        return TransferResult.reject("residual_discharge_history_invalid")
    discharged = [dict(item) for item in raw_discharged]
    for residual, witness in recovered:
        discharged.append(
            {
                "basis_id": residual.basis_id,
                "omega_id": residual.omega_id,
                "check_id": residual.check_id,
                "deadline": residual.deadline,
                "recoverability_witness_id": witness.witness_id,
                "recoverability_witness_digest": witness.digest,
                "gamma_snapshot_id": witness.context.gamma_snapshot_id,
                # Provenance only; production promotion remains externally
                # bound to the G2 planning execution and receipt identity.
                "evidence_mode": witness.context.evidence_mode,
            }
        )
    checked = _without_residuals(sigma, target_ids)
    return TransferResult.accept(
        _with_phys_props(
            checked,
            discharged_residuals=tuple(discharged),
        ),
        inserted_enforcers=(
            EnforcerInsertion(enforcer="RCheck", target_ids=target_ids),
        ),
        evidence_refs=tuple(
            f"recoverability:witness:{witness.witness_id}"
            for _residual, witness in recovered
        ),
    )


def enforce_validation_gate(
    sigma: Sigma,
    *,
    artifact_id: str,
    allowed_enforcers: Iterable[str],
) -> TransferResult:
    if "validation_gate" not in set(allowed_enforcers):
        return TransferResult.reject("validation_gate_not_allowed_by_rho")
    return TransferResult.accept(
        _with_phys_props(sigma, validation_gate=artifact_id),
        inserted_enforcers=(EnforcerInsertion(enforcer="ValidationGate", target_ids=(artifact_id,)),),
    )


def enforce_sort(
    sigma: Sigma,
    *,
    keys: Iterable[str],
    allowed_enforcers: Iterable[str],
) -> TransferResult:
    if "sort" not in set(allowed_enforcers):
        return TransferResult.reject("sort_not_allowed_by_rho")
    ordered_keys = tuple(keys)
    return TransferResult.accept(
        _with_phys_props(sigma, delivered_order=ordered_keys),
        inserted_enforcers=(EnforcerInsertion(enforcer="SortEnforce", target_ids=ordered_keys),),
    )


def enforce_materialize(
    sigma: Sigma,
    *,
    allowed_enforcers: Iterable[str],
) -> TransferResult:
    if "materialize" not in set(allowed_enforcers):
        return TransferResult.reject("materialize_not_allowed_by_rho")
    return TransferResult.accept(
        _with_phys_props(sigma, materialized=True),
        inserted_enforcers=(EnforcerInsertion(enforcer="Materialize"),),
    )


def root_close(
    sigmas: Sequence[Sigma],
    *,
    obligation_graph: ObligationGraph | None = None,
    rho: Mapping[str, Any] | None = None,
) -> RootClosure:
    if obligation_graph is None:
        return RootClosure(ok=False, reason="root_obligation_graph_missing")
    if not isinstance(obligation_graph, ObligationGraph):
        return RootClosure(ok=False, reason="root_obligation_graph_invalid")
    if not sigmas:
        return RootClosure(
            ok=False,
            reason="root_has_no_sigma",
            obligation_graph_digest=obligation_graph.digest,
        )
    actual = _root_actual_inventory(sigmas)
    all_basis_ids = actual.basis_ids
    all_live = actual.live_pairs
    all_auth = actual.auth_pairs

    required_pairs = tuple(
        (obligation.basis_id, obligation.omega_id)
        for obligation in obligation_graph.required_live_pairs
    )
    # A basis' permitted lineage chain is immutable for this root check.  The
    # former nested quantifiers rescanned and resorted the full transform list
    # for every actual/logical pair, even though every lookup used the same
    # pre-candidate obligation graph.
    transforms_by_basis = {
        basis.basis_id: obligation_graph.transforms_for_basis(basis.basis_id)
        for basis in obligation_graph.logical_basis
    }
    # Only transforms declared by the pre-candidate graph are a lineage
    # witness.  A syntactically tag-like forged identifier is not enough.
    each_logical_basis_covered = bool(all_basis_ids) and all(
        any(
            actual_basis_covers_logical(
                actual_basis,
                logical_basis,
                allowed_transforms=transforms_by_basis[logical_basis],
            )
            for actual_basis in all_basis_ids
        )
        for logical_basis in (
            basis.basis_id for basis in obligation_graph.logical_basis
        )
    )
    each_actual_basis_explained = all(
        any(
            actual_basis_covers_logical(
                actual_basis,
                logical_basis.basis_id,
                allowed_transforms=transforms_by_basis[logical_basis.basis_id],
            )
            for logical_basis in obligation_graph.logical_basis
        )
        for actual_basis in all_basis_ids
    )
    domain_covering = (
        actual.domain_identities_valid
        and actual.pair_bases_in_domain
        and each_logical_basis_covered
        and each_actual_basis_explained
    )
    live_pairs_certified = (
        actual.pair_identities_valid
        and actual.pair_bases_in_domain
        and set(all_live).issubset(set(all_auth))
        and all(
            any(
                actual_omega_covers_logical(
                    actual_omega,
                    required_omega,
                    allowed_transforms=transforms_by_basis[required_basis],
                )
                and actual_basis_covers_logical(
                    actual_basis,
                    required_basis,
                    allowed_transforms=transforms_by_basis[required_basis],
                )
                for actual_basis, actual_omega in all_live
            )
            for required_basis, required_omega in required_pairs
        )
        and all(
            any(
                actual_omega_covers_logical(
                    actual_omega,
                    required_omega,
                    allowed_transforms=transforms_by_basis[required_basis],
                )
                and actual_basis_covers_logical(
                    actual_basis,
                    required_basis,
                    allowed_transforms=transforms_by_basis[required_basis],
                )
                for actual_basis, actual_omega in all_auth
            )
            for required_basis, required_omega in required_pairs
        )
    )
    residuals_closed = (
        actual.residual_inventory_valid and actual.residual_count == 0
    )
    root_observables_match = _root_observables_satisfied(
        sigmas,
        obligation_graph=obligation_graph,
        rho=rho,
    )
    residual_discharge_valid = _residual_discharge_evidence_is_valid(
        sigmas,
        obligation_graph=obligation_graph,
    )
    if not domain_covering:
        return RootClosure(
            ok=False,
            reason="root_not_domain_covering",
            domain_covering=domain_covering,
            live_pairs_certified=live_pairs_certified,
            residuals_closed=residuals_closed,
            live_pairs=required_pairs,
            obligation_graph_digest=obligation_graph.digest,
        )
    if not residuals_closed:
        return RootClosure(
            ok=False,
            reason="root_residuals_not_closed",
            domain_covering=domain_covering,
            live_pairs_certified=live_pairs_certified,
            residuals_closed=residuals_closed,
            live_pairs=required_pairs,
            obligation_graph_digest=obligation_graph.digest,
        )
    if not residual_discharge_valid:
        return RootClosure(
            ok=False,
            reason="root_residual_discharge_evidence_invalid",
            domain_covering=domain_covering,
            live_pairs_certified=live_pairs_certified,
            residuals_closed=residuals_closed,
            live_pairs=required_pairs,
            obligation_graph_digest=obligation_graph.digest,
        )
    if not live_pairs_certified:
        return RootClosure(
            ok=False,
            reason="root_live_pairs_not_certified",
            domain_covering=domain_covering,
            live_pairs_certified=live_pairs_certified,
            residuals_closed=residuals_closed,
            live_pairs=required_pairs,
            obligation_graph_digest=obligation_graph.digest,
        )
    if not root_observables_match:
        return RootClosure(
            ok=False,
            reason="root_observables_not_satisfied",
            domain_covering=domain_covering,
            live_pairs_certified=live_pairs_certified,
            residuals_closed=residuals_closed,
            live_pairs=required_pairs,
            obligation_graph_digest=obligation_graph.digest,
        )
    return RootClosure(
        ok=True,
        domain_covering=domain_covering,
        live_pairs_certified=live_pairs_certified,
        residuals_closed=residuals_closed,
        live_pairs=required_pairs,
        obligation_graph_digest=obligation_graph.digest,
    )


def _root_observables_satisfied(
    sigmas: Sequence[Sigma],
    *,
    obligation_graph: ObligationGraph,
    rho: Mapping[str, Any] | None,
) -> bool:
    """Check the graph's explicit root-observable contract conservatively."""

    if rho is not None:
        try:
            replay_rho = canonical_root_observables(rho)
        except (TypeError, ValueError):
            return False
        if replay_rho != dict(obligation_graph.root_observables):
            # A graph must be replayed against the same root rho from which it
            # was constructed; list/tuple spelling is canonicalized, but an
            # omitted or changed value cannot be inferred from final Sigma.
            return False
    root = obligation_graph.root_observables
    recognized_root_rho_fields = {
        "logical_group_id",
        "visible_columns",
        "required_order",
        "licensed_refinements",
        "residual_allowed",
        "residual_deadline",
        "min_safety_level",
        "freshness_predicate",
        "context_predicate",
        "allowed_enforcers",
        "observable_coverage",
        "transparent",
        "unsafe_expression_boundary",
        "needs_branch_lineage",
        "future_rid_intersection",
        "required_ctx",
    }
    if set(root) - recognized_root_rho_fields:
        return False
    required_order = tuple(str(item) for item in root.get("required_order", ()))
    visible_columns = tuple(str(item) for item in root.get("visible_columns", ()))
    observable_coverage = tuple(str(item) for item in root.get("observable_coverage", ()))
    required_context = tuple(str(item) for item in root.get("required_ctx", ()))
    min_safety_level = str(root.get("min_safety_level") or "")
    freshness_predicate = str(root.get("freshness_predicate") or "")
    context_predicate = str(root.get("context_predicate") or "")
    future_rid_intersection = bool(root.get("future_rid_intersection"))
    needs_branch_lineage = bool(root.get("needs_branch_lineage"))
    if not (
        required_order
        or visible_columns
        or observable_coverage
        or required_context
        or min_safety_level
        or freshness_predicate
        or context_predicate
        or future_rid_intersection
        or needs_branch_lineage
    ):
        return True

    visible: tuple[str, ...] | None = None
    hidden: set[str] = set()
    delivered_order: tuple[str, ...] = ()
    materialized = False
    lineage_preserved = True
    safety_levels: list[str] = []
    freshness_evidence: set[str] = set()
    context_evidence: set[str] = set()
    context_keys: set[str] = set()
    has_rid_carrier = True
    for sigma in sigmas:
        props = sigma.phys_props
        current_visible = tuple(str(item) for item in props.get("visible_attrs", ()))
        if visible is None:
            visible = current_visible
        elif visible != current_visible:
            # A multi-branch root with nonidentical external schemas is not
            # comparable without a typed union/schema proof.
            return False
        hidden.update(str(item) for item in props.get("hidden_attrs", ()))
        order = tuple(str(item) for item in props.get("delivered_order", ()))
        if order and (not delivered_order or len(order) > len(delivered_order)):
            delivered_order = order
        materialized = materialized or bool(props.get("materialized"))
        lineage_preserved = lineage_preserved and sigma.branch_lineage == "preserved"
        safety_levels.extend(str(level) for level in sigma.safety.values())
        freshness_evidence.update(str(item) for item in props.get("freshness_evidence", ()))
        context_evidence.update(str(item) for item in props.get("context_evidence", ()))
        context_keys.update(str(item) for item in props.get("context_keys", ()))
        has_rid_carrier = has_rid_carrier and bool(
            sigma.rid_mat_props.get("carrier") and sigma.rid_mat_props.get("rid_domain")
        )
    if visible_columns and tuple(visible or ()) != visible_columns:
        return False
    if required_order and delivered_order[: len(required_order)] != required_order:
        return False
    if required_context and not set(required_context).issubset(context_keys):
        return False
    safety_rank = {
        "unsafe_before_authorization": 0,
        "candidate": 1,
        "candidate_authorized": 1,
        "candidate_until_residual_discharge": 1,
        "engine_authorized": 2,
        "exact_authorized": 3,
    }
    if min_safety_level:
        required_rank = safety_rank.get(min_safety_level)
        if required_rank is None or not safety_levels:
            return False
        if any(safety_rank.get(level, -1) < required_rank for level in safety_levels):
            return False
    if freshness_predicate and not _root_predicate_evidence_satisfies(
        freshness_predicate, freshness_evidence
    ):
        return False
    if context_predicate and not _root_predicate_evidence_satisfies(
        context_predicate, context_evidence
    ):
        return False
    if future_rid_intersection and not has_rid_carrier:
        return False
    if needs_branch_lineage and not lineage_preserved:
        return False
    for required in observable_coverage:
        if required == "materialized":
            if not materialized:
                return False
        elif required.startswith("hidden_carrier:"):
            if required.split(":", 1)[1] not in hidden:
                return False
        elif required.startswith("branch_tag:"):
            branch_tag = required.split(":", 1)[1]
            if not lineage_preserved or branch_tag not in hidden:
                return False
        else:
            # Unknown observable requirements are intentionally not guessed.
            return False
    return True


def _root_predicate_evidence_satisfies(predicate: str, evidence: set[str]) -> bool:
    """Require explicit validator evidence for every finite rho predicate atom."""

    atoms = tuple(item.strip() for item in predicate.split(" && ") if item.strip())
    return bool(atoms) and set(atoms).issubset(evidence)


def _residual_discharge_evidence_is_valid(
    sigmas: Sequence[Sigma],
    *,
    obligation_graph: ObligationGraph,
) -> bool:
    """Validate any recorded RCheck against its pre-candidate deadline.

    Exact leaf alternatives need no RCheck at all.  When a candidate residual
    is discharged, however, the record must identify the exact residual and a
    lineage-covered logical occurrence; a forged or after-the-fact record is
    rejected instead of being treated as a boolean success flag.
    """

    deadlines = tuple(obligation_graph.residual_deadlines)
    for sigma in sigmas:
        raw_records = sigma.phys_props.get("discharged_residuals", ())
        if not isinstance(raw_records, (list, tuple)):
            return False
        for raw in raw_records:
            if not isinstance(raw, Mapping):
                return False
            basis_id = str(raw.get("basis_id") or "")
            omega_id = str(raw.get("omega_id") or "")
            check_id = str(raw.get("check_id") or "")
            deadline = str(raw.get("deadline") or "")
            witness_id = str(raw.get("recoverability_witness_id") or "")
            witness_digest = str(
                raw.get("recoverability_witness_digest") or ""
            )
            gamma_snapshot_id = str(raw.get("gamma_snapshot_id") or "")
            evidence_mode = str(raw.get("evidence_mode") or "")
            if (
                not witness_id.startswith("sha256:")
                or len(witness_id) != 71
                or not witness_digest.startswith("sha256:")
                or len(witness_digest) != 71
                or not gamma_snapshot_id
                or evidence_mode not in RECOVERABILITY_EVIDENCE_MODES
            ):
                return False
            matched = False
            for item in deadlines:
                expected_basis = f"{item.occurrence_id}:out"
                expected_check = f"{item.policy_id}:exact_residual"
                if (
                    actual_basis_covers_logical(
                        basis_id,
                        expected_basis,
                        allowed_transforms=obligation_graph.transforms_for_basis(expected_basis),
                    )
                    and omega_id == expected_check
                    and check_id == expected_check
                    and deadline == item.deadline
                ):
                    matched = True
                    break
            if not matched:
                return False
    return True
