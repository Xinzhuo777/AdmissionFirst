"""Canonical evaluation-mode identities and the public mode registry."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, Mapping

import yaml


MODE_REGISTRY_SCHEMA_VERSION = "caprls-baseline-modes-v2"

ADMISSION_FIRST_MODE = "admission-first"
ADMISSION_FIRST_NO_DOMINANCE_MODE = "admission-first-no-dominance"
LEGACY_CONTRACT_AWARE_MODE = "contract-aware"
LEGACY_CONTRACT_AWARE_NO_DOMINANCE_MODE = "contract-aware-no-dominance"


class EvaluationRole(str, Enum):
    """Reader-facing role of a mode in the evaluation."""

    POLICY_ENFORCEMENT = "policy_enforcement"
    CONTRACT_VIOLATION_CONTROL = "contract_violation_control"
    CONSERVATIVE_CONTROL = "conservative_control"
    FINITE_TEMPLATE_UPPER_BOUND = "finite_template_upper_bound"


ALLOWED_EVALUATION_ROLES = frozenset(role.value for role in EvaluationRole)
POLICY_ENFORCEMENT_ROLE = EvaluationRole.POLICY_ENFORCEMENT.value
CONTRACT_VIOLATION_CONTROL_ROLE = EvaluationRole.CONTRACT_VIOLATION_CONTROL.value
CONSERVATIVE_CONTROL_ROLE = EvaluationRole.CONSERVATIVE_CONTROL.value
FINITE_TEMPLATE_UPPER_BOUND_ROLE = EvaluationRole.FINITE_TEMPLATE_UPPER_BOUND.value

# Retained only for caprls-run-v1/v2 ingestion and compatibility output.
LEGACY_ROLE_ALIASES = {
    "production_safe": EvaluationRole.POLICY_ENFORCEMENT.value,
    "diagnostic_unsafe": EvaluationRole.CONTRACT_VIOLATION_CONTROL.value,
    "diagnostic_conservative": EvaluationRole.CONSERVATIVE_CONTROL.value,
    "finite_template_upper_bound": EvaluationRole.FINITE_TEMPLATE_UPPER_BOUND.value,
}
ALLOWED_BASELINE_CLASSES = frozenset(LEGACY_ROLE_ALIASES)

LEGACY_MODE_ALIASES = {
    LEGACY_CONTRACT_AWARE_MODE: ADMISSION_FIRST_MODE,
    LEGACY_CONTRACT_AWARE_NO_DOMINANCE_MODE: ADMISSION_FIRST_NO_DOMINANCE_MODE,
}

# Former lexicographic order of the legacy mode ids.  Keeping it independent of
# public spelling prevents a rename from changing cache/warm-up order or a
# report's deterministic representative.
MODE_EXECUTION_ORDER = (
    "auth-index-enum-only",
    "auth-view-only",
    "barrier-only",
    "conservative-barrier",
    ADMISSION_FIRST_MODE,
    ADMISSION_FIRST_NO_DOMINANCE_MODE,
    "guard-late-only",
    "guard-mandatory-discharge",
    "incomplete-guard-candidate",
    "injection-only",
    "local-greedy",
    "manual-sql-rewrite-best-effort",
    "mav-no-version",
    "mav-only",
    "naive-artifact-only",
    "naive-auth-index-no-scope",
    "native-pg-rls",
    "native-pg-rls-physical-design",
    "no-branch-lineage",
    "no-context-scope",
    "no-domain",
    "no-freshness",
    "no-phys-props",
    "no-residual",
    "no-rid-props",
    "no-safety-level",
    "ordinary-no-contract",
    "rid-domain-blind-intersection",
    "security-barrier",
    "stale-artifact-user",
    "strong-auth-index",
    "template-oracle",
    "unsafe-pushdown-positive-control",
    "wrong-context-artifact-user",
)
CANONICAL_MODE_IDS = frozenset(MODE_EXECUTION_ORDER)
_MODE_EXECUTION_ORDER_KEYS = {
    mode: index for index, mode in enumerate(MODE_EXECUTION_ORDER)
}
_SCIENTIFIC_MODE_KEYS = {
    ADMISSION_FIRST_MODE: LEGACY_CONTRACT_AWARE_MODE,
    ADMISSION_FIRST_NO_DOMINANCE_MODE: LEGACY_CONTRACT_AWARE_NO_DOMINANCE_MODE,
}


def normalize_mode_id(mode: str) -> str:
    """Return one canonical mode id, rejecting unknown identities."""

    if not isinstance(mode, str) or not mode:
        raise ValueError(f"invalid mode id {mode!r}")
    canonical = LEGACY_MODE_ALIASES.get(mode, mode)
    if canonical not in CANONICAL_MODE_IDS:
        raise ValueError(f"unknown mode id {mode!r}")
    return canonical


def normalize_evaluation_role(role: str) -> str:
    """Return one canonical evaluation role, including legacy wire aliases."""

    if not isinstance(role, str) or not role:
        raise ValueError(f"invalid evaluation role {role!r}")
    canonical = LEGACY_ROLE_ALIASES.get(role, role)
    if canonical not in ALLOWED_EVALUATION_ROLES:
        raise ValueError(f"unknown evaluation role {role!r}")
    return canonical


def mode_execution_order_key(mode: str) -> int:
    """Return the stable execution-order ordinal for a canonical or legacy id."""

    return _MODE_EXECUTION_ORDER_KEYS[normalize_mode_id(mode)]


def scientific_mode_key(mode: str) -> str:
    """Return the rename-invariant identity used by hashes, seeds, and digests."""

    canonical = normalize_mode_id(mode)
    return _SCIENTIFIC_MODE_KEYS.get(canonical, canonical)


@dataclass(frozen=True)
class ModeSpec:
    mode: str
    evaluation_role: str
    paper_label: str
    execution_order_key: int
    notes: str = ""


def load_mode_registry(root: Path) -> Dict[str, ModeSpec]:
    """Load the canonical implementation-facing evaluation-mode registry."""

    path = root / "manifests" / "baselines" / "modes.yaml"
    if not path.exists():
        raise FileNotFoundError(f"missing baseline mode registry: {path}")

    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    if data.get("schema_version") != MODE_REGISTRY_SCHEMA_VERSION:
        raise ValueError(
            f"{path}: expected schema_version {MODE_REGISTRY_SCHEMA_VERSION!r}"
        )
    modes = data.get("modes")
    if not isinstance(modes, Mapping):
        raise ValueError(f"{path}: expected top-level 'modes' mapping")

    registry: Dict[str, ModeSpec] = {}
    for raw_mode, spec in modes.items():
        if not isinstance(spec, Mapping):
            raise ValueError(f"{path}: mode {raw_mode!r} must map to an object")
        mode = str(raw_mode)
        try:
            canonical_mode = normalize_mode_id(mode)
        except ValueError as exc:
            raise ValueError(f"{path}: {exc}") from exc
        if canonical_mode != mode:
            raise ValueError(f"{path}: legacy mode id {mode!r} is not allowed in v2")
        if "baseline_class" in spec:
            raise ValueError(
                f"{path}: mode {mode!r} must use evaluation_role, not baseline_class"
            )
        evaluation_role = spec.get("evaluation_role")
        if evaluation_role not in ALLOWED_EVALUATION_ROLES:
            raise ValueError(
                f"{path}: mode {mode!r} has invalid canonical evaluation_role "
                f"{evaluation_role!r}"
            )
        paper_label = spec.get("paper_label")
        notes = spec.get("notes", "")
        execution_order_key = spec.get("execution_order_key")
        expected_order_key = mode_execution_order_key(mode)
        if type(execution_order_key) is not int or execution_order_key != expected_order_key:
            raise ValueError(
                f"{path}: mode {mode!r} must have execution_order_key "
                f"{expected_order_key}, got {execution_order_key!r}"
            )
        if not paper_label:
            raise ValueError(f"{path}: mode {mode!r} is missing paper_label")
        registry[mode] = ModeSpec(
            mode=mode,
            evaluation_role=evaluation_role,
            paper_label=str(paper_label),
            execution_order_key=execution_order_key,
            notes=str(notes),
        )

    missing = CANONICAL_MODE_IDS - set(registry)
    extra = set(registry) - CANONICAL_MODE_IDS
    if missing or extra:
        raise ValueError(
            f"{path}: canonical mode inventory mismatch; "
            f"missing={sorted(missing)!r}, extra={sorted(extra)!r}"
        )
    if len({spec.execution_order_key for spec in registry.values()}) != len(registry):
        raise ValueError(f"{path}: execution_order_key values must be unique")

    return registry
