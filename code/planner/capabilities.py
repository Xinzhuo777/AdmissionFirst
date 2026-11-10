"""Concrete capability registries used by the canonical template catalog.

The catalog records stable capability identifiers instead of importing planner
implementation modules.  This module is the small runtime bridge that proves
those identifiers resolve to real callable implementations.  Keeping the
registries here prevents a non-empty string in ``TemplateDefinition`` from
being mistaken for an implemented certificate or cost path.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any, Callable, Mapping

from .certificates import emit_flat_certificate


def _transfer_certificate_builder(*args: Any, **kwargs: Any) -> Any:
    """Canonical certificate builder for the finite transfer fragment."""

    return emit_flat_certificate(*args, **kwargs)


def _finite_cost_model(template: Any, problem: Any, *, estimator: Any) -> float:
    """Invoke the supplied finite cost model without creating an import cycle.

    ``planner.core`` owns the model instance and its frozen weights.  Passing
    it in is deliberate: this registry establishes capability identity, not a
    second or tunable cost function.
    """

    return float(estimator.estimate(template, problem))


CERTIFICATE_BUILDERS: Mapping[str, Callable[..., Any]] = MappingProxyType(
    {"transfer_certificate_v1": _transfer_certificate_builder}
)
COST_EXTRACTORS: Mapping[str, Callable[..., float]] = MappingProxyType(
    {"finite_cost_model_v1": _finite_cost_model}
)


def certificate_builder(capability_id: str) -> Callable[..., Any]:
    try:
        return CERTIFICATE_BUILDERS[capability_id]
    except KeyError as exc:
        raise KeyError(f"unknown certificate builder capability: {capability_id}") from exc


def cost_extractor(capability_id: str) -> Callable[..., float]:
    try:
        return COST_EXTRACTORS[capability_id]
    except KeyError as exc:
        raise KeyError(f"unknown cost extractor capability: {capability_id}") from exc
