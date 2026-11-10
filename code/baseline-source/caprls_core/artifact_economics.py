"""Shared artifact-cost economics used by planners and E8 accounting."""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class ArtifactEconomics:
    query_ms: float
    build_ms: float = 0.0
    maintenance_ms_total: float = 0.0
    fallback_ms: float = 0.0
    reuse: int = 1


def estimated_invalidation_count(
    *,
    update_rate_per_hour: float,
    ttl_s: float,
    contexts: int,
) -> int:
    update_pressure = max(0.0, update_rate_per_hour) * (max(0.0, ttl_s) / 3600.0)
    return int(math.ceil(update_pressure * max(1, contexts / 1000)))


def maintenance_total_ms(*, maintenance_unit_ms: float, invalidation_count: int) -> float:
    return max(0.0, maintenance_unit_ms) * max(0, invalidation_count)


def amortized_artifact_latency_ms(economics: ArtifactEconomics) -> float:
    q = max(1, int(economics.reuse))
    return (
        max(0.0, economics.build_ms)
        + max(0.0, economics.maintenance_ms_total)
        + max(0.0, economics.fallback_ms)
        + q * max(0.0, economics.query_ms)
    ) / q


def declared_q_u_amortized_ms(
    *,
    query_ms: float,
    build_ms: float,
    maintenance_unit_ms: float,
    invalidation_count: int,
    fallback_ms: float,
    reuse: int,
) -> float:
    return amortized_artifact_latency_ms(
        ArtifactEconomics(
            query_ms=query_ms,
            build_ms=build_ms,
            maintenance_ms_total=maintenance_total_ms(
                maintenance_unit_ms=maintenance_unit_ms,
                invalidation_count=invalidation_count,
            ),
            fallback_ms=fallback_ms,
            reuse=reuse,
        )
    )
