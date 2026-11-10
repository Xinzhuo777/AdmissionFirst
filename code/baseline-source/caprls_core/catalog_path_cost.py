"""Cost contract for the bounded caprls_catalog CustomScan witness."""

from __future__ import annotations

from dataclasses import dataclass


CATALOG_PATH_COST_BASE_SCAN_UNIT = 0.01
CATALOG_PATH_COST_POLICY_EVAL_UNIT = 0.02
CATALOG_PATH_COST_ARTIFACT_LOOKUP_STARTUP = 0.05
CATALOG_PATH_COST_ARTIFACT_BASE_FETCH_UNIT = 0.01


@dataclass(frozen=True)
class CatalogPathCostBreakdown:
    template_id: str
    rows: float
    startup_cost: float
    row_cost: float
    total_cost: float


def positive_or(value: float, fallback: float) -> float:
    if value > 0.0:
        return value
    if fallback > 0.0:
        return fallback
    return 1.0


def bounded_catalog_path_cost(
    *,
    template_id: str,
    base_rows: float,
    artifact_rows: float,
    subpath_rows: float = 1.0,
) -> CatalogPathCostBreakdown:
    """Mirror caprls_catalog.c::caprls_catalog_cost_for_template."""

    if template_id == "CaprlsAuthIndexPath":
        rows = positive_or(artifact_rows, subpath_rows)
        startup = CATALOG_PATH_COST_ARTIFACT_LOOKUP_STARTUP
        row_cost = rows * CATALOG_PATH_COST_ARTIFACT_BASE_FETCH_UNIT
        return CatalogPathCostBreakdown(
            template_id=template_id,
            rows=rows,
            startup_cost=startup,
            row_cost=row_cost,
            total_cost=startup + row_cost,
        )

    rows = positive_or(base_rows, subpath_rows)
    row_cost = rows * (
        CATALOG_PATH_COST_BASE_SCAN_UNIT
        + CATALOG_PATH_COST_POLICY_EVAL_UNIT
    )
    return CatalogPathCostBreakdown(
        template_id=template_id,
        rows=rows,
        startup_cost=0.0,
        row_cost=row_cost,
        total_cost=row_cost,
    )
