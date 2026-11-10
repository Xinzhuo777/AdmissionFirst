"""BarrierFilter SQL emitter."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BarrierFilterPlan:
    template_id: str
    alternative: str
    emitted_sql: str
    delivered_sigma: dict
    generated_templates: int
    rejected_templates: int
    costed_templates: int
    rejection_reasons: dict
    estimated_cost: float


def emit_barrier_filter_sql(
    relname: str,
    alias: str,
    rid_col: str,
    predicate_sql: str,
    visible_columns: list[str],
) -> BarrierFilterPlan:
    if not visible_columns:
        raise ValueError("BarrierFilter requires at least one visible column")
    projected = ", ".join(f"auth.{column}" for column in visible_columns)
    sql = f"""WITH auth AS MATERIALIZED (
  SELECT {alias}.*, {alias}.{rid_col} AS __rid
  FROM public.{relname} {alias}
  WHERE {predicate_sql}
)
SELECT {projected}
FROM auth
ORDER BY auth.{rid_col};"""
    delivered_sigma = {
        "Dom": {"occurrence_id": "document_occ_1", "relation": relname},
        "AuthSet": "exact",
        "Residual": [],
        "SafetyLevel": "exact_authorized",
        "Freshness": "non_artifact_exact",
        "ContextScope": "bound_context",
        "RIDMatProps": {
            "rid_domain": f"{relname}.{rid_col}",
            "surrogate_col": rid_col,
            "carrier": "__rid",
        },
        "PhysProps": {"materialized": True, "order": [rid_col]},
    }
    return BarrierFilterPlan(
        template_id="barrier_filter_v1",
        alternative="BarrierFilter",
        emitted_sql=sql,
        delivered_sigma=delivered_sigma,
        generated_templates=1,
        rejected_templates=0,
        costed_templates=1,
        rejection_reasons={},
        estimated_cost=0.0,
    )
