"""Offline carrier-projection equivalence checks for R-8."""

from __future__ import annotations

from .baselines import (
    ADMISSION_FIRST_MODE,
)

import json
import sqlite3
from dataclasses import dataclass
from typing import Any, Mapping

from planner.ir import Project, walk

from .e2_smoke import _document_carrier_projection_sql, _e2_planning_problem, _e2_planning_query
from .e3_main import (
    E3_CARRIER_PROJECTION_COLUMNS,
    POLICY_CONFIGS,
    QUERIES,
    _carrier_projection_sql as _e3_carrier_projection_sql,
    _e3_planning_problem,
    _e3_planning_query,
    _e3_required_hidden_carriers,
)
from .e10_study import (
    CASES,
    _carrier_projection_sql as _e10_carrier_projection_sql,
    _planning_problem_for_case,
    _planning_query_for_case,
    _e10_required_hidden_carriers,
    _target_for_case,
)


@dataclass(frozen=True)
class CarrierProjectionIssue:
    path: str
    message: str


@dataclass(frozen=True)
class CarrierProjectionReport:
    issues: tuple[CarrierProjectionIssue, ...]
    details: Mapping[str, Any]

    @property
    def ok(self) -> bool:
        return not self.issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "details": dict(self.details),
            "issues": [issue.__dict__ for issue in self.issues],
        }


def _install_sqlite_fixture(conn: sqlite3.Connection) -> None:
    conn.execute("ATTACH DATABASE ':memory:' AS public")
    conn.executescript(
        """
        CREATE TABLE public.document (
          doc_id integer PRIMARY KEY,
          tenant_id integer NOT NULL,
          owner_id integer NOT NULL,
          public boolean NOT NULL,
          secret text NOT NULL,
          payload text NOT NULL
        );
        CREATE TABLE public.ticket (
          ticket_id integer PRIMARY KEY,
          tenant_id integer NOT NULL,
          owner_id integer NOT NULL,
          status text NOT NULL,
          priority integer NOT NULL,
          payload text NOT NULL
        );
        CREATE TABLE public.invoice (
          invoice_id integer PRIMARY KEY,
          region text NOT NULL,
          account_id integer NOT NULL,
          purpose text NOT NULL,
          payload text NOT NULL
        );
        CREATE TABLE public.tpch_customer (
          c_custkey integer PRIMARY KEY,
          c_mktsegment text NOT NULL,
          region_id integer NOT NULL,
          tenant_id integer NOT NULL,
          payload text NOT NULL
        );
        CREATE TABLE public.job_title (
          t_id integer PRIMARY KEY,
          kind text NOT NULL,
          production_year integer NOT NULL,
          region_id integer NOT NULL,
          studio_id integer NOT NULL,
          payload text NOT NULL
        );
        INSERT INTO public.document(doc_id, tenant_id, owner_id, public, secret, payload)
        VALUES
          (1, 10, 7, 1, 's1', 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'),
          (2, 10, 8, 0, 's2', 'yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy'),
          (3, 20, 7, 1, 's3', 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz');
        INSERT INTO public.ticket(ticket_id, tenant_id, owner_id, status, priority, payload)
        VALUES
          (1, 10, 7, 'open', 5, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
          (2, 10, 8, 'closed', 2, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),
          (3, 20, 7, 'open', 4, 'cccccccccccccccccccccccccccccccc');
        INSERT INTO public.invoice(invoice_id, region, account_id, purpose, payload)
        VALUES
          (1, 'emea', 101, 'audit', 'iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii'),
          (2, 'amer', 102, 'billing', 'jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj'),
          (3, 'emea', 103, 'billing', 'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk');
        INSERT INTO public.tpch_customer(c_custkey, c_mktsegment, region_id, tenant_id, payload)
        VALUES
          (1, 'BUILDING', 1, 10, 'mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm'),
          (2, 'AUTOMOBILE', 2, 10, 'nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn'),
          (3, 'BUILDING', 3, 20, 'oooooooooooooooooooooooooooooooo');
        INSERT INTO public.job_title(t_id, kind, production_year, region_id, studio_id, payload)
        VALUES
          (1, 'movie', 2001, 1, 11, 'pppppppppppppppppppppppppppppppp'),
          (2, 'series', 2002, 2, 12, 'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq'),
          (3, 'movie', 2003, 3, 13, 'rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr');
        """
    )


def _digest(conn: sqlite3.Connection, sql: str) -> dict[str, Any]:
    cursor = conn.execute(sql.strip().rstrip(";"))
    rows = [dict(row) for row in cursor.fetchall()]
    rendered = json.dumps(rows, sort_keys=True, separators=(",", ":"))
    return {"row_count": len(rows), "row_hash": rendered}


def _projection_digest_pair(
    conn: sqlite3.Connection,
    *,
    relation: str,
    alias: str,
    rid_col: str,
    predicate: str,
    new_projection: str,
    selected_columns: tuple[str, ...],
    materialized: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    materialization = "MATERIALIZED" if materialized else "NOT MATERIALIZED"
    select_list = ", ".join(f"{alias}.{column}" for column in selected_columns)
    order_by = ", ".join(f"{alias}.{column}" for column in selected_columns)
    old_sql = f"""
    WITH auth AS {materialization} (
      SELECT {alias}.*, {alias}.{rid_col} AS __rid
      FROM public.{relation} {alias}
      WHERE {predicate}
    )
    SELECT {select_list}
    FROM auth {alias}
    ORDER BY {order_by}
    """
    new_sql = f"""
    WITH auth AS {materialization} (
      SELECT {new_projection}
      FROM public.{relation} {alias}
      WHERE {predicate}
    )
    SELECT {select_list}
    FROM auth {alias}
    ORDER BY {order_by}
    """
    return _digest(conn, old_sql), _digest(conn, new_sql)


def _check_projection_pair(
    conn: sqlite3.Connection,
    issues: list[CarrierProjectionIssue],
    *,
    label: str,
    relation: str,
    alias: str,
    rid_col: str,
    predicate: str,
    new_projection: str,
    selected_columns: tuple[str, ...],
    materialized: bool = True,
) -> bool:
    old_digest, new_digest = _projection_digest_pair(
        conn,
        relation=relation,
        alias=alias,
        rid_col=rid_col,
        predicate=predicate,
        new_projection=new_projection,
        selected_columns=selected_columns,
        materialized=materialized,
    )
    if old_digest != new_digest:
        issues.append(
            CarrierProjectionIssue(
                label,
                "carrier projection changed row-count/hash: "
                f"full={old_digest}, projected={new_digest}",
            )
        )
        return False
    return True


def _project_carriers(node: object) -> list[tuple[tuple[str, ...], tuple[str, ...]]]:
    return [
        (project.visible_A, project.hidden_H)
        for project in walk(node)
        if isinstance(project, Project)
    ]


def validate_carrier_projection_equivalence() -> CarrierProjectionReport:
    issues: list[CarrierProjectionIssue] = []
    details: dict[str, Any] = {
        "schema_version": "caprls-carrier-projection-audit-v1",
        "projection_checks": 0,
        "projection_equivalence_passed": 0,
        "project_carrier_checks": 0,
        "project_carrier_passed": 0,
        "experiments": {},
    }
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    try:
        _install_sqlite_fixture(conn)

        e2_passed = 0
        for predicate in (
            "d.tenant_id = 10",
            "d.tenant_id = 10 AND d.owner_id = 7",
        ):
            details["projection_checks"] += 1
            if _check_projection_pair(
                conn,
                issues,
                label=f"E2/{predicate}",
                relation="document",
                alias="d",
                rid_col="doc_id",
                predicate=predicate,
                new_projection=_document_carrier_projection_sql("d"),
                selected_columns=("doc_id", "tenant_id", "owner_id", "public", "__rid"),
            ):
                e2_passed += 1
                details["projection_equivalence_passed"] += 1

        e3_passed = 0
        for query in QUERIES:
            selected = tuple(E3_CARRIER_PROJECTION_COLUMNS[query.query_id]) + ("__rid",)
            predicate = f"{query.alias}.{query.rid_col} IN (1, 3)"
            for materialized in (True, False):
                details["projection_checks"] += 1
                if _check_projection_pair(
                    conn,
                    issues,
                    label=f"E3/{query.query_id}/materialized={materialized}",
                    relation=query.protected_rel,
                    alias=query.alias,
                    rid_col=query.rid_col,
                    predicate=predicate,
                    new_projection=_e3_carrier_projection_sql(query),
                    selected_columns=selected,
                    materialized=materialized,
                ):
                    e3_passed += 1
                    details["projection_equivalence_passed"] += 1

        e10_passed = 0
        seen: set[tuple[str, str, str, str]] = set()
        for case in CASES:
            relname, rid_col, _policy_id, alias = _target_for_case(case)
            key = (case.query_id, relname, rid_col, alias)
            if key in seen:
                continue
            seen.add(key)
            if relname == "invoice":
                selected = (rid_col, "region", "account_id", "__rid")
            elif relname == "ticket":
                selected = (rid_col, "tenant_id", "owner_id", "status", "priority", "__rid")
            else:
                selected = (rid_col, "tenant_id", "owner_id", "public", "__rid")
            details["projection_checks"] += 1
            if _check_projection_pair(
                conn,
                issues,
                label=f"E10/{case.query_id}",
                relation=relname,
                alias=alias,
                rid_col=rid_col,
                predicate=f"{alias}.{rid_col} IN (1, 3)",
                new_projection=_e10_carrier_projection_sql(
                    case=case,
                    relname=relname,
                    rid_col=rid_col,
                    alias=alias,
                ),
                selected_columns=selected,
            ):
                e10_passed += 1
                details["projection_equivalence_passed"] += 1

        e2_problem = _e2_planning_problem(
            policy_id="tenant_group",
            total_rows=100,
            authorized_rows=20,
            artifact_availability="auth_idx",
            artifact_cardinality=20,
            s_q=0.1,
            policy_cost="cheap",
        )
        e2_query = _e2_planning_query(e2_problem, ADMISSION_FIRST_MODE)
        expected_e2 = [((e2_problem.rid_col,), ("__rid",))]
        details["project_carrier_checks"] += 1
        if _project_carriers(e2_query.ir_skeleton) == expected_e2:
            details["project_carrier_passed"] += 1
        else:
            issues.append(
                CarrierProjectionIssue(
                    "E2/project",
                    "Project carrier set does not match the declared carrier inventory",
                )
            )

        e3_project_passed = 0
        policy = next(item for item in POLICY_CONFIGS if item.config_id == "cheap_tenant_sargable")
        for query in QUERIES:
            problem = _e3_planning_problem(
                query,
                policy,
                protected_rows=100,
                query_local_rows=10,
                authorized_rows=20,
                build_ms=1.0,
            )
            planning_query = _e3_planning_query(query, policy, problem, ADMISSION_FIRST_MODE)
            expected = [((query.rid_col,), _e3_required_hidden_carriers(query))]
            details["project_carrier_checks"] += 1
            if _project_carriers(planning_query.ir_skeleton) == expected:
                e3_project_passed += 1
                details["project_carrier_passed"] += 1
            else:
                issues.append(
                    CarrierProjectionIssue(
                        f"E3/{query.query_id}/project",
                        "Project carrier set does not match the declared carrier inventory",
                    )
                )

        e10_project_passed = 0
        for case in CASES:
            relname, rid_col, policy_id, _alias = _target_for_case(case)
            problem = _planning_problem_for_case(
                case,
                relname,
                rid_col,
                policy_id,
                artifacts={},
                base_rows=100,
                filtered_rows=10,
            )
            planning_query = _planning_query_for_case(case, problem=problem, mode=ADMISSION_FIRST_MODE)
            expected = [((rid_col,), _e10_required_hidden_carriers(case))]
            details["project_carrier_checks"] += 1
            if _project_carriers(planning_query.ir_skeleton) == expected:
                e10_project_passed += 1
                details["project_carrier_passed"] += 1
            else:
                issues.append(
                    CarrierProjectionIssue(
                        f"E10/{case.query_id}/project",
                        "Project carrier set does not match the declared carrier inventory",
                    )
                )
    finally:
        conn.close()

    details["experiments"] = {
        "E2": {
            "projection_passed": e2_passed,
            "projection_total": 2,
            "project_carrier_passed": 1,
            "project_carrier_total": 1,
        },
        "E3": {
            "projection_passed": e3_passed,
            "projection_total": len(QUERIES) * 2,
            "project_carrier_passed": e3_project_passed,
            "project_carrier_total": len(QUERIES),
        },
        "E10": {
            "projection_passed": e10_passed,
            "projection_total": len(seen),
            "project_carrier_passed": e10_project_passed,
            "project_carrier_total": len(CASES),
        },
    }
    return CarrierProjectionReport(tuple(issues), details)
