"""Run Doc admission and MVCC checks against a fresh private PostgreSQL database."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

from native_af.bench.libpq import LibPQ, QueryError


READER = "af_doc_reader"
OTHER = "af_doc_other"
MODES = ("native", "af", "index_priority")
MEMBERSHIP = "SELECT id, title FROM public.doc"
EXPORT = MEMBERSHIP + " WHERE topic >= 0 ORDER BY id DESC LIMIT 3"
AUDIT = MEMBERSHIP + " WHERE public.af_doc_audit(id, secret)"
DROP = "SELECT title FROM public.doc WHERE topic = 7"
KEEP = DROP + " ORDER BY id"
ROW_COLUMNS = (("id", 20), ("title", 25))
DOCS = {
    1: ("duplicate", "shared-one"),
    2: ("duplicate", "shared-two"),
    3: ("other-topic", "shared-other-topic"),
    4: (None, "revoked"),
    6: (None, "newly-granted"),
    8: ("other-reader", "deny-other-reader"),
    10: ("group-switch", "new-membership"),
}
INITIAL = (1, 2, 3, 4)
AFTER_REVOKE = (1, 2, 3)
AFTER_GRANT = (1, 2, 3, 6)
AFTER_MEMBERSHIP_CHANGE = (1, 2, 6, 10)
NOTICE = re.compile(r"^(?:NOTICE:\s+)?af_doc_observed (\[.*\])$")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def trace(stream, **event):
    stream.write(json.dumps(event, ensure_ascii=False, allow_nan=False) + "\n")
    stream.flush()


def check_role(connection, role, mode, stream, stock):
    if not stock:
        connection.execute(f"SET native_af.mode = '{mode}'")
    connection.execute("SET max_parallel_workers_per_gather = 0")
    connection.execute("SET row_security = on")
    connection.execute("SET client_min_messages = notice")
    result = connection.execute(
        "SELECT session_user, current_user, rolsuper, rolbypassrls, "
        "row_security_active('public.doc'), pg_backend_pid() "
        "FROM pg_roles WHERE rolname = current_user"
    )
    trace(stream, mode=mode, check="session_role", rows=result.rows)
    require(len(result.rows) == 1 and result.rows[0][:5] == (role, role, "f", "f", "t"),
            f"{mode}: {role} must be a direct, unprivileged login with active RLS")
    return result.rows[0][5]


def query(connection, sql, expected, columns, ordered, mode, phase, stream):
    before = len(connection.notices)
    result = connection.execute(sql)
    trace(stream, mode=mode, phase=phase, check="rows", sql=sql,
          columns=result.columns, rows=result.rows, expected=expected, ordered=ordered,
          notices=connection.notices[before:])
    require(result.columns == columns, f"{mode}/{phase}: wrong columns for {sql}")
    equal = result.rows == expected if ordered else Counter(result.rows) == Counter(expected)
    require(equal, f"{mode}/{phase}: wrong rows for {sql}")


def observations(notices):
    return [
        tuple(json.loads(match.group(1)))
        for notice in notices
        for line in notice.splitlines()
        if (match := NOTICE.fullmatch(line.strip()))
    ]


def check_observations(notices, ids, mode, phase, stream):
    seen = observations(notices)
    expected = [(doc_id, DOCS[doc_id][1]) for doc_id in ids]
    trace(stream, mode=mode, phase=phase, check="observations",
          notices=notices, seen=seen, expected=expected)
    require(Counter(seen) == Counter(expected),
            f"{mode}/{phase}: non-leakproof audit must observe all and only the allowed rows")


def explain(connection, sql, mode, phase, stream):
    before = len(connection.notices)
    result = connection.execute("EXPLAIN (ANALYZE, TIMING OFF, FORMAT JSON) " + sql)
    plan = json.loads(result.rows[0][0])[0]
    notices = connection.notices[before:]
    trace(stream, mode=mode, phase=phase, check="executed_plan", sql=sql,
          plan=plan, notices=notices)
    return plan["Plan"], notices


def plan_nodes(plan):
    yield plan
    for child in plan.get("Plans", []):
        yield from plan_nodes(child)


def check_doc_paths(connection, mode, stream, require_sp):
    for label, sql, ordered in (("projection_drop", DROP, False), ("order_keep", KEEP, True)):
        query(connection, sql, (("duplicate",), ("duplicate",), (None,)), (("title", 25),),
              ordered, mode, label, stream)
        plan, _ = explain(connection, sql, mode, label, stream)
        require(plan["Actual Rows"] == 3 and plan["Actual Loops"] == 1,
                f"{mode}/{label}: EXPLAIN did not execute the query to completion")
        if mode == "af" and require_sp:
            check_sp_decision(plan, ordered)


def check_sp_decision(plan, ordered):
    evidence = next((node for node in plan_nodes(plan) if "AF SP Comparisons" in node), None)
    require(evidence is not None, "AF did not report an actual selection/projection comparison")
    admitted = evidence["AF SP Admitted And Costed"]
    rejected = evidence["AF SP Rejected Missing Carrier Before Cost"]
    pruned = evidence["AF SP Pruned"]
    comparisons = evidence["AF SP Comparisons"]
    require(evidence["AF SP Occurrence"] > 0 and evidence["AF SP Carrier Attribute"] == 1,
            "SP evidence did not bind the Doc occurrence and id")
    require(admitted == len(comparisons) + 1 and admitted >= 2 and
            evidence["AF SP Generated"] == admitted + rejected and
            evidence["AF SP Survivors"] == admitted - pruned,
            "SP evidence did not account for the candidates that actually entered comparison")
    if ordered:
        require(pruned == 0 and any(
            row["Root Requirement"] == row["Root Plus Carrier Requirement"] == "order_or_enforcer_mismatch"
            and not row["Index Needs Sort"] and row["Scan Needs Sort"] for row in comparisons
        ), "SP ordered continuation did not retain the scan on the order/enforcer mismatch")
    else:
        require(rejected > 0 and pruned == 1 and any(
            row["Root Requirement"] == row["Root Plus Carrier Requirement"] == "pass"
            and row["Index Cost With Enforcers"] <= row["Scan Cost With Enforcers"]
            and row["Index Rows"] == row["Scan Rows"]
            and not row["Index Needs Sort"] and not row["Scan Needs Sort"] for row in comparisons
        ), "SP unordered continuation did not reject carrier loss and prune an admitted scan")


def executed_membership(plan):
    nodes = list(plan_nodes(plan))
    for node in nodes:
        if (node.get("Custom Plan Provider") == "AF Membership Keys" and
                node.get("AF Path") == "enumerate_authorized_keys" and
                node.get("AF Authorization") == "fresh_exact_membership" and
                node.get("Actual Loops", 0) > 0):
            parameter = node.get("AF Key Parameter")
            if parameter is None:
                continue
            descendants = list(plan_nodes(node))[1:]
            return (any(child.get("Node Type") in ("Index Scan", "Index Only Scan")
                        and child.get("Relation Name") == "doc"
                        and f"ANY (${parameter})" in child.get("Index Cond", "")
                        and child.get("Actual Loops", 0) > 0 for child in descendants)
                    and any(init.get("Parent Relationship") == "InitPlan"
                            and init.get("Subplan Name", "").endswith(f"(returns ${parameter})")
                            and init.get("Actual Loops", 0) > 0
                            and {"share_acl", "group_membership"}.issubset(
                                child.get("Relation Name") for child in plan_nodes(init)
                            ) for init in nodes))
    return False


def check_snapshot(connection, ids, mode, phase, stream, require_membership=False):
    expected = tuple((str(doc_id), DOCS[doc_id][0]) for doc_id in ids)
    export = tuple((str(doc_id), DOCS[doc_id][0]) for doc_id in sorted(ids, reverse=True)[:3])
    snapshot = connection.execute("SELECT pg_current_snapshot()::text").rows[0][0]
    trace(stream, mode=mode, phase=phase, check="snapshot_marker", snapshot=snapshot)
    for sql in (MEMBERSHIP, "EXECUTE af_doc_membership"):
        query(connection, sql, expected, ROW_COLUMNS, False, mode, phase, stream)
    for sql in (EXPORT, "EXECUTE af_doc_export(0)"):
        query(connection, sql, export, ROW_COLUMNS, True, mode, phase, stream)

    before = len(connection.notices)
    query(connection, AUDIT, expected, ROW_COLUMNS, False, mode, phase, stream)
    check_observations(connection.notices[before:], ids, mode, phase, stream)
    plan, notices = explain(connection, AUDIT, mode, phase, stream)
    check_observations(notices, ids, mode, phase + "_explain", stream)
    require(plan["Actual Rows"] == len(ids) and plan["Actual Loops"] == 1,
            f"{mode}/{phase}: audit plan did not execute to completion")
    if require_membership:
        require(executed_membership(plan),
                f"{mode}/{phase}: audit did not exercise the authorized index boundary")

    for sql in (MEMBERSHIP, "EXECUTE af_doc_membership", "EXECUTE af_doc_export(0)"):
        plan, _ = explain(connection, sql, mode, phase, stream)
        if require_membership and sql != "EXECUTE af_doc_export(0)":
            require(executed_membership(plan),
                    f"{mode}/{phase}: fresh exact membership index and its InitPlan did not execute")


def prepared_state(connection):
    result = connection.execute(
        "SELECT name, prepare_time::text, generic_plans, custom_plans "
        "FROM pg_prepared_statements ORDER BY name"
    )
    return result.rows


def change(writer, statements, mode, phase, stream):
    for statement in statements:
        writer.execute(statement)
        trace(stream, mode=mode, phase=phase, check="writer", sql=statement)


def query_denied(connection, sql, mode, phase, stream):
    before = len(connection.notices)
    try:
        result = connection.execute(sql)
    except QueryError as error:
        notices = connection.notices[before:]
        trace(stream, mode=mode, phase=phase, check="permission_error", sql=sql,
              sqlstate=error.sqlstate, error=str(error), notices=notices)
        require(error.sqlstate == "42501" and not observations(notices),
                f"{mode}/{phase}: expected permission denial before audit")
    else:
        trace(stream, mode=mode, phase=phase, check="unexpected_success", sql=sql,
              rows=result.rows, notices=connection.notices[before:])
        raise AssertionError(f"{mode}/{phase}: {sql} unexpectedly succeeded")


def check_permissions(reader, writer, mode, stream):
    reader.execute("SET row_security = off")
    for sql in (AUDIT, "EXECUTE af_doc_membership"):
        query_denied(reader, sql, mode, "row_security_off", stream)
    reader.execute("SET row_security = on")

    change(writer, ("REVOKE SELECT ON public.share_acl FROM af_doc_reader",),
           mode, "acl_relation_privilege_revoke", stream)
    for sql in (AUDIT, "EXECUTE af_doc_membership"):
        query_denied(reader, sql, mode, "acl_relation_privilege_revoke", stream)
    change(writer, ("GRANT SELECT ON public.share_acl TO af_doc_reader",),
           mode, "acl_relation_privilege_restore", stream)

    change(writer, ("CREATE POLICY doc_restrictive ON public.doc AS RESTRICTIVE "
                    "FOR SELECT TO af_doc_reader USING (id <> 1)",),
           mode, "restrictive_policy_added", stream)
    check_snapshot(reader, (2, 6, 10), mode, "restrictive_policy", stream)
    change(writer, ("DROP POLICY doc_restrictive ON public.doc",),
           mode, "restrictive_policy_dropped", stream)

    reader.execute("SET ROLE af_doc_other")
    result = reader.execute("SELECT session_user, current_user, row_security_active('public.doc')")
    trace(stream, mode=mode, phase="set_role", check="role_binding", rows=result.rows)
    require(result.rows == ((READER, OTHER, "t"),), f"{mode}: role rebinding failed")
    check_snapshot(reader, (8,), mode, "set_role", stream)
    reader.execute("RESET ROLE")
    check_snapshot(reader, AFTER_MEMBERSHIP_CHANGE, mode, "reset_role", stream)


def run_mode(lib, args, writer, mode, stream):
    connect = dict(socket_dir=args.socket_dir, port=args.port, database=args.database)
    with lib.connect(**connect, role=READER) as reader, lib.connect(**connect, role=OTHER) as other:
        writer_pid = writer.execute("SELECT pg_backend_pid()").rows[0][0]
        reader_pid = check_role(reader, READER, mode, stream, args.stock)
        other_pid = check_role(other, OTHER, mode, stream, args.stock)
        require(len({writer_pid, reader_pid, other_pid}) == 3,
                f"{mode}: fixture requires distinct server sessions")
        trace(stream, mode=mode, check="backend_pids",
              writer=writer_pid, reader=reader_pid, other=other_pid)
        reader.execute("SET plan_cache_mode = force_generic_plan")
        reader.execute("PREPARE af_doc_membership AS " + MEMBERSHIP)
        reader.execute("PREPARE af_doc_export(integer) AS " + EXPORT.replace(">= 0", ">= $1"))
        initial_prepared = prepared_state(reader)
        trace(stream, mode=mode, check="prepared_before", rows=initial_prepared)

        check_doc_paths(reader, mode, stream, args.require_sp)
        query(other, MEMBERSHIP, (("8", DOCS[8][0]),), ROW_COLUMNS,
              False, mode, "other_reader", stream)
        check_snapshot(reader, INITIAL, mode, "fresh", stream,
                       require_membership=mode == "index_priority" or
                       (mode == "af" and args.require_af_membership))

        # Pin the old snapshot. The writer's commit must not change what it sees.
        reader.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
        change(writer, ("BEGIN", "DELETE FROM public.share_acl WHERE relname = 'public.doc' "
                        "AND rid = 4 AND group_id = 1 AND permission = 'read'"),
               mode, "revoke_open", stream)
        check_snapshot(reader, INITIAL, mode, "revoke_uncommitted", stream)
        change(writer, ("COMMIT",), mode, "revoke_commit", stream)
        check_snapshot(reader, INITIAL, mode, "revoke_old_snapshot", stream)
        reader.execute("COMMIT")
        check_snapshot(reader, AFTER_REVOKE, mode, "revoke_new_snapshot", stream)

        change(writer, ("BEGIN", "INSERT INTO public.share_acl "
                        "(relname,rid,group_id,permission) VALUES ('public.doc',6,1,'read')"),
               mode, "grant_open", stream)
        check_snapshot(reader, AFTER_REVOKE, mode, "grant_uncommitted", stream)
        change(writer, ("COMMIT",), mode, "grant_commit", stream)
        check_snapshot(reader, AFTER_GRANT, mode, "grant_new_snapshot", stream)

        change(writer, ("BEGIN", "DELETE FROM public.group_membership WHERE "
                        "user_id = 'af_doc_reader' AND group_id = 2",
                        "INSERT INTO public.group_membership (user_id, group_id) "
                        "VALUES ('af_doc_reader', 4)", "COMMIT"),
               mode, "membership_commit", stream)
        check_snapshot(reader, AFTER_MEMBERSHIP_CHANGE, mode, "membership_new_snapshot", stream)
        query(other, MEMBERSHIP, (("8", DOCS[8][0]),), ROW_COLUMNS,
              False, mode, "other_reader_after_changes", stream)
        check_permissions(reader, writer, mode, stream)

        final_prepared = prepared_state(reader)
        trace(stream, mode=mode, check="prepared_after", rows=final_prepared)
        require(len(initial_prepared) == len(final_prepared) == 2,
                f"{mode}: both named prepared statements must persist")
        require([row[:2] for row in initial_prepared] == [row[:2] for row in final_prepared],
                f"{mode}: prepared statement identity changed")
        require(all(int(row[2]) > 1 and row[3] == "0" for row in final_prepared),
                f"{mode}: repeated execution did not use generic plans")

        change(writer, ("BEGIN", "INSERT INTO public.share_acl "
                        "(relname,rid,group_id,permission) VALUES ('public.doc',4,1,'read')",
                        "DELETE FROM public.share_acl WHERE relname = 'public.doc' "
                        "AND rid = 6 AND group_id = 1 AND permission = 'read'",
                        "INSERT INTO public.group_membership (user_id, group_id) "
                        "VALUES ('af_doc_reader', 2)",
                        "DELETE FROM public.group_membership WHERE "
                        "user_id = 'af_doc_reader' AND group_id = 4", "COMMIT"),
               mode, "reset_fixture", stream)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket-dir", required=True, type=Path)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--database", required=True)
    parser.add_argument("--admin", required=True)
    parser.add_argument("--libpq", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="Fresh JSONL evidence path")
    parser.add_argument("--stock", action="store_true", help="Check the fixture on unmodified PostgreSQL")
    parser.add_argument("--require-af-membership", action="store_true",
                        help="Also require the cost-based AF mode to choose fresh membership")
    parser.add_argument("--require-sp", action="store_true",
                        help="Require real SP candidate pruning and order-sensitive retention")
    args = parser.parse_args()
    if not args.socket_dir.is_dir():
        parser.error("--socket-dir must be a private test cluster's local socket directory")
    if args.stock and (args.require_af_membership or args.require_sp):
        parser.error("AF membership and SP decision checks require the native implementation")

    lib = LibPQ(args.libpq)
    with args.output.open("x", encoding="utf-8") as stream:
        try:
            with lib.connect(socket_dir=args.socket_dir, port=args.port,
                             database=args.database, role=args.admin) as writer:
                trace(stream, check="environment", stock=args.stock,
                      require_af_membership=args.require_af_membership,
                      require_sp=args.require_sp,
                      rows=writer.execute("SELECT version(), current_database()").rows)
                if not args.stock:
                    writer.execute("SHOW native_af.mode")
                writer.execute(Path(__file__).with_name("doc_fixture.sql").read_text(encoding="utf-8"))
                for mode in ("native",) if args.stock else MODES:
                    run_mode(lib, args, writer, mode, stream)
        except Exception as error:
            trace(stream, check="terminal", status="error", error=str(error))
            raise
        trace(stream, check="terminal", status="pass")


if __name__ == "__main__":
    main()
