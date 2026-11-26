#!/usr/bin/env python3
"""Replay the 170 evaluation cases and compare them with the recorded run.

For every case the script installs the case's row-level-security policy,
opens a session as the case's ordinary (non-superuser) role with AF enabled,
and then checks three things against `workload/cases/<case>/expected.json`:

* plan   -- the executable plan from `EXPLAIN (VERBOSE, COSTS, SETTINGS)`,
            with the two cost-estimate fields removed and index OIDs
            replaced by index names, equals the plan recorded during the
            measurements;
* answer -- the complete typed result (column names and types, every row
            and NULL, row order and the command tag) has the recorded
            SHA-256 digest;
* audit  -- for the audited searches, the logging function received the
            recorded number of inputs and none of them was unauthorized.

The databases must already exist (see workload/databases/). Every case
restores the policy and state it changed, so the databases can be reused.

Example:
    python3 tools/replay.py --install /path/to/build/install \
        --socket-dir /path/to/socket --port 5432 --admin postgres \
        --output /path/to/new/replay-output
"""

import argparse
import csv
import fnmatch
import hashlib
import json
import sys
import time
from collections import OrderedDict
from contextlib import ExitStack
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from libpq import LibPQ, QueryError  # noqa: E402

REPOSITORY = Path(__file__).resolve().parents[1]
COST_FIELDS = ("Startup Cost", "Total Cost")
EXPLAIN = "EXPLAIN (VERBOSE, COSTS, SETTINGS, FORMAT JSON) "


# ---------------------------------------------------------------------------
# Canonical forms shared with the recorded results


def normalize_plan(node, index_name):
    """Drop the cost estimates and name indexes instead of using their OIDs.

    Costs are not part of the chosen plan, and OIDs differ between databases
    built separately; `index_name(oid)` maps an "Index OID" to the index name
    (0 means no index and is kept).
    """
    if isinstance(node, dict):
        return {key: (index_name(value) if key == "Index OID" and value else normalize_plan(value, index_name))
                for key, value in node.items() if key not in COST_FIELDS}
    if isinstance(node, list):
        return [normalize_plan(value, index_name) for value in node]
    return node


def index_namer(admin):
    def name(oid):
        rows = admin.execute(f"SELECT relname FROM pg_class WHERE oid = {int(oid)}").rows
        return rows[0][0] if rows else f"unknown index {oid}"
    return name


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def answer_digest(result):
    """Digest of the complete typed answer, in returned order and as a multiset."""
    columns = [list(column) for column in result.columns]
    rows = [list(row) for row in result.rows]
    ordered = sha256(canonical_json({"columns": columns, "command": result.command, "rows": rows}))

    def sort_key(row):
        return [(0, "") if value is None else (1, value) for value in row]

    unordered = sha256(canonical_json({"columns": columns, "command": result.command,
                                       "rows": sorted(rows, key=sort_key)}))
    return dict(columns=columns, command=result.command, row_count=len(rows),
                sha256=ordered, multiset_sha256=unordered)


def compare_answer(actual, expected):
    if actual["sha256"] == expected["sha256"]:
        return "match"
    if actual["multiset_sha256"] == expected["multiset_sha256"]:
        return "same rows, different order"
    return "different"


# ---------------------------------------------------------------------------
# Audit checks for the searches that call a logging function


TITLE_AUDIT = """
SELECT count(*),
       count(*) FILTER (WHERE a.principal::text <> {role}
           OR NOT EXISTS (SELECT 1 FROM public.prefix_doc d
                          WHERE d.id = a.rid AND d.secret IS NOT DISTINCT FROM a.secret)
           OR NOT EXISTS (SELECT 1 FROM public.share_acl s
                          JOIN public.group_membership m ON m.group_id = s.group_id
                          WHERE m.user_id = a.principal::text AND s.relname = 'public.prefix_doc'
                            AND s.rid = a.rid AND s.permission = 'read'))
FROM public.prefix_audit a
"""

APPLICATION_WATERMARK = """
SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM public.udf_audit_call_seq
"""

APPLICATION_AUDIT = """
SELECT rid, value_hash FROM public.udf_audit
WHERE run_id = {run_id} AND query_id = {query_id} AND call_counter > {after}
"""


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


class TitleAudit:
    """The title searches log (principal, id, secret) for every row they inspect."""

    def __init__(self, admin, role):
        self.admin, self.role = admin, role

    def before(self):
        self.admin.execute("TRUNCATE public.prefix_audit")

    def after(self):
        total, unauthorized = self.admin.execute(TITLE_AUDIT.format(role=quote(self.role))).rows[0]
        return int(total), int(unauthorized)


class ApplicationAudit:
    """The shared document search logs (id, hash of secret) for every row it inspects."""

    def __init__(self, admin, folder, expected):
        self.admin, self.expected = admin, expected
        self.reference_sql = (folder / "audit-reference.sql").read_text(encoding="utf-8")
        self.watermark = None

    def before(self):
        self.watermark = int(self.admin.execute(APPLICATION_WATERMARK).rows[0][0])

    def after(self):
        observed = self.admin.execute(APPLICATION_AUDIT.format(
            run_id=quote(self.expected["run_id"]), query_id=quote(self.expected["query_id"]),
            after=self.watermark)).rows
        allowed = {row for row in self.admin.execute(self.reference_sql).rows}
        return len(observed), sum(row not in allowed for row in observed)


# ---------------------------------------------------------------------------
# Replay


def load_cases(workload, patterns):
    with (workload / "cases.csv").open(newline="", encoding="utf-8") as stream:
        cases = list(csv.DictReader(stream))
    if patterns:
        cases = [case for case in cases if any(fnmatch.fnmatchcase(case["case"], p) for p in patterns)]
        if not cases:
            raise SystemExit("no case matches --case")
    return cases


def configure_reader(reader, role, session):
    """Apply the session settings used during the measurements and enable AF."""
    for name, value in session.items():
        reader.execute(f"SELECT set_config({quote(name)}, {quote(value)}, false)")
    reader.execute("SET native_af.mode = 'af'; SET native_af.trace = off")
    identity = reader.execute("SELECT current_user, session_user, rolsuper, rolbypassrls "
                              "FROM pg_roles WHERE rolname = current_user").rows
    if identity != ((role, role, "f", "f"),):
        raise RuntimeError(f"{role} must be an ordinary login without BYPASSRLS, got {identity}")


def replay_case(case, folder, admin, reader, session, output, warmups):
    expected = json.loads((folder / "expected.json").read_text(encoding="utf-8"))
    query = (folder / "query.sql").read_text(encoding="utf-8")
    row = OrderedDict(case=case["case"], plan="", answer="", audit="", audit_inputs="", unauthorized_inputs="",
                      seconds="", detail="")
    started = time.monotonic()
    restore = folder / "state-restore.sql"
    if (folder / "state-apply.sql").is_file():
        admin.execute((folder / "state-apply.sql").read_text(encoding="utf-8"))
    try:
        admin.execute((folder / "policy.sql").read_text(encoding="utf-8"))
        configure_reader(reader, case["role"], session)

        # AF's cost model reads how much of each relation is already cached
        # (native_af.os_cache_cost), so a cold cache can change a cost-based
        # choice. The measurements recorded plans with warm caches; run the
        # query first, as their warmup requests did, before recording the plan.
        for _ in range(warmups):
            try:
                reader.execute(query)
            except QueryError:
                break
        plan = normalize_plan(json.loads(reader.execute(EXPLAIN + query).rows[0][0]), index_namer(admin))
        recorded = json.loads((folder / "expected-plan.json").read_text(encoding="utf-8"))
        row["plan"] = "match" if plan == recorded else "different"
        if row["plan"] != "match":
            target = output / "plans" / (case["case"] + ".json")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(plan, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

        audit = None
        if expected["audit"] and expected["audit"]["kind"] == "title":
            audit = TitleAudit(admin, case["role"])
        elif expected["audit"]:
            audit = ApplicationAudit(admin, folder, expected["audit"])
        if audit:
            audit.before()
        try:
            answer = answer_digest(reader.execute(query))
        except QueryError as error:
            row.update(answer="error", detail=str(error).splitlines()[0])
        else:
            row["answer"] = compare_answer(answer, expected["answer"])
            if row["answer"] != "match":
                row["detail"] = f"{answer['row_count']} rows, expected {expected['answer']['row_count']}"
        if audit:
            observations, unauthorized = audit.after()
            row.update(audit_inputs=observations, unauthorized_inputs=unauthorized)
            wanted = expected["audit"]["observations"]
            ok = unauthorized == 0 and observations == wanted
            row["audit"] = f"{'ok' if ok else 'FAILED'}: {observations} inputs, {unauthorized} unauthorized"
            if observations != wanted:
                row["audit"] += f" (expected {wanted})"
    finally:
        if restore.is_file():
            admin.execute(restore.read_text(encoding="utf-8"))
    row["seconds"] = f"{time.monotonic() - started:.2f}"
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--install", type=Path, required=True,
                        help="PostgreSQL installation built with AdmissionFirst (contains lib/libpq)")
    parser.add_argument("--socket-dir", type=Path, required=True, help="server Unix socket directory")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--admin", required=True, help="superuser used to install policies and read audits")
    parser.add_argument("--output", type=Path, required=True, help="new directory for the replay report")
    parser.add_argument("--workload", type=Path, default=REPOSITORY / "workload")
    parser.add_argument("--case", action="append", default=[],
                        help="replay only cases matching this glob, e.g. 'adapted/*' (repeatable)")
    parser.add_argument("--database", action="append", default=[], metavar="NAME=ACTUAL",
                        help="use database ACTUAL for the workload database NAME (repeatable)")
    parser.add_argument("--warmups", type=int, default=1,
                        help="executions of each query before its plan is recorded (default 1)")
    args = parser.parse_args()

    workload = args.workload.resolve()
    cases = load_cases(workload, args.case)
    session = json.loads((workload / "session.json").read_text(encoding="utf-8"))
    renamed = dict(item.split("=", 1) for item in args.database)
    suffix = ".dylib" if sys.platform == "darwin" else ".so"
    client = LibPQ(args.install / "lib" / ("libpq" + suffix))
    output = args.output.resolve()
    output.mkdir(parents=False)
    endpoint = dict(socket_dir=args.socket_dir.resolve(), port=args.port)

    rows = []
    with ExitStack() as connections:
        admins, readers = {}, {}
        for case in cases:
            database = renamed.get(case["database"], case["database"])
            if database not in admins:
                admins[database] = connections.enter_context(
                    client.connect(**endpoint, database=database, role=args.admin))
                admins[database].execute("SET search_path TO pg_catalog, public; SET TimeZone TO 'UTC'")
            if (database, case["role"]) not in readers:
                readers[database, case["role"]] = connections.enter_context(
                    client.connect(**endpoint, database=database, role=case["role"]))
            folder = workload / "cases" / case["case"]
            row = replay_case(case, folder, admins[database], readers[database, case["role"]], session, output,
                              args.warmups)
            rows.append(row)
            print(f"{row['case']:<58} plan {row['plan']:<9} answer {row['answer']:<9} {row['audit']}", flush=True)

    with (output / "replay.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    summary = OrderedDict(
        cases=len(rows),
        plans_matching=sum(r["plan"] == "match" for r in rows),
        answers_matching=sum(r["answer"] == "match" for r in rows),
        answers_same_rows_other_order=sum(r["answer"] == "same rows, different order" for r in rows),
        audited_cases=sum(bool(r["audit"]) for r in rows),
        audits_ok=sum(r["audit"].startswith("ok") for r in rows),
        audit_inputs=sum(r["audit_inputs"] or 0 for r in rows),
        unauthorized_audit_inputs=sum(r["unauthorized_inputs"] or 0 for r in rows),
    )
    (output / "summary.json").write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=1))
    failed = summary["answers_matching"] + summary["answers_same_rows_other_order"] < len(rows) or \
        summary["audits_ok"] < summary["audited_cases"]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
