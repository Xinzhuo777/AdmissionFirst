"""Check that planning admits, rejects and retains selection/projection candidates.

Run after doc_safety.py on the same database. With AF tracing enabled, the
planner reports how many scan candidates it admitted, rejected before costing
(missing row identity) and pruned. The two queries check both outcomes:

* without ORDER BY, a cheaper admitted candidate replaces the others;
* with ORDER BY id, the candidate that delivers the order is retained.
"""

import argparse
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from libpq import LibPQ  # noqa: E402
from doc_safety import DROP, KEEP, READER, check_role, query, require, trace  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket-dir", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--admin", required=True)
    parser.add_argument("--libpq", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    client = LibPQ(args.libpq)
    connection = dict(socket_dir=args.socket_dir, port=args.port, database=args.database)
    expected = (("duplicate",), ("duplicate",), (None,))

    with args.output.open("x", encoding="utf-8") as stream:
        with client.connect(**connection, role=args.admin) as owner:
            owner.execute("INSERT INTO public.share_acl (relname, rid, group_id, permission) "
                          "SELECT 'public.doc', id, 1, 'read' FROM public.doc WHERE id > 10")
            owner.execute("ALTER TABLE public.doc ALTER COLUMN topic SET STATISTICS 1000")
            owner.execute("ANALYZE public.doc")
            owner.execute("ANALYZE public.share_acl")

        with client.connect(**connection, role=READER) as reader:
            check_role(reader, READER, "af", stream, False)
            for sql, ordered in ((DROP, False), (KEEP, True)):
                label = "ordered" if ordered else "projection"
                reader.execute("SET native_af.trace=off")
                query(reader, sql, expected, (("title", 25),), ordered, "af", label, stream)
                reader.execute("SET native_af.trace=on")
                reader.notices.clear()
                plan = json.loads(reader.execute("EXPLAIN (VERBOSE, COSTS, FORMAT JSON) " + sql).rows[0][0])
                notice = "\n".join(reader.notices)
                trace(stream, phase=label, check="admission", plan=plan, notices=reader.notices)
                if ordered:
                    require("root order_or_enforcer_mismatch projection order_or_enforcer_mismatch" in notice and
                            re.search(r"SP occurrence \d+ admitted [2-9]\d* rejected missing carrier \d+ pruned 0 survivors", notice),
                            "an order-sensitive alternative was not retained")
                else:
                    require("root pass projection pass" in notice and
                            re.search(r"SP occurrence \d+ admitted [2-9]\d* rejected missing carrier [1-9]\d* pruned 1 survivors", notice),
                            "the safe replacement or missing-carrier rejection was not observed")
        trace(stream, check="terminal", status="pass")


if __name__ == "__main__":
    main()
