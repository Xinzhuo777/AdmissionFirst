#!/usr/bin/env python3
"""Replay the recorded post-load history of the application database.

After the data load, the experiment database went through two complete
runs of the daily application workload before it was frozen.  Those runs
left persistent traces that are part of the frozen state:

* 228 committed transactions of the shared-document-search request, each
  calling the audit function public.unsafe_log() for the same 1400
  authorized documents, which appended 319200 rows to public.udf_audit and
  advanced public.udf_audit_call_seq to 319200;
* per run, three negative-state cases (stale dashboard, wrong context,
  revoked membership) that temporarily registered rows in
  public.artifact_dependencies, updated document 1 and the base/membership
  version counters, revoked and re-granted one group membership, and then
  restored the original values.  The restored rows keep their new physical
  positions (document 1 lives at the end of the table, the re-granted
  membership row at the end of group_membership).

This script re-executes exactly those data changes, transaction by
transaction and in the original order, so that both the visible contents
and the physical row placement (ctid) are reproduced.  Rows of the audit
table are written with their recorded values (call_counter and the recorded
observed_at timestamps from data/audit-log-transactions.tsv).  Heap placement
of the audit rows depends on which client session inserted them, because
every PostgreSQL backend remembers its own insertion target page; the data
file therefore also records the session (one of three per run) of each
transaction, and this script uses three concurrent psql sessions per run.

Temporary per-case tables and the per-case index of the original runs are
not recreated: they were dropped again and leave no data behind.

Only the Python 3 standard library is used.
"""

import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(os.path.dirname(HERE), "data")

AUDIT_ROWS_PER_TRANSACTION = 1400
RUN_COUNT = 2

# Authorized documents of the search request (document policy for principal
# 90, restricted to doc_id <= 20000), in the order the request visited them.
AUTHORIZED_RIDS_SQL = """
SELECT string_agg(d.doc_id::text, ',' ORDER BY d.doc_id)
FROM public.document d
WHERE (d.tenant_id = 90 OR d.owner_id = 90 OR d.public = true OR EXISTS (
         SELECT 1 FROM public.share_acl a
         JOIN public.group_membership gm ON gm.group_id = a.group_id
         WHERE a.rid = d.doc_id AND a.relname = 'document' AND gm.user_id = 90
           AND a.permission IN ('read','owner')
           AND TIMESTAMPTZ '2026-06-01 00:00:00+00' BETWEEN a.valid_from AND a.valid_to))
  AND d.doc_id <= 20000
"""

STATE_EPOCH = "sha256:5c139e11c2e42e62841086538a7eda82fccbf0878abc5cb5e04c364cf3b25a4d"
ORIGINAL_DOC1_PAYLOAD = '{"bucket":1,"doc_id":1,"seed":52}'

# Per-case dependency registrations: (artifact id, context hash, principal).
CASES = {
    "stale": ("e10-state:E10_Q8_stale_dashboard_mav:ctx_000001:fa7631907e699336",
              "public.e10_state_mav_fa7631907e699336",
              "sha256:f7dd134078a8f32da2a54ade0a7c9acc07f5a053877183ed253cc6907ee9cb26", "90"),
    "context": ("e10-state:E10_Q9_wrong_context_mav:ctx_000001:c2732e6953c0fc05",
                "public.e10_state_mav_c2732e6953c0fc05",
                "sha256:2f783c65383b3dd350cae8dd663b0d5d317808a2fb07ba574c7c6a73ea0c7558", "127"),
    "membership": ("e10-state:E10_Q10_revoked_membership_mav:ctx_000001:035aed1f14d2cbb9",
                   "public.e10_state_mav_035aed1f14d2cbb9",
                   "sha256:f7dd134078a8f32da2a54ade0a7c9acc07f5a053877183ed253cc6907ee9cb26", "90"),
}
# Object identifiers that the temporary per-case tables had in the two runs;
# they were recorded in the (later deleted) dependency rows.
CASE_RELATION_OIDS = {
    1: {"stale": 17970, "context": 17988, "membership": 18006},
    2: {"stale": 18028, "context": 18046, "membership": 18064},
}


def q(value):
    return "'" + value.replace("'", "''") + "'"


def register_sql(case, run):
    artifact, relation, ctx_hash, principal = CASES[case]
    a = q(artifact)
    rows = [
        (q("artifact_kind"), q("mav"), "0"),
        (q("artifact_relation"), q(relation), str(CASE_RELATION_OIDS[run][case])),
        (q("base"), q("document"), "(SELECT version FROM public.base_versions WHERE relname = 'document')"),
        (q("base_relation_oid"), q("public.document"), "'public.document'::regclass::oid::bigint"),
        (q("context_scope"), q(ctx_hash),
         "(SELECT version FROM public.context_versions WHERE ctx_hash = %s)" % q(ctx_hash)),
        (q("membership"), q("group_membership"),
         "(SELECT version FROM public.membership_versions WHERE scope_name = 'group_membership')"),
        (q("policy"), q("tenant_group"), "0"),
        (q("principal"), q(principal), "0"),
        (q("rid_domain"), q("document.doc_id"), "0"),
    ]
    values = ",\n".join("(%s, %s, %s, %s)" % (a, k, n, v) for k, n, v in rows)
    return ("BEGIN ISOLATION LEVEL REPEATABLE READ;\n"
            "INSERT INTO public.artifact_dependencies(artifact_id, dep_kind, dep_name, version_at_build)\n"
            "VALUES\n" + values + ";\nCOMMIT;\n")


def unregister_sql(case):
    return "DELETE FROM public.artifact_dependencies WHERE artifact_id = %s;\n" % q(CASES[case][0])


def case_steps(run):
    """Transactions of the three negative-state cases of one run, in order."""
    return [
        # Stale dashboard: register, advance the base epoch, restore.
        register_sql("stale", run),
        "BEGIN ISOLATION LEVEL REPEATABLE READ;\n"
        "UPDATE public.document SET payload = jsonb_set(payload, '{caprls_state_epoch}', "
        "to_jsonb(%s::text), true) WHERE doc_id = 1;\n"
        "UPDATE public.base_versions SET version = 1 WHERE relname = 'document' AND version = 0;\n"
        "COMMIT;\n" % q(STATE_EPOCH),
        "BEGIN ISOLATION LEVEL REPEATABLE READ;\n"
        "UPDATE public.document SET payload = %s::jsonb WHERE doc_id = 1;\n"
        "UPDATE public.base_versions SET version = 0 WHERE relname = 'document' AND version = 1;\n"
        % q(ORIGINAL_DOC1_PAYLOAD) + unregister_sql("stale") + "COMMIT;\n",
        # Wrong context: register, then restore (no data change in between).
        register_sql("context", run),
        "BEGIN ISOLATION LEVEL REPEATABLE READ;\n" + unregister_sql("context") + "COMMIT;\n",
        # Revoked membership: register, revoke one membership, restore it.
        register_sql("membership", run),
        "BEGIN ISOLATION LEVEL REPEATABLE READ;\n"
        "DELETE FROM public.group_membership WHERE user_id = 90 AND group_id = 843 AND membership_version = 0;\n"
        "UPDATE public.membership_versions SET version = 1 WHERE scope_name = 'group_membership' AND version = 0;\n"
        "COMMIT;\n",
        "BEGIN ISOLATION LEVEL REPEATABLE READ;\n"
        "INSERT INTO public.group_membership(user_id, group_id, membership_version) VALUES (90, 843, 0);\n"
        "UPDATE public.membership_versions SET version = 0 WHERE scope_name = 'group_membership' AND version = 1;\n"
        + unregister_sql("membership") + "COMMIT;\n",
    ]


class Session:
    """One long-lived psql backend fed through a pipe."""

    def __init__(self, argv, name):
        self.name = name
        self.counter = 0
        self.proc = subprocess.Popen(argv + ["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     universal_newlines=True, bufsize=1)

    def run(self, sql):
        self.counter += 1
        marker = "replay-%s-%d-done" % (self.name, self.counter)
        self.proc.stdin.write(sql + "\nSELECT '" + marker + "';\n")
        self.proc.stdin.flush()
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("psql session %s ended unexpectedly" % self.name)
            if line.strip() == marker:
                return

    def close(self):
        self.proc.stdin.close()
        if self.proc.wait() != 0:
            raise RuntimeError("psql session %s failed" % self.name)


def one_shot(argv, sql):
    subprocess.run(argv + ["-X", "-q", "-v", "ON_ERROR_STOP=1"], input=sql,
                   universal_newlines=True, check=True, stdout=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description="Replay the recorded post-load history.")
    parser.add_argument("--psql", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--dbname", required=True)
    args = parser.parse_args()
    argv = [args.psql, "-h", args.host, "-p", str(args.port), "-U", args.user, "-d", args.dbname]

    transactions = []
    with open(os.path.join(DATA, "audit-log-transactions.tsv")) as stream:
        for line in stream:
            if line.startswith("#") or not line.strip():
                continue
            index, run, session, observed_at = line.rstrip("\n").split("\t")
            transactions.append((int(index), int(run), int(session), observed_at))
    if [t[0] for t in transactions] != list(range(len(transactions))):
        raise RuntimeError("audit transaction file is not in order")

    out = subprocess.run(argv + ["-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", AUTHORIZED_RIDS_SQL],
                         universal_newlines=True, check=True, stdout=subprocess.PIPE).stdout.strip()
    rids = out.split(",")
    if len(rids) != AUDIT_ROWS_PER_TRANSACTION:
        raise RuntimeError("expected %d authorized documents, found %d" % (AUDIT_ROWS_PER_TRANSACTION, len(rids)))
    rid_array = "{" + ",".join(rids) + "}"

    for run in range(1, RUN_COUNT + 1):
        # The search request of each run was issued from three client
        # sessions (one per execution method); new sessions for each run.
        sessions = {}
        try:
            for index, run_of, session, observed_at in transactions:
                if run_of != run:
                    continue
                if session not in sessions:
                    sessions[session] = Session(argv, "%d.%d" % (run, session))
                first = index * AUDIT_ROWS_PER_TRANSACTION
                sessions[session].run(
                    "BEGIN;\n"
                    "INSERT INTO public.udf_audit(run_id, query_id, plan_id, occurrence_id, rid, value_hash, call_counter, observed_at)\n"
                    "SELECT 'e10', 'E10_Q4_shared_document_search_audit', 'barrier_exact', 'case_occ_1', d.doc_id,\n"
                    "       encode(public.digest(coalesce(d.secret, ''), 'sha256'), 'hex'), %d + o.ord, %s::timestamptz\n"
                    "FROM unnest(%s::bigint[]) WITH ORDINALITY AS o(rid, ord)\n"
                    "JOIN public.document d ON d.doc_id = o.rid\n"
                    "ORDER BY o.ord;\n"
                    "COMMIT;" % (first, q(observed_at), q(rid_array)))
        finally:
            for s in sessions.values():
                s.close()
        # Negative-state cases ran after the search request, each step in
        # its own short-lived client session.
        for sql in case_steps(run):
            one_shot(argv, sql)

    # The audit sequence ends at the number of audit rows.  Its last twelve
    # values are drawn with nextval() so that the sequence's internal
    # pre-logging counter (log_cnt) also ends where the original one did.
    total = len(transactions) * AUDIT_ROWS_PER_TRANSACTION
    one_shot(argv, "SELECT pg_catalog.setval('public.udf_audit_call_seq', %d, true);\n"
                   "SELECT count(nextval('public.udf_audit_call_seq')) FROM generate_series(1, 12);\n"
                   % (total - 12))
    # Later reads in the original database pruned the dead row versions on
    # nearly full pages, and later index scans marked the index entries of
    # deleted rows as dead.  Touch every page once and look up the deleted
    # keys once through their indexes so that the same hints are set.
    lookups = ["SELECT count(version_at_build) FROM public.artifact_dependencies WHERE artifact_id = %s;"
               % q(CASES[case][0]) for case in ("stale", "context", "membership")]
    one_shot(argv, "SELECT count(*) FROM public.document; SELECT count(*) FROM public.group_membership;"
                   " SELECT count(*) FROM public.artifact_dependencies;"
                   " SELECT count(*) FROM public.base_versions; SELECT count(*) FROM public.membership_versions;\n"
                   "SET enable_seqscan = off; SET enable_bitmapscan = off; SET enable_indexonlyscan = off;\n"
                   + "\n".join(lookups) + "\n"
                   "SELECT count(membership_version) FROM public.group_membership WHERE group_id = 843 AND user_id = 90;\n")
    print("replayed %d audit transactions (%d rows) and %d negative-state transactions"
          % (len(transactions), total, RUN_COUNT * len(case_steps(1))))


if __name__ == "__main__":
    main()
