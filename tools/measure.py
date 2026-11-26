#!/usr/bin/env python3
"""Measure the request latency of all five methods on the 170 cases.

This repeats the paper's measurement protocol on the local machine:

* Methods: AF, NativePG-RLS ("native") and IndexPriority run on the
  AdmissionFirst build with native_af.mode set accordingly; the IN rewrite
  and the key-array policy run on unmodified PostgreSQL 16.11.
* The cases of each database are measured in groups of at most 12. Each group
  runs four cycles; each cycle runs the five methods in the order of ORDERS,
  and each (cycle, method) pair starts its own server on the same cluster.
* For every case and method a cycle has one warmup and eight measured
  requests (4 + 32 per case and method). A request is unprepared SQL sent
  with libpq's simple protocol on an open connection; its latency runs from
  submitting the SQL to receiving and decoding the complete result.
* Policies, state changes, plan recording and all checks happen outside the
  timed part. Every request's typed answer and audit log are checked.
* A request that exceeds the session's statement_timeout (120 s) ends the
  measurement of that case and method; its remaining positions are recorded
  as not run, also in later cycles.

The output directory receives samples.csv.gz in the format of
results/samples.csv.gz, AF's plan of every cycle (plans/), af-plans.csv
with their comparison against the recorded plans, and summary.json.

Example:
    python3 tools/measure.py --af-install BUILD/install --stock-install STOCK/install \\
        --cluster CLUSTER --socket-dir /tmp/socket --port 54410 --output OUT
"""

import argparse
import csv
import gzip
import json
import subprocess
import sys
import time
from contextlib import ExitStack
from itertools import groupby
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import replay  # noqa: E402
from libpq import LibPQ, QueryError  # noqa: E402

METHODS = ("native", "af", "in_rewrite", "index_priority", "key_array")
ORDERS = (METHODS, METHODS[::-1],
          ("index_priority", "native", "key_array", "af", "in_rewrite"),
          ("in_rewrite", "af", "key_array", "native", "index_priority"))
AF_BUILD = {"af": "af", "native": "native", "index_priority": "index_priority"}  # method -> native_af.mode
POLICY_FILE = {"af": "policy.sql", "native": "policy.sql", "index_priority": "policy.sql",
               "in_rewrite": "baseline-in_rewrite.sql", "key_array": "baseline-key_array.sql"}
GROUP_SIZE = 12
WARMUPS, MEASURED = 1, 8


class Server:
    """Start and stop one PostgreSQL installation on the cluster.

    `config` replaces the cluster's postgresql.conf; the unmodified server
    uses a copy without the native_af.* settings (see stock_config).
    """

    def __init__(self, install, cluster, socket_dir, port, log, config=None):
        self.install, self.cluster, self.socket_dir, self.port, self.log = install, cluster, socket_dir, port, log
        self.config = config

    def __enter__(self):
        options = f"-c port={self.port} -c unix_socket_directories='{self.socket_dir}'"
        if self.config:
            options += f" -c config_file='{self.config}'"
        subprocess.run([str(self.install / "bin/pg_ctl"), "-D", str(self.cluster), "-o", options,
                        "-l", str(self.log), "-w", "-t", "600", "start"], check=True, stdout=subprocess.DEVNULL)
        return self

    def __exit__(self, *_):
        subprocess.run([str(self.install / "bin/pg_ctl"), "-D", str(self.cluster), "-m", "fast", "-w", "stop"],
                       check=True, stdout=subprocess.DEVNULL)


def stock_config(cluster, output):
    """The cluster's server settings without the AdmissionFirst parameters."""
    lines = (cluster / "postgresql.conf").read_text(encoding="utf-8").splitlines()
    kept = [line for line in lines if not line.lstrip().startswith("native_af.")]
    path = output / "postgresql-unmodified.conf"
    path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    return path


def configure(reader, role, session, method):
    """Session settings of the measurements; AF-build methods also set native_af.mode."""
    for name, value in session.items():
        reader.execute(f"SELECT set_config({replay.quote(name)}, {replay.quote(value)}, false)")
    if method in AF_BUILD:
        reader.execute(f"SET native_af.mode = '{AF_BUILD[method]}'; SET native_af.trace = off")
    elif reader.execute("SELECT current_setting('native_af.mode', true)").rows != ((None,),):
        raise RuntimeError("the baseline server must be unmodified PostgreSQL")
    identity = reader.execute("SELECT current_user, session_user, rolsuper, rolbypassrls "
                              "FROM pg_roles WHERE rolname = current_user").rows
    if identity != ((role, role, "f", "f"),):
        raise RuntimeError(f"{role} must be an ordinary login without BYPASSRLS, got {identity}")


class Measurement:
    def __init__(self, args):
        self.args = args
        self.workload = args.workload.resolve()
        self.session = json.loads((self.workload / "session.json").read_text(encoding="utf-8"))
        self.output = args.output.resolve()
        self.output.mkdir(parents=False)
        self.samples = (self.output / "samples.csv").open("w", newline="", encoding="utf-8")
        self.writer = csv.writer(self.samples, lineterminator="\n")
        self.writer.writerow(["request", "case", "method", "cycle", "kind", "round", "latency_ms", "status"])
        self.request = 0
        self.disabled = {}        # (case, method) -> reason; set after a timeout or an error
        self.plan_rows = []
        self.counts = {}

    def emit(self, case, method, cycle, repeat, latency, status):
        kind = "warmup" if repeat < WARMUPS else "measured"
        position = cycle if kind == "warmup" else cycle * MEASURED + repeat - WARMUPS
        self.writer.writerow([self.request, case, method, cycle, kind, position,
                              "" if latency is None else repr(latency), status])
        self.request += 1
        self.counts[status] = self.counts.get(status, 0) + 1

    def check(self, result, expected, audit):
        answer = replay.compare_answer(replay.answer_digest(result), expected["answer"])
        if answer != "match":
            return f"answer {answer}"
        if audit:
            observations, unauthorized = audit.after()
            if unauthorized or observations != expected["audit"]["observations"]:
                return f"audit: {observations} inputs, {unauthorized} unauthorized"
        return None

    def measure_case(self, case, method, cycle, admin, reader):
        name, folder = case["case"], self.workload / "cases" / case["case"]
        expected = json.loads((folder / "expected.json").read_text(encoding="utf-8"))
        positions = WARMUPS + MEASURED
        if (name, method) in self.disabled:
            for repeat in range(positions):
                self.emit(name, method, cycle, repeat, None, "not_run")
            return
        query = (folder / "query.sql").read_text(encoding="utf-8")
        restore = folder / "state-restore.sql"
        if (folder / "state-apply.sql").is_file():
            admin.execute((folder / "state-apply.sql").read_text(encoding="utf-8"))
        try:
            admin.execute((folder / POLICY_FILE[method]).read_text(encoding="utf-8"))
            configure(reader, case["role"], self.session, method)
            plan = replay.normalize_plan(json.loads(reader.execute(replay.EXPLAIN + query).rows[0][0]),
                                         replay.index_namer(admin))
            if method == "af":
                target = self.output / "plans" / f"cycle-{cycle}" / (name + ".json")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(json.dumps(plan, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
                recorded = json.loads((folder / "expected-plan.json").read_text(encoding="utf-8"))
                self.plan_rows.append(dict(case=name, cycle=cycle, plan="match" if plan == recorded else "different"))
            audit = None
            if expected["audit"] and expected["audit"]["kind"] == "title":
                audit = replay.TitleAudit(admin, case["role"])
            elif expected["audit"]:
                audit = replay.ApplicationAudit(admin, folder, expected["audit"])
            for repeat in range(positions):
                if (name, method) in self.disabled:
                    self.emit(name, method, cycle, repeat, None, "not_run")
                    continue
                if audit:
                    audit.before()
                started = time.perf_counter_ns()
                try:
                    result = reader.execute(query)
                except QueryError as error:
                    latency = (time.perf_counter_ns() - started) / 1e6
                    status = "timeout" if error.sqlstate == "57014" else "error"
                    self.disabled[name, method] = f"{status}: {str(error).splitlines()[0]}"
                    self.emit(name, method, cycle, repeat, latency, status)
                    continue
                latency = (time.perf_counter_ns() - started) / 1e6
                problem = self.check(result, expected, audit)
                if problem:
                    self.disabled[name, method] = problem
                self.emit(name, method, cycle, repeat, latency, "wrong" if problem else "ok")
            if audit and expected["audit"]["kind"] == "title":
                admin.execute("TRUNCATE public.prefix_audit")
        finally:
            if restore.is_file():
                admin.execute(restore.read_text(encoding="utf-8"))

    def run(self):
        args = self.args
        cases = replay.load_cases(self.workload, args.case)
        groups = []
        for database, members in groupby(cases, key=lambda c: c["database"]):
            members = list(members)
            groups += [(database, members[i:i + GROUP_SIZE]) for i in range(0, len(members), GROUP_SIZE)]
        started = time.monotonic()
        baseline_config = stock_config(args.cluster, self.output)
        for number, (database, members) in enumerate(groups, 1):
            for cycle, order in enumerate(ORDERS[:args.cycles]):
                for method in order:
                    install = args.af_install if method in AF_BUILD else args.stock_install
                    client = LibPQ(install / "lib" / ("libpq" + (".dylib" if sys.platform == "darwin" else ".so")))
                    log = self.output / "server.log"
                    config = None if method in AF_BUILD else baseline_config
                    with Server(install, args.cluster, args.socket_dir, args.port, log, config), ExitStack() as stack:
                        endpoint = dict(socket_dir=args.socket_dir, port=args.port, database=database)
                        admin = stack.enter_context(client.connect(**endpoint, role=args.admin))
                        admin.execute("SET search_path TO pg_catalog, public; SET TimeZone TO 'UTC'")
                        if cycle == 0 and method == order[0] and not args.no_prewarm:
                            replay.prewarm(admin)
                        readers = {}
                        for case in members:
                            if case["role"] not in readers:
                                readers[case["role"]] = stack.enter_context(client.connect(**endpoint, role=case["role"]))
                            self.measure_case(case, method, cycle, admin, readers[case["role"]])
                    self.samples.flush()
                    elapsed = time.monotonic() - started
                    print(f"group {number}/{len(groups)} {database:<17} cycle {cycle} {method:<15} "
                          f"done; {self.request} requests, {elapsed / 3600:.2f} h", flush=True)
        self.samples.close()
        return self.finish(len(cases))

    def finish(self, case_count):
        text = (self.output / "samples.csv").read_bytes()
        with (self.output / "samples.csv.gz").open("wb") as raw, \
                gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as stream:
            stream.write(text)
        (self.output / "samples.csv").unlink()
        with (self.output / "af-plans.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=["case", "cycle", "plan"], lineterminator="\n")
            writer.writeheader()
            writer.writerows(self.plan_rows)
        summary = dict(cases=case_count, requests=self.request, statuses=self.counts,
                       af_plans_matching=sum(r["plan"] == "match" for r in self.plan_rows),
                       af_plans_recorded=len(self.plan_rows),
                       stopped_cells={f"{c} / {m}": why for (c, m), why in sorted(self.disabled.items())})
        (self.output / "summary.json").write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
        print(json.dumps(summary, indent=1))
        return 1 if self.counts.get("wrong") or self.counts.get("error") else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--af-install", type=Path, required=True, help="installation built by src/build.sh")
    parser.add_argument("--stock-install", type=Path, required=True,
                        help="unmodified PostgreSQL 16.11 (NATIVE_AF_STOCK=1 sh src/build.sh ...)")
    parser.add_argument("--cluster", type=Path, required=True,
                        help="stopped cluster with the six databases (workload/databases/build_all.sh)")
    parser.add_argument("--socket-dir", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--admin", default="postgres")
    parser.add_argument("--output", type=Path, required=True, help="new directory for the measurements")
    parser.add_argument("--workload", type=Path, default=replay.REPOSITORY / "workload")
    parser.add_argument("--case", action="append", default=[], help="measure only cases matching this glob")
    parser.add_argument("--cycles", type=int, default=4, choices=range(1, 5), help="measurement cycles (default 4)")
    parser.add_argument("--no-prewarm", action="store_true",
                        help="do not read each group's database into the page cache before its first cycle")
    args = parser.parse_args()
    for name in ("af_install", "stock_install", "cluster", "socket_dir"):
        setattr(args, name, getattr(args, name).resolve())
    return Measurement(args).run()


if __name__ == "__main__":
    sys.exit(main())
