#!/usr/bin/env python3
"""Recompute every reported latency result from the per-request measurements.

Input:  results/samples.csv.gz  (one row per scheduled request)
        workload/cases.csv      (case metadata)
        workload/cases/*/expected-plan.json (only to name AF's access methods)
Output: conditions.csv   per-case median latency of each method
        comparisons.csv  per-case latency ratio to AF with its paired 95% interval
        summary.csv      the paper's performance table (Table 2, latency rows)
        paper-numbers.json  every other latency figure quoted in the evaluation

With --check, the freshly computed files are compared byte for byte with the
files committed in results/, and the script fails on any difference.

Statistics (identical to the analysis used for the paper):
* A method's latency for a case is the median of its 32 measured requests
  (4 cycles x 8 requests; each cycle also had one warmup, which is excluded).
* A ratio is baseline median / AF median; values above 1 favor AF.
* Paired 95% intervals resample whole cycles: each of the 4^4 = 256 ordered
  draws of four cycles (with replacement) gives a median per method, the same
  draw is used for every method and case, and the interval spans the 2.5th
  and 97.5th percentiles (linear interpolation) of the 256 drawn values.
* A case is an AF win if the interval of baseline/AF lies above 1, a loss if
  it lies below 1, and otherwise shows no clear difference.
* Geometric means weight cases equally. Summary rows use the cases in which
  all four reported methods completed (119 benchmark, 50 application cases).
"""

import argparse
import csv
import gzip
import itertools
import json
import math
import shutil
import sys
import tempfile
from collections import Counter, OrderedDict, defaultdict
from pathlib import Path
from statistics import median

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parent
METHODS = ("native", "af", "in_rewrite", "index_priority", "key_array")
BASELINES = ("native", "index_priority", "in_rewrite", "key_array")
REPORTED = ("af", "native", "index_priority", "in_rewrite")  # the four methods in the paper
LABEL = {"native": "Native", "index_priority": "IndexPriority", "in_rewrite": "IN rewrite", "key_array": "key array"}
DRAWS = tuple(itertools.product(range(4), repeat=4))
OUTPUTS = ("conditions.csv", "comparisons.csv", "summary.csv", "paper-numbers.json")


# ---------------------------------------------------------------------------
# Statistics


def quantile(values, p):
    values = sorted(values)
    position = (len(values) - 1) * p
    low, high = math.floor(position), math.ceil(position)
    return values[low] + (values[high] - values[low]) * (position - low)


def interval(values):
    return [quantile(values, 0.025), quantile(values, 0.975)]


def geometric_mean(values):
    values = list(values)
    return math.exp(math.fsum(math.log(v) for v in values) / len(values))


def outcome(bounds):
    """Classify a baseline/AF interval from AF's point of view."""
    return "win" if bounds[0] > 1 else "loss" if bounds[1] < 1 else "unclear"


class Cell:
    """The requests of one method on one case."""

    def __init__(self, rows):
        done = [r for r in rows if r["status"] == "ok"]
        self.cycles = [[float(r["latency_ms"]) for r in done if r["kind"] == "measured" and int(r["cycle"]) == c]
                       for c in range(4)]
        warmups = [sum(r["kind"] == "warmup" and int(r["cycle"]) == c for r in done) for c in range(4)]
        self.complete = len(rows) == len(done) == 36 and all(len(c) == 8 for c in self.cycles) and warmups == [1] * 4
        self.warmups = sum(warmups)
        self.measured = sum(len(c) for c in self.cycles)
        self.median = median(v for c in self.cycles for v in c) if self.complete else None
        self.draws = [median(v for c in draw for v in self.cycles[c]) for draw in DRAWS] if self.complete else None
        self.cycle_medians = [median(c) for c in self.cycles] if self.complete else None


class Ratio:
    """Baseline latency / AF latency on one case."""

    def __init__(self, case, baseline, af):
        self.case = case
        self.point = baseline.median / af.median
        self.draws = [b / a for b, a in zip(baseline.draws, af.draws)]
        self.interval = interval(self.draws)
        self.outcome = outcome(self.interval)
        self.cycles = [b / a for b, a in zip(baseline.cycle_medians, af.cycle_medians)]


def summarize(ratios):
    counts = Counter(r.outcome for r in ratios)
    drawn = [geometric_mean(r.draws[i] for r in ratios) for i in range(len(DRAWS))]
    return OrderedDict(cases=len(ratios), median=median(r.point for r in ratios),
                       geometric_mean=geometric_mean(r.point for r in ratios),
                       geometric_mean_interval=interval(drawn),
                       wins=counts["win"], unclear=counts["unclear"], losses=counts["loss"])


# ---------------------------------------------------------------------------
# Inputs


def load(samples_path, cases_path):
    with cases_path.open(newline="", encoding="utf-8") as stream:
        cases = list(csv.DictReader(stream))
    rows = defaultdict(list)
    with gzip.open(samples_path, "rt", newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            rows[row["case"], row["method"]].append(row)
    if len(cases) != 170 or len(rows) != 850 or sum(map(len, rows.values())) != 30600:
        raise SystemExit("expected 170 cases x 5 methods and 30,600 scheduled requests")
    cells = {key: Cell(value) for key, value in rows.items()}
    return cases, cells, rows


def af_access_methods(case):
    """Names of the AF operators in the recorded plan of a case."""
    plan = json.loads((REPOSITORY / "workload/cases" / case / "expected-plan.json").read_text(encoding="utf-8"))
    found = []

    def walk(node):
        if isinstance(node, dict):
            if "Custom Plan Provider" in node:
                found.append(node["Custom Plan Provider"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
    walk(plan)
    return found


# ---------------------------------------------------------------------------
# Outputs


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def compute(output, samples_path, cases_path):
    cases, cells, rows = load(samples_path, cases_path)
    by_id = OrderedDict((c["case"], c) for c in cases)
    latency = {(c, m): cells[c, m].median for c in by_id for m in METHODS}
    ratios = {(c, m): Ratio(c, cells[c, m], cells[c, "af"]) for c in by_id for m in BASELINES
              if cells[c, m].complete and cells[c, "af"].complete}

    # conditions.csv -- one row per case
    table = []
    for case_id, case in by_id.items():
        row = OrderedDict((k, case[k]) for k in ("case", "family", "workload", "policy"))
        for method in METHODS:
            cell = cells[case_id, method]
            row[method + "_ms"] = cell.median if cell.complete else ""
            row[method + "_requests"] = f"{cell.warmups}+{cell.measured}"
        table.append(row)
    write_csv(output / "conditions.csv", table)

    # comparisons.csv -- one row per case and baseline
    table = []
    for case_id, case in by_id.items():
        for method in BASELINES:
            r = ratios.get((case_id, method))
            table.append(OrderedDict(
                case=case_id, family=case["family"], baseline=method,
                ratio=r.point if r else "", ci_low=r.interval[0] if r else "", ci_high=r.interval[1] if r else "",
                af_outcome=r.outcome if r else "not measured",
                cycle_ratios=" ".join(repr(x) for x in r.cycles) if r else ""))
    write_csv(output / "comparisons.csv", table)

    # summary.csv -- the paper's table, on the cases where all four reported methods completed
    def common(selected):
        return [c for c in selected if all(cells[c, m].complete for m in REPORTED)]

    def fastest_gap(selected):
        gaps = [latency[c, "af"] / min(latency[c, m] for m in REPORTED) for c in selected]
        return OrderedDict(cases=len(gaps), median=median(gaps), geometric_mean=geometric_mean(gaps),
                           af_fastest=sum(g == 1 for g in gaps), within_5_percent=sum(g <= 1.05 for g in gaps))

    table, families = [], OrderedDict()
    for family in ("benchmark", "application"):
        selected = common([c for c, case in by_id.items() if case["family"] == family])
        families[family] = selected
        for method in ("native", "index_priority", "in_rewrite"):
            s = summarize([ratios[c, method] for c in selected])
            table.append(OrderedDict(
                family=family, comparison=f"{LABEL[method]} / AF", cases=s["cases"], median=s["median"],
                geometric_mean=s["geometric_mean"], gm_ci_low=s["geometric_mean_interval"][0],
                gm_ci_high=s["geometric_mean_interval"][1], af_wins=s["wins"], unclear=s["unclear"],
                af_losses=s["losses"], af_fastest="", within_5_percent=""))
        g = fastest_gap(selected)
        table.append(OrderedDict(
            family=family, comparison="AF / fastest", cases=g["cases"], median=g["median"],
            geometric_mean=g["geometric_mean"], gm_ci_low="", gm_ci_high="", af_wins="", unclear="",
            af_losses="", af_fastest=g["af_fastest"], within_5_percent=g["within_5_percent"]))
    write_csv(output / "summary.csv", table)

    # paper-numbers.json -- the other latency statements of the evaluation
    def ms(case, method):
        return latency[case, method]

    def gm_over(selected, method="native"):
        return geometric_mean(ratios[c, method].point for c in selected)

    bench = families["benchmark"]
    workload = lambda name: [c for c in bench if by_id[c]["workload"] == name]
    membership = [c for c in bench if by_id[c]["policy"] == "membership"]
    others = [c for c in bench if by_id[c]["policy"] != "membership"]
    ranked = sorted(bench, key=lambda c: -ratios[c, "native"].point)
    dense = [f"path-search/independent-dense-{p}" for p in ("prefix-0.1pct", "prefix-1pct", "prefix-20pct", "no-prefix")]
    apps = families["application"]
    searches = [c for c in apps if by_id[c]["workload"] in ("title-search", "path-search")]
    daily = [c for c in apps if by_id[c]["workload"] == "daily-requests"]
    # The six original TPC-H queries that also run with orders (and lineitem) protected.
    multi_table = [c[:-len("-membership-2-tables")] for c in bench if c.endswith("-membership-2-tables")]
    original_tpch = lambda suffix: [query + "-membership" + suffix for query in multi_table]
    native_losses = [c for c in bench if ratios[c, "native"].outcome == "loss"]
    adapted_membership = [c for c in bench if by_id[c]["workload"].startswith("adapted") and by_id[c]["policy"] == "membership"]

    def relative_to_native(method):
        values = [ms(c, method) / ms(c, "native") for c in bench]
        return OrderedDict(more_than_halves=sum(v < 0.5 for v in values), more_than_doubles=sum(v > 2 for v in values))

    af_requests = [r for (case, method), cell_rows in rows.items() if method == "af" for r in cell_rows]
    numbers = OrderedDict()
    numbers["af_requests_correct"] = OrderedDict(
        total=sum(r["status"] == "ok" for r in af_requests),
        warmups=sum(r["status"] == "ok" and r["kind"] == "warmup" for r in af_requests),
        measured=sum(r["status"] == "ok" and r["kind"] == "measured" for r in af_requests))
    numbers["search_dense_native_ms_range"] = [min(ms(c, "native") for c in dense), max(ms(c, "native") for c in dense)]
    numbers["search_dense_prefix_0.1pct_ms"] = OrderedDict(
        (m, ms("path-search/independent-dense-prefix-0.1pct", m)) for m in ("af", "native", "index_priority"))
    numbers["search_dense_prefix_20pct_af_ms"] = ms("path-search/independent-dense-prefix-20pct", "af")
    numbers["search_sparse_af_ms"] = OrderedDict(
        (p, ms(f"path-search/independent-sparse-{p}", "af")) for p in ("prefix-0.1pct", "prefix-1pct"))
    numbers["search_af_access_methods"] = OrderedDict(
        (c, af_access_methods(c)) for c in by_id if by_id[c]["workload"] == "path-search")
    numbers["benchmark_af_within_5_percent_of_fastest"] = fastest_gap(bench)["within_5_percent"]
    numbers["benchmark_native_over_af_gm"] = OrderedDict(
        all=gm_over(bench), adapted=gm_over(workload("adapted") + workload("adapted-sf10")),
        original=gm_over(workload("original")), without_largest_gain=gm_over(ranked[1:]),
        largest_gain_case=ranked[0], membership=gm_over(membership), membership_cases=len(membership),
        equality_and_key_predicate=gm_over(others), equality_and_key_predicate_cases=len(others))
    numbers["adapted_membership_cases_using_hash_check"] = OrderedDict(
        cases=len(adapted_membership),
        with_hash_check=sum("AF Completed Hash Policy" in af_access_methods(c) for c in adapted_membership))
    numbers["original_tpch_q10_membership_ms"] = OrderedDict(
        (m, ms("original/tpch-q10-membership", m)) for m in ("in_rewrite", "af"))
    numbers["original_job_31a_membership_ms"] = OrderedDict(
        (m, ms("original/job-31a-membership", m)) for m in ("af", "native"))
    numbers["original_job_1a_membership_ms"] = OrderedDict(
        (m, ms("original/job-1a-membership", m)) for m in REPORTED)
    numbers["benchmark_latency_relative_to_native"] = OrderedDict(
        af=relative_to_native("af"), index_priority=relative_to_native("index_priority"),
        in_rewrite=relative_to_native("in_rewrite"))
    numbers["original_job_26a_membership_ms"] = OrderedDict(
        (m, ms("original/job-26a-membership", m)) for m in ("in_rewrite", "af"))
    numbers["original_tpch_q8_membership_3_tables_ms"] = OrderedDict(
        (m, ms("original/tpch-q8-membership-3-tables", m)) for m in ("native", "af"))
    numbers["benchmark_losses_against_native"] = OrderedDict(
        losses=len(native_losses),
        within_5_percent=sum(ms(c, "af") / ms(c, "native") <= 1.05 for c in native_losses))
    numbers["sf10_native_over_af_gm"] = OrderedDict(
        adapted=gm_over(workload("adapted-sf10")),
        membership=gm_over([c for c in workload("adapted-sf10") if by_id[c]["policy"] == "membership"]))
    numbers["original_tpch_membership_native_over_af_gm"] = OrderedDict(
        customer=gm_over(original_tpch("")), customer_and_orders=gm_over(original_tpch("-2-tables")),
        customer_orders_and_lineitem=gm_over(original_tpch("-3-tables")))
    numbers["application_af_at_most_half_of"] = OrderedDict(
        (m, sum(ms(c, "af") <= 0.5 * ms(c, m) for c in apps)) for m in ("native", "index_priority"))
    numbers["application_searches"] = OrderedDict(
        cases=len(searches), native_over_af_gm=gm_over(searches),
        af_faster=sum(ms(c, "af") < ms(c, "native") for c in searches),
        af_slower=OrderedDict((c, ratios[c, "native"].point) for c in searches if ms(c, "af") > ms(c, "native")))
    daily_outcomes = Counter(ratios[c, "native"].outcome for c in daily)
    numbers["daily_requests"] = OrderedDict(
        cases=len(daily), af_wins=daily_outcomes["win"], unclear=daily_outcomes["unclear"],
        af_losses=daily_outcomes["loss"], af_over_native_gm=1 / gm_over(daily))
    (output / "paper-numbers.json").write_text(json.dumps(numbers, indent=1) + "\n", encoding="utf-8")
    return table, numbers


def report(table):
    print(f"{'':<12}{'comparison':<22}{'cases':>6}{'median':>9}{'geo.mean':>10}   outcome")
    for row in table:
        if row["comparison"] == "AF / fastest":
            result = f"AF fastest in {row['af_fastest']}/{row['cases']}"
        else:
            result = f"{row['af_wins']}/{row['unclear']}/{row['af_losses']} W/N/L"
        print(f"{row['family']:<12}{row['comparison']:<22}{row['cases']:>6}{row['median']:>9.3f}"
              f"{row['geometric_mean']:>10.2f}   {result}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--samples", type=Path, default=HERE / "samples.csv.gz")
    parser.add_argument("--cases", type=Path, default=REPOSITORY / "workload/cases.csv")
    parser.add_argument("--output", type=Path, default=HERE, help="directory for the computed files")
    parser.add_argument("--check", action="store_true",
                        help="compute into a temporary directory and compare with the committed files")
    args = parser.parse_args()
    if not args.check:
        table, _ = compute(args.output, args.samples, args.cases)
        report(table)
        return 0
    with tempfile.TemporaryDirectory() as scratch:
        table, _ = compute(Path(scratch), args.samples, args.cases)
        report(table)
        different = [name for name in OUTPUTS
                     if (Path(scratch) / name).read_bytes() != (args.output / name).read_bytes()]
        if different:
            for name in different:
                shutil.copy(Path(scratch) / name, args.output / (name + ".recomputed"))
            print("DIFFERENT from the committed results: " + ", ".join(different) +
                  " (recomputed copies saved with the suffix .recomputed)")
            return 1
    print("All recomputed result files are identical to the committed ones: " + ", ".join(OUTPUTS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
