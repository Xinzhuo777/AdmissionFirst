#!/usr/bin/env python3
"""Recalculate A044 medians and four-method summaries from saved timings."""

import csv
import gzip
import math
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median


HERE = Path(__file__).resolve().parent
METHODS = ("native", "af", "index_priority", "in_policy", "manual_array")


def close(actual, expected, description):
    if not math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-10):
        raise ValueError(f"{description}: calculated {actual}, recorded {expected}")


def main():
    with (HERE / "conditions.csv").open(newline="", encoding="utf-8") as stream:
        cases = list(csv.DictReader(stream))
    if len(cases) != 170 or len({r["condition"] for r in cases}) != 170:
        raise ValueError("Expected 170 distinct experiment conditions")

    measurements = defaultdict(list)
    statuses, kinds, ids = Counter(), Counter(), set()
    with gzip.open(HERE / "samples.csv.gz", "rt", newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            request_id = int(row["request_id"])
            if request_id in ids:
                raise ValueError(f"Duplicate request ID {request_id}")
            ids.add(request_id)
            statuses[row["status"]] += 1
            kinds[row["sample_kind"]] += 1
            if row["status"] == "ok":
                if row["correct"] != "True":
                    raise ValueError(f"Incorrect request {request_id}")
                value = float(row["latency_ms"])
                if not math.isfinite(value) or value <= 0:
                    raise ValueError(f"Invalid timing for request {request_id}")
                measurements[(row["condition"], row["method"], row["sample_kind"])].append(value)
    if len(ids) != 30600 or statuses != {"ok": 30528, "not_run_disabled": 72}:
        raise ValueError(f"Unexpected request status counts: {statuses}")
    if kinds != {"warmup": 3400, "formal": 27200}:
        raise ValueError(f"Unexpected scheduled sample counts: {kinds}")

    actual = {}
    for case in cases:
        for method in METHODS:
            key = (case["condition"], method)
            warmups = measurements[key + ("warmup",)]
            formal = measurements[key + ("formal",)]
            if not formal:
                if warmups:
                    raise ValueError(f"Incomplete cell: {key}")
                continue
            if len(warmups) != 4 or len(formal) != 32:
                raise ValueError(f"Unexpected measurement count for {key}")
            value = median(formal)
            close(value, float(case[method + "_median_ms"]), str(key))
            actual[key] = value

    with (HERE / "summary.csv").open(newline="", encoding="utf-8") as stream:
        summaries = list(csv.DictReader(stream))
    for summary in summaries:
        family = summary["family"]
        matched = [case for case in cases if case["family"] == family and
                   all((case["condition"], method) in actual
                       for method in ("af", "native", "index_priority", "in_policy"))]
        if len(matched) != int(summary["matched_conditions"]):
            raise ValueError(f"Incorrect common denominator for {family}")
        print(f"{family}: {len(matched)} common conditions")
        for method in ("native", "index_priority", "in_policy"):
            ratios = [actual[(case["condition"], method)] / actual[(case["condition"], "af")]
                      for case in matched]
            value = math.exp(sum(math.log(ratio) for ratio in ratios) / len(ratios))
            close(value, float(summary[method + "_over_af"]), f"{family}/{method}")
            print(f"  {method}/AF: {value:.6f}x")
    print("Verified all current-run medians and four-method geometric means.")
    print("The historical array measurement and confidence intervals are retained but not recomputed.")


if __name__ == "__main__":
    main()
