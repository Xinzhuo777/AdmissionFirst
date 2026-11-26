#!/usr/bin/env python3
"""Compare a new measurement with the paper's results.

    python3 results/compare.py NEW_TABLES_DIRECTORY [--output comparison.md]

NEW_TABLES_DIRECTORY holds the files written by `analyze.py --samples NEW
--output DIR`. The report lists the rows of the paper's latency table and the
other latency figures of the evaluation, each with the paper's value and the
new value. Latencies depend on the machine, so the numbers are expected to be
close, not equal.
"""

import argparse
import csv
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def rows(path):
    with path.open(newline="", encoding="utf-8") as stream:
        return {(r["family"], r["comparison"]): r for r in csv.DictReader(stream)}


def flat(value, prefix=""):
    """Flatten nested paper numbers into (name, number) pairs."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield from flat(item, f"{prefix}.{key}" if prefix else key)
    elif isinstance(value, list) and all(isinstance(v, (int, float)) for v in value):
        for i, item in enumerate(value):
            yield f"{prefix}[{i}]", item
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        yield prefix, value


def outcome(r):
    if r["comparison"] == "AF / fastest":
        return f"{r['af_fastest']}/{r['cases']} fastest, {r['within_5_percent']} within 5%"
    return f"{r['af_wins']}/{r['unclear']}/{r['af_losses']} W/N/L"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("new", type=Path)
    parser.add_argument("--paper", type=Path, default=HERE, help="directory with the paper's result files")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    paper, new = rows(args.paper / "summary.csv"), rows(args.new / "summary.csv")
    lines = ["# New measurement compared with the paper", "",
             "## Performance table", "",
             "| Workload | Comparison | Paper: median / geo. mean | New: median / geo. mean | Paper outcome | New outcome |",
             "| --- | --- | ---: | ---: | --- | --- |"]
    for key, p in paper.items():
        n = new[key]
        lines.append(f"| {key[0]} | {key[1]} | {float(p['median']):.3f} / {float(p['geometric_mean']):.2f} | "
                     f"{float(n['median']):.3f} / {float(n['geometric_mean']):.2f} | {outcome(p)} | {outcome(n)} |")
    old_numbers = dict(flat(json.loads((args.paper / "paper-numbers.json").read_text(encoding="utf-8"))))
    new_numbers = dict(flat(json.loads((args.new / "paper-numbers.json").read_text(encoding="utf-8"))))
    lines += ["", "## Other latency figures of the evaluation", "", "| Figure | Paper | New |", "| --- | ---: | ---: |"]
    for name, value in old_numbers.items():
        other = new_numbers.get(name)
        fmt = (lambda v: f"{v:,.0f}") if isinstance(value, int) else (lambda v: f"{v:,.3f}")
        lines.append(f"| `{name}` | {fmt(value)} | {fmt(other) if other is not None else 'not measured'} |")
    text = "\n".join(lines) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
