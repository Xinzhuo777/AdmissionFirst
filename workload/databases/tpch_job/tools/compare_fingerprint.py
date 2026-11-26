#!/usr/bin/env python3
"""Compare a fingerprint (from fingerprint.py) with the published expected one.

By default everything must match exactly, including every pg_statistic row
(build.sh loads the recorded statistics).  With --sampled-statistics (a build
that kept its own ANALYZE results) the values PostgreSQL derives from
ANALYZE's random sample are only reported, not counted as differences:
  * reltuples of tables with more than 30000 pages (ANALYZE reads a random
    sample of 30000 pages) and reltuples of their indexes;
  * reltuples of partial indexes on tables with more than 30000 rows;
  * the pg_statistic digests.
Of the cluster's roles only the benchmark login role is compared.
"""

import argparse
import json
import sys

SAMPLE_PAGES = 30000  # 300 * default_statistics_target (100)
BENCH_ROLE = "caprls_e3_rls_user"


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def sampled_relations(fp):
    catalog = fp["catalog"]
    relations = {r["name"]: r for r in catalog["relations"]}
    rows = {name: t["rows"] for name, t in fp["tables"].items()}
    sampled = set()
    for name, rel in relations.items():
        if rel["kind"] == "r" and rel["relpages"] > SAMPLE_PAGES:
            sampled.add(name)
    for index in catalog["indexes"]:
        table = index["table"] if "." in index["table"] else "public." + index["table"]
        name = index["name"] if "." in index["name"] else "public." + index["name"]
        partial = " WHERE " in index["definition"]
        if table in sampled or (partial and rows.get(table, 0) > SAMPLE_PAGES):
            sampled.add(name)
    return sampled


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("expected")
    parser.add_argument("actual")
    parser.add_argument("--sampled-statistics", action="store_true",
                        help="the build kept its own (randomly sampled) ANALYZE statistics")
    args = parser.parse_args()
    expected, actual = load(args.expected), load(args.actual)
    sampled = sampled_relations(expected) if args.sampled_statistics else set()
    problems, notes = [], []

    for key in sorted(set(expected["catalog"]) | set(actual["catalog"])):
        left, right = expected["catalog"].get(key), actual["catalog"].get(key)
        if key == "roles":
            left = [r for r in left or [] if r["name"] == BENCH_ROLE]
            right = [r for r in right or [] if r["name"] == BENCH_ROLE]
        if key == "relations":
            lrel = {r["name"]: r for r in left or []}
            rrel = {r["name"]: r for r in right or []}
            for name in sorted(set(lrel) | set(rrel)):
                if name not in lrel or name not in rrel:
                    problems.append(f"relation {name}: present only in "
                                    f"{'expected' if name in lrel else 'actual'}")
                    continue
                for field in sorted(set(lrel[name]) | set(rrel[name])):
                    a, b = lrel[name].get(field), rrel[name].get(field)
                    if a == b:
                        continue
                    if field == "reltuples" and name in sampled:
                        notes.append(f"sampled  {name}.reltuples expected {a} actual {b}")
                    else:
                        problems.append(f"relation {name}.{field}: expected {a!r} actual {b!r}")
            continue
        if key == "statistics":
            for column in sorted(set(left or {}) | set(right or {})):
                a, b = (left or {}).get(column), (right or {}).get(column)
                if a == b:
                    continue
                message = f"statistics {column}: expected {a} actual {b}"
                if args.sampled_statistics and a is not None and b is not None:
                    notes.append("sampled  " + message)
                else:
                    problems.append(message)
            same = sum(1 for c in (left or {}) if (right or {}).get(c) == left[c])
            notes.append(f"pg_statistic rows identical: {same} of {len(left or {})}")
            continue
        if left != right:
            problems.append(f"catalog {key}: expected {json.dumps(left)[:400]} "
                            f"actual {json.dumps(right)[:400]}")

    for table in sorted(set(expected["tables"]) | set(actual["tables"])):
        a, b = expected["tables"].get(table), actual["tables"].get(table)
        if a != b:
            problems.append(f"table {table}: expected {a} actual {b}")
        else:
            notes.append(f"same     {table}: {a['rows']} rows, physical {a['physical_sha256'][:16]}")

    for line in notes:
        print(line)
    for line in problems:
        print("DIFF     " + line)
    print(f"{len(problems)} difference(s)" +
          (" outside sampled statistics" if args.sampled_statistics else ""))
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
