"""Revalidate the paper's 21 constructed full-AF decisions (13 E1 + 8 E6a)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import time
import traceback
from typing import Any, Mapping, Sequence

from .final_af_auxiliary_study import ROOT, PROTECTED, _sha, _snapshot, _source_inventory, _freeze_driver_files, _drift, _utc, _write

PANEL_MAPPING = "figures/evaluation-composite/original-protocol-20261011/full_source_mapping.json"


def expected_panel_cases(root: Path) -> dict[str, bool]:
    panel = json.loads((root / PANEL_MAPPING).read_text())["panel_a"]
    expected = {row["test_id"]: row["expected_query_plan_ok"] for row in panel}
    if len(panel) != 21 or len(expected) != 21 or sum(expected.values()) != 11:
        raise ValueError("paper's predeclared 21-case panel identity differs")
    return expected


def check_panel_records(records: Sequence[tuple[Path, Mapping[str, Any]]],
                        expected: Mapping[str, bool]) -> list[dict[str, Any]]:
    from .baselines import ADMISSION_FIRST_MODE, normalize_mode_id
    checked = []
    for path, record in records:
        diagnostic = (record.get("e1_contract_case") or record.get("e6a_sigma_case") or {}).get("diagnostic")
        if normalize_mode_id(record["mode"]) != ADMISSION_FIRST_MODE or diagnostic is not False:
            continue
        query = record["query"]["query_id"]
        actual = record["planner"]["query_plan"]["ok"]
        if query not in expected or type(actual) is not bool:
            raise ValueError("unexpected AF fixture or missing actual planner decision: " + query)
        checked.append({"test_id": query, "expected_query_plan_ok": expected[query],
                        "actual_query_plan_ok": actual, "decision_matches_expected": actual == expected[query],
                        "source_raw_path": str(path), "source_raw_sha256": _sha(path),
                        "decision_field": "planner.query_plan.ok", "diagnostic": False})
    identities = [row["test_id"] for row in checked]
    if len(checked) != 21 or len(set(identities)) != 21 or set(identities) != set(expected):
        raise ValueError("fresh records do not cover the exact 21 full-AF fixture identities")
    if not all(row["decision_matches_expected"] for row in checked):
        raise ValueError("fresh AF decision disagrees with a predeclared fixture expectation")
    return sorted(checked, key=lambda row: row["test_id"])


def run_admission_study(root: Path, output: Path) -> dict[str, Any]:
    root, output = root.resolve(), output.resolve()
    if not any(output != base and output.is_relative_to(base)
               for base in (root / "results/raw", root / "AF-wiki/raw/experiments")):
        raise ValueError("output must be a fresh experiment directory")
    expected = expected_panel_cases(root)
    output.mkdir(parents=True, exist_ok=False)
    drivers = ("caprls_core/final_af_auxiliary_study.py", "caprls_core/final_af_admission_study.py", PANEL_MAPPING)
    snapshot = _snapshot(root, driver_files=drivers)
    snapshot[PANEL_MAPPING] = _sha(root / PANEL_MAPPING)
    protected = {name: _sha(root / name) for name in PROTECTED if (root / name).is_file()}
    _write(output / "source-snapshot.json", snapshot)
    _write(output / "source-inventory.json", _source_inventory(root))
    _freeze_driver_files(root, output, drivers)
    _write(output / "protected-snapshot.json", protected)
    _write(output / "protocol.json", {"started_at": _utc(), "schema": "caprls-final-af-admission-v1",
           "cases": expected, "paper_panel_mapping": PANEL_MAPPING, "paper_panel_mapping_sha256": _sha(root / PANEL_MAPPING),
           "family_counts": {"E1": 13, "E6a_full_system_controls": 8},
           "diagnostic_records_count_as_AF": False, "database_access": False})
    started, failure, checked = time.perf_counter(), None, []
    try:
        from .e1_smoke import run_e1_smoke
        from .e6a_smoke import run_e6a_smoke
        first = run_e1_smoke(root, root / "manifests/experiments/e1_smoke.yaml", output / "E1")
        sixth = run_e6a_smoke(root, root / "manifests/experiments/e6a_sigma_gate.yaml", output / "E6a")
        records = [(path, json.loads(path.read_text())) for path in first.raw_result_paths + sixth.raw_result_paths]
        checked = check_panel_records(records, expected)
        _write(output / "panel-a-decisions.json", checked)
    except Exception as exc:
        failure = {"error": str(exc), "traceback": traceback.format_exc()}
    source_drift, protected_drift = _drift(root, snapshot), _drift(root, protected)
    summary = {"schema": "caprls-final-af-admission-summary-v1", "finished_at": _utc(),
               "status": "pass" if failure is None and not source_drift and not protected_drift else "fail",
               "cases": len(checked), "expected_cases": 21, "matched": sum(r["decision_matches_expected"] for r in checked),
               "admitted": sum(r["actual_query_plan_ok"] for r in checked),
               "rejected": sum(not r["actual_query_plan_ok"] for r in checked),
               "elapsed_seconds": time.perf_counter() - started, "failure": failure,
               "source_drift": source_drift, "protected_drift": protected_drift}
    _write(output / "summary.json", summary)
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = run_admission_study(ROOT, args.output)
    print(json.dumps(result, indent=2), flush=True)
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
