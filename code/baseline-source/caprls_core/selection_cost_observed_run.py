"""One original-protocol campaign with sparse, directly measured choice costs.

The original business drivers, count SQL, roles, validation and estimators are
retained. Only observation and the separately tested pure-content digest
memoization differ. Existing results are never resumed, overwritten or removed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
ACTIVITY = "ORIGINAL_PROTOCOL_OBSERVED_20261010_V1"
BASE = ROOT / "output/observer_optimization_rerun_2026-10-10"
OLD = ROOT / "output/section65_original_protocol_execution_2026-10-06"
E3_MANIFEST = OLD / "e3_original_30.yaml"
E10_MANIFEST = OLD / "e10_original_30.yaml"
AUX_HELPER = OLD / "run_auxiliary_original.py"
AUX_SHA = "f1e50c773a902018aa0502160f25741090544366f78e8498ba6ebb8f36a19cce"
AUX_STAGES = (
    "E2_PROTOCOL", "E1", "E7", "E4_PROTOCOL", "E5_PROTOCOL",
    "E3_CANONICAL_CORRECTNESS", "CONTENT_BOUNDARY", "STABILITY_WITNESS",
    "SF10_P1", "SF10_P2", "SF10_P3",
)
REPORT_ONLY = {"paper_figures.py", "sigmod_release.py"}
ALLOWED_IMPLEMENTATION = {"planner/root_selection.py", "planner/strict_planning.py"}


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_once(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, default=str)
        handle.write("\n")


def environment():
    env = dict(os.environ)
    env.pop("CAPRLS_PG_EXTRA_OPTS", None)
    env.update(CAPRLS_PG_SHARED_BUFFERS="16MB",
               CAPRLS_PG_INITDB_SHARED_BUFFERS="400kB",
               CAPRLS_PG_INITDB_MAX_CONNECTIONS="20")
    return env


def source_snapshot():
    paths = list((ROOT / "planner").rglob("*.py"))
    paths += [p for p in (ROOT / "caprls_core").rglob("*.py") if p.name not in REPORT_ONLY]
    paths += list((ROOT / "sql").rglob("*.sql"))
    paths += list((ROOT / "manifests/experiments").glob("*.yaml"))
    paths += [ROOT / "configs/pg_smoke.yaml", E3_MANIFEST, E10_MANIFEST, AUX_HELPER,
              OLD / "independent_analysis/analyze_original.py",
              ROOT / "specs/selection_difference_classification.yaml"]
    return {str(p.relative_to(ROOT)): sha(p) for p in sorted(set(paths))
            if p.exists() and not p.name.startswith("._")}


def drift(snapshot):
    return [name for name, expected in snapshot.items()
            if not (ROOT / name).exists() or sha(ROOT / name) != expected]


def protected_snapshot():
    paths = [ROOT / name for name in ("main.tex", "reference-manuscript.tex", "main.pdf", "reference-manuscript.pdf")]
    # Preserve fingerprints of all earlier campaign metadata and the accepted
    # original cost sidecar; no new write target is in an earlier activity.
    for pattern in ("*/protocol.json", "*/completion.json", "*/analysis_receipt.json"):
        paths.extend((ROOT / "results/raw").glob(pattern))
    paths += [ROOT / "results/raw/ORIGINAL_TABLE3_COST_NOISE_20261006_V1/choice_costs.jsonl",
              OLD / "independent_analysis/adjudicated_reduction_v1/analysis.json"]
    return {str(p.relative_to(ROOT)): sha(p) for p in sorted(set(paths)) if p.is_file()}


def original_identity():
    """Permit exactly the authorized pure-content implementation change."""
    original = json.loads((ROOT / "results/raw/ORIGINAL_TABLE3_COST_NOISE_20261006_V1/original_source_snapshot.json").read_text())
    changed = [p for p, expected in original.items() if sha(ROOT / p) != expected]
    permitted = ALLOWED_IMPLEMENTATION | {"caprls_core/" + p for p in REPORT_ONLY}
    unexpected = sorted(set(changed) - permitted)
    if unexpected:
        raise RuntimeError("unexpected original measurement changes: " + repr(unexpected))
    return {"prior_registered_sources": len(original), "changed": changed,
            "authorized_implementation_changes": sorted(ALLOWED_IMPLEMENTATION),
            "report_only_exclusions": sorted(REPORT_ONLY), "unexpected": unexpected}


def offline_check():
    import yaml
    from caprls_core import e3_main as e3, e10_study as e10
    from caprls_core.selection_cost_e3 import load_family, assert_measurement_identity
    changes = original_identity()
    for new_path, old_name in ((E3_MANIFEST, "e3_standard_sf1_rawpg.yaml"), (E10_MANIFEST, "e10_case_study.yaml")):
        new = yaml.safe_load(new_path.read_text())
        old = yaml.safe_load((ROOT / "manifests/experiments" / old_name).read_text())
        if new.pop("repetitions") != {"warmup": 5, "measured": 30}:
            raise RuntimeError("formal repetition configuration differs")
        old.pop("repetitions")
        if new != old:
            raise RuntimeError("formal manifest differs beyond original 5/30 repetitions")
    loaded = load_family(ROOT, E3_MANIFEST)
    checked = 0
    for query in loaded["queries"]:
        for policy in loaded["policies"]:
            for template in e3._e3_registry_from_manifest(loaded["manifest"]).template_specs():
                assert_measurement_identity(e3, query, policy, template.template_id)
                checked += 1
    e10._validate_manifest(E10_MANIFEST, yaml.safe_load(E10_MANIFEST.read_text()))
    return {"status": "pass", "database_access": False, "sampling_started": False,
            "original_sql_identity_checks": checked, "source_identity": changes,
            "auxiliary_stages": list(AUX_STAGES)}


def load_auxiliary():
    if sha(AUX_HELPER) != AUX_SHA:
        raise RuntimeError("preserved original auxiliary helper changed")
    spec = importlib.util.spec_from_file_location("caprls_preserved_auxiliary_entries", AUX_HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def auxiliary_gate(run):
    completion = json.loads((run / "completion.json").read_text())
    receipt_path = run / "auto_reduction/receipt.json"
    receipt = json.loads(receipt_path.read_text())
    if completion.get("status") != "pass" or receipt.get("status") != "pass" or not receipt.get("ready") or receipt.get("cases") != 44:
        raise RuntimeError("new 44-case core and complete component analysis must pass")
    if sha(Path(receipt["analysis_path"])) != receipt["analysis_sha256"]:
        raise RuntimeError("new core analysis identity mismatch")
    return {"path": str(run / "completion.json"), "sha256": sha(run / "completion.json"),
            "status": "pass", "analysis_receipt": str(receipt_path),
            "analysis_receipt_sha256": sha(receipt_path)}


def internal_auxiliary(run, stage):
    gate = auxiliary_gate(run)
    original = load_auxiliary()
    original.core_pass = lambda requested, **unused: gate if Path(requested).resolve() == run.resolve() else (_ for _ in ()).throw(RuntimeError("wrong core"))
    original.independent_pass = lambda **unused: gate
    target = run / "auxiliary" / ("CONTENT_BOUNDARY" if stage == "content" else "STABILITY_WITNESS")
    (original.content_stage if stage == "content" else original.stability_stage)(target, run)


def auxiliary_entries(run):
    original = load_auxiliary()
    result = [entry for entry in original.stages(run / "auxiliary", run) if entry["stage"] in AUX_STAGES]
    result.sort(key=lambda entry: AUX_STAGES.index(entry["stage"]))
    for entry in result:
        if entry["stage"] in {"CONTENT_BOUNDARY", "STABILITY_WITNESS"}:
            internal = "content" if entry["stage"] == "CONTENT_BOUNDARY" else "stability"
            entry["command"] = [sys.executable, "-m", "caprls_core.selection_cost_observed_run", "--output", str(run), "--internal-auxiliary", internal]
    return result


def run_auxiliary(run, frozen):
    gate = auxiliary_gate(run)
    output = run / "auxiliary"
    output.mkdir(exist_ok=False)
    entries = auxiliary_entries(run)
    write_once(output / "protocol.json", {"started_at": utc(), "gate": gate, "commands": entries,
        "original_helper_sha256": AUX_SHA, "expected_stages": list(AUX_STAGES), "no_retry": True,
        "repetitions": "original auxiliary 5+10 or original deterministic counts"})
    results = []
    for entry in entries:
        if drift(frozen):
            raise RuntimeError("frozen measurement source changed before auxiliary stage")
        started = time.monotonic()
        print(json.dumps({"event": "auxiliary_stage_started", "stage": entry["stage"], "time": utc()}), flush=True)
        with (output / (entry["stage"] + ".log")).open("x") as log:
            proc = subprocess.run(entry["command"], cwd=ROOT, env=environment(), stdout=log, stderr=subprocess.STDOUT)
        item = {"stage": entry["stage"], "returncode": proc.returncode,
                "elapsed_seconds": time.monotonic() - started, "finished_at": utc(),
                "output": entry["output"], "retried": False,
                "execution_status": "completed" if proc.returncode == 0 else "failed",
                "evidence_status": "independent_content_validation_pending"}
        write_once(output / "stage_receipts" / (entry["stage"] + ".json"), item)
        results.append(item)
        print(json.dumps({"event": "auxiliary_stage_finished", **item}), flush=True)
    changed = drift(frozen)
    result = {"finished_at": utc(), "execution_status": "complete" if all(item["returncode"] == 0 for item in results) and not changed else "needs_review",
              "stages": results, "expected_stages": list(AUX_STAGES), "changed_measurement_sources": changed,
              "independent_evidence_validation": "pending", "no_retry": True}
    write_once(output / "completion.json", result)
    return result


def preflight_manifests(output):
    import yaml
    output.mkdir(parents=True, exist_ok=False)
    e3 = yaml.safe_load(E3_MANIFEST.read_text())
    e3["queries"] = [q for q in e3["queries"] if q["query_id"] == "Q10"]
    e3["policy_configs"] = [p for p in e3["policy_configs"] if p["id"] == "hybrid_selective_key"]
    e3["query_sets"] = {"tpch": ["Q10"], "job_selected_policy_stress": []}
    e3["repetitions"] = {"warmup": 1, "measured": 1}
    e10 = yaml.safe_load(E10_MANIFEST.read_text())
    e10["repetitions"] = {"warmup": 1, "measured": 1}
    paths = []
    for name, value in (("e3_preflight.yaml", e3), ("e10_preflight.yaml", e10)):
        path = output / name
        with path.open("x") as stream:
            yaml.safe_dump(value, stream, sort_keys=False)
        paths.append(path)
    return paths


def adjudicate_preflight():
    """Re-read saved measurements after the exact reader-only label fix.

    The initial completion and all sampled files remain immutable. This is not
    permission to change sampling code or waive missing observations.
    """
    from caprls_core.selection_cost_observed_analyze import validate_and_summarize_components
    preflight = BASE / "preflight"
    completion = json.loads((preflight / "completion.json").read_text())
    families = {entry["family"]: entry["status"] for entry in completion["families"]}
    failures = completion.get("failures", [])
    if (families != {"E3": "pass", "E10": "pass"} or completion.get("observer_errors")
            or completion.get("changed_measurement_sources") or completion.get("previous_result_drift")
            or len(failures) != 1 or not failures[0]["error"].startswith("component coverage failed: cases=12 expected=12 blockers=")
            or "admission: installed coverage hooks missing or not bound to inventory" not in failures[0]["error"]):
        raise RuntimeError("preflight is not the known reader-label-only failure")
    prior = json.loads((preflight / "original_source_snapshot.json").read_text())
    allowed = {"caprls_core/selection_cost_observed_analyze.py", "caprls_core/selection_cost_observed_run.py"}
    if set(drift(prior)) != allowed:
        raise RuntimeError("preflight sampling sources changed beyond reader and gate correction")
    for name in allowed:
        backup = BASE / "pre_optimization_sources/caprls_core" / (Path(name).stem + ".preflight_v1.py")
        if sha(backup) != prior[name]:
            raise RuntimeError("preflight reader/gate backup does not match sampled snapshot")
    if sha(ROOT / "caprls_core/selection_cost_observed_analyze.py") != "e7686c80f26f035e163c38db6a437fc50a897fd9eecf5c299aa99d1226a16e93":
        raise RuntimeError("reader differs from independently tested exact alias fix")
    records = [json.loads(line) for line in (preflight / "choice_costs.jsonl").read_text().splitlines() if line.strip()]
    keys = sorted({(row["family"], row.get("query_id", row.get("case_id")), row.get("policy_id", "") if row["family"] == "E3" else "")
                   for row in records if row.get("record_kind") == "choice"})
    components = validate_and_summarize_components(records, keys, warmup=1, measured=1)
    choice_count = sum(row.get("record_kind") == "choice" for row in records)
    if len(keys) != 12 or choice_count != 23 or not components["ready"]:
        raise RuntimeError("saved preflight component observations do not pass corrected reader")
    inputs = {str(path.relative_to(preflight)): sha(path) for path in sorted(preflight.rglob("*"))
              if path.is_file() and not path.name.startswith("._")}
    receipt = {"status": "pass", "validated_at": utc(), "database_access": False,
        "sampling_repeated": False, "initial_completion_retained": True,
        "reason": "Exact canonical/class-binding alias normalization in offline reader only; all actual observations retained",
        "allowed_post_preflight_sources": sorted(allowed), "source_snapshot": source_snapshot(),
        "preflight_input_hashes": inputs, "choice_records": choice_count, "cases": len(keys),
        "direct_components": components}
    write_once(BASE / "preflight_adjudication.json", receipt)
    return {key: receipt[key] for key in ("status", "validated_at", "database_access", "sampling_repeated", "choice_records", "cases")}


def validate_preflight():
    preflight = BASE / "preflight"
    completion = json.loads((preflight / "completion.json").read_text())
    if completion.get("status") == "pass" and not drift(json.loads((preflight / "original_source_snapshot.json").read_text())):
        return
    receipt = json.loads((BASE / "preflight_adjudication.json").read_text())
    if receipt.get("status") != "pass" or receipt.get("sampling_repeated") is not False or drift(receipt["source_snapshot"]):
        raise RuntimeError("read-only preflight adjudication is invalid or final sources changed")
    for name, expected in receipt["preflight_input_hashes"].items():
        path = preflight / name
        if not path.resolve().is_relative_to(preflight.resolve()) or not path.is_file() or sha(path) != expected:
            raise RuntimeError("saved preflight input changed after read-only adjudication")


def run_core(run, *, preflight=False):
    from caprls_core import e3_main as e3, e10_study as e10
    from caprls_core.postgres_runner import temporary_cluster, run_psql_command
    from caprls_core.selection_cost_observer import SparseSelectionObserver
    from caprls_core.selection_cost_observed_analyze import validate_and_summarize_components
    if sys.getprofile() is not None:
        raise RuntimeError("a global profiler is active before the new campaign")
    if preflight:
        manifests = preflight_manifests(run)
    else:
        if not (BASE / "preflight/completion.json").exists():
            raise RuntimeError("real-path preflight has not completed")
        validate_preflight()
        run.mkdir(parents=True, exist_ok=False)
        manifests = [E3_MANIFEST, E10_MANIFEST]
    frozen = source_snapshot()
    protected = protected_snapshot()
    write_once(run / "original_source_snapshot.json", frozen)
    write_once(run / "protected_previous_files.json", protected)
    write_once(run / "protocol.json", {"activity": ACTIVITY + ("_PREFLIGHT" if preflight else ""), "started_at": utc(), "pid": os.getpid(),
        "original_drivers": ["run_e3_main", "run_e10_case_study"], "warmup": 1 if preflight else 5, "measured": 1 if preflight else 30,
        "temporary_cluster": "original_private_16MB", "primary": "original server planning+execution+original applicable validation",
        "choice_E3": "one original planner call per cell, precollected inputs excluded",
        "choice_E10": "original per-case START/STOP anchor includes case planning inputs",
        "measurement_change": "global profiler replaced by named sparse function-boundary timers; original total interval retained",
        "implementation_config_change": {"pure_content_digest_memoization": sorted(ALLOWED_IMPLEMENTATION),
             "selection_algorithm_change": False, "candidate_inventory_change": False, "sql_render_change": False,
             "execution_role_change": False, "database_call_change": False, "global_profile_enabled": False},
        "manifests": list(map(str, manifests)), "no_retry": True,
        "preflight_only": preflight, "expected_core_cases": 12 if preflight else 44,
        "auxiliary_stages": [] if preflight else list(AUX_STAGES), "manuscript_adoption": False})
    statuses, failures, observer_errors, costs = [], [], [], []
    try:
        with (run / "choice_costs.jsonl").open("x") as sidecar:
            for family, manifest in zip(("E3", "E10"), manifests):
                output = run / family
                output.mkdir()
                with temporary_cluster(database="caprls_smoke") as pg:
                    buffers = run_psql_command("SHOW shared_buffers;", pg).strip()
                    if buffers != "16MB":
                        raise RuntimeError(f"original shared_buffers differs: {buffers}")
                    write_once(run / (family + "_original_environment.json"), {"shared_buffers": buffers, "host": pg.host, "port": pg.port,
                         "database": pg.database, "user": pg.user, "global_profile_enabled": False})
                    module = e3 if family == "E3" else e10
                    with SparseSelectionObserver(sidecar, **{family.lower(): module}) as observer:
                        result = e3.run_e3_main(ROOT, pg, manifest, output) if family == "E3" else e10.run_e10_case_study(ROOT, manifest, output, pg)
                    observer_errors.extend(observer.errors)
                    statuses.append({"family": family, "status": "pass", "normal_records": result.normal_records, "candidate_records": result.candidate_records})
                    print(json.dumps({"time": utc(), "event": "family_complete", **statuses[-1]}), flush=True)
        costs = [json.loads(line) for line in (run / "choice_costs.jsonl").read_text().splitlines() if line.strip()]
        keys = sorted({(row["family"], row.get("query_id", row.get("case_id")), row.get("policy_id", "") if row["family"] == "E3" else "")
                       for row in costs if row.get("record_kind") == "choice"})
        components = validate_and_summarize_components(costs, keys, warmup=1 if preflight else 5, measured=1 if preflight else 30)
        required_cases = 12 if preflight else 44
        if len(keys) != required_cases or not components["ready"]:
            raise RuntimeError(f"component coverage failed: cases={len(keys)} expected={required_cases} blockers={components['blockers']}")
        write_once(run / "direct_component_coverage.json", components)
    except Exception as exc:
        failures.append({"error": str(exc), "traceback": traceback.format_exc()})
        print(json.dumps({"time": utc(), "event": "activity_failed", **failures[-1]}), flush=True)
    changed = drift(frozen)
    old_drift = [name for name in drift(protected) if name.startswith("results/") or "adjudicated_reduction" in name]
    completion = {"completed_at": utc(), "status": "pass" if len(statuses) == 2 and not failures and not observer_errors and not changed and not old_drift else "needs_review",
        "families": statuses, "failures": failures, "observer_errors": observer_errors, "changed_measurement_sources": changed,
        "changed_original_sources": changed, "previous_result_drift": old_drift,
        "preflight_only": preflight, "no_retry": True, "global_profile_enabled": False}
    write_once(run / "completion.json", completion)
    print(json.dumps(completion), flush=True)
    return completion, frozen


def campaign(run):
    completion, frozen = run_core(run)
    analysis_ready, auxiliary = False, None
    try:
        # No analysis competes with primary query measurement.
        from caprls_core.selection_cost_observed_analyze import analyze
        exit_code = analyze(run, run / "auto_reduction")
        analysis_ready = exit_code == 0
        if analysis_ready:
            auxiliary = run_auxiliary(run, frozen)
        else:
            (run / "auxiliary").mkdir(exist_ok=False)
            auxiliary = {"execution_status": "blocked", "reason": "new core or direct component analysis did not pass", "stages": [], "database_access": False}
            write_once(run / "auxiliary/completion.json", auxiliary)
    except Exception as exc:
        auxiliary = {"execution_status": "needs_review", "reason": str(exc), "traceback": traceback.format_exc()}
        if not (run / "auxiliary/completion.json").exists():
            write_once(run / "auxiliary/completion.json", auxiliary)
    aux_complete = auxiliary is not None and auxiliary.get("execution_status") == "complete"
    chapter = {"finished_at": utc(), "status": "pass" if completion["status"] == "pass" and analysis_ready and aux_complete else "needs_review",
        "core_pass": completion["status"] == "pass", "analysis_ready": analysis_ready,
        "auxiliary_execution_complete": aux_complete, "expected_aux_stages": list(AUX_STAGES),
        "observed_aux_stages": [entry["stage"] for entry in (auxiliary or {}).get("stages", [])],
        "auxiliary": auxiliary, "evidence_validation": "auxiliary execution receipts require claim-by-claim interpretation",
        "no_retry": True, "manuscript_adoption": False}
    write_once(run / "chapter_completion.json", chapter)
    print(json.dumps(chapter), flush=True)
    return 0 if chapter["status"] == "pass" else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "results/raw" / ACTIVITY)
    parser.add_argument("--offline-check", action="store_true")
    parser.add_argument("--adjudicate-preflight", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--detach", action="store_true")
    parser.add_argument("--internal-auxiliary", choices=("content", "stability"))
    args = parser.parse_args(argv)
    if args.adjudicate_preflight:
        print(json.dumps(adjudicate_preflight()), flush=True)
        return 0
    if args.offline_check:
        print(json.dumps(offline_check()), flush=True)
        return 0
    run = args.output.resolve()
    if args.internal_auxiliary:
        internal_auxiliary(run, args.internal_auxiliary)
        return 0
    if not run.is_relative_to(ROOT / "results/raw") and not (args.preflight and run == BASE / "preflight"):
        raise RuntimeError("output must be a new narrow campaign directory")
    if run in (ROOT / "results/raw", ROOT) or run.exists():
        raise RuntimeError("refusing existing/broad output, overwrite, or resume")
    if args.detach:
        command = ["/usr/bin/caffeinate", "-i", sys.executable, "-u", "-m", "caprls_core.selection_cost_observed_run",
                   *[arg for arg in sys.argv[1:] if arg != "--detach"]]
        log = BASE / (run.name + ".log")
        with log.open("x") as stream:
            child = subprocess.Popen(command, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
                                     stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        write_once(BASE / "launch.json", {"started_at": utc(), "pid": child.pid, "command": command, "log": str(log),
                  "activity": ACTIVITY, "run": str(run), "no_retry": True})
        print(json.dumps({"pid": child.pid, "log": str(log), "run": str(run)}), flush=True)
        return 0
    os.environ.update(environment())
    return (0 if run_core(run, preflight=True)[0]["status"] == "pass" else 2) if args.preflight else campaign(run)


if __name__ == "__main__":
    raise SystemExit(main())
