"""Selected R02 declaration/effective-layout bridge for the unchanged 52 cells.

No PG or canonical algorithm imports occur on import. The original CONTENT
verifier, reference process and transaction adapter remain in use. Only its E3
selection interface is adapted to the frozen paired normal entry.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
import json
from pathlib import Path
import sys
import traceback

from support import DEFAULT_MANIFEST, DEFAULT_SOURCE, PairedSupport, sha


ROOT = Path(__file__).resolve().parents[2]
COMPATIBILITY = "specs/content_compatibility_full_predicate.yaml"
SPEC_SHA = "sha256:e214d0f590f304792f62432b884cff1b175353eec0c5909fbe944711bcde0086"
COMPATIBILITY_SHA = "sha256:7a2af11aabfcac505e114299684486942a2463d01d5fe4403bb7f987ca30569f"


def paired_session_class(module, support):
    original = module.FinalE3Session

    class PairedFinalE3Session(original):
        def __init__(self, root, pg_env, manifest_path, source, output, *,
                     access_root_wrapper=None, access_root_materialized_by_template=None):
            if (Path(root).resolve() != support.root or Path(source).resolve() != support.source
                    or access_root_wrapper not in {None, support.declared["access_root_wrapper"]}
                    or access_root_materialized_by_template is not None):
                raise ValueError("paired CONTENT requires its source declaration without runtime overrides")
            super().__init__(root, pg_env, manifest_path, source, output,
                             access_root_wrapper=support.declared["access_root_wrapper"],
                             access_root_materialized_by_template=None)

        def candidate(self, cell):
            # Keep the original setup and canonical P/q inputs. Selection is
            # performed by the frozen worker, never this project's renderer.
            from caprls_core import e3_main as e3
            from caprls_core.postgres_runner import run_psql_command
            support.guard()
            query, policy = self.queries[cell["query_id"]], self.policies[cell["policy_id"]]
            predicate = e3._policy_predicate(query, policy)
            build_ms, artifact_rows, keyed_rows = e3._build_artifact(query, policy, predicate, self.pg_env)
            e3._configure_native_rls(query, policy, self.pg_env)
            local = int(run_psql_command(
                f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} WHERE {e3._query_local_predicate(query)};", self.pg_env))
            authorized = int(run_psql_command(
                f"SELECT count(*) FROM public.{query.protected_rel} {query.alias} WHERE {predicate};", self.pg_env))
            request = {
                "worker_kind": "af", "variant": "af", "query_id": query.query_id,
                "policy_id": policy.config_id, "project_root": str(self.root),
                "manifest": str(self.manifest_path), "pg_env": asdict(self.pg_env),
                "access_root_materialized": False,
                "access_root_materialized_by_template": dict(support.declared["access_root_materialized_by_template"]),
                "stats": {"protected_rows": e3._protected_count(query, self.pg_env),
                          "query_local_rows": local, "authorized_rows": artifact_rows or authorized,
                          "artifact_build_ms": build_ms, "keyed_artifact_rows": keyed_rows},
            }
            self.worker, checked = support.run_worker(request)
            module._write(self.output / "workers" / (cell["short_id"] + ".json"), self.worker)
            module._write(self.output / "paired-audits" / (cell["short_id"] + ".json"), checked)
            spec, selection = self.worker["spec"], self.worker["selection"]
            effective = checked["effective_materialized_by_template"]
            if selection["access_root_materialized_by_template"] != effective:
                raise ValueError("paired CONTENT worker effective map differs from its validated decision")
            body, extraction = support.recover_core(spec["sql"], selection["bound_runner"])
            actual_materialized = extraction["actual_access_root_materialized"]
            selected_materialized = effective.get(spec["template_id"], checked["effective_base_materialized"])
            if actual_materialized != selected_materialized:
                raise ValueError("paired CONTENT actual wrapper differs from validated effective layout")
            proof = {
                **extraction,
                "manifest_access_root_wrapper": (self.manifest.get("scale_check") or {}).get("bound_runner_wrapper", "materialized"),
                "resolved_access_root_wrapper": support.declared["access_root_wrapper"],
                "access_root_wrapper_override": None,
                "declared_access_root_materialized_by_template": dict(support.declared["access_root_materialized_by_template"]),
                "access_root_materialized_by_template": effective,
                "access_root_materialized_by_template_override": None,
                "resolved_selected_access_root_materialized": selected_materialized,
                "actual_access_root_materialized": actual_materialized,
                "physical_recipe_strategy": support.declared["physical_recipe_strategy"],
                "physical_recipe_validation": checked["physical_recipe"],
                "support_r02_audit_ref": "paired-audits/" + cell["short_id"] + ".json",
                "selected_runner_digest_recomputed": support.study.digest_json({"exact_runner_sql": spec["sql"]}),
                "selected_plan_id": selection["selected_plan_id"],
                "actual_execution_profile": spec["execution_profile"],
                "actual_session_contract": spec["session_contract"],
                "actual_bound_runner": selection["bound_runner"],
                "worker_source_identity": self.worker["source_identity"],
            }
            proof.update(module.content.evaluate_r_c_containment(
                cell, body, "same" if spec["template_id"] == cell["frozen"]["selected_template_id"] else "differs"))
            if proof.get("r_c_containment") == "failed":
                raise module.content.ContentRefusal(
                    "actual paired bound root lacks the declared full query target",
                    partial={"extraction_proof": proof})
            support.guard()
            return module.content.CandidateBoundary(
                selected_template_id=spec["template_id"], selected_plan_id=selection["selected_plan_id"],
                selected_runner_digest=selection["selected_runner_digest"], runner_sql=spec["sql"],
                boundary_sql=body, prospective_total_cost=selection["prospective_total_cost"],
                predicate_text=predicate, extraction_proof=proof,
                candidate_cost_vector=selection["candidate_cost_vector"],
                cost_vector_source="actual frozen paired normal worker prospective selection")

    return PairedFinalE3Session


def candidate_block_formatter(module, original):
    def candidate_block(cell, candidate, *args, **kwargs):
        result = original(cell, candidate, *args, **kwargs)
        if cell["family"] == "E3":
            proof = candidate.extraction_proof
            actual = proof.get("fidelity")
            if (actual not in {"verbatim_subplan_planner_anchored",
                               "verbatim_cte_fragments_reclosed_planner_anchored"}
                    or proof.get("original_core_sql_digest_verified") is not True):
                raise module.content.ContentRefusal("E3 boundary lacks its digest-verified extraction fidelity")
            result = {**result, "declared_candidate_fidelity": result["candidate_fidelity"],
                      "candidate_fidelity": actual,
                      "fidelity_scope": "actual extraction; original specification declaration retained separately"}
        return result
    return candidate_block


def run(root, source, manifest, compatibility, output):
    root, source, manifest, compatibility, output = map(
        lambda value: Path(value).resolve(), (root, source, manifest, compatibility, output))
    if output.exists():
        raise ValueError("paired CONTENT output must be fresh")
    sys.path.insert(0, str(root))
    from caprls_core import final_af_content_study as module
    if Path(module.__file__).resolve() != root / "caprls_core/final_af_content_study.py":
        raise ValueError("CONTENT project-side verifier came from another tree")
    support = PairedSupport(root, source, extra_files=(Path(__file__), Path(module.__file__),
                                                     manifest, compatibility))
    # E2/E10 execute in the project verifier process, while E3 uses isolated
    # source workers. Require the project implementation to be exactly the
    # selected source too; a historical R08 verifier cannot qualify R02 here.
    project_identity = support.study.source_identity(root)
    if project_identity["digest"] != support.identity["digest"]:
        raise ValueError("CONTENT project algorithms must match the selected R02 source")
    from planner.identity_observation import backend_info
    if backend_info() != support.native_backend:
        raise ValueError("CONTENT E2/E10 process did not load the selected native backend")
    declaration = module.load_compatibility(root, compatibility)
    if declaration["expected_cells"] != 52 or declaration["family_cells"] != {"E2": 8, "E3": 33, "E10": 11}:
        raise ValueError("paired CONTENT requires the complete existing 52-cell specification")
    spec_path = root / declaration["base_spec"]
    if sha(spec_path) != SPEC_SHA or sha(compatibility) != COMPATIBILITY_SHA:
        raise ValueError("paired CONTENT requires the unchanged full-local-q52 specification/compatibility")
    spec = module.content.load_spec(spec_path)
    cells = module.content.ordered_cells(spec)
    if len(cells) != 52 or sum(cell["family"] == "E3" for cell in cells) != 33:
        raise ValueError("paired CONTENT input lost the complete E3 local-q grid")
    # This is an interface adapter. The existing full-local-q specification,
    # compatibility audit, reference process and 19 non-E3 sessions are intact.
    original_class, original_write = module.FinalE3Session, module._write
    original_candidate_block = module.content._candidate_block

    def write(path, value):
        if Path(path).name == "summary.json":
            support.guard()
        if Path(path) == output / "protocol.json":
            value = {**value, **support.protocol_fields(),
                     "project_algorithm_identity": project_identity,
                     "project_identity_backend": backend_info(),
                     "legacy_wrapper_bridge": "source declaration passed to unchanged legacy argument; no user override",
                     "support_execution_scope": "33 E3 actual producer boundaries; 19 original non-E3 fidelity cases"}
            original_write(path, value)
            support.archive(output, original_write)
            return
        original_write(path, value)

    module.FinalE3Session = paired_session_class(module, support)
    module._write = write
    module.content._candidate_block = candidate_block_formatter(module, original_candidate_block)
    try:
        result = module.run_content_study(
            root, output, source=source, manifest=manifest, compatibility=compatibility,
            access_root_wrapper=support.declared["access_root_wrapper"],
            access_root_materialized_by_template=None)
    finally:
        module.content._candidate_block = original_candidate_block
        module.FinalE3Session, module._write = original_class, original_write
    support.guard()
    if (support.study.source_identity(root) != project_identity
            or backend_info() != support.native_backend):
        raise ValueError("CONTENT project implementation/backend changed")
    checks = [json.loads(path.read_text()) for path in (output / "paired-audits").glob("*.json")]
    receipts = [json.loads(path.read_text()) for path in (output / "receipts").glob("*.json")]
    if (result["status"] != "pass" or not result["full_52_cell_coverage"] or len(checks) != 33
            or len(receipts) != 52 or {r["short_id"] for r in receipts} != {c["short_id"] for c in cells}
            or any(c["physical_recipe"]["status"] != "verified" or c["normal"]["normal_execution_verified"] is not True for c in checks)):
        raise RuntimeError("paired CONTENT did not finish its full original and paired interface gates")
    original_write(output / "paired-support-completion.json", {
        "schema": "a016_content_r02_completion_v1", "status": "pass", "full_52_cell_coverage": True,
        "physical_recipe_checks": len(checks), "normal_entry_execution_checks": len(checks),
        "non_e3_fidelity": dict(Counter(r["candidate"]["candidate_fidelity"] for r in receipts if r["family"] != "E3")),
        "actual_e3_extraction_fidelity": dict(Counter(r["candidate"]["candidate_fidelity"] for r in receipts if r["family"] == "E3")),
        "declared_e3_fidelity_preserved_separately": all("declared_candidate_fidelity" in r["candidate"] for r in receipts if r["family"] == "E3"),
        "vacuous_cells": sorted(r["short_id"] for r in receipts if r["result"]["vacuous"]),
        "source_and_adapter_unchanged": True, "query_latency_measured": False,
    })
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--source-root", type=Path, default=ROOT / DEFAULT_SOURCE)
    parser.add_argument("--manifest", type=Path, default=ROOT / DEFAULT_MANIFEST)
    parser.add_argument("--compatibility", type=Path, default=ROOT / COMPATIBILITY)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    existed = args.output_dir.resolve().exists()
    try:
        result = run(args.root, args.source_root, args.manifest, args.compatibility, args.output_dir)
        print(json.dumps({"status": result["status"], "full_52_cell_coverage": result["full_52_cell_coverage"]}))
        return 0
    except Exception as exc:
        if not existed and args.output_dir.is_dir():
            with (args.output_dir / "paired-support-failure.json").open("x") as handle:
                json.dump({"status": "failed", "error": str(exc), "traceback": traceback.format_exc()}, handle, indent=2)
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
