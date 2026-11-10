"""Generate the final SIGMOD report and provenance from existing summaries."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .baselines import (
    ADMISSION_FIRST_MODE,
    ADMISSION_FIRST_NO_DOMINANCE_MODE,
    LEGACY_CONTRACT_AWARE_MODE,
    LEGACY_CONTRACT_AWARE_NO_DOMINANCE_MODE,
)


class SigmodReleaseError(ValueError):
    """The current paper authority is missing or inconsistent."""


LEGACY_CURRENT = Path("results/summarized/SIGMOD_CURRENT")
ACTIVE_CURRENT = Path("results/v3/summarized/SIGMOD_CURRENT")
# Backward-compatible name for callers that explicitly inspect the retained
# paper authority.  Active writers use ``ACTIVE_CURRENT``.
CURRENT = LEGACY_CURRENT
AUTHORITY_FILES = (
    LEGACY_CURRENT / "correctness_summary.json",
    LEGACY_CURRENT / "correctness_cells.csv",
    LEGACY_CURRENT / "performance_summary.json",
    LEGACY_CURRENT / "performance_metrics.csv",
)
REPORT = Path("output/SIGMOD_RESULTS.md")
PROVENANCE = Path("output/provenance.json")
REVIEW_PROVENANCE = Path("output/provenance-review.json")
PUBLIC_FULL_PROFILE = "public/full"
REVIEW_PROFILE = "review"
E3_SNAPSHOT_EQUIVALENCE = Path("output/E3_SNAPSHOT_EQUIVALENCE.md")
E7_SUMMARY = Path("results/summarized/E7/summary.json")
E7_RUNS = Path("results/summarized/E7/runs.csv")
E7_FILES = (E7_SUMMARY, E7_RUNS)
REPORTING_ANALYSIS_FILES = (
    # Frozen release evidence keeps its historical byte path.  Active writers
    # use the canonical AdmissionFirst filename, but provenance must bind the
    # file that actually supports the paper's retained numbers.
    Path("results/analysis/native_contractaware_bootstrap_ci.json"),
    Path("results/summarized/SIGMOD_CURRENT_E10/runs.csv"),
)
P1_SCALE_CHECK = Path(
    "results/summarized/P1_E3_TPCH_SF10_RAWPG_RLSFIX_ROTATE_V3"
)
P1_SCALE_CHECK_FILES = (P1_SCALE_CHECK / "summary.json", P1_SCALE_CHECK / "cells.csv")
P2_SCALE_CHECK = Path(
    "results/summarized/P2_E3_TPCH_SF10_INLINE_RLSFIX_ROTATE_V3"
)
P2_SCALE_CHECK_FILES = (P2_SCALE_CHECK / "summary.json", P2_SCALE_CHECK / "cells.csv")
P3_SCALE_CHECK = Path(
    "results/summarized/P3_E3_TPCH_SF10_INJECTION_RLSFIX_ROTATE_V3"
)
P3_SCALE_CHECK_FILES = (P3_SCALE_CHECK / "summary.json", P3_SCALE_CHECK / "cells.csv")
PAPER_FILES = (
    Path("main.tex"),
    Path("supplement.tex"),
    REPORT,
    Path("output/pdf/main.pdf"),
    Path("output/pdf/supplement.pdf"),
)
PUBLIC_FULL_DOCUMENTS = {
    Path("main.tex"): "main_paper_source",
    Path("output/pdf/main.pdf"): "main_paper_pdf",
    Path("supplement.tex"): "comprehensive_supplement_source",
    Path("output/pdf/supplement.pdf"): "comprehensive_supplement_pdf",
    REPORT: "paper_result_report",
}
MAIN_BUILD_INPUTS = {
    Path("Makefile"): "repository_build_rules",
    Path("acmart.cls"): "main_paper_document_class",
    Path("ACM-Reference-Format.bst"): "main_paper_bibliography_style",
    Path("sample.bib"): "main_paper_bibliography",
    Path("caprls_core/paper_figures.py"): "main_paper_figure_generator",
    Path(
        "figures/theory-example-candidates/"
        "running-example-rowsets-and-reads.drawio.pdf"
    ): "main_paper_figure_asset",
    Path(
        "figures/theory-example-candidates/"
        "running-example-rowsets-and-reads.drawio"
    ): "main_paper_figure_source",
    Path(
        "figures/theory-example-candidates/generate_running_example.py"
    ): "main_paper_figure_generator",
    Path("figures/admission-before-cost-overview.drawio.pdf"): (
        "main_paper_figure_asset"
    ),
    # The combined renderer consumes the audited extraction, without requiring
    # ignored raw records, and the two retained numerical source CSVs.
    Path("figures/evaluation-composite/safety-evidence.json"): (
        "main_paper_safety_evidence_receipt"
    ),
    Path(
        "results/figures/fig6_e4_local_greedy/"
        "fig6_e4_local_greedy_source.csv"
    ): "main_paper_figure_source_data",
    Path("figures/evaluation-composite/evaluation-panels.pdf"): (
        "main_paper_figure_asset"
    ),
    Path("figures/evaluation-composite/render_panel.py"): (
        "main_paper_figure_generator"
    ),
    Path("figures/evaluation-composite/evaluation-panels.json"): (
        "main_paper_figure_derivation_receipt"
    ),
    Path("manifests/baselines/modes.yaml"): "main_paper_figure_pool_registry",
    Path(
        "results/figures/fig4_e3_speedup/"
        "fig4_e3_speedup_source.csv"
    ): "main_paper_figure_source_data",
}
REVIEW_DOCUMENTS = {
    Path("main.tex"): "main_paper_source",
    Path("output/pdf/main.pdf"): "main_paper_pdf",
    Path("submission-review-appendix/review_appendix.tex"): (
        "review_appendix_source"
    ),
    Path("output/pdf/review_appendix.pdf"): "review_appendix_pdf",
}
REVIEW_BUILD_INPUTS = {
    **MAIN_BUILD_INPUTS,
    Path("submission-review-appendix/Makefile"): (
        "review_appendix_build_rules"
    ),
    Path("submission-review-appendix/acmart.cls"): (
        "review_appendix_document_class"
    ),
}
REVIEW_STAGE_DIR = Path("output/sigmod-review-package")
REVIEW_STAGE_FILES = {
    REVIEW_STAGE_DIR / "main-paper.pdf": (
        "main_paper_submission_pdf",
        Path("output/pdf/main.pdf"),
    ),
    REVIEW_STAGE_DIR / "review-appendix.pdf": (
        "review_appendix_submission_pdf",
        Path("output/pdf/review_appendix.pdf"),
    ),
}
PUBLIC_ARTIFACT_TOP_LEVEL = {
    Path("README.md"): "artifact_documentation",
    Path("Makefile"): "artifact_build_rules",
    Path("caprls"): "artifact_entrypoint",
    Path("pyproject.toml"): "artifact_dependency_specification",
    Path("uv.lock"): "artifact_dependency_lock",
}
PUBLIC_ARTIFACT_TREES = {
    Path("caprls_core"): {".py"},
    Path("configs"): {".yaml", ".yml", ".json"},
    Path("datasets/manifests"): {".yaml", ".yml", ".json"},
    Path("experiment"): {".md", ".yaml", ".yml", ".json"},
    Path("manifests"): {".yaml", ".yml", ".json"},
    Path("planner"): {".py", ".md", ".yaml", ".yml", ".json"},
    Path("specs"): {".md", ".yaml", ".yml", ".json"},
    Path("sql"): {".sql"},
    Path("tests"): {".py", ".json", ".yaml", ".yml", ".sql"},
    Path("workloads"): {".sql", ".yaml", ".yml", ".json", ".md"},
}
RELEASE_ORIGIN_SCIENTIFIC_BASELINE_GIT_COMMIT = (
    "cceb04b869de3cff0f81140762b971e67f7c874b"
)


def _canonical_taxonomy_key(key: str) -> str:
    for legacy, current in (
        ("contractaware", "admission_first"),
        ("best_production_safe", "fastest_policy_enforcement"),
        ("fastest_production_safe", "fastest_policy_enforcement"),
        ("production_safe_mode_count", "policy_enforcement_mode_count"),
    ):
        if legacy in key:
            return key.replace(legacy, current)
    return key


def _canonicalize_taxonomy_keys(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            _canonical_taxonomy_key(str(key)): _canonicalize_taxonomy_keys(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_canonicalize_taxonomy_keys(item) for item in value]
    return value


def _json(
    path: Path,
    *,
    canonicalize_taxonomy: bool = True,
) -> Mapping[str, Any]:
    if not path.is_file():
        raise SigmodReleaseError("missing required file: {}".format(path))
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SigmodReleaseError("cannot read JSON: {}".format(path)) from exc
    if not isinstance(value, Mapping):
        raise SigmodReleaseError("expected a JSON object: {}".format(path))
    return _canonicalize_taxonomy_keys(value) if canonicalize_taxonomy else value


def _csv(path: Path) -> List[Dict[str, str]]:
    if not path.is_file():
        raise SigmodReleaseError("missing required file: {}".format(path))
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise SigmodReleaseError("missing CSV header: {}".format(path))
        rows = [dict(row) for row in reader]
    for row in rows:
        for key in list(row):
            canonical_key = _canonical_taxonomy_key(key)
            if canonical_key != key and canonical_key not in row:
                row[canonical_key] = row[key]
    return rows


def _now(value: Optional[str]) -> str:
    return value or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _hash(path: Path) -> str:
    if not path.is_file():
        raise SigmodReleaseError("missing release artifact: {}".format(path))
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _profile_name(value: str) -> str:
    normalized = value.strip().lower().replace("_", "-")
    if normalized in {"public/full", "public-full", "public"}:
        return PUBLIC_FULL_PROFILE
    if normalized == REVIEW_PROFILE:
        return REVIEW_PROFILE
    raise SigmodReleaseError("unknown provenance profile: {}".format(value))


def _default_provenance_path(profile: str) -> Path:
    return REVIEW_PROVENANCE if profile == REVIEW_PROFILE else PROVENANCE


def _role_hashes(root: Path, files: Mapping[Path, str]) -> Dict[str, Dict[str, str]]:
    return {
        path.as_posix(): {"role": role, "sha256": _hash(root / path)}
        for path, role in sorted(files.items(), key=lambda item: item[0].as_posix())
    }


def _public_artifact_materials(root: Path) -> Dict[str, Dict[str, str]]:
    files: Dict[Path, str] = dict(PUBLIC_ARTIFACT_TOP_LEVEL)
    for directory, suffixes in PUBLIC_ARTIFACT_TREES.items():
        absolute = root / directory
        if not absolute.is_dir():
            raise SigmodReleaseError(
                "missing public artifact directory: {}".format(directory)
            )
        for path in absolute.rglob("*"):
            if (
                path.is_file()
                and not path.name.startswith("._")
                and path.suffix.lower() in suffixes
            ):
                files[path.relative_to(root)] = "public_artifact_material"
    return _role_hashes(root, files)


def _review_staging_manifest(root: Path) -> Dict[str, Any]:
    absolute = root / REVIEW_STAGE_DIR
    if not absolute.is_dir():
        raise SigmodReleaseError(
            "missing review staging directory: {}".format(REVIEW_STAGE_DIR)
        )
    actual = {
        path.relative_to(root)
        for path in absolute.rglob("*")
        if path.is_file() and not path.name.startswith("._")
    }
    expected = set(REVIEW_STAGE_FILES)
    if actual != expected:
        missing = sorted(path.as_posix() for path in expected - actual)
        extra = sorted(path.as_posix() for path in actual - expected)
        raise SigmodReleaseError(
            "review staging directory must contain exactly two PDFs; "
            "missing={}, extra={}".format(missing, extra)
        )

    files = []
    for staged_path, (role, source_path) in sorted(
        REVIEW_STAGE_FILES.items(), key=lambda item: item[0].as_posix()
    ):
        staged_hash = _hash(root / staged_path)
        source_hash = _hash(root / source_path)
        if staged_hash != source_hash:
            raise SigmodReleaseError(
                "staged review file differs from its source PDF: {}".format(
                    staged_path
                )
            )
        files.append(
            {
                "role": role,
                "source_path": source_path.as_posix(),
                "staged_path": staged_path.as_posix(),
                "sha256": staged_hash,
            }
        )
    return {
        "directory": REVIEW_STAGE_DIR.as_posix(),
        "exact_file_count": 2,
        "files": files,
    }


def _items(value: Any, label: str) -> List[str]:
    if not isinstance(value, list) or not value:
        raise SigmodReleaseError("{} must be a nonempty list".format(label))
    return sorted({str(item) for item in value if str(item)})


def _canonical_content_evidence(
    correctness: Mapping[str, Any],
) -> Dict[str, Any]:
    authorities = correctness.get("canonical_content_authorities")
    if not isinstance(authorities, list) or len(authorities) != 1:
        raise SigmodReleaseError(
            "correctness summary must contain exactly one E3 canonical content authority"
        )
    item = authorities[0]
    if not isinstance(item, Mapping) or not isinstance(item.get("snapshot"), Mapping):
        raise SigmodReleaseError("invalid E3 canonical content authority")
    if (
        correctness.get("schema_version") != "caprls-sigmod-correctness-v3"
        or item.get("experiment") != "E3"
        or item.get("status") != "pass"
        or item.get("evidence_kind") != "canonical_content_receipts"
        or item.get("check_kind")
        != "independent_full_row_jsonb_multiset_equality"
    ):
        raise SigmodReleaseError("invalid E3 canonical content authority identity")

    commit = str(item.get("canonical_content_source_commit", ""))
    manifest = str(item.get("manifest_sha256", ""))
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise SigmodReleaseError("invalid E3 canonical content source commit")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", manifest) is None:
        raise SigmodReleaseError("invalid E3 canonical content manifest_sha256")
    source_file = str(item.get("source_file", ""))
    source_sha256 = str(item.get("source_sha256", ""))
    if not source_file or re.fullmatch(r"sha256:[0-9a-f]{64}", source_sha256) is None:
        raise SigmodReleaseError("invalid E3 canonical content source identity")

    snapshot = item["snapshot"]
    if _items(snapshot.get("git_commits"), "E3 canonical git_commits") != [commit]:
        raise SigmodReleaseError("E3 canonical source commit disagrees with its snapshot")
    if _items(snapshot.get("manifest_hashes"), "E3 canonical manifest_hashes") != [
        manifest
    ]:
        raise SigmodReleaseError("E3 canonical manifest_sha256 disagrees with its snapshot")
    if correctness.get("canonical_content_source_commit") != commit:
        raise SigmodReleaseError("top-level E3 canonical source commit disagrees")
    if correctness.get("canonical_content_manifest_sha256") != manifest:
        raise SigmodReleaseError("top-level E3 canonical manifest_sha256 disagrees")
    ordinary_families = correctness.get("families")
    if not isinstance(ordinary_families, list):
        raise SigmodReleaseError("correctness summary lacks ordinary families")
    ordinary_e3 = [
        family
        for family in ordinary_families
        if isinstance(family, Mapping)
        and family.get("experiment") == "E3"
    ]
    if len(ordinary_e3) != 1 or not isinstance(
        ordinary_e3[0].get("snapshot"), Mapping
    ):
        raise SigmodReleaseError("correctness summary lacks one ordinary E3 family")
    if _items(
        ordinary_e3[0]["snapshot"].get("manifest_hashes"),
        "ordinary E3 manifest_hashes",
    ) != [manifest]:
        raise SigmodReleaseError(
            "E3 canonical manifest_sha256 disagrees with ordinary E3"
        )

    counts = item.get("counts")
    if not isinstance(counts, Mapping):
        raise SigmodReleaseError("E3 canonical content authority lacks counts")
    try:
        expected = int(counts["cells_expected"])
        passed = int(counts["cells_passed"])
        receipts = int(counts["receipts"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SigmodReleaseError("invalid E3 canonical content counts") from exc
    if (expected, passed, receipts) != (33, 33, 33):
        raise SigmodReleaseError(
            "E3 canonical content authority must contain 33/33 receipts"
        )

    return {
        "family": "E3_CANONICAL_CONTENT",
        "experiment": "E3",
        "evidence_kind": item["evidence_kind"],
        "check_kind": str(item.get("check_kind", "")),
        "scope": str(item.get("scope", "")),
        "source_file": source_file,
        "source_sha256": source_sha256,
        "git_commits": [commit],
        "manifest_hashes": [manifest],
        "cells_expected": expected,
        "cells_passed": passed,
        "receipts": receipts,
    }


def _families(
    correctness: Mapping[str, Any],
    performance: Mapping[str, Any],
    canonical_content: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, set[str]]] = {}

    def add(
        family: str,
        experiment: Any,
        commits: Any,
        manifests: Any,
        authority: str,
    ) -> None:
        if not family:
            raise SigmodReleaseError("authority contains an unnamed family")
        row = merged.setdefault(
            family,
            {"experiments": set(), "git_commits": set(), "manifest_hashes": set(), "authorities": set()},
        )
        if str(experiment):
            row["experiments"].add(str(experiment))
        row["git_commits"].update(_items(commits, family + ".git_commits"))
        row["manifest_hashes"].update(_items(manifests, family + ".manifest_hashes"))
        row["authorities"].add(authority)

    correctness_families = correctness.get("families")
    if not isinstance(correctness_families, list) or not correctness_families:
        raise SigmodReleaseError("correctness summary does not declare families")
    for item in correctness_families:
        if not isinstance(item, Mapping) or not isinstance(item.get("snapshot"), Mapping):
            raise SigmodReleaseError("invalid correctness family")
        snapshot = item["snapshot"]
        add(
            str(item.get("family", "")),
            item.get("experiment", ""),
            snapshot.get("git_commits"),
            snapshot.get("manifest_hashes"),
            "correctness",
        )

    add(
        str(canonical_content["family"]),
        canonical_content["experiment"],
        canonical_content["git_commits"],
        canonical_content["manifest_hashes"],
        "correctness_canonical_content",
    )

    performance_sources = performance.get("sources")
    if not isinstance(performance_sources, Mapping) or not performance_sources:
        raise SigmodReleaseError("performance summary does not declare sources")
    for family, item in performance_sources.items():
        if not isinstance(item, Mapping):
            raise SigmodReleaseError("invalid performance family: {}".format(family))
        add(
            str(family),
            item.get("experiment", ""),
            item.get("git_commits"),
            item.get("manifest_hashes"),
            "performance",
        )

    return [
        {
            "family": family,
            **{key: sorted(values) for key, values in row.items()},
        }
        for family, row in sorted(merged.items())
    ]


def _correctness_scopes(correctness: Mapping[str, Any]) -> List[Dict[str, Any]]:
    declared = correctness.get("correctness_scopes")
    families = correctness.get("families")
    if not isinstance(declared, list) or not isinstance(families, list):
        raise SigmodReleaseError("correctness authority lacks family check scopes")
    by_family = {
        str(item.get("family", "")): item
        for item in declared
        if isinstance(item, Mapping) and str(item.get("family", ""))
    }
    rows = []
    for family in families:
        if not isinstance(family, Mapping):
            raise SigmodReleaseError("invalid correctness family")
        name = str(family.get("family", ""))
        scope = by_family.get(name)
        if scope is None:
            raise SigmodReleaseError("missing correctness scope for {}".format(name))
        for field in ("experiment", "check_kind", "scope"):
            if not str(scope.get(field, "")) or family.get(field) != scope.get(field):
                raise SigmodReleaseError("inconsistent {} for {}".format(field, name))
        counts = family.get("counts")
        if not isinstance(counts, Mapping):
            raise SigmodReleaseError("missing correctness counts for {}".format(name))
        rows.append(
            {
                "family": name,
                "experiment": scope["experiment"],
                "check_kind": scope["check_kind"],
                "scope": scope["scope"],
                "cells": counts.get("cells", ""),
            }
        )
    return rows


def _e9_denominators(performance: Mapping[str, Any]) -> Dict[str, int]:
    sections = performance.get("sections")
    e9 = sections.get("E9") if isinstance(sections, Mapping) else None
    if not isinstance(e9, Mapping):
        raise SigmodReleaseError("performance authority lacks sections.E9")
    result = {}
    for field in (
        "record_count",
        "mode_cell_count",
        "admission_first_measured_observation_count",
    ):
        try:
            value = int(e9[field])
        except (KeyError, TypeError, ValueError) as exc:
            raise SigmodReleaseError("invalid sections.E9.{}".format(field)) from exc
        if value <= 0:
            raise SigmodReleaseError("sections.E9.{} must be positive".format(field))
        result[field] = value
    return result


def _e10_q10_weakness(performance: Mapping[str, Any]) -> Dict[str, float]:
    sections = performance.get("sections")
    e10 = sections.get("E10") if isinstance(sections, Mapping) else None
    comparisons = e10.get("native_comparisons") if isinstance(e10, Mapping) else None
    if not isinstance(comparisons, list):
        raise SigmodReleaseError("performance authority lacks E10 native comparisons")
    for comparison in comparisons:
        if not isinstance(comparison, Mapping) or comparison.get("comparison") != "NativePG-RLS":
            continue
        cells = comparison.get("cells")
        if not isinstance(cells, list):
            break
        for cell in cells:
            if (
                isinstance(cell, Mapping)
                and cell.get("query_id") == "E10_Q10_revoked_membership_mav"
            ):
                try:
                    admission_first = float(cell["admission_first_total_ms_median"])
                    baseline = float(cell["baseline_total_ms_median"])
                except (KeyError, TypeError, ValueError) as exc:
                    raise SigmodReleaseError("invalid E10 Q10 latency values") from exc
                if admission_first <= 0 or baseline <= 0 or cell.get("outcome") != "loss":
                    raise SigmodReleaseError("E10 Q10 is not recorded as a positive latency loss")
                return {
                    "admission_first_ms": admission_first,
                    "native_pg_rls_ms": baseline,
                    "slowdown": admission_first / baseline,
                }
    raise SigmodReleaseError("performance authority lacks the E10 Q10 NativePG-RLS loss")


def _e7_witness(root: Path) -> Dict[str, Any]:
    """Load the separate bounded live unsafe-UDF witness."""

    summary = _json(root / E7_SUMMARY)
    rows = _csv(root / E7_RUNS)
    if summary.get("experiment") != "E7" or int(summary.get("record_count", -1)) != len(rows):
        raise SigmodReleaseError("E7 summary and runs disagree")
    by_query = {row.get("query_id", ""): row for row in rows}
    expected = {
        "E7_contract_unsafe_where": ("pass", "pass", 0),
        "E7_guard_mandatory_discharge": ("pass", "pass", 0),
        "E7_guard_late_before_unsafe": ("static_verifier_fail", "fail", 780),
        "E7_positive_raw_pushdown": ("unsafe_observation", "fail", 780),
        "E7_unsafe_throw": ("unsafe_observation", "fail", 1),
    }
    cases = []
    # Status names are retained fixture metadata; they do not certify a
    # separate planner rejection or full-row equality check in E7.
    for query_id, (status, audit_status, unauthorized) in expected.items():
        row = by_query.get(query_id)
        if row is None:
            raise SigmodReleaseError("E7 witness lacks {}".format(query_id))
        try:
            observed = int(row.get("unauthorized_observations", ""))
        except ValueError as exc:
            raise SigmodReleaseError("E7 witness has invalid observation count") from exc
        if row.get("status") != status or row.get("runtime_audit_status") != audit_status or observed != unauthorized:
            raise SigmodReleaseError("E7 witness disagrees for {}".format(query_id))
        cases.append(
            {
                "query_id": query_id,
                "mode": row.get("mode", ""),
                "status": status,
                "runtime_audit_status": audit_status,
                "unauthorized_observations": unauthorized,
            }
        )
    return {
        "authority": "separate_bounded_live_witness",
        "evidence_scope": "runtime unauthorized-observation aggregates only",
        "status_scope": "retained fixture metadata, not an independent planning decision",
        "result_scope": "count-query SQL; no independent full-row multiset receipt",
        "timing_scope": "shared batch timing; not per-plan execution latency",
        "included_in_52_cell_authority": False,
        "record_count": len(rows),
        "git_commits": _items(summary.get("git_commits"), "E7.git_commits"),
        "manifest_hashes": _items(summary.get("manifest_hashes"), "E7.manifest_hashes"),
        "summary_path": E7_SUMMARY.as_posix(),
        "runs_path": E7_RUNS.as_posix(),
        "cases": cases,
    }


def _additional_scale_check(
    root: Path,
    files: Sequence[Path] = P1_SCALE_CHECK_FILES,
    *,
    label: str = "P1",
    modes: Sequence[str] = ("native-pg-rls", "barrier-only", "local-greedy"),
    expected_mode_cells: int = 60,
) -> Optional[Dict[str, Any]]:
    present = [(root / path).is_file() for path in files]
    if not any(present):
        return None
    if not all(present):
        raise SigmodReleaseError(
            "{} SF10 scale check must include both summary.json and cells.csv".format(
                label
            )
        )
    summary = _json(root / files[0])
    rows = _csv(root / files[1])
    identity_keys = ("schema", "schema_version", "status", "authority")
    if tuple(summary.get(key) for key in identity_keys) != (
        "e3_sf10_standalone_scale_check_v1",
        1,
        "pass",
        "standalone_e3_sf10_scale_check",
    ):
        raise SigmodReleaseError(
            "invalid {} SF10 scale-check identity or status".format(label)
        )
    integration = summary.get("paper_authority_integration")
    separation_keys = (
        "included_in_existing_52_cell_correctness_authority",
        "included_in_existing_780_record_correctness_total",
        "included_in_existing_performance_authority",
        "no_cross_sf1_aggregate",
    )
    if not isinstance(integration, Mapping) or tuple(
        integration.get(key) for key in separation_keys
    ) != (False, False, False, True):
        raise SigmodReleaseError(
            "invalid {} SF10 authority-separation flags".format(label)
        )
    selection = summary.get("selection_claims")
    if not isinstance(selection, Mapping) or tuple(
        selection.get(key) for key in ("measured_best_claimed", "oracle_claimed")
    ) != (False, False):
        raise SigmodReleaseError(
            "{} SF10 scale check must remain non-oracle".format(label)
        )
    correctness = summary.get("correctness")
    try:
        count_keys = (
            "logical_cells_passed",
            "logical_cells_total",
            "mode_cells_passed",
            "mode_cells_total",
        )
        counts = tuple(int(correctness[key]) for key in count_keys)
        comparisons = summary["comparisons"]
        comparison_rows = [
            (
                mode,
                int(comparisons[mode]["cell_count"]),
                int(comparisons[mode]["wins"]),
                int(comparisons[mode]["ties"]),
                int(comparisons[mode]["losses"]),
                float(comparisons[mode]["ratio_median"]),
                float(comparisons[mode]["ratio_geometric_mean"]),
                float(comparisons[mode]["ratio_p90_linear"]),
            )
            for mode in modes
        ]
        q7 = next(
            row
            for row in rows
            if row.get("comparator_mode") == "native-pg-rls"
            and row.get("query_id") == "Q7"
            and row.get("policy_id") == "group_acl_expensive"
        )
        baseline_ms = float(q7["comparator_median_ms"])
        admission_first_ms = float(q7["contract_aware_median_ms"])
    except (KeyError, StopIteration, TypeError, ValueError) as exc:
        raise SigmodReleaseError(
            "invalid {} SF10 counts, comparisons, or Q7 row".format(label)
        ) from exc
    if counts != (15, 15, expected_mode_cells, expected_mode_cells) or set(
        comparisons
    ) != set(modes):
        raise SigmodReleaseError(
            "{} SF10 scale check must be a 15/15, {}/{} pass".format(
                label, expected_mode_cells, expected_mode_cells
            )
        )
    q7_outcome = q7.get("outcome_for_contract_aware")
    if q7_outcome not in {"win", "tie", "loss"}:
        raise SigmodReleaseError(
            "{} SF10 cells.csv has an invalid Q7 outcome".format(label)
        )
    return {
        "counts": counts,
        "comparisons": comparison_rows,
        "q7": (
            admission_first_ms,
            baseline_ms,
            admission_first_ms / baseline_ms,
            q7_outcome,
        ),
        "rows": rows,
    }


def _median(values: Sequence[float]) -> float:
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[midpoint]
    return (ordered[midpoint - 1] + ordered[midpoint]) / 2.0


def _p3_scale_check(root: Path) -> Optional[Dict[str, Any]]:
    result = _additional_scale_check(
        root,
        P3_SCALE_CHECK_FILES,
        label="P3",
        modes=(
            "native-pg-rls",
            "barrier-only",
            "local-greedy",
            "injection-only",
        ),
        expected_mode_cells=75,
    )
    if result is None:
        return None

    by_cell: Dict[tuple[str, str], Dict[str, Dict[str, str]]] = {}
    for row in result["rows"]:
        key = (row.get("query_id", ""), row.get("policy_id", ""))
        mode = row.get("comparator_mode", "")
        if not all(key) or mode in by_cell.setdefault(key, {}):
            raise SigmodReleaseError("P3 SF10 cells.csv has an invalid cell identity")
        by_cell[key][mode] = row

    expected_modes = {
        "native-pg-rls",
        "barrier-only",
        "local-greedy",
        "injection-only",
    }
    if len(by_cell) != 15 or any(set(rows) != expected_modes for rows in by_cell.values()):
        raise SigmodReleaseError("P3 SF10 cells.csv must contain four comparators for 15 cells")

    injection_ratios: List[float] = []
    regrets: List[tuple[float, tuple[str, str]]] = []
    wins = ties = losses = 0
    for key, rows in by_cell.items():
        try:
            comparator_ms = {
                mode: float(row["comparator_median_ms"])
                for mode, row in rows.items()
            }
            admission_first_values = {
                float(row["contract_aware_median_ms"]) for row in rows.values()
            }
            tie_factors = {float(row["tie_factor"]) for row in rows.values()}
        except (KeyError, TypeError, ValueError) as exc:
            raise SigmodReleaseError("P3 SF10 cells.csv has invalid latency data") from exc
        if len(admission_first_values) != 1 or len(tie_factors) != 1:
            raise SigmodReleaseError("P3 SF10 cell rows disagree on latency or tie band")

        ratio = comparator_ms["native-pg-rls"] / comparator_ms["injection-only"]
        injection_ratios.append(ratio)
        tie_factor = next(iter(tie_factors))
        if ratio > tie_factor:
            wins += 1
        elif ratio < 1.0 / tie_factor:
            losses += 1
        else:
            ties += 1

        admission_first_ms = next(iter(admission_first_values))
        best_comparator_ms = min(comparator_ms.values())
        regrets.append((max(1.0, admission_first_ms / best_comparator_ms), key))

    worst_regret, worst_cell = max(regrets)
    result["injection_vs_native"] = {
        "wins": wins,
        "ties": ties,
        "losses": losses,
        "median": _median(injection_ratios),
        "geometric_mean": math.exp(
            sum(math.log(value) for value in injection_ratios)
            / len(injection_ratios)
        ),
    }
    result["ranker_regret"] = {
        "exact_fastest": sum(regret == 1.0 for regret, _ in regrets),
        "cell_count": len(regrets),
        "median": _median([regret for regret, _ in regrets]),
        "worst": worst_regret,
        "worst_query": worst_cell[0],
        "worst_policy": worst_cell[1],
    }
    return result


def _authority_files(authority_dir: Path) -> tuple[Path, Path, Path, Path]:
    base = Path(authority_dir)
    return (
        base / "correctness_summary.json",
        base / "correctness_cells.csv",
        base / "performance_summary.json",
        base / "performance_metrics.csv",
    )


def _authority_source(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def _load(
    root: Path,
    authority_dir: Path = LEGACY_CURRENT,
) -> Dict[str, Any]:
    files = _authority_files(authority_dir)
    correctness = _json(_authority_source(root, files[0]))
    cells = _csv(_authority_source(root, files[1]))
    performance = _json(_authority_source(root, files[2]))
    metrics = _csv(_authority_source(root, files[3]))
    e7_witness = _e7_witness(root)
    additional_scale_check = _additional_scale_check(root)
    p2_scale_check = _additional_scale_check(
        root,
        P2_SCALE_CHECK_FILES,
        label="P2",
    )
    p3_scale_check = _p3_scale_check(root)
    if correctness.get("status") != "pass" or performance.get("status") != "pass":
        raise SigmodReleaseError("current correctness/performance authority is not pass")
    totals = correctness.get("totals")
    if not isinstance(totals, Mapping) or len(cells) != int(totals.get("cells_passed", -1)):
        raise SigmodReleaseError("correctness cell count does not match its summary")
    if not metrics:
        raise SigmodReleaseError("performance authority has no metric rows")
    canonical_content = _canonical_content_evidence(correctness)
    families = _families(correctness, performance, canonical_content)
    correctness_scopes = _correctness_scopes(correctness)
    correctness_scopes.append(
        {
            "family": canonical_content["family"],
            "experiment": canonical_content["experiment"],
            "check_kind": canonical_content["check_kind"],
            "scope": canonical_content["scope"],
            "cells": canonical_content["cells_passed"],
        }
    )
    e9_denominators = _e9_denominators(performance)
    e10_q10_weakness = _e10_q10_weakness(performance)
    try:
        ordinary_expected = int(totals["ordinary_records_expected"])
        ordinary_passed = int(totals["ordinary_records_passed"])
        canonical_expected = int(totals["e3_canonical_content_cells_expected"])
        canonical_passed = int(totals["e3_canonical_content_cells_passed"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SigmodReleaseError(
            "correctness authority lacks final evidence denominators"
        ) from exc
    if (
        ordinary_expected <= 0
        or ordinary_passed != ordinary_expected
        or canonical_expected != canonical_content["cells_expected"]
        or canonical_passed != canonical_content["cells_passed"]
    ):
        raise SigmodReleaseError("correctness evidence denominators are inconsistent")
    commits = sorted({commit for row in families for commit in row["git_commits"]})
    input_claims = [
        isinstance(summary.get("snapshot_policy"), Mapping)
        and summary["snapshot_policy"].get("single_combined_snapshot_claimed") is True
        for summary in (correctness, performance)
    ]
    single = len(commits) == 1 and all(input_claims)
    return {
        "correctness": correctness,
        "performance": performance,
        "metrics": metrics,
        "families": families,
        "correctness_scopes": correctness_scopes,
        "canonical_content": canonical_content,
        "correctness_denominators": {
            "ordinary_expected": ordinary_expected,
            "ordinary_passed": ordinary_passed,
            "canonical_expected": canonical_expected,
            "canonical_passed": canonical_passed,
        },
        "e9_denominators": e9_denominators,
        "e10_q10_weakness": e10_q10_weakness,
        "e7_witness": e7_witness,
        "additional_scale_check": additional_scale_check,
        "p2_scale_check": p2_scale_check,
        "p3_scale_check": p3_scale_check,
        "snapshot_policy": {
            "single_combined_snapshot_claimed": single,
            "distinct_git_commits": commits,
            "note": (
                "All authorities explicitly claim the same execution commit."
                if single
                else "Families retain their own source commits; no single combined execution snapshot is claimed."
            ),
        },
    }


def _md(value: Any) -> str:
    text = str(value).strip() or "—"
    for legacy, current in (
        ("ContractAware-NoDom", "AdmissionFirst-NoDom"),
        ("ContractAware", "AdmissionFirst"),
        (LEGACY_CONTRACT_AWARE_NO_DOMINANCE_MODE, ADMISSION_FIRST_NO_DOMINANCE_MODE),
        (LEGACY_CONTRACT_AWARE_MODE, ADMISSION_FIRST_MODE),
        ("production-safe", "policy-enforcement"),
        ("production_safe", "policy_enforcement"),
    ):
        text = text.replace(legacy, current)
    return text.replace("|", "\\|").replace("\n", " ")


def _reader_case_text(value: Any) -> str:
    """Translate retained experimental-cell prose without changing wire keys."""

    text = str(value)
    for pattern, replacement in (
        (r"\bmode-cells\b", "case--mode pairs"),
        (r"\bmode-cell\b", "case--mode pair"),
        (r"\blogical cells\b", "evaluation cases"),
        (r"\blogical cell\b", "evaluation case"),
        (r"\bcell-median\b", "within-case median"),
        (r"\bper-cell\b", "per-case"),
        (r"\bcells\b", "cases"),
        (r"\bcell\b", "case"),
    ):
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text


def generate_authority(
    repo_root: Path = Path("."),
    generated_at_utc: Optional[str] = None,
    output_dir: Path = ACTIVE_CURRENT,
) -> Path:
    """Regenerate active v3 authority files without touching frozen evidence."""

    from .sigmod_performance_preview import (
        PerformancePreviewError,
        generate_performance_preview,
    )
    from .sigmod_preview import SigmodPreviewError, generate_sigmod_preview

    root = Path(repo_root)
    destination = Path(output_dir)
    try:
        generate_sigmod_preview(root, destination)
        generate_performance_preview(root, destination)
    except (SigmodPreviewError, PerformancePreviewError) as exc:
        raise SigmodReleaseError(str(exc)) from exc
    return generate_report(
        root,
        output=destination / "SIGMOD_RESULTS.md",
        generated_at_utc=generated_at_utc,
        authority_dir=destination,
    )


def generate_report(
    repo_root: Path = Path("."),
    output: Path = REPORT,
    generated_at_utc: Optional[str] = None,
    authority_dir: Path = LEGACY_CURRENT,
) -> Path:
    """Build a report from an explicitly selected authority directory.

    The default remains the retained paper authority; active v3 generation
    passes its isolated destination explicitly.
    """

    root = Path(repo_root)
    data = _load(root, authority_dir=authority_dir)
    correctness = data["correctness"]
    totals = correctness["totals"]
    denominators = data["correctness_denominators"]
    lines = [
        "# CAPRLS SIGMOD Result Package",
        "",
        "Generated at `{}` from the current correctness and performance authorities.".format(
            _now(generated_at_utc)
        ),
        "",
        "**E9 interpretation correction.** The E9 figures below are retained "
        "diagnostic fields, not evidence of successful plan selection: all 675 "
        "final root checks failed, and PostgreSQL later executed stress SQL "
        "generated separately. The combined times and the 0.325 fraction are "
        "not the end-to-end cost of one admitted plan.",
        "",
        "## Correctness",
        "",
        "- Evidence: `{}`".format(_md(correctness.get("evidence_kind", ""))),
        "- Cases: `{}/{}` passed".format(totals["cells_passed"], totals["cells_expected"]),
        "- Retained executions: `{}/{}` passed family-specific count checks (`{}` measured executions, `{}` warmups).".format(
            denominators["ordinary_passed"],
            denominators["ordinary_expected"],
            totals["measured_records"],
            totals["warmup_records"],
        ),
        "- E3 canonical content receipts: `{}/{}` passed independent full-row multiset equality.".format(
            denominators["canonical_passed"],
            denominators["canonical_expected"],
        ),
        "- Scope: {}".format(_md(_reader_case_text(correctness.get("scope", "")))),
        "",
        "| Family | Cases | Check kind | Exact scope |",
        "|---|---:|---|---|",
    ]
    for row in data["correctness_scopes"]:
        lines.append(
            "| {} | {} | {} | {} |".format(
                _md(row["family"]),
                _md(row["cells"]),
                _md(row["check_kind"]),
                _md(_reader_case_text(row["scope"])),
            )
        )

    e7 = data["e7_witness"]
    e7_cases = {case["query_id"]: case for case in e7["cases"]}
    lines += [
        "",
        "### Separate bounded live witness",
        "",
        "E7 is not part of the 52-case denominator. Its AdmissionFirst and mandatory-discharge cases recorded `0` unauthorized observations; the guard-late diagnostic and a control that evaluates the audit expression on raw input before exact authorization each recorded `{}` unauthorized observations, and the unsafe-throw positive control recorded `{}` client-visible unauthorized observation.".format(
            e7_cases["E7_positive_raw_pushdown"]["unauthorized_observations"],
            e7_cases["E7_unsafe_throw"]["unauthorized_observations"],
        ),
        "Source: `{}` (`{}` run records).".format(e7["runs_path"], e7["record_count"]),
        "These counts come from runtime audit aggregates. The retained failure statuses are fixture metadata, not independently executed planning decisions; E7 provides no independent full-row equality receipt or per-plan latency measurement.",
        "",
        "### Active planning and template evidence",
        "",
        "Figure 3(a) reports actual planner/root decisions for 21 constructed AF plans with known expected decisions. The ten rejected plans cover eight tested problem groups. All 21 match their expected decisions: 11 admitted and 10 rejected. These planning cases did not execute SQL. The former control-effects and E6b component-effects panels are withdrawn from runtime-effect claims because their classifications came from preset case labels.",
        "",
        "Figure 3(b) plots the four logging cases in the E7 smoke workload: each records 220 authorized UDF calls, with 0, 0, 780 and 780 unauthorized calls, respectively. The separate throwing case records one client-visible unauthorized observation; it is not pooled with the logging counts.",
        "",
        "Figure 3(c) compares three specified, actually timed template pairs, each for one fixed complete query; these are not two general choice algorithms. Figure 3(d) uses the fastest applicable measured mode as a post-measurement reference, while AF chooses before timing from estimates.",
        "",
        "IndexPriority is the E3/SF10 display name for the fixed availability order: an authorization index organized by the query key, otherwise an authorization index, otherwise a barrier. It compares no costs. The internal local-greedy ID is retained, and this display mapping does not apply to its distinct E4/E9/E10 roles.",
    ]

    e9 = data["e9_denominators"]
    disclosure = data["performance"].get("loss_disclosure")
    e4_e5_scope = ""
    if isinstance(disclosure, Mapping):
        e4_e5_scope = str(
            disclosure.get("E4_E5_scope")
            or disclosure.get("E4_E5_limitation")
            or ""
        )
    if e4_e5_scope:
        e4_e5_scope = re.sub(
            r"E4[^;]*;",
            "E4 compares three specified template pairs, each for one fixed complete query;",
            e4_e5_scope, count=1,
        )
    q10 = data["e10_q10_weakness"]
    lines += [
        "",
        "## Performance",
        "",
        _md(_reader_case_text(data["performance"].get("scope", ""))),
        "",
        "E4/E5 scope: {}".format(_md(_reader_case_text(e4_e5_scope)))
        if e4_e5_scope
        else "E4/E5 scope: not declared by this authority.",
        "",
        "E9 contains `{}` executions across `{}` case--mode pairs; its distributions use `{}` measured AdmissionFirst executions.".format(
            e9["record_count"],
            e9["mode_cell_count"],
            e9["admission_first_measured_observation_count"],
        ),
        "",
        "Explicit E10 tail weakness: Q10 AdmissionFirst median `{:.3f} ms` versus NativePG-RLS `{:.3f} ms`, about `{:.2f}×` slower.".format(
            q10["admission_first_ms"],
            q10["native_pg_rls_ms"],
            q10["slowdown"],
        ),
        "",
        "Every row from `performance_metrics.csv` appears below; blank fields are not applicable.",
        "",
        "| Section | Comparison | Kind | Cases | Measurements | Median | Geomean | P90 | W/T/L | Top-1 | Top-3 |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in data["metrics"]:
        comparison = _reader_case_text(row.get("comparison", ""))
        if row.get("section") == "E4":
            comparison = "Three specified template pairs with numeric outcomes"
        elif row.get("section") == "E3":
            comparison = comparison.replace("LocalGreedy", "IndexPriority")
        wtl = "/".join(_md(row.get(key, "")) for key in ("wins", "ties", "losses"))
        values = (
            row.get("section", ""),
            comparison,
            row.get("metric_kind", ""),
            row.get("cell_count", ""),
            row.get("observation_count", ""),
            row.get("median", ""),
            row.get("geometric_mean", ""),
            row.get("p90_linear", ""),
            wtl,
            row.get("top1_count", ""),
            row.get("top3_count", ""),
        )
        lines.append("| {} |".format(" | ".join(_md(value) for value in values)))

    scale_check = data["additional_scale_check"]
    if scale_check is not None:
        logical_passed, logical_total, mode_passed, mode_total = scale_check["counts"]
        lines += [
            "",
            "## Additional TPC-H SF10 scale check (outside core authorities)",
            "",
            "This standalone, non-oracle scale check is outside the four `SIGMOD_CURRENT` core authority files. It does not change the 52-case, 780-execution, or SF1 performance authorities, and no latency is aggregated across SF1 and SF10.",
            "",
            "- Correctness: `{}/{}` query--policy cases and `{}/{}` case--mode pairs passed.".format(
                logical_passed, logical_total, mode_passed, mode_total
            ),
            "- Ratio: comparator median / AdmissionFirst median; values above 1 favor AdmissionFirst.",
            "",
            "| Comparator | Cases | W/T/L | Median ratio | Geomean ratio | P90 ratio |",
            "|---|---:|---:|---:|---:|---:|",
        ]
        for row in scale_check["comparisons"]:
            mode, cells, wins, ties, losses, median, geomean, p90 = row
            lines.append(
                "| {} | {} | {}/{}/{} | {:.3f}× | {:.3f}× | {:.3f}× |".format(
                    _md("IndexPriority" if mode == "local-greedy" else mode), cells, wins, ties, losses, median, geomean, p90
                )
            )
        q7_admission_first, q7_native, q7_ratio, q7_outcome = scale_check["q7"]
        lines += [
            "",
            "Explicit SF10 Q7 group-ACL result: AdmissionFirst median `{:.3f} ms` versus NativePG-RLS `{:.3f} ms` (AdmissionFirst/Native `{:.3f}×`; `{}` under the inclusive 1% tie band).".format(
                q7_admission_first, q7_native, q7_ratio, q7_outcome
            ),
        ]

    p2_scale_check = data["p2_scale_check"]
    if p2_scale_check is not None:
        logical_passed, logical_total, mode_passed, mode_total = p2_scale_check[
            "counts"
        ]
        lines += [
            "",
            "## P2 single-reference inline-wrapper follow-up",
            "",
            "P2 keeps the P1 denominator and protocol but explicitly uses `NOT MATERIALIZED` for single-reference AdmissionFirst access roots. It remains outside the core authorities.",
            "",
            "- Correctness: `{}/{}` query--policy cases and `{}/{}` case--mode pairs passed.".format(
                logical_passed, logical_total, mode_passed, mode_total
            ),
            "",
            "| Comparator | Cases | W/T/L | Median ratio | Geomean ratio | P90 ratio |",
            "|---|---:|---:|---:|---:|---:|",
        ]
        for row in p2_scale_check["comparisons"]:
            mode, cells, wins, ties, losses, median, geomean, p90 = row
            lines.append(
                "| {} | {} | {}/{}/{} | {:.3f}× | {:.3f}× | {:.3f}× |".format(
                    _md("IndexPriority" if mode == "local-greedy" else mode), cells, wins, ties, losses, median, geomean, p90
                )
            )
        q7_admission_first, q7_native, q7_ratio, q7_outcome = p2_scale_check["q7"]
        lines += [
            "",
            "P2 Q7 group-ACL result: AdmissionFirst median `{:.3f} ms` versus NativePG-RLS `{:.3f} ms` (AdmissionFirst/Native `{:.3f}×`; `{}` under the inclusive 1% tie band).".format(
                q7_admission_first, q7_native, q7_ratio, q7_outcome
            ),
        ]

    p3_scale_check = data["p3_scale_check"]
    if p3_scale_check is not None:
        logical_passed, logical_total, mode_passed, mode_total = p3_scale_check[
            "counts"
        ]
        lines += [
            "",
            "## P3 safe-predicate-injection follow-up",
            "",
            "P3 keeps the P2 wrapper and adds the already-admitted safe-predicate-injection representation as a measured comparator in every case. It remains outside the core authorities.",
            "",
            "- Correctness: `{}/{}` query--policy cases and `{}/{}` case--mode pairs passed.".format(
                logical_passed, logical_total, mode_passed, mode_total
            ),
            "- AdmissionFirst comparisons use comparator/AdmissionFirst ratios; values above 1 favor AdmissionFirst.",
            "",
            "| Comparator | Cases | W/T/L | Median ratio | Geomean ratio | P90 ratio |",
            "|---|---:|---:|---:|---:|---:|",
        ]
        for row in p3_scale_check["comparisons"]:
            mode, cells, wins, ties, losses, median, geomean, p90 = row
            lines.append(
                "| {} | {} | {}/{}/{} | {:.3f}× | {:.3f}× | {:.3f}× |".format(
                    _md("IndexPriority" if mode == "local-greedy" else mode), cells, wins, ties, losses, median, geomean, p90
                )
            )
        injection = p3_scale_check["injection_vs_native"]
        ranker = p3_scale_check["ranker_regret"]
        lines += [
            "",
            "Within the same P3 run, safe injection is `{}/{}/{}` W/T/L against NativePG-RLS, with Native/injection median `{:.3f}×` and geometric mean `{:.3f}×` (values above 1 favor injection).".format(
                injection["wins"],
                injection["ties"],
                injection["losses"],
                injection["median"],
                injection["geometric_mean"],
            ),
            "",
            "The post-hoc finite-set ranker audit places AdmissionFirst exactly fastest in `{}/{}` cases. Its capped regret against the fastest measured policy-enforcement comparator has median `{:.3f}×` and worst `{:.3f}×` at {} `{}`. This is a bounded diagnostic, not an oracle or universal-optimality claim.".format(
                ranker["exact_fastest"],
                ranker["cell_count"],
                ranker["median"],
                ranker["worst"],
                ranker["worst_query"],
                ranker["worst_policy"],
            ),
        ]

    policy = data["snapshot_policy"]
    lines += [
        "",
        "## Source snapshots",
        "",
        "Single combined execution snapshot claimed: **{}**. {}".format(
            "yes" if policy["single_combined_snapshot_claimed"] else "no", policy["note"]
        ),
        "",
        "| Family | Experiment | Source commit(s) | Manifest hash(es) | Authority |",
        "|---|---|---|---|---|",
    ]
    for row in data["families"]:
        values = (
            row["family"],
            ", ".join(row["experiments"]),
            ", ".join(row["git_commits"]),
            ", ".join(row["manifest_hashes"]),
            ", ".join(row["authorities"]),
        )
        lines.append("| {} |".format(" | ".join(_md(value) for value in values)))
    lines += [
        "",
        "## Regeneration",
        "",
        "- `make sigmod-paper` compiles both PDFs from tracked paper sources and figures.",
        "- `make sigmod-release-package` regenerates this report, compiles both PDFs, and refreshes provenance using tracked release evidence.",
        "- Maintainers may use `make sigmod-authority` only with the separate retained result bundle available locally.",
        "",
    ]

    destination = output if output.is_absolute() else root / output
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines), encoding="utf-8")
    return destination


def _provenance_payload(
    repo_root: Path = Path("."),
    generated_at_utc: Optional[str] = None,
    release_origin_baseline_commit: str = (
        RELEASE_ORIGIN_SCIENTIFIC_BASELINE_GIT_COMMIT
    ),
    profile: str = PUBLIC_FULL_PROFILE,
) -> Dict[str, Any]:
    """Build a role-specific provenance payload without writing it."""

    root = Path(repo_root)
    profile = _profile_name(profile)
    data = _load(root, authority_dir=LEGACY_CURRENT)
    if (
        re.fullmatch(r"[0-9a-f]{40}", release_origin_baseline_commit) is None
        or release_origin_baseline_commit
        != RELEASE_ORIGIN_SCIENTIFIC_BASELINE_GIT_COMMIT
    ):
        raise SigmodReleaseError(
            "release-origin scientific baseline must equal the fixed release baseline "
            + RELEASE_ORIGIN_SCIENTIFIC_BASELINE_GIT_COMMIT
        )
    payload: Dict[str, Any] = {
        "schema_version": "caprls-sigmod-release-provenance-v4",
        "provenance_profile": profile,
        "profile_role": (
            "anonymous_review_submission"
            if profile == REVIEW_PROFILE
            else "public_full_release"
        ),
        "generated_at_utc": _now(generated_at_utc),
        "commit_roles": {
            "release_origin_scientific_baseline": {
                "git_commit": release_origin_baseline_commit,
                "role": (
                    "The retained-performance and aggregation starting point "
                    "immediately before the P0 canonical correctness receipts."
                ),
                "predates_p0_canonical_receipts": True,
                "not_a_p0_comparator": True,
                "not_a_receipt_execution_commit": True,
                "p0_execution_commit_source": (
                    "families[E3_CANONICAL_CONTENT].git_commits"
                ),
            },
            "containing_packaging_commit": None,
            "containing_packaging_commit_role": (
                "The Git commit that eventually contains this generated file is "
                "recorded externally in release or tag metadata."
            ),
            "self_reference_policy": (
                "Intentionally null in this in-commit file: a file cannot "
                "truthfully hash or name the future Git commit that contains it."
            ),
        },
        "snapshot_policy": data["snapshot_policy"],
        "families": data["families"],
        "correctness_evidence_sources": {
            "E3_CANONICAL_CONTENT": data["canonical_content"]
        },
        "separate_witnesses": {"E7": data["e7_witness"]},
        "authority_files": {path.as_posix(): _hash(root / path) for path in AUTHORITY_FILES},
        "snapshot_equivalence_files": {
            E3_SNAPSHOT_EQUIVALENCE.as_posix(): _hash(
                root / E3_SNAPSHOT_EQUIVALENCE
            )
        },
        "separate_witness_files": {path.as_posix(): _hash(root / path) for path in E7_FILES},
        "reporting_analysis_files": {
            path.as_posix(): _hash(root / path) for path in REPORTING_ANALYSIS_FILES
        },
        "additional_scale_check_files": (
            {
                path.as_posix(): _hash(root / path)
                for path in (
                    (
                        P1_SCALE_CHECK_FILES
                        if data["additional_scale_check"] is not None
                        else ()
                    )
                    + (
                        P2_SCALE_CHECK_FILES
                        if data["p2_scale_check"] is not None
                        else ()
                    )
                    + (
                        P3_SCALE_CHECK_FILES
                        if data["p3_scale_check"] is not None
                        else ()
                    )
                )
            }
        ),
    }

    if profile == REVIEW_PROFILE:
        payload["documents"] = _role_hashes(root, REVIEW_DOCUMENTS)
        payload["build_inputs"] = _role_hashes(root, REVIEW_BUILD_INPUTS)
        payload["review_staging_manifest"] = _review_staging_manifest(root)
        payload["paper_files"] = {
            path.as_posix(): _hash(root / path) for path in REVIEW_DOCUMENTS
        }
    else:
        payload["documents"] = _role_hashes(root, PUBLIC_FULL_DOCUMENTS)
        payload["build_inputs"] = _role_hashes(root, MAIN_BUILD_INPUTS)
        payload["public_artifact_materials"] = _public_artifact_materials(root)
        # Preserve the v3 paper_files surface for existing release consumers.
        payload["paper_files"] = {
            path.as_posix(): _hash(root / path) for path in PAPER_FILES
        }
    return payload


def generate_provenance(
    repo_root: Path = Path("."),
    output: Optional[Path] = None,
    generated_at_utc: Optional[str] = None,
    release_origin_baseline_commit: str = (
        RELEASE_ORIGIN_SCIENTIFIC_BASELINE_GIT_COMMIT
    ),
    profile: str = PUBLIC_FULL_PROFILE,
) -> Path:
    """Write role-specific provenance after its documents and package exist."""

    root = Path(repo_root)
    profile = _profile_name(profile)
    payload = _provenance_payload(
        root,
        generated_at_utc=generated_at_utc,
        release_origin_baseline_commit=release_origin_baseline_commit,
        profile=profile,
    )
    output = output or _default_provenance_path(profile)
    destination = output if output.is_absolute() else root / output
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return destination


def check_provenance(
    repo_root: Path = Path("."),
    provenance_path: Optional[Path] = None,
    release_origin_baseline_commit: str = (
        RELEASE_ORIGIN_SCIENTIFIC_BASELINE_GIT_COMMIT
    ),
    profile: str = PUBLIC_FULL_PROFILE,
) -> Path:
    """Recompute one provenance profile and fail without modifying files."""

    root = Path(repo_root)
    profile = _profile_name(profile)
    path = provenance_path or _default_provenance_path(profile)
    source = path if path.is_absolute() else root / path
    # Provenance dictionary keys include historical artifact paths.  They are
    # sealed identities, not active summary-field aliases, so preserve them
    # byte-for-byte while checking the payload.
    recorded = _json(source, canonicalize_taxonomy=False)
    if recorded.get("schema_version") != "caprls-sigmod-release-provenance-v4":
        raise SigmodReleaseError(
            "provenance check requires caprls-sigmod-release-provenance-v4: {}".format(
                path
            )
        )
    if recorded.get("provenance_profile") != profile:
        raise SigmodReleaseError(
            "provenance profile mismatch: expected {}, found {}".format(
                profile, recorded.get("provenance_profile")
            )
        )
    generated_at_utc = recorded.get("generated_at_utc")
    if not isinstance(generated_at_utc, str) or not generated_at_utc:
        raise SigmodReleaseError("provenance lacks generated_at_utc: {}".format(path))
    expected = _provenance_payload(
        root,
        generated_at_utc=generated_at_utc,
        release_origin_baseline_commit=release_origin_baseline_commit,
        profile=profile,
    )
    if recorded != expected:
        raise SigmodReleaseError(
            "provenance is stale or inconsistent for profile {}: {}".format(
                profile, path
            )
        )
    return source


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build the offline SIGMOD report or final PDF-bound provenance"
    )
    parser.add_argument("command", choices=("authority", "report", "provenance"))
    parser.add_argument("--root", type=Path, default=Path("."), help="repository root")
    parser.add_argument(
        "--release-origin-baseline",
        default=RELEASE_ORIGIN_SCIENTIFIC_BASELINE_GIT_COMMIT,
        help=(
            "fixed pre-P0 retained-performance and aggregation origin; family "
            "and P0 execution commits remain recorded separately"
        ),
    )
    parser.add_argument(
        "--profile",
        default=PUBLIC_FULL_PROFILE,
        help="provenance role: review or public/full (default: public/full)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="provenance JSON path (defaults by profile)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="read and verify provenance without modifying it",
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "authority":
            if args.check or args.output is not None or args.profile != PUBLIC_FULL_PROFILE:
                raise SigmodReleaseError(
                    "--profile, --output, and --check apply only to provenance"
                )
            path = generate_authority(args.root)
        elif args.command == "report":
            if args.check or args.output is not None or args.profile != PUBLIC_FULL_PROFILE:
                raise SigmodReleaseError(
                    "--profile, --output, and --check apply only to provenance"
                )
            path = generate_report(args.root)
        elif args.check:
            path = check_provenance(
                args.root,
                provenance_path=args.output,
                release_origin_baseline_commit=args.release_origin_baseline,
                profile=args.profile,
            )
        else:
            path = generate_provenance(
                args.root,
                output=args.output,
                release_origin_baseline_commit=args.release_origin_baseline,
                profile=args.profile,
            )
    except SigmodReleaseError as exc:
        parser.exit(2, "sigmod-release: error: {}\n".format(exc))
    print("verified {}".format(path) if args.check else "wrote {}".format(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
